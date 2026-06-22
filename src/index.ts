import { WebDavLockManager } from "./lock-do";
import { WebDavUserManager } from "./user-do";
import { ACCESS_JWKS_CACHE_TTL_MS, ADMIN_PREFIX, CSRF_PROTECTED_METHODS, DIR_MARKER, XML_NS } from "./constants";
import { HttpError } from "./errors";
import { baseHeaders, htmlHeaders, xmlResponse } from "./http";
import {
  dirMarkerKey,
  isSameOrDescendantPath,
  isVisibleRoot,
  normalizeRequestPath,
  normalizeRootPath,
  parentDirectoryHref,
  prefixToPath,
  resolveMountPath,
  stripPathPrefix,
  temporarySiblingPath,
  toClientHref,
  toClientPath,
  toCollectionPrefix,
  toObjectKey,
  toStoragePath,
} from "./paths";
import type { AccessJsonWebKey, AccessJwtPayload, AuthContext, Env, Permission, ResourceInfo } from "./types";
import {
  basename,
  base64UrlDecode,
  encodePathForHref,
  ensureHref,
  escapeHtml,
  escapeXml,
  formatSize,
  parentPath,
  safeJsonEmbed,
  timingSafeEquals,
} from "./utils";

let accessJwksCache: { url: string; keys: AccessJsonWebKey[]; expiresAt: number } | null = null;

export { WebDavLockManager, WebDavUserManager };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(request.url);
      const clientPath = normalizeRequestPath(url.pathname);
      const isAdminPath = clientPath === ADMIN_PREFIX || clientPath.startsWith(`${ADMIN_PREFIX}/`);
      if (shouldShowRootAdmin(request, clientPath)) {
        return Response.redirect(new URL(`${ADMIN_PREFIX}/users`, request.url), 302);
      }
      const auth = isAdminPath ? await authenticateAdminRequest(request, env) : await authenticateRequest(request, env);
      if (!auth) {
        return new Response("Unauthorized", {
          status: 401,
          headers: {
            "WWW-Authenticate": 'Basic realm="Cloudflare WebDAV"',
          },
        });
      }
      if (auth.retryAfter) {
        return new Response("Too many failed authentication attempts", {
          status: 429,
          headers: {
            ...baseHeaders(),
            "Retry-After": String(auth.retryAfter),
          },
        });
      }

      if (isAdminPath) {
        return handleAdminRequest(request, env, auth, clientPath);
      }

      auth.mountPath = resolveMountPath(auth, clientPath);
      const resourcePath = toStoragePath(auth, clientPath);

      switch (request.method.toUpperCase()) {
        case "OPTIONS":
          return handleOptions();
        case "PROPFIND":
          return handlePropfind(request, env, auth, resourcePath);
        case "GET":
        case "HEAD":
          return handleGetLike(request, env, auth, resourcePath);
        case "PUT":
          return handlePut(request, env, auth, resourcePath);
        case "DELETE":
          return handleDelete(request, env, auth, resourcePath);
        case "MKCOL":
          return handleMkcol(request, env, auth, resourcePath);
        case "MOVE":
          return handleMove(request, env, auth, resourcePath);
        case "COPY":
          return handleCopy(request, env, auth, resourcePath);
        case "LOCK":
          return handleLock(request, env, auth, resourcePath);
        case "UNLOCK":
          return handleUnlock(request, env, auth, resourcePath);
        default:
          return new Response("Method Not Allowed", {
            status: 405,
            headers: baseHeaders(),
          });
      }
    } catch (error) {
      if (error instanceof HttpError) {
        return new Response(error.message, {
          status: error.status,
          headers: baseHeaders(),
        });
      }
      return new Response("Internal error", {
        status: 500,
        headers: baseHeaders(),
      });
    }
  },
};

function handleOptions() {
  return new Response("", {
    status: 200,
    headers: {
      ...baseHeaders(),
      Allow: "OPTIONS, PROPFIND, GET, HEAD, PUT, DELETE, MKCOL, MOVE, COPY, LOCK, UNLOCK",
      DAV: "1, 2",
      "MS-Author-Via": "DAV",
    },
  });
}

async function handlePropfind(request: Request, env: Env, auth: AuthContext, path: string) {
  const permissionCheck = requirePermission(auth, "read");
  if (permissionCheck) {
    return permissionCheck;
  }

  const depth = request.headers.get("Depth") ?? "1";
  if (depth !== "0" && depth !== "1") {
    return new Response("Depth not supported", { status: 400, headers: baseHeaders() });
  }

  const resource = await statAuthPath(env, auth, path);
  if (!resource) {
    return new Response("Not found", { status: 404, headers: baseHeaders() });
  }

  const resources: ResourceInfo[] = [resource];
  if (depth === "1" && resource.isCollection) {
    resources.push(...(await listChildren(env, path)));
  }

  return xmlResponse(multistatusXml(resources, auth), 207);
}

async function handleGetLike(request: Request, env: Env, auth: AuthContext, path: string) {
  const permissionCheck = requirePermission(auth, "read");
  if (permissionCheck) {
    return permissionCheck;
  }

  const resource = await statAuthPath(env, auth, path);
  if (!resource) {
    return new Response("Not found", { status: 404, headers: baseHeaders() });
  }

  if (resource.isCollection) {
    const children = await listChildren(env, path);
    const body = renderDirectoryListing(path, children, auth);
    const headers = new Headers(htmlHeaders());
    headers.set("Content-Length", String(new TextEncoder().encode(body).length));

    if (request.method.toUpperCase() === "HEAD") {
      return new Response(null, { status: 200, headers });
    }

    return new Response(body, { status: 200, headers });
  }

  const range = parseRangeHeader(request.headers.get("Range"), resource.size);
  if (isInvalidRange(range)) {
    return new Response("Range Not Satisfiable", {
      status: 416,
      headers: {
        ...baseHeaders(),
        "Accept-Ranges": "bytes",
        "Content-Range": `bytes */${resource.size}`,
      },
    });
  }

  const object = await env.WEBDAV_BUCKET.get(toObjectKey(path), range ? { range } : undefined);
  if (!object) {
    return new Response("Not found", { status: 404, headers: baseHeaders() });
  }

  const resolvedRange = resolveContentRange(range, object.range, resource.size);
  const headers = new Headers(baseHeaders());
  headers.set("ETag", object.httpEtag);
  headers.set("Content-Length", String(resolvedRange ? resolvedRange.length : object.size));
  headers.set("Last-Modified", object.uploaded.toUTCString());
  headers.set("Content-Type", object.httpMetadata?.contentType || "application/octet-stream");
  headers.set("Accept-Ranges", "bytes");

  if (resolvedRange) {
    headers.set("Content-Range", `bytes ${resolvedRange.start}-${resolvedRange.end}/${resource.size}`);
  }

  if (request.method.toUpperCase() === "HEAD") {
    return new Response(null, { status: range ? 206 : 200, headers });
  }

  return new Response(object.body, { status: range ? 206 : 200, headers });
}

async function handlePut(request: Request, env: Env, auth: AuthContext, path: string) {
  const permissionCheck = requirePermission(auth, "write");
  if (permissionCheck) {
    return permissionCheck;
  }

  if (isVisibleRoot(auth, path)) {
    return new Response("Cannot write root", { status: 409, headers: baseHeaders() });
  }

  const ifHeader = request.headers.get("If");
  const lockCheck = await ensureUnlocked(env, path, ifHeader);
  if (lockCheck) {
    return lockCheck;
  }

  await ensureAccountRoot(env, auth);
  await ensureParentsCreated(env, parentPath(path), ifHeader);
  const existing = await env.WEBDAV_BUCKET.head(toObjectKey(path));
  await env.WEBDAV_BUCKET.put(toObjectKey(path), request.body, {
    httpMetadata: {
      contentType: request.headers.get("Content-Type") ?? undefined,
    },
  });

  return new Response("", {
    status: existing ? 200 : 201,
    headers: baseHeaders(),
  });
}

async function handleDelete(request: Request, env: Env, auth: AuthContext, path: string) {
  const permissionCheck = requirePermission(auth, "delete");
  if (permissionCheck) {
    return permissionCheck;
  }

  if (isVisibleRoot(auth, path)) {
    return new Response("Cannot delete root", { status: 403, headers: baseHeaders() });
  }

  const target = await statAuthPath(env, auth, path);
  if (!target) {
    return new Response("Not found", { status: 404, headers: baseHeaders() });
  }

  const lockCheck = await ensureUnlocked(env, path, request.headers.get("If"), target.isCollection);
  if (lockCheck) {
    return lockCheck;
  }

  if (target.isCollection) {
    await deleteCollection(env, path);
  } else {
    await env.WEBDAV_BUCKET.delete(target.key!);
  }

  return new Response("", { status: 200, headers: baseHeaders() });
}

async function handleMkcol(request: Request, env: Env, auth: AuthContext, path: string) {
  const permissionCheck = requirePermission(auth, "write");
  if (permissionCheck) {
    return permissionCheck;
  }

  if (isVisibleRoot(auth, path)) {
    return new Response("Collection exists", { status: 405, headers: baseHeaders() });
  }

  if (request.headers.get("Content-Length") && request.headers.get("Content-Length") !== "0") {
    return new Response("MKCOL body not supported", { status: 415, headers: baseHeaders() });
  }

  const existing = await statAuthPath(env, auth, path);
  if (existing) {
    return new Response("Already exists", { status: 405, headers: baseHeaders() });
  }

  const lockCheck = await ensureUnlocked(env, path, request.headers.get("If"));
  if (lockCheck) {
    return lockCheck;
  }

  await ensureWritableParentExists(env, auth, parentPath(path));
  await writeDirMarker(env, path);
  return new Response("", { status: 201, headers: baseHeaders() });
}

async function handleMove(request: Request, env: Env, auth: AuthContext, sourcePath: string) {
  const writeCheck = requirePermission(auth, "write");
  if (writeCheck) {
    return writeCheck;
  }
  const deleteCheck = requirePermission(auth, "delete");
  if (deleteCheck) {
    return deleteCheck;
  }

  const destinationClientPath = parseDestination(request, request.url);
  if (!destinationClientPath) {
    return new Response("Bad destination", { status: 400, headers: baseHeaders() });
  }
  const destination = toStoragePath(auth, destinationClientPath);
  if (isVisibleRoot(auth, sourcePath)) {
    return new Response("Cannot move root", { status: 403, headers: baseHeaders() });
  }
  if (isVisibleRoot(auth, destination)) {
    return new Response("Bad destination", { status: 409, headers: baseHeaders() });
  }
  if (destination === sourcePath) {
    return new Response("", { status: 200, headers: baseHeaders() });
  }

  const overwrite = (request.headers.get("Overwrite") ?? "T").toUpperCase() !== "F";
  const source = await statAuthPath(env, auth, sourcePath);
  if (!source) {
    return new Response("Not found", { status: 404, headers: baseHeaders() });
  }
  if (source.isCollection && isSameOrDescendantPath(sourcePath, destination)) {
    return new Response("Bad destination", { status: 409, headers: baseHeaders() });
  }

  const sourceLock = await ensureUnlocked(env, sourcePath, request.headers.get("If"), source.isCollection);
  if (sourceLock) {
    return sourceLock;
  }

  const destinationLock = await ensureUnlocked(env, destination, request.headers.get("If"), source.isCollection);
  if (destinationLock) {
    return destinationLock;
  }

  const destinationExists = await statAuthPath(env, auth, destination);
  if (destinationExists && !overwrite) {
    return new Response("Destination exists", { status: 412, headers: baseHeaders() });
  }

  await ensureWritableParentExists(env, auth, parentPath(destination));
  await withDestinationBackup(env, destination, destinationExists, async () => {
    await copyResourcePath(env, source, sourcePath, destination);
  });
  await deleteResourcePath(env, sourcePath, source);

  return new Response("", {
    status: destinationExists ? 200 : 201,
    headers: baseHeaders(),
  });
}

async function handleCopy(request: Request, env: Env, auth: AuthContext, sourcePath: string) {
  const readCheck = requirePermission(auth, "read");
  if (readCheck) {
    return readCheck;
  }
  const writeCheck = requirePermission(auth, "write");
  if (writeCheck) {
    return writeCheck;
  }

  const destinationClientPath = parseDestination(request, request.url);
  if (!destinationClientPath) {
    return new Response("Bad destination", { status: 400, headers: baseHeaders() });
  }
  const destination = toStoragePath(auth, destinationClientPath);
  if (isVisibleRoot(auth, sourcePath)) {
    return new Response("Cannot copy root", { status: 403, headers: baseHeaders() });
  }
  if (isVisibleRoot(auth, destination)) {
    return new Response("Bad destination", { status: 409, headers: baseHeaders() });
  }
  if (destination === sourcePath) {
    return new Response("", { status: 200, headers: baseHeaders() });
  }

  const overwrite = (request.headers.get("Overwrite") ?? "T").toUpperCase() !== "F";
  const source = await statAuthPath(env, auth, sourcePath);
  if (!source) {
    return new Response("Not found", { status: 404, headers: baseHeaders() });
  }
  if (source.isCollection && isSameOrDescendantPath(sourcePath, destination)) {
    return new Response("Bad destination", { status: 409, headers: baseHeaders() });
  }

  const destinationLock = await ensureUnlocked(env, destination, request.headers.get("If"), source.isCollection);
  if (destinationLock) {
    return destinationLock;
  }

  const destinationExists = await statAuthPath(env, auth, destination);
  if (destinationExists && !overwrite) {
    return new Response("Destination exists", { status: 412, headers: baseHeaders() });
  }

  await ensureWritableParentExists(env, auth, parentPath(destination));
  await withDestinationBackup(env, destination, destinationExists, async () => {
    await copyResourcePath(env, source, sourcePath, destination);
  });

  return new Response("", {
    status: destinationExists ? 200 : 201,
    headers: baseHeaders(),
  });
}

async function handleLock(request: Request, env: Env, auth: AuthContext, path: string) {
  const permissionCheck = requirePermission(auth, "write");
  if (permissionCheck) {
    return permissionCheck;
  }

  const timeoutSeconds = parseTimeoutSeconds(request.headers.get("Timeout"));
  const depth = request.headers.get("Depth") === "0" ? "0" : "infinity";
  const ifHeader = request.headers.get("If");
  const refreshToken = ifHeader ? extractLockToken(ifHeader) : null;
  const owner = refreshToken ? null : extractLockOwner(await request.text());

  const stub = lockStub(env);
  const response = await stub.fetch("https://locks/acquire", {
    method: "POST",
    body: JSON.stringify({
      path,
      owner,
      depth,
      timeoutSeconds,
      refreshToken,
    }),
  });

  const result = (await response.json()) as {
    ok: boolean;
    status: number;
    token?: string;
    expiresAt?: number;
  };

  if (!result.ok || !result.token || !result.expiresAt) {
    return new Response("Lock conflict", { status: result.status, headers: baseHeaders() });
  }

  const target = await statAuthPath(env, auth, path);
  const headers = new Headers(baseHeaders());
  headers.set("Lock-Token", `<${result.token}>`);
  headers.set("Content-Type", 'application/xml; charset="utf-8"');

  return new Response(lockDiscoveryXml(path, auth, result.token, owner, result.expiresAt, depth, target?.isCollection ?? false), {
    status: target ? 200 : 201,
    headers,
  });
}

async function handleUnlock(request: Request, env: Env, auth: AuthContext, path: string) {
  const permissionCheck = requirePermission(auth, "write");
  if (permissionCheck) {
    return permissionCheck;
  }

  const token = extractLockToken(request.headers.get("Lock-Token"));
  if (!token) {
    return new Response("Missing lock token", { status: 400, headers: baseHeaders() });
  }

  const stub = lockStub(env);
  const response = await stub.fetch("https://locks/unlock", {
    method: "POST",
    body: JSON.stringify({ path, token }),
  });
  const result = (await response.json()) as { ok: boolean; status: number };

  return new Response("", {
    status: result.ok ? 200 : result.status,
    headers: baseHeaders(),
  });
}

async function statPath(env: Env, path: string): Promise<ResourceInfo | null> {
  if (path === "/") {
    return {
      href: "/",
      name: "",
      path: "/",
      key: null,
      isCollection: true,
      size: 0,
      etag: null,
      lastModified: null,
      contentType: "httpd/unix-directory",
    };
  }

  const objectKey = toObjectKey(path);
  const object = await env.WEBDAV_BUCKET.head(objectKey);
  if (object) {
    return {
      href: ensureHref(path, false),
      name: basename(path),
      path,
      key: objectKey,
      isCollection: false,
      size: object.size,
      etag: object.httpEtag,
      lastModified: object.uploaded,
      contentType: object.httpMetadata?.contentType ?? "application/octet-stream",
    };
  }

  const prefix = toCollectionPrefix(path);
  const marker = await env.WEBDAV_BUCKET.head(dirMarkerKey(path));
  if (marker) {
    return {
      href: ensureHref(path, true),
      name: basename(path),
      path,
      key: dirMarkerKey(path),
      isCollection: true,
      size: 0,
      etag: null,
      lastModified: marker.uploaded,
      contentType: "httpd/unix-directory",
    };
  }

  const listing = await env.WEBDAV_BUCKET.list({ prefix, limit: 1 });
  if (listing.objects.length > 0) {
    return {
      href: ensureHref(path, true),
      name: basename(path),
      path,
      key: null,
      isCollection: true,
      size: 0,
      etag: null,
      lastModified: listing.objects[0].uploaded,
      contentType: "httpd/unix-directory",
    };
  }

  return null;
}

async function statAuthPath(env: Env, auth: AuthContext, path: string): Promise<ResourceInfo | null> {
  if (isVisibleRoot(auth, path)) {
    const root = await statPath(env, path);
    if (root && !root.isCollection) {
      return root;
    }
    return {
      href: "/",
      name: "",
      path,
      key: null,
      isCollection: true,
      size: 0,
      etag: null,
      lastModified: root?.lastModified ?? null,
      contentType: "httpd/unix-directory",
    };
  }
  return statPath(env, path);
}

async function listChildren(env: Env, path: string): Promise<ResourceInfo[]> {
  const prefix = path === "/" ? "" : toCollectionPrefix(path);
  const items: ResourceInfo[] = [];
  const seenPrefixes = new Set<string>();
  let cursor: string | undefined;

  do {
    const listing = await env.WEBDAV_BUCKET.list({
      prefix,
      delimiter: "/",
      limit: 1000,
      cursor,
    });

    for (const childPrefix of listing.delimitedPrefixes) {
      if (seenPrefixes.has(childPrefix)) {
        continue;
      }
      seenPrefixes.add(childPrefix);
      const childPath = prefixToPath(childPrefix);
      items.push({
        href: ensureHref(childPath, true),
        name: basename(childPath),
        path: childPath,
        key: null,
        isCollection: true,
        size: 0,
        etag: null,
        lastModified: null,
        contentType: "httpd/unix-directory",
      });
    }

    for (const object of listing.objects) {
      if (object.key.endsWith(`/${DIR_MARKER}`)) {
        continue;
      }
      if (object.key === `${DIR_MARKER}`) {
        continue;
      }
      items.push({
        href: ensureHref(`/${object.key}`, false),
        name: basename(`/${object.key}`),
        path: `/${object.key}`,
        key: object.key,
        isCollection: false,
        size: object.size,
        etag: object.httpEtag,
        lastModified: object.uploaded,
        contentType: object.httpMetadata?.contentType ?? "application/octet-stream",
      });
    }

    cursor = listing.truncated ? listing.cursor : undefined;
  } while (cursor);

  items.sort((a, b) => a.href.localeCompare(b.href));
  return items;
}

async function ensureParentExists(env: Env, path: string) {
  if (path === "/") {
    return;
  }
  const parent = await statPath(env, path);
  if (!parent || !parent.isCollection) {
    throw new HttpError(409, "Parent collection does not exist");
  }
}

async function ensureWritableParentExists(env: Env, auth: AuthContext, path: string) {
  if (isVisibleRoot(auth, path)) {
    await ensureAccountRoot(env, auth);
    return;
  }
  await ensureParentExists(env, path);
}

async function ensureAccountRoot(env: Env, auth: AuthContext) {
  if (auth.root === "/") {
    return;
  }
  const existing = await statPath(env, auth.root);
  if (existing?.isCollection) {
    return;
  }
  if (existing) {
    throw new HttpError(409, "Account root is not a collection");
  }
  await ensureParentsCreated(env, parentPath(auth.root), null);
  await writeDirMarker(env, auth.root);
}

async function ensureParentsCreated(env: Env, path: string, ifHeader: string | null) {
  if (path === "/") {
    return;
  }
  const existing = await statPath(env, path);
  if (existing?.isCollection) {
    return;
  }
  if (existing) {
    throw new HttpError(409, "Parent path is not a collection");
  }
  await ensureParentsCreated(env, parentPath(path), ifHeader);
  await assertUnlocked(env, path, ifHeader);
  await writeDirMarker(env, path);
}

async function writeDirMarker(env: Env, path: string) {
  await env.WEBDAV_BUCKET.put(dirMarkerKey(path), "");
}

async function deleteCollection(env: Env, path: string) {
  const prefix = toCollectionPrefix(path);
  let cursor: string | undefined;
  do {
    const listing = await env.WEBDAV_BUCKET.list({ prefix, cursor });
    const keys = listing.objects.map((object) => object.key);
    if (keys.length > 0) {
      await env.WEBDAV_BUCKET.delete(keys);
    }
    cursor = listing.truncated ? listing.cursor : undefined;
  } while (cursor);
}

async function copyCollection(env: Env, sourcePath: string, destinationPath: string) {
  await writeDirMarker(env, destinationPath);
  const sourcePrefix = toCollectionPrefix(sourcePath);
  const destinationPrefix = toCollectionPrefix(destinationPath);
  let cursor: string | undefined;
  do {
    const listing = await env.WEBDAV_BUCKET.list({ prefix: sourcePrefix, cursor });
    for (const object of listing.objects) {
      const relative = object.key.slice(sourcePrefix.length);
      const cloned = await env.WEBDAV_BUCKET.get(object.key);
      if (!cloned) {
        continue;
      }
      await env.WEBDAV_BUCKET.put(`${destinationPrefix}${relative}`, cloned.body, {
        httpMetadata: cloned.httpMetadata,
      });
    }
    cursor = listing.truncated ? listing.cursor : undefined;
  } while (cursor);
}

async function copyFile(env: Env, sourceKey: string, destinationPath: string) {
  const object = await env.WEBDAV_BUCKET.get(sourceKey);
  if (!object) {
    throw new HttpError(404, "Not found");
  }
  await env.WEBDAV_BUCKET.put(toObjectKey(destinationPath), object.body, {
    httpMetadata: object.httpMetadata,
  });
}

async function copyResourcePath(env: Env, source: ResourceInfo, sourcePath: string, destinationPath: string) {
  if (source.isCollection) {
    await copyCollection(env, sourcePath, destinationPath);
    return;
  }
  if (!source.key) {
    throw new HttpError(404, "Not found");
  }
  await copyFile(env, source.key, destinationPath);
}

async function deleteResourcePath(env: Env, path: string, resource?: ResourceInfo | null) {
  const target = resource ?? await statPath(env, path);
  if (!target) {
    return;
  }
  if (target.isCollection) {
    await deleteCollection(env, path);
    return;
  }
  if (!target.key) {
    throw new HttpError(404, "Not found");
  }
  await env.WEBDAV_BUCKET.delete(target.key);
}

async function withDestinationBackup(
  env: Env,
  destinationPath: string,
  existingDestination: ResourceInfo | null,
  applyReplacement: () => Promise<void>,
) {
  if (!existingDestination) {
    await applyReplacement();
    return;
  }

  const backupPath = temporarySiblingPath(destinationPath, "backup");
  await copyResourcePath(env, existingDestination, destinationPath, backupPath);

  try {
    await deleteResourcePath(env, destinationPath, existingDestination);
    await applyReplacement();
    await deleteResourcePath(env, backupPath);
  } catch (error) {
    const replacement = await statPath(env, destinationPath);
    if (replacement) {
      await deleteResourcePath(env, destinationPath, replacement);
    }
    const backup = await statPath(env, backupPath);
    if (backup) {
      await copyResourcePath(env, backup, backupPath, destinationPath);
      await deleteResourcePath(env, backupPath, backup);
    }
    throw error;
  }
}

async function ensureUnlocked(env: Env, path: string, ifHeader: string | null, recursive = false) {
  const token = extractLockToken(ifHeader);
  const stub = lockStub(env);
  const response = await stub.fetch("https://locks/check", {
    method: "POST",
    body: JSON.stringify({ path, token, recursive }),
  });
  const result = (await response.json()) as { ok: boolean; status: number };
  if (result.ok) {
    return null;
  }
  return new Response("Locked", { status: result.status, headers: baseHeaders() });
}

async function assertUnlocked(env: Env, path: string, ifHeader: string | null, recursive = false) {
  const lockCheck = await ensureUnlocked(env, path, ifHeader, recursive);
  if (!lockCheck) {
    return;
  }
  throw new HttpError(lockCheck.status, "Locked");
}

function lockStub(env: Env) {
  return env.LOCKS.get(env.LOCKS.idFromName("global-lock-manager"));
}

function parseDestination(request: Request, requestUrl: string) {
  const destination = request.headers.get("Destination");
  if (!destination) {
    return null;
  }
  try {
    const url = new URL(destination, requestUrl);
    return normalizeRequestPath(url.pathname);
  } catch {
    return null;
  }
}

function parseTimeoutSeconds(timeoutHeader: string | null) {
  if (!timeoutHeader) {
    return 3600;
  }
  const match = timeoutHeader.match(/Second-(\d+)/i);
  if (!match) {
    return 3600;
  }
  return Number.parseInt(match[1], 10);
}

function extractLockOwner(body: string) {
  const match = body.match(/<D:owner[^>]*>([\s\S]*?)<\/D:owner>/i) || body.match(/<owner[^>]*>([\s\S]*?)<\/owner>/i);
  return match ? stripTags(match[1]).trim() || null : null;
}

function extractLockToken(value: string | null) {
  if (!value) {
    return null;
  }
  const match = value.match(/opaquelocktoken:[^>\)\s<]+/i);
  return match ? match[0] : null;
}

function stripTags(value: string) {
  return value.replace(/<[^>]+>/g, "");
}

function multistatusXml(resources: ResourceInfo[], auth: AuthContext) {
  const responses = resources
    .map((resource) => {
      const modified = resource.lastModified ? resource.lastModified.toUTCString() : "";
      const length = resource.isCollection ? "0" : String(resource.size);
      const contentType = resource.contentType ?? (resource.isCollection ? "httpd/unix-directory" : "application/octet-stream");
      const resourceType = resource.isCollection ? "<D:collection/>" : "";
      const etag = resource.etag ? `<D:getetag>${escapeXml(resource.etag)}</D:getetag>` : "";
      const href = toClientHref(auth, resource.path, resource.isCollection);
      return `
  <D:response>
    <D:href>${escapeXml(href)}</D:href>
    <D:propstat>
      <D:prop>
        <D:displayname>${escapeXml(resource.name)}</D:displayname>
        <D:resourcetype>${resourceType}</D:resourcetype>
        <D:getcontentlength>${length}</D:getcontentlength>
        <D:getcontenttype>${escapeXml(contentType)}</D:getcontenttype>
        <D:getlastmodified>${escapeXml(modified)}</D:getlastmodified>
        ${etag}
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>`;
    })
    .join("");

  return `<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="${XML_NS}">${responses}
</D:multistatus>`;
}

function lockDiscoveryXml(
  path: string,
  auth: AuthContext,
  token: string,
  owner: string | null,
  expiresAt: number,
  depth: "0" | "infinity",
  isCollection: boolean,
) {
  const timeout = Math.max(0, Math.floor((expiresAt - Date.now()) / 1000));
  return `<?xml version="1.0" encoding="utf-8"?>
<D:prop xmlns:D="${XML_NS}">
  <D:lockdiscovery>
    <D:activelock>
      <D:locktype><D:write/></D:locktype>
      <D:lockscope><D:exclusive/></D:lockscope>
      <D:depth>${depth === "0" ? "0" : "Infinity"}</D:depth>
      <D:owner>${escapeXml(owner ?? "")}</D:owner>
      <D:timeout>Second-${timeout}</D:timeout>
      <D:locktoken><D:href>${escapeXml(token)}</D:href></D:locktoken>
      <D:lockroot><D:href>${escapeXml(toClientHref(auth, path, isCollection))}</D:href></D:lockroot>
    </D:activelock>
  </D:lockdiscovery>
</D:prop>`;
}

function renderSharedStyles() {
  return `
    :root {
      color-scheme: light dark;
      --bg: #f4f6f8;
      --panel: #ffffff;
      --panel-soft: #f8fafc;
      --line: #d4dae4;
      --line-soft: #e7ebf1;
      --text: #151b24;
      --muted: #607086;
      --link: #0b5cad;
      --accent: #0f766e;
      --accent-soft: #d9f0ed;
      --danger: #b42318;
      --danger-soft: #fde7e4;
      --shadow: 0 10px 28px rgba(15, 23, 42, 0.07);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 12px;
      background: var(--bg);
      color: var(--text);
      font: 13px/1.4 "Segoe UI", system-ui, sans-serif;
      font-feature-settings: "tnum";
    }
    main {
      max-width: 1380px;
      margin: 0 auto;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
      box-shadow: var(--shadow);
    }
    header {
      padding: 0;
      border-bottom: 1px solid var(--line);
      background: var(--panel);
    }
    .app-topbar {
      min-height: 42px;
      padding: 8px 12px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      border-bottom: 1px solid var(--line-soft);
      background: var(--panel-soft);
    }
    .brand {
      font-weight: 700;
      letter-spacing: 0;
    }
    .app-nav {
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
      align-items: center;
      justify-content: flex-end;
    }
    .app-nav a {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 26px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--panel);
      color: var(--text);
      padding: 4px 8px;
      text-decoration: none;
      font-size: 12px;
    }
    .app-nav a.is-active {
      border-color: var(--accent);
      background: var(--accent);
      color: #fff;
    }
    .page-heading {
      padding: 12px 16px 10px;
      display: grid;
      gap: 10px;
    }
    .header-row {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
      justify-content: space-between;
    }
    h1 {
      margin: 0 0 2px;
      font-size: 18px;
      line-height: 1.15;
      font-weight: 650;
    }
    p {
      margin: 0;
      color: var(--muted);
      word-break: break-word;
      font-size: 12px;
    }
    a {
      color: var(--link);
      text-decoration: none;
    }
    a:hover {
      text-decoration: underline;
    }
    button, input, textarea, select {
      font: inherit;
    }
    button, .file-input-label {
      appearance: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border: 1px solid var(--line);
      background: var(--panel);
      color: var(--text);
      border-radius: 6px;
      padding: 0 10px;
      cursor: pointer;
      font-size: 12px;
      line-height: 1;
      min-height: 30px;
      height: 30px;
      vertical-align: middle;
      white-space: nowrap;
      text-align: center;
    }
    button.primary, .file-input-label.primary {
      border-color: var(--accent);
      background: var(--accent);
      color: #fff;
    }
    button.danger {
      border-color: #e7a8a1;
      color: var(--danger);
      background: var(--panel);
    }
    button:disabled {
      cursor: not-allowed;
      opacity: 0.55;
    }
    input, select, textarea {
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--panel);
      color: var(--text);
      padding: 7px 9px;
      min-height: 32px;
    }
    input[type="checkbox"] {
      width: 14px;
      height: 14px;
      margin: 0;
      padding: 0;
    }
    .toolbar {
      display: flex;
      flex-wrap: wrap;
      gap: 8px 12px;
      align-items: center;
      justify-content: space-between;
    }
    .toolbar-group {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      align-items: center;
      min-width: 0;
    }
    .toolbar-group.selection {
      padding-left: 10px;
      border-left: 1px solid var(--line);
    }
    .action-menu {
      position: relative;
    }
    .action-menu[open] {
      z-index: 30;
    }
    .action-menu summary {
      list-style: none;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 4px 8px;
      cursor: pointer;
      background: var(--panel);
      font-size: 12px;
      min-height: 30px;
    }
    .action-menu summary::-webkit-details-marker {
      display: none;
    }
    .action-menu-panel {
      position: absolute;
      right: 0;
      top: calc(100% + 4px);
      z-index: 5;
      min-width: 128px;
      padding: 6px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--panel);
      box-shadow: var(--shadow);
      display: grid;
      gap: 4px;
    }
    .action-menu-panel button {
      width: 100%;
      text-align: left;
      justify-content: flex-start;
    }
    .status {
      position: fixed;
      right: 16px;
      bottom: 16px;
      z-index: 20;
      max-width: min(420px, calc(100vw - 32px));
      padding: 9px 12px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--panel);
      box-shadow: var(--shadow);
      color: var(--muted);
      min-height: 34px;
      display: none;
      align-items: center;
      font-size: 12px;
      transition: background 0.16s ease, color 0.16s ease, opacity 0.16s ease;
    }
    .status.is-visible {
      display: flex;
    }
    .status[data-tone="success"] {
      background: var(--accent-soft);
      color: #0b5f59;
    }
    .status[data-tone="error"] {
      background: var(--danger-soft);
      color: var(--danger);
    }
    .status[data-loading="true"]::before {
      content: "";
      width: 12px;
      height: 12px;
      margin-right: 8px;
      border: 2px solid currentColor;
      border-right-color: transparent;
      border-radius: 999px;
      animation: spin 0.8s linear infinite;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    table {
      width: 100%;
      border-collapse: collapse;
    }
    th, td {
      padding: 7px 10px;
      text-align: left;
      border-bottom: 1px solid var(--line-soft);
      vertical-align: middle;
      white-space: nowrap;
    }
    th {
      background: var(--panel-soft);
      font-size: 11px;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      color: var(--muted);
      font-weight: 650;
    }
    tbody tr:hover {
      background: var(--panel-soft);
    }
    .mono {
      font-family: Consolas, "SFMono-Regular", monospace;
      font-size: 12px;
    }
    .muted {
      color: var(--muted);
      font-size: 12px;
    }
    .checks {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
      min-height: 32px;
    }
    .checks label {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      color: var(--text);
      font-size: 12px;
      text-transform: none;
    }
    .file-context {
      display: grid;
      gap: 8px;
      min-width: 0;
    }
    .context-line {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
      justify-content: space-between;
    }
    .account-pill {
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      padding: 3px 8px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--panel-soft);
      color: var(--text);
      font-size: 12px;
      font-weight: 650;
    }
    .directory-meta {
      color: var(--muted);
      font-size: 12px;
    }
    .path-bar {
      display: flex;
      align-items: center;
      gap: 3px;
      min-width: 0;
      min-height: 38px;
      padding: 5px;
      overflow-x: auto;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--panel-soft);
      scrollbar-width: thin;
    }
    .path-segment {
      flex: 0 0 auto;
      display: inline-flex;
      align-items: center;
      min-height: 26px;
      max-width: min(280px, 58vw);
      padding: 4px 8px;
      border: 1px solid transparent;
      border-radius: 5px;
      color: var(--link);
      font-weight: 600;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .path-segment:hover {
      border-color: var(--line);
      background: var(--panel);
      text-decoration: none;
    }
    .path-segment.is-current {
      border-color: var(--line);
      background: var(--panel);
      color: var(--text);
    }
    .path-separator {
      flex: 0 0 auto;
      color: var(--muted);
    }
    .selection-count {
      display: inline-flex;
      align-items: center;
      min-height: 26px;
      padding: 4px 6px;
      color: var(--muted);
      font-size: 12px;
    }
    .empty-state {
      padding: 40px 16px;
      text-align: center;
      color: var(--muted);
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #111418;
        --panel: #181c22;
        --panel-soft: #202630;
        --line: #323a46;
        --line-soft: #27303a;
        --text: #edf2f7;
        --muted: #a5b2c3;
        --link: #8ab4f8;
        --accent: #2dd4bf;
        --accent-soft: #123c38;
        --danger: #ffb4a9;
        --danger-soft: #471d1a;
        --shadow: none;
      }
    }
    @media (max-width: 900px) {
      body { padding: 8px; }
      .toolbar { display: grid; grid-template-columns: 1fr 1fr; justify-content: stretch; align-items: stretch; }
      .toolbar-group { width: 100%; }
      .toolbar-group.selection { border-left: 0; padding-left: 0; }
    }
    @media (max-width: 640px) {
      body { padding: 0; }
      main { min-height: 100vh; border: 0; border-radius: 0; }
      .app-topbar, .header-row, .toolbar { align-items: flex-start; }
      .app-topbar { display: grid; gap: 8px; }
      .app-nav { width: 100%; justify-content: flex-start; }
      .app-nav a { min-height: 34px; padding: 6px 10px; }
      .page-heading { padding: 12px; }
      .toolbar { grid-template-columns: 1fr; }
      .toolbar-group { width: 100%; }
      .toolbar-group > button,
      .toolbar-group > .file-input-label {
        flex: 1 1 120px;
      }
      .search-input { flex: 1 1 100%; min-width: 0; }
      .status { right: 10px; bottom: 10px; max-width: calc(100vw - 20px); }
      th, td { padding: 7px 8px; }
      h1 { font-size: 16px; }
    }`;
}

function renderAppTopbar(active: "files" | "users") {
  return `<div class="app-topbar">
        <div class="brand">WebDAV</div>
        <nav class="app-nav" aria-label="Primary">
          <a href="/" class="${active === "files" ? "is-active" : ""}">Files</a>
          <a href="${ADMIN_PREFIX}/users" class="${active === "users" ? "is-active" : ""}">Users</a>
          <a href="${ADMIN_PREFIX}/logout">Logout</a>
        </nav>
      </div>`;
}

function renderPathBar(auth: AuthContext, clientPath: string, itemCount: number) {
  const relativePath = auth.mountPath === "/" ? clientPath : stripPathPrefix(clientPath, auth.mountPath);
  const parts = relativePath.split("/").filter(Boolean);
  const isAdminFileView = auth.mountPath.startsWith(`${ADMIN_PREFIX}/files/`);
  const rootHref = auth.mountPath === "/" ? "/" : `${auth.mountPath}/`;
  const accountLabel = isAdminFileView ? `Managed files: ${auth.username}` : auth.username;
  const itemLabel = `${itemCount} ${itemCount === 1 ? "item" : "items"}`;
  const items = isAdminFileView
    ? [
        `<a class="path-segment" href="${ADMIN_PREFIX}/users">Users</a>`,
        `<span class="path-separator">/</span><a class="path-segment" href="${ADMIN_PREFIX}/files">Managed files</a>`,
        `<span class="path-separator">/</span><a class="path-segment ${parts.length === 0 ? "is-current" : ""}" href="${escapeHtml(rootHref)}" ${parts.length === 0 ? 'aria-current="page"' : ""}>${escapeHtml(auth.username)}</a>`,
      ]
    : [
        `<a class="path-segment ${parts.length === 0 ? "is-current" : ""}" href="${escapeHtml(rootHref)}" ${parts.length === 0 ? 'aria-current="page"' : ""}>Files</a>`,
      ];
  let current = "";
  for (const [index, part] of parts.entries()) {
    current = `${current}/${part}`;
    const href = auth.mountPath === "/" ? encodePathForHref(current) : `${auth.mountPath}${encodePathForHref(current)}`;
    const isCurrent = index === parts.length - 1;
    items.push(`<span class="path-separator">/</span><a class="path-segment ${isCurrent ? "is-current" : ""}" href="${escapeHtml(ensureHref(href, true))}" title="${escapeHtml(part)}" ${isCurrent ? 'aria-current="page"' : ""}>${escapeHtml(part)}</a>`);
  }
  return `<section class="file-context" aria-label="Current directory">
          <div class="context-line">
            <span class="account-pill">${escapeHtml(accountLabel)}</span>
            <span class="directory-meta">${escapeHtml(itemLabel)}</span>
          </div>
          <nav class="path-bar" aria-label="Directory path">${items.join("")}</nav>
        </section>`;
}

function renderResourceIcon(isCollection: boolean, label: string) {
  const title = isCollection ? "Directory" : label;
  const shape = isCollection
    ? `<path d="M3 6.5h6l1.5 2H21v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M3 6.5V5a2 2 0 0 1 2-2h4l1.5 2H19a2 2 0 0 1 2 2v1.5"/>`
    : `<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v5h4"/>`;
  return `<span class="file-icon" aria-label="${escapeHtml(title)}"><svg viewBox="0 0 24 24" aria-hidden="true">${shape}</svg></span>`;
}

function renderDirectoryListing(path: string, resources: ResourceInfo[], auth: AuthContext) {
  const clientPath = toClientPath(auth, path);
  const visiblePath = auth.mountPath === "/" ? clientPath : stripPathPrefix(clientPath, auth.mountPath);
  const isAdminFileView = auth.mountPath.startsWith(`${ADMIN_PREFIX}/files/`);
  const pageTitle = "Files";
  const pageSubtitle = isAdminFileView ? auth.username : "WebDAV file manager";
  const currentDirectoryHref = toClientHref(auth, path, true);
  const pathBar = renderPathBar(auth, clientPath, resources.length);
  const emptyRow = resources.length === 0
    ? `<tr><td colspan="5"><div class="empty-state">This directory is empty. Upload files or create a folder to start.</div></td></tr>`
    : "";
  const rows = resources
    .map((resource) => {
      const href = toClientHref(auth, resource.path, resource.isCollection);
      const name = resource.isCollection ? `${resource.name}/` : resource.name;
      const size = resource.isCollection ? "-" : formatSize(resource.size);
      const modified = resource.lastModified ? resource.lastModified.toISOString().replace("T", " ").replace("Z", " UTC") : "-";
      return `<tr data-href="${escapeHtml(href)}" data-name="${escapeHtml(resource.name)}" data-collection="${resource.isCollection ? "true" : "false"}" data-content-type="${escapeHtml(resource.contentType ?? "")}">
        <td><input type="checkbox" class="row-select" aria-label="Select ${escapeHtml(name)}"></td>
        <td class="name">
          <div class="name-cell">
            ${renderResourceIcon(resource.isCollection, "File")}
            <a class="name-text" href="${href}" title="${escapeHtml(name)}">${escapeHtml(name)}</a>
          </div>
        </td>
        <td class="mono">${size}</td>
        <td class="mono">${escapeHtml(modified)}</td>
        <td class="actions">
          <details class="action-menu">
            <summary aria-label="Actions for ${escapeHtml(name)}">Actions</summary>
            <div class="action-menu-panel">
              ${resource.isCollection ? "" : `<button type="button" data-action="edit">Edit</button>`}
              <button type="button" data-action="rename">Rename</button>
              <button type="button" data-action="move">Move</button>
              <button type="button" data-action="delete" class="danger">Delete</button>
            </div>
          </details>
        </td>
      </tr>`;
    })
    .join("");
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(pageTitle)}</title>
  <style>
    ${renderSharedStyles()}
    .file-app {
      max-width: 1380px;
      width: 100%;
      min-height: calc(100vh - 24px);
      overflow: visible;
      display: flex;
      flex-direction: column;
    }
    .file-app header {
      border-top-left-radius: 8px;
      border-top-right-radius: 8px;
      flex: 0 0 auto;
    }
    th {
      position: sticky;
      top: 0;
      z-index: 1;
    }
    th.actions-column,
    td.actions {
      width: 132px;
      min-width: 132px;
      text-align: right;
    }
    td.name {
      width: auto;
      white-space: normal;
      word-break: break-word;
    }
    .actions {
      display: flex;
      flex-wrap: nowrap;
      gap: 4px;
      white-space: nowrap;
      align-items: center;
      justify-content: flex-end;
      overflow: visible;
    }
    .actions .action-menu-panel {
      right: 0;
      left: auto;
      min-width: 148px;
    }
    .drop-target {
      outline: 2px solid var(--accent);
      outline-offset: -4px;
    }
    .search-input {
      min-width: min(260px, 100%);
    }
    .file-toolbar-label {
      color: var(--muted);
      font-size: 12px;
      padding-right: 2px;
    }
    input[type="text"], textarea {
      width: 100%;
    }
    textarea {
      min-height: 60vh;
      resize: vertical;
      font-family: Consolas, "SFMono-Regular", monospace;
      line-height: 1.45;
      font-size: 12px;
    }
    input[type="file"] {
      display: none;
    }
    .table-wrap {
      overflow-x: auto;
      overflow-y: visible;
      flex: 1 1 auto;
    }
    .file-list-header {
      border-top: 1px solid var(--line);
      border-bottom: 1px solid var(--line);
      padding: 10px 12px;
      background: var(--panel);
      flex: 0 0 auto;
    }
    .modal[hidden] {
      display: none;
    }
    .modal {
      position: fixed;
      inset: 0;
      background: rgba(12, 18, 31, 0.45);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }
    .modal-card {
      width: min(960px, 100%);
      max-height: calc(100vh - 48px);
      background: var(--panel);
      border-radius: 12px;
      border: 1px solid var(--line);
      box-shadow: 0 24px 60px rgba(10, 25, 55, 0.18);
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }
    .modal-header {
      padding: 12px 16px;
      border-bottom: 1px solid var(--line);
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
    }
    .modal-header h2 {
      margin: 0;
      font-size: 16px;
    }
    .modal-body {
      padding: 14px 16px 16px;
      overflow: auto;
      display: grid;
      gap: 10px;
    }
    .modal-footer {
      padding: 0 16px 16px;
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }
    .name-cell {
      display: flex;
      align-items: center;
      gap: 8px;
      min-width: 0;
    }
    .file-icon {
      min-width: 28px;
      height: 18px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border: 1px solid var(--line);
      border-radius: 4px;
      background: var(--panel-soft);
      text-align: center;
      color: var(--muted);
      flex: 0 0 auto;
      padding: 0 4px;
      line-height: 1;
    }
    .file-icon svg {
      width: 14px;
      height: 14px;
      fill: none;
      stroke: currentColor;
      stroke-width: 1.8;
      stroke-linecap: round;
      stroke-linejoin: round;
    }
    .name-text {
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .mono {
      font-family: Consolas, "SFMono-Regular", monospace;
      font-size: 12px;
    }
    @media (max-width: 720px) {
      .file-list-header {
        padding: 8px 10px;
      }
      .context-line {
        display: grid;
        gap: 4px;
        justify-content: stretch;
      }
      .account-pill,
      .directory-meta {
        width: fit-content;
      }
      .path-bar {
        min-height: 36px;
        padding: 4px;
      }
      .path-segment {
        max-width: min(220px, 70vw);
        min-height: 28px;
      }
      table, thead, tbody, tr, td {
        display: block;
      }
      thead {
        display: none;
      }
      tbody tr {
        position: relative;
        padding: 10px 10px 9px;
        border-bottom: 1px solid var(--line-soft);
      }
      td {
        border: 0;
        padding: 3px 0;
        white-space: normal;
      }
      td:first-child {
        position: absolute;
        top: 13px;
        left: 10px;
      }
      td.name {
        width: auto;
        padding-left: 28px;
        padding-right: 96px;
      }
      td.actions {
        position: absolute;
        top: 10px;
        right: 10px;
        width: auto;
        min-width: 0;
        text-align: right;
      }
      td.mono {
        padding-left: 28px;
        color: var(--muted);
        font-size: 11px;
      }
      .action-menu-panel {
        right: 0;
      }
      .name-cell {
        align-items: flex-start;
      }
      .name-text {
        white-space: normal;
        overflow-wrap: anywhere;
      }
    }
    @media (max-width: 640px) {
      .file-app { min-height: 100vh; }
      .table-wrap { max-height: none; overflow-x: visible; }
      .file-app header { border-radius: 0; }
      .file-toolbar-label { flex: 1 1 100%; }
      .selection-count { flex: 1 1 100%; }
    }
  </style>
</head>
<body>
  <main class="file-app">
    <header>
      ${renderAppTopbar(isAdminFileView ? "users" : "files")}
      <div class="page-heading">
        <div class="header-row">
          <div>
            <h1>${escapeHtml(pageTitle)}${pageSubtitle ? ` <span class="muted">${escapeHtml(pageSubtitle)}</span>` : ""}</h1>
          </div>
        </div>
        <div class="toolbar">
          <div class="toolbar-group">
          <span class="file-toolbar-label">Current folder</span>
          <label class="file-input-label primary" for="upload-input">Upload Files</label>
          <input id="upload-input" type="file" multiple>
          <button type="button" id="new-folder-button" class="primary">New Folder</button>
          </div>
          <div class="toolbar-group selection">
          <span id="selection-count" class="selection-count">0 selected</span>
          <button type="button" id="select-all-button">Select All</button>
          <button type="button" id="invert-selection-button">Invert</button>
          <button type="button" id="move-selected-button">Move Selected</button>
          <button type="button" id="delete-selected-button" class="danger">Delete Selected</button>
          </div>
          <div class="toolbar-group">
          <button type="button" id="refresh-button">Refresh</button>
          <input id="search-input" class="search-input" type="search" placeholder="Search files">
          </div>
        </div>
      </div>
    </header>
    <div id="status" class="status" role="status" aria-live="polite"></div>
    <div class="file-list-header">
      ${pathBar}
    </div>
    <section class="table-wrap">
      <table>
        <thead>
          <tr><th></th><th>Name</th><th>Size</th><th>Modified</th><th class="actions-column">Actions</th></tr>
        </thead>
        <tbody>${rows}${emptyRow}</tbody>
      </table>
    </section>
  </main>
  <div id="editor-modal" class="modal" hidden>
    <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="editor-title">
      <div class="modal-header">
        <h2 id="editor-title">Edit File</h2>
        <button type="button" id="close-editor-button">Close</button>
      </div>
      <div class="modal-body">
        <input id="editor-path" type="text" readonly value="">
        <textarea id="editor-content" placeholder="Select a text file and click Edit."></textarea>
        <p class="muted">Editor saves plain text back through WebDAV PUT. Suitable for text, JSON, scripts, config files and notes.</p>
      </div>
      <div class="modal-footer">
        <button type="button" id="save-editor-button" class="primary">Save File</button>
        <button type="button" id="clear-editor-button">Clear</button>
      </div>
    </div>
  </div>
  <script>
    const currentPath = ${safeJsonEmbed(visiblePath)};
    const currentDirectory = ${safeJsonEmbed(currentDirectoryHref)};
    const mountPath = ${safeJsonEmbed(auth.mountPath)};
    const statusEl = document.getElementById("status");
    const uploadInput = document.getElementById("upload-input");
    const newFolderButton = document.getElementById("new-folder-button");
    const selectAllButton = document.getElementById("select-all-button");
    const invertSelectionButton = document.getElementById("invert-selection-button");
    const moveSelectedButton = document.getElementById("move-selected-button");
    const deleteSelectedButton = document.getElementById("delete-selected-button");
    const selectionCount = document.getElementById("selection-count");
    const refreshButton = document.getElementById("refresh-button");
    const searchInput = document.getElementById("search-input");
    const editorModal = document.getElementById("editor-modal");
    const closeEditorButton = document.getElementById("close-editor-button");
    const editorPath = document.getElementById("editor-path");
    const editorContent = document.getElementById("editor-content");
    const saveEditorButton = document.getElementById("save-editor-button");
    const clearEditorButton = document.getElementById("clear-editor-button");
    const tableBody = document.querySelector("tbody");
    var RE_MULTI_SLASH = new RegExp("/{2,}", "g");
    var RE_TRAILING_SLASH = new RegExp("/+$");
    let editorDirty = false;
    let statusTimer = 0;

    function on(element, eventName, handler) {
      if (element) {
        element.addEventListener(eventName, handler);
      }
    }

    function encodePathForHref(path) {
      if (path === "/") {
        return "/";
      }
      return path.split("/").map((part, index) => index === 0 ? "" : encodeURIComponent(part)).join("/");
    }

    function mountedHref(path) {
      const encoded = encodePathForHref(path);
      if (mountPath === "/") {
        return encoded;
      }
      if (path === mountPath || path.startsWith(mountPath + "/")) {
        return encoded;
      }
      return (mountPath + encoded).replace(RE_MULTI_SLASH, "/");
    }

    function setStatus(message, tone = "") {
      if (!statusEl) {
        return;
      }
      if (!message) {
        statusEl.classList.remove("is-visible");
        statusEl.textContent = "";
        statusEl.dataset.tone = "";
        statusEl.dataset.loading = "false";
        return;
      }
      window.clearTimeout(statusTimer);
      statusEl.textContent = message;
      statusEl.dataset.tone = tone;
      statusEl.dataset.loading = /ing\\b|Loading|Uploading|Moving|Deleting|Saving|Creating/.test(message) ? "true" : "false";
      statusEl.classList.add("is-visible");
      if (tone !== "error" && statusEl.dataset.loading !== "true") {
        statusTimer = window.setTimeout(() => setStatus(""), 2400);
      }
    }

    function joinPath(baseHref, name) {
      const normalizedBase = baseHref.endsWith("/") ? baseHref : baseHref + "/";
      return normalizedBase + encodeURIComponent(name);
    }

    async function request(method, href, options = {}) {
      const headers = new Headers(options.headers || {});
      headers.set("X-Requested-With", "WebDAV-Admin");
      const response = await fetch(href, {
        method,
        headers,
        body: options.body,
      });
      if (!response.ok) {
        const text = await response.text();
        throw new Error(text || method + " " + href + " failed with " + response.status);
      }
      return response;
    }

    async function uploadFiles(files) {
      if (!files.length) {
        return;
      }
      setStatus("Uploading " + files.length + " file(s)...");
      for (const file of files) {
        const href = joinPath(currentDirectory, file.name);
        await request("PUT", href, {
          headers: {
            "Content-Type": file.type || "application/octet-stream",
          },
          body: file,
        });
      }
      setStatus("Upload completed.", "success");
      location.reload();
    }

    async function createFolder() {
      const name = window.prompt("Folder name");
      if (!name) {
        return;
      }
      setStatus("Creating folder " + name + "...");
      await request("MKCOL", joinPath(currentDirectory, name));
      setStatus("Folder created.", "success");
      location.reload();
    }

    function rowInfo(button) {
      const row = button.closest("tr");
      return {
        row,
        href: row.dataset.href,
        name: row.dataset.name,
        isCollection: row.dataset.collection === "true",
        contentType: row.dataset.contentType || "",
      };
    }

    function selectedRows() {
      return Array.from(document.querySelectorAll("tbody tr[data-href]")).filter((row) => row.querySelector(".row-select")?.checked);
    }

    function selectedItems() {
      return selectedRows().map((row) => ({
        row,
        href: row.dataset.href,
        name: row.dataset.name,
        isCollection: row.dataset.collection === "true",
      }));
    }

    function updateSelectionState() {
      const count = selectedRows().length;
      if (selectionCount) {
        selectionCount.textContent = count + " selected";
      }
      if (moveSelectedButton) {
        moveSelectedButton.disabled = count === 0;
      }
      if (deleteSelectedButton) {
        deleteSelectedButton.disabled = count === 0;
      }
    }

    async function renameResource(info) {
      const nextName = window.prompt("Rename to", info.name);
      if (!nextName || nextName === info.name) {
        return;
      }
      const destination = joinPath(currentDirectory, nextName);
      setStatus("Renaming " + info.name + "...");
      await request("MOVE", info.href, {
        headers: {
          Destination: new URL(destination, window.location.origin).toString(),
          Overwrite: "F",
        },
      });
      setStatus("Rename completed.", "success");
      location.reload();
    }

    function normalizeDestinationPath(input) {
      var trimmed = input.trim();
      if (!trimmed) {
        return null;
      }
      var withLeadingSlash = trimmed.startsWith("/") ? trimmed : "/" + trimmed;
      return withLeadingSlash.replace(RE_MULTI_SLASH, "/").replace(RE_TRAILING_SLASH, "") || "/";
    }

    function buildDestinationHref(destinationDirectory, name, isCollection) {
      var encoded = destinationDirectory === "/" ? (mountPath === "/" ? "" : mountPath) : mountedHref(destinationDirectory);
      var target = (encoded || "") + "/" + encodeURIComponent(name);
      return isCollection ? target.replace(RE_MULTI_SLASH, "/") + "/" : target.replace(RE_MULTI_SLASH, "/");
    }

    async function moveResource(info, destinationDirectory) {
      const destination = buildDestinationHref(destinationDirectory, info.name, info.isCollection);
      if (destination === info.href) {
        return;
      }
      setStatus("Moving " + info.name + "...");
      await request("MOVE", info.href, {
        headers: {
          Destination: new URL(destination, window.location.origin).toString(),
          Overwrite: "F",
        },
      });
    }

    async function promptMoveResource(info) {
      const destinationInput = window.prompt("Move to directory", currentPath);
      if (!destinationInput) {
        return;
      }
      const destinationDirectory = normalizeDestinationPath(destinationInput);
      if (!destinationDirectory) {
        return;
      }
      await moveResource(info, destinationDirectory);
      setStatus("Move completed.", "success");
      location.reload();
    }

    async function deleteResource(info) {
      const confirmed = window.confirm("Delete " + info.name + (info.isCollection ? "/ ?" : " ?"));
      if (!confirmed) {
        return;
      }
      setStatus("Deleting " + info.name + "...");
      await request("DELETE", info.href);
      setStatus("Delete completed.", "success");
      location.reload();
    }

    async function loadEditor(info) {
      setStatus("Loading " + info.name + "...");
      const response = await request("GET", info.href);
      const text = await response.text();
      editorPath.value = info.href;
      editorContent.value = text;
      editorDirty = false;
      if (editorModal) {
        editorModal.hidden = false;
      }
      setStatus("Loaded " + info.name + " into editor.", "success");
    }

    async function saveEditor() {
      if (!editorPath.value) {
        setStatus("No file selected for editing.", "error");
        return;
      }
      setStatus("Saving " + editorPath.value + "...");
      await request("PUT", editorPath.value, {
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
        },
        body: editorContent.value,
      });
      editorDirty = false;
      setStatus("File saved.", "success");
    }

    function clearEditor() {
      editorPath.value = "";
      editorContent.value = "";
      editorDirty = false;
      setStatus("Editor cleared.");
    }

    function closeEditor() {
      if (editorDirty && !window.confirm("Discard unsaved changes?")) {
        return;
      }
      if (editorModal) {
        editorModal.hidden = true;
      }
    }

    function toggleSelectAll() {
      const rows = Array.from(document.querySelectorAll(".row-select"));
      const shouldSelect = rows.some((input) => !input.checked);
      rows.forEach((input) => {
        input.checked = shouldSelect;
      });
      updateSelectionState();
      setStatus(shouldSelect ? "All items selected." : "Selection cleared.");
    }

    function invertSelection() {
      const rows = Array.from(document.querySelectorAll(".row-select"));
      rows.forEach((input) => {
        input.checked = !input.checked;
      });
      updateSelectionState();
      setStatus("Selection inverted.");
    }

    async function moveSelected() {
      const items = selectedItems();
      if (items.length === 0) {
        setStatus("No items selected.", "error");
        return;
      }
      const destinationInput = window.prompt("Move selected items to directory", currentPath);
      if (!destinationInput) {
        return;
      }
      const destinationDirectory = normalizeDestinationPath(destinationInput);
      if (!destinationDirectory) {
        return;
      }
      setStatus("Moving " + items.length + " item(s)...");
      for (const item of items) {
        await moveResource(item, destinationDirectory);
      }
      setStatus("Selected items moved.", "success");
      location.reload();
    }

    async function deleteSelected() {
      const items = selectedItems();
      if (items.length === 0) {
        setStatus("No items selected.", "error");
        return;
      }
      const confirmed = window.confirm("Delete " + items.length + " selected item(s)?");
      if (!confirmed) {
        return;
      }
      setStatus("Deleting " + items.length + " item(s)...");
      for (const item of items) {
        await request("DELETE", item.href);
      }
      setStatus("Selected items deleted.", "success");
      location.reload();
    }

    on(uploadInput, "change", async () => {
      try {
        await uploadFiles(Array.from(uploadInput.files || []));
      } catch (error) {
        setStatus(error instanceof Error ? error.message : "Upload failed.", "error");
      } finally {
        uploadInput.value = "";
      }
    });
    document.addEventListener("dragover", (event) => {
      event.preventDefault();
      document.body.classList.add("drop-target");
      setStatus("Drop files to upload.");
    });
    document.addEventListener("dragleave", (event) => {
      if (event.target === document.body || event.clientX <= 0 || event.clientY <= 0) {
        document.body.classList.remove("drop-target");
      }
    });
    document.addEventListener("drop", async (event) => {
      event.preventDefault();
      document.body.classList.remove("drop-target");
      const files = Array.from(event.dataTransfer?.files || []);
      try {
        await uploadFiles(files);
      } catch (error) {
        setStatus(error instanceof Error ? error.message : "Upload failed.", "error");
      }
    });

    on(newFolderButton, "click", async () => {
      try {
        await createFolder();
      } catch (error) {
        setStatus(error instanceof Error ? error.message : "Folder creation failed.", "error");
      }
    });

    on(selectAllButton, "click", toggleSelectAll);
    on(invertSelectionButton, "click", invertSelection);
    on(moveSelectedButton, "click", async () => {
      try {
        await moveSelected();
      } catch (error) {
        setStatus(error instanceof Error ? error.message : "Move failed.", "error");
      }
    });
    on(deleteSelectedButton, "click", async () => {
      try {
        await deleteSelected();
      } catch (error) {
        setStatus(error instanceof Error ? error.message : "Delete failed.", "error");
      }
    });
    on(refreshButton, "click", () => location.reload());
    on(tableBody, "change", (event) => {
      if (event.target instanceof Element && event.target.matches(".row-select")) {
        updateSelectionState();
      }
    });
    on(searchInput, "input", () => {
      const query = searchInput.value.trim().toLowerCase();
      document.querySelectorAll("tbody tr[data-href]").forEach((row) => {
        const name = (row.dataset.name || "").toLowerCase();
        row.hidden = query.length > 0 && !name.includes(query);
      });
    });
    on(closeEditorButton, "click", closeEditor);
    on(editorContent, "input", () => {
      editorDirty = true;
    });
    document.addEventListener("keydown", async (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "s" && editorModal && !editorModal.hidden) {
        event.preventDefault();
        try {
          await saveEditor();
        } catch (error) {
          setStatus(error instanceof Error ? error.message : "Save failed.", "error");
        }
      }
    });
    window.addEventListener("beforeunload", (event) => {
      if (editorDirty) {
        event.preventDefault();
        event.returnValue = "";
      }
    });
    on(saveEditorButton, "click", async () => {
      try {
        await saveEditor();
      } catch (error) {
        setStatus(error instanceof Error ? error.message : "Save failed.", "error");
      }
    });
    on(clearEditorButton, "click", clearEditor);

    on(tableBody, "click", async (event) => {
      if (!(event.target instanceof Element)) {
        return;
      }
      const button = event.target.closest("button[data-action]");
      if (!button) {
        return;
      }
      const info = rowInfo(button);
      try {
        button.closest("details")?.removeAttribute("open");
        if (button.dataset.action === "edit") {
          await loadEditor(info);
          return;
        }
        if (button.dataset.action === "rename") {
          await renameResource(info);
          return;
        }
        if (button.dataset.action === "move") {
          await promptMoveResource(info);
          return;
        }
        if (button.dataset.action === "delete") {
          await deleteResource(info);
        }
      } catch (error) {
        setStatus(error instanceof Error ? error.message : "Action failed.", "error");
      }
    });

    updateSelectionState();
  </script>
</body>
</html>`;
}

function validateSameOrigin(request: Request) {
  const requestUrl = new URL(request.url);
  const origin = request.headers.get("Origin");
  if (origin) {
    try {
      return new URL(origin).origin === requestUrl.origin;
    } catch {
      return false;
    }
  }

  const referer = request.headers.get("Referer");
  if (referer) {
    try {
      return new URL(referer).origin === requestUrl.origin;
    } catch {
      return false;
    }
  }

  const secFetchSite = request.headers.get("Sec-Fetch-Site");
  if (secFetchSite === "same-origin") {
    return true;
  }

  return request.headers.get("X-Requested-With") === "WebDAV-Admin";
}

function requiresAdminCsrfCheck(method: string) {
  return CSRF_PROTECTED_METHODS.has(method);
}

function shouldShowRootAdmin(request: Request, clientPath: string) {
  const method = request.method.toUpperCase();
  if (clientPath !== "/" || (method !== "GET" && method !== "HEAD")) {
    return false;
  }
  if (request.headers.has("Authorization")) {
    return false;
  }
  const accept = request.headers.get("Accept") || "";
  return accept.includes("text/html") || accept.includes("*/*");
}

async function authenticateRequest(request: Request, env: Env): Promise<AuthContext | null> {
  const credentials = parseBasicAuth(request);
  if (!credentials) {
    return null;
  }

  const adminUser = env.ADMIN_AUTH_USER || env.BASIC_AUTH_USER;
  const adminPass = env.ADMIN_AUTH_PASS || env.BASIC_AUTH_PASS;
  if (adminUser && adminPass && timingSafeEquals(credentials.user, adminUser) && timingSafeEquals(credentials.pass, adminPass)) {
    return {
      username: credentials.user,
      isAdmin: true,
      root: "/",
      mountPath: "/",
      permissions: new Set(["read", "write", "delete"]),
    };
  }

  const response = await userStub(env).fetch("https://users/authenticate", {
    method: "POST",
    body: JSON.stringify({
      username: credentials.user,
      password: credentials.pass,
      rateLimitKey: rateLimitKey(request, credentials.user),
    }),
  });
  const result = (await response.json()) as {
    ok: boolean;
    status?: number;
    retryAfter?: number;
    user?: {
      username: string;
      root: string;
      permissions: Permission[];
      enabled: boolean;
    };
  };

  if (result.status === 429) {
    return {
      username: credentials.user,
      isAdmin: false,
      root: "/",
      mountPath: "/",
      permissions: new Set(),
      retryAfter: result.retryAfter ?? 300,
    };
  }

  if (!result.ok || !result.user?.enabled) {
    return null;
  }

  return {
    username: result.user.username,
    isAdmin: false,
    root: normalizeRootPath(result.user.root),
    mountPath: "/",
    permissions: new Set(result.user.permissions),
  };
}

async function authenticateAdminRequest(request: Request, env: Env): Promise<AuthContext | null> {
  const verifiedAccessEmail = await verifyAccessJwt(request, env);
  const allowedEmail = env.ACCESS_ADMIN_EMAIL;
  if (verifiedAccessEmail && allowedEmail && timingSafeEquals(verifiedAccessEmail.toLowerCase(), allowedEmail.toLowerCase())) {
    return adminAuthContext(verifiedAccessEmail);
  }
  if (hasAccessJwtConfig(env)) {
    return null;
  }

  const accessEmail = request.headers.get("Cf-Access-Authenticated-User-Email");
  if (accessEmail && allowedEmail && timingSafeEquals(accessEmail.toLowerCase(), allowedEmail.toLowerCase())) {
    return adminAuthContext(accessEmail);
  }

  return authenticateAdminBasicRequest(request, env);
}

async function authenticateAdminBasicRequest(request: Request, env: Env): Promise<AuthContext | null> {
  const credentials = parseBasicAuth(request);
  if (!credentials) {
    return null;
  }

  const adminUser = env.ADMIN_AUTH_USER || env.BASIC_AUTH_USER;
  const adminPass = env.ADMIN_AUTH_PASS || env.BASIC_AUTH_PASS;
  if (adminUser && adminPass && timingSafeEquals(credentials.user, adminUser) && timingSafeEquals(credentials.pass, adminPass)) {
    return adminAuthContext(credentials.user);
  }

  return null;
}

async function verifyAccessJwt(request: Request, env: Env) {
  if (!hasAccessJwtConfig(env)) {
    return null;
  }
  const teamDomain = normalizeAccessTeamDomain(env.ACCESS_TEAM_DOMAIN!);
  const expectedAud = env.ACCESS_AUD!;
  const token = request.headers.get("Cf-Access-Jwt-Assertion");
  if (!token) {
    return null;
  }
  const parts = token.split(".");
  if (parts.length !== 3) {
    return null;
  }

  try {
    const header = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[0]))) as { alg?: string; kid?: string };
    if (header.alg !== "RS256" || !header.kid) {
      return null;
    }
    const keys = await getAccessJwks(teamDomain);
    const jwk = keys.find((key) => key.kid === header.kid);
    if (!jwk) {
      return null;
    }
    const key = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
    const verified = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      key,
      base64UrlDecode(parts[2]),
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
    );
    if (!verified) {
      return null;
    }
    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[1]))) as AccessJwtPayload;
    const now = Math.floor(Date.now() / 1000);
    if ((payload.exp && payload.exp <= now) || (payload.nbf && payload.nbf > now)) {
      return null;
    }
    const expectedIssuer = teamDomain;
    if (payload.iss !== expectedIssuer) {
      return null;
    }
    const audiences = Array.isArray(payload.aud) ? payload.aud : payload.aud ? [payload.aud] : [];
    if (!audiences.includes(expectedAud)) {
      return null;
    }
    return typeof payload.email === "string" ? payload.email : null;
  } catch {
    return null;
  }
}

function hasAccessJwtConfig(env: Env) {
  return Boolean(env.ACCESS_TEAM_DOMAIN && env.ACCESS_AUD);
}

async function getAccessJwks(teamDomain: string) {
  const url = `${teamDomain}/cdn-cgi/access/certs`;
  const now = Date.now();
  if (accessJwksCache?.url === url && accessJwksCache.expiresAt > now) {
    return accessJwksCache.keys;
  }
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error("Unable to fetch Access certificates");
  }
  const result = (await response.json()) as { keys?: AccessJsonWebKey[] };
  const keys = result.keys || [];
  accessJwksCache = { url, keys, expiresAt: now + ACCESS_JWKS_CACHE_TTL_MS };
  return keys;
}

function normalizeAccessTeamDomain(value: string) {
  const trimmed = value.trim().replace(/\/+$/, "");
  return trimmed.startsWith("https://") ? trimmed : `https://${trimmed}`;
}

function adminAuthContext(username: string): AuthContext {
  return {
    username,
    isAdmin: true,
    root: "/",
    mountPath: "/",
    permissions: new Set(["read", "write", "delete"]),
  };
}

function parseBasicAuth(request: Request) {
  const auth = request.headers.get("Authorization");
  if (!auth?.startsWith("Basic ")) {
    return null;
  }

  let decoded: string;
  try {
    decoded = atob(auth.slice(6));
  } catch {
    return null;
  }
  const index = decoded.indexOf(":");
  if (index === -1) {
    return null;
  }

  return {
    user: decoded.slice(0, index),
    pass: decoded.slice(index + 1),
  };
}

function userStub(env: Env) {
  return env.USERS.get(env.USERS.idFromName("global-user-manager"));
}

function rateLimitKey(request: Request, username: string) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown-ip";
  return `${ip}|${username.toLowerCase()}`;
}

async function recordAdminAudit(env: Env, actor: string, action: string, target = "") {
  await userStub(env).fetch("https://users/audit", {
    method: "POST",
    body: JSON.stringify({ actor, action, target }),
  });
}

function auditTargetFromBody(body: string) {
  try {
    const parsed = JSON.parse(body) as { username?: unknown };
    return typeof parsed.username === "string" ? parsed.username : "";
  } catch {
    return "";
  }
}

function requirePermission(auth: AuthContext, permission: Permission) {
  if (auth.permissions.has(permission)) {
    return null;
  }
  return new Response("Forbidden", { status: 403, headers: baseHeaders() });
}

async function handleAdminRequest(request: Request, env: Env, auth: AuthContext, path: string) {
  if (!auth.isAdmin) {
    return new Response("Forbidden", { status: 403, headers: baseHeaders() });
  }

  const method = request.method.toUpperCase();
  if (requiresAdminCsrfCheck(method) && !validateSameOrigin(request)) {
    return new Response("CSRF check failed", { status: 403, headers: baseHeaders() });
  }

  if (method === "GET" && path === `${ADMIN_PREFIX}/logout`) {
    if (request.headers.get("Cf-Access-Authenticated-User-Email") || request.headers.get("Cf-Access-Jwt-Assertion")) {
      return Response.redirect(new URL("/cdn-cgi/access/logout", request.url), 302);
    }
    return new Response("Logged out", {
      status: 401,
      headers: {
        ...baseHeaders(),
        "WWW-Authenticate": 'Basic realm="Cloudflare WebDAV Logout"',
      },
    });
  }

  if (method === "GET" && path === `${ADMIN_PREFIX}/logout/access`) {
    return Response.redirect(new URL("/cdn-cgi/access/logout", request.url), 302);
  }

  if (method === "GET" && (path === ADMIN_PREFIX || path === `${ADMIN_PREFIX}/users`)) {
    const body = renderAdminUsersPage();
    return new Response(body, {
      status: 200,
      headers: htmlHeaders(),
    });
  }

  if (path === `${ADMIN_PREFIX}/api/users` && method === "GET") {
    return proxyUserManager(env, "/users", "GET");
  }

  if (path === `${ADMIN_PREFIX}/api/audit` && method === "GET") {
    return proxyUserManager(env, "/audit", "GET");
  }

  if (path === `${ADMIN_PREFIX}/api/users/create` && method === "POST") {
    const body = await request.text();
    await recordAdminAudit(env, auth.username, "user.create", auditTargetFromBody(body));
    return proxyUserManager(env, "/users/create", "POST", body);
  }

  if (path === `${ADMIN_PREFIX}/api/users/update` && method === "POST") {
    const body = await request.text();
    await recordAdminAudit(env, auth.username, "user.update", auditTargetFromBody(body));
    return proxyUserManager(env, "/users/update", "POST", body);
  }

  if (path === `${ADMIN_PREFIX}/api/users/reset-password` && method === "POST") {
    const body = await request.text();
    await recordAdminAudit(env, auth.username, "user.reset-password", auditTargetFromBody(body));
    return proxyUserManager(env, "/users/reset-password", "POST", body);
  }

  if (path === `${ADMIN_PREFIX}/api/users/reveal-password` && method === "POST") {
    const body = await request.text();
    await recordAdminAudit(env, auth.username, "user.reveal-password", auditTargetFromBody(body));
    return proxyUserManager(env, "/users/reveal-password", "POST", body);
  }

  if (path === `${ADMIN_PREFIX}/api/users/delete` && method === "POST") {
    const body = await request.text();
    await recordAdminAudit(env, auth.username, "user.delete", auditTargetFromBody(body));
    return proxyUserManager(env, "/users/delete", "POST", body);
  }

  if (path === `${ADMIN_PREFIX}/files` || path.startsWith(`${ADMIN_PREFIX}/files/`)) {
    return handleAdminFilesRequest(request, env, path);
  }

  return new Response("Not found", { status: 404, headers: baseHeaders() });
}

async function handleAdminFilesRequest(request: Request, env: Env, path: string) {
  const relative = stripPathPrefix(path, `${ADMIN_PREFIX}/files`);
  const parts = relative.split("/").filter(Boolean);
  const username = parts.shift();
  if (!username) {
    const firstUser = await getFirstManagedUser(env);
    const target = firstUser ? `${ADMIN_PREFIX}/files/${encodeURIComponent(firstUser.username)}/` : `${ADMIN_PREFIX}/users`;
    return Response.redirect(new URL(target, request.url), 302);
  }

  const user = await getManagedUser(env, username);
  if (!user?.enabled) {
    return new Response("User not found", { status: 404, headers: baseHeaders() });
  }

  const clientPath = parts.length === 0 ? "/" : `/${parts.join("/")}`;
  const auth = managedUserFileAuth(user, `${ADMIN_PREFIX}/files/${encodeURIComponent(user.username)}`);
  const resourcePath = toStoragePath(auth, clientPath);

  switch (request.method.toUpperCase()) {
    case "OPTIONS":
      return handleOptions();
    case "PROPFIND":
      return handlePropfind(request, env, auth, resourcePath);
    case "GET":
    case "HEAD":
      return handleGetLike(request, env, auth, resourcePath);
    case "PUT":
      return handlePut(request, env, auth, resourcePath);
    case "DELETE":
      return handleDelete(request, env, auth, resourcePath);
    case "MKCOL":
      return handleMkcol(request, env, auth, resourcePath);
    case "MOVE":
      return handleMove(request, env, auth, resourcePath);
    case "COPY":
      return handleCopy(request, env, auth, resourcePath);
    case "LOCK":
      return handleLock(request, env, auth, resourcePath);
    case "UNLOCK":
      return handleUnlock(request, env, auth, resourcePath);
    default:
      return new Response("Method Not Allowed", { status: 405, headers: baseHeaders() });
  }
}

async function getFirstManagedUser(env: Env) {
  const response = await userStub(env).fetch("https://users/users");
  const result = (await response.json()) as {
    ok: boolean;
    users?: Array<{
      username: string;
      root: string;
      permissions: Permission[];
      enabled: boolean;
    }>;
  };
  return result.users?.find((user) => user.enabled) ?? null;
}

async function getManagedUser(env: Env, username: string) {
  const response = await userStub(env).fetch("https://users/users");
  const result = (await response.json()) as {
    ok: boolean;
    users?: Array<{
      username: string;
      root: string;
      permissions: Permission[];
      enabled: boolean;
    }>;
  };
  return result.users?.find((user) => user.username === username) ?? null;
}

function managedUserFileAuth(
  user: { username: string; root: string; permissions: Permission[] },
  mountPath: string,
): AuthContext {
  return {
    username: user.username,
    isAdmin: false,
    root: normalizeRootPath(user.root),
    mountPath,
    permissions: new Set(user.permissions),
  };
}

async function proxyUserManager(env: Env, path: string, method: string, body?: string) {
  const response = await userStub(env).fetch(`https://users${path}`, { method, body });
  return new Response(response.body, {
    status: response.status,
    headers: {
      ...baseHeaders(),
      "Content-Type": response.headers.get("Content-Type") || "application/json",
    },
  });
}

function renderAdminUsersPage() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WebDAV Admin</title>
  <style>
    ${renderSharedStyles()}
    .form {
      padding: 14px 16px;
      border-bottom: 1px solid var(--line);
      display: grid;
      grid-template-columns: minmax(140px, 1fr) minmax(220px, 2fr) minmax(140px, 1fr) auto;
      gap: 8px;
      align-items: end;
    }
    .field { display: grid; gap: 4px; }
    label { color: var(--muted); font-size: 11px; text-transform: uppercase; }
    td.actions { display: flex; gap: 4px; flex-wrap: wrap; align-items: center; }
    td.permission-cell { min-width: 210px; white-space: normal; }
    .admin-table-wrap {
      overflow-x: auto;
    }
    .admin-grid {
      display: grid;
      gap: 0;
    }
    .password-box {
      margin: 14px 16px;
      padding: 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--panel-soft);
      display: none;
      gap: 8px;
    }
    .password-box.is-visible { display: grid; }
    .password-row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
    .audit-section {
      border-top: 1px solid var(--line);
      padding: 14px 16px 16px;
      display: grid;
      gap: 10px;
    }
    .audit-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }
    .audit-header h2 {
      margin: 0;
      font-size: 15px;
    }
    code {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 5px 7px;
      word-break: break-all;
    }
    @media (max-width: 980px) {
      .form {
        grid-template-columns: minmax(160px, 1fr) minmax(220px, 1fr);
      }
      .form button {
        width: fit-content;
      }
    }
    @media (max-width: 760px) {
      .form { grid-template-columns: 1fr; }
    }
    @media (max-width: 680px) {
      .admin-table-wrap {
        overflow-x: visible;
      }
      .admin-table thead {
        display: none;
      }
      .admin-table,
      .admin-table tbody,
      .admin-table tr,
      .admin-table td {
        display: block;
        width: 100%;
      }
      .admin-table tr {
        padding: 10px 12px;
        border-bottom: 1px solid var(--line-soft);
      }
      .admin-table td {
        border: 0;
        padding: 4px 0;
        white-space: normal;
      }
      .admin-table td::before {
        content: attr(data-label);
        display: block;
        margin-bottom: 2px;
        color: var(--muted);
        font-size: 10px;
        text-transform: uppercase;
      }
      .admin-table td.actions {
        display: flex;
        gap: 6px;
        padding-top: 8px;
      }
      .admin-table td.actions::before {
        flex: 1 1 100%;
      }
      td.permission-cell {
        min-width: 0;
      }
      .password-row button,
      .audit-header button,
      .form button {
        width: 100%;
      }
    }
  </style>
</head>
<body>
  <main>
    <header>
      ${renderAppTopbar("users")}
      <div class="page-heading">
        <div class="header-row">
          <div>
            <h1>WebDAV Admin</h1>
            <p>Users and managed files</p>
          </div>
          <div class="toolbar">
            <div class="toolbar-group">
              <button type="button" id="files-button">Managed Files</button>
              <button type="button" id="refresh-button">Refresh</button>
            </div>
          </div>
        </div>
      </div>
    </header>
    <div id="status" class="status" role="status" aria-live="polite"></div>
    <section class="form">
      <div class="field">
        <label for="username">Username</label>
        <input id="username" autocomplete="off" placeholder="joplin">
      </div>
      <div class="field">
        <label>Permissions</label>
        <div class="checks">
          <label><input type="checkbox" id="perm-read" checked> Read</label>
          <label><input type="checkbox" id="perm-write" checked> Write</label>
          <label><input type="checkbox" id="perm-delete" checked> Delete</label>
        </div>
      </div>
      <div class="field">
        <label for="password">Password</label>
        <input id="password" autocomplete="new-password" placeholder="auto-generate">
      </div>
      <button type="button" id="create-button" class="primary">Create User</button>
    </section>
    <section id="password-box" class="password-box">
      <strong>Password</strong>
      <div class="password-row">
        <code id="generated-password"></code>
        <button type="button" id="toggle-password-button">Show</button>
        <button type="button" id="copy-password-button">Copy</button>
      </div>
    </section>
    <div class="admin-grid">
      <section class="admin-table-wrap">
        <table class="admin-table">
          <thead>
            <tr>
              <th>User</th><th>Directory</th><th>Permissions</th><th>Enabled</th><th>Last Used</th><th>Actions</th>
            </tr>
          </thead>
          <tbody id="users-body"></tbody>
        </table>
      </section>
      <section class="audit-section">
        <div class="audit-header">
          <div>
            <h2>Audit Log</h2>
            <p>Recent sensitive account actions.</p>
          </div>
          <button type="button" id="refresh-audit-button">Refresh Audit</button>
        </div>
        <div class="admin-table-wrap">
          <table class="admin-table audit-table">
            <thead>
              <tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th></tr>
            </thead>
            <tbody id="audit-body"></tbody>
          </table>
        </div>
      </section>
    </div>
  </main>
  <script>
    const statusEl = document.getElementById("status");
    const usersBody = document.getElementById("users-body");
    const auditBody = document.getElementById("audit-body");
    const passwordBox = document.getElementById("password-box");
    const generatedPassword = document.getElementById("generated-password");
    const togglePasswordButton = document.getElementById("toggle-password-button");
    let currentPassword = "";
    let passwordVisible = false;
    let statusTimer = 0;

    function setStatus(message, tone = "") {
      if (!message) {
        statusEl.classList.remove("is-visible");
        statusEl.textContent = "";
        statusEl.dataset.tone = "";
        statusEl.dataset.loading = "false";
        return;
      }
      window.clearTimeout(statusTimer);
      statusEl.textContent = message;
      statusEl.dataset.tone = tone;
      statusEl.dataset.loading = /ing\\b|Loading|Saving|Creating|Resetting|Deleting/.test(message) ? "true" : "false";
      statusEl.classList.add("is-visible");
      if (tone !== "error" && statusEl.dataset.loading !== "true") {
        statusTimer = window.setTimeout(() => setStatus(""), 2400);
      }
    }

    async function api(path, options = {}) {
      const response = await fetch("/_admin/api" + path, {
        method: options.method || "GET",
        headers: { "Content-Type": "application/json", "X-Requested-With": "WebDAV-Admin" },
        body: options.body ? JSON.stringify(options.body) : undefined,
      });
      const result = await response.json();
      if (!result.ok) {
        throw new Error(result.message || "Request failed");
      }
      return result;
    }

    function permissionsFromForm() {
      return [
        document.getElementById("perm-read").checked ? "read" : "",
        document.getElementById("perm-write").checked ? "write" : "",
        document.getElementById("perm-delete").checked ? "delete" : "",
      ].filter(Boolean);
    }

    function fmtTime(value) {
      return value ? new Date(value).toLocaleString() : "-";
    }

    function showPassword(password) {
      currentPassword = password || "";
      passwordVisible = false;
      generatedPassword.textContent = "*".repeat(Math.min(Math.max(currentPassword.length, 12), 48));
      togglePasswordButton.textContent = "Show";
      passwordBox.classList.add("is-visible");
    }

    function togglePasswordVisibility() {
      passwordVisible = !passwordVisible;
      generatedPassword.textContent = passwordVisible ? currentPassword : "*".repeat(Math.min(Math.max(currentPassword.length, 12), 48));
      togglePasswordButton.textContent = passwordVisible ? "Hide" : "Show";
    }

    function permissionChecks(user) {
      const permissions = new Set(user.permissions || []);
      return '<div class="checks">' +
        '<label><input type="checkbox" data-permission="read"' + (permissions.has("read") ? " checked" : "") + '> Read</label>' +
        '<label><input type="checkbox" data-permission="write"' + (permissions.has("write") ? " checked" : "") + '> Write</label>' +
        '<label><input type="checkbox" data-permission="delete"' + (permissions.has("delete") ? " checked" : "") + '> Delete</label>' +
      '</div>';
    }

    function rowPermissions(row) {
      return Array.from(row.querySelectorAll("[data-permission]"))
        .filter((input) => input.checked)
        .map((input) => input.dataset.permission);
    }

    async function copyText(value, label) {
      await navigator.clipboard.writeText(value);
      setStatus(label + " copied.", "success");
    }

    async function loadUsers() {
      setStatus("Loading users...");
      const result = await api("/users");
      usersBody.innerHTML = result.users.map((user) => {
        return '<tr data-user="' + escapeHtml(user.username) + '">' +
          '<td class="mono" data-label="User">' + escapeHtml(user.username) + '</td>' +
          '<td class="mono" data-label="Directory">' + escapeHtml(user.root) + '</td>' +
          '<td class="permission-cell" data-label="Permissions">' + permissionChecks(user) + '</td>' +
          '<td data-label="Enabled"><select data-field="enabled"><option value="true"' + (user.enabled ? " selected" : "") + '>yes</option><option value="false"' + (!user.enabled ? " selected" : "") + '>no</option></select></td>' +
          '<td class="mono" data-label="Last Used">' + escapeHtml(fmtTime(user.lastUsedAt)) + '</td>' +
          '<td class="actions" data-label="Actions">' +
            '<button data-action="save" class="primary">Save</button>' +
            '<details class="action-menu"><summary>Actions</summary><div class="action-menu-panel">' +
              '<button data-action="files">Files</button>' +
              '<button data-action="copy-user">Copy User</button>' +
              '<button data-action="copy-password">Copy Password</button>' +
              '<button data-action="reset">Reset Password</button>' +
              '<button data-action="delete" class="danger">Delete</button>' +
            '</div></details>' +
          '</td>' +
        '</tr>';
      }).join("");
      setStatus("Users loaded.", "success");
    }

    async function loadAudit() {
      const result = await api("/audit");
      auditBody.innerHTML = result.events.length ? result.events.map((event) => {
        return '<tr>' +
          '<td class="mono" data-label="Time">' + escapeHtml(fmtTime(event.ts)) + '</td>' +
          '<td class="mono" data-label="Actor">' + escapeHtml(event.actor) + '</td>' +
          '<td data-label="Action">' + escapeHtml(event.action) + '</td>' +
          '<td class="mono" data-label="Target">' + escapeHtml(event.target || "-") + '</td>' +
        '</tr>';
      }).join("") : '<tr><td colspan="4"><div class="empty-state">No audit events yet.</div></td></tr>';
    }

    function escapeHtml(value) {
      return String(value).replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
    }

    document.getElementById("files-button").addEventListener("click", () => {
      const firstUser = usersBody.querySelector("tr[data-user]")?.dataset.user;
      window.location.href = firstUser ? "/_admin/files/" + encodeURIComponent(firstUser) + "/" : "/";
    });
    document.getElementById("refresh-button").addEventListener("click", () => {
      Promise.all([loadUsers(), loadAudit()]).catch((error) => setStatus(error.message, "error"));
    });
    document.getElementById("refresh-audit-button").addEventListener("click", () => {
      loadAudit().catch((error) => setStatus(error.message, "error"));
    });
    document.getElementById("copy-password-button").addEventListener("click", async () => {
      await copyText(currentPassword, "Password");
    });
    togglePasswordButton.addEventListener("click", () => {
      togglePasswordVisibility();
    });
    document.getElementById("create-button").addEventListener("click", async () => {
      try {
        const username = document.getElementById("username").value;
        const password = document.getElementById("password").value;
        const result = await api("/users/create", {
          method: "POST",
          body: {
            username,
            permissions: permissionsFromForm(),
            password: password || undefined,
          },
        });
        showPassword(result.password);
        document.getElementById("username").value = "";
        document.getElementById("password").value = "";
        setStatus("User created.", "success");
        await loadUsers();
        await loadAudit();
      } catch (error) {
        setStatus(error instanceof Error ? error.message : "Create failed.", "error");
      }
    });

    usersBody.addEventListener("click", async (event) => {
      const button = event.target.closest("button[data-action]");
      if (!button) {
        return;
      }
      const row = button.closest("tr");
      const username = row.dataset.user;
      try {
        button.closest("details")?.removeAttribute("open");
        if (button.dataset.action === "save") {
          await api("/users/update", {
            method: "POST",
            body: {
              username,
              permissions: rowPermissions(row),
              enabled: row.querySelector('[data-field="enabled"]').value === "true",
            },
          });
          setStatus("User saved.", "success");
          await loadUsers();
          await loadAudit();
        }
        if (button.dataset.action === "files") {
          window.location.href = "/_admin/files/" + encodeURIComponent(username) + "/";
          return;
        }
        if (button.dataset.action === "copy-user") {
          await copyText(username, "Username");
          return;
        }
        if (button.dataset.action === "copy-password") {
          const result = await api("/users/reveal-password", { method: "POST", body: { username } });
          showPassword(result.password);
          await copyText(result.password, "Password");
          await loadAudit();
          return;
        }
        if (button.dataset.action === "reset") {
          if (!window.confirm("Reset password for " + username + "?")) {
            return;
          }
          const result = await api("/users/reset-password", { method: "POST", body: { username } });
          showPassword(result.password);
          setStatus("Password reset.", "success");
          await loadAudit();
        }
        if (button.dataset.action === "delete") {
          if (!window.confirm("Delete user " + username + "?")) {
            return;
          }
          await api("/users/delete", { method: "POST", body: { username } });
          setStatus("User deleted.", "success");
          await loadUsers();
          await loadAudit();
        }
      } catch (error) {
        setStatus(error instanceof Error ? error.message : "Action failed.", "error");
      }
    });

    Promise.all([loadUsers(), loadAudit()]).catch((error) => setStatus(error.message, "error"));
  </script>
</body>
</html>`;
}

function parseRangeHeader(rangeHeader: string | null, size: number): R2Range | null | { error: true } {
  if (!rangeHeader) {
    return null;
  }
  if (size === 0) {
    return { error: true };
  }

  const match = rangeHeader.match(/^bytes=(\d*)-(\d*)$/i);
  if (!match) {
    return { error: true };
  }

  const [, startRaw, endRaw] = match;
  if (startRaw === "" && endRaw === "") {
    return { error: true };
  }

  if (startRaw === "") {
    const suffix = Number.parseInt(endRaw, 10);
    if (!Number.isFinite(suffix) || suffix <= 0) {
      return { error: true };
    }
    return suffix >= size ? { offset: 0, length: size } : { suffix };
  }

  const start = Number.parseInt(startRaw, 10);
  const end = endRaw === "" ? size - 1 : Number.parseInt(endRaw, 10);
  if (!Number.isFinite(start) || !Number.isFinite(end) || start < 0 || end < start || start >= size) {
    return { error: true };
  }

  return {
    offset: start,
    length: Math.min(end, size - 1) - start + 1,
  };
}

function resolveContentRange(
  requestedRange: R2Range | null | { error: true },
  returnedRange: R2Range | undefined,
  size: number,
) {
  if (!requestedRange || "error" in requestedRange) {
    return null;
  }

  if (returnedRange) {
    if ("suffix" in returnedRange) {
      const length = Math.min(returnedRange.suffix, size);
      return { start: size - length, end: size - 1, length };
    }
    const start = returnedRange.offset ?? 0;
    const length = returnedRange.length ?? Math.max(size - start, 0);
    return { start, end: start + length - 1, length };
  }

  if ("suffix" in requestedRange) {
    const length = Math.min(requestedRange.suffix, size);
    return { start: size - length, end: size - 1, length };
  }

  const start = requestedRange.offset ?? 0;
  const length = requestedRange.length ?? Math.max(size - start, 0);
  return { start, end: start + length - 1, length };
}

function isInvalidRange(value: R2Range | null | { error: true }): value is { error: true } {
  return value !== null && "error" in value;
}
