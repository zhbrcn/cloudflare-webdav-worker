import { WebDavLockManager } from "./lock-do";

const DIR_MARKER = "._cf_webdav_dir";
const XML_NS = "DAV:";

interface Env {
  WEBDAV_BUCKET: R2Bucket;
  LOCKS: DurableObjectNamespace;
  BASIC_AUTH_USER: string;
  BASIC_AUTH_PASS: string;
}

interface ResourceInfo {
  href: string;
  name: string;
  path: string;
  key: string | null;
  isCollection: boolean;
  size: number;
  etag: string | null;
  lastModified: Date | null;
}

export { WebDavLockManager };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      if (!isAuthorized(request, env)) {
        return new Response("Unauthorized", {
          status: 401,
          headers: {
            "WWW-Authenticate": 'Basic realm="Cloudflare WebDAV"',
          },
        });
      }

      const url = new URL(request.url);
      const resourcePath = normalizeRequestPath(url.pathname);

      switch (request.method.toUpperCase()) {
        case "OPTIONS":
          return handleOptions();
        case "PROPFIND":
          return handlePropfind(request, env, resourcePath);
        case "GET":
        case "HEAD":
          return handleGetLike(request, env, resourcePath);
        case "PUT":
          return handlePut(request, env, resourcePath);
        case "DELETE":
          return handleDelete(request, env, resourcePath);
        case "MKCOL":
          return handleMkcol(request, env, resourcePath);
        case "MOVE":
          return handleMove(request, env, resourcePath);
        case "COPY":
          return handleCopy(request, env, resourcePath);
        case "LOCK":
          return handleLock(request, env, resourcePath);
        case "UNLOCK":
          return handleUnlock(request, env, resourcePath);
        default:
          return new Response("Method Not Allowed", {
            status: 405,
            headers: baseHeaders(),
          });
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "Internal error";
      return new Response(message, {
        status: 500,
        headers: baseHeaders(),
      });
    }
  },
};

function handleOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      ...baseHeaders(),
      Allow: "OPTIONS, PROPFIND, GET, HEAD, PUT, DELETE, MKCOL, MOVE, COPY, LOCK, UNLOCK",
      DAV: "1, 2",
      "MS-Author-Via": "DAV",
    },
  });
}

async function handlePropfind(request: Request, env: Env, path: string) {
  const depth = request.headers.get("Depth") ?? "0";
  if (depth !== "0" && depth !== "1") {
    return new Response("Depth not supported", { status: 400, headers: baseHeaders() });
  }

  const resource = await statPath(env, path);
  if (!resource) {
    return new Response("Not found", { status: 404, headers: baseHeaders() });
  }

  const resources: ResourceInfo[] = [resource];
  if (depth === "1" && resource.isCollection) {
    resources.push(...(await listChildren(env, path)));
  }

  return xmlResponse(multistatusXml(resources), 207);
}

async function handleGetLike(request: Request, env: Env, path: string) {
  if (path === "/") {
    return new Response("Collection listing requires PROPFIND", {
      status: 405,
      headers: baseHeaders(),
    });
  }

  const object = await env.WEBDAV_BUCKET.get(toObjectKey(path));
  if (!object) {
    return new Response("Not found", { status: 404, headers: baseHeaders() });
  }

  const headers = new Headers(baseHeaders());
  headers.set("ETag", object.httpEtag);
  headers.set("Content-Length", String(object.size));
  headers.set("Last-Modified", object.uploaded.toUTCString());
  headers.set("Content-Type", object.httpMetadata?.contentType || "application/octet-stream");

  if (request.method.toUpperCase() === "HEAD") {
    return new Response(null, { status: 200, headers });
  }

  return new Response(object.body, { status: 200, headers });
}

async function handlePut(request: Request, env: Env, path: string) {
  if (path === "/") {
    return new Response("Cannot write root", { status: 409, headers: baseHeaders() });
  }

  const lockCheck = await ensureUnlocked(env, path, request.headers.get("If"));
  if (lockCheck) {
    return lockCheck;
  }

  await ensureParentExists(env, parentPath(path));
  const existing = await env.WEBDAV_BUCKET.head(toObjectKey(path));
  await env.WEBDAV_BUCKET.put(toObjectKey(path), request.body, {
    httpMetadata: {
      contentType: request.headers.get("Content-Type") ?? undefined,
    },
  });

  return new Response(null, {
    status: existing ? 204 : 201,
    headers: baseHeaders(),
  });
}

async function handleDelete(request: Request, env: Env, path: string) {
  if (path === "/") {
    return new Response("Cannot delete root", { status: 403, headers: baseHeaders() });
  }

  const target = await statPath(env, path);
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

  return new Response(null, { status: 204, headers: baseHeaders() });
}

async function handleMkcol(request: Request, env: Env, path: string) {
  if (path === "/") {
    return new Response("Collection exists", { status: 405, headers: baseHeaders() });
  }

  if (request.headers.get("Content-Length") && request.headers.get("Content-Length") !== "0") {
    return new Response("MKCOL body not supported", { status: 415, headers: baseHeaders() });
  }

  const existing = await statPath(env, path);
  if (existing) {
    return new Response("Already exists", { status: 405, headers: baseHeaders() });
  }

  const lockCheck = await ensureUnlocked(env, path, request.headers.get("If"));
  if (lockCheck) {
    return lockCheck;
  }

  await ensureParentExists(env, parentPath(path));
  await writeDirMarker(env, path);
  return new Response(null, { status: 201, headers: baseHeaders() });
}

async function handleMove(request: Request, env: Env, sourcePath: string) {
  const destination = parseDestination(request, request.url);
  if (!destination) {
    return new Response("Bad destination", { status: 400, headers: baseHeaders() });
  }
  if (destination === "/") {
    return new Response("Bad destination", { status: 409, headers: baseHeaders() });
  }

  const overwrite = (request.headers.get("Overwrite") ?? "T").toUpperCase() !== "F";
  const source = await statPath(env, sourcePath);
  if (!source) {
    return new Response("Not found", { status: 404, headers: baseHeaders() });
  }

  const sourceLock = await ensureUnlocked(env, sourcePath, request.headers.get("If"), source.isCollection);
  if (sourceLock) {
    return sourceLock;
  }

  const destinationLock = await ensureUnlocked(env, destination, request.headers.get("If"), source.isCollection);
  if (destinationLock) {
    return destinationLock;
  }

  const destinationExists = await statPath(env, destination);
  if (destinationExists && !overwrite) {
    return new Response("Destination exists", { status: 412, headers: baseHeaders() });
  }

  if (destinationExists) {
    if (destinationExists.isCollection) {
      await deleteCollection(env, destination);
    } else {
      await env.WEBDAV_BUCKET.delete(destinationExists.key!);
    }
  }

  await ensureParentExists(env, parentPath(destination));
  if (source.isCollection) {
    await copyCollection(env, sourcePath, destination);
    await deleteCollection(env, sourcePath);
  } else {
    const object = await env.WEBDAV_BUCKET.get(source.key!);
    if (!object) {
      return new Response("Not found", { status: 404, headers: baseHeaders() });
    }
    await env.WEBDAV_BUCKET.put(toObjectKey(destination), object.body, {
      httpMetadata: object.httpMetadata,
    });
    await env.WEBDAV_BUCKET.delete(source.key!);
  }

  return new Response(null, {
    status: destinationExists ? 204 : 201,
    headers: baseHeaders(),
  });
}

async function handleCopy(request: Request, env: Env, sourcePath: string) {
  const destination = parseDestination(request, request.url);
  if (!destination) {
    return new Response("Bad destination", { status: 400, headers: baseHeaders() });
  }
  if (destination === "/") {
    return new Response("Bad destination", { status: 409, headers: baseHeaders() });
  }

  const overwrite = (request.headers.get("Overwrite") ?? "T").toUpperCase() !== "F";
  const source = await statPath(env, sourcePath);
  if (!source) {
    return new Response("Not found", { status: 404, headers: baseHeaders() });
  }

  const destinationLock = await ensureUnlocked(env, destination, request.headers.get("If"), source.isCollection);
  if (destinationLock) {
    return destinationLock;
  }

  const destinationExists = await statPath(env, destination);
  if (destinationExists && !overwrite) {
    return new Response("Destination exists", { status: 412, headers: baseHeaders() });
  }

  if (destinationExists) {
    if (destinationExists.isCollection) {
      await deleteCollection(env, destination);
    } else {
      await env.WEBDAV_BUCKET.delete(destinationExists.key!);
    }
  }

  await ensureParentExists(env, parentPath(destination));
  if (source.isCollection) {
    await copyCollection(env, sourcePath, destination);
  } else {
    const object = await env.WEBDAV_BUCKET.get(source.key!);
    if (!object) {
      return new Response("Not found", { status: 404, headers: baseHeaders() });
    }
    await env.WEBDAV_BUCKET.put(toObjectKey(destination), object.body, {
      httpMetadata: object.httpMetadata,
    });
  }

  return new Response(null, {
    status: destinationExists ? 204 : 201,
    headers: baseHeaders(),
  });
}

async function handleLock(request: Request, env: Env, path: string) {
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

  const target = await statPath(env, path);
  if (!target && path !== "/") {
    await ensureParentExists(env, parentPath(path));
    await writeDirMarker(env, path);
  }

  const headers = new Headers(baseHeaders());
  headers.set("Lock-Token", `<${result.token}>`);
  headers.set("Content-Type", 'application/xml; charset="utf-8"');

  return new Response(lockDiscoveryXml(path, result.token, owner, result.expiresAt), {
    status: refreshToken ? 200 : 200,
    headers,
  });
}

async function handleUnlock(request: Request, env: Env, path: string) {
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

  return new Response(null, { status: result.status, headers: baseHeaders() });
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
    };
  }

  return null;
}

async function listChildren(env: Env, path: string): Promise<ResourceInfo[]> {
  const prefix = path === "/" ? "" : toCollectionPrefix(path);
  const listing = await env.WEBDAV_BUCKET.list({
    prefix,
    delimiter: "/",
    limit: 1000,
  });

  const items: ResourceInfo[] = [];

  for (const childPrefix of listing.delimitedPrefixes) {
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
    });
  }

  items.sort((a, b) => a.href.localeCompare(b.href));
  return items;
}

async function ensureParentExists(env: Env, path: string) {
  if (path === "/") {
    return;
  }
  const parent = await statPath(env, path);
  if (!parent || !parent.isCollection) {
    throw new Error(`Parent collection does not exist: ${path}`);
  }
}

async function writeDirMarker(env: Env, path: string) {
  await env.WEBDAV_BUCKET.put(dirMarkerKey(path), "");
}

async function deleteCollection(env: Env, path: string) {
  const prefix = toCollectionPrefix(path);
  let cursor: string | undefined;
  do {
    const listing = await env.WEBDAV_BUCKET.list({ prefix, cursor });
    for (const object of listing.objects) {
      await env.WEBDAV_BUCKET.delete(object.key);
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

function normalizeRequestPath(pathname: string) {
  const decoded = decodeURIComponent(pathname);
  const parts = decoded.split("/").filter(Boolean);
  for (const part of parts) {
    if (part === "." || part === "..") {
      throw new Error("Invalid path");
    }
  }
  return parts.length === 0 ? "/" : `/${parts.join("/")}`;
}

function toObjectKey(path: string) {
  return path.replace(/^\/+/, "");
}

function toCollectionPrefix(path: string) {
  const key = toObjectKey(path);
  return key.endsWith("/") ? key : `${key}/`;
}

function dirMarkerKey(path: string) {
  const prefix = toCollectionPrefix(path);
  return `${prefix}${DIR_MARKER}`;
}

function parentPath(path: string) {
  if (path === "/") {
    return "/";
  }
  const parts = path.split("/").filter(Boolean);
  parts.pop();
  return parts.length === 0 ? "/" : `/${parts.join("/")}`;
}

function basename(path: string) {
  const parts = path.split("/").filter(Boolean);
  return parts[parts.length - 1] ?? "";
}

function ensureHref(path: string, isCollection: boolean) {
  if (path === "/") {
    return "/";
  }
  return isCollection ? `${path}/` : path;
}

function prefixToPath(prefix: string) {
  const normalized = prefix.endsWith("/") ? prefix.slice(0, -1) : prefix;
  return normalized ? `/${normalized}` : "/";
}

function multistatusXml(resources: ResourceInfo[]) {
  const responses = resources
    .map((resource) => {
      const modified = resource.lastModified ? resource.lastModified.toUTCString() : "";
      const length = resource.isCollection ? "0" : String(resource.size);
      const contentType = resource.isCollection ? "httpd/unix-directory" : "application/octet-stream";
      const resourceType = resource.isCollection ? "<D:collection/>" : "";
      const etag = resource.etag ? `<D:getetag>${escapeXml(resource.etag)}</D:getetag>` : "";
      return `
  <D:response>
    <D:href>${escapeXml(resource.href)}</D:href>
    <D:propstat>
      <D:prop>
        <D:displayname>${escapeXml(resource.name)}</D:displayname>
        <D:resourcetype>${resourceType}</D:resourcetype>
        <D:getcontentlength>${length}</D:getcontentlength>
        <D:getcontenttype>${contentType}</D:getcontenttype>
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

function lockDiscoveryXml(path: string, token: string, owner: string | null, expiresAt: number) {
  const timeout = Math.max(0, Math.floor((expiresAt - Date.now()) / 1000));
  return `<?xml version="1.0" encoding="utf-8"?>
<D:prop xmlns:D="${XML_NS}">
  <D:lockdiscovery>
    <D:activelock>
      <D:locktype><D:write/></D:locktype>
      <D:lockscope><D:exclusive/></D:lockscope>
      <D:depth>Infinity</D:depth>
      <D:owner>${escapeXml(owner ?? "")}</D:owner>
      <D:timeout>Second-${timeout}</D:timeout>
      <D:locktoken><D:href>${escapeXml(token)}</D:href></D:locktoken>
      <D:lockroot><D:href>${escapeXml(ensureHref(path, true))}</D:href></D:lockroot>
    </D:activelock>
  </D:lockdiscovery>
</D:prop>`;
}

function xmlResponse(body: string, status: number) {
  return new Response(body, {
    status,
    headers: {
      ...baseHeaders(),
      "Content-Type": 'application/xml; charset="utf-8"',
    },
  });
}

function baseHeaders() {
  return {
    DAV: "1, 2",
    "MS-Author-Via": "DAV",
    "Cache-Control": "no-store",
  };
}

function isAuthorized(request: Request, env: Env) {
  const auth = request.headers.get("Authorization");
  if (!auth?.startsWith("Basic ")) {
    return false;
  }

  const decoded = atob(auth.slice(6));
  const index = decoded.indexOf(":");
  if (index === -1) {
    return false;
  }

  const user = decoded.slice(0, index);
  const pass = decoded.slice(index + 1);
  return user === env.BASIC_AUTH_USER && pass === env.BASIC_AUTH_PASS;
}

function escapeXml(value: string) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}
