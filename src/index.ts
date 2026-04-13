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
  contentType: string | null;
}

export { WebDavLockManager };

class HttpError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

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
      if (error instanceof HttpError) {
        return new Response(error.message, {
          status: error.status,
          headers: baseHeaders(),
        });
      }
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
  const depth = request.headers.get("Depth") ?? "1";
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
  const resource = await statPath(env, path);
  if (!resource) {
    return new Response("Not found", { status: 404, headers: baseHeaders() });
  }

  if (resource.isCollection) {
    const children = await listChildren(env, path);
    const body = renderDirectoryListing(path, children, request.headers.get("Authorization") ?? "");
    const headers = new Headers(baseHeaders());
    headers.set("Content-Type", "text/html; charset=utf-8");
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

async function handlePut(request: Request, env: Env, path: string) {
  if (path === "/") {
    return new Response("Cannot write root", { status: 409, headers: baseHeaders() });
  }

  const lockCheck = await ensureUnlocked(env, path, request.headers.get("If"));
  if (lockCheck) {
    return lockCheck;
  }

  await ensureParentsCreated(env, parentPath(path));
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
  if (source.isCollection && isSameOrDescendantPath(sourcePath, destination)) {
    return new Response("Bad destination", { status: 409, headers: baseHeaders() });
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
  const headers = new Headers(baseHeaders());
  headers.set("Lock-Token", `<${result.token}>`);
  headers.set("Content-Type", 'application/xml; charset="utf-8"');

  return new Response(lockDiscoveryXml(path, result.token, owner, result.expiresAt, depth, target?.isCollection ?? false), {
    status: target ? 200 : 201,
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
    throw new HttpError(409, `Parent collection does not exist: ${path}`);
  }
}

async function ensureParentsCreated(env: Env, path: string) {
  if (path === "/") {
    return;
  }
  const existing = await statPath(env, path);
  if (existing?.isCollection) {
    return;
  }
  await ensureParentsCreated(env, parentPath(path));
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
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    throw new HttpError(400, "Invalid path");
  }
  const parts = decoded.split("/").filter(Boolean);
  for (const part of parts) {
    if (part === "." || part === "..") {
      throw new HttpError(400, "Invalid path");
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
      const contentType = resource.contentType ?? (resource.isCollection ? "httpd/unix-directory" : "application/octet-stream");
      const resourceType = resource.isCollection ? "<D:collection/>" : "";
      const etag = resource.etag ? `<D:getetag>${escapeXml(resource.etag)}</D:getetag>` : "";
      return `
  <D:response>
    <D:href>${escapeXml(encodePathForHref(resource.href))}</D:href>
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
      <D:lockroot><D:href>${escapeXml(encodePathForHref(ensureHref(path, isCollection)))}</D:href></D:lockroot>
    </D:activelock>
  </D:lockdiscovery>
</D:prop>`;
}

function renderDirectoryListing(path: string, resources: ResourceInfo[], authHeader: string) {
  const title = path === "/" ? "/" : path;
  const currentDirectoryHref = encodePathForHref(ensureHref(path, true));
  const rows = resources
    .map((resource) => {
      const href = encodePathForHref(resource.href);
      const name = resource.isCollection ? `${resource.name}/` : resource.name;
      const size = resource.isCollection ? "-" : formatSize(resource.size);
      const modified = resource.lastModified ? resource.lastModified.toISOString().replace("T", " ").replace("Z", " UTC") : "-";
      const icon = resource.isCollection ? "DIR" : "FILE";
      return `<tr data-href="${escapeHtml(href)}" data-name="${escapeHtml(resource.name)}" data-collection="${resource.isCollection ? "true" : "false"}" data-content-type="${escapeHtml(resource.contentType ?? "")}">
        <td><input type="checkbox" class="row-select" aria-label="Select ${escapeHtml(name)}"></td>
        <td class="name">
          <div class="name-cell">
            <span class="file-icon">${icon}</span>
            <a class="name-text" href="${href}" title="${escapeHtml(name)}">${escapeHtml(name)}</a>
          </div>
        </td>
        <td class="mono">${size}</td>
        <td class="mono">${escapeHtml(modified)}</td>
        <td class="actions">
          <button type="button" data-action="open" title="Open">Open</button>
          ${resource.isCollection ? "" : `<button type="button" data-action="edit" title="Edit">Edit</button>`}
          <button type="button" data-action="rename" title="Rename">Ren</button>
          <button type="button" data-action="move" title="Move">Move</button>
          <button type="button" data-action="delete" class="danger" title="Delete">Del</button>
        </td>
      </tr>`;
    })
    .join("");
  const parentRow = path === "/"
    ? ""
    : `<tr><td></td><td class="name"><div class="name-cell"><span class="file-icon">UP</span><a class="name-text parent-link" href="${encodePathForHref(parentDirectoryHref(path))}">Parent Directory</a></div></td><td class="mono">-</td><td class="mono">-</td><td class="actions"></td></tr>`;

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Index of ${escapeHtml(title)}</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f7fb;
      --panel: #ffffff;
      --line: #d7ddea;
      --line-soft: #e8edf5;
      --text: #152033;
      --muted: #5a6b84;
      --link: #0a5bd8;
      --accent: #0f766e;
      --accent-soft: #d8f3f0;
      --danger: #b42318;
      --danger-soft: #fde6e4;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 12px;
      background: linear-gradient(180deg, #eef3ff 0%, #f7f9fd 100%);
      color: var(--text);
      font: 13px/1.35 "Segoe UI", system-ui, sans-serif;
    }
    main {
      max-width: 1380px;
      margin: 0 auto 0 0;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 10px;
      overflow: hidden;
      box-shadow: 0 10px 28px rgba(10, 25, 55, 0.06);
    }
    header {
      padding: 12px 16px 10px;
      border-bottom: 1px solid var(--line);
      background: linear-gradient(180deg, #fbfdff 0%, #f5f8fd 100%);
    }
    .toolbar {
      display: flex;
      flex-wrap: wrap;
      gap: 8px 12px;
      margin-top: 8px;
    }
    .toolbar-group {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      align-items: center;
    }
    h1 {
      margin: 0 0 2px;
      font-size: 18px;
      line-height: 1.15;
      font-weight: 600;
    }
    p {
      margin: 0;
      color: var(--muted);
      word-break: break-all;
      font-size: 12px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
    }
    th, td {
      padding: 6px 10px;
      text-align: left;
      border-bottom: 1px solid var(--line-soft);
      vertical-align: middle;
      white-space: nowrap;
    }
    th {
      position: sticky;
      top: 0;
      z-index: 1;
      background: #f7f9fc;
      font-size: 11px;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      color: var(--muted);
      font-weight: 600;
    }
    tbody tr:hover {
      background: #f8fbff;
    }
    tbody tr:nth-child(even) {
      background: #fcfdff;
    }
    td.name {
      width: 46%;
      white-space: normal;
      word-break: break-word;
    }
    td.actions {
      width: 20%;
      min-width: 220px;
    }
    a {
      color: var(--link);
      text-decoration: none;
    }
    a:hover {
      text-decoration: underline;
    }
    button, input[type="text"], textarea, select {
      font: inherit;
    }
    button, .file-input-label {
      appearance: none;
      border: 1px solid var(--line);
      background: #fff;
      color: var(--text);
      border-radius: 6px;
      padding: 2px 7px;
      cursor: pointer;
      font-size: 11px;
      line-height: 1.2;
    }
    button.primary {
      border-color: var(--accent);
      background: var(--accent);
      color: #fff;
    }
    button.danger {
      border-color: #efb4ae;
      color: var(--danger);
      background: #fff;
    }
    .actions {
      display: flex;
      flex-wrap: nowrap;
      gap: 4px;
      white-space: nowrap;
      align-items: center;
    }
    .status {
      padding: 7px 12px;
      border-bottom: 1px solid var(--line);
      color: var(--muted);
      min-height: 34px;
      display: flex;
      align-items: center;
      font-size: 12px;
    }
    .status[data-tone="success"] {
      background: var(--accent-soft);
      color: #0b5f59;
    }
    .status[data-tone="error"] {
      background: var(--danger-soft);
      color: var(--danger);
    }
    input[type="text"], textarea {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px 10px;
      background: #fff;
      color: var(--text);
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
    .muted {
      color: var(--muted);
      font-size: 12px;
    }
    .table-wrap {
      overflow-x: auto;
      max-height: calc(100vh - 180px);
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
      background: #fff;
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
      background: #f7f9fc;
      text-align: center;
      color: var(--muted);
      flex: 0 0 auto;
      padding: 0 4px;
      font-size: 9px;
      font-weight: 700;
      line-height: 1;
    }
    .name-text {
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .parent-link {
      display: inline-block;
      padding: 2px 0;
      font-weight: 600;
    }
    .mono {
      font-family: Consolas, "SFMono-Regular", monospace;
      font-size: 12px;
    }
    .row-select {
      width: 14px;
      height: 14px;
      margin: 0;
    }
    @media (max-width: 640px) {
      body { padding: 6px; }
      th, td { padding: 6px 8px; }
      h1 { font-size: 16px; }
      .table-wrap { max-height: none; }
    }
  </style>
</head>
<body>
  <main>
    <header>
      <h1>Index of ${escapeHtml(title)}</h1>
      <p>WebDAV file manager</p>
      <div class="toolbar">
        <div class="toolbar-group">
          <button type="button" id="home-button">Home</button>
          <label class="file-input-label" for="upload-input">Upload Files</label>
          <input id="upload-input" type="file" multiple>
          <button type="button" id="new-folder-button">New Folder</button>
          <button type="button" id="select-all-button">Select All</button>
          <button type="button" id="invert-selection-button">Invert</button>
          <button type="button" id="move-selected-button">Move Selected</button>
          <button type="button" id="delete-selected-button" class="danger">Delete Selected</button>
          <button type="button" id="refresh-button">Refresh</button>
        </div>
      </div>
    </header>
    <div id="status" class="status">Ready.</div>
    <section class="table-wrap">
      <table>
        <thead>
          <tr><th></th><th>Name</th><th>Size</th><th>Modified</th><th>Actions</th></tr>
        </thead>
        <tbody>${parentRow}${rows}</tbody>
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
    const currentPath = ${safeJsonEmbed(path)};
    const currentDirectory = ${safeJsonEmbed(currentDirectoryHref)};
    const authHeader = ${safeJsonEmbed(authHeader)};
    const statusEl = document.getElementById("status");
    const homeButton = document.getElementById("home-button");
    const uploadInput = document.getElementById("upload-input");
    const newFolderButton = document.getElementById("new-folder-button");
    const selectAllButton = document.getElementById("select-all-button");
    const invertSelectionButton = document.getElementById("invert-selection-button");
    const moveSelectedButton = document.getElementById("move-selected-button");
    const deleteSelectedButton = document.getElementById("delete-selected-button");
    const refreshButton = document.getElementById("refresh-button");
    const editorModal = document.getElementById("editor-modal");
    const closeEditorButton = document.getElementById("close-editor-button");
    const editorPath = document.getElementById("editor-path");
    const editorContent = document.getElementById("editor-content");
    const saveEditorButton = document.getElementById("save-editor-button");
    const clearEditorButton = document.getElementById("clear-editor-button");
    const tableBody = document.querySelector("tbody");

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

    function setStatus(message, tone = "") {
      if (!statusEl) {
        return;
      }
      statusEl.textContent = message;
      statusEl.dataset.tone = tone;
    }

    function joinPath(baseHref, name) {
      const normalizedBase = baseHref.endsWith("/") ? baseHref : baseHref + "/";
      return normalizedBase + encodeURIComponent(name);
    }

    async function request(method, href, options = {}) {
      const headers = new Headers(options.headers || {});
      if (authHeader) {
        headers.set("Authorization", authHeader);
      }
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

    var RE_MULTI_SLASH = new RegExp("/{2,}", "g");
    var RE_TRAILING_SLASH = new RegExp("/+$");

    function normalizeDestinationPath(input) {
      var trimmed = input.trim();
      if (!trimmed) {
        return null;
      }
      var withLeadingSlash = trimmed.startsWith("/") ? trimmed : "/" + trimmed;
      return withLeadingSlash.replace(RE_MULTI_SLASH, "/").replace(RE_TRAILING_SLASH, "") || "/";
    }

    function buildDestinationHref(destinationDirectory, name, isCollection) {
      var encoded = destinationDirectory === "/" ? "" : encodePathForHref(destinationDirectory);
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
      setStatus("File saved.", "success");
      location.reload();
    }

    function clearEditor() {
      editorPath.value = "";
      editorContent.value = "";
      setStatus("Editor cleared.");
    }

    function closeEditor() {
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
      setStatus(shouldSelect ? "All items selected." : "Selection cleared.");
    }

    function invertSelection() {
      const rows = Array.from(document.querySelectorAll(".row-select"));
      rows.forEach((input) => {
        input.checked = !input.checked;
      });
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

    on(homeButton, "click", () => {
      window.location.href = "/";
    });

    on(uploadInput, "change", async () => {
      try {
        await uploadFiles(Array.from(uploadInput.files || []));
      } catch (error) {
        setStatus(error instanceof Error ? error.message : "Upload failed.", "error");
      } finally {
        uploadInput.value = "";
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
    on(closeEditorButton, "click", closeEditor);
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
        if (button.dataset.action === "open") {
          window.location.href = info.href;
          return;
        }
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

    setStatus("UI ready.");
  </script>
</body>
</html>`;
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

  let decoded: string;
  try {
    decoded = atob(auth.slice(6));
  } catch {
    return false;
  }
  const index = decoded.indexOf(":");
  if (index === -1) {
    return false;
  }

  const user = decoded.slice(0, index);
  const pass = decoded.slice(index + 1);
  const userMatches = timingSafeEquals(user, env.BASIC_AUTH_USER);
  const passMatches = timingSafeEquals(pass, env.BASIC_AUTH_PASS);
  return userMatches && passMatches;
}

function escapeXml(value: string) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function escapeHtml(value: string) {
  return escapeXml(value);
}

function safeJsonEmbed(value: string) {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}

function timingSafeEquals(left: string, right: string) {
  const encoder = new TextEncoder();
  const a = encoder.encode(left);
  const b = encoder.encode(right);
  let mismatch = a.length !== b.length ? 1 : 0;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    mismatch |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return mismatch === 0;
}

function encodePathForHref(path: string) {
  if (path === "/") {
    return "/";
  }
  return path
    .split("/")
    .map((part, index) => (index === 0 ? "" : encodeURIComponent(part)))
    .join("/");
}

function parentDirectoryHref(path: string) {
  const parent = parentPath(path);
  return ensureHref(parent, true);
}

function formatSize(size: number) {
  if (size < 1024) {
    return `${size} B`;
  }
  const units = ["KB", "MB", "GB", "TB"];
  let value = size;
  let unitIndex = -1;
  do {
    value /= 1024;
    unitIndex += 1;
  } while (value >= 1024 && unitIndex < units.length - 1);
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[unitIndex]}`;
}

function isSameOrDescendantPath(sourcePath: string, destinationPath: string) {
  return destinationPath === sourcePath || destinationPath.startsWith(withTrailingSlash(sourcePath));
}

function withTrailingSlash(path: string) {
  return path.endsWith("/") ? path : `${path}/`;
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
