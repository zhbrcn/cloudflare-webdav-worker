import { DIR_MARKER } from "./constants";
import { HttpError } from "./errors";
import type { AuthContext } from "./types";
import { basename, encodePathForHref, ensureHref, parentPath, withTrailingSlash } from "./utils";

export function normalizeRequestPath(pathname: string) {
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

export function toObjectKey(path: string) {
  return path.replace(/^\/+/, "");
}

export function toCollectionPrefix(path: string) {
  const key = toObjectKey(path);
  return key.endsWith("/") ? key : `${key}/`;
}

export function dirMarkerKey(path: string) {
  const prefix = toCollectionPrefix(path);
  return `${prefix}${DIR_MARKER}`;
}

export function prefixToPath(prefix: string) {
  const normalized = prefix.endsWith("/") ? prefix.slice(0, -1) : prefix;
  return normalized ? `/${normalized}` : "/";
}

export function toStoragePath(auth: AuthContext, clientPath: string) {
  if (auth.root === "/") {
    return clientPath;
  }
  if (clientPath === auth.mountPath) {
    return auth.root;
  }
  const relativePath = stripPathPrefix(clientPath, auth.mountPath);
  return joinNormalizedPath(auth.root, relativePath);
}

export function toClientPath(auth: AuthContext, storagePath: string) {
  if (auth.root === "/") {
    return storagePath;
  }
  if (storagePath === auth.root) {
    return auth.mountPath;
  }
  const prefix = withTrailingSlash(auth.root);
  if (storagePath.startsWith(prefix)) {
    return joinNormalizedPath(auth.mountPath, `/${storagePath.slice(prefix.length)}`);
  }
  return auth.mountPath;
}

export function toClientHref(auth: AuthContext, storagePath: string, isCollection: boolean) {
  return encodePathForHref(ensureHref(toClientPath(auth, storagePath), isCollection));
}

export function isVisibleRoot(auth: AuthContext, storagePath: string) {
  return storagePath === auth.root;
}

export function resolveMountPath(auth: AuthContext, clientPath: string) {
  if (auth.root === "/") {
    return "/";
  }
  if (clientPath === auth.root || clientPath.startsWith(withTrailingSlash(auth.root))) {
    return auth.root;
  }
  return "/";
}

export function stripPathPrefix(path: string, prefix: string) {
  if (prefix === "/") {
    return path;
  }
  if (path === prefix) {
    return "/";
  }
  const withSlash = withTrailingSlash(prefix);
  if (path.startsWith(withSlash)) {
    return `/${path.slice(withSlash.length)}`;
  }
  return path;
}

export function joinNormalizedPath(base: string, child: string) {
  if (base === "/") {
    return child;
  }
  if (child === "/") {
    return base;
  }
  return `${base}${child}`;
}

export function normalizeRootPath(value: string) {
  const parts = value.split("/").filter(Boolean);
  for (const part of parts) {
    if (part === "." || part === "..") {
      throw new HttpError(400, "Invalid root");
    }
  }
  return parts.length === 0 ? "/" : `/${parts.join("/")}`;
}

export function parentDirectoryHref(path: string) {
  const parent = parentPath(path);
  return ensureHref(parent, true);
}

export function isSameOrDescendantPath(sourcePath: string, destinationPath: string) {
  return destinationPath === sourcePath || destinationPath.startsWith(withTrailingSlash(sourcePath));
}

export function temporarySiblingPath(path: string, label: string) {
  const parent = parentPath(path);
  const name = basename(path) || "root";
  const tempName = `._cf_webdav_${label}_${name}_${crypto.randomUUID()}`;
  return parent === "/" ? `/${tempName}` : `${parent}/${tempName}`;
}
