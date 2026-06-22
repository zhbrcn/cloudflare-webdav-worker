export interface Env {
  WEBDAV_BUCKET: R2Bucket;
  LOCKS: DurableObjectNamespace;
  USERS: DurableObjectNamespace;
  BASIC_AUTH_USER: string;
  BASIC_AUTH_PASS: string;
  ADMIN_AUTH_USER?: string;
  ADMIN_AUTH_PASS?: string;
  ACCESS_ADMIN_EMAIL?: string;
  ACCESS_TEAM_DOMAIN?: string;
  ACCESS_AUD?: string;
}

export type Permission = "read" | "write" | "delete";

export type AccessJsonWebKey = JsonWebKey & { kid?: string };

export interface AccessJwtPayload {
  email?: string;
  aud?: string | string[];
  iss?: string;
  exp?: number;
  nbf?: number;
}

export interface AuthContext {
  username: string;
  isAdmin: boolean;
  root: string;
  mountPath: string;
  permissions: Set<Permission>;
  retryAfter?: number;
}

export interface ResourceInfo {
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
