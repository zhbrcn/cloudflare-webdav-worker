import type { Permission } from "./types";

interface UserRecord {
  [key: string]: SqlStorageValue;
  username: string;
  passwordHash: string;
  salt: string;
  root: string;
  permissions: string;
  enabled: number;
  createdAt: number;
  updatedAt: number;
  lastUsedAt: number | null;
  passwordCiphertext: string | null;
}

interface AuthAttemptRecord {
  [key: string]: SqlStorageValue;
  attemptKey: string;
  failures: number;
  lockedUntil: number;
  updatedAt: number;
}

interface PublicUser {
  username: string;
  root: string;
  permissions: Permission[];
  enabled: boolean;
  createdAt: number;
  updatedAt: number;
  lastUsedAt: number | null;
}

interface AuthenticatedStoredUser extends PublicUser {
  passwordHash: string;
  salt: string;
  passwordCiphertext: string | null;
}

interface CreateUserPayload {
  username: string;
  permissions?: Permission[];
  password?: string;
}

interface UpdateUserPayload {
  username: string;
  permissions?: Permission[];
  enabled?: boolean;
}

const DEFAULT_PERMISSIONS: Permission[] = ["read", "write", "delete"];
const PASSWORD_ITERATIONS = 210000;

interface Env {
  PASSWORD_SECRET?: string;
}

export class WebDavUserManager {
  private readonly ctx: DurableObjectState;
  private readonly env: Env;

  constructor(ctx: DurableObjectState, env: Env) {
    this.ctx = ctx;
    this.env = env;
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        root TEXT NOT NULL,
        permissions TEXT NOT NULL,
        enabled INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        last_used_at INTEGER
      )
    `);
    this.ensureSchema();
  }

  private ensureSchema() {
    const columns = new Set<string>();
    for (const row of this.ctx.storage.sql.exec<{ [key: string]: SqlStorageValue; name: string }>("PRAGMA table_info(users)")) {
      columns.add(row.name);
    }
    if (!columns.has("password_ciphertext")) {
      this.ctx.storage.sql.exec("ALTER TABLE users ADD COLUMN password_ciphertext TEXT");
    }
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS auth_attempt_records (
        attempt_key TEXT PRIMARY KEY,
        failures INTEGER NOT NULL,
        locked_until INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      )
    `);
  }

  async fetch(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);
      const method = request.method.toUpperCase();

      if (method === "POST" && url.pathname === "/authenticate") {
        const payload = (await request.json()) as { username: string; password: string; rateLimitKey?: string };
        return Response.json(await this.authenticate(payload.username, payload.password, payload.rateLimitKey));
      }

      if (method === "GET" && url.pathname === "/users") {
        return Response.json({ ok: true, users: this.listUsers() });
      }

      if (method === "POST" && url.pathname === "/users/create") {
        const payload = (await request.json()) as CreateUserPayload;
        return Response.json(await this.createUser(payload));
      }

      if (method === "POST" && url.pathname === "/users/update") {
        const payload = (await request.json()) as UpdateUserPayload;
        return Response.json(this.updateUser(payload));
      }

      if (method === "POST" && url.pathname === "/users/reset-password") {
        const payload = (await request.json()) as { username: string; password?: string };
        return Response.json(await this.resetPassword(payload.username, payload.password));
      }

      if (method === "POST" && url.pathname === "/users/reveal-password") {
        const payload = (await request.json()) as { username: string };
        return Response.json(await this.revealPassword(payload.username));
      }

      if (method === "POST" && url.pathname === "/users/delete") {
        const payload = (await request.json()) as { username: string };
        return Response.json(this.deleteUser(payload.username));
      }

      return new Response("Not found", { status: 404 });
    } catch (error) {
      void error;
      return Response.json({ ok: false, status: 400, message: "Request failed" });
    }
  }

  private async authenticate(username: string, password: string, rateLimitKeyInput?: string) {
    const usernameKey = normalizeUsername(username) || "unknown";
    const rateLimitKey = normalizeRateLimitKey(rateLimitKeyInput, usernameKey);
    const rateLimit = this.checkRateLimit(rateLimitKey);
    if (!rateLimit.ok) {
      return { ok: false, status: 429 as const, retryAfter: rateLimit.retryAfter };
    }

    const user = this.getUser(username);
    if (!user || !user.enabled) {
      this.recordAuthFailure(rateLimitKey);
      return { ok: false, status: 401 as const };
    }
    if (!(await verifyPassword(password, user.passwordHash, user.salt))) {
      this.recordAuthFailure(rateLimitKey);
      return { ok: false, status: 401 as const };
    }
    this.clearAuthFailures(rateLimitKey);
    this.ctx.storage.sql.exec(
      "UPDATE users SET last_used_at = ?1 WHERE username = ?2",
      Date.now(),
      user.username,
    );
    return { ok: true, status: 200 as const, user };
  }

  private listUsers() {
    const users: PublicUser[] = [];
    for (const row of this.ctx.storage.sql.exec<UserRecord>(
      "SELECT username, password_hash AS passwordHash, salt, root, permissions, enabled, created_at AS createdAt, updated_at AS updatedAt, last_used_at AS lastUsedAt FROM users ORDER BY username",
    )) {
      users.push(toPublicUser(row));
    }
    return users;
  }

  private async createUser(payload: CreateUserPayload) {
    const username = normalizeUsername(payload.username);
    if (!username) {
      return { ok: false, status: 400 as const, message: "Invalid username" };
    }
    if (this.getUser(username)) {
      return { ok: false, status: 409 as const, message: "User already exists" };
    }

    const password = payload.password || generatePassword();
    const salt = randomToken(18);
    const passwordCiphertext = await encryptPassword(password, this.env.PASSWORD_SECRET);
    const now = Date.now();
    const user: PublicUser = {
      username,
      root: rootForUsername(username),
      permissions: normalizePermissions(payload.permissions),
      enabled: true,
      createdAt: now,
      updatedAt: now,
      lastUsedAt: null,
    };

    this.ctx.storage.sql.exec(
      "INSERT INTO users (username, password_hash, salt, root, permissions, enabled, created_at, updated_at, last_used_at, password_ciphertext) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, NULL, ?8)",
      user.username,
      await hashPassword(password, salt),
      salt,
      user.root,
      JSON.stringify(user.permissions),
      now,
      now,
      passwordCiphertext,
    );

    return { ok: true, status: 201 as const, user, password };
  }

  private updateUser(payload: UpdateUserPayload) {
    const username = normalizeUsername(payload.username);
    const current = username ? this.getUser(username) : null;
    if (!current) {
      return { ok: false, status: 404 as const, message: "User not found" };
    }

    const root = rootForUsername(username);
    const permissions = payload.permissions === undefined
      ? current.permissions
      : normalizePermissions(payload.permissions);
    const enabled = payload.enabled === undefined ? current.enabled : payload.enabled;
    const now = Date.now();

    this.ctx.storage.sql.exec(
      "UPDATE users SET root = ?1, permissions = ?2, enabled = ?3, updated_at = ?4 WHERE username = ?5",
      root,
      JSON.stringify(permissions),
      enabled ? 1 : 0,
      now,
      username,
    );

    return {
      ok: true,
      status: 200 as const,
      user: {
        username: current.username,
        root,
        permissions,
        enabled,
        createdAt: current.createdAt,
        updatedAt: now,
        lastUsedAt: current.lastUsedAt,
      },
    };
  }

  private async resetPassword(usernameInput: string, passwordInput?: string) {
    const username = normalizeUsername(usernameInput);
    const current = username ? this.getUser(username) : null;
    if (!current) {
      return { ok: false, status: 404 as const, message: "User not found" };
    }

    const password = passwordInput || generatePassword();
    const salt = randomToken(18);
    const passwordCiphertext = await encryptPassword(password, this.env.PASSWORD_SECRET);
    const now = Date.now();
    this.ctx.storage.sql.exec(
      "UPDATE users SET password_hash = ?1, salt = ?2, updated_at = ?3, password_ciphertext = ?4 WHERE username = ?5",
      await hashPassword(password, salt),
      salt,
      now,
      passwordCiphertext,
      username,
    );

    return { ok: true, status: 200 as const, password };
  }

  private async revealPassword(usernameInput: string) {
    const username = normalizeUsername(usernameInput);
    const current = username ? this.getUser(username) : null;
    if (!current) {
      return { ok: false, status: 404 as const, message: "User not found" };
    }
    if (!current.passwordCiphertext) {
      return { ok: false, status: 409 as const, message: "Password is not recoverable. Reset it once to enable copying." };
    }
    return {
      ok: true,
      status: 200 as const,
      password: await decryptPassword(current.passwordCiphertext, this.env.PASSWORD_SECRET),
    };
  }

  private deleteUser(usernameInput: string) {
    const username = normalizeUsername(usernameInput);
    if (!username || !this.getUser(username)) {
      return { ok: false, status: 404 as const, message: "User not found" };
    }
    this.ctx.storage.sql.exec("DELETE FROM users WHERE username = ?1", username);
    return { ok: true, status: 200 as const };
  }

  private checkRateLimit(key: string) {
    this.cleanupAuthAttempts();
    const now = Date.now();
    const row = this.getAuthAttempt(key);
    if (row?.lockedUntil && row.lockedUntil > now) {
      return { ok: false, retryAfter: Math.ceil((row.lockedUntil - now) / 1000) };
    }
    return { ok: true };
  }

  private recordAuthFailure(key: string) {
    const now = Date.now();
    const row = this.getAuthAttempt(key);
    const failures = (row?.updatedAt && now - row.updatedAt < 10 * 60_000 ? row.failures : 0) + 1;
    const lockedUntil = failures >= 10 ? now + 5 * 60_000 : 0;
    this.ctx.storage.sql.exec(
      "INSERT OR REPLACE INTO auth_attempt_records (attempt_key, failures, locked_until, updated_at) VALUES (?1, ?2, ?3, ?4)",
      key,
      failures,
      lockedUntil,
      now,
    );
  }

  private clearAuthFailures(key: string) {
    this.ctx.storage.sql.exec("DELETE FROM auth_attempt_records WHERE attempt_key = ?1", key);
  }

  private cleanupAuthAttempts() {
    this.ctx.storage.sql.exec("DELETE FROM auth_attempt_records WHERE updated_at < ?1", Date.now() - 60 * 60_000);
  }

  private getAuthAttempt(key: string): AuthAttemptRecord | null {
    for (const row of this.ctx.storage.sql.exec<AuthAttemptRecord>(
      "SELECT attempt_key AS attemptKey, failures, locked_until AS lockedUntil, updated_at AS updatedAt FROM auth_attempt_records WHERE attempt_key = ?1",
      key,
    )) {
      return row;
    }
    return null;
  }

  private getUser(username: string): AuthenticatedStoredUser | null {
    const rows = this.ctx.storage.sql.exec<UserRecord>(
      "SELECT username, password_hash AS passwordHash, salt, root, permissions, enabled, created_at AS createdAt, updated_at AS updatedAt, last_used_at AS lastUsedAt, password_ciphertext AS passwordCiphertext FROM users WHERE username = ?1",
      username,
    );
    for (const row of rows) {
      return toPublicUser(row, row.passwordHash, row.salt);
    }
    return null;
  }
}

function toPublicUser(row: UserRecord): PublicUser;
function toPublicUser(row: UserRecord, passwordHash: string, salt: string): AuthenticatedStoredUser;
function toPublicUser(row: UserRecord, passwordHash?: string, salt?: string): PublicUser | AuthenticatedStoredUser {
  return {
    username: row.username,
    root: row.root,
    permissions: parsePermissions(row.permissions),
    enabled: row.enabled === 1,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    lastUsedAt: row.lastUsedAt,
    passwordHash,
    salt,
    passwordCiphertext: row.passwordCiphertext,
  };
}

function normalizeUsername(value: string) {
  const normalized = value.trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(normalized)) {
    return "";
  }
  if (normalized === "_admin") {
    return "";
  }
  return normalized;
}

function normalizeRateLimitKey(value: string | undefined, username: string) {
  const raw = value || username || "unknown";
  return raw.trim().toLowerCase().replace(/[^a-z0-9:._|/-]/g, "").slice(0, 180) || "unknown";
}

function rootForUsername(username: string) {
  return `/${username}`;
}

function normalizePermissions(values: Permission[] | undefined) {
  if (!values || values.length === 0) {
    return DEFAULT_PERMISSIONS;
  }
  const allowed = new Set<Permission>(["read", "write", "delete"]);
  const permissions = [...new Set(values)].filter((value): value is Permission => allowed.has(value));
  return permissions.length > 0 ? permissions : DEFAULT_PERMISSIONS;
}

function parsePermissions(value: string) {
  try {
    const parsed = JSON.parse(value);
    return normalizePermissions(Array.isArray(parsed) ? parsed : undefined);
  } catch {
    return DEFAULT_PERMISSIONS;
  }
}

async function hashPassword(password: string, salt: string) {
  return derivePasswordHash(password, salt, PASSWORD_ITERATIONS);
}

async function verifyPassword(password: string, storedHash: string, fallbackSalt: string) {
  const iterations = parsePasswordIterations(storedHash) ?? PASSWORD_ITERATIONS;
  const salt = parsePasswordSalt(storedHash) ?? fallbackSalt;
  const candidate = await derivePasswordHash(password, salt, iterations);
  return timingSafeEquals(candidate, storedHash);
}

async function derivePasswordHash(password: string, salt: string, iterations: number) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: encoder.encode(salt),
      iterations,
    },
    key,
    256,
  );
  return `pbkdf2-sha256:${iterations}:${salt}:${base64UrlEncode(new Uint8Array(bits))}`;
}

function parsePasswordIterations(value: string) {
  const parts = value.split(":");
  if (parts[0] !== "pbkdf2-sha256" || parts.length < 4) {
    return null;
  }
  const iterations = Number(parts[1]);
  return Number.isSafeInteger(iterations) && iterations > 0 ? iterations : null;
}

function parsePasswordSalt(value: string) {
  const parts = value.split(":");
  return parts[0] === "pbkdf2-sha256" && parts.length >= 4 ? parts[2] : null;
}

async function encryptPassword(password: string, secret: string | undefined) {
  const key = await importPasswordSecret(secret);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(password),
  );
  return `v1:${base64UrlEncode(iv)}:${base64UrlEncode(new Uint8Array(ciphertext))}`;
}

async function decryptPassword(value: string, secret: string | undefined) {
  const [, ivRaw, ciphertextRaw] = value.split(":");
  if (!ivRaw || !ciphertextRaw) {
    throw new Error("Invalid encrypted password");
  }
  const key = await importPasswordSecret(secret);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64UrlDecode(ivRaw) },
    key,
    base64UrlDecode(ciphertextRaw),
  );
  return new TextDecoder().decode(plaintext);
}

async function importPasswordSecret(secret: string | undefined) {
  if (!secret) {
    throw new Error("PASSWORD_SECRET is not configured");
  }
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  return crypto.subtle.importKey("raw", digest, "AES-GCM", false, ["encrypt", "decrypt"]);
}

function generatePassword() {
  return randomToken(32);
}

function randomToken(byteLength: number) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

function base64UrlEncode(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64UrlDecode(value: string) {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
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
