interface LockRecord {
  [key: string]: SqlStorageValue;
  path: string;
  token: string;
  owner: string | null;
  scope: "exclusive";
  depth: "0" | "infinity";
  expiresAt: number;
}

interface AcquirePayload {
  path: string;
  owner: string | null;
  depth: "0" | "infinity";
  timeoutSeconds: number;
  refreshToken?: string | null;
}

interface CheckPayload {
  path: string;
  token?: string | null;
  recursive?: boolean;
}

export class WebDavLockManager {
  private readonly ctx: DurableObjectState;

  constructor(ctx: DurableObjectState, env: unknown) {
    void env;
    this.ctx = ctx;
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS locks (
        path TEXT PRIMARY KEY,
        token TEXT NOT NULL,
        owner TEXT,
        scope TEXT NOT NULL,
        depth TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      )
    `);
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const method = request.method.toUpperCase();

    if (method === "POST" && url.pathname === "/acquire") {
      const payload = (await request.json()) as AcquirePayload;
      return Response.json(this.acquire(payload));
    }

    if (method === "POST" && url.pathname === "/unlock") {
      const payload = (await request.json()) as { path: string; token: string };
      return Response.json(this.unlock(payload.path, payload.token));
    }

    if (method === "POST" && url.pathname === "/check") {
      const payload = (await request.json()) as CheckPayload;
      return Response.json(this.check(payload));
    }

    return new Response("Not found", { status: 404 });
  }

  private acquire(payload: AcquirePayload) {
    this.pruneExpired();
    const normalized = normalizeLockPath(payload.path);
    const timeoutSeconds = clamp(payload.timeoutSeconds, 60, 60 * 60 * 24 * 7);
    const expiresAt = Date.now() + timeoutSeconds * 1000;

    if (payload.refreshToken) {
      const current = this.getByPath(normalized);
      if (!current || current.token !== payload.refreshToken) {
        return { ok: false, status: 412 as const };
      }
      this.ctx.storage.sql.exec(
        "UPDATE locks SET expires_at = ?1 WHERE path = ?2",
        expiresAt,
        normalized,
      );
      return { ok: true, status: 200 as const, token: current.token, expiresAt };
    }

    const conflict = this.findConflict(normalized, payload.depth);
    if (conflict) {
      return { ok: false, status: 423 as const, conflict };
    }

    const token = `opaquelocktoken:${crypto.randomUUID()}`;
    this.ctx.storage.sql.exec(
      "INSERT OR REPLACE INTO locks (path, token, owner, scope, depth, expires_at) VALUES (?1, ?2, ?3, 'exclusive', ?4, ?5)",
      normalized,
      token,
      payload.owner,
      payload.depth,
      expiresAt,
    );

    return { ok: true, status: 200 as const, token, expiresAt };
  }

  private unlock(path: string, token: string) {
    this.pruneExpired();
    const normalized = normalizeLockPath(path);
    const current = this.getByPath(normalized);
    if (!current || current.token !== token) {
      return { ok: false, status: 409 as const };
    }

    this.ctx.storage.sql.exec("DELETE FROM locks WHERE path = ?1", normalized);
    return { ok: true, status: 204 as const };
  }

  private check(payload: CheckPayload) {
    this.pruneExpired();
    const normalized = normalizeLockPath(payload.path);
    const conflicts = this.getConflicts(normalized, Boolean(payload.recursive));
    const blocking = conflicts.filter((lock) => lock.token !== payload.token);
    return {
      ok: blocking.length === 0,
      status: blocking.length === 0 ? 200 : 423,
      conflicts: blocking,
    };
  }

  private pruneExpired() {
    this.ctx.storage.sql.exec("DELETE FROM locks WHERE expires_at <= ?1", Date.now());
  }

  private getByPath(path: string): LockRecord | null {
    const rows = this.ctx.storage.sql.exec<LockRecord>(
      "SELECT path, token, owner, scope, depth, expires_at AS expiresAt FROM locks WHERE path = ?1",
      path,
    );
    for (const row of rows) {
      return row;
    }
    return null;
  }

  private findConflict(path: string, depth: "0" | "infinity"): LockRecord | null {
    for (const row of this.ctx.storage.sql.exec<LockRecord>(
      "SELECT path, token, owner, scope, depth, expires_at AS expiresAt FROM locks",
    )) {
      if (locksConflict(row.path, row.depth, path, depth)) {
        return row;
      }
    }
    return null;
  }

  private getConflicts(path: string, recursive: boolean): LockRecord[] {
    const conflicts: LockRecord[] = [];
    for (const row of this.ctx.storage.sql.exec<LockRecord>(
      "SELECT path, token, owner, scope, depth, expires_at AS expiresAt FROM locks",
    )) {
      if (overlaps(row.path, row.depth, path) || (recursive && overlaps(path, "infinity", row.path))) {
        conflicts.push(row);
      }
    }
    return conflicts;
  }
}

function overlaps(lockPath: string, depth: "0" | "infinity", targetPath: string) {
  if (lockPath === targetPath) {
    return true;
  }
  if (depth === "infinity" && targetPath.startsWith(withTrailingSlash(lockPath))) {
    return true;
  }
  return false;
}

function locksConflict(
  existingPath: string,
  existingDepth: "0" | "infinity",
  requestedPath: string,
  requestedDepth: "0" | "infinity",
) {
  return (
    overlaps(existingPath, existingDepth, requestedPath) ||
    overlaps(requestedPath, requestedDepth, existingPath)
  );
}

function normalizeLockPath(path: string) {
  if (path === "/") {
    return "/";
  }
  return `/${path.split("/").filter(Boolean).join("/")}`;
}

function withTrailingSlash(path: string) {
  return path.endsWith("/") ? path : `${path}/`;
}

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}
