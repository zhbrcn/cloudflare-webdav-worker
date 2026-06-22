# Cloudflare WebDAV Worker

Lightweight WebDAV server for Cloudflare Workers, backed by R2 for file storage and Durable Objects (SQLite) for lock and user management.

This project is intended for small personal backups, app sync targets, and low-concurrency self-hosted WebDAV usage. It is not intended to be a fully RFC-complete or high-concurrency WebDAV server.

## Features

- `OPTIONS`
- `PROPFIND`
- `GET`
- `HEAD`
- `PUT`
- `DELETE`
- `MKCOL`
- `MOVE`
- `COPY`
- `LOCK`
- `UNLOCK`
- Browser directory listing and basic file management UI
- Basic text file editing from the browser
- Browser user management for per-app WebDAV accounts
- Per-account directories derived from usernames
- Per-account read/write/delete permissions

## Architecture

- Cloudflare Worker: WebDAV request handling and browser UI
- R2: file/object storage
- Durable Object with SQLite: WebDAV lock tracking
- Durable Object with SQLite: WebDAV account storage

## Requirements

- Node.js 20+
- Cloudflare account with Workers, R2, and Durable Objects enabled

## Quick Start

1. Install dependencies:

```powershell
npm.cmd install
```

2. Create the R2 bucket:

```powershell
npx wrangler r2 bucket create webdav-files
```

3. Set admin Basic Auth credentials:

```powershell
npx wrangler secret put BASIC_AUTH_USER
npx wrangler secret put BASIC_AUTH_PASS
npx wrangler secret put ADMIN_AUTH_USER
npx wrangler secret put ADMIN_AUTH_PASS
npx wrangler secret put ACCESS_ADMIN_EMAIL
npx wrangler secret put PASSWORD_SECRET
```

`ADMIN_AUTH_USER` / `ADMIN_AUTH_PASS` are used for browser user management. If they are not set, the Worker falls back to `BASIC_AUTH_USER` / `BASIC_AUTH_PASS`.
`ACCESS_ADMIN_EMAIL` optionally allows Cloudflare Access-authenticated browser sessions to use the admin UI without Basic Auth.
`PASSWORD_SECRET` encrypts recoverable per-user passwords for the admin UI.

4. Review [wrangler.jsonc](./wrangler.jsonc):

- set your Worker name
- change the bucket name if needed
- optionally configure a custom domain

5. Deploy:

```powershell
npm.cmd run deploy
```

## Local Development

Run:

```powershell
npm.cmd run dev
```

Basic checks:

```powershell
curl.exe -i -u webdav:your-password -X OPTIONS http://127.0.0.1:8787/
curl.exe -i -u webdav:your-password -X MKCOL http://127.0.0.1:8787/config
curl.exe -i -u webdav:your-password -T .\.dev.vars.example http://127.0.0.1:8787/config/test.txt
curl.exe -i -u webdav:your-password -X PROPFIND -H "Depth: 1" http://127.0.0.1:8787/config
```

Type-check:

```powershell
npm.cmd run check
```

## Browser UI

Opening a collection URL in a browser shows a simple file manager.

Supported browser actions:

- browse directories
- upload files
- create folders
- rename
- move
- delete
- select all / invert selection
- basic text editing and save

The browser UI is a convenience layer over the WebDAV endpoints. It is not intended to be a full replacement for dedicated sync clients.

## User Management

Open `/_admin/users` in a browser and sign in with the admin credentials.

For smoother browser administration, put Cloudflare Access in front of only `/_admin/*`. Do not protect the whole WebDAV hostname if you need generic WebDAV clients to keep working. When Access protects `/_admin/*`, set `ACCESS_ADMIN_EMAIL` to the allowed admin email so the Worker can trust the `Cf-Access-Authenticated-User-Email` header.

The admin page can:

- create WebDAV users
- auto-generate long random passwords
- copy usernames and stored passwords
- reset passwords
- enable or disable users
- delete users
- assign read/write/delete permissions
- browse and manage each user's files through the same browser file manager

Managed user passwords are hashed for authentication and also stored as AES-GCM ciphertext so the Zero Trust-protected admin UI can copy them later. If `PASSWORD_SECRET` and the Durable Object data are both exposed, stored passwords can be recovered.

Client configuration stays the same for WebDAV apps:

```text
URL: https://webdav.example.com/
Username: joplin
Password: generated-password
```

Each managed user is internally mapped to a directory with the same name as the username. For example, user `joplin` sees `/` from the client side, while R2 objects are stored under `/joplin`.

## Custom Domain

Example route configuration in [wrangler.jsonc](./wrangler.jsonc):

```jsonc
"workers_dev": false,
"routes": [
  {
    "pattern": "webdav.example.com",
    "custom_domain": true
  }
],
```

Then deploy again:

```powershell
npm.cmd run deploy
```

## Notes

- Empty directories are represented by a marker object in R2.
- `PUT` can create missing parent collections to improve compatibility with some clients.
- Locking is intentionally minimal and designed for practical compatibility, not full RFC edge-case coverage.
- Success responses were adjusted for broader client compatibility, including clients that do not handle `204 No Content` well.
- `/_admin` is reserved for browser user management and is not exposed as a WebDAV storage path.

## Recommended Clients

- `rclone`
- Joplin
- FLClash
- password managers or note apps with basic WebDAV sync support

## Security

- Use strong random admin credentials.
- Prefer one managed WebDAV user per app or device.
- Rotate any password or API token exposed during setup or testing.
- If you need stronger access control, put the Worker behind Cloudflare Access.
- This project uses Basic Auth and is intended for trusted personal or small-scale use.

## Known Limitations

- No group permission model
- No quotas or advanced storage policy
- No transactional guarantees for large multi-object operations
- `MOVE` / `COPY` safety is improved, but multi-object replacements are still not truly atomic
- Client compatibility varies; test your target client before relying on it
- Browser editing is intended for text files, not binary formats

## Project Files

- [src/index.ts](./src/index.ts): Worker entrypoint, WebDAV handlers, browser UI
- [src/lock-do.ts](./src/lock-do.ts): Durable Object lock manager
- [src/user-do.ts](./src/user-do.ts): Durable Object user manager
- [wrangler.jsonc](./wrangler.jsonc): Wrangler configuration

## Publish Checklist

- set final Worker name
- confirm bucket name
- confirm custom domain or `workers.dev` usage
- set final `BASIC_AUTH_USER`
- set final `BASIC_AUTH_PASS`
- set final `ADMIN_AUTH_USER`
- set final `ADMIN_AUTH_PASS`
- set final `ACCESS_ADMIN_EMAIL`
- set final `PASSWORD_SECRET`
- run `npm.cmd run check`
- run `npm.cmd run deploy`
