# Cloudflare WebDAV Worker

Lightweight WebDAV server for Cloudflare Workers, backed by R2 for file storage and Durable Objects (SQLite) for lock management.

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

## Architecture

- Cloudflare Worker: WebDAV request handling and browser UI
- R2: file/object storage
- Durable Object with SQLite: WebDAV lock tracking

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

3. Set Basic Auth credentials:

```powershell
npx wrangler secret put BASIC_AUTH_USER
npx wrangler secret put BASIC_AUTH_PASS
```

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

## Recommended Clients

- `rclone`
- Joplin
- FLClash
- password managers or note apps with basic WebDAV sync support

## Security

- Use a strong random password.
- Rotate any password or API token exposed during setup or testing.
- If you need stronger access control, put the Worker behind Cloudflare Access.
- This project uses Basic Auth and is intended for trusted personal or small-scale use.

## Known Limitations

- No multi-user permission model
- No quotas or advanced storage policy
- No transactional guarantees for large multi-object operations
- `MOVE` / `COPY` safety is improved, but multi-object replacements are still not truly atomic
- Client compatibility varies; test your target client before relying on it
- Browser editing is intended for text files, not binary formats

## Project Files

- [src/index.ts](./src/index.ts): Worker entrypoint, WebDAV handlers, browser UI
- [src/lock-do.ts](./src/lock-do.ts): Durable Object lock manager
- [wrangler.jsonc](./wrangler.jsonc): Wrangler configuration

## Publish Checklist

- set final Worker name
- confirm bucket name
- confirm custom domain or `workers.dev` usage
- set final `BASIC_AUTH_USER`
- set final `BASIC_AUTH_PASS`
- run `npm.cmd run check`
- run `npm.cmd run deploy`
