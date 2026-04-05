# Cloudflare WebDAV Worker

A minimal WebDAV server for Cloudflare Workers, backed by R2 for file storage and Durable Objects (SQLite) for lock management.

This project is designed for:

- small configuration backups
- low concurrency WebDAV clients
- simple self-hosted sync targets

This project is not designed for:

- large media libraries
- high-concurrency collaborative editing
- full WebDAV RFC edge-case coverage

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

## Architecture

- Worker: handles the WebDAV protocol surface
- R2: stores file contents
- Durable Object (SQLite): stores WebDAV locks

## Requirements

- Node.js 20+
- A Cloudflare account with Workers and R2 enabled
- A Cloudflare-managed zone if you want to use a custom domain

## Quick Start

1. Install dependencies:

```powershell
npm.cmd install
```

2. Authenticate Wrangler.

The most reliable option is a User API Token exposed as `CLOUDFLARE_API_TOKEN`.

Minimum permissions:

- `User` -> `Memberships` -> `Read`
- `User` -> `User Details` -> `Read`
- `Account` -> `Workers Scripts` -> `Edit`
- `Account` -> `Workers R2 Storage` -> `Edit`
- `Zone` -> `Workers Routes` -> `Edit`
- `Zone` -> `Zone` -> `Read`

3. Create the R2 bucket:

```powershell
npx wrangler r2 bucket create webdav-files
```

4. Set Basic Auth secrets:

```powershell
npx wrangler secret put BASIC_AUTH_USER
npx wrangler secret put BASIC_AUTH_PASS
```

5. Deploy:

```powershell
npm.cmd run deploy
```

By default this template deploys to `workers.dev`. To use a custom domain, edit [wrangler.jsonc](/C:/Users/Brz/Desktop/webdav/wrangler.jsonc) and uncomment the `routes` block.

## Local Development

Run:

```powershell
npm.cmd run dev
```

Example requests:

```powershell
curl.exe -i -u webdav:your-password -X OPTIONS http://127.0.0.1:8787/
curl.exe -i -u webdav:your-password -X MKCOL http://127.0.0.1:8787/config
curl.exe -i -u webdav:your-password -T .\.dev.vars.example http://127.0.0.1:8787/config/test.txt
curl.exe -i -u webdav:your-password -X PROPFIND -H "Depth: 1" http://127.0.0.1:8787/config
```

## Custom Domain Example

Replace the `routes` section in [wrangler.jsonc](/C:/Users/Brz/Desktop/webdav/wrangler.jsonc) with:

```jsonc
"workers_dev": false,
"routes": [
  {
    "pattern": "webdav.example.com",
    "custom_domain": true
  }
],
```

Make sure the hostname is not already occupied by another DNS record or product.

## Notes

- Empty directories are represented with a marker object in R2.
- Parent collections must exist before uploading nested files.
- Locking is intentionally minimal but adequate for many sync clients.
- This implementation prefers predictable behavior over full protocol completeness.

## Example Client URL

```text
https://your-worker.your-subdomain.workers.dev/
```

or with a custom domain:

```text
https://webdav.example.com/
```

## Recommended Clients

- `rclone`
- Joplin
- password managers or note apps with basic WebDAV sync support

## Security

- Use a strong random password, not a human-memorable one.
- If you exposed a token or password during setup, rotate it immediately.
- For stronger protection, put the Worker behind Cloudflare Access and keep Basic Auth as an app-level credential.

## Known Limitations

- No multi-user permission model
- No advanced quota management
- No optimized bulk operations for very large trees
- WebDAV client compatibility varies; test your client before relying on it

## Project Files

- [src/index.ts](/C:/Users/Brz/Desktop/webdav/src/index.ts): Worker entrypoint and WebDAV handlers
- [src/lock-do.ts](/C:/Users/Brz/Desktop/webdav/src/lock-do.ts): Durable Object lock manager
- [wrangler.jsonc](/C:/Users/Brz/Desktop/webdav/wrangler.jsonc): Wrangler configuration

## Publish Checklist

- replace placeholder secrets
- update the Worker name
- update the bucket name if needed
- configure your own custom domain if needed
- rotate any tokens or passwords used during testing
