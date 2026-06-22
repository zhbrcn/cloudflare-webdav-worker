#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-https://webdav.669999.xyz}"

if [[ -z "${WEBDAV_SMOKE_USER:-}" || -z "${WEBDAV_SMOKE_PASS:-}" ]]; then
  echo "Set WEBDAV_SMOKE_USER and WEBDAV_SMOKE_PASS." >&2
  exit 2
fi

propfind_status="$(
  curl -sS -o /dev/null -w '%{http_code}' \
    -u "${WEBDAV_SMOKE_USER}:${WEBDAV_SMOKE_PASS}" \
    -X PROPFIND -H 'Depth: 0' "${BASE_URL}/"
)"
if [[ "${propfind_status}" != "207" ]]; then
  echo "PROPFIND smoke failed: ${propfind_status}" >&2
  exit 1
fi

root_status="$(curl -sS -o /dev/null -w '%{http_code}' "${BASE_URL}/")"
if [[ "${root_status}" != "302" ]]; then
  echo "Root redirect smoke failed: ${root_status}" >&2
  exit 1
fi

admin_status="$(curl -sS -o /dev/null -w '%{http_code}' "${BASE_URL}/_admin/users")"
if [[ "${admin_status}" != "302" ]]; then
  echo "Admin Access smoke failed: ${admin_status}" >&2
  exit 1
fi

echo "Smoke checks passed."
