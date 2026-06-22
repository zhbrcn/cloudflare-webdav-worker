#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-https://webdav.669999.xyz}"

if [[ -z "${WEBDAV_SMOKE_USER:-}" || -z "${WEBDAV_SMOKE_PASS:-}" ]]; then
  echo "Set WEBDAV_SMOKE_USER and WEBDAV_SMOKE_PASS." >&2
  exit 2
fi

anonymous_propfind_status="$(
  curl -sS -o /dev/null -w '%{http_code}' \
    -X PROPFIND -H 'Depth: 0' "${BASE_URL}/"
)"
if [[ "${anonymous_propfind_status}" != "401" ]]; then
  echo "Anonymous PROPFIND smoke failed: ${anonymous_propfind_status}" >&2
  exit 1
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

file_page_html="$(
  curl -sS -u "${WEBDAV_SMOKE_USER}:${WEBDAV_SMOKE_PASS}" "${BASE_URL}/"
)"
if [[ "${file_page_html}" != *'href="/" class="is-active">Files</a>'* ]]; then
  echo "File page top navigation smoke failed." >&2
  exit 1
fi
if [[ "${file_page_html}" != *'class="path-segment is-current" href="/" aria-current="page">Files</a>'* ]]; then
  echo "File page path bar smoke failed." >&2
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

legacy_admin_alias_status="$(
  curl -sS -o /dev/null -w '%{http_code}' \
    -u "${WEBDAV_SMOKE_USER}:${WEBDAV_SMOKE_PASS}" \
    "${BASE_URL}/_davadmin/api/users"
)"
if [[ "${legacy_admin_alias_status}" == "200" ]]; then
  echo "Legacy admin alias unexpectedly returned success." >&2
  exit 1
fi

echo "Smoke checks passed."
