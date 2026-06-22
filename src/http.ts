export function baseHeaders() {
  return {
    DAV: "1, 2",
    "MS-Author-Via": "DAV",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
  };
}

export function htmlHeaders() {
  return {
    ...baseHeaders(),
    "Content-Type": "text/html; charset=utf-8",
    "Content-Security-Policy": [
      "default-src 'none'",
      "base-uri 'none'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "img-src 'self' data:",
      "style-src 'unsafe-inline'",
      "script-src 'unsafe-inline'",
      "connect-src 'self'",
    ].join("; "),
  };
}

export function xmlResponse(body: string, status: number) {
  return new Response(body, {
    status,
    headers: {
      ...baseHeaders(),
      "Content-Type": 'application/xml; charset="utf-8"',
    },
  });
}
