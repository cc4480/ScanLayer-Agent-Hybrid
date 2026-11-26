# redis.io

- Requested: `https://redis.io`
- HTTP 200, 12.2s
- Score 90/100 — grade A
- 4 findings, 2 above Info

### Missing X-Content-Type-Options (MIME Sniffing)

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed directly from the response headers and cookie attributes on the scanned URL.
```

### Cookie "gb_assignments" is set without the HttpOnly attribute

**Low** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://redis.io in this response header (cookie value redacted): "Set-Cookie: gb_assignments=<redacted>; Path=/; Expires=Mon, 09 Nov 2026 04:26:33 GMT; Max-Age=2592000; Secure; SameSite=lax". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (10 pages, 1 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

