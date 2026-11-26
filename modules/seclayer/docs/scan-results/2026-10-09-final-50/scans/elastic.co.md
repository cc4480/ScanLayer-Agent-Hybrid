# elastic.co

- Requested: `https://www.elastic.co`
- HTTP 200, 9.2s
- Score 83/100 — grade B
- 6 findings, 3 above Info

### Missing Strict-Transport-Security (HSTS) Policy

**Medium** · medium confidence · A02:2021 – Cryptographic Failures · IAST

```
Observed directly from the response headers and cookie attributes on the scanned URL.
```

### Missing X-Content-Type-Options (MIME Sniffing)

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed directly from the response headers and cookie attributes on the scanned URL.
```

### Cookie "euid" is set without the HttpOnly attribute

**Low** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.elastic.co in this response header (cookie value redacted): "Set-Cookie: euid=<redacted>; Expires=Tuesday, 19 January 2038 01:00:00 GMT; Path=/; Secure; Domain=.elastic.co;". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (10 pages, 8 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Verbose Server Framework Signature Leaked

**Info** · high confidence · A05:2021 – Security Misconfiguration · EASM

```
Informational scan-coverage context — not a detected vulnerability.
```

