# airtable.com

- Requested: `https://www.airtable.com`
- HTTP 200, 8.0s
- Score 73/100 — grade C
- 8 findings, 5 above Info

### Missing Content-Security-Policy (CSP)

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed directly from the response headers and cookie attributes on the scanned URL.
```

### Missing X-Content-Type-Options (MIME Sniffing)

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed directly from the response headers and cookie attributes on the scanned URL.
```

### Missing X-Frame-Options / Clickjacking Immunity

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed directly from the response headers and cookie attributes on the scanned URL.
```

### Cookie "brw" is set without the HttpOnly attribute

**Low** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.airtable.com in this response header (cookie value redacted): "Set-Cookie: brw=<redacted>; Path=/; Expires=Sun, 10 Oct 2027 04:29:36 GMT; Max-Age=31536000; Domain=.airtable.com; Secure; SameSite=lax". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "marketing-homepage-e4-segment" is set without the HttpOnly attribute

**Low** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.airtable.com in this response header (cookie value redacted): "Set-Cookie: marketing-homepage-e4-segment=<redacted>; Path=/; Expires=Mon, 09 Nov 2026 04:29:36 GMT; Max-Age=2592000; Domain=airtable.com; Secure; SameSite=lax". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (10 pages, 2 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Verbose Server Framework Signature Leaked

**Info** · high confidence · A05:2021 – Security Misconfiguration · EASM

```
Informational scan-coverage context — not a detected vulnerability.
```

