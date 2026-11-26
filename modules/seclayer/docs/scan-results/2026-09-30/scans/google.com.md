# google.com

- Requested: `https://google.com`
- HTTP 200, 7.9s
- Score 80/100 — grade B
- 6 findings, 3 above Info

### Cookie "__Secure-STRP" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://google.com in this response header (cookie value redacted): "Set-Cookie: __Secure-STRP=<redacted>; expires=Wed, 30-Sep-2026 15:19:08 GMT; path=/; domain=.google.com; Secure; SameSite=strict". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Missing X-Content-Type-Options (MIME Sniffing)

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed directly from the response headers and cookie attributes on the scanned URL.
```

### Content-Security-Policy is report-only (not enforced)

**Low** · high confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed directly from the response headers and cookie attributes on the scanned URL.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (9 pages, 131 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Verbose Server Framework Signature Leaked

**Info** · high confidence · A05:2021 – Security Misconfiguration · EASM

```
Informational scan-coverage context — not a detected vulnerability.
```

