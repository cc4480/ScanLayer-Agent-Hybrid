# theverge.com

- Requested: `https://www.theverge.com`
- HTTP 200, 6.0s
- Score 85/100 — grade B
- 7 findings, 4 above Info

### Missing X-Content-Type-Options (MIME Sniffing)

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed directly from the response headers and cookie attributes on the scanned URL.
```

### Cookie "_vm_consent_type" is set without the HttpOnly attribute

**Low** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.theverge.com in this response header (cookie value redacted): "Set-Cookie: _vm_consent_type=<redacted>; expires=Sun, 11 Oct 2026 04:30:54 GMT; path=/;". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "_vm_consent_type" is set without the Secure attribute over HTTPS

**Low** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.theverge.com in this response header (cookie value redacted): "Set-Cookie: _vm_consent_type=<redacted>; expires=Sun, 11 Oct 2026 04:30:54 GMT; path=/;". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "vmidv1" is set without the HttpOnly attribute

**Low** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.theverge.com in this response header (cookie value redacted): "Set-Cookie: vmidv1=<redacted>;Expires=Thu, 09 Oct 2031 04:30:54 GMT;Domain=www.theverge.com;Path=/;SameSite=Lax;Secure". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (10 pages, 18 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Verbose Server Framework Signature Leaked

**Info** · high confidence · A05:2021 – Security Misconfiguration · EASM

```
Informational scan-coverage context — not a detected vulnerability.
```

