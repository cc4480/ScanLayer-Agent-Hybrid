# coursera.org

- Requested: `https://www.coursera.org`
- HTTP 200, 9.0s
- Score 88/100 — grade B
- 6 findings, 3 above Info

### Missing Content-Security-Policy (CSP)

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed directly from the response headers and cookie attributes on the scanned URL.
```

### Cookie "__204u" is set without the HttpOnly attribute

**Low** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.coursera.org in this response header (cookie value redacted): "Set-Cookie: __204u=<redacted>; Max-Age=31536000; Expires=Sun, 10 Oct 2027 04:32:30 GMT; Path=/; Domain=.coursera.org". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "__204u" is set without the Secure attribute over HTTPS

**Low** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.coursera.org in this response header (cookie value redacted): "Set-Cookie: __204u=<redacted>; Max-Age=31536000; Expires=Sun, 10 Oct 2027 04:32:30 GMT; Path=/; Domain=.coursera.org". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (10 pages, 25 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Verbose Server Framework Signature Leaked

**Info** · high confidence · A05:2021 – Security Misconfiguration · EASM

```
Informational scan-coverage context — not a detected vulnerability.
```

