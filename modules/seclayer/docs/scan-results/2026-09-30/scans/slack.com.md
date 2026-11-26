# slack.com

- Requested: `https://slack.com`
- HTTP 200, 5.7s
- Score 63/100 — grade D
- 8 findings, 5 above Info

### Cookie "b" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://slack.com in this response header (cookie value redacted): "Set-Cookie: b=<redacted>; expires=Tue, 30-Sep-2036 15:14:21 GMT; Max-Age=315619200; path=/; domain=.slack.com; secure; SameSite=None". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "utm" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://slack.com in this response header (cookie value redacted): "Set-Cookie: utm=<redacted>; expires=Wed, 14-Oct-2026 15:14:21 GMT; Max-Age=1209600; path=/; domain=.slack.com; secure; SameSite=None". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "x" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://slack.com in this response header (cookie value redacted): "Set-Cookie: x=<redacted>; expires=Wed, 30-Sep-2026 15:29:21 GMT; Max-Age=900; path=/; domain=.slack.com; secure; SameSite=None". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

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

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (10 pages, 28 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Verbose Server Framework Signature Leaked

**Info** · high confidence · A05:2021 – Security Misconfiguration · EASM

```
Informational scan-coverage context — not a detected vulnerability.
```

