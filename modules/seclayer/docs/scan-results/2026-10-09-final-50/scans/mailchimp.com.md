# mailchimp.com

- Requested: `https://www.mailchimp.com`
- HTTP 200, 16.0s
- Score 80/100 — grade B
- 7 findings, 4 above Info

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

### Cookie "_mcid" is set without the HttpOnly attribute

**Low** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.mailchimp.com in this response header (cookie value redacted): "Set-Cookie: _mcid=<redacted>; expires=Sun, 10 Oct 2027 04:29:59 GMT; Max-Age=31536000; path=/; domain=.mailchimp.com". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "_mcid" is set without the Secure attribute over HTTPS

**Low** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.mailchimp.com in this response header (cookie value redacted): "Set-Cookie: _mcid=<redacted>; expires=Sun, 10 Oct 2027 04:29:59 GMT; Max-Age=31536000; path=/; domain=.mailchimp.com". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (10 pages, 10 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Verbose Server Framework Signature Leaked

**Info** · high confidence · A05:2021 – Security Misconfiguration · EASM

```
Informational scan-coverage context — not a detected vulnerability.
```

