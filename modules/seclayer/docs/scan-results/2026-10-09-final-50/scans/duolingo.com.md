# duolingo.com

- Requested: `https://www.duolingo.com`
- HTTP 200, 3.8s
- Score 68/100 — grade D
- 9 findings, 7 above Info

### Missing Content-Security-Policy (CSP)

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed directly from the response headers and cookie attributes on the scanned URL.
```

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

### Cookie "logged_out_uuid" is set without the HttpOnly attribute

**Low** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.duolingo.com in this response header (cookie value redacted): "Set-Cookie: logged_out_uuid=<redacted>; Domain=.duolingo.com; Max-Age=31536000; Path=/; expires=Sun, 10-Oct-2027 04:32:23 GMT". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "logged_out_uuid" is set without the Secure attribute over HTTPS

**Low** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.duolingo.com in this response header (cookie value redacted): "Set-Cookie: logged_out_uuid=<redacted>; Domain=.duolingo.com; Max-Age=31536000; Path=/; expires=Sun, 10-Oct-2027 04:32:23 GMT". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "wuuid" is set without the HttpOnly attribute

**Low** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.duolingo.com in this response header (cookie value redacted): "Set-Cookie: wuuid=<redacted>". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "wuuid" is set without the Secure attribute over HTTPS

**Low** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.duolingo.com in this response header (cookie value redacted): "Set-Cookie: wuuid=<redacted>". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Verbose Server Framework Signature Leaked

**Info** · high confidence · A05:2021 – Security Misconfiguration · EASM

```
Informational scan-coverage context — not a detected vulnerability.
```

