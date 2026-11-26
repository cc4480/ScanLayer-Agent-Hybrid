# squarespace.com

- Requested: `https://www.squarespace.com`
- HTTP 200, 10.7s
- Score 75/100 — grade C
- 9 findings, 6 above Info

### Missing Content-Security-Policy (CSP)

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed directly from the response headers and cookie attributes on the scanned URL.
```

### Missing X-Frame-Options / Clickjacking Immunity

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed directly from the response headers and cookie attributes on the scanned URL.
```

### Cookie "crumb" is set without the HttpOnly attribute

**Low** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.squarespace.com in this response header (cookie value redacted): "Set-Cookie: crumb=<redacted>;Secure;Path=/". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "SS_ANALYTICS_ID" is set without the HttpOnly attribute

**Low** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.squarespace.com in this response header (cookie value redacted): "Set-Cookie: SS_ANALYTICS_ID=<redacted>; Path=/; Expires=Thu, 04 Nov 2027 04:30:13 GMT; Max-Age=33696000; Domain=.squarespace.com; Secure; SameSite=lax". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "SS_MID" is set without the HttpOnly attribute

**Low** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.squarespace.com in this response header (cookie value redacted): "Set-Cookie: SS_MID=<redacted>;Path=/;Domain=.squarespace.com;Expires=Thu, 04 Nov 2027 04:30:08 GMT". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "SS_MID" is set without the Secure attribute over HTTPS

**Low** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.squarespace.com in this response header (cookie value redacted): "Set-Cookie: SS_MID=<redacted>;Path=/;Domain=.squarespace.com;Expires=Thu, 04 Nov 2027 04:30:08 GMT". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
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

