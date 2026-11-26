# vercel.com

- Requested: `https://vercel.com`
- HTTP 200, 21.2s
- Score 73/100 — grade C
- 7 findings, 4 above Info

### Cookie "_v-consent" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://vercel.com in this response header (cookie value redacted): "Set-Cookie: _v-consent=<redacted>; Path=/; Expires=Thu, 30 Sep 2027 15:14:40 GMT; Max-Age=31536000; Domain=.vercel.com; Secure; SameSite=lax". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "_v-visitor-id-renewed" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://vercel.com in this response header (cookie value redacted): "Set-Cookie: _v-visitor-id-renewed=<redacted>; Path=/; Expires=Thu, 01 Oct 2026 15:14:40 GMT; Max-Age=86400; Domain=.vercel.com; Secure; SameSite=lax". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "_v-visitor-id" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://vercel.com in this response header (cookie value redacted): "Set-Cookie: _v-visitor-id=<redacted>; Path=/; Expires=Tue, 29 Dec 2026 15:14:40 GMT; Max-Age=7776000; Domain=.vercel.com; Secure; SameSite=lax". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### OpenAPI/Swagger Spec Exposed

**Low** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Confirmed by fetching the path and matching the file's signature in the response body — not a status code alone.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (10 pages, 5 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Verbose Server Framework Signature Leaked

**Info** · high confidence · A05:2021 – Security Misconfiguration · EASM

```
Informational scan-coverage context — not a detected vulnerability.
```

