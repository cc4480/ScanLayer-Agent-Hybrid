# calendly.com

- Requested: `https://calendly.com`
- HTTP 200, 5.4s
- Score 70/100 — grade C
- 6 findings, 4 above Info

### Cookie "CALENDLY_AUTHENTICATED_USER_STATUS" is set without the HttpOnly attribute

**Medium** · high confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://calendly.com in this response header (cookie value redacted): "Set-Cookie: CALENDLY_AUTHENTICATED_USER_STATUS=<redacted>; path=/; Secure; SameSite=Strict". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Missing X-Frame-Options / Clickjacking Immunity

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed directly from the response headers and cookie attributes on the scanned URL.
```

### Content-Security-Policy is report-only (not enforced)

**Low** · high confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed directly from the response headers and cookie attributes on the scanned URL.
```

### Cookie "cal_anonymous_id" is set without the HttpOnly attribute

**Low** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://calendly.com in this response header (cookie value redacted): "Set-Cookie: cal_anonymous_id=<redacted>; path=/; max-age=31536000; Secure; SameSite=Lax". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (10 pages, 3 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

