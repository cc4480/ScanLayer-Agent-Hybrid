# linkedin.com

- Requested: `https://www.linkedin.com`
- HTTP 200, 7.1s
- Score 70/100 — grade C
- 5 findings, 3 above Info

### Cookie "JSESSIONID" is set without the HttpOnly attribute

**Medium** · high confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.linkedin.com in this response header (cookie value redacted): "Set-Cookie: JSESSIONID=<redacted>; SameSite=None; Path=/; Domain=.www.linkedin.com; Secure". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "trkCode" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.linkedin.com in this response header (cookie value redacted): "Set-Cookie: trkCode=<redacted>; Max-Age=5". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "trkCode" is set without the Secure attribute over HTTPS

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.linkedin.com in this response header (cookie value redacted): "Set-Cookie: trkCode=<redacted>; Max-Age=5". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (10 pages, 245 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

