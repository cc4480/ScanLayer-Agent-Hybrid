# miro.com

- Requested: `https://miro.com`
- HTTP 200, 9.7s
- Score 93/100 — grade A
- 5 findings, 3 above Info

### Cookie "__ff_cookie_styles" is set without the HttpOnly attribute

**Low** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://miro.com in this response header (cookie value redacted): "Set-Cookie: __ff_cookie_styles=<redacted>; path=/; expires=Sat, 10 Oct 2026 04:32:30 GMT; samesite=lax; secure". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "server_experiment_viewed" is set without the HttpOnly attribute

**Low** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://miro.com in this response header (cookie value redacted): "Set-Cookie: server_experiment_viewed=<redacted>; path=/". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "server_experiment_viewed" is set without the Secure attribute over HTTPS

**Low** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://miro.com in this response header (cookie value redacted): "Set-Cookie: server_experiment_viewed=<redacted>; path=/". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (10 pages, 11 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

