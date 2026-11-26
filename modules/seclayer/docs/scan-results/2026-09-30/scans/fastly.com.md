# fastly.com

- Requested: `https://www.fastly.com`
- HTTP 200, 14.5s
- Score 68/100 — grade D
- 8 findings, 5 above Info

### Cookie "_fs_ch_st_FSBmUei20MqUiJb9" is set without the Secure attribute over HTTPS

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.fastly.com in this response header (cookie value redacted): "Set-Cookie: _fs_ch_st_FSBmUei20MqUiJb9=<redacted>; Max-Age=10; HttpOnly; Path=/". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "ff_revamp" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.fastly.com in this response header (cookie value redacted): "Set-Cookie: ff_revamp=<redacted>; domain=.fastly.com; path=/; max-age=2592000; SameSite=Lax; Secure". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Missing Content-Security-Policy (CSP)

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed directly from the response headers and cookie attributes on the scanned URL.
```

### Exposed JavaScript source maps (6 files)

**Low** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Confirmed by fetching the path and matching the file's signature in the response body — not a status code alone.
```

### TLS Certificate Expiring Soon

**Low** · high confidence · A02:2021 – Cryptographic Failures · EASM

```
Observed from the target's response headers and TLS state.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (10 pages, 1 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Verbose Server Framework Signature Leaked

**Info** · high confidence · A05:2021 – Security Misconfiguration · EASM

```
Informational scan-coverage context — not a detected vulnerability.
```

