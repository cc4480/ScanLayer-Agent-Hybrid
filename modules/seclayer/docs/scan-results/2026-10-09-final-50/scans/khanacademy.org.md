# khanacademy.org

- Requested: `https://www.khanacademy.org`
- HTTP 200, 3.0s
- Score 75/100 — grade C
- 5 findings, 4 above Info

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

### Missing X-Frame-Options / Clickjacking Immunity

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed directly from the response headers and cookie attributes on the scanned URL.
```

### Cookie "_fs_ch_st_FSBmUei20MqUiJb9" is set without the Secure attribute over HTTPS

**Low** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.khanacademy.org in this response header (cookie value redacted): "Set-Cookie: _fs_ch_st_FSBmUei20MqUiJb9=<redacted>; Max-Age=10; HttpOnly; Path=/". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

