# sqlite.org

- Requested: `https://www.sqlite.org`
- HTTP 200, 6.4s
- Score 65/100 — grade D
- 7 findings, 5 above Info

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

### Missing X-Frame-Options / Clickjacking Immunity

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed directly from the response headers and cookie attributes on the scanned URL.
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

### Application Surface Mapped (1 pages, 2 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

