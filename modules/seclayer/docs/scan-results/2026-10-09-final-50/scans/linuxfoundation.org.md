# linuxfoundation.org

- Requested: `https://www.linuxfoundation.org`
- HTTP 200, 11.7s
- Score 88/100 — grade B
- 4 findings, 2 above Info

### Missing X-Content-Type-Options (MIME Sniffing)

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed directly from the response headers and cookie attributes on the scanned URL.
```

### Exposed JavaScript source maps (2 files)

**Low** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Confirmed by fetching the path and matching the file's signature in the response body — not a status code alone.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (10 pages, 47 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

