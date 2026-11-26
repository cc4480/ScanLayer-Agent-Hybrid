# openstreetmap.org

- Requested: `https://www.openstreetmap.org`
- HTTP 200, 16.0s
- Score 83/100 — grade B
- 5 findings, 2 above Info

### Apache mod_status Exposed

**Medium** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Confirmed by fetching the path and matching the file's signature in the response body — not a status code alone.
```

### Cookie "_osm_banner_31day_2026" is set without the HttpOnly attribute

**Low** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.openstreetmap.org in this response header (cookie value redacted): "Set-Cookie: _osm_banner_31day_2026=<redacted>; path=/; samesite=lax; secure". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (10 pages, 30 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Verbose Server Framework Signature Leaked

**Info** · high confidence · A05:2021 – Security Misconfiguration · EASM

```
Informational scan-coverage context — not a detected vulnerability.
```

