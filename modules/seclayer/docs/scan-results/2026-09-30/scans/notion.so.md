# notion.so

- Requested: `https://www.notion.so`
- HTTP 200, 8.9s
- Score 63/100 — grade D
- 8 findings, 5 above Info

### Cookie "notion_browser_id" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.notion.so in this response header (cookie value redacted): "Set-Cookie: notion_browser_id=<redacted>; Path=/; Expires=Thu, 30 Sep 2027 15:18:15 GMT; Domain=.notion.com". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "notion_browser_id" is set without the Secure attribute over HTTPS

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.notion.so in this response header (cookie value redacted): "Set-Cookie: notion_browser_id=<redacted>; Path=/; Expires=Thu, 30 Sep 2027 15:18:15 GMT; Domain=.notion.com". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "notion_check_cookie_consent" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.notion.so in this response header (cookie value redacted): "Set-Cookie: notion_check_cookie_consent=<redacted>; Path=/; Expires=Thu, 01 Oct 2026 15:18:15 GMT; Domain=.notion.com". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "notion_check_cookie_consent" is set without the Secure attribute over HTTPS

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.notion.so in this response header (cookie value redacted): "Set-Cookie: notion_check_cookie_consent=<redacted>; Path=/; Expires=Thu, 01 Oct 2026 15:18:15 GMT; Domain=.notion.com". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Missing X-Content-Type-Options (MIME Sniffing)

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed directly from the response headers and cookie attributes on the scanned URL.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (10 pages, 6 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Verbose Server Framework Signature Leaked

**Info** · high confidence · A05:2021 – Security Misconfiguration · EASM

```
Informational scan-coverage context — not a detected vulnerability.
```

