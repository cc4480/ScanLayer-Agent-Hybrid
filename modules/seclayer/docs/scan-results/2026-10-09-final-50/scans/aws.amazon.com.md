# aws.amazon.com

- Requested: `https://aws.amazon.com`
- HTTP 200, 8.3s
- Score 68/100 — grade D
- 6 findings, 3 above Info

### Cookie "aws-session-id" is set without the HttpOnly attribute

**Medium** · high confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://aws.amazon.com in this response header (cookie value redacted): "Set-Cookie: aws-session-id=<redacted>; Domain=.amazon.com; Expires=Sun, 10 Oct 2027 04:28:57 GMT; Path=/; Secure". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "JSESSIONID" is set without the Secure attribute over HTTPS

**Medium** · high confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://aws.amazon.com in this response header (cookie value redacted): "Set-Cookie: JSESSIONID=<redacted>; Path=/; HttpOnly". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "aws-priv" is set without the HttpOnly attribute

**Low** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://aws.amazon.com in this response header (cookie value redacted): "Set-Cookie: aws-priv=<redacted>; Version=1; Comment="Anonymous cookie for privacy regulations"; Domain=.aws.amazon.com; Max-Age=31536000; Expires=Sun, 10 Oct 2027 04:28:51 GMT; Path=/; Secure". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (10 pages, 259 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Verbose Server Framework Signature Leaked

**Info** · high confidence · A05:2021 – Security Misconfiguration · EASM

```
Informational scan-coverage context — not a detected vulnerability.
```

