# Scan results

Passive scans of 38 sites, captured 2026-09-30. That the engine still detects real vulnerabilities is shown separately by `scripts/detection-check.ts`, because an engine that reports nothing would also produce a clean-looking page like this one.

Passive means HTTP GETs and DNS lookups against publicly served pages. No authentication was attempted, no parameters were manipulated, and no state was altered on any site. Every finding below can be reproduced with `curl` or `dig`.

**161 findings across 38 sites, 67 of them above Info.** 0 critical, 0 high, 58 medium, 9 low, 94 info.

## Read this before comparing sites

8 of these sites answered with a bot-protection interstitial rather than their own page: `amazon.co.uk`, `apnews.com`, `ebay.com`, `etsy.com`, `npmjs.com`, `nytimes.com`, `reuters.com`, `stackoverflow.com`. Every check that reads the response would have described that challenge page rather than the site, so those findings are withheld. **That is suppressed coverage, not a clean result** — it means their page was never seen, and their scores reflect only what could still be observed. Their counts are not comparable with the rest.

## Every site

| Site | Score | Grade | Findings | Actionable | Critical | High | Medium | Low | Info | Detail |
|---|---:|:--:|---:|---:|---:|---:|---:|---:|---:|---|
| amazon.co.uk * | 100 | A | 2 | 0 | 0 | 0 | 0 | 0 | 2 | [detail](scans/amazon.co.uk.md) |
| apnews.com * | 100 | A | 2 | 0 | 0 | 0 | 0 | 0 | 2 | [detail](scans/apnews.com.md) |
| apple.com | 100 | A | 3 | 0 | 0 | 0 | 0 | 0 | 3 | [detail](scans/apple.com.md) |
| archive.org | 80 | B | 5 | 3 | 0 | 0 | 2 | 1 | 2 | [detail](scans/archive.org.md) |
| bbc.co.uk | 100 | A | 3 | 0 | 0 | 0 | 0 | 0 | 3 | [detail](scans/bbc.co.uk.md) |
| cloudflare.com | 90 | A | 4 | 2 | 0 | 0 | 0 | 2 | 2 | [detail](scans/cloudflare.com.md) |
| digitalocean.com | 85 | B | 5 | 2 | 0 | 0 | 2 | 0 | 3 | [detail](scans/digitalocean.com.md) |
| dropbox.com | 95 | A | 4 | 1 | 0 | 0 | 0 | 1 | 3 | [detail](scans/dropbox.com.md) |
| ebay.com * | 100 | A | 2 | 0 | 0 | 0 | 0 | 0 | 2 | [detail](scans/ebay.com.md) |
| etsy.com * | 100 | A | 2 | 0 | 0 | 0 | 0 | 0 | 2 | [detail](scans/etsy.com.md) |
| european-union.europa.eu | 93 | A | 3 | 1 | 0 | 0 | 1 | 0 | 2 | [detail](scans/european-union.europa.eu.md) |
| fastly.com | 68 | D | 8 | 5 | 0 | 0 | 3 | 2 | 3 | [detail](scans/fastly.com.md) |
| figma.com | 100 | A | 2 | 0 | 0 | 0 | 0 | 0 | 2 | [detail](scans/figma.com.md) |
| github.com | 100 | A | 3 | 0 | 0 | 0 | 0 | 0 | 3 | [detail](scans/github.com.md) |
| gitlab.com | 78 | C | 5 | 3 | 0 | 0 | 3 | 0 | 2 | [detail](scans/gitlab.com.md) |
| google.com | 80 | B | 6 | 3 | 0 | 0 | 2 | 1 | 3 | [detail](scans/google.com.md) |
| gov.uk | 100 | A | 3 | 0 | 0 | 0 | 0 | 0 | 3 | [detail](scans/gov.uk.md) |
| letsencrypt.org | 100 | A | 3 | 0 | 0 | 0 | 0 | 0 | 3 | [detail](scans/letsencrypt.org.md) |
| linkedin.com | 70 | C | 5 | 3 | 0 | 0 | 3 | 0 | 2 | [detail](scans/linkedin.com.md) |
| mapbox.com | 100 | A | 2 | 0 | 0 | 0 | 0 | 0 | 2 | [detail](scans/mapbox.com.md) |
| microsoft.com | 60 | D | 8 | 6 | 0 | 0 | 6 | 0 | 2 | [detail](scans/microsoft.com.md) |
| mozilla.org | 100 | A | 3 | 0 | 0 | 0 | 0 | 0 | 3 | [detail](scans/mozilla.org.md) |
| nasa.gov | 85 | B | 5 | 2 | 0 | 0 | 2 | 0 | 3 | [detail](scans/nasa.gov.md) |
| netlify.com | 73 | C | 7 | 4 | 0 | 0 | 3 | 1 | 3 | [detail](scans/netlify.com.md) |
| notion.so | 63 | D | 8 | 5 | 0 | 0 | 5 | 0 | 3 | [detail](scans/notion.so.md) |
| npmjs.com * | 100 | A | 2 | 0 | 0 | 0 | 0 | 0 | 2 | [detail](scans/npmjs.com.md) |
| nytimes.com * | 100 | A | 2 | 0 | 0 | 0 | 0 | 0 | 2 | [detail](scans/nytimes.com.md) |
| paypal.com | 93 | A | 3 | 1 | 0 | 0 | 1 | 0 | 2 | [detail](scans/paypal.com.md) |
| reddit.com | 93 | A | 4 | 1 | 0 | 0 | 1 | 0 | 3 | [detail](scans/reddit.com.md) |
| reuters.com * | 100 | A | 2 | 0 | 0 | 0 | 0 | 0 | 2 | [detail](scans/reuters.com.md) |
| shopify.com | 85 | B | 4 | 2 | 0 | 0 | 2 | 0 | 2 | [detail](scans/shopify.com.md) |
| slack.com | 63 | D | 8 | 5 | 0 | 0 | 5 | 0 | 3 | [detail](scans/slack.com.md) |
| stackoverflow.com * | 100 | A | 2 | 0 | 0 | 0 | 0 | 0 | 2 | [detail](scans/stackoverflow.com.md) |
| stripe.com | 93 | A | 4 | 1 | 0 | 0 | 1 | 0 | 3 | [detail](scans/stripe.com.md) |
| theguardian.com | 70 | C | 6 | 4 | 0 | 0 | 4 | 0 | 2 | [detail](scans/theguardian.com.md) |
| vercel.com | 73 | C | 7 | 4 | 0 | 0 | 3 | 1 | 3 | [detail](scans/vercel.com.md) |
| wikipedia.org | 78 | C | 6 | 3 | 0 | 0 | 3 | 0 | 3 | [detail](scans/wikipedia.org.md) |
| zoom.us | 60 | D | 8 | 6 | 0 | 0 | 6 | 0 | 2 | [detail](scans/zoom.us.md) |

`*` answered with a bot-protection interstitial; see above.

**Grades, over the 30 sites actually reached:** A 14 · B 5 · C 6 · D 5 · F 0 — mean score 84.3.

**Higher is better.** 100 is clean; only critical/high/medium/low deduct, so a site whose findings are all info notices scores a true 100. Grade is `gradeForScore`: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F below.

> SecScan runs the opposite scale (0 = clean, A ≤ 10). The two numbers are not comparable in either direction.

## What came up most often

Across the 30 sites whose own pages were seen.

| Finding | Severity | Sites | OWASP |
|---|---|---:|---|
| Active Exploit Probing Skipped (Unverified Target) | Info | 30/30 | A05:2021 – Security Misconfiguration |
| Verbose Server Framework Signature Leaked | Info | 19/30 | A05:2021 – Security Misconfiguration |
| Missing X-Content-Type-Options (MIME Sniffing) | Medium | 11/30 | A05:2021 – Security Misconfiguration |
| Missing Content-Security-Policy (CSP) | Medium | 10/30 | A05:2021 – Security Misconfiguration |
| Missing X-Frame-Options / Clickjacking Immunity | Medium | 7/30 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 2 endpoints) | Info | 4/30 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 3 endpoints) | Info | 4/30 | A05:2021 – Security Misconfiguration |
| OpenAPI/Swagger Spec Exposed | Low | 3/30 | A05:2021 – Security Misconfiguration |
| TLS Certificate Expiring Soon | Low | 2/30 | A02:2021 – Cryptographic Failures |
| Application Surface Mapped (10 pages, 9 endpoints) | Info | 2/30 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 0 endpoints) | Info | 2/30 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 1 endpoints) | Info | 2/30 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 6 endpoints) | Info | 2/30 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (1 pages, 1 endpoints) | Info | 2/30 | A05:2021 – Security Misconfiguration |
| Missing Strict-Transport-Security (HSTS) Policy | Medium | 1/30 | A02:2021 – Cryptographic Failures |
| Cookie "_fs_ch_st_FSBmUei20MqUiJb9" is set without the Secure attribute over HTTPS | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "ff_revamp" is set without the HttpOnly attribute | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "__Secure-STRP" is set without the HttpOnly attribute | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "JSESSIONID" is set without the HttpOnly attribute | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "trkCode" is set without the HttpOnly attribute | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "trkCode" is set without the Secure attribute over HTTPS | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "bStore" is set without the HttpOnly attribute | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "bStore" is set without the Secure attribute over HTTPS | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "CAS_PROGRAM" is set without the HttpOnly attribute | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "notion_browser_id" is set without the HttpOnly attribute | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "notion_browser_id" is set without the Secure attribute over HTTPS | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "notion_check_cookie_consent" is set without the HttpOnly attribute | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "notion_check_cookie_consent" is set without the Secure attribute over HTTPS | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "ts_c" is set without the HttpOnly attribute | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "edgebucket" is set without the HttpOnly attribute | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "b" is set without the HttpOnly attribute | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "utm" is set without the HttpOnly attribute | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "x" is set without the HttpOnly attribute | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "cid" is set without the HttpOnly attribute | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "gu_client_ab_tests" is set without the HttpOnly attribute | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "gu_client_ab_tests" is set without the Secure attribute over HTTPS | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "gu_v2_mvt_id" is set without the HttpOnly attribute | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "gu_v2_mvt_id" is set without the Secure attribute over HTTPS | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "_v-consent" is set without the HttpOnly attribute | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "_v-visitor-id-renewed" is set without the HttpOnly attribute | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "_v-visitor-id" is set without the HttpOnly attribute | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "_zm_billing_visitor_guid" is set without the HttpOnly attribute | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "_zm_mtk_guid" is set without the HttpOnly attribute | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Cookie "_zm_visitor_guid" is set without the HttpOnly attribute | Medium | 1/30 | A05:2021 – Security Misconfiguration |
| Exposed JavaScript source map (/offshoot_assets/vendor/lit/polyfill-support.js.map) | Low | 1/30 | A05:2021 – Security Misconfiguration |
| Exposed JavaScript source maps (3 files) | Low | 1/30 | A05:2021 – Security Misconfiguration |
| Exposed JavaScript source maps (6 files) | Low | 1/30 | A05:2021 – Security Misconfiguration |
| Content-Security-Policy is report-only (not enforced) | Low | 1/30 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 36 endpoints) | Info | 1/30 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 46 endpoints) | Info | 1/30 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (9 pages, 131 endpoints) | Info | 1/30 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 245 endpoints) | Info | 1/30 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (4 pages, 37 endpoints) | Info | 1/30 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 11 endpoints) | Info | 1/30 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 12 endpoints) | Info | 1/30 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 85 endpoints) | Info | 1/30 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 633 endpoints) | Info | 1/30 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 28 endpoints) | Info | 1/30 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 5 endpoints) | Info | 1/30 | A05:2021 – Security Misconfiguration |

