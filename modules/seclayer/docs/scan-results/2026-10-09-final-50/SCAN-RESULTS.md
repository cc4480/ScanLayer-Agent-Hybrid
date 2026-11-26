# Scan results

Passive scans of 49 sites, captured 2026-10-10. That the engine still detects real vulnerabilities is shown separately by `scripts/detection-check.ts`, because an engine that reports nothing would also produce a clean-looking page like this one.

Passive means HTTP GETs and DNS lookups against publicly served pages. No authentication was attempted, no parameters were manipulated, and no state was altered on any site. Every finding below can be reproduced with `curl` or `dig`.

**247 findings across 49 sites, 119 of them above Info.** 0 critical, 0 high, 83 medium, 36 low, 128 info.

Not reached, and therefore not included:

- `https://www.npr.org` — Target https://www.npr.org did not respond within the timeout window.

## Every site

| Site | Score | Grade | Findings | Actionable | Critical | High | Medium | Low | Info | Detail |
|---|---:|:--:|---:|---:|---:|---:|---:|---:|---:|---|
| airtable.com | 73 | C | 8 | 5 | 0 | 0 | 3 | 2 | 3 | [detail](scans/airtable.com.md) |
| angular.dev | 78 | C | 5 | 3 | 0 | 0 | 3 | 0 | 2 | [detail](scans/angular.dev.md) |
| arstechnica.com | 100 | A | 2 | 0 | 0 | 0 | 0 | 0 | 2 | [detail](scans/arstechnica.com.md) |
| astro.build | 70 | C | 6 | 4 | 0 | 0 | 4 | 0 | 2 | [detail](scans/astro.build.md) |
| aws.amazon.com | 68 | D | 6 | 3 | 0 | 0 | 2 | 1 | 3 | [detail](scans/aws.amazon.com.md) |
| calendly.com | 70 | C | 6 | 4 | 0 | 0 | 2 | 2 | 2 | [detail](scans/calendly.com.md) |
| cloud.google.com | 100 | A | 3 | 0 | 0 | 0 | 0 | 0 | 3 | [detail](scans/cloud.google.com.md) |
| coursera.org | 88 | B | 6 | 3 | 0 | 0 | 1 | 2 | 3 | [detail](scans/coursera.org.md) |
| crowdstrike.com | 100 | A | 2 | 0 | 0 | 0 | 0 | 0 | 2 | [detail](scans/crowdstrike.com.md) |
| css-tricks.com | 93 | A | 3 | 1 | 0 | 0 | 1 | 0 | 2 | [detail](scans/css-tricks.com.md) |
| debian.org | 93 | A | 4 | 1 | 0 | 0 | 1 | 0 | 3 | [detail](scans/debian.org.md) |
| dev.to | 100 | A | 4 | 0 | 0 | 0 | 0 | 0 | 4 | [detail](scans/dev.to.md) |
| djangoproject.com | 93 | A | 4 | 1 | 0 | 0 | 1 | 0 | 3 | [detail](scans/djangoproject.com.md) |
| docker.com | 93 | A | 4 | 1 | 0 | 0 | 1 | 0 | 3 | [detail](scans/docker.com.md) |
| duolingo.com | 68 | D | 9 | 7 | 0 | 0 | 3 | 4 | 2 | [detail](scans/duolingo.com.md) |
| elastic.co | 83 | B | 6 | 3 | 0 | 0 | 2 | 1 | 3 | [detail](scans/elastic.co.md) |
| gnu.org | 93 | A | 4 | 1 | 0 | 0 | 1 | 0 | 3 | [detail](scans/gnu.org.md) |
| go.dev | 93 | A | 4 | 1 | 0 | 0 | 1 | 0 | 3 | [detail](scans/go.dev.md) |
| grafana.com | 70 | C | 6 | 3 | 0 | 0 | 3 | 0 | 3 | [detail](scans/grafana.com.md) |
| hashicorp.com | 70 | C | 6 | 4 | 0 | 0 | 4 | 0 | 2 | [detail](scans/hashicorp.com.md) |
| intercom.com | 90 | A | 5 | 2 | 0 | 0 | 1 | 1 | 3 | [detail](scans/intercom.com.md) |
| kernel.org | 85 | B | 4 | 1 | 0 | 0 | 1 | 0 | 3 | [detail](scans/kernel.org.md) |
| khanacademy.org | 75 | C | 5 | 4 | 0 | 0 | 3 | 1 | 1 | [detail](scans/khanacademy.org.md) |
| kubernetes.io | 78 | C | 5 | 3 | 0 | 0 | 3 | 0 | 2 | [detail](scans/kubernetes.io.md) |
| laravel.com | 80 | B | 6 | 3 | 0 | 0 | 2 | 1 | 3 | [detail](scans/laravel.com.md) |
| linuxfoundation.org | 88 | B | 4 | 2 | 0 | 0 | 1 | 1 | 2 | [detail](scans/linuxfoundation.org.md) |
| mailchimp.com | 80 | B | 7 | 4 | 0 | 0 | 2 | 2 | 3 | [detail](scans/mailchimp.com.md) |
| miro.com | 93 | A | 5 | 3 | 0 | 0 | 0 | 3 | 2 | [detail](scans/miro.com.md) |
| news.ycombinator.com | 100 | A | 3 | 0 | 0 | 0 | 0 | 0 | 3 | [detail](scans/news.ycombinator.com.md) |
| nodejs.org | 80 | B | 6 | 3 | 0 | 0 | 2 | 1 | 3 | [detail](scans/nodejs.org.md) |
| openstreetmap.org | 83 | B | 5 | 2 | 0 | 0 | 1 | 1 | 3 | [detail](scans/openstreetmap.org.md) |
| owasp.org | 100 | A | 3 | 0 | 0 | 0 | 0 | 0 | 3 | [detail](scans/owasp.org.md) |
| playwright.dev | 78 | C | 5 | 3 | 0 | 0 | 3 | 0 | 2 | [detail](scans/playwright.dev.md) |
| postgresql.org | 93 | A | 4 | 1 | 0 | 0 | 1 | 0 | 3 | [detail](scans/postgresql.org.md) |
| posthog.com | 80 | B | 6 | 3 | 0 | 0 | 2 | 1 | 3 | [detail](scans/posthog.com.md) |
| prometheus.io | 85 | B | 4 | 2 | 0 | 0 | 2 | 0 | 2 | [detail](scans/prometheus.io.md) |
| redis.io | 90 | A | 4 | 2 | 0 | 0 | 1 | 1 | 2 | [detail](scans/redis.io.md) |
| rubyonrails.org | 70 | C | 7 | 4 | 0 | 0 | 4 | 0 | 3 | [detail](scans/rubyonrails.org.md) |
| rust-lang.org | 78 | C | 6 | 3 | 0 | 0 | 3 | 0 | 3 | [detail](scans/rust-lang.org.md) |
| snyk.io | 100 | A | 3 | 0 | 0 | 0 | 0 | 0 | 3 | [detail](scans/snyk.io.md) |
| sqlite.org | 65 | D | 7 | 5 | 0 | 0 | 4 | 1 | 2 | [detail](scans/sqlite.org.md) |
| squarespace.com | 75 | C | 9 | 6 | 0 | 0 | 2 | 4 | 3 | [detail](scans/squarespace.com.md) |
| theverge.com | 85 | B | 7 | 4 | 0 | 0 | 1 | 3 | 3 | [detail](scans/theverge.com.md) |
| typescriptlang.org | 73 | C | 7 | 4 | 0 | 0 | 3 | 1 | 3 | [detail](scans/typescriptlang.org.md) |
| ubuntu.com | 95 | A | 4 | 1 | 0 | 0 | 0 | 1 | 3 | [detail](scans/ubuntu.com.md) |
| vite.dev | 78 | C | 6 | 3 | 0 | 0 | 3 | 0 | 3 | [detail](scans/vite.dev.md) |
| webflow.com | 93 | A | 3 | 1 | 0 | 0 | 1 | 0 | 2 | [detail](scans/webflow.com.md) |
| zalando.com | 70 | C | 6 | 4 | 0 | 0 | 4 | 0 | 2 | [detail](scans/zalando.com.md) |
| zendesk.com | 95 | A | 3 | 1 | 0 | 0 | 0 | 1 | 2 | [detail](scans/zendesk.com.md) |


**Grades, over the 49 sites actually reached:** A 20 · B 11 · C 15 · D 3 · F 0 — mean score 84.3.

**Higher is better.** 100 is clean; only critical/high/medium/low deduct, so a site whose findings are all info notices scores a true 100. Grade is `gradeForScore`: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F below.

> SecScan runs the opposite scale (0 = clean, A ≤ 10). The two numbers are not comparable in either direction.

## What came up most often

Across the 49 sites whose own pages were seen.

| Finding | Severity | Sites | OWASP |
|---|---|---:|---|
| Active Exploit Probing Skipped (Unverified Target) | Info | 49/49 | A05:2021 – Security Misconfiguration |
| Verbose Server Framework Signature Leaked | Info | 35/49 | A05:2021 – Security Misconfiguration |
| Missing Content-Security-Policy (CSP) | Medium | 25/49 | A05:2021 – Security Misconfiguration |
| Missing X-Content-Type-Options (MIME Sniffing) | Medium | 25/49 | A05:2021 – Security Misconfiguration |
| Missing X-Frame-Options / Clickjacking Immunity | Medium | 18/49 | A05:2021 – Security Misconfiguration |
| Missing Strict-Transport-Security (HSTS) Policy | Medium | 9/49 | A02:2021 – Cryptographic Failures |
| Application Surface Mapped (10 pages, 0 endpoints) | Info | 9/49 | A05:2021 – Security Misconfiguration |
| TLS Certificate Expiring Soon | Medium | 4/49 | A02:2021 – Cryptographic Failures |
| Exposed JavaScript source maps (2 files) | Low | 4/49 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 2 endpoints) | Info | 3/49 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 1 endpoints) | Info | 3/49 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 4 endpoints) | Info | 3/49 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 3 endpoints) | Info | 3/49 | A05:2021 – Security Misconfiguration |
| Content-Security-Policy is report-only (not enforced) | Low | 2/49 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 5 endpoints) | Info | 2/49 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 10 endpoints) | Info | 2/49 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 9 endpoints) | Info | 2/49 | A05:2021 – Security Misconfiguration |
| Cookie "aws-session-id" is set without the HttpOnly attribute | Medium | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "JSESSIONID" is set without the Secure attribute over HTTPS | Medium | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "CALENDLY_AUTHENTICATED_USER_STATUS" is set without the HttpOnly attribute | Medium | 1/49 | A05:2021 – Security Misconfiguration |
| Apache mod_status Exposed | Medium | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "brw" is set without the HttpOnly attribute | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "marketing-homepage-e4-segment" is set without the HttpOnly attribute | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "aws-priv" is set without the HttpOnly attribute | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "cal_anonymous_id" is set without the HttpOnly attribute | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "__204u" is set without the HttpOnly attribute | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "__204u" is set without the Secure attribute over HTTPS | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "logged_out_uuid" is set without the HttpOnly attribute | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "logged_out_uuid" is set without the Secure attribute over HTTPS | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "wuuid" is set without the HttpOnly attribute | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "wuuid" is set without the Secure attribute over HTTPS | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "euid" is set without the HttpOnly attribute | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "gtm_id" is set without the HttpOnly attribute | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "_fs_ch_st_FSBmUei20MqUiJb9" is set without the Secure attribute over HTTPS | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "_mcid" is set without the HttpOnly attribute | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "_mcid" is set without the Secure attribute over HTTPS | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "__ff_cookie_styles" is set without the HttpOnly attribute | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "server_experiment_viewed" is set without the HttpOnly attribute | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "server_experiment_viewed" is set without the Secure attribute over HTTPS | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "_osm_banner_31day_2026" is set without the HttpOnly attribute | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "gb_assignments" is set without the HttpOnly attribute | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "crumb" is set without the HttpOnly attribute | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "SS_ANALYTICS_ID" is set without the HttpOnly attribute | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "SS_MID" is set without the HttpOnly attribute | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "SS_MID" is set without the Secure attribute over HTTPS | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "_vm_consent_type" is set without the HttpOnly attribute | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "_vm_consent_type" is set without the Secure attribute over HTTPS | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Cookie "vmidv1" is set without the HttpOnly attribute | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Exposed JavaScript source maps (4 files) | Low | 1/49 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 259 endpoints) | Info | 1/49 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 123 endpoints) | Info | 1/49 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 25 endpoints) | Info | 1/49 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 21 endpoints) | Info | 1/49 | A05:2021 – Security Misconfiguration |
| OpenAPI/Swagger Spec Exposed | Info | 1/49 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 8 endpoints) | Info | 1/49 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 83 endpoints) | Info | 1/49 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (9 pages, 0 endpoints) | Info | 1/49 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 47 endpoints) | Info | 1/49 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 11 endpoints) | Info | 1/49 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (7 pages, 11 endpoints) | Info | 1/49 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 30 endpoints) | Info | 1/49 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (9 pages, 2 endpoints) | Info | 1/49 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (1 pages, 2 endpoints) | Info | 1/49 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 18 endpoints) | Info | 1/49 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (8 pages, 8 endpoints) | Info | 1/49 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (2 pages, 2 endpoints) | Info | 1/49 | A05:2021 – Security Misconfiguration |

