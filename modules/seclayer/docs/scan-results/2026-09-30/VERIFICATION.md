# Verification — 2026-09-30 corpus run

Every actionable (non-info) finding from the 38-site passive run was re-checked
**independently of the scanner**: a separate script re-fetched each site and
compared the raw response against the claim. Nothing from `server/` is used by
the checker. Raw engine output: [`raw.json`](raw.json).

## Result

- **67 actionable findings across 30 graded sites.**
- **59 confirmed true** by re-fetching: header absent, cookie flag absent, spec or source map served and valid, certificate expiring within 30 days.
- **8 cookie findings did not reproduce on a fresh homepage fetch.** They are set on other pages the crawler visits, or conditionally. The raw `Set-Cookie` lines the engine recorded show the flag really is absent in all 8 (table below), so these are true observations.
- **0 false positives** among the 67 (after one fix, described next).

## What the verification found

The first pass over this run, before the fix in commit `83ec4da`, produced 68 findings, and one was a **false positive**:

- **www.reddit.com, "Swagger UI Exposed".** Reddit answered `/swagger-ui/index.html` with a bot-challenge page (HTTP 200, title "Reddit", a hidden form whose `action` is the requested path). The detection rule matched the bare word `swagger-ui`, which was the request echoed back. There was no Swagger UI. A nonexistent path returned the same page (8,418 vs 8,429 bytes; the difference is the length of the echoed path).
- **Fix:** a word matcher whose word is part of the request path now matches against the response with that echo removed. Only `swagger-ui-exposed` and `jolokia-exposed` were exposed to it (checked programmatically across all 61 templates). A real Swagger UI page still matches; directory listings and every other matcher are untouched. Three new tests cover this; the suite is 939 tests, 0 failing.
- **Effect:** reddit 88 to 93 on the re-run.
- The checker itself had passed this finding at first, because its regex also matched the echoed path. It now requires real Swagger markers and rejects pages equal to the nonexistent-path baseline.

Findings that disappeared since 2026-09-10 were also checked. `github.com/phpmyadmin` is an ordinary GitHub organisation page and `github.com/graphiql` an ordinary repository page, which is why the earlier phpMyAdmin and GraphiQL findings on github.com were false positives and are now correctly absent.

## Grades, per URL

Higher is better: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F below. "Non-info" counts
critical, high, medium and low findings.

| Host | Score | Status | Non-info findings | 2026-09-10 |
|---|---|---|---|---|
| apnews.com | — (blocked) | not graded | 0 | 78 C |
| archive.org | 80 **B** | graded | 3 | 80 B |
| european-union.europa.eu | 93 **A** | graded | 1 | 93 A |
| github.com | 100 **A** | graded | 0 | 73 C |
| gitlab.com | 78 **C** | graded | 3 | 78 C |
| google.com | 80 **B** | graded | 3 | 80 B |
| letsencrypt.org | 100 **A** | graded | 0 | 0 F |
| slack.com | 63 **D** | graded | 5 | 63 D |
| stackoverflow.com | — (blocked) | not graded | 0 | 100 A |
| stripe.com | 93 **A** | graded | 1 | 93 A |
| vercel.com | 73 **C** | graded | 4 | 75 C |
| www.amazon.co.uk | — (blocked) | not graded | 0 | 40 F |
| www.apple.com | 100 **A** | graded | 0 | 85 B |
| www.bbc.co.uk | 100 **A** | graded | 0 | 100 A |
| www.cloudflare.com | 90 **A** | graded | 2 | 65 D |
| www.digitalocean.com | 85 **B** | graded | 2 | 85 B |
| www.dropbox.com | 95 **A** | graded | 1 | 100 A |
| www.ebay.com | — (blocked) | not graded | 0 | 100 A |
| www.etsy.com | — (blocked) | not graded | 0 | 100 A |
| www.fastly.com | 68 **D** | graded | 5 | 73 C |
| www.figma.com | 100 **A** | graded | 0 | 100 A |
| www.gov.uk | 100 **A** | graded | 0 | 100 A |
| www.linkedin.com | 70 **C** | graded | 3 | 85 B |
| www.mapbox.com | 100 **A** | graded | 0 | 100 A |
| www.microsoft.com | 60 **D** | graded | 6 | 60 D |
| www.mozilla.org | 100 **A** | graded | 0 | 100 A |
| www.nasa.gov | 85 **B** | graded | 2 | 85 B |
| www.netlify.com | 73 **C** | graded | 4 | 73 C |
| www.notion.so | 63 **D** | graded | 5 | 63 D |
| www.npmjs.com | — (blocked) | not graded | 0 | 100 A |
| www.nytimes.com | — (blocked) | not graded | 0 | 48 F |
| www.paypal.com | 93 **A** | graded | 1 | 93 A |
| www.reddit.com | 93 **A** | graded | 1 | 68 D |
| www.reuters.com | — (blocked) | not graded | 0 | 100 A |
| www.shopify.com | 85 **B** | graded | 2 | 78 C |
| www.theguardian.com | 70 **C** | graded | 4 | 70 C |
| www.wikipedia.org | 78 **C** | graded | 3 | 63 D |
| zoom.us | 60 **D** | graded | 6 | 60 D |

**Graded distribution (30 sites):** A 14 · B 5 · C 6 · D 5 · F 0. 0 critical, 0 high.

## Not graded: bot protection blocked the scan (8 sites)

The report for each of these now states exactly why the scan was judged blocked:
the HTTP status, the rule that fired and the value it fired on. Each was also
checked independently with curl, which got the same refusal or challenge.

| Site | HTTP status | Why it was judged a block (from the report) |
|---|---|---|
| apnews.com | 403 | The server answered with HTTP 403 Forbidden and a Cloudflare response header that says the request was challenged or blocked (cf-mitigated response header: challenge). Cloudflare sets that header on the requests it stops. |
| stackoverflow.com | 403 | The server answered with HTTP 403 Forbidden and a Cloudflare response header that says the request was challenged or blocked (cf-mitigated response header: challenge). Cloudflare sets that header on the requests it stops. |
| www.amazon.co.uk | 202 | The server answered with HTTP 202 and an AWS WAF response header that says the request was challenged or blocked (x-amzn-waf-action response header: challenge). AWS WAF sets that header on the requests it stops. |
| www.ebay.com | 403 | The server answered with HTTP 403 Forbidden and only a 1,829-character body titled "Error Page / eBay". No bot-protection vendor was identified. It was judged a block, not the site's page, because a refusal status with a body this small is not something a site serves as its homepage. |
| www.etsy.com | 403 | The server answered with HTTP 403 Forbidden and a 776-character body containing DataDome's challenge fingerprint (DataDome captcha delivery). That marker appears only on DataDome's challenge or captcha pages. |
| www.npmjs.com | 403 | The server answered with HTTP 403 Forbidden and a Cloudflare response header that says the request was challenged or blocked (cf-mitigated response header: challenge). Cloudflare sets that header on the requests it stops. |
| www.nytimes.com | 403 | The server answered with HTTP 403 Forbidden and a 771-character body containing DataDome's challenge fingerprint (DataDome captcha delivery). That marker appears only on DataDome's challenge or captcha pages. |
| www.reuters.com | 401 | The server answered with HTTP 401 Unauthorized and a 771-character body containing DataDome's challenge fingerprint (DataDome captcha delivery). That marker appears only on DataDome's challenge or captcha pages. |

Nothing on these sites was observed. The engine still computes a numeric score
near 100 for such a scan, because only info notices survive, but the product
**does not grade it**: the grade is N/A (`server/scoring.ts`), the gauge shows an
incomplete state and the PDF says "N/A — scan intercepted". These rows are
therefore not grades, and no letter should be read from them. (An earlier note in
[`../../SCAN-RESULTS.md`](../../SCAN-RESULTS.md) describing the 100/A as unfixed predates that change.)

## Findings that need context (true, but low signal)

29 of the 67 findings are cookie-flag findings. All are true in the sense
that the flag is absent from the observed `Set-Cookie`. Most are analytics,
consent, A/B or visitor-ID cookies that page JavaScript is meant to read, and
some live only seconds. Only one looks like a real session cookie:
**www.linkedin.com `JSESSIONID` without HttpOnly**.

Raw `Set-Cookie` recorded by the engine for the 8 that a homepage refetch did not show:

| Site | Cookie | Observed attributes |
|---|---|---|
| www.fastly.com | `_fs_ch_st_FSBmUei20MqUiJb9` | Max-Age=10; HttpOnly; Path=/ (no Secure) |
| www.linkedin.com | `trkCode` | Max-Age=5 (no Secure, no HttpOnly) |
| www.linkedin.com | `trkCode` | Max-Age=5 (no Secure, no HttpOnly) |
| www.microsoft.com | `bStore` | expires within minutes (no Secure, no HttpOnly) |
| www.microsoft.com | `bStore` | expires within minutes (no Secure, no HttpOnly) |
| zoom.us | `_zm_mtk_guid` | Secure; no HttpOnly |
| zoom.us | `_zm_visitor_guid` | Secure; no HttpOnly |
| zoom.us | `_zm_billing_visitor_guid` | Secure; no HttpOnly |

Each of these deducts as a medium, which is why cookie-heavy sites score low.
See the note on cookie volume in [`../../SCAN-RESULTS.md`](../../SCAN-RESULTS.md).

## Every finding, with its independent check

| Site | Finding | Sev | Verdict | What was observed |
|---|---|---|---|---|
| archive.org | Missing X-Frame-Options / Clickjacking Immunity | medium | TRUE | xfo=null frame-ancestors=false |
| archive.org | Missing X-Content-Type-Options (MIME Sniffing) | medium | TRUE | x-content-type-options=null |
| archive.org | Exposed JavaScript source map (/offshoot_assets/vendor/lit/polyfill-su | low | TRUE | polyfill-support.js.map:200:validmap |
| european-union.europa.eu | Missing Content-Security-Policy (CSP) | medium | TRUE | no CSP (report-only=false) |
| gitlab.com | Missing Content-Security-Policy (CSP) | medium | TRUE | no CSP (report-only=false) |
| gitlab.com | Missing X-Frame-Options / Clickjacking Immunity | medium | TRUE | xfo=null frame-ancestors=false |
| gitlab.com | Missing X-Content-Type-Options (MIME Sniffing) | medium | TRUE | x-content-type-options=null |
| google.com | Missing X-Content-Type-Options (MIME Sniffing) | medium | TRUE | x-content-type-options=null |
| google.com | Cookie "__Secure-STRP" is set without the HttpOnly attribute | medium | TRUE | {"name":"__Secure-STRP","httpOnly":false,"secure":true} |
| google.com | Content-Security-Policy is report-only (not enforced) | low | TRUE | enforced=false reportOnly=true |
| slack.com | Missing Content-Security-Policy (CSP) | medium | TRUE | no CSP (report-only=false) |
| slack.com | Missing X-Content-Type-Options (MIME Sniffing) | medium | TRUE | x-content-type-options=null |
| slack.com | Cookie "utm" is set without the HttpOnly attribute | medium | TRUE | {"name":"utm","httpOnly":false,"secure":true} |
| slack.com | Cookie "b" is set without the HttpOnly attribute | medium | TRUE | {"name":"b","httpOnly":false,"secure":true} |
| slack.com | Cookie "x" is set without the HttpOnly attribute | medium | TRUE | {"name":"x","httpOnly":false,"secure":true} |
| stripe.com | Cookie "cid" is set without the HttpOnly attribute | medium | TRUE | {"name":"cid","httpOnly":false,"secure":true} |
| vercel.com | Cookie "_v-consent" is set without the HttpOnly attribute | medium | TRUE | {"name":"_v-consent","httpOnly":false,"secure":true} |
| vercel.com | Cookie "_v-visitor-id" is set without the HttpOnly attribute | medium | TRUE | {"name":"_v-visitor-id","httpOnly":false,"secure":true} |
| vercel.com | Cookie "_v-visitor-id-renewed" is set without the HttpOnly attribute | medium | TRUE | {"name":"_v-visitor-id-renewed","httpOnly":false,"secure":true} |
| vercel.com | OpenAPI/Swagger Spec Exposed | low | TRUE | status=200 ct=application/json; charset=utf-8 openapi=3.0.3 paths=315 |
| www.cloudflare.com | Exposed JavaScript source maps (3 files) | low | TRUE | page.V2R8AmkL.js.map:200:validmap Globe.astro_astro_type_script_:200:validmap StripeMorphHero.astro_astro_ty:200:validmap |
| www.cloudflare.com | OpenAPI/Swagger Spec Exposed | low | TRUE | status=200 ct=application/json openapi=3.1.0 paths=4 |
| www.digitalocean.com | Missing Strict-Transport-Security (HSTS) Policy | medium | TRUE | hsts=null |
| www.digitalocean.com | Missing X-Content-Type-Options (MIME Sniffing) | medium | TRUE | x-content-type-options=null |
| www.dropbox.com | TLS Certificate Expiring Soon | low | TRUE | valid_to=Oct 14 23:59:59 2026 GMT (14d) |
| www.fastly.com | Missing Content-Security-Policy (CSP) | medium | TRUE | no CSP (report-only=false) |
| www.fastly.com | Cookie "ff_revamp" is set without the HttpOnly attribute | medium | TRUE | {"name":"ff_revamp","httpOnly":false,"secure":true} |
| www.fastly.com | Cookie "_fs_ch_st_FSBmUei20MqUiJb9" is set without the Secure attribut | medium | NOT-REPRODUCED | cookie not set on re-fetch (may be conditional/A-B) |
| www.fastly.com | TLS Certificate Expiring Soon | low | TRUE | valid_to=Oct 14 18:37:49 2026 GMT (14d) |
| www.fastly.com | Exposed JavaScript source maps (6 files) | low | TRUE | page.BJmh16QS.js.map:200:validmap SearchCombobox.astro_astro_typ:200:validmap Search.astro_astro_type_script:200:validmap DesktopNav.astro_astro_type_sc:200:val |
| www.linkedin.com | Cookie "JSESSIONID" is set without the HttpOnly attribute | medium | TRUE | {"name":"JSESSIONID","httpOnly":false,"secure":true} |
| www.linkedin.com | Cookie "trkCode" is set without the Secure attribute over HTTPS | medium | NOT-REPRODUCED | cookie not set on re-fetch (may be conditional/A-B) |
| www.linkedin.com | Cookie "trkCode" is set without the HttpOnly attribute | medium | NOT-REPRODUCED | cookie not set on re-fetch (may be conditional/A-B) |
| www.microsoft.com | Missing Content-Security-Policy (CSP) | medium | TRUE | no CSP (report-only=false) |
| www.microsoft.com | Missing X-Frame-Options / Clickjacking Immunity | medium | TRUE | xfo=null frame-ancestors=false |
| www.microsoft.com | Missing X-Content-Type-Options (MIME Sniffing) | medium | TRUE | x-content-type-options=null |
| www.microsoft.com | Cookie "CAS_PROGRAM" is set without the HttpOnly attribute | medium | TRUE | {"name":"CAS_PROGRAM","httpOnly":false,"secure":true} |
| www.microsoft.com | Cookie "bStore" is set without the Secure attribute over HTTPS | medium | NOT-REPRODUCED | cookie not set on re-fetch (may be conditional/A-B) |
| www.microsoft.com | Cookie "bStore" is set without the HttpOnly attribute | medium | NOT-REPRODUCED | cookie not set on re-fetch (may be conditional/A-B) |
| www.nasa.gov | Missing Content-Security-Policy (CSP) | medium | TRUE | no CSP (report-only=false) |
| www.nasa.gov | Missing X-Content-Type-Options (MIME Sniffing) | medium | TRUE | x-content-type-options=null |
| www.netlify.com | Missing Content-Security-Policy (CSP) | medium | TRUE | no CSP (report-only=false) |
| www.netlify.com | Missing X-Frame-Options / Clickjacking Immunity | medium | TRUE | xfo=null frame-ancestors=false |
| www.netlify.com | Missing X-Content-Type-Options (MIME Sniffing) | medium | TRUE | x-content-type-options=null |
| www.netlify.com | OpenAPI/Swagger Spec Exposed | low | TRUE | status=200 ct=application/json openapi=3.0.0 paths=112 |
| www.notion.so | Missing X-Content-Type-Options (MIME Sniffing) | medium | TRUE | x-content-type-options=null |
| www.notion.so | Cookie "notion_browser_id" is set without the Secure attribute over HT | medium | TRUE | {"name":"notion_browser_id","httpOnly":false,"secure":false} |
| www.notion.so | Cookie "notion_browser_id" is set without the HttpOnly attribute | medium | TRUE | {"name":"notion_browser_id","httpOnly":false,"secure":false} |
| www.notion.so | Cookie "notion_check_cookie_consent" is set without the Secure attribu | medium | TRUE | {"name":"notion_check_cookie_consent","httpOnly":false,"secure":false} |
| www.notion.so | Cookie "notion_check_cookie_consent" is set without the HttpOnly attri | medium | TRUE | {"name":"notion_check_cookie_consent","httpOnly":false,"secure":false} |
| www.paypal.com | Cookie "ts_c" is set without the HttpOnly attribute | medium | TRUE | {"name":"ts_c","httpOnly":false,"secure":true} |
| www.reddit.com | Cookie "edgebucket" is set without the HttpOnly attribute | medium | TRUE | {"name":"edgebucket","httpOnly":false,"secure":true} |
| www.shopify.com | Missing Content-Security-Policy (CSP) | medium | TRUE | no CSP (report-only=false) |
| www.shopify.com | Missing X-Frame-Options / Clickjacking Immunity | medium | TRUE | xfo=null frame-ancestors=false |
| www.theguardian.com | Cookie "gu_client_ab_tests" is set without the Secure attribute over H | medium | TRUE | {"name":"gu_client_ab_tests","httpOnly":false,"secure":false} |
| www.theguardian.com | Cookie "gu_client_ab_tests" is set without the HttpOnly attribute | medium | TRUE | {"name":"gu_client_ab_tests","httpOnly":false,"secure":false} |
| www.theguardian.com | Cookie "gu_v2_mvt_id" is set without the Secure attribute over HTTPS | medium | TRUE | {"name":"gu_v2_mvt_id","httpOnly":false,"secure":false} |
| www.theguardian.com | Cookie "gu_v2_mvt_id" is set without the HttpOnly attribute | medium | TRUE | {"name":"gu_v2_mvt_id","httpOnly":false,"secure":false} |
| www.wikipedia.org | Missing Content-Security-Policy (CSP) | medium | TRUE | no CSP (report-only=false) |
| www.wikipedia.org | Missing X-Frame-Options / Clickjacking Immunity | medium | TRUE | xfo=null frame-ancestors=false |
| www.wikipedia.org | Missing X-Content-Type-Options (MIME Sniffing) | medium | TRUE | x-content-type-options=null |
| zoom.us | Missing Content-Security-Policy (CSP) | medium | TRUE | no CSP (report-only=false) |
| zoom.us | Missing X-Frame-Options / Clickjacking Immunity | medium | TRUE | xfo=null frame-ancestors=false |
| zoom.us | Missing X-Content-Type-Options (MIME Sniffing) | medium | TRUE | x-content-type-options=null |
| zoom.us | Cookie "_zm_mtk_guid" is set without the HttpOnly attribute | medium | NOT-REPRODUCED | cookie not set on re-fetch (may be conditional/A-B) |
| zoom.us | Cookie "_zm_visitor_guid" is set without the HttpOnly attribute | medium | NOT-REPRODUCED | cookie not set on re-fetch (may be conditional/A-B) |
| zoom.us | Cookie "_zm_billing_visitor_guid" is set without the HttpOnly attribut | medium | NOT-REPRODUCED | cookie not set on re-fetch (may be conditional/A-B) |
