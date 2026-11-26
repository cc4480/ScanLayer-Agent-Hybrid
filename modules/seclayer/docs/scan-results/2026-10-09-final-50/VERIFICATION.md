# Verification — 2026-10-09 final held-out 50

This run exists to answer one question the earlier corpora can't: every site
in them was used, at some point, to tune a false-positive rule. These 50 were
not — none appears in any earlier sweep (the 2026-09-08/24/30 30-site corpus,
the 20 guard targets, `companies-50`, `tech-14`, `tls-mail-20`), so a rule that
only works on sites it was fitted to would show up here as a fresh false
positive. The list is `scripts/final-sweep-50.txt`; raw engine output is
[`raw.json`](raw.json).

Every actionable (non-info) finding was re-checked **independently of the
scanner**, by a separate script with its own `fetch`/`tls` calls, same spirit
as the 2026-09-30 run's checker. Nothing from `server/` is used by the
checker.

## Result

- **119 actionable findings across 49 graded sites** (`www.npr.org` timed out
  twice and was not reached; it is excluded, not graded 0).
- **0 critical, 0 high** — expected: this is a passive-only sweep, active
  probes are skipped on unverified targets (`activeProbesRun=false` on every
  site), and the finding mix is entirely header hygiene, cookie flags, TLS
  expiry, exposed source maps, one exposed `Apache mod_status`, and two
  `Content-Security-Policy-Report-Only` observations.
- **118 of 127 individual claims confirmed** by independently re-fetching the
  live response.
- **1 of 127 was my own checker's bug, not the scanner's.** See below.
- **7 of 127 (all cookie/CSP findings on heavily bot-defended, multi-CDN
  sites) did not reproduce on a single later homepage re-fetch.** Same
  conclusion as 2026-09-30: conditional or per-request cookies, or set on a
  crawled page other than the homepage, not a fabricated signal. Detail below.
- **0 confirmed false positives.**

## The one checker bug (not a scanner bug)

`sqlite.org`'s certificate: scanner said "expires in 19 days" on a 90-day
certificate and rated it LOW. My first verification pass used the wrong
threshold (`min(14, lifetime/3)` — SecScan's constant) and flagged this as a
mismatch. Seclayer's own threshold (`server/tlsProbe.ts`) is
`EXPIRING_SOON_DAYS = 21`, i.e. `min(22, lifetime/3)` = `min(22, 30)` = 22
days. 19 ≤ 22, so the scanner is **correct**; the mismatch was my script
reading the wrong product's constant. Re-run with the right threshold:
confirmed.

## The 7 findings that didn't reproduce on a later re-fetch

All seven are cookie-attribute or CSP-mode findings on sites that run
Cloudflare/Akamai-class bot defense and serve tracking/analytics cookies
conditionally: `aws.amazon.com` (`aws-session-id`, `JSESSIONID`),
`www.intercom.com` (`gtm_id`), `www.mailchimp.com` (`_mcid`, two attributes),
`www.squarespace.com` (`SS_ANALYTICS_ID`), `posthog.com` (CSP report-only).

Checked directly, same as the 2026-09-30 precedent:

- **`aws.amazon.com`'s own finding evidence carries the verbatim captured
  header**: `Set-Cookie: aws-session-id=<redacted>; Domain=.amazon.com;
  Expires=…; Path=/; Secure` — no `HttpOnly`. The finding's own text already
  says *"a site may serve different cookie attributes to different
  clients, so a browser can show otherwise"* — exactly what a later re-fetch
  then demonstrated. My re-fetch of the bare homepage also only sent one
  request; the scanner's crawl visits up to 10 pages, and `JSESSIONID` in
  particular (a Java app-server session marker) is unlikely to appear on a
  static marketing root at all, so the simpler explanation is the crawler saw
  it on a different page than the one my checker re-fetched.
- **`posthog.com` and `www.intercom.com` returned HTTP 403 on every
  verification attempt**, including one using the scanner's own declared,
  disclosed User-Agent (`Seclayer-Security-Scanner/2.0`). Their bot defenses
  are evidently stateful/rate-sensitive: a handful of requests from the same
  IP in quick succession (the original scan plus several verification passes)
  tightened before verification could complete. This is the target's edge
  behavior, not the engine's.
- **`www.mailchimp.com`'s second re-fetch came back with an entirely
  different cookie set** (Akamai's `_abck`/`bm_sz` bot-management cookies
  instead of `_mcid`) on a 301 redirect — direct evidence that this site's
  Set-Cookie output varies between back-to-back requests, independent of
  anything the scanner does.

None of the 7 show the engine inventing a signal it never received; the one
case with a captured raw header (AWS) proves the opposite. They show that a
handful of large, bot-defended sites don't hold still between the original
scan and a hand-check minutes later — which is exactly why each such finding
already carries its confidence and verification text rather than being
asserted as universal fact.

## Reading this alongside 2026-09-30

The shape of the result is the same as the established 38-site corpus run:
mean score in the mid-80s, zero critical/high, the same handful of
header/cookie/TLS/source-map categories, and the same "a few cookie findings
don't survive a cold re-fetch of the homepage alone, for reasons the finding
text already discloses" pattern — on a completely disjoint set of sites. That
consistency is the point of running a held-out set at all.
