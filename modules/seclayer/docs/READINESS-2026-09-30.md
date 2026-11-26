# Readiness check — 2026-09-30

State of seclayer.app on 2026-09-30, checked against production, the source and
the scanner harnesses. Nothing here was changed in production except the code
deploys listed at the end.

## Production (Railway, project `seclayer-app`)

- Live at https://seclayer.app: `/`, `/docs`, `/privacy`, `/terms`, `robots.txt`, `sitemap.xml`, `llms.txt`, `/.well-known/security.txt` all 200. Every sitemap URL resolves.
- Health is `{"status":"Online","version":"public beta"}`. A wrong `X-Health-Detail` value returns the same public body; operator fields stay off because `HEALTH_DETAIL_TOKEN` is unset.
- Auth-gated APIs (`/api/auth/me`, `/api/scans`, `/api/nmap/scans`, `/api/keys`) return 401 unauthenticated. Junk email to the sign-in endpoint returns 400.
- **Origin lock works.** A direct request to the Railway domain returns 403; traffic through Cloudflare returns 200.
- Security headers present: CSP, HSTS (preload), X-Frame-Options DENY, nosniff, Referrer-Policy.
- Variables set: `APP_URL`, `DATABASE_URL`, `RESEND_API_KEY`, `ENCRYPTION_KEY`, `DEEPSEEK_API_KEY`, `ORIGIN_AUTH_SECRET`, `EMAIL_FROM`, Google sign-in, Resend webhook secret, browser rendering and screenshots on, `MAX_CONCURRENT_SCANS`.
- **Not set, by design or pending:** Stripe keys (`FREE_MODE=true`, payments off until QA), `HEALTH_DETAIL_TOKEN`.
- Sign-in email DNS: SPF (Cloudflare + SES), DKIM (`resend._domainkey`), DMARC `p=quarantine; pct=25`, `send.` MX to SES.
- nmap 7.93 present; runs unprivileged (TCP connect scan) because Railway strips `CAP_NET_RAW`.
- **Healthcheck is configured:** path `/api/system/health`, timeout 100 s, restart policy ON_FAILURE, read back through the Railway API. The app's origin lock explicitly exempts that path (`server/originLock.ts`), and there is no HTTPS-redirect or Host check that could fail the internal HTTP probe.
- Uptime is watched externally (UptimeRobot). GitHub Actions is billing-blocked on the owning account, so CI does not run; Railway still deploys every push.

## Database

- Postgres on Railway with pgBackRest: full backup 2026-09-28 08:29 UTC and continuous WAL archiving, 0 failures at check time. `~/seclayer-backup.ps1` is an additional manual `pg_dump` (opens a temporary TCP proxy), restore-tested 2026-09-28.
- Database connection timeouts (monitor tick and nmap sweeper) were logged around 07:43 UTC. Postgres logged no restart or error in that window, and the app log buffer had rolled over by the time it was examined. Treated as transient; cause not established.

## Code

- `tsc --noEmit` clean. Unit suite: 939 tests, 935 pass, 4 skipped, 0 fail (one earlier run showed a single flaky failure that did not repeat).
- `npm audit --omit=dev`: 0 vulnerabilities after bumping `fast-uri` and `ip-address` (lockfile only; both arrived through the MCP SDK).

## Scanner

- `scripts/detection-check.ts`: PASS, every planted flaw found.
- `validate-no-fp.mjs` against the hardened fixture: zero false positives, active tier confirmed to have run.
- `validate-probes.mjs`: 16/19 locally; the three misses are the out-of-band callback probes (blind SSRF, XXE, LLM tool use). **CI on Linux, Node 22, same code, earlier the same day: 19/19, including all three.** Local Node is v24.4.1 (production and CI use 22) and no `/api/oob/` callback ever reached the local server, so this is treated as a local-environment issue, not a product defect. Not proven: the native sqlite module here is built for Node 24 and could not be run under Node 22 without rebuilding it. Port 3000 on this machine is also occupied by an unrelated Docker container, so the harness was run on other ports.
- 38-site passive sweep and independent verification: see [`scan-results/2026-09-30/VERIFICATION.md`](scan-results/2026-09-30/VERIFICATION.md). One false positive found and fixed (commit `83ec4da`).

## Known defects and open items

1. **A scan blocked by bot protection has no grade.** The numeric score is still near 100 (only info notices survive), but the product grades it N/A (`server/scoring.ts`; the gauge and PDF show an incomplete state). The report now states exactly why the scan was judged blocked: HTTP status, the rule that fired and the value it fired on. The corpus renderer (`scripts/render-scan-report.mjs`) prints a letter from the raw score, so its blocked rows read A; treat them as not graded.
2. **Cookie findings are not stable run to run** (geo, A/B and consent cookies come and go), so grades on cookie-heavy sites move by 15–20 points between runs with no change to the site. Most cookie findings concern analytics or visitor-ID cookies.
3. `HEALTH_DETAIL_TOKEN` unset.
4. Stripe not configured (intentional until QA).
5. GitHub billing block: CI and the external uptime workflow cannot run.
6. Scans run inside the web process (single instance, roughly 10–30 concurrent scans); the Redis queue in `SCALING.md` is not wired.
