# Running the verbatim scan-core tests

Two copied suites live under `src/engines/`:

- `vibescan-core/` (VibeScan api-server + db + deploy/cli). Vitest.
- `seclayer-core/` (SecLayer server + types). node:test via tsx.

## Prerequisites

- Node 22+ and `npm install` in this folder.
- PostgreSQL 17 for the VibeScan database tests (optional; without it those tests fail with
  `DATABASE_URL must be set`).
- `npx playwright install chromium` for the browser-guard tests.

## Environment

Set these in your shell. Do not commit values.

    DATABASE_URL=postgres://USER:PASSWORD@localhost:5432/DBNAME   # VibeScan tests only
    SCAN_DEV_ALLOW_HOSTS=localhost,127.0.0.1                      # lab hosts for loopback probes

Apply the VibeScan schema once:

    npx tsx src/engines/vibescan-core/lib/db/src/migrate.ts

## Commands

    npx vitest run --config vitest.scan-cwd.config.mts    # VibeScan core, cwd = api-server
    node --import tsx --test $(find src/engines/seclayer-core/server -name '*.test.ts')

`vitest.scan-cwd.config.mts` runs from the api-server folder, because some copied tests read
files by a cwd-relative path (`src/lib/...`).

## Known failures (as of commit after 0ac5d1fc)

VibeScan core: 3410 pass, 5 fail, 293 skipped.
- `pageMeta.test.ts` (3) and the `checkCatalog` / `serverCard` loads read files from the
  VibeScan website (`artifacts/vibescan`), which is not vendored.
- `monitorPulse.uptime.test.ts` (1) and `webhook.test.ts` (1) need outbound internet to httpbin.org.

SecLayer core: 1000 pass, 9 fail, 6 skip (no test-only env vars).
- Missing non-TypeScript files outside the vendored set: `server/pg/schema.sql`, `vercel.json`,
  the sitemap source.
- `DISABLE_RATE_LIMITS` tests, `sendEmail` text-part test, `appVersion` SHA test.
