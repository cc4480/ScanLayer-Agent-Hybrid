# Running the verbatim scan-core tests

Copied suites under `src/engines/`:

- `vibescan-core/` (VibeScan api-server + db + deploy/cli + the website files its tests read). Vitest.
- `seclayer-core/` (SecLayer server + root files its tests read). node:test via tsx.

## Prerequisites

- Node 22+ and `npm install` in this folder.
- PostgreSQL 17 for the VibeScan database tests. Without it those tests fail with
  `DATABASE_URL must be set`.
- `npx playwright install chromium` for the browser-guard tests.
- Harness packages built (see "Harness build" below) for the gate tests.

## Environment (test-only; never commit values)

    DATABASE_URL=postgres://USER:PASSWORD@localhost:5432/DBNAME   # VibeScan DB tests
    SCAN_DEV_ALLOW_HOSTS=127.0.0.1,localhost                      # lab hosts for loopback probes
    ALLOW_PRIVATE_SCAN_TARGETS=true                               # VibeScan loopback probes only

Apply the VibeScan schema once:

    npx tsx src/engines/vibescan-core/lib/db/src/migrate.ts

## Commands

    # VibeScan core. Runs from the api-server folder (some tests read cwd-relative paths).
    npx vitest run --config vitest.scan-cwd.config.mts

    # SecLayer core. Runs from its mirrored repo root (tests read server.ts, vercel.json, server/pg/schema.sql).
    cd src/engines/seclayer-core
    node --import tsx --test $(find server -name '*.test.ts')

    # Gate and agent-tool tests.
    npx tsx --test test/lab-hosts.test.mjs test/scope.test.mjs test/verifier.test.mjs test/runner.test.mjs \
      test/tools.test.mjs test/recon/domain.test.mjs test/recon/passive.test.mjs \
      test/seclayer/redteam-modules.test.mjs test/metasploit/msf.test.mjs test/alterego/*.test.mjs \
      test/guard/scoped-fetch.test.mjs test/redteam-tools.test.mjs test/render.test.mjs test/scan/scan-tools.test.mjs
    npx tsx --test test/secscan-src/gate.test.mjs test/seclayer-src/gate.test.mjs test/seclayer-network/adapter.test.mjs
    npx vitest run test/secscan-network

## Harness build (needed by the gate tests)

The gate imports `@deepseek-ai/dsh-tools`, which lives in the harness workspace. Build it with
pnpm 11.28.5 from `src/deepseek-harness`:

    pnpm install --filter @deepseek-ai/dsh-tools... --frozen-lockfile
    pnpm exec tsc -b packages/core/tools/tsconfig.json
    # then, per package with lib/types/index.js and no lib/index.js:
    pnpm exec tsdown --no-config lib/types/index.js --format esm --platform node --out-dir lib --no-dts --clean=false
    # rename lib/index.mjs -> lib/index.js where tsdown emitted .mjs

This is a workaround, not the harness's official build. The official pipeline (`scripts/build.ts`)
builds desktop and web targets too.

## Results (last full run)

- VibeScan core: 3425 pass, 2 fail, 293 skipped. The two failures are external (see below).
- SecLayer core: 1013 pass, 0 fail, 6 skipped.
- Gate suite: 226 pass, 0 fail, 2 skipped.
- Ported SecScan/SecLayer gate suites: 25 pass, 0 fail.

## Known external failures

- `monitorPulse.uptime.test.ts` ("refuses to follow a redirect to a private address") and
  `webhook.test.ts` ("bounds the request so a hung endpoint cannot pin the worker"). Both depend on
  httpbin.org behaviour that changed: `/redirect-to` now returns 403 and `/delay/15` returns 400.
  The engine code is not at fault. Replace with local servers to make them deterministic.
