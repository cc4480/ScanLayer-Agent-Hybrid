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
    BILLING_TEST_DATABASE_URL=postgres://USER:PASSWORD@localhost:5432/DBNAME  # enables the real-Postgres suites
    SCAN_DEV_ALLOW_HOSTS=127.0.0.1,localhost                      # lab hosts for loopback probes
    ALLOW_PRIVATE_SCAN_TARGETS=true                               # VibeScan loopback probes only

Use a dedicated, empty test database. The integration suites write rows and expect to own the tables. Recreate it
before a run, then apply the schema:

    npx tsx src/engines/vibescan-core/lib/db/src/migrate.ts

The VibeScan config runs test files one at a time (`fileParallelism: false`), because the integration suites share
one database.

## Commands

    # VibeScan core. Runs from the api-server folder (some tests read cwd-relative paths).
    npx vitest run --config vitest.scan-cwd.config.mts

    # SecLayer core. Runs from its mirrored repo root (tests read server.ts, vercel.json, server/pg/schema.sql).
    cd src/engines/seclayer-core
    node --import tsx --test $(find server -name '*.test.ts')

    # Gate and agent-tool tests (the same list as `npm test`).
    npm test

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
- Gate suite (`npm test`): 213 pass, 0 fail, 2 skipped.

## How the former httpbin tests now run

- `monitorPulse.uptime.test.ts`: redirect behaviour runs against a local HTTP server with the scanner's private-target
  allowance on. The metadata-address refusal runs with the default guard (allowance off), with the public first hop
  stubbed for example.com. The guard itself is real on every hop.
- `webhook.test.ts`: the destination check is the real guard. Delivery uses a stubbed transport for example.com, because
  webhooks may only go to public https hosts, so no local server can receive a real delivery without weakening the guard.

## Finding to decide

With `ALLOW_PRIVATE_SCAN_TARGETS=true` the scan-target guard allows any address, including the cloud metadata address
169.254.169.254, and a public host can redirect there. That is the intended self-host opt-in, but it is worth a decision
before anyone deploys with the flag set.

## Known external failures

None.
