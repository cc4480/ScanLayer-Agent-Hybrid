# ADAPTATIONS

## Edits to copied files

None. All 38 files under `secscan-src/` are byte-identical to their source (see `MANIFEST.json`, 38 of 38 SHA-256 matches). No import path, regex, threshold, or false-positive filter was changed.

## Known dangling references (not edited)

Some copied files have `import type` references to modules that were not copied. Type imports are erased at runtime, so the tests run. A `tsc` typecheck of the copy would report these. They are left in place to keep the copy byte-identical.

- `isolationHeaders.ts`, `jwtAnalysis.ts`, `structuredData.ts`, `subdomain-service-data.ts`, `secret-pattern-data.ts`: `./scanner` (or `./scanner.js`), the DB-backed engine (HOSTED).
- `scannerTypes.ts`: `./activeScopeGuard`, `./http`, `./testLedger`, `./scannerCoverage` (type-only).

## Glue outside the copied tree (new files, not edits)

- `src/engines/secscan-adapters/gate-adapter.mjs`: `gatedFetch({gate, fetchFn, toolName})`. Calls `decideScope({toolName:'nuclei', arguments:{target:url}}, gate)` before the injected fetch. A denial throws `SCOPE_DENIED` before `fetchFn` runs.
- `test/secscan-src/gate.test.mjs`: 6 tests (see report).

## Removed

- `src/engines/secscan/` (`cookies.mjs`, `exposure.mjs`, `headers.mjs`, `index.mjs`, `shared.mjs`): the earlier reimplementation. Nothing outside its own tests imported it.
- `test/secscan/` (`cookies.test.mjs`, `exposure.test.mjs`, `fixtures.mjs`, `headers.test.mjs`): tests for the removed reimplementation only.

## UNGATED modules (not ported; the scope gate has no injection point)

These send requests to a target with no injected fetch, so Step 4 says stop on them. None was copied or edited.

- Request calls through `./http` (`scanFetch`) or direct `fetch` with no injection point (the grep confirmed the call site for most; the rest are flagged by the same pattern): `spaCatchAll.ts`, `manifestSca.ts`, `probesCore.ts`, `probesHttp.ts`, `probesPage.ts`, `probesFiles.ts`, `probesSri.ts`, `probes.ts`, `jsScanner.ts`, `sourceMaps.ts`, `pathTraversal.ts`, `graphqlProbe.ts`, `graphqlExtra.ts`, `apiDocsProbe.ts`, `apiSurface.ts`, `apiProbe*.ts`, `accessControlProbe.ts`, `injectionProbe.ts`, `injectionExtra.ts`, `promptInjectionProbe.ts`, `raceConditionProbe.ts`, `priceTamperingProbe.ts`, `ssrfProbe.ts`, `storageProbe.ts`, `subdomainTakeover.ts`, `healthEndpointProbe.ts`, `reprobe.ts`, `baasDepth.ts`, `baasProbesCore.ts`, `supabase-probes-core.ts`
- Direct `fetch`: `firebase-probes.ts` (line 35), `reconDns.ts` (lines 28, 80)
- Raw sockets / DNS: `tlsCheck.ts`, `tlsCheckCertificate.ts`, `mailTls.ts`, `mailTlsProbe.ts`, `scannerHstsPreload.ts`, `scannerStartPage.ts`, `reconPorts.ts`, `recon.ts`
- Playwright: `browserPage.ts`, `browserGuard.ts`, `launchChromium.ts`

## Not copied because they import an UNGATED or HOSTED module

Tests that need these modules were not copied: `hstsParse.test.ts`, `isolationHeaders.test.ts`, `secret-pattern-more.test.ts`, `secretFalsePositives.test.ts`, `secretPlaceholders.test.ts`, `sriPolicy.test.ts`, `falsePositives.test.ts`, `techFingerprint.structural.test.ts` (needs the external package `firebase/app`, not installed).
