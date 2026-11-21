# secscan-network inventory

Source: `artifacts/api-server/src/lib` in VibeScan-Enterprise-Build (347 non-test .ts files). Docs read: `ENGINEERING.md` (SSRF guard and DNS pinning section) and `SCAN_COVERAGE.md` (Modules 3, 5, 7, 8, 14: the network checks).

## Method

1. Each non-test lib file was parsed for runtime imports (type-only imports are erased and listed apart) and for call sites of `fetch(`, `scanFetch`, `scanFetchOrThrow` and injected `fetchFn`.
2. DIRECT channel: the module's own import specifiers include `node:net`, `node:tls`, `node:dns`, `node:dns/promises`, `node:http`, `node:https`, `node:http2`, `dgram`, `child_process`, `worker_threads`, `undici`, or a Playwright or Puppeteer package. Import specifiers were checked, not text, so a string such as `"dns"` does not count.
3. CLOSURE channel: any module reached through runtime imports (transitively) is DIRECT. Rule 1 copies every relative import at its path, so such a module drags its channel dependency into the copy, and rule 4 excludes it.
4. Test fixtures (`*.testkit.ts`) open `node:http` servers and are excluded as channel modules.

## Why every scanFetch probe is excluded

- `http.ts` makes its requests with global `fetch` and passes `dispatcher: scanDispatcher` (http.ts: `fetch(current, { ... dispatcher: scanDispatcher ... })`). The dispatcher passed to fetch is covered by the guard, because the guard forwards `init`.
- `http.ts` imports `./ssrfGuard`, which is DIRECT (`node:net`, `node:dns/promises`; `dns.lookup` runs before each request), and `./pinnedDispatcher`, which is DIRECT (`node:dns` `lookup`, plus an undici `Agent` whose connect `lookup` is the vetted lookup).
- Rule 4 lists `node:dns` and undici. The dispatcher case is covered, but the `node:dns` lookups inside `pinnedDispatcher.ts` and `ssrfGuard.ts` are direct use, so both files are excluded.
- Result: `http.ts` and every module that imports it (all scanFetch probes) cannot be copied self-resolving without copying a DIRECT module. They are excluded as one block. Porting them needs a replacement for the DNS-pinning layer, which is a rewrite and not a byte-identical port.

## Counts

| Bucket | Files | Notes |
|---|---|---|
| PORTED, network clients | 5 | Global fetch to a configurable endpoint. Table A. |
| PORTED, runtime and type helpers | 7 | cveCheckCore, baasEndpoints, baasExposure, httpBody, httpTypes, httpContext, appOrigin. Needed by the clients; no channel. |
| EXCLUDED, direct channel | 15 | Table B1. |
| EXCLUDED, channel via closure | 94 | 35 of these also make their own fetch or scanFetch calls. Table B2. |
| EXCLUDED, hosted (rule 5, or DB, email, LLM, GitHub) | 13 | Channel-clean, but hosted. Table B3. |
| EXCLUDED, vendor-inert | 1 | ssllabs.ts (no endpoint override). Table B3. |
| EXCLUDED, test fixtures opening node:http | 15 | Table B4. |
| Network-touching modules examined (total) | 143 | Includes the 12 PORTED. |

## Table A: PORTED (byte-identical copies; see MANIFEST.json)

| File | Channel | Endpoint and override | Verified behaviour (guarded-scan.test.mjs) |
|---|---|---|---|
| cveCheckOsv.ts | global fetch, POST | https://api.osv.dev/v1/query. Override OSV_API_URL (read per call). | api.osv.dev refused with zero requests; loopback mirror returns the fixture vulnerability |
| dnsChecksCore.ts | global fetch, GET (DNS-over-HTTPS) | https://cloudflare-dns.com/dns-query. Override DOH_ENDPOINT_URL (read per call). | cloudflare is not verified, so it is refused in production; loopback resolver runs; a dotted query name is refused even on loopback |
| firebase-probes.ts | global fetch (Firestore REST; RTDB root .json) | https://firestore.googleapis.com (FIRESTORE_API_URL); RTDB origin via FIREBASE_DATABASE_ORIGIN_TEMPLATE | non-lab host refused with zero requests; loopback Firestore runs and reports the open sensitive collection as critical |
| baasDepth.ts | global fetch (Supabase Auth and Storage; Firebase Storage) | {ref}.supabase.co via SUPABASE_PROJECT_ORIGIN_TEMPLATE; firebasestorage.googleapis.com via FIREBASE_STORAGE_API_URL | same guard path (scopedFetch). Not exercised through the guard by any test in this port (the Storage branch needs a storageBucket in the page content). |
| supabase-probes-core.ts | global fetch (generic safeFetch) | caller-supplied URL | helper for the Supabase probes; the probes themselves are excluded (they reach scanFetch) |

The BaaS and vendor endpoints are not scan targets. The verified-scope gate refuses them unless the vendor host itself is verified. Whether to verify those hosts is a policy decision for the owner; the guard was not changed. Loopback overrides are the only way these copies run in tests.

## Table B1: EXCLUDED, direct channel

| File | Direct channel | Reason |
|---|---|---|
| cloudflareIps.ts | node:net | opens the channel directly (rule 4) |
| domainVerify.ts | node:dns/promises | opens the channel directly (rule 4) |
| mailTls.ts | node:dns | opens the channel directly (rule 4) |
| mailTlsProbe.ts | node:net, node:tls | opens the channel directly (rule 4) |
| monitorPulseCert.ts | node:tls | opens the channel directly (rule 4) |
| pinnedDispatcher.ts | node:dns, undici | opens the channel directly (rule 4) |
| recon.ts | node:dns/promises | opens the channel directly (rule 4) |
| reconDns.ts | node:dns/promises | opens the channel directly (rule 4) |
| reconPorts.ts | node:net | opens the channel directly (rule 4) |
| scannerHstsPreload.ts | node:net | opens the channel directly (rule 4) |
| signupNetwork.ts | node:net | opens the channel directly (rule 4) |
| ssrfGuard.ts | node:net, node:dns/promises | opens the channel directly (rule 4) |
| tlsCheck.ts | node:net, node:tls | opens the channel directly (rule 4) |
| tlsCheckCertificate.ts | node:tls | opens the channel directly (rule 4) |
| vettedProxy.ts | node:http, node:net | opens the channel directly (rule 4) |

## Table B2: EXCLUDED, channel via closure

Copying one of these needs its direct-channel dependency copied at the same path (rule 1), which rule 4 then excludes. The `via` column names the dependency.

| File | Own call sites | Reaches DIRECT modules |
|---|---|---|
| accessControlProbe.ts | scanFetch x4 | ssrfGuard.ts, pinnedDispatcher.ts |
| actingEndpoints.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts |
| activeProbeGate.ts | none (import-only) | domainVerify.ts, ssrfGuard.ts, pinnedDispatcher.ts |
| apiDocsProbe.ts | scanFetch x1 | ssrfGuard.ts, pinnedDispatcher.ts |
| apiProbe.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts |
| apiProbeEndpoint.ts | scanFetch x6 | ssrfGuard.ts, pinnedDispatcher.ts |
| apiProbeFindings.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts |
| apiProbeHelpers.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts |
| apiProbeSurface.ts | scanFetch x4 | ssrfGuard.ts, pinnedDispatcher.ts |
| autoSecondAccount.ts | scanFetch x5 | ssrfGuard.ts, pinnedDispatcher.ts |
| baasProbes.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts |
| baasProbesCore.ts | scanFetch x1 | ssrfGuard.ts, pinnedDispatcher.ts |
| baasProbesPocketbase.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts |
| browser.ts | none (import-only) | ssrfGuard.ts, vettedProxy.ts, pinnedDispatcher.ts |
| browserGuard.ts | fetch x1 | ssrfGuard.ts |
| browserProxy.ts | none (import-only) | vettedProxy.ts, pinnedDispatcher.ts, ssrfGuard.ts |
| clientIp.ts | none (import-only) | cloudflareIps.ts |
| configSecrets.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts |
| crashHandlers.ts | fetch x1 | ssrfGuard.ts |
| crawler-data.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts |
| crawler.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts |
| crawlerCookies.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts |
| crawlerFetch.ts | scanFetch x2 | ssrfGuard.ts, pinnedDispatcher.ts |
| crawlerHeaders.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts |
| crawlerProbes.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts |
| crossAccountStep.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts |
| domainReverify.ts | none (import-only) | domainVerify.ts, ssrfGuard.ts, pinnedDispatcher.ts |
| evidencePack.ts | none (import-only) | domainVerify.ts, ssrfGuard.ts, pinnedDispatcher.ts |
| fairUse.ts | none (import-only) | cloudflareIps.ts |
| githubRepoInput.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts |
| githubSourceProbe.ts | fetch x1 | ssrfGuard.ts, pinnedDispatcher.ts |
| graphqlExtra.ts | scanFetch x2 | ssrfGuard.ts, pinnedDispatcher.ts |
| graphqlProbe.ts | scanFetch x1 | ssrfGuard.ts, pinnedDispatcher.ts |
| healthEndpointProbe.ts | scanFetch x1 | ssrfGuard.ts, pinnedDispatcher.ts |
| http.ts | fetch x1, scanFetch x2 | ssrfGuard.ts, pinnedDispatcher.ts |
| injectionExtra.ts | scanFetch x1 | ssrfGuard.ts, pinnedDispatcher.ts |
| injectionProbe.ts | scanFetch x1 | ssrfGuard.ts, pinnedDispatcher.ts |
| jsScanner.ts | scanFetch x1 | ssrfGuard.ts, pinnedDispatcher.ts |
| mailerDrift.ts | fetch x2 | ssrfGuard.ts, pinnedDispatcher.ts |
| mailerMarketing.ts | fetch x3 | cloudflareIps.ts |
| manifestSca.ts | scanFetch x1 | ssrfGuard.ts, pinnedDispatcher.ts |
| monitorPulse.ts | fetch x1 | ssrfGuard.ts, pinnedDispatcher.ts, monitorPulseCert.ts |
| monitorScheduler.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts, monitorPulseCert.ts |
| monitorSchedulerCert.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts, monitorPulseCert.ts |
| monitorSchedulerCve.ts | fetch x1 | ssrfGuard.ts, pinnedDispatcher.ts |
| monitorSchedulerPulse.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts, monitorPulseCert.ts |
| monitorSchedulerSweep.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts |
| pathTraversal.ts | scanFetch x1 | ssrfGuard.ts, pinnedDispatcher.ts |
| priceTamperingProbe.ts | scanFetch x1 | ssrfGuard.ts, pinnedDispatcher.ts |
| probes-data-server.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts |
| probes-data.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts |
| probes.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts, scannerHstsPreload.ts |
| probesCore.ts | scanFetch x1 | ssrfGuard.ts, pinnedDispatcher.ts |
| probesFiles.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts |
| probesHttp.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts |
| probesPage.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts, scannerHstsPreload.ts |
| probesSri.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts |
| probesSupabase.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts |
| promptInjectionProbe.ts | scanFetch x1 | ssrfGuard.ts, pinnedDispatcher.ts |
| raceConditionProbe.ts | scanFetch x1 | ssrfGuard.ts, pinnedDispatcher.ts |
| rateLimit.ts | none (import-only) | cloudflareIps.ts |
| repoCheckDeps.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts |
| repoOnlyScan.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts |
| reportBadge.ts | none (import-only) | domainVerify.ts, ssrfGuard.ts, pinnedDispatcher.ts |
| repoScan.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts |
| repoSource.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts |
| reprobe.ts | fetch x1, scanFetch x2 | ssrfGuard.ts, pinnedDispatcher.ts |
| scanCredentials.ts | none (import-only) | ssrfGuard.ts, vettedProxy.ts, pinnedDispatcher.ts |
| scanner.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts, scannerHstsPreload.ts, vettedProxy.ts |
| scannerActiveStage.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts |
| scannerCoverage.ts | none (import-only) | scannerHstsPreload.ts |
| scannerProbeStage.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts, scannerHstsPreload.ts |
| scannerSettle.ts | none (import-only) | scannerHstsPreload.ts |
| scannerStartPage.ts | scanFetch x1 | ssrfGuard.ts, pinnedDispatcher.ts, vettedProxy.ts |
| scannerTransportChecks.ts | none (import-only) | scannerHstsPreload.ts |
| sourceMaps.ts | scanFetch x1 | ssrfGuard.ts, pinnedDispatcher.ts |
| spaCatchAll.ts | scanFetch x1 | ssrfGuard.ts, pinnedDispatcher.ts |
| ssrfProbe.ts | scanFetch x4 | ssrfGuard.ts, pinnedDispatcher.ts |
| storageProbe.ts | scanFetch x1 | ssrfGuard.ts, pinnedDispatcher.ts |
| subdomainTakeover.ts | fetch x1, scanFetch x1 | ssrfGuard.ts, pinnedDispatcher.ts |
| teamMonitors.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts, monitorPulseCert.ts |
| trustPage.ts | none (import-only) | domainVerify.ts, ssrfGuard.ts, pinnedDispatcher.ts |
| trustPageView.ts | none (import-only) | domainVerify.ts, ssrfGuard.ts, pinnedDispatcher.ts |
| webhook.ts | fetch x1 | ssrfGuard.ts, pinnedDispatcher.ts |
| workerAi.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts, scannerHstsPreload.ts, vettedProxy.ts |
| workerCredentials.ts | none (import-only) | ssrfGuard.ts, vettedProxy.ts, pinnedDispatcher.ts |
| workerFilters.ts | none (import-only) | ssrfGuard.ts, vettedProxy.ts, pinnedDispatcher.ts |
| workerJob.ts | none (import-only) | ssrfGuard.ts, vettedProxy.ts, pinnedDispatcher.ts, scannerHstsPreload.ts, monitorPulseCert.ts, recon.ts, reconPorts.ts, cloudflareIps.ts, reconDns.ts, domainVerify.ts, tlsCheck.ts, tlsCheckCertificate.ts |
| workerMonitor.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts, monitorPulseCert.ts, scannerHstsPreload.ts, vettedProxy.ts |
| workerPersist.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts, monitorPulseCert.ts, scannerHstsPreload.ts, vettedProxy.ts |
| workerQueue.ts | none (import-only) | ssrfGuard.ts, vettedProxy.ts, pinnedDispatcher.ts, scannerHstsPreload.ts, monitorPulseCert.ts, recon.ts, reconPorts.ts, cloudflareIps.ts, reconDns.ts, domainVerify.ts, tlsCheck.ts, tlsCheckCertificate.ts |
| workerRepoJob.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts, scannerHstsPreload.ts, vettedProxy.ts, monitorPulseCert.ts |
| workerReport.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts, scannerHstsPreload.ts, vettedProxy.ts, monitorPulseCert.ts |
| workerSideChecks.ts | none (import-only) | ssrfGuard.ts, pinnedDispatcher.ts, scannerHstsPreload.ts, vettedProxy.ts |

## Table B3: EXCLUDED, hosted or vendor-inert (channel-clean)

| File | Own call sites | Reason |
|---|---|---|
| cveMonitor.ts | fetch x1 | NVD CVE matching against monitor subscriptions, with CVE alert email (header lines 1-3; ENGINEERING.md: CVE-triggered alerts via email). Hosted (rule 5). |
| deepseekCall.ts | fetch x1 | LLM API call to api.deepseek.com (line 1 header; rule 5). |
| eolFetcher.ts | fetch x1 | Imports @workspace/db and drizzle-orm (database, rule 5); fetches endoflife.date data. |
| githubApp.ts | injected fetchFn x1 | GitHub App integration, hosted (earlier inventory: github*.ts HOSTED). |
| githubConnect.ts | injected fetchFn x4 | GitHub App connect flow, hosted. Takes an injected fetchFn, but the service is hosted. |
| githubInstallationAccess.ts | injected fetchFn x2 | GitHub App installation access, hosted. |
| githubIssues.ts | fetch x1 | Imports @workspace/db and drizzle-orm; files GitHub issues, hosted. |
| mailerAccount.ts | fetch x1 | Account email (sign-in code, reset, receipt) via Resend. Email delivery is hosted (rule 5; ENGINEERING.md RESEND_API_KEY). |
| mailerAccountAccess.ts | fetch x2 | Account email via Resend, hosted (rule 5). |
| mailerCve.ts | fetch x2 | Monitor alert email (new CVEs) via Resend, hosted (rule 5). |
| mailerHealth.ts | fetch x2 | Monitor alert email (certificate expiry, availability) via Resend, hosted (rule 5). |
| mailerReport.ts | fetch x1 | Report-ready email via Resend, hosted (rule 5). |
| ssllabs.ts | fetch x1 | VENDOR-INERT. Global fetch to api.ssllabs.com; SSL_LABS_BASE is hard-coded (line 20) with no override, so the gate refuses it and it cannot run. Header: Qualys permission required for commercial use. |
| tickets.ts | fetch x1 | Imports @workspace/db and drizzle-orm (ticket store), hosted (rule 5). |

## Table B4: EXCLUDED, test fixtures

| File | Reason |
|---|---|
| accessControlProbe.testkit.ts | node:http or node:net fixture server (rule 4). The source tests that need it cannot be copied. |
| apiProbe.testkit.ts | node:http or node:net fixture server (rule 4). The source tests that need it cannot be copied. |
| autoSecondAccount.testkit.ts | node:http or node:net fixture server (rule 4). The source tests that need it cannot be copied. |
| baasStub.testkit.ts | node:http or node:net fixture server (rule 4). The source tests that need it cannot be copied. |
| dohStub.testkit.ts | node:http or node:net fixture server (rule 4). The source tests that need it cannot be copied. |
| githubStub.testkit.ts | node:http or node:net fixture server (rule 4). The source tests that need it cannot be copied. |
| hstsPreloadStub.testkit.ts | node:http or node:net fixture server (rule 4). The source tests that need it cannot be copied. |
| http.testkit.ts | node:http or node:net fixture server (rule 4). The source tests that need it cannot be copied. |
| mailSink.testkit.ts | node:http or node:net fixture server (rule 4). The source tests that need it cannot be copied. |
| osvStub.testkit.ts | node:http or node:net fixture server (rule 4). The source tests that need it cannot be copied. |
| realDb.testkit.ts | node:http or node:net fixture server (rule 4). The source tests that need it cannot be copied. |
| routeSite.testkit.ts | node:http or node:net fixture server (rule 4). The source tests that need it cannot be copied. |
| testkit.ts | node:http or node:net fixture server (rule 4). The source tests that need it cannot be copied. |
| ticketStub.testkit.ts | node:http or node:net fixture server (rule 4). The source tests that need it cannot be copied. |
| zipReader.testkit.ts | node:http or node:net fixture server (rule 4). The source tests that need it cannot be copied. |

## Behaviour notes for callers (verified by test)

- Every copied module catches its own network errors and returns an empty or null result. A scope refusal is therefore silent. Example: a Firebase probe pointed at a non-lab host sends nothing and still returns the info finding "Firebase Backend Detected — Firestore Rules Appear Restrictive" (guarded-scan.test.mjs, refused-target case). The adapter returns `refusedHosts` and `complete` so callers can tell a refused run from a clean one.
- decideScope reads every dotted name in a URL as a target, including query-string values (scope.mjs `DOMAIN_RE`, `extractHosts`). A DNS-over-HTTPS query for a dotted name is therefore refused even when the resolver is loopback. The gate was not changed.
- OSV results are cached per process (cveCheckOsv.ts `osvCache`). A cache hit makes no request and is not checked by the gate. The cache is keyed by package, version and ecosystem only.

## Type-only imports

The copies keep `import type { ScanVulnerability } from "./scanner"` unchanged. `./scanner` is the DB-backed engine (HOSTED, not copied). TypeScript and esbuild erase the import at runtime, so the copies run. Type-checking the copies alone reports the missing module, as the earlier secscan-src copies do.

## Runtime environment

- Node v24.22.1. Vitest 4.1.12, run from the scratchpad runner outside the repo (source package.json range `^4.1.12`).
- Environment variables read by the PORTED copies: OSV_API_URL, OSV_CACHE_MAX_SIZE, DOH_ENDPOINT_URL, SUPABASE_PROJECT_ORIGIN_TEMPLATE, FIREBASE_DATABASE_ORIGIN_TEMPLATE, FIRESTORE_API_URL, FIREBASE_STORAGE_API_URL, APP_ORIGIN, SCANNER_USER_AGENT (appOrigin.ts).


## Recount after the pinning rewrite (Phase B)

The conclusion above, that every scanFetch probe is excluded, applied before `ssrfGuard.ts` and `pinnedDispatcher.ts` were rewritten (see `rewrite-spec.md`). Those two files are now rewritten and are the only non-identical files in this folder (MANIFEST.json, "non_identical_files").

- Scan-request modules found: 62 (any non-test file that calls `fetch`, `scanFetch`, `scanFetchOrThrow`, or imports `./http`). Three more modules inject `fetchFn` and are GitHub-hosted: `githubApp.ts`, `githubConnect.ts`, `githubInstallationAccess.ts`. `vettedProxy.ts` opens `node:http` directly and is excluded by channel.
- PORTABLE: 30. Their runtime closure has no direct channel, no hosted module and no testkit. 25 are new copies and 5 were already present (`baasDepth.ts`, `cveCheckOsv.ts`, `dnsChecksCore.ts`, `firebase-probes.ts`, `supabase-probes-core.ts`). `http.ts` is one of the 25. The closure adds 40 helpers, and 56 files are new in total (MANIFEST.json, "copies").
- EXCLUDED by channel: 9 (`browser.ts`, `browserGuard.ts` (its only fetch is Playwright route.fetch), `cloudflareIps.ts`, `domainVerify.ts`, `monitorPulse.ts`, `reconDns.ts`, `scannerHstsPreload.ts`, `scannerStartPage.ts`, and `autoSecondAccount.testkit.ts`, a node:http fixture) plus 2 that are also hosted (`scanner.ts`, `workerFilters.ts`).
- EXCLUDED by hosted (DB, mailer, GitHub, LLM, monitor): 18. These are the seven `mailer*.ts` modules, `eolFetcher.ts`, `githubIssues.ts`, `githubSourceProbe.ts`, `manifestSca.ts`, `monitorSchedulerCve.ts`, `ssrfProbe.ts`, `tickets.ts`, `webhook.ts`, `cveMonitor.ts`, `deepseekCall.ts`, and `crashHandlers.ts` (telemetry).
- EXCLUDED by policy: `ssllabs.ts` (vendor-inert, as in the table above).
- Not scan requests: `aiFeatureProbe.ts` (fetch appears only in a comment; copied as a helper) and `browserPage.ts`.
- Type-only edges to `scanner.ts` and `testLedger.ts` (32) are erased at runtime and not copied.
- Tests run against the copies: 15 source test files, 502 tests. Same counts on the unmodified source.
