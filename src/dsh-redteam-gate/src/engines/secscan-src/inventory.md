# SecScan source inventory

Source: `C:\Users\Cho-zen\OneDrive\Desktop\secscan-redteam-refactor\VibeScan-Enterprise-Build\artifacts\api-server\src\lib` (606 files, TypeScript).
Read first: `ENGINEERING.md`, `SCAN_COVERAGE.md`, `SCAN_CHECKS.md` (index), `SCAN_TESTS.md` (headings).

## Method

1. Import scan of every candidate module (value imports only; `import type` is erased at runtime and is listed separately).
2. Network scan of all 606 files for `fetch(`, `scanFetch`, `node:net`, `node:tls`, `node:dns`, `node:http(s)`, WebSocket, `dns.`, `fetchFn`.
3. Value-import closure from the pure-logic seeds. Result: 27 non-test files, 0 network calls, 0 DB, 0 auth, 0 HTTP. The only external runtime import is `node:crypto`.

## Classification: PORTABLE (copied verbatim, 27 files)

Each is pure detection logic over strings, headers, cookies, JWT text, JS text, or a fetched document already in memory. None sends a request.

| File (lib-relative) | Value imports (runtime) | Type-only imports (erased; dangle in copy) | Runtime deps |
|---|---|---|---|
| challengePage.ts | none | none | none |
| cookieClassification.ts | none | none | none |
| cookieFlags.ts | none | none | none |
| headerAnalysis.ts | none | none | none |
| hstsParse.ts | none | none | none |
| isolationHeaders.ts | none | ./scanner | none |
| jwtAnalysis.ts | node:crypto | ./scanner | node:crypto |
| publicKeys.ts | none | none | none |
| scannerCookies.ts | ./cookieClassification.js, ./cookieFlags.js, ./scannerTypes | none | none |
| scannerCspChecks.ts | ./headerAnalysis.js, ./scannerTypes | none | none |
| scannerHeaderChecks.ts | ./headerAnalysis.js, ./isolationHeaders, ./scannerTypes | none | none |
| scannerTypes.ts | node:crypto | ./activeScopeGuard, ./http, ./testLedger, ./scannerCoverage | node:crypto |
| secret-pattern-ai.ts | none | ./secret-pattern-data | none |
| secret-pattern-data.ts | ./secret-pattern-generic, ./secret-pattern-more, ./secret-pattern-vendors | ./scanner | none |
| secret-pattern-filters.ts | ./secretPlaceholders | none | none |
| secret-pattern-generic.ts | ./secret-pattern-filters, ./secretPlaceholders, ./publicKeys, ./secret-pattern-jwt, ./secret-pattern-ai | ./secret-pattern-data | none |
| secret-pattern-jwt.ts | ./publicKeys, ./secret-pattern-vendors | ./secret-pattern-data | none |
| secret-pattern-more.ts | none | ./secret-pattern-data | none |
| secret-pattern-vendors.ts | ./secretPlaceholders | ./secret-pattern-data | none |
| secretPlaceholders.ts | none | none | none |
| sriPolicy.ts | none | none | none |
| structuredData.ts | ./challengePage.ts, ./structuredDataHosts.ts, ./structuredDataMeta.ts, node:crypto | ./scanner.js | node:crypto |
| structuredDataHosts.ts | none | none | none |
| structuredDataMeta.ts | none | none | none |
| subdomain-service-data.ts | none | ./scanner | none |
| techEvidence.ts | none | none | none |
| techFingerprint.ts | ./techEvidence.js | none | none |

Note: `scannerTypes.ts` has a value import of `randomUUID` from `node:crypto`. The `ScanVulnerability` type-only references point to `./scanner`, which is the DB-backed engine (HOSTED) and is not copied.

## Test files (copied, runnable inside the copy)

| File | Imports | Result |
|---|---|---|
| cookieClassification.test.ts | ./cookieClassification.js, vitest | copied |
| cookieFlags.test.ts | ./cookieFlags, vitest | copied |
| headerAnalysis.test.ts | ./headerAnalysis, vitest | copied |
| jwtAnalysis.test.ts | ./jwtAnalysis.js, vitest | copied |
| scannerCspChecks.test.ts | ./headerAnalysis, ./scannerCspChecks, vitest | copied |
| secret-pattern-data.test.ts | ./secret-pattern-data.js, vitest | copied |
| techFingerprint.test.ts | ./techFingerprint.js, vitest | copied |
| techFingerprint.rules.test.ts | ./techFingerprint.js, vitest | copied |
| structuredData.findings.test.ts | ./structuredData.js, ./structuredData.testkit, vitest | copied |
| structuredData.meta.test.ts | ./structuredData.js, ./structuredData.testkit, vitest | copied |
| structuredData.testkit.ts | ./structuredData.js | copied (helper) |

Excluded, not runnable against the copy (they import modules that are not PORTABLE):

| File | Blocking import |
|---|---|
| hstsParse.test.ts | ./dnsChecksMail, ./scannerTransportChecks (network/DNS) |
| isolationHeaders.test.ts | ./compliance (DB-backed compliance mapping) |
| secret-pattern-more.test.ts | ./jsScanner (UNGATED active fetch) |
| secretFalsePositives.test.ts | ./jsScanner (UNGATED) |
| secretPlaceholders.test.ts | ./jsScanner (UNGATED) |
| sriPolicy.test.ts | ./probes (UNGATED active probes) |
| falsePositives.test.ts | ./probes, ./crawler-data, ./routeSite.testkit (UNGATED) |
| techFingerprint.structural.test.ts | firebase/app (external npm package, not installed) |

## Classification: HOSTED or UNGATED (not copied)

Network-touching modules, found by the scan. None takes an injected fetch function, so each is UNGATED for Step 4 unless it is HOSTED by definition.

UNGATED (sends requests to a target, no injection point, not copied). Verified by grep for a real call site, not a comment:

- scanFetch from ./http, hard-wired (no injection): accessControlProbe, apiDocsProbe, apiProbeEndpoint, apiProbeSurface, apiSurface, baasDepth, baasProbesCore, crawlerFetch, graphqlExtra, graphqlProbe, healthEndpointProbe, injectionExtra, injectionProbe, jsScanner, pathTraversal, priceTamperingProbe, probesCore, promptInjectionProbe, raceConditionProbe, reprobe, sourceMaps, spaCatchAll (line 45), manifestSca (line 282), ssrfProbe, storageProbe, subdomainTakeover, supabase-probes-core
- Direct global fetch, no injection: firebase-probes (line 35), reconDns (line 28, 80), tlsCheck and the other network modules listed in the scan
- Raw sockets / DNS, no injection: tlsCheck, tlsCheckCertificate, mailTls, mailTlsProbe, scannerHstsPreload (node:net), scannerStartPage, reconDns (node:dns/promises), reconPorts, recon, vettedProxy, pinnedDispatcher, ssrfGuard (the last three are guard infrastructure)
- Playwright browser, no injection: browserPage, browserGuard, launchChromium (not on the copied path)

Not network modules (matches are comments or type names only): httpBody, httpContext, scannerTypes, aiFeatureProbe (its only match is a doc comment), compliance, activeScopeGuard.

HOSTED (needs a database, auth, billing, email, a secrets store, GitHub App, an LLM, or a SecScan server or external vendor API):

- Database / job queue: scanner.ts (imports @workspace/db, which throws without DATABASE_URL), worker*.ts, monitor*.ts, eolFetcherDb, cveMonitor, reportShare, shares, subscriptions, team, tickets, freeTrial, credits, scanDiffLoader, scanNotes, logger-backed stores
- Auth / sessions / billing: auth.ts, authTokens, oauth*.ts, loginCode, accountShared, billing.ts, stripe.ts, plans.ts, entitlements
- Email: mailer*.ts, signupNetwork, reportEmail, webhook.ts (Slack-compatible outbound)
- LLM: deepseek.ts, deepseekCall.ts, deepseekPrompt*.ts, workerAi.ts, aiAnalysis.ts, aiOptOut, promptOverlap (depends on AI)
- External vendor APIs: cveCheckOsv (OSV.dev), ssllabs (Qualys), dnsChecksCore (Cloudflare DoH, default https://cloudflare-dns.com/dns-query, overridable by env DOH_ENDPOINT_URL), eolFetcher (remote data), hstsPreload API
- GitHub App / repo: github*.ts, repo*.ts, githubSourceProbe
- Secrets at rest: crypto.ts (AES key from ENCRYPTION_KEY), scanCredentials.ts

## Network-scan hits NOT in the copy, as a fact

Of the 606 files, the grep-based network scan flagged 75 non-test modules. Several are comment-only matches (see above). Every file that makes a real call is either UNGATED or HOSTED, and none of them is PORTABLE or in the copy. The PORTABLE files were checked the same way and have no real call sites.

## Runtime environment

- Node v24.22.1 on this machine.
- Environment variables read by the 27 PORTABLE files: none.
- Databases, services, or hosts contacted by the 27 PORTABLE files: none.
- npm packages used by the 27 PORTABLE files: none beyond `node:crypto`.

## Secret-shaped strings found in the copied files (not copied as credentials)

These are documented vendor placeholders or fixtures. None is a live credential.

- `secretPlaceholders.ts` lines 97 and 99: `sk_test_4eC39HqLyjWDarjtT1zdp7dc` (Stripe's published docs example) and `AKIAIOSFODNN7EXAMPLE` (AWS docs example). These are in the false-positive filter list, so they are copied as-is.
- `secret-pattern-data.test.ts` lines 70, 83, 89, 97: a fake JWT and a fake PEM block used as test fixtures. Copied as-is.
- `secret-pattern-vendors.ts` lines 66 and 74: regex patterns for `sk_live_` and `sk_test_`. These are detection patterns, not keys.
