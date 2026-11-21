# SecLayer transfer inventory

Source (read-only): `C:\Users\Cho-zen\OneDrive\Desktop\secscan-redteam-refactor\seclayer.io2026`
Copy root: this folder. Copied files keep their source-relative paths (`server/...`, `src/types.ts`) so no import has to change.

Classes: **PORTABLE** = pure detection logic, copied verbatim. **HOSTED** = needs DB, auth, billing, the Seclayer server, LLM API, OOB collaborator, email, or similar. **UNGATED** = sends requests (or spawns tools) with no injection point, so it cannot be scope-gated without editing its logic. Per the brief, UNGATED modules are not copied.

## Copied (PORTABLE, byte-identical; see MANIFEST.json)

| File | Imports | Runtime deps | Stated purpose (doc comment) |
|---|---|---|---|
| server/fpFilters.ts | none | none | False-positive filters: placeholder-secret detection, reflected-XSS execution gate (non-HTML content types, neutralizing contexts) |
| server/evidence.ts | `../src/types.js` (type-only) | none | Evidence receipt builders (buildProbeEvidence, buildOobEvidence, buildObservationEvidence, windowAround, renderRawRequest) |
| src/types.ts | none | none | Shared type contracts (ExploitEvidence, OobEvent, Severity, NmapScriptOutcome, ...) |
| server/nmap/classify.ts | `../../src/types.js` (type-only) | none | Classifies NSE `--script vuln` output into finding / negative / error / inconclusive / informational |
| server/nmap/ports.ts | none | none | Port scope data for standard nmap scans |
| server/nmap/args.ts | `node:net`, `./ports.js` | node built-ins | Builds nmap argv array (array-only, no shell string) |
| server/fpFilters.test.ts | `./fpFilters.js` | node:test | Tests for fpFilters |
| server/evidence.test.ts | `./evidence.js` | node:test | Tests for evidence builders |
| server/nmap/classify.test.ts | `./classify.js` | node:test | Tests for classify |
| server/nmap/args.test.ts | `./args.js`, `./ports.js` | node:test | Tests for args |

Test-time runner: the source uses `node --import tsx --test` (source `package.json`). The copied tree has no `package.json`, so tsx 4.19.2 was installed in the scratchpad and loaded with `node --import <tsx loader>`. No file was edited to make this work.

## PORTABLE, not copied (deferred)

| File | Imports | Why not copied now |
|---|---|---|
| server/nmap/parseXml.ts | `fast-xml-parser` (npm), `../nmapTypes.js` | npm dependency is not in the destination `package.json` (not editable here); needs nmapTypes.ts |
| server/nmap/compile.ts | `../nmapTypes.js`, `./classify.js`, `../../src/types.js` | Depends on nmapTypes.ts and the parseXml chain; deferred with it |
| server/nmapTypes.ts | not inspected in full | Type file for the two above |

## HOSTED (not copied)

| File | Dependency that makes it HOSTED |
|---|---|
| server/redTeam/blindSsrf.ts | **Blind SSRF needs the out-of-band collaborator.** Calls `ctx.oob.issue()` / `ctx.oob.poll()`; callbacks are recorded at `/api/oob/<token>` on the Seclayer public server. Classified HOSTED and not faked. It also sends requests via probeHttp (UNGATED). |
| server/oob.ts | Collaborator: needs a token store (`registerOobToken`, `getOobEvents`) backed by the Seclayer SQLite/Postgres DB, plus a public callback endpoint. |
| server/redTeam/weakSessionToken.ts | Needs caller-supplied `LoginCredentials` and crawler `InjectableTarget` from the scanner. Also calls `safeFetch` directly with no injection point (UNGATED). |
| server/redTeamProbes.ts | Orchestrator: wires blindSsrf (OOB), emits UI events via `scanEvents.js` (EmitFn to the Seclayer web UI), and reads `probeDescriptors.js`. |
| server/redTeam/types.ts | Type contract. `ProbeContext.oob` references OobCollaborator; `RedTeamFinding` comes from scanTypes.ts (large, HOSTED-coupled). Needed only by the UNGATED probes. |

## UNGATED (not copied; process stopped on these)

Each of these sends requests or spawns tools with no injection point. Their logic is not edited, per the brief.

| File | How it sends traffic |
|---|---|
| server/ssrf.ts | `guardedFetch` calls global `fetch` with an undici dispatcher; `safeFetch` follows redirects; DNS lookups via `dns` / `dns/promises`. Its pure helpers (isBlockedIp, expandIpv6) are useful, but the module owns the network path. |
| server/redTeam/probeHttp.ts | `probeFetch` calls `safeFetch` (global fetch). |
| server/redTeam/baseline.ts | `signaturePreexists` calls `probeFetch`. |
| server/redTeam/sqlInjection.ts | `probeFetch` to `?id=...` and baseline `?id=1`. |
| server/redTeam/reflectedXss.ts | `probeFetch` to `?q=...`. Imports the **copied** `fpFilters.ts` gate (xssReflectionExecutes), which is the FP-critical part. |
| server/redTeam/commandInjection.ts | `probeFetch` to `?ping=...` (oracle and `id` fallback). |
| server/redTeam/ssrf.ts | `probeFetch` to `?url=http://127.0.0.1:22`. |
| server/nmap/run.ts | `spawn('nmap', ...)` against the target. |
| server/nmap/detect.ts | `execFile` (nmap privilege check). |
| server/nmap/resolve.ts | DNS resolution (`net`, `resolveHostAddresses`) plus `ssrf.ts` guards. |

## Env vars, secrets, hosts

- Env vars read by the copied files: none. (`SCAN_DEV_ALLOW_HOSTS` and `NODE_ENV` are read by UNGATED `server/ssrf.ts`, which is not copied.)
- Network hosts contacted by copied files: none.
- Secret-like strings in copied files: the only matches are documented example or placeholder strings in fpFilters.ts and fpFilters.test.ts (`AKIAIOSFODNN7EXAMPLE`, the `sk_live_...` placeholder test strings). They are the FP filter's own test inputs, not credentials. No real secret was found in any copied file.

## Source's own documented FP evidence (cited, not a rate)

- test-targets/SECLAYER-DETECTION-BATTERY-2026-09-28.md section 2 (about line 56): `validate-no-fp.mjs` against the hardened reference target gives zero findings. About line 200: zero false positives on the tier's hardened counterparts.
- docs/READINESS-2026-09-30.md line 36: 38-site passive sweep, one false positive found and fixed (commit 83ec4da), per docs/scan-results/2026-09-30/VERIFICATION.md.
- No false-positive rate is documented in the source, and none is claimed here.
