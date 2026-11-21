# SecLayer red-team probe transfer: inventory

Source (read-only): `C:\Users\Cho-zen\OneDrive\Desktop\secscan-redteam-refactor\seclayer.io2026\server`
Copy root: `src/engines/seclayer-network/` (copied files keep their source-relative paths, so no import changed).
Hashes: `MANIFEST.json` (13 entries, all recomputed and matching).

Classes: **PORTABLE** = every HTTP request goes through global fetch (directly, or via `ssrf.ts` `guardedFetch`, which passes an undici dispatcher to fetch). **HOSTED** = needs a Seclayer-side service (OOB collaborator). **TYPE-ONLY** = imported only for types, erased at runtime.

## Probes

| File | Outbound channel | Class | In tree | Notes |
|---|---|---|---|---|
| `server/redTeam/sqlInjection.ts` | `probeFetch` (probeHttp.ts) -> `safeFetch` (ssrf.ts) -> global fetch. 1 request, plus 1 baseline `?id=1` on a match | PORTABLE (see DNS caveat) | yes | Probe code itself has no network call. |
| `server/redTeam/reflectedXss.ts` | `probeFetch` -> `safeFetch` -> global fetch. 1 request | PORTABLE (see DNS caveat) | yes | Imports `../fpFilters.js` (copied, pure). |
| `server/redTeam/commandInjection.ts` | `probeFetch` -> `safeFetch` -> global fetch. 1 request, plus `id` fallback request | PORTABLE (see DNS caveat) | yes | |
| `server/redTeam/ssrf.ts` | `probeFetch` -> `safeFetch` -> global fetch, plus `signaturePreexists` (baseline.ts) on a match | PORTABLE (see DNS caveat) | yes | |
| `server/redTeam/weakSessionToken.ts` | `safeFetch` (direct) -> global fetch: one POST login with **caller-supplied credentials** | PORTABLE (see DNS caveat and decision note) | yes | Not hosted by the brief's rule 5 (no OOB). `ADAPTATIONS.md` in `seclayer-src` lists it as HOSTED because of the login credentials; that is a different call, and it is flagged here for a decision. |
| `server/redTeam/blindSsrf.ts` | `ctx.oob.issue()` / `ctx.oob.poll()` (collaborator) plus `probeFetch` | **HOSTED** | **no** | Needs the out-of-band collaborator (`ctx.oob`, `server/oob.ts`). Not faked. |

## Helpers the probes depend on

| File | Outbound channel | Class | In tree | Notes |
|---|---|---|---|---|
| `server/ssrf.ts` | global fetch via `guardedFetch` (line 285, passes `dispatcher: safeDispatcher`). The dispatcher (line 229) is an undici `Agent` with a custom connect `lookup` (line 266). **Also node:dns**: `dns/promises` and `dns` imported (lines 10-11). `assertTargetIsScannable` calls `resolveHostAddresses` for hostnames (line 321), before the request | PORTABLE with DNS caveat | yes | The brief's rule "an undici dispatcher passed to fetch is fine" covers the Agent. The node:dns calls are the caveat, below. |
| `server/redTeam/probeHttp.ts` | calls `safeFetch` (global fetch) | PORTABLE | yes | |
| `server/redTeam/baseline.ts` | calls `probeFetch` | PORTABLE | yes | |
| `server/evidence.ts` | none (pure builders) | pure | yes | Runtime import of `../src/types.js` appears without `import type`; `src/types.ts` is copied for that reason. |
| `server/fpFilters.ts` | none (pure) | pure | yes | Already in `seclayer-src`; copied again byte-identical. |
| `src/types.ts` | none (types only) | pure | yes | |
| `server/redTeam/types.ts` | none at runtime | TYPE-ONLY | **no** | Imports `../oob.js` and `../scanTypes.js` (HOSTED-coupled, not copied). Erased at runtime. |
| `crawler.ts`, `scanTypes.ts`, `oob.ts` | type imports only (weakSessionToken.ts imports `../crawler.js` as a type) | TYPE-ONLY / HOSTED | **no** | Not present. Runtime unaffected. `tsc` would fail on these (not run). |

## Caveat: DNS before the gate (decision for the user)

The brief's rule 4 excludes a probe that opens DNS. Every ported active probe reaches the network through `ssrf.ts`, and `ssrf.ts` calls `node:dns` in three places:

1. `assertTargetIsScannable` (ssrf.ts line 321) resolves a **hostname** target before `guardedFetch` (line 361). The scope gate runs inside fetch, so this lookup happens before the gate sees the host. A DNS query for a non-verified hostname can leave the machine before it is denied. HTTP is still refused.
2. Each redirect hop to a hostname goes through the same pre-check (`safeFetch` loop, ssrf.ts line 360).
3. The dispatcher's connect `lookup` (line 266) runs only after the gate has allowed the request.

Mitigation in the adapter (not a fix in `ssrf.ts`): `adapter.mjs` calls `assertScope(ctx.url)` **before** any probe code runs, so a non-verified root hostname causes no DNS and no request. Redirect hops to hostnames are not covered by that pre-check.

Loopback IP-literal targets (the only lab case) take no DNS path: `isDevAllowedHost` returns early (ssrf.ts line 297), and the dispatcher's own comment says IP literals never reach its lookup (ssrf.ts, above the `net.isIP` check near line 263). This is by code reading; it was not measured with a DNS tracer.

I did port the five probes (sqlInjection, reflectedXss, commandInjection, ssrf, weakSessionToken), on the reading that the HTTP path is global fetch. Under a strict reading of rule 4, those five are excluded until the DNS pre-check in `ssrf.ts` is gated or removed. That needs a human decision. It cannot be fixed inside the copied tree without an edit that the brief forbids.

## Requirements for running the ported probes

- `SCAN_DEV_ALLOW_HOSTS` must name the exact lab `host:port` (`127.0.0.1:<port>`). Otherwise `ssrf.ts` refuses loopback (`isBlockedIp`). It is hard-off when `NODE_ENV=production` (ssrf.ts line 186).
- A TypeScript loader (tsx) must be present. `package.json` has none, and it was not edited.
- The `undici` package must resolve from the copied tree (`ssrf.ts` line 13). `package.json` does not list it. The test runs used the scratchpad runner (see the report).

## Secret-shaped strings (locations only)

- No real secret was found in any copied file.
- `server/fpFilters.ts` lines 6, 25, 27, 75: documentation example and placeholder strings (`AKIAIOSFODNN7EXAMPLE`, `sk_live_` prefixes) used by the FP filter. Not credentials.
- `server/redTeam/weakSessionToken.test.ts` lines 73, 99, 109, 129, 151: test literals `"whatever"` and `"wrong"` as passwords for a lab server. Not credentials.

## Other facts from the source

- `server/redTeam/weakSessionToken.test.ts` line 84-85 uses `child_process.execSync` to run the reproduction command. This is test-only. The probe itself does not spawn anything.
- `server/redTeam/baseline.ts` lines 10-12: "seven CRITICAL findings at high confidence" on a reference target, a historical count of false positives, not a rate. No false-positive rate is claimed here.
