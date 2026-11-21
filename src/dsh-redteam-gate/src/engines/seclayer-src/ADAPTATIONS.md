# Adaptations

## Copied files: none

All 10 copied files (9 code and test files, plus `src/types.ts`) are byte-identical to the source. SHA-256 matches are in MANIFEST.json. No import, regex, threshold, or filter was changed.

## Glue (outside the copied tree)

- `src/engines/seclayer-glue/gate-adapter.mjs`: `createGatedFetch({fetchFn, gate})` wraps an injected fetch-compatible function. It calls `decideScope({toolName:'nuclei', arguments:{target:url}}, gate)` before the real fetch. The default gate fails closed.
- `test/seclayer-src/gate.test.mjs`: 5 gate tests.

## UNGATED modules (not copied; process stopped on them)

Gating these requires editing their logic or threading a fetch injection through them, which the brief forbids:

- server/ssrf.ts
- server/redTeam/probeHttp.ts
- server/redTeam/baseline.ts
- server/redTeam/sqlInjection.ts
- server/redTeam/reflectedXss.ts
- server/redTeam/commandInjection.ts
- server/redTeam/ssrf.ts
- server/redTeam/weakSessionToken.ts (also HOSTED: login credentials)
- server/nmap/run.ts, server/nmap/detect.ts, server/nmap/resolve.ts (process spawn and DNS)

## HOSTED modules (not copied)

- server/redTeam/blindSsrf.ts (needs the OOB collaborator)
- server/oob.ts
- server/redTeamProbes.ts
