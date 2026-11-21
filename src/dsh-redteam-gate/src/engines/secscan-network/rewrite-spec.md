# Rewrite spec: DNS-pinning layer (ssrfGuard.ts, pinnedDispatcher.ts)

Source: `artifacts/api-server/src/lib` in VibeScan-Enterprise-Build (read-only).
Originals, byte-identical: `originals/ssrfGuard.ts`, `originals/pinnedDispatcher.ts` (hashes in MANIFEST.json, section "replaced").
Rewritten files (this folder): `ssrfGuard.ts`, `pinnedDispatcher.ts`. Same filenames, same exported names and signatures.

## What was rewritten and what was not

- `ssrfGuard.ts`: only the resolution block changed (the old cache, `resolvesPublicly`, the 30 s cache and the `_clearResolveCache` seam). The pattern lists, `isPrivateAddress`, `embeddedIpv4`, `isHostnameSafeSync`, `privateTargetsAllowed`, `checkUrlSafe`, `checkScanTarget`, `checkHostname` are byte-for-byte the original code.
- `pinnedDispatcher.ts`: rewritten as a whole, but the four exports and the `vet` decision logic are the same. The only change is that it reads the answer from `resolveVetted` instead of calling `dns.lookup` itself, so it no longer imports `node:dns`.
- Added exports (new names, no existing signature changed): `resolveVetted`, `Resolution`, `ResolvedAddress`, `_setResolverForTest` (test seam, same pattern as `_clearResolveCache`).

## Design change, in one paragraph

Source: `checkUrlSafe` resolves a name for the check (cached 30 s), and `scanDispatcher`'s connect-time lookup resolves it again for every connection. Both are judged, so no private address is connected to. The rewrite makes both read one answer: `resolveVetted(name)` resolves once per name per 30 s window, caches the whole answer (all addresses, the verdict and any error), and shares an in-flight lookup between concurrent callers. The connect-time lookup hands the socket an address from that cached, judged answer. A DNS answer that changes inside the window is not seen. The `DNS` timeout (5 s) now also applies to connect-time lookups, which had none in the source.

## Properties mapped to tests

Test names are exact. "src" = original test in the source repo, run unmodified (84 of 84 pass on the rewrite, section "Results"). "new" = added in `test/secscan-network/pinning-rebind.test.ts`.

| # | Property | Where it is enforced | Test(s) |
|---|---|---|---|
| P1 | Loopback, RFC 1918, link-local/IMDS, CGNAT, 0/8, multicast, reserved, IPv6 loopback/ULA/link-local/multicast refused as literal addresses | `isPrivateAddress`, `PRIVATE_IP_PATTERNS` (unchanged) | src: `isPrivateAddress > catches every private IPv4 range we care about`; `catches IPv6 loopback and unique-local`; `special ranges the guard used to allow (audit #14) > blocks ...` (8 cases); src: `checkUrlSafe > rejects a literal private address` |
| P2 | Public addresses are allowed (no over-blocking) | unchanged | src: `allows ordinary public addresses`; `still allows 8.8.8.8` etc. (4 cases); `IPv6 literals > accepts a public IPv6 literal target` |
| P3 | IPv4-mapped, IPv4-compatible, NAT64 and expanded forms judged on the embedded IPv4 | `embeddedIpv4`, unchanged | src: `unwraps IPv4-mapped IPv6 ...`; `embedded IPv4 in every IPv6 notation > blocks ...` (8 cases) |
| P4 | Blocked names and suffixes refused without DNS (`localhost`, `metadata.google.internal`, `169.254.169.254`, `.local`, `.internal`, bare label, trailing dot, case) | `isHostnameSafeSync`, unchanged | src: `isHostnameSafeSync > blocks known-internal names and suffixes`; `ignores a trailing dot and case` |
| P5 | Name with any private answer is refused (round-robin public + private is the bypass) | `resolveVetted` then `publicOnly` (`some` private) | src: `checkUrlSafe > rejects a public-looking name that resolves to a private address` (real DNS, `rebind.localtest.me`); src: `vettedLookup > refuses a name that answers a private address` (real DNS); new: `refuses an answer that is empty` |
| P6 | Fails closed when DNS cannot resolve the name | `resolveOnce` catch returns `publicOnly: false` | src: `checkUrlSafe > fails closed when DNS cannot resolve the name` (real DNS, `.invalid`) |
| P7 | Fails closed when DNS stalls past 5 s; applies to the connect-time lookup too (new in rewrite) | `DNS_LOOKUP_TIMEOUT_MS`, timeout race in `resolveOnce` | new: `fail closed > refuses a name whose lookup never answers, once the DNS deadline passes` (checks both the check path and the connect path, code `ETIMEDOUT`) |
| P8 | DNS resolved once per name per window; the connected IP is the judged IP (rebinding defence, pinning) | `resolveVetted` cache, `vet` in pinnedDispatcher | new: `connects to the first pinned IP, not the later answer`; `the connect-time lookup hands back the address the check judged, even after DNS changes`; `a single-address lookup ... returns the pinned first address`; new: `concurrent checks for one name share one DNS lookup` |
| P9 | A name that answers loopback at connect time is refused when the opt-in is off (rebinding, real DNS) | `vet` with `honourOptOut=true` and `privateTargetsAllowed()` false | src: `pinnedDispatcher > a rebinding name at connect time > the scanner's agent refuses the same name and never connects`; new: `refuses a name that first answers loopback when the lab opt-in is off, and keeps refusing after it changes` |
| P10 | The unguarded path does follow a rebinding name to loopback (proves the test can fail) | contrast only | src: `an unguarded agent follows the name to loopback (the hole)` |
| P11 | Every scan request (`scanFetch`) goes through the pinned dispatcher, so the same name is refused | `http.ts` `dispatcher: scanDispatcher` | src: `scanFetch sends its requests through that agent: the same name is refused, so it returns nothing` |
| P12 | Webhook / domain-verification path (`strictDispatcher`) refuses private addresses even with the opt-in on | `lookupWith(false)` | src: `strictDispatcher > refuses a name that leads to loopback for a non-scan request, even with the private-target opt-in on` |
| P13 | Opt-out (`ALLOW_PRIVATE_SCAN_TARGETS`) only when the value is exactly `"true"` and only for scan-target callers | `privateTargetsAllowed`, `checkUrlSafe` `allowOptOut` | src: `honours the self-hosted opt-out only for callers that pass allowOptOut`; `keeps the opt-out off unless it is exactly "true"` |
| P14 | Production hard-off | NOT IN SOURCE. There is no `NODE_ENV` check. The only control is that the opt-out is off unless the variable is set to exactly `"true"`, and `vitest.config.ts` sets it only for the test runner. Adding a production hard-off would change behaviour and needs owner approval; it was not added. | src: `checkUrlSafe > rejects a literal private address` runs with the variable unset (the default) |
| P15 | Scheme limits: http and https for scan targets; https only when `requireHttps` (webhooks) | `checkUrlSafe` | src: `rejects non-http schemes`; `requires https only when the caller asks for it`; `checkScanTarget > refuses a non-http scheme` |
| P16 | Unparseable URL refused | `checkUrlSafe` | src: `rejects unparseable input` |
| P17 | IPv6 literal brackets handled (`[2606:4700::1]` accepted; `[::1]` refused) | `checkUrlSafe`, `isHostnameSafeSync` | src: `IPv6 literals (regression: brackets)` (3 cases) |
| P18 | Verdict remembered for 30 s; a repeat is answered from cache | `RESOLVE_TTL_MS` | src: `checkUrlSafe > remembers a name's verdict...` (under 5 ms) |
| P19 | Cache bounded at 512 names, oldest evicted | `RESOLVE_CACHE_MAX`, eviction in `resolveVetted` | new: `bounds the cache at 512 names; an evicted name is resolved again` |
| P20 | Per-hop check: a redirect to an internal address is refused before any connection | `http.ts` loop calls `checkUrlSafe` per hop | src: `blocked target addresses > refuses to follow a redirect that points at an internal address` |
| P21 | Redirects capped at 5 hops (`MAX_REDIRECT_HOPS`, httpTypes.ts:6), loops give up | `http.ts` loop | src: `scanFetch redirects > gives up on a redirect loop instead of hanging` |
| P22 | Redirects surface the 3xx and Location in manual mode; a 3xx without Location is returned | `http.ts` | src: `exposes the 3xx and its Location in manual mode`; `returns the 3xx when a redirect has no Location header` |
| P23 | Request timeout (`DEFAULT_TIMEOUT_MS` 8000, httpTypes.ts:4) covers time to headers and the body | `http.ts` timer, not cleared until the body is read | src: `scanFetch transport > returns null on timeout`; `the timeout covers the response body ... > returns within the timeout when the body never ends`; `still bounds a redirect hop whose body never ends` |
| P24 | Unreachable host returns null, not a throw | `http.ts` | src: `scanFetch transport > returns null rather than throwing when the host is unreachable` |
| P25 | Scan abort signal fails in-flight requests at once | `http.ts` | src: `scan abort signal > fails requests at once once the scan's signal is aborted` |
| P26 | Body size cap: stops and marks truncated; small bodies returned whole | `httpBody.ts` `readBodyMarked` | src: `readBodyMarked size cap > stops at the cap and marks the body truncated`; `returns a small body whole`. NOTE: the test passes an explicit 4096 cap. No test asserts the default `MAX_BODY_BYTES` (5 MiB, httpBody.ts:43). |
| P27 | Credentials only to in-scope hosts; dropped when a redirect leaves scope | `http.ts` + `ScanScope` (not part of the pinning layer) | src: `scanFetch credentials` (5 tests); `ScanScope` (5 tests) |

## Gaps (stated, not hidden)

- P14 (production hard-off) is not implemented in the source and is not added here. Recorded above.
- P26: the default body cap value is not asserted by any test.
- The new rebinding tests use a stub resolver through `_setResolverForTest`, so they prove the cache and connect-time logic, not real DNS behaviour. The real-DNS rebinding case is P9 (src test, `rebind.localtest.me`).
- Connect-time DNS results are now cached for 30 s (previously each connection re-resolved). A name that moves to a private address inside the window is still connected to only at its pinned, judged address. A name that moves to a private address after the window is refused on the next lookup.
- Negative results are cached for 30 s, including timeouts, on both paths. The source cached negatives on the check path only.
- The ssrfProbe tests (`ssrfProbe.test.ts`, `ssrfProbe.redirect.test.ts`) were not run. They import `realDb.testkit` and the scanner graph, which need a database. They are not in the Phase A test set.

## Results

Run through the scratchpad vitest runner (vitest 4.1.12, undici 7.30.1), config copied unmodified from `artifacts/api-server/vitest.config.ts` (`ALLOW_PRIVATE_SCAN_TARGETS=true`). The real DNS names resolved live during the run (`rebind.localtest.me` to 127.0.0.1, `example.com`). No test was skipped.

- Source tests on untouched source (baseline): 7 files, 84 passed, 0 failed, 0 skipped.
- Same source tests on the rewritten copies: 7 files, 84 passed, 0 failed, 0 skipped.
- New rebinding tests (`test/secscan-network/pinning-rebind.test.ts`): 1 file, 8 passed.
