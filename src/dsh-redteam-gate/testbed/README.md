# Engine testbed — does SecLayer actually detect what it claims?

A deliberately vulnerable app (`vulnapp.mjs`) that plants one instance of each bug
class the SecLayer engine says it checks, plus hardened `/safe/*` controls that
must stay clean. `run.mjs` scans it over loopback (the lab-host path in the scope
gate — no DNS proof, nothing leaves the machine) and prints what fired.

```bash
node ../node_modules/tsx/dist/cli.mjs run.mjs            # dump every finding
node ../node_modules/tsx/dist/cli.mjs run.mjs --check    # assert against expected.json
node ../node_modules/tsx/dist/cli.mjs run.mjs --ticker   # engine's own probe verdicts
node ../node_modules/tsx/dist/cli.mjs check-probes.mjs   # each root probe in isolation
```

## What this caught

Running it found six real defects in the engine, all fixed:

1. **Every root-URL probe was broken on trailing-slash targets.** The scan
   normalises a bare host to `https://host/`, and each probe then built
   `` `${ctx.url}/?param=` `` — producing `//?param=`. Several URL parsers read
   `//?x` as a protocol-relative authority and drop the query; servers route `//`
   differently or redirect it. SQLi, reflected XSS, command injection, SSRF, open
   redirect, CRLF and the rest were all probing a path the app does not serve, so
   they reported "no signal" against plainly vulnerable code. Fixed with a shared
   `probeUrl()` / `probeRoot()` in `redTeam/probeHttp.ts`, used by every probe.
2. **The rate-limit probe's burst was below the limit it was testing for.** A
   burst of 6 reported "no rate limiting" against a limiter at 6, and a burst of 12
   against a limiter at 20 — a bounded burst below an unknown threshold always
   looks like an absence. It also sent no `email`, so an endpoint requiring one
   bounced on validation and never compared a code. Burst is now 30, the payload
   carries the common field names, validation-only 400s are skipped, and the check
   is LOW/LOW rather than a HIGH claim it cannot prove.
3. **An unconfirmed claim could label a site HIGH RISK.** `deriveSecurityPosture`
   took the headline label from raw severity, so one medium-confidence heuristic
   printed "88/100 · GRADE B · HIGH RISK". The label is now capped at MODERATE
   unless a finding at that severity is confirmed.
4. **The same contradiction in the banner** — "High Risk — Prompt Remediation
   Needed" beside a MODERATE gauge. It now asks for verification instead.
5. `probeUrl` itself briefly dropped the path (`http://host?query`), which the
   scope gate read as a hostname; fixed by building through `new URL()`.
6. The `ssti`/`pathTraversal` conversions initially mangled a template literal
   (`${name}` evaluated as a variable). Caught by running the probes.

## Both engines, not one

The harness runs the two apps' **own code**, imported directly — nothing about
either scanner is reimplemented here:

| App | Engine entry point | How it runs |
|---|---|---|
| SecLayer | `engines/seclayer-core/server/scanner.ts` → `runDiagnostics` | aggressive tier, OOB collaborator on `PORT+2` |
| SecScan | `engines/vibescan-core/.../lib/scanner.ts` → `runScan` | deep tier |

SecScan has its own SSRF guard and refuses private/local targets, so the harness
sets its documented self-hoster opt-out `ALLOW_PRIVATE_SCAN_TARGETS=true` — safe
here because every target is 127.0.0.1. Without it SecScan cannot scan a lab
target at all, which is why it went unused in the first passes.

Each engine covers checks the other does not. SecLayer owns the active exploit
proofs (SQLi, XSS, cmd injection, SSRF/XXE, SSTI, LFI, NoSQL, CORS, host header,
price tampering, webhook bypass, prototype pollution) and the OOB checks; SecScan
owns the exposure/passive catalog (`.env`, backup archive, phpinfo, git config,
package manifest, verbose error pages, cookie flags, CORS wildcard, directory
listing) and is markedly faster (9.4s vs 10-26s per target).

## One report, no overlap

`src/engine-merge.mjs` folds the two engines into a single finding list:

- **SecScan is the base.** A SecScan finding always wins and is never repeated.
- **SecLayer contributes only what SecScan does not have.** A SecLayer finding is
  dropped when SecScan already covered its issue key.
- The join key is a canonical ISSUE KEY (`headers:csp`, `cookies:httponly`,
  `injection:ssrf`, …), not a title — the engines name the same issue differently
  ("Missing Content-Security-Policy (CSP)" vs "Missing CSP Header"), which is why
  a title-based dedup would leave duplicates behind.
- A finding whose name matches no key is treated as SecLayer-only and **always
  kept**. The safe direction: a mis-keyed finding is reported twice rather than
  lost.
- Coverage is SecScan's decision only. SecLayer's own findings are not folded into
  the covered set, so two legitimate findings of the same kind on different
  targets both survive.

On the testbed: **158 raw rows → 73 merged, 85 overlaps removed.** What survives
from SecLayer is exactly the active/exploit surface SecScan lacks — command
injection, SSRF and blind SSRF, SSTI, XXE, CRLF/host-header injection, prototype
pollution, price tampering, webhook bypass, GraphQL introspection, weak-token
entropy, and HSTS (SecScan has no HSTS check).

## Current result

40 detection checks, 0 missed; 0 false positives on the controls, across both
engines. SecLayer: main app ~10s, CRLF proxy ~26s, listing server ~26s.
SecScan: ~9s on the main app.

## Known gaps in this testbed

Only one left: **IDOR/BOLA**, deliberately last. It needs two authenticated
identities plus endpoints the crawler can reach, so it is a bigger fixture than
the rest.

## Resolved since the first pass

- **Duplicate findings.** The same weak reset token was reported six times in one
  scan: the dedup key was `${issue}|${capture.url}`, and the fuzzer hits one
  endpoint once per payload, so every payload's URL looked like a new finding.
  `captureKey()` now keys on origin+pathname. 6 → 2 (one per token field).
- **Weak-token entropy, SCA, directory listing, framework signature** — all four
  were fixture problems, not engine gaps: the token endpoint needed a parameter
  for the fuzzer to reach it, the library version had to be in a *loaded resource
  URL* (not body text), `open-directory-listing` only requests `/` so it needs a
  target whose root really is a listing, and the framework check needs a revealing
  `X-Powered-By`.

- **XXE and blind SSRF** — now proven end to end. `scanSeclayer` forwards
  `ScanOptions.oob`, `vulnapp.mjs` runs a local collector on `PORT+2`, and the
  harness reads its hit log from a file. A fetch-based poll inside the engine's
  scoped-fetch window stalled for ~80s, so the store reads a file instead.
- **CRLF injection** — was "impossible on a Node origin". Node's `http` module
  rejects a header value containing CR/LF, so a second listener (`PORT+1`) writes
  the response bytes over a raw socket, the way a fronting proxy that concatenates
  input into a header would. The probe now detects it.
- **Open redirect** — was "fires standalone, no signal in the orchestrated run".
  Not a probe bug: the DSH scope gate refused every request whose *query string*
  contained a hostname (`?next=https://evil.example/`), because it substring-scanned
  the whole request URL for host-like tokens. It now checks only the URL's own
  host, which is where packets actually go. That also unblocked SSRF payloads and
  is covered by three new regression tests in `test/guard/scoped-fetch.test.mjs`.
- **OOB probe took 147s of a 148s scan.** `probeLlmInsecureToolUse` polled the
  collaborator for 8s per (candidate, field) *inside* its loop, so a page with a
  handful of forms meant ~18 sequential 8s waits — on targets with no LLM at all.
  It now fires every attempt first and waits once, concurrently: 148s → 9.9s with
  the same evidence.
