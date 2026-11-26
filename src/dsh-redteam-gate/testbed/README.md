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

## Current result

33 detection checks, 0 missed; 0 false positives on the controls. Scans: main app
~10s, raw-socket CRLF proxy ~26s, plain-file listing server ~26s. The engine
reports ~131 findings across the three targets (minus duplicates — see below).

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
