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

All ten root probes fire on their planted bug. In the full orchestrated run the
engine reports ~64 findings covering headers, cookies, exposed `.env`/`.git`,
GraphQL introspection, BOLA-style object exposure, SQLi, XSS, command injection,
SSRF, SSTI, LFI/path traversal, NoSQL, CORS, host-header injection, and the
crawled-parameter variants of the same classes.

## Known gaps in this testbed

- **CRLF injection** cannot be demonstrated by a Node origin: Node rejects a
  header value containing CR/LF, so the injected header never appears. It needs a
  fronting proxy that concatenates input into headers.
- **Open redirect** fires when the probe is called directly but reports "no
  signal" inside the orchestrated aggressive tier — unresolved. Suspect a fetch
  abort/timeout in the preceding probes being swallowed as "no signal".
- **XXE and blind SSRF** need an out-of-band collaborator (`OOB_BASE_URL`);
  without one the probes can only report "no signal".
- Not yet planted: stored XSS, IDOR/BOLA over discovered endpoints, price
  tampering, webhook signature bypass, prototype pollution, weak-token entropy,
  source-map exposure, secret scanning, directory listing, verbose errors, API
  schema discovery. The routes exist in part; the probes need the crawl to reach
  them and that wiring is not finished.
