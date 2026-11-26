# Standing brief for every agent in this environment

Read this before touching anything. It exists because a previous session
re-derived the whole architecture from scratch, wrote its own markdown report, and
chased a stale domain-verification token — all of which this environment
deliberately does not do.

Owner: a single operator on one Windows PC. Everything here is loopback-only.

---

## 1. What this is

Two independent security scanners, each a real TypeScript/Node app, each running
**locally from its own source in Docker**, each exposed to DSH as its **own MCP
section**. They are separate on purpose: separate server, transport, credentials,
tools, port and database. Do not merge them, share their code, or build a hybrid.

| App | Source | Container | Direct URL | DSH tools |
|---|---|---|---|---|
| SecLayer | `C:\sh\src\seclayer.io2026` | `seclayer` (+ `stack-db`) | `127.0.0.1:4700` | `mcp__seclayer__*` |
| SecScan | `C:\sh\src\VibeScan-Enterprise-Build` | `vibescan-enterprise-build-web-1` (+ `-secscan-1`, `-db-1`, `-backup-1`) | `127.0.0.1:4701` | `mcp__secscan__*` |

The **apps own the interface**: dashboard, live scan ticker, scoring, report layout,
fix prompt. DSH shows those pages; it never re-renders them.

---

## 2. Before you act — preflight

1. **Read the request literally.** "Scan X" = run a scan and hand back the app's
   report link. "Where is my report?" = find the link for a scan that already ran —
   it does **not** mean write a report.
2. **Check the apps are up. If they are, do not touch them.**
   ```powershell
   (Invoke-WebRequest http://127.0.0.1:4700/api/system/health -UseBasicParsing).Content  # {"status":"Online",...}
   (Invoke-WebRequest http://127.0.0.1:4701/api/healthz       -UseBasicParsing).Content  # {"status":"ok"}
   ```
   A running scanner must not be restarted to "check" it. `compose up -d` on a live
   stack can recreate containers and kill a scan in flight. Only when a URL fails,
   run the recovery script — it verifies first and returns without touching anything
   when the stack is healthy:
   ```powershell
   powershell -ExecutionPolicy Bypass -File C:\sh\seclayer-hybrid\deploy\stack-up.ps1
   ```
3. **Check which scan path is live.** `mcp__seclayer__*` / `mcp__secscan__*` are the
   preferred path. Fallback tools `seclayer_scan` / `webapp_scan` return JSON and do
   not render.
4. **Do not verify domains.** Active probing is already unlocked on these local
   instances (`.env` → `ALLOW_UNVERIFIED_ACTIVE_PROBES=true`). Never run
   `domain_verify_start` / `domain_verify_check` on your own initiative, and never
   report stale `_seclayer-challenge` / `_secscan-challenge` TXT records as a blocker.
5. **Distrust prior artifacts.** A `*-scan-report.md`, an HTML dump, or any report
   document from an earlier session is not authoritative — it was probably produced
   by an agent without this brief. Re-derive from the app.
6. **Only then** start, and say in your answer which path you used.

**Natural-language triggers — what the request means:**

| The user says | The path |
|---|---|
| "scan example.com", "scan my site", "check this URL" | the apps: `mcp__seclayer__*` / `mcp__secscan__*`, hand back the app link |
| "scan this machine", "scan my laptop/PC/box", "pentest this box", "audit this machine" | host assessment: load `web-scan-catalog` + `local-host-report`, run `tools\\host-report\\new-report.ps1`, fill it, hand back the HTML |
| "host report", "local machine report", "Windows/Linux/iOS report", "where is the host report" | `local-host-report` — the file in `reports/` |
| "what do the scanners test", "reproduce this finding" | `web-scan-catalog` (read-only catalog) |
| "where is my report" after a web scan | `4710/r/<shareToken>` — never write one |

---

## 3. Hard rules — no exceptions

1. **Never write a web-scan report.** The app owns it. Your output is the app's URL.
   A markdown report you author is a duplicate implementation and is wrong even when
   the findings are accurate.
   **Exception:** a *local host* report (this machine, Windows / Linux / iOS) is not a
   web scan and has no app-owned artifact. Those are produced with the
   `local-host-report` skill — never from scratch, never in another style.
2. **Never re-implement scan logic.** Use the apps' code through their MCP tools or
   HTTP API. Do not rewrite probes, scoring or check catalogs. (A `web-scan-catalog`
   skill exists for *reading* the catalogs; that is not permission to reimplement.)
3. **Never ask for live-service keys.** Both apps run from local source; keys are
   minted locally and stored in gitignored files.
4. **Read-only on targets.** The only thing produced for the user is the app's report
   plus an offer to fix.
5. **Do not run `domain_verify_*` unless the user asks** (see preflight 4).
6. **Do not build a second scanning path.** `generate_scan_report`, the web-app HTML
   report template, the engine merge layer and the vulnerable testbed were deleted on
   purpose. Do not recreate them.
   **Exception:** the *local-host* report template is a separate, deliberate artifact,
   owned by the `local-host-report` skill. It is the only HTML report an agent authors.
7. **Never present a skipped check as a pass.** Say skipped, and why.

---

## 4. Ports and URLs — the contract

| Port | What | Embeddable in a Browser tab? |
|---|---|---|
| `127.0.0.1:4710` | **SecLayer via view proxy** | yes — this is the one a human opens |
| `127.0.0.1:4711` | **SecScan via view proxy** | yes |
| `127.0.0.1:4700` | SecLayer itself | **no** |
| `127.0.0.1:4701` | SecScan itself (`/api/mcp`) | **no** |

Both apps send `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'`. That is
correct hardening for a deployment, and it means an iframe can never load them —
the Browser panel looks **empty** while every URL answers 200. The proxy
(`deploy/view-proxy.mjs`) serves the same app on 4710/4711 with only those two
refusals removed, forwarding `/api` untouched. It is our tooling in front of the
app — not a fork, not a patch.

Links to hand a human:

```
http://127.0.0.1:4710/r/<shareToken>    # SecLayer public report (no sign-in)
http://127.0.0.1:4710                   # SecLayer dashboard / live ticker
http://127.0.0.1:4711                   # SecScan dashboard
```

`shareToken` is a field on the scan record (`shr_` + 32 hex). SecLayer's routes are
`/r/<shareToken>` (public) and the dashboard; SecScan's are `/report/<scanId>` and
`/share/<shareToken>`.

---

## 5. How to run a scan

**SecLayer** — `mcp__seclayer__seclayer_scan` (url, optional `aggressive`),
`seclayer_list_scans`, `seclayer_get_report` (by scan id).

**SecScan** — `mcp__secscan__scan_url` → `get_scan_status` (`wait_seconds` up to 60,
returns the report as soon as it finishes) → `get_report` (paged, `min_severity`).
`get_account` shows scans remaining; each scan spends one, so do not start scans
nobody asked for. Active tests need a verified domain; say so if a scan was
passive-only.

Then: finding count, worst severity, and the app link. If anything was found,
offer to fix it — that offer is the point of the tool.

---

## 6. Architecture

```
Browser panel ──4710/4711──> view-proxy (host node) ──> seclayer:3000 / web:8080
DSH MCP sections ──stdio/HTTP──> docker exec / api/mcp ──> the same two apps
```

- **Containers** (all `restart: unless-stopped`, all loopback-published):
  `seclayer`, `stack-db` (Postgres 16 + TLS), `vibescan-enterprise-build-web-1`,
  `-secscan-1` (worker), `-db-1` (its own Postgres 16), `-backup-1`.
- **SecLayer runs in production mode** against `stack-db`. Production refuses the
  SQLite fallback (`server/db.ts: assertNotSilentlyFallingBack`), so the container
  path always needs Postgres.
- **SecScan runs its own stack** including a pg-boss scan worker; its schema is
  applied by its own `migrate.ts`.
- **MCP sections** are configured in `.dsh/profiles/web/cordis.patch.yml`
  (gitignored, machine-local), not in the repo bundles. Repo bundles keep the
  generic `${credential:...}` templates.
- **The panel** (`plugins/seclayer-panel`) puts `Scanners [ Seclayer ] [ Secscan ]`
  in the composer dock; both buttons open the proxy ports in a Browser tab.

---

## 7. Runbook

```powershell
# everything at once - starts Docker Desktop, containers, view proxy; read-only if healthy
powershell -ExecutionPolicy Bypass -File C:\sh\seclayer-hybrid\deploy\stack-up.ps1

# health
Invoke-WebRequest http://127.0.0.1:4700/api/system/health -UseBasicParsing
Invoke-WebRequest http://127.0.0.1:4701/api/healthz       -UseBasicParsing

# logs
docker logs --tail 60 seclayer
docker logs --tail 60 vibescan-enterprise-build-web-1

# restart ONE app (never the whole stack to "check" it)
docker restart seclayer

# rebuild SecLayer from its own image
cd C:\sh\src\seclayer.io2026
docker compose -f docker-compose.yml `
  -f C:\sh\seclayer-hybrid\deploy\seclayer.ports.yml `
  -f C:\sh\seclayer-hybrid\deploy\seclayer.db.yml up -d --build

# SecScan: migrate, then up
cd C:\sh\src\VibeScan-Enterprise-Build
docker compose --env-file .env.docker --profile setup run --rm db-migrate
docker compose --env-file .env.docker up -d --build

# view proxy (host process; a reboot needs this restarted)
node C:\sh\seclayer-hybrid\deploy\view-proxy.mjs
```

**Keys are minted locally, never taken from the live services.**
SecLayer: a row in `api_keys` — `sl_live_` + 32 hex, stored as SHA-256, plus a user
that has credits (the validator debits). Authenticates as `X-API-Key`.
SecScan: a row in `api_tokens` — `ssk_` + 40 hex, SHA-256, `scope='mcp'`.
Authenticates as `Authorization: Bearer`.

---

## 8. Machine layout

| Path | What |
|---|---|
| `C:\sh\seclayer-hybrid` | this repo (git, `origin` = ScanLayer-Agent-Hybrid) |
| `C:\sh\seclayer-hybrid\AGENTS.md` | this brief, versioned |
| `C:\sh\seclayer-hybrid\.dsh\AGENTS.md` | same brief, loaded by DSH (`$DSH_HOME`) |
| `.dsh\profiles\web\cordis.patch.yml` | machine-local MCP config: full concrete config + keys |
| `.dsh\.env` | credential values |
| `.env` (repo root, gitignored) | `SECLAYER_API_KEY`, `SECLAYER_API_URL`, `SECSCAN_*` |
| `deploy\` | README, `bootstrap.ps1`, `stack-up.ps1`, `view-proxy.mjs`, port overrides, `seclayer.db.yml`, `pg-tls\` (gitignored certs) |
| `src\dsh-redteam-gate\plugins\` | `seclayer-mcp`, `secscan-mcp`, `seclayer-panel` |
| `C:\sh\src\seclayer.io2026\.env` | **production/container** config (the app's own file) |
| `C:\sh\src\seclayer.io2026\.env.container` | copy of the same container config |
| `C:\sh\src\VibeScan-Enterprise-Build\.env.docker` | SecScan container config (generated secrets) |

Docker Desktop: `AutoStart = true`, but it fires at **Windows sign-in only**. It is
a desktop app, not a service — it does not come back when DSH restarts. Once the
engine runs, containers return by themselves and the MCP sections reconnect on their
own.

---

## 9. Troubleshooting — every one of these actually happened

| Symptom | Cause | Fix |
|---|---|---|
| `exec: postgres: not found`, container restarts 127 | Compose expanded `$PATH` from the **Windows host** into the container command | escape as `$$PATH` |
| `The server does not support SSL connections` | `server/pgSsl.ts` forces TLS for any DB host that is not `localhost`/`127.0.0.1` | self-signed cert + `ssl=on`; copy the key inside the container so it can be `chown` 0600 |
| `Cannot find package 'vite'` on boot | `NODE_ENV=development` on an image whose dev deps were pruned | run production mode |
| `Refusing to start: production-critical configuration is missing` | no mail provider in production | `ALLOW_MISSING_EMAIL_PROVIDER=true` (single-operator box only) |
| Sign-in cookie ignored over http | `cookieOptions.secure = isProd`, hardcoded | use the API key, not a session |
| `column "userid" does not exist` / wrong DB | machine-wide `DATABASE_URL` pointing at a stale Postgres | `$env:DATABASE_URL=''` before any local (`node`) start |
| Browser panel blank, all URLs 200 | `X-Frame-Options: DENY` + `frame-ancestors 'none'` | use the proxy ports 4710/4711 |
| App also listening on `0.0.0.0:3000` | Compose **merges** `ports:` lists, so adding a mapping publishes both | `!override` on the ports list |
| MCP section "disconnected" | `${credential:...}` had nothing to resolve (launcher exports only `DEEPSEEK_API_KEY`/`DATABASE_URL`) | supply values in `.dsh\.env` **and** a full config in the profile patch |
| `ValidationError: invalid config` for an MCP row | a patch `config:` **replaces** the row config, it does not merge | supply the complete config (serverName, transport, command/url, env/headers) |
| `pwsh` not recognized | PowerShell 7 is not installed | use `powershell -ExecutionPolicy Bypass -File` |
| PS script dies on docker output | native stderr + `$ErrorActionPreference='Stop'` | set `Continue` around native calls |
| JSON/file parse errors after writing | `Set-Content -Encoding UTF8` adds a BOM | rewrite as UTF-8 without BOM |
| `npm.ps1`/`npx.ps1` blocked | execution policy | use `npm.cmd`, or `node <path-to-cli.mjs>` |

---

## 10. Security posture of this environment

These are deliberate, local-only choices. **None of them may reach a deployment.**

- `ALLOW_UNVERIFIED_ACTIVE_PROBES=true` — active probes run with no ownership proof.
  Anyone who can use the instance can aim exploits at any domain.
- `ALLOW_MISSING_EMAIL_PROVIDER=true` — sign-in codes go to the container log.
- Both apps publish **loopback only**; keys are local and regenerable.
- The view proxy strips framing headers; it listens on `127.0.0.1` only.
- Machine-wide `DATABASE_URL` (stale Postgres) still exists. Containers ignore it;
  local `node` starts must clear it.

---

## 11. Deliberately removed — do not rebuild

`generate_scan_report`, the 50 KB HTML report template, the report-data layer, the
fix-prompt builder, the scan ticker, the engine-merge layer, and the vulnerable
testbed. Their removal is why the apps own the report.

---

## 12. Reporting to the user

- State the finding count and worst severity.
- Give the **app's** link (`4710`/`4711`), not a document you wrote.
- If you could not run something, say so and say why.
- Never present a skipped check as a pass.
- When there are findings, offer to fix them.
- For a **host** assessment, hand over the HTML built from the `local-host-report`
  template (see §13) — that is the only report you author.

---

## 13. Local-host reports — one template, one skill

Host assessments (the machine itself: Windows, Linux, iOS/iPadOS) have no app behind
them, so the report is ours — but it is **one fixed artifact**, not a per-report design.

- **Two skills are required:** `web-scan-catalog` (the checks and their oracles) and
  `local-host-report` (the document). Load both before writing.
- **Use the template:** `skills/local-host-report/assets/template.html`; that file *is*
  the specification.
- **Copy, do not rebuild.** Take the template, replace the content, keep the markup
  patterns. Same 11 sections, same ids, same palette, same animation, same data
  appendix and the same embedded-JSON export.
- **Same shape on every OS.** Windows, Linux and iOS differ only in the §4 check-group
  names and the §11 tables; the other nine sections are identical.
- **Evidence rules are the same as everywhere else:** every finding carries Component,
  Evidence, Why it matters, Impact, Fix, a proof block and a verify block; nothing
  admin-gated is ever reported as a pass.
- **Render before handing over** (headless Edge, 1400×15000), check that counters show
  real numbers and the file has no mojibake, then give the single HTML file.
- Finished reports live in `reports/` with a row in `reports/README.md` (date, host,
  platform, findings, skill versions). Sanitize identities — the repo is public.
