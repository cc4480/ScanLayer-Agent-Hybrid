# Standing brief for every agent in this environment

Read this before touching anything. It exists because a previous session re-derived
the whole architecture from scratch, wrote its own markdown report, and chased a
stale domain-verification token — all of which this environment deliberately does
not do.

## What this is

Two security scanners, each a real TypeScript/Node app, each running **locally from
its own source**, each connected to DSH as its **own MCP section**:

| App | Local URL | Source | DSH tools | Interface |
|---|---|---|---|---|
| SecLayer | `http://127.0.0.1:4700` | `C:\sh\src\seclayer.io2026` | `mcp__seclayer__*` | its own dashboard / `ReportViewer` / `PublicReport` |
| SecScan | `http://127.0.0.1:4701` (when running) | `C:\sh\src\VibeScan-Enterprise-Build` | `mcp__secscan__*` | its own dashboard |

They are separate on purpose: separate server, transport, credentials, tools and
port. They do not share code and must not be merged.

## Before you act — preflight

Run this in order. Do not skip to scanning.

1. **Read the request literally.** "Scan X" means run a scan and hand back the app's
   report link. "Where is my report?" means find the app's link for a scan that
   already ran — it does not mean write a report.
2. **Check the app is up.**
   ```powershell
   (Invoke-WebRequest http://127.0.0.1:4700/api/system/health -UseBasicParsing).Content
   ```
   Expect `{"status":"Online",...}`. If it fails, start it detached — and **clear
   `DATABASE_URL` first**, or it connects to a stale Postgres and dies:
   ```powershell
   cd C:\sh\src\seclayer.io2026
   $env:DATABASE_URL=''
   Start-Process node -ArgumentList 'node_modules/tsx/dist/cli.mjs','server.ts' -WorkingDirectory . -WindowStyle Hidden
   ```
3. **Check which scan path is live.** If the `mcp__seclayer__*` tools are present,
   use them. Otherwise fall back to `seclayer_scan` / `webapp_scan`, which return
   JSON with no rendering.
4. **Do not verify domains.** Active probing is already unlocked on these local
   instances. Never run `domain_verify_start` / `domain_verify_check` on your own
   initiative, and never report stale `_seclayer-challenge` / `_secscan-challenge`
   TXT records as a blocker.
5. **Distrust prior artifacts.** A markdown report, an HTML dashboard dump, or a
   `*-scan-report.md` from an earlier session is not authoritative and was probably
   produced by an agent that lacked this brief. Re-derive from the app, not from the
   file.
6. **Only then** start work, and state in your answer which path you used.

## Hard rules — no exceptions

1. **Never write a scan report.** The apps own the report: scoring, layout, live
   ticker, fix prompt. Your output is the app's URL, not a document. A markdown
   report you author is a duplicate implementation and is wrong even when accurate.
2. **Never re-implement scan logic.** Use the apps' code through their MCP tools or
   their HTTP API. Do not rewrite probes, scoring, or check catalogs.
3. **Never ask for live-service keys.** Both apps run from local source. Keys are
   minted locally by the apps themselves (`POST /api/keys`) and live in the
   gitignored `.env` at the repo root.
4. **Read-only on targets.** Scanning is read-only; the only thing produced for the
   user is the app's report plus an offer to fix.
5. **Do not run `domain_verify_start` / `domain_verify_check` unless the user asks.**
   See preflight step 4.
6. **Do not build a second scanning path.** `generate_scan_report`, the HTML report
   template, the engine merge layer and the vulnerable testbed were deleted on
   purpose. Do not recreate them.
7. **Do not claim a check passed because it was skipped.** Report skipped checks as
   skipped, with the reason.

## How to run a scan

Preferred: the section's own tools —
`mcp__seclayer__scan`, `mcp__seclayer__list_scans`, `mcp__seclayer__get_report`.

Keyless local fallback (no MCP section connected): the DSH tools `seclayer_scan`
and `webapp_scan`, which return findings as **JSON data**. They do not render.

Then hand the user the app's own link:

```
http://127.0.0.1:4700/r/<shareToken>     # SecLayer public report
http://127.0.0.1:4700                    # dashboard: scans, live ticker
```

`shareToken` comes from the scan record (`GET /api/scans/<id>`).

## Definition of done for a scan request

- The scan actually ran (say so if it did not, and why).
- The user has the **app's** link, not a document you wrote.
- The answer states finding count and worst severity.
- If anything was found, you offered to fix it.

## Current local state (may drift — verify before asserting)

Both apps now run **in Docker**, from their own images, each against its own database:

| Container | Port | Notes |
|---|---|---|
| `seclayer` | `127.0.0.1:4700` | production mode, Postgres `stack-db`, TLS |
| `stack-db` | internal | Postgres 16 with a self-signed cert (the app forces TLS off-localhost) |
| `vibescan-enterprise-build-web-1` | `127.0.0.1:4701` | SecScan web + API + `/api/mcp` |
| `vibescan-enterprise-build-secscan-1` | internal | the scanner worker |
| `vibescan-enterprise-build-db-1` | internal | its own Postgres 16 |

- **Docker Desktop must be running.** `AutoStart` is on, but it fires at Windows
  sign-in only. Once the engine starts, containers return by themselves
  (`restart: unless-stopped`) and the MCP sections reconnect on their own.
- **Machine-local MCP config lives in `.dsh/profiles/web/cordis.patch.yml`**, not in
  the repo bundles. It holds the full concrete config with the local key/token
  inline, because a patch `config:` REPLACES the row config — it does not merge.
- **The keys are local, never from the live services.** SecLayer's is in `api_keys`
  (sha256, `sl_live_`); SecScan's is in `api_tokens` (`ssk_`, scope `mcp`).
  Production hardcodes `cookieOptions.secure = isProd`, so an HTTP session cannot be
  used over plain http — the key is the way in (`X-API-Key` for SecLayer,
  `Authorization: Bearer` for SecScan).
- **Compose merges `ports:` lists.** Adding a mapping publishes *both*; the deploy
  overrides use `!override` so each app listens on loopback only.
- **Container scans take ~3 min** where the host Node instance took ~33s: the image
  ships nmap and port-scans the target.
- A machine-wide `DATABASE_URL` still exists and points at a stale Postgres. It does
  not affect the containers, but any local Node start must clear it.

## Where things live

- Repo: `C:\sh\seclayer-hybrid` (git; `origin` = ScanLayer-Agent-Hybrid)
- Plugins/bundles: `src/dsh-redteam-gate/plugins/` (seclayer-mcp, secscan-mcp, seclayer-panel)
- Deployment path: `deploy/` — README, bootstrap.ps1, port overrides, Postgres service
- App source: `C:\sh\src\seclayer.io2026` and `C:\sh\src\VibeScan-Enterprise-Build` (separate repos)

## Reporting to the user

State the finding count, the worst severity, and the app link. If you could not run
something, say so and say why. Never present a skipped check as a pass.

When there are findings: offer to fix them. That offer is the point of the tool.
