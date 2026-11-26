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
   The operator's local instances have active probing unlocked
   (`ALLOW_UNVERIFIED_ACTIVE_PROBES=true`). Stale `_secscan-challenge` / `_seclayer-challenge`
   TXT records are leftovers, not a task. Do not report them as a blocker.
6. **Do not build a second scanning path.** `generate_scan_report`, the HTML report
   template, the engine merge layer and the vulnerable testbed were deleted on
   purpose. Do not recreate them.

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

## Current local state (may drift — verify before asserting)

- SecLayer is a detached `node` process on 4700, SQLite at
  `C:\sh\src\seclayer.io2026\data.sqlite`.
- Its `.env` is the **dev** config. The containerised config is preserved as
  `.env.container`; switching between them is deliberate.
- **A machine-wide `DATABASE_URL` exists** and points at a stale Postgres. Any local
  app start must clear it (`$env:DATABASE_URL=''`) or the app tries that database
  and fails on schema drift.
- Docker Desktop is installed. The container stack is **stopped and its containers
  removed**; the Docker path is unfinished (see `deploy/README.md`).
- The DSH profile has: the two MCP sections, the `seclayer-panel` dock plugin, and
  the Browser sidebar enabled.

## Where things live

- Repo: `C:\sh\seclayer-hybrid` (git; `origin` = ScanLayer-Agent-Hybrid)
- Plugins/bundles: `src/dsh-redteam-gate/plugins/` (seclayer-mcp, secscan-mcp, seclayer-panel)
- Deployment path: `deploy/` — README, bootstrap.ps1, port overrides, Postgres service
- App source: `C:\sh\src\seclayer.io2026` and `C:\sh\src\VibeScan-Enterprise-Build` (separate repos)

## Reporting to the user

State the finding count, the worst severity, and the app link. If you could not run
something, say so and say why. Never present a skipped check as a pass.

When there are findings: offer to fix them. That offer is the point of the tool.
