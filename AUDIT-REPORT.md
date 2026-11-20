# Deepseek super — audit report

Audit date: 2026-11-20 (machine clock 04:1x–04:25 local). Read-only: nothing was started, stopped, restarted or edited in the project. The only files written are this report and scratch files outside the project. Secret values were never printed or copied; token values are redacted everywhere.

## 1. The error in your screenshot

> `resume failed for session "session-7661a1e3-…": RemoteError: Unknown agent preset: dsh-superagent-worker (gateway/internal)`

**What it means.** You opened a session on `127.0.0.1:3080` that can only be loaded by the superagent server on port `3082`. The session itself is intact; the 3080 server just does not know the agent preset it was saved with.

| Fact | Evidence |
| --- | --- |
| The session is bound to preset `dsh-superagent-worker` | `.dsh/storages/session_projcache/sessions/session-7661…json` (`agentPreset`); event `agent-preset/selected` at 08:54:16Z in the session log |
| It was created as `standard`, then 4 s after a `/permission danger-full-access` command the preset was switched to the worker preset | decoded `session.v4.jsonl.zstd`, events 4–10 |
| That preset is registered **only** by the `dsh-superagent` bundle | `src/dsh-superagent-prototype/cordis.patch.yml:20-23` |
| Port 3080 runs the `web` profile, whose bundles are only `dsh-base` + `dsh-web-app` | `.dsh/profiles/web/package.json` |
| Both profiles share one `DSH_HOME`, so 3080's sidebar lists 3082's sessions but cannot load this one | `.dsh/sessions/`, one shared store |
| A preset cannot be changed once a session has started a turn (`agent-preset/locked`), so the session cannot be "moved" to another preset | `agent-preset-registry/src/index.ts:363-370` |
| The repo's own docs say exactly this | `docs/006-deployment.md:15` ("Do not select them for personal Sessions") and `:246` ("a Session cannot load without its preset") |

**Your data is not lost.** The session log is 973 KB, 1,128 events, 9 turns, no error events. It will load as soon as it is opened on a server that has the superagent bundle (port 3082).

**Why the message is cryptic.** `session-controller/src/agent.ts:203-209` catches every resume error that is not one of three special cases and re-labels it `gateway/internal`, stringifying the original. The typed code `agent-preset/not-found` is lost, so the UI cannot show "open this session in the superagent profile".

## 2. Answer to "ok restarted?" — No

At audit time **nothing is listening on 3082**. Only 3080 (pid 20956, started 02:50) and the AlterEgo bridge on 8765 are up. `state/superagent/` is **empty**: the superagent runtime has never successfully started on this machine (no `orchestrator.sqlite`, no lock).

Three separate launch failures are on disk:

1. **First start (~02:50)** — `ValidationError: $.stateDir expect string to match regexp /^\//`. The plugin only accepted POSIX paths; the start script writes `C:\…`. Root cause of the whole 3082 saga.
2. **03:19** — `listen EADDRINUSE 127.0.0.1:3082`: relaunched while the previous instance still held the port (`.dsh/logs/startup-…09-19-00….log`).
3. **04:03 restart** — `state/superagent-restart.log` still shows failure #1's old regex, then `ELIFECYCLE … exit code 4294967295`. `lib/` had been rebuilt at 04:00:03, so that log was written by code loaded *before* the fix. `superagent-url.txt` was written at 04:03:50, five seconds after the log's last write. My reading (inference, not directly observed): the restart script found the URL in the stale log, reported success, and no new server came up. The URL file therefore holds a token for a server that is not running.

**The fix itself is good.** Source edits (`deployment.ts`, `infra/paths.ts`, `policy.ts`) are all older than the build, and I loaded the built bundle and validated the profile's real `stateDir` against its config schema: Windows backslash, forward-slash drive, UNC and POSIX paths are accepted; relative and `C:relative` are rejected. The new `tests/paths.spec.ts` passes (3/3).

## 3. Findings

Severity is my judgement for this single-user Windows machine.

| # | Sev | Finding | Evidence | Recommended fix |
| --- | --- | --- | --- | --- |
| 1 | **High** | Session 7661 only loads on 3082, which is down (sections 1–2) | above | Bring up 3082 (see section 5), open the session there. Use `standard` for personal sessions |
| 2 | **High (dormant)** | **Windows was never verified for the superagent's command isolation.** Worker shims for `gh`, `lark-cli` and the `blockedCommands` list are written as extensionless `#!/bin/sh` files (`src/infra/environment.ts:87-103`). `cmd`/PowerShell do not resolve extensionless scripts, so a pwsh worker calling `gh` reaches the **operator's real `gh` login** instead of the dedicated agent account, and blocked commands are not blocked. There is no `win32` branch anywhere in `src/` (grep: zero hits) | 15 `service-script.spec` failures, all exit code 9009 (Windows "command not found"); `README-TEST.md` says the build was verified on a Linux VM only | Add `.cmd` shims on win32 (or run workers through Git-Bash `sh`), and add a Windows test. Do not arm the superagent (repo, agent account, allowed users) until fixed. Currently dormant: it is unconfigured and paused |
| 3 | **Med–High** | **PC-control bridge exposure.** The AlterEgo MCP bridge (screen/mouse/keyboard/browser tools, `127.0.0.1:8765`, python pid 3060) is attached to a session running `danger-full-access` with approval policy `never`, and is also published on your tailnet via `tailscale serve` (`tcp://cho-zen1.taild72858.ts.net:8765`, tailnet-only, not Funnel). Auth **is** enforced: unauthenticated GET returns 401 on both loopback and the tailnet address | `tailscale serve status`; `curl` probe; `.dsh/profiles/superagent/cordis.patch.yml` | Confirm the tailnet forward is intended; if not, `tailscale serve reset` for that port. Restrict by Tailscale ACL |
| 4 | **Med** | Bridge bearer token is stored in plaintext in `.dsh/profiles/superagent/cordis.patch.yml` — the only file containing it (not in `.env`, not in any session log, not in the `.bak`) | grep of project tree + decoded session logs | Move to an env var or the credential store. Rotate if the folder was ever shared |
| 5 | **Med** | **The whole project lives inside OneDrive** (`C:\Users\Cho-zen\OneDrive\Desktop`). This syncs `.dsh/.credentials.yaml` (API-key reference + browser-session grant secret), every chat transcript, tokenised URLs and the bridge token to the cloud, plus 2.7 GB of `node_modules`. `OneDrive.Sync.Service` has accumulated ~3,768 CPU-seconds on this machine (correlation only). `README-TEST.md` itself suggests "OneDrive Desktop" | `du`, process list, path | Move to a non-synced path such as `C:\dsh`. README says moving requires deleting `.setup-done` and `.dsh\profiles\superagent` and re-running setup (absolute paths are baked in) |
| 6 | **Med** | `restart-superagent.ps1` defects: (a) **does not parse in Windows PowerShell 5.1** — line 85 uses `??`, PowerShell 7 only (verified with a 5.1 parse), while its own elevation hint launches `powershell` (5.1); (b) "success" means a URL string exists in the log, not that the port is listening, and the stale-log `Remove-Item` failure is silenced, which is the likely cause of the false success; (c) kills whatever process owns port 3082 without checking it is dsh; (d) writes the tokenised URL to a file (with a UTF-8 BOM), the log and the clipboard; (e) the `Write-Host '…' + $PSCommandPath + '…'` hint prints mangled text. Also: the BOM in `superagent-url.txt` is what 5.1 writes, so the restart that produced it was not this file as saved | `restart-superagent.ps1`; BOM bytes `EF BB BF` | After kill, wait until the port is free **and** delete the log with a hard error; declare success only when `Test-NetConnection 127.0.0.1 -Port 3082` passes and the process is alive 10 s later; verify the owner's command line contains `dsh` |
| 7 | **Med** | **No version control.** The folder is not a git repo, yet another agent is editing it (`deployment.ts`, `paths.ts`, `policy.ts`, `tests/paths.spec.ts`, `docs/006-deployment.md`, `examples/profile.cordis.patch.yml`, `lib/*`, `restart-superagent.ps1`, profile configs). No diff, no rollback | `git` check; mtimes after `.setup-done` | `git init` and commit a baseline now (excluding `node_modules`, `.dsh`, `state`) |
| 8 | **Low–Med** | Superagent profile `package.json` was edited at 03:20 to add four experimental bundles (voice-input, plugin-market, auto-review, forge). The first-run script cannot reproduce that; a plugin-market bundle in a full-access profile widens the supply-chain surface. A stray `cordis.patch.yml.bak-before-mcp` is left behind | `.dsh/profiles/superagent/package.json` | Confirm you intended them; otherwise remove |
| 9 | **Low** | Windows file-permission semantics: the code relies on `mode: 0o700/0o600` for the state dir and database ("owner alone"); `chmod` is a no-op on NTFS, so protection is just the inherited folder ACL. `store.spec` fails for that reason (modes 438/438 vs 448/384). Current ACL on `.credentials.yaml` is inherited and tight enough for a single-user box (user, SYSTEM, Administrators) | `icacls`; `tests/store.spec.ts` | Document, or set an explicit ACL on win32 |
| 10 | **Low** | `Commands.run` forwards the full `process.env` (including `DEEPSEEK_API_KEY`) to `gh`/`git`/`lark-cli` children (`src/infra/commands.ts:70`) | source | Pass an allow-listed environment |
| 11 | **Low (upstream)** | Resume errors are flattened to `gateway/internal` (section 1) | `agent.ts:203-209` | Map `agent-preset/not-found` and `agent-preset/invalid` to their own error with an actionable message |
| 12 | **Low (upstream)** | Worker/router presets appear in the preset picker though marked "not for manual selection"; "a preset row has no setting that hides it" (`cordis.patch.yml:17-19`). That is how a personal session ended up with one | `cordis.patch.yml` comment | Hide from the picker, or add a "belongs to profile X" guard |
| 13 | **Info** | Full TypeScript typecheck has not completed anywhere on this machine (README: host aggregate OOM on the build VM; the other agent killed `tsc` after ~8 min). Edited TS is covered by tests and a successful `tsdown` build, not by a whole-project typecheck | `README-TEST.md`; session transcript | Run `tsc --noEmit` on a quiet machine |
| 14 | **Info** | DeepSeek model-list request timed out at 5 s and fell back to the bundled catalog; the machine was also running another project's dev server and vitest (`secscan-rebuild-test`) | restart log; process list | None; expect timeouts under load |

## 4. Verification results

| Check | Result |
| --- | --- |
| Superagent test suite (`vitest run`, 60 files) | **1,162 passed, 38 failed** (8 files). Engine and policy: `core-engine` 113/113, `policy` 328/328, `paths` 3/3 |
| Where the 38 failures are (per file) | `service-script` 15 and `commands` 1 (POSIX `sh` shim scripts, Windows exit 9009); `deployment` 5 (symlink `EPERM`, needs Developer Mode/admin); `environment` 6 (symlink `EPERM`, extensionless `gh` shim `ENOENT`, a `file:` path-quoting expectation); `sources` 6 (Feishu consumer fake-CLI scripts: `EPERM`/`ENOENT`); `docs` 3 (tests split paths on `/`); `store` 1 (POSIX file modes); `runtime` 1 (expected git-config text has unescaped backslashes) |
| What they indicate | Windows portability of tests and shims. I found no logic defect in the engine or policy; the shim and file-mode failures reflect real Windows gaps (findings 2 and 9) |
| Harness preset/resume tests (`agent-preset-registry`, `session-presets.host`, `continuation-presets`) | 99 passed, 2 failed — both `EPERM` symlink. The "Unknown agent preset" path is tested and behaves as designed |
| `lib/` currency | Newer than every source/test file. Built bundle carries the Windows-path rule |
| Plugin/core version compatibility | `engines.dsh ^0.2.1-alpha.2` vs core `0.2.2-rc.5`: passes, the harness checks with `includePrerelease: true` |
| README claim "component repos are not referenced at runtime" | Confirmed: no `package.json` references either |
| Superagent management HTTP | Host-header allow-list (`127.0.0.1:<port>` / `localhost`), custom request header and Origin check (`http.ts` `sameOrigin`): sound against DNS rebinding and cross-site calls. Body size capped at 128 KB |
| GitHub access path | Calls are confined to the configured repo; `..`, absolute and URL paths are rejected (`commands.ts` `path()`). CLI errors do not echo argv |
| `.env` / `.env.example` | Blank key. The key is in the Windows User environment variable and in the harness credential store |
| Dangerous-pattern sweep of `src/` | One `spawn` (Feishu consumer) and one `execFile` wrapper; no `eval`, `new Function`, `shell: true`. One TODO in 15,212 lines |

## 5. Recommended order

1. **Get session 7661 back (no code change):** start only the superagent server in a normal window — `cd src\deepseek-harness`, set `DSH_HOME` to this folder's `.dsh`, run `pnpm dsh --profile superagent --no-open` — then open the **new** tokenised 3082 URL (the one in `superagent-url.txt` is dead). Do not run `start-super-harness.bat`: 3080 already holds its port.
2. After it is up, confirm `Test-NetConnection 127.0.0.1 -Port 3082` and that `state\superagent\orchestrator.sqlite` appears.
3. `git init` and baseline commit (finding 7).
4. Fix `restart-superagent.ps1` (finding 6) before relying on it again.
5. Decide on the tailnet forward and the bridge token (findings 3–4) and on moving out of OneDrive (finding 5).
6. Before arming the superagent for real work: fix Windows shims (finding 2).

## 6. Scope and limits

- **Audited in depth:** the integration layer (launch scripts, both profiles, `.dsh` config/session/credential layout, logs), the `dsh-superagent` plugin (15 k lines of source, 15 k lines of tests, built `lib`), the preset registry and resume path in the harness.
- **Sampled only:** `deepseek-harness` is an upstream product (2,302 spec files, 2.7 GB with dependencies); I did not review it line by line, and I did not run its full suite.
- **Not audited:** `dsh-libreoffice-kit` and `dsh-node-addon-require-builtin` (unreferenced by the build), `node_modules`, the separate `secscan-rebuild-test` project, the AlterEgo bridge's own code.
- **Not done:** no server was started, so finding 2 is from source and test evidence, not a live worker run, and my account of the 04:03 restart (section 2, item 3) is an inference from timestamps and file contents.
