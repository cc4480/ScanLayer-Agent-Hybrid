# Deepseek super — test package

A self-contained DeepSeek super harness: the DeepSeek Harness core
(v0.2.2-rc.5) with the dsh-superagent prototype integrated as a profile
plugin, plus the two component repos (dsh-libreoffice-kit,
dsh-node-addon-require-builtin) under `src\` for completeness — the build
did not need them, nothing references them at runtime.

Verified working on the build VM before packaging: dependencies installed,
artifact build passed (8/8 gates), Web UI served on port 3080, superagent
service ran on port 3082 (process alive, port answering, state database
initialized). NOT yet verified on the build VM: the end-to-end smoke test
(key → DeepSeek → answer) has no receipt — the "2+2" test below is the
first check to run on this machine, and the Orchestrator panel's
per-subsystem "ready" readout was not confirmed firsthand either.

## Layout

```
Deepseek super\
  start-super-harness.bat   <- run this (or the .ps1)
  start-super-harness.ps1   <- same thing, PowerShell version
  README-TEST.md            <- this file
  .env.example              <- DEEPSEEK_API_KEY= (template)
  .env                      <- blank, ready for a key if you use that route
  .dsh\                     <- DSH_HOME on this machine (starts empty - see "API key")
  state\superagent\         <- superagent state database lives here
  src\
    deepseek-harness\           the harness core (source + built artifacts)
    dsh-superagent-prototype\   the superagent bundle (source + built lib)
    dsh-libreoffice-kit\        component repo (not used by the build)
    dsh-node-addon-require-builtin\  component repo (not used by the build)
```

## Prerequisites (Windows)

1. **Node.js 24** (current LTS line) — https://nodejs.org
2. **pnpm 11** — either `corepack enable` (ships with Node) or
   `npm install -g pnpm@11`
3. **Internet on the first run only** — setup downloads the npm
   dependencies. Later runs work offline except for the DeepSeek API
   itself.

## API key — how it is seated

The harness resolves the DeepSeek key in this order:

1. **Its own credential store**: `.dsh\.credentials.yaml` inside this
   folder (that folder is `DSH_HOME`). **This package ships WITHOUT that
   file on purpose** — Cho-zen1 seats the PC-side credential store
   personally after transfer. You can also add a key yourself after the
   first launch: open the Web UI, go to **Models**, and save the DeepSeek
   API key there (write-only; the UI never displays it back).
2. **Windows User environment variable** `DEEPSEEK_API_KEY` — already set
   on Cho-zen by Cho-zen1. The start script inherits it automatically
   (the .ps1 also reads the User store explicitly).
3. **`.env` file** in this folder — paste the key after
   `DEEPSEEK_API_KEY=` (the file ships blank; `.env.example` is the
   template).

## Run it

1. Put this folder where you want it to live (e.g. OneDrive Desktop).
   **Don't move it after the first run** — the superagent profile stores
   this folder's absolute path. If you do move it, delete `.setup-done`
   and `.dsh\profiles\superagent`, then run the script again.
2. Double-click **`start-super-harness.bat`**
   (or right-click `start-super-harness.ps1` → Run with PowerShell).
3. **First run only**: setup installs dependencies, builds any missing
   artifacts, creates the `superagent` profile in `.dsh\profiles`,
   links the superagent plugin into it, and writes its config
   (web port 3082, state under `state\superagent`). This takes a few
   minutes. A `.setup-done` flag file marks completion.
4. Two server windows open and stay open. Each prints a **tokenized
   URL** like `dsh web: http://127.0.0.1:3080/?token=...` — open THAT
   full URL in the browser (the bare address answers 401; the token in
   the printed URL signs you in).

## What success looks like

- **http://127.0.0.1:3080** — the DeepSeek Harness Web UI (default `web`
  profile): chat, sessions, Models page.
- **http://127.0.0.1:3082** — the same UI for the `superagent` profile.
  Open its **Orchestrator** panel: `relay`, `notice`, `launch`,
  `delivery`, `assessment`, `reply`, `evals` should report **ready** —
  that readout was not confirmed firsthand on the build VM, so check it
  here. The runtime starts **paused — "Waiting for the deployment check
  / The GitHub Source names no repository"**. That pause is expected: the
  superagent's operator setup (a dedicated GitHub agent account, a
  repository it may work in, the allowed GitHub users) is a deliberate
  human step — follow `src\dsh-superagent-prototype\SETUP.md` and
  `docs\006-deployment.md` in that folder when ready to arm it.

## One sample task to try

In the Web UI at port 3080, start a chat and send:

> What is 2+2? Reply with just the number, nothing else.

That is the first smoke test to run — it has NOT yet been verified on the
build VM, so if it answers `4`, that proves the key, the model route, and
the agent loop end to end. Then try a real one:

> List the files in this workspace and summarize what the Deepseek super
> package contains.

## Stopping

Close the two server windows (or Ctrl+C in each). State persists in
`.dsh\` and `state\` inside this folder.

## Notes / known limits

- Ports 3080 and 3082 must be free on this machine.
- The package was assembled on Linux; that is why first-run setup
  reinstalls `node_modules` natively instead of shipping them.
- On the build VM, the harness's *host aggregate typecheck*
  (`tsc -p tsconfig.host.json`, part of `build:check`) could not
  complete — the VM ran out of memory (OOM-killed) on repeated attempts,
  including a final retry with a 4 GB Node heap
  (`NODE_OPTIONS=--max-old-space-size=4096`, heap hit 4095.9 MB,
  exit 134 after ~214 s; see `host-agg-check4.log`).
  It is a test/script typecheck only; the artifact build (8/8 gates,
  exit 0) and the client aggregate check both passed, and the servers
  above ran from those artifacts.
