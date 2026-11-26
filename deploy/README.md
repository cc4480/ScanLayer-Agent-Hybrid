# Running this stack on any PC

The current setup only works on the machine it was built on: absolute paths
(`C:\sh\src\seclayer.io2026`), a machine-wide `DATABASE_URL` that had to be
cleared by hand, a key minted through a one-off HTTP call, and two Node
processes started manually.

None of that is necessary. **Both apps already ship a `Dockerfile` and a working
`docker-compose.yml`**, and both are designed to run as containers. The portable
answer is to compose their own images rather than to make a Node install
path-independent.

## The contract (what makes it portable)

| | SecLayer | SecScan |
|---|---|---|
| Host port | `127.0.0.1:4700` → container `3000` | `127.0.0.1:4701` → container `8080` |
| Durable state | named volume `/data` (SQLite) | named volume for Postgres 16 |
| Migrations | schema applies itself at boot | `docker compose --profile setup run --rm db-migrate` |
| Key to mint | `POST /api/keys` | API token from its own settings |
| Bind | loopback only | loopback only |

Fixed ports on loopback are the contract: the DSH bundles and the panel point at
`127.0.0.1:4700` / `127.0.0.1:4701` on every machine, so no per-machine config
is written into a plugin.

## Shape of the repository

```
apps/seclayer/      git submodule -> the SecLayer app
apps/secscan/       git submodule -> the SecScan app
deploy/bootstrap.ps1 one command: build, migrate, start, mint keys
.env.local          generated, gitignored: URLs + the two keys
```

Prefer submodules over copying: the apps stay versioned and updatable with
`git submodule update --remote`, and nothing drifts.

## One-time setup on a new PC

```powershell
git clone <this repo> ; cd <this repo>
git submodule update --init --recursive
docker desktop  # installed and running, that is the only prerequisite
pwsh -File deploy/bootstrap.ps1
```

`bootstrap.ps1` does, in order:

1. Verifies Docker and Node are present (fails with a clear message otherwise).
2. **SecLayer**: writes `apps/seclayer/.env` with `NODE_ENV=development`,
   `APP_URL=http://127.0.0.1:4700`, then `docker compose up -d --build` with the
   port override in `deploy/seclayer.ports.yml`. The SQLite fallback means no
   database to provision.
3. **SecScan**: generates `POSTGRES_PASSWORD` and `ENCRYPTION_KEY`, writes
   `apps/secscan/.env.docker` with `APP_ORIGIN=http://127.0.0.1:4701` and
   `APP_PORT=4701`, runs the migration profile, then brings the stack up.
4. Polls both health endpoints until they answer (or fails loudly with the
   container logs).
5. Mints the two keys through each app's own API and writes `.env.local` with
   `SECLAYER_API_KEY`, `SECLAYER_API_URL`, `SECSCAN_API_TOKEN`, `SECSCAN_API_URL`.

Then DSH reads those values at startup through `${credential:...}` — the same
mechanism already in the two bundles, unchanged.

## Opening everything at once (autostart)

Three tasks, two installers, all idempotent. Nothing here restarts a healthy
component: every step is guarded by a port test.

| Task | Installer | What it does |
|---|---|---|
| `SecLayer Hybrid Stack` | `install-autostart.ps1` | at logon **and every 5 min**: Docker Desktop, both scanner stacks, the view proxy (`stack-up.ps1`) |
| `SecLayer Stack Watch` | `install-autostart.ps1` | continuous 2 s health poll while the DSH web profile listens on `:3080`; restores the stack within seconds |
| `DSH Autostart` | `install-dsh-autostart.ps1` | at logon **+30 s**: the above, then the DSH `web` (`:3080`) and `superagent` (`:3082`) profiles if their ports are closed |

```powershell
pwsh -File deploy\install-autostart.ps1        # scanners + watcher
pwsh -File deploy\install-dsh-autostart.ps1    # + DSH profiles  (-Uninstall to remove)
```

DSH liveness is decided by **port**, not URL: both profiles answer `401` on `/`
when they are perfectly healthy, so a URL probe would start a second copy
against a bound port. Logs: `.dsh\dsh-autostart.log`, plus
`.dsh\dsh-web.out.log` and `.dsh\dsh-superagent.out.log` for the profile output.

Two related settings in `.dsh\profiles\web\cordis.patch.yml` (machine-local,
effective at the next DSH start):

- `reconnect.maxAttempts: 1000` on both MCP rows. The client default is 10
  attempts at 0.5 s→30 s (~2.5 min), after which the section drops its tools for
  the rest of the session — longer than a `docker restart` of one scanner, but
  not longer than "Docker Desktop was closed while I made coffee".
- Those MCP rows exist **only in the `web` profile**. The `superagent` profile
  (the `:3082` GUI) has no MCP sections, so its app access is the fallback tools
  plus the API tokens in `.env`.

## Why containers, and what the alternative costs

| Option | Works on any PC | Cost |
|---|---|---|
| **Docker Compose (recommended)** | Yes — Windows/macOS/Linux identical | Docker Desktop must be installed; ~1–2 GB images |
| Node install per machine | Mostly | Needs Node 22 + pnpm; SecScan still needs Postgres; Windows path and `DATABASE_URL` collisions recur (we hit both) |
| Their Railway/Vercel configs | No | Cloud deployment, not "on any PC" |

## What is still machine-specific today, and must be removed

1. `plugins/seclayer-mcp/cordis.patch.yml` hardcodes
   `C:\sh\src\seclayer.io2026\mcp-server\dist\index.js`. Portable replacement:
   `npx -y @seclayer/mcp` (the published package) — the same server, versioned,
   no path. It must be re-tested once the credentials provider is in place,
   because the earlier "npx produced nothing" result was caused by the missing
   `inject: ['credentials']`, not by npx.
2. `plugins/seclayer-panel/client.js` hardcodes `127.0.0.1:4700`. Fine once the
   port is the contract above; switch to 4701 for the SecScan panel.
3. The local `.env` files carry a hand-minted key and
   `ALLOW_UNVERIFIED_ACTIVE_PROBES=true`. In the container layout the key is
   generated by `bootstrap.ps1` and the operator switch stays a deliberate
   local-only setting.

## Untested here

Docker is **not installed on this machine**, so none of the above has been
executed. The compose files it composes are the apps' own, unmodified; the
overrides only add a loopback port mapping. Treat `bootstrap.ps1` as a first
draft to run on a machine with Docker before relying on it.
