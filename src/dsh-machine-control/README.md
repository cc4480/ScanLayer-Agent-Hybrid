# dsh-machine-control

Local machine administration for DeepSeek Harness on Windows: four sidebar entries and eleven agent tools that act on
this machine.

## What it adds

Four entries in the left sidebar, each opening its own page in the main column:

| Entry | Page |
|:--|:--|
| Machine console | Host facts, drives, and every other area as a tab |
| Processes & services | Processes, services, startup items, installed applications |
| Network & security | Adapters and listeners, security posture, disks |
| Quit DSH | Writes the plan a hook applies after DSH exits |

Eleven tools for the agent: `machine_shell`, `machine_sysinfo`, `machine_process`, `machine_service`,
`machine_scheduled_task`, `machine_network`, `machine_security`, `machine_packages`, `machine_disk`,
`machine_maintenance` and `machine_event-logs`. They run PowerShell through the Harness subprocess seam and share the
queries the panels use, so a command or change is reachable from both.

## Elevation

A change that needs administrator rights takes an `elevate` argument. It first asks through the approval service, then
runs through `Start-Process -Verb RunAs`, so the user also accepts the Windows UAC prompt. Nothing runs when either step
is refused.

## The quit plan

A one-shot plugin cannot run a multi-hour job, so the Quit page writes
`%LOCALAPPDATA%\dsh-machine-control-quit.json` instead of acting immediately. A DSH hook runs

```sh
dsh-machine-control apply-plan "%LOCALAPPDATA%\dsh-machine-control-quit.json"
```

after DSH exits. The file's `action` is one of `reboot`, `shutdown`, `logoff`, `reboot-update`, `explorer` or
`flush-dns`; `name` and `delaySeconds` are optional. An unreadable or invalid plan is deleted rather than retried.

## Configuration

Set on the bundle's row in `cordis.patch.yml`; every field has a default:

| Field | Default | Meaning |
|:--|:--|:--|
| `sandbox` | `danger-full-access` | Sandbox mode reported to callers |
| `cwd` | the process directory | Directory a command without its own runs in |
| `timeoutMs` | `60000` | Default command deadline |
| `maxTimeoutMs` | `1800000` | Largest deadline a tool call may ask for |
| `maxOutputChars` | `60000` | Largest output a tool reports |
| `rowCap` | `300` | Largest rows a panel keeps per table |
| `maxBodyBytes` | `262144` | Largest accepted panel API request body |
| `tools` | `true` | Register the agent tools |
| `guide` | `true` | Add the machine catalog to the system prompt |

## Panel actions

The pages are not read-only. The Process list offers **End** per row; Services offers **Start**, **Stop** and **Restart**
per row; Disk offers **Delete temporary files**; Security offers **Start a quick scan**; Network offers **Clear the DNS
cache**. Every one of them calls the same command builder the matching agent tool uses (`src/host/actions.ts`), so the
page and the model can never drift apart. A change asks for confirmation first, shows the command's output in the panel,
then re-reads the table.

## Panel API

The pages read `GET /machine-control/api/status` and `GET /machine-control/api/page/<page>`, write
`POST /machine-control/api/quit-plan`, and act through `POST /machine-control/api/action` with `{ "op": "...", "params":
{ } }`. The operation list is closed (`PANEL_OPERATIONS`): a request naming anything else is refused, so the route is not
a general command runner. The route is owner-only (`auth: 'required'`) and additionally refuses a request whose `Host` or
`Origin` does not name this page.

## Limitations

- Windows only: every script is PowerShell and the elevation path uses `Start-Process -Verb RunAs`.
- Panel actions run without elevation. A change that needs an administrator (most service start/stop, Defender scans)
  reports the refusal the command gives; use the agent tools with `elevate` for those.
- `machine_disk usage` is bounded: it gives up after 40 s overall and 8 s per folder and says what it left unmeasured, so
  the sizes it reports can be lower bounds.
- Defender exposes no supported way to cancel a scan, so there is no cancel action.
- A tool call reports text. Long tables are capped by `rowCap` and `maxOutputChars`.
