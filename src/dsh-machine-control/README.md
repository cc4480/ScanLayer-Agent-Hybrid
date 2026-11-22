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

## Panel API

The pages read `GET /machine-control/api/status` and `GET /machine-control/api/page/<page>`, and write
`POST /machine-control/api/quit-plan`. The route is owner-only (`auth: 'required'`) and additionally refuses a request
whose `Host` or `Origin` does not name this page.

## Limitations

- Windows only: every script is PowerShell and the elevation path uses `Start-Process -Verb RunAs`.
- The panels read; they do not offer change controls beyond the quit plan. Use the agent tools for changes.
- A tool call reports text. Long tables are capped by `rowCap` and `maxOutputChars`.
