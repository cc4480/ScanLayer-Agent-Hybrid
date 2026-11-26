# ScanLayer Agent Hybrid: joined workspace

This repo is the base for the hybrid agent. The base is `deepseek-super`.

## What is in it

| Path | What |
|---|---|
| `src/deepseek-harness/` | DeepSeek agent harness (MIT). |
| `src/dsh-redteam-gate/` | Verified-scope gate and the agent scan tools. |
| `src/dsh-redteam-gate/src/engines/vibescan-core/` | Verbatim VibeScan scan core (Apache-2.0). |
| `src/dsh-redteam-gate/src/engines/seclayer-core/` | Verbatim SecLayer scan core (proprietary). |

## Provenance

The scan cores were copied byte-for-byte from `cc4480/VibeScan-Enterprise-Build` (master, `50b7e2ba`) and
`cc4480/seclayer.io2026` (main, `0610d36a`). Their history stays in those repos. The `modules/` folders that
held the original copies were removed in this repo once the verbatim copies were verified.

## Agent tools

| Tool | Engine | Gate |
|---|---|---|
| `webapp_scan` | VibeScan `runScan` | Ownership check, then per-request gate |
| `seclayer_scan` | SecLayer `runDiagnostics` | Ownership check, then per-request gate |
| `secscan_fetch` | VibeScan `scanFetch` | Per-request gate |
| `seclayer_probe` | SecLayer red-team probes | Per-request gate |

See `src/dsh-redteam-gate/TEST-SCAN-CORES.md` for how to run the test suites.
