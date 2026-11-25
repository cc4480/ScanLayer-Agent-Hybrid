# Architecture and threat model

## Picture

```
 model / harness (any MCP client)
        │  POST /mcp   Bearer <seat token>        tools: search, execute — nothing else
        ▼
 ┌────────────────────────── gateway (host) ───────────────────────────┐
 │  search ── catalog.json (+ tool knowledge) ── typed stubs           │
 │  execute ─► sandbox child (one per run)                             │
 │               empty env · permission model · no codegen · netns     │
 │               vm context: tools / catalog / manifest / parse        │
 │                 │ IPC: one tools.x(args) at a time                  │
 │                 ▼                                                   │
 │             GATE  exists → not destructive → args → protected paths │
 │                   → scope (targets in argv vs self + engagements)   │
 │                 │            │ every decision                       │
 │                 │            └─► audit.log (hash chain) ─► seal     │
 └─────────────────┼────────────────────────────────────────────────────┘
                   │ TCP :7781 (QEMU hostfwd)   {"token","argv","timeout_ms"}
                   ▼
 ┌──────────── QNX 8.0 target (QEMU x86_64) ────────────┐
 │  qnx-runner: token · allowlist · fork/execve argv    │
 │              timeout (SIGKILL pgrp) · 40k cap        │
 │              spawn log (target-side proof)           │
 │  qnx-inventory (POSIX sh): tools, pidin, /dev, io-sock│
 └──────────────────────────────────────────────────────┘
```

Separately, Agent Smith's seat (`loop/smith.js`) is just another MCP client with its own token. It goes through the same gate and lands in the same chain.

## Where each property is enforced

| Property | Enforced by | Holds even if… |
|---|---|---|
| Model sees 2 tools | `server.js` `tools/list` | — |
| No network from programs | Linux: empty network namespace (OS). Everywhere: no network API in the vm context | vm escaped (Linux) |
| No host fs / processes from programs | Node permission model in the child, no `require` in the context | vm escaped |
| No `eval` / `Function` | context `codeGeneration: false`, and `--disallow-code-generation-from-strings` for the host realm | constructor-chain tricks |
| Out-of-scope targets never contacted | gate step 6, before the runner is called | sandbox fully compromised (the gate lives in the gateway process) |
| Destructive tools off | gate step 2, plus the runner allowlist, which lists callable tools only | gateway bypassed (the runner refuses) |
| Only the gateway can run things | runner token (network mode refuses to start without one) | — |
| History cannot be quietly edited | hash chain; gateway refuses to start on a broken chain | — |
| Findings are backed | report builder drops findings whose receipts are missing | a check lies |
| Findings are true | a different seat reproduces each one; board rejects verdicts from the author, without the lock, or without a real run | the runner seat lies |
| Engagements are the operator's | HMAC-SHA256 with `operator.key`; edits after signing invalidate | an agent edits `engagements.json` |

## Threats considered and out of scope

- **Prompt-injected model** trying to reach other hosts. It goes through the gate, gets `out_of_scope`, and the attempt is recorded.
- **Escape from the vm.** On its own docs, node:vm is not a boundary. The layers that hold after an escape are the child's process restrictions and the gate, which runs in a different process.
- **Fail-closed parsing.** For packet-sending tools, an argument the gate can't classify as a target is refused rather than guessed at. Hostnames are never resolved, since resolution is itself traffic.
- **Qnet.** On QNX, `/net/<node>/…` makes another node's resources local pathnames, so these paths count as network targets (`qnet:<node>` engagements).
- **Not covered:** a compromised host OS running the gateway, a malicious operator, physical access to the target, side channels. The stand-in's sandbox network denial depends on `unshare -n` (root on Linux). Elsewhere, network denial for programs relies on the absence of network APIs in the context, and the gateway reports which case applies (`/api/state` → `policy.sandbox.network`).

## Formats

- `catalog.json`: `qnx-agent.catalog.v1` (see `node-runtime/inventory-qnx.sh` header).
- `manifest.json`: `qnx-agent.manifest.v1`, the services, processes, components (with `cksum`), network and writable allowlists the image declares.
- Audit line: `{seq, ts, kind, seat, tool, decision, argv|argv_sha256, targets[], spawned, exit, stdout_sha256, …, prev, hash}` with `hash = sha256(prev + "\n" + canonical(entry without hash))`.
- Reports: `qnx-agent.report.v1`, ed25519 over canonical JSON; verify with `cli.js verify-report`.
