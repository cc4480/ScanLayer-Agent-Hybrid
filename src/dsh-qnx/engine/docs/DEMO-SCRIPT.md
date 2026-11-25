# Demo video script (target 2:45, hard limit under 3:00)

English narration, no music. On screen: the DeepSeek Harness with the **QNX target** page open (gate tape on the left), and a terminal running the demo driver, which prints each caption as it acts.

```sh
# 1. start the app (QNX target after Phase 0; stand-in before it)
sh start-qnx.sh                      # Windows: powershell -ExecutionPolicy Bypass -File start-qnx.ps1
# 2. stand-in only: give the checks something real to find (skip on QNX)
sh src/dsh-qnx/engine/scripts/plant-standin-faults.sh
# 3. start recording, then:
node src/dsh-qnx/engine/scripts/demo.js src/dsh-qnx/engine/qnx/config.json          # stand-in: .../standin/config.json
#    Enter advances each step; --auto 12 paces it for a hands-free take
```

Film on the **QNX 8.0 QEMU target**, once Phase 0 has run. The identity bar then reads `QNX 8.0.0 · x86_64`. Anything filmed on the stand-in shows "stand-in target, not QNX", and the narration must say so. The zero-packets count needs `tcpdump` on a Linux or WSL host; on Windows, say "nothing spawned" and let the tape show it.

| Time | Driver step | On screen | Narration |
|---|---|---|---|
| 0:00–0:12 | (start) | Harness, QNX target page: identity bar, "destructive tools: off" | "This is QNX 8.0 in QEMU, driven by an AI agent through the DeepSeek Harness." |
| 0:12–0:30 | 1, 2 | Tape: `Allowed /…/netstat -an` | "The model sees two tools, search and execute. It found netstat, wrote a program, and only the answer came back." |
| 0:30–0:55 | 3 | Tape turns red: `Denied … out of scope — nothing spawned`; terminal: `packets: 0` | "Now it reaches for a host nobody approved. The gate refuses before anything runs: no process, and the packet capture shows zero packets." |
| 0:55–1:15 | 4 | Terminal: engagement signed; tape: same call allowed; `packets: 3` | "The operator signs an engagement for that network. The identical call now runs, and the capture sees it." |
| 1:15–1:25 | 5 | Tape: `Denied … destructive` | "Destructive commands are off by default on a safety-critical OS, or set to ask you every time." |
| 1:25–1:55 | 6 | Scan & verify page; terminal: findings incl. **qconn** | "Six checks written for QNX compare the running system with its image. This one found qconn, QNX's developer agent, which no shipped image should run." |
| 1:55–2:25 | 7 | Terminal: CONFIRMED / REFUTED / UNPROVEN; tape: verdicts | "A second agent with its own key re-runs every claim on the target. Real findings are confirmed; the three planted lies are refuted or unproven." |
| 2:25–2:35 | 8 | Open the verified report page | "Only confirmed findings reach the signed report." |
| 2:35–2:50 | 9 | Terminal: original intact, copy broken at line N | "Everything is one hash chain. Change one byte and verification names the line. An agent you can let near a safety-critical system." |

Keep the receipts from the same session with `node src/dsh-qnx/engine/scripts/prove.js <config> src/dsh-qnx/engine/docs/receipts`, so every number in the video has a source.
