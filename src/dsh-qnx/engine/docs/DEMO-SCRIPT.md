# Demo video script (target 2:45, hard limit under 3:00)

English narration, no music. On screen: the DeepSeek Harness (its chat plus the QNX target and Scan & verify pages in its sidebar) and one terminal. Film on the **QNX 8.0 QEMU target** once Phase 0 lands. The identity bar then reads `QNX 8.0.0 on x86_64`. If any shot is filmed on the stand-in, the bar says "stand-in target, not QNX", and the narration must say so too.

| Time | Shot | Narration |
|---|---|---|
| 0:00–0:15 | Terminal: QEMU boots QNX 8.0; `qnx-runner started on 7781` | "This is QNX 8.0 in QEMU. The only thing we added is a small runner that executes argument lists, and nothing else." |
| 0:15–0:35 | Harness chat: "What's listening on the target?" → answer arrives; the QNX target page's gate tape shows `Allowed /usr/bin/netstat -an` | "The model sees two tools, search and execute. It wrote a program; the program called netstat on the target; only the answer came back." |
| 0:35–1:05 | Chat: "Ping 198.51.100.23." The tape shows red `Denied … out of scope — nothing spawned`. Split screen: `tcpdump` on the target shows nothing | "That address isn't the target, and nobody signed an engagement for it. The gate refused before anything ran: no process, no packet. The capture proves it." |
| 1:05–1:20 | Terminal: `cli.js engage add --id lab --target 198.51.100.0/24`; same chat prompt; the tape turns amber; tcpdump shows packets | "The operator signs an engagement. Same request, now it runs, and the capture sees it." |
| 1:20–1:50 | Scan & verify page: Run checks → findings table (rogue listener, rogue process, writable path, component drift); click a receipt → tape scrolls to it | "Five checks written for QNX compare the running system with its image manifest. Every finding points at the receipt that proves it." |
| 1:50–2:25 | Scan & verify page: post claims + planted false claims → Start Agent Smith → CONFIRMED / REFUTED / UNPROVEN fill in | "A second agent, with its own key, re-runs every claim on the target itself. The real ones are confirmed. The planted lies are refuted, or left unproven, and never reach the report." |
| 2:25–2:45 | Sign verified report; Scope & proof page: Verify chain → "Chain intact: N entries" | "Everything that happened is one hash chain, signed. Change a byte and it breaks. That's an agent you can let near a safety-critical system." |

Capture the receipts for every number on screen with `node scripts/prove.js qnx/config.json docs/receipts` in the same session.
