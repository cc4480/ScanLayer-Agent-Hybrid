# AlterEgo tool inventory

Source: `C:\Users\Cho-zen\alterego` (commit 49f25d3). Catalog: `docs/tools.md`.

Count: **109 tools** = 104 wrappers in `pc-agent/tool_wrappers.py` `ALL_TOOLS` (verified by import, 104 unique names) + 5 job-layer ops registered in `pc-agent/server.py` (`submit_job`, `job_status`, `job_result`, `job_cancel`, `doctor_jobs`). This matches the claimed 109.

Risk tags: `read` (no state change), `write` (changes files, clipboard, settings or bridge state), `exec` (runs commands, processes or scripts), `network` (touches a network or a browser session), `input-control` (sends mouse, keyboard or UI input).

Tier is the bridge's approval tier from `pc-agent/tool_profiles.py`: `silent` (no dialog), `routine` / `ask` (Yes/No dialog on the PC), `always_ask` (DESTRUCTIVE dialog, always).

Status: **ALLOWLISTED** = registered as a native tool in this pass (10). **DEFERRED** = not registered. The reason is in `allowlist.mjs` (`DEFERRED`).

| # | Tool | Purpose | Risk tags | Tier | Status |
|---|---|---|---|---|---|
| 1 | screenshot | Capture primary monitor as PNG | read | silent | ALLOWLISTED |
| 2 | list_windows | List visible windows | read | silent | ALLOWLISTED |
| 3 | system_info | OS, host, user, CPU, memory | read | silent | ALLOWLISTED |
| 4 | list_dir | List a directory (profile-restricted) | read | silent | ALLOWLISTED |
| 5 | read_file | Read UTF-8 file <= 1 MB (profile-restricted) | read | silent | ALLOWLISTED |
| 6 | clipboard_get | Read clipboard text | read | silent | DEFERRED (secrets) |
| 7 | memory_recall | Search on-PC memory archive | read | silent | DEFERRED (personal data) |
| 8 | search_files | Regex content search under a dir | read | silent | ALLOWLISTED |
| 9 | search_filenames | Glob filename search under a dir | read | silent | ALLOWLISTED |
| 10 | read_file_range | Read a 1-indexed line range | read | silent | ALLOWLISTED |
| 11 | focus_window | Bring a window to foreground | input-control | routine | DEFERRED |
| 12 | close_window | Close a window gracefully | input-control, write | ask | DEFERRED |
| 13 | type_text | Type into focused window | input-control | ask | DEFERRED |
| 14 | shell_exec | Run cmd.exe command | exec | always_ask | DEFERRED (EXEC, owner approval) |
| 15 | hotkey | Send a key combo | input-control | routine | DEFERRED |
| 16 | mouse_move | Move cursor | input-control | silent | DEFERRED |
| 17 | mouse_click | Click at coordinates | input-control | routine | DEFERRED |
| 18 | mouse_scroll | Scroll wheel | input-control | routine | DEFERRED |
| 19 | uia_find | Find UI elements via UI Automation | read | silent | DEFERRED |
| 20 | uia_click | Click a UI element | input-control | routine | DEFERRED |
| 21 | uia_set_text | Set UI element text | input-control, write | ask | DEFERRED |
| 22 | desktop_state | Windows, focus, UI elements, screenshot | read | silent | DEFERRED |
| 23 | wait_for | Poll for window, element or text | read | silent | DEFERRED |
| 24 | minimize_window | Minimize a window | input-control | routine | DEFERRED |
| 25 | maximize_window | Maximize a window | input-control | routine | DEFERRED |
| 26 | kill_process | Terminate a process by PID | exec, write | always_ask | DEFERRED (EXEC) |
| 27 | clipboard_set | Replace clipboard text | write | routine | DEFERRED |
| 28 | paste_text | Paste into focused window | input-control | ask | DEFERRED |
| 29 | write_file | Create or overwrite a file | write | always_ask | DEFERRED |
| 30 | edit_file | Replace text in a file | write | ask | DEFERRED |
| 31 | delete_file | Delete a file | write | always_ask | DEFERRED |
| 32 | create_dir | Create a directory | write | ask | DEFERRED |
| 33 | copy_file | Copy a file | write | ask | DEFERRED |
| 34 | move_file | Move or rename a file | write | ask | DEFERRED |
| 35 | file_info | Size and timestamps (any path) | read | silent | DEFERRED (not profile-restricted) |
| 36 | browser_snapshot | List elements of live Edge tab | read, network | silent | DEFERRED |
| 37 | browser_navigate | Navigate Edge tab | network, input-control | routine | DEFERRED |
| 38 | browser_click | Click element in Edge tab | input-control, network | ask | DEFERRED |
| 39 | browser_fill | Fill form field in Edge tab | input-control, write, network | ask | DEFERRED |
| 40 | browser_eval | Run JavaScript in Edge tab | exec, network | always_ask | DEFERRED (EXEC) |
| 41 | cdp_launch | Launch Chrome on presentation profile | exec, network | ask | DEFERRED (EXEC) |
| 42 | cdp_connect | Attach to Chrome debug port | network | routine | DEFERRED |
| 43 | cdp_targets | List CDP page targets | read, network | silent | DEFERRED |
| 44 | cdp_navigate | Navigate CDP tab | network | routine | DEFERRED |
| 45 | cdp_snapshot | Interactive elements in CDP tab | read, network | silent | DEFERRED |
| 46 | cdp_click | Click element in CDP tab | input-control, network | ask | DEFERRED |
| 47 | cdp_type | Type into CDP field | input-control, network | ask | DEFERRED |
| 48 | cdp_evaluate | Run JavaScript in CDP tab | exec, network | always_ask | DEFERRED (EXEC) |
| 49 | cdp_readback | URL, title, ready state | read, network | silent | DEFERRED |
| 50 | cdp_close | Close Chrome session | write | routine | DEFERRED |
| 51 | shell_pwsh | Run PowerShell script | exec | always_ask | DEFERRED (EXEC) |
| 52 | batch | Run up to 20 tool calls | exec | always_ask | DEFERRED (EXEC) |
| 53 | exec_background | Start background shell command | exec | always_ask (no profile) | DEFERRED (EXEC) |
| 54 | exec_status | Poll background job | read | silent | DEFERRED |
| 55 | exec_cancel | Kill background job tree | exec | routine | DEFERRED |
| 56 | http_headers | GET URL, return headers | network | ask | DEFERRED |
| 57 | dns_query | Raw DNS query | network | ask | DEFERRED |
| 58 | tls_info | TLS version and certificate | network | ask | DEFERRED |
| 59 | tcp_check | TCP connect check | network | ask | DEFERRED |
| 60 | web_fetch | Fetch URL as readable text | network | ask | DEFERRED |
| 61 | web_search | Web search | network | ask | DEFERRED |
| 62 | active_window | Foreground window | read | silent | ALLOWLISTED |
| 63 | idle_seconds | Seconds since last input | read | silent | DEFERRED |
| 64 | list_processes | Running processes (pid, exe) | read | silent | ALLOWLISTED |
| 65 | notify | Tray balloon notification | write | routine | DEFERRED |
| 66 | speak | Speak text aloud | write | routine | DEFERRED |
| 67 | record_audio | Capture microphone audio | read | always_ask | DEFERRED (sensitive) |
| 68 | set_volume | Set master volume | write | routine | DEFERRED |
| 69 | power | Lock, sleep, restart, shutdown | exec | always_ask | DEFERRED (EXEC) |
| 70 | task_create | Create signed task record | write | silent | DEFERRED |
| 71 | task_checkpoint | Append signed checkpoint | write | silent | DEFERRED |
| 72 | task_status | Verify and list task records | read | silent | DEFERRED |
| 73 | arbitrate_tool | Rank tool sequences by risk | read | always_ask (no profile) | DEFERRED |
| 74 | doctor | Bridge health check | read | silent | DEFERRED |
| 75 | query_events | Search operation log | read | silent | DEFERRED |
| 76 | replay_session | Causal transcript of a session | read | silent | DEFERRED |
| 77 | server_reload | Restart bridge server | exec | ask | DEFERRED (EXEC) |
| 78 | supervisor_status | Supervisor state | read | silent | DEFERRED |
| 79 | hot_reload | Reload bridge behavior | exec | routine | DEFERRED (EXEC) |
| 80 | search_tools | Keyword search of tool catalog | read | silent | DEFERRED |
| 81 | complete_arg | Complete argument values from live state | read | silent | DEFERRED |
| 82 | elicit_input | Ask a structured question | write | silent | DEFERRED |
| 83 | answer_elicitation | Answer a pending elicitation | write | silent | DEFERRED |
| 84 | list_elicitations | List elicitations | read | silent | DEFERRED |
| 85 | watch_path | Register file watch | write | silent | DEFERRED |
| 86 | unwatch_path | Drop file watch | write | silent | DEFERRED |
| 87 | list_watches | List watches | read | silent | DEFERRED |
| 88 | poll_changes | Read change journal | read | silent | DEFERRED |
| 89 | dashboard | Bridge status summary | read | silent | DEFERRED |
| 90 | tool_finder | Find tools by keyword | read | silent | DEFERRED |
| 91 | mouse | Mouse, multi-op wrapper | input-control | routine | DEFERRED |
| 92 | keyboard | Keyboard, multi-op wrapper | input-control | ask | DEFERRED |
| 93 | window | Window management, multi-op | input-control, write | ask | DEFERRED |
| 94 | uia | UI Automation, multi-op | input-control, read | ask | DEFERRED |
| 95 | file | File ops, multi-op | read, write | always_ask | DEFERRED |
| 96 | process | Process list or kill, multi-op | read, exec | always_ask | DEFERRED |
| 97 | browser | Edge tab, multi-op | exec, network, input-control | always_ask | DEFERRED |
| 98 | cdp | Chrome CDP, multi-op | exec, network, input-control | always_ask | DEFERRED |
| 99 | clipboard | Clipboard get or set, multi-op | read, write | routine | DEFERRED |
| 100 | exec | Shell execution, multi-op | exec | always_ask | DEFERRED (EXEC) |
| 101 | macro_record | Record named tool-call macro | write | routine | DEFERRED |
| 102 | macro_list | List macros | read | silent | DEFERRED |
| 103 | macro_replay | Replay macro | exec | always_ask | DEFERRED (EXEC) |
| 104 | macro_delete | Delete macro | write | routine | DEFERRED |
| 105 | submit_job | Journal and run a tool call in background | exec | (wraps any tool) | DEFERRED (EXEC) |
| 106 | job_status | Job state and progress | read | silent | DEFERRED |
| 107 | job_result | Job result | read | silent | DEFERRED |
| 108 | job_cancel | Cancel a job, kills its process tree | exec | silent | DEFERRED |
| 109 | doctor_jobs | Job infrastructure health | read | silent | DEFERRED |

## Totals

- Claimed in README and docs: 109. Found: 109 (104 wrappers + 5 job ops).
- Read-only tools in this inventory: 10 allowlisted. Other read tools are deferred for a reason in `allowlist.mjs`.
- Every EXEC tool is deferred: `shell_exec`, `shell_pwsh`, `exec`, `exec_background`, `batch`, `submit_job`, `macro_replay`, `power`, `kill_process`, `process`, `browser_eval`, `cdp_evaluate`, `cdp_launch`, `server_reload`, `hot_reload`, `browser`, `cdp`.
- Two tools (`exec_background`, `arbitrate_tool`) have no entry in `pc-agent/tool_profiles.py`, so they fall back to `always_ask`. The docs say so, and it is worth noting for the owner.
- `docs/tools.md` has a stale note ("verified live at 77 tools" in the CDP section). Counts above are from the code, not that note.
