---
name: screen-capture
description: Take a screenshot the agent can actually read — the DSH window and its in-app Browser panel, the whole screen, or any URL rendered headlessly. Use when the user asks what the app/GUI looks like, when a panel appears blank or broken, when a report page must be eyeballed, or when visual proof is needed. Trigger phrases: "can you see the browser", "screenshot", "what does it look like", "the panel is blank", "show me the page".
---

# screen-capture

One script, three modes, always ends with a PNG that `read_image` can open.

```
tools\screenshot\capture.ps1
```

The agent has **no** direct view of the app: not the Web GUI, not the in-app
Browser panel, not the page inside it. This tool is the only way to see pixels.

## Run it

Always through Windows PowerShell (the `pwsh` tool here is 5.1; there is no pwsh 7):

```powershell
# the DSH window - chat, sidebar, and the in-app Browser panel
powershell -ExecutionPolicy Bypass -File C:\sh\seclayer-hybrid\tools\screenshot\capture.ps1 -Mode window -Match 'Chrome'

# match a narrower title when several windows compete
powershell -ExecutionPolicy Bypass -File C:\sh\seclayer-hybrid\tools\screenshot\capture.ps1 -Mode window -Match 'DSH Local Build'

# the whole primary screen
powershell -ExecutionPolicy Bypass -File C:\sh\seclayer-hybrid\tools\screenshot\capture.ps1 -Mode screen

# any URL, rendered headless at a chosen size (tall pages: raise -Height)
powershell -ExecutionPolicy Bypass -File C:\sh\seclayer-hybrid\tools\screenshot\capture.ps1 -Mode url -Url 'http://127.0.0.1:4710/r/<shareToken>' -Height 3000
```

It prints one JSON line: `{ok, mode, out, width, height, bytes, title, source}`.
Pass `out` straight to `read_image`. `source` tells you how the pixels arrived:

| source | meaning |
|---|---|
| `printwindow` | window captured while occluded — **no focus stolen** |
| `screen-region` | PrintWindow came back black, window brought forward and grabbed |
| `screen` | primary screen |
| `headless-edge` | URL rendered by a private Edge instance |

## Reading the result

- `-Mode window` shows exactly what the user sees, including the Browser panel's
  iframe content. This is the only mode that proves what the *panel* renders.
- `-Mode url` shows what the *server returns*, not what the panel shows. They can
  disagree — that is the point when a panel looks wrong.
- A blank panel with a `200` response is usually the framing headers, not a bug:
  `4700`/`4701` send `X-Frame-Options: DENY` + `frame-ancestors 'none'`. Only the
  proxy ports `4710`/`4711` render in an iframe.
- Check the returned `width`/`height`: a maximised window reports physical pixels,
  so a 150% DPI display gives roughly 1.5x the CSS size.

## Rules

- **Screenshots can contain secrets**: share tokens, keys, customer data, private
  chat. Keep them in `%TEMP%\dsh-shots\`, never in the repo, never in a commit,
  and do not paste one into a report.
- Do not use a screenshot as a substitute for the app's report — the app still owns
  the report. A screenshot is evidence about what is *displayed*, nothing more.
- `-Mode window` may briefly bring a window forward in the `screen-region` path.
  Say so if the user is mid-task.
- Do not screenshot another user's windows, and do not chain this into a loop.
