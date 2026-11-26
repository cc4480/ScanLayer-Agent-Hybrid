---
name: local-host-report
description: >-
  The canonical HTML report template for local-machine pentests (Windows, Linux, iOS/iPadOS) — exact section order, visual system, animations, data tables and JSON export. Load before writing any host report; replace content only, never restyle or reorder.
  Trigger phrases: "scan this machine", "pentest this box", "audit my laptop", "host report", "local machine report", "Windows/Linux/iOS report", "make a security report for this PC", "where is the host report".
---

# Local host report — the one template

Every local-machine assessment produces **one self-contained HTML file** in this
template. The template is `assets/template.html` (a real, complete report); copy it,
replace the content, never the design.

The apps own web-scan reports. This skill owns **host** reports — Windows, Linux,
iOS/iPadOS — where no app produces the artifact.

`assets/template.html` ships **sanitized example data** (`WORKSTATION-01`, `192.0.2.10`,
`100.64.0.10`, `operator`): the structure is the specification, the values are
placeholders. This repo is public — never commit a report containing real hostnames,
LAN/tailnet addresses, account names or peer names. Finished reports stay local unless
the user explicitly asks to publish one.

## Non-negotiables

1. **Same 11 sections, same order, same ids.** Do not add, drop, merge or reorder.
2. **Same visual system.** Palette, type scale, shadows, radii, animation timing are
   part of the report's identity, not a per-report choice.
3. **Content only.** Text, numbers, table rows, finding cards, code blocks change.
   CSS, JS, markup patterns and section anchors do not.
4. **Every claim carries evidence.** Each finding has Component / Evidence / Why it
   matters / Impact / Fix, plus "Proof & raw output" and "Verify the fix".
5. **Never a pass for a skipped check.** Use the Not tested pill and the §11.18 list.
6. **One file, no network.** No CDN, no external fonts, no images. It must open from
   disk and print to PDF unchanged.

## Section manifest (fixed)

| # | id | Heading | Must contain |
|---|---|---|---|
| 1 | `verdict` | Verdict | 5 severity cards (counts), radial gauge with the posture number, 3–4 sentence verdict, one-line headline risk |
| 2 | `findings` | Findings | One card per finding, severity spine, dl of 4–6 rows, two `<details>` (proof, verify) |
| 3 | `paths` | Attack paths | One panel per Medium+ chain: `.path` steps with `.arrow`, and the step that breaks it |
| 4 | `checks` | All N checks | Expand-all toolbar, one `<details class="grp">` per group: commands pre + result table |
| 5 | `timeline` | Timeline | 6–8 rows: time, phase |
| 6 | `evidence` | Evidence | Listeners table, reachability matrix (colour-coded), firewall rules pre, coverage bar |
| 7 | `raw` | Raw output | One `<details>` per command: command pre + output pre, verbatim |
| 8 | `remediation` | Remediation, in order | Numbered panels: action, addresses, time, risk of the change |
| 9 | `platforms` | Platform coverage | 3 cards: Windows / Linux / iOS with honest status |
| 10 | `method` | Method | Bullets: what was read-only, what was deliberate |
| 11 | `data` | Complete data set | 18 subsections (11.1–11.18) + embedded JSON + Download JSON |

## Component contract

- **Severity pills**: `.pill.medium`, `.pill.low`, `.pill.info`, `.pill.pass`, `.pill.nt`.
- **Finding card**: `<div class="finding {sev} reveal">` with `.fh` (id, pill, title) and
  `.fb` (dl.kv, details).
- **Key/value rows**: `<dl class="kv"><dt>Label</dt><dd>value</dd></dl>` — 132px label column.
- **Code**: always `<pre>` for commands and output, `<code>` inline. Escape `<` and `>`.
- **Checks**: `<details class="grp">` with summary row and a table whose last column is the
  evidence note; result cells use the pills above.
- **Data appendix**: each subsection is an h3 `11.N Title` + table or pre; finish with the
  export panel: `<button id="dl">Download JSON</button>`.
- **JSON export**: `<script type="application/json" id="rawdata">` holding the full dataset,
  then the 6-line script that Blobs it to `<HOST>-<YYYY-MM-DD>.json`. Keep both.

## Visual system (do not change)

- Dark: bg `#05070d`, panels `rgba(18,26,46,.72)`, lines `rgba(90,169,255,.14)`,
  text `#e6edf9`, muted `#8fa0bf`; accents `#5aa9ff` / `#8b5cf6`; severity
  `#ff5d6c` / `#ffb84d` / `#ffd166` / `#7cc4ff` / `#39d98a`.
- Motion: hero gradient drift (18s), pulse dot, scroll-progress bar, sticky blurred nav
  with active state, `.reveal` fade-up on intersection, card hover lift + glow, finding
  hover raise, counter `pop` (scale, staggered 0.05–0.33s) — **not** a count-up.
- Shadows: `0 24px 60px -20px rgba(0,0,0,.85)`, glow `0 0 0 1px rgba(90,169,255,.18)`.
- Print: white background, no nav/progress, reveal shown, code on `#f5f5f5`.
- Breakpoints: 900px — cards to 2 columns, grids to 1.

## Data contract per platform

| Platform | §4 groups | §11 emphasis |
|---|---|---|
| Windows | Host & identity, Network exposure, Service hardening, Local security posture, Secrets, Local web surfaces, Judgement calls | listeners (42), firewall rules, SSH/SMB/PG, accounts, Defender, KBs, ACLs, Tailscale, containers |
| Linux | Host & identity, Network exposure, SSH/daemons, PAM/sudo, Filesystem & SUID, Packages/CVEs, Secrets, Containers, Judgement calls | `ss -lntup`, nft/ufw, sshd -T, sudoers, SUID sweep, LUKS, AIDE |
| iOS/iPadOS | Device posture, Supervision/MDM, Passcode & biometrics, Data protection, App entitlements, Profiles, Network, Backup, Judgement calls | supervision, jailbreak indicators, protection classes, profiles, OS support |

Keep the same 11 top-level sections for all three; only the group names and table
columns inside §4/§11 change.

## One command

```powershell
powershell -ExecutionPolicy Bypass -File tools\host-report\new-report.ps1 `
  -HostName WORKSTATION-01 -Platform windows -Date 2026-11-26 `
  -Os "Windows 11 Pro 24H2" -Build "10.0.26100" -Addresses "192.0.2.10 / 100.64.0.10" `
  -Posture 62 -Critical 0 -High 0 -Medium 3 -Low 4 -Info 3 -Checks 65
```

Scaffolds `reports/host-pentest-<HOST>-<DATE>.html` from the template: hero, counters,
gauge, summary, footer and the embedded JSON host are substituted; markup is validated;
a preview is rendered. `-Platform linux|ios` switches the label and OS defaults;
`-SkipRender` skips the screenshot. It never invents findings — you still fill §2, §4,
§6–§8 and §11 from real captures.

## Fill procedure

1. Load `web-scan-catalog` (checks) and this skill (format).
2. Collect the data first — commands and raw output, not prose.
3. Copy `assets/template.html` to `host-pentest-<HOST>.html`.
4. Replace the hero: host, OS/build, window, address, counts.
5. Replace §1 numbers and the gauge value (posture 0–100).
6. Replace §2 with the findings, most severe first; delete unused cards.
7. Rebuild §3 from the Medium+ findings only.
8. Rebuild §4 groups from the actual run; keep pass/finding/info/nt honest.
9. Rewrite §6–§8 from the raw captures; §9 status per platform.
10. Rebuild §11 and its JSON from the same dataset object — they must match.
11. Render and check (below), then hand the file over.

## QA before delivering

```powershell
msedge --headless=new --disable-gpu --no-first-run --hide-scrollbars \
  --virtual-time-budget=4000 \
  --window-size=1400,15000 --screenshot=preview.png "file:///<path>.html"
```

- Counters show the real numbers (no mid-animation values).
- No mojibake (`Â·`, `â€”`) — the file must be written UTF-8 **without BOM**, and never
  round-trip it through a legacy-encoding shell read.
- `<table>`/`</table>`, `<details>`/`</details>`, `<script>`/`</script>` counts match.
- Every finding has both details blocks; every raw block shows a real command.
- Nav links resolve; JSON download produces a valid file.
- §11 numbers equal the tables and the JSON.

## Anti-patterns

- A second visual style "because this report is different" — no.
- Markdown where the template has cards/tables — no.
- Quoting a command you did not run, or an output you did not capture — no.
- Green "Pass" on anything admin-gated or skipped — no.
- A JSON export that disagrees with the visible tables — no.
