# reports/

Every document in this folder is generated from **two skills**. No exceptions.

| Skill | What it contributes |
|---|---|
| `web-scan-catalog` | The check set and each check's pass/fail oracle — what was run, and what "clean" means |
| `local-host-report` | The HTML template — 11 sections, ids, palette, motion, data appendix, JSON export |

**Flow**

1. Load both skills before writing anything.
2. Collect the data first: commands and raw output, not prose.
3. Copy `skills/local-host-report/assets/template.html` and replace content only.
4. Fill §2 from findings, §4 from the check run, §6–§8 from the raw captures, §11 from the dataset.
5. Render and QA (headless Edge, `--virtual-time-budget=4000`, 1400×15000): counters show real numbers, no mojibake, table/details/script tags balanced, JSON export matches the tables.
6. Commit here with the skill versions used.

**Naming:** `host-pentest-<HOST>-<YYYY-MM-DD>.html`

**Sanitization:** this repository is public. Reports committed here use placeholder
identities — `WORKSTATION-01`, `192.0.2.10`, `100.64.0.10`, `operator`, `peer-N`.
A report with real hostnames, LAN/tailnet addresses, account names or peer names stays
on the machine unless the user explicitly asks to publish it.

**Index**

| Date | Host | Platform | Findings | Skills | File |
|---|---|---|---|---|---|
| 2026-11-26 | WORKSTATION-01 | Windows 10 22H2 (19045.6456) | 3 Medium · 4 Low · 3 Info | `web-scan-catalog` @f0db975d · `local-host-report` @94b28c23 | [host-pentest-WORKSTATION-01-2026-11-26.html](host-pentest-WORKSTATION-01-2026-11-26.html) |

**Before you add a row:** re-read `local-host-report/SKILL.md` §"Non-negotiables" and
`web-scan-catalog` §"Ground rules". A report that changes the design, or marks a
skipped check as a pass, does not belong here.
