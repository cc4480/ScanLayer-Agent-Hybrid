# SecLayer Hybrid — joined workspace

This repo joins three existing repos into one tree. The base is `deepseek-super`;
the other two sit under `modules/`.

| Path | Source repo | Source commit |
|---|---|---|
| `/` (root, incl. `src/`, `skills/`, git history) | `cc4480/deepseek-super` | `e62e1dd3` (main) |
| `modules/vibescan-enterprise/` | `cc4480/VibeScan-Enterprise-Build` (Apache-2.0) | `50b7e2ba` (master) |
| `modules/seclayer/` | `cc4480/seclayer.io2026` (no LICENSE file) | `0610d36a` (main) |

## How the join was made

- Modules were copied in as plain trees (no `.git` directories) and committed
  under `modules/`. Their upstream history stays in their original repos; the
  commit SHAs above are the exact snapshot joined.
- The root clone is shallow (`--depth 1`), so only the joined snapshot is
  present, not the full deepseek-super history.
- Nothing in the three repos was rewritten. Each module keeps its own
  package manager and build config (VibeScan: pnpm workspace; SecLayer: npm).

## Open items before this is a working app

- **Licensing:** VibeScan is Apache-2.0. SecLayer has no LICENSE file, and the
  root repo's license needs confirming. Resolve before publishing.
- **Scan sources:** the scan checks live in `modules/vibescan-enterprise/`
  (`artifacts/api-server/src/lib/`, 418 findings per its `SCAN_CHECKS.md`) and
  `modules/seclayer/server/`. The checks are used verbatim; do not rewrite them.
- **Integration:** nothing yet wires the modules into the harness. That is the
  next build step.

## Update: licensing (2026-11-25)

- Root `LICENSE` is MIT (placeholder copyright: "SecLayer Hybrid contributors").
- `modules/seclayer/LICENSE` is proprietary, all rights reserved, matching the module's own design doc.
- `THIRD_PARTY_LICENSES.md` maps every component to its license.
- Still open: `modules/seclayer/mcp-server/package.json` says MIT and conflicts with the proprietary notice; and the copyright holder name needs your final choice.
