# Third-party and component licenses

This repository combines code under different licenses. Each part keeps its own license.

| Path | License | Notes |
|---|---|---|
| `LICENSE` (root, everything not listed below) | MIT | Covers the deepseek-super base. |
| `src/dsh-redteam-gate/src/engines/vibescan-core/` | Apache License 2.0 | Verbatim VibeScan scan core. See `LICENSE` in that folder. Keep it with any copy. |
| `src/dsh-redteam-gate/src/engines/seclayer-core/` | Source-available proprietary (all rights reserved) | Verbatim SecLayer scan core. Viewable in the public repo; not licensed for reuse or redistribution. See `LICENSE` in that folder. |
| `src/deepseek-harness/` | MIT (Copyright 2026 DeepSeek) | See `src/deepseek-harness/LICENSE`. |
| `src/deepseek-harness/native/system/` and its `packages/*` | BSD-3-Clause | See the LICENSE files in those folders. |
| `src/deepseek-harness/packages/experimental/**` | See each folder's LICENSE files | |
| `src/deepseek-harness/packages/client/ui-sidebar-documentpreview/licenses/` | FortuneSheet license | See `FortuneSheet.txt`. |

## Open items

- Copyright holder for the root `LICENSE` and the SecLayer core `LICENSE` is Carlos Cuellar.
- The SecLayer core is published as source-available: viewable, not reusable. Decided by the owner on 2026-11-25.
- The original `modules/` folders were removed in this repo. Their history is in git and in the source repositories.
