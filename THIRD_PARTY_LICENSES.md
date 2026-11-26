# Third-party and module licenses

This repository combines code under different licenses. Each part keeps its own license.

| Path | License | Notes |
|---|---|---|
| `LICENSE` (root, everything not listed below) | MIT | Covers the deepseek-super base. |
| `modules/vibescan-enterprise/` | Apache License 2.0 | See `modules/vibescan-enterprise/LICENSE`. Keep that file with any copy. |
| `modules/seclayer/` | Proprietary, all rights reserved | See `modules/seclayer/LICENSE`. Not licensed for reuse. |
| `src/deepseek-harness/` | MIT (Copyright 2026 DeepSeek) | See `src/deepseek-harness/LICENSE`. |
| `src/deepseek-harness/native/system/` and its `packages/*` | BSD-3-Clause | See the LICENSE files in those folders. |
| `src/deepseek-harness/packages/boot/hmr/` | See folder LICENSE | |
| `src/deepseek-harness/packages/experimental/**` | See each folder's LICENSE files | Includes `LICENSE-OAR`, `LICENSE.cua-driver`, `LICENSE.computer-use-icon`. |
| `src/deepseek-harness/packages/client/ui-sidebar-documentpreview/licenses/` | FortuneSheet license | See `FortuneSheet.txt` in that folder. |

## Open items

- `modules/seclayer/mcp-server/package.json` declares `"license": "MIT"`. This conflicts with the proprietary `modules/seclayer/LICENSE`. Change one of them. The `package.json` was left as it is.
- Copyright holder is listed as "SecLayer Hybrid contributors". Replace with the legal name you want to use.
