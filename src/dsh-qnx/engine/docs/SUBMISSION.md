# Phase 7 checklist (Devpost guardrails)

| Item | Status |
|---|---|
| Public repo, created during the submission period, **not a fork** | Pending: the work lives in cc4480/deepseek-super (`src/dsh-qnx`, built on the DeepSeek Harness); it moves to a fresh repo when Phase 7 opens (a plain copy, so the history starts fresh) |
| Original projects linked (Parrot AI, MCP3 Code Mode profile) | README "Origins" has the text; add the links when the repo is public |
| Open-source license file at repo root | **Owner's pick** (MIT / Apache-2.0 / BSD) |
| README names QNX 8.0, QEMU x86_64, SDP 8.0 / qcc, cold build + run steps | Done (stand-in steps verified; QNX steps marked [SDP]) |
| "Significant updates / origins" note | Done (README) |
| No redistributed QNX image or SDP files | Done: `.gitignore` excludes `image/out/`; check SDP license terms before shipping anything else |
| Demo video < 3 min, public YouTube, English, no copyrighted music | Script in `DEMO-SCRIPT.md`; film after Phase 0 |
| All materials in English | Done |
| Submission click | **Owner** |

## Still open before submission

1. Phase 0 on the real SDP: install, `scripts/phase0.sh`, fix every **VERIFY** in `image/`, replace `image/manifest.json` with the observed clean baseline, then `scripts/prove.js qnx/config.json` → `docs/receipts/qnx-*.md`.
2. Phase 5 rung: the owner types the prompt in the DeepSeek super harness chat; the `dsh-qnx` bundle gives the model `qnx_search` and `qnx_execute` (needs the DeepSeek key or sign-in).
3. The agent's name (placeholder: "QNX Agent").
4. License.
