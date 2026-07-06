# PLAN — batch-25 (P3 snapshot-baseline)

**Where we are:** Phase 0 (story intake / DoR), in-progress. Awaiting operator at the Phase-0 gate on (a) route and (b) two design forks.

## Objective (BLUF)
The TUI layout-snapshot suite (`tests/test_tui_snapshot.py`, 28 cells) is a **silently non-functional drift oracle** — CI never installs `pytest-textual-snapshot`, so the whole module is skipped, not run, on every PR/push. Fix the env so it runs, regenerate the baseline set **in the canonical CI env only**, drop the 2 permanent patch `xfail` cells, and refresh the vault gallery + `visual-evidence.md`. Baselines only.

## Verified facts (grounding)
- CI ([tui-ci.yml:29-37]) installs `requirements.txt + pytest + pillow + -e .` — never `[dev]`. `pyproject.toml:30` declares `dev = ["pytest-textual-snapshot==1.1.0", ...]`.
- `test_tui_snapshot.py:74` `import pytest_textual_snapshot` → `importorskip` (line 34) skips the module.
- Matrix = **28 cells** (24 restyled + map/diff/patch@80×24/patch@120×30). The **2 xfail cells = the 2 patch cells** (`test_tui_snapshot.py:384-401`).
- **Hard constraint:** regen must run in the canonical CI env; local Windows regen is forbidden (snapshot-regen-env memory: 2026-05-28 local regen drifted 13/27 baselines). → mandatory CI round-trip.

## Stories (pre-DoR)
- **US-A** — CI executes the snapshot suite (visible in the run log, not skipped).
- **US-B** — baselines regenerated in the canonical env; only genuinely-changed screens (patch 2×2, MAC 82-col) move.
- **US-C** — the 2 patch xfail cells pass green with real baselines (drop `_SCAFFOLD_CELLS` xfail marks).
- **US-D** — vault `assets/snapshots/` + `visual-evidence.md` reflect current UI, dated to this batch; retire the stale "MAC predates batch-05" callout.

## Design forks (Phase-0 gate)
1. **CI gating policy** — blocking gate on the existing job vs a separate non-blocking / `continue-on-error` job.
2. **Baseline CI→repo round-trip** — how CI-produced baselines land in the repo given local regen is forbidden (recommend: `workflow_dispatch` job runs `--snapshot-update`, uploads `tests/__snapshots__/` as an artifact → download + commit).

## Route
Invoked as `/dev-flow`; work is thin infra with a mandatory CI round-trip. `/fast-dev-flow` may fit better. **Operator confirms route at the Phase-0 gate.**

## Out of scope
Pilot GIF/SVG gallery (`assets/pilot/`, C-16-maintained); any engine-frozen module.

## Decision log (human mirror)
- 2026-07-03 — Operator chose snapshot-baseline as batch-25; entropy #12(b) → batch-26 (BACKLOG). RC-1 PASS @ 0c06b48.

## Watch items
- Standing flag: operator's primary checkout stuck on merged branch `fix/select-null-blank-sentinel` → switch to main.
- If a regen in the canonical env moves screens OTHER than patch/MAC → wrong env, STOP (snapshot-regen-env rule).
