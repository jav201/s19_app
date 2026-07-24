# 04 — Phase-4 validation · batch-n8 (comprehensive per-view Legend)

**BLUF:** Full non-slow suite on the final state (`6ec2a42`): **1869 passed / 0 functional
regressions**. The only red is the 19 pre-existing `tc016s` density-snapshot baselines
(batch-58/59 drift), **DEFINITIVELY proven pre-existing** by reverting the 4 N8 source
files to base `f56cf48` and re-running the snapshot suite → identical **19 failed**.

## Full suite (final state `6ec2a42`)
```
19 failed, 1869 passed, 2 skipped, 21 deselected, 3 xfailed  (1831s)
```
- **All 19 failures** = `tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot[*]`
  (workspace/a2l/mac/issues compact+comfortable + map/patch/diff comfortable). **0 non-snapshot
  failures.**
- Delta vs post-Inc-2 run (`1866 passed`): **+3** = the 3 Inc-3 tests (AT-N8-06/07, TC-N8-04).
  Purely additive; no existing test changed verdict.

## Pre-existing-drift proof (C-31/C-32 — proven, not assumed)
1. Stash-verify (pre-commit, 4 representative nodes) → base fails identically.
2. **Full base-render check:** `git checkout f56cf48 -- legend.py screens.py app.py styles.tcss`,
   `pytest tests/test_tui_snapshot.py` → **19 failed / 13 passed** — the SAME 19 nodes fail on
   base with zero N8 code present. Source restored to HEAD afterwards.
   → N8 introduces **0** snapshot drift. The Legend modal is not `tc016s`-captured; the base
   rail screens N8 does not touch account for all 19.

## AT / TC coverage (all GREEN — see 06-docs/traceability-matrix.md)
- Data (Inc-1): TC-N8-01/04/05/08/09 + band-key + `format_cutoff` + **TC-N8-11** (markup guard).
- Render (Inc-2): **AT-N8-01..05** (Pilot, per view: card + key present, negatives hold).
- Fold-in (Inc-3): **AT-N8-06** (Static wraps, `type is Static AND height>=2`), **AT-N8-07**
  (painted span == live `_SEVERITY_TO_RICH_STYLE[WARNING]`), **TC-N8-04** (AMD-8 live A2L
  column oracle).
- Regression: `test_tui_legend` (15) + N1 `test_legend_scope_and_logwidth` (5, AMD-4 amended)
  all green.

## Lint
- Ruff clean on all new/changed `.py` (`legend.py`, `screens.py`, 3 test files).
- `app.py` `F821 Undefined name Dict` is **pre-existing on `main`** (future-annotations string,
  runs fine; CI = pytest). Not introduced by N8; not in scope to fix (surgical-changes rule).

## Merge readiness
- **tui-ci gate (pytest):** the blocking job is functional tests → **green** (0 non-snapshot
  failures). The snapshot job is advisory and may be red (pre-existing) per the standing
  authorization — accepted for merge.
- Final PR-level qa-reviewer pass over the whole diff vs `main` MUST be 0-HIGH before self-merge
  (see the PR).
