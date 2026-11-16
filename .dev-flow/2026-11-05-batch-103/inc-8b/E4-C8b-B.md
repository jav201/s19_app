# Inc 8b E4 — C8b-B hand-back (group B)

Worker: C8b-B, Sonnet 5.5 (no DeepSeek: the first `opencode run` returned "Insufficient Balance", so the unit was written directly, per the brief). Commit 69ee5270. Files: `s19_app/tui/definition_bench.py`, `s19_app/tui/insight_style.py` (comment only). No tests written.

## What changed
- `_BLOCKS` is now seven levels (`▁▂▃▄▅▆▇`); `summary_strip` uses `round(t * 6)`, the grid strip uses the column-mean level (no `█`, no `ramp_style`), every block carries `DGRAY` as its own span style, no ground, spaces and the count text unstyled (R-PE-BENCH.11 / .107 / .108).
- `bench_cells`: Limits = `range_cell(definition.limits.lower, definition.limits.upper)` (R-PE-BENCH.17, R-PE-DEF.104). Imports `range_cell` (group S, pinned in the graph) and `DGRAY` (from `.insight_style`, the tui convention).
- `insight_style.MAGENTA` comment: the verdict-hue rule of R-PE-DEF.101 (GREEN `✓`/`●`, YELLOW `▲`, RED `✗`).
- `ramp_step`, `ramp_style`, `_RAMP_LO/_HI` left in place (not removed: out of scope; see Findings).

## Evidence (rtx, HT-02 env, load average 1.48 at start; scratch tree with a stand-in `range_cell` appended to the scratch copy of definition_sheet.py only)
```
~/work/zq-e4-8b-C8b-B/tree/s19_app/__init__.py
held EX-8B-F1 CURVE '▄▆▃▇▁' want '▄▆▃▇▁' {'', '#969aad'}
held EX-8B-F1 MAP '▆▃▅▃' want '▆▃▅▃' {'', '#969aad'}
held EX-8B-F1 VAL_BLK '▄▃▄' want '▄▃▄' {'', '#969aad'}
held EX-8B-F2 ramp40 '▁▁▂▂▃▃▄▄▅▅▆▆▇▇' want '▁▁▂▂▃▃▄▄▅▅▆▆▇▇' {'', '#969aad'}
held EX-8B-F2 flat '▁▁▁' want '▁▁▁' {'', '#969aad'}
nan point -> '▁ ▇'
bench_cells uses range_cell: True | old form gone: True
```
- EX-8B-F1 (CURVE, MAP, VAL_BLK), EX-8B-F2 (ramp40, flat): held. Command: the snippet `ex.py` (scratch, deleted) building `BenchValues`/`Grid` and calling `summary_strip`.
- EX-8B-L5 (`bench_cells` Limits text): could not run — needs group S's `range_cell`; verified only that `bench_cells` calls it with the definition's two limits and the old `short_number … short_number` form is gone. To be run once S lands.
- `ast.parse` both files OK; diff has 0 CR (python count).

## Deviations / findings
- No DeepSeek quota: done by hand (MD-01 fallback).
- The strip's `ramp_step`/`ramp_style` are now unused by `summary_strip`; `ramp_style` is still defined for other callers (grep before any removal; not done here).
- Existing Inc 9 tests of R-PE-BENCH.11 / .17 (EX-G1, EX-G2) will fail until T8b-R retargets them (expected per E1-slice §4).
