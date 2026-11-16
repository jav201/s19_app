# Inc 8b E4 - T8b-R (retarget tester)

Base `48af05ff` (product = `b103-inc9` b751be53, no Inc 8b code). Branch `b103-inc8b-tests`. Model: claude-sonnet-5-5. Author of evidence only; no verdict.
Evidence states: every RED row below is `executed` (transcript `evidence-e4/t8b-r/red-on-base-48af05ff.txt`, `s19_app.__file__` printed at the top of each file's section, run on `<runner>` with the HT-02 environment, `-n 2`, `timeout 300`, one file per run). Every "GREEN with the Inc 8b code" claim is `not-run` (no implementation in this tree; the integrator runs the files after the merge).

## 1. Before set on base (retargets not yet applied; `git archive 48af05ff`)

All 25 files of the Inc 8 and Inc 9 sets that finished passed on base (w_mutants 29, w_select 14 included), so every RED below is caused by the retarget alone: a_a1 23, a2 23, a3 9, at_help 2, at 11, p_layout 31, p_ledger 10, p_wiring 12, s1_detail 43, s1 118, s2_picker 6, s2_formula 27, s2_keys 21, s2_rows 35, inc9 a9 29, b_canvas 42, b_cells 40, b_detail 54, b_model 20, b_tools 59, i 3, ob_json_view 2, w_keys 19, w_mutants 29, w_select 14. `test_b103_inc9_w_jobs` (1,048,576-element LARGE) was still running when this record was written (no result; not a retargeted file). `test_tui_patch_json` on base: 3 failed (ac1, ac3, ac5, the JSON editor height at 120x50), 14 passed: **pre-existing, not caused by this work**.

## 2. RED of the retargets on base (`red/` = base product + the retargeted tests)

| file | result on base | RED because (assertion, never an import error) |
|---|---|---|
| test_b103_inc8_s1 | 28 failed, 94 passed | widths still classed (R-PE-DEF.89), header without gutters (.5), limits cell not 34 cells at fixed offsets (.21, .76), rows not 143 cells (.7 retargeted), name clip at 18 (.15, .96) |
| test_b103_inc8_s1_detail | 18 failed, 25 passed | no bar `  ┊ ` on any expanded line (R-PE-DEF.107; the six .31/.32 tests now read through `content()`), no enum/bit/text card (.33 .34 .35 .79) |
| test_b103_inc8_s2_sheet_keys | 5 failed, 17 passed | 81/1..4: no header rule line, visible = body - 1; 81/5: no `#patch_sheet_grid` |
| test_b103_inc8_s2_sheet_rows | 1 failed, 34 passed | R-PE-DEF.30: no `┊ └` detail line |
| test_b103_inc8_a3_help | 1 failed, 8 passed | R-PE-DEF.85: no `home`/`end` in the STAGING SHEET help line |
| test_b103_inc8_at_help | 1 failed, 1 passed | same row, through the Help window |
| test_b103_inc9_b_cells | 13 failed, 27 passed | R-PE-BENCH.11 (eight levels, `█`), .17 (`0 … 65.5k`), .19 strips |
| test_b103_inc9_b_detail | 4 failed, 50 passed | R-PE-BENCH.5/1..4 through `detail_lines`: no bar |
| test_b103_inc9_w_select | 4 failed, 10 passed | strips of the real app (11, 23/1, 24/1, 25/2) |
| test_tui_patch_json | 4 failed, 13 passed | `test_tc079_5c_hue_census_is_complete`: `#1c2547` is a stale exclusion on base (RED until Inc 8b's code paints it); ac1/ac3/ac5 are the 3 pre-existing failures |
| test_b103_inc8_at | 11 passed | not RED by design: the parser's control test takes synthetic text (now in the Inc 8b look, parser made gutter-safe); the AT rows read through the parser are unchanged |
| test_b103_inc9_w_mutants | 29 passed | not RED on base, and stays satisfied on the new product only if the strip is correct: the test asserts "the old page's strip is NOT painted" (`fact("S.after.CURVE_DEF_0001")`, was the eight-level strip, which could never appear after Inc 8b: that version was vacuous on the new product) |

## 3. Retarget table (file -> node -> old -> new -> requirement)

| file | node | old | new | row |
|---|---|---|---|---|
| support/b103_inc8_s1 | `cells()` | split by widths | skips the `│` after each column | R-PE-DEF.90 |
| support/b103_inc8_s2 | `SheetApp.CSS`, `cells()` | harness gave the body `height: 1fr`; cell text kept the gutter | harness gives the body no height (the product rule must); gutter dropped from the cell | E3-8b-05, R-PE-DEF.90 |
| support/b103_inc8b_r (new) | `EXB`, `fact`, `content`, `GRID_WIDTH` | - | loads `evidence-e1/examples_inc8b.py` and its transcript | - |
| s1 | `test_r_pe_def_6_widths_follow...` (kept name) | width classes | fixed grid widths at 12 view widths | .6 retired -> .89 |
| s1 | `test_r_pe_def_7_*` (2, kept names) | every line <= W; `温度`x6 clip | every line == 143 cells; `C.name_wide.fit26`, `C.unit_wide.fit8` | .7 retired -> .89, .96 |
| s1 | `test_r_pe_def_5_header_labels...` | starts by width class | `G.header_line`, gutters | .5 |
| s1 | `test_r_pe_def_15_a_long_name...` | `ASAM.C.ASCII.UBYT…` | `EXB.fit(name, 26)` | .15 (clip = .96) |
| s1 | `test_r_pe_def_21_*` (5), `_no_limits`, `test_r_pe_def_76_*` | `-40 ├…┤ 150` after lower; `5 … 5` | `L.cell.*` keys, offsets 8/25/16, `limits_5_5`, `limits_9_1` | .21, .76 |
| s1 | `..._a_track_under_six_cells...` | `limits_cell(row, None, 16)` -> `-40 … 150` | width argument changes nothing (E3-8b-10) | .21 |
| s1 | `test_r_pe_def_81_row_window_examples` | - | + `(10,0,6,10,(10,5))` = `W.standin_10_detail.h8.painted` | .81 |
| s1_detail | `lines_of` | raw plain | content after the bar | .107 |
| s1_detail | 33 x2, 34 x2, 35 x2, 79 x2 | 3-line enum, bit strip, `+00 …` rows, 6 lines | cards (`E.card.*`, `B.card.*`, `T.V171.*`), 9 / 8 lines; token styles read with `get_style_at_offset` | .33 .34 .35 .79 |
| s2_sheet_keys | 81/1..4, new 81/5 | body 21/8/9, rows from line 1 | body 22/8/8, rows from line 2, harness 53/52/50 | .81 |
| s2_sheet_rows | `_rows_with_detail` | `└` | `┊ └` | .30/.107 |
| at | parser + control | no gutter, no rule, no bar | gutter-safe (`│`), 26-cell name, rule and bar lines | .90 .91 .107 |
| inc9_b_cells | 11/1..3, 11 x2, 17 x2, 17/3, 17/4, 19 x4 | `▅▇▄█▁ 5`, `████ 12`, `0 … 65.5k` | `S.after.current.*`, `L.bench.*`, `▁`..`▇` | R-PE-BENCH.11, .17, .19 |
| inc9_b_detail | 5/1..5 | through `dv.bench_detail` only | + through `ds.detail_lines` at V = 73, 111, 195, room 1, room 0 | R-PE-BENCH.5 |
| inc9_w_select | 11, 23/1, 24/1, 25/2 | eight-level strips; 40-element array | seven-level facts; 100 elements (room 15 < 16 columns) | R-PE-BENCH.11 |
| inc9_w_mutants | 24/2 | old strip | `S.after.CURVE_DEF_0001` | R-PE-BENCH.11 |
| a3_help, at_help | R-PE-DEF.85 | no scroll keys | + `home`, `end` | .85 |
| test_tui_patch_json | `_EXCLUDED_LITERALS` | - | + `#1c2547` (reason, val 27.8%) | hue census, E1-rulings section 4 |

No law guard was weakened; no test was deleted; no test name changed. R-PE-DEF.6 and .7 tests keep their names (the brief) and cite the retirement in the docstring.

## 4. trace_check (repository root, `--ids` the 11 rows of this retarget)

`trace_check: 11 active requirements match --ids, checks run: CASE, TEST, 0 gap(s)`

## 5. Gaps and limits

- GREEN on the new product: `not-run`. Retargets written against the requirement text, the graph and the committed oracle only.
- Not retargeted because I could not see them fail or pass without the implementation: `test_b97_width`, `test_tui_patch_layout`, `test_tui_directionb`, `test_tui_snapshot` (the 80x24 / 120x30 Patch Editor snapshot cells drift if the look changes: snapshots are regenerated only by the canonical CI, HT-09). The integrator's run decides.
- R-PE-BENCH.36 (/4, /5) and the E3-addenda case R-PE-DEF.81/6 (width-only resize, MAP_DEF_0001) belong to T8b-BW; `test_b103_inc9_w_mutants.py:714` (`bench_detail` at `_windowed_cases` widths) is left for it.
- E3-addenda E3-8b-09 (R-PE-DEF.106 built directly) is T8b-S2's; E3-8b-10 is applied here (the 16-wide call).
- Notes for other testers: the harness `SheetApp.CSS` no longer gives `#patch_sheet_body` a height (E3-8b-05); a subclass that needs one sets it. `tests/support/b103_inc8_s1.cells` now skips gutters.
- A 26-cell name fills its column and the gutter follows with no space; parsers of painted rows must split on `│` (done in `test_b103_inc8_at.parse_rows`).
- `test_b103_inc9_w_jobs` not run (long).

- rtx scratch deleted at the end (explicit path, no process left); the base batch was stopped by PID after w_select, so `inc9_w_stage` and the law files were not run on base.
