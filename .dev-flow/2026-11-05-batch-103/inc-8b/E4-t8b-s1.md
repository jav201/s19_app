# Inc 8b E4 - T8b-S1 hand-back (render rows: grid D, styles, Limits column, F-R14-1 strip)

Tester: Sonnet (tester agent), relevo-15. Test file: `tests/test_b103_inc8b_s1.py` (54 test functions, 93 collected nodes). Base for RED: `48af05ff`. States: RED on base = `executed`; GREEN = `not-run` (the integrator runs it, per the brief).

Orchestrator ruling applied: `header_rule` takes the widths; both tests call `header_rule(ds.sheet_widths(111))`, never with zero arguments.

## Method
- Expected values are keys of `evidence-e1/examples_inc8b-transcript.txt` (parsed in the test file) or recomputed by `evidence-e1/examples_inc8b.py` (`EX8`, imported; stdlib oracle). No position or width is typed by hand.
- Every test drives a shipped entry point (`sheet_widths`, `header_line`, `header_rule`, `row_line`, `limits_cell`, `formula_tail`, `bench_cells`, `summary_strip`) over the real DEFC / V171 fixtures and reads the painted `Text` (plain text, cell positions, resolved colours, bold, underline).
- Oracle control: the first RED run showed one vacuous pass (R-PE-BENCH.108/2, selected-row ground: the base layout put no strip in the slice read). The test now asserts the strip blocks are found before asserting their ground; RED on base.

## RED on base 48af05ff
Transcript: `evidence-e4/t8b-s1-red-base.txt` (first line: `s19_app.__file__` inside the base tree; host load recorded; HT-02 env; `-n 2`, `timeout 300`). One complete run: **92 failed, 1 passed**.
- Passes on base: `test_r_pe_def_103_1_every_cue_survives_without_colour` (the glyph cues already exist on base, so this node cannot be RED there; its negative control is a mutant: pending `◆` replaced by a ground-only space). Partial.
- 4 REDs are exceptions, real base defects named by the requirements' own negative controls: `ValueError: cannot convert float NaN to integer` at `definition_sheet.py:724` (R-PE-DEF.106 and .114 paths).
- 4 REDs are `TypeError: row_line() got an unexpected keyword argument 'odd'` (new keyword): R-PE-DEF.97/6, R-PE-BENCH.108/2 zebra x3. RED = "absent keyword".
- 1 RED is "absent": `definition_sheet.header_rule` (R-PE-DEF.91/1).
- All others are value assertions.

## Case -> test (names in `tests/test_b103_inc8b_s1.py`)
| Case | Test | full / partial |
|---|---|---|
| R-PE-DEF.5/1-3 | `test_r_pe_def_5_header_line_is_the_grid_header_at_every_view_width[73,111,195]` | full |
| R-PE-DEF.89/1-3 | `test_r_pe_def_89_every_defc_row_has_its_cells_at_the_column_starts[3]`, `test_r_pe_def_89_the_widths_do_not_depend_on_the_view[3]` | full |
| R-PE-DEF.90/1, /2 | `test_r_pe_def_90_1_...`, `test_r_pe_def_90_2_...` | full |
| R-PE-DEF.91/1 | `test_r_pe_def_91_1_the_header_rule_is_the_grid_rule` | partial (function level; body line 2 via the app is T8b-AT) |
| R-PE-DEF.96/1-6 | `test_r_pe_def_96_1_...` .. `_6_...` | full |
| R-PE-DEF.97/1-9 | `test_r_pe_def_97_1_...` .. `_9_...` | full (frame, `┊`, `└` colours are S2's) |
| R-PE-DEF.98/1-3 | `test_r_pe_def_98_staged_scalar_is_painted_green_with_its_dot[2]`, `test_r_pe_def_98_3_...` | full |
| R-PE-DEF.99/1-3 | `test_r_pe_def_99_1_2_pending_scalar_is_painted_purple_with_its_diamond[2]`, `test_r_pe_def_99_3_...` | full |
| R-PE-DEF.100/1 | `test_r_pe_def_100_1_...` | full |
| R-PE-DEF.101/1-4 | `test_r_pe_def_101_1_...` .. `_4_...` | full |
| R-PE-DEF.103/1 | `test_r_pe_def_103_1_every_cue_survives_without_colour` | partial (`■`, underlines: S2 / AT) |
| R-PE-DEF.21/1-5 | `test_r_pe_def_21_the_limits_cell_is_the_aligned_cell_of_the_transcript[5]`, `test_r_pe_def_21_1_the_cell_in_its_row_...` | full |
| R-PE-DEF.104/1-7 | `test_r_pe_def_104_1_...` .. `_7_...` | full |
| R-PE-DEF.105/1-4 | `test_r_pe_def_105_a_wide_limit_is_written_in_its_exponent_form[4]` | full |
| R-PE-DEF.106/1, /2 | `test_r_pe_def_106_1_...`, `_2_...` (Definitions built directly, E3-8b-09) | full |
| R-PE-DEF.114/1-3 | `test_r_pe_def_114_1_...` (real FLOAT32 image `FF FF FF FF`), `_2_`, `_3_` | full |
| R-PE-DEF.76/1, /2 | `test_r_pe_def_76_limits_not_ascending_give_the_range_form_without_a_division[2]` | full |
| R-PE-BENCH.11/1-3 | `test_r_pe_bench_11_the_current_cell_is_the_strip_and_its_count[3]` (T8b-BW may duplicate) | full |
| R-PE-BENCH.17/1-3 | `test_r_pe_bench_17_1_2_...[2]`, `test_r_pe_bench_17_3_...` | full |
| R-PE-BENCH.107/1, /2 | `test_r_pe_bench_107_1_the_defc_strips_use_no_full_block[3]`, `test_r_pe_bench_107_2_...` | full |
| R-PE-BENCH.108/1, /2 | `test_r_pe_bench_108_1_...[3]`, `test_r_pe_bench_108_2_...[6]` | full |

## trace_check (one run, tree root)
`python -I -B <skill>/trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-8b/01-requirements.md --tests tests --ids <my 21 requirement ids>` -> `trace_check: 21 active requirements match --ids, checks run: CASE, TEST, 0 gap(s)`. (TEST is satisfied by any file under `tests/`; the table above is the real binding.)

## Gaps
- R-PE-BENCH.107/3: E5 real capture, not a pytest node (E5's).
- R-PE-DEF.97/10-12 (mask mark, expanded ground, card ground): card elements, T8b-S2's.
- R-PE-DEF.103/1 underline and `■` cues: S2 / AT.
- R-PE-DEF.92-.95, .81, .94, .33/3, R-PE-BENCH.5, .36: widget and app level, T8b-BW / T8b-AT.
- GREEN not-run. Where a RED reason was positional, check a GREEN failure against the requirement text before calling it a product defect.

## Findings
- F1 (spec): R-PE-DEF.97/8's example `1F F6` does not belong to the DISPLAY_0001 pending row; the test derives the after bytes from `pv.result.data` and finds them after the second ` → ` of the tail.
- F2 (E3R1 "observed, not ruled"): limits +-1.7e308 with a finite value paints at cell 1 over an infinite span; no case written (no ruled value).
- F3 (T8b-R / orchestrator): E3-8b-10 asks to retire `tests/test_b103_inc8_s1.py:503` (`limits_cell(row, None, 16)`); not my file, not touched. E3-8b-09 applied. E3-8b-11 is T8b-BW's.
- F4 (dependency): imports fixtures from `tests/support/b103_inc8_s1.py` and `b103_inc9_b.py` (`defc`, `v171`, `stage_entry`, `blank_state`, `defc_obj`, `sheet_row`, `staged_entry`, `view_state`, `decoded_of`); T8b-R must keep them.
- Interface changes proposed: none.

## Environment
Runner only (HT-01), single file, `-n 2`, `timeout 300`; PC used for reading, `ast.parse` and `trace_check`. No full suite. Runner scratch deleted at the end.
