# Inc 9 E4 group B - integrator record (W9)

Model claude-opus-5-5. Tree `b103-inc9` (sole writer). Base for RED `40f0f202`; C9's tip `3d345667` is the
"before the fix" tree for each code fix. Runner scratch `~/work/zq-e4-9-int/` (HT-02 env, HOME basename as
ruled, `-n 2`, `timeout 300`, `s19_app.__file__` first in every transcript). Scope: group B only
(`definition_bench.py`, `definition_bench_view.py`, `tests/test_b103_inc9_b_*.py`).

## State / next step
- Done: steps 1-7 (merge, RED/GREEN, fixes, rulings F-1 ... F-8, graph pins, case fold, laws, trace_check,
  final GREEN on a fresh clone, runner scratch deleted). 17/2 waits for the Inc 8 F-1 re-merge.
- Next (orchestrator): re-merge `b103-inc8` (V8) and rerun `test_b103_inc9_b_cells.py`; rule on O-1 (record
  redaction), W9-F1 (Interpolate/Smooth on a short row), SLICE ×2; move the wording list to PENDING; then the
  group B mutant worker.

## Step 1 - merge
`f4ffda1d` = `git merge --no-ff b103-inc9-tests` (T9 `3bd25875`); `steps.log` conflict resolved with both
sides kept in time order (T9 20:13, C9 21:04).

## Step 2 - RED and GREEN runs (runner transcripts; redacted copies committed in `evidence-e4/integrator-b/`)

| Run | Tree | Result |
|---|---|---|
| `red-base-b` | base `40f0f202` + the five test files | 5 errors: `ImportError: cannot import name 'definition_bench'` (the modules do not exist on base; import RED only, it proves no behaviour) |
| `g1-*` | merge `f4ffda1d` (C9 code + T9 tests) | model 19 passed; tools 3 failed / 50 passed; cells 4 failed / 29 passed; canvas 2 failed / 38 passed; detail 40 passed |
| `red-c9` | C9's tip `3d345667` + the final tests | 17 failed / 75 passed: every new or tightened test of a code fix is RED there (table below) |
| `g2-*` | final tree | model 20 passed; tools 57 passed; cells 34 passed / 1 failed (waits for Inc 8 F-1); canvas 40 passed; detail 40 passed |

Graph-example check of C9: C9's check scripts were deleted with its scratch (`E4-impl-b.md` §Pasted outputs),
so they cannot be rerun (**not-run**, reason: no script). The committed example oracles were rerun instead:
`evidence-e1/examples_inc9.py` (38 lines) and `evidence-e2/examples_e3r1.py` (30 lines), rc 0, output identical
to the committed transcripts (only the transcripts' `uptime`/command header differs). The group B tests read
the same oracle (`EX`).

## Step 3 - failures (cause, side, requirement)

| # | Node(s) | Cause | Side | Requirement |
|---|---|---|---|---|
| 1 | `tools::test_r_pe_bench_52_1…` | the test merged two applies' edits; the requirement replaces the edit | test (rewritten, ruling T9 F-2) | R-PE-BENCH.51, .52, EX-K5 |
| 2 | `tools::test_r_pe_bench_58_a…` | the test computed +Δ from the pending value 572 | test (rewritten: +Δ 0 on a pending cell -> {} and the old edit on undo; -100 -> `372` from the current 472) | R-PE-BENCH.51, .58 |
| 3 | `tools::test_r_pe_bench_59_1…` | expected `15.0` (+Δ on the pending 10) | test (`41.9`, EX-K5) | R-PE-BENCH.59, EX-K5 |
| 4 | `cells::test_r_pe_bench_15_2…` | New counted every edit cell, also one whose text equals the current text | code (`_changed_cells`, also used by Δ: "over those cells") | R-PE-BENCH.15, CTX array row cells New / Δ |
| 5 | `cells::test_r_pe_bench_19_1…`, `19_3…` | `summary_strip` read the cells of a flat grid's short last row past the count: `IndexError` | code (skip index >= count) | R-PE-BENCH.19, .11, CTX grid ("the last row may be short") |
| 6 | `canvas::test_r_pe_bench_30_2…` | the lo label touched the first bar (`11719███`): no gap after the 8-cell label column although the CTX reserves `W - 10` for the labels | code (label column 8 + 1 space, `_CHART_LABEL = 9`) | R-PE-BENCH.30, CTX chart look (left labels; column width over `W - 10`) |
| 7 | `canvas::test_r_pe_bench_19_2…` | `?` drawn on an extra line under the bars, not on the base line of the chart | code (`?` on the bottom bar row; the extra line removed) | R-PE-BENCH.19, CTX chart look, EX-N2 |
| 8 | `cells::test_r_pe_bench_17_the_limits_cell[MAP_DEF_0001…]` | Inc 8 `short_number(±1000)` gives `±1k` | Inc 8 code (P-054 F-1, fixed in `b103-inc8` by V8) | R-PE-BENCH.17/2, EX-A2, EX-G10 - **stays RED, waits for the Inc 8 F-1 fix** |

Code fixes were RED first on C9's tip (`red-c9`): 15_2 (`3 cells`), 19_1 / 19_3 (`IndexError`), 30_2
(`'11719███…'`), 19_2 (`16 == 15`), 14 ×2 (`BenchState has no field {'refusal'}`), 93 ×2 (`100 == 118`,
`202 == 220`), flat tools ×4 (`IndexError`). The rewritten F-2 tests pass on C9's tip (C9 already replaces).

## Step 4 - rulings applied

- **C9 F-1 (P-054):** not patched here. RED set waiting for the Inc 8 fix: `tests/test_b103_inc9_b_cells.py::test_r_pe_bench_17_the_limits_cell[MAP_DEF_0001--1.00k … 1.00k]` (R-PE-BENCH.17/2, EX-A2 Limits cell, EX-G10). No other group B node depends on `short_number(±1000)` (grep `1.00k`).
- **C9 F-2 / T9 F-2:** 52/1, 58_a and 59/1 rewritten to "arithmetic from the current value, a new apply replaces the edit, the old one on undo" (rows 1-3 above); the module docstring of `test_b103_inc9_b_tools.py` states the rule. Wording items W-1 ... W-4 below.
- **T9 F-1 (R-PE-BENCH.14):** C9 carried a refused decode through `isinstance(row.current, Refusal)`, but Inc 8's `build_row` never decodes a bench row (`_FALLBACK_OPS.decode` = `_decode_none`, `row.current is None`; graph §Interfaces "no I-2 call at build_row", E3A-01): the branch was dead, so the requirement had no carrier - **defect**. Added the minimal field `BenchState.refusal: Refusal | None = None` (the bench worker's decode refusal, with `values` None); `bench_cells` shows `--` from it. Pinned in `codewire/graph-inc9.md` §Interfaces (Inc 9-internal). Cases 14/1 (no image) and 14/2 (last byte missing, `A2L-DEF-BYTES`) written: `test_r_pe_bench_14_a_refused_decode_shows_two_dashes[…]`, with the control "same row, no refusal -> `6 values`". The widget (B3, group I) must set the field when `decode_values` refuses.
- **T9 F-3:** CTX "Δ ... over those cells whose current and shown values are finite" with "shown value: pending, else staged" -> the staged case uses the staged decode `838 * 0.05 = 41.900000000000006`: `max |Δ| 5.1 staged`. 16/2 tightened to that exact text; the literal `5 staged` (R-PE-BENCH.16/2, EX-T2) goes to the wording list (W-5). The pending case stays `5` (`41.9 - 36.85 = 5.0499…`).
- **T9 F-4:** `window_for` answers `(row, col)` and `BenchState.origin` is `(row, col)`; pinned in the graph. New test `test_r_pe_bench_36_window_for_answers_row_then_column` reads both members (cursor (13, 40) -> origin (21, 10)). No code change.
- **T9 F-5:** R-PE-BENCH.5 bounds every bench line ("no more bench lines than the rows the sheet leaves for the detail"); the canvases are bench lines. Both canvases already cut to `room` (`lines[: room]`), so **not a defect**; the two room tests now assert `len(lines) <= room` at rooms 1 ... 5 (and 6, 7, 8, 20, 30), the chart edited and not. They pass on C9's tip too.
- **T9 F-6 (names the tests read):** all exist as read: tool letters `s d p i m` (`_TOOL_LABELS`); `job == "summary"` (`bench_cells`), `job == "decode"` (`bench_cells`, `bench_detail`); `BenchState.status`; `BenchState` and `BenchValues` are dataclasses built by keyword (`blank_state` from `dataclasses.fields`, `BenchValues(numbers=, texts=, missing=)`); `Grid(mode, nx, ny, count, layout)`; `apply_tool(definition, state, grid, values, operand) -> BenchState` with `.edit`, `.undo`, `.status`; `undo(state)`; `bench_cells -> 5 Text`; `bench_mark(row, state) -> str`; `window_line -> Text | None`; `axis_labels -> (columns, rows)`; `op_line -> (name, tail)`. None missing.
- **T9 F-7:** `width` of `op_line` is the tail's width, the name not included: I-8.5 `bar(row, state, width)` is called by Inc 8's sheet (`_paint_bar`) with the tail widget's width, as `formula_tail`; R-PE-BENCH.93 "cut at the bar's right edge"; EX-H3 width 100 -> length 100. C9 cut the tail at `width - len(name) - 1` (inside the edge) - **code fix** (`_cut(tail, width)`). 93/1,2 tightened to `cell_len(tail) == width`. Wording W-6 (289 vs 294 characters).
- **T9 F-8:** MINOR. `examples_inc9.py` uses Python's `round` (half to even) in `strip_chart` and `step`; no `.5` tie is reachable from the DEFC inputs the requirements use. To P-026: pin the rounding mode at the batch close.

## Law guards (bundle clone of `b103-inc9` a295a81e + `main` under `~/work/zq-e4-9-int/fin`, transcripts `laws1..3`; base = archive of `40f0f202`, transcript `b-laws2`)

| Law | Tree | Base `40f0f202` |
|---|---|---|
| `engine_unchanged`, `deps_seam_law`, `docs_canon`, `b101_doc_hygiene`, `b101_help_legend_docs`, `no_private_tokens`, `filename_markup_safety`, `report_markup_safety`, `b97_key_bar`, `id_registry` (G rules) | 344 passed | - |
| `id_registry::test_tc607_scanned_corpus_matches_the_declared_bound` | failed `335 == 329` -> **test side**: the six new group B modules (5 tests + `tests/support/b103_inc9_b.py`); `EXPECTED_SCANNED_TEST_FILES` 329 -> 335 with the list (as Inc 8 F28) | - |
| `tui_directionb -k tc031` (engine-frozen law) | 3 passed | - |
| `requirements_canon` | 1 failed: R-A2L-DEF.153, R-PICKER-CORRECT.004, .008 | the same 3 rows (pre-existing) |
| `address_census` | 1 failed: 8 offenders (`test_b103_a2l_refresh` ×2, `test_b103_picker_model` ×6) | the same 8 (diffed: identical); the group B tests add none |
| `suite_hygiene::test_r_tst_070_2` | 1 failed: `inc-9/E3-security.md` ×3, `inc-9/evidence-e1/run_pilot.sh` ×5 (base), **+1 `inc-9/E4-test-b.md`** (T9's record names the runner HOME basename) | 8 lines (E1/E3 records) |
| `suite_hygiene::test_r_tst_002_2` | passed | failed (archive tree without git, as Inc 8 recorded) |

`r_tst_070_2` is left RED: the offenders are inherited records (PP-06: no edit of an inherited record to pass a law
without a recorded decision); **open item O-1 for the orchestrator** (the Inc 8 O-2 analogue: redact the token in
`inc-9/E3-security.md`, `evidence-e1/run_pilot.sh`, `E4-test-b.md`). This record does not name the token.

## trace_check (step 6) - `python <skill>/trace_check.py --req …/inc-9/01-requirements.md --base 40f0f202 --src s19_app`
```
TEST   R-PE-BENCH.1 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.20 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.22 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.23 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.24 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.25 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.27 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.28 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.29 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.40 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.44 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.45 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.46 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.47 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.48 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.49 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.6 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.70 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.71 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.72 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.73 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.74 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.75 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.76 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.77 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.78 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.80 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.81 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.82 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.83 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.9 is named by no file under tests, and neither is a TC/AT id it lists
SLICE  s19_app/tui/definition_bench.py changed since 40f0f202 and no requirement file names it
SLICE  s19_app/tui/definition_bench_view.py changed since 40f0f202 and no requirement file names it
EVID   no 04-validation.md beside .dev-flow/2026-11-05-batch-103/inc-9/01-requirements.md
trace_check: 1 US, 82 active requirements (1 withdrawn), checks run: US, CASE, TEST, SLICE, EVID, 34 gap(s)
```
- TEST ×31: rows of the widget, the app and group A9/I (no group B case), except R-PE-BENCH.29 (a group B row whose two cases are timing ATs on the widget, B33/B34; T9 left them to the widget tests). R-PE-BENCH.14's gap of T9's run is closed.
- SLICE ×2: a finding. Proposal (the Inc 8 trace-ruling form): name `definition_bench.py` in R-PE-BENCH.10's Base cell and `definition_bench_view.py` in R-PE-BENCH.3's ("code `…` (E4 trace)"). Not applied: the requirements file is the orchestrator's.
- EVID: expected before E5.

## Final GREEN - fresh bundle clone of `b103-inc9` 4fecb464 (+ `main`) under `~/work/zq-e4-9-int/fin2`
`s19_app.__file__` = `~/work/zq-e4-9-int/fin2/s19_app/__init__.py` at the top of each transcript (`f-*`, `fl-*`).
Host load 5-10 (shared runner); no timing decision is taken here (HT-08).

| Chunk | Result |
|---|---|
| `test_b103_inc9_b_model.py` | 20 passed |
| `test_b103_inc9_b_tools.py` | 57 passed |
| `test_b103_inc9_b_cells.py` | 34 passed, 1 failed: `test_r_pe_bench_17_the_limits_cell[MAP_DEF_0001--1.00k … 1.00k]` (`'-1k … 1k'`; waits for the Inc 8 F-1 fix) |
| `test_b103_inc9_b_canvas.py` | 40 passed |
| `test_b103_inc9_b_detail.py` | 40 passed |
| laws: `engine_unchanged`, `deps_seam_law`, `docs_canon`, `no_private_tokens`, `filename_markup_safety`, `id_registry` (bound 335) | 25 passed |
| `tui_directionb -k tc031` | 3 passed |
| `b97_key_bar` 38, `b101_doc_hygiene` 45, `b101_help_legend_docs` 71, `report_markup_safety` 166 | passed, one file per run. A first run of the four together hit `timeout 300` at load 10 (rc 124) with one `F` printed and no detail (killed before the report); `b97_key_bar` alone took 296 s. Load-sensitive, unverified; the same four passed at a295a81e (`laws1`, 344 passed) |
| `suite_hygiene` 66 / `requirements_canon` / `address_census` | 3 failed, 98 passed: `r_tst_070_2` (base 8 lines + 1 in `E4-test-b.md`, O-1), the canon's 3 rows (= base), the 8 address offenders (diffed = base) |

## Integrator findings (beyond T9's list)
- **W9-F1 (fixed, R-PE-BENCH.53 ... .56, CTX grid):** `_tool_results` read the rectangle's cells past a flat grid's count (anchor (15,0), cursor (1,1) on 18 elements -> `IndexError` for every tool). Fix: +Δ / ×% stop at the row's width (as `selection_cells`); Interpolate / Smooth leave out a grid row whose last selected column is past the count (its end value does not exist). **Orchestrator to confirm the Interpolate/Smooth rule** (a reading, not stated by a requirement). Test `test_r_pe_bench_53_a_flat_selection_over_the_short_last_row…[d,p,i,m]`, RED on C9's tip.
- **W9-F2 (open, group I / E5):** with `refusal` set and `values` None, `bench_detail` still shows `decoding <n> values …`; no requirement states the detail of a refused decode (R-PE-BENCH.14 covers the Current cell). For the widget design.
- **W9-F3 (MINOR):** `definition_bench.py` is 629 lines, `definition_bench_view.py` 503 (C9 delivered 610 / 502): over the module bound of 300 lines; `_tool_results` is at 40 lines. For E5.
- New and Δ now count only cells whose text differs from the current text (`_changed_cells`); Δ follows "over those cells" of the CTX.
- Capture items (DF-09 V-items, with C9's D-5/D-6): the chart label column (8 + 1 space) and `?` on the bottom bar row.

## Inc 9 wording list (for PENDING; the orchestrator moves it)
- **W-1** R-PE-BENCH.52/1: "points 1 and 3 `40000` -> edit {(1,), (3,)}" implies a merge across applies; under R-PE-BENCH.51 / EX-K5 the second apply replaces: "Set `40000` on point 1, then on point 3 -> edit {(3,): `40000`}, undo top {(1,): `40000`}; on points 1..3 -> {(1,), (2,), (3,)}".
- **W-2** R-PE-BENCH.15/3 and EX-C1 ("Set 40000 on points 1 and 3 -> `2 pts`"): same merge reading; the cell counts an edit of two points, which one apply on a rectangle cannot make on points 1 and 3 alone.
- **W-3** R-PE-BENCH.30/3 and EX-C1 in `chart_canvas` ("after Set 40000 on points 1 and 3"): same.
- **W-4** CTX "result": "v its shown value (… or the pending value)" -> v is the current value (P-054 F-2).
- **W-5** R-PE-BENCH.16/2 and EX-T2 / graph `bench_cells` example: "staged and no edit -> `max |Δ| 5 staged`" -> `max |Δ| 5.1 staged` (staged decode 41.900000000000006 - current 36.85).
- **W-6** R-PE-BENCH.93 and EX-H3: "a refusal verdict of 289 characters" -> the `x` × 300 Set refusal message is 294 characters (T9, measured).
- **W-7** CTX chart look / EX-N2 "`?` on the base line": say "on the chart's bottom row" (the reading pinned here).

## For the next workers (≤ 3 lines)
- Mutant worker: the new `refusal` field, `_changed_cells`, the flat-row guards and `_CHART_LABEL` are new code; the room tests now assert `<= room` (a mutant `lines[: room + 1]` must die).
- 17/2 stays RED until `b103-inc8` (V8) is re-merged; do not count it as a survivor or a new failure.
- Group I (bench_sheet): set `BenchState.refusal` on a refused decode and clear it on the next decode.

## After the Inc 8 re-merge (relevo-10)

Worker M9 (claude-sonnet-5-5). Tree `b103-inc9` tip `30819c7e` (group B integrated `e81c0f77` + re-merge of Inc 8
final `7ac47dc5`). Runner scratch `~/work/zq-m9/` (an archive of `30819c7e`; HT-02 env with `-n 2`, `timeout 300`,
`s19_app.__file__` = `~/work/zq-m9/tree/s19_app/__init__.py` at the top of each transcript). Host load at the runs
5-8 (shared runner, `uptime` before and after each); no timing decision is taken (HT-08).

### Step 1 - post-merge GREEN (one complete run per row, output read as printed)

| Run | Result |
|---|---|
| `test_b103_inc9_b_model.py`, `_tools.py`, `_cells.py` (one run) | 112 passed in 121 s (20 + 57 + 35) |
| `test_b103_inc9_b_canvas.py`, `_detail.py` (one run) | 80 passed (40 + 40) |
| Inc 8: `a1_service`, `a2_app`, `a3_help`, `s1`, `s1_detail` (one run) | 216 passed in 163 s |
| Inc 8: `at`, `at_help`, `p_layout`, `p_ledger`, `p_wiring`, `s2_picker_definitions`, `s2_sheet_formula`, `s2_sheet_keys`, `s2_sheet_rows` (one run) | 149 passed in 314 s |

- `test_r_pe_bench_17_the_limits_cell[MAP_DEF_0001--1.00k … 1.00k]` is **GREEN** (Inc 8's `short_number` gives `1.00k`
  after F-1). 17/2 is closed. No new failure in either set.
- Inc 8's E5 changes (`row_line` with an Optional `pending`; the removed `room` cut in `detail_lines`): group B calls
  neither (`grep row_window|row_line|detail_lines` over both group B modules: no hit). `bench_detail` cuts to its own
  `room` argument (`lines[: room]`) and the room tests (`<= room`, rooms 1 ... 30) pass, so Inc 9 does not lean on
  the removed cut. The widget (group I) is the caller to check, not group B.

### Step 2 - O-1 (`test_r_tst_070_2`), ruling P-050 O-2 applied

- RED on `30819c7e` (run `o1-red`): 15 hit lines, in `inc-8/04-validation.md`, `inc-8/E4-mutants.md`,
  `inc-8/evidence-e4/mutants/run_env.sh` (Inc 8's own records, left to Inc 8's conductor) and three Inc 9 files:
  `inc-9/E3-security.md` (3), `inc-9/E4-test-b.md` (1), `inc-9/evidence-e1/run_pilot.sh` (5).
- Fix (forward, Inc 9's own unpushed records; no inherited record touched, PP-06): the runner HOME basename became
  `<runner-home>` in the two `.md` records; `run_pilot.sh` takes it from the variable `RUNNER_HOME_NAME` (the HT-02
  basename) instead of a literal. Commit `71997e20`.
- Run `o1-green` (the three files copied into the archive tree): the hits of the three Inc 9 files are gone; the test
  still fails on **Inc 8's three files only** (`inc-8/04-validation.md`, `inc-8/E4-mutants.md`,
  `inc-8/evidence-e4/mutants/run_env.sh`, 6 lines), which are the Inc 8 conductor's O-2 redaction, not Inc 9's.

### Step 3 - W9-F2 (`bench_detail` says `decoding …` after a refused decode)

R-PE-BENCH.14 states only the Current cell (`--`). R-PE-BENCH.21 states `decoding <count> values …` "while the
selected row's decode runs"; nothing in the requirements, the CTX or the examples says what the detail shows once a
decode has been refused (the CTX's `✗ refused` lines belong to the preview and the bytes line). The requirement is
**silent**, so this is not a DF-04 a defect: the code is left as is and the item goes on the wording list:
- **W-8** R-PE-BENCH.21 / CTX detail: say what the detail shows when the selected row's decode is refused
  (`BenchState.refusal` set, `values` None, no job running): today the `decoding <count> values …` line stays.
  Proposal for the requirement owner: the refusal's message in that line's place, `✗ refused: <message>`.
