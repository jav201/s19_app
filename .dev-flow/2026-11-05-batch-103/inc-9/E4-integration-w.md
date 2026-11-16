# Inc 9 E4 widget + A9 + I - integrator record (I9)

Model claude-opus-5-5. Tree `b103-inc9` (sole writer), start tip `891d00f7`. RED base `30819c7e` (Inc 8 final +
group B); the "before the fix" tree of each ruling is the commit before it. Runner scratch `~/work/zq-e4-9w-int/`
(HT-02 env, HOME basename as ruled, `-n 2`, `timeout 300`, LARGE files `timeout 900`, `s19_app.__file__` first in
every transcript). Host load 3-10 during the runs (shared runner): no timing result is decided here (HT-08).

## State / next step
- **I9b (continuation, tip `8e8787a4` -> see §I9b):** the 7 new RED nodes are GREEN (test side, all six; none is a
  code defect of this increment), fresh-clone battery of the final product tree GREEN except the w_jobs LARGE nodes
  (§I9b w_jobs) and the three base-identical law failures, trace_check 2 gaps (Inc 8's `definition_sheet.py`, EVID).
  Next: E5.
- (I9, superseded by §I9b below) Done: merge (step 1), rulings F-M9-1, F-W1, C9b dev. 3, T9b F-6 (RED -> GREEN below), wording list, case fold,
  trace_check.
- Done: four widget code fixes (step 3 rows 3-6, commit `f29249e6`), GREEN of every non-LARGE file.
- Final run on a fresh bundle clone of `f29249e6` (+ `main`): see §Final. **Not GREEN yet: 4 Inc 8 nodes, 1 key-bar
  law node and 2 suite_hygiene nodes are new failures (below). Stopped here on context (brief §Context discipline).**
- **Next step (successor):** (1) Inc 8 `s1` 36 and 23: test side - R-PE-BENCH.3/4 registers the curve, map and array
  kinds, so drop `curve`, `map`, `array` from 36's fallback loop and check `mark is None` on Inc 8's own kinds only
  in 23 (RED now, GREEN after; requirement-backed old-test change, integrator card rule 2). (2) Inc 8 AT i8_1 / i8_7
  `could not select DISPLAY_0001: selected CURVE_DEF_0001`: diagnose (Enter or an arrow on a bench row now belongs to
  the bench; check which key the AT driver presses on CURVE_DEF_0001). (3) `b97_key_bar::test_tc_b97_69_page_keys_do_nothing_where_disabled`:
  diagnose against the bench's pageup/pagedown bindings (`check_action` False off the bench) - compare with base.
  (4) `suite_hygiene::test_r_tst_002_every_timing_arm_carries_serial_timing`: T9b's timing nodes (20_1, 23_2, 28_2,
  29_1, 29_2, 82_1) need the `serial_timing` marker (test side). (5) `r_tst_040_041`: T9b's upper timing bounds must be reported (test side, with (4)). (6) rerun w_jobs LARGE nodes on a quiet host.

## Step 1 - merge
`403ea4e4` = `git merge --no-ff b103-inc9-tests` (T9b `dbb25068`); `steps.log` conflict kept both sides in time order
(M9 22:06 / 22:18, T9b 22:38, C9b 22:40, M9 22:55).

## Step 2 - runs (RED with the base tree as cwd, GREEN with this tree)

| Run | Tree | Result |
|---|---|---|
| `g1-*` | merge `403ea4e4` | i 3 passed; a9 22 failed / 7 passed; w_keys 19 failed; w_select 11 failed / 2 passed; w_stage 9 failed / 1 passed; w_jobs 7 failed / 3 passed (654 s) |
| `g2-*` | `b0f27006` (rulings + the driver fix) | i 3 passed; a9 1 failed / 28 passed (70_4); w_keys 19 passed; w_select 2 failed / 11 passed (9_3, 22_1_and_2); w_stage 11 passed; w_jobs 5 failed / 5 passed (528 s: 20_2, 26_2, 29_1, 29_2, 82_1 never got LARGE's values) |
| `g4-*` | `f29249e6` content (fixes 3-6) | group B five files 211 passed (207 + the 4 F-M9-1 nodes); w_jobs 6 passed / 4 failed (542 s, load 9.6-10.8): 20_2 GREEN (fix 6); 29_1 `right 2.205 s, left 2.518 s`, 82_1 `slowest press 5.617 s` (timing, load-sensitive, unverified, HT-08); 29_2 `the preview arrived after 0 presses: the arrival was not exercised` (the test's own instrument control, see open items); 26_2 `did not settle within 240 s: LARGE's values` (decode under `tracemalloc` at load 10; not decided) |
| `g3-*` | fixes 3-5 (working tree) | a9 29 passed; w_select 13 passed; w_stage 11 passed; w_keys + i 22 passed; w_jobs `-k 20_2` 1 failed (`did not settle within 120 s: LARGE's values`) |

RED on base `30819c7e` for these files is T9b's (`E4-test-w.md`: group I 3 behaviour REDs, the rest absence REDs:
`bench_sheet` / `stage_record` do not exist on base). Not repeated here: an absence RED proves no behaviour.

## Step 3 - failures (cause, side, requirement)

| # | Node(s) | Cause | Side | Requirement |
|---|---|---|---|---|
| 1 | 21 a9, 19 w_keys, most w_select / w_stage / w_jobs nodes (`could not select <row>`, `Enter did not give the bench ... the focus`) | the driver `pick` pressed the arrows with the focus outside the sheet (the screen opens with the focus elsewhere); Inc 8's key tests focus `#patch_sheet_body` first | test (`tests/support/b103_inc9_w.py::pick` focuses the body first) | R-PE-DEF.45 ("while the staging sheet holds the focus") |
| 2 | w_select page summaries (`████ 12`), every painted mark / New / Δ | F-W1: Inc 8's `StagingSheet._paint` called `row_line` without `state` | code (ruling, below) | R-PE-BENCH.10 ... .19 |
| 3 | `a9::test_r_pe_bench_70_4_...` | alt+s on MAP_DEF_0001 during VAL_BLK_DEF_0001's held record encode was refused `still decoding`: re-selecting MAP queues its decode behind the held record (one worker), and `action_stage_record` refused on `job == "decode"` although MAP's values were kept (R-PE-BENCH.9). EX-Q1 (graph, E3R2 R2-01) has this exact stage succeed, so no route reached it | code (`action_stage_record` refuses only while the row has no values) | R-PE-BENCH.70/4, EX-Q1; R-PE-BENCH.27 kept for a row with no values (27/1, 27/2 BIG) |
| 4 | `w_select::test_r_pe_bench_9_3_...` | `show_page` dropped a state only when the name left the picker's `definitions`, which is the whole population (`A2LParameterPicker.definitions`), so a filtered-out row kept its state | code (drop states of names not among the shown rows) | R-PE-BENCH.9/3, CTX bench state lifetime ("a shown page's definitions no longer hold the row") |
| 6 | `w_jobs` 20_2, 26_2, 29_1, 29_2, 82_1 (LARGE's values never arrive) | instrumented run (`diag3`): the image load's `set_document` requeues LARGE's decode; the panel's `show_page` 1 s later bumps the selection key, so the 46 s decode (load 10) ends stale and is dropped; the row is still selected, Inc 8's re-posted SelectionChanged is a no-op for it (E3A-11), and nothing asked for the decode again | code (`_job_done`: a stale decode of the row still selected goes back to the slot, as C9b's stale summary does) | R-PE-BENCH.20/2 ("shows its values when the decode ends"); R-PE-BENCH.22 kept (a row no longer selected is not requeued) |
| 5 | `w_select::test_r_pe_bench_22_1_and_2_...` | every "decode" job made two I-2 decodes (current and staged over the overlay); the graph's job is one decode over the source view (`_run_job`), the staged decode its own job | code (`_staged_pair`: the second decode only when a snapshot entry falls inside the record, else the staged values are the current ones) | R-PE-BENCH.22/2, graph `_run_job`; also halves LARGE's decode work (R-PE-BENCH.28/2) |

## Step 4 - rulings (P-070)

- **F-M9-1 (DF-04 a, R-PE-BENCH.38):** new `canvas_shape(width, grid, origin, room)` in `definition_bench_view.py`
  reserves four lines, and one more while the window line shows; `bench_detail` and the widget's `_bench_geometry`
  both read it (one rule, so the cursor window and the paint agree). Test
  `test_b103_inc9_b_detail.py::test_r_pe_bench_38_6_the_bytes_line_stays_last_while_the_window_line_shows[8,12,20,30]`
  (LARGE at 118, MAP_DEF_0001 at 20, CURVE_DEF_0001 at 13). RED on `403ea4e4` (`red-fm9-1`, 4 failed:
  `('LARGE', 8, ' s  Set   d  +Δ ...')` - the last line is the tool row); GREEN on `21e499dd` (`g2-fm9`, 4 passed).
- **C9b F-W1 (DF-04 a):** `StagingSheet._paint` passes `self.states.get(item.name)` as `row_line`'s existing 6th
  argument. **This edits an Inc 8 file (`patch_editor/sheet.py`) inside `b103-inc9`; it reaches Inc 8 at the batch
  merge.** No I-8.x signature changes. Test
  `test_b103_inc9_w_stage.py::test_r_pe_bench_15_16_18_the_painted_row_shows_mark_new_count_and_delta_after_an_apply_and_a_stage`
  (220x60). RED without the line (`red-fw1`: `▶ VAL_BLK_DEF_0001  VAL_BLK  6 values ...`, `assert ' ' == '◆'`);
  GREEN with it (`g2-fw1`, 1 passed).
- **C9b F-W2:** MINOR, no change; for the batch close (P-026): `op_line` assumes a state; the widget guarantees one.
- **C9b deviation 3:** `_chart_geometry`, `_grid_geometry`, `_grid_rows_shown` -> `chart_geometry`, `grid_geometry`,
  `grid_rows_shown`; callers: the view itself (the widget now reads `canvas_shape` instead); no test read them.
- **T9b F-6:** `EXPECTED_SCANNED_TEST_FILES` 335 -> 342: seven files added (`git diff --name-status 30819c7e`:
  six `tests/test_b103_inc9_{a9,i,w_jobs,w_keys,w_select,w_stage}.py` + `tests/support/b103_inc9_w.py`).

## Step 4b - wording (DF-04 b), commit `9a930853`

Applied to `01-requirements.md`, `02-test-cases.md`, `codewire/graph-inc9.md` (meaning unchanged):
W-1 (52 threshold and 52/1: second apply replaces; 70 threshold: the EX-C1 bytes are a state's), W-2 (15, 15/3, EX-C1: "a bench edit of 40000 on points 1 and 3",
a state), W-3 (30, 30/3), W-4 (CTX result: v is the current value), W-5 (16, 16/2, graph: `5.1 staged`), W-6 (93,
93/1, EX-H1..H4, op_line example: 294 characters), W-7 (CTX chart look, R-PE-BENCH.19, EX-N2, chart_canvas: `?` on the
chart's bottom row), W-9 (CTX chart look: labels right-aligned in 8 cells, then one space), T9b F-1 (70/3: points
1..3, whole record), F-2 (EX-Q2: E2 = {(1,1): `-18.8`}, E1 to undo), F-3 (EX-F7, 77/3: factors 0.05 / 0.025 of
CM_DEF_FINE), F-4 (49 threshold: page keys keep the panel's scroll), C9b graph wording (page key / selection key,
the slot of one decode and one preview, `preview = "encoding"`).

**Not applied (listed for the orchestrator):**
- **W-8** (R-PE-BENCH.21 / CTX detail of a refused decode): adds a behaviour (`✗ refused: <message>` in place of the
  `decoding` line); a requirement change, not wording.
- `evidence-e1/cases.py` still holds the earlier case texts (regenerating the case table would undo the wording).

## Step 5 - case fold
70 rows of `02-test-cases.md` filled from `02-test-cases-W.md` (shorthand `...::`, "the same", `44/1 ... 44/5`,
`74/1 ... 74/3` expanded), plus 16/1-3 from group B's tests and the F-W1 test; no row left with `—`.

## Step 6 - trace_check (PC, `python -I -B <skill>/trace_check.py --req .../inc-9/01-requirements.md --base 40f0f202 --src s19_app`, at `9a930853`)
```
SLICE  s19_app/tui/app/patch.py changed since 40f0f202 and no requirement file names it
SLICE  s19_app/tui/definition_bench.py changed since 40f0f202 and no requirement file names it
SLICE  s19_app/tui/definition_bench_view.py changed since 40f0f202 and no requirement file names it
SLICE  s19_app/tui/definition_sheet.py changed since 40f0f202 and no requirement file names it
SLICE  s19_app/tui/screens_directionb/patch_editor/bench_sheet.py changed since 40f0f202 and no requirement file names it
SLICE  s19_app/tui/screens_directionb/patch_editor/layout.py changed since 40f0f202 and no requirement file names it
SLICE  s19_app/tui/screens_directionb/patch_editor/panel.py changed since 40f0f202 and no requirement file names it
SLICE  s19_app/tui/screens_directionb/patch_editor/sheet.py changed since 40f0f202 and no requirement file names it
SLICE  s19_app/tui/services/change_service.py changed since 40f0f202 and no requirement file names it
EVID   no 04-validation.md beside .dev-flow/2026-11-05-batch-103/inc-9/01-requirements.md
trace_check: 1 US, 82 active requirements (1 withdrawn), checks run: US, CASE, TEST, SLICE, EVID, 10 gap(s)
```
- TEST: 0 (W9's 31 TEST gaps are closed by T9b's files and the fold).
- SLICE x9 (finding): seven Inc 9 files (`definition_bench*.py`, `bench_sheet.py`, `change_service.py`, `app/patch.py`,
  `panel.py`, `layout.py`) are named by no requirement's Base cell; `sheet.py` is F-W1 (an Inc 8 file);
  `definition_sheet.py` changed only through the Inc 8 E5 re-merge `30819c7e` (Inc 8's own trace). Proposal (the Inc 8
  trace-ruling form, not applied: the Base cells are the orchestrator's): "code `<file>` (E4 trace)" in R-PE-BENCH.10
  (`definition_bench.py`), .3 (`definition_bench_view.py`, `bench_sheet.py`), .70 (`change_service.py`, `app/patch.py`),
  .1 (`panel.py`, `layout.py`), .15 (`sheet.py`).
- EVID: expected before E5.

## Final - fresh bundle clone of `f29249e6` (+ `main`) under the runner scratch `fin/`
`s19_app.__file__` = `~/work/zq-e4-9w-int/fin/s19_app/__init__.py` atop each transcript. Load 4-11 (shared runner).

| Chunk | Result |
|---|---|
| `test_b103_inc9_i.py` + `_a9.py` (`f-i9`) | 32 passed |
| `_w_keys.py`, `_w_select.py`, `_w_stage.py` (`f-w`) | 43 passed |
| group B five files (`f-b`) | 211 passed |
| `_w_jobs.py` | not rerun on the clone: `g4` above (same product content), 6 passed / 4 failed (LARGE, load-sensitive) |
| Inc 8 `a1_service`, `a2_app`, `a3_help`, `s1`, `s1_detail` (`f-i8a`) | 214 passed, **2 failed**: `s1::test_r_pe_def_36_unknown_kinds_take_the_fallback_operations_with_no_editor` (`'op =' == ''`: `map` is a bench kind now), `s1::test_r_pe_def_23_i85_mark_field_none_keeps_inc8_rule_and_a_kind_mark_overrides` (`Inc 8 kinds keep their mark rule`: the bench kinds carry `mark`) |
| Inc 8 `at`, `at_help`, `p_*`, `s2_*` (`f-i8b`) | 147 passed, **2 failed**: `at::test_at_b103_i8_1_filter_page_row_formula_stage_advances_and_marks_dirty`, `at::test_at_b103_i8_7_refused_formula_stages_nothing` (`could not select DISPLAY_0001: selected CURVE_DEF_0001`) |
| laws `engine_unchanged`, `deps_seam_law` (seam law), `docs_canon`, `no_private_tokens`, `filename_markup_safety`, `id_registry` (bound 342) (`fl-1`) | 24 passed, 1 skipped |
| `tui_directionb -k tc031` (`fl-2`) | 3 passed |
| `b101_doc_hygiene` 45, `b101_help_legend_docs` 71, `report_markup_safety` 166 | passed |
| `b97_key_bar` | 37 passed, **1 failed**: `test_tc_b97_69_page_keys_do_nothing_where_disabled` (not yet diagnosed; base not run for this file) |
| `suite_hygiene` + `requirements_canon` + `address_census` (`fl-3`; base archive `bl-3`) | 96 passed, 5 failed. Same as base: `r_tst_070_2`, `canon_rows_hold_the_obligation_word_once`, `at_b83_08` (base 4 failed, the 4th `r_tst_002_2` = archive without git). **New (test side, T9b's timing nodes):** `r_tst_002_every_timing_arm_carries_serial_timing` and `r_tst_040_041_every_upper_timing_bound_is_reported` |

## I9b - continuation (claude-opus-5-5, from `8e8787a4`)

Runner scratch `~/work/zq-e4-9w-int2/` (same HT-02 env, HOME basename as ruled; `-n 0` for diagnosis, `-n 2` for
the battery). Transcripts in `evidence-e4/integrator-w2/` (redacted as above). Host load 10-13 during steps 1-3
(two other workers on the runner).

### The 7 RED nodes (cause, side, requirement)

| Node(s) | Cause | Side | Requirement | RED / GREEN |
|---|---|---|---|---|
| Inc 8 `s1::test_r_pe_def_36_unknown_kinds_...` and `s1::test_r_pe_def_23_i85_mark_field_none_...` | the test loop asserted that `curve`, `map`, `array` take the fallback and that every `_KIND_OPS` entry has `mark is None`; once the patch editor is imported (the session imports it before `s1` runs, so this fails even alone: `d-s1-alone`), `register_bench_kinds` puts the three bench kinds in the table, editable, with Inc 9's `mark` | test: 36 loops over `cuboid`, `none`, an unknown word (the fallback half unchanged); 23 checks `mark is None` on Inc 8's own four kinds | R-PE-BENCH.3 (import case: the bench kinds are in Inc 8's per-kind table, editable; Inc 9 C-9 moved the curve case out of R-PE-DEF.36); I-8.5 amendment (only Inc 8's kinds keep the R-PE-DEF.23 rule) | RED `d-s1-alone`, `d-s1-after-bench` (2 failed); GREEN `g-s1` (118 passed) |
| Inc 8 `at::test_at_b103_i8_1_...`, `at::test_at_b103_i8_7_...` (`could not select DISPLAY_0001: selected CURVE_DEF_0001`) | diagnosed with a probe (not committed): arrows move rows normally on every row; the stuck walk comes after a stage. The stage advances the selection from DISPLAY_0001 onto CURVE_DEF_0001 (a bench row) with the focus left in the input; the driver's Escape in that input gives the bench the focus (R-PE-BENCH.47), so `up` then moves the bench cursor, never the row. Not F-W1 and not the `show_page` shown-rows filter: the same two nodes fail on `21e499dd`, which has neither (`r-at-pre`) | test: `select_row` presses Escape once more when the selected row's bench holds the focus (the operator's way back, R-PE-BENCH.46) | R-PE-BENCH.46, .47; R-PE-DEF.45, .48 kept for non-bench rows | RED `d-at` (tip), `r-at-pre` (`21e499dd`); GREEN `g-at` (11 passed) |
| `b97_key_bar::test_tc_b97_69_page_keys_do_nothing_where_disabled` (`did not settle: A2L loaded`) | the 60 s wall wait for the demo A2L load expired at `-n 2`, load 10; no bench code runs there. Base `30819c7e` and tip both pass at `-n 0` (44.3 s / 46.7 s call, load 11-12), and the whole file passes at `-n 2` on the final clone | none (load-sensitive wait, HT-08); no change | LLR-150.4 | `k69-base`, `k69-tip` 1 passed each; `f-k97` 38 passed |
| `suite_hygiene::test_r_tst_002_every_timing_arm_carries_serial_timing` | T9b marked the timing nodes through a module alias `timed = pytest.mark.serial_timing`; the census reads the mark from the decorator's attribute (`_has_serial_timing_mark`), so an `ast.Name` is invisible to it. With literal marks the law's other half then refused 28_2: its bound is peak RSS (MiB), not time, so it is not a timing arm | test: literal `@pytest.mark.serial_timing` on 20_1, 23_2, 29_1, 29_2, 82_1; 28_2 keeps `slow` only | R-TST-002 | RED `integrator-w/fl-3.txt` (I9, `f29249e6`); GREEN `g-hyg` (2 passed) |
| `suite_hygiene::test_r_tst_040_041_every_upper_timing_bound_is_reported` | the 0.5 s bounds were compared raw | test: each of the five 0.5 s bounds goes through `report_margin(label, measured, KEY_LIMIT_S)` (returns the bound unchanged; 82_1's `len(times) >= 1` became its own assert, same conditions) | R-TST-040, R-TST-041 | RED `integrator-w/fl-3.txt`; GREEN `g-hyg` |

No product code changed in I9b. Old-test changes are requirement-backed (integrator card rule 2); no assertion was
weakened: every removed case is a case the requirement now gives to another row.

### Final battery - fresh bundle clone of `62051c7c` (`b103-inc9` + `main`) under `fin/`
`s19_app.__file__` = `~/work/zq-e4-9w-int2/fin/s19_app/__init__.py` atop each transcript. Load 5-13.

| Chunk | Result |
|---|---|
| Inc 9 group B five files (`f-i9-b`) | 211 passed |
| `_a9.py` + `_i.py` (`f-i9-ai`) | 32 passed |
| `_w_keys.py`, `_w_select.py`, `_w_stage.py` (`f-i9-w`) | 43 passed |
| `_w_jobs.py -m "not serial_timing"` (`f-i9-jobs`) | 4 passed, 1 failed: 26_2 `did not settle within 240 s: LARGE's values` (decode under `tracemalloc`, load 11; see w_jobs below) |
| Inc 8's 14 files (`f-i8`) | 365 passed |
| laws `engine_unchanged`, `deps_seam_law`, `docs_canon`, `no_private_tokens`, `filename_markup_safety`, `id_registry` (`f-law1`) | 24 passed, 1 skipped |
| `tui_directionb -k tc031` (`f-law2`) | 3 passed |
| `b101_doc_hygiene`, `b101_help_legend_docs`, `report_markup_safety` (`f-law3`) | 282 passed |
| `b97_key_bar` (`f-k97`) | 38 passed |
| `suite_hygiene`, `requirements_canon`, `address_census` (`f-law4`) | 98 passed, 3 failed, all three base-identical (I9 `bl-3`): `r_tst_070_2` (Inc 8 records only), `canon_rows_hold_the_obligation_word_once` (R-A2L-DEF.153, R-PICKER-CORRECT.004/.008), `at_b83_08` (`test_b103_a2l_refresh.py`, `test_b103_picker_model.py`; not Inc 9 files). `r_tst_002_2` passes on a clone with git |

### w_jobs timing (HT-08)
Rule of the brief: run only at a 1-min load < 2, `-n 0`, `uptime` before each node; 45 min from 00:33. Readings
(1-min, every 60 s, 00:33-01:10): 10.95 10.02 10.27 10.28 9.86 10.58 12.01 13.09 13.34 13.37 13.09 12.76 12.15
11.55 11.59 11.00 10.81 10.46 10.72 9.74 10.35 10.08 10.13 9.67 8.34 8.22 8.16 9.09 7.43 6.19 5.88 6.10 5.47 3.43
2.55 2.30 **1.71** (01:10). One quiet reading; the other workers resumed during the first node.

| Node | Load before | Result |
|---|---|---|
| 26_2 (`q-26_2`) | 1.75 (01:10:11); 3.25 at its end | failed: `did not settle within 240 s: LARGE's values`. **Not load: an instrument finding (below).** |
| 29_1 | 3.25 (01:14:39) | **not decided (load)**: not run |
| 29_2 | 3.25 | **not decided (load)**: not run; I9's note stands (its arrival control needs a `Gate`) |
| 82_1 | 3.25 | **not decided (load)**: not run |

**Finding F-I9b-1 (26_2, test side; for the tester / orchestrator; no change made):** the test starts `tracemalloc`
before LARGE's decode, and tracing every allocation of the 1,048,576-value decode makes it about 8.5 times slower.
Probe `probe-262.py.txt` (scratch only, never in `tests/`; transcript `p-262`), same tree, same driver: LARGE's
values after 49.3 s untraced (load 3.6), 418.9 s traced (load 5.4). The 240 s wait cannot be met on this runner, and
no record shows 26_2 GREEN. The product decodes and shows the values; the memory claim (R-PE-BENCH.26/2,
`after <= 1 MiB`) is never reached. Proposal: the decode wait must cover the traced decode (about 7 min at load 5,
so `slow` and a quiet host), or the tester picks a retained-memory instrument that does not trace the decode; the
1 MiB bound and the control stay.

### trace_check (PC, at `62051c7c`)
```
SLICE  s19_app/tui/definition_sheet.py changed since 40f0f202 and no requirement file names it
EVID   no 04-validation.md beside .dev-flow/2026-11-05-batch-103/inc-9/01-requirements.md
trace_check: 1 US, 82 active requirements (1 withdrawn), checks run: US, CASE, TEST, SLICE, EVID, 2 gap(s)
```
- SLICE x8 closed by I9's proposal, applied (`62051c7c`): file names appended to the Base cells of R-PE-BENCH.1
  (`panel.py`, `layout.py`), .3 (`definition_bench_view.py`, `bench_sheet.py`), .10 (`definition_bench.py`), .15
  (`sheet.py`, F-W1), .70 (`change_service.py`, `app/patch.py`), as "code `<file>` (E4 trace)"; no text changed.
- SLICE `definition_sheet.py`: identical to `30819c7e` (`git diff 30819c7e -- <file>` empty); its change is Inc 8's
  E5 re-merge, traced by Inc 8. Not Inc 9's to name.
- EVID: expected before E5.

## Open items
- (I9b) The 7 failures above: GREEN (§I9b).
- (I9b) w_jobs: 29_1, 29_2, 82_1 not decided (load; one reading < 2 in 45 min); 20_1 and 23_2 passed in I9's
  runs at load 10 but are timing arms, so also undecided (HT-08). 26_2: finding F-I9b-1 (traced decode vs 240 s
  wait). 29_2's arrival control: tester to hold the encode with `Gate` (I9). 28_2 is not a timing arm (RSS).
- Readings decided here (DF-02), orchestrator to confirm: R-PE-BENCH.27 "values are decoding" = the row has no values
  (a row with kept values stages while its re-decode waits, EX-Q1); a stale decode of the selected row is requeued;
  a decode job decodes the staged record only when an entry falls inside it.
- Room 2-4 with a window line: the bytes line is still cut (no canvas row left to give); no requirement states it.
- W-8 (requirement change, not applied; P-074: provisional keep as built, P-026); SLICE: applied by I9b; `evidence-e1/cases.py` texts behind the table.
- F-W2 MINOR -> P-026. `patch_editor/sheet.py` (Inc 8) changed by F-W1: reaches Inc 8 at the batch merge.

## For the next workers (<= 3 lines)
- Mutant worker: new code = `canvas_shape` (room - 5 branch; 38_6 must kill it), `_staged_pair`, the `values is None`
  stage check, `show_page`'s shown-rows filter, the stale-decode requeue, `sheet.py`'s `state` argument (15_16_18).
- Inc 8 `s1` 36/23 and AT i8_1/i8_7 are GREEN now (I9b, test side); skip w_jobs timing arms on a loaded host and 26_2 until F-I9b-1.

Transcripts (redacted: `~`, `<user>`, `<runner-home>`, `<host>`) in `evidence-e4/integrator-w/`. Runner scratch
`~/work/zq-e4-9w-int/` deleted (explicit list: run.sh fin.sh ov.tar i9.bundle base g1 g2 g3 g4 redfm redfw fin out home x tmp).

I9b: transcripts in `evidence-e4/integrator-w2/`. Runner scratch `~/work/zq-e4-9w-int2/` deleted (explicit list:
run.sh fin.sh i9b.bundle base tip pre fin out home x tmp).
