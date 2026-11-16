# Inc 9 widget / A9 / I - mutant run, F-I9b-1 and timing nodes (MW9, relevo-11)

Model claude-sonnet-5-5 (tester role). Tree `b103-inc9`, start tip `eb911581`. Product code: unchanged (0 lines of `s19_app/`
edited; the mutants ran on COPIES, HT-09). Runner scratch `~/work/zq-mw9/` (HT-02 env, HOME basename as ruled (`<runner-home>`),
`s19_app.__file__` printed atop every transcript, `-n 2`, nodes at `-n 0`), deleted at the end (explicit list below).
Transcripts, spec, drivers and logs: `evidence-e4/mutants-w/` (redacted: `~`, `<user>`, `<host>`, `<runner-home>`).

## State / next step
- Step 1 merge GREEN. Step 2 (F-I9b-1): the node is split and RED/GREEN-shown; it is **RED on the tree for a product
  reason** (F-MW9-1, below). Step 3: 91 mutants, 87 killed, 4 survive as argued equivalents, 0 timeout. Step 4: the timing
  nodes were decided on a quiet host (load < 2 before each); two of them fail for a product reason (F-MW9-2).
- **Next (orchestrator):** rule F-MW9-1 / F-MW9-2 / F-MW9-3 below (software-dev for the code ones), then E5.

## Step 1 - merge of `b103-inc8`
`358f1057` = `git merge --no-ff b103-inc8` (tip `6c4fd21f`): **no conflict** (the two `steps.log` files differ by path, `inc-8/` and
`inc-9/`); the only code-side file it brings is `tests/test_b103_inc8_p_layout.py` (+99 lines, no product code). On the merged
tree (`rtx`, fresh bundle clone, load 1.97 -> 2.68): `test_b103_inc8_p_layout.py` + `test_suite_hygiene.py::test_r_tst_070_2_...`
= **32 passed** (`transcripts/m1.txt`). `r_tst_070_2` is GREEN here (it was one of I9b's three base-identical failures; Inc 8's
`6c4fd21f` redacted its records).

## Step 2 - F-I9b-1: node 26_2 split (ruling P-077)
`tests/test_b103_inc9_w_jobs.py::test_r_pe_bench_26_2_a_deselected_large_row_keeps_none_of_its_values` (commit `876f22d8`):
- **Run 1, untraced, time bound:** LARGE's values must show within `DECODE_WAIT_S = 240` s (unchanged), then SMALL_BLK is
  selected and LARGE's `values` / `staged` must be None.
- **Run 2, traced, memory bound:** the same decode under `tracemalloc` with only a hang guard (`TRACED_WAIT_S = 1800`, not a
  requirement); `held > 1 MiB` (control) and `after <= 1 MiB` (unchanged) after deselecting.
- **Instrument decision (F-MW9-3, needs your confirmation):** run 2 counts the allocations whose site is in `s19_app/` (a
  `tracemalloc` snapshot filtered on `*/s19_app/*`), because the first design - the whole traced total, bound unchanged - was
  measured at **7.8 MiB retained** (`transcripts/g262.txt`) and the probe (`transcripts/probe262.txt`, scratch script
  `probe262.py`) splits it: 4.07 MiB are `definition_bench_view.py:392` (the axis labels, 65,576 strings) and about 3.8 MiB are
  Textual's own message queue and caches, which grow with the wait of a 7-minute traced decode whatever the row. The failure
  message prints both numbers. The bound itself stays 1 MiB.

| Run | Tree / mutant | Result | Transcript |
|---|---|---|---|
| ORIGINAL node (one traced run, 240 s wait) | `eb911581` | RED `did not settle within 240 s` (I9b `q-26_2`; not repeated) | `inc-9/E4-integration-w.md` |
| split node | tree `876f22d8` (quiet host, load 1.62 -> 2.19) | run 1 passed; **RED**: `4.0 MiB allocated by s19_app are still retained after deselecting LARGE (all allocations: 7.8 MiB)` | `transcripts/t-test_r_pe_bench_26_2.txt`, `g262b.txt` |
| split node | FIX-SIMULATION on a copy (`tfix`: the deselect also drops `labels` and `strip`) | **GREEN**, `1 passed in 471.60 s` (load 2.62 -> 4.32) | `logs/m262.jsonl` |
| split node | mutant `t26` (a decoded record stays referenced after the deselect; `values` still None) | **RED on the memory bound only**: `12.3 MiB allocated by s19_app ... (all allocations: 16.1 MiB)`, run 1 passes | `transcripts/m262b/t26.txt` |
| split node | mutant `t26b` (the decode sleeps 300 s) | **RED on the time bound only**: `did not settle within 240 s: LARGE's values` | `transcripts/m262b/t26b.txt` |

Neither bound is loosened. The node is `slow` and takes 7-9 minutes.

**F-MW9-1 (product, R-PE-BENCH.26/2, for `software-dev`):** after LARGE is deselected, `ArrayBenchSheet.on_staging_sheet_selection_changed`
clears `values`, `staged` and `axes` only; `labels` (about 4 MiB for LARGE: 65,536 row labels) and `strip` stay in the state. The
requirement's threshold is "LARGE's values are not retained (<= 1 MiB above the sheet before LARGE)". Either the code clears them
(the fix-simulation shows the node GREEN) or the requirement is ruled to count `values` alone; the test is correct for the first.

## Step 3 - mutants (HT-09: copies only; spec `mw9_spec.py`, driver `mw9_run.py`)
Method: per mutant one source edit on a COPY (`mt*` trees under the scratch, the pristine tree untouched; the driver checks
that the old string occurs exactly once and that the result parses with `ast` before running), then the six Inc 9 widget files
(`_a9`, `_i`, `_w_keys`, `_w_select`, `_w_stage`, `_w_jobs`) with `-m "not serial_timing and not slow" -x -n 2`, `timeout 900`;
the `canvas_shape` mutants also ran against the five group B files. **Killed** = a node fails; **survived** = all pass;
**timeout** = rc 124 (none); **error** = none. Baseline of the set: 77 passed in 284 s (`transcripts/base-sweep.txt`).
Rows whose only nodes are timing or LARGE (`slow`, `serial_timing`) were excluded from kill counting: **R-PE-BENCH.20/1, .29, .82**
(timing), **.20/2** (LARGE; the stale-decode requeue it guarded is now killed by deterministic nodes).

**Result: 89 code mutants + 2 for node 26_2 = 91; 87 killed, 4 survive (all four argued equivalent below), 0 timeout, 0 error.**
Of the 89, **54 were killed by the original nodes and 35 survived them**; of those 35, 30 are killed by new nodes
(`tests/test_b103_inc9_w_mutants.py`: 23 functions, 29 items), 1 (`w15b`) by an Inc 8 node, and 4 stay as argued equivalents
(54 + 30 + 1 = 85 killed, plus `t26` and `t26b` = 87).

**Survivors and their tests** (RED on the mutant, GREEN on the tree - `transcripts/nx|ny|nz|nc|ns/<id>.txt` are the RED outputs, `transcripts/green-mut4.txt` the GREEN run of the new file: 29 passed, `f-new.txt`: 104 passed with the other five widget files):

| New node (`test_b103_inc9_w_mutants.py::`) | Kills | What was missing |
|---|---|---|
| `test_r_pe_bench_22_3_...` / `22_4_...` / `22_5_...` | w22a, w22b, w22c, w22d | the stale-decode requeue and the token check were masked by the generation bump the image load makes (the page opens with the first row selected; its decode starts at generation 1); the new nodes settle the generation first and assert only the selection key moved |
| `test_r_pe_bench_24_2_...` | w24 | a summary of an older page was never painted onto a row of the new page (the old test only looked at a row that left the page) |
| `test_r_pe_bench_25_3_...` | w25c | the staged cells of a row that is NOT selected after a raw entry (Inc 8's `●` is document-driven and proved nothing) |
| `test_r_pe_bench_27_3_...` | w27a | applying a tool to a row whose decode was refused (no values, no job) |
| `test_r_pe_bench_6_2_...` | w06 | the stage kept the selection only on the last row of the page, where the advance has nowhere to go |
| `test_r_pe_bench_48_3_...`, `49_3_...` | w48a, w49c | alt+s from an op input the bench does not hold the focus on; alt+s with the focus off both |
| `test_r_pe_bench_5_2_...`, `5_3_...` | w05, c02, c05 (and w22c) | the cursor stays on a painted row down a tall grid; the windowed LARGE bench fills its room and the window line counts the painted rows (`canvas_shape`: the original `38_6` is an upper bound) |
| `test_r_pe_bench_66_5_...`, `66_6_...` | w66c, w66d | undoing the only edit clears the bytes line; `encoding ...` shows while the preview encode is held |
| `test_r_pe_bench_70_5_...` | w28b, w70a, (s04, s06) | no bench job starts between the encode ending and the app's write (white box: the request is made inside the app's handler and the sheet's `_active_job` is read, because the UI thread cannot also run the worker there) |
| `test_r_pe_bench_70_6_...` | w70d | a second alt+s queued before the first record starts stages the newer edit |
| `test_r_pe_bench_74_2_...`, `78_3_...` | w74b, w78a | the app handler's span and generation checks, driven by the sheet's own request message (the interface), control = the same message unchanged stages |
| `test_r_pe_bench_62_6_...` | w51 | an apply refusal reaches the status line (`'abc' is not a number.`, and `\x1b` + 300 x `9` echoed as U+FFFD + 255 x `9` + `...`) |
| `test_r_pe_bench_92_2_...`, `92_3_...`, `92_4_...` | w92d, w92b, w92a | the name echo (256 + `...`) in three Inc 9 statuses (stale record, still decoding on stage, changed in the A2L) |
| `test_r_pe_bench_22_6_...`, `28_3_...` | s02, s05, s08, s03, s04, s06 | `_staged_pair`: the staged delta of a selected row over a raw entry (oracle = I-2 decodes), and no second decode for an entry that touches or is far from the record |

**Argued equivalent (4):** `w22e` (the stale requeue appended instead of inserted first: two independent queued jobs that both end before the sheet settles), `w25b` (the `_staged_differs` clause for a row that is not selected: every reader of `staged` is gated by `row.is_staged`, which an undo clears, and the next selection decodes again), `w51b` (`event.stop()` on the apply request: nothing above the sheet handles it), `s07` (`staged` None instead of the current values for a row no entry overlaps: readers need `row.is_staged`, which needs an overlapping entry). `w15b` (`sheet.py` pending default) is killed by Inc 8's `test_b103_inc8_s2_sheet_rows.py::test_r_pe_def_24_3_...` (the Inc 9 tests alone do not kill it; `transcripts/w15b/w15b.txt`).

**Not mutated (gaps, named):** R-PE-BENCH.7 and .21 (group B half done in M9), .20/1 and .23/2 (UI-thread claims, timing), .29 and .82 (timing), .80 and .81 (Inc 8's `_stage_encoded`: undo step, dirty flag, partial overlap), .91 (control characters), .2 (withdrawn). The `canvas_shape` mutants and `c02`/`c05` are product code of `definition_bench_view.py`; the tool rows .52-.67 and the cell rows .10-.19 are M9's.

**Limits of the run:** the sweep ran at host load 3-10 (three shards of `-n 2` plus other workers; HT-08 asks for a quiet host). Kills therefore rest on assertions, not waits: for the new nodes the failing assertion is in the saved outputs; for the original-node kills only the first failing node's name was kept, so a kill by a `did not settle` wait under load cannot be excluded for those 54 (the same nodes pass at load 1.8 in `f-new.txt`). `-x` with xdist reports the first failure that finished, so the "killing node" column is not always the node the requirement row names.

### Mutant table
| Id | Requirement / code | File | Original nodes | Final | Killing node (or note) |
|---|---|---|---|---|---|
| w01 | R-PE-BENCH.1 subtitle back to Inc 8's | layout.py | killed | killed | test_r_pe_bench_1_1_the_sheet_window_subtitle_names_the_bench[118x54] |
| w03a | R-PE-BENCH.3 editable=True (not a callable) | bench_sheet.py | killed | killed | test_r_pe_bench_70_1_set_10_stages_the_whole_record_with_its_symbol |
| w03b | R-PE-BENCH.3 detail = Inc 8's no-editor tail | bench_sheet.py | killed | killed | test_r_pe_bench_6_1_and_def_60_5_a_record_stage_keeps_the_row_selected_and_its_bench_ |
| w03c | R-PE-BENCH.3 array kind not a bench kind | bench_sheet.py | killed | killed | test_r_pe_bench_70_1_set_10_stages_the_whole_record_with_its_symbol |
| w03d | R-PE-BENCH.3 label stays Inc 8's | bench_sheet.py | killed | killed | test_r_pe_bench_3_4_after_import_the_three_bench_kinds_are_registered |
| w05 | R-PE-BENCH.5 geometry room not reduced by the window line (widget) | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_5_2_the_cursor_stays_on_a_painted_row_while_it_walks_down_a_tall_grid |
| w06 | R-PE-BENCH.6 stage advances the selection | patch.py | survived | killed (new node) | test_r_pe_bench_6_2_a_record_stage_keeps_the_selection_on_a_row_that_has_another_row_below_it |
| w09a | R-PE-BENCH.9 fresh state at every selection message | bench_sheet.py | killed | killed | test_r_pe_bench_70_4_a_second_stage_asked_during_the_first_ones_held_encode_is_staged |
| w09b | CODE show_page: shown-rows filter never drops | bench_sheet.py | killed | killed | test_r_pe_bench_9_3_a_page_without_the_row_drops_its_state |
| w09c | CODE show_page: shown-rows filter drops the shown | bench_sheet.py | killed | killed | test_r_pe_bench_9_1_a_filter_keystroke_that_keeps_the_row_keeps_its_state |
| w09d | CODE show_page: filter by the whole population (pre-F-M9 reading) | bench_sheet.py | killed | killed | test_r_pe_bench_9_3_a_page_without_the_row_drops_its_state |
| w20 | R-PE-BENCH.20 decode not requested at selection | bench_sheet.py | killed | killed | test_r_pe_bench_70_1_set_10_stages_the_whole_record_with_its_symbol |
| w22a | R-PE-BENCH.22 stale decode painted (decode token not checked) | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_22_3_a_decode_made_stale_by_the_selection_key_alone_runs_again_for_the_selected |
| w22b | CODE stale-decode requeue: any row, not only the selected | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_22_4_a_stale_decode_of_a_row_no_longer_selected_is_not_run_again |
| w22c | CODE stale-decode requeue removed | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_22_3_a_decode_made_stale_by_the_selection_key_alone_runs_again_for_the_selected |
| w22d | CODE stale-decode requeue: queues a second decode | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_22_5_a_stale_decode_of_the_selected_row_adds_no_second_queued_decode |
| w22e | CODE stale-decode requeue at the back of the slot | bench_sheet.py | survived | survived, argued equivalent | order of two independent queued jobs (decode, preview) that both end before the sheet settles; no settled output differs |
| w23a | R-PE-BENCH.23 summaries not in page order | bench_sheet.py | killed | killed | test_r_pe_bench_23_1_the_page_is_summarised_off_the_ui_thread_in_page_order |
| w23b | R-PE-BENCH.23 summary of a LARGE row on page change | bench_sheet.py | killed | killed | test_r_pe_bench_22_1_and_2_a_decode_ended_after_the_selection_moved_is_discarded |
| w24 | R-PE-BENCH.24 summary of an older page painted | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_24_2_a_summary_ended_after_the_page_turned_is_not_painted |
| w25a | R-PE-BENCH.25 recompute every row on a document change | bench_sheet.py | killed | killed | test_r_pe_bench_25_2_a_raw_entry_over_one_row_marks_that_row_and_decodes_no_other |
| w25b | R-PE-BENCH.25 no recompute for a row whose staged differs (undo) | bench_sheet.py | survived | survived, argued equivalent | the delta cell and the `staged` word read `row.is_staged` (the document), which an undo clears; a stale `staged` on a row that is not selected is rebuilt by the decode job at its next selection, so every observable output is equal |
| w25c | R-PE-BENCH.25 no recompute for a row holding an entry | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_25_3_a_raw_entry_over_a_row_that_is_not_selected_gives_it_a_staged_delta |
| w25d | R-PE-BENCH.25 selected row: staged recompute dropped | bench_sheet.py | killed | killed | test_r_pe_bench_15_16_18_the_painted_row_shows_mark_new_count_and_delta_after_an_apply_and_a_st |
| w27a | R-PE-BENCH.27 apply over no values (job check only) | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_27_3_a_tool_applied_to_a_row_whose_decode_was_refused_changes_nothing_and_does_ |
| w27b | CODE stage check: none at all | bench_sheet.py | killed | killed | test_r_pe_bench_27_apply_or_stage_while_the_values_decode_shows_the_still_decoding_status[stage |
| w27c | CODE stage check: refuse while the job is a decode (pre-F-M9-1 reading) | bench_sheet.py | killed | killed | test_r_pe_bench_70_4_a_second_stage_asked_during_the_first_ones_held_encode_is_staged_too |
| w28a | R-PE-BENCH.28 several jobs at once | bench_sheet.py | killed | killed | test_r_pe_bench_78_1_an_undo_during_the_held_encode_makes_the_result_stale |
| w28b | R-PE-BENCH.28 job starts while a record hold is up | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_70_5_no_bench_job_starts_between_the_encode_ending_and_the_documents_write |
| w40 | R-PE-BENCH.40 Enter focuses the op input first | bench_sheet.py | killed | killed | test_r_pe_bench_6_1_and_def_60_5_a_record_stage_keeps_the_row_selected_and_its_bench_shown[R-PE |
| w44a | R-PE-BENCH.44 d selects Set | bench_sheet.py | killed | killed | test_r_pe_bench_44_a_tool_key_selects_its_tool_and_the_app_does_not_run[s] |
| w44b | R-PE-BENCH.44 i not bound | bench_sheet.py | killed | killed | test_r_pe_bench_44_a_tool_key_selects_its_tool_and_the_app_does_not_run[i] |
| w44c | R-PE-BENCH.44 tool action ignores the key | bench_sheet.py | killed | killed | test_r_pe_bench_44_a_tool_key_selects_its_tool_and_the_app_does_not_run[i] |
| w45 | R-PE-BENCH.45 Enter in bench focus does not reach the op input | bench_sheet.py | killed | killed | test_r_pe_bench_6_1_and_def_60_5_a_record_stage_keeps_the_row_selected_and_its_bench_shown[R-PE |
| w46a | R-PE-BENCH.46 Escape keeps the bench focus | bench_sheet.py | killed | killed | test_r_pe_bench_70_4_a_second_stage_asked_during_the_first_ones_held_encode_is_staged_too |
| w46b | R-PE-BENCH.46 Escape not bound on the sheet | bench_sheet.py | killed | killed | test_r_pe_bench_70_4_a_second_stage_asked_during_the_first_ones_held_encode_is_staged_too |
| w47a | R-PE-BENCH.47 op-input Escape leaves the bench focus off | bench_sheet.py | killed | killed | test_r_pe_bench_6_1_and_def_60_5_a_record_stage_keeps_the_row_selected_and_its_bench_shown[R-PE |
| w47b | R-PE-BENCH.47 op-input Escape does not move focus to the body | bench_sheet.py | killed | killed | test_r_pe_bench_70_4_a_second_stage_asked_during_the_first_ones_held_encode_is_staged_too |
| w48a | R-PE-BENCH.48 alt+s refused from the op input | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_48_3_alt_s_from_an_op_input_the_bench_does_not_hold_the_focus_on_still_stages |
| w48b | R-PE-BENCH.48 alt+s not bound | bench_sheet.py | killed | killed | test_r_pe_bench_70_1_set_10_stages_the_whole_record_with_its_symbol |
| w49a | R-PE-BENCH.49 cursor/page/tool/escape actions enabled without the bench focus | bench_sheet.py | killed | killed | test_r_pe_bench_49_1_off_the_bench_the_keys_reach_the_app[DISPLAY_0001-s] |
| w49b | R-PE-BENCH.49 tool action not gated | bench_sheet.py | killed | killed | test_r_pe_bench_49_1_off_the_bench_the_keys_reach_the_app[DISPLAY_0001-s] |
| w49c | R-PE-BENCH.49 stage_record enabled on any bench row | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_49_3_alt_s_off_the_bench_and_off_the_op_input_stages_nothing |
| w51 | R-PE-BENCH.51 apply path loses the refusal status | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_62_6_a_refused_operand_shows_its_status_with_the_operand_echo[abc] |
| w51b | R-PE-BENCH.51 apply request not stopped | bench_sheet.py | survived | survived, argued equivalent | `event.stop()`: the apply request has no handler above the sheet, so bubbling it changes nothing a user or the document sees |
| w66a | R-PE-BENCH.66 no preview queued on an edit change | bench_sheet.py | killed | killed | test_r_pe_bench_71_1_and_2_the_second_stage_encodes_over_the_first_one |
| w66b | R-PE-BENCH.66/.71 encode over the image, not the overlay | bench_sheet.py | killed | killed | test_r_pe_bench_71_1_and_2_the_second_stage_encodes_over_the_first_one |
| w66c | R-PE-BENCH.66 preview of an emptied edit kept | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_66_5_undoing_the_only_edit_clears_the_bytes_line |
| w66d | R-PE-BENCH.66 'encoding' placeholder not set | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_66_6_the_bytes_line_says_encoding_while_the_preview_runs |
| w70a | R-PE-BENCH.70 next job starts before the app's write (no hold) | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_70_5_no_bench_job_starts_between_the_encode_ending_and_the_documents_write |
| w70b | R-PE-BENCH.70 record_done does not release the hold | bench_sheet.py | killed | killed | test_r_pe_bench_78_1_an_undo_during_the_held_encode_makes_the_result_stale |
| w70c | R-PE-BENCH.70 record_staged never clears the edit | bench_sheet.py | killed | killed | test_r_pe_bench_25_1_undo_of_a_record_stage_removes_the_staged_dot |
| w70d | R-PE-BENCH.70 a queued record of a row keeps the first edit | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_70_6_a_second_alt_s_before_the_first_record_starts_stages_the_newer_edit |
| w72 | R-PE-BENCH.72 value word always plural | change_service.py | killed | killed | test_r_pe_bench_72_1_and_70_1_stage_record_writes_one_bytes_entry_and_words_the_status |
| w72b | R-PE-BENCH.72 shown text is the count only | change_service.py | killed | killed | test_r_pe_bench_72_1_and_70_1_stage_record_writes_one_bytes_entry_and_words_the_status |
| w73a | R-PE-BENCH.73 notices dropped | change_service.py | killed | killed | test_r_pe_bench_73_1_two_notices_make_one_line_with_the_count_of_the_rest |
| w73b | R-PE-BENCH.73 the rest counted wrongly | change_service.py | killed | killed | test_r_pe_bench_73_1_two_notices_make_one_line_with_the_count_of_the_rest |
| w73c | R-PE-BENCH.73 suffix always shown | change_service.py | killed | killed | test_r_pe_bench_73_2_one_notice_has_no_suffix |
| w74a | R-PE-BENCH.74 refusal not checked | patch.py | killed | killed | test_r_pe_bench_74_a_refused_encode_shows_its_message_and_leaves_document_and_edit_unchanged[74 |
| w74b | R-PE-BENCH.74 span check dropped | patch.py | survived | killed (new node) | test_r_pe_bench_74_2_a_record_encoded_outside_its_span_is_not_staged |
| w75 | R-PE-BENCH.75 empty edit staged | bench_sheet.py | killed | killed | test_r_pe_bench_75_1_alt_s_with_an_empty_bench_edit_says_so_and_writes_nothing |
| w76 | R-PE-BENCH.76 no A2L not checked | patch.py | killed | killed | test_r_pe_bench_76_1_no_a2l_when_the_stage_acts_says_so |
| w77a | R-PE-BENCH.77 definition compared by address only | patch.py | killed | killed | test_r_pe_bench_77_a_definition_changed_since_the_bench_was_built_is_refused[77-2-reshaped-MATR |
| w77b | R-PE-BENCH.77 definition change not checked | patch.py | killed | killed | test_r_pe_bench_77_a_definition_changed_since_the_bench_was_built_is_refused[77-1-moved-VAL_BLK |
| w78a | R-PE-BENCH.78 generation not checked | patch.py | survived | killed (new node) | test_r_pe_bench_78_3_a_request_made_for_an_older_document_is_not_staged |
| w78b | R-PE-BENCH.78 an image change does not bump the generation | bench_sheet.py | killed | killed | test_r_pe_bench_78_2_an_image_push_during_the_held_encode_makes_the_result_stale |
| w78c | R-PE-BENCH.78 a document-only change does not bump the generation | bench_sheet.py | killed | killed | test_r_pe_bench_78_1_an_undo_during_the_held_encode_makes_the_result_stale |
| w79a | R-PE-BENCH.79 stage keeps the edit | bench_sheet.py | killed | killed | test_r_pe_bench_25_1_undo_of_a_record_stage_removes_the_staged_dot |
| w79b | R-PE-BENCH.79 stage clears whatever the edit is | bench_sheet.py | killed | killed | test_r_pe_bench_79_2_an_edit_made_while_the_record_encodes_is_kept_with_its_diamond |
| w83a | R-PE-BENCH.83 no busy check | patch.py | killed | killed | test_r_pe_bench_83_1_a_session_action_running_refuses_the_stage_with_the_busy_line |
| w92a | R-PE-BENCH.92 name echoed raw in the changed-in-A2L status | patch.py | survived | killed (new node) | test_r_pe_bench_92_4_the_changed_in_the_a2l_status_echoes_a_300_character_name_in_256 |
| w92b | R-PE-BENCH.92 name echoed raw in the still-decoding (stage) status | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_92_3_the_still_decoding_status_of_a_stage_echoes_a_300_character_name_in_256 |
| w92c | R-PE-BENCH.92 name echoed raw in the no-edit status | bench_sheet.py | killed | killed | test_r_pe_bench_92_1_a_300_character_name_is_echoed_as_256_characters_and_an_ellipsis |
| w92d | R-PE-BENCH.92 name echoed raw in the stale-record status | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_92_2_the_stale_record_status_echoes_a_300_character_name_in_256 |
| w15a | R-PE-BENCH.15/16/18 sheet.py: no state passed to row_line (F-W1) | sheet.py | killed | killed | test_r_pe_bench_23_1_the_page_is_summarised_off_the_ui_thread_in_page_order |
| w15b | sheet.py pending default restored to Inc 8's empty string | sheet.py | survived | killed (Inc 8 node) | test_b103_inc8_s2_sheet_rows.py::test_r_pe_def_24_3_a_text_row_left_with_its_row_fill_unchanged_is_not_pend... |
| c01 | CODE canvas_shape: room-5 branch uses room-4 | definition_bench_view.py | killed | killed | test_r_pe_bench_38_6_the_bytes_line_stays_last_while_the_window_line_shows[8] |
| c02 | CODE canvas_shape: room-5 branch uses room-6 | definition_bench_view.py | survived | killed (new node) | test_r_pe_bench_5_3_a_windowed_tall_grid_fills_its_room_and_its_window_line_counts_the_painted_ |
| c03 | CODE canvas_shape: window-line test inverted | definition_bench_view.py | killed | killed | test_r_pe_bench_38_6_the_bytes_line_stays_last_while_the_window_line_shows[8] |
| c04 | CODE canvas_shape: first reserve is 3 | definition_bench_view.py | killed | killed | test_r_pe_bench_38_5_the_bytes_line_stays_last_while_the_whole_grid_fits[10] |
| c05 | CODE canvas_shape: second shape not recomputed | definition_bench_view.py | survived | killed (new node) | test_r_pe_bench_5_2_the_cursor_stays_on_a_painted_row_while_it_walks_down_a_tall_grid |
| s01 | CODE _staged_pair: always a second decode | bench_sheet.py | killed | killed | test_r_pe_bench_22_1_and_2_a_decode_ended_after_the_selection_moved_is_discarded |
| s02 | CODE _staged_pair: never a second decode | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_22_6_a_selected_row_over_a_raw_entry_shows_the_staged_delta_of_that_entry |
| s03 | CODE _staged_pair: entry end boundary inclusive | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_28_3_an_entry_outside_the_record_costs_the_decode_job_no_second_decode[0x80008E |
| s04 | CODE _staged_pair: entry start boundary inclusive | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_70_5_no_bench_job_starts_between_the_encode_ending_and_the_documents_write |
| s05 | CODE _staged_pair: empty span | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_22_6_a_selected_row_over_a_raw_entry_shows_the_staged_delta_of_that_entry |
| s06 | CODE _staged_pair: any entry counts as overlapping | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_70_5_no_bench_job_starts_between_the_encode_ending_and_the_documents_write |
| s07 | CODE _staged_pair: None as staged | bench_sheet.py | survived | survived, argued equivalent | `staged` None versus equal to the current values for a row no entry overlaps: every reader of `staged` first needs `row.is_staged`, which needs an overlapping entry |
| s08 | CODE _staged_pair: staged decoded over the image | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_22_6_a_selected_row_over_a_raw_entry_shows_the_staged_delta_of_that_entry |

## Step 4 - timing nodes (HT-08: serial, `-n 0`, only when the rtx 1-min load < 2, reading before each; `transcripts/timing.log`, `timing2.log`)
The first quiet reading came at 05:35 (1.26), right after my own runs ended; the nodes ran one after the other as long as the
reading stayed under 2.

| Node | Load before -> after | Result | Reading |
|---|---|---|---|
| 29_1 (as I9b left it) | 1.26 -> 1.38 | RED, `right 2.190 s, left 2.228 s` | wrong measurement: **test defect** (below) |
| 29_2 (as I9b left it) | 1.38 -> 1.45 | RED, `the preview arrived after 0 presses: the arrival was not exercised` | the instrument control failed: **test defect** |
| 82_1 (as I9b left it) | 1.45 -> 1.62 | RED, `slowest press 3.774 s` | decided: see F-MW9-2 |
| 26_2 (split) | 1.62 -> 2.19 | RED, 4.0 MiB (run 1 passed inside 240 s) | F-MW9-1 |
| 29_1 (repaired, `c3329577`) | 1.73 -> 1.93 | **GREEN**, `1 passed in 109 s` | decided at load < 2: key over a previewed LARGE edit within 0.5 s |
| 29_2 (repaired) | 1.93 -> 1.22 | **RED**, `slowest press 2.241 s` (presses 2.22, 2.23, 2.20, 2.24, then 0.66 s) | decided at load < 2: F-MW9-2 |
| 82_1 (repaired) | 1.22 -> 1.00 | **RED**, `slowest press 2.977 s` (typical 2.1-2.3 s) | decided at load < 2: F-MW9-2 |

**Test defect repaired (mine):** `BenchState.preview` is the string `"encoding"` from the apply until the result arrives, so the three
nodes' wait `preview is not None` was true at once. 29_1 therefore pressed its keys DURING the encode (and failed for the encode's
sake), 29_2 never saw the arrival, 82_1's wait proved nothing. Commit `c3329577` adds `previewed(sheet)` (a result, not the
placeholder). RED before / GREEN after on 29_1: `t-test_r_pe_bench_29_1.txt` / `t2-test_r_pe_bench_29_1.txt`.

**F-MW9-2 (product, R-PE-BENCH.29/2 and .82/1, for `software-dev`):** on a quiet host, every key pressed while LARGE's preview or
record encode runs takes 2.1-3.0 s, not 0.5 s, and the figure does not move with load (I9 saw 2.2 s at load 10); the first
key after the encode ends takes 0.66 s. A key during the LARGE decode (20_1) and a key over a finished preview (29_1) are inside
the bound. Hypothesis only (not tested): the encode is pure-Python work in a worker thread holding the GIL.

## Other findings for the orchestrator
- **F-MW9-3 (decision):** the 26_2 memory run counts allocations made from `s19_app` only (reason and numbers in step 2). Confirm, or rule that
  the bound is the whole traced total (then the node needs another instrument: Textual's growth alone is 3.8 MiB).
- **F-MW9-4 (observation):** the Patch Editor opens with the first row selected, so a LARGE first row starts its decode at generation 1,
  the image load's `set_document` bumps it to 2, and the decode (about 49 s idle) ends stale and is run again. Every open on such a
  page costs one wasted LARGE decode. No requirement states it; the stale-decode requeue (ruled at I9) makes it correct, not cheap.
- **Test-side facts:** `test_b103_inc9_w_mutants.py` is a new test module: `EXPECTED_SCANNED_TEST_FILES` 342 -> 343 in `tests/test_id_registry.py`
  (same commit). 70_5 reads the sheet's private `_active_job` and calls `_enqueue` from inside the app's handler (a hold that has no other
  observable on one UI thread); 74_2 and 78_3 post the sheet's own `RecordStageRequested` message (the interface). Everything else drives the
  keys and reads the painted sheet or the document.
- Laws on a fresh clone of `4258f763` (`transcripts/f-law.txt`): 117 passed, 3 skipped, **2 failed, both base-identical** (I9b): `canon_rows_hold_the_obligation_word_once`
  (R-A2L-DEF.153, R-PICKER-CORRECT.004/.008), `at_b83_08` (`test_b103_a2l_refresh.py`, `test_b103_picker_model.py`). `r_tst_070_2`, `id_registry`, `suite_hygiene` GREEN.
  Inc 9 widget files + the new one: 104 passed (`f-new.txt`); `w_jobs -m "not serial_timing and not slow"`: 2 passed; Inc 8 `p_layout`: 31 passed.

## Coverage (requirement -> node), uncovered named
Every widget / A9 / I row with a mutant in the table has a killing node (original or new); the rows without a mutant are listed under
"Not mutated" in step 3. Uncovered: R-PE-BENCH.20/1, .29/2, .82/1 (nodes exist and are RED or not decided as above); .80, .81, .91 (no mutant run).

## Commands (one complete run each, output in `transcripts/`)
`./run.sh <tree> <out> <n> <timeout> <pytest args>` = `env -i PATH=/usr/bin:/bin HOME=<scratch>/home/<runner-home> XDG_* TMPDIR PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 PYTHONPATH=. timeout <t> ~/miniconda3/envs/s19ci/bin/python -m pytest -p no:cacheprovider -n <n> ... < /dev/null`
(the script is the scratch's `run.sh`; the loop scripts `shard.sh`, `newt2.sh`, `timing*.sh`, `final.sh` are beside the spec). No suite run (C-25).

## Evidence checklist
- [x] Every test named exists: `tests/test_b103_inc9_w_mutants.py` (23 functions, 29 items), `tests/test_b103_inc9_w_jobs.py` (26_2, 29_1, 29_2, 82_1 edited).
- [x] Each result from one complete run's own output, command quoted; the table rows come from the driver's per-mutant lines (`logs/*.jsonl`).
- [x] RED on a mutant and GREEN on the tree: step 2 (t26, t26b, tfix) and the survivor table; no RED-on-base claim is made (no escaped regression).
- [x] Assertions on outcomes (painted sheet, document, statuses); the white-box points are named above.
- [x] Uncovered rows named. [x] Environment limits: shared host load 1-10, no suite run, no network beyond rtx.
- [x] No real PII or credentials; fixtures are the repo's hand A2L/S19 cases. [x] Evidence states: `executed` for runs, `failed` for the RED nodes, `not-run` for the rows without a mutant; no `approved`.

## Scratch deleted (explicit list, only paths I created)
`~/work/zq-mw9/` : `clone fin mt mt2 mt3 mt4 drv out home x tmp mw9.bundle mw9fin.bundle run.sh sweep.sh shard.sh newt.sh newt2.sh cs.sh chain262.sh chain262b.sh timing.sh timing2.sh final.sh diag22.sh diag22b.sh diag22c.sh diag22d.sh`, then the empty folder.
