# Inc 9 - test cases of the widget, group A9 and group I (tester T9b, E4)

Tester T9b (E4), tests tree `b103-inc9-tests` (base `30819c7e`: Inc 8 final plus group B's integrated pure modules; `bench_sheet.py`, `stage_record`, the record-stage handler and the two integration lines do not exist). Format: `<requirement id>/<n> | example | test (file::function[param]) | mark | note`, then each requirement's negative control and how these tests express it. Files: `tests/test_b103_inc9_w_keys.py`, `_w_select.py`, `_w_jobs.py`, `_w_stage.py`, `tests/test_b103_inc9_a9.py`, `tests/test_b103_inc9_i.py`; support `tests/support/b103_inc9_w.py`.

Expected values come from the requirement text, from I-2 (`encode_values` / `decode_values` over the app's own A2L and image) or from the committed example oracle `EX` (`evidence-e1/examples_inc9.py`); the implementation of `bench_sheet.py` was never read. **Binding rulings:** P-054 F-2 (an apply starts from the current value and REPLACES the bench edit; the edit before it goes to the undo stack) and W9's wording list W-1 ... W-7 (`E4-integration-b.md`); where a case's literal text contradicts them the test follows the ruling and says so in its note.

Mark: **full** = the product produces what the test asserts through the shipped route; **partial** = a stand-in or a reduction sits in the chain (named in the note). **LS** = load-sensitive: decided on a quiet host only (HT-08, E3A-13), a loaded run is a record. Evidence state of every row: `planned` until the integrator's GREEN (see `E4-test-w.md`).

| Case | Example | Test | Mark | Note |
|---|---|---|---|---|
| R-PE-BENCH.1/1 | EX-L1 | `tests/test_b103_inc9_i.py::test_r_pe_bench_1_1_the_sheet_window_subtitle_names_the_bench[118x54]` and `[220x60]` | full | the clause is appended: the text still starts with Inc 8's |
| R-PE-DEF.1.2/2 | EX-L2 | `tests/test_b103_inc9_w_select.py::test_r_pe_def_1_2_2_a_bench_row_sets_the_bench_class_and_the_landing_pane_gets_6_rows` | full | 118x54: number row 9 / no class, MAP_DEF_0001 6 / `-bench` / sheet +3, back to the number row |
| R-PE-BENCH.3/4 | EX-I1 | `tests/test_b103_inc9_w_select.py::test_r_pe_bench_3_4_after_import_the_three_bench_kinds_are_registered`; `tests/test_b103_inc9_i.py::test_r_pe_bench_3_the_panel_builds_the_bench_sheet_with_inc_8s_id` | full | `ops_for("map")` a KindOps, `editable` True, `decode` None, idempotent keys, no entry for kind `""` |
| R-PE-BENCH.6/1 | EX-T1 | `tests/test_b103_inc9_a9.py::test_r_pe_bench_6_1_and_def_60_5_a_record_stage_keeps_the_row_selected_and_its_bench_shown[R-PE-BENCH.6/1]` | full | legend `shade` still painted |
| R-PE-DEF.60/5 | EX-T1 | the same test, `[R-PE-DEF.60/5]` | full | the selection before and after is the staged row (no advance) |
| R-PE-BENCH.9/1 | EX-B1 | `tests/test_b103_inc9_w_select.py::test_r_pe_bench_9_1_a_filter_keystroke_that_keeps_the_row_keeps_its_state` | full | +Δ 100 on (0,0) as the case; the cursor is then moved to (1,0) so a reset would show |
| R-PE-BENCH.9/2 | EX-B1 | `...::test_r_pe_bench_9_2_selecting_another_row_and_back_keeps_the_state` | full | edit, cursor and tool kept |
| R-PE-BENCH.9/3 | EX-B1 | `...::test_r_pe_bench_9_3_a_page_without_the_row_drops_its_state` | full | control inside: the state held the edit before the page |
| R-PE-BENCH.20/1 | EX-H5 | `tests/test_b103_inc9_w_jobs.py::test_r_pe_bench_20_1_a_key_is_handled_within_half_a_second_while_a_large_decode_runs` | full, LS | LARGE's decode HELD in the worker by the I-2 wrapper `Gate` (so it "runs" for the whole key); the key is `pilot.press`. A decode on the UI thread holds the key for the 20 s hold limit: RED |
| R-PE-BENCH.20/2 | EX-H5 | `...::test_r_pe_bench_20_2_the_bench_shows_its_values_when_the_decode_ends` | full | slow (one real LARGE decode, about 11 s); control: the `decoding 1048576 values …` line first |
| R-PE-BENCH.20/3 | EX-I1 | `...::test_r_pe_bench_20_3_a_page_holding_large_decodes_nothing_on_the_ui_thread` | full | `build_row` over LARGE: 0 calls; the app's decode of LARGE is off the main thread |
| R-PE-BENCH.22/1 | EX-H5 | `tests/test_b103_inc9_w_select.py::test_r_pe_bench_22_1_and_2_a_decode_ended_after_the_selection_moved_is_discarded` | partial | BIG (70,000 elements, over 4,096) stands for LARGE: the logic is size-independent |
| R-PE-BENCH.22/2 | EX-H5 | the same test | partial | a second decode of BIG starts (call count 1 -> 2) |
| R-PE-BENCH.23/1 | EX-A1 | `...::test_r_pe_bench_23_1_the_page_is_summarised_off_the_ui_thread_in_page_order` | full | strips from the oracle (`EX.strip_chart`), `████ 12`, `███ 6`; page order tolerates the selected row's own decode going first |
| R-PE-BENCH.23/2 | EX-C2 | `tests/test_b103_inc9_w_jobs.py::test_r_pe_bench_23_2_the_page_paint_of_200_names_stays_within_half_a_second` | full, LS | median of 3 `show_page` of software_a's first 200 names on the bench sheet |
| R-PE-BENCH.24/1 | EX-H6 | `tests/test_b103_inc9_w_select.py::test_r_pe_bench_24_1_a_page_turn_during_a_held_summary_shows_no_old_strip` | partial | the page turn is the sheet's own `show_page` call (what the picker calls), not a filter keystroke |
| R-PE-BENCH.25/1 | EX-T1 | `...::test_r_pe_bench_25_1_undo_of_a_record_stage_removes_the_staged_dot` | full | the Undo button |
| R-PE-BENCH.25/2 | EX-F4 | `...::test_r_pe_bench_25_2_a_raw_entry_over_one_row_marks_that_row_and_decodes_no_other` | full | MAP_DEF_0001's decode count unchanged, VAL_BLK_DEF_0001's grows |
| R-PE-BENCH.26/2 | EX-B1 | `tests/test_b103_inc9_w_jobs.py::test_r_pe_bench_26_2_a_deselected_large_row_keeps_none_of_its_values` | full | `tracemalloc` over LARGE; slow (decode under tracemalloc); control: LARGE's numbers are above 1 MiB while selected |
| R-PE-BENCH.27/1 | EX-H5 | `tests/test_b103_inc9_w_select.py::test_r_pe_bench_27_apply_or_stage_while_the_values_decode_shows_the_still_decoding_status[apply]` | partial | BIG for LARGE |
| R-PE-BENCH.27/2 | EX-H5 | the same, `[stage]` | partial | BIG for LARGE; document unchanged |
| R-PE-BENCH.28/1 | EX-J1 | `tests/test_b103_inc9_w_jobs.py::test_r_pe_bench_28_1_at_most_one_bench_job_runs_at_any_time` | partial | 6 BIG rows, 6 `down`; peak of outermost I-2 calls running at once == 1 |
| R-PE-BENCH.28/2 | EX-J1 | `...::test_r_pe_bench_28_2_twenty_large_rows_and_twenty_down_keys_stay_within_320_mib` | full, LS | Linux only (`/proc/self/clear_refs` resets the peak); the 20 rows share one 1 MiB image (same address) |
| R-PE-BENCH.29/1 | EX-J2 | `...::test_r_pe_bench_29_1_a_cursor_key_over_a_previewed_large_edit_is_handled_within_half_a_second` | full, LS | Set `7` over 16 x 256 cells by shift+arrows; `right` and `left` timed |
| R-PE-BENCH.29/2 | EX-J2 | `...::test_r_pe_bench_29_2_a_cursor_key_while_the_preview_result_arrives_is_handled_within_one_second` | full, LS | `right` pressed until the result arrives; more than two presses made (the arrival is inside the loop) |
| R-PE-BENCH.40/1 | EX-K1 | `tests/test_b103_inc9_w_keys.py::test_r_pe_bench_40_1_enter_on_a_map_row_gives_the_bench_the_focus` | full | control: no `▸` before Enter |
| R-PE-BENCH.40/2 | EX-K1 | `...::test_r_pe_bench_40_2_enter_on_a_number_row_focuses_the_formula_input` | full | |
| R-PE-BENCH.44/1 ... 44/5 | EX-K4 | `...::test_r_pe_bench_44_a_tool_key_selects_its_tool_and_the_app_does_not_run[s]`, `[d]`, `[p]`, `[i]`, `[m]` | full | the app's `save_project`, `a2l_describe_tag`, `load_project`, page actions are counters: 0 runs while the bench is focused |
| R-PE-BENCH.45/1 | EX-K1 | `...::test_r_pe_bench_45_1_enter_on_the_bench_moves_the_focus_to_the_op_input` | full | |
| R-PE-BENCH.46/1 | EX-K1 | `...::test_r_pe_bench_46_1_escape_on_the_bench_returns_to_the_rows_and_up_selects_the_row_above` | full | |
| R-PE-BENCH.47/1 | EX-K1 | `...::test_r_pe_bench_47_1_escape_in_the_op_input_returns_to_the_bench_and_keeps_the_operand` | full | |
| R-PE-BENCH.48/1 | EX-T1 | `...::test_r_pe_bench_48_alt_s_asks_for_the_record_stage_from_the_bench_and_from_the_op_input[the bench]` | full | the stage is observed as the written entry (12 B) |
| R-PE-BENCH.48/2 | EX-T1 | the same, `[the op input]` | full | the focus is in the op input when alt+s is pressed (asserted) |
| R-PE-BENCH.49/1 | EX-K7 | `...::test_r_pe_bench_49_1_off_the_bench_the_keys_reach_the_app[DISPLAY_0001-s]` (and the other 5 ids: rows DISPLAY_0001 and MAP_DEF_0001, keys s d p; pageup / pagedown are not asserted: the panel is a ScrollableContainer, whose own bindings answer before the app's) | full | the app action runs exactly once; a bench row not yet focused takes the same path (`check_action` False) |
| R-PE-BENCH.49/2 | EX-K7 | `...::test_r_pe_bench_49_2_escape_on_a_number_row_keeps_inc_8s_behaviour` | full | text cleared, focus to the rows; control: the text was pending before |
| R-PE-BENCH.70/1 | EX-T1 | `tests/test_b103_inc9_a9.py::test_r_pe_bench_70_1_set_10_stages_the_whole_record_with_its_symbol` | full | the 12 bytes of the case and the I-2 encode agree |
| R-PE-BENCH.70/2 | EX-M1 | `...::test_r_pe_bench_70_2_set_0_on_a_map_cell_stages_the_32_byte_record` | full | |
| R-PE-BENCH.70/3 | EX-C1 | `...::test_r_pe_bench_70_3_set_40000_on_curve_points_stages_the_whole_curve_record` | partial | W-1 / W-2: points 1 and 3 alone need two applies and the second replaces the first, so the case's bytes (point 2 unchanged) are unreachable; the test stages points 1..3 and checks first and last point from the image |
| R-PE-BENCH.70/4 | EX-Q1 | `...::test_r_pe_bench_70_4_a_second_stage_asked_during_the_first_ones_held_encode_is_staged_too` | full | 2 entries, no `changed` status |
| R-PE-BENCH.71/1 | EX-O1 | `...::test_r_pe_bench_71_1_and_2_the_second_stage_encodes_over_the_first_one` | full | 1 entry, `10.0 11.0 31.8 -20.7 -5.0 -10.7` |
| R-PE-BENCH.71/2 | EX-O1 | the same test | full | `texts[0] == "10.0"`, not the image's `36.9` |
| R-PE-BENCH.72/1 | EX-T1 | `...::test_r_pe_bench_6_1_and_def_60_5_...[R-PE-BENCH.6/1]` (status read from the app) and `::test_r_pe_bench_72_1_and_70_1_stage_record_writes_one_bytes_entry_and_words_the_status` (service) | full | |
| R-PE-BENCH.72/2 | EX-M2 | `...::test_r_pe_bench_72_2_e2e_a_four_cell_stage_says_4_values` and `::test_r_pe_bench_72_2_the_value_word_is_plural_from_two_values` | full | the service half also checks `1 value` of a map |
| R-PE-BENCH.73/1 | EX-R12 | `...::test_r_pe_bench_73_1_two_notices_make_one_line_with_the_count_of_the_rest` | partial | stand-in notices (`dataclasses.replace` on an Encoded): I-2 gives at most one notice per encode |
| R-PE-BENCH.73/2 | EX-R12 | `...::test_r_pe_bench_73_2_one_notice_has_no_suffix` | partial | the same stand-in; control: no notice -> no line |
| R-PE-BENCH.74/1 ... 74/3 | EX-T7, T6, T8 | `...::test_r_pe_bench_74_a_refused_encode_shows_its_message_and_leaves_document_and_edit_unchanged[74-1-limits]`, `[74-2-not-a-number]`, `[74-3-not-integral]` | full | the message is I-2's own (`encode_values`); edit, entries and dirty unchanged |
| R-PE-BENCH.75/1 | EX-A1 | `tests/test_b103_inc9_w_stage.py::test_r_pe_bench_75_1_alt_s_with_an_empty_bench_edit_says_so_and_writes_nothing` | full | |
| R-PE-BENCH.76/1 | EX-F2 | `tests/test_b103_inc9_a9.py::test_r_pe_bench_76_1_no_a2l_when_the_stage_acts_says_so` | full | |
| R-PE-BENCH.77/1 | EX-F3 | `...::test_r_pe_bench_77_a_definition_changed_since_the_bench_was_built_is_refused[77-1-moved]` | full | VAL_BLK_DEF_0001 moved to 0x8000A0 |
| R-PE-BENCH.77/2 | EX-F3 | the same, `[77-2-reshaped]` | full | `MATRIX_DIM 3 2` -> `2 3` |
| R-PE-BENCH.77/3 | EX-F7 | `...::test_r_pe_bench_77_3_the_conversion_alone_changing_is_a_change` | full | the pair is CM_DEF_FINE's factor 0.05 (page) and 0.025 (loaded A2L), same span, in place of Inc 8 EX-R12's 0.5 / 1.0 on CM_DEF_LIN (VAL_BLK_DEF_0001 uses CM_DEF_FINE); +Δ 5 encodes under the page's factor |
| R-PE-BENCH.78/1 | EX-F5 | `...::test_r_pe_bench_78_1_an_undo_during_the_held_encode_makes_the_result_stale` | full | the stale record's bytes are not in the document |
| R-PE-BENCH.78/2 | EX-F8 | `...::test_r_pe_bench_78_2_an_image_push_during_the_held_encode_makes_the_result_stale` | partial | the "Apply" is the panel's image push (`set_image_mem_map`, what an Apply ends with), not the Apply action itself (Inc 10's surface) |
| R-PE-BENCH.79/2 | EX-Q2 | `tests/test_b103_inc9_w_stage.py::test_r_pe_bench_79_2_an_edit_made_while_the_record_encodes_is_kept_with_its_diamond` | full | the newer edit is {(1,1): `-18.8`} (an apply replaces, P-054 F-2), not the case's merged {(0,0), (1,1)}; the entry holds the staged edit only |
| R-PE-BENCH.80/1 | EX-T1 | `tests/test_b103_inc9_a9.py::test_r_pe_bench_80_1_stage_record_adds_one_undo_step_and_undo_restores_the_document` and `::test_r_pe_bench_80_2_the_dirty_flag_and_one_undo_step_follow_a_stage_from_clear` | full | |
| R-PE-BENCH.80/2 | EX-T1 | `...::test_r_pe_bench_80_2_the_dirty_flag_and_one_undo_step_follow_a_stage_from_clear` | full | |
| R-PE-BENCH.81/1 | EX-F1 | `...::test_r_pe_bench_81_1_a_partial_overlap_is_refused_with_inc_8s_status` (service) and `::test_r_pe_bench_81_1_e2e_a_raw_entry_overlapping_the_record_refuses_the_stage` | full | |
| R-PE-BENCH.82/1 | EX-H5 | `tests/test_b103_inc9_w_jobs.py::test_r_pe_bench_82_1_a_key_is_handled_within_one_second_while_a_record_encode_runs` | full, LS | LARGE, Set `7` on 256 x 16 cells; keys pressed until the record is written |
| R-PE-BENCH.83/1 | EX-F6 | `tests/test_b103_inc9_a9.py::test_r_pe_bench_83_1_a_session_action_running_refuses_the_stage_with_the_busy_line` | full | |
| R-PE-BENCH.83/2 | EX-F9 | `...::test_r_pe_bench_83_2_a_session_action_started_during_the_held_encode_refuses_when_it_ends` | full | |
| R-PE-BENCH.92/1 | EX-H4 | `tests/test_b103_inc9_w_stage.py::test_r_pe_bench_92_1_a_300_character_name_is_echoed_as_256_characters_and_an_ellipsis` | full | the row is a hand VAL_BLK shown through the sheet's own `show_page`; expected text from `ds.name_echo` |

**Extras beyond the case list** (cheap given the drivers, each its own function): `tests/test_b103_inc9_w_stage.py::test_r_pe_bench_51_1_enter_in_the_op_input_applies_and_the_focus_stays` (R-PE-BENCH.51/1, the widget route; negative control: stage instead of apply writes an entry), `::test_r_pe_bench_51_2_a_second_apply_replaces_the_edit_and_undo_restores_the_first` (P-054 F-2), `::test_r_pe_bench_66_1_a_preview_without_notices_is_a_tick`, `::test_r_pe_bench_66_2_a_refused_preview_shows_its_message`, `::test_r_pe_bench_66_3_a_percent_refusal_names_the_element` (the widget half of R-PE-BENCH.66, at 220x60 so the verdict is not cut), `::test_r_pe_bench_79_3_record_staged_and_record_done_are_no_ops_for_a_name_with_no_state` and `::test_r_pe_bench_79_4_a_page_turn_during_a_held_record_encode_still_stages` (E4 addendum R2-03), and `tests/test_b103_inc9_a9.py::test_e3s_08_an_apply_and_a_stage_log_nothing_of_the_operand` (E4 addendum E3S-08, `caplog`).

## Negative controls (per requirement, widget / A9 / I scope)

| Requirement | Negative control of `01-requirements.md` | Expressed against these tests? |
|---|---|---|
| R-PE-BENCH.1 | keep Inc 8's `enter edit · ↑↓ row` -> RED | expressed (the base revision shows exactly that RED, behaviour) |
| R-PE-BENCH.3 | no-editor tail / `editable=True` not a callable -> RED | expressed (`editable(...)` is CALLED and must return True; the bench lines come from group B's tests) |
| R-PE-BENCH.6, R-PE-DEF.60 | select the next row (Inc 8's tail) -> RED | expressed (`selected_name` before == after == the staged row) |
| R-PE-BENCH.9 | a fresh state at every selection message -> the filter case RED | expressed (edit, cursor and tool must survive a filter, a re-selection; and must reset after a page without the row) |
| R-PE-BENCH.20 | decode in the selection handler -> RED; a `decode` entry that calls I-2 -> the build case RED | expressed (held decode + timed key; `build_row` 0 calls; no decode call on the main thread) |
| R-PE-BENCH.22, .24 | paint the older result / paint by position -> RED | expressed (the dropped row's values are None; the old strip text is absent) |
| R-PE-BENCH.23 | decode the page in the page handler -> R-PE-DEF.12 RED | expressed (all decodes off the main thread; the 200-name paint bound) |
| R-PE-BENCH.25 | recompute every row -> the MAP decode count RED | expressed (MAP_DEF_0001's `decode_values` count equal before and after) |
| R-PE-BENCH.26 | keep every visited row's values -> the second case RED | expressed (`states[LARGE].values` and `.staged` None, `tracemalloc` <= 1 MiB; the first half of the requirement, `from_decoded`, is group B's) |
| R-PE-BENCH.27 | apply over no values -> exception RED | expressed |
| R-PE-BENCH.28 | one worker per selection -> RED | expressed (peak concurrency of outermost I-2 calls must be 1) |
| R-PE-BENCH.29 | re-read and diff the whole record at every paint; diff on the UI thread when the result arrives -> RED | expressed (timed key while the result arrives and after) |
| R-PE-BENCH.40 ... .48 | no binding / focus the op input / screen back action -> RED | expressed (focus ids, `states[...].focus`, the cursor marker) |
| R-PE-BENCH.44, .49 | no binding -> `save_project` runs -> RED; plain class bindings with no focus check -> 0 runs -> RED | expressed as one pair (0 runs with the bench focused, 1 run without it) |
| R-PE-BENCH.51 | stage instead of apply -> RED | expressed (51/1: no entry after the apply) |
| R-PE-BENCH.66 | preview over the image, not the overlay -> R-PE-BENCH.71's second edit RED | expressed via 71 (the second record over the first) and the op-line verdicts |
| R-PE-BENCH.70 | write only the changed run -> a partly overlapping second edit RED; start the next job before the app's write -> 70/4 RED | expressed (whole-record entries; 70/4 with a held encode) |
| R-PE-BENCH.71 | encode over the image -> (0,0) reverts to `36.9` RED | expressed |
| R-PE-BENCH.72 | pass `shown` = the edit text -> RED | expressed (the whole status text) |
| R-PE-BENCH.73 | drop the notices -> RED | expressed (partial: stand-in notices) |
| R-PE-BENCH.74 | stage the image's record -> RED | expressed (entries and edit unchanged, I-2's refusal message) |
| R-PE-BENCH.75 | stage the unchanged record -> an entry RED | expressed |
| R-PE-BENCH.76 | stage with the old definition -> RED | expressed (a stage with `current_a2l_data = None`) |
| R-PE-BENCH.77 | compare address, byte length and shape only -> 77/3 RED | expressed (77/3 changes the conversion only) |
| R-PE-BENCH.78 | write the stale record; a document-only check -> the Apply case RED | expressed (78/1 document change, 78/2 image push) |
| R-PE-BENCH.79 | keep the edit; mark from the formula text; clear whatever the edit is -> the second case RED | expressed for the second case (79/2: newer edit and `◆` kept); the mark-from-formula control is group B's `bench_mark` and 18/4 |
| R-PE-BENCH.80 | no history push -> RED | expressed |
| R-PE-BENCH.81 | replace the partial entry -> RED | expressed |
| R-PE-BENCH.82 | encode in the key handler -> RED | expressed (timed key while the record encode runs; the write is observed) |
| R-PE-BENCH.83 | no busy check -> an entry RED; only before the encode -> 83/2 RED | expressed |
| R-PE-BENCH.92 | unbounded echo -> RED | expressed for 92/1 (256 characters + `…`); 92/2 is group B's |

## Not written, and why

- **Masked-array case of E4 addendum E3S-07** (a UWORD VAL_BLK `MATRIX_DIM 2` with `BIT_MASK 0x0FF0`, Apply then Remove, bench Set and a record stage; the refusal `encoded outside its span`): not a row of `02-test-cases.md` (an E4 addendum of the slice), needs a hand A2L with a bit mask and the Inc 8 Apply/Remove route; left to the integrator's mutant worker. **uncovered.**
- R-PE-BENCH.20/1, .28/1, .28/2, .29, .82/1 are written but their verdict needs a quiet host and, for 28/2, Linux: see the record.
