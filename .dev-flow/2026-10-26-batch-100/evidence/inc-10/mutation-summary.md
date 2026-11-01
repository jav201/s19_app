# Inc 10 E5 — mutation summary

Copy: `C:/Users/jjgh8/AppData/Local/Temp/claude/C--Users-jjgh8-clde/a8feab43-c248-4ccb-86cf-122b894659b2/scratchpad/mut10`
Interpreter: `C:/Users/jjgh8/anaconda3/envs/s19env/python.exe` (LOCALAPPDATA redirected to the scratch folder on every run).
`s19_app.__file__` resolved inside the copy.

## Table

| id | requirement | file | test | verdict |
|---|---|---|---|---|
| M01 | ConfirmQuestionScreen AUTO_FOCUS value | s19_app/tui/screens.py | test_tc_b100_45_focus_starts_on_cancel_on_every_route; test_tc_b100_45_enter_answers_with_the_focused_button | KILLED |
| M02 | ConfirmQuestionScreen AUTO_FOCUS present | s19_app/tui/screens.py | test_tc_b100_45_focus_starts_on_cancel_on_every_route | KILLED |
| M03 | `y` binding present | s19_app/tui/screens.py | test_tc_b100_45_y_replaces_with_the_focus_on_either_button | KILLED |
| M04 | `y` answers True | s19_app/tui/screens.py | test_tc_b100_45_y_replaces_with_the_focus_on_either_button; test_tc_b100_72_replace_runs_the_load_on_every_route | KILLED |
| M05 | `n` binding present | s19_app/tui/screens.py | test_tc_b100_45_n_and_escape_cancel_with_the_focus_on_either_button | KILLED |
| M06 | `n` answers False | s19_app/tui/screens.py | test_tc_b100_45_n_and_escape_cancel_with_the_focus_on_either_button; test_tc_b100_46_cancel_keeps_the_session_and_runs_no_reset | KILLED |
| M07 | `escape` binding present | s19_app/tui/screens.py | test_tc_b100_45_n_and_escape_cancel_with_the_focus_on_either_button | KILLED |
| M08 | no screen-level `enter` binding | s19_app/tui/screens.py | test_tc_b100_45_enter_answers_with_the_focused_button | SURVIVED |
| M09 | `s` is inert under the question | s19_app/tui/screens.py | test_tc_b100_45_other_keys_leave_the_question_open | KILLED |
| M10 | title Label markup off | s19_app/tui/screens.py | test_tc_b100_45_modal_builds_from_its_parameters; test_tc_b100_45_names_paint_literally | KILLED |
| M11 | body Static markup off | s19_app/tui/screens.py | test_tc_b100_45_modal_builds_from_its_parameters | KILLED |
| M12 | yes button uses `Text(...)` | s19_app/tui/screens.py | test_tc_b100_45_modal_builds_from_its_parameters | KILLED |
| M13 | yes label not hard-coded | s19_app/tui/screens.py | test_tc_b100_45_modal_builds_from_its_parameters | KILLED |
| M14 | button order (yes then no) | s19_app/tui/screens.py | test_tc_b100_45_enter_answers_with_the_focused_button | SURVIVED |
| M15 | outer box id `#confirm_box` | s19_app/tui/screens.py | test_tc_b100_45_buttons_and_body_stay_fully_visible | SURVIVED |
| M16 | `event.stop()` in on_button_pressed | s19_app/tui/screens.py | test_tc_b100_45_click_answers_with_the_clicked_button | SURVIVED |
| M17 | `confirm_yes` arm answers True | s19_app/tui/screens.py | test_tc_b100_45_click_answers_with_the_clicked_button; test_tc_b100_45_enter_answers_with_the_focused_button | KILLED |
| M18 | `confirm_no` arm present | s19_app/tui/screens.py | test_tc_b100_45_click_answers_with_the_clicked_button; test_tc_b100_45_enter_answers_with_the_focused_button | KILLED |
| M19 | `action_answer` passes value unchanged | s19_app/tui/screens.py | test_tc_b100_45_y_replaces_with_the_focus_on_either_button; test_tc_b100_45_n_and_escape_cancel_with_the_focus_on_either_button | KILLED |
| M20 | `_close` guards re-entry | s19_app/tui/screens.py | test_tc_b100_45_a_second_answer_is_ignored | KILLED |
| M21 | `_close` sets `_dismissed` | s19_app/tui/screens.py | test_tc_b100_45_a_second_answer_is_ignored | KILLED |
| M22 | `_close` dismisses with result | s19_app/tui/screens.py | test_tc_b100_45_y_replaces_with_the_focus_on_either_button | KILLED |
| M23 | `is_dirty` reads `_dirty` | s19_app/tui/screens_directionb.py | test_tc_b100_44_patch_editor_reader_follows_its_writers; test_tc_b100_44_twenty_four_cells_ask_by_kind | KILLED |
| M24 | `is_dirty` not keyed on paste buffer text | s19_app/tui/screens_directionb.py | test_tc_b100_44_patch_editor_reader_follows_its_writers | KILLED |
| M25 | `is_dirty` has no setter | s19_app/tui/screens_directionb.py | test_tc_b100_44_patch_editor_reader_follows_its_writers | KILLED |
| M26 | dropdown guard block present | s19_app/tui/app.py | test_tc_b100_45_change_file_dropdown_keeps_the_guard | KILLED |
| M27 | dropdown guard reads public `is_dirty` | s19_app/tui/app.py | test_tc_b100_44_no_private_dirty_read_outside_the_panel | KILLED |
| M28 | cancel arm resets the Select | s19_app/tui/app.py | test_tc_b100_45_change_file_dropdown_keeps_the_guard | KILLED |
| M29 | cancel status line (unasserted) | s19_app/tui/app.py | test_tc_b100_45_change_file_dropdown_keeps_the_guard | SURVIVED |
| M30 | accept arm loads (undriven) | s19_app/tui/app.py | test_tc_b100_45_change_file_dropdown_keeps_the_guard | SURVIVED |
| M31 | `_confirm_then_load` asks iff items | s19_app/tui/app.py | test_tc_b100_44_saved_states_load_without_asking; test_tc_b100_72_every_route_asks_and_cancel_keeps_the_session | KILLED |
| M32 | empty arm runs `go` synchronously | s19_app/tui/app.py | test_tc_b100_44_saved_states_load_without_asking | SURVIVED |
| M33 | replace arm defers via `call_after_refresh` | s19_app/tui/app.py | test_tc_b100_46_reset_runs_after_the_answer | SURVIVED |
| M34 | replace arm runs `go` | s19_app/tui/app.py | test_tc_b100_72_replace_runs_the_load_on_every_route; test_at_b100_15_load_over_unsaved_work_asks_one_question_per_route | KILLED |
| M35 | cancel arm runs no load | s19_app/tui/app.py | test_tc_b100_46_cancel_keeps_the_session_and_runs_no_reset; test_tc_b100_72_every_route_asks_and_cancel_keeps_the_session | KILLED |
| M36 | cancel arm re-homes focus | s19_app/tui/app.py | test_tc_b100_12_cancelled_question_rehomes_the_focus | KILLED |
| M37 | `go` runs after the answer | s19_app/tui/app.py | test_tc_b100_46_reset_runs_after_the_answer; test_tc_b100_46_cancel_keeps_the_session_and_runs_no_reset | KILLED |
| M38 | question labels "Replace (y)"/"Cancel (n)" | s19_app/tui/app.py | test_tc_b100_45_one_modal_with_replace_and_cancel | KILLED |
| M39 | attach asks nothing | s19_app/tui/app.py | test_tc_b100_44_twenty_four_cells_ask_by_kind; test_tc_b100_44_attach_asks_nothing_and_keeps_the_patch | KILLED |
| M40 | D read appends the image item | s19_app/tui/app.py | test_tc_b100_44_twenty_four_cells_ask_by_kind; test_tc_b100_44_undo_alone_and_repatch_after_save_ask | KILLED |
| M41 | D keyed on byte-diff, not entries | s19_app/tui/app.py | test_tc_b100_44_undo_alone_and_repatch_after_save_ask; test_tc_b100_44_saved_states_load_without_asking | KILLED |
| M42 | W/F read only for `project` | s19_app/tui/app.py | test_tc_b100_44_twenty_four_cells_ask_by_kind | KILLED |
| M43 | W item appended | s19_app/tui/app.py | test_tc_b100_44_twenty_four_cells_ask_by_kind; test_tc_b100_44_project_load_asks_iff_a_flag_is_set | KILLED |
| M44 | guard reads public `is_dirty` | s19_app/tui/app.py | test_tc_b100_44_guard_reads_the_public_reader; test_tc_b100_44_no_private_dirty_read_outside_the_panel | KILLED |
| M45 | F item appended | s19_app/tui/app.py | test_tc_b100_44_twenty_four_cells_ask_by_kind; test_tc_b100_45_flow_item_named_with_its_flow_name | KILLED |
| M46 | flow item carries its flow name | s19_app/tui/app.py | test_tc_b100_45_flow_item_named_with_its_flow_name; test_at_b100_15_load_over_unsaved_work_asks_one_question_per_route | KILLED |
| M47 | item order image, document, flow | s19_app/tui/app.py | test_tc_b100_45_patch_editor_entries_named_only_when_w; test_tc_b100_45_body_says_unsaved_changes_once_in_two_sentences | KILLED |
| M48 | title prefers project name | s19_app/tui/app.py | test_tc_b100_45_title_names_what_is_replaced | KILLED |
| M49 | fallback title "the current session" | s19_app/tui/app.py | test_tc_b100_45_title_names_what_is_replaced | KILLED |
| M50 | project name painted (scrubbed) | s19_app/tui/app.py | test_tc_b100_45_names_paint_literally | SURVIVED |
| M51 | image item name painted (scrubbed) | s19_app/tui/app.py | test_tc_b100_45_names_paint_literally | KILLED |
| M52 | document item wording "Patch Editor entries" | s19_app/tui/app.py | test_tc_b100_45_patch_editor_entries_named_only_when_w; tests/test_b100_session_reset.py::test_at_b100_03_project_load_over_unsaved_work_saves_only_p2 | KILLED |
| M53 | flow item prefixed "flow " | s19_app/tui/app.py | test_tc_b100_45_flow_item_named_with_its_flow_name | KILLED |
| M54 | all items joined in one question | s19_app/tui/app.py | test_tc_b100_45_body_says_unsaved_changes_once_in_two_sentences; test_at_b100_15_load_over_unsaved_work_asks_one_question_per_route | KILLED |
| M55 | two/three-item join uses " and " | s19_app/tui/app.py | test_tc_b100_45_body_says_unsaved_changes_once_in_two_sentences | KILLED |
| M56 | project target prefixed "project " | s19_app/tui/app.py | test_tc_b100_45_load_target_named_per_route | KILLED |
| M57 | target names the requested route | s19_app/tui/app.py | test_tc_b100_45_load_target_named_per_route | KILLED |
| M58 | one body sentence, two ends | s19_app/tui/app.py | test_tc_b100_45_body_says_unsaved_changes_once_in_two_sentences | KILLED |
| M59 | project route passes the seam | s19_app/tui/app.py | test_tc_b100_44_project_load_asks_iff_a_flag_is_set; tests/test_b100_session_reset.py::test_at_b100_03_project_load_over_unsaved_work_saves_only_p2 | KILLED |
| M60 | project route asks with kind "project" | s19_app/tui/app.py | test_tc_b100_44_project_load_asks_iff_a_flag_is_set | KILLED |
| M61 | pending variant stamped after confirm | s19_app/tui/app.py | test_tc_b100_46_cancelled_variant_switch_keeps_the_pending_selection | KILLED |
| M62 | variant switch passes the seam | s19_app/tui/app.py | test_tc_b100_72_every_load_call_passes_the_seam; test_tc_b100_72_every_route_asks_and_cancel_keeps_the_session | KILLED |
| M63 | "Variant not found" paints name (C60) | s19_app/tui/app.py | test_tc_b100_46_cancelled_variant_switch_keeps_the_pending_selection | SURVIVED |
| M64 | "Variant file missing" paints name (C60) | s19_app/tui/app.py | test_tc_b100_46_cancelled_variant_switch_keeps_the_pending_selection | SURVIVED |
| M65 | priority keys inert under the question (both screens) | s19_app/tui/app.py | test_tc_b100_45_priority_keys_are_inert_under_the_question | KILLED |
| M66 | whole-stack guard (not stack-top) | s19_app/tui/app.py | test_tc_b100_45_priority_keys_are_inert_under_the_question | KILLED |
| M67 | save-dialog reads public `is_dirty` | s19_app/tui/app.py | test_tc_b100_44_no_private_dirty_read_outside_the_panel | KILLED |
| M68 | install check before the reset | s19_app/tui/app.py | test_tc_b100_46_unreadable_a2l_project_after_yes_keeps_the_work | KILLED |
| M69 | A2L read before the reset | s19_app/tui/app.py | test_tc_b100_46_unreadable_a2l_project_after_yes_keeps_the_work | KILLED |
| M70 | "No supported files" paints name (C60) | s19_app/tui/app.py | test_tc_b100_46_unreadable_a2l_project_after_yes_keeps_the_work | SURVIVED |
| M71 | `_declared_regions` written after reset | s19_app/tui/app.py | test_tc_b100_46_unreadable_a2l_project_after_yes_keeps_the_work | SURVIVED |
| M72 | interim "Closed the Patch Editor document" removed | s19_app/tui/app.py | tests/test_b100_session_reset.py::test_tc_b100_10_interim_discard_notice; ::test_tc_b100_10_notice_names_every_discarded_entry | KILLED |
| M73 | typed path stripped before classification use | s19_app/tui/app.py | test_tc_b100_72_typed_path_takes_its_kind_from_the_classification | KILLED |
| M74 | typed A2L asks with kind "attach" | s19_app/tui/app.py | test_tc_b100_72_typed_path_takes_its_kind_from_the_classification; test_tc_b100_44_attach_asks_nothing_and_keeps_the_patch | KILLED |
| M75 | MAC suffix test case-folded | s19_app/tui/app.py | test_tc_b100_72_typed_path_takes_its_kind_from_the_classification | KILLED |
| M76 | typed data arm keeps MAC attach kind | s19_app/tui/app.py | test_tc_b100_72_typed_path_takes_its_kind_from_the_classification; test_tc_b100_44_attach_asks_nothing_and_keeps_the_patch | KILLED |
| M77 | typed data arm passes the seam | s19_app/tui/app.py | test_tc_b100_72_every_load_call_passes_the_seam | KILLED |
| M78 | typed project asks once | s19_app/tui/app.py | test_tc_b100_72_one_question_per_request | KILLED |
| M79 | workarea `exists()` check before the seam | s19_app/tui/app.py | test_tc_b100_72_workarea_file_takes_its_kind_from_its_suffix | SURVIVED |
| M80 | workarea kind from suffix (not always image) | s19_app/tui/app.py | test_tc_b100_72_workarea_file_takes_its_kind_from_its_suffix | KILLED |
| M81 | A2L suffix counts as attach | s19_app/tui/app.py | test_tc_b100_72_workarea_file_takes_its_kind_from_its_suffix | KILLED |
| M82 | workarea suffix test case-folded | s19_app/tui/app.py | test_tc_b100_72_workarea_file_takes_its_kind_from_its_suffix | KILLED |
| M83 | workarea file passes the seam | s19_app/tui/app.py | test_tc_b100_72_every_load_call_passes_the_seam; test_tc_b100_72_workarea_file_takes_its_kind_from_its_suffix | KILLED |

## Counts

- KILLED: 69
- SURVIVED: 14
- INVALID: 0

## Survivors

- **M08** (screen-level `enter` binding) — equivalent mutant. The focused `Button` already consumes `enter` before the screen binding fires, so adding `Binding("enter", "answer(True)")` is a dead binding and the killer passes.
- **M14** (button order) — equivalent mutant. With two buttons and `AUTO_FOCUS` pinned to `#confirm_no`, swapping yes/no leaves the tab trail identical (the two-button wrap is symmetric).
- **M15** (outer id `#confirm_box`) — wrong target. The killer queries `#confirm_yes` / `#confirm_no` / `#confirm_body`, never the outer `#confirm_box`; renaming it only drops its CSS, which did not affect visibility.
- **M16** (`event.stop()`) — gap (declared). No observer of the bubbled `Button.Pressed` on the app; deleting `event.stop()` is unobservable.
- **M29** (cancel status line) — gap (declared). The dropdown's cancel status line is unasserted (the guard and Select reset are).
- **M30** (accept arm) — gap (declared). The test drives cancel, re-pick and clean, not the accept arm.
- **M32** (empty-arm `call_after_refresh`) — gap (declared). C09 timing arm not a test.
- **M33** (replace-arm synchronous `go`) — gap (declared). No test observes the question still mounted during `go`.
- **M50** (raw `current_project`) — weak test. The killer's project name is `[i]P`, which has no scrub/clip-worthy characters, so raw == `painted_names` output.
- **M63** (`Variant not found` scrub) — gap (declared). C60 (S10-04) has no test.
- **M64** (`Variant file missing` scrub) — gap (declared). C60 (S10-04) has no test.
- **M70** (`No supported files` scrub) — gap (declared). C60 arm; the A2LONLY name is plain.
- **M71** (`_declared_regions` order) — gap (declared). No in-scope test loads a project with declared regions after a reset.
- **M79** (`exists()` into `go`) — gap (declared). C39 (file deleted during the question) is a design note, not a test.
