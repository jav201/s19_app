# Inc 10 E4 — mutant candidates (input to E5)

One row per NEW branch or arm Inc 10 adds to the source. Line numbers are the integrated tree (sources unchanged by E4: `screens.py` 58186f0551f9b02e, `screens_directionb.py` c53fd29b14f5c8ed, `app.py` ac5b417b8c3e6b47). Test names are in `tests/test_b100_load_question.py` unless another file is named; `TC44-24` = `test_tc_b100_44_twenty_four_cells_ask_by_kind`, `AT15` = `test_at_b100_15_load_over_unsaved_work_asks_one_question_per_route`.

Status column: `expect-kill` (a named test should go RED), `gap` (no test in the Inc 10 run scope is expected to kill it; see the end of the file). The kills are `planned`, not `executed`: E5 runs them.

## screens.py — `ConfirmQuestionScreen`

| # | file:function:line | Mutation | Expected killer | Status |
|---|---|---|---|---|
| M01 | screens.py:ConfirmQuestionScreen (class attr):1255 | `AUTO_FOCUS = "#confirm_yes"` | `test_tc_b100_45_focus_starts_on_cancel_on_every_route`; `..._enter_answers_with_the_focused_button` | expect-kill |
| M02 | screens.py:ConfirmQuestionScreen (class attr):1255 | delete `AUTO_FOCUS` | `test_tc_b100_45_focus_starts_on_cancel_on_every_route` | expect-kill |
| M03 | screens.py:ConfirmQuestionScreen.BINDINGS:1257 | delete the `y` binding | `test_tc_b100_45_y_replaces_with_the_focus_on_either_button` | expect-kill |
| M04 | screens.py:ConfirmQuestionScreen.BINDINGS:1257 | `y` → `answer(False)` | `test_tc_b100_45_y_replaces_with_the_focus_on_either_button`; `test_tc_b100_72_replace_runs_the_load_on_every_route[*]` | expect-kill |
| M05 | screens.py:ConfirmQuestionScreen.BINDINGS:1258 | delete the `n` binding | `test_tc_b100_45_n_and_escape_cancel_with_the_focus_on_either_button` | expect-kill |
| M06 | screens.py:ConfirmQuestionScreen.BINDINGS:1258 | `n` → `answer(True)` | `test_tc_b100_45_n_and_escape_cancel_with_the_focus_on_either_button`; `test_tc_b100_46_cancel_keeps_the_session_and_runs_no_reset` | expect-kill |
| M07 | screens.py:ConfirmQuestionScreen.BINDINGS:1259 | delete the `escape` binding | `test_tc_b100_45_n_and_escape_cancel_with_the_focus_on_either_button` | expect-kill |
| M08 | screens.py:ConfirmQuestionScreen.BINDINGS:1259 | add `Binding("enter", "answer(True)")` (screen-level enter) | `test_tc_b100_45_enter_answers_with_the_focused_button` | expect-kill |
| M09 | screens.py:ConfirmQuestionScreen.BINDINGS:1259 | add `Binding("s", "answer(True)")` (the `pb_B` third key) | `test_tc_b100_45_other_keys_leave_the_question_open` | expect-kill |
| M10 | screens.py:ConfirmQuestionScreen.compose:1282 | title `Label` `markup=True` | `test_tc_b100_45_modal_builds_from_its_parameters` (HOSTILE); `test_tc_b100_45_names_paint_literally` | expect-kill |
| M11 | screens.py:ConfirmQuestionScreen.compose:1284 | body `Static` `markup=True` | `test_tc_b100_45_modal_builds_from_its_parameters` (HOSTILE body) | expect-kill |
| M12 | screens.py:ConfirmQuestionScreen.compose:1287 | `Button(self._yes_label, …)` (a `str`, parsed as markup) | `test_tc_b100_45_modal_builds_from_its_parameters` (`[b]Quit (y)`) | expect-kill |
| M13 | screens.py:ConfirmQuestionScreen.compose:1287 | hard-code `Text("Replace (y)")` | `test_tc_b100_45_modal_builds_from_its_parameters` (QUITQ) | expect-kill |
| M14 | screens.py:ConfirmQuestionScreen.compose:1291 | swap the button order (no before yes) | `test_tc_b100_45_enter_answers_with_the_focused_button` (tab trail) | expect-kill |
| M15 | screens.py:ConfirmQuestionScreen.compose:1295 | outer id `load_dialog` | `test_tc_b100_45_buttons_and_body_stay_fully_visible[*]` (queries `#confirm_box`) | expect-kill |
| M16 | screens.py:ConfirmQuestionScreen.on_button_pressed:1300 | delete `event.stop()` | — (no observer of the bubbled `Pressed` on the app) | gap |
| M17 | screens.py:ConfirmQuestionScreen.on_button_pressed:1301 | `confirm_yes` arm → `_close(False)` | `test_tc_b100_45_click_answers_with_the_clicked_button`; `..._enter_answers_with_the_focused_button` | expect-kill |
| M18 | screens.py:ConfirmQuestionScreen.on_button_pressed:1303 | delete the `confirm_no` arm | `test_tc_b100_45_click_answers_with_the_clicked_button`; `..._enter_answers_with_the_focused_button` | expect-kill |
| M19 | screens.py:ConfirmQuestionScreen.action_answer:1307 | `self._close(not value)` | `test_tc_b100_45_y_replaces_…`; `test_tc_b100_45_n_and_escape_cancel_…` | expect-kill |
| M20 | screens.py:ConfirmQuestionScreen._close:1310 | delete `if self._dismissed: return` | `test_tc_b100_45_a_second_answer_is_ignored` | expect-kill |
| M21 | screens.py:ConfirmQuestionScreen._close:1312 | delete `self._dismissed = True` | `test_tc_b100_45_a_second_answer_is_ignored` | expect-kill |
| M22 | screens.py:ConfirmQuestionScreen._close:1313 | `self.dismiss()` (None) | `test_tc_b100_45_y_replaces_…` (callback value `True`) | expect-kill |

## screens_directionb.py — `PatchEditorPanel.is_dirty`

| # | file:function:line | Mutation | Expected killer | Status |
|---|---|---|---|---|
| M23 | screens_directionb.py:PatchEditorPanel.is_dirty:5873 | `return False` | `test_tc_b100_44_patch_editor_reader_follows_its_writers`; `TC44-24` (W cells) | expect-kill |
| M24 | screens_directionb.py:PatchEditorPanel.is_dirty:5873 | `return self._dirty or bool(<paste buffer text>)` | `test_tc_b100_44_patch_editor_reader_follows_its_writers` (P1-2 boundary) | expect-kill |
| M25 | screens_directionb.py:PatchEditorPanel.is_dirty:5866 | add a setter that writes `_dirty` | `test_tc_b100_44_patch_editor_reader_follows_its_writers` (`fset is None`) | expect-kill |

## app.py

| # | file:function:line | Mutation | Expected killer | Status |
|---|---|---|---|---|
| M26 | app.py:on_patch_editor_panel_change_file_selected:6208 | delete the `if panel.is_dirty:` block | `test_tc_b100_45_change_file_dropdown_keeps_the_guard` | expect-kill |
| M27 | app.py:on_patch_editor_panel_change_file_selected:6208 | `if panel._dirty:` | `test_tc_b100_44_no_private_dirty_read_outside_the_panel` | expect-kill |
| M28 | app.py:on_patch_editor_panel_change_file_selected:6214 | delete the `Select.NULL` reset | `test_tc_b100_45_change_file_dropdown_keeps_the_guard` (re-pick arm) | expect-kill |
| M29 | app.py:on_patch_editor_panel_change_file_selected:6212 | delete the cancel status line | — (the test asserts the guard and the Select, not the line) | gap |
| M30 | app.py:on_patch_editor_panel_change_file_selected:6217 | accept arm does nothing | — (the test drives the cancel and the clean arms, not accept) | gap |
| M31 | app.py:_confirm_then_load:7576 | `if items:` (inverted) | every route test; `test_tc_b100_44_saved_states_load_without_asking` | expect-kill |
| M32 | app.py:_confirm_then_load:7577 | empty arm → `self.call_after_refresh(go)` | — (C09 timing arm not a test) | gap |
| M33 | app.py:_confirm_then_load:7585 | `go()` synchronously instead of `call_after_refresh(go)` | — (no test observes the question still mounted during `go`) | gap |
| M34 | app.py:_confirm_then_load:7585 | replace arm drops `go` | `test_tc_b100_72_replace_runs_the_load_on_every_route[*]`; AT15 | expect-kill |
| M35 | app.py:_confirm_then_load:7587 | cancel arm also runs `go` | `test_tc_b100_46_cancel_keeps_the_session_and_runs_no_reset`; `test_tc_b100_72_every_route_asks_and_cancel_keeps_the_session` | expect-kill |
| M36 | app.py:_confirm_then_load:7587 | cancel arm skips `_rehome_focus_after_load()` | `test_tc_b100_12_cancelled_question_rehomes_the_focus` (re-home count, ruling 7) | expect-kill |
| M37 | app.py:_confirm_then_load:7577 | call `go()` before the push when items is non-empty | `test_tc_b100_46_reset_runs_after_the_answer`; `..._cancel_keeps_the_session_and_runs_no_reset` | expect-kill |
| M38 | app.py:_confirm_then_load:7591 | labels `"Discard"` / `"Keep"` | `test_tc_b100_45_one_modal_with_replace_and_cancel` | expect-kill |
| M39 | app.py:_load_would_lose:7633 | delete the `attach` early return | `TC44-24` (attach cells); `test_tc_b100_44_attach_asks_nothing_and_keeps_the_patch` | expect-kill |
| M40 | app.py:_load_would_lose:7637 | drop the D read (never append image) | `TC44-24`; `test_tc_b100_44_undo_alone_and_repatch_after_save_ask` | expect-kill |
| M41 | app.py:_load_would_lose:7637 | D keyed on `len(document.entries) > 0` | `test_tc_b100_44_undo_alone_and_repatch_after_save_ask`; `test_tc_b100_44_saved_states_load_without_asking` | expect-kill |
| M42 | app.py:_load_would_lose:7641 | `if kind != "attach":` (W, F read for image too) | `TC44-24` (image × W/F cells) | expect-kill |
| M43 | app.py:_load_would_lose:7643 | drop the W item | `TC44-24`; `test_tc_b100_44_project_load_asks_iff_a_flag_is_set` | expect-kill |
| M44 | app.py:_load_would_lose:7643 | `panel._dirty` | `test_tc_b100_44_guard_reads_the_public_reader`; `..._no_private_dirty_read_outside_the_panel` | expect-kill |
| M45 | app.py:_load_would_lose:7646 | drop the F item | `TC44-24`; `test_tc_b100_45_flow_item_named_with_its_flow_name` | expect-kill |
| M46 | app.py:_load_would_lose:7647 | flow item name `""` | `test_tc_b100_45_flow_item_named_with_its_flow_name`; AT15 (`flow flow`) | expect-kill |
| M47 | app.py:_load_would_lose:7640 | swap the order (document before image) | `test_tc_b100_45_patch_editor_entries_named_only_when_w` / body 3-item test | expect-kill |
| M48 | app.py:_load_question_text:7693 | always use the image name for `current` | `test_tc_b100_45_title_names_what_is_replaced` | expect-kill |
| M49 | app.py:_load_question_text:7698 | `the current session` → `""` | `test_tc_b100_45_title_names_what_is_replaced` (neither arm) | expect-kill |
| M50 | app.py:_load_question_text:7694 | raw `self.current_project` (no `painted_names`) | `test_tc_b100_45_names_paint_literally` | expect-kill |
| M51 | app.py:_load_question_text:7703 | raw image name | `test_tc_b100_45_names_paint_literally` | expect-kill |
| M52 | app.py:_load_question_text:7705 | document item → `the Patch Editor` | `test_tc_b100_45_patch_editor_entries_named_only_when_w`; `tests/test_b100_session_reset.py::test_at_b100_03_…[*]` | expect-kill |
| M53 | app.py:_load_question_text:7707 | flow item without the `flow ` prefix | `test_tc_b100_45_flow_item_named_with_its_flow_name` | expect-kill |
| M54 | app.py:_load_question_text:7709 | name only `names[0]` | `test_tc_b100_45_body_says_unsaved_changes_once_in_two_sentences`; AT15 items arm | expect-kill |
| M55 | app.py:_load_question_text:7711 | join with `", "` only (no ` and `) | `test_tc_b100_45_body_says_unsaved_changes_once_in_two_sentences` | expect-kill |
| M56 | app.py:_load_question_text:7714 | drop the `project ` prefix | `test_tc_b100_45_load_target_named_per_route` | expect-kill |
| M57 | app.py:_load_question_text:7716 | target = `current_file.path.name` | `test_tc_b100_45_load_target_named_per_route` | expect-kill |
| M58 | app.py:_load_question_text:7717 | one sentence per item | `test_tc_b100_45_body_says_unsaved_changes_once_in_two_sentences` | expect-kill |
| M59 | app.py:_route_load_project:7765 | call `go()` directly (no seam) | `test_tc_b100_72_every_load_call_passes_the_seam` is exempt here; `test_tc_b100_44_project_load_asks_iff_a_flag_is_set`; AT-B100-03 re-pin | expect-kill |
| M60 | app.py:_route_load_project:7765 | kind `"image"` | `test_tc_b100_44_project_load_asks_iff_a_flag_is_set` (W-only, F-only arms) | expect-kill |
| M61 | app.py:_handle_select_variant:8213 | stamp `_pending_variant_id` before the seam | `test_tc_b100_46_cancelled_variant_switch_keeps_the_pending_selection` | expect-kill |
| M62 | app.py:_handle_select_variant:8216 | call `go()` directly | `test_tc_b100_72_every_load_call_passes_the_seam`; `..._every_route_asks_and_cancel_keeps_the_session` | expect-kill |
| M63 | app.py:_handle_select_variant:8197 | raw `variant_id` in `Variant not found` | — (C60 has no test) | gap |
| M64 | app.py:_handle_select_variant:8202 | raw name in `Variant file missing` | — (C60 has no test) | gap |
| M65 | app.py:check_action:8665 | `isinstance(s, LoadDialog)` only | `test_tc_b100_45_priority_keys_are_inert_under_the_question` | expect-kill |
| M66 | app.py:check_action:8665 | stack-top test `isinstance(self.screen, (…))` | `test_tc_b100_45_priority_keys_are_inert_under_the_question` (palette arm, only if the palette opened) | expect-kill / verify |
| M67 | app.py:_handle_save_dialog:11192 | `panel._dirty` | `test_tc_b100_44_no_private_dirty_read_outside_the_panel` | expect-kill |
| M68 | app.py:_handle_load_project:12502 | move the install check after `_reset_project_session()` | `test_tc_b100_46_unreadable_a2l_project_after_yes_keeps_the_work` (Windows) | expect-kill |
| M69 | app.py:_handle_load_project:12491 | move the A2L read after the reset | `test_tc_b100_46_unreadable_a2l_project_after_yes_keeps_the_work` (Windows) | expect-kill |
| M70 | app.py:_handle_load_project:12504 | raw `name` in `No supported files` | — (C60 arm; the A2LONLY name is plain) | gap |
| M71 | app.py:_handle_load_project:12516 | move `_declared_regions = …` before the reset | — (the reset clears it to `()`; no in-scope test loads a project with declared regions after a reset) | gap |
| M72 | app.py:_handle_load_project:(after 12584) | restore the interim `Closed the Patch Editor document` line | `tests/test_b100_session_reset.py::test_tc_b100_10_interim_discard_notice`, `::test_tc_b100_10_notice_names_every_discarded_entry` | expect-kill |
| M73 | app.py:_load_path_from_user_input:13741 | `typed = path` (no strip) | `test_tc_b100_72_typed_path_takes_its_kind_from_the_classification` (quoted mac) | expect-kill |
| M74 | app.py:_load_path_from_user_input:13746 | a2l arm kind `"image"` | `test_tc_b100_72_typed_path_takes_its_kind_from_the_classification` (cal.a2l); `test_tc_b100_44_attach_asks_nothing_and_keeps_the_patch` | expect-kill |
| M75 | app.py:_load_path_from_user_input:13751 | `typed.suffix in MAC_EXTENSIONS` (case-sensitive) | `test_tc_b100_72_typed_path_takes_its_kind_from_the_classification` (`typed2.MAC`) | expect-kill |
| M76 | app.py:_load_path_from_user_input:13751 | data arm always `"image"` | `test_tc_b100_72_typed_path_takes_its_kind_from_the_classification`; `test_tc_b100_44_attach_asks_nothing_and_keeps_the_patch` | expect-kill |
| M77 | app.py:_load_path_from_user_input:13752 | data arm loads directly (no seam) | `test_tc_b100_72_every_load_call_passes_the_seam` | expect-kill |
| M78 | app.py:_load_path_from_user_input:13742 | project arm also wrapped in `_confirm_then_load("project", …)` | `test_tc_b100_72_one_question_per_request` (typed project folder asks 2) | expect-kill |
| M79 | app.py:_load_workarea_file:14216 | move the `exists()` check into `go` | — (C39 race arm not a test) | gap |
| M80 | app.py:_load_workarea_file:14220 | kind always `"image"` | `test_tc_b100_72_workarea_file_takes_its_kind_from_its_suffix` | expect-kill |
| M81 | app.py:_load_workarea_file:14220 | drop `A2L_EXTENSIONS` from the attach set | `test_tc_b100_72_workarea_file_takes_its_kind_from_its_suffix` (c.a2l) | expect-kill |
| M82 | app.py:_load_workarea_file:14220 | no `.lower()` | `test_tc_b100_72_workarea_file_takes_its_kind_from_its_suffix` (`U.MAC`) | expect-kill |
| M83 | app.py:_load_workarea_file:14231 | call `go()` directly | `test_tc_b100_72_every_load_call_passes_the_seam`; `test_tc_b100_72_workarea_file_takes_its_kind_from_its_suffix` | expect-kill |

## Gaps (declared, not fixed at E4)

- **M63, M64, M70 — C60 (S10-04) has no test.** The tester's map and its "examples not turned into tests" table both omit C60. The code paints the three lines through `painted_names` (read at E4), but no test can go RED if the scrub is dropped. Route: the orchestrator decides whether E5 adds the C60 test or records the gap.
- **M29** — the dropdown's cancel status line is unasserted (the guard and the Select reset are).
- **M32, M33** — the seam's timing (C09: `go()` synchronous when nothing is lost; `call_after_refresh` on replace) is not a test.
- **M16** — `event.stop()` has no observer.
- **M71** — `_declared_regions` order after the reset: no in-scope killer; the batch-end battery may hold one.
- **M79** — C39 (file deleted during the question) is a declared design note, not a test.
- **M30** — the dropdown guard's accept arm (load after the guard's yes) is not driven: the test covers cancel, re-pick and clean.
- **M66** — verify at E5: the killer depends on whether `ctrl+p` opens the palette in this app (tester §4).
- Not listed: the `Load question answered` log line (diagnostic only), the `_reset_project_session -> None` signature (C51, an interface ruling with no test), the type aliases (C01, code review), docstrings and the `_dirty` comment (P2-1, code review).
