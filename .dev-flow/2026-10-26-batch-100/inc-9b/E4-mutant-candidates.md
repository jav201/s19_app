# Inc 9b — E4 mutant candidates (input to the mutation stage)

One row per NEW branch or arm in the 9b source. Line numbers are those of the integrated tree (source shas in `E4-integration-notes.md` §6). "Killer" is the test the integrator expects to turn RED under the mutation; it is a prediction, not a run (state `planned`). Unless a file is named, killers are in `tests/test_b100_load_dialog.py`. `LD` = `tests/support/b100_load_dialog.py` drivers.

Scope: new arms only. Docstrings, logging-only lines and the unchanged 9a context are out.

## screens.py (G-A: LoadDialog)

| # | file:function:line | Mutation | Expected killer |
|---|---|---|---|
| M01 | screens.py:LoadDialog.BINDINGS:295 | drop `priority=True` from `alt+l` | `test_tc_b100_41_alt_l_with_the_focus_on_the_path_field_loads_and_types_nothing` |
| M02 | screens.py:LoadDialog.BINDINGS:294 | delete the `escape` binding (on_key still handles it) | `test_tc_b100_41_escape_closes_with_no_result_from_every_focus` (focus-None arm) — may survive; if so, record as equivalent (on_key covers every focused widget) |
| M03 | screens.py:LoadDialog.compose:325 | remove `restrict=` | `test_tc_b100_63_pasted_nul_is_not_inserted` |
| M04 | screens.py:LoadDialog.compose:325 | restrict `[^\x00-\x1f]*` (drop `\x7f`) | none expected (no DEL arm) — candidate survivor |
| M05 | screens.py:LoadDialog.compose:327 | `OptionList(markup=True)` | `test_tc_b100_42_project_rows_are_painted_literally[markup bold]` |
| M06 | screens.py:LoadDialog.compose:331-334 | preview `Static(markup=True)` and update with `str` | `test_tc_b100_42_preview_names_are_painted_literally` |
| M07 | screens.py:LoadDialog.compose:330 | `VerticalScroll(..., can_focus=False)` (unfocusable preview) | `test_tc_b100_41_tab_order_wraps_both_ways` |
| M08 | screens.py:LoadDialog.on_mount:361 | `if row[2] is not None` (disable loadable rows instead) | `test_tc_b100_41_load_with_the_list_last_takes_the_highlighted_row` |
| M09 | screens.py:LoadDialog.on_mount:361-362 | delete the disable loop | `test_tc_b100_41_navigation_keys_in_the_list_are_not_redirected` / `test_tc_b100_41_no_loadable_row_highlighted_is_explained` |
| M10 | screens.py:LoadDialog.on_mount:363 | `lst.highlighted = 0` | `test_tc_b100_41_list_opens_on_the_open_project` |
| M11 | screens.py:LoadDialog.on_mount:365 | swap the two focus targets | `test_tc_b100_41_l_and_ctrl_l_open_the_dialog_on_the_path_field`, `test_tc_b100_41_p_and_the_button_open_the_dialog_on_the_list` |
| M12 | screens.py:LoadDialog.on_mount:367 | delete `_apply_stack(...)` call | `test_tc_b100_64_panes_stack_below_100_columns` |
| M13 | screens.py:LoadDialog._initial_index:381 | drop `and choice.value == self._highlight` | `test_tc_b100_41_list_opens_on_the_open_project` |
| M14 | screens.py:LoadDialog._initial_index:384-386 | delete the first-project pass | `test_tc_b100_41_open_project_highlight_falls_back_to_the_first_project` |
| M15 | screens.py:LoadDialog._initial_index:387-389 | delete the first-loadable pass (return None) | `tests/test_b99_load_project.py::test_at_b99_13_project_and_file_pickers_load_by_name` (H-1 assert) |
| M16 | screens.py:LoadDialog.on_key:408-412 | delete the escape arm | `test_tc_b100_41_type_ahead_escape_then_enter_closes_with_none` |
| M17 | screens.py:LoadDialog.on_key:413 | drop `"load_preview"` from the enter arm | `test_tc_b100_41_load_with_the_list_last_takes_the_highlighted_row` (preview-focus arm) |
| M18 | screens.py:LoadDialog.on_key:413-417 | delete the enter arm (OptionList's own enter → OptionSelected, nothing loads) | `test_tc_b100_41_load_with_the_list_last_takes_the_highlighted_row` |
| M19 | screens.py:LoadDialog.on_key:418 | drop `and event.is_printable` | `test_tc_b100_41_navigation_keys_in_the_list_are_not_redirected` |
| M20 | screens.py:LoadDialog.on_key:418-426 | delete the redirect arm | `test_tc_b100_41_printable_key_in_the_list_types_into_the_path_field` |
| M21 | screens.py:LoadDialog.on_key:424 | delete `self._source = "path"` (source set only on focus) | `test_tc_b100_41_type_ahead_c_then_enter_loads_the_typed_text` |
| M22 | screens.py:LoadDialog.on_key:425 | delete `self._schedule_preview(None)` | `test_tc_b100_41_printable_key_clears_the_preview` |
| M23 | screens.py:LoadDialog.on_input_submitted:430 | invert the id test | `test_tc_b100_41_load_with_the_path_last_takes_the_typed_text` |
| M24 | screens.py:LoadDialog.on_button_pressed:437 | `#load_ok` → `action_cancel` | `test_tc_b100_41_load_with_the_list_last_takes_the_highlighted_row` |
| M25 | screens.py:LoadDialog.on_button_pressed:439 | delete the `#load_cancel` arm | `test_tc_b100_41_cancel_closes_with_no_result` |
| M26 | screens.py:LoadDialog.action_load:454-455 | delete the early `_dismissed` return | `test_tc_b100_41_double_enter_dismisses_once` (may survive behind `_close`'s guard — equivalent if so) |
| M27 | screens.py:LoadDialog.action_load:456 | always `_row_choice()` | `test_tc_b100_41_load_with_the_path_last_takes_the_typed_text` |
| M28 | screens.py:LoadDialog.action_load:457-459 | delete the nothing-selected arm (call verdict with None) | `test_tc_b100_41_empty_or_spaces_text_is_explained` |
| M29 | screens.py:LoadDialog.action_load:461-463 | dismiss even when `pair` is not None | `test_tc_b100_63_typed_path_not_found_is_explained` |
| M30 | screens.py:LoadDialog._row_choice:473 | return `self._rows[0][2]` | `test_tc_b100_41_load_with_the_list_last_takes_the_highlighted_row` |
| M31 | screens.py:LoadDialog._path_choice:480 | `if t == ""` (no strip) | `test_tc_b100_41_empty_or_spaces_text_is_explained[spaces]` |
| M32 | screens.py:LoadDialog._path_choice:482 | `LoadChoice("path", t.strip())` | `test_tc_b100_40_path_choice_takes_the_typed_route` / `test_tc_b100_40_recent_choice_loads_the_recorded_text_unchanged` (verbatim arm) |
| M33 | screens.py:LoadDialog._say:486 | separator `-` instead of U+2014 | `test_tc_b100_63_typed_path_not_found_is_explained` |
| M34 | screens.py:LoadDialog._close:490-491 | delete the `_dismissed` guard | `test_tc_b100_41_double_enter_dismisses_once` |
| M35 | screens.py:LoadDialog.on_descendant_focus:503 | drop `"load_path"` from the id set | `test_tc_b100_41_load_with_the_path_last_takes_the_typed_text` |
| M36 | screens.py:LoadDialog.on_descendant_focus:505 | drop `if src != self._source` (always re-preview) | none expected — candidate survivor (idempotent repaint) |
| M37 | screens.py:LoadDialog.on_descendant_focus:507 | always `_schedule_preview(None)` | `test_tc_b100_41_text_in_the_field_then_tab_into_the_list_loads_the_row` / `test_tc_b100_41_preview_follows_the_load_target` |
| M38 | screens.py:LoadDialog.on_option_list_option_highlighted:513 | drop the `_source == "list"` test | `test_tc_b100_41_printable_key_clears_the_preview` |
| M39 | screens.py:LoadDialog._schedule_preview:524 | delete the clear | `test_tc_b100_41_preview_follows_the_load_target` |
| M40 | screens.py:LoadDialog.show_preview:539 | mark every line | `test_tc_b100_64_project_preview_marks_equal_the_install` |
| M41 | screens.py:LoadDialog._apply_stack:549 | `width <= 100` | `test_tc_b100_64_panes_stack_below_100_columns[100]` |
| M42 | screens.py:LoadDialog.on_resize:545 | delete the handler body | `test_tc_b100_64_panes_restack_on_a_live_resize` |

## styles.tcss (G-A + E4 fix)

| # | file:rule:line | Mutation | Expected killer |
|---|---|---|---|
| M43 | styles.tcss:#load_list:1807 | delete `text-wrap: nowrap` | `test_tc_b100_64_list_rows_never_wrap` |
| M44 | styles.tcss:#load_preview Static:1827-1830 | delete the rule (the E4 fix) | `test_tc_b100_64_preview_line_never_wraps` (RED in try-01 before the fix: heights `[7]`) |
| M45 | styles.tcss:#load_panes.stacked:1789 | `layout: horizontal` | `test_tc_b100_64_panes_stack_below_100_columns` |

## app.py (G-B)

| # | file:function:line | Mutation | Expected killer |
|---|---|---|---|
| M46 | app.py:action_load_file:7364 | `mode="list"` | `test_tc_b100_41_l_and_ctrl_l_open_the_dialog_on_the_path_field` |
| M47 | app.py:action_load_project:7483 | callback `self._route_load_project` | `test_tc_b100_40_one_router_receives_every_dialog_result` |
| M48 | app.py:_load_dialog_rows:7573 | remove the `except OSError` arm | `test_tc_b100_43_unreadable_project_list_says_so` |
| M49 | app.py:_load_dialog_rows:7585 | label = raw `name` (no `painted_names`) | `test_tc_b100_42_project_rows_are_painted_literally` |
| M50 | app.py:_load_dialog_rows:7587-7588 | drop the `no projects` token line | `test_tc_b100_43_empty_projects_section_paints_its_tokens` |
| M51 | app.py:_load_dialog_rows:7591 | drop the `recent_kind(p) is not None` filter | `test_tc_b100_43_files_section_is_the_one_lister_filtered_to_loadable_files` |
| M52 | app.py:_load_dialog_rows:7598-7599 | drop the `no work-area files` token line | `test_tc_b100_43_empty_files_section_paints_its_tokens` |
| M53 | app.py:_load_dialog_rows:7602-7609 | drop the store-problem arm (fall to entries) | `test_tc_b100_43_store_problem_is_painted_in_the_recents_section` |
| M54 | app.py:_load_dialog_rows:7610-7611 | drop the `no recent sources` token | `test_tc_b100_43_empty_recents_section_paints_its_token` |
| M55 | app.py:_load_dialog_rows:7614 | label = the full path | `test_tc_b100_43_recent_row_shows_the_file_name_and_kind_only` |
| M56 | app.py:_load_dialog_rows:7613 | `reversed(store.entries)` | `test_tc_b100_43_recents_section_is_the_store_read_in_order` |
| M57 | app.py:_load_dialog_verdict:7650 | drop `"workarea"` from the go set | `test_tc_b100_40_workarea_data_choice_loads_in_place_with_no_copy` |
| M58 | app.py:_load_dialog_verdict:7653 | `if action == "refuse": return None` (invert) | `test_tc_b100_63_typed_path_not_found_is_explained` |
| M59 | app.py:_TYPED_REFUSAL_TOKENS:299 | swap the `outside` step token | `test_tc_b100_63_typed_folder_outside_the_work_area_is_explained` |
| M60 | app.py:_load_dialog_preview:7695-7701 | recent arm calls `Path(value).exists()` | `test_tc_b100_43_no_filesystem_call_touches_a_recent_before_load` |
| M61 | app.py:_load_dialog_preview:7698 | clip the recent path at 120 | `test_tc_b100_43_recent_preview_shows_the_store_facts_only` (ruling 2: the content text is the full path) |
| M62 | app.py:_load_dialog_preview:7715-7722 | delete the `project.json` regular-file gate | `test_tc_b100_64_project_json_that_is_not_a_regular_file_is_refused` |
| M63 | app.py:_load_dialog_preview:7713-7714 | treat `FileNotFoundError` as `could not be read` | `test_tc_b100_64_project_preview_states_the_manifest[no project.json]` |
| M64 | app.py:_load_dialog_preview:7731 | `a2l_ok = bool(a2l_files)` (skip admission) | none in the new file (B77 not turned into a test, tester §6) — candidate survivor |
| M65 | app.py:_load_dialog_preview:7739-7742 | delete the cardinality arm | `test_tc_b100_64_more_than_one_mac_marks_nothing` |
| M66 | app.py:_load_dialog_preview:7751 | mark every variant | `test_tc_b100_64_project_preview_lists_every_variant` / `test_tc_b100_64_project_preview_marks_equal_the_install` |
| M67 | app.py:_load_dialog_preview:7765-7770 | always `state = "ok"` | `test_tc_b100_64_project_preview_states_the_manifest` |
| M68 | app.py:_load_dialog_preview:7773 | delete the outer `except OSError` | `test_tc_b100_64_project_preview_read_error_says_so` |
| M69 | app.py:_file_preview_marks:7816 | drop the kept-MAC line on a data row | `test_tc_b100_64_file_row_preview_marks_what_the_session_keeps` |
| M70 | app.py:_file_preview_marks:7820-7827 | drop the project-open note | `test_tc_b100_64_open_project_note_on_a_data_file_row` |
| M71 | app.py:_file_preview_marks:7830 | MAC row: drop the image line | `test_tc_b100_64_file_row_preview_marks_what_the_session_keeps` |
| M72 | app.py:_file_preview_marks:7837-7840 | A2L row: drop the image / MAC lines | `test_tc_b100_64_file_row_preview_marks_what_the_session_keeps` |
| M73 | app.py:check_action:8417 | `self.screen` instead of the whole stack | `test_tc_b100_41_priority_keys_are_inert_while_the_dialog_is_open` (ctrl+p then ctrl+s arm) |
| M74 | app.py:_LOAD_DIALOG_INERT_ACTIONS:317 | drop `cycle_density` | `test_tc_b100_41_priority_keys_are_inert_while_the_dialog_is_open` |
| M75 | app.py:_handle_load_project:12115-12124 | delete the `except OSError` on `_list_project_files` | `test_tc_b100_40_unreadable_picked_project_paints_one_status_line` |
| M76 | app.py:_handle_load_project:12116 | call `validate_project_files` again | `test_tc_b100_64_linked_file_in_a_project_is_neither_listed_nor_installed` (skipped where `os.symlink` raises) |
| M77 | app.py:_handle_load_project:12208 | delete the `S_ISREG` refusal | `test_tc_b100_64_project_json_that_is_not_a_regular_file_is_refused` |
| M78 | app.py:_handle_load_project:12194-12218 | move the gate after `_reset_project_session()` | `test_tc_b100_64_project_json_that_is_not_a_regular_file_is_refused` (session-unchanged arm) |
| M79 | app.py:list_projects:12546 | `if held is not True: continue` (fail-closed) | `tests/test_b100_recents.py::test_tc_b100_38_unreadable_folder_paints_could_not_be_read[route: _list_project_files]` |
| M80 | app.py:list_projects:12545-12547 | delete the content test | `test_tc_b100_43_a_folder_that_is_not_a_project_is_not_listed` |
| M81 | app.py:_folder_holds_project:12666 | drop `not _is_reparse_point(manifest_path)` | none expected on a volume without file links — candidate survivor |
| M82 | app.py:_folder_holds_project:12671-12672 | `except OSError: return False` | `tests/test_b100_recents.py::test_tc_b100_38_unreadable_folder_paints_could_not_be_read[route: _list_project_files]` |
| M83 | app.py:_list_project_files:12723 | `entry.is_file()` (follows links) | `test_tc_b100_64_linked_file_in_a_project_is_neither_listed_nor_installed` |
| M84 | app.py:_list_project_files:12729 | do not count MAC files | `test_tc_b100_64_more_than_one_mac_marks_nothing` |
| M85 | app.py:_list_project_files:12736 | delete the more-than-one-A2L arm | none in the targeted set — candidate survivor (9a arm lives in the deferred project-homes module) |
| M86 | app.py:_a2l_admission:12775 | `>=` the cap | none expected (no exact-cap arm) — candidate survivor |
| M87 | app.py:_a2l_admission:12773 | drop the `_is_reparse_point` test | `tests/test_b100_project_homes.py` A2L link arm (deferred module; re-pinned nodes only) — likely survivor in the targeted set |
| M88 | app.py:_typed_load_route:13431 | drop `and stat.S_ISREG(last_stat.st_mode)` | `test_tc_b100_63_folder_named_like_a_data_file` |
| M89 | app.py:_typed_load_route:13470-13471 | `held is None` → `not a project` | `test_tc_b100_63_typed_folder_that_cannot_be_read_is_explained` |
| M90 | app.py:_handle_load_dialog:13572 | delete `_rehome_focus_after_load()` | `tests/test_b100_focus.py::test_tc_b100_12_load_dialog_close_rehomes_a_stale_input_focus` |
| M91 | app.py:_handle_load_dialog:13586-13587 | route `workarea` through `_load_path_from_user_input` | `test_tc_b100_40_workarea_data_choice_loads_in_place_with_no_copy` |
| M92 | app.py:_handle_load_dialog:13584 | call `_route_load_project` synchronously | none expected (behaviour equal at the user level) — candidate survivor |
| M93 | app.py:load_from_path:13658 | drop `and not via_fallback` | `tests/test_b100_recents.py::test_tc_b100_34_source_found_only_in_the_base_folder_is_not_recorded` |
| M94 | app.py:load_a2l_from_path:13734 | drop `and not via_fallback` | `tests/test_b100_recents.py::test_tc_b100_34_a2l_found_only_through_the_fallback_is_not_recorded` |
| M95 | app.py:load_a2l_from_path:13780 | paint `copied.name` raw | none in the targeted set (S9b-5 arm B100 not turned into a test) — candidate survivor |
| M96 | app.py:_load_workarea_file:13971 | always `load_a2l_from_path` | `test_tc_b100_40_workarea_data_choice_loads_in_place_with_no_copy` |

Predicted survivors to confirm or kill at the mutation stage: M02, M04, M26, M36, M64, M81, M85, M86, M87, M92, M95.
