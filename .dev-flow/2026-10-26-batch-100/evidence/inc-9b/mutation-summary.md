# Inc 9b — mutation summary (E4 mutation stage)

Copy under test: `<HOME>/AppData/Local/Temp/claude/C--Users-<USER>-clde/a8feab43-c248-4ccb-86cf-122b894659b2/scratchpad/mut9b`
Interpreter: `<HOME>/anaconda3/envs/s19env/python.exe` (env `s19env`)
`s19_app.__file__` resolves inside the copy. Every pytest run set `LOCALAPPDATA` to the scratch folder; `<HOME>/AppData/Local/s19_app` never existed before or after.

## Results

| id | requirement | file | test | verdict |
|---|---|---|---|---|
| M01 | drop `priority=True` from `alt+l` | screens.py | test_tc_b100_41_alt_l_with_the_focus_on_the_path_field_loads_and_types_nothing | KILLED |
| M02 | delete the `escape` binding | screens.py | test_tc_b100_41_escape_closes_with_no_result_from_every_focus | SURVIVED |
| M03 | remove `restrict=` | screens.py | test_tc_b100_63_pasted_nul_is_not_inserted | KILLED |
| M04 | restrict `[^\x00-\x1f]*` (drop `\x7f`) | screens.py | test_tc_b100_63_pasted_nul_is_not_inserted | SURVIVED |
| M05 | `OptionList(markup=True)` | screens.py | test_tc_b100_42_project_rows_are_painted_literally[markup bold] | KILLED |
| M06 | preview `Static(markup=True)` + update with `str` | screens.py | test_tc_b100_42_preview_names_are_painted_literally | KILLED |
| M07 | `VerticalScroll(can_focus=False)` | screens.py | test_tc_b100_41_tab_order_wraps_both_ways | KILLED |
| M08 | `if row[2] is not None` (disable loadable rows) | screens.py | test_tc_b100_41_load_with_the_list_last_takes_the_highlighted_row | KILLED |
| M09 | delete the disable loop | screens.py | test_tc_b100_41_navigation_keys_in_the_list_are_not_redirected / …no_loadable_row_highlighted_is_explained | SURVIVED |
| M10 | `lst.highlighted = 0` | screens.py | test_tc_b100_41_list_opens_on_the_open_project | KILLED |
| M11 | swap the two focus targets | screens.py | test_tc_b100_41_l_and_ctrl_l_open_the_dialog_on_the_path_field / …p_and_the_button_open_the_dialog_on_the_list | KILLED |
| M12 | delete `_apply_stack(...)` on mount | screens.py | test_tc_b100_64_panes_stack_below_100_columns | SURVIVED |
| M13 | drop `and choice.value == self._highlight` | screens.py | test_tc_b100_41_list_opens_on_the_open_project | KILLED |
| M14 | delete the first-project pass | screens.py | test_tc_b100_41_open_project_highlight_falls_back_to_the_first_project | SURVIVED |
| M15 | delete the first-loadable pass | screens.py | tests/test_b99_load_project.py::test_at_b99_13_project_and_file_pickers_load_by_name | KILLED |
| M16 | delete the escape arm | screens.py | test_tc_b100_41_type_ahead_escape_then_enter_closes_with_none | KILLED |
| M17 | drop `"load_preview"` from the enter arm | screens.py | test_tc_b100_41_load_with_the_list_last_takes_the_highlighted_row | SURVIVED |
| M18 | delete the enter arm | screens.py | test_tc_b100_41_load_with_the_list_last_takes_the_highlighted_row | KILLED |
| M19 | drop `and event.is_printable` | screens.py | test_tc_b100_41_navigation_keys_in_the_list_are_not_redirected | KILLED |
| M20 | delete the redirect arm | screens.py | test_tc_b100_41_printable_key_in_the_list_types_into_the_path_field | KILLED |
| M21 | delete `self._source = "path"` | screens.py | test_tc_b100_41_type_ahead_c_then_enter_loads_the_typed_text | KILLED |
| M22 | delete `self._schedule_preview(None)` | screens.py | test_tc_b100_41_printable_key_clears_the_preview | KILLED |
| M23 | invert the id test | screens.py | test_tc_b100_41_load_with_the_path_last_takes_the_typed_text | KILLED |
| M24 | `#load_ok` → `action_cancel` | screens.py | test_tc_b100_41_load_with_the_list_last_takes_the_highlighted_row | KILLED |
| M25 | delete the `#load_cancel` arm | screens.py | test_tc_b100_41_cancel_closes_with_no_result | KILLED |
| M26 | delete the early `_dismissed` return | screens.py | test_tc_b100_41_double_enter_dismisses_once | SURVIVED |
| M27 | always `_row_choice()` | screens.py | test_tc_b100_41_load_with_the_path_last_takes_the_typed_text | KILLED |
| M28 | delete the nothing-selected arm | screens.py | test_tc_b100_41_empty_or_spaces_text_is_explained | KILLED |
| M29 | dismiss even when `pair` is not None | screens.py | test_tc_b100_63_typed_path_not_found_is_explained | KILLED |
| M30 | return `self._rows[0][2]` | screens.py | test_tc_b100_41_load_with_the_list_last_takes_the_highlighted_row | KILLED |
| M31 | `if t == ""` (no strip) | screens.py | test_tc_b100_41_empty_or_spaces_text_is_explained[spaces] | KILLED |
| M32 | `LoadChoice("path", t.strip())` | screens.py | test_tc_b100_40_path_choice_takes_the_typed_route / …recent_choice_loads_the_recorded_text_unchanged | SURVIVED |
| M33 | separator `-` instead of U+2014 | screens.py | test_tc_b100_63_typed_path_not_found_is_explained | SURVIVED |
| M34 | delete the `_dismissed` guard in `_close` | screens.py | test_tc_b100_41_double_enter_dismisses_once | SURVIVED |
| M35 | drop `"load_path"` from the id set | screens.py | test_tc_b100_41_load_with_the_path_last_takes_the_typed_text | SURVIVED |
| M36 | drop `if src != self._source` (always re-preview) | screens.py | test_tc_b100_41_preview_follows_the_load_target | SURVIVED |
| M37 | always `_schedule_preview(None)` | screens.py | test_tc_b100_41_text_in_the_field_then_tab_into_the_list_loads_the_row / …preview_follows_the_load_target | KILLED |
| M38 | drop the `_source == "list"` test | screens.py | test_tc_b100_41_printable_key_clears_the_preview | SURVIVED |
| M39 | delete the clear in `_schedule_preview` | screens.py | test_tc_b100_41_preview_follows_the_load_target | SURVIVED |
| M40 | mark every line | screens.py | test_tc_b100_64_project_preview_marks_equal_the_install | KILLED |
| M41 | `width <= 100` | screens.py | test_tc_b100_64_panes_stack_below_100_columns[100-False] | KILLED |
| M42 | delete the resize handler body | screens.py | test_tc_b100_64_panes_restack_on_a_live_resize | KILLED |
| M43 | delete `text-wrap: nowrap` on `#load_list` | styles.tcss | test_tc_b100_64_list_rows_never_wrap | KILLED |
| M44 | delete the `#load_preview Static` rule | styles.tcss | test_tc_b100_64_preview_line_never_wraps | KILLED |
| M45 | `#load_panes.stacked` → `layout: horizontal` | styles.tcss | test_tc_b100_64_panes_stack_below_100_columns | KILLED |
| M46 | `mode="list"` in `action_load_file` | app.py | test_tc_b100_41_l_and_ctrl_l_open_the_dialog_on_the_path_field | KILLED |
| M47 | callback `self._route_load_project` | app.py | test_tc_b100_40_one_router_receives_every_dialog_result | KILLED |
| M48 | remove the `except OSError` arm | app.py | test_tc_b100_43_unreadable_project_list_says_so | KILLED |
| M49 | label = raw `name` | app.py | test_tc_b100_42_project_rows_are_painted_literally | KILLED |
| M50 | drop the `no projects` token line | app.py | test_tc_b100_43_empty_projects_section_paints_its_tokens | KILLED |
| M51 | drop the `recent_kind` filter | app.py | test_tc_b100_43_files_section_is_the_one_lister_filtered_to_loadable_files | KILLED |
| M52 | drop the `no work-area files` token | app.py | test_tc_b100_43_empty_files_section_paints_its_tokens | KILLED |
| M53 | drop the store-problem arm | app.py | test_tc_b100_43_store_problem_is_painted_in_the_recents_section | KILLED |
| M54 | drop the `no recent sources` token | app.py | test_tc_b100_43_empty_recents_section_paints_its_token | KILLED |
| M55 | label = the full path | app.py | test_tc_b100_43_recent_row_shows_the_file_name_and_kind_only | KILLED |
| M56 | `reversed(store.entries)` | app.py | test_tc_b100_43_recents_section_is_the_store_read_in_order | KILLED |
| M57 | drop `"workarea"` from the go set | app.py | test_tc_b100_40_workarea_data_choice_loads_in_place_with_no_copy | SURVIVED |
| M58 | `if action == "refuse": return None` (invert) | app.py | test_tc_b100_63_typed_path_not_found_is_explained | KILLED |
| M59 | swap the `outside` step token | app.py | test_tc_b100_63_typed_folder_outside_the_work_area_is_explained | SURVIVED |
| M60 | recent arm calls `Path(value).exists()` | app.py | test_tc_b100_43_no_filesystem_call_touches_a_recent_before_load | KILLED |
| M61 | clip the recent path at 120 | app.py | test_tc_b100_43_recent_preview_shows_the_store_facts_only | SURVIVED |
| M62 | delete the `project.json` regular-file gate | app.py | test_tc_b100_64_project_json_that_is_not_a_regular_file_is_refused | KILLED |
| M63 | treat `FileNotFoundError` as `could not be read` | app.py | test_tc_b100_64_project_preview_states_the_manifest[absent] | KILLED |
| M64 | `a2l_ok = bool(a2l_files)` (skip admission) | app.py | test_tc_b100_64_project_preview_marks_equal_the_install | SURVIVED |
| M65 | delete the cardinality arm | app.py | test_tc_b100_64_more_than_one_mac_marks_nothing | KILLED |
| M66 | mark every variant | app.py | test_tc_b100_64_project_preview_lists_every_variant / …project_preview_marks_equal_the_install | KILLED |
| M67 | always `state = "ok"` | app.py | test_tc_b100_64_project_preview_states_the_manifest | KILLED |
| M68 | delete the outer `except OSError` | app.py | test_tc_b100_64_project_preview_read_error_says_so | KILLED |
| M69 | drop the kept-MAC line on a data row | app.py | test_tc_b100_64_file_row_preview_marks_what_the_session_keeps | KILLED |
| M70 | drop the project-open note | app.py | test_tc_b100_64_open_project_note_on_a_data_file_row | KILLED |
| M71 | MAC row: drop the image line | app.py | test_tc_b100_64_file_row_preview_marks_what_the_session_keeps | SURVIVED |
| M72 | A2L row: drop the image / MAC lines | app.py | test_tc_b100_64_file_row_preview_marks_what_the_session_keeps | KILLED |
| M73 | `self.screen` instead of the whole stack | app.py | test_tc_b100_41_priority_keys_are_inert_while_the_dialog_is_open | KILLED |
| M74 | drop `cycle_density` | app.py | test_tc_b100_41_priority_keys_are_inert_while_the_dialog_is_open | KILLED |
| M75 | delete the `except OSError` on `_list_project_files` | app.py | test_tc_b100_40_unreadable_picked_project_paints_one_status_line | KILLED |
| M76 | call `validate_project_files` again | app.py | test_tc_b100_64_linked_file_in_a_project_is_neither_listed_nor_installed | KILLED |
| M77 | delete the `S_ISREG` refusal | app.py | test_tc_b100_64_project_json_that_is_not_a_regular_file_is_refused | KILLED |
| M78 | move the gate after `_reset_project_session()` | app.py | test_tc_b100_64_project_json_that_is_not_a_regular_file_is_refused | SURVIVED |
| M79 | `if held is not True: continue` (fail-closed) | app.py | tests/test_b100_recents.py::test_tc_b100_38_unreadable_folder_paints_could_not_be_read[route: _list_project_files] | KILLED |
| M80 | delete the content test | app.py | test_tc_b100_43_a_folder_that_is_not_a_project_is_not_listed | KILLED |
| M81 | drop `not _is_reparse_point(manifest_path)` | app.py | test_tc_b100_43_a_folder_that_is_not_a_project_is_not_listed | SURVIVED |
| M82 | `except OSError: return False` | app.py | tests/test_b100_recents.py::test_tc_b100_38_unreadable_folder_paints_could_not_be_read[route: _list_project_files] | KILLED |
| M83 | `entry.is_file()` (follows links) | app.py | test_tc_b100_64_linked_file_in_a_project_is_neither_listed_nor_installed | KILLED |
| M84 | do not count MAC files | app.py | test_tc_b100_64_more_than_one_mac_marks_nothing | KILLED |
| M85 | delete the more-than-one-A2L arm | app.py | test_tc_b100_64_more_than_one_mac_marks_nothing | SURVIVED |
| M86 | `>=` the cap | app.py | tests/test_b100_project_homes.py::test_tc_b100_32_a2l_guard_of_an_a2l_only_folder[at cap] | KILLED |
| M87 | drop the `_is_reparse_point` test | app.py | tests/test_b100_project_homes.py::test_tc_b100_32_a2l_guard_of_an_a2l_only_folder[link] | SURVIVED |
| M88 | drop `and stat.S_ISREG(last_stat.st_mode)` | app.py | test_tc_b100_63_folder_named_like_a_data_file | KILLED |
| M89 | `held is None` → `not a project` | app.py | test_tc_b100_63_typed_folder_that_cannot_be_read_is_explained | SURVIVED |
| M90 | delete `_rehome_focus_after_load()` | app.py | tests/test_b100_focus.py::test_tc_b100_12_load_dialog_close_rehomes_a_stale_input_focus | KILLED |
| M91 | route `workarea` through `_load_path_from_user_input` | app.py | test_tc_b100_40_workarea_data_choice_loads_in_place_with_no_copy | KILLED |
| M92 | call `_route_load_project` synchronously | app.py | test_tc_b100_40_one_router_receives_every_dialog_result | SURVIVED |
| M93 | drop `and not via_fallback` | app.py | tests/test_b100_recents.py::test_tc_b100_34_source_found_only_in_the_base_folder_is_not_recorded | KILLED |
| M94 | drop `and not via_fallback` | app.py | tests/test_b100_recents.py::test_tc_b100_34_a2l_found_only_through_the_fallback_is_not_recorded | KILLED |
| M95 | paint `copied.name` raw | app.py | test_tc_b100_40_workarea_a2l_choice_equals_the_files_list_pick | SURVIVED |
| M96 | always `load_a2l_from_path` | app.py | test_tc_b100_40_workarea_data_choice_loads_in_place_with_no_copy | KILLED |

## Counts

- KILLED: 70
- SURVIVED: 26
- INVALID: 0

## Survivors — why each one survived

- **M02** (equivalent): `on_key` handles `escape` from every focused widget, so the deleted `escape` binding is redundant; the killer never reaches the `f is None` arm where the binding would have mattered.
- **M04** (weak test): the pasted payload is `a\x00.s19` — it contains NUL but no DEL, so dropping `\x7f` from the restrict pattern changes nothing the test can see.
- **M09** (weak test): neither named killer navigates or clicks onto a disabled heading. `…no_loadable_row_highlighted_is_explained` sets `highlighted = 0` by code (where disabled-vs-enabled is irrelevant and `_row_choice` still returns `None`), and the navigation test only moves `down`/`up` from a real row.
- **M12** (equivalent): the initial Resize event fires `on_resize` → `_apply_stack(event.size.width)` when the dialog first lays out, so the on-mount `_apply_stack` call is redundant.
- **M14** (equivalent): in every scenario the Projects section is listed first, so the first project row *is* the first loadable row; the deleted "first project" pass and the surviving "first loadable" pass return the same index.
- **M17** (wrong target): `test_tc_b100_41_load_with_the_list_last_takes_the_highlighted_row` focuses the list (`_highlight_index`) and presses enter; it never focuses `#load_preview`, so the dropped preview arm is never exercised.
- **M26** (equivalent): `_close` still has its own `_dismissed` guard, which blocks the second dismiss once `action_load` has dismissed.
- **M32** (weak test): the typed path in `…path_choice_takes_the_typed_route` is an absolute path with no surrounding spaces (strip is a no-op), and `…recent_choice_loads_the_recorded_text_unchanged` drives recent choices through `_row_choice`, not `_path_choice`.
- **M33** (equivalent): `_assert_refused` checks `reason in painted and step in painted` (substring), so `-` vs `—` never changes the assertion.
- **M34** (equivalent): `action_load`'s own `_dismissed` early-return (M26's subject) already prevents the second `_close`, so `_close`'s guard is redundant.
- **M35** (wrong target): the killer runs in path mode where `_source` starts as `"path"`, so the dropped `load_path` arm (which only matters when focus flips from list to path) never fires.
- **M36** (equivalent, idempotent repaint): re-running `_schedule_preview` on every descendant-focus is a no-op for the painted result; `test_tc_b100_41_preview_follows_the_load_target` still sees the correct preview.
- **M38** (weak test): pressing a printable key in the list does not emit an `OptionHighlighted` event (the highlight index never changes), so the unconditional `_schedule_preview` added by M38 never runs in the killer.
- **M39** (weak test): the deleted clear only matters when the source flips list→path with a stale list preview already painted; the killer opens fresh in path mode (empty preview) and its list→path arms repaint via `update`, which replaces the body.
- **M57** (wrong target): `test_tc_b100_40_workarea_data_choice_loads_in_place_with_no_copy` calls `app._handle_load_dialog(LC("workarea", …))` directly, bypassing `_load_dialog_verdict` where the mutation lives.
- **M59** (equivalent): `_assert_refused` checks both reason and step with `in`; swapping the two tokens leaves both substrings present.
- **M61** (weak test): the preview test's recorded paths are all far shorter than 120 chars, so `clip=120` truncates nothing.
- **M64** (weak test): every project in `test_tc_b100_64_project_preview_marks_equal_the_install` carries an admissible (in-cap, non-link) A2L, where `_a2l_admission` returns `None` anyway — the skipped admission call changes no mark.
- **M71** (weak test): `FILE_CASES` never highlights a `.mac` row (temp holds only `a.s19`, `b.hex`, `c.a2l`), so the MAC-row image line is never painted in the killer.
- **M78** (weak test): `_digest` of a fresh, empty session is `(None, None, None, None, None)` before and after, and `_reset_project_session()` on an empty session is a no-op — the "session-unchanged" arm cannot see that a reset call now happens before the refusal.
- **M81** (weak test / equivalent on this volume): no killer creates a `project.json` that is a reparse point yet reports `S_ISREG`, so the dropped `_is_reparse_point` term never changes a listing outcome here.
- **M85** (weak test): the named killer (`…more_than_one_mac_marks_nothing`) exercises only the MAC cardinality arm; the deleted more-than-one-A2L arm has no test in the targeted set.
- **M87** (killer pre-existing failure): the named killer `…[link]` is already red on the clean tree (the deferred project-homes module still tests 9a's link-following `validate_project_files`, which Inc 9b's link-safe `_list_project_files` bypasses), so the mutation is not what turns it red — the mutant is effectively undetected.
- **M89** (wrong target): both arms inject the `PermissionError` into `os.lstat` / `list_projects`, which `_typed_load_route` itself catches and maps to `"unreadable"` *before* `_folder_holds_project` is consulted; the `held is None` arm is never reached.
- **M92** (equivalent): calling `_route_load_project` synchronously instead of via `call_after_refresh` is behaviorally equal at the user level; the AST census killer only checks which callback each push site passes, not the deferral.
- **M95** (weak test): no test loads an A2L whose name would differ between `painted_names([copied.name])` and raw `copied.name` (no hostile/control name in the A2L status path), so the scrub is unobservable.

## Predicted survivors vs. observed

The table predicted 11 survivors. Observed: **10 confirmed** (M02, M04, M26, M36, M64, M81, M85, M87, M92, M95) and **1 refuted — M86 was KILLED** by `test_tc_b100_32_a2l_guard_of_an_a2l_only_folder[at cap]` (the exact-cap arm does exist in the deferred module). An additional 16 survivors were found that the table did not predict (M09, M12, M14, M17, M32, M33, M34, M35, M38, M39, M57, M59, M61, M71, M78, M89).
