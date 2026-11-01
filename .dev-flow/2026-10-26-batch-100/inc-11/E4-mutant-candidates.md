# Inc 11 — E4 mutant candidates (input to the mutation stage)

One row per NEW branch or arm of the Inc 11 source, at the integrated tree (line numbers of the post-E4 files; CRLF). "Killer" is the test node expected to turn RED; it is the integrator's expectation from the test names and the tester's map (`E4-tester-notes.md`), not a run result. Only row M-20 was executed here (evidence `executed`); every other row is `planned`.

Abbreviations: `SD` = `tests/test_b100_save_dialog.py`; `sps` = `SaveProjectScreen`; `prep` = `S19TuiApp._prepare_project_save`.

"Expected survivor" marks a row where no test in scope can see the mutation: a guard that is redundant, or an example the tester did not turn into a test (named in `E4-tester-notes.md` §Examples not turned into tests). Those rows are listed so the mutation stage classifies them, not to be killed here.

## screens.py (G-A)

| Id | file:function:line | Mutation | Killer (expected) |
|---|---|---|---|
| M-01 | screens.py:sps (class):985 | `AUTO_FOCUS = "#project_name"` → `None` | `SD::test_tc_b100_49_dialog_opens_with_the_focus_in_the_name_field` |
| M-02 | screens.py:sps (class):989 | `alt+s` binding `priority=True` → `False` | `SD::test_tc_b100_49_confirming_save_closes_and_saves[alt+s]` |
| M-03 | screens.py:sps (class):988 | delete the `escape` binding | `SD::test_tc_b100_49_escape_from_each_focus_position` |
| M-05 | screens.py:sps.compose:1033 | `#save_where` `markup=False` → `markup=True` | `SD::test_tc_b100_65_names_are_painted_literally` |
| M-06 | screens.py:sps.compose:1068 | `"Save (alt+s)"` → `"Save"` | `SD::test_tc_b100_49_buttons_show_their_keys_and_the_keys_work` |
| M-07 | screens.py:sps._first_preview:1087 | delete `self._live = True` | `SD::test_tc_b100_65_recompute_is_a_150ms_debounce` |
| M-09 | screens.py:sps.on_input_changed:1092 | drop `or not self._live` | `SD::test_tc_b100_65_first_preview_after_the_first_frame_and_once_while_idle` |
| M-10 | screens.py:sps.on_input_changed:1094 | delete `self._stop_trailing()` (timers pile up) | `SD::test_tc_b100_65_recompute_at_most_three_of_twenty_keystrokes` |
| M-11 | screens.py:(module):926 | `SAVE_RECOMPUTE_S = 0.150` → `0.0` | `SD::test_tc_b100_65_recompute_is_a_150ms_debounce` |
| M-13 | screens.py:sps._paint:1124 | `self._plan = p.plan` → `self._plan = None` | `SD::test_tc_b100_65_save_executes_the_painted_plan` |
| M-14 | screens.py:sps._paint:1125 | delete `self._shown = False` | `SD::test_tc_b100_65_save_before_the_preview_is_shown_repaints` |
| M-15 | screens.py:sps._paint:1130 | `set_class(<cond>, "refusal")` → `set_class(False, "refusal")` | `SD::test_tc_b100_65_paint_rows_verbatim_in_order_and_refusal_empties` |
| M-17 | screens.py:sps._paint:1141 | delete the stale-row removal loop | `SD::test_tc_b100_65_paint_rows_verbatim_in_order_and_refusal_empties` |
| M-19 | screens.py:sps._mark_shown:1147 | body → `pass` (never shown) | `SD::test_tc_b100_49_confirming_save_closes_and_saves` |
| M-20 | screens.py:sps.action_save:1159 | `self._plan if self._shown else None` → `self._plan` | `SD::test_tc_b100_65_save_before_the_preview_is_shown_repaints` — **executed: killed** (`AssertionError: ('fresh1', SavePlan(...))`, 1 failed in 3.64 s, `evidence/inc-11/int-mut-M20.txt`; source restored, CRLF count re-checked) |
| M-21 | screens.py:sps.action_save:1161 | `if again is not None` → `if again is None` | `SD::test_tc_b100_49_confirming_save_closes_and_saves` |
| M-23 | screens.py:sps.action_save:1172 | `parent_folder=str(painted.target.parent)` → `str(Path.cwd())` | `SD::test_tc_b100_48_payload_parent_is_the_work_area_under_a_long_base` |
| M-24 | screens.py:sps.action_save:1176 | `plan=painted` → `plan=None` | `SD::test_tc_b100_65_save_executes_the_painted_plan` (identity) |
| M-26 | screens.py:sps.on_input_submitted:1181 | `== "project_name"` → `!= "project_name"` | `SD::test_tc_b100_49_confirming_save_closes_and_saves[enter]` |
| M-27 | screens.py:sps.on_button_pressed:1234 | `save_ok` → `self.action_cancel()` | `SD::test_tc_b100_49_confirming_save_closes_and_saves[save_ok]` |
| M-28 | screens.py:sps.on_button_pressed:1236 | `save_cancel` → `self.action_save()` | `SD::test_tc_b100_49_cancel_closes_with_no_result[click]` |
| M-29 | screens.py:sps._close:1254 | delete the `_dismissed` guard | `SD::test_tc_b100_49_escape_with_a_recompute_pending_and_double_close` |

## styles.tcss (G-A)

| Id | file:rule:line | Mutation | Killer (expected) |
|---|---|---|---|
| M-31 | styles.tcss:#save_summary:1883 | delete `max-height: 50vh` | `SD::test_tc_b100_65_buttons_stay_visible_and_rows_never_wrap` |
| M-32 | styles.tcss:#save_summary Static:1897 | `text-wrap: nowrap` → `wrap` | `SD::test_tc_b100_65_buttons_stay_visible_and_rows_never_wrap` |
| M-33 | styles.tcss:#save_where.refusal:1878 | `text-style: bold` → `none` | `SD::test_tc_b100_65_paint_rows_verbatim_in_order_and_refusal_empties` |

## app.py (G-B)

| Id | file:function:line | Mutation | Killer (expected) |
|---|---|---|---|
| M-35 | app.py:action_save_project:7634 | delete the nothing-loaded guard | `SD::test_tc_b100_49_nothing_loaded_opens_no_dialog` |
| M-36 | app.py:action_save_project:7634 | drop `and not self.current_a2l_path` | `SD::test_tc_b100_49_an_a2l_alone_opens_the_dialog` |
| M-37 | app.py:action_save_project:7657 | `initial_name=self.current_project` → `None` | `SD::test_tc_b100_49_open_project_name_is_offered_selected` |
| M-38 | app.py:action_save_project:7654 | `self._current_save_session()` → `self._save_session_inputs()` (a session per preview) | `SD::test_tc_b100_65_session_decided_once_per_open_case06` |
| M-40 | app.py:check_action:8859 | drop `SaveProjectScreen` from the whole-stack tuple | `SD::test_tc_b100_49_priority_keys_are_inert_while_the_dialog_is_open` |
| M-41 | app.py:check_action:8859 | `any(... for s in self.screen_stack)` → `isinstance(self.screen, ...)` | `SD::test_tc_b100_49_priority_keys_are_inert_while_the_dialog_is_open` (the `ctrl+p` arm) |
| M-42 | app.py:_handle_save_dialog:10293 | delete `self._save_session = None` | `SD::test_tc_b100_65_save_as_then_patch_then_direct_save_plans_fresh` |
| M-43 | app.py:_handle_save_dialog:10322 | the identity condition → `True` (always re-prepare) | `SD::test_tc_b100_65_save_executes_the_painted_plan` |
| M-44 | app.py:_handle_save_dialog:10325 | `confirmed.plan is payload.plan` → `==` | expected survivor (B11-14 not built as a test) |
| M-45 | app.py:_handle_save_dialog:10326 | drop `confirmed.typed_name == payload.project_name` | expected survivor (B11-14 not built as a test) |
| M-47 | app.py:prep:10411 | delete the blank-name refusal | `SD::test_tc_b100_49_empty_save_keeps_the_dialog_and_says_why` |
| M-48 | app.py:prep:10425 | device check on `cleaned` only | `SD::test_tc_b100_47_device_names_raw_component_and_sanitised` |
| M-49 | app.py:prep:10434 | reserved compare without `casefold` | `SD::test_tc_b100_47_reserved_names_in_mixed_case` |
| M-50 | app.py:prep:10439 | `>` → `>=` | `SD::test_tc_b100_47_name_cap_64_65_300` |
| M-51 | app.py:prep:10446 | drop `_SAVE_REPORT_SUFFIX_CHARS` from the sum | `SD::test_tc_b100_47_path_limit_met_and_exceeded` |
| M-52 | app.py:prep:10455 | delete the `except OSError` around the listing | `SD::test_tc_b100_47_refusal_painted_in_the_dialog_before_save[workarea]` |
| M-53 | app.py:prep:10465 | the clash pre-filter without `casefold` | `SD::test_tc_b100_47_disguised_clash_names_both_and_exact_name_merges` (`AB` arm) |
| M-54 | app.py:prep:10467 | delete `exact_folder = True` (SR-11-1) | `SD::test_tc_b100_47_strasse_open_strasse_eszett_present_is_a_clash` (exact-name merge arm) |
| M-55 | app.py:prep:10486 | `os.path.samefile(item, ...)` → case-folded name equality | `SD::test_tc_b100_47_strasse_open_strasse_eszett_present_is_a_clash` |
| M-56 | app.py:prep:10494 | `typed_name != item.name` → `cleaned != item.name` | `SD::test_tc_b100_47_disguised_clash_names_both_and_exact_name_merges` (`a b` arm) |
| M-57 | app.py:prep:10503 | delete the LED .52(a) rebind | `SD::test_tc_b100_47_target_line_names_the_sanitised_folder_open_project_in_another_case` |
| M-58 | app.py:prep:10508 | session refusal `toast=True` → `False` | `tests/test_b99_staging.py::test_tc_b99_ux_c10_save_project_filename_renders_literally` |
| M-59 | app.py:prep:10609 | `if live:` → unconditional write (S11-10) | `SD::test_tc_b100_65_save_as_then_patch_then_direct_save_plans_fresh` |
| M-60 | app.py:prep:10606 | compute `live` after `replace(...)` (R3-01) | `SD::test_tc_b100_65_save_as_inventory_walked_once_per_open` |
| M-61 | app.py:prep:10600 | drop `session.inventory is None` | `SD::test_tc_b100_65_save_as_inventory_walked_once_per_open` |
| M-62 | app.py:prep:10625 | delete the P-4 `_err` refusal (A11-07) | `SD::test_tc_b100_47_target_with_two_mac_files_refused_in_the_dialog` |
| M-63 | app.py:prep:10644 | the variant match → the first variant (`next(iter(...))`) | `SD::test_tc_b100_65_active_variant_stem_collision_is_predicted_exactly` |
| M-64 | app.py:prep:10660 | `>` → `>=` | `SD::test_tc_b100_47_free_space_short_by_one_and_exact` |
| M-65 | app.py:prep:10661 | the shortfall refusal passes `plan=plan` (A11-02) | `SD::test_tc_b100_47_free_space_short_by_one_and_exact` (`plan is None`) |
| M-66 | app.py:_save_session_inputs:10722 | move the `exists()` test out of the `try` (S11-02) | `SD::test_tc_b100_47_unreadable_source_painted_and_app_runs[exists]` |
| M-67 | app.py:_save_session_inputs:10724 | delete the missing-source branch | `SD::test_tc_b100_47_missing_source_painted_at_open` |
| M-68 | app.py:_save_session_inputs:10739 | drop `not image_step.emit` (digest the image always) | `SD::test_tc_b100_65_session_decided_once_per_open_case06` |
| M-70 | app.py:_save_session_inputs:10755 | delete the `except OSError` | `SD::test_tc_b100_47_unreadable_source_painted_and_app_runs[digest]` |
| M-71 | app.py:_current_save_session:10769 | always recompute | `SD::test_tc_b100_65_session_decided_once_per_open_case06` |
| M-72 | app.py:_save_dialog_preview:10796 | blank text → `where=()` always (drop the session refusal) | `SD::test_tc_b100_47_missing_source_painted_at_open` |
| M-73 | app.py:_save_dialog_preview:10806 | delete the `_save_painted_preview` memo | `SD::test_tc_b100_49_confirming_save_closes_and_saves` |
| M-74 | app.py:_compose_save_preview:10830 | a refused preview keeps the plan's rows | `SD::test_tc_b100_47_plan_refusals_replace_the_rows` |
| M-75 | app.py:_compose_save_preview:10849 | delete the A11-17 kind word | `SD::test_tc_b100_47_target_line_names_the_sanitised_folder_merge_and_existing_folder_kinds` |
| M-76 | app.py:_compose_save_preview:10862 | delete the pending line | `SD::test_tc_b100_65_pending_line_marks_unsaved_changes` |
| M-77 | app.py:_compose_save_preview:10876 | never paint the rename arrow | `SD::test_tc_b100_65_summary_rows_equal_the_plan` (pending scenario) |
| M-78 | app.py:_compose_save_preview:10885 | delete the folder rows | `tests/test_b100_project_homes.py::test_at_b100_09_save_as_copies_the_project_and_q_lists_its_flow` |
| M-79 | app.py:_compose_save_preview:10891 | delete the skipped-links row | `SD::test_tc_b100_65_skipped_links_get_one_row` |
| M-80 | app.py:_compose_save_preview:10895 | delete the active-variant row | `SD::test_tc_b100_65_merge_names_the_active_variant_it_sets` |
| M-81 | app.py:_compose_save_preview:10918 | delete the backup clause (A11-05) | `SD::test_tc_b100_65_manifest_backup_gets_its_own_row` |
| M-82 | app.py:_confirm_project_save:10964 | a refused fresh preview → `return None` | `SD::test_tc_b100_47_refusal_painted_in_the_dialog_before_save` |
| M-83 | app.py:_confirm_project_save:10971 | drop the where/rows comparison | `SD::test_tc_b100_65_active_variant_change_counts_as_out_of_date` |
| M-85 | app.py:_confirm_project_save:10979 | memoise `changed` instead of `fresh` (R2-01) | `SD::test_tc_b100_65_summary_out_of_date_at_save_is_repainted_arm_1` |
| M-86 | app.py:_confirm_project_save:10981 | `replace(prepared, plan=plan)` → `prepared` | `SD::test_tc_b100_65_save_executes_the_painted_plan` (identity) |
| M-87 | app.py:_commit_project_save:11734 | drop the Q10 (d) substitution | `SD::test_tc_b100_65_document_keep_row_is_what_the_save_writes` |
| M-88 | app.py:_plan_project_save:12031 | `os.path.samefile` → case-folded name equality | `SD::test_tc_b100_47_strasse_open_strasse_eszett_present_is_a_clash` |
| M-89 | app.py:_plan_project_save:12042 | `prepared_call` → `False` (session digests ignored) | `SD::test_tc_b100_65_session_decided_once_per_open_case06` |
| M-92 | app.py:_plan_project_save:12141 | delete the S11-11 memo (warn per recompute) | expected survivor (no test counts the warning) |

## services/project_gather_service.py (G-B)

| Id | file:function:line | Mutation | Killer (expected) |
|---|---|---|---|
| M-93 | project_gather_service.py:plan_project_save:1688 | the Q10 arm condition → `False` | `SD::test_tc_b100_65_document_keep_row_is_what_the_save_writes` |
| M-94 | project_gather_service.py:plan_project_save:1704 | `identical` → always `None` | `SD::test_tc_b100_65_document_keep_row_is_what_the_save_writes` |
| M-96 | project_gather_service.py:plan_project_save:1712 | the free-name walk without `normcase` | expected survivor (no case-only sibling fixture) |


Count: 80 rows (22 screens.py, 3 styles.tcss, 52 app.py, 3 project_gather_service.py); 4 marked expected survivor (M-44, M-45, M-92, M-96). Ids are not renumbered after trimming, so gaps in the sequence are deliberate.
