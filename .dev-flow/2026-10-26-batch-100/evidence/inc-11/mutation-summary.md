# Inc 11 — Mutation stage summary

Copy: `<HOME>/AppData/Local/Temp/claude/C--Users-<USER>-clde/a8feab43-c248-4ccb-86cf-122b894659b2/scratchpad/mut11`
Interpreter: `<HOME>/anaconda3/envs/s19env/python.exe`
`LOCALAPPDATA` redirected to the scratch folder on every run; `<HOME>/AppData/Local/s19_app` never created (checked before and after).

Baseline sha256[:16] (before == after):
- s19_app/tui/screens.py `3d1d07526bcafd5a`
- s19_app/tui/styles.tcss `038fd8dbc034373e`
- s19_app/tui/app.py `7fb2fa5f01e2311c`
- s19_app/tui/services/project_gather_service.py `e11a5e75d7346183`

All 80 rows executed; each source restored and sha256-verified (`restored = True` in every transcript).

## Verdict table

| id | requirement | file | test | verdict |
|---|---|---|---|---|
| M-01 | LLR-175.3d (auto-focus) | screens.py | SD::test_tc_b100_49_dialog_opens_with_the_focus_in_the_name_field | SURVIVED |
| M-02 | LLR-175.3g (alt+s priority) | screens.py | SD::test_tc_b100_49_confirming_save_closes_and_saves[alt+s] | SURVIVED |
| M-03 | LLR-175.3j (escape binding) | screens.py | SD::test_tc_b100_49_escape_from_each_focus_position | KILLED |
| M-05 | LLR-175.4g (markup=False where) | screens.py | SD::test_tc_b100_65_names_are_painted_literally | SURVIVED |
| M-06 | LLR-175.4 (button label) | screens.py | SD::test_tc_b100_49_buttons_show_their_keys_and_the_keys_work | KILLED |
| M-07 | LLR-175.5b (_live) | screens.py | SD::test_tc_b100_65_recompute_is_a_150ms_debounce | KILLED |
| M-09 | LLR-175.5b (live gate) | screens.py | SD::test_tc_b100_65_first_preview_after_the_first_frame_and_once_while_idle | SURVIVED |
| M-10 | LLR-175.5 (debounce reset) | screens.py | SD::test_tc_b100_65_recompute_at_most_three_of_twenty_keystrokes | KILLED |
| M-11 | LLR-175.5 (SAVE_RECOMPUTE_S) | screens.py | SD::test_tc_b100_65_recompute_is_a_150ms_debounce | KILLED |
| M-13 | LLR-175.4k (plan writer) | screens.py | SD::test_tc_b100_65_save_executes_the_painted_plan | KILLED |
| M-14 | S11-04 (_shown reset) | screens.py | SD::test_tc_b100_65_save_before_the_preview_is_shown_repaints | SURVIVED |
| M-15 | LLR-175.4 (refusal class) | screens.py | SD::test_tc_b100_65_paint_rows_verbatim_in_order_and_refusal_empties | KILLED |
| M-17 | LLR-175.4 (stale-row removal) | screens.py | SD::test_tc_b100_65_paint_rows_verbatim_in_order_and_refusal_empties | KILLED |
| M-19 | LLR-175.4b (_mark_shown) | screens.py | SD::test_tc_b100_49_confirming_save_closes_and_saves | KILLED |
| M-20 | S11-04 (shown guard) | screens.py | SD::test_tc_b100_65_save_before_the_preview_is_shown_repaints | KILLED |
| M-21 | LLR-175.4b (confirm repaint) | screens.py | SD::test_tc_b100_49_confirming_save_closes_and_saves | KILLED |
| M-23 | HLR-175f (parent folder) | screens.py | SD::test_tc_b100_48_payload_parent_is_the_work_area_under_a_long_base | KILLED |
| M-24 | LLR-175.4k (plan identity) | screens.py | SD::test_tc_b100_65_save_executes_the_painted_plan | KILLED |
| M-26 | LLR-175.4b (enter submit) | screens.py | SD::test_tc_b100_49_confirming_save_closes_and_saves[enter] | KILLED |
| M-27 | LLR-175.4b (save_ok) | screens.py | SD::test_tc_b100_49_confirming_save_closes_and_saves[save_ok] | KILLED |
| M-28 | LLR-175.3j (cancel) | screens.py | SD::test_tc_b100_49_cancel_closes_with_no_result[click] | KILLED |
| M-29 | S6-12 (double close) | screens.py | SD::test_tc_b100_49_escape_with_a_recompute_pending_and_double_close | SURVIVED |
| M-31 | LLR-175.4j (max-height) | styles.tcss | SD::test_tc_b100_65_buttons_stay_visible_and_rows_never_wrap | SURVIVED |
| M-32 | LLR-175.4j (nowrap) | styles.tcss | SD::test_tc_b100_65_buttons_stay_visible_and_rows_never_wrap | KILLED |
| M-33 | LLR-175.4g (refusal bold) | styles.tcss | SD::test_tc_b100_65_paint_rows_verbatim_in_order_and_refusal_empties | KILLED |
| M-35 | Q9 (nothing loaded) | app.py | SD::test_tc_b100_49_nothing_loaded_opens_no_dialog | KILLED |
| M-36 | Q9 (A2L alone) | app.py | SD::test_tc_b100_49_an_a2l_alone_opens_the_dialog | KILLED |
| M-37 | LLR-175.3h (initial name) | app.py | SD::test_tc_b100_49_open_project_name_is_offered_selected | KILLED |
| M-38 | LLR-175.5b (session once) | app.py | SD::test_tc_b100_65_session_decided_once_per_open_case06 | KILLED |
| M-40 | LLR-175.3g (inert tuple) | app.py | SD::test_tc_b100_49_priority_keys_are_inert_while_the_dialog_is_open | KILLED |
| M-41 | LLR-175.3g (whole-stack guard) | app.py | SD::test_tc_b100_49_priority_keys_are_inert_while_the_dialog_is_open | KILLED |
| M-42 | S11-10 (session clear) | app.py | SD::test_tc_b100_65_save_as_then_patch_then_direct_save_plans_fresh | SURVIVED |
| M-43 | Q-2 (identity condition) | app.py | SD::test_tc_b100_65_save_executes_the_painted_plan | KILLED |
| M-44 | Q-2 (plan identity is→==) | app.py | SD::test_tc_b100_65_save_executes_the_painted_plan | SURVIVED |
| M-45 | Q-2 (typed_name clause) | app.py | SD::test_tc_b100_49_confirming_save_closes_and_saves | SURVIVED |
| M-47 | Q-3 (blank-name refusal) | app.py | SD::test_tc_b100_49_empty_save_keeps_the_dialog_and_says_why | SURVIVED |
| M-48 | LLR-175.1 (device names) | app.py | SD::test_tc_b100_47_device_names_raw_component_and_sanitised | KILLED |
| M-49 | LLR-175.1 (reserved casefold) | app.py | SD::test_tc_b100_47_reserved_names_in_mixed_case | KILLED |
| M-50 | LLR-175.1 (name cap) | app.py | SD::test_tc_b100_47_name_cap_64_65_300 | KILLED |
| M-51 | LLR-175.1 (path limit) | app.py | SD::test_tc_b100_47_path_limit_met_and_exceeded | KILLED |
| M-52 | S11-03 (workarea OSError) | app.py | SD::test_tc_b100_47_refusal_painted_in_the_dialog_before_save[workarea] | KILLED |
| M-53 | LLR-175.1 (clash casefold) | app.py | SD::test_tc_b100_47_disguised_clash_names_both_and_exact_name_merges | KILLED |
| M-54 | SR-11-1 (exact folder) | app.py | SD::test_tc_b100_47_strasse_open_strasse_eszett_present_is_a_clash | KILLED |
| M-55 | S11-01 (samefile → name) | app.py | SD::test_tc_b100_47_strasse_open_strasse_eszett_present_is_a_clash | SURVIVED |
| M-56 | LLR-175.1 (typed vs cleaned) | app.py | SD::test_tc_b100_47_disguised_clash_names_both_and_exact_name_merges | KILLED |
| M-57 | LED .52(a) (rebind) | app.py | SD::test_tc_b100_47_target_line_open_project_in_another_case | KILLED |
| M-58 | LLR-175.6 (session toast) | app.py | test_b99_staging.py::test_tc_b99_ux_c10_save_project_filename_renders_literally | KILLED |
| M-59 | S11-10 (live write) | app.py | SD::test_tc_b100_65_save_as_then_patch_then_direct_save_plans_fresh | KILLED |
| M-60 | R3-01 (live after replace) | app.py | SD::test_tc_b100_65_save_as_inventory_walked_once_per_open | KILLED |
| M-61 | S11-06 (inventory once) | app.py | SD::test_tc_b100_65_save_as_inventory_walked_once_per_open | KILLED |
| M-62 | A11-07 (P-4 _err) | app.py | SD::test_tc_b100_47_target_with_two_mac_files_refused_in_the_dialog | KILLED |
| M-63 | P-4 (active variant) | app.py | SD::test_tc_b100_65_active_variant_stem_collision_is_predicted_exactly | KILLED |
| M-64 | LLR-175.1j (free space >) | app.py | SD::test_tc_b100_47_free_space_short_by_one_and_exact | KILLED |
| M-65 | A11-02 (plan=None) | app.py | SD::test_tc_b100_47_free_space_short_by_one_and_exact | KILLED |
| M-66 | S11-02 (exists in try) | app.py | SD::test_tc_b100_47_unreadable_source_painted_and_app_runs[exists] | KILLED |
| M-67 | LLR-175.1k (missing source) | app.py | SD::test_tc_b100_47_missing_source_painted_at_open | KILLED |
| M-68 | LLR-175.5 (image digest) | app.py | SD::test_tc_b100_65_session_decided_once_per_open_case06 | SURVIVED |
| M-70 | S11-02 (except OSError) | app.py | SD::test_tc_b100_47_unreadable_source_painted_and_app_runs[digest] | KILLED |
| M-71 | LLR-175.5b (session memo) | app.py | SD::test_tc_b100_65_session_decided_once_per_open_case06 | KILLED |
| M-72 | Q-3 (blank refusal) | app.py | SD::test_tc_b100_47_missing_source_painted_at_open | KILLED |
| M-73 | A11-08 (painted memo) | app.py | SD::test_tc_b100_49_confirming_save_closes_and_saves | KILLED |
| M-74 | LLR-175.1i (refused rows) | app.py | SD::test_tc_b100_47_plan_refusals_replace_the_rows | SURVIVED |
| M-75 | A11-17 (kind word) | app.py | SD::test_tc_b100_47_target_line_merge_and_existing_folder_kinds | KILLED |
| M-76 | LLR-175.4a (pending line) | app.py | SD::test_tc_b100_65_pending_line_marks_unsaved_changes | KILLED |
| M-77 | LLR-175.4 (rename arrow) | app.py | SD::test_tc_b100_65_summary_rows_equal_the_plan[pending] | KILLED |
| M-78 | LLR-171.1 (folder rows) | app.py | test_b100_project_homes.py::test_at_b100_09_save_as_copies_the_project_and_q_lists_its_flow | KILLED |
| M-79 | LLR-175.4 (skipped links) | app.py | SD::test_tc_b100_65_skipped_links_get_one_row | KILLED |
| M-80 | LLR-175.4 (active-variant row) | app.py | SD::test_tc_b100_65_merge_names_the_active_variant_it_sets | KILLED |
| M-81 | A11-05 (backup clause) | app.py | SD::test_tc_b100_65_manifest_backup_gets_its_own_row | KILLED |
| M-82 | LLR-175.4b (refused → None) | app.py | SD::test_tc_b100_47_refusal_painted_in_the_dialog_before_save | KILLED |
| M-83 | R2-01 (where/rows compare) | app.py | SD::test_tc_b100_65_active_variant_change_counts_as_out_of_date | KILLED |
| M-85 | R2-01 (memoise changed) | app.py | SD::test_tc_b100_65_summary_out_of_date_at_save_is_repainted_arm_1 | KILLED |
| M-86 | LLR-175.4k (replace plan) | app.py | SD::test_tc_b100_65_save_executes_the_painted_plan | KILLED |
| M-87 | Q10 (d) substitution | app.py | SD::test_tc_b100_65_document_keep_row_is_what_the_save_writes | SURVIVED |
| M-88 | S11-01 (samefile → name) | app.py | SD::test_tc_b100_47_strasse_open_strasse_eszett_present_is_a_clash | SURVIVED |
| M-89 | LLR-175.5 (session digests) | app.py | SD::test_tc_b100_65_session_decided_once_per_open_case06 | KILLED |
| M-92 | S11-11 (memo) | app.py | SD::test_tc_b100_65_document_digest_is_taken_in_each_preparation | SURVIVED |
| M-93 | Q10 (arm condition) | project_gather_service.py | SD::test_tc_b100_65_document_keep_row_is_what_the_save_writes | KILLED |
| M-94 | Q10 (identical) | project_gather_service.py | SD::test_tc_b100_65_document_keep_row_is_what_the_save_writes | KILLED |
| M-96 | Q10 (free-name normcase) | project_gather_service.py | SD::test_tc_b100_65_document_keep_row_is_what_the_save_writes | SURVIVED |

## Counts

- KILLED: 62
- SURVIVED: 18
- INVALID: 0
- (M-70's first edit left a `try:` without an `except` — SyntaxError, i.e. an invalid mutant; it was fixed to `except OSError: raise` and re-run, then KILLED. Never counted as INVALID.)

## Survivor explanations

- **M-01** (AUTO_FOCUS → None): equivalent — with no `AUTO_FOCUS`, Textual's default focuses the first focusable widget, which is `#project_name`, so focus still lands there.
- **M-02** (alt+s priority=False): equivalent — inside the modal the `alt+s` binding still fires; `priority` only matters for app-level routing before the modal handles it, and the test's `alt+s` still saves.
- **M-05** (markup=True on #save_where): equivalent — `_paint` always updates `#save_where` with a pre-built `Text` object (never a raw string), so the widget's `markup` flag is never consulted; spans stay 0.
- **M-09** (drop `or not self._live`): equivalent — the gate only suppresses typing before the first frame; the test's preview runs after the first frame (live already True).
- **M-14** (delete `_shown = False` reset): weak/equivalent — the reset only matters on a re-paint; the test's Save fires before the first frame, when `_shown` is still False from `__init__`.
- **M-29** (delete `_dismissed` guard): equivalent — a second `dismiss`/`_close` on an already-dismissed screen is harmless, so the double-close scenario is unchanged.
- **M-31** (delete `max-height: 50vh`): weak — `#save_box` still caps at 90% height and the buttons stay docked; the tested sizes never push the buttons off-screen without the 50vh cap.
- **M-42** (delete `_save_session = None` clear): weak — the test only exercises the direct-save path, where no live session was ever set (the session is computed fresh inside `_prepare_project_save`), so the cleared value is already None.
- **M-44** (`is` → `==` on plan identity): expected survivor — B11-14 not built as a test; the compared object is the same `SavePlan`, so `==` is always True and behavior is unchanged.
- **M-45** (drop `confirmed.typed_name == payload.project_name`): expected survivor — B11-14 not built as a test; the typed name never differs between confirm and dismiss in any test.
- **M-47** (delete blank-name refusal): equivalent — `sanitize_project_name("")` returns `""`, so the following `if not cleaned:` refusal still catches empty/whitespace names with the same message.
- **M-55** (samefile → normcase name equality, in `_prepare_project_save`): equivalent in this scenario — the test's folders differ by `ß` vs `ss`, which `os.path.normcase` does not fold, so `samefile` and the name comparison agree (no case-only sibling fixture).
- **M-68** (drop `not image_step.emit`): weak — the extra digest of the emitted image file is not counted by `test_tc_b100_65_session_decided_once_per_open_case06` (it only counts the A2L and MAC digests and the decision/derived calls).
- **M-74** (refused preview keeps plan rows): weak — the three refusal scenarios in `test_tc_b100_47_plan_refusals_replace_the_rows` carry a plan with 0 rows, so `plan.rows` is empty and the mutated preview still paints no rows.
- **M-87** (drop Q10 (d) substitution): equivalent — the document arm already predicts the `keep` landing via `_match_identical`, so the dropped substitution (a defence) is not what produces the correct row in the test.
- **M-88** (samefile → normcase name equality, in `_plan_project_save`): equivalent — same as M-55: `straße` vs `strasse` differ under `normcase`, so target-kind is computed the same way (no case-only sibling fixture).
- **M-92** (delete S11-11 warning memo): expected survivor — no test counts the warning; deleting the memo only makes the warning repeat, behavior is unchanged.
- **M-96** (free-name walk without `normcase`): expected survivor — no case-only sibling fixture, so removing `normcase` from the candidate fold does not change the chosen free name in any test.
