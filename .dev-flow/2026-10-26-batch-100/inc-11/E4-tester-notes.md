# Inc 11 — E4 tester notes (independent tester)

Stage E4 of the design-first pipeline. Written from the design only (`E1-requirements-draft.md`, `E1-scope.md`, `codewire/interfaces-11.md`, `codewire/proto-11-dialog.md`, `codewire/proto-11-app.md`, `E1-rulings.md`, `E2-rulings.md`, `E3-rulings.md` incl. the Round-3 T rows). No line of the Inc 11 implementation was read (the implementers' files were in progress in the same worktree; only `git diff --stat` names them).

Evidence states below use the seven words only. Nothing here is `approved`: that is the reviewers'.

## Files

| File | What | State |
|---|---|---|
| `tests/test_b100_save_dialog.py` | new: TC-B100-47, -48, -49, -65, -66 (ext.), AT-B100-16, AT-B100-21 | executed (RED vs base) |
| `tests/support/b100_save_dialog.py` | new: drivers / readers for the Save dialog; `SaveDialogFakes`, `bare_save_dialog`, `save_through_dialog`, `refuse_in_open_dialog`, `type_and_await_summary` | used by both |
| 13 existing test files | re-pins (list below) | executed (vs base, see RED-02) |

## Counts

- New file `tests/test_b100_save_dialog.py`: **73 test functions, 154 collected ids** (parametrised arms).
- **RED on base: 154 of 154 failed, 0 passed, 0 skipped, 0 collection errors** — one complete run, `evidence/inc-11/red-01-vs-base.txt` (33 min; header names base `1747479` and `s19_app.__file__ = …\scratchpad\base11\s19_app\__init__.py`). State: `executed`.
- Re-pins: **24 test functions (35 ids)** — one complete run on base, `evidence/inc-11/red-02-repins-vs-base.txt`: 33 failed, 2 passed (see below). State: `executed`.
- GREEN: `not-run` (the implementation was in progress in the same worktree; the brief forbids depending on it).

## Requirement → test map

All nodes are in `tests/test_b100_save_dialog.py` unless a path is given. "(fakes)" = the dialog alone, fed by recording fakes of the two fixed callables (S-a / S-b seam).

| Requirement | Test node(s) | Negative control the node turns RED on |
|---|---|---|
| HLR-175 | `test_at_b100_16_save_dialog_open_folder_clash_empty_escape` (folder half), `test_at_b100_21_painted_plan_is_the_saved_tree` (painted half), `test_tc_b100_65_summary_rows_equal_the_plan` | no `#save_where` / `#save_summary` (P11-2) |
| HLR-175a | `test_at_b100_21_painted_plan_is_the_saved_tree` (executed half), `test_tc_b100_65_save_executes_the_painted_plan` | handler places an unplanned file; router re-prepares (identity) |
| HLR-175b | `test_at_b100_16_…` (clash half), `test_tc_b100_47_refusal_painted_in_the_dialog_before_save[15 arms]`; re-pin AT-B100-02 | refusal painted only after close |
| HLR-175c | `test_at_b100_16_…` (escape half), `test_tc_b100_49_escape_from_each_focus_position[4]`, `test_tc_b100_49_escape_after_a_refusal_closes` | `escape` ignored (P-18) |
| HLR-175d | `test_at_b100_16_…` (empty half), `test_tc_b100_49_empty_save_keeps_the_dialog_and_says_why[6]` | empty Save silent (P-19) |
| HLR-175e | `test_tc_b100_48_no_parent_field_and_no_browse[2]`, `test_tc_b100_48_payload_parent_is_the_work_area_under_a_long_base`; re-pin AT-B100-02 | parent field present (P11-2) |
| HLR-175f | `test_at_b100_16_…` (open half), `test_tc_b100_48_no_parent_field_and_no_browse` (5 ids), `test_tc_b100_49_dialog_opens_with_the_focus_in_the_name_field[2]`, `test_tc_b100_49_constructor_is_keyword_only_and_computes_nothing` | focus in parent field; ids absent |
| LLR-175.1 | `test_tc_b100_47_target_line_names_the_sanitised_folder_new[2]`, `…_open_project_kind`, `…_open_project_in_another_case` (Windows), `…_merge_and_existing_folder_kinds` | case-sensitive kind; no line |
| LLR-175.1a | `…_refusal_painted…[reserved]`, `test_tc_b100_47_reserved_names_in_mixed_case[5]` | no case-fold |
| LLR-175.1b | `…[device]`, `test_tc_b100_47_device_names_raw_component_and_sanitised[6]` | sanitised-only |
| LLR-175.1c | `…[clash]`, `test_tc_b100_47_disguised_clash_names_both_and_exact_name_merges` | no case-fold clash |
| LLR-175.1d | `…[over64]`, `test_tc_b100_47_name_cap_64_65_300` | cap read as 65 |
| LLR-175.1e | `…[path]`, `test_tc_b100_47_path_limit_met_and_exceeded` | suffix dropped |
| LLR-175.1f | `…[link]` (Windows), `test_tc_b100_47_junction_target_writes_nothing_through_it` (Windows) | link check removed |
| LLR-175.1g | `…[unreadable_target]` | unreadable → no refusal |
| LLR-175.1h | `…[no_char]`, `test_tc_b100_47_no_usable_character_painted_live` | pair only on Save |
| LLR-175.1i | `…[plan]`, `test_tc_b100_47_plan_refusals_replace_the_rows`, `test_tc_b100_47_target_with_two_mac_files_refused_in_the_dialog` (A11-07) | rows painted, refusal dropped |
| LLR-175.1j | `…[space]`, `test_tc_b100_47_free_space_short_by_one_and_exact` (+A11-02) | check left in the handler |
| LLR-175.1k | `…[missing]`, `test_tc_b100_47_missing_source_painted_at_open[3]`; re-pin `test_tc_b99_14_save_project_missing_source` | painted after close |
| LLR-175.1l | `…[unreadable_source]`, `test_tc_b100_47_unreadable_source_painted_and_app_runs[digest, exists]` (S11-02) | no catch / no next step |
| LLR-175.1m | `…[blocked]`, `test_tc_b100_47_blocked_entries_painted_with_addresses[1, 3]` | painted after close |
| LLR-175.1n | retired (E2-rulings) — no test | n/a — retired |
| LLR-175.1o | `…[workarea]` (S11-03: `os.listdir` stubbed) | catch removed → app stops |
| LLR-175.1p | `…[casefold]` (Windows), `test_tc_b100_47_strasse_open_strasse_eszett_present_is_a_clash` (Windows; S11-01) | open project by case-folding |
| LLR-175.2 | `test_tc_b100_48_no_parent_field_and_no_browse[2]` | P11-2 |
| LLR-175.2a | `test_tc_b100_48_payload_parent_is_the_work_area_under_a_long_base` | `base_dir` parent (mutation; base RED via missing summary) |
| LLR-175.3 | `test_tc_b100_49_escape_from_each_focus_position[4]`, `test_tc_b100_49_escape_with_a_recompute_pending_and_double_close` (fakes) | P11-2 |
| LLR-175.3a | `test_tc_b100_49_cancel_closes_with_no_result[click, enter]` | cancel→save (mutation; base RED via missing summary) |
| LLR-175.3b | `test_tc_b100_49_empty_save_keeps_the_dialog_and_says_why[6]` | P11-2 |
| LLR-175.3c | `test_tc_b100_49_confirming_save_closes_and_saves[alt+s, save_ok, enter, posted_alt_s]` | no BINDINGS / submit |
| LLR-175.3d | `test_tc_b100_49_dialog_opens_with_the_focus_in_the_name_field[ctrl+s, palette]` | P11-2 |
| LLR-175.3e | `test_tc_b100_49_plain_letters_stay_in_the_name_field` | `s` bound (mutation; base RED via focus) |
| LLR-175.3f | `test_tc_b100_49_save_during_a_refusal_keeps_the_dialog_and_save_focusable` | disabled button; dismissed refusal |
| LLR-175.3g | `test_tc_b100_49_priority_keys_are_inert_while_the_dialog_is_open` (4 keys + `ctrl+p` whole stack + no over-reach) | P11-2/P11-3; stack-top guard |
| LLR-175.3h | `test_tc_b100_49_open_project_name_is_offered_selected` | name starts empty |
| LLR-175.3i | `test_tc_b100_49_buttons_show_their_keys_and_the_keys_work` | labels `Save` / `Cancel` |
| LLR-175.3j | `test_tc_b100_49_nothing_loaded_opens_no_dialog[2]`, `test_tc_b100_49_an_a2l_alone_opens_the_dialog` | dialog opens (P11-2) |
| LLR-175.4 | `test_tc_b100_65_summary_rows_equal_the_plan[7]`, `test_tc_b100_65_the_preview_and_the_dialog_list_nothing_themselves`, `test_tc_b100_65_paint_rows_verbatim_in_order_and_refusal_empties` (fakes) | drop `keep` rows |
| LLR-175.4a | `test_tc_b100_65_save_executes_the_painted_plan[7]`, `test_tc_b100_65_document_keep_row_is_what_the_save_writes` (A11-04), `test_tc_b100_65_payload_plan_field_and_preview_value_types` | re-plan without the document row; p11b U3 |
| LLR-175.4b | `…_summary_out_of_date_at_save_is_repainted_arm_1` (R2-01), `…_arm_2`, `test_tc_b100_65_save_before_the_preview_is_shown_repaints` (S11-04, fakes), `test_tc_b100_65_out_of_date_save_repaints_and_stops_the_timer` (fakes), `test_tc_b100_65_active_variant_change_counts_as_out_of_date` (A11-08) | dismiss with a fresh plan |
| LLR-175.4c | `test_tc_b100_65_image_line_says_emit_or_copy[3]`, `test_tc_b100_49_an_a2l_alone_opens_the_dialog` (empty boundary) | differs-only description |
| LLR-175.4d | `test_tc_b100_65_pending_line_marks_unsaved_changes` | keyed on `image_differs_from_source` |
| LLR-175.4e | `test_tc_b100_65_skipped_links_get_one_row[1, 12]` (Windows) | row omitted |
| LLR-175.4f | `test_tc_b100_65_merge_names_the_active_variant_it_sets`, `test_tc_b100_65_active_variant_stem_collision_is_predicted_exactly` (B11-53) | row omitted; first-by-name; stem-only |
| LLR-175.4g | `test_tc_b100_65_names_are_painted_literally`, `test_tc_b100_65_assignment_rows_literal_and_in_the_tab_order` (fakes) | markup on |
| LLR-175.4h | `test_tc_b100_65_buttons_stay_visible_and_rows_never_wrap[2]` | box + summary unbounded |
| LLR-175.4i | `test_tc_b100_65_last_row_reachable_by_keyboard`, `test_tc_b100_65_assignment_rows_literal_and_in_the_tab_order` (fakes) | summary not focusable |
| LLR-175.4j | `test_tc_b100_65_buttons_stay_visible_and_rows_never_wrap[2]`, `test_tc_b100_65_summary_rows_equal_the_plan` (no `\n`) | rows wrap |
| LLR-175.4k | `test_tc_b100_65_plan_is_read_only` (fakes), `test_tc_b100_49_constructor_is_keyword_only_and_computes_nothing` (`None` before paint) | plain attribute |
| LLR-175.4l | `test_tc_b100_65_a_direct_payload_saves_the_same_tree`, `test_tc_b100_65_payload_plan_field_and_preview_value_types`; the 56 + 1 direct calls (owed to the batch-end battery, operator override 2026-10-31) | dialog-only router |
| LLR-175.5 | `test_tc_b100_65_session_decided_once_per_open_case06` (+A11-01, 2 s budget), `test_tc_b100_65_first_preview_after_the_first_frame_and_once_while_idle` (fakes) | session per preview |
| LLR-175.5a | `test_tc_b100_65_recompute_is_a_150ms_debounce` (fakes), `test_tc_b100_65_recompute_at_most_three_of_twenty_keystrokes`, `test_tc_b100_65_emitting_4mib_image_recomputes_fast` (A11-01) | per-key recompute; no trailing run |
| LLR-175.5b | `test_tc_b100_65_first_frame_before_the_image_decision`, `test_tc_b100_65_first_preview_after_the_first_frame_and_once_while_idle` (fakes) | decision before push |
| LLR-175.6 | `test_tc_b100_47_one_preparation_ast_census`, `test_tc_b100_47_dialog_line_equals_the_direct_status_line[16]` | dialog copy of the rules |
| LLR-173.7 (TC-B100-66 ext.) | `test_tc_b100_66_save_dialog_paints_no_decision_id` | `D7` hint shipped |

E3 arms named by the brief:

| Arm | Node |
|---|---|
| S11-01 | `test_tc_b100_47_strasse_open_strasse_eszett_present_is_a_clash`, `…_refusal_painted…[casefold]`, `…_dialog_line_equals…[casefold]` |
| S11-02 | `test_tc_b100_47_unreadable_source_painted_and_app_runs[exists]` |
| S11-03 | `…_refusal_painted…[workarea]` (`os.listdir` stubbed) |
| S11-04 | `test_tc_b100_65_save_before_the_preview_is_shown_repaints` |
| S11-05 | `test_tc_b100_65_document_digest_is_taken_in_each_preparation` |
| A11-01 | `test_tc_b100_65_session_decided_once_per_open_case06` (`_derived_record` 1 call), `test_tc_b100_65_emitting_4mib_image_recomputes_fast` |
| A11-02 | `test_tc_b100_47_free_space_short_by_one_and_exact` (`plan is None`) |
| A11-04 | `test_tc_b100_65_document_keep_row_is_what_the_save_writes` |
| A11-05 | `test_tc_b100_65_manifest_backup_gets_its_own_row` |
| A11-08 | `test_tc_b100_65_active_variant_change_counts_as_out_of_date` |
| R2-01 | `test_tc_b100_65_summary_out_of_date_at_save_is_repainted_arm_1` (second press saves) |
| R2-02 / R3-01 | `test_tc_b100_65_save_as_inventory_walked_once_per_open`, `test_tc_b100_65_save_as_then_patch_then_direct_save_plans_fresh` |
| whole-stack guard | `test_tc_b100_49_priority_keys_are_inert_while_the_dialog_is_open` (`ctrl+l/s/k/d`, then `ctrl+p` → `ctrl+s` / `ctrl+l`) |

Uncovered, named: none of the 52 live requirements is without a node. The partial gaps are listed under "Examples not turned into tests".

## Re-pinned tests (census re-taken on this tree, 1747479)

The census of `E2-rulings.md` rows A–D plus the named single re-pins, re-taken with `grep` for `SaveProjectScreen`, `#project_parent_path`, `#save_browse`, `#save_ok`, `#project_name` on 1747479. New since the 8947666 baseline: Inc 10's `test_b100_load_question.py::test_at_b100_15_…` (it saves `PA` through the dialog over an open project). Each re-pin keeps what the test proves and changes only how it reaches the dialog.

| # | Test (file::function) | Census row | Why it broke | The re-pin (what changed; what it still proves) |
|---|---|---|---|---|
| 1 | `tests/test_tui_directionb.py::test_tc033_modals_render_with_calm_dark_tokens` (`_MODAL_SPECS`, `_build_modal`) | A | `SaveProjectScreen(tmp_path)` — the positional `default_parent` is gone (S-b) | built by `b100_save_dialog.bare_save_dialog(tmp_path)` (keyword constructor, inert fakes); still checks the Calm Dark render of all three modals |
| 2 | `tests/test_tui_directionb.py::test_tc034_modals_behavior_methods_intact` | A | positional constructor; sets `#project_parent_path` | `bare_save_dialog(tmp_path)`; the name is set, the recompute awaited, then `#save_ok`; still: Cancel → `None`, Save → a `SaveProjectPayload` naming the typed project with `parent_folder == str(tmp_path)` (the painted plan's parent) |
| 3 | `tests/test_loadfilescreen_input.py::test_ac2_paste_reaches_project_name_input` | A | `SaveProjectScreen(default_parent=tmp_path)` | `bare_save_dialog(tmp_path)`; the paste oracle unchanged |
| 4 | `tests/test_b99_staging.py::test_tc_b99_14_save_project_missing_source` | B / E | clicks `#project_parent_path`; the refusal is now painted in the dialog (Q5) | no parent click; the missing-source refusal is read in `#save_where` with the dialog open, `#save_ok` keeps it open; still: leads with the outcome, names `firmware.s19`, no empty folder, app running |
| 5 | `tests/test_b99_staging.py::test_tc_b99_14_placement_failure_removes_created_folder` | B | parent click; immediate Save (LLR-175.4b) | no parent click; the summary of `proj` awaited before `#save_ok`; the forced placement failure and its oracles unchanged |
| 6 | `tests/test_b99_staging.py::test_tc_b99_14_preexisting_folder_survives_placement_failure` | B | as 5 | as 5 |
| 7 | `tests/test_b99_staging.py::test_at_b99_05_save_project_after_same_name_save_back` | B | as 5 | as 5; the save-back chain and the "Saved project to" oracle unchanged |
| 8 | `tests/test_b99_staging.py::test_tc_b99_ux_c10_save_project_filename_renders_literally` | B / A11-11 (Q-6) | parent field; the dialog path raises no toast any more | the hostile name is read literally (0 spans) in `#save_where` with the dialog open and 0 error notices on the dialog path (Q-6); the error notice and its literal name are read from a direct `_handle_save_dialog` call (the direct path keeps the toast) |
| 9 | `tests/test_b99_staging.py::test_tc_b99_ux_c10_placement_error_path_renders_literally` | B | parent field; immediate `#save_ok.press()` | name set, summary awaited, then `#save_ok`; the literal placement-error oracle unchanged |
| 10 | `tests/test_tui_manifest_save.py::test_tc304_screen_collects_per_variant_and_batch_assignment` | C | `#save_ok.press()` before the 150 ms recompute | the summary of `proj` awaited before Save; `_capture_save_payload` (one-argument lambda) still receives the payload; batch / assignment oracle unchanged |
| 11 | `tests/test_tui_manifest_save.py::test_tc306_screen_no_selection_yields_empty_composition` | C | as 10 | as 10 |
| 12 | `tests/test_b100_active_variant.py::test_at_b100_06_reopen_opens_the_saved_back_variant` (`_save_project_through_dialog`) | D / F | typed then clicked at once; prefill | `b100_save_dialog.type_and_await_summary` (clear the prefilled name, type, await the summary) before `#save_ok` |
| 13 | `tests/test_b100_document.py::test_at_b100_08_saved_document_reopens_with_the_project` (`_at_save_project_through_dialog`) | D / F | as 12 | as 12 |
| 14 | `tests/test_b100_project_check.py::test_at_b100_07_load_names_the_changed_file_and_the_hostile_record` (`_save_project_through_dialog`) | D / F | as 12 | as 12 |
| 15 | `tests/test_b100_project_homes.py::test_at_b100_09_save_as_copies_the_project_and_q_lists_its_flow` (`_at_save_through_dialog`) | D + AT index | as 12; the AT index adds "alt+s; the summary lists flows/, patches/, reports/ before Save" | the drive awaits the summary and Save is `alt+s`; new arm: before Save exactly 1 painted row each for `flows/`, `patches/`, `reports/` holding `1 file` |
| 16 | `tests/test_b100_project_homes.py::test_at_b100_10_a2l_only_project_saves_and_reopens` | D | as 12 | same drive (`alt+s`); oracles unchanged |
| 17 | `tests/test_b100_project_homes.py::test_at_b100_11_junction_project_is_not_listed_and_save_refuses_it` | D / E | the `evil` refusal is painted in the dialog (Q5), not on the status line | the drive returns the dialog's refusal line as one more message when no kind word is painted, after `alt+s` keeps the dialog open, then `escape`; the "1 line holding link or junction" and R-unchanged oracles unchanged |
| 18 | `tests/test_b100_save_guards.py::test_at_b100_02_name_refusals_through_the_save_dialog` (`_save_project_as`, new `_refused_in_dialog`) | D / E / F (AT-B100-02 re-pin owed by E1) | refusals read from the status line after the dialog closed; immediate Save; prefill | `Reports`, `CON`, 300 × `x` and `a b` read their token pairs in `#save_where` with the dialog open, `alt+s` keeps it open, `escape` closes; each open asserts 0 `#project_parent_path` and 0 `#save_browse` (HLR-175e); the `prg` / `ab` saves use `alt+s`; the `ab` byte-identity oracle unchanged |
| 19 | `tests/test_b100_save_image.py::test_at_b100_05_save_project_saves_the_patched_image` | D | as 12 | as 12 |
| 20 | `tests/test_b100_session_reset.py::test_at_b100_03_project_load_over_unsaved_work_saves_only_p2` (`_save_project_as`) | D / F | prefill (`P2` open: typing `P2` was appended) | as 12 (the field is cleared first) |
| 21 | `tests/test_b100_load_question.py::test_at_b100_15_load_over_unsaved_work_asks_one_question_per_route` | new in this tree (Inc 10) | saves `PA` by typing then clicking at once | as 12 |
| 22 | `tests/test_b100_save_guards.py::test_tc_b100_07_ast_census_every_post_creation_return_removes` | H (TC-B100-07) | the commit moved to `_commit_project_save` (S-c Split) | the census reads `_commit_project_save`; new arm (B11-66): `_handle_save_dialog` holds 0 `mkdir` |
| 23 | `tests/test_b100_session_reset.py::test_tc_b100_09_domain_matches_the_live_source_census` (`SNAPSHOT_EXCLUSIONS`) | H (TC-B100-09) | new app attributes (Q-1 `_save_session`, P-3 `_save_confirmed`, the G-B A11-08 memo `_save_painted_preview`) | the three names classified with the reason "per-open Save dialog state; dropped when the Save router runs" |
| 24 | `tests/test_b100_reuse.py::test_tc_b100_57_export_holds_no_byte_identity_rule` | A11-03 | — (widened by ruling) | the census also catches `Attribute` calls of `_hash_file` (`x._hash_file(...)`) |

Not re-pinned, by ruling: `test_e4_r11_a3r2_5_top_level_copy_reusing_the_image_row_aborts` (A11-03). Not re-pinned because they do not break by reading: `test_tc305` (reads `screen.variants` / `candidate_files`, kept), `test_tc033_modals_use_only_calm_dark_tokens_no_hardcoded_color` (class-level only), `test_b100_load_dialog.py:1183` (asserts no `SaveProjectScreen` over the Load dialog). The 56 direct `_handle_save_dialog` call lines and the call by reference are kept unchanged (LLR-175.4l) and owed to the batch-end battery.

Shared support added for the re-pins: `tests/support/b100_save_dialog.py` (`bare_save_dialog`, `SaveDialogFakes`, `type_and_await_summary`, `refuse_in_open_dialog`, `save_through_dialog`).

## RED on base

**RED-01** (`evidence/inc-11/red-01-vs-base.txt`, one complete run, `154 failed in 1974.10s`). Every failure is behavioural — an assertion on the shipped surface, or a symbol / signature the Inc 11 design adds. None is a collection error, a typo, or a fixture failure (an earlier run, RED-00, exposed 9 fixture faults of mine — a stale `temp/firmware.s19` renaming the merge scenario's image, a 9.5 MB load past a 6 s wait, and a long file name past MAX_PATH; all were repaired before RED-01 and are not in it). Reasons, grouped by the failing line:

| Count | Reason on base | Why that is the behavioural RED |
|---|---|---|
| 114 | `timed out waiting for the dialog to paint (<tokens>) (painted: '')` | the base dialog has no `#save_where` / `#save_summary`: no target line, no kind, no refusal, no row is ever painted before Save (P11-2) |
| 8 | `TypeError: SaveProjectScreen.__init__() got an unexpected keyword argument 'preview'` | the base constructor is positional `(default_parent, variants, candidate_files)` (S-b) — the fake-fed dialog nodes |
| 10 | `AttributeError: … has no attribute '_commit_project_save' / '_save_dialog_preview' / 'plan'` | the split (S-c), the preview seam (S-a) and the read-only plan (LLR-175.4k) do not exist |
| 1 | `ImportError: cannot import name 'SavePreview'` | the S-a value type does not exist |
| 2 | `assert (2, 'project_parent_path') == (2, 'project_name')` | focus opens in the parent field (LLR-175.3d) |
| 2 | `AssertionError: 2` | with nothing loaded the base opens the dialog (LLR-175.3j) |
| 7 | bare `AssertionError` on the oracle line | the empty Save paints no `name is empty` (6 arms); the field never holds `sqlpvy` (the focus opens in the parent field) |
| 2 | `{'project_parent_path': 1, 'save_browse': 1, 'save_browse_row': 1}` | the parent field and Browse are composed (LLR-175.2) |
| 1 | `{'after palette': ['Screen', 'SaveProjectScreen', 'LoadDialog', …]}` | `ctrl+l` stacks a Load dialog over Save (LLR-175.3g) |
| 1 | `['self', 'default_parent', 'variants', 'candidate_files']` | the base signature (S-b) |
| 1 | `[]` | the image decision never runs after `ctrl+s` on base (it runs only after the dialog closes), so no first-frame record exists (LLR-175.5b) |
| 1 | `timed out waiting for the target line naming 'fresh1'` | the direct-payload twin cannot save through the dialog (no summary, no `alt+s`) |
| 1 | `timed out waiting for the first summary` | case_06: the dialog paints no summary at open |
| 1 | `no _prepare_project_save (the one preparation)` | LLR-175.6 AST census |
| 1 | `_save_dialog_preview is missing` | LLR-175.4 AST census |
| 1 | `(('missing', 'missing'), ('missing', 'missing'))` | B11-89: the app has no per-open Save state to clear (R2-02) |

**RED-02** (`evidence/inc-11/red-02-repins-vs-base.txt`, `33 failed, 2 passed in 524.56s`): the re-pinned tests fail on base for the same reasons (no summary to await, keyword constructor, no `_commit_project_save` — `StopIteration` from the census lookup, a parent field still offered). The 2 that pass on base are expected and are not RED claims: `test_tc_b100_09_domain_matches_the_live_source_census` (classifying names the base never assigns is harmless) and `test_tc_b100_57_export_holds_no_byte_identity_rule` (the widened census finds no attribute call of `_hash_file` on base — the widening is a guard for the Q10 code, not a regression capture).

## Examples not turned into tests

| Example | Why not a test |
|---|---|
| K17 / S9-7 (row repaint timings 203 / 360 / 78 / 94 ms) | a performance record with no threshold; R-GA11-3 declares E5 measures it |
| C1-1 exact `#save_box` regions; C3-1 exact button coordinates; C3-3b (a 1-row summary 3 high) | exact geometry is the CSS author's choice; the requirement (LLR-175.4h) is "fully visible", tested at both sizes |
| C1-2 (`#save_box` / `#save_where` / `#save_summary` inside the TC-033 modal block), C4-1 (`grep -c "#saveproject_buttons"` = 0), R1-1 (`id="load_dialog"` count 7) | source-layout greps with no observable outcome; TC-033's own nodes (unchanged) scan the modal block for hex colours |
| I1-1 / I1-2 (typing-only import of `project_gather_service`) | I1-1 is 9b's `test_tc_b100_64_the_dialog_reads_nothing_itself` arm 2, unchanged; I1-2 not duplicated |
| S6-9 (confirm returns `None` with no painted plan → warning log and repaint) | a contract-breach branch between two fakes; the log text is a G-A choice no LLR states |
| B11-14 (a stale confirmed save is not committed: identity, not equality) | needs writing the private `_save_confirmed`; the identity half is covered by `test_tc_b100_65_save_executes_the_painted_plan` (`prepared.plan is screen.plan`) |
| B11-71 (`_save_as_source_for` 1 call per preparation, R2-2), B11-72 (0 `_file_digest` inside `_plan_project_save` when digests are given) | internal call counts with no requirement threshold of their own; the observable consequence (LLR-175.5: 1 digest per session file per open) is tested |
| B11-86 (`source_gone` / dropped-document info rows, A11-16) | no requirement threshold; the fixture (the open project's folder vanishing between open and Save) is a race the brief does not ask for |
| The draft's 130-character file-name arm of LLR-175.4j (P-6) and the `painted_names` 120-character clip | not buildable under the test temp root with `LongPathsEnabled = 0` (MAX_PATH); the one-line rule is tested with the longest name the path allows (cap 90) |
| B11-25's `[b]P` clash | cannot fire (ambiguity 1); re-pinned to `[b]a b` against project `bab` |
| The 56 + 1 direct calls (LLR-175.4l threshold) | the operator override of 2026-10-31 defers whole-module runs to the batch-end battery |

## Design ambiguities met

1. **B11-25 / LLR-175.4g's clash with a project `[b]P` cannot fire.** `sanitize_project_name` keeps only letters, digits, `-` and `_`, so a typed `[b] P` sanitises to `bP`, which never case-folds to a folder named `[b]P`. Re-pinned in `test_tc_b100_65_names_are_painted_literally` to a typed name holding brackets (`[b]a b` against project `bab`): the refusal must hold `'[b]a b'` literally, 0 spans. Route: `qa-reviewer` (threshold text).
2. **Exact row strings.** `test_tc_b100_65_summary_rows_equal_the_plan` asserts the B11-48 rows character for character, including the renamed-row arrow on the emitted image of the pending scenario (`image firmware.s19 → firmware_1.s19 — new`). The arrow is painted "when the source is named and `source.name != landing.name`" (R2-05); whether the emitted-image row carries a named source is G-B's. If it is unnamed, this TC turns RED while the AT (landing name + action word) stays GREEN. Route: `architect` if the GREEN run disagrees.
3. **LLR-175.5 threshold vs B11-36.** The draft says "1 `_file_digest` call per session file (image, MAC, A2L)"; B11-36 says the image is digested only on the copy branch, so an emitting F-case06 session digests the A2L and the MAC and not the image. The test follows B11-36 (A2L 1, MAC 1, `_decide_project_image` 1, `_derived_record` 1).
4. **`_save_painted_preview`** is in the G-B graph (A11-08 memo) but not in the fixed `interfaces-11.md` (which names `_save_session` and `_save_confirmed`). The TC-B100-09 re-pin classifies all three; a classified name the code never assigns is harmless to that census.
5. **"RED only as a mutation" requirements** (LLR-175.2a, LLR-175.3a, LLR-175.3e — declared in E1-scope). Each node still fails on base for a behavioural reason of the same node (the summary is never painted; the focus opens in the parent field). Their own negative controls remain mutations, not executed here (no implementation tree was available to mutate).
6. **Refusal recognition in the re-pinned drives.** The G-A graph marks a refusal with the CSS class `refusal`, a G-A internal outside the fixed interface. The re-pinned drives recognise a refusal black-box (no kind word painted in `#save_where`); only the fake-fed node `test_tc_b100_65_paint_rows_verbatim_in_order_and_refusal_empties` reads the class and its bold weight (C2-1).
7. **AT shape.** The brief says "both halves each, as the draft splits them"; C-18 says one on-disk node per AT. AT-B100-16 is one chain node (open, folder, escape, clash, empty — the five halves) parametrised over the two reference sizes; AT-B100-21 is one node per scenario, each driving both halves (painted, then executed) through one dialog open.
8. **Blank field at open.** B11-46 / SC-1: an empty field paints nothing about the empty name, but a session refusal (missing / unreadable source, blocked entries) is painted at once. The LLR-175.1k / .1l / .1m nodes assert the refusal at open with an empty field; LLR-175.1h asserts no `name is empty` at open.
9. **B11-30's `total_bytes` 69 632** is asserted as a value in `test_tc_b100_47_free_space_short_by_one_and_exact` (the design example); a change in the planner's rounding rule turns only that line RED.
10. **Palette entry.** The command bar dispatches palette actions through `run_action`; the "palette entry `save_project`" arms call `app.run_action("save_project")`.

## Environment limits

- Platform: Windows 11, Python 3.11.15 (`s19env`), Textual 8.2.8. The Windows-only arms (junctions, `strasse` / `straße`, `ab` / `Ab`) ran here; elsewhere they skip (reported not run, never passed).
- `LongPathsEnabled = 0`: the 130-character file-name arm of LLR-175.4j cannot be built; the long-row arm caps the name at what MAX_PATH allows and asserts the `…` only when the row is wider than its region.
- Not run here: the GREEN run (the implementers' code was in progress in the same worktree; by the brief nothing was run against it), every whole-module / full-suite run (operator override 2026-10-31: batch-end battery), and the mutation controls. No test ran against the worktree's `s19_app`.
- `--basetemp` was `scratchpad/t11/bt` (short), never under the repo; `LOCALAPPDATA` pointed to `scratchpad/t11/lad`; the conftest session guard (the real `%LOCALAPPDATA%\s19_app` untouched) ran in every session.
- The case_06 node loads a 37.7 MB A2L (about 17 s here); the 4 MiB node generates and loads a 9.5 MB S19.

## Evidence checklist

- [✓] Every test named exists on disk at the cited path and function name — `tests/test_b100_save_dialog.py` (73 functions, `grep -n "^def test_"`), the re-pins at the paths in the table; collected 154 ids (`pytest --collect-only`).
- [✓] Each result read from ONE complete run's own output, with the command quoted — RED-01 and RED-02 headers quote the command; each file ends with its own summary line.
- [✓] RED-on-base captured where a regression is claimed (base `1747479` named) — RED-01 154/154; the 2 base-green re-pins declared above, no RED claimed for them.
- [✓] Each test asserts an observable outcome — painted `#save_where` / rows, stack, focus, dismiss value, tree on disk, session digest; spies only where a requirement states a count (LLR-175.5, .5a, .5b, A11-01, R3-01, S11-05) and the commit spy for HLR-175a's identity.
- [✓] Uncovered requirements named — none of the 52 live requirements is without a node; partial gaps in "Examples not turned into tests"; LLR-175.1n retired.
- [✓] Environment limits declared — see "Environment limits" (GREEN not run, MAX_PATH, battery deferred).
- [✓] No real PII, credentials or client data — fixtures are the repo's `examples/` files, synthetic S19/HEX bytes and invented names (`P`, `ab`, `strasse`, `[b]x.s19`).
- [✓] Evidence states used are the seven — `executed`, `not-run`, `n/a — retired`.
