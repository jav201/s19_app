# Inc 8b — E5 mutation run summary (copy tree mut8b)

Run against the copy `…/scratchpad/mut8b` with the s19env interpreter.
Every mutant was applied to its target file (bytes preserved, CRLF kept),
the named test node(s) only, then the file was restored and its sha256
verified equal to the original (all `restored = True`).

| id | requirement | file | test (killing node) | verdict |
|---|---|---|---|---|
| M01 | HLR-171 / LLR-171.1 (P-9) | app.py | test_tc_b100_31_save_as_copies_every_subfolder_file; test_at_b100_09_*[size0,size1] | KILLED |
| M02 | LLR-171.1 | project_gather_service.py | test_tc_b100_31_save_as_copies_every_subfolder_file | KILLED |
| M03 | LLR-171.1 R3 | app.py | test_tc_b100_31_save_as_copies_the_top_level_files_but_not_the_backups | KILLED |
| M04 | LLR-171.1 R10 | project_gather_service.py | test_tc_b100_31_save_as_copies_the_top_level_files_but_not_the_backups | KILLED |
| M05 | R11 (A3R2-1) | app.py | test_tc_b100_31_save_as_copies_the_top_level_files_but_not_the_backups | KILLED |
| M06 | R11 | app.py | test_tc_b100_31_save_as_copies_the_top_level_files_but_not_the_backups | KILLED |
| M07 | LLR-171.1a | workspace.py | test_tc_b100_31_links_are_skipped_and_named; test_tc_b100_31_junction_cycle_ends | KILLED |
| M08 | LLR-171.1b | project_gather_service.py | test_tc_b100_31_links_are_skipped_and_named | KILLED |
| M09 | LLR-171.1c | app.py | test_tc_b100_31_links_are_skipped_and_named | KILLED |
| M10 | LLR-171.7a R6 | project_gather_service.py | test_tc_b100_31_link_line_names_at_most_ten; test_tc_b100_31_painted_names_clip_scrub_and_count | KILLED |
| M11 | LLR-171.7 R6 | project_gather_service.py | test_tc_b100_31_link_names_are_scrubbed; test_tc_b100_31_painted_names_clip_scrub_and_count | KILLED |
| M12 | LLR-171.7 S3R2-4 | project_gather_service.py | test_tc_b100_31_link_names_are_scrubbed; test_tc_b100_31_painted_names_clip_scrub_and_count | KILLED |
| M13 | LLR-171.7 S3R2-4 | project_gather_service.py | test_tc_b100_31_painted_names_clip_scrub_and_count | KILLED |
| M14 | LLR-171.7 R6 | project_gather_service.py | test_tc_b100_31_painted_names_clip_scrub_and_count | KILLED |
| M15 | LLR-171.1e | app.py | test_tc_b100_31_free_space_is_checked_before_any_folder[T-1 refused] | KILLED |
| M16 | LLR-171.1e | app.py | test_tc_b100_31_free_space_is_checked_before_any_folder[T saved] | KILLED |
| M17 | LLR-171.1e | app.py | test_tc_b100_31_free_space_is_checked_before_any_folder[T-1 refused] | KILLED |
| M18 | LLR-171.1d | workspace.py | test_tc_b100_31_free_space_is_checked_before_any_folder[T saved]; test_tc_b100_59_plan_total_counts_every_written_byte | KILLED |
| M19 | LLR-171.1i / R7 | project_gather_service.py | test_tc_b100_59_plan_total_counts_every_written_byte | KILLED |
| M20 | R7 | project_gather_service.py | test_tc_b100_59_plan_total_counts_every_written_byte; test_tc_b100_59_plan_total_rounding_per_file; test_tc_b100_31_free_space_...[T-1 refused] | KILLED |
| M21 | R7 | project_gather_service.py | test_tc_b100_59_plan_total_counts_every_written_byte; test_tc_b100_59_plan_total_rounding_per_file; test_tc_b100_31_free_space_...[T-1 refused] | KILLED |
| M22 | R14 | project_gather_service.py | (already killed at E4 integration) | skipped |
| M23 | LLR-171.1f | app.py | test_tc_b100_31_save_as_copies_every_subfolder_file; test_tc_b100_31_failed_copy_rolls_back_in_user_terms | KILLED |
| M24 | LLR-171.1g | project_gather_service.py | test_tc_b100_31_merge_and_save_into_itself_copy_no_subfolder; test_tc_b100_59_plan_total_counts_every_written_byte (merge) | SURVIVED |
| M25 | LLR-171.1h | app.py | test_tc_b100_31_save_as_carries_the_open_projects_records | KILLED |
| M26 | LLR-171.1h | app.py | test_tc_b100_31_save_as_carries_the_open_projects_records | KILLED |
| M27 | LLR-171.6 / .6a R4 (C-7) | app.py | test_tc_b100_31_empty_selection_keeps_batch_for_every_target | KILLED |
| M28 | LLR-171.6b A3R2-3/-4 | app.py | test_tc_b100_31_gather_takes_names_from_the_recorded_batch_and_assignments | KILLED |
| M29 | LLR-171.1j R1 | project_gather_service.py | test_tc_b100_31_copy_ceiling_2000_files | KILLED |
| M30 | LLR-171.1j R1 | project_gather_service.py | test_tc_b100_31_copy_ceiling_2000_files | KILLED |
| M31 | LLR-171.1j R1 | project_gather_service.py | test_tc_b100_31_depth_ceiling[33] | KILLED |
| M32 | LLR-171.1j R1 | project_gather_service.py | test_tc_b100_31_depth_ceiling[32] | KILLED |
| M33 | LLR-171.1j R13 | project_gather_service.py | test_tc_b100_31_entry_ceiling[10001 refused] | KILLED |
| M34 | R13 | project_gather_service.py | test_tc_b100_31_entry_ceiling[10000 saved] | KILLED |
| M35 | R16 | workspace.py | test_tc_b100_31_entry_ceiling[10001 refused] | SURVIVED |
| M36 | LLR-171.1k R8 | project_gather_service.py | test_tc_b100_31_unreadable_entries_refuse_the_save[1,12] | KILLED |
| M37 | LLR-171.1k R6 | project_gather_service.py | test_tc_b100_31_unreadable_entries_refuse_the_save[12] | KILLED |
| M38 | LLR-171.7b R6 | app.py | test_tc_b100_31_failed_copy_rolls_back_in_user_terms | KILLED |
| M39 | LLR-171.7b | app.py | test_tc_b100_31_failed_copy_rolls_back_in_user_terms | KILLED |
| M40 | LLR-171.1l R9 | app.py | test_tc_b100_31_flow_session_folder_follows_q | KILLED |
| M41 | LLR-171.1m R9 / S3R2-5 | app.py | (already killed at E4 integration) | skipped |
| M42 | LLR-171.2 / HLR-171a | app.py | test_tc_b100_32_a2l_only_project_opens_with_its_own_a2l; test_at_b100_10_*[size0,size1] | KILLED |
| M43 | LLR-171.2 | app.py | test_tc_b100_32_a2l_only_project_opens_with_its_own_a2l; test_tc_b100_32_a2l_only_load_clears_the_previous_data_file; test_tc_b100_32_data_file_loaded_into_a2l_only_project_is_recorded; test_at_b100_10_* | KILLED |
| M44 | LLR-171.2a | app.py | test_tc_b100_32_a2l_only_load_clears_the_previous_data_file | KILLED |
| M45 | LLR-171.2b | app.py | test_tc_b100_32_a2l_only_project_opens_with_its_own_a2l | KILLED |
| M46 | LLR-171.2c | app.py | test_tc_b100_32_data_file_loaded_into_a2l_only_project_is_recorded | SURVIVED |
| M47 | LLR-171.2d | app.py | test_tc_b100_32_empty_folder_is_refused_before_any_reset[no data or A2L file] | KILLED |
| M48 | LLR-171.2e | app.py | test_tc_b100_32_empty_folder_is_refused_before_any_reset[no project.json] | KILLED |
| M49 | LLR-171.2d/e | app.py | test_tc_b100_32_empty_folder_is_refused_before_any_reset[no data or A2L file, no project.json] | KILLED |
| M50 | LLR-171.2f R5 | app.py | test_tc_b100_32_a2l_guard_of_an_a2l_only_folder[link] | KILLED |
| M51 | LLR-171.2f R5 | app.py | test_tc_b100_32_a2l_guard_of_an_a2l_only_folder[at cap] | KILLED |
| M52 | LLR-171.2f | app.py | test_tc_b100_32_a2l_guard_of_an_a2l_only_folder[link, over cap] | KILLED |
| M53 | LLR-171.2g R5 | app.py | test_tc_b100_32_over_cap_a2l_beside_a_data_file_is_left_out | KILLED |
| M54 | LLR-171.2g S3R2-3 | app.py | (already killed at E4 integration) | skipped |
| M55 | LLR-171.3 (C2) | app.py | test_tc_b100_33_foreign_parent_is_refused_before_any_folder[other work area, outside, W/patches] | KILLED |
| M56 | LLR-171.3 | app.py | test_tc_b100_33_foreign_parent_is_refused_before_any_folder[W/patches] | KILLED |
| M57 | LLR-171.3a | app.py | test_tc_b100_33_work_area_under_another_spelling_saves_there[*] | KILLED |
| M58 | LLR-171.3a S3-10 | app.py | test_tc_b100_33_work_area_under_another_spelling_saves_there[junction alias, upper case] | KILLED |
| M59 | LLR-171.4c | app.py | test_tc_b100_62_listing_leaves_out_links_and_junctions; test_at_b100_11_* | KILLED |
| M60 | LLR-171.4c | app.py | test_tc_b100_62_listing_leaves_out_links_and_junctions | KILLED |
| M61 | LLR-171.4e | app.py | test_tc_b100_62_load_refuses_a_junction_project[evil, alias] | KILLED |
| M62 | LLR-171.4f S3-7 | app.py | test_tc_b100_62_load_refuses_a_folder_outside_the_work_area[dot-dot name, two-part name] | KILLED |
| M63 | LLR-171.4g | app.py | test_tc_b100_62_save_target_junction_is_refused[new name, merge target]; test_at_b100_11_* | KILLED |
| M64 | LLR-167.6a | project_gather_service.py | test_tc_b100_59_save_as_plans_one_row_per_subfolder | KILLED |
| M65 | LLR-167.6a Q9 | project_gather_service.py | test_tc_b100_59_links_only_folder_and_skipped_links | KILLED |
| M66 | LLR-167.6b | project_gather_service.py | test_tc_b100_59_links_only_folder_and_skipped_links | KILLED |
| M67 | LLR-167.6c | project_gather_service.py | test_tc_b100_59_second_companion_is_refused_before_any_folder[mac-…] | KILLED |
| M68 | LLR-167.6d | project_gather_service.py | test_tc_b100_59_second_companion_is_refused_before_any_folder[a2l-…]; test_tc_b100_59_own_a2l_by_name_and_bytes[False] | KILLED |
| M69 | LLR-167.6c/f DR-6 | app.py | test_tc_b100_59_own_a2l_by_name_and_bytes[False] | KILLED |
| M70 | LLR-167.6f (C3) | app.py | test_at_b100_10_a2l_only_project_saves_and_reopens[size0,size1] | KILLED |
| M71 | LLR-167.6e | project_gather_service.py | test_tc_b100_59_document_row_owns_its_landing | KILLED |
| M72 | LLR-167.6g | project_gather_service.py | test_tc_b100_59_file_over_the_cap_is_refused_in_the_plan[1]; test_tc_b100_59_plan_cap_refusal_names_the_file[1025-True] | KILLED |
| M73 | LLR-167.6g | project_gather_service.py | test_tc_b100_59_file_over_the_cap_is_refused_in_the_plan[0]; test_tc_b100_59_plan_cap_refusal_names_the_file[1024-False] | KILLED |
| M74 | LLR-167.6g pre-ruling 4 | project_gather_service.py | test_tc_b100_59_file_over_the_cap_is_refused_in_the_plan[1] | KILLED |
| M75 | LLR-171.5 | app.py | (already killed at E4 integration) | skipped |
| M76 | R2 (A3-1) | app.py | (already killed at E4 integration) | skipped |
| M77 | R2 / LLR-167.6e | project_gather_service.py | test_e4_r2_pasted_document_beside_a_different_p_file_lands_changes_1 | KILLED |
| M78 | R11 (F-8) | app.py | (already killed at E4 integration) | skipped |
| M79 | R11 / A3R2-5 / R15 | app.py | (already killed at E4 integration) | skipped |
| M80 | LLR-171.1m S3R2-5 | app.py | (already killed at E4 integration) | skipped |
| M81 | LLR-171.1k (R8, DR-5) | project_gather_service.py | (already killed at E4 integration) | skipped |
| M82 | LLR-171.1k (S3R2-6) | project_gather_service.py | (already killed at E4 integration) | skipped |
| M83 | A3-13 | project_gather_service.py | (already killed at E4 integration) | skipped |
| M84 | token row 9 (S3-6) | app.py | (already killed at E4 integration) | skipped |
| M85 | AT-B100-10 (ruling D-5) | app.py | (already killed at E4 integration) | skipped |

## Counts

| verdict | count |
|---|---|
| KILLED | 69 |
| SURVIVED | 3 |
| INVALID | 0 |
| skipped (already killed at E4 integration) | 13 |

Total rows: 85 (72 run in this pass + 13 skipped).

## Survivors

- **M24** (LLR-171.1g, "copy run for a merge / open-project target") — **wrong target**. The
  behaviour is gated in TWO files: the app's `_plan_project_save` sets `source_dir` (and thus
  passes an inventory) only for `PLAN_TARGET_NEW`, and the planner's
  `copying = target_kind == PLAN_TARGET_NEW and inventory is not None` condition is the second
  gate. Changing only the planner's condition (`copying = inventory is not None`) leaves the
  app merge path untouched (it still passes no inventory), so
  `test_tc_b100_31_merge_and_save_into_itself_copy_no_subfolder` stays green; and the planner
  merge arm of `test_tc_b100_59_plan_total_counts_every_written_byte` is masked by the
  fixture's own A2L clash — the merge target P already holds `firmware.a2l` and the plan rows
  include an A2L, so `_second_file_refusal` returns a refusal (empty folders/copies) before
  the `copies != ()` assertion can observe the copy. No single-file edit can make either named
  test turn RED for this behaviour.
- **M35** (R16, "walk sorts/reads a whole folder before counting (unbounded)") — **weak test**.
  Removing the walk's early stop makes `walk_tree_no_links` read and sort the whole
  10 001-entry folder, but that still finishes well under the test's 5-second wall-clock
  bound on this fixture (the entry ceiling is still enforced afterwards via
  `len(walked) > entry_ceiling`, so the refusal still fires). The kill depends on the slowdown
  exceeding 5 s, which it does not.
- **M46** (LLR-171.2c, "`_variant_set` left None on the A2L-only branch") — **equivalent
  mutant**. Leaving `_variant_set` None after an A2L-only load has no observable effect: the
  subsequent `load_from_path` sync calls `_activate_project_file`, which rebuilds
  `_variant_set` from disk (`validate_project_files` + `build_variant_set`) before
  `_rewrite_project_manifest` writes `active_variant`, so `project.json` is rewritten with
  `active_variant == "firmware"` regardless of the value left by the A2L-only branch.

## E5 corrective pass 1 (LED .80) — new arms and the survivors

Run with `…/scratchpad/cp8b-1/tools/mutants.py` in the copy trees `…/scratchpad/cp8b-1/mutA|mutB|mutC` (s19env Python 3.11, `NO_COLOR` unset). Each mutant was applied to its target (CRLF kept), only the named node(s) were run, then the file was restored and its sha256 checked (`restored = True` in every transcript `mut-cp1-<id>.txt`).

| id | requirement / finding | file | killing node | verdict |
|---|---|---|---|---|
| MC01 | LLR-171.1n (F1): P's folder existence ignored | app.py | test_tc_b100_31_open_project_folder_gone_saves_without_a_copy[gone, save as P / Q] | KILLED |
| MC02 | LLR-171.1n (F1): the missing-folder line dropped | app.py | …[gone, save as Q] | KILLED |
| MC03 | LLR-171.2h (F3): no A2L-only branch in the unload | app.py | test_tc_b100_32_unload_of_an_a2l_only_session_clears_the_a2l | KILLED |
| MC04 | LLR-171.5 / token row (F4 b): "the path is too long to record" again | app.py | test_tc_b100_31_unrecorded_name_reason_is_not_too_long | KILLED |
| MC05 | token row (F5 a): the repeating mismatch says "save again" | app.py | test_tc_b100_31_identical_copy_mismatch_names_a_true_step | KILLED |
| MC06 | LLR-171.1m (F5 b): rebind to the planned name, not the gather's landing | app.py | test_tc_b100_31_document_with_an_identical_sibling_follows_its_landing | KILLED |
| MC07 | LLR-171.4f (F7 a): a permission error mapped to "outside" | app.py | test_tc_b100_62_folder_check_permission_error_has_its_own_text[load, save target] | KILLED |
| MC08 | LLR-171.7c (SEC8b-1): both rollback checks removed | app.py | test_tc_b100_31_rollback_never_deletes_through_a_swapped_folder[junction to R] | KILLED |
| MC09 | LLR-171.7c (SEC8b-1): the reparse check removed | app.py | …[junction to itself] | KILLED |
| MC10 | LLR-171.7c (SEC8b-1): the identity check removed | app.py | …[replaced file] | KILLED (re-run after the node's `is_file()` assertion was added) |
| MC11 | LLR-171.1o (SEC8b-2): the containment-only source check | app.py | test_tc_b100_31_copy_refuses_when_p_itself_becomes_a_junction | KILLED |
| MC12 | LLR-171.1h (SEC8b-3): no `lstat` of P's `project.json` | app.py | test_tc_b100_31_linked_project_json_is_not_carried | KILLED |
| MC13 | M24 again (LLR-171.1g): `copying = inventory is not None` | project_gather_service.py | test_tc_b100_59_merge_and_open_targets_plan_no_copy | KILLED |
| MC14 | M35 again (R16): no early stop in the walker | workspace.py | test_tc_b100_31_walker_stops_before_sorting_a_huge_folder | KILLED |
| MC15 | LLR-171.2g (F2, operator-approved 5th source): no `STEP_REPLACE_A2L` mark on the A2L problem | app.py | test_tc_b100_32_unreadable_a2l_row_paints_the_true_next_step | KILLED |

Survivors of the E5 run, resolved:
- **M24 (wrong target):** the new planner node passes no file row, so `_second_file_refusal` cannot mask the merge arm; it asserts refusal None and 0 folders / 0 copies for `merge` and `open project`. MC13 (M24's own edit) is KILLED.
- **M35 (weak test):** the new node spies on the walker module's `sorted` and on the yield count. One 1 050-entry folder with `max_entries=1 000` lets `sorted` see at most 1 001 entries; M35 makes it see 1 050. MC14 is KILLED, with no wall-clock bound involved.
- **M46 (equivalent):** kept as equivalent. Leaving `_variant_set` as None on the A2L-only branch has no observable effect: the next data-file load's `_activate_project_file` rebuilds `_variant_set` from disk before `_rewrite_project_manifest` writes `active_variant`, and no reader of `_variant_set` runs in between in the LLR-171.2c scenario (`inc-8b/E5-cp1-notes.md`).

Counts (cp1): 15 run, 15 KILLED, 0 SURVIVED, 0 INVALID.
