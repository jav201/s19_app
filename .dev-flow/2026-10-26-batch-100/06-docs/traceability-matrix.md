# Traceability Matrix — s19_app — Batch 2026-10-26-batch-100

> **Artifact language:** canonical English scaffold. This document mints no field a rule keys on — its ids (`US-`/`HLR-`/`LLR-`/`AT-`/`TC-`) are read by the Atlas id-scanner and are not words in any language — so it carries no reserved-field block.

> **Roles:** `docs-writer`. Phase 6 artifact. Audience: technical stakeholder. The requirement topology (US → HLR → LLR → TC/AT) is `01-requirements.md` §2.6 / §3 / §4 / §5, as amended by `01-requirements-ledger.md`. Increment attribution comes from the packet headers' `Requirement(s)` / `Acceptance` fields (`03-increments/increment-001…022.md`) and the §5.3 arms table. `Test (file::function)` is the implementing test node measured by `grep` on the current tree (`b100-close`, `main` at `570b4b5`).

> **Owed in.** `core` · `full` — one row per live LLR and one per AT, counted by script (not by eye).

> Two chains (per the Two-layer validation rule): a story is complete only when BOTH exist — the functional (white-box) chain US → HLR → LLR → TC → test node, and the behavioral (black-box) chain US → AT → observed outcome through the shipped surface. Every row below is complete; there is no coverage gap.

## 1. Master table — functional chain (white-box)

> One row per live LLR (349), grouped by HLR. `TC` is the white-box id the LLR names in its *Executed verification* (or `re-pinned` for the two G-005 re-pin requirements). `Test (file::function)` is the file and first test function of that TC (each TC expands to several `test_tc_b100_NN_*` functions; `(+N)` is the number of further functions). `Inc` is the first increment whose packet names the LLR.

| US | HLR | LLR | TC | Test (file::function) | Inc |
|----|-----|-----|-----|----------------------|-----|
| **HLR-163 — Byte-identical copies are reused (US-153)** |  |  |  |  |  |
| US-153 | HLR-163 | LLR-163.1 | TC-B100-01 | test_b100_reuse.py::test_tc_b100_01_app_placements_name_the_workarea_root (+8) | Inc 1 |
| US-153 | HLR-163 | LLR-163.2 | TC-B100-02 | test_b100_reuse.py::test_tc_b100_02_size_check_runs_before_any_candidate_read | Inc 1 |
| US-153 | HLR-163 | LLR-163.3 | — (re-pinned) | test_unified_write.py::test_tc018_existing_name_is_dedup_suffixed; test_tui_patch_editor_v2.py::test_at031b_two_saves_are_distinct_no_clobber | Inc 1 |
| US-153 | HLR-163 | LLR-163.4 | — (re-pinned) | test_b99_export.py::test_tc_b99_31_changed_bytes_take_the_next_free_name; test_b99_export.py::test_tc_b99_31_bin_pair_placed_under_one_suffix; test_flow_a2b_b94.py::test_tc_b94_04_template_save_reload_and_dedup; test_tui_flow_builder_b94.py::test_at_b94_17_template_save_listing_import_and_dedup; test_b99_staging.py::test_tc_b99_13_unchanged_resave_after_drift_adds_no_duplicate | Inc 1 |
| US-153 | HLR-163 | LLR-163.5 | TC-B100-03 | test_b100_reuse.py::test_tc_b100_03_reused_variant_is_named_not_added | Inc 1 |
| US-153 | HLR-163 | LLR-163.6 | TC-B100-57 | test_b100_reuse.py::test_tc_b100_57_export_holds_no_byte_identity_rule (+2) | Inc 1 |
| US-153 | HLR-163 | LLR-163.7 | TC-B100-68 | test_b100_reuse.py::test_tc_b100_68_forced_claim_between_prediction_and_placement (+3) | Inc 1 |
| **HLR-164 — Save project refuses unsafe names and leaves nothing behind (US-154)** |  |  |  |  |  |
| US-154 | HLR-164 | LLR-164.1 | TC-B100-04 | test_b100_save_guards.py::test_tc_b100_04_device_names_refused_raw_and_sanitised (+4) | Inc 2 |
| US-154 | HLR-164 | LLR-164.2 | TC-B100-05 | test_b100_save_guards.py::test_tc_b100_05_case_only_clash_refused (+18) | Inc 2 |
| US-154 | HLR-164 | LLR-164.3 | TC-B100-06 | test_b100_save_guards.py::test_tc_b100_06_name_cap_boundary (+1) | Inc 2 |
| US-154 | HLR-164 | LLR-164.4 | TC-B100-07 | test_b100_save_guards.py::test_tc_b100_07_ast_census_every_post_creation_return_removes (+26) | Inc 2 |
| US-154 | HLR-164 | LLR-171.7c | TC-B100-31 | test_b100_project_homes.py::test_tc_b100_31_copy_ceiling_2000_files (+27) | Inc 8b |
| **HLR-165 — A project load starts from an empty session (US-155)** |  |  |  |  |  |
| US-155 | HLR-165 | LLR-165.1 | TC-B100-08 | test_b100_session_reset.py::test_tc_b100_08_call_site_census (+3) | Inc 3 |
| US-155 | HLR-165 | LLR-165.2 | TC-B100-09 | test_b100_session_reset.py::test_tc_b100_09_domain_matches_the_live_source_census (+4) | Inc 3 |
| US-155 | HLR-165 | LLR-165.3 | TC-B100-10 | test_b100_session_reset.py::test_tc_b100_10_change_service_is_rebound (+5) | Inc 3 |
| US-155 | HLR-165 | LLR-165.4 | TC-B100-11 | test_b100_session_reset.py::test_tc_b100_11_bare_s19_reload_after_unload_shows_no_a2l_tags (+2) | Inc 3 |
| **HLR-166 — The focus lands on a named, visible, non-text widget (US-156)** |  |  |  |  |  |
| US-156 | HLR-166 | LLR-166.1 | TC-B100-12 | test_b100_focus.py::test_tc_b100_12_bad_default_focus_is_rehomed_behind_a_modal (+20) | Inc 4 |
| US-156 | HLR-166 | LLR-166.2 | TC-B100-13 | test_b100_focus.py::test_tc_b100_13_a2l_only_load_with_no_image (+1) | Inc 4 |
| **HLR-167 — Save project saves the source plus the change document, verified, and copies when nothing changed (US-157)** |  |  |  |  |  |
| US-157 | HLR-167 | LLR-167.1 | TC-B100-14 | test_b100_save_image.py::test_tc_b100_14_applied_then_undone_copies (+7) | Inc 5 |
| US-157 | HLR-167 | LLR-167.2 | TC-B100-15 | test_b100_save_image.py::test_tc_b100_15_check_document_only_copies (+7) | Inc 5 |
| US-157 | HLR-167 | LLR-167.3 | TC-B100-16 | test_b100_save_image.py::test_tc_b100_16_entry_added_after_the_apply (+1) | Inc 5 |
| US-157 | HLR-167 | LLR-167.4 | TC-B100-17 | test_b100_save_image.py::test_tc_b100_17_blocked_entry_refuses_the_whole_save (+5) | Inc 5 |
| US-157 | HLR-167 | LLR-167.5 | TC-B100-58 | test_b100_save_image.py::test_tc_b100_58_mac_attach_keeps_an_unsaved_patch_unsaved (+4) | Inc 5 |
| US-157 | HLR-167 | LLR-167.6 | TC-B100-59 | test_b100_save_image.py::test_tc_b100_59_document_row_in_a_fresh_folder (+22) | Inc 5 |
| US-157 | HLR-167 | LLR-167.6a | TC-B100-59 | test_b100_save_image.py::test_tc_b100_59_document_row_in_a_fresh_folder (+22) | Inc 8b |
| US-157 | HLR-167 | LLR-167.6b | TC-B100-59 | test_b100_save_image.py::test_tc_b100_59_document_row_in_a_fresh_folder (+22) | Inc 8b |
| US-157 | HLR-167 | LLR-167.6c | TC-B100-59 | test_b100_save_image.py::test_tc_b100_59_document_row_in_a_fresh_folder (+22) | Inc 8b |
| US-157 | HLR-167 | LLR-167.6d | TC-B100-59 | test_b100_save_image.py::test_tc_b100_59_document_row_in_a_fresh_folder (+22) | Inc 8b |
| US-157 | HLR-167 | LLR-167.6e | TC-B100-59 | test_b100_save_image.py::test_tc_b100_59_document_row_in_a_fresh_folder (+22) | Inc 8b |
| US-157 | HLR-167 | LLR-167.6f | TC-B100-59 | test_b100_save_image.py::test_tc_b100_59_document_row_in_a_fresh_folder (+22) | Inc 8b |
| US-157 | HLR-167 | LLR-167.6g | TC-B100-59 | test_b100_save_image.py::test_tc_b100_59_document_row_in_a_fresh_folder (+22) | Inc 8b |
| US-157 | HLR-167 | LLR-167.7 | TC-B100-69 | test_b100_save_image.py::test_tc_b100_69_rederive_writes_nothing_into_the_session_map (+2) | Inc 5 |
| US-157 | HLR-167 | LLR-167.8 | TC-B100-70 | test_b100_save_image.py::test_tc_b100_70_failed_document_write_keeps_the_flag (+6) | Inc 5 |
| **HLR-168 — A save-back into the project becomes the active variant (US-158)** |  |  |  |  |  |
| US-158 | HLR-168 | LLR-168.1 | TC-B100-18 | test_b100_active_variant.py::test_tc_b100_18_absent_key_is_empty_with_no_issue (+4) | Inc 6 |
| US-158 | HLR-168 | LLR-168.2 | TC-B100-19 | test_b100_active_variant.py::test_tc_b100_19_save_back_becomes_the_active_variant (+1) | Inc 6 |
| US-158 | HLR-168 | LLR-168.3 | TC-B100-20 | test_b100_active_variant.py::test_tc_b100_20_a2l_sync_carries_every_key (+13) | Inc 6 |
| US-158 | HLR-168 | LLR-168.4 | TC-B100-71 | test_b100_active_variant.py::test_tc_b100_71_byte_copy_records_nothing (+4) | Inc 7 |
| **HLR-169 — Load opens what is valid and lists every problem (US-159)** |  |  |  |  |  |
| US-159 | HLR-169 | LLR-169.1 | TC-B100-21 | test_b100_project_check.py::test_tc_b100_21_no_files_is_byte_identical (+2) | Inc 7 |
| US-159 | HLR-169 | LLR-169.2 | TC-B100-22 | test_b100_project_check.py::test_tc_b100_22_seam_scope_is_top_level_data_and_a2l | Inc 7 |
| US-159 | HLR-169 | LLR-169.3 | TC-B100-23 | test_b100_project_check.py::test_tc_b100_23_active_document_changed_between_write_and_verify (+3) | Inc 7 |
| US-159 | HLR-169 | LLR-169.4 | TC-B100-24 | test_b100_project_check.py::test_tc_b100_24_assignments_75_by_1000_is_one_issue_fast (+10) | Inc 7 |
| US-159 | HLR-169 | LLR-169.5 | TC-B100-25 | test_b100_project_check.py::test_tc_b100_25_changed_document_is_named_by_its_project_text (+8) | Inc 7 |
| US-159 | HLR-169 | LLR-169.6 | TC-B100-26 | test_b100_project_check.py::test_tc_b100_26_active_deleted_the_other_opens (+1) | Inc 7 |
| US-159 | HLR-169 | LLR-169.7 | TC-B100-27 | test_b100_project_check.py::test_tc_b100_27_concurrent_manifest_writes (+1) | Inc 7 |
| US-159 | HLR-169 | LLR-169.8 | TC-B100-60 | test_b100_project_check.py::test_tc_b100_60_default_mode_is_unchanged (+2) | Inc 7 |
| US-159 | HLR-169 | LLR-169.9 | TC-B100-61 | test_b100_project_check.py::test_tc_b100_61_case_6_is_only_not_readable (+17) | Inc 7 |
| **HLR-170 — The change document is saved and reopened with the project (US-160)** |  |  |  |  |  |
| US-160 | HLR-170 | LLR-170.1 | TC-B100-28 | test_b100_document.py::test_tc_b100_28_a15_absent_document_has_no_record (+20) | Inc 8a |
| US-160 | HLR-170 | LLR-170.2 | TC-B100-29 | test_b100_document.py::test_tc_b100_29_cp1_case_sensitive_work_area_keeps_two_projects_apart (+25) | Inc 8a |
| US-160 | HLR-170 | LLR-170.3 | TC-B100-30 | test_b100_document.py::test_tc_b100_30_classifier_a_folder_is_unreadable (+21) | Inc 8a |
| **HLR-171 — Save as copies the whole project (US-161)** |  |  |  |  |  |
| US-161 | HLR-171 | LLR-171.1 | TC-B100-31 | test_b100_project_homes.py::test_tc_b100_31_copy_ceiling_2000_files (+27) | Inc 8b |
| US-161 | HLR-171 | LLR-171.1a | TC-B100-31 | test_b100_project_homes.py::test_tc_b100_31_copy_ceiling_2000_files (+27) | Inc 8b |
| US-161 | HLR-171 | LLR-171.1b | TC-B100-31 | test_b100_project_homes.py::test_tc_b100_31_copy_ceiling_2000_files (+27) | Inc 8b |
| US-161 | HLR-171 | LLR-171.1c | TC-B100-31 | test_b100_project_homes.py::test_tc_b100_31_copy_ceiling_2000_files (+27) | Inc 8b |
| US-161 | HLR-171 | LLR-171.1d | TC-B100-31 | test_b100_project_homes.py::test_tc_b100_31_copy_ceiling_2000_files (+27) | Inc 8b |
| US-161 | HLR-171 | LLR-171.1e | TC-B100-31 | test_b100_project_homes.py::test_tc_b100_31_copy_ceiling_2000_files (+27) | Inc 8b |
| US-161 | HLR-171 | LLR-171.1f | TC-B100-31 | test_b100_project_homes.py::test_tc_b100_31_copy_ceiling_2000_files (+27) | Inc 8b |
| US-161 | HLR-171 | LLR-171.1g | TC-B100-31 | test_b100_project_homes.py::test_tc_b100_31_copy_ceiling_2000_files (+27) | Inc 8b |
| US-161 | HLR-171 | LLR-171.1h | TC-B100-31 | test_b100_project_homes.py::test_tc_b100_31_copy_ceiling_2000_files (+27) | Inc 8b |
| US-161 | HLR-171 | LLR-171.1i | TC-B100-31 | test_b100_project_homes.py::test_tc_b100_31_copy_ceiling_2000_files (+27) | Inc 8b |
| US-161 | HLR-171 | LLR-171.1j | TC-B100-31 | test_b100_project_homes.py::test_tc_b100_31_copy_ceiling_2000_files (+27) | Inc 8b |
| US-161 | HLR-171 | LLR-171.1k | TC-B100-31 | test_b100_project_homes.py::test_tc_b100_31_copy_ceiling_2000_files (+27) | Inc 8b |
| US-161 | HLR-171 | LLR-171.1l | TC-B100-31 | test_b100_project_homes.py::test_tc_b100_31_copy_ceiling_2000_files (+27) | Inc 8b |
| US-161 | HLR-171 | LLR-171.1m | TC-B100-31 | test_b100_project_homes.py::test_tc_b100_31_copy_ceiling_2000_files (+27) | Inc 8b |
| US-161 | HLR-171 | LLR-171.1n | TC-B100-31 | test_b100_project_homes.py::test_tc_b100_31_copy_ceiling_2000_files (+27) | Inc 8b |
| US-161 | HLR-171 | LLR-171.1o | TC-B100-31 | test_b100_project_homes.py::test_tc_b100_31_copy_ceiling_2000_files (+27) | Inc 8b |
| US-161 | HLR-171 | LLR-171.5 | TC-B100-31 | test_b100_project_homes.py::test_tc_b100_31_copy_ceiling_2000_files (+27) | Inc 8b |
| US-161 | HLR-171 | LLR-171.6 | TC-B100-31 | test_b100_project_homes.py::test_tc_b100_31_copy_ceiling_2000_files (+27) | Inc 8b |
| US-161 | HLR-171 | LLR-171.6a | TC-B100-31 | test_b100_project_homes.py::test_tc_b100_31_copy_ceiling_2000_files (+27) | Inc 8b |
| US-161 | HLR-171 | LLR-171.6b | TC-B100-31 | test_b100_project_homes.py::test_tc_b100_31_copy_ceiling_2000_files (+27) | Inc 8b |
| US-161 | HLR-171 | LLR-171.7 | TC-B100-31 | test_b100_project_homes.py::test_tc_b100_31_copy_ceiling_2000_files (+27) | Inc 8b |
| US-161 | HLR-171 | LLR-171.7a | TC-B100-31 | test_b100_project_homes.py::test_tc_b100_31_copy_ceiling_2000_files (+27) | Inc 8b |
| US-161 | HLR-171 | LLR-171.7b | TC-B100-31 | test_b100_project_homes.py::test_tc_b100_31_copy_ceiling_2000_files (+27) | Inc 8b |
| **HLR-171a — An A2L-only project opens (US-161)** |  |  |  |  |  |
| US-161 | HLR-171a | LLR-171.2 | TC-B100-32 | test_b100_project_homes.py::test_tc_b100_32_a2l_admission_refuses_any_reparse_point (+8) | Inc 8b |
| US-161 | HLR-171a | LLR-171.2a | TC-B100-32 | test_b100_project_homes.py::test_tc_b100_32_a2l_admission_refuses_any_reparse_point (+8) | Inc 8b |
| US-161 | HLR-171a | LLR-171.2b | TC-B100-32 | test_b100_project_homes.py::test_tc_b100_32_a2l_admission_refuses_any_reparse_point (+8) | Inc 8b |
| US-161 | HLR-171a | LLR-171.2c | TC-B100-32 | test_b100_project_homes.py::test_tc_b100_32_a2l_admission_refuses_any_reparse_point (+8) | Inc 8b |
| US-161 | HLR-171a | LLR-171.2d | TC-B100-32 | test_b100_project_homes.py::test_tc_b100_32_a2l_admission_refuses_any_reparse_point (+8) | Inc 8b |
| US-161 | HLR-171a | LLR-171.2f | TC-B100-32 | test_b100_project_homes.py::test_tc_b100_32_a2l_admission_refuses_any_reparse_point (+8) | Inc 8b |
| US-161 | HLR-171a | LLR-171.2g | TC-B100-32 | test_b100_project_homes.py::test_tc_b100_32_a2l_admission_refuses_any_reparse_point (+8) | Inc 8b |
| US-161 | HLR-171a | LLR-171.2h | TC-B100-32 | test_b100_project_homes.py::test_tc_b100_32_a2l_admission_refuses_any_reparse_point (+8) | Inc 8b |
| **HLR-171b — Only folders inside this work area are listed, loaded or written as projects (US-161)** |  |  |  |  |  |
| US-161 | HLR-171b | LLR-171.3 | TC-B100-33 | test_b100_project_homes.py::test_tc_b100_33_foreign_parent_is_refused_before_any_folder (+1) | Inc 8b |
| US-161 | HLR-171b | LLR-171.3a | TC-B100-33 | test_b100_project_homes.py::test_tc_b100_33_foreign_parent_is_refused_before_any_folder (+1) | Inc 8b |
| US-161 | HLR-171b | LLR-171.4 | TC-B100-62 | test_b100_reuse.py::test_tc_b100_62_containment_predicate (+25) | Inc 1 |
| US-161 | HLR-171b | LLR-171.4a | TC-B100-62 | test_b100_reuse.py::test_tc_b100_62_containment_predicate (+25) | Inc 1 |
| US-161 | HLR-171b | LLR-171.4b | TC-B100-62 | test_b100_reuse.py::test_tc_b100_62_containment_predicate (+25) | Inc 1 |
| US-161 | HLR-171b | LLR-171.4c | TC-B100-62 | test_b100_reuse.py::test_tc_b100_62_containment_predicate (+25) | Inc 8b |
| US-161 | HLR-171b | LLR-171.4e | TC-B100-62 | test_b100_reuse.py::test_tc_b100_62_containment_predicate (+25) | Inc 8b |
| US-161 | HLR-171b | LLR-171.4f | TC-B100-62 | test_b100_reuse.py::test_tc_b100_62_containment_predicate (+25) | Inc 8b |
| US-161 | HLR-171b | LLR-171.4g | TC-B100-62 | test_b100_reuse.py::test_tc_b100_62_containment_predicate (+25) | Inc 8b |
| US-161 | HLR-171b | LLR-171.4h | TC-B100-62 | test_b100_reuse.py::test_tc_b100_62_containment_predicate (+25) | Inc 8b |
| US-161 | HLR-171b | LLR-171.4i | TC-B100-62 | test_b100_reuse.py::test_tc_b100_62_containment_predicate (+25) | Inc 1 |
| US-161 | HLR-171b | LLR-171.4j | TC-B100-62 | test_b100_reuse.py::test_tc_b100_62_containment_predicate (+25) | Inc 1 |
| **HLR-172 — Recent sources are remembered per user (US-162)** |  |  |  |  |  |
| US-162 | HLR-172 | LLR-172.1 | TC-B100-34 | test_b100_recents.py::test_tc_b100_34_a2l_found_only_through_the_fallback_is_not_recorded (+27) | Inc 9a |
| US-162 | HLR-172 | LLR-172.1a | TC-B100-34 | test_b100_recents.py::test_tc_b100_34_a2l_found_only_through_the_fallback_is_not_recorded (+27) | Inc 9a |
| US-162 | HLR-172 | LLR-172.1b | TC-B100-34 | test_b100_recents.py::test_tc_b100_34_a2l_found_only_through_the_fallback_is_not_recorded (+27) | Inc 9a |
| US-162 | HLR-172 | LLR-172.1c | TC-B100-34 | test_b100_recents.py::test_tc_b100_34_a2l_found_only_through_the_fallback_is_not_recorded (+27) | Inc 9a |
| US-162 | HLR-172 | LLR-172.1d | TC-B100-34 | test_b100_recents.py::test_tc_b100_34_a2l_found_only_through_the_fallback_is_not_recorded (+27) | Inc 9a |
| US-162 | HLR-172 | LLR-172.1e | TC-B100-34 | test_b100_recents.py::test_tc_b100_34_a2l_found_only_through_the_fallback_is_not_recorded (+27) | Inc 9a |
| US-162 | HLR-172 | LLR-172.1f | TC-B100-34 | test_b100_recents.py::test_tc_b100_34_a2l_found_only_through_the_fallback_is_not_recorded (+27) | Inc 9a |
| US-162 | HLR-172 | LLR-172.1g | TC-B100-34 | test_b100_recents.py::test_tc_b100_34_a2l_found_only_through_the_fallback_is_not_recorded (+27) | Inc 9a |
| US-162 | HLR-172 | LLR-172.1h | TC-B100-34 | test_b100_recents.py::test_tc_b100_34_a2l_found_only_through_the_fallback_is_not_recorded (+27) | Inc 9a |
| US-162 | HLR-172 | LLR-172.1i | TC-B100-34 | test_b100_recents.py::test_tc_b100_34_a2l_found_only_through_the_fallback_is_not_recorded (+27) | Inc 9a |
| US-162 | HLR-172 | LLR-172.1j | TC-B100-34 | test_b100_recents.py::test_tc_b100_34_a2l_found_only_through_the_fallback_is_not_recorded (+27) | Inc 9a |
| US-162 | HLR-172 | LLR-172.1k | TC-B100-34 | test_b100_recents.py::test_tc_b100_34_a2l_found_only_through_the_fallback_is_not_recorded (+27) | Inc 9a |
| US-162 | HLR-172 | LLR-172.1l | TC-B100-34 | test_b100_recents.py::test_tc_b100_34_a2l_found_only_through_the_fallback_is_not_recorded (+27) | Inc 9a |
| US-162 | HLR-172 | LLR-172.1m | TC-B100-34 | test_b100_recents.py::test_tc_b100_34_a2l_found_only_through_the_fallback_is_not_recorded (+27) | Inc 9a |
| US-162 | HLR-172 | LLR-172.1n | TC-B100-34 | test_b100_recents.py::test_tc_b100_34_a2l_found_only_through_the_fallback_is_not_recorded (+27) | Inc 9b |
| US-162 | HLR-172 | LLR-172.2 | TC-B100-35 | test_b100_recents.py::test_tc_b100_35_entry_path_checks_drop_entries (+10) | Inc 9a |
| US-162 | HLR-172 | LLR-172.2a | TC-B100-35 | test_b100_recents.py::test_tc_b100_35_entry_path_checks_drop_entries (+10) | Inc 9a |
| US-162 | HLR-172 | LLR-172.2b | TC-B100-35 | test_b100_recents.py::test_tc_b100_35_entry_path_checks_drop_entries (+10) | Inc 9a |
| US-162 | HLR-172 | LLR-172.2c | TC-B100-35 | test_b100_recents.py::test_tc_b100_35_entry_path_checks_drop_entries (+10) | Inc 9a |
| US-162 | HLR-172 | LLR-172.2d | TC-B100-35 | test_b100_recents.py::test_tc_b100_35_entry_path_checks_drop_entries (+10) | Inc 9a |
| US-162 | HLR-172 | LLR-172.2e | TC-B100-35 | test_b100_recents.py::test_tc_b100_35_entry_path_checks_drop_entries (+10) | Inc 9a |
| US-162 | HLR-172 | LLR-172.2f | TC-B100-35 | test_b100_recents.py::test_tc_b100_35_entry_path_checks_drop_entries (+10) | Inc 9a |
| US-162 | HLR-172 | LLR-172.2g | TC-B100-35 | test_b100_recents.py::test_tc_b100_35_entry_path_checks_drop_entries (+10) | Inc 9a |
| US-162 | HLR-172 | LLR-172.2h | TC-B100-35 | test_b100_recents.py::test_tc_b100_35_entry_path_checks_drop_entries (+10) | Inc 9a |
| US-162 | HLR-172 | LLR-172.2i | TC-B100-35 | test_b100_recents.py::test_tc_b100_35_entry_path_checks_drop_entries (+10) | Inc 9a |
| US-162 | HLR-172 | LLR-172.2j | TC-B100-35 | test_b100_recents.py::test_tc_b100_35_entry_path_checks_drop_entries (+10) | Inc 9a |
| US-162 | HLR-172 | LLR-172.2k | TC-B100-34, TC-B100-35 | test_b100_recents.py::test_tc_b100_34_a2l_found_only_through_the_fallback_is_not_recorded (+27) · test_b100_recents.py::test_tc_b100_35_entry_path_checks_drop_entries (+10) | Inc 9a |
| US-162 | HLR-172 | LLR-172.3 | TC-B100-36 | test_b100_recents.py::test_tc_b100_36_loaded_source_path_stays_out_of_project_files (+1) | Inc 9a |
| **HLR-172a — A typed project path opens the project (US-162)** |  |  |  |  |  |
| US-162 | HLR-172a | LLR-172.5 | TC-B100-38 | test_b100_recents.py::test_tc_b100_38_nul_in_typed_path_is_refused (+19) | Inc 9a |
| US-162 | HLR-172a | LLR-172.5a | TC-B100-38 | test_b100_recents.py::test_tc_b100_38_nul_in_typed_path_is_refused (+19) | Inc 9a |
| US-162 | HLR-172a | LLR-172.5b | TC-B100-38 | test_b100_recents.py::test_tc_b100_38_nul_in_typed_path_is_refused (+19) | Inc 9a |
| US-162 | HLR-172a | LLR-172.5c | TC-B100-38 | test_b100_recents.py::test_tc_b100_38_nul_in_typed_path_is_refused (+19) | Inc 9a |
| US-162 | HLR-172a | LLR-172.5d | TC-B100-38 | test_b100_recents.py::test_tc_b100_38_nul_in_typed_path_is_refused (+19) | Inc 9a |
| US-162 | HLR-172a | LLR-172.5e | TC-B100-38 | test_b100_recents.py::test_tc_b100_38_nul_in_typed_path_is_refused (+19) | Inc 9a |
| US-162 | HLR-172a | LLR-172.5f | TC-B100-38 | test_b100_recents.py::test_tc_b100_38_nul_in_typed_path_is_refused (+19) | Inc 9a |
| US-162 | HLR-172a | LLR-172.5g | TC-B100-38 | test_b100_recents.py::test_tc_b100_38_nul_in_typed_path_is_refused (+19) | Inc 9a |
| US-162 | HLR-172a | LLR-172.5h | TC-B100-38 | test_b100_recents.py::test_tc_b100_38_nul_in_typed_path_is_refused (+19) | Inc 9a |
| US-162 | HLR-172a | LLR-172.5i | TC-B100-38 | test_b100_recents.py::test_tc_b100_38_nul_in_typed_path_is_refused (+19) | Inc 12a |
| US-162 | HLR-172a | LLR-172.5j | TC-B100-38 | test_b100_recents.py::test_tc_b100_38_nul_in_typed_path_is_refused (+19) | Inc 12a |
| US-162 | HLR-172a | LLR-172.5k | TC-B100-38, TC-B100-63 | test_b100_recents.py::test_tc_b100_38_nul_in_typed_path_is_refused (+19) · test_b100_load_dialog.py::test_tc_b100_63_folder_named_like_a_data_file (+10) | Inc 12a |
| **HLR-172b — Work-area file names render literally (US-162)** |  |  |  |  |  |
| US-162 | HLR-172b | LLR-172.4 | TC-B100-37 | test_b100_recents.py::test_tc_b100_37_file_link_in_temp_is_not_listed (+11) | Inc 9a |
| US-162 | HLR-172b | LLR-172.4a | TC-B100-37 | test_b100_recents.py::test_tc_b100_37_file_link_in_temp_is_not_listed (+11) | Inc 9a |
| US-162 | HLR-172b | LLR-172.4b | TC-B100-37 | test_b100_recents.py::test_tc_b100_37_file_link_in_temp_is_not_listed (+11) | Inc 9a |
| US-162 | HLR-172b | LLR-172.4c | TC-B100-37 | test_b100_recents.py::test_tc_b100_37_file_link_in_temp_is_not_listed (+11) | Inc 9a |
| US-162 | HLR-172b | LLR-172.4d | TC-B100-37 | test_b100_recents.py::test_tc_b100_37_file_link_in_temp_is_not_listed (+11) | Inc 9a |
| US-162 | HLR-172b | LLR-172.4e | TC-B100-37 | test_b100_recents.py::test_tc_b100_37_file_link_in_temp_is_not_listed (+11) | Inc 12a |
| US-162 | HLR-172b | LLR-172.4f | TC-B100-37 | test_b100_recents.py::test_tc_b100_37_file_link_in_temp_is_not_listed (+11) | Inc 12a |
| US-162 | HLR-172b | LLR-172.6 | TC-B100-39 | test_b100_recents.py::test_tc_b100_39_pick_of_a_reparse_point_file_is_refused (+8) | Inc 9a |
| US-162 | HLR-172b | LLR-172.6a | TC-B100-39 | test_b100_recents.py::test_tc_b100_39_pick_of_a_reparse_point_file_is_refused (+8) | Inc 9a |
| US-162 | HLR-172b | LLR-172.6b | TC-B100-39 | test_b100_recents.py::test_tc_b100_39_pick_of_a_reparse_point_file_is_refused (+8) | Inc 12a |
| US-162 | HLR-172b | LLR-172.6c | TC-B100-39 | test_b100_recents.py::test_tc_b100_39_pick_of_a_reparse_point_file_is_refused (+8) | Inc 12a |
| **HLR-173 — One Load dialog lists everything that can be loaded (US-163)** |  |  |  |  |  |
| US-163 | HLR-173 | LLR-173.1 | TC-B100-40 | test_b100_load_dialog.py::test_tc_b100_40_a2l_status_line_paints_the_name_scrubbed (+10) | Inc 9b |
| US-163 | HLR-173 | LLR-173.1e | TC-B100-40 | test_b100_load_dialog.py::test_tc_b100_40_a2l_status_line_paints_the_name_scrubbed (+10) | Inc 9b |
| US-163 | HLR-173 | LLR-173.1g | TC-B100-40 | test_b100_load_dialog.py::test_tc_b100_40_a2l_status_line_paints_the_name_scrubbed (+10) | Inc 9b |
| US-163 | HLR-173 | LLR-173.2 | TC-B100-41 | test_b100_load_dialog.py::test_tc_b100_41_alt_l_with_the_focus_on_the_path_field_loads_and_types_nothing (+27) | Inc 9b |
| US-163 | HLR-173 | LLR-173.2a | TC-B100-41 | test_b100_load_dialog.py::test_tc_b100_41_alt_l_with_the_focus_on_the_path_field_loads_and_types_nothing (+27) | Inc 9b |
| US-163 | HLR-173 | LLR-173.2b | TC-B100-41 | test_b100_load_dialog.py::test_tc_b100_41_alt_l_with_the_focus_on_the_path_field_loads_and_types_nothing (+27) | Inc 9b |
| US-163 | HLR-173 | LLR-173.2c | TC-B100-41 | test_b100_load_dialog.py::test_tc_b100_41_alt_l_with_the_focus_on_the_path_field_loads_and_types_nothing (+27) | Inc 9b |
| US-163 | HLR-173 | LLR-173.2d | TC-B100-41 | test_b100_load_dialog.py::test_tc_b100_41_alt_l_with_the_focus_on_the_path_field_loads_and_types_nothing (+27) | Inc 9b |
| US-163 | HLR-173 | LLR-173.2e | TC-B100-41 | test_b100_load_dialog.py::test_tc_b100_41_alt_l_with_the_focus_on_the_path_field_loads_and_types_nothing (+27) | Inc 9b |
| US-163 | HLR-173 | LLR-173.2j | TC-B100-41 | test_b100_load_dialog.py::test_tc_b100_41_alt_l_with_the_focus_on_the_path_field_loads_and_types_nothing (+27) | Inc 9b |
| US-163 | HLR-173 | LLR-173.2m | TC-B100-41 | test_b100_load_dialog.py::test_tc_b100_41_alt_l_with_the_focus_on_the_path_field_loads_and_types_nothing (+27) | Inc 12a |
| US-163 | HLR-173 | LLR-173.3 | TC-B100-42 | test_b100_load_dialog.py::test_tc_b100_42_a_pick_loads_the_on_disk_name (+4) | Inc 9b |
| US-163 | HLR-173 | LLR-173.3a | TC-B100-42 | test_b100_load_dialog.py::test_tc_b100_42_a_pick_loads_the_on_disk_name (+4) | Inc 9b |
| US-163 | HLR-173 | LLR-173.3b | TC-B100-42 | test_b100_load_dialog.py::test_tc_b100_42_a_pick_loads_the_on_disk_name (+4) | Inc 9b |
| US-163 | HLR-173 | LLR-173.3c | TC-B100-42 | test_b100_load_dialog.py::test_tc_b100_42_a_pick_loads_the_on_disk_name (+4) | Inc 9b |
| US-163 | HLR-173 | LLR-173.3d | TC-B100-42 | test_b100_load_dialog.py::test_tc_b100_42_a_pick_loads_the_on_disk_name (+4) | Inc 9b |
| US-163 | HLR-173 | LLR-173.4 | TC-B100-43 | test_b100_load_dialog.py::test_tc_b100_43_a_folder_that_is_not_a_project_is_not_listed (+13) | Inc 9b |
| US-163 | HLR-173 | LLR-173.4a | TC-B100-43 | test_b100_load_dialog.py::test_tc_b100_43_a_folder_that_is_not_a_project_is_not_listed (+13) | Inc 9b |
| US-163 | HLR-173 | LLR-173.4b | TC-B100-37, TC-B100-43 | test_b100_recents.py::test_tc_b100_37_file_link_in_temp_is_not_listed (+11) · test_b100_load_dialog.py::test_tc_b100_43_a_folder_that_is_not_a_project_is_not_listed (+13) | Inc 9b |
| US-163 | HLR-173 | LLR-173.4c | TC-B100-43 | test_b100_load_dialog.py::test_tc_b100_43_a_folder_that_is_not_a_project_is_not_listed (+13) | Inc 9b |
| US-163 | HLR-173 | LLR-173.4d | TC-B100-43 | test_b100_load_dialog.py::test_tc_b100_43_a_folder_that_is_not_a_project_is_not_listed (+13) | Inc 9b |
| US-163 | HLR-173 | LLR-173.4e | TC-B100-43 | test_b100_load_dialog.py::test_tc_b100_43_a_folder_that_is_not_a_project_is_not_listed (+13) | Inc 9b |
| US-163 | HLR-173 | LLR-173.4f | TC-B100-43 | test_b100_load_dialog.py::test_tc_b100_43_a_folder_that_is_not_a_project_is_not_listed (+13) | Inc 9b |
| US-163 | HLR-173 | LLR-173.4g | TC-B100-43 | test_b100_load_dialog.py::test_tc_b100_43_a_folder_that_is_not_a_project_is_not_listed (+13) | Inc 9b |
| US-163 | HLR-173 | LLR-173.4l | TC-B100-43 | test_b100_load_dialog.py::test_tc_b100_43_a_folder_that_is_not_a_project_is_not_listed (+13) | Inc 9b |
| US-163 | HLR-173 | LLR-173.4m | TC-B100-43 | test_b100_load_dialog.py::test_tc_b100_43_a_folder_that_is_not_a_project_is_not_listed (+13) | Inc 9b |
| US-163 | HLR-173 | LLR-173.6d | TC-B100-64 | test_b100_load_dialog.py::test_tc_b100_64_a_load_that_installs_another_variant_names_it (+17) | Inc 9b |
| US-163 | HLR-173 | LLR-173.6f | TC-B100-64 | test_b100_load_dialog.py::test_tc_b100_64_a_load_that_installs_another_variant_names_it (+17) | Inc 9b |
| US-163 | HLR-173 | LLR-173.6k | TC-B100-64 | test_b100_load_dialog.py::test_tc_b100_64_a_load_that_installs_another_variant_names_it (+17) | Inc 9b |
| US-163 | HLR-173 | LLR-173.6l | TC-B100-64 | test_b100_load_dialog.py::test_tc_b100_64_a_load_that_installs_another_variant_names_it (+17) | Inc 9b |
| US-163 | HLR-173 | LLR-173.6m | TC-B100-64 | test_b100_load_dialog.py::test_tc_b100_64_a_load_that_installs_another_variant_names_it (+17) | Inc 9b |
| US-163 | HLR-173 | LLR-173.6n | TC-B100-64 | test_b100_load_dialog.py::test_tc_b100_64_a_load_that_installs_another_variant_names_it (+17) | Inc 9b |
| US-163 | HLR-173 | LLR-173.7 | TC-B100-66 | test_b100_load_question.py::test_tc_b100_66_busy_line_and_quit_question_hold_no_decision_ids (+5) | Inc 9b |
| **HLR-173a — The preview marks the set a load installs (US-163)** |  |  |  |  |  |
| US-163 | HLR-173a | LLR-173.4n | TC-B100-64 | test_b100_load_dialog.py::test_tc_b100_64_a_load_that_installs_another_variant_names_it (+17) | Inc 9b |
| US-163 | HLR-173a | LLR-173.6 | TC-B100-64 | test_b100_load_dialog.py::test_tc_b100_64_a_load_that_installs_another_variant_names_it (+17) | Inc 9b |
| US-163 | HLR-173a | LLR-173.6a | TC-B100-64 | test_b100_load_dialog.py::test_tc_b100_64_a_load_that_installs_another_variant_names_it (+17) | Inc 9b |
| US-163 | HLR-173a | LLR-173.6b | TC-B100-64 | test_b100_load_dialog.py::test_tc_b100_64_a_load_that_installs_another_variant_names_it (+17) | Inc 9b |
| US-163 | HLR-173a | LLR-173.6c | TC-B100-64 | test_b100_load_dialog.py::test_tc_b100_64_a_load_that_installs_another_variant_names_it (+17) | Inc 9b |
| **HLR-173b — A recent source reopens from the dialog (US-163)** |  |  |  |  |  |
| US-163 | HLR-173b | LLR-173.1f | TC-B100-40 | test_b100_load_dialog.py::test_tc_b100_40_a2l_status_line_paints_the_name_scrubbed (+10) | Inc 9b |
| US-163 | HLR-173b | LLR-173.4h | TC-B100-43 | test_b100_load_dialog.py::test_tc_b100_43_a_folder_that_is_not_a_project_is_not_listed (+13) | Inc 9b |
| US-163 | HLR-173b | LLR-173.4i | TC-B100-43 | test_b100_load_dialog.py::test_tc_b100_43_a_folder_that_is_not_a_project_is_not_listed (+13) | Inc 9b |
| US-163 | HLR-173b | LLR-173.4j | TC-B100-43 | test_b100_load_dialog.py::test_tc_b100_43_a_folder_that_is_not_a_project_is_not_listed (+13) | Inc 9b |
| US-163 | HLR-173b | LLR-173.4k | TC-B100-43 | test_b100_load_dialog.py::test_tc_b100_43_a_folder_that_is_not_a_project_is_not_listed (+13) | Inc 9b |
| **HLR-173c — Enter loads what has the focus (US-163)** |  |  |  |  |  |
| US-163 | HLR-173c | LLR-173.1a | TC-B100-40 | test_b100_load_dialog.py::test_tc_b100_40_a2l_status_line_paints_the_name_scrubbed (+10) | Inc 9b |
| US-163 | HLR-173c | LLR-173.1b | TC-B100-40 | test_b100_load_dialog.py::test_tc_b100_40_a2l_status_line_paints_the_name_scrubbed (+10) | Inc 9b |
| US-163 | HLR-173c | LLR-173.1c | TC-B100-40 | test_b100_load_dialog.py::test_tc_b100_40_a2l_status_line_paints_the_name_scrubbed (+10) | Inc 9b |
| US-163 | HLR-173c | LLR-173.2f | TC-B100-41 | test_b100_load_dialog.py::test_tc_b100_41_alt_l_with_the_focus_on_the_path_field_loads_and_types_nothing (+27) | Inc 9b |
| US-163 | HLR-173c | LLR-173.2g | TC-B100-41 | test_b100_load_dialog.py::test_tc_b100_41_alt_l_with_the_focus_on_the_path_field_loads_and_types_nothing (+27) | Inc 9b |
| **HLR-173d — An empty or refused Load is explained inside the dialog (US-163)** |  |  |  |  |  |
| US-163 | HLR-173d | LLR-173.2h | TC-B100-41 | test_b100_load_dialog.py::test_tc_b100_41_alt_l_with_the_focus_on_the_path_field_loads_and_types_nothing (+27) | Inc 9b |
| US-163 | HLR-173d | LLR-173.2i | TC-B100-41 | test_b100_load_dialog.py::test_tc_b100_41_alt_l_with_the_focus_on_the_path_field_loads_and_types_nothing (+27) | Inc 9b |
| US-163 | HLR-173d | LLR-173.5 | TC-B100-63 | test_b100_load_dialog.py::test_tc_b100_63_folder_named_like_a_data_file (+10) | Inc 9b |
| US-163 | HLR-173d | LLR-173.5a | TC-B100-63 | test_b100_load_dialog.py::test_tc_b100_63_folder_named_like_a_data_file (+10) | Inc 9b |
| US-163 | HLR-173d | LLR-173.5b | TC-B100-63 | test_b100_load_dialog.py::test_tc_b100_63_folder_named_like_a_data_file (+10) | Inc 9b |
| US-163 | HLR-173d | LLR-173.5c | TC-B100-63 | test_b100_load_dialog.py::test_tc_b100_63_folder_named_like_a_data_file (+10) | Inc 9b |
| US-163 | HLR-173d | LLR-173.5d | TC-B100-63 | test_b100_load_dialog.py::test_tc_b100_63_folder_named_like_a_data_file (+10) | Inc 9b |
| US-163 | HLR-173d | LLR-173.5e | TC-B100-63 | test_b100_load_dialog.py::test_tc_b100_63_folder_named_like_a_data_file (+10) | Inc 9b |
| **HLR-173e — `escape` closes the dialog and changes nothing (US-163)** |  |  |  |  |  |
| US-163 | HLR-173e | LLR-173.2k | TC-B100-41 | test_b100_load_dialog.py::test_tc_b100_41_alt_l_with_the_focus_on_the_path_field_loads_and_types_nothing (+27) | Inc 9b |
| US-163 | HLR-173e | LLR-173.2l | TC-B100-41 | test_b100_load_dialog.py::test_tc_b100_41_alt_l_with_the_focus_on_the_path_field_loads_and_types_nothing (+27) | Inc 9b |
| **HLR-174 — One question before an image-replacing route replaces unsaved work (US-164)** |  |  |  |  |  |
| US-164 | HLR-174 | LLR-174.1 | TC-B100-44 | test_b100_load_question.py::test_tc_b100_44_attach_asks_nothing_and_keeps_the_patch (+7) | Inc 10 |
| US-164 | HLR-174 | LLR-174.1b | TC-B100-44 | test_b100_load_question.py::test_tc_b100_44_attach_asks_nothing_and_keeps_the_patch (+7) | Inc 10 |
| US-164 | HLR-174 | LLR-174.1c | TC-B100-44 | test_b100_load_question.py::test_tc_b100_44_attach_asks_nothing_and_keeps_the_patch (+7) | Inc 10 |
| US-164 | HLR-174 | LLR-174.2 | TC-B100-45 | test_b100_load_question.py::test_tc_b100_45_a_second_answer_is_ignored (+21) | Inc 10 |
| US-164 | HLR-174 | LLR-174.2a | TC-B100-45 | test_b100_load_question.py::test_tc_b100_45_a_second_answer_is_ignored (+21) | Inc 10 |
| US-164 | HLR-174 | LLR-174.2g | TC-B100-45 | test_b100_load_question.py::test_tc_b100_45_a_second_answer_is_ignored (+21) | Inc 10 |
| US-164 | HLR-174 | LLR-174.2h | TC-B100-45 | test_b100_load_question.py::test_tc_b100_45_a_second_answer_is_ignored (+21) | Inc 10 |
| US-164 | HLR-174 | LLR-174.2j | TC-B100-45 | test_b100_load_question.py::test_tc_b100_45_a_second_answer_is_ignored (+21) | Inc 10 |
| US-164 | HLR-174 | LLR-174.2r | TC-B100-45 | test_b100_load_question.py::test_tc_b100_45_a_second_answer_is_ignored (+21) | Inc 10 |
| US-164 | HLR-174 | LLR-174.2s | TC-B100-45 | test_b100_load_question.py::test_tc_b100_45_a_second_answer_is_ignored (+21) | Inc 10 |
| US-164 | HLR-174 | LLR-174.2t | TC-B100-45 | test_b100_load_question.py::test_tc_b100_45_a_second_answer_is_ignored (+21) | Inc 10 |
| US-164 | HLR-174 | LLR-174.3b | TC-B100-46 | test_b100_load_question.py::test_tc_b100_46_cancel_keeps_the_session_and_runs_no_reset (+7) | Inc 10 |
| US-164 | HLR-174 | LLR-174.4 | TC-B100-72 | test_b100_load_question.py::test_tc_b100_72_every_load_call_passes_the_seam (+7) | Inc 10 |
| US-164 | HLR-174 | LLR-174.4a | TC-B100-72 | test_b100_load_question.py::test_tc_b100_72_every_load_call_passes_the_seam (+7) | Inc 10 |
| US-164 | HLR-174 | LLR-174.4b | TC-B100-72 | test_b100_load_question.py::test_tc_b100_72_every_load_call_passes_the_seam (+7) | Inc 10 |
| US-164 | HLR-174 | LLR-174.4c | TC-B100-72 | test_b100_load_question.py::test_tc_b100_72_every_load_call_passes_the_seam (+7) | Inc 10 |
| **HLR-174a — A load that would replace or move no unsaved work does not ask (US-164)** |  |  |  |  |  |
| US-164 | HLR-174a | LLR-174.1a | TC-B100-44 | test_b100_load_question.py::test_tc_b100_44_attach_asks_nothing_and_keeps_the_patch (+7) | Inc 10 |
| **HLR-174b — Replace continues the load (US-164)** |  |  |  |  |  |
| US-164 | HLR-174b | LLR-174.2c | TC-B100-45 | test_b100_load_question.py::test_tc_b100_45_a_second_answer_is_ignored (+21) | Inc 10 |
| US-164 | HLR-174b | LLR-174.2e | TC-B100-45 | test_b100_load_question.py::test_tc_b100_45_a_second_answer_is_ignored (+21) | Inc 10 |
| US-164 | HLR-174b | LLR-174.2f | TC-B100-45 | test_b100_load_question.py::test_tc_b100_45_a_second_answer_is_ignored (+21) | Inc 10 |
| US-164 | HLR-174b | LLR-174.2p | TC-B100-45 | test_b100_load_question.py::test_tc_b100_45_a_second_answer_is_ignored (+21) | Inc 10 |
| US-164 | HLR-174b | LLR-174.3 | TC-B100-46 | test_b100_load_question.py::test_tc_b100_46_cancel_keeps_the_session_and_runs_no_reset (+7) | Inc 10 |
| US-164 | HLR-174b | LLR-174.3c | TC-B100-46 | test_b100_load_question.py::test_tc_b100_46_cancel_keeps_the_session_and_runs_no_reset (+7) | Inc 10 |
| **HLR-174c — Cancel keeps everything (US-164)** |  |  |  |  |  |
| US-164 | HLR-174c | LLR-174.2b | TC-B100-45 | test_b100_load_question.py::test_tc_b100_45_a_second_answer_is_ignored (+21) | Inc 10 |
| US-164 | HLR-174c | LLR-174.2d | TC-B100-45 | test_b100_load_question.py::test_tc_b100_45_a_second_answer_is_ignored (+21) | Inc 10 |
| US-164 | HLR-174c | LLR-174.3a | TC-B100-46 | test_b100_load_question.py::test_tc_b100_46_cancel_keeps_the_session_and_runs_no_reset (+7) | Inc 10 |
| US-164 | HLR-174c | LLR-174.3d | TC-B100-46 | test_b100_load_question.py::test_tc_b100_46_cancel_keeps_the_session_and_runs_no_reset (+7) | Inc 10 |
| **HLR-174d — The question names every unsaved item (US-164)** |  |  |  |  |  |
| US-164 | HLR-174d | LLR-174.2i | TC-B100-45 | test_b100_load_question.py::test_tc_b100_45_a_second_answer_is_ignored (+21) | Inc 10 |
| US-164 | HLR-174d | LLR-174.2k | TC-B100-45 | test_b100_load_question.py::test_tc_b100_45_a_second_answer_is_ignored (+21) | Inc 10 |
| US-164 | HLR-174d | LLR-174.2l | TC-B100-45 | test_b100_load_question.py::test_tc_b100_45_a_second_answer_is_ignored (+21) | Inc 10 |
| US-164 | HLR-174d | LLR-174.2m | TC-B100-45 | test_b100_load_question.py::test_tc_b100_45_a_second_answer_is_ignored (+21) | Inc 10 |
| US-164 | HLR-174d | LLR-174.2n | TC-B100-45 | test_b100_load_question.py::test_tc_b100_45_a_second_answer_is_ignored (+21) | Inc 10 |
| US-164 | HLR-174d | LLR-174.2o | TC-B100-45 | test_b100_load_question.py::test_tc_b100_45_a_second_answer_is_ignored (+21) | Inc 10 |
| US-164 | HLR-174d | LLR-174.2q | TC-B100-45 | test_b100_load_question.py::test_tc_b100_45_a_second_answer_is_ignored (+21) | Inc 10 |
| **HLR-175 — The Save project dialog shows exactly what the save will do (US-165)** |  |  |  |  |  |
| US-165 | HLR-175 | LLR-175.1 | TC-B100-47 | test_b100_save_dialog.py::test_tc_b100_47_blocked_entries_painted_with_addresses (+20) | Inc 11 |
| US-165 | HLR-175 | LLR-175.4 | TC-B100-65 | test_b100_save_dialog.py::test_tc_b100_65_a_change_before_the_first_preview_starts_no_recompute (+38) | Inc 11 |
| US-165 | HLR-175 | LLR-175.4c | TC-B100-65 | test_b100_save_dialog.py::test_tc_b100_65_a_change_before_the_first_preview_starts_no_recompute (+38) | Inc 11 |
| US-165 | HLR-175 | LLR-175.4d | TC-B100-65 | test_b100_save_dialog.py::test_tc_b100_65_a_change_before_the_first_preview_starts_no_recompute (+38) | Inc 11 |
| US-165 | HLR-175 | LLR-175.4e | TC-B100-65 | test_b100_save_dialog.py::test_tc_b100_65_a_change_before_the_first_preview_starts_no_recompute (+38) | Inc 11 |
| US-165 | HLR-175 | LLR-175.4f | TC-B100-65 | test_b100_save_dialog.py::test_tc_b100_65_a_change_before_the_first_preview_starts_no_recompute (+38) | Inc 11 |
| US-165 | HLR-175 | LLR-175.4g | TC-B100-65 | test_b100_save_dialog.py::test_tc_b100_65_a_change_before_the_first_preview_starts_no_recompute (+38) | Inc 11 |
| US-165 | HLR-175 | LLR-175.4j | TC-B100-65 | test_b100_save_dialog.py::test_tc_b100_65_a_change_before_the_first_preview_starts_no_recompute (+38) | Inc 11 |
| US-165 | HLR-175 | LLR-175.5 | TC-B100-65 | test_b100_save_dialog.py::test_tc_b100_65_a_change_before_the_first_preview_starts_no_recompute (+38) | Inc 11 |
| US-165 | HLR-175 | LLR-175.5a | TC-B100-65 | test_b100_save_dialog.py::test_tc_b100_65_a_change_before_the_first_preview_starts_no_recompute (+38) | Inc 11 |
| **HLR-175a — Save writes exactly the plan the dialog painted (US-165)** |  |  |  |  |  |
| US-165 | HLR-175a | LLR-175.3c | TC-B100-49 | test_b100_save_dialog.py::test_tc_b100_49_an_a2l_alone_opens_the_dialog (+14) | Inc 11 |
| US-165 | HLR-175a | LLR-175.4a | TC-B100-65 | test_b100_save_dialog.py::test_tc_b100_65_a_change_before_the_first_preview_starts_no_recompute (+38) | Inc 11 |
| US-165 | HLR-175a | LLR-175.4b | TC-B100-65 | test_b100_save_dialog.py::test_tc_b100_65_a_change_before_the_first_preview_starts_no_recompute (+38) | Inc 11 |
| US-165 | HLR-175a | LLR-175.4k | TC-B100-65 | test_b100_save_dialog.py::test_tc_b100_65_a_change_before_the_first_preview_starts_no_recompute (+38) | Inc 11 |
| US-165 | HLR-175a | LLR-175.4l | TC-B100-65 | test_b100_save_dialog.py::test_tc_b100_65_a_change_before_the_first_preview_starts_no_recompute (+38) | Inc 11 |
| US-165 | HLR-175a | LLR-175.4m | TC-B100-65 | test_b100_save_dialog.py::test_tc_b100_65_a_change_before_the_first_preview_starts_no_recompute (+38) | Inc 11 |
| **HLR-175b — A refused name is explained in the dialog before Save (US-165)** |  |  |  |  |  |
| US-165 | HLR-175b | LLR-175.1a | TC-B100-47 | test_b100_save_dialog.py::test_tc_b100_47_blocked_entries_painted_with_addresses (+20) | Inc 11 |
| US-165 | HLR-175b | LLR-175.1b | TC-B100-47 | test_b100_save_dialog.py::test_tc_b100_47_blocked_entries_painted_with_addresses (+20) | Inc 11 |
| US-165 | HLR-175b | LLR-175.1c | TC-B100-47 | test_b100_save_dialog.py::test_tc_b100_47_blocked_entries_painted_with_addresses (+20) | Inc 11 |
| US-165 | HLR-175b | LLR-175.1d | TC-B100-47 | test_b100_save_dialog.py::test_tc_b100_47_blocked_entries_painted_with_addresses (+20) | Inc 11 |
| US-165 | HLR-175b | LLR-175.1e | TC-B100-47 | test_b100_save_dialog.py::test_tc_b100_47_blocked_entries_painted_with_addresses (+20) | Inc 11 |
| US-165 | HLR-175b | LLR-175.1f | TC-B100-47 | test_b100_save_dialog.py::test_tc_b100_47_blocked_entries_painted_with_addresses (+20) | Inc 11 |
| US-165 | HLR-175b | LLR-175.1g | TC-B100-47 | test_b100_save_dialog.py::test_tc_b100_47_blocked_entries_painted_with_addresses (+20) | Inc 11 |
| US-165 | HLR-175b | LLR-175.1h | TC-B100-47 | test_b100_save_dialog.py::test_tc_b100_47_blocked_entries_painted_with_addresses (+20) | Inc 11 |
| US-165 | HLR-175b | LLR-175.1i | TC-B100-47 | test_b100_save_dialog.py::test_tc_b100_47_blocked_entries_painted_with_addresses (+20) | Inc 11 |
| US-165 | HLR-175b | LLR-175.1j | TC-B100-47 | test_b100_save_dialog.py::test_tc_b100_47_blocked_entries_painted_with_addresses (+20) | Inc 11 |
| US-165 | HLR-175b | LLR-175.1k | TC-B100-47 | test_b100_save_dialog.py::test_tc_b100_47_blocked_entries_painted_with_addresses (+20) | Inc 11 |
| US-165 | HLR-175b | LLR-175.1l | TC-B100-47 | test_b100_save_dialog.py::test_tc_b100_47_blocked_entries_painted_with_addresses (+20) | Inc 11 |
| US-165 | HLR-175b | LLR-175.1m | TC-B100-47 | test_b100_save_dialog.py::test_tc_b100_47_blocked_entries_painted_with_addresses (+20) | Inc 11 |
| US-165 | HLR-175b | LLR-175.1o | TC-B100-47 | test_b100_save_dialog.py::test_tc_b100_47_blocked_entries_painted_with_addresses (+20) | Inc 11 |
| US-165 | HLR-175b | LLR-175.1p | TC-B100-47 | test_b100_save_dialog.py::test_tc_b100_47_blocked_entries_painted_with_addresses (+20) | Inc 11 |
| US-165 | HLR-175b | LLR-175.3f | TC-B100-49 | test_b100_save_dialog.py::test_tc_b100_49_an_a2l_alone_opens_the_dialog (+14) | Inc 11 |
| US-165 | HLR-175b | LLR-175.6 | TC-B100-47 | test_b100_save_dialog.py::test_tc_b100_47_blocked_entries_painted_with_addresses (+20) | Inc 11 |
| **HLR-175c — `escape` closes the dialog and saves nothing (US-165)** |  |  |  |  |  |
| US-165 | HLR-175c | LLR-175.3 | TC-B100-49 | test_b100_save_dialog.py::test_tc_b100_49_an_a2l_alone_opens_the_dialog (+14) | Inc 11 |
| US-165 | HLR-175c | LLR-175.3a | TC-B100-49 | test_b100_save_dialog.py::test_tc_b100_49_an_a2l_alone_opens_the_dialog (+14) | Inc 11 |
| **HLR-175d — An empty Save is explained in the dialog (US-165)** |  |  |  |  |  |
| US-165 | HLR-175d | LLR-175.3b | TC-B100-49 | test_b100_save_dialog.py::test_tc_b100_49_an_a2l_alone_opens_the_dialog (+14) | Inc 11 |
| **HLR-175e — The dialog saves only into this work area (US-165)** |  |  |  |  |  |
| US-165 | HLR-175e | LLR-175.2 | TC-B100-48 | test_b100_save_dialog.py::test_tc_b100_48_no_parent_field_and_no_browse (+1) | Inc 11 |
| US-165 | HLR-175e | LLR-175.2a | TC-B100-48 | test_b100_save_dialog.py::test_tc_b100_48_no_parent_field_and_no_browse (+1) | Inc 11 |
| **HLR-175f — Save project opens one dialog with the name, the summary and two buttons (US-165)** |  |  |  |  |  |
| US-165 | HLR-175f | LLR-175.3d | TC-B100-49 | test_b100_save_dialog.py::test_tc_b100_49_an_a2l_alone_opens_the_dialog (+14) | Inc 11 |
| US-165 | HLR-175f | LLR-175.3e | TC-B100-49 | test_b100_save_dialog.py::test_tc_b100_49_an_a2l_alone_opens_the_dialog (+14) | Inc 11 |
| US-165 | HLR-175f | LLR-175.3g | TC-B100-49 | test_b100_save_dialog.py::test_tc_b100_49_an_a2l_alone_opens_the_dialog (+14) | Inc 11 |
| US-165 | HLR-175f | LLR-175.3h | TC-B100-49 | test_b100_save_dialog.py::test_tc_b100_49_an_a2l_alone_opens_the_dialog (+14) | Inc 11 |
| US-165 | HLR-175f | LLR-175.3i | TC-B100-49 | test_b100_save_dialog.py::test_tc_b100_49_an_a2l_alone_opens_the_dialog (+14) | Inc 11 |
| US-165 | HLR-175f | LLR-175.3j | TC-B100-49 | test_b100_save_dialog.py::test_tc_b100_49_an_a2l_alone_opens_the_dialog (+14) | Inc 11 |
| US-165 | HLR-175f | LLR-175.4h | TC-B100-65 | test_b100_save_dialog.py::test_tc_b100_65_a_change_before_the_first_preview_starts_no_recompute (+38) | Inc 11 |
| US-165 | HLR-175f | LLR-175.4i | TC-B100-65 | test_b100_save_dialog.py::test_tc_b100_65_a_change_before_the_first_preview_starts_no_recompute (+38) | Inc 11 |
| US-165 | HLR-175f | LLR-175.5b | TC-B100-65 | test_b100_save_dialog.py::test_tc_b100_65_a_change_before_the_first_preview_starts_no_recompute (+38) | Inc 11 |
| **HLR-176 — A long action shows a progress line when it begins (US-166)** |  |  |  |  |  |
| US-166 | HLR-176 | LLR-176.1 | TC-B100-50 | test_b100_busy.py::test_tc_b100_50_a2l_deferred_install_raise_ends_the_run (+44) | Inc 12a |
| US-166 | HLR-176 | LLR-176.1a | TC-B100-50 | test_b100_busy.py::test_tc_b100_50_a2l_deferred_install_raise_ends_the_run (+44) | Inc 12a |
| US-166 | HLR-176 | LLR-176.1g | TC-B100-50 | test_b100_busy.py::test_tc_b100_50_a2l_deferred_install_raise_ends_the_run (+44) | Inc 12a |
| US-166 | HLR-176 | LLR-176.1n | TC-B100-50 | test_b100_busy.py::test_tc_b100_50_a2l_deferred_install_raise_ends_the_run (+44) | Inc 12a |
| US-166 | HLR-176 | LLR-176.1p | TC-B100-50 | test_b100_busy.py::test_tc_b100_50_a2l_deferred_install_raise_ends_the_run (+44) | Inc 12a |
| US-166 | HLR-176 | LLR-176.1r | TC-B100-50 | test_b100_busy.py::test_tc_b100_50_a2l_deferred_install_raise_ends_the_run (+44) | Inc 12a |
| US-166 | HLR-176 | LLR-176.1t | TC-B100-50 | test_b100_busy.py::test_tc_b100_50_a2l_deferred_install_raise_ends_the_run (+44) | Inc 12a |
| US-166 | HLR-176 | LLR-176.2 | TC-B100-51 | test_b100_busy.py::test_tc_b100_51_a2l_load_ends_once_on_a_containment_refusal (+27) | Inc 12a |
| US-166 | HLR-176 | LLR-176.2a | TC-B100-51 | test_b100_busy.py::test_tc_b100_51_a2l_load_ends_once_on_a_containment_refusal (+27) | Inc 12a |
| US-166 | HLR-176 | LLR-176.2b | TC-B100-51 | test_b100_busy.py::test_tc_b100_51_a2l_load_ends_once_on_a_containment_refusal (+27) | Inc 12a |
| US-166 | HLR-176 | LLR-176.3 | TC-B100-52 | test_b100_a2l_progress.py::test_tc_b100_52_a2l_tag_table_step_is_painted_before_the_build (+1) | Inc 12b |
| US-166 | HLR-176 | LLR-176.4 | TC-B100-73 | test_b100_a2l_progress.py::test_tc_b100_73_a2l_py_is_listed_in_the_frozen_engine_guard (+6) | Inc 12b |
| US-166 | HLR-176 | LLR-176.4a | TC-B100-73 | test_b100_a2l_progress.py::test_tc_b100_73_a2l_py_is_listed_in_the_frozen_engine_guard (+6) | Inc 12b |
| US-166 | HLR-176 | LLR-176.4b | TC-B100-73 | test_b100_a2l_progress.py::test_tc_b100_73_a2l_py_is_listed_in_the_frozen_engine_guard (+6) | Inc 12b |
| **HLR-176a — The spinner and the elapsed time advance while a worker runs (US-166)** |  |  |  |  |  |
| US-166 | HLR-176a | LLR-176.1e | TC-B100-50 | test_b100_busy.py::test_tc_b100_50_a2l_deferred_install_raise_ends_the_run (+44) | Inc 12a |
| US-166 | HLR-176a | LLR-176.1f | TC-B100-50 | test_b100_busy.py::test_tc_b100_50_a2l_deferred_install_raise_ends_the_run (+44) | Inc 12a |
| US-166 | HLR-176a | LLR-176.1q | TC-B100-50 | test_b100_busy.py::test_tc_b100_50_a2l_deferred_install_raise_ends_the_run (+44) | Inc 12a |
| **HLR-176b — The bar moves within a step that reports its progress (US-166)** |  |  |  |  |  |
| US-166 | HLR-176b | LLR-176.1b | TC-B100-50 | test_b100_busy.py::test_tc_b100_50_a2l_deferred_install_raise_ends_the_run (+44) | Inc 12a |
| US-166 | HLR-176b | LLR-176.1c | TC-B100-50 | test_b100_busy.py::test_tc_b100_50_a2l_deferred_install_raise_ends_the_run (+44) | Inc 12a |
| US-166 | HLR-176b | LLR-176.1d | TC-B100-50 | test_b100_busy.py::test_tc_b100_50_a2l_deferred_install_raise_ends_the_run (+44) | Inc 12a |
| **HLR-176c — The end of a long action removes the indicator and shows the outcome (US-166)** |  |  |  |  |  |
| US-166 | HLR-176c | LLR-176.1i | TC-B100-50 | test_b100_busy.py::test_tc_b100_50_a2l_deferred_install_raise_ends_the_run (+44) | Inc 12a |
| US-166 | HLR-176c | LLR-176.1j | TC-B100-50, TC-B100-56 | test_b100_busy.py::test_tc_b100_50_a2l_deferred_install_raise_ends_the_run (+44) · test_b100_announce.py::test_tc_b100_56_hostile_variant_name_paints_no_markup (+4) | Inc 12a |
| US-166 | HLR-176c | LLR-176.1k | TC-B100-50 | test_b100_busy.py::test_tc_b100_50_a2l_deferred_install_raise_ends_the_run (+44) | Inc 12a |
| US-166 | HLR-176c | LLR-176.1l | TC-B100-50 | test_b100_busy.py::test_tc_b100_50_a2l_deferred_install_raise_ends_the_run (+44) | Inc 12a |
| US-166 | HLR-176c | LLR-176.1m | TC-B100-50 | test_b100_busy.py::test_tc_b100_50_a2l_deferred_install_raise_ends_the_run (+44) | Inc 12a |
| US-166 | HLR-176c | LLR-176.1o | TC-B100-50 | test_b100_busy.py::test_tc_b100_50_a2l_deferred_install_raise_ends_the_run (+44) | Inc 12a |
| US-166 | HLR-176c | LLR-176.1s | TC-B100-50 | test_b100_busy.py::test_tc_b100_50_a2l_deferred_install_raise_ends_the_run (+44) | Inc 12a |
| US-166 | HLR-176c | LLR-176.2c | TC-B100-51 | test_b100_busy.py::test_tc_b100_51_a2l_load_ends_once_on_a_containment_refusal (+27) | Inc 12a |
| US-166 | HLR-176c | LLR-176.2d | TC-B100-51 | test_b100_busy.py::test_tc_b100_51_a2l_load_ends_once_on_a_containment_refusal (+27) | Inc 12a |
| **HLR-176d — `#status_text` has one owner while a long action runs (US-166)** |  |  |  |  |  |
| US-166 | HLR-176d | LLR-176.1h | TC-B100-50 | test_b100_busy.py::test_tc_b100_50_a2l_deferred_install_raise_ends_the_run (+44) | Inc 12a |
| **HLR-177 — Project load, Save project and the A2L parse do their heavy work on worker threads (US-167)** |  |  |  |  |  |
| US-167 | HLR-177 | LLR-177.1 | TC-B100-53 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| US-167 | HLR-177 | LLR-177.1a | TC-B100-53 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| US-167 | HLR-177 | LLR-177.1b | TC-B100-53 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| US-167 | HLR-177 | LLR-177.1c | TC-B100-53 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| US-167 | HLR-177 | LLR-177.1d | TC-B100-53 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| US-167 | HLR-177 | LLR-177.1e | TC-B100-53 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| US-167 | HLR-177 | LLR-177.1f | TC-B100-09, TC-B100-53 | test_b100_session_reset.py::test_tc_b100_09_domain_matches_the_live_source_census (+4) · test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| US-167 | HLR-177 | LLR-177.1g | TC-B100-08, TC-B100-53 | test_b100_session_reset.py::test_tc_b100_08_call_site_census (+3) · test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| US-167 | HLR-177 | LLR-177.1h | TC-B100-53 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| US-167 | HLR-177 | LLR-177.1i | TC-B100-53 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| US-167 | HLR-177 | LLR-177.1j | TC-B100-53 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| US-167 | HLR-177 | LLR-177.1k | TC-B100-53 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| US-167 | HLR-177 | LLR-177.2 | TC-B100-54 | test_b100_workers.py::test_tc_b100_54_a2l_attach_refuses_when_its_folder_or_file_vanished (+6) | Inc 12b |
| US-167 | HLR-177 | LLR-177.2a | TC-B100-54 | test_b100_workers.py::test_tc_b100_54_a2l_attach_refuses_when_its_folder_or_file_vanished (+6) | Inc 12b |
| US-167 | HLR-177 | LLR-177.2b | TC-B100-54 | test_b100_workers.py::test_tc_b100_54_a2l_attach_refuses_when_its_folder_or_file_vanished (+6) | Inc 12b |
| US-167 | HLR-177 | LLR-177.2c | TC-B100-54 | test_b100_workers.py::test_tc_b100_54_a2l_attach_refuses_when_its_folder_or_file_vanished (+6) | Inc 12b |
| US-167 | HLR-177 | LLR-177.5 | TC-B100-53 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| US-167 | HLR-177 | LLR-177.5a | TC-B100-53 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| **HLR-177a — A second request is refused while a session action runs (US-167)** |  |  |  |  |  |
| US-167 | HLR-177a | LLR-177.3 | TC-B100-53 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| US-167 | HLR-177a | LLR-177.3a | TC-B100-72 | test_b100_load_question.py::test_tc_b100_72_every_load_call_passes_the_seam (+7) | Inc 12b |
| US-167 | HLR-177a | LLR-177.3b | TC-B100-53 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| US-167 | HLR-177a | LLR-177.3c | TC-B100-53 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| US-167 | HLR-177a | LLR-177.3d | TC-B100-53 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| US-167 | HLR-177a | LLR-177.3e | TC-B100-53 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| US-167 | HLR-177a | LLR-177.3f | TC-B100-53, TC-B100-66 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) · test_b100_load_question.py::test_tc_b100_66_busy_line_and_quit_question_hold_no_decision_ids (+5) | Inc 12b |
| US-167 | HLR-177a | LLR-177.3g | TC-B100-53 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| US-167 | HLR-177a | LLR-177.3h | TC-B100-53 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| US-167 | HLR-177a | LLR-177.3i | TC-B100-53 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| **HLR-177b — Quit asks first while a session action runs (US-167)** |  |  |  |  |  |
| US-167 | HLR-177b | LLR-177.4 | TC-B100-53 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| US-167 | HLR-177b | LLR-177.4a | TC-B100-53, TC-B100-66 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) · test_b100_load_question.py::test_tc_b100_66_busy_line_and_quit_question_hold_no_decision_ids (+5) | Inc 12b |
| US-167 | HLR-177b | LLR-177.4b | TC-B100-53 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| US-167 | HLR-177b | LLR-177.4d | TC-B100-53 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| **HLR-177c — A confirmed quit leaves no partial save (US-167)** |  |  |  |  |  |
| US-167 | HLR-177c | LLR-177.4c | TC-B100-53 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| US-167 | HLR-177c | LLR-177.4e | TC-B100-53 | test_b100_workers.py::test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit (+48) | Inc 12b |
| **HLR-178 — The Load-result panel says which variant opened and lists the problems (US-168)** |  |  |  |  |  |
| US-168 | HLR-178 | LLR-178.1 | TC-B100-55 | test_b100_announce.py::test_tc_b100_55_boundaries_one_variant_and_no_image (+12) | Inc 6 |
| US-168 | HLR-178 | LLR-178.2 | TC-B100-56 | test_b100_announce.py::test_tc_b100_56_hostile_variant_name_paints_no_markup (+4) | Inc 6 |
| US-168 | HLR-178 | LLR-178.3 | TC-B100-67 | test_b100_announce.py::test_tc_b100_67_damaged_manifest_paints_user_terms_only (+12) | Inc 6 |

## 1c. Retired ids (listed once, not live)

| Id | What happened |
|----|---------------|
| LLR-171.2e | Retired — superseded by LLR-173.4a (Inc 9b, Q7; `Status: retired` in its block) |
| LLR-171.4d | Withdrawn — merged into LLR-171.4c (`01-requirements.md` §4) |

## 1b. Behavioral chain (black-box)

> One row per acceptance test (21 ATs). `Test (file::function)` is the file and first `test_at_b100_NN_*` function; AT-B100-17, -18 and -20 are split into named halves under one id. `Inc` is the increment the §5.3 AT-by-increment index records as *Written at*.

| US | AT | Test (file::function) | Inc |
|----|-----|----------------------|-----|
| US-153 | AT-B100-01 | test_b100_reuse.py::test_at_b100_01_repeated_loads_reuse_and_name_existing_variant | Inc 1 |
| US-154 | AT-B100-02 | test_b100_save_guards.py::test_at_b100_02_name_refusals_through_the_save_dialog | Inc 2 |
| US-155 | AT-B100-03 | test_b100_session_reset.py::test_at_b100_03_project_load_over_unsaved_work_saves_only_p2 | Inc 3 |
| US-156 | AT-B100-04 | test_b100_focus.py::test_at_b100_04_focus_lands_and_single_keys_reach_their_screens | Inc 4 |
| US-157 | AT-B100-05 | test_b100_save_image.py::test_at_b100_05_save_project_saves_the_patched_image | Inc 5 |
| US-158 | AT-B100-06 | test_b100_active_variant.py::test_at_b100_06_reopen_opens_the_saved_back_variant | Inc 6 |
| US-159 | AT-B100-07 | test_b100_project_check.py::test_at_b100_07_load_names_the_changed_file_and_the_hostile_record | Inc 7 |
| US-160 | AT-B100-08 | test_b100_document.py::test_at_b100_08_saved_document_reopens_with_the_project | Inc 8a |
| US-161 | AT-B100-09 | test_b100_project_homes.py::test_at_b100_09_save_as_copies_the_project_and_q_lists_its_flow | Inc 8b |
| US-161 | AT-B100-10 | test_b100_project_homes.py::test_at_b100_10_a2l_only_project_saves_and_reopens | Inc 8b |
| US-161 | AT-B100-11 | test_b100_project_homes.py::test_at_b100_11_junction_project_is_not_listed_and_save_refuses_it | Inc 8b |
| US-162 | AT-B100-12 | test_b100_recents.py::test_at_b100_12_outside_load_is_remembered_and_typed_project_path_opens | Inc 9a |
| US-162 | AT-B100-13 | test_b100_recents.py::test_at_b100_13_workarea_files_show_names_as_named | Inc 9a |
| US-163 | AT-B100-14 | test_b100_load_dialog.py::test_at_b100_14_one_load_dialog_from_record_to_reopen | Inc 9b |
| US-164 | AT-B100-15 | test_b100_load_question.py::test_at_b100_15_load_over_unsaved_work_asks_one_question_per_route | Inc 10 |
| US-165 | AT-B100-16 | test_b100_save_dialog.py::test_at_b100_16_save_dialog_open_folder_clash_empty_escape | Inc 11 |
| US-166 | AT-B100-17 | test_b100_workers.py::test_at_b100_17_parse_half_case06_a2l_by_keys (+1) | Inc 12a |
| US-167 | AT-B100-18 | test_b100_workers.py::test_at_b100_18_quit_confirm_half_slow_save_as_leaves_no_partial_folder (+3) | Inc 12b |
| US-168 | AT-B100-19 | test_b100_announce.py::test_at_b100_19_the_panel_names_the_opened_variant_and_why | Inc 6 |
| US-158 | AT-B100-20 | test_b100_active_variant.py::test_at_b100_20_every_writer_carries_the_keys_it_does_not_own (+1) | Inc 6 |
| US-165 | AT-B100-21 | test_b100_save_dialog.py::test_at_b100_21_painted_plan_is_the_saved_tree | Inc 11 |

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories | `16` (US-153…US-168) |
| Covered user stories | `16` (`100%`): every US has at least one passing AT and a complete functional chain |
| Total HLR | `42` (HLR-163…HLR-178) |
| Implemented HLR | `42` (`100%`) |
| Total LLR | `351` headings: `349` live + `2` retired (LLR-171.2e, LLR-171.4d) |
| Implemented LLR | `349` (`100%` of live) |
| Test cases | `73` ids (TC-B100-01…73); every one resolves to `test_tc_b100_NN_*` functions on the current tree |
| TC pass | `73` (every TC has an executed node per the packets and the two batch-end fix rounds) |
| TC fail | `0` |
| TC pending | `0` |
| Acceptance tests | `21` ids (AT-B100-01…21); every one resolves to `test_at_b100_NN_*` functions on the current tree |

> The pass/pending figures rest on the increment packets' executed transcripts and the two batch-end fix rounds (`fix-round-1.md`, `fix-round-2.md`). The final full-suite CI gate on `main` is still running at this writing; its result belongs on the `Gate run` line of `04-validation.md` (not owned by this artifact). `<!-- CI-FINAL -->`

## 3. Detected gaps

> **The requirement chain has no gap.** Every live US, HLR, LLR, TC and AT id appears once in §1 / §1b and resolves to a node on disk. `grep` finds every `test_tc_b100_NN_*` and `test_at_b100_NN_*` function; no named test function is missing. The rows below are record notes, not coverage gaps.

| ID | Type | Description | Proposed action |
|----|------|-------------|-----------------|
| R-1 | record note | LLR-163.3 / LLR-163.4 (G-005) carry no `TC-B100` id — they re-pin pre-batch nodes (`test_tc018_…`, `test_at031b_…`, `test_tc_b99_31_…` and the b94 re-pins). Both re-pinned functions exist and are named in §1. | — |
| R-2 | record note | Two LLRs are retired: LLR-171.4d (withdrawn, merged into LLR-171.4c) and LLR-171.2e (retired, superseded by LLR-173.4a in Inc 9b). Both are listed in §1c, not live. | — |
| R-3 | record note | The final full-suite CI gate on `main` is still running. | `<!-- CI-FINAL -->` — its result lands on `04-validation.md`'s `Gate run` line. |
| R-4 | record note | The batch-end battery (local, 4 shards on `9e4dd3b`) and the two fix rounds are the local evidence; the Linux posix arms of CI9b-3 / CI11-3 / CI11-1 are confirmed only by the next CI run (`fix-round-1.md` §Pending). | — |

**A worked example — text to read, never rows of your record:**

```text
| *(example)* G-001 | TC fail | TC-004 fails on condition X | See post-mortem phase 5 |
```

## 4. Changes from previous batch

*(Added, modified or closed since batch `2026-10-25-batch-99`, close commit `bf3917d`; batch base `1d677ba`.)*

| Type | Item | Detail |
|------|------|--------|
| new | US-153…US-168 · HLR-163…HLR-178 · 351 LLR headings (349 live + 2 retired) | the Load + projects requirement set (16 stories, 42 HLR, 73 TC, 21 AT) |
| new | one Load dialog (`HLR-173`, Inc 9b) | replaces the three dialogs `LoadFileScreen` / `LoadProjectScreen` / the variant list; `l`/`ctrl+l` open on the path field, `p` on the list, preview pane, Enter loads, `esc` closes |
| new | Save project dialog (`HLR-175`, Inc 11) | paints the plan before Save (what is emitted / copied / renamed / refused); no parent field; refusals in the dialog |
| new | load question (`HLR-174`, Inc 10) | one two-button modal before an image-replacing route would lose unsaved work |
| new | Load-result panel (`HLR-178`, Inc 6) | names the opened variant, why, and every problem |
| new | progress indicator and busy model (`HLR-176`, `HLR-177`, Inc 12a/12b) | spinner, step and elapsed time; project load / Save project / A2L parse on workers; busy refusal; quit question |
| new | byte-identical reuse (`HLR-163`, Inc 1) | one placement function `place_into_workarea` reuses identical files; G-005 re-pins |
| new | project round-trip fixes (PH-1, PH-2, PH-4, PH-5; M-1…M-7; L-2…L-4) | Save project saves the patched image; a load starts from an empty session; save-back becomes the active variant; Load lists every problem; save-as copies the whole project; recent sources; typed project path |
| new | 17 `tests/test_b100_*.py` files + `tests/support/b100_*.py` helpers | the batch-100 test set (the §5.2 map lists the id-bearing files) |
| closed | G-005 (batch-99 duplicate-name decision) | byte-identical reuse adopted, the two baseline tests re-pinned (LLR-163.3/163.4) |

## 5. Quick bidirectional mapping

### 5.1 By user story

- **US-153** → HLR-163 → 7 LLR → TC TC-B100-01, TC-B100-02, TC-B100-03, TC-B100-57, TC-B100-68 · AT AT-B100-01 (Inc 1)
- **US-154** → HLR-164 → 5 LLR → TC TC-B100-04, TC-B100-05, TC-B100-06, TC-B100-07, TC-B100-31 · AT AT-B100-02 (Inc 2)
- **US-155** → HLR-165 → 4 LLR → TC TC-B100-08, TC-B100-09, TC-B100-10, TC-B100-11 · AT AT-B100-03 (Inc 3)
- **US-156** → HLR-166 → 2 LLR → TC TC-B100-12, TC-B100-13 · AT AT-B100-04 (Inc 4)
- **US-157** → HLR-167 → 15 LLR → TC TC-B100-14, TC-B100-15, TC-B100-16, TC-B100-17, TC-B100-58, TC-B100-59, TC-B100-69, TC-B100-70 · AT AT-B100-05 (Inc 5)
- **US-158** → HLR-168 → 4 LLR → TC TC-B100-18, TC-B100-19, TC-B100-20, TC-B100-71 · AT AT-B100-06, AT-B100-20 (Inc 6)
- **US-159** → HLR-169 → 9 LLR → TC TC-B100-21, TC-B100-22, TC-B100-23, TC-B100-24, TC-B100-25, TC-B100-26, TC-B100-27, TC-B100-60, TC-B100-61 · AT AT-B100-07 (Inc 7)
- **US-160** → HLR-170 → 3 LLR → TC TC-B100-28, TC-B100-29, TC-B100-30 · AT AT-B100-08 (Inc 8a)
- **US-161** → HLR-171, HLR-171a, HLR-171b → 43 LLR → TC TC-B100-31, TC-B100-32, TC-B100-33, TC-B100-62 · AT AT-B100-09, AT-B100-10, AT-B100-11 (Inc 8b)
- **US-162** → HLR-172, HLR-172a, HLR-172b → 51 LLR → TC TC-B100-34, TC-B100-35, TC-B100-36, TC-B100-37, TC-B100-38, TC-B100-39, TC-B100-63 · AT AT-B100-12, AT-B100-13 (Inc 9a)
- **US-163** → HLR-173, HLR-173a, HLR-173b, HLR-173c, HLR-173d, HLR-173e → 58 LLR → TC TC-B100-37, TC-B100-40, TC-B100-41, TC-B100-42, TC-B100-43, TC-B100-63, TC-B100-64, TC-B100-66 · AT AT-B100-14 (Inc 9b)
- **US-164** → HLR-174, HLR-174a, HLR-174b, HLR-174c, HLR-174d → 34 LLR → TC TC-B100-44, TC-B100-45, TC-B100-46, TC-B100-72 · AT AT-B100-15 (Inc 10)
- **US-165** → HLR-175, HLR-175a, HLR-175b, HLR-175c, HLR-175d, HLR-175e, HLR-175f → 47 LLR → TC TC-B100-47, TC-B100-48, TC-B100-49, TC-B100-65 · AT AT-B100-02, AT-B100-16, AT-B100-21 (Inc 11)
- **US-166** → HLR-176, HLR-176a, HLR-176b, HLR-176c, HLR-176d → 30 LLR → TC TC-B100-50, TC-B100-51, TC-B100-52, TC-B100-56, TC-B100-73 · AT AT-B100-17 (Inc 12a)
- **US-167** → HLR-177, HLR-177a, HLR-177b, HLR-177c → 34 LLR → TC TC-B100-08, TC-B100-09, TC-B100-53, TC-B100-54, TC-B100-66, TC-B100-72 · AT AT-B100-18 (Inc 12b)
- **US-168** → HLR-178 → 3 LLR → TC TC-B100-55, TC-B100-56, TC-B100-67 · AT AT-B100-19

### 5.2 By test file

- `tests/test_b100_a2l_progress.py` → TC-B100-52, TC-B100-73
- `tests/test_b100_active_variant.py` → AT-B100-06, AT-B100-20, TC-B100-18, TC-B100-19, TC-B100-20, TC-B100-71
- `tests/test_b100_announce.py` → AT-B100-19, TC-B100-55, TC-B100-56, TC-B100-67
- `tests/test_b100_busy.py` → AT-B100-17, TC-B100-50, TC-B100-51, TC-B100-53
- `tests/test_b100_document.py` → AT-B100-08, TC-B100-28, TC-B100-29, TC-B100-30
- `tests/test_b100_focus.py` → AT-B100-04, TC-B100-12, TC-B100-13
- `tests/test_b100_load_dialog.py` → AT-B100-14, TC-B100-40, TC-B100-41, TC-B100-42, TC-B100-43, TC-B100-63, TC-B100-64, TC-B100-66
- `tests/test_b100_load_question.py` → AT-B100-15, TC-B100-12, TC-B100-44, TC-B100-45, TC-B100-46, TC-B100-66, TC-B100-70, TC-B100-72
- `tests/test_b100_project_check.py` → AT-B100-07, TC-B100-21, TC-B100-22, TC-B100-23, TC-B100-24, TC-B100-25, TC-B100-26, TC-B100-27, TC-B100-60, TC-B100-61, TC-B100-62
- `tests/test_b100_project_homes.py` → AT-B100-09, AT-B100-10, AT-B100-11, TC-B100-31, TC-B100-32, TC-B100-33, TC-B100-59, TC-B100-62
- `tests/test_b100_recents.py` → AT-B100-12, AT-B100-13, TC-B100-34, TC-B100-35, TC-B100-36, TC-B100-37, TC-B100-38, TC-B100-39
- `tests/test_b100_reuse.py` → AT-B100-01, TC-B100-01, TC-B100-02, TC-B100-03, TC-B100-57, TC-B100-62, TC-B100-68
- `tests/test_b100_save_dialog.py` → AT-B100-16, AT-B100-21, TC-B100-47, TC-B100-48, TC-B100-49, TC-B100-65, TC-B100-66
- `tests/test_b100_save_guards.py` → AT-B100-02, TC-B100-04, TC-B100-05, TC-B100-06, TC-B100-07
- `tests/test_b100_save_image.py` → AT-B100-05, TC-B100-14, TC-B100-15, TC-B100-16, TC-B100-17, TC-B100-58, TC-B100-59, TC-B100-69, TC-B100-70
- `tests/test_b100_session_reset.py` → AT-B100-03, TC-B100-08, TC-B100-09, TC-B100-10, TC-B100-11
- `tests/test_b100_workers.py` → AT-B100-17, AT-B100-18, TC-B100-53, TC-B100-54

The remaining `tests/test_b100_*.py` files and `tests/support/b100_*.py` helpers carry the re-pinned and regression nodes named in `01-requirements.md` §5.4 (the reverse census); they are listed there, not re-derived here.

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | `2026-10-26-batch-100` |
| Closing date | written 2026-11-01 (P5 commit `570b4b5` on `main`) |
| Total iterations (sum of phases) | from the record: P0 · ARQ · P1 · P2 (3 rounds) · PDR · a prototype round · 16 increment packets (001–007, 008a, 015, 008b, 009a, 009b, 010, 011, 012a, 012b) · two batch-end fix rounds |
| Validation passed | the final full-suite CI gate is still running — `<!-- CI-FINAL -->` |
| Synced to Obsidian | no — the operator commits, pushes and runs `/dev-flow-sync` |
