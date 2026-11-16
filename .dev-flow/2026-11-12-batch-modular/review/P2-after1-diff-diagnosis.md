# P2 — after1 full-suite diff diagnosis

Date: 2026-11-13. Scope: the 118 `B2` outcome diffs in `~/work/zq-mod/cmp1.txt` (BEFORE = base
4f721985 + tools; AFTER = b606ff6c), both full runs `pytest -n 12 --dist loadfile` on `<runner>`.
The 8 `B1` new ids (`tests/test_package_source_helper.py`) are expected and are not classified here.
Read-only diagnosis: no product, test or tool file in either tree was changed (`git status` clean in
both after the work). The experiments ran in a `/tmp` copy that was deleted afterwards.

## Verdict

| Class | Count |
|---|---|
| EXPECTED-P1C (hazards.md H-12) | 48 |
| FLAKY/LOAD | 13 |
| REGRESSION | 57 |
| **Total** | **118** |

All 57 regressions are **test-harness seam gaps**, not behaviour changes in the moved product code.
They have four root causes:

| Group | Root cause | Nodes | Owner |
|---|---|---|---|
| RC-A | `Hold`/`Spy` helpers in `test_b100_workers.py` receive the package module as their `owner`. The helper's `monkeypatch.setattr(owner, name, …)` therefore patches the `__init__` re-export, while the product calls `deps.X`. The retargeter neither rewrites nor refuses this form. | 33 (2 also need RC-B) | retargeter |
| RC-B | Three names were patched on the app module only through those helpers, so the census and the D1 list missed them: `render_patched_image`, `check_project_files`, `build_loaded_s19`. They are not in `deps` at all, so mixins import them by name and no test patch reaches the product call. | 2 (on top of RC-A) | census → mover (D1 list) |
| RC-C | The `test_b103_copy_views.py` autouse fixture installs its tail spy through `S19TuiApp.copy_to_clipboard.__globals__`. That function now lives in `core.py` and calls `deps._mirror_and_write_os_clipboard`, so the conditional `setitem` never fires. | 23 | retargeter (detection) + one test edit |
| RC-D | `test_id_registry` declares `EXPECTED_SCANNED_TEST_FILES = 307`. The batch added 2 test modules (`tests/support/package_source.py`, `tests/test_package_source_helper.py`) without bumping it. | 1 | P1c prerequisite (whoever adds the helper) |

Evidence that these are the whole story: in a `/tmp` copy of AFTER with the RC-A…D fixes applied,
all 57 regression nodes PASS (`-n 6`, whole files `test_b100_workers.py`, `test_b103_copy_views.py`,
`test_id_registry.py`: `8 failed, 140 passed, 1 xfailed`). The 8 remaining failures are 6 nodes that
also fail on BEFORE plus H-12 rows 17 and 18 (P1c adaptations, expected).

## Method and evidence

- **H-12 rows**: each failing node was matched to its hazards.md H-12 row. The AFTER junit failure
  message was read and confirmed to be about source text, paths or AST (`FileNotFoundError …/tui/app.py`,
  `class S19TuiApp not found in …/app/__init__.py`, `StopIteration` over the parsed module, path-keyed
  set drift, …).
- **Timing candidates (13)**: each node was run serially (no `-n`) 3× per tree, BEFORE then AFTER
  alternating on an otherwise idle 16-core runner, in the isolated env (`env -i`, private HOME, TMPDIR
  and XDG dirs).
- **Regression candidates (57)**: run serially twice per tree. In AFTER each pass was split into 6
  parallel serial processes (wall time: each failing node waits ~60 s). Result: `A1:F A2:F B1:P B2:P`
  for all 57 nodes.
- **Root-cause experiments** (in `/tmp/zq-diag-exp-1`, a copy of AFTER):
  1. *Full fix* — 29 helper owners `app_module` → `app_module.deps`; copy_views fixture also patches
     `deps._mirror_and_write_os_clipboard`; bound 307 → 309; product: `deps.py` imports the 3 RC-B
     names, and their 4 call sites become `deps.X`. Result: 57/57 pass.
  2. *Test-only fix* (product restored to AFTER) on `save_rederives…`, `project_load_reads_every_file…`
     and the control `confirmed_quit_waits_for_the_end[save]`. Result: `2 failed, 1 passed`. The
     control passes (RC-A alone suffices). The other two still fail because of the RC-B names only:
     `{'build_loaded_s19': (0, False), 'check_project_files': (0, False), 'parse_a2l_file': (1, False), 'read_project_manifest': (1, False), …}`
     and `assert 'render' in ['rederive']`.
- **Scope scan** (AST over every `tests/**/*.py` of AFTER): calls that pass the bare package module
  (`s19_app.tui.app` / `.screens_directionb` alias) as an argument occur only in `test_b100_workers.py`
  (28 literal sites + 1 dict comprehension, line 538). Other hits are `inspect.getsource`/`getfile`
  reads (H-12). Writes through `__globals__` occur only in `test_b103_copy_views.py:110-111`
  (`test_flow_chainset_b94.py:150` reads `run_chain_set.__globals__`, an unrelated module).

## Classification table

Legend for the evidence column: `S 3/3 P·P` = serial ×3, all passed in BEFORE and in AFTER;
`A1:F A2:F B1:P B2:P` = serial passes AFTER 1–2, BEFORE 1–2.

### EXPECTED-P1C (48)

| Id | Class | Evidence (AFTER failure message) | H-12 row |
|---|---|---|---|
| test_b100_a2l_progress.py::test_tc_b100_73_one_argument_callers_outside_the_app_are_unchanged | EXPECTED-P1C | `['s19_app/tui/app/deps.py:107'] == []`: the name-based `app.py` exclusion no longer covers the package | 1 |
| test_b100_busy.py::test_tc_b100_50_begin_busy_is_called_only_from_the_one_label_helper | EXPECTED-P1C | `class S19TuiApp not found in …/app/__init__.py` | 2 |
| test_b100_busy.py::test_tc_b100_51_every_save_abort_return_ends_its_run_first | EXPECTED-P1C | same | 7 |
| test_b100_busy.py::test_tc_b100_51_file_load_reads_the_copy_size_before_the_worker | EXPECTED-P1C | same | 8 |
| test_b100_busy.py::test_tc_b100_51_only_the_seam_sets_the_bar | EXPECTED-P1C | same | 4 |
| test_b100_busy.py::test_tc_b100_51_workers_take_the_run_generation | EXPECTED-P1C | module walk finds `0 >= 4` worker calls | 5 |
| test_b100_load_dialog.py::test_tc_b100_40_one_router_receives_every_dialog_result | EXPECTED-P1C | `FileNotFoundError …/tui/app.py` | 9 |
| test_b100_load_question.py::test_tc_b100_45_modal_imports_nothing_from_the_app | EXPECTED-P1C | `FileNotFoundError …/tui/app/screens.py` | 21 |
| test_b100_load_question.py::test_tc_b100_46_project_load_handler_asks_nothing | EXPECTED-P1C | `StopIteration` (function not in the parsed module) | 22 |
| test_b100_load_question.py::test_tc_b100_72_every_load_call_passes_the_seam | EXPECTED-P1C | `StopIteration` (class body not found) | 23 |
| test_b100_recents.py::test_tc_b100_37_files_list_shows_loadable_suffixes_only_through_one_predicate | EXPECTED-P1C | `S19TuiApp not found` | 26 |
| test_b100_recents.py::test_tc_b100_38_one_project_match | EXPECTED-P1C | `S19TuiApp not found` | 27 |
| test_b100_recents.py::test_tc_b100_38_one_wording_table | EXPECTED-P1C | `S19TuiApp not found` | 28 |
| test_b100_reuse.py::test_tc_b100_01_app_placements_name_the_workarea_root | EXPECTED-P1C | `FileNotFoundError …/tui/app.py` | 11 |
| test_b100_reuse.py::test_tc_b100_57_export_holds_no_byte_identity_rule | EXPECTED-P1C | key drift `(…/app/save_commit.py,'_abort_save')` vs `(…/tui/app.py,'_abort_save')` | 10 |
| test_b100_save_dialog.py::test_tc_b100_47_one_preparation_ast_census | EXPECTED-P1C | `FileNotFoundError …/tui/app.py` | 29 |
| test_b100_save_dialog.py::test_tc_b100_65_first_frame_before_the_image_decision | EXPECTED-P1C | same | 31 |
| test_b100_save_dialog.py::test_tc_b100_65_the_preview_and_the_dialog_list_nothing_themselves | EXPECTED-P1C | same | 30 |
| test_b100_save_guards.py::test_tc_b100_07_ast_census_every_post_creation_return_removes | EXPECTED-P1C | same | 12 |
| test_b100_session_reset.py::test_tc_b100_08_call_site_census | EXPECTED-P1C | `['tui/app/project_load.py'] == ['tui/app.py']` | 15 |
| test_b100_workers.py::test_tc_b100_53_workers_read_only_their_frozen_request | EXPECTED-P1C | `worker functions not found in app.py` | 17 |
| test_b100_workers.py::test_tc_b100_53_session_is_written_only_on_the_main_thread | EXPECTED-P1C | `source_census()` parses `Path(app_module.__file__)` (= `__init__.py`), gets `[]`, expects `['_a2l_cache_data', …]` | 18 |
| test_b101_doc_hygiene.py::test_r_doc_dev_11_1_overview_names_every_window | EXPECTED-P1C | `s19_app/tui/app.py is missing from the working tree` | 43 |
| test_b101_doc_hygiene.py::test_r_doc_ref_1_1_named_paths_exist | EXPECTED-P1C | 14 doc paths to old files (README, PROJECT_RULES, CLAUDE.md, docs/architecture.md) | 44 |
| test_b103_copy_quit_dialog.py::test_r_dlg_14_101_copy_quit_has_reachable_shared_opener | EXPECTED-P1C | `KeyError: 's19_app/tui/app.py'` | 33 |
| test_b97_key_bar.py::test_tc_b97_69_derived_rows_follow_their_guards | EXPECTED-P1C | `FileNotFoundError …/tui/app.py` | 73 |
| test_b97_patch_editor.py::test_tc_b97_03_columns_once_and_no_geometry_pass | EXPECTED-P1C | `FileNotFoundError …/screens_directionb/app.py` | 46 |
| test_b97_patch_editor.py::test_tc_b97_04_e3_pairs_absent | EXPECTED-P1C | `FileNotFoundError …/screens_directionb/styles.tcss` | 47–50 (via 45) |
| test_b97_patch_editor.py::test_tc_b97_04_no_unscoped_patch_rule_in_the_whole_stylesheet | EXPECTED-P1C | same | 47–50 (via 45) |
| test_b97_patch_editor.py::test_tc_b97_04_patch_rules_scoped_and_check_rule_untouched | EXPECTED-P1C | same | 47–50 (via 45) |
| test_b97_patch_editor.py::test_tc_b97_40_labelled_form_and_chips_in_the_inspector[size0] | EXPECTED-P1C | same | 47–50 (via 45) |
| test_b97_patch_editor.py::test_tc_b97_40_labelled_form_and_chips_in_the_inspector[size1] | EXPECTED-P1C | same | 47–50 (via 45) |
| test_b99_staging.py::test_tc_b99_13_no_final_name_replace_outside_placement | EXPECTED-P1C | allow-list keyed `s19_app/tui/app.py`; hits in `a2l_view.py:282`, `reports.py:1477` | 32 |
| test_capped_text_area.py::test_five_construction_sites_yield_capped_text_area | EXPECTED-P1C | `__init__.py: no construction site found for #patch_paste_text` | 70 |
| test_filename_markup_safety.py::test_at_s3_dynamic_notify_sites_pass_markup_false | EXPECTED-P1C | `found 0` notify sites in app text | 81 |
| test_render_hexview.py::test_tc651_import_census_all_consumers_read_render_hexview | EXPECTED-P1C | importer set drift: new `s19_app.tui.app.{deps,file_load,hex_view}`, `…screens_directionb.ab_diff` | 75 |
| test_render_hexview.py::test_tc652_wrapper_absence_and_renderer_surface | EXPECTED-P1C | `FileNotFoundError …/tui/app.py` | 76 |
| test_tui_commandbar.py::test_at_b78_13_the_seven_symbols_and_six_selectors_are_gone | EXPECTED-P1C | `FileNotFoundError s19_app/tui/app.py` | 77 |
| test_tui_commandbar.py::test_tc_b79_05_every_cited_symbol_anchor_resolves | EXPECTED-P1C | same | 78 |
| test_tui_directionb.py::test_tc_042_10_markup_safe_renderables_and_no_from_markup | EXPECTED-P1C | `exactly one markup=True … found 0` in sdb text | 54 |
| test_tui_directionb.py::test_tc_042_12_memory_strip_touches_no_frozen_path | EXPECTED-P1C | `…/app/workspace_view.py`.endswith('app.py') is False | 55 |
| test_tui_patch_card.py::test_writer_census_every_app_site_pushes_mem_map | EXPECTED-P1C | `0 refresh_entries call(s) in app.py` | 60 |
| test_tui_patch_card.py::test_writer_census_panel_selfcall_supplies_none | EXPECTED-P1C | `exactly one panel self-call; found 0` | 61 |
| test_tui_patch_checks_strip.py::test_tc078_3_both_sites | EXPECTED-P1C | `THREE refresh_check_results call sites; found 0` | 65 |
| test_tui_patch_history_strip.py::test_tc081_3_sites | EXPECTED-P1C | `FileNotFoundError s19_app/tui/app.py` | 68 |
| test_tui_report_attribution.py::test_tc570_generation_is_outside_every_valueerror_guarded_span | EXPECTED-P1C | `StopIteration` over `getsource(app_module)` | 82 |
| test_tui_report_attribution.py::test_tc572_the_tool_failure_sequence_exists_exactly_once | EXPECTED-P1C | `ValueError: substring not found` in `getsource(app_module)` | 83 |
| test_tui_variants.py::test_no_new_parse_loaded_file_call_sites | EXPECTED-P1C | caller set `[]` from app text | 80 |

### FLAKY/LOAD (13)

Each row: under `-n 12` one tree failed on a wall-clock bound or a shared wait. Serially, 3 passes
per tree were run.

| Id | Class | Evidence | Group |
|---|---|---|---|
| test_b100_active_variant.py::test_tc_b100_20_writers_on_a_31_folder_manifest_finish_under_one_second[save-project] | FLAKY/LOAD | full run AFTER `1.14 s < 1.0`; serial `S 3/3 P·P` | timing bound |
| test_b100_project_check.py::test_at_b100_07_load_names_the_changed_file_and_the_hostile_record[size1] | FLAKY/LOAD | full run AFTER: summary line still `Loaded firmware.s19 (S19 only)` (read before the check landed); serial `S 3/3 P·P` | shared wait under load |
| test_b100_project_check.py::test_r_tst_111_112_arm_values_equal_the_product_stamps[all-bad] | FLAKY/LOAD | full run BEFORE failed `painted 1.23 s < 1.0`; serial `S 3/3 P·P` | timing bound |
| test_b100_project_check.py::test_r_tst_111_112_arm_values_equal_the_product_stamps[cap] | FLAKY/LOAD | serial BEFORE `F P P`, AFTER `P P F`: same `AssertionError: []` in both trees, so it varies on the same tree | intermittent (both trees) |
| test_b100_project_check.py::test_tc_b100_61_every_array_at_the_cap_all_bad_opens_under_one_second | FLAKY/LOAD | full run BEFORE `1.15 s < 1.0`; serial `S 3/3 P·P` | timing bound |
| test_b100_project_check.py::test_tc_b100_61_sec6_5_deep_entries_need_one_check_each_parent | FLAKY/LOAD | full run BEFORE `painted 1.026 s < 1.0`; serial `S 3/3 P·P` | timing bound |
| test_b100_save_guards.py::test_tc_b100_05_merge_keeps_a_too_large_document_under_one_second | FLAKY/LOAD | full run AFTER `1.264 s < 1.0`; serial `S 3/3 P·P` | timing bound |
| test_b100_save_image.py::test_tc_b100_59_open_project_unchanged | FLAKY/LOAD | full run BEFORE `timed out waiting for the save`; serial `S 3/3 P·P` | shared wait under load |
| test_b100_save_image.py::test_tc_b100_59_pending_patch_in_the_open_project | FLAKY/LOAD | same | shared wait under load |
| test_b103_a2l_definition_perf.py::test_r_a2l_def_136_1_describing_every_object_is_fast | FLAKY/LOAD | full run AFTER `2.14 s <= 2.0`; serial `S 3/3 P·P` | timing bound |
| test_b103_a2l_reader_perf.py::test_r_a2l_read_52_software_a_time | FLAKY/LOAD | full run AFTER `1.143 < 0.98`; serial `S 3/3 P·P` | timing bound |
| test_b103_clipboard_core.py::test_r_paste_31_3_4_linux_right_click_paste_ends_within_typed_key_time[single] | FLAKY/LOAD | full run BEFORE `0.375 <= 0.365`; serial `S 3/3 P·P` | timing bound |
| test_b103_label_match_perf.py::test_r_a2l_match_36_1_ranking_per_keystroke_over_ref | FLAKY/LOAD | full run AFTER median `0.2206 <= 0.2`; serial `S 3/3 P·P` | timing bound |

Six of the 13 failed in BEFORE (failed → passed). Seven failed in AFTER, all wall-clock bounds or
shared waits that pass serially in AFTER 3/3. Nothing points to a slowdown caused by the split.

### REGRESSION (57)

Evidence for every row: serial `A1:F A2:F B1:P B2:P`; PASS in the full-fix experiment.

| Id (all in `tests/`) | Class | Evidence (AFTER failure) | Group |
|---|---|---|---|
| test_b100_workers.py::test_at_b100_18_quit_confirm_half_slow_save_as_leaves_no_partial_folder | REGRESSION | `Save project S9 never reached its worker step place_into_workarea` | RC-A |
| test_b100_workers.py::test_at_b100_18_quit_half_q_during_a_save_asks_with_stay_focused | REGRESSION | `… never reached its worker step place_into_workarea` | RC-A |
| test_b100_workers.py::test_at_b100_18_refusal_half_l_during_a_save_by_keys | REGRESSION | same | RC-A |
| test_b100_workers.py::test_tc_b100_53_a_project_reload_reuses_the_a2l_parse | REGRESSION | `Spy(app_module,'parse_a2l_file')` counted `0 == 1` | RC-A |
| test_b100_workers.py::test_tc_b100_53_action_starts_refuse_while_another_session_action_runs | REGRESSION | `the A2L attach never reached its worker step parse_a2l_file` | RC-A |
| test_b100_workers.py::test_tc_b100_53_busy_line_names_the_action_and_changes_nothing | REGRESSION | `… never reached … place_into_workarea` | RC-A |
| test_b100_workers.py::test_tc_b100_53_busy_line_paints_a_hostile_name_literally[A‮B-AB] | REGRESSION | `… never reached … read_project_manifest` | RC-A |
| test_b100_workers.py::test_tc_b100_53_busy_line_paints_a_hostile_name_literally[[b]P-[b]P] | REGRESSION | same | RC-A |
| test_b100_workers.py::test_tc_b100_53_confirmed_quit_during_a_routed_project_load_exits_cleanly | REGRESSION | same | RC-A |
| test_b100_workers.py::test_tc_b100_53_confirmed_quit_is_withdrawn_when_the_load_fails[project_fails] | REGRESSION | same | RC-A |
| test_b100_workers.py::test_tc_b100_53_confirmed_quit_is_withdrawn_when_the_load_fails[project_refused] | REGRESSION | `… never reached … parse_a2l_file` | RC-A |
| test_b100_workers.py::test_tc_b100_53_confirmed_quit_waits_for_the_end[a2l] | REGRESSION | same | RC-A |
| test_b100_workers.py::test_tc_b100_53_confirmed_quit_waits_for_the_end[project] | REGRESSION | `… never reached … read_project_manifest` | RC-A |
| test_b100_workers.py::test_tc_b100_53_confirmed_quit_waits_for_the_end[save] | REGRESSION | `… never reached … place_into_workarea`; test-only fix passes | RC-A |
| test_b100_workers.py::test_tc_b100_53_confirmed_quit_waits_for_the_end[save_fails] | REGRESSION | same | RC-A |
| test_b100_workers.py::test_tc_b100_53_every_a2l_attach_route_parses_on_a_worker | REGRESSION | `{'pick': 0, 'startup': 0, 'typed': 0}` spy counts | RC-A |
| test_b100_workers.py::test_tc_b100_53_held_save_keeps_the_loop_free | REGRESSION | `… never reached … place_into_workarea` | RC-A |
| test_b100_workers.py::test_tc_b100_53_idle_quit_under_the_load_question_keeps_the_key | REGRESSION | `… never reached … read_project_manifest` | RC-A |
| test_b100_workers.py::test_tc_b100_53_in_place_a2l_pick_starts_at_the_parse_step | REGRESSION | `… never reached … parse_a2l_file` | RC-A |
| test_b100_workers.py::test_tc_b100_53_load_requests_are_refused_during_a_project_load | REGRESSION | `… never reached … read_project_manifest` | RC-A |
| test_b100_workers.py::test_tc_b100_53_load_result_panel_opens_after_the_install | REGRESSION | same | RC-A |
| test_b100_workers.py::test_tc_b100_53_paste_box_is_read_only_during_a_project_load | REGRESSION | same | RC-A |
| test_b100_workers.py::test_tc_b100_53_patch_editor_changes_are_refused_while_busy | REGRESSION | `… never reached … place_into_workarea` | RC-A |
| test_b100_workers.py::test_tc_b100_53_patch_editor_continuations_are_refused_while_busy | REGRESSION | same | RC-A |
| test_b100_workers.py::test_tc_b100_53_project_load_reads_every_file_on_a_worker | REGRESSION | all 5 spies `(0, False)`; with test-only fix still `build_loaded_s19`/`check_project_files` `(0, False)` | RC-A + RC-B |
| test_b100_workers.py::test_tc_b100_53_quit_boundaries | REGRESSION | `… never reached … place_into_workarea` | RC-A |
| test_b100_workers.py::test_tc_b100_53_quit_question_emphasises_the_safe_answer | REGRESSION | same | RC-A |
| test_b100_workers.py::test_tc_b100_53_report_generate_keeps_the_regions_of_a_running_save | REGRESSION | same | RC-A |
| test_b100_workers.py::test_tc_b100_53_save_rederives_on_main_before_the_worker | REGRESSION | `assert 'render' in ['rederive']`; unchanged with test-only fix | RC-A + RC-B |
| test_b100_workers.py::test_tc_b100_53_save_refuses_before_any_worker_then_writes_on_one | REGRESSION | `a write was never seen: … 'place_into_workarea': set(), 'save_patched_image': set(), 'write_project_manifest': set()` | RC-A |
| test_b100_workers.py::test_tc_b100_53_session_writers_are_refused_during_a_save | REGRESSION | `… never reached … place_into_workarea` | RC-A |
| test_b100_workers.py::test_tc_b100_53_stay_keeps_the_save_running | REGRESSION | same | RC-A |
| test_b100_workers.py::test_tc_b100_53_variant_unload_and_save_are_refused_while_busy | REGRESSION | same | RC-A |
| test_b103_copy_views.py::test_r_copy_10_one_osc52_request[R-COPY.10/2] | REGRESSION | `fixture timeout: clipboard tail completion` | RC-C |
| test_b103_copy_views.py::test_r_copy_10_one_osc52_request[R-COPY.10/3] | REGRESSION | same | RC-C |
| test_b103_copy_views.py::test_r_copy_12_7_back_to_back_and_reentry | REGRESSION | same | RC-C |
| test_b103_copy_views.py::test_r_copy_12_8_positive_bounds_and_cardinality | REGRESSION | same | RC-C |
| test_b103_copy_views.py::test_r_copy_12_right_click_selection[R-COPY.12/1] | REGRESSION | same | RC-C |
| test_b103_copy_views.py::test_r_copy_12_right_click_selection[R-COPY.12/2] | REGRESSION | same | RC-C |
| test_b103_copy_views.py::test_r_copy_12_right_click_selection[R-COPY.12/3] | REGRESSION | same | RC-C |
| test_b103_copy_views.py::test_r_copy_12_right_click_selection[R-COPY.12/4] | REGRESSION | same | RC-C |
| test_b103_copy_views.py::test_r_copy_12_right_click_selection[R-COPY.12/5] | REGRESSION | same | RC-C |
| test_b103_copy_views.py::test_r_copy_12_right_click_selection[R-COPY.12/6] | REGRESSION | same | RC-C |
| test_b103_copy_views.py::test_r_copy_15_right_click_clears_selection[R-COPY.15/1] | REGRESSION | same | RC-C |
| test_b103_copy_views.py::test_r_copy_15_right_click_clears_selection[R-COPY.15/2] | REGRESSION | same | RC-C |
| test_b103_copy_views.py::test_r_copy_15_right_click_clears_selection[R-COPY.15/3] | REGRESSION | same | RC-C |
| test_b103_copy_views.py::test_r_copy_21_valid_right_click_highlights_without_selection[R-COPY.21/1] | REGRESSION | same | RC-C |
| test_b103_copy_views.py::test_r_copy_21_valid_right_click_highlights_without_selection[R-COPY.21/2] | REGRESSION | same | RC-C |
| test_b103_copy_views.py::test_r_copy_22_right_click_does_not_jump_hex[R-COPY.22/1] | REGRESSION | same | RC-C |
| test_b103_copy_views.py::test_r_copy_22_right_click_does_not_jump_hex[R-COPY.22/2] | REGRESSION | same | RC-C |
| test_b103_copy_views.py::test_r_copy_2_app_clipboard[R-COPY.2/2] | REGRESSION | same | RC-C |
| test_b103_copy_views.py::test_r_copy_2_app_clipboard[R-COPY.2/3] | REGRESSION | same | RC-C |
| test_b103_copy_views.py::test_r_copy_2_app_clipboard[R-COPY.2/4] | REGRESSION | same | RC-C |
| test_b103_copy_views.py::test_r_copy_4_full_row_names[R-COPY.4/1] | REGRESSION | same | RC-C |
| test_b103_copy_views.py::test_r_copy_4_full_row_names[R-COPY.4/2] | REGRESSION | same | RC-C |
| test_b103_copy_views.py::test_r_copy_4_full_row_names[R-COPY.4/3] | REGRESSION | same | RC-C |
| test_id_registry.py::test_tc607_scanned_corpus_matches_the_declared_bound | REGRESSION | `the guard scanned 309 test modules, not the declared 307` | RC-D |

## Regression root causes

### RC-A — helper-mediated module patches escape the retargeter (33 nodes)

```
tests/test_b100_workers.py:304: in reached
    raise AssertionError(f"{what} never reached its worker step {hold.name}")
E   AssertionError: Save project P1 never reached its worker step place_into_workarea
```

**Mechanism.** `test_b100_workers.py` wraps product functions with two helpers: `Spy(monkeypatch,
owner, name)` (line ~226) and `Hold(monkeypatch, owner, name)` (line ~253). Each ends in
`monkeypatch.setattr(owner, name, …)`. Tests call them with `owner = app_module`, the package
`s19_app.tui.app`, at 28 literal sites plus one dict comprehension
(`{name: Spy(monkeypatch, app_module, name) for name in (…)}`, line 538).
- In BEFORE, `app_module` was the module whose globals the product read, so the wrapper took effect.
- In AFTER, `app_module.place_into_workarea` is only the `__init__` re-export. The mixins call
  `deps.place_into_workarea`, so the wrapper sits on an object nobody calls.
- A `Hold` is never entered, so `reached()` times out after 60 s. A `Spy` records 0 calls.

**Why the tools missed it.** The retargeter (spec-retarget-tests.md) has rules T1–T4 for patch
calls whose first argument is a module alias. Its refusal R1 covers `setattr(A, name_var, …)`. Here,
though, the alias is passed as a plain argument to a local helper, and inside that helper
`setattr(owner, name, …)` has no alias at all. No rule fires and no refusal fires. The census
(`test_patch_census.py`) has the same blind spot, so these 29 sites were also missing from the
"150 + 1 patch sites".

**Owner:** retargeter. The census shares the detection gap.

**Proposed fix.**
1. Tool: add a refusal R5, *"a module alias of P is passed as an argument to a call that is not a
   T1–T4 form and not a read-only introspection (`getattr`/`hasattr` with a constant name,
   `inspect.*`)"*. Add the matching census rule, so the site lands in `module_patches` with its
   names. Add a negative control `NC-RT-7`: `Spy(monkeypatch, app_module, "X")` in a scratch file →
   `REFUSE R5`.
2. Test edit (mechanical, verified in the experiment): `Hold(monkeypatch, app_module,` →
   `Hold(monkeypatch, app_module.deps,` and `Spy(monkeypatch, app_module,` →
   `Spy(monkeypatch, app_module.deps,`. That is 29 sites, all in `tests/test_b100_workers.py`.
   Class-owner calls (`Spy(monkeypatch, S19TuiApp, …)`) are untouched.
3. Masked sites: the same rewrite reaches helper calls inside tests that already fail on BEFORE.
   For example, line 731 in `test_tc_b100_53_workarea_data_pick_parses_on_the_file_load_worker[*]`
   now spies the right object. In the experiment those tests failed exactly as on BEFORE, so they
   add no new diff.

### RC-B — three D1 names missing from the seam (2 nodes, both also RC-A)

```
E   AssertionError: {'build_loaded_s19': (0, False), 'check_project_files': (0, False),
    'parse_a2l_file': (1, False), 'read_project_manifest': (1, False), ...}     # test-only fix applied
E   assert 'render' in ['rederive']                                               # test-only fix applied
```

**Mechanism.** The D1 list (interfaces.md I-3) is built from the census of literal rebinding sites.
Three names were rebound on the app module only through the RC-A helpers:

| Name | Spied in | Product call site in AFTER |
|---|---|---|
| `render_patched_image` | line 1498 | `save_plan.py`, imported by name |
| `check_project_files` | line 538 loop | `project_load.py` |
| `build_loaded_s19` | line 538 loop | `projects.py`, `checks_diff.py` |

So they are not in D1 and not in `deps`. Each mixin imports them with
`from ..x import name` and calls the local binding. Neither `app_module.X` nor `app_module.deps.X`
can intercept that call.

The experiment separates the two causes. With the test-only fix, `parse_a2l_file` and
`read_project_manifest` (D1 names) are observed on the worker, but these three are not. Adding them
to `deps` and rewriting their 4 call sites to `deps.X` makes both tests pass.

**Owner:** census → mover. The D1 list in the module map is an input to the mover.

**Proposed fix.**
1. After the census gains the RC-A rule, recompute D1. This adds `render_patched_image`,
   `check_project_files` and `build_loaded_s19`. Check whether the loop at line 538 adds anything
   else (it also names `recorded_document_state`, which is already D1).
2. Re-run the mover so `deps.py` imports the three names and the I-3 rewrite turns the 4 product
   call sites into `deps.X`.
3. Re-run the verifier: the V18/D1 counts change by 3 names.

Rejected alternative: spy on the mixin modules (e.g. `save_plan.render_patched_image`). That works
today, but it couples the test to mixin file layout, which I-3 exists to avoid.

### RC-C — fixture patches the tail through `copy_to_clipboard.__globals__` (23 nodes)

```
tests/test_b103_copy_views.py:302: in _right_click
    await _wait_copy_tail(session)
tests/test_b103_copy_views.py:139: in _wait_copy_tail
    await _wait(
E   AssertionError: fixture timeout: clipboard tail completion
```

**Mechanism.** The autouse `clipboard` fixture (lines 104–111) patches
`clipboard_module._mirror_and_write_os_clipboard`. It then does

```python
if original_entry.__globals__.get("_mirror_and_write_os_clipboard") is original_tail:
    monkeypatch.setitem(original_entry.__globals__, "_mirror_and_write_os_clipboard", tail)
```

where `original_entry = S19TuiApp.copy_to_clipboard`. Probe output on both trees:

| Tree | Module | Name in globals | Original object | Function's `co_names` |
|---|---|---|---|---|
| BEFORE | `s19_app.tui.app` | True | True | the bare name: the branch fires and the spy is installed |
| AFTER | `s19_app.tui.app.core` | False | — | `deps` + the attribute (product calls `deps._mirror_and_write_os_clipboard`) |

In AFTER the branch is skipped, so the spy never wraps the call the product makes, `tail_done`
stays empty, and `_wait_copy_tail` times out after 1000 × 20 ms. Only nodes whose scenario reaches
a copy (`ledger.entry` non-empty) wait on the tail, which is why 23 of the file's nodes differ and
the rest do not. `_mirror_and_write_os_clipboard` *is* in D1; the retargeter handled the literal
`setattr` sites in `test_b103_clipboard_tail.py` and `test_b103_copy_paste_matrix.py`. This
`__globals__` write is a form it neither rewrites nor refuses.

**Owner:** retargeter for detection; the edit is one line of test code.

**Proposed fix.**
1. Test edit (verified in the experiment): after the `clipboard_module` patch, add
   `monkeypatch.setattr(s19_app.tui.app.deps, "_mirror_and_write_os_clipboard", tail)`. The
   `__globals__` branch then becomes dead and can be removed in the same edit.
2. Tool: extend R1 to refuse `<expr>.__globals__` subscripts/`setitem` in tests (scan hit:
   only this file writes through `__globals__`).

### RC-D — test-module bound not bumped (1 node)

```
E   AssertionError: the guard scanned 309 test modules, not the declared 307. If tests/ legitimately
    grew, bump EXPECTED_SCANNED_TEST_FILES in the same PR so the bound stays a decision rather than a
    rubber stamp.
```

**Mechanism.** AFTER adds `tests/support/package_source.py` and `tests/test_package_source_helper.py`
(the H-12 prerequisite helper and its test). `tests/test_id_registry.py:214` still declares 307.
hazards.md H-13 lists `test_id_registry` among the laws that "constrain test edits", but it records
only "keep test names", not the module-count bound.

**Owner:** P1c prerequisite (the integrator step that adds the shared helper).

**Proposed fix.** `EXPECTED_SCANNED_TEST_FILES = 309` in the same commit that adds the two files.
Verified in the experiment. Add the bound to H-13's row so the next added test module bumps it too.

## Notes for the next steps

- **What the experiment did and did not check.** After the RC-A…D fixes, the three files are green
  except BEFORE-failing nodes and H-12 rows 17/18. The experiment ran `-n 6`, not a full-suite
  re-run. A new full AFTER run should follow the real fixes.
- **H-12 rows outside the diff.** These match the hazards file, so they are P1c inputs, not P2
  diffs:
  - Rows 3, 6, 13, 14 and 74 fail in both trees.
  - Rows 20, 51–53, 71 and 79 pass in both. Several are flagged [V], i.e. silently green after the
    split.
  - Row 69 is skipped.
  - Row 39 (`test_ac1_…[*]`) went from 72 to 102 parametrised ids (H-21 family).
- **`deps.py:107`.** Row 1 now reports a 2-argument `parse_a2l_file(` call at this line, inside
  `parse_a2l_cached`. It used to be hidden by the `app.py` name exclusion. Row 1's planned
  adaptation (exclude `tui/app/`) keeps it excluded; no product change is implied.
- **Load sensitivity.** The 13 FLAKY/LOAD nodes are pre-existing timing fragility under `-n 12`:
  6 of them failed on BEFORE. A comparison rule that excuses only serially re-proven timing nodes
  would remove this noise from future `cmp` runs.

## Counts

| Class | Nodes | Breakdown |
|---|---|---|
| EXPECTED-P1C | 48 | H-12 rows 1, 2, 4, 5, 7, 8, 9, 10, 11, 12, 15, 17, 18, 21, 22, 23, 26–33, 43, 44, 46, 47–50 (5 nodes), 54, 55, 60, 61, 65, 68, 70, 73, 75–78, 80–83 |
| FLAKY/LOAD | 13 | 12 pass 6/6 serially in both trees; 1 (`[cap]`) flips within each tree |
| REGRESSION | 57 | RC-A 31 · RC-A + RC-B 2 · RC-C 23 · RC-D 1 |
| **Total** | **118** | |
