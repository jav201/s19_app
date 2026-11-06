# Inc 6 — E1 slice: functions to change

Base `9bb0e3a` (line numbers are the base's). Rows: `01-requirements.md`. Design of each function: `codewire/graph-inc6.md`.

## 1. Source files (3 of the cap of 4)

`s19_app/tui/app.py`, `s19_app/tui/services/change_service.py`, `s19_app/tui/screens_directionb.py`. Not touched: `changes/io.py` (`list_change_documents`, `write_change_document` used as they are), `services/project_gather_service.py` (`scoped_home_target` used as it is), `services/folder_open_service.py` (the 📂 chips already resolve the check home), `services/before_after_service.py` (the `.11` text is already right).

## 2. Functions (30: 22 changed, 8 new)

| # | File | Function | Change | Rows |
|---|---|---|---|---|
| 1 | app.py | `on_patch_editor_panel_save_back_decision` (`:4943`) **[Inc 5]** | offer only when `_active_project_dir()` is set; text without ` (action: before_after_report)` | R-BEFORE-AFTER-REPORT-001.1, .36 |
| 2 | app.py | `on_patch_editor_panel_action_requested` (`:4733`) **[Inc 5]** | `parse_paste` arm also hides the save-back prompt (#9); the handler's last step calls #8 | R-TUI-049.3.2, R-CHK-PE-008 … 012 |
| 3 | app.py | `action_patch_undo` (`:5268`) | call #9 when the undo moved a step | R-TUI-049.3.1, .3.2 |
| 4 | app.py | `action_patch_redo` (`:5296`) | same for redo | R-TUI-049.3.1, .3.2 |
| 5 | app.py | `_refresh_patch_history_view` (`:5105`) | its `refresh_check_results` call becomes #8 (the writer census stays 3) | R-CHK-PE-009 … 012 |
| 6 | app.py | `_patch_editor_load_tail` (`:7165`) | call #9 and #8 (every load path runs it) | R-TUI-049.3.1, .3.2, R-CHK-PE-008 … 012 |
| 7 | app.py | `_reset_project_session` (`:13412`) | after the panel repaint: #9 and #8 | R-TUI-049.3.1, .3.2, R-CHK-PE-009 … 012 |
| 8 | app.py | `_refresh_patch_checks_tab` | **new**: the one Checks-tab writer outside the run arm: rows of a current run (else none), `check_status_line()`, live `check_aggregates()` | R-CHK-PE-008 … 012 |
| 9 | app.py | `_hide_replaced_document_controls` | **new**: hide the before/after control and the save-back prompt | R-TUI-049.3.1, .3.2 |
| 10 | app.py | `_apply_prepared_load` (`:17913`) | after the site-4 `refresh_entries`: #8 | R-CHK-PE-009 … 012 |
| 11 | app.py | `update_checks_view` (`:16473`) | no-run note and zero strip whenever `check_run_is_current()` is false | R-CHKS-001, -004, -009 |
| 12 | app.py | `_change_homes` | **new**: the change-list folders with their name prefix | R-PATCH-DOC-DROPDOWN-001.1 |
| 13 | app.py | `_check_home` | **new**: the check home path (`scoped_home_target`, nothing created) | R-CHKED-031, -040, R-DIFF-CHK.1 |
| 14 | app.py | `_scan_patch_change_files` (`:6898`) | the change list over #12 | R-PATCH-DOC-DROPDOWN-001.1 |
| 15 | app.py | `_scan_check_home_files` | **new**: bare names of #13 | R-CHKED-040, R-DIFF-CHK.1 |
| 16 | app.py | `_resolve_listed_file` | **new**: the one pick guard (folder by prefix, no link, inside the folder and inside the open project) | R-PATCH-DOC-DROPDOWN-001.3, .4, R-CHKED-044, R-DIFF-CHK.5 |
| 17 | app.py | `on_patch_editor_panel_change_file_selected` (`:7054`) | guard through #16 over #12 | R-PATCH-DOC-DROPDOWN-001.3, .4 |
| 18 | app.py | `on_check_editor_panel_spec_file_selected` (`:7449`) **[Inc 5]** | guard through #16 over #13 (top of the function only) | R-CHKED-044 |
| 19 | app.py | `on_ab_diff_panel_check_file_selected` (`:7765`) | guard through #16 over #13 | R-DIFF-CHK.5 |
| 20 | app.py | `_prefill_check_editor` (`:7238`) | Spec list from #15 | R-CHKED-040 |
| 21 | app.py | `_prefill_diff_check_files` (`:6816`) | list from #15 | R-DIFF-CHK.1 |
| 22 | app.py | `_compose_screen_diff` (`:6743`) | initial `check_files` from #15 | R-DIFF-CHK.1 |
| 23 | app.py | `on_check_editor_panel_action_requested` (`:7338`) | Write passes `dest_dir=_check_home()` | R-CHKED-031, -034 |
| 24 | change_service.py | `ChangeService.__init__` (`:803`) | adds `_last_check_message: str = ""` | R-CHK-PE-010 |
| 25 | change_service.py | `ChangeService.run_checks` (`:2634`) | stores the returned message in #24 | R-CHK-PE-008 |
| 26 | change_service.py | `ChangeService.check_run_is_current` | **new**: result present and stamp equals the live stamp | R-CHK-PE-008 … 012, R-CHKS-001 |
| 27 | change_service.py | `ChangeService.check_status_line` | **new**: #24 while #26, else `""` | R-CHK-PE-010 |
| 28 | change_service.py | `ChangeService.check_aggregates` (`:2721`) | all-zero while not #26 | R-CHK-PE-011, R-CHKS-009 |
| 29 | change_service.py | `ChangeService._check_glyphs` (`:2982`) | uses #26 (same behaviour) | R-CHK-PE-013 (unchanged behaviour) |
| 30 | screens_directionb.py | `PatchEditorPanel.refresh_check_results` (`:6867`) | subtitle `<n> checked` whenever the status line is not empty (a run is shown), `no run yet` otherwise | R-CHK-PE-008, -009 |

Unchanged and relied on: `_patches_dir` (still the common folder; tests stage into it), `_change_doc_save_home`, `_prefill_patch_change_files`, `PatchEditorPanel.set_change_files` (labels = values through `safe_text`), `hide_save_prompt`, `hide_before_after_prompt`, `list_change_documents`, `write_change_document` (its placement checks and creates the folder).

## 3. Overlap with Inc 5 (same functions, other lines)

`on_patch_editor_panel_action_requested` (Inc 5: one `if` after the `try`; Inc 6: `parse_paste` arm and last line), `on_patch_editor_panel_save_back_decision` (Inc 5: after `save_patched`; Inc 6: the final `notify`), `on_check_editor_panel_spec_file_selected` (Inc 5: the `items` dicts; Inc 6: the guard lines). Inc 6 is rebased on Inc 5 before E4.

## 4. Nodes touched (existing tests whose body changes; names kept)

| Node | Why |
|---|---|
| `tests/test_before_after_report.py::test_at_038a_saveback_trigger_report_pair_reread_from_surfaced_path` | its offer filter keys on the token `before_after_report`, which D14-14 removes; filter on the title `Before/after report` |
| `tests/test_b101_symbol_reads.py::test_r_chg_sym_10_reads_with_no_a2l_loaded_declare_none[ab-diff-project-a2l-not-implicit]` | stages the check document in the common folder and picks it in the A2B Diff inside project `P`; with D-1 it must stage into `P/checks/` |
| `tests/test_tui_checks_screen.py::test_tc084_3_update_checks_view_groups_and_aggregates` | injects `last_check_result` without the provenance stamp (a state no product path makes); must set the stamp |
| `tests/test_tui_checks_screen.py::test_at084g_hostile_input_renders_literal` | same |

To re-census at E4 on the LAN host (run the files, no change expected): `test_tui_patch_checks_strip.py` (census `test_tc078_3_both_sites` stays at 3 calls), `test_tui_patch_glyphs.py`, `test_change_service.py`, `test_undo_redo_ux.py`, `test_tui_patch_editor_v2.py` (AT-030a/c, TC-331), `test_tui_patch_variant.py`, `test_b100_document.py`, `test_tui_check_chain_b94.py`, `test_b97_chips_help.py`. New test file planned: `tests/test_b101_patch_lifecycle.py` (`EXPECTED_SCANNED_TEST_FILES` re-measured at integration).
