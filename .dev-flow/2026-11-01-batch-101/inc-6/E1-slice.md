# Inc 6 — E1 slice: functions to change

Base `9bb0e3a` (line numbers are the base's). Rows: `01-requirements.md`. Design of each function: `codewire/graph-inc6.md`.

## 1. Source files (4 of the cap of 4)

`s19_app/tui/app.py`, `s19_app/tui/services/change_service.py`, `s19_app/tui/screens_directionb.py`, and (E3A-09, text only) `s19_app/tui/window_help.py`: the `WINDOW_HELP_SECTIONS` lines `:113-116` ("picks a change file in `patches/`", "re-reads the file list of `patches/`") and `:530` ("loads a check spec from the patches folder") say what the lists hold with a project. Docs edited at E4 with the change (text only, not source): `docs/user-guide/ch08-patch-editor.md:109` (F-05 "the notice offers it anyway") and `:181` (F-40), `docs/user-guide/ch10-check-editor.md:23` (Spec dropdown folder), `docs/user-guide/DOSSIER.md` §5 rows F-05, F-06, F-40 (fixed) and F-47 (carried), `README.md:192-195` (Check Editor Write "into the common … folder, with or without a project" becomes false, D9-15). Not touched: `changes/io.py` (`list_change_documents`, `write_change_document` used as they are), `services/project_gather_service.py` (`scoped_home_target` used as it is), `services/folder_open_service.py` (the 📂 chips already resolve the check home), `services/before_after_service.py` (the `.11` text is already right).

## 2. Functions (37: 26 changed, 11 new; #31 … #37 added at E3)

| # | File | Function | Change | Rows |
|---|---|---|---|---|
| 1 | app.py | `on_patch_editor_panel_save_back_decision` (`:4943`) **[Inc 5]** | offer only when `_active_project_dir()` is set; text without ` (action: before_after_report)` | R-BEFORE-AFTER-REPORT-001.1, .36 |
| 2 | app.py | `on_patch_editor_panel_action_requested` (`:4733`) **[Inc 5]** | `parse_paste` arm also hides the save-back prompt (#9); the `add_entry`, `edit_entry`, `remove_entry` and `parse_paste` arms end with #8 — no other arm renders the Checks tab (E3A-13: `load_doc` renders through #6, `apply_doc` through #33, `run_checks` through its own render) | R-TUI-049.3.2, R-CHK-PE-008 … 012 |
| 3 | app.py | `action_patch_undo` (`:5268`) | call #9 when the undo moved a step | R-TUI-049.3.1, .3.2 |
| 4 | app.py | `action_patch_redo` (`:5296`) | same for redo | R-TUI-049.3.1, .3.2 |
| 5 | app.py | `_refresh_patch_history_view` (`:5105`) | its `refresh_check_results` call becomes #8 (the writer census stays 3) | R-CHK-PE-009 … 012 |
| 6 | app.py | `_patch_editor_load_tail` (`:7165`) | call #8 at its end; **no** #9 (E3A-01: its callers are `_patch_editor_load` #31, `_reopen_active_document` (`:14274`, project install), `_on_project_saved` #37 (`:12658`, a pasted document placed — no replacement) and, at E3, #33) | R-CHK-PE-008 … 012, R-CHK-PE-014 |
| 7 | app.py | `_reset_project_session` (`:13412`) | after the panel repaint: #9 and #8; then `update_checks_view()` (E3A-02) | R-TUI-049.3.1, .3.2, R-CHK-PE-009 … 012, R-CHKS-009 |
| 8 | app.py | `_refresh_patch_checks_tab` | **new**: the one Checks-tab writer outside the run arm: rows of a current run (else none), `check_status_line()`, live `check_aggregates()` | R-CHK-PE-008 … 012 |
| 9 | app.py | `_hide_replaced_document_controls` | **new**: hide the before/after control and the save-back prompt | R-TUI-049.3.1, .3.2 |
| 10 | app.py | `_apply_prepared_load` (`:17913`) | after the site-4 `refresh_entries`: #9 when a new image dict is installed (`loaded.mem_map is not previous_map`, the test `mark_saved` already uses; S-1), then #8; after the panel block `update_checks_view()` (E3A-02) | R-TUI-049.3.1, .3.2, R-CHK-PE-009 … 012, R-CHKS-004 |
| 11 | app.py | `update_checks_view` (`:16473`) | no-run note and zero strip whenever `check_run_is_current()` is false | R-CHKS-001, -004, -009 |
| 12 | app.py | `_change_homes` | **new**: the change-list folders with their name prefix; with a project `checks/`, `patches/`, then `library/` (revised D-3) | R-PATCH-DOC-DROPDOWN-001.1, .2 |
| 13 | app.py | `_check_home` | **new**: the check home path (`scoped_home_target`, nothing created) | R-CHKED-031, -040, R-DIFF-CHK.1 |
| 14 | app.py | `_scan_patch_change_files` (`:6898`) | the change list over #12: each home's sorted names with its prefix, joined in home order (project entries, then library) | R-PATCH-DOC-DROPDOWN-001.1, .2 |
| 15 | app.py | `_scan_spec_files` (E1 name `_scan_check_home_files`) | **new**: the spec list over #32, joined in home order | R-CHKED-040, R-DIFF-CHK.1, .3 |
| 16 | app.py | `_resolve_listed_file` | **new**: the one pick guard — home by prefix; a plain name (no separator, not `..`); no link on the walk from the work area down to the file (the Write guard's rule and stop point, S-3); resolved inside the resolved work area; returns the **unresolved** `folder / name` (S-4) | R-PATCH-DOC-DROPDOWN-001.3, .4, R-CHKED-044, R-DIFF-CHK.5 |
| 17 | app.py | `on_patch_editor_panel_change_file_selected` (`:7054`) | guard through #16 over #12; the unsaved-changes popup's `_answer` runs #16 again before it loads (S-5) | R-PATCH-DOC-DROPDOWN-001.3, .4 |
| 18 | app.py | `on_check_editor_panel_spec_file_selected` (`:7449`) **[Inc 5]** | guard through #16 over #32 (top of the function); `load_spec(items, candidate.name)` so Write as gets the bare name (next to Inc 5's item dicts) | R-CHKED-042, R-CHKED-044 |
| 19 | app.py | `on_ab_diff_panel_check_file_selected` (`:7765`) | guard through #16 over #32 | R-DIFF-CHK.5, .8 |
| 20 | app.py | `_prefill_check_editor` (`:7238`) | Spec list from #15 | R-CHKED-040 |
| 21 | app.py | `_prefill_diff_check_files` (`:6816`) | list from #15 | R-DIFF-CHK.1, .3 |
| 22 | app.py | `_compose_screen_diff` (`:6743`) | initial `check_files` from #15 | R-DIFF-CHK.1, .3 |
| 23 | app.py | `on_check_editor_panel_action_requested` (`:7338`) | Write passes `dest_dir=_check_home()` | R-CHKED-031, -034 |
| 24 | change_service.py | `ChangeService.__init__` (`:803`) | adds `_last_check_message: str = ""` | R-CHK-PE-010 |
| 25 | change_service.py | `ChangeService.run_checks` (`:2634`) | stores the returned message in #24 | R-CHK-PE-008 |
| 26 | change_service.py | `ChangeService.check_run_is_current` | **new**: result present and stamp equals the live stamp | R-CHK-PE-008 … 012, R-CHKS-001 |
| 27 | change_service.py | `ChangeService.check_status_line` | **new**: #24 while #26, else `""` | R-CHK-PE-010 |
| 28 | change_service.py | `ChangeService.check_aggregates` (`:2721`) | all-zero while not #26 | R-CHK-PE-011, R-CHKS-009 |
| 29 | change_service.py | `ChangeService._check_glyphs` (`:2982`) | uses #26 (same behaviour) | R-CHK-PE-013 (unchanged behaviour) |
| 30 | screens_directionb.py | `PatchEditorPanel.refresh_check_results` (`:6867`) | subtitle `<n> checked` whenever the status line is not empty (a run is shown), `no run yet` otherwise | R-CHK-PE-008, -009 |
| 31 | app.py | `_patch_editor_load` (`:7127`) | (E3A-01) #9 first — every load replaces the document, also a failed read — then the read and #6 as before | R-TUI-049.3.1, .3.2 |
| 32 | app.py | `_spec_homes` | **new** (revised D-3): the spec-list folders with their prefix — `[("", workarea/patches)]`, or `[("checks/", P/checks), ("library/", workarea/patches)]` | R-CHKED-040, -042, -044, R-DIFF-CHK.1, .3, .5, .8 |
| 33 | app.py | `_note_image_bytes_written` **[Inc 5, new there]** | (E3A-03) three statements before Inc 5's body: #34; #6 on the Patch Editor panel when it is mounted (Checks tab and ledger glyphs); `update_checks_view()` | R-CHK-PE-009 … 012, -014, R-CHKS-001, -009 |
| 34 | change_service.py | `ChangeService.end_check_run` | **new** (E3A-03): `last_check_result = None`, `_last_check_message = ""` | R-CHK-PE-009 … 012, -014 |
| 35 | app.py | `_refill_document_lists` | **new** (E3A-04): `_prefill_patch_change_files()`; the Check Editor's `set_spec_files(#15)` when mounted (not the A2L half); `_prefill_diff_check_files()` | R-PATCH-DOC-DROPDOWN-001.1, R-CHKED-040, R-DIFF-CHK.1 |
| 36 | app.py | `_install_prepared_project` (`:14066`) | (E3A-04) #35 right after `current_project_dir` is set (`:14090`); not in `_reset_project_session`, which runs before it | R-PATCH-DOC-DROPDOWN-001.1, R-DIFF-CHK.1 |
| 37 | app.py | `_on_project_saved` (`:12560`) **[Inc 5]** | (E3A-04) #35 right after `current_project_dir` is set (`:12683`, every committed Save project: plain, create, save-as) | R-PATCH-DOC-DROPDOWN-001.1, R-CHKED-040 |

Unchanged and relied on: `_patches_dir` (still the common folder; tests stage into it), `_change_doc_save_home`, `_prefill_patch_change_files`, `_reopen_active_document` (calls #6), `PatchEditorPanel.set_change_files` (labels = values through `safe_text`), `CheckEditorPanel.set_spec_files` / `AbDiffPanel.set_check_files` (labels by suffix, values verbatim), `CheckEditorPanel.load_spec`, `hide_save_prompt`, `hide_before_after_prompt`, `update_checks_view` (a guarded no-op when the Checks screen is not mounted), `list_change_documents`, `write_change_document` (its placement checks and creates the folder), `workspace._path_traverses_reparse_point` / `_is_reparse_point` (already imported by app.py).

## 3. Overlap with Inc 5 (same functions, other lines)

`on_patch_editor_panel_action_requested` (Inc 5: one `if` after the `try`; Inc 6: the add / edit / remove / `parse_paste` arms), `on_patch_editor_panel_save_back_decision` (Inc 5: after `save_patched`; Inc 6: the final `notify`), `on_check_editor_panel_spec_file_selected` (Inc 5: the `items` dicts; Inc 6: the guard lines and the `load_spec` argument on the line after the dicts — adjacent, rebase with care), `on_check_editor_panel_action_requested` (Inc 5: docstring hunk `@@ -7344`; Inc 6: the Write call `:7374`), `_on_project_saved` (Inc 5: the hook inside the image `if`; Inc 6: #35 after `current_project_dir`), `_note_image_bytes_written` (Inc 5: new; Inc 6: three statements before its body — it must exist on main before E4). Inc 6 is rebased on Inc 5 before E4, and the six functions' line ranges are re-checked (E3A-12).

## 4. Nodes touched (existing tests whose body changes; names kept)

| Node | Why |
|---|---|
| `tests/test_before_after_report.py::test_at_038a_saveback_trigger_report_pair_reread_from_surfaced_path` | its offer filter keys on the token `before_after_report`, which D14-14 removes; filter on the title `Before/after report` |
| `tests/test_b101_symbol_reads.py::test_r_chg_sym_10_reads_with_no_a2l_loaded_declare_none[ab-diff-project-a2l-not-implicit]` | stages the check document in the common folder and picks it in the A2B Diff inside project `P`; with D-1 it must stage into `P/checks/` |
| `tests/test_tui_checks_screen.py::test_tc084_3_update_checks_view_groups_and_aggregates` | injects `last_check_result` without the provenance stamp (a state no product path makes); must set the stamp |
| `tests/test_tui_checks_screen.py::test_at084g_hostile_input_renders_literal` | same |
| `tests/test_b101_help_legend_docs.py::test_r_doc_readme_4_1_no_stale_claim` | its `_CHECK_EDITOR_PHRASE` (`:1402-1405`) pins the README sentence "writes the spec into the common `.s19tool/workarea/patches/` folder, with or without a project", which D9-15 makes false (R-DOC-README.4); the phrase changes with `README.md:192-195` (E3 census) |

To re-census at E4 on the LAN host (run the files, no change expected): `test_tui_patch_checks_strip.py` (census `test_tc078_3_both_sites` stays at 3 calls), `test_tui_patch_glyphs.py`, `test_change_service.py`, `test_undo_redo_ux.py`, `test_tui_patch_editor_v2.py` (AT-030a/c, TC-331), `test_tui_patch_variant.py`, `test_b100_document.py`, `test_tui_check_chain_b94.py`, `test_b97_chips_help.py`, `test_tui_patch_card.py` (the `refresh_entries` census: Inc 6 adds no site), `test_b101_help_legend_docs.py`, and every node that stages a spec or a change file and picks it with a project open (the values gain `checks/` / `patches/` / `library/`; grep `ChangeFileSelected(`, `SpecFileSelected(`, `CheckFileSelected(` and `diff_check_select`). New test file planned: `tests/test_b101_patch_lifecycle.py` (`EXPECTED_SCANNED_TEST_FILES` re-measured at integration).
