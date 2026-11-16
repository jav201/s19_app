# Inc 8 — test cases, group P (panel wiring), E4 tester `test-p`

Format (`roles/tester.md`): `<requirement id>/<n> | example id | test name | full or partial`. Rows follow `02-test-cases.md`; rows marked `+` are added by this tester (no E1 case row; the requirement or the graph example names the behaviour). Test files: `tests/test_b103_inc8_p_layout.py` (L), `tests/test_b103_inc8_p_ledger.py` (D), `tests/test_b103_inc8_p_wiring.py` (W); shared drivers `tests/support/b103_inc8_p.py`. Test names are the function names on disk. Expected values: region/colour/text are read from the running screen and from `styles.tcss` (`$accent-calm`, `$rule`); names come from the picker's `visible_params`; DEFC values (143.5, 287, `00 33`) come from the generator's files (seed 20260001) and EX-S1/EX-R12. The result of a case comes from a run, never from this file.

**Stand-ins (every one makes its case `partial`):** a 4-row `Static` yielded after the document row from inside `ActionsMixin._compose_doc_controls` (Inc 10's dock, I-8.3); the `-bench` class added by the test (Inc 9 sets it); `PatchEditorPanel.note_staged(...)` called directly (the formula-bar Enter route is group A's and the AT's); `app.current_a2l_data` assigned to swap the app's payload before the picker repopulates (R-PE-DEF.11/3).

| Case | Example | Test name | full / partial |
|---|---|---|---|
| R-TUI-063.1/1 | EX-L1 | `test_r_tui_063_1_the_seven_regions_run_top_to_bottom[118x54]` (L) | full |
| R-TUI-063.1/2 | EX-L1 | `test_r_tui_063_1_the_seven_regions_run_top_to_bottom[220x60]` (L) | full |
| R-TUI-063.1/3 + | EX-L1 | `test_r_tui_063_1_the_sheet_is_composed_by_the_panel` (L) — `#patch_sheet` is a `StagingSheet` inside `#patch_sheet_win`, `panel._sheet` is it (P2) | full |
| R-TUI-063.1/4 + | EX-L1 | `test_r_tui_063_1_the_old_beside_layout_ids_are_gone` (L) — `#patch_main`, `#patch_win_a2l`, `#patch_tab_a2l` absent (P8) | full |
| R-TUI-063.1/5 + | EX-L1 | `test_r_tui_063_1_the_sheet_window_subtitle_names_its_keys` (L) — title `STAGING SHEET`, subtitle starts `enter edit · ↑↓ row` (P8', provisional V-13) | full |
| R-PE-DEF.1.1/1 | EX-L1 | `test_r_pe_def_1_1_the_landing_pane_has_9_rows_and_the_sheet_takes_the_rest[118x54]` (L) | full |
| R-PE-DEF.1.1/2 | EX-L1 | `test_r_pe_def_1_1_the_landing_pane_has_9_rows_and_the_sheet_takes_the_rest[220x60]` (L) | full |
| R-PE-DEF.1.1/3 | EX-L7 | `test_r_pe_def_1_1_with_a_4_row_dock_the_sheet_is_the_panel_minus_the_other_seven` (L) | partial (stand-in dock) |
| R-PE-DEF.1.2/1 | EX-L8 | `test_r_pe_def_1_2_a_bench_gives_the_landing_pane_6_rows_and_the_sheet_the_3` (L) | partial (`-bench` set by the test; until Inc 9) |
| R-PE-DEF.74/1 | EX-L9 | `test_r_pe_def_74_the_sheet_window_has_at_least_12_rows_at_80x24` (L) | full |
| R-PE-DEF.74/2 | EX-L9 | `test_r_pe_def_74_the_sheet_window_has_at_least_12_rows_with_the_4_row_dock` (L) | partial (stand-in dock) |
| R-TUI-063.3/1 | EX-L2 | `test_r_tui_063_3_the_chips_are_patch_script_inspector_json_checks` (L) | full |
| R-TUI-063.4/1 | EX-L2 | `test_r_tui_063_4_the_ledger_pane_shows_first_with_its_chip_selected` (L) | full |
| R-TUI-063.6/1 | EX-L2 | `test_r_tui_063_6_every_shown_tab_titles_the_landing_pane_lands_in[patch_tab_script-patch_win_script]` (L) | full |
| R-TUI-063.6/2 | EX-L2 | `…[patch_tab_inspector-patch_pane_inspector]` (L) | full |
| R-TUI-063.6/3 | EX-L2 | `…[patch_tab_json-patch_win_json]` (L) | full |
| R-TUI-063.6/4 | EX-L2 | `…[patch_tab_checks-patch_win_checks]` (L) | full |
| R-PE-041/1 | EX-L3 | `test_r_pe_041_the_patch_script_and_inspector_tabs_show_the_entry_count[0-entries]` (D) — both tabs | full |
| R-PE-041/2 | EX-L3 | `…[1-entry]` (D) | full |
| R-PE-041/3 | EX-L3 | `…[3-entries]` (D) | full |
| R-PE-041/4 | EX-L3 | `test_r_pe_041_a_dirty_document_adds_the_marker_on_the_inspector_tab` (D) — three Adds through the panel's own inputs | full |
| R-PE-041/5 + | EX-L3 | `test_r_pe_041_the_json_tab_shows_the_schema_token_and_checks_its_run_state` (D) — JSON `v2 schema`, Checks its run state (behaviour that exists on base) | full |
| R-PE-DEF.2/1 | EX-L4 | `test_r_pe_def_2_the_seven_controls_sit_on_the_filter_row_and_the_table_is_hidden` (L) | full |
| R-PICKER-CORRECT.011/1 | EX-L4 | `test_r_picker_correct_011_the_include_and_add_list_controls_are_on_the_filter_row` (L) | full |
| R-PICKER-CORRECT.011/2 | EX-L4 | same test: `#patch_param_bulk_button` on the filter row | full |
| R-PICKER-CORRECT.011/3 | EX-L4 | `test_r_picker_correct_011_every_picker_id_is_unique_with_both_editors_mounted` (L) — behaviour that exists on base | full |
| R-PICKER-CORRECT.020/1 | EX-L5 | `test_r_picker_correct_020_filter_row_use_row_and_status_stay_inside_the_panel[80x24]` (L) | partial (horizontal containment and non-zero region; vertical scroll reach not asserted) |
| R-PICKER-CORRECT.020/2 | EX-L5 | `…[118x54]` (L) | full |
| R-PE-DEF.3/1 | EX-L4 | `test_r_pe_def_3_use_row_and_status_are_under_the_entry_form_in_the_inspector` (L) | full |
| R-PE-DEF.4/1 | EX-L6 | `test_r_pe_def_4_focus_on_the_sheet_paints_the_accent_border` (L) | full |
| R-PE-DEF.4/2 | EX-L6 | `test_r_pe_def_4_focus_in_the_file_row_paints_the_rule_border` (L) | full |
| R-PE-DEF.10/1 | EX-R1 | `test_r_pe_def_10_1_a_population_gives_one_row_per_visible_parameter_in_order` (W) | full |
| R-PE-DEF.10/2 | EX-R1 | `test_r_pe_def_10_2_a_filter_shows_only_the_matching_rows` (W) | full |
| R-PE-DEF.10/3 | EX-R1 | `test_r_pe_def_10_3_a_page_turn_of_a_201_name_list_shows_the_one_row_of_page_2` (W) | full |
| R-PE-DEF.11/1 | EX-R2 | `test_r_pe_def_11_1_an_a2l_reload_changing_enum_text_shows_the_new_text` (W) | full |
| R-PE-DEF.11/2 | EX-R2 | `test_r_pe_def_11_2_a_page_turn_and_a_filter_change_describe_nothing` (W) — every `describe_definition(s)` in `s19_app.*` counted | full |
| R-PE-DEF.11/3 | EX-R12 | `test_r_pe_def_11_3_the_apps_a2l_swapped_before_the_picker_repopulates_does_not_leak_into_rows` (W) | partial (payload swapped by assignment) |
| R-PE-DEF.18/1 | EX-R6 | `test_r_pe_def_18_1_no_image_shows_dashes_in_current` (W) | full |
| R-PE-DEF.18/3 + | EX-R6 | `test_r_pe_def_18_2_unloading_the_image_repaints_current_as_dashes` (W) — `set_image_mem_map(None)` (P6) | full |
| R-PE-DEF.49/1 | EX-K1 | `test_r_pe_def_49_1_selecting_row_3_highlights_that_parameter` (W) — real `down` keys on the sheet body | full |
| R-PE-DEF.49/2 | EX-K1 | `test_r_pe_def_49_2_a_page_turn_highlights_row_1_of_the_new_page` (W) | full |
| R-PE-DEF.60/1 | EX-S1 | `test_r_pe_def_60_1_note_staged_selects_the_row_after_the_staged_row` (D) | partial (`note_staged` called directly) |
| R-PE-DEF.60/2 | EX-S6 | `test_r_pe_def_60_2_note_staged_on_the_last_row_stays` (D) | partial (same) |
| R-PE-DEF.60/3 | EX-S10 | `test_r_pe_def_60_3_the_row_after_the_named_row_wins_over_where_the_selection_moved` (D) | partial (same) |
| R-PE-DEF.60/4 | EX-S10 | `test_r_pe_def_60_4_a_stage_reported_without_advance_keeps_the_selection` (D) | partial (same; Inc 9's record stage is the product caller) |
| R-PE-034/1 | EX-S1 | `test_r_pe_034_1_note_staged_sets_the_dirty_flag` (D) — read off the `●` of the ledger subtitle | partial (`note_staged` called directly; the Enter route is group A's) |
| R-PE-DEF.62/1 | EX-S1 | `test_r_pe_def_62_1_a_staged_entry_marks_its_row_and_undo_clears_it` (W) | full |
| R-PE-DEF.62/3 | EX-S7 | `test_r_pe_def_62_3_parse_pasted_with_a_display_entry_marks_the_row` (W) — real Parse button | full |

## Not covered by group P (named gaps)

- **R-PE-DEF.62/2** (Remove of the 0x800010 entry → both masked rows unstaged) and **R-PE-DEF.62/4** (a new image changes the word → MASK_BIT `●`, New `1 (0x01)`, EX-M1): the staged overlay of masked pairs is the sheet model's (group S) and the stage route's (group A, EX-O1); P5 and P6 are exercised by the DISPLAY_0001 rows above.
- **R-TUI-064.1 … .3:** the brief lists them for P12, but `01-requirements.md` holds no Inc 8 row and `02-test-cases.md` no case for them. Touched only through R-PE-DEF.74/1 (80×24 height) and R-PICKER-CORRECT.020 (80×24 containment); no scroll-reach assertion.
- **R-PE-DEF.12** (page-change timing) and every row-content rule (R-PE-DEF.15 …): groups S/A and the timing owner.
- Real Windows Terminal captures (V-1, V-2, V-13) are the operator's, not this tester's.
