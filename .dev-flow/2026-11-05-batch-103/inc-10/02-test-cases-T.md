# Inc 10 E4 — tester T10: case → test map and negative controls

Author: tester T10 (Sonnet). Base for RED: `439860c4`. Cases: `02-test-cases.md` (130 = 127 rows + AT-I10-1..3; 126 written, 4 `conflict` by D-6 A). Node ids are `file::function[param id]`; the param id is the case id. Files are under `tests/`; `sup` = `tests/support/b103_inc10.py`.
`full` = the product route end to end; `partial` = a stand-in or a shortcut named in the last column. Negative control (NC) = the mutant of the product that must turn the test RED; E4's mutant worker runs them; here they are stated, and the RED on base is in `E4-test.md`.

Conventions that apply to every row:
- Loading: `app.load_from_path` (the app's own loader) except the cases marked **dialog**, which load through the Load dialog (`l`, path typed key by key). Reason: ~10 s a scene (rtx, load 6-7). Entry and name boxes are filled by assigning `value` except the cases marked **keys** (AT-I10-1, AT-I10-2). So every "Applied …" case is `partial` for the Load dialog and the box typing, `full` for Apply, tab chips, Format, Width, `Write file`, `Don't save`, which are clicked.
- Entry boxes live in the Inspector pane (Inc 8 final): every Applied scene clicks the Inspector chip first, then the entry, then tab T.

## G1 panel and dock

| Case(s) | Test node | NC (what turns it RED) | Route |
|---|---|---|---|
| R-CHG-003.1/1..8 | `test_b103_inc10_g1_panel.py::test_r_chg_003_1_the_prompt_is_shown_whichever_tab_was_shown[R-CHG-003.1/n]` (/1, /5 dialog) | prompt kept in the JSON window (base) | full (dialog on /1, /5) |
| R-CHG-003.1/9 | `…g1_panel.py::test_r_chg_003_1_9_the_prompt_is_shown_after_an_apply_on_an_intel_hex_image` | as above | full |
| R-PE-EXPORT.1/1, /2 | `…g1_panel.py::test_r_pe_export_1_the_prompt_sits_between_the_document_row_and_the_legend[R-PE-EXPORT.1/n]` | prompt inside the inspector | full |
| R-TUI-063.1/1..4 | `…g1_panel.py::test_r_tui_063_1_the_patch_editor_top_to_bottom_order[R-TUI-063.1/n]` | prompt docked under the legend | full |
| R-PE-EXPORT.2/1..10 | `…g1_panel.py::test_r_pe_export_2_every_prompt_control_is_on_screen_without_scrolling[R-PE-EXPORT.2/n]` | prompt after the legend, panel height unchanged | full |
| R-PE-EXPORT.2/11 | `…g1_panel.py::test_r_pe_export_2_11_the_largest_dock_fits_and_its_height_is_recorded` (118×54) and `::test_r_pe_export_2_11_dock_height_at_220x60_is_recorded` | no dock | full; prints `DOCK-HEIGHT` |
| R-PE-EXPORT.7/1, R-PE-EXPORT.9/1 | `…g1_controls.py::test_r_pe_export_7_1_the_format_control_shows_s19_for_an_s19_image` | always Intel HEX / no control | full |
| R-PE-EXPORT.7/2 | `…g1_controls.py::test_r_pe_export_7_2_…intel_hex_image` | always S19 | full |
| R-PE-EXPORT.7/3 | `…g1_controls.py::test_r_pe_export_7_3_each_new_prompt_starts_from_the_loaded_images_format` | format kept from last prompt | full |
| R-PE-EXPORT.9/2 | `…g1_controls.py::test_r_pe_export_9_2_the_label_follows_a_press` | label not refreshed | full |
| R-PE-EXPORT.10/1, /2 | `…g1_controls.py::test_r_pe_export_10_1_…` and `::test_r_pe_export_10_2_…` | Width shown for Intel HEX | full |
| R-PE-EXPORT.11/1, /2 | `…g1_controls.py::test_r_pe_export_11_1_…` and `::test_r_pe_export_11_2_…` | Width hidden for S19 | full |
| R-PE-EXPORT.12/1..4 | `…g1_controls.py::test_r_pe_export_12_write_file_and_dont_save_stay_put_on_a_format_change[R-PE-EXPORT.12/n]` | Width collapsed → `Write file` moves | full (/2, /4 use an Intel HEX source and one press) |
| R-S19-WIDTH-001.1/1 | `…g1_controls.py::test_r_s19_width_001_1_1_the_width_is_32_on_every_new_prompt` | width kept across prompts | full |
| R-S19-WIDTH-001.2/1 | `…g1_controls.py::test_r_s19_width_001_2_1_width_switches_32_16_in_the_new_placement` | press changes nothing | full |
| R-PE-EXPORT.14/1, /2, /3 | `…g1_controls.py::test_r_pe_export_14_1_…`, `::…14_2_…`, `::…14_3_…` | name box left / case-sensitive match / one direction only | full |
| R-HEX-VERIFY-002.3/1, /2 | `…g1_controls.py::test_r_hex_verify_002_3_the_suggested_name_follows_the_image[R-HEX-VERIFY-002.3/n]` | suffix of the other format | full |
| R-TUI-064.1/1, /2 | `…g1_controls.py::test_r_tui_064_1_validate_apply_save_stay_on_screen_with_the_prompt_shown[R-TUI-064.1/n]` | dock pushes document row off | full; guards the prompt is shown |
| R-TUI-064.2/1, /2 | `…g1_controls.py::test_r_tui_064_2_no_painted_part_is_wider_than_the_panel_with_the_prompt_shown[R-TUI-064.2/n]` | apply line / chip row wider than panel | full; `clipped_overflow` + whole apply line (partial reading of "painted line ≤ cells": the compositor row itself cannot exceed the screen) |
| R-TUI-064.4/1 | `…g1_controls.py::test_r_tui_064_4_1_the_prompts_chips_are_one_row_high` | two-row chip grid | full |

## G2 app handlers

| Case(s) | Test node | NC | Route |
|---|---|---|---|
| R-PE-EXPORT.3/1, /2 | `test_b103_inc10_g2_arms.py::test_r_pe_export_3_an_apply_that_applies_nothing_hides_the_prompt[R-PE-EXPORT.3/n]` | zero-apply leaves prompt | full, prompt re-shown through I-10.1 as the case says |
| R-PE-EXPORT.3/3 | `…g2_arms.py::test_r_pe_export_3_3_…` | as above | full + I-10.1 |
| R-PE-EXPORT.4/1, /2, /3 | `…g2_arms.py::test_r_pe_export_4_1_…`, `::…4_2_…`, `::…4_3_…` | no line / swapped counts / stale counts | full |
| R-PE-EXPORT.5/1..3 | `…g2_arms.py::test_r_pe_export_5_an_apply_that_applies_nothing_raises_one_warning_notice[R-PE-EXPORT.5/n]` | no notice / severity information | full (reads `app._notifications`) |
| R-PE-EXPORT.6/1, /2 | `…g2_arms.py::test_r_pe_export_6_a_successful_apply_raises_no_notice[R-PE-EXPORT.6/n]` | info notice on success | full; GREEN on base by design |
| R-PE-EXPORT.17/1, /2, /3 | `…g2_arms.py::test_r_pe_export_17_1_…`, `::…17_2_…`, `::…17_3_…` | hide dropped from that arm | full |
| R-PE-EXPORT.17/4 | `…g2_arms.py::test_r_pe_export_17_4_a_per_entry_json_edit_hides_the_prompt` | hide dropped from `_apply_entry_json_edit` | full; popup text replaced by `load_text` (partial: no key typing in the popup) |
| R-PE-EXPORT.17/5 | `…g2_arms.py::test_r_pe_export_17_5_a_stage_from_the_staging_sheet_hides_the_prompt` | hide dropped from `on_staging_sheet_stage_requested` | full (sheet keys, formula input, Enter); **deviation**: DEFC image instead of case01 |
| R-CHG-003.2/1 | `…g2_arms.py::test_r_chg_003_2_1_dont_save_hides_the_prompt_from_the_inspector_tab` | prompt left shown | full |
| R-CHG-003.5/1 | `…g2_arms.py::test_r_chg_003_5_1_write_file_hides_the_prompt_from_the_checks_tab` | prompt left shown | full |
| R-TUI-049.1/1..4 | `…g2_arms.py::test_r_tui_049_1_the_before_after_control_is_shown_after_a_save_back[R-TUI-049.1/n]` | control left in JSON window | full |
| AT-I10-3 | `…g2_arms.py::test_at_i10_3_an_apply_that_applies_nothing_is_seen` | prompt survives Remove / no notice / byte left patched | full |
| R-PE-EXPORT.8/1, /2 | `test_b103_inc10_g2_write.py::test_r_pe_export_8_1_…`, `::…8_2_…` | press changes nothing / only sets HEX | full |
| R-PE-EXPORT.13/1 | `…g2_write.py::test_r_pe_export_13_1_a_format_change_keeps_the_width` | width reset to 32 | full |
| R-PE-EXPORT.14/4 | `…g2_write.py::test_r_pe_export_14_4_a_trailing_space_does_not_stop_the_replacement` | suffix matched only at the very end | full |
| R-PE-EXPORT.15/1, /2 | `…g2_write.py::test_r_pe_export_15_a_name_without_a_format_suffix_is_kept_and_the_write_adds_it[R-PE-EXPORT.15/n]` | suffix appended into the box | full |
| R-HEX-SAVE-001.1/1..4 · R-HEX-VERIFY-001.1/1..4 · R-HEX-VERIFY-002.1/1..2 · R-S19-S0HEADER-001.1/1 · R-S19-S0HEADER-001.2/1 | `…g2_write.py::test_the_prompt_writes_the_chosen_format_and_verifies_it[R-HEX-SAVE-001.1/n]` (n = 1..4; the param row names every case it carries) | file written in the loaded kind / verify with the loaded reader / S0 from the typed name | full; image read back with the independent reader |
| R-S19-SAVE-REUSE-001.1/1..4 | `…g2_write.py::test_r_s19_save_reuse_001_1_a_hex_save_back_holds_at_most_16_data_bytes_per_record[R-S19-SAVE-REUSE-001.1/n]` | width handed to the HEX writer | full |
| R-S19-S0HEADER-001.3/1; .2/2..4 + .3/2..4 | `…g2_write.py::test_r_s19_s0header_001_an_intel_hex_source_written_as_s19_gets_its_header[…]` | empty header at 32 / name header at 16 | **partial**: the confirm message (with `output_format`) is posted to the panel, the handler runs; no chip is clicked |
| R-S19-S0HEADER-001.1/2 | `…g2_write.py::test_r_s19_s0header_001_1_2_…` | header from the name when the source has S0 data | partial (same route) |
| AT-I10-1 | `…g2_write.py::test_at_i10_1_apply_from_the_inspector_tab_and_export_intel_hex` | prompt hidden / no Format / written as S19 | full; **dialog + keys**; see finding F-T10-1 |
| AT-I10-2 | `…g2_write.py::test_at_i10_2_an_intel_hex_image_exported_as_s19_at_16_bytes_per_line` | Width press ignored / HEX written / name header | full; **dialog + keys** |

## G3 engine (changed node `emit_intel_hex_from_mem_map`)

| Case(s) | Test node | NC | Route |
|---|---|---|---|
| R-HEX-EMIT-001.11/1, /2 | `test_b103_inc10_g3_engine.py::test_r_hex_emit_001_11_no_type_00_record_crosses_a_64_kib_boundary[R-HEX-EMIT-001.11/n]` (+ oracle guard `::test_r_hex_emit_001_11_the_data_files_are_what_the_base_emitter_would_cross`) | base loop (`data/x64u-base-emitter.hex`); cap inside the fixed `range` (bytes lost) | full (writer + committed x64u lines) |
| R-HEX-SAVE-001.2/1..4 | `…g3_engine.py::test_r_hex_save_001_2_the_format_suffix_is_added_when_missing[R-HEX-SAVE-001.2/n]` | suffix from the loaded kind | writer; GREEN on base |
| R-PE-EXPORT.16/1..8 | `…g3_engine.py::test_r_pe_export_16_a_hex_save_back_holds_only_record_types_00_01_04[R-PE-EXPORT.16/n]` | S0 / terminator carried into HEX | writer; GREEN on base |
| R-HEX-EMIT-001.2/1 | `…g3_engine.py::test_r_hex_emit_001_2_1_…` | no type-04 first | writer; GREEN on base |
| R-HEX-EMIT-001.3/1, /2 | `…g3_engine.py::test_r_hex_emit_001_3_a_type_04_record_when_the_upper_16_bits_change[R-HEX-EMIT-001.3/n]` | no type-04 on the change | writer; GREEN on base |
| R-S19-EMIT.3/1, .4/1, .4/2, .5/1 | `…g3_engine.py::test_r_s19_emit_the_record_size_follows_the_highest_address[R-S19-EMIT.n/m]` | wrong record size | writer; tags only (E4-N2); GREEN on base |
| R-IMG-WRITE.2/1 | `…g3_engine.py::test_r_img_write_2_1_every_conversion_reads_back_to_the_same_image` | one byte dropped | writer + independent reader; GREEN on base |
| R-HEX-VERIFY-001.1/5 | `…g3_engine.py::test_r_hex_verify_001_1_5_the_conversion_matrix_verifies_and_the_wrong_reader_does_not` | verify reads with the loaded kind | writer; GREEN on base |

## Not written (4 cases, D-6 A: `conflict`, owed by open code changes D8-27 / D8-28 / D8-29)

R-S19-S0HEADER-001.1/3, R-S19-S0HEADER-001.2/5, R-S19-EMIT.11/1, R-S19-EMIT.11/2. No test here asserts an empty S0 for a source with S0 data, nor a terminator address (E4-N2).

## Count

130 cases: 126 mapped above (the 8 + 2 + 1 + … rows list each id), 4 not written. The rows with a `[…/n]` param carry one case per param; the multi-case row (R-HEX-SAVE-001.1 …) carries 13 case ids in 4 params. Uncovered by design: the four above. Shared-file retargets (I-8.3 (e)): see `E4-test.md`.
