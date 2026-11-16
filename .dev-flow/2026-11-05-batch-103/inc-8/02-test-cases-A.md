# Inc 8 — test cases, group A (staging and help) — E4 `test-a`

One row per alternative of a requirement of group A (R-PE-DEF.50 … .64, .73, .83 … .87, R-PE-034, R-PE-035, R-PE-110), from `02-test-cases.md` (E1, corrected at E3R1). The last two columns are the tester's: the test node(s) as they exist on disk, and full / partial under the tester card (full only when the product itself produces what the test asserts). A case's result comes from the test run, never from this file. Expected values come from `evidence-e2/examples_inc8.py` and I-2 itself (`encode_definition` / `decode_definition` over the DEFC image), never retyped.

| Case | Example | Objective — verify that … (expected) | Class | Test (path::name) | full / partial |
|---|---|---|---|---|---|
| R-PE-DEF.50/1 | EX-S1 | DISPLAY_0001 `25.5` → bytes entry 0x800020 `00 33` | N | tests/test_b103_inc8_a1_service.py::test_r_pe_def_50_1_display_25_5_stages_one_bytes_entry; tests/test_b103_inc8_a2_app.py::test_r_pe_def_50_1_app_display_25_5_through_the_sheet_message | full |
| R-PE-DEF.50/2 | EX-S2 | ENUM_0001 `RUN` → `02` at 0x800000 | N | tests/test_b103_inc8_a1_service.py::test_r_pe_def_50_2_enum_run_stages_02 | full |
| R-PE-DEF.50/3 | EX-S3 | MASK_FIELD_0001 `255` → `1F F7` at 0x800010 | N | tests/test_b103_inc8_a1_service.py::test_r_pe_def_50_3_masked_field_255_stages_1f_f7 | full |
| R-PE-DEF.50/4 | EX-S4 | V171 ASCII `ABC` → 42 bytes at 0x810200 | N | tests/test_b103_inc8_a1_service.py::test_r_pe_def_50_4_v171_ascii_abc_stages_42_bytes | full |
| R-PE-DEF.51/1 | EX-O1 | AT: MASK_FIELD `255` then MASK_BIT `0`, Apply → `255`, `0`, word `1F F6` | N | tests/test_b103_inc8_a1_service.py::test_r_pe_def_51_1_field_then_bit_decode_as_typed; tests/test_b103_inc8_a2_app.py::test_r_pe_def_51_1_app_field_then_bit_through_the_sheet | full |
| R-PE-DEF.51/2 | EX-O2 | AT: MASK_BIT `0` then MASK_FIELD `255`, Apply → `255`, `0`, word `1F F6` | N | tests/test_b103_inc8_a1_service.py::test_r_pe_def_51_2_bit_then_field_decode_as_typed | full |
| R-PE-DEF.51/3 | EX-O3 | MASK_FIELD `255`, Apply, Remove, then MASK_BIT `0` → entry `1A E6`, MASK_FIELD `174` | R | tests/test_b103_inc8_a1_service.py::test_r_pe_def_51_3_apply_remove_then_bit_over_the_source_view; tests/test_b103_inc8_a2_app.py::test_r_pe_def_51_3_app_handler_encodes_over_the_source_view | full |
| R-PE-DEF.52/1 | EX-S5 | DISPLAY_0001 `25.5` then `30` → one entry `00 3C` | N | tests/test_b103_inc8_a1_service.py::test_r_pe_def_52_1_second_stage_of_one_span_replaces_the_entry | full |
| R-PE-DEF.52/2 | EX-O1 | the two masked fields → one entry at 0x800010 | N | tests/test_b103_inc8_a1_service.py::test_r_pe_def_52_2_two_masked_fields_make_one_entry | full |
| R-PE-DEF.52/3 | EX-S8 | a 42-character `string` entry at 0x810200, V171 ASCII `XYZ` staged, saved, read back → `"type": "bytes"`, decodes `XYZ` | R | tests/test_b103_inc8_a1_service.py::test_r_pe_def_52_3_string_entry_replaced_by_bytes_entry_round_trips | full |
| R-PE-DEF.53/1 | EX-S1 | DISPLAY_0001 → symbol `DISPLAY_0001`, type bytes | N | tests/test_b103_inc8_a1_service.py::test_r_pe_def_53_1_no_intersect_appends_with_the_row_name_as_symbol | full |
| R-PE-DEF.54/1 | EX-O1 | MASK_FIELD then MASK_BIT → symbol `MASK_FIELD_0001` | N | tests/test_b103_inc8_a1_service.py::test_r_pe_def_54_1_replace_keeps_the_old_symbol | full |
| R-PE-DEF.55/1 | EX-F1 | raw entry at 0x800021 (1 B), stage DISPLAY_0001 → refused, status, document unchanged | R | tests/test_b103_inc8_a1_service.py::test_r_pe_def_55_1_entry_inside_the_span_refuses | full |
| R-PE-DEF.55/2 | EX-F1 | entry 0x80001F…0x800020, stage DISPLAY_0001 → refused | R | tests/test_b103_inc8_a1_service.py::test_r_pe_def_55_2_entry_straddling_the_start_refuses | full |
| R-PE-DEF.56/1 | EX-P3 | `abc` → document unchanged | R | tests/test_b103_inc8_a1_service.py::test_r_pe_def_56_1_abc_leaves_the_document_unchanged | full |
| R-PE-DEF.56/2 | EX-P7 | `250` → unchanged | R | tests/test_b103_inc8_a1_service.py::test_r_pe_def_56_2_250_leaves_the_document_unchanged | full |
| R-PE-DEF.56/3 | EX-P8 | `WALK` → unchanged | R | tests/test_b103_inc8_a1_service.py::test_r_pe_def_56_3_walk_leaves_the_document_unchanged | full |
| R-PE-DEF.57/1 | EX-P7 | `250` → status text | R | tests/test_b103_inc8_a2_app.py::test_r_pe_def_57_1_250_status_line | full |
| R-PE-DEF.57/2 | EX-P3 | `abc` → status text | R | tests/test_b103_inc8_a2_app.py::test_r_pe_def_57_2_abc_status_line | full |
| R-PE-DEF.57/3 | EX-P8 | `WALK` → status text | R | tests/test_b103_inc8_a2_app.py::test_r_pe_def_57_3_walk_status_line | full |
| R-PE-DEF.58/1 | EX-S1 | `Patch Editor: DISPLAY_0001 staged as 25.5 (2 B at 0x800020).` | N | tests/test_b103_inc8_a1_service.py::test_r_pe_def_58_1_message_of_a_display_stage; tests/test_b103_inc8_a2_app.py::test_r_pe_def_50_1_app_display_25_5_through_the_sheet_message | full |
| R-PE-DEF.58/2 | EX-S2 | `Patch Editor: ENUM_0001 staged as RUN (1 B at 0x800000).` | N | tests/test_b103_inc8_a1_service.py::test_r_pe_def_58_2_message_of_an_enum_stage | full |
| R-PE-DEF.58/3 | EX-S9 | a 4,000-byte V171 copy staged with 300 × `x` → `<text>` = 256 × `x` + `…` | R | tests/test_b103_inc8_a1_service.py::test_r_pe_def_58_3_shown_text_of_300_chars_is_clipped_to_256_and_an_ellipsis | partial (shown handed to _stage_encoded; the widened-A2L route is not built) |
| R-PE-DEF.59/1 | EX-D4 | `175` → the status line is exactly `Patch Editor: <notice>` (no `[…] warning:`) | N | tests/test_b103_inc8_a1_service.py::test_r_pe_def_59_1_notice_is_in_notices_not_in_issues; tests/test_b103_inc8_a2_app.py::test_r_pe_def_59_1_app_notice_is_a_status_line_of_its_own | full |
| R-PE-DEF.60/1 | EX-S1 | stage → next row selected | N | tests/test_b103_inc8_a2_app.py::test_r_pe_def_60_1_stage_selects_the_next_row | full |
| R-PE-DEF.60/2 | EX-S6 | stage on the last row → stays | R | tests/test_b103_inc8_a2_app.py::test_r_pe_def_60_2_stage_on_the_last_row_stays | full |
| R-PE-DEF.60/3 | EX-S10 | selection moved down two rows before the stage was handled → the row after DISPLAY_0001 | R | tests/test_b103_inc8_a2_app.py::test_r_pe_def_60_3_selection_moved_before_the_stage_is_handled | full |
| R-PE-DEF.60/4 | EX-S10 | a stage reported with no advance (Inc 9's record-stage call) → selection unchanged | R | tests/test_b103_inc8_a2_app.py::test_r_pe_def_60_4_note_staged_without_advance_keeps_the_selection | full |
| R-PE-DEF.61/1 | EX-S1 | stage then Undo → the document before the stage; undo depth +1 | N | tests/test_b103_inc8_a1_service.py::test_r_pe_def_61_1_stage_adds_one_undo_step_and_undo_restores; tests/test_b103_inc8_a2_app.py::test_r_pe_def_50_1_app_display_25_5_through_the_sheet_message | full |
| R-PE-034/1 | EX-S1 | stage DISPLAY_0001 `25.5` → dirty set | N | tests/test_b103_inc8_a2_app.py::test_r_pe_034_1_stage_sets_the_dirty_flag | full |
| R-PE-035/1 | EX-P3 | `abc` refused, flag clear → stays clear | R | tests/test_b103_inc8_a2_app.py::test_r_pe_035_1_refused_stage_keeps_the_flag_clear | full |
| R-PE-035/2 | EX-P3 | `abc` refused, flag set → stays set | R | tests/test_b103_inc8_a2_app.py::test_r_pe_035_2_refused_stage_keeps_the_flag_set | full |
| R-PE-DEF.62/1 | EX-S1 | Undo of a stage → `●` gone | N | tests/test_b103_inc8_a2_app.py::test_r_pe_def_62_1_undo_of_a_stage_clears_the_mark | full |
| R-PE-DEF.62/2 | EX-O1 | Remove of the 0x800010 entry → both masked rows unstaged | N | tests/test_b103_inc8_a2_app.py::test_r_pe_def_62_2_remove_of_the_word_entry_unstages_both_rows | full |
| R-PE-DEF.62/3 | EX-S7 | Parse pasted with a DISPLAY_0001 entry → `●` on it | N | tests/test_b103_inc8_a2_app.py::test_r_pe_def_62_3_parse_pasted_marks_the_row | full |
| R-PE-DEF.62/4 | EX-M1 | MASK_FIELD `255` staged over `1A E7`, then an image with `1A E6` → MASK_BIT `●`, New `1 (0x01)` | R | tests/test_b103_inc8_a2_app.py::test_r_pe_def_62_4_new_image_word_changes_the_staged_cue | partial (image handed through set_image_mem_map, not a file load) |
| R-PE-110/1 | EX-B1 | a session action held running → Enter on DISPLAY_0001 `25.5` → busy line, document and dirty flag unchanged | R | tests/test_b103_inc8_a2_app.py::test_r_pe_110_1_stage_refused_while_a_session_action_runs | full |
| R-PE-DEF.63/1 | EX-F2 | A2L unloaded between selection and Enter → status, nothing staged | R | tests/test_b103_inc8_a2_app.py::test_r_pe_def_63_1_no_a2l_refuses_the_stage | full |
| R-PE-DEF.64/1 | EX-F3 | reload moving DISPLAY_0001 to 0x800030, stage before the repaint → entry at 0x800030 | R | tests/test_b103_inc8_a2_app.py::test_r_pe_def_64_1_stage_describes_again_with_the_a2l_loaded_now | full |
| R-PE-DEF.73/1 | EX-H1 | `A[b]` refusal on the status line → `[b]` shown | R | tests/test_b103_inc8_a2_app.py::test_r_pe_def_73_1_status_line_is_plain_text | full |
| R-PE-DEF.83/1 | EX-HL1 | step 1 names the filter row, STAGING SHEET, LANDS IN and the four tabs | N | tests/test_b103_inc8_a3_help.py::test_r_pe_def_83_1_step_one_names_the_regions_and_four_tabs | full |
| R-PE-DEF.83/2 | EX-HL1 | no step names an A2L tab, `A2L PARAMETERS`, "on the left" or "on the right" | R | tests/test_b103_inc8_a3_help.py::test_r_pe_def_83_2_no_step_names_the_a2l_tab_or_a_side | full |
| R-PE-DEF.84/1 | EX-HL1 | a `Patch script — …` line whose effect holds `entries` | N | tests/test_b103_inc8_a3_help.py::test_r_pe_def_84_1_patch_script_line_names_entries | full |
| R-PE-DEF.85/1 | EX-HL1 | a `STAGING SHEET — …` line holding `↑↓`, `enter`, `←→`, `esc` | N | tests/test_b103_inc8_a3_help.py::test_r_pe_def_85_1_staging_sheet_line_names_the_keys | full |
| R-PE-DEF.86/1 | EX-HL1 | `new =` line naming Enter as the stage key | N | tests/test_b103_inc8_a3_help.py::test_r_pe_def_86_1_new_label_line | full |
| R-PE-DEF.86/2 | EX-HL1 | `field =` line | N | tests/test_b103_inc8_a3_help.py::test_r_pe_def_86_2_field_label_line | full |
| R-PE-DEF.86/3 | EX-HL1 | `text =` line | N | tests/test_b103_inc8_a3_help.py::test_r_pe_def_86_3_text_label_line | full |
| R-PE-DEF.87/1 | EX-HL1 | `Use parameter` effect holds `Inspector` and `selected row`, not `A2L tab` | N | tests/test_b103_inc8_a3_help.py::test_r_pe_def_87_1_use_parameter_uses_the_selected_row | full |

**Uncovered (named):** R-PE-DEF.72/1 (the 300-character name echo in the overlap status) is group S's row by `E1-slice.md` §2 and is not in this group's list; the service-level echo is still exercised by R-PE-DEF.58/3 (shown text). R-PE-DEF.58/3 and R-PE-DEF.62/4 are partial as marked. Nothing else of the group is uncovered.
