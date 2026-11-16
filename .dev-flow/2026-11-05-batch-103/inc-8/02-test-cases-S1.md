# Inc 8 — test cases of group S1 (`s19_app/tui/definition_sheet.py`, pure model)

Tester `test-s1`, E4. Format: `<requirement id>/<n> | example id | test name | full or partial`. Files: `tests/test_b103_inc8_s1.py` (F1), `tests/test_b103_inc8_s1_detail.py` (F2), support `tests/support/b103_inc8_s1.py`. Expected values come from `evidence-e2/examples_inc8.py` (loaded as `EX`), from I-2, or from the requirement's own text.

Partial = a stand-in sits in the chain (a `replace` copy carrying a refusal, a lazy image) or the case's second half lives in the widget (S2) or group A.

| Case | Example | Test name | full / partial |
|---|---|---|---|
| R-PE-DEF.5/1..3 | EX-W1 | F1 `test_r_pe_def_5_header_labels_start_where_the_widths_put_them[96,118,200]` | full |
| R-PE-DEF.6/1..3 | EX-W1 | F1 `test_r_pe_def_6_widths_follow_the_examples_of_every_class[80…220]` | full |
| R-PE-DEF.7/1..3 | EX-W2 | F1 `test_r_pe_def_7_no_painted_line_is_wider_than_the_sheet[80,118,220]` (row lines and header; detail/tail widths: F2 R-PE-DEF.41) | partial |
| R-PE-DEF.7/4 | EX-W3 | F1 `test_r_pe_def_7_wide_characters_are_clipped_by_cells_not_by_length` | full |
| R-PE-DEF.15/1 | EX-R4 | F1 `test_r_pe_def_15_a_long_name_is_clipped_with_an_ellipsis` | full |
| R-PE-DEF.15/2 | EX-H1 | F1 `test_r_pe_def_15_a_name_with_brackets_is_shown_literally` (model: a `Text`, no markup parse) | partial |
| R-PE-DEF.16/1..3 | EX-D1, V1, R5 | F1 `test_r_pe_def_16_kind_word_is_the_char_type_or_measurement` (+ the `?` case) | full |
| R-PE-DEF.17/1..4 | EX-D2, D1, D3, V1 | F1 `test_r_pe_def_17_current_value_texts_of_the_four_scalar_rows` (+ MASK_BIT) | full |
| R-PE-DEF.18/1 | EX-R6 | F1 `test_r_pe_def_18_no_image_shows_dashes` | full |
| R-PE-DEF.18/2 | EX-R6 | F1 `test_r_pe_def_18_an_image_missing_the_second_byte_shows_dashes` | full |
| R-PE-DEF.19/1 | EX-R7 | F1 `test_r_pe_def_19_a_refused_definition_shows_refused` (real I-2 refusal: unknown name) | full |
| R-PE-DEF.19/2 | EX-R7 | F1 `test_r_pe_def_19_a_second_refusal_code_shows_refused_too` (stand-in refusal object) | partial |
| R-PE-DEF.20/1 | EX-D2 | F1 `test_r_pe_def_20_unit_column_is_the_unit` | full |
| R-PE-DEF.20/2 | EX-H2 | F1 `test_r_pe_def_20_a_control_character_in_a_unit_becomes_fffd` | full |
| R-PE-DEF.21/1 | EX-D2 | F1 `test_r_pe_def_21_limits_cell_holds_the_short_limits_and_the_current_mark_on_its_cell` (+ `short_number` tests) | full |
| R-PE-DEF.21/2 | EX-D2 | F1 `test_r_pe_def_21_a_track_under_six_cells_gives_the_dots_form` | full |
| R-PE-DEF.21/3 | EX-R8 | F1 `test_r_pe_def_21_no_limits_shows_a_dash` | full |
| R-PE-DEF.21/4 | EX-D4 | F1 `test_r_pe_def_21_a_value_above_the_upper_limit_sits_on_the_right_end` (+ left end, preview mark) | full |
| R-PE-DEF.22/1,2 | EX-K1 | F1 `test_r_pe_def_22_the_selected_row_has_the_pointer_in_its_mark_cell` (mark only; moving the selection is S2) | partial |
| R-PE-DEF.23/1..3 | EX-S1, S3, S2 | F1 `test_r_pe_def_23_a_staged_number…`, `…bit_mask…`, `…enum…` (entry bytes encoded by I-2) | full |
| R-PE-DEF.23/4 | EX-R9 | F1 `test_r_pe_def_23_a_fallback_row_with_a_raw_entry_over_its_span_is_staged` (+ unchanged-entry control) | full |
| R-PE-DEF.24/1,2 | EX-P1, P2 | F1 `test_r_pe_def_24_a_pending_number…`, `…a_pending_enum…`; F2 `test_r_pe_def_24_preview_of_…` | full |
| R-PE-DEF.24/3 | EX-K5 | not in S1: "pending" is the sheet's dict (S2) | uncovered |
| R-PE-DEF.25/1,2 | EX-P3, P4 | F1 `test_r_pe_def_25_a_refused_preview_shows_the_typed_text_in_new`, `…a_long_refused_text_is_clipped…` | full |
| R-PE-DEF.26/1..5 | EX-P1, S1, P2, P5, P6 | F1 `test_r_pe_def_26_…` (five tests, through `row_line`) | full |
| R-PE-DEF.27/1 | EX-P7 | F1 `test_r_pe_def_27_a_refused_preview_shows_refused_in_the_delta_column` | full |
| R-PE-DEF.28/1 | EX-D2 | F1 `test_r_pe_def_28_an_untouched_row_shows_a_dot_and_no_delta` | full |
| R-PE-DEF.31/1..5 | EX-D2, D1, D3, V1, R11 | F2 `test_r_pe_def_31_…` (five tests) | full |
| R-PE-DEF.32/1 | EX-R7 | F2 `test_r_pe_def_32_a_refused_row_shows_its_message_as_the_detail` (real I-2 refusal) | full |
| R-PE-DEF.33/1,2 | EX-D1, P2 | F2 `test_r_pe_def_33_…` | full |
| R-PE-DEF.34/1,2 | EX-D3, P5 | F2 `test_r_pe_def_34_…` (the marked-bit cells are not pinned) | partial |
| R-PE-DEF.35/1,2 | EX-V1, P6 | F2 `test_r_pe_def_35_text_rows_show_the_image_bytes_16_per_row`, `…pending_text_rows_paint_the_changed_bytes_in_one_other_style` | full |
| R-PE-DEF.36/1 | EX-R7 | F2 `test_r_pe_def_36_a_refused_row_gets_the_inspector_text_with_its_kind_word` ("input disabled" is S2) | partial |
| R-PE-DEF.36/2,3 | EX-R9, T1 | F2 `test_r_pe_def_36_a_row_with_no_editor_gets_the_inspector_text` + F1 `…unknown_kinds_take_the_fallback…` ("input disabled" is S2) | partial |
| R-PE-DEF.36/4 | EX-T1 | F2 `test_r_pe_def_36_the_4096_byte_text_row_keeps_its_editor_and_the_text_tail` + F1 `…scalar_kinds_are_editable_and_the_text_span_bound_is_4096` | partial |
| R-PE-DEF.37/1..4 | EX-D2, D1, D3, V1 | F1 `test_r_pe_def_37_formula_label_per_kind`, `…labels_of_the_four_scalar_rows…` (label only; the bar's name placement is S2) | partial |
| R-PE-DEF.38/1,2 | EX-V1, K5 | F2 `test_r_pe_def_38_a_text_row_fills_with_its_current_text_until_edited` (`formula_fill`; the input is S2) | partial |
| R-PE-DEF.39/1,2 | EX-K3 | F2 `test_r_pe_def_39_other_rows_fill_with_their_pending_text_only` (same limit) | partial |
| R-PE-DEF.40/1..4 | EX-P1, D4, P3, P6 | F2 `test_r_pe_def_40_…` (five tests incl. the 100-cell form) | full |
| R-PE-DEF.41/1,2 | EX-P4 | F2 `test_r_pe_def_41_a_long_refusal_is_cut_at_the_bar_edge_with_one_ellipsis[100,118,220]` | full |
| R-PE-DEF.51/1,2 | EX-O1, O2 | F2 `test_r_pe_def_51_…` (preview over the overlay; the Apply half is group A) | partial |
| R-PE-DEF.62/4 | EX-M1 | F1 `test_r_pe_def_62_a_staged_row_follows_the_image_it_is_built_over` | full |
| R-PE-DEF.70/3 | EX-H1 | F1 `test_r_pe_def_70_a_unit_with_markup_shows_every_character` (model side; markup-off rendering is S2) | partial |
| R-PE-DEF.71/1..3 | EX-H2 | F1 `test_r_pe_def_71_plain_replaces_every_control_character_and_keeps_brackets`, `…in_a_name…`, unit test above | full |
| R-PE-DEF.72/1,2 | EX-H4 | F1 `test_r_pe_def_72_name_echo_caps_at_256_characters_and_cleans_controls` (the status message is group A) | partial |
| R-PE-DEF.75/1,2 | EX-R9 | F1 `test_r_pe_def_75_fallback_rows_show_the_element_count_or_dashes` | full |
| R-PE-DEF.76/1,2 | EX-R10 | F1 `test_r_pe_def_76_limits_not_ascending_paint_the_dots_form_without_a_division[5 5, 9 1]` | full |
| R-PE-DEF.77/1,2 | EX-R10 | F1 `test_r_pe_def_77_limits_not_ascending_leave_the_percent_out_of_the_delta[…]` | full |
| R-PE-DEF.78/1,2 | EX-T1 | F2 `test_r_pe_def_78_a_row_with_no_editor_fills_empty[4097,1048576]` (`formula_fill`; the input is S2) | partial |
| R-PE-DEF.79/1..3 | EX-T1 | F2 `test_r_pe_def_79_a_long_text_span_shows_four_rows_and_the_cut_line[65,4097,1048576]` (+ 64-byte boundary) | full |
| R-PE-DEF.80/1 | EX-T2 | F2 `test_r_pe_def_80_a_fill_is_capped_to_4096_characters` (`formula_fill`; the choose route is S2) | partial |
| R-PE-DEF.81/1..4 | EX-K4, K6 | F1 `test_r_pe_def_81_row_window_examples[7 rows]`, `…sweep…` (the pure window; painting in the body is S2) | partial |
| R-PE-DEF.88/1,2 | EX-T1 | F1 `test_r_pe_def_88_a_text_span_over_4096_shows_its_length_and_is_not_decoded[4097,1048576]` | full |
| I-8.1 | EX-O1, R6 | F1 `test_i81_overlay_*`, `test_r_pe_def_18_overlay_without_image_…` | full |
| S1 purity | — | F1 `test_s1_module_has_no_module_level_textual_import` (AST of the module source, orchestrator note) | full |

## Not covered by group S1 (named)

R-PE-DEF.10 … .14 (`show_page`, S2; .12 is a timing and HT-08 forbids deciding it on the shared runner, only the lookup bound is asserted in the .88/.78/.79 tests), .24/3, .30, .38/.39 input side, .42, .45 … .49, .70/1,2,4,5, .50 … .64, .73, .83 … .87 (groups S2, A), layout rows (group P). `delta_text` and `limits_cell`'s value argument are exercised through `row_line` and the pinned `limits_cell(row, number|None, width)`; `delta_text`'s own `value` argument is not pinned (finding in `E4-test-s1.md`).
