# Inc 8 — test cases of group S2 (the `StagingSheet` widget and `A2LParameterPicker.definitions`)

Tester `test-s2`, E4. Nodes S13 … S19, S15', S17', S19', S22 (`E1-slice.md` §2 and its E3R1 table; the E3R1 rows override). Interface I-8.4 of `codewire/graph-inc8.md` §Interfaces. Row format: `<requirement id>/<n> | example id | test name | full or partial`. The case ids `/1 …` are those of `02-test-cases.md`; ids marked **(S2)** are alternatives this group adds for its own node (a pinned interface fact with no E1 case). A case is **full** only when the product itself produces what the test asserts; **partial** says what is left to another group.

Files (all under `tests/`): `test_b103_inc8_s2_picker_definitions.py` (S22), `test_b103_inc8_s2_sheet_rows.py`, `test_b103_inc8_s2_sheet_formula.py`, `test_b103_inc8_s2_sheet_keys.py`; shared builders `tests/support/b103_inc8_s2.py`.

Method notes (E3 rulings kept): the widget is mounted alone in a minimal textual `App` (`run_test`); the body text is read from `#patch_sheet_body` and cut into columns where the header words start (no hand-counted slices); the formula bar is read by its DOM order (name, label, input, tail) and the input by `#patch_sheet_input`; bytes to stage come from I-2's `encode_definition`; markup variants are text replacements of the committed `definitions` case re-parsed by the app's A2L parser. Paste over 4,096 characters is refused, not truncated (E3R2). Escape is checked under an App that binds Escape as a back action and counts it. The OS clipboard is stood in by an autouse fixture that fails any test reaching it.

Test-environment assumption (declared, not a requirement): the test App gives the sheet `height: 1fr` and `#patch_sheet_body { height: 1fr }` (or a fixed height for the two small-window cases), as the panel's `#patch_sheet_win` does.

## S22 — `A2LParameterPicker.definitions` (`test_b103_inc8_s2_picker_definitions.py`)

| Case | Example | Test name | full / partial |
|---|---|---|---|
| R-PE-DEF.11/4 (S2) | EX-R2 | `test_r_pe_def_11_4_definitions_equal_the_i2_describe_of_the_population` | full |
| R-PE-DEF.11/5 (S2) | EX-R12 | `test_r_pe_def_11_5_definitions_source_is_the_populating_payload` | full |
| R-PE-DEF.11/6 (S2) | EX-R2 | `test_r_pe_def_11_6_an_equal_signature_keeps_both_and_describes_nothing` | full |
| R-PE-DEF.11/7 (S2) | EX-R2 | `test_r_pe_def_11_7_a_changed_signature_replaces_both` | full |
| R-PE-DEF.11/8 (S2) | EX-R3 | `test_r_pe_def_11_8_without_a2l_data_the_pair_is_empty_and_none` | full |
| R-PE-DEF.11/9 (S2) | I-8.4 | `test_r_pe_def_11_9_definitions_are_read_only` | full |

## Rows (`test_b103_inc8_s2_sheet_rows.py`)

| Case | Example | Test name | full / partial |
|---|---|---|---|
| R-PE-DEF.10/1 | EX-R1 | `test_r_pe_def_10_1_a_population_shows_one_row_per_name_in_page_order` | partial (the sheet half: the picker's `ViewChanged` route is group P's) |
| R-PE-DEF.10/2 | EX-R1 | `test_r_pe_def_10_2_a_filtered_page_shows_only_its_names` | partial (same) |
| R-PE-DEF.10/3 | EX-R1 | `test_r_pe_def_10_3_a_page_turn_replaces_the_rows` | partial (a 4-name then a 1-name page, not a 201-name list) |
| R-PE-DEF.11/1 | EX-R2 | `test_r_pe_def_11_1_a_reload_that_changes_a_table_text_shows_the_new_text` | partial (the picker's repopulation is S22's file) |
| R-PE-DEF.11/2 | EX-R2 | `test_r_pe_def_11_2_page_turns_and_filter_changes_describe_nothing` | partial (the sheet's calls only; spies on both I-2 names in three modules) |
| R-PE-DEF.11/3 | EX-R12 | `test_r_pe_def_11_3_the_sheet_uses_the_page_a2l_not_the_apps` | partial (the app's payload is a stand-in attribute on the host App; expected `287.0` from I-2's own decode text; E5, P-045) |
| R-PE-DEF.12/1 | EX-C1 | `test_r_pe_def_12_1_a_200_name_software_a_page_paints_within_half_a_second` | partial (`show_page` + `_paint` median of 5 ≤ 0.5 s; load-sensitive, unverified until run on a quiet host; the image is zero bytes over every span) |
| R-PE-DEF.12/2 | EX-T3 | `test_r_pe_def_12_2_a_page_of_200_one_mebibyte_text_spans_paints_within_half_a_second` | partial (same) |
| R-PE-DEF.13/1 | EX-R3 | `test_r_pe_def_13_1_a_filter_with_no_match_shows_the_line` | partial (the filter is the picker's) |
| R-PE-DEF.13/2 | EX-R3 | `test_r_pe_def_13_2_an_a2l_with_no_addressed_tag_shows_the_line` | partial (an empty page with the A2L present; no real A2L without an addressed tag) |
| R-PE-DEF.14/1 | EX-R3 | `test_r_pe_def_14_1_no_a2l_at_start_shows_the_line` | full |
| R-PE-DEF.14/2 | EX-R3 | `test_r_pe_def_14_2_an_unloaded_a2l_shows_the_line` | partial (the unload path is the panel's) |
| R-PE-DEF.18/1 | EX-R6 | `test_r_pe_def_18_1_no_image_shows_dashes` | full |
| R-PE-DEF.18/2 | EX-R6 | `test_r_pe_def_18_2_an_image_missing_the_second_byte_shows_dashes` | full |
| R-PE-DEF.30/1,2 | — | `test_r_pe_def_30_1_the_detail_moves_with_the_selection` (added at E4 integration) | full |
| R-PE-DEF.23/1 | EX-S1 | `test_r_pe_def_23_n_a_staged_row_shows_the_dot_and_its_staged_value[23-1-display]` | partial (the entries are handed to `set_document` as the panel would: bytes encoded by I-2) |
| R-PE-DEF.23/2 | EX-S3 | `…test_r_pe_def_23_n_…[23-2-mask-field]` | partial (same) |
| R-PE-DEF.23/3 | EX-S2 | `…test_r_pe_def_23_n_…[23-3-enum]` | partial (same) |
| R-PE-DEF.23/4 | EX-R9 | `test_r_pe_def_23_4_a_raw_entry_over_a_fallback_row_marks_it_staged` | partial (same; the `cuboid` copy) |
| R-PE-DEF.24/1 | EX-P1 | `test_r_pe_def_24_1_a_pending_number_shows_the_diamond_and_the_previews_text` | full |
| R-PE-DEF.24/2 | EX-P2 | `test_r_pe_def_24_2_a_pending_enum_shows_the_stored_value_and_text` | full |
| R-PE-DEF.24/3 | EX-K5 | `test_r_pe_def_24_3_a_text_row_left_with_its_row_fill_unchanged_is_not_pending` | full |
| R-PE-DEF.25/1 | EX-P3 | `test_r_pe_def_25_1_a_refusal_shows_the_formula_text_in_new` | full |
| R-PE-DEF.25/2 | EX-P4 | `test_r_pe_def_25_2_a_long_refusal_text_is_clipped_with_an_ellipsis` | full |
| R-PE-DEF.62/1 | EX-S1 | `test_r_pe_def_62_1_an_undo_that_empties_the_document_clears_the_dot` | partial (`set_document` called directly; the panel's refresh route is P5) |
| R-PE-DEF.62/2 | EX-O1 | `test_r_pe_def_62_2_removing_the_masked_entry_unstages_both_masked_rows` | partial (same) |
| R-PE-DEF.62/3 | EX-S7 | `test_r_pe_def_62_3_a_replaced_document_restages_by_its_own_entries` | partial (same; no real Parse pasted) |
| R-PE-DEF.62/4 | EX-M1 | `test_r_pe_def_62_4_a_new_image_restages_the_bit_row_over_the_new_word` | partial (same; the image swap is `set_document`'s second argument) |
| R-PE-DEF.70/1 | EX-H1 | `test_r_pe_def_70_1_an_enum_text_with_a_closing_tag_is_shown_literally` | full |
| R-PE-DEF.70/2 | EX-H1 | `test_r_pe_def_70_2_an_enum_text_with_an_action_link_paints_no_link` | full (no `@click` style span in the painted content, app still running) |
| R-PE-DEF.70/3 | EX-H1 | `test_r_pe_def_70_3_a_unit_with_brackets_shows_every_character` | full (220 columns, so the Unit column fits seven characters) |
| R-PE-DEF.70/4 | EX-H1 | `test_r_pe_def_70_4_a_refusal_tail_shows_the_formula_text_literally` | full |
| R-PE-DEF.70/5 | EX-H6 | `test_r_pe_def_70_5_a_row_named_like_a_closing_tag_selects_without_an_exception` | full |

## Formula bar (`test_b103_inc8_s2_sheet_formula.py`)

| Case | Example | Test name | full / partial |
|---|---|---|---|
| R-PE-DEF.37/1 | EX-D2 | `test_r_pe_def_37_n_the_bar_shows_the_row_name_and_its_kind_label[37-1-number]` | full |
| R-PE-DEF.37/2 | EX-D1 | `…[37-2-enum]` | full |
| R-PE-DEF.37/3 | EX-D3 | `…[37-3-bit-mask]` | full |
| R-PE-DEF.37/4 | EX-V1 | `…[37-4-text]` | full |
| R-PE-DEF.38/1 | EX-V1 | `test_r_pe_def_38_1_a_selected_text_row_fills_the_input_with_its_text` | full |
| R-PE-DEF.38/2 | EX-K5 | `test_r_pe_def_38_2_an_edited_text_row_keeps_its_edit_when_reselected` | full |
| R-PE-DEF.39/1 | EX-K3 | `test_r_pe_def_39_1_a_row_never_edited_has_an_empty_input` | full |
| R-PE-DEF.39/2 | EX-K3 | `test_r_pe_def_39_2_a_pending_row_gets_its_pending_text_back` | full |
| R-PE-DEF.40/1 | EX-P1 | `test_r_pe_def_40_1_a_good_value_shows_the_check_tail` | full (200 columns) |
| R-PE-DEF.40/2 | EX-D4 | `test_r_pe_def_40_2_a_value_between_limits_and_extended_limits_shows_the_notice` | full |
| R-PE-DEF.40/3 | EX-P3 | `test_r_pe_def_40_3_a_refused_text_shows_the_refusal_message` | full |
| R-PE-DEF.40/4 | EX-P6 | `test_r_pe_def_40_4_a_text_row_shows_the_character_count_tail` | full |
| R-PE-DEF.41/1 | EX-P4 | `test_r_pe_def_41_n_a_long_refusal_is_cut_at_the_bars_edge_with_an_ellipsis[41-1-118-columns]` | full |
| R-PE-DEF.41/2 | EX-P4 | `…[41-2-220-columns]` | full |
| R-PE-DEF.42/1 | EX-H3 | `test_r_pe_def_42_1_a_paste_over_the_cap_into_an_empty_input_leaves_it_empty` | partial (an `events.Paste` posted to the input, not a terminal's bracketed paste: E3S-11 backlog) |
| R-PE-DEF.42/2 | EX-H3 | `test_r_pe_def_42_2_a_paste_that_would_pass_the_cap_leaves_the_text_unchanged` | partial (same) |
| R-PE-DEF.42/3 | EX-H3 | `test_r_pe_def_42_3_typing_past_the_cap_keeps_the_first_4096_characters` | partial (5,000 `insert_text_at_cursor` calls, the method the key handler calls, not 5,000 pilot keys) |
| R-PE-DEF.78/1 | EX-T1 | `test_r_pe_def_78_n_a_text_row_without_an_editor_keeps_the_input_empty[78-1-4097-bytes]` | full |
| R-PE-DEF.78/2 | EX-T1 | `…[78-2-1-mebibyte]` | full |
| R-PE-DEF.50/5 (S2) | EX-P1 | `test_r_pe_def_50_n_enter_in_the_input_posts_the_request_with_the_text[50-5-display]` | partial (the request the sheet posts; the write is group A's R-PE-DEF.50/1…4) |
| R-PE-DEF.50/6 (S2) | EX-P7 | `…[50-6-refused-text]` (`250`: posted whatever the preview) | partial (same) |
| R-PE-DEF.50/7 (S2) | EX-P2 | `…[50-7-enum]` | partial (same) |
| R-PE-DEF.50/8 (S2) | EX-P5 | `…[50-8-mask-field]` | partial (same) |
| R-PE-DEF.50/9 (S2) | EX-P6 | `…[50-9-text]` | partial (same) |

## Keys, selection and the row window (`test_b103_inc8_s2_sheet_keys.py`)

| Case | Example | Test name | full / partial |
|---|---|---|---|
| R-PE-DEF.45/1 | EX-K1 | `test_r_pe_def_45_1_down_selects_the_row_below` | full |
| R-PE-DEF.45/2 | EX-K1 | `test_r_pe_def_45_2_down_again_selects_the_third_row` | full |
| R-PE-DEF.45/3 | EX-K1 | `test_r_pe_def_45_3_up_selects_the_row_above` | full |
| R-PE-DEF.45/4 | EX-K1 | `test_r_pe_def_45_4_up_on_the_first_row_keeps_it` | full |
| R-PE-DEF.45/5 (S2) | EX-K1 | `test_r_pe_def_45_5_down_on_the_last_row_keeps_it_without_wrapping` | full |
| R-PE-DEF.46/1 | EX-K1 | `test_r_pe_def_46_1_enter_on_the_sheet_moves_the_focus_to_the_formula_input` | full |
| R-PE-DEF.47/1 | EX-P2 | `test_r_pe_def_47_n_right_and_left_choose_table_entries_without_wrapping` (step 1, IDLE → RUN) | full |
| R-PE-DEF.47/2 | EX-P2 | same test (step 2, RUN → FAULT) | full |
| R-PE-DEF.47/3 | EX-P2 | same test (step 3, FAULT stays) | full |
| R-PE-DEF.47/4 (S2) | EX-P2 | same test (step 4, `left` from FAULT → RUN; the stored number `2` is never the text) | full |
| R-PE-DEF.48/1 | EX-P1 | `test_r_pe_def_48_1_escape_in_the_input_clears_the_row_and_returns_to_the_sheet` | full (the host App's own Escape action fires 0 times) |
| R-PE-DEF.49/1 | EX-K1 | `test_r_pe_def_49_1_selecting_a_row_posts_its_name` | partial (the `SelectionChanged` the sheet posts; the picker's cursor is P11's) |
| R-PE-DEF.49/2 | EX-K1 | `test_r_pe_def_49_2_a_page_turn_posts_the_new_first_row` | partial (same) |
| R-PE-DEF.60/1 | EX-S1 | `test_r_pe_def_60_1_select_after_moves_to_the_row_after_the_named_one` | partial (`select_after` called directly; the route is `note_staged`, P7') |
| R-PE-DEF.60/2 | EX-S6 | `test_r_pe_def_60_2_select_after_on_the_last_row_stays_on_it` | partial (same) |
| R-PE-DEF.60/3 | EX-S10 | `test_r_pe_def_60_3_select_after_goes_by_the_named_row_not_the_current_selection` | partial (same) |
| R-PE-DEF.60/4 | EX-S10 | not in this group: `note_staged(name, advance=False)` is group P's | uncovered here |
| R-PE-DEF.60/5 (S2) | I-8.4 | `test_r_pe_def_60_5_select_after_leaves_the_focus_where_it_was` | partial (same) |
| R-PE-DEF.82/1 | EX-S11 | `test_r_pe_def_82_1_select_after_clears_the_staged_rows_pending_text` | partial (the Undo is the document's; `select_after` direct) |
| R-PE-DEF.82/2 | EX-S11 | `test_r_pe_def_82_2_the_staged_row_selected_again_has_an_empty_input` | partial (same) |
| R-PE-DEF.81/1 | EX-K4 | `test_r_pe_def_81_1_after_40_downs_the_selected_row_and_its_detail_lie_inside_the_body` | full (118×54, software_a, 200 names) |
| R-PE-DEF.81/2 | EX-K4 | `test_r_pe_def_81_2_up_past_the_first_painted_row_makes_it_the_first_painted_row` | full |
| R-PE-DEF.81/3 | EX-K4 | `test_r_pe_def_81_3_an_enum_row_reached_from_above_paints_its_three_detail_lines` | partial (DEFC clones in an 8-row body, not software_a's first enum) |
| R-PE-DEF.81/4 | EX-K6 | `test_r_pe_def_81_4_a_detail_taller_than_the_window_is_cut_and_the_row_stays_painted` | partial (a stand-in kind registered in `_KIND_OPS`, as the requirement says) |

## Uncovered by this group (named)

- R-PE-DEF.60/4 (`note_staged(advance=False)`): group P.
- R-PE-DEF.40: the "preview over the overlay, not the image" case (masked, R-PE-DEF.51) belongs to S1 `preview` and group A; the sheet's tail is tested for the four examples of the row only.
- R-PE-DEF.49: the picker cursor itself (P11); R-PE-DEF.10/11 triggers (P10).
- `KindOps.bar` and `KindOps.cells` (Inc 9 hooks): not exercised by Inc 8's kinds.
- R-PE-DEF.12: the 0.5 s bound is a timing node; it runs on a loaded shared host here and is `unverified` until timed on a quiet one (HT-08).
- R-PE-DEF.42: a real terminal bracketed paste (E3S-11 backlog).
