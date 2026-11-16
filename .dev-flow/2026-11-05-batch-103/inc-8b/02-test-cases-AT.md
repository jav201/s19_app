# Inc 8b — acceptance test cases (E4, AT tester `T8b-AT`)

Author: AT tester (E4), model claude-sonnet-5-5. Black-box: every case drives the real app (`S19TuiApp` under Textual's pilot) with the synthetic definitions case (DEFC, seed 20260001) loaded through the app's own loaders, by keys, reading the shipped widgets by id. Expected values are keys of `evidence-e1/examples_inc8b-transcript.txt`, loaded in the test and never retyped. File: `tests/test_b103_inc8b_at.py` (12 nodes).

| AT | Chain (one node each, C-18) | Requirement cases | Node |
|---|---|---|---|
| AT-B103-I8B-1 | 118×54: open the sheet → scrollbar shown over 143 cells → End (read at once) → Home | R-PE-DEF.92/1, .94/1, .94/2, .94/6 | `test_at_b103_i8b_1_grid_118x54_shows_scrollbar_end_goes_to_last_columns_home_back` |
| AT-B103-I8B-2 | 80×24: scrollbar shown → End | R-PE-DEF.92/2, .94/3 | `test_at_b103_i8b_2_grid_80x24_shows_scrollbar_and_end_goes_to_last_columns` |
| AT-B103-I8B-3 | 220×60: no scrollbar, body takes its row, End stays at 0 | R-PE-DEF.93/1, .94/4 | `test_at_b103_i8b_3_grid_220x60_has_no_scrollbar_and_end_does_not_move` |
| AT-B103-I8B-4 | End on the body, Enter, type `25.5`, Home / End in the input move the cursor, x unchanged | R-PE-DEF.94/5 | `test_at_b103_i8b_4_home_end_in_the_formula_input_move_its_cursor_not_the_grid` |
| AT-B103-I8B-5 | Tab ring with the scrollbar shown = the base's ring; `patch_sheet_grid` never focused | R-PE-DEF.92/3 | `test_at_b103_i8b_5_scrollbar_adds_no_tab_stop_and_the_grid_never_holds_the_focus` |
| AT-B103-I8B-6 | ENUM_0001 selected → card lines; → `(●) 2 RUN`, ← back, x stays 0; DISPLAY_0001 has one expanded line, no card | R-PE-DEF.108/1, .108/4, .33/1, .33/2, .33/3 | `test_at_b103_i8b_6_enum_row_shows_its_card_and_left_right_choose_without_scrolling` |
| AT-B103-I8B-7 | MASK_FIELD_0001 selected → bit card title, mask row, bars, 73 cells | R-PE-DEF.108/2 (partial: before/after bytes not compared) | `test_at_b103_i8b_7_mask_field_row_shows_the_bit_card` |
| AT-B103-I8B-8 | Include parameter control reads `▽ Pick`; at 80×24 the seven filter-row controls keep a region inside the panel | R-PE-DEF.113/1, .113/2 | `test_at_b103_i8b_8_include_parameter_control_shows_the_filter_icon` |
| AT-B103-I8B-9 | 300 `x` typed → tail ends `…`; formula bar outside the grid and inside the sheet window at 80, 118, 220 | R-PE-DEF.95/1, .95/2, .95/3 | `test_at_b103_i8b_9_formula_bar_stays_inside_the_sheet_window_and_the_long_refusal_ends_in_an_ellipsis[80x24|118x54|220x60]` |
| AT-B103-I8B-10 | DISPLAY_0001 read as an erased FLOAT32 word → Limits cell `L.cell.float32_erased`, no crash (selected and unselected) | R-PE-DEF.114/1 | `test_at_b103_i8b_10_a_nan_current_value_paints_the_no_position_limits_cell_and_does_not_crash` |

## Not covered by this file (named)

- R-PE-DEF.81/6 (E3-8b-11, 118→220 resize with MAP_DEF_0001 expanded): owner is the W tester `T8b-BW` (E3-addenda row), not an AT here.
- R-PE-DEF.114/2 (span overflow) and /3 (new value `+inf`): need a limits or a typed value the real app route cannot reach from DEFC without an A2L edit and are unit cases of `T8b-S1`.
- R-PE-DEF.92/3 pins the base's Tab ring as a constant (`BASE_TAB_ORDER`, 31 stops, captured on `48af05ff` in this file's own run); a legitimate new stop elsewhere in the app would need the constant updated.
- Real Windows Terminal captures (E5) and the V = 111 / 73 / 195 equalities in a terminal other than the pilot's: not run here.
