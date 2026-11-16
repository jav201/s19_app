# Inc 9 - test cases of group B (`definition_bench.py`, `definition_bench_view.py`)

Tester T9 (E4), tests tree `b103-inc9-tests` (base `40f0f202`). Format: `<requirement id>/<n> | example id | test | full or partial`, then the requirement's negative control and how these tests express it. Files: `tests/test_b103_inc9_b_model.py`, `_tools.py`, `_cells.py`, `_canvas.py`, `_detail.py`; support `tests/support/b103_inc9_b.py`. Expected values come from the requirement text, from I-2 (real decode and encode of DEFC and hand A2Ls) or from the committed oracles `evidence-e1/examples_inc9.py` and `evidence-e2/examples_e3r1.py`.

Partial = a stand-in sits in the chain (a hand `BenchValues` or `DecodedValues`, a `replace` copy, state fields the B3 worker would store), or the case's second half is the widget (B3) or group A9. Evidence state of every row: `planned` until the integrator's GREEN. RED on base: an import error only, which proves nothing about behaviour.

| Case | Example | Test (file::function[param]) | Mark | Note |
|---|---|---|---|---|
| R-PE-BENCH.3/1 | EX-A3 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_3_the_bench_lines_come_in_order[CURVE_DEF_0001]` | full |  |
| R-PE-BENCH.3/2 | EX-A2 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_3_the_bench_lines_come_in_order[MAP_DEF_0001]` | full |  |
| R-PE-BENCH.3/3 | EX-A1 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_3_the_bench_lines_come_in_order[VAL_BLK_DEF_0001]` | full |  |
| R-PE-BENCH.3/4 | EX-I1 | - | - | widget case: register_bench_kinds is B23 (bench_sheet.py) |
| R-PE-BENCH.4/1 | EX-A1 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_4_1_the_definition_line_of_an_array` | full |  |
| R-PE-BENCH.4/2 | EX-A2 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_4_2_3_the_layout_follows_the_byte_order` | full | parametrized case: name MAP_DEF_0001 |
| R-PE-BENCH.4/3 | EX-A3 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_4_2_3_the_layout_follows_the_byte_order` | full | parametrized case: name CURVE_DEF_0001 |
| R-PE-BENCH.5/1 | EX-W1 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_5_1_2_3_no_bench_line_is_wider_than_the_sheet[76]` | partial | LARGE half: its values are a hand BenchValues (the decode is B3) |
| R-PE-BENCH.5/2 | EX-W1 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_5_1_2_3_no_bench_line_is_wider_than_the_sheet[114]` | partial | LARGE half: its values are a hand BenchValues (the decode is B3) |
| R-PE-BENCH.5/3 | EX-W1 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_5_1_2_3_no_bench_line_is_wider_than_the_sheet[216]` | partial | LARGE half: its values are a hand BenchValues (the decode is B3) |
| R-PE-BENCH.5/4 | EX-W3 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_5_4_room_one_shows_the_definition_line_only` | partial | LARGE half: its values are a hand BenchValues (the decode is B3) |
| R-PE-BENCH.5/5 | EX-W3 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_5_5_room_zero_shows_no_bench_line` | partial | LARGE half: its values are a hand BenchValues (the decode is B3) |
| R-PE-BENCH.7/1 | EX-W2 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_7_1_2_a_map_under_the_bench_minimum_width` | full | parametrized case: 10 and 0 |
| R-PE-BENCH.7/2 | EX-W2 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_7_1_2_a_map_under_the_bench_minimum_width` | full | parametrized case: 10 and 0 |
| R-PE-BENCH.7/3 | EX-W2 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_7_3_4_large_under_the_bench_minimum_width` | partial | LARGE half: its values are a hand BenchValues (the decode is B3); parametrized case: 10 and 0 |
| R-PE-BENCH.7/4 | EX-W2 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_7_3_4_large_under_the_bench_minimum_width` | partial | LARGE half: its values are a hand BenchValues (the decode is B3); parametrized case: 10 and 0 |
| R-PE-BENCH.10/1 | EX-A2 | `tests/test_b103_inc9_b_cells.py::test_r_pe_bench_10_the_kind_cell` | full | parametrized case: MAP, CURVE, VAL_BLK |
| R-PE-BENCH.10/2 | EX-A3 | `tests/test_b103_inc9_b_cells.py::test_r_pe_bench_10_the_kind_cell` | full | parametrized case: MAP, CURVE, VAL_BLK |
| R-PE-BENCH.10/3 | EX-A1 | `tests/test_b103_inc9_b_cells.py::test_r_pe_bench_10_the_kind_cell` | full | parametrized case: MAP, CURVE, VAL_BLK |
| R-PE-BENCH.11/1 | EX-G1 | `tests/test_b103_inc9_b_cells.py::test_r_pe_bench_11_1_the_curve_strip_and_its_count` | full |  |
| R-PE-BENCH.11/2 | EX-G2 | `tests/test_b103_inc9_b_cells.py::test_r_pe_bench_11_2_the_map_strip_has_four_shaded_blocks` | full |  |
| R-PE-BENCH.11/3 | EX-G2 | `tests/test_b103_inc9_b_cells.py::test_r_pe_bench_11_3_the_array_strip_has_three_shaded_blocks` | full |  |
| R-PE-BENCH.12/1 | EX-H5 | `tests/test_b103_inc9_b_cells.py::test_r_pe_bench_12_1_a_large_row_whose_values_are_not_decoded` | full |  |
| R-PE-BENCH.12/2 | EX-H5 | `tests/test_b103_inc9_b_cells.py::test_r_pe_bench_12_2_the_summary_limit_is_4096_elements` | partial | 4,096 half uses a hand BenchValues; the not-decoded 4,097 row is a blank state |
| R-PE-BENCH.13/1 | EX-H6 | `tests/test_b103_inc9_b_cells.py::test_r_pe_bench_13_1_a_running_summary_shows_dots_and_the_count` | partial | reads the state field `job == 'summary'` (interface reading, finding F-6) |
| R-PE-BENCH.14/1 | EX-R6 | `tests/test_b103_inc9_b_cells.py::test_r_pe_bench_14_a_refused_decode_shows_two_dashes[no image]` | partial | integrator W9: written against `BenchState.refusal` (ruling P-056 T9 F-1); the worker that sets it is B3 |
| R-PE-BENCH.14/2 | EX-R6 | `tests/test_b103_inc9_b_cells.py::test_r_pe_bench_14_a_refused_decode_shows_two_dashes[last byte missing]` | partial | integrator W9: written against `BenchState.refusal` (ruling P-056 T9 F-1); the worker that sets it is B3 |
| R-PE-BENCH.15/1 | EX-A1 | `tests/test_b103_inc9_b_cells.py::test_r_pe_bench_15_1_no_edit_shows_a_dot` | full |  |
| R-PE-BENCH.15/2 | EX-T2 | `tests/test_b103_inc9_b_cells.py::test_r_pe_bench_15_2_the_new_cell_counts_the_changed_cells` | full |  |
| R-PE-BENCH.15/3 | EX-C1 | `tests/test_b103_inc9_b_cells.py::test_r_pe_bench_15_3_a_curve_counts_points` | full |  |
| R-PE-BENCH.17/1 | EX-A3 | `tests/test_b103_inc9_b_cells.py::test_r_pe_bench_17_the_limits_cell` | full | parametrized case: name CURVE_DEF_0001 |
| R-PE-BENCH.17/2 | EX-G10 | `tests/test_b103_inc9_b_cells.py::test_r_pe_bench_17_the_limits_cell` | full | parametrized case: name MAP_DEF_0001 |
| R-PE-BENCH.17/3 | EX-R8 | `tests/test_b103_inc9_b_cells.py::test_r_pe_bench_17_3_an_array_with_no_limits_shows_a_dash` | partial | limits removed with `dataclasses.replace` on a described definition |
| R-PE-BENCH.18/1 | EX-T2 | `tests/test_b103_inc9_b_cells.py::test_r_pe_bench_18_1_a_pending_edit_shows_the_diamond` | full |  |
| R-PE-BENCH.18/2 | EX-T1 | `tests/test_b103_inc9_b_cells.py::test_r_pe_bench_18_2_staged_without_an_edit_shows_the_dot` | full |  |
| R-PE-BENCH.18/3 | EX-T1 | `tests/test_b103_inc9_b_cells.py::test_r_pe_bench_18_3_staged_and_a_new_edit_shows_the_diamond` | full |  |
| R-PE-BENCH.18/4 | EX-T9 | `tests/test_b103_inc9_b_cells.py::test_r_pe_bench_18_4_a_typed_operand_without_enter_shows_no_diamond` | partial | bench_mark takes no formula text: the state has no edit; Inc 8's call site is not exercised |
| R-PE-BENCH.19/1 | EX-N1 | `tests/test_b103_inc9_b_canvas.py::test_r_pe_bench_19_1_a_nan_cell_is_unshaded` | partial | also C ..._19_1_nan_column_is_a_space_in_the_strip and V ..._19_a_legend_over_finite_values_only; lo/hi are stored state fields (the worker that computes them is B3) |
| R-PE-BENCH.19/2 | EX-N2 | `tests/test_b103_inc9_b_canvas.py::test_r_pe_bench_19_2_a_point_that_is_not_finite_has_no_bar_and_a_question_mark` | partial | also C ..._19_2_a_curve_strip_leaves_a_space_for_a_point_that_is_not_finite; the CURVE copy is a `replace` plus hand values |
| R-PE-BENCH.19/3 | EX-N1 | `tests/test_b103_inc9_b_canvas.py::test_r_pe_bench_19_3_every_value_not_finite_gives_no_shade_and_no_exception` | partial | also C ..._19_3_every_value_not_finite_gives_a_blank_strip and V ..._19_3_a_legend_with_no_finite_value; lo = hi = 0 is set by the test |
| R-PE-BENCH.21/1 | EX-H5 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_21_1_a_decoding_row_says_so_in_place_of_the_canvas` | full |  |
| R-PE-BENCH.26/1 | EX-H5 | `tests/test_b103_inc9_b_cells.py::test_r_pe_bench_26_1_a_large_decode_is_retained_in_at_most_64_mib` | partial | BenchValues.from_decoded only (marked slow, one I-2 decode of LARGE); the page and selection retention is B3 |
| R-PE-BENCH.26/2 | EX-B1 | - | - | widget case: the selection handler dropping values is B30 (bench_sheet.py) |
| R-PE-BENCH.29/1 | EX-J2 | - | - | widget case: timing AT on the widget (B33/B34): needs the sheet and a quiet host |
| R-PE-BENCH.29/2 | EX-J2 | - | - | widget case: timing AT on the widget (B34) |
| R-PE-BENCH.30/1 | EX-A3 | `tests/test_b103_inc9_b_canvas.py::test_r_pe_bench_30_1_the_chart_has_five_columns_and_the_fourth_is_tallest` | full |  |
| R-PE-BENCH.30/2 | EX-A3 | `tests/test_b103_inc9_b_canvas.py::test_r_pe_bench_30_2_the_chart_labels_hi_on_top_and_lo_at_the_bottom` | full |  |
| R-PE-BENCH.30/3 | EX-C1 | `tests/test_b103_inc9_b_canvas.py::test_r_pe_bench_30_3_an_edited_point_has_the_edit_colour_its_text_above_and_the_old_level` | full |  |
| R-PE-BENCH.31/1 | EX-G3 | `tests/test_b103_inc9_b_canvas.py::test_r_pe_bench_31_1_map_cells_in_element_order_with_their_ramp_steps` | full |  |
| R-PE-BENCH.31/2 | EX-A1 | `tests/test_b103_inc9_b_canvas.py::test_r_pe_bench_31_2_array_cells` | full |  |
| R-PE-BENCH.31/3 | EX-T2 | `tests/test_b103_inc9_b_canvas.py::test_r_pe_bench_31_3_an_edited_cell_is_bold_with_a_star` | full |  |
| R-PE-BENCH.32/1 | EX-A2 | `tests/test_b103_inc9_b_canvas.py::test_r_pe_bench_32_1_a_map_is_labelled_by_its_axis_points` | full |  |
| R-PE-BENCH.32/2 | EX-A3 | `tests/test_b103_inc9_b_canvas.py::test_r_pe_bench_32_2_a_curve_is_labelled_by_its_com_axis` | full |  |
| R-PE-BENCH.32/3 | EX-A1 | `tests/test_b103_inc9_b_canvas.py::test_r_pe_bench_32_3_a_two_dimensional_array_is_labelled_by_index` | full |  |
| R-PE-BENCH.33/1 | EX-R10 | `tests/test_b103_inc9_b_canvas.py::test_r_pe_bench_33_1_an_axis_with_no_points_is_labelled_by_index` | partial | DecodedAxis built by hand (points None) |
| R-PE-BENCH.33/2 | EX-R10 | `tests/test_b103_inc9_b_canvas.py::test_r_pe_bench_33_2_a_point_that_is_a_refusal_is_labelled_by_index` | partial | refusal points built by hand |
| R-PE-BENCH.34/1 | EX-G4 | `tests/test_b103_inc9_b_canvas.py::test_r_pe_bench_34_1_the_map_legend` | full |  |
| R-PE-BENCH.34/2 | EX-G5 | `tests/test_b103_inc9_b_canvas.py::test_r_pe_bench_34_2_the_curve_legend` | full |  |
| R-PE-BENCH.35/1 | EX-K4 | `tests/test_b103_inc9_b_canvas.py::test_r_pe_bench_35_1_the_tool_row_selects_set_at_open` | full |  |
| R-PE-BENCH.35/2 | EX-K4 | `tests/test_b103_inc9_b_canvas.py::test_r_pe_bench_35_2_the_tool_row_selects_the_current_tool` | full |  |
| R-PE-BENCH.36/1 | EX-H5 | `tests/test_b103_inc9_b_model.py::test_r_pe_bench_36_1_the_window_moves_one_row_when_the_cursor_leaves_it` | full |  |
| R-PE-BENCH.36/2 | EX-H5 | `tests/test_b103_inc9_b_model.py::test_r_pe_bench_36_2_pagedown_moves_the_window_the_least` | full |  |
| R-PE-BENCH.36/3 | EX-A2 | `tests/test_b103_inc9_b_model.py::test_r_pe_bench_36_3_a_grid_that_fits_keeps_its_window` | full |  |
| R-PE-BENCH.37/1 | EX-H5 | `tests/test_b103_inc9_b_canvas.py::test_r_pe_bench_37_1_the_window_line_of_a_large_object_from_the_definition` | full |  |
| R-PE-BENCH.37/2 | EX-A2 | `tests/test_b103_inc9_b_canvas.py::test_r_pe_bench_37_2_a_grid_that_fits_has_no_window_line` | full |  |
| R-PE-BENCH.38/1 | EX-A1 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_38_1_no_edit` | full |  |
| R-PE-BENCH.38/2 | EX-T1 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_38_2_one_changed_run` | partial | runs computed by the test (the worker that computes them is B3) |
| R-PE-BENCH.38/3 | EX-T2 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_38_3_two_cells_make_one_run_of_four_bytes` | partial | runs computed by the test |
| R-PE-BENCH.38/4 | EX-T7 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_38_4_a_refused_preview` | full |  |
| R-PE-BENCH.39/1 | EX-H7 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_39_1_2_a_long_bytes_line_is_cut_with_an_ellipsis` | partial | runs built by hand for LARGE; parametrized case: 76 and 114 |
| R-PE-BENCH.39/2 | EX-H7 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_39_1_2_a_long_bytes_line_is_cut_with_an_ellipsis` | partial | runs built by hand for LARGE; parametrized case: 76 and 114 |
| R-PE-BENCH.41/1 | EX-K2 | `tests/test_b103_inc9_b_model.py::test_r_pe_bench_41_1_right_moves_one_cell` | partial | move_cursor only; the arrow key is the widget's (B25) |
| R-PE-BENCH.41/2 | EX-K2 | `tests/test_b103_inc9_b_model.py::test_r_pe_bench_41_2_down_moves_one_cell` | partial | move_cursor only |
| R-PE-BENCH.41/3 | EX-K2 | `tests/test_b103_inc9_b_model.py::test_r_pe_bench_41_3_a_plain_arrow_selects_one_cell` | partial | move_cursor + selection_cells only |
| R-PE-BENCH.41/4 | EX-K2 | `tests/test_b103_inc9_b_model.py::test_r_pe_bench_41_4_left_at_column_zero_stays` | partial | move_cursor only |
| R-PE-BENCH.42/1 | EX-K2 | `tests/test_b103_inc9_b_model.py::test_r_pe_bench_42_1_shift_arrows_keep_the_anchor` | partial | move_cursor only; shift+arrows reaching the app is pilot P |
| R-PE-BENCH.42/2 | EX-K2 | `tests/test_b103_inc9_b_model.py::test_r_pe_bench_42_2_where_of_the_four_cell_selection` | full |  |
| R-PE-BENCH.43/1 | EX-H5 | `tests/test_b103_inc9_b_model.py::test_r_pe_bench_43_1_pagedown_moves_the_cursor_by_the_window_rows` | partial | page_cursor only; the key is the widget's (B26) |
| R-PE-BENCH.43/2 | EX-H5 | `tests/test_b103_inc9_b_model.py::test_r_pe_bench_43_2_pageup_returns_to_row_zero_and_never_below` | partial | page_cursor only |
| R-PE-BENCH.50/1 | EX-M2 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_50_1_the_map_op_line` | full |  |
| R-PE-BENCH.50/2 | EX-C1 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_50_2_the_curve_op_line` | full |  |
| R-PE-BENCH.50/3 | EX-A1 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_50_3_the_unit_follows_the_input` | full |  |
| R-PE-BENCH.51/1 | EX-T1 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_51_1_set_on_one_cell_makes_the_edit` | partial | apply_tool only; Enter, BenchApplyRequested and the focus are B3 |
| R-PE-BENCH.52/1 | EX-C1 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_52_1_set_on_curve_points_one_and_three` | partial | integrator W9: rewritten to the replace rule (R-PE-BENCH.51, EX-K5, ruling P-054 F-2): point 1, then point 3 -> {(3,)}, {(1,)} on undo; points 1..3 in one apply |
| R-PE-BENCH.52/2 | EX-M1 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_52_2_set_gives_the_operand_text_unrounded` | full |  |
| R-PE-BENCH.53/1 | EX-T2 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_53_1_delta_adds_to_the_physical_value` | full |  |
| R-PE-BENCH.53/2 | EX-M2 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_53_2_delta_over_a_map_rectangle` | full |  |
| R-PE-BENCH.54/1 | EX-T3 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_54_1_percent_multiplies_by_one_plus_a_over_100` | full |  |
| R-PE-BENCH.55/1 | EX-T4 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_55_1_interpolate_runs_between_the_end_columns` | full |  |
| R-PE-BENCH.55/2 | EX-T4 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_55_2_interpolate_on_one_column_changes_nothing` | full |  |
| R-PE-BENCH.56/1 | EX-T5 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_56_1_smooth_averages_three_columns` | full |  |
| R-PE-BENCH.56/2 | EX-G11 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_56_2_smooth_reads_the_values_before_the_tool` | full |  |
| R-PE-BENCH.57/1 | EX-G9 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_57_1_result_text_rounds_half_away_from_zero_to_the_decimals` | full |  |
| R-PE-BENCH.57/2 | EX-G9 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_57_2_result_text_of_a_half` | full |  |
| R-PE-BENCH.57/3 | EX-G9 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_57_3_an_integer_map_rounds_half_away_not_half_even` | full |  |
| R-PE-BENCH.58/1 | EX-M2 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_58_1_a_zero_delta_leaves_the_edit_empty` | full |  |
| R-PE-BENCH.58/2 | EX-A1 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_58_2_a_zero_delta_on_a_rounded_cell_leaves_the_edit_empty` | full |  |
| R-PE-BENCH.59/1 | EX-K5 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_59_1_undo_restores_the_edit_before_each_apply` | partial | undo and apply_tool only; the `u` key is B3 |
| R-PE-BENCH.59/2 | EX-K5 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_59_2_the_undo_stack_keeps_thirty_two_edits` | partial | undo and apply_tool only |
| R-PE-BENCH.61/1 | EX-K5 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_61_1_undo_with_an_empty_stack_says_so` | partial | undo only; showing the status is B3 |
| R-PE-BENCH.62/1 | EX-H8 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_62_a_bad_operand_is_refused_and_keeps_the_edit` | full | parametrized case: operand abc |
| R-PE-BENCH.62/2 | EX-H8 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_62_a_bad_operand_is_refused_and_keeps_the_edit` | full | parametrized case: operand (empty) |
| R-PE-BENCH.62/3 | EX-H8 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_62_a_bad_operand_is_refused_and_keeps_the_edit` | full | parametrized case: operand 1_0 |
| R-PE-BENCH.62/4 | EX-N3 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_62_a_bad_operand_is_refused_and_keeps_the_edit` | full | parametrized case: operand 1e999 |
| R-PE-BENCH.62/5 | EX-N3 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_62_a_bad_operand_is_refused_and_keeps_the_edit` | full | parametrized case: operand 400 x 9 |
| R-PE-BENCH.63/1 | EX-R11 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_63_1_a_tool_on_texts_needs_numbers` | full |  |
| R-PE-BENCH.64/1 | EX-R11 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_64_1_a_refused_element_has_no_value_to_change` | partial | BenchValues from a hand DecodedValues with a Refusal element |
| R-PE-BENCH.64/2 | EX-N1 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_64_2_a_nan_element_has_no_value_to_change` | full |  |
| R-PE-BENCH.65/1 | EX-T4 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_65_1_interpolate_needs_two_columns` | full |  |
| R-PE-BENCH.65/2 | EX-T5 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_65_2_smooth_needs_three_columns` | full |  |
| R-PE-BENCH.66/1 | EX-T2 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_66_1_a_preview_without_notices_is_a_tick` | partial | op_line verdict only; the preview job is B3 |
| R-PE-BENCH.66/2 | EX-T7 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_66_2_a_refused_preview_shows_its_message` | partial | op_line verdict only |
| R-PE-BENCH.66/3 | EX-C2 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_66_3_a_percent_refusal_names_the_element` | partial | op_line verdict only (edit from apply_tool, refusal from I-2) |
| R-PE-BENCH.67/1 | EX-N4 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_67_1_a_result_that_is_not_finite_is_refused` | full |  |
| R-PE-BENCH.79/1 | EX-T1 | `tests/test_b103_inc9_b_cells.py::test_r_pe_bench_79_1_after_a_stage_the_mark_is_the_dot_while_the_edit_is_empty` | partial | mark half only; clearing the edit and the undo stack is B3 (record_staged) |
| R-PE-BENCH.79/2 | EX-Q2 | - | - | widget case: record_staged is B35 (bench_sheet.py) |
| R-PE-BENCH.90/1 | EX-H1 | `tests/test_b103_inc9_b_canvas.py::test_r_pe_bench_90_1_an_axis_text_is_not_markup` | partial | axis point texts built by hand |
| R-PE-BENCH.90/2 | EX-H1 | `tests/test_b103_inc9_b_canvas.py::test_r_pe_bench_90_2_a_unit_is_not_markup` | full |  |
| R-PE-BENCH.90/3 | EX-H1 | `tests/test_b103_inc9_b_canvas.py::test_r_pe_bench_90_3_an_element_text_is_not_markup` | partial | element texts built by hand (I-2's own texts would not carry the markup) |
| R-PE-BENCH.91/1 | EX-H2 | `tests/test_b103_inc9_b_canvas.py::test_r_pe_bench_91_1_a_control_character_in_an_element_text_becomes_fffd` | partial | element text built by hand |
| R-PE-BENCH.91/2 | EX-H2 | `tests/test_b103_inc9_b_canvas.py::test_r_pe_bench_91_2_a_control_character_in_a_unit_becomes_fffd` | full |  |
| R-PE-BENCH.92/1 | EX-H4 | - | - | widget case: action_stage_record is B28 (bench_sheet.py) |
| R-PE-BENCH.92/2 | EX-H4 | `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_92_2_the_operand_echo_is_cleaned_and_bounded` | full |  |
| R-PE-BENCH.93/1 | EX-H3 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_93_1_2_a_long_verdict_is_cut_at_the_edge` | full | parametrized case: 118 and 220 |
| R-PE-BENCH.93/2 | EX-H3 | `tests/test_b103_inc9_b_detail.py::test_r_pe_bench_93_1_2_a_long_verdict_is_cut_at_the_edge` | full | parametrized case: 118 and 220 |

## Negative controls (per requirement)

| Requirement | Negative control of `01-requirements.md` | Expressed against these tests? |
|---|---|---|
| R-PE-BENCH.3 | US-103-05 | no-editor tail -> RED: expressed (order, legend and tool-row assertions); the `editable=True` import half is B3 |
| R-PE-BENCH.4 | US-103-05 | layout left out -> RED: expressed (the line ends with the layout, address and length) |
| R-PE-BENCH.5 | US-103-05 | no column window / chart height max(4,..): expressed for the cut to the room (rooms 0..12, at most `room` lines); a chart_canvas height mutant alone is hidden by bench_detail's own cut (finding F-5) |
| R-PE-BENCH.7 | US-103-05 | unclamped geometry -> ZeroDivisionError at width 10: expressed (bench_detail 10 and 0; grid_canvas 12, 10, 0) |
| R-PE-BENCH.10 | US-103-05 | kind word only for a map -> RED: expressed |
| R-PE-BENCH.11 | US-103-05 | count only -> RED: expressed (strip text and ramp classes) |
| R-PE-BENCH.12 | US-103-05 | summarise LARGE on the page (0.5 s): NOT expressible in a pure test (timing, B3/AT); the text form is expressed |
| R-PE-BENCH.13 | US-103-05 | blank Current -> RED: expressed |
| R-PE-BENCH.14 | US-103-05 | not written |
| R-PE-BENCH.15 | US-103-05 | count the selection, not the changed cells -> RED: expressed (an unchanged-text cell inside the edit) |
| R-PE-BENCH.17 | US-103-05 | scalar ruler form -> RED: expressed |
| R-PE-BENCH.18 | US-103-05 | mark from the formula text: NOT expressible against bench_mark (it has no formula argument); expressed: edit {} -> space, staged -> dot, edit -> diamond |
| R-PE-BENCH.19 | US-103-05 | lo and hi over every value -> ValueError: expressed (strip, canvas and legend over nan and all-nan) |
| R-PE-BENCH.21 | US-103-05 | empty canvas -> RED: expressed |
| R-PE-BENCH.26 | US-103-05 | keep I-2's DecodedValues -> RED: expressed for from_decoded (tracemalloc); the deselect case is B3 |
| R-PE-BENCH.29 | US-103-05 | not written |
| R-PE-BENCH.30 | US-103-05 | bars by stored rank -> RED: expressed (heights proportional to the value from the base) |
| R-PE-BENCH.31 | US-103-05 | cells in byte order -> RED: expressed (positions follow element order, ramp classes follow the value) |
| R-PE-BENCH.32 | US-103-05 | index labels on a map -> RED: expressed |
| R-PE-BENCH.33 | US-103-05 | blank labels -> RED: expressed |
| R-PE-BENCH.34 | US-103-05 | no unit word -> RED: expressed (the `units` legend test) |
| R-PE-BENCH.35 | US-103-05 | highlight by position -> RED: expressed (each key selects its own label) |
| R-PE-BENCH.36 | US-103-05 | re-centre the window -> RED: expressed (origin row 1, not 10) |
| R-PE-BENCH.37 | US-103-05 | always show the line -> RED: expressed (37/2 gives None) |
| R-PE-BENCH.38 | US-103-05 | compare with the image, not the overlay: NOT expressible (the worker computes the runs, B3); the formatting is expressed |
| R-PE-BENCH.39 | US-103-05 | wrap -> RED: expressed (ends with the ellipsis, fits) |
| R-PE-BENCH.41 | US-103-05 | wrap at the edge -> RED: expressed (corner test) |
| R-PE-BENCH.42 | US-103-05 | move the anchor too -> RED: expressed |
| R-PE-BENCH.43 | US-103-05 | one row per key -> RED: expressed |
| R-PE-BENCH.50 | US-103-05 | Inc 8's `new =` label: expressed only through the tail (`+Δ on 4 cells`); the `op =` label is Inc 8's |
| R-PE-BENCH.51 | US-103-05 | stage instead of apply: NOT expressible (widget message routing) |
| R-PE-BENCH.52 | US-103-05 | round the text -> RED: expressed (`10.03` kept) |
| R-PE-BENCH.53 | US-103-05 | add to the stored value -> RED: expressed (41.9, not 11.2) |
| R-PE-BENCH.54 | US-103-05 | multiply by a -> RED: expressed |
| R-PE-BENCH.55 | US-103-05 | interpolate by axis value -> RED: expressed (MAP row 0, equal spacing) |
| R-PE-BENCH.56 | US-103-05 | smooth in place -> RED: expressed ((2,0) = 357) |
| R-PE-BENCH.57 | US-103-05 | Python round (half to even) -> RED: expressed (572.5 -> 573) |
| R-PE-BENCH.58 | US-103-05 | keep rounded no-op cells -> RED: expressed |
| R-PE-BENCH.59 | US-103-05 | clear the edit on undo -> RED: expressed |
| R-PE-BENCH.61 | US-103-05 | silent -> RED: expressed |
| R-PE-BENCH.62 | US-103-05 | float grammar (`1_0`) / no finite check (`1e999`) -> RED: expressed |
| R-PE-BENCH.63 | US-103-05 | add to a text -> exception RED: expressed |
| R-PE-BENCH.64 | US-103-05 | treat `--` as 0 / no finite check -> RED: expressed |
| R-PE-BENCH.65 | US-103-05 | divide by zero -> RED: expressed |
| R-PE-BENCH.66 | US-103-05 | preview over the image, not the overlay: NOT expressible (B3 job); the verdict forms are expressed |
| R-PE-BENCH.67 | US-103-05 | drop the finite check -> InvalidOperation: expressed |
| R-PE-BENCH.79 | US-103-05 | keep the edit / mark from the formula text: only the mark of an empty edit is expressed here |
| R-PE-BENCH.90 | US-103-05 | render one cell as a markup str -> RED: expressed (literal brackets, no link) |
| R-PE-BENCH.91 | US-103-05 | paint the raw word -> RED: expressed |
| R-PE-BENCH.92 | US-103-05 | unbounded echo -> RED: expressed (255 nines and the ellipsis) |
| R-PE-BENCH.93 | US-103-05 | wrap -> RED: expressed |

## Not covered by group B's tests (named)

- R-PE-BENCH.3/4: register_bench_kinds is B23 (bench_sheet.py)
- R-PE-BENCH.26/2: the selection handler dropping values is B30 (bench_sheet.py)
- R-PE-BENCH.29/1: timing AT on the widget (B33/B34): needs the sheet and a quiet host
- R-PE-BENCH.29/2: timing AT on the widget (B34)
- R-PE-BENCH.79/2: record_staged is B35 (bench_sheet.py)
- R-PE-BENCH.92/1: action_stage_record is B28 (bench_sheet.py)
- (R-PE-BENCH.14/1, 14/2: written by the integrator W9, see the table.)

Totals: 125 cases map to group B rows; 117 have tests (76 full, 41 partial); 8 are not written or not group B's.
Integrator W9: 119 have tests (76 full, 43 partial); 6 are not group B's.

## Integrator additions (W9)

- `tests/test_b103_inc9_b_model.py::test_r_pe_bench_36_window_for_answers_row_then_column` (R-PE-BENCH.36; ruling T9 F-4: origin and `window_for` are (row, col)).
- `tests/test_b103_inc9_b_tools.py::test_r_pe_bench_53_a_flat_selection_over_the_short_last_row_leaves_out_the_cells_past_the_count[d,p,i,m]` (R-PE-BENCH.53 ... .56, finding W9-F1).
- Tightened: 16/2 (`max |Δ| 5.1 staged`, ruling T9 F-3), 93/1,2 (`== width`, ruling T9 F-7), the canvas room tests (`<= room`, ruling T9 F-5). Rewritten: 52/1, the pending-cell case of 58, 59/1 (ruling T9 F-2).
- Evidence state of every row with a test: `executed` GREEN on the integrator's tree, except R-PE-BENCH.17/2 (`failed`, waits for the Inc 8 F-1 fix).
