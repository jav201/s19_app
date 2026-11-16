# Inc 9 group B - mutant run (M9, relevo-10)

Model claude-sonnet-5-5. Product under test: `b103-inc9` tip `30819c7e` (group B: `definition_bench.py`,
`definition_bench_view.py`). HT-09: every mutant ran on a COPY (a second archive of `30819c7e` under the runner
scratch `~/work/zq-m9/mt`, never in the worktree); the driver restores both sources after each mutant. Spec and
driver: `evidence-e4/mutants-b/mutants_spec.py`, `mut_run.py` (needs `RUNNER_HOME_NAME`); log: `mut-log.txt`.

Method: per mutant one source edit (exactly one occurrence checked, result parsed with `ast` before it ran), then
the five group B files with `-x -n 2`, `timeout 300`, in the order canvas, detail, model, tools, cells; a mutant is
**killed** when a node fails, **survived** when all 192 original nodes pass, **timeout** at rc 124 (none).
Host load (`uptime`) at the start 7.4 (shared runner), at the end 2.7; no timing decision rests on this run, only
pass/fail of deterministic nodes (HT-08 noted: the brief asked for the run on the shared host).

## Result

78 mutants: **67 killed, 11 survived, 0 timeout, 0 error** on the original nodes (75 ran first against the 192 nodes: 64 killed, 11 survived; the three added afterwards, m21, m07 and m90, were killed by original nodes). Of the 11 survivors,
**8 are now killed** by 8 tests added here (15 nodes) and **3 are equivalent or unpinned** (below).
Final on the product: 207 passed in 100 s (192 + 15), one complete run.

Requirement rows with no group B code (R-PE-BENCH.21, .7 and .90 are group B: m21, m07, m90 below) (widget, group I; no mutant here): R-PE-BENCH.3, .20, .22 ... .25, .27, .28, .29, .40, .44 ... .49, .51 (the Enter route; its
group B half is m51), .66 (the verdict job; its op-line half is m66a/b), .79 (the mark half is m18a/b). `n/a - widget`.

## Mutant table

| Id | Requirement / what the mutant does | File | Result | First failing node (or note) |
|---|---|---|---|---|
| m10 | R-PE-BENCH.10 | bench | killed | cells::test_r_pe_bench_10_the_kind_cell[MAP_DEF_0001-MAP 4x3] |
| m11 | R-PE-BENCH.11 | bench | killed | cells::test_r_pe_bench_11_2_the_map_strip_has_four_shaded_blocks |
| m12 | R-PE-BENCH.12 | bench | killed | cells::test_r_pe_bench_12_1_a_large_row_whose_values_are_not_decoded |
| m13 | R-PE-BENCH.13 | bench | killed | cells::test_r_pe_bench_13_1_a_running_summary_shows_dots_and_the_count |
| m14 | R-PE-BENCH.14 | bench | killed | cells::test_r_pe_bench_14_a_refused_decode_shows_two_dashes[no image] |
| m14b | R-PE-BENCH.14 (W9 refusal field read) | bench | killed | cells::test_r_pe_bench_14_a_refused_decode_shows_two_dashes[no image] |
| m15 | R-PE-BENCH.15 (_changed_cells filter) | bench | killed | cells::test_r_pe_bench_15_2_the_new_cell_counts_the_changed_cells |
| m15b | R-PE-BENCH.15 (pts/cells word) | bench | killed | cells::test_r_pe_bench_15_3_a_curve_counts_points |
| m16 | R-PE-BENCH.16 (signed delta) | bench | killed | cells::test_r_pe_bench_16_1_the_delta_is_the_largest_magnitude |
| m16b | R-PE-BENCH.16 (staged delta signed) | bench | survived | (192 passed) |
| m17 | R-PE-BENCH.17 | bench | survived | (192 passed) |
| m18a | R-PE-BENCH.18 (edit mark) | bench | killed | cells::test_r_pe_bench_18_1_a_pending_edit_shows_the_diamond |
| m18b | R-PE-BENCH.18 (staged mark) | bench | killed | cells::test_r_pe_bench_18_2_staged_without_an_edit_shows_the_dot |
| m19a | R-PE-BENCH.19 (finite_range keeps nan) | bench | killed | cells::test_r_pe_bench_19_2_a_curve_strip_leaves_a_space_for_a_point_that_is_not_finite |
| m19b | R-PE-BENCH.19 (chart ? on base line) | view | killed | canvas::test_r_pe_bench_19_2_a_point_that_is_not_finite_has_no_bar_and_a_question_mark |
| m19c | R-PE-BENCH.19 (summary strip skips non-finite) | bench | killed | cells::test_r_pe_bench_19_2_a_curve_strip_leaves_a_space_for_a_point_that_is_not_finite |
| m26 | R-PE-BENCH.26 (values kept as list not array d) | bench | survived | (192 passed) |
| m30 | R-PE-BENCH.30 (bars not by value) | view | killed | canvas::test_r_pe_bench_30_1_the_chart_has_five_columns_and_the_fourth_is_tallest |
| m30b | R-PE-BENCH.30 (hi/lo label order) | view | killed | canvas::test_r_pe_bench_30_2_the_chart_labels_hi_on_top_and_lo_at_the_bottom |
| m31 | R-PE-BENCH.31 (cells in the wrong order) | view | killed | canvas::test_r_pe_bench_31_1_map_cells_in_element_order_with_their_ramp_steps |
| m32 | R-PE-BENCH.32 (index labels on a map) | view | killed | canvas::test_r_pe_bench_33_1_an_axis_with_no_points_is_labelled_by_index |
| m33 | R-PE-BENCH.33 (blank label for refused point) | view | killed | canvas::test_r_pe_bench_33_1_an_axis_with_no_points_is_labelled_by_index |
| m34 | R-PE-BENCH.34 (no unit word, chart) | view | survived | (192 passed) |
| m34b | R-PE-BENCH.34 (no unit word, grid) | view | killed | canvas::test_r_pe_bench_34_the_unit_word_follows_the_range |
| m35 | R-PE-BENCH.35 (highlight by position) | view | killed | canvas::test_r_pe_bench_35_2_the_tool_row_selects_the_current_tool |
| m36 | R-PE-BENCH.36 (re-centre window) | bench | killed | model::test_r_pe_bench_36_1_the_window_moves_one_row_when_the_cursor_leaves_it |
| m36b | R-PE-BENCH.36 (window columns) | bench | killed | model::test_r_pe_bench_36_window_for_answers_row_then_column |
| m37a | R-PE-BENCH.37 (grid window line always) | view | killed | canvas::test_r_pe_bench_37_2_a_grid_that_fits_has_no_window_line |
| m37b | R-PE-BENCH.37 (chart window line always) | view | survived | (192 passed) |
| m38 | R-PE-BENCH.38 (differing bytes count) | view | killed | detail::test_r_pe_bench_38_2_one_changed_run |
| m38b | R-PE-BENCH.38 (no edit text) | view | killed | detail::test_r_pe_bench_3_the_bench_lines_come_in_order[CURVE_DEF_0001] |
| m39 | R-PE-BENCH.39 (bytes line not cut) | view | killed | detail::test_r_pe_bench_39_1_2_a_long_bytes_line_is_cut_with_an_ellipsis[76] |
| m41 | R-PE-BENCH.41 (cursor wraps) | bench | killed | model::test_r_pe_bench_41_4_left_at_column_zero_stays |
| m41b | R-PE-BENCH.41 (anchor follows cursor) | bench | killed | model::test_r_pe_bench_41_1_right_moves_one_cell |
| m42 | R-PE-BENCH.42 (shift moves anchor) | bench | killed | model::test_r_pe_bench_42_1_shift_arrows_keep_the_anchor |
| m43 | R-PE-BENCH.43 (one row per key) | bench | killed | model::test_r_pe_bench_36_2_pagedown_moves_the_window_the_least |
| m50 | R-PE-BENCH.50 (op line without where) | view | killed | detail::test_r_pe_bench_50_1_the_map_op_line |
| m51 | R-PE-BENCH.51 (edit merges across applies) | bench | killed | tools::test_r_pe_bench_52_1_set_on_curve_points_one_and_three |
| m52 | R-PE-BENCH.52 (Set truncates the text) | bench | killed | tools::test_r_pe_bench_52_1_set_on_curve_points_one_and_three |
| m53 | R-PE-BENCH.53 (+delta subtracts) | bench | killed | tools::test_r_pe_bench_53_1_delta_adds_to_the_physical_value |
| m54 | R-PE-BENCH.54 (x% multiplies by a) | bench | killed | detail::test_r_pe_bench_66_3_a_percent_refusal_names_the_element |
| m55 | R-PE-BENCH.55 (interpolation span off by one) | bench | killed | tools::test_r_pe_bench_55_1_interpolate_runs_between_the_end_columns |
| m56 | R-PE-BENCH.56 (smooth drops the right neighbour) | bench | killed | tools::test_r_pe_bench_56_1_smooth_averages_three_columns |
| m57 | R-PE-BENCH.57 (half to even) | bench | killed | detail::test_r_pe_bench_66_3_a_percent_refusal_names_the_element |
| m57b | R-PE-BENCH.57 (integer datatype keeps decimals) | bench | survived | (192 passed) |
| m58a | R-PE-BENCH.58 (keep no-op cells, tools) | bench | killed | tools::test_r_pe_bench_58_2_a_zero_delta_on_a_rounded_cell_leaves_the_edit_empty |
| m58b | R-PE-BENCH.58 (keep no-op cells, Set) | bench | survived | (192 passed) |
| m59 | R-PE-BENCH.59 (undo clears the edit) | bench | killed | tools::test_r_pe_bench_59_1_undo_restores_the_edit_before_each_apply |
| m59b | R-PE-BENCH.59 (undo stack bound 33) | bench | killed | tools::test_r_pe_bench_59_2_the_undo_stack_keeps_thirty_two_edits |
| m59c | R-PE-BENCH.59 (undo stack unbounded) | bench | killed | tools::test_r_pe_bench_59_2_the_undo_stack_keeps_thirty_two_edits |
| m61 | R-PE-BENCH.61 (silent empty undo) | bench | killed | tools::test_r_pe_bench_59_2_the_undo_stack_keeps_thirty_two_edits |
| m62a | R-PE-BENCH.62 (python float grammar) | bench | killed | tools::test_r_pe_bench_62_parse_operand_rejects_everything_else[0x10] |
| m62b | R-PE-BENCH.62 (no finite check) | bench | killed | tools::test_r_pe_bench_62_parse_operand_rejects_everything_else[1e999] |
| m63 | R-PE-BENCH.63 (text objects not refused) | bench | killed | tools::test_r_pe_bench_63_1_a_tool_on_texts_needs_numbers |
| m64a | R-PE-BENCH.64 (no finite check on selection) | bench | killed | tools::test_r_pe_bench_64_2_a_nan_element_has_no_value_to_change |
| m64b | R-PE-BENCH.64 (missing cell not refused) | bench | killed | tools::test_r_pe_bench_64_1_a_refused_element_has_no_value_to_change |
| m65a | R-PE-BENCH.65 (Interpolate on one column) | bench | killed | tools::test_r_pe_bench_55_2_interpolate_on_one_column_changes_nothing |
| m65b | R-PE-BENCH.65 (Smooth on two columns) | bench | killed | tools::test_r_pe_bench_65_2_smooth_needs_three_columns |
| m66a | R-PE-BENCH.66 (op line drops the refusal verdict) | view | killed | detail::test_r_pe_bench_66_2_a_refused_preview_shows_its_message |
| m66b | R-PE-BENCH.66 (bench_preview returns None) | bench | killed | cells::test_r_pe_bench_66_the_kind_preview_gives_no_result |
| m93 | R-PE-BENCH.93 (op tail not cut) | view | killed | detail::test_r_pe_bench_93_1_2_a_long_verdict_is_cut_at_the_edge[118] |
| w1 | W9 flat row width guard (_row_width) | bench | killed | tools::test_r_pe_bench_53_a_flat_selection_over_the_short_last_row_leaves_out_the_cells_past_the_count[i] |
| w2 | W9 +delta short-row guard | bench | killed | tools::test_r_pe_bench_53_a_flat_selection_over_the_short_last_row_leaves_out_the_cells_past_the_count[d] |
| w3 | W9 Interpolate short-row guard | bench | killed | tools::test_r_pe_bench_53_a_flat_selection_over_the_short_last_row_leaves_out_the_cells_past_the_count[i] |
| w4 | W9 Smooth short-row guard | bench | killed | tools::test_r_pe_bench_53_a_flat_selection_over_the_short_last_row_leaves_out_the_cells_past_the_count[m] |
| w5 | W9 selection_cells flat skip | bench | killed | tools::test_r_pe_bench_53_a_flat_selection_over_the_short_last_row_leaves_out_the_cells_past_the_count[i] |
| w6 | W9 grid cell past count | view | killed | canvas::test_r_pe_bench_19_1_a_nan_cell_is_unshaded |
| w7 | W9 summary_strip past count | bench | killed | cells::test_r_pe_bench_19_1_nan_column_is_a_space_in_the_strip |
| w8 | W9 _CHART_LABEL 8 | view | survived | (192 passed) |
| w8b | W9 _CHART_LABEL 10 | view | survived | (192 passed) |
| w9 | W9 room+1 grid_canvas | view | killed | canvas::test_r_pe_bench_5_the_grid_paints_nothing_without_room |
| w9b | W9 room+1 chart_canvas | view | killed | canvas::test_r_pe_bench_5_the_chart_paints_nothing_without_room |
| w9c | W9 room+1 bench_detail (full) | view | killed | detail::test_r_pe_bench_5_no_more_bench_lines_than_the_room[MAP_DEF_0001] |
| w9d | W9 room+1 bench_detail (decoding) | view | survived | (192 passed) |
| w9e | W9 canvas_room +1 in bench_detail | view | survived | (192 passed) |
| m21 | R-PE-BENCH.21 (no decoding line) | view | killed | detail::test_r_pe_bench_21_1_a_decoding_row_says_so_in_place_of_the_canvas |
| m07 | R-PE-BENCH.7 (bench minimum width lowered) | view | killed | detail::test_r_pe_bench_7_1_2_a_map_under_the_bench_minimum_width[10] |
| m90 | R-PE-BENCH.90 (axis label not plain) | view | killed | canvas::test_r_pe_bench_91_a_control_character_in_an_axis_text_becomes_fffd |

(Rows `m16b`, `m17`, `m26`, `m34`, `m37b`, `m57b`, `m58b`, `w8`, `w8b`, `w9d` and `w9e` read `survived (192 passed)` above report the first run (192 original nodes); the added tests kill eight of them, see below.)

## Survivors and what was done

| Id | Verdict | Test added (RED on the mutant, GREEN on the product) |
|---|---|---|
| m16b | missing test | `test_b103_inc9_b_cells.py::test_r_pe_bench_16_4_a_staged_delta_is_a_magnitude_too`: staged +5.05 on (0,0) and -10 on (2,0) -> `max |Δ| 10 staged`; the signed mutant shows `5.1` |
| m17 | missing test | `test_b103_inc9_b_cells.py::test_r_pe_bench_17_4_one_limit_alone_shows_a_dash[limits0,limits1]`: only a lower, only an upper -> `-` (R-PE-BENCH.17 "without both limits") |
| m26 | missing test | `test_b103_inc9_b_cells.py::test_r_pe_bench_26_2_the_compact_values_keep_at_most_24_bytes_per_element`: 100,000 elements, retained bytes per element after the decode is dropped <= 24 (the 64 MiB bound over current + staged of a 1,048,576-element row gives 32 B per set; the compact layout keeps 8, a list of floats 32+). The existing `slow` LARGE test (<= 64 MiB, one set) cannot tell the two |
| m34 | missing test | `test_b103_inc9_b_canvas.py::test_r_pe_bench_34_3_the_curve_legend_carries_the_unit_word`: unit `rpm` -> `scale 7.08k … 58.1k rpm   █ edited  ─ old level` |
| m37b | missing test | `test_b103_inc9_b_canvas.py::test_r_pe_bench_37_3_a_chart_window_line_only_while_a_point_is_hidden` |
| m57b | missing test | `test_b103_inc9_b_tools.py::test_r_pe_bench_57_4_an_integer_datatype_with_no_conversion_writes_no_decimals`: MAP (SWORD, IDENTICAL) with decimals 2 -> `3`; as FLOAT32 -> `3.46` |
| m58b | missing test | `test_b103_inc9_b_tools.py::test_r_pe_bench_58_4_a_set_to_the_current_text_leaves_the_edit_empty`: MAP (0,0) shows 472: Set `472` -> {} (old edit on undo), Set `473` -> {(0,0): `473`} |
| w9e | missing test | `test_b103_inc9_b_detail.py::test_r_pe_bench_38_5_the_bytes_line_stays_last_while_the_whole_grid_fits[8,9,10,11,12,20,40]`: MAP_DEF_0001 (no window line) -> the last line is the bytes line (R-PE-BENCH.38) in at most `room` lines; the mutant (canvas_room = room - 3) fails at room 10 |
| w9d | **equivalent** | `bench_detail`'s `decoding` branch holds exactly two lines and is reached only with `room >= 2` (room 0 and 1 and width < 12 return earlier), so `lines[: room + 1]` equals `lines[: room]` for every reachable input |
| w8, w8b | **unpinned by the requirement** (survive) | `_CHART_LABEL` 8 or 10 instead of 9: both keep a gap between the label and the first bar, keep every line within `W` (the geometry reserves `W - 10` through the literal 10 in `_chart_geometry`, not through `_CHART_LABEL`) and show the CTX's labels `58106` / `11719`. The CTX does not state the label column's width, so a test would restate the constant (anti-mirror). Wording item **W-9**: state in the CTX chart look "left labels: right-aligned in 8 cells, then one space" |

The m16b / m17 / m26 / m34 / m37b / m57b / m58b / w9e kills were measured with only the 15 new nodes against each
mutant (`mout2`, 8 killed, w8 / w8b / w9d survived as stated); the 15 nodes pass on the product (run `new-green`).
Laws on the archive tree (git initialised so the root is found): `test_id_registry.py` 13 passed (no new file,
the scanned bound is unchanged), `test_no_private_tokens.py` 2 passed.

## Finding F-M9-1 (production defect, NOT fixed here: outside this brief; for `software-dev` / the orchestrator)

`bench_detail` drops the bytes line whenever the window line shows. It reserves `canvas_room = room - 4` (the
definition line, legend, tool row and bytes line are 4), then appends the window line, so the lines total
`room + 1` and the final `lines[: room]` removes the LAST one, the bytes line. R-PE-BENCH.38 says the bytes line is
the bench's last line; R-PE-BENCH.37 puts the window line between the canvas and the legend; R-PE-BENCH.5 caps the
total. A requirement-consistent render shrinks the canvas by one line when the window line shows. Probe on the
product (LARGE, a state with values, width 118): rooms 6, 8, 12, 20, 30 all return `room` lines whose last line is
the tool row (` s  Set   d  +Δ …`), never the bytes line. The sheet's usual rooms are in that range, so the bytes
preview is invisible on every windowed object. Proposed test (RED on the product, not added so the suite stays
GREEN until the owner decides): for LARGE at rooms 8, 12, 20, 30 the last line of `bench_detail` is the bytes
line `no edit yet · bytes appear here`. Proposed fix: when `window_line` would show, take `canvas_room = room - 5`.
Requirement wins (DF-04 a); this is a defect, not a design question.

## Wording list (Inc 9)

- **W-8** (from W9-F2): R-PE-BENCH.21 / CTX detail say nothing for a refused decode; today `bench_detail` keeps
  `decoding <count> values …` (see `E4-integration-b.md`).
- **W-9** CTX chart look: state the label column (8 cells right-aligned, then one space; `_CHART_LABEL = 9`).

## Not done / limits

- Mutants only on `definition_bench.py` and `definition_bench_view.py`; the widget file `bench_sheet.py` waits for
  the C9b conductor.
- One mutant per requirement row plus W9's list, not an exhaustive operator sweep; the 64 kills were measured with
  `-x`, so the first failing node is shown, not every node that dies.
- The runner scratch `~/work/zq-m9/` is deleted at the end of this task (list in `steps.log`).
