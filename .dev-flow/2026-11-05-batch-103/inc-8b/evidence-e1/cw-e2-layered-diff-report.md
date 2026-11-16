# Code-Wire extractor report

- Marks found: 56
- Graph nodes parsed: 112
- Real calls between marked nodes: 81
- Findings: 92 (91 drift, 1 info)
- Ambiguous call resolutions (a name matched several defs): 39
- Files that failed to parse: 0

Type normalisation: spaces and quotes dropped; `List/Dict/Tuple/Set` -> builtins; `X | None` and graph `X?` -> `Optional[X]`; graph `(Callable) A->B` -> `Callable[[A], B]`; graph `tuple(A a, B b)` -> `tuple[A, B]`. A bare graph container (`dict`) against a parameterised code type (`dict[str, Any]`) is info (loose match), not drift.

Call resolution is name-based (`f()`, `Class()` -> `__init__`, `self.m()`, `x.m()` -> top-level `m` or a marked method `m`); dynamic calls and callables passed as values are not seen. Tests excluded.

## Counts

| Kind | Count |
|---|---|
| Graph node without mark (no code yet) | 56 |
| Input in graph, not a parameter in code | 5 |
| Parameter in code, not an input in graph | 2 |
| Input type mismatch | 3 |
| Parameter unannotated in code (cannot compare) | 22 |
| Output type mismatch | 3 |
| Info: nodes replaced by a later graph (`--layered`) | 1 |

## Real calls between marked nodes

| Caller | Callee | Sites |
|---|---|---|
| `StagingSheet._fit_window` | `detail_lines` | s19_app/tui/screens_directionb/patch_editor/sheet.py:433 |
| `StagingSheet._fit_window` | `ops_for` | s19_app/tui/screens_directionb/patch_editor/sheet.py:397 |
| `StagingSheet._fit_window` | `preview` | s19_app/tui/screens_directionb/patch_editor/sheet.py:400 |
| `StagingSheet._fit_window` | `row_window` | s19_app/tui/screens_directionb/patch_editor/sheet.py:436 |
| `StagingSheet._on_formula_escape` | `StagingSheet._paint` | s19_app/tui/screens_directionb/patch_editor/sheet.py:308 |
| `StagingSheet._on_formula_escape` | `formula_fill` | s19_app/tui/screens_directionb/patch_editor/sheet.py:447 |
| `StagingSheet._on_formula_escape` | `ops_for` | s19_app/tui/screens_directionb/patch_editor/sheet.py:448 |
| `StagingSheet._paint` | `detail_lines` | s19_app/tui/screens_directionb/patch_editor/sheet.py:341 |
| `StagingSheet._paint` | `formula_tail` | s19_app/tui/screens_directionb/patch_editor/sheet.py:384 |
| `StagingSheet._paint` | `header_line` | s19_app/tui/screens_directionb/patch_editor/sheet.py:345 |
| `StagingSheet._paint` | `name_echo` | s19_app/tui/screens_directionb/patch_editor/sheet.py:384 |
| `StagingSheet._paint` | `ops_for` | s19_app/tui/screens_directionb/patch_editor/sheet.py:379, s19_app/tui/screens_directionb/patch_editor/sheet.py:397 |
| `StagingSheet._paint` | `plain` | s19_app/tui/screens_directionb/patch_editor/sheet.py:385 |
| `StagingSheet._paint` | `preview` | s19_app/tui/screens_directionb/patch_editor/sheet.py:400 |
| `StagingSheet._paint` | `row_line` | s19_app/tui/screens_directionb/patch_editor/sheet.py:351 |
| `StagingSheet._paint` | `row_window` | s19_app/tui/screens_directionb/patch_editor/sheet.py:342 |
| `StagingSheet._paint` | `sheet_widths` | s19_app/tui/screens_directionb/patch_editor/sheet.py:339 |
| `StagingSheet.action_choose` | `StagingSheet._paint` | s19_app/tui/screens_directionb/patch_editor/sheet.py:268 |
| `StagingSheet.action_choose` | `formula_fill` | s19_app/tui/screens_directionb/patch_editor/sheet.py:259, s19_app/tui/screens_directionb/patch_editor/sheet.py:267, s19_app/tui/screens_directionb/patch_editor/sheet.py:312 |
| `StagingSheet.action_edit` | `ops_for` | s19_app/tui/screens_directionb/patch_editor/sheet.py:246 |
| `StagingSheet.action_move` | `StagingSheet._fit_window` | s19_app/tui/screens_directionb/patch_editor/sheet.py:225 |
| `StagingSheet.action_move` | `StagingSheet._paint` | s19_app/tui/screens_directionb/patch_editor/sheet.py:227 |
| `StagingSheet.action_move` | `formula_fill` | s19_app/tui/screens_directionb/patch_editor/sheet.py:447 |
| `StagingSheet.action_move` | `ops_for` | s19_app/tui/screens_directionb/patch_editor/sheet.py:448 |
| `StagingSheet.on_input_changed` | `StagingSheet._paint` | s19_app/tui/screens_directionb/patch_editor/sheet.py:280 |
| `StagingSheet.on_input_changed` | `formula_fill` | s19_app/tui/screens_directionb/patch_editor/sheet.py:312 |
| `StagingSheet.on_input_submitted` | `ops_for` | s19_app/tui/screens_directionb/patch_editor/sheet.py:288 |
| `StagingSheet.select_after` | `StagingSheet._fit_window` | s19_app/tui/screens_directionb/patch_editor/sheet.py:225 |
| `StagingSheet.select_after` | `StagingSheet._paint` | s19_app/tui/screens_directionb/patch_editor/sheet.py:218, s19_app/tui/screens_directionb/patch_editor/sheet.py:227 |
| `StagingSheet.select_after` | `formula_fill` | s19_app/tui/screens_directionb/patch_editor/sheet.py:447 |
| `StagingSheet.select_after` | `ops_for` | s19_app/tui/screens_directionb/patch_editor/sheet.py:448 |
| `StagingSheet.set_document` | `StagingSheet._fit_window` | s19_app/tui/screens_directionb/patch_editor/sheet.py:195 |
| `StagingSheet.set_document` | `StagingSheet._paint` | s19_app/tui/screens_directionb/patch_editor/sheet.py:197 |
| `StagingSheet.set_document` | `build_row` | s19_app/tui/screens_directionb/patch_editor/sheet.py:192 |
| `StagingSheet.set_document` | `formula_fill` | s19_app/tui/screens_directionb/patch_editor/sheet.py:447 |
| `StagingSheet.set_document` | `ops_for` | s19_app/tui/screens_directionb/patch_editor/sheet.py:448 |
| `StagingSheet.show_page` | `StagingSheet._fit_window` | s19_app/tui/screens_directionb/patch_editor/sheet.py:174 |
| `StagingSheet.show_page` | `StagingSheet._paint` | s19_app/tui/screens_directionb/patch_editor/sheet.py:176 |
| `StagingSheet.show_page` | `build_row` | s19_app/tui/screens_directionb/patch_editor/sheet.py:167 |
| `StagingSheet.show_page` | `formula_fill` | s19_app/tui/screens_directionb/patch_editor/sheet.py:447 |
| `StagingSheet.show_page` | `ops_for` | s19_app/tui/screens_directionb/patch_editor/sheet.py:448 |
| `_SheetBody.on_resize` | `StagingSheet._paint` | s19_app/tui/screens_directionb/patch_editor/sheet.py:53 |
| `_detail_enum` | `plain` | s19_app/tui/definition_sheet.py:481, s19_app/tui/definition_sheet.py:492, s19_app/tui/definition_sheet.py:493, s19_app/tui/definition_sheet.py:527, s19_app/tui/definition_sheet.py:529 |
| `_detail_mask` | `plain` | s19_app/tui/definition_sheet.py:481, s19_app/tui/definition_sheet.py:492, s19_app/tui/definition_sheet.py:493 |
| `_detail_text` | `plain` | s19_app/tui/definition_sheet.py:481, s19_app/tui/definition_sheet.py:492, s19_app/tui/definition_sheet.py:493 |
| `_scalar_tail` | `_verdict` | s19_app/tui/definition_sheet.py:934 |
| `_scalar_tail` | `plain` | s19_app/tui/definition_sheet.py:918 |
| `_scalar_tail` | `short_number` | s19_app/tui/definition_sheet.py:921 |
| `_stock_cells` | `delta_text` | s19_app/tui/definition_sheet.py:801, s19_app/tui/definition_sheet.py:802 |
| `_stock_cells` | `kind_word` | s19_app/tui/definition_sheet.py:823 |
| `_stock_cells` | `limits_cell` | s19_app/tui/definition_sheet.py:826 |
| `_stock_cells` | `ops_for` | s19_app/tui/definition_sheet.py:820 |
| `_stock_cells` | `plain` | s19_app/tui/definition_sheet.py:78 |
| `_stock_cells` | `value_text` | s19_app/tui/definition_sheet.py:795, s19_app/tui/definition_sheet.py:824 |
| `_verdict` | `plain` | s19_app/tui/definition_sheet.py:911 |
| `apply_tool` | `name_echo` | s19_app/tui/definition_bench.py:395, s19_app/tui/definition_bench.py:400 |
| `apply_tool` | `parse_operand` | s19_app/tui/definition_bench.py:398 |
| `apply_tool` | `result_text` | s19_app/tui/definition_bench.py:437 |
| `apply_tool` | `selection_cells` | s19_app/tui/definition_bench.py:384, s19_app/tui/definition_bench.py:406 |
| `bench_cells` | `bench_grid` | s19_app/tui/definition_bench.py:624 |
| `bench_cells` | `kind_word` | s19_app/tui/definition_bench.py:627 |
| `bench_cells` | `plain` | s19_app/tui/definition_bench.py:627 |
| `bench_cells` | `short_number` | s19_app/tui/definition_bench.py:602, s19_app/tui/definition_bench.py:609, s19_app/tui/definition_bench.py:648 |
| `build_row` | `ops_for` | s19_app/tui/definition_sheet.py:653 |
| `build_row` | `row_kind` | s19_app/tui/definition_sheet.py:652 |
| `detail_lines` | `ops_for` | s19_app/tui/definition_sheet.py:877 |
| `formula_fill` | `ops_for` | s19_app/tui/definition_sheet.py:897 |
| `formula_tail` | `_scalar_tail` | s19_app/tui/definition_sheet.py:952 |
| `formula_tail` | `kind_word` | s19_app/tui/definition_sheet.py:943 |
| `formula_tail` | `ops_for` | s19_app/tui/definition_sheet.py:942 |
| `formula_tail` | `plain` | s19_app/tui/definition_sheet.py:918, s19_app/tui/definition_sheet.py:943, s19_app/tui/definition_sheet.py:947 |
| `formula_tail` | `short_number` | s19_app/tui/definition_sheet.py:921 |
| `header_line` | `plain` | s19_app/tui/definition_sheet.py:78 |
| `limits_cell` | `short_number` | s19_app/tui/definition_sheet.py:750 |
| `name_echo` | `plain` | s19_app/tui/definition_sheet.py:62 |
| `row_line` | `_mark` | s19_app/tui/definition_sheet.py:847 |
| `row_line` | `_stock_cells` | s19_app/tui/definition_sheet.py:854 |
| `row_line` | `ops_for` | s19_app/tui/definition_sheet.py:843 |
| `row_line` | `plain` | s19_app/tui/definition_sheet.py:78 |
| `value_text` | `ops_for` | s19_app/tui/definition_sheet.py:641 |
| `where_text` | `selection_cells` | s19_app/tui/definition_bench.py:334 |

Top-level sites (no marked node above them):

- `A2LParameterPicker.set_parameters`: s19_app/tui/screens_directionb/check_editor.py:223, s19_app/tui/screens_directionb/patch_editor/a2l_picker.py:42
- `BenchValues.from_decoded`: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:176, s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:180, s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:186, s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:217
- `StagingSheet._on_formula_escape`: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:407, s19_app/tui/screens_directionb/patch_editor/sheet.py:296
- `StagingSheet._paint`: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:104, s19_app/tui/screens_directionb/patch_editor/sheet.py:137
- `StagingSheet.action_choose`: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:363
- `StagingSheet.action_edit`: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:329
- `StagingSheet.action_move`: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:351, s19_app/tui/segment_split_view.py:1248
- `StagingSheet.select_after`: s19_app/tui/screens_directionb/patch_editor/panel.py:732
- `StagingSheet.set_document`: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:549, s19_app/tui/screens_directionb/patch_editor/panel.py:697, s19_app/tui/screens_directionb/patch_editor/panel.py:713
- `StagingSheet.show_page`: s19_app/tui/screens_directionb/patch_editor/a2l_picker.py:228, s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:531
- `_SheetBody.on_resize`: s19_app/tui/app/shared.py:584
- `apply_tool`: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:456
- `bench_cells`: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:612 (ref)
- `bench_grid`: s19_app/tui/definition_bench_view.py:307, s19_app/tui/definition_bench_view.py:516, s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:288, s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:348, s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:360, s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:373, s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:385, s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:456
- `bench_mark`: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:614 (ref)
- `bench_preview`: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:609 (ref)
- `move_cursor`: s19_app/tui/app/a2l_view.py:1211, s19_app/tui/app/a2l_view.py:511, s19_app/tui/screens_directionb/patch_editor/a2l_picker.py:245, s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:349, s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:361, s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:374
- `name_echo`: s19_app/tui/app/patch.py:417, s19_app/tui/app/patch.py:422, s19_app/tui/app/patch.py:431, s19_app/tui/definition_bench_view.py:518, s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:233, s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:452, s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:470, s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:475, s19_app/tui/services/change_service.py:1473, s19_app/tui/services/change_service.py:1493, s19_app/tui/services/change_service.py:1494
- `ops_for`: s19_app/tui/definition_sheet.py:389
- `page_cursor`: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:387
- `plain`: s19_app/tui/definition_bench_view.py:130, s19_app/tui/definition_bench_view.py:133, s19_app/tui/definition_bench_view.py:206, s19_app/tui/definition_bench_view.py:302, s19_app/tui/definition_bench_view.py:383, s19_app/tui/definition_bench_view.py:411, s19_app/tui/definition_bench_view.py:500, s19_app/tui/definition_bench_view.py:524, s19_app/tui/definition_bench_view.py:535
- `preview`: s19_app/tui/definition_sheet.py:619 (ref)
- `selection_cells`: s19_app/tui/definition_bench_view.py:529
- `sheet_widths`: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:138
- `short_number`: s19_app/tui/definition_bench_view.py:415, s19_app/tui/definition_bench_view.py:417, s19_app/tui/definition_bench_view.py:428, s19_app/tui/definition_bench_view.py:430
- `summary_strip`: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:290
- `undo`: s19_app/tui/app/patch.py:846, s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:424
- `value_text`: s19_app/tui/definition_sheet.py:390
- `where_text`: s19_app/tui/definition_bench_view.py:433, s19_app/tui/definition_bench_view.py:517
- `window_for`: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:320

## Graph node without mark (no code yet)

- `s19_app/tui/screens_directionb/patch_editor/layout.py` — `LayoutMixin.compose`
- `s19_app/tui/screens_directionb/patch_editor/panel.py` — `PatchEditorPanel.__init__`
- `s19_app/tui/screens_directionb/patch_editor/panel.py` — `PatchEditorPanel._show_tab`
- `s19_app/tui/screens_directionb/patch_editor/panel.py` — `PatchEditorPanel._refresh_inspector_subtitle`
- `s19_app/tui/screens_directionb/patch_editor/panel.py` — `PatchEditorPanel.refresh_entries`
- `s19_app/tui/screens_directionb/patch_editor/panel.py` — `PatchEditorPanel.set_image_mem_map`
- `s19_app/tui/screens_directionb/patch_editor/panel.py` — `PatchEditorPanel.note_staged`
- `s19_app/tui/screens_directionb/patch_editor/a2l_picker.py` — `A2lPickerMixin._compose_filter_row`
- `s19_app/tui/screens_directionb/patch_editor/a2l_picker.py` — `A2lPickerMixin._compose_use_row`
- `s19_app/tui/screens_directionb/patch_editor/a2l_picker.py` — `A2lPickerMixin._on_a2l_parameter_picker_view_changed`
- `s19_app/tui/screens_directionb/patch_editor/a2l_picker.py` — `A2lPickerMixin._on_staging_sheet_selection_changed`
- `s19_app/tui/screens_directionb/patch_editor/panel.py` — `PatchEditorPanel._TABS`
- `s19_app/tui/services/change_service.py` — `ChangeService.stage_definition`
- `s19_app/tui/services/change_service.py` — `ChangeService._stage_encoded`
- `s19_app/tui/app/patch.py` — `PatchMixin.on_staging_sheet_stage_requested`
- `s19_app/tui/window_help.py` — `WINDOW_HELP_SECTIONS`
- `s19_app/tui/definition_bench_view.py` — `bench_detail`
- `s19_app/tui/definition_bench_view.py` — `grid_canvas`
- `s19_app/tui/definition_bench_view.py` — `chart_canvas`
- `s19_app/tui/definition_bench_view.py` — `axis_labels`
- `s19_app/tui/definition_bench_view.py` — `legend_line`
- `s19_app/tui/definition_bench_view.py` — `tool_row`
- `s19_app/tui/definition_bench_view.py` — `window_line`
- `s19_app/tui/definition_bench_view.py` — `bytes_line`
- `s19_app/tui/definition_bench_view.py` — `op_line`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `register_bench_kinds`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `bench_submit`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `ArrayBenchSheet.check_action`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `ArrayBenchSheet.action_edit`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `ArrayBenchSheet.action_move`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `ArrayBenchSheet.action_choose`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `ArrayBenchSheet.action_cursor`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `ArrayBenchSheet.action_page`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `ArrayBenchSheet.action_tool`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `ArrayBenchSheet.action_leave_bench`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `ArrayBenchSheet.action_stage_record`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `ArrayBenchSheet.on_array_bench_sheet_bench_apply_requested`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `ArrayBenchSheet.on_staging_sheet_selection_changed`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `ArrayBenchSheet._on_formula_escape`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `ArrayBenchSheet.show_page`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `ArrayBenchSheet.set_document`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `ArrayBenchSheet._run_job`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `ArrayBenchSheet._job_done`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `ArrayBenchSheet.record_staged`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `ArrayBenchSheet.record_done`
- `s19_app/tui/services/change_service.py` — `ChangeService.stage_record`
- `s19_app/tui/app/patch.py` — `PatchMixin.on_array_bench_sheet_record_stage_requested`
- `s19_app/tui/definition_sheet.py` — `header_rule`
- `s19_app/tui/definition_sheet.py` — `limit_slot`
- `s19_app/tui/definition_sheet.py` — `range_cell`
- `s19_app/tui/definition_sheet.py` — `_tone`
- `s19_app/tui/definition_sheet.py` — `card_lines`
- `s19_app/tui/definition_sheet.py` — `bit_table`
- `s19_app/tui/definition_sheet.py` — `hex_grid`
- `s19_app/tui/screens_directionb/patch_editor/sheet.py` — `StagingSheet.action_scroll_grid`
- `s19_app/tui/screens_directionb/patch_editor/sheet.py` — `StagingSheet._view_width`

## Input in graph, not a parameter in code

- `s19_app/tui/definition_sheet.py:267` — graph input `value` not a parameter of `short_number`
- `s19_app/tui/definition_sheet.py:743` — graph input `tone` not a parameter of `limits_cell`
- `s19_app/tui/definition_sheet.py:831` — graph input `odd` not a parameter of `row_line`
- `s19_app/tui/definition_sheet.py:59` — graph input `name` not a parameter of `name_echo`
- `s19_app/tui/definition_sheet.py:818` — graph input `tone` not a parameter of `_stock_cells`

## Parameter in code, not an input in graph

- `s19_app/tui/definition_sheet.py:267` — parameter `x: float` not in graph
- `s19_app/tui/definition_sheet.py:59` — parameter `text: str` not in graph

## Input type mismatch

- `s19_app/tui/definition_sheet.py:417` — `a2l_data`: graph `dict` vs code `Optional[dict]`
- `s19_app/tui/screens_directionb/patch_editor/sheet.py:148` — `definitions`: graph `Mapping[str, Definition]` vs code `Mapping[str, object]`
- `s19_app/tui/screens_directionb/patch_editor/sheet.py:49` — `event`: graph `Resize` vs code `events.Resize`

## Parameter unannotated in code (cannot compare)

- `s19_app/tui/definition_sheet.py:417` — `overlay` has no annotation (graph: `StagedOverlay`)
- `s19_app/tui/definition_sheet.py:818` — `row` has no annotation (graph: `SheetRow`)
- `s19_app/tui/definition_sheet.py:818` — `widths` has no annotation (graph: `SheetWidths`)
- `s19_app/tui/definition_sheet.py:818` — `is_pending` has no annotation (graph: `bool`)
- `s19_app/tui/definition_sheet.py:818` — `pending` has no annotation (graph: `Optional[str]`)
- `s19_app/tui/definition_sheet.py:818` — `preview` has no annotation (graph: `Optional[Preview]`)
- `s19_app/tui/definition_sheet.py:818` — `new` has no annotation (graph: `object`)
- `s19_app/tui/definition_sheet.py:533` — `row` has no annotation (graph: `SheetRow`)
- `s19_app/tui/definition_sheet.py:533` — `preview` has no annotation (graph: `Optional[Preview]`)
- `s19_app/tui/definition_sheet.py:533` — `width` has no annotation (graph: `int`)
- `s19_app/tui/definition_sheet.py:533` — `state` has no annotation (graph: `object`)
- `s19_app/tui/definition_sheet.py:533` — `room` has no annotation (graph: `int`)
- `s19_app/tui/definition_sheet.py:557` — `row` has no annotation (graph: `SheetRow`)
- `s19_app/tui/definition_sheet.py:557` — `preview` has no annotation (graph: `Optional[Preview]`)
- `s19_app/tui/definition_sheet.py:557` — `width` has no annotation (graph: `int`)
- `s19_app/tui/definition_sheet.py:557` — `state` has no annotation (graph: `object`)
- `s19_app/tui/definition_sheet.py:557` — `room` has no annotation (graph: `int`)
- `s19_app/tui/definition_sheet.py:582` — `row` has no annotation (graph: `SheetRow`)
- `s19_app/tui/definition_sheet.py:582` — `preview` has no annotation (graph: `Optional[Preview]`)
- `s19_app/tui/definition_sheet.py:582` — `width` has no annotation (graph: `int`)
- `s19_app/tui/definition_sheet.py:582` — `state` has no annotation (graph: `object`)
- `s19_app/tui/definition_sheet.py:582` — `room` has no annotation (graph: `int`)

## Output type mismatch

- `s19_app/tui/definition_sheet.py:881` — graph `tuple[int, int] (top, detail lines` vs code `tuple[int, int]`
- `s19_app/tui/definition_bench.py:193` — graph `tuple(int row, int col)` vs code `tuple[int, int]`
- `s19_app/tui/definition_sheet.py:818` — graph `tuple[Text, Text, Text, Text, Text]` vs code `tuple`

## Info: nodes replaced by a later graph (`--layered`)

- `graphs` — 12 replaced by a later graph: `PatchEditorPanel.__init__`, `LayoutMixin.compose`, `sheet_widths`, `header_line`, `limits_cell`, `row_line`, `detail_lines`, `formula_tail`, `StagingSheet._paint`, `WINDOW_HELP_SECTIONS`, `summary_strip`, `bench_cells`
