# Code-Wire extractor report

- Marks found: 6
- Graph nodes parsed: 127
- Real calls between marked nodes: 2
- Findings: 124 (123 drift, 1 info)
- Ambiguous call resolutions (a name matched several defs): 39
- Files that failed to parse: 0

Type normalisation: spaces and quotes dropped; `List/Dict/Tuple/Set` -> builtins; `X | None` and graph `X?` -> `Optional[X]`; graph `(Callable) A->B` -> `Callable[[A], B]`; graph `tuple(A a, B b)` -> `tuple[A, B]`. A bare graph container (`dict`) against a parameterised code type (`dict[str, Any]`) is info (loose match), not drift.

Call resolution is name-based (`f()`, `Class()` -> `__init__`, `self.m()`, `x.m()` -> top-level `m` or a marked method `m`); dynamic calls and callables passed as values are not seen. Tests excluded.

## Counts

| Kind | Count |
|---|---|
| Graph node without mark (no code yet) | 121 |
| Input in graph, not a parameter in code | 1 |
| Input type mismatch | 1 |
| Info: nodes replaced by a later graph (`--layered`) | 1 |

## Real calls between marked nodes

| Caller | Callee | Sites |
|---|---|---|
| `PatchEditorPanel._show_tab` | `PatchEditorPanel._refresh_inspector_subtitle` | s19_app/tui/screens_directionb/patch_editor/panel.py:777 |
| `PatchEditorPanel.note_staged` | `PatchEditorPanel._refresh_inspector_subtitle` | s19_app/tui/screens_directionb/patch_editor/panel.py:738 |

Top-level sites (no marked node above them):

- `PatchEditorPanel.__init__`: s19_app/tui/app/compose_screens.py:540
- `PatchEditorPanel._refresh_inspector_subtitle`: s19_app/tui/screens_directionb/patch_editor/panel.py:628
- `PatchEditorPanel.note_staged`: s19_app/tui/app/patch.py:377, s19_app/tui/app/patch.py:442
- `PatchEditorPanel.refresh_entries`: s19_app/tui/app/loaded_state.py:675, s19_app/tui/app/patch.py:1660, s19_app/tui/app/patch.py:294, s19_app/tui/app/patch.py:696, s19_app/tui/app/project_load.py:1029, s19_app/tui/screens_directionb/patch_editor/panel.py:755
- `PatchEditorPanel.set_image_mem_map`: s19_app/tui/app/loaded_state.py:407

## Graph node without mark (no code yet)

- `s19_app/tui/definition_sheet.py` — `sheet_widths`
- `s19_app/tui/definition_sheet.py` — `StagedOverlay.__getitem__`
- `s19_app/tui/definition_sheet.py` — `row_kind`
- `s19_app/tui/definition_sheet.py` — `ops_for`
- `s19_app/tui/definition_sheet.py` — `kind_word`
- `s19_app/tui/definition_sheet.py` — `build_row`
- `s19_app/tui/definition_sheet.py` — `value_text`
- `s19_app/tui/definition_sheet.py` — `preview`
- `s19_app/tui/definition_sheet.py` — `delta_text`
- `s19_app/tui/definition_sheet.py` — `short_number`
- `s19_app/tui/definition_sheet.py` — `limits_cell`
- `s19_app/tui/definition_sheet.py` — `row_line`
- `s19_app/tui/definition_sheet.py` — `header_line`
- `s19_app/tui/definition_sheet.py` — `detail_lines`
- `s19_app/tui/definition_sheet.py` — `row_window`
- `s19_app/tui/definition_sheet.py` — `formula_fill`
- `s19_app/tui/definition_sheet.py` — `formula_tail`
- `s19_app/tui/definition_sheet.py` — `plain`
- `s19_app/tui/definition_sheet.py` — `name_echo`
- `s19_app/tui/screens_directionb/patch_editor/sheet.py` — `StagingSheet.show_page`
- `s19_app/tui/screens_directionb/patch_editor/sheet.py` — `StagingSheet.set_document`
- `s19_app/tui/screens_directionb/patch_editor/sheet.py` — `StagingSheet.action_move`
- `s19_app/tui/screens_directionb/patch_editor/sheet.py` — `StagingSheet.action_edit`
- `s19_app/tui/screens_directionb/patch_editor/sheet.py` — `StagingSheet.action_choose`
- `s19_app/tui/screens_directionb/patch_editor/sheet.py` — `StagingSheet.on_input_submitted`
- `s19_app/tui/screens_directionb/patch_editor/sheet.py` — `StagingSheet.on_input_changed`
- `s19_app/tui/screens_directionb/patch_editor/sheet.py` — `StagingSheet._on_formula_escape`
- `s19_app/tui/screens_directionb/patch_editor/sheet.py` — `StagingSheet.select_after`
- `s19_app/tui/screens_directionb/patch_editor/sheet.py` — `StagingSheet._paint`
- `s19_app/tui/screens_directionb/patch_editor/layout.py` — `LayoutMixin.compose`
- `s19_app/tui/screens_directionb/patch_editor/a2l_picker.py` — `A2lPickerMixin._compose_filter_row`
- `s19_app/tui/screens_directionb/patch_editor/a2l_picker.py` — `A2lPickerMixin._compose_use_row`
- `s19_app/tui/screens_directionb/patch_editor/a2l_picker.py` — `A2lPickerMixin._on_a2l_parameter_picker_view_changed`
- `s19_app/tui/screens_directionb/patch_editor/a2l_picker.py` — `A2lPickerMixin._on_staging_sheet_selection_changed`
- `s19_app/tui/screens_directionb/patch_editor/panel.py` — `PatchEditorPanel._TABS`
- `s19_app/tui/services/change_service.py` — `ChangeService.stage_definition`
- `s19_app/tui/services/change_service.py` — `ChangeService._stage_encoded`
- `s19_app/tui/app/patch.py` — `PatchMixin.on_staging_sheet_stage_requested`
- `s19_app/tui/a2l_parameter_picker.py` — `A2LParameterPicker.set_parameters`
- `s19_app/tui/window_help.py` — `WINDOW_HELP_SECTIONS`
- `s19_app/tui/definition_bench.py` — `bench_grid`
- `s19_app/tui/definition_bench.py` — `BenchValues.from_decoded`
- `s19_app/tui/definition_bench.py` — `move_cursor`
- `s19_app/tui/definition_bench.py` — `page_cursor`
- `s19_app/tui/definition_bench.py` — `window_for`
- `s19_app/tui/definition_bench.py` — `selection_cells`
- `s19_app/tui/definition_bench.py` — `where_text`
- `s19_app/tui/definition_bench.py` — `parse_operand`
- `s19_app/tui/definition_bench.py` — `apply_tool`
- `s19_app/tui/definition_bench.py` — `result_text`
- `s19_app/tui/definition_bench.py` — `undo`
- `s19_app/tui/definition_bench.py` — `bench_cells`
- `s19_app/tui/definition_bench.py` — `bench_mark`
- `s19_app/tui/definition_bench.py` — `summary_strip`
- `s19_app/tui/definition_bench.py` — `bench_preview`
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
- `s19_app/tui/definition_sheet.py` — `_mark`
- `s19_app/tui/definition_sheet.py` — `_stock_cells`
- `s19_app/tui/definition_sheet.py` — `card_lines`
- `s19_app/tui/definition_sheet.py` — `bit_table`
- `s19_app/tui/definition_sheet.py` — `hex_grid`
- `s19_app/tui/definition_sheet.py` — `_detail_enum`
- `s19_app/tui/definition_sheet.py` — `_detail_mask`
- `s19_app/tui/definition_sheet.py` — `_detail_text`
- `s19_app/tui/definition_sheet.py` — `_verdict`
- `s19_app/tui/definition_sheet.py` — `_scalar_tail`
- `s19_app/tui/screens_directionb/patch_editor/sheet.py` — `StagingSheet.compose`
- `s19_app/tui/screens_directionb/patch_editor/sheet.py` — `StagingSheet.action_scroll_grid`
- `s19_app/tui/screens_directionb/patch_editor/sheet.py` — `StagingSheet._view_width`
- `s19_app/tui/screens_directionb/patch_editor/sheet.py` — `StagingSheet._detail_geometry`
- `s19_app/tui/screens_directionb/patch_editor/sheet.py` — `StagingSheet._fit_window`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `ArrayBenchSheet._bench_geometry`
- `s19_app/tui/screens_directionb/patch_editor/sheet.py` — `_SheetBody.on_resize`
- `s19_app/tui/screens_directionb/patch_editor/sheet.py` — `StagingSheet.on_resize`
- `s19_app/tui/definition_sheet.py` — `_definition_line`
- `s19_app/tui/a2l_parameter_picker.py` — `A2LParameterPicker.compose`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `busy_job`
- `s19_app/tui/definition_bench_view.py` — `busy_title`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `ArrayBenchSheet.on_mount`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `ArrayBenchSheet._enqueue`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `ArrayBenchSheet._busy_tick`
- `s19_app/tui/app/patch.py` — `PatchMixin._stage_bench_record`
- `s19_app/tui/app/patch.py` — `PatchMixin._refresh_patch_history_view`
- `s19_app/tui/app/patch.py` — `PatchMixin._patch_refresh_steps`
- `s19_app/tui/app/patch.py` — `PatchMixin._run_refresh_steps`
- `s19_app/tui/app/patch.py` — `PatchMixin._patch_document_token`
- `s19_app/tui/screens_directionb/patch_editor/panel.py` — `PatchEditorPanel.refresh_sheet_document`

## Input in graph, not a parameter in code

- `s19_app/tui/screens_directionb/patch_editor/panel.py:699` — graph input `sheet` not a parameter of `PatchEditorPanel.refresh_entries`

## Input type mismatch

- `s19_app/tui/screens_directionb/patch_editor/panel.py:699` — `mem_map`: graph `object` vs code `Union[Mapping[int, int], None, _Unset]`

## Info: nodes replaced by a later graph (`--layered`)

- `graphs` — 16 replaced by a later graph: `PatchEditorPanel.__init__`, `LayoutMixin.compose`, `sheet_widths`, `header_line`, `limits_cell`, `row_line`, `detail_lines`, `formula_tail`, `StagingSheet._paint`, `WINDOW_HELP_SECTIONS`, `summary_strip`, `bench_cells`, `ArrayBenchSheet._job_done`, `ArrayBenchSheet.record_done`, `PatchMixin.on_array_bench_sheet_record_stage_requested`, `PatchEditorPanel.refresh_entries`
