# Code-Wire extractor report

- Marks found: 22
- Graph nodes parsed: 127
- Real calls between marked nodes: 15
- Findings: 135 (134 drift, 1 info)
- Ambiguous call resolutions (a name matched several defs): 39
- Files that failed to parse: 0

Type normalisation: spaces and quotes dropped; `List/Dict/Tuple/Set` -> builtins; `X | None` and graph `X?` -> `Optional[X]`; graph `(Callable) A->B` -> `Callable[[A], B]`; graph `tuple(A a, B b)` -> `tuple[A, B]`. A bare graph container (`dict`) against a parameterised code type (`dict[str, Any]`) is info (loose match), not drift.

Call resolution is name-based (`f()`, `Class()` -> `__init__`, `self.m()`, `x.m()` -> top-level `m` or a marked method `m`); dynamic calls and callables passed as values are not seen. Tests excluded.

## Counts

| Kind | Count |
|---|---|
| Graph node without mark (no code yet) | 105 |
| Parameter in code, not an input in graph | 2 |
| Parameter unannotated in code (cannot compare) | 24 |
| Output type mismatch | 1 |
| Return unannotated in code (cannot compare) | 2 |
| Info: nodes replaced by a later graph (`--layered`) | 1 |

## Real calls between marked nodes

| Caller | Callee | Sites |
|---|---|---|
| `ArrayBenchSheet._enqueue` | `ArrayBenchSheet._run_job` | s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:163 |
| `ArrayBenchSheet._job_done` | `ArrayBenchSheet._run_job` | s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:163 |
| `ArrayBenchSheet.action_choose` | `ArrayBenchSheet._bench_geometry` | s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:318 |
| `ArrayBenchSheet.action_cursor` | `ArrayBenchSheet._bench_geometry` | s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:318 |
| `ArrayBenchSheet.action_move` | `ArrayBenchSheet._bench_geometry` | s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:318 |
| `ArrayBenchSheet.action_page` | `ArrayBenchSheet._bench_geometry` | s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:318, s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:385 |
| `ArrayBenchSheet.action_stage_record` | `ArrayBenchSheet._enqueue` | s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:476 |
| `ArrayBenchSheet.action_tool` | `ArrayBenchSheet._enqueue` | s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:434 |
| `ArrayBenchSheet.on_array_bench_sheet_bench_apply_requested` | `ArrayBenchSheet._enqueue` | s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:434 |
| `ArrayBenchSheet.on_staging_sheet_selection_changed` | `ArrayBenchSheet._enqueue` | s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:522, s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:524 |
| `ArrayBenchSheet.record_done` | `ArrayBenchSheet._run_job` | s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:163 |
| `ArrayBenchSheet.set_document` | `ArrayBenchSheet._enqueue` | s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:566, s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:568, s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:570 |
| `ArrayBenchSheet.set_document` | `ArrayBenchSheet._run_job` | s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:163 |
| `ArrayBenchSheet.show_page` | `ArrayBenchSheet._run_job` | s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:163 |
| `register_bench_kinds` | `bench_submit` | s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:610 (ref) |

Top-level sites (no marked node above them):

- `ArrayBenchSheet.action_move`: s19_app/tui/segment_split_view.py:1248
- `ArrayBenchSheet.check_action`: s19_app/tui/app/core.py:947, s19_app/tui/segment_split_view.py:1817, s19_app/tui/window_help.py:1230, s19_app/tui/window_help.py:1241
- `ArrayBenchSheet.record_done`: s19_app/tui/app/patch.py:404
- `ArrayBenchSheet.record_staged`: s19_app/tui/app/patch.py:443
- `ArrayBenchSheet.set_document`: s19_app/tui/screens_directionb/patch_editor/panel.py:697, s19_app/tui/screens_directionb/patch_editor/panel.py:713
- `ArrayBenchSheet.show_page`: s19_app/tui/screens_directionb/patch_editor/a2l_picker.py:228

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
- `s19_app/tui/screens_directionb/patch_editor/sheet.py` — `_SheetBody.on_resize`
- `s19_app/tui/screens_directionb/patch_editor/sheet.py` — `StagingSheet.on_resize`
- `s19_app/tui/definition_sheet.py` — `_definition_line`
- `s19_app/tui/a2l_parameter_picker.py` — `A2LParameterPicker.compose`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `busy_job`
- `s19_app/tui/definition_bench_view.py` — `busy_title`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `ArrayBenchSheet.on_mount`
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` — `ArrayBenchSheet._busy_tick`
- `s19_app/tui/app/patch.py` — `PatchMixin._stage_bench_record`
- `s19_app/tui/app/patch.py` — `PatchMixin._refresh_patch_history_view`
- `s19_app/tui/app/patch.py` — `PatchMixin._patch_refresh_steps`
- `s19_app/tui/app/patch.py` — `PatchMixin._run_refresh_steps`
- `s19_app/tui/app/patch.py` — `PatchMixin._patch_document_token`
- `s19_app/tui/screens_directionb/patch_editor/panel.py` — `PatchEditorPanel.refresh_sheet_document`

## Parameter in code, not an input in graph

- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:166` — parameter `snapshot: None` not in graph
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:166` — parameter `edit: None` not in graph

## Parameter unannotated in code (cannot compare)

- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:375` — `direction` has no annotation (graph: `int`)
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:414` — `key` has no annotation (graph: `str`)
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:441` — `event` has no annotation (graph: `ArrayBenchSheet.BenchApplyRequested`)
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:494` — `event` has no annotation (graph: `StagingSheet.SelectionChanged`)
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:527` — `names` has no annotation (graph: `Sequence[str]`)
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:527` — `definitions` has no annotation (graph: `Mapping[str, Definition]`)
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:527` — `a2l_data` has no annotation (graph: `Optional[dict]`)
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:527` — `image` has no annotation (graph: `Optional[Mapping[int, int]]`)
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:544` — `entries` has no annotation (graph: `Sequence[tuple[int, Sequence[int]]]`)
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:544` — `image` has no annotation (graph: `Optional[Mapping[int, int]]`)
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:166` — `kind` has no annotation (graph: `str`)
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:166` — `name` has no annotation (graph: `str`)
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:166` — `generation` has no annotation (graph: `int`)
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:166` — `definition` has no annotation (graph: `Definition`)
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:220` — `kind` has no annotation (graph: `str`)
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:220` — `name` has no annotation (graph: `str`)
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:220` — `generation` has no annotation (graph: `int`)
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:220` — `result` has no annotation (graph: `object`)
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:220` — `derived` has no annotation (graph: `object`)
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:478` — `name` has no annotation (graph: `str`)
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:478` — `edit` has no annotation (graph: `tuple`)
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:488` — `name` has no annotation (graph: `str`)
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:309` — `state` has no annotation (graph: `BenchState`)
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:309` — `grid` has no annotation (graph: `Grid`)

## Output type mismatch

- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:588` — graph `Message` vs code `ArrayBenchSheet.BenchApplyRequested`

## Return unannotated in code (cannot compare)

- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:166` — graph `None`, no return annotation
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py:220` — graph `None`, no return annotation

## Info: nodes replaced by a later graph (`--layered`)

- `graphs` — 16 replaced by a later graph: `PatchEditorPanel.__init__`, `LayoutMixin.compose`, `sheet_widths`, `header_line`, `limits_cell`, `row_line`, `detail_lines`, `formula_tail`, `StagingSheet._paint`, `WINDOW_HELP_SECTIONS`, `summary_strip`, `bench_cells`, `ArrayBenchSheet._job_done`, `ArrayBenchSheet.record_done`, `PatchMixin.on_array_bench_sheet_record_stage_requested`, `PatchEditorPanel.refresh_entries`
