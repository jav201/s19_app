# Code-Wire extractor report

- Marks found: 41
- Graph nodes parsed: 41
- Real calls between marked nodes: 47
- Findings: 0 (0 drift, 0 info)
- Ambiguous call resolutions (a name matched several defs): 0
- Files that failed to parse: 0

Type normalisation: spaces and quotes dropped; `List/Dict/Tuple/Set` -> builtins; `X | None` and graph `X?` -> `Optional[X]`; graph `(Callable) A->B` -> `Callable[[A], B]`; graph `tuple(A a, B b)` -> `tuple[A, B]`. A bare graph container (`dict`) against a parameterised code type (`dict[str, Any]`) is info (loose match), not drift.

Call resolution is name-based (`f()`, `Class()` -> `__init__`, `self.m()`, `x.m()` -> top-level `m` or a marked method `m`); dynamic calls and callables passed as values are not seen. Tests excluded.

## Counts

| Kind | Count |
|---|---|

## Real calls between marked nodes

| Caller | Callee | Sites |
|---|---|---|
| `S19TuiApp._abort_save` | `painted_names` | s19_app/tui/app.py:9276 |
| `S19TuiApp._copy_project_subfolders` | `_plan_row_mismatch` | s19_app/tui/app.py:12346 |
| `S19TuiApp._copy_project_subfolders` | `painted_names` | s19_app/tui/app.py:12299, s19_app/tui/app.py:12355, s19_app/tui/app.py:12356, s19_app/tui/app.py:12358, s19_app/tui/app.py:12366, s19_app/tui/app.py:12367 |
| `S19TuiApp._decide_project_image` | `ChangeService.image_differs_from_source` | s19_app/tui/app.py:10662 |
| `S19TuiApp._handle_save_dialog` | `ChangeService.image_differs_from_source` | s19_app/tui/app.py:10454 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp._abort_save` | s19_app/tui/app.py:10041, s19_app/tui/app.py:10067, s19_app/tui/app.py:10101, s19_app/tui/app.py:10283, s19_app/tui/app.py:10351, s19_app/tui/app.py:10375, s19_app/tui/app.py:10388, s19_app/tui/app.py:10413, s19_app/tui/app.py:10427, s19_app/tui/app.py:9935, s19_app/tui/app.py:9960 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp._copy_project_subfolders` | s19_app/tui/app.py:10090, s19_app/tui/app.py:9954 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp._decide_project_image` | s19_app/tui/app.py:9717 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp._derived_record` | s19_app/tui/app.py:9790 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp._manifest_carry` | s19_app/tui/app.py:9743 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp._manifest_is_link` | s19_app/tui/app.py:9734 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp._plan_project_save` | s19_app/tui/app.py:9794 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp._project_folder_refusal` | s19_app/tui/app.py:9658, s19_app/tui/app.py:9705 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp._save_as_source_for` | s19_app/tui/app.py:9693 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp._unrecorded_document_lines` | s19_app/tui/app.py:10217 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp._variant_display_options` | s19_app/tui/app.py:17634 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp._write_and_verify_manifest` | s19_app/tui/app.py:10334 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp._write_editor_document` | s19_app/tui/app.py:9992 |
| `S19TuiApp._handle_save_dialog` | `_plan_row_mismatch` | s19_app/tui/app.py:10063 |
| `S19TuiApp._handle_save_dialog` | `_plan_without_document_key` | s19_app/tui/app.py:10236 |
| `S19TuiApp._handle_save_dialog` | `_save_clears_panel_flag` | s19_app/tui/app.py:10580 |
| `S19TuiApp._handle_save_dialog` | `classify_active_document` | s19_app/tui/app.py:9908, s19_app/tui/services/project_gather_service.py:675 |
| `S19TuiApp._handle_save_dialog` | `is_windows_device_name` | s19_app/tui/app.py:10503, s19_app/tui/app.py:9519, s19_app/tui/services/variant_execution_service.py:548 |
| `S19TuiApp._handle_save_dialog` | `painted_names` | s19_app/tui/app.py:10479, s19_app/tui/app.py:10491, s19_app/tui/app.py:10493, s19_app/tui/app.py:10510, s19_app/tui/app.py:7326, s19_app/tui/app.py:9671 |
| `S19TuiApp._handle_save_dialog` | `resolve_input_path` | s19_app/tui/app.py:9466 |
| `S19TuiApp._handle_save_dialog` | `sanitize_project_name` | s19_app/tui/app.py:9498 |
| `S19TuiApp._plan_project_save` | `S19TuiApp._document_home_contained` | s19_app/tui/app.py:10885, s19_app/tui/app.py:10902 |
| `S19TuiApp._plan_project_save` | `S19TuiApp._save_as_source_for` | s19_app/tui/app.py:10825 |
| `S19TuiApp._plan_project_save` | `_file_digest` | s19_app/tui/app.py:10863, s19_app/tui/app.py:10870, s19_app/tui/app.py:10877, s19_app/tui/app.py:10906, s19_app/tui/app.py:10950 |
| `S19TuiApp._plan_project_save` | `_save_manifest_keys` | s19_app/tui/app.py:10960 |
| `S19TuiApp._plan_project_save` | `classify_active_document` | s19_app/tui/app.py:10896 |
| `S19TuiApp._plan_project_save` | `inventory_project_tree` | s19_app/tui/app.py:10840 |
| `S19TuiApp._plan_project_save` | `is_windows_device_name` | s19_app/tui/services/variant_execution_service.py:548 |
| `S19TuiApp._plan_project_save` | `painted_names` | s19_app/tui/app.py:10836 |
| `S19TuiApp._plan_project_save` | `plan_project_save` | s19_app/tui/app.py:10955 |
| `S19TuiApp._write_and_verify_manifest` | `is_windows_device_name` | s19_app/tui/services/variant_execution_service.py:548 |
| `S19TuiApp.action_save_project` | `S19TuiApp._assignment_candidate_files` | s19_app/tui/app.py:7403 |
| `S19TuiApp.action_save_project` | `S19TuiApp._variant_display_options` | s19_app/tui/app.py:7402 |
| `S19TuiApp.action_save_project` | `SaveProjectScreen.__init__` | s19_app/tui/app.py:7405 |
| `S19TuiApp.list_projects` | `S19TuiApp._project_folder_refusal` | s19_app/tui/app.py:12145 |
| `SaveProjectScreen.on_button_pressed` | `SaveProjectScreen._collect_composition` | s19_app/tui/screens.py:691 |
| `_save_manifest_keys` | `is_windows_device_name` | s19_app/tui/services/variant_execution_service.py:548 |
| `classify_active_document` | `is_windows_device_name` | s19_app/tui/services/variant_execution_service.py:548 |
| `plan_project_save` | `_plan_copies` | s19_app/tui/services/project_gather_service.py:1619 |
| `plan_project_save` | `classify_active_document` | s19_app/tui/services/project_gather_service.py:1666 |
| `plan_project_save` | `painted_names` | s19_app/tui/services/project_gather_service.py:1390, s19_app/tui/services/project_gather_service.py:1392, s19_app/tui/services/project_gather_service.py:1416, s19_app/tui/services/project_gather_service.py:1438, s19_app/tui/services/project_gather_service.py:1623, s19_app/tui/services/project_gather_service.py:1644, s19_app/tui/services/project_gather_service.py:1651 |
| `plan_project_save` | `predict_placement` | s19_app/tui/services/project_gather_service.py:1684 |

Top-level sites (no marked node above them):

- `S19TuiApp._derived_record`: s19_app/tui/app.py:4205
- `S19TuiApp._manifest_carry`: s19_app/tui/app.py:12512
- `S19TuiApp._project_folder_refusal`: s19_app/tui/app.py:11701
- `S19TuiApp._variant_display_options`: s19_app/tui/app.py:7546
- `S19TuiApp._write_and_verify_manifest`: s19_app/tui/app.py:12518
- `S19TuiApp.check_action`: s19_app/tui/window_help.py:1134, s19_app/tui/window_help.py:1145
- `S19TuiApp.list_projects`: s19_app/tui/app.py:11731, s19_app/tui/app.py:12895, s19_app/tui/app.py:7448
- `is_windows_device_name`: s19_app/tui/workspace.py:2241
- `painted_names`: s19_app/tui/app.py:11703, s19_app/tui/app.py:11735, s19_app/tui/app.py:11752, s19_app/tui/app.py:11792, s19_app/tui/app.py:11793, s19_app/tui/app.py:11822, s19_app/tui/app.py:11827, s19_app/tui/app.py:12968
- `resolve_input_path`: s19_app/tui/app.py:12822, s19_app/tui/app.py:12834, s19_app/tui/app.py:13057, s19_app/tui/app.py:13113, s19_app/tui/app.py:5390, s19_app/tui/app.py:6584, s19_app/tui/app.py:6585, s19_app/tui/changes/io.py:419, s19_app/tui/crc_designer_view.py:1307, s19_app/tui/operations/crc_config.py:361, s19_app/tui/operations/crc_designer_model.py:920, s19_app/tui/services/compare_service.py:528 (ref), s19_app/tui/services/report_filter.py:360
- `sanitize_project_name`: s19_app/tui/crc_designer_view.py:1227, s19_app/tui/screens.py:798, s19_app/tui/services/flow_persistence_service.py:1019, s19_app/tui/services/flow_persistence_service.py:1495
