# Code-Wire extractor report

- Marks found: 48
- Graph nodes parsed: 48
- Real calls between marked nodes: 42
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
| `S19TuiApp._handle_load_project` | `S19TuiApp._install_project_image` | s19_app/tui/app.py:11929 |
| `S19TuiApp._handle_load_project` | `S19TuiApp._load_a2l_data_with_cache` | s19_app/tui/app.py:11884 |
| `S19TuiApp._handle_load_project` | `S19TuiApp._reopen_active_document` | s19_app/tui/app.py:11912 |
| `S19TuiApp._handle_load_project` | `S19TuiApp._reset_project_session` | s19_app/tui/app.py:11847 |
| `S19TuiApp._handle_load_project` | `S19TuiApp.load_selected_file` | s19_app/tui/app.py:11946 |
| `S19TuiApp._handle_load_project` | `S19TuiApp.update_a2l_view` | s19_app/tui/app.py:11905 |
| `S19TuiApp._handle_load_project` | `choose_install_set` | s19_app/tui/app.py:11895, s19_app/tui/app.py:11936 |
| `S19TuiApp._handle_save_dialog` | `ChangeService.adopt_rederived` | s19_app/tui/app.py:10456 |
| `S19TuiApp._handle_save_dialog` | `ChangeService.emit_and_verify` | s19_app/tui/app.py:10027 |
| `S19TuiApp._handle_save_dialog` | `ChangeService.record_save_entries` | s19_app/tui/app.py:10026 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp._abort_save` | s19_app/tui/app.py:10050, s19_app/tui/app.py:10076, s19_app/tui/app.py:10110, s19_app/tui/app.py:10292, s19_app/tui/app.py:10360, s19_app/tui/app.py:10384, s19_app/tui/app.py:10397, s19_app/tui/app.py:10422, s19_app/tui/app.py:10436, s19_app/tui/app.py:9944, s19_app/tui/app.py:9969 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp._copy_project_subfolders` | s19_app/tui/app.py:10099, s19_app/tui/app.py:9963 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp._decide_project_image` | s19_app/tui/app.py:9726 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp._write_and_verify_manifest` | s19_app/tui/app.py:10343 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp._write_editor_document` | s19_app/tui/app.py:10001 |
| `S19TuiApp._handle_save_dialog` | `recorded_document_state` | s19_app/tui/app.py:9770 |
| `S19TuiApp._install_project_image` | `S19TuiApp._parse_loaded_file` | s19_app/tui/app.py:12106 |
| `S19TuiApp._install_project_image` | `S19TuiApp.update_a2l_view` | s19_app/tui/app.py:15544 |
| `S19TuiApp._load_a2l_data_with_cache` | `parse_a2l_file` | s19_app/tui/app.py:15892 |
| `S19TuiApp._load_from_item` | `S19TuiApp.load_a2l_from_path` | s19_app/tui/app.py:13366 |
| `S19TuiApp._load_from_item` | `S19TuiApp.load_selected_file` | s19_app/tui/app.py:13368 |
| `S19TuiApp._load_mac_file` | `S19TuiApp._load_a2l_data_with_cache` | s19_app/tui/app.py:14251 |
| `S19TuiApp._parse_loaded_file` | `S19TuiApp._load_a2l_data_with_cache` | s19_app/tui/app.py:15190, s19_app/tui/app.py:15209 |
| `S19TuiApp._parse_loaded_file` | `S19TuiApp._load_mac_file` | s19_app/tui/app.py:15226 |
| `S19TuiApp._parse_loaded_file` | `S19TuiApp._merge_mac_with_existing_primary` | s19_app/tui/app.py:15236 |
| `S19TuiApp._reopen_active_document` | `recorded_document_state` | s19_app/tui/app.py:12044 |
| `S19TuiApp._rewrite_project_manifest` | `S19TuiApp._write_and_verify_manifest` | s19_app/tui/app.py:12525 |
| `S19TuiApp._route_load_project` | `S19TuiApp._handle_load_project` | s19_app/tui/app.py:7494 |
| `S19TuiApp._start_load_worker` | `S19TuiApp._parse_loaded_file` | s19_app/tui/app.py:15783 |
| `S19TuiApp.action_unload_all` | `S19TuiApp.update_a2l_view` | s19_app/tui/app.py:14613 |
| `S19TuiApp.load_a2l_from_path` | `S19TuiApp._load_a2l_data_with_cache` | s19_app/tui/app.py:13177 |
| `S19TuiApp.load_a2l_from_path` | `S19TuiApp._rewrite_project_manifest` | s19_app/tui/app.py:12784 |
| `S19TuiApp.load_a2l_from_path` | `S19TuiApp.update_a2l_view` | s19_app/tui/app.py:13184 |
| `S19TuiApp.load_from_path` | `S19TuiApp._start_load_worker` | s19_app/tui/app.py:13102 |
| `S19TuiApp.load_selected_file` | `S19TuiApp._parse_loaded_file` | s19_app/tui/app.py:15118 |
| `S19TuiApp.load_selected_file` | `S19TuiApp.update_a2l_view` | s19_app/tui/app.py:15544 |
| `S19TuiApp.on_loaded_artifacts_panel_unload_requested` | `S19TuiApp.update_a2l_view` | s19_app/tui/app.py:14613 |
| `S19TuiApp.on_patch_editor_panel_action_requested` | `parse_a2l_file` | s19_app/tui/services/variant_execution_service.py:2662 |
| `S19TuiApp.on_patch_editor_panel_redo_requested` | `S19TuiApp.action_patch_redo` | s19_app/tui/app.py:4387 |
| `S19TuiApp.on_patch_editor_panel_save_back_decision` | `S19TuiApp._rewrite_project_manifest` | s19_app/tui/app.py:4201 |
| `S19TuiApp.on_patch_editor_panel_undo_requested` | `S19TuiApp.action_patch_undo` | s19_app/tui/app.py:4361 |
| `parse_a2l_file` | `build_section_tree` | s19_app/tui/a2l.py:2659 |

Top-level sites (no marked node above them):

- `ChangeService.adopt_rederived`: s19_app/tui/services/change_service.py:2594
- `ChangeService.emit_and_verify`: s19_app/tui/services/change_service.py:2629
- `ChangeService.record_save_entries`: s19_app/tui/services/change_service.py:2586
- `S19TuiApp._load_from_item`: s19_app/tui/app.py:13215
- `S19TuiApp._rewrite_project_manifest`: s19_app/tui/app.py:12710, s19_app/tui/app.py:12754
- `S19TuiApp._route_load_project`: s19_app/tui/app.py:12966
- `S19TuiApp.action_load_project`: s19_app/tui/app.py:17678
- `S19TuiApp.action_select_variant`: s19_app/tui/app.py:7523
- `S19TuiApp.check_action`: s19_app/tui/window_help.py:1134, s19_app/tui/window_help.py:1145
- `S19TuiApp.load_a2l_from_path`: s19_app/tui/app.py:12969
- `S19TuiApp.load_from_path`: s19_app/tui/app.py:12972, s19_app/tui/app.py:7628
- `parse_a2l_file`: s19_app/tui/services/change_service.py:3228, s19_app/tui/services/flow_execution_service.py:358, s19_app/tui/services/flow_execution_service.py:461
