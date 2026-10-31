# Code-Wire extractor report

- Marks found: 25
- Graph nodes parsed: 25
- Real calls between marked nodes: 30
- Findings: 0 (0 drift, 0 info)
- Ambiguous call resolutions (a name matched several defs): 30
- Files that failed to parse: 0

Type normalisation: spaces and quotes dropped; `List/Dict/Tuple/Set` -> builtins; `X | None` and graph `X?` -> `Optional[X]`; graph `(Callable) A->B` -> `Callable[[A], B]`; graph `tuple(A a, B b)` -> `tuple[A, B]`. A bare graph container (`dict`) against a parameterised code type (`dict[str, Any]`) is info (loose match), not drift.

Call resolution is name-based (`f()`, `Class()` -> `__init__`, `self.m()`, `x.m()` -> top-level `m` or a marked method `m`); dynamic calls and callables passed as values are not seen. Tests excluded.

## Counts

| Kind | Count |
|---|---|

## Real calls between marked nodes

| Caller | Callee | Sites |
|---|---|---|
| `S19TuiApp._handle_load_project` | `PatchEditorPanel.mark_saved` | s19_app/tui/app.py:13474 |
| `S19TuiApp._handle_load_project` | `S19TuiApp._reset_project_session` | s19_app/tui/app.py:10511 |
| `S19TuiApp._handle_load_project` | `check_project_files` | s19_app/tui/app.py:10527 |
| `S19TuiApp._handle_load_project` | `read_project_manifest` | s19_app/tui/app.py:10518 |
| `S19TuiApp._handle_save_dialog` | `PatchEditorPanel.mark_saved` | s19_app/tui/app.py:9736 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp._manifest_carry` | s19_app/tui/app.py:9278 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp._plan_project_save` | s19_app/tui/app.py:9287 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp._write_and_verify_manifest` | s19_app/tui/app.py:9614 |
| `S19TuiApp._handle_save_dialog` | `gather_project_artifacts` | s19_app/tui/app.py:9542 |
| `S19TuiApp._handle_save_dialog` | `manifest_keep_reason` | s19_app/tui/app.py:9578 |
| `S19TuiApp._handle_save_dialog` | `read_project_manifest` | s19_app/tui/app.py:9276 |
| `S19TuiApp._patch_editor_load` | `ChangeService.load` | s19_app/tui/app.py:5850 |
| `S19TuiApp._plan_project_save` | `_save_manifest_keys` | s19_app/tui/app.py:9966 |
| `S19TuiApp._plan_project_save` | `plan_project_save` | s19_app/tui/app.py:9961 |
| `S19TuiApp._rewrite_project_manifest` | `S19TuiApp._manifest_carry` | s19_app/tui/app.py:10814 |
| `S19TuiApp._rewrite_project_manifest` | `S19TuiApp._write_and_verify_manifest` | s19_app/tui/app.py:10820 |
| `S19TuiApp._rewrite_project_manifest` | `manifest_rewrite_refusal` | s19_app/tui/app.py:10800 |
| `S19TuiApp._rewrite_project_manifest` | `read_project_manifest` | s19_app/tui/app.py:10799 |
| `S19TuiApp._sync_loaded_a2l_to_project` | `S19TuiApp._rewrite_project_manifest` | s19_app/tui/app.py:11081 |
| `S19TuiApp._sync_loaded_file_to_project` | `S19TuiApp._rewrite_project_manifest` | s19_app/tui/app.py:11006, s19_app/tui/app.py:11050 |
| `S19TuiApp._write_and_verify_manifest` | `project_file_records` | s19_app/tui/app.py:10079 |
| `S19TuiApp._write_and_verify_manifest` | `verify_written_manifest` | s19_app/tui/app.py:10116 |
| `S19TuiApp._write_and_verify_manifest` | `write_project_manifest` | s19_app/tui/app.py:10080 |
| `S19TuiApp.on_patch_editor_panel_save_back_decision` | `PatchEditorPanel.mark_saved` | s19_app/tui/app.py:3862 |
| `S19TuiApp.on_patch_editor_panel_save_back_decision` | `S19TuiApp._rewrite_project_manifest` | s19_app/tui/app.py:3872 |
| `_save_manifest_keys` | `serialize_manifest` | s19_app/tui/app.py:1493 |
| `gather_project_artifacts` | `ChangeService.load` | s19_app/tui/services/project_gather_service.py:201 |
| `manifest_rewrite_refusal` | `manifest_keep_reason` | s19_app/tui/services/variant_execution_service.py:1863 |
| `verify_written_manifest` | `read_project_manifest` | s19_app/tui/services/manifest_writer.py:802 |
| `write_project_manifest` | `serialize_manifest` | s19_app/tui/services/manifest_writer.py:569 |

Top-level sites (no marked node above them):

- `ChangeService.load`: prototypes/fb_p1_flow_persistence.prototype.py:352, s19_app/tui/services/flow_persistence_service.py:1543, s19_app/tui/services/flow_persistence_service.py:967
- `PatchEditorPanel.mark_saved`: s19_app/tui/app.py:3076, s19_app/tui/app.py:3399, s19_app/tui/app.py:3710
- `S19TuiApp._handle_load_project`: s19_app/tui/app.py:7151
- `S19TuiApp._patch_editor_load`: s19_app/tui/app.py:3647, s19_app/tui/app.py:5832, s19_app/tui/app.py:5934
- `S19TuiApp._sync_loaded_a2l_to_project`: s19_app/tui/app.py:11304
- `read_project_manifest`: s19_app/tui/app.py:4753, s19_app/tui/app.py:5227, s19_app/tui/app.py:5335, s19_app/tui/services/variant_execution_service.py:2456
- `write_change_document`: s19_app/tui/app.py:6053, s19_app/tui/services/change_service.py:1773
