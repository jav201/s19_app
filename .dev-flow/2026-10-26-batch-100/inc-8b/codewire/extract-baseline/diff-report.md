# Code-Wire extractor report

- Marks found: 23
- Graph nodes parsed: 23
- Real calls between marked nodes: 49
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
| `S19TuiApp._abort_save` | `_is_reparse_point` | s19_app/tui/workspace.py:342, s19_app/tui/workspace.py:350, s19_app/tui/workspace.py:466, s19_app/tui/workspace.py:543, s19_app/tui/workspace.py:548, s19_app/tui/workspace.py:573, s19_app/tui/workspace.py:728 |
| `S19TuiApp._abort_save` | `contained_in_workarea` | s19_app/tui/workspace.py:746 |
| `S19TuiApp._handle_load_project` | `S19TuiApp._active_project_dir` | s19_app/tui/app.py:2619 |
| `S19TuiApp._handle_load_project` | `S19TuiApp._load_a2l_data_with_cache` | s19_app/tui/app.py:11343, s19_app/tui/app.py:13243, s19_app/tui/app.py:14172, s19_app/tui/app.py:14191 |
| `S19TuiApp._handle_load_project` | `S19TuiApp._reset_project_session` | s19_app/tui/app.py:11308 |
| `S19TuiApp._handle_load_project` | `_is_reparse_point` | s19_app/tui/services/manifest_writer.py:1160, s19_app/tui/services/manifest_writer.py:981, s19_app/tui/workspace.py:342, s19_app/tui/workspace.py:350 |
| `S19TuiApp._handle_load_project` | `build_variant_set` | s19_app/tui/app.py:11314 |
| `S19TuiApp._handle_load_project` | `choose_install_set` | s19_app/tui/app.py:11354, s19_app/tui/app.py:11387 |
| `S19TuiApp._handle_load_project` | `validate_project_files` | s19_app/tui/app.py:11294 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp._abort_save` | s19_app/tui/app.py:10064, s19_app/tui/app.py:10120, s19_app/tui/app.py:10144, s19_app/tui/app.py:10157, s19_app/tui/app.py:10182, s19_app/tui/app.py:10196, s19_app/tui/app.py:9752, s19_app/tui/app.py:9772, s19_app/tui/app.py:9784, s19_app/tui/app.py:9863, s19_app/tui/app.py:9889 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp._plan_project_save` | s19_app/tui/app.py:9648 |
| `S19TuiApp._handle_save_dialog` | `_is_reparse_point` | s19_app/tui/app.py:9497, s19_app/tui/app.py:9569, s19_app/tui/services/manifest_writer.py:981, s19_app/tui/workspace.py:342, s19_app/tui/workspace.py:350, s19_app/tui/workspace.py:466, s19_app/tui/workspace.py:543, s19_app/tui/workspace.py:548, s19_app/tui/workspace.py:573, s19_app/tui/workspace.py:728 |
| `S19TuiApp._handle_save_dialog` | `_plan_row_mismatch` | s19_app/tui/app.py:9885 |
| `S19TuiApp._handle_save_dialog` | `build_variant_set` | s19_app/tui/app.py:9916 |
| `S19TuiApp._handle_save_dialog` | `contained_in_workarea` | s19_app/tui/workspace.py:746 |
| `S19TuiApp._handle_save_dialog` | `place_into_workarea` | s19_app/tui/app.py:10723, s19_app/tui/app.py:9879, s19_app/tui/services/project_gather_service.py:453, s19_app/tui/workspace.py:1451 |
| `S19TuiApp._handle_save_dialog` | `validate_project_files` | s19_app/tui/app.py:9748, s19_app/tui/app.py:9914 |
| `S19TuiApp._handle_save_dialog` | `write_project_manifest` | s19_app/tui/app.py:10872 |
| `S19TuiApp._plan_project_save` | `_is_reparse_point` | s19_app/tui/workspace.py:342, s19_app/tui/workspace.py:350, s19_app/tui/workspace.py:466, s19_app/tui/workspace.py:728 |
| `S19TuiApp._plan_project_save` | `contained_in_workarea` | s19_app/tui/workspace.py:746 |
| `S19TuiApp._plan_project_save` | `plan_project_save` | s19_app/tui/app.py:10552 |
| `S19TuiApp._route_load_project` | `S19TuiApp._handle_load_project` | s19_app/tui/app.py:7447 |
| `S19TuiApp._sync_loaded_a2l_to_project` | `S19TuiApp._active_project_dir` | s19_app/tui/app.py:11963 |
| `S19TuiApp._sync_loaded_a2l_to_project` | `_is_reparse_point` | s19_app/tui/services/manifest_writer.py:981, s19_app/tui/workspace.py:342, s19_app/tui/workspace.py:350 |
| `S19TuiApp._sync_loaded_a2l_to_project` | `place_into_workarea` | s19_app/tui/app.py:11975 |
| `S19TuiApp._sync_loaded_a2l_to_project` | `validate_project_files` | s19_app/tui/app.py:11967 |
| `S19TuiApp._sync_loaded_a2l_to_project` | `write_project_manifest` | s19_app/tui/app.py:10872 |
| `S19TuiApp._sync_loaded_file_to_project` | `S19TuiApp._active_project_dir` | s19_app/tui/app.py:11854 |
| `S19TuiApp._sync_loaded_file_to_project` | `_is_reparse_point` | s19_app/tui/services/manifest_writer.py:981, s19_app/tui/workspace.py:342, s19_app/tui/workspace.py:350 |
| `S19TuiApp._sync_loaded_file_to_project` | `build_variant_set` | s19_app/tui/app.py:11799 |
| `S19TuiApp._sync_loaded_file_to_project` | `place_into_workarea` | s19_app/tui/app.py:11890, s19_app/tui/app.py:11929, s19_app/tui/app.py:11940 |
| `S19TuiApp._sync_loaded_file_to_project` | `validate_project_files` | s19_app/tui/app.py:11792, s19_app/tui/app.py:11858 |
| `S19TuiApp._sync_loaded_file_to_project` | `write_project_manifest` | s19_app/tui/app.py:10872 |
| `S19TuiApp.action_load_project` | `S19TuiApp.list_projects` | s19_app/tui/app.py:7409 |
| `S19TuiApp.load_a2l_from_path` | `S19TuiApp._active_project_dir` | s19_app/tui/app.py:12128 |
| `S19TuiApp.load_a2l_from_path` | `S19TuiApp._load_a2l_data_with_cache` | s19_app/tui/app.py:12171 |
| `S19TuiApp.load_a2l_from_path` | `S19TuiApp._sync_loaded_a2l_to_project` | s19_app/tui/app.py:12203 |
| `S19TuiApp.load_a2l_from_path` | `place_into_workarea` | s19_app/tui/workspace.py:1451 |
| `S19TuiApp.load_a2l_from_path` | `validate_project_files` | s19_app/tui/app.py:12130 |
| `S19TuiApp.on_patch_editor_panel_save_back_decision` | `S19TuiApp._active_project_dir` | s19_app/tui/app.py:4129, s19_app/tui/app.py:4161 |
| `S19TuiApp.on_patch_editor_panel_save_back_decision` | `_is_reparse_point` | s19_app/tui/services/manifest_writer.py:981, s19_app/tui/workspace.py:342, s19_app/tui/workspace.py:350 |
| `S19TuiApp.on_patch_editor_panel_save_back_decision` | `build_variant_set` | s19_app/tui/app.py:11799 |
| `S19TuiApp.on_patch_editor_panel_save_back_decision` | `validate_project_files` | s19_app/tui/app.py:11792 |
| `S19TuiApp.on_patch_editor_panel_save_back_decision` | `write_project_manifest` | s19_app/tui/app.py:10872 |
| `place_into_workarea` | `_is_reparse_point` | s19_app/tui/workspace.py:1125, s19_app/tui/workspace.py:1131, s19_app/tui/workspace.py:1259, s19_app/tui/workspace.py:342, s19_app/tui/workspace.py:350, s19_app/tui/workspace.py:466, s19_app/tui/workspace.py:543, s19_app/tui/workspace.py:548, s19_app/tui/workspace.py:573, s19_app/tui/workspace.py:728, s19_app/tui/workspace.py:905 |
| `place_into_workarea` | `contained_in_workarea` | s19_app/tui/workspace.py:746 |
| `plan_project_save` | `_is_reparse_point` | s19_app/tui/workspace.py:342, s19_app/tui/workspace.py:350, s19_app/tui/workspace.py:905 |
| `write_project_manifest` | `_is_reparse_point` | s19_app/tui/workspace.py:342, s19_app/tui/workspace.py:350, s19_app/tui/workspace.py:466, s19_app/tui/workspace.py:543, s19_app/tui/workspace.py:548, s19_app/tui/workspace.py:573, s19_app/tui/workspace.py:728 |
| `write_project_manifest` | `contained_in_workarea` | s19_app/tui/workspace.py:746 |

Top-level sites (no marked node above them):

- `S19TuiApp._active_project_dir`: s19_app/tui/app.py:3311, s19_app/tui/app.py:3357, s19_app/tui/app.py:3397, s19_app/tui/app.py:3431, s19_app/tui/app.py:3462, s19_app/tui/app.py:3519, s19_app/tui/app.py:3590, s19_app/tui/app.py:3669, s19_app/tui/app.py:3722, s19_app/tui/app.py:4847, s19_app/tui/app.py:5041, s19_app/tui/app.py:5234, s19_app/tui/app.py:5484, s19_app/tui/app.py:5917, s19_app/tui/app.py:5995, s19_app/tui/app.py:6838
- `S19TuiApp.action_load_project`: s19_app/tui/app.py:16657
- `S19TuiApp.load_a2l_from_path`: s19_app/tui/app.py:11993, s19_app/tui/app.py:12359
- `_is_reparse_point`: s19_app/tui/segment_split_view.py:857, s19_app/tui/workspace.py:1570, s19_app/tui/workspace.py:1576, s19_app/tui/workspace.py:1636, s19_app/tui/workspace.py:1731, s19_app/tui/workspace.py:308
- `place_into_workarea`: s19_app/tui/changes/apply.py:856, s19_app/tui/segment_split_view.py:953
- `validate_project_files`: s19_app/tui/services/variant_execution_service.py:2738
