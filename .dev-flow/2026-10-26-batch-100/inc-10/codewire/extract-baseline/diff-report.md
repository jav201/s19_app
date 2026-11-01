# Code-Wire extractor report

- Marks found: 35
- Graph nodes parsed: 35
- Real calls between marked nodes: 29
- Findings: 0 (0 drift, 0 info)
- Ambiguous call resolutions (a name matched several defs): 7
- Files that failed to parse: 0

Type normalisation: spaces and quotes dropped; `List/Dict/Tuple/Set` -> builtins; `X | None` and graph `X?` -> `Optional[X]`; graph `(Callable) A->B` -> `Callable[[A], B]`; graph `tuple(A a, B b)` -> `tuple[A, B]`. A bare graph container (`dict`) against a parameterised code type (`dict[str, Any]`) is info (loose match), not drift.

Call resolution is name-based (`f()`, `Class()` -> `__init__`, `self.m()`, `x.m()` -> top-level `m` or a marked method `m`); dynamic calls and callables passed as values are not seen. Tests excluded.

## Counts

| Kind | Count |
|---|---|

## Real calls between marked nodes

| Caller | Callee | Sites |
|---|---|---|
| `PatchEditorPanel.on_button_pressed` | `PatchEditorPanel.request_action` | s19_app/tui/screens_directionb.py:5800, s19_app/tui/screens_directionb.py:5816 |
| `S19TuiApp._handle_load_project` | `ChangeService.mark_saved` | s19_app/tui/app.py:15372 |
| `S19TuiApp._handle_load_project` | `PatchEditorPanel.mark_loaded` | s19_app/tui/app.py:12052 |
| `S19TuiApp._handle_load_project` | `PatchEditorPanel.mark_saved` | s19_app/tui/app.py:15372 |
| `S19TuiApp._handle_load_project` | `S19TuiApp._reset_project_session` | s19_app/tui/app.py:11833 |
| `S19TuiApp._handle_load_project` | `S19TuiApp.load_selected_file` | s19_app/tui/app.py:11932 |
| `S19TuiApp._handle_load_project` | `painted_names` | s19_app/tui/app.py:11698, s19_app/tui/app.py:11730, s19_app/tui/app.py:11747, s19_app/tui/app.py:11787, s19_app/tui/app.py:11788, s19_app/tui/app.py:11817, s19_app/tui/app.py:11822 |
| `S19TuiApp._handle_load_result` | `S19TuiApp.action_select_variant` | s19_app/tui/app.py:7512 |
| `S19TuiApp._handle_save_dialog` | `ChangeService.mark_saved` | s19_app/tui/app.py:10456, s19_app/tui/app.py:10582 |
| `S19TuiApp._handle_save_dialog` | `PatchEditorPanel.mark_saved` | s19_app/tui/app.py:10456, s19_app/tui/app.py:10582 |
| `S19TuiApp._handle_save_dialog` | `painted_names` | s19_app/tui/app.py:10478, s19_app/tui/app.py:10490, s19_app/tui/app.py:10492, s19_app/tui/app.py:10509, s19_app/tui/app.py:10833, s19_app/tui/app.py:12289, s19_app/tui/app.py:12345, s19_app/tui/app.py:12346, s19_app/tui/app.py:12348, s19_app/tui/app.py:12356, s19_app/tui/app.py:12357, s19_app/tui/app.py:7323, s19_app/tui/app.py:9275, s19_app/tui/app.py:9670, s19_app/tui/services/project_gather_service.py:1388, s19_app/tui/services/project_gather_service.py:1390, s19_app/tui/services/project_gather_service.py:1414, s19_app/tui/services/project_gather_service.py:1436, s19_app/tui/services/project_gather_service.py:1619, s19_app/tui/services/project_gather_service.py:1640, s19_app/tui/services/project_gather_service.py:1647 |
| `S19TuiApp._handle_select_variant` | `S19TuiApp.load_from_path` | s19_app/tui/app.py:7618 |
| `S19TuiApp._load_from_item` | `S19TuiApp.load_a2l_from_path` | s19_app/tui/app.py:13352 |
| `S19TuiApp._load_from_item` | `S19TuiApp.load_selected_file` | s19_app/tui/app.py:13354 |
| `S19TuiApp._load_path_from_user_input` | `S19TuiApp._route_load_project` | s19_app/tui/app.py:12950 |
| `S19TuiApp._load_path_from_user_input` | `S19TuiApp._typed_load_route` | s19_app/tui/app.py:12948 |
| `S19TuiApp._load_path_from_user_input` | `S19TuiApp.load_a2l_from_path` | s19_app/tui/app.py:12953 |
| `S19TuiApp._load_path_from_user_input` | `S19TuiApp.load_from_path` | s19_app/tui/app.py:12956 |
| `S19TuiApp._load_path_from_user_input` | `painted_names` | s19_app/tui/app.py:12958 |
| `S19TuiApp._reset_project_session` | `PatchEditorPanel.mark_loaded` | s19_app/tui/app.py:11546 |
| `S19TuiApp._route_load_project` | `S19TuiApp._handle_load_project` | s19_app/tui/app.py:7482 |
| `S19TuiApp.load_a2l_from_path` | `S19TuiApp._rehome_focus_after_load` | s19_app/tui/app.py:13190 |
| `S19TuiApp.load_a2l_from_path` | `painted_names` | s19_app/tui/app.py:7323 |
| `S19TuiApp.load_selected_file` | `ChangeService.mark_saved` | s19_app/tui/app.py:15372 |
| `S19TuiApp.load_selected_file` | `PatchEditorPanel.mark_saved` | s19_app/tui/app.py:15372 |
| `S19TuiApp.load_selected_file` | `S19TuiApp._rehome_focus_after_load` | s19_app/tui/app.py:15541 |
| `S19TuiApp.on_list_view_selected` | `S19TuiApp._load_from_item` | s19_app/tui/app.py:13201 |
| `S19TuiApp.on_mount` | `S19TuiApp._load_path_from_user_input` | s19_app/tui/app.py:7230 |
| `S19TuiApp.on_mount` | `painted_names` | s19_app/tui/app.py:7323 |

Top-level sites (no marked node above them):

- `ChangeService.mark_saved`: s19_app/tui/app.py:3401, s19_app/tui/app.py:3724, s19_app/tui/app.py:4036, s19_app/tui/app.py:4187
- `ConfirmDiscardScreen.__init__`: s19_app/tui/app.py:3449
- `PatchEditorPanel.mark_loaded`: s19_app/tui/app.py:6177
- `PatchEditorPanel.mark_pasted`: s19_app/tui/app.py:3982
- `PatchEditorPanel.mark_saved`: s19_app/tui/app.py:3401, s19_app/tui/app.py:3724, s19_app/tui/app.py:4036, s19_app/tui/app.py:4187
- `S19TuiApp.check_action`: s19_app/tui/window_help.py:1134, s19_app/tui/window_help.py:1145
