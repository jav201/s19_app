# Code-Wire extractor report

- Marks found: 31
- Graph nodes parsed: 31
- Real calls between marked nodes: 51
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
| `S19TuiApp._apply_prepared_load` | `S19TuiApp.set_file_status` | s19_app/tui/app.py:15487 |
| `S19TuiApp._finish_generate_report` | `S19TuiApp.set_progress` | s19_app/tui/app.py:5801 |
| `S19TuiApp._finish_generate_report` | `S19TuiApp.set_status` | s19_app/tui/app.py:5802 |
| `S19TuiApp._handle_load_error` | `S19TuiApp.set_progress` | s19_app/tui/app.py:15839 |
| `S19TuiApp._handle_load_error` | `S19TuiApp.set_status` | s19_app/tui/app.py:15838 |
| `S19TuiApp._handle_load_project` | `S19TuiApp._apply_prepared_load` | s19_app/tui/app.py:15275 |
| `S19TuiApp._handle_load_project` | `S19TuiApp.list_projects` | s19_app/tui/app.py:11728 |
| `S19TuiApp._handle_load_project` | `S19TuiApp.load_selected_file` | s19_app/tui/app.py:11934 |
| `S19TuiApp._handle_load_project` | `S19TuiApp.set_file_status` | s19_app/tui/app.py:11956 |
| `S19TuiApp._handle_load_project` | `S19TuiApp.set_status` | s19_app/tui/app.py:11716, s19_app/tui/app.py:11720, s19_app/tui/app.py:11730, s19_app/tui/app.py:11747, s19_app/tui/app.py:11759, s19_app/tui/app.py:11787, s19_app/tui/app.py:11827, s19_app/tui/app.py:11885, s19_app/tui/app.py:11955, s19_app/tui/app.py:11964 |
| `S19TuiApp._handle_load_project` | `painted_names` | s19_app/tui/app.py:11700, s19_app/tui/app.py:11732, s19_app/tui/app.py:11749, s19_app/tui/app.py:11789, s19_app/tui/app.py:11790, s19_app/tui/app.py:11819, s19_app/tui/app.py:11824 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp.refresh_files` | s19_app/tui/app.py:10614 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp.set_status` | s19_app/tui/app.py:10041, s19_app/tui/app.py:10067, s19_app/tui/app.py:10102, s19_app/tui/app.py:10277, s19_app/tui/app.py:10351, s19_app/tui/app.py:10368, s19_app/tui/app.py:10388, s19_app/tui/app.py:10406, s19_app/tui/app.py:10466, s19_app/tui/app.py:10471, s19_app/tui/app.py:10473, s19_app/tui/app.py:10478, s19_app/tui/app.py:10491, s19_app/tui/app.py:10510, s19_app/tui/app.py:10518, s19_app/tui/app.py:10601, s19_app/tui/app.py:10610, s19_app/tui/app.py:11291, s19_app/tui/app.py:11362, s19_app/tui/app.py:11370, s19_app/tui/app.py:4779, s19_app/tui/app.py:4789, s19_app/tui/app.py:9275, s19_app/tui/app.py:9290, s19_app/tui/app.py:9396, s19_app/tui/app.py:9465, s19_app/tui/app.py:9470, s19_app/tui/app.py:9479, s19_app/tui/app.py:9495, s19_app/tui/app.py:9503, s19_app/tui/app.py:9524, s19_app/tui/app.py:9536, s19_app/tui/app.py:9545, s19_app/tui/app.py:9558, s19_app/tui/app.py:9609, s19_app/tui/app.py:9641, s19_app/tui/app.py:9662, s19_app/tui/app.py:9671, s19_app/tui/app.py:9682, s19_app/tui/app.py:9812, s19_app/tui/app.py:9823, s19_app/tui/app.py:9840, s19_app/tui/app.py:9855, s19_app/tui/app.py:9935, s19_app/tui/app.py:9961 |
| `S19TuiApp._handle_save_dialog` | `painted_names` | s19_app/tui/app.py:10481, s19_app/tui/app.py:10493, s19_app/tui/app.py:10495, s19_app/tui/app.py:10512, s19_app/tui/app.py:10836, s19_app/tui/app.py:12292, s19_app/tui/app.py:12348, s19_app/tui/app.py:12349, s19_app/tui/app.py:12351, s19_app/tui/app.py:12359, s19_app/tui/app.py:12360, s19_app/tui/app.py:9278, s19_app/tui/app.py:9673, s19_app/tui/services/project_gather_service.py:1388, s19_app/tui/services/project_gather_service.py:1390, s19_app/tui/services/project_gather_service.py:1414, s19_app/tui/services/project_gather_service.py:1436, s19_app/tui/services/project_gather_service.py:1619, s19_app/tui/services/project_gather_service.py:1640, s19_app/tui/services/project_gather_service.py:1647 |
| `S19TuiApp._load_from_item` | `S19TuiApp.load_a2l_from_path` | s19_app/tui/app.py:13354 |
| `S19TuiApp._load_from_item` | `S19TuiApp.load_selected_file` | s19_app/tui/app.py:13356 |
| `S19TuiApp._load_path_from_user_input` | `S19TuiApp._route_load_project` | s19_app/tui/app.py:12953 |
| `S19TuiApp._load_path_from_user_input` | `S19TuiApp._typed_load_route` | s19_app/tui/app.py:12951 |
| `S19TuiApp._load_path_from_user_input` | `S19TuiApp.load_a2l_from_path` | s19_app/tui/app.py:12956 |
| `S19TuiApp._load_path_from_user_input` | `S19TuiApp.load_from_path` | s19_app/tui/app.py:12959 |
| `S19TuiApp._load_path_from_user_input` | `S19TuiApp.set_status` | s19_app/tui/app.py:12983 |
| `S19TuiApp._load_path_from_user_input` | `painted_names` | s19_app/tui/app.py:12961 |
| `S19TuiApp._route_load_project` | `S19TuiApp._handle_load_project` | s19_app/tui/app.py:7489 |
| `S19TuiApp._trigger_generate_report` | `S19TuiApp._start_generate_report_worker` | s19_app/tui/app.py:5570 |
| `S19TuiApp._trigger_generate_report` | `S19TuiApp.set_progress` | s19_app/tui/app.py:5569 |
| `S19TuiApp._trigger_generate_report` | `S19TuiApp.set_status` | s19_app/tui/app.py:5522, s19_app/tui/app.py:5534, s19_app/tui/app.py:5558, s19_app/tui/app.py:5563, s19_app/tui/app.py:5565 |
| `S19TuiApp._typed_load_route` | `S19TuiApp.list_projects` | s19_app/tui/app.py:12887 |
| `S19TuiApp.action_before_after_report` | `S19TuiApp._start_before_after_worker` | s19_app/tui/app.py:4877 |
| `S19TuiApp.action_before_after_report` | `S19TuiApp.set_progress` | s19_app/tui/app.py:4876 |
| `S19TuiApp.action_before_after_report` | `S19TuiApp.set_status` | s19_app/tui/app.py:4859 |
| `S19TuiApp.compose` | `S19TuiApp._build_palette_entries` | s19_app/tui/app.py:2768 |
| `S19TuiApp.load_a2l_from_path` | `S19TuiApp.refresh_files` | s19_app/tui/app.py:13153 |
| `S19TuiApp.load_a2l_from_path` | `S19TuiApp.set_progress` | s19_app/tui/app.py:13140, s19_app/tui/app.py:13145, s19_app/tui/app.py:13161, s19_app/tui/app.py:13188 |
| `S19TuiApp.load_a2l_from_path` | `S19TuiApp.set_status` | s19_app/tui/app.py:11291, s19_app/tui/app.py:11362, s19_app/tui/app.py:11370, s19_app/tui/app.py:12493, s19_app/tui/app.py:12771, s19_app/tui/app.py:13110, s19_app/tui/app.py:13114, s19_app/tui/app.py:13122, s19_app/tui/app.py:13126, s19_app/tui/app.py:13146, s19_app/tui/app.py:13189 |
| `S19TuiApp.load_a2l_from_path` | `recent_kind` | s19_app/tui/workspace.py:2240, s19_app/tui/workspace.py:2457 |
| `S19TuiApp.load_from_path` | `S19TuiApp._start_load_worker` | s19_app/tui/app.py:13089 |
| `S19TuiApp.load_from_path` | `S19TuiApp.refresh_files` | s19_app/tui/app.py:13093 |
| `S19TuiApp.load_from_path` | `S19TuiApp.set_progress` | s19_app/tui/app.py:13063, s19_app/tui/app.py:13071, s19_app/tui/app.py:13085 |
| `S19TuiApp.load_from_path` | `S19TuiApp.set_status` | s19_app/tui/app.py:13054, s19_app/tui/app.py:13059, s19_app/tui/app.py:13072 |
| `S19TuiApp.load_from_path` | `recent_kind` | s19_app/tui/workspace.py:2240, s19_app/tui/workspace.py:2457 |
| `S19TuiApp.load_selected_file` | `S19TuiApp._apply_prepared_load` | s19_app/tui/app.py:15275 |
| `S19TuiApp.load_selected_file` | `S19TuiApp.set_status` | s19_app/tui/app.py:15105, s19_app/tui/app.py:15116 |
| `S19TuiApp.on_ab_diff_panel_report_requested` | `S19TuiApp._start_diff_report_worker` | s19_app/tui/app.py:6917 |
| `S19TuiApp.on_ab_diff_panel_report_requested` | `S19TuiApp.set_progress` | s19_app/tui/app.py:6916 |
| `S19TuiApp.on_ab_diff_panel_report_requested` | `S19TuiApp.set_status` | s19_app/tui/app.py:6874 |
| `S19TuiApp.on_list_view_selected` | `S19TuiApp._load_from_item` | s19_app/tui/app.py:13203 |
| `S19TuiApp.on_list_view_selected` | `S19TuiApp.set_status` | s19_app/tui/app.py:17285 |
| `S19TuiApp.on_report_viewer_screen_generate_requested` | `S19TuiApp._trigger_generate_report` | s19_app/tui/app.py:5464 |
| `S19TuiApp.refresh_files` | `list_workarea_files` | s19_app/tui/app.py:7329 |
| `S19TuiApp.refresh_files` | `painted_names` | s19_app/tui/app.py:7331 |
| `S19TuiApp.set_progress` | `S19TuiApp.set_status` | s19_app/tui/app.py:17973 |

Top-level sites (no marked node above them):

- `S19TuiApp._load_path_from_user_input`: s19_app/tui/app.py:7237
- `S19TuiApp.action_before_after_report`: s19_app/tui/app.py:4253
- `S19TuiApp.list_projects`: s19_app/tui/app.py:7451
- `S19TuiApp.load_from_path`: s19_app/tui/app.py:7622
- `S19TuiApp.refresh_files`: s19_app/tui/app.py:7204, s19_app/tui/app.py:7337
- `S19TuiApp.set_status`: s19_app/tui/app.py:12696, s19_app/tui/app.py:12700, s19_app/tui/app.py:12710, s19_app/tui/app.py:12741, s19_app/tui/app.py:13446, s19_app/tui/app.py:13548, s19_app/tui/app.py:13552, s19_app/tui/app.py:13574, s19_app/tui/app.py:13576, s19_app/tui/app.py:13609, s19_app/tui/app.py:13706, s19_app/tui/app.py:13714, s19_app/tui/app.py:14545, s19_app/tui/app.py:14603, s19_app/tui/app.py:17747, s19_app/tui/app.py:17751, s19_app/tui/app.py:17767, s19_app/tui/app.py:17772, s19_app/tui/app.py:17805, s19_app/tui/app.py:17817, s19_app/tui/app.py:17822, s19_app/tui/app.py:17828, s19_app/tui/app.py:17833, s19_app/tui/app.py:17837, s19_app/tui/app.py:17842, s19_app/tui/app.py:17858, s19_app/tui/app.py:17863, s19_app/tui/app.py:17867, s19_app/tui/app.py:17873, s19_app/tui/app.py:17879, s19_app/tui/app.py:17884, s19_app/tui/app.py:17888, s19_app/tui/app.py:17892, s19_app/tui/app.py:17908, s19_app/tui/app.py:17913, s19_app/tui/app.py:17917, s19_app/tui/app.py:17922, s19_app/tui/app.py:17928, s19_app/tui/app.py:17933, s19_app/tui/app.py:3400, s19_app/tui/app.py:3587, s19_app/tui/app.py:3679, s19_app/tui/app.py:3703, s19_app/tui/app.py:3721, s19_app/tui/app.py:3756, s19_app/tui/app.py:3763, s19_app/tui/app.py:3947, s19_app/tui/app.py:3954, s19_app/tui/app.py:3959, s19_app/tui/app.py:3962, s19_app/tui/app.py:3969, s19_app/tui/app.py:3995, s19_app/tui/app.py:4013, s19_app/tui/app.py:4022, s19_app/tui/app.py:4059, s19_app/tui/app.py:4154, s19_app/tui/app.py:4158, s19_app/tui/app.py:4501, s19_app/tui/app.py:4620, s19_app/tui/app.py:5034, s19_app/tui/app.py:5036, s19_app/tui/app.py:5072, s19_app/tui/app.py:5077, s19_app/tui/app.py:5083, s19_app/tui/app.py:5091, s19_app/tui/app.py:5218, s19_app/tui/app.py:5227, s19_app/tui/app.py:5229, s19_app/tui/app.py:5233, s19_app/tui/app.py:5269, s19_app/tui/app.py:5342, s19_app/tui/app.py:5390, s19_app/tui/app.py:5394, s19_app/tui/app.py:5398, s19_app/tui/app.py:5430, s19_app/tui/app.py:6158, s19_app/tui/app.py:6258, s19_app/tui/app.py:6261, s19_app/tui/app.py:6368, s19_app/tui/app.py:6379, s19_app/tui/app.py:6388, s19_app/tui/app.py:6392, s19_app/tui/app.py:6400, s19_app/tui/app.py:6417, s19_app/tui/app.py:6421, s19_app/tui/app.py:6478, s19_app/tui/app.py:6486, s19_app/tui/app.py:6489, s19_app/tui/app.py:6492, s19_app/tui/app.py:6506, s19_app/tui/app.py:6657, s19_app/tui/app.py:6674, s19_app/tui/app.py:6694, s19_app/tui/app.py:6700, s19_app/tui/app.py:6795, s19_app/tui/app.py:6803, s19_app/tui/app.py:6817, s19_app/tui/app.py:6824, s19_app/tui/app.py:6833, s19_app/tui/app.py:7453, s19_app/tui/app.py:7547, s19_app/tui/app.py:7609, s19_app/tui/app.py:7613, s19_app/tui/app.py:7655, s19_app/tui/app.py:7706, s19_app/tui/app.py:7718, s19_app/tui/app.py:7756, s19_app/tui/app.py:7769, s19_app/tui/app.py:8101, s19_app/tui/app.py:8340, s19_app/tui/app.py:8776, s19_app/tui/app.py:8780, s19_app/tui/open_folder_chip.py:136, s19_app/tui/open_folder_chip.py:186, s19_app/tui/open_folder_chip.py:197, s19_app/tui/open_folder_chip.py:201, s19_app/tui/open_folder_chip.py:214, s19_app/tui/screens.py:2493, s19_app/tui/segment_split_view.py:1871, s19_app/tui/segment_split_view.py:2015, s19_app/tui/segment_split_view.py:2020, s19_app/tui/segment_split_view.py:2079, s19_app/tui/segment_split_view.py:2087, s19_app/tui/segment_split_view.py:2099, s19_app/tui/segment_split_view.py:2112, s19_app/tui/segment_split_view.py:2122, s19_app/tui/segment_split_view.py:2139
