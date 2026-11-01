# Code-Wire extractor report

- Marks found: 34
- Graph nodes parsed: 34
- Real calls between marked nodes: 44
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
| `S19TuiApp._handle_load_project` | `S19TuiApp._parse_loaded_file` | s19_app/tui/app.py:12088, s19_app/tui/app.py:15099 |
| `S19TuiApp._handle_load_project` | `S19TuiApp._project_folder_refusal` | s19_app/tui/app.py:11694 |
| `S19TuiApp._handle_load_project` | `S19TuiApp.list_projects` | s19_app/tui/app.py:11724 |
| `S19TuiApp._handle_load_project` | `choose_install_set` | s19_app/tui/app.py:11879, s19_app/tui/app.py:11920 |
| `S19TuiApp._handle_load_project` | `painted_names` | s19_app/tui/app.py:11696, s19_app/tui/app.py:11728, s19_app/tui/app.py:11745, s19_app/tui/app.py:11785, s19_app/tui/app.py:11786, s19_app/tui/app.py:11815, s19_app/tui/app.py:11820 |
| `S19TuiApp._handle_load_project` | `safe_text` | s19_app/tui/app.py:11712, s19_app/tui/app.py:11727, s19_app/tui/app.py:11744, s19_app/tui/app.py:11784, s19_app/tui/app.py:11823, s19_app/tui/app.py:11951, s19_app/tui/app.py:11952, s19_app/tui/app.py:17124, s19_app/tui/app.py:17125, s19_app/tui/app.py:17126, s19_app/tui/app.py:17127, s19_app/tui/app.py:17128, s19_app/tui/app.py:17129, s19_app/tui/app.py:17130, s19_app/tui/app.py:17131, s19_app/tui/app.py:17132, s19_app/tui/app.py:17133, s19_app/tui/app.py:17134, s19_app/tui/app.py:17135, s19_app/tui/app.py:17136, s19_app/tui/app.py:17137, s19_app/tui/app.py:17138, s19_app/tui/app.py:17139, s19_app/tui/app.py:17422 |
| `S19TuiApp._handle_load_project` | `validate_project_files` | s19_app/tui/app.py:11753 |
| `S19TuiApp._handle_select_variant` | `S19TuiApp.load_from_path` | s19_app/tui/app.py:7618 |
| `S19TuiApp._load_from_item` | `S19TuiApp._parse_loaded_file` | s19_app/tui/app.py:15099 |
| `S19TuiApp._load_from_item` | `S19TuiApp.load_a2l_from_path` | s19_app/tui/app.py:13352 |
| `S19TuiApp._load_path_from_user_input` | `S19TuiApp._route_load_project` | s19_app/tui/app.py:12950 |
| `S19TuiApp._load_path_from_user_input` | `S19TuiApp._typed_load_route` | s19_app/tui/app.py:12948 |
| `S19TuiApp._load_path_from_user_input` | `S19TuiApp.load_a2l_from_path` | s19_app/tui/app.py:12953 |
| `S19TuiApp._load_path_from_user_input` | `S19TuiApp.load_from_path` | s19_app/tui/app.py:12956 |
| `S19TuiApp._load_path_from_user_input` | `painted_names` | s19_app/tui/app.py:12958 |
| `S19TuiApp._load_path_from_user_input` | `safe_text` | s19_app/tui/app.py:12980 |
| `S19TuiApp._route_load_project` | `S19TuiApp._handle_load_project` | s19_app/tui/app.py:7484 |
| `S19TuiApp._typed_load_route` | `S19TuiApp.list_projects` | s19_app/tui/app.py:12884 |
| `S19TuiApp._typed_load_route` | `resolve_input_path` | s19_app/tui/app.py:12811, s19_app/tui/app.py:12823 |
| `S19TuiApp._typed_load_route` | `validate_project_files` | s19_app/tui/app.py:12911 |
| `S19TuiApp.action_load_project` | `LoadProjectScreen.__init__` | s19_app/tui/app.py:7452 |
| `S19TuiApp.action_load_project` | `S19TuiApp.list_projects` | s19_app/tui/app.py:7446 |
| `S19TuiApp.list_projects` | `S19TuiApp._project_folder_refusal` | s19_app/tui/app.py:12138 |
| `S19TuiApp.load_a2l_from_path` | `S19TuiApp.refresh_files` | s19_app/tui/app.py:13151 |
| `S19TuiApp.load_a2l_from_path` | `record_recent_source` | s19_app/tui/app.py:13149 |
| `S19TuiApp.load_a2l_from_path` | `resolve_input_path` | s19_app/tui/app.py:13106 |
| `S19TuiApp.load_a2l_from_path` | `safe_text` | s19_app/tui/app.py:12491, s19_app/tui/app.py:17124, s19_app/tui/app.py:17125, s19_app/tui/app.py:17126, s19_app/tui/app.py:17127, s19_app/tui/app.py:17128, s19_app/tui/app.py:17129, s19_app/tui/app.py:17130, s19_app/tui/app.py:17131, s19_app/tui/app.py:17132, s19_app/tui/app.py:17133, s19_app/tui/app.py:17134, s19_app/tui/app.py:17135, s19_app/tui/app.py:17136, s19_app/tui/app.py:17137, s19_app/tui/app.py:17138, s19_app/tui/app.py:17139, s19_app/tui/app.py:17422 |
| `S19TuiApp.load_a2l_from_path` | `validate_project_files` | s19_app/tui/app.py:12754, s19_app/tui/app.py:13118 |
| `S19TuiApp.load_from_path` | `S19TuiApp._parse_loaded_file` | s19_app/tui/app.py:15763 |
| `S19TuiApp.load_from_path` | `S19TuiApp.refresh_files` | s19_app/tui/app.py:13091 |
| `S19TuiApp.load_from_path` | `record_recent_source` | s19_app/tui/app.py:13081 |
| `S19TuiApp.load_from_path` | `resolve_input_path` | s19_app/tui/app.py:13049 |
| `S19TuiApp.on_button_pressed` | `S19TuiApp.action_load_project` | s19_app/tui/app.py:17656 |
| `S19TuiApp.on_button_pressed` | `safe_text` | s19_app/tui/app.py:17124, s19_app/tui/app.py:17125, s19_app/tui/app.py:17126, s19_app/tui/app.py:17127, s19_app/tui/app.py:17128, s19_app/tui/app.py:17129, s19_app/tui/app.py:17130, s19_app/tui/app.py:17131, s19_app/tui/app.py:17132, s19_app/tui/app.py:17133, s19_app/tui/app.py:17134, s19_app/tui/app.py:17135, s19_app/tui/app.py:17136, s19_app/tui/app.py:17137, s19_app/tui/app.py:17138, s19_app/tui/app.py:17139 |
| `S19TuiApp.on_list_view_selected` | `S19TuiApp._load_from_item` | s19_app/tui/app.py:13201 |
| `S19TuiApp.on_list_view_selected` | `safe_text` | s19_app/tui/app.py:17124, s19_app/tui/app.py:17125, s19_app/tui/app.py:17126, s19_app/tui/app.py:17127, s19_app/tui/app.py:17128, s19_app/tui/app.py:17129, s19_app/tui/app.py:17130, s19_app/tui/app.py:17131, s19_app/tui/app.py:17132, s19_app/tui/app.py:17133, s19_app/tui/app.py:17134, s19_app/tui/app.py:17135, s19_app/tui/app.py:17136, s19_app/tui/app.py:17137, s19_app/tui/app.py:17138, s19_app/tui/app.py:17139 |
| `S19TuiApp.on_mount` | `S19TuiApp._load_path_from_user_input` | s19_app/tui/app.py:7230 |
| `S19TuiApp.on_mount` | `S19TuiApp.refresh_files` | s19_app/tui/app.py:7197 |
| `S19TuiApp.refresh_files` | `list_workarea_files` | s19_app/tui/app.py:7322 |
| `S19TuiApp.refresh_files` | `painted_names` | s19_app/tui/app.py:7324 |
| `S19TuiApp.refresh_files` | `safe_text` | s19_app/tui/app.py:7324 |
| `read_recent_sources` | `recent_kind` | s19_app/tui/workspace.py:2242 |
| `record_recent_source` | `read_recent_sources` | s19_app/tui/workspace.py:2491 |
| `record_recent_source` | `recent_kind` | s19_app/tui/workspace.py:2242, s19_app/tui/workspace.py:2461 |

Top-level sites (no marked node above them):

- `S19TuiApp._build_palette_entries`: s19_app/tui/app.py:2768
- `S19TuiApp._project_folder_refusal`: s19_app/tui/app.py:9656, s19_app/tui/app.py:9703
- `S19TuiApp.check_action`: s19_app/tui/window_help.py:1134, s19_app/tui/window_help.py:1145
- `S19TuiApp.refresh_files`: s19_app/tui/app.py:10610, s19_app/tui/app.py:7330
- `painted_names`: s19_app/tui/app.py:10477, s19_app/tui/app.py:10489, s19_app/tui/app.py:10491, s19_app/tui/app.py:10508, s19_app/tui/app.py:10832, s19_app/tui/app.py:12289, s19_app/tui/app.py:12345, s19_app/tui/app.py:12346, s19_app/tui/app.py:12348, s19_app/tui/app.py:12356, s19_app/tui/app.py:12357, s19_app/tui/app.py:9275, s19_app/tui/app.py:9669, s19_app/tui/services/project_gather_service.py:1388, s19_app/tui/services/project_gather_service.py:1390, s19_app/tui/services/project_gather_service.py:1414, s19_app/tui/services/project_gather_service.py:1436, s19_app/tui/services/project_gather_service.py:1619, s19_app/tui/services/project_gather_service.py:1640, s19_app/tui/services/project_gather_service.py:1647
- `resolve_input_path`: s19_app/tui/app.py:5386, s19_app/tui/app.py:6580, s19_app/tui/app.py:6581, s19_app/tui/app.py:9464, s19_app/tui/changes/io.py:419, s19_app/tui/crc_designer_view.py:1307, s19_app/tui/operations/crc_config.py:361, s19_app/tui/operations/crc_designer_model.py:920, s19_app/tui/services/compare_service.py:528 (ref), s19_app/tui/services/report_filter.py:360
- `safe_text`: s19_app/tui/app.py:10098, s19_app/tui/app.py:10469, s19_app/tui/app.py:10475, s19_app/tui/app.py:10488, s19_app/tui/app.py:10507, s19_app/tui/app.py:10597, s19_app/tui/app.py:16242, s19_app/tui/app.py:16252, s19_app/tui/app.py:16262, s19_app/tui/app.py:9273, s19_app/tui/app.py:9288, s19_app/tui/app.py:9393, s19_app/tui/app.py:9668, s19_app/tui/app.py:9957, s19_app/tui/checks_view.py:181, s19_app/tui/checks_view.py:250, s19_app/tui/checks_view.py:255, s19_app/tui/checks_view.py:354, s19_app/tui/checks_view.py:382, s19_app/tui/checks_view.py:409, s19_app/tui/flow_screens.py:1201, s19_app/tui/flow_screens.py:1203, s19_app/tui/flow_screens.py:1396, s19_app/tui/flow_screens.py:1423, s19_app/tui/flow_screens.py:1430, s19_app/tui/flow_screens.py:1442, s19_app/tui/flow_screens.py:1467, s19_app/tui/flow_screens.py:1537, s19_app/tui/flow_screens.py:1619, s19_app/tui/flow_screens.py:1701, s19_app/tui/flow_screens.py:1705, s19_app/tui/flow_screens.py:1743, s19_app/tui/flow_screens.py:1750, s19_app/tui/flow_screens.py:1760, s19_app/tui/flow_screens.py:1765, s19_app/tui/flow_screens.py:1766, s19_app/tui/flow_screens.py:1810, s19_app/tui/flow_screens.py:1901, s19_app/tui/flow_screens.py:2190, s19_app/tui/flow_screens.py:2198, s19_app/tui/flow_screens.py:2206, s19_app/tui/flow_screens.py:2263, s19_app/tui/flow_screens.py:2271, s19_app/tui/flow_screens.py:2329, s19_app/tui/flow_screens.py:2338, s19_app/tui/flow_screens.py:2348, s19_app/tui/flow_screens.py:2360, s19_app/tui/flow_screens.py:2368, s19_app/tui/flow_screens.py:2517, s19_app/tui/flow_screens.py:2609, s19_app/tui/flow_screens.py:3083, s19_app/tui/flow_screens.py:3092, s19_app/tui/flow_screens.py:3095, s19_app/tui/flow_screens.py:3109, s19_app/tui/flow_screens.py:3114, s19_app/tui/flow_screens.py:3257, s19_app/tui/flow_screens.py:3296, s19_app/tui/flow_screens.py:3309, s19_app/tui/flow_screens.py:3314, s19_app/tui/flow_screens.py:3325, s19_app/tui/flow_screens.py:3349, s19_app/tui/flow_screens.py:3433, s19_app/tui/flow_screens.py:3442, s19_app/tui/flow_screens.py:3492, s19_app/tui/flow_screens.py:3530, s19_app/tui/flow_screens.py:3532, s19_app/tui/flow_screens.py:3540, s19_app/tui/flow_screens.py:3553, s19_app/tui/flow_screens.py:3562, s19_app/tui/flow_screens.py:3596, s19_app/tui/flow_screens.py:3662, s19_app/tui/flow_screens.py:3742, s19_app/tui/flow_screens.py:3801, s19_app/tui/flow_screens.py:731, s19_app/tui/flow_screens.py:889, s19_app/tui/flow_screens.py:899, s19_app/tui/issues_view.py:409, s19_app/tui/issues_view.py:487, s19_app/tui/issues_view.py:490, s19_app/tui/issues_view.py:492, s19_app/tui/issues_view.py:644, s19_app/tui/issues_view.py:668, s19_app/tui/issues_view.py:680, s19_app/tui/screens.py:1109, s19_app/tui/screens.py:1134, s19_app/tui/screens.py:1144, s19_app/tui/screens.py:1147, s19_app/tui/screens.py:1154, s19_app/tui/screens.py:1160, s19_app/tui/screens.py:1161, s19_app/tui/screens.py:1162, s19_app/tui/screens_directionb.py:1225, s19_app/tui/screens_directionb.py:1743, s19_app/tui/screens_directionb.py:1786, s19_app/tui/screens_directionb.py:2015, s19_app/tui/screens_directionb.py:2128, s19_app/tui/screens_directionb.py:2131, s19_app/tui/screens_directionb.py:2141, s19_app/tui/screens_directionb.py:2176, s19_app/tui/screens_directionb.py:2633, s19_app/tui/screens_directionb.py:2869, s19_app/tui/screens_directionb.py:2953, s19_app/tui/screens_directionb.py:3084, s19_app/tui/screens_directionb.py:3091, s19_app/tui/screens_directionb.py:3257, s19_app/tui/screens_directionb.py:3258, s19_app/tui/screens_directionb.py:3259, s19_app/tui/screens_directionb.py:3262, s19_app/tui/screens_directionb.py:3263, s19_app/tui/screens_directionb.py:3264, s19_app/tui/screens_directionb.py:3265, s19_app/tui/screens_directionb.py:3325, s19_app/tui/screens_directionb.py:3383, s19_app/tui/screens_directionb.py:3590, s19_app/tui/screens_directionb.py:3595, s19_app/tui/screens_directionb.py:3597, s19_app/tui/screens_directionb.py:3805, s19_app/tui/screens_directionb.py:3905, s19_app/tui/screens_directionb.py:4886, s19_app/tui/screens_directionb.py:5321, s19_app/tui/screens_directionb.py:5322, s19_app/tui/screens_directionb.py:5323, s19_app/tui/screens_directionb.py:5324, s19_app/tui/screens_directionb.py:5426, s19_app/tui/screens_directionb.py:6179, s19_app/tui/screens_directionb.py:6182, s19_app/tui/screens_directionb.py:7061, s19_app/tui/screens_directionb.py:7142, s19_app/tui/screens_directionb.py:7145, s19_app/tui/screens_directionb.py:7146, s19_app/tui/screens_directionb.py:7147, s19_app/tui/screens_directionb.py:7169, s19_app/tui/screens_directionb.py:7172, s19_app/tui/screens_directionb.py:7174, s19_app/tui/screens_directionb.py:7244, s19_app/tui/screens_directionb.py:7282, s19_app/tui/screens_directionb.py:7284, s19_app/tui/screens_directionb.py:7292, s19_app/tui/screens_directionb.py:7339, s19_app/tui/screens_directionb.py:8381, s19_app/tui/screens_directionb.py:8383, s19_app/tui/screens_directionb.py:8414, s19_app/tui/screens_directionb.py:8417, s19_app/tui/segment_split_view.py:2101, s19_app/tui/segment_split_view.py:2114, s19_app/tui/segment_split_view.py:668, s19_app/tui/segment_split_view.py:910, s19_app/tui/segment_split_view.py:911
- `validate_project_files`: s19_app/tui/app.py:10116, s19_app/tui/app.py:10917, s19_app/tui/app.py:12581, s19_app/tui/app.py:12646, s19_app/tui/app.py:9929, s19_app/tui/services/project_gather_service.py:1627, s19_app/tui/services/variant_execution_service.py:2743
