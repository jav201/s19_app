# Code-Wire extractor report

- Marks found: 28
- Graph nodes parsed: 28
- Real calls between marked nodes: 43
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
| `S19TuiApp._handle_load_project` | `S19TuiApp._apply_prepared_load` | s19_app/tui/app.py:15025 |
| `S19TuiApp._handle_load_project` | `S19TuiApp._project_folder_refusal` | s19_app/tui/app.py:11687 |
| `S19TuiApp._handle_load_project` | `S19TuiApp.load_selected_file` | s19_app/tui/app.py:11889 |
| `S19TuiApp._handle_load_project` | `_is_reparse_point` | s19_app/tui/app.py:11733, s19_app/tui/services/manifest_writer.py:1159, s19_app/tui/services/manifest_writer.py:980, s19_app/tui/workspace.py:372, s19_app/tui/workspace.py:380 |
| `S19TuiApp._handle_load_project` | `is_windows_device_name` | s19_app/tui/services/variant_execution_service.py:548 |
| `S19TuiApp._handle_load_project` | `safe_text` | s19_app/tui/app.py:11705, s19_app/tui/app.py:11743, s19_app/tui/app.py:11782, s19_app/tui/app.py:11910, s19_app/tui/app.py:11911, s19_app/tui/app.py:16879, s19_app/tui/app.py:16880, s19_app/tui/app.py:16881, s19_app/tui/app.py:16882, s19_app/tui/app.py:16883, s19_app/tui/app.py:16884, s19_app/tui/app.py:16885, s19_app/tui/app.py:16886, s19_app/tui/app.py:16887, s19_app/tui/app.py:16888, s19_app/tui/app.py:16889, s19_app/tui/app.py:16890, s19_app/tui/app.py:16891, s19_app/tui/app.py:16892, s19_app/tui/app.py:16893, s19_app/tui/app.py:16894, s19_app/tui/app.py:17177 |
| `S19TuiApp._handle_load_project` | `validate_project_files` | s19_app/tui/app.py:11712 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp._project_folder_refusal` | s19_app/tui/app.py:9649, s19_app/tui/app.py:9696 |
| `S19TuiApp._handle_save_dialog` | `S19TuiApp.refresh_files` | s19_app/tui/app.py:10603 |
| `S19TuiApp._handle_save_dialog` | `_is_reparse_point` | s19_app/tui/app.py:10926, s19_app/tui/app.py:12110, s19_app/tui/app.py:9575, s19_app/tui/services/manifest_writer.py:980, s19_app/tui/services/project_gather_service.py:1290, s19_app/tui/workspace.py:1154, s19_app/tui/workspace.py:1160, s19_app/tui/workspace.py:1288, s19_app/tui/workspace.py:336, s19_app/tui/workspace.py:372, s19_app/tui/workspace.py:380, s19_app/tui/workspace.py:496, s19_app/tui/workspace.py:573, s19_app/tui/workspace.py:578, s19_app/tui/workspace.py:603, s19_app/tui/workspace.py:758, s19_app/tui/workspace.py:935 |
| `S19TuiApp._handle_save_dialog` | `contained_in_workarea` | s19_app/tui/app.py:12237, s19_app/tui/workspace.py:776 |
| `S19TuiApp._handle_save_dialog` | `copy_into_workarea` | s19_app/tui/changes/io.py:1590 (ref) |
| `S19TuiApp._handle_save_dialog` | `is_windows_device_name` | s19_app/tui/app.py:10494, s19_app/tui/app.py:9510, s19_app/tui/services/variant_execution_service.py:548 |
| `S19TuiApp._handle_save_dialog` | `resolve_input_path` | s19_app/tui/app.py:9457 |
| `S19TuiApp._handle_save_dialog` | `safe_text` | s19_app/tui/app.py:10091, s19_app/tui/app.py:10462, s19_app/tui/app.py:10468, s19_app/tui/app.py:10481, s19_app/tui/app.py:10500, s19_app/tui/app.py:10590, s19_app/tui/app.py:17177, s19_app/tui/app.py:9265, s19_app/tui/app.py:9280, s19_app/tui/app.py:9385, s19_app/tui/app.py:9661, s19_app/tui/app.py:9950 |
| `S19TuiApp._handle_save_dialog` | `validate_project_files` | s19_app/tui/app.py:10109, s19_app/tui/app.py:10910, s19_app/tui/app.py:9922, s19_app/tui/services/project_gather_service.py:1626 |
| `S19TuiApp._handle_select_variant` | `S19TuiApp.load_from_path` | s19_app/tui/app.py:7612 |
| `S19TuiApp._load_from_item` | `S19TuiApp.load_a2l_from_path` | s19_app/tui/app.py:13104 |
| `S19TuiApp._load_from_item` | `S19TuiApp.load_selected_file` | s19_app/tui/app.py:13106 |
| `S19TuiApp._load_path_from_user_input` | `S19TuiApp.load_a2l_from_path` | s19_app/tui/app.py:12735 |
| `S19TuiApp._load_path_from_user_input` | `S19TuiApp.load_from_path` | s19_app/tui/app.py:12737 |
| `S19TuiApp._load_path_from_user_input` | `resolve_input_path` | s19_app/tui/app.py:12728 |
| `S19TuiApp._project_folder_refusal` | `_is_reparse_point` | s19_app/tui/app.py:12168 |
| `S19TuiApp._project_folder_refusal` | `contained_in_workarea` | s19_app/tui/app.py:12170 |
| `S19TuiApp._route_load_project` | `S19TuiApp._handle_load_project` | s19_app/tui/app.py:7478 |
| `S19TuiApp.action_load_project` | `S19TuiApp.list_projects` | s19_app/tui/app.py:7440 |
| `S19TuiApp.list_projects` | `S19TuiApp._project_folder_refusal` | s19_app/tui/app.py:12092 |
| `S19TuiApp.load_a2l_from_path` | `S19TuiApp.refresh_files` | s19_app/tui/app.py:12904 |
| `S19TuiApp.load_a2l_from_path` | `_is_reparse_point` | s19_app/tui/services/manifest_writer.py:980, s19_app/tui/workspace.py:1154, s19_app/tui/workspace.py:1160, s19_app/tui/workspace.py:1288, s19_app/tui/workspace.py:372, s19_app/tui/workspace.py:380, s19_app/tui/workspace.py:496, s19_app/tui/workspace.py:573, s19_app/tui/workspace.py:578, s19_app/tui/workspace.py:603, s19_app/tui/workspace.py:758, s19_app/tui/workspace.py:935 |
| `S19TuiApp.load_a2l_from_path` | `contained_in_workarea` | s19_app/tui/workspace.py:776 |
| `S19TuiApp.load_a2l_from_path` | `copy_into_workarea` | s19_app/tui/app.py:12897 |
| `S19TuiApp.load_a2l_from_path` | `resolve_input_path` | s19_app/tui/app.py:12862 |
| `S19TuiApp.load_a2l_from_path` | `safe_text` | s19_app/tui/app.py:12445, s19_app/tui/app.py:16879, s19_app/tui/app.py:16880, s19_app/tui/app.py:16881, s19_app/tui/app.py:16882, s19_app/tui/app.py:16883, s19_app/tui/app.py:16884, s19_app/tui/app.py:16885, s19_app/tui/app.py:16886, s19_app/tui/app.py:16887, s19_app/tui/app.py:16888, s19_app/tui/app.py:16889, s19_app/tui/app.py:16890, s19_app/tui/app.py:16891, s19_app/tui/app.py:16892, s19_app/tui/app.py:16893, s19_app/tui/app.py:16894, s19_app/tui/app.py:17177 |
| `S19TuiApp.load_a2l_from_path` | `validate_project_files` | s19_app/tui/app.py:12708, s19_app/tui/app.py:12874 |
| `S19TuiApp.load_from_path` | `S19TuiApp._start_load_worker` | s19_app/tui/app.py:12843 |
| `S19TuiApp.load_from_path` | `S19TuiApp.refresh_files` | s19_app/tui/app.py:12847 |
| `S19TuiApp.load_from_path` | `copy_into_workarea` | s19_app/tui/app.py:12825 |
| `S19TuiApp.load_from_path` | `resolve_input_path` | s19_app/tui/app.py:12808 |
| `S19TuiApp.load_selected_file` | `S19TuiApp._apply_prepared_load` | s19_app/tui/app.py:15025 |
| `S19TuiApp.on_mount` | `S19TuiApp._load_path_from_user_input` | s19_app/tui/app.py:7227 |
| `S19TuiApp.on_mount` | `S19TuiApp.refresh_files` | s19_app/tui/app.py:7194 |
| `copy_into_workarea` | `_is_reparse_point` | s19_app/tui/workspace.py:1154, s19_app/tui/workspace.py:1160, s19_app/tui/workspace.py:1288, s19_app/tui/workspace.py:372, s19_app/tui/workspace.py:380, s19_app/tui/workspace.py:496, s19_app/tui/workspace.py:573, s19_app/tui/workspace.py:578, s19_app/tui/workspace.py:603, s19_app/tui/workspace.py:758, s19_app/tui/workspace.py:935 |
| `copy_into_workarea` | `contained_in_workarea` | s19_app/tui/workspace.py:776 |

Top-level sites (no marked node above them):

- `S19TuiApp._apply_prepared_load`: docs/images/capture_readme_media.py:88
- `S19TuiApp._load_from_item`: s19_app/tui/app.py:12953
- `S19TuiApp.action_load_project`: s19_app/tui/app.py:17410
- `S19TuiApp.on_mount`: tools/e13/run.py:117
- `S19TuiApp.refresh_files`: s19_app/tui/app.py:7324
- `_is_reparse_point`: s19_app/tui/segment_split_view.py:857, s19_app/tui/workspace.py:1600, s19_app/tui/workspace.py:1606, s19_app/tui/workspace.py:1666, s19_app/tui/workspace.py:1761
- `copy_into_workarea`: prototypes/fb_p1_flow_persistence.prototype.py:539, prototypes/fb_p1_flow_persistence.prototype.py:552, s19_app/tui/operations/crc.py:1507, s19_app/tui/services/flow_execution_service.py:1108, s19_app/tui/services/flow_persistence_service.py:1106
- `resolve_input_path`: s19_app/tui/app.py:5383, s19_app/tui/app.py:6577, s19_app/tui/app.py:6578, s19_app/tui/changes/io.py:419, s19_app/tui/crc_designer_view.py:1307, s19_app/tui/operations/crc_config.py:361, s19_app/tui/operations/crc_designer_model.py:920, s19_app/tui/services/compare_service.py:528 (ref), s19_app/tui/services/report_filter.py:360
- `safe_text`: s19_app/tui/app.py:15997, s19_app/tui/app.py:16007, s19_app/tui/app.py:16017, s19_app/tui/checks_view.py:181, s19_app/tui/checks_view.py:250, s19_app/tui/checks_view.py:255, s19_app/tui/checks_view.py:354, s19_app/tui/checks_view.py:382, s19_app/tui/checks_view.py:409, s19_app/tui/flow_screens.py:1201, s19_app/tui/flow_screens.py:1203, s19_app/tui/flow_screens.py:1396, s19_app/tui/flow_screens.py:1423, s19_app/tui/flow_screens.py:1430, s19_app/tui/flow_screens.py:1442, s19_app/tui/flow_screens.py:1467, s19_app/tui/flow_screens.py:1537, s19_app/tui/flow_screens.py:1619, s19_app/tui/flow_screens.py:1701, s19_app/tui/flow_screens.py:1705, s19_app/tui/flow_screens.py:1743, s19_app/tui/flow_screens.py:1750, s19_app/tui/flow_screens.py:1760, s19_app/tui/flow_screens.py:1765, s19_app/tui/flow_screens.py:1766, s19_app/tui/flow_screens.py:1810, s19_app/tui/flow_screens.py:1901, s19_app/tui/flow_screens.py:2190, s19_app/tui/flow_screens.py:2198, s19_app/tui/flow_screens.py:2206, s19_app/tui/flow_screens.py:2263, s19_app/tui/flow_screens.py:2271, s19_app/tui/flow_screens.py:2329, s19_app/tui/flow_screens.py:2338, s19_app/tui/flow_screens.py:2348, s19_app/tui/flow_screens.py:2360, s19_app/tui/flow_screens.py:2368, s19_app/tui/flow_screens.py:2517, s19_app/tui/flow_screens.py:2609, s19_app/tui/flow_screens.py:3083, s19_app/tui/flow_screens.py:3092, s19_app/tui/flow_screens.py:3095, s19_app/tui/flow_screens.py:3109, s19_app/tui/flow_screens.py:3114, s19_app/tui/flow_screens.py:3257, s19_app/tui/flow_screens.py:3296, s19_app/tui/flow_screens.py:3309, s19_app/tui/flow_screens.py:3314, s19_app/tui/flow_screens.py:3325, s19_app/tui/flow_screens.py:3349, s19_app/tui/flow_screens.py:3433, s19_app/tui/flow_screens.py:3442, s19_app/tui/flow_screens.py:3492, s19_app/tui/flow_screens.py:3530, s19_app/tui/flow_screens.py:3532, s19_app/tui/flow_screens.py:3540, s19_app/tui/flow_screens.py:3553, s19_app/tui/flow_screens.py:3562, s19_app/tui/flow_screens.py:3596, s19_app/tui/flow_screens.py:3662, s19_app/tui/flow_screens.py:3742, s19_app/tui/flow_screens.py:3801, s19_app/tui/flow_screens.py:731, s19_app/tui/flow_screens.py:889, s19_app/tui/flow_screens.py:899, s19_app/tui/issues_view.py:409, s19_app/tui/issues_view.py:487, s19_app/tui/issues_view.py:490, s19_app/tui/issues_view.py:492, s19_app/tui/issues_view.py:644, s19_app/tui/issues_view.py:668, s19_app/tui/issues_view.py:680, s19_app/tui/screens.py:1106, s19_app/tui/screens.py:1131, s19_app/tui/screens.py:1141, s19_app/tui/screens.py:1144, s19_app/tui/screens.py:1151, s19_app/tui/screens.py:1157, s19_app/tui/screens.py:1158, s19_app/tui/screens.py:1159, s19_app/tui/screens_directionb.py:1225, s19_app/tui/screens_directionb.py:1743, s19_app/tui/screens_directionb.py:1786, s19_app/tui/screens_directionb.py:2015, s19_app/tui/screens_directionb.py:2128, s19_app/tui/screens_directionb.py:2131, s19_app/tui/screens_directionb.py:2141, s19_app/tui/screens_directionb.py:2176, s19_app/tui/screens_directionb.py:2633, s19_app/tui/screens_directionb.py:2869, s19_app/tui/screens_directionb.py:2953, s19_app/tui/screens_directionb.py:3084, s19_app/tui/screens_directionb.py:3091, s19_app/tui/screens_directionb.py:3257, s19_app/tui/screens_directionb.py:3258, s19_app/tui/screens_directionb.py:3259, s19_app/tui/screens_directionb.py:3262, s19_app/tui/screens_directionb.py:3263, s19_app/tui/screens_directionb.py:3264, s19_app/tui/screens_directionb.py:3265, s19_app/tui/screens_directionb.py:3325, s19_app/tui/screens_directionb.py:3383, s19_app/tui/screens_directionb.py:3590, s19_app/tui/screens_directionb.py:3595, s19_app/tui/screens_directionb.py:3597, s19_app/tui/screens_directionb.py:3805, s19_app/tui/screens_directionb.py:3905, s19_app/tui/screens_directionb.py:4886, s19_app/tui/screens_directionb.py:5321, s19_app/tui/screens_directionb.py:5322, s19_app/tui/screens_directionb.py:5323, s19_app/tui/screens_directionb.py:5324, s19_app/tui/screens_directionb.py:5426, s19_app/tui/screens_directionb.py:6179, s19_app/tui/screens_directionb.py:6182, s19_app/tui/screens_directionb.py:7061, s19_app/tui/screens_directionb.py:7142, s19_app/tui/screens_directionb.py:7145, s19_app/tui/screens_directionb.py:7146, s19_app/tui/screens_directionb.py:7147, s19_app/tui/screens_directionb.py:7169, s19_app/tui/screens_directionb.py:7172, s19_app/tui/screens_directionb.py:7174, s19_app/tui/screens_directionb.py:7244, s19_app/tui/screens_directionb.py:7282, s19_app/tui/screens_directionb.py:7284, s19_app/tui/screens_directionb.py:7292, s19_app/tui/screens_directionb.py:7339, s19_app/tui/screens_directionb.py:8381, s19_app/tui/screens_directionb.py:8383, s19_app/tui/screens_directionb.py:8414, s19_app/tui/screens_directionb.py:8417, s19_app/tui/segment_split_view.py:2101, s19_app/tui/segment_split_view.py:2114, s19_app/tui/segment_split_view.py:668, s19_app/tui/segment_split_view.py:910, s19_app/tui/segment_split_view.py:911
- `validate_project_files`: s19_app/tui/app.py:12535, s19_app/tui/app.py:12600, s19_app/tui/services/variant_execution_service.py:2743
