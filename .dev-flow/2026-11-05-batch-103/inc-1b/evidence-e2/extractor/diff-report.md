# Code-Wire extractor report

- Marks found: 25
- Graph nodes parsed: 25
- Real calls between marked nodes: 17
- Findings: 0 (0 drift, 0 info)
- Ambiguous call resolutions (a name matched several defs): 3
- Files that failed to parse: 0

Type normalisation: spaces and quotes dropped; `List/Dict/Tuple/Set` -> builtins; `X | None` and graph `X?` -> `Optional[X]`; graph `(Callable) A->B` -> `Callable[[A], B]`; graph `tuple(A a, B b)` -> `tuple[A, B]`. A bare graph container (`dict`) against a parameterised code type (`dict[str, Any]`) is info (loose match), not drift.

Call resolution is name-based (`f()`, `Class()` -> `__init__`, `self.m()`, `x.m()` -> top-level `m` or a marked method `m`); dynamic calls and callables passed as values are not seen. Tests excluded.

## Counts

| Kind | Count |
|---|---|

## Real calls between marked nodes

| Caller | Callee | Sites |
|---|---|---|
| `CappedTextArea.action_copy` | `_mirror_and_write_os_clipboard` | s19_app/tui/capped_text_area.py:270 |
| `CappedTextArea.action_cut` | `_mirror_and_write_os_clipboard` | s19_app/tui/capped_text_area.py:308 |
| `OsClipboardInput.action_copy` | `_mirror_and_write_os_clipboard` | s19_app/tui/os_clipboard_input.py:916 |
| `OsClipboardInput.action_cut` | `_mirror_and_write_os_clipboard` | s19_app/tui/os_clipboard_input.py:944 |
| `S19TuiApp._answer_quit` | `S19TuiApp._exit_if_quit_pending` | s19_app/tui/app.py:23040 |
| `S19TuiApp._exit_if_quit_pending` | `S19TuiApp._running_session_action` | s19_app/tui/app.py:23044 |
| `S19TuiApp._fit_a2l_tag_cells` | `S19TuiApp._build_a2l_table_cells` | s19_app/tui/app.py:21619 |
| `S19TuiApp._fit_a2l_tag_cells` | `S19TuiApp.update_a2l_tags_view` | s19_app/tui/app.py:21623 |
| `S19TuiApp._refuse_if_busy` | `S19TuiApp._running_session_action` | s19_app/tui/app.py:23010 |
| `S19TuiApp._repaint_a2l_tag_cells` | `S19TuiApp._build_a2l_table_cells` | s19_app/tui/app.py:21716 |
| `S19TuiApp.action_quit` | `S19TuiApp._running_session_action` | s19_app/tui/app.py:23019 |
| `S19TuiApp.compose` | `S19TuiApp._compose_screen_a2l` | s19_app/tui/app.py:3602 |
| `S19TuiApp.compose` | `S19TuiApp._compose_screen_mac` | s19_app/tui/app.py:3603 |
| `S19TuiApp.end_busy` | `S19TuiApp._exit_if_quit_pending` | s19_app/tui/app.py:22907 |
| `S19TuiApp.on_a2l_tag_table_measured` | `S19TuiApp._fit_a2l_tag_cells` | s19_app/tui/app.py:21658 |
| `S19TuiApp.update_a2l_tags_view` | `S19TuiApp._build_a2l_table_cells` | s19_app/tui/app.py:21494 |
| `_mirror_and_write_os_clipboard` | `write_os_clipboard` | s19_app/tui/os_clipboard_input.py:741 (ref) |

Top-level sites (no marked node above them):

- `A2LTagTable.on_resize`: s19_app/tui/app.py:1562
- `CappedTextArea.action_copy`: s19_app/tui/capped_text_area.py:327
- `OsClipboardInput.action_copy`: s19_app/tui/os_clipboard_input.py:879
- `S19TuiApp._invalidate_a2l_view_cache`: s19_app/tui/app.py:21157
- `S19TuiApp._refuse_if_busy`: s19_app/tui/app.py:12833, s19_app/tui/app.py:14724, s19_app/tui/app.py:16582, s19_app/tui/app.py:16695, s19_app/tui/app.py:16793, s19_app/tui/app.py:16903, s19_app/tui/app.py:18581, s19_app/tui/app.py:18609, s19_app/tui/app.py:5030, s19_app/tui/app.py:5260, s19_app/tui/app.py:5551, s19_app/tui/app.py:5578, s19_app/tui/app.py:5633, s19_app/tui/app.py:5668, s19_app/tui/app.py:5716, s19_app/tui/app.py:5770, s19_app/tui/app.py:5838, s19_app/tui/app.py:5898, s19_app/tui/app.py:7733, s19_app/tui/app.py:7868, s19_app/tui/app.py:7882, s19_app/tui/app.py:9038, s19_app/tui/app.py:9106, s19_app/tui/app.py:9176, s19_app/tui/app.py:9240, s19_app/tui/app.py:9788
- `S19TuiApp._repaint_a2l_tag_cells`: s19_app/tui/app.py:19336
- `S19TuiApp._running_session_action`: s19_app/tui/app.py:6747
- `S19TuiApp.end_busy`: s19_app/tui/app.py:13550, s19_app/tui/app.py:13669, s19_app/tui/app.py:13673, s19_app/tui/app.py:15080, s19_app/tui/app.py:15129, s19_app/tui/app.py:15164, s19_app/tui/app.py:15174, s19_app/tui/app.py:15227, s19_app/tui/app.py:16614, s19_app/tui/app.py:17043, s19_app/tui/app.py:17048, s19_app/tui/app.py:20022, s19_app/tui/app.py:20071, s19_app/tui/app.py:22966, s19_app/tui/app.py:7097
- `S19TuiApp.update_a2l_tags_view`: s19_app/tui/app.py:11643, s19_app/tui/app.py:11669, s19_app/tui/app.py:17422, s19_app/tui/app.py:21278, s19_app/tui/app.py:21283, s19_app/tui/app.py:21397, s19_app/tui/app.py:21981
