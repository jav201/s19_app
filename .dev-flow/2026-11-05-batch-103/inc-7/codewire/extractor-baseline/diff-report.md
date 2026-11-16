# Code-Wire extractor report

- Marks found: 21
- Graph nodes parsed: 21
- Real calls between marked nodes: 13
- Findings: 0 (0 drift, 0 info)
- Ambiguous call resolutions (a name matched several defs): 9
- Files that failed to parse: 0

Type normalisation: spaces and quotes dropped; `List/Dict/Tuple/Set` -> builtins; `X | None` and graph `X?` -> `Optional[X]`; graph `(Callable) A->B` -> `Callable[[A], B]`; graph `tuple(A a, B b)` -> `tuple[A, B]`. A bare graph container (`dict`) against a parameterised code type (`dict[str, Any]`) is info (loose match), not drift.

Call resolution is name-based (`f()`, `Class()` -> `__init__`, `self.m()`, `x.m()` -> top-level `m` or a marked method `m`); dynamic calls and callables passed as values are not seen. Tests excluded.

## Counts

| Kind | Count |
|---|---|

## Real calls between marked nodes

| Caller | Callee | Sites |
|---|---|---|
| `A2LDetailCard.show_tag` | `_a2l_detail_card_text` | s19_app/tui/app/shared.py:625 |
| `A2lViewMixin._filter_a2l_tags` | `A2lViewMixin._tag_matches_filter` | s19_app/tui/app/a2l_view.py:1458 |
| `A2lViewMixin._refresh_a2l_dependent_views` | `A2LDetailCard.show_tag` | s19_app/tui/app/a2l_view.py:927 |
| `A2lViewMixin._refresh_a2l_dependent_views` | `A2lViewMixin.update_a2l_view` | s19_app/tui/app/a2l_view.py:913 |
| `A2lViewMixin._refresh_a2l_filtered_tags` | `A2lViewMixin._filter_a2l_tags` | s19_app/tui/app/a2l_view.py:859 |
| `A2lViewMixin._refresh_a2l_filtered_tags` | `A2lViewMixin.update_a2l_tags_view` | s19_app/tui/app/a2l_view.py:866, s19_app/tui/app/a2l_view.py:871 |
| `A2lViewMixin._schedule_a2l_filter_refresh` | `A2lViewMixin._refresh_a2l_filtered_tags` | s19_app/tui/app/a2l_view.py:1586 |
| `A2lViewMixin.update_a2l_tags_view` | `A2lViewMixin._build_a2l_table_cells` | s19_app/tui/app/a2l_view.py:1085 |
| `A2lViewMixin.update_a2l_view` | `A2lViewMixin._refresh_a2l_filtered_tags` | s19_app/tui/app/a2l_view.py:1001 |
| `A2lViewMixin.update_a2l_view` | `A2lViewMixin.update_a2l_tags_view` | s19_app/tui/app/a2l_view.py:987 |
| `NavigationMixin.on_data_table_row_highlighted` | `A2LDetailCard.show_tag` | s19_app/tui/app/navigation.py:1423 |
| `OsClipboardInput._on_paste` | `_strip_paste_controls` | s19_app/tui/os_clipboard_input.py:947, s19_app/tui/os_clipboard_input.py:953 |
| `OsClipboardInput.action_paste` | `_strip_paste_controls` | s19_app/tui/os_clipboard_input.py:1104, s19_app/tui/os_clipboard_input.py:1108 |

Top-level sites (no marked node above them):

- `A2LDetailCard.show_tag`: s19_app/tui/app/shared.py:581
- `A2lViewMixin._build_a2l_table_cells`: s19_app/tui/app/a2l_view.py:1210, s19_app/tui/app/a2l_view.py:1307
- `A2lViewMixin._jump_to_tag_by_data`: s19_app/tui/app/a2l_view.py:441
- `A2lViewMixin._refresh_a2l_filtered_tags`: s19_app/tui/app/a2l_view.py:1554
- `A2lViewMixin.update_a2l_tags_view`: s19_app/tui/app/a2l_view.py:1214, s19_app/tui/app/a2l_view.py:366, s19_app/tui/app/a2l_view.py:392, s19_app/tui/app/a2l_view.py:507
- `OsClipboardInput.action_paste`: s19_app/tui/os_clipboard_input.py:977
- `_a2l_detail_card_text`: s19_app/tui/app/shared.py:600
- `_strip_paste_controls`: s19_app/tui/capped_text_area.py:169, s19_app/tui/capped_text_area.py:238
- `parse_parameter_list`: s19_app/tui/screens.py:1019
