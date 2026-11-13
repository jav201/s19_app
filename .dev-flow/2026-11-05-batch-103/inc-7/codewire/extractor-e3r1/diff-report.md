# Code-Wire extractor report

- Marks found: 11
- Graph nodes parsed: 11
- Real calls between marked nodes: 5
- Findings: 0 (0 drift, 0 info)
- Ambiguous call resolutions (a name matched several defs): 35
- Files that failed to parse: 1

Type normalisation: spaces and quotes dropped; `List/Dict/Tuple/Set` -> builtins; `X | None` and graph `X?` -> `Optional[X]`; graph `(Callable) A->B` -> `Callable[[A], B]`; graph `tuple(A a, B b)` -> `tuple[A, B]`. A bare graph container (`dict`) against a parameterised code type (`dict[str, Any]`) is info (loose match), not drift.

Call resolution is name-based (`f()`, `Class()` -> `__init__`, `self.m()`, `x.m()` -> top-level `m` or a marked method `m`); dynamic calls and callables passed as values are not seen. Tests excluded.

## Counts

| Kind | Count |
|---|---|

## Real calls between marked nodes

| Caller | Callee | Sites |
|---|---|---|
| `A2lViewMixin._refresh_a2l_filtered_tags` | `A2lViewMixin._filter_a2l_tags` | s19_app/tui/app/a2l_view.py:859 |
| `A2lViewMixin._refresh_a2l_filtered_tags` | `A2lViewMixin.update_a2l_tags_view` | s19_app/tui/app/a2l_view.py:866, s19_app/tui/app/a2l_view.py:871 |
| `A2lViewMixin._schedule_a2l_filter_refresh` | `A2lViewMixin._refresh_a2l_filtered_tags` | s19_app/tui/app/a2l_view.py:1584 |
| `A2lViewMixin.update_a2l_view` | `A2lViewMixin._refresh_a2l_filtered_tags` | s19_app/tui/app/a2l_view.py:1000 |
| `A2lViewMixin.update_a2l_view` | `A2lViewMixin.update_a2l_tags_view` | s19_app/tui/app/a2l_view.py:986 |

Top-level sites (no marked node above them):

- `A2LDetailCard.show_tag`: s19_app/tui/app/a2l_view.py:926, s19_app/tui/app/navigation.py:1421, s19_app/tui/app/shared.py:580
- `A2lViewMixin._jump_to_tag_by_data`: s19_app/tui/app/a2l_view.py:441
- `A2lViewMixin._refresh_a2l_filtered_tags`: s19_app/tui/app/a2l_view.py:1552
- `A2lViewMixin.update_a2l_tags_view`: s19_app/tui/app/a2l_view.py:1213, s19_app/tui/app/a2l_view.py:366, s19_app/tui/app/a2l_view.py:392, s19_app/tui/app/a2l_view.py:507
- `A2lViewMixin.update_a2l_view`: s19_app/tui/app/a2l_view.py:912
- `OsClipboardInput.action_paste`: s19_app/tui/os_clipboard_input.py:976

## Files skipped (parse error)

- `tools/mutation_harness.py`: f-string expression part cannot include a backslash (<unknown>, line 190)
