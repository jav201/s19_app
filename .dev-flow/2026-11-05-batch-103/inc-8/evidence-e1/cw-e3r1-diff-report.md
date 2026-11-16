# Code-Wire extractor report

- Marks found: 6
- Graph nodes parsed: 6
- Real calls between marked nodes: 0
- Findings: 2 (2 drift, 0 info)
- Ambiguous call resolutions (a name matched several defs): 9
- Files that failed to parse: 0

Type normalisation: spaces and quotes dropped; `List/Dict/Tuple/Set` -> builtins; `X | None` and graph `X?` -> `Optional[X]`; graph `(Callable) A->B` -> `Callable[[A], B]`; graph `tuple(A a, B b)` -> `tuple[A, B]`. A bare graph container (`dict`) against a parameterised code type (`dict[str, Any]`) is info (loose match), not drift.

Call resolution is name-based (`f()`, `Class()` -> `__init__`, `self.m()`, `x.m()` -> top-level `m` or a marked method `m`); dynamic calls and callables passed as values are not seen. Tests excluded.

## Counts

| Kind | Count |
|---|---|
| Default value mismatch | 2 |

## Real calls between marked nodes

| Caller | Callee | Sites |
|---|---|---|

Top-level sites (no marked node above them):

- `A2LParameterPicker.set_parameters`: s19_app/tui/screens_directionb/check_editor.py:223, s19_app/tui/screens_directionb/patch_editor/a2l_picker.py:40
- `PatchMixin._report_change_result`: s19_app/tui/app/patch.py:1498, s19_app/tui/app/patch.py:192, s19_app/tui/app/patch.py:213, s19_app/tui/app/patch.py:249, s19_app/tui/app/patch.py:261, s19_app/tui/app/patch.py:416, s19_app/tui/app/patch.py:860, s19_app/tui/app/patch.py:985
- `PatchMixin._strip_source_map`: s19_app/tui/app/patch.py:1537, s19_app/tui/app/patch.py:293, s19_app/tui/app/patch.py:571
- `ShellMixin._refuse_if_busy`: s19_app/tui/app/file_load.py:675, s19_app/tui/app/patch.py:1586
- `section_body_text`: s19_app/tui/window_help.py:712

## Default value mismatch

- `s19_app/tui/a2l_parameter_picker.py:568` — `signature`: graph no default vs code default `None`
- `s19_app/tui/a2l_parameter_picker.py:568` — `a2l_data`: graph no default vs code default `None`
