# Code-Wire extractor report

- Marks found: 6
- Graph nodes parsed: 6
- Real calls between marked nodes: 3
- Findings: 0 (0 drift, 0 info)
- Ambiguous call resolutions (a name matched several defs): 55
- Files that failed to parse: 0

Type normalisation: spaces and quotes dropped; `List/Dict/Tuple/Set` -> builtins; `X | None` and graph `X?` -> `Optional[X]`; graph `(Callable) A->B` -> `Callable[[A], B]`; graph `tuple(A a, B b)` -> `tuple[A, B]`. A bare graph container (`dict`) against a parameterised code type (`dict[str, Any]`) is info (loose match), not drift.

Call resolution is name-based (`f()`, `Class()` -> `__init__`, `self.m()`, `x.m()` -> top-level `m` or a marked method `m`); dynamic calls and callables passed as values are not seen. Tests excluded.

## Counts

| Kind | Count |
|---|---|

## Real calls between marked nodes

| Caller | Callee | Sites |
|---|---|---|
| `A2lPickerMixin.set_a2l_parameters` | `A2LParameterPicker.set_parameters` | s19_app/tui/screens_directionb/patch_editor/a2l_picker.py:43 |
| `CheckEditorPanel.set_a2l_parameters` | `A2LParameterPicker.set_parameters` | s19_app/tui/screens_directionb/check_editor.py:224 |
| `FileLoadMixin._start_a2l_load` | `FileLoadMixin._a2l_attach_worker` | s19_app/tui/app/file_load.py:802 |

Top-level sites (no marked node above them):

- `A2lPickerMixin.set_a2l_parameters`: s19_app/tui/app/checks_diff.py:101, s19_app/tui/app/patch.py:1860
- `CheckEditorPanel.set_a2l_parameters`: s19_app/tui/app/checks_diff.py:101, s19_app/tui/app/patch.py:1860
- `FileLoadMixin._start_a2l_load`: s19_app/tui/app/file_load.py:625, s19_app/tui/app/file_load.py:713
