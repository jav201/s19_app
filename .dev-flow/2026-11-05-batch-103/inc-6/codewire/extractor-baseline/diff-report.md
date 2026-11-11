# Code-Wire extractor report

- Marks found: 13
- Graph nodes parsed: 13
- Real calls between marked nodes: 7
- Findings: 0 (0 drift, 0 info)
- Ambiguous call resolutions (a name matched several defs): 5
- Files that failed to parse: 0

Type normalisation: spaces and quotes dropped; `List/Dict/Tuple/Set` -> builtins; `X | None` and graph `X?` -> `Optional[X]`; graph `(Callable) A->B` -> `Callable[[A], B]`; graph `tuple(A a, B b)` -> `tuple[A, B]`. A bare graph container (`dict`) against a parameterised code type (`dict[str, Any]`) is info (loose match), not drift.

Call resolution is name-based (`f()`, `Class()` -> `__init__`, `self.m()`, `x.m()` -> top-level `m` or a marked method `m`); dynamic calls and callables passed as values are not seen. Tests excluded.

## Counts

| Kind | Count |
|---|---|

## Real calls between marked nodes

| Caller | Callee | Sites |
|---|---|---|
| `A2LParameterPicker.include_names` | `A2LParameterPicker._row_cells` | s19_app/tui/a2l_parameter_picker.py:1031 |
| `A2LParameterPicker.set_parameters` | `A2LParameterPicker._refresh_full_name` | s19_app/tui/a2l_parameter_picker.py:823 |
| `A2LParameterPicker.set_parameters` | `A2LParameterPicker._row_cells` | s19_app/tui/a2l_parameter_picker.py:822 |
| `CheckEditorPanel._on_a2l_parameter_picker_bulk_add_requested` | `CheckEditorPanel._open_parameter_bulk_add` | s19_app/tui/screens_directionb.py:7888 |
| `CheckEditorPanel.set_a2l_parameters` | `A2LParameterPicker.include_names` | s19_app/tui/screens_directionb.py:7312 |
| `CheckEditorPanel.set_a2l_parameters` | `A2LParameterPicker.set_parameters` | s19_app/tui/screens_directionb.py:7307 |
| `PatchEditorPanel.set_a2l_parameters` | `A2LParameterPicker.set_parameters` | s19_app/tui/screens_directionb.py:5390 |

Top-level sites (no marked node above them):

- `A2LParameterPicker._refresh_full_name`: s19_app/tui/a2l_parameter_picker.py:598, s19_app/tui/a2l_parameter_picker.py:672, s19_app/tui/a2l_parameter_picker.py:739
- `A2LParameterPicker._row_cells`: s19_app/tui/a2l_parameter_picker.py:590, s19_app/tui/a2l_parameter_picker.py:917
- `A2LParameterPicker.include_names`: s19_app/tui/screens.py:1020, s19_app/tui/screens_directionb.py:7357
- `CheckEditorPanel.set_a2l_parameters`: s19_app/tui/app.py:7914, s19_app/tui/app.py:7935
- `PatchEditorPanel.__init__`: s19_app/tui/app.py:4931
- `PatchEditorPanel._use_highlighted_parameter`: s19_app/tui/screens_directionb.py:5929
- `PatchEditorPanel.set_a2l_parameters`: s19_app/tui/app.py:7914, s19_app/tui/app.py:7935
- `describe_definitions`: s19_app/tui/a2l_definition.py:607
- `parse_parameter_list`: s19_app/tui/screens.py:1019
