# Code-Wire extractor report

- Marks found: 12
- Graph nodes parsed: 12
- Real calls between marked nodes: 6
- Findings: 6 (6 drift, 0 info)
- Ambiguous call resolutions (a name matched several defs): 9
- Files that failed to parse: 0

Type normalisation: spaces and quotes dropped; `List/Dict/Tuple/Set` -> builtins; `X | None` and graph `X?` -> `Optional[X]`; graph `(Callable) A->B` -> `Callable[[A], B]`; graph `tuple(A a, B b)` -> `tuple[A, B]`. A bare graph container (`dict`) against a parameterised code type (`dict[str, Any]`) is info (loose match), not drift.

Call resolution is name-based (`f()`, `Class()` -> `__init__`, `self.m()`, `x.m()` -> top-level `m` or a marked method `m`); dynamic calls and callables passed as values are not seen. Tests excluded.

## Counts

| Kind | Count |
|---|---|
| Parameter in code, not an input in graph | 3 |
| Input type mismatch | 1 |
| Output type mismatch | 2 |

## Real calls between marked nodes

| Caller | Callee | Sites |
|---|---|---|
| `A2LParameterPicker.set_parameters` | `describe_definitions` | s19_app/tui/a2l_parameter_picker.py:608 |
| `PatchMixin.on_patch_editor_panel_action_requested` | `PatchMixin._report_change_result` | s19_app/tui/app/patch.py:1499, s19_app/tui/app/patch.py:193, s19_app/tui/app/patch.py:214, s19_app/tui/app/patch.py:250, s19_app/tui/app/patch.py:262 |
| `decode_values` | `display_text` | s19_app/tui/a2l_definition.py:2905 |
| `describe_definition` | `describe_definitions` | s19_app/tui/a2l_definition.py:608 |
| `encode_values` | `decode_values` | s19_app/tui/a2l_definition.py:4291 |
| `encode_values` | `display_text` | s19_app/tui/a2l_definition.py:2905 |

Top-level sites (no marked node above them):

- `A2LParameterPicker.set_parameters`: s19_app/tui/screens_directionb/check_editor.py:223, s19_app/tui/screens_directionb/patch_editor/a2l_picker.py:40
- `ChangeService._push_history`: s19_app/tui/services/change_service.py:1247, s19_app/tui/services/change_service.py:1321, s19_app/tui/services/change_service.py:1363, s19_app/tui/services/change_service.py:1393, s19_app/tui/services/change_service.py:1522, s19_app/tui/services/change_service.py:1585, s19_app/tui/services/change_service.py:1650
- `PatchEditorPanel.__init__`: s19_app/tui/app/compose_screens.py:540
- `PatchMixin._refresh_patch_history_view`: s19_app/tui/app/patch.py:1001, s19_app/tui/app/patch.py:727, s19_app/tui/app/patch.py:762
- `PatchMixin._report_change_result`: s19_app/tui/app/patch.py:417, s19_app/tui/app/patch.py:862, s19_app/tui/app/patch.py:987

## Parameter in code, not an input in graph

- `s19_app/tui/a2l_parameter_picker.py:568` — parameter `rows: Sequence[dict]` not in graph
- `s19_app/tui/a2l_parameter_picker.py:568` — parameter `signature: object` not in graph
- `s19_app/tui/a2l_parameter_picker.py:568` — parameter `a2l_data: Optional[dict]` not in graph

## Input type mismatch

- `s19_app/tui/app/patch.py:94` — `event`: graph `object` vs code `PatchEditorPanel.ActionRequested`

## Output type mismatch

- `s19_app/tui/a2l_parameter_picker.py:568` — graph `None` vs code `bool`
- `s19_app/tui/screens_directionb/patch_editor/panel.py:468` — constructor node: graph `None` vs class `PatchEditorPanel`
