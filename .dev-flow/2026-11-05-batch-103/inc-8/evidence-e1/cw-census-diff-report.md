# Code-Wire extractor report

- Marks found: 28
- Graph nodes parsed: 28
- Real calls between marked nodes: 12
- Findings: 10 (8 drift, 2 info)
- Ambiguous call resolutions (a name matched several defs): 9
- Files that failed to parse: 0

Type normalisation: spaces and quotes dropped; `List/Dict/Tuple/Set` -> builtins; `X | None` and graph `X?` -> `Optional[X]`; graph `(Callable) A->B` -> `Callable[[A], B]`; graph `tuple(A a, B b)` -> `tuple[A, B]`. A bare graph container (`dict`) against a parameterised code type (`dict[str, Any]`) is info (loose match), not drift.

Call resolution is name-based (`f()`, `Class()` -> `__init__`, `self.m()`, `x.m()` -> top-level `m` or a marked method `m`); dynamic calls and callables passed as values are not seen. Tests excluded.

## Counts

| Kind | Count |
|---|---|
| Input type mismatch | 5 |
| Output type mismatch | 3 |
| Info: graph names the bare container only (loose match) | 2 |

## Real calls between marked nodes

| Caller | Callee | Sites |
|---|---|---|
| `A2lPickerMixin._on_a2l_parameter_picker_view_changed` | `A2lPickerMixin._apply_a2l_layout` | s19_app/tui/screens_directionb/patch_editor/a2l_picker.py:221 |
| `ChangeService.add_symbol_entry` | `ChangeService._entry_index` | s19_app/tui/services/change_service.py:1315 |
| `ChangeService.add_symbol_entry` | `ChangeService._push_history` | s19_app/tui/services/change_service.py:1323 |
| `PatchEditorPanel._show_tab` | `PatchEditorPanel._refresh_inspector_subtitle` | s19_app/tui/screens_directionb/patch_editor/panel.py:728 |
| `PatchEditorPanel.on_mount` | `PatchEditorPanel._refresh_inspector_subtitle` | s19_app/tui/screens_directionb/patch_editor/panel.py:622 |
| `PatchMixin._prefill_patch_editor` | `A2lPickerMixin.set_a2l_parameters` | s19_app/tui/app/patch.py:1613 |
| `PatchMixin._refresh_patch_history_view` | `ChangeService.rows` | s19_app/tui/app/patch.py:569 |
| `PatchMixin._refresh_patch_history_view` | `EntriesMixin.refresh_entries` | s19_app/tui/app/patch.py:568 |
| `PatchMixin._refresh_patch_history_view` | `PatchMixin._strip_source_map` | s19_app/tui/app/patch.py:572 |
| `decode_definition` | `display_text` | s19_app/tui/a2l_definition.py:2906 |
| `describe_definition` | `describe_definitions` | s19_app/tui/a2l_definition.py:608 |
| `encode_definition` | `decode_definition` | s19_app/tui/a2l_definition.py:4069 |

Top-level sites (no marked node above them):

- `A2lPickerMixin.set_a2l_parameters`: s19_app/tui/app/checks_diff.py:101
- `ChangeService._entry_index`: s19_app/tui/services/change_service.py:1243, s19_app/tui/services/change_service.py:1361, s19_app/tui/services/change_service.py:1392
- `ChangeService._push_history`: s19_app/tui/services/change_service.py:1248, s19_app/tui/services/change_service.py:1365, s19_app/tui/services/change_service.py:1395, s19_app/tui/services/change_service.py:1524, s19_app/tui/services/change_service.py:1587, s19_app/tui/services/change_service.py:1652
- `ChangeService.rows`: s19_app/tui/app/loaded_state.py:676, s19_app/tui/app/patch.py:1535, s19_app/tui/app/patch.py:290, s19_app/tui/app/project_load.py:1030
- `EntriesMixin.refresh_entries`: s19_app/tui/app/loaded_state.py:675, s19_app/tui/app/patch.py:1534, s19_app/tui/app/patch.py:289, s19_app/tui/app/project_load.py:1029
- `PatchEditorPanel.__init__`: s19_app/tui/app/compose_screens.py:540
- `PatchEditorPanel.set_image_mem_map`: s19_app/tui/app/loaded_state.py:407
- `PatchMixin._refresh_patch_history_view`: s19_app/tui/app/patch.py:1000, s19_app/tui/app/patch.py:726, s19_app/tui/app/patch.py:761
- `PatchMixin._report_change_result`: s19_app/tui/app/patch.py:1499, s19_app/tui/app/patch.py:192, s19_app/tui/app/patch.py:213, s19_app/tui/app/patch.py:249, s19_app/tui/app/patch.py:261, s19_app/tui/app/patch.py:416, s19_app/tui/app/patch.py:861, s19_app/tui/app/patch.py:986
- `PatchMixin._strip_source_map`: s19_app/tui/app/patch.py:1538, s19_app/tui/app/patch.py:293
- `decode_definition`: s19_app/tui/a2l_definition.py:3149
- `describe_definitions`: s19_app/tui/a2l_parameter_picker.py:609
- `encode_definition`: s19_app/tui/a2l_definition.py:4288, s19_app/tui/a2l_definition.py:4372

## Input type mismatch

- `s19_app/tui/screens_directionb/patch_editor/entries.py:115` — `mem_map`: graph `object` vs code `Union[Mapping[int, int], None, _Unset]`
- `s19_app/tui/screens_directionb/patch_editor/entries.py:115` — `document`: graph `object` vs code `Union['PatchDocumentView', _Unset]`
- `s19_app/tui/screens_directionb/patch_editor/a2l_picker.py:212` — `event`: graph `object` vs code `A2LParameterPicker.ViewChanged`
- `s19_app/tui/app/patch.py:1002` — `loaded`: graph `object` vs code `Optional[LoadedFile]`
- `s19_app/tui/a2l_definition.py:3355` — `value`: graph `float` vs code `int | float`

## Output type mismatch

- `s19_app/tui/app/patch.py:1002` — graph `object` vs code `Optional[Mapping[int, int]]`
- `s19_app/tui/a2l_definition.py:2804` — graph `object` vs code `Decoded | Refusal`
- `s19_app/tui/a2l_definition.py:3970` — graph `object` vs code `Encoded | Refusal`

## Info: graph names the bare container only (loose match)

- `s19_app/tui/services/change_service.py:3144` — output: graph `list` vs code `list[ChangeEntryRow]`
- `s19_app/tui/a2l_definition.py:611` — output: graph `dict` vs code `dict[str, Definition]`
