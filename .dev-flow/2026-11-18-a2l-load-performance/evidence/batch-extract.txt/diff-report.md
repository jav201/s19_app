# Code-Wire extractor report

- Marks found: 23
- Graph nodes parsed: 26
- Real calls between marked nodes: 18
- Findings: 8 (6 drift, 2 info)
- Ambiguous call resolutions (a name matched several defs): 54
- Files that failed to parse: 1

Type normalisation: spaces and quotes dropped; `List/Dict/Tuple/Set` -> builtins; `X | None` and graph `X?` -> `Optional[X]`; graph `(Callable) A->B` -> `Callable[[A], B]`; graph `tuple(A a, B b)` -> `tuple[A, B]`. A bare graph container (`dict`) against a parameterised code type (`dict[str, Any]`) is info (loose match), not drift.

Call resolution is name-based (`f()`, `Class()` -> `__init__`, `self.m()`, `x.m()` -> top-level `m` or a marked method `m`); dynamic calls and callables passed as values are not seen. Tests excluded.

## Counts

| Kind | Count |
|---|---|
| Graph node without mark (no code yet) | 3 |
| Input type mismatch | 1 |
| Default value mismatch | 2 |
| Info: nodes replaced by a later graph (`--layered`) | 1 |
| Info: graph names the bare container only (loose match) | 1 |

## Real calls between marked nodes

| Caller | Callee | Sites |
|---|---|---|
| `A2LParameterPicker.set_parameters` | `describe_definitions` | s19_app/tui/a2l_parameter_picker.py:644 |
| `A2lPickerMixin.set_a2l_parameters` | `A2LParameterPicker.set_parameters` | s19_app/tui/screens_directionb/patch_editor/a2l_picker.py:55, s19_app/tui/screens_directionb/patch_editor/a2l_picker.py:62 |
| `CheckEditorPanel.set_a2l_parameters` | `A2LParameterPicker.set_parameters` | s19_app/tui/screens_directionb/check_editor.py:245, s19_app/tui/screens_directionb/check_editor.py:252 |
| `FileLoadMixin._a2l_attach_worker` | `FileLoadMixin._prepare_a2l_attach_snapshot` | s19_app/tui/app/file_load.py:959 |
| `FileLoadMixin._load_workarea_file` | `FileLoadMixin._start_load_worker` | s19_app/tui/app/file_load.py:1387 |
| `FileLoadMixin._prepare_a2l_attach_snapshot` | `describe_definitions` | s19_app/tui/app/file_load.py:1102, s19_app/tui/app/file_load.py:1103 |
| `FileLoadMixin._prepare_load_payload` | `FileLoadMixin._prepare_a2l_attach_snapshot` | s19_app/tui/app/file_load.py:1765 |
| `FileLoadMixin._start_a2l_load` | `FileLoadMixin._a2l_attach_worker` | s19_app/tui/app/file_load.py:916 |
| `FileLoadMixin._start_load_worker` | `FileLoadMixin._parse_loaded_file` | s19_app/tui/app/file_load.py:1912 |
| `FileLoadMixin._start_load_worker` | `FileLoadMixin._prepare_load_payload` | s19_app/tui/app/file_load.py:1942, s19_app/tui/app/file_load.py:1962 |
| `FileLoadMixin.load_from_path` | `FileLoadMixin._start_load_worker` | s19_app/tui/app/file_load.py:633 |
| `ProjectLoadMixin._handle_load_project` | `ProjectLoadMixin._prepare_project_load` | s19_app/tui/app/project_load.py:1425 |
| `_shared_with` | `_entry_overlaps` | s19_app/tui/a2l_definition.py:4127 |
| `_shared_with` | `_occupancy_candidates` | s19_app/tui/a2l_definition.py:4125 |
| `_shared_with` | `_pair_exempt` | s19_app/tui/a2l_definition.py:4129 |
| `describe_definition` | `describe_definitions` | s19_app/tui/a2l_definition.py:608 |
| `describe_definitions` | `_build_occupancy_index` | s19_app/tui/a2l_definition.py:875 |
| `describe_definitions` | `_shared_with` | s19_app/tui/a2l_definition.py:889 |

Top-level sites (no marked node above them):

- `A2lPickerMixin.set_a2l_parameters`: s19_app/tui/app/checks_diff.py:101, s19_app/tui/app/patch.py:1860
- `CheckEditorPanel.set_a2l_parameters`: s19_app/tui/app/checks_diff.py:101, s19_app/tui/app/patch.py:1860
- `FileLoadMixin._load_workarea_file`: s19_app/tui/app/file_load.py:1279
- `FileLoadMixin._parse_loaded_file`: s19_app/tui/app/file_load.py:1538, tools/e13/run.py:202
- `FileLoadMixin._start_a2l_load`: s19_app/tui/app/file_load.py:725, s19_app/tui/app/file_load.py:813
- `FileLoadMixin.load_from_path`: s19_app/tui/app/file_load.py:432, s19_app/tui/app/projects.py:250
- `LoadedStateMixin._apply_prepared_load`: docs/images/capture_readme_media.py:88
- `ProjectLoadMixin._handle_load_project`: s19_app/tui/app/project_load.py:562
- `describe_definition`: s19_app/tui/app/patch.py:393, s19_app/tui/app/patch.py:458

## Graph node without mark (no code yet)

- `s19_app/tui/app/file_load.py` — `FileLoadRequest`
- `s19_app/tui/app/project_load.py` — `ProjectLoadRequest`
- `s19_app/tui/app/project_load.py` — `PreparedProjectLoad`

## Input type mismatch

- `s19_app/tui/a2l_definition.py:4075` — `mask_of`: graph `Callable[[str], int|None]` vs code `Callable[[str], Optional[int]]`

## Default value mismatch

- `s19_app/tui/a2l_parameter_picker.py:590` — `a2l_data`: graph default `None (keyword-only)` vs code default `None`
- `s19_app/tui/a2l_parameter_picker.py:590` — `prepared_definitions`: graph default `None (keyword-only)` vs code default `None`

## Info: nodes replaced by a later graph (`--layered`)

- `graphs` — 2 replaced by a later graph: `describe_definitions`, `_shared_with`

## Info: graph names the bare container only (loose match)

- `s19_app/tui/a2l_definition.py:3801` — `mask_of`: graph `Callable` vs code `Callable[[str], Optional[int]]`

## Files skipped (parse error)

- `tools/mutation_harness.py`: f-string expression part cannot include a backslash (<unknown>, line 190)
