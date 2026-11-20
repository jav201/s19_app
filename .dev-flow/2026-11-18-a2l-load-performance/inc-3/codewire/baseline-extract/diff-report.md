# Code-Wire extractor report

- Marks found: 12
- Graph nodes parsed: 12
- Real calls between marked nodes: 7
- Findings: 0 (0 drift, 0 info)
- Ambiguous call resolutions (a name matched several defs): 19
- Files that failed to parse: 0

Type normalisation: spaces and quotes dropped; `List/Dict/Tuple/Set` -> builtins; `X | None` and graph `X?` -> `Optional[X]`; graph `(Callable) A->B` -> `Callable[[A], B]`; graph `tuple(A a, B b)` -> `tuple[A, B]`. A bare graph container (`dict`) against a parameterised code type (`dict[str, Any]`) is info (loose match), not drift.

Call resolution is name-based (`f()`, `Class()` -> `__init__`, `self.m()`, `x.m()` -> top-level `m` or a marked method `m`); dynamic calls and callables passed as values are not seen. Tests excluded.

## Counts

| Kind | Count |
|---|---|

## Real calls between marked nodes

| Caller | Callee | Sites |
|---|---|---|
| `FileLoadMixin._load_workarea_file` | `FileLoadMixin._start_load_worker` | s19_app/tui/app/file_load.py:1033 |
| `FileLoadMixin._prepare_load_payload` | `enrich_tags_and_render` | s19_app/tui/app/file_load.py:1357 |
| `FileLoadMixin._start_load_worker` | `FileLoadMixin._parse_loaded_file` | s19_app/tui/app/file_load.py:1496 |
| `FileLoadMixin._start_load_worker` | `FileLoadMixin._prepare_load_payload` | s19_app/tui/app/file_load.py:1520 |
| `FileLoadMixin.load_from_path` | `FileLoadMixin._start_load_worker` | s19_app/tui/app/file_load.py:534 |
| `ProjectLoadMixin._handle_load_project` | `ProjectLoadMixin._prepare_project_load` | s19_app/tui/app/project_load.py:1400 |
| `ProjectLoadMixin._install_prepared_project` | `ProjectLoadMixin._reset_project_session` | s19_app/tui/app/project_load.py:1613 |

Top-level sites (no marked node above them):

- `FileLoadMixin._load_workarea_file`: s19_app/tui/app/file_load.py:944
- `FileLoadMixin._parse_loaded_file`: s19_app/tui/app/file_load.py:1184
- `FileLoadMixin.load_from_path`: s19_app/tui/app/file_load.py:353, s19_app/tui/app/projects.py:250
- `ProjectLoadMixin._handle_load_project`: s19_app/tui/app/project_load.py:542
- `enrich_tags_and_render`: s19_app/tui/app/a2l_view.py:810, s19_app/tui/app/patch.py:2083, s19_app/tui/services/compare_service.py:305, s19_app/tui/services/flow_execution_service.py:399, s19_app/tui/services/variant_execution_service.py:2553
