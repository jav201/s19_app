# Inc 9a — E4 app-side notes (G2, `s19_app/tui/app.py`)

Only `s19_app/tui/app.py` was edited (CRLF preserved). No test run, no other source touched.
Compile check: `s19env python -m py_compile s19_app/tui/app.py` → OK.

## Functions changed / added (line numbers are post-edit)

| Function | Status | Line |
|---|---|---|
| `refresh_files` | changed | 7302 |
| `_route_load_project` | unchanged (new caller only) | 7449 |
| `_handle_load_project` | changed | 11675 |
| `list_projects` | unchanged (new callers only) | 12096 |
| `_typed_load_route` | NEW | 12754 |
| `_load_path_from_user_input` | changed (dispatcher) | 12899 |
| `load_from_path` | changed | 12999 |
| `load_a2l_from_path` | changed | 13081 |

Imports changed:
- `pathlib`: added `PurePath` (line 8).
- `.workspace` import: added `list_workarea_files` (line 277) and `record_recent_source` (line 279).

## Graph node -> code location

- `refresh_files` (HLR-172b, LLR-172.4/.4a/.4b/.4c, LLR-172.6/.6a, AT-B100-13):
  `app.py:7302-7326`. `list_workarea_files(self.workarea)`; per `Path`,
  `ListItem(Label(safe_text(painted_names([p.name]))))` with `entry.data = p.name`;
  log `Workarea refreshed. files=%d` over `len(files)`. `WORKAREA_TEMP` and
  `glob`/`is_file` no longer build the list here.
- `load_from_path` (HLR-172, LLR-172.1a/.1d/.1e/.1f/.1i/.1k/.1l/.1.3, AT-B100-12):
  `app.py:12999`. Record step at `13057-13060`: after the `copy_done` log and
  before `set_progress(50, ...)`, `if not contained_in_workarea(normalized, self.workarea):
  if not record_recent_source(normalized): logger.warning(...)`. No try/except.
- `load_a2l_from_path` (HLR-172, LLR-172.1a/.1d/.1e/.1i):
  `app.py:13081`. Same step at `13124-13127`, after the copy try/except and
  before `self.refresh_files()`.
- `_typed_load_route` (HLR-172a, LLR-172.5/.5a-.5f/.5h):
  `app.py:12754-12897`. Steps 0-11 implemented; returns
  `("project", name) | ("data", "") | ("a2l", "") | ("refuse", reason)`.
- `_load_path_from_user_input` (HLR-172a, LLR-172.5/.5a-.5f/.5h, LLR-172.1d, AT-B100-12):
  `app.py:12899-12966`. Dispatcher: `project` -> `_route_load_project(value)`;
  `a2l`/`data` -> existing loaders with the raw `path`; `refuse` -> one status
  line from the six-reason table, then the typed-load-refused warning.
- `_handle_load_project` (HLR-172a, LLR-172.5g, LLR-171.4e/.4f):
  `app.py:11675`. Listing step at `11708-11741`: after `exists()`, before
  `validate_project_files`/reset. `list_projects()` (OSError -> the existing
  `could not be read` row), `normcase` match (none -> `not a project` /
  `pick a project in the list`), match -> `name = match`,
  `project_dir = self.workarea / name`.
- `_route_load_project` (HLR-172a, LLR-172.5): `app.py:7449`, unchanged; the
  typed dispatcher is its new caller (Q3).
- `list_projects` (LLR-172.5/.5b/.5g): `app.py:12096`, unchanged; new callers
  are `_typed_load_route` (step 9) and `_handle_load_project`.

## Deviations

1. **`_typed_load_route` step (7), empty `parts` (the work area itself).**
   The graph text ("the last lstat must be a folder, else not a supported
   file") does not say what to do when there is no `lstat` at all (`W`, `W\`).
   The example pins `W` / `W\` -> `("refuse", "not a project")` ("`parts` is
   empty"). Implemented: the `S_ISDIR` check runs only when `last_stat is not
   None`; with empty `parts` the flow falls to step (8) `len(folder_parts) != 1`
   -> `not a project`. Closest thing to the graph; matches every pinned example.

2. **`_handle_load_project` listing-`OSError` arm log line.**
   The graph does not state a log line for the `list_projects()` `OSError`
   branch (only the status text and the return). Added
   `logger.warning("Project load refused (could not be read): %r", name)` to
   stay consistent with the sibling refusals. Status text matches the existing
   `could not be read` row character for character.

3. **`PROJECT_MANIFEST_NAME` vs literal `"project.json"`.**
   In `_typed_load_route` step (11) the manifest probe is written
   `folder / PROJECT_MANIFEST_NAME` (value `"project.json"`, already imported
   and used the same way by `_handle_load_project`) instead of the literal
   `folder / "project.json"` in the graph. Identical value, no behaviour
   change; kept for file consistency.

No silent divergence. The six dispatcher status lines reproduce the
"Status lines" table character for character (em-dash `—`, exact tokens).

## Open questions

- `list_projects` is called once by `_typed_load_route` and again by
  `_handle_load_project` for a typed project path (two listings per typed
  project load). The graph names both as callers and only notes a cost of
  "one listing … per typed project path or project load"; left as specified.
- G1's `list_workarea_files` / `record_recent_source` are not yet in
  `workspace.py` at the time of this edit; the module imports them. The app
  compiles (`py_compile`) but will not import until G1 lands.
