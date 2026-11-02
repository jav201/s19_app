# Inc 9b — E4 implementation notes (G-B, `s19_app/tui/app.py`)

Scope: only `s19_app/tui/app.py` edited. Interpreter: `<HOME>/anaconda3/envs/s19env/python.exe` (the file compiles with `-m py_compile`; the test suite was NOT run).

## Functions added / changed / deleted

### Changed

| Function | Line | Change |
|---|---|---|
| `action_load_file` | 7364 | Pushes `LoadDialog(mode="path", highlight=self.current_project, rows/verdict/preview = the three bound methods)`, callback `_handle_load_dialog`. |
| `action_load_project` | 7483 | No longer calls `list_projects`, no early return, no `No saved projects found.`; pushes `LoadDialog(mode="list", …)` with the same three callables and callback. |
| `check_action` | 8396 | New first test: `action in _LOAD_DIALOG_INERT_ACTIONS and any(isinstance(s, LoadDialog) for s in self.screen_stack)` → `False`. |
| `_route_load_project` | 7497 | Body unchanged; docstring `Used by` re-pointed to `_handle_load_dialog`. |
| `_handle_load_project` | 12045 | S9b-5 (paint `Project not found` name through `painted_names`); R2-N2 (listing via `_list_project_files` + `try/except OSError`, F-12); A9b-R2-6 (A2L admission via `_a2l_admission`); S9b-2 lstat regular-file gate on `project.json` placed before the reset and before `read_project_manifest`. |
| `list_projects` | 12500 | Step (5): `held = self._folder_holds_project(item)`; `False` skips, `True`/`None` lists. |
| `_typed_load_route` | 13324 | S9b-7: the inside-W `a2l`/`data` returns moved after the lstat walk, taken only when the last `lstat` is `S_ISREG`. Step 11 replaced with `_folder_holds_project`. |
| `_load_path_from_user_input` | 13468 | Unchanged (context; new caller `_handle_load_dialog`). |
| `_handle_load_dialog` | 13532 | Rewritten: `Optional[LoadChoice]` input; `None` → `_rehome_focus_after_load()` then return; log `kind=`/`value=`; dispatch `project`→`_route_load_project`, `workarea`→`_load_workarea_file`, `path`/`recent`→`_load_path_from_user_input(Path(value))`, all via `call_after_refresh`. |
| `load_from_path` | 13585 | LLR-172.1n (CR9-1): `typed`/`via_fallback` before the record step; `and not via_fallback` on the condition; INFO log when found only through the fallback. |
| `load_a2l_from_path` | 13680 | LLR-172.1n (same two lines on its record step); S9b-5 (`A2L loaded:` name through `painted_names`). |
| `_load_from_item` | 13929 | 3-line wrapper → `_load_workarea_file`. |

### Added

| Function / constant | Line |
|---|---|
| `_TYPED_REFUSAL_TOKENS` | 295 |
| `_RECENT_PROBLEM_STEPS` | 309 |
| `_LOAD_DIALOG_INERT_ACTIONS` | 317 |
| `_load_dialog_rows` | 7532 |
| `_load_dialog_verdict` | 7618 |
| `_load_dialog_preview` | 7657 |
| `_file_preview_marks` | 7783 |
| `_folder_holds_project` | 12620 |
| `_list_project_files` | 12671 |
| `_a2l_admission` | 12734 |
| `_load_workarea_file` | 13937 |

### Deleted

- `LoadFileScreen` / `LoadProjectScreen` imports and their two push sites (Q9). No references remain.

## Graph node → code location

- `action_load_file` → app.py:7364 (B01–B03).
- `action_load_project` → app.py:7483 (B04–B07a).
- `_handle_load_dialog` → app.py:13532 (B07–B16).
- `list_projects` → app.py:12500 (B17–B21).
- `_list_project_files` → app.py:12671 (B101–B102).
- `_a2l_admission` → app.py:12734 (B103).
- `_folder_holds_project` → app.py:12620 (B22).
- `_typed_load_route` → app.py:13324 (B23, B97).
- `load_from_path` → app.py:13585 (B24–B29).
- `load_a2l_from_path` → app.py:13680 (B30).
- `_load_dialog_rows` → app.py:7532 (B31–B47).
- `_load_dialog_verdict` → app.py:7618 (B48–B57).
- `_load_dialog_preview` → app.py:7657 (B58–B78, B98).
- `_file_preview_marks` → app.py:7783 (B80–B86).
- `_load_workarea_file` → app.py:13937 (B87–B88).
- `_load_from_item` → app.py:13929 (B89).
- `check_action` → app.py:8396 (B90–B92).
- module constants → app.py:295–319 (B93–B94).

## Deviations (with reasons)

1. **`validate_project_files` stays in the `.workspace` import.** The graph's import note says it "leaves the import", but it is still referenced at seven other call sites in `app.py` outside this slice (save flow ~10450/10630, `_activate_project_file` ~14085, `_sync_loaded_file_to_project` ~14145, `_sync_loaded_a2l_to_project` ~14255, and `load_a2l_from_path`'s project guard ~13797). Removing the name would raise `NameError` at runtime; `py_compile` does not catch it. Kept to avoid breaking untouched code paths.

2. **`_list_project_files` returns a 3-tuple**, not the 2-tuple in the node header. A9b-R3-4 ("also returns the 9a 'more than one MAC / A2L' error string, so the rule lives in one place; both callers use it") is an E3-rulings addendum and takes precedence over the graph line it contradicts. Return shape matches the 9a `validate_project_files`: `(data_files, a2l_files, error)`.

3. **S9b-2 gate placement in `_handle_load_project` is before `_reset_project_session()`,** not merely "before any manifest read". B99's oracle ("the session unchanged") requires the FIFO/link refusal to precede the reset; placing it only before `read_project_manifest` would have reset the session first. Behaviour (one `could not be read` status line, 0 opens, 0 raises) is otherwise as specified.

4. **A2L "not readable" log line changed.** The 9a arm logged `type(exc).__name__` for the lstat-`OSError` case only. With `_a2l_admission` returning the reason string (never the exception), the install now logs the reason word in that position. Log-only; no status line or reason string changed (A9b-R3-2 verbatim strings preserved).

5. **`_load_dialog_preview` project.json lstat:** a non-`FileNotFoundError` `OSError` (e.g. `PermissionError`) propagates to the outer `except OSError` and paints `could not be read` — consistent with `_handle_load_project`'s gate — rather than being treated as "absent". No example covers this exact arm; chosen for consistency.

## Open questions

- None blocking. The `validate_project_files` import note vs. reality (deviation 1) is worth a re-check at E4 close: either the note's "leaves the import" is dropped, or the seven remaining call sites are swept in Inc 12a.
