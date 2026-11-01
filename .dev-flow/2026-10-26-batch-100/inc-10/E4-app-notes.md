# Inc 10 — E4 G-B implementation notes (`s19_app/tui/app.py`)

Group: G-B. File edited: `s19_app/tui/app.py` only. `screens.py` and
`screens_directionb.py` were NOT touched (G-A owns them; their working-tree
diffs are the concurrent implementer's).

## Functions added

| Function | Lines | Notes |
|---|---|---|
| `QuestionKind` (module alias) | 325 | `Literal["image", "attach", "project"]` exactly as interfaces-10.md |
| `UnsavedItem` (module alias) | 328 | `tuple[Literal["image", "document", "flow"], str]` |
| `S19TuiApp._confirm_then_load` | 7526–7592 | the one load seam |
| `S19TuiApp._load_would_lose` | 7594–7648 | the guard |
| `S19TuiApp._load_question_text` | 7650–7728 | the composer |

## Functions changed

| Function | Lines | Change |
|---|---|---|
| `S19TuiApp.on_patch_editor_panel_change_file_selected` | 6154–6222 | dropdown guard: `panel.is_dirty` → push `LoadGuardScreen` (accept `_patch_editor_load`; cancel sets status + resets `#patch_doc_file_select` to `Select.NULL`, A10-R2-3); clean → load at once |
| `S19TuiApp._route_load_project` | 7720–7766 | signature `name: str`; body wrapped in local `go` passed to `_confirm_then_load("project", name, go)` |
| `S19TuiApp._handle_select_variant` | 8153–8227 | two refusal lines paint through `painted_names` (S10-04); stamp + `load_from_path` moved into local `go` passed to `_confirm_then_load("image", descriptor.path.name, go)` |
| `S19TuiApp.check_action` | 8639–8672 | whole-stack test now `(LoadDialog, ConfirmQuestionScreen)` |
| `S19TuiApp._handle_save_dialog` | 10063 (edit at ~11187) | `panel._dirty` → `panel.is_dirty`; comment sentence removed |
| `S19TuiApp._reset_project_session` | 12001–12150 | signature `-> None`; `Returns` paragraph dropped; `discarded_unsaved = len(...)` and `return discarded_unsaved` deleted; Data Flow bullet removed |
| `S19TuiApp._handle_load_project` | 12283–12582 | see restructure below |
| `S19TuiApp._load_path_from_user_input` | 13705–13785 | `typed = Path(str(path).strip().strip('"'))`; `a2l`/`data` arms route through `_confirm_then_load`; `data` MAC test `typed.suffix.lower() in MAC_EXTENSIONS` |
| `S19TuiApp._load_workarea_file` | 14186–14233 | `exists()` guard kept; kind `attach` for `(MAC_EXTENSIONS | A2L_EXTENSIONS)` (case-folded) else `image`; 9b body in local `go` passed to `_confirm_then_load` |

## Graph node → code location

- C01 (type aliases, 5 call sites): aliases at 325/328; call sites 7765, 8216, 13746, 13752, 14231.
- `_confirm_then_load` (S-b): 7526–7592.
- `_load_would_lose` (S-e): 7594–7648.
- `_load_question_text` (composer): 7650–7728.
- `_route_load_project` seam: 7720–7766.
- `_load_path_from_user_input` seam: 13705–13785.
- `_load_workarea_file` seam: 14186–14233.
- `_handle_select_variant` seam: 8153–8227.
- `check_action` (S-f): 8639–8672.
- `_handle_load_project` (S10-01, S10-05, S10-04): 12283–12582.
- `_reset_project_session` (Q-7): 12001–12150.
- `_handle_save_dialog` (LLR-174.1c app half): edit at ~11187.
- `on_patch_editor_panel_change_file_selected` (S10-02, A10-R2-3): 6154–6222.

## `_handle_load_project` restructure (S10-01 / S10-05 / S10-04 / Q-2)

New order after the manifest lstat gate:

1. `variant_set = build_variant_set(...)`, `manifest = read_project_manifest(...)`
   (reads).
2. `problems = check_project_files(project_dir, manifest)` + log (S10-05, read).
3. `if a2l_problem is not None: problems.append(a2l_problem)`.
4. `recorded = ...` read.
5. `a2l_context` read + unreadable arm (read, before reset).
6. `install = choose_install_set(...)`; all-`None` refusal paints
   `No supported files in project: {painted_names([name])}` (S10-04) and
   returns BEFORE the reset.
7. `self._reset_project_session()` (now returns `None`).
8. `self._declared_regions = ...` (the one write kept after the reset).

Deleted: the `if discarded_unsaved:` interim `Closed the Patch Editor document`
block (ruling Q2) and the `discarded_unsaved =` binding.

## Deviations

None. Every graph node and every example I could execute statically or with a
pure stub was followed. The composer outputs were verified by calling the
unbound method against a stub (C17/C18/C19/C20/C21/C22/C26 all match exactly).

One non-code note: the census C05's clause (c) ("`load_from_path`'s own worker
start") was read as the existing `_start_load_worker(copied)` inside
`load_from_path`; no code change was needed there. All direct call sites of the
four loaders / `_handle_load_project` were confirmed to be inside a `go`
closure passed to `_confirm_then_load`, or inside `_handle_load_project`.

## Verification performed

- `python -m py_compile s19_app/tui/app.py` → OK (s19env interpreter).
- `import s19_app.tui.app` → OK (no NameError/ImportError).
- Composer stub check → C17/C18/C19/C20/C21/C22/C26 strings match the graph
  character for character.
- Line endings preserved: file remains CRLF throughout (0 bare-LF lines).
- `grep panel._dirty` in app.py → 0 matches (C52 census arm).
- `grep discarded_unsaved` / `Closed the Patch Editor document` → 0 matches.

## Open questions

None.
