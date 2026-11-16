# E4 implementation brief — app.py only

Implement the approved design in `codewire/graph-inc1b.md`, `codewire/graph-app.md`, `E2-interfaces.md`, `E3-rulings.md`, `01-requirements.md` and `02-test-cases.md` **only in `s19_app/tui/app.py`**. Do not edit tests, docs, other source files or git refs. Do not commit/push. Windows: static reading and `python -m py_compile` only; no pytest, app/probe, clipboard or import of `s19_app`.

Required contracts include, without substituting older sketches:
- Bind `from textual.actions import SkipAction`; empty `copy_to_clipboard` raises it before worker creation. Non-empty schedules `_mirror_and_write_os_clipboard(self, original_text)` once via inherited `run_worker`, never super/direct writer/notify/slice.
- Early `_right_click_text` selection/full-name extraction, text-box/ancestor exclusion, A2L `_a2l_row_key_to_tag`, MAC Rich Text `.plain` with only known glyph prefix removal, `out_of_bounds=False` requirement.
- `_right_gesture` five-field transient state: optional snapshot, offset, screen, widget, valid. MouseDown captures without copying; every changed-offset MouseMove invalidates permanently, including exit-return; valid same-context button-3 MouseUp consumes/clears then copies once; every event forwards exactly once through `await super().on_event(event)`.
- `_CopyRowTable(DataTable)` before `A2LTagTable`; A2LTagTable inherits it, `_compose_screen_a2l` unchanged, MAC constructs it. Valid non-left row click moves cursor/highlight and prevents only RowSelected/jump; padding prevents default without cursor/RowSelected; left click unchanged.
- `action_help_quit` shared by q and Ctrl+C fallback, busy existing `_QuitQuestionScreen`, idle `_CopyQuitScreen` body B with `_answer_quit`; modal no-second-dialog preserved. `_CopyQuitScreen` inherits without methods.
- BINDINGS `('q','help_quit','Quit')`, visible q Quit unchanged, Ctrl+Q/palette Quit stay `action_quit`; preserve exactly one `PaletteEntry("Quit", "quit")` through the current `_build_palette_entries` projection, with no duplicate palette command.
- Preserve existing names, ids, columns, Textual dispatch, docstring/type conventions, source comments/docstrings that remain accurate. Update changed docstrings to current behavior. Keep app orchestration-only where practical.

Run `python -m py_compile s19_app/tui/app.py` and a static AST/symbol census. Do not claim runtime behavior. If any graph contract cannot be implemented literally, write only `inc-1b/E4-deviations-app.md` with the exact deviation and stop that part for orchestrator ruling. Return a concise change summary and static checks.
