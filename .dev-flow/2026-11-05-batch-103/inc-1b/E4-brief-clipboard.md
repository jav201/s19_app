# E4 implementation brief — os_clipboard_input.py only

Implement the approved design in `codewire/graph-inc1b.md`, `codewire/graph-clipboard.md`, `E2-interfaces.md` and `E3-rulings.md` **only in `s19_app/tui/os_clipboard_input.py`**. Do not edit app.py, tests, docs, other source files or git refs. Do not commit/push. Windows: static reading and `python -m py_compile` only; no pytest, app/probe, clipboard or import of `s19_app`.

Required contracts:
- Add pure `_copy_notice_text(text: str) -> str` in this module with exact ordinary/cut texts, final-LF exclusion and original grouped length.
- `_mirror_and_write_os_clipboard` preserves `original_text`, derives `capped_text` once, then checks NUL before any sink. NUL in capped payload: zero base/writer/OSC 52/process/helper/success effects, both clipboards unchanged, one 6-second warning `Clipboard copy refused — NUL cannot be represented in the Windows text clipboard.`, one WARNING `OS clipboard copy refused; payload contains NUL`, no raw/prefix/escaped payload logging. NUL solely after cap is allowed and yields the cut notice with original N.
- Non-NUL: one unbound toolkit base `App.copy_to_clipboard(app, capped_text)`, one default-executor writer awaited, success exactly one information result from `_copy_notice_text(original_text)`, failure only existing 6-second warning plus existing WARNING. Preserve best-effort mirror/notify behavior, writer budgets and all existing box action routes/cardinality. Never import app.py, re-enter override, call writer inline, or sanitize other C0/markup.
- Update the changed functions' docstrings to current Data Flow/Dependencies including the NUL refusal, all four box actions and app override as caller. Keep existing public contracts and comments accurate.

Run `python -m py_compile s19_app/tui/os_clipboard_input.py` and static checks for forbidden app imports and call cardinality. Do not claim runtime behavior. If blocked, write only `inc-1b/E4-deviations-clipboard.md` for orchestrator ruling. Return concise changes and checks.
