# Code Review — Increment 003b (batch-100, hotfix: the reset clears the paste buffer without marking the Patch Editor dirty)

| Field | Value |
|---|---|
| Reviewer | `code-reviewer`. I am independent of this code: I did not write the fix or the test. |
| Tree reviewed | Worktree `C:\Users\jjgh8\Github\s19_app-b100-inc3b`, branch `b100-inc3b` at `6d8631a`, with uncommitted changes (`git diff 6d8631a`: 3 files, +68/−10). `app.py` sha256 `f8c5efa0327c…` (equals the evidence headers). `screens_directionb.py` is LF in the work tree and the index is LF (`git ls-files --eol`: `i/lf w/lf`), so the evidence hash `47fd3bf24826…` is the work-tree bytes; a CRLF checkout of the same content hashes differently. I compared content with CR stripped: identical. I never edited the worktree. `git status` was unchanged afterwards, apart from `increment-003b.md`, which the orchestrator wrote. |
| Contract | `01-requirements.md` LLR-165.1, LLR-165.3. Ledger LED .55 (b) and LED .60 (LED .60 read from the MAIN checkout `C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-10-26-batch-100\01-requirements-ledger.md`). |
| Interpreter proof | s19env Python 3.11, Textual 8.2.8. Each run printed `s19_app.tui.app.__file__` from its own tree. Runs used `PYTHONPATH=<tree>`, `env -u NO_COLOR`, `PYTHONUTF8=1`, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONIOENCODING=utf-8` and `-p no:cacheprovider`. Scratch trees under `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-clde\a8feab43-c248-4ccb-86cf-122b894659b2\scratchpad\r3b\`: `base\` = `git worktree add --detach 6d8631a` plus the new test file; `mut\` = `6d8631a` plus `git apply` of the diff (content-identical to the worktree), with mutants copied in and the originals restored afterwards. Both worktrees were removed when I finished. |
| **Verdict** | **`PASS-WITH-NOTES`**: 0 HIGH, 0 MEDIUM, 3 LOW. |

## BLUF

The fix is correct and minimal. I confirmed by execution that it explains all five red batch-97 nodes. On `6d8631a`, after `fx_project` the next Patch Load stops on `LoadGuardScreen`. The modal keeps the focus on `load_guard_cancel`, so `#fx_run` can never be focused ("did not settle: Run focused"). On the fix tree the stack is `['Screen']`, the document has 6 entries and `#fx_run` takes the focus. `Widget.prevent` is the right tool here, and no other observer of the paste buffer's `Changed` loses anything. The new test is RED on base for the right reason, and the mutants are killed for the right reasons. The three LOW notes are about records and docstrings only.

## Scope reviewed

- `s19_app/tui/app.py:9393-9401` (`_reset_project_session`, the panel tail). I also read the whole function and its docstring, `:9257-9402`.
- `s19_app/tui/screens_directionb.py:5827-5841` (new `PatchEditorPanel.clear_paste_buffer`) and `:5581-5582` (the Used-by line). I also read `on_text_area_changed` `:5515-5553`, `_refresh_paste_gauge` `:5555-5598`, `mark_saved` / `mark_loaded` `:5806-5825` and the paste/edit-JSON button posts `:5710-5740`.
- `tests/test_b100_session_reset.py:932-974` (the new test). I also read `tests/b97_fixtures.py` `load_change_file` `:538-547` and `run_lanes` `:978-1000`, and `tests/test_b97_width.py` `_at_session` `:1484-1506` and `test_at_b97_16` `:1651-1693`.
- Textual 8.2.8 source: `MessagePump.prevent`, `post_message`, `Widget.check_message_enabled` (`widget.py:4663`), `_context.prevent_message_types_stack`, and the `TextArea.text` setter / `load_text`.
- All 10 files in `evidence/inc-3b/` (headers and tails).

## What I executed (evidence state: `executed`)

| # | Tree | Command / probe | Result |
|---|---|---|---|
| X1 | base `6d8631a` + new test | `pytest tests/test_b100_session_reset.py -k reset_leaves_the_patch_editor_clean` | **1 failed**: `AssertionError: a clean session raised the dirty-load question` (`app.screen` is `LoadGuardScreen`). RED for the claimed reason, and it matches `red-01`. |
| X2 | fix | the same node | **1 passed** |
| X3 | base | `test_b97_width.py::test_at_b97_16…` + `test_b97_chips_help.py::test_at_b97_14…` | **2 failed** (`did not settle: Run focused`; `NoMatches '#window_help_patch' on LoadGuardScreen()`), 3 passed |
| X4 | fix | the same nodes | **5 passed** |
| X5 | base | probe `_at_session(run_lanes_too=False)`, then `#fx_run.focus()` | `SCREEN LoadGuardScreen`, `STACK ['Screen','LoadGuardScreen']`, `PATCH_ENTRIES 0`, `RUN_FOCUSED False FOCUSED Button#load_guard_cancel`. This shows the mechanism: the guard modal swallows the Patch Load, and every later focus/tab step runs against the modal. |
| X6 | fix | the same probe | `SCREEN Screen`, `STACK ['Screen']`, `PATCH_ENTRIES 6`, `RUN_FOCUSED True` |
| X7 | fix | `test_b97_width.py -k "at_b97_15 or at_b97_24"` | **3 passed** |
| X8 | fix | `tests/test_b100_session_reset.py` (whole file) | **18 passed** |
| X9 | mut M1: `prevent` removed, the assignment kept | `-k "reset_leaves_the_patch_editor_clean or at_b100_03"` | **3 failed**: all three on `LoadGuardScreen`, the right reason |
| X10 | mut M3: `mark_loaded()` removed from the reset | the same | **2 failed** (at_b100_03 ×2: `timed out waiting for the clean '0 entries' subtitle`), **1 passed** (the new test; see F3) |
| X11 | mut M5 (mine): `clear_paste_buffer()` removed, `mark_loaded()` kept | the same | killed: at_b100_03 ×2 `timed out waiting for the paste buffer cleared by the reset`; the new test `assert buffer.text == ""` shows the leftover changeset text |

Probe noise: X5 and X6 end with a `PermissionError` while `TemporaryDirectory` is cleaned up, because the app's log file is still held on Windows. This comes after every printed line and does not affect the readings.

I did not re-execute the evidence's M2 (no gauge refresh) or the guard/census sets. I read their transcripts: M2 is killed by the heading assertion, and guards report 75 passed and census 87 passed.

## Questions asked of me

1. **Is `Widget.prevent` the right tool, and is it scoped to that buffer?** It is the right tool, but it is not scoped to the widget. In 8.2.8 the prevent stack is a `ContextVar` (`textual._context.prevent_message_types_stack`), so `buffer.prevent(...)` and `self.prevent(...)` are equivalent. Inside the `with`, *any* `TextArea.Changed` posted from the current task is dropped (`Widget.check_message_enabled` → `_is_prevented`). Messages and callbacks posted inside the block also carry the prevented set (`message_pump.py:517`, `:724`). This matters nothing here: the block holds exactly one synchronous assignment, the only message that assignment emits besides `Changed` is a `SelectionChanged`, and nothing in `s19_app` handles `SelectionChanged` (grep shows 0 hits). Observation only, no change asked.
2. **Other observers of the paste buffer's `Changed`.** A grep for `on_text_area_changed`, `TextArea.Changed` and `@on(TextArea` finds two handlers. `PatchEditorPanel.on_text_area_changed` (`screens_directionb.py:5515`) does the dirty flag (w2) plus the gauge/heading, and `clear_paste_buffer` repaints the gauge/heading itself. `SegmentSplitView.on_text_area_changed` (`segment_split_view.py:2154`) is filtered to `sje_manual`, so it is unaffected. `app.py` has no handler. `JsonHighlightTextArea` rebuilds its highlights on the base `_build_highlight_map` hook (`json_highlight.py:315-325`), not on `Changed`, so an empty buffer highlights correctly. The reset then calls `refresh_bindings()` synchronously, so binding checks see the empty buffer. No observer loses anything.
3. **Other caller paths with the old deferred race.** There are none. `call_after_refresh(panel.mark_loaded)` existed only in the reset, and it is gone. The other programmatic buffer write is `app.py:3943` (the JSON popup). It is *meant* to dirty the panel: it is followed by `parse_paste` → `mark_pasted()`. `_patch_editor_load` (`:5543-5547`) calls `mark_loaded()` synchronously and does not write the buffer. `_reset_project_session` still has one caller (`:9563`).
4. **Do the `test_b97_width` failures come from this mechanism?** Yes, executed (X3–X7). `_at_session` runs `fx_project` (the reset) and then `load_change_file`. On base that Load stays on the guard modal, so the document never loads (0 entries) and `run_lanes(key=True)` cannot focus `#fx_run`. at_b97_15 and at_b97_24 share `_at_session`. I saw them green on the fix tree; on base I rely on `red-02` (main checkout at `6d8631a`).
5. **Test quality.** RED on base for the right reason (X1). M1, M2 and M5 are killed by the new test. M3 is killed only by at_b100_03 (F3).

## Findings

### F1 — The new test cites the wrong LLR  [Severity: LOW]
- **What:** The docstring reads `TC-B100-10 (LLR-165.1, LED .55(b))`, but TC-B100-10 is LLR-165.3's executed verification (`-k tc_b100_10`). LED .60 is filed under `Requirement: LLR-165.3`, and the module header (`:14`) maps TC-B100-10 to LLR-165.3.
- **Where:** `tests/test_b100_session_reset.py:937`
- **Why it matters:** the trace runs from code to R. A reader following the citation lands on the reset-seam LLR, not on the requirement that owns the dirty-marker clause, and LED .60 is not cited at all.
- **Suggested fix:** `"""TC-B100-10 (LLR-165.3, LED .55(b), LED .60), hotfix 3b: …`

### F2 — The `_reset_project_session` docstring does not name the new call  [Severity: LOW]
- **What:** The Data Flow bullet (`app.py:9300-9305`) still describes only `mark_loaded()`. `Uses:` (`:9308-9310`) lists neither `PatchEditorPanel.clear_paste_buffer` nor `mark_loaded`. The inline comment (`:9393-9398`) is correct; only the structured docstring lags.
- **Where:** `s19_app/tui/app.py:9300-9310`
- **Why it matters:** the repo's docstring convention lists Uses/Used-by in both directions. The new method's `Used by` side is half-wired: the method's docstring names `app.py`, but `app.py`'s `Uses` does not name the method.
- **Suggested fix:** in Data Flow, write "``PatchEditorPanel.clear_paste_buffer()`` then ``mark_loaded()`` (LED .55(b), LED .60): …". Add `PatchEditorPanel.refresh_entries` / `clear_paste_buffer` / `mark_loaded` to `Uses:`.

### F3 — The new test does not pin the `mark_loaded()` half of the fix by itself  [Severity: LOW]
- **What:** With `mark_loaded()` dropped (M3), the new test passes. It starts from a fresh session that was never dirty, so after a prevented clear nothing remains to clear. Only `test_at_b100_03` (load over unsaved work) kills M3.
- **Where:** `tests/test_b100_session_reset.py:934-974`; evidence `mut-M3_no_mark_loaded.txt`; my X10.
- **Why it matters:** the coverage is real but split. If the hotfix's verification is ever narrowed to `-k reset_leaves_the_patch_editor_clean`, the synchronous `mark_loaded` is unguarded. The gauge text is also unasserted (only the heading is). This is acceptable because both are painted by the same `_refresh_paste_gauge` call.
- **Suggested fix:** no code change required. Record in the packet that M3 is killed by `at_b100_03`, and keep that node in the hotfix's verification set. Optionally, add `assert "●" not in subtitle` right after the reset, before the Load, to catch a deferred clear.

## Simplicity / reuse / conventions

- The fix stays small. It adds one public method that reuses `_refresh_paste_gauge`, and replaces two lines at the call site. It adds no abstraction or flag. Keeping `clear_paste_buffer` separate from `mark_loaded` is correct: the dirty-flag writers (w1–w4) stay in one census, and clearing the buffer is not a writer.
- The `clear_paste_buffer` docstring is in the short style of its neighbours `mark_saved` / `mark_loaded`. The `_refresh_paste_gauge` Used-by line was updated.
- No security or coverage hand-off needed.

## Verdict

- [ ] OK to advance
- [x] **`PASS-WITH-NOTES`**: 0 HIGH; F1–F3 LOW, recommended rather than blocking
- [ ] Block

## Evidence checklist

- ✓ Diff read in full: `app.py:9393-9401`, `screens_directionb.py:5581-5582, 5827-5841`, `test_b100_session_reset.py:932-974`.
- ✓ Correctness pass: prevent scope (context-var), other `Changed` observers, other deferred call sites, an already-empty buffer (assigning `""` is harmless), the headless no-panel branch (unchanged, `except` path).
- ✓ Simplicity pass: one method, no speculative parameters.
- ✓ Reuse checked: `_refresh_paste_gauge` reused; no duplicate clear helper exists.
- ✓ Tests reviewed for intent: X1 RED for the right reason; M1, M2 and M5 killed by the new test; M3 by at_b100_03 (F3).
- ✓ Verdict explicit: `PASS-WITH-NOTES`, no HIGH.

## §4b `Independent review` cell

`code-reviewer` — **PASS-WITH-NOTES** (0 HIGH). The fix and test were read in full against LLR-165.3, LED .55 (b) and LED .60, and verified by execution on a `6d8631a` scratch tree and the fix tree. The new node is RED on base on `LoadGuardScreen` and GREEN on the fix. A probe shows the 5 batch-97 nodes come from this mechanism: on base the guard modal swallows the Patch Load (0 entries, focus held on `load_guard_cancel`, so "Run focused" never settles); on the fix there are 6 entries and `#fx_run` takes the focus. at_b97_14/15/16/24 pass on the fix, and the session-reset file is 18/18. Mutants: M1 (no prevent) and M5 (no clear) are killed by the new test; M3 (no `mark_loaded`) only by at_b100_03. `prevent` is context-scoped rather than widget-scoped, which is harmless here: there is a single synchronous assignment and no `SelectionChanged` handlers. No other `Changed` observer loses anything, and no deferred race remains elsewhere. No HIGH to resolve. LOW notes: F1, the test cites LLR-165.1 where it should cite LLR-165.3 / LED .60; F2, the `_reset_project_session` docstring's Data Flow / Uses omit `clear_paste_buffer`; F3, keep at_b100_03 in the hotfix's verification set because it alone kills M3.
