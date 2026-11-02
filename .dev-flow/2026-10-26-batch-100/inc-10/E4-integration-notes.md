# Inc 10 E4 — integration notes

The tree is GREEN on the targeted runs with **0 source edits at integration**: both implementers' code matched the graph, and the 4 failures met were all on the test side (3 test defects, 1 orchestrator ruling). Base `741cc07` plus the working tree of `b100-inc10`. `s19_app.__file__` = `<HOME>\Github\s19_app-b100-inc10\s19_app\__init__.py` in every transcript header. Every run used `env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=.` with `LOCALAPPDATA` set to a scratch folder. The real `%LOCALAPPDATA%\s19_app` was not created.

## 1. Failures met

First run of the new file (scratch, not kept as evidence): 49 passed, 3 failed. The full guards run then showed 1 more failure.

| # | Test | Cause | Who was wrong | Fix |
|---|---|---|---|---|
| F1 | `test_tc_b100_45_modal_imports_nothing_from_the_app` | The import census matched `from textual.app import ComposeResult`, because its regex `(^|\.)(app|services|workspace)(\.|$)` accepts any module path ending in `app`. The graph (Q1-6) bans names from `s19_app.tui.app`, `.services` and `.workspace` only. | test | The census now skips absolute imports outside `s19_app` (`node.level == 0` and the module does not start with `s19_app`). The negative control still holds: `painted_names` comes from `.services`, so a screen that calls it is still caught. |
| F2 | `test_tc_b100_12_cancelled_question_rehomes_the_focus` | The test asserted C08's landing (`patch_editor_panel` after `n`). The code follows `_rehome_focus_after_load()`, which keeps a visible, healthy `Input`, so the focus stayed on `patch_entry_address_input`. | test / graph (C08 contradicts LLR-166.1) | Orchestrator ruling 7, applied (see §3). |
| F3 | `test_at_b100_15_load_over_unsaved_work_asks_one_question_per_route` | The second `add_and_apply` (the `v` route, after project `PV`) never added its entry. A diagnostic run showed the address field holding `0x8000007Cx8000007C` and the status `invalid literal for int() with base 0`. In these inputs `ctrl+a` moves the cursor to the start instead of selecting, so `ctrl+a, delete` removed one character and the typed text was prepended to the first add's text. | test (the driver) | `add_and_apply` clears both inputs by value before typing. This is the existing pattern of `tests/test_b100_document.py:125-129`, whose comment records the same `ctrl+a` behaviour. No assertion changed. |
| F4 | `tests/test_id_registry.py::test_tc607_scanned_corpus_matches_the_declared_bound` (guards run, attempt 1) | The new test module raises the scanned count from 230 to 231. The guard asks for the bound to move in the same change. | expected test-side bump | `EXPECTED_SCANNED_TEST_FILES = 231`, with a history line naming `tests/test_b100_load_question.py`. The failed attempt is kept as `guards-01-attempt1-failed.txt`. |

No failure was on the code side. No graph change is needed beyond C08 (ruling 7).

## 2. Implementer deviations

Both implementers declared none. I checked the diff against `interfaces-10.md`, `proto-10-app.md`, `proto-10-dialog.md` and the round-2 addenda of `E3-rulings.md`. **Accepted, with no correction:**

- **G-A (`screens.py`, `screens_directionb.py`).**
  - The class attributes, the signature, the compose tree and its ids are as Q1/Q2 specify.
  - The labels are `rich.text.Text` (P-GA10-1), and the title and body use `markup=False`.
  - The `_dismissed` guard is the first line of `_close` (Q-5).
  - `is_dirty` is a read-only property with no setter, placed after `mark_pasted`.
  - The `_dirty` comment states the five writers.
  - `styles.tcss` is unchanged (Q-6). The layout arms of LLR-174.2r pass at 99, 118 and 220 columns.
- **G-B (`app.py`).**
  - The seam, the guard and the composer follow S-b, S-e and the composer text exactly. `None` is treated as cancel by truthiness.
  - The four leaves hold the seam (S-d), and the router is unchanged.
  - The variant stamp is inside `go` (LLR-174.3d).
  - `check_action` adds `ConfirmQuestionScreen` to the whole-stack test.
  - **S10-01 / S10-05.** The reads, `check_project_files`, the A2L read and the install check all run before `_reset_project_session()`. Only `_declared_regions` (a write) follows it. No moved line references a name created after the reset.
  - **S10-02 / A10-R2-3.** The dropdown guard pushes `LoadGuardScreen`. Its cancel arm writes the same status line as the Load button and resets `#patch_doc_file_select` to `Select.NULL`.
  - **S10-04.** The 3 lines go through `painted_names`.
  - **Q2 / Q-7.** The interim block is gone, and `_reset_project_session -> None`.
  - **LLR-174.1c.** The private `_dirty` read in `_handle_save_dialog` is replaced by `is_dirty`.

## 3. Orchestrator rulings applied (binding)

1. The draft's `tests/test_b100_confirm.py` is corrected at close to `tests/test_b100_load_question.py`.
2–6, 8–10. Accepted as the tester wrote them (`E4-tester-notes.md` §5).
7. **C08 vs LLR-166.1: LLR-166.1 governs.** I changed `test_tc_b100_12_cancelled_question_rehomes_the_focus` to assert the re-home rule:
   - The Patch window arm: after `n`, the focus is still on `patch_entry_address_input`.
   - The Workspace arm: after `escape`, the focus is still on `files_list`.
   - In both arms, `_rehome_focus_after_load` was called exactly once. An instance spy wraps the real method.
   - The spy keeps a negative control that can go RED. With the corrected landing, a cancel branch that skips the re-home would leave the same focus and pass. The count turns that mutation (M36) RED.
   - **C08 is to be recorded as corrected in the graph at close**: "after `n`, the focus follows `_rehome_focus_after_load()`; a visible, healthy input keeps the focus".

## 4. Seam rulings for the orchestrator to confirm

- **SR-1 (C08 oracle).** The corrected C08 test reads a private method call count (the spy on `_rehome_focus_after_load`) as well as the focused id. Confirm that this oracle is acceptable. Without it, ruling 7's landing cannot detect a skipped re-home.
- **SR-2 (C60 / S10-04 coverage gap, found while writing the mutant table).** No test covers C60. The tester's requirement map and its "examples not turned into tests" table both leave it out. The code paints `Variant not found`, `Variant file missing` and `No supported files in project` through `painted_names`, but nothing goes RED if that scrub is dropped (mutants M63, M64, M70). Decide whether E5 adds the C60 test or records the gap.
- No other seam ruling: the graph was neither wrong nor silent on any failure met.

## 5. Final runs (operator scope override, 2026-10-31)

| Transcript (`.dev-flow/2026-10-26-batch-100/evidence/inc-10/`) | Scope | Result | State |
|---|---|---|---|
| `green-01-new.txt` | `tests/test_b100_load_question.py` (52 nodes) | **52 passed**, 0 failed, 421.6 s | executed |
| `green-02-repinned.txt` | the 5 re-pinned nodes (`test_b100_session_reset.py` ×4 nodes, `test_b99_editor_image.py` ×1) | **5 passed**, 0 failed, 56.0 s | executed |
| `guards-01-attempt1-failed.txt` | `test_id_registry.py`, `test_b99_staging.py`, `test_engine_unchanged.py`, `test_b100_load_dialog.py` | 177 passed, **1 failed** (F4) | failed (kept) |
| `guards-01.txt` | the same 4 files, after the bump | **178 passed**, 0 failed, 740.5 s | executed |

- The Windows-only arm `test_tc_b100_46_unreadable_a2l_project_after_yes_keeps_the_work` ran (this is Windows) and passed inside `green-01`.
- No timing arm failed in any run. Every failure above was deterministic.
- The full suite and whole touched modules are `not-run`. They are deferred to the batch-end battery by the operator override.
- Test-file sha256[:16] at the final runs:
  - `test_b100_load_question.py` d80dfa1c70db283e;
  - `test_b100_session_reset.py` 27e0036d37d03008;
  - `test_b99_editor_image.py` 8147ee6a6f99702d;
  - `test_id_registry.py` 60add5fa3d6fead5.

## 6. Source sha256[:16] (unchanged by E4)

| File | sha256[:16] |
|---|---|
| `s19_app/tui/screens.py` | 58186f0551f9b02e (as G-A reported) |
| `s19_app/tui/screens_directionb.py` | c53fd29b14f5c8ed (as G-A reported) |
| `s19_app/tui/app.py` | ac5b417b8c3e6b47 |

All three source files and all edited test files remain CRLF (0 bare LF).

## 7. Files changed at E4

- `tests/test_b100_load_question.py`: F1, F2 (ruling 7), F3.
- `tests/test_id_registry.py`: F4.
- New: `inc-10/E4-integration-notes.md` (this file) and `inc-10/E4-mutant-candidates.md` (83 rows; the gaps are listed at its end).

## Orchestrator rulings on the seam items (2026-10-31)
- **SR-1 confirmed:** the C08 oracle reads the focused widget plus a spy count on `_rehome_focus_after_load` (1 call).
- **SR-2:** E5 adds the C60 test (S10-04's painted lines) in the corrective pass, so mutants M63, M64 and M70 are killed then.
