# Inc 12b — E3 round 1 orchestrator rulings

Inputs:
- `E3-architect.md`: PASS-WITH-NOTES, 1 MAJOR · 1 MINOR · 2 NIT, plus DF-1…DF-13.
- `E3-security.md`: PASS-WITH-NOTES, 1 MAJOR · 3 MINOR · 3 NIT.

Rule: prefer removing a feature to guarding it. The orchestrator authorises edits to `interfaces-12b.md` wherever a row says "interfaces".

| Id | Ruling | Design effect |
|---|---|---|
| S12b-01 | **Accept.** The failure arm of every action handler (Save above all) sets `_quit_pending = False` before `end_busy`, so a failure keeps the app running and the failure line is the last log line. Re-word the error arms of HLR-177c and LLR-177.4c to match. Add an example: `q`, `y`, then the Save fails → the app runs, the failure line and toast are shown, and the entries are kept. | P-1, P-2; draft |
| S12b-02 | **Accept.** Remove `{exc}` from the two new arms (the Q4 rollback arm and the worker's outer catch); the traceback goes to the log (SEC7-5). `_on_project_saved` paints every line and the toast through `safe_text(...).plain`. | P-1 |
| S12b-03 | **Accept.** The Save worker returns facts only. `_on_project_saved` composes the committed tail on the main thread. | P-1 |
| S12b-04 | **Accept.** While a `project_load` run exists, `#patch_paste_text` is read-only. This is the same refusal family as E1 Q3. Add an example. | P-2 (refusal); P-1 seam |
| S12b-05 | **Accept.** Pass a deep-copied document snapshot to the unchanged `write_change_document`, and drop `_write_editor_document`. | P-1 |
| S12b-06 | **Accept.** The progress `total` is computed before `mkdir`. | P-1 |
| S12b-07 | **Accept as a design rule** written into interfaces: after `mkdir`, every cross-thread call in the Save worker stays inside the rollback `try`. | interfaces |
| A12b-01 | **Accept.** In each of the 7 test files whose `_flush` is fixed pauses, `_flush` calls the one Q6 helper (`wait_for_complete()` + 2 pauses): 7 one-line edits. The tester re-takes the census by "polls on a condition", not by helper name. | census; tester note |
| A12b-02 | **Accept.** Re-word draft §C.2's LLR-176.1l sentence: the failure handler is the end; `_busy_fail` is posted only after a main-thread handler raises. | draft |
| A12b-03 | **Accept: remove `go_if_idle` and C12b-08** (P2-6 reversed). The window it guards cannot be reached in this app. | P-2; E2-rulings note |
| A12b-04 | **Accept.** Remove `PreparedProjectLoad.recorded`, `PreparedProjectLoad.a2l_context` and `A2LAttachResult.copy_seconds`. | interfaces; P-1, P-2 |
| DF-1 … DF-9 | **Apply the binding E2 rows** to the interfaces and the prototypes. The row ids are in E3-architect.md:<br>- DF-1: no `_finish_session_action` / `_fail_session_action` / `final_line` (P2-1).<br>- DF-2: non-exclusive groups (P2-4).<br>- DF-3: an `except BaseException` guard (PR-5).<br>- DF-4…6: toast `(title, text)`, `recorded_document`, no `unrecorded` (PR-1/2/3).<br>- DF-7: retire `_load_a2l_data_with_cache` and re-pin the spy at `test_b100_project_homes.py:1996` (PR-6).<br>- DF-8: the out-list form (PR-7).<br>- DF-9: `sync_project` (P2-2). | interfaces; P-1, P-2 |
| DF-10 … DF-13 | **Apply the draft updates:**<br>- LLR-177.3e: add `save_doc`, `execute_scope` and the 4 continuations;<br>- LLR-177.1f: add the variant-id assertion;<br>- add the P2-8 and P2-9 notes;<br>- census 184 / 26, and the trace names. | draft |

Then update the decomposition lines, the TC rows and the draft ledger entry for every id added or changed, naming the ids one by one.

## Round 2 — E3 closed; addenda for E4

Inputs: `E3-architect.md` §Round 2 PASS-WITH-NOTES (0 MAJOR; 3 MINOR, 2 NIT); `E3-security.md` §Round 2 PASS-WITH-NOTES (S12b-01 closed; 1 MINOR, 3 NIT). E3 is closed. These rows bind the implementers (I) and the tester (T), override any graph line they contradict, and are corrected in the records at close.

| Id | Addendum | Who |
|---|---|---|
| R2-01 | `_on_project_saved` keeps the base's two-form outcome line: with a variant, `… (variant '<id>')`; with none, the base no-variant form (`app.py:10827-10834`). Add a no-variant example arm (an A2L-only save). | I, T |
| R2-02 = S12b-R2-1 | Textual's attribute is `read_only`. Clear it whenever `end_busy` removes a `project_load` run, whether or not other runs remain. C12b-55 drives a real typed key, not an attribute read. | I, T |
| R2-03 | `end_busy(key, gen, outcome)` has no `final_line` (glossary :17). E1-scope slice rows A3/A9/C9 are stale; the prototypes govern. | I; close |
| R2-04 | **Revert:** 12a's existing `_start_load_worker` keeps `exclusive=True`. DF-2 covers only the three new 12b workers. | I |
| R2-05 | The "159 W" wording is stale; the census is classified by "a poll on a condition" (A12b-01). | close |
| S12b-R2-2 | The Save commit arm's step (8) paints its tail lines through `safe_text(...).plain`. | I |
| S12b-R2-3 | **Declared.** A committed save whose manifest check reports MISMATCH still exits under a confirmed quit. The files are on disk and the next load reports it. | risks |
| S12b-R2-4 | 12a's `_handle_load_error` also clears `_quit_pending` before its end, for consistency. | I |
