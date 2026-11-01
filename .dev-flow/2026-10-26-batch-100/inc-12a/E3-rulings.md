# Inc 12a — E3 round 1 orchestrator rulings

Inputs:
- `E3-architect.md`: PASS-WITH-NOTES, 0 MAJOR · 7 MINOR · 2 NIT.
- `E3-security.md`: PASS-WITH-NOTES, 2 MAJOR · 2 MINOR · 2 NIT.

Rule: prefer removing a feature to guarding it. The orchestrator authorises edits to `interfaces-12a.md` wherever a row says "interfaces".

| Id | Ruling | Design effect |
|---|---|---|
| S12a-01 | **Accept.** The one `resolve_input_path` catch, already present on the 9b branch, widens to `(OSError, ValueError, RuntimeError)` → `('refuse', 'not found')`. S-j is rewritten to describe the post-9b code; it must never narrow the catch. LLR-172.5i: the NUL arms become regression arms. The requirement's RED arm is EACCES / ENAMETOOLONG, forced by monkeypatching `Path.exists` to raise `PermissionError` / `OSError(ENAMETOOLONG)` so it runs on Windows too. | G-B; interfaces S-j; draft LLR-172.5i |
| S12a-02 | **Accept.** `_paint_status_text` (the seam's one writer of `#status_text`) and the outcome log line both write `safe_text(...).plain`, so ESC and C0 never reach the terminal. `set_file_status` writes through the same writer. Add an ESC arm to LLR-176.1r: a file named `a\x1b]0;x\x07.s19` → the painted line and the log line hold no `\x1b`. | G-A; draft LLR-176.1r |
| S12a-03 | **Accept.** The pick-time re-check (LLR-172.6b/.6c) runs inside `go`, after the Inc 10 question is answered and immediately before the open. It does not run before the question. | G-B `_load_workarea_file`; examples |
| S12a-04 | **Accept.** Add an AST rule: `begin_busy` is called only from `_busy_begin_action`. Add a hostile-name arm driven through `load_from_path`. | draft LLR-176.1r threshold; tester |
| S12a-05 | **Record for 12b (seam text).** One exclusive worker group per busy key. A worker cancelled before it starts runs no `finally`, so the canceller must call `end_busy` itself. Write this into interfaces §"What Inc 12b consumes". | interfaces |
| S12a-06 | **Accept.** Worker guards use `except BaseException:` + `end` + re-raise on the failure path, plus one normal end on success. No unconditional `finally` cross-thread call after success. | G-A |
| A12a-01 | **Accept.** After Inc 10 there are 6 shared refusal sentences in `_handle_load_project`. Drop the exact-count assertion in favour of "every refusal sentence comes from `_TYPED_REFUSAL_TOKENS`". | G-B; draft LLR-172.5k |
| A12a-02 | **Accept.** The project-load begin sits immediately before `build_variant_set`, after every refusal (`project.json` check included). Add an example arm: an unreadable `project.json` → the refusal line, no `failed` end, 0 begins. | G-A; example |
| A12a-03 | **Accept.** The A2L final status line keeps 9b's `painted_names` scrub (`A2L loaded: <painted>`). | G-A |
| A12a-04 | **Accept.** `end_busy` always writes the action's final log line. The generation check governs only the indicator (spinner, elapsed, `#status_text`). | G-A; interfaces Q-3 text |
| A12a-05 | **Accept.** In the file-load worker, `_sync_loaded_file_to_project` runs before `end_busy`. This removes the file-load half of F-7. | G-A |
| A12a-06 | **Accept (simplify).** Keep one stored file-state line, not the three slots `restore` / `pending` / `final_line`. P-4 is superseded, and F-4 disappears with it. | G-A; interfaces |
| A12a-07 | **Record for 12b.** The "quit after the action ends" check belongs inside `end_busy`, so every exit path reaches it. Write this into interfaces §"What Inc 12b consumes". | interfaces |
| A12a-08 | **Accept.** Move `copied.stat()` out of the guard, before the worker starts. | G-A |
| A12a-09 | **Accept.** The project load reports "Parse the A2L" only when the project has an A2L. | G-A |

Then update the decomposition lines, the TC rows and the draft ledger entry for every id added or changed, naming the ids one by one.

## Round 2 — E3 closed; addenda for E4

Inputs: `E3-security.md` §Round 2 PASS-WITH-NOTES (all round-1 findings closed; 4 NIT); `E3-architect.md` round 1 PASS-WITH-NOTES (0 MAJOR). E3 is closed. These rows bind the implementer (I) and the tester (T) and override any graph line they contradict.

| Id | Addendum | Who |
|---|---|---|
| S12a-R2-1 | The vanish check before the question catches `OSError` (not only `FileNotFoundError`) and falls through to `go`, which refuses safely. | I |
| S12a-R2-2 | Worker guards are `except BaseException` + end + re-raise on the failure path, plus one normal end on success (S12a-06). Wherever interfaces S-e (:63, :92-97, :147) still says `finally`, the S12a-06 ruling wins. | I |
| S12a-R2-3 | The ESC/BEL arm of LLR-176.1r is declared "not run on Windows (the name cannot be created), never passed". It runs on the Linux CI. | T |
| S12a-R2-4 | LLR-172.5i's negative control means `_typed_load_route`. The sweep row at :309 means "inside `go`, after the question". Text fixes, applied at close. | — |
