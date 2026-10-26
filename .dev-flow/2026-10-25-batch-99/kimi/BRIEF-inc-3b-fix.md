# Kimi brief — batch-99 Increment 3b · review fixes (code-reviewer F1–F4)

Read `BRIEF-COMMON.md` from the MAIN checkout (`C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-10-25-batch-99\kimi\BRIEF-COMMON.md`). Same worktree, `C:\Users\jjgh8\Github\s19_app-b99-inc3b` (uncommitted, on `f1ba70c`). Do not commit. Source budget: `flow_execution_service.py`, `project_gather_service.py`, `app.py` (3 of 4).

- **F1 [HIGH] — after one drift, every unchanged re-save adds another copy** (`project_gather_service.py:300-309` compares only against `<name>`; the B8 reuse in `workspace.py:541` looks only at the requested name). The reviewer's probe: after one edit to the common copy, each unchanged re-save adds `boost_1`, then `_2`, `_3`, `_4`. That breaks LLR-138.4 (an unchanged re-save makes no `_<N>` duplicates).
  - Fix in `project_gather_service.py`: before placing, look for an existing `stem(_N)?suffix` file in the destination that already holds the same bytes, and if one exists, return it as reused (`copied=False`). Do not edit `workspace.py`: it belongs to Inc 6, which is in flight.
  - Add a TC arm (a sub-node of TC-B99-13 or of the gather test): drift once, then two unchanged re-saves → exactly one `_1`, no `_2`.
  - Mutation: compare only against `<name>` → RED.
- **F2 [MEDIUM] — the D7 refusal is not on the status line.** LLR-155.5 requires it in the status line, and today it appears only in the run log (`app.py:2835-2844`, `flow_screens.py:3409`). Make the chain-set run handlers in `app.py` also set the status line (`#log_line_4`) to the outcome-first refusal (UX-C4), with lane names literal (UX-C10). Extend AT-B99-04's duplicate arm to assert the painted status line. Correct the packet §6 claim.
- **F3 [MEDIUM]** — two evidence hashes (`green-census-b97.txt`, `green-census-batch3.txt`) do not match the files on disk, and the packet says batch 3 "timed out at ~85%" while the file shows a full run (5 failed, 500 passed). Recompute all the hashes and correct the description. Classify the 5 failures against the batch baseline ledger (main checkout `PLAN.md`); they passed alone for the reviewer.
- **F4 [LOW]:**
  - (a) Extend the LLR-155.3 census to `write_text` / `write_bytes` onto existing final names; if `flow_persistence_service.py:1032` is a violator, record it as a declared exception for the backlog, not a fix.
  - (b) The UX-C10 test at `:2017` must assert painted text, not call `safe_text` itself.
  - (c) Fix the comment at `test_flow_chainset_b94.py:565`.

Run `tests/test_b99_staging.py`, `tests/test_project_gather.py`, `tests/test_flow_chainset_b94.py`, `tests/test_tui_flow_execution_b94.py`, `tests/test_b97_flow_execution.py`, `tests/test_address_census.py` and `tests/test_id_registry.py`. Run AT-B99-04 8 times. Update the packet ("Review round 1 fixes"). Finish with `HANDOFF-fix.md`, ending with `__KIMI_UNIT_DONE__` and the 5-line summary.
