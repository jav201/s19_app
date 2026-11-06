# Inc 4 — E5 rulings (orchestrator, 2026-11-05)

Inputs: E5-code-review.md (PASS-WITH-NOTES; F1–F3 MINOR, F4–F5 NIT; SR-1 edit to docs/requirements/review/ judged minimal and correct — forwarded to the requirements session 2026-11-05), E5-security.md (PASS-WITH-NOTES; E5S4-1 LOW, E5S4-2…5 INFO), E5-coverage-audit.md (11/22 changed; 4 full → partial), E5-mutants.md (DeepSeek: 15/15 killed, with an unmutated baseline run).

## Corrective pass (binding)

| Id | Ruling |
|---|---|
| C-1 | F1 + audit: R-CHG-SYM.13/2 gains a no-A2L arm that fails if the `index_built` fix is reverted (call counter); prove with that revert as a mutant. |
| C-2 | F2 + audit 11/3: assert exactly 7 applied and 0 blocked; open the Reports screen through its key/route (or partial with reason). |
| C-3 | F3: R-CHG-SYM.12/2 asserts `0 error(s)` before its M-14 premise. |
| C-4 | Audit partials: 9/4 asserts the document is replaced (a no-op confirm turns RED); 11/2 drives Execute scope by keys and asserts the exact line ending (or partial with reason); 13/1 checks the symbol spelling of every entry. |
| C-5 | Audit records: the 7 expected results that no longer match (10/4 lists the R-TUI-058.9 line; 10/3 and 058.9/3 list the pinned lines; 058.9/1 "document unchanged"; 9/1, 9/5, 12/2 drive labels); Coverage column uses `covered`/`partial`; add the missing row R-CHG-SYM.13/3 (A-7 / OR-2: the cost symbol resolution adds to the whole-document confirm ≤ 1.0 s) and move its test out of 13/1; tester notes' `_at_1000_` names updated. |
| C-6 | Audit: the 6 clauses without a checking test get one or a not-testable ruling; the 8 owed black-box ATs (six session reads, Execute scope, report run) are driven by keys and dialogs where a route exists, else partial with the reason. |
| C-7 | Timing: R-CHG-SYM.13/3 gets 5 samples on the LAN host (serial lane, quiet host) against the 1.0 s bound. |
| C-8 | F4/F5 NITs: CODE-CHANGES Totals line left to the requirements session (forwarded); R-CHG-SYM.10/4 arm pins the exact ending. |

## Routed to BACKLOG-CODE (append, batch-101 style)

| Id | Item |
|---|---|
| S4-1 / E5S4-1 | `validate_project_files` accepts a link or reparse point named as the project's A2L (lstat refusal + test) — routed with Inc 9 (S8-1/S8-2). |
| E5S4-3 (pre-existing) | Collision check `validate.py:45` is O(n²): 10 000 entries 7.6 s, ~12 min at the 100 000 ceiling — sort-and-sweep. |
| T-02 | Still open after Inc 4 (needs `check.py`, a 5th file). T-03 closed (superseded by D9-7). |
| `check.py:278` | Stale docstring mention of the deleted headless entry point. |
| tc1802 / b100 waits | `tc1802` fails on clean clones (reads an untracked prototype file — Inc 14 re-bodies it); b100 host-load flakes. |

Runs: the LAN laptop host (the LAN Linux host; account and address redacted at E5 corrective); LAN host 2 is not answering ssh.
