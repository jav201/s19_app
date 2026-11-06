# Inc 14 — E5 rulings (orchestrator, 2026-11-05)

Inputs: E5-code-review.md (PASS-WITH-NOTES, F1…F8), E5-security.md (BLOCK-UNTIL E5-1 for SECURITY.md only; `gh-pvr.txt` = `{"enabled":false}` at 2026-11-05T23:42:44Z), E5-coverage-audit.md (59 covered, 5 partial, 4 conflict, 1 not-testable).

## Corrective pass (binding)

| Id | Ruling |
|---|---|
| C-1 | F1 + audit R-WHELP.12/2: the control-presence test scans only the window's own container and matches whole control labels (no prefix match: `Goto 0xADDR` does not stand for `Goto`). Prove with a mutant that moves a control to another window → RED. |
| C-2 | Audit partials 13/2, README.4/3, RELNOTE.1/1, GUIDE.1/9: tie each assertion to its place (the right constant per folder; the `extract`/`split_by_segment` row; the two paragraphs whole; the named bullets). Each becomes `full` or stays `partial` with its reason. |
| C-3 | SR-1 in the records: the capture-note text of the requirement, ruling D-5 and cases GUIDE.1/1, /4, /7, /8 follow graph I-5 (no closing parenthesis; `:` and what the capture shows). Case 12/1 says 8 sections. |
| C-4 | The Result column keeps the flow's values (`verified (linux, int-NN)` / `failed` / `not_run`) — the audit's `executed` is not adopted. The three supporting files that ran in no Inc 14 run (`test_tui_checks_view`, `test_map_click_chain`, `test_b100_load_question`) run in the final run. |
| C-5 | Cases 21/2 and 011/2 cite test nodes, not modules. The image-load cases state that `load_selected_file` reaches the same load code as the worker (Tests column note). |
| C-6 | The nine uncovered clauses get a case each or a `not-testable` ruling with its reason (e.g. "SECURITY.md ships in the 1.0.0 release" → batch-end evidence). |
| C-7 | Black-box: open help with `?` on each window whose section changed and compare the painted text with the pinned copy; open the legend with `k` and read the Map keys line. `F1` is n/a (no binding). |
| C-8 | F2: the DOSSIER F-28 mark says what 1.0.0 does: the CRC block names the cause when it refuses a Designer template; it does not read Designer templates. F3…F8: fix the CHANGELOG CRLF wording, use one key spelling, refresh the stale test docstrings (incl. E5-2), make the vacuous control real, keep README wrapping as the file's style, N-2 says three tests. E5-4: records cite `evidence/inc-14/`. |
| C-9 | SECURITY.md hold-out (E5-1): the branch keeps SECURITY.md, its three `test_r_doc_security_*` tests and README row `:429`; the orchestrator removes exactly that group at merge if the setting is still off. `readme_4_2` stays (it checks the CHANGELOG link). Record the group in 04-validation later. |

Runs: LAN Linux host only (operator rule). After the pass: the mutant table (DeepSeek) and a re-audit of the changed cases.
