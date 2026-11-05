# Inc 8 — E5 rulings (orchestrator, 2026-11-05)

Inputs: E5-code-review.md (FAIL, BLOCK-UNTIL F1, F2), E5-security.md (PASS-WITH-NOTES), E5-coverage-audit.md, E5-mutants.md (20/20 killed).

## Corrective pass (binding)

| Id | Source | Ruling |
|---|---|---|
| C-1 | F1 (MAJOR, impl) | `crc_config._number_field` must never raise. Bound the echo of a rejected value so it cannot recurse (catch `RecursionError`/`ValueError` from the serialisation and echo a fixed short form), keep the existing message text. RED first: one test at `parse_crc_config` (depth ~990 nested `init`) and one through the Operations dialog Execute (the app stays up, the reason shown is the malformed-config reason). |
| C-2 | F2 (MINOR, impl) + audit "EXT.14 order" | Reorder the external-step checks to R-FLOW-EXT.14 and the E3 addendum: log climb → log exists → output climb. Add the case and a test that pins the order (missing log + climbing output → the log's message). |
| C-3 | F4 (design-gap) + E4 §6 | R-FLOW-EXT.12 row text states the N-2(c) placement; test 12/10 pins the exact summary string. |
| C-4 | audit issue 1 | 9/3 reads the image named in run 3's WRITE-OUT summary, not `out.s19`. |
| C-5 | audit issue 5 | The record cases 9/1, 9/2, 9/9, 9/10, 9/13, 9/14 pin all 4 CRC bytes; 9/5 pins the CRC values, not only the addresses. |
| C-6 | audit issue 4 | Add the missing cases and tests for R-FLOW-CRC.4 (the first-three-errors join, exact text) and R-FLOW-CRC.3 (the refused branch). The other uncovered clauses the audit lists get a case each, or a `not-testable` ruling with its reason. |
| C-7 | audit issue 3 | The four "through keys" ATs drive the dialogs with `pilot.press` keys, not method calls; 001.17/2 asserts the later key's effect. Where a key route does not exist, the case is `partial` with that reason. |
| C-8 | F3 + audit issue 2 | 9/15 arm (b) cannot test the rebind while a junction back into the project is accepted (S8-2, Inc 9). Mark 9/15 and 12/10 `partial` for S-4 with that reason; S-4 is carried by arm (a). Not a code change in Inc 8. |
| C-9 | audit (records) | Repair 02-test-cases.md: coverage column per TCP-TRC-4 (no `gap` with passing full tests), the 21 cases with pre-ruling values (SR-1…SR-6, N-1, incl. 001.11/7(a) oracle `z` × 1 000 000), add rows 12/9 and 12/10, the 12 node ids that do not collect (add `ids=` to the parametrizes or cite the real ids), the 11 full → partial marks, the Count note. |

## Routed, not fixed here

| Id | Route |
|---|---|
| S8-1 (LOW, design-gap) relative output through an outside junction | Inc 9 (D15-18, manifest/path rules) |
| S8-2 (LOW, pre-existing) link back into the project accepted after `resolve()` | Inc 9: refuse such links or correct the docstring |
| S8-3 (INFO) 240-char cell clips the suffix | BACKLOG-CODE |
| S8-4 (INFO) rebind key uses the resolved name | BACKLOG-CODE |
| F5–F7 (NIT) repeated in-place append, `\uXXXX` echo, A2L ternary | BACKLOG-CODE |
| 9/15 skips off Windows | BACKLOG-CODE (a non-link arm for Linux) |

Re-review after the pass: the code reviewer checks F1, F2 only; the coverage auditor re-audits the changed cases only.
