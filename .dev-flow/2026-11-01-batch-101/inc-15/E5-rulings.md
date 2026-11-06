# Inc 15 — E5 rulings (orchestrator, 2026-11-06)

Inputs: `E5-code-review.md` (code-reviewer, **PASS-WITH-NOTES**; it also carried the security lens — no separate security reviewer, because the increment changes no product code and no product surface; the reviewer checked evidence redaction, Windows isolation and tmp-only writes) and `E5-coverage-audit.md` (qa-reviewer: 26 cases, 23 full/covered/verified, 2 partial, 1 not run; 3/26 = 11.5 % departures beyond the E1→E5 mark move). No BLOCKER/HIGH/MAJOR is open. Rulings:

| Id | Ruling | Why |
|---|---|---|
| C-1 | Move every case's marks in `02-test-cases.md` to the audited values (E1 gap/not_run → audited coverage/result). | The record must show the audited state. |
| C-2 (CR F1, MINOR design-gap) | Accept: `_INC15_WAIT_SITES` gains each wait's predicate (`ast.unparse`) and the guard asserts it; R-TST-155's text already covers "the wait named in table D". Prove the control: `lambda: True` in D6 → RED. | Without it a vacuous predicate passes the guard. |
| C-3 (CR F2, NIT) | No change; `while` pause loops join the D-6 backlog census row. | Within R-TST-155's wording. |
| C-4 (CR F3, F4 NIT) | Fix: module-level `Counter` import; D-3 cell says rule 7. | Trivial. |
| C-5 (CR F5, NIT) | Add retiring the local `_settled` of the patch-editor module to the D-6 backlog row. | Out of slice. |
| C-6 (audit R-TST-153/1) | Read lane B's paint from the product's rendered widget (the painted text) instead of `lane_paint_plain(1)` if it is a local change in the test; otherwise keep `partial` with that reason. | A full mark needs the product's own output. |
| C-7 (audit R-TST-155/1) | Extend the guard's ban in the 8 sites to the b94 file's own `_wait_for` helper (same rule as `_settled`); then `full`. | Same class as the banned helper. |
| C-8 (audit R-TST-157/1) | Split the case: serial half verified (int-01); parallel half run now on the LAN host with `-n 8` over the changed files and recorded; the batch merge verification (full suite) re-confirms it. | A result counts only for the run it cites. |
| C-9 (audit 154/1, 163/1) | 154/1: drop "in order" from Expected. 163/1: the no-skip clause gets a run (force a skip → the guard reports it) or the case says `partial` with the reason. | Expected must match what the test checks. |
| C-10 (audit: TC-B94-27 reads after fixed pauses following Import) | Fix in the changed arm: wait through `settled` on the product's import observable, add it to table D as D9 with its hold (base form RED under the hold, fixed GREEN), update `_INC15_WAIT_SITES`; re-run tc_b94_27 16 times on Windows under the same isolation rules. | Rule 7 applies to every changed arm, including this one. |

Corrective: one Opus pass (tests and records only, no product code). Re-audit: only the cases C-6 … C-10 touched.

## Re-audit rulings (2026-11-06)

- **RA-1 (R-TST-157/2):** coverage `partial` until the merge-time full-suite verification runs the whole parallel lane; the merge record cites it and flips the case to `covered`. Why: the run cited used the lane's flags on 3 files only.
- **RA-2 (D9):** R-TST-153's trigger (the `variant_b.hex` Bind) does not cover a wait after the second import. Add **R-TST-164** (strict EARS, event form: the wait after the second Import in TC-B94-27), move case 153/3 to 164/1, and extend R-TST-155's and R-TST-163's site lists to name D9. No code change (the wait already exists). Why: a requirement must cover the behaviour its case verifies.
- **RA-3 (notes):** the `variant_b.hex not in paint_b` check without its own RED control and the import helper's internal `_wait_for` go to the D-6 backlog row. Why: not blocking; the guard's stated scope is the 9 sites.
