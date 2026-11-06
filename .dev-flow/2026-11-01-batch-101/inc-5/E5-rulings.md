# Inc 5 — E5 rulings (orchestrator, 2026-11-06)

Inputs: `E5-code-review.md` (code-reviewer **PASS-WITH-NOTES**: F1 MAJOR design-gap, F2–F3 MINOR, F4–F6 NIT), `E5-security.md` (security-reviewer **PASS-WITH-NOTES**: every E3 mitigation executed; 12/12 security mutants killed; E5-S1 MEDIUM design-gap, E5-S2/S3 INFO), `E5-coverage-audit.md` (qa-reviewer: 34 cases, 10 marks changed = 29.4 %). `E5-mutants.md` (DeepSeek battery at `8fc3cd3`) is still running; its survivors, if any, are ruled when it lands. Rulings:

| Id | Ruling | Why |
|---|---|---|
| C-1 | Move every case's marks in `02-test-cases.md` to the audited values. | The record shows the audited state. |
| C-2 (CR F1 MAJOR = audit 056/1–/3, 025/3) | The 056 and 025/3 preconditions patch `0x0` to `93` first, so a demoted row that reads the image instead of the spec bytes fails; add mutant M25 (the demoted row leaves out its expected bytes) → must be RED. | R-CHKED-056 requires the spec's bytes on the demoted row; no case could tell. |
| C-3 (audit 002.5/3, /4, /7, /8; CR F4) | Take the recompute-count snapshot before the trigger, not after the write settles. | The count must decide the case, not the timeout. |
| C-4 (audit: drive rule) | Write the four owed black-box ATs through keys and clicks (Write, Validate, Add, save-back); the other cases keep the audited "drive partial" marks. | The increment owes its acceptance tests through keys and dialogs. |
| C-5 (audit: 3/3 runs) | Run the Check Editor cases 3/3 as their thresholds state and cite the runs. | A threshold of 3/3 needs three cited runs. |
| C-6 (audit gaps) | Add a deciding case for each of the four clauses the audit names; add mutants for 010/1, 025/1, 027/1. | Every clause needs a case that can fail; every row a RED control. |
| C-7 (CR F2) | Fix the `app.py` docstrings (`:7300-7310`, `:7366`): a field loaded from a spec keeps the spec's bytes. | Comments must match behaviour. |
| C-8 (CR F3) | Delete the stale F-01 "symbol specs refused" sentence at the end of the rewritten guide §10.8 paragraph now. | It contradicts the paragraph this increment rewrote; leaving it for the batch-end pass would ship a contradiction. |
| C-9 (CR F5, F6 NIT) | F6: add the `Data Flow` section to the new public method and the element type of `_spec_bytes`. F5: no change (redundant checks are expected; mutants removing only one of them may survive and are recorded as equivalent). | Convention; honest mutant accounting. |
| C-10 (SEC E5-S1 MEDIUM design-gap) | **Fold in.** New row (next free R-CHKED id, strict EARS event form): when the loaded image's bytes are written in place, the system shall clear the Check Editor's validation results and leave no "validation complete" state for the old bytes (exact observable and message text, if any, fixed in the row). Implement it through the same hook (#1, `app.py`) calling a Check Editor panel method (`screens_directionb.py`, in the slice); update the graph; case(s) RED on base for the stale `pass`; a mutant (hook does not clear) → RED. | Same integrity class as D-4: a stale `pass` an operator would trust after the bytes changed. The files are already in the slice. |
| C-11 (SEC E5-S3) | Add the R2-1 backlog row to `E1-rulings.md` §6. | Record completeness. |
| — (SEC E5-S2 INFO) | No action. | The exception ends the app; nothing stale stays on screen. |

Corrective: one Opus pass (code within the slice, tests, records, graph). Then a re-review of C-2 and C-10 (code + security) and a re-audit of the cases C-2 … C-6 and C-10 touched.

## Re-review and re-audit rulings (2026-11-06)

Security re-review: E5-S1 and code-review F1 **closed** (executed · approved), HIGH 0, MEDIUM 0. Re-audit: **PASS**, 0 marks to change; 4 partials stand with their reasons. The residuals are recorded as owed in `04-validation.md`, none blocking:

- RA-1: M1–M24 ran at `8fc3cd3` (before the corrective, which touched only the hook's callee set and tests); they carry over by reasoning, and the batch-end battery re-runs the mutant table on the merged tree.
- RA-2: mutant transcripts show `Files … differ`, not the mutant text — the mutant table in `E5-mutants.md` and `E5-corrective-notes.md` names each edit; future units print the diff.
- RA-3: R-CHKED-041.2/4 and 041.3/1 have no executed control of their own; 010/4's base failure hits another defect — backlog line for the next Check Editor increment.
- RA-4: AT-I5-4 proves the save-back confirm is reachable by keys, not that the clipped row is visible — the clipping is a UI row (KF-101 family), backlog.
- RA-5: refused/raising paths reach R-CHKED-057 only through the shared hook (RR-2); R-CHKED-056's Base column is refreshed by the close record (RR-3).
