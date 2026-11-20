# check-FA-FIX1 — TC-707 pin after G7 (batch-end suite finding)

Orchestrator Opus 5.5 (relevo-29); scripted check on the reference Linux host (rtx).

## Finding
The batch-end suite on the merge tip e54017f7 failed `tests/test_window_usage_help.py::test_tc707_numbering_generated_sequential` with `[('patch', 'c')]`: the Patch section's step count differs from its pin. Serial triage: PASS on `main` 3afebf90, FAIL on `b103-fix-round` 6eccf0cb and on the merge tip (same state path on all three trees). Cause: Front B unit G7 (c579fa46, "Patch help names Format and the D10-23 buttons") added the approved "Format" step to `WINDOW_HELP_SECTIONS["patch"]` (49 → 50 steps, counted by AST on both trees) without the pin update the file's convention requires ("a change that changes a count updates its pin by named supersession"). PR #214's lean lane never reached this file (it stops at 48 %).

## Fix (DF-04 a: the approved G7 design wins)
`tests/test_window_usage_help.py`: `_PINNED_STEP_COUNTS["patch"]` 49 → 50, with the supersession comment line naming G7. 1 file, +2/−1, 0 CR. The older record `.dev-flow/2026-11-05-batch-103/evidence/full-suite/b103-g3-oracles/RESULT.md` ("pin is 49") stays as history (PP-06).

## Check
| Step | Result |
|---|---|
| Control: TC-707 on the unfixed trees (triage) | FAIL on 6eccf0cb and e54017f7 |
| `tests/test_window_usage_help.py` + `tests/test_id_registry.py`, `-n 0`, fixed tip | 50 passed |

## Verdict
MECH-GO. Opus intent: GO.
