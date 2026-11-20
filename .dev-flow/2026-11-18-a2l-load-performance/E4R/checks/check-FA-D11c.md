# check-FA-D11c — push-only CI job for the heavy case_06 arms (Q2 = A)

Orchestrator Opus 5.5 (relevo-29). Edit-only Opus agent (no pytest on the PC, HT-01); scripted mechanical check (MD-11) on the reference Linux host (rtx), 1-min load 1.33–2.18; Opus intent review.

## Diff
`diffs/FA-D11c.diff` applied on the merge tip `2f01232b`: 6 files, +124/−32, 0 CR, 0 new test functions, needle scan 0.
- `.github/workflows/tui-ci.yml`: push lane 2 runs `pytest -q -rs -m "serial_timing and not slow"` (75 min kept). New job `tui-ci-heavy`: job-level `if: github.event_name == 'push'`, no `needs:` (a red `tui-ci` must not skip it), `timeout-minutes: 123` = ⌈1.5 × 41 min × 2⌉ (M2-REPORT: laptop heavy-arm wall 41 min; CI factor 2), setup steps identical to `tui-ci`, one step `pytest -q -rs -m "slow and serial_timing"`.
- `REQUIREMENTS.md`: R-TST-011 amended (push lane 2 command); new R-TST-019 (what `tui-ci-heavy` runs on a push) and R-TST-026 (its 123-minute limit). Both ids had 0 occurrences in the tree, `.dev-flow/` included. Two rows because strict EARS allows one "shall" per row.
- `tests/test_suite_hygiene.py`: `PUSH_LANE_2` updated; `HEAVY_LANE`; `_lane_step` selects a lane step by event and command, because PR and push lane 2 now share one command and the old run-text dicts would have mapped both to one step; heavy-job pins in `test_r_tst_011_…` (job present, push-only gate and no `needs:`, exactly one pytest step = `HEAVY_LANE`, setup equal to `tui-ci`) and `test_r_tst_015_016_017_…` (limit 123). Traces docstrings name R-TST-019/026.
- `docs/architecture.md` (marker paragraph), `CLAUDE.md` (R-DOC-DEV.3 CI sentence, by the orchestrator; it keeps both markers its law reads), E4R `01-requirements.md` (the three rows).

## Mechanical check
| Step | Result |
|---|---|
| Six laws + `test_b101_doc_hygiene.py`, `-n 0`, base (merge tip) | 160 passed, 2 skipped, 1 failed |
| Same, patched | 160 passed, 2 skipped, 1 failed — FAILED set identical (1 node: `test_no_private_tokens.py::test_no_tracked_file_holds_a_private_token`, inherited, FA-PRIV scope) |
| `--collect-only -m "slow and serial_timing"`, patched | 27 of 9,986 collected (the heavy job is not empty, so it cannot exit 5) |
| Law 070_2 offender lines, patched | 0 (0 under E4R) |

Power controls (copies of the patched tree; each mutation must turn its law RED):
| Control | Mutation | Selected laws | Result |
|---|---|---|---|
| M1 | push lane 2 back to `-m serial_timing` | 011, 012, 015 | 3 failed |
| M2 | `tui-ci-heavy` limit 123 → 60 | 015 | 1 failed |
| M3 | heavy pytest step removed | 011 | 1 failed |
| M4 | `needs: tui-ci` added to the heavy job | 011 | 1 failed |

Not run: the 27 heavy nodes themselves (timing; batch-end suite on the quiet laptop, DF-08). The job's real CI wall time is known only after the close push (PP-04).

## Open (close backlog)
- E4R `02-test-cases.md` has no rows for R-TST-011/019/026.
- `docs/requirements/review/S0-ears-strict.md` has no rationale entry for the new rows.

## Verdict
MECH-GO. Opus intent: GO — operator Q2 = A (P-191) implemented as the brief's branch A; the limit is derived from the M2 measurement rather than the brief's pre-measurement 60; H = B's `tui-ci` limits (220/75/300) are untouched.
