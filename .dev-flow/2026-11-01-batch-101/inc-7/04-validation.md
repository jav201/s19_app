# Inc 7 — validation (E5)

**Verdict: PASS-WITH-NOTES.** The diff and before/after reports now write whole hex windows, escape every file-derived field once, write each file whole or not at all, and name the before/after report as such. All 61 cases are `covered` (0 partial, 0 gap). No HIGH or MAJOR finding is open. The notes are routed (see Not run / owed). Branch `b101-inc7` at `f24d71e` plus the uncommitted E5 close (the two re-review sections, the RA-1/RA-2 test and cases, this record, the packet and the `e5d-*` transcripts). Windows and the LAN Linux host; 4 source files (`diff_report_service.py`, `before_after_service.py`, `app.py`, `flow_execution_service.py`).

## Runs

| Run | Result | Host | Evidence |
|---|---|---|---|
| Tester RED on base `9f9f6af` (64 nodes: 45 new, 19 re-pinned) | 54 failed, 10 passed (the 10 are guards that are GREEN on base by design) | Windows | `.dev-flow/2026-11-01-batch-101/evidence/inc-7/red-01-tester-base.txt` |
| E4 final integration at `9508239` (the case files plus guards) | 547 passed, 1 skipped, 1 failed (`test_at_056e…`, fails the same way on base: `int-03`) | Windows | `.dev-flow/2026-11-01-batch-101/evidence/inc-7/int-04-final-case-nodes.txt` |
| E5 corrective, C-1 RED on `90ea8ae` | 2 failed (the planted link was followed, its target created); GREEN 5 passed; final 6 passed | Windows | `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-red-c1-windows.txt`, `e5c-green-c1-windows.txt`, `e5c-final-windows-c1.txt` |
| E5 corrective final, 66 cited case nodes | 66 passed | LAN Linux | `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-final-case-nodes.txt` |
| E5 corrective final battery (22 files, `-n 8`, not serial_timing) | 603 passed, 1 failed (`test_at_056e…`, known) | LAN Linux | `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-final-linux-a.txt` |
| E5 corrective guards, serial arms, TC-031, before/after file | 119 passed; 2 passed; 3 passed; 34 passed | LAN Linux | `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-final-linux-d-guards.txt`, `-b-serial.txt`, `-c-tc031.txt`, `-e-before-after.txt` |
| E5 close, the 2 new nodes plus the 2 C-1 nodes on the tree | 4 passed | LAN Linux | `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5d-green-new-nodes.txt` |
| E5 close, mutant M28 (staging name fixed to `<name>.tmp.part`) | RED: 1 failed (`…_16_6_staging_name_is_random_per_write`), 3 passed; file restored, digest back to `8a0f4f4c…0b` | LAN Linux | `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5d-red-mutant-tmp-part.txt` |
| E5 close, mutant M29 (cleanup unlinks every `*.part`) | RED: 1 failed (`…_16_4_stale_part_file_survives_failed_write`), 1 passed; restored, same digest | LAN Linux | `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5d-red-mutant-unlink-all-part.txt` |
| E5 close, final run (10 files, `-n 8 -m "not serial_timing"`) | 327 passed, 1 failed (`test_at_056e…`, known) in 158.33 s | LAN Linux | `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5d-final-linux.txt` |
| A-6 worst case, two 4 MiB images fully changed | 32.6 s, 5,157 MiB peak, `.md` 85,459,849 B, `.html` 1,183,319,853 B (pre-existing HTML size; routed) | Windows | `.dev-flow/2026-11-01-batch-101/evidence/inc-7/int-05-a6-worst-case.txt` |

## Mutant score

**30 / 30 killed.** Run 1 (Windows, `90ea8ae`): 23 of 24, M22 survived (a real gap). E5 corrective (LAN Linux): M22 re-run killed by the new C-2 node; M24 to M27 killed, each on an output-text assertion (28 of 28). E5 close: M28 and M29 killed (30 of 30). M28 and M29 are recorded in `02-test-cases.md` and the `e5d-*` transcripts, not in `E5-mutants.md`. Arms that stayed GREEN are named in `E5-mutants.md` (M12, M20, M22 old node, M26 no-MAC arm).

## Reviews

- **E3 design:** round 1 `architect` PASS-WITH-NOTES (3 MAJOR) and `security-reviewer` PASS-WITH-NOTES (3 MAJOR); the orchestrator ruled on all six; round 2 PASS-WITH-NOTES, 6 of 6 closed, one new MINOR (the S-3 cleanup rule against addendum A-2) closed at E4.
- **E5 code review** (`code-reviewer`): PASS-WITH-NOTES, no BLOCKER or MAJOR. A-6 ruled an accepted pre-existing consequence (CR-1, routed). CR-6 fixed (C-7); CR-2 … CR-5 routed.
- **E5 security** (`security-reviewer`): PASS-WITH-NOTES, no HIGH. S5-1 (LOW, a dangling link at the guessable `.part` name is followed on Windows) fixed by C-1 and **closed on re-review** (RR-1 … RR-6). S5-5 (LOW, no test pins the unpredictable staging name) closed by the E5 close: case R-CMP-005.16/6 and M28. S5-2 and S5-3 routed; S5-6 INFO.
- **Coverage audit** (`qa-reviewer`, ran nothing): first audit 8 of 52 cases changed (15.4 %). Re-audit of the 19 corrective cases: 1 of 19 (5.3 %) still to change (RA-2) plus 1 clause without a case (RA-1). The E5 close wrote both: R-CMP-005.16/6 added, R-CMP-005.16/4 reworded with its write-failure arm. Final totals: **61 cases, 61 covered, 0 partial, 0 gap**; 68 distinct cited nodes. The auditor has not re-read these two edits; the author's evidence is the table above.

## Not run / owed

- **Full suite** at the batch end (E5 ran the touched files, guards and the corrective battery only).
- **A-6 / S5-3 report size and memory** (pre-existing; routed to a new increment): not fixed here. 16 MiB and crafted 262,144-run inputs `not-run`.
- **Known failures, unchanged by Inc 7:** `test_at_056e_a2b_diff_report_byte_identical_despite_selection` (fails on base `9f9f6af`, `int-03`) and `tests/test_tui_commandbar.py::test_at_b78_03…` (fails on base). It failed in the integration per-file rerun (`int-02d`) and is outside every later battery.
- **Flaky on base and head:** `test_tc024_report_trigger_surfaces_paths` (OBS-E5-1, routed).
- Serial-timing arms (`serial_timing`) ran once on the LAN Linux host (2 passed), not on Windows.

## Trace check

`trace_check.py --req inc-7/01-requirements.md inc-7/E1-slice.md --tests tests --base main --src s19_app`: `trace_check: 3 US, 18 active requirements (1 withdrawn), 8 gap(s)` — all 8 are EVID lines for the four uncommitted `e5d-*` transcripts (each listed twice); 0 TEST or code gaps. They clear when the orchestrator commits the evidence`
