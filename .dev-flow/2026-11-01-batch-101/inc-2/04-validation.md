# Inc 2 — validation (E5)

**Verdict: PASS-WITH-NOTES.** Test hygiene is in place: the `serial_timing` marker and the two CI lanes, the wall-clock shared waits with margin reporting, the AST timing-arm census and its guards, the version-agnostic goldens and the redaction gate. No HIGH or MAJOR is open; the MINOR notes are routed (§Not run). Branch `b101-inc2` at `57d19f4` plus the uncommitted E5 records (this file, the E5 review/audit records, the mutant transcripts, the golden re-run and the two Linux transcripts). Windows host and LAN Linux host; no product file under `s19_app/` is touched.

## Runs

| Run | Result | Evidence |
|---|---|---|
| Final Windows run at `57d19f4` (hygiene suite + Inc 1 guards + `tests/test_b100_project_check.py`) | hygiene 65/65, Inc 1 guards 25/25, `test_b100_project_check.py` 93/96; total **3 failed, 183 passed in 365.23 s**. The 3 failures are timing arms of `sec6_5`: two `painted` at 2.49 s and one `appended` at 1.017 s — the pre-existing ~1 s step ruled to Inc 3 (R-3), unchanged from E4 (base and head show the same distribution, `e5c-painted-base-vs-head.txt`) | `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-win-e5c.txt` |
| RED-before: the E5 hygiene file on the pre-E5 tree `ab879c8` | **3 failed, 12 passed, 50 deselected in 69.52 s** — each failure names the defect its fix targets (F1 wrap drift, the 041 guard text, the 051 guard text) | `.dev-flow/2026-11-01-batch-101/evidence/inc-2/e5c-red-before.txt` |
| Linux hygiene + guards at `57d19f4` (scratch clone: commit base `e2663953` + the Inc 2 diff) | **90 passed in 161.44 s**; the earlier run in the same transcript: **3 failed, 55 passed, 2 skipped, 5281 deselected in 304.28 s** (timing arms over bound, the R-3 distribution) | `.dev-flow/2026-11-01-batch-101/evidence/inc-2/e5-linux-57d19f4.txt` |
| Linux timing lane (`-m serial_timing`) at `57d19f4` | **58 passed, 2 skipped, 5281 deselected in 303.39 s** (the lane's earlier failing state is the 3-failure run above and the four E4 Linux serial runs, 2 of 4 with one arm over bound — `E4-integration-notes.md` §8 item 2) | `.dev-flow/2026-11-01-batch-101/evidence/inc-2/e5-linux-timing-57d19f4.txt` |
| The 7 report golden files, re-run at `57d19f4` (R-3 note: a plain re-run instead of the F11 harness judgment call) | **1 failed, 133 passed in 338.95 s**; the failure is `test_at_056e_a2b_diff_report_byte_identical_despite_selection`, a known failure that is not one of the 7 golden nodes | `.dev-flow/2026-11-01-batch-101/evidence/inc-2/e5-golden-rerun.txt` |
| Linux gate lanes at `86c8aa6` (the integration runs the coverage audit's Linux evidence rests on) | lane 1 (`-m "not serial_timing"`): **6 failed, 5055 passed, 205 skipped, 4 xfailed in 4014.94 s** — the 5 known failures plus one under-load flake (`tc_b100_65_merge_names…`, same class as `tc_b97_23`, §6 backlog); lane 2 (`-m serial_timing`): **1 failed, 57 passed, 2 skipped in 306.40 s** — the failure is the R-3 step (`TC-B100-61 all-bad painted` 1.127 s) | `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-linux-plain-lane1.txt`, `int-linux-plain-lane2.txt` |
| RED on base: the hygiene suite on base `84d4507` (the tester's RED-proof of its own guard) | **54/54 nodes RED** — 48 failed + 6 errors in 24.40 s | `.dev-flow/2026-11-01-batch-101/evidence/inc-2/red-01-tester-base.txt` |

## Mutant score

**45/46 KILLED** (53 mutants minus 7 N/A owed to the LAN gate or CI evidence); the survivor **M-040/4** was closed by the E5 corrective pass and re-run: killed by `test_r_tst_040_4_appended_and_conditional_reads_are_bounds` (`[] == [arm]`) and by `test_r_tst_040_1_base_tree_reports_its_37_bounds` (35 ≠ 37) — `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-r2-040_4.txt` (2 failed, 2 passed, 61 deselected). M-017's near-miss was closed the same way: killed by the row's own node — `mut-r2-017.txt`. Details: `E5-mutants.md`; transcripts `.dev-flow/2026-11-01-batch-101/inc-2/E5-mutants.md`.

## Reviews

- **E3 design:** `architect` round 1 **FAIL** (3 HIGH, 4 MAJOR) → round 2 **PASS-WITH-NOTES** (all 7 closed; notes N-1 … N-4, all E4/E5 addenda). `security-reviewer` **PASS-WITH-NOTES** (2 MEDIUM, 5 LOW for E4/E5; no new permission, trigger, action or secret).
- **E5 code review:** `code-reviewer` **FAIL** (`BLOCK-UNTIL` F1 HIGH, the wrap deleted two oracle assertions) → re-review at `57d19f4`: **PASS-WITH-NOTES** — F1 closed on the diff (2 asserts restored; the whole-file AST check and the R-TST-049 guard re-run by the reviewer), F2 closed (spec-exact all-line rule; baseline 80 waits in 14 files regenerated on `e266395` and matching), F10 closed (R-TST-049 guard); F3–F9 and F11 (MINOR) recorded as closed by the corrective pass, not re-read. **E5 security:** `security-reviewer` **PASS-WITH-NOTES**, 0 HIGH — E5S-1 MEDIUM (the redaction gate, now widened and scanning the whole batch folder: `e5c-redaction-final.txt`, 2 passed) and E5S-2/3 LOW fixed; E5S-4 and E5S-7 routed to the backlog; the whole diff holds no personal name, account name, host name or LAN address.
- **Coverage audit** (independent `qa-reviewer`, which ran nothing and consumed the transcripts): first audit 17.3 % of the 81 cases changed by judgment (69 of 81, 85.2 %, in any cell); re-audit at `57d19f4`: 13.6 % of the 81 changed (11 cases; 10 resolved, 005/7 newly lost → ruling R-1), plus the new case 049/1 (82 cases over 49 requirements). Final totals: marks 75 full / 7 partial; coverage 65 covered / 8 partial / 8 gap / 0 conflict / 1 not-testable; results 62 verified / 0 failed / 20 not_run.

## Test-case totals

`02-test-cases.md`: **82 cases over 49 requirements** — E1 wrote 59, E3 round 1 added 17, round 2 added 5, E5 added R-TST-049/1 [F10]. After the re-audit: 62 verified, 20 not_run, 0 failed.

## Not run / owed

- **R-TST-008/009** (the two LAN gate runs): owed until Inc 3 settles the painted-interval ~1 s step (ruling R-3; routed as R1-P1, profile first). LAN runs so far, both within the 75 min budget: `loadfile` 64:18 + 5:07 = 69:25; plain 66:54 + 5:06 = 72:00.
- **R-TST-014/018-2/090**: owed to Inc 2's own PR CI run; **R-TST-091** (lane 1 back on workers, ≈290 min serial) owed at the batch end. **R-TST-012/017** owe a real red/stop CI run.
- **R-TST-031/032**: 1 of 3 parallel-lane runs on record for each of 031/1, 031/2, 032/1; 3/3 owed to the gate.
- **005/7** (partial, record/input mismatch — ruling R-1) and **049/1** (partial, the planted test compares function names not the guard text — ruling R-2): routed to the backlog.
- The 7 N/A mutants (M-008, M-009, M-070, M-071, M-072, M-090, M-091) are owed to the gate, CI evidence or a condition that never occurred — not to the pytest suite.
- `trace_check.py` and the flow validator were run on this record at close; their summary lines are in the increment packet.
