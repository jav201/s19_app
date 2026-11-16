# E5 WinCI on b2d6eb25, round 3 (N=10): R-PASTE.13/101 post-fix tally (P-001, HT-07)

## Verdict

0 failures in 10 of 10 valid runs, for R-PASTE.13/101 and for every other gated node. All ten runs ended `success`, `WINCI_GATE_RESULT PASS violations=0`, obligations 108/108, acceptance 28/28, artifact-safety `PASS violations=0`. Post-fix rate of R-PASTE.13/101: **0/10**.

Base: b2d6eb25 on branch `b103-inc1b` (repo jav201/s19_app), workflow `clipboard-windows`. The change versus 53bd5fc8 is test-only (RR-1 fix: the test waits, inside its 10 s budget, for the queued notice before the snapshot it asserts on; bound, text, severity and "exactly one" unchanged). Host load not controlled (HT-08).

## Per-run results

Every run: 260 tests, 216 passed, 0 failed, 0 errors, 44 skipped; gate line `WINCI_GATE tests=260 passed=216 failed=0 errors=0 skipped=44 obligations_passed=108/108 at_passed=28/28 at_p1=14/14 at_p2=14/14`; `WINCI_GATE_RESULT PASS violations=0 pytest_exit=0 gate_exit=0`.

| run | event | conclusion | failed / passed / skipped | WINCI_GATE_RESULT | obligations | valid |
|---|---|---|---|---|---|---|
| 43553568285 | push | success | 0 / 216 / 44 | PASS 0 | 108/108 | yes |
| 43553575808 | dispatch | success | 0 / 216 / 44 | PASS 0 | 108/108 | yes |
| 43553577902 | dispatch | success | 0 / 216 / 44 | PASS 0 | 108/108 | yes |
| 43553579975 | dispatch | success | 0 / 216 / 44 | PASS 0 | 108/108 | yes |
| 43553582313 | dispatch | success | 0 / 216 / 44 | PASS 0 | 108/108 | yes |
| 43553584805 | dispatch | success | 0 / 216 / 44 | PASS 0 | 108/108 | yes |
| 43553586953 | dispatch | success | 0 / 216 / 44 | PASS 0 | 108/108 | yes |
| 43553589381 | dispatch | success | 0 / 216 / 44 | PASS 0 | 108/108 | yes |
| 43553591762 | dispatch | success | 0 / 216 / 44 | PASS 0 | 108/108 | yes |
| 43553594052 | dispatch | success | 0 / 216 / 44 | PASS 0 | 108/108 | yes |

Validity: no run shows `powershell-read-exception`; the clipboard probe passed in all ten (the artifact `b103-winci-outcomes` has gate, JUnit, pytest and artifact-safety files in each).

## Per-node rates (valid runs = 10)

Failures come from the JUnit (0 failures, 0 errors in all ten) and the gate (all 108 obligations passed in all ten). Worst measured value is the maximum of the `qc_tm` property over the ten runs.

| node | failures / valid | worst measured (bound) |
|---|---|---|
| R-PASTE.14/101 (key) | 0/10 | 0.106 s (0.200 s) |
| R-PASTE.14/102 (right) | 0/10 | 0.122 s (0.200 s) |
| R-PASTE.14/103 (row) | 0/10 | 0.106 s (0.200 s) |
| R-PASTE.14/C1 [key] | 0/10 | 0.090 s (0.200 s) |
| R-PASTE.14/C1 [right] | 0/10 | 0.075 s (0.200 s) |
| R-PASTE.14/C1 [row] | 0/10 | 0.091 s (0.200 s) |
| R-PASTE.14/1, /2 (held write) | 0/10 each | 0.013 s (0.200 s) |
| R-PASTE.13/1.2 [single], [multi] | 0/10 each | 1.765 s / 1.516 s (5.000 s) |
| **R-PASTE.13/101** | **0/10** | 1.922 s (5.000 s) |
| R-PASTE.14/C2 (report-only) | not asserted | see below |

C2 (report-only) `c2_max_lateness_s` per run, in run-table order: 0.372, 0.028, 0.247, 0.419, 0.341, 0.387, 0.403, 0.372, 0.372, 0.075 s; `c2_ticks`: 22, 30, 25, 19, 21, 21, 21, 21, 20, 26. Eight of 10 exceed the 0.200 s bound (0.247 to 0.419 s), as in round 2 (8 of 10). Nothing is asserted on it.

## R-PASTE.13/101 diagnostic, every run (R-PASTE.13/101 `r13_101_diag`)

Offsets in seconds from install. `n-a` = add minus notify; `pre` = first snapshot (`pre_observe`); `p-a` = pre minus add (positive = the first read happened after the add); `raw` / `q` = `raw_count` / `queue_size` at the first snapshot. `notice_wait_s` is the new field written by the fix.

| run | result | notify | add | n-a | pre | p-a | first read after add | raw / q at pre | notice_wait_s |
|---|---|---|---|---|---|---|---|---|---|
| 43553568285 | pass | 1.563 | 1.563 | 0 | 1.578 | +0.015 | yes | 1 / 0 | 0.0 |
| 43553575808 | pass | 1.516 | 1.516 | 0 | 1.532 | +0.016 | yes | 1 / 0 | 0.0 |
| 43553577902 | pass | 1.734 | 1.734 | 0 | 1.750 | +0.016 | yes | 1 / 0 | 0.0 |
| 43553579975 | pass | 1.656 | 1.656 | 0 | 1.734 | +0.078 | yes | 1 / 0 | 0.0 |
| 43553582313 | pass | 1.938 | 1.938 | 0 | 1.969 | +0.031 | yes | 1 / 0 | 0.0 |
| 43553584805 | pass | 1.531 | 1.531 | 0 | 1.547 | +0.016 | yes | 1 / 0 | 0.0 |
| 43553586953 | pass | 1.828 | 1.828 | 0 | 1.860 | +0.032 | yes | 1 / 0 | 0.0 |
| 43553589381 | pass | 1.734 | 1.734 | 0 | 1.766 | +0.032 | yes | 1 / 0 | 0.0 |
| 43553591762 | pass | 1.750 | 1.750 | 0 | 1.781 | +0.031 | yes | 1 / 0 | 0.0 |
| 43553594052 | pass | 1.641 | 1.641 | 0 | 1.734 | +0.093 | yes | 1 / 0 | 0.093 |

Reading:
- `notice_wait_s`: range 0.0 to 0.093 s; 9 of 10 runs needed no wait (the notice was already in `app._notifications` when the wait began); 1 of 10 waited one pause step (0.093 s).
- notify to add delay: 0 in all ten (add at the same clock instant as notify). In round 2 the two failing runs had 0.266 s and 0.593 s; those lags did not occur in this round, so the new wait was exercised only to 0.093 s here. Its ability to absorb a 0.27 to 0.59 s lag rests on the Linux-seam controls of the fix record (drop-notify FAIL, +3.5 s FAIL, +0.5 s PASS, unmutated PASS), not on a WinCI occurrence of the lag.
- First read after the add: yes in all ten (15 to 93 ms after). `raw_count=1`, `queue_size=0` at the first snapshot in all ten; one notify (warning, timeout 6.0), `writer written=False`, `same_app=true` in all ten.

## PP-04: FAILED set versus round #2 (53bd5fc8)

| item | round 2 (N=10 valid) | round 3 (N=10 valid) | delta |
|---|---|---|---|
| R-PASTE.13/101 | 2 (43548702062, 43548712365) | 0 | **gone** |
| all other nodes | 0 | 0 | same |
| new failing nodes | - | none | no new item |

## Rates (HT-07)

- Post-fix, b2d6eb25: **0/10** (R-PASTE.13/101); 0/10 for every other gated node. Reported on its own: the fix changes the test, so earlier sets do not pool with it.
- Before the fix (3c064348, 7804b500, 53bd5fc8 rounds 1 and 2): 5/39 valid runs failed (0.128), cause H5 confirmed in round 2.
- Reading: with a pre-fix rate near 0.13, P(0 in 10) is about 0.25 if the fix had changed nothing, so 0/10 alone is consistent with no effect; the evidence for the fix is the confirmed mechanism (round 2), the Linux-seam controls, and this clean round. Not claimed as proof of rate 0.

## Evidence (redacted)

JUnit properties `r13_101_diag`, `qc_tm` and `c2_*`, gate and artifact-safety files of artifact `b103-winci-outcomes`, all ten runs. Scratch copies were kept outside the repo and deleted after this record.
