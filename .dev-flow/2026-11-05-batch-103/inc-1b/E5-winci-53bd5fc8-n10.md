# E5 WinCI on 53bd5fc8: R-PASTE.13/101 diagnostic tally (P-001, HT-07)

## Verdict

The diagnostic did not catch the failure. R-PASTE.13/101 passed in 9 of 9 valid runs, so no failing run exists to read, and the data cannot decide among H1 to H5 for the failure itself. N = 9, not 10: the tenth run (43540344655) is an infrastructure failure and is not a test run.

What the nine passing runs do show, with the diagnostic fields:

- The notice is already in `app._notifications` at the pre-observe snapshot in 9 of 9 runs (`raw_count=1`, `queue_size=0`, not expired, 5.94 to 5.98 s of the 6.0 s timeout left).
- `Notifications.add` happened at the same instant as `notify` in 8 of 9 runs (same monotonic offset) and 16 ms later in the ninth. In every run the add happened at or before `tail_end` + 16 ms and at least 15 ms before the first snapshot. The margin add-to-first-snapshot is 15 to 63 ms (offsets are quantised to about 15.6 ms, the Windows clock tick).
- No run shows the add after the observe snapshot (H5 as "add later than observe"), no `notify` raised (H2: `raised` is null in 9 of 9), no expiry (H3: `has_expired=false`, 5.4 to 5.8 s left even at the settled snapshot), and no app mismatch (H4: `same_app=true`, one `app_id` per run).
- `writer` is `written=False` in 9 of 9 and `notify` has exactly one call per run, so the failure path ran as designed (H1 negative).

Support by hypothesis: H1, H2, H3 and H4 are not supported in the passing runs; H5 is not supported either, but passing runs are the wrong sample for it, because H5 predicts the race only in the rare run. With a historic rate of 3/20 (3c064348 and 7804b500, no diagnostic), a rate of 0.15 gives P(0 failures in 9) = 0.23 and 0.20 gives 0.13. Nine clean runs are weak evidence, not proof that the failure is gone. The instrumentation (spies, extra snapshots, an extra `_settle`) may itself shift timing; that cannot be excluded from this record.

Decision for the operator: either keep running the diagnostic on a fresh N (it only pays off if a failing run appears), or apply the test-side fix below, which is justified by the source reading and by the zero margin (8 of 9 adds at the same instant as `tail_end`), not by a failing capture. This record applies no change.

Base: 53bd5fc8 (repo jav201/s19_app), which differs from 3c064348 only by the test-only diagnostic (`git diff --stat`: the test file, the E5 records and steps.log; no `src/` change). Run 43540297033 is the push run; the others are re-runs. Host load was not controlled (HT-08).

## The tenth run is infrastructure

43540344655 failed after 13 min (the others took 29 to 41 min). The first node, `test_runner_clipboard_probe` (the runner clipboard round-trip probe), failed with `runner clipboard unusable: stage=powershell-read-exception, result_chars=37`. The isolated-clipboard fixture then failed on setup (`isolated WinCI clipboard probe failed`) for 28 nodes, and 201 nodes were skipped, among them R-PASTE.13/101 and every R-PASTE.14 node. Result: failed 1, errors 28, passed 30, skipped 201; obligations 28/108; gate `FAIL violations=268`. The OS-clipboard tests never ran, so this is a runner/setup failure, not a test failure, and counts as 0 observations for every node; N = 9. The probe failing at all is its own signal (the PowerShell clipboard read on a fresh runner can throw); 1 of 10 here, worth a PENDING item if it recurs.

## Per-run results

| run | conclusion | failed / passed / skipped | FAILED node ids | obligations |
|---|---|---|---|---|
| 43540297033 (push) | success | 0 / 216 / 44 | - | 108/108 |
| 43540296863 | success | 0 / 216 / 44 | - | 108/108 |
| 43540302809 | success | 0 / 216 / 44 | - | 108/108 |
| 43540308896 | success | 0 / 216 / 44 | - | 108/108 |
| 43540315512 | success | 0 / 216 / 44 | - | 108/108 |
| 43540321157 | success | 0 / 216 / 44 | - | 108/108 |
| 43540327481 | success | 0 / 216 / 44 | - | 108/108 |
| 43540333026 | success | 0 / 216 / 44 | - | 108/108 |
| 43540339082 | success | 0 / 216 / 44 | - | 108/108 |
| 43540344655 | failure (infrastructure) | 1 failed + 28 errors / 30 / 201 | runner_clipboard_probe (+28 setup errors) | 28/108 |

## R-PASTE.13/101 diagnostic, per run (all pass); offsets in seconds from install

| run | tail_end | notify | add | wait_returned | pre | observe | settled | add - tail_end | pre - add | time left at pre / observe / settled (s) |
|---|---|---|---|---|---|---|---|---|---|---|
| 43540297033 | 1.688 | 1.688 | 1.688 | 1.703 | 1.719 | 1.922 | 2.125 | 0 | 0.031 | 5.977 / 5.765 / 5.561 |
| 43540296863 | 1.594 | 1.594 | 1.594 | 1.625 | 1.625 | 1.859 | 2.156 | 0 | 0.031 | 5.977 / 5.734 / 5.447 |
| 43540302809 | 1.875 | 1.875 | 1.875 | 1.890 | 1.890 | 2.109 | 2.359 | 0 | 0.015 | 5.977 / 5.755 / 5.511 |
| 43540308896 | 1.406 | 1.406 | 1.406 | 1.438 | 1.438 | 1.609 | 1.781 | 0 | 0.032 | 5.956 / 5.789 / 5.626 |
| 43540315512 | 1.765 | 1.765 | 1.765 | 1.781 | 1.781 | 1.984 | 2.187 | 0 | 0.016 | 5.976 / 5.775 / 5.583 |
| 43540321157 | 1.922 | 1.922 | 1.938 | 1.985 | 1.985 | 2.188 | 2.407 | +0.016 | 0.047 | 5.941 / 5.731 / 5.522 |
| 43540327481 | 1.657 | 1.657 | 1.657 | 1.688 | 1.688 | 1.860 | 2.047 | 0 | 0.031 | 5.966 / 5.794 / 5.611 |
| 43540333026 | 1.500 | 1.500 | 1.500 | 1.516 | 1.532 | 1.719 | 1.938 | 0 | 0.032 | 5.976 / 5.777 / 5.567 |
| 43540339082 | 1.859 | 1.859 | 1.859 | 1.922 | 1.922 | 2.172 | 2.437 | 0 | 0.063 | 5.945 / 5.697 / 5.423 |

Common to all nine: `writer = written=False`; one `notify` (severity `warning`, timeout 6.0, `raised` null, same `screen` and `app_id` as the snapshots); one `add`; `raw_count=1`, `queue_size=0`, `has_expired=false` at all three snapshots; `events` order `tail_start`, `writer_start`, `writer_end`, `tail_end`, `wait_returned` with `same_app=true`. The test took 6.0 to 9.4 s (JUnit). The writer takes 1.3 to 1.9 s (`writer_start` to `writer_end`), so `tail_end` is far from the 10 s `_wait` timeout.

Reading: in the passing runs the add is synchronous with `notify` (same offset), not deferred to a later pump turn. So the premise of H5 as written (the Notify message still queued at `tail_done`) is not what these runs show; whatever makes the notice miss in the rare run is not visible here.

## Per-node rate table (PP-04), against 3c064348 (N = 10)

| node | 3c064348 N=10 | 53bd5fc8 N=9 | PP-04 |
|---|---|---|---|
| R-PASTE.14/101 (key) | 0/10 | 0/9 | same |
| R-PASTE.14/102 (right) | 0/10 | 0/9 | same |
| R-PASTE.14/103 (row) | 0/10 | 0/9 | same |
| R-PASTE.14/C1[key], [right], [row] | 0/10 each | 0/9 each | same |
| R-PASTE.14/C2 (report-only) | 0/10 | 0/9 | same |
| R-PASTE.14/1, /2 (held write) | 0/10 | 0/9 | same |
| R-PASTE.13/101 | 2/10 | 0/9 | gone from FAILED in this set; 0/9 vs 2/10 is not distinguishable at these N |
| runner_clipboard_probe | 0/10 | 1 run of 10 (infrastructure) | new, not a test-node result |
| P-002 teardown nodes | 0/10 | 0/9 | same |

New in the FAILED set: `test_runner_clipboard_probe` plus 28 setup errors, in the infrastructure run only. Gone: `r_paste_13_101`. Over all measured sets R-PASTE.13/101 stands at 3 failures in 29 valid runs (3/20 without diagnostic, 0/9 with it); HT-07 keeps the class open and measured.

## C2 report-only values (`c2_max_lateness_s`, `c2_ticks`)

Max lateness, in the order of the diagnostic table: 0.028, 0.059, 0.043, 0.325, 0.419, 0.403, 0.325, 0.450, 0.372 s; ticks 30, 28, 30, 23, 21, 22, 23, 21, 20. Six of 9 exceed 0.200 s (0.325 to 0.450 s), the same pattern as before (6/10 on 3c064348, 7/10 on 7804b500); every run has at least 20 ticks. Report-only: nothing is asserted on the bound.

## Proposal only: test-side fix if the race reading is adopted

Change: in `test_r_paste_13_101_held_row_copy_warns_within_bound`, replace the immediate `_notice_rows` snapshot right after `wait_returned` with a bounded wait on the condition "the write-failure notice is present in `app._notifications`" (poll with `pilot.pause()` within the existing 10 s `_wait` budget), then take the snapshot the assertion uses.

It weakens no assertion: the expected sequence (one warning, text, severity `warning`, timeout 6.0) is compared unchanged; only the moment of observation moves from "right after tail_done" to "when the notice exists". It still fails if the notice never arrives (the wait times out and the existing message prints the observed list), so a missing or wrong notice stays a failure. The "no success notice" and "exactly one notice" checks must be taken after the wait, and a duplicate would still show at the settled snapshot.

Caution: the fix rests on the source reading and the zero-margin offsets, not on a captured failing run. If the failure persists after it, keep the diagnostic so the next failing run is captured with its fields.

## Evidence (redacted)

- JUnit property `r13_101_diag` of the nine passing runs, artifact `b103-winci-outcomes` (present in all ten runs); the fields used here carry no runner account name, host or home path.
- Failing run, verbatim: `Failed: runner clipboard unusable: stage=powershell-read-exception, result_chars=37` at `tests\test_b103_clipboard_windows.py:239`; setup errors read `isolated WinCI clipboard probe failed`; gate line `WINCI_GATE_RESULT FAIL violations=268 pytest_exit=1 gate_exit=1`.
- Passing gate line in nine runs: `WINCI_GATE tests=260 passed=216 failed=0 errors=0 skipped=44 obligations_passed=108/108 at_passed=28/28`, `WINCI_GATE_RESULT PASS violations=0`.
