# check-CI (orchestrator, Linux host, clone of b103-fix-round 6480aab6 + diffs/CI.diff)

**Verdict: GO.** Diff = the exact reverse of the limit hunks of 65fcaa3f (workflow) and b5968f23 (hygiene asserts): 2 files, +6/-7, CR 0, no test removed.

| # | Check | Evidence |
|---|---|---|
| 1 | GREEN | `tests/test_suite_hygiene.py` `-n 0`: 1 failed, 64 passed, 2 skipped (285.8 s); the failure is `test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses`, base-red at 3afebf90 (`baseline/laws.txt`, records unit) |
| 2 | Negative control | copy with push lane 1 set back to 360 in the workflow: `test_r_tst_015_016_017_ci_time_limits` 1 failed (RED) |
| 3 | Canon | R-TST-015 (180 push / 120 PR) and R-TST-016 (240) in the folded canon match the workflow; the lane sum check (setup + lane 1 + lane 2 <= job) holds: the test passes |
