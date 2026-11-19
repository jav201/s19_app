# Unit H — CI time limits raised with measured margin (operator round-3 card H = B, 2026-11-19)
The full push suite took 196 min (lane 1) and 64 min (lane 2) in the last `main` CI run, over the 180/45/240 limits restored by unit CI. Operator verdict H = B: push lane 1 220 min, push lane 2 75 min, `tui-ci` job 300 min; pull-request lanes unchanged (120/30); to be revisited downwards after Front A.
Changes: `.github/workflows/tui-ci.yml` (job 300, push lane 1 220, push lane 2 75); `REQUIREMENTS.md` R-TST-015 (220 push / 120 PR) and R-TST-016 (300); `tests/test_suite_hygiene.py::test_r_tst_015_016_017_ci_time_limits` asserts the new values. The lane-sum check holds: setup 3 + 220 + 75 = 298 <= 300.
Made by the orchestrator (8 lines, mechanical); checked on the Linux host.
