# Inc 2 — E5 mutant table (test hygiene)

Batch 2026-11-01-batch-101, increment 2, stage E5. Base: `ab879c8` (branch
`b101-inc2`). Method: each requirement's negative control of
`01-requirements.md` (48 R-TST rows) plus the planted per-form controls named
in the rulings (R-TST-005/6, R-TST-005/7, R-TST-040/4, seams S-1 and G-1) =
53 mutants. Each mutant was applied to a detached copy of `ab879c8` (git
worktree under a temp dir, since removed), the test(s) the case names were
run there (env per the increment's test conventions; `s19_app.__file__`
printed first in every transcript and is the copy in all of them), the file
was restored byte-exact afterwards (`git diff --quiet` clean after every
mutant), and nothing was committed. Transcripts: `../evidence/inc-2/mut-*.txt`
(home paths and account names redacted).

Result legend: KILLED = a named test went RED for the mutant's reason;
SURVIVED = all named tests green; N/A = the control needs a CI run, the LAN
gate or another E5 measurement (reason given).

| Mutant | Requirement | Mutation (applied to the copy, then restored) | Test(s) run | Result | Transcript |
|---|---|---|---|---|---|
| M-001 | R-TST-001 | `serial_timing` entry removed from the `pyproject.toml` `markers` list | `test_r_tst_001_serial_timing_marker_is_registered` | KILLED | `mut-001.txt` |
| M-S1 | R-TST-001 (seam S-1) | marker description set to the doubled pre-S-1 form `serial_timing: serial_timing: …` | `test_r_tst_001_serial_timing_marker_is_registered` | KILLED | `mut-S1.txt` |
| M-002 | R-TST-002 | `@pytest.mark.serial_timing` removed from `test_tc_b100_20_writers_on_a_31_folder_manifest_finish_under_one_second` | `test_r_tst_002_every_timing_arm_carries_serial_timing` | KILLED (guard names it) | `mut-002.txt` |
| M-003 | R-TST-003 | `_marker_guard_lines` returns before the unmarked-arm check | `test_r_tst_003_an_unmarked_timing_arm_is_named` | KILLED | `mut-003.txt` |
| M-004 | R-TST-004 | the reverse check (marked non-arm) deleted from `_marker_guard_lines` | `test_r_tst_004_a_marked_non_arm_is_named` | KILLED | `mut-004.txt` |
| M-005 | R-TST-005 | stamp-difference rule and form (d) both removed from the census (head tree: TC-B100-20 and the 3 TC-B100-30 hostile arms missed) | `test_r_tst_002_every_timing_arm_carries_serial_timing` | KILLED ("census lost base timing arms") | `mut-005.txt` |
| M-005/6 | R-TST-005/6 | stamp form removed: a subtraction with a clock stamp on a side is no longer an interval | `test_r_tst_005_detector_finds_each_timing_arm_form[form5]` | KILLED | `mut-005-6.txt` |
| M-005/7 | R-TST-005/7 | form (d) removed: `report_margin` dropped from `_MARGIN_FUNCS` | `…[form6]`, plus `test_r_tst_040_041_every_upper_timing_bound_is_reported` | KILLED by 040_041; the named case `[form6]` passes — see analysis | `mut-005-7.txt` |
| M-006 | R-TST-006 | detector keyed on any clock call (any test calling a clock is an arm) | `test_r_tst_006_detector_ignores_intervals_no_assert_reads` | KILLED (≥18 false arms) | `mut-006.txt` |
| M-007 | R-TST-007 | release-gate sentence deleted from `docs/engineering-rules.md` | `test_r_tst_007_conventions_hold_each_test_rule[R-TST-007]` | KILLED | `mut-007.txt` |
| M-008 | R-TST-008 | whole suite in one `-n 8` lane with no `-m` | — (no pytest node, D-15) | N/A — needs the LAN Linux gate (two lanes, run twice); a full local lane exceeds the 900 s per-run budget | — |
| M-009 | R-TST-009 | serial lane given the whole suite (no `-m`) | — (no pytest node, D-15) | N/A — needs the LAN gate wall-clock measurement; see M-008 | — |
| M-010 | R-TST-010 | PR lanes collapsed to a single `pytest -q -m "not slow"` step in `tui-ci.yml` | `test_r_tst_010_pull_request_runs_two_lanes` | KILLED | `mut-010.txt` |
| M-011 | R-TST-011 | push lanes collapsed to a single `pytest -q` step | `test_r_tst_011_push_runs_two_lanes` | KILLED | `mut-011.txt` |
| M-012 | R-TST-012 | `!cancelled()` removed from both lane-2 `if:` conditions | `test_r_tst_012_serial_lane_runs_after_a_red_lane` | KILLED | `mut-012.txt` |
| M-013 | R-TST-013 | `fetch-depth: 0` removed from the `tui-ci` checkout step | `test_r_tst_013_014_ci_checks_out_full_history` | KILLED | `mut-013-014.txt` |
| M-014 | R-TST-014 | same mutation as M-013 | `test_r_tst_013_014_ci_checks_out_full_history` (static half) | KILLED statically; the dynamic half (the `b514b07` arm skipping on a shallow CI clone) needs Inc 2's PR CI run | `mut-013-014.txt` |
| M-015 | R-TST-015 | lane-1 `timeout-minutes` removed (180 push, 120 PR) | `test_r_tst_015_016_017_ci_time_limits` | KILLED | `mut-015.txt` |
| M-016 | R-TST-016 | job-level `timeout-minutes: 240` removed | `test_r_tst_015_016_017_ci_time_limits` | KILLED | `mut-016.txt` |
| M-017 | R-TST-017 | lane-2 conditions use `success()` instead of `!cancelled()` | `test_r_tst_012_serial_lane_runs_after_a_red_lane` | KILLED — note: `test_r_tst_015_016_017` does not check lane-2 conditions (see analysis) | `mut-017.txt` |
| M-018 | R-TST-018 | `python -m pip install "pytest-xdist==3.8.0"` removed from the install step | `test_r_tst_018_ci_installs_pinned_xdist` | KILLED statically; case 018/2 (the lane-1 worker header) needs the PR run log | `mut-018.txt` |
| M-G1 | seams R-TST-010/011 (seam G-1) | `--dist loadfile` restored on both lane-1 commands (pre-G-1 form) | `test_r_tst_010_pull_request_runs_two_lanes`, `test_r_tst_011_push_runs_two_lanes` | KILLED (both) | `mut-G1.txt` |
| M-020 | R-TST-020 | `range(attempts)` pause loop restored in `b100_projects.wait_for` (count-bounded form) | `test_r_tst_020_021_shared_helpers_delegate_to_the_one_wait`, `…_failure_texts[W1]` | KILLED by 020_021 (range-loop census; W1 alone stays green — see analysis) | `mut-020.txt` |
| M-021 | R-TST-021 | the 0.05 s `asyncio.sleep` yield removed between checks (bare `pilot.pause()`) | `test_r_tst_021_shared_wait_yields_between_checks` | KILLED (>21 checks) | `mut-021.txt` |
| M-022 | R-TST-022 | `settled` checks before its first pause (`pause_first=True` removed) | `test_r_tst_022_settled_pauses_before_its_first_check` | KILLED | `mut-022.txt` |
| M-023 | R-TST-023 | `attempts` removed from `b100_projects.wait_for`'s signature | `test_r_tst_023_shared_wait_signatures_are_kept` | KILLED | `mut-023.txt` |
| M-024 | R-TST-024 | W1 failure text changed (`timed out waiting for` → `waited too long for`) | `…_failure_texts[W1]` | KILLED | `mut-024.txt` |
| M-025 | R-TST-025 | `load_project` stops the clock when the wait notices (install-return stamp moved after the wait) | `test_r_tst_025_load_project_clock_stops_at_the_install_callback` | KILLED | `mut-025.txt` |
| M-030 | R-TST-030 | post-press sentence deleted from the conventions | `test_r_tst_007_conventions_hold_each_test_rule[R-TST-030]` | KILLED | `mut-030.txt` |
| M-031 | R-TST-031 | quit-confirm arm no longer holds the save worker (the `Hold(monkeypatch, app_module, "place_into_workarea")` install removed — the pre-`d460190` post-press form) | `test_r_tst_031_032_post_press_and_dwell_arms_keep_their_forms` | KILLED (static); the 3-of-3 parallel-lane half is owed to the LAN gate | `mut-031.txt` |
| M-032 | R-TST-032 | dwell restart removed: `render_run` calls `_rearm_attention()` without `restart=True` (M-dwell of fix round 3) | `test_tc_b97_64_a_new_set_run_restarts_the_dwell` (runtime arm), `test_r_tst_031_032…` (static) | KILLED (runtime arm RED: the dwell base stayed at the old time); the static guard stays green by design | `mut-032.txt` |
| M-040 | R-TST-040 | one real bound reverted to its literal (TC-B100-20's `report_margin` wrap removed) | `test_r_tst_040_041_every_upper_timing_bound_is_reported` | KILLED (site reported raw) | `mut-040.txt` |
| M-040/4 | R-TST-040/4 | the N-1 conditional-branch interval taint removed from the census (`IfExp` no longer propagates INTERVAL) | `test_r_tst_040_041_every_upper_timing_bound_is_reported` | SURVIVED — real gap, see analysis | `mut-040-4.txt` |
| M-041 | R-TST-041 | margin guard skipped (`unreported_upper_bounds` returns nothing) | `test_r_tst_040_041_every_upper_timing_bound_is_reported` | KILLED (the 4 planted raw bounds are not reported) | `mut-041.txt` |
| M-042 | R-TST-042 | `qc_tm_drain` removed from the `pytest_runtest_makereport` hook | `test_r_tst_042_margin_report_is_a_test_property` | KILLED (no `qc_tm` property on call/teardown report or junit XML) | `mut-042.txt` |
| M-043 | R-TST-043 | ascending-margin sort removed from the QC-TM section | `test_r_tst_043_045_qc_tm_section_rows_and_count` | KILLED (row order wrong) | `mut-043.txt` |
| M-044 | R-TST-044 | `MARGIN_FINDING_PCT` set to 10.0 | `test_r_tst_044_low_margin_prefix` | KILLED (the 15.0 row loses `LOW `) | `mut-044.txt` |
| M-045 | R-TST-045 | the count line reports every row as under 20 % | `test_r_tst_043_045_qc_tm_section_rows_and_count` | KILLED (`QC-TM: 3 bounds, 3 under 20 % margin`) | `mut-045.txt` |
| M-046 | R-TST-046 | the margin record is drained only when the phase passes (record written after a failed comparison) | `test_r_tst_046_over_bound_arm_still_reports` | KILLED (no `-20.0%` row on the failed arm) | `mut-046.txt` |
| M-047 | R-TST-047 | clock-rule sentence deleted from the conventions | `test_r_tst_007_conventions_hold_each_test_rule[R-TST-047]` | KILLED | `mut-047.txt` |
| M-048 | R-TST-048 | margin-rule sentence deleted from the conventions | `test_r_tst_007_conventions_hold_each_test_rule[R-TST-048]` | KILLED | `mut-048.txt` |
| M-050 | R-TST-050 | `StatusLog.since` capped to the app's 4-line log (`messages[mark:][-4:]`) | `test_r_tst_050_status_log_keeps_every_painted_line` | KILLED (4 of 6 painted lines) | `mut-050.txt` |
| M-051 | R-TST-051 | the oracle ratchet compares with `>=` (flags every file at its baseline) | `test_r_tst_050_status_log_keeps_every_painted_line` | KILLED (RED on the base tree) | `mut-051.txt` |
| M-052 | R-TST-052 | oracle-rule sentence deleted from the conventions | `test_r_tst_007_conventions_hold_each_test_rule[R-TST-052]` | KILLED | `mut-052.txt` |
| M-060 | R-TST-060 | census-rule sentence deleted from the conventions | `test_r_tst_007_conventions_hold_each_test_rule[R-TST-060]` | KILLED | `mut-060.txt` |
| M-070 | R-TST-070 | one FAILED line dropped from the batch CI record | — (no pytest node; the check is a diff of the record against the run's FAILED lines) | N/A — needs `gh run view 41372953464 --log-failed` (network) at E5; the committed suite has no completeness oracle for the record | — |
| M-071 | R-TST-071 | (cancel/timeout record) | — | N/A — the condition never occurred (the run completed); the case itself is marked not-testable | — |
| M-072 | R-TST-072 | the snapshot cell results dropped from the CI record | — (no pytest node) | N/A — needs the concluded job's log via `gh` at E5 | — |
| M-080 | R-TST-080 | one report golden re-pinned to `Tool version: 1.0.0rc1` | `test_r_tst_080_report_goldens_hold_no_tool_version` | KILLED | `mut-080.txt` |
| M-081 | R-TST-081 | the tool-version substitution removed from `canonical_report_bytes` | the 6 golden nodes (054b md+html, 055b, 196 addendum, 247 producer-bound, 256 document-bound, 288 pre-move) + `test_r_tst_081_golden_takes_the_package_version` | KILLED (7/7 RED) | `mut-081.txt` |
| M-082 | R-TST-082 | the canonicalizer masks the version line to any value | `test_r_tst_082_wrong_version_still_differs` | KILLED (a wrong version now compares equal) | `mut-082.txt` |
| M-090 | R-TST-090 | CI record without Inc 2's PR-run lane times | — (no pytest node, D-15) | N/A — needs Inc 2's own PR CI run | — |
| M-091 | R-TST-091 | lane 1 back to serial (`-n` removed) | — (no pytest node) | N/A — needs the first post-merge push run (≈290 min serial) | — |

## Score

- Scored mutants: 46 (53 mutants minus 7 N/A).
- KILLED: 45. SURVIVED: 1 (M-040/4).
- **Score: 45 / 46 ≈ 97.8 %** (N/A rows excluded; they are owed to the LAN gate or CI evidence, not to the pytest suite).

## Survivors and near-misses — analysis

1. **M-040/4 (SURVIVED — real gap).** With the N-1 taint removed
   (`x = timing[0] if timing else None` no longer propagates INTERVAL), the
   affected arms' upper-bound compares leave the census entirely: no raw site
   appears, so `test_r_tst_040_041`'s `sites == set()` stays green, and
   `test_r_tst_002` also stays green because those arms are still detected via
   another interval assert in the same test (verified: both nodes pass under
   the mutant; probe on a planted `/4` arm: the arm is not detected and no
   site is reported — transcript `mut-040-4.txt`). The head-tree oracle can
   see a *new* raw bound but not a *lost* bound. Only the `b3bf42e` half of
   R-TST-040/1 and /4 (the pinned 37-bound count and the `:841`/`:978`/`:1350`
   sites, owed at E5) would catch this; recommend a committed node that pins
   the reported-bound count or those three sites on the head tree.
2. **M-005/7 (KILLED, but the named case is redundant — test-design gap).**
   The planted `/7` module taints `elapsed` through `measure_mod.measure()`'s
   return profile (form (b)), so dropping form (d) alone does not lose the
   arm and `[form6]` passes. The same mutant turns every wrapped bound on the
   head tree raw, so `test_r_tst_040_041` kills it. The `/7` planted case
   does not isolate form (d) as the rulings assume.
3. **M-032 (KILLED via the faithful variant; one near-equivalent variant).**
   First tried variant — clearing `_attention`/`_attention_block` without
   `restart=True` — is near-equivalent for this scenario: `restart=True`
   already bypasses the early return, so the dwell base restamps either way
   (both nodes stayed green). The load-bearing seam is the
   `_rearm_attention(restart=True)` call site in `render_run`; removing it
   (the actual M-dwell) turns the runtime arm RED with the dwell base stuck at
   the old time.
4. **M-017 (KILLED by the right node, not the row's own).**
   `test_r_tst_015_016_017` does not assert the lane-2 `if:` conditions;
   the `success()` mutant passes it and is caught by
   `test_r_tst_012_serial_lane_runs_after_a_red_lane`. Coverage is complete
   across the two nodes but the row-to-node mapping is misleading.
5. **M-020 (KILLED; one node is not sufficient alone).** The count-bounded
   loop keeps W1's exact text and still raises, so `…_failure_texts[W1]`
   passes; the AST census node `test_r_tst_020_021` (0 `range` loops, 9
   `wait_until` calls) is the deterministic killer.
6. **M-014 / M-018 (KILLED statically; dynamic halves CI-owed).** The workflow
   text mutants die in the static tests; the behavior they guard (the
   `b514b07` arm skipping on a shallow clone; lane 1 failing on `-n` without
   xdist; the worker header) is only observable in Inc 2's own PR CI run.

No other surprises: every remaining mutant was killed by the test(s) its case
names, with the assertion firing for the mutant's stated reason.
