# FA-D11c — CI lane for the heavy case_06 arms (orchestrator · Opus; runs on the merge tree alp ⊕ main)

No agent edits `~/.claude/skills`. This needs Q2 (FA-QUESTIONS). It runs only after `main` (with Front B, CI limits 180/240/45) is merged into `alp-e4r`, because the workflow file and the CI-limits law differ between the branches.

## Facts (checked 2026-11-19)
- **Merge tree `tui-ci.yml` (from `b103-fix-round`)**, with each lane's timeout:
  - PR lean `-m "not slow and not serial_timing"`, 120 min;
  - PR timing `-m "serial_timing and not slow"`, 30 min;
  - push full `-m "not serial_timing"`, 180 min;
  - push timing `-m serial_timing`, **45 min** (line 76).
- **Main's push timing lane already took 78 min** in run 44285328837 (14:54:30 → 16:12:25, failed).
- **The alp heavy arms marked `slow` + `serial_timing`** (FA-2 row 5, FA-GC2T row 5, FA-D11b row 1) add roughly 25–30 min on the laptop. Measure the real sum in M2 with `--durations=0` on `-m "slow and serial_timing"`.

## Per Q2 answer
- **A (new push-only job).**
  - Add a job `tui-ci-heavy` (push only, `needs: []`, same setup steps) running `pytest -q -rs -m "slow and serial_timing"`, with `timeout-minutes` = ⌈1.5 × measured laptop sum × CI factor 2⌉, proposed 60.
  - Change the push timing step to `-m "serial_timing and not slow"`.
  - Add one canon row for the new limit next to R-TST-015/016, with the wording style of those rows, and extend `tests/test_suite_hygiene.py::test_r_tst_015_016_017_ci_time_limits` to pin it. That is a law change: it needs the operator's Q2 answer as authority, recorded in `E4R-rulings.md`.
- **B (keep in the 45-min lane).** Change nothing. Record in `E4R-rulings.md` that the push timing lane is expected to time out until it is reduced.
- **C (laptop gate, no CI).** Change the push timing step to `-m "serial_timing and not slow"`. The heavy arms become a pre-merge gate on the laptop, with a committed transcript per merge. Record the rule in `E4R-rulings.md` and in the canon's test-policy rows (operator authority Q2).

## Verify
- `tests/test_suite_hygiene.py` (`-n 0`) on the merge tree.
- `--collect-only -q -m "slow and serial_timing"`: paste the list.
- After the push (with the operator's OK), compare CI's FAILED set with the previous run (PP-04).

## Orchestrator note (relevo-20, 2026-11-19)
- **Q2 = A** (operator verdict «Ok a todo.», PENDING P-191): take the "A (new push-only job)" branch above.
- **H = B** in the same verdict raises the `b103-fix-round` limits to push full 220 min, push timing 75 min, job 300 min (unit H, Front B). Re-read the merge tree's `tui-ci.yml` and `test_r_tst_015_016_017_ci_time_limits` before editing: the facts above (180/45/240, line 76) predate unit H.

## Orchestrator facts (relevo-29, 2026-11-20 12:26 CSTM, grepped on the merge tree `alp-e4r-mB` 2f01232b; HT-13)
- **Limit:** `tui-ci-heavy` `timeout-minutes` = ⌈1.5 × 41 min × 2⌉ = **123** (M2-REPORT: `-m "slow and serial_timing"` serially on the laptop = 41 min wall; CI factor 2). Supersedes the "proposed 60" above.
- **Merge tree `tui-ci.yml`:** job `tui-ci` 300 min; PR lane 1 120 / lane 2 30 (`serial_timing and not slow`); push lane 1 220 (`not serial_timing`) / lane 2 75 (`-m serial_timing`, line 77). Job `snapshot` advisory.
- **Collision:** after the change the push lane-2 command equals `PR_LANE_2` (`pytest -q -rs -m "serial_timing and not slow"`), so the `by_run` dicts keyed by run text in `tests/test_suite_hygiene.py` (`test_r_tst_012_…` line ~811, `test_r_tst_015_016_017_ci_time_limits` line ~883) would map both lanes to one step. Key them per event (`_lane_steps(steps, "push"|"pull_request")`).
- **Pins to update:** `PUSH_LANE_2` (line 69); `test_r_tst_011_push_runs_two_lanes` (line 799); R-TST-011's row text (canon line 535); `docs/architecture.md` line 162 ("CI lane 2 runs `-m serial_timing`"). Unchanged: R-TST-007/009 and `docs/engineering-rules.md` line 197 (release gate on the LAN host keeps full `-m serial_timing`).
- **Free id:** `R-TST-019` (0 files in the tree); `R-TST-023`/`024` are taken. Trace style: docstring `"""Traces: R-TST-0xx, …"""`. `AT-TC-REGISTRY.jsonl` has no R-TST-01x rows. No new test module (HT-15 n/a).
