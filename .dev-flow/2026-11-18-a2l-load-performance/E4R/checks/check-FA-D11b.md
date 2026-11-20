# CHECK — unit FA-D11b (mechanical)

- unit: FA-D11b
- tree: ~/work/zq-fa/FA-D11b/repo
- HEAD sha: 449869815f47ccdbca6ec70c9409ba7c456776ae
- start: Thu Nov 19 11:18:01 PM CST 2026

## Step 1 — Diff hygiene

Command:
`cp -a ~/work/zq-fa/FA-D11b/repo ~/work/zq-fa/chk-FA-D11b && cd ~/work/zq-fa/chk-FA-D11b && git diff > ../chk-FA-D11b.diff`

- Files changed (must be within "Files you may edit" = tests/test_alp_inc3_load_responsiveness.py, tests/test_alp_a2l_occupancy_at.py):
  - tests/test_alp_a2l_occupancy_at.py
  - tests/test_alp_inc3_load_responsiveness.py
  → OK (both are in the allowed set).
- CR count: `tr -cd '\r' < chk-FA-D11b.diff | wc -c` → 0 (OK).
- Added skip/skipif/xfail/sleep( lines: none (OK).
- Removed `def test_` names: none (OK).
- Added `def test_` names: `test_r_a2l_refresh_050_small_routes_same_oracle` (the row-4 test the brief orders; OK).

Step 1 = PASS.

## Step 2 — GREEN vs base

Brief's runnable node set (row 4, `-n 0`): the three params of `test_r_a2l_refresh_050_small_routes_same_oracle`.

Command (from the copy's root):
`S=$HOME/work/zq-fa/chk-FA-D11b-state; mkdir -p $S/home/<runner-home> $S/tmp $S/x; timeout 1200 env -i PATH=/usr/bin:/bin HOME=$S/home/<runner-home> XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q -n 0 tests/test_alp_inc3_load_responsiveness.py::test_r_a2l_refresh_050_small_routes_same_oracle < /dev/null`

Summary: `2 failed, 1 passed in 41.32s`
- PASS `...::test_r_a2l_refresh_050_small_routes_same_oracle[a2l-only]`
- FAIL `...::test_r_a2l_refresh_050_small_routes_same_oracle[image]` at tests/test_alp_inc3_load_responsiveness.py:606 (`assert run["tick_failures"] == 0`) — tick_failures=1, install_worst_stall≈1.63s (recorded, not asserted).
- FAIL `...::test_r_a2l_refresh_050_small_routes_same_oracle[project-pair]` at :606 — tick_failures=1, install_worst_stall≈1.93s.

Base comparison:
- These three nodes are NEW (added by this worker; they do not exist at base 25161a00). Therefore no node "passed at base and fails now" — none (the constraint is vacuously satisfied).
- The 6 base-RED law nodes (from the base transcript laws-base-alp.txt) are re-run in Step 4 below; none of them is part of this unit's node set.
- The 2 REDs above are the in-window tick jitter on this shared rtx host, which the brief explicitly defers ("Never measure or decide a timing result on this host"; "indicative only"). Matches the worker's REPORT ("2 failed, 1 passed ... indicative, not decided"). Decision left to the orchestrator on the quiet host.

Step 2 = PASS (no base regression; the 2 new-node REDs are timing-indicative and deferred).

## Step 3 — Negative controls are real

Second copy `~/work/zq-fa/chk-FA-D11b-nc` (from the clean chk copy), one mutation at a time, run only the affected node `[project-pair]`.

### Control 1 — row 2 (worker's actual mutation, from REPORT.md)
Mutation: in `TickTimer._fire`, add `time.sleep(0.3)` before recording (blocks the UI thread 0.3 s on every in-window tick).
Command: `S=$HOME/work/zq-fa/chk-FA-D11b-state; ... pytest -q -n 0 tests/test_alp_inc3_load_responsiveness.py::test_r_a2l_refresh_050_small_routes_same_oracle[project-pair] < /dev/null`
RED line: `E       assert 5 == 0` (at tests/test_alp_inc3_load_responsiveness.py:606, `assert run["tick_failures"] == 0`; tick_failures=5, gate_elapsed≈1.04s, install_worst_stall≈2.11s). → RED (worker's report said `assert 6 == 0`; the count varies run-to-run, both RED).

### Control 2 — row 4 (worker's actual mutation)
Mutation: in `TimedGate._wrap`, run the producer through `self_.call_from_thread` on the UI thread with `time.sleep(0.3)` and block the worker until done.
Command: same node `[project-pair]`.
RED line: `E       assert 3 == 0` (same :606 line; tick_failures=3, gate_elapsed≈0.38s, install_worst_stall≈1.67s). → RED (matches worker's `assert 3 == 0`).

Both controls go RED under their mutation → the assertions are real. Step 3 = PASS.

## Step 4 — Laws (serial, `-n 0`)

Command: `S=$HOME/work/zq-fa/chk-FA-D11b-state; mkdir -p $S/home/<runner-home> $S/tmp $S/x; timeout 1200 env -i PATH=/usr/bin:/bin HOME=$S/home/<runner-home> XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q -n 0 -rfE --tb=line tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py < /dev/null`

Summary: `5 failed, 110 passed, 2 skipped in 401.06s`

Allowed RED at base (25161a00) and result now:
- `test_r_tst_002_every_timing_arm_carries_serial_timing` — FAILED now, but with a **NEW offender**: `serial_timing on a test that is not a timing arm: tests/test_alp_inc3_load_responsiveness.py::test_r_a2l_refresh_050_small_routes_same_oracle` (the worker's new row-4 test). The base offenders for this node (inc2_a2l_attach timing arms missing serial_timing, occupancy_perf not-a-timing-arm) are all gone; the only offender is the new test. → **NEW offender inside an allowed RED = MECH-NO-GO.**
- `test_r_tst_040_041_every_upper_timing_bound_is_reported` — PASSED now (was RED at base). OK.
- `test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses` — FAILED (allowed). Offenders = the same base evidence files (b103-g3-recents/RESULT, b103-g3-ui-a/red-before.{junit.xml,log}, inc-9b/evidence-e4/..., steps.log). No new offender from this unit (the unit added no evidence; `git status` shows only the 2 test files).
- `test_canon_rows_hold_the_obligation_word_once` — FAILED (allowed). Offenders exactly the 3 base rows: R-A2L-DEF.153 (line 1373), R-PICKER-CORRECT.004 (line 4248), R-PICKER-CORRECT.008 (line 4252). No new offender.
- `test_at_b83_08_tree_holds_no_assembled_selectors` — FAILED (allowed). Offenders now only the b103 files (line numbers shifted vs base); the inc2_a2l_attach.py:408 base offender is gone. This unit touched none of these.
- `test_no_tracked_file_holds_a_private_token` — FAILED (allowed). Offender list identical to base (.dev-flow/... files). No new offender.

Step 4 = **NO-GO**: new offender inside allowed-RED `test_r_tst_002` (the worker's `test_r_a2l_refresh_050_small_routes_same_oracle` carries `serial_timing` but the census does not classify it as a timing arm — its `timing_bound(TICK_BOUND_S)` sits in `_gate_summary` (a computation, not an assert) and `_assert_small_oracle` asserts only dict values, so no margin call / wall-clock interval appears in an assert).

## Step 5 — Worker claims (5 re-verified)

1. Claim: HEAD sha = `449869815f47ccdbca6ec70c9409ba7c456776ae`. Evidence: `git rev-parse HEAD` in the copy → `449869815f47ccdbca6ec70c9409ba7c456776ae`. **TRUE**.
2. Claim: only the 2 allowed files changed (`git diff --stat`: test_alp_a2l_occupancy_at.py, test_alp_inc3_load_responsiveness.py). Evidence: `git diff --name-only` → exactly those two. **TRUE**.
3. Claim: `git diff | grep -c $'\r'` = 0. Evidence: `tr -cd '\r' < chk-FA-D11b.diff | wc -c` = 0. **TRUE**.
4. Claim (Row 1 collect-only after): `-m "serial_timing and not slow"` = 3 small nodes; `-m "not slow and not serial_timing"` = `test_at_alp_i1_3_describe_to_encode_overlap_safety` only; `-m slow` = 6 nodes. Evidence: collect-only reproduced exactly (3 / 1 / 6). **TRUE**.
5. Claim (Row 4 negative control): RED line `assert 3 == 0`. Evidence: my re-applied mutation in `chk-FA-D11b-nc` on `[project-pair]` → `E       assert 3 == 0` (line 606). **TRUE** (exact match).

Note (not one of the 5, for completeness): the worker's Row-2 negative-control claim was `assert 6 == 0`; my re-application produced `E       assert 5 == 0` — still RED (the count is run-to-run variable), so the claim "the control goes RED" is TRUE; the exact count 6 vs 5 differs.

Step 5 = PASS.

## Step 6 — Save the diff

`cp -a ~/work/zq-fa/chk-FA-D11b.diff ~/work/zq-fa/FA-D11b/CHECK.diff` (464 lines; privacy scan of the diff: CLEAN).

## Verdict

- Step 1 PASS, Step 2 PASS (no base regression), Step 3 PASS (both negative controls RED), Step 4 **NO-GO** (new offender in allowed-RED `test_r_tst_002`), Step 5 PASS.
- MECH-NO-GO because Step 4's rule "a new offender inside an allowed RED = MECH-NO-GO" is triggered: `test_r_a2l_refresh_050_small_routes_same_oracle` carries `@pytest.mark.serial_timing` but the suite census does not classify it as a timing arm (its `timing_bound(TICK_BOUND_S)` sits in `_gate_summary` as a computation, and `_assert_small_oracle` asserts only dict values, so no margin call / wall-clock interval appears in any assert).

CHECK_DONE FA-D11b MECH-NO-GO

## Orchestrator intent review (Opus, relevo-23)
GO after two orchestrator fixes in the worker's tree, both made before integration and recorded here (precedent: FA-GC2T row 5).
- Rows 1–5 as designed (operator D11, Q1 = A, R4-F1): the six case_06 nodes move to `slow` (push lane), the tick failures count only observations due inside the Q1 window (preparation entry → install dispatch), `install_worst_stall` is recorded and not asserted, the asserts cite R-A2L-REFRESH.050, and the new small same-oracle arms run in the PR timing lane with no duration budget. Row 2's control moved from `step_busy` to `TickTimer._fire` because `step_busy` lands outside the window on every route (worker's reasoning checked against the routes; accepted).
- **Fix 1 (instrument defect, pre-existing; found from the worker's open question 1).** `_one_image_run` waited a fixed 10 s for a typed-load confirm modal the route never pushes, while the worker sat in the 0.20 s producer gate: M1's case_06 `.040` run shows `gate_elapsed` 10.08 s against 0.22–0.29 s on the project routes, so `.040`'s total carried about 10 s of test-side hold and would have inflated the D1 bound. Now it waits for "modal or gate entered" and presses `y` only when the modal is up; small image `gate_elapsed` 10.3 → 0.26 s.
- **Fix 2 (the CHK-ds MECH-NO-GO was real).** The `.050` bound was asserted only as a count (`tick_failures == 0`), so the census did not see the small arms as timing arms (law 002: "serial_timing on a test that is not a timing arm") and QC-TM never reported the tick margin. The worst in-window lateness is now recorded (`window_worst`) and asserted through `report_margin` against the same `timing_bound(0.10)` in both oracles (equivalent to the count; the count assert stays). Laws 002 + 040_041 on the fixed tree: 9 passed; the small `a2l-only` arm reports 0.062 s / 0.100 s.
- Indicative only (rtx, shared): the small `image` and `project-pair` arms show 1–4 in-window late ticks (~0.14–0.17 s). Decided on the quiet laptop after FA-TICK, which owns the attribution (Q1); they are recorded as expected-RED-until-decided, not excused.
