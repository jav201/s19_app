# CHECK — FA-TICK4u (orchestrator-scripted mechanical check; the orchestrator did not write this unit)

- unit: FA-TICK4u; worker DeepSeek v4-pro (medium), PI_EXIT=0 in ~10 min, per-row REPORT (`FA-TICK4u` REPORT copy in the orchestrator's review folder)
- tree: fresh clone of `alp-e4r` 788ecbd1 + the integration diff (= the worker diff, md5 1441678e), host `<host>` (rtx), HT-02 environment
- script: `tools27/chk_tick4u.sh` + `chk_tick4u_mut.py` (orchestrator tools, outside the repo), the CHK-ds-fa-rtx steps; no model judgement in the run
- the product hunks are compared line by line with the FA-TICK4 scratch fix that was measured (`product-hunks-equal-scratch=yes`)
- controls: c1 `tuple(records)` again; c2 `pilot.pause(0.02)` again; c3 live (released) captures; c4 a builder that ignores known-final spans (power of the VAL_BLK check); c3+c4 together (the check without snapshots must be blind: GREEN); c5 a ~0.3 s GIL hold inside `describe_definitions` (the tick oracle must still fail a real freeze under the new harness loop)

## Transcript
```
start 09:26:03 load 0.46 0.89 0.75
HEAD 788ecbd1 diff-md5 1441678e file ~/work/zq-fa/chk4u/s19_app/__init__.py
## step1
s19_app/tui/a2l_definition.py
tests/test_alp_a2l_occupancy.py
tests/test_alp_inc3_load_responsiveness.py
 3 files changed, 116 insertions(+), 6 deletions(-)
CR=0 added-skip/xfail=0 added-time.sleep=0
removed-tests=0
product-hunks-equal-scratch=yes
tick-loop-hunk-in-diff=1
## step2 green
unit+i1_3+val_blk 4 passed in 2.78s
small[image] baseline 1 passed in 25.85s 
reg rc=1 1 failed, 846 passed in 738.61s (0:12:18)
FAILED tests/test_b103_inc9b_w.py::test_r_pe_bench_95_2_summaries_of_a_page_turn_are_not_busy_jobs
9 passed, 58 deselected in 156.12s (0:02:36)
## base re-run of the failing nodes (788ecbd1)
1 passed in 9.05s
## step3 controls (expect RED except c3+c4 = blind check without snapshots, expect GREEN)
control c1 applied
~/work/zq-fa/chk4u-nc/tests/test_alp_a2l_occupancy.py:788: AssertionError: R-A2L-REFRESH.050: describe returned with index.records holding 8000 entries
1 failed in 1.92s
control c2 applied
~/work/zq-fa/chk4u-nc/tests/test_alp_inc3_load_responsiveness.py:351: AssertionError: the gate-hold loop drove the pilot's pause 1 time(s)
1 failed in 0.28s
control c3 applied
~/work/zq-fa/chk4u-nc/tests/test_alp_a2l_occupancy_at.py:122: AssertionError: 0
1 failed in 0.18s
control c4 applied
~/work/zq-fa/chk4u-nc/tests/test_alp_a2l_occupancy_perf.py:450: AssertionError: 1000 known-final VAL_BLK records kept open upper reachability
1 failed in 0.33s
control c3 applied
control c4 applied
1 passed in 0.32s
control c5 applied
~/work/zq-fa/chk4u-nc/tests/test_alp_inc3_load_responsiveness.py:663: AssertionError: {'gate_elapsed': 0.20954840899503324, 'gate_ticks': 3, 'install_worst_stall': 1.7081689309852663, 'label': 'R-A2L-REFRESH.050 small im
1 failed in 26.85s
## step4 laws
laws rc=1 4 failed, 113 passed in 416.98s (0:06:56)
FAILED tests/test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses
FAILED tests/test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once
FAILED tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors
FAILED tests/test_no_private_tokens.py::test_no_tracked_file_holds_a_private_token
E     line 1373 R-A2L-DEF.153: 'shall' appears 2 times
E     line 4248 R-PICKER-CORRECT.004: 'shall' appears 2 times
E     line 4252 R-PICKER-CORRECT.008: 'shall' appears 2 times
end 09:50:03
CHK4U_DONE
```

## Follow-up runs (`tools27/chk4u_extra.sh`, same host, serial `-n 0`)
```
## c5 detail
tests/test_alp_inc3_load_responsiveness.py:663: in _assert_small_oracle
assert run["tick_failures"] == 0, run
E   AssertionError: {'gate_elapsed': 0.2077, 'gate_ticks': 4, 'install_worst_stall': 1.105, 'label': 'R-A2L-REFRESH.050 small image', ...}
E   assert 2 == 0
1 failed in 26.71s
## c5 baseline on the fix tree
[R-A2L-REFRESH.050 small image] run: gate_ticks=4 gate_elapsed=0.210s install_worst_stall=1.696s tick_observations=187 tick_failures=0
1 passed in 25.98s
bench_95_2 fix run 1-3: 1 passed (7.28 / 7.72 / 7.56 s), load 1.45-1.58
bench_95_2 base run 1-3: 1 passed (7.57 / 7.52 / 7.68 s), load 1.39-1.55
```

## Verdict
**MECH-GO.** Step 1 clean (3 files, CR 0, no skip/xfail/`time.sleep`, no test removed, product hunks equal to the measured scratch fix, the `_tick_loop` hunk present). Unit nodes + `at_alp_i1_3` + `158_1[val_blk]` 4 passed; small `[image]` arm GREEN. Regression over the 21 files that reach `describe_definitions`, the occupancy index or the Inc 3 harness (`-m "not serial_timing and not slow"`, `-n 8`): 846 passed, 1 failed — `test_b103_inc9b_w.py::test_r_pe_bench_95_2_…` (a timing node outside this unit's code path; passes on base under `-n 4` and 3/3 serial on both trees → load-sensitive under `-n 8`, recorded as such, not called flaky (HT-07); P-243 saw it under CI load). Controls c1–c4 RED at the expected assertion; c3+c4 GREEN (the VAL_BLK check was blind without build-time snapshots, the FA-TICK4 side finding); c5 RED with `tick_failures == 2` (the new loop keeps the oracle's power). Laws: 4 failed = the inherited base-alp set (070_2, canon obligation word R-A2L-DEF.153 / R-PICKER-CORRECT.004/.008, at_b83_08, no_private_tokens). Timing is decided on the quiet laptop (M2c), not here.

# FA-TICK4u — intent review (orchestrator, Opus 5.5, relevo-27)

Verdict: **GO**.

- Product hunks: exactly `diffs/FA-TICK4-scratch.diff` (the measured FA-TICK4 fix (i); the scripted check compares the +/- lines). `_OccupancyIndex.records` becomes the builder's list and `position_by_object` its dict, so describe's existing `release_in_slices(*(f for f in index if isinstance(f, (list, dict))))` empties them; readers use only `len()`, indexing and `.get` (FA-TICK4 Q2), and the case_06 digest is identical (FA-TICK4).
- Harness hunk (ii): `_tick_loop` yields with `asyncio.sleep(0.02)` instead of `pilot.pause(0.02)`. The ticks are still the app's own `set_timer` chain (`TickTimer`), the window opens and closes at the same points, and only the test-made UI flood (one callback per widget per pause) is gone. The check's control c5 (a ~0.3 s GIL hold inside `describe_definitions`) shows the oracle still fails a real freeze under (ii).
- Row 2 (`test_r_a2l_refresh_050_gate_hold_loop_does_not_drive_the_pilot`): a deterministic pin on the harness (fake pilot, timer, gate; no timing). It encodes why: each `pilot.pause` was a test-made load in the measured window. RED under the revert (c2).
- Row 3 (`_install_counters` build-time snapshots, live index still returned): restores `test_at_alp_i1_3` and makes the perf VAL_BLK `open_known_final` check read what the builder saw. Its power is shown by c4 (a builder that ignores known-final spans → `158_1[val_blk]` RED) and its former blindness by c3+c4 (live captures → GREEN).
- Row 4 (`test_r_a2l_refresh_050_describe_frees_its_occupancy_index_before_return`): return-event oracle on the target code object with a `seen` guard (cannot pass vacuously); both containers empty; result equal to a no-op release run (keys, order, values); profiler restored in `finally`. RED under `tuple(records)` (c1).
- No new module (TC-607 unchanged); no skip/xfail/`time.sleep`; nothing removed. The worker's HT-03 note (a bare `python -I -c` resolves the shared editable install) is a probe detail: every pytest run imported the tree (`s19_app.__file__` in the check transcript).
