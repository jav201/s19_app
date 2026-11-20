# CHECK — FA-TICKac (mechanical check, CHK-ds)

- unit: FA-TICKac
- tree path: ~/work/zq-fa/FA-TICKac/repo
- HEAD sha: b5bc470b700228de68836639ec5debf7a53e340b
- start time: Fri Nov 20 01:01:21 AM CST 2026


## Step 1 — Diff hygiene
Command: `cp -a ~/work/zq-fa/FA-TICKac/repo ~/work/zq-fa/chk-FA-TICKac`; in the copy `git diff > ../chk-FA-TICKac.diff`.
- files changed (4, all within the brief's "Files you may edit"):
  - s19_app/tui/app/file_load.py
  - s19_app/tui/app/project_load.py
  - tests/test_alp_inc2_a2l_attach.py
  - tests/test_alp_inc3_snapshot_parity.py
- `git diff --stat`: 4 files changed, 272 insertions(+), 3 deletions(-)
- CR count (`tr -cd '\r' < ../chk-FA-TICKac.diff | wc -c`): 0  (PASS)
- added skip/skipif/xfail/sleep( lines: 0  (PASS)
- removed `def test_` names: none  (PASS)
- added `def test_` names: test_r_a2l_refresh_049_attach_worker_never_reprs_its_request, test_r_a2l_refresh_040_load_workers_never_repr_their_request, test_r_a2l_refresh_050_project_worker_runs_no_collection, test_r_a2l_refresh_051_project_outcomes_gc_enabled (all new, in the brief's order)

## Step 2 — GREEN vs base
Node set run on the copy (env block from CHK-BRIEF, `timeout 1200`).

Command A (new nodes of rows 2,5,6 + the brief's named parity/inc2 nodes, `-n 0`):
`S=$HOME/work/zq-fa/chk-FA-TICKac-state; mkdir -p $S/home/<runner-home> $S/tmp $S/x; timeout 1200 env -i PATH=/usr/bin:/bin HOME=$S/home/<runner-home> XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q -n 0 -k "test_r_a2l_refresh_040_load_workers_never_repr_their_request or test_r_a2l_refresh_050_project_worker_runs_no_collection or test_r_a2l_refresh_051_project_outcomes_gc_enabled or test_r_a2l_refresh_051_project_success_gc_enabled or test_r043 or test_r048 or test_r_a2l_refresh_052 or test_r_a2l_refresh_049_attach_worker_never_reprs_its_request or test_r_a2l_refresh_051_attach_outcomes_gc_enabled or test_r038_install_exception_reenables_gc" tests/test_alp_inc3_snapshot_parity.py tests/test_alp_inc2_a2l_attach.py < /dev/null`
Summary: `32 passed, 59 deselected in 498.39s (0:08:18)` (all GREEN).

Command B (parity file, `-n 4 -m "not serial_timing and not slow"`):
Summary: `45 passed in 220.70s (0:03:40)`.

Command C (inc2 file, `-n 4 -m "not serial_timing and not slow"`):
Summary: `33 passed in 269.53s (0:04:29)`.

Command D (regression, `-n 4 -rf` on the three b100 files):
Summary: `3 failed, 192 passed, 1 skipped in 334.13s (0:05:34)`.
Failing node ids:
- tests/test_b100_busy.py::test_tc_b100_51_every_baseline_bar_site_maps_to_a_seam_event
- tests/test_b100_busy.py::test_tc_b100_50_project_raise_ends_the_action_first
- tests/test_b100_busy.py::test_tc_b100_51_twelve_b_seam_sites_sit_in_the_workers_and_handlers

Base-RED nodes and result now: the 3 above are RED at base b5bc470b (re-verified on a fresh clone from ~/work/zq-fa/fa.bundle, `-n 0 -rf`):
`3 failed in 4.41s` (same 3 node ids) → all INHERITED.
Nodes that passed at base and fail now: none (0 NEW). PASS.

## Step 3 — Negative controls are real
Copy `~/work/zq-fa/chk-FA-TICKac-nc`, one mutation each, fresh copy per control.

Control 1 (row 1): dropped `description="project load worker"` from the `@work` decorator in s19_app/tui/app/project_load.py:1421 → project arm of 040.
Command: `... -m pytest -p no:cacheprovider -q -n 0 "tests/test_alp_inc3_snapshot_parity.py::test_r_a2l_refresh_040_load_workers_never_repr_their_request[R-A2L-REFRESH.041/3]" < /dev/null`
Summary: `1 failed in 5.01s`
RED line: `AssertionError: R-A2L-REFRESH.040/.041: the project load worker admission rendered its request: ['ProjectLoadRequest']`  (PASS — control goes RED)

Control 2 (row 3): removed `gc.disable()` (first statement of `_project_load_worker`) in s19_app/tui/app/project_load.py → 050.
Command: `... -m pytest -p no:cacheprovider -q -n 0 "tests/test_alp_inc3_snapshot_parity.py::test_r_a2l_refresh_050_project_worker_runs_no_collection" < /dev/null`
Summary: `1 failed in 5.76s`
RED line: `AssertionError: R-A2L-REFRESH.050: a collection ran off the main thread during the project load: ['MainThread', ..., 'asyncio_0', ...]`  (PASS)

Control 3 (row 4): removed `if not gc.isenabled(): gc.enable()` from the refusal branch in `_on_project_loaded` → 051 refusal arm.
Command: `... -m pytest -p no:cacheprovider -q -n 0 "tests/test_alp_inc3_snapshot_parity.py::test_r_a2l_refresh_051_project_outcomes_gc_enabled[R-A2L-REFRESH.051/4]" < /dev/null`
Summary: `1 failed in 4.06s`
RED line: `AssertionError: R-A2L-REFRESH.051: gc disabled after the refusal project outcome: [False]`  (PASS)

All three controls go RED under their mutation. No control stays GREEN. PASS.

## Step 4 — Laws
Command (serial, from the copy root):
`S=$HOME/work/zq-fa/chk-FA-TICKac-state; mkdir -p $S/home/<runner-home> $S/tmp $S/x; timeout 1200 env -i PATH=/usr/bin:/bin HOME=$S/home/<runner-home> XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q -n 0 -rfE --tb=line tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py < /dev/null`
Summary: `4 failed, 111 passed, 2 skipped in 429.56s (0:07:09)`

Failing nodes (all within the allowed-RED list at base 25161a00):
- test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses (allowed) — offenders all in .dev-flow/*evidence* and steps.log; grep of the full `--tb=long` output shows none of the unit's 4 files.
- test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once (allowed) — offenders: R-A2L-DEF.153, R-PICKER-CORRECT.004, R-PICKER-CORRECT.008 (exactly the base offenders; no new offender).
- test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors (allowed) — offenders in tests/test_b103_a2l_refresh.py and tests/test_b103_picker_model.py only (not the unit's files).
- test_no_private_tokens.py::test_no_tracked_file_holds_a_private_token (allowed) — offenders in .dev-flow/2026-11-18-a2l-load-performance/** only (not the unit's files).

Two of the six allowed base-REDs are now GREEN (test_r_tst_002_every_timing_arm_carries_serial_timing, test_r_tst_040_041_every_upper_timing_bound_is_reported) — an improvement, not a new RED.

Canon rows cited by the unit verified directly (the known hole): the parser sees 3356 rows and DOES include R-A2L-REFRESH.040/.041/.049/.050/.051 (lines 1482/1483/1491/1492/1493); each has form ∈ {When, While}, 3 cells, and exactly 1 "shall". No new offender inside any allowed RED.

Result: no RED outside the allowed list; no new offender. PASS.

## Step 5 — Worker claims (re-verified)
1. "HEAD: b5bc470b700228de68836639ec5debf7a53e340b" (REPORT header) → TRUE. `git -C ~/work/zq-fa/FA-TICKac/repo rev-parse HEAD` = b5bc470b700228de68836639ec5debf7a53e340b.
2. "git diff --stat: 4 files changed, 272 insertions(+), 3 deletions(-)" → TRUE. Re-produced in step 1 on the copy.
3. "git diff | grep -c $'\r': 0" → TRUE. `tr -cd '\r' < chk-FA-TICKac.diff | wc -c` = 0.
4. New nodes of rows 2/5/6 = "7 passed" → TRUE. `-n 0 -k "<the 7 new nodes>"` → `7 passed, 84 deselected in 84.05s (0:01:24)` (REPORT said 82.75s; timing is indicative on the shared host, count matches exactly).
5. The 3 `test_b100_busy.py` failures are INHERITED (fail on base b5bc470b) → TRUE. Fresh clone of fa.bundle at b5bc470b, `-n 0 -rf` on the 3 node ids → `3 failed in 4.41s` (same ids).

Extra re-verified: parity file `45 passed` and inc2 file `33 passed` (`-n 4 -m "not serial_timing and not slow"`) → both TRUE (step 2).
All 5 claims TRUE.

## Step 6 — Diff saved
`~/work/zq-fa/FA-TICKac/CHECK.diff` = copy of step 1's diff (md5 ea5a477ef1c29ac2b889c70ba9cf6f71, identical to REPORT's start/final md5).

## Verdict
Step 1 (diff hygiene): PASS — 4 files all within the allowed set, CR 0, no skip/xfail/sleep, no removed test names.
Step 2 (GREEN vs base): PASS — 7 new nodes GREEN, parity 45 passed, inc2 33 passed, 3 busy failures all INHERITED (reproduced on base b5bc470b), 0 NEW.
Step 3 (negative controls): PASS — all 3 controls go RED under their mutation.
Step 4 (laws): PASS — only the 6 allowed base-REDs (4 still RED with identical offenders, 2 now GREEN); no other RED, no new offender.
Step 5 (claims): PASS — all 5 re-verified TRUE.
CHECK_DONE FA-TICKac MECH-GO

## Orchestrator intent review (Opus, relevo-24)
GO (pending CHK-ds). Worker timed out (PI_EXIT=124) with a complete 4-file diff; MD-06 report-only session rebuilt `FA-TICKac-REPORT.md` with the tree unchanged (diff md5 `ea5a477e…` at start, end and in the frozen `diffs/FA-TICKac.diff`).
- **Rows 1–2 (admission `repr`, FA-TICK culprit 3).** The three load workers carry a fixed `description=`, so Textual 8.2.8 no longer renders the request (which carries the parsed A2L) with `repr()` on the UI thread; case_06 image admission measured 3.6–4.0 s before. The oracle counts calls of the three request classes' `__repr__` during one load per route: `[]` with the fix, `['ProjectLoadRequest']` under the control. The defect came with alp itself (f34b998d put the payload into the worker context), so it is fixed here (DF-04 a). Trace: image → R-A2L-REFRESH.040, project → .041, attach → .049 (the admission is part of those totals / the UI-thread capture).
- **Rows 3–6 (project worker GC, FA-TICK culprit 2).** `gc.disable()` is the first statement of `_project_load_worker`, as `_a2l_attach_worker` already does (D-13 extended to the whole project worker; case_06: 9–11 worker gen2 collections of 0.07–0.55 s before). Every outcome re-enables: the refusal branch is the one gap that only opens with the entry disable (orchestrator catch, HT-13) and is now closed; worker failure, superseded and install paths were already covered. `.050` oracle: no collection off the main thread during a project load (control: collections on `Dummy-1`/`asyncio_0`); `.051/4-6`: GC enabled after refusal, worker failure, superseded (control: `[False]` after refusal).
- Regression: `test_b100_busy.py` 3 failed = inherited (fail on the base clone b5bc470b and are in main 3afebf90's CI FAILED set: `test_tc_b100_50_project_raise_ends_the_action_first`, `test_tc_b100_51_every_baseline_bar_site_maps_to_a_seam_event`, `test_tc_b100_51_twelve_b_seam_sites_sit_in_the_workers_and_handlers`); load_question 58 passed / 1 skipped; session_reset 20 passed; parity file 45 passed; inc2 file 33 passed (non-timing, non-slow, rtx).
- Residual (not this unit): FA-TICK's parse-phase ticks (outside the window) and the image-payload ticks (FA-TICK2 → FA-TICK2u).
