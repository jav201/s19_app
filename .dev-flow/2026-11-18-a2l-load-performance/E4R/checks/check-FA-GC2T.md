# CHECK — FA-GC2T

- Unit: FA-GC2T
- Tree path: ~/work/zq-fa/FA-GC2T/repo
- HEAD sha: c40b49abd011c0c2adfe68cb37d2b224bf3e112f
- Start: 2026-11-19 18:17:45 CST
- Checker: DeepSeek v4-pro (mechanical check; I did not write this unit)

---

## Step 1 — Diff hygiene

Command: `cp -a <tree> ~/work/zq-fa/chk-FA-GC2T`; in the copy `git diff > ../chk-FA-GC2T.diff`.

- Files changed: `tests/conftest.py`, `tests/test_alp_inc2_a2l_attach.py`, `tests/test_alp_inc3_snapshot_parity.py` (3 files, +473 / -41).
  - All within the brief's "Files you may edit" (the same 3 files). ✓
- CR count: `tr -cd '\r' < diff | wc -c` = 0. ✓
- Added `skip`/`skipif`/`xfail`/`sleep(` lines: 0. ✓
- `def test_` names removed and not re-added: 0 (grep `^-.*def test_` = 0). ✓
- New `def test_` added (allowed, ordered by brief): 6 (rows 3/4/5/6 + 2 files).


## Step 2 — GREEN vs base

Command (from the copy's root, CHK-BRIEF env, one line): `... -m pytest -p no:cacheprovider -q -n 0 <nodes>` and `... -n 4 -m "not serial_timing and not slow" tests/test_alp_inc2_a2l_attach.py tests/test_alp_inc3_snapshot_parity.py`.

`-n 0` node set (r038, r043, rows 3, 4, 6): `4 failed, 6 passed in 257.91s`
- FAILED `test_r038_install_exception_reenables_gc` — RED, expected (row 1).
- PASS `test_r043_install_exception_reenables_gc` — GREEN (row 2).
- PASS `test_r_a2l_refresh_051_attach_outcomes_gc_enabled` (3 params) + `..._051_project_success_gc_enabled` — GREEN (row 3, 4 nodes).
- FAILED `test_r_a2l_refresh_052_install_runs_no_full_collection` (attach) + `[R-A2L-REFRESH.052/1]` (image) + `[R-A2L-REFRESH.052/2]` (project) — RED, expected (row 4, 3 nodes).
- PASS `test_r_a2l_refresh_053_reloads_do_not_accumulate_objects` — GREEN (row 6).

Full node set `-n 4 -m "not serial_timing and not slow"` on both files: `5 failed, 66 passed in 398.48s`
- The 5 failed = r038 (ordered RED) + row-4 attach/image/project (3 ordered RED) + `test_r037_picker_snapshot_reuse[adapter-mismatch]` (pre-existing RED, see base run below).

Base state (HEAD c40b49ab with the 3 test files restored via `git show HEAD:`): `-n 0` on r038 + r043 + r037 → `1 failed, 6 passed`.
- FAILED `test_r037_picker_snapshot_reuse[adapter-mismatch]` — RED at base (pre-existing; `'?'` vs `'u16'` for AUX2/OLD_SCALAR). Still RED now (unchanged). ✓
- PASS `test_r038_install_exception_reenables_gc` — GREEN at base (masked). Now RED: this is the brief's ordered falsification (row 1 "expected now RED"), not a regression.
- PASS `test_r043_install_exception_reenables_gc` — GREEN at base, GREEN now. ✓

Nodes that passed at base and fail now: exactly one — `test_r038_install_exception_reenables_gc` — and the brief explicitly orders that transition (row 1). The 3 row-4 RED nodes are new (absent at base). No other node regressed. ✓

`--collect-only -q -m "slow"` lists `test_r_a2l_refresh_052_case06_no_mainthread_gc_pause` (row 5). ✓ (row 5 never run.)

## Step 3 — Negative controls are real

Second copy `~/work/zq-fa/chk-FA-GC2T-nc` (worker's tree), each mutation applied then reverted; only the affected node run.

1. Row 2 NC — `s19_app/tui/app/file_load.py:1999 gc.enable() -> pass`. Node `test_r043_install_exception_reenables_gc` → RED: `AssertionError: R-A2L-REFRESH.051: the cycle collector stayed disabled after the install exception: [False]`. ✓
2. Row 3 NC — `s19_app/tui/app/file_load.py:1188 gc.enable() -> pass`. Node `test_r_a2l_refresh_051_attach_outcomes_gc_enabled[R-A2L-REFRESH.051/3]` → RED: `AssertionError: R-A2L-REFRESH.051: gc disabled after the superseded attach outcome: [False]`. ✓
3. Row 6 NC — `gc.collect() -> gc.freeze()` at file_load.py:1222, loaded_state.py:893, project_load.py:1824 AND delete `walk = None` at a2l_definition.py:733. Node `test_r_a2l_refresh_053_reloads_do_not_accumulate_objects` → RED: `AssertionError: R-A2L-REFRESH.053: load 3 retained 391474 objects > 1.10 x load 2 (353497); counts=[313748, 353497, 391474, 429235, 467087]`. ✓

All 3 controls go RED under their mutation. No control stayed GREEN.

## Step 4 — Laws

Command (serial `-n 0`, CHK-BRIEF env, one line): `... -m pytest -p no:cacheprovider -q -n 0 -rfE --tb=line tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py`.

Result: `5 failed, 110 passed, 2 skipped in 462.51s` (exit 1).

Allowed RED at base (25161a00): test_r_tst_002, test_r_tst_040_041, test_r_tst_070_2, test_canon_rows_hold_the_obligation_word_once, test_at_b83_08, test_no_tracked_file_holds_a_private_token.

- `test_r_tst_040_041_every_upper_timing_bound_is_reported` — now PASSES (was RED at 25161a00; fixed by intervening commits; verified GREEN on the HEAD-test-files copy too). Not a failure. ✓
- `test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses` — RED, offenders all pre-existing `evidence/full-suite/...` files; none are the unit's 3 files. ✓ (no new offender)
- `test_canon_rows_hold_the_obligation_word_once` — RED, 3 offenders = `R-A2L-DEF.153`, `R-PICKER-CORRECT.004`, `R-PICKER-CORRECT.008` (identical rows to base). ✓ (no new offender). The unit's cited rows R-A2L-REFRESH.051/.052/.053 each contain `shall` exactly once (verified manually; they sit below the known blank-line hole after R-A2L-REFRESH.028, which is "not the unit's" per the brief).
- `test_at_b83_08_tree_holds_no_assembled_selectors` — RED, offenders shrunk (base also listed `tests/test_alp_inc2_a2l_attach.py:408`; that offender is gone), no new offender. ✓
- `test_no_tracked_file_holds_a_private_token` — RED, offenders all `.dev-flow/2026-11-18-a2l-load-performance/...`; the unit's 3 files are NOT offenders (grep count 0). ✓ (no new offender)

- `test_r_tst_002_every_timing_arm_carries_serial_timing` — RED with a NEW offender:
  `serial_timing on a test that is not a timing arm: tests/test_alp_inc2_a2l_attach.py::test_r_a2l_refresh_052_case06_no_mainthread_gc_pause`
  This is the unit's new row-5 test. Verified: on the HEAD-test-files copy (same c40b49ab, worker edits reverted) `test_r_tst_002` is `1 passed` (GREEN). The base (25161a00) offenders were 5 different lines (all fixed by intervening commits); this one offender is new and is introduced by the unit's row-5 test carrying `@pytest.mark.serial_timing` while the census does not classify it as a timing arm (its `timing_bound`/`report_margin` are hoisted out of the assert into separate statements, and `assert worst <= bound` has no census-visible interval operand).

=> **New offender inside an allowed RED (and a node GREEN at the unit's tree now RED). This is MECH-NO-GO per step 4.**

## Step 5 — Worker claims (5 re-verified)

1. Claim: "HEAD verified: c40b49ab (= 9c464b6a + FA-D10)". — TRUE. `git rev-parse HEAD` = `c40b49abd011c0c2adfe68cb37d2b224bf3e112f`; parent commit is `9c464b6a` (`git log --oneline -2`). ✓
2. Claim: "Only the 3 allowed files edited (`tests/test_alp_inc2_a2l_attach.py`, `tests/test_alp_inc3_snapshot_parity.py`, `tests/conftest.py`); no git writes; CR count 0". — TRUE. `git diff --stat` = exactly those 3 files (+473/-41); `git diff | grep -c $'\r'` = 0; `git status` shows no staged/untracked writes. ✓
3. Claim: r038 RED line `AssertionError: R-A2L-REFRESH.051: the cycle collector stayed disabled after the install exception: [False]`. — TRUE. Reproduced verbatim in my `-n 0` run. ✓
4. Claim: r043 GREEN, and its negative control (remove `file_load.py:1999 gc.enable()`) goes RED. — TRUE. r043 passed; under the mutation it fails with the same `...stayed disabled after the install exception: [False]` line. ✓
5. Claim: "Pre-existing RED `test_r037_picker_snapshot_reuse[adapter-mismatch]` fails on HEAD, not caused by this unit". — TRUE. On the HEAD-test-files copy, `-n 0 tests/...::test_r037_picker_snapshot_reuse` → `1 failed, 6 passed`, the failure being exactly `adapter-mismatch` with `'?'` vs `'u16'` for AUX2/OLD_SCALAR. ✓

(Also consistent with the report: row 3 = 4 GREEN, row 4 = 3 RED, row 6 GREEN — all reproduced in step 2; row 6 NC RED counts reproduced in step 3.)

## Step 6 — Save the diff

`~/work/zq-fa/FA-GC2T/CHECK.diff` = copy of step 1's `~/work/zq-fa/chk-FA-GC2T.diff` (3 files, +473/-41, CR 0).

## Verdict

Steps 1, 2, 3, 5, 6 PASS. Step 4 FAILS: the unit's new row-5 test
`tests/test_alp_inc2_a2l_attach.py::test_r_a2l_refresh_052_case06_no_mainthread_gc_pause`
carries `@pytest.mark.serial_timing` but is not a census-visible timing arm, so it is a
NEW offender inside the allowed-RED `test_r_tst_002_every_timing_arm_carries_serial_timing`
(which was GREEN on the unit's tree before the edit). Per step 4, a new offender inside an
allowed RED = MECH-NO-GO.

CHECK_DONE FA-GC2T MECH-NO-GO

## Orchestrator intent review (Opus, relevo-22)
GO. Tests first for the GC fix, as designed (R5-F3, DX-F3, R5-F5). Row 1/2: r038 and r043 now record `gc.isenabled()` inside `body` and assert after the `pytest.raises` block, so Textual's re-raise from `run_test` can no longer swallow the `AssertionError`; r038 is RED for the stated reason (`gc_at_end == [False]`: the attach install's `except` never re-enables GC), r043 GREEN (the loose route's worker `except` does), control RED. Row 3: four R-A2L-REFRESH.051 outcome arms GREEN, superseded-path control RED. Row 4: the `.052` spy wraps `gc.collect` and counts only calls whose caller module is one of the three install modules (`sys._getframe(1).f_globals["__name__"]`), so pytest's or Textual's own collections do not count; RED with one call per route. Row 5: the case_06 MainThread generation-2 pause arm uses a `gc.callbacks` hook removed in `finally`, bound `timing_bound(0.25)` through `report_margin`, `serial_timing` + `slow`; not run by the worker (the orchestrator's RED run is on the quiet laptop). Row 6: `.053` reload arm GREEN (objects + freeze count, loads 3–5 ≤ 1.10 × load 2); its control (freeze at the three sites and no `walk = None`) grows the count every load (313,725 → 467,544). The conftest autouse fixture only re-enables and unfreezes after each test (asserts nothing). Worker deviation accepted: the two test files were run per file because their combined `-n 4` run exceeded the 300 s node timeout.
Orchestrator RED run of row 5 (quiet laptop, load 0.63 → 1.14, tree 1dd52089 + this diff): `test_r_a2l_refresh_052_case06_no_mainthread_gc_pause` RED for the stated reason — MainThread generation-2 pauses 0.034 / 0.049 / 0.071 / **1.065 s** against `timing_bound(0.25)` (QC-TM LOW −325.9 %).

## Orchestrator ruling on the MECH-NO-GO and fix (Opus, relevo-22)
The NO-GO is real: row 5 computed `report_margin(...)` and then asserted `worst <= bound` on a separate line, so the census does not see a timing arm and law `test_r_tst_002` reported `serial_timing on a test that is not a timing arm`. Orchestrator fix in the unit tree (one statement, same semantics): `assert worst <= report_margin("R-A2L-REFRESH.052-case06-gc", worst, bound), (...)`, the census-visible form used by the other arms. After the fix: `test_r_tst_002` and `test_r_tst_040_041` 2 passed; `--collect-only -m slow` still lists the pause arm. GO.
Note (GC redesign, `frontA\GC-REDESIGN.md`): FA-GC2's freeze was not adopted (stop rule); under the operator decision D-GC the case_06 pause arm may be retired or re-pinned.
