# CHECK — FA-KEY mechanical check

Unit: FA-KEY
Tree: ~/work/zq-fa/FA-KEY/repo
HEAD: 35d69a03f4f07c704857c2915b373b536a0bd17f
Start: Thu Nov 19 16:33:18 CST 2026

## Step 1 — Diff hygiene

Command: `cp -a ~/work/zq-fa/FA-KEY/repo ~/work/zq-fa/chk-FA-KEY`; in the copy `git diff > ../chk-FA-KEY.diff`.

- Files changed: `tests/test_alp_inc2_a2l_attach.py` only (within the brief's "Files you may edit"). PASS.
- CR count: `tr -cd '\r' < chk-FA-KEY.diff | wc -c` = 0. PASS.
- Added `skip`/`skipif`/`xfail`: none. PASS.
- Added `sleep(` lines: 2 — `await asyncio.sleep(0.005)` (diff line 111, the bounded 5 ms poll the brief's Helper explicitly orders) and `time.sleep(1.5)` (diff line 281, the synthetic UI-thread block the brief's row-5 arm-1 explicitly orders). Neither is a skip/xfail or a fixed-delay product-wait; both are brief-ordered. Noted, not a violation.
- `def test_` names removed and not re-added: 0. PASS.
- `def test_` added: 1 — `test_r033_key_ack_instrument_controls` (brief row 5 orders this new test). PASS.

Step 1 verdict: PASS.

## Step 2 — GREEN vs base (unit node set)

Command (from `~/work/zq-fa/chk-FA-KEY`, `-n 0`): the 10-node set (r033 arms copy/parse/enrichment/definitions/request-snapshot; r034 arms enrichment/definitions/request-snapshot; r033_key_ack_instrument_controls ui-block-detected/busy-worker-not-penalized).

Summary: `10 passed in 135.74s (0:02:15)`.

- Unit node set: all GREEN now.
- Nodes that passed at base and fail now: none (all 10 GREEN).
- Base-RED nodes (from `~/work/zq-fa/briefs/laws-base-alp.txt`, 6 failed at 25161a00) and their "result now" are finalized in Step 4 (Laws). Two base-RED items reference this unit's file: `test_r_tst_002` (missing `serial_timing` on `test_at_alp_i2_2_case06_keys_and_progress` and `test_r033_key_latency`) and `test_r_tst_040_041` (`report_margin` missing at `test_alp_inc2_a2l_attach.py:609`). The `:609` finding is absorbed by the worker (the helper now reports via `report_margin` at line 729); the `serial_timing`-mark items are outside the unit brief's ordered edits and sit inside the allowed-RED law — confirmed in Step 4.

## Step 3 — Negative controls are real

Second copy `~/work/zq-fa/chk-FA-KEY-nc`. Three worker mutations re-applied one at a time (file restored from the pristine copy between runs). All three went RED.

1. Row 1 — `s19_app/tui/app/navigation.py` `on_key`: `__import__("time").sleep(1.5)` as first statement. Node `test_r033_key_latency[parse]`.
   RED: `E   AssertionError: key 'tab' not acknowledged within 1.0 s (1.515 s)` / `E   assert 1.5149297589960042 <= 1.0` (tests/test_alp_inc2_a2l_attach.py:729). `1 failed in 193.75s`.

2. Row 3 — `s19_app/tui/app/file_load.py` `_start_a2l_load`: `time.sleep(1.2)` right after `image_mem_map = MappingProxyType(dict(current_file.mem_map))`. Node `test_r033_key_latency[request-snapshot]`.
   RED: `E   AssertionError: key 'tab' not acknowledged within 1.0 s (1.274 s)` / `E   assert 1.2743949750001775 <= 1.0` (tests/test_alp_inc2_a2l_attach.py:1347). `1 failed in 26.14s`.

3. Row 5 — `tests/test_alp_inc2_a2l_attach.py` `_key_ack_latency`: `t0 = time.monotonic(); await pilot.press(key)` instead of `_deliver_key`. Node `test_r033_key_ack_instrument_controls[busy-worker-not-penalized]`.
   RED: `E   AssertionError: key 'tab' not acknowledged within 1.0 s (2.130 s)` / `E   assert 2.129914261997328 <= 1.0` (tests/test_alp_inc2_a2l_attach.py:730). `1 failed in 5.33s`.

Step 3 verdict: PASS (no control stayed GREEN).

## Step 4 — Laws

Command (from `~/work/zq-fa/chk-FA-KEY`, `-n 0`, timeout 1200):
`S=$HOME/work/zq-fa/chk-FA-KEY-state; mkdir -p $S/home/<runner-home> $S/tmp $S/x; timeout 1200 env -i PATH=/usr/bin:/bin HOME=$S/home/<runner-home> XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 /data/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q -n 0 tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py < /dev/null`

Summary: `5 failed, 110 passed, 2 skipped in 465.23s (0:07:45)`.

Base (25161a00): `6 failed, 109 passed, 2 skipped`.

- `test_r_tst_040_041_every_upper_timing_bound_is_reported` now PASSES (base-RED). The `test_alp_inc2_a2l_attach.py:609` "timing bound without report_margin" finding is absorbed (helper now reports via `report_margin` at line 729). Good.
- Remaining 5 RED are all in the allowed-RED list: `test_r_tst_002_every_timing_arm_carries_serial_timing`, `test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses`, `test_canon_rows_hold_the_obligation_word_once` (offenders R-A2L-DEF.153, R-PICKER-CORRECT.004/.008 only — unchanged), `test_at_b83_08_tree_holds_no_assembled_selectors` (offenders incl. `test_alp_inc2_a2l_attach.py:408`, unchanged), `test_no_tracked_file_holds_a_private_token` (offenders in `.dev-flow/…`, unchanged).
- FAIL — new offender inside an allowed RED. `test_r_tst_002_every_timing_arm_carries_serial_timing` now lists a THIRD `timing arm without serial_timing` for this file: `tests/test_alp_inc2_a2l_attach.py::test_r034_progress_throughout`. Base offenders for this law in the file were only `test_at_alp_i2_2_case06_keys_and_progress` and `test_r033_key_latency` (plus the three occupancy tests). The new offender is caused by the worker's row-4 edit, which added `assert all(gap <= timing_bound(1.0) …)` to `test_r034_progress_throughout[request-snapshot]`, turning that test into a timing arm (census `_MARGIN_FUNCS` = `{timing_bound, report_margin}`) without adding `@pytest.mark.serial_timing`.
  Current offender list (6): test_at_alp_i2_2_case06_keys_and_progress, test_r033_key_latency, **test_r034_progress_throughout (new)**, test_r_a2l_def_158_1, test_r_a2l_def_158_2, test_r_a2l_def_164_1.
  Known-hole note: N/A (FA-KEY edits only the test file; canon offenders are the allowed base set).

Step 4 verdict: FAIL → MECH-NO-GO.

## Step 5 — Worker claims (5 re-verified)

1. HEAD sha `35d69a03` — TRUE. `git rev-parse HEAD` = `35d69a03f4f07c704857c2915b373b536a0bd17f`.
2. `git diff --stat` = `tests/test_alp_inc2_a2l_attach.py | 277 …, 1 file changed, 239 insertions(+), 38 deletions(-)` — TRUE (reproduced exactly).
3. `git diff | grep -c $'\r'` = 0 — TRUE (step 1, CR count 0).
4. `:609` "timing bound without report_margin" absorbed — TRUE. `test_r_tst_040_041_every_upper_timing_bound_is_reported` now passes (base-RED → GREEN).
5. Final serial run `10 passed` — TRUE for the count (reproduced `10 passed`; elapsed 135.74s vs reported 133.89s — timing variance only).
   Extra: `s19_app.__file__` resolves inside `./s19_app` (HT-03) — TRUE.

Step 5 verdict: PASS.

## Step 6 — Diff saved

`cp ~/work/zq-fa/chk-FA-KEY.diff ~/work/zq-fa/FA-KEY/CHECK.diff` (364 lines, identical to step 1's diff).

CHECK_DONE FA-KEY MECH-NO-GO

## Orchestrator intent review (Opus, relevo-21)
GO. DX-F2 fixed as designed: the instrument, not the product, was wrong (`pilot.press` awaits `wait_for_idle` twice, so any busy thread cost >= 2 s per key). `_deliver_key` builds the `events.Key` with Textual 8.2.8's `_press_keys` character rule and hands it to `driver.send_message` with no idle wait; `_poll_ack` polls the existing focus acknowledgement every 5 ms from the delivery instant; `_key_ack_latency` asserts the bound through `report_margin` (row 6, the `:609` law finding). Row 3: `tab` is delivered just before the synchronous request-snapshot capture and polled after it returns, so the capture now sits inside a 1.0 s bound (R-A2L-REFRESH.049, operator D-11); phase and mapping-independence assertions kept. Row 4: the progress interval that spans the capture is asserted (time base checked: `Sampler.text_changes` is relative to the first frame). Row 5: both instrument controls (UI block >= 1.5 s detected; a GIL-holding worker thread not penalised). Worker deviation accepted: the brief's row-1 control (`sleep` in `step_busy`) never reaches the measurement window, so the worker blocked `on_key` instead (RED at 1.516 s), which is the stronger control. Minor (no action): arm 1 calls the helper with `bound=10.0`, so it files one QC-TM margin record against a deliberately loose bound. Timing results here are indicative; the orchestrator decides timing at M1 on the quiet host (HT-08).

## Orchestrator ruling on the MECH-NO-GO (Opus, relevo-22)
Override to GO (DF-02). The only failing step is a new offender inside a law that is already RED on the base (`test_r_tst_002`): row 4 added a `timing_bound` assertion to `test_r034_progress_throughout`, which makes it a timing arm without `serial_timing`. FA-2 row 1 already names this arm among the three Inc 2 timing arms that get `serial_timing` (FA-2 diagnosis 1), and its proof is that `test_r_tst_002` passes; FA-2's check must show the law lists none of the three. Net law change of this unit: `test_r_tst_040_041` RED → GREEN; no other law changes.
