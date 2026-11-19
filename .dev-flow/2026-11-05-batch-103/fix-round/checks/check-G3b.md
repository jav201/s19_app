# check-G3b — independent check (Sonnet tester), written down by the orchestrator from the checker's reply (the checker wrote no file)

Verdict: **GO on rows 1–3, laws NOT run** (integrate only after the six law files pass on the integrated tree — DeepSeek CHK-ds step 4 or the orchestrator).

Tree checked: copy of `~/work/zq-fb/G3b/frozen-repo` (worker timed out, PI_EXIT=124, no REPORT.md; MD-06).

| check | result |
|---|---|
| 1 Diff hygiene | 2 files, both allowed (`tests/test_b100_workers.py`, `tests/test_tui_app.py`), +4/−3, CR=0, no new skip/xfail/sleep, no test def removed. Diff saved as `diffs/G3b.diff`. |
| 2 Intent | Row 1 re-pins the install spy `_apply_loaded_file` → `_apply_prepared_load`, asserted order unchanged. Row 2 re-keys the injection `load_a2l_from_path` → `_start_a2l_load`. Row 3 stubs `update_memory_map`. No assertion loosened. |
| 3 GREEN | Target nodes: 4 passed (a2l parametrised) vs 3 failed at base. Both whole files `-n 4`: 143 passed, 2 xfailed, 1 failed — `test_at_b100_18_worker_half_case06_project_load_by_keys` ("the P6 load never ended"), outside the 3 rows, fails identically on a base copy with the tests reverted: pre-existing (it is DX-F1 / G8, fixed by the a2l branch). |
| 4 Negative controls | All 3 re-applied, all RED: reset moved before the worker start → test 53 RED via `WaitForScreenTimeout` (RED but a weak signal, not an assertion line); "A2L file not found" guard removed → 54[a2l_size] RED (`'A2L loaded' != 'A2L file not found'`); MAC attach replaced by returning `mac_loaded` → test_tui_app RED (`'mac' == 's19'`). |
| 5 Laws | NOT RUN. |
| 6 Worker claims | n/a (no REPORT.md). |

Notes: MINOR — test 53's control kills by timeout, not by its order assertion.

## Laws (orchestrator, Linux host, fix-round tip b5ca5b72 + diffs/G3b.diff, 2026-11-19 13:0x)
Six law files serially: 2 failed / 113 passed / 2 skipped (528 s). The 2 RED are base-red: `test_r_tst_070_2` (unit REC) and the address census `test_at_b83_08` (unit G3c2). The canon two-shall law is GREEN (canon fold). Laws step: PASS.
