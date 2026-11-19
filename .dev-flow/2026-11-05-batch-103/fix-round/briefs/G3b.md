# Unit G3b — worker/attach tests lost their oracle (R2-F8)
Fixed diagnosis:
1. `test_tc_b100_53_reset_runs_after_the_worker_and_before_the_first_install`: the spy order no longer matches the current seams (probable; confirm by reading the test and `s19_app/tui/app/project_load.py` / `file_load.py`, then re-pin the spies to the functions that now run reset, worker and first install; the asserted ORDER stays).
2. `test_tc_b100_54_a2l_attach_refuses_when_its_folder_or_file_vanished[a2l_size]`: the injection fires on `co_name == "load_a2l_from_path"`, but the `stat()` moved to `_start_a2l_load` (`s19_app/tui/app/file_load.py:728,762`), still guarded ("A2L file not found") → re-key the injection.
3. `tests/test_tui_app.py::test_load_selected_file_attaches_mac_to_loaded_binary`: the unmounted app has no stub for `update_memory_map`, which Inc 5 `5e8f0454` added via `_refresh_a2l_dependent_views` → `ScreenStackError`; stub it the way the test stubs the others.
Files you may edit: `tests/test_b100_workers.py`, `tests/test_tui_app.py`.
Negative controls: (1) move the reset call before the worker start in a scratch copy → RED; (2) remove the "A2L file not found" guard in `_start_a2l_load` → RED; (3) remove the MAC attach in the product load route → RED.
Nodes (`-n 0`): the three above; then both whole files (`-n 4`).
