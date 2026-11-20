# Unit FA-GC2T — GC tests first: falsifiable r038/r043, collect spy, MainThread pause, reload retention [deepseek-v4-pro · high]

Tree: `alp-e4r` at **`<sha after FA-D10 and FA-GC1 integrated>`** (HEAD check mandatory). Rules: `FB-common.md` + `FA-common-laptop.md`. No agent edits `~/.claude/skills`.

You write tests only. The product fix (FA-GC2) comes after you, so several of your new arms must be **RED now, for the reason stated**.

## Fixed diagnosis (R5-F3, DX-F3, R5-F5; re-checked in code by the architect)
- **r038/r043 cannot fail.**
  - `test_r038_install_exception_reenables_gc` (`tests/test_alp_inc2_a2l_attach.py` ~2378-2441) and `test_r043_install_exception_reenables_gc` (`tests/test_alp_inc3_snapshot_parity.py` ~718-781) assert `gc.isenabled()` inside `body`, which runs under `app.run_test()`.
  - Textual 8.2.8 re-raises the app's exception from `run_test`'s `finally` (`textual/app.py` ~2211-2218), so it replaces the `AssertionError`, and `pytest.raises(Exception, match="install boom")` passes.
- **Attach route never re-enables GC on an install exception.** The `except` branch of `_install_attached_a2l` (`s19_app/tui/app/file_load.py:1249-1251`) does not call `gc.enable()`. So r038, once falsifiable, is RED today. The loose route (r043) re-enables it in the worker's `except` (`file_load.py:1998-1999`), so r043 is GREEN today.
- (Line numbers checked at c40b49ab = 9c464b6a + FA-D10, relevo-22.)
- **Each install runs a full collection on the UI thread.** The sites are `file_load.py:1222-1223`, `loaded_state.py:892-894` and `project_load.py:1823-1825` (`gc.collect(); gc.enable()`). DX measured 1.84 s on case_06.

## Files you may edit
`tests/test_alp_inc2_a2l_attach.py`, `tests/test_alp_inc3_snapshot_parity.py`, `tests/conftest.py`.

## Rows
| row | change | expected now | negative control |
|---|---|---|---|
| 1 | r038: inside `body`, append `gc.isenabled()` (and the `gc_at_boom` / outcome observations) to lists. Move every assertion **after** the `with pytest.raises(...)` block, and also assert `gc.isenabled()` there (the test process state after the route). Docstring cites R-A2L-REFRESH.051 (E4R). | RED (GC left disabled) | n/a: it is RED; the checker re-runs it after FA-GC2 |
| 2 | r043: same restructuring. Cites R-A2L-REFRESH.051. | GREEN | Scratch: remove `gc.enable()` at `file_load.py:1998-1999` → RED |
| 3 | New arms for R-A2L-REFRESH.051's success/failure/superseded outcomes on the attach route (and project success). Reuse the existing route drivers of these files; one parametrized test per file; assert `gc.isenabled()` after the route ends. | GREEN | Scratch: remove the re-enable on the superseded path (`file_load.py:1187-1188`) → that arm RED |
| 4 | New `test_r_a2l_refresh_052_install_runs_no_full_collection`, parametrized over attach (in the inc2 file) and image/project (in the parity file, one test). Use a generated mid-size A2L (`characteristic` + `inline` from `tests/support/b103_a2l_arrays.py`, about 2,000 objects; image via conftest `make_large_s19` or the file's existing image helper). Spy: monkeypatch `gc.collect` with a wrapper that records calls whose caller frame's module is one of `s19_app.tui.app.file_load` / `loaded_state` / `project_load` (use `sys._getframe(1).f_globals["__name__"]`). Assert 0 such calls between submit and outcome. | RED (1 call per route) | the checker re-runs after FA-GC2 |
| 5 | New `test_r_a2l_refresh_052_case06_no_mainthread_gc_pause` in the inc2 file, `@pytest.mark.serial_timing` + `@pytest.mark.slow`. Register a `gc.callbacks` hook that records `(phase, generation, threading.current_thread().name, perf_counter)`, pairs start/stop, then attach case_06 (as `test_r033_key_latency[case06-full-processing]` drives it). Assert no MainThread generation-2 pause > `timing_bound(0.25)`, with the margin reported by `report_margin`. Remove the callback in `finally`. | RED (about 1.84 s) | **Do not run it** (slow); the orchestrator runs it before FA-GC2 starts |
| 6 | New `test_r_a2l_refresh_053_reloads_do_not_accumulate_objects` in the inc2 file: attach the same generated mid-size A2L 5 times through the product route; after each outcome run `gc.collect()` and record `len(gc.get_objects()) + gc.get_freeze_count()`; assert loads 3–5 ≤ 1.10 × load 2. Plus `tests/conftest.py`: one autouse function-scoped fixture whose teardown runs `gc.enable(); gc.unfreeze()` (hygiene only; it asserts nothing). | GREEN (no freeze yet) | Scratch: in the copy, at the 3 sites replace `gc.collect()` by `gc.freeze()` AND delete `walk = None` in `a2l_definition.py` → RED (paste the counts) |

## Nodes you may run (`timeout 300`)
- `-n 0`: r038, r043, your new rows 3, 4 and 6;
- `-n 4 -m "not serial_timing and not slow"` on both test files;
- `--collect-only -q -m "slow"` (row 5 must be listed).

Never run row 5.
