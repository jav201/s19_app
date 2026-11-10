# Inc 12 — mechanical real-Windows-Terminal capture driver (DeepSeek)

Work only in this `b103-inc12-code` worktree. The implementation is complete; do not edit `app.py` or tests. Create only:
- `.dev-flow/2026-11-05-batch-103/inc-12/capture_driver.py`
- `.dev-flow/2026-11-05-batch-103/inc-12/capture_windows.ps1`
- optionally `capture_all_windows.ps1` in the same folder.

Read `02-test-cases.md` AT-B103-I12-2, the synthetic fixture definitions, `codewire/evidence-e2/i12e2-probe.py`, and `tools/e13/{run.py,capture.ps1,capture_all.ps1}`. Reuse the house PrintWindow/CopyFromScreen and unique-title/close-only-own-window approach. Do not run captures yourself.

The Python driver must run the real app from the checkout passed by the PowerShell wrapper, insert that checkout at `sys.path[0]` under `python -I -B`, use a scratch work area, and drive the real loading/rail/cursor/scroll handlers to stable A2L Explorer surfaces. Scenarios: SYNMAP; PAGE64(48); tracked `examples/case_00_public/ASAP2_Demo_V171.a2l` with the ASAM.M.SCALAR rows and vertical scrollbar; a tracked CURVE-without-length file selected from `../inc-11/evidence-e3/corr2-e3c2-bytesize.py`; SYNMAP mid-scroll; V171 Name-line with a display-identifier row highlighted. Synthetic text only for new fixtures; no proprietary content, no corpus text copied into records, no clipboard.

The PowerShell wrapper must accept Root, Scenario, Cols, Rows and OutPng; open a NEW `wt.exe --size` window with truecolor and NO_COLOR unset; isolate HOME, XDG_* and LOCALAPPDATA below a scratch `zq_iso_user`; set PYTHONDONTWRITEBYTECODE=1; capture that exact window as PNG; then close every window it opened and clean only its scratch. Never touch an existing window or the operator's real recent-files store. The driver must stay alive until the wrapper closes it. The optional loop covers before/after at 80x50, 118x54 and 220x60 and the extra captures without hard-coding personal paths.

On Windows run only `python -m py_compile` on the new Python file. Do not run the app, pytest, probes, clipboard, or captures. Commit the driver(s) and this handoff on `b103-inc12-code` as `batch-103 Inc 12 E5: Windows Terminal capture driver` with `Co-Authored-By: DeepSeek V4 Pro`. Report scenario coverage and any limitation honestly.
