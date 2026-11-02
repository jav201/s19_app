# Batch-100 — batch-end fix round 3: the 4 new failures of CI 41338318239

- **Branch / worktree:** `b100-fix3` = `main` 570b4b5 (fix rounds 1 and 2 merged), `<HOME>/Github/s19_app-b100-fix3`. Nothing committed.
- **Input:** CI run 41338318239 on main 570b4b5 (ubuntu, Python 3.11.17, textual 8.2.8, rich 15.0.0, pytest 9.2.0): 9 failed / 5030 passed / 211 skipped / 4 xfailed. Five are the known pre-existing failures (tc1802, tc707 ×2, 056e_a2b, b78_03) and were left alone. The four new ones are below. Excerpts: `evidence/fix-3/ci-41338318239-excerpts.txt`.
- **Linux reproduction:** WSL Ubuntu, a copy of the tree with LF line endings (`git -c core.autocrlf=false archive HEAD`, extracted to `~/s19fix3`; edited files synced with `sed 's/\r$//'`, `evidence/fix-3/sync.sh`), venv `~/s19venv` with **Python 3.12.7** (no 3.11 on the distro or in the WSL conda; the same textual 8.2.8 / rich 15.0.0 / pytest 9.2.0 as CI), `pip install -e .`. `s19_app.__file__` = `/home/jav201/s19fix3/s19_app/__init__.py`. Runner `evidence/fix-3/run4.sh` (`NO_COLOR` unset, `-p no:cacheprovider`, `timeout 1800`).
- **Windows runs:** `s19env` (Python 3.11.15), env `env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=. LOCALAPPDATA=<HOME>/AppData/Local/Temp/s19f3/la`, `--basetemp <HOME>/AppData/Local/Temp/s19f3/bt`, `timeout 1800`; `s19_app.__file__` printed first = this worktree. The real `%LOCALAPPDATA%\s19_app` was not created (checked: absent).
- **Runs:** only the 4 nodes and their 4 modules (no full suite). Evidence folder: `evidence/fix-3/`. Evidence states use the seven words.

## Summary

| Item | Cause | Requirement | Change | State |
|---|---|---|---|---|
| 1a TC-B100-73 small A2L | test (byte count pinned to the CRLF checkout) | LLR-176.4 boundary, LLR-176.4a (D12b-02, D12b-04) | `tests/test_b100_a2l_progress.py:110-122` | executed: RED on WSL base, GREEN on WSL and Windows |
| 1b TC-B100-51 A2L load | test (same literal) | LLR-176.2c, C12b-30 (A12a-03) | `tests/test_b100_busy.py:1835-1842`, comment `:1897` | executed: RED on WSL base, GREEN on WSL and Windows |
| 2 AT-B100-18 quit-confirm half | **test** (the "still running after y" observation came after `pilot.press("y")` returned, which on Linux is after the save's end); product correct | AT-B100-18, HLR-177c, LLR-177.4c | `tests/test_b100_workers.py:3055`, `:3069-3077`, `:3081-3100` | executed: RED on WSL base (reproduced), GREEN on WSL and Windows; mutant M-quit killed |
| 4 AT-B100-17 parse half (found here, GO by the coordinator) | **test** (bar sampled after `pilot.press("enter")`, which returns after the last byte report on a fast disk); product correct | AT-B100-17, LLR-177.5, LLR-176.4 | `tests/test_b100_workers.py:3135-3155`, `:3176-3179` | executed: RED 2 of 3 alone on WSL, GREEN 3 of 3 alone + module on WSL, 1 on Windows; mutant M-at17 killed |
| 3 TC-B97-64 new set run restarts the dwell | **test** (wall-clock dwell; run end → `c` exceeded 0.5 s on a loaded host); product correct | TC-B97-64, LLR-147.13, I-7 (c) | `tests/test_b97_flow_execution.py:1761-1768`, `:1773-1774`, `:1776-1789` | executed: original reproduced RED 1 of 6 under CPU load, re-pin 8 of 8 GREEN under the same load; mutant M-dwell killed |

**Source files changed under `s19_app/`: none.** All four causes are in the tests; the product paths were checked and left byte-equal (mutants restored byte-equal, `evidence/fix-3/mutants-wsl.txt`).

## Item 1 — the small A2L's byte count (2 nodes)

- **Cause: test.** `examples/case_01_basic_valid/firmware.a2l` is stored LF in git (`i/lf w/crlf`, no `.gitattributes` rule), so its size on disk is the checkout's: 1 444 bytes on a Windows CRLF checkout, 1 391 on the Linux CI. The two arms pinned `1444`. The requirement (LLR-176.4 boundary: a file smaller than one chunk reports once with `done == total ==` the file's size) never named a number.
- **Change:**
  - `tests/test_b100_a2l_progress.py:110-122` (`test_tc_b100_73_small_a2l_reports_once_and_parses_the_same`): `size = CASE01_A2L.stat().st_size`; `assert seen == [(size, size)]`; docstring says why.
  - `tests/test_b100_busy.py:1835-1842` (`test_tc_b100_51_a2l_load_ends_once_on_success`): `size = (CASE01 / "firmware.a2l").stat().st_size` (the attach parses the work-area copy, which is byte-equal: the CI log's `A2L copy complete … size_bytes=1391`); the expected step list reads `(2, size, size)`. `:1897` (`test_tc_b100_51_project_load_ends_once_on_success`) only a comment named `(1444, 1444)`; it now says `(size, size)`.
- **Other literal byte counts in the 12b tests:** grep of `1444`, `1 444`, `1391` and size-like literals in `test_b100_*.py`: no other literal byte count in an assertion. The case_06 arm already reads `CASE06_A2L.stat().st_size` (its docstring's `37 742 888 bytes` is prose only); every other size in `test_b100_*.py` is read with `stat().st_size`.
- **Evidence:** RED `wsl-01-base-4-nodes-RED.txt` (`[(1391, 1391)]`, the same as CI); GREEN `wsl-02-fix-4-nodes-GREEN.txt`, `win-01-fix-4-nodes.txt`.

## Item 2 — AT-B100-18 quit-confirm half

- **Cause: test, not product.** Reproduced on WSL at once (`wsl-01-base-4-nodes-RED.txt`). A timeline probe (`item2-probe-quit-timeline.py`, a copy of the scenario with marks on `begin_busy`, `end_busy`, `_answer_quit` and `exit`; output `item2-probe-timeline-wsl-run2-answer-exit.txt`, 3 runs) shows, run 1 (seconds from start):

  | t | event |
  |---|---|
  | 3.73 | `begin save_project` |
  | 8.90 | Save dialog closed, `save_project` running |
  | 10.94 | `q` handled, the quit question shown, `save_project` running |
  | 10.95 | `_answer_quit(True)` — **`save_project` still running; the app stays up** |
  | 12.35 | `end save_project 'Saved project to …'` |
  | 12.35 | `app.exit` called (from `end_busy` → `_exit_if_quit_pending`) |
  | 12.42 | `pilot.press("y")` returns: runs `[]`, app no longer running |

  The two other runs are the same to ±0.1 s, and `S9`'s `project.json` matches its files with 2 000 files under `flows/` in every run. So the product does what LLR-177.4c says (exit after the running session action's end handler). The test read `running(app)` after `pilot.press("y")` returned, and on Linux that return comes about 1.4 s after the answer, after the save's end (the press waits for the screen to settle while the worker's progress round trips keep the main thread busy). The 2 000-file copy is not a guarantee that the save is still running at the observation point.
- **Change (re-pin to LLR-177.4c's own verification "A Save project held at a forced slow step"):** `tests/test_b100_workers.py:3055` adds the `monkeypatch` fixture; `:3081-3100` installs the module's `Hold` on `app_module.place_into_workarea` **after** the project load (so the load is never held), waits with `reached` until the save-as worker is blocked in its first placement, then `q`, the question, `y`, 4 pauses, reads `alive_after_y`, and releases the hold in a `finally`; `wait_exit` and the existing assertions (one new folder `S9`, its `project.json` records exactly the files on disk, 2 000 files in `flows/`) are unchanged. Docstring `:3069-3077` cites this round. The base negative control still holds: on the base the save is synchronous, the hold never blocks on the event-loop thread, and `q` exits with no question.
- **Arm:** mutant M-quit (`_answer_quit` → `self.exit()` at once when `quit`) → **KILLED**: `the app stopped right after y, with the save still running` (`mutants-wsl.txt`); `app.py` restored byte-equal (WSL copy sha256[:16] `69f8e7b5fbbd8042` = `git show HEAD:s19_app/tui/app.py`).
- **Evidence:** RED `wsl-01-base-4-nodes-RED.txt`; GREEN `wsl-02-fix-4-nodes-GREEN.txt`, `win-01-fix-4-nodes.txt`.

## Item 3 — TC-B97-64 a new set run restarts the dwell

- **Cause: test, not product.** `CONFIRM_DWELL_S = 0.5` is read through the D15 clock seam `flow_screens._fx_clock` (`time.monotonic`). The arm needs the `c` to land within 0.5 s of the restarted dwell base (stamped after the repaint that follows `render_run`), but between the stamp and the `c` there are `run_lanes`' poll and the key press; on a loaded host that took over 0.5 s and the `c` confirmed. The product path is right: `render_run` calls `_rearm_attention(restart=True)` on every set run (`flow_screens.py:3497`), which clears the base and stamps it again after the refresh.
- **Reproduced on Linux:** the original arm under 20 CPU burners on WSL (`load_dwell.sh`): **1 failed of 6**, `AssertionError: ([(1, 2)], None)` — the CI assertion byte for byte (`item3-dwell-original-under-cpu-load-wsl.txt`). It passed unloaded on WSL (`wsl-01`).
- **Change (time-independent oracle):** `tests/test_b97_flow_execution.py:1773-1774` holds the dwell clock (`monkeypatch.setattr(fs, "_fx_clock", lambda: now[0])`, `now = [100.0]`); `:1776-1789`: the first base is read, the clock moves +0.6 s instead of `pilot.pause(0.6)` (so the old base is past the dwell before the run), the run, then a poll until the base reads the moved time (`100.6`), then `c`. New assertion `bases == (100.0, 100.6)`; the original `posts == [] and paused == 2` and the `c ignored — flash_chain` line stay. Docstring `:1761-1768` cites this round. The module's other dwell arms (the "after the dwell, `c` confirms" direction) keep the real clock: a slow host only makes them more past the dwell.
- **Arm:** mutant M-dwell (`render_run` calls `_rearm_attention()` without `restart=True`) → **KILLED**: `(100.0, 100.0) != (100.0, 100.6)` (`mutants-wsl.txt`); `flow_screens.py` restored byte-equal (`0f9a3a2fa1b337b4` = HEAD).
- **Evidence:** re-pinned arm under the same 20-burner load: **8 passed of 8** (`item3-dwell-fixed-under-cpu-load-wsl.txt`); GREEN `wsl-02-fix-4-nodes-GREEN.txt`, `win-01-fix-4-nodes.txt`.

## Item 4 — AT-B100-17 parse half (coordinator's GO on Open 1)

- **Cause: test, not product** (diagnosis: Open 1's first version, probe `obs-at17-probe.py`, `obs-at17-probe-timeline-wsl.txt`). The case_06 byte reports run about 1.3 s; `pilot.press("enter")` returns after the last one, so every sample read the held 66.
- **Requirement:** AT-B100-17 parse half, LLR-177.5, LLR-176.4: while `#status_text` shows `step 2/3 Parse` the bar rises at least 2 times, and the elapsed time advances.
- **Change:** `tests/test_b100_workers.py:3135-3144` docstring cites this round; `:3145-3155` wraps `app.step_busy` on the instance (the forwarder resolves `self.step_busy` at each `call_from_thread`): after each step-2 byte report of `a2l_load` is applied on the main thread, it records `bar(app)` and `status(app)`. `:3176-3179`: the bar values at those reports rise at least 2 times, all lie in `33 … 66`, and every recorded status matches the `step 2/3 Parse` line. The elapsed-time clause (`:3180`) keeps the samples loop, so a blocked loop (no step-2 sample) is still RED.
- **RED (before):** the unchanged arm failed 2 of 3 alone on WSL (`wsl-04-at17-parse-half-alone-{1,2,3}.txt`) and in the module run (`wsl-03-fix-4-modules.txt`).
- **Arm:** mutant M-at17 (`s19_app/tui/a2l.py`: the in-read `progress(handle.buffer.tell(), total)` → `pass`, so only the final report is left) → **KILLED**: `bar values at the step-2 byte reports: [66]`, 0 rises (`mutant-at17-wsl.txt`); `a2l.py` restored byte-equal (`e91dd008c31e9c9e` = `git show HEAD:s19_app/tui/a2l.py`).
- **GREEN:** WSL 3 of 3 alone (`wsl-05-at17-repin-alone-{1,2,3}.txt`, 15.6–17.2 s); WSL whole `test_b100_workers.py` **69 passed, 1 xfailed** in 10:57 (`wsl-06-module-workers-after-at17.txt`); Windows once **1 passed** in 19.66 s (`win-05-at17-repin.txt`).

## Runs

| Run | Where | Result | Evidence |
|---|---|---|---|
| 4 nodes, base 570b4b5 | WSL (Linux, 3.12.7) | **3 failed, 1 passed** (items 1a, 1b, 2 RED as on CI; item 3 passed unloaded) | `wsl-01-base-4-nodes-RED.txt` |
| AT-B100-18 timeline probe ×3 (+ answer/exit marks ×3) | WSL | product exits only after `end_busy`; `S9` complete each run | `item2-probe-timeline-wsl-run1.txt`, `item2-probe-timeline-wsl-run2-answer-exit.txt` |
| TC-B97-64 original, 20 CPU burners ×6 | WSL | **1 failed of 6** (`([(1, 2)], None)`, as CI) | `item3-dwell-original-under-cpu-load-wsl.txt` |
| 4 nodes, fix | WSL | **4 passed** in 23.31 s | `wsl-02-fix-4-nodes-GREEN.txt` |
| TC-B97-64 re-pinned, 20 CPU burners ×8 | WSL | **8 passed of 8** | `item3-dwell-fixed-under-cpu-load-wsl.txt` |
| mutants M-dwell, M-quit | WSL | **2 of 2 killed**, sources restored byte-equal | `mutants-wsl.txt` |
| 4 modules (272 tests), fix | WSL | **1 failed, 266 passed, 4 skipped, 1 xfailed** in 24:50 — the failure is `test_at_b100_17_parse_half_case06_a2l_by_keys`, not touched by this round (see Open 1) | `wsl-03-fix-4-modules.txt` |
| AT-B100-17 parse half alone ×3 (fix tree; test and product unchanged from base) | WSL | 2 failed, 1 passed | `wsl-04-at17-parse-half-alone-{1,2,3}.txt`, probe `obs-at17-probe-timeline-wsl.txt` |
| AT-B100-17 re-pinned alone ×3 | WSL | **3 passed** | `wsl-05-at17-repin-alone-{1,2,3}.txt` |
| mutant M-at17 | WSL | **killed**, `a2l.py` restored byte-equal | `mutant-at17-wsl.txt` |
| `test_b100_workers.py` after the AT-17 re-pin | WSL | **69 passed, 1 xfailed** in 10:57 | `wsl-06-module-workers-after-at17.txt` |
| 4 nodes, fix | Windows (3.11.15) | **4 passed** in 37.55 s | `win-01-fix-4-nodes.txt` |
| 4 modules in one run, fix | Windows | **timed out** (`exit=124` at 1 800 s after 31 results; `-q`, so the stalled node is not named) — see Open 2 | `win-02-fix-4-modules.txt` |
| `test_b100_a2l_progress.py` + `test_b100_busy.py`, verbose | Windows | **126 passed, 1 skipped** in 7:48 | `win-03-modules-a2l-progress-busy.txt` |
| `test_b100_workers.py`, verbose | Windows | **69 passed, 1 xfailed** in 15:21 | `win-04-module-test_b100_workers.txt` |
| `test_b97_flow_execution.py`, verbose | Windows | **75 passed** in 6:23 | `win-04-module-test_b97_flow_execution.txt` |
| AT-B100-17 re-pinned, once | Windows | **1 passed** in 19.66 s | `win-05-at17-repin.txt` |

The Windows `win-03`/`win-04` module runs were made before the AT-17 re-pin (that arm passed there unchanged); after it, the arm was run once on Windows (`win-05`). No pytest or CPU burner left running on either side (checked with `Get-CimInstance Win32_Process` and `pgrep`). The probe copies `tests/_probe_fix3_*.py` exist only in the WSL copy `~/s19fix3`, not in the worktree.

## Files

| File | sha256[:16] (worktree bytes, CRLF) | Kind |
|---|---|---|
| `tests/test_b100_a2l_progress.py` | `9ded8b3f346f2d81` | test |
| `tests/test_b100_busy.py` | `670ea44f8ba9720c` | test |
| `tests/test_b100_workers.py` | `276636e718fc0895` (after the AT-17 re-pin; `1e5edde56c122013` after items 1–3 only) | test |
| `tests/test_b97_flow_execution.py` | `04d4b20d4aafa395` | test |
| `s19_app/**` | — | **no source file changed** (0 of 4 allowed) |

Line endings kept: each edited file is CRLF in the worktree before and after (every `\n` is `\r\n`), LF in git.

## Open for the orchestrator

1. **AT-B100-17 parse half — done** (coordinator GO): see Item 4. Re-pinned to the `step_busy` seam; product unchanged.
2. **One Windows run timed out without a named node — recorded as not reproduced** (coordinator ruling): the combined 4-module run (`win-02`) stalled at 31 results until the 1 800 s timeout. The same modules then passed when run in pieces (`win-03`, `win-04`), where the longest nodes were the two `test_tc_b100_53_workarea_data_pick_parses_on_the_file_load_worker` arms (186 s and 197 s) and `test_at_b100_17_worker_load_of_an_8_mib_s19_by_keys` (81 s). Other processes were running on the host at the same time (IDE debug sessions started at 17:59 and 18:13). Not diagnosed; not reproduced in `win-03`, `win-04`, `win-05`.
3. **Backlog row (SR12b-7 family; coordinator: record, do not sweep now).** Proposed text for BACKLOG-CODE: "SR12b-7b — arms that read state right after `pilot.press(...)` while a real (not held) worker runs. The press waits for the screen to settle, and the worker's `call_from_thread` progress round trips can hold it until the work has ended, so a read meant to show the state *at* the key shows the state *after* the work (found twice in fix round 3: AT-B100-18 quit-confirm half, AT-B100-17 parse half). Re-pin each, when its module is next touched, to a forced slow step (`Hold`) or to a record taken at the seam (`step_busy`, `_answer_quit`), never a sample after the press. Evidence: `evidence/fix-3/item2-probe-timeline-wsl-run2-answer-exit.txt`, `evidence/fix-3/obs-at17-probe-timeline-wsl.txt`." Not added to BACKLOG-CODE by this round; no census made.
4. **No Python 3.11 on Linux here:** the WSL reproduction ran on Python 3.12.7 with the CI's package versions; CI uses 3.11.17. Items 1–3 reproduced on 3.12 the same way as on CI. The orchestrator's Linux 3.11 host re-runs the nodes.
5. **CI confirmation owed:** after merge, compare the FAILED set with run 41338318239. The expected set is the 5 pre-existing failures only .

## Orchestrator rulings (2026-11-01)

| Item | Ruling |
|---|---|
| 1 TC-B100-73 / TC-B100-51 | Accepted: the size is read from the fixture on disk (CRLF vs LF checkouts). |
| 2 AT-B100-18 quit-confirm half | Accepted: product correct; the test now holds the save worker at its slow step (LLR-177.4c's own wording). M-quit killed. |
| 3 TC-B97-64 dwell | Accepted: the D15 clock seam replaces the wall-clock pause. M-dwell killed; 8/8 under load. |
| 4 AT-B100-17 parse half | Accepted (go given after the round's first report): the bar is recorded at the step_busy hook. M-at17 killed. |
| Open 2 (Windows combined-run timeout) | Recorded as not reproduced. |
| Open 3 (SR12b-7b) | Added to BACKLOG-CODE as proposed. |
| Python version | WSL ran 3.12.7; the orchestrator re-ran the nodes on a Linux host with Python 3.11 (CI's version): see `evidence/fix-3/cachy-*.txt`. |
