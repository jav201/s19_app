# Batch-100 — batch-end fix round 2: the battery's real failures and routed items

- **Branch / worktree:** `b100-fix1` = `main` 760f885 + fix round 1 (dee0d96), `C:/Users/jjgh8/Github/s19_app-b100-fix1`. Nothing committed.
- **Input:** the battery re-run alone from a short basetemp (`rerun1.log`, 7 failed / 28 passed) and the routed list of the brief.
- **Runs:** only the touched nodes and their neighbours (operator override: no full suite). Env `env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=.`, `LOCALAPPDATA` under the scratchpad, `--basetemp C:/Users/jjgh8/AppData/Local/Temp/s19f2/bt`, interpreter `s19env`; `s19_app.__file__` printed first = this worktree. The real `%LOCALAPPDATA%\s19_app` was not created (checked: absent).
- **Evidence folder:** `evidence/fix-2/`. Evidence states use the seven words.

## Summary

| Item | Cause | Requirement | Change | State |
|---|---|---|---|---|
| R-1 TC-B100-05 | test (clock measured the settle) | LLR-164.2 (E3 R10) | `tests/test_b100_save_guards.py:2400-2432`, `:2525` | executed, 5/5 pass alone (0.30–0.47 s) |
| R-1 TC-B100-20 [save-project] | test (clock) **and product (slower)** | LLR-168.3 / SEC7-R2-2 time bound | `tests/test_b100_active_variant.py:108-124`, `:662-732` | executed, 5/5 pass alone, **margin ≤ 0.05 s**; product finding R1-P1 |
| R-2 CSS byte-equality | test (later named edits not folded) | D23 / design §6.1 Inc-6 (11); HLR-173, HLR-175, LLR-176.1 | `tests/test_b97_flow_execution.py:2006-2037` | executed, pass; 4 of 4 mutants killed |
| R-3 list pick re-load | test (oracle stale since Inc 12a) | LLR-162.1, LLR-162.3, US-151 | `tests/test_b99_load_project.py:40`, `:81-92`, `:125-151` | executed, module 4 passed |
| R-4 snapshot fixture path | env (custom basetemp) | — | none | executed, pass at default basetemp |
| A12-51 | missing test | LLR-176.2c, LLR-004.2 (R2-5) | `tests/test_b100_busy.py:2043-2091` (new arm) | executed, pass; kills M-70 |
| SE5-11-1 docstring | test text | LLR-175.5 | `tests/test_b100_save_dialog.py:3790-3797` | n/a — comment only (node run green) |
| SE5-12b-2 tail | **product** | LLR-176.2c pattern (CR12b-2), HLR-177 | `s19_app/tui/app.py:14614-14630`, `:14737-14753` | RED → GREEN (2 arms) |
| OBS-12b-2 | **product** (cosmetic, ruled) | HLR-177b / LLR-177.4 | `s19_app/tui/screens.py:1501`, `:1532-1541`; `s19_app/tui/app.py:442-450` | RED → GREEN (1 arm) |
| OBS-12b-1 | tool | — | `tools/e13/run.py:195-202` | executed (selftest) |
| SR12b-7 | census | — | backlog row below | listed; 2 helpers fixed (R-1, R-3) |
| BACKLOG rows naming Inc 12b | bookkeeping | — | `.dev-flow/BACKLOG-CODE.md` | 5 closed, 1 left open |

## R-1 — the two Save timing arms

### TC-B100-05 `test_tc_b100_05_merge_keeps_a_too_large_document_under_one_second`

- **Cause: test.** LLR-164.2 (E3 R10): "a merge into a never-loaded target recording a 20 000-entry document → Save project under 1 s, the document not parsed". Since Inc 12b the save runs on a worker. `_merge_into_ab` started the clock at the request and stopped it after `docs.save_project`, which polls bare `pilot.pause()` until the outcome line and then runs **6 more settle pauses**. So the bound measured poll + settle, not the save.
- **Change (re-pin, the F-23 rule):** `tests/test_b100_save_guards.py:2400-2432`. `_merge_into_ab` wraps `app._on_project_saved` and stamps the end of that main-thread commit; the save seconds run request → commit end (`None` if the save never reached the commit). `:2525-2526`: the arm asserts the commit was reached and prints the time. The bound is unchanged (`timing_bound(1.0)`).
- **Numbers:** RED alone in the battery re-run `1.132 s` (`battery-rerun1-RED.log`). After the re-pin, 5 alone runs: `0.466 / 0.298 / 0.349 / 0.407 / 0.344 s` (`R-1-step1-stamp-only-5-runs.txt`). The product is well inside the bound here; the failure was the measurement.

### TC-B100-20 `test_tc_b100_20_writers_on_a_31_folder_manifest_finish_under_one_second[save-project]`

- **Cause: test, plus a real product slow-down.** The bound (Inc 7 SEC7-R2-2 / SEC6-5 under LLR-168.3; docstring "reach their verified manifest line under 1 s from the trigger") ends at the verified line. The clock stopped when the 4 000-step bare-`pilot.pause()` loop noticed the line.
- **Change:** `tests/test_b100_active_variant.py:690-707`: the `set_status` capture stamps the moment the outcome line is painted, and the clock stops there (`:727`). `:108-124`: a new `_wait_yielding` (wall-clock bound, `asyncio.sleep(0.05)` between checks, the CI12a-1 pattern) replaces the bare loop for this arm only, because the bare loop keeps the main thread busy and the worker's `call_from_thread` round trips queue behind it. Docstring `:662-669` cites the re-pin. The bound is unchanged.
- **Numbers (all alone, idle host, this machine):**

  | Tree / measurement | 5 runs (s) | Result |
  |---|---|---|
  | pre-12b base `4dfb5a1` (Save synchronous), test as shipped | 0.786 · 0.728 · 0.742 · 0.774 · 0.710 | 5 pass (`R-1-base-4dfb5a1-tc20-save-project.txt`) |
  | fix tree, clock at the painted line, bare wait | 0.974 · 1.088 · 1.024 · 1.075 · 1.071 | 4 fail (`R-1-step1-stamp-only-5-runs.txt`) |
  | fix tree, clock at the painted line, yielding wait | 0.961 · 0.981 · 0.952 · 0.996 · 0.999 | 5 pass, margin 0.001–0.048 s (`R-1-tc20-yielding-wait-5-runs.txt`) |

- **Finding R1-P1 (product, for the orchestrator): Save project got about 0.2–0.3 s slower at Inc 12b in this composition, and now sits at the 1 s bound.** A breakdown run outside pytest (`R-1-breakdown.txt`, script `R-1-breakdown-script.py`, 6 runs, request → each stage): main-thread prepare `0.13–0.14 s`, worker files step `0.63–0.89 s`, main-thread commit `0.01 s`, request → verified line `0.79–1.04 s`. Turning off the progress round trips (`_progress_forwarder` no-op and no `step_busy` posts) gave `0.79–1.04 s` too: no consistent difference, so the ≤ 101 `call_from_thread` steps are not the main cost. The base did the same work synchronously in `0.71–0.79 s`. The final alone runs (`R-1-final-alone-3-runs.txt`, all 5 writers + TC-05, 3 repetitions) gave save-project `0.754 / 0.991 / 0.823 s` (the other 4 writers `0.40–0.59 s`). Not diagnosed further (a profile of `_save_project_files` vs the base handler is the next step). The arm passes 5/5 alone after the re-pin, but with ≤ 0.05 s margin; under load it will fail again. Proposed BACKLOG-CODE row: "R1-P1 — Save project at the TC-B100-20 composition takes 0.95–1.0 s request → verified line at Inc 12b (base 0.71–0.79 s); profile the worker step; decide optimise vs re-rule the bound." Not added to BACKLOG-CODE by this round; the orchestrator decides.

## R-2 — `test_tc_b97_flow_execution_css_section_is_scoped`

- **Cause: test.** The arm requires the whole b514b07 sheet to stay a byte prefix, with batch-97 Inc-8's `.map-region-scroll` edit folded as a named supersession. Three later batch-100 commits edit that prefix mid-file. Locally the arm was red since 741cc07; on CI it SKIPS (shallow clone, no `b514b07`), so nobody saw it. The brief named 741cc07 and d7b427d; **53d08d5 (Inc 11) is a third mid-file insert** (the Save dialog block before the report viewer section) and is folded too.
- **Change:** `tests/test_b97_flow_execution.py:2006-2037`. Each later edit is applied to `old` with its commit and requirement cited, and each anchor and inserted block must be found exactly once:
  - 741cc07 (Inc 9b, HLR-173, ruling Q9): `.modal-dialog,\n#load_dialog {` → `.modal-dialog {`; `#project_list, #variant_list {` → `#variant_list {`; the `#load_box` block before `.modal-title`; the Load-dialog panes block before the Save-project assignment lists.
  - 53d08d5 (Inc 11, HLR-175): the Save project dialog block before the report viewer section.
  - d7b427d (Inc 12a, LLR-176.1, ruling Q9 "at most one busy rule"): the `#status_text.-busy` block before the right-aligned context comment.
  - Product CSS untouched (`styles.tcss` sha256[:16] `f7b4f75911b296a4`, the same as at the Inc 12b integration).
- **Arm still guards:** 4 mutants of `styles.tcss` (an early `height: 1` → `2`; `#variant_list` border; `#load_dialog` back in `.modal-dialog`; one byte in the comment after the busy insert): **4 of 4 killed**, file restored byte-equal (`R-2-mutants.txt`).
- **Evidence:** RED `battery-rerun1-RED.log`; GREEN in `green-01-save-guards-and-load.txt`.

## R-3 — the Workarea Files list pick (3 nodes)

- **Cause: test (oracle stale since Inc 12a).** Step 1 (the brief's first move): `_wait_for` became wall-clock bounded with `asyncio.sleep(0.05)` between checks → still `did not settle` (`R-3-step1-wait-only.txt`, 1 failed in 66.97 s). So not starvation. Step 2, what the app painted (`R-3-diagnosis-painted-lines.txt`): the first load paints `Loaded a.s19 (S19 only)` then the end line `Loaded a.s19`; the pick's re-load paints **the same two lines again**, the run ends, `#log_line_3` = `Loaded a.s19 (S19 only)`. The old oracle waited for `#log_line_3` == the previous `#log_line_4` (`Loaded a.s19`), which can never hold since 12a paints the end line last. The product re-loads correctly.
- **Requirement:** LLR-162.1 (the pick loads the item's stored name), LLR-162.3 (the list reads the load folder), US-151 / AT-B99-13.
- **Change:** `tests/test_b99_load_project.py:40` (`import time`); `:81-92` `_wait_for` wall-clock bounded and yielding; `:125-151` `_pick_files_item_and_wait_load` records every line painted after the click (`_append_log_line`, the CI12a-1 idiom) and waits until the `file_load` run has ended and `Loaded <name>` is among those lines; the docstring cites the ruling. The unused `_line3_text` helper is removed (it had no other caller). The durable `#status_text` assertion stays.
- **Evidence:** `R-3-green-module.txt` (whole module: 4 passed in 44.65 s); again in `green-01-save-guards-and-load.txt`.

## R-4 — `test_tc016s_snapshot_setup_loads_only_public_fixtures`

- **Cause: env.** The fixture-path assertion accepts a path with `snapshot_public` as a whole part or `pytest` in the text; the battery re-run's basetemp `…\s19r\bt\snapshot_public0\…` has neither. No change.
- **Evidence:** `R-4-default-basetemp.txt`: default basetemp → **1 passed in 0.47 s**.

## Routed items

### A12-51 — the manifest-mismatch tail of Save project

- **Done.** New arm `tests/test_b100_busy.py:2043-2091` `test_tc_b100_51_save_project_mismatch_tail_ends_with_the_mismatch` (A12-51 / P1-72, LLR-176.2c tail outcome, R2-5 / LLR-004.2): `verify_written_manifest` forced to `mismatch` → 1 effective end with outcome `Manifest verify MISMATCH`; the newest painted row is that line and the row above starts `Saved project to `; the status messages end `…S4 (variant 'firmware')`, `Manifest verify MISMATCH`; the mismatch notice raised once.
- No product change, so no RED-before-fix is owed. Proof it can fail: mutant M-70 (`end_busy(…, tail[0])`) → **KILLED** (`A12-51-mutant-M70.txt`), source restored byte-equal.

### SE5-11-1 docstring

- **Done** (comment only). `tests/test_b100_save_dialog.py:3790-3797`: the "Why" no longer says the stale save "installs it into memory"; it says what the security round-2 correction found: the written file and the in-memory image disagree and the session is marked saved against the wrong file. Node run green (`green-02c-question-reuse-ids.txt`).
- Line endings: this file was LF in the worktree before the edit (fix round 1 rewrote it LF, like `test_b100_load_dialog.py` and `test_b100_save_image.py`); the edit kept LF.

### SE5-12b-2 tail — the two project sync helpers

- **Cause: product.** `_sync_loaded_file_to_project` and `_sync_loaded_a2l_to_project` called `project_dir.mkdir(exist_ok=True)` and `validate_project_files(project_dir)` unguarded. When the open project's folder cannot be read (or a file took its place), the raise went back to the worker → `WorkerFailed` → the app exits.
- **Change:** `s19_app/tui/app.py:14614-14630` and `:14737-14753`: both calls in one `try … except OSError` → one line with the CR12b-2 tokens (`_TYPED_REFUSAL_TOKENS["unreadable"]`): `Project sync NOT done: project '<name>' could not be read — check that the folder can be opened, then load again.` / `A2L sync NOT done: …`, a log warning, return. The load itself keeps its normal end.
- **Arms** (`tests/test_b100_workers.py:3243-3327`):
  - `test_tc_b100_54_file_load_sync_refuses_when_the_project_folder_is_gone`: `P2` open, its folder removed and a regular file `P2` put in its place, then a data load → `Loaded other.s19` end, 1 sync line, app running, no run left. Real filesystem, no patching.
  - `test_tc_b100_54_a2l_sync_refuses_when_the_project_folder_turns_unreadable`: `validate_project_files` raises `PermissionError` only when called from the A2L sync (the request-time guard of CR12b-2 passes first) → `A2L loaded: firmware.a2l` end, 1 sync line, app running.
- **RED** (`SE5-12b-2-RED.txt`, on dee0d96 source): 2 failed — `WorkerFailed: … FileExistsError(17 …)` and `PermissionError: [Errno 13] synthetic …`. **GREEN** (`SE5-12b-2-GREEN.txt`): 2 passed.
- **Observation (not fixed, out of scope):** a folder that is simply deleted does not raise: `mkdir(parents=True, exist_ok=True)` re-creates it empty, and the sync then places the file and writes a fresh `project.json` there. Pre-existing behaviour; worth a ruling (re-create silently vs refuse).

### OBS-12b-2 — the quit question's emphasis

- **Cause: product (cosmetic), ruled:** the safe default carries the emphasis.
- **Change:** `s19_app/tui/screens.py:1501` `ConfirmQuestionScreen.PRIMARY_BUTTON = "confirm_yes"` (the load question unchanged); `:1532-1541` each button gets `modal-confirm` only when it is the primary one. `s19_app/tui/app.py:442-450` `_QuitQuestionScreen.PRIMARY_BUTTON = "confirm_no"` (docstring cites the ruling). Keys (`y` / `n` / `escape`) and `AUTO_FOCUS = "#confirm_no"` unchanged.
- **Arm:** `tests/test_b100_workers.py:2419-2473` `test_tc_b100_53_quit_question_emphasises_the_safe_answer`: during a held Save, palette `quit` → `confirm_no` has `modal-confirm`, `confirm_yes` has not, focus `confirm_no`, `n` stays; a load question pushed afterwards keeps `confirm_yes` primary. RED `OBS-12b-2-RED.txt` (`{'confirm_yes': True, 'confirm_no': False}`), GREEN `OBS-12b-2-GREEN.txt`.
- **Snapshots:** no SVG under `tests/__snapshots__/` shows the quit or the load question (grep for `Stay` / `confirm_yes` / `Replace (y)`: 0 files), so none changes and none was regenerated. The E13 `qz-quit` PNG (tool capture, not a test) would now show `Stay (n)` filled.

### OBS-12b-1 — `tools/e13/run.py` `bz-busy` override

- **Done.** `tools/e13/run.py:195-202`: `_parse_loaded_file(self, path, a2l_files=None, **kwargs)` passes `**kwargs` through to `super()`.
- **Evidence:** `OBS-12b-1-bz-busy-selftest.txt` (selftest, `executed`): `status_text: ⠴ Loading fw.s19 · step 2/3 Parse · 00:02`, `status: []`, `log_tail: []`, exit 0 — no `Load failed … a2l_cache_out` line (the failure recorded in `inc-12b/E13-notes.md`).

### SR12b-7 — count-bounded bare-`pilot.pause()` waits (backlog row)

- **Census** (`SR12b-7-census.txt`, AST scan of `tests/`, script in scratch): a `for _ in range(…)` loop that awaits `pilot.pause()`, has no `asyncio.sleep`, and tests a condition inside. **91 loops in 40 files**; **30 of them are named wait helpers** (function name with wait/settle/flush/drain/until) in 26 files. The helper list is in the evidence file; the shared ones carry most callers: `tests/support/b100_projects.py:599 wait_for`, `tests/support/b100_load_dialog.py:73 wait_for`, `tests/b97_probes.py:319 settled`, and one `_wait_for` per b99/b100 module.
- **Fixed here (only what R-1 / R-3 needed):** `tests/test_b99_load_project.py` `_wait_for` (R-3) and the new `tests/test_b100_active_variant.py` `_wait_yielding` used by TC-B100-20 (R-1; that module's `_wait_for` stays as is for its other callers).
- **Backlog row (proposed text for BACKLOG-CODE):** "SR12b-7 — 30 wait helpers in 26 test files poll with a count of bare `pilot.pause()` calls; since Inc 12a/12b the work they wait for runs on workers, so the bound is not time and the tight loop delays the worker's `call_from_thread` round trips. Re-pin each to the wall-clock + `asyncio.sleep` pattern (CI12a-1) when its module is next touched, shared helpers first. Evidence: `evidence/fix-2/SR12b-7-census.txt`." Not added to BACKLOG-CODE by this round.

### BACKLOG-CODE rows whose "What closes it" names Inc 12b

| Row | Disposition | Closing id / arm |
|---|---|---|
| S10-03 (load worker installs without a check) | **closed** | Inc 12b `9e4dd3b`, LLR-177.3e / ruling Q3; `file_load` ∈ `SESSION_ACTION_KEYS`; `test_tc_b100_53_patch_editor_changes_are_refused_while_busy` (driven during a Save, same predicate) |
| Inc 11 O-1 (vanished source paints the generic line) | **left open** | 12b integration: "No change"; the arm stays `xfail` (design silent). Needs a design ruling |
| SE5-11-3 = O-3 (confirm→dismiss window) | **closed** | Inc 12b `9e4dd3b`, `test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit` |
| SE5-12a-4 (use-time `resolve_input_path`) | **closed** | Inc 12b `9e4dd3b`, `test_tc_b100_53_use_time_resolve_error_refuses_and_keeps_the_app`, `…path_gone_under_the_load_question…` |
| CR12a-1 (raise after commit drops the saved line) | **closed** | Inc 12b `9e4dd3b` (SR12b-1), `test_tc_b100_51_raise_after_the_commit_keeps_the_saved_line` |
| OBS-12a-1 (ETA readout) | **closed** | Inc 12b `9e4dd3b`, `show_eta=False`, `test_tc_b100_50_progress_bar_paints_no_eta`; snapshots regenerated `760f885` |

Also marked closed by this round (pending its commit): SE5-12b-2, OBS-12b-1, OBS-12b-2. Each closed row's lead `▸` became `✅ CLOSED` and gained a `Closed:` sub-bullet; O-1 gained a `Still open` sub-bullet. Rows SR12b-6, R2-F2, PR-6 name the batch-end round, not Inc 12b, and were not in this item; they are untouched.

## Test results (all `executed`, this worktree, Windows)

| Run | Scope | Result | Evidence |
|---|---|---|---|
| R-4 | the snapshot fixture node, default basetemp | 1 passed in 0.47 s | `R-4-default-basetemp.txt` |
| green-01 | `test_b99_load_project.py` (whole), the CSS node, `test_b100_save_guards.py` (whole except the timing arm) | **83 passed, 1 deselected** in 507.70 s | `green-01-save-guards-and-load.txt` |
| green-02 (combined) | workers + busy + questions + … in one process | **killed by the 1800 s `timeout` (exit 124)** at 285 dots, 1 `x`, 1 `s`, 0 F/E; not counted | `green-02-TIMEOUT-combined-run.txt` |
| green-02a | `test_b100_workers.py` (whole) | **69 passed, 1 xfailed** (Inc 11 O-1, design silent) in 826.27 s | `green-02a-workers.txt` |
| green-02b | `test_b100_busy.py` (whole) | **116 passed, 1 skipped** (Windows-only name) in 340.41 s | `green-02b-busy.txt` |
| green-02c | `test_b100_load_question.py`, `test_b100_reuse.py`, the 2 TC-033 modal nodes, the SE5-11-1 node, `test_b100_active_variant.py` (except the 5 timing params), `test_id_registry.py` | **180 passed, 5 deselected** in 804.56 s | `green-02c-question-reuse-ids.txt` |
| R-1 final | TC-B100-20 (5 writers) + TC-B100-05, alone, 3 repetitions | **18 of 18 passed** (save-project 0.754 / 0.991 / 0.823 s; TC-05 0.565 / 0.343 / 0.393 s) | `R-1-final-alone-3-runs.txt` |

Not run (operator override): the full suite, the SVG snapshot tests, and every module not listed above. green-02a/b/c ran as 3 parallel processes; green-01 ran in parallel with the timed-out combined run; the timing arms ran alone afterwards on an idle host (0 pytest processes running, checked). No pytest is left running.

## Source files changed (cap 4: 2 used)

| File | sha256[:16] before (dee0d96 working copy) | after |
|---|---|---|
| `s19_app/tui/app.py` | `ab9bc201022b3ee8` | `fce707dab6d2945d` |
| `s19_app/tui/screens.py` | `dc988721ae7b6a87` | `f46d545d9d61aeff` |
| `s19_app/tui/styles.tcss` | `f7b4f75911b296a4` | `f7b4f75911b296a4` (unchanged) |

Working-copy (CRLF) bytes. Tool (not capped): `tools/e13/run.py` `a83a13ed7dde4d04`. Tests (not capped): `test_b99_load_project.py`, `test_b97_flow_execution.py`, `test_b100_active_variant.py`, `test_b100_save_guards.py`, `test_b100_busy.py`, `test_b100_save_dialog.py`, `test_b100_workers.py`. Docs: `.dev-flow/BACKLOG-CODE.md`, this file. Each edited file kept its line endings (CRLF, except `test_b100_save_dialog.py`, LF before and after).

## Open for the orchestrator

1. **R1-P1** (product): Save project at the TC-B100-20 composition is at the 1 s bound since Inc 12b (0.75–1.0 s alone; base 0.71–0.79 s). The arm passes after the re-pin but will flake under load. Needs a profile and a ruling (optimise, or re-rule the bound with the requirement owner). Proposed backlog text above.
2. **SR12b-7** backlog row (text above) and the census file.
3. Deleted-project-folder observation (SE5-12b-2 section): `mkdir(exist_ok=True)` silently re-creates a deleted open project's folder on the next sync.
4. Inc 11 O-1 stays open (needs a design ruling).
5. R-2: CI still skips the CSS arm (shallow clone). A `fetch-depth` change or a pinned copy of the b514b07 sheet would make CI see it; not done (out of scope).

## Evidence checklist

- [x] Tests/type checks/lint — the touched nodes and neighbours ran (table above); no type checker or linter run (none in the brief). Full suite not run (operator override).
- [x] No secrets in code or output — the diff adds tests, two guards, one class attribute and docs; no credentials, tokens or env values.
- [x] No destructive commands without approval — none. Scratch files under the scratchpad and `C:/Users/jjgh8/AppData/Local/Temp/s19f2/` only; the temporary worktree `s19f2/base4dfb` (detached `4dfb5a1`, clean, used only to time the base) was removed with `git worktree remove` at the end. The real `%LOCALAPPDATA%\s19_app` does not exist (checked at the end).
- [x] File count within cap — 2 source files of 4.
- [x] Review packet attached — this file.

## Orchestrator rulings (2026-11-01)

| Item | Ruling |
|---|---|
| R-1 TC-B100-05 | Accepted: the clock now measures what LLR-164.2 R10 bounds; bound unchanged. |
| R-1 TC-B100-20 / R1-P1 | Re-pin accepted (paint-time clock, yielding wait). The product slowdown is real and is routed as BACKLOG-CODE row R1-P1: profile first, then optimise or re-rule; the bound is not raised now. Declared residual risk: the arm may flake under load until R1-P1 closes. |
| R-2 | Accepted, including the third supersession 53d08d5 (Inc 11, HLR-175) the brief missed. CI skip routed as BACKLOG-CODE row R2-CI. |
| R-3 | Accepted: stale oracle (a re-load paints `Loaded a.s19 (S19 only)` then `Loaded a.s19`), product correct. |
| R-4 | Accepted: environment only, no change. |
| A12-51 | Accepted (M-70 killed). |
| SE5-11-1 | Accepted. |
| SE5-12b-2 | Accepted (RED → GREEN). The re-create-on-delete observation is routed as BACKLOG-CODE row OBS-F2-1 (base behaviour, design ruling owed). |
| OBS-12b-2 | Accepted: the safe answer carries the emphasis; no SVG snapshot shows either question. |
| OBS-12b-1 | Accepted. |
| SR12b-7 | Row added to BACKLOG-CODE as proposed. |
| BACKLOG rows naming Inc 12b | Accepted: 5 closed at 9e4dd3b, 3 closed by this round, Inc 11 O-1 stays open (design ruling owed). |
| Combined-run timeout | Accepted as not counted; the 3 shard runs stand. |
