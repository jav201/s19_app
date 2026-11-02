# Inc 3 — E1 profile: the Save project margin (R1-P1) and the painted ~1 s step

Batch 2026-11-01-batch-101, increment 3. Tree `e266395` (main, worktree `b101-inc3`), Windows, s19env Python 3.11, Textual 8.2.8, run alone (no xdist), `NO_COLOR` unset, `LOCALAPPDATA` pointed at a temp folder. Host load during the runs: about 9 % CPU average over 16 logical processors, with other sessions active, so absolute times are higher than batch-100's (see §1.4). Every number below comes from a transcript in `.dev-flow/2026-11-01-batch-101/evidence/inc-3/`; the scripts that made them sit in the same folder.

**Verdict.**
1. **R1-P1 is an optimisation, not a re-ruled bound.** About 0.45 s of the 1.1–1.3 s comes from one avoidable cost: the Save worker's gather calls `Path.resolve()` once per composition name (2 000 calls for 1 000 distinct names at the end of a 31-folder chain), and on Windows each call costs a final-path lookup on a 32-part path. Checking `is_file()` on the joined path, once per distinct name, takes the real TC-B100-20 node from 1.11–1.33 s to 0.65–0.74 s (5/5), under the plan's 0.8 s target with 26 % margin or more. The rest of the time is the SEC6-5 floor (one `lstat` per recorded file per manifest read, two reads per save) and stays.
2. **The painted ~1 s step is the test clock, not the product.** The app paints the Load-result panel 0.17–0.42 s after the install callback returns (stamp: the panel screen's first layout refresh with a summary height, 8/8 runs). The test notices it 0.5–0.65 s later because `pilot.pause()` returns only when the app is idle, after two more layout passes. No product timer runs on a ~1 s cadence. The bimodal 0.001 s / 0.6–1.3 s values come from the start rule `max(pressed, _load_returned_at)` combined with that poll end point.
3. **The `sec6_5 appended` arm has the same poll end point**: 0.87–1.14 s by the poll, 0.59–0.96 s from `load_from_path` to the painted outcome line (6 runs). With the stamp it is under 1 s in 6/6 runs, but its margin is under 20 % in 4/6: the variant append's sync at the folder ceiling is a product cost of its own (§2.3), outside this increment's plan row (decision D-4).

## 1. R1-P1 — Save project at the TC-B100-20 composition

Scene: `tests/test_b100_active_variant.py::test_tc_b100_20_writers_on_a_31_folder_manifest_finish_under_one_second[save-project]` — project P holds 1 000 real files at the end of the 31-folder chain `CHAIN`, recorded in `batch`, `assignments` and `gathered`; the open project is saved again under its own name with that composition (1 000 batch names plus the same 1 000 names in `assignments`).

### 1.1 Where the time goes (marks, no profiler)

`R1-P1-profile-script.py marks 6` → `R1-P1-marks-e266395.txt`. Seconds after the handler call:

| Run | handler returns | worker starts | worker ends | outcome line painted |
|---:|---:|---:|---:|---:|
| 1 | 0.196 | 0.213 | 1.171 | 1.171 |
| 2 | 0.202 | 0.219 | 1.252 | 1.252 |
| 3 | 0.197 | 0.217 | 1.306 | 1.307 |
| 4 | 0.204 | 0.222 | 1.379 | 1.379 |
| 5 | 0.200 | 0.218 | 1.314 | 1.314 |
| 6 | 0.156 | 0.175 | 1.008 | 1.008 |

The handler (main thread: the pre-save read of the existing project.json, 3 000 entries) takes 0.16–0.20 s; the worker step `_save_project_files` takes 0.83–1.16 s; the main-thread commit `_on_project_saved` about 0.01 s. The worker step is the bound's problem.

### 1.2 Inside the worker step (cProfile)

`R1-P1-cprofile-e266395.txt`, `R1-P1-cprofile-callers-e266395.txt` (profiled times, inflated about 1.5×):

| Callee of `_save_project_files` | cumulative s | what it does |
|---|---:|---|
| `gather_project_artifacts` (`project_gather_service.py:525`) | 0.784 | 2 001 `Path.resolve()` calls (0.649 s): one per composition name, `(resolved_project / name).resolve()` at `:656`, then `is_file()` at `:657`. The 2 000 names hold 1 000 distinct texts. |
| `_write_manifest_for_save` (`app.py:12305`) → `write_project_manifest` | 0.259 | the serializer's refusal predicate, `_reject_unsafe_entry` → `_resolve_manifest_entry`, 2 001 entries (one shared walk) |
| `_write_manifest_for_save` → `verify_written_manifest` | 0.480 | the re-read `read_project_manifest` (0.300 s, 2 000 entries) and `_resolve_intended_entries` (0.103 s) |

`nt._getfinalpathname` (the Windows half of `resolve()`) alone takes 0.351 s tottime over 4 046 calls; `nt.lstat` 0.148 s over 2 089 calls (the SEC6-5 walk: one call per distinct folder and per recorded file).

### 1.3 Candidate cuts, measured

Each candidate was applied as a runtime wrapper (no source edit): `r1p1_exp.py` (a pytest plugin, `-p r1p1_exp`) and the same wrappers in `R1-P1-profile-script.py`, selected by `R1P1_EXP`.
- **gather** — the gather receives each composition name once (`dict.fromkeys`, order kept).
- **isfile** — the gather's composition limb tests `(resolved_project / name).is_file()` without `resolve()` first (the function re-compiled from its own source with that one line changed).
- **memo** — one manifest read or serialize resolves each distinct entry text once; a clean result (a path, no finding) is reused for the same walk, entry and mode.

The real node, trigger → outcome line, 5 runs each (`R1-P1-node-experiments.txt`):

| Candidate | runs (s) | max | margin at max |
|---|---|---:|---:|
| none (tree `e266395`) | 1.290 1.215 1.113 1.179 1.137 · 1.282 1.188 1.177 1.141 1.312 | 1.312 | −31 % (FAILED 10/10) |
| memo | 1.062 1.038 1.073 1.190 1.103 | 1.190 | −19 % |
| gather | 0.847 0.991 0.964 0.954 0.959 | 0.991 | 1 % |
| gather + memo | 0.807 0.826 0.733 0.834 0.883 · 0.844 0.832 0.729 0.811 0.842 | 0.883 | 12 % |
| isfile | 0.776 0.760 0.745 0.615 0.696 | 0.776 | 22 % |
| **gather + isfile** | 0.674 0.739 0.730 0.650 0.741 | **0.741** | **26 %** |
| gather + isfile + memo | 0.571 0.698 0.615 0.594 0.656 · 0.582 0.702 0.621 0.524 0.622 | 0.702 | 30 % |

The script view of the same candidates (`R1-P1-experiments-script-runs.txt`) agrees: gather + memo leaves the worker at 0.50–0.97 s. Under gather + memo the profile (`R1-P1-cprofile-gather-memo.txt`) still shows `gather_project_artifacts` at 0.314 s with 1 019 `resolve()` calls: the per-name `resolve()` is the cost, not only its duplication.

**Choice for E1: gather + isfile** (both in `gather_project_artifacts`, one file). It meets the plan's target (≤ 0.8 s alone, ≥ 20 % margin) on 5/5 runs on a loaded host. memo adds about 0.06 s but changes the SEC6-5 entry reader that Inc 4 edits next (`variant_execution_service.py`); it is not taken (decision D-2 in `E1-rulings.md`).

**What isfile changes besides time.** On Windows the two forms agree for every existing path (the Win32 layer folds `..` before the call and `is_file()` follows links). They differ when the joined path runs through a link loop: `resolve()` raises `RuntimeError` (measured: a junction that points to itself, `Symlink loop from '…\loop\x.json'`), which today leaves the gather and ends the save through the worker's unexpected-error path; `is_file()` returns `False`, so the name falls through to the common-library lookup and the save goes on. E1 states that outcome as its own row (R-PROJ-GATHER.13); E4 proves the base behaviour RED.

### 1.4 The worker step against the base handler

The backlog's base figure (0.71–0.79 s at `4dfb5a1`, batch-100) was measured on another day. Same day, same host, interleaved, each tree's own node (`R1-P1-base-4dfb5a1-vs-head.txt`; base from `git archive 4dfb5a1` into a temp folder, its `s19_app` imported):

| Run | base `4dfb5a1` (save in the handler; its clock stops when the poll notices) | head `e266395` (save on a worker; clock stops at `set_status`) |
|---:|---:|---:|
| 1 | 1.027 | 1.267 |
| 2 | 0.976 | 1.322 |
| 3 | 0.981 | 1.331 |
| 4 | 0.985 | 1.167 |
| 5 | 0.953 | 1.192 |

The head is 0.2–0.35 s slower than the base, although the base's clock is the more generous one. The services the save calls (`project_gather_service.py`, `manifest_writer.py`, `variant_execution_service.py`) are byte-identical between the two trees, so the 2 000 `resolve()` calls were already in the base. Part of the difference is contention between the worker and the event loop: with a quiet waiter (the test side sleeps 0.25 s instead of pausing the app) the worker step takes 0.74–0.91 s against 0.84–1.37 s with the busy waiter (`R1-P1-busy-vs-quiet-waiter.txt`, 8 runs each, worker end minus worker start). The rest is spread over the 12b worker hand-off (three `call_from_thread` progress steps, the thread start) and was not split further: the cut of §1.3 removes more than the whole difference, so the split would not change the design.

### 1.5 Floor

After gather + isfile the remaining worker time is the two manifest passes of SEC6-5: one `lstat` per distinct folder and per recorded file in the serializer's refusal predicate and again in the verifying re-read. These are security checks with their own rows; E1 does not touch them.

## 2. The painted ~1 s step (routed from Inc 2, ruling R-3)

Inc 2 saw the `painted` intervals of the TC-B100-61 / SEC6-5 arms take either about 0.001 s or 0.60–1.36 s on every tree, never in between (`../inc-2/E4-integration-notes.md` §4, §8 item 2 on branch `b101-inc2`; `evidence/inc-2/e5c-painted-base-vs-head.txt`). Question: does the product paint on a ~1 s cadence, or does the test clock (`_paint_clock_start`, `tests/test_b100_project_check.py:774` on `b101-inc2`, `:767` on `e266395`) mis-measure?

### 2.1 Method

`painted-step-script.py` drives the scene of `test_tc_b100_61_every_array_at_the_cap_all_bad_opens_under_one_second` exactly as the test does (Load dialog, click `#load_ok`, the test's own `_wait_for` on `#result_summary` with a height, the test's `painted` formula) and adds marks: the routed load handler entered, the install callback (it pushes `LoadResultScreen`), the panel's `compose`, every `_refresh_layout` of the panel screen with the summary's height at its end, every `_compositor_refresh` (a frame written for the panel), the test's predicate first true, and a candidate product stamp from public Textual API: the first publish of the pushed screen's `screen_layout_refresh_signal` (sent after a layout and its compositor refresh) at which `#result_summary` has a height, subscribed by the app from a wrapper of `push_screen`.

### 2.2 Result (`painted-step-marks.txt`, 8 runs; seconds after the click returned)

| Run | install ends | first layout ends (summary height) | signal stamp | predicate first true | test's `painted` | stamped: install end → signal |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 0.317 | 0.630 (6) | 0.630 | 1.229 | 0.912 | 0.313 |
| 2 | 0.350 | 0.681 (6) | 0.681 | 1.262 | 0.912 | 0.331 |
| 3 | 0.274 | 0.599 (6) | 0.599 | 1.097 | 0.823 | 0.324 |
| 4 | 0.483 | 0.657 (6) | 0.657 | 1.233 | 0.750 | 0.174 |
| 5 | 0.211 | 0.392 (6) | 0.392 | 0.982 | 0.771 | 0.181 |
| 6 | 0.348 | 0.772 (6) | 0.772 | 1.391 | 1.043 | 0.424 |
| 7 | 0.425 | 0.811 (6) | 0.811 | 1.396 | 0.972 | 0.386 |
| 8 | 0.379 | 0.793 (6) | 0.793 | 1.449 | 1.070 | 0.414 |

- The panel's summary has its height (6 rows) at the end of the **first** layout pass, and that same pass writes a frame of the panel. The signal stamp falls on that moment in 8/8 runs.
- The predicate first reads true 0.50–0.66 s later, after a second and a third layout pass of the panel screen (marks `layouts` in the transcript). The main-thread profile from the click to the predicate (`painted-step-main-profile.txt`) shows where that time goes: 12 `Screen._refresh_layout` calls (0.835 s cumulative), the screen's resume (`_on_screen_resume`, 0.247 s) and a resize of the screen (`_on_resize`, 0.306 s). `pilot.pause()` returns only when the app's message queues are empty, so the base `_wait_for` loop evaluates its predicate after those passes.
- No pass is periodic: the gaps between passes vary (0.07–0.30 s) and nothing repeats at about 1 s. The only product timer near this path is the busy tick, 0.1 s (`app.py:364`).

**Diagnosis.** The ~1 s values are install → app idle, not install → panel painted. The 0.001 s values are runs in which the click's own pause had already waited past the panel, so `pressed` falls after the paint and the poll's first check succeeds. Both are artefacts of a clock that stops when a poll notices, which the clock rule of Inc 2 forbids (R-TST-047, branch `b101-inc2`). The product paints the panel inside its 1 s bound with 58 % margin or more (0.17–0.42 s).

**The requirement follows the diagnosis**: test-clock rows (R-TST-110, R-TST-111), no product change.

### 2.3 The `sec6_5 appended` arm

Same file, `_timed_load_panel_and_append` (`tests/test_b100_project_check.py:875` on `e266395`): the clock starts just before `app.load_from_path(source)` and stops when `_wait_for` notices a manifest outcome line. `appended-stamp-script.py` stamps `set_status` receiving that line (`appended-poll-vs-stamp.txt`; distinct-folders scene, the worst case of the three, 6 runs):

| | min | max | over 0.8 s |
|---|---:|---:|---:|
| poll clock (the test's) | 0.870 | 1.141 | 6/6 |
| stamp: `load_from_path` → outcome line painted | 0.591 | 0.958 | 4/6 |

The poll adds 0.1–0.4 s. Stamped, the arm stays under its 1 s bound in 6/6 runs, but 4/6 have a margin under 20 %. `appended-split-script.py` (`appended-split.txt`, profiler on, so inflated) splits it: the file load before the sync takes 0.12–0.31 s; the variant-append sync 0.65–0.75 s, of which the re-read of the hostile manifest (`read_project_manifest` inside `_rewrite_project_manifest`: 6 000 entries, 5 000 `lstat`, 6 000 `stat`) is the largest part and `validate_project_files` runs twice (once at the sync's start, once under `_activate_project_file`; 3 000 folders listed each time). Those are the SEC6-5 checks at the folder ceiling plus one repeated folder listing — a product margin outside this increment's plan row. It goes to the orchestrator as decision D-4 (recommendation: backlog row, not this increment).

## 3. What was not measured

- The LAN Linux host: not used at E1. The plan's target is "run alone"; E5 measures the head on Windows and Linux.
- The quiet/busy split of §1.4 was not pushed to the last 0.1 s (reason given there).
- `TC-B100-61 cap painted` (`test_tc_b100_61_files_at_the_cap_all_missing_are_bounded`) and the junction-loop SEC6-5 arm were not instrumented separately: they share `_paint_clock_start` and the same poll end point, so the diagnosis applies to them by construction; E4's RED/GREEN runs cover each node.
