# Inc 3 -- E4 tester notes (independent tester)

Batch 2026-11-01-batch-101, increment 3. Written from the approved design (`01-requirements.md`, `02-test-cases.md`, `codewire/graph-inc3.md`, `E1-slice.md`, `E1-rulings.md`, `E3-rulings.md`). The implementer's source changes were not read. Evidence states: `executed` for runs below; nothing here is `approved`.

Base revision for RED: `9f9f6af` (merge-base of the branch with local `main`; it already holds Inc 2's merge, so `report_margin`, `serial_timing` and `wait_until` exist). Transcript: `.dev-flow/2026-11-01-batch-101/evidence/inc-3/red-01-tester-base.txt` (redacted). Runs were made in a detached worktree outside the repo with only the four test files copied in; the worktree was removed afterwards. Python 3.11.15, textual 8.2.8, Windows.

## 1. Test files (all CRLF kept; no source file edited; no AT-/TC- token added to a new node)

| File | New nodes | Existing nodes re-pinned (names unchanged) |
|---|---|---|
| `tests/test_project_gather.py` | 3 | none |
| `tests/test_b100_active_variant.py` | 1 | none (`...[save-project]` left unchanged on purpose, slice row 12) |
| `tests/test_b100_workers.py` | 11 (1 + 6 + 4 ids) | `test_tc_b100_54_file_load_sync_refuses_when_the_project_folder_is_gone`: docstring only (E1-slice row 15) |
| `tests/test_b100_project_check.py` | 5 (1 + 3 + 1) | the 6 nodes of E1-slice section 3, through `_paint_clock_start`, `_timed_load_panel_and_append`, `_sec6_5_filesystem_scene` and the two arm bodies. Each keeps its `report_margin` call count. Their bare-`pilot.pause()` waits became `wait_until` |

New helpers in the project-check file: `_paint_clock_start` (re-pinned), `_summary_laid_out`, `_watch_panel_paint`, `_StampObserver`, `_function_calls`, `_bound_sites`, `_off_one_second`, `_distinct_folders_scene`. `_timed_load_panel_and_append` gained a `stamps` parameter.

## 2. Case to test mapping

"full" = the product produces what the test asserts; "partial" says why not.

| Case | Test (file::name) | Mapping |
|---|---|---|
| R-PROJ-001.13/1 | test_b100_active_variant.py::test_tc_b100_20_writers_on_a_31_folder_manifest_finish_under_one_second[save-project] (existing, unchanged) | partial: asserts the 1 s bound; the 0.8 s target is read from its QC-TM row at E5, not asserted |
| R-PROJ-GATHER.12/1, /2, /3 | test_project_gather.py::test_r_proj_gather_12_each_distinct_composition_name_is_checked_once (3 arms in one node) | partial: the counter spies two seams (`Path.is_file`, `os.path.isfile`); /3 passes on base by construction and discriminates on POSIX only |
| R-PROJ-GATHER.13/1 | ::test_r_proj_gather_13_a_link_loop_at_a_composition_name_is_not_raised | full (Windows junction; skipped elsewhere) |
| R-PROJ-GATHER.13/2 | ::test_r_proj_gather_13_a_posix_self_symlink_at_a_composition_name_is_not_raised | full (ran here: symlinks were creatable; skips where not) |
| R-PROJ-ROLLBACK.9/1 and .2/1 | test_b100_active_variant.py::test_r_proj_rollback_9_2_a_link_loop_at_a_composition_name_ends_in_the_rollback_refusal | full (Windows only; one node for both cases, as the design names it) |
| R-PROJ-002.12/1 | test_b100_workers.py::test_tc_b100_54_file_load_sync_refuses_when_the_project_folder_is_gone (existing) and ::test_r_proj_002_12_..._deleted[file-in-place-s19] | full |
| R-PROJ-002.12/2, /3, /4 | ::test_r_proj_002_12_file_load_sync_refuses_when_the_project_folder_was_deleted[deleted-s19 / deleted-hex / deleted-mac] | full |
| R-PROJ-002.12/5, /6 | same node [file-in-place-hex / file-in-place-mac] | full (hold on base) |
| R-PROJ-002.13/1 | test_tc_b100_54_a2l_sync_refuses_when_the_project_folder_turns_unreadable (existing) | full |
| R-PROJ-002.13/2 | ::test_r_proj_002_13_a2l_sync_refuses_when_the_project_folder_was_deleted_mid_attach | full for the lines; the delete is injected by a wrapper of `copy_into_workarea` on the worker thread, the race itself is not produced |
| R-PROJ-002.14/1-/4 | ::test_r_proj_002_14_sync_into_a_deleted_project_folder_creates_no_folder[s19 / hex / mac / a2l] | full |
| R-TST-110/1 | test_b100_project_check.py::test_r_tst_110_panel_clock_starts_at_the_install_stamp | rule: full; the 3 call sites: partial (an `ast` check that each calls `_paint_clock_start`) |
| R-TST-111/1, /2, /3 and R-TST-112/1 | ::test_r_tst_111_112_arm_values_equal_the_product_stamps[all-bad / scene / cap] (`scene` covers 111/2 and 112/1) | full (`serial_timing`; tolerance see section 5) |
| R-TST-113/1 | ::test_r_tst_113_panel_and_append_bounds_stay_at_one_second | full as a source check; a planted `timing_bound(1.5)` copy is flagged inside the node |

Cases not expressible: none. Uncovered: none of the 26. Skips on other hosts: R-PROJ-GATHER.13/1, ROLLBACK.9/1, ROLLBACK.2/1 (Windows junctions); R-PROJ-GATHER.13/2 where symlinks need a privilege. On the LAN Linux host the junction cases skip and 13/2 is the deterministic catch.

## 3. RED summary (base `9f9f6af`, test files copied in; one complete run each)

| Run | Result | Reason (behavioural) |
|---|---|---|
| gather `-k r_proj_gather_1` | 3 failed | 12: 2 000 project checks instead of 1 000; 13/1 and 13/2: `RuntimeError: Symlink loop` out of `resolve()` |
| workers + active variant (14 nodes) | 9 failed, 5 passed | deleted-s19/hex/mac: no refusal, `Added variant ...` / `manifest verified`; 13/2: no `A2L sync NOT done`, A2L copied into a re-created folder; 14 s19/hex/mac/a2l: folder re-created (`True is False`); ROLLBACK.9/2: the unexpected-error line instead of the project.json refusal. The 5 passes are the 3 `file-in-place` arms and the 2 existing `tc_b100_54` nodes, which hold on base by design |
| project-check `-k r_tst` + the 6 touched | 11 passed | expected: R-TST rows are test-only, so on an unmutated copy the product is identical to base |

RED for the R-TST rows is shown by mutants applied to the test file in the base worktree (same transcript):

| Mutant | Result |
|---|---|
| M-5 `max(pressed, install)` restored | `test_r_tst_110...` fails (12.0 vs 10.0) |
| M-6 panel clock stopped when the wait notices | verifier fails on all 3 params (arm 0.76-0.93 s vs stamps 0.20-0.31 s) |
| M-7 append clock stopped when the wait notices | verifier `[scene]` fails. In the default run the arm's own 1 s bound tripped first (1.17 s); re-run with `CI=1` (looser bound) the equality fails: 1.119 s vs 0.714 s |
| M-8 `timing_bound(1.5)` at `sec6_5 appended` | `test_r_tst_113...` fails naming the label and line |

GREEN control: the same files against my own hand patch of the design on a second worktree of the base: gather 3 passed; workers + active variant 14 passed; project-check R-TST 5 passed and the 6 touched nodes 6 passed; `tests/test_suite_hygiene.py` + `tests/test_id_registry.py` 77 passed. This is not the implementer's tree; E5 owns GREEN on the real one.

## 4. Mutants not run here (E5)
M-1, M-2, M-3, M-4, M-9, M-10, M-11 need source copies; not run. Predictions only (state `planned`): M-11 (rollback loses `written`) is what ROLLBACK.2's `lexists` assertions catch; M-9 survives on Windows by construction.

## 5. Ambiguities and deviations (not resolved by reading the implementation)

1. **Tolerance.** A-1 asks `abs_tol=0.001`. Measured on this host the arm and the observer readings differ by 0.4-0.6 ms (1 ms failed 1 of 3 runs before a reorder fix). I kept the design's mechanism, moved the arm's `push_screen` subscription after the real push so the observer's callback runs first, and set `_STAMP_TOLERANCE_S = 0.005` (a GIL switch interval). Every mutant is 50 ms or more off. Orchestrator: confirm or restore 0.001.
2. **Row count selector.** The graph says `.result-problem`; the arms' final `rows` use `#result_body .result-problem`. I used the latter for the stamp so F4's equality compares like with like.
3. **Gather counter seams** (R-PROJ-GATHER.12): "project-folder file checks" does not name a function. If the implementation checks through `os.stat`/`Path.exists`, the counter reads 0 and the node fails for the wrong reason; widen the seams then.
4. **`sec6_5 load` margin:** 0.971 s of 1.0 s (2.9 %) in one GREEN-control run of the untouched `sec6_5 load` bound of the folder-ceiling arm. Not in Inc 3's rows (D-4 covers `appended`); E5 should read it on the LAN host.
5. **Docstring wording in `...54_file_load_sync...`** names the new base error (`NotADirectoryError`); the gone-folder variants are the new nodes.

## 6. Environment limits
No Linux host run; no CI lane; the full suite and the serial lane were not run (orchestrator, E5). Timing figures are for this host and day.

## 7. Evidence checklist
- [x] Every test named exists on disk at the cited path and name.
- [x] Each result read from one complete run's output; commands quoted in the transcript.
- [x] RED on base captured (product rows); mutant RED for test-only rows; base named (`9f9f6af`).
- [x] Tests assert observable outcomes (status lines, files on disk, recorded stamps).
- [x] Uncovered cases named: none; partials named above.
- [x] Environment limits declared.
- [x] No PII, credentials, home paths or hosts in files (transcript redacted).
- [x] Evidence states: `executed` only.
