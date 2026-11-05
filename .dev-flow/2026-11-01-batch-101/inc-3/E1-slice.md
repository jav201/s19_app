# Inc 3 — E1 slice: functions to change, mapped to rows

Base `e266395`. Line numbers are `e266395`'s for `s19_app/`; for `tests/test_b100_project_check.py` both `e266395` and `b101-inc2` (Inc 2 merges first and moves lines) are given. E3 round 1 corrections carry the finding id in brackets (`E3-rulings.md`).

## 0. Drift on origin/main (`f11b3f4`, batch-102, checked 2026-11-05)

batch-102 merged seven hot-fixes into main. Among them, `s19_app/tui/app.py` gained 621 lines and `workspace.py` 267; `screens.py` changed too. **No slice function changed.** The bodies of `_sync_loaded_file_to_project` and `_sync_loaded_a2l_to_project` are byte-identical (diff of `e266395:app.py` 14572–14760 against `f11b3f4:app.py` 14897–15085: no difference). `project_gather_service.py`, `manifest_writer.py`, `variant_execution_service.py` and the four test files of §2 are unchanged. Only line numbers move. The orchestrator rebases before E4; E4 uses the right-hand column:

| Site | `e266395` | origin/main `f11b3f4` |
|---|---|---|
| `app.py` `_save_project_files` / `composition_names` / `gather_project_artifacts(` call / gather-issue log | 11542 / 11836 / 11848 / 11860 | 11852 / 12146 / 12158 / 12171 |
| `app.py` R-PROJ-ROLLBACK.9 lines (`… project.json was not written. check the folder.`) | 11994–11996 | 12304–12306 |
| `app.py` `_install_prepared_project` / `_activate_project_file` | 13659 / 14517 | 13984 / 14842 |
| `app.py` `_sync_loaded_file_to_project` / its `mkdir` | 14572 / 14615 | 14897 / 14940 |
| `app.py` `_sync_loaded_a2l_to_project` / its `mkdir` | 14725 / 14738 | 15050 / 15063 |
| `app.py` `load_a2l_from_path` / its CR12b-2 guard / A2L sync call | 15186 / 15205 / 15351 | 15511 / 15530 / 15675 |
| `app.py` file-load worker posting the sync | 18014 | 18453 |
| `workspace.py` `place_into_workarea` / its destination `mkdir` | 1032 / 1183 | 1049 / 1200 |
| `workspace.py` `validate_project_files` / its `iterdir` | 1874 / 1911 | 2139 / 2176 |
| `screens.py` `LoadResultScreen` / `#result_summary` | 1652 / 1722 | 2493 / 2563 |
| `project_gather_service.py` composition limb | 654–668 | unchanged |

E4 entry check [F9]: Inc 2's merge commit (PR #212) is an ancestor of `origin/main`. At this check (2026-11-05) it is **not**: `origin/b101-inc2` is not an ancestor of `f11b3f4`. E4 does not start until it is.

## 1. Source files (2 of the cap of 4)

| # | File | Function | Change | Rows |
|---:|---|---|---|---|
| 1 | `s19_app/tui/services/project_gather_service.py` | `gather_project_artifacts` (`:525`; composition limb `:654-668`) | the composition loop skips a name it has already checked in this call (key: the exact text [F11]); the check is `Path(os.path.normpath(resolved_project / name)).is_file()`: `.` and `..` folded lexically [F5], no `.resolve()` (`:656`) | R-PROJ-001.13, R-PROJ-GATHER.12, R-PROJ-GATHER.13 |
| 2 | `s19_app/tui/app.py` | `S19TuiApp._sync_loaded_file_to_project` (`:14572`) | the line `project_dir.mkdir(parents=True, exist_ok=True)` (`:14615`) goes; the `try` keeps `validate_project_files(project_dir)` and its `except OSError` refusal | R-PROJ-002.12, R-PROJ-002.14 |
| 3 | `s19_app/tui/app.py` | `S19TuiApp._sync_loaded_a2l_to_project` (`:14725`) | the same line (`:14738`) goes | R-PROJ-002.13, R-PROJ-002.14 |

**Count: 3 functions in 2 source files.** `project_gather_service.py` is outside the plan row's file list (decision D-1, approved). No other function under `s19_app/` changes; no signature changes; no new import (`os` is already imported in `project_gather_service.py`).

**Out of the slice, must not change [S-1]:** `manifest_writer._reject_unsafe_entry`, `variant_execution_service._EntryWalk`, `variant_execution_service._entry_text` (and the rest of the manifest writer and reader). R-PROJ-ROLLBACK.9/1 depends on the writer refusing the link entry; a change there to make a case pass is a containment regression and a review blocker.

Callers checked (read before writing, rule 8):
- `gather_project_artifacts` has one product caller, `S19TuiApp._save_project_files` (`app.py:11848`), which passes `composition_names = list(batch) + [assignment names]` (`:11836`) and only logs the returned issues (`:11860`). Tests call it directly in `tests/test_project_gather.py` (15 tests) and elsewhere. The change keeps its signature. Its outcome is unchanged for every input except three: duplicate names (findings collapse, E1-D3), a link loop at a name (R-PROJ-GATHER.13), and on POSIX a `..` after a link (judged lexically, E1-D8) [F5].
- `_sync_loaded_file_to_project` is posted by the file-load worker (`app.py:18014`, `call_from_thread`); `_sync_loaded_a2l_to_project` is called from the A2L install (`:15351`). Neither caller reads a return value.
- `validate_project_files` (`workspace.py:1874`) iterates `project_dir.iterdir()` (`:1911`): a missing folder raises `FileNotFoundError`, a file in the folder's place `NotADirectoryError` — both `OSError`, both caught by the existing `except OSError` of each sync.

## 2. Test files (no new file; tests are not capped)

| # | File | Function / node | Change | Rows |
|---:|---|---|---|---|
| 4 | `tests/test_b100_project_check.py` | `_paint_clock_start` (`:767` base, `:774` inc-2) | returns the install stamp (`app._load_returned_at`), not `max(pressed, …)` | R-TST-110 |
| 5 | same | new helper `_watch_panel_paint`: the panel paint stamp. A `push_screen` wrapper subscribes the app to the pushed `LoadResultScreen`'s `screen_layout_refresh_signal` (`immediate=True`) and records the first publish (stamp taken first [N-3]) at which `screen.query_one_optional("#result_summary")` is a widget with height > 0, never `query_one` [F3; id lookup since E4 integration S-1]. With the stamp it records the panel's `#result_body .result-problem` count [F4, OR-3] | new | R-TST-111 |
| 6 | same | `test_tc_b100_61_every_array_at_the_cap_all_bad_opens_under_one_second` (`:788` base, `:796` inc-2) | `painted` = paint stamp − install stamp; asserts the stamp list is non-empty, with the message `the Load-result panel was never laid out with a summary` [F3]; asserts the row count recorded at the stamp equals its final `rows` [F4]; its wait stays only as the arm's precondition; keeps exactly 1 `report_margin` call per bound [F9] | R-TST-110, R-TST-111, R-TST-113 |
| 7 | same | `test_tc_b100_61_files_at_the_cap_all_missing_are_bounded` (`:1295` base, `:1325` inc-2) | as 6 | R-TST-110, R-TST-111, R-TST-113 |
| 8 | same | `_timed_load_panel_and_append` (`:875` base, `:887` inc-2) and `_sec6_5_filesystem_scene` (`:909` base, `:921` inc-2) | `painted` as 6 (incl. the [F3] and [F4] asserts); `appended` = outcome-line stamp (a `set_status` capture already in the scene, `_capture`) − the `load_from_path` call; `_assert_sec6_5_bounded` keeps its 4 `report_margin` calls, none added [F9] | R-TST-110, R-TST-111, R-TST-112, R-TST-113 |
| 9 | `tests/test_project_gather.py` | new nodes for R-PROJ-GATHER.12 (count of project-folder checks on 2 000 names; a repeated missing name; a `..` name [F5]) and R-PROJ-GATHER.13 at gather level, two arms: Windows junction loop, POSIX self-symlink (`os.symlink("x.json", <project>/x.json)`, skipped where symlinks need a privilege the run lacks) [F6] | new | R-PROJ-GATHER.12, R-PROJ-GATHER.13 |
| 10 | `tests/test_b100_workers.py` | new nodes for R-PROJ-002.12/.13 deleted alternative and R-PROJ-002.14 (S19, HEX, MAC, A2L) | new | R-PROJ-002.12, R-PROJ-002.13, R-PROJ-002.14 |
| 11 | `tests/test_b100_active_variant.py` | new node [F1, S-1]: Save project with a junction loop at a composition name ends with R-PROJ-ROLLBACK.9's `Project NOT saved: could not save — project.json was not written. check the folder.` exactly once, 0 lines `an unexpected error stopped the save`, 0 lines `Project saved + manifest verified`, and no `patches/x.json` after the rollback (Windows only; the junction is removed with `os.rmdir`, never a recursive delete through it) | new | R-PROJ-ROLLBACK.9, R-PROJ-ROLLBACK.2 |
| 12 | `tests/test_b100_active_variant.py` | `test_tc_b100_20_writers_on_a_31_folder_manifest_finish_under_one_second[save-project]` (`:650` base) | **unchanged**; it verifies R-PROJ-001.13 (bound 1 s through `report_margin` on `b101-inc2`; the 0.8 s target is read from its QC-TM row) | R-PROJ-001.13 |
| 13 | a static check (proposed in `tests/test_b100_project_check.py`) | new node: the 4 panel/append bound sites are `report_margin(…, timing_bound(1.0))` | new | R-TST-113 |
| 14 | `tests/test_b100_project_check.py` | new verifier node `test_r_tst_111_112_arm_values_equal_the_product_stamps[all-bad|cap|scene]` and its class-level observer [F2]; mechanism in graph nodes `_StampObserver` and the verifier, interfaces I-6, I-7 | new | R-TST-111, R-TST-112 |
| 15 | `tests/test_b100_workers.py` | `test_tc_b100_54_file_load_sync_refuses_when_the_project_folder_is_gone`: docstring only — its negative control names `mkdir` raising `FileExistsError`, which this change removes; the case now passes through `iterdir()` raising `NotADirectoryError` [F8]. Body and name unchanged | docstring | R-PROJ-002.12 |

Proposed new node names (E4 may refine the tail; the `test_r_<id>` prefix binds the trace):
- `tests/test_project_gather.py::test_r_proj_gather_12_each_distinct_composition_name_is_checked_once`
- `tests/test_project_gather.py::test_r_proj_gather_13_a_link_loop_at_a_composition_name_is_not_raised`
- `tests/test_project_gather.py::test_r_proj_gather_13_a_posix_self_symlink_at_a_composition_name_is_not_raised` [F6]
- `tests/test_b100_active_variant.py::test_r_proj_rollback_9_2_a_link_loop_at_a_composition_name_ends_in_the_rollback_refusal` [F1, S-1; was `test_r_proj_gather_13_save_goes_on_past_…`]
- `tests/test_b100_workers.py::test_r_proj_002_12_file_load_sync_refuses_when_the_project_folder_was_deleted`
- `tests/test_b100_workers.py::test_r_proj_002_13_a2l_sync_refuses_when_the_project_folder_was_deleted_mid_attach`
- `tests/test_b100_workers.py::test_r_proj_002_14_sync_into_a_deleted_project_folder_creates_no_folder[s19|hex|mac|a2l]`
- `tests/test_b100_project_check.py::test_r_tst_110_panel_clock_starts_at_the_install_stamp`
- `tests/test_b100_project_check.py::test_r_tst_111_112_arm_values_equal_the_product_stamps`
- `tests/test_b100_project_check.py::test_r_tst_113_panel_and_append_bounds_stay_at_one_second`

## 3. Nodes touched (existing test node names — all kept)

Bodies change, names unchanged:
1. `tests/test_b100_project_check.py::test_tc_b100_61_every_array_at_the_cap_all_bad_opens_under_one_second`
2. `tests/test_b100_project_check.py::test_tc_b100_61_files_at_the_cap_all_missing_are_bounded`
3. `tests/test_b100_project_check.py::test_tc_b100_61_sec6_5_deep_entries_need_one_check_each_parent` (through the shared scene)
4. `tests/test_b100_project_check.py::test_tc_b100_61_sec6_5_entries_under_an_existing_folder_are_all_checked` (through the shared scene)
5. `tests/test_b100_project_check.py::test_tc_b100_61_sec6_5_distinct_folders_stop_at_the_folder_ceiling` (through the shared scene)
6. `tests/test_b100_project_check.py::test_tc_b100_61_sec6_5_junction_loop_costs_one_failure` (through the shared scene; Windows only)

Verifiers re-run, code unchanged:
- `tests/test_b100_active_variant.py::test_tc_b100_20_writers_on_a_31_folder_manifest_finish_under_one_second[save-project]` (and its 4 sibling params, whose writers share nothing changed but run in the same node family)
- `tests/test_b100_workers.py::test_tc_b100_54_file_load_sync_refuses_when_the_project_folder_is_gone`
- `tests/test_b100_workers.py::test_tc_b100_54_a2l_sync_refuses_when_the_project_folder_turns_unreadable`
- every node of `tests/test_project_gather.py` (the gather's other limbs)

Census to run at E5 (Inc 2's census rule R-TST-060): `grep -rn "gather_project_artifacts\|composition document\|sync NOT done\|_paint_clock_start\|painted\b\|current_project = \|current_project_dir = " tests/` and run every node it finds [F10: tests that set `current_project` without creating its folder would have relied on the removed `mkdir`; none found in the E3 sample, the census confirms].

Docstring to update when E4 touches the file: `test_tc_b100_54_file_load_sync_refuses_when_the_project_folder_is_gone` (§2 row 15) [F8].

## 4. Interfaces with other increments

- **Inc 2 (merged before E4; an E4 entry check, §0) [F9]:** uses `report_margin`, `timing_bound`, `wait_until`, the `serial_timing` marker and the clock rule R-TST-047. Inc 3 changes no file Inc 2 owns except `tests/test_b100_project_check.py`, which Inc 2 also edited (37 `report_margin` wraps): E4 starts from the merged file. Inc 2's wrap guard R-TST-049 compares wrapped functions with the merge base; after Inc 2's merge the merge base already carries the wraps, so Inc 3's body changes are outside that guard's trigger (it fires only when a function gains a marker or a `report_margin` call, `head_wraps > base_wraps`). Graph group G2 rule: each edited existing function keeps its `report_margin` call count; no bound moves into a new helper [F9]. The verifier node (row 14) patches `report_margin` and adds no call. Its equality uses `math.isclose(…, abs_tol=0.001)`, not an ordering assert, so Inc 2's margin guard (R-TST-041) does not read it as a raw timing bound. It reaches the arms' bounds through the arms, so Inc 2's census sees it as a timing arm and it carries `serial_timing` (R-TST-002/003).
- **Inc 4 (next on the `app.py` chain):** edits `app.py` elsewhere (F-01 sites) and `variant_execution_service.py`. Inc 3 changes neither the reader nor any line near Inc 4's sites. R-PROJ-ROLLBACK.9/1's expected line depends on the writer's link refusal (`_EntryWalk` / `_lstat_state` in that file); if Inc 4 changes it, that case's expected line changes with it [F1].
- **Inc 7, 8, 11, 13, 14 (parallel):** no shared file. `project_gather_service.py` is in no other plan row.
- **R-TST-008 (Inc 2's owed gate evidence):** depends on items 2 and 3 of §1 of `E1-rulings.md`; E5 here runs the serial lane's panel/append arms and TC-B100-20 so Inc 2's owed gate can follow.
- **E5 corrective (C-11, 2026-11-05).** (1) R-TST-049's "outside that guard's trigger" holds only when the run's local `main` ref is current: on the LAN clone a stale `main` gave an older merge base, and the guard read Inc 2's wraps as drift (`lan-01-lane1.txt`, `lan-01b-hygiene-049-diag.txt`). The orchestrator made the clone's `main` follow `origin/main`; the guard passed in the final LAN lane 1 runs (`e5c-final-lane1-lan.txt`). (2) The verifier's observer now takes its own "laid out" reading instead of calling the arm's `_summary_laid_out` (C-1; graph `_StampObserver`), so it shares no logic with the arms either. (3) The 1 ms equality stays: the stamp-pair gap on the LAN host is +31 to +80 us for the panel and -0.3 to -3.9 us for the append, under N-3's 0.5 ms trigger (C-9, `e5c-c9-stamp-gaps-lan.txt`); the verifier prints each gap (`GAP <label>: … us`) so later runs record it. (4) R-TST-008: E5 ran the serial lane's panel/append arms and TC-B100-20 on the LAN host (`lan-02-*`, `lan-03-*`, `e5c-final-serial-lan.txt`, 0 under 20 % margin on the idle runs); the `sec6_5` margins under load are routed (BACKLOG-CODE, OR-4 / D-4).
