# Inc 3 — E1 slice: functions to change, mapped to rows

Base `e266395`. Line numbers are `e266395`'s for `s19_app/`; for `tests/test_b100_project_check.py` both `e266395` and `b101-inc2` (Inc 2 merges first and moves lines) are given.

## 1. Source files (2 of the cap of 4)

| # | File | Function | Change | Rows |
|---:|---|---|---|---|
| 1 | `s19_app/tui/services/project_gather_service.py` | `gather_project_artifacts` (`:525`; composition limb `:654-668`) | the composition loop skips a name it has already checked in this call; the check is `(resolved_project / name).is_file()`, no `.resolve()` first (`:656`) | R-PROJ-001.13, R-PROJ-GATHER.12, R-PROJ-GATHER.13 |
| 2 | `s19_app/tui/app.py` | `S19TuiApp._sync_loaded_file_to_project` (`:14572`) | the line `project_dir.mkdir(parents=True, exist_ok=True)` (`:14615`) goes; the `try` keeps `validate_project_files(project_dir)` and its `except OSError` refusal | R-PROJ-002.12, R-PROJ-002.14 |
| 3 | `s19_app/tui/app.py` | `S19TuiApp._sync_loaded_a2l_to_project` (`:14725`) | the same line (`:14738`) goes | R-PROJ-002.13, R-PROJ-002.14 |

**Count: 3 functions in 2 source files.** `project_gather_service.py` is outside the plan row's file list (decision D-1). No other function under `s19_app/` changes; no signature changes; no new import.

Callers checked (read before writing, rule 8):
- `gather_project_artifacts` has one product caller, `S19TuiApp._save_project_files` (`app.py:11848`), which passes `composition_names = list(batch) + [assignment names]` (`:11836`) and only logs the returned issues (`:11860`). Tests call it directly in `tests/test_project_gather.py` (15 tests) and elsewhere; the change keeps its signature and its outcome for every input without duplicates or link loops.
- `_sync_loaded_file_to_project` is posted by the file-load worker (`app.py:18014`, `call_from_thread`); `_sync_loaded_a2l_to_project` is called from the A2L install (`:15351`). Neither caller reads a return value.
- `validate_project_files` (`workspace.py:1874`) iterates `project_dir.iterdir()` (`:1911`): a missing folder raises `FileNotFoundError`, a file in the folder's place `NotADirectoryError` — both `OSError`, both caught by the existing `except OSError` of each sync.

## 2. Test files (no new file; tests are not capped)

| # | File | Function / node | Change | Rows |
|---:|---|---|---|---|
| 4 | `tests/test_b100_project_check.py` | `_paint_clock_start` (`:767` base, `:774` inc-2) | returns the install stamp (`app._load_returned_at`), not `max(pressed, …)` | R-TST-110 |
| 5 | same | new helper: the panel paint stamp (a `push_screen` wrapper that subscribes the app to the pushed `LoadResultScreen`'s `screen_layout_refresh_signal`, `immediate=True`, and records the first publish with `#result_summary` height > 0) | new | R-TST-111 |
| 6 | same | `test_tc_b100_61_every_array_at_the_cap_all_bad_opens_under_one_second` (`:788` base, `:796` inc-2) | `painted` = paint stamp − install stamp; its wait stays only as the arm's precondition | R-TST-110, R-TST-111, R-TST-113 |
| 7 | same | `test_tc_b100_61_files_at_the_cap_all_missing_are_bounded` (`:1295` base, `:1325` inc-2) | as 6 | R-TST-110, R-TST-111, R-TST-113 |
| 8 | same | `_timed_load_panel_and_append` (`:875` base, `:887` inc-2) and `_sec6_5_filesystem_scene` (`:909` base, `:921` inc-2) | `painted` as 6; `appended` = outcome-line stamp (a `set_status` capture already in the scene, `_capture`) − the `load_from_path` call | R-TST-110, R-TST-111, R-TST-112, R-TST-113 |
| 9 | `tests/test_project_gather.py` | new nodes for R-PROJ-GATHER.12 (count of project-folder checks on 2 000 names) and R-PROJ-GATHER.13 at gather level | new | R-PROJ-GATHER.12, R-PROJ-GATHER.13 |
| 10 | `tests/test_b100_workers.py` | new nodes for R-PROJ-002.12/.13 deleted alternative and R-PROJ-002.14 (S19, HEX, MAC, A2L) | new | R-PROJ-002.12, R-PROJ-002.13, R-PROJ-002.14 |
| 11 | `tests/test_b100_active_variant.py` or `tests/test_b100_workers.py` | new node: Save project with a junction loop at a composition name ends `Project saved + manifest verified` (Windows only) | new | R-PROJ-GATHER.13 |
| 12 | `tests/test_b100_active_variant.py` | `test_tc_b100_20_writers_on_a_31_folder_manifest_finish_under_one_second[save-project]` (`:650` base) | **unchanged**; it verifies R-PROJ-001.13 (bound 1 s through `report_margin` on `b101-inc2`; the 0.8 s target is read from its QC-TM row) | R-PROJ-001.13 |
| 13 | a static check (proposed in `tests/test_b100_project_check.py`) | new node: the 4 panel/append bound sites are `report_margin(…, timing_bound(1.0))` | new | R-TST-113 |

Proposed new node names (E4 may refine the tail; the `test_r_<id>` prefix binds the trace):
- `tests/test_project_gather.py::test_r_proj_gather_12_each_distinct_composition_name_is_checked_once`
- `tests/test_project_gather.py::test_r_proj_gather_13_a_link_loop_at_a_composition_name_is_not_raised`
- `tests/test_b100_active_variant.py::test_r_proj_gather_13_save_goes_on_past_a_link_loop_at_a_composition_name`
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

Census to run at E5 (Inc 2's census rule R-TST-060): `grep -rn "gather_project_artifacts\|composition document\|sync NOT done\|_paint_clock_start\|painted\b" tests/` and run every node it finds.

## 4. Interfaces with other increments

- **Inc 2 (merged before E4):** uses `report_margin`, `timing_bound`, `wait_until`, the `serial_timing` marker and the clock rule R-TST-047. Inc 3 changes no file Inc 2 owns except `tests/test_b100_project_check.py`, which Inc 2 also edited (37 `report_margin` wraps): E4 starts from the merged file. Inc 2's wrap guard R-TST-049 compares wrapped functions with the merge base; after Inc 2's merge the merge base already carries the wraps, so Inc 3's body changes are outside that guard's trigger (it fires only when a change adds a marker or a `report_margin` wrap).
- **Inc 4 (next on the `app.py` chain):** edits `app.py` elsewhere (F-01 sites) and `variant_execution_service.py`. Inc 3 changes neither the reader nor any line near Inc 4's sites.
- **Inc 7, 8, 11, 13, 14 (parallel):** no shared file. `project_gather_service.py` is in no other plan row.
- **R-TST-008 (Inc 2's owed gate evidence):** depends on items 2 and 3 of §1 of `E1-rulings.md`; E5 here runs the serial lane's panel/append arms and TC-B100-20 so Inc 2's owed gate can follow.
