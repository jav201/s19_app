# Inc 8b — E4 tester notes

Stage E4 (test design, parallel to implementation) of the `design-first-increment` pipeline. Tests written from the approved graph examples (`codewire/proto-8b-app.md`, `codewire/proto-8b-gather.md`), the token table of `proto-8b-app.md`, the rulings R1–R16 (`E3-rulings.md`) and the thresholds / negative controls of `01-requirements.md`; the implementers' code was not read. RED evidence: `../evidence/inc-8b/red-01-vs-base.txt` (cwd = the base worktree at `ebe6d0c`, test files copied in and restored; `s19_app.__file__` printed in the header).

## Files

| File | Change |
|---|---|
| `tests/test_b100_project_homes.py` | NEW module (the module §5.3 names for TC-B100-31/32/33/62 and AT-B100-09/10/11) |
| `tests/test_b100_save_image.py` | TC-B100-59 Inc 8b arms appended (the module §5.3 names for LLR-167.6a–g) |
| `tests/support/b100_projects.py` | Inc 8b builders appended (save-as trees, links / junctions at depth, links-only folder, bulk files, nested empty folders, deep path, extended-length names, digest walk, R7 total oracle, another work area's project) |
| `tests/test_id_registry.py` | `EXPECTED_SCANNED_TEST_FILES` 225 → 226 (measured: `scanned_test_files()` = 226) |

## Re-pins the design intends (old → new → requirement)

None of the existing assertions found by search pins a behaviour 8b changes:

- "Project already has a MAC file." / "Project already has an A2L file." (in-body text, LLR-167.6c/d move them to the plan with a next step): 0 existing assertions.
- "No supported files in project: …" (LLR-171.2d/e replace it): 0 existing assertions.
- A Save project parent other than the work area (LLR-171.3 refuses it): every existing save passes `app.workarea` (or the work area spelled as `parent`, `tests/test_tui_app.py:85`).
- An open-project save that writes an empty `batch` over P's (C-7, R4): 0 existing assertions; the `batch == []` assertions in `test_b100_project_check.py` / `test_b100_announce.py` are manifest-READER arms.

Watch items for the integration step (not re-pins; they may move only if the implementation diverges from the graph):

- `tests/test_tui_app.py:87` asserts `current_project_dir == (parent / "P1").resolve()`; 8b sets `project_dir = self.workarea / cleaned` (unresolved, step 2). Equal when `tmp_path` is already in resolved form, which it normally is on this machine; if a short-name or junction spelling appears, this is the design-intended change (LLR-171.3a: `W/P` textually), old → `(parent/"P1").resolve()`, new → `app.workarea / "P1"`.
- `tests/test_b99_load_project.py:163`, `tests/test_tui_app.py:377`, `tests/test_tui_helpers.py:141`, `tests/test_b100_save_guards.py:421` call `list_projects()` on plain folders only; the new link check must keep them listed.

## Requirement → test coverage

(H = `tests/test_b100_project_homes.py`, S = `tests/test_b100_save_image.py`.)

| Requirement / AT | Node(s) |
|---|---|
| HLR-171, AT-B100-09 | H `test_at_b100_09_save_as_copies_the_project_and_q_lists_its_flow[size0,size1]` |
| LLR-171.1, .1f | H `test_tc_b100_31_save_as_copies_every_subfolder_file`, `..._top_level_files_but_not_the_backups`, `..._with_no_subfolder_copies_none` |
| LLR-171.1a, .1b, .1c | H `test_tc_b100_31_links_are_skipped_and_named`, `test_tc_b100_31_junction_cycle_ends` |
| LLR-171.1d, .1e, .1i | H `test_tc_b100_31_free_space_is_checked_before_any_folder[T-1 refused, T saved]`; S `test_tc_b100_59_plan_total_counts_every_written_byte`, `test_tc_b100_59_plan_total_rounding_per_file` |
| LLR-171.1g | H `test_tc_b100_31_merge_and_save_into_itself_copy_no_subfolder`; S `..._plan_total_counts_every_written_byte` (merge plan) |
| LLR-171.1h | H `test_tc_b100_31_save_as_carries_the_open_projects_records` |
| LLR-171.1j | H `test_tc_b100_31_copy_ceiling_2000_files`, `test_tc_b100_31_depth_ceiling[32,33]`, `test_tc_b100_31_entry_ceiling[10000 saved,10001 refused]` |
| LLR-171.1k | H `test_tc_b100_31_unreadable_entries_refuse_the_save[1,12]` |
| LLR-171.1l | H `test_tc_b100_31_flow_session_folder_follows_q` |
| LLR-171.6, .6a | H `test_tc_b100_31_empty_selection_keeps_batch_for_every_target` |
| LLR-171.6b | H `test_tc_b100_31_gather_takes_names_from_the_recorded_batch_and_assignments` |
| LLR-171.7, .7a | H `test_tc_b100_31_link_line_names_at_most_ten`, `test_tc_b100_31_link_names_are_scrubbed`, `test_tc_b100_31_painted_names_clip_scrub_and_count` |
| LLR-171.7b | H `test_tc_b100_31_failed_copy_rolls_back_in_user_terms` |
| HLR-171a, AT-B100-10 | H `test_at_b100_10_a2l_only_project_saves_and_reopens[size0,size1]` |
| LLR-171.2, .2b | H `test_tc_b100_32_a2l_only_project_opens_with_its_own_a2l` |
| LLR-171.2a | H `test_tc_b100_32_a2l_only_load_clears_the_previous_data_file` |
| LLR-171.2c | H `test_tc_b100_32_data_file_loaded_into_a2l_only_project_is_recorded` |
| LLR-171.2d, .2e | H `test_tc_b100_32_empty_folder_is_refused_before_any_reset[2 arms]` |
| LLR-171.2f | H `test_tc_b100_32_a2l_guard_of_an_a2l_only_folder[link, over cap, at cap]` |
| LLR-171.2g | H `test_tc_b100_32_over_cap_a2l_beside_a_data_file_is_left_out` |
| LLR-171.3 | H `test_tc_b100_33_foreign_parent_is_refused_before_any_folder[3 arms]` |
| LLR-171.3a | H `test_tc_b100_33_work_area_under_another_spelling_saves_there[4 arms]` |
| HLR-171b, AT-B100-11 | H `test_at_b100_11_junction_project_is_not_listed_and_save_refuses_it[size0,size1]` |
| LLR-171.4c | H `test_tc_b100_62_listing_leaves_out_links_and_junctions` |
| LLR-171.4e | H `test_tc_b100_62_load_refuses_a_junction_project[evil, alias]` |
| LLR-171.4f | H `test_tc_b100_62_load_refuses_a_folder_outside_the_work_area[dot-dot, two-part]` |
| LLR-171.4g | H `test_tc_b100_62_save_target_junction_is_refused[new name, merge target]` |
| LLR-167.6a | S `test_tc_b100_59_save_as_plans_one_row_per_subfolder`, `test_tc_b100_59_links_only_folder_and_skipped_links` |
| LLR-167.6b | S `test_tc_b100_59_links_only_folder_and_skipped_links`; H `test_tc_b100_31_links_are_skipped_and_named` (status side) |
| LLR-167.6c, .6d | S `test_tc_b100_59_second_companion_is_refused_before_any_folder[mac, a2l]` |
| LLR-167.6e | S `test_tc_b100_59_document_row_owns_its_landing` |
| LLR-167.6f | S `test_tc_b100_59_own_a2l_by_name_and_bytes[True, False]`; H `test_at_b100_10_*` (two saves into itself) |
| LLR-167.6g | S `test_tc_b100_59_file_over_the_cap_is_refused_in_the_plan[1, 0]`, `test_tc_b100_59_plan_cap_refusal_names_the_file[1025, 1024]` |

## Uncovered (named, not omitted)

- **G-1 LLR-171.4h** (8 named writers, 16 + 8 junction arms): no new node; the Inc 1 arms in `test_b100_reuse.py` / `test_b100_project_check.py` stay; the Save writers' swap arm (`W/P` swapped for a junction after the load, save into P) and the swap between plan and copy are not written.
- **G-2 LLR-171.1m** (Patch Editor rebind inside P, S3R2-5 `..` and skipped-junction arms): not written.
- **G-3 R14** (carried top-level rows counted once in `total_bytes`): no node combines a top-level copy with a free-space boundary; the planner nodes use `files` rows + sub-folder copies only.
- **G-5 R16 / S3R2-1 walker bound**: the 10 001-entry arm asserts the refusal and a 5 s bound; it does not spy on `walk_tree_no_links`'s yield count or the `sorted` sizes (the 50 000-file single-folder arm of the gather prototype is not written).
- **G-6 LLR-171.2g S3R2-3 MAC arm** (parse spy on `_load_a2l_data_with_cache` beside a MAC): not written.
- **G-7 LLR-171.5** (copied-but-not-recorded line; a device-stem file in the common library): not written.
- **R2 / R11 ordering arms**: the `changes_1.json` landing (pasted document vs a different `P/patches/changes.json`), the call-order spy, `firmware_1.s19` (F-8) and the `fw.s19` / `fw_2.s19` mismatch abort are not written; only the carried-row single placement and the variant rebuild of R11 are.
- **S3-6 token row 9** (the open project folder swapped for a junction before a save as), **A3-13 precedence**, **LLR-171.1k** "folder cannot be listed" and reserved-device-name arms (only the trailing-dot arm is written), and the `inventory_project_tree` unit arms of the gather prototype other than those reached through `plan_project_save`.
- **AT-B100-10 Loaded panel**: asserted on the painted `#loaded_panel` strips; the Execute-on-A2L-only crash check (Q11) is not written.

## Environment limits

- Windows-only arms (junctions, file symbolic links, trailing-dot names) skip with a named reason off Windows; file symbolic links need Developer Mode or privilege (available here: probe `symlink ok`).
- The 2 000-file save and the 10 000-entry walk run on the main thread; their times are printed in the GREEN transcript (R12, R16). The RED run cannot measure the shipped copy time (the base copies no sub-folder).
- No full suite and no census were run (E4 scope).

## RED on base (`ebe6d0c`) — `../evidence/inc-8b/red-01-vs-base.txt`

One complete run, cwd = the base worktree, `s19_app.__file__` = the base tree's `s19_app/__init__.py`, base `git status` clean after the restore. Result: **57 failed, 8 passed** (65 selected), 348 s.

- **Behavioural RED: 52** — each fails on its own assertion against the base's observable behaviour (Q lacks the sub-folder / top-level files; no link line; free space unchecked; `batch` cleared; ceilings and unreadable entries not refused; no rollback; session strip names P; "No supported files in project: …"; the A2L attached beside an over-cap guard; foreign parent refused only after `mkdir` ("Cannot save project: Refusing to place…") or `W/patches/P` created; spellings kept; junction projects listed and loaded; MAC / A2L refusals after `mkdir` without a next step; the own A2L refused by name).
- **Import RED: 5** — only NEW symbols: `painted_names` (1 node: `test_tc_b100_31_painted_names_clip_scrub_and_count`) and `inventory_project_tree` (4 nodes: `test_tc_b100_59_plan_total_counts_every_written_byte`, `..._plan_total_rounding_per_file`, `..._plan_cap_refusal_names_the_file[1025-True,1024-False]`). `plan_project_save(..., inventory=, size_cap=)` and `SavePlan.folders / copies / skipped_links / total_bytes` are reached only behind that import.
- **Passing at base (guards, by design): 8** — `..._save_as_with_no_subfolder_copies_none`, `..._free_space_...[T saved]`, `..._merge_and_save_into_itself_copy_no_subfolder`, `..._entry_ceiling[10000 saved]`, `..._work_area_under_another_spelling_saves_there[trailing separator]`, `test_tc_b100_62_save_target_junction_is_refused[new name, merge target]` (LLR-171.4g holds at base), `test_tc_b100_59_document_row_owns_its_landing`. Each is the positive/boundary side of a mutant in `E4-mutants.md` (M16, M24, M34, M57, M63, M71).

`../evidence/inc-8b/red-00-vs-base-superseded.txt` is the first pass (56 failed, 8 passed): 11 of its failures were wait timeouts (the base's refusal texts were not in the outcome list, and the Load dialog was closed with an unbound `escape`), not assertions. The waits were made tolerant, the 2c node got a precondition assertion, the 2g node goes through the dialog router (the panel opens only there), the LLR-171.6b node was added, and the whole selection was run again as `red-01`.


## Re-pins and test fixes at E4 integration (old → new → requirement)

Applied by the E4 integration step (`E4-integration-notes.md`). Each keeps the test's intent; none weakens an oracle.

- **RP-1** `tests/test_b100_save_image.py::test_tc_b100_59_gather_service_imports_no_change_module` — old: the import set `{__future__, json, os, dataclasses, pathlib, typing, ...validation.model, ..workspace, .variant_execution_service}` → new: the same plus `stat`, `unicodedata` and `..` → requirement: LLR-171.1a/.1k (the inventory's `lstat` mode test), LLR-171.7 / S3R2-4 (`painted_names` removes Unicode categories), pre-ruling 4 (`from .. import workspace`, the cap read at call time). The intent assertion (0 imports whose name holds "change") is unchanged.
- **RP-2** `tests/test_b100_save_image.py::test_tc_b100_69_sec4_junction_save_back_stages_in_this_work_area` — old: `W/J` created as a junction, then loaded through `_handle_load_project("J")` → new: `W/J` is a real folder when loaded, then renamed away and replaced by a junction to the other work area's project before the save-back (the swap LLR-171.4h names) → requirement: LLR-171.4e (a junction project can no longer be loaded). The oracle is unchanged: "Patched image not saved" and 0 new entries in the other work area.
- **RP-3** `tests/support/b100_projects.py::_is_link` — old: `entry.is_symlink() or entry.is_junction()` with `is_junction` defaulted to `False` (`DirEntry.is_junction` is 3.12+, so on 3.11 a junction was followed) → new: `entry.is_symlink()` or the `FILE_ATTRIBUTE_REPARSE_POINT` bit of `os.lstat(entry.path).st_file_attributes` → requirement: the fixture oracles of LLR-171.1d / .1f (`tree_digests`, `walked_entries`). Before the fix `test_tc_b100_31_free_space_is_checked_before_any_folder[T-1 refused]` computed T with the 10 MiB behind the junction (T = 10 596 352) and failed on a fixture defect, not on the code.
- **RP-4** `tests/test_b100_project_homes.py::test_at_b100_10_a2l_only_project_saves_and_reopens` (the Loaded-panel read) — old: `painted_lines(app.query_one("#loaded_panel"))`, which reads the container's own background strips (blank lines at both sizes) → new: the painted lines of every `Static` cell under `#loaded_panel` → requirement: AT-B100-10 "the painted Loaded panel names `firmware.a2l`". Probe (headless, 118 × 54): the A2L slot paints `firmware.a2l  3 tags` with ruling D-5 in place, `(none)` without it (mutant M85).
- **Watch items, no change needed:** `tests/test_tui_app.py:87` and the four `list_projects()` callers (`test_b99_load_project.py:163`, `test_tui_app.py:377`, `test_tui_helpers.py:141`, `test_b100_save_guards.py:421`) — see the GREEN transcript.
- **RP-5** `tests/test_b100_reuse.py::test_tc_b100_01_app_placements_name_the_workarea_root` — old: 8 `app.py` placement calls → new: 9, plus exactly 1 placement inside `_copy_project_subfolders` (it names `workarea_root`, like every call) → requirement: LLR-171.1 / pre-ruling 1 (the save-as copy goes through the guarded placement), LED .50.
