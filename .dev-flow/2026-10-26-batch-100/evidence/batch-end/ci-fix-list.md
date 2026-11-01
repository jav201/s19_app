# CI fix list (batch-100) — new failures beyond the known 6

Known 6 (pre-existing on main): tc1802, b78_03, b78_32, 056e_a2b, tc707_copy, tc707_numbering.

## From 9b CI run 41263643715 (main 2305c8b) — 10 failed / 4571 passed / 200 skipped
| Id | Test | Cause (first read) | Route |
|---|---|---|---|
| CI9b-1 | test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors | screens.py:365-367 LoadDialog.on_mount: `query_one("#load_list" if self._mode == "list" else "#load_path")` — an IfExp selector argument; the census allows literal/name/fstring only. Platform-independent. | Inc 11 corrective (screens.py in scope): two literal query_one calls in an if/else. |
| CI9b-2 | test_loadfilescreen_input.py::test_at042b_ctrl_v_inserts_capped_value_via_real_read | SEC9b-1 put max_length=4096 on #load_path; ruling B: an over-long paste is refused, so value == ''. The older test (LLR-044.x) still expects blob[:CAP]. Platform-independent. | Inc 11 corrective: re-pin at042b to ruling B (SEC9b-1), cite LLR-173.x; reason in the docstring. |
| CI9b-3 | test_b100_load_dialog.py::test_tc_b100_43_no_filesystem_call_touches_a_recent_before_load | Linux only: the Recent section shows 1 row ('fw.s19') instead of 3; the seeded Windows-style 'Q:\nowhere\fw.s19' and/or posix paths are handled differently by the store/label on posix. | Batch-end fix round (analyse on Linux semantics; likely make the fixture host-neutral). |
| CI9b-4 | test_b100_load_dialog.py::test_tc_b100_63_typed_unsupported_file_is_explained[trailing dot] | Linux only: 'name.' is a distinct name on posix (Windows strips the trailing dot), so the path is "not found". | Batch-end fix round: mark the arm Windows-only (skipif not win32) with reason. |

## From Inc 10 CI run 41269650910 (main 21e5488) — 12 failed / 4625 passed / 201 skipped
- The known 6 + CI9b-1..4 (same as 9b run; CI9b-1/2 fixed on b100-inc11 at 24f779f).
| CI10-1 | test_b97_flow_execution.py::test_tc_b97_23_waiting_card_past_the_viewport_is_brought_into_view[deep-size0] | `assert (False)`; passes locally on main (Windows, 32 s). Suspected Linux-runner timing flake (run took 3h12). | Re-check on the Inc 11 push CI; if it repeats, batch-end fix round. |
| CI10-2 | test_b97_flow_execution.py::test_tc_b97_64_burst_on_two_waiting_lanes_confirms_one | `AssertionError: ([(0, 2), (1, 2)], None, False)`; passes locally. Same suspicion. | Same. |

## From Inc 11 CI run 41284211218 (main 4e7ceb4) — 12 failed / 4779 passed / 210 skipped / 3 xfailed
- Known 6 (b78_32 still red here: 12a D-1 landed later) + CI9b-3/4. CI10-1/2 did NOT repeat → treated as Linux timing flakes, closed unless they return.
- New, all Inc 11 tests, all Linux-only (pass on Windows); common thread = posix path semantics (case-sensitive names, no `..` collapse before resolve):
| CI11-1 | test_b100_project_homes.py::test_e4_llr_171_1m_rebind_only_to_a_plan_entry[dot-dot] | Expected `workarea/P/../elsewhere/x.json` kept unresolved; got rebound to `workarea/Q/patches/x.json`. On posix `P/..` is not collapsed the same way before the plan-entry match. | Batch-end fix round. |
| CI11-2 | test_b100_save_dialog.py::test_tc_b100_47_target_line_merge_and_existing_folder_kinds | Typed `nt` gets the `ef` folder's line: `_where_line_for_text` case/prefix match differs on posix. | Batch-end fix round. |
| CI11-3 | test_b100_save_dialog.py::test_tc_b100_65_document_free_name_walk_folds_case | Free-name walk does not fold case on posix (`patches/changes.json` instead of `changes_1.json`). Design question: fold case on every host, or arm Windows-only. | Batch-end fix round (decide host-neutral fold). |
| CI11-4 | test_b100_save_image.py::test_tc_b100_59_refused_plan_writes_nothing | `plans[-1]` IndexError: no plan captured on posix (planner path not reached). | Batch-end fix round. |

## From 12a snapshot CI run 41290452101 (main 4dfb5a1) — 13 failed / 4906 passed / 210 skipped / 3 xfailed; snapshot job SUCCESS
- at_b78_32 left the list (12a D-1 confirmed). Known 5 remain: tc1802, b78_03, 056e_a2b, tc707_copy, tc707_numbering. CI9b-3/4 and CI11-1..4 repeat.
| CI12a-1 | test_b100_reuse.py::test_at_b100_01_repeated_loads_reuse_and_name_existing_variant[size0], [size1] | `did not settle: the first load's added-variant status` (tests/test_b100_reuse.py:104 poll helper). Run took 4h21 (slow runner); the file load is on a worker since 12a and the poll bound is wall-clock. Passes locally. | Batch-end fix round: re-pin the wait to the 12b `settle_workers` helper / raise the bound; re-check on the 12b close CI first. |
