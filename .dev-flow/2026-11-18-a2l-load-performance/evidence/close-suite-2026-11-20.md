# Batch-end full suite and triage — 2026-11-20

Tree: merge tip `e54017f7` (Front A on `b103-fix-round` 6eccf0cb, with FA-D11c, FA-RT/RTFIX, FA-PRIV), before FA-FIX1. Environment per HT-02 (isolated HOME, XDG, TMPDIR; `-p no:cacheprovider`). Transcripts stay on the lab hosts; this file holds counts and node ids only.

## Shards (DF-08, HT-12)
| Shard | Host | Command | Wall | Result |
|---|---|---|---|---|
| Non-timing | 16-core Linux host | `pytest -n 14 -m "not serial_timing"` | 1 h 30 min | 12 failed, 9440 passed, 271 skipped, 12 xfailed |
| Timing | 8-core Linux laptop, quiet (1-min load 1.1–2.9 incl. the test process) | `pytest -n 0 -m serial_timing` | 1 h 30 min | 7 failed, 221 passed, 23 skipped |

Collected: 9986 nodes (9735 + 251).

## Comparison with main's last full CI
`main` 3afebf90, CI run 44552093077 (GitHub runner): 49 failed. Union of the two shards: 19 nodes. 5 in both, 14 only on the tip, 44 only on `main` (fixed by the batch or not reproduced on the lab hosts).

## Serial triage (one `-n 0` run per tree: `main` 3afebf90, `b103-fix-round` 6eccf0cb, tip e54017f7)
| Class | Nodes | Evidence |
|---|---|---|
| Defect, fixed by FA-FIX1 | `tests/test_window_usage_help.py::test_tc707_numbering_generated_sequential` | PASS main, FAIL 6eccf0cb and tip; G7 added a Patch help step (49 → 50) without the pin update |
| Inherited from `main` | `tests/test_b99_export.py::test_tc_b99_29_hostile_set_writes_nothing_outside`; `tests/test_b101_inplace_views.py::test_qc_tm_10b_1_a2l_refresh_cost_on_the_largest_a2l` (220,040 tags 1.80 s); `tests/test_b103_a2l_reader_perf.py::test_r_a2l_read_52_case06_time` (9.03 s vs 5.898 s); `tests/test_b100_focus.py::test_tc_b100_12_map_load_keeps_the_region_row_and_down_walks_it`; `tests/test_b100_project_check.py::test_at_b100_07_load_names_the_changed_file_and_the_hostile_record[size1]`; `tests/test_b103_clipboard_matrix.py::test_r_tui_044_1_walk_single_line_round_trip[patch]`; `tests/test_b99_staging.py::test_tc_b99_ux_c10_save_project_filename_renders_literally` | FAIL on all three trees, or in main's CI too |
| Temporary-path length | `tests/test_b99_export.py::test_tc_b99_41_collision_reason_is_scrubbed_clipped_and_indexed`, `…::test_tc_b99_41_part_way_failure_status_names_the_first_file` | FAIL with longer state paths; PASS on all three trees with the same state path (the test counts the absolute temporary path against a 260-character limit) |
| Load-sensitive (PASS serially on all three trees) | `tests/test_b100_load_dialog.py::test_tc_b100_40_project_choice_opens_the_load_result_panel`; `tests/test_b100_save_dialog.py::test_at_b100_21_painted_plan_is_the_saved_tree[merge]`; `tests/test_b103_inc9b_w.py::test_r_pe_bench_95_2_summaries_of_a_page_turn_are_not_busy_jobs`; `tests/test_b103_inc9b_s.py::test_r_pe_bench_98_2_the_stepped_stage_writes_the_base_bytes_and_yields_between_write_and_refresh`; `tests/test_b100_project_check.py::test_r_tst_111_112_arm_values_equal_the_product_stamps[scene]`; `tests/test_b100_save_guards.py::test_tc_b100_05_merge_keeps_a_too_large_document_under_one_second`; `tests/test_b103_inc9b_at.py::test_r_pe_bench_97_3_the_gaps_between_changed_titles_stay_within_the_bounds`; `tests/test_b103_inc9b_s.py::test_r_pe_bench_101_3_a_record_stage_refused_at_its_write_with_the_a2l_unloaded_returns_to_the_idle_look` | serial PASS ×3 trees |
| Load / order sensitive (N = 10, isolated) | `tests/test_b103_inc9_w_jobs.py::test_r_pe_bench_82_1_a_key_is_handled_within_one_second_while_a_record_encode_runs` | 6eccf0cb 10/10 PASS; tip 9/10 PASS (the failure: slowest press 1.178 s at load 2.83, reported "load-sensitive" by the test); in the suite it failed after many case_06 loads in one process, like `bench_20_1` (P-263) |

Nothing is called flaky (HT-07): the load-sensitive nodes stay visible.

## After FA-FIX1
`tests/test_window_usage_help.py` + `tests/test_id_registry.py` on the fixed tip: 50 passed. Six laws on the tip before FA-FIX1: 116 passed, 2 skipped, 0 failed.
