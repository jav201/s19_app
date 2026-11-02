# Inc 2 — E1 slice: every file and function to change, counted and mapped

Base `b3bf42e`; Inc 2 is rebased onto main (Inc 1 merged) before E4. 0 files under `s19_app/`. E3 round 1 changes are marked with the finding id in brackets. Counts by AST census on the base tree (the prototype detector of R-TST-005/006, run from the session scratchpad; it reads `tests/` and writes nothing in the worktree).

## 1. Summary

| Group | Files | Functions / entries | Rows |
|---|---:|---:|---|
| Config: marker registration | 1 (`pyproject.toml`) | 1 marker line | R-TST-001 |
| CI workflow | 1 (`.github/workflows/tui-ci.yml`) | job `tui-ci`: 1 checkout step changed, the install step gains `python -m pip install "pytest-xdist==3.8.0"` [R2], 2 steps split into 4 (lane 1 parallel: `-n auto --dist loadfile`), `timeout-minutes` on the job (240) and on each lane (lane 1: 180 push / 120 PR; lane 2: 45 / 30) [E3A-4, R2, N-3] | R-TST-010 … 018 |
| Test infrastructure, timing (`tests/support/timing.py`) | 1 | 3 new functions (`wait_until`, `report_margin`, `qc_tm_summary_lines`) + 1 new drain function (`qc_tm_drain`) + 3 constants; `timing_bound` unchanged | R-TST-020 … 022, 024, 040, 042 … 046 |
| Test infrastructure, census (`tests/support/suite_census.py`, new, not a `test_*.py`) | 1 | 4 new functions (`timing_arms`, `unreported_upper_bounds`, `newest_line_waits`, `shared_wait_bodies`) + 2 constants (`SAMPLED_TIMING_ARMS`, `NEWEST_LINE_BASELINE`) | R-TST-002 … 006, 020, 021, 040, 041, 051 |
| Session hooks (`tests/conftest.py`) | 1 | 2 new hooks (`pytest_runtest_makereport` hookwrapper that drains into `item.user_properties` **before** its `yield` for the call phase [E3A-1]; `pytest_terminal_summary` reading call-phase reports only); `canonical_report_bytes` puts the package version in place of `<TOOL-VERSION>` + 1 constant `TOOL_VERSION_TOKEN` [US-TST-5] | R-TST-042 … 046, 081, 082 |
| Shared wait helpers (bodies only) | 3 (`tests/b97_probes.py`, `tests/support/b100_load_dialog.py`, `tests/support/b100_projects.py`) | 7 functions, 9 waits: `settled`; `b100_load_dialog.wait_for`; `b100_projects.wait_for`, `read_load_result_panel`, `dismiss_load_result_panel` (2), `save_case01_project` (2), `append_variant`; + `load_project`'s clock (8 functions in all) | R-TST-020 … 025 |
| Guard host (new test file, orchestrator ruling O-1) | 1 (`tests/test_suite_hygiene.py`, new) | about 28 new test functions named `test_r_tst_<id>_…` | every row with a pytest case (`02-test-cases.md`) |
| Version-agnostic report goldens [US-TST-5] | 7 golden files + 2 test files (`tests/test_report_service.py`, `tests/test_report_addendum_bound.py`) | 7 goldens: the version → `<TOOL-VERSION>`; `test_at288_report_hex_sections_identical_after_move` compares through `canonical_report_bytes`; `_golden_documents` passes the golden through `canonical_report_bytes` | R-TST-080 … 082 |
| Timing arms: decorator + `report_margin` wrap | 12 test files | 32 test functions (31 static + 1 sampled), 37 upper timing bounds, 1 module helper (`_assert_sec6_5_bounded`) | R-TST-002, 040 |
| Test conventions | 1 (`docs/engineering-rules.md`) | 1 new section with 6 rules + the gate commands | R-TST-007, 030, 047, 048, 052, 060 |
| Backlog flips (at E5) | `.dev-flow/BACKLOG-CODE.md` | rows G-015, SR12b-7 (shared part), SR12b-7b (rule part), R2-CI, dwell flake; CI deferral when R-TST-070 and R-TST-072 hold; a new row for the already-committed evidence files that carry home paths (E3S-2) | — |

**Totals:** 32 files (0 product, 2 config, 1 doc, 29 under `tests/`: 1 new non-test module, 1 new test file, 7 golden files); 8 changed shared-helper functions, 7 new infrastructure functions, 2 new hooks, 1 changed canonicalizer, about 28 new guard tests, 32 marked arms, 37 wrapped bounds. Graph: 29 nodes (`codewire/graph-inc2.md`).

**Registry and coordination (E3A-7).** TC-607 (`EXPECTED_SCANNED_TEST_FILES`) counts `tests/**/*.py`, so Inc 2 adds **2** scanned files: `tests/support/suite_census.py` and `tests/test_suite_hygiene.py` (239 on main after Inc 1 → 241, re-measured once at Inc 2's integration). On `b3bf42e` alone TC-607 is already RED (238 scanned vs 237 declared, since `tests/test_synth_release_case.py` arrived in `7717394`); that failure is not Inc 2's [R2, E3A-7 note]. The text of the two new modules holds no `AT-…` or `TC-…` token: node ids are written in underscore form (`test_at_b100_18_…`), so Inc 1's registry rules do not see them. At integration, on top of Inc 1, run `tests/test_id_registry.py` and `tests/test_batch91_registry_hygiene.py`. `tests/test_report_addendum_bound.py` is one of Inc 1's files: Inc 2 touches it only after the rebase onto main (Inc 1 merged), one line in `_golden_documents`, and only with the orchestrator's go (listed in `E3-rulings.md`).

## 2. Shared wait helpers (SR12b-7, R-TST-020 … 025)

| Function | File:line at `b3bf42e` | Loops | Callers (files / calls) | Change | Rows |
|---|---|---:|---|---|---|
| `settled` | `tests/b97_probes.py:314` | 1 | 3 files (`b97_fixtures.py`, `test_b97_key_bar.py`, `test_b99_a2l_encode.py`) / 45 calls; `b97_fixtures` is itself used widely | body → `wait_until(..., pause_first=True)`, text W3 | 020–024 |
| `wait_for` | `tests/support/b100_load_dialog.py:72` | 1 | via `ld.wait_for`, `wait_for_dialog`, `wait_for_dialog_closed` | body → `wait_until`, text W2 | 020–024 |
| `wait_for` | `tests/support/b100_projects.py:598` | 1 | `projects.wait_for` and its users `load_image`, `load_project`, `save_project` (9 files call them through `projects.` / `docs.`); 114 direct `wait_for` calls with `ld.wait_for`, 243 calls counting the wrappers | body → `wait_until`, text W1 | 020–024 |
| `read_load_result_panel` | `tests/support/b100_projects.py:212` | 1 | 7 files / 9 calls | wait → `wait_until`, text W4 | 020, 021, 024 |
| `dismiss_load_result_panel` | `tests/support/b100_projects.py:230` | 2 | 15 files / 22 calls | both waits → `wait_until`, texts W5, W6 | 020, 021, 024 |
| `save_case01_project` | `tests/support/b100_projects.py:273` (loops `:304`, `:317`) | 2 | 6 files / 54 calls | both waits → `wait_until`, texts W7, W8 | 020, 021, 024 |
| `append_variant` | `tests/support/b100_projects.py:369` (loop `:394`) | 1 | 5 files / 4 calls | wait → `wait_until`, text W9 | 020, 021, 024 |
| `load_project` | `tests/support/b100_projects.py:615` | 0 | 16 files / 37 calls | clock stops at `_install_prepared_project`'s return | 025 |

Not in the slice (stay on the SR12b-7 backlog row): the 23 module-private wait helpers of the census and its other 82 count-bounded loops; `b100_load_dialog.highlight_row` (a key-press loop bounded by the row count, not a wait); `b100_save_dialog.wait_for` (already wall-clock); `_wait_yielding` (already conforms).

## 3. Timing arms (G-015 + QC-TM, R-TST-002, 040)

31 static arms (the R-TST-005 census) + 1 sampled. "13" marks batch-100's parallel-only failures. Bounds = upper timing bounds to wrap in `report_margin`.

| # | Node | Bounds (line at `b3bf42e`) | 13 |
|---:|---|---|---|
| 1 | `tests/test_a2l_alignment_sizing.py::test_at120_oversized_alignment_layout_clamps_to_none` | `:251` | |
| 2 | `tests/test_a2l_alignment_sizing.py::test_tc149_dos_clamp_includes_padding` | `:400` | |
| 3 | `tests/test_a2l_inline_axis_length.py::test_tc138_dos_clamp_pure_arithmetic` | `:352` | |
| 4 | `tests/test_a2l_inline_axis_length.py::test_at111_oversized_axis_clamps_to_none` | `:567` | |
| 5 | `tests/test_a2l_multiline_headers.py::test_at101_megabyte_unterminated_block_is_linear` (`slow`) | `:321` | |
| 6 | `tests/test_b100_active_variant.py::test_tc_b100_20_writers_on_a_31_folder_manifest_finish_under_one_second` (×5 params) | `:738` | ×4 |
| 7 | `tests/test_b100_document.py::test_tc_b100_28_document_finding_is_kept_first_beside_a_full_batch` | `:366` | |
| 8 | `tests/test_b100_document.py::test_tc_b100_30_classifier_outcome` (params) | `:964` | |
| 9 | `tests/test_b100_document.py::test_tc_b100_30_hostile_document_is_one_not_readable_under_one_second` (×3) | `:1206` | ×3 |
| 10 | `tests/test_b100_project_check.py::test_tc_b100_24_one_entry_over_the_cap_is_one_issue_fast` (×5) | `:363` | |
| 11 | `tests/test_b100_project_check.py::test_tc_b100_24_assignments_75_by_1000_is_one_issue_fast` | `:383` | |
| 12 | `tests/test_b100_project_check.py::test_tc_b100_61_every_array_at_the_cap_all_bad_opens_under_one_second` | `:841`, `:842` | ✓ |
| 13 | `tests/test_b100_project_check.py::test_tc_b100_61_sec6_5_each_name_is_checked_once_per_read` | `:1023`, `:1034`, `:1050`, `:1066` | |
| 14 | `tests/test_b100_project_check.py::test_tc_b100_61_sec6_5_deep_entries_need_one_check_each_parent` | via `_assert_sec6_5_bounded` | ✓ |
| 15 | `tests/test_b100_project_check.py::test_tc_b100_61_sec6_5_entries_under_an_existing_folder_are_all_checked` | via `_assert_sec6_5_bounded` | ✓ |
| 16 | `tests/test_b100_project_check.py::test_tc_b100_61_sec6_5_distinct_folders_stop_at_the_folder_ceiling` | via `_assert_sec6_5_bounded` | ✓ |
| 17 | `tests/test_b100_project_check.py::test_tc_b100_61_sec6_5_junction_loop_costs_one_failure` | via `_assert_sec6_5_bounded` | |
| — | helper `tests/test_b100_project_check.py::_assert_sec6_5_bounded` | `:977`, `:978`, `:979`, `:980` | |
| 18 | `tests/test_b100_project_check.py::test_tc_b100_61_r2_2_legitimate_manifest_inside_every_cap_is_checked_whole` | `:1183` | |
| 19 | `tests/test_b100_project_check.py::test_tc_b100_61_sec7_r2_2_one_serialize_checks_each_name_once` | `:1268` | |
| 20 | `tests/test_b100_project_check.py::test_tc_b100_61_files_at_the_cap_all_missing_are_bounded` | `:1350`, `:1351` | |
| 21 | `tests/test_b100_project_homes.py::test_tc_b100_31_junction_cycle_ends` | `:363` | |
| 22 | `tests/test_b100_project_homes.py::test_tc_b100_31_entry_ceiling` (×2) | `:766` | |
| 23 | `tests/test_b100_save_dialog.py::test_tc_b100_65_recompute_is_a_150ms_debounce` | `:2333`, `:2335` (upper half) | |
| 24 | `tests/test_b100_save_dialog.py::test_tc_b100_65_session_decided_once_per_open_case06` | `:3459` | |
| 25 | `tests/test_b100_save_dialog.py::test_tc_b100_65_recompute_at_most_three_of_twenty_keystrokes` | `:3494` | |
| 26 | `tests/test_b100_save_dialog.py::test_tc_b100_65_emitting_4mib_image_recomputes_fast` | `:3535` | |
| 27 | `tests/test_b100_save_guards.py::test_tc_b100_05_merge_keeps_a_too_large_document_under_one_second` | `:2527` | ✓ |
| 28 | `tests/test_compare_engine.py::test_large_image_perf` (`slow`) | `:279` | |
| 29 | `tests/test_tui_app.py::test_build_mac_view_cache_scales_under_load` | `:916` | |
| 30 | `tests/test_tui_app.py::test_end_to_end_load_pipeline_under_budget` (`slow`) | `:1244` | |
| 31 | `tests/test_tui_app.py::test_stress_load_s19_then_a2l_then_mac` (`slow`) | `:1333` | |
| 32 | `tests/test_b100_busy.py::test_at_b100_17_worker_load_of_an_8_mib_s19_by_keys` — **sampled**, marker only, no bound to wrap | — | ✓ |

Bound count: 5 + 1 + 3 + 16 + 2 + 5 + 1 + 1 + 3 = **37**. Not bounds (a coarse taint reaches them; the position- and key-aware taint of the *Upper timing bound* definition must not) [E3A-3]: `tests/test_b100_project_check.py:843` `rows <= LOAD_PANEL_ROW_BOUND` (third item of `timing, painted, rows = …`), `:981` `scene["rows"] <= LOAD_PANEL_ROW_BOUND` (in `_assert_sec6_5_bounded`), `tests/test_b100_save_dialog.py:2331` and `:3493` (counts; `count, final = _run(...)` unpacks a count at position 0), the lower halves of `:2335`.

Prints an interval but asserts none (not a timing arm): `tests/test_b100_project_homes.py::test_tc_b100_31_copy_ceiling_2000_files`.

## 4. CI workflow (R-TST-010 … 014)

| Entry | `b3bf42e` | Change |
|---|---|---|
| `tui-ci` › `Check out repository` (`:27-28`) | `actions/checkout@v4` | `with: fetch-depth: 0` |
| `Install dependencies` (`:35-41`) | `pip install pytest` | also `python -m pip install "pytest-xdist==3.8.0"` [R2] |
| `Run lean test suite (pull requests)` (`:43-45`) | `pytest -q -m "not slow"` | lane 1 (`timeout-minutes: 120`) [R2]: `pytest -v -rs -n auto --dist loadfile -m "not slow and not serial_timing"`; lane 2 (new step, `if: github.event_name == 'pull_request' && !cancelled()`): `pytest -q -rs -m "serial_timing and not slow"` |
| `Run full test suite (pushes)` (`:47-49`) | `pytest -q` | lane 1 (`timeout-minutes: 180`) [E3A-4, R2]: `pytest -v -rs -n auto --dist loadfile -m "not serial_timing"`; lane 2 (new step, `if: github.event_name == 'push' && !cancelled()`): `pytest -q -rs -m serial_timing` |
| job `tui-ci` | no `timeout-minutes` (default 360) | `timeout-minutes: 240` [E3A-4, R2]; lane-2 steps `timeout-minutes` 45 (push) / 30 (PR) [N-3] |
| `snapshot` job | unchanged | — (E3S-3's `persist-credentials: false` is an E4 addendum) |

## 5. Mapping of rows to slice entries

| Rows | Slice entries |
|---|---|
| R-TST-001 | `pyproject.toml` markers |
| R-TST-002 … 006 | `suite_census.timing_arms`, `SAMPLED_TIMING_ARMS`; the 32 decorators; guard tests |
| R-TST-007, 030, 047, 048, 052, 060 | `docs/engineering-rules.md` new section; conventions guard test |
| R-TST-008, 009 | the release gate run (evidence) over the whole slice |
| R-TST-010 … 014 | `tui-ci.yml`; workflow guard tests (partial); CI run log (full) |
| R-TST-020 … 024 | `timing.wait_until`; the 7 shared functions; `suite_census.shared_wait_bodies`; guard tests |
| R-TST-025 | `b100_projects.load_project` |
| R-TST-031, 032 | unchanged arms (`d460190`); static guard + parallel-lane runs |
| R-TST-040, 041 | `timing.report_margin`; `suite_census.unreported_upper_bounds`; the 37 wraps |
| R-TST-042 … 046 | `timing.qc_tm_drain`, `timing.qc_tm_summary_lines`; the 2 hooks in `tests/conftest.py` |
| R-TST-050 | `b100_projects.StatusLog` (unchanged; verified) |
| R-TST-051 | `suite_census.newest_line_waits`, `NEWEST_LINE_BASELINE` |
| R-TST-015 … 018 | `tui-ci.yml` timeouts, lane-2 condition, the xdist install; workflow guard test |
| R-TST-090, 091 | CI records of Inc 2's PR run (E5) and the first post-merge push run (batch end) |
| R-TST-070 … 072 | `evidence/ci/41372953464.txt` (batch folder): `tui-ci` FAILED census + `snapshot` job result |
| R-TST-080 … 082 | §7: the 7 goldens, `canonical_report_bytes`, the 2 test files; golden guard test |

## 6. Nodes touched

Coordination list for the session that keys test-case records to node ids. **No existing test function or file is renamed, moved or deleted.** Inc 1's files — except the one line of `tests/test_report_addendum_bound.py` in §7, after the rebase and with the orchestrator's go — (`tests/test_id_registry.py`, `tests/test_batch91_registry_hygiene.py`, `tests/test_report_addendum_bound.py`, `AT-TC-REGISTRY.jsonl`) are not touched.

**Existing nodes whose decorator or body changes (names kept):** the 32 nodes of §3 (a `@pytest.mark.serial_timing` decorator on each; a `report_margin(...)` wrap on the bound side of each of the 37 bounds; nothing else in their bodies), and the module helper `tests/test_b100_project_check.py::_assert_sec6_5_bounded`.

**Existing test files touched:** `tests/test_a2l_alignment_sizing.py`, `tests/test_a2l_inline_axis_length.py`, `tests/test_a2l_multiline_headers.py`, `tests/test_b100_active_variant.py`, `tests/test_b100_busy.py`, `tests/test_b100_document.py`, `tests/test_b100_project_check.py`, `tests/test_b100_project_homes.py`, `tests/test_b100_save_dialog.py`, `tests/test_b100_save_guards.py`, `tests/test_compare_engine.py`, `tests/test_tui_app.py` (12, decorator + wraps), `tests/test_suite_hygiene.py` (new file).

**Golden-version nodes (body of one helper or one comparison; names kept) [US-TST-5]:** `tests/test_report_service.py::test_at288_report_hex_sections_identical_after_move` (its comparison and its capture branch), `tests/test_report_addendum_bound.py::_golden_documents` (helper of `test_at196_below_bound_report_is_byte_identical_to_the_inc1_golden`). Unchanged nodes whose golden changes: `tests/test_before_after_report.py::test_at_054b_no_filter_bkey_report_pair_byte_identical_to_golden`, `tests/test_tui_report_seam.py::test_at_055b_no_filter_generate_report_byte_identical_to_golden`, `tests/test_tui_report_filter_surface.py::test_at_056c_fresh_default_blank_dropdown_full_report_golden`, `tests/test_report_producer_bound.py::test_at247_under_cap_report_is_byte_identical_to_the_shipped_output`, `tests/test_report_document_bound.py::test_at256_pin_under_cap_report_is_byte_identical_to_the_inc0_golden`, `tests/test_report_addendum_bound.py::test_at196_below_bound_report_is_byte_identical_to_the_inc1_golden`. `tests/test_report_symbol_escape.py::test_at160_recaptured_golden_carries_the_escaped_forms` reads lines 14, 15 and 51 of the at055b golden; the token keeps the line count, so it is unaffected.

**Support and session files touched (no test nodes):** `tests/conftest.py`, `tests/b97_probes.py`, `tests/support/timing.py`, `tests/support/b100_load_dialog.py`, `tests/support/b100_projects.py`; new `tests/support/suite_census.py`.

**Nodes whose behaviour changes through a shared helper (no edit in their file):** every caller of the 7 shared waits and of `load_project`: the waits are now bounded by 60 s of wall time and poll every 0.05 s. Files (call sites, unchanged): 3 files calling `settled` (`tests/b97_fixtures.py` among them, itself used widely), 9 files calling `b100_projects` waits or timing helpers, the `b100_load_dialog` wait callers, 15 files calling `dismiss_load_result_panel`, 7 calling `read_load_result_panel`, 6 calling `save_case01_project`, 5 calling `append_variant`. Their node ids and outcomes are expected unchanged.

**New nodes (all in `tests/test_suite_hygiene.py`, a new file):** `test_r_tst_001_serial_timing_marker_is_registered`, `test_r_tst_002_every_timing_arm_carries_serial_timing`, `test_r_tst_003_an_unmarked_timing_arm_is_named`, `test_r_tst_004_a_marked_non_arm_is_named`, `test_r_tst_005_detector_finds_each_timing_arm_form[form1..form4]`, `test_r_tst_006_detector_ignores_intervals_no_assert_reads`, `test_r_tst_007_conventions_hold_each_test_rule[R-TST-007|030|047|048|052|060]`, `test_r_tst_010_pull_request_runs_two_lanes`, `test_r_tst_011_push_runs_two_lanes`, `test_r_tst_012_serial_lane_runs_after_a_red_lane`, `test_r_tst_013_014_ci_checks_out_full_history`, `test_r_tst_020_shared_wait_is_bounded_by_the_wall_clock`, `test_r_tst_020_021_shared_helpers_delegate_to_the_one_wait`, `test_r_tst_021_shared_wait_yields_between_checks`, `test_r_tst_022_settled_pauses_before_its_first_check`, `test_r_tst_023_shared_wait_signatures_are_kept`, `test_r_tst_024_shared_wait_failure_texts[W1..W9]`, `test_r_tst_025_load_project_clock_stops_at_the_install_callback`, `test_r_tst_031_032_post_press_and_dwell_arms_keep_their_forms`, `test_r_tst_040_report_margin_returns_the_bound`, `test_r_tst_040_041_every_upper_timing_bound_is_reported`, `test_r_tst_042_margin_report_is_a_test_property`, `test_r_tst_043_045_qc_tm_section_rows_and_count`, `test_r_tst_044_low_margin_prefix`, `test_r_tst_046_over_bound_arm_still_reports`, `test_r_tst_050_status_log_keeps_every_painted_line`, `test_r_tst_051_newest_line_waits_do_not_grow`, `test_r_tst_015_016_017_ci_time_limits`, `test_r_tst_018_ci_installs_pinned_xdist`, `test_r_tst_080_report_goldens_hold_no_tool_version`, `test_r_tst_081_golden_takes_the_package_version`, `test_r_tst_082_wrong_version_still_differs` [E3 round 1]. The final names are fixed at E4; the `test_r_tst_<id>` prefix is binding (D-12).

## 7. Version-agnostic report goldens (US-TST-5, R-TST-080 … 082)

| Entry | `b3bf42e` / main hotfix | Change |
|---|---|---|
| `tests/conftest.py::canonical_report_bytes` | CRLF undo, run-root token, separators | also replaces `TOOL_VERSION_TOKEN` (`b"<TOOL-VERSION>"`) with `s19_app.version.__version__` encoded UTF-8 (read at call time, so a patched version is seen). Produced reports hold no token, so they pass through unchanged |
| the 7 report goldens with a version (Definitions) | `Tool version: 0.1.0`; the main hotfix re-pins `1.0.0rc1` | `Tool version: <TOOL-VERSION>` (HTML: `<li>Tool version: <TOOL-VERSION></li>`); no other byte changes |
| `tests/test_report_service.py::test_at288_report_hex_sections_identical_after_move` | `assert emitted == pinned` (raw bytes); capture branch writes `emitted` | compares `emitted == canonical_report_bytes(pinned)`; the capture branch writes `emitted` with the version replaced by the token |
| `tests/test_report_addendum_bound.py::_golden_documents` (Inc 1's file) | decodes the raw golden | decodes `canonical_report_bytes(_GOLDEN.read_bytes())` (one line) |
| the 5 other golden tests (§6) | compare through `canonical_report_bytes` | unchanged |
| `tests/test_suite_hygiene.py` | — | `test_r_tst_080_…`, `test_r_tst_081_…`, `test_r_tst_082_…` |
