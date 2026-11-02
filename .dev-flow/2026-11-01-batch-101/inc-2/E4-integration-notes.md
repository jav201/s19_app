# Inc 2 — E4 integration notes (batch-101, test hygiene)

Integration of the E4 implementation (`E4-impl-notes.md`) and the independent tests
(`E4-tester-notes.md`, `tests/test_suite_hygiene.py`) against the approved design
(`01-requirements.md`, `02-test-cases.md`, `codewire/graph-inc2.md`, `E3-rulings.md`).
Branch `b101-inc2`, rebased onto main `e266395` (the repo-wide redaction merge) before any
run; the rebase applied without conflict. **0 files under `s19_app/` change.**

## 1. Verdict

E4 integration is done. The hygiene suite is 54/54 on Windows and green in the LAN gate
run. The Inc 1 registry guards are 25/25 with TC-607 at the measured 241. The LAN Linux
two-lane run had 0 timing-arm failures and 69 min 25 s of wall time in total. Lane 1's 8
failures are the 5 known pre-existing ones plus 3 that are not caused by Inc 2: two come
from this run's environment and fail identically on base, and one is a `-n 8` flake that
reproduced on neither tree (§5). Head does not slow down any bounded interval on Linux or
on Windows (§4, §6), so the over-bound arms are environmental and no bound was raised.
Open items for E5 are in §8.

## 2. Failures met and fixed

| # | Failure | Who disagreed with the approved design | Cause | Fix |
|---|---|---|---|---|
| F-1 | `test_r_tst_001_serial_timing_marker_is_registered`: `pytest --markers` printed `@pytest.mark.serial_timing: a wall-clock timing arm; …` | the **implementation** | R-TST-001 gives the description as `serial_timing: a wall-clock timing arm; run apart and serially (-m serial_timing)`. The graph example (`graph-inc2.md:336`) and case R-TST-001/1 both pin the printed line `@pytest.mark.serial_timing: serial_timing: a wall-clock timing arm; …`. The implementation registered the description without its leading `serial_timing: ` (following the `slow:`/`snapshot:` style) | `pyproject.toml:114` now registers `"serial_timing: serial_timing: a wall-clock timing arm; run apart and serially (-m serial_timing)"`, the design's literal text (see seam note S-1) |
| F-2 | `test_r_tst_031_032_post_press_and_dwell_arms_keep_their_forms`: `assert "held_save_scene" in quit_body` | the **test** | Case R-TST-031/1 pins "installs `Hold` on `place_into_workarea`". The arm (unchanged since `d460190`) does that inline: `Hold(monkeypatch, app_module, "place_into_workarea")`. It never used the `held_save_scene` helper. The tester assumed the helper name (`E4-tester-notes.md` row 031). The next line checked the `Hold` text over the **whole file**, where `held_save_scene` already satisfied it | `tests/test_suite_hygiene.py:1123`: the `Hold(…, "place_into_workarea"` check now runs on the **function body**, and the helper-name check is gone. This is stricter than before. Negative control: removing the arm's `Hold` line makes the new check false, while the old file-wide check stayed true |
| F-3 | same test: `assert 'Spy(monkeypatch, S19TuiApp, "step_busy")' in parse_body` | the **test** | Case R-TST-031/2 pins "wraps `app.step_busy`". The arm reads `applied = app.step_busy` and reassigns `app.step_busy = step_busy` on the instance. The `Spy` form was the tester's assumption | `tests/test_suite_hygiene.py:1129`: asserts the body both reads (`= app.step_busy`) and reassigns (`app.step_busy = `) the hook. Negative control: removing the reassignment makes it false |

No assertion was weakened and no requirement changed. F-2 and F-3 replace a guessed
helper name with the form the case row pins, and F-2's scope narrows from the file to the
function.

### Seam rulings

- **S-1 (F-1, design literal kept).** R-TST-001, the graph example and case 001/1 all pin
  the doubled prefix, so the implementation follows them. The result is a redundant
  description beside `slow:`/`snapshot:`. If the operator prefers the conventional
  `serial_timing: a wall-clock …` form, R-TST-001, `graph-inc2.md:336`, case 001/1,
  `MARKER_LINE` (`tests/test_suite_hygiene.py:53`) and `pyproject.toml:114` change together
  in one design edit. Not done here: E4 does not change requirements.
- **S-2 (redaction rule on Inc 2's own files).** After the rebase,
  `codewire/graph-inc2.md:3` still named the local account folder in the Code-Wire
  notation path. It now reads `<HOME>/Github/code-wire/...`, matching main's redaction.
  No other Inc 2 file held a home path, account name, host name or LAN address. This
  includes every evidence file written by this step, which all use
  `<HOME>`/`<USER>`/`<OUT>`.

## 3. TC-607

`tests/test_id_registry.py:171` changed from `EXPECTED_SCANNED_TEST_FILES = 239` to `241`. It
is the only edit to that file: one comment line plus a docstring paragraph in the file's
own style. MEASURED: before the edit the guard reported `the guard scanned 241 test
modules, not the declared 239`. The 2 added modules are `tests/support/suite_census.py`
and `tests/test_suite_hygiene.py`, as the design said (E3A-7). After the edit,
`tests/test_id_registry.py`, `tests/test_batch91_registry_hygiene.py` and
`tests/test_requirements_canon.py` give **25 passed** (`int-win-registry.txt`).

## 4. Timing arms: base vs head, measured

**Question.** On a loaded Windows host the implementer saw 6 arms over their 1.0 s bound
(1.09–1.24 s). Inc 2 changes no product code. Does head slow down any bounded interval?

**Method (LAN Linux host, otherwise idle, serial, no xdist).** Six serial runs, in the
order base1, head1, base2, head2, basewaits1, basewaits2:
- **base** = `origin/main` `e266395`, given the 59 head `serial_timing` node ids
  explicitly (base has no marker and no `report_margin`, so it gives outcomes and call
  durations only).
- **head** = base + the Inc 2 diff, `-m serial_timing`.
- **basewaits** = head with `tests/b97_probes.py`, `tests/support/b100_load_dialog.py`
  and `tests/support/b100_projects.py` restored to base. This keeps head's QC-TM
  instrumentation, which returns the bound unchanged, but uses base's shared waits and
  base's `load_project` clock. So its QC-TM rows are the base value of every bounded
  interval, measured the same way as head's.

The gate's serial lane (`int-linux-lane2.txt`) is a third head sample.

**Result.**

| Run | Outcome | Wall | Sum of call durations (s) |
|---|---|---:|---:|
| base1 | 1 failed (TC-B100-61 all-bad painted 1.236 s), 56 passed, 2 skipped | 4:58 | 297.3 |
| base2 | 57 passed, 2 skipped | 4:57 | 296.7 |
| basewaits1 | 1 failed (sec6_5 distinct-folders painted 1.113 s), 56 passed, 2 skipped | 5:04 | 300.0 |
| basewaits2 | 2 failed (TC-B100-30 5000-digit-integer load 3.491 s; sec6_5 existing-folder appended 1.007 s), 55 passed, 2 skipped | 5:05 | 301.0 |
| head1 | 58 passed, 2 skipped | 5:05 | 300.4 (+0.7 hygiene node) |
| head2 | 1 failed (sec6_5 deep-entries painted 1.355 s), 57 passed, 2 skipped | 5:06 | 301.3 (+0.7) |
| gate lane 2 (head) | 58 passed, 2 skipped | 5:06 | — |

Verdict: **head is not slower on any bounded interval, so the arms stay as designed and
no bound was raised.**
- Every arm that comes near or over its bound does the same with base's waits:
  `sec6_5 appended` 0.79–1.01 s, `TC-B100-20 save-project` 0.77–0.99 s, and the
  `painted` intervals.
- The `painted` intervals are **bimodal on every tree**: about 0.001 s or 0.60–1.36 s,
  never in between. The base runs failed on that too (base1: 1.236 s).
- Head is **faster** where R-TST-025 applies. The three TC-B100-30 hostile-document loads
  measure 0.57–0.78 s (once 3.49 s) with base's `load_project` clock and 0.08–0.38 s with
  head's, which stops at the install callback.
- Whole-test call time is about 1.3% higher on head than on base (about 4 s of 300 s),
  about 0.1% of it against basewaits. That cost sits outside the bounded intervals: it
  comes from the 0.05 s poll granularity of `wait_until` (R-TST-021's ≤ 21 checks per
  second), paid once per wait.

The implementer's Windows over-bound arms are the same arms on a host loaded by other
sessions. Windows re-run: §6.

Full per-arm table: measured seconds (margin %); bold = margin under 20 %; sorted by the
lowest margin seen. Transcripts: `int-linux-timing-{base1,base2,basewaits1,basewaits2,head1,head2}.txt`
and `int-linux-lane2.txt`.

Columns: `basewaits` = base value of each bounded interval (head instrumentation, base waits and base `load_project`); `head1`/`head2`/`gate-l2` = head. TC-B100-31 junction cycle is a Windows-only arm (skipped on Linux), so Linux reports 72 bounds.

| arm (node :: label) | bound s | basewaits1 | basewaits2 | head1 | head2 | gate-l2 |
|---|---:|---:|---:|---:|---:|---:|
| test_tc_b100_30_hostile_document_is_one_not_readable_unde... :: TC-B100-30 5000-digit-integer | 1.0 | 0.573 (42.7%) | **3.491 (-249.1%)** | 0.083 (91.7%) | 0.079 (92.1%) | 0.078 (92.2%) |
| test_tc_b100_61_sec6_5_deep_entries_need_one_check_each_p... :: sec6_5 painted | 1.0 | 0.001 (99.9%) | 0.001 (99.9%) | 0.001 (99.9%) | **1.355 (-35.5%)** | 0.001 (99.9%) |
| test_tc_b100_61_sec6_5_distinct_folders_stop_at_the_folde... :: sec6_5 painted | 1.0 | **1.113 (-11.3%)** | 0.602 (39.8%) | 0.001 (99.9%) | 0.001 (99.9%) | 0.001 (99.9%) |
| test_tc_b100_61_sec6_5_entries_under_an_existing_folder_a... :: sec6_5 appended | 1.0 | 0.793 (20.7%) | **1.007 (-0.7%)** | **0.988 (1.2%)** | **0.957 (4.3%)** | 0.766 (23.4%) |
| test_tc_b100_20_writers_on_a_31_folder_manifest_finish_un... :: TC-B100-20 save-project | 1.0 | **0.989 (1.1%)** | 0.770 (23.0%) | 0.789 (21.1%) | **0.802 (19.8%)** | 0.800 (20.0%) |
| test_tc_b100_61_sec6_5_deep_entries_need_one_check_each_p... :: sec6_5 appended | 1.0 | **0.908 (9.2%)** | **0.930 (7.0%)** | 0.739 (26.1%) | - | **0.964 (3.6%)** |
| test_tc_b100_61_files_at_the_cap_all_missing_are_bounded :: TC-B100-61 cap painted | 1.0 | **0.963 (3.7%)** | 0.001 (99.9%) | **0.896 (10.4%)** | 0.001 (99.9%) | 0.001 (99.9%) |
| test_tc_b100_61_every_array_at_the_cap_all_bad_opens_unde... :: TC-B100-61 all-bad painted | 1.0 | 0.001 (99.9%) | 0.001 (99.9%) | 0.001 (99.9%) | **0.902 (9.8%)** | 0.001 (99.9%) |
| test_tc_b100_61_sec6_5_distinct_folders_stop_at_the_folde... :: sec6_5 appended | 1.0 | - | 0.633 (36.7%) | **0.846 (15.4%)** | 0.620 (38.0%) | **0.865 (13.5%)** |
| test_tc_b100_30_hostile_document_is_one_not_readable_unde... :: TC-B100-30 brackets-1MiB | 1.0 | 0.761 (23.9%) | 0.778 (22.2%) | 0.383 (61.7%) | 0.143 (85.7%) | 0.106 (89.4%) |
| test_tc_b100_61_sec6_5_entries_under_an_existing_folder_a... :: sec6_5 painted | 1.0 | 0.746 (25.4%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) |
| test_tc_b100_20_writers_on_a_31_folder_manifest_finish_un... :: TC-B100-20 variant-append | 1.0 | 0.717 (28.3%) | 0.659 (34.1%) | 0.576 (42.4%) | 0.557 (44.3%) | 0.585 (41.5%) |
| test_tc_b100_20_writers_on_a_31_folder_manifest_finish_un... :: TC-B100-20 mac-sync | 1.0 | 0.519 (48.1%) | 0.529 (47.1%) | 0.537 (46.3%) | 0.508 (49.2%) | 0.710 (29.0%) |
| test_tc_b100_65_recompute_is_a_150ms_debounce :: TC-B100-65 final paint | 0.3 | 0.196 (34.6%) | 0.186 (38.0%) | 0.164 (45.3%) | 0.152 (49.4%) | 0.186 (37.8%) |
| test_tc_b100_65_emitting_4mib_image_recomputes_fast :: TC-B100-65 4MiB paint | 0.3 | 0.185 (38.3%) | 0.190 (36.6%) | 0.185 (38.4%) | 0.161 (46.4%) | 0.162 (46.1%) |
| test_tc_b100_05_merge_keeps_a_too_large_document_under_on... :: TC-B100-05 merge | 1.0 | 0.395 (60.5%) | 0.619 (38.1%) | 0.411 (58.9%) | 0.620 (38.0%) | 0.466 (53.4%) |
| test_tc_b100_65_recompute_at_most_three_of_twenty_keystrokes :: TC-B100-65 keystroke paint | 0.3 | 0.166 (44.7%) | 0.163 (45.8%) | 0.163 (45.8%) | 0.183 (39.0%) | 0.161 (46.2%) |
| test_tc_b100_20_writers_on_a_31_folder_manifest_finish_un... :: TC-B100-20 a2l-sync | 1.0 | 0.578 (42.2%) | 0.543 (45.7%) | 0.528 (47.2%) | 0.504 (49.6%) | 0.596 (40.4%) |
| test_tc_b100_30_hostile_document_is_one_not_readable_unde... :: TC-B100-30 20000-entries | 1.0 | 0.586 (41.4%) | 0.577 (42.3%) | 0.090 (91.0%) | 0.088 (91.2%) | 0.094 (90.6%) |
| test_tc_b100_61_sec6_5_distinct_folders_stop_at_the_folde... :: sec6_5 load | 1.0 | 0.305 (69.5%) | 0.533 (46.7%) | 0.330 (67.0%) | 0.284 (71.6%) | 0.311 (68.9%) |
| test_r_tst_020_shared_wait_is_bounded_by_the_wall_clock :: R-TST-020 fast return | 0.4 | - | - | 0.202 (49.4%) | 0.203 (49.4%) | 0.203 (49.3%) |
| test_tc_b100_20_writers_on_a_31_folder_manifest_finish_un... :: TC-B100-20 save-back | 1.0 | 0.434 (56.6%) | 0.421 (57.9%) | 0.441 (55.9%) | 0.440 (56.0%) | 0.437 (56.3%) |
| test_tc_b100_61_sec6_5_deep_entries_need_one_check_each_p... :: sec6_5 load | 1.0 | 0.348 (65.2%) | 0.353 (64.7%) | 0.316 (68.4%) | 0.403 (59.7%) | 0.314 (68.6%) |
| test_tc_b100_65_session_decided_once_per_open_case06 :: TC-B100-65 case06 paint | 2.0 | 0.776 (61.2%) | 0.784 (60.8%) | 0.769 (61.5%) | 0.775 (61.3%) | 0.757 (62.1%) |
| test_r_tst_020_shared_wait_is_bounded_by_the_wall_clock :: R-TST-020 wall-clock bound | 1.5 | - | - | 0.505 (66.3%) | 0.505 (66.3%) | 0.505 (66.3%) |
| test_tc_b100_65_recompute_is_a_150ms_debounce :: TC-B100-65 q delay | 0.5 | 0.159 (68.1%) | 0.163 (67.4%) | 0.165 (66.9%) | 0.164 (67.2%) | 0.154 (69.2%) |
| test_tc_b100_61_files_at_the_cap_all_missing_are_bounded :: TC-B100-61 cap load | 1.0 | 0.249 (75.1%) | 0.197 (80.3%) | 0.216 (78.4%) | 0.183 (81.7%) | 0.214 (78.6%) |
| test_tc_b100_61_sec6_5_each_name_is_checked_once_per_read :: TC-B100-61 checks a | 1.0 | 0.226 (77.4%) | 0.229 (77.1%) | 0.222 (77.8%) | 0.245 (75.5%) | 0.229 (77.1%) |
| test_tc_b100_61_every_array_at_the_cap_all_bad_opens_unde... :: TC-B100-61 all-bad load | 1.0 | 0.213 (78.7%) | 0.199 (80.1%) | 0.198 (80.2%) | 0.242 (75.8%) | 0.199 (80.1%) |
| test_tc_b100_61_sec6_5_entries_under_an_existing_folder_a... :: sec6_5 load | 1.0 | 0.231 (76.9%) | 0.182 (81.8%) | 0.177 (82.3%) | 0.197 (80.3%) | 0.214 (78.6%) |
| test_tc_b100_61_sec6_5_deep_entries_need_one_check_each_p... :: sec6_5 read | 1.0 | 0.215 (78.5%) | 0.220 (78.0%) | 0.218 (78.2%) | 0.216 (78.4%) | 0.221 (77.9%) |
| test_tc_b100_31_entry_ceiling[10001 refused] :: TC-B100-31 10001 refused | 5.0 | 0.909 (81.8%) | 0.696 (86.1%) | 0.867 (82.7%) | 0.696 (86.1%) | 0.913 (81.7%) |
| test_tc_b100_61_sec6_5_distinct_folders_stop_at_the_folde... :: sec6_5 read | 1.0 | 0.132 (86.8%) | 0.126 (87.4%) | 0.130 (87.0%) | 0.130 (87.0%) | 0.178 (82.2%) |
| test_large_image_perf :: TC-006 large image | 2.0 | 0.232 (88.4%) | 0.231 (88.5%) | 0.231 (88.5%) | 0.348 (82.6%) | 0.231 (88.5%) |
| test_tc_b100_61_sec7_r2_2_one_serialize_checks_each_name_... :: TC-B100-61 sec7 serialize | 1.0 | 0.144 (85.6%) | 0.127 (87.3%) | 0.125 (87.5%) | 0.130 (87.0%) | 0.128 (87.2%) |
| test_tc_b100_30_classifier_outcome[exactly-1000-entries] :: TC-B100-30 classifier exactly-1000-entries | 1.0 | 0.106 (89.4%) | 0.110 (89.0%) | 0.108 (89.2%) | 0.108 (89.2%) | 0.111 (88.9%) |
| test_build_mac_view_cache_scales_under_load :: MAC view cache | 2.0 | 0.195 (90.2%) | 0.052 (97.4%) | 0.073 (96.3%) | 0.098 (95.1%) | 0.221 (88.9%) |
| test_tc_b100_61_sec6_5_entries_under_an_existing_folder_a... :: sec6_5 read | 1.0 | 0.086 (91.4%) | 0.088 (91.2%) | 0.085 (91.5%) | 0.083 (91.7%) | 0.086 (91.4%) |
| test_tc_b100_61_sec6_5_each_name_is_checked_once_per_read :: TC-B100-61 checks d | 1.0 | 0.086 (91.4%) | 0.084 (91.6%) | 0.082 (91.8%) | 0.083 (91.7%) | 0.085 (91.5%) |
| test_stress_load_s19_then_a2l_then_mac[s19_first] :: stress load s19_first | 20.0 | 1.531 (92.3%) | 1.593 (92.0%) | 1.392 (93.0%) | 1.524 (92.4%) | 1.403 (93.0%) |
| test_stress_load_s19_then_a2l_then_mac[mac_first] :: stress load mac_first | 20.0 | 1.412 (92.9%) | 1.378 (93.1%) | 1.563 (92.2%) | 1.410 (93.0%) | 1.562 (92.2%) |
| test_tc_b100_61_r2_2_legitimate_manifest_inside_every_cap... :: TC-B100-61 R2-2 read | 1.0 | 0.040 (96.0%) | 0.042 (95.8%) | 0.044 (95.6%) | 0.043 (95.7%) | 0.060 (94.0%) |
| test_end_to_end_load_pipeline_under_budget :: end-to-end load pipeline | 10.0 | 0.539 (94.6%) | 0.527 (94.7%) | 0.546 (94.5%) | 0.536 (94.6%) | 0.530 (94.7%) |
| test_tc_b100_61_sec6_5_each_name_is_checked_once_per_read :: TC-B100-61 checks e | 1.0 | 0.045 (95.5%) | 0.047 (95.3%) | 0.046 (95.4%) | 0.046 (95.4%) | 0.047 (95.3%) |
| test_tc_b100_28_document_finding_is_kept_first_beside_a_f... :: TC-B100-28 | 1.0 | 0.024 (97.6%) | 0.039 (96.1%) | 0.021 (97.9%) | 0.022 (97.8%) | 0.036 (96.4%) |
| test_at101_megabyte_unterminated_block_is_linear :: AT101 | 5.0 | 0.190 (96.2%) | 0.183 (96.3%) | 0.190 (96.2%) | 0.188 (96.2%) | 0.190 (96.2%) |
| test_tc_b100_61_sec6_5_each_name_is_checked_once_per_read :: TC-B100-61 checks b | 1.0 | 0.013 (98.7%) | 0.014 (98.6%) | 0.013 (98.7%) | 0.013 (98.7%) | 0.013 (98.7%) |
| test_tc_b100_30_classifier_outcome[brackets-1MiB] :: TC-B100-30 classifier brackets-1MiB | 1.0 | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.014 (98.6%) | 0.001 (99.9%) |
| test_tc_b100_30_classifier_outcome[1001-entries] :: TC-B100-30 classifier 1001-entries | 1.0 | 0.012 (98.8%) | 0.001 (99.9%) | 0.013 (98.7%) | 0.001 (99.9%) | 0.001 (99.9%) |
| test_tc_b100_24_assignments_75_by_1000_is_one_issue_fast :: TC-B100-24 assignments | 1.0 | 0.005 (99.5%) | 0.005 (99.5%) | 0.006 (99.4%) | 0.006 (99.4%) | 0.005 (99.5%) |
| test_tc_b100_30_classifier_outcome[entries-long-string] :: TC-B100-30 classifier entries-long-string | 1.0 | 0.001 (99.9%) | 0.001 (99.9%) | 0.002 (99.8%) | 0.001 (99.9%) | 0.001 (99.9%) |
| test_tc_b100_24_one_entry_over_the_cap_is_one_issue_fast[... :: TC-B100-24 files | 1.0 | 0.001 (99.9%) | 0.001 (99.9%) | 0.001 (99.9%) | 0.001 (99.9%) | 0.001 (99.9%) |
| test_tc_b100_24_one_entry_over_the_cap_is_one_issue_fast[... :: TC-B100-24 declared_regions | 1.0 | 0.001 (99.9%) | 0.001 (99.9%) | 0.001 (99.9%) | 0.001 (99.9%) | 0.001 (99.9%) |
| test_tc_b100_24_one_entry_over_the_cap_is_one_issue_fast[... :: TC-B100-24 derived_from | 1.0 | 0.001 (99.9%) | 0.001 (99.9%) | 0.001 (99.9%) | 0.001 (99.9%) | 0.001 (99.9%) |
| test_at120_oversized_alignment_layout_clamps_to_none :: AT120 | 2.0 | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) |
| test_tc149_dos_clamp_includes_padding :: TC149 | 1.0 | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) |
| test_tc138_dos_clamp_pure_arithmetic :: TC138 | 1.0 | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) |
| test_at111_oversized_axis_clamps_to_none :: AT111 | 2.0 | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) |
| test_tc_b100_30_classifier_outcome[20000-entries] :: TC-B100-30 classifier 20000-entries | 1.0 | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) |
| test_tc_b100_30_classifier_outcome[5000-digit-integer] :: TC-B100-30 classifier 5000-digit-integer | 1.0 | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) |
| test_tc_b100_30_classifier_outcome[bare-entries-is-5] :: TC-B100-30 classifier bare-entries-is-5 | 1.0 | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) |
| test_tc_b100_30_classifier_outcome[brackets-under-entries] :: TC-B100-30 classifier brackets-under-entries | 1.0 | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) |
| test_tc_b100_30_classifier_outcome[empty-entries] :: TC-B100-30 classifier empty-entries | 1.0 | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) |
| test_tc_b100_30_classifier_outcome[entries-is-5] :: TC-B100-30 classifier entries-is-5 | 1.0 | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) |
| test_tc_b100_30_classifier_outcome[entries-wide-object] :: TC-B100-30 classifier entries-wide-object | 1.0 | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) |
| test_tc_b100_30_classifier_outcome[not-utf8] :: TC-B100-30 classifier not-utf8 | 1.0 | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) |
| test_tc_b100_30_classifier_outcome[one-byte-over-1MiB] :: TC-B100-30 classifier one-byte-over-1MiB | 1.0 | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) |
| test_tc_b100_30_classifier_outcome[one-entry] :: TC-B100-30 classifier one-entry | 1.0 | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) |
| test_tc_b100_30_classifier_outcome[truncated] :: TC-B100-30 classifier truncated | 1.0 | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) |
| test_tc_b100_30_classifier_outcome[v1-document] :: TC-B100-30 classifier v1-document | 1.0 | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) |
| test_tc_b100_24_one_entry_over_the_cap_is_one_issue_fast[... :: TC-B100-24 batch | 1.0 | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) |
| test_tc_b100_24_one_entry_over_the_cap_is_one_issue_fast[... :: TC-B100-24 gathered | 1.0 | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) | 0.000 (100.0%) |

## 5. Linux gate run (two lanes, the way the gate will run)

Head = `origin/main` `e266395` + the Inc 2 diff. Lane 1:
`pytest -n 8 --dist loadfile -rs -m "not serial_timing"`. Lane 2: `pytest -rs -m serial_timing`
(serial).

| Lane | Result | Wall |
|---|---|---:|
| 1 | 8 failed, 5053 passed, 205 skipped, 4 xfailed | 64:18 |
| 2 | 58 passed, 2 skipped (the 2 Windows-only junction arms), 5270 deselected; QC-TM 72 bounds, 2 under 20 % | 5:07 |
| total | 0 failed timing arms | **69:25** |

Lane-1 failures:
- **Known pre-existing (5):** tc1802, tc707 ×2, 056e_a2b, b78_03.
- `tests/test_flow_report_service.py::test_tc016b_exception_diagnostics_do_not_leak_absolute_paths`.
  **Run environment.** The test asserts `os.environ.get("USERNAME", "") not in report`.
  The host's ssh login shell sets no `USERNAME`, so the test checks `'' not in report`,
  which always fails. It fails identically on base, and passes on both trees with
  `USERNAME` set (`int-linux-confirm.txt`). Not an Inc 2 defect. The gate needs
  `USERNAME` set, or the test needs fixing (§8).
- `tests/test_tui_snapshot.py::test_tc016s_snapshot_setup_loads_only_public_fixtures`.
  **Run environment.** The test requires `pytest` in the fixture path, or a path part named
  exactly `snapshot_public`. The `--basetemp <OUT>/bt-l1` of this run removes the
  `pytest-of-<user>` component. It fails identically on base with the same basetemp and
  passes on both trees with the default basetemp. Not an Inc 2 defect. The gate must keep
  the default basetemp (§8).
- `tests/test_b97_flow_execution.py::test_tc_b97_23_waiting_card_past_the_viewport_is_brought_into_view[wait_third_6-size0]`.
  **Flake under `-n 8`, not reproduced.** Its `poll` is a local, unchanged 60-pause
  count-bounded loop (`tests/test_b97_flow_execution.py:303`). Inc 2 changed neither it
  nor `settle`. On both trees it passes 3/3 serially (4 nodes each), and the whole file
  passes under `-n 8 --dist loadfile` and under default `-n 8` (`int-linux-confirm.txt`).
  It is a count-bounded wait of the kind R-TST-020 bounded for the 7 shared waits, but
  outside Inc 2's slice (§8).

**R-TST-009 caveat.** The documented release gate (R-TST-007,
`docs/engineering-rules.md:199`) is `pytest -n 8 -m "not serial_timing"`, with the default
`--dist load`. This run used `--dist loadfile` (the CI form), as the integration brief
asked. `loadfile` pins each file to one worker, and on this host
`test_b97_flow_execution.py` alone takes 8:51 under `loadfile` against 2:02 under default
`-n 8`. The 69:25 total therefore sits inside R-TST-009's 75 min even with the slower
form, but it is one run of a different command, not the R-TST-008/009 evidence (two
consecutive gate runs with the documented command, owed at E5).

Collect split (Windows, head): full `5330`, `-m "not serial_timing"` `5270`,
`-m serial_timing` `60` (59 arm nodes + the hygiene timing node); 5270 + 60 = 5330. On
Linux the serial lane deselects 5270 of 5330 (lane 2 header), so the split matches.

## 6. Windows runs (head)

Interpreter: s19env (Python 3.11.15, pytest 8.4.2). Env as pinned (`PYTHONPATH=.`,
`LOCALAPPDATA` and `--basetemp` under a temp folder, `NO_COLOR` unset), each run under
`timeout`. `s19_app.__file__` is printed first in every transcript (this worktree). The
real `%LOCALAPPDATA%\s19_app` was never created (checked before and after).

| Run | Result | Wall | Transcript |
|---|---|---:|---|
| `tests/test_suite_hygiene.py`, before the fixes | 2 failed (F-1, F-2), 52 passed | 1:54 | `int-win-hygiene-pre-fix-1.txt` |
| same, after F-1 | 1 failed (F-3), 53 passed | 2:03 | `int-win-hygiene-pre-fix-2.txt` |
| `tests/test_suite_hygiene.py`, final | **54 passed** (QC-TM: 2 bounds, 0 under 20 %) | 2:24 | `int-win-hygiene.txt` |
| TC-607 measurement before the edit | the guard scanned 241, not the declared 239 | 0:04 | `int-win-tc607-measure.txt` |
| Inc 1 guards after TC-607 (`test_id_registry`, `test_batch91_registry_hygiene`, `test_requirements_canon`) | **25 passed** | 0:06 | `int-win-registry.txt` |
| the 9 golden test files | 1 failed (`test_at_056e_a2b`, known pre-existing), **204 passed**; the 7 golden nodes of R-TST-081/1 all pass | 6:27 | `int-win-goldens.txt` |
| 12 touched arm files, first 7, unfiltered | 4 failed, 507 passed, 1 skipped; the 4 are timing arms over their 1.0 s bound (table below) | 20:50 | `int-win-arms-a.txt` |
| 12 touched arm files, last 5, unfiltered | **407 passed**, 1 xfailed | 50:35 | `int-win-arms-b.txt` |
| 12 touched arm files in one run (first attempt) | stopped by `timeout 1800` inside `test_b100_project_homes.py`; 5 failures in `test_b100_project_check.py` before the stop (the same arms) | 30:00 | `int-win-arms-timeout.txt` |
| shared-wait callers: `test_b99_load_project.py`, `test_b100_load_dialog.py` | **163 passed** | 14:07 | `int-win-waitcallers.txt` |
| shared-wait callers: `test_b100_workers.py` | **69 passed**, 1 xfailed | 17:06 | `int-win-workers.txt` |
| the 3 shared-wait caller files in one run (first attempt) | stopped by `timeout 1800` inside `test_b100_workers.py`, all green up to there | 30:00 | `int-win-waitcallers-timeout.txt` |
| `-m serial_timing`, head, serial (CPU 12 % before, 15 % after) | 3 failed, 57 passed; QC-TM 77 bounds, 9 under 20 % | 7:50 | `int-win-serial-timing.txt` |
| same 59 nodes, **base** `e266395`, serial (CPU 36 % at start) | 6 failed, 53 passed | 7:33 | `int-win-serial-timing-base.txt` |
| collect split | 5330 = 5270 + 60 | — | `int-win-collect-split.txt` |
| **final**: hygiene suite + Inc 1 guards, after every evidence file was written (`test_r_tst_070_2` scans them) | **79 passed** | 2:30 | `int-win-final.txt` |

The two first-attempt timeouts come from the host. Each stopped file passed in its own
run, with no test near the 60 s `wait_until` timeout. The slowest test,
`test_tc_b100_65_session_decided_once_per_open_case06`, takes 136.8 s of its own work on
this host against 43 s on the LAN host.

**Windows timing, base vs head.** Base and head share the same failing set: base fails
`TC-B100-20 save-project` (1.344 s), `sec6_5` existing-folder (appended 1.087 s), `sec6_5`
distinct-folders, `sec6_5` junction-loop (painted 1.050 s), `TC-B100-61 cap` (painted
1.070 s), and the TC-B100-30 5000-digit-integer load (4.130 s, base `load_project` clock).
Head fails only `save-project` (1.116 s) and the two `sec6_5 appended` arms (1.247 s,
1.086 s). Head's summed call time is about 3 % above base's (458.7 s against 444.9 s,
including the 0.7 s hygiene node). That is the same poll cost outside the bounded
intervals that Linux shows (§4). On Windows the same arms run 0.1–0.3 s slower than on
Linux and cross 1.0 s on either tree. **Verdict: environmental (host speed), not Inc 2.
No bound raised.**

Head arms under 20 % margin on Windows (bold), measured s (margin %):

| arm (node :: label) | bound s | head-serial | head-unfiltered |
|---|---:|---:|---:|
| test_tc_b100_20_writers_on_a_31_folder_manifest_finish_un... :: TC-B100-20 save-project | 1.0 | **1.116 (-11.6%)** | **1.260 (-26.0%)** |
| test_tc_b100_61_sec6_5_distinct_folders_stop_at_the_folde... :: sec6_5 appended | 1.0 | **1.247 (-24.7%)** | - |
| test_tc_b100_61_sec6_5_entries_under_an_existing_folder_a... :: sec6_5 appended | 1.0 | **1.086 (-8.6%)** | **1.175 (-17.5%)** |
| test_tc_b100_61_sec6_5_distinct_folders_stop_at_the_folde... :: sec6_5 load | 1.0 | **0.898 (10.2%)** | **1.103 (-10.3%)** |
| test_tc_b100_61_sec6_5_deep_entries_need_one_check_each_p... :: sec6_5 painted | 1.0 | **0.941 (5.9%)** | **1.063 (-6.3%)** |
| test_tc_b100_61_sec6_5_junction_loop_costs_one_failure :: sec6_5 painted | 1.0 | 0.001 (99.9%) | **0.986 (1.4%)** |
| test_tc_b100_61_every_array_at_the_cap_all_bad_opens_unde... :: TC-B100-61 all-bad painted | 1.0 | **0.953 (4.7%)** | 0.001 (99.9%) |
| test_tc_b100_61_files_at_the_cap_all_missing_are_bounded :: TC-B100-61 cap painted | 1.0 | **0.937 (6.3%)** | **0.824 (17.6%)** |
| test_tc_b100_61_sec6_5_deep_entries_need_one_check_each_p... :: sec6_5 appended | 1.0 | **0.928 (7.2%)** | - |
| test_tc_b100_61_sec6_5_distinct_folders_stop_at_the_folde... :: sec6_5 painted | 1.0 | **0.908 (9.2%)** | - |
| test_tc_b100_61_sec6_5_deep_entries_need_one_check_each_p... :: sec6_5 load | 1.0 | 0.430 (57.0%) | **0.837 (16.3%)** |
| test_tc_b100_61_sec6_5_entries_under_an_existing_folder_a... :: sec6_5 painted | 1.0 | 0.680 (32.0%) | **0.819 (18.1%)** |

## 7. `02-test-cases.md` result column

Updated only where a run on this commit now verifies the case, with the platform
named. Cases whose full verification is a gate, CI or E5 artifact keep `not_run` and
record which part was verified. Rows changed: 72. Of these, **56 are `verified (Windows + Linux, E4 integration)`**: every hygiene-suite case whose test is full and reaches its whole expected result on the head tree, plus R-TST-081/1 (the 7 golden nodes pass in `int-win-goldens.txt` and in LAN lane 1). The other **16 keep `not_run` with the verified part named**: the static halves of 010/011/012/017/018/1, 024/7–9 and 031/1, 031/2, 032/1 (one passing parallel-lane run each in LAN lane 1); the head-tree halves of 005/5, 040/1 and 040/4; and 008/1 and 009/1 (one run in the CI form, gate owed). The **Coverage** column still holds its E1 value (`gap`); this step was scoped to the result column only, so E5 updates Coverage when it confirms the trace.

## 8. Left for E5

1. **R-TST-008/009 gate evidence.** Two consecutive gate runs on the LAN host with the
   documented command (`pytest -n 8 -m "not serial_timing"`, then
   `pytest -m serial_timing`), with `USERNAME` set and the default basetemp. This run is
   one data point with the CI form (§5).
2. **Bimodal `painted` intervals and the `sec6_5 appended` / `TC-B100-20 save-project`
   arms near 1.0 s.** These are pre-existing and identical with base's waits (§4). In the
   four Linux serial runs before the gate, 2 had one such arm over its bound (base1,
   head2). Basewaits2 had a further over-bound arm, and the gate lane 2 had none. R-TST-008
   needs 0 failed timing arms in each of 2 consecutive gate runs, which this distribution
   does not guarantee. The ~1 s step has no obvious product timer behind it (the busy tick
   is 0.1 s, `s19_app/tui/app.py:364`). It needs a diagnosis: a product paint delay, or
   the clock-start rule `_paint_clock_start` (`tests/test_b100_project_check.py:774`).
   That is a design decision outside this E4 (no bound raised).
3. **Two environment-fragile tests.** `test_tc016b` (needs `USERNAME`) and `test_tc016s`
   (needs a pytest-named basetemp). They are pre-existing, and the gate procedure should
   name both conditions (or a backlog row should fix the tests).
4. **`test_tc_b97_23[wait_third_6-size0]` under `-n 8`.** A local count-bounded `poll`. It
   is a backlog candidate for the same treatment R-TST-020 gave the shared waits.
5. Census base-tree halves (R-TST-005/5, R-TST-040/1's 37-count, R-TST-040/4's base
   list) re-run on `b3bf42e`. The CI/PR evidence rows (R-TST-014/1, 018/2, 090/1, 091/1)
   and the three parallel-lane 3/3 runs of R-TST-031/032 are as listed in
   `E4-tester-notes.md` §Owed. The gate lane 1 gives one passing run of each of those
   three nodes.
6. The implementer's own notes end with "(pending — see below)". Their verification runs
   were cut by the swarm cap. This integration's runs replace them as the E4 evidence.

## 9. Evidence checklist

- [x] Tests / type checks / lint: the runs in §3–§6 with transcripts. No lint or type
      checker is configured for `tests/`.
- [x] No secrets in code or output: the evidence grep for home paths, account names and
      LAN addresses gives 0 matches on every new transcript, and `test_r_tst_070_2` is
      green.
- [x] No destructive commands. The only resets were `git reset --hard` / `git clean -fd`
      in the LAN host's scratch clone, which the brief prescribes. Nothing was pushed to
      GitHub.
- [x] File count: source edits are `pyproject.toml` (1 line) and
      `tests/test_id_registry.py` (the one allowed edit). Test edits are in
      `tests/test_suite_hygiene.py`. Docs are `codewire/graph-inc2.md` (redaction), this
      file and `02-test-cases.md`.
- [x] Review packet: this file, plus the final report to the orchestrator.
