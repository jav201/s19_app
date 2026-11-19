# CHECK — U1-recite (C1)

- Unit: U1-recite
- Tree: ~/work/zq-ta/U1/repo
- HEAD: b5ca5b7277e3a0aa9683e50fdd71ebb578ee7d80
- Start: Thu Nov 19 02:01:01 PM CST 2026

## Step 1 — Diff hygiene

```
$ cp -a ~/work/zq-ta/U1/repo ~/work/zq-ta/chk-U1
$ cd ~/work/zq-ta/chk-U1 && git diff > ~/work/zq-ta/chk-U1.diff
$ git diff --name-only | wc -l
65
$ tr -cd '\r' < ~/work/zq-ta/chk-U1.diff | wc -c
0
$ git diff | grep '^+' | grep -v '^+++' | grep -cE '\b(skip|skipif|xfail)\b|sleep\('
0
$ git diff | grep '^-' | grep -v '^---' | grep -E 'def test_'   # (none)
$ git diff | grep '^+' | grep -v '^+++' | grep -E 'def test_'   # (none)
```

- Files changed: 65, all within the 65 files named by applied rows of `recite-map.tsv` (set equality verified; the 66th distinct file `tests/test_examples_pilot_gifs.py` holds only the NEEDS-RULING row seq 349 and was not edited).
- CR count: 0. Added `skip`/`skipif`/`xfail`/`sleep(` lines: 0. `def test_` names removed and re-added: none.


## C1 Step 1 — Only docstrings/comments changed (own `ast_same.py`)

`~/work/zq-ta/chk-U1/ast_same.py` parses each changed `.py` in base and U1,
removes every docstring node (module/class/function first-statement string
constant), and compares `ast.dump`. Comments never enter the AST, so equality
proves only docstrings/comments changed.

```
$ ~/miniconda3/envs/s19ci/bin/python -I -B ast_same.py
OK  tests/test_a2l_missing_length_fix.py
OK  tests/test_a2l_record_layout_length.py
OK  tests/test_b100_active_variant.py
OK  tests/test_b100_save_guards.py
OK  tests/test_b101_designer_recompute.py
OK  tests/test_b101_inplace_views.py
OK  tests/test_b102_a2l_refresh.py
OK  tests/test_b102_clipboard.py
OK  tests/test_b102_flow_block_edit.py
OK  tests/test_b102_flow_file_chooser.py
OK  tests/test_b102_parameter_picker.py
OK  tests/test_b102_patch_picker.py
OK  tests/test_b103_inc8_p_layout.py
OK  tests/test_b103_picker_editor.py
OK  tests/test_b103_picker_model.py
OK  tests/test_b97_check_editor.py
OK  tests/test_before_after_report.py
OK  tests/test_capped_text_area.py
OK  tests/test_change_service.py
OK  tests/test_changes_apply.py
OK  tests/test_changes_collision.py
OK  tests/test_changes_schema.py
OK  tests/test_checks_engine.py
OK  tests/test_compare_service.py
OK  tests/test_crc_config.py
OK  tests/test_crc_designer_model.py
OK  tests/test_crc_designer_view.py
OK  tests/test_crc_engine.py
OK  tests/test_crc_operation.py
OK  tests/test_diff_report_service.py
OK  tests/test_discoverability.py
OK  tests/test_filename_markup_safety.py
OK  tests/test_flow_a2b_b94.py
OK  tests/test_flow_persistence.py
OK  tests/test_help_toggle_and_a2l_panel.py
OK  tests/test_hexfile.py
OK  tests/test_loadfilescreen_input.py
OK  tests/test_manifest_verify.py
OK  tests/test_manifest_writer.py
OK  tests/test_map_click_chain.py
OK  tests/test_range_index.py
OK  tests/test_report_field_census.py
OK  tests/test_report_symbol_escape.py
OK  tests/test_suite_hygiene.py
OK  tests/test_tui_a2l.py
OK  tests/test_tui_check_editor.py
OK  tests/test_tui_crc_surface.py
OK  tests/test_tui_diff_compare_realpath.py
OK  tests/test_tui_diff_screen.py
OK  tests/test_tui_directionb.py
OK  tests/test_tui_flow_execution_b94.py
OK  tests/test_tui_helpers.py
OK  tests/test_tui_manifest_save.py
OK  tests/test_tui_map_wrap.py
OK  tests/test_tui_operations_view.py
OK  tests/test_tui_patch_editor_b94.py
OK  tests/test_tui_patch_editor_v2.py
OK  tests/test_tui_patch_json.py
OK  tests/test_tui_report_seam.py
OK  tests/test_tui_services.py
OK  tests/test_undo_redo_ux.py
OK  tests/test_validation_a2l.py
OK  tests/test_validation_mac.py
OK  tests/test_variant_execution.py
OK  tests/test_verify_on_save.py

65 files compared; 65 OK; 0 mismatches.
```

Result: all 65 changed files are docstring/comment-only edits. PASS.

## C1 Step 2 — Rows really applied (seed printed)

Script: `~/work/zq-ta/chk-U1/rows_check.py`. REPLACE checked via the P3 token
regex (`(?<![A-Za-z0-9_.-])` + escaped old id + `(?![A-Za-z0-9_]|[.-][A-Za-z0-9]|/)`)
over the row's citation region (docstring / comment / banner); ADD checked that
the test's own docstring has exactly one `Traces:` line equal to the ordered
union of its group's `new_ids`; NEEDS-RULING checked `skipped` status in the
worker's result TSV plus unchanged citations.

```
seed=20261119
REPLACE rows total=144, ADD tests total=122, NEEDS-RULING total=4

== REPLACE rows (20) ==
[OK] seq=37 tests/test_change_service.py::test_add_edit_remove_string_entry (doc) old=LLR-003.4 new=R-PE-021;R-PE-024;R-PE-026 | old_in_base=True old_gone=True new_present=True
[OK] seq=64 tests/test_changes_apply.py::test_error_blocks_apply_zero_writes_all_blocked (comment) old=LLR-002.8 new=R-CHG-002.3;R-CHG-002.4 | old_in_base=True old_gone=True new_present=True
[OK] seq=66 tests/test_changes_apply.py::test_save_back_written_file_reparses_to_post_apply_map (comment) old=LLR-002.7 new=R-IMG-WRITE.2 | old_in_base=True old_gone=True new_present=True
[OK] seq=73 tests/test_changes_schema.py::test_metadata_faults (doc) old=LLR-001.3 new=R-CHG-001.12;R-CHG-001.14 | old_in_base=True old_gone=True new_present=True
[OK] seq=75 tests/test_changes_schema.py::test_resource_ceilings_size_cap_before_parse (doc) old=LLR-001.7 new=R-CHG-001.5;R-CHG-001.4 | old_in_base=True old_gone=True new_present=True
[OK] seq=109 tests/test_diff_report_service.py::test_no_project_nonexistent_dir_refused (doc) old=LLR-004.6 new=R-CMP-005.4 | old_in_base=True old_gone=True new_present=True
[OK] seq=123 tests/test_flow_a2b_b94.py::test_tc_b94_22_patch_write_out_run_records_per_block_results (doc) old=LLR-013.3 new=R-FLOW-PATCH.10 | old_in_base=True old_gone=True new_present=True
[OK] seq=164 tests/test_manifest_writer.py::test_relative_paths_resolve_with_no_escape (comment) old=LLR-001.2 new=R-MAN-SER-001.6;R-MAN-SER-001.4 | old_in_base=True old_gone=True new_present=True
[OK] seq=169 tests/test_manifest_writer.py::test_refuse_escape_and_absolute_entries_writes_nothing (doc) old=LLR-001.5 new=R-MAN-SER-001.7;R-MAN-SER-001.8 | old_in_base=True old_gone=True new_present=True
[OK] seq=173 tests/test_manifest_writer.py::test_write_places_manifest_and_reads_back (doc) old=LLR-002.1 new=R-MAN-WRITE-001.1 | old_in_base=True old_gone=True new_present=True
[OK] seq=211 tests/test_tui_check_editor.py::test_tc_b94_06_composition_census (doc) old=LLR-001.1 new=R-CHKED-022 | old_in_base=True old_gone=True new_present=True
[OK] seq=223 tests/test_tui_diff_screen.py::test_tc_b78_49_a_second_compare_rebuilds_the_list (doc) old=HLR-122 new=R-CMP-006.5 | old_in_base=True old_gone=True new_present=True
[OK] seq=237 tests/test_tui_flow_execution_b94.py::test_tc_b94_08_rail_entries_census_and_duplicate_rejection (doc) old=LLR-002.1 new=R-TUI-021.1 | old_in_base=True old_gone=True new_present=True
[OK] seq=348 tests/test_crc_designer_view.py::test_save_check_mismatch_warns_but_still_writes (doc) old=LLR-V5.4c new=R-CRC-TEMPLATE-001.4 | old_in_base=True old_gone=True new_present=True
[OK] seq=362 tests/test_loadfilescreen_input.py::test_ctrl_v_notifies_user_when_every_clipboard_source_is_empty (doc) old=R-TUI-043-l new=R-TUI-043.7 | old_in_base=True old_gone=True new_present=True
[OK] seq=363 tests/test_loadfilescreen_input.py::test_powershell_layer_does_not_require_wt_or_windows_terminal (doc) old=R-TUI-043-m new=R-TUI-043.11 | old_in_base=True old_gone=True new_present=True
[OK] seq=368 tests/test_map_click_chain.py::test_ac6_gap_hatch_segments_are_not_clickable (doc) old=LLR-045C.3 new=R-TUI-062.9 | old_in_base=True old_gone=True new_present=True
[OK] seq=371 tests/test_b102_parameter_picker.py::test_tc_b102_sel_02_filter_is_debounced_and_reports_truncation (doc) old=R-B102-SEL-002 new=R-B102-SEL-002.1;R-B102-SEL-002.2 | old_in_base=True old_gone=True new_present=True
[OK] seq=386 tests/test_b102_patch_picker.py::test_tc_b102_pe_03_use_parameter_populates_inputs_without_document_mutation (doc) old=R-B102-PE-003 new=R-PICKER-CORRECT.006 | old_in_base=True old_gone=True new_present=True
[OK] seq=388 tests/test_b102_patch_picker.py::test_tc_b102_pe_06_hostile_parameter_name_reads_literally (doc) old=R-B102-PE-006 new=R-PICKER-CORRECT.017 | old_in_base=True old_gone=True new_present=True

== ADD tests (20) ==
[OK] tests/test_a2l_missing_length_fix.py::test_ac1_valid_address_missing_length_is_schema_ok | planned=Traces: R-A2L-072, R-A2L-070. | found=['Traces: R-A2L-072, R-A2L-070.']
[OK] tests/test_a2l_record_layout_length.py::test_ac1_wider_layout_resolves | planned=Traces: R-A2L-015, R-A2L-022. | found=['Traces: R-A2L-015, R-A2L-022.']
[OK] tests/test_a2l_record_layout_length.py::test_ac4_absent_layout_stays_none | planned=Traces: R-A2L-020. | found=['Traces: R-A2L-020.']
[OK] tests/test_b103_picker_editor.py::test_r008_declared_length_observes_decode_cap | planned=Traces: R-PICKER-CORRECT.008.1, R-PICKER-CORRECT.008.2. | found=['Traces: R-PICKER-CORRECT.008.1, R-PICKER-CORRECT.008.2.']
[OK] tests/test_change_service.py::test_add_duplicate_address_is_rejected | planned=Traces: R-PE-023. | found=['Traces: R-PE-023.']
[OK] tests/test_change_service.py::test_refused_save_leaves_verify_result_none | planned=Traces: R-CHG-003.16. | found=['Traces: R-CHG-003.16.']
[OK] tests/test_change_service.py::test_rows_render_kind_address_status_and_fault_marker | planned=Traces: R-CHG-004.4, R-PE-040. | found=['Traces: R-CHG-004.4, R-PE-040.']
[OK] tests/test_change_service.py::test_run_checks_default_seam_is_real_engine | planned=Traces: R-PATCH-CHECKS-CLARITY-001.1, R-CHK-PE-003. | found=['Traces: R-PATCH-CHECKS-CLARITY-001.1, R-CHK-PE-003.']
[OK] tests/test_change_service.py::test_run_checks_with_injected_runner_shapes_display | planned=Traces: R-CHK-PE-002, R-CHK-PE-003. | found=['Traces: R-CHK-PE-002, R-CHK-PE-003.']
[OK] tests/test_crc_designer_model.py::test_evaluate_target_ignore_is_silent | planned=Traces: R-CRC-PREVIEW-001.7. | found=['Traces: R-CRC-PREVIEW-001.7.']
[OK] tests/test_hexfile.py::test_hex_checksum_mismatch_is_reported | planned=Traces: R-HEX-007.1, R-HEX-007.2, R-VAL-001a. | found=['Traces: R-HEX-007.1, R-HEX-007.2, R-VAL-001a.']
[OK] tests/test_hexfile.py::test_hex_missing_file_raises | planned=Traces: R-READ-004.1. | found=['Traces: R-READ-004.1.']
[OK] tests/test_manifest_verify.py::test_reader_issues_force_mismatch_even_if_surviving_keys_match | planned=Traces: R-MAN-VERIFY-001.2. | found=['Traces: R-MAN-VERIFY-001.2.']
[OK] tests/test_tui_a2l.py::test_characteristic_accessor_payloads | planned=Traces: R-A2L-053, R-A2L-040. | found=['Traces: R-A2L-053, R-A2L-040.']
[OK] tests/test_tui_a2l.py::test_parse_compu_method_extracts_unit_from_body_conversion_line | planned=Traces: R-A2L-033. | found=['Traces: R-A2L-033.']
[OK] tests/test_tui_a2l.py::test_validate_a2l_tags_virtual_without_address_skips_range | planned=Traces: R-A2L-072. | found=['Traces: R-A2L-072.']
[OK] tests/test_tui_helpers.py::test_render_a2l_view_shows_nested_sections | planned=Traces: R-A2L-076. | found=['Traces: R-A2L-076.']
[OK] tests/test_tui_manifest_save.py::test_manifest_write_refusal_surfaces_error_notice_no_crash | planned=Traces: R-MAN-TUI-001.2, R-MAN-TUI-001.1. | found=['Traces: R-MAN-TUI-001.2, R-MAN-TUI-001.1.']
[OK] tests/test_tui_report_seam.py::test_report_seam_renders_generated_report_in_viewer | planned=Traces: R-RPT-002.5. | found=['Traces: R-RPT-002.5.']
[OK] tests/test_validation_mac.py::test_validate_mac_records_detects_duplicate_address_alias_candidate | planned=Traces: R-VAL-023. | found=['Traces: R-VAL-023.']

== NEEDS-RULING rows (4) — skipped, citations unchanged ==
[OK] seq=349 tests/test_examples_pilot_gifs.py::test_case_pilot_capture_and_gif old=R-7 | skipped=True docstring_unchanged=True real_citation=True token_still_present=True
[OK] seq=351 tests/test_b101_designer_recompute.py::test_r_crc_preview_coverage_crc_error_after_a_clean_evaluation_is_named old=R-CRC-PREVIEW-COVERAGE-CRC-ERROR-AFTER-A-CLEAN-EVALUATION-IS-NAMED | skipped=True docstring_unchanged=True real_citation=False token_still_present=False
[OK] seq=389 tests/test_b102_patch_picker.py::test_tc_b102_pe_06_empty_states_mirror_check old=R-B102-PE-006 | skipped=True docstring_unchanged=True real_citation=True token_still_present=True
[OK] seq=390 tests/test_validation_mac.py::test_validate_mac_records_reports_parse_and_empty_fields old=LLR-122.3 | skipped=True docstring_unchanged=True real_citation=True token_still_present=True

TOTAL FAIL: 0
```

Notes: seq 351's `old_id` is a synthetic "no target id" placeholder (never
appears in base), so only docstring-unchanged + skipped applies; it holds. All
20 REPLACE + 20 ADD + 4 NEEDS-RULING checks pass. PASS.

## C1 Step 3 — Trace classes (reverse_trace base vs U1; scope join)

```
$ ~/miniconda3/envs/s19ci/bin/python -I -B in/reverse_trace.py --repo base --out chk-U1/rt-base --tmp chk-U1/rt-tmp-base --ta2
tests: 6966 {'O': 1563, 'K?': 602, 'S': 1215, 'K': 3062, 'X': 484, 'U': 40}

$ ~/miniconda3/envs/s19ci/bin/python -I -B in/reverse_trace.py --repo chk-U1 --out chk-U1/rt-u1 --tmp chk-U1/rt-tmp-u1 --ta2
tests: 6966 {'O': 1561, 'K?': 625, 'S': 1215, 'K': 3280, 'X': 278, 'U': 7}
```

Base = 6966, X 484, U 40; U1 = 6966, X 278, U 7 — both match the brief's
expected figures.

Scope join (U1 `TA2-matrix.tsv` × `scope-before.tsv` on (file,test)):

```
scope-before rows: 261
NEEDS-RULING (file,test): 4
scope tests still X/U: 3
  class=U map_class=U-STALE [NEEDS-RULING] tests/test_b101_designer_recompute.py::test_r_crc_preview_coverage_crc_error_after_a_clean_evaluation_is_named
  class=U map_class=U-STALE [NEEDS-RULING] tests/test_examples_pilot_gifs.py::test_case_pilot_capture_and_gif
  class=X map_class=TR01-RETRACE [NEEDS-RULING] tests/test_validation_mac.py::test_validate_mac_records_reports_parse_and_empty_fields
scope tests missing from matrix: 0
RESULT: PASS
```

Only 3 scope tests remain X/U, all NEEDS-RULING (2 U + 1 X). The 4th
NEEDS-RULING test `tests/test_b102_patch_picker.py::test_tc_b102_pe_06_empty_states_mirror_check`
is class O (absent from the X/U list). Every scope test without a NEEDS-RULING
row has a class other than X and U. PASS.

## C1 Step 4 — NC-c (tool catches a bad id) and NC-d (which law catches what)

Copy `~/work/zq-ta/chk-U1-nc` = `cp -a ~/work/zq-ta/U1/repo`, then the first
`Traces:` line of `tests/test_hexfile.py` (the docstring of
`test_hex_extended_linear_address`, line 19) was rewritten:

```
    """Traces: R-NOPE-999.1."""
```

**NC-c** — reverse_trace on the copy classes that test U:

```
$ ~/miniconda3/envs/s19ci/bin/python -I -B in/reverse_trace.py --repo chk-U1-nc --out chk-U1/rt-nc --tmp chk-U1/rt-tmp-nc --ta2
tests: 6966 {'O': 1561, 'K?': 625, 'S': 1215, 'K': 3279, 'X': 278, 'U': 8}

class of tests/test_hexfile.py::test_hex_extended_linear_address = U (ids=R-NOPE-999.1, class2=U)
```

U count went 7 -> 8; the bad id `R-NOPE-999.1` is caught (test now class U). PASS.

**NC-d part 1** — in the same copy add ` TC-99999` to that docstring; then
`tests/test_id_registry.py::test_tc602_g3_every_citation_is_registered` goes RED
naming TC-99999:

```
$ ... pytest -p no:cacheprovider -q tests/test_id_registry.py::test_tc602_g3_every_citation_is_registered
>       assert not problems, _report("G3 (citation -> registry)", problems)
E       AssertionError: G3 (citation -> registry) failed with 1 offender(s):
E           - TC-99999 is cited at ['tests/test_hexfile.py:19'] but is not registered
E       assert not ["TC-99999 is cited at ['tests/test_hexfile.py:19'] but is not registered"]
FAILED tests/test_id_registry.py::test_tc602_g3_every_citation_is_registered
1 failed in 8.21s
```

PASS.

**NC-d part 2** — revert to only `R-NOPE-999.1` planted (no TC-99999); run all
six law files serially (`-n 0`). They keep the U0 result (no new RED), proving
no law checks R-/US- citations in tests:

```
FAILED tests/test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses
FAILED tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors
2 failed, 113 passed, 2 skipped in 433.77s (0:07:13)
```

Same 2-RED set as U0. Law gap confirmed as stated. PASS.

## C1 Step 5 — `--collect-only -q tests` (base vs U1)

```
base: 9834 tests collected in 18.36s
U1  : 9834 tests collected in 20.92s
```

Counts equal (9834 == 9834). PASS.

## CHK-ds Step 4 — Laws (six files, serial, on clean U1 copy)

Fresh clean copy `~/work/zq-ta/chk-U1-laws` = `cp -a ~/work/zq-ta/U1/repo`.

```
$ cd ~/work/zq-ta/chk-U1-laws && S=$HOME/work/zq-ta/chk-U1-state; mkdir -p $S~ $S/tmp $S/x; timeout 1200 env -i PATH=/usr/bin:/bin HOME=$S~ XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py < /dev/null
FAILED tests/test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses
FAILED tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors
2 failed, 113 passed, 2 skipped in 442.23s (0:07:22)
```

U0 baseline (`~/work/zq-ta/baseline/laws-b5ca5b72.txt`) is exactly
`2 failed, 113 passed, 2 skipped` with the same two RED tests
(`test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses`,
`test_at_b83_08_tree_holds_no_assembled_selectors`). No new RED vs U0. PASS.

(Note: the first law run I attempted was on the polluted `chk-U1` copy that held
my reverse_trace `rt-tmp-*` control repos, which made
`test_r_tst_002_2_parallel_lane_collection_prints_no_qc_tm_text` fail spuriously
during its subprocess `--collect-only`. Re-running on a clean copy removes that
artifact; the two remaining REDs are exactly the U0 baseline REDs.)

## CHK-ds Step 5 — Worker claims (5, re-verified)

1. **Claim:** `test_apply_recite.py` = `11 passed`. **TRUE.**
   `$ ... pytest -p no:cacheprovider -q ../test_apply_recite.py` -> `11 passed in 0.49s`.

2. **Claim:** 144 REPLACE + 242 ADD = 386 applied, 4 skipped, 65 files. **TRUE.**
   `recite-result.tsv` (final idempotent state) has 390 rows: `386 already` + `4 skipped`.
   Map action counts: REPLACE 144, ADD 242, NEEDS-RULING 4.

3. **Claim:** `git diff --stat` = 65 files, 334 insertions, 155 deletions. **TRUE.**
   `65 files changed, 334 insertions(+), 155 deletions(-)` (numstat totals: 334/155 over 65 files).

4. **Claim:** NC-a — seq 368 with `new_ids=R-NOPE-999.1` -> dry run exit 2 naming seq 368. **TRUE.**
   `$ ... apply_recite.py --repo <fresh base copy> --map nc-map.tsv` -> `recite: non-canon new_ids: 368=R-NOPE-999.1`, exit 2.

5. **Claim:** NC-b — idempotent rerun: all `already`, diff md5 identical. **TRUE.**
   `$ ... apply_recite.py --repo <applied copy> --map recite-map.tsv --apply` ->
   `REPLACE rows: 144 (applied=0, already=144)`, `ADD rows: 242 (applied=0, already=242)`,
   `NEEDS-RULING rows: 4 (skipped=4)`, `files: 0`;
   `git diff | md5sum` before = after = `97fcbbb60367d589e2a2e291c1619af6`.

All 5 claims TRUE.

## CHK-ds Step 6 — Save the diff

```
$ cp ~/work/zq-ta/chk-U1.diff ~/work/zq-ta/U1/CHECK.diff
```

(step 1's diff, 131915 bytes, CR count 0).

CHECK_DONE U1 MECH-GO
