# Inc 7 — E1 slice: every file and function to change, counted and mapped

Base `e266395`. Counted by reading the four files at that commit. The plan named 2 source files; the slice needs 4 (decisions O-1, O-2 of `E1-rulings.md`), which is the increment cap.

## 1. Summary

| Group | File | Functions changed | Functions new | Rows |
|---|---|---:|---:|---|
| G1 report generators | `s19_app/tui/services/diff_report_service.py` | 13 | 3 | R-CMP-004.14, R-CMP-004.9.1, R-CMP-004.9.2, R-BEFORE-AFTER-REPORT-001.32 … .34, guards R-CMP-004.1, .8, R-BEFORE-AFTER-REPORT-001.21, .22 |
| G2 before/after composer | `s19_app/tui/services/before_after_service.py` | 1 | 0 | R-BEFORE-AFTER-REPORT-001.24, .35, R-CMP-003.2 |
| G3 app trigger (O-1) | `s19_app/tui/app.py` | 2 | 0 | R-BEFORE-AFTER-REPORT-001.24, .35, R-CMP-003.2 (key `b` path) |
| G4 flow-A2B producer (O-2) | `s19_app/tui/services/flow_execution_service.py` | 1 (2 lines) | 0 | R-CMP-004.9.1, R-CMP-004.9.2 (no double escape) |

**Totals:** 4 source files, 17 changed functions, 3 new functions, 0 new modules, 0 new test files. Imports: `diff_report_service.py` adds `md_code` (from `markdown_safety`) and `REPORT_CELL_CHARS` (from `report_service`, value 512) and drops `MAX_HEX_ROWS` and `render_hex_view` (both unused after D-4); `flow_execution_service.py` keeps `md_safe`/`md_code` (used by the chain-set report).

## 2. Functions

| # | File | Function | Change | Rows |
|---|---|---|---|---|
| 1 | diff_report_service | `_md_text` | **new**: `md_safe(_strip_ctl(value), limit=REPORT_CELL_CHARS)` — the label-field writer | R-CMP-004.9.1, R-BEFORE-AFTER-REPORT-001.21 |
| 2 | diff_report_service | `_md_path` | **new**: `md_code(_strip_ctl(value))` — the path-field writer (the caller keeps the backticks) | R-CMP-004.9.2 |
| 3 | diff_report_service | `_run_symbol_names` | **new**: the names of the `(address, name)` pairs whose address lies in the run (the membership `_annotate_run` has today), as a list | R-CMP-004.5, R-BEFORE-AFTER-REPORT-001.24 |
| 4 | diff_report_service | `_annotate_run` | changed: `", ".join(_run_symbol_names(...))` or `-` (HTML output unchanged) | R-CMP-004.5 |
| 5 | diff_report_service | `_window_rows` | changed: renders every row of `[low, high)` itself, same row format, no cap (D-4) | R-CMP-004.14 |
| 6 | diff_report_service | `_image_line` | changed: label and variant id through `_md_text`, path through `_md_path` | R-CMP-004.9.1, .9.2 |
| 7 | diff_report_service | `_header_lines` | changed: new parameter `title` (first line `# <title>`) | R-BEFORE-AFTER-REPORT-001.32, R-CMP-004.1 |
| 8 | diff_report_service | `_run_table_lines` | changed: Symbols cell = `", ".join(_md_text(n) for n in names)` or `-` | R-CMP-004.9.1, R-BEFORE-AFTER-REPORT-001.24 |
| 9 | diff_report_service | `_provenance_lines` | changed: the 3 paths through `_md_path` (was `_md_cell`) | R-CMP-004.9.2, R-BEFORE-AFTER-REPORT-001.21 |
| 10 | diff_report_service | `_linkage_table_lines` | changed: Symbol cell through `_md_text` (was `_md_cell`); other cells unchanged (D-7) | R-CMP-004.9.1, R-BEFORE-AFTER-REPORT-001.21, .22 |
| 11 | diff_report_service | `_flow_change_attribution_lines` | changed: change-document reference and symbol through `_md_text`, in the table and the refusal bullets | R-CMP-004.9.1 |
| 12 | diff_report_service | `flow_change_census_complete` | changed: looks the document up with `_md_text` (lockstep with #11); refusal code unchanged | R-CMP-004.9.1 (TC-717/718 battery stays meaningful) |
| 13 | diff_report_service | `_audit_header_lines` | changed: filter name through `_md_text` (was `_strip_ctl`) | R-CMP-004.9.1 |
| 14 | diff_report_service | `_html_header` | changed: new parameter `title` (`<h1><title></h1>`) | R-BEFORE-AFTER-REPORT-001.34, R-CMP-004.1 |
| 15 | diff_report_service | `generate_diff_report` | changed: `title = "Before/after report" if provenance is not None else "Diff report"` passed to `_header_lines` (D-1) | .32, R-CMP-004.1 |
| 16 | diff_report_service | `generate_diff_report_html` | changed: same title rule for `<title>` and `_html_header` | .33, .34, R-CMP-004.1 |
| 17 | before_after_service | `compose_before_after_report` | changed: keyword inputs `a2l_data`, `a2l_records`, `mac_records` (default `None`); `a2l_data` + `mac_records` to `compare_images`; `a2l_records` / `mac_records` into the generator kwargs only when not `None` (D-2) | .24, .35, R-CMP-003.2 |
| 18 | app | `action_before_after_report` | changed: on the UI thread, gathers `a2l_data=self.current_a2l_data`, `a2l_records=self._compute_a2l_enriched_tags() or None`, `mac_records=loaded.mac_records if loaded is not None and loaded.mac_path is not None else None` (D-3) and passes them to the worker | .24, .35, R-CMP-003.2 |
| 19 | app | `_start_before_after_worker` | changed: three new keyword parameters, forwarded to `compose_before_after_report` | .24, .35 |
| 20 | flow_execution_service | `run_flow` (A2B external arm, `:981-988`) | changed: `md_safe(path.stem, limit=120)` → `path.stem`; `md_code(str(path))` → `str(path)` (D-6) | R-CMP-004.9.1, .9.2 |

Unchanged and relied on (context nodes of the graph): `_strip_ctl`, `_md_cell`, `_md_table_cell`, `md_safe`, `md_code`, `_diff_block_lines`, `_hex_windows_lines`, `_html_hex_windows`, `_html_side_by_side_pane`, `_html_hex_row`, `_html_run_rows`, `compute_hexdump_windows`, `compare_images`, `_compute_a2l_enriched_tags`.

## 3. Rows → functions (every row reaches code)

| Row | Functions |
|---|---|
| R-BEFORE-AFTER-REPORT-001.32 | 7, 15 |
| R-BEFORE-AFTER-REPORT-001.33 | 16 |
| R-BEFORE-AFTER-REPORT-001.34 | 14, 16 |
| R-CMP-004.1 (guard) | 7, 14, 15, 16 |
| R-BEFORE-AFTER-REPORT-001.35 | 17, 18, 19 |
| R-CMP-003.2 | 17, 18 |
| R-BEFORE-AFTER-REPORT-001.24 | 3, 8, 17, 18, 19 |
| R-CMP-004.5 | 3, 4 |
| R-CMP-004.14 | 5 |
| R-CMP-004.9.1 | 1, 6, 8, 10, 11, 12, 13, 20 |
| R-CMP-004.9.2 | 2, 6, 9, 20 |
| R-CMP-004.8 (guard) | — (HTML helpers unchanged; the guard checks they stay so) |
| R-BEFORE-AFTER-REPORT-001.21 | 1, 2, 9, 10 |
| R-BEFORE-AFTER-REPORT-001.22 | 1, 10 |

## 4. Nodes touched (existing tests; every node name stays)

Assertions that change because a row changes (E4 re-pins them, each with its row in the commit message):

| Node | Line(s) | Change | Row |
|---|---|---|---|
| `tests/test_before_after_report.py::test_at_054b_no_filter_bkey_report_pair_byte_identical_to_golden` | goldens | the two batch35 goldens (`E1-rulings.md` §3) | .32 … .34, .9.1 |
| `tests/test_diff_report_service.py::test_report_sections_present_in_order` | 297-298 | `A\.s19`, `B\.s19` | .9.1 |
| `tests/test_diff_report_service.py::test_symbol_annotation_only_intersecting_run` | 431, 434 | `INSIDE\_SYM`; negative re-pinned to `OUTSIDE\_SYM` (vacuity) | .9.1 |
| `tests/test_diff_report_service.py::test_default_kwargs_output_byte_identical_pre_change_golden` | 690 template | labels escaped | .9.1 |
| `tests/test_diff_report_service.py::test_tc313_no_filter_output_byte_identical_todays` | 690 template | same | .9.1 |
| `tests/test_diff_report_service.py::test_provenance_and_linkage_render_in_both_formats` | 835-836, 846-847 | Markdown spelling `CAL\_SYM`, `A2L\_SYM` (HTML keeps the raw names) | .9.1 |
| `tests/test_diff_report_service.py::test_pipe_bearing_symbol_md_escaped_html_intact` | 913 | `EVIL\|SYM\<b\>END` | .9.1 |
| `tests/test_diff_report_service.py::test_tc312_filter_restricts_linkage_and_run_sections_both_formats` | 1264, 1268 | escaped spelling; negative re-pinned (vacuity) | .9.1 |
| `tests/test_diff_report_service.py::test_tc312_a9_merged_window_spans_excluded_run` | 1323-1324 | same | .9.1 |
| `tests/test_diff_report_service.py::test_tc312_zero_match_notice_and_refusal_disjoint` | 1347 | negatives re-pinned (vacuity) | .9.1 |
| `tests/test_diff_report_service.py::test_tc312_audit_header_first_block_fixed_format` | 1386 | `cal-filter\.json` (O-5) | .9.1 |
| `tests/test_diff_report_service.py::test_tc318_hostile_filter_name_sanitized_md_html` | 1419 | `a\|b\`c\<b\>d\.json` (O-5) | .9.1 |
| `tests/test_tui_report_filter_surface.py::test_at_053b_hostile_valid_filter_proceeds_sanitized_everywhere` | 961-965, 982, 996 | ba-md filter name escaped (O-5); `# Before/after report`; `<h1>Before/after report</h1>` | .32, .34, .9.1 |
| `tests/test_changes_symbol_entries.py::test_tc717_flow_produced_image_diff_references_all_flow_changes` | 1368 | `c2\.json` | .9.1 |
| `tests/test_flow_a2b_b94.py::test_tc_b94_24_a2b_report_states_each_inputs_provenance` | 348-349 | `_TC_B94_24_FLOW_ARM_PASTE`: `patch\.out` | .9.1 |

Must stay GREEN unchanged (interface guards): `tests/test_before_after_report.py::test_tc311_no_filter_generator_kwargs_shape_is_todays` (D-1, D-2: no new kwarg without an A2L/MAC), `::test_tc_038_3_ctl_symbol_renders_identically_in_md_and_html_pair` (`CTLSYM` in both files), `tests/test_tui_flow_builder_b94.py::test_at_b94_18_hostile_names_render_literally` (one escape, D-6), `::test_at_b94_16_a2b_wiring_rule_and_report_provenance`, `tests/test_render_hexview.py` consumer census (D-4), `tests/test_diff_report_service.py::test_markdown_file_is_complete_no_truncation` and `::test_html_export_complete_and_safe` (0 `TRUNCATED`).

New tests: about 25 functions in `tests/test_diff_report_service.py` and `tests/test_before_after_report.py`, named `test_r_cmp_004_14_…`, `test_r_cmp_004_9_1_…`, `test_r_before_after_report_001_32_…` and so on (the token `trace_check.py` matches); no new file (D-8).
