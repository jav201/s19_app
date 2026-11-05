# Inc 7 — E1 slice: every file and function to change, counted and mapped

Base `e266395`. Counted by reading the four files at that commit. The plan named 2 source files; the slice needs 4 (rulings O-1, O-2), which is the increment cap. E3 round 1 (`E3-rulings.md`) adds functions inside the same 4 files and no new file; changed entries carry the finding id in brackets.

## 1. Summary

| Group | File | Functions changed | Functions new | Rows |
|---|---|---:|---:|---|
| G1 report generators | `s19_app/tui/services/diff_report_service.py` | 15 | 4 | R-CMP-004.14, .15, R-CMP-004.9.1, .9.2, R-CMP-005.16, R-BEFORE-AFTER-REPORT-001.32 … .34, .21; guards R-CMP-004.1, .8, R-BEFORE-AFTER-REPORT-001.22 |
| G2 before/after composer | `s19_app/tui/services/before_after_service.py` | 1 | 0 | R-BEFORE-AFTER-REPORT-001.11, .24, .35, R-CMP-003.2, R-CMP-005.17 |
| G3 app (O-1) | `s19_app/tui/app.py` | 3 | 0 | R-BEFORE-AFTER-REPORT-001.24, .35, R-CMP-003.2 (key `b` path); R-CMP-005.17 (A↔B report) |
| G4 flow-A2B producer (O-2) | `s19_app/tui/services/flow_execution_service.py` | 1 (2 lines) | 0 | R-CMP-004.9.1, R-CMP-004.9.2 (no double escape) |

**Totals:** 4 source files (the cap; not exceeded), 20 changed functions, 4 new functions, 0 new modules, 0 new test files. Imports: `diff_report_service.py` adds `md_code` and the private `_normalise` (from `markdown_safety`: the one definition of the visible-text steps and of `_DROP_CATEGORIES`, already pinned by `tests/test_report_markup_safety.py:185`) [S-2], `REPORT_CELL_CHARS` (from `report_service`, value 512) and `os`; it drops `MAX_HEX_ROWS` and `render_hex_view` (both unused after D-4). `flow_execution_service.py` keeps `md_safe`/`md_code` (used by the chain-set report).

## 2. Functions

| # | File | Function | Change | Rows |
|---|---|---|---|---|
| 1 | diff_report_service | `_md_text` | **new**: `md_safe(value, limit=limit)`, `limit` = 512 by default, 500 for a refusal message. No separate strip before it: `md_safe` runs the visible-text steps itself after slicing its input at 8 × limit [S-1, S-2, S-5] | R-CMP-004.9.1, R-BEFORE-AFTER-REPORT-001.21 |
| 2 | diff_report_service | `_md_path` | **new**: `md_code(value)` — the path-field writer (the caller keeps the backticks) [S-2] | R-CMP-004.9.2, R-BEFORE-AFTER-REPORT-001.21 |
| 3 | diff_report_service | `_run_symbol_names` | **new**: the names of the `(address, name)` pairs whose address lies in the run (today's `_annotate_run` membership), as a list | R-CMP-004.5, R-BEFORE-AFTER-REPORT-001.24 |
| 4 | diff_report_service | `_write_report` | **new** [S-3]: writes the text to `<target>.<16 random hex>.part` (exclusive create, UTF-8; random name since E5 C-1), then `os.replace(<target>.part, <target>)`; on any exception removes `<target>.part` (missing is fine) and re-raises | R-CMP-005.16 |
| 5 | diff_report_service | `_strip_ctl` | changed [S-2]: was: removes U+0000 … U+001F and U+007F / now: returns the visible text (`_normalise(str(value))`: tab/CR/LF → space; Cc, Cf, Cs, Zl, Zp → `�`). Name kept (a test calls it, `tests/test_tui_report_filter_surface.py:1390`; its asserts still hold). Every HTML sink that already calls it (`_html_provenance`, `_html_linkage`, `_html_flow_change_attribution`, `_html_audit_header`) and `_md_cell` follow without a code change | R-CMP-004.15, R-BEFORE-AFTER-REPORT-001.21 |
| 6 | diff_report_service | `_annotate_run` | changed: `", ".join(_run_symbol_names(...))` or `-` | R-CMP-004.5 |
| 7 | diff_report_service | `_window_rows` | changed: renders every row of `[low, high)` itself in the `render_hex_view` row format (`hexview.py:273-276`), no cap (D-4) [F-E3-5] | R-CMP-004.14 |
| 8 | diff_report_service | `_image_line` | changed: label and variant id through `_md_text`, path through `_md_path` | R-CMP-004.9.1, .9.2 |
| 9 | diff_report_service | `_header_lines` | changed: new parameter `title` (first line `# <title>`) | R-BEFORE-AFTER-REPORT-001.32, R-CMP-004.1 |
| 10 | diff_report_service | `_run_table_lines` | changed: Symbols cell = `", ".join(_md_text(n) for n in names)` or `-` | R-CMP-004.9.1, R-BEFORE-AFTER-REPORT-001.24 |
| 11 | diff_report_service | `_provenance_lines` | changed: the 3 paths through `_md_path` (was `_md_cell`) | R-CMP-004.9.2, R-BEFORE-AFTER-REPORT-001.21 |
| 12 | diff_report_service | `_linkage_table_lines` | changed: Symbol cell through `_md_text` (was `_md_cell`); Type, Disposition, Linkage stay `_md_cell` (D-7) | R-CMP-004.9.1, R-BEFORE-AFTER-REPORT-001.21, .22 |
| 13 | diff_report_service | `_flow_change_attribution_lines` | changed: change-document reference and symbol through `_md_text`; the refusal **message** through `_md_text(message, limit=500)` [S-1]; disposition and code stay `_md_cell` | R-CMP-004.9.1 |
| 14 | diff_report_service | `flow_change_census_complete` | changed: looks the document up with `_md_text` (lockstep with #13); refusal code unchanged; the message is not read | R-CMP-004.9.1 |
| 15 | diff_report_service | `_audit_header_lines` | changed: filter name through `_md_text` (was `_strip_ctl`) | R-CMP-004.9.1 |
| 16 | diff_report_service | `_html_header` | changed: new parameter `title` (`<h1>{_esc(title)}</h1>`); label, variant id and path through `_esc(_strip_ctl(…))` (was `_esc` alone) [S-2] | R-BEFORE-AFTER-REPORT-001.34, R-CMP-004.1, R-CMP-004.15 |
| 17 | diff_report_service | `_html_run_rows` | changed [S-2]: Symbols cell `_esc(_strip_ctl(_annotate_run(...)))` (was `_esc` alone) | R-CMP-004.15 |
| 18 | diff_report_service | `generate_diff_report` | changed: `title = "Before/after report" if provenance is not None else "Diff report"` (D-1); writes through `_write_report` [S-3] | .32, R-CMP-004.1, R-CMP-005.16 |
| 19 | diff_report_service | `generate_diff_report_html` | changed: same title rule, `<title>{_esc(title)}</title>` [F-E3-10] and `_html_header(..., title)`; writes through `_write_report` [S-3] | .33, .34, R-CMP-004.1, R-CMP-005.16 |
| 20 | before_after_service | `compose_before_after_report` | changed: keyword inputs `a2l_data`, `a2l_records`, `mac_records` (default `None`); `a2l_data` + `mac_records` to `compare_images`; `a2l_records` / `mac_records` into the generator kwargs only when not `None` (D-2). The no-project reason reads `(key 7)` [F-E3-1]. If the HTML generator raises or refuses after the Markdown file was written, removes that Markdown file (`unlink(missing_ok=True)`, an `OSError` from the removal suppressed: the module does no logging), then re-raises or returns the refusal as today [S-3] | .11, .24, .35, R-CMP-003.2, R-CMP-005.17 |
| 21 | app | `action_before_after_report` | changed: on the UI thread, gathers `a2l_data=self.current_a2l_data`, `a2l_records=self._compute_a2l_enriched_tags() or None`, `mac_records=loaded.mac_records if loaded is not None and loaded.mac_path is not None else None` (D-3) and passes them to the worker | .24, .35, R-CMP-003.2 |
| 22 | app | `_start_before_after_worker` | changed: three new keyword parameters, forwarded to `compose_before_after_report` | .24, .35 |
| 23 | app | `_start_diff_report_worker` | changed [S-3]: when `generate_diff_report_html` raises or refuses after the Markdown file was written, removes `md.path` (`unlink(missing_ok=True)`; an `OSError` logged at WARNING `report kind=diff orphan not removed: <error type>`, never the content) before the existing status; status texts unchanged | R-CMP-005.17 |
| 24 | flow_execution_service | `run_flow` (A2B external arm, `:981-988`) | changed: `md_safe(path.stem, limit=120)` → `path.stem`; `md_code(str(path))` → `str(path)` (D-6) | R-CMP-004.9.1, .9.2 |

Unchanged and relied on (context nodes of the graph): `_md_cell`, `_md_table_cell`, `md_safe`, `md_code`, `_normalise`, `_diff_block_lines`, `_hex_windows_lines`, `_html_hex_windows`, `_html_side_by_side_pane`, `_html_hex_row`, `_html_provenance`, `_html_linkage`, `_html_flow_change_attribution`, `_html_audit_header` (code unchanged, output follows #5), `compute_hexdump_windows`, `compare_images`, `_compute_a2l_enriched_tags`.

## 3. Rows → functions (every row reaches code)

| Row | Functions |
|---|---|
| R-BEFORE-AFTER-REPORT-001.32 | 9, 18 |
| R-BEFORE-AFTER-REPORT-001.33 | 19 |
| R-BEFORE-AFTER-REPORT-001.34 | 16, 19 |
| R-CMP-004.1 (guard) | 9, 16, 18, 19 |
| R-BEFORE-AFTER-REPORT-001.35 | 20, 21, 22 |
| R-CMP-003.2 | 20, 21 |
| R-BEFORE-AFTER-REPORT-001.24 | 3, 10, 20, 21, 22 |
| R-CMP-004.5 | 3, 6 |
| R-BEFORE-AFTER-REPORT-001.11 | 20 |
| R-CMP-004.14 | 7 |
| R-CMP-005.16 | 4, 18, 19 |
| R-CMP-005.17 | 20, 23 |
| R-CMP-004.9.1 | 1, 8, 10, 12, 13, 14, 15, 24 |
| R-CMP-004.9.2 | 2, 8, 11, 24 |
| R-CMP-004.15 | 5, 16, 17 |
| R-CMP-004.8 (guard) | 16, 17 (still `_esc`, no Markdown escape) |
| R-BEFORE-AFTER-REPORT-001.21 | 1, 2, 5, 11, 12 |
| R-BEFORE-AFTER-REPORT-001.22 | 1, 12 |

## 4. Nodes touched (existing tests; every node name stays)

Assertions that change because a row changes (E4 re-pins them, each with its row in the commit message). Every negative on a symbol or file name is re-pinned to **both** spellings, raw and escaped [F-E3-2].

| Node | Line(s) | Change | Row |
|---|---|---|---|
| `tests/test_before_after_report.py::test_at_054b_no_filter_bkey_report_pair_byte_identical_to_golden` | goldens | the two batch35 goldens (`E1-rulings.md` §3) | .32 … .34, .9.1 |
| `tests/test_before_after_report.py::test_tc311_composer_forwards_matcher_filtered_output_both_formats` [F-E3-2] | 999-1001 | loop over both files: Markdown arm `cal-filter\.json`, `CAL\_KEEP`; negative `OTHER_DROP` re-pinned to both spellings (the fifth vacuous site) | .9.1 (O-5 for the filter name) |
| `tests/test_before_after_report.py::test_tc_038_3_ctl_symbol_renders_identically_in_md_and_html_pair` [S-2] | 599 | `CTLSYM` → `CTL�SYM` in both files | .21 (changed) |
| `tests/test_tui_report_filter_surface.py::test_at_054a_bkey_filtered_pair_keeps_match_omits_unmatched` [F-E3-2] | 1073 | Markdown arm `first-byte\.json` | .9.1 (O-5) |
| `tests/test_diff_report_service.py::test_report_sections_present_in_order` | 297-298 | `A\.s19`, `B\.s19` | .9.1 |
| `tests/test_diff_report_service.py::test_symbol_annotation_only_intersecting_run` | 431, 433 [F-E3-2: was 434] | `INSIDE\_SYM`; negative `OUTSIDE_SYM` re-pinned to both spellings | .9.1 |
| `tests/test_diff_report_service.py::test_default_kwargs_output_byte_identical_pre_change_golden` | 690 template | labels escaped | .9.1 |
| `tests/test_diff_report_service.py::test_tc313_no_filter_output_byte_identical_todays` | 690 template | same | .9.1 |
| `tests/test_diff_report_service.py::test_provenance_and_linkage_render_in_both_formats` | 835-836, 846-847 | Markdown spelling `CAL\_SYM`, `A2L\_SYM` (HTML keeps the raw names) | .9.1 |
| `tests/test_diff_report_service.py::test_pipe_bearing_symbol_md_escaped_html_intact` | 913-914 | `EVIL\|SYM\<b\>�END` (U+0001 now `�`) | .9.1, .21 |
| `tests/test_diff_report_service.py::test_tc312_filter_restricts_linkage_and_run_sections_both_formats` | 1264, 1268 | escaped spelling; negative re-pinned to both spellings | .9.1 |
| `tests/test_diff_report_service.py::test_tc312_a9_merged_window_spans_excluded_run` | 1323-1324 | same | .9.1 |
| `tests/test_diff_report_service.py::test_tc312_zero_match_notice_and_refusal_disjoint` | 1347 | negatives re-pinned to both spellings | .9.1 |
| `tests/test_diff_report_service.py::test_tc312_audit_header_first_block_fixed_format` | 1386 | `cal-filter\.json` (O-5) | .9.1 |
| `tests/test_diff_report_service.py::test_tc318_hostile_filter_name_sanitized_md_html` | 1419, 1422 | Markdown `a\|b\`c\<b\>� d\.json`; HTML `a|b`c&lt;b&gt;� d.json` (U+0001 → `�`, CR → space) | .9.1, R-CMP-004.15 |
| `tests/test_tui_report_filter_surface.py::test_at_053b_hostile_valid_filter_proceeds_sanitized_everywhere` | 961-965, 982, 996 | ba-md filter name escaped (O-5); `# Before/after report`; `<h1>Before/after report</h1>` | .32, .34, .9.1 |
| `tests/test_changes_symbol_entries.py::test_tc717_flow_produced_image_diff_references_all_flow_changes` | 1368 | `c2\.json` | .9.1 |
| `tests/test_flow_a2b_b94.py::test_tc_b94_24_a2b_report_states_each_inputs_provenance` | 348-349 | `_TC_B94_24_FLOW_ARM_PASTE`: `patch\.out` | .9.1 |
| `tests/test_b99_staging.py` LLR-155.3 census allow-list (`test_tc_b99_13_no_final_name_replace_outside_placement`) [SR-1, E4 integration; recorded at E5 C-8] | 2165-2174 | adds `_write_report`, `_remove_orphan_markdown`, `_drop_orphan_md` with their reasons; E5 C-1 updates the comment to the random staging name | R-CMP-005.16, .17 |
| `tests/test_diff_report_service.py::test_r_cmp_005_16_3_stale_part_file_is_not_touched` [E5 C-1] | 1816-1836 | `FileExistsError` replaced by: the report is written beside the stale `.part`, which keeps its bytes (design-gap fix, `01-requirements.md` §E5) | R-CMP-005.16 |
| `tests/test_diff_report_service.py::test_r_cmp_004_14_2_html_and_markdown_agree` [E5 C-6] | 1642-1662 | `row[:10]` tightened to `row[:58]` and the whole hex part | R-CMP-004.14 |
| `tests/test_diff_report_service.py::test_r_cmp_005_17_1_ab_html_failure_removes_markdown` [E5 C-7] | 1917-1921 | asserts `reports/` exists before its emptiness | R-CMP-005.17 |
| `tests/test_tui_flow_builder_b94.py::test_at_b94_18_hostile_names_render_literally` [E5 C-5] | 416-425 | adds the flow Image A line (one escape, no double backslash) | R-CMP-004.9.1 |
| `tests/test_before_after_report.py::_drive_bkey_texts` (helper) [E5 C-4] | 1355-1423 | optional `mac_text` (loads a MAC through the app's loader) and the painted log lines and `reports/` listing in its result | .35, .24, R-CMP-005.16, .17 |

Must stay GREEN unchanged (interface guards): `tests/test_before_after_report.py::test_tc311_no_filter_generator_kwargs_shape_is_todays` (D-1, D-2), `::test_tc_038_4_no_project_refusal_names_manual_ab_path` (substring checks, both texts pass), `tests/test_tui_flow_builder_b94.py::test_at_b94_18_hostile_names_render_literally` (one escape, D-6), `::test_at_b94_16_a2b_wiring_rule_and_report_provenance`, `tests/test_tui_report_filter_surface.py` `_strip_ctl` asserts at `:1390-1391` (no U+0001, no LF), `tests/test_b100_busy.py::test_tc_b100_51_diff_report_ends_once_and_logs_its_outcome` (its stubbed `md` path may not exist: the removal uses `missing_ok=True`), `tests/test_render_hexview.py` consumer census (D-4), `tests/test_diff_report_service.py::test_markdown_file_is_complete_no_truncation` and `::test_html_export_complete_and_safe` (0 `TRUNCATED`).

New tests: about 32 functions in `tests/test_diff_report_service.py` and `tests/test_before_after_report.py`, named `test_r_cmp_004_14_…`, `test_r_cmp_004_9_1_…`, `test_r_before_after_report_001_32_…` and so on (the token `trace_check.py` matches); no new file (D-8). The A↔B orphan case (R-CMP-005.17/1) drives `_start_diff_report_worker` through the A2B Diff Report control with `generate_diff_report_html` patched to raise; it lives in `tests/test_diff_report_service.py` beside the other report cases.
