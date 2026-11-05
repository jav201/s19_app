# Inc 7 — E4 implementer notes

Source files edited: 4 (the cap). No test, registry or requirements file touched. Nothing committed.

## Functions changed (file: function)
- diff_report_service.py: NEW `_md_text`, `_md_path`, `_run_symbol_names`, `_write_report`; CHANGED `_strip_ctl` (= `_normalise(str(v))`, private import, docstring note), `_annotate_run`, `_window_rows` (own rows, no cap, empty range yields no rows), `_image_line`, `_header_lines(title)`, `_run_table_lines`, `_provenance_lines`, `_linkage_table_lines`, `_flow_change_attribution_lines` (message limit 500), `flow_change_census_complete`, `_audit_header_lines`, `_html_header(title)`, `_html_run_rows`, `generate_diff_report`, `generate_diff_report_html`. Imports: +os, +`_normalise`, `md_code`, `REPORT_CELL_CHARS`; -`MAX_HEX_ROWS`, `render_hex_view`.
- before_after_service.py: CHANGED `compose_before_after_report` (3 kwargs, compare gets a2l_data/mac_records, `(key 7)` text, orphan .md removal); NEW private helper `_remove_orphan_markdown`.
- app.py: CHANGED `action_before_after_report` (gather a2l_data / a2l_records / mac_records on UI thread, mac None when mac_path is None), `_start_before_after_worker` (3 kw params, forwarded), `_start_diff_report_worker` (md path tracked after `md.written`; removed on HTML exception or refusal; OSError logged at WARNING with type only).
- flow_execution_service.py: CHANGED `run_flow` A2B external arm (raw `path.stem`, `str(path)`; comment updated). `md_safe`/`md_code` imports still used elsewhere.

## Deviations
- One helper not in the graph: `_remove_orphan_markdown` in before_after_service (de-duplicates the two removal arms). Same behaviour as G2 node. Not a test-imported name.
- In `_write_report`, the exclusive open happens before the try (N-1): a pre-existing `.part` is never unlinked.
- Local names in `action_before_after_report` are `report_a2l_data/records/mac_records` to avoid clashing with the filter branch's own `mac_records`.
- A-8 grep (no in-place mutation of mac_records / enriched tags / current_a2l_data) not repeated by E4-impl; owed to tester/E4 close.

## Smoke (evidence/inc-7/impl-smoke.txt)
`import s19_app.tui.app` ok, package from this worktree. 9 existing files: 19 failed, 397 passed, 1 skipped.
- Expected (design changes the pin): the 17 E1-slice §4 nodes (diff_report_service x10, before_after_report x3 incl. goldens, filter_surface 053b/054a, changes_symbol_entries TC-717, flow_a2b_b94 TB94-24) plus `test_at_056a_dropdown_selection_filters_both_triggers` (not listed in §4: asserts `only-first.json` in the Markdown header; now `only-first\.json`, O-5 consequence — tester should re-pin).
- Pre-existing, unrelated: `test_at_056e_a2b_diff_report_byte_identical_despite_selection` fails identically on unmodified HEAD (checked in a temp worktree, removed).
- Not run: ~4 MiB worst case measurement (A-6), reader-level census, differential hex test: tester/E4 close.
