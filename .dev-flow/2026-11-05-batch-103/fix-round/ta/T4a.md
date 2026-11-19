# T4a — design-guard rows: headless modules, render layering, batch-92 surfaces, docstrings (DeepSeek v4-pro)

Appended after `frontB/FB-common.md` and `units2/TA2-common.md`. Tree 2a8ab75f. Source: `TA2b-X-rulings.tsv` KEEP-NEWREQ group DESIGN (rows 6-8, 11-15, 47, 48, 50); orchestrator decision P-173 "T4 one S0/R-TST process row per guard class" (DF-02). The rows go to S0 in the families S0 already has (`R-DOC-ARCH` architecture map, `R-DOC-DEV` developer documents); the import rules and surfaces they name are the ones `docs/architecture.md` §10/§11 declares (`docs/architecture.md:237-240`; canon CTX-SUBMOD, CTX-IFACE).

## Files
- By hand: `REQUIREMENTS.md` only.
- By `apply_recite.py` (`../in/T4a-map.tsv`, 11 ADD rows, 8 files): `tests/test_change_service.py`, `tests/test_checks_engine.py`, `tests/test_compare_service.py`, `tests/test_tui_manifest_save.py`, `tests/test_render_hexview.py` (2 tests), `tests/test_import_census.py` (2), `tests/test_render_format.py`, `tests/test_tui_helpers.py` (2). Docstrings only.
- No product file.

## Rows to write
Block A, inserted directly after the line starting `| R-DOC-ARCH.6 |` (S0.9, :495): one empty line, the lead line, one empty line, the table.
```text

**(from the batch-103 trace audit, TR-02)** Import rules and surfaces the code keeps; their tests were guards with no row.

| Id | Form | Requirement |
|---|---|---|
| R-DOC-ARCH.7 | U | The system shall import no Textual module into a headless module: `s19_app/tui/changes/check.py`, `s19_app/tui/services/change_service.py`, `s19_app/tui/services/compare_service.py`, `s19_app/tui/services/manifest_writer.py` and every `s19_app` module that the first two import, directly or indirectly. |
| R-DOC-ARCH.8 | U | The system shall import no logging module into `s19_app/tui/services/manifest_writer.py`. |
| R-DOC-ARCH.9 | U | The system shall import no `s19_app.tui` module into a module of `s19_app/render`. |
| R-DOC-ARCH.10 | U | The system shall implement the four batch-92 surfaces of CTX-IFACE (`render.hexview`, `render.format`, `utils.safe_text` and the `tui/__init__` re-export) as the Interfaces table of `docs/architecture.md` states them. |
```
Block B, inserted directly after the line starting `| R-DOC-DEV.15 |` (S0.8, :484), same shape:
```text

**(from the batch-103 trace audit, TR-02)** The TUI's entry points carry docstrings (S0 D0-3 kept these checks without a row).

| Id | Form | Requirement |
|---|---|---|
| R-DOC-DEV.16 | U | The system shall carry a docstring on the `s19_app.tui` package and on the class `S19TuiApp`. |
```
Ids free at 2a8ab75f. Map: `R-DOC-ARCH.7` <- the 4 headless tests; `R-DOC-ARCH.8` <- `test_manifest_writer_module_is_headless`; `R-DOC-ARCH.9` and `.10` <- `test_tc651_…`; `.10` <- `test_tc652_…`, `test_tc653_…`, `test_tc654_…`, `test_tc655_…`; `R-DOC-DEV.16` <- the 2 docstring tests.

## Steps (append to `../REPORT.md` after each)
1. Header; tool regression (19 passed); N0; reverse_trace before.
2. Blocks A and B into `REQUIREMENTS.md`; lint the 5 rows (`bad: 0`); the file still has exactly one `#### S0.9 ` and one `#### S0.10 ` heading.
3. Script dry run, then `--apply` -> `ADD rows: 11 (applied=11, already=0)`, 8 files.
4. Run the 11 nodes -> GREEN.
5. Negative controls (own copy each):
   - R-DOC-ARCH.7: insert `import textual  # NC` as a new line after `s19_app/tui/services/compare_service.py:27` -> `tests/test_compare_service.py::test_module_imports_no_textual` RED.
   - R-DOC-ARCH.8: insert `import logging  # NC` after `s19_app/tui/services/manifest_writer.py:44` -> `test_manifest_writer_module_is_headless` RED.
   - R-DOC-ARCH.9: append at the end of `s19_app/render/format.py` the two lines `def _nc_probe():` / `    import s19_app.tui.models  # NC` -> `test_tc651_import_census_all_consumers_read_render_hexview` RED with `render/ must be tui-free`.
   - R-DOC-ARCH.10: `s19_app/render/format.py:20` `CYAN = "#7dd3fc"` -> `CYAN = "#7dd3fd"` -> `test_tc655_render_format_values_pinned_to_frozen_origins` RED.
   - R-DOC-DEV.16: delete the class docstring line `s19_app/tui/app/core.py:145` -> `test_tui_app_has_docstring` RED.
6. After: N0 unchanged; reverse_trace after: `X 257`, `U 2`; none of the 11 tests in class X. End per TA2-common.

## For the checker
Laws on the unit tree: no new RED (R-DOC-CANON.6: rows still under S0; R-DOC-CANON.5: no duplicate id). Planted control: on a copy, rename `R-DOC-ARCH.10` to `R-DOC-ARCH.6` -> `test_canon_row_ids_are_unique` RED naming it. Diff: 2 blocks and 11 `Traces:` lines only.
