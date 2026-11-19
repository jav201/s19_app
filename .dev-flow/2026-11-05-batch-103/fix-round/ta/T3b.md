# T3b — GAP rows: A2B Diff screen, Workarea Files height, coverage CRC error (DeepSeek v4-pro)

Appended after `frontB/FB-common.md` and `units2/TA2-common.md`. Tree 2a8ab75f. Source: `TA2b-X-rulings.tsv` GAP rows 43-46; NEEDS-RULING test `test_r_crc_preview_coverage_crc_error_after_a_clean_evaluation_is_named` (P-182: "T3 GAP step, candidate R-CRC-DESIGNER-002.5 checked there" — checked: R-CRC-DESIGNER-002.5 is the non-number-field row `Invalid parameters: …`, not this branch, so two new S13 rows); orchestrator decision P-173 (DF-02).

## Files
- By hand: `REQUIREMENTS.md` only.
- By `apply_recite.py` (`../in/T3b-map.tsv`, 6 ADD rows): docstrings of `tests/test_tui_diff_screen.py` (`test_at_b78_16_every_run_reachable_by_mouse`, `test_at_b78_23_no_wrapped_row_in_the_wide_regime`, `test_at_b78_24_no_hex_row_wraps_in_the_fallback_regime`, `test_tc_b78_34_control_rows_are_one_row_at_80x24`), `tests/test_tui_directionb.py::test_ac5_files_list_grows_beyond_legacy_cap`, `tests/test_b101_designer_recompute.py::test_r_crc_preview_coverage_crc_error_after_a_clean_evaluation_is_named`. (`test_at_b78_24` is not a GAP test: it is the narrow-regime verifier of the same no-wrap row, class O today.)
- No product file.

## Rows to write (copy each line verbatim; insert it directly after its anchor line)
- Row 1, after the line starting `| R-DIFF-SCR.2 |` (S14.4, :7952).
- Rows 2 and 3 (in this order), after the line starting `| R-DIFF-SCR.10 |` (S14.5, :7966).
- Row 4, after the line starting `| R-TUI-029.3 |` (S5.6, :2714).
- Rows 5 and 6 (in this order), after the line starting `| R-CRC-PREVIEW-001.12 |` (S13, :7693).
```text
| R-DIFF-SCR.21 | U | The system shall let a mouse click reach every shown run and no header line of the run list. |
| R-DIFF-SCR.22 | While | While the A2B Diff is in the wide or the narrow regime, the system shall show each hex row of a window on one screen line. |
| R-DIFF-SCR.23 | U | The system shall draw row A, row B and the action row of the A2B Diff one terminal row high each. |
| R-TUI-029.8 | While | While a file is loaded, the system shall give the Workarea Files list half of the free height of the Workspace's left pane, at least one row. |
| R-CRC-PREVIEW-001.13 | If | If computing a coverage CRC fails outside the refusal of R-CRC-PREVIEW-001.4, then the system shall show `Cannot preview: <reason>` in the coverage preview. |
| R-CRC-PREVIEW-001.14 | If | If computing a coverage CRC fails, then the system shall show `Cannot compute: <reason>` as line 2 of the coverage window. |
```
Ids free at 2a8ab75f (whole tree, both spellings). Facts behind the texts: run rows are `ListItem`s with class `diff-run-entry`, header/notice rows `diff-run-note` are `disabled` (`s19_app/tui/screens_directionb/ab_diff.py:1013`, `:1049`); the three control rows are `height: 1` (`s19_app/tui/styles.tcss:1294-1298`); the files and sections lists share the left pane 1fr:1fr (`styles.tcss:411-421`); the preview checks the refusal before `crc_error` and the window does not (`s19_app/tui/crc_designer_view.py:1229-1237`, `:1313-1315`).

## Steps (append to `../REPORT.md` after each)
1. Header; tool regression (19 passed); `--collect-only -q tests` -> N0; reverse_trace before.
2. Rows 1-6 into `REQUIREMENTS.md`; lint (`bad: 0`).
3. Script dry run, then `--apply` -> `ADD rows: 6 (applied=6, already=0)`.
4. Run the 6 nodes -> GREEN (they are unchanged except the docstring).
5. Negative controls (own copy each, only the named node[s]):
   - R-DIFF-SCR.21: `ab_diff.py:1013` add a line `disabled=True,` after `classes="diff-run-entry",` -> `test_at_b78_16_every_run_reachable_by_mouse` RED.
   - R-DIFF-SCR.22: `styles.tcss:1599` (`#diff_window_column`) `width: 1fr;` -> `width: 60;` -> `test_at_b78_23_…` and `test_at_b78_24_…` RED (window narrower than the 79-cell row).
   - R-DIFF-SCR.23: `styles.tcss:1298` `height: 1;` -> `height: 2;` -> `test_tc_b78_34_…` RED.
   - R-TUI-029.8: `styles.tcss:420` (`#ws_left #files_list`) `height: 1fr;` -> `height: 8;` -> `test_ac5_files_list_grows_beyond_legacy_cap` RED at 80x50.
   - R-CRC-PREVIEW-001.13: `crc_designer_view.py:1236-1237` delete the two lines `if run.crc_error is not None:` / `return f"Cannot preview: {run.crc_error}"` -> the CRC test RED (`TypeError` or wrong text).
   - R-CRC-PREVIEW-001.14: `crc_designer_view.py:1314` `"Cannot compute: "` -> `"Cannot preview: "` -> the CRC test RED on the window assert.
6. After: `--collect-only` = N0; reverse_trace after: `X 264`, `U 1`, `O 1559`; none of the 6 tests in class X, U or O. End per TA2-common.

## For the checker
Laws on the unit tree: no new RED. Planted control: R-DIFF-SCR.22 form changed to `U` on a copy -> `test_canon_rows_open_with_their_form` RED naming it. Diff: 6 row lines and 6 `Traces:` lines only.
