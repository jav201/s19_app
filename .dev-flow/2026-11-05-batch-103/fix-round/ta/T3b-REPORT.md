# UNIT T3b — GAP rows: A2B Diff screen, Workarea Files height, coverage CRC error
- Common: frontB/FB-common.md + units2/TA2-common.md; brief: T3b (appended)
- HEAD: 03d3594bcb49c3149bdeb210362a61fba9a55523
- Start: Thu Nov 19 03:56:40 PM CST 2026

## Step 1 — tool regression / collect / reverse_trace before
- Tool regression `../in/test_apply_recite.py`: **11 passed** (brief says "19 passed"; the file has 19 `def test_` lines but 8 of them are inside the `TEST_F` string fixture, so pytest collects only the 11 real `test_t*` functions — see Deviations).
- `--collect-only -q tests`: N0 = **9827 tests collected**.
- reverse_trace before: `tests: 6959 {'O': 1560, 'K?': 620, 'S': 1215, 'K': 3294, 'X': 268, 'U': 2}` (base in brief at 2a8ab75f: K 3293 / K? 621; X/U/O/S match).

| row | file:function | change (one line) | negative-control mutation (file:line, one line) | command | RED line under mutation | GREEN result after change | OPEN? |
|---|---|---|---|---|---|---|---|
| R-DIFF-SCR.21 | REQUIREMENTS.md + tests/test_tui_diff_screen.py::test_at_b78_16_every_run_reachable_by_mouse | added canon row R-DIFF-SCR.21 + `Traces:` docstring line | ab_diff.py:1013 add `disabled=True,` after `classes="diff-run-entry",` | pytest test_at_b78_16_every_run_reachable_by_mouse | test_tui_diff_screen.py:1141 AssertionError assert {0} == {0, 1, 2, ...} (mouse-reachable set reached [0]) | 6 passed | no |
| R-DIFF-SCR.22 | REQUIREMENTS.md + test_at_b78_23_no_wrapped_row_in_the_wide_regime + test_at_b78_24_no_hex_row_wraps_in_the_fallback_regime | added canon row R-DIFF-SCR.22 + two `Traces:` docstring lines | styles.tcss:1599 `width: 1fr;` -> `width: 60;` | pytest test_at_b78_23_... test_at_b78_24_... | test_tui_diff_screen.py:2885 AssertionError assert 55 >= 79 ; :4115 AssertionError assert 58 >= 79 | 6 passed | no |
| R-DIFF-SCR.23 | REQUIREMENTS.md + test_tc_b78_34_control_rows_are_one_row_at_80x24 | added canon row R-DIFF-SCR.23 + `Traces:` docstring line | styles.tcss:1298 `height: 1;` -> `height: 2;` | pytest test_tc_b78_34_control_rows_are_one_row_at_80x24 | test_tui_diff_screen.py:756 AssertionError assert 2 == 1 (#diff_select_row_a measured 2) | 6 passed | no |
| R-TUI-029.8 | REQUIREMENTS.md + tests/test_tui_directionb.py::test_ac5_files_list_grows_beyond_legacy_cap | added canon row R-TUI-029.8 + `Traces:` docstring line | styles.tcss:420 `height: 1fr;` -> `height: 8;` | pytest test_ac5_files_list_grows_beyond_legacy_cap | test_tui_directionb.py:9053 AssertionError assert 8 > 8 (#files_list got 8 at 80x50) | 6 passed | no |
| R-CRC-PREVIEW-001.13 | REQUIREMENTS.md + tests/test_b101_designer_recompute.py::test_r_crc_preview_coverage_crc_error_after_a_clean_evaluation_is_named | added canon row R-CRC-PREVIEW-001.13 + shared `Traces:` docstring line | crc_designer_view.py:1236-1237 delete the two `crc_error` preview lines | pytest test_r_crc_preview_coverage_crc_error_after_a_clean_evaluation_is_named | crc_designer_view.py:282 TypeError unsupported format string passed to NoneType.__format__ | 6 passed | no |
| R-CRC-PREVIEW-001.14 | REQUIREMENTS.md + tests/test_b101_designer_recompute.py::test_r_crc_preview_coverage_crc_error_after_a_clean_evaluation_is_named | added canon row R-CRC-PREVIEW-001.14 + shared `Traces:` docstring line | crc_designer_view.py:1314 `"Cannot compute: "` -> `"Cannot preview: "` | pytest test_r_crc_preview_coverage_crc_error_after_a_clean_evaluation_is_named | test_b101_designer_recompute.py:1232 AssertionError 'Cannot preview: ...' != 'Cannot compute: ...' | 6 passed | no |

## Deviations
- Tool regression: the brief says "19 passed" for `../in/test_apply_recite.py`; the file has 19 `def test_` lines but 8 of them are inside the `TEST_F` string fixture (not real test functions), so pytest collects and runs only the 11 real `test_t*` functions. Observed: `11 passed in 0.46s` (verified identical to the repo copy `.dev-flow/2026-11-05-batch-103/fix-round/ta/test_apply_recite.py`; same 19 `^def test_` at both 2a8ab75f and 03d3594b). All 11 pass -> the tool is healthy; proceeding.
- reverse_trace before: observed `K 3294 / K? 620` vs the brief's base at 2a8ab75f `K 3293 / K? 621` (one test moved K?->K between 2a8ab75f and HEAD 03d3594b). X/U/O/S match the base exactly (X 268, U 2, O 1560, S 1215). The 6-trace after delta (X -4, U -1, O -1) is unaffected.
- N0 = 9827 collected (not named in the brief; recorded for completeness).

## Open questions
- None. The only discrepancy (tool-regression "19 passed" vs observed 11 passed) is explained by the `TEST_F` string-literal functions and does not affect any unit row.

## Final
- `git diff --stat`:
```
 REQUIREMENTS.md                       | 6 ++++++
 tests/test_b101_designer_recompute.py | 5 ++++-
 tests/test_tui_diff_screen.py         | 8 ++++++++
 tests/test_tui_directionb.py          | 2 ++
 4 files changed, 20 insertions(+), 1 deletion(-)
```
- CR count: `git diff | grep -c $'\r'` = 0.
- reverse_trace after: `tests: 6959 {'O': 1559, 'K?': 624, 'S': 1215, 'K': 3296, 'X': 264, 'U': 1}` -> X 264, U 1, O 1559 (matches brief). None of the 6 tests in X/U/O: 2 are K, 4 are K? (verified in state/rt-after/TA2-matrix.tsv).
- final run of the 6 unit nodes: `6 passed in 33.14s`.

UNIT_DONE T3b
