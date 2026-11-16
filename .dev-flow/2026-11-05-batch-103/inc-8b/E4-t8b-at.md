# Inc 8b E4 — AT tester record (`T8b-AT`)

Model claude-sonnet-5-5. Tests tree `b103-inc8b-tests` (base `48af05ff`; no Inc 8b code). Cases: `02-test-cases-AT.md`. Tests: `tests/test_b103_inc8b_at.py` (12 nodes: 10 test functions, AT-9 parametrized over 3 sizes).

## State of evidence

| Item | State |
|---|---|
| RED on base `48af05ff` | executed (transcript below, one complete run): 12 of 12 fail, each on an assertion or the base's own crash; none on an import error. |
| GREEN | not-run: the integrator runs it on the implementers' tree. Testers never read that tree. The GREEN path of every node (selectors, geometry reads, the 80×24 layout, the card text after `  ┊ `) is therefore unverified against real new code. |
| Windows-only pilots / real captures | not-run (E5). |

RED reasons: nodes 1, 2, 3, 4, 6, 9 (×3), 10's grid reads fail at `#patch_sheet_grid: expected exactly 1 widget, found 0`; node 5 passes the Tab-ring equality (the base's ring is the constant, by design) and fails on the missing grid; node 7 fails at `(0, [])` (no expanded lines on the base's mask row); node 8 fails at `AssertionError: Pick` (the label is `Pick`, not `▽ Pick`); node 10 fails on a **real base defect**: `WorkerFailed: ValueError('cannot convert float NaN to integer')` raised from the paint path (the E3-8b-04 crash, reachable through the app with the erased-FLOAT32 fixture; the fixture is built by the test from the DEFC files).

## RED transcript (base tree as cwd; one complete run)

Command (from the tree root; `S` = my scratch, env per HT-02/HT-03): `env -i PATH=/usr/bin:/bin HOME=$S/home/<runner-home> XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 PYTHONPATH=. timeout 300 python -m pytest -p no:cacheprovider -n 2 -rA --tb=line tests/test_b103_inc8b_at.py`

```text
cwd=~/work/zq-e4-8b-t8b-at/tree
 00:16:53 up 2 days,  9:05,  3 users,  load average: 3.99, 3.05, 1.43
~/work/zq-e4-8b-t8b-at/tree/s19_app/__init__.py
============================= test session starts ==============================
platform linux -- Python 3.11.18, pytest-8.4.2, pluggy-1.7.0
rootdir: ~/work/zq-e4-8b-t8b-at/tree
configfile: pyproject.toml
plugins: syrupy-4.8.0, xdist-3.8.0, platformdirs-4.14.5, textual-snapshot-1.1.0

2 workers [12 items]

FFFFFFFFFFFF                                                             [100%]
=================================== FAILURES ===================================
~/work/zq-e4-8b-t8b-at/tree/tests/test_b103_inc8b_at.py:236: AssertionError: #patch_sheet_grid: expected exactly 1 widget, found 0
~/work/zq-e4-8b-t8b-at/tree/tests/test_b103_inc8b_at.py:236: AssertionError: #patch_sheet_grid: expected exactly 1 widget, found 0
~/work/zq-e4-8b-t8b-at/tree/tests/test_b103_inc8b_at.py:236: AssertionError: #patch_sheet_grid: expected exactly 1 widget, found 0
~/work/zq-e4-8b-t8b-at/tree/tests/test_b103_inc8b_at.py:236: AssertionError: #patch_sheet_grid: expected exactly 1 widget, found 0
~/work/zq-e4-8b-t8b-at/tree/tests/test_b103_inc8b_at.py:236: AssertionError: #patch_sheet_grid: expected exactly 1 widget, found 0
~/work/zq-e4-8b-t8b-at/tree/tests/test_b103_inc8b_at.py:496: AssertionError: ([], 'control: the scroller exists and its scrollbar is shown for this case')
~/work/zq-e4-8b-t8b-at/tree/tests/test_b103_inc8b_at.py:594: AssertionError: Pick
~/work/zq-e4-8b-t8b-at/tree/tests/test_b103_inc8b_at.py:561: AssertionError: (0, [])
~/work/zq-e4-8b-t8b-at/tree/tests/test_b103_inc8b_at.py:236: AssertionError: #patch_sheet_grid: expected exactly 1 widget, found 0
~/work/zq-e4-8b-t8b-at/tree/tests/test_b103_inc8b_at.py:236: AssertionError: #patch_sheet_grid: expected exactly 1 widget, found 0
~/work/zq-e4-8b-t8b-at/tree/tests/test_b103_inc8b_at.py:236: AssertionError: #patch_sheet_grid: expected exactly 1 widget, found 0
~/miniconda3/envs/s19ci/lib/python3.11/site-packages/textual/app.py:2218: textual.worker.WorkerFailed: Worker raised exception: ValueError('cannot convert float NaN to integer')
=========================== short test summary info ============================
FAILED tests/test_b103_inc8b_at.py::test_at_b103_i8b_3_grid_220x60_has_no_scrollbar_and_end_does_not_move
FAILED tests/test_b103_inc8b_at.py::test_at_b103_i8b_1_grid_118x54_shows_scrollbar_end_goes_to_last_columns_home_back
FAILED tests/test_b103_inc8b_at.py::test_at_b103_i8b_4_home_end_in_the_formula_input_move_its_cursor_not_the_grid
FAILED tests/test_b103_inc8b_at.py::test_at_b103_i8b_2_grid_80x24_shows_scrollbar_and_end_goes_to_last_columns
FAILED tests/test_b103_inc8b_at.py::test_at_b103_i8b_6_enum_row_shows_its_card_and_left_right_choose_without_scrolling
FAILED tests/test_b103_inc8b_at.py::test_at_b103_i8b_5_scrollbar_adds_no_tab_stop_and_the_grid_never_holds_the_focus
FAILED tests/test_b103_inc8b_at.py::test_at_b103_i8b_8_include_parameter_control_shows_the_filter_icon
FAILED tests/test_b103_inc8b_at.py::test_at_b103_i8b_7_mask_field_row_shows_the_bit_card
FAILED tests/test_b103_inc8b_at.py::test_at_b103_i8b_9_formula_bar_stays_inside_the_sheet_window_and_the_long_refusal_ends_in_an_ellipsis[80x24]
FAILED tests/test_b103_inc8b_at.py::test_at_b103_i8b_9_formula_bar_stays_inside_the_sheet_window_and_the_long_refusal_ends_in_an_ellipsis[220x60]
FAILED tests/test_b103_inc8b_at.py::test_at_b103_i8b_9_formula_bar_stays_inside_the_sheet_window_and_the_long_refusal_ends_in_an_ellipsis[118x54]
FAILED tests/test_b103_inc8b_at.py::test_at_b103_i8b_10_a_nan_current_value_paints_the_no_position_limits_cell_and_does_not_crash
============================= 12 failed in 46.68s ==============================
```

Host load is on the second line of the transcript (4.0 at start); no timing node here.

## trace_check (from the repository root)

`python <skill>/trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-8b/01-requirements.md --tests tests --ids R-PE-DEF.33 R-PE-DEF.92 R-PE-DEF.93 R-PE-DEF.94 R-PE-DEF.95 R-PE-DEF.108 R-PE-DEF.113 R-PE-DEF.114`

```text
trace_check: 8 active requirements match --ids, checks run: CASE, TEST, 0 gap(s)
```

## Deviations, findings, gaps

- The brief's "↑/→ on an enum row" etc. map to nodes 6 and 4; the card (R-PE-DEF.108) is checked line by line against `E.card.ENUM_0001.line0..3`; the mask card only on its image-independent lines (title, mask row, bars) because the before/after bytes of the examples (`1A E7`) are the examples' own hand image, not proven to equal the DEFC image.
- `BASE_TAB_ORDER` (31 ids) is a constant captured from this tree's base run; it is the only retyped list and its provenance is the base.
- The seven filter-row controls (R-PE-DEF.113/2) are taken as filter, status, page prev / label / next, include, bulk (the existing R-PICKER-CORRECT.020 selectors); the requirement does not enumerate them: ask `qa-reviewer` if another set was meant.
- Finding for the requirement owner: R-PE-DEF.92/1 and the examples fix V = 111 at 118 columns in "the sheet window"; node 1 asserts the pilot's own view equals `G.view.118cols`, which E5 should confirm in a real terminal. If the pilot's app chrome yields another view width, the node is the first to show it.
- Not run here: GREEN, 80×24 layout on new code, Windows captures. Scratch on the runner is removed at the end.
