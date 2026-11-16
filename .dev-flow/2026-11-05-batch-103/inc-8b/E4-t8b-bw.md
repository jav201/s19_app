# E4 T8b-BW hand-back (tester; evidence authored, nothing approved)

Test file: `tests/test_b103_inc8b_bw.py` (30 nodes). Base for RED: `48af05ff` (product tree = HEAD of `b103-inc8b-tests`, product untouched). State: RED `executed` on rtx; GREEN `not-run` (the integrator's).

## Coverage (case -> test)
| Case | Test | Full/partial |
|---|---|---|
| R-PE-BENCH.11/1-3 | test_r_pe_bench_11_the_strip_and_its_count_use_seven_levels[1..3] | full |
| R-PE-BENCH.107/1, /2 | test_r_pe_bench_107_1_..., test_r_pe_bench_107_2_... | full |
| R-PE-BENCH.107/3 | none: E5 real capture (`f_r14_1_probe.py`) | UNCOVERED at E4 |
| R-PE-BENCH.108/1, /2 | test_r_pe_bench_108_1_..., test_r_pe_bench_108_2_... (selected, zebra, even control) | full |
| R-PE-BENCH.17/1-3 | test_r_pe_bench_17_the_limits_cell_is_the_range_form[1..3], test_r_pe_bench_17_3_... | full |
| R-PE-DEF.101 (rule statement, group B) | test_r_pe_def_101_the_hue_rule_is_stated_... | partial (reads the comment; behaviour 101/1-4 is group S) |
| R-PE-DEF.92/1-2, .93/1 | test_r_pe_def_92_93_the_scrollbar_shows_only_when_... [3 params] (real Patch Editor; also G.end 32/70/0) | full |
| R-PE-DEF.92/3 + scroller class (E3-8b-03) | test_r_pe_def_92_3_..., test_r_pe_def_92_scroller_is_a_plain_container_... | partial (no base Tab list to compare) |
| R-PE-DEF.81/5 | test_r_pe_def_81_5_the_body_fills_... (host without body CSS) | full |
| R-PE-DEF.81/6 (E3-8b-11) | test_r_pe_def_81_6_a_resize_that_only_widens_... | full |
| R-PE-BENCH.36/4, /5 | test_r_pe_bench_36_4_..., test_r_pe_bench_36_5_... (right/down) | /4 full; /5 deviates, see findings |
| R-PE-DEF.113/1, /2 | test_r_pe_def_113_1_..., test_r_pe_def_113_2_... | full |
| R-PE-DEF.85/1 | test_r_pe_def_85_1_the_help_line_names_the_scroll_keys | full |
| R-PE-BENCH.5/1-5 | none here: covered by T8b-S2 (`tests/test_b103_inc8b_s2.py`, 62c3b53a) per orchestrator | n/a |
| Not mine: R-PE-DEF.81/1-4, .94, .95, .33/3 | T8b-R / T8b-AT | - |

`trace_check` (repo root, ids R-PE-BENCH.11/.17/.107/.108/.36, R-PE-DEF.92/.93/.81/.101/.113/.85): `trace_check: 11 active requirements match --ids, checks run: CASE, TEST, 0 gap(s)`.

## RED transcript on base 48af05ff (one complete run)
Command (rtx, tree = base archive + this file, env per HT-02, `-n 2`, timeout 600): `pytest -p no:cacheprovider -n 2 tests/test_b103_inc8b_bw.py -q -rA --tb=line`.
Package: `<runner-home>/work/zq-e4-8b-t8b-bw/tree/s19_app/__init__.py`; load average 4.14, 2.05, 0.85.
Result: `25 failed, 5 passed in 44.27s`. Failures are assertions except `test_r_pe_bench_108_2_..[zebra]` (`TypeError: row_line() got an unexpected keyword argument 'odd'`: new keyword, recorded as absent). Key lines:
```
11 curve:   assert '▅▇▄█▁' == '▄▆▃▇▁'   11 map: assert '████' == '▆▃▅▃'   11 valblk: assert '███' == '▄▃▄'
107/2:      assert '▁▂▂▃▃▄▄▅▅▆▆▇▇█' == '▁▁▂▂▃▃▄▄▅▅▆▆▇▇'
108/1 map:  ('MAP_DEF_0001', 0, '#101828', '#869fdc')   (ramp ground, not none)
17/1:       assert '0 … 65.5k' == '     0      ...        65.5k'     17/3: assert 0 == 16
101:        ('✓', 'is not in the verdict-hue comment')
92/93 x3 and class test: the sheet holds 0 #patch_sheet_grid widgets
81/5:       body height 53 (expected 52)
81/6:       no line after the selected row carries the bar '  ┊ '
113/1:      AssertionError: Pick           85/1: ('home', '↑↓ select a row, ...')
```
PASSED on base (guards, not RED): 36/4 right and down, 36/5 right and down, 113/2.

## Findings / gaps
- R-PE-BENCH.36/4, /5 hold on base: the defect needs W2 (body 143 wide) with the old `_bench_geometry`, a state absent on base. No RED captured; they guard the combination at GREEN.
- R-PE-BENCH.36/5 text says "cursor right" at V=111, but LARGE has 16 columns and all 16 show, so no column lies past the last; I exercise `down` (first row +1) and keep `right` as "cursor stays painted". The case text should say "down" at 118 (cases file not mine).
- R-PE-DEF.81/5 asserts painted lines - 2 == visible (50); the integrator should check this at GREEN.
- R-PE-DEF.92/3 compares the Tab ring to the rule, not to a base list (partial).
- R-PE-BENCH.107/3 (real capture) uncovered at E4.
- Bench window tests use a 70,000-element stand-in (16 columns, thousands of rows), not 1,048,576.
- `_GridHost` subclasses `SheetApp` from `tests/support/b103_inc8_s2.py` (T8b-R may retarget it); it overrides CSS to `StagingSheet {height:1fr;width:1fr}` only.
- No timing node.
