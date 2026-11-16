# Inc 7 — test cases, group G-V (the viewer)

Format: `roles/tester.md` — `<requirement id>/<n> | example id | test name | full or partial`. Example `X<row>.<k>` = item k of the row's Threshold in `01-requirements.md`; the test computes its expected value from committed data (never retyped: tester rule 2). Planned test file: `tests/test_b103_a2l_list_view.py`. Test names are planned names; the tester may rename them, keeping the id in the name. Coverage is the planned mark; E5 re-checks it. Result comes from the run, never from this file.

| Case | Example | Test name | Coverage |
|---|---|---|---|
| R-A2L-LIST.006/1 | X006.1 | `test_r_a2l_list_006_1` | full |
| R-A2L-LIST.006/2 | X006.2 | `test_r_a2l_list_006_2` | full |
| R-A2L-LIST.006/3 | X006.3 | `test_r_a2l_list_006_3` | full |
| R-A2L-LIST.007/1 | X007.1 | `test_r_a2l_list_007_1` | full |
| R-A2L-LIST.008/1 | X008.1 | `test_r_a2l_list_008_1` | full |
| R-A2L-LIST.008/2 | X008.2 | `test_r_a2l_list_008_2` | full |
| R-A2L-LIST.008/3 | X008.3 (E3R1, E3A-08: unload in list mode → `FILTER`, `No A2L tags.`) | `test_r_a2l_list_008_3` | full |
| R-A2L-LIST.009/1 | X009.1 | `test_r_a2l_list_009_1` | full |
| R-A2L-LIST.010/1 | X010.1 | `test_r_a2l_list_010_1` | partial (T7: reads the rendered line of the fixed columns, not every row) |
| R-A2L-LIST.011/1 | X011.1 | `test_r_a2l_list_011_1` | full |
| R-A2L-LIST.011/2 | X011.2 | `test_r_a2l_list_011_2` | full |
| R-A2L-LIST.011/3 | X011.3 | `test_r_a2l_list_011_3` | full |
| R-A2L-LIST.011/4 | X011.4 | `test_r_a2l_list_011_4` | full |
| R-A2L-LIST.012/1 | X012.1 | `test_r_a2l_list_012_1` | full |
| R-A2L-LIST.012/2 | X012.2 | `test_r_a2l_list_012_2` | full |
| R-A2L-LIST.012/3 | X012.3 | `test_r_a2l_list_012_3` | full |
| R-A2L-LIST.012/4 | X012.4 | `test_r_a2l_list_012_4` | full |
| R-A2L-LIST.013/1 | X013.1 | `test_r_a2l_list_013_1` | full |
| R-A2L-LIST.013/2 | X013.2 | `test_r_a2l_list_013_2` | full |
| R-A2L-LIST.013/3 | X013.3 | `test_r_a2l_list_013_3` | full |
| R-A2L-LIST.014/1 | X014.1 | `test_r_a2l_list_014_1` | full |
| R-A2L-LIST.014/2 | X014.2 | `test_r_a2l_list_014_2` | full |
| R-A2L-LIST.014/3 | X014.3 | `test_r_a2l_list_014_3` | full |
| R-A2L-LIST.014/4 | X014.4 | `test_r_a2l_list_014_4` | full |
| R-A2L-LIST.014/5 | X014.5 | `test_r_a2l_list_014_5` | full |
| R-A2L-LIST.014/6 | X014.6 | `test_r_a2l_list_014_6` | full |
| R-A2L-LIST.014/7 | X014.7 | `test_r_a2l_list_014_7` | full |
| R-A2L-LIST.014/8 | X014.8 | `test_r_a2l_list_014_8` | full |
| R-A2L-LIST.014/9 | X014.9 | `test_r_a2l_list_014_9` | full |
| R-A2L-LIST.015/1 | X015.1 | `test_r_a2l_list_015_1` | full |
| R-A2L-LIST.015/2 | X015.2 | `test_r_a2l_list_015_2` | full |
| R-A2L-LIST.016/1 | X016.1 | `test_r_a2l_list_016_1` | full |
| R-A2L-LIST.016/2 | X016.2 | `test_r_a2l_list_016_2` | full |
| R-A2L-LIST.017/1 | X017.1 | `test_r_a2l_list_017_1` | full |
| R-A2L-LIST.017/2 | X017.2 | `test_r_a2l_list_017_2` | full |
| R-A2L-LIST.018/1 | X018.1 | `test_r_a2l_list_018_1` | full |
| R-A2L-LIST.018/2 | X018.2 | `test_r_a2l_list_018_2` | full |
| R-A2L-LIST.019/1 | X019.1 | `test_r_a2l_list_019_1` | full |
| R-A2L-LIST.019/2 | X019.2 | `test_r_a2l_list_019_2` | full |
| R-A2L-LIST.019/3 | X019.3 (E3R1, E3S-02: 300 characters with NUL and TAB, field `unit`) | `test_r_a2l_list_019_3` | full |
| R-A2L-LIST.020/1 | X020.1 | `test_r_a2l_list_020_1` | full |
| R-A2L-LIST.020/2 | X020.2 | `test_r_a2l_list_020_2` | full |
| R-A2L-LIST.021/1 | X021.1 | `test_r_a2l_list_021_1` | full |
| R-A2L-LIST.021/2 | X021.2 | `test_r_a2l_list_021_2` | full |
| R-A2L-LIST.021/3 | X021.3 | `test_r_a2l_list_021_3` | full |
| R-A2L-LIST.022/1 | X022.1 | `test_r_a2l_list_022_1` | full |
| R-A2L-LIST.022/2 | X022.2 | `test_r_a2l_list_022_2` | full |
| R-A2L-LIST.023/1 | X023.1 | `test_r_a2l_list_023_1` | full |
| R-A2L-LIST.023/2 | X023.2 (E3R1, E3A-08: no missing line after an unload) | `test_r_a2l_list_023_2` | full |
| R-A2L-LIST.024/1 | X024.1 | `test_r_a2l_list_024_1` | full |
| R-A2L-LIST.024/2 | X024.2 | `test_r_a2l_list_024_2` | full |
| R-A2L-LIST.025/1 | X025.1 | `test_r_a2l_list_025_1` | full |
| R-A2L-LIST.025/2 | X025.2 | `test_r_a2l_list_025_2` | full |
| R-A2L-LIST.025/3 | X025.3 (E3R1, E3S-02: a fixture tag with a 300-character name holding NUL and ESC; E3R2, E3S-R2: also the kept mode-All summary as a short text) | `test_r_a2l_list_025_3` | full |
| R-A2L-LIST.026/1 | X026.1 | `test_r_a2l_list_026_1` | full |
| R-A2L-LIST.026/2 | X026.2 | `test_r_a2l_list_026_2` | full |
| R-A2L-LIST.027/1 | X027.1 | `test_r_a2l_list_027_1` | full |
| R-A2L-LIST.028/1 | X028.1 | `test_r_a2l_list_028_1` | full |
| R-A2L-LIST.028/2 | X028.2 | `test_r_a2l_list_028_2` | full |
| R-A2L-LIST.029/1 | X029.1 | `test_r_a2l_list_029_1` | full |
| R-A2L-LIST.030/1 | X030.1 | `test_r_a2l_list_030_1` | full |
| R-A2L-LIST.031/1 | X031.1 | `test_r_a2l_list_031_1` | full |
| R-A2L-LIST.031/2 | X031.2 | `test_r_a2l_list_031_2` | full |
| R-A2L-LIST.031/3 | X031.3 | `test_r_a2l_list_031_3` | full |
| R-A2L-LIST.031/4 | X031.4 (E3R1, E3A-13: enter on a missing row → nothing changes) | `test_r_a2l_list_031_4` | full |
| R-A2L-LIST.032/1 | X032.1 | `test_r_a2l_list_032_1` | full |
| R-A2L-LIST.035/1 | X035.1 | `test_r_a2l_list_035_1` | full |
| R-A2L-LIST.036/1 | X036.1 | `test_r_a2l_list_036_1` | full |
| R-A2L-LIST.036/2 | X036.2 | `test_r_a2l_list_036_2` | full |
| R-A2L-LIST.036/3 | X036.3 (E3R1, E3A-07: now with a missing and a duplicate row) | `test_r_a2l_list_036_3` | partial (T7: drives `_refresh_a2l_values_after_write`, not the Save dialog) |
| R-A2L-LIST.036/4 | X036.4 (E3R1, E3A-07: R-A2L-049/1 in list mode, first shown row kept) | `test_r_a2l_list_036_4` | partial (as /3) |
| R-A2L-LIST.036/5 | X036.5 (E3R1, E3A-07: R-A2L-105/1 in list mode, cursor row and card kept) | `test_r_a2l_list_036_5` | partial (as /3) |
| R-A2L-LIST.085/2 | X085.2 (E3R1, E3A-05: the card's closest-names ranking released after teardown, with its positive arm) | `test_r_a2l_list_085_2` | full |
| R-A2L-007.1/1 | X(R-A2L-007.1).1 | `test_r_a2l_007_1_1` | full |
| R-A2L-007.1/2 | X(R-A2L-007.1).2 | `test_r_a2l_007_1_2` | full |
| R-A2L-007.2/1 | X(R-A2L-007.2).1 | `test_r_a2l_007_2_1` | full |
| R-A2L-007.6/1 | X(R-A2L-007.6).1 | `test_r_a2l_007_6_1` | full |
| R-A2L-007.7/1 | X(R-A2L-007.7).1 | `test_r_a2l_007_7_1` | full |
| R-A2L-007.8/1 | X(R-A2L-007.8).1 | `test_r_a2l_007_8_1` | full |
| R-TUI-042a.4/1 | X(R-TUI-042a.4).1 | `test_r_tui_042a_4_1` | full |
| R-TUI-069.6/1 | X(R-TUI-069.6).1 | `test_r_tui_069_6_1` | full |
| R-TUI-069.7/1 | X(R-TUI-069.7).1 (E3R1, E3A-11: wide body) | `test_r_tui_069_7_1` | full |
| R-TUI-069.7/2 | X(R-TUI-069.7).2 (E3R1, E3A-11: stacked body) | `test_r_tui_069_7_2` | full |
| R-TUI-069.7/3 | X(R-TUI-069.7).3 (E3R1, E3A-11: short body) | `test_r_tui_069_7_3` | full |
| R-TUI-037.1/1 | X(R-TUI-037.1).1 (E3R1, E3A-10: 80×24) | `test_r_tui_037_1_1` | full |
| R-TUI-037.1/2 | X(R-TUI-037.1).2 (E3R1, E3A-10: 120×30) | `test_r_tui_037_1_2` | full |
| R-TUI-037.1/3 | X(R-TUI-037.1).3 (E3R1, E3A-10: 160×40) | `test_r_tui_037_1_3` | full |
| R-TUI-037.2/1 | X(R-TUI-037.2).1 (E3R1, E3A-10: 80×24) | `test_r_tui_037_2_1` | full |
| R-TUI-037.2/2 | X(R-TUI-037.2).2 (E3R1, E3A-10: 120×30) | `test_r_tui_037_2_2` | full |
| R-TUI-037.2/3 | X(R-TUI-037.2).3 (E3R1, E3A-10: 160×40) | `test_r_tui_037_2_3` | full |
| R-A2L-LIST.040/1 | X040.1 | `test_r_a2l_list_040_1` | full |
| R-A2L-LIST.040/2 | X040.2 | `test_r_a2l_list_040_2` | full |
| R-A2L-LIST.041/1 | X041.1 | `test_r_a2l_list_041_1` | full |
| R-A2L-LIST.041/2 | X041.2 | `test_r_a2l_list_041_2` | full |
| R-A2L-LIST.053/1 | X053.1 | `test_r_a2l_list_053_1` | full |
| R-A2L-LIST.053/2 | X053.2 | `test_r_a2l_list_053_2` | full |
| R-A2L-LIST.054/1 | X054.1 | `test_r_a2l_list_054_1` | full |
| R-A2L-LIST.055/1 | X055.1 | `test_r_a2l_list_055_1` | full |
| R-A2L-LIST.055/2 | X055.2 | `test_r_a2l_list_055_2` | full |
| R-A2L-LIST.056/1 | X056.1 | `test_r_a2l_list_056_1` | partial (T7: a cloned MEASUREMENT block named `MAP_0024`) |
| R-A2L-LIST.060/1 | X060.1 | `test_r_a2l_list_060_1` | full |
| R-A2L-LIST.060/2 | X060.2 | `test_r_a2l_list_060_2` | full |
| R-A2L-LIST.060/3 | X060.3 | `test_r_a2l_list_060_3` | full |
| R-A2L-LIST.062/1 | X062.1 | `test_r_a2l_list_062_1` | full |
| R-A2L-LIST.062/2 | X062.2 | `test_r_a2l_list_062_2` | full |
| R-A2L-LIST.072/1 | X072.1 | `test_r_a2l_list_072_1` | full |
| R-A2L-LIST.072/2 | X072.2 | `test_r_a2l_list_072_2` | full |
| R-A2L-LIST.074/1 | X074.1 | `test_r_a2l_list_074_1` | full |
| R-A2L-LIST.080/1 | X080.1 | `test_r_a2l_list_080_1` | full |
| R-A2L-LIST.080/2 | X080.2 | `test_r_a2l_list_080_2` | full |
| R-A2L-LIST.081/1 | X081.1 | `test_r_a2l_list_081_1` | full |
| R-A2L-LIST.082/1 | X082.1 (E3R1, E3A-10: 120×30, card ≤ 5 lines above the hex view) | `test_r_a2l_list_082_1` | full |
| R-A2L-LIST.082/2 | X082.2 (E3R1, E3A-10: 80×54) | `test_r_a2l_list_082_2` | full |
| R-A2L-LIST.083/1 | X083.1 (E3R1, E3A-10: 120×30 list mode → ≥ 1 table row; measured P4, E3R2) | `test_r_a2l_list_083_1` | full |
| R-A2L-LIST.083/2 | X083.2 (E3R1, E3A-10: 160×40 → ≥ 11 rows; measured P4, E3R2) | `test_r_a2l_list_083_2` | full |
| R-A2L-LIST.083/3 | X083.3 (E3R1, E3A-10: 118×54 → ≥ 11 rows; measured P4, E3R2, was ≥ 10 derived) | `test_r_a2l_list_083_3` | full |

**After E3R1: 116 cases over 54 requirements** (E1: 94 over 48; R-A2L-LIST.085 is shared with G-L, which holds its other five cases). E3R1 added 22: .008/3, .019/3, .023/2, .025/3, .031/4, .036/4–/5, .085/2, R-TUI-069.7/1–/3, R-TUI-037.1/1–/3, R-TUI-037.2/1–/3, .082/1–/2, .083/1–/3, and re-pointed .036/3 (a list with a missing and a duplicate row). The tc019 tests (`tests/test_tui_directionb.py:1373`, `:1415`, `:1451`) stay as they are and keep passing under R-TUI-037.1/.2 as changed: they run at short bodies (`E1-slice.md` §5).

## Folded at E4 (integrator I7)

Every planned name above exists with that name in `tests/test_b103_a2l_list_view.py` (116/116, checked by script against `02-test-cases-T.md`). Rows marked partial were set from T7's hand-back (`E4-test.md` "What this does not prove"). Results: `E4-integration.md`.
