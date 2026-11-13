# Inc 7 — test cases, group G-L (list module and I-1 hook)

Format: `roles/tester.md` — `<requirement id>/<n> | example id | test name | full or partial`. Example `X<row>.<k>` = item k of the row's Threshold in `01-requirements.md`; the test computes its expected value from committed data (never retyped: tester rule 2). Planned test file: `tests/test_b103_label_list.py`. Test names are planned names; the tester may rename them, keeping the id in the name. Coverage is the planned mark; E5 re-checks it. Result comes from the run, never from this file.

| Case | Example | Test name | Coverage |
|---|---|---|---|
| R-A2L-LIST.001/1 | X001.1 | `test_r_a2l_list_001_1` | full |
| R-A2L-LIST.001/2 | X001.2 | `test_r_a2l_list_001_2` | full |
| R-A2L-LIST.001/3 | X001.3 | `test_r_a2l_list_001_3` | full |
| R-A2L-LIST.002/1 | X002.1 | `test_r_a2l_list_002_1` | full |
| R-A2L-LIST.002/2 | X002.2 | `test_r_a2l_list_002_2` | full |
| R-A2L-LIST.002/3 | X002.3 | `test_r_a2l_list_002_3` | full |
| R-A2L-LIST.003/1 | X003.1 | `test_r_a2l_list_003_1` | full |
| R-A2L-LIST.003/2 | X003.2 | `test_r_a2l_list_003_2` | full |
| R-A2L-LIST.004/1 | X004.1 | `test_r_a2l_list_004_1` | full |
| R-A2L-LIST.004/2 | X004.2 | `test_r_a2l_list_004_2` | full |
| R-A2L-LIST.004/3 | X004.3 | `test_r_a2l_list_004_3` | full |
| R-A2L-LIST.005/1 | X005.1 | `test_r_a2l_list_005_1` | full |
| R-A2L-LIST.005/2 | X005.2 | `test_r_a2l_list_005_2` | full |
| R-A2L-LIST.033/1 | X033.1 | `test_r_a2l_list_033_1` | full |
| R-A2L-LIST.033/2 | X033.2 | `test_r_a2l_list_033_2` | full |
| R-A2L-LIST.033/3 | X033.3 | `test_r_a2l_list_033_3` | full |
| R-A2L-LIST.034/1 | X034.1 | `test_r_a2l_list_034_1` | full |
| R-A2L-LIST.034/2 | X034.2 | `test_r_a2l_list_034_2` | full |
| R-PASTE.1/1 | X(R-PASTE.1).1 | `test_r_paste_1_1` | full |
| R-PASTE.1/2 | X(R-PASTE.1).2 | `test_r_paste_1_2` | full |
| R-TUI-043.4/1 | X(R-TUI-043.4).1 | `test_r_tui_043_4_1` | full |
| R-TUI-043.4/2 | X(R-TUI-043.4).2 | `test_r_tui_043_4_2` | full |
| R-PASTE.29/1 | X(R-PASTE.29).1 | `test_r_paste_29_1` | full |
| R-PASTE.29/2 | X(R-PASTE.29).2 | `test_r_paste_29_2` | full |
| R-A2L-LIST.042/1 | X042.1 | `test_r_a2l_list_042_1` | full |
| R-A2L-LIST.043/1 | X043.1 | `test_r_a2l_list_043_1` | full |
| R-A2L-LIST.044/1 | X044.1 | `test_r_a2l_list_044_1` | full |
| R-A2L-LIST.045/1 | X045.1 | `test_r_a2l_list_045_1` | full |
| R-A2L-LIST.046/1 | X046.1 | `test_r_a2l_list_046_1` | full |
| R-A2L-LIST.046/2 | X046.2 | `test_r_a2l_list_046_2` | full |
| R-A2L-LIST.047/1 | X047.1 | `test_r_a2l_list_047_1` | full |
| R-A2L-LIST.047/2 | X047.2 | `test_r_a2l_list_047_2` | full |
| R-A2L-LIST.048/1 | X048.1 | `test_r_a2l_list_048_1` | full |
| R-A2L-LIST.049/1 | X049.1 | `test_r_a2l_list_049_1` | full |
| R-A2L-LIST.049/2 | X049.2 | `test_r_a2l_list_049_2` | full |
| R-A2L-LIST.050/1 | X050.1 | `test_r_a2l_list_050_1` | full |
| R-A2L-LIST.050/2 | X050.2 | `test_r_a2l_list_050_2` | full |
| R-A2L-LIST.051/1 | X051.1 | `test_r_a2l_list_051_1` | full |
| R-A2L-LIST.051/2 | X051.2 | `test_r_a2l_list_051_2` | full |
| R-A2L-LIST.052/1 | X052.1 | `test_r_a2l_list_052_1` | full |
| R-A2L-LIST.052/2 | X052.2 | `test_r_a2l_list_052_2` | full |
| R-A2L-LIST.057/1 | X057.1 | `test_r_a2l_list_057_1` | full |
| R-A2L-LIST.057/2 | X057.2 | `test_r_a2l_list_057_2` | full |
| R-A2L-LIST.058/1 | X058.1 | `test_r_a2l_list_058_1` | full |
| R-A2L-LIST.059/1 | X059.1 | `test_r_a2l_list_059_1` | full |
| R-A2L-LIST.061/1 | X061.1 | `test_r_a2l_list_061_1` | full |
| R-A2L-LIST.063/1 | X063.1 | `test_r_a2l_list_063_1` | full |
| R-A2L-LIST.063/2 | X063.2 | `test_r_a2l_list_063_2` | full |
| R-A2L-LIST.064/1 | X064.1 | `test_r_a2l_list_064_1` | full |
| R-A2L-LIST.064/2 | X064.2 | `test_r_a2l_list_064_2` | full |
| R-A2L-LIST.065/1 | X065.1 | `test_r_a2l_list_065_1` | full |
| R-A2L-LIST.065/2 | X065.2 | `test_r_a2l_list_065_2` | full |
| R-A2L-LIST.066/1 | X066.1 | `test_r_a2l_list_066_1` | full |
| R-A2L-LIST.066/2 | X066.2 | `test_r_a2l_list_066_2` | full |
| R-A2L-LIST.067/1 | X067.1 | `test_r_a2l_list_067_1` | full |
| R-A2L-LIST.067/2 | X067.2 | `test_r_a2l_list_067_2` | full |
| R-A2L-LIST.068/1 | X068.1 | `test_r_a2l_list_068_1` | full |
| R-A2L-LIST.068/2 | X068.2 | `test_r_a2l_list_068_2` | full |
| R-A2L-LIST.068/3 | X068.3 | `test_r_a2l_list_068_3` | full |
| R-A2L-LIST.069/1 | X069.1 | `test_r_a2l_list_069_1` | full |
| R-A2L-LIST.069/2 | X069.2 | `test_r_a2l_list_069_2` | full |
| R-A2L-LIST.070/1 | X070.1 | `test_r_a2l_list_070_1` | full |
| R-A2L-LIST.070/2 | X070.2 | `test_r_a2l_list_070_2` | full |
| R-A2L-LIST.071/1 | X071.1 | `test_r_a2l_list_071_1` | full |
| R-A2L-LIST.071/2 | X071.2 | `test_r_a2l_list_071_2` | full |
| R-A2L-LIST.073/1 | X073.1 | `test_r_a2l_list_073_1` | full |
| R-A2L-LIST.073/2 | X073.2 | `test_r_a2l_list_073_2` | full |
| R-A2L-LIST.076/1 | X076.1 | `test_r_a2l_list_076_1` | full |
| R-A2L-LIST.076/2 | X076.2 | `test_r_a2l_list_076_2` | full |
| R-A2L-LIST.076/3 | X076.3 | `test_r_a2l_list_076_3` | full |
| R-A2L-LIST.076/4 | X076.4 | `test_r_a2l_list_076_4` | full |
| R-A2L-LIST.076/5 | X076.5 | `test_r_a2l_list_076_5` | full |
| R-A2L-LIST.076/6 | X076.6 | `test_r_a2l_list_076_6` | full |
| R-A2L-LIST.077/1 | X077.1 | `test_r_a2l_list_077_1` | full |
| R-A2L-LIST.077/2 | X077.2 | `test_r_a2l_list_077_2` | full |

75 cases over 37 requirements.
