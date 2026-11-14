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
| R-A2L-LIST.033/4 | X033.4 (E3R1, E3A-12: field `source` → stock first line) | `test_r_a2l_list_033_4` | full |
| R-A2L-LIST.033/5 | X033.5 (E3R1, E3S-05: 32,768 names → 98,302-character value, not cut) | `test_r_a2l_list_033_5` | full |
| R-A2L-LIST.034/3 | X034.3 (E3R1, E3S-03: the hook receives the stripped text) | `test_r_a2l_list_034_3` | full |
| R-PASTE.1/1 | X(R-PASTE.1).1 | `test_r_paste_1_1` | full |
| R-PASTE.1/2 | X(R-PASTE.1).2 | `test_r_paste_1_2` | full |
| R-PASTE.1/3 | X(R-PASTE.1).3 (E3R1, E3A-01 (2): `P_CTRL` into the filter box, terminal route) | `test_r_paste_1_3` | full |
| R-PASTE.1/4 | X(R-PASTE.1).4 (E3R1, E3S-03: a `restrict` box never calls the hook) | `test_r_paste_1_4` | full |
| R-TUI-043.4/1 | X(R-TUI-043.4).1 | `test_r_tui_043_4_1` | full |
| R-TUI-043.4/2 | X(R-TUI-043.4).2 | `test_r_tui_043_4_2` | full |
| R-TUI-043.4/3 | X(R-TUI-043.4).3 (E3R1, E3A-01 (2): `P_CTRL`, Ctrl+V route) | `test_r_tui_043_4_3` | full |
| R-PASTE.29/1 | X(R-PASTE.29).1 | `test_r_paste_29_1` | full |
| R-PASTE.29/2 | X(R-PASTE.29).2 | `test_r_paste_29_2` | full |
| R-PASTE.29/3 | X(R-PASTE.29).3 (E3R1, E3A-01 (2): `P_CTRL`, right-click route) | `test_r_paste_29_3` | full |
| R-A2L-LIST.042/1 | X042.1 | `test_r_a2l_list_042_1` | full |
| R-A2L-LIST.043/1 | X043.1 | `test_r_a2l_list_043_1` | full |
| R-A2L-LIST.044/1 | X044.1 | `test_r_a2l_list_044_1` | full |
| R-A2L-LIST.045/1 | X045.1 | `test_r_a2l_list_045_1` | full |
| R-A2L-LIST.046/1 | X046.1 | `test_r_a2l_list_046_1` | full |
| R-A2L-LIST.046/2 | X046.2 | `test_r_a2l_list_046_2` | full |
| R-A2L-LIST.047/1 | X047.1 | `test_r_a2l_list_047_1` | full |
| R-A2L-LIST.047/2 | X047.2 | `test_r_a2l_list_047_2` | full |
| R-A2L-LIST.047/3 | X047.3 (E3R1, E3A-14: columns fixed at open) | `test_r_a2l_list_047_3` | full |
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
| R-A2L-LIST.078/1 | X078.1 (E3R1, E3S-01: 4,906 names → 200 rows + the more line) | `test_r_a2l_list_078_1` | full |
| R-A2L-LIST.078/2 | X078.2 (E3R1, E3S-01: 32,768 names → 200 rows + the more line) | `test_r_a2l_list_078_2` | full |
| R-A2L-LIST.078/3 | X078.3 (E3R1, E3S-01: one rebuild ≤ 0.25 s; `@pytest.mark.serial_timing`, `uptime` printed) | `test_r_a2l_list_078_3` | full |
| R-A2L-LIST.061/1 | X061.1 | `test_r_a2l_list_061_1` | full |
| R-A2L-LIST.063/1 | X063.1 | `test_r_a2l_list_063_1` | full |
| R-A2L-LIST.063/2 | X063.2 | `test_r_a2l_list_063_2` | full |
| R-A2L-LIST.064/1 | X064.1 | `test_r_a2l_list_064_1` | full |
| R-A2L-LIST.064/2 | X064.2 | `test_r_a2l_list_064_2` | full |
| R-A2L-LIST.065/1 | X065.1 | `test_r_a2l_list_065_1` | full |
| R-A2L-LIST.065/2 | X065.2 | `test_r_a2l_list_065_2` | full |
| R-A2L-LIST.066/1 | X066.1 | `test_r_a2l_list_066_1` | full |
| R-A2L-LIST.066/2 | X066.2 (E3R1: the echo is now the 64-character short text) | `test_r_a2l_list_066_2` | full |
| R-A2L-LIST.066/3 | X066.3 (E3R1, E3S-02: 300 characters with NUL and ESC) | `test_r_a2l_list_066_3` | full |
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
| R-A2L-LIST.075/1 | X075.1 (E3R1, E3A-06: held + 5 keystrokes → 2 `rank` calls) | `test_r_a2l_list_075_1` | full |
| R-A2L-LIST.075/2 | X075.2 (E3R1, E3S-04: 11 missing, held, 3 edits → ≤ 2 calls per slot) | `test_r_a2l_list_075_2` | full |
| R-A2L-LIST.084/1 | X084.1 (E3R1, E3A-05: held preparation released after teardown) | `test_r_a2l_list_084_1` | full |
| R-A2L-LIST.084/2 | X084.2 (E3R1, E3A-05: `build_label_index` raising) | `test_r_a2l_list_084_2` | full |
| R-A2L-LIST.084/3 | X084.3 (E3R1, E3A-05: positive arm, released while running) | `test_r_a2l_list_084_3` | full |
| R-A2L-LIST.085/1 | X085.1 (E3R1, E3A-05: filter ranking released after teardown) | `test_r_a2l_list_085_1` | full |
| R-A2L-LIST.085/3 | X085.3 (E3R1, E3A-05: similar ranking released after teardown) | `test_r_a2l_list_085_3` | full |
| R-A2L-LIST.085/4 | X085.4 (E3R1, E3A-05: window dismissed, its ranking released) | `test_r_a2l_list_085_4` | full |
| R-A2L-LIST.085/5 | X085.5 (E3R1, E3A-05: `rank` raising) | `test_r_a2l_list_085_5` | full |
| R-A2L-LIST.085/6 | X085.6 (E3R1, E3A-05: positive arm for the filter box and the similar line) | `test_r_a2l_list_085_6` | full |
| R-A2L-LIST.086/1 | X086.1 (E3R1, E3A-05: preview due after the window closed) | `test_r_a2l_list_086_1` | full |
| R-A2L-LIST.086/2 | X086.2 (E3R1, E3A-05: preview due after teardown) | `test_r_a2l_list_086_2` | full |
| R-A2L-LIST.086/3 | X086.3 (E3R1, E3A-05: positive arm, window open) | `test_r_a2l_list_086_3` | full |
| R-A2L-LIST.087/1 | X087.1 (E3R2, E3A-R4: the build fails once, the next request rebuilds, the dropdown opens) | `test_r_a2l_list_087_1` | full |
| R-A2L-LIST.087/2 | X087.2 (E3R2, E3A-R4: the build always fails → exactly 2 builds) | `test_r_a2l_list_087_2` | full |
| R-A2L-LIST.076/1 | X076.1 | `test_r_a2l_list_076_1` | full |
| R-A2L-LIST.076/2 | X076.2 | `test_r_a2l_list_076_2` | full |
| R-A2L-LIST.076/3 | X076.3 | `test_r_a2l_list_076_3` | full |
| R-A2L-LIST.076/4 | X076.4 | `test_r_a2l_list_076_4` | full |
| R-A2L-LIST.076/5 | X076.5 | `test_r_a2l_list_076_5` | full |
| R-A2L-LIST.076/6 | X076.6 | `test_r_a2l_list_076_6` | full |
| R-A2L-LIST.076/7 | X076.7 (E3R1, E3S-06: U+202E and U+2066 → U+FFFD; E3R2, E3S-R1: also U+200B and U+FEFF) | `test_r_a2l_list_076_7` | full |
| R-A2L-LIST.077/1 | X077.1 | `test_r_a2l_list_077_1` | full |
| R-A2L-LIST.077/2 | X077.2 | `test_r_a2l_list_077_2` | full |
| R-A2L-LIST.077/3 | X077.3 (E3R1, E3S-09: a 1,024-character dropdown row) | `test_r_a2l_list_077_3` | full |
| R-A2L-LIST.077/4 | X077.4 (E3R1, E3S-09: the card's `✗` line of a 300-character missing name) | `test_r_a2l_list_077_4` | full |

**After E3R2: 105 cases over 43 requirements** (E3R2 added .087/1–/2 and widened .076/7's text). After E3R1: 103 cases over 42 requirements (E1: 75 over 37). E3R1 added 28: .033/4–/5, .034/3, R-PASTE.1/3–/4, R-TUI-043.4/3, R-PASTE.29/3, .047/3, .066/3, .075/1–/2, .076/7, .077/3–/4, .078/1–/3, .084/1–/3, .085/1, /3–/6 (.085/2, the card, is G-V's), .086/1–/3. The robustness cases (.084–.086) follow R-COPY.26/1's form (`01-requirements.md` §Deferred work after teardown): each captures the deferred work and runs it once live (it paints) and once after its target is gone (no exception, nothing painted).

## Folded at E4 (integrator I7)

Every planned name above exists with that name in `tests/test_b103_label_list.py` (105/105, checked by script against `02-test-cases-T.md`; T7 renamed none). Six extra tests carry no case of their own: `test_i7_display_text_never_raises_and_keeps_length`, `test_i7_filter_box_esc_clears_a_list_text`, `test_i7_list_row_cells_reads_text_cells_by_the_shipped_labels`, `test_i7_resolution_rows_are_the_tag_objects_and_equal_when_repeated` (I-7 interface checks), `test_r_a2l_list_069_control_inserts_the_name_not_its_display_text` (the `.069` U+0007 control), `test_r_a2l_list_077_1_similar_line` (the `.077/1` similar-line half). Partial by construction (T7): the negative arms of `.084`–`.086` wait 0.6 s after releasing the held worker. Results: `E4-integration.md`.
