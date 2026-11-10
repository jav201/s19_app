# E5 mutant table — Inc 3b, product tree `98904e82`

**28 killed / 0 survived / 0 not realisable.** Every mutant ran serially in a separate copy under `/tmp/b103-e5-3b-mut` on <runner>, Python 3.11.18, with isolated HOME/XDG/LOCALAPPDATA, stdin closed and bytecode disabled. The integration clone was never mutated. Driver: `write3b-mutants-driver.txt`; per-mutant diff and pytest output: `mutants-3b/M-*.txt`; machine summary: `mutants-3b/summary.json`.

| Id(s) | Row / arm | Negative control | Discriminating selection |
|---|---|---|---|
| M-120 | .120 | single-text array encode no longer refuses ELEMENTS | `a2l_def_120` |
| M-121 | .121 | element suffix removed from `_name_echo` | `a2l_def_121` |
| M-122 | .122 | every conversion forced IDENTICAL | `a2l_def_122` |
| M-123 | .123 | COLUMN_DIR linear index transposed incorrectly | `a2l_def_123` |
| M-124 | .124 | initial decode refusal ignored | `a2l_def_124` |
| M-125 | .125 | shape validation disabled | `a2l_def_125` |
| M-125b | .125/5 | public element_name returns raw name/position | `a2l_def_125_5` |
| M-126 | .126 | FIX_AXIS edit guard removed | `a2l_def_126` |
| M-127 | .127 | COM_AXIS edit guard removed | `a2l_def_127` |
| M-128 | .128 | no-points guard removed | `a2l_def_128` |
| M-129 | .129 | monotony breaking point always None | `a2l_def_129` |
| M-130 | .130 | PARSE gate disabled in encode_values | `a2l_def_130_4 or a2l_def_130_5` |
| M-131 | .131 | display-precision rejection removed | `a2l_def_122_5 or a2l_def_131_1` |
| M-131b | .131/5 | exact-first linear lookup restored | `a2l_def_131_5` |
| M-131c | .131/4 | nonfinite raw fraction rounded | `a2l_def_131_4` |
| M-131d | .131/6 | composed message cap removed | `a2l_def_131_6` |
| M-132 | .132 | record zero-filled, unedited bytes lost | `a2l_def_132` |
| M-140 | .140 | AXIS_PTS omitted from candidates | `a2l_def_140_1` |
| M-140b | .140/10 | unsound 1 MiB lower address window restored | `a2l_def_140_10` |
| M-140c | .140/11 | malformed MEASUREMENT matrix uses provisional length | `a2l_def_140_11` |
| M-153 | .153 | scalar `(0,)` delegation disabled | `a2l_def_153` |
| M-154 | .154 | unknown monotony accepted | `a2l_def_154` |
| M-155 | .155 | breaking point text no longer echo-capped | `a2l_def_155_2` |
| M-58.1a | .58.1/arr-1 edit arm | caller image mutated | `58_1_arr_1_edit_arm` |
| M-58.1b | .58.1/arr-2 edit arm | caller image mutated | `58_1_arr_2_edit_arm` |
| M-AT1 | AT-B103-I3-1 edit arm | COLUMN_DIR index transposed | `at_b103_i3_1_edit_arm` |
| M-AT2 | AT-B103-I3-2 edit arm | COM_AXIS guard removed | `at_b103_i3_2_edit_arm` |
| M-AT3 | AT-B103-I3-3 edit arm | COLUMN_DIR index transposed | `at_b103_i3_3_edit_arm or a2l_def_123_2` |

An independent read-only audit of the driver caught three non-discriminating controls before execution: M-121 initially changed only `Definition.name`, M-131 selected only accepted writes, and M-AT3 exercised only zero positions. They were corrected as shown above; no survivor was removed by weakening a test.
