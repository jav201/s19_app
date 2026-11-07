# Inc 4 — test cases (ISO/IEC/IEEE 29119-3), E1

One case per coverage item `<requirement id>/<n>` of `01-requirements.md`, plus the black-box cases `AT-B103-I4-1` and `AT-B103-I4-2`. Written at E1, before any test: **Tests** is empty, **Coverage** is `gap` and **Result** is `not_run` everywhere (E4 fills them). Proposed test files (`E1-slice.md` §4): G-T1 `tests/test_b103_label_match.py` (every case but the two timing cases), G-T2 `tests/test_b103_label_match_timing.py` (`serial_timing`: R-A2L-MATCH.35/1, .36/1). Class: *robustness* for the cases of an `If` row and for the edge inputs the brief names (non-ASCII, brackets and pattern characters, a query longer than every name); *normal* otherwise.

Every expected result was derived from the rows by hand and then compared with the ranked lists of the E1 oracle (a throwaway reference of the rows under the recommended rule order, D-3 B): `evidence-e1/i4e1-pilot3-transcript.txt` §1–§2. The oracle and the prepared-index variant agree on 409 generated queries at 4 limits (§3: 0 mismatches). An E4 test asserts the values below, never the oracle.

**Notation.** A ranked list is written `[entry; entry; …]`; an entry is `NAME · rule · spans`, and a `fuzzy` entry adds `· e<k>` (its total edits). Spans are `(start,end)` offsets into the name. `[]` is the empty ranked list. "Exactly" means the whole list, in that order, nothing more.

**Fixtures** (every list is prepared, then ranked; limit 20 unless the case says otherwise):
- **C08** — the 462 names of `firmware.a2l` of release case 08, made by `tools/synth/make_release_case.py --out <tmp> --seed 20260001` (never into the repository) and read with the app's A2L reader (`s19_app.tui.a2l.parse_a2l_file(path)["tags"]`, each tag's `name`), in file order. Copy: `evidence-e1/case08-names.txt` (VALUE_0001…0208, MEASUREMENT_0001…0104, CURVE_0001…0060, MAP_0001…0020, ASCII_0001…0010, VAL_BLK_0001…0060).
- **C08i** — the 470 names of `firmware_issues.a2l` of the same run: C08 plus LIMIT_BREAKER, MISSING_CM, OUT_OF_RANGE_1…3, SPAN_OVER_1…2, with VALUE_0001 twice (`evidence-e1/case08-issues-names.txt`). **C08r** — C08 in reverse order.
- **BAL**, **SRC**, **SWB**, **SWA** — the names of `examples/case_00_public/BalanceTube_STMicro.a2l` (111), `from_source.a2l` (72), `software_b.a2l` (67), `software_a.a2l` (13,990), read the same way.
- **TW** = [`RPM`, `rpm`, `Rpm`]; **TW2** = [`Rpm`, `rpm`, `RPM`]; **NA** = [`Drück_Max`, `DRÜCK_MAX`, `druck_max`]; **CUR** = [`ABSValue`, `AValue`, `engineSpeed`, `Map3D`].
- **REF** — the SWA names in file order, then the SWA names each with `_1` appended, then with `_2`, then with `_3`; the first 50,000 (all unique).
- **REF6** — the first 50,000 names of `examples/case_06_large_nested_a2l/firmware.a2l` (every name 13 characters, `CHAR_00000_00` / `MEAS_00000_00`), read the same way. Its queries: `m`, `meas_`, `chr`, `mesa`, `cahr`, `cr0`, `char 1`, `0`, `chr 0`, `ch00`, `meas 1`, `c 0 1`.
- **QSET** — 33 queries: `a`, `e`, `0`, `zz`, `ab`, `JotafVod_msrqlLzL_kh2C_rWl_pfue._0_`, `JotafVod_msr`, `srqlLzL_`, `0 jotaf`, `JVmL`, `xqzjvkw`, `qqqq zzzz`, `aaaa`, `e e e`, `Nzukij`, `Ierxjr_Eud`, `ledRing`, `pposbxiif`, `cnt`, `temp_sensor_max`, `x y z w v u`, `pposbxiifkdgfiajnbbpvb_dyan_xvz1` (they reach every rule, the empty result and the worst case the pilots found); `njraipjtbtu lsuakcoj hsxgibymjxu orfltalc uadvdygb zobnkw`, `votklbi fjblnabj qghque pdjxmq tiprdynotu djchlitjt`, `lmmwngodou jadkvqy khbnukc qomfrybiza evfwbqj` (E3A-02, multi-word); `e ` × 128, `a b c … z ` cut at 256, `0 ` × 128, `a` × 256, two seeded 256-character `,`-joined SWA name lists, the longest REF name whole and with a transposition (E3S-01).

| Case | Objective | Class | Preconditions | Inputs | Expected result | Tests (full / partial) | Coverage | Result |
|---|---|---|---|---|---|---|---|---|
| R-A2L-MATCH.1/1 | Verify that leading and trailing spaces are not part of the query text | normal | C08 | `  VALUE_0001  ` | exactly [VALUE_0001 · exact · (0,10)] | | gap | not_run |
| R-A2L-MATCH.1/2 | Verify that a leading tab and a trailing line feed are not part of the query text | normal | C08 | `\tVALUE_0001\n` | exactly [VALUE_0001 · exact · (0,10)] | | gap | not_run |
| R-A2L-MATCH.1/3 | Verify that stripped whitespace counts in no span | normal | C08 | ` value_000 `, limit 5 | exactly [VALUE_0001 … VALUE_0005, each · prefix · (0,9)] | | gap | not_run |
| R-A2L-MATCH.1/4 | Verify that a control character that is not defined whitespace is not stripped | robustness | C08 | U+001C followed by `VALUE_0001` | exactly [VALUE_0001 · token · (0,5),(6,10)] | | gap | not_run |
| R-A2L-MATCH.2/1 | Verify that an empty query lists nothing | robustness | C08 | `` | [] | | gap | not_run |
| R-A2L-MATCH.2/2 | Verify that a query of spaces lists nothing | robustness | C08 | `   ` | [] | | gap | not_run |
| R-A2L-MATCH.2/3 | Verify that a query of tab and line feed lists nothing | robustness | C08 | `\t\n` | [] | | gap | not_run |
| R-A2L-MATCH.2/4 | Verify that a query of one separator lists nothing | robustness | C08 | `_` | [] | | gap | not_run |
| R-A2L-MATCH.2/5 | Verify that a query of dots and brackets lists nothing | robustness | C08 | `._[]` | [] | | gap | not_run |
| R-A2L-MATCH.3/1 | Verify that lowercase query letters match uppercase name letters | normal | C08 | `value_0001` | exactly [VALUE_0001 · exact · (0,10)] | | gap | not_run |
| R-A2L-MATCH.3/2 | Verify that mixed-case query letters match | normal | C08 | `Value_0001` | exactly [VALUE_0001 · exact · (0,10)] | | gap | not_run |
| R-A2L-MATCH.3/3 | Verify that names differing only in case all match | normal | TW | `rpm` | exactly [rpm · exact · (0,3); RPM · exact · (0,3); Rpm · exact · (0,3)] | | gap | not_run |
| R-A2L-MATCH.4/1 | Verify that a non-ASCII letter is not folded | robustness | NA | `drück` | exactly [Drück_Max · prefix · (0,5); DRÜCK_MAX · fuzzy · (0,5) · e1; druck_max · fuzzy · (0,5) · e1] | | gap | not_run |
| R-A2L-MATCH.4/2 | Verify the same with an uppercase non-ASCII query | robustness | NA | `DRÜCK` | exactly [DRÜCK_MAX · prefix · (0,5); Drück_Max · fuzzy · (0,5) · e1; druck_max · fuzzy · (0,5) · e1] | | gap | not_run |
| R-A2L-MATCH.4/3 | Verify that `-` and `_` are different characters | robustness | C08 | `VALUE-0001` | exactly [VALUE_0001 · token · (0,5),(6,10)] | | gap | not_run |
| R-A2L-MATCH.5/1 | Verify an exact match | normal | C08 | `VALUE_0001` | exactly [VALUE_0001 · exact · (0,10)] | | gap | not_run |
| R-A2L-MATCH.5/2 | Verify an exact match of another family | normal | C08 | `map_0020` | exactly [MAP_0020 · exact · (0,8)] | | gap | not_run |
| R-A2L-MATCH.5/3 | Verify that three exact matches are all listed | normal | TW | `rpm` | 3 entries, each · exact | | gap | not_run |
| R-A2L-MATCH.6/1 | Verify prefix matches | normal | C08 | `value_000`, limit 5 | exactly [VALUE_0001 … VALUE_0005, each · prefix · (0,9)] | | gap | not_run |
| R-A2L-MATCH.6/2 | Verify prefix matches of the issue names | normal | C08i | `span` | exactly [SPAN_OVER_1 · prefix · (0,4); SPAN_OVER_2 · prefix · (0,4)] | | gap | not_run |
| R-A2L-MATCH.6/3 | Verify an uppercase prefix | normal | C08i | `LIMIT` | exactly [LIMIT_BREAKER · prefix · (0,5)] | | gap | not_run |
| R-A2L-MATCH.7/1 | Verify substring matches at the end of names | normal | C08 | `0001` | exactly [MAP_0001 · substring · (4,8); ASCII_0001 · substring · (6,10); CURVE_0001 · substring · (6,10); VALUE_0001 · substring · (6,10); VAL_BLK_0001 · substring · (8,12); MEASUREMENT_0001 · substring · (12,16)] | | gap | not_run |
| R-A2L-MATCH.7/2 | Verify that brackets compare as characters | robustness | SRC | `knife[1]` | exactly [parameter_instance[0].Knife[1].x · substring · (22,30); parameter_instance[1].Knife[1].x · substring · (22,30); parameter_instance[2].Knife[1].x · substring · (22,30); parameter_instance[3].Knife[1].x · substring · (22,30); parameter_instance[1].Knife[0].x · token · (19,20),(22,27)] | | gap | not_run |
| R-A2L-MATCH.7/3 | Verify a substring that starts with a bracket and holds a dot | robustness | SRC | `[0].Spoon` | exactly [parameter_instance[0].Spoon.x · substring · (18,27)] | | gap | not_run |
| R-A2L-MATCH.7/4 | Verify a camelCase substring with an index | robustness | BAL | `ledRing[1]`, limit 4 | exactly [model.Signals.ledRing[1].red · substring · (14,24); model.Signals.ledRing[1].blue · substring · (14,24); model.Signals.ledRing[1].green · substring · (14,24); model.MainClass.ledController.ledRing[1].red · substring · (30,40)] | | gap | not_run |
| R-A2L-MATCH.8/1 | Verify that query words match name tokens in any order | normal | C08 | `blk val 00`, limit 3 | exactly [VAL_BLK_0001, VAL_BLK_0002, VAL_BLK_0003, each · token · (0,3),(4,7),(8,10)] | | gap | not_run |
| R-A2L-MATCH.8/2 | Verify a camelCase cut | normal | BAL | `stop watch` | exactly [model.MainClass.gameController.stopWatch.timeCounter · token · (31,40)] | | gap | not_run |
| R-A2L-MATCH.8/3 | Verify the cut before the last letter of an uppercase run | normal | SWB | `oks ahw` | exactly [LukPvq.JXML_UPQ_BI.OKSAhwvcueaniy · token · (19,25); AwsQdc.VXAO_CSP_KH.NkshfehlTcyfkjea_IPNR · fuzzy · (0,3),(19,27) · e2; OotGyt.FmcP_UGL_SgvHhu_MME_GEH_kdfba.VsvL_BILR_GtnWga_HGW_RKK_eroog · subsequence · (0,1),(31,32),(38,39),(52,53),(54,55),(56,57)] | | gap | not_run |
| R-A2L-MATCH.8/4 | Verify digit tokens and bracket separators | normal | SRC | `knife 1 x` | exactly [parameter_instance[0].Knife[1].x · token · (22,27),(28,29),(31,32); parameter_instance[1].Knife[0].x · token · (19,20),(22,27),(31,32); parameter_instance[1].Knife[1].x · token · (19,20),(22,27),(31,32); parameter_instance[2].Knife[1].x · token · (22,27),(28,29),(31,32); parameter_instance[3].Knife[1].x · token · (22,27),(28,29),(31,32)] | | gap | not_run |
| R-A2L-MATCH.8/5 | Verify `_` separators | normal | C08i | `out range` | exactly [OUT_OF_RANGE_1, OUT_OF_RANGE_2, OUT_OF_RANGE_3, each · token · (0,3),(7,12)] | | gap | not_run |
| R-A2L-MATCH.8/6 | Verify that `.` and `*` in the query are separators, not a pattern | robustness | SRC | `knife.*`, limit 4 | exactly [parameter_instance[0].Knife[0].x; parameter_instance[0].Knife[1].x; parameter_instance[1].Knife[0].x; parameter_instance[1].Knife[1].x, each · token · (22,27)] | | gap | not_run |
| R-A2L-MATCH.8/7 | Verify the one-letter token before a capitalised word | normal | CUR | `a value` | exactly [AValue · token · (0,6); ABSValue · token · (0,1),(3,8)] | | gap | not_run |
| R-A2L-MATCH.8/8 | Verify letter/digit cuts | normal | CUR | `map 3 d` | exactly [Map3D · token · (0,5)] | | gap | not_run |
| R-A2L-MATCH.8/9 | Verify a query longer than every name (21 characters; repeated query tokens) | robustness | C08 | `VALUE_0001_VALUE_0001` | exactly [VALUE_0001 · token · (0,5),(6,10)] | | gap | not_run |
| R-A2L-MATCH.9/1 | Verify a subsequence match | normal | C08 | `mp`, limit 3 | exactly [MAP_0001, MAP_0002, MAP_0003, each · subsequence · (0,1),(2,3)] | | gap | not_run |
| R-A2L-MATCH.9/2 | Verify a subsequence where a digit query token starts no name token | normal | C08 | `ascii 1` | exactly [ASCII_0001 · subsequence · (0,5),(9,10); ASCII_0010 · subsequence · (0,5),(8,9)] | | gap | not_run |
| R-A2L-MATCH.9/3 | Verify an index typed without its zeros | normal | C08 | `map 20` | exactly [MAP_0020 · subsequence · (0,3),(6,8)] | | gap | not_run |
| R-A2L-MATCH.9/4 | Verify words typed joined and lowercase | normal | BAL | `gamecontroller timer`, limit 3 | exactly [model.MainClass.gameController.timer.timeCounter · subsequence · (16,30),(31,36); model.MainClass.gameController.stopWatch.timeCounter · subsequence · (16,30),(32,33),(42,45),(51,52)] | | gap | not_run |
| R-A2L-MATCH.10/1 | Verify a transposition | normal | C08 | `cuvre`, limit 3 | exactly [CURVE_0001, CURVE_0002, CURVE_0003, each · fuzzy · (0,5) · e1] | | gap | not_run |
| R-A2L-MATCH.10/2 | Verify a transposition in a long word with an index | normal | C08 | `maesurement_0001` | exactly [MEASUREMENT_0001 · fuzzy · (0,11),(12,16) · e1] | | gap | not_run |
| R-A2L-MATCH.10/3 | Verify a transposition at the start | normal | C08 | `vlaue_0001` | exactly [VALUE_0001 · fuzzy · (0,5),(6,10) · e1] | | gap | not_run |
| R-A2L-MATCH.10/4 | Verify a transposition in 3 letters | normal | C08 | `mpa`, limit 3 | exactly [MAP_0001, MAP_0002, MAP_0003, each · fuzzy · (0,3) · e1] | | gap | not_run |
| R-A2L-MATCH.10/5 | Verify an insertion | normal | C08 | `xmap`, limit 3 | exactly [MAP_0001, MAP_0002, MAP_0003, each · fuzzy · (0,3) · e1] | | gap | not_run |
| R-A2L-MATCH.10/6 | Verify a substitution | normal | C08 | `maq`, limit 3 | exactly [MAP_0001, MAP_0002, MAP_0003, each · fuzzy · (0,3) · e1] | | gap | not_run |
| R-A2L-MATCH.11/1 | Verify that a digit token allows no edit | normal | C08 | `VALUE_0300` | [] | | gap | not_run |
| R-A2L-MATCH.11/2 | Verify that a 2-letter token allows no edit | normal | [`BA_X`] | `ab` | [] | | gap | not_run |
| R-A2L-MATCH.11/3 | Verify the same against a longer name token | normal | [`abc`] | `ca` | [] | | gap | not_run |
| R-A2L-MATCH.12/1 | Verify that a 3-letter token allows 1 edit | normal | C08 | `maq`, limit 3 | 3 entries, each · fuzzy · e1 | | gap | not_run |
| R-A2L-MATCH.12/2 | Verify that a 5-letter token allows 1 edit | normal | C08 | `cuvre`, limit 3 | 3 entries, each · fuzzy · e1 | | gap | not_run |
| R-A2L-MATCH.12/3 | Verify that a 5-letter token allows no second edit | normal | C08 | `cvure` | [] | | gap | not_run |
| R-A2L-MATCH.12/4 | Verify that a non-ASCII digit is a letter, not a digit token | robustness | [`٣٣٣_X`] | `٣٣٤` | exactly [٣٣٣_X · fuzzy · (0,3) · e1] | | gap | not_run |
| R-A2L-MATCH.13/1 | Verify that a 7-letter token allows 2 edits | normal | C08 | `valuexx_0001` | exactly [VALUE_0001 · fuzzy · (0,5),(6,10) · e2] | | gap | not_run |
| R-A2L-MATCH.13/2 | Verify that an 8-letter token allows no third edit | normal | C08 | `valuexxx_0001` | [] | | gap | not_run |
| R-A2L-MATCH.13/3 | Verify that a 6-letter token allows 1 and 2 edits | normal | [`CUVE`, `CURVE_0001`] | `curvee` | exactly [CURVE_0001 · fuzzy · (0,5) · e1; CUVE · fuzzy · (0,4) · e2] | | gap | not_run |
| R-A2L-MATCH.13/4 | Verify that a 6-letter token at OSA distance 3 gives no match | normal | C08 | `crxuve` | [] | | gap | not_run |
| R-A2L-MATCH.14/1 | Verify that every match is listed | normal | C08 | `value_000`, limit 100 | exactly 20 entries: VALUE_0001 … VALUE_0009 · prefix · (0,9), then VALUE_0010, 0020, 0030, 0040, 0050, 0060, 0070, 0080, 0090 · subsequence · (0,5),(6,8),(9,10), then VALUE_0100, VALUE_0200 · subsequence · (0,5),(6,7),(8,10) | | gap | not_run |
| R-A2L-MATCH.14/2 | Verify the same for substring matches | normal | C08 | `0001`, limit 100 | exactly the 6 entries of R-A2L-MATCH.7/1 | | gap | not_run |
| R-A2L-MATCH.15/1 | Verify that a name that meets no rule is left out | robustness | C08 | `temp_sensor_max` | [] | | gap | not_run |
| R-A2L-MATCH.15/2 | Verify that an empty or blank name is never listed | robustness | [``, `   `, `VALUE_0001`] | `v` | exactly [VALUE_0001 · prefix · (0,1)] | | gap | not_run |
| R-A2L-MATCH.16/1 | Verify that a name gets the first rule it meets | normal | C08 | `value_000`, limit 1 | exactly [VALUE_0001 · prefix · (0,9)] (it is also a substring and a fuzzy match) | | gap | not_run |
| R-A2L-MATCH.16/2 | Verify token before fuzzy on two names | normal | C08 | `valu_0001` | exactly [VALUE_0001 · token · (0,4),(6,10); VAL_BLK_0001 · fuzzy · (0,3),(8,12) · e1] | | gap | not_run |
| R-A2L-MATCH.16/3 | Verify fuzzy before subsequence on one name | normal | C08 | `vale_0001` | exactly [VALUE_0001 · fuzzy · (0,5),(6,10) · e1; VAL_BLK_0001 · fuzzy · (0,3),(8,12) · e1] (VALUE_0001 is also a subsequence match) | | gap | not_run |
| R-A2L-MATCH.17/1 | Verify that a repeated name is listed once | robustness | C08i | `VALUE_0001` | exactly [VALUE_0001 · exact · (0,10)] | | gap | not_run |
| R-A2L-MATCH.17/2 | Verify that a repeated name does not change a longer list | robustness | C08i | `value_000` | the same 20 entries as R-A2L-MATCH.14/1, VALUE_0001 once | | gap | not_run |
| R-A2L-MATCH.18/1 | Verify the limit cut | normal | C08 | `value_000`, limit 5 | 5 entries, the first 5 of R-A2L-MATCH.14/1 | | gap | not_run |
| R-A2L-MATCH.18/2 | Verify a limit above the count | normal | C08 | `0001`, limit 20 | the 6 entries of R-A2L-MATCH.7/1 | | gap | not_run |
| R-A2L-MATCH.18/3 | Verify limit 1 | normal | C08 | `value_000`, limit 1 | exactly [VALUE_0001 · prefix · (0,9)] | | gap | not_run |
| R-A2L-MATCH.19/1 | Verify limit 0 | robustness | C08 | `VALUE`, limit 0 | [] | | gap | not_run |
| R-A2L-MATCH.19/2 | Verify a negative limit | robustness | C08 | `VALUE`, limit −1 | [] | | gap | not_run |
| R-A2L-MATCH.20/1 | Verify prefix before subsequence | normal | C08 | `value_000` | the 9 `prefix` entries are entries 1–9 and the 11 `subsequence` entries 10–20 (R-A2L-MATCH.14/1) | | gap | not_run |
| R-A2L-MATCH.20/2 | Verify substring before subsequence | normal | BAL | `gamecontroller.timer` | exactly [model.MainClass.gameController.timer.timeCounter · substring · (16,36); model.MainClass.gameController.stopWatch.timeCounter · subsequence · (16,30),(32,33),(42,45),(51,52)] | | gap | not_run |
| R-A2L-MATCH.20/3 | Verify token, then fuzzy, then subsequence | normal | SWB | `oks ahw` | the three entries of R-A2L-MATCH.8/3, in that order | | gap | not_run |
| R-A2L-MATCH.21/1 | Verify a boundary occurrence before a mid-token one | normal | [`timeCounter`, `Encounter`] | `counter` | exactly [timeCounter · substring · (4,11); Encounter · substring · (2,9)] | | gap | not_run |
| R-A2L-MATCH.21/2 | Verify that a separator offset is a boundary | normal | C08 | `_0001` | exactly [MAP_0001 · substring · (3,8); ASCII_0001 · substring · (5,10); CURVE_0001 · substring · (5,10); VALUE_0001 · substring · (5,10); VAL_BLK_0001 · substring · (7,12); MEASUREMENT_0001 · substring · (11,16)] | | gap | not_run |
| R-A2L-MATCH.21/3 | Verify names with no boundary occurrence, ordered among themselves | normal | BAL | `ounter`, limit 4 | exactly [model.MainClass.ledController.sw.timeCounter · substring · (38,44); model.MainClass.gameController.timer.timeCounter · substring · (42,48); model.MainClass.gameController.stopWatch.timeCounter · substring · (46,52)] | | gap | not_run |
| R-A2L-MATCH.22/1 | Verify fewer edits first | normal | [`CUVE`, `CURVE_0001`] | `curvee` | exactly [CURVE_0001 · fuzzy · (0,5) · e1; CUVE · fuzzy · (0,4) · e2] | | gap | not_run |
| R-A2L-MATCH.23/1 | Verify the shorter name first | normal | C08 | `0001` | entry 1 is MAP_0001 (8 characters), entry 6 is MEASUREMENT_0001 (16) (R-A2L-MATCH.7/1) | | gap | not_run |
| R-A2L-MATCH.23/2 | Verify length before case-exactness | normal | [`rpm_x`, `RPMX`] | `rpm` | exactly [RPMX · prefix · (0,3); rpm_x · prefix · (0,3)] | | gap | not_run |
| R-A2L-MATCH.24/1 | Verify the case-exact name first (lowercase query) | normal | TW | `rpm` | entry 1 is `rpm` (R-A2L-MATCH.3/3) | | gap | not_run |
| R-A2L-MATCH.24/2 | Verify the case-exact name first (uppercase query) | normal | TW | `RPM` | exactly [RPM · exact · (0,3); Rpm · exact · (0,3); rpm · exact · (0,3)] | | gap | not_run |
| R-A2L-MATCH.24/3 | Verify that fuzzy names of one rule, key and length fall to code-point order, not case-exactness | robustness | NA | `drück` | entry 2 is DRÜCK_MAX and entry 3 is druck_max (R-A2L-MATCH.4/1) | | gap | not_run |
| R-A2L-MATCH.25/1 | Verify code-point order | normal | C08 | `0001` | entries 2–4 are ASCII_0001, CURVE_0001, VALUE_0001 in that order | | gap | not_run |
| R-A2L-MATCH.25/2 | Verify that the input order decides nothing | normal | C08r | `0001` | the same 6 entries as R-A2L-MATCH.7/1, in the same order | | gap | not_run |
| R-A2L-MATCH.25/3 | Verify code-point order of case twins | normal | TW2 | `rpm` | exactly [rpm · exact · (0,3); RPM · exact · (0,3); Rpm · exact · (0,3)] | | gap | not_run |
| R-A2L-MATCH.26/1 | Verify the exact span | normal | C08 | `VALUE_0001` | the entry's spans are exactly (0,10) | | gap | not_run |
| R-A2L-MATCH.26/2 | Verify the exact span of a shorter name | normal | C08 | `map_0020` | (0,8) | | gap | not_run |
| R-A2L-MATCH.27/1 | Verify the prefix span | normal | C08 | `value_000`, limit 5 | each entry (0,9) | | gap | not_run |
| R-A2L-MATCH.27/2 | Verify a short prefix span | normal | C08i | `span` | each entry (0,4) | | gap | not_run |
| R-A2L-MATCH.27/3 | Verify that the span counts the query text, not the whitespace | normal | C08 | ` value_000 `, limit 5 | each entry (0,9) | | gap | not_run |
| R-A2L-MATCH.28/1 | Verify the boundary occurrence, not the leftmost | normal | [`DiscountCount`] | `count` | exactly [DiscountCount · substring · (8,13)] | | gap | not_run |
| R-A2L-MATCH.28/2 | Verify a boundary span after a separator | normal | C08 | `0001` | MAP_0001's spans are exactly (4,8) | | gap | not_run |
| R-A2L-MATCH.29/1 | Verify the span with no boundary occurrence | normal | BAL | `ounter`, limit 4 | model.MainClass.ledController.sw.timeCounter's spans are exactly (38,44) | | gap | not_run |
| R-A2L-MATCH.29/2 | Verify the same inside an uppercase run | normal | SWB | `sahw` | entry 1 is LukPvq.JXML_UPQ_BI.OKSAhwvcueaniy · substring · (21,25) | | gap | not_run |
| R-A2L-MATCH.30/1 | Verify token spans | normal | C08 | `blk val 00`, limit 3 | each entry (0,3),(4,7),(8,10) | | gap | not_run |
| R-A2L-MATCH.30/2 | Verify that a query token takes the leftmost name token it starts | normal | SRC | `knife 1 x` | parameter_instance[1].Knife[0].x's spans are exactly (19,20),(22,27),(31,32) | | gap | not_run |
| R-A2L-MATCH.30/3 | Verify a one-letter token span | normal | CUR | `a value` | ABSValue's spans are exactly (0,1),(3,8) | | gap | not_run |
| R-A2L-MATCH.31/1 | Verify subsequence spans | normal | C08 | `mp`, limit 3 | each entry (0,1),(2,3) | | gap | not_run |
| R-A2L-MATCH.31/2 | Verify subsequence spans across a separator | normal | C08 | `value_000` | VALUE_0010's spans are exactly (0,5),(6,8),(9,10) | | gap | not_run |
| R-A2L-MATCH.31/3 | Verify leftmost-after-previous positions on a long name | normal | BAL | `gamecontroller timer`, limit 3 | model.MainClass.gameController.stopWatch.timeCounter's spans are exactly (16,30),(32,33),(42,45),(51,52) | | gap | not_run |
| R-A2L-MATCH.32/1 | Verify that a fuzzy span covers the whole name token | normal | C08 | `maesu`, limit 3 | exactly [MEASUREMENT_0001, MEASUREMENT_0002, MEASUREMENT_0003, each · fuzzy · (0,11) · e1] | | gap | not_run |
| R-A2L-MATCH.32/2 | Verify fuzzy spans of two query tokens | normal | C08 | `valu_0001` | VAL_BLK_0001's spans are exactly (0,3),(8,12) | | gap | not_run |
| R-A2L-MATCH.32/3 | Verify the span of the token at the smallest distance | normal | C08 | `vblk`, limit 2 | exactly [VAL_BLK_0001 · fuzzy · (4,7) · e1; VAL_BLK_0002 · fuzzy · (4,7) · e1] | | gap | not_run |
| R-A2L-MATCH.33/1 | Verify total edits 1 | normal | C08 | `maesurement_0001` | the entry's total edits are 1 | | gap | not_run |
| R-A2L-MATCH.33/2 | Verify total edits 2 | robustness | C08 | `measurementss_0001` (18 characters, longer than every name) | exactly [MEASUREMENT_0001 · fuzzy · (0,11),(12,16) · e2] | | gap | not_run |
| R-A2L-MATCH.33/3 | Verify that total edits add over query tokens | normal | [`Curve_Map_X`] | `cuvre maq` | exactly [Curve_Map_X · fuzzy · (0,5),(6,9) · e2] | | gap | not_run |
| R-A2L-MATCH.34/1 | Verify that touching spans are joined | normal | CUR | `abs value` | exactly [ABSValue · token · (0,8)] | | gap | not_run |
| R-A2L-MATCH.34/2 | Verify spans in offset order whatever the query order | normal | C08 | `blk val 00`, limit 1 | VAL_BLK_0001's spans are exactly (0,3),(4,7),(8,10), in that order | | gap | not_run |
| R-A2L-MATCH.34/3 | Verify joined spans of two tokens | normal | CUR | `a value` | AValue's spans are exactly (0,6) | | gap | not_run |
| R-A2L-MATCH.35/1 | Verify the preparation time of 50,000 names | normal | cachyos-rtx, Python 3.11.18; host load printed before and after | prepare REF 3 times | the median of the 3 preparation times ≤ 5.0 s | | gap | not_run |
| R-A2L-MATCH.36/1 | Verify the ranking time per keystroke | normal | REF prepared once and REF6 prepared once; cachyos-rtx, Python 3.11.18; host load printed | each query of QSET over REF and each query of REF6, limit 20, ranked 7 times in a row | for every query the median of its 7 times ≤ 200 ms | | gap | not_run |
| R-A2L-MATCH.37/1 | Verify that the prepared reference list stays within 64 MiB | normal | REF (50,000 names); cachyos-rtx, Python 3.11.18 | prepare REF once under tracemalloc | the tracemalloc peak ≤ 67,108,864 bytes (64 MiB) | | gap | not_run |
| R-A2L-MATCH.38/1 | Verify that a query at the cap is ranked | robustness | C08 | `'VALUE_0001_' * 23 + 'VAL'` (256 characters) | exactly [VALUE_0001 · token · (0,5),(6,10)] | | gap | not_run |
| R-A2L-MATCH.38/2 | Verify that a query over the cap lists nothing | robustness | C08 | `'VALUE_0001_' * 23 + 'VALU'` (257 characters) | [] | | gap | not_run |
| R-A2L-MATCH.39/1 | Verify that a name of 1,024 characters is indexed and listed | robustness | one name of 1,024 `x` characters | `x` | exactly [the name · prefix · (0,1)] | | gap | not_run |
| R-A2L-MATCH.39/2 | Verify that a name of 1,025 characters is left out | robustness | one name of 1,025 `x` characters | `x` | [] | | gap | not_run |
| AT-B103-I4-1 | Verify through I-3, over real case-08 names, that typing a name keystroke by keystroke gives the expected list at each step (US-I4-1) | normal | C08, limit 5 | `m`, `ma`, `map`, `map_`, `map_00`, `map_002`, `map_0020`, ranked in turn on the same prepared list | the first five steps: exactly [MAP_0001 … MAP_0005, each · prefix · (0,k)] with k = 1, 2, 3, 4, 6; `map_002`: exactly [MAP_0020 · prefix · (0,7); MAP_0002 · subsequence · (0,3),(4,6),(7,8); MAP_0012 · subsequence · (0,3),(4,6),(7,8)]; `map_0020`: exactly [MAP_0020 · exact · (0,8)] — rows .5, .6, .9, .18, .23, .25, .27, .31 | | gap | not_run |
| AT-B103-I4-2 | Verify through I-3, over the 13,990 real-shape names, that a name is found first from its whole text, its start, its middle, its end, two of its words in either order and a typo (the operator's words, US-I4-1) | normal | SWA, limit 5; target `JotafVod_msrqlLzL_kh2C_rWl_pfue._0_` | the target, `jotafvod`, `msrqlLzL`, `pfue._0_`, `jotaf vod`, `vod jotaf`, `jotfa vod`, `jotaf_vdo` | in each list entry 1 is the target, as: exact (0,35); prefix (0,8); substring (9,17); substring (27,35); token (0,8); token (0,8); fuzzy (0,8) e1; fuzzy (0,8) e1 — rows .5–.8, .10, .20 (under the handoff order, D-3 A, `jotfa vod` puts the target third, `evidence-e1/i4e1-at-examples-transcript.txt`) | | gap | not_run |

**Counts:** 115 coverage items over the 39 rows (.1 4, .2 5, .3 3, .4 3, .5 3, .6 3, .7 4, .8 9, .9 4, .10 6, .11 3, .12 4, .13 4, .14 2, .15 2, .16 3, .17 2, .18 3, .19 2, .20 3, .21 3, .22 1, .23 2, .24 3, .25 3, .26 2, .27 3, .28 2, .29 2, .30 3, .31 3, .32 3, .33 3, .34 3, .35 1, .36 1, .37 1, .38 2, .39 2) and 2 black-box cases: 117 cases (G-T1 115, G-T2 2). Negative controls (one or two per row, run at E5 in a copy of the tree): `01-requirements.md`, column "Negative control".
