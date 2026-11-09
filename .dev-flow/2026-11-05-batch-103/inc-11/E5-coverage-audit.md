# Coverage audit: FAIL

Static inspection only at `f1397097`; no tests, edits, or commits were performed.

## Exact counts

`02-test-cases.md` contains **277 unique case ids**, with **0 duplicate ids**. Seven are correctly marked moved to Inc 12 and excluded, leaving **270 in-scope cases: 268 requirement cases plus two ATs**.

| Static coverage finding | Requirement cases | ATs | Total |
|---|---:|---:|---:|
| **Full** — all stated inputs/observables asserted | 132 | 2 | **134** |
| **Partial** — some coverage, but not enough for `full` | 109 | 0 | **109** |
| **Missing** — no assertion of the case’s expected observable | 27 | 0 | **27** |
| **Total** | **268** | **2** | **270** |

Thus **136 of 270 cases are incorrectly recorded as `full / covered / verified`**. Broad tracked-file differential and fixture assertions were credited where they genuinely cover a field. “Full” here means static assertion coverage, not an independently rerun result.

Unless noted otherwise, findings below are **HIGH / impl**: test-coverage implementation gaps, not confirmed product defects. The smallest correction is to add the named input/assertion through the case’s product route; until then, downgrade `full/covered/verified` to the appropriate partial/gap state.

## Two app acceptance tests

Both ATs have genuine full product-route coverage:

- **AT-B103-I11-2:** real image/A2L loads at `tests/test_b103_a2l_reader.py:1886` and `:1896`; Explorer row/address, Issues, and Workspace assertions at `:1904-1935`.
- **AT-B103-I11-3:** real V171 load at `tests/test_b103_a2l_reader.py:1960`; application log and Workspace assertions at `:1968-1980`.

However, both matrix node references are wrong (**MEDIUM / design-gap**):

- **AT-B103-I11-2:** `.dev-flow/2026-11-05-batch-103/inc-11/02-test-cases.md:312` names nonexistent `test_at_b103_i11_2`; the actual function is `test_at_b103_i11_2_commented_old_copy_changes_nothing` at `tests/test_b103_a2l_reader.py:1845`.
- **AT-B103-I11-3:** `02-test-cases.md:313` names nonexistent `test_at_b103_i11_3`; the actual function is `test_at_b103_i11_3_v171_loads_clean` at `tests/test_b103_a2l_reader.py:1940`.

Correct the two matrix node ids; no acceptance-coverage downgrade is needed.

## Missing coverage — 27 cases

- **R-A2L-READ.7/2:** `tests/test_b103_a2l_reader.py:515-536` covers /1 and /3–/6 only; no multi-line comment glued on both sides.
- **R-A2L-READ.13/4:** `tests/test_b103_a2l_reader.py:638-649` has no multi-line-string `/end` shape and no corresponding BIT_MASK/end assertion.
- **R-A2L-READ.54/2:** `tests/test_b103_a2l_reader.py:771-785` never calls the imported encoder or asserts raw bytes `00 05`.
- **R-A2L-READ.54/4:** `tests/test_b103_a2l_reader.py:771-815` skips directly from RECORD_LAYOUT to AXIS_PTS; no later-named COMPU_VTAB or raw-1→`on` assertion.
- **R-A2L-READ.54/6:** `tests/test_b103_a2l_reader.py:939-944` checks CK1’s header fields only; no `describe_definition` display-format assertion.
- **R-A2L-READ.24/3:** `tests/test_b103_a2l_reader.py:771-785` does not use CM_LID/`engine speed` or assert the method’s long identifier and conversion type.
- **R-A2L-READ.21/1:** `tests/test_b103_a2l_reader.py:826-833` asserts mismatch diagnostics only, never X’s closure at line 23.
- **R-A2L-READ.65/4:** `tests/test_b103_a2l_reader.py:879-898` contains no hostile-corpus mutation loop or render over 1,000 seeded mutants.
- **R-A2L-READ.31/3:** `tests/test_b103_a2l_reader.py:1092-1097` covers only /1–/2; no CURVE with AXIS_DESCR-local BYTE_ORDER.
- **R-A2L-READ.59/3:** `tests/test_b103_a2l_reader.py:1158-1168` has no undeclared-layout VAL_BLK asserting sizes `4 and 5`.
- **R-A2L-READ.59/4:** `tests/test_b103_a2l_reader.py:1432-1439` checks lengths of three agreeing pairs but never asserts absence of `declares the` errors; the fourth pair is also absent.
- **R-A2L-READ.59/6:** `tests/test_b103_a2l_reader.py:1158-1168` lacks all four no-datatype-size diagnostic shapes.
- **R-A2L-READ.59/7:** no SYNMAP LENGTH 2264/2266 diagnostic test; `tests/test_b103_a2l_reader.py:1158-1168` covers only simple address/size cases.
- **R-A2L-READ.59/8:** no COM_AXIS SYNMAP external-axis-pass diagnostic; same incomplete function at `tests/test_b103_a2l_reader.py:1158-1168`.
- **R-A2L-READ.68/2:** `tests/test_b103_a2l_reader.py:1259-1281` has no inherited MOD_COMMON/layout invalid-byte-order cases or exactly-once assertions.
- **R-A2L-READ.33/1:** `tests/test_b103_a2l_reader.py:1284-1287` tests only synthetic /2; no six tracked display identifiers or detail-card assertion.
- **R-A2L-READ.63/2:** `tests/test_b103_a2l_reader.py:1218-1230` tests keyword arguments only, not H2e’s header-address diagnostic.
- **R-A2L-READ.61/2:** `tests/test_b103_a2l_reader.py:1416-1429` has none of the five required invalid/missing size-keyword no-length shapes.
- **R-A2L-READ.61/4:** `tests/test_b103_a2l_reader.py:1442-1450` describes LENGTH 0/huge tags, not /1’s first two-LENGTH disagreement tag.
- **R-A2L-READ.61/6:** `tests/test_b103_a2l_reader.py:1416-1429` lacks the four no-datatype-size forms and their no-length assertions.
- **R-A2L-READ.61/8:** no SYNMAP final-refusal sequence for LENGTH 2264/`x4`/2266.
- **R-A2L-READ.61/10:** no external-axis COM_AXIS MAP no-length assertion.
- **R-A2L-READ.48/2:** `tests/test_b103_a2l_reader.py:1634-1644` runs only the 35 tracked files; the **162-shape hostile-corpus differential is absent**.
- **R-A2L-READ.50/2:** `tests/test_b103_a2l_reader.py:1802-1808` never supplies the required two-blank input.
- **R-A2L-READ.50/3:** the same function never asserts that `"one-line header"` retains its quotes.
- **R-A2L-READ.50/4:** the same function never renders V161 or asserts the later-named CHARACTERISTIC summary line.
- **R-A2L-076/3:** `tests/test_b103_a2l_reader.py:1811-1819` has no empty-begin-words MOD_COMMON summary-line case.

## Partial coverage incorrectly marked full — 109 cases

- **R-A2L-READ.1/1,/2,/3:** `tests/test_b103_a2l_reader.py:184-204` compares six tag fields and errors, but not sections or their line numbers.
- **R-A2L-READ.1/4:** `:207-215` checks one address and PROJECT’s two boundaries, not complete tag/error equality and all section line mappings.
- **R-A2L-READ.4/1:** `:278-283` accepts any matching substring; it does not assert exactly one error or `Line 20`.
- **R-A2L-READ.4/2:** `:286-290` filters only `unexpected character` errors instead of asserting the required zero errors.
- **R-A2L-READ.4/4:** `:300-304` checks only one U+FFFD error; the required comment input, exact line, and replacement in XL1’s long identifier are unasserted.
- **R-A2L-READ.4/5:** `:320-330` aggregates three errors per character without per-shape exact messages or line assertions.
- **R-A2L-READ.4/6:** `:333-337` uses `any`, not exactly one `Line 20` diagnostic.
- **R-A2L-READ.5/1:** `:340-343` checks only X’s address, not equality of tags, sections, and errors with the no-BOM reading.
- **R-A2L-READ.5/2:** `:346-351` checks errors and X but never asserts that PROJECT is a section.
- **R-A2L-READ.55/2,/3,/4:** `:374-395` checks only the refusal text, not zero sections and zero tags.
- **R-A2L-READ.56/1:** `:412-420` does not prove absence of a marker at 100 or preservation of the first 100 errors at 101.
- **R-A2L-READ.56/2:** `:423-428` checks length and final marker only, not the first 100 U+00E9 diagnostics.
- **R-A2L-READ.56/3:** `:888-891` checks only 101 entries; no `… 199900 more parse errors`, Workspace cap, or Issues-screen cap.
- **R-A2L-READ.56/4:** `:431-437` omits all `_CappedErrors.extend/insert/__iadd__` refusal assertions.
- **R-A2L-READ.66/1:** `:440-448` covers the parser error only, not the application log line.
- **R-A2L-READ.66/3:** `:466-470` checks a substring without the exact `Line 23` diagnostic.
- **R-A2L-001.2/3:** `:478-491` checks length 8 but not MATRIX_DIM 4.
- **R-A2L-READ.7/1:** `:515-523` checks the address but not that `4026` is a separate word.
- **R-A2L-READ.7/4:** `:526-536` has a comment after the keyword, not glued on both sides of it.
- **R-A2L-READ.7/6:** `:526-536` checks BIT_MASK but not upper limit `65535`.
- **R-A2L-READ.8/2:** `:545-550` never establishes that `c` is an own word of X.
- **R-A2L-READ.9/2:** `:553-558` turns the embedded CRLF into **CR-CR-LF** during `.replace`, so it does not isolate a lone CRLF terminator.
- **R-A2L-READ.10/1:** `:561-566` omits exact `Line 20`.
- **R-A2L-READ.11/1:** `:569-573` omits exact `Line 20`.
- **R-A2L-READ.11/2:** `:545-550` finds any stray-close error, not exact `Line 22`.
- **R-A2L-001.3.2/1:** `:621-628` checks the address but not long identifier `C:\\`.
- **R-A2L-001.3.2/4:** `:631-635` finds any stray `/end`, not the required line-3 diagnostic.
- **R-A2L-READ.13/3:** `:638-649` checks X and absence of Q, but not exactly one tag.
- **R-A2L-READ.14/1:** `:652-667` checks the later BIT_MASK but not that the multi-line string is one word.
- **R-A2L-READ.14/2:** `:670-674` checks the error line but not X’s `end_line`.
- **R-A2L-READ.15/1:** `:677-681` omits exact `Line 22`.
- **R-A2L-001.1/1,/3:** `:700-713` does not assert IF_DATA parentage for /1 or closing line/zero errors for /3.
- **R-A2L-001.1/4:** `:716-724` omits both INSTANCE sections, their equal start/end lines, and both spans.
- **R-A2L-READ.19/1,/2:** `:753-760` checks tags/address but not section-X absence or exact line for /1, nor closing line and `/endX` ownership for /2.
- **R-A2L-READ.54/1:** `:771-785` checks conversion name/method existence only, not raw 5→physical 10 or absence of identity fallback.
- **R-A2L-READ.54/3:** `:788-797` checks length 2 but not the named layout’s FNC_VALUES UWORD.
- **R-A2L-001.4/1,/2:** `:818-823` finds any stray-end error, not exact `Line 30`.
- **R-A2L-001.5/1,/2:** `:826-833` finds message substrings without exact line 23.
- **R-A2L-READ.22/1,/2:** `:836-853` does not assert exactly one include error for /1; /2 excludes only include errors rather than asserting zero errors.
- **R-A2L-READ.64/1,/2,/3:** `:856-869` respectively omits zero tags, zero sections, and the asserted 32 nested sections.
- **R-A2L-READ.65/1,/2:** `:879-885` omits the closed 5,000-level and one-line variants and does not render the 50,000-unclosed result.
- **R-A2L-READ.65/3:** `:888-891` parses but never calls `render_a2l_view`.
- **R-A2L-READ.65/5:** `:894-898` parses/renders but never asserts that the string remains one word.
- **R-A2L-READ.65/6:** `tests/test_b103_a2l_reader_perf.py:209-215` parses only the 600,000-line form; no render and no one-body-line variant.
- **R-A2L-READ.23/5:** `tests/test_b103_a2l_reader.py:926-936` omits datatype, length, and zero duplicate-symbol assertions.
- **R-A2L-READ.25/5:** `:971-984` checks datatype/length but not address `0x1234`.
- **R-A2L-READ.26/3,/4:** `:987-1000` supplies only one /3 reduction and omits /4’s length 2.
- **R-A2L-READ.27/1:** `:1019-1022` itself checks only tag count; the differential/fixture does not cover the required limits and unit fields.
- **R-A2L-READ.27/4:** `:995-997` and `:1011-1013` cover kind/address/deposit, but never little byte order.
- **R-A2L-READ.28/1,/2,/4:** `:1025-1037` omits exact lines; /2’s complete name/kind chain and /4’s length 2 are also unasserted.
- **R-A2L-READ.29/4:** `:1047-1057` checks length 12 but not MATRIX_DIM 6.
- **R-A2L-READ.29/5:** `:1060-1070` checks BIT_MASK and an error, but not absence of own byte order and address.
- **R-A2L-READ.58/1,/2,/3,/5:** `:1123-1155` omits exact lines; /2 does not distinguish the third bare ECU_ADDRESS error, and /5 omits the next-line `3E00` shape and exact per-shape diagnostics.
- **R-A2L-READ.30/1,/3:** `:1082-1089` omits /1’s address and /3’s zero-error assertion.
- **R-A2L-READ.32/1,/2,/3:** `:1100-1113` omits required diagnostic lines; /1 also lacks the exact begin-line disagreeing-address diagnostic.
- **R-A2L-READ.59/1,/2:** `:1158-1168` omits begin-line assertions, and /2 covers only the DATA_SIZE/LENGTH pair out of five required size-disagreement shapes.
- **R-A2L-READ.60/2:** `:1190-1197` checks no address but not preservation of the BIT_MASK word.
- **R-A2L-READ.60/4:** `:1178-1187` covers only duplicate ECU_ADDRESS agreement, not the agreeing header-address and BIT_MASK pairs or their duplicate diagnostics.
- **R-A2L-READ.60/6:** `:1190-1197` checks no address but not the corresponding arity errors.
- **R-A2L-READ.60/8:** `:1140-1155` covers only the SIG_X positive case; eight fail-closed addresses and both Patch Editor routes are unasserted.
- **R-A2L-READ.60/9:** `:1259-1265` covers two own invalid BYTE_ORDER words only; inherited module/layout sources and the holding case are absent.
- **R-A2L-READ.62/1,/2:** `:1208-1215` lacks /1’s associated .28 error for the exact H3c shape and /2’s `deposit is None`.
- **R-A2L-READ.67/1,/2:** `:1240-1249` omits exact lines, and /2 does not assert zero X tags.
- **R-A2L-READ.68/1:** `:1259-1265` checks presence and no address, not exactly one error at the required line.
- **R-A2L-READ.63/1,/3,/4:** `:1218-1230` omits exact echoed words/lines, fullwidth replacement, and /4’s `MATRIX_DIM 2 x 3` shape.
- **R-A2L-READ.69/3:** `:1308-1318` checks no address but not absence of `is not a number`.
- **R-A2L-READ.37/2:** `:1326-1329` checks length 8 but not MATRIX_DIM 4.
- **R-A2L-READ.38/2:** `:1361-1365` omits the ASCII `NUMBER 1000000000000` shape.
- **R-A2L-READ.39/1:** `:1368-1372` likewise omits the ASCII case and all begin-line assertions.
- **R-A2L-013/2:** `:1375-1378` checks length 4 but not absence of `declares the sizes`.
- **R-A2L-READ.61/1:** `:1416-1429` substitutes the LENGTH-surplus case for the required undeclared-layout VAL_BLK, leaving that expected shape uncovered.
- **R-A2L-READ.61/3:** `:1432-1439` omits the agreeing ASCII NUMBER/MATRIX_DIM pair.
- **R-A2L-READ.61/9:** `:1453-1459` covers only LENGTH 0 enrichment, omits `physical_value`, the other three shapes, and both picker routes.
- **R-A2L-READ.48/1:** `:1609-1631` excludes CURVE/MAP axis point counts from comparison, and `:1634-1644` has no ≤120-second assertion.
- **R-A2L-READ.49/2:** `:1776-1783` uses `RL_SWORD`, not required `RL.FNC.SWORD.ROW_DIR`; the D5 reduction therefore no longer excludes deriving size from the layout name.
- **R-A2L-READ.50/1:** `:1802-1808` checks comment removal and one substring, not the complete required A2L Sections line.
- **R-A2L-READ.51/1:** `:1831-1837` finds U+FFFD somewhere but never asserts zero broken summary lines.
- **R-A2L-076/1,/2:** `:1811-1819` checks heading presence, not errors-before-sections ordering.
- **R-A2L-077/1:** `:1822-1828` checks only a tag substring, omitting the complete `mem=unknown` line and errors-before-tags chain.
- **R-A2L-READ.52/1,/2:** `tests/test_b103_a2l_reader_perf.py:110-157` uses least-of-15 in-process timing and best-of-three current-only memory against hard-coded old constants, not median-of-three fresh-process same-session comparisons; no pre-parse RSS or peak-minus-before reporting.
- **R-A2L-READ.52/3:** `:203-215` has the same memory-protocol/RSS-reporting gaps and checks only an error substring, not exactly one `Line 11` diagnostic.

## Matrix integrity

- **R-A2L-READ.51/1:** `02-test-cases.md:298` is malformed: the unescaped regex pipe truncates the expected-result cell and leaves contradictory trailing `gap / not_run` cells after `full / covered / verified`. **MEDIUM / design-gap.** Escape the pipe and repair the row.
- The seven moved Inc 12 rows are **not** counted in this audit; none was found incorrectly included in the in-scope total.
- No ruling covers the 109 partial or 27 missing cases. The E5 AT ruling supports only the two real-app acceptance upgrades.