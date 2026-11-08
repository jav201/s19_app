# E3 correction unit B — Inc 2 test cases (`inc-2/02-test-cases.md` only)

Rules: `design/E3-corr-2-common.md` (read it first). Every new case: Tests empty, Coverage `gap`, Result `not_run`.

## Apply, in `02-test-cases.md`
- Cases for the split and new rows (ids fixed by E3-rulings.md and unit A):
  - R-A2L-DEF.7.2: the fix column's NUMBER `0`, `-5`, `1048577`; ECU_ADDRESS `-0x10`; a span ending above 0xFFFFFFFF.
  - R-A2L-DEF.58.2: one case per hostile-corpus shape of E3S-03's fix column (≥ 14).
  - R-A2L-DEF.136: software_a, all objects, ≤ 2.0 s.
  - R-A2L-DEF.137: NUL and ESC in an enum text and in a name → U+FFFD.
  - The existing cases of .7 and .58 move to .7.1 / .58.1 (rename the keys only).
- New cases named in the fix columns, with their inputs and expected results: .19/4 and a text-with-mask case (E3A-08 / E3S-01), .4/8 (E3A-09), R-A2L-014/def-1 (E3A-10), .46/4 (E3A-11), .26/3 (E3S-05), .45/3 (E3S-06), .54/3 (E3S-07), .54/4 (E3S-09), .21/3 (E3S-10), .40/8 and .40/9 (E3S-11), .59/3 (E3A-15).
- Changed cases: .36/1 expects `0.10000000000000000` (E3A-06); .38/1 and .38/2 become class normal (E3A-04); `%.15` and the typed values join .55's grid (E3A-02); the encode cases .41–.45, .48, .50, .53, .54 state an image that holds the span (E3S-05).
- Update the count lines consistently and append to `inc-2/steps.log`: `<ISO timestamp> E3 correction unit B (cases) — deepseek-v4-pro via pi — <n> cases added, <m> changed`.
