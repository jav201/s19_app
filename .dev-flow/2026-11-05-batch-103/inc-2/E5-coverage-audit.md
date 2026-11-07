# Inc 2a — E5 coverage re-audit (independent of the tester)

**Verdict: PASS-WITH-NOTES.** The 2a coverage is complete and correct — every 2a case has a test that
asserts its Expected, every Coverage mark is justified, and the mutant tables show 63/64 controls killed
(the 1 non-killed control is the 2b encode arm of .58.1, not realisable on the read side). Two record
defects do not change any coverage mark: the Result column of the 181 E4-era cases still reads `not_run`
while those tests are GREEN, and the split tally is off by one (.59/4 untallied).

Mode: validation (read-only; nothing was run on this PC). Auditor: qa-reviewer (deepseek-v4-pro).
Inputs: `02-test-cases.md` (325 case rows; the split's own counts say 324), `tests/test_b103_a2l_definition.py`
(191 tests), `tests/test_b103_a2l_definition_perf.py` (22 tests), `tests/test_b103_synth_definitions.py`
(9 tests), and the GREEN transcripts `evidence-e5/fix-tests-*.txt`, `evidence-e5/gap2-tests-*.txt`,
`evidence-e4/int-green-run2.txt`, `evidence-e4/tests-red-base-synth.txt`.

## Counts

| Result | Cases |
|---|---|
| Agree with the tester (`covered` / `partial`) | 216 |
| Changed to `partial` | 0 |
| Changed to `gap` | 0 |

The 2b cases (109) stay `gap` / `not_run` by design — verified: every 2b row has an empty Tests cell,
Coverage `gap` and Result `not_run` (`.19/6-8,/10-23`, `.25/2`, `.26/2-4`, `.40-.57`, `.138`).

## What was checked

- **Test existence (all 216 2a cases):** each `::test_*` name in the Tests column resolves to a defined
  function in one of the three files; 0 missing. 5 cases legitimately name >1 test (.136/1, .149/1-4).
- **Assertions match Expected:** the perf file's scaling cases assert the E5-3 measure (one fresh walk,
  generator, least-of-31 interleaved rounds, x2S ≤ 1.5, x8S ≤ 2.0, message ≤ 1,024, shared-form identity
  via `id(...)`); `.150/7`/`.150/10` pin the frozen `_apply_compu_method`/`_table_lookup` as oracle;
  `.149/5` writes into each form and asserts TypeError/AttributeError; `.150/6`/`.150/9` probe every
  corpus/hostile table against a test-local verbatim oracle and require ≥100 tables/≥5,000 values with
  0 diffs; `.151/*` and `.58.2/18-24` assert the exact refusal messages and the 1,024-char bound; the
  synth `.59/.60-63` pin the case-08 digests and the planned texts. No mismatch found.
- **Coverage marks:** 194 `covered` (full) + 22 `partial`. The 22 are exactly the 21 arm-waiting cases
  (`.21/3`, `.136/1`, `.58.1/1-2`, the 15 `.58.2` encode-arm cases `/1-5,/7-15,/17`, `AT-B103-I2-1/-2`)
  plus `AT-B103-I2-3` (its "22 case files" is 11-checked here; the 10 MiB half is the slow `.59/2`).
- **Mutant tables:** unit A 50 killed + 1 not realisable (`.58.1`, the 2b encode arm); unit B 13 killed
  (incl. second controls M-59b = CR-6 `planned_text`, M-149b = CR-7 `compare=True`). Total 64 controls,
  63 killed, 1 not realisable — matches the brief.
- **Result column vs GREEN:** the 35 post-E4 cases carry `executed: RED … GREEN …`; the 181 E4-era cases
  still read `not_run`.

## Disagreements (record defects; fixes are column edits, no mark changes)

1. **HIGH — `02-test-cases.md`, Result column of the 181 E4-era rows** (e.g. `R-A2L-DEF.1/1` at
   `02-test-cases.md:17`, and every other E4 row through line 351): still `not_run`, but GREEN —
   `evidence-e4/int-green-run2.txt` (182 passed) and `evidence-e5/fix-tests-green-main.txt` (199 passed,
   1 deselected) cover the model cases, `fix-tests-green-main.txt` covers the synth cases, and
   `evidence-e4/tests-red-base-synth.txt:96` shows `.59/2` PASSED on base (by design). Fix: set Result to
   `executed: GREEN on <transcript>` for each of the 181 rows (the tester, who owns the column, back-fills).
2. **MINOR — `02-test-cases.md:388` and `:390`:** the split reads "2a: 215 cases" and "Total: 324 cases",
   but the table holds 216 2a / 325 total. `.59/4` (CR-6's seeds test, added by the fix-pass tester in
   `26d3e309`, killed by M-59b) is real but untallied. Fix: "2a: 216" and "Total: 325" (or add `.59/4` to
   the fix-pass list on line 390).

## Notes that do not change a mark

1. **INFO — private helpers in `.149/5`, `.150/6`, `.150/9`.** These three use `_read_method_record`,
   `_read_enum_table`, `_enum_entry_text`, `_enum_text`, `_table_value`, `_name_echo`, `_table_form` and
   stay `covered`/full. The E4 rule ("a test that needs a private helper is `partial`") does not apply:
   each case's Expected column names the private symbol, so black-box testing is impossible by design.
2. **INFO — `AT-B103-I2-3` `partial`.** Marked `(partial)` though the split calls it "the whole case";
   correct because the test checks 11 of the 22 pin files and the 10 MiB half lives in the slow `.59/2`.

## Coverage values to apply

All 216 2a rows keep their Coverage mark (`covered` 194 / `partial` 22). Apply only the two column
edits above. No case moves to `partial` or `gap`.
