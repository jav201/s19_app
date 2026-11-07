# Inc 4 - E5 coverage re-audit (independent of the tester)

Mode: validation (read-only; no test was run on this PC). Auditor: qa-reviewer (claude-sonnet-5-5). Inputs: `02-test-cases.md` (120 cases), `tests/test_b103_label_match.py` (G-T1, 129 items GREEN in `evidence-e4/int-green-behaviour.txt`), `tests/test_b103_label_match_perf.py` (7 items GREEN, 78 bounds, 0 under 20 % margin, `evidence-e4/int-green-perf.txt`; executed by the E4 integrator on cachyos-rtx, not by me).

## Counts

| Result | Cases |
|---|---|
| Agree with the tester (`full` / `covered`) | 120 |
| Changed to `partial` | 0 |
| Changed to `gap` | 0 |

Item arithmetic checked: 83 parametrised whole-list items (`test_ranked_list_is_exactly`, id = case id) + 21 relational tests + 9 AT items + 16 I-3 interface tests = 129 = the green count. The 83 + the relational tests cover the 113 G-T1 coverage items; G-T2 covers .35/1, .36/1, .37/1, .40/1, .40/2.

## What was checked, per group

- **Whole-list cases (83, parametrised):** every parameter tuple carries its own case id, list key, query, limit and expected list; I compared each expected list (names, rule word, edits, spans, order) with the row's text. No mismatch. Non-ASCII inputs (`Drück_Max`, `DRÜCK_MAX`, `٣٣٣_X`, `٣٣٤`) are the same code points in the test and in the row. Expected values are literals or shared constants equal to the row (R_0001 = .7/1 = .14/2 = .18/2 = .25/2; R_VALUE_000 = .14/1 = .17/2 = .18/1 = .20/1); nothing is read from the implementation.
- **Relational cases (.5/3, .12/1-2, .18/1-2, .20/1, .20/3, .23/1, .24/1, .24/3, .25/1-2, .26-.31, .32/2, .33/1, .34/2-3):** each asserts the row's property on the real `rank` output (span tuples, entry position, rule sequence, edits). `.34/2` is a real offset-order check (query order `blk val 00` differs from offset order). Several rows share one test (.26, .27, .29, .30, .31, .34); every row's assertion is present, but a failure of the first masks the later ones (INFO below).
- **AT-B103-I4-1:** the seven steps carry the row's queries, limit 5, k = 1,2,3,4,6, the `map_002` three-entry list and the `map_0020` exact entry, on one prepared list. **AT-B103-I4-2:** eight parametrised queries, SWA, limit 5, entry 1 compared on name, rule, edits and spans against the row.
- **Perf (G-T2):** fixtures match the case text. REF is built as stated (4 x SWA, first 50,000, uniqueness asserted); REF6 is 50,000 names of 13 characters (asserted); LONG is 49,900 + 100 names of 1,022/1,023 characters (asserted). QSET has 33 queries (22 + 3 + 8, asserted); PSET over REF has 6 shapes and over REF6 15 + the 8 E3S-01 shapes, each with `len <= 256` asserted. `LONGEST_REF_NAME` is 103 characters and is asserted to be in REF. Statistic and bound: median of 3 for .35 (<= 5.0 s), median of 7 per query for .36 (<= 200 ms) and .40 (<= 1.0 s), tracemalloc peak <= 67,108,864 B for .37 (no `serial_timing`, as the row says). The index is built before the clock in .36/.40; `build_label_index` has no cross-call cache (grep: only a per-call `_prefix_distance` memo), so the 3 preparations of .35 and the 7 repeats of a ranking are real work. The transcript shows bounds 0.200 s / 1.000 s, so `CI` was unset and `timing_bound` did not double them.
- **Private names:** none of the 120 cases' tests imports or touches a private name; `.names`, `len(index)` and the dataclass fields used are the public I-3 surface. The `test_i3_*` tests are interface checks outside the 120 cases.

## Changed cases

None. (A table of changed cases would be empty; the corrected Coverage values to apply are therefore the existing ones: `covered` for all 120 cases, with each test mark staying `(full)`.)

## Notes that do not change a mark (for the orchestrator)

1. **INFO - no product route calls the matcher yet.** `grep label_match s19_app` outside the module finds no caller; the consumer arrives in a later increment. The rule "an entry point no product route calls makes it partial" read literally would turn all 120 cases (not only the two ATs) to partial, which would not discriminate. I kept `full` because every case, including AT-B103-I4-1/-2 ("through I-3"), names I-3 as its surface. The orchestrator should rule this once; the user-level AT through keys and dialogs belongs to the increment that wires the matcher. Tag: `design-gap` (the AT wording "typing keystroke by keystroke" is at the service level only).
2. **INFO - empty-result cases are not self-discriminating.** `tests-red-stub.txt` shows 34 items passing against a stub that returns empty results (the `[]` cases .2/1-5, .11/1-3, .12/3, .13/2, .13/4, .15/1, .19/1-2, .38/2, .39/2 and the I-3 checks). Their sensitivity rests on the E5 mutant table (`E5-mutants-A.md`, `E5-mutants-B.md`: their results are not in the tree yet). If a negative control for one of them survives, that case drops to `partial`.
3. **INFO - bound under `CI`.** `timing_bound` doubles .36/.40 to 400 ms / 2.0 s when `CI` is truthy; the evidenced run had it unset. Keep the evidence run on the reference host without `CI`.
4. **INFO - shared tests.** A failing first assertion hides the later rows in `test_rows_26/27/29/30/31/34`. Fix (optional): split per row. Tag: `impl` (test style).
5. **INFO - fixture trust.** `LONGEST_REF_NAME` as the 27-token name and the REF6 "51 typos that start no REF6 token" filter are not re-derived by the test (the filter removes nothing on REF6's tokens CHAR/MEAS/00000/00; the length 103 matches). Low risk.

## Coverage values to apply

All 120 rows of `02-test-cases.md` keep Coverage = `covered` and their `(full)` / `(full; bound valid on cachyos-rtx only)` marks. Re-open only if note 1 is ruled otherwise or a mutant in note 2 survives.
