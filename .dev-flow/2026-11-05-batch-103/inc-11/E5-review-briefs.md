# Inc 11 E5: independent review briefs (Kimi)

Baseline: `f1397097`, clean `b103-inc11-code`. Product slice since `10d01dc1`: `s19_app/tui/a2l.py`, `a2l_definition.py`, `a2l_extract.py`. E4 integration run 6 is GREEN (1017 passed, 4 skipped). AT-B103-I11-2 and AT-B103-I11-3 are now full/covered/verified through the real app.

Shared sources, read only the parts relevant to your role:

- `inc-11/01-requirements.md` and `02-test-cases.md`.
- `inc-11/E1-slice.md`, `E3-rulings.md`, `E4-fix2-rulings.md`, `E4-oracle-rulings.md`, `E5-at-rulings.md`.
- `inc-11/codewire/graph-inc11.md`.
- The three product files above and the changed reader/perf/legacy tests.

No edits, no tests and no commits for the Kimi reviewers. Return findings with severity, `impl` or `design-gap`, exact `file:line`, the requirement affected and the smallest justified correction. Do not manufacture style findings. A reference-oracle disagreement alone is not proof of a product defect. Do not read unrelated batches or the whole repository.

## Code reviewer (Kimi)

Review the product diff for correctness against the approved graph and requirements. Focus on comment/quote/line-end lexing, tree construction, header/keyword arity, address and length bounds, INSTANCE/BLOB spans, error caps, no-regression behavior and the `_describe_one` contract. Check public API and consumer compatibility, including Inc 2a and the two real-app acceptance paths. Return PASS, PASS-WITH-NOTES or FAIL and findings with file:line. No general refactor proposals.

## Security reviewer (Kimi)

Review hostile-input behavior: deep nesting, unterminated strings/comments, NUL/UTF-16, huge words and error floods, control/markup characters, integer overflow and bounded lengths, invalid addresses and byte order, wrong record layouts, partial reads and unsafe consumer assumptions. Include the new UI-visible strings and declared spans. Verify that refusals stay final and cannot be re-derived later. Return PASS, PASS-WITH-NOTES or FAIL and findings with file:line. Do not run probes; this is a read-only review of the existing evidence and code.

## Coverage auditor (Kimi, independent of the test authors)

Audit `02-test-cases.md` against the actual tests. Every in-scope case must be `covered` or ruled and `verified`; every Tests cell must be `full` only when the product route itself produces the asserted observable. Re-check especially the reference-oracle cases, timing rows and AT-B103-I11-2/-3. Identify missing test ids, duplicate ids, assertions that do not test the stated expected result, partial routes incorrectly marked full, and moved Inc 12 rows incorrectly counted. Use static inspection only; do not rerun tests. Return exact counts, PASS/PASS-WITH-NOTES/FAIL and any case id with `file:line`.
