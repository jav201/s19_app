# Inc 2a — E5 rulings (2026-11-07, orchestrator Opus 5.5)

Sources:
- `E5-code-review.md`: FAIL, CR-1 and CR-2 MAJOR.
- `E5-security.md`: FAIL, E5S-01 and E5S-02 MAJOR.

Both reviews ran on the real code at `069171cd`. They agree on the two blocking defects, and both fixes are small.

What holds:
- 37 of 39 scaling paths are flat, and 15 of 15 negative controls are RED.
- The v2 table lookup and the range segment index differ from their oracles in 0 cases over the full corpus and 8,000 hostile tables.
- The .58.2 shapes raise 0 exceptions.
- The closed list of shared kinds holds at describe.

## Rulings

| Finding | Ruling |
|---|---|
| CR-1 = E5S-02 (MAJOR, impl) | **Accept.** Delete the walk-back loop in `_table_value` (`:1336-1339`); one `bisect_left` gives the start of the run of equal x. The security reviewer measured it flat, with 0 of 152,294 hostile pairs differing. New case **.150/10**: a TAB_NOINTP COMPU_TAB with a run of repeated x, flat at 2S and 8S, plus equality with the frozen lookup. Negative control: the loop restored → RED. |
| CR-2 + E5S-01 (MAJOR) + E5S-03 (MINOR) + CR-3 + CR-5 | **Accept, as one rule for numbers in messages.** A number the system writes into a refusal message or a kind text (`<n>`, `<byte length>`, the MATRIX_DIM and address placeholders) is written in decimal (addresses as now) when it is at most 2^64 − 1. Above that, it is written as the .151 echo of its file word. No message can then raise, and no message exceeds 1,024 characters. Extend R-A2L-DEF.151's text to say this; fix the CTX placeholders (CR-3) and the graph's "at most 1,024 characters whatever the file holds". The MATRIX_DIM kind text goes through the same rule (CR-5). Cases: the four E5S-01 shapes (hex LENGTH, DATA_SIZE, NUMBER, MATRIX_DIM of 5,000 digits) → a refusal, 0 exceptions, message ≤ 1,024 characters; the E5S-03 hex-address shapes ≤ 1,024 characters. Negative control: `str(n)` → `ValueError` → RED. |
| CR-4 = E5S-05 (MEDIUM / MINOR) | **Accept: conversion type words are case-sensitive**, as A2L keywords are. A type word that is not exactly one of the known types gets the existing CONVERSION refusal. The verdict and every reader of the type word use the same exact comparison: `:700`, `:708`, `:1179`, `:1415`, `:1420`. Measured: 0 of 560 corpus methods use another letter case, so a silent 0.0 is worse than a refusal. Case: `tab_intp` → the CONVERSION refusal. Negative control: upper-casing kept → 0.0 or 50.0 → RED. |
| E5S-04 (MINOR, impl) | **Accept.** `_walk` becomes iterative (an explicit stack), so deep nesting that the frozen parser still reads cannot raise `RecursionError`. Inc 11 caps nesting at 32 later; Inc 2a merges first. Case: the hostile nesting shape → 0 exceptions. |
| E5S-06 (LOW, design-gap) | **Backlog, not this pass.** Bidi and separator characters (Cf, Zl, Zp) in display texts are a consumer matter: the views render through `safe_text`, the residue is recorded (Inc 12 E3S-04), and the views of Inc 5–9 owe it. Recorded as BL-I2-1. |
| E5S-07 (INFO) | As ruled at E3: no change. |
| CR-6 (MINOR, synth) | Apply the review's fix (`planned_text`). |
| CR-7 (MINOR, test) | Add the missing test the review names. |
| CR-8 (INFO) | Record only. |
| CR-9 … CR-11 (LOW) | Apply: the docstrings and the test helper. |
| **E5-3 (measure)** | **Accept the reviewer's form.** Time `names[1:]` inside one fresh walk, through a generator passed as `names`: each run builds its own walk, and the timer covers only the names after the first. Measured ×0.99–1.02 in 11 of 11 trials, and RED on the per-object mutant (×1.98 / ×7.84). This replaces the "difference of two walks" form in every .149 / .150 timing test. Inc 3a's records are told the same at its next correction. |

## Not run in E5 (owed to the re-review)

- The corpus immutability and order check: the harness's `pickle` hit a recursion limit. Use a non-recursive digest.
- The seeded mutation run, stopped at handback.

## Order

1. Records + graph: Opus.
2. Code (DeepSeek) ∥ tests (Sonnet tester).
3. GREEN.
4. A narrow E5 re-review (code + security) on the changed lines, plus the two runs above.
5. Mutants (DeepSeek).
6. Coverage audit (qa-reviewer).
7. `04-validation.md`, then the merge to `batch-103`.
