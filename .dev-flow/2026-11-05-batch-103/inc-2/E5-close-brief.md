# Inc 2a E5 close: write `04-validation.md` (DeepSeek v4 Pro)

Worktree `C:\Users\jjgh8\Github\s19_app-b103-inc2a-code`, folder `.dev-flow/2026-11-05-batch-103/inc-2/`.

1. **Write `inc-2/04-validation.md`** with the sections and tone of Inc 4's record. That record is read-only: `C:\Users\jjgh8\Github\s19_app-b103\.dev-flow\2026-11-05-batch-103\inc-4\04-validation.md`. Take every fact from these sources in this folder:
   - `E5-rulings.md`
   - `E5-code-review.md`
   - `E5-security.md`, both rounds
   - `E5-coverage-audit.md`
   - `evidence-e5/mutant-table-{A,B}.md` (63 killed, 0 survived, 1 not realisable)
   - `evidence-e5/fix-tests-*.txt`, the final GREEN: main + synth 199 passed; perf 22 passed in each of 3 runs
   - `E3-rulings.md`, the gap passes

   Give the verdict with its reason. List the open notes: BL-I2-18, E5S-08, E5S-09, CR-8, the 2b arms, and the Windows / full suite owed at the batch end. Do not invent any number.
2. **Evidence for the trace checker.** The checker links only paths that contain an `evidence/` folder segment.
   - Copy the decisive transcripts into the batch folder `.dev-flow/2026-11-05-batch-103/evidence/inc-2/`: the final GREEN main, the 3 perf runs, the two mutant tables, `sec-e5r2` census and mutation, and the coverage audit.
   - Cite them from `04-validation.md` as `` `../evidence/inc-2/<file>` ``.
   - Never write any other backticked path that holds `evidence/` followed by `…`, `...` or a bare folder: the checker treats it as a citation.
3. **SLICE check.** Make sure `inc-2/01-requirements.md` names every source file changed since `e07fb00`: `s19_app/tui/a2l_definition.py` and `tools/synth/make_release_case.py`. If one is missing, add it in one line of the header, the way Inc 4 did.
4. Add one line to `inc-2/steps.log`. Do not commit. Run no tests and nothing that imports `s19_app`. Never write the operator's name.

Report in at most 100 words: the files you wrote and the verdict.

5. **Fix the two record defects found by the coverage audit** (`E5-coverage-audit.md`), changing columns only:
   - In `02-test-cases.md`, set the Result column of every 2a row that reads `not_run` but is GREEN in `evidence-e4/int-green-run2.txt` or `evidence-e5/fix-tests-green-main.txt` to the result the transcript shows.
   - Correct the split tally to 2a 216 / total 325, which adds `.59/4`.
   - Keep every table's column count, and record `wc -l` before and after.
