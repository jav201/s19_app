# E5 coverage audit — Inc 2a (DeepSeek v4 Pro; the Sonnet run hit its weekly limit)

**Rules:** `C:\Users\jjgh8\Github\s19_app-b103\.dev-flow\2026-11-05-batch-103\design\E5-brief-common.md`, with N = 2 and role `coverage`. Read it first.

**Shape:** follow Inc 4's audit as a read-only example:
- the brief, `C:\Users\jjgh8\Github\s19_app-b103\.dev-flow\2026-11-05-batch-103\inc-4\E5-coverage-audit.md`;
- the output it produced, which is under `inc-4/` in the same folder.

**Scope.** Audit only the **2a** cases of `inc-2/02-test-cases.md`, as its section "Split (amendment A2)" divides them. The 2b cases stay `gap` / `not_run` by design. For each 2a case, check four things:
1. A test exists, as the Tests column names it.
2. The test asserts what the case's Expected column says. Read the test code in `tests/test_b103_a2l_definition*.py` and `tests/test_b103_synth_definitions.py`.
3. The `full` / `partial` value in the Coverage column is justified.
4. The Result column matches the latest GREEN transcripts: `inc-2/evidence-e5/fix-tests-*.txt` and `gap2-tests-*.txt`.

Cross-check against the mutant tables `inc-2/evidence-e5/mutant-table-{A,B}.md`: 64 controls, of which 63 were killed and 1 is not realisable (the 2b arm of .58.1).

This audit is read only. Run no tests at all, and never on this PC.

**Output:** write `inc-2/E5-coverage-audit.md` with:
- the verdict first (PASS / PASS-WITH-NOTES / FAIL);
- the counts of agree / partial / gap;
- each disagreement with its case id, `file:line` and the fix (a column edit, or a missing assert).

Add one start line and one end line to `inc-2/steps.log`. Do not run git commands that write. Never write the operator's name.

**Report:** at most 120 words.
