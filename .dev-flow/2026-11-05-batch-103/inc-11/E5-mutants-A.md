# Inc 11 E5: mutants A — lexer and section tree (DeepSeek)

Baseline `f1397097`. Work only in a fresh copy under `/tmp/b103-e5-11-mutA`; never mutate the local worktree. Do not commit or edit product/tests/records in the real worktree.

Read the negative controls in `inc-11/01-requirements.md` for R-A2L-001.1 through .5, R-A2L-READ.1 through .22, .54 through .56 and .64 through .67, plus the relevant graph nodes `_lex_a2l_lines`, `_lex_a2l_words` and `_build_section_tree_into` in `s19_app/tui/a2l.py`.

Build a table before running: requirement, mutation, exact unique anchor, expected discriminating test, applied count and verdict. Cover comments, quoted strings and escapes, CR/CRLF, BOM/NUL, one-line sections, nesting cap, `/include`, error caps and malformed `/begin`/`/end`. Do not mutate a guard without naming the observable that becomes wrong. A mutation that applies zero times is BAD, not SURVIVED.

Run the baseline first. Apply one mutation at a time, restore it, and run the smallest test node(s) that prove it, from the correct tree cwd. Use `PYTHONDONTWRITEBYTECODE=1`, closed stdin and isolated environment. Record KILLED / SURVIVED / CRASH / BAD separately. Assert the applied count equals the table count. Keep a known-bad control so the harness itself is proven able to fail. Do not count a process exit code alone as proof per arm.

After all mutants are restored, prove the copied tree green. Save `inc-11/evidence-e5/mutant-table-A.md` and the complete runner transcripts under `inc-11/evidence-e5/mutants-A/`, then remove only `/tmp/b103-e5-11-mutA*`. Report totals, every survivor with its requirement and evidence, and any test gap. Do not change source to kill a survivor; the orchestrator rules it. Do not use proprietary A2L material or the OS clipboard.
