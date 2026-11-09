# Inc 11 E5: mutants B — tags, lengths and declared spans (DeepSeek)

Baseline `f1397097`. Work only in a fresh copy under `/tmp/b103-e5-11-mutB`; never mutate the local worktree. Do not commit or edit product/tests/records in the real worktree.

Read the negative controls in `inc-11/01-requirements.md` for R-A2L-013 through .017 and R-A2L-READ.23 through .53, .57 through .63, .68 and .69, plus `_tag_header`, `_tag_keyword_lines`, `_number_word`, `_tag_sizes`, `extract_a2l_tags`, `extract_declared_spans` and `_describe_one` in the Inc 11 slice.

Build a table before running: requirement, mutation, exact unique anchor, expected discriminating test, applied count and verdict. Cover header boundaries and arity, keyword case, number/address bounds, byte order, sizes that stop agreeing, refused lengths staying final, CURVE/MAP refusal, forward typedefs, unresolvable deposits, BLOB/INSTANCE bounds, public export and `_describe_one` not refilling a missing length. Do not mutate a guard without naming the observable that becomes wrong. A mutation that applies zero times is BAD, not SURVIVED.

Run the baseline first. Apply one mutation at a time, restore it, and run the smallest test node(s) that prove it, from the correct tree cwd. Use `PYTHONDONTWRITEBYTECODE=1`, closed stdin and isolated environment. Record KILLED / SURVIVED / CRASH / BAD separately. Assert the applied count equals the table count. Keep a known-bad control so the harness itself is proven able to fail. Do not count a process exit code alone as proof per arm.

After all mutants are restored, prove the copied tree green. Save `inc-11/evidence-e5/mutant-table-B.md` and the complete runner transcripts under `inc-11/evidence-e5/mutants-B/`, then remove only `/tmp/b103-e5-11-mutB*`. Report totals, every survivor with its requirement and evidence, and any test gap. Do not change source to kill a survivor; the orchestrator rules it. Do not use proprietary A2L material or the OS clipboard.
