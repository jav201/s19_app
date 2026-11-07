# Inc 11 E4: implementation fix pass (DeepSeek v4 Pro, implementer role)

Worktree `C:\Users\jjgh8\Github\s19_app-b103-inc11-code`, branch `b103-inc11-code`. Integration run 2 is **not GREEN**. Read the report `inc-11/evidence-e4/int-run2-report.txt` and every transcript in `inc-11/evidence-e4/int-green2-*.txt`. Your rules are those of `inc-11/E4-handoff-impl-11.md`: the same 3 source files, and the design pinned by `codewire/graph-inc11.md` and `E3-rulings.md`.

Fix every failure the report classes as **implementation**:
1. The **hang**: `_split_line_respecting_quotes` loops forever (`a2l.py:1093/1106`), because `\n` is not in `_BLANKS`.
2. The 15 reader mis-reads.
3. **READ.52 time and memory.** The run measured 11.93 s, or 2.02× against the ≤ 1.5× bound, and a peak RSS of 6.28 GB, or 12× the base. The lexer must stream per line, as the graph's DE-10 says. Do not build the whole file's word list at once. Use one compiled regex per line, as the E3 ruling on READ.52 states.
4. The 49 tag-count mismatches. The tester's fixture holds the reference tags (`tests/fixtures/b103_i11/e07fb00_tags.jsonl`); find out which side departs from the rows. If it is the test, list it for the tester and change nothing.
5. The MEMORY_SEGMENT regression in `test_b101_a2l_blocks_and_segments.py:371`.
6. The 24 failures in Inc 2a's tests (`a2l_definition.py` changed). Each of them must pass again unless one of Inc 11's rows changes it on purpose; in that case, name the row.

On this PC run only `py_compile` and the code-wire extractor; run no other Python. To verify, update `/home/javiergr/work/b103-int11` on cachyos-rtx with a bundle of your **committed** branch. Commit as `batch-103 Inc 11 E4: implementation fixes after integration (DeepSeek)` with `Co-Authored-By: DeepSeek V4 Pro`. Then re-run (a), (b) and (c) of `E4-integration-brief.md` the Run-2 way (nohup and polling, `-n 8`), and after them (d). Save the results as `int-green3-*.txt` and commit them.

Do not edit any test file. Write a list of the test faults in `inc-11/evidence-e4/test-faults.md` for the tester pass.

**Report** (≤ 150 words): what you fixed, the counts per run, the READ.52 ratio and peak memory, and what still fails, with its cause.
