# check-G5a — verdict: GO

Diff saved: `frontB\diffs\G5a.diff` (LF). Checked on rtx copy of `~/work/zq-fb/G5a/repo` (copies deleted).

| # | Check | Evidence |
|---|---|---|
| 1 | Diff hygiene | chkdiff: files=3, CR=0, skipadd=0, no def removed. Files: tests/test_a2l_f841_cleanup.py, tests/test_a2l_inline_axis_length.py, tests/test_b103_a2l_reader.py (= brief's allowed set) |
| 2 | Intent | at094 24→25 (R-A2L-READ.49, REQUIREMENTS.md:884); tc136 999→None (R-A2L-READ.61, :896, row text: sizes disagree → no length); i11_2 reads Tag/Address by column label (R-A2L-006.1, :1010, column order). All three rows opened and match the brief. No assertion loosened; i11_2 still asserts names==["X"] and address 0x00001234. |
| 3 | GREEN | three `-k` nodes (-n 0): 1 passed each. Three files (-n 4): 202 passed, 1 skipped (base: 3 failed, 199 passed, 1 skipped; the 3 base-RED nodes are now GREEN, none new RED). |
| 4 | Negative controls | Re-applied all 3 in a scratch copy: a2l.py:3777 `if no_number:` -> tc136 RED (`assert 13 is None`); a2l.py:834 `in_comment = False` -> i11_2 RED (test_b103_a2l_reader.py:1955); a2l.py:3520 datatype revert -> at094 RED (`0 = len([])`, :116). |
| 5 | Laws | six files serially: 3 failed, 112 passed, 2 skipped = baseline (r_tst_070_2, canon two-shall, address census). All three are in the allowed base-red set; no other law RED. |
| 6 | Worker claims | Verified: file list/stat, CR=0, 202 passed/1 skipped, the three RED lines, both deviations (i11_2 mutation choice is valid: label-based read is column-order independent). No false claim. |

Notes: at094's negative control is a broad mutation (count goes to 0, not 24); acceptable, disclosed by the worker (Deviation 2). Test timing: file run 124 s here vs 192 s in the worker report (no issue).
