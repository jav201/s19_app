# Batch-103 "G3 fix round" (relevo-17, 2026-11-19)

Why: the independent review of 2026-11-19 (R1/R2) found that batch-103's G3 "PASS-WITH-NOTES" was self-declared on a red suite; R2 section 6 grouped the `main` failures into root-cause groups G1-G12. This round fixes them on branch `b103-fix-round` (from `main` 3afebf90). Operator verdicts: decision page relevo-17 (D4 = fix C-7, D5 = fix 80x24, D9 = relabel G3 BLOCKED until the close suite after this round).

Method per unit: fixed diagnosis -> DeepSeek v4-pro worker on a Linux lab host (one unit, scoped nodes only, negative control per changed row) -> independent Sonnet tester (diff hygiene, intent vs requirement row, GREEN vs the base RED transcript, re-applied negative controls, six law files vs the base-red set) -> orchestrator integration. Briefs: `briefs/FB-common.md` (worker rules) and the checker brief (kept outside the repo: it names lab hosts, RL-06). Verdicts: `checks/`.

Base-red law set at 3afebf90 (accepted until its own unit lands): canon two-`shall` rows (G7), address census AT-B83-08 (G3c), `test_r_tst_070_2` (inherited evidence paths; records unit).

| unit | root cause (R2) | files | worker | checker verdict | commit |
|---|---|---|---|---|---|
| G5a | F11 obsolete oracles after approved Inc 11/12 rules (R-A2L-READ.49/.61, Inc 12 column order) | tests/test_a2l_f841_cleanup.py, tests/test_a2l_inline_axis_length.py, tests/test_b103_a2l_reader.py | deepseek-v4-pro (high) | GO (`checks/check-G5a.md`): 3 base-RED -> GREEN, 202 passed / 1 skipped, 3/3 negative controls RED, laws = base-red set | this commit |
| G5b | F11 TC-718 limb (R-A2L-READ.61) and hostile-name fixture cut at `//` by the A2L comment rule (P-057) | tests/test_changes_symbol_entries.py, tests/test_b97_check_editor.py | deepseek-v4-pro (high) | GO (`checks/check-G5b.md`): 3 base-RED -> GREEN, 82 passed, controls RED, laws = base-red set; hostile name keeps control char, markup, link and click action (only the `https://` scheme dropped) | this commit |
| G3a | F8 busy-seam tests patched seams the batch-103 refactor replaced (`_apply_prepared_load`, `_start_a2l_load`, `_complete_prepared_load`) | tests/test_b100_busy.py | deepseek-v4-pro (high) | GO-WITH-NOTES (`checks/check-G3a.md`): 3 base-RED -> GREEN, file 117 passed, 2/3 re-pins killed by re-applied controls (the `_complete_prepared_load` end re-pin is not exercised by a control: MINOR), laws = base-red set | this commit |
