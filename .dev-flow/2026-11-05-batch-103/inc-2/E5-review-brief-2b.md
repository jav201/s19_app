# Inc 2b E5 review brief

Review the actual integration tree on branch `b103-inc2b-code` at `cb083d07` plus its current working-tree tests and case ledger. Product diff: `git diff b73fb886..cb083d07 -- s19_app/tui/a2l_definition.py`. Tests: current `tests/test_b103_a2l_definition.py` and `tests/test_b103_synth_definitions.py`. Approved design: `inc-2/01-requirements.md`, `codewire/graph-inc2.md`, and `E3-rulings.md` final sections.

Verified on <runner>: GREEN 307 passed main + 12 passed synth; final stub RED 114 failed + 193 passed main, 3 failed + 9 passed synth; base collection lacks Encoded and base synth has 3 failures. Law guards and serial_timing are still running and will be supplied later.

Read the implementation critically, especially span-index identity and cross-kind order, CLEAN masks, duplicate names, byte-order sources, numeric vs enum precision, parse-error ordering, image/mask merging, immutable input and exact messages. New strings reach persisted/rendered surfaces: check caps and control handling. Test hostile content, BLOB/INSTANCE and unknown lengths. Check that each negative control is discriminating.

Read-only except your assigned report. Do not edit source, tests, records or steps.log, do not run pytest/probes on Windows and do not run git mutations. Tag every finding `impl` or `design-gap`, give severity and exact file:line/requirement references, and propose a bounded correction. Verdict PASS / PASS-WITH-NOTES / FAIL; MAJOR/HIGH blocks integration. State executed versus read-only checks.
