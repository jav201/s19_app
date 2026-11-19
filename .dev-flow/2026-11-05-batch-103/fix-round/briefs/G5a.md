# Unit G5a — obsolete oracles after approved Inc 11/12 rules (R2-F11)
Each requirement change below was approved; the tests still assert the old behaviour. Re-pin each test to the current rule and cite the row (id + `REQUIREMENTS.md` line) in its docstring.
1. `tests/test_a2l_f841_cleanup.py -k at094`: `assert 25 == 24` — the added length is V161 `ASAM.M.VIRTUAL.SCALAR.SWORD.PHYSICAL` None→2 under R-A2L-READ.49 (listed in `.dev-flow/2026-11-05-batch-103/inc-11/evidence-e1/e1-fx-defects.jsonl`); re-pin to 25.
2. `tests/test_a2l_inline_axis_length.py -k tc136`: explicit `LENGTH 999` against layout 13 now gives no length (R-A2L-READ.61); re-pin.
3. `tests/test_b103_a2l_reader.py -k at_b103_i11_2`: one row as required, but column 0 is now the address (`['0x00001234']`) after the Inc 12 column order; read the name by its column LABEL, not by index.
Files you may edit: the three test files.
Negative controls: in a scratch copy revert the corresponding reader rule (or restore the old column order) → each re-pinned node RED.
Nodes: the three `-k` selections (`-n 0`), then the three whole files (`-n 4`).
