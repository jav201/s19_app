# Unit G6c — scope R-A2L-LIST.091 to text mode, add .092 for list mode (finish G6b)
Your tree is a COPY of G6b's tree: fix-round tip **c579fa46** (FB-common's "HEAD = main 3afebf90" line does not apply) + G6's diff + G6b's edits, all uncommitted. Keep them. Read `../G6b-REPORT.md` (copied next to this brief) first: its body-height probe is the fact base.

## Orchestrator ruling on G6b's STOP (2026-11-19, DF-02)
Measured by G6b: in list mode the chips are 3 rows and the missing line 1, so at 80×24 (body 9) the tag table keeps only its header, even in the `-tight` body; from body 10 (80×25) list mode shows ≥ 1 tag row. Text mode at 80×24 shows header + 2 rows (G6). Whether list mode at 80×24 should sacrifice another line is an operator question (round-3 page), not this unit. So:
1. `REQUIREMENTS.md`: replace the text of the `R-A2L-LIST.091` row with
   `| R-A2L-LIST.091 | While | While the A2L Explorer body is 9 to 14 rows high and the viewer is in text mode, the system shall show at least one tag table row. |`
   and add right after it
   `| R-A2L-LIST.092 | While | While the A2L Explorer body is 10 to 14 rows high and the viewer is in list mode, the system shall show at least one tag table row. |`
   (check first that `R-A2L-LIST.092` appears nowhere: `git grep -n "R-A2L-LIST.092"`; if it does, STOP.)
2. `tests/test_b103_a2l_list_view.py`:
   - rename `test_r_a2l_list_091_1` to `test_r_a2l_list_092_1`, size **80×25** (body 10, per G6b's probe), docstring `R-A2L-LIST.092/1: 80x25 (body 10 rows, list mode) -> at least 1 table row.`;
   - rename `test_r_a2l_list_091_2` to `test_r_a2l_list_092_2` (80×27, body 12, unchanged assertion), docstring `R-A2L-LIST.092/2: 80x27 (body 12 rows, list mode) -> at least 1 table row.`;
   - leave `test_r_a2l_list_090_1` as G6b wrote it.
   (These names are new in this uncommitted unit, so renaming them is allowed here; no committed test is renamed.)
3. `tests/test_b99_a2l_encode.py`: in the comment above G6's `assert table.region.height >= 2`, add the citation `R-A2L-LIST.091 (text mode, body 9 at 80x24)`. Change nothing else in that file.

Files you may edit: `REQUIREMENTS.md`, `tests/test_b103_a2l_list_view.py`, `tests/test_b99_a2l_encode.py`.

## Negative controls (scratch copies, paste the RED line)
1. `TIGHT_BELOW_HEIGHT` back to 12 in `s19_app/tui/a2l_label_list.py` → `test_r_a2l_list_092_2` RED (body 12 not tight → header only).
2. Remove all three `-tight` rules from `styles.tcss` → `tests/test_b99_a2l_encode.py::test_at_b99_09_a2l_window_physical_column` RED (`no tag row paints at (80, 24)`).
3. Remove `#a2l_panes.-tight #a2l_tags_title { display: none; }` → `test_r_a2l_list_092_1` RED (if it stays GREEN, report the measured rows; do not change the test).

## Nodes
- `tests/test_b103_a2l_list_view.py::test_r_a2l_list_092_1`, `::test_r_a2l_list_092_2`, `::test_r_a2l_list_090_1`, `::test_r_a2l_list_083_1`, `::test_r_a2l_list_083_2`, `::test_r_a2l_list_083_3` (`-n 0`).
- `tests/test_b99_a2l_encode.py::test_at_b99_09_a2l_window_physical_column` (`-n 0`).
- The whole `tests/test_b103_a2l_list_view.py` (`-n 4`), `tests/test_requirements_canon.py` (`-n 0`).
