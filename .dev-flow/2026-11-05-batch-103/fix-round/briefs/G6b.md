# Unit G6b — the `-tight` threshold and its canon rows (follow-up of G6)
Your tree is the fix-round tip **c579fa46** (FB-common's "HEAD = main 3afebf90" line does not apply to this unit) PLUS the uncommitted G6 diff (already applied, `git diff` shows it).

Relaunch note (orchestrator ruling on your first run's STOP, 2026-11-19): ids R-A2L-LIST.088/.089 appear only as a stale forward reference in the Inc 7 evidence comment `i7e3r1-layout-pilot.py:11` (those rows were allocated as .082/.083). To avoid any ambiguity this unit uses the fresh ids **.090/.091** (`git grep` finds no use of R-A2L-LIST.09x). Proceed. Keep G6's change. Read `../G6-REPORT.md` first (copied next to this brief): it measured the 80×24 height budget.

## Why (orchestrator design, 2026-11-19, DF-02)
G6 added the class `-tight` on `A2LExplorerBody` when the body is under `TIGHT_BELOW_HEIGHT = 12` rows (`s19_app/tui/a2l_label_list.py`). Canon row R-A2L-LIST.083 promises a tag row only from 15 body rows up. Between 12 and 14 rows the body is not tight, and by G6's own budget (pane border 2, title 1 + margin 1, filter row 4, chips 2, summary 1, plus 1 more in list mode for `#a2l_list_missing`) the tag table can be left with its header only. So:
1. Set `TIGHT_BELOW_HEIGHT = 15` (aligned with R-A2L-LIST.083's 15) and update the constant's comment and the `on_resize` docstring line (cite R-A2L-LIST.090).
2. Add two canon rows to `REQUIREMENTS.md`, right after the `R-A2L-LIST.087` row, same table format (`| id | EARS type | text |`), one `shall` each:
   - `| R-A2L-LIST.090 | While | While the A2L Explorer body is less than 15 rows high, the system shall show the tags pane without its frame and without its title. |`
   - `| R-A2L-LIST.091 | While | While the A2L Explorer body is 9 to 14 rows high, the system shall show at least one tag table row. |`
   Check first with `grep -n "R-A2L-LIST.09[01]" -r .` that neither id exists (if one does, STOP and report).
3. Add three tests to `tests/test_b103_a2l_list_view.py`, right after `test_r_a2l_list_083_3`, reusing `_table_rows_shown` and `_layout` (list mode, fixture `case08`):
   - `test_r_a2l_list_091_1`: 80×24 → `_table_rows_shown(...) >= 1`. Docstring `R-A2L-LIST.091/1: 80x24 (body 9 rows, list mode) -> at least 1 table row.`
   - `test_r_a2l_list_091_2`: the terminal height whose body is 12 rows at 80 columns. **Measure it** (do not assume): print the body height (`app.query_one(A2LExplorerBody).size.height`, or the class the code uses) for 80×25…80×30 in one scratch probe and pick the size with body = 12. Assert `>= 1`. Docstring `R-A2L-LIST.091/2: 80x<H> (body 12 rows, list mode) -> at least 1 table row.` Record the probe output in REPORT.md.
   - `test_r_a2l_list_090_1`: at 80×24 the tags pane has no border and `#a2l_tags_title` is not displayed; at 120×30 the border is present and the title displayed (read `styles.border` / `display` of the widgets; no screen-text guessing). Docstring `R-A2L-LIST.090/1: tight body (80x24) drops the tags pane frame and title; 120x30 keeps both.`

Files you may edit: `s19_app/tui/a2l_label_list.py`, `REQUIREMENTS.md`, `tests/test_b103_a2l_list_view.py`. Nothing else (G6's `styles.tcss` and `tests/test_b99_a2l_encode.py` changes stay as they are).

## Negative controls (scratch copies, paste the RED line)
1. `TIGHT_BELOW_HEIGHT` back to 12 → `test_r_a2l_list_091_2` RED (this is the gap the unit closes; if it stays GREEN, STOP and report the measured table rows at body 12 with threshold 12).
2. Remove the `#a2l_panes.-tight #a2l_tags_pane { border: none; }` rule from `styles.tcss` in the scratch copy → `test_r_a2l_list_090_1` RED.
3. Remove all three `-tight` rules → `test_r_a2l_list_091_1` RED.

## Nodes
- The three new tests and `test_r_a2l_list_083_1/_2/_3` (`-n 0`).
- `tests/test_b99_a2l_encode.py::test_at_b99_09_a2l_window_physical_column` (`-n 0`).
- The whole `tests/test_b103_a2l_list_view.py` (`-n 4`).
- `tests/test_requirements_canon.py` (`-n 0`): the two new rows must pass the canon laws (one `shall`, EARS type matches the text).
