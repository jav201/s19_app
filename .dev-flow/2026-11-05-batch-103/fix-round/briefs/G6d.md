# Unit G6d — list mode at 80×24: hide the position line so a tag row paints (operator verdict I = A)
Your tree is the fix-round tip **2a8ab75f** (FB-common's "HEAD = main 3afebf90" line does not apply; `git rev-parse --short HEAD` must print `2a8ab75f`, else STOP). G6 is integrated there: `-tight` class below 15 body rows (`s19_app/tui/a2l_label_list.py`, `TIGHT_BELOW_HEIGHT`), canon rows R-A2L-LIST.090/.091/.092.

## Fact base (measured by G6b/G6c; re-check with your own probe before row 1)
In list mode the chips are 3 rows and the missing line 1. At 80×24 the Explorer body is 9 rows; even `-tight`, the tag table keeps only its header. From body 10 (80×25) list mode shows ≥ 1 tag row. Text mode at 80×24 shows header + 2 rows.

## Operator verdict (2026-11-19, PENDING P-191, card I = A)
When the body is < 10 rows **and** the viewer is in list mode, hide the position line under the table (`#a2l_tags_summary`, text `LIST  rows <a>-<b> / <n> in pasted order`). The counts stay visible on the first chips line. Text mode is not changed.

## Fixed design (orchestrator; do not redesign)
| row | change | proof |
|---|---|---|
| 1 | `s19_app/tui/a2l_label_list.py`: add `TINY_BELOW_HEIGHT = 10` next to `TIGHT_BELOW_HEIGHT`, with a `#:` comment citing R-A2L-LIST.093; in the method that calls `self.set_class(self.size.height < TIGHT_BELOW_HEIGHT, "-tight")` add `self.set_class(self.size.height < TINY_BELOW_HEIGHT, "-tiny")` and one docstring bullet (`-tiny` exactly when height < 10; R-A2L-LIST.093) | read back |
| 2 | `s19_app/tui/app/a2l_view.py`, `_paint_a2l_filter_chips`: right after `names = self._a2l_list_names()`, mark the body with `-list` exactly in list mode: `panes = self.query("#a2l_panes")` then, if found, `panes.first().set_class(names is not None, "-list")`. Add one line to its Summary/Returns docstring naming the `-list` class (R-A2L-LIST.093). Before editing, check that `_paint_a2l_filter_chips` runs both when list mode starts and when it ends (grep its callers; report them). If it does not run when list mode ends, STOP and report. | test row 4 (093_2) |
| 3 | `s19_app/tui/styles.tcss`: after the three `#a2l_panes.-tight …` rules add `#a2l_panes.-tiny.-list #a2l_tags_summary { display: none; }` with a one-line comment (R-A2L-LIST.093, operator I = A). Also fix G6's stale comment above those rules: "under 12 body rows" → "under 15 body rows". | read back |
| 4 | `REQUIREMENTS.md`: the three canon edits in the block "Row 4 texts" below. First check that `git grep -n "R-A2L-LIST.093"` finds nothing (else STOP) and that each "current" line is byte-equal in the canon (else STOP that edit) | `tests/test_requirements_canon.py` GREEN |
| 5 | `tests/test_b103_a2l_list_view.py`, new tests after `test_r_a2l_list_092_2` (reuse `_table_rows_shown`, `_layout`, `run_a2l`, `set_filter`, `settle`, `G2L_JOINED`, `mode_tag`): | |
|   | `test_r_a2l_list_092_3`: 80×24 (body 9, list mode) → `_table_rows_shown(...) >= 1`; docstring `R-A2L-LIST.092/3: 80x24 (body 9 rows, list mode) -> at least 1 table row.` | RED at base (0 rows), GREEN after |
|   | `test_r_a2l_list_093_1`: list mode; at 80×24 `#a2l_tags_summary` has `display` False; at 80×25 (body 10) it is True and its text starts with `LIST  rows` | RED at base, GREEN after |
|   | `test_r_a2l_list_093_2`: at 80×24 enter list mode (`set_filter(app, pilot, G2L_JOINED)`), then clear the filter back to text mode (use the same helper the existing tests use to clear; grep for it); assert `mode_tag(app) == "FILTER"`, `"-list" not in app.query_one("#a2l_panes").classes` and `#a2l_tags_summary` `display` True | GREEN after; RED under NC-2 |

## Row 4 texts (copy exactly; each is one whole canon line)
Current `.016` line:
```
| R-A2L-LIST.016 | While | While the viewer is in list mode, the system shall show under the table the summary `LIST  rows <a>-<b> / <n> in pasted order`. |
```
New `.016` line:
```
| R-A2L-LIST.016 | While | While the viewer is in list mode and the A2L Explorer body is 10 rows high or more, the system shall show under the table the summary `LIST  rows <a>-<b> / <n> in pasted order`. |
```
Current `.092` line:
```
| R-A2L-LIST.092 | While | While the A2L Explorer body is 10 to 14 rows high and the viewer is in list mode, the system shall show at least one tag table row. |
```
New `.092` line:
```
| R-A2L-LIST.092 | While | While the A2L Explorer body is 9 to 14 rows high and the viewer is in list mode, the system shall show at least one tag table row. |
```
New line, inserted right after `.092`:
```
| R-A2L-LIST.093 | While | While the viewer is in list mode and the A2L Explorer body is less than 10 rows high, the system shall hide the summary under the table. |
```

Files you may edit: `s19_app/tui/a2l_label_list.py`, `s19_app/tui/app/a2l_view.py`, `s19_app/tui/styles.tcss`, `REQUIREMENTS.md`, `tests/test_b103_a2l_list_view.py`.

## Negative controls (scratch copies `../scratch/nc-<n>`, paste the RED line, delete after)
1. Remove the `#a2l_panes.-tiny.-list #a2l_tags_summary` rule → `test_r_a2l_list_092_3` and `test_r_a2l_list_093_1` RED.
2. In row 2 use `panes.first().add_class("-list")` only when `names is not None` (never removed) → `test_r_a2l_list_093_2` RED.
3. `TINY_BELOW_HEIGHT = 9` → `test_r_a2l_list_092_3` RED.

## Nodes (`timeout 300`)
- `-n 0`: `tests/test_b103_a2l_list_view.py::test_r_a2l_list_092_1`, `::test_r_a2l_list_092_2`, `::test_r_a2l_list_092_3`, `::test_r_a2l_list_093_1`, `::test_r_a2l_list_093_2`, `::test_r_a2l_list_090_1`, `::test_r_a2l_list_083_1`, `::test_r_a2l_list_083_2`, `::test_r_a2l_list_083_3`, `::test_r_a2l_list_016_1`, `::test_r_a2l_list_016_2`; `tests/test_b99_a2l_encode.py::test_at_b99_09_a2l_window_physical_column`.
- First run the five new nodes on the unchanged tree (only the test file edited) and paste the base outcome: 092_3 and 093_1 must be RED there.
- The whole `tests/test_b103_a2l_list_view.py` (`-n 4`, `timeout 900`), `tests/test_requirements_canon.py` and `tests/test_address_census.py` (`-n 0`).
