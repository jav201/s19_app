# Inc 12 — E1 slice: the file and functions to change, counted and mapped

Base: product tree `e07fb00`; line numbers are as of `e07fb00` (`git show e07fb00:s19_app/tui/app.py`). Rows are in `01-requirements.md` and decisions in `E1-rulings.md` §3; the slice follows each recommended option.

Real callers come from `evidence-e1/i12e1-callers-transcript.txt`: the Code-Wire v3.1.0 extractor (`git -C C:\Users\jjgh8\Github\code-wire describe --tags` = `v3.1.0`, commit `e436a08`) over a throwaway `git archive e07fb00 s19_app` copy in the scratchpad, with one `# node:` mark per def (1,996 marks, 3,771 calls, 0 parse failures). The script is `evidence-e1/i12e1-callers.py`, Inc 11's `e1-callers.py` with Inc 12's targets. The copy was deleted after the run.

## 1. Summary

| File | Functions | Rows |
|---|---|---|
| `s19_app/tui/app.py` (`S19TuiApp`) | 5 changed: `_compose_screen_a2l` (the tag table's arguments `:8516-8521`), `_setup_datatable_columns` (the tag table's column labels `:8733-8751`), `update_a2l_tags_view` (`:20286`), `_build_a2l_table_cells` (`:20389`), `on_resize` (`:10864`) | R-TUI-042a.2 … .5; R-A2L-006.1 through CTX-A2L-SCREEN |

**Totals:** 1 source file of the 4 allowed. 5 changed functions, 0 new (E2 may add one helper for the shortened name, D-1 A). Two of them were Inc 11's graph nodes (`_compose_screen_a2l`, `_build_a2l_table_cells`; `../inc-11/codewire/graph-inc11.md`, noted there as Inc 12's). PLAN's estimate was ~6 rows / ~4 nodes. Tests and snapshot baselines are not counted (`E1-rulings.md` §4).

## 2. Function map

| # | Function | File:line (base) | Change | Real callers (X) | Rows |
|---|---|---|---|---|---|
| 1 | `S19TuiApp._compose_screen_a2l` | `app.py:8456`; `DataTable(id="a2l_tags_list", zebra_stripes=True, cursor_type="row", cell_padding=0)` at `:8516-8521` | `cell_padding=1` (moved from Inc 11, D-1 A there) and the two first columns fixed (F used textual 8.2.8's `DataTable(..., fixed_columns=2)`; the mechanism is E2's) | `S19TuiApp.compose` `app.py:3385` | R-TUI-042a.2, .4 |
| 2 | `S19TuiApp._setup_datatable_columns` | `app.py:8693`; the tag table's `add_columns("Tag", "Address", "Length", "Source", …)` at `:8733-8751` | the labels in CTX-A2L-SCREEN's new order: `Address`, `Length`, `Tag`, then the other 13 unchanged | `S19TuiApp.on_mount` `app.py:8644` | R-TUI-042a.4; R-A2L-006.1 |
| 3 | `S19TuiApp.update_a2l_tags_view` | `app.py:20286-20387` (the per-row build `:20352-20372`) | before the rows are added, computes the width left and the name width *w* from the table's visible width and the Address and Length widths of the page's cells, and gives *w* to #4; the rest (paging, row keys `a2l:<index>`, severity styles, the summary) unchanged | `_apply_viewer_setting` `:20605`; `_focus_a2l_tag_absolute_index` `:16603`; `_refresh_a2l_filtered_tags` `:20217`, `:20222`; `action_a2l_tags_page_next` `:11102`; `action_a2l_tags_page_prev` `:11128`; `update_a2l_view` `:20269` | R-TUI-042a.3, .5 |
| 4 | `S19TuiApp._build_a2l_table_cells` | `app.py:20389-20473` (the Tag cell `:20457`, the address format `:20430`) | the cells in the new order (Address, Length, Tag, then the other 13 as today); the Tag cell's name shortened in the middle with `…` to min(34, *w*) cells when wider (moved from Inc 11 as the fixed 34-cell cap, E3A-03; sized from *w* here); the address format `0x{addr:08X}` unchanged (CTX *Address* now says what it does) | `S19TuiApp.update_a2l_tags_view` `app.py:20357` | R-TUI-042a.3, .5 (the order: .4) |
| 5 | `S19TuiApp.on_resize` | `app.py:10864-10893` | when the width changes while the A2L Explorer is shown, the current page is rebuilt after the refresh (as `update_project_labels` is, `call_after_refresh`, because `App.size` is stale inside the handler, its docstring), keeping the cursor row | none (a Textual event handler; 0 marked callers) | R-TUI-042a.5 (/6) |

Unchanged and read: the row-key → tag map (`_a2l_row_key_to_tag`) and `coordinate_to_cell_key((row, 0))` (`:9763`) take the row key, not a column, so the new order changes neither; the filter and find read the tag dicts (`_a2l_tag_find_haystack`, `:16614`), not the cells; the detail card (`_a2l_detail_card_text`, `:1278`) reads the tag, so it keeps the full name.

## 3. Interfaces

- **I-1 (Inc 1b, copy from the tag table):** the copied row name is the tag's full name, never the painted Tag cell (`E1-rulings.md` D-3).
- **The cell tuple of #4** has one caller in the product (#3) and is read by position in four test files (`E1-rulings.md` §4); its new order is CTX-A2L-SCREEN's.
