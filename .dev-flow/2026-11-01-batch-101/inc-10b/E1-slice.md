# Inc 10b — E1 slice

Records at base `98d94d7`; the hook is written against Inc 6's version (`b101-inc6`, `56593a30`). 2 source files of the 4 allowed; 5 functions (1 changed, 4 new). No module-level import changes except `Coordinate`, imported locally where #4 uses it (R2-7).

## 1. Files

| File | Functions | Rows |
|---|---|---|
| `s19_app/tui/app.py` | `_note_image_bytes_written` changed; `_refresh_hex_views_after_write`, `_refresh_a2l_values_after_write`, `_repaint_a2l_tag_cells` new | R-A2L-048, -049, -105, -106, R-TUI-004.7, .8, .9 |
| `s19_app/tui/segment_split_view.py` | `SplitJoinWindow.note_image_bytes_written` new | R-SEG-PREV.21, .22, R-SEG-EXP.15 |

## 2. Functions → rows

| # | Function | File:line | Change | Rows |
|---|---|---|---|---|
| 1 | `S19TuiApp._note_image_bytes_written` | `app.py:17910-17955` at `98d94d7`; `b101-inc6` `app.py:18315-` (Inc 6's body) | the Check Editor block switched from `except Exception: return` to the `checks = None` idiom (A10-08); then appended: `_refresh_hex_views_after_write()`, `_refresh_a2l_values_after_write()`, the Split / Join window's `note_image_bytes_written()` (a missing window skips only its own notice); never `refresh_window`, no focus call | all rows |
| 2 | `S19TuiApp._refresh_hex_views_after_write` (new) | `app.py`, beside #1 | no file → return; `update_hex_view()` (no focus); `update_alt_hex_view(start_row=<index of _alt_first_visible_address in _hex_view_rows()>)`; the same for the MAC view; no scroll reset | R-TUI-004.7, .8, .9 |
| 3 | `S19TuiApp._refresh_a2l_values_after_write` (new) | `app.py`, beside #1 | no A2L → return; `_a2l_enriched_key = None`; `_compute_a2l_enriched_tags()`; `_a2l_filtered_tags` re-pointed to the recomputed tags, same tags, same order, no re-filter; `_update_a2l_summary_buffer()` (S-8); `_repaint_a2l_tag_cells()` | R-A2L-048, -049, -105, -106 |
| 4 | `S19TuiApp._repaint_a2l_tag_cells` (new) | `app.py`, beside `update_a2l_tags_view` (`:19840-19950`) | for each row of the shown page: the cells from `_build_a2l_table_cells` with the row's severity style; a cell whose text differs is written with `DataTable.update_cell_at(..., update_width=True)` (R2-7); `_a2l_row_key_to_tag` re-pointed; the summary label recomputed with `update_a2l_tags_view`'s text; no `clear()`, no cursor or scroll call | R-A2L-048, -049, -105 |
| 5 | `SplitJoinWindow.note_image_bytes_written` (new) | `segment_split_view.py`, beside `refresh_window` (`:1722-1746`) | while displayed: `self._bump()` (disarm and one sync); while hidden: `self._armed = False` only; no focus call, no selection reset | R-SEG-PREV.21, .22, R-SEG-EXP.15 |

Not changed: `update_hex_view`, `update_alt_hex_view`, `update_mac_hex_view`, `_hex_view_rows` (Inc 10a's, used through I-3 and I-5); `_compute_a2l_enriched_tags`, `_update_a2l_summary_buffer`, `_build_a2l_table_cells`, `update_a2l_tags_view`, `on_data_table_row_highlighted`; `SplitJoinWindow._bump`, `_sync`, `refresh_window`.

## 3. Callers read

- `_note_image_bytes_written` ← `:4914`, `:5046` (apply, save-back), `:12642` (Save project commit), at `98d94d7`. No new caller; one call per write, so no storm (E3 architect A10-12).
- `_compute_a2l_enriched_tags` consumers (Patch Editor, Check Editor, reports, `_decide_project_image`): read names, addresses and linkage; byte verdicts read the image (`change_service.py:810-853`, E3 security "read and cleared"). The recompute only makes their values current.
- `_a2l_row_key_to_tag` readers: `on_data_table_row_highlighted` (`:15896`), the row-select jump; both key by `a2l:<absolute index>`, which #4 keeps.

## 4. Overlap

- **Inc 6** (in flight, merges first): shared `_note_image_bytes_written` only (E3 architect: an AST map of Inc 6's hunks meets the slice at this one function). 10b changes Inc 6's Check Editor block idiom (D-10b-5) and appends after it.
- **Inc 10a** (merges before 10b): shares no function; 10b calls 10a's `update_hex_view` (no-focus path), `update_alt_hex_view` / `update_mac_hex_view` (`start_row`), `_hex_view_rows` and reads `_alt_first_visible_address` / `_mac_first_visible_address` (interfaces in `codewire/graph-inc10b.md`).
- **Inc 9**: none.

## 5. Nodes touched (existing tests whose body may change; names kept)

- None asserted to change. Candidates to re-run at E4: `tests/test_segment_split_window.py` (the arm and disarm nodes), the A2L table tests that count `DataTable.clear` calls or row keys, and Inc 5's in-place-write tests (`_note_image_bytes_written` callers).
- New file W (`02-test-cases.md`): `EXPECTED_SCANNED_TEST_FILES` re-measured at integration.
