# Inc 10b — E4 implementation notes (G1 app)

Batch 2026-11-01-batch-101, increment 10b. Implementer G1 app (E4). Files touched: `s19_app/tui/app.py`.

## 1. Functions changed

| File | Function | Graph node | Change |
|---|---|---|---|
| s19_app/tui/app.py | `S19TuiApp._note_image_bytes_written` | `_note_image_bytes_written` (changed) | Check Editor query switched from `except Exception: return` to the `checks = None` idiom (`if checks is not None: checks.clear_check_results()`); appended the three notices after it: `_refresh_hex_views_after_write()`, `_refresh_a2l_values_after_write()`, then the Split / Join window queried in its own `try` and `note_image_bytes_written()` (I-1). No `refresh_window`, no focus call. |
| s19_app/tui/app.py | `S19TuiApp._refresh_hex_views_after_write` | `_refresh_hex_views_after_write` (new) | No `current_file` → return; `update_hex_view()` (no focus); `rows = self._hex_view_rows()`; for the A2L view `start = bisect_left(rows, _alt_first_visible_address)` when set else `None`, `update_alt_hex_view(start_row=start)`; the same for the MAC view. No `reset_scroll`, no focus address. |
| s19_app/tui/app.py | `S19TuiApp._refresh_a2l_values_after_write` | `_refresh_a2l_values_after_write` (new) | No `current_a2l_data` → return; `old = _a2l_enriched_tags`; `_a2l_enriched_key = None`; `new = _compute_a2l_enriched_tags()`; `_a2l_filtered_tags` re-pointed to the recomputed tag at each listed tag's position in `old` (same tags, same order, no `_filter_a2l_tags`); `_update_a2l_summary_buffer()`; `_repaint_a2l_tag_cells()`. |
| s19_app/tui/app.py | `S19TuiApp._repaint_a2l_tag_cells` | `_repaint_a2l_tag_cells` (new, I-7) | For each shown page row (`_get_window_bounds` over `_a2l_filtered_tags` at `_a2l_window_start`): rebuild 16 cells via `_build_a2l_table_cells` with the row's severity style; write only cells whose plain text or style differs via `DataTable.update_cell_at(Coordinate(i, column), cell, update_width=True)`; re-point `_a2l_row_key_to_tag`; recompute the summary label with `update_a2l_tags_view`'s text. No `clear()`, no `move_cursor`, no `scroll_to`, no `RowHighlighted`. `Coordinate` imported locally (R2-7). |

## 2. Deviations from the graph (each with its reason)

none

## 3. Open questions for the integrator

none

## 4. Checks

py_compile per edited file:

```
<HOME>/anaconda3/envs/s19env/python.exe -m py_compile s19_app/tui/app.py
```

Output: exit status 0 (no output; `PY_COMPILE_OK`).
