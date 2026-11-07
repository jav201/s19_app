# Code-Wire graph — Inc 10b (views that follow in-place writes), batch-101

Stage E2 of the design-first flow (`dev-flow-v3-beta`), split from Inc 10 at E3. Graph only: no stub, mark or declaration in any tree. Records at base `98d94d7`; the hook node is written against Inc 6's version (`b101-inc6`), and the hex nodes call Inc 10a's prototype (`../../inc-10/codewire/graph-inc10.md`). Requirements `../01-requirements.md`, slice `../E1-slice.md`, rulings `../E1-rulings.md`, cases `../02-test-cases.md`.

How to read it:
- Every node's `func:` starts with **unchanged**, **changed** ("was: … / now: …") or **new**. Context nodes are unchanged nodes a changed node calls or relies on; a node marked *(10a)* is Inc 10a's prototype, which merges first.
- Example sources are case ids of `../02-test-cases.md`; `P1` = E3 security probe P1, `P4` = E3 architect probe P4, `P` = the Inc 10 E1 pilot (`../../inc-10/evidence-e1/i10e1-pilot-transcript.txt`). An example states the 10b target unless it says "base".
- Values: case 08 (row 150 = `0x00000960`; `VALUE_0001` @ `0x00000000` = `6C`, Raw `108`), fixture three (`0x8000`, `0x8010` all `FF`, `0x8020`), guard fixture (`0x00000000`, `0x00100000`, 8 bytes each).

## Groups and interfaces

5 slice nodes in 2 files (one E4 implementer per group).

| Group | File | Owns nodes |
|---|---|---|
| G1 app | `s19_app/tui/app.py` | `_note_image_bytes_written`, `_refresh_hex_views_after_write`, `_refresh_a2l_values_after_write`, `_repaint_a2l_tag_cells` |
| G2 split-join | `s19_app/tui/segment_split_view.py` | `SplitJoinWindow.note_image_bytes_written` |

| Interface | Pinned form | Producer → consumers |
|---|---|---|
| I-1 in-place write notice | `SplitJoinWindow.note_image_bytes_written(self) -> None`: public, no argument; while the window has no `hidden` class it calls `self._bump()` once (disarm and one `_sync`); while hidden it sets `self._armed = False` and does nothing else; it never focuses, never resets a selection and never calls `refresh_window` | G2 → G1 (`_note_image_bytes_written`) |
| I-7 tag table repaint | `_repaint_a2l_tag_cells(self) -> None`: writes the shown page's cells in place; reads `_a2l_filtered_tags`, `_a2l_window_start`; never calls `DataTable.clear`, `move_cursor` or `scroll_to` | G1 internal |

Interfaces with Inc 10a (10a merges first; both edit `app.py` and `segment_split_view.py`; no function in common):

| 10a item | What 10b relies on |
|---|---|
| I-3 `update_hex_view(focus_address=None)` | without a focus: `_hex_window_start` kept (one clamp to `[0, len(view rows) − 1]`, A10-02), marker kept, scroll untouched |
| I-3 `update_alt_hex_view(..., *, start_row=None)`, `update_mac_hex_view` | `start_row` is an index into the view rows and wins over `near_top`; a `None` focus address never clears the marker; `reset_scroll=False` leaves the scroll |
| I-3 `_alt_first_visible_address`, `_mac_first_visible_address` | the painted first view row of the view (or `None` with no rows) |
| I-5 `_hex_view_rows()` | the view-row list the renderer paints; 10b bisects the first visible address in it |
| I-2 `SplitJoinWindow.refresh_window` | 10b never calls it (Inc 5 E3 A-4) |
| I-4 focus landing | an in-place write schedules no landing; 10b's notices move no focus (R-SEG-PREV.22) |
| case R-SEG-OPEN.6/3 | stays in 10a's records; re-run at 10b's E5 |

Interfaces with other increments:

| With | What is shared | Rule |
|---|---|---|
| Inc 6 (in flight, merges first) | `_note_image_bytes_written` (Inc 6 adds the Checks-run end, the Patch Editor load tail and `update_checks_view`) | 10b changes only Inc 6's Check Editor `try` idiom (D-10b-5) and appends three notices after it; E4 writes on main after Inc 6's merge |
| Inc 5 (merged) | the hook and its three callers; the term *in-place write* | reused; no `refresh_window` from the hook |
| Inc 13 (merged) | `_bump`, `_sync`, `_state_text` (conflict first) | reused unchanged |

## Nodes — G1 app

S19TuiApp._note_image_bytes_written
req: R-A2L-048, R-A2L-049, R-A2L-105, R-A2L-106, R-TUI-004.7, R-TUI-004.8, R-TUI-004.9, R-SEG-PREV.21, R-SEG-PREV.22, R-SEG-EXP.15
in: —
out: None
func: changed (on Inc 6's version). was: Checks-run end, Patch Editor load tail, `update_checks_view`, CRC Designer notice, then `try: checks = query_one(...) except Exception: return` and `checks.clear_check_results()`. / now: identical up to the Check Editor query, which becomes `except Exception: checks = None` with `if checks is not None: checks.clear_check_results()`; then `self._refresh_hex_views_after_write()`, `self._refresh_a2l_values_after_write()`, then the Split / Join window (queried in its own `try`; missing → skip) `note_image_bytes_written()` (I-1). No `refresh_window`, no focus call. A fault inside a notice is not swallowed (each call sits outside its `try`).
module: s19_app/tui/app.py
calls: CheckEditorPanel.clear_check_results, S19TuiApp._refresh_hex_views_after_write, S19TuiApp._refresh_a2l_values_after_write, SplitJoinWindow.note_image_bytes_written
examples: (R-SEG-PREV.21/1) fixture three, join-fill pick displayed, a Save project commit writes `0x8015`, `0x8016` = `BB CC` → band `data 8 · fill 13 · conflict 2 · fill 9 · data 8`, state `⚠ 2 B would clobber source — abort on export` (base P: `conflict 1` at offset 19)
examples: (R-SEG-PREV.22/1) `#sje_export` focused before the commit (the open leaves `sje_table` focused; `tab`) → `#sje_export` focused after; the window's open refresh would focus `sje_table` (E4 integration I-D5: the E1 example started on `sje_table`, which that negative control cannot change)
examples: (A10-08) no `#check_editor_panel` mounted → the three notices still run (Inc 6's body: they would be skipped)

S19TuiApp._refresh_hex_views_after_write
req: R-TUI-004.7, R-TUI-004.8, R-TUI-004.9
in: —
out: None
func: new. No `current_file` → return. `update_hex_view()` (no focus: window, marker and scroll kept, 10a I-3). `rows = self._hex_view_rows()`; for the A2L view: `start = bisect_left(rows, _alt_first_visible_address)` when that address is set, else `None`; `update_alt_hex_view(start_row=start)`; the same for the MAC view with `_mac_first_visible_address`. No `reset_scroll`, no focus address, so no marker change. Hidden views re-render too.
module: s19_app/tui/app.py
calls: S19TuiApp.update_hex_view, S19TuiApp._hex_view_rows, S19TuiApp.update_alt_hex_view, S19TuiApp.update_mac_hex_view
examples: (R-TUI-004.7/1) fixture three, apply `0x8013` = `AA`, key `1` → `#hex_view` row `0x00008010` = `FF FF FF AA FF FF FF FF` (base P1: `FF FF FF FF …`)
examples: (R-TUI-004.7/2) save-back of the same document, key `2` → `#alt_hex_view` row `0x00008010` = `FF FF FF AA FF FF FF FF`
examples: (R-TUI-004.7/3) Save project commit of the same document, key `3` → `#mac_hex_view` row `0x00008010` = `FF FF FF AA FF FF FF FF`
examples: (R-TUI-004.8/1) case 08, go-to `0x00000960` (window from index 149), scroll (10, 40), write at `0x00000965` → `_hex_window_start` 149, first hex row `0x00000950`, scroll (10, 40)
examples: (R-TUI-004.8/2) A2L view, `_alt_first_visible_address` `0x00000950` → `start_row` 149 → first hex row `0x00000950`, scroll (10, 40)
examples: (R-TUI-004.8/3) MAC view, likewise with `_mac_first_visible_address`
examples: (R-TUI-004.9/1) markers on `0x00000960` in the three views → after the write one `> ` line per view, row `0x00000960`
examples: (no rows rendered yet in the A2L view: `_alt_first_visible_address` `None`) → `start_row=None` → rendered from the first view row, as a load does

S19TuiApp._refresh_a2l_values_after_write
req: R-A2L-048, R-A2L-049, R-A2L-105, R-A2L-106
in: —
out: None
func: new. No `current_a2l_data` → return. `old = self._a2l_enriched_tags`; `self._a2l_enriched_key = None`; `new = self._compute_a2l_enriched_tags()` (one dict per tag, same order as `old`); `self._a2l_filtered_tags` = for each listed tag, the recomputed dict at its position in `old` (same tags, same order, no `_filter_a2l_tags` call); `self._update_a2l_summary_buffer()` (S-8: the stored lines and `#a2l_view` agree; `_a2l_summary_start` is 0 on every path, D-10b-3); `self._repaint_a2l_tag_cells()`. Not `update_a2l_view()` and not `_refresh_a2l_filtered_tags` (both repaint through `update_a2l_tags_view`, whose `clear()` resets cursor and scroll, P4).
module: s19_app/tui/app.py
calls: S19TuiApp._compute_a2l_enriched_tags, S19TuiApp._update_a2l_summary_buffer, S19TuiApp._repaint_a2l_tag_cells
examples: (R-A2L-048/1) `VALUE_0001` `6C` → `93` applied; key `2` → Raw `147`, Physical `147` (base P: `108` / `108`, cache key unchanged, uncached `147`)
examples: (R-A2L-048/2) entry edited to `55`, Save project commit while the A2L Explorer is displayed → Raw `85`, Physical `85`
examples: (R-A2L-048/3) save-back of `55` → Raw `85`, Physical `85`
examples: (R-A2L-106/1) filter Raw `108`, `VALUE_0001` listed; apply `93` → `_a2l_filtered_tags` still holds `VALUE_0001` (now Raw `147`), the same count `T`
examples: (no A2L) → nothing computed, nothing painted

S19TuiApp._repaint_a2l_tag_cells
req: R-A2L-048, R-A2L-049, R-A2L-105
in: —
out: None
func: new. `table = #a2l_tags_list`; for each row `i` of the shown page (`start = _a2l_window_start`, the page bounds `update_a2l_tags_view` uses): `tag = _a2l_filtered_tags[start + i]`; `cells = _build_a2l_table_cells(tag)` with the row's severity style (`_a2l_tag_row_severity`, `_severity_style`); each cell whose plain text or style differs from the table's is written with `table.update_cell_at(Coordinate(i, column), cell, update_width=True)` (R2-7: `update_width=True` only marks the column dimensions for update, so a written Raw or Physical value wider than its column's widest cell is not clipped; no cursor or scroll moves); `_a2l_row_key_to_tag[f"a2l:{start + i}"] = tag`; the summary label recomputed with `update_a2l_tags_view`'s text (`Page …  ·  <K> in image`). No `clear()`, no `move_cursor`, no `scroll_to`; no `RowHighlighted` is posted, so the detail card keeps its tag (it shows no value, R-TUI-069.1).
module: s19_app/tui/app.py
calls: S19TuiApp._build_a2l_table_cells, DataTable.update_cell_at, Coordinate (imported locally, R2-7)
examples: (R-A2L-049/1) first shown row = page row 30 before → page row 30 after (base P4 shape: `scroll_y` 30 → 0)
examples: (R-A2L-049/2) filter on Raw, text `1`, first shown row page row 30 → page row 30 after
examples: (R-A2L-105/1) cursor on page row 40 → cursor on page row 40, the detail card names the same tag (P4: cursor 40 → 0)
examples: (R-A2L-048/1) the `VALUE_0001` row: Raw and Physical cells `108` → `147`; its other 14 cells unchanged, so not written
examples: (R2-7) a written Raw value `108` → `1000` (wider than its column's widest cell) → `update_cell_at(..., update_width=True)` marks the column dimensions for update; the value is not clipped, no cursor or scroll moves

## Nodes — G2 split-join

SplitJoinWindow.note_image_bytes_written
req: R-SEG-PREV.21, R-SEG-PREV.22, R-SEG-EXP.15
in: —
out: None
func: new. `if not self.has_class("hidden"): self._bump()` (disarm + one `_sync`); `else: self._armed = False`. No selection reset (the image object is the same), no focus, no `refresh_window`.
module: s19_app/tui/segment_split_view.py
calls: SplitJoinWindow._bump
examples: (R-SEG-PREV.21/1) as `_note_image_bytes_written`
examples: (R-SEG-PREV.21/2) hidden → arm cleared only; the next open re-syncs (base P: fresh on reopen, 1 B = uncached plan)
examples: (R-SEG-EXP.15/1) guard fixture displayed, `e` armed (`— e again to confirm`), Save project commit → `— e will ask`; the next `e` arms again, 0 files written (base: armed after the commit; `e` writes)
examples: (R-SEG-EXP.15/2) armed, Esc (hidden), apply → `_armed` False; the palette open shows `— e will ask`; `e` arms, 0 files (base: the arm survives the hidden write and the reopen, `refresh_window` resets it only for a new image object)

## Context nodes (unchanged)

S19TuiApp.update_hex_view *(10a)* — req: R-TUI-004.8, R-TUI-004.9 — the no-focus path keeps the window, the marker and the scroll (10a I-3).
S19TuiApp.update_alt_hex_view *(10a)* — req: R-TUI-004.7, R-TUI-004.8 — `start_row` wins over `near_top`; `None` focus keeps the marker.
S19TuiApp.update_mac_hex_view *(10a)* — req: R-TUI-004.7, R-TUI-004.8 — as `update_alt_hex_view`.
S19TuiApp._hex_view_rows *(10a)* — req: R-TUI-004.8 — the view rows (present rows and MAC-added rows).
S19TuiApp._compute_a2l_enriched_tags — req: R-A2L-048 — key `(_a2l_view_generation, _image_generation, len(mem_map))`; an in-place write changes none, hence the explicit `_a2l_enriched_key = None`; sets `_a2l_summary_start = 0`.
S19TuiApp._update_a2l_summary_buffer — req: (S-8, no row) — paints `#a2l_view` from `_a2l_summary_lines`.
S19TuiApp._build_a2l_table_cells — req: R-A2L-048 — the 16 cells of one tag row; Raw and Physical read the enriched tag.
S19TuiApp.update_a2l_tags_view — req: R-A2L-049 — not called by 10b: its `DataTable.clear(columns=False)` (`app.py:19887`) resets cursor and scroll (P4).
S19TuiApp.on_data_table_row_highlighted — req: R-A2L-105 — resolves `_a2l_row_key_to_tag`; fires on cursor moves only.
SplitJoinWindow._bump — req: R-SEG-EXP.15 — `_armed = False`, then `_sync()` (`segment_split_view.py:1983-1985`).
SplitJoinWindow._sync — req: R-SEG-PREV.21 — reads `current_file.mem_map` live; `build_plan` → `_conflict_marks` (Inc 13).
CheckEditorPanel.clear_check_results — req: (R-CHKED-057, Inc 5) — unchanged; now reached through the `checks = None` idiom.

QC-TM-10b-1 (A10-12): `_refresh_a2l_values_after_write` timed on the largest synth A2L; bound `timing_bound(1.0)`; example: case 08's 462 tags recompute once per write (E1 D-4 cost note).
