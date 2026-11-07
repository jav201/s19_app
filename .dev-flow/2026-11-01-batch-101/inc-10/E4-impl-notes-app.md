# Inc 10a — E4 implementation notes (app)

Batch 2026-11-01-batch-101, increment 10a. Implementer app (G1, E4). Files touched: `s19_app/tui/app.py` (only — `segment_split_view.py` is G2's, `render/hexview.py` is G3's, both untouched here).

## 1. Functions changed

| File | Function | Graph node | Change |
|---|---|---|---|
| s19_app/tui/app.py | `update_hex_view` | G1 #1 | `rows = _hex_view_rows()`; a focus sets `_hex_window_start = _row_start_for_near_top_focus(...)`; one clamp `[0, len(rows)-1]` (page floor removed); marker cleared when a non-`None` focus differs from `_goto_focus_address`; a focused render calls `_reset_scroll_to_top("#hex_scroll")`. |
| s19_app/tui/app.py | `action_hex_page_next` | G1 #2 | `total = len(_hex_view_rows())`; `start + page if start + page < total else start`. |
| s19_app/tui/app.py | `update_alt_hex_view` | G1 #3 | new keyword-only `start_row` (wins over `near_top`); `rows = _hex_view_rows()`; near-top start from `_row_start_for_near_top_focus`; `_alt_first_visible_address = rows[effective start]`; marker clear clause `focus_address is not None and != _alt_goto_focus_address`. |
| s19_app/tui/app.py | `update_mac_hex_view` | G1 #4 | as #3 for the MAC view. |
| s19_app/tui/app.py | `_handle_goto` | G1 #5 | on empty/invalid/miss: status first, then clear marker + `update_hex_view()` only when a marker was set. |
| s19_app/tui/app.py | `_handle_goto_alt` | G1 #6 | hit → `update_alt_hex_view(addr, near_top=True, reset_scroll=True)`; failure with a marker → clear + `update_alt_hex_view(start_row=index of _alt_first_visible_address)`. |
| s19_app/tui/app.py | `_handle_goto_mac` | G1 #7 | as #6 for the MAC view. |
| s19_app/tui/app.py | `_handle_search_alt` | G1 #8 | hit → `update_alt_hex_view(addr, near_top=True, reset_scroll=True)`. |
| s19_app/tui/app.py | `_handle_search_mac` | G1 #9 | as #8 for the MAC view. |
| s19_app/tui/app.py | `_handle_a2l_tag_find_next` | G1 #10 | tag-find render → `update_alt_hex_view(addr, near_top=True, reset_scroll=True)`. |
| s19_app/tui/app.py | `_unload_primary` (module) | G1 #12 | rebuild only when `mac_path is not None`; sets `path=loaded.mac_path` and `errors=[{"line": None, "message": d} for d in loaded.mac_diagnostics]`; image facts/caches cleared as before. |
| s19_app/tui/app.py | `_apply_unload` | G1 #13 | (a) `all` with no `current_file` and no `current_a2l_path` → `set_status("Nothing to unload.")`, return; (b) `set_file_status(f"Unloaded {label}.")` beside `set_status`; (c) `trigger = default_screen.focused` read first, `call_after_refresh(self._land_focus, trigger, None, on_switch=False)` last; also resets `_hex_view_rows_cache` after `current_file` install. |
| s19_app/tui/app.py | `_format_coexistence_status` | G1 #14 | file names through `painted_names([...])` in all 5 returns. |
| s19_app/tui/app.py | `action_show_screen` | G1 #15 | captures whether the call changes what is shown; clears a focused widget whose window ancestor now has `hidden` (`screen.set_focus(None)`); when changed, `call_after_refresh(self._land_focus, focused, _active_screen_key, on_switch=True)` before `refresh_bindings()`. |
| s19_app/tui/app.py | `_land_focus` | G1 #16 (new) | stale-switch no-op; reads `default_screen.focused`; moves on `None` / `_focus_needs_rehome` / (`on_switch` and still trigger) / (not `on_switch` and no longer trigger); lands via `_resolve_focus_target()` + `screen.set_focus`. |
| s19_app/tui/app.py | `_row_start_for_near_top_focus` | G1 #17 | signature `(focus_address, row_bases, view_rows, context_rows=1)`; snap via `_snapped_focus_row_index`, then `bisect_left(view_rows, row_bases[i])`, return `max(0, j - context_rows)`. |
| s19_app/tui/app.py | `_hex_view_rows` | G1 #18 (new) | `[]` without a file; else `hex_row_bases(row_bases, bases_set, _collect_mac_highlight_addresses(file))`, memoised on `(image_generation, frozenset(mac set))`. |
| s19_app/tui/app.py | `_first_visible_hex_address` | G1 #19 | main view reads `_hex_view_rows()[_hex_window_start]` (the painted first row). |
| s19_app/tui/app.py | `set_file_status` | G1 #20 | `painted_names([text], limit=1, clip=max(1, len(text)))` (Cc/Cf/Zl/Zp filter, no clip) before `safe_text(...).plain`. |

Supporting edits in the same file, required by the new attribute/import (not slice nodes):
- Import: `hex_row_bases` joins the `..render.hexview` import (pinned interface I-5).
- `_SESSION_SNAPSHOT_NAMES`: `_hex_view_rows_cache` added.
- `_session_snapshot`: `_hex_view_rows_cache` special-cased to `_norm(value[1])` (the view-row list), mirroring the `_mac_view_cache_key` / `_a2l_cache_key` handling so the generation-and-frozenset key never leaks into the cold-vs-cold snapshot.

## 2. Deviations from the graph

- **AR2-5 re-anchoring (not implemented).** The `update_hex_view` "without a focus" clause names "a load resets `_hex_window_start` … and a MAC load/unload re-anchors it by the first shown address". Not built: the natural hook points are the load tail (`_step_hex`) and the MAC-load install (`_apply_prepared_load`), neither of which is a G1 node; doing it inside `update_hex_view` requires distinguishing an image load from a MAC load, and both bump `_image_generation` (`_apply_prepared_load` bumps on every install), so a faithful version needs extra state beyond the G1 nodes. No case in `tests/test_b101_hex_jump.py` / `tests/test_b101_unload_focus.py` drives it (the testers load, then jump, from a fresh `_hex_window_start == 0`). What G1 owns is done: `_apply_unload` invalidates `_hex_view_rows_cache`, and the single `[0, len(rows)-1]` clamp bounds the window on every render.

## 3. Open questions for the integrator

1. `hex_row_bases` is imported from `..render.hexview` and called by `_hex_view_rows`; G3 must land its `hex_row_bases` node (pinned I-5) before the suite runs.
2. `_hex_view_rows_cache` is a new app attribute. It is added to `_SESSION_SNAPSHOT_NAMES` and special-cased in `_session_snapshot`, but the Inc 12b census `_CENSUS_AT_12B_BASE` in `tests/test_b100_session_reset.py` must be re-frozen to include it when that increment runs (test file not editable here).
3. AR2-5 (see deviation) — the increment owning the load tail / MAC-load install should implement the reset and re-anchor.
4. `_has_mac` is now unused in `app.py` (the only caller was `_unload_primary`, which now keys on `loaded.mac_path is not None` per the graph). Left in place (minimum code, no refactor); a later cleanup may remove it.

## 4. Checks

Command (operator rule: byte-compilation only, no pytest / no import of `s19_app`):

```
<HOME>/anaconda3/envs/s19env/python.exe -m py_compile s19_app/tui/app.py
```

Output: empty (exit 0).

DONE app
Files edited: s19_app/tui/app.py
