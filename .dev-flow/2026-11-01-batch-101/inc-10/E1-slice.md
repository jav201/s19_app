# Inc 10 — E1 slice

Base `98d94d7`. Lines are base lines. 2 source files of the 4 allowed; 19 functions (17 changed, 2 new). No module-level import changes (`painted_names` is already imported, `app.py:224`).

## 1. Files

| File | Functions | Rows |
|---|---|---|
| `s19_app/tui/app.py` | 16 changed, 1 new (below) | S4, S5, S6, S2 rows |
| `s19_app/tui/segment_split_view.py` | `SplitJoinWindow.refresh_window` changed; `SplitJoinWindow.note_image_bytes_written` new | R-SEG-OPEN.1, .6, R-SEG-PREV.21, .22 |

## 2. Functions → rows

| # | Function | File:line (base) | Change | Rows |
|---|---|---|---|---|
| 1 | `S19TuiApp.update_hex_view` | `app.py:19173-19213` | with a focus address: window start = target row index − 1 (min 0), clamped to `[0, rows − 1]` instead of the page floor; `#hex_scroll` reset to (0, 0) (`_reset_scroll_to_top`); `_goto_focus_address` cleared when it differs from the focus address | R-TUI-018.1, .2, R-TUI-040.4, .12, R-TUI-007.3, .5 |
| 2 | `S19TuiApp.action_hex_page_next` | `app.py:10606-10637` | `start + page` when it is below the row count, else the start is kept (was `min(max_start, start + page)`) | R-TUI-007.3, .5 |
| 3 | `S19TuiApp.update_alt_hex_view` | `app.py:19247-19315` | new keyword-only `start_row: Optional[int] = None` (render from that row index, the failed-go-to re-render); `_alt_goto_focus_address` cleared when a focus address differs from it | R-TUI-040.8, .11, .12 |
| 4 | `S19TuiApp.update_mac_hex_view` | `app.py:19317-19358` | as #3 for the MAC view | R-TUI-040.8, .11, .12 |
| 5 | `S19TuiApp._handle_goto` | `app.py:20697-20715` | empty, invalid, miss: when a marker is set, clear it and `update_hex_view()` (window kept); no call when none is set | R-TUI-040.8, .11 |
| 6 | `S19TuiApp._handle_goto_alt` | `app.py:20747-20766` | hit: `near_top=True, reset_scroll=True`; failure: as #5 with `start_row` = the index of `_alt_first_visible_address` | R-TUI-018.1, .2, R-TUI-040.4, .8, .11 |
| 7 | `S19TuiApp._handle_goto_mac` | `app.py:20797-20815` | as #6 for the MAC view | as #6 |
| 8 | `S19TuiApp._handle_search_alt` | `app.py:20717-20745` | the hit render with `near_top=True, reset_scroll=True` | R-TUI-018.1, .2, R-TUI-040.12 |
| 9 | `S19TuiApp._handle_search_mac` | `app.py:20768-20795` | as #8 | as #8 |
| 10 | `S19TuiApp._handle_a2l_tag_find_next` | `app.py:16227-16284` | the tag-find render (`:16278`) with `near_top=True, reset_scroll=True` | R-TUI-018.1 |
| 11 | `S19TuiApp._jump_to_validation_issue_object` | `app.py:16383-16423` | the A2L and MAC renders (`:16412-16413`) with `near_top=True, reset_scroll=True`; the main view through #1 | R-TUI-018.1, .2, R-TUI-040.12 |
| 12 | `_unload_primary` (module) | `app.py:1831-1889` | the MAC-only rebuild also sets `errors=[]` | R-WS-LOADED.16 |
| 13 | `S19TuiApp._apply_unload` | `app.py:17184-17305` | (a) kind `all` with no `current_file` and no `current_a2l_path` → `set_status("Nothing to unload.")`, return before any change; (b) after the renders, `set_file_status(f"Unloaded {label}.")` beside the unchanged `set_status`; (c) last step `_rehome_focus_after_load()` | R-WS-LOADED.13, .14, .18, R-SHELL-FOCUS.3, .4 |
| 14 | `S19TuiApp._format_coexistence_status` | `app.py:18277-18320` | `<name>` = `painted_names([path.name])` and `<MAC file name>` = `painted_names([loaded.mac_path.name])` in every arm (5 returns) | R-TUI-012L.8 |
| 15 | `S19TuiApp.action_show_screen` | `app.py:9563-9645` | after the swap and the Split / Join hide, the focus goes to `_resolve_focus_target()` through `screen.set_focus` (fallback `_fallback_focus_target`, R-SHELL-FOCUS.5, .6) | R-SHELL-FOCUS.2, .5, R-SEG-OPEN.6 |
| 16 | `S19TuiApp._note_image_bytes_written` | `app.py:17910-17955` (**Inc 6 changes it**) | appended after Inc 6's body: `_refresh_a2l_values_after_write()`; the Split / Join window's `note_image_bytes_written()` (a missing window is a no-op, the CRC Designer idiom); never `refresh_window` | R-A2L-048, -049, R-SEG-PREV.21, .22, R-SEG-OPEN.6 |
| 17 | `S19TuiApp._refresh_a2l_values_after_write` (new) | `app.py`, beside #16 | no A2L → return; `_a2l_enriched_key = None`; `_compute_a2l_enriched_tags()`; `_refresh_a2l_filtered_tags(preserve_anchor=True)` and the tag-table repaint the A2L view uses (E3 confirms the anchor path) | R-A2L-048, -049 |
| 18 | `SplitJoinWindow.refresh_window` | `segment_split_view.py:1722-1746` | the `#sje_table` focus only while the window has no `hidden` class | R-SEG-OPEN.1, .6 |
| 19 | `SplitJoinWindow.note_image_bytes_written` (new) | `segment_split_view.py`, beside #18 | while displayed: `self._sync()`; while hidden: nothing (the next open re-syncs); no focus call | R-SEG-PREV.21, .22 |

Not changed: `_jump_to_section`, `on_memory_map_panel_open_in_hex_requested`, `_handle_search` (their jumps go through #1); `_apply_goto`; `SplitJoinWindow.action_cycle_tab` (F-18 not reproduced, D-3) and `action_close_window` (its `action_show_screen` call gets the focus from #15); `_rehome_focus_after_load` (reused as is).

## 3. Callers read

- `update_hex_view(focus)` ← `_jump_to_section` `:16070`, `_jump_to_validation_issue_object` `:16411`, `on_memory_map_panel_open_in_hex_requested` `:19132`, `_handle_search` `:20653`, `_handle_goto` `:20714`: all are jumps. Without a focus: paging `:10637`, `:10668`, unload `:17298`, load `:18231`, settings `:20153`.
- `update_alt_hex_view` / `update_mac_hex_view` with a focus: `:16153`, `:16316` (already near-top), `:16278`, `:16412-16413`, `:20744`, `:20765`, `:20794`, `:20814` — all jumps.
- `action_show_screen` ← the 12 rail bindings (`:2720-2736`), `on_rail_selected` `:9902`, `action_view_main/alt/mac` `:10349-10357`, `on_memory_map_panel_open_in_hex_requested` `:19131`, `SplitJoinWindow.action_close_window` (`segment_split_view.py:2199`), the window-help open action (`window_help.py:1036`). Startup focus is `_focus_activity_rail()` (`:8271`), not this action, so R-SHELL-FOCUS.1 is untouched.
- `_note_image_bytes_written` ← `:4914`, `:5046` (apply, save-back), `:12642` (Save project commit).
- `refresh_window` ← `watch_current_file` `:17991`, `action_open_split_join_export` `:9761`.

## 4. Overlap with Incs 6 and 9 (`app.py`)

- **Inc 6** (`b101-inc6`, 30 functions, list in `inc-9/E1-slice.md` §4): **shared: `_note_image_bytes_written`** (#16). Inc 6 adds the Checks-run end, the Patch Editor load tail and `update_checks_view` to it; Inc 10 appends two notices after them and changes nothing of Inc 6's. No other function in common (`_apply_prepared_load`, `_on_project_saved` and the Patch Editor handlers are Inc 6's; Inc 10 reads them only).
- **Inc 9** (`:3988-4572`, three flow save handlers): none in common.
- Main (with Incs 6 and 9) is merged into `b101-inc10` before E4; #16 is written against Inc 6's version.

## 5. Nodes touched (existing tests whose body may change; names kept)

- `tests/test_b97_flow_execution.py::test_tc_b97_64_arriving_with_bracket_c_confirms[rail]` and `[none]`: the asserted focus after `]` becomes `fx_panel` (R-SHELL-FOCUS.2); its `c` assertion stays (D-2).
- Candidates to check at E4 (they pin today's focus or page-aligned windows; none found asserting the defect, to re-run): `tests/test_tui_app.py::test_jump_actions_request_near_top_focus_and_scroll_reset`, `tests/test_tui_goto_marker.py` (TC-007, TC-010, TC-011), `tests/test_b100_focus.py`, `tests/test_tui_map_big.py::test_b77_select_focus_is_not_taken_while_the_map_screen_is_hidden`, `tests/test_map_click_chain.py`, `tests/test_tui_search_pagination.py`, `tests/test_b97_key_bar.py`, `tests/test_segment_split_window.py`, `tests/test_b99_export.py` (its `t` workaround comment).
- New files H, F, W (`02-test-cases.md`): `EXPECTED_SCANNED_TEST_FILES` re-measured at integration.
