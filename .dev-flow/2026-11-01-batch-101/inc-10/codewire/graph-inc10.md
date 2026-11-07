# Code-Wire graph — Inc 10a (hex navigation, unload state, focus), batch-101

Stage E2 of the design-first flow (`dev-flow-v3-beta`), corrected at E3 (`../E3-rulings.md`; split: the in-place-write nodes moved to `../../inc-10b/codewire/graph-inc10b.md`). Graph only: no stub, mark or declaration in any tree. Base `98d94d7`. Requirements `../01-requirements.md`, slice `../E1-slice.md`, rulings `../E1-rulings.md` (E3 decisions: §7), cases `../02-test-cases.md`. `P1` … `P7` in an example = the E3 architect probe of that number unless it says "security".

How to read it:
- One file holds the baseline and the prototype. Every node's `func:` starts with **unchanged**, **changed** ("was: … / now: …") or **new**. Context nodes are unchanged nodes a changed node calls or relies on.
- Example sources are case ids of `02-test-cases.md`; `P` = the E1 pilot on `98d94d7` (`../evidence-e1/i10e1-pilot-transcript.txt`). An example states the Inc 10 target unless it says "base".
- Values: case 08 (26 546 present rows, page 200; row 150 = `0x00000960`; `BUILD_ID` at `0x00C00050`; `VALUE_0001` @ `0x00000000` = `6C`), fixture three (`0x8000`, `0x8010` all `FF`, `0x8020`).

## Groups and interfaces

24 slice nodes in 3 files and 12 context nodes (E3 addendum, Inc 12 D-2: #11 `_jump_to_validation_issue_object` withdrawn, no product route; before: 25 slice nodes, the header said 24 since round 2 added `SplitJoinWindow.action_export`), grouped by file ownership (one E4 implementer per group; G1's 19 nodes are one file, so one agent; G3's two nodes may go to the same agent, built first, since G1 calls them). Interfaces are pinned here; an E4 agent proposes a change and never changes one alone.

| Group | File | Owns nodes |
|---|---|---|
| G1 app | `s19_app/tui/app.py` | the 19 `S19TuiApp` / module nodes below |
| G2 split-join | `s19_app/tui/segment_split_view.py` | `SplitJoinWindow.refresh_window`, `SplitJoinWindow.check_action`, `SplitJoinWindow.action_export` |
| G3 render | `s19_app/render/hexview.py` | `hex_row_bases`, `_collect_hex_rows` |

| Interface | Pinned form | Producer → consumers |
|---|---|---|
| I-1 | moved to 10b (`SplitJoinWindow.note_image_bytes_written`) | — |
| I-2 open/reload seam | `SplitJoinWindow.refresh_window(self) -> None`: parameters and selection reset unchanged; the `#sje_table` focus only while the window has no `hidden` class | G2 → G1 (`watch_current_file`, `action_open_split_join_export`) |
| I-3 hex view render | `update_alt_hex_view(self, focus_address=None, near_top=False, reset_scroll=False, *, start_row: Optional[int] = None)`, same for `update_mac_hex_view`; `start_row` is an index into the view rows (I-5) and wins over `near_top`; a focus address that is not `None` and differs from the view's marker address clears the marker, `None` keeps it; `_alt_first_visible_address` / `_mac_first_visible_address` = the painted first view row. `update_hex_view(focus_address=None)`: without a focus, `_hex_window_start` kept (clamped to `[0, len(view rows) − 1]`), marker kept, scroll untouched | G1 internal; 10b `_refresh_hex_views_after_write` |
| I-4 focus landing | `_land_focus(self, trigger: Optional[Widget], switch: Optional[str], *, on_switch: bool, layout_waits: int = 3) -> None` (`layout_waits` added at E4 integration, I-D3: callers never pass it; while the shown window has no region the landing re-schedules itself with `layout_waits − 1`), scheduled with `call_after_refresh` by `action_show_screen` (`on_switch=True`, `switch = self._active_screen_key`) and `_apply_unload` (`False`, `switch = None`); a landing whose `switch` is no longer `_active_screen_key` returns without moving (AR2-2); it lands through `screen.set_focus` on `_resolve_focus_target()`; `_resolve_focus_target()` / `_fallback_focus_target()` / `_focus_needs_rehome()` unchanged; `_rehome_focus_after_load()` stays the load tails' | G1 internal |
| I-5 view rows | `hex_row_bases(row_bases: List[int], row_bases_set: Optional[set[int]] = None, extra_addresses: Optional[set[int]] = None) -> List[int]`: the row list `_collect_hex_rows` paints (present rows plus the rows of extra addresses, ascending; the given list itself when nothing is added). `S19TuiApp._hex_view_rows(self) -> list[int]`: `hex_row_bases(current_file.row_bases, bases_set, _collect_mac_highlight_addresses(current_file))`, `[]` without a file | G3 → G1; 10b |
| I-6 hidden-window keys | `SplitJoinWindow.check_action(self, action: str, parameters: tuple) -> Optional[bool]`: `False` while the window has `hidden`, else `super().check_action(action, parameters)` | G2 (Textual calls it) |

Interfaces with Inc 10b (10a merges first; both edit `app.py` and `segment_split_view.py`; no function in common): I-3 (10b's hex refresh renders the main view without a focus and the A2L / MAC views with `start_row`, relying on the kept window, marker and scroll); I-5 (10b bisects the first visible address in `_hex_view_rows()`); I-2 (10b never calls `refresh_window`); I-4 (an in-place write schedules no landing); case R-SEG-OPEN.6/3 stays here and is re-run at 10b's E5.

Interfaces with other increments:

| With | What is shared | Rule |
|---|---|---|
| Inc 6 (in flight, merges first) | none after the split (`_note_image_bytes_written` is 10b's) | — |
| Inc 9 (in flight) | none (`app.py:3988-4572` flow save handlers) | — |
| Inc 5 (merged) | the in-place-write hook and its three callers; the term *in-place write* | reused; scope of the term widened (`../E1-rulings.md` §4); no `refresh_window` from the hook (Inc 5 E3 A-4) |
| Inc 13 (merged) | `segment_split_view.py` `_conflict_marks`, `build_plan`, `_state_text` (conflict first), `_sync` | reused unchanged; D-1 … D-4 of Inc 13 untouched |
| Inc 12 (next in the `app.py` chain) | Inc 12's E1 found one: `_jump_to_validation_issue_object` (10a #11). Inc 12 removes it, with `_jump_to_validation_issue`, `_format_validation_issue_line` and `action_view_main` / `_alt` / `_mac` (its D-2 A). 10a also changes `action_show_screen`, which Inc 12 only calls | E3 addendum (Inc 12 D-2): #11 withdrawn (no product route); 10a changes none of the removed functions, and no 10a test drives them (`../02-test-cases.md`, window-switch rule) |

## Nodes — G1 app

S19TuiApp.update_hex_view
req: R-TUI-018.1, R-TUI-018.2, R-TUI-018.3, R-TUI-018.4, R-TUI-040.4, R-TUI-040.8, R-TUI-040.12, R-TUI-007.3, R-TUI-007.5
in: focus_address: Optional[int]
out: None
func: changed. was: with a focus, `_hex_window_start = (snapped_index // page) * page`, then, with or without a focus, clamped to `max_start` (the last page floor, `app.py:19191-19192`); the scroll untouched; the marker kept. / now (E3 A10-02, A10-03): `rows = _hex_view_rows()`; with a focus, `_hex_window_start = _row_start_for_near_top_focus(focus_address, row_bases, rows)`; then, with or without a focus, one clamp `max(0, min(_hex_window_start, len(rows) − 1))` and no page floor; when a focus address that is not `None` and differs from `_goto_focus_address` the marker is cleared before the render; after a focused render `_reset_scroll_to_top("#hex_scroll")` (both axes). Without a focus: window kept (clamped), marker kept, scroll untouched. (E4 integration, I-D2: the AR2-5 clause — a load resets `_hex_window_start` and a MAC load/unload re-anchors it by the first shown address — is removed: no coverage item of an Inc 10a row requires it, and read literally it contradicts R-TUI-007.8/1's first page; backlog BL-I10-1, with D4-14.)
module: s19_app/tui/app.py
calls: S19TuiApp._hex_view_rows, S19TuiApp._row_start_for_near_top_focus, render_hex_view_text, S19TuiApp._reset_scroll_to_top
examples: (R-TUI-018.1/1) go-to `0x00000960` → start 149; rows `0x00000950`, `0x00000960` (`> `), …; notice `... showing from 0x00000950 ...` (base P: start 0, target on line 151, viewport 28)
examples: (R-TUI-018.1/3) section `0x00040000` → second row `0x00040000`; marker cleared (base P: line 98; marker address `0x50` kept)
examples: (R-TUI-018.1/11) last present row → start = last − 1; 2 rows; no `window limited` notice
examples: (R-TUI-018.2/1) scroll (10, 40), go-to `0x00000140` → (0, 0) (base P: (10, 40))
examples: (no focus, after `.`) → rows from `_hex_window_start`, marker as set
examples: (R-TUI-040.8/4) after a jump to the last present row (start 26 544 of 26 546), a render without a focus → start 26 544 kept (base P7: 26 400, the last page floor)
examples: (R-TUI-018.1/12) MAC below, go-to `0x00008020` → view rows `0x1000`, `0x8000`, `0x8010`, `0x8020`; start 2; rows `0x00008010`, `0x00008020` (base P5: start 1 counted in `row_bases`, target third)
examples: (R-TUI-018.1/13) 80 × 24, go-to `0x00000960` → the `0x00000960` row is the second hex row, below at most 2 notice lines, inside `#hex_scroll`'s region
examples: (unit shape, no product route — Inc 12 D-2; R-TUI-018.3/1 withdrawn) a focus address with no present row → start = (index of the snapped present row in the view rows) − 1; second row = the snapped row. Every shipped main-view jump targets a present row, so no case drives this arm
examples: (R-TUI-018.4/1) go-to `0x00000000` → start 0; first hex row `0x00000000`, no `... showing from` line; the miss after it (#5) re-renders from start 0

S19TuiApp.action_hex_page_next
req: R-TUI-007.3, R-TUI-007.5, R-TUI-007.8
in: —
out: None
func: changed. was: `start = min(max_start, start + page)`, `max_start` from `len(row_bases)`. / now: `total = len(_hex_view_rows())`; `start = start + page if start + page < total else start`; the rest unchanged (search hit and marker cleared, `update_hex_view()`).
module: s19_app/tui/app.py
calls: S19TuiApp._hex_view_rows, S19TuiApp.update_hex_view
examples: (R-TUI-007.3/1) 1 000 rows, start 150 → 350
examples: (R-TUI-007.5/1) start 948 → 948 (base: 800)
examples: (R-TUI-007.3/2) 12 rows, page 5: 0 → 5
examples: (R-TUI-007.8/1) MAC below, page 3: 4 view rows; 0 → 3 (`0x00008020` alone); 3 → 3 (base: `max_start` 0 from 3 present rows, 0 → 0)

S19TuiApp.update_alt_hex_view
req: R-TUI-018.1, R-TUI-018.3, R-TUI-018.4, R-TUI-040.8, R-TUI-040.11, R-TUI-040.12
in: focus_address, near_top, reset_scroll, *, start_row: Optional[int] = None
out: None
func: changed. was: `start_row_index` = near-top index by exact match or None (then the renderer centres with 64 context rows, while `_alt_first_visible_address` records row 0, `app.py:19295-19298`). / now: `rows = _hex_view_rows()`; `start_row` given → `start_row_index = start_row` (clamped to `[0, len(rows) − 1]`); else `near_top` with a focus → `_row_start_for_near_top_focus(focus_address, row_bases, rows)` (snapped, never `None` while rows exist); a focus address that is not `None` and differs from `_alt_goto_focus_address` clears it before the render; `_alt_first_visible_address = rows[effective start]` (the painted first view row).
module: s19_app/tui/app.py
calls: S19TuiApp._hex_view_rows, S19TuiApp._row_start_for_near_top_focus, render_hex_view_text, S19TuiApp._reset_scroll_to_top
examples: (R-TUI-040.11/4) marker on `0x00000050`, window from `0x00000040`; failed go-to → `start_row` = index of `0x00000040` in the view rows → same rows, 0 marked lines
examples: (R-TUI-040.12/5) continued search hit ≠ marker → marker cleared
examples: (R-TUI-018.1/12) MAC below, go-to `0x00008020` → start 2; first rows `0x00008010`, `0x00008020`
examples: (R-TUI-018.3/2) tag find of a tag outside the image → start = snapped row's view index − 1; second row = snapped row (base: no start index, 64 context rows, E1 N-2)
examples: (R-TUI-018.4/1) go-to `0x00000000` → start 0, `_alt_first_visible_address` `0x00000000`; the miss re-renders from index 0

S19TuiApp.update_mac_hex_view
req: R-TUI-018.1, R-TUI-018.3, R-TUI-018.4, R-TUI-040.8, R-TUI-040.11, R-TUI-040.12
in: as update_alt_hex_view
out: None
func: changed. As `update_alt_hex_view` for `#mac_hex_view`, `_mac_goto_focus_address`, `_mac_first_visible_address`, `#mac_hex_scroll`.
module: s19_app/tui/app.py
calls: S19TuiApp._row_start_for_near_top_focus, render_hex_view_text, S19TuiApp._reset_scroll_to_top
examples: (R-TUI-040.11/5) marker set, `zz` → 0 marked lines, rows unchanged
examples: (R-TUI-018.3/3) case 08 + `firmware_issues.mac`; Enter on the `#mac_records_list` row of `0x00FF0000` (In mem `no`) → `_jump_to_mac_address` (unchanged) → `update_mac_hex_view(0x00FF0000, near_top=True, reset_scroll=True)` → snapped to the last present row `0x00C00FF0`; start = its view index − 1; rows `0x00C00FE0`, `0x00C00FF0`, then the MAC-added rows of the valid records outside the image (base: no start index → centred on the `0x00FF0000` row with 64 context rows)

S19TuiApp._handle_goto
req: R-TUI-040.8, R-TUI-040.11, R-TUI-018.4
in: — (reads `#goto_input`)
out: None
func: changed. was: empty / invalid → marker field cleared, no render; miss → `_apply_goto` status, nothing cleared. / now: on each failure, after its status: if a marker was set, clear it and `update_hex_view()`; if none was set, no render (TC-007 keeps 0 calls).
module: s19_app/tui/app.py
calls: S19TuiApp._apply_goto, S19TuiApp.update_hex_view, S19TuiApp.set_status
examples: (R-TUI-040.11/1) hit `0x00000050` then `0xFFFFFFF0` → `Address 0xFFFFFFF0 not in loaded file.`; 0 marked lines; rows unchanged (base P: marker on line 6)
examples: (R-TUI-040.11/3) `zz` → `Invalid address format.`; 0 marked lines (base P: line 6)
examples: (R-TUI-040.8/1) no marker set, miss → 0 `update_hex_view` calls

S19TuiApp._handle_goto_alt
req: R-TUI-018.1, R-TUI-018.2, R-TUI-040.4, R-TUI-040.8, R-TUI-040.11
in: — (reads `#alt_goto_input`)
out: None
func: changed. was: hit → `update_alt_hex_view(addr)`; failures as `_handle_goto` on base. / now: hit → `update_alt_hex_view(addr, near_top=True, reset_scroll=True)`; failure with a marker → clear, `update_alt_hex_view(start_row=<index of _alt_first_visible_address>)`.
module: s19_app/tui/app.py
calls: S19TuiApp._apply_goto, S19TuiApp.update_alt_hex_view
examples: (R-TUI-018.1/6) `0x00000960` → second row `0x00000960` (base P: row 65, 64 context rows, viewport 37)
examples: (R-TUI-040.11/4) as `update_alt_hex_view`

S19TuiApp._handle_goto_mac
req: R-TUI-018.1, R-TUI-018.2, R-TUI-040.4, R-TUI-040.8, R-TUI-040.11
in: — (reads `#mac_goto_input`)
out: None
func: changed. As `_handle_goto_alt`, for `#mac_goto_input` and the MAC view.
module: s19_app/tui/app.py
calls: S19TuiApp._apply_goto, S19TuiApp.update_mac_hex_view
examples: (R-TUI-018.1/9) `0x00000960` → second row `0x00000960` (base: 64 context rows, guide ch05-04)

S19TuiApp._handle_search_alt
req: R-TUI-018.1, R-TUI-018.2, R-TUI-040.12
in: — (reads `#alt_search_input`)
out: None
func: changed. was: `update_alt_hex_view(addr)`. / now: `update_alt_hex_view(addr, near_top=True, reset_scroll=True)`; the marker clear comes from I-3.
module: s19_app/tui/app.py
calls: find_string_in_mem, S19TuiApp.update_alt_hex_view
examples: (R-TUI-018.1/7) `BUILD_ID` → `Found at 0x00C00050`; second row `0x00C00050`

S19TuiApp._handle_search_mac
req: R-TUI-018.1, R-TUI-018.2, R-TUI-040.12
in: — (reads `#mac_search_input`)
out: None
func: changed. As `_handle_search_alt` for the MAC view.
module: s19_app/tui/app.py
calls: find_string_in_mem, S19TuiApp.update_mac_hex_view
examples: (R-TUI-018.1/10) `BUILD_ID` → second row `0x00C00050`; (R-TUI-040.12/6) a continued hit clears the marker

S19TuiApp._handle_a2l_tag_find_next
req: R-TUI-018.1, R-TUI-018.3
in: —
out: None
func: changed. was: `update_alt_hex_view(addr)` for a tag with an address. / now: `update_alt_hex_view(addr, near_top=True, reset_scroll=True)`; the rest unchanged.
module: s19_app/tui/app.py
calls: S19TuiApp.update_alt_hex_view
examples: (R-TUI-018.1/8) `VALUE_0200` → its address row is the second row

S19TuiApp._jump_to_validation_issue_object — withdrawn (no product route — Inc 12 D-2)
func: unchanged; not a slice node and not counted. Its only caller, `_jump_to_validation_issue` (the legacy ListView adapter), has no caller on `98d94d7` or on main `2d1e2b1`. Enter on an issue row runs `on_issue_row_selected` → `_update_issues_hex_pane` (the Issues peek). Its A2L and MAC renders keep the 64-row centring, which no product route reaches. Inc 12 removes it (its D-2 A). Cases R-TUI-018.1/5, R-TUI-018.3/1 and R-TUI-040.12/2 are withdrawn with it; R-TUI-018.3's MAC arm is re-pointed to R-TUI-018.3/3 (`update_mac_hex_view` above).

_unload_primary
req: R-WS-LOADED.16, R-WS-LOADED.19, R-WS-LOADED.20
in: loaded: LoadedFile
out: Optional[LoadedFile]
func: changed. was: when `_has_mac`, the MAC-only `replace(...)` keeps `path` (the unloaded image's) and `errors` (the primary's). / now (E3 S-2, A10-07; D-5 withdrawn, D-7): when `loaded.mac_path is not None`, the same `replace(...)` also sets `path=loaded.mac_path` and `errors=[{"line": None, "message": d} for d in loaded.mac_diagnostics]` (the shape a MAC-only load builds, `app.py:16924`, `:16948-16960`); `mem_map`, rows, ranges stay empty; MAC records with no MAC file, or no MAC → None.
module: s19_app/tui/app.py
calls: dataclasses.replace
examples: (R-WS-LOADED.16/1) 1 bad-checksum diagnostic + case 08 MAC (no MAC diagnostic) → `errors` `[]`; Issues 0 loader diagnostics (base P: 1)
examples: (R-WS-LOADED.16/2) no MAC → None
examples: (R-WS-LOADED.16/3) bad S19 + `firmware_issues.mac` (2 diagnostics) → `errors` = those 2, as a MAC-only load of it (E1 shape `errors=[]`: 0)
examples: (R-WS-LOADED.19/1) `unloaded_primary.s19` + `firmware.mac`, `[u]` primary → `path` = `firmware.mac`; Save project `P6` plans the MAC as its only data file → no `.s19` in `P6` (base security P6: `P6/unloaded_primary.s19`)
examples: (R-WS-LOADED.19/2) no unload → the S19 is planned and placed (the control)
examples: (R-WS-LOADED.20/1) after the unload, a project load with an unsaved entry → `_load_question_text` reads `current_file.path.name` = `firmware.mac` → `Replace firmware.mac?` (base: `Replace unloaded_primary.s19?`)
examples: (unit shape, no product route) `mac_records` set, `mac_path` None → None

S19TuiApp._apply_unload
req: R-WS-LOADED.13, R-WS-LOADED.14, R-WS-LOADED.18, R-SHELL-FOCUS.3, R-SHELL-FOCUS.4
in: kind: str
out: None
func: changed. was: `all` always proceeds (`Unloaded all artifacts.` with nothing loaded); ends with `set_status(f"Unloaded {label}.")`; no file-status write; no focus step. / now: (a) `kind == "all"` with `current_file is None` and `current_a2l_path is None` → `set_status("Nothing to unload.")`, return; (b) after `_refresh_loaded_panel()`: `set_file_status(f"Unloaded {label}.")` and the unchanged `set_status(...)` (one message line; `set_file_status` writes no message); (c) E3 A10-01, AR2-1: `trigger = default_screen.focused` read before (a)'s changes, and as the last step `call_after_refresh(self._land_focus, trigger, None, on_switch=False)` (no synchronous re-home; the focus has already moved — `_refresh_loaded_panel()` removes the button and Textual's prune reset moves the focus to `window_help_workspace` synchronously inside `_apply_unload`, P3).
module: s19_app/tui/app.py
calls: _unload_primary, _unload_mac, _unload_a2l, S19TuiApp._replace_current_a2l, S19TuiApp.set_file_status, S19TuiApp.set_status, App.call_after_refresh, S19TuiApp._land_focus
examples: (R-WS-LOADED.18/1) S19+MAC, `[u]` MAC → `#status_text` `Unloaded MAC.`, newest message `Unloaded MAC.` (base P: `Loaded firmware.mac (S19+MAC)`)
examples: (R-WS-LOADED.14/1) nothing loaded, `U` → `Nothing to unload.`; `#status_text` `Ready.` (base P: `Unloaded all artifacts.`)
examples: (R-WS-LOADED.14/2) A2L-only, `U` → `Unloaded all artifacts.`
examples: (R-SHELL-FOCUS.4/1) `files_list` focused, `U` → `files_list` (with I-2; base P: `sje_table`, area 0)
examples: (R-SHELL-FOCUS.3/1) the MAC `[u]` focused and pressed → `_refresh_loaded_panel()` removes the button and Textual's prune reset moves the focus to `window_help_workspace` synchronously inside `_apply_unload`; the landing sees `focused is not trigger` → `files_list` (P3: a synchronous re-home gives `window_help_workspace`)
examples: (R-SHELL-FOCUS.3/2) nothing focused, `U` → the landing sees `None` → `files_list`
examples: (R-SHELL-FOCUS.4/2) `rail_item_workspace` focused, `U` → healthy and attached → kept

S19TuiApp._format_coexistence_status
req: R-TUI-012L.8
in: loaded: LoadedFile, path: Path
out: str
func: changed. was: `path.name` and `loaded.mac_path.name` formatted raw in the 5 returns. / now: `painted_names([path.name])` and `painted_names([loaded.mac_path.name])`; texts otherwise identical.
module: s19_app/tui/app.py
calls: _integrity_notice_codes, painted_names
examples: (R-TUI-012L.8/1) `fw` U+202E `gpj.s19` → `Loaded fwgpj.s19 (S19 only)` (base P: U+202E kept)
examples: (R-TUI-012L.8/4) `firmware.s19` → `Loaded firmware.s19 (S19 only)`
examples: (R-TUI-012L.8/2) MAC `m` U+200B `x.mac` → `… (S19+MAC: mx.mac)`; the message line (`_append_log_line`, `:18206`) gets the same text, so the composer's scrub is what keeps the log clean
examples: (A10-06) a 130-character name → its first 119 characters + `…` (the `painted_names` clip)

S19TuiApp.action_show_screen
req: R-SHELL-FOCUS.2, R-SHELL-FOCUS.5, R-SEG-OPEN.6
in: screen_key: str
out: None
func: changed. was: swaps the `hidden` classes, hides Split / Join, moves the rail marker, runs the entry prefills; no focus move. / now (E3 A10-01 = S-4, D-8): identical, then, before `refresh_bindings()`: (1) when `default_screen.focused` has an ancestor in `_WINDOW_CONTAINER_IDS` that now has `hidden`, `default_screen.set_focus(None)` at once (a class test, valid before any layout); (2) when the call changed what is shown (the shown window's container had `hidden` before the swap, or Split / Join was displayed), `call_after_refresh(self._land_focus, default_screen.focused, self._active_screen_key, on_switch=True)`; a call that shows the window already shown (`1` on the Workspace, a click on the active rail item; on the base also `action_view_main`, which Inc 12 removes and no 10a test drives) schedules no landing and a healthy focus there stays (AR2-4). No synchronous landing: the window un-hidden in this call has no region until the next layout (Textual `widget.py:2285-2294`, P1/P2). Unknown key → return as on base. Every caller gets it (A10-11: rail keys and clicks, palette, Memory Map open-in-hex, window help, `action_view_*` (removed by Inc 12; tests switch with the keys or `action_show_screen`), the Split / Join close).
module: s19_app/tui/app.py
calls: Rail.set_active, S19TuiApp._apply_empty_state, Screen.set_focus, App.call_after_refresh, S19TuiApp._land_focus
examples: (R-SHELL-FOCUS.2/1) `files_list` focused, `2` → `a2l_tags_list` (base P: `ws_load_project_button`, hidden, area 0)
examples: (R-SHELL-FOCUS.2/2) Split / Join open from the Workspace, Esc → `files_list` (base P: none)
examples: (R-SHELL-FOCUS.2/4) `rail_item_workspace` focused, `]` → `fx_panel`; `c` still confirms
examples: (R-SHELL-FOCUS.5/1) target paints no region → first shown focusable non-text widget, else the rail item
examples: (R-SHELL-FOCUS.2/6) a Patch Editor button focused, `1`: the button's window is hidden → focus cleared at once; an Enter before the landing reaches no Patch Editor control (no `Validate:`; base security P5: `Validate: 1 entry, 0 error(s), 0 warning(s)`); the landing → `files_list`
examples: (R-SHELL-FOCUS.2/3) Split / Join open, `3` → `sje_table` sits in the window just hidden → cleared; landing → `mac_records_list` (base P: none)

Moved to 10b at E3: `_note_image_bytes_written`, `_refresh_a2l_values_after_write` (`../../inc-10b/codewire/graph-inc10b.md`). R-SEG-OPEN.6/3 (a write while Split / Join is hidden: no focus inside `#screen_split_join`) stays a 10a case; 10b re-runs it.

S19TuiApp._land_focus
req: R-SHELL-FOCUS.2, R-SHELL-FOCUS.3, R-SHELL-FOCUS.4, R-SHELL-FOCUS.5, R-SEG-OPEN.6
in: trigger: Optional[Widget], switch: Optional[str], *, on_switch: bool
out: None
func: new (E3 A10-01, AR2-1, AR2-2). `switch` is not `None` and is not the latest `self._active_screen_key` → return (a stale landing does nothing, AR2-2). E4 integration (I-D3): the shown window's container (`SCREEN_CONTAINER_IDS[_active_screen_key]`, or `#screen_split_join`) has no region yet and `layout_waits > 0` → `call_after_refresh(self._land_focus, trigger, switch, on_switch=on_switch, layout_waits=layout_waits − 1)` and return (an after-refresh callback can run before the layout that gives the window just shown its region: `#screen_mac` area 0 at the landing of the two-key burst, int-07). `focused = default_screen.focused` (never `self.focused`: a dialog keeps its own focus, R-SHELL-FOCUS.7); an unmounted tree → return. Move when `focused is None`, or `_focus_needs_rehome(focused)`, or (`on_switch` and `focused is trigger`), or (not `on_switch` and `focused is not trigger`) (AR2-1: `not trigger.is_attached` is dropped — the prune reset moves the focus synchronously inside `_apply_unload`, and the removed button's own task exit is not ordered against the landing). Then `target = _resolve_focus_target()` (it reads `_active_screen_key` now); not `None` → `target.screen.set_focus(target)`. Otherwise the focus stays (a caller or the operator moved it since the trigger).
module: s19_app/tui/app.py
calls: S19TuiApp._focus_needs_rehome, S19TuiApp._resolve_focus_target, Screen.set_focus
examples: (R-SHELL-FOCUS.2/1) `2` from `files_list`: trigger `None` (cleared), focused `None` → `a2l_tags_list` (P2 deferred variant: `a2l_tags_list`; base P: `ws_load_project_button`)
examples: (R-SHELL-FOCUS.2/4) `]` from `rail_item_workspace` (frame widget, not cleared): focused is the trigger → `fx_panel`; `c` still confirms
examples: (R-SHELL-FOCUS.2/7) `2` then `3` in one burst: the `2` landing is stamped `a2l` and is stale once `_active_screen_key` is `mac` → it does nothing; the `3` landing (stamped `mac`) → `mac_records_list`
examples: (a caller's own focus) `action_show_screen("workspace")` then the caller focuses `#goto_input` before the refresh → focused is not the trigger and healthy → `#goto_input` kept
examples: (R-SHELL-FOCUS.3/1) unload: trigger the removed `[u]`, focused `window_help_workspace` (moved by the prune reset inside `_apply_unload`) → `focused is not trigger` → `files_list`
examples: (R-SHELL-FOCUS.4/1) unload: trigger `files_list`, focused `files_list`, attached, healthy → kept

S19TuiApp._row_start_for_near_top_focus
req: R-TUI-018.1, R-TUI-018.3, R-TUI-018.4
in: focus_address: Optional[int], row_bases: list[int], view_rows: list[int], context_rows: int = 1
out: Optional[int]
func: changed (E3 A10-03). was: `row_bases.index(focus_base)` (exact; `None` when the row is absent) minus `context_rows`, in `row_bases`. / now: no focus or no rows → `None`; `i = _snapped_focus_row_index(focus_address, row_bases)` (the CTX-HEX target row: next present row, else the last); `j = bisect_left(view_rows, row_bases[i])` (its index in the view rows); return `max(0, j − context_rows)`.
module: s19_app/tui/app.py
calls: S19TuiApp._snapped_focus_row_index, bisect.bisect_left
examples: (R-TUI-018.1/12) MAC below, `0x8020` → `i` 2, `j` 3 → 2
examples: (R-TUI-018.3/2) a tag at an absent address `A` → `i` = the first present row at or after `A`'s row base → `j − 1` (base: `None`)
examples: (R-TUI-018.4/1) `0x00000000` → `j` 0 → 0
examples: (R-TUI-018.1/6) case 08, `0x00000960` → 149

S19TuiApp._hex_view_rows
req: R-TUI-018.1, R-TUI-007.8
in: —
out: list[int]
func: new (E3 A10-03, I-5; AR2-6 (b)). No `current_file` → `[]`; else `hex_row_bases(current_file.row_bases or [], getattr(current_file, "bases_set", None), _collect_mac_highlight_addresses(current_file))`, memoised on the image generation and the MAC record set so one sorted list is built per render and shared by the paging, the render and the first-visible reads.
module: s19_app/tui/app.py
calls: hex_row_bases, S19TuiApp._collect_mac_highlight_addresses
examples: (R-TUI-007.8/1) MAC below → `[0x1000, 0x8000, 0x8010, 0x8020]`
examples: (R-TUI-018.1/1) case 08 with no MAC → `row_bases` itself (no copy)

S19TuiApp._first_visible_hex_address
req: R-TUI-018.1, R-TUI-040.12
in: view: str
out: Optional[int]
func: changed (E3 A10-03). was: main → `row_bases[_hex_window_start]`. / now: main → `_hex_view_rows()[_hex_window_start]` (the painted first row); A2L, MAC unchanged (their fields hold the painted first view row, I-3).
module: s19_app/tui/app.py
calls: S19TuiApp._hex_view_rows
examples: (R-TUI-018.1/12) MAC below, window start 0 → `0x00001000` (base: `row_bases[0]` = `0x00008000`, a row below the painted first row)

S19TuiApp.set_file_status
req: R-SHELL-STATUS.7, R-WS-LOADED.18
in: message: str
out: None
func: changed (E3 S-5, D-12). was: `_busy.file_state = safe_text(str(message)).plain` (C0 / C1 removed). / now: `text = str(message)`; every character of category Cc, Cf, Zl or Zp removed (`painted_names([text], limit=1, clip=max(1, len(text)))`: its filter, no clip); then `safe_text(...).plain`; the paint rule unchanged.
module: s19_app/tui/app.py
calls: painted_names, safe_text, S19TuiApp._paint_status_text
examples: (R-SHELL-STATUS.7/1) `Loaded project 'PB' -> fw` U+202E `gpj.s19` → `Loaded project 'PB' -> fwgpj.s19` (base security P7: U+202E kept)
examples: (R-SHELL-STATUS.7/2) `… -> fwgpj.s19 + m` U+200B `x.mac` → `… -> fwgpj.s19 + mx.mac`
examples: (R-WS-LOADED.18/1) `Unloaded MAC.` → unchanged

## Nodes — G2 split-join

SplitJoinWindow.refresh_window
req: R-SEG-OPEN.1, R-SEG-OPEN.6
in: —
out: None
func: changed. was: selection reset on a new image, `_sync()`, `call_after_refresh(_sync)`, then `#sje_table` focused always. / now: identical, but the focus only `if not self.has_class("hidden")`.
module: s19_app/tui/segment_split_view.py
calls: SplitJoinWindow._sync, Widget.focus
examples: (R-SEG-OPEN.1/1) palette open → `sje_table` focused
examples: (R-SEG-OPEN.6/1) window hidden, `U` (via `watch_current_file`) → focus not moved (base P: `sje_table`, area 0)

SplitJoinWindow.check_action
req: R-SEG-OPEN.7
in: action: str, parameters: tuple
out: Optional[bool]
func: new (E3 S-3, D-11, I-6). `if self.has_class("hidden"): return False`; else `return super().check_action(action, parameters)`. Textual asks it for every binding of the window (`␣`, `a`, `n`, `t`, `m`, `g`, `f`, `p`, `d`, `e`, Esc, arrows); a refused key goes on to the app's bindings.
module: s19_app/tui/segment_split_view.py
calls: WindowSection.check_action
examples: (R-SEG-OPEN.7/3) window hidden, focus put on `#sje_table`, `a`, `e` → both refused; 0 files, no `Exported` (base security P3: 4 files, `Exported 4 files: wrote firmware_range_00.s19; …`)
examples: (R-SEG-OPEN.7/1) `[u]` MAC from `files_list`, then `a`, `e` → the focus never enters the window (I-2, the landing); `a`, `e` reach the app → 0 files
examples: (R-SEG-OPEN.7/2) `U` from `files_list`, then `a`, `e` → as /1 (base security P3 shape: `refresh_window` focused the hidden `sje_table`, 4 files)
examples: (R-SEG-OPEN.1/1) window shown → `super()`'s answer, `e` exports as before

SplitJoinWindow.action_export
req: R-SEG-OPEN.7
in: —
out: None
func: changed (E3 SR2-1). was: `on_button_pressed` (`#sje_export`) → `action_export()` directly; nothing on that path asks `check_action` (`textual/widgets/_button.py:297,429`). / now: `if self.has_class("hidden"): return` at the top, before the export body; `check_action` (I-6) stays for the other keys.
module: s19_app/tui/segment_split_view.py
calls: —
examples: (R-SEG-OPEN.7/4) window opened and closed (Esc), the focus put on `#sje_export`, Enter → `action_export` returns at once: 0 files, no `Exported` (with I-6 alone the button's own binding runs the export, E3 security R2-1)
examples: (R-SEG-OPEN.1/1) window shown → export proceeds as before

Moved to 10b at E3: `SplitJoinWindow.note_image_bytes_written` (I-1).

## Nodes — G3 render

hex_row_bases
req: R-TUI-018.1, R-TUI-007.8
in: row_bases: List[int], row_bases_set: Optional[set[int]] = None, extra_addresses: Optional[set[int]] = None
out: List[int]
func: new (E3 A10-03, I-5). The row list `_collect_hex_rows` builds today (`render/hexview.py:192-207`), moved out unchanged: no extra address, or every extra row already present → `row_bases` itself (no copy, the multi-million-row hot path); else `sorted(existing | extra_rows)` with `existing = row_bases_set or set(row_bases)`.
module: s19_app/render/hexview.py
calls: —
examples: (R-TUI-007.8/1) `[0x8000, 0x8010, 0x8020]`, extra `{0x1000}` → `[0x1000, 0x8000, 0x8010, 0x8020]`
examples: (R-TUI-018.1/1) case 08, extra `{}` → the same list object

_collect_hex_rows
req: R-TUI-007.8
in: as on base
out: as on base
func: changed. was: builds `bases` inline. / now: `bases = hex_row_bases(base_row_bases, row_bases_set, extra)`; everything after unchanged (output identical for every input).
module: s19_app/render/hexview.py
calls: hex_row_bases
examples: (R-TUI-018.1/12) MAC below, `start_row_index` 2 → rows `0x8010`, `0x8020`; notice `... showing from 0x00008010 ...`

## Context nodes (unchanged)

S19TuiApp._rehome_focus_after_load — req: R-SHELL-FOCUS.3, R-SHELL-FOCUS.4 — the load tails' synchronous re-home, kept for them; the unload uses `_land_focus` (E3).
S19TuiApp._focus_needs_rehome — req: R-SHELL-FOCUS.3 — zero area, or an ancestor window with `hidden` (`app.py:9967-10020`).
S19TuiApp._fallback_focus_target — req: R-SHELL-FOCUS.5 — the window's first shown focusable non-text widget, else the active rail item (`app.py:10022-10077`).
S19TuiApp._snapped_focus_row_index — req: R-TUI-018.3 — next present row at or after the target's row base, else the last (`app.py:19134-19171`).
S19TuiApp._collect_mac_highlight_addresses — req: R-TUI-007.8 — the valid MAC record addresses (`app.py:17073-17082`).
S19TuiApp._plan_project_save — req: R-WS-LOADED.19 — plans `loaded.path` as the project's data file (`app.py:13054-13081`); after #12 that is the MAC file.
S19TuiApp._load_question_text — req: R-WS-LOADED.20 — `<current>` = project, else `current_file.path.name`, else `the current session` (`app.py:8703-8709`).
S19TuiApp._resolve_focus_target — req: R-SHELL-FOCUS.2, R-SHELL-FOCUS.5 — `_FOCUS_TARGETS[_active_screen_key]`, fallback `_fallback_focus_target` (R-SHELL-FOCUS.6).
render_hex_view_text — req: R-TUI-018.1 — `start_row_index` wins over the focus centring; notice lines above the rows.
S19TuiApp._reset_scroll_to_top — req: R-TUI-018.2 — `scroll_home(animate=False)` (Textual 8.2.8: both axes).
painted_names — req: R-TUI-012L.8 — `project_gather_service.py:978`, Cc/Cf/Zl/Zp removed, 120-character clip.
SplitJoinWindow._sync — req: R-SEG-OPEN.1 — called by `refresh_window`; reads `current_file.mem_map` live; `build_plan` → `_conflict_marks` (Inc 13).
