# Code-Wire graph — Inc 10 (hex navigation, unload state, Split/Join focus, views after in-place writes), batch-101

Stage E2 of the design-first flow (`dev-flow-v3-beta`). Graph only: no stub, mark or declaration in any tree. Base `98d94d7`. Requirements `../01-requirements.md`, slice `../E1-slice.md`, rulings `../E1-rulings.md`, cases `../02-test-cases.md`.

How to read it:
- One file holds the baseline and the prototype. Every node's `func:` starts with **unchanged**, **changed** ("was: … / now: …") or **new**. Context nodes are unchanged nodes a changed node calls or relies on.
- Example sources are case ids of `02-test-cases.md`; `P` = the E1 pilot on `98d94d7` (`../evidence-e1/i10e1-pilot-transcript.txt`). An example states the Inc 10 target unless it says "base".
- Values: case 08 (26 546 present rows, page 200; row 150 = `0x00000960`; `BUILD_ID` at `0x00C00050`; `VALUE_0001` @ `0x00000000` = `6C`), fixture three (`0x8000`, `0x8010` all `FF`, `0x8020`).

## Groups and interfaces

19 slice nodes in 2 files, grouped by file ownership (one E4 implementer per group; G1's 17 nodes are one file, so one agent). Interfaces are pinned here; an E4 agent proposes a change and never changes one alone.

| Group | File | Owns nodes |
|---|---|---|
| G1 app | `s19_app/tui/app.py` | the 17 `S19TuiApp` / module nodes below |
| G2 split-join | `s19_app/tui/segment_split_view.py` | `SplitJoinWindow.refresh_window`, `SplitJoinWindow.note_image_bytes_written` |

| Interface | Pinned form | Producer → consumers |
|---|---|---|
| I-1 in-place write notice | `SplitJoinWindow.note_image_bytes_written(self) -> None`: public, no argument; while the window has no `hidden` class it calls `self._sync()` once; while hidden it does nothing; it never focuses and never calls `refresh_window` | G2 → G1 (`_note_image_bytes_written`) |
| I-2 open/reload seam | `SplitJoinWindow.refresh_window(self) -> None`: parameters and selection reset unchanged; the `#sje_table` focus only while the window has no `hidden` class | G2 → G1 (`watch_current_file`, `action_open_split_join_export`) |
| I-3 hex view render | `update_alt_hex_view(self, focus_address=None, near_top=False, reset_scroll=False, *, start_row: Optional[int] = None)`, same for `update_mac_hex_view`; `start_row` wins over `near_top`; a focus address that differs from the view's marker address clears the marker | G1 internal |
| I-4 focus landing | `_resolve_focus_target()` / `_fallback_focus_target()` / `_rehome_focus_after_load()` used unchanged, through `screen.set_focus` | G1 internal |

Interfaces with other increments:

| With | What is shared | Rule |
|---|---|---|
| Inc 6 (in flight, merges first) | `S19TuiApp._note_image_bytes_written` (Inc 6 adds the Checks-run end, the Patch Editor load tail and `update_checks_view`) | Inc 10 appends two notices after Inc 6's body; E4 writes on main after Inc 6's merge |
| Inc 9 (in flight) | none (`app.py:3988-4572` flow save handlers) | — |
| Inc 5 (merged) | the in-place-write hook and its three callers; the term *in-place write* | reused; scope of the term widened (`../E1-rulings.md` §4); no `refresh_window` from the hook (Inc 5 E3 A-4) |
| Inc 13 (merged) | `segment_split_view.py` `_conflict_marks`, `build_plan`, `_state_text` (conflict first), `_sync` | reused unchanged; D-1 … D-4 of Inc 13 untouched |
| Inc 12 (next in the `app.py` chain) | no function named in common at E1 | re-checked at Inc 12's E1 |

## Nodes — G1 app

S19TuiApp.update_hex_view
req: R-TUI-018.1, R-TUI-018.2, R-TUI-040.4, R-TUI-040.12, R-TUI-007.3, R-TUI-007.5
in: focus_address: Optional[int]
out: None
func: changed. was: with a focus, `_hex_window_start = (snapped_index // page) * page`, then clamped to `max_start` (the last page floor); the scroll untouched; the marker kept. / now: with a focus, `_hex_window_start = max(0, snapped_index − 1)`, clamped to `[0, len(row_bases) − 1]`; when `focus_address != _goto_focus_address` the marker is cleared before the render; after the render `_reset_scroll_to_top("#hex_scroll")` (both axes). Without a focus: unchanged (window kept, marker kept).
module: s19_app/tui/app.py
calls: S19TuiApp._snapped_focus_row_index, render_hex_view_text, S19TuiApp._reset_scroll_to_top
examples: (R-TUI-018.1/1) go-to `0x00000960` → start 149; rows `0x00000950`, `0x00000960` (`> `), …; notice `... showing from 0x00000950 ...` (base P: start 0, target on line 151, viewport 28)
examples: (R-TUI-018.1/3) section `0x00040000` → second row `0x00040000`; marker cleared (base P: line 98; marker address `0x50` kept)
examples: (R-TUI-018.1/11) last present row → start = last − 1; 2 rows; no `window limited` notice
examples: (R-TUI-018.2/1) scroll (10, 40), go-to `0x00000140` → (0, 0) (base P: (10, 40))
examples: (no focus, after `.`) → rows from `_hex_window_start`, marker as set

S19TuiApp.action_hex_page_next
req: R-TUI-007.3, R-TUI-007.5
in: —
out: None
func: changed. was: `start = min(max_start, start + page)`. / now: `start = start + page if start + page < total else start`; the rest unchanged (search hit and marker cleared, `update_hex_view()`).
module: s19_app/tui/app.py
calls: S19TuiApp.update_hex_view
examples: (R-TUI-007.3/1) 1 000 rows, start 150 → 350
examples: (R-TUI-007.5/1) start 948 → 948 (base: 800)
examples: (R-TUI-007.3/2) 12 rows, page 5: 0 → 5

S19TuiApp.update_alt_hex_view
req: R-TUI-040.8, R-TUI-040.11, R-TUI-040.12
in: focus_address, near_top, reset_scroll, *, start_row: Optional[int] = None
out: None
func: changed. was: `start_row_index` = near-top index or None (then the renderer centres with 64 context rows). / now: `start_row` given → `start_row_index = start_row` (clamped); a focus address that differs from `_alt_goto_focus_address` clears it before the render; otherwise unchanged (`_alt_first_visible_address` from the effective start).
module: s19_app/tui/app.py
calls: S19TuiApp._row_start_for_near_top_focus, render_hex_view_text, S19TuiApp._reset_scroll_to_top
examples: (R-TUI-040.11/4) marker on `0x00000050`, window from `0x00000040`; failed go-to → `start_row` = index of `0x00000040` → same rows, 0 marked lines
examples: (R-TUI-040.12/5) continued search hit ≠ marker → marker cleared

S19TuiApp.update_mac_hex_view
req: R-TUI-040.8, R-TUI-040.11, R-TUI-040.12
in: as update_alt_hex_view
out: None
func: changed. As `update_alt_hex_view` for `#mac_hex_view`, `_mac_goto_focus_address`, `_mac_first_visible_address`, `#mac_hex_scroll`.
module: s19_app/tui/app.py
calls: S19TuiApp._row_start_for_near_top_focus, render_hex_view_text, S19TuiApp._reset_scroll_to_top
examples: (R-TUI-040.11/5) marker set, `zz` → 0 marked lines, rows unchanged

S19TuiApp._handle_goto
req: R-TUI-040.8, R-TUI-040.11
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
req: R-TUI-018.1
in: —
out: None
func: changed. was: `update_alt_hex_view(addr)` for a tag with an address. / now: `update_alt_hex_view(addr, near_top=True, reset_scroll=True)`; the rest unchanged.
module: s19_app/tui/app.py
calls: S19TuiApp.update_alt_hex_view
examples: (R-TUI-018.1/8) `VALUE_0200` → its address row is the second row

S19TuiApp._jump_to_validation_issue_object
req: R-TUI-018.1, R-TUI-018.2, R-TUI-040.12
in: issue: ValidationIssue
out: None
func: changed. was: `update_hex_view(a)`, `update_alt_hex_view(a)`, `update_mac_hex_view(a)`. / now: the A2L and MAC calls with `near_top=True, reset_scroll=True`; the main call unchanged (near-top through `update_hex_view`).
module: s19_app/tui/app.py
calls: S19TuiApp.update_hex_view, S19TuiApp.update_alt_hex_view, S19TuiApp.update_mac_hex_view
examples: (R-TUI-018.1/5) issue at *A* → second row of each view = *A*'s row; (R-TUI-040.12/2) three markers cleared

_unload_primary
req: R-WS-LOADED.16
in: loaded: LoadedFile
out: Optional[LoadedFile]
func: changed. was: the MAC-only `replace(...)` keeps `errors`. / now: also `errors=[]`; `path` unchanged (D-5); no MAC → None as on base.
module: s19_app/tui/app.py
calls: dataclasses.replace, _has_mac
examples: (R-WS-LOADED.16/1) 1 bad-checksum diagnostic + MAC → MAC-only spine with 0 errors; Issues 0 loader diagnostics (base P: 1)
examples: (R-WS-LOADED.16/2) no MAC → None

S19TuiApp._apply_unload
req: R-WS-LOADED.13, R-WS-LOADED.14, R-WS-LOADED.18, R-SHELL-FOCUS.3, R-SHELL-FOCUS.4
in: kind: str
out: None
func: changed. was: `all` always proceeds (`Unloaded all artifacts.` with nothing loaded); ends with `set_status(f"Unloaded {label}.")`; no file-status write; no focus step. / now: (a) `kind == "all"` with `current_file is None` and `current_a2l_path is None` → `set_status("Nothing to unload.")`, return; (b) after `_refresh_loaded_panel()`: `set_file_status(f"Unloaded {label}.")` and the unchanged `set_status(...)` (one message line; `set_file_status` writes no message); (c) last: `_rehome_focus_after_load()`.
module: s19_app/tui/app.py
calls: _unload_primary, _unload_mac, _unload_a2l, S19TuiApp._replace_current_a2l, S19TuiApp.set_file_status, S19TuiApp.set_status, S19TuiApp._rehome_focus_after_load
examples: (R-WS-LOADED.18/1) S19+MAC, `[u]` MAC → `#status_text` `Unloaded MAC.`, newest message `Unloaded MAC.` (base P: `Loaded firmware.mac (S19+MAC)`)
examples: (R-WS-LOADED.14/1) nothing loaded, `U` → `Nothing to unload.`; `#status_text` `Ready.` (base P: `Unloaded all artifacts.`)
examples: (R-WS-LOADED.14/2) A2L-only, `U` → `Unloaded all artifacts.`
examples: (R-SHELL-FOCUS.4/1) `files_list` focused, `U` → `files_list` (with I-2; base P: `sje_table`, area 0)
examples: (R-SHELL-FOCUS.3/1) the MAC `[u]` focused and pressed → `files_list`

S19TuiApp._format_coexistence_status
req: R-TUI-012L.8
in: loaded: LoadedFile, path: Path
out: str
func: changed. was: `path.name` and `loaded.mac_path.name` formatted raw in the 5 returns. / now: `painted_names([path.name])` and `painted_names([loaded.mac_path.name])`; texts otherwise identical.
module: s19_app/tui/app.py
calls: _integrity_notice_codes, painted_names
examples: (R-TUI-012L.8/1) `fw` U+202E `gpj.s19` → `Loaded fwgpj.s19 (S19 only)` (base P: U+202E kept)
examples: (R-TUI-012L.8/4) `firmware.s19` → `Loaded firmware.s19 (S19 only)`

S19TuiApp.action_show_screen
req: R-SHELL-FOCUS.2, R-SHELL-FOCUS.5, R-SEG-OPEN.6
in: screen_key: str
out: None
func: changed. was: swaps the `hidden` classes, hides Split / Join, moves the rail marker, runs the entry prefills; no focus move. / now: identical, then `target = _resolve_focus_target()`; if not None, `target.screen.set_focus(target)` (before `refresh_bindings()`); unknown key → return as on base.
module: s19_app/tui/app.py
calls: Rail.set_active, S19TuiApp._apply_empty_state, S19TuiApp._resolve_focus_target, Screen.set_focus
examples: (R-SHELL-FOCUS.2/1) `files_list` focused, `2` → `a2l_tags_list` (base P: `ws_load_project_button`, hidden, area 0)
examples: (R-SHELL-FOCUS.2/2) Split / Join open from the Workspace, Esc → `files_list` (base P: none)
examples: (R-SHELL-FOCUS.2/4) `rail_item_workspace` focused, `]` → `fx_panel`; `c` still confirms
examples: (R-SHELL-FOCUS.5/1) target paints no region → first shown focusable non-text widget, else the rail item

S19TuiApp._note_image_bytes_written
req: R-A2L-048, R-A2L-049, R-SEG-PREV.21, R-SEG-PREV.22, R-SEG-OPEN.6
in: —
out: None
func: changed (on Inc 6's version). was: CRC Designer notice, Check Editor results cleared (+ Inc 6's Checks-run end, Patch Editor load tail, `update_checks_view`). / now: identical, then `self._refresh_a2l_values_after_write()`, then the Split / Join window (queried in its own `try`; missing → skip) `note_image_bytes_written()` (I-1). No `refresh_window`, no focus call.
module: s19_app/tui/app.py
calls: CrcDesignerPanel.note_image_bytes_written, CheckEditorPanel.clear_check_results, S19TuiApp._refresh_a2l_values_after_write, SplitJoinWindow.note_image_bytes_written
examples: (R-SEG-PREV.21/1) fixture three, join-fill pick displayed, Save project commit writes `0x8015`, `0x8016` = `BB CC` → band `data 8 · fill 13 · conflict 2 · fill 9 · data 8`, state `⚠ 2 B would clobber source — abort on export` (base P: `conflict 1` at offset 19)
examples: (R-SEG-PREV.22/1) `sje_table` focused before → focused after
examples: (R-SEG-OPEN.6/3) window hidden, apply → no focus inside `#screen_split_join`

S19TuiApp._refresh_a2l_values_after_write
req: R-A2L-048, R-A2L-049
in: —
out: None
func: new. No `current_a2l_data` → return. Else `_a2l_enriched_key = None`; `_compute_a2l_enriched_tags()`; `_refresh_a2l_filtered_tags(preserve_anchor=True)`; the tag-table repaint the A2L view uses. Not `update_a2l_view()` (it drops the anchor). E3 confirms the repaint call and that the summary scroll reset of `_compute_a2l_enriched_tags` is acceptable.
module: s19_app/tui/app.py
calls: S19TuiApp._compute_a2l_enriched_tags, S19TuiApp._refresh_a2l_filtered_tags, S19TuiApp.update_a2l_tags_view
examples: (R-A2L-048/1) `VALUE_0001` `6C` → `93` applied; key `2` → Raw `147`, Physical `147` (base P: `108` / `108`, cache key unchanged, uncached `147`)
examples: (R-A2L-049/1) first shown row `VALUE_0040` before → `VALUE_0040` after
examples: (no A2L) → nothing computed

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

SplitJoinWindow.note_image_bytes_written
req: R-SEG-PREV.21, R-SEG-PREV.22
in: —
out: None
func: new. `if not self.has_class("hidden"): self._sync()`. No selection reset (the image object is the same), no focus.
module: s19_app/tui/segment_split_view.py
calls: SplitJoinWindow._sync
examples: (R-SEG-PREV.21/1) as `_note_image_bytes_written`
examples: (R-SEG-PREV.21/2) hidden → nothing; the next open re-syncs (base P: fresh on reopen, 1 B = uncached plan)

## Context nodes (unchanged)

S19TuiApp._rehome_focus_after_load — req: R-SHELL-FOCUS.3, R-SHELL-FOCUS.4 — reused by `_apply_unload`; judges `default_screen.focused` (`_focus_needs_rehome`), lands on `_resolve_focus_target()`.
S19TuiApp._resolve_focus_target — req: R-SHELL-FOCUS.2, R-SHELL-FOCUS.5 — `_FOCUS_TARGETS[_active_screen_key]`, fallback `_fallback_focus_target` (R-SHELL-FOCUS.6).
render_hex_view_text — req: R-TUI-018.1 — `start_row_index` wins over the focus centring; notice lines above the rows.
S19TuiApp._reset_scroll_to_top — req: R-TUI-018.2 — `scroll_home(animate=False)` (Textual 8.2.8: both axes).
painted_names — req: R-TUI-012L.8 — `project_gather_service.py:978`, Cc/Cf/Zl/Zp removed, 120-character clip.
SplitJoinWindow._sync — req: R-SEG-PREV.21 — reads `current_file.mem_map` live; `build_plan` → `_conflict_marks` (Inc 13).
