# Code-Wire graph — Inc 1b, group A (`app.py`), batch-103

Stage E2 corrective design after the E3 architect/security review, graph only. No stub, extractor mark, declaration, product edit, test edit, runtime probe or test run is claimed in this lane. Authority: the current G2 r2 export (`../evidence/G2/veredicto-b103-r2.json`, exported_at `2026-11-12T11:43:28.859Z`), `../01-requirements.md` (E2 baseline 22 active rows; current corrective ledger 23), `../02-test-cases.md` (E2 baseline 100 active requirement cases; current corrective ledger 112, plus acceptance), `../E1-rulings.md` (*Resume reconciliation* and its current G2 r2 reconciliation), `../E1-slice.md` (its directed G2 r2 addendum), `../E2-interfaces.md` for I-1, I-12.2 and right-click contracts, and the orchestrator's E3 corrective rulings. Current G2 r2 and the interfaces agree on body B and q=B / O-1=B; no dialog/q supersession by this graph is needed. Code-Wire v3.1.0 (`e436a08`), layout as `../../inc-6/codewire/graph-inc6.md`. Current source references are on `59d467ff7390`; toolkit references are textual 8.2.8.

How to read it: every implementation or context node's `func:` starts with **new**, **changed** or **unchanged context**. The baseline is the current source identified below. The prototype is only the new/changed contracts. Group B owns `graph-clipboard.md` and the internal design of `os_clipboard_input.py`; here I-1 and corrective R-COPY.25 are consumed interfaces, not a second design of that file.

## 1. Delta, ownership and pinned interfaces

**17 group-A fragment entries: 10 implementation nodes (7 new + 3 changed) + 7 context entries.** C1 is only the consumed tail boundary and is omitted from integration because group B owns the changed node of the same name; group A therefore contributes **16 integrated nodes (10 implementation + 6 context)**. One product file is in this group, `s19_app/tui/app.py`. The integrated census remains **24 unique function nodes across 2 changed source files, one per group** (12 implementation + 12 context). `_CopyRowTable` and its method are separate nodes so the class chain and the click behavior are both explicit. `_CopyQuitScreen` includes its module constant `_COPY_QUIT_BODY`; it is not another node. N10 is the only added G2 r2 node, covering `BINDINGS` and the existing palette projection needed to keep palette Quit on `action_quit`. N3 adds exactly one private transient `S19TuiApp._right_gesture` data entity; it is not session-action state or a function node, and no other new `S19TuiApp` attribute is introduced.

| Group | Files | Owns |
|---|---|---|
| G-A app | `s19_app/tui/app.py` | N1-N10; copy scheduling, deferred right-gesture capture/release, one table base class, MAC construction, shared q/Ctrl+C fallback, quit-dialog class, q binding and palette Quit route |
| G-B clipboard | `s19_app/tui/os_clipboard_input.py` | I-1 tail, consumed R-COPY.25 and `_copy_notice_text`; designed only in `graph-clipboard.md` |
| Read-only context | textual 8.2.8; `capped_text_area.py`; `screens.py`; unchanged `app.py` producers/consumers | C1-C7; no edits in this group |

### I-1 — one copy, one write, one notice (CONSUMED, pinned)

`S19TuiApp.copy_to_clipboard(text: str) -> None` stays synchronous and, for each non-empty copy, schedules `_mirror_and_write_os_clipboard(self, text)` exactly once with the original, untruncated text. If `text == ""`, it executes `raise textual.actions.SkipAction` before constructing a coroutine or worker; a normal return would consume Ctrl+C and suppress the idle body-B fallback. N1 does not call `super()`, call `write_os_clipboard`, truncate, sanitize or notify. For a representable payload, the existing async tail remains the only owner of the app clipboard/OSC 52 mirror, the 65,536-character cap, the OS write and the result notification. Text-box copy/cut continues to call that tail directly, never through the override. `_copy_notice_text` belongs to group B in `os_clipboard_input.py`; there is no app-level `_write_copied_text` and no import from `app.py` into `os_clipboard_input.py`.

**R-COPY.25 is consumed at this boundary, not redesigned here.** Group B's tail rejects U+0000 in the already capped payload before the base mirror/writer: zero base calls, writer calls, OSC 52 requests, processes and success/cut notices; both seeds stay unchanged; exactly one 6-second warning says `Clipboard copy refused — NUL cannot be represented in the Windows text clipboard.` and the fixed WARNING is `OS clipboard copy refused; payload contains NUL`, without payload or prefix. NUL only after the cap leaves a clean capped prefix and follows the ordinary one-base/one-writer/one-OSC-52 route with one cut notice retaining the original total. Other C0 controls and markup-like text are not sanitized; NUL is the only new representability refusal.

### I-12.2 — one table class chain (PINNED)

Define `_CopyRowTable(DataTable)` before `A2LTagTable`, then change only the latter's base to `_CopyRowTable`. The resulting MRO is `A2LTagTable → _CopyRowTable → DataTable`; there is no sibling `DataTable` subclass for `#a2l_tags_list`. `_compose_screen_a2l` remains unchanged and `_compose_screen_mac` constructs `_CopyRowTable`. A non-left click on a valid in-bounds row moves the cursor/highlight and prevents only the toolkit's default selection route. Left clicks on valid in-bounds cells retain the toolkit route. `out_of_bounds=True` is empty space: N2 returns `None`, N5 prevents the default and returns without moving the cursor or emitting `RowSelected`; `out_of_bounds=False` with otherwise valid metadata is the positive row control.

### Copy gestures and quit (PINNED to current G2 r2)

At `S19TuiApp.on_event`, every not-forwarded `MouseDown` first replaces or clears the one `_right_gesture` candidate. Button 3 alone captures N2's text plus `screen_offset`, screen and widget before toolkit dispatch, with `valid=True`; no N1 call occurs on press. Text boxes are excluded inside N2 before any other selection/name read because their `event.stop()` cannot act retroactively on the app entry. A containing view contributes its whole top-screen selection; A2L resolves the clicked row key through `_a2l_row_key_to_tag`; MAC normalizes the stored cell with `.plain`/`str` and removes one known producer prefix. Any `MouseMove` offset change makes the candidate permanently invalid, even after returning to the press cell. Every not-forwarded `MouseUp` consumes and clears the candidate before any N1 call; only a valid button-3 release with non-empty text and the same offset/screen/widget calls N1 once. Every event then takes exactly one `await super().on_event(event)`, preserving focus, selection clearing, click synthesis, table behavior and back-to-back press/release capture.

`action_help_quit` serves both the existing product `q` binding and the toolkit Ctrl+C fallback. With a running session action it opens the existing busy `_QuitQuestionScreen`; otherwise it opens exactly one `_CopyQuitScreen`, with `_answer_quit` for both. Ctrl+C reaches it only with nothing selected, including N1's empty-string `SkipAction`; q reaches it directly with a selection present or absent. The modal binding chain prevents either non-priority key from opening another dialog, including when the empty copy skips beneath a modal. `_CopyQuitScreen(_QuitQuestionScreen)` uses G2 body B: `Quit the app? Nothing is selected to copy.` Title/buttons remain `Quit?`, `Quit (y)`, `Stay (n)`. q=B / O-1=B: N10 changes `('q', 'quit', 'Quit')` to `('q', 'help_quit', 'Quit')`, leaving the visible `q Quit` token unchanged. `action_quit` keeps its body and remains the route for Ctrl+Q and palette Quit, including its existing busy branch; idle Ctrl+Q/palette Quit exits immediately without a dialog.

### Superseded E1/G2 sketches and explicit exclusions

- `E1-slice.md` predates the merged tree. Its `super()` plus second-writer sketch, app-level `_write_copied_text` and `_copy_notice_text`, and two-composition change are superseded by Resume reconciliation and the pinned interfaces.
- The first G2 export/integration retains earlier dialog/q choices and is historical. Current G2 r2 and `E2-interfaces.md` are already aligned on body B (`Quit the app? Nothing is selected to copy.`) and q=B / O-1=B; this graph does not supersede the interfaces. Current G2 r2 has `notes={}` and an empty general note. Geometry and A2L hex-width material from older G2 notes is historical, not a current-export note.
- There is no whole-view copy on bare Ctrl+C, no row-name copy on bare Ctrl+C, no `Nothing copied` notice and no additional key or palette command. N10 rebinds the existing q key and preserves the existing palette Quit command on `action_quit`.
- `screens_directionb.py` is unchanged; the stock read-only `#patch_json_view` stays a `TextArea` (`screens_directionb.py:5031-5036`).
- The A2L Viewer hex-width note belongs to Inc 7 and is historical. It is not silently added here or attributed to current G2 r2, whose `notes={}`.

## 2. Baseline and real callers (static re-check)

No new extraction was run in this lane. E1's Code-Wire v3.1.0 caller censuses are `../evidence-e1/cw-callers-census-graph.md` and `../evidence-e1/cw-callers-census-e1a-graph.md`; the following current source/toolkit reads re-pin their line references after the batch-101 merges. Absent overrides/classes were checked by symbol search, not inferred from the old slice.

| Node | Current baseline | Real caller / dispatch |
|---|---|---|
| N1 `S19TuiApp.copy_to_clipboard` | absent on `S19TuiApp` (`app.py:2875`); toolkit base `textual/app.py:1770-1786` | `Screen.action_copy_text` (`textual/screen.py:985-991`), stock `TextArea.action_copy` (`textual/widgets/_text_area.py:2653-2659`); future N3 |
| N2 `S19TuiApp._right_click_text` | absent | future N3 only; no widget-specific handlers |
| N3 `S19TuiApp.on_event` | absent; toolkit entry `textual/app.py:4060-4148` | driver messages to the App; Pilot bypasses this entry (`textual/pilot.py:463-468`) |
| N4 `_CopyRowTable` | absent | future N6 base and N7 construction |
| N5 `_CopyRowTable.on_click` | absent; toolkit default `DataTable._on_click` (`textual/widgets/_data_table.py:2669-2702`) | Textual MRO dispatch (`textual/message_pump.py:794-800`) |
| N6 `A2LTagTable` | `A2LTagTable(DataTable)`, `app.py:1456-1515` | constructed by unchanged `_compose_screen_a2l` at `app.py:8764-8770` |
| N7 `S19TuiApp._compose_screen_mac` | `app.py:8816`; `DataTable` construction at `:8860` | main `compose` at `app.py:3603` |
| N8 `S19TuiApp.action_help_quit` | absent; toolkit fallback `textual/app.py:3990-4002` | toolkit Ctrl+C fallback (`textual/app.py:463`) after copy skips, and product q through future N10 |
| N9 `_CopyQuitScreen` | absent; `_QuitQuestionScreen` at `app.py:462-470` | future N8, reached by Ctrl+C and N10 q; inherited modal and `action_quit` stack guard |
| N10 `S19TuiApp.BINDINGS` / palette projection | `('q', 'quit', 'Quit')` at `app.py:2902`; builder dispatches binding actions at `:10219-10229` | q moves to N8; Ctrl+Q remains `quit`; palette Quit must remain `PaletteEntry("Quit", "quit")` |
| C1 `_mirror_and_write_os_clipboard` | current tail `os_clipboard_input.py:698-750` | direct text-box calls; future N1 schedules it; group B changes its notices |
| C2 toolkit selection/event routes | `textual/screen.py:254`, `:633-646`, `:963-991`; `textual/app.py:4060-4148` | mouse selection, Ctrl+C and driver event forwarding |
| C3 text-box routes | `os_clipboard_input.py:861-916`; `capped_text_area.py:242-308`, `:310-335` | copy/cut/right-click actions call C1 directly |
| C4 q/Ctrl+C fallback/modal chain | toolkit binding `textual/app.py:463`; `textual/screen.py:448-455` | modal chain truncates before App fallback and the non-priority product q binding |
| C5 quit pipeline | `_QuitQuestionScreen` `app.py:462-470`; `ConfirmQuestionScreen` `screens.py:2229-2318`; `action_quit`/`_answer_quit` `app.py:23017-23045` | Ctrl+Q/palette and future N8 callback; q moves to N10/N8; callback passed at `app.py:23034` |
| C6 A2L composition/producers | `_compose_screen_a2l` `app.py:8701`; map fill `:21464-21507`; cells `:21749-21849` | main `compose` `:3602`; highlight/copy consumers read row keys, not painted names |
| C7 table/MAC consumers | `_populate_mac_datatable` `app.py:21016-21090`; row selected/highlighted `:17089-17178` | toolkit `Click`, `RowSelected`, `RowHighlighted`; `move_cursor` `textual/widgets/_data_table.py:1214-1259` |

## Nodes

S19TuiApp.copy_to_clipboard
req: R-COPY.1, R-COPY.2, R-COPY.6, R-COPY.7, R-COPY.8, R-COPY.9, R-COPY.10, R-COPY.16, R-COPY.20, R-PASTE.9, R-PASTE.10, R-PASTE.13, R-PASTE.14, R-TUI-043.13
in: str text (original, untruncated)
out: None after one started clipboard worker per non-empty copy; textual.actions.SkipAction for an empty string
module: s19_app/tui/app.py
modify: [Data: clipboard copy requests] (append only for non-empty text); [Data: S19TuiApp session attributes] (unchanged by N1)
func: **new override.** Keep the toolkit method's synchronous signature and bind the real exception with `from textual.actions import SkipAction`. If `text == ""`, execute `raise SkipAction` before constructing a coroutine or worker; do not return normally, because that would mark Ctrl+C handled and suppress N8. A missing import or resulting `NameError` is a RED implementation defect, not a SkipAction. Otherwise import and pass `_mirror_and_write_os_clipboard(self, text)` once to inherited `run_worker` with its default immediate start and non-exclusive behavior; do not await it. Return `None` after scheduling. Never call `super().copy_to_clipboard`, `App.copy_to_clipboard`, `write_os_clipboard` or `notify`, and never slice or sanitize `text`: C1 alone owns those effects, the original length and the consumed R-COPY.25 refusal. C1's explicit base-class call cannot re-enter this override.
examples: (R-COPY.6/1 empty-screen-selection arm, R-COPY.16/1) idle, no session action, `screen.selections` present but `get_selected_text() == ""`; Ctrl+C → N1 raises `textual.actions.SkipAction` before coroutine/worker construction, the chain reaches N8 once and opens exactly one body-B N9; app and OS clipboards remain `SEED-1b` while it is open and after `n`, with zero workers/base calls/writes/OSC 52 requests/notices; replacing the raise with `return` consumes the action, opens zero dialogs and goes RED
examples: (R-COPY.20/1 empty-screen-selection arm) the Workspace help modal is topmost and its present selection extracts `""`; Ctrl+C → the same early `SkipAction`, zero workers/base calls/writes/OSC 52 requests/notices and unchanged seeds, while C4 stops before N8 so the original help remains the only modal and zero N9/second dialogs open
examples: (R-COPY.1/1) three hex rows selected, Ctrl+C → `Screen.action_copy_text` calls this override once with exactly those three selected lines; C1's separate Windows read equals them
examples: (R-COPY.1/2) the whole five-line `#ws_stats` selection, Ctrl+C → N1 receives exactly those five lines once and the separate Windows read equals them, not a whole-view substitute
examples: (R-COPY.1/3) the selected `#a2l_tags_summary` lines, Ctrl+C → N1 receives the exact summary selection once and the separate Windows read equals it, including the painted `Page 1/1 | tags 1-118 / 118 …` line when selected
examples: (R-COPY.1/4) two lines selected in `#a2l_detail_card`, Ctrl+C → N1 receives exactly those two detail-card lines once and the separate Windows read equals them, never the whole card or the highlighted row name
examples: (R-COPY.1/6, R-COPY.20/1 selected arm) the first two lines selected in the Workspace help modal, Ctrl+C → N1 receives exactly those two lines once and the separate Windows read equals them; the original help stays open and zero N9/second dialogs appear
examples: (R-COPY.2/2) right-click a three-row hex selection with matching press/release → app clipboard receives exactly the same three-line snapshot once
examples: (R-COPY.2/4, R-COPY.7/8, R-PASTE.9/103) right-click A2L row 3 with the OS writer failing → app clipboard still receives exactly `ASAM.M.SCALAR.UBYTE.RAT_FUNC.IDENT.STATUS_STRING`, the OS seed remains, no notice starts `Copied`, and exactly one 6-second warning says `Clipboard write failed — copied inside the app only.`; substituting a selection-right-click for this row-plus-failure arm is not equivalent coverage
examples: (R-COPY.7/1, /2, /3) one row name → exactly one `Copied 1 line to the clipboard.`; five selected stats lines → exactly one `Copied 5 lines to the clipboard.`; three hex lines by Ctrl+C → exactly one `Copied 3 lines to the clipboard.`
examples: (R-COPY.8/1, /2) JSON selection length `75,210`, copied by Ctrl+C and then by right-click → this override passes all 75,210 characters to C1; app clipboard, OSC 52 payload and separate OS read each equal only the first 65,536
examples: (R-COPY.9/1, /2) the same two copies → exactly one `Copied the first 65,536 characters to the clipboard (75,210 in all).` per copy and no ordinary copy notice; pre-truncating in N1 would lose `75,210` and go RED
examples: (R-COPY.10/1, /2, /3) Ctrl+C selection, right-click selection and right-click row → exactly one OSC 52 request per gesture, decoding to the copied text; calling `super()` here as well as C1 would make two and go RED
examples: (R-PASTE.10/101, R-TUI-043.13/101) failing copy of `SECRET-COPY-43` → at least one WARNING naming the write failure, zero log records containing either that payload or its first 16 characters
examples: (R-PASTE.13/101) third A2L row copied while another program holds the clipboard → warning within 2.5 s (CI timing bound 5.0 s), no success notice
examples: (R-PASTE.14/101, /102, /103) held clipboard during Ctrl+C selection, right-click selection and right-click row → the synchronous override only schedules; a 50 ms screen timer is late by at most 100 ms per tick until each copy ends

S19TuiApp._right_click_text
req: R-COPY.4, R-COPY.12, R-COPY.13, R-COPY.14
in: int x; int y (top-screen cell, read on the not-forwarded press)
out: Optional[str] text to copy; None means no clipboard action
module: s19_app/tui/app.py
func: **new read-only helper.** Resolve `widget, _ = self.screen.get_widget_at(x, y)` and read `self.screen.get_style_at(x, y).meta`, the compositor metadata Textual assigns to the forwarded mouse event (`textual/screen.py:714-724`, `:1940`). First return `None` when the clicked widget or an ancestor is an Inc 1a `OsClipboardInput` or `CappedTextArea` (import the latter; no app import back into either module), before reading any other selection or row name. For `#patch_json_view`, return its non-empty `selected_text`, else `None`. For `#a2l_tags_list` / `#mac_records_list`, require integer row/column metadata, `0 <= row < table.row_count`, `column >= 0` and `not meta.get("out_of_bounds", False)` before resolving a row key or reading a cell. `out_of_bounds=True` is empty space and returns `None` even when the row number exists; headers, absent metadata and other empty space also return `None`. A2L obtains the key with `coordinate_to_cell_key((row, 0))`, normalizes `row_key.value` or the key itself, and returns the mapped tag's non-empty full `name` from `_a2l_row_key_to_tag`; column 0 is only a key lookup, never an assumption about the Tag column. For MAC, read `cell = table.get_row_at(row)[0]` and normalize with `painted = cell.plain if isinstance(cell, Text) else str(cell)`. Require one status-glyph-plus-space prefix actually emitted by `_populate_mac_datatable` (`app.py:21069-21073`), remove exactly that matched prefix once, and return the complete remaining `str`, including internal spaces; if no producer prefix matches or the remaining name is empty, return `None`. Never delete two arbitrary characters or add a tab. For any other widget, return `self.screen.get_selected_text()` only when that widget is a key in `self.screen.selections` and the result is non-empty; otherwise `None`. Never log, notify, move a cursor, clear a selection or write a clipboard here.
examples: (R-COPY.4/1) cursor on A2L row 1, right-click row 3 whose key maps to `ASAM.M.SCALAR.UBYTE.RAT_FUNC.IDENT.STATUS_STRING` → that exact full name, one line, no glyph, no tab, independent of the old cursor
examples: (R-COPY.4/3, shortened-cell control) cursor on row 2; right-click row 5, key `a2l:4` mapped to full name `ASAM.M.SCALAR.UBYTE.RAT_FUNC.IDENT.STATUS_STRING` while painted Tag reads `· ASAM.M.S…STATUS_STRING` → the full mapped name, never the shortened cell, `a2l:4`, or row 2's name
examples: (R-COPY.4/2) MAC row 3 Rich `Text` cell `⚠ Curve_ExternalAxis` → `.plain` yields `⚠ Curve_ExternalAxis`, removal of the exact producer prefix `⚠ ` yields the `str` `Curve_ExternalAxis`; no address cell, glyph, tab or currently highlighted row is used
examples: (R-COPY.4/2 MAC long-name arm) a stored Rich `Text` cell whose `.plain` is `⚠ Curve External Axis With A Very Long Full Name`, deliberately longer than its painted column → exact `str` `Curve External Axis With A Very Long Full Name`, preserving every internal space with no glyph, truncation or arbitrary two-character slice; a non-`Text` cell follows the explicit `str(cell)` arm
examples: (E3A-02 negative, R-COPY.13/5, R-COPY.14/5) for A2L row 3 and independently MAC row 3, use valid `row=2`, `column=0` but `out_of_bounds=True` → N2 returns `None` before key/cell resolution, N1/base/writer/OSC 52/notice counts are zero and both seeds remain unchanged
examples: (E3A-02 positive control, R-COPY.4/1, /2) repeat each preceding fixture with the sole change `out_of_bounds=False` → N2 returns respectively the full A2L row-3 name and `Curve_ExternalAxis`, and a valid release produces one copy/write/OSC 52/notice
examples: (R-COPY.12/1, /6) three selected hex rows → all three lines; a selection spanning `#ws_stats` and `#a2l_view`, right-click on `#a2l_view` → the whole two-view selection, not only the clicked widget's part
examples: (R-COPY.12/3) two lines selected in `#a2l_detail_card`, button-3 press/release inside that selection → N2 returns exactly those two detail lines and the separate Windows read equals them, never the whole card, a row name or another view's selection
examples: (R-COPY.12/4) two lines selected with Shift+Down in stock `#patch_json_view` → its own two selected lines; an empty JSON selection returns `None`
examples: (R-COPY.12/5) two lines selected in the Workspace help dialog → those two lines from the top modal screen, not the window behind it
examples: (R-COPY.13/4, R-COPY.14/4) three hex rows selected but right-click on unselected `#ws_stats` → `None`, both clipboards keep `SEED-1b`, zero notices; a global `get_selected_text()` without membership would wrongly copy the hex rows
examples: (R-COPY.13/5, /6, R-COPY.14/5, /6) right-click A2L header (`row=-1`) or a table with zero rows → `None`, seed unchanged, zero notices
examples: (R-COPY.13/1, /2, /3, R-COPY.14/1, /2, /3) empty hex view, empty JSON selection and empty help-window selection → `None`, no write and no notice
examples: (E3-03, R-TUI-043.13/102) an A2L model name combining `[red]`, ESC, BEL, an OSC-52-looking sequence and LF, with no NUL, copied by valid right-click with `out_of_bounds=False` → N2 supplies that exact raw full name, not the U+FFFD painted projection; through consumed C1 the app clipboard, decoded OSC 52 and separate Windows read equal it exactly, base/writer/OSC 52 counts are `1/1/1` and exactly one notice says `Copied 2 lines to the clipboard.`; the forced-PowerShell arm uses a static `shell=False` command with payload on stdin only and absent from every argv, emits no extra terminal sequence, and logs neither the full name nor any payload prefix; do not sanitize markup or any representable C0 control
examples: (E3A-24(c), R-COPY.7/7 cross-increment) an unrelated three-row hex selection exists while `abc` is selected in `#a2l_tags_filter_input`; right-click `abc` → this helper returns `None`, the box performs one direct-tail copy of `abc`, no hex text is copied, exactly one copy notice

S19TuiApp.on_event
req: R-COPY.4, R-COPY.11, R-COPY.12, R-COPY.13, R-COPY.14, R-COPY.15
in: events.Event event
out: None; every event forwarded exactly once
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._right_gesture] (replace, invalidate, consume or clear); [Data: clipboard copy requests] (append only for a valid non-empty release snapshot)
func: **new async override with one private transient candidate.** Initialize no other app/session attribute. `_right_gesture` is either `None` or one record containing `text`, `screen_offset`, `screen`, `widget` and `valid`. On every not-forwarded `events.MouseDown`, first clear any old candidate; a non-button-3 press leaves it cleared. On button 3 only, before any toolkit forwarding, capture `screen = self.screen`, the widget returned by `screen.get_widget_at(event.screen_x, event.screen_y)`, `screen_offset = event.screen_offset`, and `text = N2(event.screen_x, event.screen_y)`, storing one fresh candidate with `valid=True`; N2 retains its early text-box exclusion and returns either non-empty text or `None`. Do not call N1 on `MouseDown`. On every `events.MouseMove` with a candidate, if `event.screen_offset != candidate.screen_offset`, set only `valid=False`; never restore it on a later move, even to the original offset. On every not-forwarded `events.MouseUp`, first copy the candidate to a local and set `_right_gesture = None`, consuming it before any possible N1 call. Call N1 once only when `event.button == 3`, a candidate exists, `candidate.valid` is true, its text is non-empty, and the release has the same `screen_offset`, the identical current screen and the identical widget from `get_widget_at` at the release coordinates. Different offset/screen/widget, a `None` text, any invalidated drag, a replayed release and every forwarded release copy nothing. N3 does not stop/prevent events, synthesize clicks, await C1 or handle `Click`; every event path, including keys, pastes, forwarded events, invalid gestures and the path that calls N1, finishes with exactly one `await super().on_event(event)`. Back-to-back behavior is preserved because the press snapshots before its superclass forward and the matching release calls N1 before its own superclass forward clears the selection.
examples: (R-COPY.12/7, R-COPY.15/1) three hex rows selected; button-3 `MouseDown` and `MouseUp` posted back-to-back with no pause and identical offset/screen/widget → press stores all three lines without copying, release consumes/clears the candidate then schedules exactly one N1/C1/base/writer/OSC 52/notice, and each event has exactly one superclass forward before the toolkit release clears the selection; copying on press or reading after release goes RED
examples: (R-COPY.12/4, R-COPY.15/3) two JSON lines selected; matching press/release posted back-to-back → two lines captured before the stock TextArea press clears its selection, one copy on valid release, final `selected_text` empty
examples: (R-COPY.12/2, R-COPY.15/2) five stats lines selected and right-clicked with matching press/release → five lines copied once, top-screen selection none after forwarding
examples: (R-COPY.13/1, R-COPY.14/1) empty button-3 press/release → N2 stores `None`, zero N1 calls/notices/writes, but exactly one superclass forward per event so ordinary mouse behavior is not disabled
examples: (R-COPY.4/1) matching button-3 press/release on row 3 → its name is snapshotted on press and copied once on release before the later click moves the highlight; copying `cursor_row` after forwarding would copy the wrong row in the discriminating row-2/row-5 case
examples: (E3-01 right-drag selection negative) a previous selection contains `SECRET-SELECTION-MARKER`; button-3 press inside it, move to another cell, release there → the offset change makes `valid=False`, N1/tail/base/writer/OSC 52/notice counts are zero and both clipboard seeds remain unchanged; each mouse event is still forwarded exactly once
examples: (E3-01 out-and-return negative) button-3 press at offset A, MouseMove to B and back to A, release at A → the first change permanently invalidates the candidate and returning does not revalidate it; zero N1/tail/base/writer/OSC 52/notices and both seeds remain
examples: (E3-01 right-drag row negative) repeat the move-away/release arm on an otherwise valid A2L row and independently on a MAC row with `out_of_bounds=False` → no row name reaches N1 or any clipboard sink, both seeds remain and zero copy notices appear; the row fixture alone must not turn a drag into a click
examples: (E3-01 context negative) with no intervening move, release at the captured offset but with a different resolved widget or on a different screen → the candidate is consumed/cleared and zero N1/copy effects occur; equality of offset alone is insufficient
examples: (E3-01 reentry control) button-3 down at A followed by a second button-3 down at B replaces A's candidate; release at A consumes B without copying, then a fresh matching press/release at B copies B exactly once; a replayed or forwarded release finds no candidate and adds no N1/tail/base/writer/OSC 52/notice, while every event still delegates once
examples: (R-COPY.11/1) left-drag over three hex rows without Ctrl+C → the initial non-button-3 down leaves no right candidate, moves and release cause zero N1/tail/base/writer/OSC 52/notices, both seeds remain and the selection is left for a later explicit copy
examples: (R-COPY.11/3) F7 in `#patch_json_view` selects the document without any copy key → N3 takes only its one superclass route, N1/tail/base/writer/OSC 52/notice counts remain zero and both seeds remain unchanged

_CopyRowTable
req: R-COPY.21, R-COPY.22
in: DataTable constructor arguments, unchanged
out: one shared row-copy table type
module: s19_app/tui/app.py
func: **new class.** Declare `_CopyRowTable(DataTable)` before `A2LTagTable`; N5 is its only new behavior. It adds no app/session state, selection handler, row-name policy or second A2L subclass. N2 owns name resolution; this class owns only non-left click behavior shared by A2L and MAC.
examples: (R-COPY.21/1, R-COPY.22/1) `#a2l_tags_list` is an `A2LTagTable` and an instance of both `_CopyRowTable` and `DataTable`; its MRO contains exactly one DataTable chain
examples: (R-COPY.21/2, R-COPY.22/2) `#mac_records_list` is a direct `_CopyRowTable`; both widgets therefore execute N5 while only A2L retains its `Measured`, `on_resize` and `_highlight_row` specializations

_CopyRowTable.on_click
req: R-COPY.11, R-COPY.21, R-COPY.22
in: events.Click event
out: None; valid non-left in-bounds row cursor moved, toolkit default prevented; out-of-bounds click has no cursor/selection effect
module: s19_app/tui/app.py
modify: [Data: DataTable.cursor_coordinate] (replace only on valid non-left in-bounds row, unchanged when out_of_bounds=True); [Data: DataTable.RowSelected] (suppressed on valid non-left rows and all out-of-bounds clicks)
func: **new.** Read `meta = event.style.meta`. First, if `meta.get("out_of_bounds", False)` is true, call `event.prevent_default()` and return without `move_cursor`: this is empty space even when its row number exists, and it produces no copy, cursor movement, `RowSelected` or hex jump on any button. For an in-bounds `event.button == 1`, return without preventing the default: Textual continues to `DataTable._on_click`, including its existing highlighted-row `RowSelected` and hex jump. For any other button, read integer `row` and `column` from `meta`; unless `0 <= row < self.row_count` and `column >= 0`, return without copying or special handling. On a valid row with `out_of_bounds=False` or no flag, call public `move_cursor(row=row, column=column, animate=True)` so `RowHighlighted` and cursor scrolling still occur, then `event.prevent_default()` before MRO dispatch can reach `DataTable._on_click`. Do not call `_post_selected_message`, `super()._on_click`, `event.stop`, or any app jump helper. `prevent_default`, not `stop`, is what suppresses the private toolkit default (`textual/message_pump.py:758-800`).
examples: (E3A-02 negative, R-COPY.13/5, R-COPY.14/5, R-COPY.21/1, R-COPY.22/1) with A2L row 1 and independently MAC row 1 highlighted, click metadata for row 3 (`row=2`, `column=0`) with `out_of_bounds=True` → N5 prevents the default and returns, N1=0, both seeds unchanged, zero notices/writes/OSC 52, `cursor_row` and every relevant first painted hex line unchanged, and zero `RowSelected`; treating this padding as a valid row goes RED
examples: (E3A-02 positive control, R-COPY.4/1, /2, R-COPY.21/1, /2, R-COPY.22/1, /2) repeat each fixture with the sole change `out_of_bounds=False` and a valid button-3 press/release → the clicked A2L/MAC row 3 highlights and copies its exact name once, while zero `RowSelected` and unchanged first painted hex lines prevent a jump
examples: (R-COPY.21/1) A2L cursor on row 1, right-click row 5 with valid in-bounds metadata → `cursor_row == 4` and the detail card shows row 5's tag through unchanged `RowHighlighted`
examples: (R-COPY.21/2) MAC right-click row 3 with valid in-bounds metadata → `cursor_row == 2`; the clicked row, not the previously highlighted row, is highlighted
examples: (R-COPY.22/1) A2L row 3 already highlighted, main/A2L hex first painted lines recorded, right-click that row → zero `RowSelected`, both first painted lines unchanged; allowing `DataTable._on_click` would post on the highlight-click and jump
examples: (R-COPY.22/2) MAC row 3 highlighted and right-clicked → zero `RowSelected`, MAC hex first painted line unchanged
examples: (R-COPY.11/4) left-click A2L row 5 with valid in-bounds metadata → N5 does not prevent the toolkit route, row 5 highlights, zero copy requests and the OS seed remains; existing left-click selection/jump behavior is not removed

A2LTagTable
req: R-COPY.4, R-COPY.21, R-COPY.22, R-TUI-042a.5, R-TUI-042a.6
in: unchanged constructor and existing A2L methods/messages
out: A2LTagTable(_CopyRowTable)
module: s19_app/tui/app.py
func: **changed class base only.** Was `A2LTagTable(DataTable)` at `app.py:1456`; now `A2LTagTable(_CopyRowTable)`. Keep nested `Measured`, `suppress_row_highlight`, `_highlight_row` and `on_resize` byte-for-byte behavior. Do not move N5 into this subclass and do not create another A2L DataTable subclass. N6 inherits N5; its own `on_resize` still wins at its MRO level and posts the same bubbling measurement message.
examples: (R-COPY.4/3) shortened A2L cell still resolves through C6's row-key map, so changing the base cannot regress copy to the painted abbreviation or internal key
examples: (R-COPY.21/1, R-COPY.22/1) right-click row 5 invokes inherited N5: row 5 highlights and no hex jump occurs, with no duplicate `on_click` in `A2LTagTable`
examples: (R-TUI-042a.5/6 regression) at 220×60 then 80×54, the same `A2LTagTable.on_resize` posts one `Measured` and the existing fit yields `✓ SYN_MA…LLL_END` within the visible Tag width; the new base adds no competing resize handler
examples: (R-TUI-042a.6 regression) a hostile tag's painted cell remains the existing literal U+FFFD projection with zero markup spans/raw controls, while N2 copies the mapped full name rather than reparsing that painted cell

S19TuiApp._compose_screen_mac
req: R-COPY.4, R-COPY.21, R-COPY.22
in: none
out: Container screen; MAC table is _CopyRowTable
module: s19_app/tui/app.py
modify: [Data: MAC records table widget class] (replace); [Data: MAC widget ids/columns] (unchanged)
func: **changed one construction.** At `app.py:8860`, replace `DataTable(id="mac_records_list", zebra_stripes=True, cursor_type="row")` with `_CopyRowTable` and the identical arguments. Every other widget, renderer, row key, column and jump helper stays unchanged. `_compose_screen_a2l` is not changed.
examples: (R-COPY.4/2) MAC screen mounts `#mac_records_list` as `_CopyRowTable`; right-click row 3 still reads `⚠ Curve_ExternalAxis` from the same producer and copies `Curve_ExternalAxis`
examples: (R-COPY.21/2, R-COPY.22/2) right-click MAC row 3 highlights it through N5 while `#mac_hex_view` keeps its first painted line; no MAC-specific click subclass is introduced

S19TuiApp.action_help_quit
req: R-COPY.6, R-COPY.16, R-COPY.17, R-COPY.19, R-COPY.20, R-COPY.23, R-DLG.14, R-QUIT.8
in: none; q directly with selection present or absent; Ctrl+C only after focused copy and screen selection copy raised SkipAction
out: None; one existing busy question or one new idle copy-quit screen pushed per reachable invocation
module: s19_app/tui/app.py
modify: [Data: App.screen_stack] (append on reachable idle/busy route)
func: **new override shared by the toolkit Ctrl+C fallback and N10's product q binding.** Do not call the base hint and do not inspect or copy selections: Ctrl+C reaching this method means no non-empty selected text, including N1's present-but-empty `SkipAction`, while q must ask with a selection present or absent. Read `run = self._running_session_action()`. If non-`None`, push the existing `_QuitQuestionScreen(_QUIT_TITLE, _QUIT_BODY.format(label=run.label), _QUIT_YES, _QUIT_NO)` with `self._answer_quit`. Otherwise push `_CopyQuitScreen(_QUIT_TITLE, _COPY_QUIT_BODY, _QUIT_YES, _QUIT_NO)` with the same callback. No extra priority binding and no explicit modal-stack branch: C4 prevents both q and Ctrl+C from reaching this action while a modal is open, keeping exactly one dialog. N9's subclass is covered by the existing `action_quit` isinstance guard. N10 leaves Ctrl+Q and palette Quit on `action_quit`, whose body is unchanged.
examples: (R-COPY.6/3, R-COPY.16/3) A2L row 3 highlighted but no view/text selection, idle, Ctrl+C → one N9 dialog, zero copy calls; app and OS clipboards remain `SEED-1b` while it is open and after `n`
examples: (R-COPY.6/1, /2, /4) independently arm `#search_button` focused with nothing selected, no widget focused, and an empty `#a2l_tags_filter_input`; each idle Ctrl+C opens exactly one body-B N9, and both app and OS clipboards equal `SEED-1b` at two independent observations, while the dialog is open and again after `n`, with zero copy workers/writes/OSC 52/notices
examples: (R-COPY.16/1, /2, /4, /5, /6) focus on `#search_button`, no focus, empty filter, empty JSON selection, or non-empty `#patch_paste_text` with no selection → the same one N9 with exact G2 body B and no `Do you want to quit?` notice
examples: (R-COPY.16/1 empty-screen-selection arm) `screen.selections` is present but extracts `""` → N1's `SkipAction`, not a normal return, reaches this action once and opens the same single body-B N9 with both seeds unchanged before and after `n`
examples: (R-COPY.16/1 geometry) at 118×54 and 220×60 body B `Quit the app? Nothing is selected to copy.` fits on one line, with `Quit (y)` and `Stay (n)` wholly painted, contained and operable; these are E4 measurement targets retained from historical G2 notes, not measurements or current-note claims; current G2 r2 has `notes={}` and an empty general note
examples: (R-COPY.17/1) idle dialog answered `y` → `_answer_quit(True)` exits with return code 0 within 1 s; N8 itself does not exit before an answer
examples: (R-COPY.19/1) held `Loading <name>` session action, nothing selected, Ctrl+C → existing busy question with `still working: Loading <name> — wait, or quit after it finishes`; zero `_CopyQuitScreen` instances
examples: (R-COPY.23/1) idle, `#search_button` focused, nothing selected, q → N8 opens exactly one N9 with body B, zero immediate exits and zero busy questions; keeping `q → quit` would exit and go RED
examples: (R-COPY.23/2) idle with three hex rows selected, q → the same one N9 without inspecting/copying the selection; a second q while N9 is open does not reach N8, so still one dialog, app running, `app.clipboard == "SEED-1b"`, zero copy notices
examples: (R-QUIT.8/101) answer the Ctrl+C-opened busy question `y`, then release the held load → app remains running until the load completes, then exits 0 through unchanged C5
examples: (R-COPY.20/1, /2, /3, /4) Ctrl+C with help, Load, N9 or the busy question on top, including a present-but-empty screen selection → C4 does not reach N8; original top screen remains, no second dialog is added and both clipboard seeds remain unchanged
examples: (R-DLG.14/101) dialog census finds N9's construction in this shared reachable action with openers from Ctrl+C without selection and q while idle; current 21-dialog census plus N9 gives 22, with zero dialogs lacking an opener

_CopyQuitScreen
req: R-COPY.16, R-COPY.17, R-COPY.18, R-COPY.23, R-DLG.1, R-DLG.2, R-DLG.6, R-DLG.9, R-DLG.11, R-DLG.12
in: title/body/yes/no strings supplied by N8
out: modal bool answer through inherited ConfirmQuestionScreen behavior
module: s19_app/tui/app.py
modify: [Data: _CopyQuitScreen._dismissed] (inherited, False then True once)
func: **new class beside `_QuitQuestionScreen`, with new module constant `_COPY_QUIT_BODY`.** Declare `_CopyQuitScreen(_QuitQuestionScreen)` with no methods. `_COPY_QUIT_BODY` is exactly `Quit the app? Nothing is selected to copy.` N8 constructs it with `_QUIT_TITLE`, that body, `_QUIT_YES`, `_QUIT_NO`. Inherit `AUTO_FOCUS = "#confirm_no"`, `PRIMARY_BUTTON = "confirm_no"`, `y/n/escape` bindings, plain-text `markup=False` labels, `Text` button labels and the one-answer `_dismissed` guard. Do not alter `_QuitQuestionScreen`, `ConfirmQuestionScreen` or the body of `action_quit`.
examples: (R-COPY.16/1, R-COPY.23/1) top dialog has title `Quit?`, exact body B `Quit the app? Nothing is selected to copy.`, buttons `Quit (y)` and `Stay (n)`, no markup transformation and exactly one instance on the stack
examples: (R-COPY.17/1, /2, /3) `y`, Tab then Enter on `Quit (y)`, and click on `Quit (y)` each dismiss `True` once and exit 0 within 1 s
examples: (R-COPY.18/1) `#confirm_no` / `Stay (n)` carries `modal-confirm`; `#confirm_yes` / `Quit (y)` does not
examples: (R-DLG.1/101, R-COPY.23/2) with N9 open, keys `1`, `2`, `/` and a second `q` leave the shown window and N9 unchanged and the app running; no key of the window behind acts and no second modal is stacked
examples: (R-DLG.2/101) Escape dismisses `False`, restores focus to `#search_button`, leaves both seeded clipboards unchanged and keeps the app running
examples: (R-DLG.6/101) opening N9 puts initial focus on `#confirm_no` / `Stay (n)`, not Quit
examples: (R-DLG.9/101) click `Stay (n)` → main screen only, previous window and scroll unchanged, no clipboard or pending-quit side effect
examples: (R-DLG.11/101) visible button labels are exactly `Quit (y)` and `Stay (n)`, each exposing its key
examples: (R-DLG.12/101, /102) `n` presses Stay and closes without exiting; `y` presses Quit and exits 0; a repeated second answer is ignored by inherited `_dismissed`

S19TuiApp.BINDINGS
req: R-COPY.23, R-COPY.24
in: existing S19TuiApp.BINDINGS and _build_palette_entries projection
out: q → help_quit; Ctrl+Q and palette Quit → quit; visible q Quit token unchanged
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.BINDINGS] (replace the q action only); [Data: palette Quit action] (preserve quit, one entry)
func: **changed binding and its existing palette projection.** At `app.py:2902`, replace `('q', 'quit', 'Quit')` with `('q', 'help_quit', 'Quit')`; the key and description do not change, so the visible key-bar token remains `q Quit`. q now reaches N8 directly with a selection present or absent; the toolkit Ctrl+C fallback is unchanged. Ctrl+Q retains its inherited priority `quit` binding. Because `_build_palette_entries` currently turns each binding action into a same-action `PaletteEntry` (`app.py:10219-10229`), preserve palette Quit by projecting only this new `help_quit` entry to the existing `PaletteEntry("Quit", "quit")` in that builder; do not append a duplicate Quit and do not let the palette inherit `help_quit`. This palette projection is part of N10, not another node. `action_quit` keeps its body and its Ctrl+Q/palette busy and idle branches.
examples: (R-COPY.23/1) idle, nothing selected, q → N8 opens one body-B N9, app running, zero immediate exits; the old tuple would quit before confirmation
examples: (R-COPY.23/2) idle with three hex rows selected, q then a second q → one N9 after each key, no selection copy, no added modal and `app.clipboard == "SEED-1b"`; either copying the selection or stacking/quitting on the second q goes RED
examples: (R-COPY.24/1) idle, no dialog open, Ctrl+Q → unchanged `action_quit` exits with return code 0 within 1 s, zero N9 and zero busy questions; routing Ctrl+Q to N8 would instead ask and go RED
examples: (R-COPY.24/2) idle, open palette and choose `Quit` → N10 supplies `PaletteEntry("Quit", "quit")`, so unchanged `action_quit` exits 0 within 1 s with zero dialogs; propagating raw `help_quit` from BINDINGS would open N9 and go RED
examples: (R-COPY.23 key-bar regression) after the tuple change, the visible token remains exactly `q Quit`; no additional palette command appears and the existing palette has one `Quit` entry whose action is `quit`
examples: (R-QUIT.1 context, no new case) busy q reaches N8's existing busy question, while busy Ctrl+Q/palette Quit reaches the unchanged `action_quit` busy branch; neither route gains a new immediate-exit behavior

_mirror_and_write_os_clipboard
req: R-COPY.25
in: App app; str text (original)
out: None (I-1 and consumed R-COPY.25)
module: s19_app/tui/os_clipboard_input.py
func: **unchanged context at the group-A boundary.** Current definition is `os_clipboard_input.py:698`; its group-B delta owns all internal changes. For a representable payload this section consumes only pinned I-1: one toolkit-base mirror/OSC 52 request, one executor OS write capped at 65,536, and one result notification per scheduled tail. It calls `App.copy_to_clipboard(app, …)` explicitly, so N1 is not re-entered. It also consumes the orchestrator's R-COPY.25 contract: U+0000 in the capped payload refuses the copy before base/writer/OSC 52/process effects and emits only the fixed refusal warning/WARNING; U+0000 solely beyond the cap leaves the capped prefix on the ordinary cut-notice route. No other C0 control or markup-like text is sanitized. Group A adds no tail, notice helper, write call, notification or NUL branch of its own.
examples: (I-1 one-write control) one non-empty representable N1 call records one tail schedule, one toolkit-base call and one OS write; an override calling `super()` or `write_os_clipboard` adds a forbidden second effect
examples: (R-COPY.25/1 capped-payload view refusal) independently copy hex selection `A\0B` by Ctrl+C and A2L model row name `VISIBLE\0SECRET-SUFFIX` by valid right-click through N1 with app/OS seeds armed → tail entry may occur, but base/writer/OSC 52/process counts are `0/0/0/0`, both seeds remain unchanged, success/cut notices are zero, exactly one 6-second warning says `Clipboard copy refused — NUL cannot be represented in the Windows text clipboard.`, and exactly one WARNING says `OS clipboard copy refused; payload contains NUL`; neither payload nor a prefix appears in logs, and any base/writer retry or success notice goes RED
examples: (R-COPY.25/2 direct-box refusal) copy selected `A\0B` through one direct text-box route with app/OS seeds armed → the same `0/0/0/0` base/writer/OSC 52/process counts, unchanged seeds, zero success/cut notices, exactly one fixed 6-second refusal warning and exactly one fixed WARNING without payload/prefix; N1 remains uncalled on this direct route
examples: (R-COPY.25/3 NUL-after-cap control) original text is `P65536 + "\0"` (65,537 characters), so its 65,536-character capped prefix has no NUL → with a successful writer, base/writer/OSC 52 counts are `1/1/1`, all three clipboard surfaces equal `P65536`, exactly one information notice says `Copied the first 65,536 characters to the clipboard (65,537 in all).`, and zero refusal warnings/WARNING records occur
examples: (R-COPY.7/4, /5, /6) text-box single-line copy, three-line copy and Ctrl+X each enter C1 directly and produce exactly one appropriate copy notice; none calls N1 or produces two notices

Screen.action_copy_text / TextArea.action_copy / App.on_event
req: to trace
in: toolkit selection state and driver events
out: selected text to N1; events to focused/top screen
module: textual 8.2.8
func: **unchanged context.** `Screen.action_copy_text` raises `SkipAction` only for `None` and otherwise calls `app.copy_to_clipboard` (`screen.py:985-991`); stock `TextArea.action_copy` does the same for non-empty selected text (`_text_area.py:2653-2659`). Therefore N1, not toolkit context, must raise `textual.actions.SkipAction` when the extracted value is `""`. `Screen.selections` maps widgets to selections, and `get_selected_text` joins all parts (`screen.py:963-983`). `App.on_event` handles a not-forwarded `MouseDown` before `screen._forward_event` (`app.py:4073-4082`), which is why N3 snapshots on press and then always delegates; its matching release is also consumed before the superclass route.
examples: (R-COPY.1/5) two JSON lines selected with Shift+Down, Ctrl+C → stock TextArea calls N1 with those two lines
examples: (R-COPY.6/5) JSON has no selection → stock copy raises `SkipAction`; the fallback opens one body-B N9, no empty string is copied, and both app/OS seeds remain `SEED-1b` while the dialog is open and after `n`
examples: (R-COPY.12/6) selection map contains `#ws_stats` and `#a2l_view` → `get_selected_text` returns both parts in order; N2 returns it only for a containing widget
examples: (R-COPY.15/1, /3) after N3 forwards, toolkit release clears the screen selection and stock JSON press clears its own selection; no custom clearing code is needed

OsClipboardInput / CappedTextArea copy, cut and right-click
req: to trace
in: text-box selection/cut text and button-3 press
out: direct C1 call or paste action
module: s19_app/tui/os_clipboard_input.py; s19_app/tui/capped_text_area.py
func: **unchanged context.** Copy/cut actions call C1 directly (`os_clipboard_input.py:891-916`; `capped_text_area.py:242-308`). Their button-3 handlers stop only later bubbled handling (`os_clipboard_input.py:861-889`; `capped_text_area.py:310-335`); N3 has already seen the press, hence N2's upfront type/ancestor exclusion. These classes never call the N1 override.
examples: (R-COPY.7/4, /5, /6, /7) `abc` copy in single-line, `L1\nL2\nL3` copy in multi-line, `abc` cut, and right-click copy of selected `abc` → one direct C1 call and exactly one notice each (`1`, `3`, `1`, `1` lines respectively)
examples: (E3A-24(c) negative) with a hex view selection also present, right-click the text box → N2 returns `None`; only the box's one copy or paste act occurs, never a second view copy

App.action_help_quit / Screen._modal_binding_chain
req: to trace
in: Ctrl+C and non-priority product q binding resolution; active screen stack
out: fallback only when no modal truncates the chain
module: textual 8.2.8
func: **unchanged context.** App owns the non-priority `ctrl+c → help_quit` binding (`app.py:463`); its base body only paints the quit hint (`:3990-4002`) and is not called by N8. N10's product q binding is also non-priority. `_modal_binding_chain` cuts the chain at the last modal (`screen.py:448-455`), so an open dialog keeps both Ctrl+C and q away from the App fallback without a product priority binding or a second modal.
examples: (R-COPY.20/1, /2) help or Load modal open, nothing selected, Ctrl+C → zero N8 calls, zero new dialogs and no notice
examples: (R-COPY.20/3, /4) N9 or busy quit question open, second Ctrl+C → still exactly the original one dialog
examples: (R-COPY.23/2) N9 open after idle q with a selection, second q → modal chain stops before N8; still one N9, app running and zero copy notices

_QuitQuestionScreen / action_quit / _answer_quit / _exit_if_quit_pending
req: to trace
in: Optional[bool] answer; current session-action run
out: deferred or immediate exit; Stay leaves app running
module: s19_app/tui/app.py; s19_app/tui/screens.py
func: **unchanged context.** `_QuitQuestionScreen` makes Stay primary (`app.py:462-470`); `ConfirmQuestionScreen` supplies its bindings/focus/plain labels/answer guard (`screens.py:2254-2318`). After N10, `action_quit` remains the route for Ctrl+Q and palette Quit, not q; its body is unchanged: exit immediately when idle and use the busy question when a session action runs. Its isinstance stack guard also recognizes N9 (`app.py:23017-23035`). `_answer_quit` remains exactly the shared callback for N8 and the existing busy route: assign `_quit_pending = bool(quit)` and call `_exit_if_quit_pending`; that exits only when pending is true and no session action runs (`:23037-23045`).
examples: (R-COPY.17/1) idle N9 answer `True` → pending true, no running action, immediate exit 0; `False`/`None` → pending false and no exit
examples: (R-QUIT.8/101) busy answer `True` → pending true but no immediate exit while load runs; completion calls the same exit check and then exits 0
examples: (O-1=B, R-COPY.23/1) idle q follows N10 → N8 and opens N9 instead of reaching `action_quit`; busy q follows N8 to the existing busy question, leaving R-QUIT.1 unchanged
examples: (R-COPY.24/1, /2) idle Ctrl+Q and palette Quit both reach unchanged `action_quit` → exit 0 within 1 s, zero N9 and zero busy questions; their busy branch still uses the existing CTX-BUSY question

S19TuiApp._compose_screen_a2l / update_a2l_tags_view / _build_a2l_table_cells
req: to trace
in: enriched A2L tags and current visible page
out: unchanged A2LTagTable, row-key map and painted cells
module: s19_app/tui/app.py
func: **unchanged context.** `_compose_screen_a2l` already constructs `A2LTagTable` with its id/padding/fixed columns (`app.py:8764-8770`). `update_a2l_tags_view` stores `a2l:<absolute index> → tag` and adds the row under that key (`:21490-21507`). `_build_a2l_table_cells` puts Tag at column 2 and may shorten its painted name (`:21806-21809`, `:21835`). N2 therefore performs a key lookup at column 0 and reads the full mapped tag name, never a Tag-cell index or text.
examples: (R-COPY.4/3) key `a2l:4` and painted `· ASAM.M.S…STATUS_STRING` → copy the map's full `ASAM.M.SCALAR.UBYTE.RAT_FUNC.IDENT.STATUS_STRING`; the abbreviated pixels are not the data model
examples: (R-COPY.21/1) the same row key drives unchanged `on_data_table_row_highlighted` at `app.py:17167-17178`, so the card identifies row 5 after N5 moves the cursor

DataTable._on_click / S19TuiApp row handlers / _populate_mac_datatable
req: to trace
in: Click metadata including out_of_bounds, RowSelected/RowHighlighted, MAC visible rows
out: cursor highlight versus explicit selection jump; MAC painted name
module: textual 8.2.8; s19_app/tui/app.py
func: **unchanged context.** Toolkit metadata marks horizontal row padding `out_of_bounds=True` even with an existing row (`_data_table.py:2350-2390`). Toolkit `_on_click` sets the clicked coordinate and posts `RowSelected` only when that coordinate was already highlighted (`_data_table.py:2694-2702`). App `on_data_table_row_selected` performs A2L/MAC hex jumps (`app.py:17089-17132`), while `on_data_table_row_highlighted` only updates the A2L card (`:17134-17178`). MAC producer writes column 0 as Rich `Text` containing glyph + space + full record name (`:21069-21073`) and keeps row key/address separately (`:21079-21090`); N2 therefore uses `.plain`/`str`, not a painted truncation.
examples: (R-COPY.11/2) `down` three times in A2L moves only the highlight → zero N1 calls and OS clipboard remains seeded
examples: (R-COPY.21/1, R-COPY.22/1) N5 produces `RowHighlighted` for the clicked in-bounds row but prevents `RowSelected`; detail card follows while both hex views keep their first painted rows
examples: (E3A-02) `out_of_bounds=True` takes N2's `None` and N5's prevent/default-return route, while the sole flag change to `False` is the valid-row control
examples: (R-COPY.4/2) producer cell `⚠ Curve_ExternalAxis`, row key `mac:2`, address metadata separate → `.plain` and exact prefix removal copy only `Curve_ExternalAxis`, never key or address

## Entities

[Data: clipboard copy requests]
in: original selected text or clicked row name
desc: one immutable text snapshot per accepted gesture; N1 schedules C1 once for non-empty text and retains no copy snapshot, while N3's single candidate below owns the pre-dispatch snapshot until release
sequence:
  keySelection: Screen.action_copy_text / TextArea.action_copy → S19TuiApp.copy_to_clipboard → _mirror_and_write_os_clipboard
  rightSelection: driver MouseDown → S19TuiApp.on_event → S19TuiApp._right_click_text → _right_gesture; valid matching MouseUp → consume/clear candidate → S19TuiApp.copy_to_clipboard → _mirror_and_write_os_clipboard → superclass forwarding clears selection
  textBox: OsClipboardInput/CappedTextArea.action_copy/action_cut → _mirror_and_write_os_clipboard (direct; never S19TuiApp.copy_to_clipboard)
  emptyRight: S19TuiApp._right_click_text returns None → valid release consumes candidate without N1 → superclass forwarding only
  emptyKey: S19TuiApp.copy_to_clipboard("") → raise textual.actions.SkipAction before coroutine/worker → no copy request

[Data: S19TuiApp._right_gesture]
in: Optional[str] text; Offset screen_offset; Screen screen; Widget widget; bool valid
desc: exactly one new private transient N3 candidate, initially/absent as None and consumed to None on every not-forwarded MouseUp; not session-action state, not a global clipboard guard and not a new function node
sequence:
  press: any not-forwarded MouseDown → clear old candidate; button 3 only → N2 snapshot + screen_offset/screen/widget + valid=True → one superclass forward, zero N1
  move: any MouseMove with different screen_offset → valid=False permanently, including later return to the original offset → one superclass forward
  validRelease: not-forwarded button-3 MouseUp with same offset/screen/widget and non-empty text → consume/clear candidate → N1 once → one superclass forward
  cancelledRelease: any not-forwarded MouseUp with missing/invalid/mismatched candidate or non-button-3 → consume/clear without N1 → one superclass forward; replayed/forwarded releases cannot copy

[Data: Screen.selections]
in: widget → Selection map on the top screen
desc: membership determines whether right-click may copy; get_selected_text supplies all parts, while stock JSON uses its own selected_text; a present selection extracting empty still reaches N1's SkipAction on Ctrl+C
sequence:
  spanningSelection: MouseDown on contained widget → S19TuiApp._right_click_text → whole get_selected_text stored in _right_gesture → matching MouseUp copies snapshot
  outsideSelection: MouseDown on unrelated widget → None; valid release copies nothing and both clipboards unchanged, zero notices
  emptySelectionCtrlC: present map with get_selected_text()=="" → N1 raises SkipAction → idle body-B fallback or modal no-dialog route

[Data: S19TuiApp._a2l_row_key_to_tag]
in: a2l:<absolute index> → enriched tag dict
desc: canonical full-name source; painted Tag may be shortened and internal row key is never copied
sequence:
  rightA2LRow: MouseDown in-bounds metadata row → coordinate_to_cell_key((row, 0)) → _a2l_row_key_to_tag → tag[name] stored in _right_gesture → valid matching MouseUp → S19TuiApp.copy_to_clipboard

[Interface: copy row tables]
desc: A2LTagTable → _CopyRowTable → DataTable and MAC _CopyRowTable → DataTable; one shared non-left in-bounds click policy plus the out_of_bounds empty-space guard
sequence:
  rightRow: MouseDown snapshots name without N1 → valid MouseUp consumes/clears and calls N1 → superclass forwarding synthesizes Click → _CopyRowTable.on_click → move_cursor → RowHighlighted; DataTable._on_click prevented → no RowSelected → no hex jump
  outOfBounds: out_of_bounds=True → N2 returns None and N5 prevent_default/returns → no copy, cursor move, RowSelected or hex jump
  leftRow: in-bounds _CopyRowTable.on_click returns → DataTable._on_click unchanged → RowHighlighted and, on an already highlighted row, RowSelected/jump; zero copy

[Interface: copy quit dialog]
desc: _CopyQuitScreen(_QuitQuestionScreen), exact G2 body B `Quit the app? Nothing is selected to copy.`, title/buttons, Stay focus/emphasis, plain labels and one-answer guard
sequence:
  idleCtrlC: widget/screen copy SkipAction or N1 empty-string SkipAction → S19TuiApp.action_help_quit → _CopyQuitScreen → _answer_quit → _exit_if_quit_pending
  idleQ: q with selection present or absent → S19TuiApp.BINDINGS(help_quit) → S19TuiApp.action_help_quit → one _CopyQuitScreen → _answer_quit → _exit_if_quit_pending
  busyHelpQuit: q or widget/screen/N1 copy SkipAction → S19TuiApp.action_help_quit → _QuitQuestionScreen → _answer_quit → wait for session action → _exit_if_quit_pending
  immediateQuit: idle Ctrl+Q or palette Quit → S19TuiApp.action_quit → exit 0 within 1 s; no dialog
  modalQorCtrlC: Screen._modal_binding_chain stops before App fallback, including N1 empty-string SkipAction → original modal only, no second dialog

[Data: S19TuiApp._quit_pending]
in: bool(Optional[bool] answer)
desc: existing shared pending-quit state, unchanged; no second callback or dialog-specific answer state
sequence:
  stay: _answer_quit(False or None) → pending False → app running
  quitIdle: _answer_quit(True) → pending True → exit now
  quitBusy: _answer_quit(True) → pending True → session action completes → exit

## Acceptance examples (downstream, no additional nodes)

Each AT uses the driver's back-to-back button-3 press/release route and the real copy source, then the four E1 cells: T1 receives exactly the first line once and T2 receives every copied line once, by both P1 and P2 where applicable. The separate OS read equals the copied source on WinCI. These are design examples, not executed results.

examples: (AT-I1b-1) three main-hex rows selected and right-clicked → exact three-line source; all four paste cells receive it without duplication
examples: (AT-I1b-2) whole five-line stats selection right-clicked → exact five-line source; T1 gets its first line and T2 all five
examples: (AT-I1b-3) A2L summary lines selected and right-clicked → exact selection, not a withdrawn whole-view copy
examples: (AT-I1b-4) third A2L row right-clicked → `ASAM.M.SCALAR.UBYTE.RAT_FUNC.IDENT.STATUS_STRING`, never its shortened painted Tag cell
examples: (AT-I1b-5) third MAC row right-clicked → `Curve_ExternalAxis`, without `⚠ ` or a tab
examples: (AT-I1b-6) two stock JSON lines selected with Shift+Down and right-clicked → those two lines captured before the press clears them
examples: (AT-I1b-7) two Workspace-help lines selected in the modal and right-clicked → both lines; Escape then closes help before the paste steps
examples: (AT-I1b-8, manual operator only) Windows Terminal six-step acceptance uses body B; existing steps 4–5 also exercise idle q with selection present and absent plus the one-instance guard on a second q; remains not_run here and no agent touches the operator clipboard

## Findings

finding R-COPY.1
anchor: N1, C2
seen: explicit examples cover Ctrl+C of three hex rows, five stats lines, the A2L summary, two detail-card lines, two stock-JSON lines and two Workspace-help-modal lines; each reaches N1 once with its exact source and has an independent Windows-read oracle, and modal copy opens no N9
decision: covered by concrete design examples for all six sources, not by route equivalence alone

finding R-COPY.2
anchor: N1, N3, C1
seen: matching right-click release fills app clipboard with the three-line selection; R-COPY.2/4 independently right-clicks A2L row 3 with a failing writer and retains the exact row name in app clipboard while the OS seed remains
decision: covered by concrete selection and row-plus-failure examples jointly with group B

finding R-COPY.4
anchor: N2, N6, N7, C6, C7
seen: clicked A2L row key yields full mapped name despite shortened cell; MAC Rich Text is normalized by .plain/str and loses exactly one known producer prefix, including on a long name with spaces; out_of_bounds=False is the positive control and highlighted-row/tab/truncation mutants go RED
decision: covered by concrete design examples

finding R-COPY.6
anchor: N1, N8, C2
seen: button/no-focus/highlighted-table/empty-box/empty-JSON routes and the new present-but-empty screen-selection arm open one body-B N9 with both app/OS seeds observed unchanged while open and after n; N1 raises SkipAction before coroutine/worker rather than returning
decision: covered by concrete design examples; the return mutant suppresses the idle dialog and goes RED

finding R-COPY.7
anchor: N1, C1, C3
seen: one/five/three-line view notices and text-box copy/cut/right-click each exactly one; failure gives no success notice
decision: covered jointly with group B; app supplies one schedule and no notice

finding R-COPY.8
anchor: N1, C1
seen: 75,210-character JSON passed whole to C1 and capped to 65,536 on every clipboard surface for key/right-click
decision: covered jointly with group B; N1 never truncates

finding R-COPY.9
anchor: N1, C1
seen: exact cut notice retains grouped original total 75,210 and excludes ordinary copy notice
decision: covered jointly with group B

finding R-COPY.10
anchor: N1, C1
seen: one OSC 52 per key/right-click/row; super-call mutant gives two
decision: covered jointly with group B

finding R-COPY.11
anchor: N3, N5, C7
seen: explicit left-drag, down-key, F7 and valid-left-click examples schedule no copy; right-drag, out-and-return and reentry negatives preserve both seeds with zero N1/tail/base/writer/OSC 52/notices; the valid in-bounds left-click toolkit route remains
decision: covered by concrete design examples, including the E3-01 release-only copy oracle

finding R-COPY.12
anchor: N2, N3, C2
seen: whole spanning selection, explicit detail-card/modal/JSON selections and back-to-back press/release are captured on MouseDown but copied only after a valid matching MouseUp consumes/clears the candidate
decision: covered by concrete design examples

finding R-COPY.13
anchor: N2, N3, N5
seen: unrelated view, header, zero-row table and A2L/MAC row padding with out_of_bounds=True return None and preserve both seeds; no candidate can turn right-drag padding into a copy
decision: covered by concrete design examples

finding R-COPY.14
anchor: N2, N3, N5
seen: the same empty gestures plus out_of_bounds=True schedule zero tail/base/writer/OSC 52 and show zero notices; the sole flag change to False is the positive copy/highlight control
decision: covered by concrete positive and negative design examples

finding R-COPY.15
anchor: N3, C2
seen: exactly one unconditional superclass forwarding per event lets toolkit clear hex/stats/JSON selections after the valid release has consumed the candidate and called N1 with its press snapshot
decision: covered by concrete design examples

finding R-COPY.16
anchor: N1, N8, N9
seen: idle no-selection routes show exactly one body-B Quit? dialog with `Quit the app? Nothing is selected to copy.`, including highlighted table, non-empty unselected text box and a present screen selection extracting empty through N1 SkipAction; geometry at 118×54/220×60 remains a historical-note E4 target, while current G2 notes={}
decision: covered by concrete design examples; empty-copy normal return is a RED mutant

finding R-COPY.17
anchor: N8, N9, C5
seen: y, Tab+Enter and click Quit share one answer and exit 0 within 1 s
decision: covered by concrete design examples

finding R-COPY.18
anchor: N9
seen: Stay has modal-confirm and Quit does not through inherited PRIMARY_BUTTON
decision: covered by concrete design examples

finding R-COPY.19
anchor: N8, C5
seen: held Loading opens existing busy question and zero N9
decision: covered by concrete design examples

finding R-COPY.20
anchor: N1, C4, N8
seen: help/Load/N9/busy modal prevents reaching N8 even when a present screen selection extracts empty and N1 raises SkipAction; no second dialog, no copy effects and both seeds unchanged; selected help text copies without opening N9
decision: covered by concrete design examples; no product modal branch added

finding R-COPY.21
anchor: N5, N6, N7, C7
seen: clicked in-bounds A2L/MAC row with out_of_bounds=False moves cursor and RowHighlighted updates detail without using old highlight as copy source; True prevents default and leaves cursor unchanged with zero RowSelected
decision: covered by concrete positive and negative design examples

finding R-COPY.22
anchor: N5, N6, N7
seen: second right-click on a highlighted valid row prevents RowSelected and all three hex views retain first painted rows; out_of_bounds=True likewise gives no selection/jump but also no cursor move; valid left route unchanged
decision: covered by concrete design examples

finding R-COPY.23
anchor: N8, N9, N10, C4
seen: idle q with nothing selected and with three hex rows selected opens one body-B N9 without copying or exiting; second q cannot stack another modal or quit; q Quit token unchanged
decision: covered by discriminating examples; old q → quit and selection-copy/suppression mutants go RED

finding R-COPY.24
anchor: N10, C5
seen: idle Ctrl+Q and palette Quit each exit 0 within 1 s with zero N9/busy questions; palette remains PaletteEntry("Quit", "quit"), not raw help_quit
decision: covered by discriminating examples; N10 preserves action_quit and its busy body while preventing the palette-propagation regression

finding R-COPY.25 (consumed corrective tail contract)
anchor: C1, N1
seen: NUL in capped payload from either N1 or a direct text box gives zero base/writer/OSC 52/process/success notices and unchanged seeds, one 6-second `Clipboard copy refused — NUL cannot be represented in the Windows text clipboard.` warning and fixed WARNING `OS clipboard copy refused; payload contains NUL`; NUL only after cap writes the capped prefix with one cut notice; other C0/markup remains raw
decision: consumed jointly with group B through I-1; group A adds no internal tail, NUL, writer or notification design and no function node

finding R-PASTE.9
anchor: N1, C1
seen: failing view/key/right-click/row writes produce one exact warning and no success notice
decision: covered jointly with group B through I-1

finding R-PASTE.10
anchor: N1, C1
seen: failing view copy emits WARNING without copied payload
decision: covered jointly with group B through I-1

finding R-PASTE.13
anchor: N1, C1
seen: held OS clipboard ends with warning within 2.5 s and no success notice
decision: covered jointly with group B through I-1

finding R-PASTE.14
anchor: N1, C1
seen: synchronous schedule plus I-1 async tail keeps 50 ms timer lateness ≤100 ms on all three view-copy routes
decision: covered jointly with group B through I-1

finding R-TUI-043.13
anchor: N1-N3, C1
seen: SECRET-COPY-43 and its first 16 characters occur in zero log records; the E3-03 model fixture with [red], ESC, BEL, OSC-looking text and LF but no NUL is observed raw at app clipboard, decoded OSC 52 and separate Windows read, including forced PowerShell, with no payload process argument, extra terminal sequence or name/prefix in logs
decision: covered by concrete design examples through consumed C1; no markup or representable-C0 sanitization is added

finding R-DLG.1
anchor: N9, C4
seen: window keys and q do not act behind N9
decision: covered by inherited modal behavior and concrete example

finding R-DLG.2
anchor: N9, C5
seen: Escape equals Stay, restores focus and preserves both clipboards
decision: covered by inherited bindings and concrete example

finding R-DLG.6
anchor: N9
seen: initial focus is Stay through inherited AUTO_FOCUS
decision: covered by concrete design example

finding R-DLG.9
anchor: N9, C5
seen: Stay closes only N9, preserving window/scroll and pending state
decision: covered by concrete design example

finding R-DLG.11
anchor: N9
seen: exact visible labels Quit (y) and Stay (n)
decision: covered by concrete design example

finding R-DLG.12
anchor: N9
seen: n stays, y quits and repeated answer is guarded
decision: covered by inherited bindings/guard and concrete example

finding R-DLG.14
anchor: N8, N9, N10
seen: N9 has the shared action_help_quit opener reached by Ctrl+C without selection and by q while idle; current census 21 becomes 22
decision: covered by concrete design examples for both opener routes

finding R-QUIT.8
anchor: N8, C5
seen: busy Quit waits for held load completion before exit 0
decision: covered by unchanged shared _answer_quit and concrete example

finding R-TUI-042a.5 (regression pin)
anchor: N6, C6
seen: base-class change adds no resize competitor; existing Measured/fit still clips at 80×54
decision: regression covered by concrete design example; not a new Inc 1b requirement

finding R-TUI-042a.6 (regression pin)
anchor: N2, N6, C6
seen: literal safe painted cell stays unchanged while copy reads the raw full model name rather than the U+FFFD projection; only capped NUL is refused under consumed R-COPY.25
decision: regression covered by concrete design example; not a new Inc 1b requirement and not a general sanitizer

finding E2-1 (superseded E1 and historical G2 sketches)
anchor: N1, N4, N6, N7, N10, C6
seen: the old second writer/two-composition sketch conflicts with Resume reconciliation; first-G2 dialog/q choices are historical, while current G2 r2 and E2-interfaces already agree on body B and q=B/O-1=B; current G2 notes={} and its general note is empty, so old geometry/A2L notes are not current
decision: resolved by pinned I-1/I-12.2 without superseding the aligned interfaces; N10 remains the only G2 r2 node added to the previous 16

finding E2-2 (cross-increment text-box exclusion)
anchor: N2, N3, C3
seen: App.on_event sees the press before a text box can stop bubbling, but N2 returns None before any other selection read and N3 never calls N1 on press; an unrelated view selection must not become a second copy on release
decision: N2 preserves the early text-box exclusion and the box's direct route; E3A-24(c) has a discriminating example

finding COVERAGE
anchor: 24 unique integrated function nodes; group A has 17 fragment entries (N1-N10 implementation and C1-C7 context) and contributes 16 integrated nodes after C1 yields to group B's changed tail
seen: the E2 baseline was 22 rows/100 cases (82 R-COPY + 9 cited clipboard + 9 cited dialog); the current corrective ledger is 23 active R-COPY rows and 112 cases (93 R-COPY + 10 cited clipboard/security + 9 dialog/quit), with all E3A-03 source arms, R-COPY.25/1…3 and R-TUI-043.13/102 explicit; R-COPY.25 is consumed through I-1 without a requirements/test edit in this lane; 13 cited clipboard/security/dialog/quit rows, 2 Inc 12 regression pins, 7 copy-source ATs and manual AT-I1b-8 remain represented; integrated source census is 2 changed files (one per group), with 1 app source file in group A
decision: 16 group-A integrated nodes plus 8 group-B nodes give 24 unique nodes below the 40-node cap across 2 changed source files; the 17-entry fragment count includes the consumed C1 boundary and is not an additional integrated node; _right_gesture is a data entity and adds no function node; no further split, no runtime claim and E3 re-review remains required
