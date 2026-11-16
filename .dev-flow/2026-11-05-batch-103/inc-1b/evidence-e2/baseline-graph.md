# Inc 1b E2 — baseline Code-Wire v3.1.0

Current product tree: `59d467ff7390844455e80b367db9beb4957b23c5` (`batch-103`). This file records only current code and current behavior; it adds no prototype declaration. Class-only symbols are entities because Code-Wire nodes bind to function or method defs. `_a2l_row_key_to_tag` is a data entity, not a function. Line citations are from the current tree; the extractor report is authoritative for static callers, subject to its name-based limits.

Static-reading caveats: the extractor reports 3 ambiguous call resolutions. Its top-level citation `A2LTagTable.on_resize` at `s19_app/tui/app.py:1562` is `super().on_resize(event)` inside `A2LDetailCard.on_resize` (`app.py:1560`), not a call to `A2LTagTable.on_resize`; do not use it as a caller edge. Textual message/key dispatch is outside static call resolution: the table handlers and `action_quit` therefore have no direct product caller in the report. Likewise, `_answer_quit` is passed as a callback at `app.py:23034`, not called directly there. The `## Edges` section records those routes explicitly. The executor reference to `write_os_clipboard` is the extractor's `(ref)` at `os_clipboard_input.py:741`.

## Nodes

S19TuiApp.compose
req: to trace
in:
out: ComposeResult result
func: baseline. Builds the main screen and calls both rail-screen builders.
module: s19_app/tui/app.py
examples: (baseline compose) one app composition → containers `screen_a2l` and `screen_mac`

A2LTagTable._highlight_row
req: R-COPY.21
in: int row_index
out: None
func: baseline. Refreshes the row without the toolkit highlight while `suppress_row_highlight` is true; otherwise delegates to `DataTable._highlight_row`.
module: s19_app/tui/app.py
examples: (R-COPY.21 base) row_index `4` with suppression false → toolkit highlight of row `4`; suppression true → refresh of row `4` only

A2LTagTable.on_resize
req: R-TUI-042a.5
in: events.Resize event
out: None
func: baseline. Re-emits the table resize as one bubbling `A2LTagTable.Measured` message.
module: s19_app/tui/app.py
examples: (R-TUI-042a.5/6 base) a shown table resize to size `(38, 30)` → one `Measured` message

S19TuiApp._compose_screen_a2l
req: R-COPY.4, R-COPY.21, R-COPY.22
in:
out: Container result
func: baseline. Builds `screen_a2l`; `#a2l_tags_list` is one `A2LTagTable` with row cursor, zebra stripes, cell padding 1 and two fixed columns.
module: s19_app/tui/app.py
examples: (baseline A2L compose) the A2L rail → `A2LTagTable` `a2l_tags_list` with `cell_padding` `1` and `fixed_columns` `2`

S19TuiApp._compose_screen_mac
req: R-COPY.4, R-COPY.21, R-COPY.22
in:
out: Container result
func: baseline. Builds `screen_mac`; `#mac_records_list` is currently a plain `DataTable` with a row cursor and zebra stripes.
module: s19_app/tui/app.py
examples: (baseline MAC compose) the MAC rail → plain `DataTable` `mac_records_list` with cursor type `row`

S19TuiApp.on_data_table_row_selected
req: R-COPY.22
in: DataTable.RowSelected event
out: None
func: baseline. Resolves a MAC row through `_mac_row_key_to_address` or an A2L row through `_a2l_row_key_to_tag`, then calls the corresponding hex jump helper.
module: s19_app/tui/app.py
examples: (R-COPY.22 base) selected A2L row `a2l:2` whose map holds `ASAM.M.SCALAR.UBYTE.RAT_FUNC.IDENT.STATUS_STRING` → `_jump_to_tag_by_data` for that tag, so the current hex position can change

S19TuiApp.on_data_table_row_highlighted
req: R-COPY.21
in: DataTable.RowHighlighted event
out: None
func: baseline. For the A2L table only, resolves the highlighted row key and passes its tag, or `None`, to the detail card; it does not call a hex jump helper.
module: s19_app/tui/app.py
examples: (R-COPY.21 base) highlighted A2L row `a2l:4` → detail card `show_tag` with the fifth row's full tag and no selection-event jump

S19TuiApp.update_a2l_tags_view
req: R-COPY.4, R-TUI-042a.5
in: list[dict] tags; str? empty_message = None
out: None
func: baseline. Rebuilds one visible tag page, resets and repopulates the row-key-to-tag map with the original enriched dicts, and paints cells built at the measured name width.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._a2l_row_key_to_tag] (replace); [Data: A2L Explorer tag table rows] (replace)
examples: (R-COPY.4 baseline map) one visible tag named `ABCDEFGHIJKLMNO` at absolute index `0`, name width `5` → row key `a2l:0` maps to the original full name while the painted Tag cell is `· AB…NO`
examples: (baseline empty A2L) `tags=[]`, no custom message → empty row map and summary `No A2L tags.`

S19TuiApp._fit_a2l_tag_cells
req: R-TUI-042a.5
in:
out: None
func: baseline. Compares each painted Tag cell with the cell for the measured width; on the first mismatch it rebuilds through `update_a2l_tags_view` and restores cursor and scroll.
module: s19_app/tui/app.py
examples: (R-TUI-042a.5/6 base) row `a2l:0` painted `· ABCDEFGHIJKLMNO` but width `5` requires `· AB…NO` → one page rebuild, then cursor and scroll restoration

S19TuiApp.on_a2l_tag_table_measured
req: R-TUI-042a.5
in: A2LTagTable.Measured event
out: None
func: baseline. Stops the bubbling measurement message and calls `_fit_a2l_tag_cells` directly once.
module: s19_app/tui/app.py
examples: (R-TUI-042a.5/6 base) one `Measured` after a resize → stopped event and one `_fit_a2l_tag_cells` call

S19TuiApp._repaint_a2l_tag_cells
req: R-COPY.4, R-TUI-042a.5
in:
out: None
func: baseline. Rewrites changed cells in place after an image write, retains full tag dicts in the row-key map and invalidates the table caches without clearing rows or moving the cursor.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._a2l_row_key_to_tag] (replace); [Data: A2L Explorer tag table rows] (replace)
examples: (R-COPY.4 baseline repaint) shown row `a2l:0` repainted at width `5` → Tag cell `· AB…NO` and map value still full name `ABCDEFGHIJKLMNO`

S19TuiApp._build_a2l_table_cells
req: R-COPY.4, R-TUI-042a.5
in: dict tag; int? name_width = None
out: tuple[Text, ...] cells
func: baseline. Produces 16 markup-safe cells; Tag is index 2 and contains the in-image glyph plus the name shortened to the measured cap, not a separate copy-name value.
module: s19_app/tui/app.py
examples: (R-TUI-042a.5 baseline cell) name `ABCDEFGHIJKLMNO`, not in memory, name_width `5` → 16 cells with Tag index `2` equal to `· AB…NO`
examples: (R-TUI-042a.5 baseline uncapped) name `ABCDEFGHIJKLMNO`, in memory, name_width `None` → Tag cell `✓ ABCDEFGHIJKLMNO`

S19TuiApp._invalidate_a2l_view_cache
req: R-B102-A2L-005
in:
out: None
func: baseline. Clears the enriched and filtered A2L caches and replaces the row-key-to-tag map with an empty dict.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._a2l_row_key_to_tag] (replace)
examples: (R-B102-A2L-005 baseline) map containing `a2l:0` before invalidation → map `{}` afterward, so no old payload remains resolvable

S19TuiApp._running_session_action
req: R-COPY.19, R-QUIT.8
in:
out: _BusyRun? run
func: baseline. Returns the newest running session action, or `None`, without mutating busy state.
module: s19_app/tui/app.py
examples: (baseline idle session) no busy runs → `None`
examples: (R-COPY.19 baseline busy) newest running key `file_load` → that `_BusyRun`

S19TuiApp._refuse_if_busy
req: to trace
in:
out: bool refused
func: baseline. Returns false when no session action runs; otherwise paints the busy refusal and returns true.
module: s19_app/tui/app.py
examples: (baseline busy refusal) a running `file_load` → `True` and status `busy: Loading demo.s19 — wait for it to finish.`
examples: (baseline idle refusal) no session run → `False` and no refusal status

S19TuiApp.end_busy
req: R-QUIT.8
in: BusyKey key; int gen; str outcome
out: bool ended
func: baseline. Ends the matching busy generation and, after every effective end, calls `_exit_if_quit_pending`; stale generations return false before that call.
module: s19_app/tui/app.py
examples: (R-QUIT.8 baseline) matching final `file_load` generation `3` with quit pending → `True` followed by the pending-quit exit check
examples: (baseline stale busy end) generation `2` when current generation is `3` → `False` and no pending-quit exit check

S19TuiApp.action_quit
req: R-COPY.19, R-QUIT.8
in:
out: None
func: baseline. Exits immediately when idle; while a session action runs, ignores a repeated quit question or pushes `_QuitQuestionScreen` with `_answer_quit` as callback.
module: s19_app/tui/app.py
examples: (baseline idle quit) no session action → immediate `exit`, no question screen
examples: (R-COPY.19 baseline busy quit) running `file_load` → title `Quit?`, body `still working: Loading demo.s19 — wait, or quit after it finishes`, buttons `Quit (y)` and `Stay (n)`

S19TuiApp._answer_quit
req: R-COPY.17, R-QUIT.8
in: bool? quit
out: None
func: baseline. Converts the answer to a boolean pending flag and immediately runs the pending-quit exit check.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._quit_pending] (replace)
examples: (R-COPY.17 baseline answer) answer `True` while idle → pending `True` and exit
examples: (baseline stay answer) answer `False` → pending `False` and no quit

S19TuiApp._exit_if_quit_pending
req: R-QUIT.8
in:
out: None
func: baseline. Exits only when quit is pending and no session action is running; a busy run keeps the app alive until an effective `end_busy` checks again.
module: s19_app/tui/app.py
examples: (R-QUIT.8 baseline deferred quit) pending `True` and a running `file_load` → no exit; after its effective end and no session run → exit

write_os_clipboard
req: R-PASTE.9, R-PASTE.10, R-PASTE.12, R-PASTE.13
in: str text; tuple[tuple[str, Callable[[str], bool]], ...]? strategies = None
out: bool written
func: baseline. Caps the payload at 65,536 characters, tries the ordered writers and returns true on the first success; exceptions skip only that writer and total failure returns false.
module: s19_app/tui/os_clipboard_input.py
modify: [I/O: Windows clipboard] (replace)
examples: (baseline write success) text `abc` and one writer returning `True` → writer receives `abc` and result `True`
examples: (R-PASTE.12 baseline cap) text of `65537` characters → one writer receives exactly `65536` characters
examples: (R-PASTE.9 baseline failure) every writer returns `False` → result `False` and warning `write_os_clipboard: every strategy failed`

_mirror_and_write_os_clipboard
req: R-PASTE.9, R-PASTE.10, R-PASTE.12, R-PASTE.14
in: App app; str text
out: None
func: baseline. Caps once, calls toolkit base `App.copy_to_clipboard` directly, awaits `write_os_clipboard` in the executor, returns without a success notice and emits only the existing warning on failure.
module: s19_app/tui/os_clipboard_input.py
modify: [Data: App._clipboard] (replace); [I/O: terminal] (append); [I/O: Windows clipboard] (replace)
examples: (baseline mirror success) selected text `COPYME-1` and write `True` → app clipboard `COPYME-1`, one executor write and no success notice
examples: (R-PASTE.9/101 baseline failure) write `False` → one warning notice `Clipboard write failed — copied inside the app only.`, severity `warning`, timeout `6.0`
examples: (R-PASTE.12 baseline mirror cap) text of `65537` characters → toolkit base copy and OS write each receive `65536` characters

OsClipboardInput.action_copy
req: R-PASTE.2, R-PASTE.3, R-PASTE.5, R-PASTE.15
in:
out: None
func: baseline. Raises `SkipAction` for an empty selection; otherwise awaits the shared mirror/write tail without changing value or selection.
module: s19_app/tui/os_clipboard_input.py
examples: (R-PASTE.3/1 baseline) selection `COPYME-1` → one `_mirror_and_write_os_clipboard` call with `COPYME-1`, value unchanged
examples: (R-PASTE.5/1 baseline) empty selection and app clipboard `BEFORE` → `SkipAction`, clipboard remains `BEFORE`

OsClipboardInput.action_cut
req: R-PASTE.5, R-PASTE.6, R-PASTE.7, R-PASTE.15
in:
out: None
func: baseline. Raises `SkipAction` for an empty selection; otherwise deletes the selection locally and awaits the shared tail with the removed text.
module: s19_app/tui/os_clipboard_input.py
examples: (R-PASTE.7/1 baseline) value `DE AD BE EF`, selected `DE AD` → remaining value ` BE EF` and one tail call with `DE AD`
examples: (R-PASTE.5/3 baseline) empty selection → `SkipAction`, no local deletion and no tail call

CappedTextArea.action_copy
req: R-PASTE.2, R-PASTE.3, R-PASTE.5, R-PASTE.12, R-PASTE.15
in:
out: None
func: baseline. Raises `SkipAction` for an empty selection; otherwise awaits the shared mirror/write tail without modifying the document.
module: s19_app/tui/capped_text_area.py
examples: (R-PASTE.3/2 baseline) selected document text `COPYME-2` → one tail call with `COPYME-2`, document unchanged
examples: (R-PASTE.5/2 baseline) empty selection → `SkipAction`, no tail call

CappedTextArea.action_cut
req: R-PASTE.6, R-PASTE.7, R-PASTE.8, R-PASTE.15
in:
out: None
func: baseline. Returns for a read-only buffer; otherwise deletes the selection, or the cursor line when there is no selection, and sends the replaced text to the shared tail.
module: s19_app/tui/capped_text_area.py
examples: (R-PASTE.7/2 baseline) text `DE AD BE EF`, selected `DE AD` → remaining text ` BE EF` and one tail call with `DE AD`
examples: (R-PASTE.8/1 baseline) lines `first`, `line_to_cut`, `third`, cursor on the second line and no selection → remaining lines `first`, `third`, tail receives `line_to_cut` with at most one line end
examples: (baseline read-only cut) read-only document `KEEP` → no deletion and no tail call

## Entities

[Interface: A2LTagTable]
desc: Current module-level class at `s19_app/tui/app.py:1456`, directly inheriting `DataTable`; owns `_highlight_row`, `on_resize`, nested `Measured` and `suppress_row_highlight`. Composed only as `#a2l_tags_list` by `_compose_screen_a2l`.

[Interface: MAC records DataTable]
desc: Current plain `DataTable` constructed as `#mac_records_list` by `_compose_screen_mac` at `s19_app/tui/app.py:8860`.

[Interface: _QuitQuestionScreen]
desc: Current class at `s19_app/tui/app.py:462`, inheriting `ConfirmQuestionScreen` without adding methods; `PRIMARY_BUTTON = "confirm_no"`, inherited y/n/Escape bindings, focus, plain-text labels and answer guard.

[Data: S19TuiApp._a2l_row_key_to_tag]
in: dict[str, dict[str, Any]]
desc: Current map declared at `s19_app/tui/app.py:3086`; keys `a2l:<absolute index>` resolve original enriched tag dicts, independently of shortened painted cells.

[Data: S19TuiApp._mac_row_key_to_address]
in: dict[str, int]
desc: Current MAC row-key map declared at `s19_app/tui/app.py:3085`; selection resolves it before `_jump_to_mac_address`.

[Data: A2L Explorer tag table rows]
desc: The currently painted A2L page; Tag cell index 2 can be shortened while the row map retains the full name.

[Data: S19TuiApp._quit_pending]
in: bool
desc: Set from `_answer_quit`; read with `_running_session_action` by `_exit_if_quit_pending`.

[Data: App._clipboard]
in: str
desc: Textual's in-process clipboard, written through toolkit base `App.copy_to_clipboard` by the current async tail.

[Data: _WRITE_STRATEGIES]
desc: Current ordered OS write cascade used when `write_os_clipboard` receives `strategies=None`.

[I/O: Windows clipboard]
desc: External OS clipboard; no real clipboard call was made while producing this baseline.

[I/O: terminal]
desc: OSC 52 output produced by toolkit base `App.copy_to_clipboard`.

## Edges

S19TuiApp.compose ──▶ S19TuiApp._compose_screen_a2l
S19TuiApp.compose ──▶ S19TuiApp._compose_screen_mac
S19TuiApp._compose_screen_a2l ──▶ [Interface: A2LTagTable]
S19TuiApp._compose_screen_mac ──▶ [Interface: MAC records DataTable]
[Outside: terminal resize] ──▶ A2LTagTable.on_resize
A2LTagTable.on_resize ──▶ S19TuiApp.on_a2l_tag_table_measured
S19TuiApp.on_a2l_tag_table_measured ──▶ S19TuiApp._fit_a2l_tag_cells
S19TuiApp.update_a2l_tags_view ──▶ S19TuiApp._build_a2l_table_cells
S19TuiApp.update_a2l_tags_view ──▶ [Data: S19TuiApp._a2l_row_key_to_tag]
S19TuiApp._repaint_a2l_tag_cells ──▶ S19TuiApp._build_a2l_table_cells
S19TuiApp._repaint_a2l_tag_cells ──▶ [Data: S19TuiApp._a2l_row_key_to_tag]
S19TuiApp._invalidate_a2l_view_cache ──▶ [Data: S19TuiApp._a2l_row_key_to_tag]
[Data: S19TuiApp._a2l_row_key_to_tag] ──▶ S19TuiApp.on_data_table_row_selected
[Data: S19TuiApp._a2l_row_key_to_tag] ──▶ S19TuiApp.on_data_table_row_highlighted
[Data: S19TuiApp._a2l_row_key_to_tag] ──▶ S19TuiApp._fit_a2l_tag_cells
[Data: S19TuiApp._mac_row_key_to_address] ──▶ S19TuiApp.on_data_table_row_selected
[Outside: DataTable.RowSelected] ──▶ S19TuiApp.on_data_table_row_selected
[Outside: DataTable.RowHighlighted] ──▶ S19TuiApp.on_data_table_row_highlighted
S19TuiApp._fit_a2l_tag_cells ──▶ S19TuiApp._build_a2l_table_cells
S19TuiApp._fit_a2l_tag_cells ──▶ S19TuiApp.update_a2l_tags_view
when: at least one painted Tag cell differs from the measured-width form
[Outside: q, ctrl+q or palette Quit] ──▶ S19TuiApp.action_quit
S19TuiApp.action_quit ──▶ S19TuiApp._running_session_action
S19TuiApp.action_quit ──▶ [Interface: _QuitQuestionScreen]
when: a session action is running and no quit question is already stacked
S19TuiApp.action_quit ──▶ S19TuiApp._answer_quit
when: `_answer_quit` is passed as the `push_screen` callback; this is not a direct static call
S19TuiApp._answer_quit ──▶ [Data: S19TuiApp._quit_pending]
S19TuiApp._answer_quit ──▶ S19TuiApp._exit_if_quit_pending
S19TuiApp.end_busy ──▶ S19TuiApp._exit_if_quit_pending
when: the busy key and generation match an effective end
S19TuiApp._exit_if_quit_pending ──▶ S19TuiApp._running_session_action
S19TuiApp._refuse_if_busy ──▶ S19TuiApp._running_session_action
[Outside: ctrl+c] ──▶ OsClipboardInput.action_copy
[Outside: ctrl+x] ──▶ OsClipboardInput.action_cut
[Outside: ctrl+c or f7 then ctrl+c] ──▶ CappedTextArea.action_copy
[Outside: ctrl+x or f7 then ctrl+x] ──▶ CappedTextArea.action_cut
OsClipboardInput.action_copy ──▶ _mirror_and_write_os_clipboard
OsClipboardInput.action_cut ──▶ _mirror_and_write_os_clipboard
CappedTextArea.action_copy ──▶ _mirror_and_write_os_clipboard
CappedTextArea.action_cut ──▶ _mirror_and_write_os_clipboard
_mirror_and_write_os_clipboard ──▶ write_os_clipboard
_mirror_and_write_os_clipboard ──▶ [Data: App._clipboard]
_mirror_and_write_os_clipboard ──▶ [I/O: terminal]
[Data: _WRITE_STRATEGIES] ──▶ write_os_clipboard
write_os_clipboard ──▶ [I/O: Windows clipboard]
when: a platform writer is attempted; no such attempt was made for this baseline

## Findings

> No design finding is asserted by this baseline. Extractor and lint counts are recorded separately in this directory.
