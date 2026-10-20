# Code-Wire graph: Patch Editor document to JSON view and stamp (batch-97, PDR)

> Format B, Code-Wire draft v2.5, forward direction (PDR baseline). The node name is the code qualname (C11 rule of this project).
> Design source: `design/design-proposal.md` D1 to D4 (I-2/I-3). Requirements: HLR-144, LLR-144.5, LLR-144.6, LLR-144.7, LLR-148.9.
> The writers of `ChangeService.document` are not nodes here. They are shipped and unchanged, and the app node that calls them carries the `modify:` of the document entity.
> Thread: `TC-B94-10` (`tests/test_tui_patch_editor_b94.py::test_tc_b94_10_dirty_flag_transitions`), recorded at `7d823a7` (`extract/trace-patch.json`). The thread is entry `0x100` with bytes `DE AD BE EF`: Add, Save, then a Load of `t.json` with entry `0x300`. A line marked `synthetic` is the design example of behaviour that does not exist yet.
> Convention: an edge from a node with no port to a port means that the node computes that value in its own body (annex, M-3).

## Nodes

S19TuiApp.on_patch_editor_panel_action_requested
req: LLR-144.5, LLR-144.6, HLR-144
in: PatchEditorPanel.ActionRequested event
out: None
func: routes one Patch Editor action to the change service. At its end (`app.py:3265`) it always refreshes the panel with rows, image map and the document view
module: s19_app/tui/app.py
modify: [Data: ChangeService.document] (replace)
inner: S19TuiApp._patch_editor_load, S19TuiApp._patch_document_view, PatchEditorPanel.refresh_entries, PatchEditorPanel.mark_saved, PatchEditorPanel.mark_loaded
examples: (TC-B94-10) event {action "add_entry"} → None; the call ends with one refresh_entries call
examples: (TC-B94-10) event {action "save_doc"} → None; the call also ends with one refresh_entries call (H-P1)
examples: (AT-B97-02, synthetic) event {action "add_entry"} on the 6-entry fixture → `refresh_entries` receives document {entry_count 7}

S19TuiApp.action_patch_undo
req: LLR-144.6
in: S19TuiApp self
out: None
func: moves the document one step back in the history, then refreshes the panel through the history view
module: s19_app/tui/app.py
modify: [Data: ChangeService.document] (replace)
inner: S19TuiApp._refresh_patch_history_view
examples: (TC-B97-06, inferred) undo after one Add on 6 entries → document 6 entries; view parses to 6

S19TuiApp.action_patch_redo
req: LLR-144.6
in: S19TuiApp self
out: None
func: moves the document one step forward in the history, then refreshes the panel through the history view
module: s19_app/tui/app.py
modify: [Data: ChangeService.document] (replace)
inner: S19TuiApp._refresh_patch_history_view
examples: (TC-B97-06, inferred) redo after that undo → document 7 entries; view parses to 7

S19TuiApp._apply_entry_json_edit
req: LLR-144.6
in: int index; str? edited
out: None
func: replaces one entry from the popup JSON on Confirm. Cancel changes nothing
module: s19_app/tui/app.py
modify: [Data: ChangeService.document] (replace)
inner: S19TuiApp._refresh_patch_history_view
examples: (TC-B97-06, inferred) index 0; edited with a new value → view shows the new value of entry 1 of 6

S19TuiApp._refresh_patch_history_view
req: LLR-144.6
in: S19TuiApp self
out: None
func: refreshes rows, issues, history strip and the document view after a history move (`app.py:3451`)
module: s19_app/tui/app.py
inner: S19TuiApp._patch_document_view, PatchEditorPanel.refresh_entries
examples: (TC-B97-06, synthetic) after undo → `refresh_entries` receives the document view of the restored document

S19TuiApp._patch_editor_load
req: LLR-144.5, HLR-144
in: PatchEditorPanel panel; str path_text
out: None
func: loads one change-set file through the change service. On success it clears the dirty flag. Then it runs the shared load tail
module: s19_app/tui/app.py
modify: [Data: ChangeService.document] (replace)
inner: PatchEditorPanel.mark_loaded, S19TuiApp._patch_editor_load_tail
examples: (TC-B94-10) path_text ".../patches/t.json" → None; the document now holds the one entry of t.json

S19TuiApp._patch_editor_load_tail
req: LLR-144.5
in: PatchEditorPanel panel
out: None
func: the shared re-render after a load (`app.py:5279`): rows, image map, issues, the file-backed guards and the document view
module: s19_app/tui/app.py
inner: S19TuiApp._patch_document_view, PatchEditorPanel.refresh_entries
examples: (TC-B94-10, inferred) after the Load of t.json → `refresh_entries` receives 1 row, address "0x300"
examples: (AT-B97-01, synthetic) after the Load of the 6-entry fixture → the view parses to 6 entries, addresses `0xEB10` to `0xED40`

S19TuiApp._apply_prepared_load
req: LLR-144.5
in: PreparedLoad prepared; Path path; float load_started
out: None
func: installs a newly loaded image. For the Patch Editor it re-renders rows with the new image map and the unchanged document view (`app.py:10758`)
module: s19_app/tui/app.py
inner: S19TuiApp._patch_document_view, PatchEditorPanel.refresh_entries
examples: (TC-B97-06, synthetic) a new image while 6 entries are loaded → view and entry count unchanged; stamp time moves

S19TuiApp._patch_document_view
req: LLR-144.5, LLR-144.7
in: S19TuiApp self
out: PatchDocumentView view {name, kind, json_text, entry_count}
func: builds the plain-data payload of the panel from the service document: file name, kind, serialised JSON as text, entry count
module: s19_app/tui/app.py
inner: serialize_change_document
examples: (TC-B94-10, synthetic) document 1 entry {address 0x100, bytes DE AD BE EF}; no source path → view {name None, kind "change", json_text with `"address": "0x100"`, entry_count 1}

serialize_change_document
req: LLR-144.5
in: ChangeDocument document
out: bytes wire
func: writes the document as canonical v2 JSON, UTF-8, indent 2, `ensure_ascii` on
module: s19_app/tui/changes/io.py
examples: (TC-B94-10) document {kind "change", entries 1 of 1 {address 0x100, encoded_bytes (0xDE, 0xAD, 0xBE, 0xEF)}} → wire 232 bytes with `"address": "0x100"` and `"bytes": "DE AD BE EF"`

PatchEditorPanel.refresh_entries
req: LLR-144.5, LLR-144.6, LLR-144.7, LLR-148.9
in: Sequence[object] rows; Union[Mapping[int, int], None, _Unset] mem_map = _UNSET; Union[PatchDocumentView, _Unset] document = _UNSET
out: None
func: repaints the ledger from the rows. A supplied document replaces the retained view, repaints the JSON view and recomposes the stamp. The sentinel keeps the retained value
module: s19_app/tui/screens_directionb.py
modify: [Data: PatchEditorPanel._document_view] (replace); [Interface: patch ledger] (replace); [Interface: patch json view] (replace); [Interface: patch json stamp] (replace)
inner: json_stamp_text, PatchEditorPanel._render_before_after_card
contract: the view shows at most `JSON_TAB_LINE_CAP` = 5000 document lines, then one note line `showing 5000 of M lines`; no action reads the view text
examples: (TC-B94-10) rows 1 of 1 {address_text "0x100", value_text "DE AD BE EF"}; mem_map None → ledger 1 row
examples: (AT-B97-02, synthetic) rows 7; document {entry_count 7}; dirty True → view parses to 7 entries; stamp "7 entries · 10:02:13 · unsaved changes"

PatchEditorPanel._refresh_dirty_indicator
req: LLR-144.6
in: PatchEditorPanel self
out: None
func: repaints the dirty marker and recomposes the stamp from the retained entry count and refresh time and the current dirty flag
module: s19_app/tui/screens_directionb.py
modify: [Interface: patch json stamp] (replace); [Interface: patch ledger] (replace)
inner: json_stamp_text
examples: (TC-B94-10, inferred) 6 calls in the thread; the SCRIPT subtitle marker follows the flag
examples: (AT-B97-02, synthetic) after Save, retained {entry_count 7, time "10:02:13"}; dirty False → stamp "7 entries · 10:02:13 · saved"

json_stamp_text
req: LLR-144.6
in: int n; str hhmmss; bool dirty
out: str stamp
func: composes the stamp `N entries · HH:MM:SS · saved` or `… · unsaved changes`
module: s19_app/tui/screens_directionb.py
examples: (AT-B97-02, synthetic) n 7; hhmmss "10:02:13"; dirty True → stamp "7 entries · 10:02:13 · unsaved changes"
examples: (TC-B97-06, synthetic) n 0; hhmmss "10:03:00"; dirty True → stamp "0 entries · 10:03:00 · unsaved changes"

PatchEditorPanel.mark_saved
req: LLR-144.6
in: PatchEditorPanel self
out: None
func: clears the dirty flag after a clean save (writer w3) and repaints the marker and the stamp
module: s19_app/tui/screens_directionb.py
modify: [Data: PatchEditorPanel._dirty] (clear)
inner: PatchEditorPanel._refresh_dirty_indicator
examples: (TC-B94-10) after Save of the 1-entry document → None; the flag reads False

PatchEditorPanel.mark_loaded
req: LLR-144.6
in: PatchEditorPanel self
out: None
func: clears the dirty flag after a successful load or paste parse (writer w4)
module: s19_app/tui/screens_directionb.py
modify: [Data: PatchEditorPanel._dirty] (clear)
inner: PatchEditorPanel._refresh_dirty_indicator
examples: (TC-B94-10) after the Load of t.json → None; the flag reads False (2 calls in the thread)

PatchEditorPanel.request_action
req: LLR-144.6
in: str action
out: None
func: sets the dirty flag for an entry Add, Edit or Remove (writer w1), then posts the action to the app
module: s19_app/tui/screens_directionb.py
modify: [Data: PatchEditorPanel._dirty] (replace)
inner: PatchEditorPanel._refresh_dirty_indicator
examples: (TC-B94-10) action "add_entry" → None; the flag reads True
examples: (TC-B94-10) action "save_doc" → None; the flag does not change here (Save clears it later, in mark_saved)

PatchEditorPanel.on_text_area_changed
req: LLR-144.6
in: TextArea.Changed event
out: None
func: sets the dirty flag when the paste buffer changes (writer w2). The document does not change
module: s19_app/tui/screens_directionb.py
modify: [Data: PatchEditorPanel._dirty] (replace)
inner: PatchEditorPanel._refresh_dirty_indicator
examples: (TC-B94-10, inferred) one newline typed into `#patch_paste_text` → the flag reads True; the stamp is the only repaint (P-57)

## Entities

[Data: ChangeService.document]
in: ChangeDocument
desc: the owned change document. Its writers change entries in place (`change_service.py:1080, 1154, 1196, 1223, 1344`) or replace it (`:861, 893, 1404, 1465`)
sequence:
  addEntry: on_patch_editor_panel_action_requested wins
  loadByButton: _patch_editor_load wins
  undo: action_patch_undo wins
  save: no write; `ChangeService.save` reads it only
  validate: on_patch_editor_panel_action_requested wins (it replaces `document.issues`, a field that the JSON does not carry)

[Data: PatchEditorPanel._dirty]
in: bool
desc: the one dirty flag of the panel (`screens_directionb.py:4851`)

[Data: PatchEditorPanel._document_view]
in: PatchDocumentView?
desc: the retained document view and its refresh time. The stamp of the dirty trigger reads the count and the time from here. None until the first document arrives (proposed by this graph, see H-P3)
sequence:
  loadByButton: mark_loaded → _refresh_dirty_indicator (!) → refresh_entries (load tail, `app.py:5279`) → refresh_entries wins (handler end, `app.py:3265`)
  loadByDropdown: mark_loaded → _refresh_dirty_indicator (!) → refresh_entries wins (load tail)
  addEntry: request_action → _refresh_dirty_indicator (!) → on_patch_editor_panel_action_requested → refresh_entries wins
  save: on_patch_editor_panel_action_requested → mark_saved → _refresh_dirty_indicator → refresh_entries wins
  pasteTyping: on_text_area_changed → _refresh_dirty_indicator (reads only)
  validateOrRunChecks: on_patch_editor_panel_action_requested → refresh_entries wins (no document change)
  undo: action_patch_undo → _refresh_patch_history_view → refresh_entries wins

[I/O: change-set file]
in: bytes
desc: the v2 change-set JSON that Load reads (thread: `t.json`)

[I/O: clock]
in: str
desc: the local wall time, read as HH:MM:SS when the view refreshes

[Data: S19TuiApp.current_file]
in: LoadedFile?
desc: the loaded image. Its `mem_map` and `ranges` go to every refresh

[Interface: patch ledger]
in: Sequence[object]
desc: `#patch_doc_entries_table` and the SCRIPT window subtitle

[Interface: patch json view]
in: str
desc: `#patch_json_view`, a read-only TextArea (D3)

[Interface: patch json stamp]
in: str
desc: `#patch_json_stamp` above the view (D3, D4)

## Edges

[I/O: change-set file] ──▶ S19TuiApp._patch_editor_load.path_text
[Data: ChangeService.document] ──▶ S19TuiApp._patch_document_view
[Data: S19TuiApp.current_file] ──▶ S19TuiApp.on_patch_editor_panel_action_requested
[Data: S19TuiApp.current_file] ──▶ S19TuiApp._patch_editor_load_tail
[Data: S19TuiApp.current_file] ──▶ S19TuiApp._refresh_patch_history_view
S19TuiApp._patch_document_view ──▶ serialize_change_document.document
serialize_change_document.wire ──▶ S19TuiApp._patch_document_view.view.json_text
S19TuiApp._patch_document_view.view ──▶ PatchEditorPanel.refresh_entries.document
S19TuiApp.on_patch_editor_panel_action_requested ──▶ PatchEditorPanel.refresh_entries.rows
S19TuiApp._patch_editor_load_tail ──▶ PatchEditorPanel.refresh_entries.rows
S19TuiApp._refresh_patch_history_view ──▶ PatchEditorPanel.refresh_entries.rows
S19TuiApp._apply_prepared_load ──▶ PatchEditorPanel.refresh_entries.rows
[Data: PatchEditorPanel._dirty] ──▶ PatchEditorPanel.refresh_entries
[Data: PatchEditorPanel._dirty] ──▶ PatchEditorPanel._refresh_dirty_indicator
[Data: PatchEditorPanel._document_view] ──▶ PatchEditorPanel._refresh_dirty_indicator
[I/O: clock] ──▶ PatchEditorPanel.refresh_entries
PatchEditorPanel.refresh_entries.document.entry_count ──▶ json_stamp_text.n
PatchEditorPanel.refresh_entries ──▶ json_stamp_text.hhmmss
PatchEditorPanel.refresh_entries ──▶ json_stamp_text.dirty
PatchEditorPanel._refresh_dirty_indicator ──▶ json_stamp_text.n
PatchEditorPanel._refresh_dirty_indicator ──▶ json_stamp_text.hhmmss
PatchEditorPanel._refresh_dirty_indicator ──▶ json_stamp_text.dirty
json_stamp_text.stamp ──▶ [Interface: patch json stamp]

## Findings

H-P1
anchor: S19TuiApp.on_patch_editor_panel_action_requested ──▶ PatchEditorPanel.refresh_entries.rows
what: every Patch Editor action ends at `app.py:3265` with a `refresh_entries` call, Save included. With D1 that call also carries `document=`
evidence: `app.py:3146-3265` (no early return); recorded TC-B94-10: the `save_doc` handler call is followed by a `refresh_entries` call
consequence: the TC-B97-06 mutation "a stamp recomposed only by the document writers" keeps the Save arm GREEN, because the end-of-handler refresh recomposes the stamp. Only the paste-typing arm can go RED for the D4 second trigger
decision: no change to D4. TC-B97-06 names the typing arm as the RED arm of that mutation, or D1 passes `document=` only when the document changed

H-P2
anchor: S19TuiApp._patch_document_view ──▶ serialize_change_document.document
what: the serialiser runs once for each `refresh_entries` call, not once for each document write. That is 11 action kinds, undo, redo, entry JSON edit, every image load, and two times for one Load by button
evidence: recorded TC-B94-10: 6 `refresh_entries` calls, 2 of them for one `load_doc` (`app.py:5279` then `:3265`); `design-proposal.md:310` says "once per document write"
consequence: the §6.2 cost row is wrong. At the S-5 boundary (100,000 entries) each Validate, Run checks or Refresh files re-serialises the whole document on the UI thread. The stamp time also moves with no document change
decision: changes D1 or §6.2. Build the view only when a document revision changed (the writers mutate in place, so object identity is not a key). Or keep D1 and measure the 100,000-entry cost per action

H-P3
anchor: [Data: PatchEditorPanel._document_view] ──▶ PatchEditorPanel._refresh_dirty_indicator
what: D4 composes the stamp in `_refresh_dirty_indicator` from `n` and `hhmmss`, but no design element keeps them. The graph needs a retained view with its refresh time, and its initial value
evidence: C2 on `json_stamp_text.n` and `.hhmmss` for the dirty-flag trigger; D2 fields (`name, kind, json_text, entry_count`) hold no time; D22 deletes the show-time block `app.py:6966-6978`
consequence: two readings exist (the time of the last document refresh, or the time of the key press). Before the first action no site pushes a document. Thus the JSON view of a fresh start shows the LLR-148.9 empty line, not the empty draft
decision: D2/D4 add the retained field and say which time the stamp shows. LLR-148.9 names the fresh-start state of the JSON view

H-P4
anchor: serialize_change_document.wire ──▶ S19TuiApp._patch_document_view.view.json_text
what: the serialiser returns `bytes`. D2 types `json_text` as `str`
evidence: `changes/io.py:1392`; D2 at `design-proposal.md:47`
consequence: the helper decodes the wire (ASCII is safe, `ensure_ascii` is on). A missed decode paints `b'{...'` in the view
decision: none. Record the decode in D2
