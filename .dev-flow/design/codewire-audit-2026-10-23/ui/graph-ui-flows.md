# Code-Wire graph: s19_app user-interface flows (audit, reverse direction)

> Format B, Code-Wire draft v2.6 (`code-wire` main `dd39f91`). Reverse direction: the graph is written from the code at `9793fcd` (detached worktree `s19_app-cwaudit-ui`). The node name is the code qualname (C11 rule of this project, as in batch-97).
> Scope: six UI flows. U1 Load file. U2 Save and Load project. U3 Patch Editor apply, undo and save. U4 Flow Execution run and confirm. U5 Check Editor and CRC Designer. U6 navigation (rail, key bar, focus, help).
> Threads: each `examples:` line names its source, a step of a recorded headless run (`run_test`, Textual 8.2.8, real files from `examples/`). The probes are `probes/u0N_*.py`. Their recorded output is `probes/u0N.out.txt`. The source `(U1.3)` is step U1.3 of `u01.out.txt`. `inferred` = behaviour that the code has, with no recording in these runs.
> App state is a `[Data]` entity (Q19 option A). A Textual message is a declared edge (v2.6). A key press or a button press from the user is an `[Outside: …]` item.
> Requirement ids: `R-*` are in `REQUIREMENTS.md`; `LLR-*` name their batch in parentheses where the id repeats across batches. `to trace` = no requirement governs the behaviour.

## Nodes

LoadFileScreen.on_button_pressed
req: R-TUI-043, LLR-015.2 (batch-02)
in: Button.Pressed event
out: None
func: Load dismisses the dialog with the typed path. Cancel dismisses with None. Load with an empty path does nothing
module: s19_app/tui/screens.py
modify: [Interface: modal dialog] (replace)
examples: (U1.1) `Load` with the probe path ext\firmware.s19 → screen `Screen` (dialog closed); "Copying into workarea temp..."
examples: (U1.6) `Load` with an empty input → dialog still `LoadFileScreen`; no log line, no notice (`recorded = []`)
examples: (U6.3) `escape` on the dialog → still `LoadFileScreen`

S19TuiApp._load_path_from_user_input
req: R-TUI-011, R-PROJ-002
in: S19TuiApp self; Path path
out: None
func: resolves the path and sends it to the data load or to the A2L load by its suffix
module: s19_app/tui/app.py
modify: [Interface: status log] (append)
examples: (U1.7) missing path → "File not found: …\nope.s19"
examples: (U1.8) a folder path → "Unsupported file type: " (empty suffix; the line does not say that a folder was given)

S19TuiApp.load_from_path
req: R-TUI-011, R-TUI-006
in: S19TuiApp self; Path path
out: None
func: copies the source into `workarea/temp` and starts the parse worker
module: s19_app/tui/app.py
modify: [I/O: workarea temp] (append); [Interface: status log] (append)
examples: (U1.1) probe path ext\firmware.s19 (case_01) → temp [`firmware.s19`]; log "Copying into workarea temp..." then "Parsing firmware.s19..."
examples: (U1.3) the same source path with case_02 bytes → temp [`firmware.s19`, `firmware_1.s19`]; log "Parsing firmware_1.s19..."; no line says that a second copy was made
examples: (U1.5) the work copy temp\firmware_1.s19 itself → temp still [`firmware.s19`, `firmware_1.s19`]; the log still says "Copying into workarea temp..."

copy_into_workarea
req: R-TUI-006, R-TUI-011
in: Path source; Path destination; int max_size_bytes = DEFAULT_COPY_SIZE_CAP_BYTES
out: Path copied
func: copies a file into a contained work-area folder; a byte-identical target is reused, a different one gets `_<N>`
module: s19_app/tui/workspace.py
modify: [I/O: workarea temp] (append)
examples: (U1.2) same bytes again → copied `firmware.s19` (reused); temp has `1` file
examples: (U1.4) source back to the case_01 bytes → copied `firmware.s19` (reused); temp still [`firmware.s19`, `firmware_1.s19`]

S19TuiApp._apply_prepared_load
req: R-TUI-029, LLR-080.2 (batch-48)
in: S19TuiApp self; PreparedLoad prepared; Path path
out: None
func: installs the parsed file as the current file, repaints the Patch Editor rows against the new image and writes the file status line
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.current_file] (replace); [Interface: file status line] (replace); [Interface: status log] (append)
examples: (U1.1) → file status "Loaded firmware.s19 (S19 only)"; the log gets "Loaded firmware.s19 (S19 only)" and "Loaded firmware.s19"
examples: (U3.9) a load over an image with an applied, unsaved patch (`0B 16 BE EF` at `0x8000007C`) → no question, no notice; file status "Loaded firmware_1.s19 (S19 only)"; the patched bytes are gone; the Patch Editor keeps its `2` entries, now "outside"
examples: (U2.7) project P2 over P1 → file status "Loaded prg.s19 (S19+MAC: firmware.mac)": the MAC of P1 stays

S19TuiApp.refresh_files
req: to trace (R-TUI-003 is superseded by R-TUI-029, which does not name the list)
in: S19TuiApp self
out: None
func: fills the Workarea Files list from the files at the top level of the work area
module: s19_app/tui/app.py
modify: [Interface: Workarea Files list] (replace)
examples: (U1.1) after the load → list `[]`; temp holds `firmware.s19`
examples: (U1.9) after 5 loads → list `[]`; work-area root files `[]`, dirs [`patches`, `temp`]

S19TuiApp._load_from_item
req: to trace
in: S19TuiApp self; ListItem item
out: None
func: loads the file that the Workarea Files list row names, from the work-area root
module: s19_app/tui/app.py
examples: (U1.9, inferred) no row exists to select, so the node never runs; its name lookup also reads `Label.text`, which Textual 8.2.8 does not have

S19TuiApp.watch_current_file
req: HLR-138 (batch-95)
in: S19TuiApp self
out: None
func: on each change of the current file, refreshes the Split/Join/Export window, also when that window is hidden
module: s19_app/tui/app.py
inner: SplitJoinWindow.refresh_window

SplitJoinWindow.refresh_window
req: HLR-138, HLR-135 (batch-95)
in: SplitJoinWindow self
out: None
func: re-reads the loaded image into the window and moves the focus to the window table
module: s19_app/tui/segment_split_view.py
modify: [Data: App.focused] (replace)
examples: (U6.2) after a load on the Workspace → focused `_SegTable sje_table`; window hidden `True`
examples: (U6.1, U6.2) then `p` → screen stays `Screen` (no Load project dialog); `a` → log "manual: dropped a"; `k` (key bar "Legend") → log "manual: dropped aeek"
examples: (U5.4) on the Check Editor after a load → focused `_SegTable sje_table`

SaveProjectScreen.on_button_pressed
req: R-TUI-012, LLR-017.3
in: Button.Pressed event
out: None
func: Save dismisses with the parent folder, the name and the composition. Save with an empty field does nothing
module: s19_app/tui/screens.py
modify: [Interface: modal dialog] (replace)
examples: (U2.1) name "P1" → payload; log "Saved project to …\P1 (variant 'firmware')"
examples: (U2.8) empty name → still `SaveProjectScreen`; nothing recorded

S19TuiApp._handle_save_dialog
req: R-TUI-012, R-PROJ-001, R-MAN-SER-001
in: S19TuiApp self; SaveProjectPayload? payload
out: None
func: copies the loaded files into the project folder and writes and verifies `project.json`
module: s19_app/tui/app.py
modify: [I/O: project folder] (append); [Interface: status log] (append)
examples: (U2.1) → "Project saved + manifest verified"; the painted file status still reads "Loaded firmware.mac (S19+MAC)"

S19TuiApp.action_load_project
req: R-TUI-013
in: S19TuiApp self
out: None
func: opens the Load project dialog with the work-area folders
module: s19_app/tui/app.py
modify: [Interface: modal dialog] (replace)
examples: (U2.4) listed projects [`P1`, `P2`, `patches`]

LoadProjectScreen.on_button_pressed
req: R-TUI-013, LLR-015.2 (batch-02)
in: Button.Pressed event
out: None
func: Load dismisses with the name of the highlighted project
module: s19_app/tui/screens.py
modify: [Interface: modal dialog] (replace)
examples: (U2.4) `P1` highlighted, `Load` clicked → dismiss value `Label()`; log "Project not found: Label()"
examples: (U2.5) `P1` highlighted, `enter` on the list → dismiss value none; the dialog stays open
examples: (U6.3) `escape` → still `LoadProjectScreen`

S19TuiApp._handle_load_project
req: R-TUI-013, R-PROJ-002, LLR-005.6
in: S19TuiApp self; str? name
out: None
func: opens the active variant of the named project and its MAC, and reports the project load
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.current_project] (replace); [Interface: status log] (append)
examples: (U2.6) direct call with "P1" (the dialog cannot send it) → "Loaded project 'P1' -> firmware.s19 + firmware.mac"; context "P1:firmware (1/2)"
examples: (U2.7) "P2" over P1 → "Loaded project 'P2' -> prg.s19"; context "P2  |  firmware.a2l" (the A2L of P1)

S19TuiApp._apply_unload
req: to trace (unload feature; no R or LLR id found for `U`)
in: S19TuiApp self; str kind
out: None
func: removes one artifact or all artifacts from the session and repaints the views
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.current_file] (clear); [Interface: status log] (append)
examples: (U2.2) `U` → "Unloaded all artifacts."; no question; the project stays: context "P1  |  (none)"

S19TuiApp._sync_loaded_file_to_project
req: R-PROJ-002
in: S19TuiApp self
out: None
func: copies a newly loaded data file into the active project as a variant
module: s19_app/tui/app.py
modify: [I/O: project folder] (append); [Interface: status log] (append)
examples: (U2.3) after `U`, a loose load of `prg.s19` → "Added variant 'prg' to project 'P1'"; P1 now holds `prg.s19`

S19TuiApp.on_patch_editor_panel_action_requested
req: LLR-003.2, LLR-002.7, LLR-002.8 (batch-07)
in: S19TuiApp self; PatchEditorPanel.ActionRequested event
out: None
func: runs one Patch Editor action on the change service and repaints the rows. Apply changes the in-memory image and offers the save-back
module: s19_app/tui/app.py
modify: [Data: ChangeService.document] (replace); [Data: S19TuiApp.current_file] (replace); [Interface: status log] (append)
examples: (U3.2) Apply → "Apply: 1 applied, 0 skipped, 0 blocked"; image `DE AD BE EF` at `0x8000007C`; file status still "Loaded firmware.s19 (S19 only)"
examples: (U3.6) an entry at `0x80000080` → "Apply: 0 applied, 1 skipped, 0 blocked"; the save-back row stays hidden

parse_new_bytes
req: LLR-001.2 (batch-07), F-Q-04 (batch-07)
in: str bytes_text
out: list[int] values
func: reads the Bytes field: each token is a Python integer literal (decimal or `0x`), else a hex byte
module: s19_app/tui/services/change_service.py
examples: (U5.7) "11 22" → [`0B`, `16`]
examples: (U5.7) "10 1A 08" → [`0A`, `1A`, `08`]: three bases rules in one run
examples: (U3.9) probe Bytes field 11 22 → ledger row "0x8000007C | 0B 16"

ChangeService.load_text
req: LLR-014.2 (batch-13), LLR-001.2 (batch-07)
in: ChangeService self; str text
out: ChangeResult result
func: replaces the document from a pasted JSON change set (wire grammar: two-hex-digit tokens)
module: s19_app/tui/services/change_service.py
modify: [Data: ChangeService.document] (replace)
examples: (U5.7) paste JSON with bytes 11 22 → entries [(`0x8000007c`, "11 22")]

before_after_card_text
req: LLR-144.8 (batch-97), LLR-080.3 (batch-48)
in: int? address; Sequence[int?]? before; Sequence[int] after; int per_row = 8; Sequence[int?] lead = (); Sequence[int?] trail = (); int row_cap = STRIP_ROW_CAP
out: Text strip
func: paints the before and after bytes of one entry and a count of changed bytes; an unmapped byte counts as changed
module: s19_app/tui/screens_directionb.py
examples: (U3.1) before the apply → "was    38 39 3A 3B 3C 3D 3E 3F", "now    38 39 3A 3B DE AD BE EF", "4 B @ 0x8000007C · 4 changed"
examples: (U3.2) after the apply → "was    38 39 3A 3B DE AD BE EF", "· 0 changed": the card reads the patched image as was
examples: (U3.6) an entry outside the image → "2 B @ 0x80000080 · 2 changed" while the ledger says "outside" and Apply says "1 skipped"

S19TuiApp.action_patch_undo
req: R-TUI-057, LLR-068a.2 (batch-40)
in: S19TuiApp self
out: None
func: restores the previous change set when the Patch Editor is active and the document is paste-authored
module: s19_app/tui/app.py
modify: [Data: ChangeService.document] (replace)
examples: (U3.4) `ctrl+z` after Apply → table `[]`, card "No entry yet: Add one or Load a file."; no log line; image still `DE AD BE EF` (integrity H-4)

S19TuiApp.on_patch_editor_panel_save_back_decision
req: LLR-002.7 (batch-07), R-HEX-VERIFY-001
in: S19TuiApp self; PatchEditorPanel.SaveBackDecision event
out: None
func: writes the in-memory image under the typed name, verifies it, and offers the before/after report
module: s19_app/tui/app.py
modify: [I/O: patched image file] (append); [Interface: status log] (append)
examples: (U3.3) Decline → "Patch Editor: save-back declined"; the image stays patched; nothing on screen says so
examples: (U3.7) Confirm → "Saved + verified: firmware-patched.s19"; an independent read of the file gives `DE AD BE EF` at `0x8000007C`, the undone entry (integrity H-4)

FlowExecutionPanel.render_run
req: LLR-147.3, LLR-147.5 (batch-97), LLR-020.1 (batch-94)
in: FlowExecutionPanel self; ChainSetRunRecord record
out: None
func: paints each lane head, card and cable from the run record, and the run log
module: s19_app/tui/flow_screens.py
modify: [Interface: Flow Execution lanes] (replace); [Interface: run log] (replace)
examples: (U4.1) lane `outside_chain` → head "▓ outside_chain · done · … · wrote out_outside.s19", card "outside.json / → image ¦ ▓ done" (record: patch `ok`, "applied 0 entries"; integrity H-2/H-10)
examples: (U4.1) lane `malformed_chain` (its change doc is not JSON) → "▓ malformed_chain · done"

FlowExecutionPanel._paint_log
req: LLR-147.8 (batch-97), design D "Run log"
in: FlowExecutionPanel self
out: None
func: paints at most 8 log lines; above that, one line points to the run report
module: s19_app/tui/flow_screens.py
modify: [Interface: run log] (replace)
examples: (U4.2) → "… 3 earlier lines — the full log is in the run report"; the two chain-set reports hold only the ledger and the input provenance (`0` log lines); no line on screen names the report path

S19TuiApp.on_flow_execution_panel_external_step_confirmed
req: LLR-147.13, LLR-147.10 (batch-97)
in: S19TuiApp self; FlowExecutionPanel.ExternalStepConfirmed event
out: None
func: re-runs the confirmed lane from its external step and hands the record to the panel
module: s19_app/tui/app.py
inner: FlowExecutionPanel.apply_confirmed_run
modify: [Interface: status log] (append)
examples: (U4.2) Confirm with no evidence files → "flash_chain failed at block 3/4 — log 'flash_log.txt' does not exist - … Run re-runs the set."; lane "✗ flash_chain · failed"; Confirm hidden
examples: (U4.3) evidence written, then `c` → "c: no lane is waiting for confirmation."

CrcDesignerPanel._coverage_preview_text
req: LLR-V6.2, LLR-V7.1 (batch-58)
in: CrcDesignerPanel self; CrcAlgorithm algo
out: str preview
func: computes the coverage CRC of the current target for both gap policies over the loaded image
module: s19_app/tui/crc_designer_view.py
examples: (U5.1) `prg.s19` loaded, no field changed → "Load an image to preview coverage CRCs over real bytes."
examples: (U5.2) range "20000-30000" (no bytes) → "concat: 0x00000000", "fill:   0x00000000"; warnings "✓ none"
examples: (U5.3) case_02 loaded over case_01 → the same "0x6EC3F848" as for case_01; a forced recompute gives "0x00000000"

S19TuiApp._check_items_to_document
req: LLR-009.1 (batch-94)
in: S19TuiApp self; Sequence[dict] items
out: tuple[ChangeDocument, int] documentAndSkipped
func: builds the check document; the expected bytes of each field are the bytes of the current in-memory image
module: s19_app/tui/app.py
examples: (U5.5) a field at `0x8000007C`, size 4 (probe input), after an unsaved Patch Editor apply → written spec "bytes": "DE AD BE EF"

S19TuiApp.on_check_editor_panel_action_requested
req: LLR-009.1, LLR-009.2 (batch-94)
in: S19TuiApp self; CheckEditorPanel.ActionRequested event
out: None
func: writes the check spec, or runs it against the current image and paints one verdict row per field
module: s19_app/tui/app.py
inner: S19TuiApp._check_items_to_document
modify: [I/O: check spec file] (append); [Interface: status log] (append)
examples: (U5.4) Validate on the clean image → "Checks: 1 passed, 0 failed, 0 uncheckable"
examples: (U5.5) Validate on the patched, unsaved image → "Checks: 1 passed, 0 failed, 0 uncheckable"; Write → "Check Editor: wrote spec.chk.json (1 fields, kind=check)."

## Entities

[Data: S19TuiApp.current_file]
in: LoadedFile?
desc: the image, MAC and A2L of the session. The Patch Editor apply changes its `mem_map` in place
sequence:
  loadOverPatch: on_patch_editor_panel_action_requested (apply) → _apply_prepared_load wins (no question)
  checkSpec: on_patch_editor_panel_action_requested (apply) wins → _check_items_to_document reads the patched bytes

[Data: S19TuiApp.current_project]
in: str?
desc: the active project name and folder. `_apply_unload("all")` does not clear it

[Data: ChangeService.document]
in: ChangeDocument
desc: the Patch Editor change set. A new image load does not reset it

[Data: App.focused]
in: Widget?
desc: the widget that receives the keys. App single-key bindings fire only when no focused widget binds the same key
sequence:
  fileLoad: _apply_prepared_load → watch_current_file → SplitJoinWindow.refresh_window wins (focus on hidden `sje_table`) → user key (!)

[I/O: workarea temp]
in: Path
desc: `<workarea>/temp`, where Load file puts each work copy

[I/O: project folder]
in: Path
desc: `<workarea>/<project>/`

[I/O: patched image file]
in: Path
desc: the save-back output in the project folder or the work-area root

[I/O: check spec file]
in: Path
desc: `<workarea>/patches/<name>.chk.json`

[Interface: modal dialog]
in: str
desc: LoadFileScreen, SaveProjectScreen, LoadProjectScreen. None of them binds `escape`

[Interface: Patch Editor card]
in: Text
desc: the before/after hex strip in the Patch Editor inspector

[Interface: CRC coverage preview]
in: str
desc: `#crc_coverage_preview` in the CRC Designer

[Interface: status log]
in: str
desc: the four log lines under the status line (`#log_line_1..4`)

[Interface: file status line]
in: str
desc: `#status_text`, the first status line, for file state only

[Interface: Workarea Files list]
in: str
desc: `#files_list` in the Workspace left pane

[Interface: Flow Execution lanes]
in: str
desc: lane heads, cards and cables of `#fx_panel`

[Interface: run log]
in: str
desc: `#fx_log`, at most 8 lines

## Edges

LoadFileScreen.on_button_pressed ──▶ S19TuiApp._load_path_from_user_input.path
S19TuiApp._load_path_from_user_input ──▶ S19TuiApp.load_from_path.path
S19TuiApp.load_from_path ──▶ copy_into_workarea.source
S19TuiApp.load_from_path ──▶ copy_into_workarea.destination
copy_into_workarea.copied ──▶ S19TuiApp.load_from_path
S19TuiApp.load_from_path ──▶ S19TuiApp.refresh_files
S19TuiApp.load_from_path ──▶ S19TuiApp._apply_prepared_load.path
[Data: S19TuiApp.current_file] ──▶ S19TuiApp.watch_current_file
S19TuiApp.watch_current_file ──▶ SplitJoinWindow.refresh_window
[Interface: Workarea Files list] ──▶ S19TuiApp._load_from_item.item
S19TuiApp._load_from_item ──▶ S19TuiApp.load_from_path.path
SaveProjectScreen.on_button_pressed ──▶ S19TuiApp._handle_save_dialog.payload
[Data: S19TuiApp.current_file] ──▶ S19TuiApp._handle_save_dialog
[Data: App.focused] ──▶ S19TuiApp.action_load_project
when: App.focused binds no `p`
LoadProjectScreen.on_button_pressed ──▶ S19TuiApp._handle_load_project.name
S19TuiApp._handle_load_project ──▶ S19TuiApp._apply_prepared_load.path
[Data: S19TuiApp.current_project] ──▶ S19TuiApp._sync_loaded_file_to_project
S19TuiApp._apply_prepared_load ──▶ S19TuiApp._sync_loaded_file_to_project
S19TuiApp.on_patch_editor_panel_action_requested ──▶ parse_new_bytes.bytes_text
parse_new_bytes.values ──▶ S19TuiApp.on_patch_editor_panel_action_requested
S19TuiApp.on_patch_editor_panel_action_requested ──▶ before_after_card_text.before
S19TuiApp.on_patch_editor_panel_action_requested ──▶ before_after_card_text.after
S19TuiApp.on_patch_editor_panel_action_requested ──▶ before_after_card_text.address
[Data: S19TuiApp.current_file] ──▶ before_after_card_text.before
[Data: S19TuiApp.current_file] ──▶ S19TuiApp.on_patch_editor_panel_save_back_decision
FlowExecutionPanel.render_run ──▶ FlowExecutionPanel._paint_log
[Data: S19TuiApp.current_file] ──▶ CrcDesignerPanel._coverage_preview_text
S19TuiApp.on_check_editor_panel_action_requested ──▶ S19TuiApp._check_items_to_document.items
[Data: S19TuiApp.current_file] ──▶ S19TuiApp._check_items_to_document
S19TuiApp.load_from_path ──▶ S19TuiApp._apply_prepared_load.prepared
ChangeService.load_text.result ──▶ S19TuiApp.on_patch_editor_panel_action_requested
before_after_card_text.strip ──▶ [Interface: Patch Editor card]
CrcDesignerPanel._coverage_preview_text.preview ──▶ [Interface: CRC coverage preview]
S19TuiApp._check_items_to_document.documentAndSkipped ──▶ S19TuiApp.on_check_editor_panel_action_requested
FlowExecutionPanel.render_run ──▶ [Interface: Flow Execution lanes]

## Boundary

[Outside: Load button] ──▶ LoadFileScreen.on_button_pressed.event
[Outside: Save button] ──▶ SaveProjectScreen.on_button_pressed.event
[Outside: key p] ──▶ S19TuiApp.action_load_project
[Outside: Load project button] ──▶ LoadProjectScreen.on_button_pressed.event
[Outside: key U] ──▶ S19TuiApp._apply_unload.kind
[Outside: Patch Editor button] ──▶ S19TuiApp.on_patch_editor_panel_action_requested.event
[Outside: paste parse button] ──▶ ChangeService.load_text.text
[Outside: key ctrl+z] ──▶ S19TuiApp.action_patch_undo
[Outside: save-back buttons] ──▶ S19TuiApp.on_patch_editor_panel_save_back_decision.event
[Outside: Run run_chain_set] ──▶ FlowExecutionPanel.render_run.record
[Outside: Confirm or key c] ──▶ S19TuiApp.on_flow_execution_panel_external_step_confirmed.event
[Outside: CRC field change] ──▶ CrcDesignerPanel._coverage_preview_text.algo
[Outside: Check Editor button] ──▶ S19TuiApp.on_check_editor_panel_action_requested.event

## Findings

The full table, with the requirement status and the known ids, is in `AUDIT-codewire-ui-2026-10-23.md` §2. The ids are `CW-U-n`.

CW-U-1
anchor: LoadProjectScreen.on_button_pressed
what: the dialog sends `str(Label)` = "Label()" as the project name. `Label` has no `.text` in Textual 8.2.8
evidence: (U2.4) "Project not found: Label()"; (U2.5) `enter` sends nothing

CW-U-2
anchor: SplitJoinWindow.refresh_window
what: every load moves the focus to the table of the hidden Split/Join/Export window; the next single-key commands go to that window
evidence: (U6.2) focused `_SegTable sje_table`; `p` opens nothing; `k` "manual: dropped aeek"

CW-U-3
anchor: S19TuiApp.refresh_files
what: the Workarea Files list reads the work-area root; every work copy is in `temp`, so the list is always empty
evidence: (U1.9) list `[]`, temp [`firmware.s19`, `firmware_1.s19`]

CW-U-4
anchor: parse_new_bytes
what: the Bytes field reads "11" as decimal 11; the paste JSON and the change files read "11" as 0x11
evidence: (U5.7) [`0B`, `16`] vs "11 22"

CW-U-5
anchor: S19TuiApp._apply_prepared_load
what: a load over an image with an applied, unsaved patch asks nothing and says nothing
evidence: (U3.9) "Loaded firmware_1.s19 (S19 only)"

CW-U-6
anchor: before_after_card_text
what: after Apply the card shows the patched bytes as "was" and "0 changed"; for an outside entry it shows "2 changed"
evidence: (U3.2), (U3.6)

CW-U-7
anchor: FlowExecutionPanel._paint_log
what: the log points to a report that has no log lines and whose path the screen never shows
evidence: (U4.2)

CW-U-8
anchor: CrcDesignerPanel._coverage_preview_text
what: the preview does not recompute on a load; it shows the CRC of the previous image or the no-image note
evidence: (U5.1), (U5.3)

CW-U-9
anchor: S19TuiApp._check_items_to_document
what: the expected bytes come from the current image, so Validate always passes and Write can capture unsaved patched bytes
evidence: (U5.5)
