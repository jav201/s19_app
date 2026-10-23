# Code-Wire graph F2: Patch Editor add → apply → undo → apply → save-back → verify (data audit, reverse)

> Format B, Code-Wire v2.6. Reverse direction from `s19_app` `9793fcd`. Node name = code qualname.
> Thread T2: `cwaudit/test_t2_patch_editor.py` (recorded: `trace-t2.json`). Data: `examples/case_02_gaps_and_patch_targets/firmware.s19`; its README names the patch targets `0x80010080` "DE AD BE EF" and `0x80010005` text "05182025". The thread types the README bytes, then the hex dump of the README text (`30 35 31 38 32 30 32 35`) into the Bytes field (placeholder "DE AD BE EF").
> The app handler is driven headless. Undo is the body of `action_patch_undo` after its screen gate (`app.py:3615`): `ChangeService.undo`.

## Nodes

S19TuiApp.on_patch_editor_panel_action_requested
req: R-TUI-057, LLR-003.4
in: S19TuiApp self; PatchEditorPanel.ActionRequested event
out: None
func: routes one Patch Editor action to the change service; `apply_doc` passes `current_file.mem_map` to the service and paints the counts
module: s19_app/tui/app.py
modify: [Data: ChangeService.document] (replace)
inner: ChangeService.add_entry, ChangeService.apply
examples: (T2, t2a) event {action "add_entry", address_text "0x80010080", bytes_text "DE AD BE EF"} → None
examples: (T2, t2a) event {action "add_entry", address_text "0x80010005", bytes_text "30 35 31 38 32 30 32 35"} → None

ChangeService.add_entry
req: LLR-003.4, LLR-001.2
in: ChangeService self; str address_text; str value_text; str bytes_text
out: ChangeEntry entry
func: parses the address and the Bytes field, and appends one entry
module: s19_app/tui/services/change_service.py
modify: [Data: ChangeService.document] (append)
inner: parse_new_bytes
examples: (T2, t2a) address_text "0x80010005"; bytes_text "30 35 31 38 32 30 32 35" → entry {address 0x80010005, encoded_bytes [`30`, `35`, `31`, `38`, `32`, `30`, `32`, `35`]} (decimal values 0x1E 0x23 …)

parse_new_bytes
req: LLR-001.2
in: str bytes_text
out: list[int] values
func: one byte per token: base-0 parse first, base-16 only when base-0 fails
module: s19_app/tui/services/change_service.py
examples: (T2, t2b) bytes_text "DE AD 10 20" → values [0xDE, 0xAD, 0xA, 0x14]
examples: (T2, t2b) bytes_text "0F 10 1F 20" → values [0xF, 0xA, 0x1F, 0x14] (one dump, two bases)

ChangeService.apply
req: LLR-003.4, R-CHG-002
in: ChangeService self; Dict[int, int]? mem_map; Sequence[Tuple[int, int]]? ranges; Sequence[dict]? mac_records; Sequence[dict]? a2l_tags; str? variant_id = None
out: ChangeSummary summary
func: applies the owned document to the given map in place and keeps the summary as `last_summary`
module: s19_app/tui/services/change_service.py
modify: mem_map (replace)
inner: apply_change_document
examples: (T2, t2a) entry 0x80010080 DE AD BE EF on case_02 → summary {counts {applied `1`}, entries 1 of 1 {before_bytes [`170`, `187`, `204`, `221`], after_bytes [`222`, `173`, `190`, `239`]}}
examples: (T2, t2a) after the undo, entry 0x80010005 only → summary entries 1 of 1 {address_start `2147549189`, after_bytes [`30`, `35`, `31`, `38`, `32`, `30`, `32`, `35`]}

ChangeService.undo
req: R-TUI-057, LLR-068a.2
in: ChangeService self
out: ChangeDocument document
func: restores the previous document from the history. The image bytes do not change
module: s19_app/tui/services/change_service.py
modify: [Data: ChangeService.document] (replace)
examples: (T2, t2a) two undos after add + apply → document {format "s19app-changeset", entries []}; the image byte at the first target stays DE (read after the call, see t2a-undo in the run log)

S19TuiApp.on_patch_editor_panel_save_back_decision
req: LLR-015.3, R-CHG-003, LLR-038.3
in: S19TuiApp self; PatchEditorPanel.SaveBackDecision event
out: None
func: saves `current_file.mem_map` under the typed name. At 32 bytes/line it passes the source S0 header; at 16 it passes None
module: s19_app/tui/app.py
inner: ChangeService.save_patched
examples: (T2, t2a) event {filename "p16.s19", bytes_per_line `16`} → None
examples: (T2, t2a) event {filename "p32.s19", bytes_per_line `32`} → None

save_patched_image
req: LLR-002.7, LLR-015.3, R-MAN-WRITE-001
in: Dict[int, int] mem_map; Sequence[Tuple[int, int]] ranges; Path dest_dir; str filename; str source_kind; int bytes_per_line = 32; bytes? s0_header = None
out: tuple(Path? saved_path, List[ValidationIssue] issues)
func: emits the map as S19 or HEX, stages it at `temp/<name>`, places it with containment and dedup
module: s19_app/tui/changes/apply.py
modify: [I/O: patched image] (replace)
examples: (T2, t2a) filename "p16.s19"; bytes_per_line `16` → file line 1 "S0030000FC" (empty S0), line 2 "S310000000004341534530325F47415053E7" (S0 text as data at 0x0), "S31580010000444154453D1E231F26201E20233B415338", "S31580010080DEADBEEFEEFF00112233445566778899C7" (undone entry), "S70500000000FA" (entry point 0)
examples: (T2, t2a) filename "p32.s19"; bytes_per_line `32` → file line 1 "S00E00004341534530325F47415053E9"

verify_written_image
req: R-HEX-VERIFY-001
in: Path written_path; Dict[int, int] intended_mem_map; str file_type
out: VerifyResult result
func: re-reads the written file with the repo reader and diffs it against the intended map
module: s19_app/tui/changes/verify.py
examples: (T2, t2a) written_path ".../workarea/p16.s19"; intended_mem_map holds 0x0: 0x43 and 0x80010005: 0x1E → result {status "verified", byte_counts {changed `0`}}

## Entities

[Data: ChangeService.document]
in: ChangeDocument
desc: the owned change document
sequence:
  addEntry: on_patch_editor_panel_action_requested → add_entry wins
  undo: ChangeService.undo wins (the image is not touched)

[Data: S19TuiApp.current_file]
in: LoadedFile?
desc: the loaded image. Apply changes its mem_map in place
sequence:
  apply: on_patch_editor_panel_action_requested → ChangeService.apply wins (mem_map in place)
  undo: ChangeService.undo (no write to mem_map)
  saveBack: on_patch_editor_panel_save_back_decision reads mem_map (!) after the undo, the undone bytes are still there

[I/O: patched image]
in: str
desc: the saved S19 file (`p16.s19`, `p32.s19`)

## Edges

[Outside: Bytes field] ──▶ S19TuiApp.on_patch_editor_panel_action_requested.event
S19TuiApp.on_patch_editor_panel_action_requested ──▶ ChangeService.add_entry.bytes_text
ChangeService.add_entry ──▶ parse_new_bytes.bytes_text
[Data: ChangeService.document] ──▶ ChangeService.apply
[Data: S19TuiApp.current_file] ──▶ ChangeService.apply.mem_map
ChangeService.apply.mem_map ──▶ [Data: S19TuiApp.current_file]
[Data: S19TuiApp.current_file] ──▶ S19TuiApp.on_patch_editor_panel_save_back_decision
S19TuiApp.on_patch_editor_panel_save_back_decision ──▶ save_patched_image.mem_map
save_patched_image.saved_path ──▶ verify_written_image.written_path
S19TuiApp.on_patch_editor_panel_save_back_decision ──▶ verify_written_image.intended_mem_map
save_patched_image ──▶ [I/O: patched image]

## Boundary

[Outside: Bytes field] ──▶ S19TuiApp.on_patch_editor_panel_action_requested
discarded: verify_written_image.result — the status line reads it (Saved + verified)
discarded: ChangeService.undo.document — the panel repaints from it; outside this slice

## Findings

CW-D-4
anchor: parse_new_bytes
what: a token of digits only is decimal; a token with a letter is hex. A hex dump typed or pasted into the Bytes field (placeholder "DE AD BE EF") is mixed-base
evidence: T2 t2b "0F 10 1F 20" → 0F 0A 1F 14; T2 t2a the saved file holds 1E 23 1F 26 20 1E 20 23 at 0x80010005 for the typed 30 35 31 38 32 30 32 35; status "Saved + verified"
consequence: a silent wrong byte in a written image. LLR-001.2 (batch-07) allows decimals in the TUI grammar but does not say how an all-digit token reads. The docstring promises "paste a hex-dump fragment directly"

CW-D-5
anchor: ChangeService.undo
what: undo changes the document, not the image (known I-H-4)
evidence: T2 t2a: entries [] after undo, file still holds DEADBEEF at 0x80010080, verify "verified"

CW-D-6
anchor: S19TuiApp.on_patch_editor_panel_save_back_decision
what: a save-back at 16 bytes/line writes an empty S0 header. LLR-015.2 (TC-215) requires it; the S0 text of the source is lost
evidence: T2 t2a p16.s19 line 1 "S0030000FC" vs p32.s19 "S00E00004341534530325F47415053E9"
consequence: req and code agree; the requirement itself drops data (low)
