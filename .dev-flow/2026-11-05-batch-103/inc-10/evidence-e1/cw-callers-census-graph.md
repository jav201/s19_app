# Code-Wire callers census — batch-103 Inc 10 E1 (throwaway context graph; not the E2 prototype)

Context nodes Inc 10 changes or reads; contracts copied from the e07fb00 signatures.

## Nodes

PatchEditorPanel.SaveBackDecision.__init__
req: to trace
in: Optional[str] filename; int bytes_per_line = 32
out: None
func: unchanged (census context; e07fb00 s19_app/tui/screens_directionb.py:4675)
module: s19_app/tui/screens_directionb.py

PatchEditorPanel.compose
req: to trace
in: 
out: ComposeResult result
func: unchanged (census context; e07fb00 s19_app/tui/screens_directionb.py:4930)
module: s19_app/tui/screens_directionb.py

PatchEditorPanel._show_tab
req: to trace
in: str chip_id
out: None
func: unchanged (census context; e07fb00 s19_app/tui/screens_directionb.py:5637)
module: s19_app/tui/screens_directionb.py

PatchEditorPanel.on_button_pressed
req: to trace
in: Button.Pressed event
out: None
func: unchanged (census context; e07fb00 s19_app/tui/screens_directionb.py:5896)
module: s19_app/tui/screens_directionb.py

PatchEditorPanel.show_save_prompt
req: to trace
in: str suggestion
out: None
func: unchanged (census context; e07fb00 s19_app/tui/screens_directionb.py:6448)
module: s19_app/tui/screens_directionb.py

PatchEditorPanel.hide_save_prompt
req: to trace
in: 
out: None
func: unchanged (census context; e07fb00 s19_app/tui/screens_directionb.py:6471)
module: s19_app/tui/screens_directionb.py

_synth_s0_header_from_filename
req: to trace
in: str filename
out: bytes result
func: unchanged (census context; e07fb00 s19_app/tui/app.py:662)
module: s19_app/tui/app.py

S19TuiApp.on_patch_editor_panel_action_requested
req: to trace
in: PatchEditorPanel.ActionRequested event
out: None
func: unchanged (census context; e07fb00 s19_app/tui/app.py:4734)
module: s19_app/tui/app.py

S19TuiApp.on_patch_editor_panel_save_back_decision
req: to trace
in: PatchEditorPanel.SaveBackDecision event
out: None
func: unchanged (census context; e07fb00 s19_app/tui/app.py:4958)
module: s19_app/tui/app.py

S19TuiApp._hide_replaced_document_controls
req: to trace
in: PatchEditorPanel panel
out: None
func: unchanged (census context; e07fb00 s19_app/tui/app.py:5173)
module: s19_app/tui/app.py

render_patched_image
req: to trace
in: Dict[int, int] mem_map; Sequence[Tuple[int, int]] ranges; str source_kind; int bytes_per_line = 32; bytes | None s0_header = None
out: Optional[bytes] result
func: unchanged (census context; e07fb00 s19_app/tui/changes/apply.py:629)
module: s19_app/tui/changes/apply.py

save_patched_image
req: to trace
in: Dict[int, int] mem_map; Sequence[Tuple[int, int]] ranges; Path dest_dir; str filename; str source_kind; int bytes_per_line = 32; bytes | None s0_header = None; Optional[Path] workarea_root = None; Optional[Callable[[PlacementResult], None]] on_placed = None
out: Tuple[Optional[Path], List[ValidationIssue]] result
func: unchanged (census context; e07fb00 s19_app/tui/changes/apply.py:686)
module: s19_app/tui/changes/apply.py

ChangeService.emit_and_verify
req: to trace
in: Dict[int, int] image; Sequence[Tuple[int, int]] ranges; Path dest_dir; str filename; str source_kind; int bytes_per_line = 32; bytes | None s0_header = None; Optional[Path] source_image_path = None; Optional[ChangeSummary] summary = None; Optional[Path] workarea_root = None; Optional[Callable[[PlacementResult], None]] on_placed = None
out: ChangeActionResult result
func: unchanged (census context; e07fb00 s19_app/tui/services/change_service.py:2375)
module: s19_app/tui/services/change_service.py

ChangeService.save_patched
req: to trace
in: Dict[int, int] mem_map; Sequence[Tuple[int, int]] ranges; Path dest_dir; str filename; str source_kind; int bytes_per_line = 32; bytes | None s0_header = None; Optional[Path] source_image_path = None; Optional[Sequence[dict]] mac_records = None; Optional[Sequence[dict]] a2l_tags = None; Optional[Path] workarea_root = None
out: ChangeActionResult result
func: unchanged (census context; e07fb00 s19_app/tui/services/change_service.py:2481)
module: s19_app/tui/services/change_service.py
