# Code-Wire callers census — batch-103 Inc 1b E1 (throwaway context graph; not the E2 prototype)

Context nodes Inc 1b reads or overrides beside; contracts copied from the e07fb00 signatures.

## Nodes

S19TuiApp.on_mount
req: to trace
in: 
out: None
func: unchanged (census context; e07fb00 s19_app/tui/app.py:8643)
module: s19_app/tui/app.py

S19TuiApp.update_workspace_stats
req: to trace
in: 
out: None
func: unchanged (census context; e07fb00 s19_app/tui/app.py:19328)
module: s19_app/tui/app.py

S19TuiApp.update_hex_view
req: to trace
in: Optional[int] focus_address = None
out: None
func: unchanged (census context; e07fb00 s19_app/tui/app.py:19619)
module: s19_app/tui/app.py

S19TuiApp.update_alt_hex_view
req: to trace
in: Optional[int] focus_address = None; bool near_top = False; bool reset_scroll = False
out: None
func: unchanged (census context; e07fb00 s19_app/tui/app.py:19693)
module: s19_app/tui/app.py

S19TuiApp.update_mac_hex_view
req: to trace
in: Optional[int] focus_address = None; bool near_top = False; bool reset_scroll = False
out: None
func: unchanged (census context; e07fb00 s19_app/tui/app.py:19763)
module: s19_app/tui/app.py

S19TuiApp._update_a2l_summary_buffer
req: to trace
in: 
out: None
func: unchanged (census context; e07fb00 s19_app/tui/app.py:20147)
module: s19_app/tui/app.py

S19TuiApp.update_a2l_tags_view
req: to trace
in: list[dict] tags; Optional[str] empty_message = None
out: None
func: unchanged (census context; e07fb00 s19_app/tui/app.py:20286)
module: s19_app/tui/app.py

PatchEditorPanel.compose
req: to trace
in: 
out: ComposeResult result
func: unchanged (census context; e07fb00 s19_app/tui/screens_directionb.py:4930)
module: s19_app/tui/screens_directionb.py

PatchEditorPanel._show_document
req: to trace
in: 'PatchDocumentView' document
out: None
func: unchanged (census context; e07fb00 s19_app/tui/screens_directionb.py:5743)
module: s19_app/tui/screens_directionb.py

write_os_clipboard
req: to trace
in: str text; Optional[tuple[tuple[str, Callable[[str], bool]], ...]] strategies = None
out: bool result
func: unchanged (census context; e07fb00 s19_app/tui/os_clipboard_input.py:665)
module: s19_app/tui/os_clipboard_input.py

_mirror_and_write_os_clipboard
req: to trace
in: 'App' app; str text
out: None
func: unchanged (census context; e07fb00 s19_app/tui/os_clipboard_input.py:727)
module: s19_app/tui/os_clipboard_input.py

OsClipboardInput.action_copy
req: to trace
in: 
out: None
func: unchanged (census context; e07fb00 s19_app/tui/os_clipboard_input.py:839)
module: s19_app/tui/os_clipboard_input.py

CappedTextArea.action_copy
req: to trace
in: 
out: None
func: unchanged (census context; e07fb00 s19_app/tui/capped_text_area.py:239)
module: s19_app/tui/capped_text_area.py
