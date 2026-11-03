# Code-Wire — Inc 1 — Clipboard OS copy/paste

Graph of the changing clipboard slice. Requirements: `01-requirements.md`. Tests: `02-test-cases.md`.

## Nodes

write_os_clipboard
req: R-B102-CLIP-002, R-B102-CLIP-003, R-B102-CLIP-004, R-B102-CLIP-005
in: str text; tuple strategies = None
out: bool written
func: new. Caps `text` at 65,536 characters and writes it through the ordered Win32 → Tk → PowerShell cascade. Returns True on the first successful strategy and False when every strategy fails; a strategy exception means failure of that layer and the cascade continues.
module: s19_app/tui/os_clipboard_input.py
modify: [Data: OS clipboard] (replace)
examples: (TC-B102-02) text `firmware.a2l`, strategies [win32: True] → written True; [Data: OS clipboard] receives `firmware.a2l`
examples: (TC-B102-06) text `payload`, strategies [win32: False, tk: False, powershell: False] → written False; [Data: App.clipboard] receives `payload`
examples: (TC-B102-05) text `payload`, strategies [win32: False, tk: False, powershell: slow-success] → written True

_write_via_ctypes
req: R-B102-CLIP-002, R-B102-CLIP-004
in: str text
out: bool written
func: new. On Windows, allocates a movable UTF-16 buffer, opens the clipboard, empties it and sets `CF_UNICODETEXT`; ownership of the global buffer passes to the system on success. Returns False off Windows or on any Win32 failure and frees the allocated buffer only on that failure path.
module: s19_app/tui/os_clipboard_input.py
modify: [Data: OS clipboard] (replace)
examples: (TC-B102-02, non-win32) text `firmware.a2l` → written False; [Data: OS clipboard] unchanged
examples: (TC-B102-06, win32-fake) text `payload` with OpenClipboard false on every retry → written False

_write_via_tk
req: R-B102-CLIP-002, R-B102-CLIP-004
in: str text
out: bool written
func: new. Clears and appends `text` on the existing process-wide Tk root. This layer is the rescue after Win32; it does not create a root off the UI thread. Returns False when Tk is unavailable or the write raises.
module: s19_app/tui/os_clipboard_input.py
modify: [Data: OS clipboard] (replace)
examples: (TC-B102-02) text `firmware.a2l` on a fake Tk root → written True; fake root received `clipboard_clear()` then `clipboard_append("firmware.a2l")`
examples: (TC-B102-06) text `payload` with Tk unavailable → written False

_write_via_powershell
req: R-B102-CLIP-004, R-B102-CLIP-005
in: str text
out: bool written
func: new. On Windows, runs a static Set-Clipboard command with a 2.0 s timeout and passes UTF-8 text through stdin; the copied text is never interpolated into the command. Requests a hidden window and returns True only for exit code 0. Returns False off Windows, on timeout, on missing PowerShell or on a non-zero exit.
module: s19_app/tui/os_clipboard_input.py
modify: [Data: OS clipboard] (replace)
examples: (TC-B102-05) text `payload`, subprocess fake records timeout `2.0` and exit 0 → written True
examples: (TC-B102-06) text `payload`, simulated PowerShell exit 1 → written False

OsClipboardInput.action_copy
req: R-B102-CLIP-002, R-B102-CLIP-004
in: OsClipboardInput self
out: None
func: changed async override. Reads `selected_text`; when empty raises Textual's SkipAction. Otherwise mirrors it to App.clipboard, primes the Tk root, runs `write_os_clipboard` in the executor, and leaves `value` and selection unchanged. On OS write failure paints the exact warning `Clipboard write failed — copied inside the app only.`
module: s19_app/tui/os_clipboard_input.py
modify: [Data: OS clipboard] (replace); [Data: App.clipboard] (replace)
examples: (TC-B102-02) selection `firmware.a2l` → None; input value is unchanged; OS payload and App.clipboard are `firmware.a2l`
examples: (TC-B102-06) selection `payload`, all OS writes fail → None; App.clipboard is `payload`; latest notification is `Clipboard write failed — copied inside the app only.`

OsClipboardInput.action_cut
req: R-B102-CLIP-003, R-B102-CLIP-004
in: OsClipboardInput self
out: None
func: changed async override. Empty selection raises SkipAction. Otherwise captures the selected text, removes it from the input, mirrors it to App.clipboard, primes Tk, writes OS text in the executor, and on OS failure paints the exact write warning. The local cut remains even if every OS layer fails.
module: s19_app/tui/os_clipboard_input.py
modify: [Data: OS clipboard] (replace); [Data: App.clipboard] (replace); [Data: focused input.value] (replace)
examples: (TC-B102-03) value before `DE AD BE EF`, selection `DE AD` → None; OS payload is `DE AD`; value is ` BE EF`
examples: (TC-B102-06) selection `payload`, OS writes fail → None; App.clipboard is `payload`; latest warning is `Clipboard write failed — copied inside the app only.`

CappedTextArea.action_paste
req: R-B102-CLIP-001, R-B102-CLIP-005, R-B102-CLIP-006
in: CappedTextArea self
out: None
func: changed async override. Returns without mutation for a read-only buffer. Primes Tk, runs the same OS-read cascade as `OsClipboardInput.action_paste` in the executor, caps the result at 65,536 characters, falls back to App.clipboard, and inserts via Textual's keyboard replacement path. Empty total result selects the whole buffer and paints the existing read warning.
module: s19_app/tui/capped_text_area.py
modify: [Data: CappedTextArea.document] (replace); [Data: App.clipboard] (read)
examples: (TC-B102-01) OS clipboard `{"entries": []}` → None; buffer text contains `{"entries": []}`
examples: (TC-B102-04) subprocess fake makes the real PowerShell read succeed with `OK_FROM_PS` → None; buffer text contains `OK_FROM_PS`
examples: (TC-B102-07) OS read None and App.clipboard empty → None; buffer text unchanged and selected; warning is `Clipboard read failed — try Ctrl+Shift+V or type the path manually.`

CappedTextArea.action_copy
req: R-B102-CLIP-002, R-B102-CLIP-004
in: CappedTextArea self
out: None
func: changed async override. Mirrors `OsClipboardInput.action_copy` for the selected document text: empty selection raises SkipAction; otherwise internal mirror, Tk prime, OS write in the executor, no document mutation, exact write warning on total failure.
module: s19_app/tui/capped_text_area.py
modify: [Data: OS clipboard] (replace); [Data: App.clipboard] (replace)
examples: (TC-B102-02) selection `DE AD` → None; OS payload and App.clipboard are `DE AD`; document text unchanged
examples: (TC-B102-06) selection `payload`, all OS writes fail → None; App.clipboard is `payload`; latest warning is `Clipboard write failed — copied inside the app only.`

CappedTextArea.action_cut
req: R-B102-CLIP-003, R-B102-CLIP-004
in: CappedTextArea self
out: None
func: changed async override. Returns without mutation for a read-only buffer. Deletes the selection through Textual's keyboard path, or the cursor line through `_delete_cursor_line()` when no selection exists; captures the replaced text, mirrors it internally, primes Tk, writes OS text in the executor, and on OS failure paints the exact write warning.
module: s19_app/tui/capped_text_area.py
modify: [Data: OS clipboard] (replace); [Data: App.clipboard] (replace); [Data: CappedTextArea.document] (replace)
examples: (TC-B102-03) document `DE AD BE EF`, selection `DE AD` → None; OS payload is `DE AD`; document text is ` BE EF`
examples: (TC-B102-08) no selection, cursor line `line_to_cut` → None; document no longer contains that line; OS payload is `line_to_cut`
examples: (TC-B102-06) selection `payload`, all OS writes fail → None; App.clipboard is `payload`; latest warning is `Clipboard write failed — copied inside the app only.`

read_os_clipboard
req: R-B102-CLIP-001, R-B102-CLIP-005, R-B102-CLIP-006
in: tuple strategies = None
out: str? text
func: changed timeout budget. The existing read cascade remains Tk → Win32 → PowerShell, but the PowerShell rescue timeout is 2.0 s so a cold Windows PowerShell start can succeed; every other contract is unchanged.
module: s19_app/tui/os_clipboard_input.py
examples: (TC-B102-04) subprocess fake makes the real PowerShell read succeed with `OK_FROM_PS` → text `OK_FROM_PS`
examples: (TC-B102-07) strategies [tk: None, win32: None, powershell: None] and App.clipboard empty → text None

## Entities

[Data: OS clipboard]
in: str
desc: the operating-system clipboard shared with other Windows applications.
sequence:
  copy: write_os_clipboard wins → read_os_clipboard
  cut: write_os_clipboard wins → CappedTextArea.action_cut

[Data: App.clipboard]
in: str
desc: Textual's in-process clipboard mirror and fallback.

[Data: focused input.value]
in: str
desc: the current single-line input text; copy must not change it, cut must remove only the selection.

## Edges

[Data: OS clipboard] ──▶ read_os_clipboard
write_os_clipboard ──▶ [Data: OS clipboard]
OsClipboardInput.action_copy ──▶ [Data: App.clipboard]
CappedTextArea.action_copy ──▶ [Data: App.clipboard]

## Findings

finding F-B102-1 PowerShell cold start exceeds the existing 0.5 s paste budget
anchor: _read_via_powershell
seen: operator report on Windows 11/PowerShell: paste intermittently does nothing in Workspace, A2L and Load
cause: the rescue layer is capped at 500 ms before Get-Clipboard can finish a cold process start
decision: enlarge the rescue budget to 2.0 s and keep both read and write off the UI event loop

finding F-B102-2 copy only reaches Textual's OSC52/internal clipboard
anchor: OsClipboardInput.action_copy
seen: text copied in the TUI is unavailable in external Windows applications
cause: the inherited Textual action writes App.clipboard/OSC52, and the Windows driver path does not reliably deliver an OS clipboard write
decision: implement an OS write cascade for Input and CappedTextArea selections

finding F-B102-3 the original write cascade would have preferred a transient Tk write
anchor: write_os_clipboard
seen: E3 review noted that Tk clipboard content can vanish when the process-wide root is destroyed at exit
cause: Tk owns clipboard content until another app takes ownership, and the singleton root destruction at process exit releases it
decision: try Win32 first so successful writes survive app exit; keep Tk as the isolated-process fallback
