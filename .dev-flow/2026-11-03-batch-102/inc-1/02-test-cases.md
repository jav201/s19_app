# E1 test cases — Inc 1 — Clipboard OS copy/paste

| TC | Objective | Class | Preconditions | Inputs | Expected result | Covers | Mutant control | Status |
|---|---|---|---|---|---|---|---|---|
| TC-B102-01 | Verify that activating paste inserts the current OS clipboard text in representative single-line inputs and the patch paste buffer. | normal | A representative widget is mounted; `read_os_clipboard` is replaced by a fake returning `C:\tmp\firmware.s19`. | Activate paste on Load path, A2L filter and Patch paste buffer. | Each widget contains `C:\tmp\firmware.s19`; payload is capped at 65,536 chars; internal clipboard is not consulted first. | R-B102-CLIP-001, full | Paste reads only `App.clipboard`. | not_run |
| TC-B102-02 | Verify that activating copy writes the selected text to the OS clipboard without changing the input. | normal | An `OsClipboardInput` has selection around `firmware.a2l`; OS write strategies are fakes that record the payload. | Activate copy. | Recorded payload is exactly `firmware.a2l`; input value and selection remain unchanged; Textual internal clipboard also holds the text. | R-B102-CLIP-002, full | Copy writes only the internal clipboard. | not_run |
| TC-B102-03 | Verify that activating cut writes OS text and removes it from both widget classes. | normal | Each widget class has a selected substring `DE AD`; OS write strategies are fakes. | Activate cut. | Recorded payload is `DE AD`; widget text no longer contains the selected substring. | R-B102-CLIP-003, full | Cut deletes without OS write. | not_run |
| TC-B102-04 | Verify that a Windows PowerShell rescue read is allowed to complete within the enlarged budget. | robustness | Tk and Win32 strategies return `None`; PowerShell strategy sleeps 1.5 s then returns `OK_FROM_PS`. | Call `read_os_clipboard`. | Returned value is `OK_FROM_PS`; total timeout is at least 2.0 s. | R-B102-CLIP-005, full | Timeout remains 0.5 s; returned value is `None`. | not_run |
| TC-B102-05 | Verify that a Windows PowerShell rescue write is allowed to complete within the enlarged budget. | robustness | Tk and Win32 write strategies return `False`; PowerShell writer sleeps 1.5 s then returns `True`. | Call `write_os_clipboard("payload")`. | Returned value is `True`; timeout budget is at least 2.0 s. | R-B102-CLIP-005, full | Timeout remains 0.5 s; returned value is `False`. | not_run |
| TC-B102-06 | Verify that total copy/cut failure degrades to internal clipboard with the exact warning. | robustness | Every OS write strategy returns failure; the widget has selected text. | Activate copy and then cut on each widget class. | Internal clipboard holds the selected text; painted warning is exactly `Clipboard write failed — copied inside the app only.` | R-B102-CLIP-004, full | Omit the warning. | not_run |
| TC-B102-07 | Verify the existing total-paste failure feedback contract. | robustness | OS read returns `None`; `App.clipboard` is empty; the field contains old text. | Activate paste. | Current text is selected and the exact read warning is painted. | R-B102-CLIP-006, full | Remove `select_all()` or change the warning. | not_run |

## Superficies de aceptación

- Load: `#load_path`.
- Workspace/A2L: `#a2l_tags_filter_input` y/o `#a2l_tag_find_input`.
- Patch paste: `#patch_paste_text`.
- Check Editor entra en el censo universal existente y se cubre de forma representativa por el mismo componente.
