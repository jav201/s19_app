# E5 PowerShell transport fix — product only

Edit only `s19_app/tui/os_clipboard_input.py` to close the intentional RED in `tests/test_b103_clipboard_tail.py` (static PowerShell exact transport). Do not edit tests, docs, other source files or git refs. Do not commit.

- Replace `_POWERSHELL_WRITE_COMMAND`: stop `$input | Set-Clipboard`; instead read the entire stdin with `[Console]::In.ReadToEnd()` into a variable and call `[Windows.Clipboard]::SetText($text)`, preserving LF exactly and keeping static argv/stdin. Load `PresentationCore` and use `UTF8Encoding($false)` where relevant.
- In `_read_via_powershell`, replace `Encoding.UTF8` with `UTF8Encoding($false)` and emit through `[Console]::Out.Write((Get-Clipboard -Raw))`, so no BOM or extra newline is appended while preserving the existing plain-text protocol and mocks.
- Update the affected comments/docstrings to the new behavior.

Run `python -m py_compile s19_app/tui/os_clipboard_input.py` and a static assertion that the old `$input | Set-Clipboard` and `Encoding.UTF8` forms are gone. No pytest, no commit. Report exact changes.
