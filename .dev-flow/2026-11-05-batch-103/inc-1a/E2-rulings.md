# Inc 1a — orchestrator rulings on the E2 graph (2026-11-06T18:52:33-06:00, Opus 5.5)

| Item | Ruling |
|---|---|
| I-1: `_mirror_and_write_os_clipboard` is the one copy tail (one app-clipboard/OSC 52 write, one OS write, one warning on failure) | **pinned** |
| P-2 (no OS write inside `copy_to_clipboard`, or a copy writes twice) | **pinned now** as an I-1 rule; Inc 1b's seam must respect it |
| P-1, P-3, P-4 (where the copy notice lives; views' copies through the tail; Inc 1b's app-level right-click never sees a text box's) | **PROPOSED for Inc 1b's E2**; recorded in `../inc-1b/E1-rulings.md` by reference to this file |
| E2-1 (D-9 seam: `focus_on_click()` instead of `_on_focus` + `Message.time`) | **to E3** |
| `_system_directory` seam; separate up/click handlers; `pytest -v` in the workflow | **accepted** |
| E2-2 (Ctrl+V with no text on the clipboard starts PowerShell, 0.2–2 s, no row bounds it) | **to E3** (a row, or a reason) |
| E2-5 (tag pushes run the Windows job: path filters skip tags) | **to E3** |
