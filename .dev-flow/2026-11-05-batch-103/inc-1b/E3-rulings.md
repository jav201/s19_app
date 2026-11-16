# Inc 1b — E3 rulings, round 1 corrective design

The orchestrator accepts every finding in `E3-architect.md` and `E3-security.md` as a `design-gap` correction. No product or test code is authorized by this file. Current G2 remains body B and O-1=B from the second export.

| Finding | Ruling and required observable |
|---|---|
| E3A-01 | **Accept.** `copy_to_clipboard("")` raises `textual.actions.SkipAction` before coroutine/worker creation. Idle reaches one body-B dialog with both clipboards unchanged; modal keeps the existing dialog and opens none. A plain `return` is the RED mutant. |
| E3A-02 | **Accept.** `out_of_bounds=True` is empty space in N2/N5: no copy, cursor move, `RowSelected`, notice or hex jump. A real cell of the same row with `False` is the positive control and must copy/highlight. |
| E3A-03 | **Accept.** Add concrete examples for every Ctrl+C source, detail-card right-click, drag/F7 non-copy and seeds before/after Stay. Correct R-COPY.2/4 to the row-name failure route. No redundant new requirement. |
| E3A-04 | **Accept.** MAC uses `cell.plain` for Rich `Text`, otherwise `str(cell)`, removes only a known producer glyph+space prefix and preserves the full remaining name, including spaces. |
| E3A-05 | **Accept.** Remove stale current-G2 provenance and use the integrated census: 24 unique function nodes, 2 source files; the group-A 17-node count is only a fragment count. The latest export has `notes={}`; earlier notes are historical. |
| E3-01 | **Accept.** N3 captures the early snapshot on button-3 MouseDown but copies only on a valid button-3 MouseUp with unchanged offset, screen and widget. Any MouseMove offset change invalidates permanently, including exit/return. MouseDown replaces state; MouseUp consumes/clears it before one possible N1 call; every event forwards once through `super()`. |
| E3-02 | **Accept as R-COPY.25.** After capping and before any sink, NUL causes fail-closed refusal: zero base/writer/OSC 52/process/helper/success effects, both seeds unchanged, one 6-second warning `Clipboard copy refused — NUL cannot be represented in the Windows text clipboard.` and one WARNING `OS clipboard copy refused; payload contains NUL`, without payload or escaped payload. NUL solely beyond the cap does not refuse and preserves the original-length cut notice. No sanitization of the approved full name. |
| E3-03 | **Accept as R-TUI-043.13/102.** A hostile full-name fixture combines markup, ESC, BEL, OSC-like text and LF without NUL. Assert exact app/OSC 52/Windows payloads, forced PowerShell stdin/static argv, one write/request, no extra terminal sequence and no payload logs. Do not use the U+FFFD painted projection as the expected value. |

**Correction population (C-14/C-65):** the rulings are applied across `01-requirements.md`, `02-test-cases.md`, `E1-slice.md`, `E2-interfaces.md`, `graph-app.md`, `graph-clipboard.md`, integrated `graph-inc1b.md`, this file and `steps.log`. R-COPY.25 is owned by the changed clipboard tail; right-gesture state is an entity, not another function node. The integrated graph deliberately removes group A's duplicate tail-context block so group B's changed tail is not hidden by first-node-wins merge.

**Counts after correction:** 23 active requirements; 112 active requirement cases = 93 R-COPY + 10 cited clipboard/security + 9 dialog/quit; 9 withdrawn cases and the existing acceptance counts preserved. Source files remain `app.py` and `os_clipboard_input.py`.

**Conditional-gate discharge:** architecture and security must re-review the corrected graph and every finding above. PASS requires E3A-01/02 and E3-01/02 closed with concrete examples and no HIGH/MAJOR/BLOCKER open. Minor findings may remain only as explicitly routed E4 addenda, not as unowned notes.

## Round-2 minor addenda discharged before E4

- **E3R2-01 (architect census and shared SkipAction note):** `E2-interfaces.md` now distinguishes 17 group-A fragment entries from 16 integrated app nodes and 24 total; N1 pins `from textual.actions import SkipAction` and `raise SkipAction`, with missing-import/`NameError` RED. The E1 slice carries the same binding.
- **E3R2-02 (gesture state):** the slice now declares five fields — optional text, offset, screen, widget and `valid` — matching the graph/interfaces. Empty text never copies.
- **E3R2-03 (canonical fixtures):** the long MAC name is a second arming inside R-COPY.4/2, preserving 112 cases; `NUL_AFTER = P65536 + "\x00"` is exactly 65,537 characters with NUL only at index 65,536, and every cut-total example says 65,537. HOSTILE remains the ledger's exact `HOSTILE_NAME` in every graph.
- **E3R2-04 (ownership):** the slice names one changed `_compose_screen_mac`, unchanged `_compose_screen_a2l`, and the tail/helper in `os_clipboard_input.py`, with no stale app-level `_write_copied_text`.

Both round-2 reviews returned **PASS-WITH-NOTES** with no BLOCKER/HIGH/MAJOR open. These minor addenda are now closed in the design; no separate E4 deviation is needed.
