# Inc 10b — E4 implementation notes (G2 split-join)
Batch 2026-11-01-batch-101, increment 10b. Implementer G2 split-join (E4). Files touched: `s19_app/tui/segment_split_view.py`

## 1. Functions changed
| File | Function | Graph node | Change |
|---|---|---|---|
| `s19_app/tui/segment_split_view.py` | `SplitJoinWindow.note_image_bytes_written` | `SplitJoinWindow.note_image_bytes_written` (new) | Added. While the window has no `hidden` class it calls `self._bump()` once (disarm + one `_sync`); while hidden it sets `self._armed = False` only. No focus, no selection reset, no `refresh_window`. Implemented exactly as I-1 pins it. |

## 2. Deviations from the graph (each with its reason) — or "none"
none

## 3. Open questions for the integrator — or "none"
none

## 4. Checks
`<HOME>/anaconda3/envs/s19env/python.exe -m py_compile s19_app/tui/segment_split_view.py`

Output: (exit 0, no output — byte-compilation succeeded)
