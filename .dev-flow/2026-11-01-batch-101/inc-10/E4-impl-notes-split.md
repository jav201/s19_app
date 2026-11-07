# Inc 10a — E4 implementation notes (G2 split-join)

Batch 2026-11-01-batch-101, increment 10a. Implementer G2 split-join (E4). Files touched: `s19_app/tui/segment_split_view.py`

## 1. Functions changed

| File | Function | Graph node | Change |
|---|---|---|---|
| `s19_app/tui/segment_split_view.py` | `SplitJoinWindow.refresh_window` | G2 `refresh_window` (I-2) | The `#sje_table` focus now runs only `if not self.has_class("hidden")`; selection reset, `_sync()` and `call_after_refresh(_sync)` unchanged. |
| `s19_app/tui/segment_split_view.py` | `SplitJoinWindow.check_action` | G2 `check_action` (new, I-6) | New method: `if self.has_class("hidden"): return False`; else `return super().check_action(action, parameters)`. |
| `s19_app/tui/segment_split_view.py` | `SplitJoinWindow.action_export` | G2 `action_export` (SR2-1) | Added `if self.has_class("hidden"): return` at the top, before the export body; the rest unchanged. |

## 2. Deviations from the graph (each with its reason) — or "none"

none

## 3. Open questions for the integrator — or "none"

none

## 4. Checks

- Command: `<HOME>/anaconda3/envs/s19env/python.exe -m py_compile s19_app/tui/segment_split_view.py`
- Output: (empty — py_compile prints nothing on success)
- Exit code: `0`
- Line endings: file remains CRLF throughout (verified: 2233 CRLF terminators, 0 bare LF), matching the existing file.
