# Inc 10a — E4 implementation notes (G3 render)

Batch 2026-11-01-batch-101, increment 10a. Implementer G3 render (E4). Files touched: `s19_app/render/hexview.py` (only — `app.py` is G1's, `segment_split_view.py` is G2's, both untouched here).

## 1. Functions changed

| File | Function | Graph node | Change |
|---|---|---|---|
| s19_app/render/hexview.py | `hex_row_bases` | G3 `hex_row_bases` (new, I-5) | New module-level function (placed before `_collect_hex_rows`): resolves the row anchors a hex view paints — the image's row bases plus the extra row bases (MAC highlights) spliced in, ascending. Returns `row_bases` itself (no copy) when there is no extra address or every extra row is already present; otherwise `sorted(existing | extra_bases)` with `existing = row_bases_set if row_bases_set is not None else set(row_bases)`. |
| s19_app/render/hexview.py | `_collect_hex_rows` | G3 `_collect_hex_rows` | The inline `bases` build (fast-path copy / subset check / union) is replaced by `bases: List[int] = hex_row_bases(base_row_bases, row_bases_set, extra)`; everything after is unchanged (output identical for every input). |

## 2. Deviations from the graph (each with its reason) — or "none"

none.

## 3. Open questions for the integrator — or "none"

none. Signature confirmed against G1: `S19TuiApp._hex_view_rows` calls `hex_row_bases(file.row_bases or [], getattr(file, "bases_set", None), mac_set)` — three positional args matching pinned I-5 `(row_bases, row_bases_set, extra_addresses)`. The existing `tests/test_tui_hexview.py` fast-path regressions (`_uses_row_bases_set_without_rebuilding` → 0 `set(...)` calls; `_without_row_bases_set_still_rebuilds` → ≥1; `_merges_when_extras_outside`) remain satisfied by the moved-out logic, including the `hexview.set` monkeypatch counters (the new function resolves `set` as a module global).

## 4. Checks

Command (operator rule: byte-compilation only, no pytest / no import of `s19_app`):

```
<HOME>/anaconda3/envs/s19env/python.exe -m py_compile s19_app/render/hexview.py
```

Output: empty (exit 0). Line endings: file remains CRLF throughout (437 CRLF terminators, 0 bare LF), matching the existing file.

DONE G3 render
Files edited: s19_app/render/hexview.py
