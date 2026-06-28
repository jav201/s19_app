# Batch-17 flow diagrams — s19_app

> Phase 6 artifact. Accurate to the shipped tree (symbols + file:line grep-verified). Companion to `06-docs/functionality.md`.

---

## 1. CRC write — operator-selected record width threading (US-019)

The operator's width choice (16/32) is captured on the modal and carried through the worker into the emitter, so the data records in the written `.s19` are framed at the selected width.

```mermaid
flowchart TD
    A["Operator: Write CRC image\n→ push_screen(ConfirmWriteScreen)\nscreens.py:1368"] --> B["ConfirmWriteScreen\nWidth-cycle button over (32, 16), default 32\nscreens.py:689 · cycle :759"]
    B -->|Confirm| C["dismiss(ConfirmWriteResult(True, bytes_per_line))\nscreens.py:770"]
    B -->|Cancel| X["dismiss(ConfirmWriteResult(False, ...))\n→ no file written\nscreens.py:774"]
    C --> D["_on_confirm_write(result)\nreads result.bytes_per_line\nscreens.py:1370"]
    D --> E["_run_crc_write_worker(op_input, config, token, bytes_per_line)\nscreens.py:1432"]
    E --> F["write_crc_image(..., bytes_per_line=bytes_per_line)\ncrc.py:790 (kwarg :796)"]
    F --> G["emit_s19_from_mem_map(working_mem, working_ranges, bytes_per_line=bytes_per_line)\ncrc.py:884"]
    G --> H["Written .s19 under .s19tool/workarea/crc/\nData records framed at the selected width\n(16 selected / 32 default)"]
```

> The `bytes_per_line` kwarg already existed at `emit_s19_from_mem_map` (in the frozen-adjacent `changes/io.py`), so that file was **not** edited. The S0-header policy stays `s0_header=None` on the CRC path (US-019 keeps US-015's S0 synthesis out of scope).

---

## 2. Issues screen — row select → hex pane render (US-020a)

Selecting an issue row resolves the `ValidationIssue` and renders the bytes at its address into the on-screen hex pane; an address-less issue shows a placeholder and clears any prior bytes.

```mermaid
flowchart TD
    A["Operator selects an issue row\n(DataTable cursor + Enter)"] --> B["on_data_table_row_selected(event)\nroutes issue rows\napp.py:4408"]
    B --> C["_jump_to_validation_issue_by_index(absolute_index)\napp.py:4761"]
    C --> D["_jump_to_validation_issue_object(issue)\napp.py:4832"]
    D --> E["_update_issues_hex_pane(address)\napp.py:4784 (called :4859)"]
    E -->|address is not None| F["render_hex_view_text(... focus=address)\nhexview.py → #issues_hex_pane shows the bytes\n(0x%08X focus row + byte groups)"]
    E -->|address is None| G["#issues_hex_pane =\n'(issue has no address — nothing to show)'\nprior bytes cleared (no stale carry-over)"]
    F --> H["#issues_hex_pane\n(compose tree: _compose_screen_issues, app.py:1128 · pane :1143)"]
    G --> H
```

> `on_data_table_row_selected` (`app.py:4408`) only routes — it is untouched. The render site is `_jump_to_validation_issue_object`, where the three pre-existing cross-screen hex updates already live; `_update_issues_hex_pane` is additive (the no-address placeholder + clear is the net-new behavior).

---

## 3. Issues list — Related cell composition (US-020b)

The Related column is built once when the issue payload is precomputed, then rendered by the DataTable; the cell tuple stays index-aligned with severity styles and the column count.

```mermaid
flowchart LR
    A["ValidationIssue.related_artifacts\nvalidation/model.py"] --> B["precompute_issue_datatable_payload(issues)\napp.py:475"]
    B --> C["related = ', '.join(...) or '-'\napp.py:509"]
    C --> D["8-tuple cell row\n(severity, code, artifact, RELATED[idx 3], symbol, address, line, message)\napp.py:511-519"]
    D --> E["#validation_issues_list DataTable\nRelated column header; 8 cells == 8 columns"]
```

> Pure formatting over existing fields — no new validation logic. The 7→8 tuple widening keeps the cell array index-aligned with the per-row severity styles (contract-touch identity check: tuple width 8 == column count 8).
