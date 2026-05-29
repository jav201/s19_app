# US-03 — Goto input → membership check → status (miss) or focus + marker (hit)

Covers HLR-003 / LLR-003.1–003.5. All three `_handle_goto*` handlers route through the shared `_apply_goto(view, addr)` helper, which does the binary-search membership check and decides between the miss path (status only, view unmoved) and the hit path (set focus + render the `> ` marker).

```mermaid
flowchart TD
    A[User submits goto address in the field] --> B{int raw 0 parses?}
    B -- no --> C["status: Invalid address format.<br/>clear _view_goto_focus_address<br/>(early return, view unmoved)"]
    B -- yes --> D["_handle_goto* calls<br/>_apply_goto(view, addr)"]
    D --> E["range_index = _get_range_index(self.current_file)"]
    E --> F{"address_in_sorted_ranges(addr, range_index)?"}
    F -- "False (miss)" --> G["set_status: Address 0xAAAAAAAA not in loaded file.<br/>_view_goto_focus_address stays None<br/>update_hex_view NOT called"]
    G --> H[return False — view unmoved]
    F -- "True (hit)" --> I["_view_goto_focus_address = addr"]
    I --> J["update_hex_view(addr) — move window<br/>status: Goto 0xAAAAAAAA"]
    J --> K["renderer forwards<br/>focus_row_marker_address = _view_goto_focus_address<br/>into render_hex_view_text"]
    K --> L{"row_addr <= focus < row_addr + HEX_WIDTH?"}
    L -- yes --> M["prepend '> ' (plain text, no Rich style)"]
    L -- no --> N["prepend '  ' (two spaces, keeps alignment)"]
    M --> O[return True — exactly one row marked]
    N --> O
```

**Notes**
- `LoadedFile` exposes `ranges`; the membership index is resolved through the cached `_get_range_index(...)`, not a raw `sorted_ranges` attribute.
- The marker carries no Rich `style=`, no `sev-*` class, and no color — it cannot collide with validation severity colors or the search/MAC byte highlights.
