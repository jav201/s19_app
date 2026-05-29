# US-01 — Search resume after pagination (anchor clear → first-visible resume)

Covers HLR-001 / LLR-001.1–001.4. Two events: (1) the user moves the window (page or tag/record selection), which **clears** the stale anchor; (2) the user presses Find Next, which **resumes** from the first visible address.

```mermaid
sequenceDiagram
    actor User
    participant App as S19TuiApp
    participant Vis as _first_visible_hex_address(view)
    participant Find as find_string_in_mem

    Note over User,App: (1) User moves the hex window
    User->>App: page next/prev · select A2L tag · select MAC record
    App->>App: mutate window / re-render pane
    App->>App: last_search_address = None  (clear stale anchor)
    App-->>App: (alt/mac) renderer caches first-row address

    Note over User,Find: (2) User presses Find Next (same query)
    User->>App: Find Next (query unchanged)
    alt last_search_address is None AND last_search_text == query
        App->>Vis: _first_visible_hex_address(view)
        alt main view
            Vis-->>App: current_file.row_bases[_hex_window_start]
        else alt / mac view
            Vis-->>App: cached _alt/_mac_first_visible_address
        end
        App->>Find: find_string_in_mem(start_address = first-visible)
    else query changed
        App->>Find: find_string_in_mem(start_address = None)  %% full-image from lowest key
    end
    Find-->>App: hit address  -or-  None
    alt hit
        App->>App: last_search_address = hit; scroll to hit
        App-->>User: highlight match on current page
    else miss
        App->>App: anchor stays None (next Find Next resumes from first-visible again)
        App-->>User: "not found" — round-trip is idempotent
    end
```

**Fallback (LLR-001.2 acceptance):** if `row_bases` is empty or `_hex_window_start` is out of bounds, `_first_visible_hex_address` returns `None` and search falls back to the lowest mem-map key.
