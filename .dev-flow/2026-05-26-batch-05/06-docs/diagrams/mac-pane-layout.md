# US-02 — MAC two-pane layout, before → after (≥120-column regime)

Covers HLR-002 / LLR-002.1–002.4. Only the comfortable (≥120-column) regime changed; the narrow (<120-column) proportional regime is byte-identical.

## Before — `#mac_hex_pane { width: 40 }` (clips a full hex row)

```mermaid
flowchart LR
    subgraph WB["#workspace_body (≥120 cols)"]
        direction LR
        R1["#mac_records_pane<br/>(record list)"]
        H1["#mac_hex_pane<br/>width: 40<br/>(clips / wraps — a full hex row needs ~80)"]
    end
    R1 --- H1
```

## After — `#mac_hex_pane { width: 82 }` + `#mac_hex_scroll { height: 100% }`

```mermaid
flowchart LR
    subgraph WB2["#workspace_body (≥120 cols)"]
        direction LR
        R2["#mac_records_pane<br/>(record list, ~14 cells — stays ≥1)"]
        subgraph H2["#mac_hex_pane — width: 82"]
            direction TB
            T["#mac_hex_title (1 row)"]
            C["#mac_hex_controls (4 rows)"]
            S["#mac_hex_scroll<br/>height: 100%; overflow: auto<br/>(fills remaining height; tallest child)<br/>full hex row: '> ' + 0xAAAAAAAA + 16 bytes + ASCII"]
        end
    end
    R2 --- H2
    T --> C --> S
```

**Invariants:** at terminal width 120 the hex pane measures ≥ 82 cells and the records pane ≥ 1 cell; the `#mac_hex_scroll` height equals the pane height minus the title (1) and controls (4) and is the tallest child of the pane.
