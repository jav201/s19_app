# Batch-22 flows — Patch Editor 4-pane 2×2 split

> Phase 6 diagrams for feature #8 slice 2 (US-030 / HLR-033). Both diagrams are faithful to the final-tree seams: `s19_app/tui/screens_directionb.py` (`compose`, `:627`/`:663`/`:706`/`:717`/`:734`) and `s19_app/tui/styles.tcss` (`:560` grid, `:570` per-pane overflow, `:582` span, `:690` button-grid).

## (a) 2×2 grid layout — `#patch_editor_panel`

`layout: grid; grid-size: 2 3; grid-columns: 1fr 1fr; grid-rows: 1fr 1fr auto`. The two `1fr` rows hold the four panes; the `auto` third row holds the full-width, `column-span: 2`, normally-hidden save-back prompt.

```mermaid
flowchart TB
    subgraph PANEL["#patch_editor_panel — layout: grid, grid-size 2×3 (grid-rows 1fr / 1fr / auto)"]
        direction TB
        subgraph ROW1[" "]
            direction LR
            TL["#patch_pane_entries (TL, 1fr)<br/>section title · entries DataTable<br/>· empty-state · Address/Value/Bytes<br/>· Add·Edit·Remove<br/><i>overflow-y: auto</i>"]
            TR["#patch_pane_changefile (TR, 1fr)<br/>Change-file Select + path input<br/>· #patch_doc_controls (grid-size 3 → 2 rows)<br/>· #patch_checks_help Label · paste row<br/><i>overflow-y: auto</i>"]
        end
        subgraph ROW2[" "]
            direction LR
            BL["#patch_pane_checks (BL, 1fr)<br/>issue count · issues Static<br/>· Checks status · results container<br/><i>overflow-y: auto</i>"]
            BR["#patch_pane_variant (BR, 1fr)<br/>Execute-over-variants<br/>(scope button + execute button)<br/><i>overflow-y: auto</i>"]
        end
        SPAN["#patch_saveback_row — column-span: 2 (auto row)<br/>hidden by default (zero-height) · full width when shown<br/>Save-as name · Width · Write file · Don't save"]
    end

    ROW1 --> ROW2 --> SPAN
```

**Notes**
- Each `#patch_pane_*` scrolls vertically and independently (`overflow-y: auto; overflow-x: hidden`, styles.tcss `:570`) — scroll moved off the panel and onto the panes.
- The save-back row is **not a fifth pane**: it is a direct grid child spanning both columns in the `auto` row, so it never squeezes the `1fr` panes while hidden.
- Measured content width: **70 cols @80 / 92 cols @120** → ~35 cols/pane at 80 (C-13 budget clears).

## (b) Reparent mapping — ~12 flat compose groups → 4 panes

Each pre-existing group is moved **wholesale** into its pane; no inner `patch_*` id is renamed or reordered (the property AT-033c guards).

```mermaid
flowchart LR
    subgraph BEFORE["BEFORE — ~12 sibling groups in one ScrollableContainer"]
        direction TB
        G1["section title"]
        G2["#patch_doc_entries_table"]
        G3["#patch_doc_empty_state"]
        G4["#patch_doc_entry_inputs (Address/Value/Bytes + Add·Edit·Remove)"]
        G5["#patch_doc_file_row (Select + path + #patch_doc_controls + #patch_checks_help)"]
        G6["#patch_paste_row (TextArea + Parse pasted)"]
        G7["#patch_doc_issue_count"]
        G8["#patch_doc_issues"]
        G9["#patch_checks_status"]
        G10["#patch_checks_results"]
        G11["#patch_execute_row (scope + execute)"]
        G12["#patch_saveback_row"]
    end

    subgraph AFTER["AFTER — 4 panes + span child (grid)"]
        direction TB
        PE["#patch_pane_entries (TL)"]
        PC["#patch_pane_changefile (TR)"]
        PK["#patch_pane_checks (BL)"]
        PV["#patch_pane_variant (BR)"]
        SB["#patch_saveback_row (column-span: 2)"]
    end

    G1 --> PE
    G2 --> PE
    G3 --> PE
    G4 --> PE

    G5 --> PC
    G6 --> PC

    G7 --> PK
    G8 --> PK
    G9 --> PK
    G10 --> PK

    G11 --> PV

    G12 --> SB
```

**Seam anchors (final tree)**
- `#patch_pane_entries` yielded @ `screens_directionb.py:627`
- `#patch_pane_changefile` @ `:663` (contains `#patch_doc_controls`, now `grid-size: 3`, styles.tcss `:690`)
- `#patch_pane_checks` @ `:706`
- `#patch_pane_variant` @ `:717`
- `#patch_saveback_row` span child @ `:734` (CSS `column-span: 2` @ styles.tcss `:582`)
