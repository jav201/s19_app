# Batch-48 — Architecture & Flow Diagrams

> **Audience:** a maintainer of the `s19_app` TUI layer. **Purpose:** show how already-computed data reaches the Patch Editor's new render surfaces, and how the headline before/after card is driven — with the **C-7 panel-purity boundary** made explicit. Symbols cite `screens_directionb.py` / `services/change_service.py` / `models.py` at HEAD `fccab02`.

---

## 1. Architecture — data flow into the Patch Editor render surfaces (`architecture-dataflow`)

The defining constraint is **C-7 panel purity**: `PatchEditorPanel` is strictly presentational — zero `self.app`, zero `mem_map` reach-ins, zero service imports. Every datum it renders is **pushed in as a method parameter** by `S19TuiApp` (`app.py`); the panel never pulls. The batch-48 additions all respect that boundary — `mem_map` is threaded through `refresh_entries(…, mem_map=…)`, aggregates through an extended `refresh_check_results`, and history depths through a dedicated refresh.

```mermaid
flowchart TD
    subgraph SNAP["Snapshot (built off the UI thread)"]
        LF["LoadedFile.mem_map<br/>Dict[int,int] sparse image<br/>(models.py:57)"]
    end

    subgraph SVC["ChangeService (services/change_service.py) — the data owner"]
        ROWS["rows() → ChangeEntryRow[]<br/>kind/address/value/status/linkage<br/>+ check_glyph (LLR-077.4)<br/>+ numeric address / encoded_bytes (LLR-080.3)"]
        AGG["check_aggregates()<br/>passed / failed / uncheckable<br/>(:1455; from CheckRunResult.aggregates)"]
        HIST["history_depths()<br/>back / fwd / bound=_HISTORY_MAX(20)<br/>(:606; derived from undo/redo stacks)"]
        PROV["provenance stamp<br/>(document_signature, image_generation)<br/>guards glyph staleness (LLR-077.2)"]
    end

    subgraph APP["S19TuiApp orchestration (app.py) — pushes data across the boundary"]
        RE["refresh_entries(rows, mem_map=…)"]
        RC["refresh_check_results(…, aggregates)"]
        RH["history refresh (depths + key hints)"]
    end

    subgraph PANEL["PatchEditorPanel (C-7: presentational only — params in, messages out)"]
        ET["Entries table<br/>#patch_doc_entries_table<br/>role-styled Text cells + Kind-cell glyph"]
        STRIP["CHECKS pass/fail strip<br/>✓P · ✗F · ◐U + microbar"]
        GAUGE["JSON colouring + paste-cap gauge<br/>N KB / 64KB (MAGENTA)"]
        HS["History strip<br/>↶ back ↷ fwd N/20 + ctrl+z/ctrl+y"]
        CARD["BeforeAfterCard (Static)<br/>before ← image · after ← entry bytes"]
    end

    LF -->|threaded as a param| RE
    ROWS --> RE
    PROV -.guards.-> ROWS
    AGG --> RC
    HIST --> RH

    RE --> ET
    RE -->|mem_map retained for card use| CARD
    RC --> STRIP
    RH --> HS

    ET -->|RowHighlighted → index| CARD

    classDef boundary stroke-dasharray:5 5;
    class PANEL boundary;
```

**Reading it:** `LoadedFile.mem_map` and everything `ChangeService` computes stay on the service/snapshot side of the dashed C-7 boundary. `app.py` is the only thing that crosses it, and it crosses by **calling the panel's `refresh_*` methods with parameters** — never by letting the panel reach back into the app. The entries table and the card are fed by the same `refresh_entries` call (the card reuses the `mem_map` the table was given), which is why a row highlight can drive the card without any new service round-trip.

---

## 2. Sequence — the live before/after card on row select (`sequence-before-after-card`)

The card is driven by a positional (index-based) join, never an address match: the entries table is `cursor_type="row"`, so the highlighted row index **is** the entry index. Before-bytes come from `LoadedFile.mem_map` at the entry's address; after-bytes are the entry's declared `encoded_bytes`. The whole path is read-only — it paints, it applies nothing.

```mermaid
sequenceDiagram
    autonumber
    actor Analyst
    participant Table as Entries table<br/>#patch_doc_entries_table
    participant Panel as PatchEditorPanel
    participant Card as BeforeAfterCard (Static)
    participant Mem as mem_map (retained param)<br/>+ ChangeEntryRow

    Analyst->>Table: highlight / select a row
    Table->>Panel: on_data_table_row_highlighted(event)
    Note over Panel: cursor_type="row" ⇒<br/>highlighted row index = entry index<br/>(positional join, LLR-080.3 — never address-match)
    Panel->>Mem: row = rows[index]<br/>addr = row.address (int)<br/>after = row.encoded_bytes
    Panel->>Mem: before = [mem_map.get(a) for a in span]
    Note over Mem: absent address → distinct placeholder,<br/>NEVER a fabricated 00 (A4 / AT-080c)
    Mem-->>Panel: before-bytes, after-bytes
    Panel->>Card: before_after_card_text(addr, before, after)<br/>→ _render_before_after_card → Card.update()
    Card-->>Analyst: paints before | after (read-only)
    Note over Card,Mem: mem_map and the document are UNCHANGED<br/>after N selections (read-only, AT-080b)
```

**Reading it:** selection produces a paint and nothing else. The panel derives both sides from data it was already handed (`mem_map` retained from `refresh_entries`, and the row's own numeric `address` / `encoded_bytes`), so it neither re-parses `address_text` nor touches the service — keeping the C-7 boundary intact and the operation provably side-effect-free.
