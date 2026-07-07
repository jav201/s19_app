# Diagrams — Interactive Memory Map — s19_app — Batch 2026-07-06-batch-27

Reference diagrams for **R-TUI-041 — Interactive Memory-Map Minimap** (US-035 / US-036 / US-037).

1. **Component / architecture** — `S19TuiApp.update_memory_map` → `MemoryMapPanel.render_ranges` → grid cells / detail / stats, and the `OpenInHexRequested` message → app handler → `update_hex_view`, sitting on top of the **frozen** engine.
2. **Sequence** — operator selects a cell → detail renders → Open-in-Hex → hex view focuses `cell_start`.
3. **Data flow** — `LoadedFile.ranges`/`range_validity` + `_validation_issues` → `coverage_stats` / `cell_status` / `issues_in_window` → rendered widgets.

All blocks are **Mermaid source** — render in any GitHub Markdown viewer or Mermaid-aware IDE. No build step, no rendered images checked in, no extra dev dependency (Phase 6 hard constraint).

Source data:

- [`01-requirements.md`](../../01-requirements.md) §2.1 (product perspective), §3 (HLR), §4 (LLR), §6.2 (C-13 geometry budget), draft-time probe ledger (P-1..P-12).
- [`03-increments/increment-001.md`](../../03-increments/increment-001.md) / [`-002.md`](../../03-increments/increment-002.md) / [`-003.md`](../../03-increments/increment-003.md).
- [`04-validation.md`](../../04-validation.md) §2/§3 (real test nodes), §8 (engine-freeze verification).
- Code: `s19_app/tui/screens_directionb.py` (`MemoryMapPanel` + helpers), `s19_app/tui/app.py` (`update_memory_map` ~7180, `on_memory_map_panel_open_in_hex_requested` ~7220), `s19_app/tui/styles.tcss` (`#map_*` rules 529-617).

---

## 1. Component / architecture

The redesign lives entirely in the **view layer** (yellow). The dashed red line is the **engine-freeze boundary** — nothing below it changed this batch (`git diff main` empty over the seven frozen modules, [`04-validation.md`](../../04-validation.md) §8). The panel consumes the already-computed `LoadedFile` snapshot, the pre-computed `_validation_issues`, and the frozen `css_class_for_severity`; the Open-in-Hex jump reuses the existing `update_hex_view`.

```mermaid
flowchart TB
    subgraph shell["s19_app/tui/app.py — S19TuiApp (orchestration-only)"]
        umm["update_memory_map()<br/>app.py:7180<br/><i>render-only handoff</i>"]
        openh["on_memory_map_panel_open_in_hex_requested()<br/>app.py:7220<br/>switch to workspace + focus"]
        uhv["update_hex_view(focus_address)<br/>app.py:7249 <i>(existing, reused)</i>"]
        vi["_validation_issues<br/>app.py:764<br/><i>single canonical issue list</i>"]
    end

    subgraph panel["s19_app/tui/screens_directionb.py — MemoryMapPanel <i>(new this batch)</i>"]
        rr["render_ranges(ranges, range_validity, issues)"]

        subgraph helpers["Pure helpers (no I/O, no analysis — LLR-041.7)"]
            span["derive_image_span"]
            count["cell_count_for_geometry<br/>bytes_per_cell"]
            cstatus["cell_status → status_to_css_class"]
            iss["issues_in_window · covering_range"]
            stats["coverage_stats → CoverageStats"]
            adj["adjacent_cell_index"]
            safe["safe_text <i>(markup-safe, LLR-041.11)</i>"]
        end

        grid["#map_grid<br/>MapCell × N<br/>(.map-cell + sev-* class)"]
        detail["#map_detail<br/>build_detail_text →<br/>#map_detail_body + Open button"]
        strip["#map_stats<br/>build_stats_text →<br/>#map_stats_body (7 metrics)"]
        msg["OpenInHexRequested(focus_address=cell_start)"]
    end

    styles["styles.tcss #map_* rules<br/>grid-size:16 · sev-* colours<br/>width-narrow reflow<br/><i>(new this batch)</i>"]

    freeze["━━━━━━ ENGINE FREEZE BOUNDARY — zero bytes changed below ━━━━━━"]

    subgraph frozen["Frozen engine / model (consumed read-only)"]
        lf["tui/models.py<br/>LoadedFile.ranges / range_validity"]
        vm["validation/model.py<br/>ValidationIssue<br/>code/severity/message/symbol/address"]
        cp["tui/color_policy.py<br/>css_class_for_severity<br/>SEVERITY_CLASS_MAP"]
    end

    umm -->|"ranges, range_validity, _validation_issues"| rr
    vi --> umm
    rr --> span --> count
    rr --> cstatus --> grid
    rr --> stats --> strip
    rr --> safe
    grid -->|"click / Enter → MapCell.Selected"| detail
    detail --> iss
    grid -->|"arrow keys"| adj
    detail -->|"Open in Hex View press"| msg
    msg -->|"Textual message dispatch"| openh
    openh --> uhv
    rr -.applies.- styles

    rr --> freeze
    umm --> lf
    cstatus --> cp
    detail --> vm

    classDef new fill:#fff4cc,stroke:#a07a00,stroke-width:1.5px,color:#2a2200
    classDef app fill:#e3f2fd,stroke:#1565c0,color:#0d3a73
    classDef frz fill:#eef0f4,stroke:#5b6473,color:#2a2a30
    classDef boundary fill:#fde8e8,stroke:#c43a3a,stroke-width:2px,color:#7a1d1d

    class rr,span,count,cstatus,iss,stats,adj,safe,grid,detail,strip,msg,styles new
    class umm,openh,uhv,vi app
    class lf,vm,cp frz
    class freeze boundary
```

**Reading the diagram.**

- **Yellow** = new/respecified this batch (`MemoryMapPanel`, its helpers, the `#map_*` widgets and CSS).
- **Blue** = existing `app.py` orchestration — `update_memory_map` gains **one** extra argument (`_validation_issues`) and there is **one** new handler; `update_hex_view` is reused verbatim.
- **Grey below the red line** = the frozen engine/model, consumed read-only. `css_class_for_severity` is the single source of truth for cell colours; `ValidationIssue` fields feed the detail pane; `LoadedFile` fields feed the grid and stats.
- The panel never renders hex itself — it posts `OpenInHexRequested` and the app owns the focus path (LLR-041.6).

---

## 2. Sequence — select a cell, then Open-in-Hex

The operator selects a cell, the detail pane renders, and the Open-in-Hex jump focuses the hex view at `cell_start`. This is the AT-036a / AT-036b path, observed black-box through `#map_detail` and `#hex_view`.

```mermaid
sequenceDiagram
    actor Op as Operator
    participant Cell as MapCell (#map_grid)
    participant Panel as MemoryMapPanel
    participant App as S19TuiApp
    participant Hex as Hex view (#hex_view)

    Note over Op,Cell: Grid already rendered by update_memory_map → render_ranges

    alt keyboard navigation
        Op->>Cell: press ← / → / ↑ / ↓
        Cell->>Panel: focus_adjacent_cell(self, key)
        Panel->>Panel: adjacent_cell_index(current, key, count, cols) — clamped, no wrap
        Panel-->>Cell: cells[target].focus()  (moves focus only)
        Op->>Cell: press Enter
    else pointer
        Op->>Cell: click
        Cell->>Cell: self.focus()
    end

    Cell->>Panel: post MapCell.Selected(cell)
    Panel->>Panel: on_map_cell_selected(event)
    Panel->>Panel: build_detail_text(cell_start, cell_end, status)
    Note right of Panel: covering_range(...) + issues_in_window(...)<br/>every file-derived token via safe_text (LLR-041.11)
    Panel-->>Op: #map_detail_body updated (chip · window · region · issues · counts)
    Panel-->>Op: reveal "Open in Hex View" button

    Op->>Panel: press "Open in Hex View"
    Panel->>App: post OpenInHexRequested(focus_address = cell_start)
    App->>App: on_memory_map_panel_open_in_hex_requested(message)
    App->>App: action_show_screen("workspace")
    App->>Hex: update_hex_view(focus_address = cell_start)
    Hex-->>Op: hex row containing cell_start rendered + focused
```

**Reading the diagram.**

- **Arrows move focus; `Enter` (or click) selects** — the two are deliberately separate so keyboard traversal never triggers a detail re-render on every hop.
- The detail pane is assembled by pure helpers over the panel's stored ranges/issues — no new analysis (LLR-041.7), all file-derived text markup-safe (LLR-041.11).
- Open-in-Hex is a **message**, not a direct call: the panel stays render-only and the app owns `update_hex_view`. The black-box proof (AT-036b) asserts the *rendered hex row* at `cell_start` appears — not a mock call.

---

## 3. Data flow — already-computed inputs → derived widgets

Everything the screen shows is derived by arithmetic on already-parsed values. No box in this diagram parses a file, computes coverage, or runs validation — those all happened upstream, before `update_memory_map` is called.

```mermaid
flowchart LR
    subgraph inputs["Already-computed inputs (verbatim)"]
        ranges["LoadedFile.ranges<br/>List[(start,end)] end-exclusive"]
        validity["LoadedFile.range_validity<br/>List[bool]"]
        issues["_validation_issues<br/>List[ValidationIssue]<br/>(from ValidationReport)"]
    end

    subgraph derive["Pure derivation (screens_directionb.py helpers)"]
        span["derive_image_span<br/>→ [span_start, span_end)"]
        cells["cell_count_for_geometry<br/>+ bytes_per_cell<br/>→ N cells, B/cell"]
        cstat["cell_status<br/>→ valid / invalid / gap"]
        cov["coverage_stats<br/>→ CoverageStats (7 metrics)"]
        join["issues_in_window<br/>+ covering_range<br/>→ cell/region issue join"]
        cls["status_to_css_class<br/>via css_class_for_severity (frozen)"]
    end

    subgraph widgets["Rendered widgets (#screen_map)"]
        header["#map_header<br/>≈ N KiB/cell"]
        grid["#map_grid<br/>coloured .map-cell tiles"]
        detailw["#map_detail_body<br/>chip · window · region · issues · counts"]
        statsw["#map_stats_body<br/>coverage% · bytes · valid/invalid ·<br/>gaps · largest gap · total issues"]
    end

    ranges --> span
    span --> cells
    cells --> header
    cells --> grid
    ranges --> cstat
    validity --> cstat
    cstat --> cls --> grid
    ranges --> cov
    validity --> cov
    issues --> cov
    cov --> statsw
    issues --> join
    ranges --> join
    join --> detailw
    cstat --> detailw

    classDef inNode fill:#e8f5e9,stroke:#2e7d32,color:#0e3a13
    classDef deriveNode fill:#fff4cc,stroke:#a07a00,color:#2a2200
    classDef widgetNode fill:#e3f2fd,stroke:#1565c0,color:#0d3a73

    class ranges,validity,issues inNode
    class span,cells,cstat,cov,join,cls deriveNode
    class header,grid,detailw,statsw widgetNode
```

**Reading the diagram.**

- **Green** = the three already-computed inputs handed to `render_ranges` verbatim.
- **Yellow** = pure, side-effect-free derivation — the cell partition, the per-cell status, the coverage arithmetic, and the read-only issue join. The `span > 0` check inside the auto-scale / stats path is the single divide-by-zero guard.
- **Blue** = the four rendered widget bodies. Both `#map_stats_body` and `#map_detail_body` read the **same canonical** `_validation_issues` — never a re-derived count — so the "total issues" figure and the per-cell/region joins can never diverge.
- Cell colour flows only through `status_to_css_class` → `css_class_for_severity` (frozen); the panel hard-codes no severity value.

---

## 4. Diagram-source maintenance notes

- **Format.** All blocks are Mermaid source — render client-side. No build step, no rendered images, no extra dev dependency.
- **Point-in-time.** This file is the batch-archive diagram set for the R-TUI-041 minimap redesign. Line citations (`app.py:7180` etc.) are accurate as of this batch; re-verify if the app is refactored.
- **Freeze boundary.** The freeze boundary in §1 is an accurate architectural fact for batch-27 — `git diff main` over the seven frozen modules is empty. Re-draw it if a future engine batch changes what lives below the line.
- **Validation.** Render in any GitHub Markdown view to verify syntax. The diagrams use only Mermaid `flowchart` and `sequenceDiagram` features — no plugins, no client-config injection.
