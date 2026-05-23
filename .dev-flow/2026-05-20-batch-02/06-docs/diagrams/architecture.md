# Architecture diagrams — s19_app — Batch 2026-05-20-batch-02 (Direction B restyle)

This document collects the reference diagrams for the Direction B "Rail + Command" view-layer restyle:

1. **Direction B TUI architecture** — the app shell (rail + command bar + 8 `.hidden`-toggled screen containers) sitting on top of the **frozen** engine/services layer, with the view-layer / engine boundary drawn explicitly.
2. **Screen-routing flow** — how a rail key / palette / command-bar input moves the user between the eight screens.
3. **Two-regime responsive layout** — how the 120-column breakpoint switches the pane-width regime.

All diagrams are Mermaid source — render in any GitHub Markdown viewer or Mermaid-aware IDE. No build step, no rendered images checked into git, no extra dev dependency (Phase 6 hard constraint).

Source data:

- [`CLAUDE.md`](../../../CLAUDE.md) §Architecture — the three-layer model.
- [`01-requirements.md`](../../01-requirements.md) §2.1 (product perspective), §3 (screen inventory), §6 (`R-*` traceability).
- [`03-increments/increment-plan.md`](../../03-increments/increment-plan.md) — the new-module split and the `.hidden`-toggle decision.
- [`04-validation.md`](../../04-validation.md) §2 — the engine-freeze verification.

---

## 1. Direction B TUI architecture

The Direction B restyle adds a **view layer** (yellow) on top of an unchanged engine. The dashed horizontal line is the **freeze boundary**: nothing below it changed this batch — the Phase 4 `git diff main` over all seven frozen modules is empty (HLR-014). The restyle introduces three new modules (`rail.py`, `command_bar.py`, `screens_directionb.py`) plus the extracted `styles.tcss`, all consuming the existing `LoadedFile` snapshot and `tui/services/` exactly as the pre-batch view code did.

```mermaid
flowchart TB
    subgraph entry["Entry point (pyproject.toml)"]
        tui["s19tui<br/>(s19_app.tui:main)"]
    end

    subgraph shell["Direction B app shell — s19_app/tui/app.py (S19TuiApp, orchestration-only)"]
        app["S19TuiApp<br/>BINDINGS · screen routing<br/>density action · CSS_PATH"]
        styles["styles.tcss <i>(new)</i><br/>Calm Dark tokens · 5 sev-* rules<br/>two-regime layout · modal block"]
    end

    subgraph nav["Navigation surfaces (persistent, on every screen)"]
        rail["rail.py <i>(new)</i><br/>Rail / RailItem<br/>8 items · keys 1-8<br/>glyphs + ASCII fallback<br/>(R-TUI-021)"]
        cmdbar["command_bar.py <i>(new)</i><br/>CommandBar<br/>palette Ctrl+K · find / · go-to g<br/>project + A2L labels<br/>(R-TUI-022, R-TUI-033, R-TUI-036)"]
    end

    subgraph screens["8 single-context screens (.hidden-toggled sibling containers)"]
        sWork["1 Workspace<br/>3-pane: ranges · hex · context<br/>restyle (R-TUI-029)"]
        sA2L["2 A2L Explorer<br/>symbol table + hex<br/>restyle"]
        sMac["3 MAC View<br/>record table + hex<br/>restyle"]
        sMap["4 Memory Map<br/>coverage scaffold<br/>new (R-TUI-026)"]
        sIss["5 Issues Report<br/>validation table<br/>restyle/promoted (R-TUI-025)"]
        sPatch["6 Patch Editor<br/>inert view shell<br/>new (R-TUI-027)"]
        sDiff["7 A↔B Diff<br/>static placeholder<br/>new (R-TUI-028)"]
        sBook["8 Bookmarks<br/>coming-soon placeholder"]
    end

    subgraph dbscreens["screens_directionb.py (new) — scaffold widgets"]
        scaffolds["Memory Map · Patch Editor<br/>A↔B Diff · Bookmarks placeholder"]
    end

    subgraph modals["Modal screens — s19_app/tui/screens.py (re-skinned)"]
        modal["LoadFileScreen · SaveProjectScreen<br/>LoadProjectScreen<br/>Calm Dark re-skin (R-TUI-024)<br/>behavior unchanged"]
    end

    freeze["━━━━━━━━ ENGINE FREEZE BOUNDARY (HLR-014) — zero bytes changed below ━━━━━━━━"]

    subgraph services["Layer 3a — TUI services (orchestration boundary, FROZEN)"]
        loadsvc["services/load_service.py<br/>build_loaded_s19 / build_loaded_hex"]
        a2lsvc["services/a2l_service.py<br/>enrich_tags_and_render"]
        valsvc["services/validation_service.py<br/>build_validation_report"]
    end

    subgraph snapshot["Read-only snapshot + hex renderer (FROZEN)"]
        models["tui/models.py<br/>LoadedFile snapshot"]
        hexview["tui/hexview.py<br/>render_hex_view_text · find_string_in_mem<br/>MAX_HEX_BYTES / MAX_HEX_ROWS caps"]
        workspace["tui/workspace.py<br/>copy_into_workarea · validate_project_files<br/>setup_logging"]
    end

    subgraph parsers["Layer 1 — Parsers (FROZEN)"]
        core["core.py — S19File"]
        hexfile["hexfile.py — IntelHexFile"]
        a2l["tui/a2l.py — A2L parse/extract"]
        mac["tui/mac.py — parse_mac_file"]
    end

    subgraph engine["Layer 2 — Range / validation engine (FROZEN)"]
        rangeidx["range_index.py"]
        engineCore["validation/engine.py<br/>validate_artifact_consistency"]
        rules["validation/rules.py"]
        model["validation/model.py<br/>ValidationIssue / Severity"]
        colorpolicy["tui/color_policy.py<br/>SEVERITY_CLASS_MAP"]
    end

    tui --> app
    app --- styles
    app --> rail
    app --> cmdbar
    app --> screens
    rail -->|"key 1-8 / click → action_show_screen"| screens
    cmdbar -->|"palette select → action handler"| app
    cmdbar -->|"find → find_string_in_mem"| hexview
    cmdbar -->|"go-to → _handle_goto"| hexview
    screens --> dbscreens
    app --> modals

    app --> freeze
    freeze --> services
    app --> loadsvc
    app --> a2lsvc
    app --> valsvc
    app --> models
    app --> hexview
    app --> workspace

    loadsvc --> core
    loadsvc --> hexfile
    a2lsvc --> a2l
    valsvc --> engineCore
    hexview --> models
    workspace --> models
    engineCore --> rules
    engineCore --> rangeidx
    engineCore --> model
    rules --> model
    colorpolicy --> model

    classDef new fill:#fff4cc,stroke:#a07a00,stroke-width:1.5px,color:#2a2200
    classDef restyle fill:#e3f2fd,stroke:#1565c0,color:#0d3a73
    classDef frozen fill:#eef0f4,stroke:#5b6473,color:#2a2a30
    classDef boundary fill:#fde8e8,stroke:#c43a3a,stroke-width:2px,color:#7a1d1d

    class rail,cmdbar,styles,scaffolds,sMap,sPatch,sDiff,sBook new
    class app,sWork,sA2L,sMac,sIss,modal restyle
    class loadsvc,a2lsvc,valsvc,models,hexview,workspace,core,hexfile,a2l,mac,rangeidx,engineCore,rules,model,colorpolicy frozen
    class freeze boundary
```

**Reading the diagram.**

- **Yellow nodes** = new this batch (`rail.py`, `command_bar.py`, `screens_directionb.py`, `styles.tcss`, the four new scaffold screens).
- **Blue nodes** = restyled — re-laid-out in `app.py` / `screens.py`, same data wiring.
- **Grey nodes below the red boundary** = the frozen engine/services layer — zero bytes changed (verified by `git diff main`, [`04-validation.md`](../../04-validation.md) §2).
- The command bar's find/go-to inputs route to the **existing** `find_string_in_mem` / `_handle_goto` handlers — no new search or address-parsing code was added (LLR-004.6 / LLR-004.2, security finding S-1).
- The eight screens are **sibling containers toggled by the `.hidden` CSS class**, not `push_screen` stacks — this reuses the pre-batch view-toggle mechanism (LLR-002.1) and keeps the persistent command bar / footer and the existing `query_one` test harness intact.

---

## 2. Screen-routing flow

How the user moves between the eight screens. Every path ends at `action_show_screen`, which toggles `.hidden` on the eight sibling containers so exactly one is visible, and moves the rail's single active marker.

```mermaid
flowchart TD
    start([User input on any Direction B screen])

    railkey["Press 1-8<br/>or click a rail item"]
    palette["Press Ctrl+K → command palette<br/>type-to-filter → select a<br/>'go to screen' command"]
    findkey["Press / → find input"]
    gotokey["Press g → go-to input"]

    inputFocus{"A command-bar input<br/>holds focus?"}
    asText["Unmodified single key<br/>(g, 1-8, + - , .)<br/>inserted as text<br/>(LLR-004.5)"]

    showScreen["action_show_screen(name)"]
    toggle["Toggle .hidden on the<br/>8 sibling screen containers<br/>→ exactly one visible<br/>(LLR-002.1)"]
    marker["Move the rail active marker<br/>→ exactly one active<br/>(LLR-001.2)"]

    fileLoaded{"Is a LoadedFile<br/>present?"}
    content["Render screen content from<br/>the LoadedFile snapshot<br/>via existing update_* renderers"]
    empty["Render the neutral<br/>empty-state panel<br/>'no file loaded'<br/>(LLR-002.3)"]

    bookmark["Bookmarks (rail 8) →<br/>'coming soon' placeholder<br/>(LLR-002.2)"]
    findRoute["find → find_string_in_mem<br/>(existing handler, no new code)"]
    gotoRoute["go-to → _handle_goto<br/>(existing handler, no new code)"]

    start --> railkey
    start --> palette
    start --> findkey
    start --> gotokey

    railkey --> inputFocus
    inputFocus -- yes --> asText
    inputFocus -- no --> showScreen
    palette --> showScreen

    showScreen --> toggle
    toggle --> marker
    marker --> fileLoaded
    fileLoaded -- "screen 8" --> bookmark
    fileLoaded -- "yes (screens 1-7)" --> content
    fileLoaded -- "no (screens 1,2,3,4)" --> empty

    findkey --> findRoute
    gotokey --> gotoRoute

    classDef inputNode fill:#e3f2fd,stroke:#1565c0,color:#0d3a73
    classDef routeNode fill:#fff8e1,stroke:#a07a00,color:#3a2900
    classDef stateNode fill:#e8f5e9,stroke:#2e7d32,color:#0e3a13
    classDef altNode fill:#f3e5f5,stroke:#6a1b9a,color:#3a0d52

    class railkey,palette,findkey,gotokey inputNode
    class showScreen,toggle,marker,findRoute,gotoRoute routeNode
    class content,empty,bookmark stateNode
    class inputFocus,fileLoaded,asText altNode
```

**Reading the diagram.**

- Rail key, click and the command palette all converge on `action_show_screen` — there is one routing path, not three.
- The `inputFocus` gate is the LLR-004.5 suppression rule: while a command-bar input has focus, an unmodified single key (`g`, `1`–`8`, `+ - , .`) is typed as text and **does not** navigate; modified keys (`Ctrl+K`, `Ctrl+D`) still fire.
- After routing, the `fileLoaded` gate decides between real content and the neutral empty-state panel — activating Workspace / A2L Explorer / MAC View / Memory Map with no file shows the empty state, never an error or a blank pane.
- Bookmarks (screen 8) always routes to the "coming soon" placeholder regardless of load state — its persistence logic is deferred.

---

## 3. Two-regime responsive layout

The 120-column breakpoint that governs pane widths (HLR-007 / LLR-007.1 / LLR-008.1 / LLR-009.1 / LLR-010.1). This closes the A-03 contradiction between the fixed 84-column chrome and the 80×24 minimum.

```mermaid
flowchart LR
    width{"Terminal width?"}

    subgraph fixed["FIXED regime — width ≥ 120 columns"]
        fRail["Rail: full fixed width (22 cols)"]
        fWork["Workspace: left 22±2 · right 40±2<br/>center hex = 1fr remainder"]
        fA2L["A2L / MAC: hex pane 40±2<br/>table = 1fr remainder"]
    end

    subgraph prop["PROPORTIONAL regime — width < 120 columns"]
        pRail["Rail: collapsed icon-only (4±1 cols)"]
        pWork["Workspace: left 24%±3 · right 30%±3<br/>center hex = 1fr remainder (>0)"]
        pA2L["A2L / MAC: hex pane 35%±3<br/>table = 1fr remainder (>0)"]
    end

    sizes["Supported matrix:<br/>80×24 (min) · 120×30 (primary) · 160×40"]

    width -- "≥ 120 (120×30, 160×40)" --> fixed
    width -- "< 120 (80×24)" --> prop
    sizes -.-> width

    guard["Verified by the 27-baseline<br/>pytest-textual-snapshot matrix<br/>+ CV-04 119/120 boundary tests<br/>→ no clip, no overlap, no 0-width pane"]
    fixed --> guard
    prop --> guard

    classDef regimeFixed fill:#e3f2fd,stroke:#1565c0,color:#0d3a73
    classDef regimeProp fill:#fff4cc,stroke:#a07a00,color:#2a2200
    classDef metaNode fill:#e8f5e9,stroke:#2e7d32,color:#0e3a13

    class fRail,fWork,fA2L regimeFixed
    class pRail,pWork,pA2L regimeProp
    class sizes,guard metaNode
```

**Reading the diagram.**

- The same screen renders in either regime depending purely on terminal width — there is one layout, width-responsive, not two layouts.
- In the proportional regime the rail **collapses to an icon-only 4-column strip** so the side panes plus rail never sum past the 80-column minimum; the center hex pane always receives a strictly positive `1fr` remainder.
- The numeric tolerances (`±2` columns, `±3` percentage points) absorb border/padding rounding without permitting layout drift; both regimes are asserted as numbers by TC-017 / TC-019 / TC-021, not by inspection.
- The 27 SVG baselines (24 restyled-screen cells + 3 scaffold cells) plus the two CV-04 boundary tests are the automated layout-drift guard.

---

## 4. Diagram-source maintenance notes

- **Format.** All blocks use Mermaid source — render client-side. No build step, no rendered images, no extra dev dependency.
- **Single source of truth.** This file is the diagram artefact for the batch archive. The **living** canonical diagram is the repo-root [`docs/diagrams/architecture.md`](../../../../docs/diagrams/architecture.md), seeded this batch — keep that one current as `s19_app` evolves; this batch-archive copy is a point-in-time snapshot of the Direction B restyle.
- **Updating after the next batch.** When the deferred patch/diff/bookmark logic lands, the "scaffold" / "placeholder" labels on screens 6/7/8 in §1 should be updated and the freeze boundary re-drawn (a logic batch will touch the engine). Until then, the freeze boundary in §1 is an accurate architectural fact for batch-02.
- **Validation.** Render in any GitHub Markdown view to verify syntax. The diagrams use only Mermaid `flowchart` features — no plugins, no client-config injection.
