# Diagram — batch-97 architecture

> **Role:** `docs-writer`. Mermaid architecture block for `06-docs/functionality.md` / `traceability-matrix.md`. Facts: the increment packets §1 / §2 (`03-increments/increment-001…009.md`), `01-requirements.md` §3 (shipped surfaces), `docs/architecture.md` §11 (batch-97 interface amendments). No module was created and no boundary moved (`PLAN.md` §Triggers, A1 not fired).

```mermaid
flowchart TB
    subgraph APP["s19_app/tui/app.py — S19TuiApp"]
        RAIL["rail · action_show_screen"]
        HDR["screen headers · WindowSection<br/>titled_header + OpenFolderChip + WindowHelpChip"]
        KEYS["c binding · check_action · key_condition<br/>action_confirm_attention"]
        KB["KeyBar (replaces Footer)<br/>row 1 global · row 2 window keys"]
    end

    subgraph SD["s19_app/tui/screens_directionb.py"]
        PE["PatchEditorPanel (pe_A)<br/>ledger · Inspector / JSON / Checks tabs<br/>PatchDocumentView · json_stamp_text · patch_layout"]
        CE["CheckEditorPanel (ce_A)<br/>IncludeTable ledger · REPORT FIELDS card<br/>check_layout · clip_param"]
    end

    subgraph FS["s19_app/tui/flow_screens.py"]
        FB["FlowBuilderPanel (fb_A)<br/>pipeline_text · pipeline_layout · KindChip ×7<br/>add form · nul_add_refusal"]
        FX["FlowExecutionPanel (fx_A)<br/>lanes · cable_glyph · lane_layout<br/>attention state · ModeToggle"]
    end

    subgraph WH["s19_app/tui/window_help.py"]
        TBL["WINDOW_KEYS (one window-key table)"]
        HELP["WindowHelpScreen · code-authored sections<br/>scrolls by key"]
        PACK["pack_key_row · global_tokens · KeyRow"]
    end

    subgraph SVC["services and style"]
        FOS["folder_open_service.py<br/>flows · session families<br/>resolve_chip_target · is_openable_chip_dir"]
        FPS["flow_persistence_service.py<br/>NUL refusal → FLOW-UNSAFE-REF"]
        VES["variant_execution_service.py<br/>NUL → MANIFEST-PATH-ESCAPE"]
        FES["flow_execution_service.py<br/>run_chain_set · English strings"]
        STY["insight_style.py<br/>WAITING_HUMAN · CRC_FAMILY"]
    end

    LPS["screens.py · LoadProjectScreen<br/>dismisses with projects[index]"]

    RAIL --> PE
    RAIL --> CE
    RAIL --> FB
    RAIL --> FX
    HDR -->|"chip press"| FOS
    HDR -->|"? chip"| HELP
    PE -->|"Load / Add / Save / paste → refresh_entries(document=)"| PE
    FB -->|"load / save flow"| FPS
    FX -->|"import / save set"| FPS
    FX -->|"Run · Confirm"| FES
    FES --> VES
    FB -.->|"CRC cards"| STY
    FX -.->|"waiting elements"| STY
    KEYS -->|"c on flow_execution only"| FX
    TBL --> PACK
    TBL --> HELP
    PACK --> KB
    KEYS -->|"live / dim state"| KB
    APP -->|"p · Load project"| LPS
```

**Reading notes.** Solid arrows are calls or data the packets name; dotted arrows are colour tokens. `WINDOW_KEYS` feeds both the key bar's second row and each help's keys block (LLR-150.1), so the two cannot disagree. The `c` binding acts only when Flow Execution is the active screen (`check_action`). The NUL refusal sits in the persistence and manifest parsers, before any path is resolved (LLR-146.14). Every file-derived string on the four screens is painted through `safe_text` or a `markup=False` widget (LLR-144.7, 145.5, 146.8, 147.6); that sink is not drawn, to keep the figure readable.
