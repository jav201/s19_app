# Diagram — batch-94 architecture

> **Role:** `docs-writer`. Mermaid architecture block for `06-docs/functionality.md` / `traceability-matrix.md`. Facts: `docs/architecture.md` §10 "Batch-94 declarations" (as-built), `01-requirements.md` §3/§4 (surfaces), the four increment packets §2 (file sets).

```mermaid
flowchart TB
    subgraph RAIL["Activity rail — 12 ordered surfaces (app.py)"]
        R1["Patch Editor · 6"]
        R2["Check Editor · = (show=False)"]
        R3["Flow Builder · 8"]
        R4["Flow Execution · ] (show=False)"]
        R5["Issues · 9"]
    end

    subgraph SD["s19_app/tui/screens_directionb.py"]
        PE["PatchEditorPanel (pe_b rework)<br/>expanded editor · dirty-guarded Load<br/>variant selector retired · Apply loaded changes"]
        CE["CheckEditorPanel (ce_a, NEW)<br/>A2L parameter + memory-location collector<br/>write/validate only — 0 apply controls"]
        A2B["AbDiffPanel (A2B Diff)<br/>dropdown lists .chk.json suffix-distinguished"]
    end

    subgraph FS["s19_app/tui/flow_screens.py (NEW module, R8)"]
        FB["FlowBuilderPanel (fb_a)<br/>palette · canvas _Grid · cables<br/>patch / CRC / A2B-diff blocks"]
        FX["FlowExecutionPanel (fx_a)<br/>per-chain lanes · per-lane rebind<br/>RUN LOG strip · Save/Load Set"]
    end

    subgraph IV["s19_app/tui/issues_view.py"]
        IP["GroupedIssuesPanel<br/>curated-set reclassification<br/>single counts fold"]
    end

    subgraph SVC["services"]
        IO["changes/io.py<br/>v2 grammar · .chk.json suffix"]
        CHK["changes/check.py<br/>run_check_document"]
        APP["apply.py<br/>kind gate — check docs never apply"]
        DRS["diff_report_service.py<br/>## Checks addendum"]
        FM["flow_model.py<br/>BLOCK_A2B · binding grammar"]
        FP["flow_persistence_service.py<br/>templates · chain-sets"]
        FE["flow_execution_service.py<br/>run_flow · run_chain_set (sequential default / parallel per chain)"]
    end

    UTIL["s19_app/utils.py · safe_text (C-17 sink)<br/>markdown_safety.md_safe for reports"]

    R1 --> PE
    R2 --> CE
    R3 --> FB
    R4 --> FX
    R5 --> IP

    CE -->|"write_change_document kind=check"| IO
    IO -->|".chk.json on disk"| A2B
    A2B -->|"load + addendum"| DRS
    CE -->|"validate"| CHK
    PE -->|"apply loaded changes (gate)"| APP
    CHK -.->|"check spec → blocked, 0 writes"| APP

    FB -->|"per-kind serialization"| FM
    FB -->|"save template / dedup suffix"| FP
    FX -->|"import template"| FP
    FX -->|"run_chain_set wraps run_flow"| FE
    FM --> FE
    FE -->|"A2B arm + provenance lines"| DRS
    FX -->|"save/load set (flowsets/*.json)"| FP

    IP -->|"adjust_counts_for_a2l_triage"| IP
    PE -.-> UTIL
    CE -.-> UTIL
    FB -.-> UTIL
    FX -.-> UTIL
    DRS -.-> UTIL
```

**Reading notes.** Solid arrows are the shipped information flows (the contract's IFC Part A blocks, `01-requirements.md` §4). Dotted arrows are the safety sink (`safe_text` / `md_safe` — every file-derived string rides it, C-17). The two surfaces Check Editor and Flow Execution entered the rail as entries 11 and 12 with non-digit bindings `=` / `]` (`show=False`, PDR-ratified). Flow semantics stay in `services/flow_*`; the panels are pure view (`docs/architecture.md` §10, R8).
