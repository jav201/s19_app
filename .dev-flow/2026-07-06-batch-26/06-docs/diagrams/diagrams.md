# Diagrams — Entropy / Data-Classification Viewer (batch-26, feature #12(b))

> Three Mermaid diagrams: (a) architecture, (b) US-036 viewer sequence, (c) US-037 report data-flow.
> **Engine-frozen boundary is drawn explicitly in (a) — all entropy code sits OUTSIDE it.**
> Facts sourced from the shipped code and `01-requirements.md` / `04-validation.md` (see `../traceability-matrix.md`).

---

## (a) Architecture — where `entropy_service` sits

`entropy_service.py` is a NEW, headless, pure-arithmetic module. It reads the same `LoadedFile.mem_map` / `VariantExecutionResult.mem_map` substrate the rest of the tool carries, and feeds two consumers: the report section (US-037) and the viewer modal (US-036). It lives entirely OUTSIDE the engine-frozen set — it derives ranges itself and imports no parser and no Textual symbol.

```mermaid
flowchart TB
    subgraph FROZEN["ENGINE-FROZEN SET (read-only — 0 diff vs origin/main)"]
        direction LR
        core["core.py / hexfile.py<br/>range_index.py"]
        valid["validation/"]
        a2lmac["tui/a2l.py · tui/mac.py"]
        colpol["tui/color_policy.py<br/>(sev-* — NOT reused)"]
    end

    subgraph SUBSTRATE["Substrate (in-memory, already flows)"]
        loaded["LoadedFile.mem_map<br/>Dict[int,int]"]
        varres["VariantExecutionResult.mem_map<br/>(capture_mem_map=True)"]
    end

    subgraph ENTROPY["Entropy feature (NEW — outside frozen set)"]
        svc["entropy_service.py (US-035)<br/>compute_entropy(mem_map)<br/>→ list[EntropyWindow]<br/>headless · pure · deterministic"]
        report["report_service.py (US-037)<br/>_entropy_lines(result)<br/>+ ReportOptions.include_entropy"]
        modal["screens.py (US-036)<br/>EntropyViewerScreen<br/>ENTROPY_BAND_COLOUR (own map)"]
        appact["app.py (US-036)<br/>action_show_entropy · 'e' key<br/>_focus_entropy_target"]
    end

    reportfile["Report file on disk<br/>&lt;project&gt;/reports/*.md<br/>(### Entropy section)"]
    hexview["Main hex view<br/>(focus moved on jump)"]

    core -.->|builds| loaded
    loaded --> svc
    varres --> svc
    svc --> report
    svc --> modal
    report --> reportfile
    appact -->|push_screen| modal
    modal -->|dismiss with target addr| appact
    appact -->|_apply_goto + update_hex_view| hexview

    colpol -. "read-only ref<br/>(sev-* deliberately NOT used)" .-> modal

    classDef frozen fill:#f8d7da,stroke:#a33,color:#111;
    classDef newcode fill:#d4edda,stroke:#3a3,color:#111;
    class core,valid,a2lmac,colpol frozen;
    class svc,report,modal,appact newcode;
```

---

## (b) Sequence — US-036 viewer flow (`e` → modal → jump → focus)

Operator presses `e`; the app snapshots the loaded image's `mem_map` at push time, the modal renders the band strip + jump list, the operator activates a jump row, the modal dismisses **with the target address**, and the host moves the hex view there. No-image is a safe no-op.

```mermaid
sequenceDiagram
    autonumber
    actor Op as Operator
    participant App as S19TuiApp
    participant Svc as entropy_service.compute_entropy
    participant Modal as EntropyViewerScreen
    participant Hex as Main hex view

    Op->>App: press "e" (BINDINGS → action_show_entropy)
    alt no image loaded
        App-->>Op: notify "No image loaded — nothing to classify." (no-op)
    else image loaded
        App->>App: loaded = current_file (snapshot mem_map at push time)
        App->>Svc: compute_entropy(loaded.mem_map)
        Svc-->>App: list[EntropyWindow] (start, band, H, low_confidence)
        App->>Modal: push_screen(EntropyViewerScreen(mem_map), _focus_entropy_target)
        Modal->>Modal: compose strip (█ per window, ENTROPY_BAND_COLOUR)<br/>+ jump list (0xADDR band H=…), capped at 512 (+truncation indicator)
        Modal-->>Op: render band strip + jump-to-address list
        Op->>Modal: activate a jump row (on_list_view_selected)
        Modal->>App: dismiss(target address)  %% ModalScreen[Optional[int]]
        App->>App: _focus_entropy_target(target)
        App->>Hex: _apply_goto("main", target) + update_hex_view(target)
        Hex-->>Op: hex view focused at the window's start address
    end
    Note over Op,Modal: Close without selection → dismiss(None) → no-op, app state undisturbed
```

---

## (c) Data flow — US-037 report section (`mem_map` → written report file)

Inside `generate_project_report`'s per-variant loop, when `include_entropy` is true, `_entropy_lines(result)` runs `compute_entropy` over the variant's `result.mem_map`, counts windows per band, and emits a band-summary section through the budget-charged `emit()` helper — after the hexdump. The lines land in the single report file written once at the end.

```mermaid
flowchart LR
    memmap["result.mem_map<br/>(populated via<br/>capture_mem_map=True)"]

    subgraph LOOP["generate_project_report — per-variant loop"]
        direction TB
        gate{"options.<br/>include_entropy?"}
        elines["_entropy_lines(result)"]
        compute["compute_entropy(mem_map)<br/>→ list[EntropyWindow]"]
        count["count windows per band<br/>(low-confidence flagged)"]
        md["### Entropy<br/>- **band**: N window(s)"]
        emptychk{"mem_map<br/>empty?"}
        nodata["### Entropy<br/>No mapped bytes -<br/>entropy not computed."]
        emit["emit(...) — budget-charged<br/>(after _hexdump_section)"]
    end

    write["target.write_text(...)<br/>&lt;project&gt;/reports/&lt;report&gt;.md"]
    disk["Report file on disk<br/>(### Entropy per variant)"]

    memmap --> gate
    gate -->|"False"| write
    gate -->|"True"| elines
    elines --> emptychk
    emptychk -->|"yes"| nodata --> emit
    emptychk -->|"no"| compute --> count --> md --> emit
    emit --> write --> disk

    Note1["include_entropy=False ⇒ section omitted,<br/>report byte-identical to pre-feature baseline"]
    gate -.-> Note1
```

> **Read-back (validation, C-12):** the US-037 gate re-reads the WRITTEN file from disk and asserts the `### Entropy` heading + band lines are present under the variant — it never calls `_entropy_lines` directly (see `../traceability-matrix.md` §1b, `test_report_contains_entropy_section_on_disk`).
