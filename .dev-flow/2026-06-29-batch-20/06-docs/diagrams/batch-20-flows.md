# Batch-20 flows — declared-region round-trip + skip-count

> Mermaid diagrams for the D-1 (save/load round-trip) and D-2 (malformed-line skip count) flows.
> Node labels carry the verified `file:line` seams from the final tree.

## (a) D-1 — declared-region round-trip (dialog → capture → save → project.json → load → seed)

```mermaid
sequenceDiagram
    autonumber
    actor Op as Operator
    participant Dlg as ReportViewerScreen<br/>(screens.py)
    participant App as S19TuiApp<br/>(app.py)
    participant Writer as manifest_writer<br/>(reused, batch-19)
    participant Disk as project.json
    participant Reader as variant_execution_service<br/>read_project_manifest (reused)

    Note over Op,Dlg: declare regions, then Generate
    Op->>Dlg: type name,start,end lines + press Generate
    Dlg->>Dlg: _parse_declared_regions (screens.py:543)
    Dlg->>App: GenerateRequested(declared_regions)
    App->>App: capture → self._declared_regions<br/>(app.py:1899/1908) [HLR-027]

    Note over Op,Disk: Save project
    Op->>App: Save project
    App->>App: _handle_save_dialog (app.py:3791)
    App->>App: _write_and_verify_manifest (app.py:3802)
    App->>Writer: write_project_manifest(declared_regions=...)<br/>(app.py:3867)
    Writer->>Disk: serialize_manifest — array written<br/>only when non-empty (key omitted if empty)
    Note right of Disk: verify leg re-reads disk,<br/>NOT threaded from state

    Note over Op,Dlg: Load project later
    Op->>App: Load project
    App->>App: _handle_load_project (app.py:3977)
    App->>Reader: read_project_manifest(project_dir)
    Reader-->>App: ProjectManifest.declared_regions<br/>(names re-scrubbed on read)
    App->>App: adopt → self._declared_regions<br/>(else () reset, no cross-load leak) [HLR-028]

    Note over Op,Dlg: Reopen Reports dialog
    Op->>App: open Reports
    App->>Dlg: action_view_reports passes regions (app.py:1874)
    Dlg->>Dlg: compose seeds #report_declared_regions TextArea<br/>(screens.py:691-698 / 703-708) — inverse of parser
    Dlg-->>Op: regions restored, pre-filled
```

## (b) D-2 — skip-count flow (parse → count → notify with zero-suppression)

```mermaid
flowchart TD
    A[Operator presses Generate] --> B["_parse_declared_regions(text)<br/>screens.py:543"]
    B --> C{Per line}
    C -->|blank / whitespace-only| D[skip — NOT counted<br/>intentional spacing]
    C -->|wrong field count| E[malformed → count++]
    C -->|field won't parse /<br/>DeclaredRegion rejects| F[invalid → count++]
    C -->|valid| G[append DeclaredRegion<br/>name scrubbed at __post_init__]
    D --> H["returns (regions, skipped)"]
    E --> H
    F --> H
    G --> H
    H --> I{"skipped >= 1 ?<br/>screens.py:807-813"}
    I -->|yes| J["self.notify('N region line(s) skipped')<br/>count-only — no line text echoed"]
    I -->|no| K[no toast — zero-suppression]
    J --> L[post GenerateRequested with valid regions]
    K --> L
```

> Notes
> - In (a) the **capture** happens on Generate, not on keystroke — a region typed but never Generated is never saved (AT-027b).
> - In (a) the **verify** leg of save re-reads the on-disk manifest and is intentionally not threaded from `self._declared_regions` (TC-027.1).
> - In (b) malformed and invalid are **mutually exclusive** per line; blank lines never increment the count (AT-029c); the notify text is count-only so unscrubbed operator input is never echoed (LLR-029.3).
