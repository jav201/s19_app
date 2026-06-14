# Compare flow — A↔B Diff (US-006, batch-09)

End-to-end path from the operator's inline source selection in the A↔B Diff
screen to the collision-safe write of the complete diff report. Guard-rail
callouts (dashed nodes) mark the decisions that keep the feature layered, safe,
and honest.

```mermaid
flowchart TD
    OP([Operator: A2B Diff screen, press 7]) --> SEL[Inline source select<br/>variant list + external path]
    SEL --> CS["compare_service.compare_images<br/>(tui/services/compare_service.py)"]

    CS --> ENG["compare.diff_mem_maps<br/>(s19_app/compare.py — headless)"]
    ENG --> RES["ComparisonResult<br/>runs / stats / notes / diagnostics / refused"]

    RES --> REFUSED{refused?}
    REFUSED -- yes --> STATUS[Status line: diagnostic<br/>screen keeps running, no write]
    REFUSED -- no --> RENDER["Rich render in AbDiffPanel<br/>run list + bounded A/B hex windows<br/>(DISPLAY-capped)"]

    RENDER --> TRIG{Operator triggers report?}
    TRIG -- no --> DONE([Stay on screen])
    TRIG -- yes --> GEN["diff_report_service<br/>generate_diff_report (Markdown)<br/>generate_diff_report_html (HTML)"]

    GEN --> MD["Markdown: COMPLETE<br/>fenced ```diff cue (-/+)"]
    GEN --> HTML["HTML: COMPLETE<br/>html.escape, inline CSS, no script"]

    MD --> DEST["_resolve_destination"]
    HTML --> DEST

    DEST --> DESTQ{project active?}
    DESTQ -- yes --> PROJ["&lt;project&gt;/reports/<br/>inside .s19tool/"]
    DESTQ -- no --> PROMPT["operator-supplied dir<br/>expanduser().resolve() → is_dir()?"]
    PROMPT -- invalid/empty/missing --> REFW[Refuse: 0 files, diagnostic]
    PROMPT -- valid --> WRITE
    PROJ --> WRITE["Collision-safe write<br/>tool-generated name, -NN sibling,<br/>never overwrite"]
    WRITE --> PATHS[Status line: .md + .html paths]

    %% Guard-rail callouts
    G1[["GUARD: service-route only<br/>view never calls diff_mem_maps"]] -.-> CS
    G2[["GUARD: headless engine<br/>no Textual / no parser import"]] -.-> ENG
    G3[["GUARD: file COMPLETE vs<br/>display-capped — caps bound<br/>the screen, not the file (G-9)"]] -.-> RENDER
    G4[["GUARD: html.escape + no script /<br/>external / CDN / network (R-10)"]] -.-> HTML
    G5[["GUARD: no implicit Downloads<br/>default — operator-prompt only (G-8)"]] -.-> PROMPT
    G6[["GUARD: no logging of<br/>report body / memory bytes (F-S-07)"]] -.-> GEN

    classDef guard fill:#fff3cd,stroke:#d39e00,color:#5c4500,stroke-dasharray:4 3;
    classDef refuse fill:#f8d7da,stroke:#b02a37,color:#5c1a1f;
    class G1,G2,G3,G4,G5,G6 guard;
    class STATUS,REFW refuse;
```

## Legend

- **Solid nodes** — the runtime flow.
- **Dashed yellow callouts** — guard rails enforced by tests/inspections this
  batch (service-route only, headless engine, file-complete-vs-display-capped
  per G-9, HTML safety per R-10, no-Downloads-default per G-8, no-logging per
  F-S-07).
- **Red nodes** — refusal terminals: no file is written and a diagnostic is
  surfaced; the screen keeps running.

> The report file is always COMPLETE; only the on-screen render is capped
> (`REPORT_MAX_TOTAL_BYTES` / the 128-region cap relocated to the display path).
> The compare engine is parser-free and Textual-free, making it the reusable
> substrate batch-10 verify-on-save will consume.
