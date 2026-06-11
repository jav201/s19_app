# Diagram — change/check → execution → report flow — Batch 2026-06-10-batch-07

How a v2 JSON document flows through the batch-07 system, from file on disk to rendered report. One reader serves both document kinds (`changes/io.py` + `validate.py`); the `kind` field routes to the apply engine (`changes/apply.py`) or the check engine (`changes/check.py`); their result objects (`ChangeSummary` / `CheckRunResult`, the canonical C-6 contract — each carrying its document's declaration faults in `issues`) are the **only** inputs the execution and report layers consume. The variant execution service (`services/variant_execution_service.py`) drives the loop over N variants per the hand-authored `project.json`; the report generator (`services/report_service.py`) writes the timestamped Markdown; the viewer (`screens.py::ReportViewerScreen`, key `t`) renders it read-only. Dashed callouts mark the security gates verified in Phase 4.

```mermaid
flowchart TD
    F["v2 JSON file<br/>change or check<br/>(format / version / kind /<br/>encoding / value_mode / entries)"] --> RD["Reader + validator<br/>changes/io.py + validate.py<br/>collect-don't-abort"]

    RD --> K{"kind?"}
    K -- "change<br/>(0 ERROR issues)" --> AP["Apply engine<br/>changes/apply.py::apply_change_document<br/>dispositions: applied / skipped-* / blocked<br/>before-capture pre-mutation<br/>linkage: standalone / MAC / A2L / both"]
    K -- "check" --> CK["Check engine<br/>changes/check.py::run_check_document<br/>pass / fail / uncheckable per entry<br/>mutates nothing"]
    K -- "any ERROR issue<br/>(collision, encoding, v1, syntax)" --> BL["Document blocked:<br/>zero writes / all uncheckable<br/>issues carried forward"]

    AP --> SB{"≥1 applied<br/>and S19 image?"}
    SB -- "yes — operator-edited filename" --> EMIT["Save-back<br/>changes/io.py::emit_s19_from_mem_map<br/>→ .s19tool/workarea/&lt;project&gt;/&lt;name&gt;-patched.s19"]
    SB -- "HEX image — declines,<br/>saved_path = None" --> CS
    EMIT --> CS["ChangeSummary<br/>before/after bytes · dispositions ·<br/>linkage · saved_path · issues"]
    AP --> CS
    BL --> CS
    BL --> CR
    CK --> CR["CheckRunResult<br/>expected/actual bytes · results ·<br/>counts · linkage · issues"]

    CS --> EX
    CR --> EX["Variant execution loop<br/>services/variant_execution_service.py<br/>project.json: batch | per-assignment | active<br/>fresh parse per variant, sequential,<br/>collect-don't-abort: len(results) == N"]
    M["project.json manifest<br/>(hand-authored this batch)"] --> EX

    EX --> RG["Report generator<br/>services/report_service.py::generate_project_report<br/>inventory · overview · before→after tables ·<br/>declaration errors · checklists ·<br/>hexdumps ± context (merged, 16-aligned) ·<br/>truncation markers"]
    RG --> RF["reports/&lt;UTC-ts&gt;(-NN)?-report.md<br/>under gitignored .s19tool/"]
    RF --> VW["Report viewer (key t)<br/>screens.py::ReportViewerScreen<br/>newest-first · read-only"]

    G1["GATE: text-codec allowlist<br/>(_is_text_encoding) · pre-encode<br/>length guard · size caps ·<br/>CHG-COLLISION = ERROR ·<br/>v1 → CHG-V1-FORMAT"]:::gate -.-> RD
    G2["GATE: filename containment<br/>sanitizer (traversal / absolute /<br/>CON.s19 rejected) · staged write ·<br/>must stay in workarea"]:::gate -.-> EMIT
    G3["GATE: manifest paths resolve<br/>inside project dir only ·<br/>escape/absolute/reparse → ERROR + skip ·<br/>size-capped read"]:::gate -.-> M
    G4["GATE: open_links=False ·<br/>no LinkClicked handler ·<br/>render size cap · raw bytes<br/>never logged"]:::gate -.-> VW

    classDef gate fill:#3a2a1e,stroke:#b8865b,color:#e8dcd0;
```
