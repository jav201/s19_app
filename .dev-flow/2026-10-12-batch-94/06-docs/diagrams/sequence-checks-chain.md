# Diagram — the C-12 check-spec chain (sequence)

> **Role:** `docs-writer`. Mermaid sequence block: Check Editor writes `.chk.json` → A2B Diff loads THAT file → the report carries the `## Checks` addendum. The acceptance observes only the shipped producer→consumer chain (C-12 output-then-consume; contract `01-requirements.md` HLR-010, D-4; AT-B94-11/12, TC-B94-13/15/16).

```mermaid
sequenceDiagram
    autonumber
    actor OP as Operator (calibration engineer)
    participant CE as CheckEditorPanel (ce_a)
    participant IO as changes/io.py (v2 writer)
    participant DISK as workarea/patches/*.chk.json
    participant A2B as AbDiffPanel (A2B Diff)
    participant DRS as diff_report_service.py
    participant RPT as A2B diff report markdown

    OP->>CE: collect A2L parameters + memory locations
    OP->>CE: Write
    CE->>IO: ChangeDocument(kind="check")
    IO->>DISK: write_change_document — the .chk.json double suffix survives _safe_name
    Note over DISK: kind="check" — write/validate ONLY<br/>apply gate refuses: blocked, 0 writes (apply.py:320)
    OP->>CE: Validate
    CE->>CE: run_check_document — one verdict row per entry
    OP->>A2B: open the file dropdown
    A2B->>IO: folder scan — .chk.json listed suffix-distinguished from patch files
    OP->>A2B: load THAT file
    A2B->>DRS: generate_diff_report + the check spec
    DRS->>RPT: _check_addendum_lines — the ## Checks addendum
    Note over RPT: 100% of the declared parameter/location names<br/>escape via md_safe — hostile text inert (C-17)
    OP->>RPT: read the report — the declared items are there
```

**Pins.** The chain is accepted only through the shipped surfaces — a hand-written file fed to the consumer is not the acceptance (C-12). The write/validate-only ruling is enforced by the existing kind gate, not by convention. Emitted form pinned by `evidence/p1_probe_diff_report_emitted.txt` + `evidence/p1_probe_chk_roundtrip.txt`.
