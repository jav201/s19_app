# Diagrams — s19_app TUI — Batch 2026-06-29-batch-21

Feature #8 patch-editor, slice 1. Two views:
(a) the save → `patches/` → scan → select → load round-trip (the C-12 producer→consumer chain);
(b) the patch-editor change-file row components.

---

## (a) Save → patches-folder → dropdown-scan → select → load (US-027 producer → US-026 consumer)

The C-12 chain: the **producer** (`write_change_document`) writes into `patches/`; the **consumer** (patch-screen dropdown) observes that handler-produced artifact — never a same-values direct write. AT-030a is the through-surface GATE over exactly this round-trip.

```mermaid
sequenceDiagram
    autonumber
    actor Op as Operator
    participant IO as changes/io.py<br/>write_change_document
    participant WS as workspace.py<br/>ensure_workarea
    participant FS as .s19tool/workarea/patches/
    participant App as app.py<br/>_scan_patch_change_files / _prefill
    participant Sel as screens_directionb.py<br/>Select#patch_doc_file_select
    participant CS as ChangeService.load

    Note over WS,FS: WORKAREA_PATCHES="patches" (workspace.py:19)<br/>mkdir at ensure_workarea (:47-48)

    rect rgb(235,245,255)
    Note right of Op: US-027 — producer
    Op->>IO: save change document
    IO->>FS: write under workarea/patches/ (io.py:1354)
    IO-->>App: save complete
    App->>App: _prefill_patch_change_files (:1428-1431)
    end

    rect rgb(240,255,240)
    Note right of Op: US-026 — consumer
    App->>FS: _scan_patch_change_files (:2217-2240)
    FS-->>App: sorted .json set<br/>(non-change ignored, symlinks skipped — F1)
    App->>Sel: set_change_files (:549/:587)
    Sel-->>Op: dropdown lists saved file<br/>(empty folder → placeholder, no crash — AT-030b)
    Op->>Sel: select entry
    Sel->>App: Select.Changed (:889)
    App->>App: is_relative_to(patches/) containment (:2315-2322)
    App->>CS: ChangeService.load(path)
    CS-->>Op: change document loaded
    end
```

**Node coverage on this flow:** AT-030a (GATE, full round-trip), AT-030a-R2 (save-while-open prefill), AT-030b (empty placeholder), AT-030c (directly-dropped file loadable), F1 (symlink skipped), TC-030 (scan returns sorted `.json` set), AT-031a/b + TC-031 (save lands in `patches/`, distinct).

---

## (b) Patch-editor change-file row — component / data view

```mermaid
flowchart TB
    subgraph Row["Patch-editor change-file row (screens_directionb.py)"]
        direction TB
        Sel["Select#patch_doc_file_select<br/>(:649) — lists patches/*.json, sorted"]
        Inp["Input — change-document path field"]
        Ctl["Controls — save / other change-doc actions"]
        subgraph Checks["Checks control (US-029)"]
            Btn["Button#patch_checks_run_button (:662)<br/>action run_checks (:856) — UNCHANGED"]
            Help["Label#patch_checks_help (:665-670)<br/>styles.tcss (:680-685)<br/>'Checks: runs the loaded change document's<br/>checks against the loaded image.'"]
            Btn --- Help
        end
    end

    Scan["app.py _scan_patch_change_files<br/>(:2217-2240) sorted + symlink-skip"] -->|set_change_files :549/:587| Sel
    Sel -->|Select.Changed :889 → containment :2315-2322| Load["ChangeService.load"]
    Save["write_change_document → patches/<br/>(io.py:1354)"] -->|_prefill_patch_change_files :1428-1431| Scan

    classDef new fill:#e6f3ff,stroke:#2b6cb0;
    classDef unchanged fill:#f0f0f0,stroke:#888;
    class Sel,Help,Scan,Save new;
    class Btn unchanged;
```

**Legend:** blue = added/changed this batch (dropdown, Checks help Label, scan, save-placement); grey = existing wiring left intact (Checks button id + `run_checks` action). The Checks Label is static explanatory text with no action wiring of its own.
