# batch-14 Save-Path Flow (US-015)

> Phase 6 artifact. Owner: `docs-writer`. **Audience:** engineers reviewing the
> US-015 save path. **Purpose:** show how the 16/32 Width selection and the S0
> header policy thread from the shipped Patch Editor save-back surface down to the
> emitter and back through the frozen reader-as-oracle.
>
> **Legend:** **NEW** = added/changed in batch-14 · **REUSED** = pre-existing,
> consumed unchanged · **FROZEN** = engine-frozen module (0 edits this batch).

## Save path: Width selector → emission → re-parse oracle

```mermaid
flowchart TD
    subgraph SHIPPED_SURFACE["Patch Editor save-back surface"]
        WS["Width selector<br/>#patch_saveback_width_button<br/>cycles 16 / 32, default 32"]:::new
        SBD["SaveBackDecision<br/>carries bytes_per_line"]:::new
    end

    H["app.py save-back handler<br/>S0 policy:<br/>source_s0_header or synth"]:::new

    subgraph S0POLICY["S0 header policy (32-byte mode)"]
        PRES["preserve captured source S0<br/>LoadedFile.source_s0_header<br/>(content-bearing)"]:::new
        SYNTH["synthesize minimal ASCII S0<br/>from output filename, len ≤ 252"]:::new
        EMPTY["16-byte mode:<br/>keep empty legacy S0"]:::new
    end

    CS["change_service.save_patched<br/>forwards bytes_per_line + s0_header"]:::new
    SPI["apply.py::save_patched_image<br/>S19-branch-only dispatch (C1)"]:::new
    EMIT["io.py::emit_s19_from_mem_map(<br/>mem_map, ranges,<br/>bytes_per_line=, s0_header=)"]:::new
    CIW["copy_into_workarea<br/>contained-write (no new write surface)"]:::reused
    FILE["written .s19 file on disk"]:::reused

    ORACLE["frozen S19File re-parse<br/>(reader-as-oracle)<br/>data-record map byte-equal?"]:::frozen

    WS --> SBD --> H
    H --> PRES
    H --> SYNTH
    H --> EMPTY
    PRES --> CS
    SYNTH --> CS
    EMPTY --> CS
    CS --> SPI --> EMIT --> CIW --> FILE
    FILE --> ORACLE

    classDef new fill:#1f6feb,stroke:#0b3d91,color:#ffffff;
    classDef reused fill:#2d333b,stroke:#768390,color:#ffffff;
    classDef frozen fill:#6e4a00,stroke:#3d2900,color:#ffffff;
```

## Capture seam (load side — feeds the preserve leg)

```mermaid
flowchart LR
    SRC[".s19 source file"]:::reused
    BLS["load_service.build_loaded_s19<br/>reads S19File.records, scans type=='S0'"]:::new
    LF["LoadedFile.source_s0_header<br/>(captured source S0, or None)"]:::new
    READER["frozen S19File.records<br/>(read-only)"]:::frozen

    SRC --> READER --> BLS --> LF
    LF -. "feeds the preserve leg<br/>in the save-back handler" .-> H["app.py save-back handler"]:::new

    classDef new fill:#1f6feb,stroke:#0b3d91,color:#ffffff;
    classDef reused fill:#2d333b,stroke:#768390,color:#ffffff;
    classDef frozen fill:#6e4a00,stroke:#3d2900,color:#ffffff;
```

## Notes

- The only new write delta is the `bytes_per_line` / `s0_header` threading; the
  contained-write itself (`copy_into_workarea`) is **REUSED** unchanged — no new
  write surface (`R-S19-SAVE-REUSE-001`).
- Dispatch is **S19-branch-only** (C1): the Intel-HEX save path never sees the
  S19-only `bytes_per_line` kwarg, verified by
  `test_tc220b_hex_save_unaffected_by_s19_only_kwargs`.
- The S0 capture is **read-only** against the frozen reader — `build_loaded_s19`
  scans `S19File.records`; no edit to `core.py`. The whole 7-path frozen set has
  **0 diffs vs main** (`test_tc027_*` / `test_tc031_*` / `test_tc032_*`).
- The reader-as-oracle re-parse is the data-integrity gate for both widths
  (data-record map byte-equal, 0 errors): `test_tc216_*` (32) / `test_tc217_*`
  (16), with the non-vacuous negative control `test_tc218_*`.
