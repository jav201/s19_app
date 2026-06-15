# Diagram — Save + Verify-on-Save Flow (batch-10)

> The end-to-end path from a TUI save-back to the hybrid quiet/loud verify surface.
> Covers US-008 (Intel HEX emitter + save-back) and US-009 (verify-on-save).
> Guard-rail callouts are dashed notes; every node cites its implementation site.

```mermaid
flowchart TD
    A["TUI save-back<br/>app.py:1364 → ChangeService.save_patched<br/>change_service.py:851"]
    --> B["save_patched_image (apply.py:574)<br/>select emitter by source_kind<br/>_SAVE_BACK_EMITTERS (apply.py:101)"]

    B -->|source_kind == 'hex'| C["emit_intel_hex_from_mem_map<br/>io.py:1424 → Intel HEX text"]
    B -->|source_kind == 's19'| D["emit_s19_from_mem_map<br/>io.py:1300 → S19 text"]
    B -->|other, e.g. 'mac'| R["REFUSE: CHG_HEX_SAVE_UNSUPPORTED<br/>apply.py:94 — 0 writes"]

    C --> E
    D --> E["Stage + place into workarea<br/>copy_into_workarea (workspace.py)<br/>containment + collision-suffix<br/>apply.py:687-692"]

    E --> F["returns 2-tuple<br/>(Optional[Path], List[ValidationIssue])<br/>apply.py:581 — UNCHANGED"]

    F --> G["ChangeService stamps saved_path,<br/>then verify_written_image (verify.py:119)<br/>change_service.py:867"]

    G --> H["re-read written file by file_type<br/>_reread_mem_map (verify.py:81)<br/>IntelHexFile (hexfile.py:20) / S19File"]

    H --> I["diff_mem_maps(intended, reread)<br/>compare.py:272 → runs, stats"]

    I --> J{"runs empty?"}
    J -->|yes| K["VerifyResult status='verified'<br/>verify.py:165"]
    J -->|no| L["VerifyResult status='mismatch'<br/>carries runs + stats"]

    K --> M
    L --> M["stamp last_summary.verify_result<br/>(C-10 carrier) change_service.py:869"]

    M --> N["app hybrid surface<br/>_surface_verify_result (app.py:1420)"]
    N --> O{"status"}
    O -->|verified| P["QUIET: 'Saved + verified: name'<br/>single status line (app.py:1464)<br/>no modal / no notice"]
    O -->|mismatch| Q["LOUD: error notice naming file +<br/>_verify_mismatch_summary (app.py:1476)<br/>per-kind run/byte counts over DIFF_KIND_DOMAIN"]

    %% ---- guard-rail callouts ----
    GR1["GUARD: emitter lives in io.py,<br/>NOT the engine-frozen hexfile.py<br/>(D-A=(c) / H-5 reversal)"]
    GR1 -.-> C
    GR2["GUARD: 2-tuple return preserved —<br/>VerifyResult rides last_summary,<br/>0 unpack-site edits (M-1)"]
    GR2 -.-> F
    GR3["GUARD: counts/addresses only,<br/>no raw mem_map byte leaked (F-S-05)"]
    GR3 -.-> Q
    GR4["GUARD: collect-don't-abort —<br/>mismatch keeps the file on disk"]
    GR4 -.-> L
```

## Legend / guard-rail rationale

| # | Guard rail | Why it matters |
|---|------------|----------------|
| GR1 | Emitter placed in `s19_app/tui/changes/io.py` (next to `emit_s19_from_mem_map`), **not** `hexfile.py`. | `hexfile.py` is in `_ENGINE_PATHS` (git-frozen vs `main`); writing there trips three engine-frozen guards. `io.py` is unfrozen and not package-root → zero guards tripped. (D-A reversal, operator R2 / H-5.) |
| GR2 | `save_patched_image` keeps its 2-tuple return `(Optional[Path], List[ValidationIssue])`. | The `VerifyResult` rides `ChangeService.last_summary.verify_result` — a back-compatible carrier — so all 5 existing 2-tuple unpack sites stay valid with zero edits (M-1 / C-10). |
| GR3 | The mismatch summary reports per-kind **run/byte counts** and addresses only. | `VerifyResult` carries `DiffRun` (addresses) + `DiffStats` (counts) — never raw byte values — so no image content leaks into a TUI notification (F-S-05). |
| GR4 | A mismatch does **not** delete or suppress the written file. | Collect-don't-abort: the operator requested the save; the file is kept so it can be inspected, and the loud notice tells them not to trust it (HLR-004 / LLR-003.3). |
