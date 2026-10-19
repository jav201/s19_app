# Diagram — chain-set save → load → re-run (sequence)

> **Role:** `docs-writer`. Mermaid sequence block: the US-007 end-to-end scenario (AT-B94-24, ratified two-node realization `DDR-2026-10-12-batch-94#COND-2`; contract HLR-017…021; `03-increments/increment-003` §1).

```mermaid
sequenceDiagram
    autonumber
    actor OP as Operator (calibration engineer)
    participant FX as FlowExecutionPanel (fx_a)
    participant FP as flow_persistence_service.py
    participant FE as flow_execution_service.py
    participant DISK as workarea/flowsets/<name>.json
    participant LOG as RUN LOG strip
    participant RPT as chain-set report

    OP->>FX: Import… (template picker) ×2
    FX->>FP: load_flow_json — one lane per template, side by side
    Note over FX: cancel adds 0 lanes · corrupt refused · duplicates uniquify _<N>
    OP->>FX: Bind — per-lane inputs (lane A ≠ lane B)
    Note over FX: a Bind writes only its own lane's record
    OP->>FX: Run (mode Select untouched → sequential default)
    FX->>FE: run_chain_set — wraps the union run_flow per chain
    FE->>LOG: one ▶ started + one terminal line per chain
    FE->>RPT: one input-provenance line per bound input
    OP->>FX: Save Set
    FX->>FP: save_chain_set (v1 envelope: chains + bound inputs + recorded outputs)
    FP->>DISK: flowsets/<name>.json — empty/hostile sets write NOTHING (V1–V6 fail-closed)
    OP->>FX: Load Set + re-run
    FX->>FP: load_chain_set
    FP->>FX: REPLACES the lanes — a restore, never a merge
    alt a bound input moved
        FX->>FX: per-lane provenance-mismatch notice — never a silent stale run
    else a chain's template is gone
        FX->>LOG: that chain is skipped and NAMED
    else clean reload
        FX->>FE: re-run — both chains' outputs regenerate without re-binding
    end
```

**Pins.** Sequential is the untouched default; the parallel mode is operator-selected per run, isolates a failed chain to its own lane, and the selected mode is captured in the run record (C-10 — the acceptance drives the non-default). Save/load reuses the containment-checked persistence idiom; the reload is a replace, not a merge. The UI node `tests/test_tui_flow_execution_b94.py:846` drives the whole chain end-to-end; the service node `tests/test_flow_chainset_b94.py:484` is the declared supplementary arm (`DDR-2026-10-12-batch-94#COND-2`).
