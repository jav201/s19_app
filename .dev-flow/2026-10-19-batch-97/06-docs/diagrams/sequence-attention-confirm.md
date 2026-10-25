# Diagram — Flow Execution run, pause and scoped Confirm (sequence)

> **Role:** `docs-writer`. Mermaid sequence block: a lane pauses on an external step and the engineer confirms it with `c` (US-137; HLR-147, LLR-147.3, 147.10, 147.13; AT-B97-09, AT-B97-20). Facts: `03-increments/increment-006.md` §1 and §1b; anchors on the tree at `c899113`.

```mermaid
sequenceDiagram
    autonumber
    actor ENG as Engineer
    participant FX as FlowExecutionPanel (flow_screens.py:2641)
    participant APP as S19TuiApp (app.py)
    participant SVC as flow_execution_service (run_chain_set)

    ENG->>FX: press Run (#fx_run)
    FX->>FX: disable Run and every Confirm (no blur, focus stays)
    FX->>APP: RunRequested(mode)
    APP->>SVC: run_chain_set(lanes, mode)
    SVC-->>APP: run record (lane B waits on an external step)
    APP->>FX: render_run(record)
    FX->>FX: cables from the record (cable_glyph): ▓ ok · □ into the waiting block · ░ after it
    FX->>FX: _rearm_attention(restart) → attention = lane B
    FX->>FX: scroll waiting card + Confirm into view (focus not moved)
    FX-->>ENG: waiting colour on card, cable, status word, Confirm; REQUIRED line "press c to confirm"
    Note over FX: dwell base stamped after refresh; CONFIRM_DWELL_S = 0.5 s
    ENG->>APP: press c
    APP->>APP: check_action: confirm_attention only on flow_execution
    APP->>FX: action_confirm_attention → confirm_attention()
    alt dwell elapsed and no run in flight
        FX->>APP: ExternalStepConfirmation per confirmed block
        APP->>SVC: re-run lane B
        SVC-->>APP: record
        APP->>FX: apply_confirmed_run → re-arm attention
        APP-->>ENG: status "Confirmed <chain> — re-running from block i/n."
    else a run is in progress
        APP-->>ENG: status "c: a run is in progress — wait for it to finish."
    end
    FX->>FX: no lane waits → scroll lanes home (x 0)
```

**Reading notes.** The panel alone writes the attention state (`_rearm_attention` is the only writer, code-reviewer F1). A second `c` within the same waiting entry confirms nothing (`c c` → 1 confirm, `04-validation.md` Layer A). A failed re-run writes `<chain> failed at block i/n — <reason>; Run re-runs the set.` and leaves the step unconfirmed. A lane with two external steps reaches its end because the app sends one confirmation per confirmed block (the Inc-6 HIGH, fixed in the increment).
