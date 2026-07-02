# Diagrams — Batch 2026-07-01-batch-23 (US-028 inline variant dropdown)

> Three views of the shipped behavior: (a) the switch sequence with its guard ladder, (b) the dropdown's state machine, (c) the C-12 persist-then-consume chain. Extends the §6.2 sequence diagram in 01-requirements.md with the guards and re-sync as implemented. All symbols cited in `functionality.md` §2 with file:line.

---

## (a) Switch sequence — pick → guards → threaded load → re-sync

```mermaid
sequenceDiagram
    actor Op as Operator
    participant Sel as Select#patch_variant_select
    participant P as PatchEditorPanel
    participant App as S19TuiApp
    participant LP as load pipeline (worker thread)

    Op->>Sel: pick variant_id
    Sel->>P: Select.Changed
    Note over P: blank sentinel (Select.NULL)?<br/>→ dropped in panel (no message)
    P->>App: VariantSelected(variant_id)
    Note over App: guard ladder (handler)<br/>1. same-as-active → drop (absorbs repopulate echo)<br/>2. load in flight (_variant_load_in_flight) → drop + status<br/>   "Variant switch ignored - a load is already in progress."
    App->>App: _handle_select_variant(variant_id)  — reused UNCHANGED
    Note over App: reused guards: no variant set /<br/>unknown id / missing file → status, no load
    App->>LP: stamp _pending_variant_id + load_from_path
    LP-->>App: PreparedLoad
    App->>App: _apply_prepared_load → variant_set.active_id = chosen
    App->>App: update_project_labels (single funnel)
    App->>P: _refresh_patch_variant_select → set_variants(options, value=active_id)
    App-->>Op: label «project»:«chosen» (i/N) + chosen variant's image + dropdown value re-synced
```

---

## (b) Dropdown state machine

```mermaid
stateDiagram-v2
    [*] --> Disabled_NoProject : first paint (disabled=True at construction)

    Disabled_NoProject : No project — disabled,\nplaceholder "Variants in project", 0 options
    Disabled_Degenerate : N < 2 variants — disabled,\nplaceholder, 0 options, no preselection
    Enabled : N >= 2 — enabled,\noptions in model order, value = active_id
    InFlight : Load in flight — picks suppressed\n(status line; displayed value may lag)

    Disabled_NoProject --> Enabled : project load, N >= 2
    Disabled_NoProject --> Disabled_Degenerate : project load, N == 1
    Disabled_Degenerate --> Enabled : variant append reaches N == 2\n(refresh via update_project_labels tail)
    Enabled --> Disabled_Degenerate : project switch to N < 2
    Enabled --> Disabled_NoProject : project switch away / none
    Enabled --> InFlight : pick (activation dispatched)\nor any load starts
    InFlight --> Enabled : apply-finalize — active_id stamped,\nvalue self-heals to active_id
```

Notes: every transition into a populated state runs `set_options` **before** the value assignment (textual 8.2.5 resets the selection on `set_options` and emits `Changed(Select.NULL)` + `Changed(active_id)` — absorbed by the panel NULL filter and the same-as-active short-circuit). There is no project-close path in the codebase; state changes arrive via project load/switch and variant append, all funneled through `update_project_labels`.

---

## (c) C-12 persist chain — switch → save → project.json → fresh load consumes

```mermaid
flowchart LR
    A[Dropdown switch<br/>in patch editor] -->|existing pipeline| B[in-memory<br/>variant_set.active_id = chosen]
    B -.->|NO disk write<br/>TC-035.6: project dir byte-identical| B
    B --> C[Operator: project save<br/>shipped save flow]
    C --> D["project.json (handler-written)<br/>manifest_writer.py:319<br/>active_variant: chosen_id"]
    D --> E[Fresh app instance<br/>unmodified load path]
    E --> F["chosen variant active:<br/>label «proj2»:«chosen» (i/N)"]

    D -. "AT-035b gate: raw json.loads re-read,<br/>NOT the writer's oracle" .-> G[["AT-035b<br/>output-then-consume"]]
    F -. "consume leg: 'a' sorts first, so a<br/>manifest-ignoring load lands on 'a' (discriminating)" .-> G
```

The pre-existing direct-write consumer test (`test_variant_execution.py::test_load_project_honors_manifest_active_variant`) sits outside this chain as a **guard only** — it hand-writes the manifest, never touches the dropdown, and stays green under a reverted route, so it must never gate.
