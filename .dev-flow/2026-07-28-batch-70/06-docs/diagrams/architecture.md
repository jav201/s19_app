# batch-70 — FB-P2 architecture

## The run path, single vs fused

```mermaid
flowchart TD
    A["FlowBuilderPanel<br/>#flow_scope Select + Run"] -->|"RunRequested(flow, scope)"| B{"S19TuiApp<br/>on_flow_builder_panel_run_requested"}
    B -->|"scope = single<br/>(DEFAULT)"| C["run_flow(flow, ctx)"]
    C --> D["render_result — unchanged path"]
    B -->|"scope = all / assignments"| E{"_variant_set present?"}
    E -->|no| F["error card:<br/>'no variants declared'"]
    E -->|yes| G["run_flow_over_variants"]
    G --> H["plan_variant_executions<br/>(REUSED — never a path list, D-1)"]
    H --> I["per descriptor:<br/>replace(ctx, variant=d, defer_report=True)"]
    I --> J["run_flow — isolated per variant (D-3)"]
    J --> I
    I --> K["_roll_up_variants<br/>worst + n_ok/n_issues/n_error (D-5)"]
    K --> L{"flow has a<br/>REPORT block?"}
    L -->|yes| M["write_fused_flow_report<br/>ONE file (D-4)"]
    L -->|no| N["no report — as unscoped"]
    M --> O["render_fused_result"]
    N --> O
```

## The containment seam — why the ref is relative

```mermaid
flowchart LR
    A["VariantDescriptor.path<br/>ABSOLUTE"] -->|"_bound_source_ref"| B{"relative_to(project_dir)?"}
    B -->|"ValueError / OSError"| C["ValidationIssue<br/>MANIFEST-PATH-ESCAPE"]
    C --> D["that variant fails CLOSED<br/>others still run (AC-7)"]
    B -->|ok| E["'sub/fw_a.s19'<br/>project-RELATIVE POSIX"]
    E --> F["_resolve_manifest_entry<br/>REUSED, never forked"]
    F --> G["absolute? escape? reparse point?"]
    G -->|any| C
    G -->|clean| H["resolved path → build_loaded_s19/hex"]
```

> ⚠️ Passing the **absolute** path straight to `_resolve_manifest_entry` fails **every** variant —
> that seam rejects absolute refs by design. This was premise **P-2**, executed and FALSE, and it is
> the single most likely thing for a future editor to "simplify" back into a bug.

## Where the bound is charged (D-7)

```mermaid
flowchart TD
    subgraph P["PRODUCER — where the cost is PAID"]
        A["section.block_results<br/>section.findings (len = N)"] -->|"islice(…, cap)"| B["format ≤ cap rows<br/>each paying md_safe"]
        A -->|"len() — O(1), traverses nothing"| C["dropped = N − cap"]
    end
    B --> D["> **Cut in `id`:** findings: N−cap omitted"]
    C --> D
    D --> E["_ByteBudget.put()"]
    subgraph W["WRITER — bounds OUTPUT only"]
        E
    end
    F["### id · Status · Footprint · Cut notice"] -.->|"emitted OUTSIDE the gate<br/>so no variant can vanish"| G["document"]
    E --> G
```

**The distinction that matters:** capping at `E` (the writer) bounds what is *written*; capping at
`islice` (the producer) bounds what is *formatted*. batch-63's Phase-2 finding was precisely that
bounding output does not bound traversal — which is why `AT-209`'s oracle counts **formatting
operations**, not bytes, wall-clock or RSS.

## Module placement

| Module | Role | Edited? |
|---|---|---|
| `services/flow_model.py` | pure data — `FlowContext.variant`, `defer_report`, `FusedFlowRunResult`, `FLOW_SCOPE_*` | ✏️ |
| `services/flow_execution_service.py` | `_bound_source_ref`, `_roll_up_variants`, `run_flow_over_variants` | ✏️ |
| `services/flow_fused_report_service.py` | the fused composer + its per-variant bound | 🆕 |
| `services/flow_report_service.py` | the single-image composer | ⛔ **untouched — this is how AC-6 is structural rather than conditional** |
| `screens_directionb.py` | scope `Select`, `render_fused_result` | ✏️ |
| `app.py` | the one run call site dispatches on scope | ✏️ |
| engine-frozen set | `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py` | ⛔ intersection with the edit set = ∅ |
