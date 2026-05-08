# Architecture diagrams — s19_app — Batch 2026-05-05-batch-01

This document collects the three reference diagrams for the audit batch:

1. **System architecture** — the three-layer codebase (parsers → range/validation engine → TUI services + view), with audit targets highlighted.
2. **V-model dev-flow sequence** — how the 6 phases flowed in this batch, including the iter 2 → iter 3 rollback when the security blockers were found and the increment 1 → 1.5 follow-up.
3. **Finding flow** — how a Finding moves through the system from discovery (test xfail or inspection matrix) to next-batch closure plan.

All three are Mermaid source. Render in any GitHub Markdown viewer or any Mermaid-aware IDE.

Source data:

- [`CLAUDE.md`](../../../CLAUDE.md) §Architecture — three-layer model.
- [`01-requirements.md`](../../01-requirements.md) §1.2 Scope — audit targets per layer.
- [`05-postmortem.md`](../../05-postmortem.md) §0 — phase / iteration summary.
- [`02-review.md`](../../02-review.md) §Deferrals — Finding flow output point.
- [`03-increments/increment-001.md` … `increment-009.md`](../../03-increments) — increment cadence.

---

## 1. System architecture

The three layers of `s19_app`. Yellow nodes are the files this audit batch touched (read or modified). Grey nodes are dependent layers cited but not directly audited (renderers, screens). Service-layer routing is the structural anchor for LLR-003.1; the three documented bypasses (F-9.04-01/02/03) are drawn as dashed arrows to make the orchestration deviations explicit.

```mermaid
flowchart TB
    subgraph entry["Entry points (pyproject.toml)"]
        cli["s19tool CLI<br/>(s19_app.cli:main)<br/><i>out of scope this batch</i>"]
        tui["s19tui TUI<br/>(s19_app.tui:main)"]
    end

    subgraph parsers["Layer 1 — Parsers"]
        core["s19_app/core.py<br/>S19File / SRecord<br/>(LLR-001.1)"]
        hexfile["s19_app/hexfile.py<br/>IntelHexFile<br/>(LLR-001.1)"]
        a2l["s19_app/tui/a2l.py<br/>+ a2l_parse / extract / render / validate facades<br/>(LLR-001.2, LLR-006.1)"]
        mac["s19_app/tui/mac.py<br/>parse_mac_file<br/>(LLR-001.2)"]
    end

    subgraph engine["Layer 2 — Range / validation engine"]
        rangeidx["s19_app/range_index.py<br/>build_sorted_range_index<br/>address_in_sorted_ranges"]
        rules["s19_app/validation/rules.py<br/>validate_mac_records<br/>validate_a2l_structure<br/>(LLR-002.2, LLR-002.3, LLR-008.2)"]
        engineCore["s19_app/validation/engine.py<br/>validate_artifact_consistency<br/>(LLR-007.2, LLR-008.1, LLR-009.1, LLR-009.2)"]
        model["s19_app/validation/model.py<br/>ValidationIssue / Severity / CoverageMetrics<br/>(LLR-002.1, LLR-002.3, LLR-009.2)"]
        colorpolicy["s19_app/tui/color_policy.py<br/>SEVERITY_CLASS_MAP<br/>(LLR-002.1)"]
    end

    subgraph services["Layer 3a — TUI services (orchestration boundary)"]
        loadsvc["services/load_service.py<br/>build_loaded_s19 / build_loaded_hex"]
        a2lsvc["services/a2l_service.py<br/>enrich_tags_and_render"]
        valsvc["services/validation_service.py<br/>build_validation_report"]
    end

    subgraph view["Layer 3b — TUI app + view"]
        app["s19_app/tui/app.py<br/>S19TuiApp orchestration only<br/>(LLR-003.1)"]
        models["s19_app/tui/models.py<br/>LoadedFile snapshot<br/>(LLR-003.1)"]
        hexview["s19_app/tui/hexview.py<br/>render_hex_view_text<br/>(LLR-003.2)"]
        screens["s19_app/tui/screens.py<br/>Load / Save / Project modals"]
        workspace["s19_app/tui/workspace.py<br/>copy_into_workarea<br/>sanitize_project_name<br/>validate_project_files<br/>setup_logging<br/>(LLR-005.1..5)"]
    end

    cli -.-> core
    cli -.-> hexfile
    tui --> app

    app --> loadsvc
    app --> a2lsvc
    app --> valsvc
    app --> hexview
    app --> screens
    app --> workspace
    app --> models

    loadsvc --> core
    loadsvc --> hexfile
    a2lsvc --> a2l
    valsvc --> engineCore

    %% Documented bypasses surfaced by LLR-003.1 audit
    app -. "F-9.04-01<br/>direct parse_mac_file" .-> mac
    app -. "F-9.04-02<br/>direct S19File.get_overlap_addresses" .-> core
    app -. "F-9.04-03<br/>direct parse_a2l_file (cache)" .-> a2l

    rules --> model
    engineCore --> rules
    engineCore --> rangeidx
    engineCore --> model
    colorpolicy --> model

    hexview --> models
    workspace --> models

    classDef audited fill:#fff4cc,stroke:#a07a00,stroke-width:1.5px,color:#2a2200
    classDef ancillary fill:#eef0f4,stroke:#5b6473,color:#2a2a30
    classDef finding stroke-dasharray:5 3,stroke:#c43a3a,color:#7a1d1d

    class core,hexfile,a2l,mac,rules,engineCore,model,colorpolicy,app,workspace,hexview,loadsvc,a2lsvc,valsvc audited
    class rangeidx,models,screens,tui,cli ancillary
```

**Reading the diagram.**

- **Solid arrows** = routed call (the orchestration contract holds).
- **Dashed red arrows** = documented bypass (`app.py` reaches into a parser layer directly, captured as a Finding). All three are minor-severity and are queued for batch B-2C (service-layer symmetry).
- **Yellow nodes** = files modified or audited in this batch.
- **Grey nodes** = supporting infrastructure cited but not the audit's primary target.

---

## 2. V-model dev-flow sequence

How the 6 phases flowed in this batch, including the iter 2 → iter 3 rollback (security blockers force return to Phase 1) and the increment 1 → 1.5 follow-up (test rename after LLR-005.3 product change broke a pre-existing test by-design). Source: [`05-postmortem.md` §0](../../05-postmortem.md).

```mermaid
sequenceDiagram
    autonumber
    participant User as User<br/>(Javier)
    participant P1 as Phase 1<br/>Requirements
    participant P2 as Phase 2<br/>Review
    participant P3 as Phase 3<br/>Implementation
    participant P4 as Phase 4<br/>Validation
    participant P5 as Phase 5<br/>Post-mortem
    participant P6 as Phase 6<br/>Docs

    User->>P1: dev-flow-init: audit batch
    Note over P1: Iter 1 — initial draft<br/>6 US, top-down HLRs

    P1->>P2: 01-requirements.md iter 1
    Note over P2: architect / qa / security<br/>parallel review

    P2-->>P1: ITERATE — security blockers S-001/S-002<br/>+ user-prompted US-001/002 expansion

    Note over P1: Iter 2 — add HLR-007/008/009<br/>(scope grow)

    P1->>P2: 01-requirements.md iter 2
    Note over P2: Iter 2 review<br/>S-001/S-002 still mis-routed in HLR-005

    P2-->>P1: ITERATE — security rollback<br/>(S-001 destination containment,<br/>S-002 symlink/junction)

    Note over P1: Iter 3 — split LLR-005<br/>into 5.1..5.5; add Finding schema;<br/>add LLR-002.3 message scrubbing

    P1->>P2: 01-requirements.md iter 3 (final)
    P2->>P3: 02-review.md APPROVED<br/>4 majors → §Deferrals

    Note over P3: 9 increments

    P3->>P3: Increment 1 — LLR-005.3<br/>(closes S-001/S-002 inline)
    P3->>P3: Increment 1.5 — test rename<br/>(workspace tightening broke pre-existing test by-design)
    P3->>P3: Increment 2 — snapshot harness + per-class fixtures
    P3->>P3: Increment 3 — LLR-002.3 message scrubbing
    P3->>P3: Increment 4 — LLR-002.1 round-trip (16 tests)
    P3->>P3: Increment 5 — LLR-007.2 co-emission (8 classes; F-7.2-01/02 raised)
    P3->>P3: Increment 6 — LLR-007.4 panel render (8 snapshots)
    P3->>P3: Increment 7 — LLR-005/006/003 sweep (38 tests; F-7.7-02..07 raised)
    P3->>P3: Increment 8 — LLR-009.1/2 determinism + coverage
    P3->>P3: Increment 9 — 9 inspection matrices (doc-only; F-9.* raised)

    Note over P3: Suite 173 → 259<br/>(+86 tests, 0 unexpected fails, 3 documented xfail)

    P3->>P4: 9 increment packets + code/tests
    Note over P4: 60 TCs evaluated<br/>49 pass / 11 gap / 0 fail / 3 xfail

    P4-->>P5: VERDICT = gap<br/>(pass-with-known-gaps)

    Note over P5: Architect + qa-reviewer<br/>parallel retrospective

    P5->>User: Recommend close batch<br/>+ open B-2A as follow-up

    User->>P6: APPROVE — close batch
    P6->>P6: traceability-matrix.md<br/>functionality.md<br/>diagrams/architecture.md
    P6->>User: Phase 6 complete →<br/>/dev-flow-sync-en after merge
```

**Reading the diagram.**

- The two `P2-->>P1: ITERATE` arrows mark the rollbacks: iter 1→2 (user-prompted scope expansion) and iter 2→3 (security-blocker driven rebuild). Per [`05-postmortem.md` §1.D](../../05-postmortem.md), the iter 2→3 rollback was the avoidable one; the architectural lesson — "every HLR that names a module must cite the public-function enumeration that produced it" — is the carry into batch 2.
- Increment 1 → 1.5 is shown as a sub-step inside Phase 3 because 1.5 was a tactical follow-up: the LLR-005.3 product change tightened `copy_into_workarea` and broke a pre-existing test by-design. 1.5 was the gated rename that restored green CI without expanding scope.
- The 3 documented `xfail` decorators sit on tests added in increments 5 (TC-062.a, F-7.2-01), 6 (TC-065.a, F-7.2-01), and 7 (TC-052, F-7.7-07). Each is a green test today that becomes a closure tripwire for the corresponding follow-up batch.
- Phase 6 (this artefact) is the final gate before `/dev-flow-sync-en` uploads the batch to the Obsidian vault.

---

## 3. Finding flow

How a single Finding propagates from discovery through the artefact set to a next-batch closure plan. The flow has two main entry points (test xfail vs. inspection matrix), one persistence point (`02-review.md` §Deferrals for majors), and one closure point (the next batch's `01-requirements.md` seed).

```mermaid
flowchart TD
    subgraph discovery["Discovery"]
        d1["Test fails or xfail-passes<br/>during Phase 3 increment"]
        d2["Inspection matrix row in<br/>increment-NNN.md gets<br/>verdict: drift / unknown"]
        d3["Audit-matrix walk<br/>uncovers undocumented<br/>rule or doc-vs-code drift"]
    end

    subgraph triage["Triage in increment review packet (§6 of every increment-NNN.md)"]
        t1{"Severity?"}
        tMajor["major:<br/>blocking gate or<br/>data-correctness bug"]
        tMinor["minor:<br/>doc gap, severity drift,<br/>architectural smell"]
    end

    subgraph persistence["Persistence"]
        pDef["02-review.md §Deferrals<br/>{ID, owner, target batch,<br/>blast radius if not fixed}"]
        pInc["increment-009.md §10<br/>Findings table<br/>(lighter doc-Finding schema)"]
    end

    subgraph testlock["Test-lock if product-side"]
        tl1["pytest.xfail(strict=False,<br/>reason='F-X.Y-NN: ...')<br/>carries Finding ID"]
        tl2["Self-flip-guard test<br/>asserts de-facto behaviour<br/>+ inline F-NN comment"]
    end

    subgraph aggregation["Aggregation at gate"]
        a1["04-validation.md §0<br/>Open Findings count<br/>(3 major + 15 minor)"]
        a2["traceability-matrix.md §3.2<br/>full register with<br/>proposed batch"]
        a3["05-postmortem.md §3<br/>consolidated next-batch<br/>proposals B-2A..E"]
    end

    subgraph closure["Closure (next batch)"]
        c1["B-2A — engine completeness<br/>F-7.2-01/02, F-7.7-07,<br/>F-9.07-01, F-9.03-01/02, F-9.09-01"]
        c2["B-2B — workspace hardening<br/>F-7.7-02/03/04/05/06"]
        c3["B-2C — service-layer symmetry<br/>F-9.04-01/02/03"]
        c4["B-2D — REQUIREMENTS.md numbering<br/>F-9.01-01, F-9.02-01..03, F-9.09-01"]
        c5["B-2E — demo evidence<br/>+ promotions + drift remediation<br/>TC-032, TC-047, 5 R-* promote, 2 R-* drift"]
    end

    d1 --> t1
    d2 --> t1
    d3 --> t1

    t1 -- "blocker / data-correctness /<br/>architectural breach" --> tMajor
    t1 -- "doc / minor severity drift /<br/>architectural smell" --> tMinor

    tMajor --> pDef
    tMinor --> pInc

    tMajor -.-> tl1
    tMinor -.-> tl2

    pDef --> a1
    pInc --> a1
    tl1 --> a1
    tl2 --> a1

    a1 --> a2
    a2 --> a3

    a3 --> c1
    a3 --> c2
    a3 --> c3
    a3 --> c4
    a3 --> c5

    classDef discoverNode fill:#e3f2fd,stroke:#1565c0,color:#0d3a73
    classDef triageNode fill:#fff8e1,stroke:#a07a00,color:#3a2900
    classDef persistNode fill:#f3e5f5,stroke:#6a1b9a,color:#3a0d52
    classDef closeNode fill:#e8f5e9,stroke:#2e7d32,color:#0e3a13

    class d1,d2,d3 discoverNode
    class t1,tMajor,tMinor triageNode
    class pDef,pInc,tl1,tl2,a1,a2,a3 persistNode
    class c1,c2,c3,c4,c5 closeNode
```

**Reading the diagram.**

- A Finding's discovery channel determines its initial register: a `xfail`-driven Finding is paired with a `pytest.xfail(strict=False, reason="F-NN-NN ...")` decorator (test-lock pattern); an inspection-matrix-driven Finding lives only in the audit matrix until triage.
- Severity decides which register (Phase 4 gate file vs. increment §10). Majors **must** carry the full schema `{ID, owner, target batch, blast radius if not fixed}`; this satisfies `01-requirements.md` §5.3 acceptance criterion. Minors use a lighter schema in `increment-009.md` §10.
- The test-lock layer (xfail / self-flip-guard) is critical: it keeps the suite green AND surfaces the gap as a tripwire that closes naturally when the product fix lands.
- Closure is **always in the next batch**, never inline — the per-increment ≤5-files cap makes inline closure of cross-cutting Findings impractical, and the carry-forward register in `02-review.md` §Deferrals + `traceability-matrix.md` §3.2 is the requirements seed for batch 2.

---

## 4. Diagram-source maintenance notes

- **Format.** All three blocks use Mermaid source — render client-side. No build step, no rendered images checked into git, no extra dev dependencies (per the Phase 6 hard constraint).
- **Single source of truth.** This file is the only diagram artefact for the batch. Any future diagram (e.g. an ADR-specific call graph) should be added as a new section in this file or in a clearly-named sibling under `06-docs/diagrams/` — do NOT scatter `.mmd` source files across the increments.
- **Updating after batch 2.** When B-2A closes F-7.2-01, the dashed-bypass arrow in §1 stays (it is an architectural fact at audit time). The `xfail` annotations in §2 and §3 should be updated to "closed in batch 2" with the increment ID. The closure boxes in §3 should turn green / get strikethrough text once their Findings are crossed off.
- **Validation.** Render in any GitHub Markdown view to verify the syntax. The diagrams use only Mermaid `flowchart` and `sequenceDiagram` features — no plugins, no client-config injection.
