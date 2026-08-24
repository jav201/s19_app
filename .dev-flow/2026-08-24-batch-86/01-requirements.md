# Requirements — s19_app — 2026-08-24-batch-86

> **Station P0 state of this document.** Only §1 (context) and §2.6 (story intake) are
> authored at batch open; §2.7 (premises), §3 (acceptance), §4 (HLR/LLR) and §5 (IFC record)
> are Phase-1 work and are ABSENT, not pending-in-template. This early creation is deliberate:
> the active batch's own copy must win `_artifacts()` arbitration, or V1–V9 judge a frozen
> May-2026 document (measured at this batch's open: 17 V4 blocks from batch-01's LLRs).

## 1 · Context

First batch run under flow rev42–rev44 (derived Atlas + V20 · declared selector taxonomy ·
coherence rules V21–V23). Objective: the IFC record for a SECOND surface, clean-start,
applying the batch-85 format lessons — pair-based thresholds, split populations, scoped
statements — with the `SURFACE:` field, canon mirror seeding, and a per-surface cost record
at n=2. Zero product code planned.

## 2.6 · Story intake (Definition of Ready)

### US-86-1 — a second surface becomes contractually addressable

As the operator auditing s19_app's addressability, I want the IFC record (Part A + Part B)
of a second surface — selected by measured evidence — authored to the corrected format, so
that a second surface is contractually addressable, the pilot's `PARENT` can be balanced
(V12 verdict instead of "NOT checked"), and the per-surface retrofit cost gains a second
data point.

- **Who:** the operator (audit) and the flow's own validators (machine consumers).
- **Outcome (observable, black-box):** `devflow-validate` reports verdicts — not SKIP — for
  V10–V14/V19/V21 over the new component with 0 BLOCK attributable to it; the regenerated
  Atlas renders the component (V20 `atlas current`); the living canon reflects the batch's
  new ids (V22's unreflected aggregate does not grow); the whole-suite gate run is neutral
  (0 source files touched).
- **Out of scope:** D-II (any amendment to the pilot's record) · the remaining surfaces ·
  the C3 seeding backlog beyond this batch's own ids · `docs/ARCHITECTURE.md` (D-IV carry).
- **INVEST:** Independent · Negotiable (record detail at Phase 1) · Valuable (audit + V12
  live + n=2 cost) · Estimable (LLR-85.7's measured pilot cost) · Small (record + canon
  mirror only) · Testable (validator + Atlas + suite-neutrality as oracles).
- **Classification: READY.** Surface-selection hypothesis and its confirming probes are
  recorded in `PLAN.md` (leading candidate: the workspace surface the pilot names as its
  undeclared `PARENT`); confirmation is Phase 1's first task, by execution.
