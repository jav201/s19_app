# PLAN — s19_app — batch-16 (living compendium)

**Batch:** 2026-06-25-batch-16 · **Language:** en · **Branch:** claude/batch-16-gap2 (off origin/main b734c19, per RC-1)

## Where we are
**Phase 1 — requirements engineered, awaiting gate.** 1 HLR / 4 LLR / TC-301..312 + AT-017.1..4. Baseline 922. Next: Phase 2 cross-review on approve.

## Objective
**GAP #2 / US-017** — close batch-11 SCOPE-1: give the project save an operator surface to assign per-variant change/check files (+ project-wide `batch`), persist them into `project.json`, and prove the round-trip THROUGH the shipped save handler (assign → save → reload → consumed by `plan_variant_executions`). Today the save (app.py:3687) passes no `batch`/`assignments`; the writer/verifier/consumer already support them (tested only via direct kwargs = the SCOPE-1 hole).

## Decisions
- **Scoping (operator):** extend SaveProjectScreen (at-save-time) · persist assignments + batch · project-workarea files only.
- **D-NEWPROJ (confirm at gate):** assignment UI scoped to re-saving an EXISTING project; new-project save writes empty (variant set doesn't exist until after image copy).
- **D-KEY (load-bearing):** assignment keys = `variant_id` (stem), not filename, or the consumer silently drops.

## Increments
- Inc1 (load-bearing): SaveProjectPayload +fields + handler threading + round-trip AT (payload built programmatically → closes SCOPE-1 w/o UI). ≤5 files.
- Inc2: the per-variant assignment UI in SaveProjectScreen. ≤5 files.

## Risks
R1 write-intent==verify-intent (else spurious drift) · R2 assignment-key stem (D-KEY) · R3 new-project UI timing (D-NEWPROJ).

## Census / frozen
All planned files (screens.py, app.py, tests) outside frozen set; manifest_writer/variant_execution_service read-only substrate.

## Test ledger
Baseline 922 (b734c19). TC-301..312 / AT-017.1..4 net-new.

## Decision log (mirror)
- 2026-06-25 — batch-16 opened (RC-1 gate's first use); GAP#2 confirmed live; US-017 READY (3 scoping Qs resolved); Phase 1 → 1 HLR/4 LLR/AT-017.* + the D-NEWPROJ fork flagged. Awaiting Phase-1 gate.
