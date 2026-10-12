# PLAN — s19_app — Batch 2026-10-11-batch-93

> **Artifact language.** Canonical **English scaffold**; generate in the batch's language.
> **Owed in.** `core` ✓ · `full` ✓
> Seeded by `/dev-flow-init` step 4 at both levels; the living plan is owed at every gate
> that follows (`/dev-flow` §Living plan is the rule's home).

> **Field guide:** `templates/guides/plan-template.md` explains each field below and the rules that read it. It ships with the flow and is not copied into this batch.

The living compendium of this batch: where-we-are · objective · per-story/per-station status ·
roadmap + increment plan · key decisions · risks/watch-items · conventions honored ·
out-of-scope carries · test ledger · decision log (the human-readable mirror of `state.json`).
**Create at batch open and update at every gate and significant checkpoint** — the
orchestrator presents the full plan in-conversation at each phase gate.

## Header

| Field | Value |
|---|---|
| Project | s19_app |
| Batch | 2026-10-11-batch-93 |
| Objective | The Memory Map cohesion pass (batch-93, the memmap2 charter): variant C -- the inspector cockpit -- carrying the shared cohesion kit, plus legend A -- the spec sheet -- per the operator's 2026-08-06 ruling; re-derived from prototypes/memmap2.HANDOFF.md (not copied); sequenced AFTER batch-92 (the layer-inversions refactor, the other agent's lane) -- P0-P2 now, P3+ after batch-92 merges |
| Standing authorization | Operator (Javier), 2026-10-11, quoted in `state.json`: "sigue con memmap. Pero coordina con el otro agente que esta haciendo refactor del codigo para modularizarlo." Read with the established chain: Gates -- autonomous with the two exceptions; Git -- the COORDINATOR commits and pushes at each close (no PR); data safeguard -- synthetic boards only; the coordination note lives in the batch-92 lane's dir (`COORDINATION-batch93-memmap.md`); this batch's P3+ holds until batch-92 merges; Kimi agents under coordinator briefs do NOT commit/push/stash; this batch runs in the MAIN checkout. |
| First gate | Not yet run at P1 authoring (`state.json`: `current_station` P0, `phase_status` not-started). The executed premise evaluation in `01-requirements.md` §2.7 (P-1..P-7) is the P0 evidence pack; the coordinator's P0 gate run appends its exit code and `V7` line here. |
| Premises / RC-1 | RC-1 verified: `origin/main` tip = `c9dcc25` (`git log origin/main` at P1: the batch-93 seed commit). Premises P-1..P-7 evaluated TRUE in `01-requirements.md` §2.7 -- each with executed evidence (capture reconstructions, shipped-code measurements, the registry parse). |

## Triggers

The trigger evaluation `state.json`'s `triggers.record` points at: one row per trigger evaluated, fired or not.

| Id | Verdict | Probe output |
|---|---|---|
| <A1 / B1 / …> | <fired / not fired> | NOT EVALUATED at P1 authoring — owed at the coordinator's P0 gate run (`state.json` carries the flow's NOT-EVALUATED marker, not a verdict). |

## Where we are

P1 (the contract) is authored: `01-requirements.md` declares US-125..128, HLR-125..133,
LLR-125.1..133.1, the IFC, the AT-287..295 / TC-649..684 reservation and the 5.2 acceptance
criteria; `01-requirements-ledger.md` carries LED-2026-10-11-batch-93.1 (the derivation + the
three Before/After amendments). P2 (this review) approves. Next: the P0/P1 gate runs, then
P3 holds for batch-92's merge.

## Objective

The Memory Map cohesion pass: variant C (the inspector cockpit) carrying the shared cohesion
kit, plus legend A (the spec sheet), re-derived from the memmap2 charter — contracted in
`01-requirements.md`, sequenced after batch-92 (P0–P2 now, P3+ after batch-92 merges).

## Per-story / per-station status

| Story / station | Status | Notes |
|---|---|---|
| US-125 (cockpit + chrome) | contracted | HLR-125/126/128/133 · AT-287/289/295 |
| US-126 (one-line stats + chips) | contracted | HLR-129 · AT-288/294 · amends HLR-113 + R-TUI-061 |
| US-127 (alignment/no-wrap/regimes) | contracted | HLR-127/130/131 · AT-290/291/292 · amends R-TUI-073's row format |
| US-128 (legend spec sheet) | contracted | HLR-132 · AT-293 |
| P0 | evidence pack ready | premises P-1..P-7 executed in §2.7; the gate run + trigger evaluation owed |
| P1 | authored | this contract; the P1 gate validates it |
| P2 | this review | approve, observations recorded |
| P3+ | HOLD | until batch-92 merges AND `COORDINATION-batch93-memmap.md` exists on disk |

## Roadmap + increment plan

1. P0/P1 gate runs over this contract; the AT-287..295 + TC-649..684 RESERVED rows are written to `AT-TC-REGISTRY.jsonl` at P0.
2. **P3 (holds for batch-92):** the `MemoryMapPanel` re-composition (chrome kit, cockpit layout, aligned rows, 8-byte peek, chips + one-line stats), the wrap-audit harness, the legend-A content — increment(s) sliced at the gate, each with its review packet.
3. **P4:** validation — the TC/AT suite under textual==8.2.8, the full (not `-m "not slow"`) suite before merge.
4. **P5:** close — backlog reconciliation, the prototypes/memmap2.* commit per the charter §6, the close-out validator pass.

## Key decisions

| Date | Decision | Why |
|---|---|---|
| 2026-10-11 | The contract re-derives every chartered number from the captures/shipped code (methods stated in §2.7), and corrects two charter shorthand readings: the glance block's canon row is `R-TUI-061` (the charter said "R-TUI-072/073"), and the chips' `share%` is the mapped-BYTE share (only reading under which the capture's chips sum to 100). | the charter's own rule: re-derive, don't copy |
| 2026-10-11 | The interlock is satisfied by verification, not work: `#command_bar_row` is already deleted (batch-79 HLR-118 merged); HLR-133 is a do-not-resurrect law with a grep TC. | P-2's executed grep |
| 2026-10-11 | The ~84- and ~43-column thresholds stay charter-measured constants to be re-measured pilot-style at P3 (C-29), not P1-invented numbers. | PANEL-column calibration law |

## Risks / watch-items

- **batch-92 hasn't merged** (its lane dir does not exist yet under `.dev-flow/`; the coordination note `COORDINATION-batch93-memmap.md` is not on disk) · likely · the P3+ hold is the mitigation; P0–P2 proceed now.
- **The variant-C capture does not glyph-render the region-list scrollbar** (asserted behaviorally instead: scroll reachability + DOM) · capture limitation · noted in the P2 review; the AT asserts the scrollbar's presence/behavior, not a glyph.
- **Threshold re-measurement drift** (~84 / ~43 panel cols) · medium · P3 records the measured values in the increment packet; the contract's thresholds follow the measurement.
- **The four memmap/legend test modules pin the old format** (row format, glance, stats assumptions) · certain · planned adaptations preserved the behavior oracles (LLR-127.4/LLR-126.4); counted work, not regressions.

## Conventions honored

- Re-derive, don't copy (charter rule); reserved field names literal; English artifacts (`state.json` language `en`).
- The batch-77 direction (band bar, ruler, mapped-byte widths) carried untouched; the panel stays presentational (LLR-041.7/045A.2); B3 + colour discipline + remount discipline + no `_nodes`/`_context` shadowing; styles via `styles.tcss`.
- textual==8.2.8 pin; snapshots regenerate in canonical CI only; the full suite before merge; every ledger figure states its form.
- AT/TC ids pass the G1–G7 guard; the registry reservation lands at P0.
- No git operations by this (Kimi, coordinator-briefed) lane — the coordinator commits at close.

## Out-of-scope carries

- Map variants A/B and legend B (evaluated, not chosen — nothing registered).
- Re-litigating the band-bar direction; the other screens' legends beyond the byte-identical control.
- The command-bar deletion itself (owned by batch-79, already merged).
- Anything sequenced behind batch-92's merge (this batch's P3+).
- Minting the P3 TCs' exact id assignments beyond the reserved block (P3's test plan owns the mapping).

## Test ledger

| Suite / command | Last run | Result |
|---|---|---|
| `python -m pytest tests -q` (the base suite, before any source change) | owed at P0's gate run (P3's base-count measurement) | — |
| SVG capture reconstructions (baseline / variant-C / legend-A) | 2026-10-11 (P1) | the six defects + the decided layout re-measured (P-1/P-6) |
| shipped-code measurements (`render_hex_view`, row/label widths) | 2026-10-11 (P1) | 79-cell peek row · 237-cell defect · 33-cell 8-byte row · 50-cell shipped row · band label lengths (P-1) |
| `AT-TC-REGISTRY.jsonl` numeric parse | 2026-10-11 (P1) | max numeric AT 286; TC-649.. free; TC-1728 BURNED seed (P-5) |
