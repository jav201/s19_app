# PLAN — batch-53 · Flow Builder FB-P1: flow.json persistence (living compendium)

## Where we are
- **Phase 3 (Implementation) — Inc-1 dispatched.** Phase-1 + Phase-2 gates APPROVED (self, autonomy). Branch `feat/batch-53-flow-persistence` off `origin/main` `4f4f20f`.
- **Phase-2 outcome:** 0 blocker · security **0 HIGH**. Resolutions AMD-1..12 (02-review.md, §6.5-authoritative): report block=`BLOCK_STATUS_OK`+deferred-summary · import copy `max_size=FLOW_SIZE_CAP_BYTES` · ReportBlock LOCKED field-less · reject-arm census→LLR-002.9 · AT thresholds reconciled up to catalog rigor · `_flow_block_label` report arm + AT-006 tightened · US-004 reworded · dirty-guard/F-findings de-conflicted.
- **Increment plan (C-21 re-derived):** Inc-1 data layer (persistence service + ReportBlock + report no-op + security battery/census tests) → Inc-2 file I/O + Import (size-capped) → Inc-3 UI (Save/Load modals + FlowBuilderPanel name-strip/Save-Load row + label arm + quarantine card + app handlers + styles) → Inc-4 dirty-guard modal + fold-in ATs.
- **Both prototypes operator-approved** ("Excelentes los prototipos, vamos adelante"). CRC realign = separate `/fast-dev-flow`, queued after FB-P1 (or parallel on operator call).
- **Phase-1 outcome:** 4 US / 4 HLR / 15 LLR / AT-001..006 / TC-001..021. OQ-1..4 adopted (MANIFEST-* verbatim · no existence-check · dirty-guard confirm-discard · caps 64/64/1MiB+min1). **RB-model (operator): model+persist the ref-less ReportBlock NOW; DEFER report generation to FB-P1b.** ID reconciliation: architect AT-001..006 canonical, qa AT-P1-* fold as detailed coverage (none dropped).
- Authorization: **AUTONOMOUS + self-merge**, with a **plan+prototype-first** precondition that is **already satisfied** (Phase-0 plan approved + colored prototype Artifact approved). Self-approve gates with a Coverage/Certainty/Evidence axis check; present packets in-conversation; final qa **and** security PR-pass 0-HIGH before self-merge (untrusted loader).

## Objective
Save/load a `Flow` to `.s19tool/workarea/<project>/flows/<name>.json` (multiple named
flows), reusable across a file and its variants. Greenfield serialize/deserialize +
a HARDENED untrusted loader that re-validates every embedded ref via the reused
`_resolve_manifest_entry` on LOAD (fail closed, whole-flow, never partial). Save/Load/
Import UI on the FlowBuilderPanel. Import copies external `flow.json` into `flows/`
(never executed in place).

## Design inputs (prototype pre-approved — Fable 5, colored Artifact)
- `prototypes/fb_p1_flow_persistence.NOTES.md` — schema, load-validation order, rejection table, UI layouts.
- `prototypes/fb_p1_flow_persistence.prototype.py` — runnable serialize+hardened-load; **ALL CASES HELD** (13 security cases + NTFS junction + hostile import).
- `prototypes/fb_p1_flow_persistence.DECISIONS.md` — D1 surface-1 layout; D2 ref-less report block.
- `prototypes/fb_p1_flow_persistence.artifact.html` — colored to-scale UI viz (Save/Load/Import + quarantine card).

## Operator decisions folded in
- **D1** — UI = surface-1: FlowBuilderPanel name-strip (`Flow: <name>` + dirty `●`/saved `✓`) + Save…/Load… on the Run/Clear row; Save/Load modals + quarantine card as designed.
- **D2** — NEW **ref-less REPORT block** (`kind: "report"`, no `*_ref`) that must round-trip in flow.json; **every flow generates its report**. Model (explicit-optional vs implicit-always) to settle at the Phase-1 gate.

## Phase-1 open questions (resolve at the gate)
- **OQ-1** finding codes: keep `MANIFEST-*` verbatim from the reused guard, or wrap as `FLOW-REF-*`? (public test contract)
- **OQ-2** no existence-check at load (containment only; missing files surface at run)?
- **OQ-3** dirty-guard confirm modal on Load over unsaved edits (recommended) vs silent replace?
- **OQ-4** caps: 64 blocks / 64-char name / 1 MiB file — confirm before test-asserted.
- **RB-model** report block: explicit-and-optional (author-added) vs implicit-always (auto terminal report)?

## Security posture (C-17 family)
Untrusted `flow.json` loader is the risk. Prototype proved: schema-strict, unknown-kind
reject, per-block field validation, and **every embedded ref re-validated through
`_resolve_manifest_entry` (absolute/escape/reparse) on LOAD** → whole-flow reject, never
partial. Report block is ref-less → no ref to validate (its output filename, if any, is a
work-area write via `save_*`/`copy_into_workarea`). Markup-safety: file-derived finding
text rendered markup-safe at the UI boundary (quarantine card).

## Landing map (provisional)
New `services/flow_persistence_service.py` (no Textual, C-7); `flow_model.py` gains
`ReportBlock`; two modals in `screens.py`; panel messages + `set_blocks` in
`screens_directionb.py`; two app handlers mirroring `on_flow_builder_panel_run_requested`.
No frozen-engine file; no `workspace.py` edit (`validate_project_files` skips subdirs).

## Files (production, NON-frozen)
`flow_persistence_service.py` (new) · `flow_model.py` · `screens.py` · `screens_directionb.py` · `app.py` · `styles.tcss` · tests. Frozen OFF-LIMITS: core/hexfile/range_index/validation/tui a2l/mac/color_policy.

## Roadmap (phases)
P0 intake ✓ (plan + prototype approved) → **P1 requirements (IN PROGRESS)** → P2 review (architect+qa+security) → P3 impl (≤5 files/inc, code-reviewer per gate) → P4 validation → P5 postmortem → P6 docs + PR (self-merge after qa+security 0-HIGH).

## Decision log
- 2026-07-24 P0: kickoff off 4f4f20f; autonomous+self-merge (plan+prototype-first satisfied); storage = named flows; prototype ALL-CASES-HELD + colored Artifact approved; D1/D2 captured. → P1.
- 2026-07-24 P1: architect + qa dispatched to author requirements folding D1/D2 + the 4 OQs + the report-block model.

## Out-of-scope carries
- Report-block EXECUTION semantics (generating the actual report content) may exceed FB-P1's persistence scope — architect to scope at Phase 1 (serialize-now vs execute-now).
- Concurrent CRC-screen realign (separate `/fast-dev-flow`, prototype under review) — not this batch.

## Test ledger
- base (`4f4f20f`): TBD at Phase-3 entry.
