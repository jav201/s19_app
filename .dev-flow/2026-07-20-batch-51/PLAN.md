# PLAN — batch-51 · Flow Builder (CHECK + notices/completed-with-issues + Direction A UI)

**BLUF:** Extend the shipped Flow Builder tracer (`SOURCE→PATCH→WRITE-OUT`) into the operator-specified
pipeline's first slice: a **LOAD** block that surfaces image-integrity findings as **WARN notices**
(never aborting the chain), a read-only **CHECK** block (address-list json → report, image passes
through), the new **`notices`** block status and **`completed-with-issues`** amber flow status
(distinct from `failed`), and the **Direction A "Pipeline Ledger"** TUI (vertical block-node flow +
status gutter + block separators + twin memory ribbon). **CRC (batch-52) and flow.json persistence /
external-import (batch-53) are OUT.** Prototype-validated model + chosen TUI direction are inputs.

---

## Where we are
- **Phase:** 0 (Story intake & Definition of Ready) — in progress → gate.
- **Branch:** `feat/batch-51-flow-builder`, cut off `origin/main` tip `2b285a8`.
- **RC-1 base-currency:** ✅ PASS @ `2b285a8`. Cut after A2L **batch-50** fully merged (PR #99 F841
  `76652756` + PR #100 P-2 a2l.py re-freeze `2b285a8`). HEAD == origin/main == merge-base; 0/0.
- **Design source committed:** `736113c` (prototypes/flow_builder.{prototype.py, NOTES.md, screen.prototype.html}).

## Objective (operator-specified, prototype-validated)
The Flow Builder composes an ordered pipeline of typed blocks over an S19 image, reusable across a
file and its variants. Batch-51 delivers the lowest-risk value slice (no new untrusted-file loader,
no CRC address-space seam):
- **LOAD** (extends shipped SOURCE): validates image integrity → emits **WARN notices**; never
  aborts. Only an unresolvable/unopenable image = **STOP** that breaks the image.
- **PATCH** (shipped, keep) · **WRITE-OUT** (shipped, keep).
- **CHECK** (new, read-only): address-list json → report; image **passes through unchanged**.
  Per-block gating flag (advisory default | block-its-own-op-when-invalid). **INVARIANT: the CHAIN is
  never blocked**; a block marks *itself* blocked only when *its own operation* is invalid.
  Validation/blocking rules are **highly user-visible** → spec with maximum clarity (operator).
- **Status model:** block status +`notices`; flow status +`completed-with-issues` (amber, distinct
  from `failed`); the amber outcome **MUST appear in any generated report**.
- **UI: Direction A "Pipeline Ledger"** — vertical block-node flow + per-block status gutter +
  **block separators** (Rule between block widgets, tone `$rule`) + **twin memory ribbon**; 80×24
  ceiling + width-narrow/density-compact; `sev-*` tokens; `markup=False`/`safe_text`.

## Standing authorization (batch-51, per-batch — NOT carried from batch-50)
- **Autonomy + merge:** GRANTED — autonomous end-to-end + **self-merge** under a FINAL independent
  PR-level `qa-reviewer` pass (dual traceability · 0 engine-frozen diffs · no cross-increment
  regression via C-26 · every gate carry discharged). A HIGH finding BLOCKS + returns to operator.
- **Decision recording:** FULL — every un-asked decision → this PLAN decision log + `state.json` +
  `05-postmortem` + vault at sync.
- **Trigger:** started after the operator-set trigger was **verified via git** (A2L batch-50 fully
  merged + LIVE BACKLOG refreshed 2026-07-20). Coordination handoff sent to the A2L session.
- **Language:** English.

## Hard constraints
- **FROZEN — do not touch** (C-27 dual-guard, re-frozen at batch-50 PR #100): `core.py`,
  `hexfile.py`, `range_index.py`, `validation/`, `tui/mac.py`, `tui/color_policy.py`,
  **`tui/a2l.py`**, and the frozen TEST files. Batch-51 lives in `services/flow_model.py`,
  `services/flow_execution_service.py`, `screens_directionb.py`, `app.py`, `styles.tcss` + new
  files/tests — none frozen. Reuses `run_check_document` (tui/changes), `build_loaded_*`
  (load_service) — not frozen.
- **≤5 files per increment.** No abstractions not derivable from an approved LLR.
- **Untrusted-render (C-17):** CHECK reports + LOAD integrity messages carry file-derived strings →
  render `markup=False` / `safe_text` (the shipped panel already does; maintain + AT a hostile payload).
- **Snapshot drift (project C-22/C-28/C-30):** the Direction A render changes `#screen_flow` cells →
  expect drift → **canonical-CI regen follow-up** (local regen FORBIDDEN). Rail unchanged (Flow = rail-8).

## Candidate user stories (Phase 0 — for DoR gate)
- **US-085 — LOAD integrity-notices:** engineer adds a LOAD block for an image with integrity issues
  → observes WARN notices on the block, `notices` status, chain continues; an unresolvable image →
  STOP, image broken, downstream skipped. (Behavioral; observable on the run-result surface.)
- **US-086 — CHECK block (read-only, gating):** engineer adds a CHECK block (address-list json) →
  observes a present/absent report; image passes through unchanged to downstream; CHECK finding is
  advisory (chain continues); the per-block gate marks only the block itself. (Behavioral.)
- **US-087 — status model + completed-with-issues:** after a run, engineer observes flow status
  CLEAN / **ISSUES (completed-with-issues)** / FAILED; ISSUES = output produced + advisories, distinct
  from FAILED = no/broken output; the amber outcome appears in any generated report. (Behavioral.)
- **US-088 — Direction A "Pipeline Ledger" UI:** the Flow Builder screen renders the flow as a
  vertical block-node pipeline with status gutter, **block separators**, and the **twin memory
  ribbon**, at 80×24 and wider. (Behavioral, observed through the rendered screen.)

## Roadmap / increment plan (provisional — finalized after Phase-1 AT registry pin)
- **Inc-1 — status model + engine (headless):** `flow_model.py` (+`CheckBlock`, `notices` /
  `completed-with-issues` tokens, per-block gating field, `Finding` severity) +
  `flow_execution_service.py` (LOAD notices, CHECK read-only pass-through + gating, abort-asymmetry:
  image-breaking vs read-only failure, flow-status roll-up incl. `completed-with-issues`). Reuses
  `run_check_document`. Unit-tested end-to-end headless. **The keel — no Textual.**
- **Inc-2 — Direction A UI:** `screens_directionb.py` `FlowBuilderPanel` → Pipeline-Ledger render
  (block-node flow, status gutter, block separators, twin memory ribbon, flow-status banner) +
  CHECK/LOAD in the add dropdown + render the extended `FlowRunResult`; `styles.tcss` (sep + ribbon
  + banner classes) + `app.py` wiring if needed. Pilot ATs at both regimes. `markup=False`/`safe_text`.
- **(Boundary — STOP here for batch-51.)** No CRC, no persistence, no external-import.

## Key decisions (log)
- **2026-07-20** — Flow Builder renumbered **batch-50 → batch-51** (A2L cleanup owns batch-50; PR
  titles "batch-50 PR-A/…"). Verified via git.
- **2026-07-20** — Started autonomously after the operator-set trigger verified via git (A2L merged +
  backlog refreshed). `.dev-flow/state.json` reset batch-50 → batch-51 (batch-50 artifacts preserved
  in its subdir); recorded as an autonomous init decision.
- **2026-07-20** — Prototype-validated forks locked (operator, prior session): `completed-with-issues`
  amber status (must appear in report); per-block gating with "chain never blocked" invariant; CRC =
  single block, deferred to batch-52.

## Risks / watch-items
- **R-1** Untrusted-render sink on CHECK/LOAD strings → C-17 markup-safety LLR + hostile-payload AT.
- **R-2** Snapshot drift on `#screen_flow` → canonical-CI regen follow-up (not local).
- **R-3** "Blocking rules highly user-visible" (operator) → the advisory-vs-gate distinction must be
  crisp in the UI and spec; avoid any hidden chain-kill.
- **R-4** `run_check_document` reuse — verify its signature/return shape at draft time (C-15 identity).
- **R-5** Geometry at 80×24 (project C-13/C-23) — pilot-measure the ribbon + node columns in the real
  boxed panel; don't inherit the HTML prototype's width budget (C-16 cross-tech prototype caveat).

## Out-of-scope carries (recorded, not built)
- CRC block (template lib + address-space growth, ADR §7) → **batch-52** ("be very thorough").
- flow.json save/load + external-file→import + variant reuse → **batch-53**.
- PKI binary-region extraction · CRC-as-sub-flow · multi-image scope → backlog.

## Test ledger
- Base suite @ `2b285a8`: 1593 passed (per batch-50 close). Post = base − D + A (reconcile each gate).

## OPEN increment-scope flag (decide at the Inc cut)
- **UI gating setter?** LLR-086.1 gives `CheckBlock` a `gating` field (default `advisory`); the engine
  (Inc-1) supports both `advisory` and `block-own-op`. Question for Inc-2: expose a UI **setter** for
  gating (so a user can create a `block-own-op` CHECK and SEE the distinct `error` status), or ship
  gating engine-only in batch-51 with the visible distinction being the resulting status
  (notices vs error)? Operator emphasis "highly user-visible" leans toward a minimal UI selector — but
  keep Inc-2 ≤5 files; if it overflows, split the gating-UI to a follow-up. Software-dev to assess at Inc-2.

## Decision log (human-readable mirror of state.json.decisions_log)
| date | phase | decision | note |
|------|-------|----------|------|
| 2026-07-20 | 0 | kickoff (autonomous) | trigger verified; branch off 2b285a8; prototypes committed 736113c; renumber 50→51 |
| 2026-07-20 | 0 | DoR gate self-approved | 4 stories US-085..088 READY; already-shipped check clean |
| 2026-07-20 | 1 | requirements self-approved | architect+qa parallel; 4 HLR/17 LLR/9 AT; roll-up 3-way (LLR-087.2); chain-never-blocked (LLR-086.4); D1 LOAD=source; frozen 0 |
| 2026-07-20 | 2 | tri-review: blocker+2 major folded, gate self-approved | architect+qa CONVERGED on AT-086c blocker (phantom `block` value) → reauthored (REC-4) to advisory-vs-block-own-op on unreadable-doc; matrix tabulated (REC-5); markup-sink sweep widened (REC-6); security clean. iter 2×1 |

## Sync carries (independent of this batch)
- **batch-49** awaiting-sync · **batch-50** awaiting-sync → operator runs `/dev-flow-sync`.
