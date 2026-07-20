# PLAN — batch-50 · A2L length cleanup + a2l.py re-freeze

**BLUF:** Finish the A2L length-derivation work (P-1b: CURVE/MAP/axis sizing), clear the last a2l.py lint debt (F841 at `a2l.py:942`), then re-freeze `a2l.py` into the engine-guard set (P-2) — in the correct sequence: **a2l.py source edits first, re-freeze last**. The re-freeze is a hard-sequenced **follow-up PR** (feasibility finding below), not a same-PR increment.

---

## Where we are
- **Phase:** 0 (Story intake & Definition of Ready) — awaiting gate.
- **Branch:** `claude/a2l-cleanup-batch-7dcd53` (real worktree `trusting-lichterman-f08516`), cut off `bdebc89` = `origin/main` tip.
- **RC-1 base-currency:** ✅ PASS @ `bdebc89`. `git fetch` clean; HEAD == origin/main == merge-base; 0 ahead / 0 behind; no rebase.

## Objective
Three backlog items, one tight batch, correct sequence:
1. **P-1b** — derive length for CURVE/MAP/axis CHARACTERISTICs (AXIS_DESCR + MATRIX_DIM + RECORD_LAYOUT), *without ever under-reporting* (false-green memory-check hazard). Extends P-1 (scalar VALUE, PR #93).
2. **F841** — remove the unused `header` local at `a2l.py:942` (`header = header_meas or header_char`; never read — the code uses `header_meas`/`header_char` directly).
3. **P-2** — re-freeze `a2l.py` into the C-27 dual-guard frozen set (`_ENGINE_PATHS` in `tests/test_engine_unchanged.py` **and** `tests/test_tui_directionb.py` tc031 list). **Guard-files-only; no a2l.py source change.**

## Standing authorization (batch-50, per-batch — NOT carried from batch-49)
- **Autonomy + merge:** GRANTED — autonomous end-to-end + **self-merge**. Merge gated: green CI + a FINAL independent PR-level `qa-reviewer` pass over the whole diff vs `main` (dual traceability intact · 0 engine-frozen diffs · no cross-increment regression via C-26 · every gate carry discharged). A HIGH finding BLOCKS the merge and returns to the operator. (Operator AskUserQuestion 2026-07-19: "Autonomous + self-merge".)
- **Decision recording:** FULL — every un-asked decision → this PLAN decision log + `state.json.decisions_log` + `05-postmortem` + vault at sync. Autonomy is never silent. (Operator AskUserQuestion 2026-07-19: "Yes — full record".)
- **Language:** English.

## ⚠ Key feasibility finding — P-2 must be a FOLLOW-UP PR (hard sequencing)
The frozen guards diff a2l.py against the **`main`** ref (`git diff --stat main -- s19_app/tui/a2l.py`, both `tests/test_engine_unchanged.py:154/161` and `tests/test_tui_directionb.py:5961/5977`). Therefore:
- If P-2 re-adds a2l.py to the frozen set **in the same PR** that edits a2l.py (P-1b + F841), the guard **trips** — branch a2l.py ≠ main a2l.py until the PR merges. Chicken-and-egg.
- **Correct sequence:** PR-A (P-1b + F841) lands the a2l.py edits with a2l.py **still unfrozen**; merge to main. Then PR-B (P-2) — off updated main, **guard-files-only, zero a2l.py source diff** — re-freezes; `git diff main -- a2l.py` is now empty → guards pass.
- This is exactly the operator's "edits first, re-freeze last." Precedent: batch-49's canonical-CI snapshot regen was likewise a post-merge follow-up PR.

## Roadmap / increment plan (provisional — finalized after Phase-1 AT registry pin)
**PR-A (feature) — the /dev-flow batch proper:**
- Inc-1: **P-1b** CURVE/MAP/axis length derivation in `a2l.py` + tests in a NON-frozen sibling (`test_a2l_record_layout_length.py` or new `test_a2l_curve_map_length.py`; NEVER `test_tui_a2l.py` — frozen by tc032/C-27).
- Inc-2: **F841** remove the dead `header` local (`a2l.py:942`) + ruff-clean assertion (may fold into Inc-1 if ≤5 files and cohesive).
**PR-B (re-freeze) — post-merge follow-up:**
- Re-add `s19_app/tui/a2l.py` to both frozen lists; delete the "UNFROZEN" NOTE blocks; keep a2l.py source byte-identical to main. Verify tc031/tc032/test_tc027 all green.

## Key decisions
- (Phase 0) P-2 re-freeze split to a follow-up PR — forced by the guard's diff-vs-main mechanic (finding above).
- P-1b **safety contract (design default, pending operator scope pick):** derive a length ONLY when a **definite full byte span** is computable; where the span is ambiguous (external COM_AXIS via AXIS_PTS_REF, unresolvable RECORD_LAYOUT, partial dims), **stay `length=None` (honest grey)** — never under-report. False-green is worse than grey.

## Risks / watch-items
- **R1 (P-1b false-green):** a naive `el × axis_pts` under-reports STD_AXIS CURVE real span (25B vs 16B in the demo fixture) → memory check falsely passes. Mitigation: full-span-or-None contract + a negative AT proving under-reportable shapes stay None.
- **R2 (structural):** `_infer_length_characteristic` is called (a2l.py:1056) BEFORE the AXIS_DESCR child walk (a2l.py:1061); axis_meta isn't available inside it yet. P-1b needs either a reorder or a post-axis-walk length pass. Design in Phase 1.
- **R3 (frozen test files):** P-1b tests must NOT land in `test_tui_a2l.py` (frozen by tc032/C-27) — route to a non-frozen sibling. (Origin: batch-38 F-1.)
- **R4 (P-2 timing):** re-freeze PR must be cut off *merged* main, else guard trips. Enforced by the follow-up-PR structure.

## Conventions honored
- CLAUDE.md engine-layer note: a2l.py is the canonical A2L module; add public symbols here + re-export from facades. Docstring section order. Type hints mandatory.
- C-27 dual-guard (both frozen lists). C-26 reverse-census on any touched symbol. C-19/C-34 full-guard-host run per render/engine increment.
- REQUIREMENTS.md R-A2L-005 (length metadata) + the "underivable length is not a schema failure" / "scalar VALUE derives from RECORD_LAYOUT" notes (lines 387-399) — P-1b extends these.

## Out-of-scope carries
- Batch-49 `/dev-flow-sync` to the vault (still pending; independent of this batch).
- P-3 string-precision on the address branch (blocked by frozen tc032; not this batch).
- `report_service:1091` raw source_path heading (cosmetic carry).

## Test ledger
- Baseline: TBD (measure at Phase-1/Inc-1 entry, `pytest -q -m "not slow"`).
- Additions: P-1b TCs + ATs (Phase 1). F841: ruff-clean assertion (may reuse existing lint gate).

## Decision log (human mirror of state.json.decisions_log)
- 2026-07-19 · Phase 0 kickoff · Authorization: autonomous + self-merge, full recording (operator AskUserQuestion). Language English. Batch id 2026-07-19-batch-50.
- 2026-07-19 · Phase 0 · Feasibility: P-2 re-freeze split to a post-merge follow-up PR (guard diffs vs main).
- 2026-07-19 · Phase 0 · P-1b scope LOCKED = **Moderate** (inline-axis RECORD_LAYOUT span; COM_AXIS/external stay grey; no cross-object AXIS_PTS) — operator AskUserQuestion.
- 2026-07-19 · Phase 0 · **DoR gate SELF-APPROVED** — all 3 stories READY; Coverage/Certainty/Evidence axes met. → Phase 1.
- 2026-07-19 · Phase 1 · architect + qa-reviewer dispatched in parallel (HLR/LLR + Acceptance ; validation method + AT catalog).
- 2026-07-19 · Phase 1 · Requirements assembled + reconciled into ONE canonical AT/TC registry (C-21 pin). New ids R-A2L-008/009/010. Lint clean (19 shall, 0 modal-should, 0 placeholders).
- 2026-07-19 · Phase 1 · **Requirements gate SELF-APPROVED** — Coverage/Certainty/Evidence met. → Phase 2 triple review.

## Phase status
- **Phase 0** ✅ approved (all 3 stories READY; P-1b scope Moderate; P-2 = follow-up PR-B).
- **Phase 1** ✅ approved (3 HLR / 8 LLR; canonical AT-090..095 / TC-090..096 pinned).
- **Phase 2** ✅ triple review complete → BLOCKERS on P-1b → operator **DESCOPED** (2026-07-19): defer P-1b, ship F841 + P-2 only. F841 + P-2 reviewed CLEAN by all 3 agents. Reduced gate self-approved. See `02-review.md`.
- **Phase 3** ✅ COMPLETE — Inc-1 (F841) APPROVED. a2l.py −1 dead-store line + NEW test_a2l_f841_cleanup.py (TC-094/AT-094). ruff F841 0; new test 2 passed; frozen guards 10 passed; C-34 full guard-host 174 passed; code-reviewer independent APPROVE 0 findings.
- **Phase 4** ▶ in progress — orchestrator-owned gate suite `pytest -q -m "not slow"` running (C-25); expected baseline+2 green.
- **Phase 5** ✅ postmortem approved; **C-35 encoded** (global dev-flow.md, operator-approved) + lineage memory updated.
- **Phase 6** ✅ docs written (traceability-matrix, functionality, executive-summary; diagrams N/A — no architectural change). No REQUIREMENTS.md change (F841/P-2 add no behavior).
- **PR-A** ✅ committed `9e9a90f`, pushed, opened [#99](https://github.com/jav201/s19_app/pull/99). ▶ CI running (tui-ci blocking + snapshot advisory). Awaiting green → final PR-QA gate → self-merge.
- **PR-B (P-2 re-freeze)** — PENDING PR-A merge. Prepared edits (guard-files-only, off MERGED main):
  1. `tests/test_engine_unchanged.py` — re-add `"s19_app/tui/a2l.py"` to `_ENGINE_PATHS` (after `validation` @ ~:124); delete the 5-line UNFROZEN NOTE (:125-129).
  2. `tests/test_tui_directionb.py` — re-add `"s19_app/tui/a2l.py"` to the tc031 `_ENGINE_PATHS` tuple (@ ~:5424); delete the UNFROZEN NOTE (:5425-5428).
  Verify: `pytest -k "tc031 or tc032 or tc027"` green + `git diff main -- s19_app/tui/a2l.py` empty.

## REDUCED SCOPE (post-Phase-2 operator descope)
- **PR-A / Inc-1 — F841:** delete dead `header` local (`a2l.py:942`) + TC-094/AT-094 in a NON-frozen sibling.
- **PR-B — P-2 re-freeze (post-merge follow-up):** re-add `a2l.py` to both `_ENGINE_PATHS`; delete UNFROZEN notes; guard-files-only, off merged main.
- **DEFERRED → future batch:** P-1b (needs multi-line-header parsing first). Seed: `01-requirements.md §7` + `02-review.md`.

## Decision log (continued)
- 2026-07-19 · Phase 1 gate SELF-APPROVED → Phase 2.
- 2026-07-19 · Phase 2 triple review: 2 blockers (P-1b multi-line collision) / 8 majors / 0 security blocker-major. Central finding exec-verified (49/50 demo CHARACTERISTICs parse char_type=None).
- 2026-07-19 · **Operator descope (AskUserQuestion):** defer P-1b; ship F841 + P-2; R2 cap N/A. → Requirements amended (§6.5), reduced gate self-approved → Phase 3.
