# PLAN — 2026-07-20-batch-56 · alignment-aware padding sizing (P-1b follow-up)

> Living compendium. Updated at every gate + checkpoint. BLUF-first.

## BLUF / where we are
- **Objective:** extend `_record_layout_full_span` (`s19_app/tui/a2l.py`) to model ASAM alignment padding, so CURVE/MAP RECORD_LAYOUTs that declare `ALIGNMENT_*` directives SIZE CORRECTLY (a cumulative-offset walk with per-component padding) instead of degrading to honest grey (batch-55's force-None). Preserve full-span-or-None for genuinely-unmodeled directives.
- **Phase:** **2 (cross-agent review) — RESUMED 2026-07-21.** Phase-0/1 authored 2026-07-20 (WIP `741e86e`, Phase-1 only, no code). Recovered onto a fresh branch off current `origin/main`.
- **Route:** full /dev-flow (frozen-`a2l.py` core-parser change under sanctioned unfreeze; correctness-sensitive math on a safety artifact).
- **Branch:** `feat/batch-56-alignment-aware` off `origin/main` `7954652` (batch-59 #113 tip). RC-1 clean: merge-base==tip.

## Standing authorization (operator, 2026-07-20, per-batch — NOT carried)
- **Autonomy:** end-to-end autonomous; self-approve gates with a named axis check; surface genuine either/or product decisions (esp. the packed-vs-natural alignment default) via AskUserQuestion.
- **Merge:** GRANTED, gated on green CI + final PR-level qa pass vs main (0 OTHER-frozen diffs; C-26; carries discharged). HIGH → blocks + returns.
- **a2l.py unfreeze:** APPROVED; re-freeze post-merge PR-B.
- **Decision recording:** FULL.

## RC-1 — PASS
- Base = origin/main `1cc5683` (batch-55 PR-B). merge-base == HEAD == origin/main → no rebase.
- **Already-shipped = NOT shipped:** `_record_layout_full_span` currently FORCES `None` on `ALIGNMENT_*` (a2l.py:1161); no offset/padding computation.

## The governing rule (to PIN in Phase 1 vs the ASAM spec) — the batch's main risk
- **R-A: Alignment applies ONLY when `ALIGNMENT_*` is explicitly declared in the RECORD_LAYOUT (or MOD_COMMON).** Absent any `ALIGNMENT_*`, the layout is **packed** (alignment=1, padding=0). This **preserves ALL batch-55 oracles by construction** (CURVE.STD_AXIS=25, MAP=51, FIX_AXIS=12 — those layouts are alignment-free). Operator-framed; confirm spec-defensibility in Phase 1.
- **R-B: Per-component padding** — each component's start offset is aligned UP to `ALIGNMENT_<class>` where <class> matches the component datatype's size (BYTE=1B, WORD=2B, LONG=4B, INT64/FLOAT64=8B, FLOAT16=2B, FLOAT32=4B). Standard ASAM.
- **R-C (Phase-1 DECISION): trailing record pad** — whether to pad the record's total size up to its max component alignment. Two readings; must decide + cite. Default lean: **decide in Phase 1 with an executed reference** (affects array-of-record stride vs single-object span).
- **Oracle-validation risk:** the demo is alignment-free → the batch-56 oracle is necessarily a SYNTHETIC fixture WITH `ALIGNMENT_*`, hand-computed from R-A/R-B/R-C. No client A2L to cross-check → the oracle is only as strong as the pinned rule. Phase 1 must hand-compute rigorously + EXECUTE (C-35) + consider any available reference (python a2l lib?) as a secondary check.

## Stories (Phase-0 DoR)
| ID | Title | Class |
|----|-------|-------|
| US-ALIGN | ALIGNMENT-bearing CURVE/MAP size correctly (padded); alignment-free unchanged | READY |
| US-P2b | Re-freeze a2l.py post-merge (PR-B) | READY (post-merge) |

## Roadmap (provisional)
1. Inc-1 — UNFREEZE a2l.py (2 guard files).
2. Inc-2 — alignment-aware `_record_layout_full_span`: replace the running-sum with a cumulative-offset walk that (a) detects declared `ALIGNMENT_*` directives, (b) pads each component to its class alignment, (c) applies R-C trailing pad per the Phase-1 decision, (d) keeps force-None for genuinely-unmodeled non-alignment directives; NEW oracle fixture + tests; REQUIREMENTS.md prose. Preserve batch-55 oracles.
3. PR-B (post-merge) — re-freeze.

## Decisions log (human mirror of state.json)
- **2026-07-20 · kickoff:** autonomous + self-merge; a2l unfreeze YES (re-freeze PR-B); full recording. RC-1 clean @ 1cc5683; alignment-aware NOT shipped. Feasibility flag raised: ASAM alignment semantics (packed-vs-natural) — governing rule R-A pins packed-absent-ALIGNMENT.

## Risks / watch-items
- **ASAM semantics correctness (R-A/R-B/R-C)** — the batch's central risk; pin with spec citations + executed oracle.
- **Batch-55 oracle preservation** — 25/51/12 MUST be unchanged (regression AT); the packed-default rule guarantees it, but assert it explicitly.
- **Offset-walk bound** — reuse `MAX_A2L_DECODE_BYTES` cap (padding can't blow up).
- **Frozen dual-guard (C-27)** — a2l.py unfrozen; run BOTH guards; new tests to a non-frozen file.
- **Snapshot drift** — the demo is alignment-free → NO A2L-view change expected (0 drift, like batch-55's non-drift). Verify at Phase 4.

## Out of scope
- Natural-alignment-by-default (R-A pins packed-absent-ALIGNMENT). MEASUREMENT length. External-axis derivation. Any A2L-view restyle.

## Test ledger
- Base (post batch-55): 1670 passed. Current `origin/main` (post batch-59 #113): gate suite 1772 passed (b59 Phase-4). Δ tracked per increment.

---

## RESUME 2026-07-21 — re-authorization + Phase-2 reconciliation

### Re-authorization (operator, per-batch, NEVER carried — re-asked at resume)
- **Autonomy:** end-to-end autonomous from Phase 2; self-approve gates with a named Coverage/Certainty/Evidence axis; full packets in-conversation.
- **Merge:** GRANTED (final PR-level qa pass vs main; HIGH blocks + returns).
- **RISK-1:** **SHIP LAYOUT-LOCAL, DEFER MOD_COMMON.** MOD_COMMON module-wide alignment stays under-modelled (R-A); reversible follow-up; needs a non-demo alignment oracle fixture. Preserves batch-55 oracles by construction.
- **a2l.py unfreeze:** GRANTED (PR-A removes from both `_ENGINE_PATHS` same-PR; PR-B re-freeze post-merge). New white-box tests → a NON-frozen file.
- **Prereq done:** batch-59 (#113 `7954652`) given a minimal dev-flow close — BACKLOG.md reconciled; `/dev-flow-sync` (b57+b58+b59) deferred as a vault-upload follow-up.

### Phase-2 reconciliation items (the two Phase-1 artifacts disagree — fold at the gate; qa catalog authoritative per §5.2)
1. **AT/TC id ranges:** 01-req AT-113..118 / TC-143..150 vs 01b-qa AT-113..121 / TC-143..153 → adopt the qa-catalog range (more ATs: adds AT-119 R-C, AT-120 DoS, AT-115 R-A-isolation).
2. **New-test file:** 01-req `test_a2l_inline_axis_length.py` vs 01b-qa **NEW** `test_a2l_alignment_sizing.py` → adopt the NEW file (C-27-cleaner; TC-151 still edits the non-frozen inline-axis file for the TC-133b supersede).
3. **Primary fixture oracle:** 01-req `ALIGNMENT_WORD 2` `[2]`→8/packed7 vs 01b-qa multi-class→16/packed13 → pick ONE canonical; both hand-computed + probe-grounded. (Lean 01b-qa multi-class 16/13: exercises 2 alignment classes + over-align, stronger.)
4. **R-C:** 01-req CLOSED (reading i, no trailing pad) vs 01b-qa OPEN (AT-119 17 vs 24). Operator/spec ruling = **no trailing pad** → R-C CLOSED; AT-119 asserts the no-trailing value (17). This is a memory-coverage semantics call (single object, not array element), NOT an AskUserQuestion (§6.2 R-C rationale).

### Phase-2 roadmap
- Dispatch `architect` + `qa-reviewer` + `security-reviewer` in parallel over 01-requirements + 01b-qa-catalog.
- Fold blockers (esp. the 4 reconciliation items above) into a single canonical §4.9 splice + §5.2 reconciliation; re-derive the increment cut (C-21) if the AT set changes.
- Then Phase 3 (implementation, ≤5 files/inc).

### Phase 2 — DONE (self-approved, autonomous), iter=1 → Phase 3
- **3 reviewers**, 0 HIGH / 0 redesign. architect: 3 reconciliation blockers (all id/registry) + 2 major. qa: 4 major (coverage/reachability). **security: 1 real MAJOR — `ALIGNMENT 0`/neg → `align_up` `o%0` ZeroDivisionError NOT caught by `(ValueError,TypeError)`.**
- **Fold (02-review.md):** canonical registry **AT-113..122 / TC-143..153**; primary fixture = multi-class **16/13**; **R-C=17** (no trailing pad); **+AT-122** (hostile alignment value non-int/0/neg → None) merging sec-M3+qa-M4; MOD_COMMON=**26** pinned as AT-114's named RED. Spec edits landed: LLR-A56.2 non-positive guard, LLR-A56.5 `align_up a<=1` short-circuit, §4.9 splice.
- **Re-cut (C-21):** Inc-1 unfreeze(2) · Inc-2 walk + NEW `test_a2l_alignment_sizing.py`(2) · Inc-3 supersede+docs(2) · PR-B re-freeze. New tests import `_write_a2l`/`_axis_meta` from the batch-55 module.
- **Decision:** the R-C no-trailing-pad ruling and the RISK-1 MOD_COMMON deferral are operator-set (kickoff); all other folds are unambiguous reviewer-agreed reconciliations. Recorded in state.json decisions_log.
