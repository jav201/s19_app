# PLAN — batch-54 · Multi-line A2L header parsing (P-1b prerequisite, split batch-A)

**BLUF:** Make the A2L parser read multi-line CHARACTERISTIC / MEASUREMENT / AXIS_DESCR headers (the real ASAM convention) so `char_type` / `deposit` / `address` / axis `MaxAxisPoints` populate instead of `None`. This is the **prerequisite** the batch-50 Phase-2 review surfaced (49/50 demo CHARACTERISTICs parse `char_type=None` because the parser requires all 7 mandatory params on ONE line). Split from the inline-axis **length summer** (batch-55, P-1b proper), which builds on this. Requires an **operator-approved a2l.py unfreeze** (re-freeze at close, batch-50 P-2 pattern).

## Where we are
- **Phase:** 0 (story intake / DoR).
- **Branch:** `claude/a2l-multiline-headers-b54` off `origin/main` `640de1b` (batch-51 FB merged).
- **RC-1:** ✅ PASS @ `640de1b`. batch-51 A2L diff EMPTY (independently verified). a2l.py re-frozen (needs unfreeze). `parse_characteristic_header` still has `len(parts) < 7` single-line guard (`a2l.py:327`) → multi-line NOT shipped → batch genuinely needed.

## Standing authorization (batch-54, per-batch — operator AskUserQuestion 2026-07-20)
- **Scope:** SPLIT — this batch = header parsing only; length summer = batch-55.
- **a2l.py unfreeze:** APPROVED (re-freeze as a post-merge follow-up PR at close, batch-50 P-2 pattern).
- **Autonomy + merge:** Autonomous + self-merge (gated: green CI + final independent PR-level qa-reviewer pass; a HIGH finding blocks + returns to operator).
- **Recording:** FULL.

## Objective / the change
The mandatory CHARACTERISTIC header is `<LongIdentifier> <Type> <Address> <Deposit> <MaxDiff> <Conversion> <LowerLimit> <UpperLimit>`; in real ASAM A2L these span multiple body lines (fixture `ASAP2_Demo_V161.a2l:3321-3328`). Current parsers require one 7-token line → fail on multi-line. Planned changes (Phase-1 design):
- **`build_section_tree` (`a2l.py:136-167`)** — strip `/* … */` block comments from body lines (currently kept verbatim → `CM.IDENTICAL /* … */` pollutes tokens; the architect's batch-50 BLOCKER-1 compounding finding).
- **`parse_characteristic_header` / `parse_measurement_header` (`a2l.py:324`)** — assemble the mandatory params by flattening the comment-stripped body (quote-respecting), skipping the leading LongIdentifier string, reading the next positional tokens. Superset of the single-line path (no single-line regression).
- **`_first_header_line` (`a2l.py:348`)** — gather the full multi-line header, not just the first matching line.
- **`axis_meta` capture (`a2l.py:1061-1069`)** — read the FULL AXIS_DESCR body (comment-stripped) so `MaxAxisPoints` (token[3]) + an `AXIS_PTS_REF`/external flag are captured (batch-50 architect BLOCKER-1/2).

## Acceptance (black-box, C-35 executed at draft time)
- The ASAM demo goes from **1/50 → 50/50** CHARACTERISTICs with `char_type` populated; STD_AXIS CURVE gets `char_type=CURVE`, `record_layout_name=RL.CURVE.SWORD.SBYTE.DECR`, `address=0x810300`, `axis_meta` with MaxAxisPoints=8 + external=False; COM_AXIS gets external=True (AXIS_PTS_REF captured).
- MEASUREMENTs unchanged or improved (24/25 → all with length).
- **No single-line-header regression:** existing `test_a2l_record_layout_length.py` / `test_tui_a2l.py` / `test_a2l_*` suites stay green.
- Length stays `None` for CURVE/MAP (that's batch-55) — this batch only populates the HEADER fields, not the array length.

## Risks / watch-items
- **R1 (regression surface):** touches the core header parser → ALL 50 CHARACTERISTICs / 25 MEASUREMENTs re-parse. Full guard suite + snapshot check mandatory. Baseline shifts (1/50 → 50/50) will move any test that asserted the old None-heavy parse — reverse-census (C-26) every touched field.
- **R2 (frozen tests):** new tests go in a NON-frozen sibling; `test_tui_a2l.py` is tc032-frozen. But this batch UNFREEZES a2l.py, so its SOURCE guard is lifted — still keep tests out of the frozen test files unless the unfreeze covers them (decide at Phase 1).
- **R3 (comment grammar):** ASAM has `/* */` block (may span lines) AND possibly `//` line comments; strip both safely without eating string contents. C-17-adjacent: comment-stripping over untrusted file text — verify no injection/crash on malformed comments.
- **R4 (quote handling):** LongIdentifier + some fields are quoted strings possibly containing spaces; the flatten must be quote-respecting (`_split_line_respecting_quotes` exists).
- **R5 (a2l.py re-freeze):** follow-up PR-B off merged main (same as batch-50 P-2).

## Conventions honored
C-35 (execute parser over real demo at draft time — the whole reason this batch exists). C-26 reverse-census on every touched field. C-27 dual-guard (a2l.py unfrozen this batch → re-freeze at close). C-19/C-34 full-guard-host run. Docstring order + type hints. a2l.py canonical + facade re-exports.

## Out-of-scope carries
- batch-55: the inline-axis length summer (P-1b proper) — seed in the batch-50 `01-requirements.md §7`.
- batch-51 FB /dev-flow-sync (its step; independent).

## Decision log
- 2026-07-20 · Phase 0 kickoff · SPLIT scope, a2l.py unfreeze approved, autonomous+self-merge (operator AskUserQuestion). RC-1 clean @ 640de1b; multi-line NOT shipped (verified). Branch cut. Batch-number 54 (FB reserved 52/53).
