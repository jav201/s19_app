# batch-59 — Post-mortem (CRC Designer view-fidelity rebuild to Variant B)

**Outcome:** the shipped CRC Designer became the approved Variant-B "coverage-first bench" — wide LIVE-rendered coverage window hero + verdict/warnings hero row + 3-column bench with a roomy JSON preview — closing the batch-58 design-fidelity gap. 3 increments, all gates green, 0 engine change, 0 frozen-file diffs. Branch `feat/batch-59-crc-view`, commits `3ffbf85` / `266dae6` / `41f5a87`.

## What worked
- **Root-cause find at draft-time (V-1):** the "flat form" was not a missing feature — the `crc-*` CSS classes were **entirely undefined** in `styles.tcss`, so the panel fell back to Textual default stacking. This reframed the batch from "add layout" to "define the CSS + re-nest", and made it purely additive.
- **The `/tui-design` PROTOTYPE.md flow (new this session) drove the design.** Sub-shape A (mount the redesign inside the real `S19TuiApp`, reuse shipped `#crc_*` widgets by id) produced an honest, iterable prototype; SVG-in-HTML render let the operator art-direct (verdict/warnings up, JSON roomy) before any production code.
- **Design-fidelity ATs with teeth (US-L5).** AT-B59-03/08 assert `len(distinct bench-column ancestors)==3` — provably `==1` on the flat form, so a regression to single-column fails the gate. This is the control that would have caught batch-58's miss.
- **Preservation was cheap and provable.** All 29 `#crc_*` ids re-nested verbatim; the 20 batch-58 crc tests are id-scoped (`query_one`), so re-nesting could not un-wire a handler (P-1). AT-B59-06 re-proves a real handler fires through the re-nested tree.
- **Reviews caught real defects.** Phase-2 qa found the live-window oracle hole (B2 — a partial hardcoded-hex mock would have passed the "live" gate); Inc-2 code-review found F1 (the hero showed a `store` word under `on_gap_conflict="abort"` that the sibling preview deliberately refuses — a false-confidence surface on the primary readout). Both fixed with 0 new engine math by reusing shipped functions (`compute_target_crc`, `evaluate_target`).

## What didn't (friction / scope)
- **The requirements shipped Phase 1 with a stale layout** (verdict in bench col3) because the operator's hero-row refinement landed after derivation — Phase 2 forced a 13-amendment iterate-to-refine (§6.7). Root cause: the design was still being art-directed during Phase 1. Not waste (the fold is the mechanism), but a full cross-review cycle it caused.
- **qa was folded into Phase 2 rather than run in parallel at Phase 1** (deliberate, to avoid a same-file write conflict with the architect). It worked — qa owns the Phase-2 pass anyway — but it means the AT-vacuity shift-left happened one gate later than the ideal.

## Scope drift
- **F1 fix (abort-contract gating) was slightly more than "pure re-arrangement"** — but it's a correctness/safety fix on the new live surface, discharged in-batch. **OQ-1 (live window)** was likewise a deliberate operator-confirmed step beyond pure layout (a static window would be a fidelity lie). Both recorded, both bounded.

## Metrics
- Iterations: Phase 2 = 1 iterate-to-refine (13 amendments); Phases 1/3/4 = 0.
- Findings: Phase-2 across 3 reviewers = 3 blockers (all folded) + 7 major + minors; Phase-3 code-review = 1 MED self-fixed (F1) + 1 MED accepted-design (F3) + LOWs. 0 HIGH anywhere. 0 surviving blockers.
- Tests: 32 crc-view nodes (11 AT + F2 + 20 batch-58 preservation), all green; full gate suite 1772 passed. 0 engine-frozen diffs.

## Items proposed for the next batch (→ BACKLOG)
- **F4 (LOW):** window-level warn/ignore branch test (mirror AT-058-08 for the window; the abort/refuse path is pinned, warn/ignore isn't).
- **batch-58 snapshot-regen closeout (pre-existing, NOT batch-59):** the 19 `tc016s` failures are batch-58's uncommitted 10th-rail baselines — regenerate in canonical CI (`snapshot-regen.yml`, textual==8.2.8; local FORBIDDEN). This predates and outlives batch-59.
- **F3 (accepted design, revisit-if-needed):** the window shows labeled concat/fill comparison hexes under abort-refusal (store word gated); if strict display-parity with the preview (hide the comparison hex too) is ever wanted, it's a one-line guard.
- Carry: the batch-58 LOW review carries + the operator-flagged N1-N5 asks remain in `.dev-flow/BACKLOG.md`.

## New control candidate (for operator AskUserQuestion — NOT auto-encoded)
- **Design-fidelity AT:** when a prototype is operator-approved, an AT must assert the shipped layout matches the prototype's SIGNATURE elements (a rendered hero, a multi-column container), not merely functional widget presence — the exact gap that let batch-58 ship a functional-but-off-design view. Encoded ad-hoc as US-L5/AT-B59-03 this batch; generalizing it (extends C-32 "assert-painted-result") needs its own AskUserQuestion before touching `~/.claude/`.
