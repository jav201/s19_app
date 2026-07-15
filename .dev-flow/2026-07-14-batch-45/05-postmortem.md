# 05-postmortem.md — batch-45 (Memory-Map entropy Band-Bands view)

**BLUF.** A clean, deletion-heavy feature batch (net ≈ −2100 lines): replaced the all-grey
validation-only Memory Map with an entropy Band-Bands view (band bar + textured region list +
At-a-glance histogram/sparkline + single-click region→hex) and retired the standalone entropy modal.
6 increments, 0 HIGH findings batch-wide, 0 story-kill, 0 scope drift, PASS at Phase 4. Two real
catches earned their gates: the Phase-2 set-site blocker (the only site the AT fixture reaches) and
the Phase-4 footer-drift containment miss (a removed footer-visible binding drifts every screen).

## What worked
- **Prototype→spec→build fidelity.** The operator-approved prototype (Variant 3) pinned the visual
  design; every LLR traced back to it; no design churn in implementation.
- **Phase-2 caught the two load-bearing gaps.** B1: the entropy set-site had to be
  `LoadedFile.entropy_windows` computed in `build_loaded_*` — the *only* site the AT fixture
  (`_install_case_02_loaded_file` → `build_loaded_s19`) reaches; an app-state mirror would have left
  every map AT empty. B2: the fixture couldn't span the needed bands → the seeded `_two_band_loaded`.
  Both fixed in the fold, before a line of Phase-3 code.
- **Code-review earned its keep.** Inc-2 F1 (cross-gap same-band over-merge — a real mis-render on
  the feature's primary target: firmware with multiple padding/table regions) caught + fixed with a
  gap-case AT (RED-if-revert confirmed). Inc-2 F2 hardened the AST-purity guard for bare-name calls.
  The DuplicateIds re-render bug was caught by the consumer suites and guarded.
- **C-17 preserved on a LIVE path.** Rather than let the batch-43 A2L-symbol markup-safety test become
  dead-code coverage, the detail pane was re-wired to region-row selection (Inc-3), keeping
  `build_detail_text` + its hostile-name guard meaningful.
- **Deletion done safely.** Inc-5's per-symbol C-26 reverse-census ran *before* any deletion → 0 live
  references, KEEP-list verified wired, coverage preserved (compute_entropy via test_entropy_service.py).

## What didn't (root causes)
- **F-1 (Phase-4) — footer-binding snapshot containment miss.** Retiring the entropy modal removed
  `Binding("e","show_entropy","Entropy",show=True)`, which was **footer-visible**. The Footer renders
  on *every* screen, so all wide-width `tc016s` snapshot cells drifted — not just the 2 map cells the
  Inc-2 snapshot handling marked. Surfaced only at the Phase-4 full-suite run (the increment agents ran
  file subsets, never the snapshot suite). Fixed test-only (`_batch45_footer_drift_marks`, 18 cells,
  tight per-cell, 0 xpassed). **Not a shipped defect** (behavior green; SVG baseline bookkeeping) but a
  real prediction gap → control candidate below.
- **F-2 (Phase-1) — set-site under-specified.** LLR-045A.6 shipped as "assumed — verify Phase 2." The
  flag was correct and Phase-2 closed it, but a writers-grep (C-15.1) on `entropy_windows` at draft
  time would have pinned the loader site in Phase 1. Left-shift efficiency gap, not a correctness gap.

## Scope drift: NONE
All work inside the approved 4 stories (US-045a–d). Inc-2 split 2a/2b and Inc-5 split 5a/5b on the
5-file cap (surfaced, not silent). The detail-pane retention ruling (keep R-TUI-041 R-3, re-wire to
region selection) preserved shipped behavior rather than dropping it.

## Metrics
- Iterations/phase: 0:1, 1:1, 2:1 (fold), 3:6 (increments; 2a/2b + 5a/5b splits), 4:1 (iterate-to-fix).
- Findings: Phase-2 = 3 blockers + 4 majors + minors, all folded (0 story-kill, security OK-to-ship
  low-surface). Code-review = Inc-1 F1(MED), Inc-2 F1(MED)/F2(MED)/F4(LOW), Inc-5 F1(MED) — all applied;
  **0 HIGH batch-wide**. Phase-4 = 1 iterate-to-fix (footer drift, test-only).
- Gate: 1374 passed / 0 failed / 23 xfailed (20 batch-45 drift + 3 pre-existing) / exit 0.
- Net ≈ −2100 lines (Inc-5 −2304; feature +~200). Requirements: +3 (R-TUI-060/061/062), amend 1
  (R-TUI-041), retire 2 (R-TUI-050/051).
- Engine-frozen: 0 diffs every increment (C-27 dual-guard).

## Control candidate (PROPOSE, not encode — per feedback_devflow_control_encode_approval)
**C-CAND (batch-45): footer/shared-chrome binding-drift snapshot census.** When an increment
adds/removes/changes an App-level `Binding(..., show=True)` (or any shared-chrome element rendered on
every screen — Footer, Header, rail), the snapshot-drift census MUST mark **every** snapshot cell that
renders that chrome, not only the feature's own screen cells. Generalizes C-22 (per-cell drift
reasoning) to shared chrome: a footer-visible binding change drifts the whole `tc016s` matrix at the
widths where it renders. Origin: F-1. Detection today relied on the Phase-4 full-suite run; a
"does this change Footer/Header/rail bindings?" check at the increment snapshot step would catch it at
Inc-5. Awaiting operator approval before entering the lineage.

## Items for next batch / carries
- **Post-merge:** dispatch `snapshot-regen.yml` to regenerate the 20 drift baselines (18 footer + 2
  map) in canonical CI and retire `_batch45_footer_drift_marks` + `_batch45_map_drift_marks` (batch-44
  lane).
- **Cosmetic (Inc-4 risk):** the band bar's fixed `_BAND_BAR_WIDTH=60` clips to ~21 cols at 120×30 now
  the glance shares the row — a responsive width would need a snapshot regen; deferred.
- **Field-audit remainder** (separate batches): patch-editor responsive 3-column (operator-approved,
  next), B1 Issues paging, B3 A2L two-extra-chars (needs live repro), N2 Issues filter/sort, N4 paste
  everywhere.
