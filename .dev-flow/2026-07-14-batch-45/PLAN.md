# PLAN — batch-45 — Memory-Map Band-Bands entropy view + retire entropy pop-up

**Where we are:** Phase 1 complete, awaiting operator PLAN-APPROVAL gate (the single operator gate;
after approval Phases 2→6 run autonomously through PR, stop before merge — operator merges).

**Objective:** Replace the Memory Map's validation-only cell colouring (real files render all-grey)
with an ENTROPY "Band-Bands" view — proportional segmented band bar + textured per-region list +
docked "At a glance" histogram/sparkline; single-click region→hex; RETIRE the standalone entropy
pop-up (its function moves into the always-visible map). Origin: operator-approved prototype V3.

**Authorization:** plan-approval gate (operator AskUserQuestion 2026-07-14); merge NOT granted (stop
at PR opened + CI green). Per-batch, never carried.

**RC-1:** PASS @ origin/main `a015e28` (post #78/#79/#80). Branch `feat/batch-45-map-entropy`. N1
verified NOT-IMPLEMENTED; EntropyViewerScreen verified present.

## Stories / requirements
| US | Req | What | Status |
|----|-----|------|--------|
| US-045a | R-TUI-060 | band bar + textured region list | Phase 1 done |
| US-045b | R-TUI-061 | At-a-glance histogram + sparkline | Phase 1 done |
| US-045c | R-TUI-062 | single-click region → hex nav | Phase 1 done |
| US-045d | R-TUI-041 amend + R-TUI-050/051 retire | delete entropy pop-up; map supersedes | Phase 1 done |

## Key decisions (log)
- Prototype V3 (BAND BANDS) chosen by operator over grid/waveform (2026-07-14).
- **C-15 catch:** amendment target is R-TUI-041 (+ retire 050/051), NOT R-TUI-035/036 (those are
  unrelated command-bar/issues-rail reqs; the brief conflated them with internal HLR-035/036).
- Colour via NEW non-frozen `entropy_style.py` (band→class/glyph/meaning); color_policy.py untouched.
- Band differentiation carries a texture glyph + `band-*` class (not colour alone) — headless
  assertability (C-10).
- Entropy computed on the worker-thread load path, cached (mirror `_a2l_enriched_tags`); exact
  set-site to verify Phase 2 (R3).

## Roadmap / increment cut (≤5 files each)
1. entropy_style.py + `.band-*` + census test [3]
2. band bar + region list + compute-on-load + RED-first AC-045a [3]
3. At-a-glance panel + pilot-geometry (80×24/120×30) [3]
4. single-click nav (foldable into 2) [2]
5. retire modal (screens.py/app.py/styles.tcss/delete viewer test/snapshot) [5]
6. REQUIREMENTS.md amendments (R-TUI-060/061/062 add; 041 amend; 050/051 retire) [2]
+ post-merge canonical-CI snapshot regen follow-up PR (2 map cells drift; 2 entropy cells deleted).

## Risks / watch-items
R1 modal-removal reach (grep-gate=0); R2 map arrow-nav ATs superseded (rework not drop); R3
entropy-compute set-site (Phase 2); R4 band-run fragmentation (fast-follow only if Phase-4 clutters);
R5 delete ENTROPY_BAND_COLOUR (no orphan); R6 snapshot canonical-only; R7 entropy_service purity.

## Conventions honored
C-FRZ + C-27 dual-guard; C-COLOUR (new module); C-17 markup safety; C-22 per-cell snapshot upper
bound; C-23 pilot-measured geometry; C-26 reverse-census on touched ids; requirement amendments §6.5.

## Test ledger
Base TBD at Inc-1. New: AT-069..076 (8 black-box) + TC-045.1..6 (white-box). Deletions: entropy
viewer ATs (AT-062a/b/063a/b, TC-324..327) + `test_tui_entropy_viewer.py` + 2 `tc036s` cells.

## Out-of-scope carries
Band-run merge-tolerance (R4, fast-follow if needed); patch 3-column responsive batch (separate,
operator-approved, next); field-audit P0 bugs B1/B3, N2/N4 (separate batches).
