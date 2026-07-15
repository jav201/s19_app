# Post-mortem — batch-46 · Patch Editor responsive 3-window layout (B2 + U8)

> Orchestrator-synthesized from the full batch record (PLAN.md · 01/01b/02/03/04 artifacts ·
> state.json decisions_log), applying the architect + qa lenses. **Outcome: SHIPPED-CLEAN, APPROVE
> to close.** 0 HIGH findings batch-wide; 0 scope drift; every gate green; app.py diff = 0.

## BLUF
The 2×2 Patch Editor grid became three responsive windows (PATCH SCRIPT / CHECKS / JSON EDIT) with
docked buttons — a **pure-CSS** change (app.py diff = 0) reusing the existing `width-narrow` regime.
Two things went right that usually go wrong: (1) **measuring geometry before coding** caught a
*physically impossible* acceptance criterion at Phase 3 instead of after merge, and (2) the
**preserve-pane-ids fold** turned a would-be >5-file structural churn into a 5-file atomic increment
that left two test files untouched. Two root causes are worth encoding as control refinements
(below), both stack-specific → propose for `docs/engineering-rules.md`.

## What worked
- **Pilot-measure-before-code (C-16/C-23) earned its keep.** The dev measured the real panel budget
  *before* writing the layout and found 5 content rows @80×24 — proving the spec's "all 17 buttons
  visible at the floor" (AT-064a) physically impossible. Caught at Phase 3, not post-merge. This is the
  single highest-value moment of the batch.
- **Preserve-don't-retire fold (FOLD-1, arch-M2).** Recasting the four `#patch_pane_*` containers as
  non-scrolling sub-containers (instead of retiring them) kept `test_tui_patch_variant.py` +
  `test_tui_directionb.py` green *untouched*, collapsed the atomic green unit to 5 files, and dodged a
  >5-file exception. A reverse-census finding turned into a design simplification.
- **CSS-only responsive reuse.** `#patch_editor_panel` being a `#workspace_body` descendant meant the
  3-col↔stacked switch was pure CSS on the existing 120-col regime — zero new Python, no `TabbedContent`
  widget-swap, no recompose fragility. app.py diff = 0 held end-to-end.
- **The reachable-under-scroll oracle is honest and discriminating.** Independent code-review verified
  it drives real `scroll_y` (the mouse-wheel mechanism, not a `.focus()` bypass), re-checks the actual
  region against every scrollable ancestor, and has a structural "no VerticalScroll ancestor" docked-
  sibling check — so it goes RED if a button is re-trapped below an inner fold. RED-proven on the 2×2 tree.
- **Phase-2 triple review paid for itself** — 7 MAJOR folds, all pre-implementation, including the
  min-usable-size floor (M-Q1: without it a 3-col-wide window starved to 3 cols would pass) and the
  AT-064c gate for revealed rows (M-Q4).

## What didn't (root causes)
- **RC-1 — the AT-064 acceptance was physically impossible (FOLD-8 iterate-to-refine).** Phase-1
  measured the **width** budget (70 cols @80×24) but **assumed height**, inheriting the prototype's
  full-screen ~22-row budget (the prototype ran the patch editor as the *whole* screen). The real
  panel gets ~5 rows; 17 three-row buttons can't coexist there. Black-box-fails / white-box-would-pass
  ⇒ requirement-wrong ⇒ iterate-to-refine. Resolved by operator-approved Option A (reachable-under-
  scroll floor, all-visible @120×30). **Non-defect** (measurement caught it), but a Phase-1 both-axes
  measurement would have caught it a phase earlier and avoided a mid-Phase-3 stop. → **CONTROL CAND A.**
- **RC-2 — the C-26 reverse-census under-counted by one file (`test_tui_variants.py`).** The reverse-
  grep keyed on the *structural container ids* being retired (`patch_pane_*`, `patch_doc_file_row`). But
  `test_tui_variants.py` broke for a different reason: it `pilot.click`s `#patch_variant_info_button` —
  a **leaf id whose screen POSITION moved** (into a docked-below-fold spot) → `OutOfBounds`. The census
  found the tests that *assert a container's structure* but missed the tests that *interact with a moved
  widget by position*. Caught at the Phase-3 broad-suite run (a 6th file); fixed with the same scroll-
  before-click pattern. → **CONTROL CAND B.**
- **RC-3 — concurrent-session branch contention (operational, not a batch defect).** A different
  active session (`claude/app-screens-audit-c58d94`) switched HEAD off `feat/batch-46-patch-3col`
  mid-Inc-1 in the shared main-repo working dir. Changes were uncommitted (floated with the working
  tree, nothing lost); switched back cleanly (both branches at the same base). Mitigated by committing
  Inc-1 promptly to pin the work. Lesson: in a contended working dir, commit increments promptly rather
  than holding a long uncommitted working tree.

## Metrics
- **Iterations/phase:** 0:1 · 1:1 · 2:1 (fold) · 3:2 (Inc-1 + the FOLD-8 refine) · 4:1 · 5:1 · 6:pending.
- **Gate:** 1394 passed / 0 failed / 5 xfailed (2 batch-46 patch drift + 3 pre-existing) / 2 skipped;
  C-27 0 frozen diffs; ruff clean; app.py diff = 0.
- **Requirements:** +2 rows (R-TUI-063/064); §6.5 supersede ×2, amend ×1, note ×1; +8 spec folds.
- **Tests:** 6 ATs (063a/b/c · 064a/b/c) + TC-46.1/46.2 + FOLD-6 census; 2 patch snapshot cells xfail
  (canonical-CI regen post-merge). 0 story-kill, 0 scope drift, 0 HIGH.
- **Files:** Inc-1 = 6 (source ×2 + tests ×4, census-miss +1); Inc-2 = 1 (REQUIREMENTS.md). net +964/−782.

## Control candidates — operator decision (AskUserQuestion, 2026-07-15)
Both stack-specific → `docs/engineering-rules.md` (classify-before-encode placement policy).
**Operator APPROVED CAND-A → encoded as `C-29` in `docs/engineering-rules.md`. CAND-B DECLINED**
(left proposed-only below; revisit only if the moved-widget-interaction census-miss recurs).
- **CAND-A — two-axis geometry-budget measurement (refines C-23). → ENCODED C-29.** When a spec sets an acceptance
  threshold that depends on how much fits in a container (button/row count visible, "all X visible"),
  Phase 1 MUST pilot-measure BOTH axes of the container's real budget (width cols AND height rows)
  against the actual app chrome — never measure one axis and assume the other, and never inherit a
  full-screen prototype's budget for a boxed panel (C-16). Origin: batch-46 RC-1 (measured width,
  assumed height → AT-064 physically impossible, caught only at Phase-3).
- **CAND-B — reverse-census covers interaction-tests of MOVED widgets (refines C-26). → DECLINED (proposed-only).** When an
  increment changes a widget's screen POSITION or reachability (docks it, reparents it below a fold,
  moves it across a regime), the reverse-census must reverse-grep not only tests that ASSERT the
  widget's container structure, but every test that DRIVES the widget by id (`pilot.click`/`press`/
  `scroll` on `#that_id`) — a position-dependent interaction breaks even when the id survives. Origin:
  batch-46 RC-2 (`test_tui_variants.py` clicks the moved `#patch_variant_info_button`; the pane-id-keyed
  census missed it → surfaced as a 6th file at the broad-suite run).

## Carries to next batch
- **Snapshot regen (post-merge):** the 2 `patch-comfortable-{80x24,120x30}` cells ride
  `_batch46_patch_drift_marks` (xfail); regenerate in canonical CI (`snapshot-regen.yml`, local regen
  forbidden), retire the marks + helper — a follow-up snapshot-baselines PR (the #82 lane).
- **Deferred app-start-geometry (now better motivated).** RC-1 is a symptom of the operator-deferred
  app start width/height + font scale: at 80×24 the whole app is chrome-starved (~5 content rows). The
  FOLD-8 reachable-under-scroll floor is the honest fix *given* that constraint; raising the panel's
  vertical budget (the deferred work) would let more buttons show at once.
- **F4 (informational):** `test_variant_help_modal_fits_at_both_sizes` opens the modal via message at
  the floor (real click retained @120×30 by AT-067a) — legitimate scope call, no action.

## Verdict
Coverage / Certainty / Evidence all MET (Phase-4). 0 HIGH, 0 blocker, 0 scope drift, 0 story-kill.
**APPROVE — close batch.** Phase 6 (docs + PR) next; then the final independent PR-QA pass gates the
self-merge.
