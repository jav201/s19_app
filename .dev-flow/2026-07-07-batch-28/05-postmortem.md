# 05 — Post-mortem · batch-28 (R-TUI-042) · view enhancements

**BLUF:** Shipped 3 prototype-approved view enhancements (A2L polish, Issues grouped-dense,
Workspace inline signal) across 4 increments, 0 engine-frozen diffs, ledger 1121→1151. The batch
ran clean through Phase 3 gates but the **Phase-3 full-suite exit gate caught two regressions the
per-increment `-k` subsets missed** — one crash, one severe perf regression — both fixed before
merge. The single most important process lesson: **run the full suite (or broadly, not a narrow
`-k` slice) at each increment gate**, and **never attribute a full-suite failure to a "known flake"
without confirming on clean `main`.**

## What worked
- **Prototype-first + supervised increments.** The scope pivot at the P1 gate (operator re-selected
  prototype directions — A2L C→A, MAC dropped, Issues C→B) cost **zero implementation rework**
  because it happened pre-code; the `iterate-to-refine` + §6.5 amendment absorbed it.
- **Phase-2 tri-agent review** folded 8 majors pre-code, incl. the DoS bound (LLR-042.6) and the
  vacuous AT-038a — before a line was written.
- **C-17 designed in, held.** The markup-safety LLR + hostile-input AT-039e shipped correct on the
  first Issues increment (the one new untrusted-render surface); security-reviewer verified the
  scrubber gap at source.
- **The main-comparison diligence.** Stashing the batch and running the suspect `tc_065` class on
  clean `main` (7 pass/34s vs 4 fail/252s) is what converted a wrong "known flake" call into a
  correct "my regression" call. This one step prevented shipping a 35s-render perf cliff.
- **Increment code-reviews caught a real HIGH** (Inc-2 duplicate visible Issues lists) that the
  author's own tests passed through.

## What didn't (and the fixes)
- **Two regressions escaped the increment gates.** Each increment ran a targeted `-k` subset
  (fast) which was GREEN, so all 4 increments gated clean — yet:
  1. `update_workspace_stats`/`update_memory_strip` crashed on the monkeypatched unit-test app
     (`#ws_stats` query → None → unguarded `.update()`), failing `test_update_sections_caps_*` —
     tests in a *different file* the `-k` subset never ran.
  2. The grouped Issues panel mounted ~600 non-virtualized widgets per render (full 200-row page),
     causing a ~35s Issues render + `WaitForScreenTimeout` failures in `tc_065` — again a
     different file, and only visible when the whole class ran together.
- **A wrong first attribution.** The 5 `tc_065` failures were initially triaged as the
  memory-documented "pre-existing full-suite global-state flake" (one test *did* pass in isolation).
  The clean-`main` run disproved it. Lesson encoded below.

## Scope drift
- **None uncontrolled.** The P1 re-selection was operator-directed (not drift). The `_GROUP_DISPLAY_MAX=40`
  cap is a within-spec tightening of LLR-042.6 (mounted ≤ cap ≤ page_size), not new scope. The
  hidden legacy Issues DataTable (Inc-2 HIGH-fix) is a deliberate, flagged compatibility carry.

## Metrics
- Iterations: P0=1, **P1=2** (prototype re-selection), P2=1 (iterate-to-refine on majors), P3=1, P4=1. No 3-cap hit.
- Requirements: 3 US · 6 HLR clauses · 12 LLR · 15 AT · 12 TC. Dual traceability complete.
- Tests: ledger **1121 → 1151** (+30). Full suite 1126 passed / 2 skipped / 23 xfailed / 0 failed.
- Reviews: 3 Phase-2 reviewers (0 blockers, 8 majors, 8 minors) + 4 increment code-reviews (1 HIGH
  found+fixed, several LOW). 0 engine-frozen diffs throughout.
- Regressions: 2 found by the exit gate, both fixed with counterfactual evidence.

## Root-cause analysis
- **Escaped regressions → gate scope.** Increment gates verified the increment's *own* `-k` tests,
  not the blast radius. Both regressions landed in *other* test files (`test_tui_app.py`) exercising
  shared code (`update_sections`, `update_validation_issues_view`) the increments modified. A narrow
  `-k` gate cannot see cross-file fallout.
- **Perf regression → widget-model swap.** Replacing a *virtualized* framework widget (DataTable)
  with a *mounted-widget container* (GroupedIssuesPanel) is O(N) real widgets; no LLR or AT bounded
  the mounted count until the Phase-2 DoS clause (which bounded *data*, not *mount cost*), and no
  test rendered a full page until the exit gate.

## Proposed controls (for operator review — NOT self-encoded, per the control-encode-approval rule)
1. **C-CANDIDATE-A (increment-gate blast-radius run):** at each Phase-3 increment gate, run the full
   suite — or at minimum every test file that imports/exercises the touched symbols — not only the
   increment's `-k` subset. Both batch-28 regressions were invisible to the `-k` gate and caught only
   at the exit. (Cheaper variant: a `-k` gate PLUS a mandatory full-suite run before the Phase-3→4 gate.)
2. **C-CANDIDATE-B (virtualized→mounted swap owes a mass-render bound + perf AT):** when an increment
   replaces a virtualized framework widget (DataTable/ListView/OptionList) with a custom
   mounted-widget container over a list of unbounded length, it MUST cap the mounted count AND ship a
   perf/settle AT at a realistic max (the batch-28 AT-039g pattern) — a data-only DoS bound does not
   cover mount cost.
3. **C-CANDIDATE-C (no "known-flake" attribution without a clean-base run):** a full-suite failure may
   only be attributed to a pre-existing flake after reproducing it on the clean base ref (stash/detached
   checkout); an in-isolation pass is insufficient (batch-28's `tc_065` passed in isolation yet was a
   real regression). This is the diligence that saved the merge.

## Items proposed for the next batch / backlog
- **Retire the hidden legacy Issues DataTable** (full grouped-panel-only Issues screen; update the 2
  external tests that read it via `get_row_at`).
- **Narrow the `update_memory_strip` bare `except`** to `NoMatches` (Inc-4 LOW, deferred).
- **Canonical-CI snapshot regen** for the 20 batch-28 restyled + entropy-backdrop cells → retire xfails.
- **Bookmarks dead screen** (standing backlog).
