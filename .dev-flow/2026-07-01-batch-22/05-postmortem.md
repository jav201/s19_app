# 05 — Post-mortem — batch-22 (#8 US-030 4-pane split + US-031 snapshots)

> Co-authored: architect (design/process lens) + qa-reviewer (metrics/validation lens). **Outcome: PASS, clean run — phases 0-4 each single-iteration, 0 blockers, 0 HIGH/MED findings, frozen-diff 0. A textbook C-13 measure-before-code win.**

## Metrics
| Dimension | Value |
|---|---|
| Iterations / phase (0–4) | 1 each · 0 re-loops |
| Blockers at gates | 0 (every gate) |
| Phase-2 cross-review | 0 blocker / **1 major** (R1 `Horizontal`-no-wrap false premise → explicit button-grid) / 5 minor / 0 security (inline-N/A, pure layout) — all folded |
| Increment code-reviews | Inc1 APPROVE-WITH-NITS (F1 docstring/CSS overclaim) · Inc2 APPROVE-WITH-NITS (F1b two stale "27" labels). **0 HIGH/MED**; both nits folded live |
| Increment findings | 2 LOW folded-live · 1 LOW→BACKLOG (F2 save-back-shown span) · 1 pre-existing F401 (left) |
| AT / TC | AT-033a/b (geometry) · AT-033c×2 (reparent-safety) · TC-033 (grid/overflow) · +1 snapshot cell (patch 80×24) |
| Ledger (collected non-slow) | 985 (batch-21 close @13c06c4) → **991 (+6)** |
| Final non-slow run | **958 passed / 30 skipped / 3 xfailed / 0 failed** |
| Stories / reqs | 2 US (030/031) · 2 HLR · 8 LLR; US-028 deferred |
| Frozen diff | **0** · ruff 1 pre-existing F401 left |

## What worked
- **Measurement spike de-risked the deferred story (headline / C-13).** Phase-0 drove the real app under Pilot and measured the patch host at **70 @80 / 92 @120** — killing batch-21's ~37/~58 estimate (which wrongly assumed the patch editor shared the workspace body). The feared 4-across-underflow-at-80 collapsed into a comfortable 2×2 (~35/~46 per pane). Measure-before-code turned an unknown into a bounded refactor — exactly why US-030 was deferred to its own measured batch.
- **The batch-21 deferral decision paid off** — deferring the geometry-heavy story *specifically so it got a spike* was vindicated.
- **R1 false-premise catch at cross-review.** The architect lens caught the Phase-1 claim that Textual `Horizontal` *wraps* the 5-button row (it clips) — corrected to an explicit `#patch_doc_controls { grid-size: 3 }` button-grid before a line of code. Independent cross-review earned its keep.
- **Reparent census proved completeness cheaply** — id-set diff confirmed all 39 `patch_*` ids preserved, only one structural query (`#patch_checks_results > Static`) and it survives. Demonstrated, not asserted. No re-loop.
- **Two Phase-2 test-quality folds:** the 2×2 proof tightened to "each row/col band exactly 2 panes" (rejects an L-shape that 2-distinct-x/y alone would pass) and the divisor fixed to `content_region.width` (else the geometry math is off by the border/scrollbar).
- **US-031 snapshot honesty (the key QA event):** the SVG baseline regens in CI only; rather than fake a local pass, the cells are `xfail`-until-CI and the 2×2 is behaviorally validated by US-030's geometry AT (green locally). No unrunnable node stands in as the gate.

## What didn't / friction
- **A framework-behavior assumption reached Phase-1.** The `Horizontal`-wraps premise is a draft-time-verification miss (assuming library behavior). Caught at Phase-2 → no downstream cost, but it should have been confirmed at draft time.
- **Overclaiming docstrings/comments — a 2-instance pattern.** Inc1 (a CSS comment + AT-033a docstring claimed the pane-level check proves the button-grid no-clip — it proves pane-in-host; the TC proves the grid) and Inc2 (two stale "27-baseline" labels). Both self-folded on honesty. Two instances of "the assertion claims more than the test proves" in one batch = a signature worth naming.
- **Concurrent hooks task on main mid-batch.** origin/main advanced 74f19ac→13c06c4 (PR #33, the batch-21-spawned artifact-completeness hook) during Phase 2 — benign (zero target overlap, branch ff'd cleanly, the new hook now validates batch-22's close artifacts). Reminder: spawned tasks can land mid-flight and need a glance.
- **Agent-stall avoidance:** Inc2 + Phase-4 executed directly by the orchestrator (batch-20/21 checkpoint-before-long-run carry); independent lens preserved via 2× code-reviewer + Phase-2 architect/qa.

## Scope drift
**None.** 2 increments = the 2 stories; US-028 stayed deferred; no adjacent-code "improvements."

## Root cause (0 iterations)
Measurement killed the dominant unknown (geometry) at Phase 0; cross-review caught the framework error before code (R1 was a Phase-2 spec fold, not a gate rejection — the spec changed before implementation, so the increment gates never saw a defect); snapshot honesty avoided a false-green trap to unwind later.

## Items for next batch
- **US-028 (variant dropdown)** — next for #8. **#12** — after #8 closes.
- **CI baseline regen (post-merge, GATED):** regen the patch 80×24 + 120×30 SVG baselines in canonical CI, then drop the `xfail` — do NOT drop before CI green.
- **F2 (LOW → BACKLOG):** save-back-shown span test. **Pre-existing F401** (`Optional`): batch with the standing ruff carry.

## Candidate controls — OPERATOR APPROVAL REQUIRED (NOT self-encoded)
Both co-authors' honest lean is **against over-encoding** — the controls held; these are watch-items, not urgent gaps:
1. **Framework/library-behavior draft-time verification** (trigger: the `Horizontal`-wrap assumption). Lean: this is the EXISTING draft-time-verification rule *working* (cross-review caught it as designed) → **no new control**; at most a one-line clarification that "framework/library behavior asserted in a spec must be confirmed (doc/measurement), not assumed."
2. **"Assertion ≤ evidence" overclaim check** (trigger: 2 overclaiming docstrings/comments this batch). Lean: the more genuinely novel signal, but only 2 instances — a *lightweight* cross-review prompt line ("does each AT/TC docstring claim exactly what its assertions verify, no more?"), or **watch for a 3rd instance before encoding**.
- **Recommendation:** do NOT encode a new control this batch; optionally sharpen the draft-time-verification wording (#1); WATCH the overclaim pattern (#2) and revisit if it recurs. Operator's call per the control-encode-approval rule.
