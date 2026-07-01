# 05 — Post-mortem — batch-21 (#8 patch-editor overhaul, SLICE 1)

> Co-authored: architect (design/process lens) + qa-reviewer (metrics/validation lens). **Outcome: PASS, clean run — phases 0-4 each single-iteration, 0 blockers, 0 HIGH/MED findings, frozen-diff 0. One real process gap (census scope) + two agent stalls, both absorbed without a re-loop.**

## Metrics
| Metric | Value |
|---|---|
| Iterations / phase (0-4) | 1 · 1 · 1 · 1 · 1 (zero re-loops) |
| Blockers at gates | 0 (every gate) |
| Phase-2 cross-review | architect PROCEED (2 major / 3 minor) · qa PROCEED (3 major / minors) · security GRANTED-after-fold (1 LOW) — all folded body-first |
| Increment code-reviews | Inc1 APPROVE (1 LOW N1) · Inc2 APPROVE-WITH-NITS (1 LOW F1 → folded live) · Inc3 APPROVE (0). **0 HIGH/MED across all 3.** |
| AT / TC | 7 AT (incl. F1 adversarial, AT-030c guard, AT-030a-R2) + TC-030 / TC-031 |
| Counterfactual REDs | 3 (one per increment) — all captured |
| Ledger (collected non-slow) | 974 (ec3a2a7) → **985 (+11)**: Inc1 +3, Inc2 +6, Inc3 +2 |
| Final non-slow run | **953 passed / 29 skipped / 3 xfailed / 0 failed** |
| Files touched | Inc1: workspace.py + io.py; Inc2: screens_directionb.py + app.py; Inc3: screens_directionb.py + styles.tcss (+ tests) |
| Frozen diff | **0 throughout** · ruff clean · no SVG regen |
| V-5 reconciliation | 11 AT/TC ids → real on-disk nodes, all PASS |

## What worked
- **Scope-first decomposition of #8 did its job.** The largest/highest-blast-radius backlog item shipped as a low-risk 3-story slice (US-026/027/029); the geometry-heavy 4-pane split (US-030) was isolated as its own C-13/C-13.1 SPIKE and **deferred to a measured batch** — the single real geometry risk never entered batch-21. This is the intended use of the mandatory decompose-before-code gate.
- **Adopting the concurrent Phase-0 correctly.** The scaffold + #8 decomposition were already at the DoR gate from an earlier run on the shared worktree; the orchestrator honored the awaiting-gate "don't regenerate" rule, spike-verified the adopted work vs `ec3a2a7`, and surfaced the adoption transparently before presenting. Regenerating would have burned tokens and risked drift.
- **temp→root correction caught at cross-review** — the Phase-0 spike wrongly said saves land in `temp/`; they land in the workarea ROOT (temp is staging-only). Caught at the design gate, not runtime. Same one-liner, but it flipped the R1 answer and forced a net-new placement TC. Cross-review earned its place.
- **Fail-loud held at Inc1** — when the census-missed e2e tests broke, `software-dev` fixed them (glob→rglob, intent preserved) and *reported* rather than silently patching (Rule 12).
- **C-13 PASS by structure** — the patch panel is a vertical `overflow-y:auto` container; the added Select + description Label are vertical rows, no horizontal budget hit — reasoned, not hand-waved; the one case needing measurement (4-pane) was deferred.
- **Two Phase-2 AT-authoring folds killed latent bad tests before merge (highest-value QA event):** deterministic sort + select-by-name (glob order is FS-dependent → prevented a **flaky gate**) and producer = `save_doc` not the save-back image writer (→ prevented a **vacuous gate** observing the wrong surface). Both convert the AT into intent-encoding tests (Rule 9). F1 security test is portable (the `is_relative_to` guard fires unconditionally via `../outside.json`; symlink branch `if`-guarded — no Windows no-op).

## What didn't / friction
- **HEADLINE — supersession-census SCOPE gap.** The Phase-2 census swept the white-box placement tests (`test_unified_write.py::tc018`, generic `workarea/` containment — survive the move) but **missed 2 e2e save-observing tests** that pinned the OLD root location via a non-recursive glob. The census reasoned about *where the code writes* and never asked *who observes the written file on disk*. For a story whose whole change is an on-disk LOCATION move, those observers are precisely the blind spot. (Broke at Inc1; dev caught + fixed; net-0 rewrite.)
- **Agent stalls (2).** Inc2 `software-dev` completed the work (94 tool calls) but stalled with a no-op "wait for monitor" and delivered no review packet; the Phase-4 qa-agent pattern stalls behind the ~7-min suite. Orchestrator reconstructed verification directly + had `code-reviewer` capture the missing counterfactual RED, and ran Phase-4 directly. **Independent lens preserved** (3× code-reviewer + Phase-2 qa, not implementer self-cert). Reinforces batch-20's "checkpoint-before-long-run".
- **Spike imprecision propagated** — the temp→root error originated in the *adopted* Phase-0 spike and rode into Phase 1 before cross-review caught it. Low cost this time, but an adopted spike's factual error is one review-gate from code — a small precision tax on the adoption convenience.
- **Hollow "iterate?" menu (operator callout).** The orchestrator repeatedly closed gates with an empty "approve, or iterate?" — a violation of the encoded rule (offering iterate without a named gap is a process violation). Corrected mid-batch to resolved-axis-assessment-then-call; saved to memory ([[feedback_no_hollow_iterate_at_gates]]) + a hooks task spawned. **Enforcement limit:** the iterate-prose rule is message prose, not a tool event → NOT hook-enforceable; only the checklist reject-check half can become a pre-commit hook.

## Scope drift
**None.** 3 increments = the 3 chosen stories; deferred set (US-028/030/031) explicit at Phase 0 and stayed deferred. Ledger +11 consistent with 3 small stories + the net-new placement TC.

## Root cause (why 0 iterations)
- Scoped to the low-risk slice by construction — the geometry SPIKE (the only C-13 exposure) was factored out at Phase 0, and cross-review caught the one factual defect (temp→root) at the design gate.
- **The census-miss didn't force a re-loop** because it surfaced as a *test-breakage inside Inc1*, not a gate rejection: fail-loud + honest dev report meant the fix landed within the increment and `code-reviewer` still returned APPROVE. Catch-and-fix inside an increment is cheaper than a re-loop — provided the break is loud.

## Items proposed for next batch
- **Deferred queue (from the #8 decomposition):** **US-030 4-pane split** → its own geometry batch *next* for #8 (the C-13/C-13.1 SPIKE — host-width measurement + deficit-matched fallback ladder before any code); **US-028 variant dropdown** + **US-031 snapshots** after.
- **N1 (LOW):** pre-existing `write_change_document` "later increment" docstring — fold on next touch.

## Control refinement — C-14 ENCODED (operator-approved at Phase-5 gate)
> **C-14 — Location-move census sweep:** when a story changes a file's **on-disk location** (not just its contents), the Phase-2 supersession census MUST additionally sweep e2e / save-observing tests — any test that reads the artifact back from disk (grep save-path `glob`/`rglob` over the workarea) — not only the white-box placement tests, and count rewritten-in-place (net-0) tests as touched nodes. Trigger: a diff that moves *where* a file is written.
- **Rationale:** batch-21's one real defect was exactly a location-move whose observers were e2e globs invisible to a white-box-keyed census; near-zero cost (a grep at census time). Both architect + qa endorsed.
- **Status: ENCODED 2026-06-30** in `~/.claude/commands/dev-flow.md` (Phase-2 census guidance, C-14 bullet), operator-approved at the Phase-5 gate + permission-gated per the control-encode-approval rule. First use: the next batch that moves a file's on-disk location.
