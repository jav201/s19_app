# 05 — Post-mortem — batch-20 (D-1 + D-2 declared-region cleanup)

> Co-authored: architect (design/process lens) + qa-reviewer (metrics/validation lens). **Outcome: PASS, clean run — phases 0-4 each single-iteration, 0 blockers at every gate.**

## Metrics

| Dimension | Value |
|---|---|
| Iterations per phase (0–4) | **1 each** — 0 re-loops, 0 blockers |
| US / HLR / LLR | 2 / 3 (027 save, 028 load, 029 D-2) / 10 |
| AT / TC | 9 AT · 7 new TC + 1 rewritten-in-place (TC-024.5, net 0) |
| Phase-2 findings | 6 (0 blocker / 0 major / 4 minor / 2 LOW-sec) → **6/6 closed body-first** |
| Increment code-review | 4 LOW raised → 0 actioned / 4 noted-or-deferred; **0 HIGH/MED** across A/B/C |
| Counterfactual REDs | 3 (≥1 per increment), all value-discriminating |
| Test ledger (collected, non-slow) | 958 → **974 (+16)**: Inc A +6, Inc B +4, Inc C +6 |
| Final non-slow run | 942 passed / 29 skipped / 3 xfailed / **0 failed** |
| Files touched | **3** — `app.py`, `screens.py`, `tests/test_tui_report_seam.py` |
| Frozen-engine diff | **0 throughout** · ruff clean · no SVG regen |

## What worked
- **Phase-0 capture-point decision (Option A, on Generate) — highest-leverage call of the batch.** Resolved the one real ambiguity (when does a typed region "count"?) with the cheapest mechanism: a single new `self._declared_regions` attribute written only on `GenerateRequested`. One source of truth, no observer plumbing. The accepted edge (type-without-generate not saved) was promoted to a boundary AT (AT-027b) rather than silently absorbed — documents the decision so a future reader doesn't "fix" it back into a bug.
- **D-1 split into two HLRs (save=027 / load=028) — correct V-model hygiene.** The A→B dependency was real (load consumes the attribute save produces); one fused trace would let a half-done round-trip hide behind a single green check.
- **C-12 gate/guard pair (AT-028a gate over the handler-produced project.json + AT-028b direct-write guard) held on the output-then-consume pattern** — the exact discipline seeded by the batch-16 G-3 near-miss, applied correctly here. The load AT is anchored on what save actually wrote, not a same-values direct write.
- **C-13 correctly returned N/A with stated arithmetic** (no new always-on widget — D-1 seeds an existing TextArea, D-2 reuses the existing notify). A geometry check that can say "N/A, footprint delta = 0" is doing its job — contrast batch-17/18 where it fired.
- **D-1 was pure wiring because the hard part was pre-paid:** batch-19 shipped the serialization layer as a deliberate "serialization-only, UI deferred" slice. The incremental-slice strategy paid compound interest — deferring the UI wire was the right reversible call, not debt.
- **Two Phase-2 test-quality folds prevented vacuous ATs:** the `\b1\b` standalone-token assertion (kills the "100"/"0 of 1" false-green class) and the literal-not-reconstruction fix on AT-028a (kills the tautology where a test can't fail when the logic changes — Engineering Rule 9). Both caught at cross-review, both corroborated by the counterfactual REDs.

## What didn't / friction
- **qa-reviewer agent stalled on its Phase-4 summary** (blocked behind a ~7-min pytest); orchestrator ran validation directly + reconciled the V-5 ids. No correctness impact, but a process smell: an agent owning a gate it can be starved out of. **Lesson:** checkpoint-before-long-run — emit the validation plan / expected ids first, then run; or let the orchestrator own the long test invocation and hand results to qa for interpretation.
- **Worktree-not-editor-root friction recurred (batches 19→20, now 2-for-2).** The flow runs from an auto-cut worktree the operator's editor isn't rooted in, so every gate needs reviewable artifacts pasted inline. Mitigated twice by the same manual workaround → a standing tax, not a one-off. **Operator decision proposed (see below).**
- **Ledger-unit confusion (collected 958→974 vs passed 932→942)** — surfaced and reconciled, not averaged. **Lesson:** label the unit (collected vs passed) on every ledger figure.
- **Comma-in-region-name edge** surfaced but scoped out — correct: the scrub already guarantees no newline can be smuggled (security GRANT, both ends), so comma-escaping is a parsing-nicety, not a safety gap. Flag-don't-fix; logged for D-2 follow-on.

## Scope drift
**None.** 3 increments mapped 1:1 to the 3 HLRs, each ≤5 files, 0 engine-frozen edits. The D-2 return-type ripple to 8 call sites is fan-out of one intended change (fail-loud TC-024.5 rewrite was its designed signal), not creep.

## Root-cause analysis
**N/A — 0 iterations, 0 blockers.** Why it ran clean (reproduce deliberately, don't bank on luck): (1) small + well-scoped (3 HLRs, ≤5 files, frozen diff 0); (2) the riskiest surface (disk format) was settled in batch-19 before this batch opened; (3) surfaces disk-mapped at Phase 0; (4) **the one real ambiguity (capture point) was killed before Phase 1, not deferred into implementation** — which is precisely why phases 0-4 each ran single-iteration. Takeaway: clean batches correlate with *killing design ambiguity before Phase 1 and pre-shipping the risky substrate*.

## Items proposed for next batch
- **D-1 fully closed** (round-trip save+load shipped + traced both ends) → drop from BACKLOG.
- **Recommended next sequence:** (1) **#8 patch-editor overhaul (P1)** — highest-priority open feature; recommend a Phase-0 scope-split spike before committing increments (editing surface = more state/failure modes than seeding a TextArea). (2) **#12 (P2)** after. (3) **D-2 follow-ons (low):** line-level error detail in the skip notify + comma-escaping — UX polish, no safety gap; fold opportunistically only if a future batch already touches that surface.
- **Process carries (cheap, prevent recurrence):** "checkpoint-before-long-run" for the qa agent; "label ledger units".
- **Worktree-not-editor-root friction — RESOLVED (operator decision, Phase-5 gate):** **formalize "paste reviewable artifacts inline at every gate" as a documented dev-flow convention** (not a per-batch improvisation). To be encoded in `~/.claude/commands/dev-flow.md` Communication-style section, with explicit operator approval at edit time per the control-encode-approval rule (the `ask` rule on `Edit(~/.claude/commands/**)` prompts). Stops the per-batch re-decision.
