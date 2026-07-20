# 05 — Post-mortem · batch-54 (Multi-line A2L header parsing)

**BLUF:** A clean, zero-blocker batch — the core-parser change that batch-50 identified as P-1b's prerequisite landed with 1652 passed / 0 failed / 0 snapshot drift and an independent code-review APPROVE, no iterations. The reason it went smoothly is directly attributable to **C-35** (the control batch-50 produced): every agent *executed* the parser over the real ASAM demo at draft time, so the requirements were pinned to measured values (0-genuine→50/50, exact oracles) before a line was written. The design was de-risked at Phase 1, confirmed at Phase 2, and implemented once.

*(Orchestrator-authored — a 4-file core-parser batch with full agent coverage; co-author dispatch would re-derive known context.)*

## What worked
- **C-35 paid off end-to-end.** Phase-1 (both agents), Phase-2 (all three reviewers), and Phase-3 all ran probes against the real fixture. This surfaced the *spurious* "1/50" (a `ASCII /* … */` comment-token artifact — genuine parses were 0), pinned every oracle, and let the architect **disprove both candidate-blockers by execution** rather than argue them. The batch this line of work exists to enable was itself executed-verified throughout.
- **0 iterations.** Phase-2's 6 MAJOR + 9 minor findings were all AT/LLR *folds* (wording/oracle tightenings), applied inline before the gate — no back-to-Phase-1. The design never changed.
- **Unfreeze/edit worked in one PR.** Unfreezing a2l.py (removing it from `_ENGINE_PATHS`) *lifts* the guard, so the same PR can edit a2l.py freely — the inverse asymmetry of batch-50's re-freeze (which *adds* to the set → self-trips → must be post-merge). See lesson below.
- **0 snapshot drift, verified not assumed.** Phase-1 R3's claim (synthetic `make_large_a2l` blocks carry no kind token → stay `char_type=None`) held: 29 snapshots passed. The C-26 census correctly identified that the only demo-parsing sentinel (`test_at094`) needed a docstring reconcile, not a value change.
- **Security-critical stripper hardened by design.** Linear O(n) quote-state machine, fail-closed, `//`→newline-only; 8 hostile cases + a positive control + a `@slow` 2 MB DoS test lock the contract.

## What didn't / friction
- **The architect run was long** (~12 min) because it wrote/ran three probes — the right tradeoff (it disproved two blockers), but worth noting the C-35 discipline has a wall-clock cost at Phase 1.
- **Cosmetic count drift** in increment-002 ("31 tests" vs 30 on disk) — caught by the Phase-4 `--collect-only` reconciliation, corrected. Minor.
- **A multi-line surface-limit AT gap** — `lower_limit`/`upper_limit` for multi-line headers are white-box-pinned (TC-099) + reached transitively (AT-096 proves window alignment via deposit/address), but no *direct* black-box multi-line-limit assertion. Documented as non-blocking; batch-55 could add one.

## Scope drift
None. Scope held exactly (HEADER-only; length stays None; MEASUREMENT multi-line deferred — confirmed sound by all three reviewers, not a silent cut).

## Metrics
- Iterations/phase: **0 / 0 / 0 / 0 / 0** (no iterate; Phase-2 folds applied inline).
- Increments: 2 (Inc-1 unfreeze, Inc-2 parser). Files: 6 total (a2l.py, a2l_parse.py, 2 guard files, 1 new test, 1 census test).
- Tests: +29 net (30 new nodes − 1 `@slow` deselected; census in-place). Gate 1652 passed / 0 failed; 29 snapshots 0 drift.
- Findings: Phase-2 6 MAJOR + 9 minor/LOW, **0 blocker**, all folded. Inc-2 code-review 0 HIGH/MEDIUM (2 LOW, intentional). Security: 0 HIGH/MEDIUM.
- Engine-frozen diffs: 0 (a2l.py sanctioned-unfrozen; re-freeze = PR-B).

## Root cause of the smooth run
Not luck — the C-35 control (draft-time EXECUTION over the real input) forced every phase to work from measured reality. The batch is essentially C-35 validating itself: the exact discipline whose absence caused batch-50's P-1b to be specced against a non-existent parser capability is what made batch-54 airtight.

## Candidate control (assessed — NOT proposing a new one)
The **unfreeze/re-freeze PR asymmetry** is a genuine, if minor, nuance: *unfreezing* (remove from `_ENGINE_PATHS`) can share the same PR as the sanctioned edits (the guard stops checking the file), whereas *re-freezing* (add back) must be a separate post-merge PR (else `git diff main -- <file>` is non-empty and self-trips). This is a corollary of the existing C-27 dual-guard mechanics + the batch-50 P-2 lineage, already documented in both batch records. **Recommendation: capture as a one-line note in the batch-54 record + the P-1b lineage, do NOT mint a new control** (it's an instance of understood C-27 behavior, not a new general principle — per the "general controls, not narrow patches" rule).

## Items for the next batch
1. **a2l.py re-freeze** — post-merge follow-up PR-B (add a2l.py back to both `_ENGINE_PATHS`, guard-files-only, off merged main).
2. **batch-55 (P-1b proper)** — the inline-axis length summer, now UNBLOCKED: it consumes the `axis_meta.max_axis_points` (str — cast it) + `axis_meta.external` fields this batch populates. Full seed in the batch-50 `01-requirements.md §7` + this batch's axis contract.
3. Optional: a direct multi-line surface-limit AT (the documented Phase-4 flag).
4. Carries: batch-51 FB `/dev-flow-sync` (its step).
