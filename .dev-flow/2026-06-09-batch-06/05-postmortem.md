# Post-mortem — s19_app — Batch 2026-06-09-batch-06

**Date:** 2026-06-10 · **Co-authors:** architect (§1–§5, §7–§8) + qa-reviewer (§6) · **Batch scope:** US-001 (MAC View ↔ A2L Explorer layout parity, proportional `4fr:3fr` + `min-width: 82` floor, TUI/CSS-only)

**One-line takeaway:** batch-05 taught us that *named symbols* must be grep-verified; batch-06 taught us that *measured constants* must be regime-verified — existence checks and validity checks are different controls, and the template needs both.

---

## 1. What worked

1. **The batch-05 preventive control (LLR symbol-citation rule) demonstrably paid off.** Adopted into the template before this batch; effect per `02-review.md`: all `styles.tcss`/`app.py` `file:line` anchors byte-accurate, symbol-citation clean, §6.4 carries 20 grep-verified anchors. Contrast with batch-05 (three plausible-but-wrong symbol names survived to Phase 3+). This batch: **0 symbol defects at any phase**; increment-001 records **0 spec deviations**.
2. **Independent dual-review redundancy caught the blocker the citation rule could not.** B-1 (`body_w = term − 24` at ≥120 cols) was found **independently by both** architect (F-A-01) and qa-reviewer (F-Q-01) in the parallel Phase-2 fan-out — two uncorrelated passes converging on the same measured fact eliminated any debate at the gate.
3. **Empirical verification *inside* the review, before any code.** The design's load-bearing mechanism — Textual clamping an `fr` pane up to `min-width` — was flagged `assumed` at draft and **empirically reproduced by both Phase-2 reviewers** (a `3fr` pane sharing 41 cells widened to 82 at 120 cols). The riskiest assumption was retired one phase early; had the clamp not worked, the whole design would have needed rework discovered in review, not mid-increment.
4. **Operator gate decisions resolved design ambiguity at the cheapest points.** (a) Phase 1: both agents flagged that strict A2L parity would *regress* the operator's complaint (hex ~41 at 120 cols); operator chose proportional+floor before LLRs were drafted. (b) Phase-2 gate: M-1 surfaced the floor's real consequence (hex pinned at 82 for 120–215 cols); operator explicitly confirmed the tradeoff (`§2.5 [decided — Phase-2 gate]`). Design intent is documented as a decision, not discoverable as a surprise.
5. **Single-increment Phase 3 with zero deviations.** All 6 LLRs in one increment, 3 files (under budget), CSS byte-exact per §6.2, A2L byte-identical, `app.py`/engine 0 lines. The iteration-2 requirements were precise enough that implementation became transcription.
6. **Test intent preserved, not erased** (CLAUDE.md rule 9): `:1399` re-purposed (`floor_below_minimum`, now documents graceful clipping) rather than deleted; `:139`'s intent migrated into TC-005; `:1355` re-banded with docstring updated.

## 2. What didn't

1. **B-1 root-cause chain:** a batch-05 narrow-regime observation in a test comment ("~113 at 119", measured with the activity rail collapsed) → generalized into a universal constant `body_w = term − 6` without re-measuring in the ≥120 regime (where the rail consumes 18 more columns) → every derived number asserted as fact and propagated through 5+ sections (§1.3, §2.5, HLR-001, LLR-001.3, LLR-001.5, §6.3). **The symbol-citation rule did not and could not prevent this:** it checks existence (`does this symbol exist at this line`), not validity conditions (`does this number hold under these conditions`). The measurement *had* a citation — its **validity regime was unstated**.
2. **B-2: the superseded-test inventory was built from the spec's assumptions, not measured test behavior.** Result: one missed failure (`test_tc021_mac_two_panes_proportional_regime:1399`, still asserting the 35% regime) and one false must-fix (`test_mac_hex_pane_width_at_wide_terminal:82`, whose `≥82` assertion is floor-compatible and survives). An inventory is a *measurement* task, not an inference task.
3. **Downstream corruption:** M-2 and M-3 were consequences of B-1, not independent defects — one bad environmental constant produced 1 blocker + 2 majors. Derived numbers inherit the validity of the measurement they came from.
4. **Friction (minor):** duplicated suite execution in Phase 4 (qa-reviewer + orchestrator each ran the suites; ~12 min duplicate wall-clock). Defensible at 3 files — the independent re-run is what made the PASS trustworthy — but it scales linearly; batch-07 should assign run-ownership explicitly (A-6). Subagents twice ended their turn while waiting on background suite runs; the orchestrator absorbed the gap by running/collecting suites itself.

## 3. Scope drift

**None.** Closed at exactly the 3 files predicted at the Phase-2 gate. Confinement was a normative requirement (LLR-001.6), with unusually strong evidence: `app.py` diff 0 lines, `#a2l_*` byte-identical (authoritative diff check), 0 engine/parser/model files, test delta +3 net reconciling exactly (772 → 775). US-002..US-005 stayed deferred with no leakage.

## 4. Root-cause analysis of the forced Phase-1 iteration

**Proximate cause:** B-1 + B-2 (two factual errors in the doc), per the dev-flow rule that blockers force iteration.

**Deepest common cause: a measured-once constant treated as a universal fact.** The drafter applied batch-05's verification discipline to symbols (and it worked) but not to *derived environmental measurements*: `body_w` was carried from a single observation in one regime across the regime boundary. B-2 is the same failure shape in test-space (inferred instead of measured).

**Failure-mode generalization:** *"grep-verifiable" covers existence; it does not cover validity conditions.* A symbol either exists at `file:line` or not — binary, regime-free. An environmental measurement (`body_w`, a pane share, a breakpoint, a timing budget) is a **function of conditions**; citing the value without the conditions is the same defect as citing a symbol without grepping it — it just fails one regime later. The fix was cheap because the gate caught it pre-code (9 fixes, one iteration, no redesign). The real cost B-1 threatened was not broken code (the tests read geometry live) but a **mis-informed gate**: the operator's floor decision (M-1) was initially computed from wrong facts.

## 5. Proposed preventive control (template-ready)

Add to the requirements template, immediately after the LLR symbol-citation rule block:

> **Environmental-measurement citation rule — extends the LLR symbol-citation rule.** Any constant describing the runtime or layout **environment** — container/parent widths, derived geometry (e.g. `body_w`, pane shares), responsive breakpoints and transition points, timing/latency budgets, platform or CI environment values — MUST cite, at draft time: **(a) WHERE it was measured** (the probe or test `file:line`, or the exact `App.run_test(size=...)` / command invocation), **AND (b) the REGIME/CONDITIONS under which the measurement holds** (terminal-size band, CSS class state, rail/panel visibility, platform, dataset size). A measurement applied **outside its measured regime** MUST be re-measured in that regime or flagged `assumed — verify per-regime`. **Derived numbers inherit the flag**: any cell count, threshold, or transition point computed from an environmental constant is not a fact until the underlying measurement is regime-valid, and must cite the constant it derives from. **Phase-2 blocker classes:** (a) an environmental constant asserted as fact whose citation lacks its measurement conditions; (b) a constant or its derivatives applied in a regime other than the one cited. (Origin: batch-06 B-1.)

## 6. Validation retrospective (qa-reviewer)

1. **Percentage-band + live-geometry assertions were the single best call of the batch.** When B-1 landed, **the test designs survived untouched while the prose had to be rewritten** — the tests read `#workspace_body.region.width` live. Exact-cell assertions derived from the wrong `term − 6` model would have shipped 4 tests failing for the wrong reason or passing against the wrong invariant. Standing rule for Textual geometry: **tests measure the parent live; only documentation carries derived constants, and constants carry their measurement method.**
2. **Avoiding snapshot tests was correct:** kept the batch local-safe on Python 3.14.4 with zero baseline-drift risk; geometry bands gave equivalent guarantees. Confirmed: no `.svg`/snapshot artifacts in the diff.
3. **`_mac_layout_dims` reuse** kept one shared measurement path (no parallel helper to drift); per-TC harness cost stays cheap (7 tests in 5.12 s).
4. **Test-disposition lesson (F-Q-04/F-Q-05):** a test's fate is determined by **its assertion arithmetic under the new geometry**, not by what it is "about" (`:1399` never mentions 35% in its name; `:82` asserts a bound that happens to equal the new floor). **Standing rule for batch-07+:** Phase-1 test-disposition tables must be derived by executing/simulating each assertion against the new model, recording PASS/FAIL with the computed number — the B-2 table format in `02-review.md` is the template. Batch-07 retires the cfdx/.cdfx flow, so this applies immediately.
5. **Execution quality:** per-TC evidence verbatim (incl. compound thresholds and *documented benign grep hits*); independent re-run discipline held (timing divergence between qa and orchestrator runs is itself evidence of separate execution). Tighten next batch: (a) the Python-version caveat is structural — see A-3/A-5; (b) make the suite-count reconciliation (`775 = 772 + 4 − 1`) an explicit named check in the validation template so a silently-skipped test cannot hide in totals.
6. **Residual coverage gap (accepted, LOW):** no test at the ~216-col knee where the proportional share overtakes the floor (TC-002 jumps 160→250). Acceptable because the clamp is structurally guaranteed (empirically confirmed twice) and the knee is a rare width. Recommendation: batch-07 adds one parametrized width (~218×40) to TC-002 asserting non-decreasing width across the knee — opportunistic hardening; becomes MUST only if batch-07 touches MAC selectors.

## 7. Metrics

| Metric | Value |
|---|---|
| Iterations per phase | P1 **2** (forced by P2 blockers) · P2 1 · P3 1 · P4 1 · P5 1 |
| Findings (Phase 2) | 2 blockers / 4 majors / 4 minors / 0 security = 10 actionable |
| Findings closed | **10/10 in one iteration**; 0 reopened |
| Blockers found redundantly | B-1 by 2/2 independent reviewers |
| Requirements | 1 HLR / 6 LLR / 7 TC + TC-021′; 1 US active, 4 deferred |
| Increments | **1** (0 spec deviations) |
| Files touched | **3** (under 5-file budget) |
| Tests added / deleted / re-purposed / re-banded | 4 / 1 / 1 / 1 (+4 survivors untouched); net +3 (772→775) |
| Suite results | targeted 108 · lean **775/0 failed** (3 xfailed pre-existing) · slow 19/19 · A2L guard 8 |
| Acceptance criteria | 6/6 met · verdict **PASS** |
| Cycle time | Phases 0–4 in 1 calendar day (2026-06-09); Phase 5 on 06-10 |

## 8. Action items / next batch

| # | Action | Owner | Priority | When |
|---|---|---|---|---|
| A-1 | Adopt the **environmental-measurement citation rule** (§5) into the dev-flow req template + its 2 Phase-2 blocker classes | architect | **High** | Before batch-07 Phase 1 |
| A-2 | Phase 6 (this batch): update living `REQUIREMENTS.md` **R-TUI-039** to proportional+floor; repoint file/test pointers | docs-writer | High | Phase 6 |
| A-3 | **Resolve the CI-trigger gap** (recurring since batch-05): `tui-ci.yml` fires only on `main-tui` PRs, so the 3.11 gate never runs; add `main` to the trigger branches (one-line workflow change) | orchestrator | **High** | Before/with the batch-06 merge |
| A-4 | Batch-07: superseded-test inventories as **measured disposition tables** (B-2 method) in Phase 1 — applies immediately to the cfdx/.cdfx retirement | qa-reviewer | High | Batch-07 Phase 1 |
| A-5 | Close the 3.11-vs-local interpreter gap (pairs with A-3: once CI fires on `main` PRs the caveat dissolves) | orchestrator | Medium | With A-3 |
| A-6 | Batch-07 Phase-4: explicit suite run-ownership (qa vs orchestrator) to avoid duplicate wall-clock at larger scale | orchestrator | Medium | Batch-07 Phase 4 |
| A-7 | M-1 watch item: if the operator later reports MAC "still not growing", the answer is the documented §2.5/§6.3 floor tradeoff (revisit floor value / rail cost then) | architect | Low | If raised |
| A-8 | Run `/dev-flow-sync` after commit/push/merge (`obsidian_synced: false`) | orchestrator | Low | After PR merge |
| A-9 | Batch-07 (opportunistic): one parametrized TC-002 width at the ~216-col knee (§6.6) | qa-reviewer | Low | Batch-07 |
