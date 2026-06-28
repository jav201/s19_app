# Post-mortem — s19_app — Batch 2026-06-26-batch-17

> Phase 5 artifact. Co-authors: `architect` + `qa-reviewer`. Structured for cross-batch sweeping — keep the section order.
> Scope: three previously-deferred features run under full /dev-flow because "it is not the first time we try to fix them."

## 🔑 At a glance (read first)

- **Outcome:** closed clean — PASS, 0 iterations on any phase, one process carry-over (G-1 snapshot baselines).
- **Top 3:** ① draft-time + Phase-3 measurement caught two wrong premises before code landed ② US-018 root cause finally understood — a 2-pane fix never transferred to a 3-pane layout ③ the Phase-2 cross-review (M1) and counterfactual discipline both earned their keep.
- **New control this batch:** none new formally proposed — existing controls (RC-1, two-layer AT/TC, C-10, C-12, QC-2, per-increment reviewer) all exercised and held. The reusable *lesson* (geometry math at draft time for multi-pane layout changes) is logged as a candidate control below.
- **Open items → next batch:** 1 — G-1: regenerate workspace + issues SVG snapshot baselines in canonical CI (never local). Plus the pre-agreed US-020c/d deferral (addendum + report integration).
- **Metrics:** iterations 6 (1 per phase; Phase-3 = 4 increments) · findings 5 closed / 5 opened (0 blocker) · ledger 883→892.

> Enough to know the batch's health and what carries forward. Detail below only for the why.

---

## Detail (reference)

### What worked

- **Prior-attempt archaeology up front paid off immediately (architect).** The operator's "not the first time" framing was treated as a Phase-0 input, not folklore. Git archaeology reclassified all three stories before any design: US-018 was an *overlooked pane* (not a failed fix), US-019 was *net-new* (no prior attempt), US-020 had *nothing reverted*. That reframing is what let US-018 be sized XS instead of being feared as a recurring defect.
- **Draft-time verification killed a false premise (architect).** The original #7/US-019 framing assumed `write_crc_image` already had a width parameter to wire a selector to. Reading the function at draft time showed it did not — the story's real shape was "add the kwarg AND the selector," which is why US-019 was consolidated into a single increment.
- **Phase-3 measurement overrode the Phase-1 plan, correctly (architect + qa).** The plan was to mirror the proven `#mac_hex_pane min-width:82` floor onto `#ws_center`. Phase-3 measurement disproved it for the 3-pane workspace (see Root causes). The flow tolerated being wrong at Phase 1 and corrected via a §6.5 amendment (A2, operator-approved) rather than shipping the planned-but-broken fix.
- **Two-layer validation held its line (qa).** Every story has a black-box AT observing the shipped surface (Pilot-driven or on-disk artifact) plus a white-box TC, with both traceability chains intact. Every AT was shown RED under a counterfactual, and QC-2 confirmed each post-fix assertion is value-discriminating, not mere presence — notably AT-019b asserts `16 in widths / 32 not in widths / max==16`, and AT-020a asserts the specific `0x00001000` row with bytes `AB`/`CD` rather than "pane non-empty."
- **C-12 enforced honestly (qa).** AT-019b reads the record width back off the handler-produced `.s19` on disk, not a same-values direct write — the output-then-consume rule applied exactly as intended.
- **Engine-frozen discipline intact (architect).** 0 edits to the frozen set; `io.py` was not touched because the needed kwarg pre-existed. No guard tripped.
- **RC-1 held twice (architect).** Base-currency gate passed at open and again mid-flight — the branch was ff-merged onto `origin/main` (6a5859f / PR #27) at operator request with 0 conflicts.

### What didn't / friction

- **The big one: the Phase-1 design was wrong and we only learned it by measuring (architect).** A pattern proven in the 2-pane MAC/A2L views (`min-width:82` floor) was assumed to transfer to the 3-pane workspace. It does not. This is the documented "not first time" root cause — see Root causes. The flow caught it, but at Phase 3, later than ideal.
- **Shared UI methods are not headless-safe by default (qa + architect).** US-020a added `self.query` into the jump path, which broke a headless unit test with `ScreenStackError`. Fixed with a `screen_stack` guard. Friction signal: DOM queries placed in methods shared between interactive and headless call paths must tolerate the no-screen case.
- **Contract-touch fan-out on US-020b (qa).** Widening the issues row from a 7-cell to an 8-cell tuple required moving the formatter, `add_columns`, two docstrings, and one existing positional test in lockstep. Cheap individually, but a reminder that positional-tuple contracts spread the blast radius of a single added column.
- **Snapshot baselines drift on any layout change (qa).** Both US-018 (`#hex_view`) and US-020a/b (issues column split + Related column) alter rendered geometry, so the CI-gated SVG snapshot cells need regeneration. Expected friction with this project's snapshot strategy, not a defect — but recurring and worth noting (carried as G-1).

### Scope drift (planned vs actual)

| Planned | Actual | Note |
|---------|--------|------|
| US-018 + US-019 + US-020a/b; US-020c/d deferred | Same — exactly as scoped | **No drift.** The US-020 split into a/b (this batch) vs c/d (own batch) was a **DoR decision at the Phase-0 gate**, not mid-flight drift. Option (A) chosen deliberately: ship the READY parts, defer the net-new addendum (needs design + operator clarification on "declared memory locations"). |
| US-019 ~2 increments | US-019 = 1 increment | **Consolidation, not drift.** A selector with no wire is a half-wired intermediate with no observable behavior; splitting it would have produced a meaningless first increment. Folded into one. |
| US-018 mirror `#ws_center min-width:82` | `#hex_view {width:auto}` + existing `#hex_scroll` horizontal scroll | **Design correction inside the story**, via §6.5 amendment A2 (operator-approved). Same story, different mechanism — the planned one was disproven. |

### Metrics (full)

| Metric | Value |
|--------|-------|
| Iterations per phase | `{0:1, 1:1, 2:1, 3:1 (4 increments), 4:1, 5:1}` |
| Findings opened / closed | 5 / 5 (M1 + 4 minor; all folded or Phase-3-noted) |
| Findings by severity (blocker/major/minor) | 0 / 1 / 4 |
| Where caught (Phase 2 / P3 gate / P4) | 5 / 0 / 0 (all 5 surfaced in the Phase-2 cross-review; M1 corrected before Phase 3) |
| Test ledger (base − D + A = post) | `883 − 0 + 9 = 892` (re-pointed/renamed nodes are rewrites-in-place, net 0) |
| Files touched · increments (cap trips) | 4 increments, ≤5 files each · 0 cap trips |

### Root causes (only if a phase took ≥2 iterations)

> No phase took ≥2 iterations. The headline lesson is recorded here anyway because it is the operator's central concern ("why didn't prior fixes stick?") and the corrective insight is reusable.

- **US-018 — a 2-pane fix does not transfer to a 3-pane layout.** The MAC/A2L hex panes live in 2-pane layouts; flooring the hex pane at `min-width:82` simply makes the body scroll and costs nothing visible. The **workspace is a 3-pane layout** (fixed left 22 + flexed center + fixed right 40). At a 120-col terminal (body ≈96), a floored center=82 demands `22 + 82 + 40 = 144` and pushes the right **context pane off-screen**. So the "obvious" mirror trades one defect (hex row wraps) for a worse one (a whole pane vanishes) — which is almost certainly why earlier attempts to floor the center never stuck: whoever tried it saw the context pane disappear and backed it out. The correct fix is `#hex_view {width:auto}` so the row content-sizes and the pre-existing `#hex_scroll` scrolls horizontally: row on one line, all three panes visible. **Lesson: validate a borrowed layout pattern against the *target* container's geometry before adopting it. Draft-time geometry math (sum of fixed + flexed panes vs body width at the reference terminal size) — or a one-line Phase-1 measurement spike — would have caught this at Phase 1 instead of Phase 3.**

### Process / workflow findings

> About the dev-flow itself (phases, gates, templates, agents, controls). Feeds workflow improvement — keep separate from product.

- **Phase-1 plans for layout changes should carry a geometry budget (architect).** When a story changes container widths in a multi-pane layout, the plan should state the arithmetic (sum of fixed + flexed panes vs the body width at the reference terminal size) before committing to a mechanism. Candidate lightweight control for a future batch; not yet formalized.
- **Consolidating "selector + wire" into one increment was correct and should be the default (architect).** A UI control with no behavioral wire produces no black-box-observable outcome, so it cannot satisfy an AT on its own. Half-wired intermediates fight the two-layer model. Where a control is meaningless without its wire, keep them in one increment.
- **The Phase-2 cross-review earned its keep (qa + architect).** Major finding M1 caught a self-modifying carry mechanism (Option B infeasible) and replaced it with Option C *before* Phase 3 — i.e. the most expensive class of finding (an unworkable approach) was caught at the cheapest point (design review, pre-code). All 5 findings were caught in Phase 2; none escaped to the P3 gate or P4.

### Product findings

> About the code/product under development.

- **`#hex_scroll` was already the right primitive (architect).** The horizontal-scroll container already existed; the workspace fix was to stop fighting it (`width:auto` instead of a width floor). The workspace's correct hex behavior was one CSS property away, not a structural change.
- **Headless-safe DOM access is a latent hazard in shared methods (qa).** The `ScreenStackError` from `self.query` in a shared jump path is a class of bug, not a one-off. Any method reachable from both Pilot/interactive and headless-unit contexts must guard `screen_stack` (or equivalent) before querying the DOM.
- **Positional-tuple row contracts couple their consumers (architect).** The 7→8 cell widening rippled to formatter + `add_columns` + docstrings + an index-based test. Not worth refactoring now, but a future column add will pay the same tax; a named structure would localize it if this area grows.

### Control lineage

- **New control proposed this batch:** none formal. Candidate: a Phase-1 "layout geometry budget" check for multi-pane width changes (origin: US-018 root cause). Status: propose / consider-next-batch.
- **Prior controls exercised:**
  - **RC-1 (base-currency gate)** — *held twice*: at open and mid-flight (ff-merge onto `origin/main` 6a5859f / PR #27, 0 conflicts).
  - **Two-layer AT/TC + dual traceability** — held; 4 HLR / 7 LLR / 4 US covered on both layers.
  - **C-10 (non-default values in ATs)** — held; ATs use 16 (vs default 32) and specific addresses/bytes.
  - **C-12 (output-then-consume)** — held; AT-019b reads the handler-produced `.s19` off disk.
  - **QC-2 (value-discrimination per AT)** — held; every AT shown RED under a counterfactual, post-fix assertions value-discriminating (no presence-only passes).
  - **Per-increment independent `code-reviewer`** — held; all increments APPROVE.
  - **Engine-frozen guard** — held; 0 frozen edits, no guard tripped.
  - **Near-miss:** the Phase-1 `#ws_center min-width:82` plan would have shipped a regression (context pane off-screen) had Phase-3 measurement not overridden it — caught by the flow's iterate-to-refine, not by a named control. This is the strongest argument for the proposed geometry-budget check.

### Open / deferred items → next batch

| Item | Type (process/product) | Reason deferred | Trigger / owner |
|------|------------------------|-----------------|-----------------|
| G-1 — regenerate workspace + issues SVG snapshot baselines | process | Must regenerate ONLY in canonical CI env; local regen drifts unrelated baselines (memory `reference_snapshot_regen_env`). | Watch the PR's `tui-ci`; regen in CI env if snapshot cells fail. Owner: whoever lands the PR. |
| US-020c — report-addendum input (operator-declared memory locations) | product | NET-NEW data model + form + persistence; "declared memory locations" semantics need operator clarification before deriving — the exact two-layer mis-capture risk. | Own /dev-flow batch with a design spike (BACKLOG). |
| US-020d — issues→report integration (issues + addenda section) | product | Depends on US-020c. | Follows US-020c (BACKLOG). |
| Layout geometry-budget check (Phase-1) | process | New candidate control from US-018 root cause; not yet specified. | Control-lineage review at next batch open. |

### Evidence checklist — architect + qa-reviewer

#### Architect evidence checklist
- [x] Constraints stated explicitly — engine-frozen set off-limits, ≤5 files/increment, 3-pane geometry at 120-col reference, default CRC width must stay 32. (PLAN.md §Surfaces; root-cause arithmetic `22+82+40=144 > 96`.)
- [x] At least 2 alternatives considered — US-018: `#ws_center min-width:82` (rejected, measured) vs `#hex_view {width:auto}` (adopted); US-020 carry: Option B (self-modifying, infeasible) vs Option C (adopted). (PLAN.md §US-020 split; Phase-2 M1.)
- [x] Recommendation has rationale tied to constraints — `width:auto` chosen because the floor violates the 3-pane body budget and hides the context pane. (04-validation supersession line; root cause above.)
- [x] Risks listed (operational, security, cost, lock-in) — CRC contract re-point risk, US-020 addendum semantics risk, batch-breadth risk all logged. (PLAN.md §Risks/watch.)
- [x] Cost / latency estimated where relevant — N/A for a TUI CSS/threading batch; no model calls, no network, no per-request cost surface. Flagged not-applicable rather than skipped.
- [x] Diagram included when flow is non-trivial — not added; the flow is one CSS property + a known kwarg thread + a row-select→pane render. Geometry stated as arithmetic instead; no mermaid warranted.
- [x] What would change the recommendation is stated — if the workspace were ever reduced to 2 panes, the `min-width:82` floor becomes valid again; the geometry budget is the decision pivot. (Root cause.)
- [x] Two-layer requirements — every US has a first-class Acceptance block + `AT-NNN`; both chains exist (US→AT→outcome behavioral + US→HLR→LLR→TC functional). (04-validation Layer A + Layer B tables.)

#### QA-reviewer evidence checklist
- [x] Both layers executed; every LLR has a TC node, every US an AT node, all on disk + GREEN. (04-validation §Layer A / §Layer B.)
- [x] Every AT drives the shipped surface (Pilot / on-disk artifact), references no internal symbol in assertions. (04-validation §Layer B "Surface driven".)
- [x] Every AT shown RED under a counterfactual (non-vacuous); QC-2 value-discrimination confirmed per AT. (04-validation §Counterfactual — AT-018/019b/020a/021.)
- [x] Bidirectional reachability: inputs AND outputs observed at the surface. (04-validation §Bidirectional matrix — width selection in; record width / hex pane / Related cell out.)
- [x] Test ledger reconciles (883→892). (04-validation §Signed-balance ledger; +9 = US-018×3, US-019×3, US-020a×1, US-020b×2.)
- [x] 0 engine-frozen edits; full non-slow suite 892 passed / 0 failed; ruff clean. (04-validation §Verdict.)
- [x] One process gap (G-1 snapshot CI) recorded, not hidden — carried to next batch, not papered over. (04-validation §Gaps detected.)
- [x] Headless-safe regression (`ScreenStackError`) found and fixed with a `screen_stack` guard; verified by full-suite green. (Phase-3 increment note; What didn't.)
