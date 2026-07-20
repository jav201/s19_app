# Post-mortem — s19_app — Batch 2026-07-20-batch-51 (Flow Builder: LOAD notices · CHECK block · status model · Direction-A render)

> Phase 5 artifact. Co-authors: `architect` + `qa-reviewer`. Structured for cross-batch sweeping — keep the section order.

## 🔑 At a glance (read first)

- **Outcome:** **closed clean** — 1 Phase-2 iteration (blocker folded before code); 0 Phase-3/4 iterations; PASS at Phase 4; 0 frozen diffs; 0 snapshot drift.
- **Top 3:** ① prototype-first + Phase-2 tri-review caught the AT-086c blocker BEFORE any code (architect + qa converged independently) ② the Phase-1 fold of qa's concern invented a *phantom* gating vocabulary that would have false-failed correct code ③ root cause = the fold followed the reviewer's prose SHORTHAND instead of the LLR-defined token/status vocabulary on disk.
- **New control this batch:** none adopted — **1 strong candidate flagged** (fold-against-defined-vocabulary), operator-gated. See §Control lineage.
- **Open items → next batch:** 4 — biggest is the **CRC block + the deferred twin/`before_ranges` ribbon** (batch-52, AMD-1).
- **Metrics:** iterations `1` (all in Phase 2) · findings `all closed`/`1 blocker + 2 major + minors (P2) + 5 nits (Inc-1) + 4 nits (Inc-2)` · ledger `1593 → 1623 (+30)`.

> Enough to know the batch's health and what carries forward. Detail below only for the why.

---

## Detail (reference)

### What worked

- **Prototype-first de-risking.** `flow_builder.prototype.py` had already validated the abort-asymmetry (LOAD/PATCH failure breaks the image → downstream skipped; CHECK failure keeps the chain running, image intact) and `flow_builder.screen.prototype.html` fixed Direction A as the design source. The batch entered Phase 1 with the hard model question already answered, so the spec was decomposition, not discovery.
- **Phase-2 tri-review caught the blocker BEFORE code.** `architect`, `qa`, and `security` ran in parallel; `architect(B-1)` and `qa(B1)` **independently converged on the same blocker** — the orchestrator's Phase-1 AT-086c fold. Two reviewers reaching the identical finding from different starting points is the strongest possible signal that the fix (REC-4) was real, not taste; the orchestrator judged a full re-dispatch unnecessary given the convergence + a mechanical fix (recorded).
- **The structural chain-never-blocked fix (TC-086.6).** Inc-1 code-review widened the CHECK inner `try` to enclose the *whole* branch body so any exception routes to the non-aborting `_record_check_own_op`, and TC-086.6 (bad-aggregate `KeyError` → assert non-aborting + downstream produces) makes the operator's non-negotiable invariant **structural**, not contract-conditional. The "chain is never blocked" invariant now survives an unexpected exception class, not just the anticipated ones.
- **0 engine-frozen diffs across the whole batch.** `git diff` over the 7 frozen paths stayed empty at both increment gates and Phase 4; `app.py` was untouched (the `render_result` call was unchanged). The status→`sev-*` map was placed in `screens_directionb.py` (D4), deliberately NOT routed through frozen `color_policy.py`.
- **0 snapshot drift — and it was measured, not assumed.** Inc-2 honestly superseded the PLAN's drift expectation: no parametrized snapshot baseline navigates into `#screen_flow`, so the Direction-A render changed 0 cells → **no canonical-CI regen follow-up needed** (29 snapshots passed, 0 drift). The PLAN's R-2 risk simply didn't fire.
- **C-33 transcript-mtime liveness monitoring held — no agent hang.** Every parallel sub-agent dispatch (Phase-1 architect+qa, Phase-2 tri-review) was liveness-monitored on artifact/transcript mtime. Unlike batch-49 (a delegated review sub-agent hung ~10.5h), no agent stalled this batch; the active-poll discipline (C-33) was exercised and held.
- **Geometry measured in-regime (C-16/C-29).** The ribbon was pilot-measured in the mounted boxed panel (80×24 content-width 70, ribbon 48 cells, 22-col margin; 120×30→92; 160×40→132) rather than inheriting the HTML prototype's wider budget — the cross-tech prototype caveat was respected.

### What didn't / friction

- **The Phase-2 blocker — a phantom vocabulary invented during a Phase-1 fold (ROOT CAUSE).** When the orchestrator folded qa's Phase-1 gating-coverage concern into a new acceptance node (REC-1, AT-086c), it authored the test against the reviewer's **prose shorthand** ("test the gating *block* value") rather than the **LLR-defined vocabulary on disk**. The model actually defines gating tokens `advisory` / `block-own-op` (LLR-086.1) and a block-status set `ok / notices / error / skipped` (LLR-086.4/086.5). The fold invented three things that do not exist in the model:
  1. a **phantom gating value** `"block"` (the real non-default token is `block-own-op`);
  2. a **phantom block status** `"blocked"` (the real errored status is `error` → `sev-error`);
  3. a **false-failing trigger** — it fired on *entries-absent*, but per the LLR-086.4 matrix an entries-fail does **not** flip the block status under either gating mode, so a *correct* implementation would have failed the AT.
  This is the classic "named a value that looks like it should exist" failure, one level up from the batch-05 symbol-citation failure: not a fabricated *symbol* but a fabricated *enum/status token*. It was caught pre-code by the tri-review (REC-4 reauthored AT-086c to drive the SAME unreadable-doc input under both real tokens `CHECK_GATING_ADVISORY`/`CHECK_GATING_BLOCK_OWN`, asserting the status *differs* — `notices` vs `error` — and both runs still write; entries-absent dropped). Had the fold instead been checked against the on-disk token/status set at authoring time, the phantom never forms.
- **AMD-1 — the "twin ribbon" spec assumed data + growth that don't exist in batch-51.** The Inc-2 software-dev correctly STOPPED before coding (engineering rule 8, read-before-write) on a real blocker: LLR-088.4's "twin memory ribbon" (a) had **no data source** — the Inc-1 `FlowRunResult` carried only a range *count* in a summary string, not address extents; and (b) the "twin" (before + image rows) is **meaningless in batch-51** because no block grows the range set (CRC = batch-52), so the two rows would be byte-identical and *misleading*. Resolution: add an additive `FlowRunResult.image_ranges` carrier (re-opened the 2 Inc-1 engine files additively with the full Inc-1 suite + frozen guard re-run to prove 0 regression) and render a **single** honest ribbon now; the twin + `before_ranges` carrier + the operator's "watch it grow" signature defer to batch-52 where growth makes them meaningful. Friction, but caught at the right seam (rule-8) — the spec drove more UI than the data model could honestly support.
- **A latent AT-authoring gap the process only partly closes.** The Phase-1 fold went *into the spec* and was only caught at Phase-2 because two reviewers happened to re-derive it. The dev-flow has strong rules for fabricated *symbols* (symbol-citation) and *artifacts* (AC-artifact citation) but no explicit rule that a folded acceptance value must be checked against the model's *defined token/status vocabulary*. That gap is the control candidate below.

### Scope drift (planned vs actual)

| Planned | Actual | Note |
|---------|--------|------|
| Twin memory ribbon (before + image rows) in batch-51 | **Single** image ribbon; twin deferred to batch-52 | AMD-1 — no range-growing block in batch-51 → two identical bars would mislead; operator-awareness flag raised (reversible) |
| `FlowRunResult` carries range footprint | Added **`image_ranges`** additive field (re-opened 2 Inc-1 files additively) | AMD-1 carrier; §6.3 R-6-sanctioned; 0 Inc-1 regression proven |
| Snapshot drift on `#screen_flow` → canonical-CI regen follow-up (R-2) | **0 drift**, no regen needed | No baseline navigates into `#screen_flow`; PLAN expectation honestly superseded at Inc-2 |
| gating UI: possible split to a follow-up if Inc-2 overflows (open flag) | Gating Select shipped in Inc-2 **without** a split; stayed ≤5 files | The gating-UI fit budget held; F3 (hide `#flow_gating` for non-CHECK) noted as batch-52 polish |
| CRC block, flow.json persistence, external-import | **OUT** as planned | CRC → batch-52; persistence/import → batch-53. No drift. |

No unplanned scope entered. The two adjustments (twin→single, image_ranges carrier) were AMD-1, recorded with an operator-awareness flag.

### Metrics (full)

| Metric | Value |
|--------|-------|
| Iterations per phase | `{0:0, 1:0, 2:1, 3:0, 4:0, 5:0, 6:0}` |
| Findings opened / closed | Phase-2: 1 blocker + 2 major + minors (REC-4/5/6/7) — **all folded**; Inc-1 review: 5 nits (F1–F4,F6); Inc-2 review: 4 nits (F1–F4) — **all applied or dispositioned** / **all closed** |
| Findings by severity (blocker/major/minor) | `1 / 2 / (minors: REC-7 cluster + 9 increment nits)` |
| Where caught (Phase 2 / P3 gate / P4) | `Phase 2: 1 blocker + 2 major + minors` / `P3 increment gates: 9 nits (5 Inc-1, 4 Inc-2) + AMD-1 rule-8 catch` / `P4: 0 blockers, 1 non-blocking gap (G-1)` |
| Test ledger (base − D + A = post) | `1593 − 0 + 30 = 1623` (test_flow_model.py 4 + test_flow_execution_service.py 15 + test_flow_builder_render.py 11; tracer test_flow_execution.py 4 unchanged) |
| Files touched · increments (cap trips) | Production source: **4** (`flow_model.py`, `flow_execution_service.py`, `screens_directionb.py`, `styles.tcss`; app.py untouched) · **2** increments (0 cap trips) |
| Frozen diffs · snapshot drift | **0** engine-frozen diffs · **0** snapshot drift |

### Root causes (Phase 2 took 1 iteration)

- **Iteration trigger:** Phase-2 tri-review raised 1 blocker (AT-086c) + 2 major (LLR-086.4 matrix un-tabulated; LLR-088.6 markup-sweep hand-enumerated) → fold REC-4/5/6/7 → re-gate.
- **Root cause of the blocker:** the Phase-1 acceptance-fold was authored from the **reviewer's prose shorthand** ("the gating *block* value"), not from the **LLR-defined vocabulary on disk** (`advisory`/`block-own-op`; `ok/notices/error/skipped`). The fold therefore named a gating value (`"block"`), a status (`"blocked"`), and a trigger (entries-absent) that the model does not define/support — a phantom that false-fails a correct implementation. Contributing: LLR-086.4's gating matrix existed only as *prose* ("per the matrix above"), so the 3-of-4 cells that collapse to `notices` were not visible at fold time — which is exactly what let AT-086c be mis-authored (REC-5 tabulated it).
- **Root cause of AMD-1 (Phase-3, not an iteration — caught at rule-8):** the UI spec (twin ribbon, "watch it grow") was inherited from a prototype whose payoff is inherently a *range-growing* (CRC) operation; batch-51 has no such block, so the spec outran the data model. Caught at read-before-write, resolved additively, deferred honestly.

### Process / workflow findings

> About the dev-flow itself (phases, gates, templates, agents, controls).

- **A folded acceptance value is citation surface, same as a symbol.** The dev-flow mandates `file:line` citation for folded *symbols* (symbol-citation rule) and existence probes for folded *artifacts* (AC-artifact rule), but has **no rule that a folded token/status/enum value must be reconciled to the model's defined vocabulary**. The AT-086c blocker is that gap made concrete. Suggested change → the control candidate below.
- **Tri-review convergence is a reliable blocker detector for folded ATs.** Two reviewers independently re-deriving the same blocker validated skipping a re-dispatch. Keep parallel independent review on any orchestrator-authored fold (the fold is the least-reviewed artifact in the flow because the orchestrator both wrote and gated it).
- **Rule-8 (read-before-write) is doing real work at the Inc boundary.** AMD-1 was a spec/data-model mismatch that only surfaces when the implementer actually goes to source the render's data. The stop-at-blocker-before-coding discipline paid off; the artifact (AMD-1 in §6.5, Before/After) captured it without silently editing a locked requirement.
- **Tabulate any matrix an AT keys on.** LLR-086.4 as prose was mis-readable; as a 4-cell truth table it made the single differing cell (block-own-op × unreadable → `error`) unambiguous. Consider: any LLR whose acceptance drives a multi-axis decision must ship the truth table, not prose.

### Product findings

> About the code/product under development.

- **The chain-never-blocked invariant is now structural.** TC-086.6 (widened try + bad-aggregate KeyError) means an unexpected exception in the CHECK branch cannot abort the chain. This is the operator's headline requirement and it is now defended structurally, not by enumerated cases.
- **The twin/growth ribbon is a genuine batch-52 payoff, not a cut feature.** A single honest footprint ribbon ships now; the "watch it grow" signature lands with CRC where a range-growing block makes before-vs-after meaningful.
- **`FlowContext` MAC/A2L is `None` in batch-51 (D6).** CHECK linkage classification is informative-only, so `None` yields unclassified-but-non-blocking linkage. Wiring project MAC/A2L into the context is a possible later refinement (out of scope, recorded).
- **G-1 (non-blocking): no zero-block / pre-run empty-state render TC.** The single-block boundary is covered; a mount-with-zero-children render through `render_result` is not directly exercised (the empty-ribbon path is unit-proven `_memory_ribbon_text([]).plain == ""`, and roll-up over no blocks is `ok` by LLR-087.2). Recommended Phase-3 follow-up TC; low risk.

### Control lineage

> **CANDIDATES ONLY — flagged, not adopted. The operator gates every control via AskUserQuestion before any encoding.** Each is classified GLOBAL (dev-flow, project-agnostic) vs PROJECT (s19_app `docs/engineering-rules.md`) per the placement policy.

- **CAND-1 (STRONGEST) — "fold-against-defined-vocabulary."** When folding a reviewer's finding into an AT/LLR (or authoring any acceptance node from a reviewer's prose), verify the fold against the **LLR-defined vocabulary on disk** — the actual token / status / enum values the model defines — **not the reviewer's prose shorthand**. A fold that names a value, status, or trigger the model does not define is a *phantom* that false-fails correct code. Mechanically checkable: grep every literal token an AT asserts against the model's defined constant set; an unmatched literal is a Phase-2 blocker (same shape as the symbol-citation and AC-artifact blockers).
  - **Rationale:** direct root cause of this batch's sole blocker (AT-086c phantom `"block"`/`"blocked"`/entries-absent). Generalizes the batch-05 symbol-citation rule from *symbols* to *enum/status/token values*.
  - **Proposed placement: GLOBAL (dev-flow).** It is a project-agnostic V-model/acceptance-authoring discipline (any batch that folds a reviewer finding into an acceptance node), so it belongs with the symbol-citation / AC-artifact family in the global command, not in `docs/engineering-rules.md`.

- **CAND-2 (weaker, corollary) — "tabulate any matrix an AT keys on."** An LLR whose acceptance drives a multi-axis decision (here: gating × doc-readability) must ship the decision as an explicit truth table, not prose; prose let the AT-086c mis-author slip. Could be folded into CAND-1 as a sub-clause rather than a standalone control.
  - **Proposed placement: GLOBAL (dev-flow)** if adopted, as a spec-authoring clause. Likely too narrow to stand alone — flag for the operator as a possible rider on CAND-1.

- **Prior controls exercised (held / stressed / near-miss):**
  - **C-33 (transcript-mtime liveness)** — exercised on every parallel dispatch; **held** (no hang, unlike batch-49). 
  - **C-27 dual-guard frozen set** — **held**; 0 frozen diffs at both gates + Phase-4, including re-frozen `a2l.py`.
  - **C-10 (observed-change acceptance)** — **stress-tested**: the AT-086c blocker was precisely a *defective* C-10 node (pinned one branch, never drove the baseline on the same input); REC-4 restored a true observed-change form.
  - **C-17 (untrusted-render) / markup-sink sweep** — **stressed**: REC-6 widened the hand-enumerated sink set to a code-derived set; Inc-2 F1 hardened it to a 3-layer AST completeness guard, bypass-proven RED. Closes the batch-33/43/48 sink-sweep miss pattern for this render path.
  - **C-16/C-29 (in-regime geometry measurement)** — **held**; ribbon measured in the mounted panel, not inherited from the HTML prototype.
  - **C-26 (touched-symbol consumer reconcile)** — **held**; the 1 `test_tui_directionb.py` reconciliation touched no `tc031`/`tc032`/`_ENGINE_PATHS`.
  - **Rule-8 (read-before-write)** — **held**; surfaced AMD-1 at the Inc-2 boundary before any code.

### Open / deferred items → next batch

| Item | Type | Reason deferred | Trigger / owner |
|------|------|-----------------|-----------------|
| **CRC block** (template lib + address-space growth, ADR §7) | product | Out of batch-51 scope (address-space-growth seam = "be very thorough") | **batch-52** / architect + software-dev |
| **Ribbon "before"/twin row + `before_ranges` carrier** (AMD-1) | product | No range-growing block in batch-51 → twin would be two identical bars; lands with CRC where growth is meaningful | **batch-52** / software-dev (carries the operator's "watch it grow" signature) |
| **F3 — hide/disable `#flow_gating` when kind ≠ CHECK** | product (polish) | Deferred at Inc-2 as batch-52 polish note | **batch-52** / software-dev |
| **G-1 — empty-flow / pre-run empty-state render TC** | product (test) | Non-blocking boundary-TC gap (all 9 ATs observed); empty-ribbon path unit-proven | **batch-52** (or its own fast-flow) / qa-reviewer |
| **CAND-1 / CAND-2 control encode** | process | Operator gates every control (AskUserQuestion) before encoding | **operator decision** at closeout / orchestrator |
| flow.json persistence + external-import + variant reuse | product | Out of scope | **batch-53** |
| **P-1b A2L handoff** | product | Separate session's batch (A2L line, not Flow Builder) | separate session — NOT batch-52 |

**Closeout carries (batch-51 itself):** `/dev-flow-sync` to the vault (`obsidian_synced: false`); no snapshot-regen PR needed (0 drift measured). Batch-49 + batch-50 remain awaiting-sync independently.

### Evidence checklist — architect + qa-reviewer

**architect (design/spec):**
- [✓] Constraints stated explicitly — §2.4 (frozen set, ≤5 files, C-17, geometry, snapshot, OUT-of-scope).
- [✓] ≥2 alternatives considered — twin-ribbon vs single ribbon (AMD-1); D1 LOAD-as-SOURCE vs new discriminator; D4 status→sev map placement (screens_directionb vs frozen color_policy).
- [✓] Recommendation tied to constraints — single ribbon chosen because no range-growth in batch-51 (honest-render constraint); D4 chosen to keep 0 frozen diff.
- [✓] Risks listed — §6.3 R-1..R-6 (untrusted-render, snapshot, gating visibility, reuse, geometry, contract-touch).
- [✓] Cost/latency where relevant — geometry pilot-measured (48-cell ribbon @ 80×24, 22-col margin); n/a for token cost.
- [✓] Diagram/flow — abort-asymmetry model in prototype + §6.1 glossary; render structure in Inc-2.
- [✓] What would change the recommendation — AMD-1 operator-awareness flag (force twin earlier → pull a range-growing block forward).
- [✓] Two-layer requirements — every US-085..088 has a first-class Acceptance block + AT-NNN; both chains present (§5.2 behavioral US→AT + functional US→HLR→LLR→TC).

**qa-reviewer (validation):**
- [✓] Acceptance criteria Given/When/Then-equivalent — §3 EARS + black-box AT observable-outcome blocks.
- [✓] TCs have explicit Expected — every node asserts concrete values (tokens, byte-equality, counts, `spans==[]`); evidence = the 1623-pass gate run.
- [✓] Edge cases — empty (`test_tc085_2`, empty ribbon `test_tc088_4`), boundary (exactly-one-error, single-block, all-present), invalid/error (`test_at085b`, `test_at086b`, `test_tc086_6`), gating-observable (`test_at086c`).
- [✓] Regression — frozen dual-guard + full Inc-1 suite re-run at Inc-2 (0 regression) + C-26 consumer reconcile, all inside the 1623.
- [✓] Exit criteria met — 0 fail, 0 frozen diff, 0 snapshot drift.
- [✓] No real PII/secrets — synthetic S19 fixtures + a hostile literal payload only.
- [✓] Results section machine-cited — §0 gate run verbatim (1623 passed / 0 drift / exit 0).
- [✓] Layer B — all 9 ATs observe their outcome through the shipped surface with boundary + negative; AT-086c + AT-088b non-vacuous.
- [✓] Bidirectional surface-reachability — §3 matrix complete both directions.
- [✓] No unfilled template — all AT/TC ids reconciled to real on-disk nodes (V-5); one non-blocking gap G-1 logged as a carry.
