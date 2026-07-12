# 05 — Post-mortem — 2026-07-11-batch-36

> Phase 5 (Post-mortem). Authors: architect + QA lens (QA metrics derived from `04-validation.md`).
> Batch: US-058 (B-22 Patch Editor paste box) · US-059 (B-24 hex-view colour legend) · US-060
> (B-23 fixture relocate + heavy-A2L prune) + BACKLOG refresh. Fully supervised run (operator
> approved every gate + every increment; operator merges). Base `7df60dd`, worktree
> `heuristic-wu-1c7c49`, branch `claude/ui-layout-backlog-review-f9a343`.
> **Gate verdict carried in: Phase-4 PASS, 0 blockers, 0 HIGH across the batch.**

---

## BLUF

Batch-36 shipped all three operator-requested stories with a clean Phase-4 gate
(`1343 passed / 2 skipped / 5 xfailed / 0 failed`, exit 0). The V-model worked exactly as
designed: **the Phase-2 cross-review killed three would-be-latent defects before a line of code was
written** (an unsatisfiable acceptance predicate, a CSS-invariant metric that could never fail, and
a missing verify-before-delete gate on an irreversible 54 MB deletion). The one real process miss was
a **geometry estimate that was 4.5× wrong** because Phase-1 computed rows from CSS `fr`-arithmetic
instead of measuring the rendered pane — caught at the Phase-2 re-measurement, but it forced an
operator escalation (F-01) that a pilot-measurement at Phase 1 would have pre-empted. Two smaller
recurrences (a writer-census golden gap; the Phase-4 harness-backgrounding of the 14-min suite) were
both recovered with zero rework. No scope drift. Four candidate controls proposed below — none
encoded (operator approves each first).

---

## 1. What worked

- **Phase-2 cross-review caught three blockers BEFORE implementation** — all corrections/gates, no
  story killed (`02-review.md` consolidated table):
  - **A-01 (architect):** AT-058a's "five regions pairwise-disjoint" predicate was *unsatisfiable* —
    `#patch_doc_controls` / `#patch_checks_controls` are CHILDREN of `#patch_doc_file_row`, so
    parent⊃child always "overlaps", and it contradicted the surviving TC-319. Redefined to
    leaf-sibling disjointness + a non-descendant guard on the reparented paste group.
  - **Q-01 (qa):** AT-058a's paste metric `region.height >= N` was **CSS-invariant** — the box is
    already `height: 8` in `styles.tcss:949-951` whether visible or below the fold, so the
    counterfactual could never RED (C-10 violation). Switched to the content-region **placement**
    idiom (paste's first line below the pane fold today → inside the viewport after).
  - **Q-04 / A-08 (qa+architect):** the I-060-1 construct-equivalence gate was **absent** — LLR-060.2
    authorized the 54 MB `git rm` on file-SIZE alone, i.e. coverage-preservation was unproven before
    an irreversible delete. Added a hard Phase-3 verify-before-delete gate (construct-kind subset
    census, evidence recorded BEFORE the `git rm`).
- **The I-060-1 census gate made a destructive delete safe** (`increment-002.md` §I-060-1). Before any
  `git rm`, the 54 MB `professional_validation/case_06` A2L was proven a pure SCALE duplicate of the
  retained 36 MB `case_06`: identical 13 `/begin` construct kinds, `kinds(54 MB) ⊆ kinds(36 MB)` TRUE,
  `comm -23` = ∅. No unique parser/validator branch lived only in the deleted copy. Reversible-by-history
  `git rm` (not `rm`), working-tree-only, security-confirmed 0 secrets/PII.
- **The software-dev caught the spec's illustrative weight vector breaking a survivor test**
  (`increment-003.md` §5 Deviation-1). The Phase-2 requirement *illustrated* rung-1 with
  `grid-rows: 1fr 1fr 2fr auto`; measured, that starved the checks/variant middle row to 1 row and
  pushed the variant `Select` below the fold, breaking **TC-035.2**
  (`test_tc_035_2_variant_group_above_execute_row`). Dev rebalanced to `1fr 2fr 2fr auto` (paste and
  checks rows each 2 of the 5 @80x24), keeping TC-035.2 green — surfaced honestly as a spec deviation,
  not silently absorbed.
- **Measured-not-estimated geometry at Phase 3** (`increment-003.md` §4 table). Every N_w is a MEASURED
  pilot pin at `scroll_y == 0`: BEFORE `region.y=38` @80x24 / `36` @120x30 = **0** in-viewport lines
  (below fold); AFTER **N_80=1 / N_120=4** (the latter *exceeds* the spec provisional of 3). RED→GREEN
  proven by file-level source revert (C-20, not `git stash`).
- **Two-layer + C-18 discipline held end-to-end** (`04-validation.md` §3). All 5 ATs reconcile to
  exactly ONE on-disk node each, each drives the shipped surface with a real MEASURED counterfactual;
  AT-060a fuses its four facts into one node so a half-migration can't half-pass. C-12 output-then-consume
  honoured (AT-059b writes `reports/*.md` → re-reads the file; AT-060a drives the real service pipeline).
- **Engine-frozen boundary respected** (`04-validation.md` §5): 0 diffs on the frozen set; legend logic
  went in non-frozen `legend.py` reading `color_policy` constants READ-only.

## 2. What didn't / friction (root-caused)

- **F-01 — measurement miss (the batch's one real process failure).** Phase-1 estimated "~9 rows/pane"
  from CSS `fr`-arithmetic. The real rendered panel was **~5 rows @80x24** (`#patch_pane_changefile`
  content h = 2), a **4.5× overestimate** (§7 probe P24: "Draft '~9 rows/pane' WRONG ~4.5×"). This
  surfaced only at the Phase-2 amendment re-measurement (probe P24, Textual pilot), which forced a NEW
  finding beyond the three reviews and an **operator escalation** — the operator chose the in-place
  "first option" (accept a low N_80, no expand-view). **Root cause:** geometry was claimed from
  `fr`-math, not pilot-measured. Consequence was contained (F-01 accepted; N_80=1 still beats the
  below-fold 0), but the whole US-058 acceptance had to be rebuilt at Phase 2 partly because the budget
  premise was wrong. → C-CAND-A.

- **Writer-census golden gap.** The Phase-1 supersession census for US-059 (LLR-059.3) enumerated exactly
  the two breaking legend assertions (`test_tui_legend.py:70,:78`) and asserted frozen tests stay green —
  but it **missed the batch-35 report byte-identity golden** `tests/goldens/batch35/at055b-project-report.md`,
  which captures the FULL unfiltered report bytes including the legend. Adding the `### Hex` block
  legitimately drifts it. **Root cause:** the census treated the legend's *assertion* consumers but not
  its *byte-identity* consumers — a report-content SOURCE (`LEGEND_TABLE`) changed, and any golden that
  snapshots rendered report bytes is a downstream writer. Caught at Inc-1 by the failing `at055b` run,
  rebaselined surgically (+4/-0 = exactly the Hex block, independently re-verified). → C-CAND-B.

- **Phase-4 harness-backgrounding recurrence.** The qa validation agent kicked off the ~14-min full gate
  suite; the harness backgrounded the long run, and the agent ENDED before the run finished — the known
  C-19 failure mode, **now running two batches in a row** (state.json Phase-4 note: "C-19 harness-backgrounding
  recurrence, 2nd batch running"). Recovered by the orchestrator (caught the completed run, resumed the
  agent with context intact → `04-validation.md` written, **zero rework**). **Root cause:** the ~14-min gate
  run outlives the agent's turn budget and the harness detaches it; nothing binds "agent may not end before
  its own gate run completes." A recovery-that-works is not a fix — it's a repeat. → C-CAND-C.

## 3. Scope drift

**None.** Reported honestly against each temptation:

- **F-01 escalation resolved WITHIN scope.** When the re-measurement showed @80x24 could not show a
  multi-line paste box in compose+CSS, the operator chose the in-place "first option" — accept N_80=1,
  a real improvement over the below-fold 0. **No focus-to-expand affordance, no sub-view, no new
  handler/binding** was added (`increment-003.md` §5 risk 1; §1 "no scope expansion"). The change stayed
  compose+CSS-only.
- **The 3-column reflow idea was measured-and-rejected at Phase 1, not built** (DF-1/D-058). The operator's
  original 3-column concept was refuted by the measured 80-col budget (a 3-col button cell gives 7 cols,
  clipping "Validate" which needs 8) — rejected up front, dedicated vertical paste region chosen instead.
  Rejection, not build-then-revert.
- **US-060 prune stayed working-tree-only.** No git-history rewrite crept in (explicitly out-of-scope,
  LLR-060.4); `examples/` 96M→42M in the working tree, history weight left for a separate approved pass.
- **File caps held every increment:** Inc-1 = 4 files, Inc-2 = 4 code/doc files (+ git mv/rm authorized
  per-task), Inc-3 = 5 files. Never exceeded the ≤5 cap.

## 4. Metrics

### Iterations per phase
| Phase | Iterations | Note |
|---|---|---|
| 0 — Story intake | 1 | DoR gate approved first pass (3 stories READY, 0 REFINE/SPIKE/OUT) |
| 1 — Requirements | 1 | Approved; 2 premise-overturning findings accepted (DF-1 3-col rejected, DF-2 synthetic-not-vendor) |
| 2 — Cross-review | **2** | iterate-to-refine: 11 findings folded (§6.5 Before/After) + AT registry reconciled, then re-gate |
| 3 — Implementation | **3** | one increment per story (Inc-1 US-059, Inc-2 US-060, Inc-3 US-058) |
| 4 — Validation | 1 | PASS all 3 axes, 0 blockers |
| 5 — Post-mortem | 1 | this document |

### Findings opened vs closed
- **Phase-2 cross-review: 11 findings, ALL folded + re-verified** — 3 blockers (A-01, Q-01, Q-04/A-08),
  4 majors (Q-02/A-05, Q-03, A-02/Q-05, A-03), 4 minors/low (A-04/Q-07, A-06/Q-08, A-07/Q-06, S-01, S-02).
  Recorded as §6.5 amendment records R-A01/R-A02/R-A03/R-A04/R-A06/R-A07/R-Q01/R-Q02(+F-01)/R-Q03/R-Q04,
  each with a Before/After block. Plus **F-01** = a NEW finding surfaced at the re-measurement, escalated
  to the operator.
- **Increment code-reviews:** Inc-1 = 1 LOW (operator "approve + harden" → TC-322 hardened to feed live
  constants so a bare RE-VALUE fails, not only a rename); Inc-2 = 0 findings (APPROVE 0 HIGH/MEDIUM/LOW);
  Inc-3 = 1 MEDIUM (stale comments cited the rejected weight vector → orchestrator fixed, 2 comment edits).
- **0 HIGH across the entire batch.** 3/3 increments APPROVE.

### Test ledger (base 1362 → 1370, +8 net)
| Increment | Added | Ledger |
|---|---|---|
| Inc-1 (US-059) | AT-059a, AT-059b, TC-322 | 1362 → **1365** |
| Inc-2 (US-060) | AT-060a, TC-323 (case-param swap nets 0) | 1365 → **1367** |
| Inc-3 (US-058) | AT-058a, AT-058b, TC-321 | 1367 → **1370** |

- **Gate run (C-19, ONE complete run, CI-equivalent `-m "not slow"`):** `1343 passed / 2 skipped /
  20 deselected / 5 xfailed / 0 failed`, exit 0, 14:25. Reconciles to 1370 collected.
- **5 xfails** = 2 batch-36 patch snapshot cells (`patch-comfortable-80x24`, `-120x30`, canonical-CI
  regen deferred) + 3 pre-existing entropy-modal cells. None a regression.
- **Repo weight:** `examples/` **96M → 42M** (~54 MB reclaimed in the working tree; ≤45 MB threshold met).
- **Engine-frozen guards:** 0 diffs on the frozen set.

## 5. Root causes where multiple iterations occurred

**Only Phase 2 took >1 iteration (2 iterations — the amendment fold).** Root cause: the Phase-1 draft
carried three defects that the review is *designed* to catch —
1. a **vacuous/unsatisfiable acceptance predicate** (AT-058a five-region disjointness, plus the
   CSS-invariant `region.height >= N` metric with no counterfactual), and
2. **`fr`-math geometry** ("~9 rows/pane") that was 4.5× off the rendered budget, and
3. a **missing verify-before-delete gate** on an irreversible deletion.

Was the second iteration avoidable? **Partly.** The vacuous-predicate and missing-gate catches are the
process working as intended — that's what an independent cross-review is *for*, and folding them at Phase 2
(before code) is far cheaper than discovering them at Phase 3/4. **The geometry, however, was avoidable at
Phase 1**: had the paste budget been pilot-MEASURED when first claimed (as it ultimately was at probe P24),
F-01 would not have been a Phase-2 surprise and the US-058 acceptance would not have needed rebuilding on a
corrected premise. So: the amendment *fold* was healthy; the *geometry re-derivation inside it* was
self-inflicted and is the target of C-CAND-A/D.

Phase 3's three iterations are **by design** — one supervised increment per story, each with its own
operator gate — not a defect signal.

## 6. Items proposed for the next batch (B-37)

**Feature backlog (from `project_baseline_backlog_2026-07-09` reconciliation):**
- **P2:** B-11 (press-b persistent surface), B-12 (entropy pagination + sort), B-13 (entropy legend /
  clickable), B-14 (patch refresh / JSON popup).
- **P3:** B-16 (v2-path relabel), B-17 (A2L >32-bit defensive warning), B-18 (info buttons), B-19
  (patch undo/redo).
- **Bookmarks screen** — the dead "coming soon" rail-item-8 scaffold; the one clear TUI gap, own batch.

**Hygiene carries (unchanged from batch-35 + batch-36 additions):**
- S-F7 raw `linkage_symbol` in `report_service`.
- `canonical_report_bytes` helper consolidation.
- `__setattr__` retire.
- P-1 / P-2 / P-3.

**New this batch:**
- **Writer-census golden lesson** — fold report byte-identity goldens into the standing supersession-census
  checklist whenever a report-content source changes (basis for C-CAND-B).
- **Post-merge:** canonical-CI SVG regen to retire the 2 patch snapshot xfails
  (`patch-comfortable-{80x24,120x30}`) — standard convention, not a defect.
- **Phase-6 owed (this batch):** REQUIREMENTS.md rows R-TUI-046/047/048 + `.dev-flow/BACKLOG.md` refresh
  + operator-facing docs (`04-validation.md` §6 R-3).

## 7. Candidate dev-flow controls — PROPOSE, do NOT encode

> Each is a proposal. The operator approves each individually before any `~/.claude/commands` edit
> (feedback_devflow_control_encode_approval). Labelled C-CAND-<x>.

### C-CAND-A — Geometry claims must be pilot-MEASURED, never fr-arithmetic-estimated
- **Origin incident (this batch):** F-01. Phase-1 estimated "~9 rows/pane" from CSS `fr`-arithmetic; the
  rendered panel was ~5 rows @80x24 — a 4.5× overestimate that surfaced only at the Phase-2 re-measurement
  and forced an operator escalation + full US-058 acceptance rebuild (§7 probe P24; `01-requirements.md`
  R-Q02/F-01).
- **Exact rule:** Any requirement or acceptance predicate that asserts a rendered-region dimension (rows,
  columns, visible-line counts, viewport fit) must cite a MEASURED value from a Textual pilot at the target
  size(s) at the phase where the claim is first made — never a value derived from CSS `fr`/`grid-rows`
  arithmetic. An unmeasured geometry claim blocks the phase gate.
- **Extends:** C-13 (geometry-budget-at-80-cols) — C-13 mandates *budgeting*; C-CAND-A mandates the budget
  be *measured, not computed*.

### C-CAND-B — Report byte-identity goldens are census members whenever a report-content source changes
- **Origin incident (this batch):** the LLR-059.3 supersession census missed
  `tests/goldens/batch35/at055b-project-report.md`; adding `### Hex` to `LEGEND_TABLE` legitimately drifted
  it, caught only by the failing golden at Inc-1 (`increment-001.md` §5).
- **Exact rule:** When a change touches a report-content SOURCE (`LEGEND_TABLE`, legend/section templates,
  any string that renders into a generated report), the supersession census MUST enumerate every
  byte-identity / full-output golden that snapshots rendered report bytes as a superseded consumer, with an
  explicit rebaseline disposition — not only the unit assertions on the source.
- **Extends:** the writer-census family (C-15.1 / C-14 location-move + writer-census sweeps) — adds
  byte-identity goldens as a first-class census target for content-source changes.

### C-CAND-C — Phase-4 gate run is the ONE CI-equivalent `-m "not slow"` run; the validation agent must not end before it completes
- **Origin incident (this batch):** the qa validation agent backgrounded the ~14-min full suite and ended
  pre-completion — the C-19 harness-backgrounding failure mode, now recurring a **second consecutive batch**;
  recovered by the orchestrator with zero rework, but a repeat (state.json Phase-4 note).
- **Exact rule:** The Phase-4 gate evidence is exactly ONE complete `pytest -q -m "not slow"` run
  (CI-equivalent, `.github/workflows/tui-ci.yml`). The validation agent MUST NOT end its turn before that
  run completes, OR must explicitly hand the in-flight run off to the orchestrator with a resume marker.
  A validation artifact citing a backgrounded/incomplete run does not satisfy the gate.
- **Extends / refines:** C-19 (one-complete-run test evidence) — adds the agent-lifecycle binding that C-19
  currently lacks (C-19 says "one complete run"; C-CAND-C says "the agent may not exit before it finishes").

### C-CAND-D — Illustrative spec values are non-normative; Phase-3 re-measures the FULL pane budget
- **Origin incident (this batch):** the Phase-2 spec's *illustrative* rung-1 weight vector
  `grid-rows: 1fr 1fr 2fr auto` starved the checks/variant row and broke TC-035.2; the software-dev caught
  it at Inc-3 and rebalanced to `1fr 2fr 2fr auto` (`increment-003.md` §5 Deviation-1).
- **Exact rule:** Any concrete value a spec offers to *illustrate* a mechanism (CSS weights, grid sizes,
  pixel/row counts) must be explicitly marked **non-normative / illustrative**; Phase-3 implementation must
  re-measure the FULL affected pane budget — every sibling widget in the layout, not just the target widget —
  and is free to deviate from the illustrative value, surfacing the deviation honestly (C-20/12).
- **Extends:** C-13 — pairs with C-CAND-A; C-13 budgets, C-CAND-A measures, C-CAND-D scopes the measurement
  to all siblings and de-normativizes illustrative values.

---

## 8. Sign-off

Phase-4 gate: **PASS** (0 blockers, 0 HIGH, all 3 axes). No defect outstanding; residuals all accepted
(F-01 N_80=1) or owed to Phase 6 (docs/ledger). Recommend proceeding to Phase 6 (docs: R-TUI-046/047/048
+ BACKLOG refresh) and, post-merge, the canonical-CI SVG regen to retire the 2 patch snapshot xfails.
The four C-CAND controls above are **proposed only** — awaiting the operator's per-control approval before
any `~/.claude/commands` edit.
