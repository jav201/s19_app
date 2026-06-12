# Post-mortem — s19_app — 2026-06-11-batch-08

Co-authored: architect (process half) + qa-reviewer (validation half), merged by orchestrator, 2026-06-11.

**One-line takeaway (lineage):** b05 symbols→grep · b06 measurements→regime · b07 the spec's own checks must be executed · **b08: executed checks must cover the full citation surface (AC artifacts) and run in the target's REGIME; spec pins whose referents are created in Phase 3 (node ids, UI mechanisms) need their first verification at the creating increment's gate — Phase 2 structurally cannot check them and Phase 4 is the most expensive place to find them.**

---

## PROCESS HALF (architect)

### 1. What worked (template controls, now 4 generations deep)

**Probe self-test rule (b07 adoption) — paid for itself on its highest-leverage target.** B-2 (TC-008 regex under-covers two-dot relatives / from-import / indented forms) was findable ONLY because the rule forced the probe to be executed with recorded controls: reviewers re-ran P8b's counter-probes and showed three natural violation forms escaping with 0 hits, against the sole verification of LLR-003.2. In batch-07 this exact class ("asserted but never run") produced 4 blockers that reached the spec unexecuted; in batch-08 the probe WAS executed and the residual defect was one level subtler (regime, see §2). The class moved one generation deeper, as designed.

**Symbol-citation / measured-census discipline (b05 lineage) — redundant detection.** B-1 (LLR-001.4 AC names a `.hex` fixture; measured 0 `.hex` files in the repo, full examples/ census recorded) was found INDEPENDENTLY by two reviewers (F-A-01 ≡ F-Q-01). Independent convergence on 4 of 17 findings (B-1, B-2, M-1, M-5) is the strongest review-depth signal this project has recorded.

**Review-catches-what-batch-07-shipped.** M-1 (execute/now_fn signature contradiction making TC-001 unpassable) is the same B-4 unpassable-determinism class that reached the batch-07 spec; this batch it was caught at Phase 2, pre-implementation, and closed with a parent+LLR+forwarding edit verified by 3-hit grep. Concrete left-shift of a known failure class.

**Env-measurement rule (b06) — both reactive and proactive payoff.** Reactive: M-3 ("pytest 8.x" asserted ×3; measured 9.0.3). Proactive: probe P4's MEASURED S19 re-emission non-byte-stability (9544→10774 bytes, mem_map/ranges equal) grounded C-3's in-memory identity semantics at Phase 1 — an unachievable "byte-identical file" acceptance criterion was prevented from ever entering the requirement set.

**Contract-touch rule (b07 adoption) — exercised twice, both re-runs recorded.** C-2 re-opened at the G-1 reversal (audit row D-4) and again at the M-1 fix (E-3); both re-runs proved 7=7=7=7 and correctly classified the signature change as parameter-not-field. The rule's value here was disciplined non-drift, verified rather than assumed.

**Audit-table mechanics + ledger discipline held under churn.** D-1..D-8 (gate-1 scope reversal) and E-1..E-15 (full 17-finding register) all body-first, mechanically grep-verified; collection ledger EXACT at every gate (722→729→730→733) and full-suite reconciliation exact (701+29+3=733; 681+20=701). Run-ownership per batch-07 A-6 eliminated duplicate full-suite runs.

### 2. What didn't / near-misses + root causes

**B-1 entered the iteration-2 draft despite the symbol-citation rule existing.** Root cause: rule-surface gap, not rule failure. The rule's wording targets cited SYMBOLS (functions, classes, line anchors); the `.hex` fixture was asserted inside an ACCEPTANCE CRITERION as a data artifact — a surface the rule does not explicitly enumerate. The catch depended on reviewer diligence, not on the control. → A-1.

**B-2 entered despite the probe self-test rule being EXECUTED.** Root cause: the P8b positive control ran on `app.py` — a single-dot import regime — while the protected targets live one package level deeper (two-dot regime). The env-measurement rule makes regime explicit for measured constants; for probe controls, regime coverage was implicit until this batch's fix made it concrete (synthetic in-regime package, 3/3 hits, negative control 0). The rule said "control must execute"; it did not say "in the target's regime". → A-2.

**DEV-1 escaped to Phase 4 (3 pilot node ids drift from §4 pins).** Root cause: §4/§5.3 pinned implementation-level identifiers (verbatim pytest node ids) at Phase 1, before any test existed — and E-12 then HARDENED the criterion ("all 11 named node ids collected") without adding any checkpoint that reconciles pins against collected names. Increment gates verified counts (733 exact) but never names. The spec made a prediction and nothing ever compared prediction to reality until validation. → A-3.

**DEV-2 escaped to Phase 4 (dismiss-callback mechanism vs modal-internal execution).** Root cause: mechanism over-specification. LLR-004.2 encoded a structural UI prediction (`push_screen(..., callback)` pattern) when the normative property was "execution exclusively through the LLR-003.1 service" — which IS fully verified (TC-011 seam proof, P8 0 hits). The clause was born in the gate-1 HLR-004 addition, written in one iteration under gate pressure, with no TC asserting the named structure — so nothing could fail when implementation legitimately chose a different locus. → A-4.

**Minor hygiene residue:** ~35 double-encoded em-dashes from iteration-1 text (flagged at iteration-3, deferred to Phase 6); N-3 `load_buttons` widget-id reuse in `OperationsScreen` (cosmetic, Textual-legal, no LLR pins it).

### 3. Scope drift assessment

Two mid-stream injections; both absorbed by the controls rather than around them.

- **G-1 reversal at gate-1 (TUI view added).** Absorbed cleanly: HLR-004 appended without renumbering, audit series D-1..D-8 with parent re-reads, C-2 re-opened per contract-touch (D-4), A-4 assumption rewritten rather than silently relaxed (D-3), file budget recounted 6→~10-11 with the increment plan re-split (D-6/R-4), new risk R-6 minted for the synchronous-execution debt. Cost: +1 Phase-1 iteration, and arguably DEV-2 — the one defective clause this batch traces to the gate-time LLR block. The process paid the reversal's price in the right currency (documentation and one iteration), not in code rework.
- **C-7 per-operation requirements convention at the I1 gate (mid-Phase 3).** Absorbed with zero requirement churn: informative §6.2/§6.3 additions only, correctly judged to need no audit row (no statement/threshold touched); the one potential clash (LoadedFile input contract) was VERIFIED already-deferred (R-2) rather than assumed — the operator's "si choca, relégalo" was answered with a check, not a promise. Persistent memory updated. Clean.
- The conditional 11th file (`services/__init__.py`) was resolved NO at I2 with recorded reasoning (adding a re-export would invent a convention) — the "conditional" mechanism in C-5 worked exactly as intended.

Verdict: no uncontrolled drift. Both injections are operator decisions executed through the gate/audit machinery; residue (DEV-1/DEV-2) stems from spec-ahead-of-code pinning, not from the scope changes themselves.

### 4. Metrics

| Metric | Value |
|---|---|
| Iterations per phase | P1: 3 (initial + gate-1 scope + Phase-2 fix) · P2: 1 + re-confirmation · P3: 3 increments (5/2/4 files, all ≤5 cap) · P4: 1 |
| Phase-2 findings | 17 opened (2 B / 5 M / 10 m), 17/17 closed in ONE iteration (2 folds); load-bearing closures independently re-verified by orchestrator |
| Cross-reviewer independent convergences | 4 (B-1, B-2, M-1, M-5) |
| Security | PASS, 0 blockers/majors, 4 advisories — all folded into requirements (P11, m-7 thresholds, R-6 hardening) |
| Phase-4 | 11/11 TC pass individually (0 skips), 9/9 inspections at numeric thresholds; 2 DEV (LOW, doc-drift) + 3 notes |
| Collection ledger | 722→729→730→733, EXACT at every gate; full-suite reconciliation 701+29+3=733 exact |
| File budget | 10 files, +1532/−0 purely additive, vs planned ~10–11; conditional resolved NO |
| Calendar | Phases 0–4 in one day (2026-06-11) |

---

## VALIDATION HALF (qa-reviewer)

### 1. Verification-quality wins (evidence-cited)

| # | Win | Evidence | Assessment |
|---|---|---|---|
| W-1 | **Source-level threshold re-count at Phase 4 was cheap because thresholds were written as arithmetic, not prose.** | Every §1 row in `04-validation.md` re-derives its count from test source with line cites (e.g. TC-002 "`_assert_identity_passthrough` `:108-119` = 3×5 = 15/15"). Phase 2 had already re-added all 10 formulas, so Phase 4 was a diff against a known vector, not a fresh derivation. | The "3×5=15" decomposition style made the audit a counting exercise. It also surfaced N-1 and N-2 — variances prose thresholds would have hidden. 11/11 formulas certified at source; zero trust placed in increment packets. Keep (→ V-4). |
| W-2 | **The Phase-2 M-2 intervention produced a genuinely stronger TC-012.** | Pre-M-2, the equality was vacuous by construction (`result.output is loaded` ⇒ a test computing both renders compares a dict with itself). Post-M-2: live `#operation_result_hex` `.plain` vs an independent in-test baseline with the §4-pinned argument tuple. | The post-M-2 test fails if the screen passes different render args, renders the wrong widget, or drops the render entirely — three real regression modes the vacuous form passes silently. Rule-9 standard enforced at review time, before the test existed. m-8 fold (pin `max_rows`) was free hardening. |
| W-3 | **The 11-node N pin (m-5) made criterion 4 mechanically checkable — and it is what exposed DEV-1.** | Count exact (733), but 3 pilot functions exist under different names than the §4 pins → criterion 4 PASS-WITH-NOTES, DEV-1 registered. | **The pin did not create the drift, it detected it.** The unpinned formulation would have passed silently — drift invisible, §4 node ids permanently un-runnable documentation. Cost: one LOW doc-reconciliation item. Benefit: spec↔code identity is auditable at all. Keep the pin; fix the TIMING of the check (→ V-1). |
| W-4 | **Orchestrator-owned suite runs with exact reconciliation closed criterion 3 without ambiguity.** | Lean 681/0, full 701/0; 701+29+3=733; 681+20=701. | The batch-07 A-6 run-ownership split worked: no double-counting, no phantom green. |

### 2. Leak analysis — what escaped Phase 2 and why

Both DEVs share one root cause: **they are forward references to artifacts that did not exist on the Phase-2 tree.** A pinned node id for a file at P10 pre-state "exit 4", and a mechanism clause about a screen not yet written, have **no pre-state to check**. The review could only verify the pins were internally consistent, not that Phase 3 would honor them. This is a distinct leak class from batch-05's fabricated symbols: those were checkable-and-wrong; these were unverifiable-until-built.

| ID | Root cause | Where it was catchable | Missed step |
|---|---|---|---|
| DEV-1 (node-id drift) | Node ids pinned at Phase 1 for tests written at Phase 3 I3; implementer chose different (view-prefixed, arguably more consistent) names; nothing at the I3 gate compared names against §4. | **I3 increment gate.** Running each §4-pinned node id verbatim returns "no tests ran" / exit 4 in seconds. The detection signal Phase 4 used was available at the increment for the same cost. | Increment verification ran new tests by FILE, not by pinned NODE ID. The pin existed; nobody executed it as a gate check until Phase 4. |
| DEV-2 (execution-locus drift) | LLR-004.2 pinned a UI MECHANISM (dismiss-callback pattern) by symmetry with a precedent, before `OperationsScreen` existed. Phase 3 built modal-internal execution. The normative core (execution exclusively via `run_operation`, guard, KeyError→status) held and was fully verified. | Phase 1 drafting. The batch-05 "looks like it should exist" class transposed from symbols to MECHANISMS. The `assumed — verify in Phase 3` flag is the right device but only covers symbols/constants today. | LLR pinned mechanism as normative text instead of behavior + service-route. A mechanism clause for a NEW screen can never be grep-verified at draft; it should never be `shall`-grade. |

The asymmetry worth recording: in both cases **no behavior went unverified**. The leaks are spec-fidelity leaks, not coverage leaks; LOW severity correctly assigned, batch-07 DEV-8 supersession precedent gives the clean Phase-6 disposition path.

### 3. Probe & ledger practice

- All 11 probes executed at draft with recorded pre-states; both Phase-2 reviewers independently reproduced all of them; Phase 4 re-ran every probe mechanically.
- **B-2 is the batch's most important probe lesson: an executed positive control is not a valid control unless it runs in the target's regime.** The iteration-3 fix (synthetic scratch package at the exact target depth, 3/3 hits + negative control 0, scratch deleted) is the template-worthy form. Generalizes the b06 environmental-measurement rule from constants to probe controls (→ V-3).
- **P11 positive-control re-confirmation at Phase 4: keep.** Phase 4 re-ran the control and got 7 hits MATCHING the §5.1 draft record — an equality, not a bare ">0". Without it, a 0-hit target result is indistinguishable from a silently broken probe. Requires the draft ledger to record the expected count (→ V-5).
- **Ledger: the batch-07 basis-error class (794 vs 826) did not recur — structurally, not by luck:** baseline MEASURED at draft (P6: 722 on the pre-implementation tree), delta PINNED (N=11), dual closure at Phase 4 (722+11=733 collection identity; 701+29+3=733 and 681+20=701 execution identity). Both ends of the equation were fixed before Phase 3 wrote a line. Cheapest control in the batch; must survive into the template (→ V-7).
- Threshold-formula noise: "100% of 5 assertions" reads as exact count and produced non-finding N-1 when the test contained 10 → wording fix V-6.

### 4. Verification recommendations (next batch)

| ID | Recommendation | Derives from |
|---|---|---|
| V-1 | Increment gates execute every §4-pinned pytest node id VERBATIM in the increment that creates it; exit 4 = increment blocker (rename or amend the pin in that packet, never later). | DEV-1 |
| V-2 | LLRs pin BEHAVIOR + service-route only; UI mechanisms become acceptance criteria flagged `assumed — verify in Phase 3`. | DEV-2 |
| V-3 | Every probe positive control records its REGIME next to the probe and must run in the target's regime (synthetic in-regime fixture if the target doesn't exist — the `_b2_scratch` pattern). Out-of-regime controls are superseded-pending, not evidence. | B-2 |
| V-4 | Keep Phase-4 source-level threshold re-counts; keep thresholds as decomposed arithmetic (`3×5=15`). | W-1 |
| V-5 | Keep Phase-4 positive-control re-confirmation for every absence probe, as an EQUALITY against the draft-recorded hit count. | P11 |
| V-6 | Threshold wording: "all N mandated elements present; additional assertions permitted" instead of "100% of N assertions" when N enumerates elements. | N-1/N-2 |
| V-7 | Keep the pinned-N + draft-measured-baseline reconciliation pair (P6 pattern) as a mandatory template element. | §2.10 |

---

## MERGED ACTION REGISTER

| ID | Action | Prevents/serves | Owner / when |
|---|---|---|---|
| A-1 | Extend the symbol-citation rule to ACCEPTANCE-CRITERIA ARTIFACTS (fixtures, example files, data paths): executed existence probe or NEW flag + budget recount. | B-1 | Template adoption at next batch Phase 0 |
| A-2 | Extend the probe self-test rule: positive controls must be IN-REGIME, and the ledger entry states the regime (merges V-3). | B-2 | Template adoption at next batch Phase 0 |
| A-3 | Spec-pinned pytest node ids are `provisional until Phase 3`; each increment gate reconciles collected node ids against the pins verbatim (merges V-1). | DEV-1 | Phase-3 increment-gate checklist, next batch |
| A-4 | Mechanism-clause lint at Phase 2: any LLR naming a UI structural pattern either carries a TC asserting it or is reworded to the normative property (merges V-2). | DEV-2 | Phase-2 checklist, next batch |
| A-5 | THIS BATCH Phase 6: DEV-1 node-id amendment + DEV-2 LLR-004.2 mechanism rewording as audit-noted supersessions; em-dash mojibake normalization (optional). | DEV-1/DEV-2 | Phase 6 (already gate-assigned) |
| A-6 | Hygiene: rename `OperationsScreen`'s reused `load_buttons` container id (N-3). | N-3 | Next TUI-touching batch |
| A-7 | Next-batch candidate queue (operator picks at init): (1) first operation fill-in per C-7 — co-located REQ-<id>.md, neutral input-contract decision (R-2), MANDATORY inheritances R-6 worker migration + confirmation/sanitized paths, budgets C-2 widening (R-3); (2) US-006 hex compare; (3) manifest writer; (4) HEX emitter; (5) E2E pilot; (6) knee test (3-6 carried from batch-07 A-7). | — | Operator at next /dev-flow-init |
| A-8 | Keep: V-4/V-5/V-6/V-7 validation practices (source re-counts, control-equality re-confirmation, element-style threshold wording, pinned-N reconciliation pair). | W-1/P11/N-1/ledger | qa practice, ongoing |

**Caveat recorded:** single-day batch, one operator, standing-approval phases 4-6 — iteration counts not comparable to multi-day batches; A-3/A-4 add checklist weight to phases that closed in 1 iteration, so drop them if two consecutive batches show no DEV-1/DEV-2-class residue.

**Orchestrator gate disposition (2026-06-11, under the operator's standing approval):** Phase 5 APPROVED — the post-mortem is analysis with no open defects; A-5 is the only this-batch action and is already assigned to Phase 6. A-1/A-2 (template edits) are deferred to the next batch's Phase 0 for explicit operator confirmation, per the batch-06/07 precedent that template adoption is operator-confirmed at close. Advancing to Phase 6.
