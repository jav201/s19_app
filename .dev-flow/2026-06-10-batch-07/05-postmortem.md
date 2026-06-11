# Post-mortem — s19_app — Batch 2026-06-10-batch-07

**Date:** 2026-06-11 · **Co-authors:** architect (§1–§5, §7–§8) + qa-reviewer (§6) · **Scope:** US-002..US-005 (single hex-first JSON change system + cfdx retirement, declarative check files, Markdown project report, multi-S19 variant projects) + CI-1.

**One-line takeaway:** batch-05 proved *named symbols* must be grep-verified, batch-06 proved *measured constants* must be regime-verified; batch-07 proves the spec's **own checks** must be executed — all 4 blockers reduce to "the document asserted something that had never been run."

---

## 1. What worked

1. **Both batch-06 preventive controls paid off at scale — first stress-test of adopted controls.** *Env-measurement rule:* zero B-1-class findings; it drove the E7 `REPORT_MAX_*` measurement at implementation time (constants HOLD; the measurement became the batch's 1 new slow test). *Measured-disposition rule:* the single highest-leverage control — the 355-row §6.6 table superseded the ~192 estimate by +85% (inference would have missed nearly half the blast radius), was audited 10/10 at Phase 2, validated **35/35 mid-flight** by the E3a interim-red prediction diff, enacted as a checklist at E3b (ledger exact), and finished at **98.3% first-pass accuracy** (6 re-dispositions, one shared root cause, all gate-ratified via the STOP rule).
2. **Security in Phase 2, with runtime verification, before any code.** F-S-02 (non-text codecs) and F-S-06 (`open_links=True` default) were verified live against the actual runtime at review; all 7 F-S-* mitigations entered as iteration-2 spec amendments and landed with code+test pins by Phase 4. Zero security findings at Phase 3/4 — the cheapest possible placement.
3. **The E3a/E3b split + interim-red-as-table-validation pattern.** D-2 turned a budget violation into a verification opportunity: consolidate → measure the red set against the model → then delete. E3b's 46-file deletion (+1,550/−16,212) started from a pre-validated table with a rollback commit behind it. Reusable for any large retirement.
4. **Ledger discipline — exact at 11 checkpoints** (lean chain 775→…→670; collection 915/662/722). A constraint tight enough to surface a 32-test discrepancy (§2.2) is a constraint tight enough to trust; it made the 229-test retirement auditable.
5. **C-6 cross-architect reconciliation held — after the fix.** Post B-1/B-2, the canonical `ChangeSummary`/`CheckRunResult` contract carried E2→E4→E6→E7 without a single interface defect. Two-architect parallel drafting bought a same-day Phase 1 for 51 LLRs at the cost of one reconciliation table — a good trade *when the table is kept live* (§2.1).
6. Honorable mentions: anchor hygiene "best of any batch" (batch-05 control compounding); operator decisions consistently at the cheapest gate (6 confirmables P1, 3 at P2, ratifications at increment gates); 8 deviations all surfaced at their gate, zero discovered later.

## 2. What didn't / friction

1. **C-6 staleness blocker class (B-1/B-2):** the canonical contract was reconciled once at merge and went stale the SAME DAY when gate decisions added LLR-002.7/002.8 — precisely the edits most likely to touch producer contracts and least likely to be re-reconciled. → contract-touch rule (§5).
2. **Units error inside a NAMED check:** the "794" pre-batch basis circulated through Phase-3 prompts was passed-counts, not collected-counts (true basis 826); the ledger missed by exactly 32 at every checkpoint until qa corrected it in Phase 4. The discipline *worked* (a constant exact offset is the signature of a units error) — but a named check with wrong units confers false authority. → units rule (V-2).
3. **Recurring subagent friction:** implementer agents end their turn while background suites run (~8 orchestrator absorptions across 10 increments; flagged in batch-06 §2.4). Harness behavior, so the fix is procedural: extend run-ownership to Phase 3 (A-6).
4. **Unexecutable-verification blocker class (B-3/B-4):** the retirement probe false-passed on ANY tree (BRE `\|`), guarding the most destructive operation of the batch — the highest-stakes near-miss dev-flow has produced; the determinism spec could never pass. Same family at lower severity: F-A-05's false reuse claim, DEV-8's wrong node id. → probe self-test rule (§5).
5. Minor: E1's commit landed on the stale chore branch (recovered at zero cost) → worktree checklist line (A-9).

## 3. Scope drift
**Effectively none — every boundary event surfaced and ratified.** Deferred-and-surfaced: manifest writer (E6 gate), Intel HEX emitter (operator decision D-1). Cap excursions all contract-driven and ratified (E3b pre-approved exception; E6's 2 mandated pins; E5a's 3 logically-forced lock flips). The cap behaved as intended: **a tripwire, not a wall** — 3 of 10 increments tripped it, all with the excess explained by a named contract clause at the gate.

## 4. Root causes of the forced P1 iteration
| Cluster | Blockers | Mechanism |
|---|---|---|
| Contract staleness | B-1, B-2 | identity check ran once at merge; post-draft gate decisions edited a producer LLR; check never re-fired |
| Unexecutable verification | B-3, B-4 | verification commands/specs written from intent; never executed (B-3 false-passes always; B-4 cannot pass ever) |

**Deepest common cause: the spec asserted something that was never executed.** The cross-batch progression is now a clean sequence of verification-discipline generalizations: symbols (b05) → measured constants (b06) → the spec's own checks (b07). The gate caught all of it pre-code and closure was cheap (34/34 in one iteration) — the system working — but B-3 guarded a 16,212-line deletion.

## 5. Proposed preventive controls (template-ready)

> **Probe self-test rule — captured from batch-07 B-3/B-4.** Any executable verification artifact written into an HLR/LLR — a grep/rg probe, a regex, a pytest node id, a determinism/equality procedure, an inspection command — MUST be EXECUTED at draft time against the current tree, with its **expected pre-state result recorded next to the spec** (e.g. "probe run 2026-06-10: 164 hits pre-retirement; pass condition = 0 post"). A probe that cannot demonstrate a non-trivial pre-state — hits today for a future-absence check, a failing-then-passing pair for a behavioral check, both sides exercised for an equality — is unproven and shall be flagged `unexecuted — verify in Phase 2`. **Phase-2 blocker classes:** (a) a verification command recorded without executed pre-state evidence; (b) a verification whose pre-state execution contradicts its claimed semantics. (Origin: batch-07 B-3 — a BRE grep returning 0 on a tree known to contain 164 hits — and B-4 — a double-apply equality no correct implementation could satisfy; the E3b probe's recorded 164→0 self-test is the worked example.)

> **Contract-touch rule — captured from batch-07 B-1/B-2.** A cross-cutting interface contract (canonical field set, producer/consumer table) is reconciled at merge but **invalidated by any subsequent edit to any LLR it cites** — including gate-decision insertions, which are the most likely to add fields and the least likely to be reconciled. Any post-draft edit touching a producer or consumer LLR re-opens the contract as a mandatory checklist row: the editor shall re-run the identity check (field-set equality across every producer and consumer enumeration) and record the re-run in that edit's audit-table row. An edit that adds a field to one side without the recorded re-run is a Phase-2 blocker. (Origin: batch-07 B-1/B-2 — LLR-002.7/002.8 added `saved_path`/`issues` hours after C-6 was drafted.)

## 6. Validation retrospective (qa-reviewer)

1. **Per-LLR embedded verification held at 51 LLRs:** Phase 4 mapped all 9 clusters 1:1 onto runnable commands — 196/196, 0 Phase-3 iteration. The only spec↔execution friction was a node-id string drift (DEV-8) — at this scale, that's the pattern working. The four Phase-2 verification-spec fixes (B-3 `-rE`+self-test, B-4 injectable clock, F-Q-07 subprocess isolation, F-Q-05 regex pin) each demonstrably prevented a Phase-3/4 failure: every fixed form executed cleanly where the original would have false-passed or hard-failed. **Standing Phase-2 reviewer question: "would this command actually run, and could it pass on a wrong tree?"**
2. **Disposition table at scale:** 355 rows, 98.3% first-pass; the 6 misses were SURVIVES rows whose assertions depended on v1-issue *semantics* (MEMV-* warnings eliminated when containment became apply dispositions) — symbol-level screening catches collection deaths; only **semantic screening** catches assertion deaths. Fix for 100%: re-screen SURVIVES rows against the design's category-move list (issue→disposition class changes) — one extra pass, not a method overhaul (V-1).
3. **Reconciliation-as-named-check earned its place:** the exact-form ledger (the F-Q-14 Phase-2 upgrade from `~` deltas) refused to close on the wrong basis and proved the 32-unit error; without exactness it would have been waved through as noise. Units rule → V-2.
4. **Residual coverage:** snapshot cell xfail (correct by design; CI regen + drop with CI-1) · demo criteria executed at gates (gate observation = evidence of record) · **no single E2E pilot** (load→execute→generate→view) — recommend ONE pilot in batch-08 (amortizes with US-006's flow; the only uncovered defect class is seam state, e.g. the `_last_execution` handoff) · 3.11 pending on the PR · **batch-06 A-9 knee test NOT added and its conditional MUST did not trigger** (no MAC selectors touched — verified live); now ridden two batches → convert to a fixed batch-08 task (V-5).
5. **Numbers:** N_i ledger 42/23/24/7/12/8/11/14/8 = 149 (zero post-gate drift); 722 collected / 670 lean / 20 slow / 196 targeted — all exact.

## 7. Metrics

| Metric | Value |
|---|---|
| User stories delivered | 4 (US-002..US-005) |
| Iterations | P1 **2** (forced) · P2 1 · P3 1 · P4 1 · P5 1 |
| Phase-2 findings | 4 blockers / 17 majors / 13 minors = **34**; closed **34/34** in one iteration; §6.7 audit 45 rows |
| Requirements | 8 HLR / 51 LLR / TC-001..053; 9 design decisions |
| Increments | **10** (incl. both gate-decided splits); files 6/5/5/**46**/6/7/4/7/3/4 |
| Test ledger | collected **826 → 722** exact; lean **670/0**; slow **20/20**; exact at **11 checkpoints** |
| Disposition table | 355 rows · 98.3% first-pass · 35/35 interim validation |
| Security | 7 F-S-* mitigations spec'd P2, implemented + pin-tested P4 |
| Deviations | 8 ratified, 0 silent |
| Phase-4 verdict | PASS-WITH-NOTES (1 open criterion = CI-1 on the PR) |
| Cycle time | Phases 0–3 in 1 day (2026-06-10); 4–5 on 06-11 — **~2 days** |

## 8. Action items

| # | Action | Owner | Priority | When |
|---|---|---|---|---|
| A-1 | **CI-1 rides the batch PR** (two-tier tui-ci.yml edit; both jobs green = closes 3.11 confirmation; §5.3 criterion 5) | orchestrator | **High** | At PR open |
| A-2 | Adopt **probe self-test rule** + **contract-touch rule** (§5) into the req template | architect | **High** | Before batch-08 P1 |
| A-3 / V-2 | **Suite-basis units rule**: every count states `collected`/`passed-lean`/`passed-full`; quote full pytest tuples; ledgers on collected only | all writers | **High** | Immediate |
| A-4 | Phase-6 doc reconciliation: REQUIREMENTS.md §8–9 supersession; DEV-1/7/8 wording; §6.6 archive annotations; DEV-5 notes | docs-writer | High | Phase 6 |
| A-5 / V-6 | CI-env snapshot regen (`patch-comfortable-120x30`) then drop the xfail | orchestrator | Medium | First post-merge CI |
| A-6 | **Phase-3 run-ownership** (extends b06 A-6): work orders state who runs the lean suite — implementer foreground pre-packet, or orchestrator at gate entry | orchestrator | Medium | Batch-08 P3 |
| A-7 | Batch-08 candidates: **US-006 hex-compare** (memory), **manifest writer** (E6), **Intel HEX emitter** (D-1), **E2E pilot** (V-4), **knee test as fixed task** (V-5) | architect | Medium | Batch-08 planning |
| A-8 | Template option: disposition column in report/validation tables | qa-reviewer | Low | Batch-08 |
| A-9 | Worktree checklist: confirm branch before first increment commit | orchestrator | Low | Template |
| A-10 | `/dev-flow-sync` to the canonical G: vault after merge | orchestrator | Low | Post-merge |
| V-1 | Semantic SURVIVES screening (category-move list) in disposition tables | qa-reviewer | High | Batch-08 P1 |
| V-3 | Verification node ids copy-pasted/collect-checked at draft (prevents DEV-8) | architect/qa | Medium | Batch-08 P1 |
