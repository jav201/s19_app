# 05 — Post-mortem — 2026-07-01-batch-23 (US-028 inline variant dropdown)

> **BLUF: Clean single-iteration PASS that closes feature #8 entirely (US-026/027/029 b21 · US-030/031 b22 · US-028 b23). Phase 2 was the batch's highest-value phase — 1 BLOCKER + 5 MAJOR caught pre-code, including a second framework-surprise save (F-4) and a security MAJOR (SEC-F2) that became a normative requirement. The one defect that slipped past review, D-1 (`Select.BLANK` is the wrong object), exposes a precise, encodeable gap in draft-time verification: we verify behavior CLAIMS about a framework API, but not the runtime IDENTITY of the symbol the spec names. One control candidate leans encode (symbol-identity probe); the duplicate-PR episode leans operator-process note, not flow control.**
>
> Companion: `05b-postmortem-qa.md` (qa-reviewer, validation/metrics deep-dive) — this document does not duplicate that analysis.

---

## 1. What worked

**Conclusion: the front-loaded phases (0 measurement, 2 cross-review) did the risk-retirement; implementation and validation were consequently uneventful — every phase closed in 1 iteration.**

- **Phase-0 measurement probe (C-13) paid twice.** The temp Pilot probe measured `#patch_pane_variant` at 35×3 @80×24 / 46×6 @120×30 *before* requirements were written, turning geometry from a risk into a design input: the deficit (~5 rows @80) mapped to an already-shipped rung (batch-22 per-pane `overflow-y:auto`), and the design consequence was encoded as **LLR-035.2** (variant group composes ABOVE the execute row). At Phase 3, residual assumption **A-1** (closed-Select row cost) resolved by measurement — Label+Select = 4 rows with the Select's first row visible at scroll 0 — so the pre-planned sacrificial-Label contingency was **not needed**. Second consecutive batch where measuring beats estimating (batch-22's spike precedent).
- **Phase 2 was the star: 5 substantive findings pre-code, all folded body-first before the gate** (02-review.md, §6.4 log — 1 BLOCKER + 5 MAJOR + 9 MINOR, PROCEED ×3):
  - **F-4 (architect):** `set_options` RESETS the selection and fires the watcher → every repopulate emits `Changed(NULL)`+`Changed(active_id)`. Caught pre-code; the LLR-035.4 short-circuits became normative against exactly that pair. This is the **second save by the framework-behavior-verify rule** (batch-22 R-1 `Horizontal`-doesn't-wrap was the first) — an **existing control demonstrably working**, not a new candidate.
  - **SEC-F2 (security):** switch-during-load race on the single unguarded `_pending_variant_id` slot → phantom-copy side-door. Became **NEW LLR-035.7 + TC-035.7**. Notably, Phase 0's intake had claimed "no security-reviewer trigger" — running the security pass anyway over that claim is what found it. The chosen mechanism (suppress-while-loading) had the smallest blast radius: load pipeline byte-untouched, modal path demonstrably unaffected.
  - **F-2/F-3 (architect):** an N==1 contradiction between LLR-035.3 and .5, and an unowned disabled/enabled transition trigger — both spec-consistency bugs that would have surfaced as implementation churn.
  - **qa-M1 (qa):** the **orchestrator's own** TC-fold-in reconciliation note was incomplete (TC-035.1/.6 authoring rows missing from 01b) — independent cross-review catching the coordinator's error is the review design working as intended.
- **Wholesale-reuse design (Option B) held end-to-end.** Zero new activation or persistence logic; all guards, the pending-stamp pipeline, and the save serialization reused unchanged. The census was concrete (pane regions are fixed grid cells → batch-22 geometry tests survive), and it held: 0 unexpected regressions, frozen set 0-diff.
- **Deviation due process worked under pressure.** Three implementation-surfaced deviations (D-1 sentinel, D-2 proj2 drive, D-3 compositor mapping) were flagged loudly in increment-1.md with Before/After records, independently re-verified (code-reviewer for D-1/D-2, validator for all three), and folded post-PASS as §6.5 amendments A-6.5-1/2/3 — body edited first, contract-unchanged in every case. No silent spec edits.
- **C-10/C-12 gate discipline held.** AT-035a drives OFF the default and its counterfactual RED was captured and bound to the reconciled node (silent-no-op mode, exactly what the gate exists to catch); AT-035b is a genuine output-then-consume chain (handler-written manifest, raw re-read, fresh-app consume with discriminating power since `a` sorts first); the pre-existing direct-consume test stayed guard-only.
- **Mid-batch base-move absorption was orderly.** Two ff-merges (c6f75aa→a4ab8ba→f5f8111) absorbed via stash/ff/pop with one docstring conflict resolved by merging both intents; RC-1 re-run; integration re-verified 138/138; frozen re-checked post-ff. The RC-1 protocol now has three mid-flight exercises across batches (17, 23×2) — battle-tested.

## 2. What didn't / friction

**Conclusion: one review-escape with a genuinely interesting failure mode (D-1), one operator-side coordination miss (duplicate PRs), and residual environment litter — nothing that cost an iteration, but D-1 is the lesson of the batch.**

- **D-1 — the `Select.BLANK` symbol-identity trap (review-escape, found only at implementation).** The failure mode is worth stating precisely because it evaded a review that was *actively verifying this exact API*: Phase-2 F-1 was a BLOCKER on an unflagged framework claim, and its resolution **read the textual 8.2.5 source** and cited `_select.py` line numbers for emission semantics (same-value no-emit, `set_options` reset, `InvalidSelectValueError`). Every behavioral claim was TRUE. Yet nobody checked that the NAME `Select.BLANK` denotes the blank sentinel — it exists (`hasattr` passes), but resolves to the inherited `Widget.BLANK` bool (`False`), which can never match a `NoSelection` value. A spec-conformant implementation would have shipped a dead filter. Verification of *claims about an API* and verification of *a symbol's binding* are different checks, and the flow currently only mandates the first. Severity multiplier: the identical latent bug already existed in **shipped** US-026 and AbDiff code (the chip → PRs #37/#38), i.e. this trap had passed two prior batches' reviews too.
- **Concurrent-agent episode: one chip, two agents, duplicate PRs.** The operator deployed 2 agents on the Select.NULL background chip; they produced PRs #37 and #38 sharing the same hunks (#38 added one unique AbDiff fix + test). Cost: an orchestrator de-conflict cycle (scratchpad clone, merge, residual-diff isolation, targeted suites 5+27 green), two base moves instead of one, and a side effect — **agent 2 left the primary repo checkout on `fix/select-null-blank-sentinel`** (flagged; operator to restore). Both PRs were individually well-formed (red-checked, surgical, frozen-clean); the duplication was the only flaw. This happened *outside* the dev-flow loop — the flow's job was absorption, which it did cleanly.
- **Minor: the orchestrator's own reconciliation output needed the cross-review to be trusted** (qa-M1). Not new friction — it is the reason Phase 2 reviews the orchestrator's reconciliation at all — but worth naming: self-produced bookkeeping is not exempt from review, and this batch proved why.

## 3. Scope drift — verified: NONE

**Conclusion: the batch shipped exactly US-028, nothing more.**

- Changed-file set = exactly the 5 files roadmapped in §6.6 (5/5, at cap) + state.json bookkeeping — verified by the validator (04-validation.md §6).
- All three deviations are **spec corrections**, not scope additions: D-1 rebinds a symbol (contract unchanged), D-2 amends a test drive, D-3 conditions an assert on a compositor fact. Each carries a "Deleted: none. New: none." record in §6.5.
- Adjacent temptations were correctly externalized, not absorbed: the pre-existing US-026 dead blank-filter was **chipped** (task_478df389 — subsequently resolved by the operator's PRs #37/#38, so the chip is now closed), and SEC-F1 (symlink dead-option parity hardening) went to **BACKLOG** as optional, explicitly NOT a US-028 requirement.
- Engine-frozen set: 0-diff, verified three times (Inc1, post-ff, validator re-run).

## 4. Metrics

**Conclusion: a textbook-clean run — every phase 1 iteration, cap held at the limit, zero regressions, zero frozen diffs.** (Depth analysis in 05b.)

| Metric | Value |
|---|---|
| Phases 0–4 iterations | 1 / 1 / 1 / 1 / 1 |
| Increments | 1 planned / 1 executed (contingency split unused) |
| File cap | 5 of ≤5 — at cap, exactly as roadmapped |
| Test ledger (batch delta) | 991 → 1002 (+11, −0), reconciled |
| Full non-slow suite (final base f5f8111) | **971 passed / 30 skipped / 3 xfailed / 0 FAILED** (448 s); pre-ff run 969/0-fail (467 s) |
| Engine-frozen set | 0 diffs (verified Inc1 + post-ff + validator) |
| Phase-2 findings | 1 BLOCKER + 5 MAJOR + 9 MINOR — all folded body-first pre-gate |
| Deviations (Phase 3) | 3 (D-1/D-2/D-3), all flagged loudly + independently re-verified → §6.5 A-6.5-1/2/3 |
| Counterfactual RED | Captured (AT-035a silent-no-op mode), bound to the reconciled node at Phase 4 |
| Code review | APPROVE-WITH-NITS (3 LOW: 2 folded, 1 observation) |
| V-5 reconciliation | 10 provisional ids → 11 real nodes, 1:1, 0 orphans |
| QC-3 catalog / reachability matrix | 7/7 rows covered / 0 gaps (both directions) |
| Mid-batch base moves absorbed | 2 (c6f75aa→a4ab8ba→f5f8111), 1 docstring conflict, RC-1 re-held |
| Verdict | **PASS** |

## 5. Root causes

**Conclusion: one specification-verification gap, one coordination gap; both have crisp mechanisms.**

- **D-1 root cause — verification target mismatch.** Draft-time verification (as practiced and as F-1 enforced it) validates *behavioral claims* about a framework API against source/docs. It never asks whether the spec's *dotted name* denotes the object the claims are about. Python's inheritance makes the trap silent: `hasattr(Select, "BLANK")` is True via an unrelated inherited attribute, so existence checks give false confidence, and reading `_select.py` for behavior never forces you to `repr()` the name. This is a **rule gap, not a rule misapplication** — F-1's verification was executed correctly per the rule's text and still could not have caught D-1. Supporting evidence that it's systemic rather than a one-off lapse: the identical binding error passed review in two earlier batches (shipped US-026 + AbDiff code).
- **Duplicate-PR root cause — no single-owner convention for chipped tasks.** The chip mechanism produces a self-contained prompt; nothing marks a chip as claimed once dispatched, and the second agent had no signal that PR #37 existed (or was in flight). Purely a dispatch-time coordination gap on the operator side of the boundary — the dev-flow artifacts and gates were never the failure surface, and the flow's absorption protocol (RC-1 re-run, stash/ff/pop, de-conflict) contained the cost.
- **qa-M1 root cause — self-produced bookkeeping treated as trusted input.** The orchestrator's Phase-1 reconciliation note went into 01b without an independent completeness pass; Phase 2's qa lens supplied exactly that pass. The existing review topology already covers this — no new mechanism needed, just the observation that it fired.

## 6. Control candidates — for operator decision at this gate

**Conclusion: 1 lean-encode, 1 lean-against (as a flow control; keep as process note), 1 watch-continue. Plus one existing control confirmed working (no action). Per the encode-approval protocol, nothing is encoded without your explicit approval.**

### CC-1 — Symbol-identity check (draft-time) — **lean: ENCODE**

- **Proposed rule (one bullet, framework-behavior-verify family):** when a spec/LLR names a framework CONSTANT or SENTINEL by dotted name, draft-time verification must confirm that symbol's **runtime identity/type** with a live probe (`repr()`/`type()` of the exact name against the pinned version) — behavioral-claim verification and existence (`hasattr`) checks do NOT satisfy this.
- **Why encode, not watch:** (a) the gap is demonstrated, not hypothesized — F-1's verification was done *correctly and thoroughly* (source read, lines cited) and still structurally could not catch D-1, so "apply the existing rule harder" is not a fix; (b) this is the **third** occurrence of the same trap (US-026 and AbDiff shipped it before batch-23 specified it), which is past the house 3-instance watch threshold on arrival; (c) cost is near-zero — one probe line per named sentinel, only when a spec names one.
- **Honest counterpoint:** one could read the existing draft-time-verification rule expansively ("verify the claim" includes "verify the name"). In practice nobody read it that way across three batches — a rule whose natural reading misses the case needs the case named.

### CC-2 — Single-owner chips — **lean: AGAINST encoding as a dev-flow control; record as operator-process note**

- **Assessment: this is an operator-process gap, not a flow gap.** The duplication occurred at dispatch time, outside any dev-flow phase or gate; the flow's own obligations (absorb base moves, RC-1 re-run, de-conflict audit) were met cleanly. A dev-flow control cannot govern how many agents the operator points at a chip.
- **Proposed process note instead (operator-side, no encoding):** one chip = one agent; before dispatching a chip, check for an open PR / in-flight session on the same chip; on completion, verify the agent restored the primary checkout. If a second data point occurs, revisit as a chip-metadata convention (e.g. claimed-by marker in the chip lifecycle) rather than a dev-flow gate.
- **One flow-adjacent residue worth a checklist line, not a control:** "agent left primary checkout on a PR branch" is now a known post-episode hazard — cheap to add to the close checklist as a verify item if you want it (operator call).

### CC-3 — Batch-22 "overclaim" watch-pattern (assertion ≤ evidence) — **lean: WATCH continues; no 3rd instance this batch**

- **Verified: Inc1's claims were honest.** The validator independently audited every LLR threshold against the *actual asserts* (04-validation.md §2) and found them genuinely encoded; the two places where evidence was weaker than the strongest reading (TC-035.4 behavioral no-load proof instead of a worker count; TC-035.5 observation-only interaction leg) were **pre-declared** in the artifacts, not discovered — the opposite of overclaim. Counterfactual RED was real and re-verified. Pattern count stays at 2; keep watching.

### Existing control — framework-behavior-verify: **2nd save, WORKING, no action**

F-4 (`set_options` resets selection) is a batch-22-R1-class catch by the same rule, pre-code. Recorded here so the control lineage credits it; nothing to encode or change. (Note the complementarity: this rule catches wrong *behavior* claims; CC-1 closes the wrong-*binding* case it structurally cannot.)

## 7. Items proposed for next batch

**Conclusion: #8 is fully closed — the feature queue advances to #12; carries are small and pre-logged.**

1. **#12 — before/after report + entropy viewer + reconcile** (P1, the remaining queued feature per BACKLOG sequence). Full `/dev-flow`; likely needs a Phase-0 scope-first decomposition like #8's (batch-21 precedent — it is a 3-part bundle).
2. **BACKLOG carries (logged, not scheduled):** SEC-F1 symlink dead-dropdown-option parity hardening (optional, pre-existing in the modal too); batch-22 SVG snapshot baseline batch — the two `patch-comfortable-*` cells now ALSO carry the variant-row tree change and stay xfail-until-baseline; regenerate only in the canonical CI env.
3. **Immediate housekeeping (this batch's close, not next batch):** Phase 6 docs + PR + merge + `/dev-flow-sync` to the vault + close snapshot; **operator restores the primary repo checkout** off `fix/select-null-blank-sentinel` (left by agent 2 — flagged in state.json, untouched by the flow).
4. **Chip status:** task_478df389 (US-026 dead blank-filter) is RESOLVED via PRs #37/#38 — no carry.
5. **If CC-1 is approved:** encode the symbol-identity bullet in the global dev-flow command file via the AskUserQuestion approval path (encode-approval protocol; user-directed edit).

---

*Merged view: see `05b-postmortem-qa.md` for the validation/metrics deep-dive (qa-reviewer). Verdicts and §6.5 amendment records cross-checked against 01-requirements.md, 02-review.md, 03-increments/increment-1.md, 04-validation.md, and state.json decisions_log — no fact above is uncited in those artifacts.*


> **Orchestrator merge note (2026-07-02):** MAJOR count normalized to 5 (F-2, F-3, F-4, SEC-F2, qa-M1) per the Phase-5 qa audit — 02-review.md's header understated its own register; corrected there too. The qa deep-dive lives in 05b-postmortem-qa.md (scorecard: 21 findings, 71% caught-P2, 83% excluding execute-to-discover deviations; sharpest fix = the post-fold SWEEP-BACK rule, folded into control candidate CC-1's package below/above).

---

## Decision-outcome addendum (2026-07-02, post-gate sweep-back — C-15 applied to our own artifact)

The Phase-5 gate decisions, recorded here per the C-15 sweep-back discipline (the docs-writer cross-read caught this artifact still presenting CC-1 as pending):

- **CC-1 → APPROVED and ENCODED as C-15 (symbol-identity + sweep-back)** in `~/.claude/commands/dev-flow.md` (Phase-1 draft-time-verification family, before C-13), operator-directed via AskUserQuestion (encode-approval protocol satisfied).
- **CC-2 → operator chose the optional checklist add:** repo-hygiene line (primary checkout on `main`, no stray agent branches; list, don't switch) added to `~/.claude/commands/dev-flow-sync.md` step 3.
- **CC-3 → watch continues** at 2 instances; no action.
- Note: the "sweep-back" companion rule referenced in the orchestrator merge note lives in the encoded C-15(b) wording in the global command file, not in this artifact's CC-1 text.
