# 05 — Post-mortem — 2026-07-02-batch-24

> **BLUF: PASS with zero P4 gaps, and the strongest evidence chain a batch has produced — 2 of the 3 RED captures were live shipped bugs failing verbatim pre-fix. The batch's defining event was Phase 2 finding 2 real BLOCKERS (the no-MAC wipe, the stale-provenance report) that the Phase-1 probe ledger missed; both became normative requirements and shipped. The defining stress test was the I4 session-limit interruption, absorbed at a clean RED checkpoint with zero rework. Two control candidates recommended for ENCODE (writer-census probe rule, state-lifetime provenance question); operator decides at the gate.**
>
> Batch `2026-07-02-batch-24` · feature #12 slice (a)+(c) — US-032/033/034; entropy (b) deferred whole · branch `claude/batch-24-feat12` @ base `origin/main 9d2123c` · Author: architect (Phase 5). Companion scorecard: `05b-postmortem-qa.md` (qa, concurrent).

---

## 1. What worked

**Phase-2 cross-review earned its cost — twice.** Two BLOCKERS, both real, both with fully specified fixes at finding time (02-review.md §1):
- **B-1 (architect):** `update_mac_view` wipes `_validation_issues` + early-returns on every no-MAC session (`app.py:7160-7186`) — US-032/033's MAC-less AT fixtures could never observe their outcomes, AND the product itself was broken there. Operator chose **fix-the-wipe** → NEW LLR-037.4, a shipped-product fix beyond the batch's original slice, routed through the §6.5 amendment channel (AM-1), not smuggled.
- **B-2 (security):** stale/cross-project `last_summary` → false-provenance report. Every then-specced AT would have passed green over the hole. Fix = `source_image_path` stamp + refusal class 4 + AT-038d (AM-2). Found because the **security-review-every-write-surface routing** put a real security pass on US-034's new write surface.

**RED-first counterfactuals at full strength.** AT-036a and AT-037a were **live bugs on the shipped tree** — captured verbatim pre-fix (`Rendered issue rows: []`, increment-1.md §4a; non-red duplicate rows, increment-2.md §4a), then flipped green by the implementation. AT-038a's RED = trigger-absent (increment-4.md §0). Reviewers independently verified all three captures credible (lazy imports made pre-fix collection possible — a deliberate authoring property, now proven twice).

**The one-iteration fold.** All 18 Phase-2 findings (2 BLOCKER + 4 MAJOR + 12 minor) folded body-first in a single Phase-1 iteration: 18-row §6.4 reconciliation table, 4 §6.5 amendments (AM-1..3 at the fold, AM-4 at I5), C-15 sweep-back finding + fixing 1 residual stale reference, 0 `should`-as-modal. The amendment machinery absorbed two blockers without artifact churn or silent edits.

**The interruption protocol held on first live contact.** I4 died mid-run on an account session limit. The tree was a *coherent partial* — and the current 5-fail state WAS the specced trigger-absent RED, so the checkpoint doubled as the AT-038a counterfactual evidence (zero evidence work wasted). The resume agent **re-verified on-disk state before extending**, found MORE done than the orchestrator's briefing credited (Agent A had landed the binding, the B-2 handler pass, and the offer notify), did NOT regenerate any of it, completed exactly the 4 missing pieces, and credited the split in increment-4.md's authorship note. The cross-agent seam was then independently reviewed clean (no mismatch/phantom/dead params).

**The I3 golden double-proof.** The byte-identical regression golden was captured pre-edit with a self-checking exec-compare, then **independently re-derived by the code-reviewer from a detached worktree @origin/main** — 2437B md / 2386B html byte-match. The golden then survived the I4 `_strip_ctl` factoring untouched, exactly as designed (default path never reaches the new helpers).

**Per-increment independent review + orchestrator gates.** 4 reviews, 0 HIGH / 0 MED / 10 LOW, every LOW dispositioned (fold, note, carry, or BACKLOG — 04-validation.md §5.2). The I2 agent caught a citation error in its own gate instructions (`:153` vs the real `:80`) and fixed the one real occurrence instead of blindly obeying — fail-loud working as intended.

**Architecture discipline.** Composer = NEW `s19_app/tui/services/before_after_service.py` (no Textual import, no logging, never raises, never writes on refusal); generator changes = default-off kwargs gated by the byte-identical golden; frozen set 0-diff at every gate; `app.py` got only orchestration (trigger, map build, reorder).

## 2. What didn't / friction

1. **P-10 probe depth (the B-1 root).** The Phase-1 probe verified `update_a2l_view` (the function the spec edits) but never read `update_mac_view`'s body (the function it calls, whose side effect — the wipe — the story's observable depends on). The C-15 blind spot ONE FUNCTION DEEPER. Cost: forced iterate, I1 restructured to 4 files carrying the fix, I1→I2 became STRICT. Caught at Phase 2, not Phase 3 — the net held, but one layer later than designed.
2. **Session-limit interruption mid-I4** (external). Absorbed cleanly, but real: orchestration overhead, a resume briefing that UNDER-credited the done state (the resume agent's tree verification is what prevented redo/clobber), and a benign key-bound-to-missing-action window on the checkpoint tree.
3. **Windows platform artifacts in test authoring (I3).** 2 first-run failures, both in test asserts, not product code: golden compared LF while `write_text` emits CRLF on Windows; `str(Path(...))` backslash rendering. Fixed with the `os.linesep` expansion + field-derived asserts. Recurring class on this machine (see the batch-08/09 encoding memory) — cheap to pre-empt in test-authoring guidance, not control-worthy.
4. **Roadmap staleness at I4.** §6.6 said 4 files; the I3 gate addendum instructed a 5th (`diff_report_service.py` `_strip_ctl`). Handled correctly — flagged loudly in §2 of the packet, within the ≤5 cap — but gate addenda that add work should ideally touch the roadmap row too.

## 3. Scope drift — verified NONE

- The slice shipped exactly as locked at the DoR gate: US-032 + US-033 + US-034; entropy trio (US-035/036/037) deferred whole, untouched.
- Two scope ADDITIONS occurred, both operator-decided at gates through the formal channel, neither drift: **LLR-037.4** (B-1 option (a), AM-1 — a shipped-product fix the batch's ATs required to be observable) and **B-2 provenance** (AM-2). Both carry Before/After records.
- I4's 5th file was gate-addendum-instructed and flagged; ≤5 cap held ×5 (I1: 4, I2: 5, I3: 5, I4: 5, I5: doc-only).
- No frozen-set edit anywhere (0-diff verified at every gate + Phase 4 direct check). No unapproved feature, no adjacent "improvement", no silent requirement edit (§6.5 complete per 04-validation §5.1).

## 4. Metrics

| Metric | Value |
|---|---|
| Iterations per phase | 0: 1 · **1: 2** (the forced 18-finding fold) · 2: 1 · 3: 1 · 4: 1 |
| Increments / file cap | 5/5 planned; ≤5-file cap held ×5 |
| Test ledger | 1004 → **1037** (+33 / −0); net-0 rewrites: 1 in-place update + 3 no-op monkeypatches surviving unchanged (census held) |
| Full suite at I4 gate | **1004 passed / 0 failed** (no code changed after; Phase 4 re-ran targeted 26+45+1 green) |
| Frozen set | 0-diff at every increment gate + Phase-4 direct check |
| Phase-2 findings | 18 (2 BLOCKER, 4 MAJOR, 12 minor) — all folded in ONE iteration; ~30 citations re-verified |
| RED-first counterfactuals | 3 (AT-036a live bug · AT-037a live bug · AT-038a trigger-absent 5-fail) |
| Code reviews | 4 independent · **0 HIGH / 0 MED / 10 LOW** · all dispositioned |
| Deviations record | AM-1..AM-4 + 4 D-notes + I4 split-credit — all recorded, Phase-4 verified |
| Traceability | 24 provisional ids → 33 real nodes, 0 orphans; all 12 LLR thresholds read-in-assert, none vacuous |
| Verdict | **PASS**, zero P4 gaps; 1 soft cell honestly classified (project.json by-construction) |
| Interruptions | 1 (I4 session limit) — absorbed at a clean RED checkpoint, 0 rework, 0 clobber |

## 5. Root causes

- **B-1 →** probe-scope rule gap: C-15 probes verify the claim *at the function the spec edits*; nothing forced enumerating the OTHER writers of the state the story consumes (`_validation_issues`). A writer-census grep (`_validation_issues\s*=`) would have surfaced the wipe sites mechanically at Phase 1. → Candidate 1.
- **B-2 →** spec-template gap: the requirement modeled the happy temporal path (apply → save → report). No template question asks, for state captured earlier by ANOTHER flow: who wrote it, what invalidates it, how does the consumer prove it is still about the same subject? Security's write-surface routing caught it this time; a consume-only story would have no such pass. → Candidate 2.
- **Interruption →** external cause (account limit); zero-rework outcome was produced by two specific behaviors worth keeping: checkpoint-at-clean-RED and resume-verifies-tree-before-extending. → Candidate 3.
- **I3 platform failures →** test-authoring blind spot (Windows byte/path semantics), self-caught in-increment. Guidance note, not a control.

## 6. Control candidates (operator decides at gate)

| # | Candidate | Recommendation | Rationale |
|---|---|---|---|
| 1 | **C-15.1 writer-census probe rule**: when a draft-time probe establishes a data-flow claim over app state a story consumes ("X is installed/retained at render time"), the probe MUST include a writer census — grep every assignment/mutation site of that state and verify none intervenes on the active path between producer and the claimed read point. | **ENCODE — with this wording, not the "terminal writer" wording.** | Honest counterfactual check: "trace to the TERMINAL writer" via call-graph reading is "read more code" restated — unbounded and judgment-dependent, and P-10's author could plausibly have stopped at the caller again. The **grep form is mechanical and would have fired**: `rg "_validation_issues\s*="` lists the two wipe sites in `update_mac_view`, forcing the body read at Phase 1. Bounded cost: scoped to state variables a requirement consumes (map sources, caches), not every probe. |
| 2 | **State-lifetime provenance question** (from B-2): req-template line for any story consuming state captured earlier by another flow — state the lifetime/invalidation story and bind consumption to provenance (who wrote it · when does it die · what invalidates it · how does the consumer verify same-subject). | **ENCODE** (QC-3-style template question). | Genuine class, not an instance: extends the C-12 output-then-consume family from the *test* layer to the *spec* layer. One template line; the reliable net for consume-only stories that get no security write-surface pass. B-2 shows the failure shape is silent (all specced ATs green over the hole). |
| 3 | **Interruption protocol paragraph**: resume agent MUST re-verify on-disk state before extending (never regenerate verified-done work; credit the split); prefer checkpoints where the failing tests ARE the specced RED. | **ENCODE** (short paragraph in dev-flow.md). | Single instance, but recurrence is externally guaranteed (session limits) and both clauses are crisp and battle-proven: the briefing under-credited the tree and only the re-verify prevented redo/clobber; the RED-checkpoint clause turned dead time into the AT-038a evidence. Cost ≈ 3 lines. |
| 4 | **Golden double-proof**: reviewer independently re-derives byte-identical baselines from a clean base checkout. | **ENCODE, narrowly scoped** — only when a batch MINTS a new golden/byte-identical baseline (rare event); not a blanket byte-claim rule. | The self-checking capture already guards transcription; the re-derivation adds independent-source proof for an artifact that will gate every future batch. Worth it at mint time; wasteful as a routine. If the operator prefers, WATCH is defensible — but the trigger is rare enough that encoding costs nothing. |
| 5 | **Batch-22 overclaim watch (at 2)** | **Stays at 2 — no 3rd instance. Confirmed.** | Checked all 4 increment packets against their reviews: no reviewer flagged a claim the code didn't back. The batch actually produced the OPPOSITE twice: I4 §0 corrected its own wrong read of the ctl-leak (both-formats → html-only, "verified, not assumed") before documenting, and the I4 briefing UNDER-credited Agent A. I1's D-note-1 docstring was reviewer-audited "honest". Watch continues. |

**Existing controls that scored saves this batch:** C-15 (13-probe ledger produced the real P-10 finding; sweep-back at the fold caught 1 residual stale ref — and B-1 precisely maps its boundary, feeding candidate 1) · security-review-every-write-surface routing (found B-2) · QC-2/C-10/C-12 AT-authoring family (Q-M1 surfaced-path chain + Q-M2 pinned literal caught at review; GUARD-class marks kept AT-038b/c/d non-vacuous) · the two-layer model itself (the batch's stories WERE divergence bugs only the black-box layer could observe — both live REDs are its trophies) · RC-1 (PASS at open, merge-base == tip) · C-14-style census discipline (R-1 executed sweep; 3 monkeypatches survived exactly as predicted; snapshot matrix swept in via A-m5) · ≤5-file cap + fail-loud (I4's instructed 5th file flagged, not hidden).

## 7. Next-batch items

1. **#12(b) entropy trio (US-035/036/037)** — the deferred slice, own spike batch (greenfield model + surface + geometry; C-13 measurement mandatory if it takes a pane; computation TUI-side, frozen set off-limits). Queue head for #12 completion.
2. **BACKLOG: I4-F1** orphan-md-on-html-refusal hygiene (theoretical branch, optional unlink).
3. **Hygiene sweep candidate:** 3 pre-existing ruff F401s (`change_service.py:38`, `tests/test_diff_report_service.py:67`, `tests/test_tui_app.py:1599`) — flagged I2/I3, untouched per the surgical rule.
4. **Optional LOW:** widen `_strip_ctl` to the C1 range (0x80-0x9F); currently C0 + 0x7F only.
5. **Recorded limitation:** AT-037b single-shot inertness (spec-accepted).
6. **Re-derive trigger (F3):** if a future batch adds `last_summary` invalidation to the real project-switch path, re-derive AT-038d (its "open project B" step is state-level by ratified idiom).
7. **Test-authoring guidance note (no control):** byte-exact asserts on Windows must account for `write_text` newline translation and `Path` rendering — pre-empt the I3 first-run failure class.

---

## Architect evidence checklist (Phase-5 artifact)

- [✓] Constraints stated explicitly — batch facts table §4 sourced from state.json `iterations_per_phase` + increment ledger deltas + 04-validation §6.
- [✓] ≥2 alternatives considered — each control candidate assessed encode/watch/against with the counterfactual argued (§6; candidate 1 explicitly rejects the as-proposed wording for a sharper form).
- [✓] Recommendation tied to constraints — encode recommendations bounded by cost (grep-mechanical, template-line, 3-line paragraph, rare-trigger).
- [✓] Risks listed — §2 friction items + §5 root causes; candidate-1 unbounded-cost risk named and scoped.
- [✓] Cost/latency estimated where relevant — N/A (process post-mortem; no runtime surface).
- [✓] Diagram — N/A with reason: no new flow; narrative timeline is linear (5 increments, 1 interruption).
- [✓] What would change the recommendation — candidate 4 flips to WATCH if the operator weighs reviewer time over mint-time assurance; candidate 1 flips to WATCH if a 2nd instance never appears AND the grep form proves noisy in practice.
- [✓] Two-layer requirements — verified discharged batch-wide (04-validation §3: 3 GATE ATs + GUARD marks honored; both chains bound, 0 orphans).
