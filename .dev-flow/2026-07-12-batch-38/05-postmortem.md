# Post-mortem — s19_app — Batch 2026-07-12-batch-38

> Phase 5 artifact. Co-authors: `architect` + `qa-reviewer`. Language: English (`state.json.language = en`).
> Structured for cross-batch sweeping — section order preserved.

## 🔑 At a glance (read first)

- **Outcome:** **closed clean** — 5/5 increments APPROVE, 0 HIGH batch-wide, gate PASS (exit 0), no cross-increment regression, 0 engine-frozen diffs. One notable *process* defect (a freeze-file miss) was self-caught and fixed in-batch with **zero shipped-code impact**.
- **Top 3:** ① **What worked** — the proactive C-26 sibling-census sweeps stopped the batch-37 TC-319 escape class from recurring (undo/redo deliberately placed in a *new* row; per-entry button verified census-free). ② **What didn't** — Inc-2 landed AT-066a in a git-**frozen engine TEST file** and the per-increment guard didn't catch it (single-guard blind spot). ③ **Key root cause** — the per-increment frozen-file check ran only the SOURCE-freeze guard, not the TEST-file-freeze guard; the freeze discipline has two guards and increments ran one.
- **New control this batch:** **none encoded** — **C-CAND-A proposed** (per-increment frozen guard must run BOTH `test_engine_unchanged.py` AND `test_tc032`/`test_tc031`). Propose-not-encode; orchestrator will AskUserQuestion before encoding.
- **Open items → next batch:** ~9 — headline: **canonical-CI snapshot regen** for the 2 patch xfail cells (follow-up PR, #67/#69 pattern) + the Bookmarks screen.
- **Metrics:** iterations `8` (0:1 1:1 2:2 3:1 4:1 5:1 6:0) · findings `12 opened / 12 closed` (2 blocker + 4 major + 6 minor/low, all folded; 5 code-review LOW carried) · ledger `1358 → 1377` (+19).

> Enough to know the batch's health and what carries forward. Detail below only for the why.

---

## Detail (reference)

### What worked

- **C-26 sibling-census discipline held — the batch-37 TC-319 escape class did NOT recur.** This was the explicit watch-item after batch-37. It was exercised three times and paid off every time:
  - **Inc-3 (US-067):** the new info button was nested in a *new* `Horizontal(#patch_variant_select_row)` **inside** `#patch_variant_row`, so the `#patch_pane_variant` direct-child census (`test_tui_patch_variant.py:429`) stayed unchanged; reviewer independently re-verified 0 sibling breaks.
  - **Inc-4 (US-068a):** undo/redo controls were deliberately placed in a **new `#patch_history_controls` row** (NOT the 5-button `#patch_doc_controls` row that TC-319 pins) precisely to avoid census churn; `test_tui_patch_layout.py::tc319` + siblings swept green, new id referenced by 0 tests.
  - **Inc-5 (US-068b):** the new per-entry button joined `#patch_doc_entry_buttons`; a reverse-grep confirmed that id carries **no census** (tc319 pins the different `#patch_doc_controls` row), so adding a 4th button broke nothing.
- **Geometry was pilot-measured (C-23), not fr-math.** The US-067 help modal was measured at both target sizes — 80×24 (right=65, bottom=24 inclusive edge) and 120×30 (right=101, bottom=24) — and fit both. No repeat of the batch-36 F-01 fr-math 4.5×-off miss.
- **The A-01 data-loss guard was designed in at Phase 2, not caught late.** Security's M4 folded the file-backed disable-guard into the requirements before any code — both undo/redo (LLR-068a.4) and per-entry edit (LLR-068b.4) DISABLE when `document.source_path is not None`, with discriminating boundary nodes (TC-344/TC-345, AT-064c precedent). No late rework.
- **Clean gate with no cross-increment regression.** The +19 passed-delta reconciled **exactly** to the increment sum (Inc1 +2, Inc2 +5, Inc3 +3, Inc4 +4, Inc5 +5; AT-066a relocation net 0). Contrast batch-37, where the gate run caught a real first-run regression (test_tc319). Here the reverse-census work moved that detection **left** into the increments.
- **Autonomous run stayed inside its authorization.** The single operator gate (plan approval) was honored; all phase + increment gates self-approved against a named axis check; the Phase-2 iterate-to-refine folded 2 blockers + 4 majors without an operator stop (correct: no HIGH security, no story-kill). Security PASS (0 HIGH/MEDIUM).

### What didn't / friction

- **Inc-2 freeze-file miss (F-1, the notable process defect).** AT-066a was authored into `tests/test_tui_a2l.py`, which is a git-**frozen engine TEST file** (`_ENGINE_TEST_FILES`). Inc-2's own gate passed it because the per-increment frozen check ran only `test_engine_unchanged.py` (frozen **SOURCE**) — not `test_tc032_engine_test_files_unmodified_vs_main` (frozen **TEST** files). It surfaced at Inc-5's broader guard run and was fixed test-only: revert `test_tui_a2l.py` to `main` (byte-identical), relocate AT-066a to non-frozen `test_tui_a2l_issue_recolor.py` (reusing its helpers, which also resolved the Inc-2 F1 test-helper-dup LOW). **Zero shipped-code impact**; net test count unchanged; all three freeze guards green afterward.
- **Phase-2 cross-artifact contradiction cluster (F-2).** The Phase-1 §4 HLR/LLR spine was correct, but the intake / PLAN / 01b-qa satellite artifacts pointed implementers at the **wrong producer sink** (`a2l_service.enrich_tags_and_render` — returns tag rows, not issues — vs the correct `validation_service.build_validation_report`), diverged on the **issue-code spelling** (`EXCEEDS_32BIT` vs `OVER_32BIT`, a public contract), and **mis-targeted AT-068b** (clicked the existing `#patch_entry_edit_button`, an unsound counterfactual). All three were caught by the Phase-2 reconciliation and folded — the review worked as designed — but they are a pattern worth flagging (see Root causes).

### Scope drift (planned vs actual)

| Planned | Actual | Note |
|---------|--------|------|
| B-16..B-19 → 4 stories (US-065..068) | 5 stories (US-068 split → 068a/068b) | Split was **pre-flagged at Phase 0** (US-064 precedent), landed at Phase 1; C-21 confirmed the increment cut stands. **Not drift.** |
| ~4–6 increments | 5 increments | Within estimate. |
| Engine-frozen set untouched | 0 frozen SOURCE + 0 frozen TEST diffs vs `main` | Inc-2 transient freeze breach was reverted before batch close. |
| No new external-write surface | None added | Parse route is `json.loads` via ChangeService; no eval/pickle/exec/network. |

**Scope drift = NONE.** The US-068 split was anticipated and owned; every AT amendment (B2 re-point, M4 guards) folded into an existing increment (C-21) — no un-owned work appeared.

### Metrics (full)

| Metric | Value |
|--------|-------|
| Iterations per phase | `{0:1, 1:1, 2:2, 3:1, 4:1, 5:1, 6:0}` (sum 8) |
| Findings opened / closed | `12` / `12` (all Phase-2 findings folded before Phase 3) |
| Findings by severity (blocker/major/minor+low) | `2 / 4 / 6` |
| Where caught (Phase 2 / P3 gate / P4) | `12 / 1 (freeze-file miss, Inc-2→caught Inc-5) / 0` |
| Code-review LOW carried → batch-39 | `3` live (Inc-4 F1, Inc-4 F2, Inc-5 F1); Inc-2 F1 RESOLVED by relocation |
| Test ledger (base − D + A = post) | `1358 − 0 + 19 = 1377` passed (+19 reconciles increment sum exactly) |
| Files touched · increments (cap trips) | 5 source files (app.py, screens.py, screens_directionb.py, change_service.py, validation_service.py) + test files · 5 increments (0 cap trips — each ≤5 files) |
| Gate run | 1377 passed / 2 skipped / 20 deselected / 5 xfailed / 0 failed · exit 0 · 12:12 |
| Security | PASS — 0 HIGH / 0 MEDIUM |
| Engine-frozen | 0 SOURCE diffs + 0 TEST diffs vs `main` (tc031/tc032/engine_unchanged 6 passed) |
| ATs / TCs | 6 AT (each C-18 single-node, real RED counterfactual) · 14 TC (TC-332..345) |

**xfail reconciliation (5):** 3 pre-existing (batch-37 baseline — `test_tui_app:1784`, `test_tui_public_api:162`, `test_validation_engine:211`) + 2 batch-38 patch-cell snapshot drift (`patch-comfortable-80x24` / `120x30`, `xfail(strict=False)`, US-065 copy + US-067 button + US-068a/b rows all fold into the same two `patch` cells). **No batch-38 xfail masks a regression** — behavioral correctness is proven GREEN by AT-065a/067a/068a/068b through the live surface; the snapshot is a cosmetic pixel-oracle awaiting canonical baseline regen.

### Root causes (phases with ≥2 iterations)

Only **Phase 2** took ≥2 iterations (iterate-to-refine → re-approve). Two root causes are recorded — one for the Phase-2 iteration trigger (F-2), one for the notable in-batch process defect (F-1).

**F-1 — Inc-2 freeze-file miss (single-guard blind spot).**
- **Trigger:** Inc-2's gate passed AT-066a even though it sat in the frozen `tests/test_tui_a2l.py`; the breach only surfaced at Inc-5's broader guard run (`test_tc032` RED).
- **Root cause:** the frozen-file discipline has **two** guards — `test_engine_unchanged.py`/`tc031` (frozen **SOURCE**) and `test_tc032` (frozen **TEST files**) — but the per-increment frozen check ran only the SOURCE guard. A new test placed in a frozen *test* file is invisible to a SOURCE-only check. This is a **coverage gap in the guard invocation**, not a flaw in the guards themselves.
- **Why it was low-impact:** the miss was confined to test-file placement (zero shipped-code effect), self-caught within the same phase by the broader Inc-5 run, and fixed by reverting + relocating with net-zero test count. But had Inc-5 not run the broader guard, it would have reached the final PR-QA pass — later and more expensive.
- **Generalizes:** any increment that adds/edits a test could land in a frozen test file; the SOURCE-only guard cannot see it. The fix belongs at the guard-invocation layer for *every* increment.

**F-2 — Phase-2 cross-artifact contradiction cluster (M1 / B1 / B2).**
- **Trigger:** Phase 2 found 2 blockers (B1 issue-code divergence, B2 wrong AT target) + M1 (wrong producer sink) → iterate-to-refine.
- **Root cause:** Phase 1 is authored by **parallel authors** (architect owns §4 HLR/LLR; qa owns 01b; the intake/PLAN carry Phase-0 assumptions). The §4 spine was correct, but the satellite artifacts drifted on **shared contract details that no single author owned** — the exact issue-code string, the producer sink module, and the AT click target. When the correct answer lives in one author's artifact and the wrong copy lives in three others, implementers can be pointed at the wrong copy.
- **Why the process still worked:** Phase-2 triple review (architect + qa + security) is precisely the reconciliation step that catches this; all three defects folded autonomously with no re-derivation and no story-kill. The pattern — not a failure — is worth a lightweight ownership note so future multi-author Phase-1 batches converge the shared contract before Phase 2 rather than at it.

### Process / workflow findings

> About the dev-flow itself (phases, gates, templates, agents, controls).

- **F-1 → C-CAND-A (primary control candidate, propose-only):** the per-increment frozen-file guard must run **BOTH** `test_engine_unchanged.py` (frozen SOURCE) **AND** `test_tc032`/`test_tc031` (frozen TEST files). A single-guard check is structurally incomplete — it cannot detect a test authored into a frozen test file. Frame as **extending the existing engine-freeze discipline** (it does not replace a control; it closes the invocation gap that let F-1 through). Origin finding: F-1.
- **F-2 → C-CAND-B (secondary, propose-only):** a **Phase-1 shared-contract convergence step** — before the Phase-2 gate, reconcile the handful of cross-artifact contract details (public issue codes, producer sink module, AT click targets) across §4 / intake / PLAN / 01b so a single canonical value exists in all copies. Could be as light as a Phase-1-exit checklist item ("shared contract strings identical across all artifacts"). Marked **secondary**; the Phase-2 review already catches these, so this is an efficiency/left-shift improvement, not a correctness gap.
- **C-25 held under adversity:** the orchestrator-owned Phase-4 gate run's first background launch was orphaned at 52% by a session teardown (NOT a test failure); it was re-launched and completed clean. The C-25 "orchestrator owns the gate run" control absorbed the interruption with zero rework — the reconciliation consumed one complete run, not a stitched-together partial.
- **Autonomous decision-recording worked:** every un-asked decision is captured in `state.json.decisions_log` + the PLAN decision log + this post-mortem (see Decisions-summary below), satisfying the operator's "record all autonomous decisions" refinement.

### Product findings

> About the code/product under development.

- **Inc-4 F1 (LOW, carry):** the Checks panel (`last_check_result`) is not reset after an undo/redo, so it can show a stale check result until the next Validate — a secondary user-invoked surface, not a data-integrity issue.
- **Inc-4 F2 (LOW, carry):** undo/redo discoverability is below-fold; suggest a `ctrl+z`/`ctrl+y` keybinding for reachability parity with the pointer path.
- **Inc-5 F1 (LOW, informational, by-design):** a per-entry JSON edit can introduce a cross-entry address collision; per LLR-068b.3 the per-entry parse validates byte-validity only, and the collision is re-detected at the document Validate/Apply/Save gate (never silently written). Documented as a design decision, carried as a note.
- **L1 (LOW, batch-39 carry):** the new `#entry_json_text` TextArea inherits **uncapped native paste** (the 64 KiB cap is `OsClipboardInput`-only). No batch-38 action; folds into the standing native-paste-cap hygiene item alongside batch-37's `#patch_paste_text`.

### Control lineage

- **New control proposed this batch:** **C-CAND-A** (dual frozen-guard per increment) — origin F-1; **status: propose** (AskUserQuestion pending; do NOT encode here). Secondary **C-CAND-B** (Phase-1 shared-contract convergence) — origin F-2; status: propose.
- **Prior controls exercised / held:**
  - **C-26** (touched-symbol reverse census) — **stress-tested and held** across Inc-3/4/5; the batch-37 TC-319 escape class did not recur. Notably, Inc-4 *designed around* it by choosing a new row.
  - **C-23** (geometry pilot-measure, not fr-math) — held (US-067 modal fit both sizes on measured geometry).
  - **C-25** (orchestrator owns the Phase-4 gate run) — held under a mid-run session teardown; re-launched clean, zero rework.
  - **C-18** (one AT → exactly one on-disk node) — held; 6 ATs each reconciled to one distinct node with real counterfactuals (AT-066a/066b two functions same file; AT-068a/068b two functions same file — one node each at node granularity).
  - **C-16** (real-interaction ATs) — held (AT-067a/068a/068b use real `pilot.click`, scroll_end first for a genuine pointer path).
  - **C-17** (markup safety) — held (AT-066b hostile tag name: brackets verbatim, ANSI neutralized, 0 MarkupError).
  - **C-21** (re-cut on AT amend) — held (B2 re-point + M4 guards folded into existing Inc-4/Inc-5; no un-owned AT).
  - **C-22** (per-cell snapshot drift) — held (2 patch cells `xfail(strict=False)`, canonical-CI regen only, local regen forbidden).
  - **Near-miss:** the engine-freeze discipline (C-frozen guards) was the one that *let something through* — the SOURCE guard held but the TEST-file guard wasn't invoked per-increment. This is exactly the gap C-CAND-A closes.

### Open / deferred items → next batch (batch-39)

| Item | Type | Reason deferred | Trigger / owner |
|------|------|-----------------|-----------------|
| Canonical-CI snapshot regen for 2 patch xfail cells (`patch-comfortable-80x24`/`120x30`) | process/product | Local regen forbidden (C-22); canonical-CI only | Follow-up PR (like #67/#69) — orchestrator |
| Bookmarks screen (dead "coming soon" rail scaffold) | product | Own future batch (the one clear TUI gap) | batch-39 candidate |
| Native-paste 64 KiB cap on new TextAreas incl. `#entry_json_text` (+ batch-37 `#patch_paste_text`) | product | Standing hygiene; L1 batch-39 carry | batch-39 hygiene lane |
| Inc-4 F1 — Checks panel stale after undo/redo | product | LOW, secondary surface | batch-39 polish |
| Inc-4 F2 — undo/redo discoverability → `ctrl+z`/`ctrl+y` binding | product | LOW, below-fold reachability | batch-39 polish |
| Inc-5 F1 — per-entry cross-entry address collision note | product | LOW, by-design (caught at doc gate) | doc/comment only |
| S-F7 (raw `linkage_symbol` in report_service) | product | Standing backlog carry | batch-39 hygiene |
| Canonicalizer 3-copy consolidation · `object.__setattr__` test-helper · P-1/P-2/P-3 | product/hygiene | Standing carries | batch-39 hygiene |
| C-CAND-A / C-CAND-B encoding decision | process | Propose-not-encode; AskUserQuestion pending | operator @ batch-39 kickoff or on control-encode ask |

### Decisions-summary (every autonomous decision — mirror of `state.json.decisions_log`)

> The operator authorized autonomous execution with the single exception of plan approval. Every un-asked decision below is reconstructable from here + `state.json`.

- **Phase 0 (kickoff, recorded):** scope = all 4 P3 (B-16..B-19); run mode Autonomous + self-merge; RC-1 PASS @ `5a6c45b` (HEAD == origin/main == merge-base); US-068 flagged split-likely; B-17 routed TUI-side (engine freeze). — *This intake awaited the one operator gate.*
- **Phase 0 (operator gate — the ONE ask):** PLAN APPROVED ("approved."). Phase 0 closed; Phases 1–6 autonomous.
- **Phase 1 (autonomous approve):** 5 US (US-068 SPLIT → 068a/068b), 5 HLR (R-TUI-054..058), 14 LLR, 6 AT. All seams verified file:line; every LLR non-frozen; 0 should-as-modal. 4 feasibility flags carried to Phase 2 (wrong-sink risk, US-068b needs new id, issue-code reconcile, TC-id reconcile).
- **Phase 2 (autonomous iterate-to-refine):** triple review — security PASS (0 HIGH/MEDIUM). **B1** ratify `A2L_ADDRESS_EXCEEDS_32BIT`; **B2** re-point AT-068b to new `#patch_entry_edit_json_button` (single-entry seed, siblings byte-identical); **M1** correct sink to `validation_service.build_validation_report`; **M2** adopt TC-332..345; **M3** pin US-065 copy verbatim; **M4** A-01 file-backed disable-guard (LLR-068a.4/068b.4 + TC-344/345). 6 minors/lows folded. Increment cut unchanged (C-21). Before/After recorded in 01-requirements §6.5.
- **Phase 2 (autonomous re-approve):** all folds re-verified by orchestrator spot-check (grep: only `[Deleted]` retains old code; new button targeted; 0 frozen LLR targets; TC ids consistent both files). Reconciled US 5 / HLR 5 / LLR 16 / AT 6 / TC 14.
- **Phase 3 Inc-1 (US-065, autonomous approve):** 2 pinned copy edits; C-26 reverse census 0; 2 patch snapshot cells xfail; ledger 1365→1367 (+2); 0 HIGH/MEDIUM/LOW.
- **Phase 3 Inc-2 (US-066, autonomous approve):** WARNING producer in `validation_service` merged into BOTH report branches; boundary (0xFFFFFFFF no-warn / 0x100000000 warns) + C-17 hostile-input; ledger 1367→1372 (+5); 0 HIGH; 1 LOW (test-helper dup, later RESOLVED by the freeze relocation).
- **Phase 3 Inc-3 (US-067, autonomous approve):** variant info modal, real `pilot.click`, C-23 pilot-measured fits 80×24 + 120×30; C-26 sibling sweep clean (nested inside `#patch_variant_row`); ledger 1372→1375 (+3); 0 HIGH/MEDIUM/LOW.
- **Phase 3 Inc-4 (US-068a, autonomous approve):** bounded undo/redo (`_HISTORY_MAX=20`, deep-copy no-alias) + A-01 guard; placed in NEW `#patch_history_controls` row to avoid `#patch_doc_controls` census churn (C-26); reachability ruled OK (overflow-y scrollbar); ledger 1375→1379 (+4); 0 HIGH; **2 LOW carried** (F1 checks-panel-stale, F2 discoverability→ctrl+z/y).
- **Phase 3 Inc-5 (US-068b, autonomous approve) + FREEZE FIX:** per-entry JSON popup (distinctness proven: single-entry seed i≠0, siblings byte-identical) + A-01 guard; C-26 census on `#patch_doc_entry_buttons` clean; ledger 1379→1384 (+5); 0 HIGH; 1 LOW informational (cross-entry collision at doc gate, by-design). **Freeze fix:** reverted frozen `test_tui_a2l.py` to main + relocated AT-066a to non-frozen `test_tui_a2l_issue_recolor.py` (resolves Inc-2 F1 dup); 3 freeze guards green. **Phase 3 CLOSED: 5/5 APPROVE, 0 HIGH batch-wide.**
- **Phase 4 (autonomous approve, PASS all axes):** C-25 orchestrator-owned gate run (first background run orphaned at 52% by session teardown — not a test failure; re-launched clean). **1377 passed / 2 skipped / 20 deselected / 5 xfailed / 0 failed / exit 0.** +19 reconciles increment sum exactly; NO cross-increment regression; 6 ATs C-18 single-node with real counterfactuals; engine-frozen 0 diffs (source + test); 5 xfail = 3 pre-existing + 2 batch-38 snapshot drift, none masking a regression.
- **Phase 5 (this artifact):** post-mortem authored (architect + qa lenses). C-CAND-A/B proposed, **not encoded** — AskUserQuestion pending.

### Evidence checklist — architect + qa-reviewer

**Architect lens:**
- [✓] Constraints stated — run mode + engine-freeze + P3 scope in PLAN §Objective/§Batch-kickoff; RC-1 @ `5a6c45b`.
- [✓] Alternatives considered — Phase-2 M1 sink choice (`a2l_service` rejected vs `validation_service`); US-068 split vs monolith (split adopted).
- [✓] Recommendation tied to constraints — B-17 WARNING built in non-frozen `validation_service` to respect `_ENGINE_PATHS` freeze (01-requirements §4 / PLAN Feasibility).
- [✓] Risks listed — PLAN §Risks R-1..R-5 (engine freeze, undo/redo balloon, A-01 data-loss, C-26 census, snapshot drift, markup safety).
- [✓] Cost/latency — n/a for UI stories; history bounded `_HISTORY_MAX=20` (memory ceiling) recorded.
- [✓] Diagram — flow is small; reachability matrix (04-validation §3) substitutes.
- [✓] What would change the recommendation — if `validation/` freeze lifted, US-066 could move to `rules.py` (stated PLAN Feasibility).
- [✓] Two-layer requirements — every US has an AT-<n> id (black-box) + both traceability chains (US→AT→outcome behavioral; US→HLR→LLR→TC functional); reconciled 04-validation §1/§2.

**QA-reviewer lens:**
- [✓] Acceptance criteria observable-outcome form — 04-validation §1 (each AT states outcome + shipped surface + deliverable).
- [✓] Test cases have explicit Expected — 04-validation §2 (verbatim copy, WARNING code, byte-identical siblings, disabled iff source_path is not None).
- [✓] Edge cases (empty/boundary/invalid/error) — TC-335 boundary, TC-338/339 history bound + empty no-op, TC-343 malformed JSON no-mutation, AT-066b hostile.
- [✓] Regression checklist / frozen guard — 04-validation §5 (6 passed, 0 diffs); C-26 sweeps green every increment.
- [✓] Exit criteria stated — 04-validation gate-verdict axes (Coverage/Certainty/Evidence all PASS).
- [✓] No PII/secrets — synthetic A2L/change-set fixtures; hostile payloads inert; no I/O or network added.
- [✓] Test results only if actually run — reports the real C-25 gate run (1377) + Phase-4 targeted freeze run (6 passed) + node greps; nothing fabricated.
- [✓] Black-box through the SHIPPED surface + boundary/negative — 04-validation §1/§6 (issues panel / modal / entries table / rendered widget; AT-066a in-range negative control; AT-068a empty-history + file-backed boundary).
- [✓] Two-layer / bidirectional reachability — 04-validation §3 matrix (every input dim + deliverable through the handler, all 5 stories).
