# 05b — Post-mortem (QA / validation lens) — 2026-07-06-batch-26

> Feature #12(b) — entropy / data-classification viewer. US-035 (headless service) · US-037 (report section) · US-036 (viewer modal).
> Phase 5 (Post-mortem), `/dev-flow`. Author: `qa-reviewer`. Companion to `05-postmortem.md` (architect / engineering lens — NOT edited here).
> Sources cited inline: `04-validation.md`, `01b-validation-strategy.md`, `02-review.md`, `03-increments/increment-00{1,2,3,3b}.md`, `PLAN.md`.

---

## 1. BLUF — did the validation model earn its keep?

**Yes, decisively — the two-layer model caught a real ship-blocking defect that the white-box layer alone would have passed green.** The headline is **AT-037a's LIVE RED** (`increment-002.md` §4a): with the report-emission wiring stubbed `if options.include_entropy and False:`, the C-12 disk re-read AT *failed at the shipped surface* (`"### Entropy" in variant_block` → `AssertionError`, `1 failed in 0.66s`) **while the capture-plumbing precondition asserts still passed**. That is a genuine counterfactual — the feature discriminated by the test, not the fixture — not a by-construction ImportError. Had the gate been a direct `_entropy_lines()` call (Layer A only), a stubbed emission would have shipped a report with no entropy section and the white-box builder test would have stayed green. **This is exactly the seam the C-12 "output-then-consume" control exists to close, and it fired.**

Secondary wins: the **C-10 non-vacuity discipline held end-to-end** — every gate AT asserts an *exact* value (H = 0.0 / 1.0 / 2.0 / 5.0 / 8.0; exact bands; exact addresses 0x3000/0x4000; caps ≤512), never "non-empty" — enabled by the load-bearing testability fact that entropy is a pure deterministic arithmetic transform (`01b` §0, eng-rule 5). **TC-036.4** pinned the `e`-binding registration white-box (the silent-unbind class that shipped in PRs #37/#38), and **TC-036.5b** (F1 fold) is genuinely mutation-verified for the either-cap truncation semantics.

**Coverage integrity is clean:** AT/TC → real-node reconciliation complete, 0 orphans, dual traceability closed, bidirectional surface-reachability matrix complete for all three stories (`04-validation.md` §3–§4). **The only red in the entire suite** is the 19-cell `test_tc016s_density_layout_snapshot` footer drift — a known, non-gating, expected artifact with a defined post-merge regen path, **not a validation failure**.

**QA verdict: the Phase-4 PASS is sound.** One weak-but-acceptable counterfactual (US-036 by-construction, mitigated by two positive pins) and two carry-forward QA items (below) are the only asterisks.

---

## 2. Two-layer model in practice (Layer B black-box + Layer A white-box)

| Mechanism | What it was meant to catch | Did it? | Evidence |
|---|---|---|---|
| **C-12 AT-037a** (disk re-read, output-then-consume) | A report where the entropy code exists but never reaches the written file (stubbed/mis-wired emission) | **YES — live RED** | `increment-002.md` §4a: emission stubbed `and False` → precondition PASS, `"### Entropy" in variant_block` FAIL (`1 failed in 0.66s`); restored → PASS |
| **C-10 exact-H asserts** (anti-vacuity) | An estimator that "returns something" but computes the wrong H, or a band mis-classification | **YES — non-vacuous by design** | AT-035a/b/d/e + TC-035.6 assert H==0.0/1.0/2.0/5.0/8.0 exactly (`abs<1e-9`), not `< band`; `01b` §0 deterministic-arithmetic fact |
| **TC-036.4** (white-box binding guard) | The silent-unbind regression class (`e` key defined but not registered → modal unreachable), which shipped in PRs #37/#38 | **YES — closes M3 review gap** | `04-validation.md` §3 `test_tc036_4_e_binding_registered`; `02-review.md` M3 fold |
| **TC-036.5b** (either-cap truncation, F1 fold) | A truncation indicator that only fires when BOTH caps blow (the `max()` bug) → silent truncation | **YES — mutation-verified** | `increment-003.md` F1: `max→min`, unequal-cap monkeypatch test; "production reverted to `max()` → test FAILS; `min()` → PASSES" |

**Where Layer B carried the story vs Layer A being a guard:** the model was applied with discipline — the report gate is the on-disk file re-read (AT-037a), and `_entropy_lines()` direct calls (TC-037.1) are explicitly labelled GUARD-not-gate (`01b` §3, QR-3). Likewise US-036's gate is the Pilot `e`-key modal open (AT-036a), and `_strip_text()` reads are diagnostics only. **No story's "done" rested on a white-box-only observation** (`04-validation.md` §2 closing line). This is the black-box behavioral-acceptance principle working as intended.

**Layer A did its job as regression scaffolding, not as a stand-in for behavior:** service purity (TC-035.7, 0 `import textual`), constants pinned (TC-035.5), estimator reference values (TC-035.6), `sev-*`-not-reused (TC-036.1). These are the "how" guards; the "what" was always observed through the shipped surface.

---

## 3. QR-1..8 testability-risk disposition (Phase-1 risks → how each actually resolved)

| QR | Risk (Phase 1) | Needed real mitigation? | Resolution in practice |
|---|---|---|---|
| **QR-1** | exact-H needs purpose-built fixtures, not `large_s19` (random-fill → non-exact H) | **Decision held, no drift** | `01b` §5 sanctioned tiny in-memory `mem_map` dict literals; every exact-H AT used them (`increment-001.md` §4). `large_s19` used ONLY for the count/cap stress guards, never for exact H. |
| **QR-2** | H==7.2 not integer-constructible from a 256-histogram; "nearest constructible" blurs the cutoff side | **YES — real mitigation (M5 fold)** | TC-035.2 pins the cutoff side by **direct float injection** at literal `7.1999 / 7.2 / 7.2001` (and 1.0 / 5.0), decoupled from histogram construction (`01b` QR-2, §4 note; `increment-001.md` test map). Histogram-derived cases kept as complementary coverage. |
| **QR-3** | US-037 C-12 masking — the gate could collapse into a direct `_entropy_lines()` call | **YES — structural discipline** | Gate re-reads the handler-written file at `target` path (never glob, never direct call). TC-037.1 is GUARD-only. The live RED (§1) proves the gate stayed a gate. |
| **QR-4** | `capture_mem_map` must be on, AND a fixture that populates `mem_map` off-chain must not false-pass | **YES — strengthened (M4 fold)** | AT-037a drives real variant execution with `capture_mem_maps=True` and asserts `result.mem_map` non-empty **as a precondition BEFORE report gen** (`increment-002.md` §4a: `[0x3000]==0x00`, `[0x40FF]==255` passed pre-fix). Proves the plumbing, not just the formatter. |
| **QR-5** | Pilot geometry/timing flake (missing `pause()`) | Held — no flake observed | Every modal AT pauses after open + after each interaction (`01b` QR-5). Two full suite runs produced an identical failure set (§5) → no observed Pilot nondeterminism. |
| **QR-6** | entropy colour map must NOT reuse `sev-*` (frozen `color_policy.py` is severity-semantic) | Held — clean | TC-036.1 grep-guards no `sev-*` / `css_class_for_severity` in the band path; `ENTROPY_BAND_COLOUR` is its own map (`increment-003.md` §1; `04-validation.md` §8 cites `screens.py:662`). |
| **QR-7** | engine-frozen guard must stay green | Held — 0 diff | `git diff --name-only origin/main` over the 7 frozen paths → empty; `test_engine_unchanged.py` + `test_tui_directionb.py::test_tc031_*` = 101 passed (`04-validation.md` §5). All new code outside the frozen set. |
| **QR-8** | each pre-fix counterfactual must be captured before its increment merges | **YES — captured, mixed strength** | AT-035* ImportError-by-construction (NEW module); **AT-037a captured LIVE RED** (strong); AT-036a RED-by-construction (`e` unbound) + two positive pins. See §4 grading. |

**Net:** QR-2, QR-3, QR-4, QR-8 needed genuine mitigation and got it (three of them via the Phase-2 major folds M4/M5 + the C-12 structural rule). QR-1, QR-5, QR-6, QR-7 were held decisions that did not drift.

---

## 4. Counterfactual quality — graded per story

| Story | Pre-fix RED | Grade | Rationale |
|---|---|---|---|
| **US-035** (service) | `ImportError` — module absent on pre-fix tree | **Acceptable (weak-but-fine)** | The symbol genuinely does not exist pre-fix, so the AT cannot import → demonstrably fails today. For a NEW module this is the correct and unavoidable counterfactual; it is NOT a by-construction cop-out because the exact-H asserts (§2) make the *green* side non-vacuous. |
| **US-037** (report) | **AT-037a LIVE RED** — emission stubbed `and False`, precondition PASS then disk-section FAIL | **STRONG (best in batch)** | A real counterfactual on a real feature seam: the code path exists but is severed, and the test discriminates it at the shipped surface while the plumbing precondition still passes. This is the gold-standard shape (output-then-consume, live). |
| **US-036** (modal) | `e` unbound + `action_show_entropy`/`EntropyViewerScreen` absent → key press pushes nothing | **Acceptable (by-construction, mitigated)** | **The one weaker-than-ideal counterfactual.** A synthetic "strip the binding" RED run was *attempted* but hit an unrelated textual CSS-source-introspection error on a dynamically-defined `App` subclass and was not pursued (`increment-003.md` §5). Mitigated two ways: TC-036.4 positively pins the binding registration, and AT-036a positively pins the modal opens through the key. AT-036b's before≠after focus assert (==0x4000) further discriminates a "renders but jump is a no-op" bug. |

**Only weak spot: US-036.** The by-construction argument is sound (net-new code, `e` did nothing before, neither symbol existed), and the two positive pins + the AT-036b before/after discrimination are strong compensating evidence. But a *demonstrated* live RED (as AT-037a achieved) would have been stronger, and the attempt was abandoned for a tooling reason rather than a design one. **QA carry (§7):** find a Pilot-safe way to force the binding-absent RED for modal-through-key stories, so the strongest story-type in the batch (a user-facing surface) also carries the strongest counterfactual.

---

## 5. Coverage integrity + test-count ledger

**AT/TC → real-node reconciliation: COMPLETE, 0 orphans** (`04-validation.md` §3 "AT/TC reconciliation (V-5)"). Every provisional `AT-035*/037*/036*` and `TC-035.*/037.*/036.*` from `01b` §8 maps to a concrete `file::function` collected node (verified against `pytest -v`: 60 items collected & named). No orphan LLR (every functional-chain row has a passing node); no orphan test (every batch test binds to an LLR/AT per the increment maps). The two US-036 snapshot cells reconcile to the two xfail `test_tc036s_entropy_modal_snapshot[...]` params.

**Bidirectional surface-reachability: COMPLETE for all three stories** (`04-validation.md` §4). Every named INPUT dimension and every OUTPUT/deliverable is exercised/observed through the shipped surface, not only the service API: US-037's output observed on the on-disk FILE (not `_entropy_lines`); US-036's output on rendered widget cells (not `compose`); US-035's surface is its public call by design (library).

**Test-count ledger (reconciled against `PLAN.md` + increment packets):**

| Increment | Story | Δ tests | Running behavioral total | Source |
|---|---|---|---|---|
| Inc 1 | US-035 service | **+14** | base + 14 | `increment-001.md` §4 (AT-035a..e + TC-035.1..7 + frozen-shape + stress guard) |
| Inc 2 | US-037 report | **+8** | base + 22 | `increment-002.md` §2 (25→33 in `test_report_service.py`; AT-037a/b + TC-037.1×2/.2×2/.3/.4) |
| Inc 3 | US-036 modal core | **+13** | base + 35 | `increment-003.md` §4 (12 core) **+1** F1 either-cap fold (`test_tc036_5_truncation_fires_on_either_cap`) → 13 |
| Inc 3b | US-036 snapshots | **+2 xfail** | (non-gating) | `increment-003b.md` §1 (@80×24 / @120×30, xfail-until-baseline) |

**Full-suite reconciliation (`-m "not slow"`, authoritative local, reproduced twice):** **1048 passed · 19 failed (ALL snapshot-drift, non-gating) · 2 skipped · 5 xfailed** (`04-validation.md` §5). Batch modules alone: 60 passed. Frozen guards: 101 passed. Slow set: 21 passed. **Non-snapshot FAILED count = 0.** The 5 xfailed = the pre-existing patch/xfail convention set + the 2 new batch-26 entropy snapshot cells.

---

## 6. Known non-gating items + environment

**19-cell snapshot drift — NOT a validation failure.** The only red across the entire suite is `test_tc016s_density_layout_snapshot` (19 parametrized cells at 120x30 & 160x40). Cause: Inc-3 added the global `e`/`Entropy` footer binding + entropy styles, which re-renders every screen's footer vs the pre-feature batch-25 committed baselines. **Isolation proof** (`increment-003b.md` §4, re-confirmed by the identical 19-cell set across both full runs this phase): `git stash` of the feature code → 28 snapshot cells pass; feature present (with or without the Inc-3b test edits) → identical 19-cell drift. So the drift is the FEATURE footer, not the test scaffold. The snapshot job is `continue-on-error: true` (non-gating), and US-036's behavioral verdict is the Pilot ATs (all PASS). **Resolution:** post-merge canonical-CI regen via `snapshot-regen.yml` (`workflow_dispatch` → artifact, pinned `textual==8.2.8`), re-baseline the 19 drifted + 2 new entropy cells, then a follow-up drops the 2 entropy xfails → all green, 0 xfail. This is the batch-25 pattern (commit 35238ea). **Local regen was correctly NOT run** (forbidden per `snapshot-regen-env` — a local regen drifts unrelated cells and breaks the CI oracle).

**Python version split — handled correctly.** Local dev/regression ran on **Python 3.14.4** (textual 8.2.8 pinned, cwd-first `.pth` resolving THIS worktree). The **authoritative merge gate is the CI matrix on Python 3.11** (`04-validation.md` §7, `PLAN.md`). The local 3.14.4 run is explicitly labelled confirmatory, not authoritative — the phase did not overclaim a merge-gate pass from a non-canonical interpreter.

**Env-sensitive test handled portably (the one to watch).** AT-037b's byte-identical assert (`test_report_omits_entropy_when_disabled_byte_identical`) is CRLF/LF-robust **by construction**: the F2 fold matched the entropy block against the on-disk newline via `newline = "\r\n" if b"\r\n" in on_bytes else "\n"` rather than assuming `\n` (`increment-002.md` F2). This surfaced as a real correctness detail while authoring (the report writes with the platform newline — CRLF on Windows). So it passes on Windows (CRLF) locally and will pass on Linux CI (LF); `.gitattributes eol=lf` (batch-25) keeps committed baselines LF. **This is the model to copy** for any future on-disk-text assert — no other env sensitivity was observed.

---

## 7. QA lessons to carry to the next batch

1. **Snapshot cells that don't drift the whole footer.** A single new global footer binding (`e`/`Entropy`) drifted **19 of 28** committed baselines — every screen re-rendered its footer. The behavioral cost was zero (non-gating job + Pilot ATs), but it forces a full canonical-CI regen every time a global binding lands. **Carry:** when authoring snapshot cells, prefer cells whose region excludes the global footer where feasible, OR **accept the "feature-ships → regen-follows" pattern as the standard, pre-planned follow-up** for ANY new global binding (it is now the batch-22 → batch-25 → batch-26 lineage — treat it as routine, not a surprise, and budget the 2-PR regen sequence into the batch close).

2. **Force a live RED for modal-through-key stories too.** US-037 got the strongest counterfactual in the batch (AT-037a live RED) because a stub-the-wiring RED is trivial to produce for a headless handler. US-036 (the user-facing surface) fell back to by-construction because the "strip the binding" RED hit a textual CSS-source-introspection error on a dynamically-defined `App` subclass (`increment-003.md` §5). **Carry:** invest once in a Pilot-safe binding-absent harness (e.g. a module-level `App` subclass fixture whose CSS source introspects cleanly, or a `monkeypatch`-of-`BINDINGS` that Pilot tolerates) so surface stories can also demonstrate — not just argue-by-construction — their counterfactual.

3. **The exact-value + tiny-dict fixture discipline is reusable.** The whole batch's non-vacuity rests on entropy being a deterministic arithmetic transform, letting ATs assert exact H instead of "non-empty". Any future pure-transform feature (checksums, coverage metrics, diffs) should default to the same tiny-in-memory-literal + exact-value approach rather than reaching for `large_*` stress fixtures (which random-fill and cannot pin exact values). This is already sanctioned in `01b` §5 — worth promoting to a standing fixture-selection heuristic.

---

## 8. QA evidence checklist (Phase-5, this retrospective)

- [✓] **Two-layer disposition stated with evidence** — §2 table cites the live RED (`increment-002.md` §4a), the exact-H asserts, TC-036.4, TC-036.5b mutation-verification.
- [✓] **QR-1..8 each walked to a real resolution** — §3; QR-2/3/4/8 flagged as needing genuine mitigation (M4/M5 folds + C-12 rule), QR-1/5/6/7 as held decisions.
- [✓] **Counterfactual graded per story, weak spot named** — §4: US-035 acceptable, US-037 STRONG, US-036 acceptable-but-weakest (abandoned live-RED attempt named).
- [✓] **Coverage integrity confirmed** — §5: 0 orphans, dual traceability closed, bidirectional matrix complete (cites `04-validation.md` §3/§4).
- [✓] **Test-count ledger reconciled** — §5: Inc1 +14 / Inc2 +8 / Inc3 +13 (incl. F1 fold) / Inc3b +2 xfail; full suite 1048 pass / 19 non-gating fail / 5 xfail.
- [✓] **Non-gating items + env sensitivity addressed** — §6: 19-cell drift isolation-proven + regen path; 3.14 vs 3.11 gate; CRLF/LF portability of AT-037b handled by construction.
- [✓] **QA carries for next batch stated** — §7: footer-drift/regen pattern, modal live-RED harness, exact-value fixture heuristic.
- [✓] **No real PII / secrets** — this retrospective cites only synthetic byte patterns (`0x00`/`0xFF`/permutations) and public `examples/` data; no operator firmware referenced.
- [✓] **No fabricated results** — every count/quote traces to a cited increment packet or `04-validation.md` executed-output line; no re-run performed in this phase (retrospective over recorded evidence).
- [✓] **Companion boundary respected** — this file is `05b-postmortem-qa.md`; the engineering retrospective `05-postmortem.md` (architect) was not edited.

---

## 9. QA gate recommendation for Phase 5

**No QA-lens blocker.** The Phase-4 PASS is well-founded: the two-layer model caught a live ship-blocker (AT-037a), non-vacuity held, coverage reconciliation is complete with 0 orphans, and the single suite red is a documented non-gating snapshot drift with a defined post-merge regen. **Carry-forward (Phase 6, not gate blockers):** (a) the canonical-CI snapshot regen + dropping the 2 entropy xfails; (b) REQUIREMENTS.md `R-*` status promotion for HLR-035/037/036 + traceability rows; (c) the QA-process carries in §7 (modal live-RED harness; treat global-binding regen as a planned 2-PR follow-up).
