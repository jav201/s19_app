# 05 — Post-mortem (engineering) — 2026-07-06-batch-26

> Feature #12(b) — entropy / data-classification viewer. US-035 (headless service) · US-037 (per-variant report section) · US-036 (viewer modal).
> Route: full `/dev-flow`. Executor: `architect` (this file) + `qa-reviewer` (`05b-postmortem-qa.md`, the validation retrospective — not edited here).
> Companion artifacts cited throughout: `PLAN.md`, `02-review.md`, `04-validation.md`, `03-increments/increment-00{1,2,3,3b}.md`, `01-requirements.md` §6.4.

---

## 0. BLUF

**Batch-26 was a clean single-pass batch: 0 iterations at every phase (0-4), 0 blockers, 0 engine-frozen edits, GATE PASS — and it CLOSES feature #12** (a+c shipped batch-24, b lands here). The single-pass record is not luck: it traces to the Phase-0 measurement spike (which converted the HIGH-geometry US-036 SPIKE into a first-pass-READY story with an exact 48/76-col budget, so no `/prototype` step and no fallback rung were needed) plus disciplined pre-lock folding in Phase 2 (11 findings folded before implementation started). The one friction item — 19 drifted snapshot baselines — is a *known, non-gating, expected* consequence of adding a global footer binding, with a defined post-merge canonical-CI regen path (the batch-25 pattern). **No new control is warranted; the review-time candidates were all existing controls (C-12/C-13/C-15) doing their job.**

---

## 1. What worked

**BLUF: the Phase-0 measurement spike is the single biggest reason this batch was single-pass — it retired the only HIGH-risk story before Phase 1 even started.**

- **The Phase-0 geometry MEASUREMENT retired US-036's risk pre-derivation.** US-036 entered as a `SPIKE` with **HIGH geometry risk (C-13)** and a planned `/prototype` measurement step (`PLAN.md` roadmap Inc-3). Instead, a batch-22-style spike drove the real app under Pilot and *measured* the modal content width at **48@80 / 76@120** (`PLAN.md` "Where we are"; `04-validation.md` §4 geometry_80/120). That single measurement (a) confirmed a comfortable fit with an 18-col margin, (b) let the team adopt `.modal-dialog` box-model reuse so the budget holds *by construction* (not per-regime assumption — LLR-036.2 mandate via fold m3), and (c) **eliminated both the fallback rung and the `/prototype` step**. This is C-13 (geometry-budget check) working exactly as designed: measure at draft time, don't assume. It is the same lever that de-risked batch-22's deferred 2×2 patch-editor story.

- **The bands-only algorithm decision made the exact-value ATs trivially non-vacuous.** The Phase-0 spike recommended *bands-only* (deterministic Shannon `H` → 4 fixed cutoffs) over semantic code/data classification (heuristic, accuracy-risk) — `PLAN.md` Key decisions. Because the estimator is deterministic, the black-box ATs assert **exact** values: `H==0.0` (constant), `H==8.0` (0..255 permutation), `H==1.0/2.0/5.0` (integer-log2 references) with `abs()<1e-9` (`increment-001.md` §4; `04-validation.md` §2). Determinism is what lets an AT be exact rather than "approximately high" — an exact-H assertion cannot silently pass on a broken estimator. The alternative (semantic classification) would have forced fuzzy, vacuity-prone assertions.

- **The C-15 e-binding white-box guard (TC-036.4) pre-empted the PR#37/#38 silent-unbind class.** US-036's `e` key had black-box coverage (AT-036a opens the modal), but qa finding **M3** flagged that no white-box TC pinned the *registration* — the exact regression class that silently shipped in PRs #37/#38. Fold M3 added **TC-036.4** asserting `"e" in S19TuiApp.BINDINGS → action_show_entropy` (`02-review.md` M3; `04-validation.md` §3). As `02-review.md` §Control-watch notes, "M3 is C-15 doing its job at review time" — a pre-existing control caught the gap before code, not after ship. C-15 symbol-identity was also clean at authoring: `e` is a plain key string, no `Select.BLANK`-class framework-sentinel trap (`01-requirements.md` §6 checklist).

- **The C-12 output-then-consume AT captured a genuine LIVE RED (AT-037a).** US-037's gate AT does not read `_entropy_lines` directly — it re-reads the WRITTEN report file from disk (C-12). To prove the AT discriminates the *feature* and not the *fixture*, the wiring was stubbed `and False` and the test run: the capture-plumbing preconditions (`result.mem_map` non-empty, exact bytes) PASSED, then `"### Entropy" in variant_block` FAILED (`increment-002.md` §4a). This is a real captured RED over the shipped chain — the strongest possible evidence that the AT is load-bearing, and it directly answers the M4 "plumbing not verified" concern with an end-to-end precondition assert.

- **Fail-loud caught the S0-header substrate reality instead of shipping a guessed constant.** The Inc-1 stress guard first asserted `large_s19` → 3200 windows. It failed loud: `S19File.get_memory_map()` maps the **S0 header record's `"STRESS"` ASCII @ address 0**, adding a 201st tiny range → **3201** windows (`increment-001.md` §5). The fix derived the expected count from the *actually parsed* ranges (`Σ ceil(len/256)`) rather than pinning a magic number, so the test now encodes real substrate behavior. A silent overrun-or-adjust would have hidden a wrong mental model; failing loud surfaced and corrected it (engineering rule #12).

- **Every phase was single-iteration (0 iterations/phase).** Phases 0-4 each passed first-pass (`PLAN.md` "Where we are"). Phase-1 derivation was clean on first draft (3 HLR ↔ 3 US, 16 LLR all parent-traced, `shall`-only, 0 orphans — `02-review.md` BLUF). Phase-2 raised 11 findings but 0 blockers, all folded pre-lock. Phase-4 gate passed with 0 non-snapshot failures. The pipeline never had to loop back.

---

## 2. What didn't / friction

**BLUF: the only real friction was expected, non-gating, and previously-seen — the new footer binding drifted 19 committed snapshot baselines.**

- **New global `e`/Entropy footer binding drifted 19 of 28 committed snapshot baselines.** Adding the `e` binding + entropy styles changes *every* screen's rendered footer, so 19 pre-feature baselines no longer match (`04-validation.md` §6; `increment-003b.md` §4). This is the largest visible red in the suite. It is **non-gating** (the snapshot job is `continue-on-error: true`), the behavioral verdict for US-036 is carried by the Pilot ATs (AT-036a/b/c, all PASS), and the 2 new entropy cells ship `xfail(strict=False)` — never `failed`. Isolation proof: `git stash` of the feature → 28 pass; feature present → identical 19-cell drift regardless of the test-file edits (`increment-003b.md` §4). **Cost:** it requires a post-merge canonical-CI regen (re-baseline 19 + 2, drop 2 xfails) — a follow-up chore, exactly the batch-25 pattern (commit 35238ea). Not a code defect, but real drift-management overhead every time a global binding changes.

- **Doc-drift between the validation-strategy draft and the LLR (Inc-2 F1).** `01b-validation-strategy.md` described the report entropy output as per-window `addr / H=` lines, while the shipped LLR-037.2 emits a per-*band* count summary (O(bands), not O(windows) — a byte-budget + confidentiality decision). Caught at Inc-2 code review as MEDIUM finding **F1** and reconciled (`increment-002.md`; `PLAN.md` Inc-2 note). Minor, folded, no rework — but it is a reminder that a validation-strategy doc written before the format is finalized can drift from the normative LLR.

- **The editable-install worktree `.pth` trap.** pip's editable `.pth` resolves `s19_app` to a *different* worktree (`lucid-margulis-a63fd4`) by default; only the cwd-first ordering (running `pytest` from *this* worktree root) makes imports resolve correctly, and standalone scripts need an explicit `sys.path.insert` (`PLAN.md` Risks; `increment-001.md`/`-002.md` "How to test"). This is a recurring multi-worktree hazard that every increment had to guard against by pinning cwd.

- **Local Python 3.14 vs canonical 3.11 split.** All dev/regression runs were local Python **3.14.4**; the authoritative merge gate is the CI matrix on **3.11** (`04-validation.md` §7; `PLAN.md` Test ledger). The local run is confirmatory only, so the *true* gate result is deferred to CI. One env-sensitive test (AT-037b byte-identical) needed CRLF/LF-robust construction to pass on both Windows-local and Linux-CI (`04-validation.md` §7) — handled in the F2 fold, but it is friction that the two-environment split imposes on every byte-level assertion.

---

## 3. Scope drift assessment

**Verdict: NONE. The batch stayed inside its 3 stories and its Phase-0 decisions.**

- **Story count held at 3** (US-035/037/036) through all phases — no story added, none silently expanded (`PLAN.md`; `04-validation.md`).
- **Bands-only held as decided.** The Phase-0 spike explicitly deferred semantic classification (the ambition-creep risk); the shipped service is deterministic bands-only (`PLAN.md` Key decisions; §1 above). The ambition axis was decided *before* deriving and never re-opened.
- **LLR-036.6 (cost-cap) was a review-driven tightening, NOT scope creep.** The new LLR promoted an *already-present* risk (R-4, cost cap) from a prose note to a normative `shall`, in response to convergent finding M1 (architect + security F5). The §6.4 reconciliation log records the parent-HLR re-read: "HLR-036 already carries R-4 and the `hexview` cost-cap precedent in Rationale; derivation unchanged — this LLR makes the existing intent normative, no new obligation on HLR-036" (`01-requirements.md` §6.4). This is spec-tightening within the existing HLR envelope, which is exactly what the Phase-2 fold mechanism exists to do — it is the *opposite* of scope creep (it *closed* an under-specification, adding no new capability).
- **All other Phase-2 folds** (snapshot-at-push non-goal, box-model reuse mandate, `emit()` routing, band-cutoff single-sourcing, purity-probe TC) were likewise refinements of existing LLRs, each with a "derivation unchanged" parent re-read (`01-requirements.md` §6.4). No fold introduced a new external surface (`02-review.md` security BLUF: "no new external surface").

---

## 4. Metrics

| Metric | Value | Source |
|---|---|---|
| **Iterations per phase (0-4)** | **0 / 0 / 0 / 0 / 0** — every phase single-pass | `PLAN.md` "Where we are" |
| **Route** | full `/dev-flow` (operator AskUserQuestion) | `PLAN.md` |
| **Stories → HLR → LLR** | 3 US → 3 HLR → **17 LLR** (16 at draft → +LLR-036.6 fold) | `PLAN.md`; `01-requirements.md` §6.4 |
| **Phase-2 findings raised vs closed** | 0 blocker · 5 major · 6 minor = **11 raised, 11 folded pre-lock** | `02-review.md` |
| **Increment code-review folds** | **4 folded** (Inc-2 F1 doc, F2 byte-identical AT; Inc-3 F1 either-cap truncation mutation-verified, F3 type) + Inc-2 F3/F4, Inc-3 F2 LOW → backlog | `increment-002.md`, `-003.md` |
| **HIGH code-review findings** | **0 throughout** all increments | `increment-00*.md`; `PLAN.md` |
| **Behavioral test delta** | **+35** (14 US-035 + 8 US-037 + 13 US-036) + 2 xfail snapshot cells | `04-validation.md` §5; `PLAN.md` test ledger |
| **Files touched** | 1 NEW service (`entropy_service.py`) + edits to `report_service.py`, `screens.py`, `app.py`, `styles.tcss` + 3 new/edited test files + `tui-ci.yml` step-name; ≤5 files per increment held every increment | `increment-00*.md` §2 |
| **Engine-frozen diff** | **0** (`git diff --name-only origin/main` over the 7 frozen paths → empty; guard suites 101 pass) | `04-validation.md` §5 |
| **Phase-4 gate result** | **PASS** — batch modules 60 pass · frozen guards 101 pass · full `not slow` 1048 pass / 19 fail (ALL snapshot-drift, non-gating) / 2 skip / 5 xfail · slow 21 pass · **0 non-snapshot failures** | `04-validation.md` §1/§5 |
| **AT/TC reconciliation** | complete — 0 orphan provisional ids, 0 unfilled placeholders | `04-validation.md` §3 |
| **Counterfactual ledger** | complete — AT-037a captured LIVE RED; AT-035* ImportError-by-construction; AT-036a RED-by-construction + 2 positive pins | `04-validation.md` §2/§4 |
| **Feature status** | **#12 COMPLETE** (a+c batch-24, b batch-26) | `PLAN.md` Objective |

---

## 5. Root causes

**N/A for iteration-driven root causes — there were no phase iterations to diagnose.** Every phase (0-4) passed first-pass (`PLAN.md`). The single-pass record traces to two upstream disciplines, stated affirmatively so the next batch can reproduce them:

1. **The Phase-0 measurement spike front-loaded the only HIGH-risk unknown.** Measuring the modal geometry (48/76) *before* Phase 1 converted US-036 from a SPIKE-with-fallback into a READY story with an exact budget — so there was nothing left to discover during implementation that could force a loop-back (§1). This is the batch-22 pattern applied deliberately.

2. **Pre-lock fold discipline in Phase 2 resolved all 11 findings before any code was written.** Because every major/minor was folded into the spec *before* Phase 3 (`02-review.md` §Fold-log; `01-requirements.md` §6.4), no review finding turned into implementation rework. The two increment-time folds that did surface (Inc-2 F1/F2, Inc-3 F1/F3) were caught at the *increment* code-review gate and folded in-place within the same increment (`increment-002.md`, `-003.md`), never causing a phase re-run.

The one place fail-loud fired (the S0-header 3200→3201 window count, `increment-001.md` §5) was absorbed *within* Inc-1 as a test-correctness fix, not a phase iteration — the increment was still single-pass.

---

## 6. Items proposed for next batch

1. **Snapshot-regen follow-up (post-merge, canonical CI).** Run `.github/workflows/snapshot-regen.yml` (`workflow_dispatch` → artifact) in the pinned-`textual==8.2.8` canonical env; commit the regenerated `.svg` set (**19 refreshed drifted cells + 2 new entropy baselines**); then a follow-up **drops the 2 entropy `xfail` marks** → all cells green, zero xfail. Exactly the batch-25 lineage (commit 35238ea). NOT a code defect — drift-management chore. (`04-validation.md` §6; `increment-003b.md` §7.)
2. **Deferred LOW code-review nits → backlog.** Inc-1 F1/F2/F3 (3 optional service nits), Inc-2 F3/F4 (LOW), Inc-3 F2 (LOW, no-action) (`PLAN.md`; `increment-00*.md`). None load-bearing; batch them into a hygiene pass.
3. **SEC-F1 (P3 hardening) — already discharged as LLR-036.6.** The security-reviewer's sole P3 (cost-cap → `shall`) converged with architect M1 and shipped as normative LLR-036.6 + TC-036.5 (`02-review.md` M1). No residual security action; note for the ledger only.
4. **D-3 / pre-existing `F401 Optional` cleanup in `test_tui_snapshot.py`** — pre-exists on HEAD, left untouched per surgical-changes discipline; fold into an unrelated hygiene pass (`increment-003b.md` §7).
5. **REQUIREMENTS.md `R-*` status promotion** for HLR-035/037/036 + traceability rows (Phase-6 doc task, not a gate blocker — `04-validation.md` §9).
6. **Feature #12 is now COMPLETE.** Next batch should pull the next queued feature/entropy from the backlog (the #12 line is closed).

---

## 7. Control assessment

**BLUF: No new control is warranted. I agree with `02-review.md` §Control-watch — every review-time candidate was an EXISTING control working as designed. I propose no watch-item.**

The three patterns that surfaced this batch each map to a standing control that *fired correctly*:

- **Geometry measurement (C-13):** the Phase-0 spike measured 48/76 rather than assuming, retiring the fallback and the `/prototype` step (§1). C-13 did its job at draft time — nothing new to encode.
- **Output-then-consume AT (C-12):** AT-037a observed the on-disk report file and captured a live RED (§1). C-12 held; the M4 fold *strengthened* the same control (precondition assert) rather than revealing a gap in it.
- **Symbol-identity / silent-unbind (C-15):** M3 (the white-box `e`-binding TC) is, verbatim from `02-review.md`, "C-15 doing its job at review time" — it caught the PR#37/#38 regression class *before* code. C-15 was also clean at authoring (plain key string, no framework-sentinel trap).

There is **no recurring un-controlled pattern** across this batch that a new control would address. The candidates a naive reader might reach for (add a geometry rule, add a binding rule, add an AT rule) are all already encoded and already worked. Encoding a redundant control would violate simplicity-first and the "control only where a recurring gap exists" bar.

**Recommendation: encode NOTHING.** (Control encodes are operator-approved only — this section is an assessment, not an action.) If a watch-item were forced, the *only* candidate is the **snapshot-drift-from-global-binding** pattern (batch-25 and batch-26 both required a post-merge regen after adding a footer binding) — but that is already a known, documented, batch-25-established *process* (`snapshot-regen.yml` + the `snapshot-regen-env` memory), not an un-handled gap. It needs no new control; it needs the follow-up in §6.1. I do not propose it as a watch-item.

---

## 8. Evidence checklist (Phase-5 architect)

- [✓] **Constraints stated** — engine-frozen off-limits (0 diff verified), bands-only (deterministic, ambition decided Phase-0), measured 48/76 geometry, ≤5 files/increment. Evidence: `04-validation.md` §5; `PLAN.md` Key decisions / Conventions.
- [✓] **Single-pass record substantiated, not asserted** — 0 iterations/phase traced to the measurement spike + pre-lock fold discipline (§5). Evidence: `PLAN.md` "Where we are"; `02-review.md` Fold-log.
- [✓] **What-worked tied to controls with artifact citations** — C-13 (geometry), C-12 (AT-037a live RED), C-15 (TC-036.4), fail-loud (S0 header). Evidence: `increment-001.md` §5, `increment-002.md` §4a, `02-review.md` M3/§Control-watch.
- [✓] **Friction listed with cost** — 19-cell snapshot drift (regen chore), doc-drift F1, `.pth` trap, 3.14/3.11 split. Evidence: `04-validation.md` §6/§7; `increment-002.md`.
- [✓] **Scope-drift assessed honestly** — verdict NONE, with LLR-036.6 explicitly justified as review-driven tightening (parent re-read "derivation unchanged"). Evidence: `01-requirements.md` §6.4.
- [✓] **Metrics from real artifacts, not fabricated** — iterations, findings 11/11, folds 4, +35 tests, 17 LLR, 0 frozen diff, gate PASS. Evidence: `04-validation.md` §1/§5; `PLAN.md` test ledger.
- [✓] **Root-cause section correctly marks iteration-RCA N/A** (no phase looped) and states the affirmative single-pass causes. Evidence: `PLAN.md`.
- [✓] **Next-batch items are concrete + owned** — snapshot regen path (batch-25 pattern, commit 35238ea cited), LOW-nit backlog, SEC-F1 discharged, R-* promotion, #12 COMPLETE. Evidence: `04-validation.md` §6/§9; `increment-003b.md` §7.
- [✓] **Control-assessment call made explicitly** — encode NOTHING; agree with `02-review.md`; no watch-item; snapshot-drift is a known process not a gap. No control self-encoded (operator-approval-only respected).
- [✓] **Risks of the recommendation stated** — the residual risk is the deferred post-merge regen (§6.1): until it runs, the snapshot job stays visibly red (non-gating) and the 2 entropy cells stay xfail; if skipped, future drift compounds. Flagged as the one carry that must not be dropped.
- [✓] **Companion QA retrospective not edited** — `05b-postmortem-qa.md` is authored by `qa-reviewer`; this file is engineering-only.

---

*End 05-postmortem.md — architect. Companion: `05b-postmortem-qa.md` (qa-reviewer).*
