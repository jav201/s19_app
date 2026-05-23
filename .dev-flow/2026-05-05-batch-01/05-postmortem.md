# Post-mortem — s19_app — 2026-05-05-batch-01

**Phase:** 5 — Post-mortem
**Iteration:** 1
**Date:** 2026-05-07
**Source artifacts:** `state.json`, `01-requirements.md`, `02-review.md`, `03-increments/increment-001.md` … `increment-009.md`, `04-validation.md`
**Co-authors:** `architect` agent + `qa-reviewer` agent
**Worktree:** `C:\Users\jjgh8\OneDrive\Documents\Github\s19_app\.claude\worktrees\lucid-margulis-a63fd4`
**Branch:** `claude/lucid-margulis-a63fd4`

---

## 0. Executive summary

The batch ran the full V-model dev-flow against `s19_app` with the objective *"review the integrity and functionality of the application using the dev-flow process and specialized agents."* It closed in 5 phases over 16 iterations (3 + 2 + 9 + 1 + 1) and produced:

- **17 testable LLRs automated** (LLR-002.1, 002.3, 003.2, 005.1–005.5, 006.1, 007.2, 007.4, 009.1, 009.2 + the audit-deliverable LLRs).
- **9 inspection-method audit matrices** in `increment-009.md`.
- **Suite growth: 173 → 259 passing tests** (net +86), with 3 documented `xfail` rows carrying real product-gap Findings, 0 unexpected failures.
- **18 open Findings** (3 major + 15 minor) — every one has a closure plan in `02-review.md` §Deferrals or `increment-009.md` §10.
- **2 security blockers closed inline** (S-001 destination containment, S-002 symlink/junction follow-through in `copy_into_workarea`) by the LLR-005.3 product change in increment 1.
- **41 `R-*` rows reviewed** — 28 confirmed / 5 promote / 2 drift / 6 unknown.

**Phase 4 verdict was `gap`** (pass-with-known-gaps): 60 TCs evaluated, 49 pass, 11 gap (mostly TC-032 demo evidence), 0 fail. The gaps are doc/manual-evidence only and do not gate Phase 5.

**Recommendation:** close this batch and open **B-2A (engine completeness)** as the immediate follow-up — it clears the largest open-Findings cluster including the 3 `xfail` rows.

| Phase | Iterations | Artifact | Key result |
|---|---|---|---|
| 1 — Requirements | 3 | `01-requirements.md` | 6 US, 9 HLR, 19 LLR, 60 TCs (after iter-3 rebuild) |
| 2 — Cross-agent review | 2 | `02-review.md` | iter 1 found 2 blockers + 16 majors; iter 2 closed all 29 prior + flagged 4 new majors (all doc) |
| 3 — Implementation | 9 increments (1, 1.5, 2–9) | 9 increment packets + code/test changes | +86 tests, 5 files product change (LLR-005.3), 18 Findings raised |
| 4 — Validation | 1 | `04-validation.md` | 0 blockers, 11 gaps (demo + Windows re-attach + CI confirm), verdict = `gap` |
| 5 — Post-mortem | 1 | this document | recommend close batch + open B-2A |

---

## 1. Architect perspective

### A. What worked (architecture / design level)

**Audit-as-system framing.** Treating the audit batch itself as a software system with HLRs, LLRs, TCs, Findings, and explicit boundaries scaled cleanly across all 9 LLRs. The schema added in Phase 1 iter 3 (§1.3 Finding / Audit-matrix / Deferral) was the single highest-leverage decision in the batch: every Phase 3 increment from §6 onward consumed it without re-design, and the Phase 4 register at `04-validation.md` §4 is a pure aggregation of those rows. The deferral schema (`{ID, owner, target batch, blast radius if not fixed}`) directly satisfied the §5.3 "every major Finding logged" gate without bespoke per-Finding prose — which is why Phase 4 closed without iterating despite 18 open Findings.

**HLR-007 split into 007a (engine co-emission) and 007b (panel render).** This was the right structural call. It surfaced F-7.2-01 (engine-side `CROSS_S19_HEX_OVERLAP` doesn't exist) at TC-062.a in increment 5 instead of letting it hide behind a panel-level assertion in increment 6. The matching `xfail(strict=False)` pair (TC-062.a + TC-065.a) was a productive pattern: the gap is documented in test code, naturally surfaces as `xpass` when the engine is fixed, and never blocked the suite. Worth carrying into batch 2.

**Increment ordering and dependency management.** Putting increment 2 (test infra: deterministic builders + Textual snapshot harness) before increments 5–6 (the engine + panel consumers) was correct — the alternative would have been builders inlined per-test and a snapshot harness invented twice. The ≤5-files-per-increment cap held without drama on 8 of 9 increments; only increment 1 needed a separately-gated 1.5 follow-up to rename a test that the workspace tightening had broken by design.

**Agent dispatch shape.** Phase 1/2 ran architect + qa-reviewer + security-reviewer in parallel against the same artifacts; Phase 3 ran software-dev sequentially per increment with explicit gating between them. Parallel-for-review, sequential-for-implement is the right default for V-model batches and should be the template for batch 2.

### B. What didn't work (architecture / design level)

**Phase 1 iter 1 under-specified the workspace surface.** S-001 / S-002 (path-traversal + symlink/junction in `copy_into_workarea`) were live in `workspace.py` and visible to anyone reading the file — they should not have required a Phase 2 security pass to surface. Iter 1's HLR-005 was framed in terms of high-level intent ("workspace owns `.s19tool/`") and never enumerated the actual write-path call sites. That gap is the single biggest architectural miss of the batch and is treated again in §D below.

**LLR-007.2 doc-vs-code drift on fixture location.** The LLR text said `tests/fixtures/<class>/` but the project convention (per `CLAUDE.md`) is conftest builders. Increment 2 caught it on the way in (§6 closure note) and the right thing was done — fixtures landed in `tests/conftest.py` as `make_overlap_s19_hex` / `make_duplicate_alias_mac` / `make_corrupt_records`. Cost: a small documented deviation surfaced in `04-validation.md` §3. Lesson: when the LLR specifies a path, cross-check against `CLAUDE.md` conventions before sign-off.

**Iteration churn.** Three iterations on Phase 1 and two on Phase 2 is on the high side for a single batch. Iter 1 → 2 was user-prompted (US-001 expansion + US-002 robustness, additional HLR-007/008/009) and was healthy growth, not waste. Iter 2 → 3 was the avoidable one — see §D.

**No "while I'm here" scope drift detected.** Software-dev held the line. Increments 1, 3, 4, 5, 6, 7, 8, 9 all delivered exactly what the LLR scoped, plus the small intentional product change in increment 1 (LLR-005.3, accepted in §6.3 R-6). This is itself a positive finding — the ≤5-files cap and the per-increment gate are working as designed.

### C. Scope drift detection (per HLR)

| HLR | Increment(s) | Verdict |
|---|---|---|
| HLR-001 (parser) | 9 (audit matrix only) | in-scope |
| HLR-002 (engine fusion) | 3, 4, 9 | in-scope |
| HLR-003 (TUI orchestration) | 7, 9 | in-scope (3 routed-bypass Findings F-9.04-01/02/03 are gaps surfaced, not drift) |
| HLR-004 (REQUIREMENTS traceability) | 9 | in-scope |
| HLR-005 (workspace IO) | 1, 1.5, 7 | **intentional, accepted product change** in increment 1 (LLR-005.3 added containment + symlink rejection + 256 MB cap on `copy_into_workarea`) — explicitly approved in `01-requirements.md` §6.3 R-6 because it closed Phase 2 blockers S-001/S-002. Not drift. |
| HLR-006 (public A2L API) | 7 | in-scope (F-7.7-07 merge-order bug is a finding, not drift; the audit asserted the contract that uncovered it) |
| HLR-007a (cross-file engine) | 2, 5 | in-scope |
| HLR-007b (cross-file panel) | 6 | in-scope |
| HLR-008 (rule completeness) | 9 | in-scope |
| HLR-009 (engine determinism + coverage) | 8 | in-scope |

**Net:** zero major scope drift. One intentional, pre-approved product change in increment 1. The audit produced 18 open Findings and no new requirements. This is exactly the shape the audit-as-system framing was designed to deliver.

### D. Root cause for repeated iterations

The Phase 1 iter 2 expansion (HLR-007/008/009 added) and the Phase 1 iter 3 rebuild (HLR-005 + 5 LLRs, plus the Finding/deferral schemas, plus message scrubbing, plus TC-047) **share one root cause**: the iter 1 architect pass treated the existing codebase as an opaque box and derived HLRs top-down from the audit objective in `state.json`. It did not bottom-up read the four highest-risk files (`workspace.py`, `validation/engine.py`, `validation/model.py`, the call-site list in `app.py`) before drafting. The two trigger types — user-prompted scope expansion vs. security-driven rebuild — look orthogonal in the decisions log, but both were the predictable consequence of an HLR set that did not survive contact with the actual call surface.

**The architectural decision in Phase 1 iter 1 that would have avoided iter 3:** make a "surface enumeration" pass mandatory before LLR drafting. Concretely, before writing any HLR that touches a module (e.g. `workspace.py`), enumerate every public function and every external call site in `tests/` and `app.py`, then derive the LLRs from that list. That single discipline would have surfaced `copy_into_workarea` and `sanitize_project_name` as candidates for direct LLRs in iter 1, would have caught the 10 orchestration call sites that increment 9 ended up enumerating in §4, and would have made the iter 2 expansion (HLR-007/008/009) happen as a planned scope decision rather than a mid-flight add. **Carry into batch 2 as a Phase 1 §1.X bullet:** *"every HLR that names a module must cite the public-function enumeration that produced it."*

### E. Items proposed for the next batch (architecture angle)

Four candidate batches, each derivable from existing Findings — no new requirements invented.

**Batch B-2A — Engine completeness.** Closes F-7.2-01, F-7.2-02, F-7.7-07, F-9.07-01, F-9.03-01, F-9.03-02, F-9.09-01. All are engine-side product changes: add `CROSS_S19_HEX_OVERLAP` rule + code (closes 4 xfail rows once flipped), pipe S19/A2L parse-time errors into the engine, fix `validate_characteristic` merge order, resolve the `alias_policy="error"` dead branch, reconcile `A2L_BROKEN_REFERENCE` severity, add direct assert for `A2L_INVALID_ADDRESS`, document `A2L_UNRECOGNIZED_BLOCK`. Single owner (software-dev), single review pass (qa + security), 1 small increment per Finding under the ≤5-files cap. Estimated 5–6 increments.

**Batch B-2B — Workspace hardening.** Closes F-7.7-02, F-7.7-03, F-7.7-04, F-7.7-05, F-7.7-06. Tighten `sanitize_project_name` to reject Windows reserved names, enforce 64-char cap, normalize Unicode confusables; switch `validate_project_files` from `is_file()` to a non-symlink-following test; reconcile the schema/memory/in_memory triplet doc. Self-flip-guard tests already exist in increment 7 — they will go green when the code lands. 2–3 increments.

**Batch B-2C — Service-layer symmetry.** Closes F-9.04-01, F-9.04-02, F-9.04-03. Add `tui/services/mac_service.py`, fold `S19File.get_overlap_addresses()` into `validation_service.build_validation_report`, add `a2l_service.parse_and_cache` to consume the third `app.py` direct-call bypass. Mechanical refactor; security-reviewer optional. 1–2 increments.

**Batch B-2D — REQUIREMENTS.md numbering and demo evidence.** Closes F-9.01-01, F-9.02-01, F-9.02-02, F-9.02-03, F-9.09-01 (overlap with B-2A acceptable), plus the TC-032 9-pack demo evidence and TC-047 Windows stdout (Q-N01) gap from `04-validation.md` §5. Doc-only batch + a manual demo capture session. Owner: docs-writer + Javier. 1 increment.

**Suggested execution order:** B-2A first (clears all `xfail` rows and the largest open-Findings cluster), then B-2B in parallel with B-2C, then B-2D as the closing doc sweep before the next /dev-flow-sync.

### F. Architecture-level surprises

Three learnings worth carrying.

1. **The audit-as-system framing scaled.** It absorbed a security-driven rebuild (iter 3) without re-architecting Phase 1, absorbed a product change (LLR-005.3) without breaking the audit shape, and let Phase 4 close pass-with-known-gaps on a pure aggregation of Phase 3 §6 sections. This pattern — treat audit batches as systems with their own HLRs/LLRs/TCs — should be the GRNDIA default for any non-trivial review engagement.

2. **`pytest.xfail(strict=False)` carrying a Finding ID is a high-quality contract.** The pattern in increments 5/6/7 (TC-062.a, TC-065.a, TC-052) makes pre-existing product gaps visible in the test suite without breaking it, and the gap closes cleanly as an `xpass` when the product fix lands. Carry into batch 2 as a documented architectural pattern.

3. **The ≤5-files cap held.** 8 of 9 increments stayed within. Increment 1 needed an explicit 1.5 follow-up, and that gating worked as designed. The cap is not just a discipline rule — it is what made the Phase 3 review cadence (gate after every increment) possible. Do not relax it for batch 2.

---

## 2. QA-reviewer perspective

### A. Coverage metrics (objective)

**Per-Phase metrics:**

| Phase | Iterations | Artifacts produced | Tests added | Findings raised | Findings closed |
|---|---|---|---|---|---|
| 1 | 3 | `01-requirements.md` (US-001..006, HLR-001..009, 17 LLRs, 60 TCs) | 0 | 7 (S-001..S-007 + 16 majors + 11 minors in iter 1) | 0 (all rolled into iter-3 scope) |
| 2 | 2 | `02-review.md` | 0 | 29 (iter 1) + 16 (iter 2: 4 maj + 11 min + 1 info) | 29 (all iter-1 incl. S-001/S-002 closed by iter 2) |
| 3 | 9 increments (1, 1.5, 2–9) | 9 increment packets + source/test code | **86 net** (173 → 259) + 3 documented `xfail` | 14 product-side (F-7.2-01/02, F-7.7-02..07) + 10 doc/architecture (F-9.01-01, F-9.02-01..03, F-9.03-01/02, F-9.04-01..03, F-9.07-01, F-9.09-01) | S-005, S-N03, R-3, R-7, R-9, Q-N02 (test-side), Q-N03, Q-N04, A-N02 partial, Q-N01 partial |
| 4 | 1 | `04-validation.md` | 0 | 0 new | 0 (gap-verdict, no iterate) |

**Per-increment breakdown for Phase 3** (verified against `increment-009.md` §0):

| # | LLR(s) | Files | Tests added | Findings raised |
|---|---|---|---|---|
| 1 | LLR-005.3 | 5 | 4 (TC-044..047) | A-N02 / Q-N01 closure criteria |
| 1.5 | LLR-005.3 alignment | 2 | rename only | 0 |
| 2 | infrastructure | 3 | 1 smoke + 3 fixture builders | R-7/R-9/Q-N04 closed |
| 3 | LLR-002.3 | 3 | 6 (TC-090.a×3 + TC-090.b×2 + benign) | S-005, S-N03 |
| 4 | LLR-002.1 | 2 | 16 round-trip | R-3 closed |
| 5 | LLR-007.2 | 2 | 8 (TC-062.a..h, 1 xfail) | F-7.2-01, F-7.2-02 |
| 6 | LLR-007.4 | 2 | 8 (TC-065.a..h, 1 xfail) | Q-N03 closed |
| 7 | LLR-005/006/003 | 4 | 38 | F-7.7-02..07 |
| 8 | LLR-009.1/2 | 2 | 4 | 0 |
| 9 | 9 inspection LLRs | 1 | 0 | 10 (F-9.*) |

**Suite trajectory:** 173 → 180 (1.5) → 181 (2) → 187 (3) → 203 (4) → 210 (5) → 217 (6) → 255 (7) → 259 (8) → 259 (9). The +86 headline breaks down as:

- **Product-behaviour-asserting tests (~64):** TC-044..047 (4), TC-090.a/b + benign (6), TC-062.a..h (8), TC-065.a..h (8), TC-041 (4), TC-042 (8), TC-048 (3), TC-049 (3), TC-051/052 (7), TC-023 (6), TC-081 (1), TC-082 (3), AST walk (1), plus parametric expansions in increment 4.
- **Audit-deliverable tests (~16):** the 16 round-trip cases in `tests/test_color_policy_round_trip.py` are explicitly written to *lock* the LLR-002.1 contract — pure regression scaffolding rather than discovery.
- **Snapshot tests (~6):** the harness smoke (increment 2) plus the panel-render `test_tc_065_*` tests render real Textual widgets via `App.run_test()`.
- **Documentation tests (0):** none. The 9 audit matrices in increment 9 are the inspection-method evidence — they are not executable, but TC-002/005/014/021/030/061/063/071/072 are checked by them and cited as `pass` evidence in `04-validation.md` §2.

### B. Test design quality

**`xfail(strict=False)`:** Used on TC-062.a, TC-065.a (both carry F-7.2-01) and TC-052 outside-memory (carries F-7.7-07). The pattern worked: each `xfail` surfaces a real product gap as a Finding, the pytest suite stays green, and closure naturally promotes to `xpass` once code is fixed. **Right tool**, with one nuance: `strict=False` was correct because the engine bug for F-7.2-01 might be partially fixed and emit *some* code (just not `CROSS_S19_HEX_OVERLAP`); a `strict=True` would risk a false `xpass`. None of the three xfails hid an issue that should have failed — each is paired with a Finding ID and a one-line product fix recommendation.

**Self-flip xfail (increment 7):** TC-042 and TC-048 ship as **green** tests that assert the *de-facto* behaviour and contain a comment naming the Finding (F-7.7-02..05). When the product is fixed, the assertion will flip and the test will go red. This was the right call for sanitiser/symlink behaviour where the current contract is defensible-but-loose: it gives a regression net today AND a closure tripwire tomorrow. Slightly confusing on first read — the comment is critical — but cheaper than maintaining 4 separate `xfail` rows.

**Audit-matrix-as-evidence:** The 9 matrices in `increment-009.md` are markdown tables, not executable tests. The 2 `verdict: drift` rows (`tests/fixtures/` location in §5.3 acceptance, `A2L_BROKEN_REFERENCE` severity in F-9.03-02) are **trivially CI-grep-able** — a `grep -E "verdict.*drift" .dev-flow/03-increments/increment-009.md` would catch any new drift introduced by future batches. Recommend exactly that for the next batch's pre-merge check.

### C. Validation strategy retrospective (against §5.1 / §5.2 / §5.3)

- **Test method:** 65 product-asserting + 16 round-trip tests; 3 documented xfails. This is the strongest method in the batch and held up cleanly.
- **Inspection method:** 9 audit matrices in increment 9 plus per-increment matrices in 1/3/5/7. The §1.3 finding schema (`{ID, severity, source, blast radius, owner, target batch, blast radius if not fixed}`) is fine for product Findings but mildly over-engineered for doc-only Findings (F-9.0*) where "owner" and "target batch" reduce to "Phase 6 docs". Suggest a lighter doc-Finding schema next batch.
- **Analysis method:** §5.2 names this for very few rows. Most analysis-style reasoning ended up in increment-packet §5 (Risks). That was the right home — Risks are tied to the increment that surfaced them, not floating in a generic analysis column.
- **Demo method:** the §5.1 mandatory `.png` + signed transcript contract was **too strict for an audit batch** whose deliverable is the audit, not a working demo. TC-032 is the only Phase 4 gap, and it concentrates 9 demo packs that no Phase 3 increment was supposed to capture. Recommend: for audit batches, allow demo rows to be deferred to a single "evidence capture" follow-up batch and mark them `Manual + scheduled` rather than `gap` in the Phase 4 verdict.

### D. Where the audit found real product bugs

**Buckets:**

- **Caught by `xfail`-as-test:** F-7.2-01 (engine `CROSS_S19_HEX_OVERLAP` missing), F-7.2-02 (engine partial coverage), F-7.7-07 (`validate_characteristic` merge order).
- **Caught by self-flip test:** F-7.7-02 (Windows reserved names), F-7.7-03 (64-char cap), F-7.7-04 (Unicode confusables), F-7.7-05 (symlink follow-through).
- **Caught by inspection matrix:** F-9.01-01, F-9.02-01..03, F-9.03-01/02, F-9.04-01..03, F-9.07-01, F-9.09-01, F-7.7-06.

**Could a feature batch have caught the majors first?** F-7.7-07 (merge-order bug) was reachable from a single trivial "two-tag" unit test — yes, a feature batch with even minimal accessor tests would have caught it. F-7.2-01 (overlap detection) is a missing rule, not a bug — no feature test covering "what happens when S19 and HEX overlap?" existed because the rule itself didn't exist; only an audit-style inspection of cross-file classes (LLR-007.1 enumeration) would surface it. **The audit batch was the most efficient way** for F-7.2-01 and the F-9.* doc Findings; F-7.7-07 was avoidable upstream and is the cleanest argument for adding accessor unit tests in any future feature batch touching `validate_characteristic`.

### E. Findings open vs. closed

**Closed by inline iteration (Phase 1/2/3):** S-001, S-002, S-003, S-004, S-005, S-006, S-007 (Phase 2 iter 1 → Phase 1 iter 3 → Phase 3 increment 1/3); Q-N02 (test-side closed inc 3, doc edit deferred); Q-N03 (Option A inc 6); Q-N04 (inc 2); R-3 (inc 4), R-7 (inc 2), R-9 (inc 2); A-N02, Q-N01 (partial — local pass captured, Linux-CI/Windows-stdout pending).

**Open at Phase 4 close: 18** (3 major: F-7.2-01, F-7.7-07, A-N02/Q-N01 partial-equivalent; 15 minor/doc).

**Closure plan ratio:** every open Finding has either a deferral-register line in `02-review.md` §Deferrals or a §10 entry in `increment-009.md` with closure path. ✅

### F. Items proposed for the next batch (QA angle)

1. **Demo-evidence-capture batch.** Close TC-032 (9 packs under `.dev-flow/evidence/TC-032-<R-id>/`) for `R-TUI-003`, `R-TUI-008..010`, `R-TUI-016`, `R-A2L-003/004`, `R-PROJ-001/002`. Effort: ~1 hour. Gates: every `.png` paired with a signed `transcript.md` per §5.1.
2. **R-* test-promotion batch.** LLR-004.1 marked 5 rows `promote`: R-TUI-002, R-TUI-005, R-TUI-009, R-A2L-004, R-PROJ-001. Each has a justifying test cited in `increment-009.md` §5.2. Promote `Manual`/`Partial` → `Automated` in REQUIREMENTS.md and add a CI grep-check that fails on `verdict.*drift`.
3. **Drift-remediation batch.** Two `drift` rows: (a) `tests/fixtures/` documented location vs. conftest-builders actual location (resolve in REQUIREMENTS.md); (b) `A2L_BROKEN_REFERENCE` severity drift (F-9.03-02 — pick one of: rule → ERROR or doc → Warnings).

All three are derivable from existing Findings/verdict rows. No new test requirements invented.

### G. QA-level surprises

- **`large_project` determinism held across 8 increments without re-seeding.** TC-081 (deep-equality on issues + coverage across two engine runs) passed first try. The seeded-builder convention pays off.
- **`App.run_test() + asyncio.run` wrapper** sidestepped `pytest-asyncio` cleanly, at the cost of 4–6 extra lines per snapshot test. Worth it for an audit batch (no new dev dependency); revisit if the next batch adds >10 snapshot tests, where `pytest-asyncio` would amortise.
- **The 60-TC granularity in §5.2 was right.** Finer (per-`R-*` TC) would have ballooned to 120+ rows; coarser (per-LLR TC) would have hidden the per-class detail in TC-062/065 that surfaced F-7.2-01. The TC-032 demo collapse into one row is the only granularity miss — finer (one TC per `R-*` covered by demo) would have made the gap visible per-row instead of as one fat `gap`.
- **Carry-forward Findings from Phase 2 (A-N02, Q-N01) closed *partially* in Phase 3.** This is the only structural awkwardness in the batch — a "partial closure" is not a state the V-model gate cleanly handles. Recommend adding a `partial-closed` verdict to the dev-flow vocabulary so it doesn't have to be encoded as "open major with documented closure step" each time.

---

## 3. Consolidated next-batch proposals

The architect and qa-reviewer recommendations overlap cleanly. Merged with no contradiction:

| Batch | Closes | Owner | Increments | Priority |
|---|---|---|---|---|
| **B-2A — Engine completeness** | F-7.2-01, F-7.2-02, F-7.7-07, F-9.07-01, F-9.03-01, F-9.03-02, F-9.09-01 | software-dev (qa-reviewer + security-reviewer review) | 5–6 | high (clears all 3 xfails + 7 Findings) |
| **B-2B — Workspace hardening** | F-7.7-02, F-7.7-03, F-7.7-04, F-7.7-05, F-7.7-06 | software-dev | 2–3 | high (closes 5 Findings; self-flip tests already in place) |
| **B-2C — Service-layer symmetry** | F-9.04-01, F-9.04-02, F-9.04-03 | software-dev | 1–2 | medium (refactor; no new product behaviour) |
| **B-2D — REQUIREMENTS.md numbering** | F-9.01-01, F-9.02-01..03, F-9.09-01 (overlap with B-2A acceptable) | docs-writer | 1 | medium (doc-only) |
| **B-2E — Demo evidence + test promotions + drift remediation** | TC-032 (9 packs), TC-047 Windows stdout (Q-N01), 5 R-* `promote`, 2 R-* `drift` | docs-writer + Javier | 1 | medium (closes Phase 4 gaps; ~1 hour manual + doc edit) |

**Suggested execution order:** B-2A first (clears xfails + largest cluster) → B-2B + B-2C in parallel → B-2D + B-2E as the closing doc/evidence sweep before the next batch sync to Obsidian.

---

## 4. Process learnings to carry into batch 2

1. **Mandatory "surface enumeration" before LLR drafting** — for any HLR that names a module, enumerate its public functions and external call sites first. Would have prevented Phase 1 iter 3 (architect §D).
2. **`pytest.xfail(strict=False)` + Finding ID** is now the documented pattern for surfacing pre-existing product gaps without breaking CI (architect §F.2, qa-reviewer §B).
3. **Self-flip-guard tests** are appropriate for defensible-but-loose contracts (sanitiser, symlink follow-through). Document them with the Finding ID inline (qa-reviewer §B).
4. **Audit-matrix-as-evidence** with grep-able `verdict: drift` rows enables CI regression checks on inspection-method LLRs (qa-reviewer §B).
5. **Lighter doc-Finding schema** for the F-9.* style (no `owner` / `target batch` fields when it's always Phase 6 docs).
6. **`partial-closed` verdict** for the dev-flow vocabulary (qa-reviewer §G).
7. **Demo-method TCs in audit batches** — relax to `Manual + scheduled` rather than `gap` to avoid concentrating Phase 4 gap-verdicts on evidence capture (qa-reviewer §C).

---

## 5. Decision (user gate)

Per dev-flow Phase 5 spec, three options:

1. **`close batch`** *(co-authors recommend)* — accept the audit deliverable as the outcome of batch 1; the 18 open Findings are queued in the deferral register; advance to Phase 6 (docs) for traceability matrix + functionality.md + executive summary; then `/dev-flow-sync-en` to upload to the Obsidian vault.
2. **`open new batch`** — start B-2A immediately as `2026-05-07-batch-02` (or similar), keeping the deferral register as the requirements seed. This skips Phase 6 of the current batch — generally not recommended because the docs work wraps up the audit deliverable for stakeholders.
3. **`iterate current`** — reopen Phase 3 to fold one or more Findings inline before closing. Only meaningful if the user wants F-7.7-07 (one-line major) closed inside this batch rather than as the first item of B-2A.

**Recommendation: option 1.** The audit deliverable is complete; B-2A is well-scoped and starts cleanly from the deferral register. Phase 6 is the right place to consolidate the audit findings into client-facing documentation.
