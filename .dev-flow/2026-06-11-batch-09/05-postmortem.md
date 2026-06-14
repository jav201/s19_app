# Post-mortem — s19_app — 2026-06-11-batch-09 (US-006 hex compare)

Co-authored: architect (process half) + qa-reviewer (validation half), merged by orchestrator, 2026-06-13.

**One-line takeaway (lineage):** b05 symbols→grep · b06 measurements→regime · b07 spec's-own-checks-must-run · b08 AC-artifact-surface + probe-regime + spec-pins-need-increment-gate-verification · **b09: the supersession census must cover ALL guard classes (placement/allowlist + AST-composition, not only behavioral placeholders); and the per-increment gate is a requirement-validation surface — it caught an intent-wrong-but-spec-clean design (a truncated report file inherited as a pattern from a sibling module) that all of Phase 1/2 review passed.**

---

## PROCESS HALF (architect)

### 1. What worked — the 6-generation control stack earned its keep

First batch run with all six preventive-control generations active (b05 symbol-citation, b06 env-measurement, b07 probe-self-test + contract-touch, b08 AC-artifact + probe-regime). Each fired on a real trap:

- **AC-artifact citation (b08) — no-`.hex` trap avoided.** Probe P-03 recorded `examples/**/*.hex` = 0 files (P-02 `*.s19` = 16 as the in-regime positive control); that zero propagated into R-7 + A-3 (HEX tests synthetic; any new on-disk `.hex` is NEW + budget-counted). Phase 4: zero fabricated `.hex` fixtures. The rule converted an absence into a binding constraint instead of a silent assumption.
- **Probe-regime (b08) — caught a false-positive before it became a false failure.** Every purity/no-logging probe declared its regime + ran a same-regime positive control (P-10 `compare.py` vs `range_index.py`; P-11 `diff_report_service.py` vs `report_service.py`/`workspace.py:60`). At Phase 4 this resolved DEV-5: `rg -c "textual"` returned 1 hit on `diff_report_service.py` that regime-aware inspection correctly identified as prose (line 52), not an import.
- **Contract-touch C-9 — field set held at 6 through every perturbation.** `ComparisonResult` = {image_a, image_b, runs, stats, notes, diagnostics, refused} re-derived independently at iteration 2 (F-3), iteration 3 (M-5/F-11), iteration 4 (F-18..F-20 incl. the whole HTML format addition). All three: 0 added / 0 removed — HTML correctly classified as another OUTPUT FORMAT of the same result, not a contract field.
- **Signed-balance ledger — exact at every gate.** M-3's `post = 733 − D + A` reconciled `782 = 733 − 3 + 52`, cross-checked against the full run `750 + 29 + 3 = 782`.
- **Measured perf — never hand-waved.** P-15 ~201.7ms → G-7 budget ≤2.0s (~10×) → LLR-001.5 validated 1.39s. Three independent measures agree.
- **A-3 node-id discipline — worked as designed.** Provisional ids flagged in Phase 1; real tree collected at Phase 4; drift recorded as DEV-1/DEV-2, not failures.

### 2. The two named lessons

**Lesson 1 (FINDING) — Census-completeness: the R-8 census searched ONE guard class, not all.**
The R-8/P-16 supersession census catalogued behavioral-placeholder guards (TC-027 family asserting `#diff_deferral_notice`/`DEFERRAL_TEXT`/static rows; predicted-red corrected 4→5 by M-2) but MISSED two structural module-placement guards — `test_tc028_no_new_processing_module_added_outside_view_layer` (`:3174`) + `_inc10` (`:3534`) — that pin `s19_app/` to a 7-module batch-04 allowlist. D-7's `compare.py` at the package root tripped both; surfaced only at the I1 gate. **Root cause:** pattern blind spot — the census grepped the placeholder/deferral shape, not the structural-allowlist shape; P-16 was a precise probe of an incomplete target set. **Mitigating:** the I1 gate caught it (full-suite run) and the conflict rule already existed — resolved by adding `compare.py` to both allowlists with a supersession comment (HLR-001/D-7 supersedes the batch-04 invariant), bounded cost (1 unbudgeted 3rd-file at I1). **Corrective → A-1.**

**Lesson 2 (KEEP/WIN) — a mid-flight requirement change was caught AT the increment gate and routed back into Phase 1.**
The complete-export + HTML decision (G-9) arrived at the I3 gate. Rather than slip it to Phase 4 or ship the truncated-file design actually implemented, it was handled as a Phase-1 requirement iteration (iteration 4) mid-Phase-3: amend LLR-004.3 + add LLR-004.7 + relocate display caps to LLR-005.2 + R-10 + count 25→26, then redo only the I3 report portion (I3-redo, 85164ff), with full F-18..F-21 audit + parent-HLR re-read + C-9 re-check. **Why the gate caught it:** the gate presents *realized behavior* (a truncated report file — the `REPORT_MAX_TOTAL_BYTES` cap inherited as a pattern from report_service via D-5) to the operator, who recognized it contradicted intent (the persisted report is the authoritative deliverable; caps belong on the display). It was C-9-clean, anchor-clean, audit-clean — but intent-wrong, and only a behavior-presenting gate surfaces intent-wrong. **The increment gate is a requirement-validation point, not just a code checkpoint. → A-2.** Sub-note: pattern-reuse (D-5 "copied/parameterized" caps) carries invisible behavioral assumptions (file == bounded) — worth a half-line in the template's reuse guidance.

### 3. Scope evolution — absorbed cleanly, no ad-hoc patching

- **G-9 mid-flight (+1 LLR, +1 format, +R-10, cap relocation):** §6.4 F-18..F-21 (per-body-change rows, parent-HLR re-read populated), C-9 re-check 0/0, R-10 added + routed to security, count integrity 25→26 across §1.5/§5.3/§5.2 (no M-1 denominator drift recurrence), Phase-4 TC-026..029 PASS with a real injection probe (§2.3).
- **G-8 reversal in Phase 2 (Downloads→solo-prompt):** F-12 removed `Path.home()/"Downloads"` throughout; the reversal *simplified* the surface (R-9 cross-platform failure mode removed, M-6 moot); dead probe P-18 marked historical not deleted (traceability preserved).
- **Strain point:** G-9 arrived after Phase 2 closed and still needed security routing — handled correctly but informally (→ A-3).

### 4. Metrics

| Metric | Value |
|---|---|
| Iterations — Phase 1 | 3 (draft + operator gates + Phase-2 fixes) + iter-4 mid-Phase-3 (G-9) |
| Iterations — Phase 2 | 1 + re-confirmation |
| Increments — Phase 3 | I1, I2, I3, I3-redo, I4, I5 (6) |
| Phase-2 findings | 0 blockers / 5 majors / 6 minors + 1 medium; 11/11 closed in 1 iteration (F-7..F-17) |
| Ledger | 733→744→756→773→776→782 exact at every gate; full-run cross-check 750+29+3=782 |
| D / A split | D=3 (delete-and-replace), A=52 (49 new-file + 3 directionb replacements); rewrite-in-place 0/0 |
| Predicted-red | R-8 set 5 (3 delete-replace + 2 rewrite-in-place) — count exact; one rewrite stayed green at the I4 checkpoint (safe over-prediction) |
| File budget | I1 = 2 + 1 gate-authorized allowlist 3rd-file; I4 = 5 (at cap); I3-redo = report-portion modifications |
| TC coverage | 29/29 TC PASS; 26/26 LLR; 5/5 HLR |
| Perf | budget ≤2.0s, measured 1.39s |
| Open at close | 5 DEV doc-reconciliation; 0 code/behavior defects |
| Contract stability | C-9 = 6 fields, unchanged across 3 re-checks under +1-LLR + format-add churn |
| Full suite | 750 passed / 0 failed / 29 skipped / 3 xfailed |

---

## VALIDATION HALF (qa-reviewer)

### A. Verification-quality wins

- **W-1 — Signed-balance handled its first D≠0 batch cleanly.** First batch with a non-zero deletion term — the real test of the M-3 fix. `782 = 733 − 3 + 52`, cross-checked by component and by full-run total. Decisive evidence: rewrite-in-place scored 0/0 (directionb `def test_` count 98→98 across base→HEAD; +3 D / +3 A nets zero). An additive `+N` would have over-counted the 3 replacements and swallowed the 3 deletions, landing on a wrong-but-plausible total. Proved its worth on the exact case it was designed for; survived two mid-batch shocks (I3-redo −2/+5; R-8 −3/2-rewrite).
- **W-2 — The HTML-safety test is genuinely adversarial (rule-9).** `test_html_escapes_embedded_payload` plants `<script>alert("x")</script>&` into `ImageRef.label`/`.path` and asserts BOTH directions: raw payload absent (`payload not in text`), escaped form present (`&lt;script&gt;`, `&amp;`), 0 `<script`. It would FAIL if `html.escape` were removed — the property rule 9 demands. Companion `_EXTERNAL_RESOURCE_RE` asserts 0 exfil vectors (`<script|https?://|@import|src=|url(`). §2.3 re-ran the generator out-of-test with the payload in `diagnostics` too. The strongest single test in the batch; TC-027 (```diff `-`/`+` with byte asserts) and TC-006 (measured 1.39s) are the same non-vacuous tier.
- **W-3 — Source-level threshold re-count kept, stayed cheap.** Each §1 matrix row carries an inline source citation (`test:279`, `test:618`, …); all 26 LLR thresholds MET by inspection, not by trust. Folded into the matrix the reviewer was already building.
- **W-4 — A-3 provisional node-id discipline prevented a batch-08 DEV-1-class false alarm.** Implemented ids collected from the real tree, drift recorded as DEV-1/DEV-2 (doc reconciliation) not failures. The tradeoff is favorable: a cheap guaranteed Phase-6 chore vs an expensive intermittent false-failure signal at the gate.

### B. Leak analysis — 0 behavior leaks

Full suite 750 passed / 0 failed; the entire DEV register is doc-reconciliation.

| DEV | Class | Root cause | Preventable earlier? |
|---|---|---|---|
| DEV-1 | spec test FILE `test_diff_report.py` vs disk `test_diff_report_service.py` | A-3 provisional flag covered node ids but not FILE names | Partially — widen the flag's scope (V-5) |
| DEV-2 | provisional `-k` selectors don't all match impl names | intended A-3 consequence | No — correct conservatism |
| DEV-3 | predicted-red disposition split (3 delete-replace + 2 rewrite) | Phase-1 predicted count not disposition | No — confirmatory |
| DEV-4 | TC-006 run in-file not via `-m slow -k` | task-framing assumption | No — resolution note |
| DEV-5 | purity grep substring-matches prose | substring probe | Marginally — tighten probe (V-4) |

**DEV-1 assessment:** the A-3 provisional flag's scope was too narrow — it should cover every implementer-owned identifier (file path + node id + `-k` token), not just node ids. A pinned-but-wrong file name produces a false "test file missing" signal at the gate. One-line scope widening → V-5. **Predicted-red assessment:** the R-8 count (5) was correct, not over-predicted; the one I4-checkpoint test that stayed green is *safe* over-prediction (predict-red-find-green = investigate-and-move-on; the dangerous direction is predict-green-get-red, the M-2 failure mode Phase 2 caught). The census should bias toward over-predicting reds; a 1-of-5 over-prediction is within tolerance and must NOT be "corrected" by making the census less conservative.

### C. Probe & ledger practice

The b08 probe-regime rule held for all 19 probes incl. the new classes: P-19 (HTML-safety) recorded its `tui/services/` regime + planted-payload adversarial assertion + scratch cleanup; the I1 placement-guard discovery recorded the package-root regime + supersession comment; P-15→≤2.0s→1.39s is a clean measure-then-validate loop (budget stated before the Phase-4 measurement — no post-hoc threshold fitting). The contrast P-19 (plants-and-asserts, no false-positive) vs the purity substring grep (greps-only, DEV-5 false-positive) is instructive — adversarial probes don't have the false-positive problem.

### D. Recommendations V-1..V-6

| # | Recommendation | Tied to |
|---|---|---|
| V-1 | Keep the signed-balance `post = base − D + A`; require the I-packet disposition table to label every touched test D / A / rewrite-0-0. | W-1, DEV-3 |
| V-2 | Keep the measure-then-validate perf loop; budget stated before the Phase-4 measurement; record both. | W-4/P-15 |
| V-3 | Add a "supersession-completeness" inspection row to the Phase-4 matrix: grep the WHOLE class of placeholder constants/markers and assert all surviving references are negative assertions (verified by hand this batch: only `#diff_deferral_notice` ref is `not bool(...)` at directionb:3679; the 4 constants survive only in the "they're gone" guard :3423-3434). | M-2, §2.8 |
| V-4 | Tighten the purity probe from substring `rg -c "textual"` to `rg -n "import textual\|from textual\|Textual"`. | DEV-5 |
| V-5 | Widen the A-3 provisional flag to ALL implementer-owned identifiers — test FILE paths + `-k` tokens, not just node ids. | DEV-1/DEV-2 |
| V-6 | Keep source-level threshold re-count + implemented-id collection as standing Phase-4 steps; make the inline `test:NNN` citation mandatory. | W-3/W-4 |

---

## MERGED ACTION REGISTER

| ID | Action | Prevents/serves | Owner / when |
|---|---|---|---|
| A-1 | **Census-completeness probe (template):** the supersession census MUST grep BOTH guard families — behavioral-placeholder (existing P-16) AND structural/placement/allowlist + AST-composition guards. Concrete pair: `rg -n 'glob\(.\*\.py.\)\|listdir\|iterdir\|allowlist\|_root_modules' tests/` + `rg -n 'ast\.\|\.body\|calls\s*<=' tests/`. A predicted-red set is incomplete until both run. | Lesson 1 (the two `_outside_view_layer` guards) | Phase-1 census, next batch (template adoption confirmed at batch-10 Phase 0) |
| A-2 | **KEEP: increment gate = requirement-validation point.** Document the I3→iteration-4 episode as the canonical example. Add to the "reuse as PATTERN" guidance: when copying a sibling module's pattern, list the behavioral assumptions that ride along (e.g. file-is-bounded) and confirm each against the NEW module's intent. | Lesson 2 (G-9 truncation) | Phase-3 gate practice + template |
| A-3 | **Post-Phase-2 scope-change → re-route security.** When a requirement iteration after Phase-2-close adds a new external-write/output surface, the orchestrator must explicitly re-invoke the security-reviewer for that surface (don't rely on author self-routing). | G-9/R-10 informal routing | Phase 3→2 re-entry |
| A-4 | **KEEP: signed-balance ledger + C-9 re-check on every contract-touch iteration** (V-1). Both held exactly under churn; do not weaken. I-packet disposition table labels each touched test D/A/rewrite-0-0. | W-1, 3× C-9 re-checks | all phases |
| A-5 | **KEEP: AC-artifact + probe-regime (b08)** — both fired on real traps (no-`.hex`, DEV-5 false-positive caught). Keep verbatim. | P-03, P-10/P-11, DEV-5 | Phase 1 |
| A-6 | **DEV-1..5 doc reconciliation** → Phase 6: rename `test_diff_report.py`→`test_diff_report_service.py` in §3/§4 (DEV-1); real node ids for the `-k` selectors (DEV-2); record the 3+2 disposition split in §6.x closeout (DEV-3); TC-006 in-file note (DEV-4); tighten purity probe wording (DEV-5/V-4). | 04-validation §5 | Phase 6 docs-writer |
| A-7 | **REQUIREMENTS.md updates** → Phase 6: new R-* section for compare + HTML export; update stale batch-04 LLR-012.3/012.4 rows (R-6); record the `compare.py` allowlist supersession; promote Manual/Partial rows the 4 new test files now automate. | R-6; I1 supersession | Phase 6 docs-writer |
| A-8 | **Template control widenings (operator-confirm at batch-10 Phase 0):** V-3 supersession-completeness matrix row, V-4 purity-probe tightening, V-5 provisional-flag scope widening to file paths + `-k` tokens. | V-3/V-4/V-5 | batch-10 Phase 0 |

### Batch-10 slate (operator-named; merged with these actions — recorded for the close slate, NOT batch-09 actions)
- **NEW pair — HEX emitter + verify-on-save:** save → re-read → diff against intent **using the batch-09 compare engine** (`s19_app/compare.py` — first downstream consumer, validates the engine as reusable substrate). Both Lesson-1 (new module locations: emitter + verify service) and Lesson-2 (reuses the compare-engine sibling pattern) hazards recur directly here → fold A-1/A-2 into batch-10 Phase 1.
- **Queued:** manifest writer `project.json`; hygiene N-3 (`load_buttons` id + `OperationsScreen` except-`KeyError`); optional E2E / perf-knee test.
- **Still queued pending operator definition:** the CRC first-operation fill-in (unchanged since batch-08).

**Orchestrator gate disposition (2026-06-13, operator standing directive):** Phase 5 APPROVED — analysis with 0 open defects; A-6/A-7 are Phase-6 work (already gate-assigned); A-8 template widenings deferred to batch-10 Phase 0 for explicit operator confirmation (the batch-06/07/08 precedent that template adoption is operator-confirmed at the next batch's open). Advancing to Phase 6.
