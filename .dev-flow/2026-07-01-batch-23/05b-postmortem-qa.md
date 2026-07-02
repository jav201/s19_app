# 05b — Post-mortem, validation/metrics deep-dive — 2026-07-01-batch-23 (US-028)

> **BLUF: 71% of all findings were caught at the P2 cross-review (15 of 21; batch-22: 75%). The 4-point dip is compositional, not a quality regression — the P3 tail is 3 LOW nits + 3 recorded deviations, zero behavioral defects, and P4 raised 0 new findings. The two-layer AT/TC model earned its cost outright this batch: the C-12 gate (AT-035b) is the only test in the repo that goes RED on a reverted dropdown route, and the D-1 sentinel bug is a category a spec-mirroring white-box test would have certified green-and-wrong. One process lesson stands out: the correct sentinel name (`Select.NULL`) was already printed inside 01b §5 at P2 — three sections away from the `Select.BLANK` asserts it contradicted.**
>
> Author: qa-reviewer · Scope: validation + metrics only. The main post-mortem is `05-postmortem.md` (architect).

---

## 1. Shift-left scorecard

Counting convention: one finding = one reviewer-raised issue or one recorded implementation deviation. P2 counts follow the 02-review verdict line (the register merges dual-source findings into shared rows, so row-count < finding-count; note the verdict line SAID "4 MAJOR" while the register table marks 5 rows — corrected in 02-review.md at Phase 5 (header now reads 5 MAJOR with an italic correction note); this scorecard always used the register MAJOR — the table is authoritative here).

| Phase caught | Findings | Detail |
|---|---|---|
| **P2 cross-review** | **15** | 1 BLOCKER (F-1 unflagged framework claim → verified true, pinned) · 5 MAJOR (F-2 N==1 contradiction, F-3 trigger-owner gap, F-4 set_options reset pair, SEC-F2 switch-during-load race → new LLR-035.7, qa-M1 missing TC-035.1/.6 rows) · 9 MINOR |
| **P3 implementation** | **6** | code-review F1/F2/F3 (all LOW; F1+F2 folded, F3 observation-only) · deviations D-1 (Select.NULL sentinel), D-2 (AT-035b proj2 drive), D-3 (TC-035.2 compositor-mapping) — all three recorded §6.5 (A-6.5-1/2/3) |
| **P4 validation** | **0** | V-5 reconciliation, threshold audit, QC-3 catalog, reachability matrix — no new finding; 2 assert nuances confirmed as pre-declared, not deviations |
| **Total** | **21** | |

**Caught-at-P2: 15/21 = 71%** (batch-22: 75%). Excluding the 3 deviations — framework-fact and drive-detail discoveries that require executing against the installed stack — the review-miss rate view is 15/18 = 83%.

**What the comparison implies.** The headline dipped 4 points but the residue quality improved: batch-23's post-P2 tail contains zero behavioral defects — no blocker, no major, nothing that changed observable behavior. Every P3 item is either a nit or a Before/After-recorded correction whose observable contract survived unchanged. The one genuinely P2-catchable item in the tail is D-1: the F-4 verification at P2 opened `_select.py` and wrote the true sentinel name (`Changed(Select.NULL)`) into 01b §5 — while §2's AT-035c asserts still said `Select.BLANK`. The miss was not a verification gap; it was a failure to sweep the verified fact back across the spec's own text. **Cheap fix for next batch: after any framework-fact fold, grep both artifacts for the superseded symbol** (would have moved D-1 to P2 and put the scorecard at 76%, above batch-22).

---

## 2. Two-layer model performance (AT/TC split)

**Verdict: earned its cost, with the clearest evidence of the model's life so far.**

- **The C-12 chain (AT-035b) is irreplaceable by any service-level test.** The direct-write consumer test (`tests/test_variant_execution.py::test_load_project_honors_manifest_active_variant`) hand-writes `active_variant: "b"` into `project.json` — it stays green under a fully reverted dropdown route, because it never touches the dropdown. Only AT-035b (widget drive → shipped save handler → raw `json.loads` of the handler-written manifest → fresh-app consume) goes RED on revert (manifest would carry `"a"`). The gate/guard separation was enforced correctly: the pre-existing test was kept as the consumer-contract guard and explicitly barred from gating. The one test that survives a revert is precisely the one you must never gate on.
- **C-10 converged with framework physics.** The non-default discipline (never gate on the default value) is normally a methodological rule against vacuous asserts. On textual 8.2.5 it is *physically mandatory*: `Select` does not emit `Changed` on a same-value assignment (`_select.py:362`, verified at P2 under F-1), so a default-value "switch" cannot exercise the route at all. When a house rule and the framework's mechanics independently demand the same test shape, the rule has stopped being a style preference — that convergence is worth citing whenever C-10 is challenged as pedantry.
- **Layer A carried the invariants Layer B can't.** TC-035.6 (full byte-snapshot of the project dir: 0 bytes changed, 0 files created on switch) is the Q2 no-write invariant; TC-035.7 (rapid double-pick: label==content coherence, 0 phantom files) is the SEC-F2 race invariant. Neither is an acceptance behavior a user "does" — they are things that must *not* happen, and the white-box layer is where they live.
- **The D-1 sentinel bug is the layer-split's teaching example.** It was caught by *driving the live framework* at implementation (repopulate emitted `Changed(Select.NULL)`; a filter bound to `Select.BLANK` — which resolves to the inherited `Widget.BLANK == False` — never matches anything). A white-box test written to mirror the spec text, asserting the code performs the BLANK comparison, would have been **green-and-wrong**: the comparison exists, executes, and is dead. Proof this failure mode is real and not hypothetical: the pre-existing US-026 change-file branch contains exactly that dead filter, its test suite is green, and it shipped two batches ago (now chipped, task_478df389). Behavioral drive through the shipped surface is the only layer that can catch a dead guard.

---

## 3. Counterfactual discipline (QC-2)

- **AT-035a RED captured, bound to the reconciled node.** `increment-1.md` §4: routing reverted → `AssertionError: ... got 'Project: proj:a (1/2)'` at `tests/test_tui_patch_variant.py:166`, `1 failed in 3.95s`; restored → `11 passed in 31.38s`. P4 verified line 166 is the `proj:b (2/2)` gate assert in `test_at035a_dropdown_switch_updates_label_and_image` — the captured failure mode is exactly the silent-no-op the gate exists to catch.
- **D-2 is the sharper insight: the literal 01b drive would have failed a CORRECT implementation.** 01b sketched "save back into the same project `proj`"; the shipped save flow's `copy_into_workarea` dedup renames the re-copied `b.s19` to `b_1.s19`, so a correct implementation legitimately writes `active_variant == "b_1"` and fails the `== "b"` assert. This is the strongest argument yet for V-5's existence: **a test plan authored before code exists is a hypothesis about un-executed machinery.** Its job is to fix the *observable contract* and the *counterfactual power* (both survived D-2 intact — 2-variant set, raw re-read, revert → `"a"` → RED, `a`-sorts-first consume leg); the literal drive is subordinate and gets reconciled against reality at P4. A process that treated 01b drives as immutable would have either shipped a false-failing gate or silently weakened it. The deviation-with-Before/After path (D-2 → A-6.5-2, C-12 power re-verified by code-reviewer) is the correct absorption mechanism, and it worked.

---

## 4. Metrics table

| Metric | Value | Evidence |
|---|---|---|
| Iterations per phase (0-4) | 1 / 1 / 1 / 1 / 1 | state.json `iterations_per_phase` — no phase re-ran |
| Findings raised / closed | 21 / 21 | §1 above; P2: 15 folded body-first pre-gate; P3: 3 LOW dispositioned + 3 deviations recorded; P4: 0 new |
| Test count | 991 → 1002 (+11 / −0) | ledger reconciled; validator's own `--collect-only` = 11 nodes in the new file |
| Full non-slow suite | 971 passed / 30 skipped / 3 xfailed / **0 FAILED** (448s, f5f8111 base) | 04-validation orchestrator addendum; pre-ff run 969/0 also 0-fail |
| US coverage | 1/1 (US-028) | AT-035a/b/c all PASSED (4 nodes) |
| LLR coverage | 7/7 = 100% | 04-validation §2 — every LLR row has a passing node with the numeric threshold audited in-assert |
| AT gates | 3/3 PASSED, all black-box | 04-validation §3 — zero private-attr gate asserts |
| QC-3 boundary/negative catalog | 7/7 rows covered, 0 gaps | 04-validation §3 (plus beyond-catalog: ghost id, N==3 order, dup stems) |
| Reachability matrix | 0 gaps, both directions | 04-validation §4 |
| Deviations | 3, all recorded §6.5 (A-6.5-1/2/3) | folded post-PASS, body-first |
| Engine-frozen set | 0 diffs | re-verified post-ff |

---

## 5. Validation-process notes

- **V-5 reconciliation friction: zero.** All 10 provisional ids bound 1:1 to the 11 collected nodes (AT-035c = 2 sub-case nodes exactly as planned in 01b §2); no orphan nodes, no re-keying, file path matched the A-4 provisional name. The Phase-1 orchestrator reconciliation note (canonical LLR-aligned numbering, qa numbers superseded) plus the qa-M1/F-7 renumbering fold at P2 is why: the id-collision risk was spent *before* implementation. This is the first batch where V-5 was a pure confirmation pass.
- **Two pre-declared assert nuances, both held.** (1) TC-035.4's "0 loads" on guard branches is proven behaviorally (label/active unchanged after `wait_for_complete`) rather than by a worker count — equivalent observable, declared in the P4 threshold audit. (2) TC-035.5/AT-035c's disabled leg is observation-only by design (01b R-3: nothing user-drivable exists on a disabled `Select`; programmatic value-assign would bypass the very state under test). Because both were written down in 01b before code existed, at P4 they audited as *designed behavior*, not deviations — the difference between a nuance and a finding is whether it was pre-declared.
- **The R-1 resolve-at-P2 pattern worked.** Raised at P1 as a testability risk (where is the label observable; does the hex read need a screen hop?), explicitly deadline-bound to "confirm at Phase 2", resolved there with file:line evidence (CommandBar app-persistent, `app.py:1014-1017` → no hop; hex hop step bound verbatim into AT-035a). Result: zero AT rework at P3 — the implementer transcribed the drive, and it passed first run. Contrast with the alternative timeline where the hop question surfaces mid-implementation and the AT gets redesigned under schedule pressure. Recommendation: keep the pattern as-is — named risk, named resolution phase, exact step bound into the AT text at resolution.

---

*Cross-references: 02-review.md (findings register) · 03-increments/increment-1.md §4 + Deviations (RED capture, D-1/D-2/D-3) · 04-validation.md (V-5, thresholds, matrix) · state.json decisions_log (phase iterations).* 
