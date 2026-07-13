# 02 — Cross-agent review (synthesis) — 2026-07-12-batch-38

> **BLUF:** Three independent reviews (architect · qa · security) found **2 blockers + 4 majors + 6 minors/lows; security PASS (0 security blockers)**. The §4 HLR/LLR spine was correct and engine-freeze-clean; the defects were **cross-artifact contradictions** (intake/PLAN/01b pointing implementers away from the correct §4) + one data-loss guard. **All folded autonomously** (no story-kill, no HIGH security, no requirement re-derivation) and re-verified. Gate: **iterate-to-refine → re-approved (autonomous)**.

Sub-reviews: [`02-review-architect.md`](02-review-architect.md) · [`02-review-qa.md`](02-review-qa.md) · [`02-review-security.md`](02-review-security.md).

## Findings & disposition

| id | sev | source | finding | fold |
|----|-----|--------|---------|------|
| **B1** | blocker | arch (qa concur) | Issue-code divergence `EXCEEDS_32BIT` vs `OVER_32BIT` (public contract) | Ratified **`A2L_ADDRESS_EXCEEDS_32BIT`** everywhere; bound in AT-066a + TC-333/334/335. ✅ verified (only the `[Deleted]` record retains old code) |
| **B2** | blocker | qa (arch concur) | AT-068b clicked existing `#patch_entry_edit_button` → unsound counterfactual | Re-pointed AT-068b + TC-341/342/343 to **new `#patch_entry_edit_json_button`**; asserts single-entry seed + siblings byte-identical; existing button survives. ✅ |
| **M1** | major | arch + qa | US-066 wrong sink — `a2l_service.enrich_tags_and_render` returns tag rows, not issues (WARNING dropped) | Reconciled §2.6/PLAN/01b TCs to **`validation_service.build_validation_report`** (§4 was already correct). Sink path confirmed → `update_validation_issues_view` (app.py:3670) → `GroupedIssuesPanel`. ✅ |
| **M2** | major | arch | TC ids TC-001..019 collide with batch-01 / non-monotonic | Adopted **TC-332..345** (14 TCs); TC-001.. deleted; one coherent §5.2 table. ✅ verified consistent across both files |
| **M3** | major | qa | AT-065a no pinned positive copy | Pinned: title `:1854` → **`"Change document (JSON)"`**; placeholder `:1904` → **`"or type a path to the same change-set JSON (alternative to the patches/ dropdown)"`**. AT asserts both verbatim + `v2` absent. F-m4 honored (framing on the placeholder; `:1854` is the entries-pane header). ✅ |
| **M4** | major | security | US-068a/b file-loaded A-01 data-loss guard unspecified | **DISABLE** Undo/Redo + per-entry-JSON-edit when `document.source_path is not None` (batch-37 precedent). New LLR-068a.4 + LLR-068b.4; boundary AT branch (file-loaded → disabled/no-clobber; paste-authored → enabled), mirroring batch-37 AT-064c; TC-344/345. ✅ |
| m-a | minor | qa | AT-066b: ANSI is scrubbed by `__post_init__` (model.py:71) | Assert brackets **verbatim**; ANSI **neutralized/stripped** (not verbatim). ✅ |
| m-b | minor | qa | AT-067a render-vs-enable rule + fixture | Pinned: info button **always rendered**; ≥2-image fixture so click target exists. ✅ |
| m-c | minor | arch/sec | `_HISTORY_MAX` value + deep-copy unproven | `_HISTORY_MAX` default **20** `assumed — verify Phase 3`; deep-copy/no-alias assertion required (LLR-068a.1 + AT-068a). ✅ |
| m-d | minor | arch | US-066 positive branch depends on parsed `int` address | AT-066a A-1 flag `confirm in Phase 3` (avoid vacuous pass). ✅ |
| m-e | minor | arch | `patch-section-title` used at 3 sites (1854/1918/1936) | Edit scoped to `:1854` only (C-26). 0 existing tests assert old "v2" copy. ✅ |
| L1 | low | security | New `#entry_json_text` TextArea inherits uncapped native-paste (64 KiB cap is `OsClipboardInput`-only) | **batch-39 carry** (native-paste-cap item); no batch-38 action. |
| L2 | low | security | US-066 must not pre-format markup into message | Build message as plain literal; confirm at code (render sink `safe_text`/`IssueRow` already escapes). |

## Two-layer review (blockers cleared)
- (a) every story has a black-box AT ✅ (065a,066a,066b,067a,068a,068b) · (b) every output-producing req names its deliverable + observation ✅ · (c) both traceability chains complete ✅ · (d) ATs are black-box (drive surface, no internal symbol) ✅ post-B2.
- **C-10** content assertions ✅ (AT-065a asserts verbatim copy, not non-empty) · **C-16** real interaction ✅ (AT-067a/068b real `pilot.click`) · **C-17** markup-safety ✅ (AT-066b hostile-input) · **C-18** one-node-per-AT ✅ · **C-23** geometry `assumed — pilot-measure` ✅ · **C-26** touched symbols declared ✅.

## Security verdict
**PASS (with mitigations).** 0 blocker / 1 major (M4, folded) / 1 minor (m-c, folded) / 2 low (L1 batch-39 carry, L2 code-time confirm). Parse route validated (`json.loads` via ChangeService, no eval/pickle/exec); no new secret/network/external-write surface; engine-frozen sanitizer integrity intact.

## Reconciled counts
**US 5 · HLR 5 (R-TUI-054..058) · LLR 16 · AT 6 · TC 14 (TC-332..345).** 0 `should`-as-modal (verified); 0 LLR targets a frozen file (verified).

## Increment cut (C-21 — stands)
Inc-1 US-065 → Inc-2 US-066 → Inc-3 US-067 → Inc-4 US-068a → Inc-5 US-068b. A-01 guards fold into Inc-4/Inc-5. AT-068b was re-pointed (not added); no new/split AT lacks an owning increment.

## Gate
Blockers existed → **iterate-to-refine** (autonomous fold, no operator stop: no HIGH security, no story-kill) → all folds applied + re-verified → **re-approved (autonomous)**. Certainty axis (unsound counterfactual B2, ambiguous contract B1) now closed. Proceed to Phase 3.
