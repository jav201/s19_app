# Increment 2 — CHECKS data accessor + presentational widgets (HLR-084 core)

**Status:** ✅ APPROVED (self, autonomous) after code-review APPROVE-WITH-NITS → F1 applied. **Files:** 3 (change_service.py, checks_view.py NEW, tests/test_tui_checks_view.py NEW). **Test delta:** +5 tests + 3 doctests / −0.

## 1. What changed
Read-only data layer + presentational widgets for the CHECKS screen, NO app wiring:
- **LLR-084.2** — `CheckDisplayRow` (5 fields incl. optional `linkage_symbol`, §6.5 AMD-1) + `ChangeService.check_display_rows()`: reads `last_check_result.entries`, maps `result`→severity via `_CHECK_RESULT_SEVERITY`→`css_class_for_severity`, pinned `text` composition, `[]` when None.
- **LLR-084.1/.4/.6** — `checks_view.py`: `CheckGroupHeader`, `CheckRow(.Selected + address)`, `GroupedChecksPanel` (fail→uncheckable→pass, `_CHECK_DISPLAY_MAX=40` cap + truncation note, `NO_RUN_TEXT`), `build_checks_aggregate_strip`. All cells `safe_text`; colour via `css_class_for_severity` + insight_style.

## 2. Spec amendment (§6.5 AMD-1)
`CheckDisplayRow` gained a 5th optional `linkage_symbol` field — surfaced by `software-dev` (Rule 7/12): the 4-field pin contradicted the "linkage in its own cell" + C-17-seed requirement. Optional/backward-compatible; HLR-084 intent unchanged.

## 3. Code-review (independent) → APPROVE-WITH-NITS → F1 applied
- **F1 (MEDIUM, single-source):** `checks_view.py` had a duplicate `_GROUP_SEVERITY` colour map used for the group header (row colour was already single-sourced from the accessor — reviewer confirmed no HIGH). Fix: `CheckGroupHeader` now takes `css_class` from the group's row (`group_rows[0].css_class`); `_GROUP_SEVERITY` deleted (0 code refs). **F2 (LOW, resolved by F1):** TC-084.1 header oracle was tautological → test now uses an independent `_EXPECTED_SEVERITY` literal for BOTH header and row assertions. F3/F4: informational, no change.
- Reviewer confirmed: row colour single-sourced ✓, C-17 seed strong (`.plain` verbatim + `spans==[]`, not crash-only) ✓, group order ✓, mount cap real ✓, 5th-field sound ✓, frozen-safe ✓.

## 4. Test results (post-F1)
- ruff `checks_view.py`: All checks passed.
- `tests/test_tui_checks_view.py`: **5 passed** (TC-084.1/.2/.4/.10 + C-17 seed) + doctests 3 passed.
- Regression `-k "change_service or check"`: **82 passed** (no regression from the change_service edit — C-19 broad run).
- `test_engine_unchanged.py`: 1 passed (0 frozen diffs).
- RED counterfactual: pre-increment `checks_view.py` absent → module import fails → all TC-084.* RED.

## 5. Axis check (gate) — APPROVE
- **Coverage:** LLR-084.1/.2/.4/.6(NO_RUN_TEXT) ↔ TC-084.1/.2/.4/.10 + C-17 seed. ✓
- **Certainty:** non-tautological post-F1; C-31 fixture-derived; C-17 seed strong; mount cap numeric. ✓
- **Evidence:** 5 passed + 82 regression + frozen guard + ruff; F1 re-verified; RED counterfactual. ✓

## 6. Carries (Inc-3/4)
App wiring (compose/rail/bindings/empty-state/refresh) = Inc-3; through-surface AT-084a–g via real `#patch_checks_run_button` = Inc-4; `styles.tcss` `.check-*`/`#checks_*` rules = Inc-3.
