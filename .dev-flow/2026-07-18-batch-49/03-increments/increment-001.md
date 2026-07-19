# Increment 1 — Issues Report MID visual upgrade (HLR-082)

**Status:** ✅ APPROVED (self, autonomous) after code-review BLOCK→fixed. **Files:** 4 (issues_view.py, app.py, styles.tcss, tests/test_tui_issues_view.py). **Test delta:** +10 / −0.

## 1. What changed
Render-only insight layer on `#screen_issues` (LLR-082.1–.6): `build_issues_severity_strip()` (Errors/Warnings/Info counts + microbars, RED/YELLOW/CYAN from insight_style) mounted as `#issues_severity_strip` and driven by `update_validation_issues_view`; leading severity glyph (`✗`/`⚠`/`•`, `_SEVERITY_GLYPH`) in `IssueGroupHeader.__init__`; border titles on `#issues_list_stack`/`#issues_hex_pane` (grouped-panel border moved to the titled stack); colored summary `Text` with `.plain` byte-identical. No engine/data/paging/filter change.

## 2. Code-review (independent) → BLOCK → resolved
- **F1 (HIGH):** `_update_issues_severity_strip` copied only half its sibling's guard — dropped `if strip is None: return`; the headless harness stubs `query_one`→None (not raise), so `None.update(...)` crashed 3 pre-existing Issues-paging tests (`test_tui_app.py`). The dev's new-file-only run missed it (C-19 partial-run trap). **Fix:** added the one-line None-guard (`app.py:6977-6978`). Verified: `pytest tests/test_tui_app.py tests/test_tui_issues_view.py` → **75 passed, 1 xfailed** (regressions gone); ruff clean; `test_engine_unchanged.py` 1 passed (0 frozen diffs).
- Reviewer confirmed the two GATE ATs genuinely strong: **AT-082a** uses an asymmetric 3/1/2 fixture + independent `Counter(i.severity …)` per-slot oracle (not circular); **AT-082f** asserts `.plain==payload verbatim` AND `spans==[]` with both `[/nope]` (crash-class) and `[link=…]` (injection) payloads. Count-hoist verified byte-identical `.plain`, empty-state preserved.

## 3. Test results (post-fix)
- `tests/test_tui_app.py` + `tests/test_tui_issues_view.py`: **75 passed, 1 xfailed** (33.5s).
- `ruff check s19_app/tui/app.py`: All checks passed.
- `tests/test_engine_unchanged.py`: 1 passed (0 frozen diffs).
- RED counterfactual (dev-captured): AT-082c `'ERRORS (1)'.startswith('✗')`→False pre-glyph; AT-082a fails on absent `#issues_severity_strip` pre-mount.

## 4. Axis check (gate) — APPROVE
- **Coverage:** LLR-082.1–.6 each ↔ TC; AT-082a–f present. ✓
- **Certainty:** gate ATs reviewer-verified non-vacuous; RED counterfactual captured. ✓
- **Evidence:** 75-passed re-run, ruff clean, frozen guard, reviewer BLOCK resolved + re-verified. ✓

## 5. Carries
- 6 Issues SVG baselines expected-drift → canonical-CI regen at closeout (with Inc-3 rail churn).
