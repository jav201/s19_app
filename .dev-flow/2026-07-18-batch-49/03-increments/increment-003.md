# Increment 3 — CHECKS rail entry + screen + render-on-nav + empty states (HLR-083 + LLR-084.3/.6)

**Status:** ✅ APPROVED (self, autonomous). Code-review done INLINE (the delegated code-review agent hung ~10h → stopped; orchestrator reviewed inline). **Files:** 5 (rail.py, app.py, styles.tcss, tests/test_tui_directionb.py, tests/test_tui_checks_screen.py NEW) + a cross-increment docstring fixup (issues_view.py/checks_view.py, see below). **Test delta:** +5 (new screen tests) / −0; census assertions rewritten-in-place.

## 1. What changed
Ninth rail screen `#screen_checks` (key `9`): `RailEntry("checks","☑","C","Checks")`; `SCREEN_CONTAINER_IDS`; `Binding("9",…)`; compose insertion; `_compose_screen_checks` scaffold; `update_checks_view` driver (LLR-084.3); nav-refresh hook (083.6); `_EMPTY_STATE_SCREENS` registration (084.6); `#checks_*`/`.check-*` CSS. Consumes Inc-2 `checks_view.py` + `check_display_rows()`. Full R-2 census (8→9) in `test_tui_directionb.py`.

## 2. Escaped pre-existing defect (Inc-1) caught by Inc-3's full-file run + FIXED
The full `test_tui_directionb.py` run (which Inc-1's gates never did — only `-k` subsets, the C-19 partial-run gap) surfaced `test_tc_042_10` failing: it does `assert "from_markup" not in issues_view_source`, and Inc-1's new docstring literally said "`Text.from_markup`". Fix (orchestrator, convention-respecting Rule 11): reworded the docstring token → "markup parsing" in **both** `issues_view.py` (Inc-1) and `checks_view.py` (Inc-2, same latent token). Verified: `grep from_markup` → 0 in both; guard + doctests 8 passed; **full `test_tui_directionb.py` → 174 passed / 0 failed.**

## 3. Inline code-review (orchestrator; delegated agent hung)
- **Census completeness (C-26):** independently grepped `tests/` for `== 8` / `[1..8]` / `12345678` / `EXPECTED_RAIL` / `len(RAIL_ENTRIES)` near rail/screen → 0 residual count assertions. The `test_tui_app.py == 8` hits are mac-width (unrelated, confirmed). Reverse-census extended 4 extra digit-string sites (TC-002/TC-003 pairs) beyond the architect's list.
- **`update_checks_view` (app.py:7051):** guards `not screen_stack` + `try/except` + `if panel is None: return` (Inc-1 F1 lesson APPLIED). Three-state: `last_check_result is None` → `render_no_run()`; else group+`render_groups`; no-file via `_EMPTY_STATE_SCREENS`. R-6 satisfied.
- **ATs strong:** AT-083a (C-10 — active screen changed off default + `-active` marker); AT-084e (R-6 — `.checks-no-run-note`==1 AND `.checks-empty-note`==0, distinct from empty run); TC-084.3 (fixture integrity first C-31, then row=4/header=3/strip). AT-084d (EmptyStatePanel + content hidden). All non-vacuous.
- **Frozen-safe:** `test_engine_unchanged.py` 1 passed.

## 4. Test results
- ruff (4 files): All checks passed.
- `tests/test_tui_checks_screen.py`: 5 passed (AT-083a/b, AT-084d/e, TC-084.3).
- `tests/test_tui_directionb.py` (FULL): **174 passed / 0 failed** (post docstring fix).
- `tests/ -k "rail or screen or show_screen"`: 83 passed.
- `test_engine_unchanged.py`: 1 passed (0 frozen diffs).
- RED counterfactual (AT-083a): pre-change 8 rail entries, no `#screen_checks` → `NoMatches`.

## 5. Findings / carries
- **LOW (cosmetic carry):** stale "eight"/"1..8" PROSE in ~7 test docstrings (`test_tui_directionb.py` :198/:408/:560/:637/:723/:854/:5810 + `test_loadfilescreen_input.py:61` comment). Non-functional (tests iterate the real 9 entries); not fixed to avoid churn — address in Phase-6 docs pass if desired.
- **Snapshot drift (expected, C-30/R-5):** 9th rail redraws every screen → large SVG delta; canonical-CI regen at closeout, NOT local.
- **PROCESS:** the delegated code-review agent hung ~10h with no completion notification; caught only when the operator flagged it. Byte-size monitoring is useless here (0-byte agent files). Going forward: actively wait on critical-path agents (TaskOutput block=true + re-poll) instead of ending the turn on a completion-notification-only assumption.

## 6. Pending (Inc-4)
Hex peek on row-select (`on_check_row_selected`/`_update_checks_hex_pane`, LLR-084.5); run/undo/redo refresh wiring (LLR-084.7); through-surface AT-084a/b/c/f/g via the real `#patch_checks_run_button`; TC-084.11 (uncheckable/outside-image `0x9000` hex).
