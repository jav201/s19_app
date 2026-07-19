# Increment 4 — CHECKS hex peek + run/undo refresh wiring + through-surface ATs (LLR-084.5/.7/.8)

**Status:** ✅ APPROVED (self, autonomous). Code-review INLINE (orchestrator). **Files:** 2 (app.py, tests/test_tui_checks_screen.py) + 1 batch-consequence test fix (test_tui_patch_history_strip.py). **Test delta:** +6 / −0.

## 1. What changed
- **LLR-084.5** — `on_check_row_selected` → `_update_checks_hex_pane` (app.py:7295/7319), faithful mirror of `_update_issues_hex_pane`: `not screen_stack` guard, `query("#checks_hex_pane").first(Static)` + `if pane is None: return` (F1 guard present), placeholder for non-int address/no-file, else `render_hex_view_text(mem_map, address, aligned±6 rows, None)`.
- **LLR-084.7** — `self.update_checks_view()` added at BOTH `panel.refresh_check_results(...)` sites (post-run + undo/redo clear) so the CHECKS screen and Patch panel read one `last_check_result`.
- **LLR-084.8** — proven end-to-end by AT-084g.

## 2. Inline code-review — APPROVE
- Hex handler correct + F1-guarded; mirrors the approved Issues peek. Wiring at both refresh sites.
- **AT-084a (C-12):** drives the REAL `#patch_checks_run_button` (`_run_checks`), fixture integrity FIRST (2/1/3), header order fail→uncheckable→pass, each row's distinct `sev-*` class (swap fails). `_select_check_row` uses real focus+Enter (C-16). AT-084b live-count strip. AT-084g `.plain` verbatim + `spans==[]`. Non-vacuous; RED counterfactuals captured (AT-084c/TC-084.11 → empty pane when handler neutered).

## 3. §6.5 AMD-2 (AT-084c discriminator)
`0x102` literally can't appear in the pane (`render_hex_view_text` labels rows by 16-byte-aligned base → `0x00000100`). Resolved to assert the aligned base `0x00000100`; **TC-084.11 cross-checks** `0x9000`→`0x00009000`, so the pair proves the pane reflects the SELECTED row's address. Surfaced fail-loud by `software-dev`, ratified.

## 4. Test results
- ruff (2 files): All checks passed.
- `tests/test_tui_checks_screen.py`: **11 passed** (5 Inc-3 + 6 Inc-4: AT-084a/b/c/f/g + TC-084.11).
- `tests/test_tui_directionb.py` (FULL): **174 passed**.
- `test_engine_unchanged.py`: 1 passed (0 frozen diffs).
- `tests/ -k "check or patch"`: initially 2 failed / 253 passed →
  - `test_tc081_4_no_binding_diff` — the C-28 binding-census guard tripped on Inc-3's deliberate `9` rail-nav binding (HLR-083, `show=False`). **FIXED** by sanctioning `show_screen('checks')` in `_SANCTIONED_BINDING_MARKERS` (batch-consequence, the mechanism working as designed). Now passes.
  - `test_tc016s_density_layout_snapshot[patch-comfortable-120x30]` — EXPECTED rail-drift (9th item redraws every screen); canonical-CI regen owed (R-5/C-30), NOT local.
- RED counterfactual: AT-084c/TC-084.11 → `pane=''` when `on_check_row_selected` neutered.

## 5. Carries → closeout
- Canonical-CI snapshot regen for the batch drift (9-item rail on every screen + Issues strip + new Checks screen baselines).
- Stale "eight"/"1..8" docstring prose (Inc-3 LOW carry).
