# Increment 5 — retire entropy modal + delete dead grid machinery (HLR-045D, R-TUI-041/050/051)

Split 5a (source deletions) + 5b (test deletions + AT-075/076 + snapshot). Net −2192 lines.

1. **What changed:** deleted the entropy pop-up + all dead grid machinery.
   - screens.py: `EntropyViewerScreen`, `EntropyCell`(+.Selected), `ENTROPY_BAND_COLOUR`,
     `ENTROPY_LOW_CONFIDENCE_STYLE`, the MODAL `ENTROPY_BAND_MEANING`, `ENTROPY_MAX_ROWS` + modal
     internals + 5 now-unused imports.
   - screens_directionb.py: `MapCell`(+.Selected), `adjacent_cell_index`, `_ARROW_DELTAS`,
     `focus_adjacent_cell`, `on_map_cell_selected`, `on_button_pressed`, `_cell_tooltip`,
     `_grid_geometry`, `MAP_GRID_COLS`, `DEFAULT_GRID_COLS/ROWS`, `_CELL_GLYPH`, `_KIB`,
     `#map_open_hex_button`; F1 Data-Flow docstring reconciled to the band view.
   - app.py: `action_show_entropy`, `_focus_entropy_target`, `Binding("e","show_entropy")`, import.
   - styles.tcss: `.map-cell`, `#entropy_*`, `.entropy-*`.
   - DELETED tests/test_tui_entropy_viewer.py (918 lines). test_tui_snapshot.py: dropped tc036s cells
     + `_batch37_entropy_drift_marks` + `_entropy_run_before`. test_tui_directionb.py: removed
     test_tc041_4b + 5 unused cell helpers; ADDED AT-075/076. Fixed stale comments
     (entropy_service.py docstring, test_loadfilescreen_input.py).
2. **Files:** 5a: screens.py, screens_directionb.py, app.py, styles.tcss, services/entropy_service.py.
   5b: test_tui_entropy_viewer.py (D), test_tui_snapshot.py, test_tui_directionb.py,
   test_loadfilescreen_input.py.
3. **How to test:** broad run (deletions ripple); `pytest tests/ --collect-only`; C-27; grep-gate.
4. **Results:** collection **1419 tests no error**; directionb+entropy_service+tui_app **250 passed /
   0 failed**; directionb **175 passed**; C-27 **0 frozen**; 2 map cells xfail; ruff clean. AT-075/076
   RED captured (git-stash revert → both fail → pop → green). **C-26 grep-gate: 0 live references** to
   any deleted symbol (residuals = comments + AT-076 assertions). `e` frees with no collision.
5. **Risks:** −2192 lines mitigated by the pre-deletion per-symbol C-26 census + broad cross-file run.
   Deleting test_tui_entropy_viewer.py drops ~30 modal tests; compute_entropy stays covered by
   test_entropy_service.py — no surviving-surface loss. KEEP-list (cell_status/build_detail_text/
   coverage_stats/OpenInHexRequested/entropy_style.ENTROPY_BAND_MEANING/action_page_*_context) verified live.
6. **Pending:** Inc-6 REQUIREMENTS.md amendments; post-merge snapshot regen (2 map cells).
7. **Next:** Inc-6 — REQUIREMENTS.md (add R-TUI-060/061/062; amend R-TUI-041; retire R-TUI-050/051).

Code-review: full independent pass, APPROVE-WITH-NITS 0 HIGH. F1 (MEDIUM stale Data-Flow docstring)
FIXED. Verified: 0 live deleted-symbol refs (grep + ruff F821), KEEP-list wired, coverage preserved,
e freed, ATs sound + RED, frozen 0. Axis check clean → APPROVE.
