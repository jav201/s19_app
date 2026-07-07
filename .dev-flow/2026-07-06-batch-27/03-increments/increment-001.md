# Increment 001 — US-035 colour-coded minimap grid

**BLUF:** Replaced the monochrome text list with a colour-coded 2-D minimap grid (`MemoryMapPanel` `Static`→`Container` hosting `#map_grid` of `.map-cell` widgets). LLR-041.1/.2/.3/.7/.9/.11 delivered. `code-reviewer`: **OK to advance, 0 HIGH**. Ledger 1037→1039.

## 1. What changed
Six pure module functions extracted (`derive_image_span`, `cell_count_for_geometry`, `bytes_per_cell` [zero-span guarded], `cell_status` [valid/invalid/gap overlap], `status_to_css_class` [routes through frozen `css_class_for_severity`], `safe_text` [`rich.text.Text` explicit-style — the LLR-041.11 security pattern]). Panel keeps `render_ranges(ranges, range_validity)` signature → `update_memory_map` untouched. `#map_detail`/`#map_stats` empty placeholders for Inc 2/3.

## 2. Files modified (4 ≤ 5)
- `s19_app/tui/screens_directionb.py` — grid + 6 helpers.
- `s19_app/tui/styles.tcss` — `#map_header`/`#map_grid`/`.map-cell`/`#map_detail`/`#map_stats`.
- `tests/test_tui_directionb.py` — −3 TC-025 text-list tests, +`_install_case_04_loaded_file` + TC-041.1/.2/.3/.11 + AT-035.
- `tests/test_tui_snapshot.py` — `map-comfortable-120x30` → xfail-until-baseline.

## 3/4. Tests
- Ledger: base 1037 − 3 (superseded TC-025) + 5 (TC-041.1/.2/.3/.11 + AT-035) = **1039**.
- New tests `5 passed`; engine guard + directionb `103 passed`; snapshot `30 passed / 1 xfailed` (map cell); ruff clean (authored), mypy 0 new; **0 engine-frozen diffs**.
- Pre-existing full-suite flake (TUI global-state leakage across ~1000 tests) confirmed NOT a regression via stashed-main control run (different unrelated test fails on main).

## Code-review verdict (independent)
**OK to advance — 0 HIGH.** HIGH axes all PASS: LLR-041.3 colour routing (no hard-coded severity hex), LLR-041.11 markup safety (`Text(style=)`, TC-041.11 genuine counterfactual feeding `[red]`/`[/]`/ANSI), LLR-041.7 render-only (0 I/O in panel), LLR-041.1 half-open boundary correct (`cell_status(8,16,[(0,8,True)])=="gap"`), AT-035 genuinely black-box, supersession legitimate (removed tests asserted old text format; no survivor asserts old output).

## 5. Risks / carries
- **CARRY-F2 (MEDIUM):** shipped panel reads live `#map_grid.content_size`; helper arithmetic is pure/injected. When the map xfail is retired (snapshot-regen), ADD a Pilot test asserting `len(grid.query(".map-cell"))` is fixed at `size=(120,30)` to lock live geometry (batch-25 flap-avoidance).
- F1 (LOW) redundant `not ranges` guard; F3 (LOW) cosmetic trailing zero-width gap cells at tail — polish in Inc 2/3; F4 (LOW) `map-80x24` cell lands with the US-036/reflow increment (consistent deferral).
- Pre-existing `Optional` F401 in `test_tui_snapshot.py:57` (not ours) — separate cleanup.

## 6. Pending (later increments)
- **Inc 2 (US-036):** cell selection + `#map_detail` (status chip, window, covering region, cell-scoped issue join, region count) + Open-in-Hex (`update_hex_view`) + `_validation_issues` handoff into `update_memory_map` (the one app.py call-site change) + AT-036a–g + TC-041.4/.5/.6/.11(detail).
- **Inc 3 (US-037):** `#map_stats` strip + narrow reflow + `map-80x24` snapshot + TC-041.8/.9/.10.
- Baseline regen (canonical CI) + REQUIREMENTS.md R-TUI-041 body edit (Phase 6).

## 7. Next: Increment 2 (US-036).
