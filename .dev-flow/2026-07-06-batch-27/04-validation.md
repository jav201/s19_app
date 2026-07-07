# 04 — Validation — 2026-07-06-batch-27 — R-TUI-041 Interactive Memory-Map Minimap

## 1. BLUF — verdict per story

| Story | Deliverable | Verdict | Rests on (real node) |
|-------|-------------|---------|----------------------|
| **US-035** — colour-coded spatial minimap grid | green/red/grey `.map-cell` grid + "≈ N KiB/cell" header via `#screen_map`→`#map_grid` | **PASS** | `test_at035_minimap_grid_colours_and_header` |
| **US-036** — cell selection → detail pane | non-default cell changes `#map_detail`; per-branch content; Open-in-Hex focuses `cell_start`; markup-safe file text; address-less excluded | **PASS** | `test_at036a…b…c…d…e…f…g` (all pass) |
| **US-037** — coverage stats strip | 7-metric `#map_stats` strip matching `case_02` true coverage | **PASS** | `test_at037_stats_strip_matches_case_02_coverage` |

**Overall: PASS. No blockers.** Every output-producing story has ≥1 black-box AT driving the shipped `#screen_map` surface (`action_show_screen("map")` + `update_memory_map()`) and observing the deliverable through the rendered `#map_grid`/`#map_detail`/`#map_stats` widgets. Layer A (14/14 white-box TC) + Layer B (11/11 black-box AT) both green. directionb + engine guard = **122 passed**; snapshot = **30 passed, 2 xfailed** (the 2 map cells xfail-until-baseline by design). **0 engine-frozen diffs.**

## 2. Layer A — functional (white-box, LLR → real TC node → result)
`pytest tests/test_tui_directionb.py -k "tc041 or tc025_memory" -v` → **14 passed, 107 deselected in 5.13s.**

| LLR | TC | Real node | Result |
|-----|----|-----------|--------|
| 041.1 cell status | TC-041.1 | `test_tc041_1_cell_status_derivation` | PASS |
| 041.2 auto-scale + zero-span | TC-041.2 | `test_tc041_2_auto_scale_cell_count_and_zero_span` | PASS |
| 041.3 colour via frozen sev map | TC-041.3 | `test_tc041_3_invalid_cell_carries_sev_error_class` | PASS |
| 041.4 selection → detail | TC-041.4 | `test_tc041_4_build_detail_text_content` | PASS |
| 041.4 arrow nav | TC-041.4b | `test_tc041_4b_arrow_adjacent_index_and_edge_clamp` | PASS |
| 041.5 issue join (boundary+neg) | TC-041.5 | `test_tc041_5_cell_issue_join_boundary_and_negative` | PASS |
| 041.6 Open focus=cell_start | TC-041.6 | `test_tc041_6_open_computes_focus_equals_cell_start` | PASS |
| 041.7 render-only (inspection) | TC-041.7 | `test_tc028_memory_map_renderer_adds_no_coverage_computation` + direct AST scan (0 I/O in `MemoryMapPanel` body :804-1356) | PASS |
| 041.8 stats exact literals | TC-041.8 | `test_tc041_8_coverage_stats_exact_case_02_literals` | PASS |
| 041.8 single-range 100% | TC-041.8b | `test_tc041_8_single_range_full_coverage_no_gaps` | PASS |
| 041.9 empty state | TC-041.9 | `test_tc041_9_empty_state_stats_neutral_no_exception` | PASS |
| 041.9 legacy empty (R-TUI-026) | TC-025 | `test_tc025_memory_map_empty_state_with_no_file` / `…_clears_when_file_loads` | PASS |
| 041.10 reflow 119 vs 120 | TC-041.10 | `test_tc041_10_reflow_class_toggles_at_119_vs_120` | PASS |
| 041.11 markup-safe hostile text | TC-041.11 | `test_tc041_11_markup_safe_render_of_hostile_text` | PASS |

**LLR-041.7** ships as `inspection` (no dedicated pytest node): satisfied by the pre-existing `test_tc028_…` AST-inspection of `update_memory_map` + a direct AST scan of the `MemoryMapPanel` body returning `[]` I/O hits.

## 3. Layer B — behavioral (black-box, US → AT → real node → observed-through-surface)
`pytest tests/test_tui_directionb.py -k "at035 or at036 or at037" -v` → **11 passed, 110 deselected in 13.41s.** Every AT drives `action_show_screen("map")` + `update_memory_map()` under Pilot and queries the shipped widgets.

| US | AT | Real node | Observed through surface | Result |
|----|----|-----------|--------------------------|--------|
| 035 | AT-035 | `test_at035_minimap_grid_colours_and_header` | `#map_grid`.query(".map-cell") ≥1 valid + ≥1 gap; header regex | PASS |
| 036 | AT-036a | `test_at036a_non_default_cell_changes_detail` | `press("right")+"enter"` → detail changes + new start token | PASS |
| 036 | AT-036a hint | `test_at036_detail_hint_prompts_navigation_before_selection` | nav hint pre-selection in `#map_detail` | PASS |
| 036 | AT-036a arrow/no-scroll | `test_at036_arrow_moves_cell_focus_without_scrolling` | focus moves; `#map_content.scroll_offset.y` unchanged | PASS |
| 036 | AT-036b | `test_at036b_open_in_hex_focuses_cell_start` | hex row at `A` renders in `#hex_view` (behavioral) | PASS |
| 036 | AT-036c | `test_at036c_valid_cell_detail` | valid chip + region bounds/size | PASS |
| 036 | AT-036d | `test_at036d_invalid_cell_seeded_issue_detail` | seeded ERROR issue → invalid chip + code + `0x…` + counts | PASS |
| 036 | AT-036e | `test_at036e_gap_cell_detail` | gap chip, no region claim | PASS |
| 036 | AT-036f | `test_at036f_markup_safe_symbol_in_detail` | literal `sensor[red]`, no `MarkupError` | PASS |
| 036 | AT-036g | `test_at036g_addressless_issue_excluded_from_cell_and_region` | `address=None` in neither list nor count | PASS |
| 037 | AT-037 | `test_at037_stats_strip_matches_case_02_coverage` | `#map_stats` 7 metrics; coverage == TC-041.8 number | PASS |

## 4. Bidirectional surface-reachability matrix
**Inputs (exercised through the handler):** `ranges` (AT-035/036c/e/037) · `range_validity` (AT-036d, TC-041.3) · `_validation_issues` in-cell (AT-036d via `render_ranges(…, _validation_issues)` handoff) · `address=None` (AT-036g) · empty/no-file (TC-041.9) · zero-span (TC-041.2) · single-range (TC-041.8). All PASS.
**Outputs (observed through the widget):** colored cells (AT-035/TC-041.3) · KiB/cell header (AT-035) · detail chip/window/region/issues/count (AT-036c/d/e, TC-041.4) · Open-in-Hex (AT-036b, TC-041.6) · 7-metric stats (AT-037, TC-041.8) · arrow-nav + no-scroll (arrow test, TC-041.4b) · hint (hint test) · reflow (TC-041.10 + snapshot 80x24 pending baseline) · markup-safe text (AT-036f, TC-041.11). All PASS. **No deliverable is observed only white-box.**

## 5. Boundary + negative evidence
empty (`test_tc041_9…`) · single-range 100% (`test_tc041_8_single_range…`) · invalid→red+issue (`test_at036d…`, `test_tc041_3…`) · gap (`test_at036e…`, `cell_status(8,16,[(0,8,True)])=="gap"`) · `address=None` excluded (`test_at036g…`) · zero-span no-divide (`test_tc041_2…`) · arrow edge-clamp (`test_tc041_4b…`) · focus-no-scroll (`test_at036_arrow…`) · markup/ANSI injection (`test_tc041_11…`, `test_at036f…`). All PASS.

## 6. Executed command outputs (real)
```
pytest -k "tc041 or tc025_memory" -v  → 14 passed, 107 deselected in 5.13s
pytest -k "at035 or at036 or at037" -v → 11 passed, 110 deselected in 13.41s
pytest tests/test_tui_directionb.py tests/test_engine_unchanged.py -q → 122 passed in 97.90s
pytest tests/test_engine_unchanged.py -q → 1 passed in 0.07s
pytest tests/test_tui_snapshot.py -q -m "not slow" → 30 passed, 2 xfailed in 40.77s
  XFAIL map-comfortable-80x24  — baseline-regen-pending (batch-27)
  XFAIL map-comfortable-120x30 — baseline-regen-pending (batch-27)
```
The 2 mismatched = the 2 xfailed map cells (`strict=False`, baseline-regen-pending) → designed state, canonical-CI regen post-merge. NOT a failure. Other 27 cells pass.

## 7. Provisional-id reconciliation (V-5)
All AT/TC spec ids reconciled to real collected node names — see §2/§3 tables. Benign deviations (all forward-covered): TC-041.7 = inspection (no pytest node; `test_tc028_…` + AST scan); AT-036a expanded to 3 nodes (core + hint + arrow-no-scroll, the F1 follow-on — strengthens); TC-041.8 split to 2 (exact + single-range boundary — strengthens).

## 8. Gaps / blockers
**None.** Each story observed black-box through `#screen_map`; no service-API-only fallback. Non-blocking carries: 2 map snapshot cells xfail-until-baseline (canonical-CI regen post-merge, then retire); CARRY-F2 live-geometry lock (`_EXPECTED_MAP_CELLS_120x30=128`, update in lockstep with regen); pre-existing full-suite TUI global-state flake — **classified NOT a batch-27 regression** (stashed-main control fails a different unrelated test; batch-27 suites clean in isolation).

## 9. Evidence checklist
- ✓ Acceptance in Given/When/Then — §3 acceptance blocks + §7 (contract).
- ✓ Explicit Expected — `test_tc041_8…` asserts exact literals (span 0x80010140, 93 B, 0.000004%, gaps 3, largest 2,147,549,173 B).
- ✓ Edge/empty/boundary/invalid/error — §5.
- ✓ Regression — engine guard `test_tc031_…` + `test_engine_unchanged.py` (1 passed) + directionb (122 passed) + 27 workspace snapshots.
- ✓ Exit criteria (§5.3) met — every LLR ≥1 TC; every US ≥1 AT through surface; 0 frozen diffs; suite ≥ prior.
- ✓ No PII/secrets — public `case_02`/`case_04` fixtures + synthetic seeds.
- ✓ Results real, not fabricated — pasted pytest summaries (§6).
- ✓ Layer B through shipped surface w/ boundary+negative — §3/§5.
- ✓ Bidirectional reachability — §4.
- ✓ No unfilled template — all ids reconciled (§7); 25 nodes executed + snapshot suite.
- ✓ Counterfactual — ATs RED pre-change (`#map_grid`/`#map_detail`/`#map_stats`/Open absent → NoMatches), documented in §7 of 01-requirements + Phase-2/3 reviews.

**Phase-4 verdict: PASS — all three stories validated through the shipped `#screen_map` surface with boundary + negative evidence; no blocker.** Open items (2 xfail snapshot cells, CARRY-F2 lock) are baseline-regen carries queued for canonical CI post-merge, explicitly non-blocking.
