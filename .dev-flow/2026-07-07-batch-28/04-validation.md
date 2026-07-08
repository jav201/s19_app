# 04 — Validation · batch-28 (R-TUI-042) · view enhancements

**BLUF:** Both validation layers PASS with **no blocker**. Full suite **1126 passed / 2 skipped /
23 xfailed / 0 failed** (17 min). Every user story is observed black-box through its shipped
screen surface (Layer B), every LLR has a passing white-box TC (Layer A), the bidirectional
surface-reachability matrix is complete, and the two regressions the Phase-3 full-suite gate
surfaced are fixed with counterfactual evidence. Snapshot drift for the 3 restyled views + the
entropy modal backdrop is `xfail-until-baseline` (canonical-CI regen post-merge). 0 engine-frozen
diffs. Method: the strategy in §5 of `01-requirements.md` was executed across the 4 increments
(each AT/TC authored + run, then independently re-run by the increment code-reviewer) and
confirmed by the whole-suite re-run; this artifact reconciles the provisional ids to the real
collected nodes (V-5) and records the evidence.

## Layer A — functional (white-box `TC-042.N` ↔ LLR), all in `tests/test_tui_directionb.py`

| LLR | TC | Real collected node | Result |
|-----|----|---------------------|--------|
| 042.1 A2L header-fixed | TC-042.1 | `test_at_038a_a2l_table_owns_scroll_header_fixed` (white-box scroll-ownership assert) | pass |
| 042.2 A2L density | TC-042.2 | `test_tc_042_2_density_class_text_cells_and_paging` | pass |
| 042.3 Issues grouping | TC-042.3 | `test_tc_042_3_group_order_and_header_counts` | pass |
| 042.4 code chips | TC-042.4 | `test_tc_042_4_chip_colour_via_policy_no_hardcoded_hex` | pass |
| 042.5 selection→peek | TC-042.5 | `test_tc_042_5_selection_handler_drives_peek` | pass |
| 042.6 paging/filter/observables | TC-042.6 | `test_tc_042_6_paging_window_preserved_and_filter_scopes` | pass |
| 042.6 mass-mount cap (perf-fix) | TC-042.6b | `test_at_039g_tc_042_6b_full_page_render_is_row_capped_and_settles` | pass |
| 042.7 coverage bar | TC-042.7 | `test_tc_042_7_coverage_bar_arithmetic_pure` | pass |
| 042.8 memory strip | TC-042.8 | `test_tc_042_8_strip_colour_is_pure_reuse_of_batch27_helpers` | pass |
| 042.9 stat pane | TC-042.9 | `test_tc_042_9_stat_pane_values_pure` | pass |
| 042.10 markup-safe (C-17) | TC-042.10 | `test_tc_042_10_markup_safe_renderables_and_no_from_markup` | pass |
| 042.11 geometry/empty-state | TC-042.11 | `test_at040_workspace_geometry_no_clip_80_and_120` (80×24 + 120×40, incl. `#a2l_scroll` + `#ws_memstrip`) | pass |
| 042.12 engine-frozen invariant | TC-042.12 | `test_tc_042_12_memory_strip_touches_no_frozen_path` + `tests/test_engine_unchanged.py` + `test_tc031_*` | pass (0 frozen diffs) |

## Layer B — behavioral acceptance (black-box `AT-NNN` ↔ US), through the shipped screen surface

| US | Surface | AT → real node | Kind / evidence |
|----|---------|----------------|-----------------|
| US-038 | `#screen_a2l` → `#a2l_tags_list` | AT-038a `test_at_038a_a2l_table_owns_scroll_header_fixed` | **C-16 real** `pilot.press("pagedown")`; asserts `scroll_offset.y>0` + header shown (non-tautology) |
| | | AT-038b `test_at_038b_a2l_pane_carries_density_compact_class` | density class observable |
| | | AT-038c `test_at_038c_a2l_error_row_keeps_severity_style` | regression: `sev-error` preserved |
| | | AT-038d `test_at_038d_a2l_empty_state_no_file` | boundary: no-file, no crash |
| US-039 | `#screen_issues` → grouped panel \| `#issues_hex_pane` | AT-039a `..._group_headers_carry_whole_filtered_counts_and_chips` | queryable `.issue-group-header`(count) + `.issue-code-chip` |
| | | AT-039b `..._groups_render_in_error_warning_info_order` | per-branch order (ERROR/WARNING/INFO seeded) |
| | | AT-039c `..._real_click_repaints_hex_peek_and_none_is_neutral` | **C-16 real** click/Enter, non-default, content-changed + address-None branch |
| | | AT-039d `..._zero_issues_empty_state_and_neutral_peek` | boundary: empty |
| | | AT-039e `..._c17_hostile_code_symbol_message_render_literal` | **C-17** brackets+ANSI+`[link]` literal; no MarkupError/OSC-8/leak/crash |
| | | AT-039f `..._dos_bound_large_issue_list_mounts_one_window` | DoS: 5000 issues → bounded mount |
| | | AT-039g `..._full_page_render_is_row_capped_and_settles` | perf-regression guard: 200-issue page → mounted ≤ `_GROUP_DISPLAY_MAX`, render settles |
| US-040 | `#screen_workspace` / `#ws_left` | AT-040a `test_at040a_per_range_micro_bar_colour_and_width` | per-branch: valid≠invalid colour + larger→wider bar |
| | | AT-040b `test_at040b_memory_strip_valid_and_gap_cells` / `..._is_workspace_only` / `..._empty_when_no_file` / `..._cell_count_is_bounded` | strip valid+gap cells · Workspace-only · empty · bounded |
| | | AT-040c `test_at040c_stat_pane_values_match_image` | exact coverage%/counts; error count differs vs clean |
| | | AT-040d `test_at040d_stat_pane_neutral_when_no_file` | boundary: neutral |
| | | AT-040e `test_at040e_stat_pane_has_no_entropy_element` | scope-negative: no entropy (D3) |

## Bidirectional surface-reachability matrix
- **Inputs exercised through the handler** (not just a service): rail navigation (`press "2"/"5"/"1"`),
  real DataTable scroll (`pagedown`), real issue-row click/Enter, severity-filter scoping, paging
  window, no-file / empty-issues / gapped-image / error-image / large-N(5000) / full-page(200) fixtures,
  hostile file-derived `.code`/`.symbol`/`.message`.
- **Outputs/deliverables observed through the surface:** A2L density class + fixed header + preserved
  `sev-error` rows; Issues `.issue-group-header` counts + `.issue-code-chip` + hex-peek repaint;
  Workspace per-range bar colour+width + memory-strip cells + stat-pane exact values + absence of
  entropy. Every named input dimension and every named deliverable is reached through the shipped
  screen, not only a service API.

## Counterfactual / escaped-bug regressions (found by the Phase-3 full-suite gate, fixed)
1. **`update_workspace_stats`/`update_memory_strip` None-crash** — RED pre-fix:
   `test_update_sections_caps_primary_ranges` + `..._mac_out_of_range` (AttributeError on the
   monkeypatched unit-test app); GREEN post-fix (None-guard). The 2 caps tests are the standing guard.
2. **Grouped-panel mass-mount perf regression** — counterfactual established by the
   **clean-`main` comparison**: `TestCrossFileCompatibilityPanelRender` = 7 passed / 34s on main vs
   4-5 failed / ~252-276s on the pre-fix branch (`textual.pilot.WaitForScreenTimeout`, ~600 widgets/
   render). GREEN post-fix (`_GROUP_DISPLAY_MAX=40`), and now guarded DIRECTLY by AT-039g (a future
   uncapped render fails it, not just the incidental tc_065 timeout).

## Snapshot (Layer-A visual regression) — deferred, non-blocking
23 xfailed cells: A2L (6) + Issues (6) + Workspace (6) restyled + entropy modal backdrop (2) +
pre-existing map/patch/diff scaffolds. Local regen FORBIDDEN (textual pinned 8.2.8; canonical-CI
`snapshot-regen.yml` only). Post-merge canonical regen retires the batch-28 xfails. An xfail cell is
not a failure (the batch-25/27 pattern).

## Gate assessment (exit criteria)
- **Coverage** ✅ — every US→AT and every LLR→TC chain exists and is GREEN; no orphan; matrix complete.
- **Certainty** ✅ — ATs observe the shipped surface; C-16 real-mechanism (AT-038a/039c/039g), C-17
  hostile-input (AT-039e), boundary + negative + scope-negative present; 2 regressions carry
  counterfactual evidence; no pass-that-cannot-fail.
- **Evidence** ✅ — full-suite node counts + real collected node ids + 0-frozen-diff guard + the
  main-comparison, all re-runnable.
- **Blocker check:** none (no story without a black-box deliverable observation; artifact fully
  executed, no template placeholders). → **Phase-4 APPROVE.**
