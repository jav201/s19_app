# Traceability Matrix · batch-28 (R-TUI-042)

Requirement **R-TUI-042** — prototype-approved view enhancements (A2L polish, Issues grouped-dense,
Workspace inline signal). All render-side; 0 engine-frozen diffs. Full suite 1126 passed / 0 failed.
Test file (unless noted): `tests/test_tui_directionb.py`.

| US | HLR | LLR | Code | White-box TC (node) | Black-box AT (node) | Status |
|----|-----|-----|------|---------------------|---------------------|--------|
| US-038 A2L polish | HLR-038 | 042.1 header-fixed | `app.py _compose_screen_a2l` | TC-042.1 `test_at_038a_a2l_table_owns_scroll_header_fixed` | AT-038a `test_at_038a_...` (real pagedown) | Automated |
| | | 042.2 compact density | `app.py` (cell_padding=0) · `styles.tcss #a2l_tags_pane.density-compact` | TC-042.2 `test_tc_042_2_density_class_text_cells_and_paging` | AT-038b `test_at_038b_...density_compact_class`; AT-038c `..._error_row_keeps_severity_style`; AT-038d `..._empty_state_no_file` | Automated |
| US-039 Issues dense | HLR-039.a | 042.3 grouping | `issues_view.py GroupedIssuesPanel` · `app.py _render_validation_issues_groups` | TC-042.3 `test_tc_042_3_group_order_and_header_counts` | AT-039a `..._group_headers_carry_whole_filtered_counts_and_chips`; AT-039b `..._error_warning_info_order` | Automated |
| | HLR-039.a | 042.4 code chips | `issues_view.py IssueRow` | TC-042.4 `test_tc_042_4_chip_colour_via_policy_no_hardcoded_hex` | (via AT-039a chip node) | Automated |
| | HLR-039.b | 042.5 selection→peek | `app.py on_issue_row_selected` · `_update_issues_hex_pane` | TC-042.5 `test_tc_042_5_selection_handler_drives_peek` | AT-039c `..._real_click_repaints_hex_peek_and_none_is_neutral` (C-16) | Automated |
| | HLR-039.a | 042.6 paging/filter/observ. + DoS + cap | `issues_view.py _GROUP_DISPLAY_MAX` · `app.py` window | TC-042.6 `test_tc_042_6_paging_window_preserved_and_filter_scopes`; TC-042.6b `test_at_039g_..._row_capped_and_settles` | AT-039f `..._dos_bound_large_issue_list_mounts_one_window`; AT-039g `..._full_page_render_is_row_capped_and_settles` | Automated |
| | HLR-039.a | 042.10 markup-safe (C-17) | `issues_view.py safe_text` | TC-042.10 `test_tc_042_10_markup_safe_renderables_and_no_from_markup` | AT-039e `..._c17_hostile_code_symbol_message_render_literal` | Automated |
| | HLR-039.a | (empty-state) | `issues_view.py` EMPTY_TEXT | — | AT-039d `..._zero_issues_empty_state_and_neutral_peek` | Automated |
| US-040 Workspace | HLR-040.a | 042.7 coverage micro-bar | `app.py coverage_bar_cells / update_sections` | TC-042.7 `test_tc_042_7_coverage_bar_arithmetic_pure` | AT-040a `test_at040a_per_range_micro_bar_colour_and_width` | Automated |
| | HLR-040.b | 042.8 memory strip | `app.py update_memory_strip` · `styles.tcss #ws_memstrip/.strip-cell` | TC-042.8 `test_tc_042_8_strip_colour_is_pure_reuse_of_batch27_helpers` | AT-040b ×4 (`..._valid_and_gap_cells` / `..._is_workspace_only` / `..._empty_when_no_file` / `..._cell_count_is_bounded`) | Automated |
| | HLR-040.c | 042.9 stat pane | `app.py update_workspace_stats` · `styles.tcss #ws_stats` | TC-042.9 `test_tc_042_9_stat_pane_values_pure` | AT-040c `..._values_match_image`; AT-040d `..._neutral_when_no_file`; AT-040e `..._has_no_entropy_element` | Automated |
| (cross) | all | 042.11 geometry/empty-state | `styles.tcss` regimes | TC-042.11 `test_at040_workspace_geometry_no_clip_80_and_120` | (geometry gate) | Automated |
| (cross) | all | 042.12 engine-frozen invariant | — | TC-042.12 `test_tc_042_12_memory_strip_touches_no_frozen_path` + `test_engine_unchanged.py` + `test_tc031_*` | — | Automated (0 frozen diffs) |

**Regression guards (escaped-bug, `tests/test_tui_app.py`):** `test_update_sections_caps_primary_ranges` +
`..._mac_out_of_range` (None-guard); `TestCrossFileCompatibilityPanelRender` (grouped-panel mass-mount
perf, 7 passed / 34s == main).

**Snapshot (xfail-until-canonical-baseline, `tests/test_tui_snapshot.py`):** A2L / Issues / Workspace
restyled cells (18) + entropy-modal backdrop (2). Local regen FORBIDDEN; canonical-CI `snapshot-regen.yml`.

**Gaps:** none — every US→AT and every LLR→TC chain exists and is GREEN.
