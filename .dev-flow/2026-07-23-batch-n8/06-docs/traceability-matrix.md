# 06-docs — traceability matrix · batch-n8 (comprehensive per-view Legend)

Dual traceability: US → HLR → LLR → AT/TC → shipped code + test node. All AT/TC GREEN
(see 04-validation.md). `§6.5 AMD-*` OVERRIDE the §3/§4 body on conflict.

| US | HLR | LLR | AT / TC | Test node | Code |
|----|-----|-----|---------|-----------|------|
| US-N8-1 Workspace | HLR-N8-1 | 1.1/1.2/1.3/1.4 | AT-N8-01, TC-N8-01 | `test_at_n8_01_workspace_card_and_no_severity_key`, `test_tc_n8_01_workspace_example_data`, `test_workspace_is_example_only_no_severity_key_required`, `test_n1_workspace_is_example_only` | `legend.LEGEND_EXAMPLES["workspace"]`, `screens.LegendScreen._render_card`, `app._SCREEN_LEGEND_SECTIONS["workspace"]=()` |
| US-N8-2 A2L | HLR-N8-2 | 2.1/2.2 | AT-N8-02, TC-N8-04 (AMD-8) | `test_at_n8_02_a2l_card_above_key`, `test_tc_n8_04_a2l_example_data`, `test_tc_n8_04_a2l_card_covers_every_live_column` | `LEGEND_EXAMPLES["a2l"]`, `_render_card`+`_render_key` |
| US-N8-3 Map | HLR-N8-3 | 3.1/3.2/3.3 | AT-N8-03 | `test_at_n8_03_map_band_key_and_overlays`, `test_tc_n8_05_map_example_data`, `test_map_card_contains_both_hex_overlay_meanings`, `test_band_key_*` | `LEGEND_EXAMPLES["map"]`, `build_band_key_rows`, `screens._render_key` (map branch, `markup=False`), `app._SCREEN_LEGEND_SECTIONS["map"]=()` |
| US-N8-4 MAC | HLR-N8-4 | 4.1/4.2/4.3 | AT-N8-04, AT-N8-07 | `test_at_n8_04_mac_card_key_and_reconciliation`, `test_at_n8_07_mac_warning_sample_painted_warning_style`, `test_mac_card_carries_orange_reconciliation`, `test_mac_card_has_a_warning_sample_row` | `LEGEND_EXAMPLES["mac"]` (`warning_sample` role), `screens._MAC_WARNING_SAMPLE_STYLE` + `#legend_mac_warning_sample`, coupled to `app._SEVERITY_TO_RICH_STYLE[WARNING]` |
| US-N8-5 Issues | HLR-N8-5 | 5.1/5.2 | AT-N8-05 | `test_at_n8_05_issues_card_above_key`, `test_tc_n8_09_issues_example_data` | `LEGEND_EXAMPLES["issues"]` |
| (cross) | HLR-N8-6 | 6.1/6.2 | AT-N8-06 | `test_at_n8_06_long_key_row_is_static_and_wraps` | `screens.LegendScreen._render_key` (Static rows), `styles.tcss .legend-card-*` |
| (cross) | — | AMD-9/F3 | TC-N8-11 | `test_tc_n8_11_every_line_parses_without_markup_error`, `test_tc_n8_11_escaped_brackets_round_trip_to_literal` | `legend.LEGEND_EXAMPLES` (escaped literal brackets) |
| N1 regression (AMD-4) | — | — | — | `test_n1_legend_scoped_per_screen` (map→`Entropy bands`), `test_n1_unmapped_screen_shows_full_table` (re-pointed to `flow`) | `app._SCREEN_LEGEND_SECTIONS` |
| batch-51 legend (regression) | HLR-023/059 | — | — | `tests/test_tui_legend.py` (all, `_modal_meanings` `Label`→`Static`; 4 full-table tests → `flow`) | `screens.LegendScreen` |

## Frozen-set audit
No frozen-engine edit. Touched only NON-frozen: `legend.py`, `screens.py`, `app.py`,
`styles.tcss` + test files. `color_policy.py`/`a2l.py`/`mac.py` read-only oracles
(`_SEVERITY_TO_RICH_STYLE` lives in `app.py`, not frozen).

## Requirements.md
N-series items (N1..N8) are tracked via the dev-flow batch docs + backlog, not repo
`REQUIREMENTS.md` R-* rows (N1..N7 precedent). N8 extends N1 (per-screen scoping,
`7ba2631`); no new permanent R-* row added — deliberate, matches precedent.
