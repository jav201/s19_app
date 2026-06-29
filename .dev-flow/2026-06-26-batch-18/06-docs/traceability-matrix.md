# Traceability Matrix — s19_app — Batch 2026-06-26-batch-18

> Two chains (per the Two-layer validation rule): functional (white-box) US→HLR→LLR→`TC`→file:line, and behavioral (black-box) US→`AT`→observed outcome. All ids reconciled to real on-disk nodes (V-5). Feature #11 — Q1 report legend + Q2 in-app legend modal.

---

## 1. Master table — functional chain (white-box)

| US | HLR | LLR | TC (real node) | File:line | Status |
|----|-----|-----|----------------|-----------|--------|
| US-022 | HLR-022 | LLR-022.1 (shared `legend.py`) | `test_tui_legend.py::test_legend_table_covers_all_severities`, `::test_legend_table_has_documented_artifacts_and_rows`, `::test_legend_data_not_in_frozen_color_policy` | `s19_app/tui/legend.py:33` (LEGEND_TABLE), `:103` (COLOUR_SEVERITY) | pass |
| US-022 | HLR-022 | LLR-022.2 (report emitter) | `test_report_service.py::test_legend_lines_renders_shared_table`, `::test_include_legend_default_true_and_validated` | `report_service.py:923` (`_legend_lines`), `:192` (`include_legend`) | pass |
| US-023 | HLR-023 | LLR-023.1 (`LegendScreen`) | `test_tui_legend.py::test_tc023_1_modal_renders_all_table_rows` | `s19_app/tui/screens.py:474` | pass |
| US-023 | HLR-023 | LLR-023.2 (buttons + dispatch + `k` binding) | `test_tui_legend.py::test_tc023_2_mac_issues_buttons_present_a2l_absent` | `app.py:563` (binding), `:1171`/`:2477` (buttons), `:3059` (`action_show_legend`), `:7511` (dispatch) | pass |
| US-023 | HLR-023 | LLR-023.3 (C-13 geometry) | `test_tui_legend.py::test_at023e_c13_geometry_at_80_cols` | measurement over `app.py` views + `styles.tcss` `#legend_dialog`/`#legend_body` | pass |
| (shared) | HLR-022/023 | Single-source anti-drift | `test_tui_legend.py::test_tc_s2_report_and_modal_render_same_rows` | `legend.py` ↔ `_legend_lines` ↔ `LegendScreen` | pass |

## 1b. Behavioral chain (black-box)

| US | Acceptance test (real node) | Shipped surface | Observed outcome / deliverable | Status |
|----|-----------------------------|-----------------|--------------------------------|--------|
| US-022 | `test_report_includes_legend_with_documented_rows` (AT-022a) | `generate_project_report` → `reports/<ts>-report.md` | report file contains `## Legend` + every colour→meaning row | pass |
| US-022 | `test_report_omits_legend_when_disabled` (AT-022b, negative) | same, `include_legend=False` | legend section absent | pass |
| US-023 | `test_at023a_a2l_legend_opens_via_key` (AT-023a) | A2L view → `k` key | rendered `LegendScreen` with A2L rows | pass |
| US-023 | `test_at023b_mac_legend_button_opens` (AT-023b) | `#mac_legend_button` | modal with MAC rows | pass |
| US-023 | `test_at023c_issues_legend_button_opens` (AT-023c) | `#issues_legend_button` | modal with Issues rows | pass |
| US-023 | `test_at023d_close_dismisses_modal` (AT-023d) | `#legend_close` | modal dismissed | pass |
| US-023 | `test_at023e_c13_geometry_at_80_cols` (AT-023e) | 80-col render | MAC/Issues buttons on-screen; A2L 0 buttons; modal within terminal | pass |
| US-023 | `test_at023f_legend_shows_without_file_loaded` (AT-023f, empty) | `k` key, no file | static 12-row legend still shows | pass |

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| User stories | 2 / 2 covered (100%) |
| HLR | 2 / 2 implemented (100%) |
| LLR | 5 / 5 implemented (100%) |
| Acceptance tests (`AT`) | 8 pass / 0 fail |
| Test cases (`TC`) | 8 pass / 0 fail (incl. TC-S1 ×2, TC-frozen-diff, TC-S2) |
| Orphans | 0 |

---

## 3. Detected gaps

| ID | Type | Description | Proposed action |
|----|------|-------------|-----------------|
| G-1 | snapshot (process) | SVG baselines for `#screen_a2l`/`#screen_mac`/`#screen_issues` + footer skip locally | Regenerate in canonical CI at PR; `tui-ci` authoritative |

---

## 4. Changes from previous batch

| Type | Item | Detail |
|------|------|--------|
| new | `s19_app/tui/legend.py` | `LEGEND_TABLE` single source + `COLOUR_SEVERITY` anti-drift |
| new | `LegendScreen` (`screens.py`) | read-only legend modal |
| modified | `report_service.py` | `_legend_lines` + `ReportOptions.include_legend` |
| modified | `app.py` | MAC/Issues Legend buttons + `k` binding + `action_show_legend` |
| amended | LLR-023.2 / .3 | §6.5 A1 — A2L button → `k` key (C-13 measurement) |

---

## 5. Quick bidirectional mapping

### 5.1 By user story
- **US-022** → HLR-022 → LLR-022.1, LLR-022.2 → TC-S1 ×2, TC-frozen-diff, TC-022.1, TC-022.2 + AT-022a/b
- **US-023** → HLR-023 → LLR-023.1, LLR-023.2, LLR-023.3 → TC-023.1, TC-023.2, AT-023e + AT-023a–f; TC-S2 (shared)

### 5.2 By code file
- `s19_app/tui/legend.py` → LLR-022.1 → TC-S1, TC-frozen-diff
- `report_service.py` → LLR-022.2 → TC-022.1/.2, AT-022a/b
- `s19_app/tui/screens.py` → LLR-023.1 → TC-023.1, AT-023a–f
- `s19_app/tui/app.py` → LLR-023.2 → TC-023.2, AT-023a/b/c
- `s19_app/tui/styles.tcss` → LLR-023.1/.3 → AT-023e

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | `2026-06-26-batch-18` |
| Closing date | 2026-06-28 (pending commit/PR + Obsidian sync) |
| Validation passed | yes (Phase 4 PASS) |
| Synced to Obsidian | no (pending PR merge) |
