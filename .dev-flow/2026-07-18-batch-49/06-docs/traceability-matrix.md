# Traceability Matrix — s19_app — Batch 2026-07-18-batch-49

Dual traceability: behavioral `US → AT → observed outcome` AND functional `US → HLR → LLR → TC`. All chains complete, 0 gaps.

| US | HLR | R-TUI | LLR | White-box TC | Black-box AT | Shipped surface | Status |
|---|---|---|---|---|---|---|---|
| US-082 | HLR-082 | R-TUI-082 | 082.1–.6 | TC-082.1–.5 | AT-082a–f | `#screen_issues` / `#issues_severity_strip` / group headers / summary | ✅ green |
| US-083 | HLR-083 | R-TUI-083 | 083.1–.6 | TC-083.1–.6 (rail census, `test_tui_directionb.py`) | AT-083a–b | activity rail key `9` / `#screen_checks` | ✅ green |
| US-083 | HLR-084 | R-TUI-084 | 084.1–.8 | TC-084.1–.11 (+ TC-084.9 consumer guard) | AT-084a–g | `#checks_grouped` / `#checks_aggregate_strip` / `#checks_hex_pane` | ✅ green |

**Gate ATs (8):** AT-082a, AT-082c, AT-082f, AT-083a, AT-084a, AT-084b, AT-084c, AT-084g — all pass through the shipped surface with fixture-integrity-first oracles + captured RED counterfactuals.

**Amendments:** §6.5 AMD-1 (`CheckDisplayRow` +`linkage_symbol` 5th field); AMD-2 (AT-084c discriminator = aligned base `0x00000100`, TC-084.11 cross-checks `0x9000`).

**Requirement→code map (REQUIREMENTS.md rows R-TUI-082/083/084):**
- R-TUI-082 → `issues_view.py::build_issues_severity_strip`/`_SEVERITY_GLYPH`/`IssueGroupHeader`; `app.py::_compose_screen_issues`/`update_validation_issues_view`/`_update_issues_severity_strip`; `styles.tcss` `#issues_*`.
- R-TUI-083 → `rail.py::RAIL_ENTRIES` (9th); `app.py::SCREEN_CONTAINER_IDS`/`BINDINGS`("9")/`compose`/`_compose_screen_checks`/`action_show_screen`(nav hook)/`_EMPTY_STATE_SCREENS`.
- R-TUI-084 → `checks_view.py` (`GroupedChecksPanel`/`CheckRow`/`CheckGroupHeader`/`build_checks_aggregate_strip`/`NO_RUN_TEXT`); `change_service.py::check_display_rows`/`CheckDisplayRow`; `app.py::update_checks_view`/`on_check_row_selected`/`_update_checks_hex_pane` + run/undo wiring.

**Validation evidence:** gate suite 1570 passed / 0 non-snapshot failures (`04-validation.md`); 21 `test_tc016s` snapshot cells = intended rail/strip drift, canonical-CI regen owed. 0 engine-frozen diffs.
