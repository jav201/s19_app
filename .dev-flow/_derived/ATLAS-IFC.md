<!-- DERIVED — DO NOT EDIT. Regenerate: devflow-validate.py --atlas --write -->
<!-- flow_version: 2026.08.24-rev46 | flow_hash: 9c1449ed815d267c | corpus: 65 requirement files | corpus digest: 5b7f63c6b38b0d98 -->

# ATLAS-IFC — how is the application addressed?

5 FLOW declaration(s) · 3 COMPONENT declaration(s) · 570 declared requirement heading ids — one row per declaration.

### FLOW `loaded_artifacts_readout` — .dev-flow/2026-08-21-batch-85/01-requirements.md:277
- node `render_slots` — owner LLR-85.1
- node `_build_project_row` — owner LLR-85.3
- node `_slot_state` — owner LLR-85.2
- node `_build_slot_row` — owner LLR-85.2
- node `_build_unload_all_row` — owner LLR-85.1

### FLOW `workspace_readout` — .dev-flow/2026-08-24-batch-86/01-requirements.md:323
- node `_apply_loaded_file` — owner LLR-86.1
- node `refresh_files` — owner LLR-86.3
- node `update_sections` — owner LLR-86.3
- node `update_memory_strip` — owner LLR-86.2
- node `update_workspace_stats` — owner LLR-86.5
- node `update_hex_view` — owner LLR-86.4
- node `update_a2l_view` — owner LLR-86.5
- node `_apply_empty_state` — owner LLR-86.2
- node `_refresh_loaded_panel` — owner LLR-86.6

### FLOW `workspace_find_goto` — .dev-flow/2026-08-24-batch-86/01-requirements.md:365
- node `_handle_search` — owner LLR-86.4
- node `_handle_goto` — owner LLR-86.4

### FLOW `rail_screen_activation` — .dev-flow/2026-08-24-batch-87/01-requirements.md:793
- node `on_rail_selected` — owner LLR-87.6
- node `action_show_screen` — owner LLR-87.6
- node `_active_view_name` — owner LLR-87.6

### FLOW `shell_regime` — .dev-flow/2026-08-24-batch-87/01-requirements.md:810
- node `on_mount` — owner LLR-87.6
- node `on_resize` — owner LLR-87.6
- node `_apply_width_regime` — owner LLR-87.6
- node `action_cycle_density` — owner LLR-87.6

### COMPONENT `loaded_panel` — .dev-flow/2026-08-21-batch-85/01-requirements.md:504
- inputs : loaded: Optional[LoadedFile] ; project: str
- outputs : 
- parent : screen_workspace
- surface : LoadedArtifactsPanel — the Loaded-artifacts panel on the Workspace rail screen (s19_app/tui/screens_directionb.py:1741)

| output | address | cardinality | consumers | owner |
|---|---|---|---|---|
| `panel_handle` | `query_one("#loaded_panel")` | 1 | 5 declared | LLR-87.1 |
| `slots_container` | `query_one("#loaded_slots")` | 1 | 3 declared | LLR-87.1 |
| `artifact_row_set` | `query(".loaded-slot")` | 4 | 2 declared | LLR-87.2 |
| `unload_all_row` | `query(".loaded-allrow")` | 1 | 1 declared | LLR-87.2 |
| `artifact_slots` | `query(".loaded-detail"), INDEXED POSITIONALLY` | 3 | 4 declared | LLR-87.3 |
| `project_row` | `query(".loaded-project-detail")` | 1 | 3 declared | LLR-87.3 |

### COMPONENT `screen_workspace` — .dev-flow/2026-08-24-batch-86/01-requirements.md:386
- inputs : loaded: Optional[LoadedFile] ; project: str ; workarea_files: list[Path] ; search_query: str ; goto_addr: str
- outputs : 
- parent : workspace_body
- surface : Workspace rail screen — S19TuiApp._compose_screen_workspace (s19_app/tui/app.py:1963)

| output | address | cardinality | consumers | owner |
|---|---|---|---|---|
| `screen_root` | `query_one("#screen_workspace")` | 1 | 5 declared | LLR-86.2 |
| `memstrip_band` | `query_one("#ws_memstrip")` | 1 | 4 declared | LLR-86.2 |
| `panes_container` | `query_one("#workspace_panes")` | 1 | 3 declared | LLR-86.2 |
| `left_pane` | `query_one("#ws_left")` | 1 | 3 declared | LLR-86.2 |
| `center_pane` | `query_one("#ws_center")` | 1 | 3 declared | LLR-86.2 |
| `right_pane` | `query_one("#ws_right")` | 1 | 3 declared | LLR-86.2 |
| `empty_state` | `query_one(EmptyStatePanel) scoped to the workspace screen subtree — type selector, computed, carries no quoted literal by design (the widget sets no id)` | 1 | 2 declared | LLR-86.2 |
| `load_project_button` | `query_one("#ws_load_project_button")` | 1 | 3 declared | LLR-86.3 |
| `files_title` | `query_one("#files_title")` | 1 | 1 declared | LLR-86.3 |
| `files_list` | `query_one("#files_list")` | 1 | 4 declared | LLR-86.3 |
| `sections_title` | `query_one("#sections_title")` | 1 | 1 declared | LLR-86.3 |
| `sections_list` | `query_one("#sections_list")` | 1 | 5 declared | LLR-86.3 |
| `hex_title` | `query_one("#hex_title")` | 1 | 1 declared | LLR-86.4 |
| `hex_controls` | `query_one("#hex_controls")` | 1 | 1 declared | LLR-86.4 |
| `search_input` | `query_one("#search_input")` | 1 | 8 declared | LLR-86.4 |
| `search_button` | `query_one("#search_button")` | 1 | 2 declared | LLR-86.4 |
| `goto_input` | `query_one("#goto_input")` | 1 | 6 declared | LLR-86.4 |
| `goto_button` | `query_one("#goto_button")` | 1 | 2 declared | LLR-86.4 |
| `hex_scroll` | `query_one("#hex_scroll")` | 1 | 3 declared | LLR-86.4 |
| `hex_view` | `query_one("#hex_view")` | 1 | 5 declared | LLR-86.4 |
| `ws_stats_title` | `query_one("#ws_stats_title")` | 1 | 1 declared | LLR-86.5 |
| `ws_stats` | `query_one("#ws_stats")` | 1 | 4 declared | LLR-86.5 |
| `a2l_title` | `query_one("#a2l_title")` | 1 | 1 declared | LLR-86.5 |
| `a2l_view` | `query_one("#a2l_view")` | 1 | 3 declared | LLR-86.5 |
| `a2l_scroll` | `query_one("#a2l_scroll")` | 1 | 2 declared | LLR-86.5 |
| `panel_handle` | `query_one("#loaded_panel")` | 1 | 5 declared | LLR-86.6 |
| `slots_container` | `query_one("#loaded_slots")` | 1 | 3 declared | LLR-86.6 |
| `artifact_row_set` | `query(".loaded-slot")` | 4 | 2 declared | LLR-87.5 |
| `unload_all_row` | `query(".loaded-allrow")` | 1 | 1 declared | LLR-87.5 |
| `artifact_slots` | `query(".loaded-detail"), INDEXED POSITIONALLY` | 3 | 4 declared | LLR-86.6 |
| `project_row` | `query(".loaded-project-detail")` | 1 | 3 declared | LLR-86.6 |

### COMPONENT `workspace_body` — .dev-flow/2026-08-24-batch-87/01-requirements.md:845
- inputs : loaded: Optional[LoadedFile] ; project: str ; workarea_files: list[Path] ; search_query: str ; goto_addr: str ; active_screen_key: str
- outputs : 
- parent : workspace_shell
- surface : the Direction-B app shell — the ten-screen body composed by S19TuiApp.compose (s19_app/tui/app.py:1906)

| output | address | cardinality | consumers | owner |
|---|---|---|---|---|
| `body_root` | `query_one("#workspace_body")` | 1 | 10 declared | LLR-87.6 |
| `screen_slot_set` | `query(".db-screen")` | 10 | 1 declared | LLR-87.6 |
| `a2l_screen` | `query_one("#screen_a2l")` | 1 | 4 declared | LLR-87.6 |
| `mac_screen` | `query_one("#screen_mac")` | 1 | 4 declared | LLR-87.6 |
| `map_screen` | `query_one("#screen_map")` | 1 | 4 declared | LLR-87.6 |
| `issues_screen` | `query_one("#screen_issues")` | 1 | 6 declared | LLR-87.6 |
| `patch_screen` | `query_one("#screen_patch")` | 1 | 3 declared | LLR-87.6 |
| `diff_screen` | `query_one("#screen_diff")` | 1 | 4 declared | LLR-87.6 |
| `flow_screen` | `query_one("#screen_flow")` | 1 | 2 declared | LLR-87.6 |
| `checks_screen` | `query_one("#screen_checks")` | 1 | 4 declared | LLR-87.6 |
| `crc_designer_screen` | `query_one("#screen_crc_designer")` | 1 | 3 declared | LLR-87.6 |
| `screen_root` | `query_one("#screen_workspace")` | 1 | 5 declared | LLR-87.7 |
| `memstrip_band` | `query_one("#ws_memstrip")` | 1 | 4 declared | LLR-87.7 |
| `panes_container` | `query_one("#workspace_panes")` | 1 | 3 declared | LLR-87.7 |
| `left_pane` | `query_one("#ws_left")` | 1 | 3 declared | LLR-87.7 |
| `center_pane` | `query_one("#ws_center")` | 1 | 3 declared | LLR-87.7 |
| `right_pane` | `query_one("#ws_right")` | 1 | 3 declared | LLR-87.7 |
| `empty_state` | `query_one(EmptyStatePanel) scoped to the workspace screen subtree — type selector, computed, carries no quoted literal by design` | 1 | 2 declared | LLR-87.7 |
| `load_project_button` | `query_one("#ws_load_project_button")` | 1 | 3 declared | LLR-87.7 |
| `files_title` | `query_one("#files_title")` | 1 | 1 declared | LLR-87.7 |
| `files_list` | `query_one("#files_list")` | 1 | 4 declared | LLR-87.7 |
| `sections_title` | `query_one("#sections_title")` | 1 | 1 declared | LLR-87.7 |
| `sections_list` | `query_one("#sections_list")` | 1 | 5 declared | LLR-87.7 |
| `hex_title` | `query_one("#hex_title")` | 1 | 1 declared | LLR-87.7 |
| `hex_controls` | `query_one("#hex_controls")` | 1 | 1 declared | LLR-87.7 |
| `search_input` | `query_one("#search_input")` | 1 | 8 declared | LLR-87.7 |
| `search_button` | `query_one("#search_button")` | 1 | 2 declared | LLR-87.7 |
| `goto_input` | `query_one("#goto_input")` | 1 | 6 declared | LLR-87.7 |
| `goto_button` | `query_one("#goto_button")` | 1 | 2 declared | LLR-87.7 |
| `hex_scroll` | `query_one("#hex_scroll")` | 1 | 3 declared | LLR-87.7 |
| `hex_view` | `query_one("#hex_view")` | 1 | 5 declared | LLR-87.7 |
| `ws_stats_title` | `query_one("#ws_stats_title")` | 1 | 1 declared | LLR-87.7 |
| `ws_stats` | `query_one("#ws_stats")` | 1 | 4 declared | LLR-87.7 |
| `a2l_title` | `query_one("#a2l_title")` | 1 | 1 declared | LLR-87.7 |
| `a2l_view` | `query_one("#a2l_view")` | 1 | 3 declared | LLR-87.7 |
| `a2l_scroll` | `query_one("#a2l_scroll")` | 1 | 2 declared | LLR-87.7 |
| `panel_handle` | `query_one("#loaded_panel")` | 1 | 5 declared | LLR-87.7 |
| `slots_container` | `query_one("#loaded_slots")` | 1 | 3 declared | LLR-87.7 |
| `artifact_row_set` | `query(".loaded-slot")` | 4 | 2 declared | LLR-87.7 |
| `unload_all_row` | `query(".loaded-allrow")` | 1 | 1 declared | LLR-87.7 |
| `artifact_slots` | `query(".loaded-detail"), INDEXED POSITIONALLY` | 3 | 4 declared | LLR-87.7 |
| `project_row` | `query(".loaded-project-detail")` | 1 | 3 declared | LLR-87.7 |

## STATUS — the real rules, run at derivation

- [-] V10  01-requirements.md: 23 FLOW node(s), every one owned
- [-] V11  01-requirements.md: 79 OUTPUT(s), each with an address and a declared consumer list
- [!] V12  .dev-flow/2026-08-24-batch-87/01-requirements.md:845: COMPONENT workspace_body: parent `workspace_shell` is not declared in this document, so balancing was NOT checked; this is not a pass
- [!] V13  .dev-flow/2026-08-21-batch-85/01-requirements.md:509: COMPONENT loaded_panel/panel_handle: reached by 2 undeclared file(s) — .fast-dev-flow/archive/2026-07-23-n6-n7-spec.md, prototypes/legend_n8.INVENTORY.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-21-batch-85/01-requirements.md:519: COMPONENT loaded_panel/slots_container: reached by 1 undeclared file(s) — s19_app/tui/screens_directionb.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-21-batch-85/01-requirements.md:540: COMPONENT loaded_panel/artifact_slots: reached by 1 undeclared file(s) — .fast-dev-flow/archive/2026-08-21-batch-85-ifc-pilot-promoted-spec.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:391: COMPONENT screen_workspace/screen_root: reached by 4 undeclared file(s) — .fast-dev-flow/archive/2026-07-20-unload-feature-spec.md, REQUIREMENTS.md, docs/architecture.md, prototypes/legend_n8.INVENTORY.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:401: COMPONENT screen_workspace/memstrip_band: reached by 4 undeclared file(s) — REQUIREMENTS.md, prototypes/legend_n8.INVENTORY.md, prototypes/screen_upgrades.HANDOFF-PLAN.md, tests/test_tui_snapshot.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:418: COMPONENT screen_workspace/left_pane: reached by 3 undeclared file(s) — .fast-dev-flow/archive/2026-07-07-sections-label-spec.md, prototypes/screen_upgrades.HANDOFF-PLAN.md, s19_app/tui/app.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:426: COMPONENT screen_workspace/center_pane: reached by 2 undeclared file(s) — REQUIREMENTS.md, prototypes/screen_upgrades.HANDOFF-PLAN.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:434: COMPONENT screen_workspace/right_pane: reached by 2 undeclared file(s) — prototypes/screen_upgrades.HANDOFF-PLAN.md, s19_app/tui/app.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:449: COMPONENT screen_workspace/load_project_button: reached by 1 undeclared file(s) — tests/test_tui_patch_chips.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:463: COMPONENT screen_workspace/files_list: reached by 2 undeclared file(s) — .fast-dev-flow/archive/2026-07-09-batch-31-quick-strike-spec.md, tests/test_tui_snapshot.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:478: COMPONENT screen_workspace/sections_list: reached by 2 undeclared file(s) — .fast-dev-flow/archive/2026-07-07-sections-label-spec.md, .fast-dev-flow/archive/2026-07-09-batch-31-quick-strike-spec.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:494: COMPONENT screen_workspace/hex_controls: reached by 1 undeclared file(s) — s19_app/tui/app.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:500: COMPONENT screen_workspace/search_input: reached by 1 undeclared file(s) — prototypes/cmdbar_a2bdiff.HANDOFF.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:513: COMPONENT screen_workspace/search_button: reached by 1 undeclared file(s) — tests/test_tui_patch_chips.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:520: COMPONENT screen_workspace/goto_input: reached by 1 undeclared file(s) — prototypes/cmdbar_a2bdiff.HANDOFF.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:531: COMPONENT screen_workspace/goto_button: reached by 1 undeclared file(s) — tests/test_tui_patch_chips.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:538: COMPONENT screen_workspace/hex_scroll: reached by 3 undeclared file(s) — REQUIREMENTS.md, s19_app/tui/app.py, tests/test_tui_mac_layout.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:546: COMPONENT screen_workspace/hex_view: reached by 2 undeclared file(s) — .fast-dev-flow/archive/2026-07-09-batch-31-quick-strike-spec.md, REQUIREMENTS.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:562: COMPONENT screen_workspace/ws_stats: reached by 2 undeclared file(s) — REQUIREMENTS.md, tests/test_tui_snapshot.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:592: COMPONENT screen_workspace/panel_handle: reached by 2 undeclared file(s) — .fast-dev-flow/archive/2026-07-23-n6-n7-spec.md, prototypes/legend_n8.INVENTORY.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:602: COMPONENT screen_workspace/slots_container: reached by 1 undeclared file(s) — s19_app/tui/screens_directionb.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:623: COMPONENT screen_workspace/artifact_slots: reached by 1 undeclared file(s) — .fast-dev-flow/archive/2026-08-21-batch-85-ifc-pilot-promoted-spec.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:850: COMPONENT workspace_body/body_root: reached by 4 undeclared file(s) — .fast-dev-flow/ADR-flow-builder-tracer.md, REQUIREMENTS.md, s19_app/tui/screens.py, s19_app/tui/screens_directionb.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:871: COMPONENT workspace_body/a2l_screen: reached by 2 undeclared file(s) — docs/architecture.md, prototypes/legend_n8.INVENTORY.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:880: COMPONENT workspace_body/mac_screen: reached by 2 undeclared file(s) — docs/architecture.md, prototypes/legend_n8.INVENTORY.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:889: COMPONENT workspace_body/map_screen: reached by 3 undeclared file(s) — REQUIREMENTS.md, docs/architecture.md, prototypes/legend_n8.INVENTORY.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:898: COMPONENT workspace_body/issues_screen: reached by 5 undeclared file(s) — REQUIREMENTS.md, docs/architecture.md, prototypes/legend_n8.INVENTORY.md, s19_app/tui/styles.tcss, tests/test_tui_issues_view.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:909: COMPONENT workspace_body/patch_screen: reached by 1 undeclared file(s) — docs/architecture.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:917: COMPONENT workspace_body/diff_screen: reached by 1 undeclared file(s) — docs/architecture.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:926: COMPONENT workspace_body/flow_screen: reached by 4 undeclared file(s) — .fast-dev-flow/ADR-flow-builder-tracer.md, .fast-dev-flow/archive/2026-07-14-batch44-flow-builder-spec.md, REQUIREMENTS.md, tests/test_flow_builder_render.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:933: COMPONENT workspace_body/checks_screen: reached by 2 undeclared file(s) — prototypes/legend_n8.INVENTORY.md, s19_app/tui/styles.tcss. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:942: COMPONENT workspace_body/crc_designer_screen: reached by 2 undeclared file(s) — docs/crc-algorithm-designer/01-requirements.md, s19_app/tui/crc_designer_view.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:950: COMPONENT workspace_body/screen_root: reached by 4 undeclared file(s) — .fast-dev-flow/archive/2026-07-20-unload-feature-spec.md, REQUIREMENTS.md, docs/architecture.md, prototypes/legend_n8.INVENTORY.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:960: COMPONENT workspace_body/memstrip_band: reached by 4 undeclared file(s) — REQUIREMENTS.md, prototypes/legend_n8.INVENTORY.md, prototypes/screen_upgrades.HANDOFF-PLAN.md, tests/test_tui_snapshot.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:977: COMPONENT workspace_body/left_pane: reached by 3 undeclared file(s) — .fast-dev-flow/archive/2026-07-07-sections-label-spec.md, prototypes/screen_upgrades.HANDOFF-PLAN.md, s19_app/tui/app.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:985: COMPONENT workspace_body/center_pane: reached by 2 undeclared file(s) — REQUIREMENTS.md, prototypes/screen_upgrades.HANDOFF-PLAN.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:993: COMPONENT workspace_body/right_pane: reached by 2 undeclared file(s) — prototypes/screen_upgrades.HANDOFF-PLAN.md, s19_app/tui/app.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1008: COMPONENT workspace_body/load_project_button: reached by 1 undeclared file(s) — tests/test_tui_patch_chips.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1022: COMPONENT workspace_body/files_list: reached by 2 undeclared file(s) — .fast-dev-flow/archive/2026-07-09-batch-31-quick-strike-spec.md, tests/test_tui_snapshot.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1037: COMPONENT workspace_body/sections_list: reached by 2 undeclared file(s) — .fast-dev-flow/archive/2026-07-07-sections-label-spec.md, .fast-dev-flow/archive/2026-07-09-batch-31-quick-strike-spec.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1053: COMPONENT workspace_body/hex_controls: reached by 1 undeclared file(s) — s19_app/tui/app.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1059: COMPONENT workspace_body/search_input: reached by 1 undeclared file(s) — prototypes/cmdbar_a2bdiff.HANDOFF.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1072: COMPONENT workspace_body/search_button: reached by 1 undeclared file(s) — tests/test_tui_patch_chips.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1079: COMPONENT workspace_body/goto_input: reached by 1 undeclared file(s) — prototypes/cmdbar_a2bdiff.HANDOFF.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1090: COMPONENT workspace_body/goto_button: reached by 1 undeclared file(s) — tests/test_tui_patch_chips.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1097: COMPONENT workspace_body/hex_scroll: reached by 3 undeclared file(s) — REQUIREMENTS.md, s19_app/tui/app.py, tests/test_tui_mac_layout.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1105: COMPONENT workspace_body/hex_view: reached by 2 undeclared file(s) — .fast-dev-flow/archive/2026-07-09-batch-31-quick-strike-spec.md, REQUIREMENTS.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1121: COMPONENT workspace_body/ws_stats: reached by 2 undeclared file(s) — REQUIREMENTS.md, tests/test_tui_snapshot.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1151: COMPONENT workspace_body/panel_handle: reached by 2 undeclared file(s) — .fast-dev-flow/archive/2026-07-23-n6-n7-spec.md, prototypes/legend_n8.INVENTORY.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1161: COMPONENT workspace_body/slots_container: reached by 1 undeclared file(s) — s19_app/tui/screens_directionb.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1182: COMPONENT workspace_body/artifact_slots: reached by 1 undeclared file(s) — .fast-dev-flow/archive/2026-08-21-batch-85-ifc-pilot-promoted-spec.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  01-requirements.md: 2 address(es) carry no quoted literal, so nothing was searched for them — screen_workspace/empty_state, workspace_body/empty_state. A computed address cannot be followed by grep; recognising those SITES is the project's own rule
- [-] V14  01-requirements.md: 251 declared consumer(s), every one resolved
- [-] V19  01-requirements.md: 3 COMPONENT id(s), each declared exactly once
