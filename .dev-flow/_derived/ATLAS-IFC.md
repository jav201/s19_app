<!-- DERIVED — DO NOT EDIT. Regenerate: devflow-validate.py --atlas --write -->
<!-- flow_version: 2026-10-12-rev102 | flow_hash: ef4561d60ce65e0f | corpus: 72 requirement files | corpus digest: f7ca0d85cb67d5ca -->

# ATLAS-IFC — how is the application addressed?

19 FLOW declaration(s) · 10 COMPONENT declaration(s) · 638 declared requirement heading ids — one row per declaration.

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

### FLOW `id-authority` — .dev-flow/2026-09-06-batch-90/01-requirements.md:207
- node `tools/id_registry.py::iter_tokens` — owner LLR-90.1.1
- node `tools/id_registry.py::derive_named_nodes` — owner LLR-90.1.2
- node `tests/test_id_registry.py::g1_named_nodes_are_registered` — owner LLR-90.1.4
- node `tests/test_id_registry.py::g7_no_stem_exceeds_high_water` — owner LLR-90.1.4

### FLOW `residual-guard` — .dev-flow/2026-09-06-batch-90/01-requirements.md:230
- node `tests/test_report_addendum_bound.py::test_tc497_shipped_requirement_carries_the_residuals_with_their_numbers` — owner LLR-90.2.1
- node `tests/test_report_addendum_bound.py::_typographic_variants` — owner LLR-90.2.1

### FLOW `the batch's documentation flows (adoption and drift-closure move RECORDS, not data)` — .dev-flow/2026-10-08-batch-91/01-requirements.md:223
- node `the S19/HEX adoption (contract section -> docstring tokens -> registry LIVE entries)` — owner LLR-122.1
- node `the A2L adoption` — owner LLR-122.2
- node `the MAC adoption` — owner LLR-122.3
- node `the CRC adoption` — owner LLR-122.4
- node `the TUI host-surface adoption` — owner LLR-122.5
- node `the docs catch-up (README + docs/* read the shipped app)` — owner HLR-123
- node `the AT-043 resolution` — owner LLR-124.1
- node `the 44 token adoptions` — owner LLR-124.2

### FLOW `F-92-1` — .dev-flow/2026-10-11-batch-92/01-requirements.md:379
- node `render_hex_view / render_hex_view_text (+ build_mem_map_s19, build_range_validity_s19, [+ABSORBED]` — owner LLR-001.2

### FLOW `F-92-2` — .dev-flow/2026-10-11-batch-92/01-requirements.md:392
- node `safe_text (+ private _CONTROL_SCRUB)` — owner LLR-003.2

### FLOW `F-92-3` — .dev-flow/2026-10-11-batch-92/01-requirements.md:404
- node `microbar (+ MICROBAR_FILLED, MICROBAR_EMPTY, GREEN, LABEL, VALUE)` — owner LLR-004.1

### FLOW `the Memory Map cohesion pass — a presentational re-render of already-computed LoadedFile facts` — .dev-flow/2026-10-11-batch-93/01-requirements.md:587
- node `pane chrome + subtitles (bordered panes, lit titles, affordance hints)` — owner LLR-125.1
- node `left-pane stack order (bar -> ruler -> chips -> list)` — owner LLR-126.1
- node `inspector aligned field block` — owner LLR-126.2
- node `multi-row peek sizing` — owner LLR-126.3
- node `first-region auto-selection + focus` — owner LLR-126.4
- node `fixed-width region-row fields` — owner LLR-127.1
- node `display-only short band labels` — owner LLR-127.2
- node `width-aware microbar drop` — owner LLR-127.3
- node `RegionRow interaction semantics (N4a split, keyboard path)` — owner LLR-127.4
- node `8-byte peek row format (33 cells, no ascii, .. unmapped)` — owner LLR-128.1
- node `one-line always-visible stats strip` — owner LLR-129.1
- node `width-adaptive stats compact form` — owner LLR-129.2
- node `glance chips line (shares sum to 100 +/- rounding)` — owner LLR-129.3
- node `wrap-audit harness at five geometries` — owner LLR-130.1
- node `the audit counterfactual injection` — owner LLR-130.2
- node `two-regime stack/side-by-side layout` — owner LLR-131.1
- node `resize re-apportionment (bar, rows, peek)` — owner LLR-131.2
- node `bounded width-0 convergence` — owner LLR-131.3
- node `the four legend boxes (bands / anatomy / region row / keys)` — owner LLR-132.1
- node `legend no-wrap + Esc close` — owner LLR-132.2
- node `LegendScreen API + other-view byte-identical control` — owner LLR-132.3
- node `live-sourced band key` — owner LLR-132.4
- node `command-bar interlock` — owner LLR-133.1

### FLOW `check_spec_to_diff_report` — .dev-flow/2026-10-12-batch-94/01-requirements.md:1031
- node `write_change_document (Check Editor write action)` — owner LLR-009.1
- node `parse_change_document + read_change_document (A2B Diff load)` — owner LLR-010.1
- node `generate_diff_report addendum (check-spec append)` — owner LLR-010.2

### FLOW `a2l_file_to_issues_triage` — .dev-flow/2026-10-12-batch-94/01-requirements.md:1050
- node `validate_a2l_structure section classification (engine, frozen)` — owner LLR-012.1
- node `curated-set reclassification policy (view layer)` — owner LLR-012.2

### FLOW `flow_template_to_execution` — .dev-flow/2026-10-12-batch-94/01-requirements.md:1065
- node `save_flow_json (builder template save)` — owner LLR-015.1
- node `load_flow_json + dict_to_flow (execution import)` — owner LLR-017.1

### FLOW `chain_set_save_load` — .dev-flow/2026-10-12-batch-94/01-requirements.md:1080
- node `chain-set serializer (chains + input bindings + outputs)` — owner LLR-021.1
- node `chain-set loader (reload + provenance rebind)` — owner LLR-021.2

### FLOW `block_input_provenance_to_report` — .dev-flow/2026-10-12-batch-94/01-requirements.md:1095
- node `binding validation (flow-output-or-file, >=1 from current flow)` — owner LLR-014.1
- node `provenance line emission in the A2B report` — owner LLR-014.2

### FLOW `rail_selection_to_panel_mount` — .dev-flow/2026-10-12-batch-94/01-requirements.md:1110
- node `RAIL_ENTRIES census + key/click routing (app.py action_show_screen)` — owner LLR-002.1
- node `check-editor panel mounting` — owner LLR-001.2
- node `flow-execution panel mounting` — owner LLR-017.1

### FLOW `the amendment, from the operator's eye to one word of chrome` — .dev-flow/2026-10-13-batch-94/01-requirements.md:126
- node `the legend spec sheet's fourth box title (screens.py _box)` — owner HLR-134

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

### COMPONENT `C-92-1` — .dev-flow/2026-10-11-batch-92/01-requirements.md:418
- inputs : loaded image: S19File | IntelHexFile ; ranges: list[tuple[int, int]] ; focus/match params
- outputs : 
- parent : SYSTEM
- surface : render package (s19_app/render/)

| output | address | cardinality | consumers | owner |
|---|---|---|---|---|
| `hex-rendered rows` | `s19_app.render.hexview.render_hex_view / render_hex_view_text (+ builder fns)` | None | 17 declared | LLR-001.2 |
| `layout constants` | `s19_app.render.hexview::<constant name>` | None | 8 declared | LLR-001.3 |

### COMPONENT `C-92-2` — .dev-flow/2026-10-11-batch-92/01-requirements.md:447
- inputs : value: str ; style: str
- outputs : 
- parent : SYSTEM
- surface : render package (s19_app/render/)

| output | address | cardinality | consumers | owner |
|---|---|---|---|---|
| `microbar bar + style constants` | `s19_app.render.format.microbar / ::MICROBAR_FILLED / ::MICROBAR_EMPTY / [+ABSORBED]` | None | 5 declared | LLR-004.1 |

### COMPONENT `C-92-3` — .dev-flow/2026-10-11-batch-92/01-requirements.md:464
- inputs : value: str ; style: str
- outputs : 
- parent : SYSTEM
- surface : app root utilities (s19_app/utils.py)

| output | address | cardinality | consumers | owner |
|---|---|---|---|---|
| `markup-safe Text` | `s19_app.utils.safe_text` | None | 14 declared | LLR-003.2 |

### COMPONENT `check_editor_panel` — .dev-flow/2026-10-12-batch-94/01-requirements.md:1131
- inputs : selected_a2l_tags: list[dict] ; check_spec_entries: list[ChangeEntry] ; spec_file_listing: list[str]
- outputs : 
- parent : workspace_shell
- surface : Check Editor (rail surface, Inc-001)

| output | address | cardinality | consumers | owner |
|---|---|---|---|---|
| `collector_rows` | `query("#check-editor-panel parameter-collector"), INDEXED POSITIONALLY` | per declared spec entries | 0 declared | LLR-001.1 |
| `spec_write_path` | `query("#check-editor-panel write-action result")` | 1 | 1 declared | LLR-009.1 |

### COMPONENT `patch_editor_panel` — .dev-flow/2026-10-12-batch-94/01-requirements.md:1153
- inputs : change_document: ChangeDocument|None ; folder_listing: list[str] ; loaded_image: mem_map|ranges|None
- outputs : 
- parent : workspace_shell
- surface : Patch Editor (reworked, Inc-001)

| output | address | cardinality | consumers | owner |
|---|---|---|---|---|
| `entries_table_rows` | `query("#patch_doc_entries_table"), INDEXED POSITIONALLY` | per loaded document entries | 2 declared | LLR-004.1 |
| `json_editor_region` | `query("#patch-editor-json-region")` | 1 | 0 declared | LLR-003.1 |
| `load_guard_popup` | `query("#patch-load-guard-popup")` | 1 | 0 declared | LLR-005.2 |

### COMPONENT `flow_builder_panel` — .dev-flow/2026-10-12-batch-94/01-requirements.md:1182
- inputs : template_listing: list[str] ; loaded_artifacts: list[str]
- outputs : 
- parent : workspace_shell
- surface : Flow Builder (fb_a redesign; address moves screens_directionb -> flow_screens, B2)

| output | address | cardinality | consumers | owner |
|---|---|---|---|---|
| `canvas_blocks` | `query("#flow-builder-canvas .flow-block"), INDEXED POSITIONALLY` | per placed blocks | 1 declared | LLR-013.1 |
| `template_save_name` | `query("#flow-builder-save-result")` | 1 | 0 declared | LLR-015.1 |

### COMPONENT `flow_execution_panel` — .dev-flow/2026-10-12-batch-94/01-requirements.md:1204
- inputs : template_listing: list[str] ; chain_input_files: list[str] ; run_mode: "sequential"|"parallel"
- outputs : 
- parent : workspace_shell
- surface : Flow Execution (fx_a, Inc-003)

| output | address | cardinality | consumers | owner |
|---|---|---|---|---|
| `run_lanes` | `query("#flow-execution-lanes .flow-lane"), INDEXED POSITIONALLY` | per imported chains | 1 declared | LLR-017.1 |
| `run_log` | `query("#flow-run-log")` | 1 | 0 declared | LLR-020.1 |
| `chain_set_save_result` | `query("#flow-set-save-result")` | 1 | 0 declared | LLR-021.1 [+ABSORBED] |

## STATUS — the real rules, run at derivation

- [-] V10  01-requirements.md: 78 FLOW node(s), every one owned
- [-] V11  01-requirements.md: 93 OUTPUT(s), each with an address and a declared consumer list
- [!] V12  .dev-flow/2026-08-24-batch-87/01-requirements.md:845: COMPONENT workspace_body: parent `workspace_shell` is not declared in this document, so balancing was NOT checked; this is not a pass
- [!] V12  .dev-flow/2026-10-12-batch-94/01-requirements.md:1131: COMPONENT check_editor_panel: parent `workspace_shell` is not declared in this document, so balancing was NOT checked; this is not a pass
- [!] V12  .dev-flow/2026-10-12-batch-94/01-requirements.md:1153: COMPONENT patch_editor_panel: parent `workspace_shell` is not declared in this document, so balancing was NOT checked; this is not a pass
- [!] V12  .dev-flow/2026-10-12-batch-94/01-requirements.md:1182: COMPONENT flow_builder_panel: parent `workspace_shell` is not declared in this document, so balancing was NOT checked; this is not a pass
- [!] V12  .dev-flow/2026-10-12-batch-94/01-requirements.md:1204: COMPONENT flow_execution_panel: parent `workspace_shell` is not declared in this document, so balancing was NOT checked; this is not a pass
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
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:500: COMPONENT screen_workspace/search_input: reached by 2 undeclared file(s) — prototypes/cmdbar_a2bdiff.HANDOFF.md, tests/test_command_bar_interlock.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:513: COMPONENT screen_workspace/search_button: reached by 1 undeclared file(s) — tests/test_tui_patch_chips.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:520: COMPONENT screen_workspace/goto_input: reached by 2 undeclared file(s) — prototypes/cmdbar_a2bdiff.HANDOFF.md, tests/test_command_bar_interlock.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:531: COMPONENT screen_workspace/goto_button: reached by 1 undeclared file(s) — tests/test_tui_patch_chips.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:538: COMPONENT screen_workspace/hex_scroll: reached by 3 undeclared file(s) — REQUIREMENTS.md, s19_app/tui/app.py, tests/test_tui_mac_layout.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:546: COMPONENT screen_workspace/hex_view: reached by 2 undeclared file(s) — .fast-dev-flow/archive/2026-07-09-batch-31-quick-strike-spec.md, REQUIREMENTS.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:562: COMPONENT screen_workspace/ws_stats: reached by 2 undeclared file(s) — REQUIREMENTS.md, tests/test_tui_snapshot.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:592: COMPONENT screen_workspace/panel_handle: reached by 2 undeclared file(s) — .fast-dev-flow/archive/2026-07-23-n6-n7-spec.md, prototypes/legend_n8.INVENTORY.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:602: COMPONENT screen_workspace/slots_container: reached by 1 undeclared file(s) — s19_app/tui/screens_directionb.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:623: COMPONENT screen_workspace/artifact_slots: reached by 1 undeclared file(s) — .fast-dev-flow/archive/2026-08-21-batch-85-ifc-pilot-promoted-spec.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:850: COMPONENT workspace_body/body_root: reached by 6 undeclared file(s) — .fast-dev-flow/ADR-flow-builder-tracer.md, REQUIREMENTS.md, s19_app/tui/screens.py, s19_app/tui/screens_directionb.py, tests/test_tui_map_big.py, tests/test_tui_patch_editor_b94.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:865: COMPONENT workspace_body/screen_slot_set: reached by 2 undeclared file(s) — s19_app/tui/open_folder_chip.py, tests/test_open_folder_chips.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:871: COMPONENT workspace_body/a2l_screen: reached by 2 undeclared file(s) — docs/architecture.md, prototypes/legend_n8.INVENTORY.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:880: COMPONENT workspace_body/mac_screen: reached by 2 undeclared file(s) — docs/architecture.md, prototypes/legend_n8.INVENTORY.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:889: COMPONENT workspace_body/map_screen: reached by 4 undeclared file(s) — REQUIREMENTS.md, docs/architecture.md, prototypes/legend_n8.INVENTORY.md, tests/test_command_bar_interlock.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:898: COMPONENT workspace_body/issues_screen: reached by 5 undeclared file(s) — REQUIREMENTS.md, docs/architecture.md, prototypes/legend_n8.INVENTORY.md, s19_app/tui/styles.tcss, tests/test_tui_issues_view.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:909: COMPONENT workspace_body/patch_screen: reached by 1 undeclared file(s) — docs/architecture.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:917: COMPONENT workspace_body/diff_screen: reached by 1 undeclared file(s) — docs/architecture.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:926: COMPONENT workspace_body/flow_screen: reached by 5 undeclared file(s) — .fast-dev-flow/ADR-flow-builder-tracer.md, .fast-dev-flow/archive/2026-07-14-batch44-flow-builder-spec.md, REQUIREMENTS.md, docs/architecture.md, tests/test_flow_builder_render.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:933: COMPONENT workspace_body/checks_screen: reached by 3 undeclared file(s) — docs/architecture.md, prototypes/legend_n8.INVENTORY.md, s19_app/tui/styles.tcss. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:942: COMPONENT workspace_body/crc_designer_screen: reached by 3 undeclared file(s) — docs/architecture.md, docs/crc-algorithm-designer/01-requirements.md, s19_app/tui/crc_designer_view.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:950: COMPONENT workspace_body/screen_root: reached by 4 undeclared file(s) — .fast-dev-flow/archive/2026-07-20-unload-feature-spec.md, REQUIREMENTS.md, docs/architecture.md, prototypes/legend_n8.INVENTORY.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:960: COMPONENT workspace_body/memstrip_band: reached by 4 undeclared file(s) — REQUIREMENTS.md, prototypes/legend_n8.INVENTORY.md, prototypes/screen_upgrades.HANDOFF-PLAN.md, tests/test_tui_snapshot.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:977: COMPONENT workspace_body/left_pane: reached by 3 undeclared file(s) — .fast-dev-flow/archive/2026-07-07-sections-label-spec.md, prototypes/screen_upgrades.HANDOFF-PLAN.md, s19_app/tui/app.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:985: COMPONENT workspace_body/center_pane: reached by 2 undeclared file(s) — REQUIREMENTS.md, prototypes/screen_upgrades.HANDOFF-PLAN.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:993: COMPONENT workspace_body/right_pane: reached by 2 undeclared file(s) — prototypes/screen_upgrades.HANDOFF-PLAN.md, s19_app/tui/app.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1008: COMPONENT workspace_body/load_project_button: reached by 1 undeclared file(s) — tests/test_tui_patch_chips.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1022: COMPONENT workspace_body/files_list: reached by 2 undeclared file(s) — .fast-dev-flow/archive/2026-07-09-batch-31-quick-strike-spec.md, tests/test_tui_snapshot.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1037: COMPONENT workspace_body/sections_list: reached by 2 undeclared file(s) — .fast-dev-flow/archive/2026-07-07-sections-label-spec.md, .fast-dev-flow/archive/2026-07-09-batch-31-quick-strike-spec.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1053: COMPONENT workspace_body/hex_controls: reached by 1 undeclared file(s) — s19_app/tui/app.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1059: COMPONENT workspace_body/search_input: reached by 2 undeclared file(s) — prototypes/cmdbar_a2bdiff.HANDOFF.md, tests/test_command_bar_interlock.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1072: COMPONENT workspace_body/search_button: reached by 1 undeclared file(s) — tests/test_tui_patch_chips.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1079: COMPONENT workspace_body/goto_input: reached by 2 undeclared file(s) — prototypes/cmdbar_a2bdiff.HANDOFF.md, tests/test_command_bar_interlock.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1090: COMPONENT workspace_body/goto_button: reached by 1 undeclared file(s) — tests/test_tui_patch_chips.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1097: COMPONENT workspace_body/hex_scroll: reached by 3 undeclared file(s) — REQUIREMENTS.md, s19_app/tui/app.py, tests/test_tui_mac_layout.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1105: COMPONENT workspace_body/hex_view: reached by 2 undeclared file(s) — .fast-dev-flow/archive/2026-07-09-batch-31-quick-strike-spec.md, REQUIREMENTS.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1121: COMPONENT workspace_body/ws_stats: reached by 2 undeclared file(s) — REQUIREMENTS.md, tests/test_tui_snapshot.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1151: COMPONENT workspace_body/panel_handle: reached by 2 undeclared file(s) — .fast-dev-flow/archive/2026-07-23-n6-n7-spec.md, prototypes/legend_n8.INVENTORY.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1161: COMPONENT workspace_body/slots_container: reached by 1 undeclared file(s) — s19_app/tui/screens_directionb.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:1182: COMPONENT workspace_body/artifact_slots: reached by 1 undeclared file(s) — .fast-dev-flow/archive/2026-08-21-batch-85-ifc-pilot-promoted-spec.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-10-12-batch-94/01-requirements.md:1158: COMPONENT patch_editor_panel/entries_table_rows: reached by 14 undeclared file(s) — REQUIREMENTS.md, s19_app/tui/screens.py, s19_app/tui/screens_directionb.py, s19_app/tui/services/change_service.py, s19_app/tui/styles.tcss, tests/test_tui_checks_screen.py, tests/test_tui_patch_big.py, tests/test_tui_patch_card.py, tests/test_tui_patch_checks_strip.py, tests/test_tui_patch_editor_b94.py, tests/test_tui_patch_editor_v2.py, tests/test_tui_patch_glyphs.py, tests/test_tui_patch_layout.py, tests/test_tui_patch_variant.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  01-requirements.md: 6 address(es) carry no quoted literal, so nothing was searched for them — screen_workspace/empty_state, workspace_body/empty_state, C-92-1/hex-rendered rows, C-92-1/layout constants, C-92-2/microbar bar + style constants, C-92-3/markup-safe Text. A computed address cannot be followed by grep; recognising those SITES is the project's own rule
- [-] V14  01-requirements.md: 300 declared consumer(s), every one resolved
- [-] V19  01-requirements.md: 10 COMPONENT id(s), each declared exactly once
