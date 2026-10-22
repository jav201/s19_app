<!-- DERIVED — DO NOT EDIT. Regenerate: devflow-validate.py --atlas --write -->
<!-- flow_version: 2026-10-12-rev102 | flow_hash: 6f99c414f39c84d9 | corpus: 74 requirement files | corpus digest: c3c14b8c994dbaba -->

# ATLAS-IFC — how is the application addressed?

40 FLOW declaration(s) · 18 COMPONENT declaration(s) · 758 declared requirement heading ids — one row per declaration.

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

### FLOW `split_join_screen` — .dev-flow/2026-10-13-batch-95/01-requirements.md:719
- node `the three segment-source tabs + the ranges-first default + the manual parser` — owner LLR-135.7
- node `the graft chassis composition` — owner LLR-135.1
- node `the output plan (per-file blocks, coverage sweep, conflict marks, guard flag)` — owner LLR-136.1
- node `the visor band + legend + ruler` — owner LLR-135.2
- node `the two-regime reflow + the split gantt show/hide` — owner LLR-135.3
- node `the span guard arm/disarm` — owner LLR-135.5
- node `split/join emission (slicer + pad-fill emitter + S19/HEX/BIN emitters + naming)` — owner LLR-136.5

### FLOW `save_gather` — .dev-flow/2026-10-13-batch-95/01-requirements.md:757
- node `the used-set computation (the P3-recorded predicate)` — owner LLR-138.1
- node `the COPY gather into the project homes` — owner LLR-138.2
- node `the no-project guard + the snapshot refresh on re-save` — owner LLR-138.4

### FLOW `open_folder_buttons` — .dev-flow/2026-10-13-batch-95/01-requirements.md:777
- node `the per-window target resolution (project vs COMMON, missing-folder limbs)` — owner LLR-139.1
- node `the cross-platform seam` — owner LLR-139.3

### FLOW `usage_help` — .dev-flow/2026-10-13-batch-95/01-requirements.md:792
- node `the per-window modal on the VariantHelpScreen pattern` — owner LLR-140.1
- node `the section census (9/9, step counts, markup-free)` — owner LLR-140.2

### FLOW `a2l_referenced_patch` — .dev-flow/2026-10-13-batch-95/01-requirements.md:807
- node `symbol resolution (name -> address+length+datatype via the tag map)` — owner LLR-141.1
- node `physical->raw encode (the COMPU_METHOD composition) + the canonical wire form` — owner LLR-141.1
- node `the Patch Editor symbol picker + the refusal limb` — owner LLR-141.2
- node `the flow blocks' A2L reference resolution -- project home` — owner LLR-142.1
- node `the flow blocks' A2L reference resolution -- workspace home` — owner LLR-142.2
- node `report attribution` — owner LLR-143.1
- node `the A2B diff reference block` — owner LLR-143.2

### FLOW `change_doc_to_json_view` — .dev-flow/2026-10-19-batch-97/01-requirements.md:1145
- node `the ChangeService writers of the document (change_service.py:861, :893, :1080, :1154, :1196, :1223, :1344, :1404, :1465)` — owner LLR-144.6
- node `serialize_change_document (changes/io.py:1392)` — owner LLR-144.5
- node `app-to-panel feed at the refresh_entries sites (I-3, NEW) into the read-only view, capped at JSON_TAB_LINE_CAP lines + note` — owner LLR-144.5
- node `the panel's dirty-flag writers (screens_directionb.py:5707, :5771, :5953, :5964), each followed by _refresh_dirty_indicator` — owner LLR-144.6
- node `stamp composition — entry count, refresh time, dirty flag (NEW), re-run on every document write and every dirty-flag change` — owner LLR-144.6

### FLOW `document_identity_to_ribbon` — .dev-flow/2026-10-19-batch-97/01-requirements.md:1172
- node `identity feed through refresh_entries keyword or setter (I-2, NEW)` — owner LLR-144.7
- node `safe_text render (utils.py:44) of the name, kind and every file-derived entry field` — owner LLR-144.7

### FLOW `highlighted_row_to_hex_strip` — .dev-flow/2026-10-19-batch-97/01-requirements.md:1187
- node `before/after byte read for the highlighted entry, changed bytes marked with a text attribute (NEW)` — owner LLR-144.8

### FLOW `a2l_parameters_to_check_ledger` — .dev-flow/2026-10-19-batch-97/01-requirements.md:1198
- node `S19TuiApp._prefill_check_editor (app.py:5329) — one row per tag with an integer address` — owner LLR-145.1
- node `Address column sizing and placement` — owner LLR-145.2
- node `name clipping — first segment + ellipsis + tail in the ledger, ellipsis + tail on Fields lines` — owner LLR-145.3
- node `REPORT FIELDS composition — Fields lines, capped JSON spec, Addendum preview (NEW layout over the shipped collector)` — owner LLR-145.6
- node `safe_text render of names and spec file names` — owner LLR-145.5

### FLOW `flow_template_to_pipeline` — .dev-flow/2026-10-19-batch-97/01-requirements.md:1225
- node `FlowBuilderPanel.set_blocks (flow_screens.py:878) and the pipeline layout (NEW)` — owner LLR-146.1
- node `card text clipping by element class` — owner LLR-146.4
- node `CRC card paint with the CRC token #c9562b (NEW)` — owner LLR-146.6
- node `session directory onto the ribbon (set_session_dir → #flow_name_strip)` — owner LLR-146.11
- node `funnel count into the Variables (n) label (flow_screens.py:1243)` — owner LLR-146.10
- node `safe_text render of flow names, refs, EXT-STEP instruction / log_ref / output_path, paths` — owner LLR-146.8

### FLOW `ref_text_to_load_guard` — .dev-flow/2026-10-19-batch-97/01-requirements.md:1256
- node `NUL test on the eight path-bearing block fields in load_flow_json (flow_persistence_service.py:868), FLOW-UNSAFE-REF; its stat() guard catches ValueError and OSError` — owner LLR-146.14
- node `NUL test on template and input refs in load_chain_set (:1452) / _is_plain_template_stem (:1147), CHAIN-SET-UNSAFE-REF` — owner LLR-146.14
- node `NUL test in _resolve_manifest_entry (variant_execution_service.py:205, resolve at :273), MANIFEST-PATH-ESCAPE` — owner LLR-146.14

### FLOW `palette_kind_to_add_form` — .dev-flow/2026-10-19-batch-97/01-requirements.md:1275
- node `FlowBuilderPanel.on_button_pressed flow_palette_ prefix (flow_screens.py:1455-1461)` — owner LLR-146.2
- node `FlowBuilderPanel._sync_kind_dependent_visibility (flow_screens.py:1534)` — owner LLR-146.3

### FLOW `run_record_to_lane_cables` — .dev-flow/2026-10-19-batch-97/01-requirements.md:1290
- node `FlowExecutionPanel.render_run cable glyphs (flow_screens.py:2399)` — owner LLR-147.1
- node `paused-lane paint, pending lines, REQUIRED line naming the attention lane's chain, scroll-into-view on both axes (a focused widget in the lanes kept in view), attention class (focus untouched)` — owner LLR-147.3
- node `lane-header worst-status mark from the LLR-147.1 vocabulary (NEW)` — owner LLR-147.12
- node `waiting-colour assignment restricted to waiting-human elements` — owner LLR-147.7
- node `external-step summaries and diagnostics (flow_execution_service.py:501, :840-:846, :860, :867, :885) and run-log lines in English` — owner LLR-147.5
- node `safe_text render of chain names, refs, EXT-STEP fields, written paths` — owner LLR-147.6

### FLOW `flowset_listing_to_set_picker` — .dev-flow/2026-10-19-batch-97/01-requirements.md:1321
- node `set_available_sets option prompts as safe_text Text (flow_screens.py:2566)` — owner LLR-147.6

### FLOW `run_press_to_single_run` — .dev-flow/2026-10-19-batch-97/01-requirements.md:1332
- node `in-flight guard — #fx_run disabled for the run's duration, re-enabled when it ends or raises (NEW)` — owner LLR-147.10

### FLOW `confirm_key_to_rerun` — .dev-flow/2026-10-19-batch-97/01-requirements.md:1343
- node `attention-lane lookup; confirm only with the focus outside a text input, once per waiting entry, after CONFIRM_DWELL_S of attention; the same confirmation a #fx_confirm_<i> press posts (NEW)` — owner LLR-147.13

### FLOW `project_dir_to_folder_chip` — .dev-flow/2026-10-19-batch-97/01-requirements.md:1354
- node `resolve_chip_target, flows family (folder_open_service.py:232)` — owner LLR-148.1
- node `resolve_chip_target, session family` — owner LLR-148.2
- node `OpenFolderChip.refresh_target per-family no-project status (open_folder_chip.py:92-127)` — owner LLR-148.3
- node `chip label from the family's folder-name constant (NEW)` — owner LLR-148.10
- node `real-directory guard, after any create-on-press — is_dir, no reparse point up to the family root (workspace.py:184), inside the root (NEW)` — owner LLR-148.8
- node `OpenFolderChip._open_target to the open seam (open_folder_chip.py:139)` — owner LLR-148.5

### FLOW `help_chip_to_modal` — .dev-flow/2026-10-19-batch-97/01-requirements.md:1385
- node `open_window_help + section_body_text (window_help.py:290, :305)` — owner LLR-148.6

### FLOW `renderer_vocabulary_to_legend` — .dev-flow/2026-10-19-batch-97/01-requirements.md:1396
- node `legend composition — status and mark glyphs with one meaning each, at most two rows (NEW)` — owner LLR-148.7

### FLOW `terminal_size_to_layout` — .dev-flow/2026-10-19-batch-97/01-requirements.md:1407
- node `per-panel width and height derivation (NEW, on mount and on_resize)` — owner LLR-149.1
- node `ellipsis clipping by element class` — owner LLR-149.4

### FLOW `active_window_to_key_bar` — .dev-flow/2026-10-19-batch-97/01-requirements.md:1422
- node `window-key table lookup and binding resolution at mount; labels are the bindings' descriptions (NEW, I-10)` — owner LLR-150.1
- node `global row composition in the theme's footer colours (NEW)` — owner LLR-150.2
- node `window row composition: tag in the .db-screen-title pair, window tokens, go tokens (NEW)` — owner LLR-150.3
- node `handled-key filter and state dimming; S19TuiApp.check_action (NEW)` — owner LLR-150.4
- node `whole-token packing with "? more" (NEW, pack_key_row)` — owner LLR-150.5
- node `click hit-test to app.simulate_key (NEW)` — owner LLR-150.7

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

### COMPONENT `split_join_engine` — .dev-flow/2026-10-13-batch-95/01-requirements.md:848
- gap : str ; pad_byte: int ; fmt: str ; stem: str ; pattern: str ; destination: Path
- inputs : image: S19File|IntelHexFile ; segments: SegRow[] ; selection: set[int] ; mode: str ;
- outputs : 
- parent : SYSTEM
- surface : the Split / Join / Export screen

| output | address | cardinality | consumers | owner |
|---|---|---|---|---|
| `output_files` | `s19_app/tui/changes/io.py (the split/join emit entry minted by LLR-137.1-137.3)` | 1..N | 0 declared | LLR-136.5 |
| `memory_segment_rows` | `s19_app/tui/a2l.py::extract_memory_segments` | 0..N | 2 declared | LLR-137.4 |

### COMPONENT `change_set_wire` — .dev-flow/2026-10-13-batch-95/01-requirements.md:871
- inputs : document: ChangeDocument (address-form and symbol-form entries) ; a2l: the referenced [+ABSORBED]
- outputs : 
- parent : SYSTEM
- surface : the change-set JSON (the s19app-changeset v2 wire) + the flow blocks' a2l_ref

| output | address | cardinality | consumers | owner |
|---|---|---|---|---|
| `resolved_entries` | `s19_app/tui/changes/io.py (read_change_document — the v2 reader seam)` | 1..N | 3 declared | LLR-141.1 |

### COMPONENT `pe_ledger_inspector` — .dev-flow/2026-10-19-batch-97/01-requirements.md:1455
- inputs : change_document: ChangeDocument ; document_json: str ; loaded_image: dict
- outputs : 
- parent : workspace_shell
- surface : Patch Editor (batch-97 pe_A port)

| output | address | cardinality | consumers | owner |
|---|---|---|---|---|
| `entries_ledger` | `query("#patch_doc_entries_table"), INDEXED POSITIONALLY` | len(document.entries) | 11 declared | LLR-144.2 |
| `json_tab` | `query("#patch_win_json")` | 1 | 10 declared | LLR-144.12 |
| `json_view` | `query("#patch_json_view")` | 1 | 0 declared | LLR-144.5 |
| `identity_ribbon` | `query("#patch_identity_ribbon")` | 1 | 0 declared | LLR-144.7 |

### COMPONENT `ce_ledger_inspector` — .dev-flow/2026-10-19-batch-97/01-requirements.md:1506
- inputs : a2l_parameters: list ; check_spec_entries: list ; spec_file_listing: list
- outputs : 
- parent : workspace_shell
- surface : Check Editor (batch-97 ce_A port)

| output | address | cardinality | consumers | owner |
|---|---|---|---|---|
| `parameter_ledger` | `query("#check_param_table"), INDEXED POSITIONALLY` | one per A2L parameter (75 in the fixture) | 2 declared | LLR-145.2 |
| `write_action` | `query("#check_write_button")` | 1 | 3 declared | LLR-145.1 |
| `fields_count` | `query("#check_fields_count")` | 1 | 1 declared | LLR-145.1 |

### COMPONENT `fb_pipeline_rail` — .dev-flow/2026-10-19-batch-97/01-requirements.md:1535
- inputs : flow: Flow ; flow_name: str ; session_dir: str
- outputs : 
- parent : workspace_shell
- surface : Flow Builder (batch-97 fb_A port)

| output | address | cardinality | consumers | owner |
|---|---|---|---|---|
| `pipeline` | `query("#flow_pipeline"), INDEXED POSITIONALLY` | len(flow.blocks) | 0 declared | LLR-146.1 |
| `palette` | `query("#flow_palette")` | 7 | 3 declared | LLR-146.2 |
| `run_action` | `query("#flow_run")` | 1 | 8 declared | LLR-146.5 |

### COMPONENT `fx_pipeline_rail` — .dev-flow/2026-10-19-batch-97/01-requirements.md:1570
- inputs : run_record: ChainSetRunRecord ; lanes: list ; session_dir: str
- outputs : 
- parent : workspace_shell
- surface : Flow Execution (batch-97 fx_A port)

| output | address | cardinality | consumers | owner |
|---|---|---|---|---|
| `lanes` | `query("#fx_lanes"), INDEXED POSITIONALLY` | one per imported lane (lane i reads record.outcomes[i]) | 2 declared | LLR-147.1 |
| `confirm` | `query("#fx_confirm_<i>") COMPUTED` | 1 per waiting lane | 2 declared | LLR-147.3 |
| `run_log` | `query("#fx_log")` | 1 | 3 declared | LLR-147.5 |
| `set_row` | `query("#fx_set_row")` | 1 | 1 declared | LLR-147.4 |

### COMPONENT `screen_header_chips` — .dev-flow/2026-10-19-batch-97/01-requirements.md:1606
- inputs : active_project_dir: Path ; family: str ; window_key: str
- outputs : 
- parent : workspace_shell
- surface : the headers of Patch Editor, Check Editor, Flow Builder, Flow Execution

| output | address | cardinality | consumers | owner |
|---|---|---|---|---|
| `folder_chip` | `query("#open_folder_<family>") COMPUTED` | exactly 1 widget per id | 10 declared | LLR-148.4 |
| `help_chip` | `query("#window_help_<key>") COMPUTED` | 1 per window key | 3 declared | LLR-148.6 |
| `glyph_legend` | `query(".glyph-legend")` | 1 per panel | 0 declared | LLR-148.7 |

### COMPONENT `bottom_key_bar` — .dev-flow/2026-10-19-batch-97/01-requirements.md:1643
- inputs : active_window: str ; focus: Widget ; window_key_table: Mapping[str, WindowKeys]
- outputs : 
- parent : workspace_shell
- surface : the bottom two rows of every window (replaces the shipped Footer, app.py:2077)

| output | address | cardinality | consumers | owner |
|---|---|---|---|---|
| `key_bar` | `query("#key_bar")` | exactly 1 | 0 declared | LLR-150.6 |

## STATUS — the real rules, run at derivation

- [-] V10  01-requirements.md: 148 FLOW node(s), every one owned
- [-] V11  01-requirements.md: 114 OUTPUT(s), each with an address and a declared consumer list
- [!] V12  .dev-flow/2026-08-24-batch-87/01-requirements.md:845: COMPONENT workspace_body: parent `workspace_shell` is not declared in this document, so balancing was NOT checked; this is not a pass
- [!] V12  .dev-flow/2026-10-12-batch-94/01-requirements.md:1131: COMPONENT check_editor_panel: parent `workspace_shell` is not declared in this document, so balancing was NOT checked; this is not a pass
- [!] V12  .dev-flow/2026-10-12-batch-94/01-requirements.md:1153: COMPONENT patch_editor_panel: parent `workspace_shell` is not declared in this document, so balancing was NOT checked; this is not a pass
- [!] V12  .dev-flow/2026-10-12-batch-94/01-requirements.md:1182: COMPONENT flow_builder_panel: parent `workspace_shell` is not declared in this document, so balancing was NOT checked; this is not a pass
- [!] V12  .dev-flow/2026-10-12-batch-94/01-requirements.md:1204: COMPONENT flow_execution_panel: parent `workspace_shell` is not declared in this document, so balancing was NOT checked; this is not a pass
- [!] V12  .dev-flow/2026-10-19-batch-97/01-requirements.md:1455: COMPONENT pe_ledger_inspector: parent `workspace_shell` is not declared in this document, so balancing was NOT checked; this is not a pass
- [!] V12  .dev-flow/2026-10-19-batch-97/01-requirements.md:1506: COMPONENT ce_ledger_inspector: parent `workspace_shell` is not declared in this document, so balancing was NOT checked; this is not a pass
- [!] V12  .dev-flow/2026-10-19-batch-97/01-requirements.md:1535: COMPONENT fb_pipeline_rail: parent `workspace_shell` is not declared in this document, so balancing was NOT checked; this is not a pass
- [!] V12  .dev-flow/2026-10-19-batch-97/01-requirements.md:1570: COMPONENT fx_pipeline_rail: parent `workspace_shell` is not declared in this document, so balancing was NOT checked; this is not a pass
- [!] V12  .dev-flow/2026-10-19-batch-97/01-requirements.md:1606: COMPONENT screen_header_chips: parent `workspace_shell` is not declared in this document, so balancing was NOT checked; this is not a pass
- [!] V12  .dev-flow/2026-10-19-batch-97/01-requirements.md:1643: COMPONENT bottom_key_bar: parent `workspace_shell` is not declared in this document, so balancing was NOT checked; this is not a pass
- [!] V13  .dev-flow/2026-08-21-batch-85/01-requirements.md:509: COMPONENT loaded_panel/panel_handle: reached by 2 undeclared file(s) — .fast-dev-flow/archive/2026-07-23-n6-n7-spec.md, prototypes/legend_n8.INVENTORY.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-21-batch-85/01-requirements.md:519: COMPONENT loaded_panel/slots_container: reached by 1 undeclared file(s) — s19_app/tui/screens_directionb.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-21-batch-85/01-requirements.md:540: COMPONENT loaded_panel/artifact_slots: reached by 1 undeclared file(s) — .fast-dev-flow/archive/2026-08-21-batch-85-ifc-pilot-promoted-spec.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-86/01-requirements.md:391: COMPONENT screen_workspace/screen_root: reached by 4 undeclared file(s) — .fast-dev-flow/archive/2026-07-20-unload-feature-spec.md, REQUIREMENTS.md, prototypes/legend_n8.INVENTORY.md, tests/test_segment_split_window.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
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
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:850: COMPONENT workspace_body/body_root: reached by 7 undeclared file(s) — .fast-dev-flow/ADR-flow-builder-tracer.md, REQUIREMENTS.md, s19_app/tui/screens.py, s19_app/tui/screens_directionb.py, tests/test_b97_width.py, tests/test_tui_map_big.py, tests/test_tui_patch_editor_b94.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:865: COMPONENT workspace_body/screen_slot_set: reached by 6 undeclared file(s) — s19_app/tui/open_folder_chip.py, tests/test_b97_check_editor.py, tests/test_b97_chips_help.py, tests/test_b97_patch_editor.py, tests/test_open_folder_chips.py, tests/test_window_usage_help.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:871: COMPONENT workspace_body/a2l_screen: reached by 2 undeclared file(s) — prototypes/legend_n8.INVENTORY.md, s19_app/tui/styles.tcss. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:880: COMPONENT workspace_body/mac_screen: reached by 1 undeclared file(s) — prototypes/legend_n8.INVENTORY.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:889: COMPONENT workspace_body/map_screen: reached by 4 undeclared file(s) — REQUIREMENTS.md, prototypes/legend_n8.INVENTORY.md, tests/test_command_bar_interlock.py, tests/test_segment_split_window.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:898: COMPONENT workspace_body/issues_screen: reached by 4 undeclared file(s) — REQUIREMENTS.md, prototypes/legend_n8.INVENTORY.md, s19_app/tui/styles.tcss, tests/test_tui_issues_view.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:909: COMPONENT workspace_body/patch_screen: reached by 2 undeclared file(s) — tests/test_b97_chips_help.py, tests/test_b97_patch_editor.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:926: COMPONENT workspace_body/flow_screen: reached by 10 undeclared file(s) — .fast-dev-flow/ADR-flow-builder-tracer.md, .fast-dev-flow/archive/2026-07-14-batch44-flow-builder-spec.md, REQUIREMENTS.md, s19_app/tui/flow_screens.py, tests/test_b97_chips_help.py, tests/test_b97_flow_builder.py, tests/test_flow_builder_render.py, tests/test_tui_flow_builder_b94.py, tests/test_tui_flow_execution_b94.py, tests/test_tui_snapshot.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:933: COMPONENT workspace_body/checks_screen: reached by 2 undeclared file(s) — prototypes/legend_n8.INVENTORY.md, s19_app/tui/styles.tcss. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:942: COMPONENT workspace_body/crc_designer_screen: reached by 2 undeclared file(s) — docs/crc-algorithm-designer/01-requirements.md, s19_app/tui/crc_designer_view.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-24-batch-87/01-requirements.md:950: COMPONENT workspace_body/screen_root: reached by 4 undeclared file(s) — .fast-dev-flow/archive/2026-07-20-unload-feature-spec.md, REQUIREMENTS.md, prototypes/legend_n8.INVENTORY.md, tests/test_segment_split_window.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
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
- [!] V13  .dev-flow/2026-10-12-batch-94/01-requirements.md:1158: COMPONENT patch_editor_panel/entries_table_rows: reached by 17 undeclared file(s) — REQUIREMENTS.md, s19_app/tui/screens.py, s19_app/tui/screens_directionb.py, s19_app/tui/services/change_service.py, s19_app/tui/styles.tcss, tests/test_b97_chips_help.py, tests/test_b97_patch_editor.py, tests/test_b97_width.py, tests/test_tui_checks_screen.py, tests/test_tui_patch_big.py, tests/test_tui_patch_card.py, tests/test_tui_patch_checks_strip.py, tests/test_tui_patch_editor_b94.py, tests/test_tui_patch_editor_v2.py, tests/test_tui_patch_glyphs.py, tests/test_tui_patch_layout.py, tests/test_tui_patch_variant.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-10-19-batch-97/01-requirements.md:1460: COMPONENT pe_ledger_inspector/entries_ledger: reached by 6 undeclared file(s) — REQUIREMENTS.md, s19_app/tui/screens.py, s19_app/tui/services/change_service.py, tests/test_b97_chips_help.py, tests/test_b97_patch_editor.py, tests/test_b97_width.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-10-19-batch-97/01-requirements.md:1476: COMPONENT pe_ledger_inspector/json_tab: reached by 2 undeclared file(s) — .fast-dev-flow/archive/2026-07-18-json-editor-fill-height-spec.md, REQUIREMENTS.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-10-19-batch-97/01-requirements.md:1491: COMPONENT pe_ledger_inspector/json_view: reached by 5 undeclared file(s) — s19_app/tui/screens_directionb.py, s19_app/tui/styles.tcss, tests/test_b97_chips_help.py, tests/test_b97_patch_editor.py, tests/test_tui_patch_json.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-10-19-batch-97/01-requirements.md:1497: COMPONENT pe_ledger_inspector/identity_ribbon: reached by 4 undeclared file(s) — s19_app/tui/screens_directionb.py, s19_app/tui/styles.tcss, tests/test_b97_patch_editor.py, tests/test_b97_width.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-10-19-batch-97/01-requirements.md:1511: COMPONENT ce_ledger_inspector/parameter_ledger: reached by 4 undeclared file(s) — s19_app/tui/styles.tcss, tests/test_b97_check_editor.py, tests/test_b97_chips_help.py, tests/test_b97_width.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-10-19-batch-97/01-requirements.md:1518: COMPONENT ce_ledger_inspector/write_action: reached by 2 undeclared file(s) — tests/test_b97_check_editor.py, tests/test_b97_chips_help.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-10-19-batch-97/01-requirements.md:1526: COMPONENT ce_ledger_inspector/fields_count: reached by 2 undeclared file(s) — s19_app/tui/styles.tcss, tests/test_b97_check_editor.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-10-19-batch-97/01-requirements.md:1540: COMPONENT fb_pipeline_rail/pipeline: reached by 5 undeclared file(s) — s19_app/tui/flow_screens.py, s19_app/tui/styles.tcss, tests/test_b97_chips_help.py, tests/test_b97_flow_builder.py, tests/test_b97_width.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-10-19-batch-97/01-requirements.md:1546: COMPONENT fb_pipeline_rail/palette: reached by 4 undeclared file(s) — s19_app/tui/styles.tcss, tests/test_b97_chips_help.py, tests/test_b97_flow_builder.py, tests/test_b97_width.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-10-19-batch-97/01-requirements.md:1554: COMPONENT fb_pipeline_rail/run_action: reached by 4 undeclared file(s) — s19_app/tui/styles.tcss, tests/test_b97_chips_help.py, tests/test_b97_flow_builder.py, tests/test_b97_width.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  01-requirements.md: 9 address(es) carry no quoted literal, so nothing was searched for them — screen_workspace/empty_state, workspace_body/empty_state, C-92-1/hex-rendered rows, C-92-1/layout constants, C-92-2/microbar bar + style constants, C-92-3/markup-safe Text, split_join_engine/output_files, split_join_engine/memory_segment_rows, change_set_wire/resolved_entries. A computed address cannot be followed by grep; recognising those SITES is the project's own rule
- [-] V14  01-requirements.md: 364 declared consumer(s), every one resolved
- [-] V19  01-requirements.md: 18 COMPONENT id(s), each declared exactly once
