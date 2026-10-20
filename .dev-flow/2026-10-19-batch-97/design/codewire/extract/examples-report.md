# Code-Wire examples check

- Threads with a recorded run: BAT-drive-rel, BAT-output-name, BAT-traversal, PROBE-2EXT, TC-1804, TC-703, TC-704, TC-705, TC-B94-10, TC-B94-31
- Example lines: 89 · ok 31 · drift 0 · node not run 0 · not observed 6 · no trace 52

| node | thread | status | detail |
|---|---|---|---|
| `S19TuiApp.on_patch_editor_panel_action_requested` | TC-B94-10 | ok |  |
| `S19TuiApp.on_patch_editor_panel_action_requested` | TC-B94-10 | ok |  |
| `S19TuiApp.on_patch_editor_panel_action_requested` | AT-B97-02 | no_trace | no recorded run for this thread |
| `S19TuiApp.action_patch_undo` | TC-B97-06 | no_trace | no recorded run for this thread |
| `S19TuiApp.action_patch_redo` | TC-B97-06 | no_trace | no recorded run for this thread |
| `S19TuiApp._apply_entry_json_edit` | TC-B97-06 | no_trace | no recorded run for this thread |
| `S19TuiApp._refresh_patch_history_view` | TC-B97-06 | no_trace | no recorded run for this thread |
| `S19TuiApp._patch_editor_load` | TC-B94-10 | ok |  |
| `S19TuiApp._patch_editor_load_tail` | TC-B94-10 | not_observed | marked as not observed in the run |
| `S19TuiApp._patch_editor_load_tail` | AT-B97-01 | no_trace | no recorded run for this thread |
| `S19TuiApp._apply_prepared_load` | TC-B97-06 | no_trace | no recorded run for this thread |
| `S19TuiApp._patch_document_view` | TC-B94-10 | not_observed | marked as not observed in the run |
| `serialize_change_document` | TC-B94-10 | ok |  |
| `PatchEditorPanel.refresh_entries` | TC-B94-10 | ok |  |
| `PatchEditorPanel.refresh_entries` | AT-B97-02 | no_trace | no recorded run for this thread |
| `PatchEditorPanel._refresh_dirty_indicator` | TC-B94-10 | not_observed | marked as not observed in the run |
| `PatchEditorPanel._refresh_dirty_indicator` | AT-B97-02 | no_trace | no recorded run for this thread |
| `json_stamp_text` | AT-B97-02 | no_trace | no recorded run for this thread |
| `json_stamp_text` | TC-B97-06 | no_trace | no recorded run for this thread |
| `PatchEditorPanel.mark_saved` | TC-B94-10 | ok |  |
| `PatchEditorPanel.mark_loaded` | TC-B94-10 | ok |  |
| `PatchEditorPanel.request_action` | TC-B94-10 | ok |  |
| `PatchEditorPanel.request_action` | TC-B94-10 | ok |  |
| `PatchEditorPanel.on_text_area_changed` | TC-B94-10 | not_observed | marked as not observed in the run |
| `OpenFolderChip.__init__` | AT-B97-12 | no_trace | no recorded run for this thread |
| `OpenFolderChip.__init__` | AT-B97-12 | no_trace | no recorded run for this thread |
| `OpenFolderChip.refresh_target` | AT-B97-13 | no_trace | no recorded run for this thread |
| `OpenFolderChip._open_target` | TC-704 | not_observed | marked as not observed in the run |
| `OpenFolderChip._open_target` | AT-B97-12 | no_trace | no recorded run for this thread |
| `resolve_chip_target` | TC-704 | ok |  |
| `resolve_chip_target` | TC-703 | ok |  |
| `resolve_chip_target` | AT-B97-12 | no_trace | no recorded run for this thread |
| `create_chip_home` | TC-704 | ok |  |
| `create_chip_home` | AT-B97-12 | no_trace | no recorded run for this thread |
| `no_project_reason` | AT-B97-13 | no_trace | no recorded run for this thread |
| `is_openable_chip_dir` | AT-B97-12 | no_trace | no recorded run for this thread |
| `is_openable_chip_dir` | TC-B97-57 | no_trace | no recorded run for this thread |
| `_path_traverses_reparse_point` | TC-704 | ok |  |
| `open_folder_in_file_manager` | TC-705 | ok |  |
| `load_flow_json` | TC-B97-62 | no_trace | no recorded run for this thread |
| `dict_to_flow` | BAT-traversal | ok |  |
| `dict_to_flow` | BAT-drive-rel | ok |  |
| `dict_to_flow` | BAT-output-name | ok |  |
| `dict_to_flow` | TC-B97-62 | no_trace | no recorded run for this thread |
| `_parse_a2b_entry` | TC-B97-62 | no_trace | no recorded run for this thread |
| `_parse_external_step_entry` | TC-B97-62 | no_trace | no recorded run for this thread |
| `_parse_external_step_entry` | P-36 | no_trace | no recorded run for this thread |
| `load_chain_set` | TC-B94-31 | ok |  |
| `load_chain_set` | TC-B97-62 | no_trace | no recorded run for this thread |
| `dict_to_chain_set` | TC-B94-31 | ok |  |
| `dict_to_chain_set` | TC-B94-31 | ok |  |
| `dict_to_chain_set` | TC-B97-62 | no_trace | no recorded run for this thread |
| `_resolve_manifest_entry` | TC-B94-31 | ok |  |
| `_resolve_manifest_entry` | AT-B97-23 | no_trace | no recorded run for this thread |
| `read_project_manifest` | TC-B97-62 | no_trace | no recorded run for this thread |
| `run_flow` | P-50 | no_trace | no recorded run for this thread |
| `run_flow` | AT-B97-23 | no_trace | no recorded run for this thread |
| `_chain_inputs` | AT-B97-23 | no_trace | no recorded run for this thread |
| `_FlowExecutionSection.action_confirm_attention` | AT-B97-20 | no_trace | no recorded run for this thread |
| `FlowExecutionPanel.confirm_attention` | TC-B97-64 | no_trace | no recorded run for this thread |
| `FlowExecutionPanel.confirm_attention` | TC-B97-64 | no_trace | no recorded run for this thread |
| `FlowExecutionPanel.on_button_pressed` | TC-1804 | not_observed | marked as not observed in the run |
| `FlowExecutionPanel.on_button_pressed` | TC-B97-55 | no_trace | no recorded run for this thread |
| `S19TuiApp.on_flow_execution_panel_run_requested` | TC-1804 | ok |  |
| `S19TuiApp.on_flow_execution_panel_run_requested` | TC-B97-55 | no_trace | no recorded run for this thread |
| `S19TuiApp.on_flow_execution_panel_external_step_confirmed` | PROBE-2EXT | ok |  |
| `run_chain_set` | TC-1804 | ok |  |
| `run_chain_set` | PROBE-2EXT | ok |  |
| `FlowExecutionPanel.render_run` | TC-1804 | ok |  |
| `FlowExecutionPanel.render_run` | AT-B97-20 | no_trace | no recorded run for this thread |
| `FlowExecutionPanel.apply_confirmed_run` | TC-1804 | ok |  |
| `FlowExecutionPanel.apply_confirmed_run` | PROBE-2EXT | ok |  |
| `FlowExecutionPanel.apply_confirmed_run` | TC-B97-64 | no_trace | no recorded run for this thread |
| `FlowExecutionPanel.render_run_error` | TC-B97-55 | no_trace | no recorded run for this thread |
| `patch_layout` | D21 | no_trace | no recorded run for this thread |
| `check_layout` | D21 | no_trace | no recorded run for this thread |
| `pipeline_layout` | D21 | no_trace | no recorded run for this thread |
| `lane_layout` | D21 | no_trace | no recorded run for this thread |
| `PatchEditorPanel._apply_layout` | TC-B97-34 | no_trace | no recorded run for this thread |
| `PatchEditorPanel.on_resize` | TC-B97-34 | no_trace | no recorded run for this thread |
| `CheckEditorPanel._apply_layout` | TC-B97-34 | no_trace | no recorded run for this thread |
| `FlowBuilderPanel._apply_layout` | AT-B97-16 | no_trace | no recorded run for this thread |
| `FlowExecutionPanel._apply_layout` | AT-B97-15 | no_trace | no recorded run for this thread |
| `PatchEditorPanel._render_before_after_card` | TC-B94-10 | ok |  |
| `PatchEditorPanel._render_before_after_card` | TC-B97-39 | no_trace | no recorded run for this thread |
| `BeforeAfterCard.show_entry` | TC-B94-10 | ok |  |
| `BeforeAfterCard.show_entry` | TC-B97-39 | no_trace | no recorded run for this thread |
| `before_after_card_text` | TC-B94-10 | ok |  |
| `before_after_card_text` | TC-B97-39 | no_trace | no recorded run for this thread |
