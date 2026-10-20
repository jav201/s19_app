# Code-Wire DDR diff report

- Marks found: 43
- Graph nodes parsed: 57 · edges: 95 (12 with `when:`)
- Nodes with `examples:`: 57/57 (89 pairs)
- Lifted calls between marked nodes (O2): 45 (43 declared, 2 divergent)
- Findings: 54 (23 drift, 31 info)
- Ambiguous call resolutions (a name matched several defs): 31
- Files that failed to parse: 0

Type normalisation: spaces and quotes dropped; `List/Dict/Tuple/Set` -> builtins; `X | None` and graph `X?` -> `Optional[X]`; graph `(Callable) A->B` -> `Callable[[A], B]`; graph `tuple(A a, B b)` -> `tuple[A, B]`. A bare graph container (`dict`) against a parameterised code type (`dict[str, Any]`), at top level or nested, is info (loose match), not drift.

Call resolution is name-based (`f()`, `Class()` -> `__init__`, `self.m()`, `x.m()` -> top-level `m` or a marked method `m`); dynamic calls and callables passed as values are not seen. Tests excluded.

## Counts

| Kind | Count |
|---|---|
| Graph node without mark | 14 |
| Input in graph, not a parameter in code | 3 |
| Input type mismatch | 2 |
| Parameter unannotated in code (cannot compare) | 2 |
| C15 divergence: lifted call not declared in the graph | 2 |
| Info: declared in `inner:`, no lifted call found (C15 absence) | 19 |
| Info: node declared in two `inner:` lists | 12 |

## C15 · lifted calls (O2)

| Caller | Callee | Sites | Declared via |
|---|---|---|---|
| `BeforeAfterCard.show_entry` | `before_after_card_text` | s19_app/tui/screens_directionb.py:4302 | inner |
| `OpenFolderChip._open_target` | `OpenFolderChip.refresh_target` | s19_app/tui/open_folder_chip.py:185 | inner |
| `OpenFolderChip._open_target` | `create_chip_home` | s19_app/tui/open_folder_chip.py:167 | inner |
| `OpenFolderChip._open_target` | `open_folder_in_file_manager` | s19_app/tui/open_folder_chip.py:177 | inner |
| `OpenFolderChip._open_target` | `resolve_chip_target` | s19_app/tui/open_folder_chip.py:154 | inner |
| `OpenFolderChip.refresh_target` | `resolve_chip_target` | s19_app/tui/open_folder_chip.py:105 | inner |
| `PatchEditorPanel._render_before_after_card` | `BeforeAfterCard.show_entry` | s19_app/tui/screens_directionb.py:6335, s19_app/tui/screens_directionb.py:6345, s19_app/tui/screens_directionb.py:6350 | inner |
| `PatchEditorPanel.mark_loaded` | `PatchEditorPanel._refresh_dirty_indicator` | s19_app/tui/screens_directionb.py:5972 | inner |
| `PatchEditorPanel.mark_saved` | `PatchEditorPanel._refresh_dirty_indicator` | s19_app/tui/screens_directionb.py:5960 | inner |
| `PatchEditorPanel.on_text_area_changed` | `PatchEditorPanel._refresh_dirty_indicator` | s19_app/tui/screens_directionb.py:5712 | inner |
| `PatchEditorPanel.refresh_entries` | `PatchEditorPanel._render_before_after_card` | s19_app/tui/screens_directionb.py:6238 | inner |
| `PatchEditorPanel.request_action` | `PatchEditorPanel._refresh_dirty_indicator` | s19_app/tui/screens_directionb.py:5777 | inner |
| `S19TuiApp._apply_entry_json_edit` | `S19TuiApp._refresh_patch_history_view` | s19_app/tui/app.py:3832 | inner |
| `S19TuiApp._apply_prepared_load` | `PatchEditorPanel.refresh_entries` | s19_app/tui/app.py:10768 | inner |
| `S19TuiApp._patch_editor_load` | `PatchEditorPanel.mark_loaded` | s19_app/tui/app.py:5271 | inner |
| `S19TuiApp._patch_editor_load` | `S19TuiApp._patch_editor_load_tail` | s19_app/tui/app.py:5272 | inner |
| `S19TuiApp._patch_editor_load_tail` | `PatchEditorPanel.refresh_entries` | s19_app/tui/app.py:5288 | inner |
| `S19TuiApp._refresh_patch_history_view` | `PatchEditorPanel.refresh_entries` | s19_app/tui/app.py:3455 | inner |
| `S19TuiApp.action_patch_redo` | `S19TuiApp._refresh_patch_history_view` | s19_app/tui/app.py:3622 | inner |
| `S19TuiApp.action_patch_undo` | `S19TuiApp._refresh_patch_history_view` | s19_app/tui/app.py:3595 | inner |
| `S19TuiApp.on_flow_execution_panel_external_step_confirmed` | `FlowExecutionPanel.apply_confirmed_run` | s19_app/tui/app.py:2893 | inner |
| `S19TuiApp.on_flow_execution_panel_external_step_confirmed` | `FlowExecutionPanel.render_run_error` | s19_app/tui/app.py:2857 | inner |
| `S19TuiApp.on_flow_execution_panel_external_step_confirmed` | `run_chain_set` | s19_app/tui/app.py:2887 | inner |
| `S19TuiApp.on_flow_execution_panel_run_requested` | `FlowExecutionPanel.render_run` | s19_app/tui/app.py:2822 | inner |
| `S19TuiApp.on_flow_execution_panel_run_requested` | `FlowExecutionPanel.render_run_error` | s19_app/tui/app.py:2803 | inner |
| `S19TuiApp.on_flow_execution_panel_run_requested` | `run_chain_set` | s19_app/tui/app.py:2816 | inner |
| `S19TuiApp.on_patch_editor_panel_action_requested` | `PatchEditorPanel.mark_loaded` | s19_app/tui/app.py:3186 | inner |
| `S19TuiApp.on_patch_editor_panel_action_requested` | `PatchEditorPanel.mark_saved` | s19_app/tui/app.py:3239 | inner |
| `S19TuiApp.on_patch_editor_panel_action_requested` | `PatchEditorPanel.refresh_entries` | s19_app/tui/app.py:3268 | inner |
| `S19TuiApp.on_patch_editor_panel_action_requested` | `S19TuiApp._patch_editor_load` | s19_app/tui/app.py:3177 | inner |
| `S19TuiApp.on_patch_editor_panel_action_requested` | `_path_traverses_reparse_point` | s19_app/tui/services/project_gather_service.py:241 | **divergence** |
| `S19TuiApp.on_patch_editor_panel_action_requested` | `read_project_manifest` | s19_app/tui/app.py:4171, s19_app/tui/services/variant_execution_service.py:947 | **divergence** |
| `_chain_inputs` | `_resolve_manifest_entry` | s19_app/tui/services/flow_execution_service.py:1438 | inner |
| `_parse_a2b_entry` | `_resolve_manifest_entry` | s19_app/tui/services/flow_persistence_service.py:751 | inner |
| `_resolve_manifest_entry` | `_path_traverses_reparse_point` | s19_app/tui/services/variant_execution_service.py:284 | inner |
| `create_chip_home` | `_path_traverses_reparse_point` | s19_app/tui/services/project_gather_service.py:241 | inner |
| `dict_to_chain_set` | `_resolve_manifest_entry` | s19_app/tui/services/flow_persistence_service.py:1378 | inner |
| `dict_to_flow` | `_parse_a2b_entry` | s19_app/tui/services/flow_persistence_service.py:498 | inner |
| `dict_to_flow` | `_parse_external_step_entry` | s19_app/tui/services/flow_persistence_service.py:508 | inner |
| `dict_to_flow` | `_resolve_manifest_entry` | s19_app/tui/services/flow_persistence_service.py:570, s19_app/tui/services/flow_persistence_service.py:598 | inner |
| `load_chain_set` | `dict_to_chain_set` | s19_app/tui/services/flow_persistence_service.py:1498 | inner |
| `load_flow_json` | `dict_to_flow` | s19_app/tui/services/flow_persistence_service.py:928 | inner |
| `read_project_manifest` | `_resolve_manifest_entry` | s19_app/tui/services/variant_execution_service.py:498, s19_app/tui/services/variant_execution_service.py:526 | inner |
| `run_flow` | `_path_traverses_reparse_point` | s19_app/tui/workspace.py:338 | inner |
| `run_flow` | `_resolve_manifest_entry` | s19_app/tui/services/flow_execution_service.py:299, s19_app/tui/services/flow_execution_service.py:329, s19_app/tui/services/flow_execution_service.py:388, s19_app/tui/services/flow_execution_service.py:409, s19_app/tui/services/flow_execution_service.py:548, s19_app/tui/services/flow_execution_service.py:610, s19_app/tui/services/flow_execution_service.py:707 | inner |

Top-level sites (orchestration with no marked node above):

- `OpenFolderChip.__init__`: s19_app/tui/app.py:2321, s19_app/tui/app.py:2476, s19_app/tui/app.py:3050, s19_app/tui/screens.py:1668
- `OpenFolderChip._open_target`: s19_app/tui/open_folder_chip.py:139
- `OpenFolderChip.refresh_target`: s19_app/tui/app.py:12767, s19_app/tui/open_folder_chip.py:91
- `PatchEditorPanel._render_before_after_card`: s19_app/tui/screens_directionb.py:6277
- `PatchEditorPanel.mark_saved`: s19_app/tui/app.py:2653, s19_app/tui/app.py:2939
- `PatchEditorPanel.refresh_entries`: s19_app/tui/screens_directionb.py:5665
- `PatchEditorPanel.request_action`: s19_app/tui/screens_directionb.py:5933, s19_app/tui/screens_directionb.py:5949
- `S19TuiApp._apply_entry_json_edit`: s19_app/tui/app.py:3788
- `S19TuiApp._apply_prepared_load`: docs/images/capture_readme_media.py:88, s19_app/tui/app.py:10625
- `S19TuiApp._patch_editor_load`: s19_app/tui/app.py:5250, s19_app/tui/app.py:5330
- `S19TuiApp.action_patch_redo`: s19_app/tui/app.py:3538
- `S19TuiApp.action_patch_undo`: s19_app/tui/app.py:3513
- `_chain_inputs`: s19_app/tui/services/flow_execution_service.py:1514
- `_path_traverses_reparse_point`: s19_app/tui/services/manifest_writer.py:407
- `_resolve_manifest_entry`: prototypes/fb_p1_flow_persistence.prototype.py:289, s19_app/tui/services/manifest_writer.py:216
- `dict_to_flow`: s19_app/tui/flow_screens.py:1352
- `load_chain_set`: s19_app/tui/app.py:2973
- `load_flow_json`: s19_app/tui/app.py:2690, s19_app/tui/app.py:2757, s19_app/tui/app.py:2988
- `open_folder_in_file_manager`: s19_app/tui/app.py:6397
- `read_project_manifest`: s19_app/tui/app.py:2606, s19_app/tui/app.py:4645, s19_app/tui/app.py:4753, s19_app/tui/app.py:8172, s19_app/tui/services/manifest_writer.py:701
- `run_flow`: s19_app/tui/app.py:2581
- `serialize_change_document`: s19_app/tui/changes/io.py:1583, s19_app/tui/services/change_service.py:1269

## Graph node without mark

- `s19_app/tui/app.py` — `S19TuiApp._patch_document_view`
- `s19_app/tui/screens_directionb.py` — `json_stamp_text`
- `s19_app/tui/services/folder_open_service.py` — `no_project_reason`
- `s19_app/tui/services/folder_open_service.py` — `is_openable_chip_dir`
- `s19_app/tui/app.py` — `_FlowExecutionSection.action_confirm_attention`
- `s19_app/tui/flow_screens.py` — `FlowExecutionPanel.confirm_attention`
- `s19_app/tui/screens_directionb.py` — `patch_layout`
- `s19_app/tui/screens_directionb.py` — `check_layout`
- `s19_app/tui/flow_screens.py` — `pipeline_layout`
- `s19_app/tui/flow_screens.py` — `lane_layout`
- `s19_app/tui/screens_directionb.py` — `PatchEditorPanel._apply_layout`
- `s19_app/tui/screens_directionb.py` — `CheckEditorPanel._apply_layout`
- `s19_app/tui/flow_screens.py` — `FlowBuilderPanel._apply_layout`
- `s19_app/tui/flow_screens.py` — `FlowExecutionPanel._apply_layout`

## Input in graph, not a parameter in code

- `s19_app/tui/screens_directionb.py:6112` — graph input `document` not a parameter of `PatchEditorPanel.refresh_entries`
- `s19_app/tui/open_folder_chip.py:72` — graph input `id_suffix` not a parameter of `OpenFolderChip.__init__`
- `s19_app/tui/screens_directionb.py:4272` — graph input `max_bytes` not a parameter of `BeforeAfterCard.show_entry`

## Input type mismatch

- `s19_app/tui/screens_directionb.py:4272` — `before`: graph `Optional[Sequence[int?]]` vs code `Optional[Sequence[Optional[int]]]`
- `s19_app/tui/screens_directionb.py:4119` — `before`: graph `Optional[Sequence[int?]]` vs code `Optional[Sequence[Optional[int]]]`

## Parameter unannotated in code (cannot compare)

- `s19_app/tui/flow_screens.py:2399` — `record` has no annotation (graph: `ChainSetRunRecord`)
- `s19_app/tui/flow_screens.py:2502` — `record` has no annotation (graph: `ChainSetRunRecord`)

## C15 divergence: lifted call not declared in the graph

- `s19_app/tui/services/project_gather_service.py:241` — `S19TuiApp.on_patch_editor_panel_action_requested` → `_path_traverses_reparse_point` (sites: s19_app/tui/services/project_gather_service.py:241) not declared in `inner:` of `S19TuiApp.on_patch_editor_panel_action_requested` nor as an edge; also called at top level: s19_app/tui/services/manifest_writer.py:407
- `s19_app/tui/app.py:4171` — `S19TuiApp.on_patch_editor_panel_action_requested` → `read_project_manifest` (sites: s19_app/tui/app.py:4171, s19_app/tui/services/variant_execution_service.py:947) not declared in `inner:` of `S19TuiApp.on_patch_editor_panel_action_requested` nor as an edge; also called at top level: s19_app/tui/app.py:2606, s19_app/tui/app.py:4645, s19_app/tui/app.py:4753, s19_app/tui/app.py:8172, s19_app/tui/services/manifest_writer.py:701

## Info: declared in `inner:`, no lifted call found (C15 absence)

- `S19TuiApp.on_patch_editor_panel_action_requested` — `inner:` of `S19TuiApp.on_patch_editor_panel_action_requested` declares `S19TuiApp._patch_document_view`, no lifted call found
- `S19TuiApp._refresh_patch_history_view` — `inner:` of `S19TuiApp._refresh_patch_history_view` declares `S19TuiApp._patch_document_view`, no lifted call found
- `S19TuiApp._patch_editor_load_tail` — `inner:` of `S19TuiApp._patch_editor_load_tail` declares `S19TuiApp._patch_document_view`, no lifted call found
- `S19TuiApp._apply_prepared_load` — `inner:` of `S19TuiApp._apply_prepared_load` declares `S19TuiApp._patch_document_view`, no lifted call found
- `S19TuiApp._patch_document_view` — `inner:` of `S19TuiApp._patch_document_view` declares `serialize_change_document`, no lifted call found
- `PatchEditorPanel.refresh_entries` — `inner:` of `PatchEditorPanel.refresh_entries` declares `json_stamp_text`, no lifted call found
- `PatchEditorPanel._refresh_dirty_indicator` — `inner:` of `PatchEditorPanel._refresh_dirty_indicator` declares `json_stamp_text`, no lifted call found
- `OpenFolderChip.refresh_target` — `inner:` of `OpenFolderChip.refresh_target` declares `no_project_reason`, no lifted call found
- `OpenFolderChip._open_target` — `inner:` of `OpenFolderChip._open_target` declares `is_openable_chip_dir`, no lifted call found
- `OpenFolderChip._open_target` — `inner:` of `OpenFolderChip._open_target` declares `no_project_reason`, no lifted call found
- `is_openable_chip_dir` — `inner:` of `is_openable_chip_dir` declares `_path_traverses_reparse_point`, no lifted call found
- `_FlowExecutionSection.action_confirm_attention` — `inner:` of `_FlowExecutionSection.action_confirm_attention` declares `FlowExecutionPanel.confirm_attention`, no lifted call found
- `run_chain_set` — `inner:` of `run_chain_set` declares `run_flow`, no lifted call found
- `run_chain_set` — `inner:` of `run_chain_set` declares `_chain_inputs`, no lifted call found
- `PatchEditorPanel._apply_layout` — `inner:` of `PatchEditorPanel._apply_layout` declares `patch_layout`, no lifted call found
- `PatchEditorPanel.on_resize` — `inner:` of `PatchEditorPanel.on_resize` declares `PatchEditorPanel._apply_layout`, no lifted call found
- `CheckEditorPanel._apply_layout` — `inner:` of `CheckEditorPanel._apply_layout` declares `check_layout`, no lifted call found
- `FlowBuilderPanel._apply_layout` — `inner:` of `FlowBuilderPanel._apply_layout` declares `pipeline_layout`, no lifted call found
- `FlowExecutionPanel._apply_layout` — `inner:` of `FlowExecutionPanel._apply_layout` declares `lane_layout`, no lifted call found

## Info: node declared in two `inner:` lists

- `S19TuiApp._patch_document_view` — `S19TuiApp._patch_document_view` declared inside `S19TuiApp.on_patch_editor_panel_action_requested`, `S19TuiApp._refresh_patch_history_view`, `S19TuiApp._patch_editor_load_tail`, `S19TuiApp._apply_prepared_load`: two call sites by design
- `PatchEditorPanel.refresh_entries` — `PatchEditorPanel.refresh_entries` declared inside `S19TuiApp.on_patch_editor_panel_action_requested`, `S19TuiApp._refresh_patch_history_view`, `S19TuiApp._patch_editor_load_tail`, `S19TuiApp._apply_prepared_load`: two call sites by design
- `PatchEditorPanel.mark_loaded` — `PatchEditorPanel.mark_loaded` declared inside `S19TuiApp.on_patch_editor_panel_action_requested`, `S19TuiApp._patch_editor_load`: two call sites by design
- `S19TuiApp._refresh_patch_history_view` — `S19TuiApp._refresh_patch_history_view` declared inside `S19TuiApp.action_patch_undo`, `S19TuiApp.action_patch_redo`, `S19TuiApp._apply_entry_json_edit`: two call sites by design
- `json_stamp_text` — `json_stamp_text` declared inside `PatchEditorPanel.refresh_entries`, `PatchEditorPanel._refresh_dirty_indicator`: two call sites by design
- `PatchEditorPanel._refresh_dirty_indicator` — `PatchEditorPanel._refresh_dirty_indicator` declared inside `PatchEditorPanel.mark_saved`, `PatchEditorPanel.mark_loaded`, `PatchEditorPanel.request_action`, `PatchEditorPanel.on_text_area_changed`: two call sites by design
- `resolve_chip_target` — `resolve_chip_target` declared inside `OpenFolderChip.refresh_target`, `OpenFolderChip._open_target`: two call sites by design
- `no_project_reason` — `no_project_reason` declared inside `OpenFolderChip.refresh_target`, `OpenFolderChip._open_target`: two call sites by design
- `_path_traverses_reparse_point` — `_path_traverses_reparse_point` declared inside `create_chip_home`, `is_openable_chip_dir`, `_resolve_manifest_entry`, `run_flow`: two call sites by design
- `_resolve_manifest_entry` — `_resolve_manifest_entry` declared inside `dict_to_flow`, `_parse_a2b_entry`, `dict_to_chain_set`, `read_project_manifest`, `run_flow`, `_chain_inputs`: two call sites by design
- `run_chain_set` — `run_chain_set` declared inside `S19TuiApp.on_flow_execution_panel_run_requested`, `S19TuiApp.on_flow_execution_panel_external_step_confirmed`: two call sites by design
- `FlowExecutionPanel.render_run_error` — `FlowExecutionPanel.render_run_error` declared inside `S19TuiApp.on_flow_execution_panel_run_requested`, `S19TuiApp.on_flow_execution_panel_external_step_confirmed`: two call sites by design
