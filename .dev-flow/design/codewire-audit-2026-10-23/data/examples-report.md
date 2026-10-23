# Code-Wire examples check

- Threads with a recorded run: T1, T2, T3, T4, T5, T5b, T6
- Example lines: 53 · ok 53 · drift 0 · no anchor 0 · node not run 0 · no def 0 · not observed 0 · no trace 0
- Lines with a bare number (a warning: the check does not compare it): 8

| node | thread | status | detail | bare numbers |
|---|---|---|---|---|
| `S19File.__init__` | T1 | ok |  | 1, 9, 2 |
| `S19File.__init__` | T1 | ok |  |  |
| `build_mem_map_s19` | T1 | ok |  |  |
| `S19File.get_memory_ranges` | T1 | ok |  |  |
| `S19File.get_memory_ranges` | T1 | ok |  |  |
| `build_loaded_s19` | T1 | ok |  |  |
| `build_loaded_s19` | T1 | ok |  |  |
| `parse_mac_file` | T1 | ok |  | 2 |
| `S19TuiApp._load_mac_file` | T1 | ok |  |  |
| `S19TuiApp._merge_primary_with_existing_mac` | T1 | ok |  |  |
| `S19TuiApp._parse_loaded_file` | T1 | ok |  |  |
| `parse_a2l_file` | T1 | ok |  |  |
| `_apply_compu_method` | T1 | ok |  | 32 |
| `_apply_compu_method` | T4 | ok |  |  |
| `_apply_compu_method` | T4 | ok |  |  |
| `S19TuiApp.on_patch_editor_panel_action_requested` | T2 | ok |  |  |
| `S19TuiApp.on_patch_editor_panel_action_requested` | T2 | ok |  |  |
| `ChangeService.add_entry` | T2 | ok |  |  |
| `parse_new_bytes` | T2 | ok |  |  |
| `parse_new_bytes` | T2 | ok |  |  |
| `ChangeService.apply` | T2 | ok |  | 1, 1 |
| `ChangeService.apply` | T2 | ok |  | 1, 1 |
| `ChangeService.undo` | T2 | ok |  |  |
| `S19TuiApp.on_patch_editor_panel_save_back_decision` | T2 | ok |  |  |
| `S19TuiApp.on_patch_editor_panel_save_back_decision` | T2 | ok |  |  |
| `save_patched_image` | T2 | ok |  | 1, 2 |
| `save_patched_image` | T2 | ok |  | 1 |
| `save_patched_image` | T3 | ok |  |  |
| `verify_written_image` | T2 | ok |  |  |
| `run_flow` | T3 | ok |  |  |
| `apply_change_document` | T3 | ok |  | 2, 2 |
| `inject_crcs` | T3 | ok |  |  |
| `compose_flow_report` | T3 | ok |  |  |
| `run_chain_set` | T3 | ok |  |  |
| `compose_chain_set_report` | T3 | ok |  |  |
| `resolve_symbol_entry` | T4 | ok |  |  |
| `resolve_symbol_entry` | T4 | ok |  |  |
| `encode_physical_to_raw_bytes` | T4 | ok |  |  |
| `encode_physical_to_raw_bytes` | T4 | ok |  |  |
| `_invert_physical_to_raw` | T4 | ok |  |  |
| `S19TuiApp._handle_save_dialog` | T5 | ok |  |  |
| `S19TuiApp._handle_save_dialog` | T5b | ok |  |  |
| `write_project_manifest` | T5b | ok |  |  |
| `read_project_manifest` | T5b | ok |  |  |
| `read_project_manifest` | T5 | ok |  |  |
| `S19TuiApp._handle_load_project` | T5b | ok |  |  |
| `S19TuiApp._handle_load_project` | T5 | ok |  |  |
| `build_plan` | T6 | ok |  |  |
| `write_split_join_export` | T6 | ok |  |  |
| `write_split_join_export` | T6 | ok |  |  |
| `fill_range` | T6 | ok |  |  |
| `emit_image` | T6 | ok |  |  |
| `emit_image` | T6 | ok |  |  |

## Node status

NEW 0 · CHANGED 0 · SHIPPED 35

| node | status | why |
|---|---|---|
| `ChangeService.add_entry` | SHIPPED | a def and no `synthetic` line |
| `ChangeService.apply` | SHIPPED | a def and no `synthetic` line |
| `ChangeService.undo` | SHIPPED | a def and no `synthetic` line |
| `S19File.__init__` | SHIPPED | a def and no `synthetic` line |
| `S19File.get_memory_ranges` | SHIPPED | a def and no `synthetic` line |
| `S19TuiApp._handle_load_project` | SHIPPED | a def and no `synthetic` line |
| `S19TuiApp._handle_save_dialog` | SHIPPED | a def and no `synthetic` line |
| `S19TuiApp._load_mac_file` | SHIPPED | a def and no `synthetic` line |
| `S19TuiApp._merge_primary_with_existing_mac` | SHIPPED | a def and no `synthetic` line |
| `S19TuiApp._parse_loaded_file` | SHIPPED | a def and no `synthetic` line |
| `S19TuiApp.on_patch_editor_panel_action_requested` | SHIPPED | a def and no `synthetic` line |
| `S19TuiApp.on_patch_editor_panel_save_back_decision` | SHIPPED | a def and no `synthetic` line |
| `_apply_compu_method` | SHIPPED | a def and no `synthetic` line |
| `_invert_physical_to_raw` | SHIPPED | a def and no `synthetic` line |
| `apply_change_document` | SHIPPED | a def and no `synthetic` line |
| `build_loaded_s19` | SHIPPED | a def and no `synthetic` line |
| `build_mem_map_s19` | SHIPPED | a def and no `synthetic` line |
| `build_plan` | SHIPPED | a def and no `synthetic` line |
| `compose_chain_set_report` | SHIPPED | a def and no `synthetic` line |
| `compose_flow_report` | SHIPPED | a def and no `synthetic` line |
| `emit_image` | SHIPPED | a def and no `synthetic` line |
| `encode_physical_to_raw_bytes` | SHIPPED | a def and no `synthetic` line |
| `fill_range` | SHIPPED | a def and no `synthetic` line |
| `inject_crcs` | SHIPPED | a def and no `synthetic` line |
| `parse_a2l_file` | SHIPPED | a def and no `synthetic` line |
| `parse_mac_file` | SHIPPED | a def and no `synthetic` line |
| `parse_new_bytes` | SHIPPED | a def and no `synthetic` line |
| `read_project_manifest` | SHIPPED | a def and no `synthetic` line |
| `resolve_symbol_entry` | SHIPPED | a def and no `synthetic` line |
| `run_chain_set` | SHIPPED | a def and no `synthetic` line |
| `run_flow` | SHIPPED | a def and no `synthetic` line |
| `save_patched_image` | SHIPPED | a def and no `synthetic` line |
| `verify_written_image` | SHIPPED | a def and no `synthetic` line |
| `write_project_manifest` | SHIPPED | a def and no `synthetic` line |
| `write_split_join_export` | SHIPPED | a def and no `synthetic` line |
