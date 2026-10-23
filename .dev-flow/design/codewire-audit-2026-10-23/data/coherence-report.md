# Code-Wire coherence check

| Rule | Open |
|---|---|
| C2 · input with no edge | 46 |
| C2 · info: input with a default value and no edge | 19 |
| C2 · input that only a node-to-node call edge (no ports) reaches: open under §3.3 | 3 |
| C3 · output that nothing uses | 16 |
| C4 · node that no source reaches | 3 |
| C4 · node that reaches no sink | 6 |
| C7 · name used two times | 0 |
| C10 · `modify:` target that is not declared | 0 |
| C10 · entity that no node reads or writes | 0 |

## C2 · input with no edge

- `S19TuiApp._load_mac_file.path`
- `S19TuiApp._parse_loaded_file.path`
- `parse_a2l_file.path`
- `_apply_compu_method.compu_tables_by_name`
- `ChangeService.add_entry.address_text`
- `ChangeService.add_entry.value_text`
- `ChangeService.apply.ranges`
- `ChangeService.apply.mac_records`
- `ChangeService.apply.a2l_tags`
- `S19TuiApp.on_patch_editor_panel_save_back_decision.event`
- `save_patched_image.ranges`
- `save_patched_image.dest_dir`
- `save_patched_image.filename`
- `save_patched_image.source_kind`
- `verify_written_image.file_type`
- `apply_change_document.ranges`
- `apply_change_document.mac_records`
- `apply_change_document.a2l_tags`
- `inject_crcs.crc_regions`
- `compose_flow_report.generated_at`
- `run_chain_set.ctx`
- `compose_chain_set_report.set_name`
- `compose_chain_set_report.generated_at`
- `encode_physical_to_raw_bytes.tag`
- `_invert_physical_to_raw.method`
- `_invert_physical_to_raw.compu_tabs_by_name`
- `write_project_manifest.variant_set`
- `write_project_manifest.project_dir`
- `build_plan.sel`
- `build_plan.mem_map`
- `build_plan.mode`
- `build_plan.gap`
- `build_plan.stem`
- `build_plan.ext`
- `write_split_join_export.mode`
- `write_split_join_export.gap`
- `write_split_join_export.pad_byte`
- `write_split_join_export.fmt`
- `write_split_join_export.stem`
- `write_split_join_export.dest_dir`
- `fill_range.start`
- `fill_range.end`
- `fill_range.pad_byte`
- `fill_range.intra_gap`
- `emit_image.ranges`
- `emit_image.fmt`

## C2 · info: input with a default value and no edge

- `S19File.__init__.endian`
- `S19TuiApp._load_mac_file.a2l_files`
- `S19TuiApp._parse_loaded_file.a2l_files`
- `ChangeService.apply.variant_id`
- `save_patched_image.bytes_per_line`
- `save_patched_image.s0_header`
- `apply_change_document.now_fn`
- `apply_change_document.variant_id`
- `run_chain_set.mode`
- `run_chain_set.set_name`
- `run_chain_set.run_one`
- `run_chain_set.clock`
- `resolve_symbol_entry.value_mode`
- `encode_physical_to_raw_bytes.compu_methods_by_name`
- `encode_physical_to_raw_bytes.compu_tabs_by_name`
- `encode_physical_to_raw_bytes.record_layouts_by_name`
- `write_project_manifest.gathered`
- `build_plan.pad_byte`
- `write_split_join_export.zero_coverage_empty`

## C2 · input that only a node-to-node call edge (no ports) reaches: open under §3.3

- `build_loaded_s19.path`
- `build_loaded_s19.a2l_path`
- `build_loaded_s19.a2l_data`

## C3 · output that nothing uses

- `build_mem_map_s19.mem_map`
- `S19File.get_memory_ranges.ranges`
- `S19TuiApp._load_mac_file.loaded`
- `_apply_compu_method.status`
- `_apply_compu_method.message`
- `ChangeService.add_entry.entry`
- `parse_new_bytes.values`
- `ChangeService.apply.summary`
- `save_patched_image.issues`
- `inject_crcs.ranges`
- `encode_physical_to_raw_bytes.raw_bytes`
- `encode_physical_to_raw_bytes.reason`
- `encode_physical_to_raw_bytes.flags`
- `_invert_physical_to_raw.reason`
- `write_project_manifest.issues`
- `fill_range.planned_ranges`

## C4 · node that no source reaches

- `ChangeService.undo`
- `S19File.get_memory_ranges`
- `parse_a2l_file`

## C4 · node that reaches no sink

- `_apply_compu_method`
- `_invert_physical_to_raw`
- `encode_physical_to_raw_bytes`
- `parse_a2l_file`
- `parse_new_bytes`
- `verify_written_image`
