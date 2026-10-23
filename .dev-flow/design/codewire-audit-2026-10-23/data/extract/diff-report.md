# Code-Wire DDR diff report

- Marks found: 35
- Graph nodes parsed: 35 · edges: 66 (1 with `when:`)
- Nodes with `examples:`: 35/35 (53 pairs)
- Lifted calls between marked nodes (O2): 40 (23 declared, 17 divergent)
- Findings: 38 (36 drift, 2 info)
- Ambiguous call resolutions (a name matched several defs): 32
- Files that failed to parse: 1

Type normalisation: spaces and quotes dropped; `List/Dict/Tuple/Set` -> builtins; `X | None` and graph `X?` -> `Optional[X]`; graph `(Callable) A->B` -> `Callable[[A], B]`; graph `tuple(A a, B b)` -> `tuple[A, B]`. A bare graph container (`dict`) against a parameterised code type (`dict[str, Any]`), at top level or nested, is info (loose match), not drift.

Call resolution is name-based (`f()`, `Class()` -> `__init__`, `self.m()`, `x.m()` -> top-level `m` or a marked method `m`); dynamic calls and callables passed as values are not seen. Tests excluded.

## Counts

| Kind | Count |
|---|---|
| Input in graph, not a parameter in code | 1 |
| Parameter in code, not an input in graph | 5 |
| Input type mismatch | 1 |
| Default value mismatch (C12) | 3 |
| Output type mismatch | 2 |
| `inner:` names an unknown node | 7 |
| C15 divergence: lifted call not declared in the graph | 17 |
| Info: node declared in two `inner:` lists | 2 |

## C15 · lifted calls (O2)

| Caller | Callee | Sites | Declared via |
|---|---|---|---|
| `ChangeService.add_entry` | `parse_new_bytes` | s19_app/tui/services/change_service.py:1003 | inner |
| `ChangeService.apply` | `apply_change_document` | s19_app/tui/services/change_service.py:1662 | inner |
| `S19TuiApp._handle_load_project` | `S19TuiApp._parse_loaded_file` | s19_app/tui/app.py:10508 | **divergence** |
| `S19TuiApp._handle_load_project` | `read_project_manifest` | s19_app/tui/app.py:8226 | inner |
| `S19TuiApp._handle_save_dialog` | `read_project_manifest` | s19_app/tui/services/manifest_writer.py:702 | **divergence** |
| `S19TuiApp._handle_save_dialog` | `write_project_manifest` | s19_app/tui/app.py:8101 | inner |
| `S19TuiApp._load_mac_file` | `parse_a2l_file` | s19_app/tui/app.py:11250 | **divergence** |
| `S19TuiApp._load_mac_file` | `parse_mac_file` | s19_app/tui/app.py:9629 | edge |
| `S19TuiApp._parse_loaded_file` | `S19File.__init__` | s19_app/tui/app.py:10578 | **divergence** |
| `S19TuiApp._parse_loaded_file` | `S19TuiApp._load_mac_file` | s19_app/tui/app.py:10616 | inner |
| `S19TuiApp._parse_loaded_file` | `S19TuiApp._merge_primary_with_existing_mac` | s19_app/tui/app.py:10582, s19_app/tui/app.py:10601 | inner |
| `S19TuiApp._parse_loaded_file` | `build_loaded_s19` | s19_app/tui/app.py:10581 | inner |
| `S19TuiApp._parse_loaded_file` | `parse_a2l_file` | s19_app/tui/app.py:11250 | **divergence** |
| `S19TuiApp.on_patch_editor_panel_action_requested` | `ChangeService.add_entry` | s19_app/tui/app.py:3173 | inner |
| `S19TuiApp.on_patch_editor_panel_action_requested` | `ChangeService.apply` | s19_app/tui/app.py:3221 | inner |
| `S19TuiApp.on_patch_editor_panel_action_requested` | `S19File.__init__` | s19_app/tui/services/variant_execution_service.py:764 | **divergence** |
| `S19TuiApp.on_patch_editor_panel_action_requested` | `_apply_compu_method` | s19_app/tui/a2l.py:2619 | **divergence** |
| `S19TuiApp.on_patch_editor_panel_action_requested` | `apply_change_document` | s19_app/tui/services/variant_execution_service.py:787 | **divergence** |
| `S19TuiApp.on_patch_editor_panel_action_requested` | `build_loaded_s19` | s19_app/tui/services/variant_execution_service.py:763 | **divergence** |
| `S19TuiApp.on_patch_editor_panel_action_requested` | `parse_a2l_file` | s19_app/tui/services/variant_execution_service.py:879 | **divergence** |
| `S19TuiApp.on_patch_editor_panel_action_requested` | `parse_mac_file` | s19_app/tui/services/variant_execution_service.py:877 | **divergence** |
| `S19TuiApp.on_patch_editor_panel_action_requested` | `read_project_manifest` | s19_app/tui/app.py:4192, s19_app/tui/services/variant_execution_service.py:958 | **divergence** |
| `S19TuiApp.on_patch_editor_panel_action_requested` | `save_patched_image` | s19_app/tui/services/variant_execution_service.py:798 | **divergence** |
| `build_loaded_s19` | `S19File.get_memory_ranges` | s19_app/tui/services/load_service.py:61 | edge |
| `build_loaded_s19` | `build_mem_map_s19` | s19_app/tui/services/load_service.py:60 | edge |
| `encode_physical_to_raw_bytes` | `_invert_physical_to_raw` | s19_app/tui/a2l.py:2060, s19_app/tui/a2l.py:2236 | inner |
| `resolve_symbol_entry` | `encode_physical_to_raw_bytes` | s19_app/tui/services/change_service.py:542 | inner |
| `run_chain_set` | `compose_chain_set_report` | s19_app/tui/services/flow_execution_service.py:1701 | inner |
| `run_chain_set` | `run_flow` | s19_app/tui/services/flow_execution_service.py:1503 (ref) | inner |
| `run_flow` | `S19File.__init__` | s19_app/tui/services/flow_execution_service.py:315, s19_app/tui/services/flow_execution_service.py:728 | **divergence** |
| `run_flow` | `_apply_compu_method` | s19_app/tui/a2l.py:2619 | **divergence** |
| `run_flow` | `apply_change_document` | s19_app/tui/services/flow_execution_service.py:448 | inner |
| `run_flow` | `build_loaded_s19` | s19_app/tui/services/flow_execution_service.py:314, s19_app/tui/services/flow_execution_service.py:727 | inner |
| `run_flow` | `compose_flow_report` | s19_app/tui/services/flow_report_service.py:545 | inner |
| `run_flow` | `inject_crcs` | s19_app/tui/services/flow_execution_service.py:651 | inner |
| `run_flow` | `parse_a2l_file` | s19_app/tui/services/flow_execution_service.py:342, s19_app/tui/services/flow_execution_service.py:422 | **divergence** |
| `run_flow` | `save_patched_image` | s19_app/tui/services/flow_execution_service.py:520 | inner |
| `verify_written_image` | `S19File.__init__` | s19_app/tui/changes/verify.py:115 | **divergence** |
| `write_split_join_export` | `emit_image` | s19_app/tui/segment_split_view.py:544 | inner |
| `write_split_join_export` | `fill_range` | s19_app/tui/segment_split_view.py:562 | inner |

Top-level sites (orchestration with no marked node above):

- `ChangeService.undo`: cwaudit/test_t2_patch_editor.py:25, cwaudit/test_t2_patch_editor.py:26, s19_app/tui/app.py:3617
- `S19File.__init__`: cwaudit/test_t1_load.py:12, cwaudit/test_t1_load.py:28, cwaudit/test_t1_load.py:37, cwaudit/test_t6_split.py:10, docs/images/capture_readme_media.py:79, prototypes/screen_upgrades.prototype.py:101, prototypes/screen_upgrades.prototype.py:85, s19_app/cli.py:98, s19_app/tui/app.py:10398, s19_app/tui/app.py:5855, s19_app/tui/services/before_after_service.py:178, s19_app/tui/services/change_service.py:2361, s19_app/tui/services/compare_service.py:169
- `S19File.get_memory_ranges`: prototypes/screen_upgrades.prototype.py:87, s19_app/core.py:645, s19_app/core.py:661, s19_app/core.py:667, s19_app/core.py:676, s19_app/core.py:687
- `S19TuiApp._handle_load_project`: cwaudit/test_t5_project.py:46, cwaudit/test_t5_project.py:89
- `S19TuiApp._handle_save_dialog`: cwaudit/test_t5_project.py:27, cwaudit/test_t5_project.py:34, cwaudit/test_t5_project.py:51, cwaudit/test_t5_project.py:72, cwaudit/test_t5_project.py:78, cwaudit/test_t5_project.py:91
- `S19TuiApp._parse_loaded_file`: s19_app/tui/app.py:11143
- `S19TuiApp.on_patch_editor_panel_action_requested`: cwaudit/cwh.py:105
- `S19TuiApp.on_patch_editor_panel_save_back_decision`: cwaudit/test_t2_patch_editor.py:34, cwaudit/test_t2_patch_editor.py:38
- `_apply_compu_method`: s19_app/tui/a2l.py:2851, s19_app/tui/a2l.py:2898, s19_app/tui/a2l.py:3000
- `build_loaded_s19`: cwaudit/test_t1_load.py:13, cwaudit/test_t1_load.py:28, cwaudit/test_t1_load.py:38, cwaudit/test_t6_split.py:10, docs/images/capture_readme_media.py:80, s19_app/tui/app.py:5855, s19_app/tui/services/before_after_service.py:178, s19_app/tui/services/change_service.py:2360, s19_app/tui/services/compare_service.py:169
- `build_plan`: cwaudit/test_t6_split.py:42, s19_app/tui/segment_split_view.py:1236
- `inject_crcs`: s19_app/tui/operations/crc.py:1327, s19_app/tui/screens.py:2792
- `parse_a2l_file`: cwaudit/test_t4_a2l_encode.py:17, cwaudit/test_t4_a2l_encode.py:32, cwaudit/test_t4_a2l_encode.py:44, docs/images/capture_readme_media.py:78, prototypes/screen_upgrades.prototype.py:88, s19_app/tui/services/change_service.py:2354
- `parse_mac_file`: cwaudit/test_t6_split.py:34, docs/images/capture_readme_media.py:81, prototypes/screen_upgrades.prototype.py:92, s19_app/tui/services/change_service.py:2364
- `parse_new_bytes`: cwaudit/test_t2_patch_editor.py:56
- `read_project_manifest`: s19_app/tui/app.py:4666, s19_app/tui/app.py:4774
- `resolve_symbol_entry`: cwaudit/test_t4_a2l_encode.py:20, cwaudit/test_t4_a2l_encode.py:25, s19_app/tui/services/change_service.py:1134
- `run_chain_set`: cwaudit/test_t3_flow.py:61, s19_app/tui/app.py:2799, s19_app/tui/app.py:2889
- `run_flow`: cwaudit/test_t3_flow.py:37, s19_app/tui/app.py:2587, s19_app/tui/services/flow_execution_service.py:1184 (ref)
- `save_patched_image`: s19_app/tui/services/change_service.py:1735
- `verify_written_image`: s19_app/tui/operations/crc.py:1367, s19_app/tui/services/change_service.py:1758
- `write_split_join_export`: cwaudit/test_t6_split.py:19, cwaudit/test_t6_split.py:38, cwaudit/test_t6_split.py:57, s19_app/tui/segment_split_view.py:1632

## Input in graph, not a parameter in code

- `s19_app/tui/services/manifest_writer.py:414` — graph input `project_dir` not a parameter of `write_project_manifest`

## Parameter in code, not an input in graph

- `s19_app/tui/services/manifest_writer.py:414` — parameter `project_root: Path` not in graph
- `s19_app/tui/services/manifest_writer.py:414` — parameter `base_dir: Path` not in graph
- `s19_app/tui/services/manifest_writer.py:414` — parameter `schema_version: int` not in graph
- `s19_app/tui/services/variant_execution_service.py:376` — parameter `size_probe: Optional[SizeProbe]` not in graph
- `s19_app/segment_ops.py:465` — parameter `bytes_per_line: int` not in graph

## Input type mismatch

- `s19_app/tui/services/flow_execution_service.py:1444` — `run_one`: graph `Callable[[Flow, FlowContext], Optional[FlowRunResult]]` vs code `Optional[Callable[[Flow, FlowContext], FlowRunResult]]`

## Default value mismatch (C12)

- `s19_app/tui/services/flow_execution_service.py:1444` — `mode`: graph default `'sequential'` vs code `CHAIN_RUN_SEQUENTIAL`
- `s19_app/segment_ops.py:280` — `pad_byte`: graph default `None` vs code `DEFAULT_PAD_BYTE`
- `s19_app/segment_ops.py:280` — `intra_gap`: graph default `None` vs code `'fill'`

## Output type mismatch

- `s19_app/tui/services/variant_execution_service.py:376` — graph `ProjectManifest` vs code `Optional[ProjectManifest]`
- `s19_app/segment_ops.py:465` — graph `str` vs code `Union[str, bytes]`

## `inner:` names an unknown node

- `parse_a2l_file` — `extract_a2l_tags` in `inner:` of `parse_a2l_file` is not a graph node
- `S19TuiApp.on_patch_editor_panel_save_back_decision` — `ChangeService.save_patched` in `inner:` of `S19TuiApp.on_patch_editor_panel_save_back_decision` is not a graph node
- `run_flow` — `read_change_document` in `inner:` of `run_flow` is not a graph node
- `run_flow` — `check_regions` in `inner:` of `run_flow` is not a graph node
- `run_flow` — `run_check_document` in `inner:` of `run_flow` is not a graph node
- `S19TuiApp._handle_save_dialog` — `copy_into_workarea` in `inner:` of `S19TuiApp._handle_save_dialog` is not a graph node
- `write_split_join_export` — `join_concat` in `inner:` of `write_split_join_export` is not a graph node

## C15 divergence: lifted call not declared in the graph

- `s19_app/tui/app.py:10508` — `S19TuiApp._handle_load_project` → `S19TuiApp._parse_loaded_file` (sites: s19_app/tui/app.py:10508) not declared in `inner:` of `S19TuiApp._handle_load_project` nor as an edge; also called at top level: s19_app/tui/app.py:11143
- `s19_app/tui/services/manifest_writer.py:702` — `S19TuiApp._handle_save_dialog` → `read_project_manifest` (sites: s19_app/tui/services/manifest_writer.py:702) not declared in `inner:` of `S19TuiApp._handle_save_dialog` nor as an edge; also called at top level: s19_app/tui/app.py:4666, s19_app/tui/app.py:4774
- `s19_app/tui/app.py:11250` — `S19TuiApp._load_mac_file` → `parse_a2l_file` (sites: s19_app/tui/app.py:11250) not declared in `inner:` of `S19TuiApp._load_mac_file` nor as an edge; also called at top level: cwaudit/test_t4_a2l_encode.py:17, cwaudit/test_t4_a2l_encode.py:32, cwaudit/test_t4_a2l_encode.py:44, docs/images/capture_readme_media.py:78, prototypes/screen_upgrades.prototype.py:88 (+1 more)
- `s19_app/tui/app.py:10578` — `S19TuiApp._parse_loaded_file` → `S19File.__init__` (sites: s19_app/tui/app.py:10578) not declared in `inner:` of `S19TuiApp._parse_loaded_file` nor as an edge; also called at top level: cwaudit/test_t1_load.py:12, cwaudit/test_t1_load.py:28, cwaudit/test_t1_load.py:37, cwaudit/test_t6_split.py:10, docs/images/capture_readme_media.py:79 (+8 more)
- `s19_app/tui/app.py:11250` — `S19TuiApp._parse_loaded_file` → `parse_a2l_file` (sites: s19_app/tui/app.py:11250) not declared in `inner:` of `S19TuiApp._parse_loaded_file` nor as an edge; also called at top level: cwaudit/test_t4_a2l_encode.py:17, cwaudit/test_t4_a2l_encode.py:32, cwaudit/test_t4_a2l_encode.py:44, docs/images/capture_readme_media.py:78, prototypes/screen_upgrades.prototype.py:88 (+1 more)
- `s19_app/tui/services/variant_execution_service.py:764` — `S19TuiApp.on_patch_editor_panel_action_requested` → `S19File.__init__` (sites: s19_app/tui/services/variant_execution_service.py:764) not declared in `inner:` of `S19TuiApp.on_patch_editor_panel_action_requested` nor as an edge; also called at top level: cwaudit/test_t1_load.py:12, cwaudit/test_t1_load.py:28, cwaudit/test_t1_load.py:37, cwaudit/test_t6_split.py:10, docs/images/capture_readme_media.py:79 (+8 more)
- `s19_app/tui/a2l.py:2619` — `S19TuiApp.on_patch_editor_panel_action_requested` → `_apply_compu_method` (sites: s19_app/tui/a2l.py:2619) not declared in `inner:` of `S19TuiApp.on_patch_editor_panel_action_requested` nor as an edge; also called at top level: s19_app/tui/a2l.py:2851, s19_app/tui/a2l.py:2898, s19_app/tui/a2l.py:3000
- `s19_app/tui/services/variant_execution_service.py:787` — `S19TuiApp.on_patch_editor_panel_action_requested` → `apply_change_document` (sites: s19_app/tui/services/variant_execution_service.py:787) not declared in `inner:` of `S19TuiApp.on_patch_editor_panel_action_requested` nor as an edge
- `s19_app/tui/services/variant_execution_service.py:763` — `S19TuiApp.on_patch_editor_panel_action_requested` → `build_loaded_s19` (sites: s19_app/tui/services/variant_execution_service.py:763) not declared in `inner:` of `S19TuiApp.on_patch_editor_panel_action_requested` nor as an edge; also called at top level: cwaudit/test_t1_load.py:13, cwaudit/test_t1_load.py:28, cwaudit/test_t1_load.py:38, cwaudit/test_t6_split.py:10, docs/images/capture_readme_media.py:80 (+4 more)
- `s19_app/tui/services/variant_execution_service.py:879` — `S19TuiApp.on_patch_editor_panel_action_requested` → `parse_a2l_file` (sites: s19_app/tui/services/variant_execution_service.py:879) not declared in `inner:` of `S19TuiApp.on_patch_editor_panel_action_requested` nor as an edge; also called at top level: cwaudit/test_t4_a2l_encode.py:17, cwaudit/test_t4_a2l_encode.py:32, cwaudit/test_t4_a2l_encode.py:44, docs/images/capture_readme_media.py:78, prototypes/screen_upgrades.prototype.py:88 (+1 more)
- `s19_app/tui/services/variant_execution_service.py:877` — `S19TuiApp.on_patch_editor_panel_action_requested` → `parse_mac_file` (sites: s19_app/tui/services/variant_execution_service.py:877) not declared in `inner:` of `S19TuiApp.on_patch_editor_panel_action_requested` nor as an edge; also called at top level: cwaudit/test_t6_split.py:34, docs/images/capture_readme_media.py:81, prototypes/screen_upgrades.prototype.py:92, s19_app/tui/services/change_service.py:2364
- `s19_app/tui/app.py:4192` — `S19TuiApp.on_patch_editor_panel_action_requested` → `read_project_manifest` (sites: s19_app/tui/app.py:4192, s19_app/tui/services/variant_execution_service.py:958) not declared in `inner:` of `S19TuiApp.on_patch_editor_panel_action_requested` nor as an edge; also called at top level: s19_app/tui/app.py:4666, s19_app/tui/app.py:4774
- `s19_app/tui/services/variant_execution_service.py:798` — `S19TuiApp.on_patch_editor_panel_action_requested` → `save_patched_image` (sites: s19_app/tui/services/variant_execution_service.py:798) not declared in `inner:` of `S19TuiApp.on_patch_editor_panel_action_requested` nor as an edge; also called at top level: s19_app/tui/services/change_service.py:1735
- `s19_app/tui/services/flow_execution_service.py:315` — `run_flow` → `S19File.__init__` (sites: s19_app/tui/services/flow_execution_service.py:315, s19_app/tui/services/flow_execution_service.py:728) not declared in `inner:` of `run_flow` nor as an edge; also called at top level: cwaudit/test_t1_load.py:12, cwaudit/test_t1_load.py:28, cwaudit/test_t1_load.py:37, cwaudit/test_t6_split.py:10, docs/images/capture_readme_media.py:79 (+8 more)
- `s19_app/tui/a2l.py:2619` — `run_flow` → `_apply_compu_method` (sites: s19_app/tui/a2l.py:2619) not declared in `inner:` of `run_flow` nor as an edge; also called at top level: s19_app/tui/a2l.py:2851, s19_app/tui/a2l.py:2898, s19_app/tui/a2l.py:3000
- `s19_app/tui/services/flow_execution_service.py:342` — `run_flow` → `parse_a2l_file` (sites: s19_app/tui/services/flow_execution_service.py:342, s19_app/tui/services/flow_execution_service.py:422) not declared in `inner:` of `run_flow` nor as an edge; also called at top level: cwaudit/test_t4_a2l_encode.py:17, cwaudit/test_t4_a2l_encode.py:32, cwaudit/test_t4_a2l_encode.py:44, docs/images/capture_readme_media.py:78, prototypes/screen_upgrades.prototype.py:88 (+1 more)
- `s19_app/tui/changes/verify.py:115` — `verify_written_image` → `S19File.__init__` (sites: s19_app/tui/changes/verify.py:115) not declared in `inner:` of `verify_written_image` nor as an edge; also called at top level: cwaudit/test_t1_load.py:12, cwaudit/test_t1_load.py:28, cwaudit/test_t1_load.py:37, cwaudit/test_t6_split.py:10, docs/images/capture_readme_media.py:79 (+8 more)

## Info: node declared in two `inner:` lists

- `build_loaded_s19` — `build_loaded_s19` declared inside `S19TuiApp._parse_loaded_file`, `run_flow`: two call sites by design
- `apply_change_document` — `apply_change_document` declared inside `ChangeService.apply`, `run_flow`: two call sites by design

## Files skipped (parse error)

- `tools/mutation_harness.py`: f-string expression part cannot include a backslash (<unknown>, line 190)
