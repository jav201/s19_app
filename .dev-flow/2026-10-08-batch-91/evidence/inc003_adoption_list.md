# inc-003 — the 44 token-invisible LIVE ids (LLR-124.2), derived 2026-10-11

Derived with `tools/id_registry.py` (see `inc003_invisible.py` in this
directory): a LIVE registry id is token-invisible when its dash-form token
(the entry's verbatim `id`) does not occur **as a maximal-munch TOKEN_RE
token** in any file its `nodes` name. Token-exact, not substring — the
substring reading stops at 42 because `TC-041.1` rides inside `TC-041.10` and
`TC-062` inside `TC-062.a`; the token reading reproduces the survey's 44
exactly. Post-increment re-run (`inc003_invisible_after.txt`): 0 remaining.

One line each — id → file that received the `# <id>` docstring/comment line:

- AT-002b → tests/test_flow_report_wire.py (docstring of test_at002b_report_renders_inert_through_the_shipped_viewer_parser)
- AT-030a-R2 → tests/test_tui_patch_editor_v2.py (docstring of test_at030a_r2_save_while_open_appears_without_reactivation)
- AT-034a → tests/test_tui_snapshot.py (docstring of test_tc016s_density_layout_snapshot)
- AT-034b → tests/test_tui_snapshot.py (same docstring — shared node)
- AT-40 → tests/test_tui_directionb.py (docstring of test_at040_workspace_geometry_no_clip_80_and_120)
- AT-43 → re-spelled AT-043 in the registry (LLR-124.1); token added to tests/test_tui_a2l_issue_recolor.py (docstring of test_at_043_c17_file_derived_hostile_ref_symbol_renders_literal)
- AT-050a-pilot → tests/test_tui_patch_editor_v2.py (docstring of test_at050a_pilot_mixed_results_via_real_button)
- AT-073b → tests/test_tui_directionb.py (docstring of test_at073b_glance_geometry_fits_and_reflows)
- AT-80 → tests/test_tui_patch_layout.py (module docstring — the cluster's other node lives in tests/test_tui_legend.py; any-named-file visibility)
- AT-88 → tests/test_flow_builder_render.py (docstring of test_at088_gating_selector_appends_block_own_op_check)
- AT-107b → tests/test_a2l_inline_axis_length.py (docstring of test_at107b_synthetic_single_line_curve_length_13)
- AT-124a → tests/test_flow_crc_block.py (comment above the def — the function carries no docstring)
- AT-124b → tests/test_flow_crc_block.py (comment above the def)
- AT-125a → tests/test_flow_crc_block.py (comment above the def)
- AT-125b → tests/test_flow_crc_block.py (comment above the def)
- AT-127a → tests/test_flow_crc_block.py (docstring of test_at127a_absolute_config_ref_rejected)
- AT-127b → tests/test_flow_crc_block.py (docstring of test_at127b_escape_config_ref_rejected)
- AT-172b → tests/test_report_document_bytes.py (docstring of test_at172b_the_unpatched_report_is_exactly_the_encoder_output)
- AT-173b → tests/test_flow_report_service.py (docstring of test_at173b_flow_report_bytes_equal_the_encoder_output)
- AT-174b → tests/test_report_document_bytes.py (docstring of test_at174b_line_bytes_is_partition_invariant)
- TC-013b → tests/test_flow_report_service.py (docstring of test_tc013b_non_aborting_error_is_issues_not_failed; second node in tests/test_tui_theme.py — any-named-file visibility)
- TC-16b → tests/test_flow_report_service.py (docstring of test_tc016b_exception_diagnostics_do_not_leak_absolute_paths)
- TC-16s → tests/test_tui_snapshot.py (docstring of test_tc016s_density_layout_snapshot; the file's "TC-016-S" spelling is the separate legacy entry)
- TC-41c → tests/test_tui_directionb.py (docstring of test_tc041_4c_gap_cell_detail_no_region)
- TC-41d → tests/test_tui_directionb.py (docstring of test_tc041_4d_hostile_issue_symbol_rendered_literally)
- TC-041.1 → tests/test_tui_directionb.py (docstring of test_tc041_1_cell_status_derivation; was substring-hidden by TC-041.10)
- TC-041.2 → tests/test_tui_directionb.py (docstring of test_tc041_2_auto_scale_cell_count_and_zero_span)
- TC-041.3 → tests/test_tui_directionb.py (docstring of test_tc041_3_invalid_cell_carries_sev_error_class)
- TC-041.11 → tests/test_tui_directionb.py (docstring of test_tc041_11_markup_safe_render_of_hostile_text)
- TC-43 → tests/test_tui_issues_view.py (docstring of test_tc043_restore1_related_node_is_markup_safe)
- TC-046.1 → tests/test_tui_patch_layout.py (docstring of test_tc46_1_window_structure_layout_agnostic; the guard's own test_tc608 node is the second named node — any-named-file visibility, guard file untouched by this arm)
- TC-062 → tests/test_validation_engine.py (class docstring of TestCrossFileCompatibilityCoEmission — the 8-node battery; was substring-hidden by the TC-062.a..h spellings)
- TC-79b → tests/test_tui_patch_json.py (docstring of test_tc079_3b_inert_predicate_colour_axis_discriminates)
- TC-79c → tests/test_tui_patch_json.py (docstring of test_tc079_5c_hue_census_is_complete)
- TC-79d → tests/test_tui_patch_json.py (docstring of test_tc079_5d_flank_rule_has_teeth)
- TC-220b → tests/test_changes_apply.py (docstring of test_tc220b_hex_save_unaffected_by_s19_only_kwargs)
- TC-346b → tests/test_flow_crc_block.py (comment above the def)
- TC-351 → tests/test_flow_crc_block.py (comment above the def)
- TC-501b → tests/test_flow_multi_image.py (docstring of test_tc501b_model_containers_are_well_formed)
- TC-503b → tests/test_flow_report_fusion.py (comment above the def — no docstring)
- TC-504b → tests/test_flow_report_fusion.py (comment above the def — no docstring)
- TC-505b → tests/test_flow_report_fusion.py (docstring of test_tc505b_a_variant_under_the_cap_carries_no_cut_notice)
- TC-505c → tests/test_flow_report_fusion.py (docstring of test_tc505c_diagnostics_share_the_variant_budget_with_findings)
- TC-509b → tests/test_flow_report_ac6_golden.py (docstring of test_tc509b_the_golden_is_stored_lf_only_and_non_empty)
