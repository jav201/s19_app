# Traceability matrix · batch-53 (FB-P1 flow.json persistence)

## User stories → coverage
| US | Statement (abbrev) | Shipped surface | AT | Status |
|----|--------------------|-----------------|----|--------|
| US-001 | Save the built flow to a named `flows/<name>.json` | Panel Save → SaveFlowScreen → `save_flow_json` | AT-001 | Covered |
| US-002 | Load a saved flow, hardened untrusted loader | Panel Load → LoadFlowScreen → `load_flow_json` → set_blocks / quarantine | AT-002, AT-P1-01..08 | Covered |
| US-003 | Import an external flow (copy, dirty-guard) | LoadFlowScreen Import + ConfirmDiscardScreen | AT-004, AT-005 | Covered |
| US-004 | A report block, when present, persists + round-trips (generation → FB-P1b) | ReportBlock model + `_flow_block_label` REPORT arm | AT-006 | Covered (model+persist) |

## LLR → test
| LLR | Behaviour | Test |
|-----|-----------|------|
| LLR-001.1 | `flow_to_dict` envelope shape (6 kinds) | `test_roundtrip_all_kinds_field_by_field` |
| LLR-001.2 | `save_flow_json` sanitised write / None-on-empty | `test_save_flow_json_sanitises_and_roundtrips`, `test_save_flow_json_empty_after_clean_writes_nothing`, `test_save_flow_json_sanitiser_contains_traversal` |
| LLR-002.1 | size probe before parse + parse guard | `test_size_cap_before_parse`, parse-error cases |
| LLR-002.2 | V1/V2 envelope + schema-version gate | schema-version battery |
| LLR-002.3 | V3/V4 name + blocks-array bounds | `test_block_count_cap_boundary`, `test_name_length_cap_boundary` |
| LLR-002.4 | V5 per-block strict validation | strict-keys / unknown-kind / missing-ref / enum cases |
| LLR-002.5 | V6 READ-ref containment via reused guard | traversal/absolute/junction battery |
| LLR-002.6 | V7 output_name shape (+ drive-relative, F1) | `test_output_name_shape_rejected_per_branch`, `test_negative_control_benign_output_name` |
| LLR-002.7 | fail-closed aggregate (never partial) | one-good-one-bad → `flow is None` |
| LLR-002.8 | findings markup-safe | quarantine C-17 pilot `test_at006_quarantine_card_painted_and_flow_unchanged` |
| LLR-002.9 | reject-arm census (AMD-6) | `battery_codes ⊇ REJECTING_CODES` |
| LLR-003.1 | name strip + dirty tracking (C-10) | `test_at002_name_strip_glyph_dirty_then_saved` |
| LLR-003.2 | SaveFlowScreen + overwrite notice | `test_at003_save_overwrite_notice_fires_on_existing_name` |
| LLR-003.3 | LoadFlowScreen ListView + `list_saved_flows` | `test_at003_load_screen_lists_saved_flow_stems` |
| LLR-003.4 | Import copies via `import_flow_file` (AMD-4 cap) | `test_import_copies_then_loads_the_copy_not_the_source`, `test_import_over_size_cap_refused_at_copy_step`, `test_import_hostile_dest_outside_workarea_refused` |
| LLR-003.5 | quarantine card (blocks untouched, C-32) | `test_at006_quarantine_card_painted_and_flow_unchanged` |
| LLR-003.6 | dirty-guard confirm modal (AMD-8) | `test_at005_dirty_guard_cancel_keeps_blocks_confirm_replaces` |
| LLR-003.7 | app handlers + set_blocks / no-project card | `test_tc018_no_project_save_and_load_render_error_card` |
| LLR-004.1 | ReportBlock ref-less field-less | `test_report_serializes_ref_less`, `test_report_strict_keys_reject_smuggled_field` |
| LLR-004.2 | serialize + ref-less load path | `test_report_block_roundtrip` |
| LLR-004.3 | run_flow no-op → BLOCK_STATUS_OK "deferred" (AMD-1) | `test_report_noop_keeps_rollup_ok` |
| LLR-004.4 | `_flow_block_label` REPORT arm (AMD-2) | `test_at006_report_bearing_flow_shows_report_row` |

**LLR coverage: 24/24 (100%).**
