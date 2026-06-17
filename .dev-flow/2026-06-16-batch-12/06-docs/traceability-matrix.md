# Traceability Matrix — s19_app — Batch 2026-06-16-batch-12 (CRC_F2)

> Full chain: **User Story → HLR → LLR → Test Case → File:line**, plus the increment each row landed in.
> Authored Phase 6 (docs-writer). Node ids reconciled against the real tree (`pytest --collect-only`, 2026-06-17) and `04-validation.md` §2. No gaps: every in-scope LLR cites its implementing file + a passing node. LLR-002.5 is **WITHDRAWN** (§6.4 J-3) and LLR-003.5 is **RE-SCOPED** — both recorded as decisions, not coverage gaps.

---

## 1. Master table

US → HLR → LLR → TC → implementing `file:line` → passing node. `Inc` = the increment the row landed in (I1a → I5b).

| US | HLR | LLR | TC | Implementing file:line | Passing test node | Inc | Status |
|----|-----|-----|-----|------------------------|-------------------|-----|--------|
| US-011 (also US-012) | HLR-005 | LLR-005.1 — neutral `OperationInput`, both call-sites migrated | TC-108 | `s19_app/tui/operations/model.py:27` (`OperationInput`), `:82` (`from_loaded`); `operation_service.py:94`; `screens.py:836` | `test_operations.py::test_operation_input_exposes_mem_map_ranges_metadata` (+ `::test_run_operation_service`, `::test_operation_interface`) | I1a | PASS |
| US-011, US-012 | HLR-005 | LLR-005.2 — `OperationResult` widened (contract-touch) | TC-109 | `s19_app/tui/operations/model.py:182` (`OperationResult`), `:260` (`crc_regions`), `:23` (`STATUS_DOMAIN`), `:282` (`to_dict`), `:131` (`CrcRegionResult`) | `test_operations.py::test_operation_result_widened_field_count_and_status_domain` | I1a | PASS |
| US-011, US-012 | HLR-005 | LLR-005.3 — co-located `REQ-crc.md` | TC-131 | `s19_app/tui/operations/requirements/REQ-crc.md` | inspection: file exists (`04-validation.md` §1/§4(i)) | I1b | PASS (note: `REQUIREMENTS.md` back-ref deferred to Phase 6) |
| US-011 (also US-012) | HLR-001 | LLR-001.1 — parameterized CRC32 core + chaining | TC-101 (gating), TC-106, TC-106b | `s19_app/tui/operations/crc.py:82` (`crc32_stream`) | `test_crc_engine.py::test_known_answer_vector`, `::test_config_params_change_result`, `::test_bitwise_path_reproduces_published_variant_kats` | I1b | PASS |
| US-011 (also US-012) | HLR-001 | LLR-001.2 — region byte assembly (sort/filter/segment/chain) | TC-102, TC-103, TC-104, TC-105 | `s19_app/tui/operations/crc.py:154` (`region_segments`), `:210` (`compute_region_crc`) | `test_crc_engine.py::test_segment_chaining_does_not_reset_state`, `::test_gap_splits_segments_no_inserted_bytes`, `::test_ascending_address_ordering`, `::test_region_filter_excludes_out_of_range` | I1b | PASS |
| US-011 (also US-012) | HLR-001 | LLR-001.3 — per-region payload, no mutation | (no-mutation assert), TC-107 | `s19_app/tui/operations/crc.py:271` (`compute_region_crcs`), `:327` (`encode_le32`), `:354` (`decode_le32`) | `test_crc_engine.py::test_entry_point_does_not_mutate_mem_map`, `::test_le_codec_roundtrip`; `test_crc_operation.py::test_check_multi_region_order` | I1b | PASS |
| US-011, US-012 | HLR-004 | LLR-004.1 — external JSON config reader (resolve + size-cap + parse + collect) | TC-113, TC-114 | `s19_app/tui/operations/crc_config.py:156` (`read_crc_config`), `:90` (`CrcConfig`), `:60` (`CrcRegion`) | `test_crc_config.py::test_params_loaded_from_synthetic_json`, `::test_no_real_config_required`, `::test_unresolvable_path_collects_one_error`, `::test_malformed_json_collects_one_error`, `::test_over_size_cap_collects_one_error_without_reading`, `::test_missing_field_collects_one_error` | I2 | PASS |
| US-011, US-012 | HLR-004 | LLR-004.2 — TUI editable text config surface (dummy pre-fill) | TC-115 (path) | `s19_app/tui/operations/crc_config.py:242` (`parse_crc_config`), `:47` (`DUMMY_CONFIG_TEXT`); `screens.py:765` (`#operation_config` TextArea), `:838` (parse on execute) | `test_crc_config.py::test_parse_crc_config_valid_text_populates_config`, `::test_parse_crc_config_dummy_prefill_is_valid`, `::test_parse_crc_config_malformed_text_collects_one_error`, `::test_parse_crc_config_non_object_top_level_collects_one_error`, `::test_parse_crc_config_missing_field_collects_one_error`; `test_tui_crc_surface.py::test_crc_config_error_surfaces_error_and_no_match` | I3b | PASS |
| US-011 | HLR-002 | LLR-002.1 — read stored 4-byte LE value | TC-111, TC-112 | `s19_app/tui/operations/crc.py:391` (`read_stored_crc_le`) | `test_crc_operation.py::test_check_reports_match_nonmutating`, `::test_read_stored_missing_returns_none` | I2 | PASS |
| US-011 | HLR-002 | LLR-002.2 — compare + per-region payload (non-mutating) | TC-111, TC-112 | `s19_app/tui/operations/crc.py:445` (`check_regions`), `:995` (`CrcOperation.execute`) | `test_crc_operation.py::test_check_reports_match_nonmutating`, `::test_check_reports_mismatch`, `::test_execute_with_config_populates_crc_regions`, `::test_execute_no_config_returns_ok_no_regions` | I2 (headless) + I3a (`OperationResult` assembly) | PASS |
| US-011 | HLR-002 | LLR-002.3 — check execution on worker-thread (R-6) | TC-116 | `s19_app/tui/screens.py:878` (`@work(thread=True … group="crc_operation")` `_run_crc_worker`) | `test_tui_crc_surface.py::test_crc_execute_path_uses_thread_worker`, `::test_stale_crc_worker_result_does_not_overwrite_error` | I3b | PASS |
| US-011 | HLR-002 | LLR-002.4 — render per-region results in op-result view | TC-115 | `s19_app/tui/screens.py:985` (`_crc_region_lines` render), `:655` (`_last_crc_regions`) | `test_tui_crc_surface.py::test_crc_check_reaches_result_surface_via_handler` | I3b | PASS |
| US-011 | HLR-002 | ~~LLR-002.5 — persistent project-report render~~ | ~~TC-117~~ | — (`report_service.py` untouched) | — | — | **WITHDRAWN (J-3)** — not a gap |
| US-012 | HLR-003 | LLR-003.1 — inject 4-byte LE + write-into-gap range extension | TC-121, TC-122 | `s19_app/tui/operations/crc.py:632` (`inject_crcs`), `:584` (`_extend_ranges`) | `test_crc_operation.py::test_inject_writes_le_at_output_address`, `::test_inject_into_gap_extends_ranges` | I5a | PASS |
| US-012 | HLR-003 | LLR-003.2 — emit via `emit_s19_from_mem_map` into contained work area | TC-123 | `s19_app/tui/operations/crc.py:790` (`write_crc_image`, emit + `copy_into_workarea` containment) | `test_crc_operation.py::test_modified_s19_reread_matches_intent`, `::test_write_outside_workarea_collects_finding_and_writes_no_file` | I5a | PASS |
| US-012 | HLR-003 | LLR-003.3 — verify written image (reader-as-oracle) | TC-123 | `s19_app/tui/operations/crc.py:900` (`verify_written_image` call in `write_crc_image`) | `test_crc_operation.py::test_modified_s19_reread_matches_intent` (clean → verified+empty; corrupted → mismatch+runs) | I5a | PASS |
| US-012 | HLR-003 | LLR-003.4 — two-stage operator confirmation gates the write (R-6) | TC-124 | `s19_app/tui/screens.py:502` (`ConfirmWriteScreen`), `:542` (`#confirm_write_ok`), `:543` (`#confirm_write_cancel`) | `test_tui_crc_surface.py::test_no_write_without_confirmation`; headless `test_crc_operation.py::test_write_only_when_invoked` | I5b | PASS |
| US-012 | HLR-003 | LLR-003.5 — persistent record via the operation output (**RE-SCOPED**, J-3) | TC-125, TC-126 | `s19_app/tui/operations/crc.py:732` (`CrcWriteResult`), `:790` (`write_crc_image`); `screens.py` write-outcome rows | `test_crc_operation.py::test_write_result_records_emitted_path_and_verdict`; `test_tui_crc_surface.py::test_crc_inject_reaches_surface_via_handler` | I5a (record) + I5b (surface) | PASS — **RE-SCOPED** (no `report_service` binding) |

**Score: 5/5 HLR PASS · 12/12 in-scope LLR PASS · 1 LLR WITHDRAWN (not a gap) · 0 FAIL.** Matches `04-validation.md` §1 (BLUF: PASS-WITH-NOTES).

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories | 2 (US-011, US-012) |
| Covered user stories | 2 (100%) |
| Total HLR | 5 |
| Implemented HLR | 5 (100%) |
| Total LLR (drafted) | 14 |
| In-scope LLR | 13 (LLR-002.5 withdrawn) |
| In-scope LLR PASS | 13 (100%) — LLR-003.5 PASS as re-scoped |
| Withdrawn LLR | 1 (LLR-002.5, J-3) |
| In-scope spec TCs | 23 mapped (TC-101..132 less withdrawn TC-117) |
| TC pass | 23 (100% of in-scope) |
| TC withdrawn | 1 (TC-117, J-3) |
| TC fail / pending | 0 |
| CRC-file test nodes (on disk) | 48 collected, 48 pass (53 incl. `test_tui_operations_view.py`) |

> The drafted-LLR count is 14 (5.1–5.3, 1.1–1.3, 4.1–4.2, 2.1–2.5, 3.1–3.5) but LLR-002.5 was withdrawn at Phase 3, leaving 13 in-scope; HLR-002 therefore decomposes to 002.1–002.4.

---

## 3. Detected gaps

**None.** Every in-scope LLR maps to ≥1 passing node and an implementing `file:line`. The two non-PASS dispositions are recorded decisions, not gaps:

| ID | Type | Description | Disposition |
|----|------|-------------|-------------|
| (n/a) LLR-002.5 | withdrawn | Persistent project-report CRC section | **WITHDRAWN (§6.4 J-3).** `report_service.generate_project_report` is `VariantExecutionResult`/project-scoped; CRC is per-file, so the binding was an operator-unreachable coupling (SCOPE-1/A-5 risk). Check has no separate persistent artifact; its surface is the op-result view (LLR-002.4). TC-117 removed; `report_service.py` untouched. Not a coverage gap. |
| (n/a) LLR-003.5 | re-scoped | Persistent record of the write | **RE-SCOPED (§6.4 J-3).** The write's durable record is the operation's OWN output — the emitted modified S19 (FR9 artifact) + the `OperationResult` (`crc_regions` with `written=True` + emitted path + verify verdict), rendered in the op-result view. No `report_service` integration. Validated PASS via TC-126/TC-125. |

**Non-blocking notes carried from `04-validation.md` §5 (not gaps):**
- **RK-3** — non-default *device* CRC convention is "params-WIRED" (TC-106) and bitwise-path-anchored against published variant KATs (TC-106b), but no operator-sourced *device* reference vector exists in-tree. Do not trust a non-zlib device verdict without one.
- **REQUIREMENTS.md → REQ-crc.md** — the co-located doc exists (the C-7 obligation, LLR-005.3 PASS); the repo-wide `REQUIREMENTS.md` back-reference line / `R-*` status update is a Phase-6 docs task, owned by the REQUIREMENTS.md owner, not this matrix.

---

## 4. Changes from previous batch (batch-11)

| Type | Item | Detail |
|------|------|--------|
| new | HLR-001..HLR-005 + LLR set | First concrete *operation* fill-in of the batch-08 operations framework. |
| new | `s19_app/tui/operations/crc.py` | Headless CRC32 engine + check + inject + emit + verify. |
| new | `s19_app/tui/operations/crc_config.py` | External JSON config reader (`CrcConfig`/`CrcRegion`). |
| new | `s19_app/tui/operations/requirements/REQ-crc.md` | Co-located operation requirements (C-7 mandate). |
| new | `examples/crc_config.example.json` | Dummy config template (fake values only). |
| modified | `s19_app/tui/operations/model.py` | `OperationInput` (NEW), `OperationResult` widened with `crc_regions`, `CrcRegionResult` (NEW). Resolves batch-08 C-7/R-2/R-3. |
| modified | `s19_app/tui/services/operation_service.py`, `screens.py` | Migrated both `execute` call-sites off the `LoadedFile` binding; CRC TUI surface (config editor, worker, per-region rows, `ConfirmWriteScreen`). |
| withdrawn | I4 / `report_service` binding | §6.4 J-3 re-scope — `report_service.py` not touched this batch. |
| signed-balance | full suite | 879 = 839 (batch-11 close) + 40 (CRC nodes), D=0/A=40. |

---

## 5. Quick bidirectional mapping

### 5.1 By user story
- **US-011** (check) → HLR-001, HLR-002, HLR-004, HLR-005 → LLR-001.1/.2/.3, LLR-002.1/.2/.3/.4, LLR-004.1/.2, LLR-005.1/.2/.3 → TC-101..116, TC-131/132.
- **US-012** (inject + emit) → HLR-001, HLR-003, HLR-004, HLR-005 → LLR-001.*, LLR-003.1/.2/.3/.4/.5, LLR-004.*, LLR-005.* → TC-121..126.

### 5.2 By code file
- `s19_app/tui/operations/crc.py` → LLR-001.1/.2/.3, LLR-002.1/.2, LLR-003.1/.2/.3/.5 → `test_crc_engine.py`, `test_crc_operation.py`.
- `s19_app/tui/operations/crc_config.py` → LLR-004.1/.2 → `test_crc_config.py`.
- `s19_app/tui/operations/model.py` → LLR-005.1/.2 → `test_operations.py`.
- `s19_app/tui/operations/requirements/REQ-crc.md` → LLR-005.3 → inspection.
- `s19_app/tui/services/operation_service.py` → LLR-005.1 (service call-site) → `test_operations.py::test_run_operation_service`.
- `s19_app/tui/screens.py` → LLR-002.3/.4, LLR-003.4/.5 (surface), LLR-004.2 (surface) → `test_tui_crc_surface.py`.

### 5.3 By increment
- **I1a** → LLR-005.1, LLR-005.2.
- **I1b** → LLR-001.1, LLR-001.2, LLR-001.3, LLR-005.3.
- **I2** → LLR-004.1, LLR-002.1, LLR-002.2 (headless).
- **I3a** → LLR-002.2 (`OperationResult`-assembly half).
- **I3b** → LLR-004.2, LLR-002.3, LLR-002.4.
- **I5a** → LLR-003.1, LLR-003.2, LLR-003.3, LLR-003.5 (record, headless).
- **I5b** → LLR-003.4, LLR-003.5 (confirm + surface). *(I4 withdrawn — J-3.)*

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | `2026-06-16-batch-12` (CRC_F2) |
| Closing date | 2026-06-17 |
| Validation verdict | PASS-WITH-NOTES (`04-validation.md`) |
| Frozen-set | CLEAR (`test_engine_unchanged.py` 1 passed) |
| Full suite | 847 passed / 0 failed / 29 skipped / 3 xfailed (exit 0) |
| Validation passed | yes |
| Synced to Obsidian | pending (post-merge `/dev-flow-sync`) |

*UTF-8, no BOM. Phase 6 (docs-writer). Node ids verified on disk 2026-06-17.*
