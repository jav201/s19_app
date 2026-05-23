# Increment 9 — consolidated inspection-method audit matrices

**Phase:** 3 — Implementation (final increment of the audit batch)
**Increment:** 9 of N (Phase 3 closure)
**Date:** 2026-05-05
**Branch:** `claude/lucid-margulis-a63fd4`
**Mode:** **Documentation only.** No code changes, no test changes, no fixture changes.
**LLR targets:** the 9 inspection-method LLRs whose audit matrices have not yet landed:

- LLR-001.1 (TC-002) — S-record + Intel HEX rule coverage matrix
- LLR-001.2 (TC-005) — A2L + MAC parser rule coverage matrix
- LLR-002.2 (TC-014) — Issues-panel classification audit
- LLR-003.1 (TC-021/022) — `app.py` parsing/validation call-site enumeration
- LLR-004.1 (TC-030/031/032/033) — per-`R-*` verdict report
- LLR-007.1 (TC-061) — cross-file class enumeration
- LLR-007.3 (TC-063) — severity matrix per active alias policy
- LLR-008.1 (TC-071) — forward-direction (code → rule → test) audit matrix
- LLR-008.2 (TC-072) — reverse-direction (rule → code → severity) audit matrix

This packet does NOT touch source or test code. The pytest suite is unchanged from increment 8: **259 passed / 2 skipped / 3 xfailed / 0 failed** (carry-through baseline; not re-executed in this increment).

---

## 0. Phase 3 closure summary

Phase 3 ran 9 supervised increments (1, 1.5, 2, 3, 4, 5, 6, 7, 8, 9). Increments 1–8 landed code/test changes; increment 9 (this packet) is documentation only.

| # | LLR(s) | Files modified | Tests added | Findings raised | Outcome |
|---|---|---|---|---|---|
| 1 | LLR-005.3 | 4 source/test + packet (5) | TC-044/045/046/047 (4) | S-N01/S-N02/S-N04 closed; A-N02/Q-N01 closure criteria stated | Phase-2 blockers S-001/S-002/S-003 closed; one pre-existing test broke by-design (fixed in 1.5) |
| 1.5 | LLR-005.3 (test alignment) | 1 test + packet (2) | rename of `test_save_project_writes_under_chosen_parent` | none | green CI restored |
| 2 | LLR-007.2 / LLR-007.4 (infra) | 2 test + packet (3) | 1 smoke (`test_snapshot_harness_renders_issues_panel`) + 3 fixture builders | R-7 / R-9 / Q-N04 closed | Snapshot harness + per-class fixtures unblocked |
| 3 | LLR-002.3 | 1 source + 1 test + packet (3) | TC-090.a (3) + TC-090.b (2) + benign-passthrough (1) | S-005 closed; S-N03 captured | Issue-message scrubbing + 500-char cap |
| 4 | LLR-002.1 | 1 test + packet (2) | TC-012 (5 parametric) + bidirectional invariants (3) + colour contract (2) + idempotency (5) + TC-013 integration (1) = 16 | R-3 closed | Severity round-trip locked |
| 5 | LLR-007.2 | 1 test + packet (2) | TC-062.a..h (8; 1 xfail) | F-7.2-01, F-7.2-02 raised | Engine co-emission for the 8 cross-file classes |
| 6 | LLR-007.4 | 1 test + packet (2) | TC-065.a..h (8; 1 xfail) | Q-N03 closed (Option A annotation) | Panel-render snapshots for the 8 classes |
| 7 | LLR-005.1/2/4/5 + LLR-006.1 + LLR-003.2 | 3 test + packet (4) | TC-041 (4) + TC-042 (8) + TC-048 (3) + TC-049 (3) + TC-051/052 (7) + TC-023 (6) + AST walk (1) = 32 (38 cases incl. parametrics; 1 xfail) | F-7.7-02..07 raised | Workspace + accessor + hex-view caps |
| 8 | LLR-009.1/2 | 1 test + packet (2) | TC-081 (1) + TC-082 (3) | none | Engine determinism + `CoverageMetrics` correctness |
| 9 | LLR-001.1/2 + LLR-002.2 + LLR-003.1 + LLR-004.1 + LLR-007.1/3 + LLR-008.1/2 (this packet) | 1 packet (this file) | none | New Findings filed in §10 (3) | Inspection-method audit matrices |

Suite trajectory: 173 → 179/180 (1.5) → 181 (2) → 187 (3) → 203 (4) → 210 (5) → 217 (6) → 255 (7) → 259 (8) → **259** (9, no code change).

Open carry-through Findings (not closed by this batch; deferred to follow-up):

- **F-7.2-01** — engine gap: `CROSS_S19_HEX_OVERLAP` code is missing. (S19/HEX-overlap class.) Major.
- **F-7.2-02** — engine partial coverage: S19 checksum errors and A2L missing-`ECU_ADDRESS` not piped into the engine. Minor.
- **F-7.7-02** — `sanitize_project_name` does not reject Windows reserved names (`CON`, `PRN`, `AUX`, `NUL`, `COMn`, `LPTn`). Minor.
- **F-7.7-03** — `sanitize_project_name` does not enforce 64-char length cap. Minor.
- **F-7.7-04** — `sanitize_project_name` does not detect Unicode confusables. Minor.
- **F-7.7-05** — `validate_project_files` follows symlinks via `Path.is_file()`. Minor.
- **F-7.7-06** — REQUIREMENTS.md §Output API documents the `schema_ok / memory_checked / in_memory` triplet on the per-tag accessor; code surfaces it on the bulk validator instead. Minor.
- **F-7.7-07** — `validate_characteristic` returns the wrong tag's enrichment when the requested tag is not first in the parsed list (broken merge order). Major.
- **(new this increment)** see §10.

---

## 1. LLR-001.1 — S-record + Intel HEX rule coverage matrix (TC-002)

Acceptance: each `R-READ-*`, `R-PARSE-*`, `R-VAL-*`, and `R-HEX-*` row is implemented by a named symbol in `s19_app/core.py` or `s19_app/hexfile.py` and asserted by at least one test in `tests/test_core_srecord_validation.py` or `tests/test_hexfile.py`.

| `R-*` (or class) | Implementing symbol | Asserting test | Verdict | Finding |
|---|---|---|---|---|
| R-READ-001 — line-by-line read, ignore empty | `s19_app/core.py::S19File._load` | `tests/test_core_srecord_validation.py::test_s19file_collects_errors` | confirmed | — |
| R-PARSE-001 — non-empty line starts with `S`, supported type | `s19_app/core.py::SRecord.__init__` | `tests/test_core_srecord_validation.py::test_srecord_unsupported_type_raises`, `test_s19file_collects_errors` | confirmed | — |
| R-PARSE-002 — byte count valid hex + length matches | `s19_app/core.py::SRecord.__init__` | `tests/test_core_srecord_validation.py::test_srecord_invalid_byte_count_hex_raises`, `test_srecord_length_mismatch_raises` | confirmed | — |
| R-PARSE-003 — address field valid hex + fits record type | `s19_app/core.py::SRecord.__init__` | `tests/test_core_srecord_validation.py::test_srecord_valid_line`, `test_srecord_invalid_address_hex_raises` | confirmed | — |
| R-PARSE-004 — data field length matches byte count + valid hex | `s19_app/core.py::SRecord.__init__` | `tests/test_core_srecord_validation.py::test_srecord_invalid_data_hex_raises` | confirmed | — |
| R-PARSE-005 — checksum field valid hex | `s19_app/core.py::SRecord.__init__` | `tests/test_core_srecord_validation.py::test_srecord_invalid_checksum_hex_raises` | confirmed | — |
| R-VAL-001 — byte-count + checksum validate per spec | `s19_app/core.py::SRecord._validate`, `SRecord._calculate_checksum` | `tests/test_core_srecord_validation.py::test_srecord_valid_line`, `test_srecord_checksum_mismatch_invalid` | confirmed | — |
| R-VAL-002 — collect failures with line numbers, do not abort | `s19_app/core.py::S19File._load` | `tests/test_core_srecord_validation.py::test_s19file_collects_errors` | confirmed | — |
| R-HEX-001 — extended linear address (`:04`) | `s19_app/hexfile.py::IntelHexFile._load` | `tests/test_hexfile.py::test_hex_extended_linear_address` | confirmed | — |
| R-HEX-002 — extended segment address (`:02`) | `s19_app/hexfile.py::IntelHexFile._load` | `tests/test_hexfile.py::test_hex_extended_segment_address` | confirmed | — |
| R-HEX-003 — start-address records ignored (`:03`, `:05`) | `s19_app/hexfile.py::IntelHexFile._load` | `tests/test_hexfile.py::test_hex_start_address_records_are_ignored` | confirmed | — |
| Intel HEX checksum validation | `s19_app/hexfile.py::IntelHexFile._load` | `tests/test_hexfile.py::test_hex_checksum_mismatch_is_reported` | confirmed (extra coverage; not an `R-*` row but spec-implied) | F-9.01-01 — REQUIREMENTS.md is silent on Intel HEX checksum / length-mismatch / unsupported-record-type rules; tests exist but no `R-HEX-*` row owns them |
| Intel HEX length-mismatch reporting | `s19_app/hexfile.py::IntelHexFile._load` | `tests/test_hexfile.py::test_hex_length_mismatch_is_reported` | confirmed (extra) | F-9.01-01 |
| Intel HEX unsupported record type | `s19_app/hexfile.py::IntelHexFile._load` | `tests/test_hexfile.py::test_hex_unsupported_record_type_is_reported` | confirmed (extra) | F-9.01-01 |
| Intel HEX missing-prefix / parse-error / extended-segment-length / extended-linear-length / data-record-without-extended-address | `s19_app/hexfile.py::IntelHexFile._load` | `tests/test_hexfile.py::test_hex_missing_prefix_is_reported`, `test_hex_parse_error_is_reported`, `test_hex_invalid_extended_segment_length_is_reported`, `test_hex_invalid_extended_linear_length_is_reported`, `test_hex_data_record_without_extended_address` | confirmed (extra) | F-9.01-01 |
| `IntelHexFile.get_ranges()` contiguous grouping | `s19_app/hexfile.py::IntelHexFile.get_ranges` | `tests/test_hexfile.py::test_hex_get_ranges_groups_contiguous_addresses` | confirmed (extra) | — |
| `IntelHexFile` missing-file error | `s19_app/hexfile.py::IntelHexFile.__init__` | `tests/test_hexfile.py::test_hex_missing_file_raises` | confirmed (extra) | — |
| Loader summary log emission (S19 + HEX) | `s19_app/core.py::S19File._load`, `s19_app/hexfile.py::IntelHexFile._load` | `tests/test_core_srecord_validation.py::test_s19file_emits_load_summary_log`, `tests/test_hexfile.py::test_hex_loader_emits_summary_log` | confirmed (extra) | — |

**Summary.** All 11 declared `R-*` rows for S19/HEX parsing are confirmed. Test files contain ≥9 additional rules that are test-covered but not tied to a written `R-HEX-*` row. New Finding **F-9.01-01** filed in §10 to extend REQUIREMENTS.md so those rules become traceable.

---

## 2. LLR-001.2 — A2L + MAC parser rule coverage matrix (TC-005)

Acceptance: each `R-A2L-*` row plus the canonical MAC parsing behaviour is implemented by a named symbol in `s19_app/tui/a2l.py` (or its facades) / `s19_app/tui/mac.py` and asserted by a test in `tests/test_tui_a2l.py` or `tests/test_tui_mac.py` (or the helpers/app suite). MAC parsing has no `R-*` row in `REQUIREMENTS.md`; entries below labelled "MAC parser" are test-covered behaviour without a doc requirement (Finding F-9.02-01 in §10).

| `R-*` (or class) | Implementing symbol | Asserting test | Verdict | Finding |
|---|---|---|---|---|
| R-A2L-001 — minimal JSON-friendly parse + error capture | `s19_app/tui/a2l.py::parse_a2l_file` | `tests/test_tui_helpers.py::test_parse_a2l_file_captures_sections`, `test_parse_a2l_file_reports_unclosed_section`; `tests/test_tui_a2l.py::test_parse_a2l_file_reports_missing_file` | confirmed | — |
| R-A2L-002 — readable view summary, parse-error display, validation status | `s19_app/tui/a2l.py::render_a2l_view`, `validate_a2l_tags`; `s19_app/tui/app.py::update_a2l_view` | `tests/test_tui_helpers.py::test_render_a2l_view_shows_sections`, `test_render_a2l_view_shows_errors`, `test_validate_a2l_tags_matches_memory`; `tests/test_tui_a2l.py::test_render_a2l_view_shows_tag_validation_status` | confirmed (`Partial` flag in REQUIREMENTS.md retained — live tile integration still manual) | — |
| R-A2L-003 — JSON export keybinding | `s19_app/tui/app.py::action_dump_a2l_json` | none (`Manual`) | confirmed-as-Manual | F-9.02-02 (defer; manual gate before Phase 4) |
| R-A2L-004 — load A2L file + show in view | `s19_app/tui/screens.py::LoadFileScreen`; `s19_app/tui/app.py::_load_path_from_user_input`, `load_a2l_from_path`, `update_a2l_view` | none (`Manual`) | confirmed-as-Manual | F-9.02-02 |
| R-A2L-005 — extract MEASUREMENT/CHARACTERISTIC tag address+length | `s19_app/tui/a2l.py::extract_a2l_tags` | `tests/test_tui_a2l.py::test_parse_a2l_file_extracts_nested_measurement_and_characteristic_tags`, `test_extract_a2l_tags_ignores_unrelated_sections` | confirmed | — |
| R-A2L-006 — A2L tag column display | `s19_app/tui/app.py::update_a2l_tags_view` | `tests/test_tui_helpers.py::test_a2l_tag_filters_by_mode_and_field`; `tests/test_tui_a2l.py::test_parse_a2l_file_extracts_nested_measurement_and_characteristic_tags` | confirmed (`Partial` flag retained — column layout visual inspection still manual) | — |
| R-A2L-007 — filter by field + mode (All/Invalid/In-Memory) | `s19_app/tui/app.py::_filter_a2l_tags`, `_set_a2l_filter_field`, `_toggle_a2l_filter_menu` | `tests/test_tui_helpers.py::test_a2l_tag_filters_by_mode_and_field`; `tests/test_tui_app.py::test_filter_a2l_tags_supports_in_memory_and_boolean_fields` | confirmed | — |
| MAC parser — `TAG=hexaddr` line parse + diagnostics | `s19_app/tui/mac.py::parse_mac_file` | `tests/test_tui_mac.py::test_parse_mac_file_emits_summary_log` (only directly asserts log emission); MAC parse output is downstream-asserted via `tests/test_validation_engine.py` (consumes `parse_mac_file` for the `large_project` and `corrupt_records` fixtures) | confirmed (indirect) | F-9.02-01 — REQUIREMENTS.md has no `R-MAC-*` rows; behaviour is implicit and only asserted indirectly |
| A2L COMPU_METHOD/RECORD_LAYOUT/COMPU_TAB indexed maps | `s19_app/tui/a2l.py::parse_a2l_file` (populates `record_layouts_by_name`, `compu_methods_by_name`, `compu_tabs_by_name`) | `tests/test_tui_a2l.py::test_parse_a2l_file_extracts_layout_and_compu_maps` | confirmed (REQUIREMENTS.md "A2L Structural Parsing" §; no `R-A2L-*` row) | F-9.02-03 — A2L Structural Parsing prose section is not numbered |
| RECORD_LAYOUT decode metadata (`decode_type`, `element_count`, `byte_size`, `decode_endian`, byte-order precedence) | `s19_app/tui/a2l.py` (RECORD_LAYOUT resolution helpers; consumed by `enrich_a2l_tags_with_values`) | `tests/test_tui_a2l.py::test_enrich_a2l_tags_with_values_decodes_and_converts_linear`, `test_enrich_a2l_tags_with_values_uses_tab_interp` | confirmed | F-9.02-03 |
| Raw memory extraction (`raw_bytes`, `raw_available`, `missing_ranges`, `overlap_conflict`) | `s19_app/tui/a2l.py` (extraction helpers; `enrich_a2l_tags_with_values`) | `tests/test_tui_a2l.py::test_enrich_a2l_tags_with_values_decodes_and_converts_linear`; downstream via `tests/test_a2l_enriched.py` | confirmed | F-9.02-03 |
| COMPU_METHOD execution (IDENTICAL/LINEAR/RAT_FUNC/TAB_INTP/TAB_NOINTP/FORM) | `s19_app/tui/a2l.py` (compu-method evaluator) | `tests/test_tui_a2l.py::test_enrich_a2l_tags_with_values_decodes_and_converts_linear`, `test_enrich_a2l_tags_with_values_uses_tab_interp`, `test_parse_compu_method_extracts_unit_from_body_conversion_line` | confirmed | F-9.02-03 |
| Output API (`get_raw_value`, `get_physical_value`, `validate_characteristic`) | `s19_app/tui/a2l.py` accessors | `tests/test_tui_a2l.py::test_characteristic_accessor_payloads`; `tests/test_tui_public_api.py::test_tc_051_*`, `test_tc_052_*` (incl. xfail for F-7.7-07) | confirmed (with caveat F-7.7-06, F-7.7-07) | — (already filed in increment 7) |

**Summary.** All 7 declared `R-A2L-*` rows are confirmed (5 automated, 2 partial-with-asserted-core). 5 prose-only rule clusters (MAC parser, A2L structural parsing, RECORD_LAYOUT, raw extraction, COMPU_METHOD) are test-covered but lack `R-*` numbering — Finding F-9.02-01/03 logged.

---

## 3. LLR-002.2 — Issues-panel classification audit (TC-014)

Acceptance: every `ValidationIssue.code` actually emitted by `s19_app/validation/rules.py` or `engine.py` lands in the correct `Errors` / `Warnings` / `Optional info` tier per `REQUIREMENTS.md` §Issues Tile Severity Policy. Severity assignment is the engine's; the policy ties severity → tier through `color_policy.SEVERITY_CLASS_MAP` (locked by LLR-002.1 / TC-012).

Tier mapping per `REQUIREMENTS.md` §Issues Tile Severity Policy:

- **Errors** = `ValidationSeverity.ERROR` → CSS class `sev-error`
- **Warnings** = `ValidationSeverity.WARNING` → CSS class `sev-warning`
- **Optional info** = `ValidationSeverity.INFO` (+ `OK` / `NEUTRAL` for non-issue rendering) → CSS class `sev-info` / `sev-ok` / `sev-neutral`

### 3.1 Errors tier (REQUIREMENTS.md text → emitted code)

| REQUIREMENTS.md text | Emitted code | Emitting symbol | Asserting test | Verdict |
|---|---|---|---|---|
| MAC parse error | `MAC_PARSE_ERROR` | `s19_app/validation/rules.py::validate_mac_records` (line ~318) | `tests/test_validation_engine.py::TestCrossFileCompatibilityCoEmission::test_tc_062_h_parsed_record_corruption_emits_issue`; `tests/test_tui_app.py::test_tc_065_h_parsed_record_corruption_panel_render` | confirmed |
| MAC empty name | `MAC_EMPTY_NAME` | `rules.py::validate_mac_records` (line ~331) | `tests/test_validation_mac.py::test_validate_mac_records_reports_parse_and_empty_fields` | confirmed |
| MAC invalid/missing address | `MAC_INVALID_ADDRESS` | `rules.py::validate_mac_records` (line ~341) | `tests/test_validation_mac.py::test_validate_mac_records_reports_parse_and_empty_fields` | confirmed |
| Duplicate MAC symbol name | `MAC_DUPLICATE_NAME` | `rules.py::validate_mac_records` (line ~358) | `tests/test_validation_mac.py::test_validate_mac_records_duplicate_name_remains_hard_error` | confirmed |
| A2L parser/structure errors | `A2L_STRUCTURE_ERROR` | `rules.py::validate_a2l_structure` (line ~444) | covered by `tests/test_validation_a2l.py::test_validate_a2l_structure_detects_unrecognized_and_duplicate_symbols` (asserts errors flow); engine integration via `tests/test_color_policy_round_trip.py::test_validate_artifact_consistency_round_trip_on_large_project` | confirmed |
| Invalid A2L address field type | `A2L_INVALID_ADDRESS` | `rules.py::validate_a2l_structure` (line ~463) | not directly asserted by code-string match in any test today (covered indirectly via `large_project` round-trip) | drift (minor) — F-9.03-01 |
| Duplicate A2L symbol | `A2L_DUPLICATE_SYMBOL` | `rules.py::validate_a2l_structure` (line ~474) | `tests/test_validation_a2l.py::test_validate_a2l_structure_detects_unrecognized_and_duplicate_symbols` | confirmed |
| Broken GROUP/FUNCTION references | `A2L_BROKEN_REFERENCE` | `rules.py::validate_a2l_structure` (line ~507) | `tests/test_validation_a2l.py::test_validate_a2l_structure_detects_broken_references` | confirmed (note: severity is **WARNING** in code, not ERROR — see drift below) |
| A2L↔MAC same-name address mismatch | `TRIPLE_NAME_ADDRESS_MISMATCH` | `s19_app/validation/engine.py::validate_artifact_consistency` (line ~163) | `tests/test_validation_engine.py::TestCrossFileCompatibilityCoEmission::test_tc_062_d_a2l_mac_name_address_mismatch_emits_issue`; `test_tui_app.py::test_tc_065_d_*` | confirmed |

**Drift on `A2L_BROKEN_REFERENCE` severity.** REQUIREMENTS.md §Issues Tile Severity Policy lists "broken GROUP/FUNCTION references" under **Errors**. `s19_app/validation/rules.py:508` emits `A2L_BROKEN_REFERENCE` at `ValidationSeverity.WARNING`. New Finding **F-9.03-02** in §10 (severity divergence between policy and code).

### 3.2 Warnings tier

| REQUIREMENTS.md text | Emitted code | Emitting symbol | Asserting test | Verdict |
|---|---|---|---|---|
| MAC address out of S19 range | `CROSS_MAC_S19_OUT_OF_RANGE` | `engine.py::validate_artifact_consistency` (line ~90) | `tests/test_validation_engine.py::TestCrossFileCompatibilityCoEmission::test_tc_062_c_*`; `test_tui_app.py::test_tc_065_c_*` | confirmed |
| A2L range out of S19 range | `CROSS_A2L_S19_OUT_OF_RANGE` | `engine.py` (line ~128) | `tests/test_validation_engine.py::TestCrossFileCompatibilityCoEmission::test_tc_062_b_*`; `test_tui_app.py::test_tc_065_b_*` | confirmed |
| Overlap ambiguity (MAC) | `CROSS_MAC_S19_OVERLAP_AMBIGUOUS` | `engine.py` (line ~102) | `tests/test_tui_services.py` line 49 (assertion against the code); engine round-trip on `large_project` | confirmed |
| Overlap ambiguity (A2L) | `CROSS_A2L_S19_OVERLAP_AMBIGUOUS` | `engine.py` (line ~140) | `tests/test_validation_engine.py` line 39 (existing `test_validate_artifact_consistency_reports_cross_mismatches`) | confirmed |
| Symbol-only-in-MAC | `CROSS_MAC_ONLY_SYMBOL` | `engine.py` (line ~177) | `tests/test_validation_engine.py::TestCrossFileCompatibilityCoEmission::test_tc_062_e_*`; `test_tui_app.py::test_tc_065_e_*` | confirmed |
| Symbol-only-in-A2L | `CROSS_A2L_ONLY_SYMBOL` | `engine.py` (line ~188) | `tests/test_validation_engine.py::TestCrossFileCompatibilityCoEmission::test_tc_062_f_*`; `test_tui_app.py::test_tc_065_f_*` | confirmed |
| Duplicate-address alias when policy emits warning | `MAC_DUPLICATE_ADDRESS` (with classification ∈ `alias candidate`/`bitfield sharing`/`segment ambiguity`) | `rules.py::validate_mac_records` line ~376 + `classification_to_severity` (line ~244) | `tests/test_validation_engine.py::TestCrossFileCompatibilityCoEmission::test_tc_062_g_*`; `tests/test_validation_mac.py::test_validate_mac_records_detects_duplicate_address_alias_candidate`; `test_tui_app.py::test_tc_065_g_*` | confirmed (severity policy-dependent — see §7) |
| Unrecognised A2L block (extra) | `A2L_UNRECOGNIZED_BLOCK` | `rules.py::validate_a2l_structure` line ~487 | `tests/test_validation_a2l.py::test_validate_a2l_structure_detects_unrecognized_and_duplicate_symbols` | confirmed (extra rule not enumerated in REQUIREMENTS.md tier text) |

### 3.3 Optional-info tier

| REQUIREMENTS.md text | Emitted code | Emitting symbol | Asserting test | Verdict |
|---|---|---|---|---|
| Valid-but-not-image-backed | (no `ValidationIssue` emitted; surfaced as `White` row colour at the A2L view layer via `validate_a2l_tags`) | `s19_app/tui/a2l.py::validate_a2l_tags` (`schema_ok=True, in_memory=False`) | `tests/test_tui_helpers.py::test_validate_a2l_tags_matches_memory`; `tests/test_tui_a2l.py::test_validate_a2l_tags_without_mem_map_skips_image_check`, `test_render_a2l_view_shows_out_of_image_status` | confirmed-as-Color-only — no `ValidationIssue` code |
| Not-checked-without-primary-image | (no `ValidationIssue` emitted; surfaced as `Grey` row colour) | `s19_app/tui/a2l.py::validate_a2l_tags` (returns `memory_checked=False` when `mem_map=None`) | `tests/test_tui_a2l.py::test_validate_a2l_tags_without_mem_map_skips_image_check` | confirmed-as-Color-only |
| Virtual / dependent / non-memory-backed | (no `ValidationIssue` emitted; row-level virtual flag) | `s19_app/tui/a2l.py::validate_a2l_tags` (virtual-tag branch) | `tests/test_tui_a2l.py::test_validate_a2l_tags_virtual_without_address_skips_range` | confirmed-as-Color-only |
| Duplicate-address alias under `alias_policy="allow"` | `MAC_DUPLICATE_ADDRESS` with `severity=INFO` | `rules.py::classification_to_severity` (line ~273) | `tests/test_validation_mac.py::test_validate_mac_records_duplicate_address_info_when_allow_policy` | confirmed |
| Hard-conflict promotion (escalation, not info) | `MAC_DUPLICATE_ADDRESS` with `severity=ERROR` (`classification == "hard conflict"`) | `rules.py::classify_mac_duplicate_group` (line ~232) + `classification_to_severity` (line ~266) | `tests/test_validation_engine.py::test_validate_artifact_consistency_escalates_duplicate_address_hard_conflict`; `tests/test_validation_mac.py::test_validate_mac_records_duplicate_address_hard_conflict_from_a2l` | confirmed |

**Summary.** 17 emitted codes mapped to tiers. 16 confirmed; 1 drift (`A2L_BROKEN_REFERENCE` severity = WARNING in code but tier in policy = Errors → F-9.03-02). 1 minor drift (`A2L_INVALID_ADDRESS` not asserted by direct code-string match in any unit test — F-9.03-01). The three "Optional info" REQUIREMENTS.md bullets are color-policy only (no `ValidationIssue` codes emitted) — that is the documented intent (see §A2L Tag/Parameter Validation Criteria — `Grey/White` semantics).

---

## 4. LLR-003.1 — `app.py` parsing/validation call-site enumeration (TC-021/022)

Acceptance: every `app.py` call-site that touches the parsing layer (`S19File`, `IntelHexFile`, `parse_a2l_file`, `parse_mac_file`) or the validation layer (`validate_artifact_consistency`, `enrich_a2l_tags_with_values`) is either:

(a) routed via a `tui/services/*` function (`load_service.build_loaded_s19/build_loaded_hex`, `a2l_service.enrich_tags_and_render`, `validation_service.build_validation_report`), OR
(b) a documented bypass that this audit explicitly justifies.

Imports in `s19_app/tui/app.py` lines 29–49 (verified verbatim):

```
from ..core import S19File                                         # line 29
from ..hexfile import IntelHexFile                                 # line 30
from .a2l_parse import parse_a2l_file                              # line 31  (facade for s19_app/tui/a2l.py::parse_a2l_file)
from .mac import parse_mac_file                                    # line 42
from ..validation import ValidationIssue, ValidationReport, ValidationSeverity  # line 46  (types only — no rule symbols imported)
from .services.a2l_service import enrich_tags_and_render           # line 47
from .services.load_service import build_loaded_hex, build_loaded_s19  # line 48
from .services.validation_service import build_validation_report   # line 49
```

Note `validate_artifact_consistency`, `enrich_a2l_tags_with_values`, and `validate_a2l_tags` are NOT imported by `app.py`. This is the structural anchor for LLR-003.1 — feature logic flows through the services, not direct rule symbols.

| Call-site (`app.py` line) | Called function | Routed-via-service? | Verdict | Finding |
|---|---|---|---|---|
| line 2716 — `mac_data = parse_mac_file(path)` (within `_parse_mac_loaded_file`) | `parse_mac_file` (parser) | **bypass** — direct parser call from app, not via a service | drift-acceptable | F-9.04-01 — no `mac_service` exists; MAC load path bypasses the service layer that S19/HEX/A2L use. Recommend `tui/services/mac_service.py::build_loaded_mac` for symmetry. (Minor — consistent with the project's "simple over clever" decision rule, but inconsistent with the other 3 file types.) |
| line 3158 — `S19File(str(primary_file.path)).get_overlap_addresses()` (inside `_run_validation`) | `S19File` constructor | **bypass** — direct parser call to fetch the overlap set; the parsed result is then handed to `build_validation_report` | drift-acceptable | F-9.04-02 — overlap-set extraction is the only piece of the validation pipeline not encapsulated in `validation_service.build_validation_report`. Recommend folding it into `build_validation_report` (signature would become `build_validation_report(..., primary_path=...)` and compute the overlap inline). Minor. |
| line 3166 — `report, issues, coverage_line = build_validation_report(...)` | `validation_service.build_validation_report` | **routed** | confirmed | — |
| line 3338 — `s19 = S19File(str(path))` (inside `_load_s19_loaded_file`) | `S19File` constructor | **routed** — the `S19File` instance is then passed directly into `build_loaded_s19` on line 3341 | confirmed (the construct-then-route pattern is acceptable; see §5.1 of `01-requirements.md`) | — |
| line 3341 — `loaded = build_loaded_s19(path, s19, a2l_path, a2l_data)` | `load_service.build_loaded_s19` | **routed** | confirmed | — |
| line 3357 — `hex_file = IntelHexFile(str(path))` (inside `_load_hex_loaded_file`) | `IntelHexFile` constructor | **routed** (same construct-then-route pattern) | confirmed | — |
| line 3360 — `loaded = build_loaded_hex(path, hex_file, a2l_path, a2l_data)` | `load_service.build_loaded_hex` | **routed** | confirmed | — |
| line 3665 — `a2l_enriched_tags, a2l_summary_lines = enrich_tags_and_render(...)` (inside `_apply_loaded_file`) | `a2l_service.enrich_tags_and_render` | **routed** | confirmed | — |
| line 3902 — `parsed = parse_a2l_file(path)` (inside `_load_a2l_data_cached`) | `parse_a2l_file` (parser facade) | **bypass** — direct parser call from app | drift-acceptable | F-9.04-03 — A2L cache lookup is implemented in `app.py` rather than in `a2l_service`. Recommend `a2l_service.parse_and_cache(path, cache)`. Minor; the cache key is `(resolved_path, mtime, size)` which is straightforward, but routing through a service would let tests against `a2l_service` lock the cache contract. |
| line 4449 — `enriched, summary_lines = enrich_tags_and_render(...)` (inside `_render_a2l_via_service`) | `a2l_service.enrich_tags_and_render` | **routed** | confirmed | — |

**Hex-view bypass cross-check (LLR-003.2 reference).** Increment 7 §1 added an AST walk of `app.py` for `from s19_app.tui.hexview import _xxx` (private-helper imports). Result: empty list. App.py only imports the documented public knobs (`MAX_HEX_BYTES`, `MAX_HEX_ROWS`, `FOCUS_CONTEXT_ROWS`, `HEX_WIDTH`, `SEARCH_ENCODING`, `render_hex_view_text`, `find_string_in_mem`). LLR-003.2 confirmed by test `tests/test_tui_hexview.py::test_app_does_not_import_private_hexview_helpers` (per increment 7). Restated here for the LLR-003.1 audit: the parsing/validation/hex-view call-site discipline is consistent — no private symbols leak into `app.py`.

**Summary.** 10 call-sites enumerated. 7 routed (confirmed), 3 documented-bypasses (drift-acceptable; Findings F-9.04-01/02/03 raised in §10 for the symmetry follow-up). The orchestration-only contract is **substantially upheld** — no validation rule logic and no hex-view private helper logic resides in `app.py`. The three bypasses are at the parser layer (MAC + A2L parse + S19 overlap fetch), not at the rule/render layer.

---

## 5. LLR-004.1 — Per-`R-*` verdict report (TC-030/031/032/033)

Acceptance: every `R-*` row in `REQUIREMENTS.md` is reviewed against the post-Phase-3 codebase. Each row gets one of `confirmed` / `promote` / `drift` / `unknown`.

### 5.1 Full per-row matrix (41 rows)

| `R-*` | Doc claim | Implementing symbol | Asserting test | Verdict | Notes |
|---|---|---|---|---|---|
| R-READ-001 | Automated | `core.py::S19File._load` | `test_core_srecord_validation.py::test_s19file_collects_errors` | confirmed | — |
| R-PARSE-001 | Automated | `core.py::SRecord.__init__` | `test_srecord_unsupported_type_raises`, `test_s19file_collects_errors` | confirmed | — |
| R-PARSE-002 | Automated | `core.py::SRecord.__init__` | `test_srecord_invalid_byte_count_hex_raises`, `test_srecord_length_mismatch_raises` | confirmed | — |
| R-PARSE-003 | Automated | `core.py::SRecord.__init__` | `test_srecord_valid_line`, `test_srecord_invalid_address_hex_raises` | confirmed | — |
| R-PARSE-004 | Automated | `core.py::SRecord.__init__` | `test_srecord_invalid_data_hex_raises` | confirmed | — |
| R-PARSE-005 | Automated | `core.py::SRecord.__init__` | `test_srecord_invalid_checksum_hex_raises` | confirmed | — |
| R-VAL-001 | Automated | `core.py::SRecord._validate`, `_calculate_checksum` | `test_srecord_valid_line`, `test_srecord_checksum_mismatch_invalid` | confirmed | — |
| R-VAL-002 | Automated | `core.py::S19File._load` | `test_s19file_collects_errors` | confirmed | — |
| R-HEX-001 | Automated | `hexfile.py::IntelHexFile._load` | `test_hexfile.py::test_hex_extended_linear_address` | confirmed | — |
| R-HEX-002 | Automated | `hexfile.py::IntelHexFile._load` | `test_hex_extended_segment_address` | confirmed | — |
| R-HEX-003 | Automated | `hexfile.py::IntelHexFile._load` | `test_hex_start_address_records_are_ignored` | confirmed | — |
| R-TUI-001 | Partial | `workspace.py::ensure_workarea`, `app.py::S19TuiApp.__init__` | `test_tui_workspace.py::test_ensure_workarea_creates_expected_directories` | confirmed | startup wiring still verified manually per the row text |
| R-TUI-002 | Partial | `workspace.py::copy_into_workarea`, `app.py::load_selected_file` | `test_tui_helpers.py::test_copy_into_workarea_creates_unique_names` (post-increment 1: also TC-044/045/046/047 in `test_tui_workspace.py::TestCopyIntoWorkareaContainment`) | **promote** | Increment 1 added 4 dedicated containment tests (TC-044 size cap, TC-045 source symlink, TC-046 destination containment, TC-047 NTFS junction Windows-only). The full load action is now strongly automated against pathological inputs; manual run only required for TC-047 on Windows hosts. Row should read `Automated (TC-047 manual on non-Windows CI)`. |
| R-TUI-003 | Manual | `app.py::S19TuiApp.CSS`, `compose` | none (visual) | unknown | layout DOM exists; no automated screenshot or widget-tree assertion exercises the four-tile geometry today. Requires textual-snapshot or DOM-assertion tooling. |
| R-TUI-004 | Automated | `hexview.py::render_hex_view`, `render_hex_view_text` | `test_render_hex_view_includes_focus_context`, `test_render_hex_view_truncates_output`, `test_tui_hexview.py::test_render_hex_view_text_highlights_match_range` | confirmed | — |
| R-TUI-005 | Automated | `workspace.py::resolve_input_path`, `find_repo_root` | `test_resolve_input_path_prefers_base_dir`, `test_resolve_input_path_falls_back_to_repo_root`; post-increment 7: `test_tui_workspace.py::TestReadPathResolution` (4 cases — TC-041) | **promote-extended** | Doc still reads `Automated`; increment 7 added explicit `None`/absolute-path/`project.toml`-marker/no-marker corner cases. Row already meets `Automated`; suggested doc footnote linking to TC-041. |
| R-TUI-006 | Automated | `workspace.py::copy_into_workarea` | `test_copy_into_workarea_creates_unique_names` | confirmed | — |
| R-TUI-007 | Automated | `hexview.py::render_hex_view`, `_collect_hex_rows` | `test_render_hex_view_includes_focus_context`, `test_render_hex_view_truncates_output`, `test_tui_hexview.py::test_collect_hex_rows_reports_missing_focus_address` | confirmed | — |
| R-TUI-008 | Manual | `app.py::action_open_workarea` | none | unknown | Cross-platform shell-out — would require a per-OS subprocess assertion. Defer. |
| R-TUI-009 | Manual | `app.py::_jump_to_section`, `update_hex_view` | indirect via `test_tui_app.py` (selection-jump tests cover R-TUI-018 which generalises this) | **promote** | `test_tui_app.py` exercises section-jump in the A2L/MAC selection-jump tests (R-TUI-018 row); the same focus-then-update pipeline is hit. Row should read `Automated` with citation to `test_tui_app.py` selection-jump tests. |
| R-TUI-010 | Manual | `app.py::CSS`, `compose` | none (visual) | unknown | Same constraint as R-TUI-003 — no DOM/widget-tree automated assertion. |
| R-TUI-011 | Partial | `workspace.py::WORKAREA_TEMP`, `ensure_workarea`; `app.py::load_from_path` | `test_tui_workspace.py::test_ensure_workarea_creates_expected_directories`; increment 1 indirectly via TC-046 (containment requires temp/) | confirmed | — |
| R-TUI-012 | Partial | `workspace.py::sanitize_project_name`, `copy_into_workarea`; `app.py::action_save_project`, `_handle_save_dialog` | `test_sanitize_project_name_*` (3 cases); post-increment 1.5: `test_tui_app.py::test_save_project_writes_under_workarea`; post-increment 7: `TestSanitizeProjectName` (TC-042 — 8 cases, **3 of which are self-flip-guarded for F-7.7-02/03/04**) | **drift** | The save-flow itself is now Automated thanks to increment 1.5. **However** `sanitize_project_name` does not enforce the LLR-005.2 acceptance contract (Windows reserved names, 64-char cap, Unicode confusables — F-7.7-02/03/04). The row's `Partial` claim is correct in spirit but the doc text does not flag the acceptance gap. Recommend doc text: "Automated for happy-path; LLR-005.2 acceptance gaps tracked under F-7.7-02/03/04." |
| R-TUI-013 | Partial | `app.py::LoadProjectScreen`, `list_projects`, `action_load_project`, `_handle_load_project` | `test_list_projects_ignores_temp`; `test_tui_app.py::test_list_projects_skips_files_and_sorts_names` | confirmed | manual still required for the live project-load flow per row text |
| R-TUI-014 | Automated | `workspace.py::validate_project_files` | `test_validate_project_files_allows_single_data_and_a2l`, `test_validate_project_files_rejects_multiple_data`, `test_validate_project_files_rejects_multiple_a2l`; post-increment 7: `TestValidateProjectFilesSymlinkAndCase` (TC-048 — 3 cases, **1 self-flip-guarded for F-7.7-05**) | **drift** | Doc says `Automated` for cardinality. Increment 7 confirmed cardinality but exposed F-7.7-05 (symlinks pass `is_file()`). The cardinality contract is automated; the broader LLR-005.4 acceptance (no symlink/reparse-point in the project tree) is **not** met. Recommend doc text: "Automated for cardinality; symlink-rejection deferred under F-7.7-05." |
| R-TUI-015 | Automated | `workspace.py::setup_logging`, `ensure_workarea` | `test_setup_logging_creates_log_handler`, `test_setup_logging_uses_rotating_file_handler`; `test_tui_workspace.py::test_setup_logging_reuses_handler_for_same_path`; post-increment 7: `TestSetupLoggingSurface` (TC-049 — 3 cases) | confirmed | — |
| R-TUI-016 | Manual | `app.py::update_project_labels` | none | unknown | tile-label assertion would need DOM probing; defer |
| R-TUI-017 | Partial | `hexview.py::find_string_in_mem`, `render_hex_view_text`; `app.py::_handle_search`, `_handle_goto` | `test_find_string_in_mem_finds_address`, `test_find_string_in_mem_returns_none_when_missing`, `test_find_string_in_mem_supports_next_search`; `test_tui_hexview.py::test_render_hex_view_text_highlights_match_range` | confirmed | manual interactive goto flow remains the partial-claim residue |
| R-TUI-018 | Automated | `app.py::_jump_to_tag_by_data`, `_jump_to_mac_address`, `update_alt_hex_view`, `update_mac_hex_view`; `hexview.py::_collect_hex_rows`, `render_hex_view_text` | `test_tui_app.py` (selection-jump behavior) | confirmed | — |
| R-TUI-019 | Automated | `app.py::compose`, button handlers, paging actions | `test_tui_app.py` | confirmed | — |
| R-TUI-020 | Automated | `app.py::action_page_next_context`, `action_page_prev_context`, `action_a2l_tags_page_next`, `action_a2l_tags_page_prev`, `action_mac_records_page_next`, `action_mac_records_page_prev` | `test_tui_app.py` | confirmed | — |
| R-A2L-001 | Automated | `tui/a2l.py::parse_a2l_file` | `test_parse_a2l_file_captures_sections`, `test_parse_a2l_file_reports_unclosed_section`; `test_tui_a2l.py::test_parse_a2l_file_reports_missing_file` | confirmed | — |
| R-A2L-002 | Partial | `tui/a2l.py::render_a2l_view`, `validate_a2l_tags`; `app.py::update_a2l_view` | `test_render_a2l_view_shows_sections`, `test_render_a2l_view_shows_errors`, `test_validate_a2l_tags_matches_memory`; `test_tui_a2l.py::test_render_a2l_view_shows_tag_validation_status` | confirmed | live-tile manual portion residual |
| R-A2L-003 | Manual | `app.py::action_dump_a2l_json` | none | unknown | keybinding action — defer to manual gate |
| R-A2L-004 | Manual | `screens.py::LoadFileScreen`; `app.py::_load_path_from_user_input`, `load_a2l_from_path`, `update_a2l_view` | indirect via `test_tui_app.py` (selection-jump tests load A2L data) | **promote** | A2L load through the project pipeline is exercised in `test_tui_app.py` and `test_validation_engine.py::TestCrossFileCompatibilityCoEmission` (the engine-side tests parse A2L through `parse_a2l_file` and feed it to the engine). The user-keypress dialog is not exercised; the load+show pipeline is. Recommend partial promotion to "Partial — A2L parse + view automated; modal dialog still manual." |
| R-A2L-005 | Automated | `tui/a2l.py::extract_a2l_tags` | `test_tui_a2l.py::test_parse_a2l_file_extracts_nested_measurement_and_characteristic_tags`, `test_extract_a2l_tags_ignores_unrelated_sections` | confirmed | — |
| R-A2L-006 | Partial | `app.py::update_a2l_tags_view` | `test_a2l_tag_filters_by_mode_and_field`; `test_tui_a2l.py::test_parse_a2l_file_extracts_nested_measurement_and_characteristic_tags` | confirmed | column-layout visual residue |
| R-A2L-007 | Automated | `app.py::_filter_a2l_tags`, `_set_a2l_filter_field`, `_toggle_a2l_filter_menu` | `test_a2l_tag_filters_by_mode_and_field`; `test_tui_app.py::test_filter_a2l_tags_supports_in_memory_and_boolean_fields` | confirmed | — |
| R-PROJ-001 | Manual | `app.py::_handle_save_dialog` | indirect via `test_tui_app.py::test_save_project_writes_under_workarea` (post-increment 1.5) — covers the data-file save path | **promote** | Save path is automated for the workarea-rooted positive case. Multi-file (data + A2L together) save still relies on the same `_handle_save_dialog` code path; recommend an additional positive test that asserts both files land. Row could promote to `Partial` (data path automated; combined data+A2L still manual). |
| R-PROJ-002 | Manual | `app.py::_sync_loaded_file_to_project`, `_sync_loaded_a2l_to_project`, `load_from_path`, `load_a2l_from_path`, `_load_path_from_user_input` | none | unknown | sync-after-active-project flow not exercised; defer |
| R-DOC-001 | Automated | `tui/__init__.py`, `app.py` | `test_tui_module_has_docstring`, `test_tui_app_has_docstring` | confirmed | — |

### 5.2 Promotions (Manual/Partial → Automated thanks to increments 1–8)

| `R-*` | Pre-batch claim | Post-batch verdict | Increment(s) responsible | New test(s) |
|---|---|---|---|---|
| R-TUI-002 | Partial | promote → `Automated` | 1 | `tests/test_tui_workspace.py::TestCopyIntoWorkareaContainment` (TC-044/045/046/047) |
| R-TUI-005 | Automated (kept) | promote-extended (corner cases) | 7 | `tests/test_tui_workspace.py::TestReadPathResolution` (TC-041) |
| R-TUI-009 | Manual | promote → `Automated` (via R-TUI-018 lineage) | 6 (selection-jump tests; pre-existing in `test_tui_app.py`) | indirect citation — recommend explicit row update |
| R-A2L-004 | Manual | promote → `Partial` (parse + view automated; modal manual) | 5 / 6 | `tests/test_validation_engine.py::TestCrossFileCompatibilityCoEmission` and `tests/test_tui_app.py::TestCrossFileCompatibilityPanelRender` |
| R-PROJ-001 | Manual | promote → `Partial` (save-path positive case automated) | 1.5 | `tests/test_tui_app.py::test_save_project_writes_under_workarea` |

Drift entries (5.1): **R-TUI-012**, **R-TUI-014** — doc claim does not reflect the LLR-005.x acceptance gaps surfaced by increments 7's Findings F-7.7-02/03/04 and F-7.7-05.

### 5.3 Roll-up

- **Confirmed:** 28 rows
- **Promote:** 5 rows (see §5.2)
- **Drift:** 2 rows (R-TUI-012, R-TUI-014; doc text understates the LLR-005.2 / LLR-005.4 gap)
- **Unknown (Phase 4 manual review needed):** 6 rows (R-TUI-003, R-TUI-008, R-TUI-010, R-TUI-016, R-A2L-003, R-PROJ-002)
- **Total:** 41 rows

The `unknown` rows are all UI-only or single-keybinding flows that no automated test exercises today. They do not require code changes — they require either a manual gate run logged in `04-validation.md` or a follow-up batch that adds DOM-assertion / subprocess-assertion infrastructure.

---

## 6. LLR-007.1 — Cross-file class enumeration (TC-061)

Acceptance: each of the 8 cross-file incompatibility classes is enumerated with fixture, expected `ValidationIssue.code`, severity (under each alias policy), emitting rule, and engine-test result. Source: increment 5 §6 per-class evidence table — restated here with explicit `R-*`-style class IDs (`X-007.1-a` through `X-007.1-h`).

| Class ID | Class | Fixture | Engine-emitted code | Severity (`alias_policy="warn"`) | Severity (`alias_policy="error"`) | Severity (`alias_policy="allow"`) | Emitting rule (file:line) | Engine test (TC-062.X) | Panel test (TC-065.X) | Result |
|---|---|---|---|---|---|---|---|---|---|---|
| X-007.1-a | S19/HEX overlap | `overlap_s19_hex` | **gap** — recommend `CROSS_S19_HEX_OVERLAP` | recommend WARNING | recommend WARNING | recommend WARNING | n/a (no rule) | `tests/test_validation_engine.py::test_tc_062_a_*` | `tests/test_tui_app.py::test_tc_065_a_*` | **xfail** (F-7.2-01) |
| X-007.1-b | A2L tag range out of S19 range | `large_project` | `CROSS_A2L_S19_OUT_OF_RANGE` | WARNING | WARNING | WARNING | `engine.py:128` | `test_tc_062_b_*` | `test_tc_065_b_*` | pass |
| X-007.1-c | MAC address out of S19 range | `large_project` | `CROSS_MAC_S19_OUT_OF_RANGE` | WARNING | WARNING | WARNING | `engine.py:90` | `test_tc_062_c_*` | `test_tc_065_c_*` | pass |
| X-007.1-d | A2L↔MAC same-name address mismatch | `large_project` | `TRIPLE_NAME_ADDRESS_MISMATCH` | ERROR | ERROR | ERROR | `engine.py:163` | `test_tc_062_d_*` | `test_tc_065_d_*` | pass |
| X-007.1-e | symbol-only-in-MAC | `large_project` | `CROSS_MAC_ONLY_SYMBOL` | WARNING | WARNING | WARNING | `engine.py:177` | `test_tc_062_e_*` | `test_tc_065_e_*` | pass |
| X-007.1-f | symbol-only-in-A2L | `large_project` | `CROSS_A2L_ONLY_SYMBOL` | WARNING | WARNING | WARNING | `engine.py:188` | `test_tc_062_f_*` | `test_tc_065_f_*` | pass |
| X-007.1-g | duplicate-address alias | `duplicate_alias_mac` | `MAC_DUPLICATE_ADDRESS` (`classification="alias candidate"`) | **WARNING** (active default) | ERROR (escalated by `classification_to_severity` only when `classification="hard conflict"`; the `"error"` policy alone does not change `alias candidate` severity in the current implementation — see Finding below) | INFO (downgraded) | `rules.py:377` (severity via `classification_to_severity`, line ~244) | `test_tc_062_g_*` | `test_tc_065_g_*` | pass |
| X-007.1-h | parsed-record corruption | `corrupt_records` | `MAC_PARSE_ERROR` (engine-visible subset) | ERROR | ERROR | ERROR | `rules.py:318` | `test_tc_062_h_*` | `test_tc_065_h_*` | pass (partial — F-7.2-02 covers the S19/A2L gap) |

**New observation worth filing.** Re-reading `rules.py::classification_to_severity` (lines 244–276) at audit time: the function's `alias_policy` argument only branches on `"allow"` (downgrade non-conflicts to INFO). There is **no `"error"` branch** — passing `alias_policy="error"` produces the same WARNING severity as `"warn"`. The increment 5 §6 row for `alias_policy="error"` claimed the duplicate-alias class would emit at ERROR; that is **incorrect for non-hard-conflict classifications**. Hard-conflict groups always reach ERROR via the `MAC_DUPLICATE_HARD_CONFLICT` branch (line 266), regardless of policy. The `"error"` token therefore is a **dead alias-policy value** today. Filed as **F-9.07-01** in §10.

**Active alias policy at audit time:** `validate_artifact_consistency(... alias_policy="warn" ...)` — confirmed by inspection of `s19_app/validation/engine.py:27` (default value of the kwarg). The engine has no caller in `app.py` or `validation_service.py` that overrides this default — confirmed by grep. The TUI does not expose an alias-policy toggle today.

---

## 7. LLR-007.3 — Severity matrix per active alias policy (TC-063)

Derived from §6, organised by Issues-tile tier and alias policy. **Active alias policy at audit time = `"warn"` (engine default).** Per LLR-007.3 acceptance: this matrix MUST log the active policy explicitly — done.

### 7.1 Severity-by-tier matrix (active `alias_policy="warn"`)

| Tier (per REQUIREMENTS.md) | Code | Class | Severity | CSS class (per `color_policy.SEVERITY_CLASS_MAP`) |
|---|---|---|---|---|
| Errors | `MAC_PARSE_ERROR` | X-007.1-h | ERROR | `sev-error` |
| Errors | `MAC_EMPTY_NAME` | (intra-MAC) | ERROR | `sev-error` |
| Errors | `MAC_INVALID_ADDRESS` | (intra-MAC) | ERROR | `sev-error` |
| Errors | `MAC_DUPLICATE_NAME` | (intra-MAC) | ERROR | `sev-error` |
| Errors | `A2L_STRUCTURE_ERROR` | (intra-A2L) | ERROR | `sev-error` |
| Errors | `A2L_INVALID_ADDRESS` | (intra-A2L) | ERROR | `sev-error` |
| Errors | `A2L_DUPLICATE_SYMBOL` | (intra-A2L) | ERROR | `sev-error` |
| Errors | `TRIPLE_NAME_ADDRESS_MISMATCH` | X-007.1-d | ERROR | `sev-error` |
| Errors | `MAC_DUPLICATE_ADDRESS` (classification="hard conflict") | X-007.1-g escalation | ERROR | `sev-error` |
| Warnings | `CROSS_MAC_S19_OUT_OF_RANGE` | X-007.1-c | WARNING | `sev-warning` |
| Warnings | `CROSS_A2L_S19_OUT_OF_RANGE` | X-007.1-b | WARNING | `sev-warning` |
| Warnings | `CROSS_MAC_S19_OVERLAP_AMBIGUOUS` | (S19-overlap aware MAC) | WARNING | `sev-warning` |
| Warnings | `CROSS_A2L_S19_OVERLAP_AMBIGUOUS` | (S19-overlap aware A2L) | WARNING | `sev-warning` |
| Warnings | `CROSS_MAC_ONLY_SYMBOL` | X-007.1-e | WARNING | `sev-warning` |
| Warnings | `CROSS_A2L_ONLY_SYMBOL` | X-007.1-f | WARNING | `sev-warning` |
| Warnings | `MAC_DUPLICATE_ADDRESS` (alias/bitfield/segment) | X-007.1-g | WARNING | `sev-warning` |
| Warnings | `A2L_UNRECOGNIZED_BLOCK` | (intra-A2L extra) | WARNING | `sev-warning` |
| **Drift** | `A2L_BROKEN_REFERENCE` | (intra-A2L) | **WARNING in code** but **Errors in REQUIREMENTS.md** | `sev-warning` (code-driven) |
| Optional info | `MAC_DUPLICATE_ADDRESS` (under `alias_policy="allow"`) | X-007.1-g | INFO | `sev-info` |

### 7.2 Severity per alias policy (cross-policy matrix for `MAC_DUPLICATE_ADDRESS` only)

`MAC_DUPLICATE_ADDRESS` is the only code whose severity is alias-policy-sensitive. All other codes have a fixed severity regardless of policy.

| Classification | `"warn"` (active default) | `"error"` | `"allow"` |
|---|---|---|---|
| `alias candidate` | WARNING | **WARNING** (no policy branch — F-9.07-01) | INFO |
| `bitfield sharing` | WARNING | **WARNING** (F-9.07-01) | INFO |
| `segment ambiguity` | WARNING | **WARNING** (F-9.07-01) | INFO |
| `hard conflict` | ERROR | ERROR | ERROR |
| `valid unresolved` | INFO | INFO | INFO |

**Conclusion.** The `"error"` policy value is dead today (Finding F-9.07-01). Closing F-9.07-01 would either remove the value from the kwarg's accepted set or implement the upgrade-to-ERROR branch.

### 7.3 Implications for LLR-007.3 acceptance

LLR-007.3 acceptance asks for a matrix that documents how each class's severity changes under each alias policy. The matrix above shows:

- **15 of 16 active codes are policy-invariant.** Severity is fixed by `model.py` / `engine.py` / `rules.py` constants.
- **1 code (`MAC_DUPLICATE_ADDRESS`) is policy-variant**, but only the `"allow"` branch is observable; the `"error"` branch is dead.
- **Drift on 1 code** (`A2L_BROKEN_REFERENCE`): policy-invariant in code (always WARNING), but REQUIREMENTS.md tier policy says it should be ERROR. Already filed as F-9.03-02.

---

## 8. LLR-008.1 — Forward direction code → rule → test (TC-071)

Acceptance: every `ValidationIssue.code` literal that exists in `s19_app/validation/rules.py` or `s19_app/validation/engine.py` is mapped to its emitting rule symbol and to at least one asserting test in `tests/`.

Codes enumerated by direct grep of `s19_app/validation/`:

| `ValidationIssue.code` | Severity (in code) | Emitting rule (file:line) | Asserting test(s) | Verdict |
|---|---|---|---|---|
| `MAC_PARSE_ERROR` | ERROR | `rules.py:318` (`validate_mac_records`) | `tests/test_validation_engine.py::TestCrossFileCompatibilityCoEmission::test_tc_062_h_*`; `tests/test_validation_mac.py::test_validate_mac_records_reports_parse_and_empty_fields` | confirmed |
| `MAC_EMPTY_NAME` | ERROR | `rules.py:331` (`validate_mac_records`) | `tests/test_validation_mac.py::test_validate_mac_records_reports_parse_and_empty_fields` | confirmed |
| `MAC_INVALID_ADDRESS` | ERROR | `rules.py:341` (`validate_mac_records`) | `tests/test_validation_mac.py::test_validate_mac_records_reports_parse_and_empty_fields` | confirmed |
| `MAC_DUPLICATE_NAME` | ERROR | `rules.py:358` (`validate_mac_records`) | `tests/test_validation_mac.py::test_validate_mac_records_duplicate_name_remains_hard_error` | confirmed |
| `MAC_DUPLICATE_ADDRESS` | WARNING / ERROR / INFO (classification + policy dependent) | `rules.py:377` (`validate_mac_records`); severity via `rules.py:244` (`classification_to_severity`) | `tests/test_validation_mac.py::test_validate_mac_records_detects_duplicate_address_alias_candidate`, `test_validate_mac_records_duplicate_address_hard_conflict_from_a2l`, `test_validate_mac_records_duplicate_address_info_when_allow_policy`; `tests/test_validation_engine.py::test_tc_062_g_*`, `test_validate_artifact_consistency_escalates_duplicate_address_hard_conflict` | confirmed |
| `A2L_STRUCTURE_ERROR` | ERROR | `rules.py:444` (`validate_a2l_structure`) | indirect via `tests/test_color_policy_round_trip.py::test_validate_artifact_consistency_round_trip_on_large_project` (large_project triggers structure errors); `tests/test_tui_a2l.py::test_parse_a2l_file_extracts_nested_measurement_and_characteristic_tags` exercises the parse-error path | confirmed (no direct `assert "A2L_STRUCTURE_ERROR" in codes` — covered indirectly) |
| `A2L_INVALID_ADDRESS` | ERROR | `rules.py:463` (`validate_a2l_structure`) | none with direct code-string match (covered indirectly via `large_project` round-trip in `test_color_policy_round_trip.py`) | drift (minor) — F-9.03-01 (filed in §3) |
| `A2L_DUPLICATE_SYMBOL` | ERROR | `rules.py:474` (`validate_a2l_structure`) | `tests/test_validation_a2l.py::test_validate_a2l_structure_detects_unrecognized_and_duplicate_symbols` | confirmed |
| `A2L_UNRECOGNIZED_BLOCK` | WARNING | `rules.py:487` (`validate_a2l_structure`) | `tests/test_validation_a2l.py::test_validate_a2l_structure_detects_unrecognized_and_duplicate_symbols` | confirmed |
| `A2L_BROKEN_REFERENCE` | WARNING **(drift vs. REQUIREMENTS.md `Errors`)** | `rules.py:507` (`validate_a2l_structure`) | `tests/test_validation_a2l.py::test_validate_a2l_structure_detects_broken_references` | drift (severity) — F-9.03-02 |
| `CROSS_MAC_S19_OUT_OF_RANGE` | WARNING | `engine.py:90` (`validate_artifact_consistency`) | `tests/test_validation_engine.py::test_tc_062_c_*`; `tests/test_tui_app.py::test_tc_065_c_*` | confirmed |
| `CROSS_MAC_S19_OVERLAP_AMBIGUOUS` | WARNING | `engine.py:102` (`validate_artifact_consistency`) | `tests/test_tui_services.py:49` | confirmed |
| `CROSS_A2L_S19_OUT_OF_RANGE` | WARNING | `engine.py:128` (`validate_artifact_consistency`) | `tests/test_validation_engine.py::test_tc_062_b_*`; `tests/test_tui_app.py::test_tc_065_b_*` | confirmed |
| `CROSS_A2L_S19_OVERLAP_AMBIGUOUS` | WARNING | `engine.py:140` (`validate_artifact_consistency`) | `tests/test_validation_engine.py:39` (`test_validate_artifact_consistency_reports_cross_mismatches`) | confirmed |
| `TRIPLE_NAME_ADDRESS_MISMATCH` | ERROR | `engine.py:163` (`validate_artifact_consistency`) | `tests/test_validation_engine.py::test_tc_062_d_*`; `tests/test_tui_app.py::test_tc_065_d_*` | confirmed |
| `CROSS_MAC_ONLY_SYMBOL` | WARNING | `engine.py:177` (`validate_artifact_consistency`) | `tests/test_validation_engine.py::test_tc_062_e_*`; `tests/test_tui_app.py::test_tc_065_e_*` | confirmed |
| `CROSS_A2L_ONLY_SYMBOL` | WARNING | `engine.py:188` (`validate_artifact_consistency`) | `tests/test_validation_engine.py::test_tc_062_f_*`; `tests/test_tui_app.py::test_tc_065_f_*` | confirmed |
| `CROSS_S19_HEX_OVERLAP` (recommended; not yet emitted) | recommend WARNING | not in code (F-7.2-01) | `tests/test_validation_engine.py:229` (xfail); `tests/test_tui_app.py:1915` (xfail) | xfail — F-7.2-01 |

**Code count.** 17 codes emitted by code today + 1 recommended (`CROSS_S19_HEX_OVERLAP`). 15 confirmed; 1 minor drift (`A2L_INVALID_ADDRESS` indirect-only); 1 severity drift (`A2L_BROKEN_REFERENCE`); 1 xfail (`CROSS_S19_HEX_OVERLAP`).

---

## 9. LLR-008.2 — Reverse direction rule → code → severity (TC-072)

Acceptance: every rule function in `s19_app/validation/rules.py` and `s19_app/validation/engine.py` is mapped to the codes it emits and the severity assigned to each, and that severity is checked against `REQUIREMENTS.md` §Issues Tile Severity Policy (where the policy applies).

| Rule function (file:line) | Emitted code(s) | Severity assigned (in code) | Matches REQUIREMENTS.md tier? | Notes |
|---|---|---|---|---|
| `rules.py::validate_mac_records` (line 279) | `MAC_PARSE_ERROR` | ERROR | ✅ Errors | — |
|  | `MAC_EMPTY_NAME` | ERROR | ✅ Errors | — |
|  | `MAC_INVALID_ADDRESS` | ERROR | ✅ Errors | — |
|  | `MAC_DUPLICATE_NAME` | ERROR | ✅ Errors | — |
|  | `MAC_DUPLICATE_ADDRESS` | WARNING / ERROR / INFO via `classification_to_severity` | ✅ Warnings (alias/bitfield/segment) / Errors (hard conflict) / Optional info (`allow` policy) | severity branches by classification + policy |
| `rules.py::collect_mac_duplicate_address_groups` (line 78) | (no codes — pure data assembly) | n/a | n/a | helper |
| `rules.py::classify_mac_duplicate_group` (line 186) | (no codes — returns classification string) | n/a | n/a | feeds `classification_to_severity` |
| `rules.py::classification_to_severity` (line 244) | (no codes — returns severity) | maps classification → ValidationSeverity | ✅ for hard/alias/bitfield/segment/valid-unresolved; ❌ for `"error"` policy value (no branch — F-9.07-01) | dead alias-policy value `"error"` |
| `rules.py::validate_a2l_structure` (line 412) | `A2L_STRUCTURE_ERROR` | ERROR | ✅ Errors | — |
|  | `A2L_INVALID_ADDRESS` | ERROR | ✅ Errors | — |
|  | `A2L_DUPLICATE_SYMBOL` | ERROR | ✅ Errors | — |
|  | `A2L_UNRECOGNIZED_BLOCK` | WARNING | ⚠ extra (REQUIREMENTS.md does not enumerate this rule in any tier; emission stands but not policy-anchored) | F-9.09-01 — extend REQUIREMENTS.md to enumerate `A2L_UNRECOGNIZED_BLOCK` under Warnings |
|  | `A2L_BROKEN_REFERENCE` | WARNING | ❌ DRIFT — REQUIREMENTS.md tier = Errors | F-9.03-02 (severity drift) |
| `engine.py::validate_artifact_consistency` (line 21) | `CROSS_MAC_S19_OUT_OF_RANGE` | WARNING | ✅ Warnings | — |
|  | `CROSS_MAC_S19_OVERLAP_AMBIGUOUS` | WARNING | ✅ Warnings (overlap ambiguity) | — |
|  | `CROSS_A2L_S19_OUT_OF_RANGE` | WARNING | ✅ Warnings | — |
|  | `CROSS_A2L_S19_OVERLAP_AMBIGUOUS` | WARNING | ✅ Warnings (overlap ambiguity) | — |
|  | `TRIPLE_NAME_ADDRESS_MISMATCH` | ERROR | ✅ Errors (A2L↔MAC name/address mismatch) | — |
|  | `CROSS_MAC_ONLY_SYMBOL` | WARNING | ✅ Warnings (symbol-only-in-MAC) | — |
|  | `CROSS_A2L_ONLY_SYMBOL` | WARNING | ✅ Warnings (symbol-only-in-A2L) | — |
| `model.py::_scrub_issue_message` (line 25) | (no codes; sanitiser) | n/a | n/a | invoked by `ValidationIssue.__post_init__` |
| `model.py::ValidationIssue.__post_init__` (line 131) | (no codes; sanitises `self.message`) | n/a | n/a | LLR-002.3 closure |
| `model.py::CoverageMetrics.*` (line 140) | (no codes; metrics) | n/a | n/a | LLR-009.2 closure |

**Reverse-direction roll-up.**

- **8 rule-emission paths** (5 in `validate_mac_records`, 5 in `validate_a2l_structure`, 7 in `validate_artifact_consistency`) totalling 17 distinct codes — same set as §8.
- **15 / 17 codes match the REQUIREMENTS.md tier policy.**
- **1 severity drift** (`A2L_BROKEN_REFERENCE`) — F-9.03-02.
- **1 extra-rule** (`A2L_UNRECOGNIZED_BLOCK`) not enumerated by REQUIREMENTS.md — F-9.09-01.
- **1 dead-policy-value** in `classification_to_severity` — F-9.07-01.

---

## 10. Phase 3 closure — what's left for Phase 4

### 10.1 Findings raised in this increment

Five new Findings, all minor or doc-only. None blocking for Phase 4 entry.

| ID | Target | Observation | Severity | Recommended fix |
|---|---|---|---|---|
| **F-9.01-01** | `REQUIREMENTS.md` (Reading / Parsing / Validation / Intel HEX sections) | `tests/test_hexfile.py` covers ≥9 Intel HEX rules (checksum mismatch, length mismatch, unsupported record type, missing prefix, parse error, invalid extended-segment length, invalid extended-linear length, data-record-without-extended-address, missing-file) that have no `R-HEX-*` (or `R-VAL-*`) row in REQUIREMENTS.md. Tests are real but rules are doc-orphaned. | minor (doc) | Add `R-HEX-004` … `R-HEX-012` rows (or fold under existing R-VAL-001/002 with cross-references to the Intel HEX symbols). |
| **F-9.02-01** | `REQUIREMENTS.md` (no MAC parser section) | MAC parser (`s19_app/tui/mac.py::parse_mac_file`) is core behaviour: parses `TAG=hexaddr` lines, emits diagnostics, populates `parse_ok` / `parse_error` per record. No `R-MAC-*` row exists. Test coverage is indirect (`tests/test_tui_mac.py` only asserts log emission; semantic coverage is via downstream engine tests). | minor (doc + test) | Add `R-MAC-001..00N` rows mirroring R-A2L-001..N style; add a direct `tests/test_tui_mac.py::test_parse_mac_file_*` suite for malformed hex / empty name / duplicate address / blank-line-handling. |
| **F-9.02-02** | `R-A2L-003`, `R-A2L-004` | Both rows are `Manual` and rely on a keybinding (action) flow. No automated subprocess/dialog assertion exists. Increment 6 indirectly covered the parse + view path; the keypress+modal flow is still un-asserted. | minor | Either accept as Manual (log a manual gate run in `04-validation.md` for Phase 4) or add a Textual `Pilot.press(...)` test that fires the binding and asserts the dialog opens. |
| **F-9.02-03** | `REQUIREMENTS.md` (A2L Structural Parsing / RECORD_LAYOUT / Raw Memory Extraction / COMPU_METHOD / Output API sections) | These five sections are written as prose with bullet lists but contain no `R-*` numbering. Tests cover the behaviour, but per-row traceability is impossible. | minor (doc) | Number the prose-only rules as `R-A2L-008..R-A2L-NN` (or new `R-DEC-*` / `R-EXT-*` / `R-CONV-*` / `R-API-*` series). |
| **F-9.03-01** | `s19_app/validation/rules.py::validate_a2l_structure` (line ~463) → `A2L_INVALID_ADDRESS` emission | Code emits `A2L_INVALID_ADDRESS` at ERROR but no test in `tests/` asserts the code-string by direct match. Coverage is indirect (`large_project` round-trip). A regression that silently changed the code string would not be caught by an explicit assertion. | minor | Add a direct unit test in `tests/test_validation_a2l.py` with a synthetic A2L payload whose tag has a non-int address; assert `"A2L_INVALID_ADDRESS"` is in the emitted codes. |
| **F-9.03-02** | `s19_app/validation/rules.py::validate_a2l_structure` (line ~507) — `A2L_BROKEN_REFERENCE` severity | Code emits at WARNING; REQUIREMENTS.md §Issues Tile Severity Policy lists "broken GROUP/FUNCTION references" under **Errors**. Severity policy / code drift. | minor (severity) | Either upgrade the rule to `ValidationSeverity.ERROR` (closer to REQUIREMENTS.md), or downgrade the REQUIREMENTS.md text to Warnings. The rule-emission line + the doc bullet must agree; pick one. |
| **F-9.04-01** | `s19_app/tui/app.py:2716` — `parse_mac_file(path)` direct call | MAC load path bypasses the `tui/services/` layer that S19/HEX/A2L use. No `mac_service` exists. | minor (architecture) | Add `s19_app/tui/services/mac_service.py::build_loaded_mac(path)` mirroring the load-service shape; route the bypass through it. |
| **F-9.04-02** | `s19_app/tui/app.py:3158` — direct `S19File(...).get_overlap_addresses()` call | Overlap-set extraction is the only piece of the validation pipeline not encapsulated in `validation_service.build_validation_report`. | minor (architecture) | Fold the overlap-set fetch into `validation_service.build_validation_report` — pass `primary_path` and let the service compute the overlap. App.py would then call only `build_validation_report`. |
| **F-9.04-03** | `s19_app/tui/app.py:3902` — `parse_a2l_file(path)` direct call | A2L cache lookup is implemented in `app.py` (lines ~3895–3905) rather than in `a2l_service`. | minor (architecture) | Move `(_a2l_cache_key, _a2l_cache_data, _load_a2l_data_cached)` into `a2l_service.parse_and_cache(path, cache)`. App.py keeps only the cache state container. |
| **F-9.07-01** | `s19_app/validation/rules.py::classification_to_severity` (line ~244) | Function accepts an `alias_policy` kwarg that documents `allow` / `warn` / `error`. Only `"allow"` has a behavioural branch; `"warn"` and `"error"` collapse to identical severities (WARNING for non-conflicts). The `"error"` alias-policy value is therefore dead. | minor (API) | Either implement an `"error"` branch that escalates `alias candidate` / `bitfield sharing` / `segment ambiguity` to ERROR, or remove `"error"` from the documented value set and update LLR-007.3 acceptance text accordingly. |
| **F-9.09-01** | `REQUIREMENTS.md` §Issues Tile Severity Policy | `A2L_UNRECOGNIZED_BLOCK` is emitted at WARNING by `validate_a2l_structure` line ~487, but no Issues tier in the policy mentions "unrecognised A2L block". Code is correct; policy doc is incomplete. | minor (doc) | Add "unrecognised A2L block" to the Warnings tier list. |

### 10.2 Open carry-through Findings (from earlier increments)

| ID | Increment | Severity | Status |
|---|---|---|---|
| F-7.2-01 | 5 | major (engine gap) | open — pending follow-up batch |
| F-7.2-02 | 5 | minor (engine partial coverage) | open — pending follow-up batch |
| F-7.7-02 | 7 | minor (sanitiser reserved-name) | open — pending follow-up batch |
| F-7.7-03 | 7 | minor (sanitiser length cap) | open — pending follow-up batch |
| F-7.7-04 | 7 | minor (sanitiser Unicode confusables) | open — pending follow-up batch |
| F-7.7-05 | 7 | minor (validate_project_files symlink) | open — pending follow-up batch |
| F-7.7-06 | 7 | minor (REQUIREMENTS.md per-tag/bulk-validator drift) | open — pending follow-up batch |
| F-7.7-07 | 7 | major (validate_characteristic merge order) | open — pending follow-up batch |

### 10.3 Open deferrals (doc-only / iteration)

- **A-N04 / Q-N02 doc-edit** (TC-090 → TC-090.a/b renumber + LLR-002.x renumber to TC-015) — fold into Phase 6 docs sweep or a Phase-1 light iteration.
- **Q-N01 — TC-047 NTFS-junction Windows manual run** — captured in increment 1 §4 on the local Windows host; needs to be re-executed on the canonical Windows host of record before the Phase 4 close gate.
- **Linux-CI portion of TC-044/045/046** — append the Linux pytest output to `increment-001.md` §6 once the next CI run completes.

### 10.4 Items that DO need code/test work in Phase 4 or later (outside this batch's scope)

| Item | Source Finding | Recommendation |
|---|---|---|
| Add `CROSS_S19_HEX_OVERLAP` engine code + rule | F-7.2-01 | follow-up batch (engine change) |
| Pipe S19 + A2L parse-time errors into the engine | F-7.2-02 | follow-up batch (engine change) |
| Tighten `sanitize_project_name` (3 finding fixes in one PR) | F-7.7-02/03/04 | follow-up batch (workspace change) |
| Reject symlinks in `validate_project_files` | F-7.7-05 | follow-up batch (workspace change) |
| Reconcile `schema_ok / memory_checked / in_memory` location | F-7.7-06 | doc edit OR API change |
| Fix `validate_characteristic` merge order | F-7.7-07 | one-line product fix + remove xfail |
| Direct unit test for `A2L_INVALID_ADDRESS` | F-9.03-01 | one new test case |
| Resolve `A2L_BROKEN_REFERENCE` severity drift | F-9.03-02 | either code or doc edit |
| Service-layer symmetry (MAC + overlap + A2L cache) | F-9.04-01/02/03 | refactor batch |
| Implement or remove `alias_policy="error"` | F-9.07-01 | API fix |
| Number prose-only A2L/MAC/Intel-HEX rules | F-9.01-01, F-9.02-01, F-9.02-03, F-9.09-01 | REQUIREMENTS.md edit |

### 10.5 Phase 3 close recommendation

All 9 inspection-method LLRs now have audit matrices. Combined with increments 1–8 (which automated the 17 testable LLRs in the batch) the audit deliverable is **complete for Phase 3**. New Findings F-9.01-01 through F-9.09-01 (10 items, all minor or doc) plus the 8 carry-through Findings are queued for Phase 4 / follow-up batches and are individually scoped (each ≤5 files).

Recommendation: move to **Phase 4 (qa-reviewer validation execution)** against `.dev-flow/05-acceptance.md`. The pytest baseline carrying into Phase 4 is **259 passed / 2 skipped / 3 xfailed / 0 failed**, with the manual Windows-only TC-047 run captured in `increment-001.md` §4 awaiting Phase 4 sign-off on the canonical Windows host.
