# Traceability Matrix — batch-58 (CRC Algorithm Designer, Variant B view + engine E4/E5/E6)

Dual traceability: **US → AT (black-box)** and **US → HLR → LLR → TC (white-box)**. No gaps. (Detail + node reconciliation in `04-validation.md`.)

## Behavioral (Layer B): US → AT → on-disk node (all PASS)
| US | Story | AT | Collected node (`tests/`) |
|---|---|---|---|
| US-E4 | big-endian/wider word codec | AT-CRC-DSN-014 | `test_crc_word_codec.py::test_at_crc_dsn_014_encode_word_endianness` |
| US-E5 | template loader facade | AT-CRC-DSN-015 (engine) | `test_crc_template_loader.py::test_collect_dont_abort_malformed_json` |
| US-E6 | job up-converter + emit_job | AT-058-01, AT-CRC-DSN-012, AT-CRC-DSN-010 | `test_crc_job_upconvert.py::{test_at_058_01_flat_upconvert_round_trips_through_emit_job, test_at_crc_dsn_012_template_round_trip_is_identical, test_llr_e6_1_upconvert_digest_matches_compute_group_crc_semantics}` |
| US-V1 | form + preset | AT-058-02 | `test_crc_designer_view.py::test_form_and_preset_populates_off_seed_without_mutating_catalogue` |
| US-V2 | live KAT verdict | AT-CRC-DSN-011, AT-CRC-DSN-016 | `…::test_live_verdict_every_preset_reads_match`, `…::test_live_verdict_transitions_on_single_field_events` |
| US-V3 | custom vector | AT-058-03 | `…::test_custom_vector_ascii_and_hex_reproduce_kat` |
| US-V4 | JSON preview round-trip | AT-058-04 | `…::test_json_preview_roundtrips_through_mounted_widget` |
| US-V5 | Load/Save + KAT + markup | AT-058-05, AT-058-06, AT-CRC-DSN-015 (view), AT-058-10 | `…::{test_save_then_load_roundtrip_through_view, test_hostile_template_renders_literally_at_preview, test_load_malformed_file_surfaces_one_error, test_three_warn_conditions_through_view}` |
| US-V6 | coverage + per-policy preview | AT-CRC-DSN-013, AT-CRC-DSN-013b, AT-058-07 | `…::{test_coverage_single_range_skip_equals_region_crc, test_coverage_preview_shows_both_policy_oracles}` |
| US-V7 | gap-conflict | AT-CRC-DSN-017, AT-058-08 | `…::test_gap_conflict_clean_previews_dirty_abort_refuses` |
| US-V8 | preview-only guard | AT-058-09 | `…::test_preview_only_mem_map_unchanged` |

19 ATs → 17 distinct nodes (013b/058-07 and 017/058-08 each = one behavioral claim → one node; C-18 holds, 0 unrealized).

## Functional (Layer A): HLR → LLR → TC
| HLR | LLR | Verifying tests |
|---|---|---|
| HLR-E4 | E4.1/.2/.3 | `test_crc_word_codec.py` (13 cases) |
| HLR-E5 | E5.1/.2 | `test_crc_template_loader.py` (6) |
| HLR-E6 | E6.1/.2/.3 | `test_crc_job_upconvert.py` (13) |
| HLR-V1 | V1.1/.2 | `test_crc_designer_view.py` + `test_tui_directionb.py` rail census |
| HLR-V2 | V2.1/.2 | `test_crc_designer_view.py` (verdict + fault guard) |
| HLR-V3 | V3.1 | `test_crc_designer_view.py` (custom vector) |
| HLR-V4 | V4.1 | `test_crc_designer_view.py` (JSON preview) |
| HLR-V5 | V5.1/.2/.3/.4 | `test_crc_designer_view.py` (Load/Save/warns/markup) |
| HLR-V6 | V6.1/.2 | `test_crc_designer_view.py` (coverage/preview) |
| HLR-V7 | V7.1 | `test_crc_designer_view.py` (gap-conflict) |
| HLR-V8 | V8.1 | `test_crc_designer_view.py` (preview-only) |

All 22 LLRs → ≥1 passing test. 0 orphan tests, 0 requirement without a verifier.

## Gate-run evidence
`pytest -m "not slow" -k "not tc031" --ignore=test_engine_unchanged.py` → 1757 passed + 4 census-fix (b809c98) + 19 EXPECTED snapshot rail-drift (canonical-CI regen). Frozen static-check: 0 frozen paths touched. Full detail: `04-validation.md`.
