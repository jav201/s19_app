# batch-57 — Traceability matrix

Dual traceability: behavioral `US → AT` (black-box, through the shipped headless surface) AND
functional `HLR/LLR (E-item) → TC` (white-box). All nodes on disk in `tests/test_crc_kernel.py` /
`tests/test_crc_designer_model.py` (commit `1341fd3`).

| US | Outcome (WHAT) | Engine item (HOW) | AT / TC node (on disk) |
|----|----|----|----|
| US-CRC1 | A designed variant is provably correct vs the `"123456789"` KAT | E1 `crc_stream` / E2 KAT | `test_every_preset_reproduces_its_catalogue_check` (AT-CRC-DSN-011) · `test_seed_algorithm_equals_zlib_crc32_over_many_vectors` (AT-CRC-DSN-010) · `test_kat_ok_*` |
| US-CRC2 | Multi-range coverage with two independent gap levels | E3 `gather_target` / E4 `store_word` | `test_join_concat_matches_group_behavior_oracle` + `test_join_fill_pads_between_ranges_oracle` (AT-CRC-DSN-013b) · `test_declared_range_order_is_authoritative` · `test_store_word_*` (AT-CRC-DSN-014) |
| US-CRC3 | No silent divergence: refuse a CRC over a wrongly-assumed-empty gap | E8 `gap_conflict` + `evaluate_target` | `test_gap_conflict_*` (AT-CRC-DSN-017) · `test_evaluate_target_aborts_on_conflict` (AT-E8-abort) · `test_evaluate_target_warn_proceeds_with_diagnostic` (AT-E8-warn) · `test_evaluate_target_ignore_is_silent` · `test_evaluate_target_clean_computes_under_every_policy` |
| US-CRC4 | Fast enough for MB-scale firmware (LUT), result unchanged | E7 `crc_lut` / `make_crc_table` | `test_lut_matches_bitwise_oracle_over_presets_and_random_vectors` (TC-E7-LUT) · `test_lut_matches_oracle_for_non_catalogue_refin_ne_refout` · `test_compute_routes_through_lut_and_preserves_kat` · `test_crc_table_is_cached_per_width_poly` |
| (loader) | Malformed template/job → one error, never a crash | E5 `read_template`/`parse_*` | `test_parse_template_collects_faults_without_raising` · `test_parse_job_reports_unknown_ref_and_bad_targets` · `test_read_template_faults_are_collected` · `test_invalid_on_gap_conflict_is_one_collected_error` |
| (round-trip) | Template saved then loaded is identical | E5 `emit_template` | `test_template_round_trips_through_json` · `test_read_template_round_trips_a_written_file` |

**Gaps:** none within batch-57 scope. Deferred to batch-58 (documented, not gaps here): the Variant B
TUI view (R-CRC-DSN-001/002/008/009), E6 legacy up-converter, `emit_job`, wiring the width-general
kernel into the shipped `crc.py` operation.

**Coverage:** every batch-57 US → ≥1 AT through the headless surface; every E-item → ≥1 TC. Zero orphans.
