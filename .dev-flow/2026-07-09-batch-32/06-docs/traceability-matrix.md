# Traceability matrix — batch-32 · CRC multi-region single-CRC groups

**Audience:** repo maintainers / auditors. **Purpose:** prove the dual-trace chains
(US → HLR → LLR → TC and US → AT → single on-disk node) are complete with zero gaps.
Sources: `01-requirements.md` (§5 ATs, §9 decision record, §12 LLRs + fold record),
`04-validation.md` (C-18 reconciliation — authoritative Layer-B mapping), test files at
`feat/batch-32-crc-groups`. All node names below were grepped on disk (2026-07-09).

## 1. Functional chain (Layer A): US → HLR → LLR → TC

HLRs: **R-CRC-GROUP-001** (groups schema / compute / surface; traces US-044/045/047) ·
**R-CRC-WIDTH-001** (configurable output width; traces US-046). White-box TC families
TC-201..TC-205 (all GREEN; 49 base → 110 CRC-file tests).

| US | HLR | LLR | Scope (gist) | Owning AT(s) | TC family |
|----|-----|-----|--------------|--------------|-----------|
| US-044 | R-CRC-GROUP-001 | GRP-001.1 | `groups` parse → `CrcGroup`; `CrcConfig.groups` defaulted | AT-044b | TC-201 |
| US-044 | R-CRC-GROUP-001 | GRP-001.2 | at-least-one presence rule (§6.5 amendment #1) | AT-044d(a) | TC-201 |
| US-044 | R-CRC-GROUP-001 | GRP-001.3 | parse rejections: empty inner regions; bad `output_bytes`; N5 inverted span REJECT; N6 stray `output_address` REJECT | AT-044d(b,c) | TC-201 |
| US-044 | R-CRC-GROUP-001 | GRP-001.14 | span-count ceiling 4096 (security F1) | AT-044d(d) | TC-201 |
| US-044 | R-CRC-GROUP-001 | GRP-001.15 | groups-only 32-bit numeric bounds incl. output window (security F2) | AT-044d(e) | TC-201 |
| US-044 | R-CRC-GROUP-001 | GRP-001.4 | `normalized_targets` — the only ordering/widening seam (Q3) | AT-044c | TC-202 |
| US-045 | R-CRC-GROUP-001 | GRP-001.5 | one `crc32_stream` over declared-order concat; params flow; no `mem_map` mutation | AT-045a/b/e/f | TC-202 |
| US-045 | R-CRC-GROUP-001 | GRP-001.6 | per-group aggregate coverage note; legacy silent (Q4) | AT-045c, AT-044a | TC-203 |
| US-047 | R-CRC-GROUP-001 | GRP-001.7 | check per target: N-LE read, tri-state `matched`, never raises | AT-047a, AT-046d | TC-203 |
| US-047 | R-CRC-GROUP-001 | GRP-001.8 | overlap notes scoped: ≥1 group member only (F-2 fold) | AT-047c/g, AT-044a | TC-203 |
| US-047 | R-CRC-GROUP-001 | GRP-001.9 | all computes precede all writes; ranges extend `[out, out+N)` | AT-047f, AT-046a | TC-203 |
| US-047 | R-CRC-GROUP-001 | GRP-001.10 | `CrcRegionResult.output_bytes=4`; inject width from RESULT field (screens re-inject safe) | AT-047d | TC-203 |
| US-047 | R-CRC-GROUP-001 | GRP-001.11 | `to_dict` gains `output_bytes`; legacy 5 keys byte-identical | AT-047d | TC-203 |
| US-047 | R-CRC-GROUP-001 | GRP-001.12 | surface: "(N LE bytes)" parameterized; markup-safe rendering (C-17, security F4) | AT-047e/h | TC-204 |
| US-044 | R-CRC-GROUP-001 | GRP-001.13 | `DUMMY_CONFIG_TEXT` + example file gain a demo group, parse cleanly | AT-044e | TC-204 |
| US-046 | R-CRC-WIDTH-001 | WID-001.1 | `encode_le(value, width)`; `encode_le32` fixed-4 wrapper (KATs untouched) | AT-046a/b | TC-202 |
| US-046 | R-CRC-WIDTH-001 | WID-001.2 | `decode_le` length-driven inverse; `decode_le32` wrapper | AT-046a | TC-202 |
| US-046 | R-CRC-WIDTH-001 | WID-001.3 | truncation warning per target, check and write | AT-046b | TC-203 |
| US-046 | R-CRC-WIDTH-001 | WID-001.4 | `read_stored_crc_le(..., width)`; any absent byte → None/None | AT-046d, B8 | TC-202 |
| US-046 | R-CRC-WIDTH-001 | WID-001.5 | compare rule: masked equality; N=8 requires high 4 stored bytes ≡ 0 (F-6) | AT-047a | TC-203 |
| US-046 | R-CRC-WIDTH-001 | WID-001.6 | range extension `[out, out+N)` at every width via `_extend_ranges` | AT-046a, B7/B9 | TC-203 |

TC nodes per family (all verified on disk): **TC-201** `test_at044b_group_values_round_trip_hex_and_int`,
`test_at044b_output_bytes_defaults_to_4_when_omitted`, `test_legacy_only_config_still_parses_with_empty_groups`,
`test_at044d_parse_rejections_one_named_error` (15 cases), `test_at044b_allowed_output_bytes_all_parse`
(tests/test_crc_config.py). **TC-202** normalizer/codec/oracle nodes incl.
`test_tc202_8_normalized_targets_order_and_widening`, the AT-045 oracle nodes,
`test_at045d_single_span_group_equals_legacy_region_crc`, `test_at045c_gap_present_bytes_only_compute_half`
(tests/test_crc_engine.py). **TC-203** 11 wiring nodes incl. `test_at046b_truncation_note_per_narrow_width`,
`test_at046a_inject_width8_zero_extends_and_extends_ranges`, `test_at044a_legacy_gapped_golden_compat`
(tests/test_crc_operation.py). **TC-204** the 4 surface/guidance nodes (tests/test_tui_crc_surface.py +
test_crc_config.py). **TC-205** the 4 Inc-5 C-18 reconciliation nodes (tests/test_crc_operation.py).

## 2. Behavioral chain (Layer B): US → AT → single on-disk node (C-18)

Reconciled mapping from `04-validation.md` §Layer-B — **23 ATs, each realized by exactly ONE distinct
node**; five in-parts realizations were caught by the C-18 reconciliation and closed in Inc-5
(marked ⁵). Counterfactual evidence per AT is recorded in `04-validation.md`.

| US | AT | Single on-disk node | File |
|----|----|---------------------|------|
| US-044 | AT-044a | `test_at044a_legacy_gapped_golden_compat` (golden `0x156424B4`, double-proven vs pre-change engine @ `551fc77`) | tests/test_crc_operation.py |
| US-044 | AT-044b | `test_at044b_group_values_round_trip_hex_and_int` | tests/test_crc_config.py |
| US-044 | AT-044c | `test_at047a_mixed_check_per_target_verdicts_and_order` (order assertions) | tests/test_crc_operation.py |
| US-044 | AT-044d | `test_at044d_parse_rejections_one_named_error` (15 named cases) | tests/test_crc_config.py |
| US-044 | AT-044e | `test_at044e_dummy_prefill_demonstrates_both_forms` | tests/test_crc_config.py |
| US-045 | AT-045a | `test_at045a_group_crc_equals_zlib_over_declared_concat` | tests/test_crc_engine.py |
| US-045 | AT-045b | `test_at045b_declared_order_not_address_order` | tests/test_crc_engine.py |
| US-045 | AT-045c | `test_at045c_gap_note_names_group_and_count_legacy_stays_silent` ⁵ | tests/test_crc_operation.py |
| US-045 | AT-045d | `test_at045d_single_span_group_equals_legacy_end_to_end` ⁵ | tests/test_crc_operation.py |
| US-045 | AT-045e | `test_at045e_non_default_params_flow_through_group_path` | tests/test_crc_engine.py |
| US-045 | AT-045f | `test_at045f_duplicate_span_digested_each_time` | tests/test_crc_engine.py |
| US-046 | AT-046a | `test_at046a_width8_through_the_shipped_write_path` ⁵ | tests/test_crc_operation.py |
| US-046 | AT-046b | `test_at046b_truncated_compare_matches_low_bytes` ⁵ | tests/test_crc_operation.py |
| US-046 | AT-046c | `test_at044b_output_bytes_defaults_to_4_when_omitted` | tests/test_crc_config.py |
| US-046 | AT-046d | `test_at046d_check_absent_stored_byte_tri_state_operation_half` | tests/test_crc_operation.py |
| US-047 | AT-047a | `test_at047a_mixed_check_per_target_verdicts_and_order` | tests/test_crc_operation.py |
| US-047 | AT-047b | `test_at047b_write_reread_groups_c12` (C-12: path-from-result, fresh `S19File`, dual oracle, widths 8+2+4) | tests/test_crc_operation.py |
| US-047 | AT-047c | `test_at047c_group_self_overlap_warns_and_completes` (B10 1-byte boundary) | tests/test_crc_operation.py |
| US-047 | AT-047d | `test_at047d_to_dict_through_a_real_mixed_run` ⁵ | tests/test_crc_operation.py |
| US-047 | AT-047e | `test_at047e_group_check_reaches_surface_via_handler` (hostile-input companion: `test_at047e_hostile_config_value_renders_literal`) | tests/test_tui_crc_surface.py |
| US-047 | AT-047f | `test_at047f_all_computes_precede_all_writes` (m-5 ordering precondition named) | tests/test_crc_operation.py |
| US-047 | AT-047g | `test_at047g_cross_target_overlap_distinct_warning` | tests/test_crc_operation.py |
| US-047 | AT-047h | `test_at047h_group_confirm_write_flow_and_row_text` (real Write button + modal + on-disk oracle) | tests/test_tui_crc_surface.py |

Note (not gaps): AT-044c and AT-046c intentionally share their nodes with AT-047a and AT-044b
respectively — each AT still maps to exactly one node, and each shared node asserts both contracts
distinctly (C-18 allows node sharing, not in-parts realization). The AT-044a "suite passes unmodified"
clause is **inspection** evidence at the gate, not a test node (2 sanctioned rewrites-in-place ledgered).

## 3. §6.5 requirement amendments (Before/After, both landed + recorded in REQUIREMENTS.md)

| # | Requirement touched | Before | After | Landed |
|---|---------------------|--------|-------|--------|
| 1 | `crc_config` presence rule (R-CRC-CONFIG-001 note) | "field 'regions' must contain at least one region" | "at least one of 'regions' / 'groups' must be present and non-empty" | Inc-1 |
| 2 | §6.2 D-5 storage codec | "Fixed storage codec width … NOT parameterized" (LE32 only) | Parameterized per GROUP: `output_bytes ∈ {1,2,4,8}` LE; legacy regions keep fixed 4; `encode_le32`/`decode_le32` remain wrappers | Inc-2/3 |

## 4. Operator-question decision rows (Phase-0/1 record, §9 — defaults adopted under standing auth)

| Q | Decision adopted | Alternatives on file | AT(s) pinning it |
|---|------------------|----------------------|------------------|
| Q1 | Gaps in a group span: CRC covers present bytes only + mandatory per-group coverage warning | hard-fail the group; configurable pad fill | AT-045c |
| Q2 | Width set `{1,2,4,8}` LE; `<4` truncate-low + warning | reject `<4`; wider set | AT-046a/b/c, AT-044d(c) |
| Q3 | Mixed result order: legacy regions first (file order), then groups (file order) | strict interleaved file order | AT-044c |
| Q4 | Legacy regions stay SILENT on gaps (strict compat) | extend the coverage warning to legacy | AT-044a (gapped fixture, zero new notes) |

## 5. Completeness statement

Every US traces to an HLR; every HLR clause decomposes into LLRs (GRP-001.1–.15, WID-001.1–.6) each
carrying an owning AT and a GREEN TC family; every one of the 23 §5 ATs maps to exactly one on-disk
node with recorded counterfactual evidence. No orphan LLR, no orphan AT, no node without an AT/TC
parent (`04-validation.md`). **Zero gaps.**
