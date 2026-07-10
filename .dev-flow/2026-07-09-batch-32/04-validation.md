# 04 — Validation · batch-32 · CRC multi-region single-CRC groups

**BLUF.** Both validation layers executed and GREEN. Layer A: every LLR (GRP-001.1–.15,
WID-001.1–.6) has on-disk TCs (TC-201..TC-205 families) — 5 CRC-adjacent suites **105 passed → 110
after the C-18 Inc-5 reconciliation** (config 35 · engine 20 · operation 30 · operations 6 ·
tui-surface 14 + others; per-file counts in the ledger). Layer B: all **23 §5 ATs reconcile to
exactly ONE distinct on-disk node each** (C-18 table below; five in-parts realizations were caught by
this reconciliation and closed in Inc-5). Full-suite + engine-frozen evidence: run recorded at the
gate (background run; result appended below). Counterfactual evidence captured per increment
(trigger-absent stash RED ×3 + the golden double-proof vs the pre-change engine).

## Layer A — functional (white-box) TC ↔ LLR

| LLR family | TC family | Nodes (all verified on disk, all GREEN) |
|---|---|---|
| GRP-001.1/.2/.3/.14/.15 (schema) | TC-201 | `test_at044b_group_values_round_trip_hex_and_int`, `test_at044b_output_bytes_defaults_to_4_when_omitted`, `test_legacy_only_config_still_parses_with_empty_groups`, `test_at044d_parse_rejections_one_named_error[15 cases]`, `test_at044b_allowed_output_bytes_all_parse` |
| GRP-001.4/.5 + WID-001.1/.2/.4 (compute/codec) | TC-202 | `test_tc202_8_normalized_targets_order_and_widening`, `test_at045a/b/e/f`, `test_b5_adjacent_spans...`, `test_at045d_single_span_group_equals_legacy_region_crc`, `test_at045c_gap_present_bytes_only_compute_half`, `test_tc202_9/10/11` |
| GRP-001.6/.7/.8/.9/.10/.11 + WID-001.3/.5/.6 (wiring) | TC-203 | 11 nodes (`test_at047a...` … `test_at044a_legacy_gapped_golden_compat`) |
| GRP-001.12/.13 (surface/guidance) | TC-204 | `test_at047e_group_check_reaches_surface_via_handler`, `test_at047e_hostile_config_value_renders_literal`, `test_at047h_group_confirm_write_flow_and_row_text`, `test_at044e_dummy_prefill_demonstrates_both_forms` |
| C-18 reconciliation | TC-205 | `test_at045d_single_span_group_equals_legacy_end_to_end`, `test_at046a_width8_through_the_shipped_write_path`, `test_at046b_truncated_compare_matches_low_bytes`, `test_at047d_to_dict_through_a_real_mixed_run` |

## Layer B — behavioral (black-box) C-18 reconciliation: AT → single node

| AT | Single on-disk node | Counterfactual evidence |
|----|---------------------|------------------------|
| AT-044a | `test_at044a_legacy_gapped_golden_compat` | Compat pin — golden `0x156424B4` **double-proven** by the independent reviewer against the pre-change engine at origin/main `551fc77` (three-way agreement) |
| AT-044b | `test_at044b_group_values_round_trip_hex_and_int` | Inc-1 stash RED (collection error, trigger-absent) |
| AT-044c | `test_at047a_mixed_check_per_target_verdicts_and_order` (order assertions) | Inc-3 stash RED |
| AT-044d | `test_at044d_parse_rejections_one_named_error` (15 named cases) | Inc-1 stash RED |
| AT-044e | `test_at044e_dummy_prefill_demonstrates_both_forms` | Inc-4 stash RED (2 failed) |
| AT-045a/b/e/f | one node each (TC-202 names above) | Inc-2 stash RED (collection error) |
| AT-045c | `test_at045c_gap_note_names_group_and_count_legacy_stays_silent` (owns compute clause since Inc-5) | Inc-3 stash RED |
| AT-045d | `test_at045d_single_span_group_equals_legacy_end_to_end` (Inc-5; check verdict + injected bytes + CRC in one node) | RED-first per §5 (group path absent pre-batch) |
| AT-046a | `test_at046a_width8_through_the_shipped_write_path` (Inc-5; on-disk window) | Inc-2/3 stash RED |
| AT-046b | `test_at046b_truncated_compare_matches_low_bytes` (Inc-5; MATCH + warning) | Inc-3 stash RED |
| AT-046c | `test_at044b_output_bytes_defaults_to_4_when_omitted` | Inc-1 stash RED |
| AT-046d | `test_at046d_check_absent_stored_byte_tri_state_operation_half` | Inc-3 stash RED |
| AT-047a | `test_at047a_mixed_check_per_target_verdicts_and_order` | Inc-3 stash RED |
| AT-047b | `test_at047b_write_reread_groups_c12` (C-12: path-from-result, fresh `S19File`, dual oracle, widths 8+2+4) | Inc-3 stash RED |
| AT-047c | `test_at047c_group_self_overlap_warns_and_completes` (B10 1-byte boundary) | Inc-3 stash RED |
| AT-047d | `test_at047d_to_dict_through_a_real_mixed_run` (Inc-5) | Inc-3 stash RED (key absent) |
| AT-047e | `test_at047e_group_check_reaches_surface_via_handler` (+ hostile-input companion `test_at047e_hostile_config_value_renders_literal`) | Non-vacuous: mismatch fixture flips verdict; hostile payload rendered verbatim |
| AT-047f | `test_at047f_all_computes_precede_all_writes` (m-5 ordering precondition named) | Discriminating vs a compute-inject-compute loop (reviewer-verified) |
| AT-047g | `test_at047g_cross_target_overlap_distinct_warning` | Inc-3 stash RED |
| AT-047h | `test_at047h_group_confirm_write_flow_and_row_text` (real Write button + modal + on-disk oracle) | Inc-4 stash RED |

**No AT is realized "in parts"; no AT lacks a node; no node lacks an AT/TC parent.** The AT-044a
"suite passes unmodified" clause is process evidence (inspection): 0 pre-existing CRC test nodes
edited except the spec-sanctioned serializer-pin rewrite-in-place (AT-047d contract) and the Inc-1
compat-sanity test repointed when the dummy gained its demo group (both ledgered).

## Bidirectional surface-reachability matrix

| Dimension | Exercised through | Node |
|---|---|---|
| Input: groups JSON (TextArea) | shipped Execute handler | AT-047e |
| Input: hostile field value | shipped Execute handler | AT-047e-hostile |
| Input: config file path seam | unchanged (`read_crc_config` suite, pre-existing) | TC-113-family |
| Input: widths {1,2,4,8} + faults | parse + engine + operation | AT-044d/046a/b/c/d |
| Output: result rows + notes | `#operation_result_status` via handler | AT-047e/h |
| Output: emitted S19 on disk | write path + fresh re-parse | AT-047b, AT-046a, AT-047h |
| Output: JSON report | `to_dict` over a real mixed run | AT-047d |

## Methods other than test
- Inspection: §6.5 amendments recorded (REQUIREMENTS.md R-CRC-CONFIG-001 amendment note + the two
  new rows); AT-044a unmodified-suite clause (diff audit above).
- Analysis + manual (residual): RK-7 device-tool equivalence — semantics proven WIRED against
  zlib/crc32_stream oracles; the operator validates one real config against their build tool before
  trusting inject (unchanged residual from R-CRC-ENGINE-002).

## Full-suite evidence
- 5 CRC-adjacent suites: **110 passed** (final Inc-5 state; ledger below).
- Full `pytest -q -m "not slow"` + engine-frozen guards: executed at this gate (background run) —
  result: **1215 passed, 2 skipped, 3 xfailed (pre-existing), 21 deselected (slow), 31/31 snapshots
  — 0 failures** (596s). Engine-frozen guards GREEN inside the run; 0 frozen diffs.

## Ledger
`post = base − D + A`: CRC-file base 49 → **110** (A=+61 across TC-201..205, D=0, 2 rewrite-in-place
[serializer pin; legacy-only sanity repoint]). Suite total: 1191 → 1252 expected (final number
recorded from the gate run).

## Gaps
None open at this gate. Deferred (out-of-scope §7): structured group form editor; report_service
integration; per-group algorithm params; fill/pad gap semantics (Q1 alternative, on file).
