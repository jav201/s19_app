# Inc 8 — E4 tester notes

Owner: E4 independent tester. Deliverables: the two new test files
(`tests/test_b101_crc_model_and_reasons.py` = G1, `tests/test_b101_flow_ext_copy.py`
= G2), the re-pinned existing tests (none — see §2), the RED proof on base, and
the tests-column update of `02-test-cases.md`. No source file was edited. Nothing
committed.

## 1. Test → case mapping

Naming: `test_<row-id-lowercased-with-underscores>_<n>_<short>`; parametrized
families carry the case in the param id. Full = the product itself produces the
asserted value (black box through public engines / run_flow / the TUI pilot).
Partial = the test pins one clause of the case and another test pins the rest.

### G1 — `tests/test_b101_crc_model_and_reasons.py`

| Case | Test | Full/partial |
|---|---|---|
| R-CRC-ENGINE-001.1/1 | `test_r_crc_engine_001_1_1_reverse_takes_init_as_given` | full (product `crc32_stream`) |
| /2 | `test_r_crc_engine_001_1_2_bit_reversed_inits_stay_distinct` | full |
| /3, /4 | `test_r_crc_engine_001_1_catalogue_32_bit_checks[MPEG-2, JAMCRC]` | full |
| /5 | `test_r_crc_engine_001_1_5_operations_check_gives_model_value` | full (the shipped `check_regions` call) |
| /6 | `test_r_crc_engine_001_1_6_operations_write_stores_model_value` | full (the shipped `write_crc_image` route; file read back) |
| /7 | `test_r_crc_engine_001_1_7_flow_crc_block_injects_model_value` | full (run_flow end to end) |
| R-CRC-ENGINE-002.2/1 | `test_r_crc_engine_002_2_1_operation_equals_designer_grid` | full (24/24) |
| /2 | `test_r_crc_engine_002_2_2_operation_equals_designer_random` | full (50/50, seed 7) |
| R-CRC-DESIGNER-001.1/1–/6 | `test_r_crc_designer_001_1_catalogue_checks[ARC, MODBUS, RIELLO, TMS37157, ISO-HDLC, MPEG-2]` | full (the cited oracle row) |
| R-CRC-CONFIG-001.10/1–/8 | `test_r_crc_config_001_10_missing_field_is_named[reverse, polynomial, init, final_xor, region-start, group-output_address, group-regions, span-end]` | full (exact one-error lists) |
| R-CRC-CONFIG-001.11/1–/6 | `test_r_crc_config_001_11_non_number_is_named[init-zz, init-true, polynomial-1.5, final_xor-null, region-end, span-start]` | full (value as JSON text — the new spelling; the base/raw Python-repr spelling `'zz'` is exactly what these tests must NOT show, which is the RED clause on base) |
| /7 | `test_r_crc_config_001_11_7_value_is_clipped` | full — **[N-1]** the case's /7(a) oracle in `02-test-cases.md` line 42 still says `a` × 1 000 000, which the E3 round-2 ruling N-1 proved is a number under the designed grammar (a probe on base parses it, `init.bit_length() == 4000000`). The test follows the ruling: `z` × 1 000 000 → `"` + 63 × `z` + `…`. **The 02 row text was left untouched (tests column only)** — the requirements session should correct the case oracle to match ruling N-1. |
| /8 | `test_r_crc_config_001_11_8_markup_value_shown_plain` | full, through keys (Textual pilot; the `[/]` value asserted verbatim as plain text, no hex view) |
| R-CRC-CONFIG-001.16/1–/3 | `test_r_crc_config_001_16_designer_template_is_named[saved, width16, algorithm-not-object]` | full (`saved` = `emit_template(seed_template())`) |
| /4 | `test_r_crc_config_001_16_4_config_with_algorithm_key_still_parses` | full |
| /5 | `test_r_crc_config_001_16_5_operations_dialog_names_template` | full, through keys (Load config + Execute) |
| R-CRC-CONFIG-001.17/1 | `test_r_crc_config_001_17_1_deep_nesting_is_a_reason` | full (parse returns the reason, no raise) |
| /2 | `test_r_crc_config_001_17_2_operations_execute_survives_deep_nesting` | full, through keys (result area + a later key still acts) |

### G2 — `tests/test_b101_flow_ext_copy.py`

Flow-X fixture and `Doc(v)` are exactly the `02-test-cases.md` common fixtures.
The block "cause" is asserted as the LAST diagnostics line (UX-C2, the
user-facing cause), per the shipped `_record_error` form.

| Case | Test | Full/partial |
|---|---|---|
| R-FLOW-EXT.2/1 | `test_r_flow_ext_2_1_relative_log_read_under_project` | full (positive control — holds on base by design) |
| /2 | `test_r_flow_ext_2_2_relative_output_read_under_project` | full |
| R-FLOW-EXT.9/1 | `test_r_flow_ext_9_1_later_patch_reads_this_runs_copy` | full (summaries, `in_place_reads`, out.s19 bytes) |
| /2 | `test_r_flow_ext_9_2_first_run_reads_the_plain_copy` | full (holds on base) |
| /3 | `test_r_flow_ext_9_3_reused_copy_is_read` | full (holds on base) |
| /4 | `test_r_flow_ext_9_4_later_check_block` | full (failed=1 + suffix pinned in 12/2) |
| /5 | `test_r_flow_ext_9_5_later_crc_block` | full (bytes at the NEW address, none at the old) |
| /6 | `test_r_flow_ext_9_6_later_load_block` | full (holds on base? NO — RED: base provenance/bytes differ; see §3) |
| /7 | `test_r_flow_ext_9_7_later_a2b_file_input` | full (the run-2 A2B report lists 0x00001000) |
| /8 | `test_r_flow_ext_9_8_other_refs_unchanged` | full (mixed: the rebound first PATCH is the RED clause, the second PATCH is the positive control) |
| /9 | `test_r_flow_ext_9_9_earlier_block_reads_the_file_as_it_is` | full (both change records + out.s19) |
| /10 | `test_r_flow_ext_9_10_case_insensitive_on_windows` | full, skipped off Windows |
| /11 | `test_r_flow_ext_9_11_flow_execution_confirm_reads_new_output` | full, through keys (project opened via the app's own load, lane imported via `#fx_import`, Run + `c`; `terminal_out.s19` at 0x00C001B0) |
| /12 | `test_r_flow_ext_9_12_later_a2l_ref` | full (change-record address 0x1002) |
| /13 | `test_r_flow_ext_9_13_first_run_over_a_foreign_file_reads_the_copy` | full [A-2], foreign file bytes asserted unchanged |
| /14 | `test_r_flow_ext_9_14_other_chain_is_not_rebound` | full (holds on base — the no-cross-chain positive control) |
| /15 | `test_r_flow_ext_9_15_refused_ref_stays_refused_after_rebind` | full [S-4], skipped off Windows (holds on base — the guard-order positive control) |
| R-FLOW-EXT.10/1 | `test_r_flow_ext_10_1_flow_report_names_the_copy` | full (record value + report section) |
| /2 | `test_r_flow_ext_10_2_chain_set_report_names_the_copy` | full (Not applied line, disposition-agnostic) |
| /3 | `test_r_flow_ext_10_3_unbound_ref_kept_as_typed` | full (holds on base) |
| /4 | `test_r_flow_ext_10_4_flow_report_names_the_copy_a2l_own` | full [A-1] |
| /5 | `test_r_flow_ext_10_5_flow_report_names_the_copy_a2l_inherited` | full [A-1] (record + report cell + LOAD summary suffix) |
| R-FLOW-EXT.12/1–/8 | `test_r_flow_ext_12_1_…_patch` … `test_r_flow_ext_12_8_no_suffix_without_in_place_read` | full (exact summary texts; /8 holds on base except the `in_place_reads` pin — §3) |
| /9 | `test_r_flow_ext_12_9_suffix_survives_the_raise_exit` | full [N-4] — written per the E3 round-2 ruling; **no row in `02-test-cases.md`** (the table still counts 82 cases; N-4 ordered this case but the round-2 corrective pass did not add it). |
| /10 | `test_r_flow_ext_12_10_suffix_before_the_refusal_token` | full [N-2 option (c)], skipped off Windows — asserts the summary-level contract (refusal token last + suffix present + one `[MANIFEST-PATH-ESCAPE]`). **No row in `02-test-cases.md`** for the same reason as /9. The case wording names the FX-lane ✗ line; that line is painted by unchanged `flow_screens` code whose branch condition is exactly "summary ends with the token", so the summary-level assertion covers the ruling without a fifth-source dependency. |
| R-FLOW-EXT.13/1 | `test_r_flow_ext_13_chain_set_provenance_names_the_copy` | full (outcome.inputs 2-tuple + the exact provenance line) |
| /2 | `test_r_flow_ext_13_2_unbound_input_keeps_the_base_line` | full (holds on base except the `in_place_inputs` pin — §3) |
| R-FLOW-EXT.14/1 | `test_r_flow_ext_14_climbing_path_refused_log` | full [S-3] |
| /2 | `test_r_flow_ext_14_climbing_path_refused_output` | full |
| /3 | `test_r_flow_ext_14_climbing_path_inside_accepted` | full |
| R-FLOW-EXT.11/1 | `test_r_flow_ext_11_earlier_copy_unchanged_bytes` | full (holds on base) |
| /2 | `test_r_flow_ext_11_earlier_copy_unchanged_names` | full (holds on base) |
| R-FLOW-CRC.3/1 | `test_r_flow_crc_3_missing_config_exact_text` | full (exact summary + cause; holds on base — the C-1 wording re-pin, previously unpinned) |
| R-FLOW-CRC.4/1 | `test_r_flow_crc_4_designer_template_is_named_in_the_flow` | full |
| /2 | `test_r_flow_crc_4_missing_field_is_named_in_the_flow` | full |
| /3 | `test_r_flow_crc_4_not_json_cause` | full (cause prefix; holds on base) |
| R-FLOW-CRC.9/1 | `test_r_flow_crc_9_over_limit_config_not_read` | full (cap lowered by monkeypatch, per the case) |

## 2. Existing tests ("Nodes touched" re-pin)

**None changed.** `E1-slice.md` §4 censused the base tree: no existing test pins
the old reason texts, the bare `'reverse'`, the old CRC values, or any summary
the read suffix can alter; `test_at044d_parse_rejections_one_named_error` keeps
its rule texts (group/output_bytes rules are unchanged by the design). The
existing partial/covered nodes (`test_at123…`, `test_at126…`, `test_at127a/b`,
`test_tc1804…`, `test_tc_b94_30…`, `test_crc_kernel.py` presets) keep passing
unmodified per §4 — verified indirectly: the RED run imported and exercised the
same tree and every failure names a new-behaviour clause, never an old pin.

One registry consequence: `tests/test_id_registry.py` `EXPECTED_SCANNED_TEST_FILES`
grows by 2 (E1-slice §5 says "re-measured at integration") — left to the
integration step, not edited here.

## 3. RED on base — summary

Evidence: `.dev-flow/2026-11-01-batch-101/evidence/inc-8/red-01-tester-base.txt`
(redacted; home paths and interpreter path replaced). Method per the E4 brief:
detached worktree of `e266395` (merge-base HEAD main) outside the repo, ONLY the
two new files copied in, run with that worktree as cwd, `s19_app.__file__`
printed first (points inside the temp worktree), `timeout 1800`. The worktree
was removed afterwards.

Result: **64 failed, 18 passed** in ~40 s. The 18 passes are exactly the
design's holds-on-base positive controls: 001.1/3–/4, the 6 Designer catalogue
cases, 001.16/4, EXT.2/1, EXT.9/2, /3, /14, /15, EXT.10/3, EXT.11/1–/2,
FLOW-CRC.3, FLOW-CRC.4/3. Every failure is behavioural, by family:

- D13-20 engine: wrong CRC values (base seeds the reflected init) — /1, /2,
  /5, /6, /7, 002.2/1, /2.
- D13-23 reasons: base gives the bare key / parser texts — 001.10 all,
  001.11 all (incl. the clip), 001.16/1–/3, 001.17/1.
- Through-keys ATs: the dialog shows the base texts (001.11/8, 001.16/5), and
  the deep-nesting Execute raises/does not paint the reason (001.17/2).
- F-28 in the flow: the cause ends `field 'reverse' is missing` (FLOW-CRC.4/1, /2).
- F-49/D15-17/S-3: no rebind (PATCH/CHECK/CRC/LOAD/A2B/A2L read the stale file
  or the pre-run provenance), no read suffix anywhere, relative output refused
  (EXT.2/2), no climb refusal (EXT.14 all), no read cap (FLOW-CRC.9).
- 12/8 and 13/2 additionally fail on base with `AttributeError` for the
  design's new API fields (`FlowRunResult.in_place_reads`,
  `ChainRunOutcome.in_place_inputs`, S-2/N-3) — structural on base, but the
  behavioural clauses in the same tests (no suffix / base provenance line) are
  separately pinned by 12/1 and 13/1.

Two harness bugs were caught by the RED run itself and fixed before the final
transcript (the confirmation's `log_ref`/`source_path` must carry the block's
refs verbatim for the relative-path cases; 9/15 must not assert on run 1's
`out.s19`). After the fix, EXT.2/1 and EXT.9/15 pass on base as the design
predicts.

## 4. Cases not expressible / not written

- None of the 82 cases is inexpressible. Four black-box ATs are written through
  the pilot (001.11/8, 001.16/5, 001.17/2, EXT.9/11); the rest through the
  shipped engines and `run_flow`/`run_chain_set`, which are the same surfaces
  the shipped UI calls (A-5 reachability idiom of the tree's own tests).
- EXT.9/10 and 9/15 and 12/10 skip off Windows by the case's own rule (the
  junction/case-insensitivity halves are Windows-only).
- R-FLOW-EXT.13/2 and FLOW-CRC.1/1, FLOW-EXT.2/3 keep their existing tests
  (covered rows); 13/2 got an additional full pin in G2.

## 5. Ambiguities (not resolved by reading the implementation)

1. **N-1 vs `02-test-cases.md` /7(a)**: the table's oracle (`a` × 1 000 000)
   contradicts E3 ruling N-1 (probe: base parses it as a number). The test
   follows the ruling (`z`). The row text needs the requirements session's
   correction.
2. **12/9 and 12/10 have no rows** in `02-test-cases.md` (round-2 rulings N-4 /
   N-2 ordered them after the table was last counted at 82). The tests exist
   and are named for the rows they will land on; the table needs two rows.
3. **R-FLOW-EXT.12 vs N-2(c)**: the row text says the summary ENDS with the
   suffix; ruling N-2(c) inserts the suffix BEFORE a trailing refusal/status
   token. 12/10 follows the ruling (token last). If the row text is not
   amended, 12/10 is the ruling's regression pin and the row text should be
   updated to state the placement.
4. **`cause` carrier**: the requirement rows say "summary X and cause Y"; the
   product carries the cause as the last `diagnostics` line (UX-C2, per
   `_record_error`). Tests assert `diagnostics[-1]`; if the implementer chose a
   different carrier the tests will say so.
5. **md escaping in report cells**: the case texts name plain file names
   (`step.changes_1.json`); the shipped reports escape markdown punctuation
   (Mode A). The tests assert the record fields verbatim (exact) and the report
   cells via the shipped escaper (identity on the value, escaping on the text).
6. **`test_id_registry.py`**: EXPECTED_SCANNED_TEST_FILES +2 is deferred to
   integration per E1-slice §5; E4 did not edit it.
