# Inc 10 E4 - mutant run (MU10, relevo-11)

Model claude-sonnet-5-5 (tester role). Product under test: `b103-inc10` tip `4dffe1ca` (Inc 10 integrated: the seven source files of `git diff 439860c4 4dffe1ca -- s19_app`). HT-09: every mutant ran on a COPY, a `git archive` of `4dffe1ca` (LF, with `tools/`) under the runner scratch `~/work/zq-mu10/tree`, never in the worktree; the driver restores the one mutated file from a pristine copy of `s19_app/` after each mutant. Spec and driver: `evidence-e4-mut/mutants.py` (59 mutants, one exact-once text edit each), `mu.py`, `run.sh`; results `evidence-e4-mut/results.jsonl`; transcripts of the baseline in `evidence-e4-mut/logs/`.

Method: HT-02 environment (HOME basename `<runner-home>`, `-p no:cacheprovider`, `-n 2`, `timeout 300`, `s19_app.__file__` in line 1 of the baseline transcripts). Baseline first, on the unmutated copy, one run per file: `g1_panel` 27 passed, `g1_controls` 24, `g2_arms` 23, `g2_write` 21, `g3_engine` 24, `s0_written_name` 5 = 124 passed (`logs/base-*.txt`). Per mutant the nodes of its requirement row (a file plus `-k`, the `tests` field in `mutants.py`) with `--maxfail=1`; **killed** = a selected node failed, **survived** = every selected node passed, **timeout** = rc 124. A survivor was then judged against the requirement text: a test was written (RED on the mutant, GREEN on the tree) or the mutant was argued equivalent. Host load (`uptime` on the runner) 9 to 13 during the whole run (16 cores, other workers): HT-08 noted; nothing here is a timing result, only pass/fail of deterministic nodes, and the one timeout is a hang by construction (below).

## Result

59 mutants: **52 killed by the 124 original nodes, 6 survived, 1 timeout (hang)**. Of the 6 survivors, **5 are now killed by 4 new nodes** (`tests/test_b103_inc10_mu_survivors.py`, 3 tests, 4 nodes; 4 passed on the tree, `logs/green-mu_survivors.txt`) and **1 is equivalent** (MU26h). Final: **57 killed + 1 timeout (hang, MU24c) + 1 equivalent = 59**; no survivor left unexplained.

The mutants the I10 record named: MU13b (Format chip back to `width: 17`) fails both `test_r_pe_export_7_2_...` and `test_r_pe_export_9_2_...` (run without `--maxfail`; painted `Format: Intel`), as required; MU26a (first render returned) fails `..._a_numbered_written_name_wins_over_the_typed_one`; MU26b (header built from the typed name) fails the typed-path parameters; MU07a..e (the stage hide dropped, one arm per mutant: Add, Edit, Remove, per-entry JSON edit, staging-sheet stage) each fail their own R-PE-EXPORT.17 node.

## Mutant table

Result column: killed = by an original node; "survived, then killed by the new test" = the node named is the new one. Ids with a letter are variants of the same row; the edit itself is the `old`/`new` pair of the id in `evidence-e4-mut/mutants.py`.

| Id | Requirement / what the mutant does | Result | First failing node (file::test) |
|---|---|---|---|
| MU01 | R-CHG-003.1 | killed | `g1_panel::test_r_chg_003_1_the_prompt_is_shown_whichever_tab_was_shown[R-CHG-003.1/3]` |
| MU02 | R-PE-EXPORT.1 | killed | `g1_panel::test_r_pe_export_1_the_prompt_sits_between_the_document_row_and_the_legend[R-PE-EXPORT.1/1]` |
| MU03 | R-TUI-063.1 | killed | `g1_panel::test_r_tui_063_1_the_patch_editor_top_to_bottom_order[R-TUI-063.1/4]` |
| MU04 | R-PE-EXPORT.2 | survived, then killed by the new test | `mu_survivors::test_the_largest_dock_is_four_rows_high_with_one_chip_row[MU-DOCK/1]` |
| MU05 | R-TUI-049.1 | killed | `g2_arms::test_r_tui_049_1_the_before_after_control_is_shown_after_a_save_back[R-TUI-049.1/3]` |
| MU06 | R-PE-EXPORT.3 | killed | `g2_arms::test_r_pe_export_3_an_apply_that_applies_nothing_hides_the_prompt[R-PE-EXPORT.3/2]` |
| MU07a | R-PE-EXPORT.17/1 (Add) | killed | `g2_arms::test_r_pe_export_17_1_adding_an_entry_hides_the_prompt` |
| MU07b | R-PE-EXPORT.17/2 (Edit) | killed | `g2_arms::test_r_pe_export_17_2_editing_an_entry_hides_the_prompt` |
| MU07c | R-PE-EXPORT.17/3 (Remove) | killed | `g2_arms::test_r_pe_export_17_3_removing_an_entry_hides_the_prompt` |
| MU07d | R-PE-EXPORT.17/4 (JSON edit) | killed | `g2_arms::test_r_pe_export_17_4_a_per_entry_json_edit_hides_the_prompt` |
| MU07e | R-PE-EXPORT.17/5 (stage) | killed | `g2_arms::test_r_pe_export_17_5_a_stage_from_the_staging_sheet_hides_the_prompt` |
| MU08a | R-PE-EXPORT.4 (line text) | killed | `g2_arms::test_r_pe_export_4_1_the_apply_line_after_one_applied_entry` |
| MU08b | R-PE-EXPORT.4/3 (line refresh) | killed | `g2_arms::test_r_pe_export_4_1_the_apply_line_after_one_applied_entry` |
| MU09a | R-PE-EXPORT.5 (title) | killed | `g2_arms::test_r_pe_export_5_an_apply_that_applies_nothing_raises_one_warning_notice[R-PE-EXPORT.5/1]` |
| MU09b | R-PE-EXPORT.5 (severity) | killed | `g2_arms::test_r_pe_export_5_an_apply_that_applies_nothing_raises_one_warning_notice[R-PE-EXPORT.5/1]` |
| MU09c | R-PE-EXPORT.5 (notice dropped) | killed | `g2_arms::test_r_pe_export_5_an_apply_that_applies_nothing_raises_one_warning_notice[R-PE-EXPORT.5/1]` |
| MU10 | R-PE-EXPORT.6 | killed | `g2_arms::test_r_pe_export_6_a_successful_apply_raises_no_notice[R-PE-EXPORT.6/1]` |
| MU11a | R-PE-EXPORT.7/3 (format kept) | killed | `g1_controls::test_r_pe_export_7_2_the_format_control_shows_intel_hex_for_an_intel_hex_image` |
| MU11b | R-PE-EXPORT.7/2 (always s19) | killed | `g1_controls::test_r_pe_export_7_2_the_format_control_shows_intel_hex_for_an_intel_hex_image` |
| MU12a | R-PE-EXPORT.8 (no change) | killed | `g2_write::test_r_pe_export_8_1_one_press_changes_s19_to_intel_hex_shown_and_written` |
| MU12b | R-PE-EXPORT.8/2 (only to hex) | killed | `g2_write::test_r_pe_export_8_2_a_second_press_changes_back_to_s19` |
| MU13a | R-PE-EXPORT.9 (label constant) | killed | `g1_controls::test_r_pe_export_7_2_the_format_control_shows_intel_hex_for_an_intel_hex_image` |
| MU13b | R-PE-EXPORT.9 (chip width 17) | killed | `g1_controls::test_r_pe_export_7_2_the_format_control_shows_intel_hex_for_an_intel_hex_image` |
| MU14a | R-PE-EXPORT.10 (width always shown) | killed | `g1_controls::test_r_pe_export_10_1_no_width_control_for_an_intel_hex_image` |
| MU14b | R-PE-EXPORT.10 (opacity not visibility) | killed | `g1_controls::test_r_pe_export_10_1_no_width_control_for_an_intel_hex_image` |
| MU15 | R-PE-EXPORT.11 (width always hidden) | killed | `g1_controls::test_r_pe_export_11_2_the_width_control_returns_when_switching_intel_hex_to_s19` |
| MU16 | R-PE-EXPORT.12 (width collapsed) | killed | `g1_controls::test_r_pe_export_12_write_file_and_dont_save_stay_put_on_a_format_change[R-PE-EXPORT.12/3]` |
| MU17 | R-PE-EXPORT.13 (width reset on switch) | killed | `g2_write::test_r_pe_export_13_1_a_format_change_keeps_the_width` |
| MU18a | R-PE-EXPORT.14 (case) | killed | `g1_controls::test_r_pe_export_14_2_an_upper_case_suffix_is_replaced` |
| MU18b | R-PE-EXPORT.14 (whitespace) | killed | `g2_write::test_r_pe_export_14_4_a_trailing_space_does_not_stop_the_replacement` |
| MU18c | R-PE-EXPORT.14/3 (only .s19) | killed | `g1_controls::test_r_pe_export_14_3_a_switch_to_s19_replaces_hex` |
| MU19 | R-PE-EXPORT.15 | killed | `g2_write::test_r_pe_export_15_a_name_without_a_format_suffix_is_kept_and_the_write_adds_it[R-PE-EXPORT.15/2]` |
| MU20 | R-HEX-SAVE-001.1 | killed | `g2_write::test_the_prompt_writes_the_chosen_format_and_verifies_it[R-HEX-SAVE-001.1/2]` |
| MU21a | R-HEX-SAVE-001.2 (any suffix kept) | killed | `g3_engine::test_r_hex_save_001_2_the_format_suffix_is_added_when_missing[R-HEX-SAVE-001.2/1]` |
| MU21b | R-HEX-SAVE-001.2 (case sensitive) | killed | `g3_engine::test_r_hex_save_001_2_the_format_suffix_is_added_when_missing[R-HEX-SAVE-001.2/2]` |
| MU22 | R-S19-SAVE-REUSE-001.1 | killed | `g2_write::test_r_s19_save_reuse_001_1_a_hex_save_back_holds_at_most_16_data_bytes_per_record[R-S19-SAVE-REUSE-` |
| MU23 | R-PE-EXPORT.16 (type 04 -> 02) | killed | `g3_engine::test_r_pe_export_16_a_hex_save_back_holds_only_record_types_00_01_04[R-PE-EXPORT.16/3]` |
| MU24a | R-HEX-EMIT-001.11 (boundary dropped) | killed | `g3_engine::test_r_hex_emit_001_11_no_type_00_record_crosses_a_64_kib_boundary[R-HEX-EMIT-001.11/1]` |
| MU24b | R-HEX-EMIT-001.11 (+2) | killed | `g3_engine::test_r_hex_emit_001_11_no_type_00_record_crosses_a_64_kib_boundary[R-HEX-EMIT-001.11/2]` |
| MU24c | R-HEX-EMIT-001.11 (-0) | timeout (hang) | (every selected node passed) |
| MU25 | R-S19-S0HEADER-001.1 | killed | `g2_write::test_r_s19_s0header_001_1_2_the_source_s0_data_is_kept_at_width_32_for_case00` |
| MU26a | R-S19-S0HEADER-001.2 (first render) | killed | `s0_written_name::test_r_s19_s0header_001_2_5_a_numbered_written_name_wins_over_the_typed_one` |
| MU26b | R-S19-S0HEADER-001.2 (typed name) | killed | `s0_written_name::test_r_s19_s0header_001_2_5_the_header_is_the_written_name_never_the_typed_path[full-windows-path]` |
| MU26c | R-S19-S0HEADER-001.2 (non-ASCII kept as ?) | killed | `s0_written_name::test_r_s19_s0header_001_2_5_the_header_is_the_written_name_never_the_typed_path[non-ascii-dropped]` |
| MU26d | R-S19-S0HEADER-001.2 (cap 253) | survived, then killed by the new test | `mu_survivors::test_r_s19_s0header_001_2_6_a_long_written_name_is_cut_to_252_bytes` |
| MU26e | R-S19-S0HEADER-001.2 (rounds 1) | killed | `s0_written_name::test_r_s19_s0header_001_2_5_a_numbered_written_name_wins_over_the_typed_one` |
| MU26f | R-S19-S0HEADER-001.2 (rounds 2) | survived, then killed by the new test | `mu_survivors::test_r_s19_s0header_001_2_7_the_header_follows_a_landing_name_that_moves_twice` |
| MU26g | R-S19-S0HEADER-001.2 (no re-render) | killed | `s0_written_name::test_r_s19_s0header_001_2_5_the_header_is_the_written_name_never_the_typed_path[full-windows-path]` |
| MU26h | R-S19-S0HEADER-001.2 (never stops early) | survived (equivalent) | (every selected node passed) |
| MU27 | R-S19-S0HEADER-001.3 | killed | `g2_write::test_r_s19_s0header_001_an_intel_hex_source_written_as_s19_gets_its_header[R-S19-S0HEADER-001.3/1]` |
| MU29 | R-HEX-VERIFY-001.1 | killed | `g2_write::test_the_prompt_writes_the_chosen_format_and_verifies_it[R-HEX-SAVE-001.1/3]` |
| MU30 | R-HEX-VERIFY-002.3 | killed | `g1_controls::test_r_hex_verify_002_3_the_suggested_name_follows_the_image[R-HEX-VERIFY-002.3/2]` |
| MU31 | R-S19-WIDTH-001.1 | killed | `g1_controls::test_r_s19_width_001_1_1_the_width_is_32_on_every_new_prompt` |
| MU32 | R-S19-WIDTH-001.2 | killed | `g1_controls::test_r_s19_width_001_2_1_width_switches_32_16_in_the_new_placement` |
| MU33 | R-CHG-003.2/.5 | killed | `g2_arms::test_r_chg_003_2_1_dont_save_hides_the_prompt_from_the_inspector_tab` |
| MU34 | R-TUI-064.1 (prompt rows padded) | survived, then killed by the new test | `mu_survivors::test_the_largest_dock_is_four_rows_high_with_one_chip_row[MU-DOCK/1]` |
| MU35 | R-TUI-064.2 | killed | `g1_controls::test_r_tui_064_2_no_painted_part_is_wider_than_the_panel_with_the_prompt_shown[R-TUI-064.2/2]` |
| MU36 | R-TUI-064.4 | survived, then killed by the new test | `mu_survivors::test_the_largest_dock_is_four_rows_high_with_one_chip_row[MU-DOCK/1]` |
| MU37 | I-10.2 (confirm without format) | killed | `g2_write::test_the_prompt_writes_the_chosen_format_and_verifies_it[R-HEX-SAVE-001.1/3]` |

## Survivors

| Mutant | Why it lived | Resolution |
|---|---|---|
| MU04 (the prompt's chips in the base's two-row grid), MU34 (prompt rows padded by 4 rows), MU36 (chip row 3 rows high) | every prompt control stayed inside a 54-row screen and every chip stayed one row high, so R-PE-EXPORT.2, R-TUI-064.1/.4 held; only the dock's height changed, which `test_r_pe_export_2_11_...` prints (`DOCK-HEIGHT`, "more than 4 is F-R8-1, not a failure here") and does not assert | new `test_the_largest_dock_is_four_rows_high_with_one_chip_row` (2 nodes, 118x54 and 220x60): the dock at most 4 rows in its largest form and the four chips in one screen row. RED on the three mutants, GREEN on the tree. **Judgment for the orchestrator**: this pins the "4-row dock, I-8.3 fit" named in the R-PE-EXPORT.2 status; the requirement text asks only for "every control without scrolling". If 4 is not meant as a requirement, drop this one test and accept MU04/34/36 as unpinned |
| MU26d (S0 header cut at 253 bytes) | no node wrote a name longer than 252 bytes, so "cut to 252 bytes" of R-S19-S0HEADER-001.2 was never observed | new `test_r_s19_s0header_001_2_6_a_long_written_name_is_cut_to_252_bytes` (254-character name; header data = its first 252 bytes). RED on the mutant, GREEN on the tree |
| MU26f (`_S0_NAME_ROUNDS` 2 instead of 3) | every original work-area state reaches the fixed point in two rounds | new `test_r_s19_s0header_001_2_7_the_header_follows_a_landing_name_that_moves_twice`: `fw.s19` holds other bytes, `fw_1.s19` the exact bytes of the `fw.s19`-headed render; the landing name moves `fw.s19` -> `fw_1.s19` -> `fw_2.s19` and only the third render carries the right header. RED on the mutant (header `fw_1.s19`), GREEN on the tree. The state needs a reused name followed by a numbered one; "2 suffice" holds for a fresh, numbered or reused landing alone |
| MU26h (never stops early: the `break` on `name == header_name` replaced by never) | **equivalent**: at the fixed point the next round renders the same header, hence the same bytes and the same predicted landing, so the returned payload is identical; it costs up to two extra renders and nothing observes the render count | none (argued) |

Timeout: MU24c (the third bound of the HEX row, `(row_start | 0xFFFF) + 1`, without the `+ 1`): a row starting at an address whose low 16 bits are `0xFFFF` gets `row_end == row_start`, the `while` loop never advances, and a fixture image has such a row; the run hangs (rc 124 at 301 s). Counted as detected (a hang), not as a timing result. The other two variants of the boundary (MU24a dropped, MU24b `+ 2`) are killed in 4 s by R-HEX-EMIT-001.11/1 and /2.

## Coverage of the Inc 10 rows

Rows with a mutant (killed unless noted): R-CHG-003.1 (MU01), R-PE-EXPORT.1 (MU02), R-TUI-063.1 (MU03), R-PE-EXPORT.2 (MU04, new test), R-TUI-049.1 (MU05), R-PE-EXPORT.3 (MU06), .17 (MU07a..e), .4 (MU08a, b), .5 (MU09a..c), .6 (MU10), .7 (MU11a, b), .8 (MU12a, b), .9 (MU13a, b), .10 (MU14a, b), .11 (MU15), .12 (MU16), .13 (MU17), .14 (MU18a..c), .15 (MU19), R-HEX-SAVE-001.1 (MU20), .2 (MU21a, b), R-S19-SAVE-REUSE-001.1 (MU22), R-PE-EXPORT.16 (MU23), R-HEX-EMIT-001.11 (MU24a..c), R-S19-S0HEADER-001.1 (MU25), .2 (MU26a..h), .3 (MU27), R-HEX-VERIFY-001.1 (MU29); and the cited rows R-HEX-VERIFY-002.3 (MU30), R-S19-WIDTH-001.1 (MU31), .2 (MU32), R-CHG-003.2/.5 (MU33), R-TUI-064.1 (MU34, new test), .2 (MU35), .4 (MU36, new test), and I-10.2 (MU37).

No mutant: **R-S19-EMIT.11** (`n/a - owed by D8-29`: no code and no test in this increment, status `conflict`). The cited rows Inc 10 only re-runs (R-S19-EMIT.3/.4/.5, R-HEX-EMIT-001.2/.3, R-IMG-WRITE.2) were not mutated; MU23 touches the HEX emitter they share. Not run (brief item 4): the 8 shipped nodes waiting for the Inc 8 fix F-I10-1 and AT-B99-02, AT-076a, R-DOC-CANON.4; none was needed to kill or judge a mutant and none counts as a kill.

## Limits

- Per mutant only the row's own nodes ran, not all 124: a mutant no selected node catches but another node would is counted a survivor here. The six survivors were all re-checked against the whole file set by reading (the three new tests are the only nodes that kill them; MU26h is equivalent whatever runs). The table is one driver run (`results.jsonl` lines 1 to 59), the retest of the five survivors with the new file (lines 60 to 64) and the MU13b re-run without `--maxfail` (line 65).
- Host shared and loaded (HT-08): load 9 to 13 on 16 cores; pass/fail only.
- No product code changed; no push. Runner scratch `~/work/zq-mu10/` (created by this run) deleted at the end.
