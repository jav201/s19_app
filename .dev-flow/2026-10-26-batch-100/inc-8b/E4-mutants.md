# Inc 8b — E4 mutant table (tester)

One row per negative control of the 8b requirements and per ruling mutant (R1–R16). Each mutant is a BEHAVIOUR, not a line: E5 writes it into a copy of the tree against whatever code implements the behaviour. The "killed by" column names the test node(s) on disk that must turn RED; "expected RED" is the observable assertion that fails. State of every row: `planned` (E4 authors the table; E5 runs the mutants in a copy of the tree, new arms only).

Modules: `H` = `tests/test_b100_project_homes.py`, `S` = `tests/test_b100_save_image.py` (TC-B100-59 Inc 8b arms).

| # | Requirement / ruling | Mutant (behaviour) | Killed by | Expected RED | State |
|---|---|---|---|---|---|
| M01 | HLR-171 / LLR-171.1 (P-9) | save as copies no sub-folder file | H `test_tc_b100_31_save_as_copies_every_subfolder_file`; H `test_at_b100_09_*[size0,size1]` | 8 missing; picker lists nothing | planned |
| M02 | LLR-171.1 | first-level-only copy (no recursion) | H `test_tc_b100_31_save_as_copies_every_subfolder_file` | `reports/2026/r2.md` missing | planned |
| M03 | LLR-171.1 R3 | sub-folders only, top-level files not copied | H `test_tc_b100_31_save_as_copies_the_top_level_files_but_not_the_backups` | `Q/a.json` absent | planned |
| M04 | LLR-171.1 R10 | `project.json.previous-*` backups copied (no exclusion, or a case-sensitive one) | same node | a backup present in Q | planned |
| M05 | R11 (A3R2-1) | rows loop does not skip `carried` rows | same node | `place_into_workarea` from `P/a.json` called 2 times (or abort) | planned |
| M06 | R11 | top-level copy after the variant rebuild | same node | variant set 1, not 2 | planned |
| M07 | LLR-171.1a | enumeration follows a directory junction (`os.walk`/`rglob` copy) | H `test_tc_b100_31_links_are_skipped_and_named`; H `test_tc_b100_31_junction_cycle_ends` | `secret.txt` in Q; cycle copies P into Q / exceeds 5 s | planned |
| M08 | LLR-171.1b | a file symbolic link is copied (followed) | H `test_tc_b100_31_links_are_skipped_and_named` | `Q/patches/l.json` exists | planned |
| M09 | LLR-171.1c | links skipped silently (no status line) | same node | 0 of 3 named | planned |
| M10 | LLR-171.7a R6 | every link name painted (no 10-name cap) | H `test_tc_b100_31_link_line_names_at_most_ten`; H `test_tc_b100_31_painted_names_clip_scrub_and_count` | 25 names shown / no "and 15 more" | planned |
| M11 | LLR-171.7 R6 | no scrub of control / bidi / zero-width characters | H `test_tc_b100_31_link_names_are_scrubbed`; H `..._painted_names_clip_scrub_and_count` | U+202E painted | planned |
| M12 | LLR-171.7 S3R2-4 | round 1's fixed character list instead of the Unicode categories | same two nodes | U+061C / U+2028 painted | planned |
| M13 | LLR-171.7 S3R2-4 | unpaired surrogate passed through (no U+FFFD) | H `..._painted_names_clip_scrub_and_count` | `e�f` absent / encode raises | planned |
| M14 | LLR-171.7 R6 | no 120-character clip | same node | length 300 | planned |
| M15 | LLR-171.1e | free-space check after `mkdir` (folder rolled back) | H `test_tc_b100_31_free_space_is_checked_before_any_folder[T-1 refused]` | `mkdir` spy 1+ calls | planned |
| M16 | LLR-171.1e | `>=` instead of `>` | same, `[T saved]` | T arm refused | planned |
| M17 | LLR-171.1e | no free-space check | same, `[T-1 refused]` | T − 1 saves | planned |
| M18 | LLR-171.1d | bytes behind the junction counted (plain walk) | H `..._free_space_...[T saved]`; S `test_tc_b100_59_plan_total_counts_every_written_byte` | T arm refused; total ≠ 90 112 | planned |
| M19 | LLR-171.1i / R7 | source image size instead of emitted | S `test_tc_b100_59_plan_total_counts_every_written_byte` | 86 016 | planned |
| M20 | R7 | no 4 KiB rounding | S `..._plan_total_counts_every_written_byte`; S `test_tc_b100_59_plan_total_rounding_per_file`; H `..._free_space_...[T-1 refused]` | 70 896 / ≠ 81 920 / T − 1 saves | planned |
| M21 | R7 | no 64 KiB margin | same three | 24 576 / 16 384 / T − 1 saves | planned |
| M22 | R14 | carried top-level rows counted twice in `total_bytes` (row sum + copies) | H `test_e4_r14_top_level_copy_counted_once_in_the_plan_total`; H `test_e4_r14_top_level_copy_at_the_free_space_boundary_saves` | 94 208 ≠ 86 016; T arm "not enough free space" | executed at E4 integration (sanity run in a copy tree: KILLED) |
| M23 | LLR-171.1f | move instead of copy | H `test_tc_b100_31_save_as_copies_every_subfolder_file`; H `test_tc_b100_31_failed_copy_rolls_back_in_user_terms` | P's digest set changes | planned |
| M24 | LLR-171.1g | copy run for a merge / open-project target | H `test_tc_b100_31_merge_and_save_into_itself_copy_no_subfolder`; S `..._plan_total_counts_every_written_byte` (merge plan) | `R/flows/f1.json` present; merge copies ≠ () | planned |
| M25 | LLR-171.1h | fresh manifest for a save as (no carry) | H `test_tc_b100_31_save_as_carries_the_open_projects_records` | Q `batch` empty | planned |
| M26 | LLR-171.1h | carried records written absolute | same node | "project.json was not written" / absolute strings | planned |
| M27 | LLR-171.6 / .6a R4 (C-7) | `payload.batch` written when the selection is empty | H `test_tc_b100_31_empty_selection_keeps_batch_for_every_target` | P `batch` 0 entries after the save into P | planned |
| M28 | LLR-171.6b A3R2-3/-4 | gather fed from `payload.batch` / from the resolved `batch` only | H `test_tc_b100_31_gather_takes_names_from_the_recorded_batch_and_assignments` | spy 0 names, `P/patches/a.json` absent; batch-only → `c.json` absent | planned |
| M29 | LLR-171.1j R1 | file ceiling removed | H `test_tc_b100_31_copy_ceiling_2000_files` | the 2 001 arm saves | planned |
| M30 | LLR-171.1j R1 | `>=` ceiling | same node | the 2 000 arm refused | planned |
| M31 | LLR-171.1j R1 | depth check removed | H `test_tc_b100_31_depth_ceiling[33]` | 33 saves | planned |
| M32 | LLR-171.1j R1 | depth `>=` (32 refused) | H `test_tc_b100_31_depth_ceiling[32]` | 32 refused | planned |
| M33 | LLR-171.1j R13 | entry ceiling counts regular files only | H `test_tc_b100_31_entry_ceiling[10001 refused]` | 10 001 arm saves | planned |
| M34 | R13 | entry ceiling `>=` | H `test_tc_b100_31_entry_ceiling[10000 saved]` | 10 000 refused | planned |
| M35 | R16 | walk sorts / reads a whole folder before counting (unbounded) | H `..._entry_ceiling[10001 refused]` (5 s bound) | only if the slowdown exceeds 5 s on this fixture — weak; see G-5 | planned |
| M36 | LLR-171.1k R8 | unreadable entry dropped silently | H `test_tc_b100_31_unreadable_entries_refuse_the_save[1,12]` | saved | planned |
| M37 | LLR-171.1k R6 | all unreadable names painted (no cap) | same `[12]` | no "and 2 more" | planned |
| M38 | LLR-171.7b R6 | exception text painted on a failed copy | H `test_tc_b100_31_failed_copy_rolls_back_in_user_terms` | "WinError" in status | planned |
| M39 | LLR-171.7b | no rollback of copied files / created sub-folders | same node | Q exists | planned |
| M40 | LLR-171.1l R9 | no `_publish_flow_session_dir` after a save as | H `test_tc_b100_31_flow_session_folder_follows_q` | strip names P | planned |
| M41 | LLR-171.1m R9 / S3R2-5 | no rebind, or rebind after an `is_file()` probe | H `test_e4_llr_171_1m_document_inside_p_follows_its_copy` | `source_path` stays under P | executed at E4 integration (sanity run in a copy tree: KILLED) (no-rebind arm; the probe arm is not mutated) |
| M42 | LLR-171.2 / HLR-171a | attach through `load_a2l_from_path` (temp copy) | H `test_tc_b100_32_a2l_only_project_opens_with_its_own_a2l`; H `test_at_b100_10_*` | new file under `W/temp`; A2L path ≠ `W/P/firmware.a2l` | planned |
| M43 | LLR-171.2 | A2L-only folder still refused ("No supported files") | same two + `..._2a`, `..._2c` | P never opens | planned |
| M44 | LLR-171.2a | reset skipped on the A2L-only branch | H `test_tc_b100_32_a2l_only_load_clears_the_previous_data_file` | `current_file` not None | planned |
| M45 | LLR-171.2b | project not set on the A2L-only branch | H `..._a2l_only_project_opens_with_its_own_a2l` | `current_project` ≠ P | planned |
| M46 | LLR-171.2c | `_variant_set` left None on the A2L-only branch | H `test_tc_b100_32_data_file_loaded_into_a2l_only_project_is_recorded` | `project.json` not rewritten | planned |
| M47 | LLR-171.2d | old "No supported files" line | H `test_tc_b100_32_empty_folder_is_refused_before_any_reset[no data or A2L file]` | token absent | planned |
| M48 | LLR-171.2e | the `no data or A2L file` branch reached with no `project.json` | same `[no project.json]` | wrong token | planned |
| M49 | LLR-171.2d/e | refusal after the reset | both arms | reset spy 1 | planned |
| M50 | LLR-171.2f R5 | no A2L guard (link attached) | H `test_tc_b100_32_a2l_guard_of_an_a2l_only_folder[link]` | link target attached | planned |
| M51 | LLR-171.2f R5 | cap `>=` | same `[at cap]` | at-cap refused | planned |
| M52 | LLR-171.2f | guard after the reset | `[link]`, `[over cap]` | reset spy 1 | planned |
| M53 | LLR-171.2g R5 | guard only on the A2L-only branch (data + A2L branch attaches an over-cap A2L) | H `test_tc_b100_32_over_cap_a2l_beside_a_data_file_is_left_out` | A2L attached | planned |
| M54 | LLR-171.2g S3R2-3 | list cleared for `choose_install_set` only (MAC load parses) | H `test_e4_llr_171_2g_linked_a2l_beside_a_mac_is_never_parsed` | spy: 1+ `_load_a2l_data_with_cache` calls with `firmware.a2l` | executed at E4 integration (sanity run in a copy tree: KILLED) (run as the wider mutant "the A2L list is not cleared") |
| M55 | LLR-171.3 (C2) | foreign-parent refusal after `mkdir` | H `test_tc_b100_33_foreign_parent_is_refused_before_any_folder[*]` | `mkdir` spy 1 | planned |
| M56 | LLR-171.3 | `is_relative_to` instead of equality | same `[W/patches]` | `W/patches/P` created | planned |
| M57 | LLR-171.3a | text comparison of the parent | H `test_tc_b100_33_work_area_under_another_spelling_saves_there[*]` | spelling refused | planned |
| M58 | LLR-171.3a S3-10 | `project_dir` keeps the typed spelling | same, `[junction alias]`, `[upper case]` | `current_project_dir` ≠ `W/P` | planned |
| M59 | LLR-171.4c | no link check in the listing | H `test_tc_b100_62_listing_leaves_out_links_and_junctions`; H `test_at_b100_11_*` | `alias` / `evil` listed | planned |
| M60 | LLR-171.4c | resolve before the link check | same | `alias` listed | planned |
| M61 | LLR-171.4e | no link check on load | H `test_tc_b100_62_load_refuses_a_junction_project[evil,alias]` | loads | planned |
| M62 | LLR-171.4f S3-7 | no one-component name check | H `test_tc_b100_62_load_refuses_a_folder_outside_the_work_area[*]` | `..` name / `sub/P` load | planned |
| M63 | LLR-171.4g | Save target resolved before the link check | H `test_tc_b100_62_save_target_junction_is_refused[*]`; H `test_at_b100_11_*` | no "link or junction" / bytes in R | planned |
| M64 | LLR-167.6a | no sub-folder rows | S `test_tc_b100_59_save_as_plans_one_row_per_subfolder` | 0 rows | planned |
| M65 | LLR-167.6a Q9 | 0-file sub-folder omitted | S `test_tc_b100_59_links_only_folder_and_skipped_links` | no `splits` row | planned |
| M66 | LLR-167.6b | links dropped from the plan | same node | `skipped_links` ≠ the 4 names | planned |
| M67 | LLR-167.6c | in-body MAC refusal kept after `mkdir` | S `test_tc_b100_59_second_companion_is_refused_before_any_folder[mac]` | `mkdir` spy 1 | planned |
| M68 | LLR-167.6d | in-body A2L refusal kept after `mkdir` | same `[a2l]`; S `test_tc_b100_59_own_a2l_by_name_and_bytes[False]` | `mkdir` spy 1 | planned |
| M69 | LLR-167.6c/f DR-6 | exemption by name only | S `..._own_a2l_by_name_and_bytes[False]` | other bytes saved | planned |
| M70 | LLR-167.6f (C3) | the open project's own A2L refused on a save into itself | H `test_at_b100_10_*` (two saves into P) | "already has an A2L file" | planned |
| M71 | LLR-167.6e | both the document row and the copy own a landing | S `test_tc_b100_59_document_row_owns_its_landing` | duplicate landing / copy holds `patches/boost.json` | planned |
| M72 | LLR-167.6g | cap check after `mkdir` / none | S `test_tc_b100_59_file_over_the_cap_is_refused_in_the_plan[1]`; S `test_tc_b100_59_plan_cap_refusal_names_the_file[1025-True]` | `mkdir` spy 1 / saved | planned |
| M73 | LLR-167.6g | cap `>=` | S `..._file_over_the_cap_...[0]`; S `..._plan_cap_refusal_...[1024-False]` | at-cap refused | planned |
| M74 | LLR-167.6g pre-ruling 4 | cap bound at import (lowered cap not seen) | S `..._file_over_the_cap_...[1]` | cap + 1 saved | planned |
| M75 | LLR-171.5 | unrecorded gathered row not reported | H `test_e4_llr_171_5_unrecorded_gathered_rows_are_named[1,12]` (painting side; `unrecorded` injected) | 0 lines / no "and 2 more" | executed at E4 integration (sanity run in a copy tree: KILLED) |

| M76 | R2 (A3-1) | the sub-folder copy after the rows loop | H `test_e4_r2_r11_call_order_of_a_save_as`; H `test_e4_r2_pasted_document_beside_a_different_p_file_lands_changes_1` | spy order starts `document`; "the plan named" abort | executed at E4 integration (sanity run in a copy tree: KILLED) |
| M77 | R2 / LLR-167.6e | the pasted document predicted against the empty home (no `changes_1.json`) | H `test_e4_r2_pasted_document_beside_a_different_p_file_lands_changes_1` | P's `changes.json` lost or abort | planned (E5) |
| M78 | R11 (F-8) | the top-level copy before the rows loop | H `test_e4_r2_r11_call_order_of_a_save_as`; H `test_e4_r11_f8_identical_firmware_1_in_p_is_copied_not_reused` | spy order; image row reuses `Q/firmware_1.s19` → abort | executed at E4 integration (sanity run in a copy tree: KILLED) |
| M79 | R11 / A3R2-5 / R15 | no `_plan_row_mismatch` on a carried row | H `test_e4_r11_a3r2_5_top_level_copy_reusing_the_image_row_aborts` | saved, Q lacks `fw.s19` | executed at E4 integration (sanity run in a copy tree: KILLED) |
| M80 | LLR-171.1m S3R2-5 | rebind by text (no plan-entry and no `..` check) | H `test_e4_llr_171_1m_rebind_only_to_a_plan_entry[skipped junction, dot-dot]` | `source_path` moves under Q | executed at E4 integration (sanity run in a copy tree: KILLED) |
| M81 | LLR-171.1k (R8, DR-5) | an unlistable folder skipped silently | H `test_e4_llr_171_1k_unlistable_folder_refuses_the_save` | saved | executed at E4 integration (sanity run in a copy tree: KILLED) |
| M82 | LLR-171.1k (S3R2-6) | reserved device stems not classified unreadable | H `test_e4_llr_171_1k_reserved_device_names_refuse_the_save[CON.txt, lpt1.json, CONOUT$.md]` | saved | executed at E4 integration (sanity run in a copy tree: KILLED) |
| M83 | A3-13 | the unreadable refusal before the depth ceiling | H `test_e4_a3_13_refusal_precedence_in_the_plan` | "could not be read" where "nested too deep" is owed | executed at E4 integration (sanity run in a copy tree: KILLED) (after the fixture moved the unreadable entry to the top level: with it under `flows` the depth stop ended the walk first and the mutant survived) |
| M84 | token row 9 (S3-6) | no source-folder check before the walk | H `test_e4_token_row_9_open_project_swapped_for_a_junction` | saved through the junction | executed at E4 integration (sanity run in a copy tree: KILLED) |
| M85 | AT-B100-10 (ruling D-5) | the Loaded panel's A2L slot ignores the session A2L when no data file is loaded | H `test_at_b100_10_a2l_only_project_saves_and_reopens[size0,size1]` | slot paints `(none)` | executed at E4 integration (sanity run in a copy tree: KILLED) |

Count: 85 rows — 84 with a killing node on disk (M35's kill is weak: it depends on the slowdown passing 5 s); 0 gaps. M22, M41, M54, M75 were the tester's gaps, filled at E4 integration; M76–M85 are new rows of that step. The E4 sanity runs are not E5's mutation run: each was applied once in a copy of the tree against its named nodes only (`scratchpad/int8b/mutants.py`).
