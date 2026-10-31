# Inc 9a — E4 mutant plan (tester)

One mutant per new arm, taken from each requirement's negative control (`01-requirements.md`) and the E3 rulings. Each row names the node in `tests/test_b100_recents.py` that must turn RED when the mutant is applied to the 9a implementation. State of every row: `planned` (no mutant has been executed by the tester; E5/E6 run them).

"W" = the work area. Node names drop the `test_` prefix and the file name.

| Id | Requirement | Target file | The change in words | Node expected to turn RED |
|---|---|---|---|---|
| M01 | LLR-172.1 | `s19_app/tui/workspace.py` | `recent_store_path` reads `APPDATA` instead of `LOCALAPPDATA` | `tc_b100_34_store_lives_under_localappdata`; `tc_b100_34_no_usable_localappdata_writes_no_store[unset]` (file under `<tmp>/roam`) |
| M02 | LLR-172.1 | `workspace.py` | the store is written under `<base>/.s19tool/recent_sources.json` (the round-2 location) | `tc_b100_34_store_lives_under_localappdata` (base arm); `tc_b100_34_twenty_five_outside_loads_keep_twenty_newest_first` |
| M03 | LLR-172.1 / seam S9 | `workspace.py` | `LOCALAPPDATA` read once at import and cached | `tc_b100_34_store_lives_under_localappdata` (`lad2` arm) |
| M04 | LLR-172.1f | `workspace.py` | any non-empty `LOCALAPPDATA` accepted (a relative value used as a folder) | `tc_b100_34_unusable_localappdata_gives_no_store_path[relative]`; `tc_b100_34_no_usable_localappdata_writes_no_store[relative]` |
| M05 | LLR-172.1f | `workspace.py` | unset `LOCALAPPDATA` falls back to `Path.home()` | `tc_b100_34_unusable_localappdata_gives_no_store_path[unset]`; `tc_b100_34_no_usable_localappdata_writes_no_store[unset]` |
| M06 | LLR-172.1f (R7) | `workspace.py` | `mkdir(parents=True)` creates a missing `LOCALAPPDATA` | `tc_b100_34_no_usable_localappdata_writes_no_store[absent folder]` |
| M07 | LLR-172.1f (R5) | `workspace.py` | the drive test is `PureWindowsPath(v).is_absolute()` (accepts UNC) | `tc_b100_34_unusable_localappdata_gives_no_store_path[UNC]` |
| M08 | LLR-172.1a / .2h | `workspace.py` | `.srec` maps to kind `srec` | `tc_b100_34_recent_kind_follows_the_loaders_suffix_sets[...a.srec-s19]`, `[...A.SREC-s19]` |
| M09 | LLR-172.1a | `workspace.py` | the new entry is appended last | `tc_b100_34_record_puts_newest_first_with_its_kind` |
| M10 | LLR-172.1a (R1) | `workspace.py` | the record stores `Path(path).resolve()` | `tc_b100_34_record_does_not_resolve_a_junction` |
| M11 | LLR-172.1a (S7) | `s19_app/tui/app.py` | `load_from_path` / `load_a2l_from_path` record `copied` (the work copy) | `tc_b100_34_outside_load_records_the_source_not_the_work_copy` |
| M12 | LLR-172.1a (S7) | `workspace.py` | the record stores `str(path)` without `abspath` | `tc_b100_34_record_stores_the_lexical_absolute_path` |
| M13 | LLR-172.1b | `workspace.py` | no de-duplication | `tc_b100_34_same_source_keeps_one_entry_in_first_place` |
| M14 | LLR-172.1b | `workspace.py` | a duplicate keeps its old position | `tc_b100_34_same_source_keeps_one_entry_in_first_place` (A, B, A arm) |
| M15 | LLR-172.1b | `workspace.py` | paths compared without `normcase` | `tc_b100_34_case_spelling_of_one_source_keeps_one_entry` |
| M16 | LLR-172.1c | `workspace.py` | cap 21 (or none) | `tc_b100_34_store_holds_at_most_twenty_entries` |
| M17 | LLR-172.1c | `workspace.py` | the newest entry dropped at the cap | `tc_b100_34_store_holds_at_most_twenty_entries` |
| M18 | LLR-172.1d | `app.py` | the record moves before `copy_into_workarea` | `tc_b100_34_load_failing_before_its_copy_records_nothing` (over-cap arm) |
| M19 | LLR-172.1d (Q1) | `app.py` | the record runs only after a successful install | `tc_b100_34_source_that_copies_then_fails_to_parse_is_recorded` |
| M20 | LLR-172.1e | `app.py` | the `contained_in_workarea` test before the record removed | `tc_b100_34_source_inside_the_work_area_is_not_recorded` |
| M21 | LLR-172.1g | `workspace.py` | no reparse-point check of the store folder | `tc_b100_34_linked_store_folder_is_not_written` |
| M22 | LLR-172.1h | `workspace.py` | a fixed staging name | `tc_b100_34_store_is_replaced_through_unique_staging_files` |
| M23 | LLR-172.1h | `workspace.py` | the store written in place (no `os.replace`) | `tc_b100_34_store_is_replaced_through_unique_staging_files` |
| M24 | LLR-172.1i | `workspace.py` | the `OSError` of `os.replace` let out of `record_recent_source` | `tc_b100_34_failed_store_write_returns_false_and_keeps_the_store[replace refused]`; `tc_b100_34_failed_store_write_never_fails_the_load[replace refused-data]` |
| M25 | LLR-172.1i (S6) | `app.py` | no warning logged when the record returns False | `tc_b100_34_failed_store_write_never_fails_the_load[*]` |
| M26 | LLR-172.1i (S6) | `workspace.py` | the record logs its own WARNING (2 in all) | `tc_b100_34_failed_store_write_returns_false_and_keeps_the_store[*]`; `tc_b100_34_failed_store_write_never_fails_the_load[*]` |
| M27 | LLR-172.1i | `workspace.py` | the staging file is not removed after a failed replace | `tc_b100_34_failed_store_write_returns_false_and_keeps_the_store[replace refused]` |
| M28 | LLR-172.1i | `workspace.py` | the `ValueError` of `abspath` (embedded NUL) not caught | `tc_b100_34_record_with_an_embedded_nul_never_raises` |
| M29 | LLR-172.1j | `workspace.py` | the raw stored entries carried forward | `tc_b100_34_record_writes_back_only_accepted_entries` |
| M30 | LLR-172.1k | `workspace.py` | "could not be read" treated as an empty store | `tc_b100_34_unreadable_store_is_left_unchanged[open refused]`, `[read failed]` |
| M31 | LLR-172.1l | `workspace.py` | the entry check of the new path skipped | `tc_b100_34_source_the_read_would_drop_is_not_recorded` |
| M32 | LLR-172.1m | `workspace.py` | no size loop | `tc_b100_34_written_store_fits_the_read_cap` |
| M33 | LLR-172.1m | `workspace.py` | the size loop drops the newest entry | `tc_b100_34_written_store_fits_the_read_cap` (paths arm) |
| M34 | HLR-172 | `app.py` | the record call removed from both loads | `tc_b100_34_twenty_five_outside_loads_keep_twenty_newest_first`; `at_b100_12_*` |
| M35 | LLR-172.2 | `workspace.py` | no 20-entry cap on read | `tc_b100_35_read_returns_the_first_twenty_accepted_in_order` |
| M36 | LLR-172.2 | `workspace.py` | the read sorts the entries | `tc_b100_35_read_returns_the_first_twenty_accepted_in_order` (5-entry arm) |
| M37 | LLR-172.2a | `workspace.py` | `>=` instead of `>` against 65 536 | `tc_b100_35_oversized_store_reads_as_too_large` (65 536 arm) |
| M38 | LLR-172.2a (S-12) | `workspace.py` | `stat` then an unbounded `read()` | `tc_b100_35_oversized_store_reads_as_too_large` (read-size spy) |
| M39 | LLR-172.2b | `workspace.py` | no shape check | `tc_b100_35_store_of_the_wrong_shape_reads_as_empty[top-level list]` |
| M40 | LLR-172.2b | `workspace.py` | any `schema_version` accepted | `tc_b100_35_store_of_the_wrong_shape_reads_as_empty[version 2 with an entry]` |
| M41 | LLR-172.2b (R-5) | `workspace.py` | `schema_version == 1` without the type check | `tc_b100_35_store_of_the_wrong_shape_reads_as_empty[version true]`, `[version 1.0]` |
| M42 | LLR-172.2c | `workspace.py` | `PermissionError` of the open not caught | `tc_b100_35_unreadable_store_reads_as_could_not_be_read[open refused]` |
| M43 | LLR-172.2c | `workspace.py` | problem None for an unreadable store | `tc_b100_35_unreadable_store_reads_as_could_not_be_read[directory at the store path]` |
| M44 | LLR-172.2c (R6) | `workspace.py` | no link check before the open | `tc_b100_35_unreadable_store_reads_as_could_not_be_read[store file a symbolic link]`, `[store folder a junction]` |
| M45 | LLR-172.2d | `workspace.py` | a missing store reported "could not be read" | `tc_b100_35_missing_store_reads_as_empty_with_no_problem` |
| M46 | LLR-172.2e | `workspace.py` | `is_absolute()` instead of the drive-and-root test | `tc_b100_35_entry_path_checks_drop_entries[LLR-172.2e ...]` |
| M47 | LLR-172.2f | `workspace.py` | device names checked on the last component only | `tc_b100_35_entry_path_checks_drop_entries[LLR-172.2f ...]` |
| M48 | LLR-172.2g | `workspace.py` | only NUL refused | `tc_b100_35_entry_path_checks_drop_entries[LLR-172.2g ...]` |
| M49 | LLR-172.2h | `workspace.py` | the kind not compared with the suffix | `tc_b100_35_entry_whose_kind_does_not_match_its_suffix_is_dropped` |
| M50 | LLR-172.2i | `workspace.py` | the entry indexed without the type check | `tc_b100_35_malformed_entry_is_dropped` |
| M51 | LLR-172.2j (R-4) | `workspace.py` | only `ValueError` caught around `json.loads` | `tc_b100_35_store_read_never_raises` (`[` × 65 536 arm) |
| M52 | LLR-172.2j | `workspace.py` | no decode guard | `tc_b100_35_store_of_the_wrong_shape_reads_as_empty[not utf-8]` |
| M53 | LLR-172.3 (R-9) | `workspace.py` | the read logs each entry at DEBUG | `tc_b100_35_read_logs_no_entry_and_writes_nothing` |
| M54 | LLR-172.3 | `s19_app/tui/services/manifest_writer.py` | the store's entries added to `project.json` | `tc_b100_36_seeded_recent_entries_never_reach_the_base_folder`; `tc_b100_36_loaded_source_path_stays_out_of_project_files` |
| M55 | LLR-172.4 | `app.py` | `refresh_files` keeps `temp_dir.glob("*")` beside the lister | `tc_b100_37_one_function_enumerates_the_temp_folder` |
| M56 | LLR-172.4a | `workspace.py` | the lister recurses | `tc_b100_37_lister_returns_the_regular_files_sorted` |
| M57 | LLR-172.4a | `workspace.py` | the lister does not sort | `tc_b100_37_lister_returns_the_regular_files_sorted` |
| M58 | LLR-172.4b | `workspace.py` | `Path.is_file()` (follows links) without the link gate | `tc_b100_37_file_link_in_temp_is_not_listed` |
| M59 | LLR-172.4c | `workspace.py` | the lister's `OSError` catch removed | `tc_b100_37_unlistable_temp_gives_an_empty_list[listing refused]`, `[temp a regular file]`; `tc_b100_37_unlistable_temp_shows_no_rows[listing refused]` |
| M60 | LLR-172.4c (R11) | `workspace.py` | no link check of `temp` itself | `tc_b100_37_unlistable_temp_gives_an_empty_list[temp a junction]`; `tc_b100_37_unlistable_temp_shows_no_rows[temp a junction]` |
| M61 | LLR-172.5 (R3) | `app.py` | the typed spelling is loaded instead of the listed on-disk name | `tc_b100_38_typed_project_folder_loads_the_project[name in upper case]` |
| M62 | LLR-172.5 | `app.py` | the typed path compared case-sensitively with the work area | `tc_b100_38_typed_project_folder_loads_the_project[work area in upper case]` |
| M63 | LLR-172.5a | `app.py` | `project.json` matched case-sensitively | `tc_b100_38_typed_project_json_loads_its_project[PROJECT.JSON]` |
| M64 | LLR-172.5b (R3) | `app.py` | a case-folded reserved-home test instead of the listing match | `tc_b100_38_typed_folder_that_is_not_a_project_is_refused[temp::$INDEX_ALLOCATION]`, `[8.3 name of templates]` |
| M65 | LLR-172.5b | `app.py` | the listing step removed (any folder the §1.3 test accepts loads) | `tc_b100_38_typed_folder_that_is_not_a_project_is_refused[temp]` |
| M66 | LLR-172.5c | `app.py` | any folder holding a `project.json` is routed | `tc_b100_38_typed_folder_outside_the_work_area_is_refused[outside folder]` |
| M67 | LLR-172.5d | `app.py` | `resolve()` before the link walk | `tc_b100_38_typed_path_through_a_junction_is_refused[junction folder]` |
| M68 | LLR-172.5e | `app.py` | a file without a suffix sent to the data load | `tc_b100_38_typed_unsupported_file_is_refused[firmware]` |
| M69 | LLR-172.5f | `app.py` | the old `File not found: <path>` line kept | `tc_b100_38_typed_path_that_does_not_exist_is_refused[missing file]` |
| M70 | LLR-172.5g | `app.py` | the listing step removed from `_handle_load_project` | `tc_b100_38_project_load_of_an_unlisted_name_is_refused[temp]` |
| M71 | LLR-172.5g | `app.py` | a matched name loaded with the asked spelling | `tc_b100_38_project_load_of_another_case_loads_the_listed_name` |
| M72 | E3 R14 | `app.py` | `list_projects` lists a name ending in a dot or a space | `tc_b100_38_project_list_skips_a_name_ending_in_a_dot_or_space[temp.]`, `[ab ]` |
| M73 | LLR-172.5h | `app.py` | step 0 tests `os.path.isabs` (true for `\x`) | `tc_b100_38_typed_relative_folder_is_refused[root-relative]` |
| M74 | LLR-172.5h | `app.py` | step 0 removed (a relative folder reaches the project route) | `tc_b100_38_typed_relative_folder_is_refused[relative found by the base fallback]`, `[relative junction]` |
| M75 | LLR-172.6 / HLR-172b | `app.py` | the row label is `Label(p.name)` (markup on) | `tc_b100_39_rows_paint_names_literally[markup bold]`, `[markup link]`, `[markup action]`; `at_b100_13_*` |
| M76 | LLR-172.6 (R4) | `app.py` | the label is `safe_text(p.name)` (C0 / C1 only, the E2 design) | `tc_b100_39_rows_paint_names_literally[bidi override U+202E]`, `[unpaired surrogate U+DC80]` |
| M77 | LLR-172.6 | `app.py` | no 120-character clip | `tc_b100_39_rows_paint_names_literally[130 characters]` |
| M78 | LLR-172.6a | `app.py` | `item.data` holds the painted label | `tc_b100_39_picked_row_loads_the_file_as_named[C1 control U+009B]`, `[130 characters]` |
| M79 | HLR-172a (ruling Q3) | `app.py` | the typed dispatcher calls `_handle_load_project` directly (no Load-result panel) | `at_b100_12_outside_load_is_remembered_and_typed_project_path_opens[*]` (panel assertion) |

79 mutants (M01–M79).
