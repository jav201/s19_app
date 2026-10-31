# Inc 9a — E4 mutation results (M01–M79)

Run against the 9a implementation copy (`mut9a` scratchpad). Verdicts follow the
E4 tester protocol: **KILLED** = a named node failed on an assertion; **SURVIVED**
= all named nodes passed; **INVALID** = mutant did not import/compile (none here).
`LOCALAPPDATA` was pinned to the scratch folder for every run, and both frozen
files' sha256 (`workspace.py` `a3342ed048ebe157`, `app.py` `6223201188232562`)
were identical before the first and after the last mutant; `C:/Users/jjgh8/AppData/Local/s19_app`
did not exist before or after.

| id | requirement | file | test | verdict |
|---|---|---|---|---|
| M01 | LLR-172.1 | workspace.py | store_lives_under_localappdata; no_usable...writes_no_store[unset] | KILLED |
| M02 | LLR-172.1 | workspace.py | store_lives_under_localappdata (base); twenty_five_outside_loads | KILLED |
| M03 | LLR-172.1 / S9 | workspace.py | store_lives_under_localappdata (lad2) | KILLED |
| M04 | LLR-172.1f | workspace.py | unusable...[relative]; no_usable...writes_no_store[relative] | KILLED |
| M05 | LLR-172.1f | workspace.py | unusable...[unset]; no_usable...writes_no_store[unset] | KILLED |
| M06 | LLR-172.1f (R7) | workspace.py | no_usable...writes_no_store[absent folder] | KILLED |
| M07 | LLR-172.1f (R5) | workspace.py | unusable...[UNC] | KILLED |
| M08 | LLR-172.1a/.2h | workspace.py | recent_kind...[...a.srec-s19], [...A.SREC-s19] | KILLED |
| M09 | LLR-172.1a | workspace.py | record_puts_newest_first_with_its_kind | KILLED |
| M10 | LLR-172.1a (R1) | workspace.py | record_does_not_resolve_a_junction | KILLED |
| M11 | LLR-172.1a (S7) | app.py | outside_load_records_the_source_not_the_work_copy | KILLED |
| M12 | LLR-172.1a (S7) | workspace.py | record_stores_the_lexical_absolute_path | KILLED |
| M13 | LLR-172.1b | workspace.py | same_source_keeps_one_entry_in_first_place | KILLED |
| M14 | LLR-172.1b | workspace.py | same_source_keeps_one_entry_in_first_place (A,B,A) | KILLED |
| M15 | LLR-172.1b | workspace.py | case_spelling_of_one_source_keeps_one_entry | KILLED |
| M16 | LLR-172.1c | workspace.py | store_holds_at_most_twenty_entries | KILLED |
| M17 | LLR-172.1c | workspace.py | store_holds_at_most_twenty_entries | KILLED |
| M18 | LLR-172.1d | app.py | load_failing_before_its_copy_records_nothing (over-cap) | KILLED |
| M19 | LLR-172.1d (Q1) | app.py | source_that_copies_then_fails_to_parse_is_recorded | SURVIVED |
| M20 | LLR-172.1e | app.py | source_inside_the_work_area_is_not_recorded | KILLED |
| M21 | LLR-172.1g | workspace.py | linked_store_folder_is_not_written | SURVIVED |
| M22 | LLR-172.1h | workspace.py | store_is_replaced_through_unique_staging_files | KILLED |
| M23 | LLR-172.1h | workspace.py | store_is_replaced_through_unique_staging_files | KILLED |
| M24 | LLR-172.1i | workspace.py | failed_store_write_returns_false...[replace refused]; ...never_fails_the_load[replace refused-data] | SURVIVED |
| M25 | LLR-172.1i (S6) | app.py | failed_store_write_never_fails_the_load[*] | KILLED |
| M26 | LLR-172.1i (S6) | workspace.py | failed_store_write_returns_false[*]; ...never_fails_the_load[*] | KILLED |
| M27 | LLR-172.1i | workspace.py | failed_store_write_returns_false...[replace refused] | KILLED |
| M28 | LLR-172.1i | workspace.py | record_with_an_embedded_nul_never_raises | SURVIVED |
| M29 | LLR-172.1j | workspace.py | record_writes_back_only_accepted_entries | KILLED |
| M30 | LLR-172.1k | workspace.py | unreadable_store_is_left_unchanged[open refused], [read failed] | KILLED |
| M31 | LLR-172.1l | workspace.py | source_the_read_would_drop_is_not_recorded | KILLED |
| M32 | LLR-172.1m | workspace.py | written_store_fits_the_read_cap | KILLED |
| M33 | LLR-172.1m | workspace.py | written_store_fits_the_read_cap (paths) | KILLED |
| M34 | HLR-172 | app.py | twenty_five_outside_loads; at_b100_12_* | KILLED |
| M35 | LLR-172.2 | workspace.py | read_returns_the_first_twenty_accepted_in_order | KILLED |
| M36 | LLR-172.2 | workspace.py | read_returns_the_first_twenty_accepted_in_order (5-entry) | KILLED |
| M37 | LLR-172.2a (S-12) | workspace.py | oversized_store_reads_as_too_large (65 536) | KILLED |
| M38 | LLR-172.2a (S-12) | workspace.py | oversized_store_reads_as_too_large (read-size spy) | KILLED |
| M39 | LLR-172.2b | workspace.py | store_of_the_wrong_shape_reads_as_empty[top-level list] | KILLED |
| M40 | LLR-172.2b | workspace.py | store_of_the_wrong_shape_reads_as_empty[version 2 with an entry] | KILLED |
| M41 | LLR-172.2b (R-5) | workspace.py | ...wrong_shape...[version true], [version 1.0] | KILLED |
| M42 | LLR-172.2c | workspace.py | unreadable_store_reads_as_could_not_be_read[open refused] | SURVIVED |
| M43 | LLR-172.2c | workspace.py | unreadable_store_reads_as_could_not_be_read[directory at the store path] | KILLED |
| M44 | LLR-172.2c (R6) | workspace.py | unreadable...[store file a symbolic link], [store folder a junction] | KILLED |
| M45 | LLR-172.2d | workspace.py | missing_store_reads_as_empty_with_no_problem | KILLED |
| M46 | LLR-172.2e | workspace.py | entry_path_checks_drop_entries[LLR-172.2e ...] | KILLED |
| M47 | LLR-172.2f | workspace.py | entry_path_checks_drop_entries[LLR-172.2f ...] | KILLED |
| M48 | LLR-172.2g | workspace.py | entry_path_checks_drop_entries[LLR-172.2g ...] | KILLED |
| M49 | LLR-172.2h | workspace.py | entry_whose_kind_does_not_match_its_suffix_is_dropped | KILLED |
| M50 | LLR-172.2i | workspace.py | malformed_entry_is_dropped | KILLED |
| M51 | LLR-172.2j (R-4) | workspace.py | store_read_never_raises ([ × 65 536) | KILLED |
| M52 | LLR-172.2j | workspace.py | store_of_the_wrong_shape_reads_as_empty[not utf-8] | KILLED |
| M53 | LLR-172.3 (R-9) | workspace.py | read_logs_no_entry_and_writes_nothing | KILLED |
| M54 | LLR-172.3 (R-9) | manifest_writer.py | seeded_recent_entries_never_reach_the_base_folder; loaded_source_path_stays_out_of_project_files | KILLED |
| M55 | LLR-172.4 | app.py | one_function_enumerates_the_temp_folder | KILLED |
| M56 | LLR-172.4a | workspace.py | lister_returns_the_regular_files_sorted | KILLED |
| M57 | LLR-172.4a | workspace.py | lister_returns_the_regular_files_sorted | SURVIVED |
| M58 | LLR-172.4b | workspace.py | file_link_in_temp_is_not_listed | KILLED |
| M59 | LLR-172.4c | workspace.py | unlistable_temp_gives_an_empty_list[listing refused], [temp a regular file]; ...shows_no_rows[listing refused] | KILLED |
| M60 | LLR-172.4c (R11) | workspace.py | unlistable_temp...[temp a junction]; ...shows_no_rows[temp a junction] | KILLED |
| M61 | LLR-172.5 (R3) | app.py | typed_project_folder_loads_the_project[name in upper case] | SURVIVED |
| M62 | LLR-172.5 | app.py | typed_project_folder_loads_the_project[work area in upper case] | KILLED |
| M63 | LLR-172.5a | app.py | typed_project_json_loads_its_project[PROJECT.JSON] | KILLED |
| M64 | LLR-172.5b (R3) | app.py | typed_folder_that_is_not_a_project_is_refused[temp::$INDEX_ALLOCATION], [8.3 name of templates] | SURVIVED |
| M65 | LLR-172.5b | app.py | typed_folder_that_is_not_a_project_is_refused[temp] | SURVIVED |
| M66 | LLR-172.5c | app.py | typed_folder_outside_the_work_area_is_refused[outside folder] | KILLED |
| M67 | LLR-172.5d | app.py | typed_path_through_a_junction_is_refused[junction folder] | KILLED |
| M68 | LLR-172.5e | app.py | typed_unsupported_file_is_refused[firmware] | KILLED |
| M69 | LLR-172.5f | app.py | typed_path_that_does_not_exist_is_refused[missing file] | KILLED |
| M70 | LLR-172.5g | app.py | project_load_of_an_unlisted_name_is_refused[temp] | KILLED |
| M71 | LLR-172.5g | app.py | project_load_of_another_case_loads_the_listed_name | KILLED |
| M72 | E3 R14 | app.py | project_list_skips_a_name_ending_in_a_dot_or_space[temp.], [ab ] | KILLED |
| M73 | LLR-172.5h | app.py | typed_relative_folder_is_refused[root-relative] | KILLED |
| M74 | LLR-172.5h | app.py | typed_relative_folder_is_refused[relative found by the base fallback], [relative junction] | KILLED |
| M75 | LLR-172.6 / HLR-172b | app.py | rows_paint_names_literally[markup bold], [markup link], [markup action]; at_b100_13_* | KILLED |
| M76 | LLR-172.6 (R4) | app.py | rows_paint_names_literally[bidi override U+202E], [unpaired surrogate U+DC80] | KILLED |
| M77 | LLR-172.6 | app.py | rows_paint_names_literally[130 characters] | KILLED |
| M78 | LLR-172.6a | app.py | picked_row_loads_the_file_as_named[C1 control U+009B], [130 characters] | KILLED |
| M79 | HLR-172a (Q3) | app.py | at_b100_12_outside_load_is_remembered_and_typed_project_path_opens[*] (panel) | KILLED |

## Counts

- KILLED: **70**
- SURVIVED: **9**
- INVALID: **0**

## Survivors — why

- **M21** (workspace.py, LLR-172.1g) — equivalent mutant. Removing the write-side
  `_is_reparse_point(folder)` check is masked by the read-side
  `_is_reparse_point(store.parent)` check in `read_recent_sources`, which
  `record_recent_source` calls: the read returns "could not be read", so the record
  still returns False and writes nothing through the junction.
- **M24** (workspace.py, LLR-172.1i) — equivalent mutant. Removing the inner
  `except OSError` around the staging write/replace is masked by the outer
  `except Exception` guard (which still returns False), and the `finally` still
  unlinks the staging file, so the behaviour is byte-for-byte unchanged.
- **M28** (workspace.py, LLR-172.1i) — equivalent mutant. Dropping `ValueError`
  from the inner `abspath` catch is masked by the outer `except Exception`
  guard, which still returns False, so `record_recent_source` still "never raises".
- **M42** (workspace.py, LLR-172.2c) — equivalent mutant. Removing the open's
  `except OSError` is masked by the outer `except Exception` guard, which still
  returns "could not be read"; the open-refused arm still passes.
- **M57** (workspace.py, LLR-172.4a) — weak test. `os.scandir` on this filesystem
  already returns the three files in sorted (name) order, so removing
  `files.sort(...)` is not observable by the order arm.
- **M19** (app.py, LLR-172.1d) — weak test. The `bad.s19` in
  `source_that_copies_then_fails_to_parse_is_recorded` "installs" successfully
  (current_file is set with 2 record-level errors, no exception), so moving the
  record to `_apply_prepared_load` still records it; the node cannot distinguish
  "record after copy" from "record after install".
- **M61** (app.py, LLR-172.5) — wrong target. Returning `typed_name` from
  `_typed_load_route` is re-normalised by `_handle_load_project`'s
  `name = match` (its own listing match), so `current_project` is still "ab".
  The case arm is only killed by M71 (removing `name = match`).
- **M64** (app.py, LLR-172.5b) — wrong target. The route-level reserved-home test
  is masked by `_handle_load_project`'s own `list_projects()` listing match,
  which still refuses the stream/8.3 spellings with "not a project".
- **M65** (app.py, LLR-172.5b) — wrong target. Removing the route's listing step
  is masked by `_handle_load_project`'s own listing match, which still refuses
  `temp` with "not a project".
