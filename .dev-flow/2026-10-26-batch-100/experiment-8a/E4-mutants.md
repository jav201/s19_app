# E4 — mutant table (batch-100 Inc 8a)

One row per LLR negative control and per ruling mutant. Mutants are described by behaviour (position + operation), never by line: the implementers' code was not final when this was written. "Expected RED" is the node that must fail when the mutant is applied; E5 runs them (mutants of the new arms only). Planned, not run: state `planned`.

Node prefixes: `DOC` = `tests/test_b100_document.py::test_tc_b100_`, `SI` = `tests/test_b100_save_image.py::test_tc_b100_`, `SG` = `tests/test_b100_save_guards.py::test_tc_b100_`, `PC` = `tests/test_b100_project_check.py::test_tc_b100_`, `AV` = `tests/test_b100_active_variant.py::test_tc_b100_`.

## LLR negative controls

| # | Source | Target file | Mutation (behaviour) | Expected RED |
|---|---|---|---|---|
| M-01 | LLR-170.1 | variant_execution_service.py | reader: skip the form predicate (prefix/home rule) after the text rules | `DOC28_reader_refuses_a_value_out_of_form['firmware.s19'-…]`, `['project.json'-…]`, `['patches/x.txt'-…]` |
| M-02 | LLR-170.1 | manifest_writer.py | writer: drop the `is_active_document_form` check before emitting | `DOC28_writer_refuses_a_value_out_of_form['firmware.s19']` (and 9 further params) |
| M-03 | LLR-170.1 | variant_execution_service.py | remove `"active_document"` from `KNOWN_MANIFEST_KEYS` | `DOC28_valid_key_is_carried_not_kept_aside`, `DOC28_variant_append_keeps_the_key`, `AV20_writers_carry_the_active_document[*]` |
| M-04 | LLR-170.2 (P-8) | app.py | Save project never writes the pasted document | `DOC29_pasted_document_lands_and_is_recorded`, `SI59_document_row_in_a_fresh_folder` |
| M-05 | LLR-170.2 | app.py | the written document is not added to the save's placed files (rollback skips it) | `DOC29_failure_after_the_write_removes_the_document` |
| M-06 | LLR-170.2 | app.py | after a failed document write, record the session landing as `active_document` anyway | `DOC29_forced_write_failure_saves_without_the_document` |
| M-07 | LLR-170.2 / E3 R1 | app.py | second Save project rewrites the bound file in place (or lands `changes_1.json`) | `DOC29_second_save_of_the_bound_document_writes_nothing` |
| M-08 | LLR-170.3 (P-8) | app.py | the reopen is not called (editor document stays empty) | `DOC30_reopen_lists_the_recorded_document`, `SI70_natural_path_load_edit_save_keeps_the_flag` (vacuity line) |
| M-09 | LLR-170.3 / Q5 (C1) | app.py | the reopen parses with `a2l_context=None` (or before the A2L load) | `DOC30_reopen_resolves_a_symbol_against_the_project_a2l` |
| M-10 | LLR-170.3 | app.py | the reopen also adds `missing` for an absent document | `DOC30_missing_document_is_one_missing_problem` |
| M-11 | LLR-170.3 / E3 R4 | app.py | both caps removed in `recorded_document_state` | `DOC30_classifier_outcome[20000-entries]` (outcome + < 1 s), `DOC30_hostile_document_is_one_not_readable_under_one_second[20000-entries]` |
| M-12 | LLR-170.3 / E3 R10 | app.py | `RecursionError` removed from the classifier's catch set | `DOC30_classifier_outcome[brackets-1MiB]`, `[brackets-under-entries]`, `DOC30_hostile_…[brackets-1MiB]` |
| M-13 | LLR-170.3 / Q6 | app.py | the reopen applies the document's entries to the loaded image | `DOC30_reopen_never_applies_the_entries` |
| M-14 | LLR-167.6 / A3R2-1 | app.py or project_gather_service.py | plan a document row for a document inside the project but outside its home (no `inside_elsewhere` class) | `DOC29_document_inside_the_project_outside_its_home_is_not_placed` (plan 0 rows) |
| M-15 | LLR-167.6 / A3R2-1 | app.py | let the document digest's `OSError` propagate (refuse the save) | `DOC29_deleted_file_backed_document_is_not_placed` |
| M-16 | LLR-167.6 | project_gather_service.py | the document row's action is always `new` | `DOC29_identical_changes_json_is_reused` (plan `keep`) |
| M-17 | LLR-167.6 / LLR-164.2 | app.py | the plan's `manifest_keys` ignore a carried `active_document` | `SI59_open_project_carry_sets_the_keys[present]`, `[too-large]` |
| M-18 | LLR-164.2 | project_gather_service.py | the merge `project.json` row keeps `rewrite` | `SI59_merge_plans_a_merge_row` |
| M-19 | LLR-167.8 | app.py | skip the panel's `mark_saved` after a written document | `SI70_written_document_clears_the_flag` |
| M-20 | LLR-167.8 | app.py | call the panel's `mark_saved` after every completed save | `SI70_file_backed_document_from_outside_keeps_the_flag`, `SI70_natural_path_load_edit_save_keeps_the_flag`, `SI70_failed_document_write_keeps_the_flag` |
| M-21 | LLR-167.8 / Q2 | app.py | `_save_clears_panel_flag` ignores unparsed paste text | `SI70_unparsed_paste_text_keeps_the_flag` |
| M-22 | LLR-164.2 | app.py | the merge passes the session's `active_document` (`None`) when the session has no document | `SG05_merge_carries_the_document_and_gathered` |
| M-23 | LLR-164.2 / E3 R2 | app.py | carry an `active_document` whose file is absent | `SG05_merge_drops_a_faulty_carried_document_with_one_line[deleted]`, `SI59_open_project_carry_sets_the_keys[deleted]` |
| M-24 | LLR-164.2 / R8 | app.py | carry an `unreadable` document | `SG05_merge_drops_…[unreadable]`, `SI59_open_project_carry_sets_the_keys[unreadable]` |
| M-25 | LLR-164.2 / R8 refined | app.py | drop a `too_large` document | `SG05_merge_keeps_a_too_large_document_under_one_second`, `SI59_open_project_carry_sets_the_keys[too-large]` |
| M-26 | LLR-164.2 / R10 | app.py | Save project's check parses without the caps | `SG05_merge_keeps_a_too_large_document_under_one_second` (< 1 s) |
| M-27 | LLR-164.2 / R3 | app.py | drop the target's value after a failed document write | `SG05_r3_failed_write_carries_the_target_document` |
| M-28 | LLR-164.2 / R5 | app.py / variant_execution_service.py | drop a refused target value with no `.previous-<UTC>` copy | `SG05_r5_refused_target_value_is_kept_aside_and_named`, `DOC28_refused_value_is_a_keep_reason` |
| M-29 | LLR-169.2 (A-15) | manifest_writer.py | `project_file_records` leaves the active document out | `DOC28_a15_files_records_the_active_document` |
| M-30 | LLR-169.3 | manifest_writer.py | `active_document` left out of the verify drift domain | `PC23_active_document_changed_between_write_and_verify` |
| M-31 | LLR-169.4 | variant_execution_service.py | the `files` exception removed (the document's own key refused) | `PC24_files_key_of_the_active_document_is_read` |
| M-32 | LLR-169.4 | variant_execution_service.py | the exception widened to any key under a document home | `PC24_files_key_of_the_active_document_is_read` (other.json arm) |
| M-33 | LLR-169.4 | variant_execution_service.py | the exception extended to `derived_from` | `PC24_derived_from_gets_no_document_exception` |
| M-34 | LLR-169.5 | manifest_writer.py | `check_project_files` skips an unrecorded active document | `PC25_missing_active_document_is_one_problem[without-record]` |
| M-35 | LLR-169.5 | manifest_writer.py | the missing-document helper also runs for a recorded document | `PC25_missing_active_document_is_one_problem[with-record]` |
| M-36 | LLR-169.5 (P-B2) | manifest_writer.py | the document check placed after the `no digests saved` return | `PC25_missing_document_survives_the_no_digests_return` |
| M-37 | LLR-169.5 / A3-1 | manifest_writer.py | the document's record named by `path.name` ("boost.json") | `PC25_changed_document_is_named_by_its_project_text` |
| M-38 | LLR-169.5 / E3 R7 | variant_execution_service.py | `_missing_recorded` without the primary-data-suffix restriction | `PC25_r7_missing_variant_never_names_the_document` |

## Ruling mutants

| # | Ruling | Target file | Mutation (behaviour) | Expected RED |
|---|---|---|---|---|
| R-01 | R4 byte cap | app.py | byte cap removed (entry cap kept) | `DOC30_classifier_outcome[one-byte-over-1MiB]` (`ok` instead of `too_large`) |
| R-02 | R4 entry cap | app.py | entry cap removed (byte cap kept) | `DOC30_classifier_outcome[1001-entries]` |
| R-03 | R4 boundary | app.py | entry cap compared with `>=` | `DOC30_classifier_outcome[exactly-1000-entries]` |
| R-04 | R8 refined | app.py | Save project drops on `too_large` | `SG05_merge_keeps_a_too_large_document_under_one_second`, `SI59_open_project_carry_sets_the_keys[too-large]` |
| R-05 | R8 refined | app.py | Save project drops on `io_error` | `SG05_merge_keeps_a_held_document_with_one_line` |
| R-06 | R8 refined | app.py | Save project keeps on `unreadable` | `SG05_merge_drops_…[unreadable]`, `SI59_open_project_carry_sets_the_keys[unreadable]` |
| R-07 | R8 refined | app.py | Save project keeps on `missing` | `SG05_merge_drops_…[deleted]`, `SI59_…[deleted]` |
| R-08 | R8 refined | app.py | Save project keeps on `link` | none — gap (classifier-level `DOC30_classifier_linked_file_is_a_link` only) |
| R-09 | R10 catch set | app.py | `ValueError` removed (R19) | `DOC30_classifier_outcome[5000-digit-integer]`, `DOC30_hostile_…[5000-digit-integer]` |
| R-10 | R10 catch set | app.py | `UnicodeDecodeError` removed | `DOC30_classifier_outcome[not-utf8]` |
| R-11 | R10 catch set | app.py | `JSONDecodeError` removed | `DOC30_classifier_outcome[truncated]` |
| R-12 | R10 catch set | app.py | `TypeError` removed | none — gap (no input found that raises it) |
| R-13 | R10 count | app.py | count `len(entries)` without checking it is a list | `DOC30_classifier_outcome[entries-wide-object]`, `[entries-long-string]` (`too_large` instead of `unreadable`) |
| R-14 | R10 OSError | app.py | an `OSError` on open re-raised (not `io_error`) | `DOC30_classifier_held_file_is_io_error`, `DOC30_held_document_is_not_readable_and_stays_recorded` |
| R-15 | R10 lstat | app.py | the home's `lstat` skipped (only the file checked) | `DOC30_classifier_junction_home_is_a_link` |
| R-16 | R15 | app.py | paint the drop line for a carried record even when a placed session document replaces it | `SG05_r15_placed_document_replaces_a_missing_carried_one_silently` |
| R-17 | R16 | app.py | `io_error` painted with the generic reason | `DOC30_held_document_is_not_readable_and_stays_recorded`, `SG05_merge_keeps_a_held_document_with_one_line` |
| R-18 | R17 | app.py | step (5): any ERROR finding → `unreadable` | `DOC30_classifier_symbol_entry_is_ok_with_or_without_context` |
| R-19 | R17 | app.py | `CHG-V1-FORMAT` left out of the file-level codes | `DOC30_classifier_outcome[v1-document]` |
| R-20 | R18 | project_gather_service.py | `classify_active_document` `lstat`s only the source file, not its parent folder | `DOC29_r18_document_behind_a_junctioned_home_is_never_copied` |
| R-21 | R11 / S3R2-5 | project_gather_service.py | the source resolved before the class decision | `DOC29_r18_document_behind_a_junctioned_home_is_never_copied` |
| R-22 | no-`a2l_context` control | app.py | the reopen passes no A2L context | `DOC30_reopen_resolves_a_symbol_against_the_project_a2l` (= M-09) |
| R-23 | Q6 no re-apply | app.py | the reopen applies entries | `DOC30_reopen_never_applies_the_entries` (= M-13) |
| R-24 | R6 predicate | variant_execution_service.py | no control-character check in `is_active_document_form` | `DOC28_form_predicate_refuses['patches/\x1b]0;x\x07a.json']`, `DOC28_reader_refuses_…[ESC]`, `DOC28_writer_refuses_…[ESC]` |
| R-25 | R6 painted | app.py | a reader code / exception class painted in a document status line | `DOC29_forced_write_failure_saves_without_the_document`, `DOC29_deleted_file_backed_document_is_not_placed`, `DOC30_truncated_document_is_one_not_readable`, `SG05_merge_drops_…[*]` |
| R-26 | R5 / R6 phrase | variant_execution_service.py | `manifest_keep_reason` ignores a refused document, or names the key | `DOC28_refused_value_is_a_keep_reason` |
| R-27 | R9 | app.py | the ≥1-entry rule applied to a file-backed document | `DOC29_file_backed_zero_entries_is_recorded` |
| R-28 | pre-ruling 1 | variant_execution_service.py | `ACTIVE_DOCUMENT_HOMES` drifts from the gather's homes | `DOC28_document_homes_equal_the_gather_homes` |
| R-29 | pre-ruling 4 | manifest_writer.py | the writer accepts a sub-folder `files` key other than the document | `DOC28_writer_refuses_a_sub_folder_files_key_unless_it_is_the_document` |
| R-30 | pre-ruling 1 suffix | variant_execution_service.py | `.json` compared case-sensitively | `DOC28_form_predicate_accepts['patches/boost.JSON']` |
| R-31 | P5 | variant_execution_service.py | `"active_document": null` gives an issue | `DOC28_reader_null_and_absent_are_none` |
| R-32 | R12 bind spelling | app.py | the bind stores `PlacementResult.path` (resolved) | none — gap (no junction-above-anchor node) |
| R-33 | R13 | app.py | `gathered` carried for an open-project save | none — gap |

**Count:** 38 LLR rows + 33 ruling rows = **71 rows**; 67 name an expected RED node (R-22 and R-23 repeat M-09 and M-13 for the ruling index), 4 are named gaps (R-08, R-12, R-32, R-33).
