# E5: mutation run summary (batch-100 Inc 8a)

State: `executed`. Wall time 2026-10-30 23:05:38Z to 23:15:43Z UTC.

## Result

- **78 rows in total:** 71 from `experiment-8a/E4-mutants.md` and 7 integration mutants, M-I1 to M-I7, from `experiment-8a/E4-integration-notes.md`.
- **72 KILLED.** One extra arm, R-26b, was also KILLED. It is not counted in the 78.
- **5 SURVIVED:** M-10, M-15, R-10, R-11 and R-19.
- **0 INVALID.** Every edit applied uniquely on the first try and every mutant imported.
- **1 not-run:** R-12.

Every mutant transcript ends with `restored = True`.

## Method

**Sources at the start:** every copy held the integration hashes (sha256[:16]):

| file | hash |
|---|---|
| `app.py` | 8c627b717172ccd8 |
| `manifest_writer.py` | a638b23d2bb861b1 |
| `project_gather_service.py` | 6f2d419ea0d2ee56 |
| `variant_execution_service.py` | 5f2ab3268d9cdc4d |

**Sources at the end:** the same four hashes hold in all four copies and in the real worktree. No source in the worktree was edited.

**Copies:** the mutants ran in four lanes in parallel, each against its own copy of the tree under the session scratchpad:

| lane | copy |
|---|---|
| A, classifier and reopen | `mut8a-b` |
| B1, document write, plan, panel flag, bind | `mut8a-c` |
| B2, Save project carry and drop | `mut8a-d` |
| C, services | `mut8a` |

Each lane:
- ran pytest with cwd = its copy and `PYTHONPATH` = its copy, and confirmed that `s19_app.__file__` resolved to the copy;
- ran all of its named nodes on the unmutated copy first. That record is `mut-baseline-lane{A,B1,B2,C}.txt`. All base runs were GREEN: 29, 18, 16 and 91 passed.

**Runner:** one script, `mutharness/mut.py`, ran every mutant. It:
1. saves the original bytes;
2. requires each old text to occur exactly once;
3. applies the edit and runs the named nodes with `-p no:cacheprovider -q --tb=line -rfE`;
4. restores the bytes and checks the sha256 again;
5. writes the transcript `mut-<id>.txt`. The header holds the edit, the hash before, the command and the cwd. The footer holds the pytest summary, the verdict and `restored`.

**Verdicts:** KILLED was confirmed by reading each failure line for a behavioural assertion, not only by the return code.

**Timing:** only M-26 is killed by a timing assertion alone: Save project took 34.2 s with the mutant. The same node passed on base under the same load in 2.07 s (`mut-M-26-base-rerun.txt`).

## Table

Node prefixes follow E4: DOC = `tests/test_b100_document.py`, SI = `tests/test_b100_save_image.py`, SG = `tests/test_b100_save_guards.py`, PC = `tests/test_b100_project_check.py`, AV = `tests/test_b100_active_variant.py`. The service files are abbreviated: ves = `variant_execution_service.py`, mw = `manifest_writer.py`, pgs = `project_gather_service.py`.

| id | LLR / ruling | file | test (named node) | verdict |
|---|---|---|---|---|
| M-01 | LLR-170.1 | ves | DOC28_reader_refuses_a_value_out_of_form | KILLED |
| M-02 | LLR-170.1 | mw | DOC28_writer_refuses_a_value_out_of_form | KILLED |
| M-03 | LLR-170.1 | ves | DOC28_valid_key_is_carried_not_kept_aside, DOC28_variant_append_keeps_the_key, AV20_writers_carry_the_active_document | KILLED (note 3) |
| M-04 | LLR-170.2 (P-8) | app.py | DOC29_pasted_document_lands_and_is_recorded, SI59_document_row_in_a_fresh_folder | KILLED |
| M-05 | LLR-170.2 | app.py | DOC29_failure_after_the_write_removes_the_document | KILLED |
| M-06 | LLR-170.2 | app.py | DOC29_forced_write_failure_saves_without_the_document | KILLED |
| M-07 | LLR-170.2 / E3 R1 | app.py | DOC29_second_save_of_the_bound_document_writes_nothing | KILLED |
| M-08 | LLR-170.3 (P-8) | app.py | DOC30_reopen_lists_the_recorded_document, SI70_natural_path_load_edit_save_keeps_the_flag | KILLED |
| M-09 | LLR-170.3 / Q5 | app.py | DOC30_reopen_resolves_a_symbol_against_the_project_a2l | KILLED |
| M-10 | LLR-170.3 | app.py | DOC30_missing_document_is_one_missing_problem | **SURVIVED** |
| M-11 | LLR-170.3 / E3 R4 | app.py | DOC30_classifier_outcome[20000-entries], DOC30_hostile_…[20000-entries] | KILLED (outcome assertion, not timing) |
| M-12 | LLR-170.3 / E3 R10 | app.py | DOC30_classifier_outcome[brackets-*], DOC30_hostile_…[brackets-1MiB] | KILLED (RecursionError escapes) |
| M-13 | LLR-170.3 / Q6 | app.py | DOC30_reopen_never_applies_the_entries | KILLED (note 6) |
| M-14 | LLR-167.6 / A3R2-1 | pgs | DOC29_document_inside_the_project_outside_its_home_is_not_placed | KILLED |
| M-15 | LLR-167.6 / A3R2-1 | app.py | DOC29_deleted_file_backed_document_is_not_placed | **SURVIVED** |
| M-16 | LLR-167.6 | pgs | DOC29_identical_changes_json_is_reused | KILLED (note 4) |
| M-17 | LLR-167.6 / LLR-164.2 | app.py | SI59_open_project_carry_sets_the_keys[present, too-large] | KILLED |
| M-18 | LLR-164.2 | pgs | SI59_merge_plans_a_merge_row | KILLED |
| M-19 | LLR-167.8 | app.py | SI70_written_document_clears_the_flag | KILLED |
| M-20 | LLR-167.8 | app.py | SI70_…_keeps_the_flag (3 nodes) | KILLED |
| M-21 | LLR-167.8 / Q2 | app.py | SI70_unparsed_paste_text_keeps_the_flag | KILLED |
| M-22 | LLR-164.2 | app.py | SG05_merge_carries_the_document_and_gathered | KILLED |
| M-23 | LLR-164.2 / E3 R2 | app.py | SG05_merge_drops_…[deleted], SI59_…[deleted] | KILLED |
| M-24 | LLR-164.2 / R8 | app.py | SG05_merge_drops_…[unreadable], SI59_…[unreadable] | KILLED |
| M-25 | LLR-164.2 / R8 refined | app.py | SG05_merge_keeps_a_too_large_document_under_one_second, SI59_…[too-large] | KILLED |
| M-26 | LLR-164.2 / R10 | app.py | SG05_merge_keeps_a_too_large_document_under_one_second | KILLED (timing; base re-run GREEN) |
| M-27 | LLR-164.2 / R3 | app.py | SG05_r3_failed_write_carries_the_target_document | KILLED |
| M-28 | LLR-164.2 / R5 | ves | SG05_r5_refused_target_value_is_kept_aside_and_named, DOC28_refused_value_is_a_keep_reason | KILLED |
| M-29 | LLR-169.2 (A-15) | mw | DOC28_a15_files_records_the_active_document | KILLED |
| M-30 | LLR-169.3 | mw | PC23_active_document_changed_between_write_and_verify | KILLED |
| M-31 | LLR-169.4 | ves | PC24_files_key_of_the_active_document_is_read | KILLED |
| M-32 | LLR-169.4 | ves | PC24_files_key_of_the_active_document_is_read | KILLED |
| M-33 | LLR-169.4 | ves | PC24_derived_from_gets_no_document_exception | KILLED |
| M-34 | LLR-169.5 | mw | PC25_missing_active_document_is_one_problem[without-record] | KILLED |
| M-35 | LLR-169.5 | mw | PC25_missing_active_document_is_one_problem[with-record] | KILLED |
| M-36 | LLR-169.5 (P-B2) | mw | PC25_missing_document_survives_the_no_digests_return | KILLED |
| M-37 | LLR-169.5 / A3-1 | mw | PC25_changed_document_is_named_by_its_project_text | KILLED |
| M-38 | LLR-169.5 / E3 R7 | ves | PC25_r7_missing_variant_never_names_the_document | KILLED |
| R-01 | R4 byte cap | app.py | DOC30_classifier_outcome[one-byte-over-1MiB] | KILLED |
| R-02 | R4 entry cap | app.py | DOC30_classifier_outcome[1001-entries] | KILLED |
| R-03 | R4 boundary | app.py | DOC30_classifier_outcome[exactly-1000-entries] | KILLED |
| R-04 | R8 refined | app.py | SG05_merge_keeps_a_too_large_…, SI59_…[too-large] | KILLED |
| R-05 | R8 refined | app.py | SG05_merge_keeps_a_held_document_with_one_line | KILLED |
| R-06 | R8 refined | app.py | SG05_merge_drops_…[unreadable], SI59_…[unreadable] | KILLED |
| R-07 | R8 refined | app.py | SG05_merge_drops_…[deleted], SI59_…[deleted] | KILLED |
| R-08 | R8 refined | app.py | SG05_r8_target_document_that_is_a_link_is_not_carried, SG05_r8_document_turned_into_a_link_before_the_check_is_dropped | KILLED (note 2) |
| R-09 | R10 / R19 | app.py | DOC30_classifier_outcome[5000-digit-integer], DOC30_hostile_…[5000-digit-integer] | KILLED (ValueError escapes) |
| R-10 | R10 catch set | app.py | DOC30_classifier_outcome[not-utf8] | **SURVIVED** |
| R-11 | R10 catch set | app.py | DOC30_classifier_outcome[truncated] | **SURVIVED** |
| R-12 | R10 catch set | app.py | none | not-run |
| R-13 | R10 count | app.py | DOC30_classifier_outcome[entries-wide-object, entries-long-string] | KILLED |
| R-14 | R10 OSError | app.py | DOC30_classifier_held_file_is_io_error, DOC30_held_document_is_not_readable_and_stays_recorded | KILLED (PermissionError escapes) |
| R-15 | R10 lstat | app.py | DOC30_classifier_junction_home_is_a_link | KILLED |
| R-16 | R15 | app.py | SG05_r15_placed_document_replaces_a_missing_carried_one_silently | KILLED |
| R-17 | R16 | app.py | DOC30_held_document_is_not_readable_and_stays_recorded, SG05_merge_keeps_a_held_document_with_one_line | KILLED by SG05 only (note 7) |
| R-18 | R17 | app.py | DOC30_classifier_symbol_entry_is_ok_with_or_without_context | KILLED |
| R-19 | R17 | app.py | DOC30_classifier_outcome[v1-document] | **SURVIVED** |
| R-20 | R18 | pgs | DOC29_r18_document_behind_a_junctioned_home_is_never_copied | KILLED |
| R-21 | R11 / S3R2-5 | pgs | DOC29_r18_document_behind_a_junctioned_home_is_never_copied | KILLED |
| R-22 | no-a2l_context control (= M-09) | app.py | DOC30_reopen_resolves_a_symbol_against_the_project_a2l | KILLED |
| R-23 | Q6 (= M-13) | app.py | DOC30_reopen_never_applies_the_entries | KILLED |
| R-24 | R6 predicate | ves | DOC28_form_predicate_refuses, DOC28_reader_refuses_…[ESC], DOC28_writer_refuses_…[ESC] | KILLED |
| R-25 | R6 painted | app.py | SG05_merge_drops_…[*] | KILLED (Save drop-line site only; note 5) |
| R-26 | R5 / R6 phrase | ves | DOC28_refused_value_is_a_keep_reason | KILLED (also extra arm R-26b, "names the key": KILLED) |
| R-27 | R9 | app.py | DOC29_file_backed_zero_entries_is_recorded | KILLED |
| R-28 | pre-ruling 1 | ves | DOC28_document_homes_equal_the_gather_homes | KILLED |
| R-29 | pre-ruling 4 | mw | DOC28_writer_refuses_a_sub_folder_files_key_unless_it_is_the_document | KILLED |
| R-30 | pre-ruling 1 suffix | ves | DOC28_form_predicate_accepts | KILLED |
| R-31 | P5 | ves | DOC28_reader_null_and_absent_are_none | KILLED |
| R-32 | R12 bind spelling | app.py | DOC29_r12_bind_keeps_the_unresolved_spelling | KILLED |
| R-33 | R13 | app.py | SG05_r13_open_project_save_does_not_carry_gathered | KILLED |
| M-I1 | R13 (integration) | app.py | SG05_r13_open_project_save_does_not_carry_gathered | KILLED |
| M-I2 | R12 (integration) | app.py | DOC29_r12_bind_keeps_the_unresolved_spelling | KILLED |
| M-I3 | R8 refined (integration) | app.py | SG05_r8_… (2 nodes) | KILLED (note 2) |
| M-I4 | ruling 1 | ves | DOC30_not_readable_document_paints_the_next_step_of_its_reason | KILLED ([too_large], [io_error]) |
| M-I5 | ruling 3 | ves | DOC30_linked_document_is_one_not_readable_row | KILLED ([recorded]) |
| M-I6 | ruling 3 | ves | DOC30_linked_document_is_one_not_readable_row, DOC30_refused_record_is_one_not_readable_row_and_no_reopen | KILLED |
| M-I7 | ruling 2 | pgs | SI59_planning_writes_nothing_and_hashes_no_payload | KILLED |

## Survivors

No test was changed. Each diagnosis is for the corrective pass.

| id | class | why |
|---|---|---|
| M-10 | equivalent mutant (observable) | `merge_load_problems` keeps one problem per file text. The extra `missing` row from the reopen merges with the `missing` row from `check_project_files` for the same file, so the painted announcement is identical. The described behaviour cannot be observed at Load. E4's expectation was wrong. |
| M-15 | wrong target (test never reaches the arm) | `classify_active_document` returns `missing` for a source deleted after its load, so the plan never calls the digest and the `except OSError` arm is not executed. The mutant is not equivalent: it would raise for a source that passes the `lstat` but fails its read, or for a classify-then-digest race. A test needs a source that exists but whose read raises `OSError`. |
| R-10 | equivalent mutant | `UnicodeDecodeError` is a subclass of `ValueError`, which stays in the catch set. No test can kill it while `ValueError` is caught. |
| R-11 | equivalent mutant | `json.JSONDecodeError` is a subclass of `ValueError`. Same reason as R-10. |
| R-19 | vacuous fixture (wrong target) | `V1_DOCUMENT` in `tests/support/b100_manifests.py` has no `entries` key. It is refused earlier as "no entries list" and never reaches the file-level codes step. A probe with a v1 body that has `"entries": []` showed that `parse_change_document` reports `CHG-V1-FORMAT`, so the arm is reachable. A fixture with an entries list would kill the mutant. |

## Not run

- **R-12:** `TypeError` removed from the classifier's catch set. Named gap: no input has been found that raises `TypeError` in the classifier, so no test exists. Recorded in `mut-R-12.txt`.

## Notes on the kills

1. **Same behaviour, different site.** These pairs apply the same behaviour at different code sites, and both mutants in each pair were killed: M-23/R-07, M-24/R-06, M-25/R-04, R-08/M-I3, R-33/M-I1, R-32/M-I2. R-22 and R-23 repeat M-09 and M-13, as E4 intended. M-26 removes the caps in `recorded_document_state`, the only place they exist, so it is M-11's edit seen from the Save path.
2. **R-08 and M-I3 are caught downstream.** The kill is `SG05_r8_document_turned_into_a_link_before_the_check_is_dropped` at the "Saved project to" check. With the mutant, the link is carried, the manifest writer's own link guard refuses the write, and the whole save fails. The drop assertion in the test is never reached. This is still behavioural. The end-to-end node `…_link_is_not_carried` passes under both mutants by design: the reader refuses the link earlier, on the R5 path, and never consults the drop set.
3. **M-03 kills indirectly in some nodes.** The DOC28 carry node fails directly. The four AV20 writer nodes and DOC28_variant_append fail on "timed out waiting for the manifest rewrite" or "did not land", because an unknown key makes every writer refuse. They never read the key's value back.
4. **M-16 dies at the save, not at the plan row.** The pre-write check refuses the save, so the test fails on the status line rather than on the `keep` row it names.
5. **R-25 was probed at one painting site:** Save project's drop line for a carried record. The other sites the ruling names (document-write failure, file-backed document not placed, Load reopen line) are separate code paths and were not probed by mutant here.
6. **M-13/R-23 apply site.** No image is installed at reopen time, so the apply was placed in `_handle_load_project` right after the install. That realises "the reopen's entries applied to the loaded image".
7. **R-17's DOC30 node does not guard the app's `io_error` reason at Load.** `manifest_writer.py` paints its own "could not be read" row for the held file. That row has the same rank and comes first, so the app's row is merged away. Only the SG05 node guards `_DOCUMENT_REASON[io_error]`.
8. **Mutants realised approximately.** The table describes behaviour, not lines, so some needed interpretation:
   - M-11 and R-01 remove the bounded read along with the cap.
   - M-33 feeds the accepted document into the `derived_from` parser, which takes 3 edits.
   - R-20 skips the reparse-point walk of the folders above the source.
   - R-31 turns an explicit null into an issue at the call site.
   - M-16 makes both the keep row and the reused-placement row `new`.

   Each edit is printed verbatim in its transcript header.
9. **R-27 is killed by `FileNotFoundError`.** It comes from the test's `read_bytes()` of the expected copy (DOC :734). With no plan row, the gather never copies the file. That is behavioural, not a crash in the harness or the app.

## Files

- Transcripts: `mut-<id>.txt` in this folder (78 rows, plus `mut-R-26b.txt` and `mut-M-26-base-rerun.txt`).
- Base runs: `mut-baseline-laneA.txt`, `mut-baseline-laneB1.txt`, `mut-baseline-laneB2.txt`, `mut-baseline-laneC.txt`.
- Runner and specs: `mutharness/mut.py` and `spec-{A,B1,B2,C}.py` in the session scratchpad, outside the repository.
