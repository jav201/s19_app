# E4 — tester notes (batch-100 Inc 8a)

Author: tester agent (E4, parallel to the three implementers). No file under `s19_app/` was edited. Nothing committed.
Spec read: `codewire/proto-8a-app.md`, `proto-8a-writer-gather.md`, `proto-8a-reader.md`, `codewire/interfaces-8a.md`, `E3-rulings.md` (R1–R19), `01-requirements.md` (HLR-170, LLR-170.1–170.3, LLR-167.6, LLR-167.8, LLR-164.2, LLR-169.2–169.5, §3 token rows), the orchestrator note to E4 (D-E4-1, D-E4-2, `details["key"]`), `E4-reader-notes.md`.

## 1. Re-pins (old → new → requirement)

| # | Module::node (old) | New node and assertion | Requirement |
|---|---|---|---|
| RP-1 | `tests/test_b100_save_image.py::test_tc_b100_70_unwritten_document_keeps_the_flag` — Save project of a typed (no-file) document → `dirty_after is True` | `test_tc_b100_70_written_document_clears_the_flag` — the same scene → `P1/patches/changes.json` written, `dirty_after is False`, and a following Patch Editor Load raises 0 `LoadGuardScreen` | LLR-167.8 (LED .61, LED .72; C5: "Inc 5's `test_tc_b100_70_unwritten_document_keeps_the_flag` is re-pinned at Inc 8a: its typed document is now written, so it becomes the first arm") |

No `replace`-action expectation existed in the suite (`grep '"replace"\|PLAN_ACTION_REPLACE' tests/test_b100_*.py` → only `os.replace` / `errors="replace"`). The house helper `_assert_plan_equals_tree` (save_image) still raises on any action other than `new` / `rewrite` / `keep`; the Inc 8a merge arm therefore asserts the `merge` row directly and does not call that helper. No other existing node was changed.

Not re-pinned, flagged for the census: (a) any existing node that lists a project folder's files after a Save project with a pasted entry now also sees `patches/changes.json` (LLR-170.2); I did not run the suite to find them (brief: no census). (b) The session-snapshot census (A3-10) must list `_parsed_paste_text`; the existing census node is the control, unchanged.

## 2. Tests written

| Module | New test functions | Collected nodes | Re-pinned |
|---|---|---|---|
| `tests/test_b100_document.py` (new) | 49 | 128 | — |
| `tests/test_b100_project_check.py` | 9 | 10 | 0 |
| `tests/test_b100_save_image.py` | 9 (4 TC-59, 5 TC-70 incl. RP-1) | 12 | 1 (RP-1) |
| `tests/test_b100_save_guards.py` | 9 | 10 | 0 |
| `tests/test_b100_active_variant.py` | 1 | 4 | 0 |
| **Total** | **77** | **164** | **1** |

Helpers added (no `s19_app` import at module level): `tests/support/b100_projects.py` — `seed_document_project`, `change_document_bytes`, `address_entry`, `symbol_entry`, `file_record_of`, `junction_home`, `held_exclusively` (a real share-mode-0 `CreateFileW` hold, not a mock), `StatusLog` (full `set_status` messages), `run_app`, `wait_for`, `load_image`, `load_project` (returns the handler's wall time), `save_project`, `tree_files`; `tests/support/b100_manifests.py` — the hostile documents (1 048 577 bytes, 1 000 / 1 001 / 20 000 entries, `[`×1 MiB, `{"entries":`+`[`×10⁶, `"entries": 5`, the 5 000-digit integer, a 900 000-char and a 1 001-key `entries`, `{`, v1, non-UTF-8, empty entries).

## 3. Requirement → test coverage

| Requirement / arm | Nodes (all in the module named) |
|---|---|
| LLR-170.1 / TC-B100-28 | `test_b100_document.py`: `form_predicate_accepts|refuses|is_total`, `document_homes_equal_the_gather_homes`, `writer_and_reader_round_trip`, `absent_key_is_byte_identical`, `reader_refuses_a_value_out_of_form` (18 values, codes per pre-ruling 6, `details["key"]`), `document_finding_is_kept_first_beside_a_full_batch` (D-E4-2), `reader_null_and_absent_are_none`, `reader_accepts_a_document_absent_from_disk`, `writer_refuses_a_value_out_of_form` (12), `writer_refusal_writes_no_bytes`, `writer_refuses_a_sub_folder_files_key_unless_it_is_the_document`, `writer_refuses_a_junction_home`, `valid_key_is_carried_not_kept_aside`, `refused_value_is_a_keep_reason` (D-E4-1 phrase, R6), `variant_append_keeps_the_key` |
| LLR-169.2 A-15 (run in TC-28) | `test_tc_b100_28_a15_files_records_the_active_document`, `_a15_absent_document_has_no_record`, `_a15_junction_home_is_never_followed` |
| LLR-170.2 / TC-B100-29 | `pasted_document_lands_and_is_recorded` (AT-B100-08 seed), `pasted_check_document_lands_in_checks`, `zero_entries_writes_no_document`, `different_changes_json_lands_as_changes_1`, `identical_changes_json_is_reused` (+ plan `keep`), `file_backed_document_is_copied_and_recorded`, `file_backed_zero_entries_is_recorded` (R9), `deleted_file_backed_document_is_not_placed` (R11 missing), `forced_write_failure_saves_without_the_document`, `failure_after_the_write_removes_the_document`, `second_save_of_the_bound_document_writes_nothing` (R1), `document_inside_the_project_outside_its_home_is_not_placed` (R11 + plan 0 rows), `r18_document_behind_a_junctioned_home_is_never_copied` |
| LLR-170.3 / TC-B100-30 | `classifier_outcome` (16 bodies, timing < 1 s), `classifier_missing_file_and_missing_home`, `classifier_a_folder_is_unreadable`, `classifier_linked_file_is_a_link`, `classifier_junction_home_is_a_link`, `classifier_held_file_is_io_error`, `classifier_symbol_entry_is_ok_with_or_without_context` (R17), `reopen_lists_the_recorded_document`, `reopen_resolves_a_symbol_against_the_project_a2l`, `reopen_never_applies_the_entries` (Q6), `missing_document_is_one_missing_problem`, `truncated_document_is_one_not_readable` (R6), `hostile_document_is_one_not_readable_under_one_second` (3), `held_document_is_not_readable_and_stays_recorded` (R16), `refused_record_is_one_manifest_damaged_row_and_no_reopen`, `reopened_document_loads_without_a_question` |
| LLR-167.6 / TC-B100-59 Inc 8a | `test_b100_save_image.py`: `test_tc_b100_59_document_row_in_a_fresh_folder`, `_zero_entries_plans_no_document_row`, `_open_project_carry_sets_the_keys` (present / deleted / unreadable / too-large), `_merge_plans_a_merge_row`; plus the two plan assertions in `test_b100_document.py` (identical → `keep`; inside_elsewhere → 0 rows) |
| LLR-167.8 / TC-B100-70 | `test_b100_save_image.py`: `written_document_clears_the_flag` (RP-1), `failed_document_write_keeps_the_flag`, `file_backed_document_from_outside_keeps_the_flag`, `natural_path_load_edit_save_keeps_the_flag`, `unparsed_paste_text_keeps_the_flag` (Q2); `refused_save_keeps_the_flag` unchanged |
| LLR-164.2 / TC-B100-05 Inc 8a | `test_b100_save_guards.py`: `merge_carries_the_document_and_gathered`, `merge_with_a_pasted_document_names_it` (A3-7), `r15_placed_document_replaces_a_missing_carried_one_silently`, `merge_drops_a_faulty_carried_document_with_one_line` (deleted / unreadable, R6), `merge_keeps_a_too_large_document_under_one_second` (R10), `merge_keeps_a_held_document_with_one_line` (R16), `r3_failed_write_carries_the_target_document`, `r5_refused_target_value_is_kept_aside_and_named`, `r5_overlong_refused_value_is_clipped_in_the_status` |
| LLR-168.3 / TC-B100-20, AT-B100-20 carry | `test_b100_active_variant.py::test_tc_b100_20_writers_carry_the_active_document` (save-back, variant append, MAC sync, A2L sync) |
| LLR-169.3 / TC-B100-23 | `test_b100_project_check.py::test_tc_b100_23_active_document_changed_between_write_and_verify` |
| LLR-169.4 / TC-B100-24 | `test_tc_b100_24_files_key_of_the_active_document_is_read`, `_refused_document_refuses_its_files_key`, `_derived_from_gets_no_document_exception` |
| LLR-169.5 / TC-B100-25 (+ E3 R7) | `test_tc_b100_25_missing_active_document_is_one_problem` (with / without record), `_missing_document_survives_the_no_digests_return`, `_recorded_document_present_and_equal_is_clean`, `_changed_document_is_named_by_its_project_text` (A3-1), `_r7_missing_variant_never_names_the_document` |

**Uncovered (named, not omitted):**
- AT-B100-08 and AT-B100-20 as single black-box nodes through keys and dialogs (C-18): not written; the arms run through the handlers (`_handle_save_dialog`, `_handle_load_project`), not the dialogs.
- E3 R12 (bind stores the unresolved spelling; work area reached through a junction above the anchor): no node.
- E3 R13 (`gathered` NOT carried for an open-project save): no node.
- E3 R8 refined, `link` at Save time (drop on a link): classifier-level only (`classifier_linked_file_is_a_link`); no Save-project node.
- A recorded `active_document` that is a link at Load: the reader refuses it at its walk (`MANIFEST-PATH-ESCAPE`), so the app-level kind is the manifest-damaged row, not `not readable`; the prototype line (app :182) and the reader line (:119) disagree. Tested only at the classifier; flagged for `qa-reviewer`.
- `classify_active_document`, `document_in_home`, `is_active_document_form` callers in the gather: the gather classifier is exercised only through the app (TC-29 arms); there is no direct unit node for its four classes (a file-symlink source, `P/Patches/` case arm untested).
- `TypeError` arm of the R10 catch set: no input found that raises it; the `TypeError` removal mutant is not killable by this suite.
- `parse_change_document` "never raises" (R19 backlog bug): out of 8a, not tested.
- TC-B100-09 snapshot census for `_parsed_paste_text`: relies on the existing census node.

## 4. RED result (`evidence/inc-8a/red-01-vs-base.txt`, one complete run, 2026-10-30 22:13:20Z–22:17:12Z)

164 collected → **160 failed, 4 passed** (pytest exit 1). Failure kinds, read from the run's own `--tb=line` lines:
- **79 behavioural assertions** (78 `AssertionError` + 1 bare `assert`) on existing symbols / the shipped handlers.
- **22 keyword REDs** on existing functions that gain the `active_document` parameter: `serialize_manifest` 17, `project_file_records` 3, `write_project_manifest` 2 (`TypeError: … unexpected keyword argument 'active_document'`). The symbol exists on the base; the new parameter does not, so no value assertion can run.
- **59 `ImportError`**, all on NEW symbols the design adds: `is_active_document_form` 36 (new pure predicate), `recorded_document_state` 22 (new pure classifier), `ACTIVE_DOCUMENT_HOMES` 1 (new constant).
- **4 passed on base (hold by construction, named):** `DOC29_zero_entries_writes_no_document` and `SI59_zero_entries_plans_no_document_row` (the ≥1-entry rule, a "holds" arm), `SI59_open_project_carry_sets_the_keys[deleted]` and `[unreadable]` (the base carries nothing, so the drop arms hold; their mutants are M-23 / M-24, which a carry-everything implementation turns RED).

GREEN on the finished tree is not claimed here (the implementers' code was not final); E5 owns it.

## 5. Environment and method notes

- **RED import path.** Running the brief's command with the worktree as cwd imports the WORKTREE's `s19_app` (python `-m` puts cwd first; pytest's rootdir insertion does too), whatever `PYTHONPATH` says — confirmed with a probe node (`--import-mode=prepend` and `append` both printed the worktree path). The RED run therefore runs with cwd = the base worktree, the test and support files copied there byte-for-byte (sha256 prefixes in the transcript header), and restored afterwards (`git status` clean). Script (scratch, not committed): `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-clde\a8feab43-c248-4ccb-86cf-122b894659b2\scratchpad\e4\red.sh`.
- `NO_COLOR` unset for every run (`env -u NO_COLOR`).
- Timing thresholds (< 1 s) are asserted on this machine's wall clock inside the test; a slow CI host can make the timing nodes flaky.
- Windows-only arms (junctions, share-mode locks, file symlinks) skip with a named reason elsewhere (PDR C-QA-6); here all ran (none skipped).
- An informational smoke run on the in-progress worktree (not evidence; the implementers were still editing) found two defects in MY tests, both repaired before the RED run: the panel-add helper did not clear the inputs on a second add; the refused-record arm seeded a `files` record that the design refuses too (2 rows). It also showed, at that moment, the held-file reopen painting the generic `not readable` reason instead of R16's `could not be read`; on a later re-run of that node it passed, so no finding is raised from it — the node stays as the R16 control.
