# Inc 12a — E4 tester notes (independent tests, RED on base)

Author role: tester (E4, design-first pipeline). Oracles: the design files in this folder only (`E1-requirements-draft.md`, `E1-scope.md`, `E1/E2/E3-rulings.md`, `codewire/interfaces-12a.md`, `codewire/proto-12a-indicator.md`, `codewire/proto-12a-sweep.md`). The implementers' `s19_app/tui/app.py` was never read. No source file was edited.

Base revision: `051f586` (main + Inc 11 corrected), the detached scratch worktree `base12a`; the new and re-pinned test files were copied into it and run against its own `s19_app` (path printed in the transcript header).

Transcript: `.dev-flow/2026-10-26-batch-100/evidence/inc-12a/red-01-vs-base.txt` (one complete run; command and environment in its header).

## 1. Counts

- New test functions: 67 (112 collected items with parametrisation).
  - `tests/test_b100_busy.py` (new file): 52 functions, 81 items.
  - `tests/test_b100_load_dialog.py`: 3 functions (TC-B100-41 labels arm, 2 × TC-B100-66 extension).
  - `tests/test_b100_announce.py`: 1 function (TC-B100-56 extension).
  - `tests/test_b100_recents.py`: 11 functions, 27 items (TC-B100-37 / -38 / -39 arms).
- Re-pinned existing tests: 15 functions, 23 items (section 3).
- RED on base: 125 of 135 items run (105 of the 112 new items; 20 of the 23 re-pinned items); 9 passed, 1 skipped. Details in section 4.

## 2. Requirement → test map

All new tests are in the four files above; `busy` = `tests/test_b100_busy.py`, `recents` = `tests/test_b100_recents.py`, `dialog` = `tests/test_b100_load_dialog.py`, `announce` = `tests/test_b100_announce.py`.

| Requirement | Test(s) (file::function) | Design example |
|---|---|---|
| HLR-176 | busy::test_tc_b100_50_begin_paints_the_first_progress_line; busy::test_tc_b100_50_each_worker_action_begins_with_a_progress_line[4]; busy::test_at_b100_17_worker_load_of_an_8_mib_s19_by_keys | A12-01, A12-35, A12-37 |
| HLR-176a | busy::test_tc_b100_50_spinner_and_elapsed_advance_while_a_worker_runs; busy::test_at_b100_17_… | A12-09, A12-37 |
| HLR-176b | busy::test_tc_b100_50_step_amount_moves_the_bar_within_the_step | A12-07 (E2 P-2 threshold) |
| HLR-176c | busy::test_tc_b100_51_* exits (below); busy::test_tc_b100_50_last_end_clears_the_bar; busy::test_at_b100_17_… | A12-30 … A12-66 |
| HLR-176d | busy::test_tc_b100_50_status_line_has_one_owner_during_a_worker_load; busy::test_tc_b100_50_file_state_waits_while_a_run_is_shown | A12-36, A12-14 |
| LLR-176.1 | busy::test_tc_b100_50_begin_paints_the_first_progress_line; busy::test_tc_b100_50_long_label_stays_on_one_row | A12-01, A12-02, A12-03 (P-3) |
| LLR-176.1a | busy::test_tc_b100_50_begin_sets_the_bar_to_zero | A12-04 |
| LLR-176.1b | busy::test_tc_b100_50_steps_by_index_set_the_bar | A12-05, A12-06 |
| LLR-176.1c | busy::test_tc_b100_50_step_amount_moves_the_bar_within_the_step | A12-07 |
| LLR-176.1d | busy::test_tc_b100_50_out_of_range_step_data_is_clamped[6] | A12-08 |
| LLR-176.1e | busy::test_tc_b100_50_spinner_and_elapsed_advance_while_a_worker_runs; busy::test_tc_b100_50_overlapping_runs_share_one_timer; busy::test_tc_b100_50_action_shorter_than_a_tick | A12-09, A12-10, A12-11 |
| LLR-176.1f | busy::test_tc_b100_50_last_end_stops_the_timer; busy::test_tc_b100_50_action_shorter_than_a_tick | A12-12, A12-11 |
| LLR-176.1g | busy::test_tc_b100_50_elapsed_is_minutes_and_seconds[5] | A12-13 |
| LLR-176.1h | busy::test_tc_b100_50_file_state_waits_while_a_run_is_shown; busy::test_tc_b100_50_image_pick_file_state_waits_for_a_running_report | A12-14, A12-73 |
| LLR-176.1i | busy::test_tc_b100_50_end_writes_the_outcome_to_the_status_log | A12-15 |
| LLR-176.1j | busy::test_tc_b100_50_last_end_paints_the_stored_file_state; announce::test_tc_b100_56_project_line_is_the_file_state_painted_at_the_last_end; busy::test_tc_b100_51_project_load_ends_once_on_success | A12-16, A12-42, A12-70 |
| LLR-176.1k | busy::test_tc_b100_50_last_end_clears_the_bar; re-pinned test_report_progress.py::test_report_generation_drives_progress_bar_to_100 | A12-17, A12-18, A12-77 |
| LLR-176.1l | busy::test_tc_b100_50_kickoff_raise_ends_the_file_load_first; busy::test_tc_b100_50_worker_raise_ends_the_action_first[file_load, report, diff_report, before_after]; busy::test_tc_b100_50_a2l_raise_ends_the_action_first; busy::test_tc_b100_50_project_raise_ends_the_action_first; busy::test_tc_b100_50_save_raise_ends_the_action_first | A12-71, A12-33, A12-56, A12-62, A12-66, A12-40, A12-45, A12-49 |
| LLR-176.1m | busy::test_tc_b100_50_unknown_or_replaced_run_leaves_the_indicator[3] | A12-19 (A12a-04) |
| LLR-176.1n | busy::test_tc_b100_50_a_newer_action_is_the_one_shown | A12-20 |
| LLR-176.1o | busy::test_tc_b100_50_the_newest_running_action_is_shown_after_an_end | A12-21 |
| LLR-176.1p | busy::test_tc_b100_50_a_begin_under_a_running_key_restarts_it | A12-22 |
| LLR-176.1q | busy::test_tc_b100_50_progress_widgets_are_written_on_the_main_thread[4] | A12-23 |
| LLR-176.1r | busy::test_tc_b100_50_names_paint_literally_through_load_from_path[4]; busy::test_tc_b100_50_begin_busy_is_called_only_from_the_one_label_helper | A12-24 (S12a-02, S12a-04, S12a-R2-3) |
| LLR-176.1s | busy::test_tc_b100_50_the_bar_keeps_its_row_when_idle[2] | A12-25 |
| LLR-176.1 look (Q-6 / P-3) | busy::test_tc_b100_50_running_line_paints_in_the_accent | A12-26 |
| LLR-176.2 | busy::test_tc_b100_51_every_baseline_bar_site_maps_to_a_seam_event | A12-28 |
| LLR-176.2a | busy::test_tc_b100_51_only_the_seam_sets_the_bar | A12-29 |
| LLR-176.2b | busy::test_tc_b100_51_action_table_names_the_seven_long_actions | A12-27 |
| LLR-176.2c | busy::test_tc_b100_51_file_load_ends_once_on_success / _on_a_parse_failure / _on_a_containment_refusal; _a2l_load_ends_once_on_success / _on_a_containment_refusal; _project_load_ends_once_on_success / _on_a_failure_after_the_begin; _save_project_reports_its_phases_as_steps / _save_project_ends_once_on_a_placement_failure; _report_ends_once_on_success / _on_a_failure[2]; _diff_report_ends_once_and_logs_its_outcome[4] / _diff_report_without_a_comparison_begins_nothing; _before_after_ends_once_and_logs_its_outcome[2] | the 14 arms + A12-31/-32/-34/-39/-41/-43/-44/-52/-55/-57/-60/-61/-65/-67/-72 |
| LLR-176.2d | busy::test_tc_b100_51_save_project_reports_its_phases_as_steps | A12-46, A12-47 |
| A12a-09 | busy::test_tc_b100_51_project_load_without_an_a2l_skips_its_step | A12-68 |
| Interfaces S-m / Q-1 | busy::test_tc_b100_51_workers_take_the_run_generation | A12-69 |
| LLR-173.2m | dialog::test_tc_b100_41_labels_key_bar_and_palette_say_load_and_projects; re-pinned key-bar / bindings tests | B12-01, B12-02, B12-03, B12-05 |
| LLR-173.7 (TC-B100-66 ext.) | dialog::test_tc_b100_66_progress_lines_carry_no_decision_id; dialog::test_tc_b100_66_pick_refusal_tokens_carry_no_decision_id | A12-27 scan, B12-36 |
| LLR-178.2 (TC-B100-56 ext.) | announce::test_tc_b100_56_project_line_is_the_file_state_painted_at_the_last_end | A12-42, A12-70 |
| LLR-172.4e | recents::test_tc_b100_37_project_list_skips_a_trailing_dot_on_every_platform; re-pinned recents::test_tc_b100_38_project_list_leaves_a_trailing_dot_name_out_off_windows | B12-07, B12-08 |
| LLR-172.4f | recents::test_tc_b100_37_files_list_shows_loadable_suffixes_only[3]; recents::test_tc_b100_37_files_list_shows_loadable_suffixes_only_through_one_predicate | B12-11, B12-12, B12-13 |
| LLR-172.5i | recents::test_tc_b100_38_nul_in_typed_path_is_refused[8] | B12-15, B12-16, B12-21, B12-22, B12-38 (S12a-01) |
| LLR-172.5j | recents::test_tc_b100_38_one_project_match; recents::test_tc_b100_38_one_project_match_returns_the_listed_spelling | B12-20, B12-19 |
| LLR-172.5k | recents::test_tc_b100_38_one_wording_table | B12-37 (A12a-01: no exact count) |
| LLR-172.6b | recents::test_tc_b100_39_pick_rechecks_the_entry[3 arms × 2 routes]; recents::test_tc_b100_39_pick_rechecks_the_entry_after_the_question; recents::test_tc_b100_39_pick_rechecks_the_entry_and_fails_closed[2] | B12-27 … B12-30, B12-39 (S12a-03), B12-33, B12-32 |
| LLR-172.6c | recents::test_tc_b100_39_pick_over_cap_is_refused[3] | B12-31 |
| AT-B100-17 (12a half) | busy::test_at_b100_17_worker_load_of_an_8_mib_s19_by_keys | A12-37 |

Named E3 arms: S12a-01 → test_tc_b100_38_nul_in_typed_path_is_refused[EACCES/ENAMETOOLONG ×2 routes]; S12a-02 → test_tc_b100_50_names_paint_literally_through_load_from_path[ESC and BEL] (no ESC/BEL in the painted line and the outcome log line); S12a-R2-3 → that arm is `skipif(win32, reason="not run on Windows (the name cannot be created), never passed")`, it runs on the Linux CI; S12a-03 → test_tc_b100_39_pick_rechecks_the_entry_after_the_question; S12a-04 → test_tc_b100_50_begin_busy_is_called_only_from_the_one_label_helper + the hostile names through `load_from_path`; S12a-06 → test_tc_b100_50_worker_raise_ends_the_action_first (one failure end, then the exception surfaces) and test_tc_b100_51_file_load_ends_once_on_success (exactly one effective end, nothing logged after it); A12a-01 → test_tc_b100_38_one_wording_table; A12a-02 → test_tc_b100_51_project_load_ends_once_on_a_failure_after_the_begin (unreadable `project.json` → refusal line, 0 begins, no `failed` end); A12a-03 → test_tc_b100_51_a2l_load_ends_once_on_success (outcome `A2L loaded: <painted>`); A12a-04 → test_tc_b100_50_unknown_or_replaced_run_leaves_the_indicator (a replaced run's outcome is logged); A12a-05 → test_tc_b100_51_file_load_ends_once_on_success (the outcome is the last log line; no line after the end); A12a-06 → test_tc_b100_50_last_end_paints_the_stored_file_state + announce overlap arm; A12a-08 → covered behaviourally by test_tc_b100_50_kickoff_raise_ends_the_file_load_first and test_tc_b100_51_file_load_ends_once_on_success (no structural test of where `copied.stat()` sits); A12a-09 → test_tc_b100_51_project_load_without_an_a2l_skips_its_step.

Uncovered requirements: none of the 38 E1 requirements is left without a test. Partially covered: see section 5.

## 3. Re-pinned tests (census rows A, B, C per E2-rulings; plus A9)

| Row | Test | Reason / new pin |
|---|---|---|
| A1 | tests/test_report_progress.py::test_report_generation_drives_progress_bar_to_100 | Stale-100 pin. Now: the bar moves off 0 while the report runs, and after the end it is 0 of 100 with `Report: …md` on the last log line (A12-53/A12-77). Test id kept. |
| A2 | tests/test_report_progress.py::test_kickoff_sets_bar_in_progress_before_worker | Constant 15 is gone. Now: the progress line `<glyph> Generating the project report  ·  step 1/2 Prepare the results  ·  00:0x` and bar 0 (A12-75). |
| A3 | tests/test_report_progress.py::test_finish_generate_report_completes_bar | `gen` is required (Q-1). Now: begin a run, bar 40, finish with `gen` → bar 0 and `Report: reports/r.md` (A12-77). |
| A4 | tests/test_before_after_report.py::test_at_038a_saveback_trigger_report_pair_reread_from_surfaced_path | Success arm ended at 100. Now begins at 0 and ends at 0 (1-step run). |
| A5 | tests/test_report_off_ui_thread.py::test_ac4_diff_progress_never_sticks_mid_fill | Success arm ended at 100. Now passes 50 and ends at 0; the refused arm is unchanged. |
| A6/A7 | tests/test_tui_report_attribution.py::test_at260…, ::test_at261…, ::test_at262…, ::test_tc571…, ::test_at263… (one helper, `_drive_worker`) | The helper begins a `report` run and passes `gen=` (A12-76). |
| A8 | tests/test_b100_session_reset.py::test_tc_b100_09_domain_matches_the_live_source_census | `_busy` added to `SNAPSHOT_EXCLUSIONS` with its reason (A12-74). |
| A9 | tests/test_tui_app.py::test_save_project_writes_under_workarea | Runs inside `app.run_test()` (P-5, F-9); the assertions are unchanged. |
| B1 | tests/test_b97_key_bar.py `GLOBAL_TEXTS` (`^l Load`) and the `GLOBAL_TEXTS_80` comment; read by ::test_tc_b97_67_row_one_is_the_eight_globals_whatever_the_focus, ::test_tc_b97_67_row_one_at_80x24_drops_palette_whole, ::test_at_b97_25_two_rows_on_every_window_and_clicks, ::test_tc_b97_70_every_painted_row_is_whole_tokens | LLR-173.2m. `GLOBAL_TEXTS_80 = GLOBAL_TEXTS[:6]` keeps its shape (P-B2). |
| B2 | tests/test_tui_diff_screen.py::test_at_b78_32_app_bindings_block_is_untouched | Rows `l` → `Load`, `p` → `Projects`, `ctrl+s` → `Save project` (P-B4). It was already RED on base (a known CI failure). It STAYS RED after the re-pin: see ambiguity D-1. |
| B3 | tests/test_tui_patch_history_strip.py::test_tc081_4_no_binding_diff | Two sanctioned markers `'"l", "load_file"'` and `'"p", "load_project"'`. |
| B4 | the 29 snapshot files (`tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[<cell>].svg`, cells as listed in E1 draft §D.4 / proto-12a-sweep R-5) | NOT regenerated (CI workflow only). The snapshot test that will change is `tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot` for those 29 cells. |
| C1 | tests/test_b100_recents.py::test_tc_b100_38_project_list_keeps_a_trailing_dot_name_off_windows → renamed **test_tc_b100_38_project_list_leaves_a_trailing_dot_name_out_off_windows** | LLR-172.4e supersedes CR9-9: `fw-v1.` is absent from both readings. Renamed because the old name states the superseded behaviour. |

Census re-take on this tree (grep only, not executed):
- `Load file` / `Load project` literals: no other test pins them (`test_b97_key_bar._layer0_lists` is a test-local input; the Workspace button `Load project (p)` in `test_tui_directionb.py` AC-7 keeps its text, ruling Q6).
- Direct calls of the workers / `_finish_generate_report` / `_handle_load_error` / `_start_load_worker`: only the two re-pinned sites (A3, A6/A7).
- `set_progress` spies: `test_report_off_ui_thread` (held: ac3 `[-1] in (0, 100)`; ac2 thread-only), `test_report_progress::test_failed_report_resets_progress_bar_to_zero` (held), `test_tui_directionb.py:2206` direct call (allowed by LLR-176.2a).
- `#status_text` read while a worker runs (owed by E2): 9 files read `#status_text` around a worker action (`test_b100_active_variant`, `test_b100_focus`, `test_b100_load_dialog`, `test_b100_project_check`, `test_b100_reuse`, `test_b99_staging`, `test_report_progress`, `test_tui_diff_screen`, `test_tui_operations_view`). Every read found by grep waits for an end state (`startswith("Loaded ")`, after `wait_for_complete`, or reads `#log_line_*`). No further re-pin found; the batch-end battery is the execution of this census (`not-run` here, operator override 2026-10-31).

## 4. RED on base (state: executed)

Transcript: `evidence/inc-12a/red-01-vs-base.txt`, one complete run, base `051f586`, `s19_app.__file__` = the base scratch tree.

Result line: `125 failed, 9 passed, 1 skipped in 595.18s (0:09:55)`, pytest exit code 1. The 9 passed are exactly the declared GREEN-on-base items listed below; the 1 skip is the declared ESC/BEL arm.

Reasons, grouped (each RED is an assertion or a missing attribute of the new design; 0 collection errors, 0 typos):
- Missing seam attribute (`begin_busy`, `_busy_tick`, `_BusyRun`, `_busy`, `_BUSY_ACTIONS`, `_listed_project_name`, `end_busy`): the synthetic seam tests of TC-B100-50 (begin/step/end/timer/clock/overlap/restart/layout/accent), the TC-B100-66 progress scan, the TC-B100-56 extension, the A12-73 pick test, the B12-19 unit, and re-pins A3, A6/A7 (5).
- Behavioural assertions on base:
  - no progress line painted (P12a-2): the 4 first-line arms, the 4 main-thread probe arms, the hostile-name arms (`[b]x.s19`, U+202E, 130 chars), HLR-176d (the file state is painted mid-load), AT-B100-17 (only `Ready.` sampled);
  - bar sequences `[10, 50, 100]`, `[10, 0]`, `[15, 55, 100]`, `[15, 0]`, `[15, 100]`, `[]` instead of the seam's `[0, …, 0]`: every LLR-176.2c exit test, the exception arms (`[10, 50]` left mid-fill for the A2L), re-pins A1 (bar 100), A4 (`[15, 100]`), A5 (`[15, 55, 100]`);
  - 0 effective ends recorded: worker-raise, kickoff, project and Save raise arms;
  - AST: 24 baseline sites with no seam call; 24 `set_progress` references outside the seam; `begin_busy` called 0 times; no `gen` parameter; `refresh_files` has no `recent_kind`; 2 project-match functions; 5+ literal refusal sentences;
  - re-pin A2: `#status_text` reads `Loaded project 'proj' -> a.s19`, no progress line;
  - labels: key bar row 1 reads `^l Load file` (TC-B100-41 arm, B1 re-pins ×7 items); the palette holds `Load file`;
  - sweep: Workarea Files lists 6 / 5 / 1 rows; the trailing-dot folders are listed in the `posix` reading; EACCES / ENAMETOOLONG leave the classifier (status route: the exception is caught by the test; dialog route: the app stops); the swapped entries and the over-cap file are parsed; C1 re-pin lists `fw-v1.` in the `posix` reading;
  - B2: still RED (`c`, `d` rows and `ctrl+l`/`l`/`p` labels; see D-1).
- GREEN on base by design (declared, not RED): the 4 NUL regression arms of LLR-172.5i (E3 S12a-01 / interfaces S-j: GREEN on the post-9b base); `test_tc_b100_39_pick_rechecks_the_entry_and_fails_closed[vanished]` (9b B88 regression); `test_tc_b100_39_pick_over_cap_is_refused[at the cap]` (the boundary twin); re-pins A8, A9, B3 (they widen an allow-list or change the harness only, so base passes).
- Skipped: `test_tc_b100_50_names_paint_literally_through_load_from_path[ESC and BEL]` — "not run on Windows (the name cannot be created), never passed" (S12a-R2-3).

GREEN capture: `not-run` — the implementation is in progress in the worktree; the orchestrator owns the gate run (C-25).

## 5. Examples not turned into a test, or turned into a weaker form

- A12-69 "`_start_load_worker(path)` with no `gen` → `TypeError`": a `@work` method runs its body in a worker, so the `TypeError` would surface as a worker failure, not at the call. Tested instead through `inspect.signature` (keyword-only, no default) plus the AST "every worker call passes `gen=`".
- A12-51 (Save tail outcome `Manifest verify MISMATCH`): not written — forcing a manifest-verify mismatch needs patching Inc 11 internals not named by the interface; the tail ordering is covered only by the success arm (outcome = last log line).
- A12-48's toast titled `Project not saved` and A12-46's log-line list: only the outcome and `log_lines[-1]` are asserted.
- A12-30 / A12-42 exact "log lines added" lists: A12-30 lists `Loaded firmware.s19 (S19 only)` as a log line, but on base that text is a `#status_text` value, not a log line, and interfaces S-d does not say `set_file_status` logs. The test asserts the last line is the outcome and that no begin/step line is logged, not the full list (ambiguity D-3).
- A12-26's `-busy` class: asserted through its observable colour (`#91abec` while shown, the idle colour after the last end), not the class name.
- A12-12 `app._busy.timer is None`: asserted through running 0.1 s timers instead.
- A12-41 third arm (project already has an A2L) and A12-61 with the seam present on base: the refusal-before-begin arms are folded into the success tests of each action (the success arm carries the base RED); `test_tc_b100_51_diff_report_without_a_comparison_begins_nothing` is RED on base only through an explicit "the seam exists" precondition.
- A12a-08 (`copied.stat()` before the dispatch): no structural test.
- B12-03 at 80 and 99 columns, B12-04 (Workspace button), B12-10, B12-14, B12-17, B12-18, B12-23 … B12-26, B12-34, B12-35: hold examples or texts unchanged by design; not written as new tests (existing TC-B100-38 / -39 / -40 / -63 tests pin those texts).
- LLR-176.1s at 80×24 elapsed-time visibility (risk R-6): not tested (declared risk).
- LLR-172.4e Windows `\\?\` arm on Linux: the Linux CI runs the plain-name arm only.
- LLR-172.6b arm (c) (file symbolic link): runs here (the privilege exists on this host per probe G3); elsewhere it skips "reported not run".

## 6. Design ambiguities met

- D-1 (B2, P-B4). The ruling says re-pinning the three rows (`l`, `p`, `ctrl+s`) makes `test_at_b78_32_app_bindings_block_is_untouched` green. Executed on base: the frozen set also lacks `('c', 'confirm_attention', 'Confirm', False)` and `('d', 'a2l_describe_tag', 'Describe tag', False)`, and `_B79_COMMITTED_APP_BINDING_COUNT` is 40 while `BINDINGS` has 42 rows. Re-pinned only the three authorised rows; the test stays RED after Inc 12a. Adding the two rows and the count 42 is outside the authorised re-pin — orchestrator decision.
- D-2 (A1 re-pin). E1 §D.3 says "the bar reaches 100 before the end and is cleared after it"; the design (A12-53 spy `[0, 50, 0]`, A12-77) never writes 100 for a report. The re-pin follows the design: the bar moves while the report runs and is cleared after.
- D-3 (A12-30 / A12-42). The examples list `Loaded firmware.s19 (S19 only)` among the added status-log lines; on base it is a `#status_text` value only, and S-d says `set_file_status` stores and paints, not logs. Not asserted.
- D-4 (B12-07). "→ the project list is `[P]` on Windows" cannot hold with the plain `fw-v1` / `fw-v2` helper folders the example itself requires (they hold a data file, so they are projects). The Windows assertion is "no dot/space name listed, `P` listed"; the exact `["P"]` is asserted on Linux.
- D-5 (LLR-172.5i RED arm). E2 ruling says "only the relative NUL arm is RED on base"; E3 S12a-01 and interfaces S-j say both NUL arms are GREEN on the post-9b base. Executed: all 4 NUL arms are GREEN on `051f586`; the RED arms are EACCES / ENAMETOOLONG (E3 wins).
- D-6 (interfaces S-i vs S12a-03). S-i says "Both checks run before the Inc 10 question"; E3 S12a-03 says inside `go`, after the question. Tests follow S12a-03 (B12-39); the fails-closed arm injects the `PermissionError` from the second `os.lstat` so the pre-question vanish look passes either way.
- D-7 (A12-03 / P-3). The visible-row ellipsis is asserted (P-3 accepted in E2); the 200-character label's row is read at 118×54 only.
- D-8 (re-pin names). C1's id is renamed (the old name states the superseded behaviour); A1 keeps its id `…_to_100` although it no longer reaches 100 (kept for traceability).

## 7. Environment limits

- Windows 11 host, Python 3.11.15, Textual 8.2.8; `LongPathsEnabled = 0`. The 130-character name arm asserts only the begin's painted label (the copy into a deep work area may fail on MAX_PATH; that is not LLR-176.1r).
- The ESC/BEL name arm cannot run on Windows (declared, S12a-R2-3).
- Host loaded by parallel jobs: timing arms assert ≥ thresholds and observed transitions only (glyph count ≥ 5, `00:00` then `00:01` observed, waits until `00:01` is painted).
- Snapshots not regenerated (CI workflow only). Full suite and whole touched modules not run (operator override 2026-10-31; batch-end battery).
- No real PII, credentials or client data in fixtures (case_01 examples and generated files only).
