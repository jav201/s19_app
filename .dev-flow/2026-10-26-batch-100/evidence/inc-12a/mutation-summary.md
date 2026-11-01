# Inc 12a — E5 mutation run summary

Copy: `C:/Users/jjgh8/AppData/Local/Temp/claude/C--Users-jjgh8-clde/a8feab43-c248-4ccb-86cf-122b894659b2/scratchpad/mut12a`
Interpreter: `C:/Users/jjgh8/anaconda3/envs/s19env/python.exe` (Python 3.11.15)

Fingerprints before and after (sha256[:16], all unchanged):
- `s19_app/tui/screens.py` dc988721ae7b6a87
- `s19_app/tui/styles.tcss` f7b4f75911b296a4
- `s19_app/tui/app.py` 2d1908b14236004f
- `s19_app/tui/services/project_gather_service.py` e11a5e75d7346183

`C:/Users/jjgh8/AppData/Local/s19_app` does NOT exist before and after (good).

## Table

| id | file | test (named killer) | verdict |
|---|---|---|---|
| M-01 | app.py:_BUSY_ACTIONS | B action_table_names_the_seven | KILLED |
| M-02 | app.py:_BUSY_ACTIONS | B action_table_names_the_seven | KILLED |
| M-03 | app.py:_BUSY_ACTIONS | B action_table_names_the_seven | KILLED |
| M-04 | app.py:_BUSY_FRAMES | B begin_paints_the_first_progress_line | KILLED |
| M-05 | app.py:_BUSY_TICK_SECONDS | B spinner_and_elapsed_advance | KILLED |
| M-06 | app.py:__init__ | B begin_paints_the_first_progress_line | KILLED |
| M-07 | app.py:begin_busy | B unknown_or_replaced[end of a replaced run] | KILLED |
| M-08 | app.py:begin_busy | B begin_paints_the_first_progress_line | SURVIVED |
| M-09 | app.py:begin_busy | B a_begin_under_a_running_key_restarts_it | SURVIVED |
| M-10 | app.py:begin_busy | B begin_paints_the_first_progress_line | KILLED |
| M-11 | app.py:begin_busy | B begin_sets_the_bar_to_zero | KILLED |
| M-12 | app.py:begin_busy | B running_line_paints_in_the_accent | KILLED |
| M-13 | app.py:begin_busy | B overlapping_runs_share_one_timer | KILLED |
| M-14 | app.py:step_busy | B unknown_or_replaced[end of a replaced run] | KILLED |
| M-15 | app.py:step_busy | B out_of_range[step 0 / step m+1] | KILLED |
| M-16 | app.py:step_busy | B out_of_range[total 0] | KILLED |
| M-17 | app.py:step_busy | B out_of_range[done -5] | SURVIVED |
| M-18 | app.py:step_busy | B out_of_range[done total+1] | KILLED |
| M-19 | app.py:step_busy | B steps_by_index_set_the_bar | SURVIVED |
| M-20 | app.py:step_busy | B step_amount_moves_the_bar | SURVIVED |
| M-21 | app.py:step_busy | B a_newer_action_is_the_one_shown | KILLED |
| M-22 | app.py:step_busy | B steps_by_index_set_the_bar | KILLED |
| M-23 | app.py:end_busy | B unknown_or_replaced[end of an unknown key] | KILLED |
| M-24 | app.py:end_busy | B end_writes_the_outcome_to_the_status_log | KILLED |
| M-25 | app.py:end_busy | B names_paint_literally[ESC and BEL] | SURVIVED |
| M-26 | app.py:end_busy | B unknown_or_replaced[end of a replaced run] | KILLED |
| M-27 | app.py:end_busy | B newest_running_action_is_shown_after_an_end | KILLED |
| M-28 | app.py:end_busy | B newest_running_action_is_shown_after_an_end | SURVIVED |
| M-29 | app.py:end_busy | B newest_running_action_is_shown_after_an_end | KILLED |
| M-30 | app.py:end_busy | B last_end_stops_the_timer | KILLED |
| M-31 | app.py:end_busy | B last_end_stops_the_timer | SURVIVED |
| M-32 | app.py:end_busy | B running_line_paints_in_the_accent | KILLED |
| M-33 | app.py:end_busy | B last_end_clears_the_bar | KILLED |
| M-34 | app.py:end_busy | B last_end_paints_the_stored_file_state | KILLED |
| M-35 | app.py:end_busy | B file_load_ends_once_on_success | KILLED |
| M-36 | app.py:_busy_tick | B last_end_stops_the_timer | SURVIVED |
| M-37 | app.py:_busy_tick | RP kickoff_sets_bar_in_progress_before_worker | KILLED |
| M-38 | app.py:_busy_tick | B spinner_and_elapsed_advance | KILLED |
| M-39 | app.py:_busy_line | B elapsed_is_minutes_and_seconds[59.9] | KILLED |
| M-40 | app.py:_busy_line | B elapsed_is_minutes_and_seconds[4503] | KILLED |
| M-41 | app.py:_busy_line | B begin_paints_the_first_progress_line | KILLED |
| M-42 | app.py:_busy_begin_action | B names_paint_literally[bidi override / 130] | KILLED |
| M-43 | app.py:_busy_begin_action | B each_worker_action_begins[report] | KILLED |
| M-44 | app.py:_busy_fail | B a2l_load_ends_once_on_success | SURVIVED |
| M-45 | app.py:_busy_fail | B worker_raise_ends_the_action_first[*] | KILLED |
| M-46 | app.py:set_file_status | B file_state_waits_while_a_run_is_shown | KILLED |
| M-47 | app.py:set_file_status | B last_end_paints_the_stored_file_state | KILLED |
| M-48 | app.py:_paint_status_text | B names_paint_literally[ESC and BEL] | SURVIVED |
| M-49 | styles.tcss | B running_line_paints_in_the_accent | KILLED |
| M-50 | app.py:action_before_after_report | B workers_take_the_run_generation | KILLED |
| M-51 | app.py:_start_before_after_worker | B worker_raise[before_after] | KILLED |
| M-52 | app.py:_start_before_after_worker | B before_after_ends_once[refused] | KILLED |
| M-53 | app.py:_start_generate_report_worker | B report_ends_once_on_a_failure[generator raises] | KILLED |
| M-54 | app.py:_start_generate_report_worker | B report_ends_once_on_a_failure[rejected input] | KILLED |
| M-55 | app.py:_start_generate_report_worker | B report_ends_once_on_success | KILLED |
| M-56 | app.py:_start_generate_report_worker | B worker_raise[report] | KILLED |
| M-57 | app.py:_finish_generate_report | RP finish_generate_report_completes_bar | KILLED |
| M-58 | app.py:_start_diff_report_worker | B diff_report_ends_once[markdown refused] | SURVIVED |
| M-59 | app.py:_start_diff_report_worker | B diff_report_ends_once[written] | KILLED |
| M-60 | app.py:_start_diff_report_worker | B diff_report_ends_once[html raises] | KILLED |
| M-61 | app.py:_start_diff_report_worker | B diff_report_ends_once[html refused] | KILLED |
| M-62 | app.py:_start_diff_report_worker | B diff_report_ends_once[written] | KILLED |
| M-63 | app.py:_start_diff_report_worker | B worker_raise[diff_report] | KILLED |
| M-64 | app.py:_commit_project_save | B save_project_reports_its_phases_as_steps | KILLED |
| M-65 | app.py:_commit_project_save | B save_project_reports_its_phases_as_steps | KILLED |
| M-66 | app.py:_commit_project_save | B save_project_reports_its_phases_as_steps | KILLED |
| M-67 | app.py:_commit_project_save | B save_project_reports_its_phases_as_steps | KILLED |
| M-68 | app.py:_commit_project_save | B save_project_ends_once_on_a_placement_failure | KILLED |
| M-69 | app.py:_commit_project_save | B save_project_ends_once_on_a_placement_failure | SURVIVED |
| M-70 | app.py:_commit_project_save | B save_project_reports_its_phases_as_steps | SURVIVED |
| M-71 | app.py:_commit_project_save | B save_raise_ends_the_action_first | KILLED |
| M-72 | app.py:_handle_load_project | B project_load_ends_once_on_a_failure_after_the_begin | KILLED |
| M-73 | app.py:_handle_load_project | B project_load_without_an_a2l_skips_its_step | KILLED |
| M-74 | app.py:_handle_load_project | B project_load_ends_once_on_a_failure_after_the_begin | KILLED |
| M-75 | app.py:_handle_load_project | B project_load_ends_once_on_success | KILLED |
| M-76 | app.py:_handle_load_project | AN project_line_is_the_file_state_painted | KILLED |
| M-77 | app.py:_handle_load_project | AN project_line_is_the_file_state_painted | SURVIVED |
| M-78 | app.py:_handle_load_project | B project_raise_ends_the_action_first | KILLED |
| M-79 | app.py:load_from_path | B file_load_ends_once_on_a_containment_refusal | SURVIVED |
| M-80 | app.py:load_from_path | B file_load_ends_once_on_a_containment_refusal | KILLED |
| M-81 | app.py:load_from_path | B file_load_ends_once_on_success | KILLED |
| M-82 | app.py:load_from_path | B file_load_ends_once_on_success | SURVIVED |
| M-83 | app.py:load_from_path | B file_load_ends_once_on_success | KILLED |
| M-84 | app.py:load_a2l_from_path | B a2l_load_ends_once_on_a_containment_refusal | KILLED |
| M-85 | app.py:load_a2l_from_path | B a2l_load_ends_once_on_success | KILLED |
| M-86 | app.py:load_a2l_from_path | B a2l_load_ends_once_on_success | SURVIVED |
| M-87 | app.py:load_a2l_from_path | B a2l_raise_ends_the_action_first | KILLED |
| M-88 | app.py:_start_load_worker | B file_load_ends_once_on_success | KILLED |
| M-89 | app.py:_start_load_worker | B file_load_ends_once_on_success | SURVIVED |
| M-90 | app.py:_start_load_worker | B worker_raise[file_load] | KILLED |
| M-91 | app.py:_handle_load_error | B file_load_ends_once_on_a_parse_failure | KILLED |
| M-92 | app.py:BINDINGS | LD labels_key_bar_and_palette | KILLED |
| M-93 | app.py:BINDINGS | LD labels_key_bar_and_palette | KILLED |
| M-94 | app.py:refresh_files | R files_list_shows_loadable_suffixes_only | KILLED |
| M-95 | app.py:list_projects | R project_list_skips_a_trailing_dot_on_every_platform | KILLED |
| M-96 | app.py:list_projects | R project_list_skips_a_trailing_dot_on_every_platform | KILLED |
| M-97 | app.py:_listed_project_name | R one_project_match_returns_the_listed_spelling | KILLED |
| M-98 | app.py:_handle_load_project | R one_project_match (AST) | KILLED |
| M-99 | app.py:_load_path_from_user_input | R one_wording_table (AST) | KILLED |
| M-100 | app.py:_typed_load_route | R nul_in_typed_path_is_refused[EACCES/ENAMETOOLONG] | KILLED |
| M-101 | app.py:_load_workarea_file | R pick_rechecks_the_entry_and_fails_closed[vanished] | SURVIVED |
| M-102 | app.py:_load_workarea_file | R pick_rechecks_the_entry_and_fails_closed[lstat refused] | SURVIVED |
| M-103 | app.py:_load_workarea_file | R pick_rechecks_the_entry_and_fails_closed[lstat refused] | KILLED |
| M-104 | app.py:_load_workarea_file | R pick_rechecks_the_entry[folder-*] | KILLED |
| M-105 | app.py:_load_workarea_file | R pick_rechecks_the_entry[junction-*] | SURVIVED |
| M-106 | app.py:_load_workarea_file | R pick_over_cap_is_refused[at the cap] | KILLED |
| M-107 | app.py:_load_workarea_file | R pick_over_cap_is_refused[over the cap] | KILLED |
| M-108 | app.py:_load_workarea_file | R pick_rechecks_the_entry_after_the_question | KILLED |

## Counts

- KILLED: 86
- SURVIVED: 22
- INVALID: 0
- TIMEOUT: 0

## Survivors

- M-08 (begin frame reset): equivalent — no test begins twice in one app and reads the first frame; the `b.frame = 0` reset is unobservable.
- M-09 (drop `b.runs.pop`): weak test — the named test drives a single key, so the restarted run's dict position (which pop moves to "last") is unobservable.
- M-17 (drop `max(done/total, 0.0)`): equivalent via the never-falls rule — `[done -5]` is on the same step, so `max(run.fraction, fraction)` keeps the bar at 50.
- M-19 (`and` -> `or`): equivalent — no caller passes exactly one of `done`/`total`.
- M-20 (drop never-falls rule): weak test — the named test has no falling amount (all amounts rise), so the rule is unobservable there.
- M-25 (outcome unscruibbed): Windows skip — the `[ESC and BEL]` arm is SKIPPED on Windows (S12a-R2-3).
- M-28 (show oldest after end): weak test — the selection point always has exactly one run remaining, so `iter` vs `reversed` is the same.
- M-31 (drop `b.timer = None`): weak test — no second begin; the stopped timer still counts 0 running timers.
- M-36 (drop `if not runs: return` in tick): equivalent — the timer is stopped at the last end, so a tick with no runs cannot be scheduled.
- M-44 (drop gen check in `_busy_fail`): weak test — the `finally` `_busy_fail` sees `run is None` (already deleted), never a stale generation.
- M-48 (`_paint_status_text` unscruibbed): Windows skip — the `[ESC and BEL]` arm is SKIPPED on Windows (S12a-R2-3).
- M-58 (markdown-refused order swap): equivalent — the order of two `call_from_thread` posts is unobservable.
- M-69 (other 9 abort arms `end_busy` -> `set_status`): untested — only the placement arm is driven (declared A12-51-class debt).
- M-70 (`tail[-1]` -> `tail[0]`): untested — the success arm's tail has one line, so `tail[0] == tail[-1]`.
- M-77 (end before `set_file_status`): equivalent — `set_file_status` paints when idle; the stored state and final painted text are unchanged.
- M-79 (begin before suffix refusal): untested — no test drives the suffix refusal arm of `load_from_path`.
- M-82 (`copied.stat()` after dispatch): untested — structural (declared in tester notes §5).
- M-86 (a2l outcome without `painted_names`): equivalent for a plain name — the a2l success arm uses a plain name.
- M-89 (end before `_sync_loaded_file_to_project`): weak test — the named test loads with no open project, so the reordering is unobservable.
- M-101 (pre-question `FileNotFoundError` -> fall through): weak test — `go()` still returns silently on the vanished entry, so 0 loads / 0 lines hold.
- M-102 (pre-question `except OSError: pass` -> `return`): untested — the test injects the error only into the second lstat (tester D-6).
- M-105 (drop `_is_reparse_point`): weak test — a junction is a directory, so `not stat.S_ISREG(...)` already refuses it; the reparse check is unobservable on the junction arm.
