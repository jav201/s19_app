# Inc 12a — E4 mutant candidates

One row per NEW branch or arm in the Inc 12a source (`s19_app/tui/app.py`, `s19_app/tui/styles.tcss`). Line numbers are those of the integrated tree (`app.py` sha256[:16] in `E4-integration-notes.md`). State of every row: `planned` (no mutant was executed at E4; the SR-12a-2 guard has a natural negative control, see the note at the end). The E5 / batch-end mutation run picks from this list.

Test file abbreviations: `B` = `tests/test_b100_busy.py`, `R` = `tests/test_b100_recents.py`, `LD` = `tests/test_b100_load_dialog.py`, `AN` = `tests/test_b100_announce.py`, `RP` = `tests/test_report_progress.py`, `SR` = `tests/test_b100_session_reset.py`, `KB` = `tests/test_b97_key_bar.py`, `DS` = `tests/test_tui_diff_screen.py`.

"Survivor?" = `expected` when no listed test is believed to read the arm; the reason is given.

## G-A — the seam

| # | file:function:line | Mutation | Expected killer | Survivor? |
|---|---|---|---|---|
| M-01 | app.py:`_BUSY_ACTIONS`:389 | delete the `diff_report` row | B::test_tc_b100_51_action_table_names_the_seven_long_actions | |
| M-02 | app.py:`_BUSY_ACTIONS`:366 | `file_load` step 2 `"Parse"` → `"Parsing"` | B::test_tc_b100_51_action_table_names_the_seven_long_actions; LD::test_tc_b100_66_progress_lines_carry_no_decision_id (count unchanged, so only the table test) | |
| M-03 | app.py:`_BUSY_ACTIONS`:393 | `before_after` gains a second step | B::test_tc_b100_51_action_table_names_the_seven_long_actions; B::test_tc_b100_51_before_after_ends_once_and_logs_its_outcome | |
| M-04 | app.py:`_BUSY_FRAMES`:360 | first frame `⠋` → `⠙` | B::test_tc_b100_50_begin_paints_the_first_progress_line | |
| M-05 | app.py:`_BUSY_TICK_SECONDS`:361 | `0.1` → `1.0` | B::test_tc_b100_50_spinner_and_elapsed_advance_while_a_worker_runs (glyph count ≥ 5) | |
| M-06 | app.py:`S19TuiApp.__init__`:2538 | drop `self._busy = _BusyState()` | every B test (AttributeError); SR::test_tc_b100_09_domain_matches_the_live_source_census | |
| M-07 | app.py:`begin_busy`:19832 | drop `b.last_gen += 1` (every gen is 0) | B::test_tc_b100_50_unknown_or_replaced_run_leaves_the_indicator[end of a replaced run] | |
| M-08 | app.py:`begin_busy`:19834 | drop the `if not b.runs: b.frame = 0` reset | none found (P-6: a first begin after an earlier action paints `⠋`; no test begins twice in one app and reads the first frame) | expected |
| M-09 | app.py:`begin_busy`:19836 | drop `b.runs.pop(key, None)` (a restart keeps its old position) | B::test_tc_b100_50_a_begin_under_a_running_key_restarts_it | |
| M-10 | app.py:`begin_busy`:19839 | drop the first paint | B::test_tc_b100_50_begin_paints_the_first_progress_line | |
| M-11 | app.py:`begin_busy`:19840 | drop `set_progress(0)` | B::test_tc_b100_50_begin_sets_the_bar_to_zero; B::test_tc_b100_51_* bar sequences | |
| M-12 | app.py:`begin_busy`:19841 | drop `add_class("-busy")` | B::test_tc_b100_50_running_line_paints_in_the_accent | |
| M-13 | app.py:`begin_busy`:19842 | `if b.timer is None` → `if True` (a timer per begin) | B::test_tc_b100_50_overlapping_runs_share_one_timer | |
| M-14 | app.py:`step_busy`:19879 | drop `or run.gen != gen` | B::test_tc_b100_50_unknown_or_replaced_run_leaves_the_indicator[end of a replaced run] (its stale `step_busy(g1, 3)`) | |
| M-15 | app.py:`step_busy`:19882 | drop the clamp `min(max(n, 1), m)` | B::test_tc_b100_50_out_of_range_step_data_is_clamped[step 0 / step m + 1] | |
| M-16 | app.py:`step_busy`:19884 | `total <= 0` → `total < 0` | B::test_tc_b100_50_out_of_range_step_data_is_clamped[total 0] (ZeroDivisionError) | |
| M-17 | app.py:`step_busy`:19884 | drop `max(…, 0.0)` | B::test_tc_b100_50_out_of_range_step_data_is_clamped[done -5] | |
| M-18 | app.py:`step_busy`:19884 | drop `min(…, 1.0)` | B::test_tc_b100_50_out_of_range_step_data_is_clamped[done total + 1] | |
| M-19 | app.py:`step_busy`:19883 | `and` → `or` (amount with `total=None`) | none found (no caller passes one of the two); TypeError only on that call | expected |
| M-20 | app.py:`step_busy`:19887 | drop the never-falls rule `max(run.fraction, fraction)` | B::test_tc_b100_50_step_amount_moves_the_bar_within_the_step (if it reports a smaller amount in the same step) | possible — confirm the test has a falling amount |
| M-21 | app.py:`step_busy`:19892 | `if shown is run` → `if True` | B::test_tc_b100_50_a_newer_action_is_the_one_shown | |
| M-22 | app.py:`step_busy`:19894 | bar `100 * (n - 1 + f) / m` → `100 * n / m` | B::test_tc_b100_50_steps_by_index_set_the_bar; B::test_tc_b100_51_* `[0, 50, 0]` | |
| M-23 | app.py:`end_busy`:19919 | log the outcome only after the generation check | B::test_tc_b100_50_unknown_or_replaced_run_leaves_the_indicator[end of an unknown key / replaced run] (`added == ["x"]`) | |
| M-24 | app.py:`end_busy`:19919 | drop `if outcome.strip()` (an empty outcome logs) | none direct; `_append_log_line` already drops an empty line, the `StatusLog` spy would see `""` — B unknown_or_replaced tail `end_busy(…, "")` is after `added` is read | expected |
| M-25 | app.py:`end_busy`:19920 | `safe_text(outcome).plain` → `outcome` | B::test_tc_b100_50_names_paint_literally_through_load_from_path[ESC and BEL] — skipped on Windows (S12a-R2-3), Linux CI only | expected on Windows |
| M-26 | app.py:`end_busy`:19922 | drop `or run.gen != gen` | B::test_tc_b100_50_unknown_or_replaced_run_leaves_the_indicator[end of a replaced run] | |
| M-27 | app.py:`end_busy`:19925 | `if self._busy.runs` → `if False` (the first end always clears) | B::test_tc_b100_50_the_newest_running_action_is_shown_after_an_end | |
| M-28 | app.py:`end_busy`:19926 | show `next(iter(...))` (oldest) instead of the newest | B::test_tc_b100_50_the_newest_running_action_is_shown_after_an_end (three runs) | |
| M-29 | app.py:`end_busy`:19928 | drop the bar repaint of the remaining run | B::test_tc_b100_50_the_newest_running_action_is_shown_after_an_end | |
| M-30 | app.py:`end_busy`:19933 | drop `b.timer.stop()` | B::test_tc_b100_50_last_end_stops_the_timer | |
| M-31 | app.py:`end_busy`:19934 | drop `b.timer = None` | B::test_tc_b100_50_last_end_stops_the_timer (second begin finds a stopped timer, no tick) | |
| M-32 | app.py:`end_busy`:19935 | drop `remove_class("-busy")` | B::test_tc_b100_50_running_line_paints_in_the_accent (idle colour after the end) | |
| M-33 | app.py:`end_busy`:19936 | drop `set_progress(0)` | B::test_tc_b100_50_last_end_clears_the_bar; RP::test_report_generation_drives_progress_bar_to_100 | |
| M-34 | app.py:`end_busy`:19937 | paint `"Ready."` instead of `b.file_state` | B::test_tc_b100_50_last_end_paints_the_stored_file_state; AN::test_tc_b100_56_project_line_is_the_file_state_painted_at_the_last_end | |
| M-35 | app.py:`end_busy`:19938 | `return True` → `return False` | every B `seam.effective(...)` count (TC-B100-51 exits) | |
| M-36 | app.py:`_busy_tick`:19942 | drop the `if not runs: return` | none found (the timer is stopped at the last end; a tick with no run cannot be scheduled) | expected |
| M-37 | app.py:`_busy_tick`:19947 | drop the SR-12a-2 `#status_text` guard | RP::test_kickoff_sets_bar_in_progress_before_worker (NoMatches at exit) — the pre-fix tree is this mutant, executed RED in `int-diag-D-repinned.txt` | |
| M-38 | app.py:`_busy_tick`:19949 | drop the frame advance | B::test_tc_b100_50_spinner_and_elapsed_advance_while_a_worker_runs | |
| M-39 | app.py:`_busy_line`:19956 | `int(...)` elapsed → `round(...)` | B::test_tc_b100_50_elapsed_is_minutes_and_seconds[59.9-00:59] | |
| M-40 | app.py:`_busy_line`:19961 | cap minutes at 59 (`min(elapsed // 60, 59)`) | B::test_tc_b100_50_elapsed_is_minutes_and_seconds[4503-75:03] | |
| M-41 | app.py:`_busy_line`:19959 | separator `  ·  ` → ` - ` | B::test_tc_b100_50_begin_paints_the_first_progress_line | |
| M-42 | app.py:`_busy_begin_action`:19985 | `painted_names([name])` → `name` | B::test_tc_b100_50_names_paint_literally_through_load_from_path[bidi override] / [130 characters] | |
| M-43 | app.py:`_busy_begin_action`:19986 | the `"{name}" in row.label` test inverted | B::test_tc_b100_50_each_worker_action_begins_with_a_progress_line[report] (KeyError/format of a name-less row is harmless — `format` ignores; label then wrong for `file_load`) | |
| M-44 | app.py:`_busy_fail`:19994 | drop the generation check | B::test_tc_b100_51_file_load_ends_once_on_success (A12-72: no second `… failed` end) — only if a stale `_busy_fail` is posted; main-thread `finally` sites make it observable: B::test_tc_b100_51_a2l_load_ends_once_on_success | |
| M-45 | app.py:`_busy_fail`:19996 | outcome `f"{run.label} failed"` → `"failed"` | B::test_tc_b100_50_worker_raise_ends_the_action_first[*]; LD::test_tc_b100_66_progress_lines_carry_no_decision_id (`endswith(" failed")` still true → only the B arms) | |
| M-46 | app.py:`set_file_status`:19757 | drop `if not self._busy.runs` (paint always) | B::test_tc_b100_50_file_state_waits_while_a_run_is_shown; B::test_tc_b100_50_status_line_has_one_owner_during_a_worker_load | |
| M-47 | app.py:`set_file_status`:19756 | store only when idle | B::test_tc_b100_50_last_end_paints_the_stored_file_state; B::test_tc_b100_50_image_pick_file_state_waits_for_a_running_report | |
| M-48 | app.py:`_paint_status_text`:19808 | drop `safe_text(...).plain` | B::test_tc_b100_50_names_paint_literally_through_load_from_path[ESC and BEL] (Linux CI only) | expected on Windows |
| M-49 | styles.tcss:`#workspace_status_bar #status_text.-busy`:582 | delete the rule | B::test_tc_b100_50_running_line_paints_in_the_accent | |

## G-A — the action sites

| # | file:function:line | Mutation | Expected killer | Survivor? |
|---|---|---|---|---|
| M-50 | app.py:`action_before_after_report`:5184 | drop `gen=gen` / begin | B::test_tc_b100_51_workers_take_the_run_generation; B::test_tc_b100_51_before_after_ends_once_and_logs_its_outcome | |
| M-51 | app.py:`_start_before_after_worker`:5293 | drop the `except BaseException` guard | B::test_tc_b100_50_worker_raise_ends_the_action_first[before_after] | |
| M-52 | app.py:`_start_before_after_worker`:5288 | refused exit posts no end | B::test_tc_b100_51_before_after_ends_once_and_logs_its_outcome[refused] | |
| M-53 | app.py:`_start_generate_report_worker`:5978 | `report_failed` posts no end | B::test_tc_b100_51_report_ends_once_on_a_failure[generator raises] | |
| M-54 | app.py:`_start_generate_report_worker`:6019 | rejected exit posts no end | B::test_tc_b100_51_report_ends_once_on_a_failure[rejected input] | |
| M-55 | app.py:`_start_generate_report_worker`:6042 | drop `step_busy(..., 2)` | B::test_tc_b100_51_report_ends_once_on_success (`[0, 50, 0]`); RP::test_report_generation_drives_progress_bar_to_100 (moves off 0) | |
| M-56 | app.py:`_start_generate_report_worker`:6054 | drop the `except BaseException` guard | B::test_tc_b100_50_worker_raise_ends_the_action_first[report] | |
| M-57 | app.py:`_finish_generate_report`:6130 | end with a stale `gen - 1` | RP::test_finish_generate_report_completes_bar; B::test_tc_b100_51_report_ends_once_on_success | |
| M-58 | app.py:`_start_diff_report_worker`:7324 | Markdown-refused exit: panel status before the end | none (order of two `call_from_thread` posts; no test reads the order) | expected |
| M-59 | app.py:`_start_diff_report_worker`:7328 | drop `step_busy(..., 2)` | B::test_tc_b100_51_diff_report_ends_once_and_logs_its_outcome[written] (`[0, 50, 0]`) | |
| M-60 | app.py:`_start_diff_report_worker`:7337 | HTML-raises exit posts no end | B::test_tc_b100_51_diff_report_ends_once_and_logs_its_outcome[html raises] | |
| M-61 | app.py:`_start_diff_report_worker`:7345 | HTML-refused exit posts no end | B::test_tc_b100_51_diff_report_ends_once_and_logs_its_outcome[html refused] | |
| M-62 | app.py:`_start_diff_report_worker`:7352 | written exit outcome text drops the HTML path | B::test_tc_b100_51_diff_report_ends_once_and_logs_its_outcome[written] (whole-text compare after the E4 fix) | |
| M-63 | app.py:`_start_diff_report_worker`:7354 | drop the `except BaseException` guard | B::test_tc_b100_50_worker_raise_ends_the_action_first[diff_report] | |
| M-64 | app.py:`_commit_project_save`:11166 | begin with `name=None` | B::test_tc_b100_51_save_project_reports_its_phases_as_steps (label `Saving project <name>`) | |
| M-65 | app.py:`_commit_project_save`:11232 | drop `step_busy(…, 2)` | B::test_tc_b100_51_save_project_reports_its_phases_as_steps | |
| M-66 | app.py:`_commit_project_save`:11477 | drop `step_busy(…, 3)` | B::test_tc_b100_51_save_project_reports_its_phases_as_steps | |
| M-67 | app.py:`_commit_project_save`:11564 | drop `step_busy(…, 4)` | B::test_tc_b100_51_save_project_reports_its_phases_as_steps | |
| M-68 | app.py:`_commit_project_save`:11710 | placement `OSError` arm: `end_busy` → `set_status` | B::test_tc_b100_51_save_project_ends_once_on_a_placement_failure (end then from the `finally`: outcome `… failed`, not the message) | |
| M-69 | app.py:`_commit_project_save`:11235 / 11261 / 11341 / 11367 / 11402 / 11579 / 11655 / 11672 / 11692 | any one of the other 9 abort `end_busy` → `set_status` | none per arm (only the placement arm is driven); the `finally` still ends the run with `Saving project <name> failed` and the abort message stays the second-to-last log line | expected (9 arms; A12-51-class debt, batch-end battery) |
| M-70 | app.py:`_commit_project_save`:11928 | tail: end with `tail[0]` instead of `tail[-1]` | B::test_tc_b100_51_save_project_reports_its_phases_as_steps (outcome = last log line) on a tail of ≥ 2 lines only; the success arm has 1 line | expected (A12-51 untested, declared) |
| M-71 | app.py:`_commit_project_save`:11939 | drop the outer `finally` | B::test_tc_b100_50_save_raise_ends_the_action_first | |
| M-72 | app.py:`_handle_load_project`:13226 | begin moved above the `project.json` gate | B::test_tc_b100_51_project_load_ends_once_on_a_failure_after_the_begin (A12a-02: 0 begins on an unreadable `project.json`) | |
| M-73 | app.py:`_handle_load_project`:13254 | `step_busy(…, 2)` unconditional (outside `if a2l_files`) | B::test_tc_b100_51_project_load_without_an_a2l_skips_its_step | |
| M-74 | app.py:`_handle_load_project`:13269 | all-`None` refusal: `end_busy` → `set_status` | B::test_tc_b100_51_project_load_ends_once_on_a_failure_after_the_begin (if it drives the A2L-only arm) / the `finally` then logs `… failed` | |
| M-75 | app.py:`_handle_load_project`:13316 / 13334 | drop step 3 or step 4 | B::test_tc_b100_51_project_load_ends_once_on_success (`[2, 3, 4]`) | |
| M-76 | app.py:`_handle_load_project`:13357 | drop `set_file_status(...)` of the project line | B::test_tc_b100_50_last_end_paints_the_stored_file_state / AN::test_tc_b100_56_project_line_is_the_file_state_painted_at_the_last_end (T reads the image's line) | |
| M-77 | app.py:`_handle_load_project`:13357–13358 | swap the order (end first, then `set_file_status`) | none for T (set_file_status paints when idle, same final T); the stored state is the same | expected |
| M-78 | app.py:`_handle_load_project`:13371 | drop the `finally` | B::test_tc_b100_50_project_raise_ends_the_action_first | |
| M-79 | app.py:`load_from_path`:14709 | begin before the suffix refusal | B::test_tc_b100_51_file_load_ends_once_on_a_containment_refusal does not cover suffix; none found for the suffix arm | expected |
| M-80 | app.py:`load_from_path`:14720 | containment arm posts no end | B::test_tc_b100_51_file_load_ends_once_on_a_containment_refusal | |
| M-81 | app.py:`load_from_path`:14751 | drop `step_busy(…, 2)` | B::test_tc_b100_51_file_load_ends_once_on_success (step sequence) | |
| M-82 | app.py:`load_from_path`:14756 | move `copied.stat()` after the dispatch (A12a-08) | none structural (declared in tester notes §5) | expected |
| M-83 | app.py:`load_from_path`:14773 | `except BaseException` → `finally` | B::test_tc_b100_51_file_load_ends_once_on_success (an extra `… failed` end at once) | |
| M-84 | app.py:`load_a2l_from_path`:14819 | containment arm posts no end | B::test_tc_b100_51_a2l_load_ends_once_on_a_containment_refusal | |
| M-85 | app.py:`load_a2l_from_path`:14848 / 14857 | drop step 2 or step 3 | B::test_tc_b100_51_a2l_load_ends_once_on_success | |
| M-86 | app.py:`load_a2l_from_path`:14883 | outcome without `painted_names` | none on Windows for a plain name; A12a-03 arm uses a plain name | expected |
| M-87 | app.py:`load_a2l_from_path`:14895 | drop the `finally` | B::test_tc_b100_50_a2l_raise_ends_the_action_first | |
| M-88 | app.py:`_start_load_worker`:17594 | drop `step_busy(…, 3)` | B::test_tc_b100_51_file_load_ends_once_on_success | |
| M-89 | app.py:`_start_load_worker`:17599–17601 | end before `_sync_loaded_file_to_project` (A12a-05) | B::test_tc_b100_51_file_load_ends_once_on_success (no log line after the end) — only with an open project | possible |
| M-90 | app.py:`_start_load_worker`:17603 | drop the `except BaseException` guard | B::test_tc_b100_50_worker_raise_ends_the_action_first[file_load] | |
| M-91 | app.py:`_handle_load_error`:17637 | `end_busy` → `set_progress(100)` (base) | B::test_tc_b100_51_file_load_ends_once_on_a_parse_failure | |

## G-B — labels and sweep

| # | file:function:line | Mutation | Expected killer | Survivor? |
|---|---|---|---|---|
| M-92 | app.py:`BINDINGS`:2414 | `ctrl+l` description back to `Load file` | LD::test_tc_b100_41_labels_key_bar_and_palette_say_load_and_projects; KB::test_tc_b97_67_*; DS::test_at_b78_32_app_bindings_block_is_untouched | |
| M-93 | app.py:`BINDINGS`:2427 | `p` description back to `Load project` | LD::test_tc_b100_41_labels_key_bar_and_palette_say_load_and_projects (palette); DS::test_at_b78_32_app_bindings_block_is_untouched | |
| M-94 | app.py:`refresh_files`:7676 | drop the `recent_kind` filter | R::test_tc_b100_37_files_list_shows_loadable_suffixes_only[*]; R::…_through_one_predicate | |
| M-95 | app.py:`list_projects`:13544 | restore `os.name == "nt" and` | R::test_tc_b100_37_project_list_skips_a_trailing_dot_on_every_platform (`posix` reading) | |
| M-96 | app.py:`list_projects`:13544 | drop `" "` from the suffix tuple | R::test_tc_b100_37_project_list_skips_a_trailing_dot_on_every_platform (if it has a trailing-space arm) | possible |
| M-97 | app.py:`_listed_project_name`:13560 | `normcase` dropped (exact compare) | R::test_tc_b100_38_one_project_match_returns_the_listed_spelling | |
| M-98 | app.py:`_handle_load_project`:13089 | inline a second match (two match functions) | R::test_tc_b100_38_one_project_match (AST) | |
| M-99 | app.py:`_handle_load_project`:13100 / `_load_path_from_user_input`:14593 | a literal refusal sentence instead of `_TYPED_REFUSAL_TOKENS` | R::test_tc_b100_38_one_wording_table | |
| M-100 | app.py:`_typed_load_route`:14418 | catch narrowed back to `(ValueError, RuntimeError)` | R::test_tc_b100_38_nul_in_typed_path_is_refused[EACCES-*/ENAMETOOLONG-*] | |
| M-101 | app.py:`_load_workarea_file`:15088 | pre-question `FileNotFoundError` → fall through | R::test_tc_b100_39_pick_rechecks_the_entry_and_fails_closed[vanished] (no question asked) | |
| M-102 | app.py:`_load_workarea_file`:15090 | pre-question `except OSError: pass` → `return` (S12a-R2-1) | R::test_tc_b100_39_pick_rechecks_the_entry_and_fails_closed[lstat refused] — the test injects the error into the SECOND lstat only (tester D-6), so | expected |
| M-103 | app.py:`_load_workarea_file`:15104 | `st = None` → `return` (fail open, silent) | R::test_tc_b100_39_pick_rechecks_the_entry_and_fails_closed[lstat refused] (refusal line expected) | |
| M-104 | app.py:`_load_workarea_file`:15107 | drop `not stat.S_ISREG(...)` | R::test_tc_b100_39_pick_rechecks_the_entry[folder-*] | |
| M-105 | app.py:`_load_workarea_file`:15108 | drop `_is_reparse_point(candidate)` | R::test_tc_b100_39_pick_rechecks_the_entry[junction-*] | |
| M-106 | app.py:`_load_workarea_file`:15120 | `>` → `>=` | R::test_tc_b100_39_pick_over_cap_is_refused[at the cap] | |
| M-107 | app.py:`_load_workarea_file`:15120 | read the cap as a constant captured at import | R::test_tc_b100_39_pick_over_cap_is_refused[over the cap] (monkeypatched module cap) | |
| M-108 | app.py:`_load_workarea_file`:15099 | re-check moved before the question (S12a-03) | R::test_tc_b100_39_pick_rechecks_the_entry_after_the_question | |

## Note on executed controls

- M-37 is the only row with an executed RED: the tree before SR-12a-2 is exactly that mutant, and `int-diag-D-repinned.txt` records `NoMatches: No nodes match '#status_text'` from `_busy_tick` in `RP::test_kickoff_sets_bar_in_progress_before_worker` (`1 failed, 21 passed`).
- Rows marked `expected` are the first candidates for an E5 test addition or a declared survivor.
