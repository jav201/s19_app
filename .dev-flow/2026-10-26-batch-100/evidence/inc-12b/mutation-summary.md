# Inc 12b — E5 mutation run summary

Copy: `<HOME>/AppData/Local/Temp/claude/C--Users-<USER>-clde/a8feab43-c248-4ccb-86cf-122b894659b2/scratchpad/mut12b`
Interpreter: `<HOME>/anaconda3/envs/s19env/python.exe`
sha256 before == after (app.py `6ada85782fdd80de…`, a2l.py `d70b17982f1cee30…`, styles.tcss `f7b4f75911b296a4…`). `<HOME>/AppData/Local/s19_app` does NOT exist before or after.

Counts: **KILLED 85 / SURVIVED 30 / INVALID 0** (TIMEOUT 0, FLAKY-KILL 0).

| id | requirement (file:function:line) | file | test (named killer) | verdict |
|---|---|---|---|---|
| 001 | app.py:_running_session_action:20364 | app.py | W running_session_action_ignores_reports | KILLED |
| 002 | app.py:_running_session_action:20362 | app.py | W busy_line_names_the_action_and_changes_nothing | SURVIVED |
| 003 | app.py:SESSION_ACTION_KEYS:~430 | app.py | W action_starts_refuse… ; Q the_load_guard_refuses… | SURVIVED |
| 004 | app.py:SESSION_ACTION_KEYS | app.py | W session_writers_are_refused_during_a_save | KILLED |
| 005 | app.py:_refuse_if_busy:20387 | app.py | W session_writers_are_refused_during_a_save | KILLED |
| 006 | app.py:_refuse_if_busy:20389 | app.py | W busy_line_names_the_action_and_changes_nothing | KILLED |
| 007 | app.py:_BUSY_LINE | app.py | W session_writers_are_refused_during_a_save | KILLED |
| 008 | app.py:action_quit:20395 | app.py | W quit_asks_only_while_a_session_action_runs | KILLED |
| 009 | app.py:action_quit:20401 | app.py | W quit_asks_only_while_a_session_action_runs | KILLED |
| 010 | app.py:action_quit:20404 | app.py | W quit_asks_only_while_a_session_action_runs | KILLED |
| 011 | app.py:_answer_quit:20415 | app.py | W stay_keeps_the_save_running | KILLED |
| 012 | app.py:_answer_quit:20416 | app.py | W quit_boundaries | KILLED |
| 013 | app.py:_answer_quit:20415 | app.py | W quit_boundaries | KILLED |
| 014 | app.py:_exit_if_quit_pending:20420 | app.py | W confirmed_quit_waits_for_the_end | KILLED |
| 015 | app.py:end_busy:20283 | app.py | W confirmed_quit_waits_for_the_end | KILLED |
| 016 | app.py:end_busy:20283 | app.py | W confirmed_quit_waits_for_the_end | KILLED |
| 017 | app.py:end_busy:20260 | app.py | W paste_box_is_read_only_during_a_project_load | KILLED |
| 018 | app.py:end_busy:20266 | app.py | W paste_box_is_read_only_during_a_project_load | KILLED |
| 019 | app.py:_handle_load_project:13455 | app.py | W paste_box_is_read_only_during_a_project_load | KILLED |
| 020 | app.py:_progress_forwarder:20449 | app.py | W case06_project_load… | KILLED |
| 021 | app.py:_progress_forwarder:20449 | app.py | W case06_project_load… ; W save_reports_each_file_placed | SURVIVED |
| 022 | app.py:_progress_forwarder:20448 | app.py | W case06_project_load… | SURVIVED |
| 023 | app.py:_progress_forwarder | app.py | W save_reports_each_file_placed | KILLED |
| 024 | app.py:_handle_load_project:13278 | app.py | W action_starts_refuse_while_another_session_action_runs | KILLED |
| 025 | app.py:_handle_load_project:13469 | app.py | B twelve_b_kickoff_raise_ends_the_run_first[project_load] | KILLED |
| 026 | app.py:_handle_load_project | app.py | W load_result_panel_opens_after_the_install | KILLED |
| 027 | app.py:_route_load_project:8338 | app.py | W load_result_panel_opens_after_the_install | KILLED |
| 028 | app.py:_project_load_worker:13484 | app.py | B twelve_b_handler_raise_ends_the_run_first[project_load] | KILLED |
| 029 | app.py:_project_load_worker | app.py | W project_worker_failure_keeps_the_session | KILLED |
| 030 | app.py:_prepare_project_load:13508 | app.py | W project_over_an_open_image_equals_a_cold_load | KILLED |
| 031 | app.py:_prepare_project_load | app.py | W case06_project_load… | KILLED |
| 032 | app.py:_prepare_project_load | app.py | B twelve_b_seam_sites_sit_in_the_workers_and_handlers | KILLED |
| 033 | app.py:_prepare_project_load | app.py | B project_load_ends_once_on_a_failure_after_the_begin | KILLED |
| 034 | app.py:_prepare_project_load:13532 | app.py | B project_load_ends_once_on_a_failure_after_the_begin | KILLED |
| 035 | app.py:_prepare_project_load:13577 | app.py | project_check test_tc_b100_61_empty_image_is_not_readable… | KILLED |
| 036 | app.py:_prepare_project_load:13613 | app.py | W project_over_an_open_image_equals_a_cold_load | KILLED |
| 037 | app.py:_prepare_project_load | app.py | B twelve_b_seam_sites_sit… | KILLED |
| 038 | app.py:_prepare_project_load | app.py | W project_load_reads_every_file_on_a_worker | KILLED |
| 039 | app.py:_on_project_loaded:13632 | app.py | B project_load_ends_once_on_a_failure_after_the_begin | SURVIVED |
| 040 | app.py:_on_project_loaded:13636 | app.py | P project_install_step_is_painted_before_the_install | KILLED |
| 041 | app.py:_install_prepared_project:13644 | app.py | R reset_runs_once_before_the_first_install | KILLED |
| 042 | app.py:_install_prepared_project:13650 | app.py | test_tui_app a2l_cache_reuses_parse_for_unchanged_file | SURVIVED |
| 043 | app.py:_install_prepared_project:13665 | app.py | W reset_runs_after_the_worker_and_before_the_first_install | KILLED |
| 044 | app.py:_install_prepared_project:13670 | app.py | R reset_runs_once_before_the_first_install | KILLED |
| 045 | app.py:_install_prepared_project:13698 | app.py | W load_result_panel_opens_after_the_install | KILLED |
| 046 | app.py:_install_prepared_project | app.py | W confirmed_quit_waits_for_the_end[project] | SURVIVED |
| 047 | app.py:_install_prepared_project:13706 | app.py | B twelve_b_handler_raise_ends_the_run_first[project_load] | SURVIVED |
| 048 | app.py:_on_project_load_failed:13716 | app.py | W project_worker_failure_keeps_the_session | SURVIVED |
| 049 | app.py:_on_project_load_failed | app.py | W project_worker_failure_keeps_the_session | KILLED |
| 050 | app.py:parse_a2l_cached:914 | app.py | test_tui_app a2l_cache_reuses_parse_for_unchanged_file | SURVIVED |
| 051 | app.py:parse_a2l_cached | app.py | W case06_a2l_attach… | KILLED |
| 052 | app.py:_a2l_cache_entry:17985 | app.py | W project_over_an_open_image_equals_a_cold_load | SURVIVED |
| 053 | app.py:_parse_loaded_file:17331 | app.py | W session_is_written_only_on_the_main_thread | KILLED |
| 054 | app.py:load_selected_file:17316 | app.py | test_tui_app a2l_cache_reuses_parse_for_unchanged_file | SURVIVED |
| 055 | app.py:_start_load_worker:17925 | app.py | W session_is_written_only_on_the_main_thread | KILLED |
| 056 | app.py:_apply_prepared_load:17474 | app.py | W session_is_written_only_on_the_main_thread | KILLED |
| 057 | app.py:_handle_load_error:17982 | app.py | B file_load_ends_once_on_a_parse_failure | SURVIVED |
| 058 | app.py:_commit_project_save:11463 | app.py | W action_starts_refuse_while_another_session_action_runs | KILLED |
| 059 | app.py:_commit_project_save:11468 | app.py | save_image test_tc_b100_15_patched_hex_is_emitted | KILLED |
| 060 | app.py:_commit_project_save:11493 | app.py | W save_rederives_on_main_before_the_worker | SURVIVED |
| 061 | app.py:_commit_project_save:11513 | app.py | B twelve_b_kickoff_raise_ends_the_run_first[save_project] | KILLED |
| 062 | app.py:_save_project_worker:11522 | app.py | G each_save_stage_failure_on_the_worker_rolls_back[mkdir] | KILLED |
| 063 | app.py:_save_project_worker:11533 | app.py | B twelve_b_handler_raise_ends_the_run_first[save_project] | KILLED |
| 064 | app.py:_save_project_files:11549 | app.py | W save_reports_each_file_placed | KILLED |
| 065 | app.py:_save_project_files:11551 | app.py | W save_reports_each_file_placed | SURVIVED |
| 066 | app.py:_save_project_files:11592 | app.py | W save_reports_each_file_placed | KILLED |
| 067 | app.py:_save_project_files:11654 | app.py | W save_reports_each_file_placed | SURVIVED |
| 068 | app.py:_save_project_files:11747 | app.py | W save_reports_each_file_placed | KILLED |
| 069 | app.py:_save_project_files:11641 | app.py | document test_tc_b100_29_failure_after_the_write_removes_the_document | KILLED |
| 070 | app.py:_save_project_files:11712 | app.py | save_image test_tc_b100_17_verify_reread_failure_rolls_the_emit_back | KILLED |
| 071 | app.py:_save_project_files:11715 | app.py | save_image test_tc_b100_17_emit_refusal_writes_no_manifest | SURVIVED |
| 072 | app.py:_save_project_files:11820 | app.py | patch_variant test_at035b_switch_persists_on_save_and_load_consumes | SURVIVED |
| 073 | app.py:_save_project_files | app.py | B save_project_reports_its_phases_as_steps | KILLED |
| 074 | app.py:_save_project_files | app.py | B save_project_reports_its_phases_as_steps | KILLED |
| 075 | app.py:_save_project_files | app.py | G ast_census_every_post_creation_return_removes | KILLED |
| 076 | app.py:_save_project_files | app.py | G ast_census_every_post_creation_return_removes | KILLED |
| 077 | app.py:_on_project_saved:12159 | app.py | W confirmed_quit_waits_for_the_end[save_fails] | KILLED |
| 078 | app.py:_on_project_saved:12163 | app.py | W confirmed_quit_waits_for_the_end[save_fails] | KILLED |
| 079 | app.py:_on_project_saved | app.py | B save_validation_abort_ends_with_its_own_line | SURVIVED |
| 080 | app.py:_on_project_saved:12175 | app.py | W stay_keeps_the_save_running | KILLED |
| 081 | app.py:_on_project_saved:12195 | app.py | W save_adopts_only_after_the_commit | KILLED |
| 082 | app.py:_on_project_saved:12197 | app.py | save_image test_tc_b100_58_save_project_records_the_saved_state | SURVIVED |
| 083 | app.py:_on_project_saved:12205 | app.py | save_image test_tc_b100_58_save_project_records_the_saved_state | KILLED |
| 084 | app.py:_on_project_saved:12281 | app.py | B raise_after_the_commit_keeps_the_saved_line | SURVIVED |
| 085 | app.py:_on_project_saved:12282 | app.py | B raise_after_the_commit_keeps_the_saved_line | KILLED |
| 086 | app.py:_on_project_saved | app.py | B raise_after_the_commit_keeps_the_saved_line | KILLED |
| 087 | app.py:_on_project_saved | app.py | B raise_after_the_commit_keeps_the_saved_line | SURVIVED |
| 088 | app.py:load_a2l_from_path:15136 | app.py | W action_starts_refuse_while_another_session_action_runs | KILLED |
| 089 | app.py:load_a2l_from_path:15177 | app.py | recents test_tc_b100_34_a2l_found_only_through_the_fallback… | KILLED |
| 090 | app.py:load_a2l_from_path:15194 | app.py | load_dialog workarea_a2l_choice_equals_the_files_list_pick | SURVIVED |
| 091 | app.py:load_a2l_from_path:15198 | app.py | B a2l_load_ends_once_on_success | SURVIVED |
| 092 | app.py:_a2l_attach_worker:15207 | app.py | W every_a2l_attach_route_parses_on_a_worker | KILLED |
| 093 | app.py:_a2l_attach_worker:15229 | app.py | W a2l_worker_failure_keeps_the_session[containment] | SURVIVED |
| 094 | app.py:_a2l_attach_worker:15235 | app.py | B twelve_b_handler_raise_ends_the_run_first[a2l_load] | KILLED |
| 095 | app.py:_on_a2l_attached | app.py | P a2l_tag_table_step_is_painted_before_the_build | KILLED |
| 096 | app.py:_install_attached_a2l:15249 | app.py | recents test_tc_b100_34_source_inside_the_work_area_is_not_recorded | KILLED |
| 097 | app.py:_install_attached_a2l:15287 | app.py | B a2l_deferred_install_raise_ends_the_run | KILLED |
| 098 | app.py:_on_a2l_attach_failed:15294 | app.py | W a2l_worker_failure_keeps_the_session[containment] | KILLED |
| 099 | app.py:_on_a2l_attach_failed:15299 | app.py | W a2l_worker_failure_keeps_the_session[copy] | SURVIVED |
| 100 | app.py:_load_workarea_file:~15545 | app.py | W workarea_pick_begins_a_file_load_and_never_syncs_the_project | KILLED |
| 101 | app.py:_load_workarea_file | app.py | W every_a2l_attach_route_parses_on_a_worker | KILLED |
| 102 | app.py:_start_load_worker:17942 | app.py | W workarea_pick_begins_a_file_load_and_never_syncs_the_project | KILLED |
| 103 | app.py:_confirm_then_load:8160 | app.py | Q the_load_guard_refuses_while_busy_before_it_asks | SURVIVED |
| 104 | app.py:16 entry + 4 continuations | app.py | W patch_editor_changes_are_refused_while_busy | KILLED |
| 105 | app.py:load_from_path:15049 | app.py | B use_time_resolve_error…[load_from_path-ValueError/RuntimeError] | KILLED |
| 106 | app.py:load_a2l_from_path:15138 | app.py | B use_time_resolve_error…[load_a2l_from_path-ValueError] | KILLED |
| 107 | app.py:_load_path_from_user_input:14919 | app.py | B path_gone_under_the_load_question_keeps_the_app | SURVIVED |
| 108 | app.py:compose:3373 | app.py | B progress_bar_paints_no_eta | KILLED |
| 109 | a2l.py:build_section_tree:196 | a2l.py | P case06_reports_bytes_and_parses_the_same | KILLED |
| 110 | a2l.py:build_section_tree:197 | a2l.py | P case06_reports_bytes_and_parses_the_same | SURVIVED |
| 111 | a2l.py:build_section_tree:230 | a2l.py | P small_a2l_reports_once_and_parses_the_same | KILLED |
| 112 | a2l.py:build_section_tree:229 | a2l.py | P a_failed_read_reports_no_final_total | KILLED |
| 113 | a2l.py:build_section_tree:194 | a2l.py | P case06_reports_bytes_and_parses_the_same | SURVIVED |
| 114 | a2l.py:parse_a2l_file:2681 | a2l.py | P case06_reports_bytes_and_parses_the_same | KILLED |
| 115 | a2l.py:_PROGRESS_LINES | a2l.py | P case06_reports_bytes_and_parses_the_same | KILLED |

## Survivors (30)

Equivalent mutants (the mutation does not change observable behaviour for the named test):
- **002** — `reversed(...)` removed: only one session run can exist at a time (every start is refused), so the iteration order is never observed with two session runs.
- **021** — `or done >= total` dropped: the final report's `pct` is always 100, which always differs from the previous (`<100`); the clause is redundant.
- **022** — `else 100`: unreachable branch (the `total == 0` case never occurs in practice).
- **052** — `_a2l_cache_entry` `and data is not None` → `or`: the two fields are always set together.
- **060** — `copy.deepcopy(document)` → `document`: no arm edits the document while the Save worker writes it (every edit is refused while busy).
- **099** — `if request.copy: refresh_files()` → always: an extra refresh is invisible.
- **110** — `handle.buffer.tell()` → `total`: the test only asserts non-decreasing consumed values and `(size,size)` last, which `(size,size)` every report still satisfies.
- **113** — `total` from `path.stat()`: same value as `os.fstat` for a regular file.

Weak test (named killer does not drive the mutated branch):
- **003** — drop `"file_load"` from SESSION_ACTION_KEYS: both named killers hold an `a2l_load` / `save_project` as the running action, never a `file_load`.
- **042** — `_install_prepared_project` store skipped: the named `test_a2l_cache_reuses_parse_for_unchanged_file` is a pure unit test of `parse_a2l_cached`, not the store site.
- **050** — `cached[0] == key` → `True` (stale hit): the named test only has the unchanged-file arm (which still hits); no changed-file arm exists.
- **054** — `load_selected_file` store removed: named killer is the same pure unit test; no test drives a synchronous load with an attached A2L cache.
- **071** — `if path is None or not landed` → `if path is None`: the named test drives `path is None` (emit returns `None`), not the `not landed` branch.
- **079** — failure `end_busy` moved before the lines: the validation abort has an empty `outcome.lines`, so the move is a no-op.
- **082** — `summary.verify_result` not set: the named test checks `mark_saved` / `differs_from_last_saved`, not `summary.verify_result`.
- **103** — busy check moved after `_load_would_lose`: the busy check is still before `push_screen`, so the question is still never asked.

Wrong target (named killer does not touch the mutated arm at all):
- **039** — `_on_project_loaded` refusal `_quit_pending = False` removed: no arm confirms a quit during a refused project load.
- **046** — `end_busy` before the panel push: a direct load has no panel push; no test drives a routed load with a pending quit.
- **047** — `_install_prepared_project` `except` guard removed: no arm raises inside `_install_prepared_project`.
- **048** — `_on_project_load_failed` `_quit_pending` removed: no test confirms a quit before a project-load worker failure.
- **057** — `_handle_load_error` `_quit_pending` removed: no test confirms a quit before a file-load failure.
- **065** — file-backed document row counted in `total`: no test saves a file-backed document row and reads the forwards.
- **067** — `tick()` removed from document placement: the forwards tests save no pasted document.
- **072** — `target_carry.get("batch")` → `()`: no test drives the batch-carry `else` branch (a merge into a target carrying a batch).
- **084** — `run.gen == gen` check removed: no arm produces a stale `end_busy` after an effective end.
- **087** — `saved_painted = len(tail) > 1` → `False`: needs a raise after a multi-line tail, which no arm produces.
- **090** — `if not copy:` step 2 removed: the in-place pick's step 2 is only a bar value; no arm reads the bar of an in-place attach.
- **091** — `load_a2l_from_path` kickoff guard removed: no arm raises in the A2L kickoff.
- **093** — containment logged as an exception: log-only.
- **107** — `_load_path_from_user_input` data-arm `except` removed: the classifier's own guarded look runs first; a raise needs the path to change between two looks in one call.

Note: rows **035**, **043** and **101** were reported KILLED via a *more relevant* test than the named killer (the named killer passed because it drives a different branch); the actual killing test is noted in the per-mutant transcript.

## Round 2

The 30 survivors re-read against the round-1 code (d4d9c1a). New and strengthened arms were written (tests only). Each non-equivalent row was re-run on the scratch copy `scratchpad/mutc12b` with the mutant applied to the current code, and each record is `mut-r2-NNN.txt`. Every record shows `restored = True`, and the sha256 of `app.py` (`46f7ee6aa8a0fbfb…`) and `a2l.py` (`73c3820fe0d6ecd2…`) is equal before and after.

Counts: **KILLED 22** (003 039 042 047 048 050 054 057 065 067 071 072 079 082 087 090 091 093 099 107 110 113; 072 and 113 by tests that already existed) / **EQUIVALENT 7** (002 021 022 052 060 084 103) / **NOT KILLED 1** (046: blocked by product defect R2-F1; its arm is `xfail(strict=True)`, and the record shows `1 xfailed` = SURVIVED) / **TARGET REMOVED 0**. Rows 099 and 110, called equivalent in round 1, are refuted. Rows 084 and 103 (weak test / wrong target in round 1) are equivalent on reading. Each disposition and its reason: `inc-12b/E5-corrective-notes.md` § "Round 2 — mutant survivors". GREEN: `green-07-mutant-arms.txt` (26 passed, 1 xfailed).
