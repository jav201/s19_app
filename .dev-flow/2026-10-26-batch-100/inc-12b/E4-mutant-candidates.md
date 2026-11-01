# Inc 12b — E4 mutant candidates

One row per NEW branch or arm in the 12b source (the integrated tree; line numbers are those of the final `s19_app/tui/app.py` / `s19_app/tui/a2l.py`, see the shas in `E4-integration-notes.md`). Short test names: `W` = `tests/test_b100_workers.py`, `B` = `tests/test_b100_busy.py`, `P` = `tests/test_b100_a2l_progress.py`, `G` = `tests/test_b100_save_guards.py`, `Q` = `tests/test_b100_load_question.py`, `R` = `tests/test_b100_session_reset.py`, `SD` = `tests/test_b100_save_dialog.py`.
Column **Exp.** = expected result: `K` killed, `S?` expected survivor (with the reason). None of these mutants was run here (E5 owns the mutation run); the killers are named from the test bodies, not measured.

## G-C1 — busy check, quit, end tail, forwarder

| # | file:function:line | Mutation | Expected killer | Exp. |
|---|---|---|---|---|
| 1 | app.py:`_running_session_action`:20364 | `if key in SESSION_ACTION_KEYS` → `if True` (reports count as session actions) | W `test_tc_b100_53_running_session_action_ignores_reports` | K |
| 2 | app.py:`_running_session_action`:20362 | `reversed(...)` removed (oldest run first) | W `…busy_line_names_the_action_and_changes_nothing` (two runs: the newest names the line) | S? — only one session run can exist at a time once every start is refused; the order matters only with two session runs |
| 3 | app.py:`SESSION_ACTION_KEYS`:~430 | drop `"file_load"` from the set | W `…action_starts_refuse_while_another_session_action_runs`; Q `test_tc_b100_72_…` (a file load running) | K |
| 4 | app.py:`SESSION_ACTION_KEYS` | drop `"save_project"` | W `…session_writers_are_refused_during_a_save` | K |
| 5 | app.py:`_refuse_if_busy`:20387 | `return False` when busy (no refusal) | W `…session_writers_are_refused_during_a_save` (8 of 8) | K |
| 6 | app.py:`_refuse_if_busy`:20389 | busy line not painted (`set_status` removed) | W `…busy_line_names_the_action_and_changes_nothing`; Q `test_tc_b100_66_…` | K |
| 7 | app.py:`_BUSY_LINE` | text changed (`— wait for it to finish.` dropped) | W `busy()` oracle in every refusal arm | K |
| 8 | app.py:`action_quit`:20395 | idle arm: `self.exit()` → push the question | W `…quit_asks_only_while_a_session_action_runs` (idle q exits, 0 questions) | K |
| 9 | app.py:`action_quit`:20401 | Q-c2 guard removed (a second `ctrl+q` stacks a second question) | W `…quit_boundaries` (arm: `ctrl+q` under the question) | K |
| 10 | app.py:`action_quit`:20404 | `_QUIT_BODY.format(label=run.label)` → `_QUIT_BODY` unformatted | W `…quit_asks_only_while_a_session_action_runs` (texts); Q `test_tc_b100_66_…` | K |
| 11 | app.py:`_answer_quit`:20415 | `bool(quit)` → `True` (Stay quits) | W `test_tc_b100_53_stay_keeps_the_save_running` | K |
| 12 | app.py:`_answer_quit`:20416 | the immediate `_exit_if_quit_pending()` removed (an action that ended while the question was open never exits) | W `…quit_boundaries` (arm: the action ends under the question, then `y`) | K |
| 13 | app.py:`_answer_quit`:20415 | `self._quit_pending = bool(quit)` → `self._quit_pending or bool(quit)` (a later Stay does not withdraw a confirmed quit) | W `test_tc_b100_53_quit_boundaries` (arm 2, C12b-26 b) | K |
| 14 | app.py:`_exit_if_quit_pending`:20420 | drop `and self._running_session_action() is None` (exit while busy) | W `…confirmed_quit_waits_for_the_end[save]` (app alive while held) | K |
| 15 | app.py:`end_busy`:20283 | the `_exit_if_quit_pending()` tail removed | W `…confirmed_quit_waits_for_the_end[save, project, a2l]` (never exits) | K |
| 16 | app.py:`end_busy`:20283 | the tail moved before the hand-back (`del runs[key]`) | W `…confirmed_quit_waits_for_the_end` (exit sees the run still open → no exit) | K |
| 17 | app.py:`end_busy`:20260 | `if key == "project_load":` → `if False:` (paste box stays read-only) | W `test_tc_b100_53_paste_box_is_read_only_during_a_project_load` (typing after the end) | K |
| 18 | app.py:`end_busy`:20266 | `read_only = False` → `True` | same as 17 | K |
| 19 | app.py:`_handle_load_project`:13455 | `read_only = True` removed | W `…paste_box_is_read_only_during_a_project_load` (a typed key during the load) | K |
| 20 | app.py:`_progress_forwarder`:20449 | `pct != last[0]` → `True` (forward every report) | W `…case06_project_load…` (`forwards <= 101`) | K |
| 21 | app.py:`_progress_forwarder`:20449 | drop `or done >= total` (the final `(total, total)` may be skipped) | W `…case06_project_load…` (`step2[-1] == 50`); W `…save_reports_each_file_placed` | K |
| 22 | app.py:`_progress_forwarder`:20448 | `if total > 0 else 0` → `else 100` | none (total is never 0: the parser reports file sizes ≥ 1 and the Save total counts ≥ 1 placement) | S? — unreachable branch |
| 23 | app.py:`_progress_forwarder` | forward with `n + 1` | W `…save_reports_each_file_placed` (forwards on step 2) | K |

## G-A — project load

| # | file:function:line | Mutation | Expected killer | Exp. |
|---|---|---|---|---|
| 24 | app.py:`_handle_load_project`:13278 | the busy check (Q-a1) removed | W `…action_starts_refuse_while_another_session_action_runs` | K |
| 25 | app.py:`_handle_load_project`:13469 | kickoff guard `_busy_fail` removed | B `test_tc_b100_50_twelve_b_kickoff_raise_ends_the_run_first[project_load]` | K |
| 26 | app.py:`_handle_load_project` | `routed` not passed into the request (always `False`) | W `test_tc_b100_53_load_result_panel_opens_after_the_install` | K |
| 27 | app.py:`_route_load_project`:8338 | `routed=True` → `routed=False` | W `…load_result_panel_opens_after_the_install` | K |
| 28 | app.py:`_project_load_worker`:13484 | outer `_busy_fail` post removed | B `…twelve_b_handler_raise_ends_the_run_first[project_load]` | K |
| 29 | app.py:`_project_load_worker` | inner `except Exception` removed (the step failure escapes) | W `test_tc_b100_54_project_worker_failure_keeps_the_session[PermissionError, ValueError]` | K |
| 30 | app.py:`_prepare_project_load`:13508 | `if a2l_files:` → `if False:` (no A2L parse) | W `…project_over_an_open_image_equals_a_cold_load` (digest with the A2L) | K |
| 31 | app.py:`_prepare_project_load` | `progress=` not passed to `parse_a2l_cached` | W `…case06_project_load…` (≥ 2 increases within step 2) | K |
| 32 | app.py:`_prepare_project_load` | step 2 post removed | B `test_tc_b100_51_twelve_b_seam_sites_sit_in_the_workers_and_handlers`; B `…project_load_ends_once_on_success` (bar) | K |
| 33 | app.py:`_prepare_project_load` | the A2L parse `except` arm removed | B `test_tc_b100_51_project_load_ends_once_on_a_failure_after_the_begin` / `…unreadable_a2l_is_its_own_problem…` (project_check) | K |
| 34 | app.py:`_prepare_project_load`:13532 | the all-`None` refusal returns `refusal=None` | B `test_tc_b100_51_project_load_…` (A2LONLY arm: `No supported files in project: A2LONLY`) | K |
| 35 | app.py:`_prepare_project_load`:13577 | next-valid loop: `continue` → `break` (first unreadable variant kept) | `test_b100_project_check.py::test_tc_b100_26_active_deleted_the_other_opens` | K |
| 36 | app.py:`_prepare_project_load`:13613 | MAC merged with `None` instead of `image` | `test_memmap_entropy_merge.py::test_memory_map_renders_when_s19_and_mac_coexist`; W `…equals_a_cold_load` | K |
| 37 | app.py:`_prepare_project_load` | step 3 post removed | B `…twelve_b_seam_sites_sit…` | K |
| 38 | app.py:`_prepare_project_load` | recorded document not read (`document = None`) | W `test_tc_b100_53_project_load_reads_every_file_on_a_worker` (1 entry) | K |
| 39 | app.py:`_on_project_loaded`:13632 | refusal arm: `_quit_pending = False` removed | none: no arm confirms a quit during a refused project load | S? — needs q/y during a load that ends in the all-`None` refusal |
| 40 | app.py:`_on_project_loaded`:13636 | step 4 painted after the install (`call_after_refresh` removed, install inline) | P `test_tc_b100_52_project_install_step_is_painted_before_the_install[case_06, case_01]` | K |
| 41 | app.py:`_install_prepared_project`:13644 | `_reset_project_session()` removed | `test_b100_session_reset.py::test_tc_b100_08_reset_runs_once_before_the_first_install`; R `…the_one_reset_call_sits_in_the_install_handler` | K |
| 42 | app.py:`_install_prepared_project`:13650 | `_store_a2l_cache` skipped | `test_tui_app.py::test_a2l_cache_reuses_parse_for_unchanged_file` (re-pinned C6) | K |
| 43 | app.py:`_install_prepared_project`:13665 | image install skipped | W `…equals_a_cold_load` | K |
| 44 | app.py:`_install_prepared_project`:13670 | MAC install skipped | R `…reset_runs_once_before_the_first_install` (`["reset","install","install"]`) | K |
| 45 | app.py:`_install_prepared_project`:13698 | `if request.routed` → `if True` (panel on direct loads) | W `…load_result_panel_opens_after_the_install` (0 panels on the direct route) | K |
| 46 | app.py:`_install_prepared_project` | `end_busy` moved before the panel push (end not last) | W `…confirmed_quit_waits_for_the_end[project]` (announcement at exit) | K |
| 47 | app.py:`_install_prepared_project`:13706 | `except BaseException: _busy_fail` removed | B `…twelve_b_handler_raise_ends_the_run_first[project_load]` variant via the deferred install | S? — the B arm raises in `_on_project_loaded`, not in the deferred install; no arm raises inside `_install_prepared_project` |
| 48 | app.py:`_on_project_load_failed`:13716 | `_quit_pending = False` removed | none (no confirmed quit before a worker failure of a project load) | S? |
| 49 | app.py:`_on_project_load_failed` | end outcome text changed | W `test_tc_b100_54_project_worker_failure_keeps_the_session` | K |
| 50 | app.py:`parse_a2l_cached`:914 | `cached[0] == key` → `True` (stale hit) | `test_tui_app.py::test_a2l_cache_reuses_parse_for_unchanged_file` (changed-file arm) | K |
| 51 | app.py:`parse_a2l_cached` | always parse without the callback | P `…a2l_tag_table_step…` / W `…case06_a2l_attach…` (≥ 2 increases) | K |
| 52 | app.py:`_a2l_cache_entry`:17985 | `and data is not None` → `or` | none (the two fields are set together by `_store_a2l_cache`) | S? — equivalent |
| 53 | app.py:`_parse_loaded_file`:17331 | the out-list append removed | W `test_tc_b100_53_session_is_written_only_on_the_main_thread` (cache written off main / not at all) and `test_tui_app.py::test_a2l_cache_reuses_parse_for_unchanged_file` | K |
| 54 | app.py:`load_selected_file`:17316 | `if out:` store removed | `test_tui_app.py::test_a2l_cache_reuses_parse_for_unchanged_file` | K |
| 55 | app.py:`_start_load_worker`:17925 | `prepared.a2l_cache = out[0]` removed | W `…session_is_written_only_on_the_main_thread` (file-load cache) | K |
| 56 | app.py:`_apply_prepared_load`:17474 | store skipped | same as 55 | K |
| 57 | app.py:`_handle_load_error`:17982 | `_quit_pending = False` removed | none written for the file-load failure | S? |

## G-B — Save project

| # | file:function:line | Mutation | Expected killer | Exp. |
|---|---|---|---|---|
| 58 | app.py:`_commit_project_save`:11463 | busy check removed | W `…action_starts_refuse_while_another_session_action_runs` | K |
| 59 | app.py:`_commit_project_save`:11468 | `image_input` always `None` (no emit) | `test_b100_save_image.py::test_tc_b100_15_patched_hex_is_emitted`; SD `…save_as_then_patch_then_direct_save_plans_fresh` | K |
| 60 | app.py:`_commit_project_save`:11493 | `copy.deepcopy(document)` → `document` (shared snapshot) | none: no arm edits the document while the Save worker writes it | S? — needs an edit under a held save; every Patch Editor change is refused while busy (rows 5/6), so the race is closed by the refusal |
| 61 | app.py:`_commit_project_save`:11513 | kickoff `_busy_fail` removed | B `…twelve_b_kickoff_raise_ends_the_run_first[save_project]` | K |
| 62 | app.py:`_save_project_worker`:11522 | the outer `except Exception` removed | G `test_tc_b100_07_each_save_stage_failure_on_the_worker_rolls_back[mkdir]` | K |
| 63 | app.py:`_save_project_worker`:11533 | outer `_busy_fail` post removed | B `…twelve_b_handler_raise_ends_the_run_first[save_project]` | K |
| 64 | app.py:`_save_project_files`:11549 | the total counts manifest/carried rows | W `…save_reports_each_file_placed` (`(1, 3)…`) | K |
| 65 | app.py:`_save_project_files`:11551 | file-backed document row counted | none: no arm saves a file-backed document row and reads the forwards | S? |
| 66 | app.py:`_save_project_files`:11592 | step 2 post removed | W `…save_reports_each_file_placed` (posted `[2, 3, 4]`) | K |
| 67 | app.py:`_save_project_files`:11654 | `tick()` removed from the document placement | none: the forward arms save no pasted document | S? |
| 68 | app.py:`_save_project_files`:11747 | `tick()` removed from the row placement | W `…save_reports_each_file_placed` | K |
| 69 | app.py:`_save_project_files`:11641 | `created_home` always `None` | `test_b100_document.py::test_tc_b100_29_failure_after_the_write_removes_the_document` | K |
| 70 | app.py:`_save_project_files`:11712 | `emit_verify` not computed | `test_b100_save_image.py::test_tc_b100_17_verify_reread_failure_rolls_the_emit_back` | K |
| 71 | app.py:`_save_project_files`:11715 | `if path is None or not landed` → `if path is None` | `test_b100_save_image.py::test_tc_b100_17_emit_refusal_writes_no_manifest` | K |
| 72 | app.py:`_save_project_files`:11820 | `prepared.target_carry.get("batch")` → `()` (F-1's site) | `test_b100_save_guards.py` merge-carry arms / `test_tui_patch_variant.py::test_at035b_switch_persists_on_save_and_load_consumes` | K |
| 73 | app.py:`_save_project_files` | step 3 post removed | B `…save_project_reports_its_phases_as_steps` | K |
| 74 | app.py:`_save_project_files` | step 4 post removed | B `…save_project_reports_its_phases_as_steps` | K |
| 75 | app.py:`_save_project_files` | the `except Exception` arm re-raises (SEC-7 kept) | G `test_tc_b100_07_ast_census_every_post_creation_return_removes` (no `raise`); W `test_tc_b100_54_save_worker_non_os_error_rolls_back_and_reports` | K |
| 76 | app.py:`_save_project_files` | one abort `return` without `_abort_save` | G `…ast_census…`; B `test_tc_b100_51_every_save_abort_return_ends_its_run_first` | K |
| 77 | app.py:`_on_project_saved`:12159 | failure arm: `_quit_pending = False` removed | W `…confirmed_quit_waits_for_the_end[save_fails]` (the app exits) | K |
| 78 | app.py:`_on_project_saved`:12163 | toast skipped | W `…confirmed_quit_waits_for_the_end[save_fails]` (notify spy); G `…[placement]` | K |
| 79 | app.py:`_on_project_saved` | failure end before the lines (`end_busy` first) | B `test_tc_b100_51_save_validation_abort_ends_with_its_own_line` (last line) | K |
| 80 | app.py:`_on_project_saved`:12175 | no-variant form always used | W `…stay_keeps_the_save_running` (`(variant 'firmware')`) | K |
| 81 | app.py:`_on_project_saved`:12195 | `adopt_rederived` skipped | W `test_tc_b100_53_save_adopts_only_after_the_commit` | K |
| 82 | app.py:`_on_project_saved`:12197 | `summary.verify_result` not set | `test_b100_save_image.py::test_tc_b100_58_save_project_records_the_saved_state` | K |
| 83 | app.py:`_on_project_saved`:12205 | `mark_saved` skipped | `test_b100_save_image.py::test_tc_b100_58_…`; SD `test_tc_b100_65_pending_line_marks_unsaved_changes` | K |
| 84 | app.py:`_on_project_saved`:12281 | CR12a-1: `run.gen == gen` check removed (end with the committed line even after the tail ended) | none: the raise arm raises before the tail's end | S? — a stale `end_busy` writes one more log line only after an effective end, which no arm produces |
| 85 | app.py:`_on_project_saved`:12282 | CR12a-1: committed line → `""` always | B `test_tc_b100_51_raise_after_the_commit_keeps_the_saved_line` | K |
| 86 | app.py:`_on_project_saved` | CR12a-1 `except` removed | B `…raise_after_the_commit_keeps_the_saved_line` | K |
| 87 | app.py:`_on_project_saved` | `saved_painted = len(tail) > 1` → `False` | none (needs a raise after a multi-line tail) | S? |

## G-C2 — A2L attach, work-area pick, refusal sites, routed fixes

| # | file:function:line | Mutation | Expected killer | Exp. |
|---|---|---|---|---|
| 88 | app.py:`load_a2l_from_path`:15136 | busy check removed | W `…action_starts_refuse_while_another_session_action_runs` | K |
| 89 | app.py:`load_a2l_from_path`:15177 | `record = outside and not via_fallback` → `outside` | `test_b100_recents.py` fallback arm (`…found_through_the_fallback…`) | K |
| 90 | app.py:`load_a2l_from_path`:15194 | `if not copy:` step 2 removed | B `test_tc_b100_51_twelve_b_seam_sites…` (no: it reads the worker's post) / `test_b100_load_dialog.py::test_tc_b100_40_workarea_a2l_choice_equals_the_files_list_pick` | S? — the in-place pick's step 2 is only a bar value; no arm reads the bar of an in-place attach |
| 91 | app.py:`load_a2l_from_path`:15198 | kickoff `_busy_fail` removed | none (no arm raises in the A2L kickoff) | S? |
| 92 | app.py:`_a2l_attach_worker`:15207 | `if request.copy:` → `if True:` (in-place pick copies) | `test_b100_load_dialog.py::test_tc_b100_40_workarea_a2l_choice_equals_the_files_list_pick`; W `…every_a2l_attach_route_parses_on_a_worker` (0 pick copies) | K |
| 93 | app.py:`_a2l_attach_worker`:15229 | containment logged as an exception too | none (log only) | S? — log-only |
| 94 | app.py:`_a2l_attach_worker`:15235 | outer `_busy_fail` removed | B `…twelve_b_handler_raise_ends_the_run_first[a2l_load]` | K |
| 95 | app.py:`_on_a2l_attached` | step 3 painted after the build (no `call_after_refresh`) | P `test_tc_b100_52_a2l_tag_table_step_is_painted_before_the_build` | K |
| 96 | app.py:`_install_attached_a2l`:15249 | `req.record_recent` ignored (always record) | `test_b100_recents.py::test_tc_b100_34_source_inside_the_work_area_is_not_recorded` | K |
| 97 | app.py:`_install_attached_a2l`:15287 | deferred-install guard removed | B `test_tc_b100_50_a2l_deferred_install_raise_ends_the_run` | K |
| 98 | app.py:`_on_a2l_attach_failed`:15294 | containment arm removed (falls to `could not be read`) | W `test_tc_b100_54_a2l_worker_failure_keeps_the_session[containment]` | K |
| 99 | app.py:`_on_a2l_attach_failed`:15299 | `if request.copy: refresh_files()` → always | none (an extra refresh is invisible) | S? — equivalent |
| 100 | app.py:`_load_workarea_file`:~15545 | data arm: `sync_project=False` → `True` | W `…workarea_pick_begins_a_file_load_and_never_syncs_the_project` | K |
| 101 | app.py:`_load_workarea_file` | A2L arm `copy=False` → `copy=True` | `test_b100_load_dialog.py::test_tc_b100_40_workarea_a2l_choice_…` | K |
| 102 | app.py:`_start_load_worker`:17942 | `if sync_project and …` → `if self.current_project` | W `…workarea_pick_…never_syncs_the_project` | K |
| 103 | app.py:`_confirm_then_load`:8160 | busy check moved after `_load_would_lose` | Q `test_tc_b100_72_the_load_guard_refuses_while_busy_before_it_asks` | K |
| 104 | app.py:16 entry points + 4 continuations | any one `if self._refuse_if_busy(): return` removed | W `…patch_editor_changes_are_refused_while_busy` (16 of 16), `…patch_editor_continuations_are_refused_while_busy`, `…variant_unload_and_save_are_refused_while_busy`, `…load_requests_are_refused_during_a_project_load` | K (the dropdown `LoadGuardScreen` arm d is S?: not covered, tester note C12b-13) |
| 105 | app.py:`load_from_path`:15049 | SE5-12a-4 `except` narrowed to `OSError` | B `test_tc_b100_53_use_time_resolve_error_refuses_and_keeps_the_app[load_from_path-ValueError / -RuntimeError]` | K |
| 106 | app.py:`load_a2l_from_path`:15138 | SE5-12a-4 `except` removed | B `…use_time_resolve_error…[load_a2l_from_path-*]` | K |
| 107 | app.py:`_load_path_from_user_input`:14919 | SE5-12a-4 data-arm `except` removed | none: the classifier's own guarded look runs first; a raise here needs the path to change between two looks in one call | S? |
| 108 | app.py:`compose`:3373 | `show_eta=False` removed | B `test_tc_b100_50_progress_bar_paints_no_eta` | K |

## G-D — a2l.py progress

| # | file:function:line | Mutation | Expected killer | Exp. |
|---|---|---|---|---|
| 109 | a2l.py:`build_section_tree`:196 | `% _PROGRESS_LINES == 0` → `!= 0` (report almost every line) | P `test_tc_b100_73_case06_reports_bytes_and_parses_the_same` (report count bound) | K |
| 110 | a2l.py:`build_section_tree`:197 | `handle.buffer.tell()` → `total` (jumps to the end at once) | P `…case06_reports_bytes…` (non-decreasing values below the size before the last) | K |
| 111 | a2l.py:`build_section_tree`:230 | the final `progress(total, total)` removed | P `test_tc_b100_73_small_a2l_reports_once…` (exactly 1 report) | K |
| 112 | a2l.py:`build_section_tree`:229 | final report moved into a `finally` (also on a failed read) | P `test_tc_b100_73_a_failed_read_reports_no_final_total` | K |
| 113 | a2l.py:`build_section_tree`:194 | `total` from `path.stat()` before open | none (same value for a regular file) | S? — equivalent |
| 114 | a2l.py:`parse_a2l_file`:2681 | `progress` not forwarded | P `…case06_reports_bytes…` (0 reports) | K |
| 115 | a2l.py:`_PROGRESS_LINES` | 4096 → 1 | P `…case06_reports_bytes…` (report-count bound, ~255) | K |

Totals: 115 rows; 97 expected killed (K), 18 expected survivors (S?) (row 104 is K except its dropdown arm). The S? rows name either an equivalent mutant (22, 52, 99, 113) or an arm no test drives (the rest); E5 decides each.
