# Inc 12b E4 — tester notes

Author: independent tester (E4), with one re-pin sub-agent under its brief. The oracles come from the design files only. Nobody read the implementation in the worktree (`s19_app/tui/app.py`, `a2l.py`). No source file was edited.
Base revision for RED: `71376a3` (main + Inc 11 corrected + Inc 12a), in the scratch worktree `base12b`.
Evidence: `.dev-flow/2026-10-26-batch-100/evidence/inc-12b/red-01-vs-base.txt` (one complete run, header with sha, `s19_app.__file__`, command, node list).

## Files (tests only)
- NEW `tests/support/b100_workers.py`: `settle_workers(pilot)`, ruling Q6's one wait (`wait_for_complete()` + 2 pauses).
- NEW `tests/test_b100_workers.py` (44 functions, 52 items): TC-B100-53, TC-B100-54, AT-B100-18 (4 halves), AT-B100-17 parse half, plus the routed Inc 11 arms (SE5-11-3, and O-1 as an xfail).
- NEW `tests/test_b100_a2l_progress.py` (8 functions, 9 items): TC-B100-73, TC-B100-52.
- EXTENDED `tests/test_b100_busy.py`: 6 new TC-B100-50/-51 functions (11 items) and 9 re-pinned 12a tests.
- EXTENDED `tests/test_b100_load_question.py`: TC-B100-72 (LLR-177.3a), TC-B100-66 (C12b-50), 1 re-pin. The design calls this file `test_b100_confirm.py`, which does not exist; TC-72 lives here.
- EXTENDED `tests/test_b100_save_guards.py`: TC-B100-07 worker arms (5 items) and the census C1 re-pin in place.
- EXTENDED `tests/test_b100_session_reset.py`: TC-B100-08 (P1-14), TC-B100-09 (P1-83), and the `_quit_pending` exclusion.
- EDITED `tests/test_engine_unchanged.py`: `s19_app/tui/a2l.py` is back in `_ENGINE_PATHS` (LLR-176.4b, node T1). This is a test file, so the tester did it. TC-027 now fails on the branch until the merge (declared, E1). Its full run is owed after the merge.
- RE-PINNED by the sub-agent: about 30 further test files (the list is below).

## Forced slow step: how it is built
`Hold(monkeypatch, owner, name)` blocks the first matching call made OFF the event-loop thread on a `threading.Event`. A call ON the event-loop thread (the base, where the action is synchronous) passes through and is recorded. `reached()` then fails at once with "ran on the main (event-loop) thread — the action has no worker". Every "during" arm is therefore deterministic on 12b and fails fast on the base, with no hang.
The held steps (interfaces seam X-14 / X12b-11, -12):
- Save: `app_module.place_into_workarea`. A trio project is open, so the MAC and A2L rows are placed.
- Project load: `app_module.read_project_manifest`.
- A2L attach: `app_module.parse_a2l_file`, reached through `parse_a2l_cached`.
- File load: `S19TuiApp._parse_loaded_file`.

## Requirement → test map (file `W` = test_b100_workers.py, `P` = test_b100_a2l_progress.py, `B` = test_b100_busy.py, `Q` = test_b100_load_question.py, `G` = test_b100_save_guards.py, `R` = test_b100_session_reset.py)
| Requirement | Test(s) |
|---|---|
| HLR-177 | W `…case06_project_load_keeps_the_loop_free…`, W `…project_load_reads_every_file_on_a_worker`, W `…save_refuses_before_any_worker_then_writes_on_one`, W `…every_a2l_attach_route_parses_on_a_worker`; AT: W `test_at_b100_18_worker_half_case06_project_load_by_keys` |
| HLR-177a | W `…session_writers_are_refused_during_a_save` (8 of 8), W `…action_starts_refuse_while_another_session_action_runs`; AT: W `test_at_b100_18_refusal_half_l_during_a_save_by_keys` |
| HLR-177b | W `…quit_asks_only_while_a_session_action_runs`; AT: W `test_at_b100_18_quit_half_q_during_a_save_asks_with_stay_focused` |
| HLR-177c | W `…confirmed_quit_waits_for_the_end[save, save_fails]`; AT: W `test_at_b100_18_quit_confirm_half_slow_save_as_leaves_no_partial_folder` |
| LLR-177.1 | W `…project_load_refuses_cheaply_then_returns_before_the_install`, W `…project_load_reads_every_file_on_a_worker` |
| LLR-177.1a | W `…save_refuses_before_any_worker_then_writes_on_one` |
| LLR-177.1b | W `…every_a2l_attach_route_parses_on_a_worker`, W `…case06_a2l_attach…` |
| LLR-177.1c | W `…case06_project_load…` (≥ 10 ticks), W `…case06_a2l_attach…`, W `…held_save_keeps_the_loop_free`, W `…workarea_data_pick…` |
| LLR-177.1d | W `…session_is_written_only_on_the_main_thread` (7 runs + service spies) |
| LLR-177.1e | W `…workers_read_only_their_frozen_request` (AST census + frozen dataclasses) |
| LLR-177.1f | W `…project_over_an_open_image_equals_a_cold_load`, W `…refuses_cheaply…` (digest D2), W `…case06_project_load…` (D6) |
| LLR-177.1g | W `…reset_runs_after_the_worker_and_before_the_first_install`; R `test_tc_b100_08_the_one_reset_call_sits_in_the_install_handler` |
| LLR-177.1h | W `…load_result_panel_opens_after_the_install` |
| LLR-177.1i | W `…save_rederives_on_main_before_the_worker` |
| LLR-177.1j | W `…save_adopts_only_after_the_commit` |
| LLR-177.1k | W `…workarea_data_pick_parses_on_the_file_load_worker[files_list, load_dialog]`, W `…workarea_pick_begins_a_file_load_and_never_syncs_the_project` |
| LLR-177.2 | W `test_tc_b100_54_project_worker_failure_keeps_the_session[PermissionError, ValueError]`, W `…refusals_stop_after_each_project_load_exit` |
| LLR-177.2a | W `test_tc_b100_54_save_worker_non_os_error_rolls_back_and_reports`; B `…save_raise_ends_the_action_first` (re-pinned) |
| LLR-177.2b | W `test_tc_b100_54_a2l_worker_failure_keeps_the_session[parse, copy, containment]`; B `…a2l_raise_ends_the_action_first` (re-pinned) |
| LLR-177.3 | W `…load_requests_are_refused_during_a_project_load` (6 triggers) |
| LLR-177.3a | Q `test_tc_b100_72_the_load_guard_refuses_while_busy_before_it_asks` |
| LLR-177.3b, .3c, .3d | W `…variant_unload_and_save_are_refused_while_busy` |
| LLR-177.3e | W `…patch_editor_changes_are_refused_while_busy` (16 of 16), W `…patch_editor_continuations_are_refused_while_busy` (arms a, b, c) |
| LLR-177.3f | W `…busy_line_names_the_action_and_changes_nothing`, W `…busy_line_paints_a_hostile_name_literally[[b]P, A‮B]`; Q `test_tc_b100_66_…` |
| LLR-177.3g | W `…busy_line_names_the_action_and_changes_nothing` (focus arms), and the digest/depth checks in every refusal arm |
| LLR-177.3h | W `…refusals_stop_after_each_project_load_exit`, W `…load_requests_are_refused_during_a_project_load` (after the install) |
| LLR-177.4, .4a | W `…quit_asks_only_while_a_session_action_runs` (q, ctrl+q, palette; texts; Q-c2) |
| LLR-177.4b | W `…stay_keeps_the_save_running`, W `…quit_boundaries` (arm 2) |
| LLR-177.4c | W `…confirmed_quit_waits_for_the_end[save, save_fails, project, a2l]`, W `…quit_boundaries` |
| LLR-177.4d | W `…quit_asks_only_while_a_session_action_runs` (idle q / ctrl+q / report-only), W `…idle_quit_under_the_load_question_keeps_the_key` |
| LLR-177.5 | W `…case06_project_load…`, W `…case06_a2l_attach…`; AT: W `test_at_b100_17_parse_half_case06_a2l_by_keys` |
| LLR-177.5a | W `…save_reports_each_file_placed` (3 / 4 / 1 files), W `…a_two_thousand_file_save_moves_the_bar_ten_times` |
| LLR-176.3 | P `test_tc_b100_52_a2l_tag_table_step_is_painted_before_the_build`, P `test_tc_b100_52_project_install_step_is_painted_before_the_install[case_06, case_01]` |
| LLR-176.4 | P `test_tc_b100_73_case06_reports_bytes…`, `…small_a2l_reports_once…`, `…no_report_without_a_file…`, `…a_failed_read_reports_no_final_total`, `…one_argument_callers_outside_the_app_are_unchanged` |
| LLR-176.4a | P `test_tc_b100_73_case06_reports_bytes_and_parses_the_same`, `…small_a2l…`, `…no_report_without_a_file…` |
| LLR-176.4b | P `test_tc_b100_73_a2l_py_is_listed_in_the_frozen_engine_guard` (TC-027 owed after the merge) |
| LLR-164.4 (TC-07 ext) | G `test_tc_b100_07_each_save_stage_failure_on_the_worker_rolls_back[5 stages]`, G `test_tc_b100_07_ast_census_every_post_creation_return_removes` (re-pinned) |
| LLR-165.1 (TC-08) | R `test_tc_b100_08_the_one_reset_call_sits_in_the_install_handler`; the existing `…reset_runs_once_before_the_first_install` and `…call_site_census` still hold (Q-g1) |
| LLR-165.2 (TC-09 ext) | R `test_tc_b100_09_twelve_b_adds_exactly_the_quit_flag`, plus the exclusion entry |
| LLR-174.4 (TC-72 ext) | Q `test_tc_b100_72_the_load_guard_refuses_while_busy_before_it_asks` |
| LLR-176.1l (TC-50 ext) | B `…twelve_b_kickoff_raise_ends_the_run_first[project_load, save_project]`, `…twelve_b_handler_raise_ends_the_run_first[×3]`, `…a2l_success_posts_no_failure_end`, `…a2l_deferred_install_raise_ends_the_run`, `…project_raise_ends_the_action_first` (re-pinned) |
| LLR-176.1q (TC-50 ext) | B `…twelve_b_progress_reaches_the_widgets_from_workers_on_main[×3]` |
| LLR-176.2/.2c/.2d (TC-51) | B `…twelve_b_seam_sites_sit_in_the_workers_and_handlers`, re-pinned `…every_baseline_bar_site…`, `…a2l_load_ends_once_on_success`, `…project_load_ends_once_on_success`, `…save_project_reports_its_phases_as_steps`; W `…save_reports_each_file_placed` (steps posted from the worker) |
| LLR-173.7 (TC-66 ext) | Q `test_tc_b100_66_busy_line_and_quit_question_hold_no_decision_ids`; plus the decision-id checks in W |
| LLR-178.3 | W `…load_result_panel_opens_after_the_install` |
| SE5-11-3 (routed) | W `…a_load_queued_under_the_save_dialog_is_refused_at_its_commit` |
| Inc 11 O-1 (routed) | W `…a_source_that_vanished_under_the_dialog_is_refused_by_the_save_worker`: **xfail, "design silent: Inc 11 O-1"** |

Uncovered requirements: none of the 39 in scope. Partial arms are listed under "Examples not turned into tests".

## Re-pinned tests, with reasons
By the tester (wait-only unless marked):
- `test_b100_busy.py`:
  - `::test_tc_b100_50_image_pick_file_state_waits_for_a_running_report` (R-2: the pick is now a file-load worker).
  - `::test_tc_b100_51_a2l_load_ends_once_on_a_containment_refusal`.
  - `::test_tc_b100_51_project_load_without_an_a2l_skips_its_step`.
  - `::test_tc_b100_51_project_load_ends_once_on_a_failure_after_the_begin`: wait, plus the patch target moves from the retired `_load_a2l_data_with_cache` to `app_module.parse_a2l_file`.
  - `::test_tc_b100_51_save_project_ends_once_on_a_placement_failure`.
  - `::test_tc_b100_50_project_raise_ends_the_action_first`: target `_install_project_image` (retired) → `_apply_loaded_file`, P1-34, P1-C9.
- Behaviour re-pins (12b changes the oracle; RED on base by construction):
  - `test_b100_busy.py::test_tc_b100_50_a2l_raise_ends_the_action_first`: A12-40 → C12b-37, reported and not raised.
  - `::test_tc_b100_50_save_raise_ends_the_action_first`: A12-49 → P1-64 / Q4, reported; the bar gains the placement value.
  - `::test_tc_b100_51_every_baseline_bar_site_maps_to_a_seam_event`: the a2l rows are re-keyed, X12b-14.
  - `::test_tc_b100_51_a2l_load_ends_once_on_success`: bar `[0,33,66,66,0]`, C12b-30.
  - `::test_tc_b100_51_project_load_ends_once_on_success`: bar `[0,25,50,50,75,0]`, P1-21.
  - `::test_tc_b100_51_save_project_reports_its_phases_as_steps`: bar `[0,25,50,50,75,0]`, LLR-177.5a.
- `test_b100_load_question.py::test_tc_b100_45_refusal_lines_paint_names_literally`: the retired instance patch → `app_module.parse_a2l_file`, plus the worker wait.
- `test_b100_save_guards.py::test_tc_b100_07_ast_census_every_post_creation_return_removes`: census C1, re-pinned in place to `_save_project_files` (P1-66). `_abort_save` now restores nothing (P1-77). The main-thread router and kickoff make no folder.
- `test_b100_session_reset.py`: `SNAPSHOT_EXCLUSIONS["_quit_pending"]` added (C4).
- `test_b100_save_dialog.py`: 6 tests chain a second Save, or read the commit, after a fixed pause or a poll on `project.json`, which the worker writes before the commit handler runs. Each gets `settle_workers`:
  - `::test_tc_b100_47_dialog_line_equals_the_direct_status_line`;
  - `::test_tc_b100_65_pending_line_marks_unsaved_changes`;
  - `::test_tc_b100_65_save_as_then_patch_then_direct_save_plans_fresh`;
  - `::test_tc_b100_65_dialog_save_as_leaves_no_session_for_the_next_direct_save`;
  - `::test_tc_b100_65_confirm_is_not_reused_for_another_typed_name`;
  - `::test_at_b100_16_save_dialog_open_folder_clash_empty_escape`.

By the sub-agent (its report is relayed here in full form; its transcripts are `r1b.out`, `r2.out`, `r4.out`, `r5`, `r6.out` in the scratch folder):
- `_flush` → `settle_workers` (A12b-01): the 7 listed files, plus 3 that the census missed (`test_project_gather.py`, `test_tui_report_seam.py`, `test_b100_focus.py`).
- A1, A2 `test_variant_execution.py` (2 tests).
- A3, A4 `test_b100_project_check.py` tc_b100_22 / tc_b100_23.
- A5 `_load_directly`.
- A6 `test_b100_save_image.py::_save` and `_save_session`.
- A7 `test_help_toggle_and_a2l_panel.py`.
- A8 `b97_fixtures.open_check_editor`.
- A9 `support/b100_projects.append_variant`.
- A10 `test_b100_save_image.py::test_tc_b100_17_non_os_error_after_the_emit_rolls_back_then_surfaces`: no raise; patch on `app_module`; the line without `{exc}`.
- A11 `test_tui_app.py::test_save_project_writes_under_workarea`.
- B1 `b97_fixtures.load_project`: now async, plus `flow_project` / `fx_project`; 35 call sites gained `await`.
- `support/b100_projects.load_project`: returns request → end of install (`test_b100_document.py::test_tc_b100_30_…` is no longer vacuous).
- Structural re-pins:
  - C5 `test_tui_variants.py::test_no_new_parse_loaded_file_call_sites`;
  - C6 `test_tui_app.py::test_a2l_cache_reuses_parse_for_unchanged_file`;
  - C7 `_denied`;
  - C8 `test_b100_project_homes.py` linked-A2L spy;
  - C9 `test_b100_document.py::test_tc_b100_29_…` and `test_b100_save_image.py::test_tc_b100_17_failed_manifest_write_adopts_nothing`;
  - P1-C2 (2 tests in `test_tui_app.py`);
  - P1-C3 (5 sites);
  - P1-C4 (4 tests in `test_b100_save_guards.py`);
  - P1-C5 (2 tests in `test_b100_save_image.py`);
  - P1-C7 `test_b100_reuse.py::test_tc_b100_01_…`;
  - P1-82 `test_b100_project_homes.py::test_e4_r2_r11_call_order_of_a_save_as`.
- R-4, R-5, R-7:
  - `test_b100_focus.py::test_tc_b100_12_…`;
  - `test_b100_load_dialog.py::test_tc_b100_40_*`;
  - in `test_b100_recents.py`: tc_b100_34 (2 tests) and tc_b100_39 (3 tests);
  - `test_examples_pilot_gifs.py::test_case_pilot_capture_and_gif`.
- Census misses fixed (the census did not list them):
  - `test_b100_reuse.py::test_tc_b100_03_reused_variant_is_named_not_added`;
  - `test_b99_staging.py::test_tc_b99_ux_c10_…`;
  - 3 `_timed` wrappers in `test_b100_project_check.py`, which now forward `*args, **kwargs` because the routed `go` passes `routed=True`.

Re-pins that PASS on base (wait-only): every wait-only re-pin above, and `test_tc_b100_50_project_raise_ends_the_action_first`. Re-pins that FAIL on base by construction: every structural / behaviour re-pin, each failing with the missing symbol or the old oracle (see the transcript).

## RED on base (`red-01-vs-base.txt`, one complete run, 164 node ids → 305 items, 33 min)
Result: **108 failed, 195 passed, 1 skipped, 1 xfailed**, exit 1.
- **New Inc 12b tests: 80 of 80 items RED** (+1 xfail, the O-1 arm). Every one fails on an `AssertionError` / `pytest.fail` for a behavioural reason, never a collection error. The reasons, by family:
  - "held step ran on the main (event-loop) thread — the action has no worker": every "during" arm (refusals, quit, held save/load/attach, AT refusal/quit halves, paste box, TC-72);
  - "installed / `project.json` written / adopted inside the request frame": the request-frame arms;
  - "read / parsed / written on the main thread": the thread spies (project files, A2L routes, data pick, stage failures);
  - "0 ticks before the install": the timers;
  - "no bar increase within the step": the byte / file reports;
  - `_a2l_cache_*` written off the main thread (the base file-load worker): LLR-177.1d;
  - the workers, request classes, constants or `_running_session_action` are absent: the AST / constant arms;
  - the exception leaves the request: TC-54, TC-50 deferred install;
  - `q` exits with no question: the quit arms, AT quit-confirm;
  - no progress line / elapsed sampled: AT-18 worker half, AT-17;
  - `parse_a2l_file` / `build_section_tree` take no callback: TC-73;
  - the base `_ENGINE_PATHS` lacks `a2l.py`: LLR-176.4b;
  - the step read sees the install already done: TC-52;
  - the Save committed while a file load ran: SE5-11-3.
  - Breakdown: `test_b100_workers.py` 51, `test_b100_a2l_progress.py` 9, `test_b100_busy.py` 11, `test_b100_load_question.py` 2, `test_b100_save_guards.py` 5, `test_b100_session_reset.py` 2.
- **Behaviour / structural re-pins RED by construction: 24.**
  - Tester: 6 in `test_b100_busy.py` and the C1 census.
  - Sub-agent: 17. They fail on a missing symbol (`_write_manifest_for_save`, `parse_a2l_cached`, `save_patched_image` / `verify_written_image` on `app_module`, `_save_project_files`) or the old signature (merge helpers, `_keep_previous_manifest`, the old call-site list).
- **Environment / host-load failures: 4. They are not RED evidence and not re-pin defects.**
  - `test_b97_width.py::test_at_b97_24_…`: MAX_PATH with the long basetemp.
  - Three 1 s timing bounds in `test_b100_project_check.py` (`…files_at_the_cap_all_missing_are_bounded` 1.107 s, `…sec6_5_deep_entries…` painted 1.193 s, `…sec6_5_junction_loop…` painted 1.067 s), on the base code under host load. The re-pin there only made the `_timed` wrapper forward `*args, **kwargs`. The sub-agent's lone re-run of one of them passed at 0.918 s.
- **Wait-only re-pins: all pass on base** (195 passed; it includes the tester's 6 wait-only re-pins, the `test_b100_load_question` re-pin, the 6 `test_b100_save_dialog` re-pins and the sub-agent's wait re-pins).

## Examples not turned into tests, and why
- C12b-29's recent-entry route. Driving a Recent row needs a recorded store entry and the Recent prompt's exact text; 3 of the 4 routes are covered.
- C12b-13 arm (d), the dropdown `LoadGuardScreen` (post-10). It needs a patch-file dropdown fixture; arms a, b, c are covered.
- C12b-14's rail focus arm. The rail widget has no stable id; the list and input arms are covered.
- LLR-177.2a's "1 logged traceback", and C12b-37's ERROR record count. No log-capture seam is named; the app logs to its own file.
- P1-68 / P1-79. These are Windows junction-swap / `os.replace` rollback notes, and order-of-lines parity of the base; not 12b-specific.
- P1-75 and P1-76. These are unit arms of `_write_manifest_for_save` (a private helper). They are covered behaviourally by `…save_adopts_only_after_the_commit` (failure arm) and the C9 re-pins.
- P1-44 to P1-47. These are unit arms of the explicit-input merge helpers. They are covered by the P2-over-P1 equality, the variant-id assertion and the AST census.
- D12b-07 (cost). No timing gate, as the design says.
- P1-33 and C12b-24's exact `App.exit` state. The project arm asserts `current_project` and the announcement at exit; it does not assert the panel push.

## Design ambiguities / notes
- A-1: C12b-05 holds the Save at `place_into_workarea`. An emitting save of an image-only session places nothing through that name, because the image row goes through `save_patched_image`. The tests hold it with a trio project open, so the MAC and A2L rows are placed.
- A-2: The "palette entries" (`load_file`, `load_project`, `select_variant`, `save_project`, `quit`) are dispatched with `app.run_action(<name>)`, the palette's dispatch, not by typing into the command palette.
- A-3: P1-10's "not listed" refusal: the base paints `Project not found: Z` for a missing folder. The test uses that line (the design's `'Z' is not a project` wording needs a listed-vs-existing distinction the design does not fix).
- A-4: The TC-72 file name (the design names `test_b100_confirm.py`).
- A-5: Inc 11 O-1 (a vanished source refused by the Save worker): the 12b design is silent, so it is written as an xfail.
- A-6: SE5-11-3: the window is reachable in 12b only through a direct start under the open dialog. While a session action runs, `ctrl+s` is refused and `ctrl+l` is inert under the dialog. The arm starts the file load directly with the dialog open.
- A-7 (sub-agent): P1-C7's `write_change_document` census inside `_save_project_files` is the sub-agent's inference from the proto (`:416`). No design row fixes it, so it needs confirmation.
- A-8 (sub-agent): The `_timed` tests' handler wall-time half becomes vacuous after 12b (the E2 ruling named only TC-B100-30); their press→painted half still covers the install.
- A-9: `test_b100_recents.py:3840` patches `load_a2l_from_path` with `lambda self, p:`; it holds today only because its A2L arm is refused first (at risk).
- A-10: Declared at risk, not exhaustively read: other tests that poll `project.json` (written by the worker before the commit handler) and then chain a second session action could meet the busy refusal. The refusal is loud and deterministic (E1 §5).

## Environment limits
- Windows host. The long scratch basetemp hits MAX_PATH in `test_b97_width.py::test_at_b97_24_breakpoint_and_below_the_range_by_key` (environment; it failed after the re-pinned step had completed).
- The host is loaded: one 1 s timing bound flaked under load (`test_b100_project_check.py::test_tc_b100_61_sec6_5_junction_loop_costs_one_failure`, 1.217 s) and passed when re-run alone (0.918 s).
- GREEN on 12b is `not-run`: the implementation was still being edited while E4 ran. The GREEN run is the orchestrator's (C-25).
- Not run: full modules, and the full suite (operator override). Only 2 callers per `_flush` file were sampled.
