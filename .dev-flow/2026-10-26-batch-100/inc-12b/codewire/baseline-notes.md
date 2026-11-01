# Code-Wire baseline notes — Inc 12b slice on main 8947666 (designed post-9b / post-10 / post-11 / post-12a)

## Numbers

| Item | Value |
|---|---|
| Graph | `baseline-12b.md` (this folder) |
| Base | main checkout `C:\Users\jjgh8\Github\s19_app` at `8947666`, clean apart from the untracked `prototypes/load_projects/` that was there before. sha256 prefixes: `app.py` bbf04117fbf0 (the bytes the 9b, 10, 11 and 12a baselines read), `a2l.py` 6d12c964344b. The checkout was only read; `git status` was unchanged after the probe. |
| Nodes | **58**. By group: **G-A** 13 (`_handle_load_project`, `_route_load_project`, `_reset_project_session`, `_install_project_image`, `_reopen_active_document`, `recorded_document_state`, `choose_install_set`, `_parse_loaded_file`, `_merge_mac_with_existing_primary`, `_load_mac_file`, `_load_a2l_data_with_cache`, `load_selected_file`, `_session_snapshot`); **G-B** 14 (`action_save_project`, `_handle_save_dialog`, `_commit_project_save`, `_prepare_project_save`, `_save_session_inputs`, `_decide_project_image`, `_abort_save`, `_write_and_verify_manifest`, `_rewrite_project_manifest`, `_copy_project_subfolders`, `_write_editor_document`, `ChangeService.record_save_entries`, `ChangeService.emit_and_verify`, `ChangeService.adopt_rederived`); **G-C** 24 (`load_a2l_from_path`, `_load_workarea_file`, `_load_from_item`, `update_a2l_view`, `load_from_path`, `_start_load_worker`, `_handle_load_error`, 16 of the 17 refusal entry points: `action_load_file`, `action_load_project`, `_confirm_then_load`, `action_select_variant`, `action_unload_all`, `on_loaded_artifacts_panel_unload_requested`, the 10 Patch Editor handlers / actions (the 17th, `action_save_project`, is counted in G-B); plus `check_action`); **consumed seams** 5 (`begin_busy`, `step_busy`, `end_busy`, `_busy_fail` from 12a; `ConfirmQuestionScreen.__init__` from 10); **G-D** 2 (`parse_a2l_file`, `build_section_tree`). Modules: `app.py` 52, `change_service.py` 3, `screens.py` 1, `a2l.py` 2. |
| Nodes 12b changes (per `func:`) | 41: G-A 9 (`_handle_load_project`, `_route_load_project`, `_reset_project_session` caller, `_install_project_image`, `_reopen_active_document`, `_parse_loaded_file`, `_load_a2l_data_with_cache`, plus `load_selected_file` (loses its product callers) and `_load_mac_file` (its A2L fallback, through the request)); G-B 9 (`action_save_project` (busy check), `_handle_save_dialog`'s commit call, `_commit_project_save`, `_abort_save`, `_write_and_verify_manifest`, `_rewrite_project_manifest`, `_copy_project_subfolders`, `_write_editor_document`, `record_save_entries` / `adopt_rederived` call site); G-C 21 (`load_a2l_from_path`, `_load_workarea_file`, `load_from_path`, `_start_load_worker`, `_handle_load_error` (their ends, S-c), the 16 refusal entry points other than `action_save_project`); G-D 2. The rest are context. |
| Post-9b / 10 / 11 / 12a nodes | In code, body from the graphs (`func:` says which part is post-*): `_handle_load_project` (9b, 10, 12a), `_route_load_project` (10), `_reset_project_session` (10), `action_save_project` (11), `_handle_save_dialog` (11), `load_a2l_from_path` (9b, 12a), `_load_from_item` (9b), `load_from_path` (9b, 12a), `_start_load_worker` (12a), `_handle_load_error` (12a), `action_load_file` / `action_load_project` (9b), `on_patch_editor_panel_change_file_selected` (10), `check_action` (9b, 10, 11). Their `in:` / `out:` give the **base** signature (the extractor compares them with the code); a post-* signature is stated in `func:`. Not in code, not marked (10 nodes): `_commit_project_save`, `_prepare_project_save`, `_save_session_inputs`, `_load_workarea_file`, `_confirm_then_load`, `begin_busy`, `step_busy`, `end_busy`, `_busy_fail`, `ConfirmQuestionScreen.__init__`. |
| NEW nodes with no code | The three workers, their install / failure handlers, the request and result values, `_refuse_if_busy`, the `action_quit` override, the quit-answer handler, the shared end tail (E1 A2–A4, A8, B2, B3, C2, C3, C5, C7–C9, D1–D3). A baseline graphs only code that exists, so they are seams in `interfaces-12b-proposed.md`. |
| Example lines | 87, 1 to 4 per node. Each names a probe step (p12b U1–U4, E1 P12b-1 … P12b-7), an existing test, a code read, or a line of the 9b / 10 / 11 / 12a graphs. All hold on the base unless they say post-9b / post-10 / post-11 / post-12a. Where 12b turns a line RED, the line says so. |
| Caller lines | one `> callers (extractor): …` note per node, generated from `extract-baseline/extract.json` by `../work/callers.py` (`../work/callers.out.txt`, the 12a script) and converted to base line numbers. "direct" = inside the caller's own `def`; "through an unmarked helper" = lifted; "unmarked site" = a call whose enclosing function is not a node. Callables passed as values (`push_screen(…, self._route_load_project)`, `call_from_thread(self._handle_load_error, …)`) are not seen. |
| Extractor | `codewire_extract.py` (Code-Wire v3.1 core), s19env Python 3.11, on a throwaway marked copy. First run: 34 findings (28 drift, 6 info) — the graph had post-* signatures (`gen`, `name: str`, `-> None`), a bare `out:` with no name, a tuple `out:` written with brackets, and loose container types. I set `in:` / `out:` to the base signatures, moved the post-* signatures into `func:`, and re-ran. **Final: exit 0, 48 marks, 48 graph nodes, 42 real calls, 0 findings, 0 ambiguous resolutions, 0 parse failures.** The graph given to the extractor (`../work/graph-extract.md`) is `baseline-12b.md` minus the 10 nodes with no code. |
| Marks | 48 marks written by `codewire_marks.py` into `../work/marked`, a copy of `s19_app/` committed into a throwaway `git init` repo (`core.autocrlf false`) — `48 marks written, 0 nodes without code`. Removed after the run. The checkout has 0 marks. |
| Lint | not run (brief: no lint, coherence or STE gates). |
| Report | `extract-baseline/diff-report.md`, `extract-baseline/extract.json` |
| Probe | `probe-p12b.py` (this folder); output `probe-p12b.out.txt`; stderr `probe-p12b.err.txt` (empty for the final U4 run). It imports the checkout read-only (`python -I`, the checkout first on `sys.path`, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONUTF8=1`, `LOCALAPPDATA` in `../work/localappdata`) and writes only under `../work/p12b` (removed after). The import line prints `C:\Users\jjgh8\Github\s19_app\s19_app\__init__.py`. One targeted probe, no test module run. |

### Probe p12b output (executed, base; long paths shortened)

```text
== U3 case_01 size 1444 lines 53 text-mode bytes 1391 (short by 53) buffer.tell distinct 1 first 1444 last 1444 non-decreasing True
== U3 case_01 loop plain 0.000 s, with tell per line 0.000 s
== U3 case_06 size 37742888 lines 1039926 text-mode bytes 36702962 (short by 1039926) buffer.tell distinct 4608 first 8192 last 37742888 non-decreasing True
== U3 case_06 loop plain 0.073 s, with tell per line 0.659 s
== U2 no image open: _parse_loaded_file(P2/firmware.mac) -> file_type=mac path=firmware.mac mac=firmware.mac
== U2 P1 image open: _parse_loaded_file(P2/firmware.mac) -> file_type=s19 path=p1img.s19 parent=u2 mac=firmware.mac
== U2 P1 image open: _parse_loaded_file(P2/firmware.s19) -> mac carried=None
== U1 case_01 cold P2 digest ('P2\\firmware.s19', 'f254f33fe5405d40', 'P2', 'P2\\firmware.a2l', 'P2\\firmware.mac', 0)
== U1 case_01 P1 before: ('<work>\\p12b\\u1-case_01-over\\p1img.s19', 'f254f33fe5405d40', None, None, None, 0)
== U1 case_01 P2-over-P1 digest ('P2\\firmware.s19', 'f254f33fe5405d40', 'P2', 'P2\\firmware.a2l', 'P2\\firmware.mac', 0) equal_to_cold=True snapshot names differing ['_image_generation', 'log_lines']
== U1 case_06 cold P6 digest ('P6\\firmware.s19', 'f917cd2dca22da9a', 'P6', 'P6\\firmware.a2l', 'P6\\firmware.mac', 0) wall 7.34 s
(first run stopped at U4 with a StylesheetError: the recording subclass lived outside the package, so CSS_PATH resolved next to the probe; fixed with an absolute CSS_PATH and U4 re-run alone:)
== U4 project load assigns [49 names: '_a2l_cache_data', '_a2l_cache_key', … '_change_service', '_declared_regions', … '_last_load_announcement', … '_pending_variant_id', '_report_filter_path', … '_variant_set', '_variant_set_value', 'current_a2l_data', 'current_a2l_path', 'current_file', 'current_project', 'current_project_dir', 'cursor_position']
== U4 save assigns ['_last_manifest_verify_result', '_report_filter_path', '_variant_set', '_variant_set_value', 'current_project', 'current_project_dir']
== U4 A2L attach assigns ['_a2l_cache_data', '_a2l_cache_key', '_a2l_enriched_key', '_a2l_enriched_tags', '_a2l_filtered_tags', '_a2l_row_key_to_tag', '_a2l_summary_lines', '_a2l_summary_start', '_a2l_window_start', '_mac_row_key_to_address', '_validation_issues', '_validation_report', 'a2l_tags_filter_text', 'current_a2l_data', 'current_a2l_path']
```

The **session digest** of U1 is E1's definition: (`current_file.path` relative to the work area, SHA-256 of the installed image — here the first 16 hex digits of `sha256(addr as 8 bytes big-endian + byte, for each (addr, byte) in sorted mem_map)` — `current_project`, `current_a2l_path`, the MAC path, the change document's entry count). A tester that reuses the digest must use the same image hash.

Notes on the probe:
- U1 / U2 / U4 run the shipped handlers inside `run_test(size=(160, 50))`, called directly (the E1 probe style), so the base's synchronous load and save complete inside the call.
- U4's Save is a copy-only save (no patch), so it shows the app attributes only; the change-service state changes of an emitting save (`record_save_entries`, `mark_saved`, `adopt_rederived`) are not app attributes and are read from the code (baseline nodes).
- U3 runs `a2l.py`'s read pattern on the two fixtures, outside the app; it does not call `build_section_tree`.

### Controls owed at E2 by the E1, now executed

| E1 item | Result on base |
|---|---|
| LLR-177.1f's base-digest arm ("recorded at the E2 baseline", `planned`) | **executed (U1)**: case_01 cold `P2` → `('P2\firmware.s19', 'f254f33fe5405d40', 'P2', 'P2\firmware.a2l', 'P2\firmware.mac', 0)`; P2-over-P1 equal; case_06 cold `P6` → `('P6\firmware.s19', 'f917cd2dca22da9a', 'P6', 'P6\firmware.a2l', 'P6\firmware.mac', 0)`. The arm can now be `executed`. |
| LLR-177.1f's negative control (a worker that parses P2's MAC against the live `current_file`) | **executed as a base behaviour (U2)**: with P1's image open, `_parse_loaded_file(P2/firmware.mac)` returns P1's image (`p1img.s19`, `file_type s19`) with P2's MAC — exactly the merge the mutant would install. |
| LLR-177.1d's code-read control | **executed (U4)**: the lists of app attributes each base action assigns; a worker that ran those bodies would write every listed name off the main thread. |
| LLR-176.4's "at most once per chunk" (seam S-f) | **executed (U3)**: one 8 KiB refill = one distinct `buffer.tell()` value → 4 608 reports for case_06, 1 for case_01; text-mode line lengths under-count CRLF bytes by 1 per line, so only the buffer position reaches `last = size`. A per-line `tell()` costs 0.59 s on case_06 (12 % of the 5.01 s parse). See interfaces Q-f1. |

## Selectors

No `styles.tcss` rule is in the slice. 12b paints into existing widgets: the busy line goes to the status log (`set_status`, `#log_line_*`), the indicator's `#status_text` / `#progress_bar` belong to 12a, and the quit question reuses Inc 10's `ConfirmQuestionScreen` ids (`#confirm_box`, `#confirm_title`, `#confirm_body`, `#confirm_buttons`, `#confirm_yes`, `#confirm_no`) unchanged.

## Census (by grep and by reading; **not executed** — host busy, per the brief)

### Method

- **Direct call sites** of `_handle_load_project`, `_route_load_project`, `_handle_save_dialog`, `load_a2l_from_path` in `tests/`: E1's pass-2 AST script (`../work/census2.py`) re-read, then a pass-4 script (`../work/census4.py`, output `../work/census4.out.txt`) that **counts each call site once**, classified by its innermost enclosing function, and also scans `tests/support/`. Both only parse the test sources; no test runs. Classes as E1: W = a polling or flushing wait follows (within 6 lines), P = only `pilot.pause()`-style awaits follow, N = no await follows in a running app, U = a sync test with no running app, H = a sync helper.
- **Internal seams**: `grep -rnF` over `tests/` for every function or attribute 12b moves or changes (`_load_from_item(`, `_install_project_image`, `_reopen_active_document`, `_reset_project_session`, `_parse_loaded_file`, `_load_a2l_data_with_cache`, `_abort_save`, `_write_and_verify_manifest`, `_last_manifest_verify_result`, `_rewrite_project_manifest`, `parse_a2l_file`, `build_section_tree`, `_ENGINE_PATHS`, `action_quit`, `press("q")`, `"ctrl+q"`, `_a2l_cache_key`, the merge helpers, `_start_load_worker`, `update_a2l_view`, `record_save_entries`, `adopt_rederived`, `_decide_project_image`, `emit_and_verify`), then each hit read.
- Every row below is **by grep, not executed**. "Breaks" means: by reading the assertion against the E1 design and the proposed interfaces.

### Correction to E1's count (by reading)

E1 (`work/census.out.txt`, `census2.out.txt`): "29 test files, 340 direct call sites (181 / 6 / 101 / 52) … 11 in sync tests with no running app". Pass 2 walks every `def` and counts every call under it, so a call inside a nested `async def _scenario` / `_drive` is counted for the nested function **and** for the enclosing test. Counted once (pass 4, with `tests/support/`):

| Function | Distinct sites | Files | W | P | N | U | H |
|---|---|---|---|---|---|---|---|
| `_handle_load_project` | 97 | 21 | 85 | 9 | 1 | 0 | 2 |
| `_route_load_project` | 3 | 1 | 3 | 0 | 0 | 0 | 0 |
| `_handle_save_dialog` | 56 | 11 | 48 | 4 | 1 | 1 | 2 |
| `load_a2l_from_path` | 28 | 10 | 23 | 3 | 2 | 0 | 0 |
| **all** | **184** | **26** | 159 | 16 | 4 | 1 | 4 |

- 56 Save sites equals Inc 11's independent count ("56 direct call lines"), a cross-check.
- Of E1's 11 "U" sites, 10 are nested `async` scenarios inside sync tests (already counted in their scenario's class) and 1 is a real no-app test, `tests/test_tui_app.py::test_save_project_writes_under_workarea` (:85).

### A. Direct call sites at risk (P, N, U), by reading each

| # | Site (file:line, test) | Class | After 12b | Disposition |
|---|---|---|---|---|
| A1 | `tests/test_variant_execution.py:194` `test_load_project_honors_manifest_active_variant` | P | one pause after a worker load → the install may not have run → its active-variant assertion reads the old state | **breaks**: re-pin to the shared wait helper |
| A2 | `tests/test_variant_execution.py:231` `test_load_project_unknown_active_variant_falls_back` | P | same | **breaks** |
| A3 | `tests/test_b100_project_check.py:213` `test_tc_b100_22_seam_scope_is_top_level_data_and_a2l` | P | one pause, then `_write_and_verify_manifest(project_dir) is True`; with `_variant_set` not yet installed the writer returns `True` without writing (`variant_set is None`), so the file assertions after it read no new manifest; B4 also changes the return | **breaks** (wait + B4 re-pin) |
| A4 | `tests/test_b100_project_check.py:264` `test_tc_b100_23_digest_changed_between_write_and_verify` | P | same wait, and it reads `app._last_manifest_verify_result` right after the writer (B4 removes that assignment from the writer) | **breaks** (wait + B4 re-pin) |
| A5 | `tests/test_b100_project_check.py:111` helper `_load_directly` (12 pauses), used by 8 tests: `test_tc_b100_25_load_reports_the_case`, `test_tc_b100_26_active_deleted_the_other_opens`, `test_tc_b100_26_every_image_deleted_the_mac_opens`, `test_tc_b100_61_case_6_is_only_not_readable`, `test_tc_b100_61_checksum_errors_only_keep_the_image_open`, `test_tc_b100_61_empty_image_is_not_readable_and_load_moves_on`, `test_tc_b100_61_unreadable_a2l_is_its_own_problem_and_the_image_opens`, `test_tc_b100_61_case_7_is_only_manifest_damaged` | P | 12 fixed pauses; a case_01-size project probably installs inside them, but nothing guarantees it | **at risk**: one helper edit (`wait_for_complete()` + 2 pauses) |
| A6 | `tests/test_b100_save_image.py:223` helper `_save` (1 pause), used by 5 tests: `test_tc_b100_15_patched_hex_is_emitted`, `test_tc_b100_15_mac_and_a2l_stay_byte_copies`, `test_tc_b100_58_save_project_records_the_saved_state`, `test_tc_b100_59_fresh_folder`, `test_tc_b100_59_files_row` | P | one pause after a worker save | **breaks**: one helper edit |
| A7 | `tests/test_help_toggle_and_a2l_panel.py:90` `test_a2l_load_refreshes_loaded_panel_without_screen_switch` | P | one pause, then reads the Loaded panel's A2L slot | **breaks** |
| A8 | `tests/b97_fixtures.py:406` helper `open_check_editor` (`settle` = 4 pauses, then asserts the A2L tags), used by `test_b97_check_editor.py` (1 drive), `test_b97_chips_help.py::test_tc_b97_33_check_glyphs_closed_and_in_the_legend`, `::test_tc_b97_58_check_editor_region_states`, `::test_at_b97_23_each_failed_region_says_so_in_one_line`, `test_b97_flow_execution.py::test_tc_b97_52_waiting_colour_only_on_waiting_human_elements`, `test_b97_key_bar.py::test_tc_b97_72_owner_click_runs_on_its_widget_not_the_focus`, `test_b97_width.py` (`_at_session`) | P | 4 fixed pauses | **at risk**: one helper edit |
| A9 | `tests/support/b100_projects.py:383` helper `append_variant` (project load, 1 pause, then `load_from_path`), used by `test_b100_active_variant.py::test_tc_b100_71_variant_append_carries_derived_from`, `test_b100_document.py::test_tc_b100_28_variant_append_keeps_the_key`, `test_b100_project_check.py::test_tc_b100_26_active_deleted_the_other_opens`, `test_b100_recents.py::test_tc_b100_34_source_inside_the_work_area_is_not_recorded` | P | `load_from_path` starts while the project worker may still run. With the busy check only at the 17 E1 entry points (C6), this direct call is **not** refused: two session writers race (the file worker's install can land before the project install, and `_sync_loaded_file_to_project` then appends to whichever project is current). With a check at the action starts (interfaces Q-a1), it is refused loudly | **breaks** either way; re-pin the helper to wait |
| A10 | `tests/test_b100_save_image.py:818` `test_tc_b100_17_non_os_error_after_the_emit_rolls_back_then_surfaces` | N | `pytest.raises` around `_handle_save_dialog`; after 12b nothing raises (ruling Q4) | **breaks**: re-pin to the `could not save` line + logged traceback (E1 lists it) |
| A11 | `tests/test_tui_app.py:85` `test_save_project_writes_under_workarea` | U | no running app → no worker can start. Already re-pinned into `run_test` by 12a P-5; after 12b it must also wait | **breaks** (E1 lists it) |
| A12 | `tests/test_b100_active_variant.py:687` `test_tc_b100_20_writers_on_a_31_folder_manifest_finish_under_one_second` | N (heuristic) | the call is followed by `_wait_for(…, attempts=4000)` over a multi-line `if` chain; it measures trigger → outcome with polling | **holds** (misclassified by the 6-line window) |
| A13 | `tests/support/b100_projects.py:293` / `:308` (`save_case01_project`) | N / P (heuristic) | both poll (`for _ in range(400)` with an awaited pause) | **holds** |
| A14 | refusal sites: `test_b100_project_homes.py:1343`, `:2405`, `:2407`; `test_b100_recents.py:2689` | P / N | the call is a refusal (outside, permission error, unreadable folder); refusals stay synchronous (LLR-177.1, .1a) | **holds** |
| A15 | the 159 W sites | W | each polls or calls `wait_for_complete()` / `_flush`; a worker's `call_from_thread` blocks until its main-thread callback returns, so the install is done when the worker is | **holds**, except where a poll's condition turns true before the install ends (see the interfaces' S-g rule: the install sets `current_project` and composes the announcement in one main-thread callback) |

### B. The four sync helpers (H), by reading

| # | Helper | Callers | After 12b | Disposition |
|---|---|---|---|---|
| B1 | `tests/b97_fixtures.py:168` `load_project` (`_handle_load_project`, then asserts `current_project == name` at once) | 29 test functions (`test_b100_document.py` 4, `test_b100_project_homes.py` 3, `test_b100_recents.py` 2, `test_b100_save_guards.py` 1, `test_b100_save_image.py` 2, `test_b97_chips_help.py` 15, `test_b97_flow_execution.py` 1, `test_b99_staging.py` 1; names in `../work/census3.out.txt`) | the assertion runs before the install | **breaks**: make it `async` and wait (E1 Q6) |
| B2 | `tests/test_b100_session_reset.py:645` `_load_p1` | 3: `test_tc_b100_11_unload_all_clears_the_parsed_a2l`, `test_tc_b100_11_unload_a2l_alone_clears_the_parsed_a2l`, `test_tc_b100_11_bare_s19_reload_after_unload_shows_no_a2l_tags` | the next statement runs before the install | **breaks**: one helper edit |
| B3 | `tests/test_project_gather.py:147` `_save_project` | 13 (`test_b100_active_variant.py` 5 `test_tc_b100_19/71_…`, `test_project_gather.py` 8 `test_tc699/700/701/702_…`, `test_scoped_home_template_save_with_project_lands_in_project`) | returns before the save commits | **breaks**: one helper edit |
| B4 | `tests/test_tui_report_seam.py:632` `_save_loaded_project` | 5: `test_save_persists_declared_regions`, `test_typed_but_not_generated_not_saved`, `test_save_without_regions_byte_identical`, `test_save_threads_declared_regions_to_writer`, `test_load_prefills_declared_regions` | same | **breaks**: one helper edit |

### C. Internal seams the slice moves (by grep, each hit read)

| # | Test | Pins | After 12b | Disposition |
|---|---|---|---|---|
| C1 | `tests/test_b100_save_guards.py::test_tc_b100_07_ast_census_every_post_creation_return_removes` (:801; the `_abort_save` asserts at :873–:891) | `_abort_save` contains an `Attribute` `_variant_set` ("must restore the pre-save app state"); every post-`mkdir` return follows `_abort_save`; 1 `except OSError` after the `mkdir` | E1 B5 removes the session-restore half → the `_variant_set` assert fails. The `mkdir` / return census moves to the Save worker body | **breaks**: re-pin both halves (E1 lists only the worker extension, not the `_abort_save` assert) |
| C2 | `tests/test_b100_session_reset.py::test_tc_b100_08_reset_runs_once_before_the_first_install` (:197) | events `["reset", "install", "install"] * 2` (P1 = S19 + MAC: two `_apply_loaded_file` installs per load, both after the reset) | holds if the install handler installs the image and then the MAC as two `_apply_loaded_file` calls; **breaks** if the worker returns one merged `LoadedFile` installed once | **depends on G-A** (interfaces Q-g1) |
| C3 | `tests/test_b100_session_reset.py::test_tc_b100_08_call_site_census` (:271) | exactly 1 `_reset_project_session` call site, in `tui/app.py` (file-level) | holds (1 site, in the install handler) | E1 C.1 re-pins the text; the assertion is file-level and holds |
| C4 | `tests/test_b100_session_reset.py::test_tc_b100_09_domain_matches_the_live_source_census` | every `self.<name> =` classified | each new attribute (the quit flag) is unclassified until listed | **breaks** until classified (E1 C.2) |
| C5 | `tests/test_tui_variants.py::test_no_new_parse_loaded_file_call_sites` (:196) | `_parse_loaded_file` call sites == `["_install_project_image", "_start_load_worker", "load_selected_file"]` | E1 A6 / A8: the project parse moves into the worker or a pure sibling → the list changes | **breaks**: re-pin the expected sites (not in E1's list) |
| C6 | `tests/test_tui_app.py::test_a2l_cache_reuses_parse_for_unchanged_file` (:398) | `_load_a2l_data_with_cache` twice → `parse_a2l_file` (monkeypatched `fake_parse(path)`, one parameter) called once | A9 splits the parse from the cache write; if the app always passes `progress=` the fake raises `TypeError` | **breaks** unless the cache path calls `parse_a2l_file(path)` when no callback is given (interfaces Q-f2) |
| C7 | `tests/test_b100_project_check.py::test_tc_b100_61_unreadable_a2l_is_its_own_problem_and_the_image_opens` (:678, `_denied(path)` at :704) | the A2L read raising `PermissionError` → `("not readable", "firmware.a2l")` | if `progress=` is always passed, `_denied` raises `TypeError` instead, which the project load also turns into `not readable` → **passes for the wrong reason** | vacuous-pass risk; Q-f2 |
| C8 | `tests/test_b100_project_homes.py::test_e4_llr_171_2g_linked_a2l_beside_a_mac_is_never_parsed` (:1945, spies at :1927–:1941) | 0 `_load_a2l_data_with_cache` and 0 `parse_a2l_file` calls for a linked A2L | the spies are tolerant (`*args, **kwargs`). If the worker no longer calls `_load_a2l_data_with_cache`, the cache spy sees 0 for every case → its half passes vacuously; the `parse_a2l_file` spy stays meaningful **only if** the worker calls the module attribute `app_module.parse_a2l_file` | re-point the spy at the new parse seam (vacuous-pass risk) |
| C9 | `tests/test_b100_project_check.py` :215 (`assert app._write_and_verify_manifest(project_dir) is True`), :264–:267 (reads `_last_manifest_verify_result`), :1421 (`ok … is False`); `tests/test_tui_report_seam.py::test_write_and_verify_manifest_accepts_declared_regions_default` (:788, calls at :811–:860); monkeypatches `tests/test_b100_document.py:815` (`_fail_after_landing(self, project_dir, *args, **kwargs) -> bool`) and `tests/test_b100_save_image.py:836` (`lambda self, *a, **k: False`, the F4 test) | the writer's `bool` return, its keyword set, and its attribute side effect | E1 B4 (return the verify result, take the variant set): every pin of the return or the attribute changes | **breaks** (not in E1's list); see Q-b1 for a shape that keeps them |
| C10 | `tests/test_b100_save_image.py::test_tc_b100_17_failed_manifest_write_adopts_nothing` (:836) | 0 adopts after a failed manifest write | holds in intent; must wait for the worker (E1 lists it) | re-pin (wait) |
| C11 | `tests/test_b100_document.py::test_tc_b100_30_hostile_document_is_one_not_readable_under_one_second` (:1182; bound at :1203 on `projects.load_project`'s returned wall time) | `_handle_load_project` wall time < 1 s | the handler returns at once after 12b → the bound passes vacuously | **vacuous**: re-pin to request → end of install (E1 lists it) |
| C12 | `tests/test_engine_unchanged.py` (`_ENGINE_PATHS`, the `a2l.py` entry commented out since batch-95) | the frozen-engine list | T1 uncomments it; TC-027 then compares `a2l.py` against `main`, where it differs until the merge | owed after the merge (E1 LLR-176.4b) |
| C13 | `tests/test_b97_key_bar.py:1238`–`:1250` (monkeypatches `S19TuiApp.action_quit`) | `q` in an input types, outside calls `action_quit` once | `setattr` replaces an override the same way | **holds** |
| C14 | `tests/test_examples_pilot_gifs.py:231` (`await pilot.press("q")`, "clean shutdown") | idle quit exits | idle → exits at once (LLR-177.4d), provided no session action is still running at that frame | **holds** (at risk only if a frame is taken while a worker still runs) |
| C15 | `tests/test_b100_save_image.py:2247` (`_spy_abort_8b`), `tests/test_b100_reuse.py:531` (`("s19_app/tui/app.py", "_abort_save")` in an allow-list), `tests/test_b99_staging.py:2074` (`_abort_save` in the unlink allow-list) | `_abort_save` by name | hold while the rollback stays in `_abort_save` (called on the worker) | **holds** if the name is kept |
| C16 | `tests/test_b100_project_homes.py:918`, `tests/test_b100_recents.py:415` (pass-through wrappers of `_reset_project_session`) | the call still happens | hold | **holds** |
| C17 | 0 tests reference `_reopen_active_document`, `_rewrite_project_manifest`, `record_save_entries`, `adopt_rederived`, `"ctrl+q"`, `exit_on_error`, `WorkerFailed` (grep) | — | — | none |

### Count

- **Breaks (by reading): about 75 test functions** (a few sit under two rows): A1–A4, A7, A10, A11 (7 tests), A6 (5 behind `_save`), A9 (4 behind `append_variant`), B1–B4 (50 behind the 4 sync helpers), C1, C4, C5, C6 (4), C9 (3 more: `test_b100_project_check.py::test_tc_b100_62_swap_toast_and_status_paint_no_exception_class`, `test_tui_report_seam.py::test_write_and_verify_manifest_accepts_declared_regions_default`, `test_b100_document.py::test_tc_b100_29_failure_after_the_write_removes_the_document`; the 4th and 5th C9 pins are A3 / A4 and the F4 test), C10, C11 (2).
- **At risk (by reading): about 18** — A5 (8 behind `_load_directly`), A8 (7 drives behind `open_check_editor`), C2 (only under Q-g1 option 2), C7 and C8 (vacuous-pass risks). **Owed after the merge:** C12 (TC-027).
- **Test files that need an edit** (union): `test_variant_execution.py`, `test_b100_project_check.py`, `test_b100_save_image.py`, `test_help_toggle_and_a2l_panel.py`, `b97_fixtures.py`, `support/b100_projects.py`, `test_tui_app.py`, `test_b100_session_reset.py`, `test_project_gather.py`, `test_tui_report_seam.py`, `test_b100_save_guards.py`, `test_tui_variants.py`, `test_b100_document.py`, `test_b100_project_homes.py` (C8), `test_engine_unchanged.py` = **15 files**, inside E1's estimate of 15–25. 0 SVG snapshots.

## Surprises

1. **E1's census double-counts.** 340 sites / 29 files / "11 no-app tests" become 184 distinct sites / 26 files / 1 no-app test (table above). Q6's ruling (one wait helper, a handful of helper edits) is unaffected; the numbers in E1 §5 and the ledger's D.4 row should be corrected.
2. **E1 names two timing tests; only one bounds the handler's wall time.** `test_b100_active_variant.py::test_tc_b100_20_writers_on_a_31_folder_manifest_finish_under_one_second` measures trigger → outcome with polling (`_wait_for`, 4 000 attempts) and stays meaningful after 12b. Only `test_b100_document.py::test_tc_b100_30_hostile_document_is_one_not_readable_under_one_second` (through `support.load_project`'s returned wall time) becomes vacuous.
3. **The base commit writes session attributes inside the rollback `try`**, and the manifest writer reads one of them back: `_report_filter_path = None` (`:10102`), `_variant_set = build_variant_set(…)` and `current_file.variant_id` (`:10109`–`:10124`), then `_write_and_verify_manifest` reads `self._variant_set` (`:11255`). On a worker the variant set must be a local that the writer takes as an argument; E1 B4 names only the verify-result half.
4. **The Patch Editor dispatcher has 11 action arms, not 9 + 2.** Besides the 12 + 2 of LLR-177.3e's threshold, `save_doc` and `execute_scope` (`PATCH_ACTIONS_V2`) are refused by the same top-of-handler guard (ruling Q3), and the threshold does not list them.
5. **E1 observation on `support/b100_projects.py:383` assumes the direct `load_from_path` is refused**; with the busy check only at the 17 entry points of E1 C6 it is not (A9). Interfaces Q-a1.
6. **`ChangeService.emit_and_verify` is not state-free on a worker.** It assigns no service attribute (E1 is right there), but it reads `self.last_summary` (when `summary` is `None`), `self.last_save_applied` / `last_save_not_applied` for its message, and writes `stamped.verify_result` on the summary object the main thread later adopts (`change_service.py:2445`, `:2471`–`:2477`). Called as `self._change_service.emit_and_verify(…)` from a worker, LLR-177.1e's census names `self._change_service`. Interfaces Q-b2.
7. **The parser's natural progress unit is too fine.** "At most once per chunk" = once per 8 KiB refill = 4 608 blocking `call_from_thread` round trips for case_06; reading the position after every line adds 12 % to the parse (U3). Interfaces Q-f1.
8. **One-parameter fakes of `parse_a2l_file`** (C6, C7) break or pass for the wrong reason if the app always passes `progress=`.
9. **`ctrl+q` reaches `action_quit` under every modal**, the quit question included (`quit` is not in `_LOAD_DIALOG_INERT_ACTIONS`; Textual binds `ctrl+q` with `priority=True`). A second `ctrl+q` while the quit question is open would stack a second question unless `action_quit` checks for it. Interfaces Q-c2.
10. **Textual's `App.action_quit` is `async`** (`textual/app.py:4460`); the override may be sync or async (Textual's `run_action` awaits either). Recorded for the prototype; no question.

## Callers outside the slice that matter for 12b

- `_handle_load_project`: 1 product caller (`_route_load_project`, `:7478`); 97 direct test sites.
- `load_a2l_from_path`: `_load_path_from_user_input` (`:12939`), `_load_from_item` (`:13333`; post-9b `_load_workarea_file`); also `on_mount`'s start-up `load_path` through `_load_path_from_user_input`.
- `_load_a2l_data_with_cache`: `_handle_load_project` (`:11858`), `load_a2l_from_path` (`:13145`), `_load_mac_file` (`:14217`), `_parse_loaded_file` (`:15151`, `:15170`; reached from the file-load worker). A9 touches every one.
- `_write_and_verify_manifest`: the Save commit (`:10323`) and `_rewrite_project_manifest` (`:12495`), which serves the save-back (`:4197`) and the variant-append / MAC / A2L syncs (`:12680`, `:12724`, `:12754`). B4 must keep those main-thread callers working.
- `parse_a2l_file` outside `app.py`: `change_service.py:3225`, `flow_execution_service.py:358`, `:461`, `variant_execution_service.py:2662` — all call it with one argument; an optional `progress=None` keeps them unchanged.
- `check_action`: `window_help.py:1134`, `:1145` (the key bar).
- Calls the extractor cannot see: the dismiss callbacks (`push_screen(…, self._route_load_project)` / `_handle_save_dialog`), every `call_from_thread(callable, …)`, `call_after_refresh(go)` in `_confirm_then_load`, and Textual's dispatch of `action_*` and `on_*`.

## Wall time

About 75 minutes by the shell clock: reading the E1 and the four earlier designs (most of it), one probe (about 1 minute of run time), the extractor (two runs), the census scripts (static, seconds each), and writing.
</content>
</invoke>
<invoke name="Bash">
<parameter name="command">cd C:/Users/jjgh8/Github/s19_app && sed -n 11253,11256p s19_app/tui/app.py; sed -n 2470,2478p s19_app/tui/services/change_service.py