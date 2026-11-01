# Inc 12a — E4 implementation notes

Implementer notes for the 12a E4 build. Only `s19_app/tui/app.py` and the one
`styles.tcss` rule were changed. Line numbers are the post-edit line numbers of
the tree at the end of this build. Base symbols carried from Inc 9b / 10 / 11
are used as-is; the only Inc-11 rename that mattered for this design is
`_commit_project_save(prepared, payload)` (the Save commit, post-11), which the
12a graph calls "Save project phases" / `_commit_project_save` — it exists
unchanged by name, so no rename was needed. `_PreparedSave.cleaned` supplies
the `save_project` label name.

## Functions changed / added / deleted

### Added (module constants, `s19_app/tui/app.py`)
- `BusyKey` — `:341`
- `_BusyAction` (frozen dataclass) — `:353`
- `_BUSY_FRAMES` — `:360`
- `_BUSY_TICK_SECONDS` — `:361`
- `_BUSY_ACTIONS` (7 rows) — `:363`
- `_BusyRun` (dataclass) — `:401`
- `_BusyState` (dataclass) — `:413`

### Added (methods on `S19TuiApp`, `s19_app/tui/app.py`)
- `_paint_status_text` — `:19779`
- `begin_busy` — `:19800`
- `step_busy` — `:19836`
- `end_busy` — `:19886`
- `_busy_tick` — `:19930`
- `_busy_line` — `:19939`
- `_busy_begin_action` — `:19949`
- `_busy_fail` — `:19976`
- `_listed_project_name` (G-B, new) — `:13553`

### Changed (`s19_app/tui/app.py`)
- `from textual.timer import Timer` import — `:18`
- `S19TuiApp.BINDINGS` (3 descriptions: `Load`/`Load`/`Projects`) — `:2414`,
  `:2419`, `:2427`
- `S19TuiApp.__init__` (one attribute `self._busy = _BusyState()`) — `:2538`
- `set_file_status` — `:19726`
- `action_before_after_report` — `:5104`
- `_start_before_after_worker` — `:5194`
- `_trigger_generate_report` — `:5784`
- `_start_generate_report_worker` — `:5897`
- `_finish_generate_report` — `:6103`
- `on_ab_diff_panel_report_requested` — `:7181`
- `_start_diff_report_worker` — `:7262`
- `refresh_files` — `:7649`
- `_commit_project_save` — `:11099`
- `_handle_load_project` — `:13045`
- `list_projects` — `:13500`
- `_typed_load_route` — `:14366`
- `_load_path_from_user_input` — `:14514`
- `load_from_path` — `:14662`
- `load_a2l_from_path` — `:14770`
- `_load_workarea_file` — `:15045`
- `_start_load_worker` — `:17502`
- `_handle_load_error` — `:17598`

### Changed (`s19_app/tui/styles.tcss`)
- `#workspace_status_bar #status_text.-busy` rule — `:582` (inside the
  persistent status-bar block, after `#workspace_status_bar #status_text`).

### Deleted
- None. `set_progress` and `set_status` keep their bodies and signatures; their
  callers are now the seam (and the tail loop / direct result lines that were
  already there).

## G-A nodes -> code

- `BusyKey / _BusyAction / _BUSY_ACTIONS / _BUSY_FRAMES / _BUSY_TICK_SECONDS`
  -> `:341`–`:399`
- `_BusyRun / _BusyState` -> `:401`–`:424`
- `S19TuiApp.__init__` (the `_busy` attribute) -> `:2538`
- `S19TuiApp.begin_busy` -> `:19800`
- `S19TuiApp.step_busy` -> `:19836`
- `S19TuiApp.end_busy` -> `:19886`
- `S19TuiApp._busy_tick` -> `:19930`
- `S19TuiApp._busy_line` -> `:19939`
- `S19TuiApp._busy_begin_action` -> `:19949`
- `S19TuiApp._busy_fail` -> `:19976`
- `S19TuiApp._paint_status_text` -> `:19779`
- `S19TuiApp.set_file_status` -> `:19726`
- `S19TuiApp.load_from_path` -> `:14662`
- `S19TuiApp._start_load_worker` -> `:17502`
- `S19TuiApp._handle_load_error` -> `:17598`
- `S19TuiApp.load_a2l_from_path` -> `:14770`
- `S19TuiApp.action_before_after_report` -> `:5104`
- `S19TuiApp._start_before_after_worker` -> `:5194`
- `S19TuiApp._trigger_generate_report` -> `:5784`
- `S19TuiApp._start_generate_report_worker` -> `:5897`
- `S19TuiApp._finish_generate_report` -> `:6103`
- `S19TuiApp.on_ab_diff_panel_report_requested` -> `:7181`
- `S19TuiApp._start_diff_report_worker` -> `:7262`
- `S19TuiApp._handle_load_project` (the G-A half: begin before
  `build_variant_set`, steps 2/3/4, the two ends, the `try`/`finally`) ->
  `:13219` (begin), `:13247` (step 2), `:13309` (step 3), `:13327` (step 4),
  `:13262` (all-`None` end), `:13351` (success end), `:13365` (`finally`)
- `S19TuiApp._commit_project_save` (post-11) -> `:11159` (begin),
  `:11225`/`:11470`/`:11557` (steps 2/3/4), `:11923` (tail outcome end),
  `:11933` (`finally`), plus the 10 abort `end_busy` sites listed below.
- `styles.tcss` rule -> `:582`

## G-B nodes -> code

- `S19TuiApp.BINDINGS` (labels) -> `:2414`, `:2419`, `:2427`
- `S19TuiApp.list_projects` (platform gate removed) -> `:13500`
- `S19TuiApp.refresh_files` (`recent_kind` filter) -> `:7649`
- `S19TuiApp._typed_load_route` (S-j catch widened; S-k `_listed_project_name`)
  -> `:14366`
- `S19TuiApp._listed_project_name` (new) -> `:13553`
- `S19TuiApp._load_path_from_user_input` (2 arms read `_TYPED_REFUSAL_TOKENS`)
  -> `:14514`
- `S19TuiApp._handle_load_project` (the G-B listing block + the 4 shared
  refusal sentences) -> `:13045` (folder refusal `:13050`, listing
  `_listed_project_name` `:13072`, `_list_project_files` OSError `:13117`,
  `project.json` lstat OSError `:13135`, `project.json` not-regular `:13146`)
- `S19TuiApp._load_workarea_file` (pick-time lstat re-check) -> `:15045`

## Deviations

1. **`project.json` lstat not-regular arm uses the `unreadable` pair, not the
   `not a project` pair.** The sweep graph (`proto-12a-sweep.md`, node (b),
   4th bullet) says "the `project.json` lstat gate not-regular arm ... the
   `not a project` pair". The live post-9b code and the still-green test
   `tests/test_b100_load_dialog.py::test_tc_b100_64_project_json_that_is_not_a_regular_file_is_refused`
   both paint `could not be read` for that arm, and the 9b graph
   (`proto-9b-app.md` B99) says the same. Following the graph line would have
   changed a painted sentence character-for-character (against the graph's own
   "Every painted text is unchanged character for character" and interfaces
   S-k), so I read that arm from `_TYPED_REFUSAL_TOKENS["unreadable"]`
   (closest thing, text unchanged). Both arms of the gate therefore use the
   `unreadable` pair; the census (B12-37) still passes because no sentence
   paints the reason as a literal.

2. **`_handle_load_project` success order**: base painted `set_status(summary)`
   then `set_file_status(status)`. The graph step (8) lists `set_file_status`
   first, then `end_busy(summary)`. I followed the graph (store the file state
   first, then end with the summary outcome), which is what makes A12-42's
   "last end paints the project and file line" hold. This is a stated reorder
   in the graph, not a silent divergence.

3. **`_start_generate_report_worker` / `_start_diff_report_worker` /
   `_start_before_after_worker` / `_start_load_worker` docstrings** do not list
   the new keyword-only `gen` argument in their `Args` sections (the signature
   and the call sites are correct). Left as a known docstring gap rather than
   churn the doc blocks further; noted here.

4. No other deviations. `begin_busy` is called only from `_busy_begin_action`
   (verified by grep: 1 call site at `:19974`); `set_progress` is referenced
   only from `begin_busy` / `step_busy` / `end_busy`.

## Open questions

- Whether the tester's `SNAPSHOT_EXCLUSIONS` re-pin entry for `_busy` will be
  added to `tests/test_b100_session_reset.py` (the census A8 re-pin). The
  attribute is added here; the exclusion string is test-side and out of my
  allowed edits.
- The 29 SVG snapshot regenerations (labels `^l Load`, `p Projects`) are
  tester/orchestrator-side via `snapshot-regen.yml`; not performed here.
- Census re-pins A1/A2/A3/A6/A7/A9 and the G-B R-1..R-4 test edits are
  tester-side and were not applied (tests are out of my edit scope).
