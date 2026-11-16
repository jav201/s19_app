# Inc 9b — E1 slice: the files and functions to add or change, counted and mapped

Base `09001bbc`. Line numbers "as of `09001bbc`" unless marked *merged*. Nodes and examples: `codewire/graph-inc9b.md`. Rulings: `E1-rulings.md`.

**P9b (E4 prep) re-check on the merged base `e4485817`** (= `3daea03d` + Inc 8b `103a72df`): E4 starts from this merge (§7). Inc 8b changed no slice file except `bench_sheet.py` (`_bench_geometry`, 3 lines fewer: later lines shift by −3), and none of `app/patch.py`, `panel.py`, `definition_bench_view.py`, `layout.py`, `styles.tcss`. The names Inc 8b changed that touch a 9b node, the layered extraction and the line map: graph §"E4-prep re-check on the merged base". Pilot results and the three design fixes they force (F-9b-4 … F-9b-6): `E4-pilots.md`.

## 1. Source files (4) and E4 groups (none over 4 files) — confirmed by P9b; tester roster `E4-roster.md`

| Group | Files | Nodes (new / changed) | Requirements |
|---|---|---|---|
| W — the cue | `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py`; `s19_app/tui/definition_bench_view.py` (one pure function added) | 7 (4 new, 3 changed) | R-PE-BENCH.94 … .97, .100 … .105 |
| S — the stepped write and refresh (O-E) | `s19_app/tui/app/patch.py`; `s19_app/tui/screens_directionb/patch_editor/panel.py` | 10 (5 new, 5 changed) | R-PE-BENCH.98, .99, .101 (write refusals), .106; .100/3 |

**Source files: 4** — `bench_sheet.py`, `definition_bench_view.py`, `app/patch.py`, `patch_editor/panel.py`. Not touched: `styles.tcss` (the busy border is an inline style the bench sheet sets and clears, `E1-rulings.md` ED-1), `patch_editor/layout.py` (the idle title is read from the window at run time, not re-typed), `sheet.py`, `definition_sheet.py`, `definition_bench.py`, `a2l_definition.py` (I-2 read only), `services/change_service.py`. Tests (uncapped): new `tests/test_b103_inc9b_*.py`; Inc 9's timing nodes re-run unchanged (§6).

## 2. Function map (17 nodes; count from the graph's `## Nodes`)

### Group W — `bench_sheet.py`

| Node | New / changed | What changes | Requirements |
|---|---|---|---|
| `busy_job` (module function) | new, pure | from the selected row's name and bench state and the record-stage name → `(job word, name)` or `None` (CTX-PE-BENCH busy job) | .94, .95, .102 |
| `ArrayBenchSheet.on_mount` | new (does not call `super()`; Textual dispatches `StagingSheet.on_mount` exactly once along the MRO) | initializes ask, frame and stage state; creates the paused 0.1 s (`BUSY_TICK_S`) cue tick | .97 |
| `ArrayBenchSheet._enqueue` (`:123-132`) | changed (+3 lines) | a decode, preview or record ask keeps its ask time per (job word, name) unless one is kept already, and resumes the tick | .94, .96 |
| `ArrayBenchSheet._job_done` (`:218-250`) | changed (+1 line) | a record result that holds the queue keeps its name as the stage name | .94/3, .98 |
| `ArrayBenchSheet.record_done` (`:475-478`; *merged* `:472-475`) | changed (+2 lines) | clears the stage name, runs one cue tick at once (the cue leaves without waiting a tick) | .100, .101 |
| `ArrayBenchSheet._busy_tick` | new | the tick: `busy_job`; drops the ask times of jobs no longer busy; under `BUSY_GRACE_S` = 0.2 s or none → the idle look (clear the inline border, restore the kept idle title) and pause the tick when no job is asked; else the busy border (inline `round` `BUSY_COLOR` on `#patch_sheet_win`) and the busy title from `busy_title`; advances the frame; `BUSY_TICK_S` = 0.1 s, no new colour literal | .94, .95, .97, .100 … .102 |

### Group W — `definition_bench_view.py`

| Node | New / changed | What changes | Requirements |
|---|---|---|---|
| `busy_title` | new, pure | `(idle title, job word, name, seconds, frame, room) -> Text`: the busy title, the pill styled, the name echoed (`name_echo`) and cut to the room; `BUSY_COLOR = Style.parse(EDIT).color.get_truecolor().hex` defined in this module, no new colour literal | .96, .103 … .105 |

### Group S — `app/patch.py`

| Node | New / changed | What changes | Requirements |
|---|---|---|---|
| `PatchMixin.on_array_bench_sheet_record_stage_requested` (`:379-402`) | changed | runs the write; when the write reached the service, runs the refresh steps chained and releases the hold (`sheet.record_done`) after the last one; else releases at once; a raising step still releases (try/finally per step) | .98, .99, .100/3, .101 |
| `PatchMixin._stage_bench_record` (`:404-441`) | changed | returns `True` when the change service ran (`:433`); its last line (`:441`, the synchronous refresh) moves to the caller | .98, .101/3, .101/4 |
| `PatchMixin._refresh_patch_history_view` (`:654-728`) | changed (same calls, same order) | runs `_patch_refresh_steps()` one after the other (the five other callers keep a synchronous refresh) | regression (R-PE-DEF.62, LLR-081.3) |
| `PatchMixin._patch_refresh_steps` | new | the refresh as four steps, each reading the service when it runs: (1) serialize the document view; (2) the ledger, card and JSON view (`panel.refresh_entries(…, sheet=False)`); (3) the staging sheet (`panel.refresh_sheet_document()`); (4) `_patch_refresh_tail` | .98, .106 |
| `PatchMixin._patch_refresh_tail` | new | step 4's body: `refresh_bindings`, `refresh_issues`, `_refresh_patch_checks_tab`, `update_checks_view`, `set_edit_json_enabled`, `set_undo_redo_enabled(history_depths)`, `set_entry_edit_json_enabled` | .98, .106 |
| `PatchMixin._run_refresh_steps` | new | runs step 1 now and each next step through `set_timer(STEP_GAP_S, …)`; before each later step compares `_patch_document_token()` with the token taken at step 1: changed, or `#patch_editor_panel` no longer queryable, → skips the remaining steps as on a token change (the change's own refresh already painted the latest document); ALWAYS calls `on_done` exactly once, including a skip and any step raising; a raise is re-raised after `on_done` | .98, .99, .106 |
| `PatchMixin._patch_document_token` | new | `(id(service.document), tuple(sorted(service.history_depths().items())), id(self.current_file), self._image_write_generation)`; Apply mutates `current_file.mem_map` in place, so the object id alone cannot detect it | .106 |
| `PatchMixin._note_image_bytes_written` | changed (+1 line) | increments the per-instance monotonic `_image_write_generation` before the existing in-place-write hook work; all prior hook behavior unchanged | .106 |

### Group S — `patch_editor/panel.py`

| Node | New / changed | What changes | Requirements |
|---|---|---|---|
| `PatchEditorPanel.refresh_entries` (`:696-709`) | changed (additive keyword) | `sheet: bool = True`; `False` skips the sheet's `set_document` | .98 |
| `PatchEditorPanel.refresh_sheet_document` | new | `self._sheet.set_document(self._sheet_entries(self._entry_rows), self._mem_map)` | .98, .106 |

**Count:** 17 nodes, **9 new** (`busy_job`, `ArrayBenchSheet.on_mount`, `ArrayBenchSheet._busy_tick`, `busy_title`, `PatchMixin._patch_refresh_steps`, `PatchMixin._patch_refresh_tail`, `PatchMixin._run_refresh_steps`, `PatchMixin._patch_document_token`, `PatchEditorPanel.refresh_sheet_document`) and **8 changed** (`ArrayBenchSheet._enqueue`, `._job_done`, `.record_done`, `PatchMixin.on_array_bench_sheet_record_stage_requested`, `._stage_bench_record`, `._refresh_patch_history_view`, `._note_image_bytes_written`, `PatchEditorPanel.refresh_entries`). Group W 7 (4 new, 3 changed), group S 10 (5 new, 5 changed). Requirements → nodes: the graph's §Coverage.

## 3. Callers read (rule 8)

- `_refresh_patch_history_view`: `app/patch.py:377` (bytes entry apply), `:441` (the record stage — moves to the stepped path), `:850` (Undo), `:885` (Redo), `:1124` (load) — four keep the synchronous refresh.
- `PatchEditorPanel.refresh_entries`: `app/patch.py:294`, `:692`, `:1656`, `app/loaded_state.py:675`, `app/project_load.py:1029`, `panel.py:750` (`on_mount` self-call through `EntriesMixin`); all keep the default `sheet=True`. Tests that call it: `tests/test_tui_patch_card.py` (26), `test_tui_patch_editor_b94.py` (8), `test_tui_patch_big.py` (4), `test_b103_inc9_w_stage.py` (3), four more files (1 each) — positional calls, unaffected by a keyword-only parameter.
- `ArrayBenchSheet.record_done`: only `app/patch.py:402`. `record_staged`: only `:440` (both unchanged on the merged base; the methods are at *merged* `bench_sheet.py:472-475`, `:463-470`).
- `ArrayBenchSheet._enqueue`: `on_staging_sheet_selection_changed` (`:507`, `:509`; *merged* `:504`, `:506`), `_edit_changed` (`:424`; *merged* `:421`), `action_stage_record` (`:464`; *merged* `:461`), `set_document` (`:549`, `:551`, `:553`; *merged* `:546`, `:548`, `:550`). `_job_done`'s requeue (`:234`, `:237`) writes the queues directly, so a requeued job keeps its first ask time (wanted: the user has waited since the key).
- `#patch_sheet_win`: composed by `LayoutMixin.compose` (`patch_editor/layout.py:45-47`, title `STAGING SHEET`, subtitle `enter edit · ↑↓ row · arrays open the bench`); styled by `styles.tcss:2893-2900` (`border: round $rule`) and `:2920-2923` (`:focus-within` → `round $accent-calm`). The bench sheet is its child (`layout.py:48`).

## 4. Pilots E4 runs first (code `P` in the requirements)

1. **A frame between steps:** `call_after_refresh` runs its callback after the screen refresh, so a tick and a key queued during step k run and paint before step k + 1 (Textual 8.2.8). Pilot: two steps with a 0.3 s sleep each, a tick that records `monotonic()` and the painted title → a tick lands between them. If not, chain with `set_timer(0, …)` and re-pilot.
2. **Clearing the inline border:** after `styles.border = ("round", <busy colour>)` on `#patch_sheet_win`, clearing the inline rule (`styles.clear_rule("border")`, or setting the four edges back) returns the stylesheet's `round $rule` and the `:focus-within` accent. Pilot both, focused and not.
3. **The title room B:** the cells the top border gives a `Text` border title at 80, 118 and 220 columns (Textual draws corners and pads); read from a rendered screen line, not computed by hand.

**P9b results (merged base, quiet rtx; `E4-pilots.md`):** (1) `call_after_refresh` gives no key and no paint between steps 1 and 2 (0/3); `set_timer(0, …)` kills its timer (division by zero in `Timer._run`); `set_timer(0.1, …)` handles the key between steps 1 and 2 and paints a new title in every gap (3/3) → **STEP_GAP_S = 0.1 s via `set_timer`** (F-9b-4). (2) `clear_rule("border")` clears nothing; clearing the four edge rules restores the stylesheet's border only after `refresh()`; then both the rule colour and the `:focus-within` accent return (F-9b-6); `EDIT` is a style string, the busy colour is its foreground (F-9b-5). (3) **B = window content width − 4: 66 / 106 / 190** at 80 / 118 / 220 columns (window content width 70 / 110 / 194 = Inc 8b's V); a longer title is cropped by Textual to B − 1 characters plus `…`.

## 5. Item 3 of the brief: the measured 0.9–2.5 s gap between the key and the job start (cause not measured)

Path read from the key to the job start: `down` → `StagingSheet.action_move` (`sheet.py:199-203`) → `_select` (`:216-223`: `_fit_window` `:404-423`, `_fill_input` `:425-438`, `_paint` `:312-354` via `ArrayBenchSheet._paint` `bench_sheet.py:100-104`) → `_announce` posts `SelectionChanged` (`sheet.py:225-228`) → on a later loop turn `ArrayBenchSheet.on_staging_sheet_selection_changed` (`bench_sheet.py:480-510`; also `A2lPickerMixin._on_staging_sheet_selection_changed` `a2l_picker.py:234-245` moves the picker cursor) → `_enqueue("decode")` (`:123-132`) → `_start_next` (`:134-163`) sets `_active_job` and starts the `@work(thread=True)` worker `_run_job` (`:165-206`).

Candidate causes (none measured; E4 measures each):

| Id | Candidate | Where | Expected size |
|---|---|---|---|
| K1 | **Measurement artefact of the prototype driver.** `t0` is taken before `select()` (`proto8/capture_p8_driver.py:292-294`), which awaits `App._press_keys` → Textual `app.py:2067` and `:2069` each `await wait_for_idle(0)`, which returns only when process CPU time stops advancing or after `max_sleep = 1` s (`textual/_wait.py:8-10`, `:34-40`); with a decode thread burning CPU the process is never idle, so each wait runs its full 1 s. Then `pause=0.15` (driver `:159`) and the 0.05 s poll (`:119-124`). | driver + Textual 8.2.8 | 0.2–2.25 s, matching 0.89–2.50 s; the product's own share may be small |
| K2 | **The single-job queue.** `_start_next` returns while `_active_job` is set or a record stage holds the queue (`bench_sheet.py:135`); a running job (another row's summary or staged decode, a preview encode, or the decode of a row the user already left, whose result is discarded but whose thread runs on, R-PE-BENCH.22) delays the new decode by that job's remaining time — up to ~11 s for LARGE. | product | 0 to ~11 s |
| K3 | **The posted selection message** is handled behind messages already queued (job results `call_from_thread` `:206`, timers, refreshes). | product | ms to one queued handler |
| K4 | **Synchronous work in the key handler** before the post: `_fit_window` and `_paint` each build the selected row's detail (`detail_lines`) and `_paint` a row line per painted row. | product | small for LARGE with no values |
| K5 | **GIL contention** with a running worker (5 ms switch interval; FX9b: keys p50 0.044 s, max 0.357 s during an encode). | product | ≤ ~0.4 s |
| K6 | **A cyclic GC pass** after a > 4,096-element row is left (`:497-503` drops ~1 M element objects), on the UI thread. | product | unknown |

**What E4 must measure (skill `diagnose`), host `<runner>` (the 16-core runner of FX9f), quiet (1-min load < 1.0, `uptime` printed before each run), `s19_app.__file__` atop the transcript:** a probe in the real app under `run_test` (not the prototype driver) that stamps `time.monotonic()` at: the key event entering the app (`App.on_event` for `events.Key`), `action_move` entry, `SelectionChanged` handled by the bench, `_enqueue("decode")`, `_active_job` set, `_run_job`'s thread start, and the first tick that paints the busy cue. Scenarios, 10 runs each: (a) the prototype's `sc_busy` (LARGE ↔ SMALL_BLK, idle queue); (b) LARGE re-selected while another row's summary decode runs (K2); (c) (a) driven by `pilot.press` and by a posted `events.Key` (splits K1 out); (d) (a) with `gc.callbacks` timing (K6). Report p50 / max per segment and name the cause(s) with their share. Whatever the cause, R-PE-BENCH.94 bounds what the user sees: the cue keys on the ask (`BenchState.job`, set in the selection handler) — the queued case .94/4 covers K2.

## 6. Item 4 of the brief: does O-E bring R-PE-BENCH.29/2 and .82/1 back under 0.5 s? (measured, not promised)

The rows stay as FX9f left them (1.0 s for .29/2 and .82/1). E4 runs, after GREEN, on the quiet host above, alone (`-n 0`), `uptime` before each: the four timing nodes of `tests/test_b103_inc9_w_jobs.py` (29_1, 29_2, 82_1, 20_1), 5 runs each at the base `09001bbc` and at the Inc 9b tip, median and max; and Inc 9's FX9c probe `test_probe_parts` (82_1's scenario) for the duration of each refresh step and the block as a whole. Expected from FX9c/FX9d's numbers: 82_1's key lands in the write and refresh, so with the steps (largest ~0.25 s, the sheet's `set_document`) it should drop well under 0.5 s; 29_2 is a GIL tail of the preview encode on its worker (FX9c "the only option for 29_2 … is O-A"), so O-E should not move it. **Proposal the measurement would support:** if 82_1 is under 0.4 s (≥ 20 % margin) in 5 of 5 quiet runs, propose to the operator to restore R-PE-BENCH.82/1 to 0.5 s (a page item, DF-09); keep .29/2 at 1.0 s unless 29_2 shows the same margin; O-A stays in the backlog either way. E4 records the table in `E4-measure-o-e.md`.

## 7. Inc 8b and the E4 order (shared interfaces)

The amber border belongs to **`Container#patch_sheet_win`**, composed by `LayoutMixin.compose` in `patch_editor/layout.py:45-47` and styled by `styles.tcss:2893-2900` / `:2920-2923`; Inc 9b sets and clears it at run time from `ArrayBenchSheet._busy_tick` (`bench_sheet.py`) as an inline style plus the window's `border_title`, and edits neither `layout.py` nor `styles.tcss`. Inc 8b (grid D, colour tokens, Limits alignment, bit card, V-2, V-11, F-R14-1) likely edits `sheet.py`, `definition_sheet.py`, `styles.tcss` and possibly `bench_sheet.py` or `definition_bench_view.py` (array-row look, F-R14-1's sparkline) — not known until its slice is written. **Resolved (P9b):** Inc 8b's slice named `bench_sheet.py` (`_bench_geometry` only) and did not touch `#patch_sheet_win`'s title, subtitle or border; Inc 9b's E4 starts from the merge `e4485817`, and pilot §4.2 was re-run there (P2). **Rule for the orchestrator (as written at E1):** if Inc 8b's slice names `bench_sheet.py`, `definition_bench_view.py`, `app/patch.py` or `panel.py`, or changes `#patch_sheet_win`'s title, subtitle or border (its `layout.py` lines or its `styles.tcss` rules), Inc 9b's E4 starts from Inc 8b's merge and re-runs pilot §4.2; else they can run in parallel and merge in either order.
