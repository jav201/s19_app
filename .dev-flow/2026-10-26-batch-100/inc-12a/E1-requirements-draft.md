# Inc 12a E1 — replacement requirement blocks (draft, not merged)

Stage E1 of the design-first pipeline (skill `dev-flow-v3-beta`) for Inc 12a, "the progress indicator" (PLAN.md row 12a: "progress indicator (begin/step/end, elapsed) — N5 — app, styles (+ screens) — gate P-D"; verdict P-D variant A).

**How to merge.**
1. §A replaces the `### HLR-176 — Worker actions show real progress in the status line` block in `01-requirements.md` (§3) with HLR-176, and inserts HLR-176a … HLR-176d right after it.
2. §B replaces the blocks `### LLR-176.1` and `### LLR-176.2` (§4) with the blocks below, in the order given. `### LLR-176.3` and `### LLR-176.4` keep their text; only their owner changes to Inc 12b (§D.1, ruling Q1).
3. §C restores LLR-173.2m (removed from 9b by the 9b E1 ruling Q8). Insert it after LLR-173.2l.
4. §C' holds the backlog-sweep blocks (LLR-172.4e, LLR-172.4f, LLR-172.5i, LLR-172.5j, LLR-172.5k, LLR-172.6b, LLR-172.6c). Insert each after the last block of its family. If a suffix is taken by then, use the next free one and rename it in §C', §D and §E.
5. §D holds the AT / TC index rows (§5.3), the token-table rows (§3 preface) and the reverse-census rows (§5.4).
6. §E is the ledger entry, numbered `LED .NN`. Every `LED-2026-10-26-batch-100.NN` below takes the number assigned at merge.

**Conventions.**
- Every Statement holds exactly one "shall". No other field uses the word.
- Function names appear only in the trace, the thresholds and the negative controls, never in a Statement.
- Painted strings are English.
- "The tree" is main at `8947666` (Inc 9a merged). Inc 9b, 10 and 11 run before 12a and change `app.py`; where 12a hooks into their code, it names their interfaces (`_handle_load_dialog`, `_load_workarea_file`, `_TYPED_REFUSAL_TOKENS`, `_load_dialog_verdict`, `check_action`, `_prepare_project_save`).
- **Long action:** one entry of the action table (LLR-176.2b): file load, A2L load, project load, Save project, report, diff report, before/after. At 12a, four of them run their heavy part on a worker today (file load, report, diff report, before/after). Three run on the main thread (A2L load, project load, Save project) until Inc 12b moves them (HLR-177).
- **Progress line:** the text `<glyph> <label>  ·  step <n>/<m> <step name>  ·  <mm:ss>` in `#status_text` (the `pd_A` layout). `<glyph>` is one of the ten frames `⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏`.
- **Progress indicator:** the progress line plus a bar value above 0.
- **Cleared bar:** `#progress_bar` at progress 0 of total 100, the same state as at start-up.
- **Running action:** a long action that has begun and not ended.
- **Final line:** the text a long action gives at its end for `#status_text` (a project load gives the project and file line, LLR-178.2).
- **File state:** the text the app writes for `#status_text` when a file is installed (today `set_file_status`, for example `Loaded firmware.s19 (S19 only)`).
- **Outcome:** the one status-log line that names how a long action ended (today the `message` of the last `set_progress` call, for example `Loaded firmware.s19` or `Load failed`).
- **The seam:** `begin_busy`, `step_busy`, `end_busy` (NEW, `app.py`, B100-I12) and the timer callback that drives them.
- **Executed probes** (this E1, on `8947666`, outputs under `work/`):
  - P12a-1 `p1_progress_census.py`: 24 `set_progress` calls in 12 functions (P-29 holds); 2 `set_file_status` calls (`_handle_load_project`, `_apply_prepared_load`); 1 `#status_text` query site.
  - P12a-2 `p2_base_load.py`: across `load_from_path(case_01)`, `#status_text` takes the values `Ready.` and `Loaded firmware.s19 (S19 only)`; the second is painted while the bar is at 50; the bar ends at 100; `set_interval(` occurs 0 times in `app.py`; bar row height 1 and `#log_line_1` y 47, idle and after.
  - P12a-3 `p3_s19_parse_time.py`: a generated S19 holding 8 MiB of data (20 709 376 bytes) parses in 2.38 s in `S19File`; 4 MiB in 1.16 s.
  - P12a-4 `p4_sweep_base.py`: `_typed_load_route(Path('fw\x00.s19'))` raises `ValueError: stat: embedded null character in path`; 2 functions hold the `list_projects()` + `normcase` match (`_handle_load_project`, `_typed_load_route`); the `os.name == "nt"` gate is present in `list_projects`; loadable suffixes are `.hex .ihex .mac .s19 .srec` and `.a2l`.

---

## §A — HLR blocks (replace HLR-176; insert HLR-176a … HLR-176d after it)

### HLR-176 — A long action shows a progress line when it begins
- **Traceability:** US-166
- **Ledger:** LED-2026-10-26-batch-100.2, LED-2026-10-26-batch-100.11, LED-2026-10-26-batch-100.19, LED-2026-10-26-batch-100.35, LED-2026-10-26-batch-100.39, LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When a long action begins, the system shall paint in `#status_text` one progress line that holds a spinner glyph, the action's label, the step `n/m` with the step's name, and the elapsed time.
- **Decomposition:** LLR-176.1, LLR-176.1a, LLR-176.1g, LLR-176.1n, LLR-176.1p, LLR-176.1r, LLR-176.2, LLR-176.2a, LLR-176.2b.
  - The compound HLR-176 (8 obligation clauses, about 14 behaviours) is split into HLR-176 … HLR-176d (LED .NN).
  - Its A2L parse callback clause and its main-thread freeze clause move with LLR-176.4 and LLR-176.3 to Inc 12b (ruling Q1).
- **Variant slots (filled by the P-D verdict A, LED-2026-10-26-batch-100.2):** VS-PD-1 = the status line (`#status_text`), with the progress bar kept working. VS-PD-2 = no cancel.
- **Rationale (informative):** N5. The operator's P-D note: "El spinner con la acción en progreso debe ser suficiente. asumiendo que la barra de progreso realmente hace su trabajo también, mostrando el progreso." The `pd_A` prototype paints `⠋ Loading <name>  ·  step 1/3 <step>  ·  00:03`. UX-29 / B-11: one owner of `#status_text`.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_busy.py -k "tc_b100_50 or tc_b100_51 or at_b100_17"`
- **Numeric pass threshold:** each of the 4 actions that run a worker today (file load, report, diff report, before/after) → the first `#status_text` text after the begin matches `^[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏] .+  ·  step 1/[1-9] .+  ·  00:0[0-9]$` (4 of 4).
- **Negative control:** executed P12a-2 on `8947666`: across a file load, `#status_text` takes only `Ready.` and `Loaded firmware.s19 (S19 only)`, with no glyph and no step → RED.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-17, 12a half) the engineer loads a generated S19 holding 8 MiB of data by `l`, a typed path and Enter. While it parses, `#status_text` shows a spinner, `Loading <name>`, the step and an elapsed time that advances at least once. At the end, the status log names the file loaded, `#status_text` shows the file state, and the bar is empty.
  - **Shipped surface:** Load (`l`), `#status_text`, `#progress_bar`, the status log.
  - **Acceptance test(s):** AT-B100-17
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☐ invalid ☒ error
    - boundary: an action shorter than one timer tick (shown, then cleared);
    - error: a load that fails (the indicator ends with `Load failed`);
    - empty / invalid: N/A, no input.
  - **Negative control:** as above → AT-B100-17 (12a half) RED.

### HLR-176a — The spinner and the elapsed time advance while a worker runs
- **Traceability:** US-166
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS state):** While a long action runs its worker, the system shall advance the spinner glyph and the elapsed time of the progress line.
- **Decomposition:** LLR-176.1e, LLR-176.1f, LLR-176.1g, LLR-176.1q.
- **Rationale (informative):** "so that I do not think the app froze" (US-166). Declared limit at 12a: the three main-thread actions (A2L load, project load, Save project) block the event loop, so nothing advances between their begin and end; Inc 12b moves them to workers (HLR-177).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_busy.py -k "tc_b100_50 or at_b100_17"`
- **Numeric pass threshold:**
  - The 8 MiB-data S19 load (P12a-3: 2.38 s of parse) → before the end, the elapsed text changes at least 1 time and the glyph takes at least 5 distinct values (2 assertions).
  - A synthetic worker action of 1.2 s → the same 2 assertions.
- **Negative control:** executed P12a-2: `set_interval(` occurs 0 times in `app.py`, so no clock can repaint → RED.
- **Priority:** medium
- **Acceptance (black-box):** covered by AT-B100-17 (12a half), as HLR-176.

### HLR-176b — The bar moves within a step that reports its progress
- **Traceability:** US-166
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When a running step reports how much of its work is done, the system shall advance the progress bar within that step.
- **Decomposition:** LLR-176.1b, LLR-176.1c, LLR-176.1d.
- **Rationale (informative):** the operator's condition, "asumiendo que la barra de progreso realmente hace su trabajo" (UX-30, R-PD). At 12a no shipped action reports a done-of-total amount; the seam carries it, and the first shipped reporter is the A2L parse callback at Inc 12b (LLR-176.4). The old HLR named "bytes copied, read or parsed"; copy and read have no callback inside the 12a+12b files (ruling Q5).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_busy.py -k tc_b100_50`
- **Numeric pass threshold:** a synthetic worker action of 2 steps whose step 2 reports 1, 2, 3 and 4 MiB of 4 MiB → the bar reads 50, 62, 75, 87 within step 2, rising 4 times, never falling (4 of 4).
- **Negative control:** executed P12a-1: every bar value at `8947666` is a constant (0, 10, 15, 50, 55, 100), and no call carries a done-of-total amount → RED. A mutation that sets the bar from the step index only → the 4 within-step values stay at 50 → RED.
- **Priority:** medium
- **Acceptance (black-box):** none at 12a; the AT arm "the bar rises at least 2 times during the A2L parse" is AT-B100-17's 12b half.

### HLR-176c — The end of a long action removes the indicator and shows the outcome
- **Traceability:** US-166
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When a long action ends, by success, failure or exception, the system shall replace its progress indicator with the action's outcome.
- **Decomposition:** LLR-176.1i, LLR-176.1j, LLR-176.1k, LLR-176.1l, LLR-176.1m, LLR-176.1o, LLR-176.1s, LLR-176.2c, LLR-176.2d.
- **Rationale (informative):** the old text said "never left at a stale `100%`" and "one final writer … paint[s], in this order, the outcome, then the project and file line, then the file state". `#status_text` is one row, so three paints in order leave only the last; that contradicted HLR-176's own threshold and LLR-178.2 (the project and file line stays). The order is replaced by a precedence (LLR-176.1j, ruling Q4).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_busy.py -k "tc_b100_50 or tc_b100_51 or at_b100_17"`
- **Numeric pass threshold:** each of the 7 long actions, on its success exit and on its failure exit (14 arms) → after the end, `#status_text` holds no glyph, the bar is cleared, the status log's last line is the outcome, and 0 timers run.
- **Negative control:** executed P12a-2: after a successful load the bar stays at 100 → RED.
- **Priority:** medium
- **Acceptance (black-box):** covered by AT-B100-17 (12a half): at the end the status log names the file loaded and the bar is empty.

### HLR-176d — `#status_text` has one owner while a long action runs
- **Traceability:** US-166
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS state):** While a long action runs, the system shall keep `#status_text` for the progress line.
- **Decomposition:** LLR-176.1h, LLR-176.1j.
- **Rationale (informative):** UX-29 / B-11. P12a-2 shows the file state painted over the status line while the action still runs (bar at 50).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_busy.py -k tc_b100_50`
- **Numeric pass threshold:** a worker file load whose install writes the file state before the end → every `#status_text` value between the begin and the end is a progress line (0 other values), and after the end `#status_text` holds the file state (`Loaded <name> (S19 only)`, 1 equality).
- **Negative control:** executed P12a-2: `Loaded firmware.s19 (S19 only)` is painted while the bar is at 50, before the load's last progress call → RED.
- **Priority:** medium
- **Acceptance (black-box):** covered by AT-B100-17 (12a half).

---

## §B — LLR blocks (replace LLR-176.1 and LLR-176.2)

### LLR-176.1 — The begin paints the first progress line
- **Traceability:** HLR-176 · trace: `begin_busy` (NEW), `_busy_line` (NEW, guess) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.11, LED-2026-10-26-batch-100.19, LED-2026-10-26-batch-100.35, LED-2026-10-26-batch-100.39, LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When a long action begins, the system shall paint in `#status_text` the progress line with the first glyph, the action's label, `step 1/<m>` with the first step's name, and `00:00`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50 — `pytest tests/test_b100_busy.py -k tc_b100_50`
- **Numeric pass threshold:** a begin with label `Loading x.s19` and steps `Copy into the work area`, `Parse`, `Install` → `#status_text` equals `⠋ Loading x.s19  ·  step 1/3 Copy into the work area  ·  00:00` (1 equality), read in the same frame as the begin.
- **Negative control:** executed P12a-2: no progress line is ever painted at `8947666` → RED.
- **Boundary catalog:** ☒ boundary — 1 step (`step 1/1`); a label of 200 characters (clipped by the `#status_text` ellipsis, never wrapped).

### LLR-176.1a — The begin shows the bar from 0
- **Traceability:** HLR-176 · trace: `begin_busy`, `set_progress` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When a long action begins, the system shall set `#progress_bar` to 0 of 100.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** the bar at 40 before a begin (set by a prior call) → 0 of 100 after it (1 equality).
- **Negative control:** a mutation that leaves the bar untouched at begin → 40 → RED. Declared: at `8947666` the file load begins with `set_progress(10, …)`, so the base starts at 10, not 0 (P12a-1) → RED.
- **Boundary catalog:** none — the begin has no input classes.

### LLR-176.1b — A step without an amount sets the bar from its index
- **Traceability:** HLR-176b · trace: `step_busy` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When a running action reaches step `n` of `m` without reporting an amount, the system shall paint `step n/m` with that step's name and set the bar to `floor(100 × (n − 1) / m)`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** 4 steps reached in order → `step 1/4` … `step 4/4` painted and the bar at 0, 25, 50, 75 (4 of 4).
- **Negative control:** a mutation that paints the step but leaves the bar → 0, 0, 0, 0 → RED.
- **Boundary catalog:** ☒ boundary — `m = 1`; the last step (`n = m`).

### LLR-176.1c — A step with an amount moves the bar within the step
- **Traceability:** HLR-176b · trace: `step_busy` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When a running action's step `n` of `m` reports `done` of `total`, the system shall set the bar to `floor(100 × (n − 1 + done / total) / m)`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** step 2 of 2 reporting 1, 2, 3, 4 MiB of 4 MiB → 62, 75, 87, 100 (4 of 4, strictly rising).
- **Negative control:** a mutation that ignores `done` / `total` → 50, 50, 50, 50 → RED.
- **Boundary catalog:** ☒ boundary — `done = 0`; `done = total`.

### LLR-176.1d — Out-of-range step data is clamped
- **Traceability:** HLR-176b · trace: `step_busy` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If a running action reports a step outside `1 … m`, a `total` of 0 or less, or a `done` outside `0 … total`, then the system shall clamp the step to `1 … m` and the fraction to `0 … 1` without raising.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** step 0, step `m + 1`, `total = 0`, `total = −1`, `done = −5`, `done = total + 1` (6 arms) → 0 exceptions, the painted step within `1 … m`, the bar within 0 … 100 and never below the previous value of the same step (6 of 6).
- **Negative control:** a mutation dividing by `total` without the clamp → `ZeroDivisionError` on the `total = 0` arm → RED.
- **Boundary catalog:** ☒ invalid ☒ boundary — the 6 arms.

### LLR-176.1e — One timer advances the line while an action runs
- **Traceability:** HLR-176a · trace: `begin_busy`, `_busy_tick` (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS state):** While at least one long action runs, the system shall keep exactly one 0.1-second interval timer that advances the glyph by one frame and repaints the elapsed time.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** a synthetic worker action of 1.2 s → at least 5 distinct glyphs and the elapsed text `00:00` then `00:01` (2 assertions); 2 overlapping actions → 1 active timer (the app's timer count rises by 1, not 2).
- **Negative control:** executed P12a-2: `set_interval(` occurs 0 times → RED. A mutation that starts one timer per begin → 2 timers in the overlap arm → RED.
- **Boundary catalog:** ☒ boundary — an action that ends before the first tick (0 ticks, the line painted once and cleared).

### LLR-176.1f — The timer stops when no action runs
- **Traceability:** HLR-176a · trace: `end_busy` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the last running long action ends, the system shall stop the progress timer.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** after the last end → 0 progress timers active, and 0.5 s later `#status_text` unchanged (2 assertions).
- **Negative control:** a mutation that never stops the timer → the glyph-free final text is overwritten by a progress line on the next tick → RED.
- **Boundary catalog:** ☒ boundary — the end inside the first tick.

### LLR-176.1g — Elapsed time is minutes and seconds since the begin
- **Traceability:** HLR-176, HLR-176a · trace: `_busy_line` (guess) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall paint the elapsed time of a progress line as `mm:ss` counted from that action's begin, with the minutes not capped at 59.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** a clock injected at 0, 59.9, 60, 3 599 and 4 503 s → `00:00`, `00:59`, `01:00`, `59:59`, `75:03` (5 of 5).
- **Negative control:** a mutation using `%M:%S` of a time value → `75:03` becomes `15:03` → RED.
- **Boundary catalog:** ☒ boundary — 59 / 60 s; over 60 minutes.

### LLR-176.1h — The file state waits while an action runs
- **Traceability:** HLR-176d · trace: `set_file_status` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS state):** While a long action runs, the system shall store a file state written for `#status_text` as the one stored file-state line instead of painting it.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** 2 file-state writes during an action → 0 changes to `#status_text` before the end, and the second write kept as the stored file state (2 assertions).
- **Negative control:** executed P12a-2: the file state is painted while the load runs (bar at 50) → RED.
- **Boundary catalog:** ☒ boundary — a file-state write while no action runs (painted at once, as today).

### LLR-176.1i — The end writes the outcome to the status log
- **Traceability:** HLR-176c · trace: `end_busy`, `set_status` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When a long action ends with a non-empty outcome, the system shall append that outcome as one status-log line.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** an end with outcome `Loaded x.s19` → the log's last line is `Loaded x.s19` and the line count rose by 1; an end with an empty outcome → the count unchanged (2 arms).
- **Negative control:** a mutation that drops the outcome → the count unchanged in the first arm → RED.
- **Boundary catalog:** ☒ empty — an empty outcome.

### LLR-176.1j — The last end paints the stored file state
- **Traceability:** HLR-176c, HLR-176d · trace: `end_busy`, `set_file_status` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the last running long action ends, the system shall set `#status_text` to the one stored file-state line (the last text a file-state write stored, `Ready.` until the first write).
- **Rationale (informative):** A12a-06: one stored `file_state` replaces the three hand-back slots `restore` / `pending` / `final_line`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50; TC-B100-56 (Inc 12a extension, the project load's file state)
- **Numeric pass threshold:** two file-state writes during a run → `#status_text` = the last one after the end (1 equality); no write during a run → `#status_text` = the prior stored value (`Ready.` from a fresh app) (1 equality). Result 2 of 2.
- **Negative control:** a mutation that paints a `final_line` argument over `file_state` → the project-load arm of TC-B100-56 loses the project and file line → RED.
- **Boundary catalog:** ☒ boundary — a run with and without a file-state write.

### LLR-176.1k — The last end clears the bar
- **Traceability:** HLR-176c · trace: `end_busy`, `set_progress` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the last running long action ends, the system shall clear the progress bar.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50; re-pinned `tests/test_report_progress.py::test_report_generation_drives_progress_bar_to_100`
- **Numeric pass threshold:** an action whose last step reported 100 → after the end, progress 0 of total 100 (1 equality); the rendered bar row equals the start-up idle render (1 string comparison).
- **Negative control:** executed P12a-2: after a load the bar is at 100 → RED.
- **Boundary catalog:** ☒ boundary — an end after a failure (bar never past 0).

### LLR-176.1l — An exception still ends the indicator
- **Traceability:** HLR-176c · trace: the 7 actions' bodies (try / finally), `end_busy` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If a long action raises before its end, then the system shall end that action's progress with a failure outcome before the exception leaves the action.
- **Rationale (informative):** at 12a the app's survival of a raising worker is not claimed; LLR-177.2 (Inc 12b) keeps the app running (ruling Q8).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** a forced raise inside each of the 7 actions (7 arms) → an end recorded by a spy before the exception is observed, its outcome non-empty, 0 progress timers after it (7 of 7).
- **Negative control:** a mutation dropping the end on the exception path of the file load → 0 ends recorded → RED.
- **Boundary catalog:** ☒ error — one forced raise per action.

### LLR-176.1m — A step or an end from an unknown or replaced run leaves the indicator unchanged
- **Traceability:** HLR-176c · trace: `step_busy`, `end_busy` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If a step or an end names a key that is not running, or comes from a run that a later begin of the same key replaced, then the system shall leave the progress line, the bar and the timer unchanged, while an end with a non-empty outcome still appends that outcome to the status log.
- **Rationale (informative):** the load, report, diff-report and before/after workers are `exclusive=True` per group, so a second request replaces the first worker while the first thread can still post its end. The log is history, not indicator state (A12a-04).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** an end for a key never begun (with a non-empty outcome); a step for it; an end posted by the first of two file-load runs while the second runs (3 arms) → 0 changes to `#status_text`, the bar and the timer count in all three, and the log gains the outcome in the first and third arms (the step arm writes nothing) (3 of 3).
- **Negative control:** a mutation keyed only by the key name → the third arm clears the second run's indicator → RED.
- **Boundary catalog:** ☒ invalid ☒ boundary — an unknown key; a replaced run.

### LLR-176.1n — A second action begun while one runs is the one shown
- **Traceability:** HLR-176 · trace: `begin_busy` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If a long action begins while another long action runs, then the system shall show the newer action's progress line and bar.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** a report running, then a file load begun → `#status_text` holds the load's progress line and the bar the load's value (2 assertions); the report's later steps change neither (1 assertion).
- **Negative control:** a mutation keeping the first action shown → the report's line stays → RED.
- **Boundary catalog:** ☒ boundary — 2 and 3 overlapping actions.

### LLR-176.1o — When a shown action ends, the newest one still running is shown
- **Traceability:** HLR-176c · trace: `end_busy` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When a running long action ends while another long action still runs, the system shall show the progress line and bar of the most recently begun action still running.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** report begun, load begun, load ends → the report's progress line and bar shown, the load's outcome in the log, the timer still active (3 assertions); then the report ends → LLR-176.1j applies (1 assertion).
- **Negative control:** a mutation that runs the last-end hand-back on any end → `#status_text` loses the report's line while it runs → RED.
- **Boundary catalog:** ☒ boundary — the older action ends first (the newer stays shown).

### LLR-176.1p — A begin under a running key restarts that key's line
- **Traceability:** HLR-176 · trace: `begin_busy` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If a long action begins under the key of an action that is already running, then the system shall restart that key's progress line at `step 1/<m>` and `00:00`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** a file load at `step 2/3`, `00:01`, then a second file load → `step 1/3` and `00:00`, 1 entry for the key (2 assertions).
- **Negative control:** a mutation that keeps both entries → 2 entries → RED.
- **Boundary catalog:** ☒ boundary — the replaced run then ends (LLR-176.1m).

### LLR-176.1q — Progress widgets are written only on the main thread
- **Traceability:** HLR-176a · trace: the seam; the 4 worker bodies (`call_from_thread`) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall write `#status_text` and `#progress_bar` only on the main thread.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** a thread-id probe on `#status_text` and `#progress_bar` updates during the 4 worker actions → 0 writes off the main thread (4 of 4).
- **Negative control:** a mutation that calls the step function directly from the load worker → at least 1 off-main write → RED.
- **Boundary catalog:** none — the probe covers every worker action.

### LLR-176.1r — Names in a progress line are painted literally
- **Traceability:** HLR-176 · trace: `_busy_begin_action`, `painted_names` (`project_gather_service.py`), `_paint_status_text` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall paint a file or project name inside a progress line, and write the end's outcome line, through the batch's one name scrub and the one `safe_text` choke point, with markup off.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** driven through `load_from_path` (the real entry): `[b]x.s19`, `fw` + U+202E + `gpj.s19`, a 130-character name, and `a` + ESC + `]0;x` + BEL + `.s19` → 0 markup spans, 0 U+202E characters, the long name clipped to 120 characters ending in `…`, and the painted line and the end's outcome log line hold no `\x1b` / `\x07` (4 of 4). AST: `begin_busy(` is called only inside `_busy_begin_action` (1 call site).
- **Negative control:** a mutation inserting the raw name → U+202E present → RED; a site that calls `begin_busy` directly with a formatted label → the AST finds 2 → RED.
- **Boundary catalog:** ☒ invalid — a markup-shaped name; a bidirectional control; a long name; an ESC-bearing name.

### LLR-176.1s — The bar keeps its row when idle
- **Traceability:** HLR-176c · trace: `compose` (`#progress_bar`), `styles.tcss` `#progress_bar`
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall keep the progress bar's row height and the status log's vertical position the same whether or not a long action runs.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** at 118×54 and 80×24, idle and during an action → `#progress_bar` region height equal and `#log_line_1` region `y` equal (2 sizes × 2 assertions).
- **Negative control:** declared RED only as a mutation: executed P12a-2 shows the base already holds (height 1 / 1, `y` 47 / 47). A mutation hiding the bar when idle → `#log_line_1` moves up 2 rows → RED.
- **Boundary catalog:** ☒ boundary — 80×24, the smallest supported size.

### LLR-176.2 — Every progress-bar write maps to one action (C-31)
- **Traceability:** HLR-176 · trace: the action table `_BUSY_ACTIONS` (NEW, data); the 12 functions of P-29 (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.11, LED-2026-10-26-batch-100.19, LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** Every site that set the progress bar at the Inc 12a baseline shall map to exactly one long action's begin, step or end in the action table.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-51 — `pytest tests/test_b100_busy.py -k tc_b100_51` (an AST derivation over the baseline's `app.py`, stored as a fixture list at E2)
- **Numeric pass threshold:** the derivation maps 24 of 24 sites (P-29, re-derived at the E2 baseline after Inc 9b, 10 and 11; at least 24) to exactly one begin, step or end (24 of 24, 0 sites mapped twice).
- **Negative control:** executed P12a-1: 24 sites in 12 functions, none mapped (no table exists) → RED. A mutation removing one row → the census names its site → RED.
- **Boundary catalog:** none — the set is derived from the code.

### LLR-176.2a — Only the seam sets the bar
- **Traceability:** HLR-176 · trace: `set_progress`, the seam (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall set the progress bar only from inside the progress seam.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-51 (AST over `app.py`)
- **Numeric pass threshold:** calls of `set_progress` outside `begin_busy`, `step_busy` and `end_busy`, direct or through `call_from_thread` → 0; `#progress_bar` query sites outside `set_progress` and `compose` → 0 (2 assertions).
- **Negative control:** executed P12a-1: 24 calls outside any seam → RED.
- **Boundary catalog:** none — the census has no input classes.

### LLR-176.2b — The action table names the seven long actions
- **Traceability:** HLR-176 · trace: `_BUSY_ACTIONS` (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The action table shall hold one entry, with an English label and at least one named step, for each of file load, A2L load, project load, Save project, report, diff report and before/after.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-51
- **Numeric pass threshold:** 7 keys, each with a non-empty label and at least 1 step name (7 of 7); TC-B100-66 finds 0 decision ids in the 7 labels and their step names.
- **Negative control:** code read on `8947666`: no table → RED.
- **Boundary catalog:** none.

### LLR-176.2c — Each action ends on every success and failure exit
- **Traceability:** HLR-176c · trace: the 7 actions' exits; `_handle_load_error`, `report_failed` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** Each long action of the action table shall end its progress on every success exit and every failure exit.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-51
- **Numeric pass threshold:** per action, 1 success and 1 forced failure (7 × 2 = 14 arms: for example a file that is not found, an A2L of an unsupported type, a project that cannot be read, a placement failure after the save begins, a report write that fails, a diff report on a missing file, a before/after on a missing file; E2 lists the reachable arm per action) → exactly 1 begin and 1 end per arm, 0 indicators left (14 of 14).
- **Negative control:** a mutation dropping the end in `_handle_load_error` → the failure arm of the file load leaves 1 indicator → RED.
- **Boundary catalog:** ☒ error — 1 failure per action.

### LLR-176.2d — Save project reports its phases as steps (Inc 11 ruling Q2, the indicator half)
- **Traceability:** HLR-176c · trace: `_handle_save_dialog`, `_prepare_project_save` (Inc 11) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When Save project runs, the system shall report each save phase named in the action table as one step of its progress line, in order.
- **Rationale (informative):** Inc 11 ruling Q2 moved "the save runs on a worker with real progress" to 12a+12b. The indicator half is here: the Save project entry, its step reports and its end. Inc 12b moves the save onto a worker (HLR-177), and only then does the line show between the begin and the end. A refused save is refused in the dialog (Inc 11 ruling Q5), so it never begins.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-51
- **Numeric pass threshold:** a Save project of the case_01 session → a step spy records the phases of the Save project entry in order, each once (at least 3, for example `Copy the files`, `Write project.json`, `Check the saved files`; E2 names them), then 1 end with the success outcome (1 sequence equality); a name refused in the dialog → 0 begins (1 assertion).
- **Negative control:** executed P12a-1: no progress call sits in `_handle_save_dialog` at `8947666` → 0 steps → RED.
- **Boundary catalog:** ☒ boundary ☒ error — a save of a session with no MAC and no A2L (the phases still reported once each); a placement failure after the begin (1 end with the failure outcome).

---

## §C — Restored from Inc 9b (9b E1 ruling Q8)

### LLR-173.2m — The key bar and the palette name the two actions "Load" and "Projects"
- **Traceability:** HLR-173 · trace: `BINDINGS`, `_build_palette_entries` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall label the load-file action "Load" and the load-project action "Projects" in the key bar and in the command palette.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41_labels`; `pytest tests/test_b97_key_bar.py`; `pytest tests/test_tui_snapshot.py -m snapshot`
- **Numeric pass threshold:**
  - The footer at 118 columns holds `^l Load` and 0 occurrences of `Load file` (2 assertions).
  - The palette holds the entries "Load" and "Projects" and 0 entries "Load file" or "Load project" (4 assertions).
  - `tests/test_b97_key_bar.py` `GLOBAL_TEXTS` re-pinned to `^l Load`; the 80×24 row-1 set `GLOBAL_TEXTS_80` re-measured with the shorter label (the drop of `q Quit` and `^p palette` was caused by the longer labels; the measured set is recorded in the packet).
  - The 29 snapshot files of §D.4 rebaselined in the CI-matching environment and named one by one in the packet (29 of 29; 35 cells: 29 `Load file`, 6 `Load project`).
- **Negative control:** code read on `8947666`: `Binding("ctrl+l", "load_file", "Load file", priority=True)` (`app.py:2122`), `Binding("l", "load_file", "Load file", …)` (`:2127`), `Binding("p", "load_project", "Load project", …)` (`:2135`) → RED.
- **Boundary catalog:** ☒ boundary — the key bar at 80, 99 and 118 columns.
- **Note (informative):** the Workspace button `Load project (p)` (`#ws_load_project_button`, `app.py:2892`) is not part of VS-PA-4 and keeps its text (ruling Q6). The help overlay lists binding descriptions, so it shows "Load" and "Projects" too.

---

## §C' — Backlog sweep blocks (the BACKLOG-CODE rows routed to the Inc 12a sweep)

### LLR-172.4e — A project folder ending in a dot or a space is not listed on any platform (CR9-9 addendum)
- **Traceability:** HLR-172b · trace: `list_projects` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If a folder in the work area has a name that ends in a dot or a space, then the system shall leave it out of the project list on every operating system.
- **Rationale (informative):** the lister skip (LLR-172.4d) has no platform gate; the project-list skip has `os.name == "nt"`. Removing the gate makes both rules the same (backlog disposition B7: prefer removal over a new helper in `workspace.py`).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-37 — `pytest tests/test_b100_recents.py -k tc_b100_37_project_list_skips_a_trailing_dot_on_every_platform`
- **Numeric pass threshold:** `fw-v1.` and `fw-v2 ` (both holding `project.json` and a data file) beside `P` → the project list is `[P]` (1 row) on Windows (folders made through `\\?\`) and on the Linux CI (plain names) (2 platform arms).
- **Negative control:** executed P12a-4: the `os.name == "nt"` gate is present in `list_projects` → the Linux arm lists 3 projects → RED on the Linux CI.
- **Boundary catalog:** ☒ invalid ☒ boundary — a trailing dot; a trailing space.

### LLR-172.4f — The Workarea Files list holds only loadable files (C7)
- **Traceability:** HLR-172b · trace: `refresh_files`; the loadable-suffix predicate shared with `_load_dialog_rows` (Inc 9b, LLR-173.4b) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If a file in the work-area temp folder does not have a loadable suffix, then the system shall leave it out of the Workarea Files list.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-37 — `pytest tests/test_b100_recents.py -k tc_b100_37_files_list_shows_loadable_suffixes_only`
- **Numeric pass threshold:** temp holds `a.s19`, `b.hex`, `c.mac`, `d.a2l`, `d.a2l.json` and `e.txt` → 4 rows (`a.s19`, `b.hex`, `c.mac`, `d.a2l`), 0 rows for `d.a2l.json` or `e.txt` (1 list equality); an AST check → 1 loadable-suffix predicate, read by `refresh_files` and by the Load dialog's files section (1 assertion).
- **Negative control:** code read on `8947666`: `refresh_files` paints every regular file the lister returns (C7) → 6 rows → RED.
- **Boundary catalog:** ☒ invalid — a sidecar dump; an unrelated suffix; an upper-case suffix `F.S19` (listed).

### LLR-172.5i — A typed path the operating system refuses is refused (CR9-8)
- **Traceability:** HLR-172a · trace: `_typed_load_route`, `_load_path_from_user_input`; `_load_dialog_verdict` (Inc 9b) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the text typed into Load holds a character that the operating system's path calls refuse, such as NUL, or names a path whose existence check the operating system refuses, then the system shall load nothing and paint the `not found` and `check the path` tokens.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-38 — `pytest tests/test_b100_recents.py -k tc_b100_38_nul_in_typed_path_is_refused`
- **Numeric pass threshold:** a typed text whose `Path.exists` is monkeypatched to raise `PermissionError` (EACCES) and one to raise `OSError(ENAMETOOLONG)`, each through the status-line route and through the Load dialog's `#load_reason` (4 arms) → 0 exceptions, 0 loads, the token pair painted (4 of 4). Regression arms, GREEN on the post-9b base: the relative and absolute NUL texts (4 arms) → the same token pair, 0 exceptions.
- **Negative control:** on base `resolve_input_path` catches only `ValueError` / `RuntimeError`, so the monkeypatched `PermissionError` leaves `_typed_load_route` and stops the app → RED. The `resolve_input_path` catch is widened to `(OSError, ValueError, RuntimeError)` (S12a-01).
- **Boundary catalog:** ☒ invalid ☒ error — a NUL in a relative and in an absolute text; EACCES and ENAMETOOLONG.

### LLR-172.5j — A name is matched to the project list in one place (CR9-7, match)
- **Traceability:** HLR-172a · trace: `_listed_project_name` (NEW); `_handle_load_project`, `_typed_load_route` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall decide whether a name matches a listed project in one function.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-38 — `pytest tests/test_b100_recents.py -k tc_b100_38_one_project_match` (AST), plus every TC-B100-38 arm kept green
- **Numeric pass threshold:** an AST check → exactly 1 function compares a name against the `list_projects()` result (1 assertion); the TC-B100-38 and TC-B100-40 arms → 0 failures.
- **Negative control:** executed P12a-4: 2 functions hold the match (`_handle_load_project`, `_typed_load_route`) → RED.
- **Boundary catalog:** none — the census has no input classes.

### LLR-172.5k — The shared project refusals are worded from one table (CR9-7, wording)
- **Traceability:** HLR-172a · trace: `_TYPED_REFUSAL_TOKENS` (Inc 9b), `_load_path_from_user_input`, `_handle_load_project`, `_typed_load_route` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall word the `could not be read` and `not a project` project refusals of the status line and of the Load dialog from one table.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-38 (AST), plus TC-B100-63 kept green
- **Numeric pass threshold:** an AST check → the two token pairs are defined once, and every painted Load refusal sentence reads one of the two pairs (0 string literals of either reason outside the table, docstrings excluded); no exact site count is asserted, because the count breaks on every future site (A12a-01) (2 assertions).
- **Negative control:** executed P12a-4 (raw count, docstrings included): `could not be read` 8 occurrences and `not a project` 6 in `app.py`; E2 derives the painting sites (CR9-7: 3 copies) → RED.
- **Boundary catalog:** none.

### LLR-172.6b — A Workarea Files pick that is no longer a regular file loads nothing (SEC9-2)
- **Traceability:** HLR-172b · trace: `_load_workarea_file` (Inc 9b G1), `_load_from_item` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the picked work-area entry is not a regular file when it is picked, a link or another reparse point included, then the system shall load nothing and paint the `not a regular file` and `pick another file` tokens.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-39 — `pytest tests/test_b100_recents.py -k tc_b100_39_pick_rechecks_the_entry`
- **Numeric pass threshold:** list `fw.s19`, then replace it before the pick with (a) a folder `fw.s19`, (b) a junction `fw.s19`, (c) a file symbolic link to a file outside the work area (3 arms; arm (c) needs the symbolic-link privilege and is reported not run, never passed, where the platform cannot make it) → 0 parses (spy on the parse), the token pair painted, the session digest unchanged; through the Workarea Files list and through the Load dialog's `workarea` choice (2 routes; 6 arms in all).
- **Negative control:** code read on `8947666` (SEC9-2): `_load_from_item` tests `candidate.exists()`, which follows a link, then parses it → arm (c) loads the outside file → RED. E2 executes arms (a) and (b) on the baseline.
- **Boundary catalog:** ☒ invalid ☒ error — a folder; a junction; a file link.

### LLR-172.6c — A Workarea Files pick larger than the copy cap loads nothing (SEC9-2)
- **Traceability:** HLR-172b · trace: `_load_workarea_file` (Inc 9b G1); `DEFAULT_COPY_SIZE_CAP_BYTES` (`workspace.py`, read only) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the picked work-area file is larger than the work-area copy size cap when it is picked, then the system shall load nothing and paint the `too large to open` token with the file name and the `load a smaller file` token.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-39 — `pytest tests/test_b100_recents.py -k tc_b100_39_pick_over_cap_is_refused`
- **Numeric pass threshold:** the cap read at call time, patched to 1 024 bytes → a 1 025-byte `big.s19` → 0 parses, the tokens painted; a 1 024-byte `edge.s19` → loaded (2 arms).
- **Negative control:** code read on `8947666`: `_load_from_item` has no size check → the 1 025-byte arm parses → RED.
- **Boundary catalog:** ☒ boundary — cap and cap + 1 bytes.

---

## §D — Index, token and census edits

### D.1 — §5.3 AT and TC index rows

| AT | Story | Written at | Re-pinned at | Chain |
|---|---|---|---|---|
| AT-B100-17 | US-166 | Inc 12a (the 12a half: a worker file load of a generated S19 with 8 MiB of data — the line, the advancing elapsed time, the outcome and the cleared bar); Inc 12b (the 12b half: the bar rises at least 2 times during the case_06 A2L parse) | — | — |
| AT-B100-18 | US-167 | Inc 12b (uses the Inc 12a indicator) | — | — |

| TC arm | Written at | Extended at |
|---|---|---|
| TC-B100-50 (LLR-176.1, LLR-176.1a, LLR-176.1b, LLR-176.1c, LLR-176.1d, LLR-176.1e, LLR-176.1f, LLR-176.1g, LLR-176.1h, LLR-176.1i, LLR-176.1j, LLR-176.1k, LLR-176.1l, LLR-176.1m, LLR-176.1n, LLR-176.1o, LLR-176.1p, LLR-176.1q, LLR-176.1r, LLR-176.1s) | Inc 12a: the begin line and bar, steps by index and by amount, the clamp, one timer and its stop, `mm:ss`, the stored file state, the outcome line, the file-state hand-back, the cleared bar, the exception end, unknown and replaced runs (a replaced run's outcome is still logged), overlapping actions, main-thread writes, scrubbed names (ESC and C0 included), the idle row (LED .NN) | Inc 12b: the three moved actions animate between begin and end |
| TC-B100-51 (LLR-176.2, LLR-176.2a, LLR-176.2b, LLR-176.2c, LLR-176.2d) | Inc 12a: the site census, only the seam sets the bar, the 7-entry table, an end on every success and failure exit, the Save project phases (LED .NN) | Inc 12b: the worker exits of the three moved actions |
| TC-B100-52 (LLR-176.3) | Inc 12b (owner moved from 12a, ruling Q1) | — |
| TC-B100-73 (LLR-176.4) | Inc 12b: the parse callback; `s19_app/tui/a2l.py` back in `_ENGINE_PATHS` (owner moved from 12a, ruling Q1) | — |
| TC-B100-41 (LLR-173.2m) | Inc 12a: the "Load" / "Projects" labels in the key bar and the palette (LED .NN) | — |
| TC-B100-37 (LLR-172.4e, LLR-172.4f) | Inc 12a: the project-list skip on every platform; the Workarea Files list holds loadable suffixes only (LED .NN) | — |
| TC-B100-38 (LLR-172.5i, LLR-172.5j, LLR-172.5k) | Inc 12a: a path the OS refuses (EACCES / ENAMETOOLONG) refused, with the NUL arms as regression arms; one project match; one refusal wording table (LED .NN) | — |
| TC-B100-39 (LLR-172.6b, LLR-172.6c) | Inc 12a: the pick re-checks the entry (folder, junction, link) and the copy cap (LED .NN) | — |

**Edits to existing rows.**
- TC-B100-66 (LLR-173.7), "Extended at": `Inc 12a: the busy indicator` → `Inc 12a: the progress lines of the 7 long actions (labels and step names) and the two new token pairs (LED .NN)`.
- TC-B100-56 (LLR-178.2), "Extended at": add `Inc 12a: the project and file line reaches #status_text as the project load's file state (LLR-176.1j) (LED .NN)`. LLR-178.2's text already names this hand-back; Inc 12a makes it true.

### D.2 — §3 preface token table (new rows)

| Case | Reason token | Next-step token |
|---|---|---|
| Workarea Files pick: the entry is no longer a regular file (Inc 12a, LLR-172.6b) | `not a regular file` | `pick another file` |
| Workarea Files pick: the file is over the copy size cap (Inc 12a, LLR-172.6c) | `too large to open` + the file | `load a smaller file` |

Row edit: `typed path not found / unsupported …` → add `, a typed text holding a character the path calls refuse (Inc 12a, LLR-172.5i)` to its Case cell.

### D.3 — §5.4 reverse census

| Symbol (increment) | Test sources | Disposition |
|---|---|---|
| `set_progress` / `#progress_bar` (Inc 12a; replaces the "Inc 12a+12b" row) | 5: `test_before_after_report.py` (`:228` spy), `test_report_off_ui_thread.py` (`:173`, `:259` spies), `test_report_progress.py` (`:49` AC-2/3 "leave the bar at 100", `:66` AC-4, `:126` direct call), `test_tui_directionb.py` (`:2048`, `:2206` direct call), `test_tui_report_attribution.py` (`:106` replaces `set_progress` with a one-argument lambda) | `set_progress(value, message=None)` keeps its signature and stays the seam's bar writer, so the spies and the lambda still see every value. `test_report_generation_drives_progress_bar_to_100` is re-pinned: the bar reaches 100 before the end and is cleared after it (LLR-176.1k; the old pin encodes the stale-100 defect HLR-176c removes). The direct calls (`test_report_progress.py:126`, `test_tui_directionb.py:2206`) are allowed: LLR-176.2a counts sites in `app.py` only. |
| `set_file_status` (Inc 12a) | E2 derives it (the `#status_text` consumers in the `busy_status_line` component list 25 test sources) | the stored file state is painted at the end, so a test that reads `#status_text` after an action ends sees the same text; a test that reads it while an action runs is re-pinned |
| `list_projects` trailing-dot gate (Inc 12a) | E2 derives it | Windows unchanged; a Linux test that lists a dot-ending folder is re-pinned |
| `refresh_files` rows (Inc 12a, C7) | E2 derives it (tests that count Workarea Files rows with a `.a2l.json` or another non-loadable file) | re-pinned to the loadable rows |
| snapshot cells (Inc 12a; replaces the "Inc 9b, 11, 12a" row's 12a share) | the 29 files of D.4 | rebaselined in the CI-matching environment and named in the packet |

### D.4 — Snapshot files to rebaseline (LLR-173.2m)

Executed census on `8947666` (`work/snap_loadfile.txt`, `work/snap_loadproject.txt`): 29 pinned files under `tests/__snapshots__/test_tui_snapshot/` hold `Load file` in the key bar, and 6 of them also hold `Load project` (35 cells). The 104 / 66 matches under `tests/_artifacts/` are untracked generated output (`git ls-files tests/_artifacts` → 0) and are not pinned.

All 29 are `test_tc016s_density_layout_snapshot[<cell>].svg`, with these cells:
1. `a2l-comfortable-120x30`
2. `a2l-comfortable-160x40`
3. `a2l-comfortable-80x24`
4. `a2l-compact-120x30`
5. `a2l-compact-160x40`
6. `a2l-compact-80x24`
7. `diff-comfortable-120x30`
8. `issues-comfortable-120x30`
9. `issues-comfortable-160x40`
10. `issues-comfortable-80x24`
11. `issues-compact-120x30`
12. `issues-compact-160x40`
13. `issues-compact-80x24`
14. `mac-comfortable-120x30`
15. `mac-comfortable-160x40`
16. `mac-comfortable-80x24`
17. `mac-compact-120x30`
18. `mac-compact-160x40`
19. `mac-compact-80x24`
20. `map-comfortable-120x30`
21. `map-comfortable-80x24`
22. `patch-comfortable-120x30`
23. `patch-comfortable-80x24`
24. `workspace-comfortable-120x30` (also `Load project`)
25. `workspace-comfortable-160x40` (also `Load project`)
26. `workspace-comfortable-80x24` (also `Load project`)
27. `workspace-compact-120x30` (also `Load project`)
28. `workspace-compact-160x40` (also `Load project`)
29. `workspace-compact-80x24` (also `Load project`)

The workspace cells also paint the button `Load project (p)`, which keeps its text (ruling Q6).

**Constraint.** These baselines are tooling-version sensitive. They are regenerated only in the CI-matching environment: the manual workflow `.github/workflows/snapshot-regen.yml` (`ubuntu-latest`, Python 3.11, `pytest-textual-snapshot==1.1.0`, `pytest tests/test_tui_snapshot.py -m snapshot --snapshot-update`). Its artifact is downloaded, and only the 29 files above are committed. A local Windows regeneration is not accepted; the workflow's own header records that a local regeneration on 2026-05-28 moved 13 of 27 cells. Inc 9b, 10 and 11 run first. If one of them rebaselines any of these 29 files, E2 re-runs the census on the 12a baseline and the packet names the final list.

---

## §E — Ledger entry (draft)

**LED-2026-10-26-batch-100.NN — Inc 12a E1: HLR-176 split, the seam made singular, the 12a/12b boundary drawn, the labels restored, the backlog sweep decided.**
- **Split (compound into singular requirements):** HLR-176 into HLR-176, HLR-176a, HLR-176b, HLR-176c, HLR-176d. LLR-176.1 into LLR-176.1, LLR-176.1a, LLR-176.1b, LLR-176.1c, LLR-176.1d, LLR-176.1e, LLR-176.1f, LLR-176.1g, LLR-176.1h, LLR-176.1i, LLR-176.1j, LLR-176.1k, LLR-176.1l, LLR-176.1m, LLR-176.1n, LLR-176.1o, LLR-176.1p, LLR-176.1q, LLR-176.1r, LLR-176.1s. LLR-176.2 into LLR-176.2, LLR-176.2a, LLR-176.2b, LLR-176.2c.
- **New:** LLR-176.2d (Inc 11 ruling Q2, the indicator half of Save project).
- **Moved to Inc 12b (text unchanged):** LLR-176.3, LLR-176.4; TC-B100-52, TC-B100-73; AT-B100-18; AT-B100-17's parse half; HLR-176's A2L-callback and main-thread-freeze clauses (ruling Q1).
- **Restored from Inc 9b:** LLR-173.2m (9b ruling Q8), with the 29 snapshot files named in §D.4.
- **Backlog sweep, new:** LLR-172.4e (CR9-9 addendum), LLR-172.4f (C7), LLR-172.5i (CR9-8), LLR-172.5j (CR9-7), LLR-172.5k (CR9-7), LLR-172.6b (SEC9-2), LLR-172.6c (SEC9-2).
- **Defects fixed in place:** the three-paint order on a one-row label replaced by a precedence (LLR-176.1j); "bytes copied, read" removed from the within-step list (no callback in the 12a+12b files); the overlap of `exclusive` worker runs (LLR-176.1m, LLR-176.1n, LLR-176.1o, LLR-176.1p); LLR-176.2's site lines re-derived at the 12a baseline; the stale-100 pin of `test_report_progress.py` named for re-pin.
- **Backlog rows decided, not turned into requirements:** CR9-2 declared; CR9-5 / SEC9-8 declared and moved; SEC9-5 moved; OBS-9a-1 moved; OBS-9a-2 closed as not a defect; the batch-100 Inc 8b R12 save-as copy moved to Inc 12b; the Inc 10 Q7 and Q8 rows routed to the next batch (rulings file).
- **E3 r1 (design-fix) changes:**
  - LLR-172.5i (S12a-01): the one `resolve_input_path` catch widens to `(OSError, ValueError, RuntimeError)` → `('refuse', 'not found')`; the NUL arms become regression arms, and the RED arm is EACCES / ENAMETOOLONG forced by monkeypatching `Path.exists`.
  - LLR-176.1r (S12a-02, S12a-04): an ESC-bearing name arm (the painted line and the outcome log line hold no C0); the negative control becomes the AST rule "`begin_busy(` is called only inside `_busy_begin_action`", driven through `load_from_path`.
  - LLR-176.1m (A12a-04): `end_busy` writes the outcome before the generation check, so a replaced run's outcome is logged; the generation check governs only the indicator.
  - LLR-176.1h, LLR-176.1j (A12a-06): the three hand-back slots `restore` / `pending` / `final_line` collapse into one `file_state`; the last end paints it; P-4 and F-4 are superseded.
  - LLR-176.2c (A12a-01, A12a-02, A12a-03, A12a-05, A12a-08, A12a-09): the 6 `_handle_load_project` refusal sites are listed (8 in all); the project-load begin anchors immediately before `build_variant_set`; the A2L outcome keeps 9b's `painted_names` scrub; the file-load sync runs before `end_busy`; `copied.stat()` moves before the worker dispatch; `Parse the A2L` is reported only when the project has an A2L.
  - LLR-176.2c, LLR-176.2d (S12a-06): worker guards use `except BaseException` + `end` + re-raise, no unconditional `finally` cross-thread call after success.
