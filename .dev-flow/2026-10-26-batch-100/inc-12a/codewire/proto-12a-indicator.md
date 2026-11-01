# Code-Wire prototype — Inc 12a, group G-A, the progress indicator (`s19_app/tui/app.py` + one `styles.tcss` rule)

Stage E2 of the design-first pipeline (`dev-flow-v3-beta`) for Inc 12a ("the progress indicator"). Graph only: no stub, mark or other change in `s19_app/` of any tree. New functions are nodes whose `func:` starts with "new". Base: main `8947666` plus the fixed graphs of Inc 9b (`../../inc-9b-design/codewire/proto-9b-app.md`), Inc 10 (`../../inc-10-design/codewire/proto-10-app.md`) and Inc 11 (`../../inc-11-design/codewire/proto-11-app.md`). Line numbers are `8947666` lines of `app.py` unless another file is named.

Inputs: `../E1-requirements-draft.md`, `../E1-scope.md`, `../E1-rulings.md` (Q1–Q10), `../E2-rulings.md`, `baseline-12a.md`, `baseline-notes.md`, `interfaces-12a.md` (FIXED; what I need changed is in "Proposals to the orchestrator"), `../../inc-12b-design/E1-rulings.md` and `E1-scope.md` (the consumer of the seam). Four small probes ran with the s19env interpreter (Python 3.11, Textual 8.2.8), `python -I`, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONUTF8=1`, `LOCALAPPDATA` under `../work/ga/localappdata-ga`. Only the last two import the checkout. They import it read-only and write under `../work/ga/base`; `git status` of the checkout was unchanged afterwards (only the untracked `prototypes/load_projects/` that was there before):
- `../work/ga/probe-ga-timer.py` → `probe-ga-timer.out.txt`: the timer count after `stop()`, the `Label` text read, and `call_from_thread` re-raising in a worker;
- `../work/ga/probe-ga-bar.py` → `probe-ga-bar.out.txt`: the bar row after 0 → 100 → 0 compared with the start-up row;
- `../work/ga/probe-ga-long.py`, `probe-ga-long-nowrap.py` → `probe-ga-long.out.txt`, `probe-ga-long-nowrap.out.txt`: a 221-character `#status_text` on the real app at 118×54 and 80×24, as styled today and with `text-wrap: nowrap`;
- `../work/ga/census-noapp.py` → `census-noapp.out.txt`: the sync test functions that call a seam action with no running app.

Conventions:
- `T` = `app.query_one("#status_text", Label)`. "T reads x" means `str(T.render()) == x`, which is the read the tests already use (`test_b100_focus._file_status_text`).
- "Bar" = `app.query_one("#progress_bar", ProgressBar).progress`. "Spy" = a class-level `set_progress` spy that records `value` (the existing `test_report_off_ui_thread` form).
- "Active timers" = `[t for t in app._timers if t._task is not None]`. `stop()` clears `_task` at once, but the `WeakSet` only drops the timer after its cancelled task is collected, which needs one `pilot.pause()` (probe ga-timer T2, T4; finding F-5).
- "Effective end" = an `end_busy` call that returned `True`.
- `pn(x)` = `painted_names([x])`.
- `·` is U+00B7, always with two spaces on each side. The glyph frames are `⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏` (frame 0 is `⠋`).
- Fixtures: case_01 (`firmware.s19` 358 bytes, `firmware.mac`, `firmware.a2l`); project `P` of probe p12a U1.6 (`firmware.s19`, `firmware.a2l`, `project.json` without `files`); `A2LONLY` (only `cal.a2l`); the reportable project of p12a U1.11. Unless an example says otherwise, the app is `S19TuiApp(base_dir=tmp)` under `run_test(size=(118, 54))`, T reads `Ready.` and the bar is at 0 before the action.
- Every example states the Inc 12a target unless it says "holds on base".
- Example ids are `A12-NN`.

## Owned nodes (28) and context

- **New, data (4):** `BusyKey`, `_BusyAction` with `_BUSY_ACTIONS` (and `_BUSY_FRAMES`, `_BUSY_TICK_SECONDS`), `_BusyRun`, `_BusyState`. These are the fixed S-b / S-c / S-f types.
- **New, functions (8):** `begin_busy`, `step_busy`, `end_busy`, `_busy_tick`, `_busy_line`, `_busy_begin_action` (fixed, S-a / S-c / S-f), plus two private helpers that are not in the fixed file: `_busy_fail` and `_paint_status_text` (proposal P-1).
- **Changed (15, app.py):** `__init__` (1 attribute line), `set_file_status`, `load_from_path`, `_start_load_worker`, `_handle_load_error`, `load_a2l_from_path`, `action_before_after_report`, `_start_before_after_worker`, `_trigger_generate_report`, `_start_generate_report_worker` (with its nested `report_failed`), `_finish_generate_report`, `on_ab_diff_panel_report_requested`, `_start_diff_report_worker`, `_handle_load_project` (the G-A half: begin, steps, ends), `_commit_project_save` (post-11).
- **Changed (1, styles.tcss):** the selector `#workspace_status_bar #status_text.-busy` (fixed Q-6).
- **Unchanged, new or changed callers:** `set_progress` (body and signature kept; its callers are now only the three seam functions), `set_status`, `compose`, `_apply_prepared_load`, `load_selected_file`, `_handle_save_dialog` (post-11), `_route_load_project` (post-10), `on_report_viewer_screen_generate_requested`, `painted_names`.
- **Retired:** none.

**Imports (`app.py`).** `Literal` joins the `typing` import (`:13`), and `from textual.timer import Timer` is added (the `_BusyState.timer` annotation; with `from __future__ import annotations` it is used only for typing, but pyflakes still flags an undefined annotation name). `field` (`:4`) and `time` (`:11`) are already imported.

## Nodes

BusyKey / _BusyAction / _BUSY_ACTIONS / _BUSY_FRAMES / _BUSY_TICK_SECONDS
req: LLR-176.2b, LLR-176.2, LLR-176.2d, LLR-176.1e, LLR-173.7 (TC-B100-66 extension)
in:
out: module constants
func: new (module level, beside the other app constants). `BusyKey = Literal["file_load", "a2l_load", "project_load", "save_project", "report", "diff_report", "before_after"]`. `@dataclass(frozen=True) class _BusyAction: label: str; steps: tuple[str, ...]`. `_BUSY_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"`. `_BUSY_TICK_SECONDS = 0.1`. `_BUSY_ACTIONS` holds exactly these 7 rows (fixed S-c, Q-5):

| key | label | steps |
|---|---|---|
| `file_load` | `Loading {name}` | `Copy into the work area`, `Parse`, `Install` |
| `a2l_load` | `Loading {name}` | `Copy into the work area`, `Parse`, `Build the tag table` |
| `project_load` | `Loading project {name}` | `Check the files`, `Parse the A2L`, `Parse the image`, `Install` |
| `save_project` | `Saving project {name}` | `Create the folder`, `Place the files`, `Gather the project files`, `Write project.json` |
| `report` | `Generating the project report` | `Prepare the results`, `Write the report` |
| `diff_report` | `Writing the diff report` | `Write Markdown`, `Write HTML` |
| `before_after` | `Writing the before/after report` | `Compose the report` |

callers: `_busy_begin_action` (reads a row); TC-B100-51 / TC-B100-66 (read the table). Inc 12b reads the labels through `_BusyRun.label` only.
module: s19_app/tui/app.py
examples: A12-27 (LLR-176.2b) `len(_BUSY_ACTIONS) == 7`. The keys equal the 7 `BusyKey` values. Each label is non-empty and each row has at least 1 step (7 of 7). The step counts are `3, 3, 4, 4, 2, 2, 1` (18 names). TC-B100-66 scans the 7 labels, the 18 step names and the failure template `<label> failed` and finds 0 decision ids (no `HLR-`, `LLR-`, `US-`, `AT-`, `TC-`, `LED`, `UX-`, `CR`, `SEC`). Negative control: code read on `8947666`, no table → RED. A mutation that removes the `diff_report` row → `len == 6` → RED.
examples: A12-28 (LLR-176.2, TC-B100-51) the fixture list holds the 24 baseline sites (P12a-1; Inc 9b, 10 and 11 add none, baseline-notes "Numbers"). Each site is keyed by (function, ordinal of the `set_progress` call inside it), because line numbers move. Each maps to exactly one seam event:

| # | baseline site (`8947666` line) | value | maps to |
|---|---|---|---|
| 1 | `action_before_after_report` :4874 | 15 | begin `before_after` |
| 2 | `_start_before_after_worker` :4943 | 0 | end `before_after` (failed) |
| 3 | `_start_before_after_worker` :4957 | 100 | end `before_after` (written) |
| 4 | `_start_before_after_worker` :4969 | 0 | end `before_after` (refused) |
| 5 | `_trigger_generate_report` :5564 | 15 | begin `report` |
| 6 | `_start_generate_report_worker` :5650 (`report_failed`) | 0 | end `report` (failed) |
| 7 | `_start_generate_report_worker` :5687 | 0 | end `report` (rejected) |
| 8 | `_start_generate_report_worker` :5710 | 55 | step `report` 2 |
| 9 | `_finish_generate_report` :5794 | 100 | end `report` (success) |
| 10 | `on_ab_diff_panel_report_requested` :6908 | 15 | begin `diff_report` |
| 11 | `_start_diff_report_worker` :6962 | 0 | end `diff_report` (Markdown refused) |
| 12 | `_start_diff_report_worker` :6969 | 55 | step `diff_report` 2 |
| 13 | `_start_diff_report_worker` :6976 | 0 | end `diff_report` (failed) |
| 14 | `_start_diff_report_worker` :6987 | 0 | end `diff_report` (HTML refused) |
| 15 | `_start_diff_report_worker` :6997 | 100 | end `diff_report` (written) |
| 16 | `load_from_path` :13045 | 10 | begin `file_load` |
| 17 | `load_from_path` :13053 | 0 | end `file_load` (containment) |
| 18 | `load_from_path` :13067 | 50 | step `file_load` 2 |
| 19 | `load_a2l_from_path` :13121 | 10 | begin `a2l_load` |
| 20 | `load_a2l_from_path` :13126 | 0 | end `a2l_load` (containment) |
| 21 | `load_a2l_from_path` :13142 | 50 | step `a2l_load` 2 |
| 22 | `load_a2l_from_path` :13169 | 100 | end `a2l_load` (success) |
| 23 | `_start_load_worker` :15781 | 100 | end `file_load` (success) |
| 24 | `_handle_load_error` :15814 | 100 | end `file_load` (`Load failed`) |

  The result is 24 of 24 mapped and 0 sites mapped twice. The TC runs the AST walk on the post-12a `app.py` and checks that each of these (function, event) pairs is present: a `_busy_begin_action(key…)` / `begin_busy(key…)`, `step_busy(key…, n)` or `end_busy(key…)` call, direct or as the first argument of `call_from_thread`. Negative control: executed P12a-1, 24 sites with no table → RED. A mutation that removes row 8 (the report step) → the census names `_start_generate_report_worker` step 2 → RED.

_BusyRun / _BusyState
req: LLR-176.1n, LLR-176.1o, LLR-176.1p, LLR-176.1j, LLR-176.1h, LLR-176.1e
in:
out: types
func: new (fixed S-b, simplified A12a-06). `@dataclass class _BusyRun: gen: int; label: str; steps: tuple[str, ...]; n: int; fraction: float; started: float`. `@dataclass class _BusyState: runs: dict[BusyKey, _BusyRun] = field(default_factory=dict); last_gen: int = 0; file_state: str = "Ready."; timer: Optional[Timer] = None; frame: int = 0`. The shown run is `next(reversed(self._busy.runs.values()))`. Only the main thread reads or writes it.
callers: the seam functions and `_busy_fail` (main thread); Inc 12b's `_refuse_if_busy()` (read only, 12b S-a).
module: s19_app/tui/app.py
examples: see A12-20, A12-21 and A12-22 (order and restart) and A12-14 (file_state).

S19TuiApp.__init__
req: LLR-176.1e (one state), TC-B100-09 census
in: (unchanged)
out: None
func: changed: one attribute line beside the other run state, `self._busy = _BusyState()` (fixed S-b). Nothing else.
callers: Textual app construction (unchanged).
module: s19_app/tui/app.py
examples: A12-74 (census A8) `tests/test_b100_session_reset.py::test_tc_b100_09_domain_matches_the_live_source_census` is RED with `unclassified census names: ['_busy']` until `SNAPSHOT_EXCLUSIONS` holds `"_busy": "progress indicator run state; main-thread UI state, not session state (Inc 12a)"`. After the re-pin, 0 are unclassified. Negative control: the entry left out → RED. The guard holds.

S19TuiApp.begin_busy
req: LLR-176.1, LLR-176.1a, LLR-176.1e, LLR-176.1n, LLR-176.1p, HLR-176
in: BusyKey key; str label; Sequence[str] steps (at least 1)
out: int gen
func: new (fixed S-a). Main thread only. Steps:
- (1) `b = self._busy`; `b.last_gen += 1`; `gen = b.last_gen`.
- (2) When `b.runs` is empty: `b.frame = 0` (the frame reset is clarification P-6, so the first begin after an earlier action paints `⠋` again).
- (3) `b.runs.pop(key, None)`; `b.runs[key] = _BusyRun(gen, label, tuple(steps), 1, 0.0, time.monotonic())`. Popping first moves a restarted key to the end, so it is the shown run (LLR-176.1n, .1p).
- (4) `self._paint_status_text(self._busy_line(run))`; `self.set_progress(0)`; `self.query_one("#status_text", Label).add_class("-busy")`.
- (5) When `b.timer is None`: `b.timer = self.set_interval(_BUSY_TICK_SECONDS, self._busy_tick)`. So there is 1 timer however many runs exist.
- (6) `return gen`.
- It writes no status-log line (fixed Q-3).
callers: `_busy_begin_action` (the 7 actions); tests (synthetic begins with their own label and steps).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._busy] (run added or replaced)
examples: A12-01 (LLR-176.1, HLR-176) `gen = app.begin_busy("file_load", "Loading x.s19", ("Copy into the work area", "Parse", "Install"))`, read in the same frame with no `await` → T reads `⠋ Loading x.s19  ·  step 1/3 Copy into the work area  ·  00:00`, and `gen == 1` (2 of 2). Negative control: executed P12a-2, no progress line is ever painted on base → RED.
examples: A12-02 (LLR-176.1 boundary, 1 step) `begin_busy("before_after", "Writing the before/after report", ("Compose the report",))` → T reads `⠋ Writing the before/after report  ·  step 1/1 Compose the report  ·  00:00`.
examples: A12-03 (LLR-176.1 boundary, a 200-character label; finding F-3) label `"Loading " + "x" * 188 + ".s19"` → `str(T.render())` holds the whole line (1 equality) and the `#status_line` height is 1. The visible row is a separate matter, executed on base with a 221-character text (probe ga-long): `#status_text` wraps to region height 3 inside the 1-row `#status_line` at both 118×54 and 80×24, and the visible row ends in spaces, with no `…`. With the fixed Q-6 rule the label therefore is "clipped by the row", not "by the ellipsis". With proposal P-3 (`text-wrap: nowrap` in the same rule) the region height is 1 and the row ends `xx…` (probe ga-long-nowrap). The E4 test reads the row only once P-3 is ruled.
examples: A12-04 (LLR-176.1a) `app.set_progress(40)`, then `begin_busy("report", "R", ("a", "b"))` → bar 0 of total 100 (1 equality). Negative control: a mutation that leaves the bar untouched → 40 → RED. Declared: on base the file load begins with `set_progress(10, …)` (P12a-1) → RED.
examples: A12-26 (fixed S-g) after a begin, T has the class `-busy`. After a non-last end it still has it. After the last end it does not (3 of 3). Negative control: a mutation that removes the class on any end → the second assertion fails → RED.

S19TuiApp.step_busy
req: LLR-176.1b, LLR-176.1c, LLR-176.1d, LLR-176.1m, LLR-176.1n, HLR-176b
in: BusyKey key; int gen; int n; Optional[int] done = None; Optional[int] total = None
out: None
func: new (fixed S-a). Main thread only. Steps:
- (1) `run = self._busy.runs.get(key)`; `run is None or run.gen != gen` → return. Nothing changes (LLR-176.1m).
- (2) `m = len(run.steps)`; `n = min(max(n, 1), m)`.
- (3) When `done is not None and total is not None`: `fraction = 0.0 if total <= 0 else min(max(done / total, 0.0), 1.0)`. Otherwise `fraction = 0.0`.
- (4) When `n == run.n`: `fraction = max(run.fraction, fraction)`. Within a step the fraction never falls.
- (5) `run.n = n`; `run.fraction = fraction`.
- (6) Only when `run` is the shown run (`next(reversed(self._busy.runs.values())) is run`): `self._paint_status_text(self._busy_line(run))`; `self.set_progress(int(100 * (n - 1 + fraction) / m))`. `int` truncates a non-negative value, so it is the floor (risk R-3).
- It writes no status-log line (fixed Q-3) and never raises on its numbers.
callers: `load_from_path` (step 2); `_start_load_worker` (step 3, through `call_from_thread`); `load_a2l_from_path` (steps 2, 3); `_handle_load_project` (steps 2, 3, 4); `_commit_project_save` (steps 2, 3, 4); `_start_generate_report_worker` (step 2, through `call_from_thread`); `_start_diff_report_worker` (step 2, through `call_from_thread`). Inc 12b adds the byte callback (`done`, `total`) and the Save worker's per-file step.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._busy] (n, fraction)
examples: A12-05 (LLR-176.1b) `g = begin_busy("report", "L", ("a", "b", "c", "d"))`, then `step_busy("report", g, 2)`, `step_busy("report", g, 3)`, `step_busy("report", g, 4)`, all in the same frame. T reads `⠋ L  ·  step 2/4 b  ·  00:00`, then `… step 3/4 c …`, then `… step 4/4 d …`. The bar reads 0 after the begin, then 25, 50, 75 (4 of 4). Negative control: a mutation that paints the step but leaves the bar → 0, 0, 0, 0 → RED.
examples: A12-06 (LLR-176.1b boundary) a 1-step run: `step_busy(k, g, 1)` → `step 1/1`, bar 0. A 3-step run at its last step: `step_busy(k, g, 3)` → `step 3/3`, bar 66 (`int(100 * 2 / 3)`) (2 of 2).
examples: A12-07 (LLR-176.1c, HLR-176b) `g = begin_busy("report", "L", ("a", "b"))`; `step_busy("report", g, 2)` → bar 50; then `step_busy("report", g, 2, done, 4 * 2**20)` with `done` = 1, 2, 3 and 4 MiB → bar 62, 75, 87, 100. That is strictly rising: from the step's 50 it rises 4 times (4 of 4). Boundaries: `done = 0` → 50; `done = total` → 100. Negative control: a mutation that ignores `done` / `total` → 50, 50, 50, 50 → RED. HLR-176b's threshold says "1, 2, 3 and 4 MiB → 50, 62, 75, 87". That cannot hold together with LLR-176.1c's formula (finding F-2, proposal P-2).
examples: A12-08 (LLR-176.1d, 6 arms) each arm starts fresh from `g = begin_busy("report", "L", ("a", "b", "c"))`, `step_busy("report", g, 2, 1, 2)` (step 2, fraction 0.5, bar `int(100 * 1.5 / 3)` = 50):
  - (1) `step_busy(…, g, 0)` → `step 1/3 a`, bar 0;
  - (2) `step_busy(…, g, 4)` → `step 3/3 c`, bar 66;
  - (3) `step_busy(…, g, 2, 5, 0)` → `step 2/3 b`, bar 50 (the fraction is kept by the max rule);
  - (4) `step_busy(…, g, 2, 5, -1)` → bar 50;
  - (5) `step_busy(…, g, 2, -5, 10)` → bar 50;
  - (6) `step_busy(…, g, 2, 11, 10)` → bar 66 (fraction 1.0).
  Each arm: 0 exceptions, the painted step within `1 … 3`, the bar within 0 … 100, and on the same-step arms (3)–(6) never below 50 (6 of 6). Negative control: a mutation that divides by `total` without the clamp → `ZeroDivisionError` on arm (3) → RED. A mutation that drops the max rule → arm (5) reads 33 → RED.
examples: A12-19 (LLR-176.1m) three arms, each against a running `file_load` run, with T, the bar and the active timer count recorded before, and the log line count recorded:
  - (a) `end_busy("diff_report", 99, "x")` → returns `False`, and the log line count rose by 1 (`x` is logged; the indicator is unchanged);
  - (b) `step_busy("diff_report", 99, 2)` → returns, and the log line count is unchanged (a step writes no log line);
  - (c) `g1 = begin_busy("file_load", "Loading a.s19", S)`, `g2 = begin_busy("file_load", "Loading b.s19", S)`, then `end_busy("file_load", g1, "Loaded a.s19")` → `False`, `Loaded a.s19` is logged, and `step_busy("file_load", g1, 3)` → no repaint.
  In each arm T, the bar and the timer count are unchanged (3 of 3); arms (a) and (c) log the replaced run's outcome, arm (b) logs nothing. T still reads `⠋ Loading b.s19  ·  step 1/3 Copy into the work area  ·  00:00` in arm (c). Negative control: a mutation keyed by the key name only → arm (c) clears b's indicator → RED.

S19TuiApp.end_busy
req: LLR-176.1f, LLR-176.1i, LLR-176.1j, LLR-176.1k, LLR-176.1m, LLR-176.1o, HLR-176c, HLR-176d
in: BusyKey key; int gen; str outcome
out: bool ended
func: new (fixed S-a, Q-4; simplified A12a-06; A12a-04). Main thread only. Steps:
- (1) `outcome.strip()` non-empty → `self.set_status(safe_text(outcome).plain)`. This is one status-log line, through the instance attribute, so the lambda that `test_tui_report_attribution._drive_worker` installs still receives it. It is written before the generation check: the log is history, not indicator state (A12a-04).
- (2) `run = self._busy.runs.get(key)`; `run is None or run.gen != gen` → `return False`. Nothing else changes, so a second end of the same run is a no-op.
- (3) `del self._busy.runs[key]`.
- (4) Others remain → `shown = next(reversed(self._busy.runs.values()))`; `self._paint_status_text(self._busy_line(shown))`; `self.set_progress(int(100 * (shown.n - 1 + shown.fraction) / len(shown.steps)))`. The timer keeps running and `-busy` stays (LLR-176.1o).
- (5) None remain → `b.timer.stop()`; `b.timer = None`; `T.remove_class("-busy")`; `self.set_progress(0)`; `self._paint_status_text(b.file_state)` (LLR-176.1f, .1j, .1k).
- (6) `return True`.
- The hand-back is complete before it returns (12b S-c reads its quit flag after the call).
callers: `load_from_path` (containment refusal); `_start_load_worker` (success, through `call_from_thread`); `_handle_load_error`; `load_a2l_from_path` (containment, success); `_handle_load_project` (all-`None` refusal, success); `_commit_project_save` (10 abort exits and the committed tail); `report_failed` and the rejection arm of `_start_generate_report_worker` (through `call_from_thread`); `_finish_generate_report`; `_start_diff_report_worker` (4 exits, through `call_from_thread`); `_start_before_after_worker` (3 exits, through `call_from_thread`); `_busy_fail`.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._busy] (run removed; timer cleared at the last end; file_state painted)
examples: A12-12 (LLR-176.1f) after the last end: active timers 0 at once, `app._busy.timer is None`, and `len(app._timers)` back to its idle count after one `pilot.pause()` (probe ga-timer: `T2 right after stop … active 0`, `T4 after pause+gc 0`). 0.5 s later T is unchanged (`await pilot.pause(0.5)`) (3 of 3). Negative control: a mutation that never stops the timer → the next tick repaints a progress line over the hand-back → RED.
examples: A12-15 (LLR-176.1i) `end_busy(k, g, "Loaded x.s19")` → `app.log_lines[-1] == "Loaded x.s19"` and the line count rose by 1. A second run ended with `""` and a third with `"   "` → the count is unchanged and a `set_status` spy sees 0 calls (3 of 3). Negative control: a mutation that drops the outcome → the count is unchanged in the first arm → RED.
examples: A12-16 (LLR-176.1j, 1 arm) the app starts with `file_state` = `Ready.`. During a run, `set_file_status("Loaded firmware.s19 (S19 only)")` then `set_file_status("Loaded project 'P' -> firmware.s19")` → T still reads the progress line (0 changes), and `app._busy.file_state == "Loaded project 'P' -> firmware.s19"`. Then `end_busy(k, g, "o")` → T reads `Loaded project 'P' -> firmware.s19` (the last file state written). Result 2 of 2. Boundary: with no `set_file_status` write during the run, `end_busy` paints the prior `file_state` (the start-up `Ready.`). Negative control: a mutation that paints a `final_line` argument over `file_state` → TC-B100-56's project arm (A12-42) loses the project and file line → RED.
examples: A12-17 (LLR-176.1k) `g = begin_busy("report", "L", ("a", "b"))`; `step_busy("report", g, 2, 4, 4)` → bar 100; `end_busy("report", g, "done")` → bar progress 0 of total 100 (1 equality). The bar row text equals the start-up row text (probe ga-bar, a bare app with the same widget: 32 `━` then `   0% --:--:--` both times, `EQUAL after==idle True`) (1 string comparison). Negative control: executed P12a-2, after a load the bar is at 100 → RED.
examples: A12-18 (LLR-176.1k boundary) a run ended with a failure outcome before any step → bar 0 (it never passed 0), and the row equals the idle row.
examples: A12-21 (LLR-176.1o) `gr = begin_busy("report", "Generating the project report", ("Prepare the results", "Write the report"))`; `step_busy("report", gr, 2)`; `gl = begin_busy("file_load", "Loading x.s19", S)`; `end_busy("file_load", gl, "Loaded x.s19")` → T reads `<glyph> Generating the project report  ·  step 2/2 Write the report  ·  00:00`, bar 50, `log_lines[-1] == "Loaded x.s19"`, 1 active timer (3 assertions). Then `end_busy("report", gr, "Report: reports/r.md")` → LLR-176.1j applies: T reads `Ready.`, bar 0, 0 active timers (1 assertion). Boundary (the older run ends first): with both running, `end_busy("report", gr, "x")` → T still holds the load's line and bar 0. Negative control: a mutation that runs the last-end hand-back on any end → T reads `Ready.` while the report still runs → RED.

S19TuiApp._busy_tick
req: LLR-176.1e, LLR-176.1g, HLR-176a
in:
out: None
func: new (fixed S-f). The 0.1 s interval callback. `if not self._busy.runs: return` (a defensive one-liner; a stopped Textual timer runs no callback, see the `Timer._tick` read). `self._busy.frame = (self._busy.frame + 1) % 10`; `self._paint_status_text(self._busy_line(next(reversed(self._busy.runs.values()))))`. No bar write.
callers: the timer `begin_busy` creates (Textual `Timer._tick` invokes the callback in the timer's own task on the main loop).
module: s19_app/tui/app.py
examples: A12-09 (LLR-176.1e, HLR-176a, synthetic worker of 1.2 s) the test begins `report` on the main thread, starts a plain `threading.Thread` that sleeps 1.2 s and then calls `app.call_from_thread(app.end_busy, "report", g, "done")`, and samples T every 0.05 s with `await pilot.pause(0.05)` until the end. The samples hold at least 5 distinct glyphs, and the elapsed texts `00:00` then `00:01` in that order (2 assertions). Negative control: executed P12a-2, `set_interval(` occurs 0 times in `app.py` → 1 glyph, `00:00` only → RED.
examples: A12-10 (LLR-176.1e, overlap) a spy on `app.set_interval`; `begin_busy("report", …)` then `begin_busy("file_load", …)` → 1 `set_interval` call and active timers 1 (2 assertions). Negative control: a mutation that starts one timer per begin → 2 → RED.
examples: A12-11 (LLR-176.1e / LLR-176.1f boundary, an action shorter than one tick) `begin_busy(…)` and `end_busy(…)` in the same frame, with no `await` → a `_busy_tick` spy sees 0 calls; T was painted once with the progress line and then reads `Ready.`; active timers 0 (3 of 3).

S19TuiApp._busy_line
req: LLR-176.1, LLR-176.1g, LLR-176.1r, HLR-176
in: _BusyRun run
out: str line
func: new (fixed S-f, the pd_A text). `elapsed = int(time.monotonic() - run.started)`; `n = run.n`; returns `f"{_BUSY_FRAMES[self._busy.frame]} {run.label}  ·  step {n}/{len(run.steps)} {run.steps[n - 1]}  ·  {elapsed // 60:02d}:{elapsed % 60:02d}"`. A plain `str` (T keeps `markup=False`). The minutes are not capped. `time` is read through the module, so a test patches `s19_app.tui.app.time.monotonic`.
callers: `begin_busy`, `step_busy`, `end_busy` (the others-remain arm), `_busy_tick`.
module: s19_app/tui/app.py
examples: A12-13 (LLR-176.1g, injected clock; finding F-6) `app = S19TuiApp(base_dir=tmp)`, not run. `run = _BusyRun(1, "L", ("s",), 1, 0.0, 1000.0)`. For `t` in 0, 59.9, 60, 3599 and 4503 the test patches `app_module.time.monotonic` to `lambda: 1000.0 + t` around the synchronous `app._busy_line(run)` call only, with no `await` while patched → `⠋ L  ·  step 1/1 s  ·  00:00`, `… 00:59`, `… 01:00`, `… 59:59`, `… 75:03` (5 of 5). Negative control: a mutation that uses `time.strftime("%M:%S", time.gmtime(elapsed))` → `75:03` becomes `15:03` → RED.
examples: A12-24 (LLR-176.1r, driven through `load_from_path`, the real entry; S12a-04) four arms, each a `load_from_path` of a file under that name (the begin runs through `_busy_begin_action`):
  - `[b]x.s19` → T reads `⠋ Loading [b]x.s19  ·  step 1/3 Copy into the work area  ·  00:00`, verbatim, with 0 markup spans (the `Label` is `markup=False`);
  - `fw` + U+202E + `gpj.s19` → `⠋ Loading fwgpj.s19  ·  …`, with 0 U+202E characters;
  - a 130-character name → the label is `Loading ` plus 119 characters plus `…` (the name clipped to 120);
  - `a` + ESC + `]0;x` + BEL + `.s19` (a real file name) → the painted line holds no `\x1b` and no `\x07`, and the end's outcome log line (`Loaded …`) holds no `\x1b` / `\x07` (S12a-02).
  Result 4 of 4. Negative control: a mutation that inserts the raw name → U+202E present → RED; a mutation that skips the `_paint_status_text` scrub → the ESC arm shows `\x1b` → RED.

S19TuiApp._busy_begin_action
req: LLR-176.1r, LLR-176.2b
in: BusyKey key; Optional[str] name = None
out: int gen
func: new (fixed S-c, Q-2). `row = _BUSY_ACTIONS[key]`; `label = row.label.format(name=painted_names([name])) if "{name}" in row.label else row.label`; `return self.begin_busy(key, label, row.steps)`. This is the one `painted_names` call for progress labels. The rows with `{name}` are always called with a name (the 4 callers below).
callers: `load_from_path` (`file_load`, `normalized.name`); `load_a2l_from_path` (`a2l_load`, `normalized.name`); `_handle_load_project` (`project_load`, the listed name); `_commit_project_save` (`save_project`, `prepared.cleaned`); `_trigger_generate_report` (`report`); `on_ab_diff_panel_report_requested` (`diff_report`); `action_before_after_report` (`before_after`).
module: s19_app/tui/app.py
examples: A12-24 above; A12-30, A12-38, A12-42 and A12-46 (the four named labels). AST: in `app.py`, `begin_busy(` is called only inside `_busy_begin_action` (1 call site; tests stay exempt) (1 assertion). Negative control: a site that calls `begin_busy` directly with a `_BUSY_ACTIONS[key].label.format(…)` label → the AST finds 2 → RED.

S19TuiApp._busy_fail
req: LLR-176.1l, HLR-176c
in: BusyKey key; int gen
out: bool ended
func: new, private (proposal P-1: additive; no fixed signature changes). Main thread only. `run = self._busy.runs.get(key)`; `run is None or run.gen != gen` → `return False`; `return self.end_busy(key, gen, f"{run.label} failed")`. It builds the S-e failure outcome `<label> failed` from the painted label on the main thread, so a worker never reads `self._busy` and no second scrub exists. After an effective end it is a no-op.
callers: the `finally` of `load_a2l_from_path`, `_handle_load_project` and `_commit_project_save`; the `except BaseException` of `load_from_path`'s kickoff (finding F-1); the `except BaseException` of `_start_load_worker`, `_start_generate_report_worker`, `_start_diff_report_worker` and `_start_before_after_worker` (through `call_from_thread`) (S12a-06).
module: s19_app/tui/app.py
examples: A12-72 (no `_busy_fail` on success) a file load that ended with `Loaded firmware.s19` → its worker's success path posts no `_busy_fail` (the guard is `except BaseException`, not `finally`, S12a-06). Exactly 1 effective end is recorded, and 0 log lines are added after it (2 of 2). Negative control: `_busy_fail` that ends without the generation check → a second end with `Loading firmware.s19 failed` appears → RED.
examples: A12-33, A12-40, A12-45, A12-49, A12-56, A12-62, A12-66 (one per action, LLR-176.1l), and A12-71 (the kickoff).

S19TuiApp._paint_status_text
req: HLR-176d, LLR-176.1q
in: str text
out: None
func: new, private (proposal P-1). `self.query_one("#status_text", Label).update(safe_text(text).plain)`. It is the seam's only painter of T, and the one scrub choke point: ESC and C0 never reach the terminal (S12a-02). `set_file_status` routes through the same writer. LLR-176.2a counts `#progress_bar` query sites only, so this `#status_text` query site is outside every census.
callers: `begin_busy`, `step_busy`, `end_busy` (2 arms), `_busy_tick`, `set_file_status`.
module: s19_app/tui/app.py
examples: A12-23 (LLR-176.1q) a thread-id probe wraps `Label.update` on T and `ProgressBar.update` on the bar, and records `threading.get_ident()` against the `run_test` thread, across the 4 worker actions (A12-30, A12-53, A12-58, A12-63) → 0 writes off the main thread (4 of 4). Negative control: a mutation where `_start_load_worker` calls `self.step_busy(…)` directly instead of through `call_from_thread` → at least 1 off-main write → RED.

S19TuiApp.set_file_status
req: LLR-176.1h, HLR-176d, LLR-176.1j
in: str message
out: None
func: changed (:17913). It always stores `self._busy.file_state = safe_text(str(message)).plain`, and paints `self._paint_status_text(self._busy.file_state)` only when `self._busy.runs` is empty (fixed S-d, simplified A12a-06; the one writer of `#status_text` outside the seam now routes through the same scrub). After Inc 12a its callers are `_apply_prepared_load` and `_handle_load_project` (which stores the project and file line as the file state).
callers: `_apply_prepared_load` (baseline: direct :15464). `_handle_load_project` keeps its base `set_file_status(status_line)` (A12-42). `test_filename_markup_safety:94` calls it with no run (idle arm).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._busy] (file_state)
examples: A12-14 (LLR-176.1h) during a synthetic run, `set_file_status("A")` then `set_file_status("B")` → T still reads the progress line (0 changes from those calls), and `app._busy.file_state == "B"` (2 assertions). Then `end_busy(k, g, "")` → T reads `B`. Boundary: with no run, `set_file_status("Loaded x.s19 (S19 only)")` → T reads it at once and `file_state` stores it (holds on base). Negative control: executed P12a-2, the file state is painted while the load runs (bar at 50) → RED.

S19TuiApp.load_from_path
req: LLR-176.2, LLR-176.2c, LLR-176.1l, HLR-176, HLR-176a, HLR-176c, HLR-176d, AT-B100-17
in: Path path
out: None
func: changed (post-9b body). Steps:
- (1) The not-found and suffix refusals are unchanged and come before any begin.
- (2) `gen = self._busy_begin_action("file_load", normalized.name)` replaces `set_progress(10, "Copying into workarea temp...")`. That begin-line message is gone (fixed Q-3).
- (3) Everything after the begin to the end of the function sits in `try: … except BaseException: self._busy_fail("file_load", gen); raise`. The guard is `except`, not `finally`: on a normal return the run belongs to the worker (finding F-1).
- (4) The `WorkareaContainmentError` arm: `self.set_progress(0, "")` and `self.set_status(f"Cannot load file: {exc}")` become `self.end_busy("file_load", gen, f"Cannot load file: {exc}")`; `_pending_variant_id` and the logger are unchanged.
- (5) `self.set_progress(50, f"Parsing {copied.name}...")` becomes `self.step_busy("file_load", gen, 2)`.
- (6) `copied_size = copied.stat().st_size` is computed before the dispatch, then `self._start_load_worker(copied, gen=gen)` (A12a-08: nothing that can raise sits between the dispatch and the end of the guard, so `_busy_fail` never ends a run the worker owns).
- The recent record (post-9b condition) and the `call_later` of `_post_worker_launch` are unchanged.
callers: `_load_path_from_user_input` (baseline: direct :12942; post-10 inside `_confirm_then_load`'s `go`); `_handle_select_variant` (:7606, not marked). Unchanged.
module: s19_app/tui/app.py
modify: [I/O: workarea temp]
examples: A12-30 (LLR-176.2c success, HLR-176c) `load_from_path(case_01/firmware.s19)`, then `wait_for_complete()` and 2 pauses:
  - 1 begin with label `Loading firmware.s19`;
  - 1 effective end, with outcome `Loaded firmware.s19`;
  - spy `[0, 33, 66, 0]`;
  - the log lines added are `['Loaded firmware.s19 (S19 only)', 'Loaded firmware.s19']`;
  - T reads `Loaded firmware.s19 (S19 only)` (the stored file state);
  - no glyph in T; 0 active timers; `app._busy.runs == {}`.
  Negative control: executed p12a U1.1 on base, spy `[10, 50, 100]`, bar 100, log `['Copying into workarea temp...', 'Parsing firmware.s19...', …]` → RED.
examples: A12-32 (LLR-176.2c failure, after the begin) `copy_into_workarea` patched to raise `WorkareaContainmentError("synthetic containment refusal")` → spy `[0, 0]`; log `['Cannot load file: synthetic containment refusal']`; T reads `Ready.`; 1 effective end; 0 timers. Holds on base for the log line (p12a U1.3); the begin and end are new.
examples: A12-34 (no begin before the refusals) `load_from_path(tmp/"missing.s19")` → `File not found: …`, 0 begins, spy `[]`. `load_from_path(tmp/"x.txt")` (an existing file) → `Unsupported file type: .txt`, 0 begins (2 of 2).
examples: A12-71 (LLR-176.1l, the main-thread kickoff) `copy_into_workarea` patched to raise `PermissionError("synthetic")` (not a containment error) → an `end_busy` spy records `("file_load", g, "Loading firmware.s19 failed")` returning `True`, then `PermissionError` leaves `load_from_path` (`pytest.raises`); 0 active timers; T reads `Ready.` (3 of 3). Negative control: the guard left out → the run stays, with 1 active timer, after the raise → RED.
examples: A12-35 (HLR-176, 4 of 4 worker actions) the first T text after each begin, read in the begin's frame, matches `^[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏] .+  ·  step 1/[1-9] .+  ·  00:0[0-9]$`. From idle the four texts are:
  - `⠋ Loading firmware.s19  ·  step 1/3 Copy into the work area  ·  00:00`;
  - `⠋ Generating the project report  ·  step 1/2 Prepare the results  ·  00:00`;
  - `⠋ Writing the diff report  ·  step 1/2 Write Markdown  ·  00:00`;
  - `⠋ Writing the before/after report  ·  step 1/1 Compose the report  ·  00:00`.
  Negative control: executed P12a-2, T takes only `Ready.` and `Loaded firmware.s19 (S19 only)` → RED.
examples: A12-36 (HLR-176d) a wrapper on `Label.update` of T records every value during a worker file load of case_01 → every value between the begin and the end matches the HLR-176 pattern (`step [1-3]/3`), with 0 other values. After the end T reads `Loaded firmware.s19 (S19 only)` (1 equality). Negative control: executed P12a-2, `Loaded firmware.s19 (S19 only)` is painted while the bar is at 50 → RED.
examples: A12-37 (AT-B100-17, the 12a half, by keys) a generated S19 `big8.s19` with 8 MiB of data (20 709 376 bytes; P12a-3: 2.38 s of parse) in a folder outside the work area. The steps are `l` (the 9b Load dialog), type its absolute path, `enter` (post-10: nothing unsaved, so no question). The test samples T every 0.05 s while the worker runs:
  - at least 1 sample reads `<glyph> Loading big8.s19  ·  step 2/3 Parse  ·  <mm:ss>`;
  - the elapsed text changes at least 1 time (`00:00` → `00:01`);
  - at least 5 distinct glyphs.
  At the end: `log_lines[-1] == "Loaded big8.s19"`, T reads `Loaded big8.s19 (S19 only)`, the bar row equals the idle row, and 0 active timers. Result 7 of 7. Negative control: executed P12a-2 on base, T takes only `Ready.` and the file state, and the bar ends at 100 → RED.

S19TuiApp._start_load_worker
req: LLR-176.2, LLR-176.2c, LLR-176.1l, LLR-176.1q, HLR-176a
in: Path path; Optional[list[Path]] a2l_files = None; keyword-only int gen
out: None
func: changed (fixed S-m, Q-1: `gen` is required). `@work(thread=True, exclusive=True, group="load")` is unchanged. The whole body sits in `try: … except BaseException: self.call_from_thread(self._busy_fail, "file_load", gen); raise` (S12a-06: no unconditional `finally` cross-thread call after success). Inside:
- (a) the parse `except` posts `self._handle_load_error, path, exc, gen`;
- (b) the `loaded is None` arm posts `self._handle_load_error, path, ValueError(f"Unsupported file type: {suffix}"), gen`;
- (c) before `call_from_thread(self._apply_prepared_load, …)`, `self.call_from_thread(self.step_busy, "file_load", gen, 3)`;
- (d) `call_from_thread(self.set_progress, 100, f"Loaded {path.name}")` becomes `self.call_from_thread(self.end_busy, "file_load", gen, f"Loaded {path.name}")`.
- `_sync_loaded_file_to_project` runs before `end_busy` (A12a-05): `call_from_thread(self._apply_prepared_load, …)`, then `call_from_thread(self._sync_loaded_file_to_project, …)`, then the `end_busy` post, so the outcome is the last log line. The file-load half of finding F-7 is gone. `_parse_loaded_file` stays called here (the `test_tui_variants:228` census holds).
callers: `load_from_path` (baseline: direct :13071). No test calls it directly (grep). Inc 12b adds `_load_workarea_file`'s data arm (12b C4).
module: s19_app/tui/app.py
examples: A12-31 (LLR-176.2c failure) `_parse_loaded_file` patched to raise `RuntimeError("synthetic parse failure")` → spy `[0, 33, 0]`; log `['Load failed: synthetic parse failure', 'Load failed']`; T reads `Ready.`; 1 effective end (`Load failed`); 0 timers. Negative control: a mutation that drops the end in `_handle_load_error` → 1 run left, 1 active timer → RED. Executed p12a U1.2 on base: bar 100 after the failure → RED for LLR-176.1k.
examples: A12-33 (LLR-176.1l, the worker) `app._apply_prepared_load` patched to raise `RuntimeError("forced")`. `call_from_thread` re-raises it in the worker (probe ga-timer C1), and the `except BaseException` guard posts `_busy_fail` and re-raises → the `end_busy` spy records `("file_load", g, "Loading firmware.s19 failed")` returning `True` before `run_test` raises `WorkerFailed` (exit_on_error, P12b-2). The outcome is non-empty, and 0 active timers are recorded in the spy's callback after the end (3 of 3). Negative control: the `except BaseException` removed → 0 ends recorded → RED.
examples: A12-69 (Q-1) `app._start_load_worker(path)` with no `gen` → `TypeError` (missing keyword-only argument). AST: every `_start_load_worker` / `_start_*_report_worker` / `_start_before_after_worker` call in `app.py` passes `gen=` (4 of 4).

S19TuiApp._handle_load_error
req: LLR-176.2c
in: Path path; Exception exc; int gen
out: None
func: changed (S-m). The last line `self.set_progress(100, "Load failed")` becomes `self.end_busy("file_load", gen, "Load failed")`. `_pending_variant_id`, the error log and `set_status(f"Load failed: {exc}")` are unchanged and come before the end.
callers: `_start_load_worker` through `call_from_thread` (baseline: value at :15742, :15745; no direct test call, grep).
module: s19_app/tui/app.py
examples: A12-31 above. A12-52 (the unsupported arm) `_parse_loaded_file` patched to return `None` for `x.s19` → log `['Load failed: Unsupported file type: .s19', 'Load failed']`, 1 effective end, spy `[0, 33, 0]`.

S19TuiApp.load_a2l_from_path
req: LLR-176.2, LLR-176.2c, LLR-176.1l, LLR-176.2b
in: Path path
out: None
func: changed (post-9b body). Steps:
- (1) The not-found, suffix and project-guard refusals, and the large-A2L warning (`normalized.stat()`), are unchanged and come before the begin.
- (2) `gen = self._busy_begin_action("a2l_load", normalized.name)` replaces `set_progress(10, "Copying A2L into workarea temp...")`.
- (3) The rest of the function sits in `try: … finally: self._busy_fail("a2l_load", gen)`.
- (4) Containment arm: `set_progress(0, "")` and `set_status(f"Cannot load A2L: {exc}")` become `self.end_busy("a2l_load", gen, f"Cannot load A2L: {exc}")`, then `return`.
- (5) `set_progress(50, f"Parsing {copied.name}...")` becomes `self.step_busy("a2l_load", gen, 2)`.
- (6) Before `self.update_a2l_view()`: `self.step_busy("a2l_load", gen, 3)`.
- (7) `set_progress(100, f"Loaded {copied.name}")` and `set_status(f"A2L loaded: {copied.name}")` become `self.end_busy("a2l_load", gen, safe_text(f"A2L loaded: {painted_names([copied.name])}").plain)` (the outcome definition: the last painted line, keeping 9b's `painted_names` scrub — A12a-03; the `Loaded <name>` line goes).
- The focus re-home, the INFO log and `_sync_loaded_a2l_to_project` follow the end, as today.
- At 12a the line is painted and cleared inside one blocked call (declared invisibility, HLR-176a; Inc 12b moves it).
callers: `_load_path_from_user_input` (baseline: direct :12939; post-10 inside `go`); `_load_from_item` (:13333), post-9b `_load_workarea_file` (A2L arm). Unchanged.
module: s19_app/tui/app.py
modify: [I/O: workarea temp]
examples: A12-38 (LLR-176.2c success) `load_a2l_from_path(case_01/firmware.a2l)` → 1 begin (`Loading firmware.a2l`), spy `[0, 33, 66, 0]`, the log lines added are `['A2L loaded: firmware.a2l']`, T reads `Ready.`, 1 effective end, 0 timers. `test_b100_focus` reads `A2L loaded:` in `#log_line_4` (8 sites), and those hold. Negative control: executed p12a U1.4 on base, spy `[10, 50, 100]`, bar 100, 4 log lines → RED.
examples: A12-39 (LLR-176.2c failure) `copy_into_workarea` patched to raise `WorkareaContainmentError("synthetic containment refusal")` → spy `[0, 0]`, log `['Cannot load A2L: synthetic containment refusal']`, 1 effective end.
examples: A12-40 (LLR-176.1l) `_load_a2l_data_with_cache` patched to raise `RuntimeError("synthetic")` → the `end_busy` spy records `("a2l_load", g, "Loading firmware.a2l failed")` → `True`, then `RuntimeError` leaves `load_a2l_from_path` (`pytest.raises`); spy `[0, 33, 0]`; 0 active timers; T reads `Ready.` (4 of 4). Negative control: executed p12a U1.5 on base, spy `[10, 50]`, bar left at 50, no end line → RED.
examples: A12-41 (no begin before the refusals) a missing `x.a2l`, a `.txt` file, and a project that already has an A2L (`Project already has an A2L file.`) → 0 begins each (3 of 3).

S19TuiApp.action_before_after_report
req: LLR-176.2, LLR-176.2c, HLR-176
in:
out: None
func: changed. The filter read and its refusal are unchanged and come before the begin. Then `project_dir = self._active_project_dir()` is computed **before** the begin (finding F-10). `self.set_progress(15)` becomes `gen = self._busy_begin_action("before_after")`. The dispatch is `self._start_before_after_worker(loaded.path if loaded is not None else None, project_dir, report_filter, loaded.path.name if loaded is not None else "-", gen=gen)`.
callers: key `b` and the save-back control (baseline: none listed); `test_report_off_ui_thread.py:100`, `:272` call it directly (spies held, A12-64).
module: s19_app/tui/app.py
examples: A12-65 (no begin before the refusal) a report filter file that does not parse → `Before/after report refused: <errors>`, 0 begins, spy `[]`.

S19TuiApp._start_before_after_worker
req: LLR-176.2, LLR-176.2c, LLR-176.1l, LLR-176.1q
in: Optional[Path] loaded_path; Optional[Path] project_dir; Optional[ReportFilterMatcher] report_filter; str source_name; keyword-only int gen
out: None
func: changed. The body sits in `try: … except BaseException: self.call_from_thread(self._busy_fail, "before_after", gen); raise` (S12a-06). Each of the 3 exits replaces its pair `call_from_thread(self.set_progress, …)` + `call_from_thread(self.set_status, text)` with `self.call_from_thread(self.end_busy, "before_after", gen, text)`:
- failed: `f"Before/after report failed: {type(exc).__name__}: {exc}"`;
- written: `f"Before/after report written: {result.md_path} | {result.html_path}"`;
- refused: `"Before/after report refused: " + " ".join(result.diagnostics)`.
- The `_log_report_event` calls are unchanged.
callers: `action_before_after_report` (baseline: direct :4875).
module: s19_app/tui/app.py
examples: A12-63 (LLR-176.2c success) the composer stubbed to a written result (`md_path = base/"ba.md"`, `html_path = base/"ba.html"`) → spy `[0, 0]` (1 step, no step call); `log_lines[-1] == f"Before/after report written: {base/'ba.md'} | {base/'ba.html'}"` clipped to the log cap (finding F-8); 1 effective end; T reads `Ready.`.
examples: A12-64 (LLR-176.2c failure) nothing loaded → the composer refuses → spy `[0, 0]`; `log_lines[-1]` equals `"Before/after report refused: No applied change summary - apply a change document and save the patched image first."` (plus any further diagnostics, joined by spaces) clipped to `max(50, app.size.width)` characters; 1 effective end. `test_ac3_before_after_progress_never_sticks_mid_fill` (`seen[-1] in (0, 100)`) holds with `[0, 0]`. Holds on base for the log line (p12a U1.15).
examples: A12-66 (LLR-176.1l) `app._log_report_event` patched to raise `RuntimeError("forced")` when `ok=True`, with the composer stubbed to written → the spy records `("before_after", g, "Writing the before/after report failed")` → `True` before `WorkerFailed`; 0 active timers.

S19TuiApp._trigger_generate_report
req: LLR-176.2, LLR-176.2c, HLR-176
in: int context_bytes; Sequence[DeclaredRegion] declared_regions = ()
out: None
func: changed. The refusals and the one announcement status line are unchanged and come before the begin. `self.set_progress(15)` becomes `gen = self._busy_begin_action("report")`, and the dispatch passes `gen=gen` (its other arguments are already locals).
callers: `on_report_viewer_screen_generate_requested` (baseline: direct :5460); `test_b100_recents.py:1742` (`_trigger_generate_report(16)`, through the begin, held).
module: s19_app/tui/app.py
examples: A12-57 (no begin before the refusals) no project → `Report: no project variants - load a project first.`, 0 begins, spy `[]`.
examples: A12-75 (census A2 re-pin) `test_kickoff_sets_bar_in_progress_before_worker` stubs the worker (`lambda *a, **k: None`, which accepts `gen=`) → after the press, T reads `⠋ Generating the project report  ·  step 1/2 Prepare the results  ·  00:0x` and the bar is 0. The old `0 < p < 100` is replaced by "the progress line is painted and the bar is 0". The stubbed run stays open until the app exits (risk R-7).

S19TuiApp._start_generate_report_worker
req: LLR-176.2, LLR-176.2c, LLR-176.1l, LLR-176.1q
in: (unchanged positional parameters); keyword-only int gen
out: None
func: changed. The body (after the nested `def report_failed`) sits in `try: … except BaseException: self.call_from_thread(self._busy_fail, "report", gen); raise` (S12a-06). Changes:
- (a) `report_failed(exc)`: the pair `set_progress(0)` + `set_status(f"Report failed: {type(exc).__name__}: {exc}")` becomes `self.call_from_thread(self.end_busy, "report", gen, f"Report failed: {type(exc).__name__}: {exc}")`. It stays the single builder (TC-572: `f"Report failed:` 1, `report_failed(exc)` 2, `f"Report rejected:` 1).
- (b) The rejection arm: the pair becomes `self.call_from_thread(self.end_busy, "report", gen, f"Report rejected: {exc}")`.
- (c) `call_from_thread(self.set_progress, 55)` becomes `self.call_from_thread(self.step_busy, "report", gen, 2)`.
- (d) Success: `self.call_from_thread(self._finish_generate_report, report_path, gen)`.
- The `status_callback` lambda (the variant lines) is unchanged.
callers: `_trigger_generate_report` (baseline: direct :5565); `test_tui_report_attribution._drive_worker` (:109, re-pinned, A12-76).
module: s19_app/tui/app.py
examples: A12-54 (LLR-176.2c failure) `generate_project_report` patched to raise `RuntimeError("synthetic report failure")` → spy `[0, 50, 0]`; `log_lines[-1] == "Report failed: RuntimeError: synthetic report failure"`; 1 effective end. TC-572's three counts hold (1, 2, 1). Holds on base for the log line (p12a U1.12).
examples: A12-55 (the rejection arm) `context_bytes = -1` → spy `[0, 0]`; `log_lines[-1]` starts with `Report rejected: `; 1 effective end.
examples: A12-56 (LLR-176.1l) `app._log_report_event` patched to raise `RuntimeError("forced")` when `ok=True` → the spy records `("report", g, "Generating the project report failed")` → `True` before `WorkerFailed`; 0 active timers.
examples: A12-76 (census A6 / A7 re-pin) `_drive_worker` gains `gen = app.begin_busy("report", "x", ("a", "b"))` after it installs its two lambdas, and passes `gen=gen`. AT-263 then records `[0, 50, 0]` (failure) and `[0, 0]` (rejection), so its last values are `0` and `0`. AT-260 / AT-261 / AT-262 / TC-571 read `statuses`, which `end_busy` fills through `self.set_status` (A12-15) (5 of 5). Negative control: the helper without a begin → `end_busy` returns `False` and `statuses` lacks the result line → RED (the reason for the re-pin).

S19TuiApp._finish_generate_report
req: LLR-176.2c, LLR-176.1k
in: Path report_path; int gen
out: None
func: changed (S-m). `self._last_execution = None` (unchanged); then `self.set_progress(100)` and `self.set_status(f"Report: {report_path.parent.name}/{report_path.name}")` become `self.end_busy("report", gen, f"Report: {report_path.parent.name}/{report_path.name}")`.
callers: `_start_generate_report_worker` through `call_from_thread` (baseline: value at :5719); `test_report_progress.py:127` (re-pinned, A12-77).
module: s19_app/tui/app.py
examples: A12-53 (LLR-176.2c success) the reportable project of p12a U1.11 → the log lines added are `['Report: no prior execution - running active scope...', "Executing variant 'a' (1 file(s))...", "Variant 'a': ok - 1 change, 0 check", 'Report: reports/<stamp>-report.md']`; spy `[0, 50, 0]`; 1 effective end; T unchanged from before the action. Negative control: executed p12a U1.11, spy `[15, 55, 100]`, bar 100 → RED.
examples: A12-77 (census A1, A3 re-pins) `test_report_generation_drives_progress_bar_to_100` reads bar `0` after the report and the idle row (LLR-176.1k). `test_finish_generate_report_completes_bar` becomes `g = app.begin_busy("report", "x", ("a", "b"))`; `app.set_progress(40)`; `app._finish_generate_report(path, g)` → bar 0, `log_lines[-1] == "Report: reports/r.md"` (2 of 2).

S19TuiApp.on_ab_diff_panel_report_requested
req: LLR-176.2, LLR-176.2c, HLR-176
in: AbDiffPanel.ReportRequested event
out: None
func: changed. The no-comparison refusal (panel status only) is unchanged and comes before the begin. `self.set_progress(15)` becomes `gen = self._busy_begin_action("diff_report")`; the dispatch passes `gen=gen` (its arguments are already locals).
callers: Textual message dispatch (baseline: none listed).
module: s19_app/tui/app.py
examples: A12-61 (no begin before the refusal) Report pressed with no comparison → panel `No comparison yet — press Compare first.` (`sev-warning`), 0 begins, 0 status-log lines (holds on base).

S19TuiApp._start_diff_report_worker
req: LLR-176.2, LLR-176.2c, LLR-176.1l, LLR-176.1q, HLR-176c
in: AbDiffPanel panel; object result; dict kwargs; str diff_source; keyword-only int gen
out: None
func: changed. The body sits in `try: … except BaseException: self.call_from_thread(self._busy_fail, "diff_report", gen); raise` (S12a-06). At each of the 4 exits the panel text is held in a local `text`; `call_from_thread(self.set_progress, 0|100)` becomes `self.call_from_thread(self.end_busy, "diff_report", gen, text)`, at the same place (so the end comes before the panel status); then `self.call_from_thread(panel.set_status, text, <severity>)` is unchanged. The texts are `"Report refused: " + "; ".join(md.diagnostics)`, `f"Diff report failed: {type(exc).__name__}: {exc}"`, `"HTML report refused: " + "; ".join(html.diagnostics)` and `f"Diff report written: {md.path}  |  {html.path}"`. Each exit therefore adds 1 status-log line, which is new (fixed Q-3, E2 rulings "Diff report"). `call_from_thread(self.set_progress, 55)` becomes `self.call_from_thread(self.step_busy, "diff_report", gen, 2)`.
callers: `on_ab_diff_panel_report_requested` (baseline: direct :6909). `test_tui_diff_screen._b78_press_report` waits on `panel.set_status`, which now runs after the end.
module: s19_app/tui/app.py
examples: A12-58 (LLR-176.2c success, HLR-176c) both generators stubbed to written (`md.path = d/"r.md"`, `html.path = d/"r.html"`) → spy `[0, 50, 0]`; `log_lines[-1] == f"Diff report written: {d/'r.md'}  |  {d/'r.html'}"` (clipped to the log cap); the panel status has the same text with `sev-ok`; 1 effective end. Negative control: executed p12a U1.13 on base, 0 status-log lines and bar 100 → RED.
examples: A12-59 (LLR-176.2c failure) Markdown refused with diagnostics `["synthetic"]` → spy `[0, 0]`; `log_lines[-1] == "Report refused: synthetic"`; the panel `Report refused: synthetic` with `sev-error`; 1 effective end. Holds on base for the panel (p12a U1.14); the log line is new.
examples: A12-60 (the two later failure arms) the HTML generator raises `RuntimeError("x")` → spy `[0, 50, 0]`, `log_lines[-1] == "Diff report failed: RuntimeError: x"`. HTML refused with `["y"]` → `[0, 50, 0]`, `HTML report refused: y` (2 of 2). `test_ac4_diff_progress_never_sticks_mid_fill`'s refused arm (`[-1] == 0`) holds; its success arm is re-pinned from 100 to 0 (census A5).
examples: A12-62 (LLR-176.1l) `app._log_report_event` patched to raise when `ok=True`, generators stubbed to written → the spy records `("diff_report", g, "Writing the diff report failed")` → `True` before `WorkerFailed`.

S19TuiApp._handle_load_project
req: LLR-176.2b, LLR-176.2c, LLR-176.1j, LLR-176.1h, LLR-176.1l, LLR-178.2 (TC-B100-56 extension)
in: Optional[str] name
out: None
func: changed (post-10 body; G-B edits the listing block first, seam X-1). The G-A half:
- (1) Immediately before `variant_set = build_variant_set(name, data_files)`, after every refusal (the `project.json` lstat gate included): `gen = self._busy_begin_action("project_load", name)` (A12a-02). `name` is the listed spelling by then (`name = match`, G-B).
- (2) The rest of the function sits in `try: … finally: self._busy_fail("project_load", gen)`.
- (3) Step 1 `Check the files` is painted by the begin. It covers `build_variant_set`, `read_project_manifest`, `check_project_files` and the recorded variant.
- (4) Immediately before the `a2l_context` block, only when `a2l_files` is non-empty: `self.step_busy("project_load", gen, 2)` (A12a-09: the step is skipped when the project has no A2L; skipping a step is allowed).
- (5) The post-10 all-`None` refusal: `self.set_status(f"No supported files in project: {painted_names([name])}")` becomes `self.end_busy("project_load", gen, f"No supported files in project: {painted_names([name])}")`; the logger and `return` are unchanged. (This `painted_names` is the post-10 refusal's own scrub; it is not a progress label.)
- (6) Immediately before the image install loop (`while install.variant is not None:`): `self.step_busy("project_load", gen, 3)`.
- (7) After the loop and before `if install.mac is not None:`: `self.step_busy("project_load", gen, 4)`.
- (8) `self.set_file_status(safe_text(announcement.status_line()).plain)` keeps the base call and now stores the project and file line as the file state; `self.set_status(safe_text(announcement.summary_line()).plain)` becomes `self.end_busy("project_load", gen, safe_text(announcement.summary_line()).plain)` — the summary is the outcome, and the last end paints the stored file state (A12a-06). The INFO log and `update_project_labels()` follow the end.
- The image installs inside the run reach `set_file_status` through `_apply_prepared_load`, storing their file state; step (8)'s later write overwrites it with the project and file line.
callers: `_route_load_project` (baseline: direct :7478, inside post-10 `go`); 13 test files call it directly (post-10 census); `tests/b97_fixtures.load_project`, `tests/support/b100_projects` (:383, :613). All run inside `run_test` (census-noapp: `_load_p1` is called only from async tests).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.current_project] (replace, unchanged)
examples: A12-42 (LLR-176.2c success, LLR-176.1j, TC-B100-56 extension) project `P` (which holds an A2L, so step 2 is reported) → 1 begin (`Loading project P`); `step_busy` spy `[2, 3, 4]`; spy `[0, 25, 50, 75, 0]`; the log lines added are `['Loaded firmware.s19 (S19 only)', "Loaded project 'P' -> firmware.s19 - variant 1 of 1, 1 problem - details: p"]`; 1 effective end, whose outcome is the second line; `app._busy.file_state == "Loaded project 'P' -> firmware.s19"`; T reads `Loaded project 'P' -> firmware.s19`. `test_b100_announce.py:432` holds. Negative control: executed p12a U1.6 on base, spy `[]`, no progress line → RED for HLR-176c's begin / end count. A mutation that drops step (8)'s `set_file_status` → T reads `Loaded firmware.s19 (S19 only)` (the image install's file state) → RED (LLR-176.1j).
examples: A12-43 (LLR-176.2c failure after the begin) `A2LONLY` with `_load_a2l_data_with_cache` patched to raise `ValueError("synthetic")` (the post-10 read runs after the begin and is caught as an unreadable A2L) → spy `[0, 25, 0]`; `log_lines[-1] == "No supported files in project: A2LONLY"`; 1 effective end; T reads `Ready.` (the stored file state); the session is unchanged (post-10 C58 holds). Negative control: a mutation that drops this end → 1 run left → RED.
examples: A12-68 (A12a-09, a project with no A2L) a project holding only `firmware.s19` and `project.json` → the `step_busy` spy records `[3, 4]` (step 2 `Parse the A2L` is skipped), spy `[0, 50, 75, 0]`; 1 effective end. `Parse the A2L` is reported only when `a2l_files` is non-empty.
examples: A12-44 (no begin before the cheap refusals) `Q` holding only `project.json` → `Project NOT loaded: 'Q' has no data or A2L file — load a file and Save project.`, 0 begins, spy `[]` (holds on base for the line, p12a U1.7).
examples: A12-67 (A12a-02, no begin before the `project.json` gate) `P` whose `project.json` lstat raises `PermissionError` (monkeypatched) → the refusal line `Project NOT loaded: 'P' could not be read — check that the folder can be opened, then load again.`, no `Loading project P failed` end, 0 begins, spy `[]` (the begin sits after every refusal, the `project.json` lstat gate included).
examples: A12-45 (LLR-176.1l) `app._install_project_image` patched to raise `RuntimeError("forced")` → the spy records `("project_load", g, "Loading project P failed")` → `True`, then `RuntimeError` leaves `_handle_load_project`; spy `[0, 25, 50, 0]`; 0 active timers.
examples: A12-70 (overlap, A12a-06) a report run is held open (`gen_r = begin_busy("report", …)`), then `_handle_load_project("P")` → the project's end is not the last end, so nothing is painted yet; its step (8) stored `file_state = "Loaded project 'P' -> firmware.s19"`. When the report (the last run) ends, T reads `Loaded project 'P' -> firmware.s19` (the stored file state). The F-4 loss is gone: one stored file-state line, painted at the last end.

S19TuiApp._commit_project_save
req: LLR-176.2d, LLR-176.2c, LLR-176.1l, HLR-176c
in: _PreparedSave prepared; SaveProjectPayload payload
out: None
func: changed (post-11 body, from the 11 graph). Steps:
- (1) At entry, after the unpack of the crossing locals: `gen = self._busy_begin_action("save_project", prepared.cleaned)`. Step 1 `Create the folder` covers the `mkdir`.
- (2) The rest of the function sits in `try: … finally: self._busy_fail("save_project", gen)`.
- (3) First statement inside the existing rollback `try` (before `validate_project_files`): `self.step_busy("save_project", gen, 2)`. Step 2 `Place the files` covers the sub-folder copies, the rows loop, the top-level copies and the variant rebuild.
- (4) Immediately before `gather_outcome = gather_project_artifacts(…)`: `self.step_busy("save_project", gen, 3)`.
- (5) Immediately before `manifest_previous: Optional[bytes] = None` (the SEC7-3 keep and `_write_and_verify_manifest`): `self.step_busy("save_project", gen, 4)`.
- (6) Each of the 10 abort exits (7 inside the `try`, 3 `except … return` arms; finding F-12) replaces its one `self.set_status(<text>)` with `self.end_busy("save_project", gen, <text>)` at the same place. `_abort_save` and its rollback lines, the `notify` and the logger are unchanged and follow it. The log stays line-for-line the same (finding F-7: a rollback that leaves files writes its note after the outcome, as today).
- (7) The committed tail: the conditional writes (`Saved project to …`, the kept note, the document lines, `Manifest verify MISMATCH`) are appended in the same order to a local `tail: list[str]`. Then `for line in tail[:-1]: self.set_status(line)` and `self.end_busy("save_project", gen, tail[-1])`, before `self.current_project = cleaned`. `tail` always holds the `Saved project to` line.
- (8) The SEC-7 `except Exception: _abort_save(…); raise` is unchanged; the outer `finally` ends the run with `Saving project <name> failed` before the exception leaves (ruling Q8: 12a guarantees only the end).
- A refused save returns in `_handle_save_dialog` before this function, so it never begins.
callers: `_handle_save_dialog` (post-11 router step 6). One no-app test reaches it (`tests/test_tui_app.py::test_save_project_writes_under_workarea`, census-noapp), census A9.
module: s19_app/tui/app.py
modify: [I/O: work area]
examples: A12-46 (LLR-176.2d, LLR-176.2c success; the boundary "no MAC and no A2L") case_01's `firmware.s19` loaded alone, `_handle_save_dialog(SaveProjectPayload(str(W), "S1"))`:
  - the begin spy records `("save_project", "Saving project S1", ("Create the folder", "Place the files", "Gather the project files", "Write project.json"))`;
  - the `step_busy` spy records `[("save_project", g, 2), ("save_project", g, 3), ("save_project", g, 4)]`, each once and in order;
  - 1 effective end, with `f"Saved project to {W / 'S1'} (variant 'firmware')"`;
  - spy `[0, 25, 50, 75, 0]`;
  - the log lines added are `['Project saved + manifest verified', f"Saved project to {W / 'S1'} (variant 'firmware')"]`;
  - T reads what it read before the save.
  Result 1 sequence equality plus 4 assertions. Negative control: executed p12a U1.9 / P12a-1 on base, no progress call in the save, 0 steps → RED.
examples: A12-47 (LLR-176.2d, the refused arm) `SaveProjectPayload(str(W), "")` and `SaveProjectPayload(str(W), "temp")` (a reserved name) → `Project NOT saved: name is empty — type a project name.` and `Project NOT saved: 'temp' is a reserved name — choose another name.`, 0 begins each (2 of 2).
examples: A12-48 (LLR-176.2c failure after the begin) `place_into_workarea` patched to raise `OSError(28, "synthetic no space")` → 1 effective end with `Project NOT saved: could not save — [Errno 28] synthetic no space. check the folder.`; spy `[0, 25, 0]`; `W/S2` does not exist; 1 toast titled `Project not saved`; `log_lines[-1]` equals the outcome (the rollback left nothing, so it wrote no note). Holds on base for the line and the rollback (p12a U1.10).
examples: A12-49 (LLR-176.1l, SEC-7) `gather_project_artifacts` patched in the app module to raise `RuntimeError("forced")` → `_abort_save` runs, the `end_busy` spy records `("save_project", g, "Saving project S3 failed")` → `True`, then `RuntimeError` leaves `_handle_save_dialog`; spy `[0, 25, 50, 0]`; `W/S3` was removed by the rollback; 0 active timers (4 of 4).
examples: A12-51 (the tail outcome) a save whose manifest verify reports a mismatch (`_last_manifest_verify_result.status != MANIFEST_VERIFIED`) → `tail == [f"Saved project to {W/'S4'} (variant 'firmware')", "Manifest verify MISMATCH"]`; the end's outcome is `Manifest verify MISMATCH`, and `log_lines[-1]` is the same, as on base (R2-5 holds).
examples: A12-50 (TC-B100-07 census) `test_tc_b100_07_ast_census_every_post_creation_return_removes`, re-pinned at Inc 11 to read `_commit_project_save`, still holds: every `return` after the first `mkdir` follows an `_abort_save` call, and exactly 1 `except OSError` follows the `mkdir`. The outer `try` / `finally` adds 0 returns and 0 `except OSError`.

styles.tcss `#workspace_status_bar #status_text.-busy`
req: LLR-176.1 (the look, ruling Q9)
in:
out: one rule
func: changed (`styles.tcss`, inside the persistent status-bar block `:532`–`:615`, after `#workspace_status_bar #status_text` at `:572`): `#workspace_status_bar #status_text.-busy { color: $accent-calm; }` (fixed Q-6). `begin_busy` adds the class and the last `end_busy` removes it. No snapshot cell paints a running action, so no SVG moves. Proposal P-3 adds `text-wrap: nowrap;` to this same rule.
callers: Textual CSS.
module: s19_app/tui/styles.tcss
examples: A12-26 above. While a run is shown, `T.styles.color` equals the `$accent-calm` colour `#91abec`. After the last end, it equals `$fg-base` (2 of 2).

## Context nodes (unchanged)

- `S19TuiApp.set_progress`: body and signature kept (`value, message=None`). The seam calls it positionally with one argument, so the class-level spies (`test_report_off_ui_thread`, `test_before_after_report`) and the one-argument lambda (`_drive_worker`) see every value. Its callers become `begin_busy`, `step_busy` and `end_busy` only.
- `S19TuiApp.set_status`: unchanged; `end_busy` writes the outcome through it.
- `S19TuiApp.compose`: unchanged. A12-25 (LLR-176.1s): idle and during a held run, at 118×54 the `#progress_bar` region height is 1 / 1 and `#log_line_1` is at y 47 / 47; at 80×24 they are 1 / 1 and 17 / 17 (probe ga-long idle rows; probe p12a U3.4). That is 2 sizes × 2 assertions. Negative control: declared RED only as a mutation, because base holds. A mutation that hides the bar when idle (`display: none` without a run) → `#log_line_1` moves up 2 rows → RED.
- `S19TuiApp._apply_prepared_load`: unchanged; its `set_file_status` stores `file_state` while a run exists (A12-30, A12-42).
- `S19TuiApp.load_selected_file`: unchanged. It is not a long action at 12a; the work-area image pick (`_load_workarea_file`) runs no begin. A12-73: a pick of `W/temp/x.s19` with no run → 0 begins and T reads `Loaded x.s19 (S19 only)` at once. The same pick while a report is held open → T keeps the report's line and the file state is stored until the report ends (finding F-11).
- `S19TuiApp._handle_save_dialog` (post-11): unchanged. A refused save returns before `_commit_project_save` (A12-47).
- `S19TuiApp._route_load_project` (post-10), `on_report_viewer_screen_generate_requested`, `painted_names`: unchanged.

## Entities

[Data: S19TuiApp._busy]
desc: the progress indicator's whole run state (fixed S-b, simplified A12a-06); one app attribute, main thread only. `runs` in begin order (newest last, the shown run), `last_gen`, `file_state`, `timer`, `frame`. Classified in `SNAPSHOT_EXCLUSIONS` (A12-74). Inc 12b reads `runs` only.
sequence:
  workerLoad: load_from_path → _busy_begin_action → begin_busy (runs={file_load}, timer started) → step_busy 2 → _start_load_worker (thread) → call_from_thread step_busy 3 → call_from_thread _apply_prepared_load → set_file_status (file_state) → call_from_thread _sync_loaded_file_to_project → call_from_thread end_busy (outcome logged; runs={}; timer stopped; T=file_state) → expect none (no _busy_fail on success)
  parseFails: _start_load_worker → _parse_loaded_file raises → call_from_thread _handle_load_error → set_status "Load failed: …" → end_busy "Load failed" (T=file_state) → expect none (no _busy_fail)
  workerRaises: _start_load_worker → call_from_thread _apply_prepared_load raises → except BaseException call_from_thread _busy_fail → end_busy "<label> failed" → raise → WorkerFailed
  overlap: begin_busy report → begin_busy file_load (shown) → step_busy report (stored, not painted) → end_busy file_load (report shown, timer kept) → end_busy report (T=file_state)
  restart: begin_busy file_load (g1) → begin_busy file_load (g2, 1 entry) → end_busy file_load g1 → expect none (False; the outcome is logged)
  mainThreadAction: _commit_project_save → begin_busy → step_busy 2, 3, 4 → end_busy (tail) → finally _busy_fail → expect none

[UI: #status_text]
desc: one row. While a run exists only the seam paints it (HLR-176d); `set_file_status` writes store `file_state`. The last end paints the stored `file_state`.
sequence:
  idleFileState: _apply_prepared_load → set_file_status → T painted at once, file_state stored
  busyFileState: _apply_prepared_load → set_file_status → file_state stored (T unchanged) → last end_busy → T = file_state
  projectLine: _handle_load_project → set_file_status(status line) → file_state = project and file line → end_busy → T = project and file line

[UI: #progress_bar]
desc: written only by `set_progress`, called only by the seam. The begin sets 0, steps set `int(100 * (n - 1 + fraction) / m)` for the shown run, and the last end sets 0 (the start-up row).
sequence:
  report: begin_busy 0 → step_busy 2 → 50 → end_busy → 0

[UI: status log]
desc: the begin and steps write nothing. Each end writes its outcome (one line) through `set_status`, even for a run whose generation was replaced (the log is history). Result lines that came before the last stay `set_status` calls before the end.

## Callers and what changes for each

Each row is checked against the baseline's `> callers (extractor)` note for that node; values passed to `call_from_thread` are listed from P12a-1 and a code read.

| Node | Baseline callers (extractor / code read) | After 12a |
|---|---|---|
| `set_progress` | 12 functions, 24 sites (11 direct, 13 as `call_from_thread` values) | `begin_busy`, `step_busy`, `end_busy` only (A12-29) |
| `set_file_status` | `_handle_load_project` :11942, `_apply_prepared_load` :15464 | `_apply_prepared_load`, `_handle_load_project` (the project and file line, stored as `file_state`) |
| `load_from_path` | `_load_path_from_user_input` :12942 (post-10 in `go`); `_handle_select_variant` :7606 | unchanged |
| `_start_load_worker` | `load_from_path` :13071 | unchanged, plus `gen=`; Inc 12b adds `_load_workarea_file` |
| `_handle_load_error` | value at :15742, :15745 | unchanged, plus `gen` |
| `load_a2l_from_path` | `_load_path_from_user_input` :12939; `_load_from_item` :13333 (post-9b `_load_workarea_file`); post-10 `go` | unchanged |
| `action_before_after_report` | key `b`, save-back control; tests `test_report_off_ui_thread` :100, :272 | unchanged |
| `_start_before_after_worker` | `action_before_after_report` :4875 | unchanged, plus `gen=` |
| `_trigger_generate_report` | `on_report_viewer_screen_generate_requested` :5460; test `test_b100_recents` :1742 | unchanged |
| `_start_generate_report_worker` | `_trigger_generate_report` :5565; test `_drive_worker` :109 | plus `gen=`; the helper is re-pinned (A12-76) |
| `_finish_generate_report` | value at :5719; test `test_report_progress` :127 | plus `gen`; the test is re-pinned (A12-77) |
| `on_ab_diff_panel_report_requested` | Textual dispatch | unchanged |
| `_start_diff_report_worker` | `on_ab_diff_panel_report_requested` :6909 | unchanged, plus `gen=` |
| `_handle_load_project` | `_route_load_project` :7478; 13 test files; `b97_fixtures`, `b100_projects` | unchanged |
| `_commit_project_save` | `_handle_save_dialog` (post-11; no code, extractor not run) | unchanged; 1 no-app test re-pinned (census A9) |
| `begin_busy` | NEW | `_busy_begin_action`; tests |
| `_busy_begin_action` | NEW | the 7 actions above |
| `step_busy`, `end_busy` | NEW | listed in their nodes |
| `_busy_fail` | NEW | 3 main-thread `finally` blocks, 1 kickoff `except`, 4 worker `except BaseException` blocks |
| `_busy_tick` | NEW | the one timer |

## Census additions (to the baseline's A1–A8)

| # | Test | After 12a | Disposition |
|---|---|---|---|
| A9 | `tests/test_tui_app.py::test_save_project_writes_under_workarea` (:58) | it calls `_handle_save_dialog` on an app that was never run (census-noapp: the only sync test of 4 hits; the other 3 are helpers called inside `run_test`). The begin's `query_one("#status_text")` raises `NoMatches` → RED | re-pin: run it inside `app.run_test()` (proposal P-5). The rest of Inc 12b Q6's no-app conversion is 12b's. |
| A2 | `test_report_progress.py::test_kickoff_sets_bar_in_progress_before_worker` | as baseline A2 | re-pinned as A12-75 |
| A1, A3 | `test_report_progress.py` :49, :118 | as baseline | re-pinned as A12-77 |
| A6, A7 | `test_tui_report_attribution._drive_worker` | as baseline | one helper edit, A12-76 |

Held, by reading against this design: `test_report_progress.py::test_failed_report_resets_progress_bar_to_zero` (`[0, 50, 0]` → 0); `test_report_off_ui_thread.py::test_ac3_…` (`[0, 0]`); `::test_ac2_diff_generators_run_off_the_ui_thread`; `test_tui_report_attribution.py::test_tc572_…` (A12-54); `test_tui_variants` `_parse_loaded_file` census; `test_tui_diff_screen._b78_press_report` (it waits on `panel.set_status`, which runs after the end). Reads of T while a worker still runs are owed at E4 (E2 rulings).

## Seams with G-B (same file, `app.py`), by id

| Id | Where | G-B side | G-A side (this design) | Rule |
|---|---|---|---|---|
| X-1 | `_handle_load_project` (interface S-k) | the listing block: `_listed_project_name(name)`, the refusal sentences from `_TYPED_REFUSAL_TOKENS`, `name = match` | the begin immediately before `build_variant_set`, the steps 2–4, the two ends, the `try` / `finally` | E4 order G-B first. G-A's begin uses `name` after G-B's match, so the label carries the listed spelling. G-A's `try` re-indents the body after the begin only, not G-B's block. |
| X-2 | `_load_workarea_file` (S-i) | the pick-time `lstat` / size gate inside `go` (after the Inc 10 question); `not a regular file` / `too large to open` lines | none: its A2L arm reaches `load_a2l_from_path` (begins `a2l_load`), its data arm reaches `load_selected_file` (no run at 12a) | a refused pick paints its line before any begin (the re-check runs inside `go`, after the question), so 0 begins (G-B's TC-B100-39 arms can assert `app._busy.runs == {}`) |
| X-3 | `refresh_files` (S-h) | the `recent_kind` filter | called between the begin and the end of `load_a2l_from_path`, in `_post_worker_launch` during a file-load run, and after the Save end | it writes no status line and no T, so it adds no seam event |
| X-4 | `_typed_load_route` / `_load_path_from_user_input` (S-j) | the path refusal (EACCES / ENAMETOOLONG / NUL) → `("refuse", "not found")` | `load_from_path` begins only after the router chose `data` | a refused typed text never begins |
| X-5 | `BINDINGS` (S-l) | `Load` / `Projects` labels | the action table's labels (`Loading {name}`, …) | distinct strings; TC-B100-66 scans both sets (G-A: 7 labels, 18 step names, `<label> failed`; G-B: 2 token pairs) |
| X-6 | `__init__` / `SNAPSHOT_EXCLUSIONS` | no new attribute | `self._busy` and its exclusion line (A12-74) | G-B adds no `self.` attribute (confirm at E4) |
| X-7 | `set_status` from G-B refusals | refusal lines at any time | while a run exists they go to the log only; T keeps the progress line | no conflict; a G-B test that reads T after a refusal reads `Ready.` or the file state when no run exists |
| X-8 | test files | `test_b100_recents.py`, `test_b97_key_bar.py`, `test_b100_load_dialog.py` | `tests/test_b100_busy.py` (new), the re-pins above | no shared test file except TC-B100-66's scan in `test_b100_load_dialog.py` |

## What Inc 12b consumes (checked; `interfaces-12a.md` §"What Inc 12b consumes" stays true)

| 12b need | Served by this design |
|---|---|
| S-a busy check over `self._busy.runs`, newest last, painted label | `begin_busy` step (3) and `_BusyRun.label` (A12-20, A12-22) |
| S-b requests carry `gen` | `_busy_begin_action` returns it; the 4 workers take `gen=` keyword-only (A12-69) |
| S-c quit-after-end check inside `end_busy` | the check belongs in `end_busy`'s effective branch, at the point where no session run remains (node step 5) (A12a-07) |
| S-d `exit_on_error=False` + body `except` | the `except BaseException` → `_busy_fail` → re-raise guard; a second end is a no-op (A12-72) |
| S-f byte callback → `step_busy(key, gen, n, done, total)` | clamp and the rising fraction (A12-07, A12-08); `a2l_load` / `project_load` step 2 are the parse steps |
| LLR-176.3 main-thread step paints before its work | `step_busy` paints synchronously; `a2l_load` step 3 and `project_load` step 4 |
| LLR-177.5a per-file Save step | `save_project` step 2 with `done` / `total` |
| A3 `set_file_status(line)` then `end_busy(...)` | A12-42 (A12a-06) |
| C4 data pick → `_start_load_worker` with step 2 at once | step 1 can be skipped; `step_busy(…, 2)` right after the begin is valid (A12-05 form) |

No 12b signature changes. P-1's `_busy_fail` is available to 12b's handlers but is not required.

## Findings

finding F-1 (S-e concretised, no signature change) a worker action's main-thread kickoff cannot use `finally`
anchor: S19TuiApp.load_from_path
seen: S-e gives the main-thread form as `try: … finally: end_busy(…)`. In `load_from_path` the run outlives the function: the worker ends it. A `finally` there would end the run with `<label> failed` on every normal return, before the worker parses.
decision: the kickoff guard is `except BaseException: self._busy_fail("file_load", gen); raise` (A12-71). The three main-thread actions (A2L load, project load, Save project) keep `finally`; the four worker bodies use `except BaseException` + re-raise (S12a-06). Proposal P-7 records the wording.

finding F-2 (requirement text) HLR-176b's numbers contradict LLR-176.1c
anchor: S19TuiApp.step_busy
seen: HLR-176b: "step 2 reports 1, 2, 3 and 4 MiB of 4 MiB → the bar reads 50, 62, 75, 87". LLR-176.1c's formula `floor(100 × (n − 1 + done / total) / m)` gives 62, 75, 87, 100 for those reports. 50, 62, 75, 87 belongs to 0, 1, 2, 3 MiB.
decision: designed to LLR-176.1c (A12-07: the step's own 50, then 62, 75, 87, 100, rising 4 times). Proposal P-2 corrects HLR-176b's threshold. Without it, HLR-176b's threshold is infeasible as written.

finding F-3 (requirement boundary, executed) a long progress line wraps instead of taking the ellipsis
anchor: styles.tcss `#workspace_status_bar #status_text`
seen: probe ga-long on the base app: a 221-character T wraps to region height 3 inside the 1-row `#status_line` at 118×54 and at 80×24. The visible row ends in spaces, with no `…`, because `text-overflow: ellipsis` applies only with `text-wrap: nowrap`. With `text-wrap: nowrap` set (probe ga-long-nowrap) the height is 1 and the row ends `xx…`. Also, T is 59 columns wide at 80×24 (idle region `(2, 14, 59, 1)`), and the case_01 file-load line is 69 characters, so at 80×24 the step's end and the elapsed time are cut even with a short name.
decision: LLR-176.1's boundary "clipped by the `#status_text` ellipsis, never wrapped" cannot hold under the fixed Q-6 rule. Proposal P-3 adds `text-wrap: nowrap;` to that one rule (still one rule, ruling Q9). The 80-column cut of the elapsed time is declared (risk R-6). The thresholds read the label text, not the screen.

finding F-4 (gap under the fixed S-a) a non-last end drops its final line — resolved by A12a-06
anchor: S19TuiApp.end_busy
seen: S-a used `final_line` only at the last end. At 12a the project load runs on the main thread while a report worker may run (reports overlap, 12b Q2). The project load then ends while the report runs, and the project and file line was lost (A12-70).
decision: A12a-06 removes the three hand-back slots (`restore` / `pending` / `final_line`) for one `file_state`. `set_file_status` always stores it and the last end paints it, so A12-70 now shows the project line. The gap disappears; P-4 is superseded.

finding F-5 (test method) the timer count falls only after a pause
anchor: S19TuiApp.end_busy
seen: probe ga-timer: after `Timer.stop()`, `len(app._timers)` is still 1 in the same frame and 0 after one `pilot.pause()` (the `WeakSet` drops the timer after its cancelled task is collected). `t._task is None` is true at once.
decision: the examples count active timers as `_task is not None` (immediate) and the `WeakSet` length after a pause. S-f's "app._timers … falls by 1 at the last end" holds after a pause.

finding F-6 (test method) the injected clock must not span an `await`
anchor: S19TuiApp._busy_line
seen: patching `s19_app.tui.app.time.monotonic` patches `time.monotonic` itself (`app.time` is the module). Textual's own clock (`textual._time`) binds `monotonic` by name and is unaffected, but asyncio's `loop.time()` reads `time.monotonic` at each call, so a patched clock during an `await` moves the event loop's timers.
decision: A12-13 patches only around a synchronous `_busy_line` call on an app that is not running.

finding F-7 (declared) lines after the outcome that are not the action's own
anchor: S19TuiApp._start_load_worker / load_a2l_from_path / _commit_project_save
seen: with a project open, `_sync_loaded_file_to_project` / `_sync_loaded_a2l_to_project` write `Added variant …`, `Project '…' now opens …` or `… sync rejected: …` after the load's outcome, as they do after `Loaded <name>` today. A Save rollback that leaves files writes its `Not removed after the failed save: …` note after the outcome, as today.
decision: the file-load half is removed by A12a-05 (`_sync_loaded_file_to_project` runs before `end_busy`). The A2L sync (`_sync_loaded_a2l_to_project`) and the Save rollback note stay after the outcome; the log stays line-for-line the same there. HLR-176c's 14 arms (A12-30 … A12-64) run with no project open and with a clean rollback, so `log_lines[-1]` equals the outcome in each.

finding F-8 (test method) the status log clips lines
anchor: S19TuiApp.set_status
seen: `_append_log_line` keeps `trimmed[:max(50, width)]` (p12a U1.9 / U1.16 show clipped paths).
decision: "the log's last line is the outcome" compares against `outcome.strip()[:max(50, app.size.width)]`.

finding F-9 (census) one no-app test turns RED
anchor: S19TuiApp._commit_project_save
seen: census-noapp finds 1 sync test that reaches a begin with no running app: `test_tui_app.py::test_save_project_writes_under_workarea`. The other 3 hits (`_load_p1`, `_save_project`, `_save_loaded_project`) are helpers called only inside `run_test`.
decision: census row A9, re-pin inside `run_test` (P-5). The seam gets no "no app" branch, which would be a production branch only tests reach (12b ruling Q6).

finding F-10 (exception rule) nothing that can raise sits between a kickoff's begin and its dispatch
anchor: S19TuiApp.action_before_after_report
seen: the dispatch's argument `self._active_project_dir()` (path resolution) would be evaluated after the begin, and a raise there would leave a run with its timer and no end.
decision: computed before the begin. The report and diff kickoffs already pass locals only.

finding F-11 (declared) a synchronous image pick during a report waits for the report
anchor: S19TuiApp.set_file_status
seen: the work-area image pick is not a long action at 12a (Inc 12b moves it to the file-load worker). If a report runs, the pick's file state is stored (LLR-176.1h) and is painted only when the report ends.
decision: by design (HLR-176d: one owner of T). A12-73.

finding F-12 (count) the Save commit has 10 abort exits
anchor: S19TuiApp._commit_project_save
seen: interfaces S-n / the baseline name "15 exits (11 abort returns, 3 except returns, the committed tail)". In the base body (`:9856`–`:10605`) there are 11 `_abort_save` calls: 7 in-`try` returns, 3 `except … return` arms and the SEC-7 re-raise. That makes 10 returns.
decision: 10 abort ends plus the tail end plus the `finally` for the SEC-7 re-raise and for raises outside the rollback `try` (`mkdir` errors other than `FileExistsError`, the committed tail).

finding F-13 (declared, HLR-176a) three actions are invisible at 12a
anchor: load_a2l_from_path / _handle_load_project / _commit_project_save
seen: they hold the main thread from begin to end, so no frame shows their line.
decision: their examples use spies (begin, steps, ends, bar values). HLR-176a's thresholds use worker actions only (E1 declared exception).

## Proposals to the orchestrator

- **P-1 (additive private helpers).** `S19TuiApp._busy_fail(key, gen) -> bool` builds the S-e failure outcome `<run.label> failed` on the main thread, and `S19TuiApp._paint_status_text(text)` is the seam's one painter of T (and its one scrub choke point, S12a-02). No fixed signature changes. Without `_busy_fail`, each worker `except BaseException` guard needs the label off-thread: the three report rows can use their static table label, but the file-load worker would need a second `painted_names` call (against Q-2) or a different failure text such as `Load failed`. Without `_paint_status_text`, the seam repeats `query_one("#status_text", Label).update(…)` 5 times.
- **P-2 (HLR-176b threshold, F-2).** Replace "→ the bar reads 50, 62, 75, 87 within step 2, rising 4 times" with "→ the bar reads 50 at the step's start, then 62, 75, 87, 100, rising 4 times, never falling".
- **P-3 (the one CSS rule, F-3).** `#workspace_status_bar #status_text.-busy { color: $accent-calm; text-wrap: nowrap; }`. It is still one rule (ruling Q9), it applies the existing `text-overflow: ellipsis` while a line is shown, and it moves no SVG (no snapshot paints a running action). Without it, LLR-176.1's boundary must change to "clipped by the `#status_line` row (wrapped inside a 1-row container)".
- **P-4 (non-last end, F-4).** Superseded by A12a-06: with one stored `file_state`, a non-last end needs no `final_line` hand-over; the project line is stored and painted at the last end (A12-70). No code from this proposal is taken.
- **P-5 (census row A9, F-9).** Add `tests/test_tui_app.py::test_save_project_writes_under_workarea` to E1 §D.3 / the tester's re-pin list: run it inside `app.run_test()`.
- **P-6 (S-a clarification).** When `runs` is empty at a begin, also `frame = 0`. Otherwise the first begin after an earlier action paints whatever frame the last tick left, and LLR-176.1's `⠋` holds only for the first action of a session.
- **P-7 (S-e wording, F-1).** "A main-thread kickoff that hands its run to a worker guards the code after its begin with `except BaseException: <failure end>; raise`, not `finally`."
- **No other interface change.** The seam signatures, `_BusyRun` / `_BusyState`, the 7-row table, `_busy_begin_action`, the `gen=` keyword-only worker parameters, `end_busy -> bool` and the Q-6 rule text are used as fixed.

## Design risks

- **R-1 (re-indent).** The `try` blocks re-indent the bodies after the begin: about 750 lines of `_commit_project_save`, about 270 of `_handle_load_project`, about 80 of `load_a2l_from_path` and about 60 of each worker. Behaviour is unchanged apart from the listed lines. Reviewers use `git diff -w`, and TC-B100-07, the 57 Save direct calls and the 13 project-load test files are the guard.
- **R-2 (worker `except BaseException` at shutdown).** If the app is already closing, the `except BaseException` guard's `call_from_thread` can raise `RuntimeError` and hide the worker's own exception. This was not probed. Inc 12b's body-level `except` (S-d) narrows it.
- **R-3 (float floor).** `int(100 * (n - 1 + fraction) / m)` can land 1 below an exact integer for some `done / total` (for example `0.3 * 100 / 1`). The thresholds use binary-exact fractions (quarters of 4 MiB, thirds of an index). E4 may switch to the integer form `100 * ((n - 1) * total + done) // (m * total)` if a test needs it; it gives the same values for the examples.
- **R-4 (reads of T while a worker runs).** A test that reads T between a begin and an end now sees the progress line. The census of such reads among the 29 files that name `status_text` is owed at E4 (E2 rulings).
- **R-5 (failure-path round trip only).** Each worker run posts the `_busy_fail` cross-thread call only on the exception path (S12a-06); the success path has no extra no-op post.
- **R-6 (80 columns).** At 80×24 the progress line is cut before the elapsed time (F-3). The text tests pass; the visible elapsed time needs a width of about 70 columns for T.
- **R-7 (open runs in stubbed tests).** A test that stubs a worker leaves its run and timer open until the app exits (A12-75). Textual stops every timer at exit.
- **R-8 (P-1, P-3, P-6 pending; P-4 superseded).** The design assumes P-1 and P-6. If P-1 is rejected, the fallback is named there. If P-6 is rejected, A12-01's `⠋` holds only from a fresh app. P-4 is superseded by A12a-06.

## Platform notes

No Windows-only arm. The probes ran on Windows. Every path in the examples is built with `Path` (`W / 'S1'`), so the texts follow the platform's separator.

## Requirement coverage (G-A)

| Requirement | Examples |
|---|---|
| HLR-176 | A12-01, A12-35, A12-37 |
| HLR-176a | A12-09, A12-37 |
| HLR-176b | A12-07 (finding F-2, P-2) |
| HLR-176c | A12-30 … A12-34, A12-38 … A12-49, A12-53 … A12-66 (the 14 arms below) |
| HLR-176d | A12-36, A12-14 |
| LLR-176.1 | A12-01, A12-02, A12-03 |
| LLR-176.1a | A12-04 |
| LLR-176.1b | A12-05, A12-06 |
| LLR-176.1c | A12-07 |
| LLR-176.1d | A12-08 |
| LLR-176.1e | A12-09, A12-10, A12-11 |
| LLR-176.1f | A12-12, A12-11 |
| LLR-176.1g | A12-13 |
| LLR-176.1h | A12-14, A12-73 |
| LLR-176.1i | A12-15 |
| LLR-176.1j | A12-16, A12-42 |
| LLR-176.1k | A12-17, A12-18, A12-77 |
| LLR-176.1l | A12-33 (file load), A12-40 (A2L), A12-45 (project), A12-49 (Save), A12-56 (report), A12-62 (diff), A12-66 (before/after), A12-71 (kickoff) |
| LLR-176.1m | A12-19, A12-72 |
| LLR-176.1n | A12-20 |
| LLR-176.1o | A12-21 |
| LLR-176.1p | A12-22 |
| LLR-176.1q | A12-23 |
| LLR-176.1r | A12-24 |
| LLR-176.1s | A12-25 |
| LLR-176.2 | A12-28 |
| LLR-176.2a | A12-29 |
| LLR-176.2b | A12-27 |
| LLR-176.2c (14 arms) | file load A12-30 / A12-31; A2L A12-38 / A12-39; project A12-42 / A12-43; A12-67 (project.json refusal, 0 begins); A12-68 (no-A2L project skips step 2); Save A12-46 / A12-48; report A12-53 / A12-54; diff A12-58 / A12-59; before/after A12-63 / A12-64 |
| LLR-176.2d | A12-46, A12-47, A12-48 |
| LLR-178.2 (TC-B100-56 extension) | A12-42, A12-70 |
| LLR-173.7 (TC-B100-66 extension, G-A strings) | A12-27 |
| AT-B100-17 (12a half) | A12-37 |
| Census re-pins (A1, A2, A3, A6, A7, A8, A9) | A12-77, A12-75, A12-76, A12-74; A9 in "Census additions" |

The examples not written out above:
- A12-20 (LLR-176.1n): `gr = begin_busy("report", "Generating the project report", ("Prepare the results", "Write the report"))`; `step_busy("report", gr, 2)` (bar 50); then `gl = begin_busy("file_load", "Loading x.s19", S)` → T reads `<glyph> Loading x.s19  ·  step 1/3 Copy into the work area  ·  00:00` and the bar is 0 (2 assertions). Then `step_busy("report", gr, 2, 3, 4)` → T and the bar are unchanged (1 assertion). Boundary with 3 overlapping runs (add `before_after`): the newest is shown, and ending it shows `file_load` again. Negative control: a mutation that keeps the first run shown → T keeps the report's line → RED.
- A12-22 (LLR-176.1p): `g1 = begin_busy("file_load", "Loading a.s19", S)`; `step_busy("file_load", g1, 2)`; `await pilot.pause(1.1)` (T shows `step 2/3 Parse  ·  00:01`); `g2 = begin_busy("file_load", "Loading b.s19", S)` → T reads `<glyph> Loading b.s19  ·  step 1/3 Copy into the work area  ·  00:00`, `len(app._busy.runs) == 1` and `g2 == g1 + 1` (2 assertions plus 1). Boundary: `end_busy("file_load", g1, "x")` → `False` (A12-19 (c)). Negative control: a mutation that keeps both entries → 2 entries → RED.
- A12-29 (LLR-176.2a, AST over post-12a `app.py`): `set_progress` referenced outside `begin_busy`, `step_busy` and `end_busy` (a call, or an `Attribute` passed to `call_from_thread`) → 0. `query_one("#progress_bar"…)` outside `set_progress` → 0 (`compose` constructs the widget and does not query it) (2 assertions). Negative control: executed P12a-1, 24 references outside any seam → RED.

**G-B only** (no G-A node): LLR-173.2m, LLR-172.4e, LLR-172.4f, LLR-172.5i, LLR-172.5j, LLR-172.5k, LLR-172.6b, LLR-172.6c, and the G-B strings of TC-B100-66.

**G-A requirements left uncovered: none.**

**Infeasible as written:** HLR-176b's threshold numbers (F-2, P-2) and LLR-176.1's 200-character boundary under the fixed Q-6 rule (F-3, P-3). Everything else is feasible in `app.py` plus the one rule.
