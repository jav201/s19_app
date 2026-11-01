# Inc 12a — proposed interfaces between G-A (the indicator) and G-B (the labels and the sweep), and the seam Inc 12b consumes

PROPOSED by the E2 baseline. The orchestrator fixes it as `interfaces-12a.md`; a group never changes an interface alone. Both groups edit `s19_app/tui/app.py`; G-A may add one rule to `s19_app/tui/styles.tcss` (ruling Q9). Base: main `8947666` plus the fixed interfaces of Inc 9b (`../../inc-9b-design/codewire/interfaces-9b.md`), Inc 10 (`../../inc-10-design/codewire/interfaces-10.md`) and Inc 11 (`../../inc-11-design/codewire/interfaces-11.md`). Evidence ids (`p12a Un.m`) are lines of `probe-p12a.out.txt`; `P12a-n` are the E1 probes in `../work/`. Node names are those of `baseline-12a.md`.

G-A and G-B share no function: G-A owns the seam, the action table and the 12 functions of P-29 plus `set_file_status`, `_handle_load_project`'s begin / end and `_commit_project_save`; G-B owns `BINDINGS`, `list_projects`, `refresh_files`, `_typed_load_route`, `_load_path_from_user_input`, `_load_workarea_file`, the new `_listed_project_name`, and `_handle_load_project`'s listing match and two refusal sentences. The one function both groups edit is `_handle_load_project` (S-k): G-B's edit is the listing block (`:11709`–`:11739`), G-A's edit is the begin after it and the end at its exits. They run in sequence (E1 rulings, "Sequencing"), G-B first, so G-A's begin sits after G-B's call of `_listed_project_name`.

```python
# app.py (G-A) — the seam. Main thread only; a worker reaches it through call_from_thread.
BusyKey = Literal["file_load", "a2l_load", "project_load", "save_project", "report", "diff_report", "before_after"]

@dataclass(frozen=True)
class _BusyAction:                       # S-c: one row of the action table
    label: str                           # English template; "{name}" is replaced by painted_names([name])
    steps: tuple[str, ...]               # >= 1 English step names, in order

_BUSY_ACTIONS: Mapping[BusyKey, _BusyAction] = { ... }      # S-c, 7 rows, values below
_BUSY_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"                              # S-f, 10 frames
_BUSY_TICK_SECONDS = 0.1                                     # S-f

@dataclass
class _BusyRun:                          # S-b: one running action (mutable, main thread only)
    gen: int                             # >= 1, unique per begin
    label: str                           # painted label (already scrubbed)
    steps: tuple[str, ...]
    n: int                               # current step, 1-based, clamped to 1..len(steps)
    fraction: float                      # 0.0..1.0 within step n
    started: float                       # time.monotonic() at the begin

@dataclass
class _BusyState:                        # S-b: the whole run state, ONE app attribute (self._busy)
    runs: dict[BusyKey, _BusyRun] = field(default_factory=dict)   # insertion order = begin order; the LAST item is the shown run
    last_gen: int = 0
    file_state: str = "Ready."           # the one stored file-state line; the last end paints it (A12a-06)
    timer: Optional[Timer] = None        # the one 0.1 s interval timer, None when no run exists
    frame: int = 0

def begin_busy(self, key: BusyKey, label: str, steps: Sequence[str]) -> int: ...
def step_busy(self, key: BusyKey, gen: int, n: int, done: Optional[int] = None, total: Optional[int] = None) -> None: ...
def end_busy(self, key: BusyKey, gen: int, outcome: str) -> bool: ...
def _busy_tick(self) -> None: ...
def _busy_line(self, run: _BusyRun) -> str: ...          # G1: the pd_A text, plain str
def _busy_begin_action(self, key: BusyKey, name: Optional[str] = None) -> int: ...   # S-c helper: formats the table row, scrubs name, calls begin_busy

# app.py (G-B)
def _listed_project_name(self, name: str) -> Optional[str]: ...   # S-k, LLR-172.5j; OSError from list_projects() propagates
```

## Seams

- **S-a, the three seam functions (E1 S-a, kept; the return of `end_busy` added).**
  - `begin_busy(key, label, steps) -> int`:
    - `self._busy.last_gen += 1`; `gen = last_gen`.
    - If `self._busy.runs` is empty, `frame = 0` (so a first begin after an earlier action paints `⠋` again, P-6).
    - A run under the same `key` is removed first (LLR-176.1p: restart, 1 entry), then `runs[key] = _BusyRun(gen, label, tuple(steps), 1, 0.0, time.monotonic())` is inserted last, so it is the shown run (LLR-176.1n).
    - Paints `_busy_line(run)` into `#status_text` at once (`00:00`, step 1), `set_progress(0)` (LLR-176.1, .1a), adds the `-busy` class (S-g), and starts the timer when `timer is None` (`self.set_interval(_BUSY_TICK_SECONDS, self._busy_tick)`, LLR-176.1e: 1 timer however many runs).
    - Returns `gen`.
  - `step_busy(key, gen, n, done=None, total=None)`:
    - `runs.get(key)` missing or `.gen != gen` → return, nothing changed (LLR-176.1m).
    - Clamp (LLR-176.1d): `n` to `1 … len(steps)`; with `done` and `total` given: `total <= 0` → fraction `0.0`, else `min(max(done / total, 0.0), 1.0)`; no amount → `0.0`. Within the same step the fraction never falls (`max(old, new)` when `n` is unchanged).
    - Store `n` and `fraction`. Only when the run is the shown one (last in `runs`): repaint the line and `set_progress(floor(100 * (n - 1 + fraction) / len(steps)))` (LLR-176.1b, .1c).
  - `end_busy(key, gen, outcome) -> bool`:
    - `outcome.strip()` non-empty → `set_status(safe_text(outcome).plain)` (LLR-176.1i), written before the generation check (the log is history, not indicator state, A12a-04).
    - Unknown key or replaced generation → return `False`, nothing else changes (LLR-176.1m). So a second end for the same run is a no-op, and the exception rule (S-e) can always end in a `finally`.
    - Remove the run. If other runs remain: repaint the newest one's line and `set_progress` its value; the timer keeps running (LLR-176.1o).
    - If none remains (LLR-176.1f, .1j, .1k): stop the timer and set `timer = None`; remove the `-busy` class; `set_progress(0)`; paint `self._busy.file_state` (the one stored file-state line).
    - Returns `True`. A test spy counts effective ends with the return value (LLR-176.2c "exactly 1 end per arm").
  - All three run on the main thread. A worker calls `self.call_from_thread(self.step_busy, key, gen, n[, done, total])` and `self.call_from_thread(self.end_busy, key, gen, outcome)` (LLR-176.1q).
  - The seam calls `set_progress(value)` with no `message`, so the bar spies of §D.3 still see every bar value; whether the begin and step names also go to the status log is Q-3.
- **S-b, the run state: one attribute.** All state lives in `self._busy = _BusyState()`, set in `__init__`.
  - Reason: `tests/test_b100_session_reset.py::test_tc_b100_09_domain_matches_the_live_source_census` fails for every new `self.<name> =` in `S19TuiApp` until it is classified (Inc 11 hit it, proto-11-app B11-01). One attribute means one `SNAPSHOT_EXCLUSIONS` entry: `"_busy": "progress indicator run state; main-thread UI state, not session state (Inc 12a)"`.
  - The shown run is `next(reversed(self._busy.runs.values()))`. The mapping's order is the begin order, and a restart moves its key to the end.
  - **12b reads it as is** (12b S-a): `_refuse_if_busy()` walks `reversed(self._busy.runs.items())`, takes the first key in `{"file_load", "a2l_load", "project_load", "save_project"}`, and paints `busy: <run.label> is running — wait for it to finish.` 12b writes nothing in `_busy`.
- **S-c, the action table.** `_BUSY_ACTIONS` holds exactly 7 rows (LLR-176.2b). Proposed values (English, 0 decision ids, TC-B100-66):

  | key | label | steps |
  |---|---|---|
  | `file_load` | `Loading {name}` | `Copy into the work area`, `Parse`, `Install` |
  | `a2l_load` | `Loading {name}` | `Copy into the work area`, `Parse`, `Build the tag table` |
  | `project_load` | `Loading project {name}` | `Check the files`, `Parse the A2L`, `Parse the image`, `Install` |
  | `save_project` | `Saving project {name}` | `Create the folder`, `Place the files`, `Gather the project files`, `Write project.json` |
  | `report` | `Generating the project report` | `Prepare the results`, `Write the report` |
  | `diff_report` | `Writing the diff report` | `Write Markdown`, `Write HTML` |
  | `before_after` | `Writing the before/after report` | `Compose the report` |

  - The file-load row is exactly the TC-B100-50 example (`⠋ Loading x.s19  ·  step 1/3 Copy into the work area  ·  00:00`).
  - The step boundaries are real code boundaries: file load copy (main) / parse (worker start) / install (before `_apply_prepared_load`); A2L copy / parse / view build; project load reads / `_load_a2l_data_with_cache` / `_install_project_image` / install tail; Save project `mkdir` / rows loop and copies / `gather_project_artifacts` / `_write_and_verify_manifest` (the four phases of `_commit_project_save`, LLR-176.2d); report span 1 / span 2 (the 55 site); diff report Markdown / HTML (the 55 site).
  - 12b needs: an A2L parse step for the byte callback (`a2l_load` step 2, `project_load` step 2), a tag-table step painted before its work (`a2l_load` step 3, LLR-176.3), a project install step (`project_load` step 4, LLR-176.3), and a per-file placement step for the Save worker (`save_project` step 2, LLR-177.5a). Each row has them.
  - `_busy_begin_action(key, name=None)` is the only place that formats a label: `label = row.label.format(name=painted_names([name]))` when the row holds `{name}`, then `begin_busy(key, label, row.steps)`. It makes LLR-176.1r's "through the one scrub" one call site. A synthetic TC action calls `begin_busy` directly with its own label and steps.
- **S-d, the file state and the cleared bar (E1 S-d, simplified A12a-06).** The one stored file-state line is `self._busy.file_state`, initial `"Ready."`; the last end paints it, and the bar `set_progress(0)` (progress 0 of total 100, the start-up state, LLR-176.1k).
  - `set_file_status(message)`: always stores `self._busy.file_state = safe_text(str(message)).plain`; paints it only when `self._busy.runs` is empty (LLR-176.1h).
  - The project load keeps its base order: `set_file_status(safe_text(announcement.status_line()).plain)` stores the project and file line, then its `end_busy(..., safe_text(announcement.summary_line()).plain)` writes the outcome, and the last end paints the file state. TC-B100-56's "project and file line" then reaches `#status_text`.
- **S-e, the exception rule (E1 S-e, concretised).** Every action holds its body between the begin and a `finally` that ends with a failure outcome. Because a second end is a no-op (S-a), the `finally` needs no flag:
  - main thread: `gen = self._busy_begin_action(key, name)`; `try: <body, whose exits call end_busy with their own outcome> finally: self.end_busy(key, gen, f"{<label>} failed")`;
  - worker: the same `try` / `finally`, with the end posted through `self.call_from_thread(self.end_busy, key, gen, <failure outcome>)`.
  - At 12a this only guarantees the end runs first (ruling Q8). The re-raise stays: `load_a2l_from_path`'s parse raise and `_commit_project_save`'s SEC-7 re-raise still leave the action. Keeping the app alive is 12b's (LLR-177.2, 12b S-d `exit_on_error=False`).
  - The failure outcome text of the `finally` arm: `<label> failed` (for example `Loading firmware.a2l failed`). It is new text, written only on the exception path. Today the app ends there or leaves the bar mid-fill (p12a U1.5).
- **S-f, the line and the timer (pd_A, ruling Q9).**
  - `_busy_line(run)` = `f"{_BUSY_FRAMES[frame]} {run.label}  ·  step {n}/{m} {run.steps[n - 1]}  ·  {mm}:{ss:02d}"` with `elapsed = int(time.monotonic() - run.started)`, `mm = f"{elapsed // 60:02d}"` (minutes not capped at 59, LLR-176.1g), `ss = elapsed % 60`. A plain `str`; `#status_text` keeps `markup=False`.
  - `_busy_tick()`: `frame = (frame + 1) % 10`; repaint the shown run's line. Nothing else (no bar write).
  - Time source: `time.monotonic` read through the module (`time` is already imported, `app.py:11`), so a test patches `s19_app.tui.app.time.monotonic` for LLR-176.1g's injected clock.
  - Timer count: `app._timers` (Textual `WeakSet`, p12a U3.3: 0 at idle) rises by 1 at the first begin and falls by 1 at the last end. TC-B100-50 reads it (LLR-176.1e, .1f).
- **S-g, `styles.tcss` (ruling Q9: at most one rule).** Proposed: `#workspace_status_bar #status_text.-busy { color: $accent-calm; }`, inside the persistent status-bar block (`:532`–`:615`). It uses one of the 6 closed tokens and needs a selector more specific than `#workspace_status_bar #status_text` (`:572`). The seam adds the class at the begin and removes it at the last end. pd_A styles only the glyph and the elapsed time; a `Label` has no component classes, so the closest one-rule form tints the whole line. See Q-6. No snapshot cell paints a running action, so no SVG moves for this rule.
- **S-h, the loadable-suffix predicate (E1 S-f).** It is `recent_kind(path) is not None` (`workspace.py:2139`, read-only), the predicate 9b's `_load_dialog_rows` already uses (proto-9b-app N1 step 2). `refresh_files` filters `list_workarea_files(...)` through it (LLR-172.4f). No new function (E1 guess G2 dropped): the AST check of LLR-172.4f looks for `recent_kind` in both readers.
  - `recent_kind` maps `.s19 .srec .hex .ihex .mac .a2l`, case-folded, on Windows suffix rules (P12a-4). So `F.S19` is listed, and `d.a2l.json` and `e.txt` are not (p12a U2.1: 6 rows on base, 4 after).
- **S-i, the pick-time re-check (LLR-172.6b, .6c), in `_load_workarea_file` only.**
  - It replaces `candidate.exists()` by `st = os.lstat(candidate)`. `FileNotFoundError` keeps the silent return (9b B88). Any other `OSError` → `not a regular file` (fail closed).
  - `not stat.S_ISREG(st.st_mode) or _is_reparse_point(candidate)` → `File NOT loaded: '<pn(name)>' is not a regular file — pick another file.`
  - `st.st_size > workspace.DEFAULT_COPY_SIZE_CAP_BYTES` (read through the module at call time, as the 9b A2L admission does) → `File NOT loaded: '<pn(name)>' is too large to open — load a smaller file.`
  - Both checks run before the Inc 10 question, so a refused pick never asks. Both surfaces reach it: `_load_from_item` (`#files_list`) and the 9b router (`workarea` choice).
  - `_load_dialog_verdict` stays free of filesystem calls (9b B55). The `workarea` refusal is therefore a status line after the dialog closed, not `#load_reason`.
  - Two new token rows (E1 §D.2) and their text live in G-B. TC-B100-66 scans them.
- **S-j, the path refusal (LLR-172.5i).** `_typed_load_route` wraps its one `resolve_input_path(path, self.base_dir)` call (the post-9b shape, SEC9b-1) as `try: normalized = resolve_input_path(path, self.base_dir)` / `except (OSError, ValueError, RuntimeError): return ("refuse", "not found")`. The catch must never narrow below that tuple.
  - The NUL arms are regression arms, GREEN on the post-9b base: 9b's `except (ValueError, RuntimeError)` already returns `("refuse", "not found")` for a relative NUL and a symlink loop.
  - The RED arm is EACCES / ENAMETOOLONG: `Path.exists` monkeypatched to raise `PermissionError` / `OSError(errno.ENAMETOOLONG)` for the typed text → `("refuse", "not found")` with 0 exceptions, through the status-line route and the Load dialog's `#load_reason`.
  - The status-line route and 9b's verdict both go through the classifier, so this one change covers the arms.
- **S-k, the one project match (LLR-172.5j) and the one wording table (LLR-172.5k), G-B.**
  - `_listed_project_name(name) -> Optional[str]`: `next((e for e in self.list_projects() if os.path.normcase(e) == os.path.normcase(name)), None)`. An `OSError` from `list_projects()` propagates. `_handle_load_project` maps it to its `could not be read` line, and `_typed_load_route` maps it to `("refuse", "unreadable")`, as each does today.
  - The two shared project refusals read 9b's `_TYPED_REFUSAL_TOKENS`: `reason, step = _TYPED_REFUSAL_TOKENS["not a project"]` → `f"Project NOT loaded: '{t}' is {reason} — {step}."`; `reason, step = _TYPED_REFUSAL_TOKENS["unreadable"]` → `f"Project NOT loaded: '{t}' {reason} — {step}."`.
  - Painting sites: `_load_path_from_user_input` (2); `_handle_load_project`'s folder-unreadable arm (`:11694`), listing `OSError` arm (`:11716`), not-listed arm (`:11733`); and post-9b its `_list_project_files` catch and its `project.json` lstat gate. The texts are unchanged character for character, so TC-B100-38, -40 and -63 stay green. Census scope: Q-7.
- **S-l, the labels (LLR-173.2m), G-B.** `BINDINGS`: `Binding("ctrl+l", "load_file", "Load", priority=True)`, `Binding("l", "load_file", "Load", show=False)`, `Binding("p", "load_project", "Projects", show=False)`. `#ws_load_project_button` keeps `Load project (p)` (ruling Q6). The palette (`_build_palette_entries`), the key bar and the help panel follow the descriptions with no other code change.
- **S-m, the worker generation.** Each of the 4 worker bodies, and the two main-thread end sites they post to, take the run's generation as a parameter: `_start_load_worker(path, a2l_files=None, *, gen)`, `_start_before_after_worker(..., *, gen)`, `_start_generate_report_worker(..., *, gen)`, `_start_diff_report_worker(..., *, gen)`, `_handle_load_error(path, exc, gen)`, `_finish_generate_report(report_path, gen)`. A worker never reads `self._busy` (off-thread read). Default or required: Q-1.
- **S-n, where each begin sits (refusals before it paint no progress).**
  - `load_from_path`: after the not-found and suffix refusals, in place of `set_progress(10, …)`.
  - `load_a2l_from_path`: after the not-found, suffix and project-guard refusals, in place of `set_progress(10, …)`.
  - `_handle_load_project`: after the cheap refusals (folder check, not found, listing match, the `project.json` gate, the file listing, the A2L admission, no data or A2L), before the post-10 reads.
  - `_commit_project_save`: at its entry. The router's refusals return before it, so a refused save never begins (LLR-176.2d).
  - `_trigger_generate_report`, `on_ab_diff_panel_report_requested`, `action_before_after_report`: in place of `set_progress(15)`.
  - The reachable failure arm after the begin, per action (LLR-176.2c, executed on base unless stated):

    | action | failure arm after the begin | base trace |
    |---|---|---|
    | file load | parse raises → `_handle_load_error` | p12a U1.2 (bar 100) |
    | A2L load | `copy_into_workarea` refused (containment) | code read; same shape as p12a U1.3 |
    | project load | an A2L-only project whose A2L does not parse → `No supported files in project: <name>` (post-10: the A2L read and the all-`None` refusal run after the begin, before the reset) | proto-10-app C58 (executed by Inc 10's probe_sec_refuse); code read on base |
    | Save project | placement `OSError` after `mkdir` | p12a U1.10 |
    | report | generator raises | p12a U1.12 |
    | diff report | Markdown refused | p12a U1.14 |
    | before/after | composer refuses (nothing loaded) | p12a U1.15 |

## What Inc 12b consumes, unchanged (checked against `../../inc-12b-design/E1-rulings.md` and `E1-scope.md`)

| 12b need | 12a seam that serves it |
|---|---|
| S-a busy check over the run state; the newest session action's label | `self._busy.runs`, ordered, newest last; `_BusyRun.label` is already painted (S-b) |
| S-b requests carry `gen` | `begin_busy` / `_busy_begin_action` return it; workers take it as a parameter (S-m) |
| S-c quit-after-end check inside `end_busy` | the check belongs in `end_busy`'s effective branch, at the point where no session run remains, so every exit path (`_handle_load_error`, `_busy_fail` included) reaches it (A12a-07) |
| S-d `@work(thread=True, exit_on_error=False)` plus a body-level `except` | S-e's `finally` end still applies; a second end is a no-op |
| S-f byte callback → `step_busy(key, gen, n, done, total)` through `call_from_thread`, at most once per chunk | `step_busy` clamps and keeps the fraction rising within a step (S-a); `a2l_load` step 2 and `project_load` step 2 are the parse steps (S-c) |
| LLR-176.3: a main-thread step paints its name before its work | `step_busy` paints synchronously; 12b defers the work with `call_after_refresh`; `a2l_load` step 3 and `project_load` step 4 are those steps |
| LLR-177.5a: the Save worker advances the bar per file placed | `save_project` step 2 `Place the files`, reported with `done` / `total` |
| A3 `set_file_status(line)` then `end_busy(...)` from the project-load install handler | the `file_state` attribute (S-d, A12a-06) |
| C4 `_load_workarea_file` data arm → `_start_load_worker` in place | it begins `file_load` and calls `step_busy(…, 2)` at once (no copy step); nothing in 12a forbids a skipped step |

One seam rule 12b must keep (S12a-05): one exclusive worker group per busy key. Textual cancels a worker that has not reached `run_in_executor` before its body (and therefore its `finally` end) runs; a worker cancelled before it starts runs no `finally`, so the canceller must call `end_busy` itself. At 12a each worker group (`load`, `generate_report`, `diff_report`, `before_after_report`) maps to exactly one busy key. 12b keeps that, or uses a distinct group per key.

12b needs no change to these signatures.

## Open questions (one per undecided seam)

- **Q-1 (S-m), is the worker `gen` required?**
  - Option 1: keyword-only and required. Production always passes it. Tests that call a worker or `_finish_generate_report` directly get a `TypeError` until they begin a run first. That is 5 tests through one helper, `test_tui_report_attribution._drive_worker`, plus `test_report_progress::test_finish_generate_report_completes_bar`.
  - Option 2: default `gen=0` (never issued, so ignored). The direct calls run, but their steps and ends are silently dropped. That keeps a production branch that exists only for tests, which 12b ruling Q6 rejects.
  - Recommendation: option 1. One helper edit (`gen = app.begin_busy("report", "x", ("a", "b"))` before the worker call); the census rows below are re-pins either way.
- **Q-2 (S-c), where the label is formatted and scrubbed.** Option 1: `_busy_begin_action(key, name)` formats and scrubs, and the 7 sites call it. Option 2: each site formats `_BUSY_ACTIONS[key].label.format(name=painted_names([name]))` and calls `begin_busy`; that is 4 copies of the scrub. Recommendation: option 1 (one scrub site for LLR-176.1r; 7 callers, so it is not single-use).
- **Q-3 (S-a / S-c), which status-log lines the indicator owns.** Today the begin and step messages of `set_progress` go to the log (`Copying into workarea temp...`, `Parsing <name>...`, and their A2L twins: 4 lines per file or A2L load, p12a U1.1 / U1.4). Each action then writes its own result lines with `set_status`.
  - Option 1 (recommended): the seam writes no begin or step line; at each end site, the action's **last** status-log line today becomes the `outcome` passed to `end_busy`, and the action stops writing that line itself; any earlier result lines stay `set_status` calls before the end. Result:
    - file load: `Loaded <name>` (success) / `Load failed` (parse failure; `Load failed: <exc>` stays before it) / `Cannot load file: <exc>`;
    - A2L load: `A2L loaded: <name>` (the extra `Loaded <name>` set_progress line goes);
    - project load: the summary line (the project line is stored as the file state, A12a-06);
    - Save project: the last line of the committed tail or of the abort arm;
    - report: `Report: <dir>/<file>` / `Report failed: …` / `Report rejected: …`;
    - before/after: its one result line;
    - diff report: a new status-log line equal to the text it gives the panel (`Diff report written: …`, `Report refused: …`, …), because today it writes none (p12a U1.13, U1.14) and HLR-176c asks for the outcome in the log.
    - The last log line after every action is then the outcome (HLR-176c, 14 of 14), and the lines tests read with `log_lines[-1]` or `#log_line_4` after an action are unchanged (`test_b100_focus` reads `A2L loaded:` there 8 times).
  - Option 2: keep logging the begin and step names. Each step then adds a log line, and the 4-row log tail fills with step names during a long action.
  - Option 3: the outcome is only the old `set_progress` message (E1 glossary). The A2L load would end with `Loaded <name>` and then paint `A2L loaded: <name>` after the end, so the last log line is not the outcome.
  - Recommendation: option 1. The executed mutant M1 (baseline-notes "Census") measures the cost of dropping the begin and step lines.
- **Q-4 (S-a), `end_busy` returns `bool`.** E1 S-a has no return value. Returning `True` only for an effective end lets the `finally` end be unconditional and lets TC-B100-51 count "exactly 1 end per arm" without a second bookkeeping path. Recommendation: return `bool`. 12b's end handlers ignore it.
- **Q-5 (S-c), the step names.** LLR-176.2d says "E2 names them" (at least 3 for Save project). The table above is the proposal, chosen at the code boundaries each action already has, and so that 12b's byte callback, its tag-table / install steps and its per-file Save step each fall on one row. Confirm or rename. Renaming later costs only TC-B100-66 / -51 fixture strings.
- **Q-6 (S-g), the one `styles.tcss` rule.**
  - Option 1: `#workspace_status_bar #status_text.-busy { color: $accent-calm; }`. The whole running line is in the accent. That is near pd_A, inside the closed palette, and it moves no snapshot.
  - Option 2: no rule; the line paints in `$fg-base`, and the source stays at 1 file.
  - Option 3: a styled `Text` built in `app.py`. This needs a hex colour or a new token outside `styles.tcss`, which the closed palette forbids.
  - Recommendation: option 1.
- **Q-7 (S-k), the scope of LLR-172.5k's census.** The AST check "0 string literals of either reason outside the table, docstrings excluded" would, read literally, count:
  - the classifier's reason keys (`return ("refuse", "not a project")`, 3 sites);
  - the logger messages (`"Project load refused (could not be read): %r"`);
  - the A2L refusal word (`a2l_reason = "could not be read"`, `:11762`);
  - the Save refusals (`_handle_save_dialog`, `_plan_project_save`, `_unrecorded_document_lines`) (p12a U4.1).
  - Recommendation: the census counts painted **Load** refusal sentences only. Scope: functions on the Load path (`_handle_load_project`, `_load_path_from_user_input`, `_typed_load_route`), string literals that reach `set_status`; reason keys, logger arguments and the A2L-specific sentence (its step token differs) are excluded by name in the TC. Alternative: named constants for the reason keys (`_REASON_NOT_A_PROJECT`), which touches 3 more return lines for no behaviour.

## Census consequences the orchestrator should see with these seams

- **E1 §D.3 says the spies "still see every value", and only `test_report_progress.py:49` is re-pinned. That is not enough.** By reading the assertions against S-a (the begin writes 0, the end writes 0, no step writes 100), these turn RED:
  - `test_report_progress.py::test_report_generation_drives_progress_bar_to_100` (bar 100 → 0);
  - `test_report_progress.py::test_kickoff_sets_bar_in_progress_before_worker` (`0 < p < 100`, and the begin writes 0);
  - `test_report_progress.py::test_finish_generate_report_completes_bar` (direct call; 100 → TypeError under Q-1 option 1, or 40 under option 2);
  - `test_before_after_report.py::test_at_038a_saveback_trigger_report_pair_reread_from_surfaced_path` (`progress[-1] == 100`);
  - `test_report_off_ui_thread.py::test_ac4_diff_progress_never_sticks_mid_fill` (success arm `[-1] == 100`);
  - `test_tui_report_attribution.py::test_at263_pin_progress_resets_to_zero_on_both_branches`, and under Q-1 option 1 the other 4 tests of `_drive_worker`.
- **TC-B100-09** (`test_b100_session_reset.py::test_tc_b100_09_domain_matches_the_live_source_census`) is RED until `_busy` is classified (S-b).
- **Labels:**
  - `test_b97_key_bar.py` `GLOBAL_TEXTS` / `GLOBAL_TEXTS_80`;
  - `test_tui_diff_screen.py::test_at_b78_32_app_bindings_block_is_untouched` — already RED on base: its frozen rows say `Load` / `Save` for `ctrl+l` / `ctrl+s`, the code says `Load file` / `Save project`. 12a makes the `ctrl+l` row match, and moves the `l` and `p` rows;
  - `test_tui_patch_history_strip.py::test_tc081_4_no_binding_diff` (the `l` and `p` Binding lines need sanctioned markers);
  - the 29 SVG files, regenerated only through `.github/workflows/snapshot-regen.yml`.

  Details and the full list are in `baseline-notes.md` "Census".

## Orchestrator rulings (2026-10-31): this file is now FIXED

The orchestrator owns this file. A prototype group proposes changes and never edits an interface alone.

- **Q-1:** the worker `gen` is keyword-only and required. Re-pin the one test helper.
- **Q-2:** one helper, `_busy_begin_action(key, name)`, holds the single `painted_names` call.
- **Q-3:** begin and step write no log line. At each end, the action's final status line is the `outcome` written to the log, even for a run whose generation a later begin replaced (the log is history, not indicator state; the generation check governs only the indicator). The diff report gains one log line.
- **Q-4:** `end_busy` returns `bool`.
- **Q-5:** the step names in the 7-row table are confirmed, including the steps 12b needs.
- **Q-6:** one rule, `#workspace_status_bar #status_text.-busy { color: $accent-calm; }`.
- **Q-7:** LLR-172.5k's census counts only painted Load refusal sentences.
- **Outcome definition** (this resolves the A2L contradiction): the outcome is the action's last painted status line, so `A2L loaded: x` for an A2L load. The glossary "last `set_progress` message" is corrected to this, and HLR-176c then holds with `test_b100_focus` unchanged.
