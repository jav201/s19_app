# Code-Wire graph — Inc 3 (Save project margin; a vanished project folder), batch-101

Stage E2 of the design-first flow (`dev-flow-v3-beta`). Graph only: no stub, mark or declaration in any tree. Base `e266395`; the test nodes build on the tree after Inc 2's merge (branch `b101-inc2`). Requirements `../01-requirements.md`, slice `../E1-slice.md`, cases `../02-test-cases.md`, profile `../E1-profile.md`.

E3 round 1 corrections (`../E3-rulings.md`) carry the finding id in brackets. Line numbers are `e266395`'s; origin/main `f11b3f4` moved `app.py`, `workspace.py` and `screens.py` lines without changing any node below (`../E1-slice.md` §0).

How to read it:
- One file holds the baseline and the prototype. Every node's `func:` starts with **unchanged**, **changed** (then "was: … / now: …", the baseline first) or **new**. Unchanged nodes are context: a changed node calls them, or they call it.
- Example sources are the test-case ids of `02-test-cases.md`; `P` = a probe of the base tree run at E1 (scripts and transcripts under `evidence/inc-3/`, named in the line). Every example states the Inc 3 target unless it says "holds on base" or "base:".
- "T2" = the T2 composition of `01-requirements.md` Definitions. "Lines since" = the status lines painted after the trigger (Inc 2's `StatusLog.since(mark)`).

Groups for E4 (file ownership) and the interfaces they share — pinned here, changed only by an orchestrator ruling:

| Group | Files | Owns nodes |
|---|---|---|
| G1 product | `s19_app/tui/services/project_gather_service.py`, `s19_app/tui/app.py` | `gather_project_artifacts`, `S19TuiApp._sync_loaded_file_to_project`, `S19TuiApp._sync_loaded_a2l_to_project` |
| G2 timing clocks (tests) | `tests/test_b100_project_check.py` | `_paint_clock_start`, `_watch_panel_paint` (new), `_timed_load_panel_and_append`, `_sec6_5_filesystem_scene`, the 2 panel arm bodies, `_StampObserver` (new), the R-TST-110 … 113 nodes. Rule [F9]: each edited existing function keeps its `report_margin` call count, and no bound moves into a new helper (Inc 2's R-TST-049 guard fires on a gained call) |
| G3 product tests | `tests/test_project_gather.py`, `tests/test_b100_workers.py`, `tests/test_b100_active_variant.py` | the R-PROJ-* nodes of `E1-slice.md` §2 |

| Interface | Pinned form | Producer → consumers |
|---|---|---|
| I-1 the gather's contract | `gather_project_artifacts(project_dir: Path, *, composition_names: Sequence[str] = (), active_document: Optional[Path] = None, active_document_kind: str = "change", active_template: Optional[Path] = None, common_patches_dir: Path, common_templates_dir: Path, workarea_root: Path) -> GatherOutcome` — unchanged signature. The outcome is unchanged except for four inputs [F5, N-2]: repeated names (one check, one finding per missing name; E1-D3); a link loop at a name (looked up in the common library; R-PROJ-GATHER.13); and, on POSIX, a `..` after a link in a name (judged on the lexically folded path, as the manifest writer and Windows judge it; E1-D8). A `..` over a missing folder keeps its base answer through the fold. Fourth [N-2]: a name `resolve()` rejects with `ValueError`, such as an embedded NUL (base raises; now one `GATHER-SOURCE-MISSING` finding, then the writer refuses the entry and the save ends with R-PROJ-ROLLBACK.9's line, the same shift as the link loop; no test owed) | G1 → `_save_project_files`, G3 |
| I-2 the sync refusal texts | `Project sync NOT done: project '<painted project name>' could not be read — check that the folder can be opened, then load again.` and the same with `A2L sync NOT done:` — canon R-PROJ-002.12/.13, built from `_TYPED_REFUSAL_TOKENS["unreadable"]` as today | G1 → G3 |
| I-3 the install stamp | `app._load_returned_at: float`, set by the arm's wrapper of `_install_prepared_project` right after the real install returns (as today) | G2 internal |
| I-4 the panel paint stamp | `_watch_panel_paint(app) -> list[tuple[float, int]]`: a list the helper appends `(stamp, problem_rows)` to, once; installed before the click [F3, F4] | G2 internal |
| I-5 the outcome-line stamp | the scene's existing `set_status` capture (`_capture`, `app._statuses`) also records `time.perf_counter()` at the first line holding `was not rewritten` or `manifest verified` after the append's trigger | G2 internal |
| I-6 the margin recorder [F2] | the verifier replaces the module attribute `tests.test_b100_project_check.report_margin` (monkeypatch) with `_record(label, measured, bound)`. It appends `(label, measured)` to a list and returns `real_report_margin(label, measured, bound)`, so QC-TM keeps its rows and the bound object is the same | G2 internal (verifier → arms) |
| I-7 the stamp observer [F2] | `_StampObserver.install(monkeypatch) -> _StampObserver`: class-level wrappers on `S19TuiApp` (`monkeypatch.setattr(S19TuiApp, …)`), installed before the arm builds its app. Fields `install: float?` (after `_install_prepared_project` returns), `paint: float?` (its own subscription to the pushed `LoadResultScreen`'s signal, first publish with a summary height), `append_start: float?` (entry of `load_from_path`, the last one before the outcome line), `outcome: float?` (first `set_status` with `manifest verified` or `was not rewritten` after `append_start`). It never reads `_watch_panel_paint`'s list, `app._load_returned_at` or `app._statuses` | G2 internal (verifier only) |

Order inside E4: G1 and G3 in parallel (G3 proves RED on base first); G2 independently. No interface crosses G1 and G2. E4 entry check [F9]: Inc 2's merge commit is an ancestor of `origin/main`. Out of the slice, must not change [S-1]: `manifest_writer._reject_unsafe_entry`, `variant_execution_service._EntryWalk`, `variant_execution_service._entry_text`.

## Entities

[Data: project folder]
desc: the open project's folder on disk, `S19TuiApp._active_project_dir()` (`current_project_dir`, else `workarea / current_project`)

[Data: S19TuiApp.status]
desc: the status line; `set_status` paints it and Inc 2's `StatusLog` records every painted line

[Data: GatherOutcome]
desc: `gathered` rows, `issues` (findings, logged by the caller), `written`, `created_homes`, `active_document`, `unrecorded`

[Interface: Load-result panel]
desc: `LoadResultScreen`, pushed by `_install_prepared_project` on a routed load; its summary is `#result_summary`; Textual publishes its `screen_layout_refresh_signal` after each layout and screen refresh

## Nodes

gather_project_artifacts
req: R-PROJ-001.13, R-PROJ-GATHER.12, R-PROJ-GATHER.13
in: Path project_dir; Sequence[str] composition_names = (); Path? active_document = None; str active_document_kind = "change"; Path? active_template = None; Path common_patches_dir; Path common_templates_dir; Path workarea_root
out: GatherOutcome outcome
func: changed. was: for each composition name, in order and with repeats, `in_project = (resolved_project / name).resolve()`; `in_project.is_file()` → already home, skip; else the common library by bare name, else one `GATHER-SOURCE-MISSING` issue. now: a name whose exact text was already checked in this call is skipped (a set of seen texts, first occurrence kept, order unchanged) [F11]; the check is `Path(os.path.normpath(resolved_project / name)).is_file()`, with `.` and `..` folded lexically [F5] and no `resolve()`. `is_file()` follows links itself and returns False for a link loop (ELOOP, WinError 1921), so such a name falls to the common-library lookup by `Path(name).name`. Other `OSError`s still propagate, as at base (S-3, backlog). Limbs 2a/2b (active document, template), the de-duplication by resolved source in `_schedule`, the copies and the outcome are unchanged.
module: s19_app/tui/services/project_gather_service.py
modify: outcome (append)
examples: (R-PROJ-GATHER.12/1) T2 project folder; composition_names = the 1 000 chain names + the same 1 000 again → `1000` project-folder checks; outcome.gathered `{}` and outcome.issues `[]` (all 1 000 already home) — base: `2000` checks, each with a `resolve()` (P: `R1-P1-cprofile-callers-e266395.txt`, 2 001 `resolve` calls from this function)
examples: (R-PROJ-GATHER.12/2) empty project, empty library; composition_names ["gone.json", "gone.json"] → `1` check; outcome.issues holds `1` `GATHER-SOURCE-MISSING` issue with text "gather: composition document 'gone.json' resolved to no file in the project or the common patches library — skipped" — base: `2` such issues
examples: (R-PROJ-GATHER.12/3) project holds `x.json`, no folder `missing`, empty library; composition_names ["missing/../x.json"] → `1` check, on `<project>/x.json`; outcome.gathered `{}`, outcome.issues `[]` (already home; the same answer as base on both platforms) [F5]
examples: (R-PROJ-GATHER.13/1) Windows; project folder holds a junction loop `x.json`; library holds `x.json` (change document); composition_names ["x.json"] → returns, no exception; outcome.gathered {"patches": ["patches/x.json"]} — base: raises `RuntimeError` "Symlink loop from '…\x.json'" (P: measured on a junction loop at E1, `E1-profile.md` §1.3) [F1]
examples: (R-PROJ-GATHER.13/2) POSIX; `os.symlink("x.json", <project>/x.json)`; library and names as /1 → returns, no exception; outcome.gathered {"patches": ["patches/x.json"]} — base: `RuntimeError` (Python 3.11/3.12 `resolve()` on the loop) [F6]
examples: (R-PROJ-001.13/1) T2 save through `_save_project_files` → the whole Save project, confirm → `Project saved + manifest verified`, in 0.65–0.74 s alone on the E1 host (P: `R1-P1-node-experiments.txt`, the `gather` + `isfile` rows, applied as runtime wrappers) — base: 1.11–1.33 s
examples: (holds on base) composition_names ["boost.json"], `boost.json` only in the library → outcome.gathered {"patches": ["patches/boost.json"]} (the existing `test_tc699_common_change_set_is_gathered_into_project_patches` keeps passing)

S19TuiApp._save_project_files
req: R-PROJ-001.13, R-PROJ-ROLLBACK.9, R-PROJ-ROLLBACK.2
in: SaveRequest request
out: SaveOutcome outcome
func: unchanged (context). The Save worker step: C1 folder creation, the plan's rows, `gather_project_artifacts(project_dir, composition_names=list(batch) + [assignment names], …)` at `app.py:11848`, then `_write_manifest_for_save` (serialize with the SEC6-5 refusal predicate, write, verifying re-read). Its time at T2 is R-PROJ-001.13's interval minus the handler (0.16–0.20 s) and the commit (about 0.01 s).
module: s19_app/tui/app.py
examples: (R-PROJ-001.13/1) T2 request → outcome whose lines lead to the status `Project saved + manifest verified`; worker step 0.83–1.16 s on base (P: `R1-P1-marks-e266395.txt`), about 0.45 s less with the gather change
examples: (R-PROJ-ROLLBACK.9/1) Windows; P with a junction loop `x.json` at its top level, library `x.json`; request batch ("x.json",) → the gather copies `patches/x.json`; `serialize_manifest` refuses the batch entry (`MANIFEST-WRITE-ESCAPE` "refusing to serialize manifest batch entry that is absolute or escapes the project directory: 'x.json'", executed by the E3 probes); outcome lines include `Project NOT saved: could not save — project.json was not written. check the folder.`; no line holds `an unexpected error stopped the save` — base: the gather raises and the lines hold `Project NOT saved: could not save — an unexpected error stopped the save. check the folder.` [F1, S-1]
examples: (R-PROJ-ROLLBACK.2/1) the same request, P without `patches/` before the save → after `_abort_save`, `<P>/patches/x.json` and `<P>/patches` do not exist (the gather's `written` and `created_homes` reach the rollback through `placed_files` / `created_dirs`)

S19TuiApp._sync_loaded_file_to_project
req: R-PROJ-002.12, R-PROJ-002.14
in: S19TuiApp self
out: None
func: changed. was: inside the SE5-12b-2 `try`, `project_dir.mkdir(parents=True, exist_ok=True)` then `validate_project_files(project_dir)`; a deleted folder is re-created, read as empty, and the S19/HEX/MAC is placed into it with a fresh project.json. now: the `mkdir` line goes; `validate_project_files(project_dir)` raises `FileNotFoundError` on a deleted folder (and `NotADirectoryError` on a file in its place, as before) and the existing `except OSError` paints the canon refusal and returns. Nothing else changes.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.status] (replace)
examples: (R-PROJ-002.12/2) P2 open, its folder deleted, `load_from_path(other.s19)` → lines since hold `Project sync NOT done: project 'P2' could not be read — check that the folder can be opened, then load again.` exactly `1` time; last line `Loaded other.s19` — base: `Added variant 'other' to project 'P2'` and the folder exists again
examples: (R-PROJ-002.12/3) as /2 with `other.hex` → the same refusal line `1` time
examples: (R-PROJ-002.12/4) as /2 with `other.mac`, P2 without a MAC file → the same refusal line `1` time
examples: (R-PROJ-002.12/1) a regular file `P2` in the folder's place → the same refusal line `1` time (holds on base: `mkdir` raises `FileExistsError` there)
examples: (R-PROJ-002.12/5) as /1 with `other.hex` → the same refusal line `1` time
examples: (R-PROJ-002.12/6) as /1 with `other.mac` → the same refusal line `1` time
examples: (R-PROJ-002.14/1) as R-PROJ-002.12/2 → after the load, `os.path.lexists(<work area>/P2)` `False` — base: `True`
examples: (R-PROJ-002.14/2) as R-PROJ-002.12/3 → `False`
examples: (R-PROJ-002.14/3) as R-PROJ-002.12/4 → `False`

S19TuiApp._sync_loaded_a2l_to_project
req: R-PROJ-002.13, R-PROJ-002.14
in: S19TuiApp self
out: None
func: changed. was: inside the SE5-12b-2 `try`, `project_dir.mkdir(parents=True, exist_ok=True)` then `validate_project_files(project_dir)`. now: the `mkdir` line goes; a folder gone since the attach's request-time guard raises `FileNotFoundError` in `validate_project_files` and the existing `except OSError` paints the canon refusal and returns.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.status] (replace)
examples: (R-PROJ-002.13/2) P2 (no A2L) open; the folder deleted inside the attach worker after the request-time guard → lines since hold `A2L sync NOT done: project 'P2' could not be read — check that the folder can be opened, then load again.` exactly `1` time; `0` lines `A2L NOT loaded: …`; last line `A2L loaded: firmware.a2l` — base: the A2L is copied into a re-created `P2`
examples: (R-PROJ-002.13/1) `validate_project_files` raises `PermissionError` from this function only → the same line `1` time (holds on base)
examples: (R-PROJ-002.14/4) as R-PROJ-002.13/2 → `os.path.lexists(<work area>/P2)` `False` after `A2L loaded: firmware.a2l`

validate_project_files
req: R-PROJ-002.12, R-PROJ-002.13
in: Path project_dir
out: tuple(list[Path] data_files, list[Path] a2l_files, str? error)
func: unchanged (context). Lists `project_dir.iterdir()`; the listing raises `FileNotFoundError` for a missing folder and `NotADirectoryError` for a file. The two syncs rely on that raise once their `mkdir` is gone.
module: s19_app/tui/workspace.py
examples: (R-PROJ-002.12/2) a path whose folder was deleted → raises `FileNotFoundError` (holds on base when called without the sync's `mkdir`)

S19TuiApp.load_a2l_from_path
req: R-PROJ-002.13
in: Path path; bool copy = True
out: None
func: unchanged (context). Its request-time project guard (`app.py:15202-15217`) refuses a folder that is already gone with `A2L NOT loaded: project '<name>' could not be read — …`, so R-PROJ-002.13's deleted alternative is reached only when the folder goes during the attach worker.
module: s19_app/tui/app.py
examples: (R-PROJ-002.13/2) folder deleted before the call → `A2L NOT loaded: project 'P2' could not be read — check that the folder can be opened, then load again.` (holds on base; not this increment's case, it shows why /2 deletes mid-attach)

_paint_clock_start
req: R-TST-110
in: S19TuiApp app; float pressed
out: float start
func: changed. was: `max(pressed, getattr(app, "_load_returned_at", pressed))`. now: `app._load_returned_at` (the install stamp); `pressed` stays a parameter for its callers and is not read. A missing stamp is a test failure (`AssertionError("the project install callback did not run")`), never a silent fall-back to `pressed`.
module: tests/test_b100_project_check.py
examples: (R-TST-110/1) app with `_load_returned_at` `10.0`, pressed `12.0` → start `10.0` — base: `12.0`
examples: (R-TST-110/1b) app with `_load_returned_at` `12.0`, pressed `10.0` → start `12.0` (holds on base)

_watch_panel_paint
req: R-TST-111
in: S19TuiApp app
out: list[tuple[float, int]] stamps
func: new. Wraps the instance's `push_screen`. When the screen pushed is a `LoadResultScreen`, it subscribes the app (a running node; subscribing the screen raises `SignalError` before mount) to that screen's `screen_layout_refresh_signal` with `immediate=True`. The callback runs on every publish, once per layout pass, not per frame. The callback takes `time.perf_counter()` first [N-3]. The first time `screen.query_one_optional("#result_summary")` is not `None` and that widget's `size.height > 0` (never `query_one`: the signal can fire before the summary is mounted [F3]; E4 integration replaced the `query` length check with this id lookup, which does not walk the 1 000 rows, see `E4-integration-notes.md` S-1), it appends `(that stamp, len(screen.query("#result_body .result-problem")))` [F4, OR-3], and never appends again. Returns `stamps` (empty until the paint). `Signal.publish` swallows callback exceptions (`log.error`), so a failing callback leaves `stamps` empty: each caller asserts it is non-empty with the message `the Load-result panel was never laid out with a summary` [F3]. Public Textual API only (E1-D6). Caveat [F3]: outside a `batch_update` the publish follows the pass's screen refresh; inside one it precedes the deferred refresh. `s19_app/tui` has no `batch_update` today. Diagnosed on `textual==8.2.8`; re-check on a bump.
module: tests/test_b100_project_check.py
modify: stamps (append)
examples: (R-TST-111/1) all-bad scene, installed before the click → after the panel paints, `stamps` holds `1` item whose stamp equals the first layout pass's end within 0.001 s (P: `painted-step-marks.txt`, `signal_painted` = `layout_first_end` in 8/8 runs) and whose row count equals the panel's final `.result-problem` count
examples: (R-TST-111/1b) a push of any other screen → `stamps` stays `[]`
examples: (R-TST-111/1c) a publish before `#result_summary` is mounted → nothing appended, no exception; the next publish with a height appends

test_tc_b100_61_every_array_at_the_cap_all_bad_opens_under_one_second
req: R-TST-110, R-TST-111, R-TST-113
in: Path tmp_path
out: None
func: changed (body only, name kept). was: `painted = time.perf_counter() - _paint_clock_start(app, pressed)` after `_wait_for` notices `#result_summary` with a height. now: `stamps = _watch_panel_paint(app)` before the click; the wait stays as the precondition that the panel exists (Inc 2's `wait_until` form); `assert stamps, "the Load-result panel was never laid out with a summary"` [F3]; `painted = stamps[0][0] - _paint_clock_start(app, pressed)`; `assert stamps[0][1] == rows` (the rows were in the stamped layout) [F4]; bound `report_margin("TC-B100-61 all-bad painted", painted, timing_bound(1.0))` unchanged and still the only `report_margin` call for it [F9]; rows bound unchanged.
module: tests/test_b100_project_check.py
examples: (R-TST-111/1) all-bad scene → `painted` 0.17–0.42 s, < `1.0` (P: `painted-step-marks.txt`, stamped column) — base: 0.75–1.07 s by the poll in the same runs

test_tc_b100_61_files_at_the_cap_all_missing_are_bounded
req: R-TST-110, R-TST-111, R-TST-113
in: Path tmp_path
out: None
func: changed (body only, name kept). The same clock change and the same [F3]/[F4] asserts as the all-bad arm; label `TC-B100-61 cap painted`; bound unchanged.
module: tests/test_b100_project_check.py
examples: (R-TST-111/3) cap scene → `painted` equals stamp difference within `0.001` s; < `1.0`

_timed_load_panel_and_append
req: R-TST-110, R-TST-111, R-TST-112
in: Pilot pilot; S19TuiApp app; Path source
out: tuple(float painted, int rows, float appended)
func: changed. was: `painted` from `_paint_clock_start` to when `_wait_for` notices the panel; `appended` from just before `app.load_from_path(source)` to when `_wait_for` notices an outcome line in `app._statuses`. now: `painted` = panel paint stamp (`_watch_panel_paint`, installed by the scene before the click; non-empty assert and row-count assert as in the all-bad arm [F3, F4]) − install stamp; `appended` = outcome-line stamp (I-5) − the moment just before `app.load_from_path(source)`; both waits stay as preconditions.
module: tests/test_b100_project_check.py
examples: (R-TST-112/1) distinct-folders scene → `appended` 0.59–0.96 s, < `1.0` (P: `appended-poll-vs-stamp.txt`, stamped column) — base: 0.87–1.14 s by the poll
examples: (R-TST-111/2) distinct-folders scene → `painted` equals the stamp difference within `0.001` s

_sec6_5_filesystem_scene
req: R-TST-111, R-TST-112, R-TST-113
in: Path tmp_path; dict payload; (Callable) Path->None setup = None
out: dict scene
func: changed. was: `_capture` appends each status line to `app._statuses`. now: `_capture` also records the outcome-line stamp (I-5) once per append; the scene installs `_watch_panel_paint(app)` before the panel is opened and passes the stamps to `_timed_load_panel_and_append`. The scene dict keeps its keys (`read`, `load`, `painted`, `rows`, `appended`, `problems`, `manifest`); `_assert_sec6_5_bounded` keeps its 4 bounds at `timing_bound(1.0)`.
module: tests/test_b100_project_check.py
examples: (R-TST-112/1) the first status holding `manifest verified` or `was not rewritten` after the append's trigger → stamp recorded `1` time; lines painted before the trigger (the panel load's) record nothing

_StampObserver
req: R-TST-111, R-TST-112
in: pytest.MonkeyPatch monkeypatch
out: _StampObserver observer
func: new [F2]. `install` wraps 4 methods at class level with `monkeypatch.setattr(S19TuiApp, name, wrapper)`, before the arm builds its app, so the arm's instance wrappers call through them: `_install_prepared_project` (stamp `install` after the real call returns); `push_screen` (for a `LoadResultScreen`, its own app subscription with `immediate=True`, stamping `paint` at the first publish with a summary height, by the same rule as `_watch_panel_paint`, written separately); `load_from_path` (stamp `append_start` at entry); `set_status` (stamp `outcome` at the first line holding `manifest verified` or `was not rewritten` after `append_start`). It shares no list or attribute with the arm.
module: tests/test_b100_project_check.py
modify: observer (replace)
examples: (R-TST-111/1) all-bad arm run under the observer → `install` and `paint` set; `paint - install` within `0.001` s of the arm's recorded `painted` (the two wrappers nest; E1 measured the stamps' spread in microseconds)
examples: (R-TST-112/1) distinct-folders scene → `append_start` and `outcome` set; `outcome - append_start` within `0.001` s of the recorded `appended`
examples: (R-TST-111/1d) no `LoadResultScreen` pushed → `paint` stays `None` and the verifier fails with `the observer saw no panel paint`

test_r_tst_111_112_arm_values_equal_the_product_stamps
req: R-TST-111, R-TST-112
in: pytest.MonkeyPatch monkeypatch; Path tmp_path; str scene
out: None
func: new [F2], parametrized `scene` in `all-bad`, `cap`, `scene`; marked `serial_timing`, because it reaches the arms' bounds through the arms, so Inc 2's census reads it as a timing arm. It installs I-6 and then I-7, and runs the scene once: the arm function itself for `all-bad` and `cap`; `_sec6_5_filesystem_scene` on the distinct-folders payload followed by `_assert_sec6_5_bounded` for `scene`. It then asserts, per label recorded through I-6, `math.isclose(recorded, observer difference, abs_tol=0.001)`: `TC-B100-61 all-bad painted`, `TC-B100-61 cap painted` or `sec6_5 painted` against `paint - install`; `sec6_5 appended` against `outcome - append_start`. The comparison is `math.isclose`, not an ordering assert, so Inc 2's margin guard (R-TST-041) does not read it as a raw timing bound. It adds no `report_margin` call.
module: tests/test_b100_project_check.py
examples: (R-TST-111/1) `all-bad`, head → recorded `TC-B100-61 all-bad painted` equals `paint - install` within `0.001` s → passes
examples: (R-TST-111/1, M-6) `all-bad` with the arm's clock stopped when its wait notices the panel → recorded exceeds the observer's difference by > `0.1` s (E1: 0.50–0.66 s) → fails
examples: (R-TST-112/1, M-7) `scene` with the append clock stopped when the wait notices the line → recorded `sec6_5 appended` exceeds `outcome - append_start` by > `0.05` s (E1: 0.1–0.4 s) → fails
examples: (R-TST-111/2) `scene`, head → both `sec6_5 painted` and `sec6_5 appended` match within `0.001` s → passes

test_r_tst_113_panel_and_append_bounds_stay_at_one_second
req: R-TST-113
in: None
out: None
func: new. Reads `tests/test_b100_project_check.py` with `ast`; finds the `report_margin` calls whose label is `TC-B100-61 all-bad painted`, `TC-B100-61 cap painted`, `sec6_5 painted`, `sec6_5 appended`; asserts each third argument is `timing_bound(1.0)`.
module: tests/test_b100_project_check.py
examples: (R-TST-113/1) the head file → `4` of `4` sites hold `timing_bound(1.0)`
examples: (R-TST-113/1b) a planted copy with `timing_bound(1.5)` at `sec6_5 appended` → fails naming that label's line
