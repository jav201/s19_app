# Code-Wire graph — Inc 3 (Save project margin; a vanished project folder), batch-101

Stage E2 of the design-first flow (`dev-flow-v3-beta`). Graph only: no stub, mark or declaration in any tree. Base `e266395`; the test nodes build on the tree after Inc 2's merge (branch `b101-inc2`). Requirements `../01-requirements.md`, slice `../E1-slice.md`, cases `../02-test-cases.md`, profile `../E1-profile.md`.

How to read it:
- One file holds the baseline and the prototype. Every node's `func:` starts with **unchanged**, **changed** (then "was: … / now: …", the baseline first) or **new**. Unchanged nodes are context: a changed node calls them, or they call it.
- Example sources are the test-case ids of `02-test-cases.md`; `P` = a probe of the base tree run at E1 (scripts and transcripts under `evidence/inc-3/`, named in the line). Every example states the Inc 3 target unless it says "holds on base" or "base:".
- "T2" = the T2 composition of `01-requirements.md` Definitions. "Lines since" = the status lines painted after the trigger (Inc 2's `StatusLog.since(mark)`).

Groups for E4 (file ownership) and the interfaces they share — pinned here, changed only by an orchestrator ruling:

| Group | Files | Owns nodes |
|---|---|---|
| G1 product | `s19_app/tui/services/project_gather_service.py`, `s19_app/tui/app.py` | `gather_project_artifacts`, `S19TuiApp._sync_loaded_file_to_project`, `S19TuiApp._sync_loaded_a2l_to_project` |
| G2 timing clocks (tests) | `tests/test_b100_project_check.py` | `_paint_clock_start`, `_watch_panel_paint` (new), `_timed_load_panel_and_append`, `_sec6_5_filesystem_scene`, the 2 panel arm bodies, the R-TST-110 … 113 nodes |
| G3 product tests | `tests/test_project_gather.py`, `tests/test_b100_workers.py`, `tests/test_b100_active_variant.py` | the R-PROJ-* nodes of `E1-slice.md` §2 |

| Interface | Pinned form | Producer → consumers |
|---|---|---|
| I-1 the gather's contract | `gather_project_artifacts(project_dir: Path, *, composition_names: Sequence[str] = (), active_document: Optional[Path] = None, active_document_kind: str = "change", active_template: Optional[Path] = None, common_patches_dir: Path, common_templates_dir: Path, workarea_root: Path) -> GatherOutcome` — unchanged signature; the outcome for a duplicate-free, loop-free input is unchanged | G1 → `_save_project_files`, G3 |
| I-2 the sync refusal texts | `Project sync NOT done: project '<painted project name>' could not be read — check that the folder can be opened, then load again.` and the same with `A2L sync NOT done:` — canon R-PROJ-002.12/.13, built from `_TYPED_REFUSAL_TOKENS["unreadable"]` as today | G1 → G3 |
| I-3 the install stamp | `app._load_returned_at: float`, set by the arm's wrapper of `_install_prepared_project` right after the real install returns (as today) | G2 internal |
| I-4 the panel paint stamp | `_watch_panel_paint(app) -> list[float]`: a list the helper appends the panel paint stamp to, once; installed before the click | G2 internal |
| I-5 the outcome-line stamp | the scene's existing `set_status` capture (`_capture`, `app._statuses`) also records `time.perf_counter()` at the first line holding `was not rewritten` or `manifest verified` after the append's trigger | G2 internal |

Order inside E4: G1 and G3 in parallel (G3 proves RED on base first); G2 independently. No interface crosses G1 and G2.

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
func: changed. was: for each composition name, in order and with repeats, `in_project = (resolved_project / name).resolve()`; `in_project.is_file()` → already home, skip; else the common library by bare name, else one `GATHER-SOURCE-MISSING` issue. now: a name already checked in this call is skipped (a set of seen texts, first occurrence kept, order unchanged); the check is `(resolved_project / name).is_file()` with no `resolve()` — `is_file()` follows links itself and returns False for a link loop, so the name falls to the common-library lookup. Limbs 2a/2b (active document, template), the de-duplication by resolved source in `_schedule`, the copies and the outcome are unchanged.
module: s19_app/tui/services/project_gather_service.py
modify: outcome (append)
examples: (R-PROJ-GATHER.12/1) T2 project folder; composition_names = the 1 000 chain names + the same 1 000 again → `1000` project-folder checks; outcome.gathered `{}` and outcome.issues `[]` (all 1 000 already home) — base: `2000` checks, each with a `resolve()` (P: `R1-P1-cprofile-callers-e266395.txt`, 2 001 `resolve` calls from this function)
examples: (R-PROJ-GATHER.12/2) empty project, empty library; composition_names ["gone.json", "gone.json"] → `1` check; outcome.issues holds `1` `GATHER-SOURCE-MISSING` issue with text "gather: composition document 'gone.json' resolved to no file in the project or the common patches library — skipped" — base: `2` such issues
examples: (R-PROJ-GATHER.13/1) Windows; project folder holds a junction loop `x.json`; library holds `x.json` (change document); composition_names ["x.json"] → returns, no exception; the library `x.json` is scheduled into `patches/` — base: raises `RuntimeError` "Symlink loop from '…\x.json'" (P: measured on a junction loop at E1, `E1-profile.md` §1.3)
examples: (R-PROJ-001.13/1) T2 save through `_save_project_files` → the whole Save project, confirm → `Project saved + manifest verified`, in 0.65–0.74 s alone on the E1 host (P: `R1-P1-node-experiments.txt`, the `gather` + `isfile` rows, applied as runtime wrappers) — base: 1.11–1.33 s
examples: (holds on base) composition_names ["boost.json"], `boost.json` only in the library → outcome.gathered {"patches": ["patches/boost.json"]} (the existing `test_tc699_common_change_set_is_gathered_into_project_patches` keeps passing)

S19TuiApp._save_project_files
req: R-PROJ-001.13
in: SaveRequest request
out: SaveOutcome outcome
func: unchanged (context). The Save worker step: C1 folder creation, the plan's rows, `gather_project_artifacts(project_dir, composition_names=list(batch) + [assignment names], …)` at `app.py:11848`, then `_write_manifest_for_save` (serialize with the SEC6-5 refusal predicate, write, verifying re-read). Its time at T2 is R-PROJ-001.13's interval minus the handler (0.16–0.20 s) and the commit (about 0.01 s).
module: s19_app/tui/app.py
examples: (R-PROJ-001.13/1) T2 request → outcome whose lines lead to the status `Project saved + manifest verified`; worker step 0.83–1.16 s on base (P: `R1-P1-marks-e266395.txt`), about 0.45 s less with the gather change

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
out: list[float] stamps
func: new. Wraps the instance's `push_screen`: when the screen pushed is a `LoadResultScreen`, it subscribes the app (a running node) to that screen's `screen_layout_refresh_signal` with `immediate=True`; the callback appends `time.perf_counter()` to `stamps` the first time `#result_summary` has `size.height > 0`, and never again. Returns `stamps` (empty until the paint). Public Textual API only (E1-D6).
module: tests/test_b100_project_check.py
modify: stamps (append)
examples: (R-TST-111/1) all-bad scene, installed before the click → after the panel paints, `stamps` holds `1` value, equal to the first layout pass's end within 0.001 s (P: `painted-step-marks.txt`, `signal_painted` = `layout_first_end` in 8/8 runs)
examples: (R-TST-111/1b) a push of any other screen → `stamps` stays `[]`

test_tc_b100_61_every_array_at_the_cap_all_bad_opens_under_one_second
req: R-TST-110, R-TST-111, R-TST-113
in: Path tmp_path
out: None
func: changed (body only, name kept). was: `painted = time.perf_counter() - _paint_clock_start(app, pressed)` after `_wait_for` notices `#result_summary` with a height. now: `stamps = _watch_panel_paint(app)` before the click; the wait stays as the precondition that the panel exists (Inc 2's `wait_until` form); `painted = stamps[0] - _paint_clock_start(app, pressed)`; bound `report_margin("TC-B100-61 all-bad painted", painted, timing_bound(1.0))` unchanged; rows bound unchanged.
module: tests/test_b100_project_check.py
examples: (R-TST-111/1) all-bad scene → `painted` 0.17–0.42 s, < `1.0` (P: `painted-step-marks.txt`, stamped column) — base: 0.75–1.07 s by the poll in the same runs

test_tc_b100_61_files_at_the_cap_all_missing_are_bounded
req: R-TST-110, R-TST-111, R-TST-113
in: Path tmp_path
out: None
func: changed (body only, name kept). The same clock change as the all-bad arm; label `TC-B100-61 cap painted`; bound unchanged.
module: tests/test_b100_project_check.py
examples: (R-TST-111/3) cap scene → `painted` equals stamp difference within `0.001` s; < `1.0`

_timed_load_panel_and_append
req: R-TST-110, R-TST-111, R-TST-112
in: Pilot pilot; S19TuiApp app; Path source
out: tuple(float painted, int rows, float appended)
func: changed. was: `painted` from `_paint_clock_start` to when `_wait_for` notices the panel; `appended` from just before `app.load_from_path(source)` to when `_wait_for` notices an outcome line in `app._statuses`. now: `painted` = panel paint stamp (`_watch_panel_paint`, installed by the scene before the click) − install stamp; `appended` = outcome-line stamp (I-5) − the moment just before `app.load_from_path(source)`; both waits stay as preconditions.
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

test_r_tst_113_panel_and_append_bounds_stay_at_one_second
req: R-TST-113
in: None
out: None
func: new. Reads `tests/test_b100_project_check.py` with `ast`; finds the `report_margin` calls whose label is `TC-B100-61 all-bad painted`, `TC-B100-61 cap painted`, `sec6_5 painted`, `sec6_5 appended`; asserts each third argument is `timing_bound(1.0)`.
module: tests/test_b100_project_check.py
examples: (R-TST-113/1) the head file → `4` of `4` sites hold `timing_bound(1.0)`
examples: (R-TST-113/1b) a planted copy with `timing_bound(1.5)` at `sec6_5 appended` → fails naming that label's line
