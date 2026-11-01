# Code-Wire prototype — Inc 12b, groups G-A (project load on a worker) and G-B (Save project on a worker), `s19_app/tui/app.py`

Stage E2 of the design-first pipeline (`dev-flow-v3-beta`) for Inc 12b ("project load, Save project and the A2L parse on workers"), prototype P-1. Graph only: no stub, mark or other change in `s19_app/` of any tree. New functions are nodes whose `func:` starts with "new". Base: main `8947666` (the bytes the baseline read; main has since merged Inc 9b at `3bf20b3`, whose `_handle_load_project` request frame is cited where it is the real post-9b shape) plus the fixed graphs and interfaces of Inc 9b, 10, 11 and 12a. Line numbers are `8947666` lines of `app.py` unless another file is named.

Inputs: `../E1-requirements-draft.md`, `../E1-scope.md`, `../E1-rulings.md` (Q1–Q7), `../E2-rulings.md`, `baseline-12b.md`, `baseline-notes.md`, `interfaces-12b.md` (FIXED; what I need changed is in "Proposals to the orchestrator"), `../../inc-12a-design/codewire/interfaces-12a.md` and `proto-12a-indicator.md` (consumed unchanged), `../../inc-11-design/codewire/interfaces-11.md` / `proto-11-app.md`, `../../inc-10-design/codewire/proto-10-app.md`, `../../inc-9b-design/codewire/proto-9b-app.md`.

Probes (2 runs of one script, s19env Python 3.11 / Textual 8.2.8, on a throwaway `git archive` copy of `8947666` under `../work/p1/repo`, `LOCALAPPDATA` under `../work/localappdata-p1`, outputs under `../work/p1`; the checkout was not imported and `git status` of it is unchanged):
- `../work/p1/probe_p1.py` → `probe_p1.out.txt` (U1): the 12b split of the project load emulated on base functions — a "worker" half that reads only explicit inputs and a main-thread "install" half — against a cold base `_handle_load_project`.
- the same script with `lines` → `probe_p1_lines.utf8.txt` (U2): the exact painted lines of the base project load and Save of the same fixture, and of a Save whose placement raises `OSError(28)`.
- `../work/p1/probe_p1_plan.py` → `probe_p1_plan.out.txt` (U3): the base save plans behind P1-62 / P1-63 (rows by role, copies).
- Note: `python -I` ignores `PYTHONUTF8` / `PYTHONDONTWRITEBYTECODE`; that is why the probes ran on a copy (any bytecode lands in the copy) and U2's raw output is cp1252 (`probe_p1_lines.out.txt`, re-saved as UTF-8).

Conventions:
- `W` = the work area (`<base>/.s19tool/workarea`). `pn(x)` = `painted_names([x])`. `T` = `#status_text` read as 12a does. "Spy" = a wrapper that records arguments and `threading.get_ident()`; "main" = the `run_test` thread.
- "Session digest" = E1's tuple (`current_file.path` relative to `W`, image SHA-256 prefix as in `probe-p12b.py`, `current_project`, `current_a2l_path`, MAC path, document entry count).
- Fixtures: `P2` = case_01 `firmware.s19` + `firmware.mac` + `firmware.a2l` in `W/P2`, no `project.json` (digest `D2 = ('P2\firmware.s19', 'f254f33fe5405d40', 'P2', 'P2\firmware.a2l', 'P2\firmware.mac', 0)`, probe U1 and baseline p12b U1); `P6` = the same three case_06 files (digest `D6 = ('P6\firmware.s19', 'f917cd2dca22da9a', 'P6', 'P6\firmware.a2l', 'P6\firmware.mac', 0)`, baseline p12b U1); `A2LONLY` = only `cal.a2l`; `S` = an open project holding the case_01 trio plus `flows/f1.json` (the save-as source).
- "Forced slow step" = a test double that blocks the named call on a `threading.Event` until the test sets it (E1 glossary).
- Example ids are `P1-NN`. Every example states the Inc 12b target unless it says "holds on base".
- 12a's table (fixed): `project_load` label `Loading project {name}`, steps `Check the files`, `Parse the A2L`, `Parse the image`, `Install`; `save_project` label `Saving project {name}`, steps `Create the folder`, `Place the files`, `Gather the project files`, `Write project.json`. Bar = `floor(100 × (n − 1 + fraction) / 4)`.

## Decisions taken inside the fixed interface

| Point | Decision | Reason |
|---|---|---|
| The worker step as a function | `_prepare_project_load(request)` and `_save_project_files(request)` are plain methods; the `@work` functions only hold the S-d body around them | S-d's body shape is fixed; a plain function lets the outer guard see a failure before the rollback `try` (the `mkdir`), and gives TC-B100-07's census and LLR-177.1e's AST census one named target each |
| Worker guard form | `except BaseException: call_from_thread(_busy_fail, …); raise`, not S-d's `finally` | the fixed file's last list makes 12a's E3 S12a-06 binding ("worker guards are `except BaseException` + end + re-raise"); a `finally` would post a second end after every success (proposal PR-5 aligns S-d's text; E3 DF-3) |
| Worker options | `@work(thread=True, group="project_load")` and `group="save_project"` — distinct, non-exclusive (E3 DF-2 / P2-4); `exit_on_error` left at Textual's default `True` | fixed Q-d1; with a distinct non-exclusive group no worker is cancelled, so no canceller owes an `end_busy` (superseding 12a S12a-05 for 12b) |
| `_install_project_image` | **retired**; its parse half is inlined in `_prepare_project_load`, its apply half is 2 lines in `_install_prepared_project` | E1 A6 "may dissolve"; a 2-line single-use apply wrapper adds nothing (rule 2) |
| `_reopen_active_document` | keeps its name as the main-thread install half; the read half (`recorded_document_state` and the problem) is inlined in `_prepare_project_load` | E1 A7; single-use halves are not split into new functions |
| The pure parse (E1 A8) | one explicit-input core `_parse_data_file(path, a2l_path, a2l_data, existing)`; `_parse_loaded_file` becomes its session-reading wrapper; `_load_mac_file` and the two merge methods take their inputs explicitly | one suffix dispatch and one merge rule shared by the file load and the project worker; no copy of either (rule 7) |
| `workarea` / `base_dir` on the worker | the Save helpers the worker reaches take `workarea` from the request as a parameter | fixed S-b: "`base_dir` / `workarea` come from the request" |
| The Save handler | one handler, `_on_project_saved(outcome)`, for both arms; a failure outside the rollback `try` becomes a failure `SaveOutcome` built in the worker body | the fixed G-B row names only `_on_project_saved`; Save has no `_on_<action>_failed` |
| The Save lines | the worker composes every line it can decide (failure lines in base order; the committed tail from `Saved project to …` to the worker's document lines); the handler adds only the main-thread lines; the outcome is always the last line in base order | fixed 12a Q-3 ("the action's last painted status line is the outcome") and the 12b rule "the end tail is the last statement" keep the status log line-for-line equal to the base |

## Owned nodes (39) and context

- **G-A, new (12):** `A2LCacheEntry` (data), `parse_a2l_cached` (module), `S19TuiApp._a2l_cache_entry`, `S19TuiApp._store_a2l_cache`, `ProjectLoadRequest` (data), `PreparedProjectLoad` (data), `S19TuiApp._project_load_worker`, `S19TuiApp._prepare_project_load`, `S19TuiApp._on_project_loaded`, `S19TuiApp._install_prepared_project`, `S19TuiApp._on_project_load_failed`, `S19TuiApp._parse_data_file`.
- **G-A, changed (10):** `_handle_load_project`, `_route_load_project`, `_reopen_active_document`, `_parse_loaded_file`, `_load_mac_file`, `_merge_mac_with_existing_primary`, `_merge_primary_with_existing_mac`, `PreparedLoad` (one field, Q-h1), `_apply_prepared_load` (one store line, Q-h1), `load_selected_file` (the cache hand-off).
- **G-A, retired (2):** `_install_project_image`, `_load_a2l_data_with_cache` (E3 DF-7).
- **G-B, new (8):** `SaveImageInput`, `SaveRequest`, `SaveOutcome`, `S19TuiApp._save_project_worker`, `S19TuiApp._save_project_files`, `_save_failure_outcome` (module), `S19TuiApp._on_project_saved`, `S19TuiApp._write_manifest_for_save` (Q-b1).
- **G-B, changed (6):** `_commit_project_save`, `_write_and_verify_manifest` (delegates to the core, behaviour and signature kept), `_abort_save`, `_restore_manifest`, `_keep_previous_manifest`, `_copy_project_subfolders`.
- **G-B, retired (1):** `_write_editor_document` (E3 S12b-05).
- Count: G-A 12 new + 10 changed + 2 retired = 24; G-B 8 new + 6 changed + 1 retired = 15; **39 nodes**.
- **Context (unchanged, new or moved callers):** `recorded_document_state`, `choose_install_set`, `compose_load_announcement`, `check_project_files`, `build_variant_set`, `read_project_manifest`, `_reset_project_session` (post-10, `-> None`; caller moves), `_apply_loaded_file`, `update_a2l_view`, `_handle_save_dialog` (post-11 router), `_prepare_project_save`, `_save_session_inputs`, `_decide_project_image` (ruling Q1), `_rewrite_project_manifest` (unchanged under Q-b1), `_surface_verify_result`, `_surface_manifest_verify_result`, `_unrecorded_document_lines` (pure; now reached on the worker), `ChangeService.record_save_entries` / `adopt_rederived` / `mark_saved` (new call sites, main), `ChangeService.emit_and_verify` (no longer called by Save; `save_patched` keeps it), `_session_snapshot`.
- **Consumed from P-2 (G-C1) by name, never re-implemented:** `_refuse_if_busy`, `_progress_forwarder`; from 12a: `_busy_begin_action`, `step_busy`, `end_busy`, `_busy_fail`; from G-D: `parse_a2l_file(path, progress=None)`.

**Imports (`app.py`).** `import logging` (the module-level `parse_a2l_cached` logs on the process-global `logging.getLogger("s19tui")`, the logger `setup_logging` returns, `workspace.py:166`); `import copy` (the document snapshot, E3 S12b-05); `save_patched_image` joins `from .changes.apply import render_patched_image`; `from .changes.verify import verify_written_image` (Q-b2). `serialize_change_document`, `classify_active_document`, `document_home_for_kind`, `write_change_document` (stays imported; the document row calls it, E3 S12b-05), `_private_stage_dir`, `save_back_status_suffix`, `painted_names`, `safe_text`, `place_into_workarea` are already imported.

## Nodes

A2LCacheEntry
req: LLR-177.1d, LLR-177.1e
in:
out: type alias
func: new (module level, fixed S-h): `A2LCacheEntry = tuple[tuple[str, int, int], dict]` — `((str(path.resolve()), st_mtime_ns, st_size), parsed payload)`, the key shape `_load_a2l_data_with_cache` uses today (`:15845`).
callers: `parse_a2l_cached`, `ProjectLoadRequest`, `PreparedProjectLoad`, `PreparedLoad`, `_a2l_cache_entry`, `_store_a2l_cache`; P-2's `A2LAttachRequest` / `A2LAttachResult`.
module: s19_app/tui/app.py
examples: P1-01 (type) `parse_a2l_cached(case_01/firmware.a2l, None)` returns a 2-tuple whose first item is a 3-tuple `(str, int, int)` with `[2] == 1444` (the file size) and whose second item is a `dict` with keys `path`, `sections`, `errors`, `tags`, `record_layouts_by_name`, `compu_methods_by_name`, `compu_tabs_by_name` (2 of 2).

parse_a2l_cached
req: LLR-177.1d, LLR-177.1e, LLR-177.5, LLR-177.1
in: Path path; Optional[A2LCacheEntry] cached; Optional[A2LProgress] progress = None
out: A2LCacheEntry entry
func: new (module level, pure, fixed S-h). Steps:
- (1) `st = path.stat()`; `key = (str(path.resolve()), st.st_mtime_ns, st.st_size)`.
- (2) `cached is not None and cached[0] == key` → `_LOG.info("A2L cache hit: path=%s size_bytes=%d", path, st.st_size)`; `return cached` (no parse).
- (3) Else `_LOG.info("A2L cache miss: …")`; `data = parse_a2l_file(path, progress=progress) if progress is not None else parse_a2l_file(path)` (fixed Q-f2: the no-callback call is the real main-thread / file-load path); `return (key, data)`.
- `_LOG = logging.getLogger("s19tui")` (the same process-global logger as `self.logger`, so the two log lines keep their file). It reads no `self`, writes nothing; `parse_a2l_file` is the app module's global (tests monkeypatch `app_module.parse_a2l_file`). An exception from `stat` or the parse propagates to the caller.
callers: `_prepare_project_load` (worker, with the step-2 forwarder); `_parse_loaded_file` (main or the file-load worker, no callback); P-2's `_a2l_attach_worker` (with the step-2 forwarder); the re-pinned `test_tui_app.py::test_a2l_cache_reuses_parse_for_unchanged_file` (E3 DF-7).
module: s19_app/tui/app.py
examples: P1-02 (hit, S-h) `e = parse_a2l_cached(a, None)` then `parse_a2l_cached(a, e)` with `a` unchanged → the second returns `e` itself (`is`), and a spy on `app_module.parse_a2l_file` counts 1 call over both (2 of 2). Touch `a` (`os.utime` with `mtime_ns + 1`) → a third call parses again (count 2) and returns a new entry whose `[0][1]` differs. Negative control: a mutation that compares only the resolved path → the third call returns the stale `e` → RED.
examples: P1-03 (LLR-177.5, Q-f2) with `progress = rec.append`-style recorder `lambda d, t: seen.append((d, t))` → `parse_a2l_file` receives `progress=` (a tolerant spy records the keyword); with `progress=None` the spy receives exactly 1 positional argument and no keyword (`test_tui_app.py::test_a2l_cache_reuses_parse_for_unchanged_file`'s `fake_parse(path)` still works) (2 of 2). Negative control: always passing `progress=progress` → the one-parameter fake raises `TypeError` → C6 RED.
examples: P1-04 (LLR-177.1e) AST: the function body holds 0 `self` names and 0 `Attribute` reads of `_a2l_cache_key` / `_a2l_cache_data` (1 assertion).

S19TuiApp._a2l_cache_entry
req: LLR-177.1d, LLR-177.1e
in:
out: Optional[A2LCacheEntry] entry
func: new (fixed S-h). Main thread (also read once by the file-load worker inside `_parse_loaded_file`, as that worker reads the session today; finding F-6). `key, data = self._a2l_cache_key, self._a2l_cache_data`; `return (key, data) if key is not None and data is not None else None`. Writes nothing.
callers: `_handle_load_project` (into the request); `_parse_loaded_file`; P-2's `load_a2l_from_path` (into `A2LAttachRequest`).
module: s19_app/tui/app.py
examples: P1-05 a fresh app → `None`; after `_store_a2l_cache(e)` → a tuple equal to `e` whose `[1] is e[1]` (2 of 2).

S19TuiApp._store_a2l_cache
req: LLR-177.1d
in: A2LCacheEntry entry
out: None
func: new (fixed S-h). Main thread only: `self._a2l_cache_key, self._a2l_cache_data = entry`. The only writer of the two attributes after 12b (`_load_a2l_data_with_cache`'s inline write goes; `_reset_project_session` never touched them, K2).
callers: `_install_prepared_project`; `_apply_prepared_load` (Q-h1); `load_selected_file`; P-2's `_install_attached_a2l`.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._a2l_cache_key] (replace), [Data: S19TuiApp._a2l_cache_data] (replace)
examples: P1-06 (LLR-177.1d, AST) in `app.py`, every assignment to `self._a2l_cache_key` / `self._a2l_cache_data` outside `__init__` sits in `_store_a2l_cache` (2 targets, 1 function) (1 assertion). Negative control: the base `_load_a2l_data_with_cache` (`:15851`–`:15852`) → 2 targets in a second function → RED.

S19TuiApp._load_a2l_data_with_cache
req: LLR-177.1d
in: Optional[Path] path
out: Optional[dict[str, Any]] a2l_data
func: **retired** (E3 DF-7 / PR-6). Its 4 base callers all move to `parse_a2l_cached` (the project load to `_prepare_project_load`'s worker, `load_a2l_from_path` to P-2's worker, `_load_mac_file` to explicit inputs, `_parse_loaded_file` to `parse_a2l_cached`), so it keeps no product caller after 12b. Its one test re-pins to `parse_a2l_cached` (`test_tui_app.py::test_a2l_cache_reuses_parse_for_unchanged_file`), and the C8 spy at `test_b100_project_homes.py:1996` (`monkeypatch.setattr(cls, "_load_a2l_data_with_cache", …)`, which raises `AttributeError` once the name is gone) re-pins to `parse_a2l_cached` too.
callers: none after 12b (base: `_handle_load_project` :11858, `load_a2l_from_path` :13145, `_load_mac_file` :14217, `_parse_loaded_file` :15151 / :15170).
module: s19_app/tui/app.py
examples: P1-07 (re-pinned, E3 DF-7) `parse_a2l_cached(a, None)` twice on an unchanged `firmware.a2l` with `app_module.parse_a2l_file` replaced by `fake_parse(path)` → 1 fake call, the two results equal. Negative control: a mutation that drops the cache store in `load_selected_file` → 2 fake calls → RED.

ProjectLoadRequest
req: LLR-177.1e, LLR-177.1h
in:
out: frozen dataclass
func: new (fixed S-b), exactly the fixed fields: `name`, `project_dir` (`self.workarea / name`, unresolved, SEC-1), `data_files`, `a2l_files` (0 or 1, after `_a2l_admission`), `a2l_problem`, `a2l_cache` (`self._a2l_cache_entry()`), `gen`, `routed`. Built on the main thread in `_handle_load_project`; the worker's only argument. Never stored on the app.
callers: `_handle_load_project` (builds); `_project_load_worker`, `_prepare_project_load`, `_on_project_load_failed` (read); `PreparedProjectLoad.request`.
module: s19_app/tui/app.py
examples: P1-08 (LLR-177.1e) `dataclasses.is_dataclass(ProjectLoadRequest)` and `__dataclass_params__.frozen` → `True`, `True`; assigning `request.name = "x"` raises `FrozenInstanceError` (3 of 3). Negative control: a plain (non-frozen) dataclass → the frozen arm RED.

PreparedProjectLoad
req: LLR-177.1e, LLR-177.1f
in:
out: frozen dataclass
func: new (fixed S-b), the fixed fields: `request`, `refusal`, `variant_set`, `manifest`, `problems`, `a2l_cache`, `install`, `image`, `unreadable`, `mac`, `document`. Built by the worker; nothing in it is session until `_install_prepared_project` installs it. `image.variant_id` is already set to the opened variant's id (finding F-1); `mac` is the MAC merged onto `image`, never onto the live `current_file`. The retired fields `recorded` and `a2l_context` (E3 A12b-04) are gone: the install reads `prepared.a2l_cache[1]` for the A2L context, and `recorded` is read nowhere.
callers: `_prepare_project_load` (builds); `_on_project_loaded`, `_install_prepared_project` (read).
module: s19_app/tui/app.py
examples: P1-09 for `P2`: `refusal is None`, `install.variant.path.name == "firmware.s19"`, `install.mac.name == "firmware.mac"`, `image.path.name == "firmware.s19"`, `image.variant_id == "firmware"`, `mac.file_type == "s19"`, `mac.mem_map is image.mem_map`, `mac.mac_path.name == "firmware.mac"`, `mac.variant_id == "firmware"`, `a2l_cache[1] is not None`, `document is None` (no `project.json`) (11 of 11; probe U1 arm A shapes).

S19TuiApp._handle_load_project
req: LLR-177.1, LLR-177.1g, LLR-177.1h, HLR-177a (Q-a1), LLR-176.2c, LLR-176.1l
in: Optional[str] name; bool routed = False
out: None
func: changed (post-9b request frame as merged at `3bf20b3`, post-10, post-12a). Steps:
- (0) `if self._refuse_if_busy(): return` — the first statement (fixed Q-a1; P-2's helper).
- (1) Unchanged cheap refusals, in the post-9b order: `name is None` → log; `_project_folder_refusal` (link / unreadable / outside); `exists()`; the listing match (12a S-k `_listed_project_name`, `OSError` → `could not be read`, unlisted → `is not a project`); `_list_project_files` (`OSError` → `could not be read`; `error` → its line); `_a2l_admission` (an inadmissible A2L with no data file → its refusal; beside a data file → `a2l_problem`, `a2l_files = []`); `not data_files and not a2l_files` → `has no data or A2L file` / `has no project.json`; the `project.json` lstat gate (`could not be read`). Each refusal paints in the frame of the request and starts nothing (LLR-177.1's "4 of 4").
- (2) `gen = self._busy_begin_action("project_load", name)` (12a; `name` is the listed spelling).
- (3) `try: request = ProjectLoadRequest(name, project_dir, tuple(data_files), tuple(a2l_files), a2l_problem, self._a2l_cache_entry(), gen, routed); self._project_load_worker(request)` / `except BaseException: self._busy_fail("project_load", gen); raise` (S-d kickoff guard; the run outlives the function, so no `finally`; this replaces 12a's `try / finally: _busy_fail`).
- Removed from the body: `build_variant_set`, `read_project_manifest`, `_declared_regions`, `check_project_files`, the recorded variant, the A2L read, `choose_install_set` and its refusal, the A2L-only attach, `_reopen_active_document`, `current_project` / `current_project_dir` / `_variant_set`, the image loop, the MAC install, the announcement, its lines and the tail (they move to the worker and the install handler). It no longer calls `_reset_project_session` (LLR-165.1, E1 §C.1).
callers: `_route_load_project` (inside `go`, `routed=True`); 97 direct test sites (`routed=False`), `tests/b97_fixtures.load_project`, `tests/support/b100_projects` (:383, :613), `_load_directly` (census A5).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._busy] (begin)
examples: P1-10 (LLR-177.1, request frame) the 4 cheap refusals of LLR-177.1's threshold, each in a fresh app: a junction `W/J` (Windows only) → `Project NOT loaded: 'J' is a link or junction — pick a project in the list.`; `W/../X` outside → `… is outside the work area — copy the folder into the work area.`; `Z` not listed → `Project NOT loaded: 'Z' is not a project — pick a project in the list.`; `Q` holding only `project.json` → `Project NOT loaded: 'Q' has no data or A2L file — load a file and Save project.`. Each: the line is `log_lines[-1]` right after the synchronous call returns, a `_busy_begin_action` spy counts 0, a `_project_load_worker` spy counts 0, `app._busy.runs == {}` (4 × 4). Negative control: a mutation that starts the worker before the listing match → the `Z` arm shows 1 worker start → RED.
examples: P1-11 (LLR-177.1, the begin and the hand-off) `_handle_load_project("P2")` → returns with `current_project is None` (the install has not run), `app._busy.runs["project_load"].label == "Loading project P2"`, T reads `⠋ Loading project P2  ·  step 1/4 Check the files  ·  00:00` in the call's frame, 1 `_project_load_worker` call whose only argument is a `ProjectLoadRequest` with `name == "P2"`, `routed is False`, `a2l_files == (W/P2/firmware.a2l,)`, `gen == app._busy.runs["project_load"].gen` (6 of 6). Negative control: the base body (synchronous) → `current_project == "P2"` when the call returns → RED.
examples: P1-12 (fixed Q-a1, seam X-1) with a Save run held at a forced slow step (`app._busy.runs` holds `save_project` labelled `Saving project Q`), `_handle_load_project("P2")` → `log_lines[-1] == "busy: Saving project Q is running — wait for it to finish."`, 0 begins of `project_load`, `current_project` unchanged, 0 worker starts (4 of 4). Negative control: the check left out → a second session writer starts → the `project_load` begin spy counts 1 → RED.
examples: P1-13 (LLR-176.1l, the kickoff guard) `S19TuiApp._project_load_worker` patched to raise `RuntimeError("forced")` at call time → an `end_busy` spy records `("project_load", g, "Loading project P2 failed")` → `True`, then `RuntimeError` leaves `_handle_load_project` (`pytest.raises`); `app._busy.runs == {}`; 0 active timers (4 of 4). Negative control: the guard removed → the run stays with 1 active timer after the raise → RED.
examples: P1-14 (TC-B100-08 call-site census holds, LLR-165.1 §C.1) AST of `s19_app/`: exactly 1 call of `_reset_project_session`, and it is inside `_install_prepared_project`; `_handle_load_project` holds 0 (2 of 2). Negative control: the base body → the one call sits in `_handle_load_project` → the re-pinned function-level arm RED.

S19TuiApp._project_load_worker
req: LLR-177.1, LLR-177.1c, LLR-177.2, LLR-176.1l, LLR-176.1q
in: ProjectLoadRequest request
out: None
func: new (fixed S-b / S-d). `@work(thread=True, group="project_load")`, not exclusive (E3 DF-2 / P2-4; default `exit_on_error=True`, Q-d1). Body:
- `try:` / `try: prepared = self._prepare_project_load(request)` / `except Exception as exc: self.logger.exception("Project load failed on the worker: %r", request.name); self.call_from_thread(self._on_project_load_failed, request, exc); return` / `self.call_from_thread(self._on_project_loaded, prepared)` (outside the inner `try`: a handler raise is not a worker failure).
- `except BaseException: self.call_from_thread(self._busy_fail, "project_load", request.gen); raise` (S12a-06; posted only on the exception path, so the success path adds no no-op round trip).
- It reads `request`, `self.logger`, `self.call_from_thread` and the bound handlers only.
callers: `_handle_load_project` (kickoff). Group `project_load` is used by no other worker (seam X-9).
module: s19_app/tui/app.py
examples: P1-15 (LLR-177.1, thread ids, 5 of 5) `P2` plus a recorded change document: a fixture `W/P2/project.json` written by a Save of `P2` with 1 pasted entry, then a fresh app loads `P2` through the Load dialog (`p`, the `P2` row, `enter`). Thread-recording spies on `app_module.check_project_files`, `app_module.read_project_manifest`, `app_module.parse_a2l_file`, `app_module.build_loaded_s19`, `app_module.recorded_document_state` → each records 1 call on a thread other than main (5 of 5). Negative control: executed P12b-5 on base (`ran on main thread True`) → RED; a mutation that parses the A2L in the install handler → the `parse_a2l_file` spy records main → RED.
examples: P1-16 (LLR-177.1c, project arm) a 0.1 s `set_interval` counter started before `_handle_load_project("P6")`, read at the worker's start (a spy on `_prepare_project_load` entry posts the count through `call_from_thread`) and at the entry of `_install_prepared_project` → ≥ 10 ticks between them (case_06: P12b-7 5.01 s parse on the worker). Boundary: `P2` (case_01) → 0 ticks required, the session digest after the install equals `D2`. Negative control: executed P12b-5 (0 ticks in 5.81 s) → RED.
examples: P1-17 (LLR-176.1l, worker exception exit) `S19TuiApp._on_project_loaded` patched to raise `RuntimeError("forced")` → `call_from_thread` re-raises it in the worker; the outer guard posts `_busy_fail` → the `end_busy` spy records `("project_load", g, "Loading project P2 failed")` → `True` before `run_test` raises `WorkerFailed` (Q-d1 loud) (2 of 2). Negative control: the outer guard removed → 0 ends recorded → RED.
examples: P1-84 (HLR-177 elapsed arm, AT-B100-18 worker half) by keys: `p`, the `P6` row, `enter` (nothing unsaved, so no question); T sampled every 0.05 s from the `enter` until `_install_prepared_project` starts (a flag set at its first line) → ≥ 2 distinct elapsed texts among the samples matching `^[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏] Loading project P6  ·  step [1-4]/4 .+  ·  (\d\d:\d\d)$` (the elapsed text changes ≥ 1 time before the install ends); after the end `log_lines[-1]` starts with `Loaded project 'P6' -> firmware.s19 + firmware.mac - variant 1 of 1` (the shape of probe U2's `P2` line; the problem count of case_06 is not restated here) and T reads `Loaded project 'P6' -> firmware.s19 + firmware.mac` (2 of 2). Negative control: executed P12b-5 (`wall 5.81 s; ticks during the call 0`) → 1 elapsed text → RED.
examples: P1-18 (LLR-176.1q) a thread-id probe on `Label.update` of T and `ProgressBar.update` across a `P6` load → 0 writes off main (1 assertion; every `step_busy` reaches the widgets through `call_from_thread`). Negative control: `self.step_busy("project_load", gen, 3)` called directly on the worker → ≥ 1 off-main write → RED.

S19TuiApp._prepare_project_load
req: LLR-177.1, LLR-177.1e, LLR-177.1f, LLR-177.5, LLR-169.6, LLR-169.9
in: ProjectLoadRequest request
out: PreparedProjectLoad prepared
func: new, the worker step (post-10 read order; E1 A2). Reads only `request` (plus `self.logger`, `self._flush_logger`, `self._parse_data_file`, `self.call_from_thread`, `self.step_busy` as a value, `self._progress_forwarder`). Steps:
- (1) `data = list(request.data_files)`; `a2l_files = list(request.a2l_files)`; `variant_set = build_variant_set(request.name, data)`; `manifest = read_project_manifest(request.project_dir)`.
- (2) `problems = check_project_files(request.project_dir, manifest)`; one warning per problem (`"Project %s: %s %s (%s)"`, as `:11853`); `request.a2l_problem` appended when set.
- (3) `recorded = manifest.active_variant if manifest is not None and not manifest_is_damaged(manifest) else None`.
- (4) A2L (only when `a2l_files`): `self.call_from_thread(self.step_busy, "project_load", request.gen, 2)`; `try: entry = parse_a2l_cached(a2l_files[0], request.a2l_cache, progress=self._progress_forwarder("project_load", request.gen, 2))` → `a2l_context, a2l_cache = entry[1], entry` / `except Exception as exc:` warning `"Project A2L not readable: %s (%s)"`, `ProjectFileProblem(PROBLEM_NOT_READABLE, a2l_files[0].name, "the file cannot be read")`, `a2l_files = []`, `a2l_cache = None`. With no A2L: `a2l_context = None`, `a2l_cache = None` (the install keeps the existing cache, K2), and step 2 is skipped (12a A12a-09).
- (5) `install = choose_install_set(variant_set, recorded, data, a2l_files)`; all three `None` → warning `"No loadable data file in project: %s"` and `return PreparedProjectLoad(request, f"No supported files in project: {pn(request.name)}", variant_set, manifest, tuple(problems), a2l_cache, install, None, (), None, None)` (post-10 S10-04 text; `recorded` and `a2l_context` dropped from the result, E3 A12b-04).
- (6) The recorded document (the read half of `_reopen_active_document`, inlined): when `manifest` is set, not damaged and `manifest.active_document` is set: `state = recorded_document_state(request.project_dir, text, a2l_context)`; `DOCUMENT_MISSING` → no problem (`check_project_files` owns `missing`); another non-OK outcome → the base warning and `ProjectFileProblem(PROBLEM_NOT_READABLE, document_problem_file(text), _DOCUMENT_REASON[outcome], step=_DOCUMENT_STEP.get(outcome))`; `DOCUMENT_OK` → `state.document.source_path = request.project_dir.absolute() / text` (the worker's own object, before the hand-off). `document = state` (or `None` when nothing is recorded).
- (7) `self.call_from_thread(self.step_busy, "project_load", request.gen, 3)`.
- (8) The image loop (the parse half of the retired `_install_project_image`): `a2l_path = a2l_files[0] if a2l_files else None`; `a2l_data = a2l_context if a2l_files else None`; while `install.variant` is set: `try: loaded = self._parse_data_file(install.variant.path, a2l_path, a2l_data, None)` / `except Exception:` warning `"Project image not readable: %s (%s)"`, `loaded = None`; reason = `"not an S19 or HEX file"` when `None`, `"not an S19 or HEX file" if loaded.errors else "0 data bytes"` when `mem_map` is empty, else accept (`image = loaded`, break); a rejected variant → `unreadable.append`, `ProjectFileProblem(PROBLEM_NOT_READABLE, name, reason)`, `install = choose_install_set(…, [v.variant_id for v in unreadable])` (LLR-169.6). The explicit `existing=None` reproduces the base, where `current_file` is `None` after the reset (the primary-with-MAC merge is then the identity).
- (9) `opened = install.variant`; `variant_set.active_id = opened.variant_id if opened else None`; when `image` is set: `image.variant_id = opened.variant_id` (finding F-1).
- (10) MAC: when `install.mac` is set: `mac = self._parse_data_file(install.mac, a2l_path, a2l_data, image)` — the MAC built with the explicit A2L and merged onto the worker's own `image` (fixed U2 rule: never the live `current_file`).
- (11) `return PreparedProjectLoad(request, None, variant_set, manifest, tuple(problems), a2l_cache, install, image, tuple(unreadable), mac, document)` (`recorded` and `a2l_context` dropped from the result, E3 A12b-04; `recorded` stays a local for `choose_install_set`, `a2l_context` stays a local for the document / image reads).
- It writes no app attribute and posts only `step_busy` (steps 2, 3 and step 2's byte reports).
callers: `_project_load_worker` only.
module: s19_app/tui/app.py
examples: P1-19 (LLR-177.1f, executed as an emulation: probe U1 arm A) the worker half on base functions with explicit inputs for `P2`, then the install half → session digest `D2`, equal to a cold base load; `current_file.variant_id == "firmware"` after the image and after the MAC install; `_variant_set.active_id == "firmware"`; `_session_snapshot()` differs from the cold one only in `log_lines` (4 assertions). Arm C (the same over an open `p1img.s19`, P2-over-P1) → digest `D2`, snapshot differing only in `['_image_generation', 'log_lines']` (the base's own P2-over-P1 result, baseline p12b U1) (2 assertions). Negative control: executed base U2 (`_parse_loaded_file(P2/firmware.mac)` with `p1img.s19` open → `file_type s19`, path `p1img.s19`): a worker that merges with the live `current_file` installs P1's image under P2 → digest path `p1img.s19` → RED.
examples: P1-20 (finding F-1, executed: probe U1 arm B) the same emulation without step (9)'s stamp → digest still `D2`, snapshot still differing only in `log_lines`, but `current_file.variant_id` is `'firmware'` after the image install and **`None` after the MAC install** (the merged MAC copied the unstamped `None`, and `_apply_prepared_load` stamps only from `_pending_variant_id`, already cleared). The TC therefore asserts `app.current_file.variant_id == "firmware"` after a `P2` load (1 assertion). Negative control: step (9) removed → `None` → RED; LLR-177.1f's snapshot arm alone stays GREEN on that mutant (proposal PR-10).
examples: P1-21 (LLR-177.5, project half; AT-B100-17 parse half shape) a `P6` load with a bar spy → within step 2 (between the `step_busy(…, 2)` post and the `step_busy(…, 3)` post) the bar takes ≥ 2 increasing values in `(25, 50]`, read on main; the last value in the step is `50` (the final `(total, total)` forward: `floor(100 × (1 + 1) / 4)`) (3 assertions). Boundary: `P2`'s 1 444-byte A2L → ≥ 1 forward, the last `(1444, 1444)` → bar `50`. Negative control: a mutation that passes no `progress=` → the bar sits at `25` through step 2 → 0 increases → RED.
examples: P1-22 (LLR-177.1 boundary, A2L-only) `A2LONLY` → the worker parses `cal.a2l` (the `parse_a2l_file` spy on a non-main thread), `install.variant is None`, `install.mac is None`, `install.a2l == W/A2LONLY/cal.a2l`, `image is None`, `mac is None`, `refusal is None` (6 of 6); after the install `current_a2l_path == W/A2LONLY/cal.a2l` and `current_file is None`.
examples: P1-23 (LLR-169.6 on the worker; LLR-177.1 boundary) `PV` holding `a.s19` (valid), `b.s19` (bytes `not s19\n`) and `project.json` recording `active_variant` `b` → `unreadable == (b,)`, `problems[-1] == ProjectFileProblem("not readable", "b.s19", "not an S19 or HEX file")`, `install.variant.variant_id == "a"`, `image.path.name == "a.s19"`, both parses on the same non-main thread (5 of 5). Negative control: the fallback loop moved to the install handler → the second parse records main → RED.
examples: P1-24 (post-10 C58 on the worker) `A2LONLY` with `app_module.parse_a2l_file` patched to raise `ValueError("synthetic")` → `refusal == "No supported files in project: A2LONLY"`, `problems` holds `("not readable", "cal.a2l", "the file cannot be read")`, `a2l_cache is None`, `document is None` (the reopen does not run on a refusal) (4 of 4).
examples: P1-25 (LLR-177.1e, AST census, fixed S-b list) over `_project_load_worker`, `_prepare_project_load`, `_parse_data_file`, `_load_mac_file`, `_merge_mac_with_existing_primary`, `_merge_primary_with_existing_mac`, `_log_loaded_file_summary`, `_flush_logger` and the module function `parse_a2l_cached`: 0 `Attribute` reads on `self` of `current_file`, `current_project`, `current_project_dir`, `current_a2l_path`, `current_a2l_data`, `_variant_set`, `_change_service`, `_a2l_cache_key`, `_a2l_cache_data`, `_declared_regions`, `_last_template_path`, `_parsed_paste_text`, `workarea`, `base_dir` (1 census, 0 hits); `_project_load_worker` has 1 parameter after `self`, annotated `ProjectLoadRequest`, a frozen dataclass (1 assertion). Negative control: the base `_parse_loaded_file` body inside the worker → hits `current_a2l_path`, `current_a2l_data`, `current_file`, `current_project` (`:15140`–`:15193`) → RED.

S19TuiApp._on_project_loaded
req: LLR-176.3, LLR-177.1g, LLR-177.3h, LLR-177.4c
in: PreparedProjectLoad prepared
out: None
func: new (fixed S-g). Main thread, reached through `call_from_thread`. `gen = prepared.request.gen`.
- `prepared.refusal is not None` → `self._quit_pending = False` (E3 S12b-01); `self.end_busy("project_load", gen, prepared.refusal)` — the end tail is the only statement of this arm; 0 resets, nothing installed (post-10 C58).
- Else `self.step_busy("project_load", gen, 4)` (paints `Install` synchronously, 12a) then `self.call_after_refresh(self._install_prepared_project, prepared)` (LLR-176.3: the step name is on screen before the install's work starts; the `:8708` idiom). It returns at once, so the worker's `call_from_thread` returns and the thread ends; the run stays open until the install's end tail.
callers: `_project_load_worker` through `call_from_thread`.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._busy] (step 4, or the end)
examples: P1-26 (LLR-176.3, project install step) a spy on `step_busy` that, when `n == 4` for `project_load`, schedules `probe` with `app.call_after_refresh`; `probe` records T and whether `_install_prepared_project` has started (a flag set at its first line) → for `P6`, T matches `^[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏] Loading project P6  ·  step 4/4 Install  ·  \d\d:\d\d$` and the flag is `False`; for `P2` the same (2 equalities, the E1 "+ 1" small arm). Negative control: a mutation that calls `self._install_prepared_project(prepared)` directly → the install runs before `probe` → `probe` reads `Loaded project 'P6' -> firmware.s19 + firmware.mac` and flag `True` → RED.
examples: P1-27 (post-10 C58, LLR-177.1g failure arm, LLR-177.3h) image `fw.s19` loaded and 2 Patch Editor entries; `A2LONLY` with the A2L parse raising → `log_lines[-1] == "No supported files in project: A2LONLY"`, `_reset_project_session` spy 0, `current_file.path.name == "fw.s19"`, 2 entries kept, `app._busy.runs == {}`; then `l` opens the Load dialog (P-2's refusal no longer fires) (6 of 6).

S19TuiApp._install_prepared_project
req: LLR-177.1f, LLR-177.1g, LLR-177.1h, LLR-177.1d, LLR-178.3, LLR-178.2, LLR-165.1, LLR-177.4c, LLR-176.1j
in: PreparedProjectLoad prepared
out: None
func: new (fixed S-g), one main-thread callback with no `await`. `request = prepared.request`; `gen = request.gen`. The whole body sits in `try: … except BaseException: self._busy_fail("project_load", gen); raise` (it runs from `call_after_refresh`, outside the worker's `call_from_thread`, so it needs its own guard). Steps, in the base order:
- (1) `self._reset_project_session()` — the one call site (LLR-165.1 §C.1, LLR-177.1g: after the worker step, before the first install).
- (2) `self._declared_regions = tuple(manifest.declared_regions) if manifest is not None else ()`.
- (3) `prepared.a2l_cache is not None` → `self._store_a2l_cache(prepared.a2l_cache)`.
- (4) A2L-only (`install.variant is None and install.mac is None`): `current_a2l_path = install.a2l`; `current_a2l_data = prepared.a2l_cache[1] if prepared.a2l_cache is not None else None` (E3 A12b-04); `update_a2l_view()`; `_refresh_loaded_panel()`; `_apply_empty_state()` (the tag-table build runs inside step 4, painted first).
- (5) `self._reopen_active_document(prepared.document)`.
- (6) `self.current_project = request.name`; `self.current_project_dir = request.project_dir` (unresolved, SEC-1); `self._variant_set = prepared.variant_set`.
- (7) Image: when `prepared.image` is set: `self._pending_variant_id = install.variant.variant_id`; `self._apply_loaded_file(prepared.image, install.variant.path, time.perf_counter())`.
- (8) MAC: when `prepared.mac` is set: `self._apply_loaded_file(prepared.mac, install.mac, time.perf_counter())` — two installs, image then MAC (fixed Q-g1; TC-B100-08's `["reset", "install", "install"]` holds).
- (9) `loaded = self.current_file`; `announcement = compose_load_announcement(request.name, prepared.variant_set, prepared.manifest, mac_name=…, a2l_name=…, problems=list(prepared.problems), unreadable=[v.path.name for v in prepared.unreadable])`; `self._last_load_announcement = announcement`; `self.set_file_status(safe_text(announcement.status_line()).plain)` (12a: stored as the file state while the run exists).
- (10) `self.logger.info("Project loaded. name=%s file=%s mac=%s", …)`; `self.update_project_labels()`; `self._publish_flow_session_dir()`.
- (11) `request.routed` → `self.push_screen(LoadResultScreen(announcement), self._handle_load_result)` (LLR-177.1h).
- (12) The end tail, **last**: `self.end_busy("project_load", gen, safe_text(announcement.summary_line()).plain)` — the summary is the outcome (12a A12-42); 12a's last end paints the stored file state. No `_finish_session_action` and no `final_line` (E3 DF-1 / P2-1).
- Because `current_project` and `_last_load_announcement` are set in this one callback, the 159 W-class test polls on `current_project == name` see a complete install (fixed S-g).
callers: `_on_project_loaded` through `call_after_refresh`.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.current_project] (replace), [Data: S19TuiApp.current_file] (replace, through `_apply_loaded_file`), [Data: S19TuiApp._a2l_cache_key] (through `_store_a2l_cache`), [UI: App.screen_stack] (push when routed)
examples: P1-28 (LLR-177.1f, LLR-178.2) `P2` through `_handle_load_project("P2")`, then `wait_for_complete()` and 2 pauses (the fixed Q6 helper) → session digest `D2`; the status-log lines added are `['Loaded firmware.s19 (S19 only)', 'Loaded firmware.mac (S19+MAC)', "Loaded project 'P2' -> firmware.s19 + firmware.mac - variant 1 of 1, 1 problem - details: p"]` (probe U1 / U2; the two image lines go through `_append_log_line`); T reads `Loaded project 'P2' -> firmware.s19 + firmware.mac`; `current_file.variant_id == "firmware"`; `app._busy.runs == {}`; 0 active timers (6 of 6). `P6` → digest `D6` (1). Negative control: the planned base-digest arm is now executed (baseline p12b U1: `D2`, `D6`); a mutation that installs `mac` before `image` → the image install replaces the merged MAC → digest MAC path `None` → RED.
examples: P1-29 (LLR-177.1g order, 3 of 3) a call-order spy over the end of `_prepare_project_load` (worker), `_reset_project_session` (thread recorded) and `_apply_loaded_file` → events `["worker_end", "reset@main", "install", "install"]` for `P2`. A `PermissionError` forced into `read_project_manifest` → 0 resets (1). Negative control: a mutation that resets in `_handle_load_project` before the worker starts → the forced-failure arm leaves `current_file is None` and 0 entries → RED.
examples: P1-30 (TC-B100-08 holds, fixed Q-g1) `test_tc_b100_08_reset_runs_once_before_the_first_install` (`:197`): two loads of an S19 + MAC project → events `["reset", "install", "install"] * 2` (1 sequence equality). Negative control: one merged install → `["reset", "install"] * 2` → RED (the reason Q-g1 keeps two installs).
examples: P1-31 (LLR-177.1h, LLR-178.3) the Load dialog `P6` row, `enter`, with `read_project_manifest` held on a forced slow step → 0 `LoadResultScreen` on the stack while held; released → after the install exactly 1 `LoadResultScreen` (2 of 2). A typed absolute `<W>\P2` in the Load dialog → 1 panel after the install (1). `_handle_load_project("P2")` directly → 0 panels (LLR-174.3b) (1). Result 4 of 4. Negative control: the base `_route_load_project` identity check after the call (`:7478`–`:7482`) → the worker has not composed the announcement when the call returns → 0 panels → RED.
examples: P1-32 (LLR-177.1d, project load, 2 of the 6 runs) a test subclass whose `__setattr__` records `(name, thread)` and spies on `ChangeService` methods that change state (`document` setter through `_reopen_active_document`, `mark_saved`, `set_image_generation`) during a `P2` load with a recorded document and during a `P2` load with `read_project_manifest` raising → 0 records off main in both runs (2 of 2). Negative control: the base body moved into the worker unchanged → `current_file`, `current_project`, `_a2l_cache_key` … (baseline p12b U4, 49 names) recorded off main → RED.
examples: P1-33 (LLR-177.4c, project arm, end tail last; seam X-8) `P6` with `read_project_manifest` held, `q` → the quit question (P-2), `y` → the app still running while held; released → a spy on `App.exit` records, at its call, `current_project == "P6"`, `_last_load_announcement is not None`, the summary line already in `log_lines`, and 1 `LoadResultScreen` pushed (routed through the dialog); the app exits with 0 exceptions logged (5 of 5). Negative control: a mutation that puts the end tail before step (9) → `exit` sees `_last_load_announcement is None` → RED.
examples: P1-34 (LLR-176.1l, install raise) `S19TuiApp._apply_loaded_file` patched to raise `RuntimeError("forced")` → the guard posts the failure end: the `end_busy` spy records `("project_load", g, "Loading project P2 failed")` → `True`, then the exception reaches Textual from the `call_after_refresh` callback and `run_test` raises it (loud, as the same defect does on base inside a synchronous load); 0 active timers recorded in the end spy (3 of 3). Negative control: the guard removed → the run stays open with its timer → RED.

S19TuiApp._on_project_load_failed
req: LLR-177.2, LLR-177.3h, LLR-177.4c
in: ProjectLoadRequest request; BaseException exc
out: None
func: new (fixed S-b). Main thread. `self.logger.warning("Project load not installed: %r (%s)", request.name, type(exc).__name__)` (the traceback was logged on the worker); `self._quit_pending = False` (E3 S12b-01: a failed load keeps the app running so the failure line is the last log line); the end tail with the `could not be read` sentence as the outcome: `self.end_busy("project_load", request.gen, safe_text(f"Project NOT loaded: '{pn(request.name)}' could not be read — check that the folder can be opened, then load again.").plain)` (the sentence 12a S-k composes from `_TYPED_REFUSAL_TOKENS["unreadable"]`; character-for-character the same). No reset, no session write.
callers: `_project_load_worker` through `call_from_thread`.
module: s19_app/tui/app.py
examples: P1-35 (LLR-177.2, 2 × 4) `fw.s19` open with 1 Patch Editor entry; `app_module.read_project_manifest` patched to raise `PermissionError("synthetic")`, then (fresh app) `ValueError("synthetic")`; `_handle_load_project("P2")`, then wait → each: `log_lines[-1] == "Project NOT loaded: 'P2' could not be read — check that the folder can be opened, then load again."`, the session digest equal to the digest before the request, `_reset_project_session` spy 0, the app running and `app._busy.runs == {}` (the indicator ended). 1 logged traceback per arm (`Project load failed on the worker`). Negative control: executed P12b-2 (an exception escaping a `@work(thread=True)` body ends the app, `WorkerFailed`, return code 1) → RED; a mutation with no inner `except` → the same.
examples: P1-36 (LLR-177.3h, the three exits) after a `P2` load ending by success (P1-28), by the A2L-only refusal (P1-27) and by the forced exception (P1-35) → `l` opens the Load dialog each time (3 of 3; P-2's refusal reads `app._busy.runs`, empty after each end tail). Negative control: a mutation that ends the failure arm with `step_busy` only → `project_load` stays in `runs` → `l` paints the busy line → RED.

S19TuiApp._route_load_project
req: LLR-177.1h, LLR-178.3, LLR-174.4
in: str name
out: None
func: changed (post-10 body, fixed S-e). `self._confirm_then_load("project", name, lambda: self._handle_load_project(name, routed=True))`. The base `before` / identity test and the push after the call are deleted; the install handler pushes the panel (P1-31). P-2's `_confirm_then_load` refuses while busy before it asks (LLR-177.3a, seam X-6).
callers: `_handle_load_dialog` (`project`, deferred; post-9b); `_load_path_from_user_input` (project arm; baseline extractor: unmarked site :12936). Tests: `test_b100_project_homes.py:1117`, `:1154`, `:1945` (they now wait for the install before reading the panel).
module: s19_app/tui/app.py
examples: P1-37 (LLR-177.1h) AST of `_route_load_project`: 0 reads of `_last_load_announcement`, 0 `push_screen` calls, 1 call of `_confirm_then_load` whose third argument calls `_handle_load_project` with `routed=True` (3 of 3). Negative control: the base body → 2 reads and 1 push → RED.
examples: P1-38 (9b probe p9b U8 shape, holds after 12b) project `[b]P`: the Load dialog row, `enter`, wait → 1 `LoadResultScreen` after the install; `current_project == "[b]P"` (2 of 2).

S19TuiApp._install_project_image
req: LLR-177.1, LLR-177.1d
in: VariantDescriptor variant; Sequence[Path] a2l_files
out: Optional[str] reason
func: **retired** (E1 A6 "may dissolve"). Its parse and reason half is step (8) of `_prepare_project_load`; its `_pending_variant_id` write and `_apply_loaded_file` call are step (7) of `_install_prepared_project`. No product or test caller remains (tests reference it only in a comment, `test_b100_session_reset.py:208`, and in the C5 census list).
callers: none after 12b (base: `_handle_load_project` :11903).
module: s19_app/tui/app.py
examples: P1-39 (retirement, C5 re-pin) AST of `app.py`: no `FunctionDef` named `_install_project_image`; the `_parse_loaded_file` call sites are exactly `["_start_load_worker", "load_selected_file"]` and the `_parse_data_file` call sites exactly `["_parse_loaded_file", "_prepare_project_load"]` (`test_tui_variants.py::test_no_new_parse_loaded_file_call_sites` re-pinned to both lists) (3 of 3). Negative control: a third parse caller on the UI thread (for example an install handler that parses) → the census lists it → RED.

S19TuiApp._reopen_active_document
req: LLR-170.3, LLR-177.1d
in: Optional[RecordedDocumentState] state
out: None
func: changed (`:11963`), the main-thread install half. `state is None or state.outcome != DOCUMENT_OK` → return. Else `self._change_service.document = state.document` (its `source_path` was set by the worker); `panel = self.query_one("#patch_editor_panel", PatchEditorPanel)` (a not-mounted tree → return, as `:12036`); `panel.mark_loaded()`; `self._patch_editor_load_tail(panel)`. The read, the problem and the warning moved to `_prepare_project_load` step (6). Signature changes from `(project_dir, manifest, a2l_context) -> Optional[ProjectFileProblem]` to `(state) -> None`; no test calls it (C17 grep: 0).
callers: `_install_prepared_project` step (5).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._change_service] (document)
examples: P1-40 (LLR-170.3 on the worker path) a project `PD` whose `project.json` records `active_document` `patches/changes.json` with 2 entries → after the load `len(app._change_service.document.entries) == 2`, `document.source_path == (W/PD).absolute()/"patches"/"changes.json"`, the panel paints 2 entries, 0 problems for the document; `recorded_document_state` ran on a non-main thread and the `document` assignment on main (5 of 5). A `changes.json` of 2 MiB (over `REOPEN_MAX_BYTES`) → 0 entries installed and 1 `not readable` problem named in the announcement (holds the base text) (2 of 2).

S19TuiApp._parse_loaded_file
req: LLR-177.1d (Q-h1), LLR-177.1k (consumed by P-2), LLR-005.4
in: Path path; Optional[list[Path]] a2l_files = None; keyword-only Optional[list[A2LCacheEntry]] a2l_cache_out = None
out: Optional[LoadedFile] loaded
func: changed (`:15099`), the session-reading wrapper of `_parse_data_file`. Steps:
- (1) The base INFO line `Loading file: path=%s suffix=%s project=%s` (reads `self.current_project`, as today).
- (2) `a2l_path = a2l_files[0] if a2l_files else self.current_a2l_path`.
- (3) `a2l_path` set → `entry = parse_a2l_cached(a2l_path, self._a2l_cache_entry())`; `a2l_data = entry[1]`; `a2l_cache_out.append(entry)` when the list is given (it never stores: Q-h1, the caller stores on main). `a2l_path` unset → `a2l_data = self.current_a2l_data`.
- (4) `return self._parse_data_file(path, a2l_path, a2l_data, self.current_file)` (the merge target is the live session, as on base: the file load merges a new file with what is open).
- It keeps reading the session when it runs on the file-load worker, as it does today (that worker is outside LLR-177.1e's three workers; finding F-6). It writes no attribute.
callers: `_start_load_worker` (P-2 passes `a2l_cache_out`, seam X-5); `load_selected_file`; direct test calls (`test_tui_a2l_detail.py:168`, `test_tui_a2l_issue_recolor.py:158`, `:694`, `test_tui_app.py:638`, `:703`, `:1217`, `test_validation_service_supplemental.py:151`, `:567`, `:605`).
module: s19_app/tui/app.py
examples: P1-41 (Q-h1, LLR-177.1d file-load arm) case_01 `firmware.a2l` attached (cache stored on main by P-2's handler), then `load_from_path(case_01/firmware.s19)` → the `__setattr__` recorder sees 0 writes of `_a2l_cache_key` / `_a2l_cache_data` off main; `app_module.parse_a2l_file` spy 0 calls (a hit through the out-list entry); `current_file.a2l_data is app._a2l_cache_data` after the install (3 of 3). Negative control: the base body (`_load_a2l_data_with_cache` on the file-load worker, `:15151`) → 2 off-main writes → RED.
examples: P1-42 (U2 behaviour kept for the file load) with `p1img.s19` open, `app._parse_loaded_file(P2/firmware.mac, [P2/firmware.a2l])` on main → `file_type == "s19"`, `path.name == "p1img.s19"`, `mac_path.name == "firmware.mac"` (holds on base, baseline p12b U2): the file load still merges a MAC onto the open image, which is the base behaviour of a loose MAC load; only the project worker passes its own image (3 of 3).
examples: P1-43 (merge tests through the wrapper) `test_tui_app.py::test_parse_loaded_file_mac_after_s19_preserves_both` (`:607`) and `::test_parse_loaded_file_primary_after_mac_keeps_mac_payload` (`:649`) pass after their `_load_mac_file` lambdas are re-pinned to `lambda path, *args, **kwargs: mac_loaded` (census P1-C2) (2 of 2). Negative control: a wrapper that passes `existing=None` → the MAC is not merged onto the open S19 → RED.

S19TuiApp._parse_data_file
req: LLR-177.1e, LLR-177.1f, LLR-177.1
in: Path path; Optional[Path] a2l_path; Optional[dict] a2l_data; Optional[LoadedFile] existing
out: Optional[LoadedFile] loaded
func: new (E1 A8), the explicit-input core: the base suffix dispatch of `_parse_loaded_file` (`:15135`–`:15226`) with every session read replaced by an argument:
- S19 → `loaded = build_loaded_s19(path, S19File(str(path)), a2l_path, a2l_data)`; `loaded = self._merge_primary_with_existing_mac(loaded, existing)`;
- HEX → the same with `IntelHexFile` / `build_loaded_hex`;
- MAC → `mac = self._load_mac_file(path, a2l_path, a2l_data)`; `loaded = self._merge_mac_with_existing_primary(mac, existing)`; the `mac_merge_entry` log reads `existing` (not `self.current_file`);
- else `None`.
- The phase-boundary logs, `_log_loaded_file_summary` and `_flush_logger` are kept (they read only `self.logger`). It reads no session attribute and writes none.
callers: `_parse_loaded_file`; `_prepare_project_load` (image loop and MAC).
module: s19_app/tui/app.py
examples: P1-44 (LLR-177.1e) with `p1img.s19` open in the app, `app._parse_data_file(P2/firmware.mac, P2/firmware.a2l, data, None)` → `file_type == "mac"`, `path.name == "firmware.mac"` (no merge, whatever `current_file` holds); with `existing=image` (the worker's `P2/firmware.s19` parse) → `file_type == "s19"`, `path.name == "firmware.s19"`, `path.parent.name == "P2"`, `mem_map is image.mem_map` (5 of 5). Negative control: a core that reads `self.current_file` → the first arm returns `p1img.s19` → RED (the U2 hazard).

S19TuiApp._load_mac_file
req: LLR-177.1e
in: Path path; Optional[Path] a2l_path; Optional[dict] a2l_data
out: LoadedFile loaded
func: changed (`:14140`). The base body with `a2l_path` and `a2l_data` taken as arguments: the lines `a2l_path = a2l_files[0] if a2l_files else self.current_a2l_path` (`:14210`) and `a2l_data = self._load_a2l_data_with_cache(a2l_path) if a2l_path else self.current_a2l_data` (`:14217`) go; the `mac_a2l_resolve_*` log lines report the given values. No session read, no cache write.
callers: `_parse_data_file` (MAC branch). Tests monkeypatch it (`test_tui_app.py:226`, `:636`, re-pinned, census P1-C2).
module: s19_app/tui/app.py
examples: P1-45 `app._load_mac_file(P2/firmware.mac, None, None)` with an A2L attached in the app → `a2l_path is None` and `a2l_data is None` on the result (the session's A2L is not picked up) (2 of 2). Negative control: the base fallback kept → `a2l_path == current_a2l_path` → RED.

S19TuiApp._merge_mac_with_existing_primary
req: LLR-177.1e, LLR-177.1f
in: LoadedFile mac_loaded; Optional[LoadedFile] existing
out: LoadedFile merged
func: changed (`:14425`). `existing = self.current_file` (`:14447`) becomes the parameter; the merge rule is unchanged (no S19 / HEX primary → the MAC as is; else the primary's image, `variant_id`, entropy, S0 header with the MAC's records, `a2l_path or`, `a2l_data or`). It reads no `self` attribute.
callers: `_parse_data_file`. Tests call it directly with one argument (`test_memmap_entropy_merge.py:85`, `test_tui_workspace_insight.py:279`; re-pinned to pass `app.current_file`, census P1-C3).
module: s19_app/tui/app.py
examples: P1-46 (LLR-177.1f, finding F-1 mechanism) `merged = app._merge_mac_with_existing_primary(mac, image)` with `image.variant_id = "firmware"` → `merged.variant_id == "firmware"`, `merged.mem_map is image.mem_map`, `merged.entropy_windows == image.entropy_windows`; with `image.variant_id = None` → `merged.variant_id is None` (probe U1 arm B) (4 of 4).

S19TuiApp._merge_primary_with_existing_mac
req: LLR-177.1e
in: LoadedFile primary_loaded; Optional[LoadedFile] existing
out: LoadedFile merged
func: changed (`:14371`). `existing = self.current_file` (`:14393`) becomes the parameter; the rule is unchanged (no existing MAC → the primary as is).
callers: `_parse_data_file` (S19 / HEX branches). Tests: `test_tui_app.py:274`, `test_memmap_entropy_merge.py:71`, `:101` (re-pinned, census P1-C3).
module: s19_app/tui/app.py
examples: P1-47 `app._merge_primary_with_existing_mac(primary, None)` → `is primary`; with `existing` a MAC-only `LoadedFile` → `mac_path == existing.mac_path`, `mem_map is primary.mem_map` (3 of 3; the base examples of `test_tui_app.py:246` hold with the argument added).

PreparedLoad
req: LLR-177.1d (Q-h1)
in:
out: dataclass
func: changed (`:563`, fixed Q-h1: "`PreparedLoad` gains one field"): `a2l_cache: Optional[A2LCacheEntry] = None`, last, with a default so `PreparedLoad(loaded=loaded)` (`_apply_loaded_file`, `test_tui_app.py:1355`) is unchanged. P-2's `_start_load_worker` fills it from the `a2l_cache_out` list (seam X-5).
callers: `_prepare_load_payload` / `_start_load_worker` (P-2); `_apply_prepared_load`; `_apply_loaded_file`.
module: s19_app/tui/app.py
examples: P1-48 `PreparedLoad(loaded=lf).a2l_cache is None` (1 assertion; the 1-argument construction holds).

S19TuiApp._apply_prepared_load
req: LLR-177.1d (Q-h1)
in: PreparedLoad prepared; Path path; float load_started
out: None
func: changed (`:15291`) by one statement at the top: `if prepared.a2l_cache is not None: self._store_a2l_cache(prepared.a2l_cache)`. Main thread. Everything else unchanged.
callers: `_start_load_worker` (through `call_from_thread`); `_apply_loaded_file` (the project install, `load_selected_file`).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._a2l_cache_key] (through `_store_a2l_cache`)
examples: P1-41 above (the file-load arm stores on main). P1-49 the project install passes `PreparedLoad(loaded=…)` with no cache → `_store_a2l_cache` is called once per project load, from step (3), not from the two installs (a spy counts 1) (1 assertion).

S19TuiApp.load_selected_file
req: LLR-177.1d
in: Path path; Optional[list[Path]] a2l_files = None
out: None
func: changed (`:15047`) by the cache hand-off: `out: list[A2LCacheEntry] = []`; `loaded = self._parse_loaded_file(path, a2l_files, a2l_cache_out=out)`; after the parse succeeded, `if out: self._store_a2l_cache(out[0])` (main thread, so its cache behaviour equals the base). After 12b it has **no product caller** (the project MAC install moved to the worker, the work-area pick to P-2's file-load start) — finding F-4, proposal PR-6.
callers: none in `s19_app/` after 12b; 88 direct test calls.
module: s19_app/tui/app.py
examples: P1-50 two `load_selected_file(case_01/firmware.s19, [case_01/firmware.a2l])` calls on main → `app_module.parse_a2l_file` spy 1 call (the second is a cache hit through the stored entry) (holds on base, 1 assertion). Negative control: a mutation that drops the store → 2 calls → RED.

SaveImageInput
req: LLR-177.1e, LLR-177.1i
in:
out: frozen dataclass
func: new (fixed S-b), the fixed fields: `derived` (`prepared.image_step.derived`, re-derived on main by Inc 11's session, ruling Q1), `ranges` (`tuple(current_file.ranges)`), `file_type`, `s0_header` (`current_file.source_s0_header`), `source_path` (`current_file.path`), `summary` (`prepared.image_step.summary`), `applied`, `not_applied` (the `record_save_entries()` result taken on main). The worker never writes `summary` (the handler stamps it, Q-b2).
callers: `_commit_project_save` (builds, only when emitting); `_save_project_files` (emit); `_on_project_saved` (adopt and stamp).
module: s19_app/tui/app.py
examples: P1-51 (LLR-177.1e) a patched `firmware.s19` session saved as `Q` → the request's `image.ranges == tuple(app.current_file.ranges)`, `image.derived is prepared.image_step.derived`, `image.applied == app._change_service.last_save_applied` (3 of 3); a copy-only save → `request.image is None` (1).

SaveRequest
req: LLR-177.1e, LLR-177.1a
in:
out: frozen dataclass
func: new (fixed S-b), the fixed fields: `prepared`, `payload`, `image`, `document_kind`, `document_source_path`, `document_class` (`classify_active_document(prepared.project_dir, source, home)[0]`, a pure path-text test, so taking it before the `mkdir` gives the base value), `document_snapshot` (`copy.deepcopy(document)` when `document.source_path is None and document.entries` — exactly when the plan holds the pasted document row (`_plan_project_save` `:10871`–`:10881`) or the "was not saved" line can apply — else `None`; E3 S12b-05 replaces the serialised `document_bytes`), `declared_regions` (`tuple(self._declared_regions)`), `active_template` (`self._last_template_path`), `workarea`, `base_dir`, `gen`.
callers: `_commit_project_save` (builds); `_save_project_files`, `_save_failure_outcome`, `_on_project_saved` (read).
module: s19_app/tui/app.py
examples: P1-52 (LLR-177.1e) frozen (assignment raises `FrozenInstanceError`); for a session with 1 pasted entry, `document_snapshot` is not `app._change_service.document` (a deep copy), `serialize_change_document(request.document_snapshot)` equals `serialize_change_document(app._change_service.document)` and its SHA-256 equals the plan's document row digest (`row.sha256`); for a file-backed document `document_snapshot is None` and `document_source_path == document.source_path` (5 of 5).

SaveOutcome
req: LLR-177.1d, LLR-177.1j, LLR-177.2a
in:
out: frozen dataclass
func: new (fixed S-b) with the fixed fields used this way: `request`; `committed`; `lines` and `outcome` — the failure lines in base order (`outcome` the last of them, `lines` those before it; the commit arm leaves both empty, E3 S12b-03); `toast` (`Optional[tuple[str, str]]`, title and text, E3 DF-4 / PR-1); `variant_set`, `saved_variant_id`; `verify_result` (the manifest verify); `emit_verify` (the image verify, Q-b2; its `written_path` is the emitted file); `document_source_path` (the rebinding, or `None` for no change); `pasted_placed`; `recorded_document: Optional[str]` (the panel's dirty-line condition, E3 DF-5 / PR-2). The committed-tail **facts** (E3 S12b-03), returned for `_on_project_saved` to compose the tail on the main thread: `kept_note: Optional[str]`, `skipped_links: Optional[str]`, `source_gone: Optional[str]`, `unrecorded_names: tuple[str, ...]`, `document_lines: tuple[str, ...]`. `unrecorded` is dropped (E3 DF-6 / PR-3); the raw names return as `unrecorded_names` because S12b-03 needs them on the main thread.
callers: `_save_project_files`, `_save_failure_outcome`, `_save_project_worker` (build); `_on_project_saved` (read).
module: s19_app/tui/app.py
examples: P1-53 the committed copy-only save of `P2` as `Q` → `committed is True`, `lines == ()`, `outcome == ""`, `toast is None`, `saved_variant_id == "firmware"`, `verify_result.status == MANIFEST_VERIFIED`, `emit_verify is None`, `document_source_path is None`, `pasted_placed is False`, `recorded_document is None`, `unrecorded_names == ()` (11 of 11; the outcome line `Saved project to …` is composed by the handler, probe U2 line).

S19TuiApp._commit_project_save
req: LLR-177.1a, LLR-177.1i, HLR-177a (Q-a1), LLR-176.2d, LLR-176.1l
in: _PreparedSave prepared; SaveProjectPayload payload
out: None
func: changed (post-11 name and signature kept; fixed S-b): the main-thread kickoff. Steps:
- (0) `if self._refuse_if_busy(): return` (fixed Q-a1).
- (1) `gen = self._busy_begin_action("save_project", prepared.cleaned)` (12a; step 1 `Create the folder`).
- (2) `try:` — the image input, only when `prepared.image_step.emit and any(row.role == "image" for row in prepared.plan.rows)` (the base condition under which the rows loop records and emits): `applied, not_applied = self._change_service.record_save_entries()` (a service write on main, LLR-177.1d); `SaveImageInput(…)` from `self.current_file` and `prepared.image_step`. The document facts: `document = self._change_service.document`, `home = document_home_for_kind(document.kind)`, `document_class`, `document_snapshot = copy.deepcopy(document)` when `document.source_path is None and document.entries` else `None` (E3 S12b-05). `request = SaveRequest(prepared, payload, image_input, document.kind, document.source_path, document_class, document_snapshot, tuple(self._declared_regions), self._last_template_path, self.workarea, self.base_dir, gen)`; `self._save_project_worker(request)`.
- `except BaseException: self._busy_fail("save_project", gen); raise` (S-d kickoff guard; replaces 12a's `finally`).
- The re-derive stays in Inc 11's `_save_session_inputs` → `_decide_project_image`, on main, before this function (ruling Q1, LLR-177.1i). Every Inc 11 refusal returns in `_handle_save_dialog` before this function, so a refused save begins nothing and creates no folder.
callers: `_handle_save_dialog` (router step 6). One no-app test reaches it (census A11, re-pinned inside `run_test` and waiting).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._busy] (begin)
examples: P1-54 (LLR-177.1a, preparation refusals before any worker, 10 of 10) the Inc 11 refusals through `_handle_save_dialog`: empty name, device name `CON`, reserved `temp`, a 300-character name, a path separator `a/b`, a clash with an existing differently-cased project, a link at the target, a missing session source, a plan refusal, and free space short (`shutil.disk_usage` patched) → each paints its Inc 11 line, `_save_project_worker` spy 0, `_busy_begin_action` spy 0, 0 new folders under `W` (each × 3). Negative control: a mutation that begins in the router before the preparation → each refusal shows 1 begin → RED.
examples: P1-55 (LLR-177.1i, order 2 + 2) an emitting save of a patched `firmware.s19` through the dialog → spies on `ChangeService.rederive_for_save` and `app_module.render_patched_image` each record main, and both precede the `_save_project_worker` call in a shared order log (4 assertions). Copy-only save → 0 calls of each (boundary). Negative control: a mutation that re-derives inside `_save_project_files` → the thread arm RED, and P1-66's AST census names `self._change_service` → RED.
examples: P1-56 (fixed Q-a1, seam X-7) with a `project_load` run held (`Loading project P6`), `_handle_save_dialog(SaveProjectPayload(str(W), "Q"))` → the preparation runs (writes nothing), then `log_lines[-1] == "busy: Loading project P6 is running — wait for it to finish."`, 0 `save_project` begins, `W/Q` absent (3 of 3).
examples: P1-57 (LLR-176.1l, the kickoff guard) `S19TuiApp._save_project_worker` patched to raise `RuntimeError("forced")` → the `end_busy` spy records `("save_project", g, "Saving project Q failed")` → `True`, `RuntimeError` leaves `_handle_save_dialog`, `W/Q` absent (the worker never ran), 0 active timers (4 of 4).

S19TuiApp._save_project_worker
req: LLR-177.1a, LLR-177.1c, LLR-177.2a, LLR-176.1l, LLR-176.1q, LLR-164.4
in: SaveRequest request
out: None
func: new (fixed S-b / S-d). `@work(thread=True, group="save_project")`, not exclusive (E3 DF-2 / P2-4; default `exit_on_error=True`). Body:
- `try:` / `try: outcome = self._save_project_files(request)` / `except Exception as exc:` — a failure before the rollback `try` (the `mkdir` raising something other than `FileExistsError`; nothing was created): `self.logger.exception("Project save failed outside the rollback.")`; `message = "Project NOT saved: could not save — an unexpected error stopped the save. check the folder."` (E3 S12b-02: no `{exc}`; the traceback goes to the log, SEC7-5); `outcome = _save_failure_outcome(request, [message], ("Project not saved", message))`.
- `self.call_from_thread(self._on_project_saved, outcome)` (outside the inner `try`).
- `except BaseException: self.call_from_thread(self._busy_fail, "save_project", request.gen); raise`.
callers: `_commit_project_save`. Group `save_project` is used by no other worker.
module: s19_app/tui/app.py
examples: P1-58 (LLR-177.1a, 4 of 4) an emitting save of a patched session as new project `Q` → thread spies on `pathlib.Path.mkdir` (filtered to `W/Q`), `app_module.place_into_workarea`, `app_module.save_patched_image` and `app_module.write_project_manifest` each record non-main threads (4 of 4). Negative control: executed P12b-6 (`_handle_save_dialog('Q') … ran on main thread True`) → RED.
examples: P1-59 (LLR-177.1c, save arm) `app_module.place_into_workarea` held on a forced slow step for 1.5 s → a 0.1 s interval counter rises ≥ 10 during the hold (1 assertion). Negative control: executed P12b-6 (0 ticks; the save holds the main thread) → RED.
examples: P1-60 (LLR-164.4, TC-B100-07 worker arm: stage 1 of 5) `pathlib.Path.mkdir` patched to raise `PermissionError("synthetic")` for `W/Q` → `log_lines[-1] == "Project NOT saved: could not save — an unexpected error stopped the save. check the folder."` (E3 S12b-02: no `{exc}`), 1 toast titled `Project not saved`, `W/Q` absent, 0 raises out of the test's wait, the app running, `app._busy.runs == {}` (6 of 6). Negative control: a body with no inner `except` → the `PermissionError` escapes the worker → `WorkerFailed` → RED (base: the same `mkdir` error propagates out of `_handle_save_dialog`, `:9857`; executed P12b-2 shape).
examples: P1-61 (LLR-176.1l) `S19TuiApp._on_project_saved` patched to raise `RuntimeError("forced")` → the `end_busy` spy records `("save_project", g, "Saving project Q failed")` → `True` before `run_test` raises `WorkerFailed` (2 of 2).

S19TuiApp._save_project_files
req: LLR-177.1a, LLR-177.1e, LLR-177.1d, LLR-177.2a, LLR-177.5a, LLR-164.4, LLR-176.2d
in: SaveRequest request
out: SaveOutcome outcome
func: new, the worker step: the base commit half C1–C4 (`:9856`–`:10425`, post-11 body with Inc 11's (d) document rule) reading only `request`. Locals: `prepared = request.prepared`, `plan = prepared.plan`, `project_dir = prepared.project_dir`, `workarea = request.workarea`, `gen = request.gen`. Changes from the base:
- (Progress) **before** `mkdir` (E3 S12b-06: `total` depends only on `plan`, so nothing fallible sits between the `mkdir` and the rollback `try`): `total` = `len(plan.copies)` + the rows the loop places (`role` not manifest / carried, and not a file-backed document row); `forward = self._progress_forwarder("save_project", gen, 2)`; `tick()` adds 1 to a local count and calls `forward(count, total)` (LLR-177.5a; at most 101 forwards per step by the forwarder's percent rule).
- (C1) `mkdir(parents=True, exist_ok=False)` / `except FileExistsError` → `created_project_dir`, unchanged. Removed: `save_state` (B5), `document = self._change_service.document` and `classify_active_document` (from the request).
- (C3) First statement inside the rollback `try`: `self.call_from_thread(self.step_busy, "save_project", gen, 2)` (12a step 2). The sub-folder and top-level copies call `self._copy_project_subfolders(…, workarea=workarea, on_placed=tick)`. The rows loop: the pasted document row → `write_change_document(request.document_snapshot, request.base_dir, file_name="changes.json", copy_fn=_place, dest_dir=project_dir / document_home_for_kind(request.document_kind))` (tick on success; E3 S12b-05, the unchanged `changes/io.py` writer, no `_write_editor_document`; the retired `_write_editor_document`'s created-home detection stays inline and uses `os.path.lexists(home_dir)` — one `except OSError` after the `mkdir` per P1-66 — corrected at close: SR12b-4); the image row with `request.image` set → the emit with the direct calls (fixed Q-b2): `path, issues = save_patched_image(image.derived, image.ranges, project_dir, row.landing.name, source_kind=image.file_type, bytes_per_line=32, s0_header=image.s0_header, workarea_root=workarea, on_placed=_emit_landed)`, then, when `path` is set, `emit_verify = verify_written_image(path, image.derived, image.file_type)` (the base order inside `emit_and_verify`), then `path is None or not landed` → the emit abort with `detail = "; ".join(i.message for i in issues) or ("Patched image not saved - see issues" if path is None else f"Patched image saved as {path.name}{save_back_status_suffix(image.applied, image.not_applied)}")` (the base `emit_result.message` texts); `_emit_landed` appends the landing and ticks; other rows → `place_into_workarea(row.source, project_dir, workarea_root=workarea)` and tick.
- The base session writes inside the `try` become locals (E2 ruling "Base commit writes"): `_report_filter_path = None` is dropped here (the handler writes it on commit); `variant_set = build_variant_set(prepared.cleaned, saved_data_files)` / `None`, `saved_variant_id`, `variant_set.active_id = saved_variant_id`; `current_file.variant_id` is not touched (the handler writes it).
- Before `gather_project_artifacts`: `self.call_from_thread(self.step_busy, "save_project", gen, 3)`; the gather takes `active_document_kind=request.document_kind`, `active_template=request.active_template`, `common_patches_dir=workarea / WORKAREA_PATCHES`, `common_templates_dir=request.base_dir / WORKAREA_DIRNAME / WORKAREA_TEMPLATES`, `workarea_root=workarea`. The document-line rules read `request.document_source_path`, `request.document_class`, `request.document_snapshot is not None` (for "`document.entries` and no document row") and call `self._unrecorded_document_lines` (pure).
- Before the SEC7-3 keep: `self.call_from_thread(self.step_busy, "save_project", gen, 4)`; `self._keep_previous_manifest(manifest_path, manifest_previous, workarea)`.
- The manifest: `result, refusal = self._write_manifest_for_save(project_dir, variant_set, request.base_dir, batch=…, assignments=…, declared_regions=request.declared_regions, gathered=…, derived_from=…, active_document=recorded_document, on_written=_manifest_written)`; `refusal is not None` → the abort exit with lines `["Manifest write failed", "Project NOT saved: could not save — project.json was not written. check the folder."]` and toast `("Manifest write failed - project.json not written", refusal)` (the base writer's line and notice, then the base commit's line).
- Every abort exit (7 inside the `try`; the `WorkareaPlacementError`, `WorkareaContainmentError`, `OSError` arms; and the `except Exception` arm, ruling Q4) has the same shape: its base status text first, then `notes = self._abort_save(project_dir, created_project_dir, placed_files, created_dirs, workarea, manifest_restores[, kept_copies])`, then `return _save_failure_outcome(request, [text, *notes], toast)`; toasts as the base: placement error → `("Project not saved", str(exc))`, `OSError` → `("Project not saved", message)`, containment → none. The `except Exception` arm (Q4): `self.logger.exception("Project save failed with an unexpected error.")`, `message = "Project NOT saved: could not save — an unexpected error stopped the save. check the folder."` (E3 S12b-02: no `{exc}`, SEC7-5), toast `("Project not saved", message)`; **no `raise`** (re-pin of SEC-7, E1 LLR-177.2a).
- (C5, the worker part) after the `try`: the committed **facts only** (E3 S12b-03) — no text composition on the worker: `kept_note`, the skipped-links text, the `source_gone` text, `unrecorded_names = tuple(gather_outcome.unrecorded)`, the worker's document lines (raw), and `document_source_path` (computed from `pasted_placed`, `prepared.save_as_source`, `request.document_source_path`, `plan.copies`, `document_row`, `landed_document`, `recorded_document`; the base `:10521`–`:10554` path text plus Inc 11's (d)). `return SaveOutcome(request, True, (), "", None, variant_set, saved_variant_id, result, emit_verify, document_source_path, pasted_placed is not None, recorded_document, kept_note, skipped_links, source_gone, unrecorded_names, document_lines)`.
- It never paints, never notifies, never assigns an app attribute and never calls `self._change_service`; it reads `request`, `self.logger` and the helpers named here. After E3 S12b-03 it also composes no committed-tail text (the `safe_text` / `f"..."` work moves to `_on_project_saved`), so the outer catch only ever sees pre-`mkdir` failures.
callers: `_save_project_worker` only.
module: s19_app/tui/app.py
modify: [I/O: work area] (the only writer of the Save path)
examples: P1-62 (copy-only commit, probe U2 texts) `P2` loaded, `_handle_save_dialog(SaveProjectPayload(str(W), "Q"))`, wait → `W/Q` holds `firmware.a2l`, `firmware.mac`, `firmware.s19`, `project.json`; the status-log lines added are `['Project saved + manifest verified', f"Saved project to {W / 'Q'} (variant 'firmware')"]`; the step spy records `[2, 3, 4]` for `save_project`, each through `call_from_thread`; the plan places 3 rows and 0 copies (probe U3: rows `image firmware.s19`, `mac firmware.mac`, `a2l firmware.a2l`, `manifest project.json`; copies `[]`), so `total == 3`, the step-2 forwards are `(1, 3)`, `(2, 3)`, `(3, 3)` and the bar spy reads `[0, 25, 33, 41, 50, 50, 75, 0]` (`floor(100 × (1 + k/3) / 4)` within step 2, then step 3, step 4, the end) (3 assertions + 1 sequence). Negative control: executed P12a-1 / p12a U1.9 on base (no progress call in the save) → RED.
examples: P1-63 (LLR-177.5a, 4 files) save-as of the open `S` (case_01 trio plus `flows/f1.json`) as `S2` → `total == 4` (probe U3: copies `['flows/f1.json']`, then the 3 rows) → step-2 forwards `(1, 4)`, `(2, 4)`, `(3, 4)`, `(4, 4)` → bar `31, 37, 43, 50`, 4 increases within step 2, read on main (1 sequence). 2 000 files under `flows/` → ≥ 10 increases within step 2 (the forwarder sends at most 101) (1). Boundary: a save of only `firmware.s19` → `total == 1` → 1 forward `(1, 1)` → bar `50`, 1 increase (1). Result 3 of 3. Negative control: a mutation that reports only after the copies → 1 increase per step → RED.
examples: P1-64 (LLR-177.2a, 6 of 6) a patched session saved as `Q`, with `app_module.verify_written_image` patched to raise `ValueError("forced defect")` → after the wait: `W/Q` absent, the `W` tree digest equal to before, `log_lines[-1] == "Project NOT saved: could not save — an unexpected error stopped the save. check the folder."` (E3 S12b-02: no `{exc}`; the traceback `Project save failed with an unexpected error.` is logged, SEC7-5; no rollback note: nothing was left), 1 logged traceback, the app running, the session digest unchanged (the image map still the source bytes at the patched span). Re-pin of `test_tc_b100_17_non_os_error_after_the_emit_rolls_back_then_surfaces` (`:818`): `pytest.raises` goes, the patch target moves from `change_service_module` to `app_module` (census P1-C5), and the asserted line is re-pinned to the no-`{exc}` form. Negative control: code read, base `:10413`–`:10425` re-raises after the rollback; on a worker that raise ends the app (P12b-2) → RED.
examples: P1-65 (LLR-164.4, TC-B100-07 worker arms, stages 2–5) `OSError(28, "synthetic no space")` forced into, in turn, the sub-folder copy (`_copy_project_subfolders` on a save-as), a row placement (`app_module.place_into_workarea`), the gather (`app_module.gather_project_artifacts`) and the manifest write (`app_module.write_project_manifest`) → each: a line holding `could not save` and `check the folder` as `log_lines[-1]`, `W/<target>` absent (0 folders left), 0 raises, the app running (4 × 4). With P1-60 (the `mkdir` stage): 5 of 5. The placement arm reads exactly `Project NOT saved: could not save — [Errno 28] synthetic no space. check the folder.` with 1 toast `('Project not saved', <same>)` (probe U2: holds on base for the line and the toast). Negative control: a stage whose failure is not caught → `WorkerFailed` → RED.
examples: P1-66 (LLR-177.1e, Save census; TC-B100-07 re-pin) AST over `_save_project_worker`, `_save_project_files`, `_save_failure_outcome`, `_abort_save`, `_restore_manifest`, `_keep_previous_manifest`, `_copy_project_subfolders`, `_write_manifest_for_save`, `_unrecorded_document_lines`: 0 `self` reads of the 14 names of P1-25 (1 census); `_save_project_files` holds 0 `raise` after the `mkdir`, exactly 1 `except OSError` after the `mkdir`, and every `return` after the `mkdir` except the last (the committed outcome) follows an `_abort_save` call in the same block (the base TC-B100-07 rules re-pinned to this function, census C1) (3 assertions). Negative control: the SEC-7 `raise` kept → the no-`raise` arm RED.
examples: P1-67 (LLR-177.1d, Save, 2 of the 6 runs) the `__setattr__` recorder and the service spies during an emitting save and during the P1-64 failure → 0 app writes off main; `record_save_entries`, `adopt_rederived`, `mark_saved` (commit) recorded on main only; in the failure run 0 calls of `adopt_rederived` and 0 of `mark_saved` (3 assertions). Negative control: the base body on the worker → `_report_filter_path`, `_variant_set`, `current_project`, `current_project_dir`, `_last_manifest_verify_result` written off main (baseline p12b U4) → RED.

_save_failure_outcome
req: LLR-177.2a, LLR-164.4
in: SaveRequest request; Sequence[str] lines; Optional[tuple[str, str]] toast
out: SaveOutcome outcome
func: new (module level, pure). `SaveOutcome(request, False, tuple(lines[:-1]), lines[-1], toast, None, None, None, None, None, False, None, None, None, None, (), ())` (E3 DF-6 dropped `unrecorded`; `recorded_document` and the tail facts are `None` / empty on the failure arm). `lines` is never empty (every caller passes its base status text first), so the outcome is the last line in base order and a rollback note, when one exists, is the outcome (finding F-3).
callers: `_save_project_files` (11 abort exits); `_save_project_worker` (the outer catch).
module: s19_app/tui/app.py
examples: P1-68 (F-3, order kept) a failed save whose rollback keeps a file (a placed file swapped for a junction before the rollback, Windows only) → the lines added are `['Project NOT saved: could not save — …. check the folder.', 'Not removed after the failed save: … — a folder changed while saving; check the project folders.']` in that order and `log_lines[-1]` is the note (2 of 2; the base order, 12a finding F-7's lines unchanged).

S19TuiApp._on_project_saved
req: LLR-177.1d, LLR-177.1j, LLR-177.2a, LLR-167.2, LLR-177.4c, HLR-177c, LLR-175 (C53 / B11-70)
in: SaveOutcome outcome
out: None
func: new (fixed S-b), main thread, reached through `call_from_thread`. `request = outcome.request`; `prepared = request.prepared`; `gen = request.gen`.
- **Failure** (`not outcome.committed`): `self._quit_pending = False` (E3 S12b-01: a failed save keeps the app running, the failure line is the last log line); `for line in outcome.lines: self.set_status(safe_text(line).plain)` (E3 S12b-02); `outcome.toast` → `title, text = outcome.toast; self.notify(safe_text(text).plain, title=safe_text(title).plain, severity="error", timeout=10.0, markup=False)` (E3 S12b-02); the end tail, last: `self.end_busy("save_project", gen, safe_text(outcome.outcome).plain)`. Nothing is adopted and no session attribute changes (review F4, LLR-177.1j; E1 B5).
- **Commit**, in the base order:
  - (1) `self._report_filter_path = None`; `self._variant_set = outcome.variant_set`; `outcome.saved_variant_id and self.current_file` → `self.current_file.variant_id = outcome.saved_variant_id`; `self._last_manifest_verify_result = outcome.verify_result`.
  - (2) `outcome.verify_result is not None` → `self._surface_manifest_verify_result(outcome.verify_result)` (the writer's line, `Project saved + manifest verified` or `Manifest verify MISMATCH` + its notice, painted where the base writer painted it: before the tail).
  - (3) `mem_map = self.current_file.mem_map if self.current_file else None`; when `request.image` is set: stamp `summary.saved_path = outcome.emit_verify.written_path`, `summary.source_image_path = request.image.source_path`, `summary.verify_result = outcome.emit_verify` (what `emit_and_verify` wrote on the worker in the base, now on main, Q-b2); `self._change_service.adopt_rederived(mem_map, request.image.derived, summary)` (LLR-177.1j: after `project.json` is on disk); `self._surface_verify_result()`.
  - (4) `request.image is not None or not self._change_service.image_differs_from_source(mem_map)` → `self._change_service.mark_saved(mem_map)` (the base condition reads `image_step.emit`; equal, see `_commit_project_save` step 2).
  - (5) **Compose the committed tail on the main thread** (E3 S12b-03): `tail = [f"Saved project to {prepared.project_dir} (variant '{outcome.saved_variant_id}')" + (f" — {prepared.plan.image}" if request.image is not None else "")]`; then, from the facts, in base order: `safe_text(kept_note).plain`, the skipped-links line, the `source_gone` line, the unrecorded lines (`PAINTED_NAME_LIMIT`, then `and N more files not recorded in project.json`, composed from `outcome.unrecorded_names`), and the document lines (`safe_text(line).plain`). A defect in this composition raises on the main thread and stays loud (Q-d1 parity), never a false `Project NOT saved`. `document = self._change_service.document`; `outcome.document_source_path is not None` → `document.source_path = outcome.document_source_path`.
  - (6) The panel (the base `:10556`–`:10583`, post-10 `is_dirty`): `outcome.pasted_placed` → `self._patch_editor_load_tail(panel)`; `_save_clears_panel_flag(outcome.pasted_placed, paste_text, self._parsed_paste_text)` → `panel.mark_saved()`; elif `request.document_class == _DOCUMENT_IN_HOME and outcome.recorded_document is not None and panel.is_dirty` → `tail.append(f"Change document {document.source_path.name} has unsaved edits — the project records the file as it is on disk; save it from the Patch Editor to keep them")`.
  - (7) `outcome.verify_result is not None and outcome.verify_result.status != MANIFEST_VERIFIED` → `tail.append("Manifest verify MISMATCH")`.
  - (8) `for line in tail[:-1]: self.set_status(line)`.
  - (9) `self.current_project = prepared.cleaned`; `self.current_project_dir = prepared.project_dir`; `self.update_project_labels()`; `self.refresh_files()`; `prepared.save_as_source is not None` → `self._publish_flow_session_dir()`.
  - (10) The end tail, **last**: `self.end_busy("save_project", gen, tail[-1])`.
callers: `_save_project_worker` through `call_from_thread`.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.current_project] (replace), [Data: S19TuiApp._variant_set] (replace), [Data: S19TuiApp._last_manifest_verify_result] (replace)
examples: P1-69 (LLR-177.1j, LLR-167.2, 3 of 3) an emitting save of a patched `firmware.s19` (1 byte at `0x8000` changed) as `Q` → 1 `adopt_rederived` call, on main, whose time is after `W/Q/project.json` exists (the spy stats the file); after the wait the session map at `0x8000` equals the emitted file's byte; the lines added are, in order, `Project saved + manifest verified`, `f"Saved + verified: {landing}{save_back_status_suffix(applied, not_applied)}"` (the base `_surface_verify_result` text over the stamped summary) and `f"Saved project to {W / 'Q'} (variant 'firmware') — {prepared.plan.image}"` (3 assertions; the texts are composed by the unchanged base helpers and Inc 11's `plan.image`, so the TC reads them from those helpers rather than restating them). Forced manifest-write failure (`S19TuiApp._write_manifest_for_save` patched to return `(None, "forced refusal")`) → 0 adopts, the session map still holds the source byte at `0x8000`, `image_step.summary.saved_path is None`, `"project.json was not written" in log_lines[-1]`, `W/Q` absent (4). Re-pin of `test_tc_b100_17_failed_manifest_write_adopts_nothing` (`:836`): the patch moves from `_write_and_verify_manifest` to `_write_manifest_for_save` (census P1-C6). Negative control: a mutation that adopts in `_commit_project_save` before the worker (the old "apply before" text) → the failure arm shows the re-derived byte although no file holds it → RED.
examples: P1-70 (failure arm, LLR-177.2a) P1-64 again: the session's `_variant_set`, `current_project`, `current_project_dir`, `_report_filter_path` and `current_file.variant_id` equal their values before the save (5 equalities; the base restored them through `_abort_save`, 12b never changes them). Negative control: a handler that writes `_variant_set = outcome.variant_set` on both arms → `_variant_set is None` after the failure → RED.
examples: P1-71 (C53 / B11-70 holds) the E3 R1 arm: the document recorded in the project home, the panel dirty → the lines end with `Change document changes.json has unsaved edits — the project records the file as it is on disk; save it from the Patch Editor to keep them` as `log_lines[-1]` (the outcome) (1 assertion; `recorded_document` is a field, E3 DF-5). Negative control: the line appended without the `recorded_document` condition → it also paints when the save recorded no document → the paired arm (`project.json` without `active_document`) RED.
examples: P1-72 (12a A12-51 holds) a manifest verify mismatch (`verify_written_manifest` patched to return `status="mismatch"`) → `tail[-1] == "Manifest verify MISMATCH"` is the outcome and `log_lines[-1]`; the notice `Manifest verify mismatch - project.json may be wrong` raised once (from step 2) (3 of 3).
examples: P1-73 (HLR-177c, LLR-177.4c save arms, 3 of 4; seam X-8) a save-as of `S` as `S9` with `app_module.place_into_workarea` held on a forced slow step; `q` → the quit question (P-2); `y` → the app still running while held (1); released → the app exits and `W/S9/project.json` verifies (`verify_written_manifest` re-run by the test after exit → `MANIFEST_VERIFIED`) (1); the same with the held step raising `OSError` after `y` → the app **keeps running** (E3 S12b-01: the failure arm clears `_quit_pending`), `W/S9` is absent, the failure line is `log_lines[-1]` and the failure toast is shown (3); 0 partial folders under `W` over both arms (1). Negative control: a mutation that exits on `y` → the app stops while held → RED; executed P12b-3 (after `exit()` the worker's callback still lands on a stopped app).
examples: P1-74 (failure toast and lines; PR-1 evidence) a save whose manifest write is refused (`app_module.write_project_manifest` returns `(None, [issue "disk full"])`) → lines `['Manifest write failed', 'Project NOT saved: could not save — project.json was not written. check the folder.']`, 1 notice with title `Manifest write failed - project.json not written` and text `disk full` (`test_tui_manifest_save.py:275`, `:539` assert a title holding `manifest write failed`) (3 of 3). Negative control: a toast carried as text only and always titled `Project not saved` → those two tests RED.
examples: P1-85 (E3 S12b-01; HLR-177c error arm) a save-as of `S` as `S9` with the pasted Patch Editor entries held; `app_module.place_into_workarea` held, `q` → the quit question, `y` → `_quit_pending is True`; released with the held step raising `OSError(28, "synthetic no space")` → the worker rolls back, `_on_project_saved`'s failure arm sets `self._quit_pending = False` before `end_busy`, so the app **keeps running**; `log_lines[-1] == "Project NOT saved: could not save — [Errno 28] synthetic no space. check the folder."`, the failure toast is shown, `W/S9` is absent, and the pasted Patch Editor entries are kept (6 of 6). Negative control: a failure arm that omits `_quit_pending = False` → `end_busy`'s quit check exits the app in the same callback that paints the failure → the app stops before the failure line is seen → RED.

S19TuiApp._write_manifest_for_save
req: LLR-177.1d, LLR-177.1e
in: Path project_dir; Optional[ProjectVariantSet] variant_set; Path base_dir; keyword-only Sequence[str] batch = (); Optional[Mapping[str, Sequence[str]]] assignments = None; Sequence[DeclaredRegion] declared_regions = (); Optional[Mapping[str, Sequence[str]]] gathered = None; Optional[Mapping[str, DerivedFrom]] derived_from = None; Optional[str] active_document = None; Optional[Callable[[Path], None]] on_written = None
out: tuple(Optional[ManifestVerifyResult] result, Optional[str] refusal)
func: new (fixed Q-b1: the worker-side core). The base body of `_write_and_verify_manifest` (`:11255`–`:11313`) with `variant_set` and `base_dir` as arguments and no painting: `variant_set is None` → `(None, None)` (nothing written; ok). `files = project_file_records(project_dir, active_document=active_document)`; `write_project_manifest(variant_set, project_dir, base_dir, …)`; refused → the base warning `Manifest write refused: …` and `(None, detail)` with `detail = "; ".join(issue.message for issue in issues) or "unknown error"`. Written → `on_written(written)`; `result = verify_written_manifest(…)`; `(result, None)`. An `OSError` propagates (the Save worker's `except OSError` arm, as on base). It assigns nothing and calls neither `set_status` nor `notify`.
callers: `_save_project_files`; `_write_and_verify_manifest`.
module: s19_app/tui/app.py
examples: P1-75 (Q-b1, 3 arms) `variant_set=None` → `(None, None)` and 0 files written; `write_project_manifest` patched to refuse with issue `disk full` → `(None, "disk full")`; a real write → `result.status == MANIFEST_VERIFIED`, refusal `None`, `on_written` called once with `project_dir / "project.json"`. In all three: 0 `set_status` and 0 `notify` calls (spies), and the `__setattr__` recorder sees 0 app writes (3 × 2). Negative control: a core that assigns `_last_manifest_verify_result` → the recorder arm RED.

S19TuiApp._write_and_verify_manifest
req: LLR-177.1d
in: Path project_dir; keyword-only Sequence[str] batch = (); Optional[Mapping[str, Sequence[str]]] assignments = None; Sequence[DeclaredRegion] declared_regions = (); Optional[Mapping[str, Sequence[str]]] gathered = None; Optional[Mapping[str, DerivedFrom]] derived_from = None; Optional[str] active_document = None; Optional[Callable[[Path], None]] on_written = None
out: bool ok
func: changed (`:11147`), signature and behaviour kept (fixed Q-b1): `self._last_manifest_verify_result = None`; `result, refusal = self._write_manifest_for_save(project_dir, self._variant_set, self.base_dir, …same keywords)`; `refusal is not None` → `self.set_status("Manifest write failed")`, the base notice (`title="Manifest write failed - project.json not written"`), `return False`; `result is not None` → `self._last_manifest_verify_result = result`, `self._surface_manifest_verify_result(result)`; `return True`. Main thread only; the Save worker no longer calls it.
callers: `_rewrite_project_manifest` (`:12495`; the save-back, the variant append, the MAC / A2L syncs). The Save commit is no longer a caller. Tests: `test_b100_project_check.py:215`, `:266`, `:1421`; `test_tui_report_seam.py:811`–`:860`.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._last_manifest_verify_result] (replace)
examples: P1-76 (census C9 holds) `test_b100_project_check.py::test_tc_b100_23_digest_changed_between_write_and_verify` reads `app._last_manifest_verify_result` after a direct call; `:1421` → `ok is False` and `painted[0] == "Manifest write failed"` on a refused write; `test_tui_report_seam.py::test_write_and_verify_manifest_accepts_declared_regions_default` keyword set unchanged (3 of 3; the 2 Save monkeypatches move, census P1-C6).

S19TuiApp._abort_save
req: LLR-164.4, LLR-177.2a, LLR-177.1d, LLR-177.1e
in: Path project_dir; bool created_project_dir; Sequence[Path] placed_files; Sequence[Path] created_dirs; Path workarea; Sequence[Tuple[Path, bytes]] manifest_restores = (); Sequence[Tuple[Path, bytes]] kept_copies = ()
out: list[str] notes
func: changed (`:9162`, E1 B5). The session-restore half (`:9201`–`:9213`, the `save_state` parameter) is removed: the worker never writes the session. The file rollback is unchanged (manifest restores, identity-checked unlinks of the placed files, the kept-copy check, the created folders deepest first; never raises), with `self.workarea` replaced by the `workarea` parameter. Each `set_status` (the "Not removed after the failed save" note, the "could not be restored" kept-copy note) and the line `_restore_manifest` now returns become entries of the returned `notes`, in the base order; it paints nothing.
callers: `_save_project_files` (11 exits). Tests: `test_b100_save_image.py:2245` (`_spy_abort_8b`, forwards `*args`: holds), `test_b100_reuse.py:531`, `test_b99_staging.py:2074` (by name: hold).
module: s19_app/tui/app.py
modify: [I/O: work area] (rollback)
examples: P1-77 (E1 B5, census C1 re-pin) AST: `_abort_save` holds no `Attribute` `_variant_set`, `_report_filter_path`, `current_project`, `current_project_dir` or `current_file`, and still holds an `unlink` and a folder removal (`rmdir`) (2 of 2; the `"must restore the pre-save app state"` assert of `test_tc_b100_07_ast_census_every_post_creation_return_removes` goes, ruled in E2-rulings). Negative control: the base helper → the `_variant_set` attribute is present → the re-pinned arm RED.
examples: P1-78 (12a A12-48 holds) the `OSError(28)` placement arm → `notes == []` (nothing kept), `W/S2` absent (2 of 2).

S19TuiApp._restore_manifest
req: LLR-164.4, LLR-177.1e
in: Path manifest_path; bytes previous_bytes; Path workarea; bool already_kept = False
out: Optional[str] note
func: changed (`:9304`). `_private_stage_dir(self.workarea)` → `_private_stage_dir(workarea)`; `self._keep_previous_manifest(manifest_path, previous_bytes)` → `(…, workarea)`; the final `self.set_status(safe_text(message).plain)` becomes `return safe_text(message).plain`; every other return is `None`. Logging unchanged.
callers: `_abort_save`. Test `test_b99_staging.py:2076` (allow-list by name: holds).
module: s19_app/tui/app.py
examples: P1-79 a merge save into `P` whose manifest restore fails (`os.replace` patched to raise `PermissionError` 5 times) → the note `project.json could not be restored; its previous content is kept as project.json.previous-<stamp> in <W>\P - rename it to project.json` is the last line, painted by `_on_project_saved` (1 of 1; holds on base for the text).

S19TuiApp._keep_previous_manifest
req: LLR-177.1e
in: Path manifest_path; bytes previous_bytes; Path workarea
out: Optional[Path] kept
func: changed (`:9392`): `_guarded_destination(manifest_path.parent, self.workarea)` → `(…, workarea)`. Nothing else.
callers: `_save_project_files` (the SEC7-3 keep); `_restore_manifest`. Tests: `test_b100_save_guards.py:1903`, `:1932` (direct calls), `:2017`, `:2069`–`:2083` (monkeypatches with a 2-argument signature) → re-pinned (census P1-C4).
module: s19_app/tui/app.py
examples: P1-80 `app._keep_previous_manifest(W/"P"/"project.json", b"previous", app.workarea)` → a `project.json.previous-<UTC stamp>` file holding `b"previous"`; a `manifest_path` outside `workarea` → `None` (2 of 2; the base test bodies with the argument added).

S19TuiApp._copy_project_subfolders
req: LLR-177.5a, LLR-177.1e
in: Path source_dir; Path project_dir; Sequence[InventoryFile] copies; list[Path] placed_files; list[Path] created_dirs; Optional[Mapping[str, SavePlanRow]] carried = None; keyword-only Path workarea; keyword-only Callable[[], None] on_placed
out: Optional[str] failure
func: changed (`:12208`): every `self.workarea` (`:12270`, `:12294`, `:12303`) → `workarea`; after each successful placement (`placed_files.append` point), `on_placed()` (one tick per file placed, LLR-177.5a). Both new parameters are keyword-only and required (the Save worker is the only caller; no default branch).
callers: `_save_project_files` (sub-folder copies, top-level copies). Tests wrap it forwarding `*args, **kwargs` (`test_b100_project_homes.py:1668`, `:2522`): hold.
module: s19_app/tui/app.py
modify: [I/O: work area]
examples: P1-63 above (4 and 2 000 placements); P1-81 (SEC-1 census holds, `test_b100_reuse.py:810`) the function holds exactly 1 placement call and it passes `workarea_root=` (2 of 2).

S19TuiApp._write_editor_document
req: LLR-170.2, LLR-177.1e
in: SavePlanRow row; Path project_dir; bytes document_bytes; str document_kind; Path workarea
out: tuple(Optional[PlacementResult] placed, Optional[Path] created_home, Optional[str] failure)
func: **retired** (E3 S12b-05). Its staging copy of `write_change_document`'s path (`changes/io.py:1586`–`:1624`) is gone: `_save_project_files` calls the unchanged `write_change_document(request.document_snapshot, request.base_dir, file_name="changes.json", copy_fn=_place, dest_dir=project_dir / document_home_for_kind(request.document_kind))` with a deep-copied snapshot taken on the main thread. One serializer (`serialize_change_document`) keeps P1-52's digest arm.
callers: none after 12b (base: `_handle_save_dialog` :9981). Test wrapper `test_b100_project_homes.py:1669` re-pins to `write_change_document`.
module: s19_app/tui/app.py
modify: [I/O: work area] (moved to `write_change_document`)
examples: P1-82 (re-pinned, E3 S12b-05; LLR-170.2 holds) a session with 2 pasted entries saved as `Q` → `W/Q/patches/changes.json` exists, its bytes equal `serialize_change_document(document)` taken before the save, `Q/project.json` records `active_document == "patches/changes.json"`, the document is rebound (`document.source_path == W/Q/patches/changes.json`) and the panel's dirty marker is cleared (4 of 4). SEC-1 census (`test_b100_reuse.py:823`): 1 placement call in `write_change_document` with `workarea_root=` (1). Negative control: a worker that reads `self._change_service.document` → P1-66's census hit → RED.

## Context nodes (unchanged)

- `S19TuiApp._handle_save_dialog` (post-11 router): unchanged; its 56 direct call lines now return after the begin, and the census's waits (A6, A10, A11, B3, B4) carry the outcome (Q6).
- `S19TuiApp._prepare_project_save`, `_save_session_inputs`, `_decide_project_image`: unchanged (ruling Q1); they run before `_commit_project_save` on main.
- `S19TuiApp._rewrite_project_manifest`: unchanged (Q-b1 keeps `_write_and_verify_manifest`'s contract), so E1 B4's change to it is not needed.
- `recorded_document_state`, `choose_install_set`, `compose_load_announcement`, `check_project_files`, `build_variant_set`, `read_project_manifest`, `_unrecorded_document_lines`, `classify_active_document`: pure; new thread or call site only.
- `S19TuiApp._reset_project_session`: unchanged body (post-10 `-> None`); its one caller is `_install_prepared_project`.
- `S19TuiApp._session_snapshot`: unchanged; G-A and G-B add **0** app attributes (requests and results are arguments and locals), so TC-B100-09 needs only P-2's `_quit_pending` (P1-83).
- `ChangeService.emit_and_verify`: unchanged; after 12b its app-side caller is only `save_patched` (Patch Editor `save_doc`), so `test_b99_editor_image.py:728`'s patch of `change_service_module.verify_written_image` keeps its meaning.

P1-83 (LLR-165.2, TC-B100-09) the live source census of `self.<name> =` in `S19TuiApp` after 12b adds exactly 1 name over the 12a census, `_quit_pending` (P-2); G-A and G-B add 0 (1 assertion). Negative control: a design that stores the request on the app (`self._project_load_request = request`) → 1 more unclassified name → TC-B100-09 RED.

## Entities

[I/O: work area]
desc: written by the Save path only on the Save worker (`_save_project_files` and its helpers), rolled back there; the main thread writes nothing under `W` during a save. A failure outside the rollback `try` happens before any write.
sequence:
  commit: _commit_project_save (main: record_save_entries, request) → _save_project_worker (thread) → _save_project_files → mkdir → step 2 → copies / rows / emit (tick per file) → step 3 → gather → step 4 → keep → _write_manifest_for_save → SaveOutcome(committed, facts) → call_from_thread _on_project_saved (main: session writes, adopt, mark_saved, compose tail, current_project, refresh_files) → end_busy (last)
  stageFailure: _save_project_files → place_into_workarea raises OSError → _abort_save (files and folders removed; notes returned) → _save_failure_outcome → _on_project_saved (quit_pending False, lines, toast) → end_busy → expect none (0 adopts, session unchanged)
  unexpected: _save_project_files → verify_written_image raises ValueError → except Exception (logged traceback) → _abort_save → failure outcome → expect none (no raise, app running)
  outside: _save_project_files → mkdir raises PermissionError → _save_project_worker inner except → failure outcome → expect none (0 folders)

[Data: S19TuiApp.current_project]
desc: written only on the main thread, by `_install_prepared_project` (project load) and `_on_project_saved` (commit).
sequence:
  load: _handle_load_project (main, request) → _project_load_worker → _prepare_project_load (reads only the request) → call_from_thread _on_project_loaded → step 4 → call_after_refresh _install_prepared_project → reset → installs → current_project → announcement → panel (routed) → end_busy (last)
  loadFails: _prepare_project_load raises → call_from_thread _on_project_load_failed → quit_pending False → end_busy ("could not be read") → expect none (0 resets)
  refused: _prepare_project_load → refusal → _on_project_loaded → quit_pending False → end_busy ("No supported files in project: …") → expect none (0 resets)

[Data: S19TuiApp._a2l_cache_key / _a2l_cache_data]
desc: one entry `(key, payload)`; read into requests on main (`_a2l_cache_entry`), parsed or hit on workers (`parse_a2l_cached`), stored only on main (`_store_a2l_cache`).
sequence:
  projectLoad: _handle_load_project → request.a2l_cache → worker parse_a2l_cached (hit or parse with byte reports) → PreparedProjectLoad.a2l_cache → _install_prepared_project → _store_a2l_cache
  fileLoad: _start_load_worker (P-2) → _parse_loaded_file(a2l_cache_out=out) → PreparedLoad.a2l_cache → call_from_thread _apply_prepared_load → _store_a2l_cache
  a2lAttach: load_a2l_from_path (P-2) → A2LAttachRequest.a2l_cache → worker parse_a2l_cached → _install_attached_a2l → _store_a2l_cache

[Data: S19TuiApp._busy]
desc: 12a's run state; G-A and G-B write it only through `_busy_begin_action`, `step_busy` (posted from workers) and the end tail (`end_busy` / `_busy_fail` directly, E3 DF-1).
sequence:
  load: begin (main) → step 2 bytes, step 3 (worker, posted) → step 4 (main) → end tail in the install (last)
  save: begin (main) → step 2 files placed, 3, 4 (worker, posted) → end tail in _on_project_saved (last)

## Callers and what changes for each

Each row is checked against the baseline's `> callers (extractor)` note for that node (callables passed as values are listed from a code read).

| Node | Baseline callers (extractor / code read) | After 12b |
|---|---|---|
| `_handle_load_project` | `_route_load_project` (direct :7478) | `_route_load_project` inside `go` (`routed=True`); tests unchanged in call form, re-pinned to wait (census A/B) |
| `_route_load_project` | unmarked `_load_path_from_user_input` :12936; `LoadProjectScreen` dismiss (retired by 9b) | `_handle_load_dialog` (`project`), `_load_path_from_user_input` (project arm) — unchanged set |
| `_reset_project_session` | `_handle_load_project` (direct :11821) | `_install_prepared_project` only |
| `_install_project_image` | `_handle_load_project` (direct :11903) | retired |
| `_reopen_active_document` | `_handle_load_project` (direct :11886) | `_install_prepared_project` |
| `recorded_document_state` | `_handle_save_dialog` (direct :9750, post-11 in the preparation), `_reopen_active_document` (direct :12017) | the preparation (unchanged), `_prepare_project_load` (worker) |
| `choose_install_set` | `_handle_load_project` (direct :11869, :11910) | `_prepare_project_load` (2 sites) |
| `_parse_loaded_file` | `_install_project_image` :12078, `_start_load_worker` :15743, `load_selected_file` :15080 | `_start_load_worker`, `load_selected_file` |
| `_merge_mac_with_existing_primary` | `_parse_loaded_file` (direct :15197) | `_parse_data_file` |
| `_merge_primary_with_existing_mac` | `_parse_loaded_file` (:15153, :15172; not marked) | `_parse_data_file` |
| `_load_mac_file` | `_parse_loaded_file` (direct :15187) | `_parse_data_file` |
| `_load_a2l_data_with_cache` | `_handle_load_project` :11858, `_load_mac_file` :14217, `_parse_loaded_file` :15151 / :15170, `load_a2l_from_path` :13145 | retired (E3 DF-7); the one test re-pins to `parse_a2l_cached` |
| `load_selected_file` | `_handle_load_project` :11920, `_load_from_item` :13335 | none in `s19_app/` (the MAC install moves to the worker; the pick to P-2's file-load start; finding F-4) |
| `_session_snapshot` | none listed | unchanged |
| `_commit_project_save` | not run (post-11) | `_handle_save_dialog` step 6, unchanged |
| `_abort_save` | `_handle_save_dialog` (11 direct sites) | `_save_project_files` (11 sites) |
| `_write_and_verify_manifest` | `_handle_save_dialog` :10323, `_rewrite_project_manifest` :12495 | `_rewrite_project_manifest` only |
| `_copy_project_subfolders` | `_handle_save_dialog` :9943, :10079 | `_save_project_files` (2 sites) |
| `_write_editor_document` | `_handle_save_dialog` :9981 | retired (E3 S12b-05); the document row calls `write_change_document` |
| `ChangeService.record_save_entries` | `_handle_save_dialog` :10006 | `_commit_project_save` (main) |
| `ChangeService.emit_and_verify` | `_handle_save_dialog` :10007; `save_patched` | `save_patched` only |
| `ChangeService.adopt_rederived` | `_handle_save_dialog` :10436 | `_on_project_saved` (main) |
| `_decide_project_image` | `_handle_save_dialog` :9706 (post-11 `_save_session_inputs`) | unchanged |
| `update_a2l_view` | `_handle_load_project` :11879 and others | `_install_prepared_project` (A2L-only) plus the unchanged others |

## Census additions (to the baseline's A1–A15, B1–B4, C1–C17)

| # | Test | Pins | After 12b | Disposition |
|---|---|---|---|---|
| P1-C1 | `tests/test_tui_variants.py::test_no_new_parse_loaded_file_call_sites` (:196) | call sites `["_install_project_image", "_start_load_worker", "load_selected_file"]` | `_install_project_image` retired; a new core | re-pin to 2 lists (P1-39) — baseline C5 |
| P1-C2 | `tests/test_tui_app.py:226`, `:636` | `_load_mac_file` replaced by `lambda path, a2l_files=None: mac_loaded` | called with 3 positional arguments → `TypeError` | re-pin the 2 lambdas to `lambda path, *args, **kwargs: mac_loaded` |
| P1-C3 | `tests/test_tui_app.py:274`, `tests/test_memmap_entropy_merge.py:71`, `:85`, `:101`, `tests/test_tui_workspace_insight.py:279` | the two merge methods called with one argument | `existing` is now required | re-pin: pass `app.current_file` (5 sites) |
| P1-C4 | `tests/test_b100_save_guards.py:1903`, `:1932` (direct), `:2017` (`lambda self, path, data: None`), `:2069`–`:2083` (`_keep(self, path, data)`) | the 2-argument `_keep_previous_manifest` | `workarea` parameter | re-pin 4 sites (add `app.workarea`; patches take `*args`) |
| P1-C5 | `tests/test_b100_save_image.py:754`, `:781`, `:806` | `monkeypatch.setattr(change_service_module, "save_patched_image" / "verify_written_image", …)` | the Save worker calls the app module's names (Q-b2) → the patches no longer reach Save (vacuous or RED) | re-point the 3 patches to `app_module`; `:806` also loses `pytest.raises` (P1-64) |
| P1-C6 | `tests/test_b100_document.py:815`, `tests/test_b100_save_image.py:836` | monkeypatches of `_write_and_verify_manifest` returning `False` | the Save worker calls `_write_manifest_for_save` | re-pin to `_write_manifest_for_save` returning `(None, "forced …")` (fixed Q-b1 noted it) |
| P1-C7 | `tests/test_b100_reuse.py:770` `test_tc_b100_01_app_placements_name_the_workarea_root` | `emit_calls` (`Attribute` `save_patched` / `emit_and_verify`) `== 2`, each with `workarea_root` | the Save emit is now a `Name` call `save_patched_image(…)` → `emit_calls == 1` → RED; and the new call is outside the census | re-pin: count `save_patched` (Attribute) + `save_patched_image` (Name) `== 2`, each with `workarea_root=`; `place_into_workarea` count stays 9 |
| P1-C8 | `tests/test_b100_project_homes.py:1945` (baseline C8) | spies on `_load_a2l_data_with_cache` and `parse_a2l_file` | the project worker calls `parse_a2l_cached` → the cache spy sees 0 for every case (vacuous) | re-point the cache spy to `app_module.parse_a2l_cached` |
| P1-C9 | 12a's own tests that patch `_install_project_image` to raise (12a A12-45, if written at 12a E4) | the project load's exception exit | the function is retired | re-target to `_apply_loaded_file` (P1-34) |
| P1-C10 | `tests/test_b100_save_guards.py:801` (baseline C1) | the `mkdir` / return census and `_abort_save`'s `_variant_set` | moved to `_save_project_files`; the last return is the committed outcome; no `raise` | re-pin as P1-66 / P1-77 |

Holds by reading against this design: `_spy_abort_8b` (forwards `*args`), `test_b100_project_homes.py:1668`–`:1691` and `:2522` (forward `*args, **kwargs`), `test_b99_staging.py:2068`–`:2076` (names kept), `test_b100_reuse.py:810` / `:823` (1 placement each, with the root), `test_tui_app.py:1355` (`PreparedLoad(loaded=…)`), the C9 pins of `_write_and_verify_manifest` (Q-b1), TC-B100-08 both arms (Q-g1), `test_b99_editor_image.py:728` (Patch Editor path). Not executed (host busy; the brief allows no broad test run).

## Seams with P-2 (G-C + G-D), by id

| Id | Where | P-1 side (this design) | P-2 must | Example |
|---|---|---|---|---|
| X-1 | the busy check at the action starts (fixed Q-a1) | `if self._refuse_if_busy(): return` is the first statement of `_handle_load_project` and `_commit_project_save` | provide `_refuse_if_busy()` (paints the busy line, returns `True`); its 17 entry points are P-2's | P1-12, P1-56 |
| X-2 | the end tail | every P-1 end site calls `end_busy(key, gen, outcome)` / `_busy_fail(key, gen)` directly as its **last** statement (`_install_prepared_project`, `_on_project_loaded` refusal arm, `_on_project_load_failed`, `_on_project_saved` both arms); the failure arms clear `_quit_pending` first (E3 S12b-01) | no wrappers, no `final_line` (E3 DF-1 / P2-1); the quit check lives inside `end_busy` | P1-28, P1-33, P1-73, P1-85 |
| X-3 | progress forwarding | project step 2: bytes from `parse_a2l_cached(…, progress=self._progress_forwarder("project_load", gen, 2))`; Save step 2: `forward = self._progress_forwarder("save_project", gen, 2)` called with `(files placed, files planned)` | the forwarder closes over `key, gen, n` only and forwards on a percent change plus the final `(total, total)` (fixed S-f) | P1-21, P1-63 |
| X-4 | the A2L cache for the A2L attach | `A2LCacheEntry`, `parse_a2l_cached`, `_a2l_cache_entry`, `_store_a2l_cache` as specified here | `load_a2l_from_path` puts `self._a2l_cache_entry()` in `A2LAttachRequest`; the worker calls `parse_a2l_cached(path, request.a2l_cache, progress=…)`; `_install_attached_a2l` calls `_store_a2l_cache(result.entry)`; no other cache writer | P1-02, P1-06 |
| X-5 | Q-h1, the file-load cache | `_parse_loaded_file(path, a2l_files, *, a2l_cache_out=None)` appends the entry it used and never stores; `PreparedLoad.a2l_cache`; `_apply_prepared_load` stores | `_start_load_worker` passes `a2l_cache_out=out` and builds `PreparedLoad(…, a2l_cache=out[0] if out else None)` (through `_prepare_load_payload` or `replace`); it keeps calling `_parse_loaded_file` | P1-41 |
| X-6 | the load guard | `_route_load_project` → `_confirm_then_load("project", name, go)`, `go` calls `_handle_load_project(name, routed=True)` | `_confirm_then_load` refuses while busy before it asks (LLR-177.3a); a `go` run later after `y` is checked again by X-1 | P1-31, P1-37 |
| X-7 | Save while busy | `_commit_project_save` refuses (X-1) after the preparation | `action_save_project` refuses before the dialog (LLR-177.3d) | P1-56 |
| X-8 | quit | the end tail is the last statement in each P-1 end handler, after the Load-result panel push, labels, `refresh_files` and the flow folder | `_exit_if_quit_pending` runs inside the tail; `action_quit` / `_answer_quit` are P-2's | P1-33, P1-73 |
| X-9 | worker groups | `project_load`, `save_project`, distinct and **not** exclusive (E3 DF-2 / P2-4), each used by one worker | the A2L worker uses its own group (`a2l_load`); the file load keeps `load` (12a) | — |
| X-10 | the work-area pick and `load_selected_file` | the project MAC install no longer calls `load_selected_file` | `_load_workarea_file`'s data arm no longer calls it (LLR-177.1k) → 0 product callers (F-4) | — |
| X-11 | `parse_a2l_file(path, progress=None)` (G-D) | `parse_a2l_cached` calls it with `progress=` only when given (fixed Q-f2) | the one-line re-pin of `_denied(path)` (baseline C7) | P1-03 |
| X-12 | shared test file `tests/test_b100_workers.py` | TC-B100-53 / -54 arms for project load and Save (P1-15 … P1-74) | the A2L, refusal and quit arms | — |
| X-13 | TC-B100-51 re-keyed rows (P-2's X12b-14) | `project_load`: begin `_handle_load_project`; steps 2, 3 `_prepare_project_load` (posted); step 4 `_on_project_loaded`; ends `_install_prepared_project`, `_on_project_loaded` (refusal), `_on_project_load_failed`, guards. `save_project`: begin `_commit_project_save`; steps 2–4 `_save_project_files` (posted); ends `_on_project_saved` (both arms), guards | the `a2l_load` / `file_load` rows | P1-62 |
| X-14 | held steps in P-2's examples (X12b-11, -12) | the workers call `read_project_manifest`, `place_into_workarea` (also inside `_copy_project_subfolders`), `save_patched_image`, `verify_written_image`, `write_project_manifest`, `gather_project_artifacts` and `parse_a2l_cached` through `app.py` module-level names, so a `monkeypatch` of `app_module.<name>` reaches the worker | — | P1-31, P1-59 |
| X-15 | `#patch_paste_text` read-only during a project load (E3 S12b-04) | `_handle_load_project` step (2), after `_busy_begin_action("project_load", …)`, sets `#patch_paste_text.readonly = True` | P-2's `end_busy` clears it on the `project_load` hand-back; the example is C12b-55 | P1-11 |

**Resolved by the E3 rulings (was open between P-1 and P-2):**
- **X-2 vs X12b-02 (end tail form).** E3 DF-1 / P2-1: no `_finish_session_action` / `_fail_session_action`, no `final_line`; the quit check lives inside `end_busy` (A12a-07); end sites call `end_busy` / `_busy_fail` directly. Each P-1 end call is renamed one-for-one; nothing else moves.
- **X-5 vs X12b-06 (the Q-h1 parse form).** E3 DF-8 / PR-7: the out-list form wins (`_parse_loaded_file(…, *, a2l_cache_out=None)`); `_parse_loaded_file` reads `_a2l_cache_entry()` itself, and P-2's `_start_load_worker` passes `a2l_cache_out=out` and sets `PreparedLoad.a2l_cache = out[0] if out else None`.
- **Worker exclusivity.** E3 DF-2 / P2-4: one distinct, non-exclusive group per busy key (`project_load`, `save_project`, `a2l_load`); no canceller owes an `end_busy`.

## What P-1 consumes from 12a (checked; unchanged)

| Need | 12a seam |
|---|---|
| begin with the painted label, `gen` | `_busy_begin_action("project_load" / "save_project", name)` |
| step 2 within-step amounts, steps 3 / 4 | `step_busy(key, gen, n, done, total)` (clamped, rising), posted with `call_from_thread` |
| the outcome as the last log line; the stored file state painted at the last end | `end_busy(key, gen, outcome) -> bool`, `set_file_status` storing `file_state` (A12a-06) — called directly (E3 DF-1) |
| `<label> failed` on an exception exit | `_busy_fail(key, gen)` (P-1 of 12a) — called directly (E3 DF-1) |

## Findings

finding F-1 (correctness, executed) the merged MAC drops the opened variant's id unless the worker stamps it
anchor: S19TuiApp._prepare_project_load
seen: probe U1 arm B: with the image parsed on the worker and the MAC merged onto it before any install, `current_file.variant_id` is `'firmware'` after the image install and `None` after the MAC install. On base the MAC merges onto the **installed** image, whose `variant_id` `_apply_prepared_load` stamped from `_pending_variant_id` (`:15337`–`:15339`), and the merge copies `existing.variant_id` (`:14465`); the worker's image is not installed yet, and `_pending_variant_id` is cleared by the first install.
effect: the session after a project load with a MAC would carry no variant id (the Save's active variant, the variant panel). LLR-177.1f's threshold does not see it: the digest and `_session_snapshot()` (which normalises `current_file` to type, path and image digest) are equal in arm B.
decision: step (9) stamps `image.variant_id = opened.variant_id` on the worker's own object before the merge (arm A: `'firmware'` after both installs). P1-20 asserts it; proposal PR-10 adds it to LLR-177.1f's threshold.

finding F-2 (base arm unreachable) the project MAC's `Load failed:` line
anchor: S19TuiApp._prepare_project_load
seen: base installs the project MAC through `load_selected_file`, which paints `Load failed: <exc>` when the parse raises. `parse_mac_file` catches its own read errors into diagnostics (`mac.py:135`–`:136`), and the MAC's A2L comes from the already-read project A2L, so that arm does not occur in practice.
decision: on the worker a raising MAC parse is a worker failure (LLR-177.2, `could not be read`, session kept), not a `Load failed:` line. Declared; no requirement covers the old line.

finding F-3 (order) a Save failure's outcome is the last line in base order
anchor: _save_failure_outcome
seen: 12a F-7 left a rollback note after the outcome. With the 12b rule "the end tail is the last statement" and 12a Q-3 "the outcome is the last painted line", the only way to keep the status log line-for-line equal to the base is to end with the base's last line.
decision: `outcome = lines[-1]`; a rollback note, when present, is the outcome (P1-68). The log is unchanged line for line; `log_lines[-1]` is the outcome on every arm (HLR-176c).

finding F-4 (dead production code, Q6 principle) two functions keep no product caller
anchor: S19TuiApp.load_selected_file / S19TuiApp._load_a2l_data_with_cache
seen: after 12b, `load_selected_file` is called only by tests (88 calls): its two product callers move to the project worker (here) and to P-2's file-load start (LLR-177.1k). `_load_a2l_data_with_cache` is called only by `test_tui_app.py:410`/`:411`: its 4 product callers move to `parse_a2l_cached`. E1 ruling Q6 says "a test-only production branch is dead code"; S-h and E1's slice keep both.
decision: **resolved by E3 DF-7** — `_load_a2l_data_with_cache` is retired (its one test re-pins to `parse_a2l_cached`); `load_selected_file` goes to a backlog row (88 test calls; the re-pin is outside 12b's slice).

finding F-5 (requirement trace) E1's traces name `ChangeService.emit_and_verify` and a changed `_write_and_verify_manifest`
anchor: S19TuiApp._save_project_files
seen: LLR-177.1a's trace names `ChangeService.emit_and_verify`; LLR-177.1d's names `_write_and_verify_manifest (its _last_manifest_verify_result write)`. Fixed Q-b2 replaces the first with `save_patched_image` / `verify_written_image`; fixed Q-b1 keeps the second unchanged and adds `_write_manifest_for_save`.
decision: designed to the rulings; the traces should name `_save_project_files`, `save_patched_image`, `verify_written_image`, `_write_manifest_for_save` (a text edit at merge; no behaviour).

finding F-6 (scope note) the file-load worker still reads the session
anchor: S19TuiApp._parse_loaded_file
seen: on the file-load worker `_parse_loaded_file` reads `current_a2l_path`, `current_a2l_data`, `current_file`, `current_project` and now `_a2l_cache_entry()`, as it reads the first four today. LLR-177.1e's census covers the three 12b workers only; Q-h1 moved only the cache write.
decision: declared. The reads cannot race a session writer: every session writer is a session action, refused while the file load runs (HLR-177a), and reports write no session state. The two cache attributes are read together without a lock for the same reason.

## Proposals to the orchestrator

All of the proposals below were ruled by the E3 rulings (DF-1 … DF-9, S12b-01 … S12b-07, A12b-04); the nodes above carry the rulings.

- **PR-1 (S-b, `SaveOutcome.toast`).** `toast: Optional[tuple[str, str]]` = (title, text) instead of `Optional[str]`. The worker raises two toast kinds with different titles: `Project not saved` and `Manifest write failed - project.json not written`; `test_tui_manifest_save.py:275`, `:539` assert the second title (P1-74). Without it, the manifest refusal's notice is retitled and those two tests turn RED.
- **PR-2 (S-b, `SaveOutcome.recorded_document`).** Add `recorded_document: Optional[str]`. The panel's dirty line (C53 / B11-70) needs the base condition `recorded_document is not None`, which only the worker knows (P1-71).
- **PR-3 (S-b, `SaveOutcome.unrecorded`).** Drop it: the worker composes the painted unrecorded lines into `lines`, and the handler reads nothing else from it. Keeping it costs nothing but an unused field.
- **PR-4 (S-c, `final_line`).** `_finish_session_action(key, gen, outcome)` without `final_line`. 12a's fixed `end_busy(key, gen, outcome) -> bool` has no `final_line` (A12a-06 replaced the hand-back slots with `file_state`, P-4 superseded); the project install stores the project line with `set_file_status` before the end (12a A12-42). Seam with P-2.
- **PR-5 (S-d text).** Write the worker body's guard as `except BaseException: call_from_thread(_fail_session_action, …); raise` (12a E3 S12a-06, binding in the fixed file's last list), not `finally`, so the success path posts no second end. This design follows the binding.
- **PR-6 (F-4).** Retire `load_selected_file` (re-pin 88 direct test calls to `load_from_path` or the worker helper) and `_load_a2l_data_with_cache` (re-pin 1 test to `parse_a2l_cached`), or record both as a declared exception to ruling Q6. Recommendation: a backlog row for `load_selected_file` (the re-pin is large and outside 12b's slice), and retire `_load_a2l_data_with_cache` now (1 test).
- **PR-7 (Q-h1 seam detail; conflicts with P-2's X12b-06).** Confirm the out-channel `_parse_loaded_file(…, *, a2l_cache_out=None)`: keeping `_start_load_worker` on `_parse_loaded_file` (fixed table) and its `Optional[LoadedFile]` return (patched to raise or return `None` by 12a tests) leaves no other way to hand the entry to `PreparedLoad` without a stale re-stat on main. P-2's tuple-returning form would need those patches re-pinned.
- **PR-8 (with P-2's P2-1).** Accept P2-1 for the end tail; this design's end calls rename one-for-one (seam X-2).
- **PR-10 (LLR-177.1f threshold, F-1).** Add "`current_file.variant_id` equals the opened variant's id after the install (1 assertion)" to LLR-177.1f; the snapshot normalisation does not see a lost variant id.

## Design risks

- **R-1 (re-indent and size).** `_save_project_files` carries about 550 lines of the base commit half; `_handle_load_project` shrinks by about 170. Reviewers use `git diff -w`; TC-B100-07 (re-pinned), the 56 Save call lines and the 97 project-load call sites are the guard.
- **R-2 (toast order).** On a failed save the handler paints all lines, then raises the toast; on base the toast followed its own line, before the rollback notes. No test reads the interleaving of the status log and toasts (the census captures them separately).
- **R-3 (a second staging path).** Resolved by E3 S12b-05: `_write_editor_document` is retired; the worker calls the unchanged `write_change_document` with a deep-copied snapshot, so a later fix to `changes/io.py`'s staging reaches Save.
- **R-4 (handler raises).** A defect in `_install_prepared_project` reaches Textual from a `call_after_refresh` callback and ends the app (loud, Q-d1 parity); the run is ended first by its guard (P1-34).
- **R-5 (between step 4 and the install).** For one refresh the worker has returned and the run is still open; requests are refused (the run exists) and a quit waits (the tail has not run).
- **R-6 (stale cache read).** `_a2l_cache_entry()` reads two attributes without a lock (F-6); safe only because no session action overlaps another.

## Platform notes

Windows-only arms (reported not run on the Linux CI, never passed): P1-10's junction arm, P1-68 (junction swap during the rollback). Paths in the examples are built with `Path` (`W / 'Q'`), so the painted texts follow the platform separator. The probe ran on Windows.

## Requirement coverage (G-A + G-B)

Requirements owned by P-1 (G-A: project load; G-B: Save project), and their shared halves:

| Requirement | Examples |
|---|---|
| HLR-177 (project load and Save halves) | P1-84 (elapsed arm, AT-B100-18 worker half), P1-15, P1-58 (thread arms, 2 of the 3 worker steps) |
| HLR-177a (P-1's two action starts, Q-a1) | P1-12, P1-56 |
| HLR-177c (Save arms) | P1-73 |
| LLR-177.1 | P1-10, P1-11, P1-15, P1-22, P1-23 |
| LLR-177.1a | P1-54, P1-58, P1-62 |
| LLR-177.1c (project and Save arms) | P1-16, P1-59 |
| LLR-177.1d (project load, Save, and their failures: 4 of the 6 runs; Q-h1 file-load arm) | P1-06, P1-32, P1-41, P1-67, P1-75 |
| LLR-177.1e (project and Save workers) | P1-08, P1-25, P1-44, P1-52, P1-66 |
| LLR-177.1f | P1-19, P1-20, P1-28 |
| LLR-177.1g | P1-27, P1-29, P1-14 |
| LLR-177.1h | P1-31, P1-37 |
| LLR-177.1i | P1-55 |
| LLR-177.1j | P1-69 |
| LLR-177.2 | P1-35 |
| LLR-177.2a | P1-64, P1-70 |
| LLR-177.3h (project-load exits) | P1-36, P1-27 |
| LLR-177.4c (project and Save arms) | P1-33, P1-73 |
| LLR-177.5 (project half) | P1-21, P1-03 |
| LLR-177.5a | P1-62, P1-63 |
| LLR-176.3 (project install step) | P1-26 |
| LLR-165.1 (§C.1) | P1-14, P1-29 |
| LLR-165.2 (TC-B100-09) | P1-83 |
| LLR-164.4 (TC-B100-07 worker arms) | P1-60, P1-65, P1-66 |
| LLR-176.1l (P-1's two worker bodies, the kickoffs, the install) | P1-13, P1-17, P1-34, P1-57, P1-61 |
| LLR-176.1q (P-1's workers) | P1-18 |
| LLR-176.2, LLR-176.2c, LLR-176.2d (re-derived over P-1's bodies) | P1-11, P1-28, P1-35, P1-62, P1-65 |
| LLR-178.3 | P1-31 |
| LLR-167.2 (review F4, kept) | P1-69 |

Requirements left uncovered by P-1: **0**. Owned by P-2 and not covered here: HLR-177b, LLR-177.1b, LLR-177.1k, LLR-177.2b, LLR-177.3 … LLR-177.3g, LLR-177.4, LLR-177.4a, LLR-177.4b, LLR-177.4d, LLR-177.5 (A2L attach half), LLR-176.3 (tag-table half), LLR-176.4, LLR-176.4a, LLR-176.4b.
