# Inc 12b — proposed interfaces between G-A (project load), G-B (Save project), G-C (A2L attach, busy refusal, quit) and G-D (`a2l.py` progress callback)

PROPOSED by the E2 baseline. The orchestrator fixes it as `interfaces-12b.md`; a group never changes an interface alone. G-A, G-B and G-C edit `s19_app/tui/app.py`; G-D edits `s19_app/tui/a2l.py` and `tests/test_engine_unchanged.py` (ruling Q7: 2 source files). Base: main `8947666` plus the fixed interfaces of Inc 9b (`../../inc-9b-design/codewire/interfaces-9b.md`), Inc 10 (`../../inc-10-design/codewire/interfaces-10.md`), Inc 11 (`../../inc-11-design/codewire/interfaces-11.md`) and Inc 12a (`../../inc-12a-design/codewire/interfaces-12a.md`, **consumed unchanged**: `begin_busy` / `step_busy` / `end_busy`, `_busy`, `_busy_begin_action`, `_busy_fail`, `gen` keyword-only and required). Evidence ids: `p12b Un` = lines of `probe-p12b.out.txt`; `P12b-n` = the E1 probes in `../work/`. Node names are those of `baseline-12b.md`.

**Order (E1 rulings "Sequencing", E1-scope §3).** G-C1 first (the shared busy check, the quit flag, the end tail: S-a, S-c), then G-D (S-f, an independent file), then G-A, G-B, then G-C2 (the A2L attach, the work-area pick, the 17 refusal calls). Each later group calls the G-C1 helpers by the names below and adds no second copy.

**Who owns which shared function.**

| Function | Owner | Other groups |
|---|---|---|
| `_running_session_action`, `_refuse_if_busy`, `_exit_if_quit_pending`, `action_quit`, `_answer_quit`, `_quit_pending` | G-C1 | G-A, G-B, G-C2 call them |
| `_start_load_worker`, `_handle_load_error`, `load_from_path` (12a bodies): their ends switch to the end tail | G-C1 | G-C2 adds a caller of `_start_load_worker` |
| `parse_a2l_file`, `build_section_tree`, `A2LProgress` | G-D | G-A, G-C2 pass a callback |
| `_progress_forwarder` | G-D's consumer side, written by G-C1 with the end tail (it is app code) | G-A (A2L step), G-B (files placed), G-C2 (A2L step) |
| `A2LCacheEntry`, `parse_a2l_cached`, `_a2l_cache_entry`, `_store_a2l_cache` | G-A (E1 A9) | G-C2's A2L worker; the file-load path (Q-h1) |
| `_parse_loaded_file` (and its pure sibling, E1 A8) | G-A | `_start_load_worker` keeps calling `_parse_loaded_file` |
| `ProjectLoadRequest`, `PreparedProjectLoad`, the project worker and handlers | G-A | `_route_load_project` (G-A) |
| `SaveRequest`, `SaveOutcome`, the Save worker and handlers, `_write_and_verify_manifest` | G-B | — |
| `A2LAttachRequest`, `A2LAttachResult`, the A2L worker and handlers, `_load_workarea_file` | G-C2 | — |

```python
# app.py — G-C1: the busy check, the quit flag, the end tail (main thread only)
SESSION_ACTION_KEYS: frozenset[BusyKey] = frozenset({"file_load", "a2l_load", "project_load", "save_project"})   # S-a, ruling Q2
_BUSY_LINE = "busy: {label} is running — wait for it to finish."                                          # S-a, LLR-177.3f
_QUIT_TITLE = "Quit?"                                                                                      # S-c, LLR-177.4a
_QUIT_BODY = "still working: {label} — wait, or quit after it finishes"
_QUIT_YES, _QUIT_NO = "Quit (y)", "Stay (n)"

def _running_session_action(self) -> Optional[_BusyRun]: ...          # newest run in self._busy.runs whose key is in SESSION_ACTION_KEYS
def _refuse_if_busy(self) -> bool: ...                                 # True = refused (busy line painted, nothing else changed)
def action_quit(self) -> None: ...                                     # override of Textual's async App.action_quit (S-c)
def _answer_quit(self, quit: Optional[bool]) -> None: ...              # ConfirmQuestionScreen callback
def _exit_if_quit_pending(self) -> None: ...                           # exit() when _quit_pending and no session action runs
def _progress_forwarder(self, key: BusyKey, gen: int, n: int) -> A2LProgress: ...   # worker-side callable (S-f)
# __init__: self._quit_pending: bool = False                           # the ONE new app attribute (TC-B100-09)

# a2l.py — G-D
A2LProgress = Callable[[int, int], None]                               # (bytes_consumed, total_bytes)
def build_section_tree(path: Path, progress: Optional[A2LProgress] = None) -> tuple[list[dict], list[str]]: ...
def parse_a2l_file(path: Path, progress: Optional[A2LProgress] = None) -> dict: ...

# app.py — G-A: the A2L cache seam (S-h) and the project load (S-b, S-g)
A2LCacheEntry = tuple[tuple[str, int, int], dict]                      # ((resolved path, mtime_ns, size), parsed payload)
def parse_a2l_cached(path: Path, cached: Optional[A2LCacheEntry], progress: Optional[A2LProgress] = None) -> A2LCacheEntry: ...   # module level, pure
def _a2l_cache_entry(self) -> Optional[A2LCacheEntry]: ...             # main: the current entry or None
def _store_a2l_cache(self, entry: A2LCacheEntry) -> None: ...          # main: assigns _a2l_cache_key / _a2l_cache_data
# _load_a2l_data_with_cache: RETIRED (E3 DF-7 / PR-6): its 4 base callers move to `parse_a2l_cached`; the one test re-pins to `parse_a2l_cached`.

@dataclass(frozen=True)
class ProjectLoadRequest:                 # built by _handle_load_project after the cheap refusals
    name: str                             # the listed on-disk spelling
    project_dir: Path                     # self.workarea / name, unresolved (SEC-1)
    data_files: tuple[Path, ...]          # post-9b _list_project_files, read in the request frame
    a2l_files: tuple[Path, ...]           # 0 or 1, after _a2l_admission
    a2l_problem: Optional[ProjectFileProblem]
    a2l_cache: Optional[A2LCacheEntry]
    gen: int
    routed: bool                          # True from _route_load_project only (LLR-177.1h)

@dataclass(frozen=True)
class PreparedProjectLoad:                # the project worker's result; nothing in it is session yet
    request: ProjectLoadRequest
    refusal: Optional[str]                # post-10 all-None refusal ("No supported files in project: …"), else None
    variant_set: ProjectVariantSet
    manifest: Optional[ProjectManifest]
    problems: tuple[ProjectFileProblem, ...]
    a2l_cache: Optional[A2LCacheEntry]    # the entry the install stores (S-h); its [1] is the A2L context (A12b-04)
    install: InstallSet                   # after the next-valid fallback
    image: Optional[LoadedFile]           # the opened variant, parsed with explicit A2L inputs and no merge into the session
    unreadable: tuple[VariantDescriptor, ...]
    mac: Optional[LoadedFile]             # P2's MAC merged with `image` (never with the live current_file)
    document: Optional[RecordedDocumentState]   # None when nothing is recorded

def _handle_load_project(self, name: Optional[str], routed: bool = False) -> None: ...   # request frame: cheap refusals, request, begin, start
@work(thread=True, exit_on_error=…)       # Q-d1
def _project_load_worker(self, request: ProjectLoadRequest) -> None: ...
def _on_project_loaded(self, prepared: PreparedProjectLoad) -> None: ...         # main: refusal end, or paint step 4 then defer the install (LLR-176.3)
def _install_prepared_project(self, prepared: PreparedProjectLoad) -> None: ...  # main: reset, installs, announcement, panel, end tail LAST
def _on_project_load_failed(self, request: ProjectLoadRequest, exc: BaseException) -> None: ...   # main: `could not be read`, end tail

# app.py — G-B: the Save worker (S-b)
@dataclass(frozen=True)
class SaveImageInput:                     # the emit's inputs, read from the session on the main thread
    derived: Mapping[int, int]            # prepared.image_step.derived (re-derived on main, LLR-177.1i)
    ranges: tuple[tuple[int, int], ...]   # current_file.ranges
    file_type: str
    s0_header: Optional[bytes]
    source_path: Path
    summary: Optional[ChangeSummary]      # prepared.image_step.summary
    applied: tuple[int, ...]              # record_save_entries() result, taken on main
    not_applied: tuple[int, ...]

@dataclass(frozen=True)
class SaveRequest:
    prepared: _PreparedSave               # Inc 11 S-c, unchanged
    payload: SaveProjectPayload           # batch, assignments
    image: Optional[SaveImageInput]       # None for a copy-only save
    document_kind: str
    document_source_path: Optional[Path]
    document_class: Optional[str]         # classify_active_document(...)[0], computed on main
    document_bytes: Optional[bytes]       # the pasted document serialised on main; None when file-backed
    declared_regions: tuple[DeclaredRegion, ...]
    active_template: Optional[Path]       # self._last_template_path
    workarea: Path
    base_dir: Path
    gen: int

@dataclass(frozen=True)
class SaveOutcome:
    request: SaveRequest
    committed: bool
    lines: tuple[str, ...]                # status lines before the outcome, in today's order
    outcome: str                          # the last painted line → end tail outcome
    toast: Optional[tuple[str, str]]      # (title, text), or None (E3 DF-4 / PR-1)
    variant_set: Optional[ProjectVariantSet]
    saved_variant_id: Optional[str]
    verify_result: Optional[ManifestVerifyResult]
    emit_verify: Optional[VerifyResult]   # the image verify, for the main-thread summary (Q-b2)
    document_source_path: Optional[Path]  # the rebinding the tail assigns (pasted landing or save-as follow), computed on the worker
    pasted_placed: bool
    recorded_document: Optional[str]      # the panel's dirty-line condition (E3 DF-5 / PR-2)

def _commit_project_save(self, prepared: _PreparedSave, payload: SaveProjectPayload) -> None: ...   # Inc 11 name kept: begin (12a), record_save_entries, request, start
@work(thread=True, exit_on_error=…)       # Q-d1
def _save_project_worker(self, request: SaveRequest) -> None: ...      # C1–C4: files only; reads only the request
def _on_project_saved(self, outcome: SaveOutcome) -> None: ...         # main: session writes, adopt_rederived, mark_saved, tail lines, end tail LAST
def _write_and_verify_manifest(…) -> …: ...                             # shape: Q-b1

# app.py — G-C2: the A2L attach (S-b)
@dataclass(frozen=True)
class A2LAttachRequest:
    source: Path                          # resolve_input_path result (already checked)
    copy: bool                            # False for the work-area pick (in place)
    temp_dir: Path                        # self.workarea / WORKAREA_TEMP
    workarea: Path
    record_recent: bool                   # decided on main (not contained, not found through the fallback)
    a2l_cache: Optional[A2LCacheEntry]
    gen: int

@dataclass(frozen=True)
class A2LAttachResult:
    request: A2LAttachRequest
    path: Path                            # the work-area copy, or the source in place
    entry: A2LCacheEntry                  # key + parsed payload
    parse_seconds: float

def load_a2l_from_path(self, path: Path, *, copy: bool = True) -> None: ...   # main checks, request, begin, start
@work(thread=True, exit_on_error=…)       # Q-d1
def _a2l_attach_worker(self, request: A2LAttachRequest) -> None: ...
def _on_a2l_attached(self, result: A2LAttachResult) -> None: ...       # main: paint step 3, defer the tag-table build (LLR-176.3)
def _install_attached_a2l(self, result: A2LAttachResult) -> None: ...  # main: current_a2l_*, current_file.a2l_*, recent record, refresh_files, update_a2l_view, labels, focus, sync, end tail LAST
def _on_a2l_attach_failed(self, request: A2LAttachRequest, exc: BaseException) -> None: ...   # main: `could not be read`, end tail
```

## Seams

- **S-a, the busy check (G-C1; E1 S-a, ruling Q2; constraint P12b-1: a state check, never an exclusive group).**
  - `_running_session_action()`: `next((run for key, run in reversed(self._busy.runs.items()) if key in SESSION_ACTION_KEYS), None)`. It reads `self._busy.runs` only (12a S-b: ordered, newest last; `_BusyRun.label` already painted through `painted_names`). It writes nothing in `_busy`.
  - `_refuse_if_busy()`: `run = self._running_session_action()`; `None` → `return False`. Else `self.set_status(_BUSY_LINE.format(label=run.label))`, one INFO log line, `return True`. No `focus`, no `push_screen`, no `notify`, no `#status_text` write (LLR-177.3g; the line goes to the status log only, the indicator keeps `#status_text`, HLR-176d).
  - Report, diff-report and before/after runs never trigger it; they are not in `SESSION_ACTION_KEYS`.
  - Call form at each site, as its first statement: `if self._refuse_if_busy(): return`.
  - Sites (E1 C6, 17): `action_load_file`, `action_load_project`, `_confirm_then_load` (before `_load_would_lose`, LLR-177.3a), `action_select_variant`, `action_unload_all`, `on_loaded_artifacts_panel_unload_requested`, `action_save_project`, `on_patch_editor_panel_action_requested` (top of the dispatcher, so all 11 arms incl. `save_doc` and `execute_scope`, baseline Surprise 4), `on_patch_editor_panel_save_back_decision`, `on_patch_editor_panel_undo_requested`, `on_patch_editor_panel_redo_requested`, `action_patch_undo`, `action_patch_redo`, `on_patch_editor_panel_edit_json_requested`, `on_patch_editor_panel_entry_edit_json_requested`, `on_patch_editor_panel_change_file_selected`, `on_patch_editor_panel_dirty_load_requested`. Whether the four action starts also check: Q-a1.
  - Evidence: P12b-1 (the exclusive group lets a cancelled worker's install land); baseline C6 nodes (no state check on base).
- **S-b, request and result values (E1 S-b; constraint LLR-177.1e: a worker reads only an immutable request).**
  - One frozen dataclass per request, built on the main thread before the worker starts, passed as the worker's **only** argument. The worker body and every `app.py` method it calls read no `self.current_file`, `self.current_project`, `self.current_project_dir`, `self.current_a2l_path`, `self.current_a2l_data`, `self._variant_set`, `self._change_service` (the LLR-177.1e census list), and no other session attribute (`_a2l_cache_*`, `_declared_regions`, `_last_template_path`, `_parsed_paste_text`, `base_dir` / `workarea` come from the request). They may call `self.call_from_thread`, `self.logger`, and module-level pure functions.
  - A result value is handed to exactly one main-thread handler with `self.call_from_thread(handler, result)`. The handler is the only writer of the session for that action (LLR-177.1d).
  - A frozen dataclass may hold mutable objects (`ProjectVariantSet`, `LoadedFile`, the parsed A2L `dict`); the worker builds them and never touches them after the hand-off, and `call_from_thread` orders the hand-off.
  - **Project load (G-A).** The request frame keeps every refusal that needs no file content (folder check, `exists()`, listing match, the `project.json` gate, `_list_project_files` and its catch, cardinality, `_a2l_admission`, "no data or A2L"), then `_busy_begin_action("project_load", name)`, the request, `_project_load_worker(request)`. The worker runs, in the post-10 order: `build_variant_set`, `read_project_manifest`, `check_project_files`, the recorded variant, `parse_a2l_cached` (byte callback on step 2), `choose_install_set` and the all-`None` refusal, the image parses with the next-valid fallback (step 3), the MAC parse merged with the worker's own `image` (U2: never with the live `current_file`), `recorded_document_state`. A merged MAC is built with the pure merge rule applied to explicit arguments (E1 A8). Base digest to equal (LLR-177.1f): p12b U1.
  - **Save project (G-B).** `_commit_project_save` keeps its Inc 11 name and signature. On the main thread: the 12a begin, `self._change_service.record_save_entries()` (a service write, LLR-177.1d), the `SaveImageInput` from `current_file` and `prepared.image_step`, the document facts (`document_home_for_kind`, `classify_active_document`, the pasted bytes), then `_save_project_worker(request)`. The worker runs C1–C4 of the commit (mkdir … verified manifest) and the rollback; it never assigns `_report_filter_path`, `_variant_set`, `current_file.variant_id`, `current_project(_dir)` or `_last_manifest_verify_result` (U4 lists the base's writes) — the variant set is a worker local handed back in `SaveOutcome`. The handler `_on_project_saved` writes them, then (when committed and emitting) `adopt_rederived` and `_surface_verify_result`, `mark_saved`, the tail lines, `panel.mark_saved()`, the document rebinding, `refresh_files`, the flow session folder. `_abort_save` keeps only the file rollback (E1 B5); the failure arm paints the same lines as today and adopts nothing (review F4, LLR-177.1j). Manifest writer: Q-b1. Emit: Q-b2.
  - **A2L attach (G-C2).** `load_a2l_from_path(path, *, copy=True)`: the not-found, suffix and project-guard refusals and the size warning stay on the main thread, then the 12a begin, the request (`record_recent` decided here with the post-9b fallback rule), `_a2l_attach_worker(request)`. The worker copies (`copy_into_workarea`, unless `copy is False`) and parses (`parse_a2l_cached`, byte callback on step 2). The recent record, `refresh_files`, `current_a2l_path` / `current_a2l_data`, `current_file.a2l_*`, the cache store and `update_a2l_view` run in the main-thread handlers. `WorkareaContainmentError` from the copy keeps its own line `Cannot load A2L: …` (12a A12-39) and is not a `could not be read` failure.
- **S-c, the quit flag and the end tail (G-C1; E1 S-c; constraint P12b-3: exit from the end handler, never a main-thread wait).**
  - `action_quit()` (sync; Textual's `run_action` awaits either form): `run = self._running_session_action()`; `None` → `self.exit()` (LLR-177.4d). Else push `ConfirmQuestionScreen(_QUIT_TITLE, _QUIT_BODY.format(label=run.label), _QUIT_YES, _QUIT_NO)` with `_answer_quit` (LLR-177.4, .4a). The modal starts on `#confirm_no` (Stay) by its own `AUTO_FOCUS` (Inc 10 S-a). A second `ctrl+q` while it is open: Q-c2.
  - `_answer_quit(quit)`: falsy → nothing (Stay, LLR-177.4b). Truthy → `self._quit_pending = True`; `self._exit_if_quit_pending()` (the action may have ended while the question was open).
  - `_exit_if_quit_pending()`: `self._quit_pending and self._running_session_action() is None` → `self.exit()`.
  - No `_finish_session_action` / `_fail_session_action` wrappers and no `final_line` (E3 DF-1 / P2-1): end sites call `end_busy(key, gen, outcome)` / `_busy_fail(key, gen)` directly as their last statement; the quit-after-end check lives inside `end_busy` (12a A12a-07). 12a's `end_busy` finishes its hand-back before it returns (12a S-a), so the exit sees the hand-back done.
  - **Rule: in every session action's main-thread end handler, the end tail is the last statement** (after the Load-result panel push, the labels, `_rehome_focus_after_load`, the syncs). A quit then exits after everything the handler does.
  - End sites (by group): G-A `_install_prepared_project`, the refusal arm of `_on_project_loaded`, `_on_project_load_failed`; G-B `_on_project_saved` (both arms); G-C2 `_install_attached_a2l`, `_on_a2l_attach_failed`, the containment arm; G-C1 the file load (12a code): `_start_load_worker`'s success end (posted through `call_from_thread`), `_handle_load_error`, `load_from_path`'s containment end, and every `except BaseException` / kickoff guard that posts `_busy_fail`. The failure arms clear `_quit_pending` first (E3 S12b-01). Count and the file-load sync order: Q-c1.
  - New attribute: `self._quit_pending = False` in `__init__`, classified in `SNAPSHOT_EXCLUSIONS` as `"_quit_pending": "quit confirmed while a session action runs; UI control state, not session state (Inc 12b)"` (TC-B100-09). Requests and results are never stored on the app, so this is the only new attribute.
  - Evidence: P12b-3 (after `exit()` a worker's `call_from_thread` callback still lands, with the app no longer running); Textual 8.2.8 `call_from_thread` returns `future.result()` (a main-thread wait on the worker would deadlock).
- **S-d, worker options (E1 S-d; constraint P12b-2: every worker body catches its own failures).**
  - Each 12b worker: `@work(thread=True, exit_on_error=<Q-d1>)`, no `exclusive`, no shared `group` with `_start_load_worker`'s `"load"` group (an exclusive group in `"load"` would cancel the file-load `Worker` object; P12b-1).
  - Body shape (12a S-e kept, with the 12b tail):
    ```python
    try:
        try:
            result = <worker step; reads only `request`>
        except Exception as exc:                       # the worker step's own failures (LLR-177.2 … .2b)
            self.logger.exception(...)                 # the traceback, on the worker (logging is thread-safe)
            self.call_from_thread(self._on_<action>_failed, request, exc)
            return
        self.call_from_thread(self._on_<action>_done, result)   # outside the inner try: a handler raise is not a worker failure
    except BaseException:                              # E3 DF-3 / PR-5 / S12a-06
        self.call_from_thread(self._busy_fail, key, request.gen)   # a no-op after an effective end (12a A12-72)
        raise
    ```
  - A handler that raises on the main thread re-raises inside the worker's `call_from_thread` (12a probe ga-timer C1). What then happens to the app is Q-d1.
  - The **main-thread kickoff** (`_handle_load_project`, `_commit_project_save`, `load_a2l_from_path`, `_load_workarea_file`'s data arm) guards the code after its begin with `except BaseException: self._busy_fail(key, gen); raise` — not 12a's `finally`, because the run now outlives the function (12a finding F-1 / ruling P-7 wording). This changes 12a's `finally` in those three bodies.
  - **Save shutdown safety (E3 S12b-07):** after `mkdir`, every cross-thread call in the Save worker (the `step_busy` posts and the single `call_from_thread` of the outcome) sits inside the rollback `try`. In a real `App.run()`, after `exit()` a worker's `call_from_thread` raises `RuntimeError('App is not running')`, and `run()` returns only after the thread ends, so an exit that is not ours makes the next step or tick post raise **inside** the rollback `try` — the save is rolled back or already complete, never half-written (production semantics beside P12b-3, which measured `run_test`).
- **S-e, the Inc 9b / 10 / 11 hooks (E1 S-e).**
  - `_confirm_then_load(kind, target, go)` (Inc 10): `if self._refuse_if_busy(): return` before `_load_would_lose` (LLR-177.3a). The question is never pushed while busy.
  - `_route_load_project(name)` (Inc 10): `go` becomes `lambda: self._handle_load_project(name, routed=True)`; the `before` / identity test after the call is deleted (LLR-177.1h). `_install_prepared_project` pushes `LoadResultScreen(announcement)` with `_handle_load_result` when `prepared.request.routed` and the announcement was composed. A direct `_handle_load_project(name)` (97 test sites) keeps `routed=False` → 0 panels (LLR-174.3b).
  - `_load_workarea_file(name)` (9b G1, post-10, post-12a S-i): the A2L arm in `go` becomes `self.load_a2l_from_path(candidate, copy=False)` (in place, LLR-177.1b; 9b Surprise 2's self-copy goes); the data arm becomes the file-load start in place: `gen = self._busy_begin_action("file_load", candidate.name)`; `self.step_busy("file_load", gen, 2)` (no copy step; 12a's consumed-table row says a skipped step is allowed); `self._start_load_worker(candidate, gen=gen, sync_project=False)` (E3 DF-9 / P2-2), guarded by `except BaseException: self._busy_fail("file_load", gen); raise` (LLR-177.1k). `load_selected_file` is no longer called on the pick.
  - Save (Inc 11): the router `_handle_save_dialog` and `_prepare_project_save` are unchanged; the re-derive stays in `_save_session_inputs` / `_decide_project_image` on the main thread (ruling Q1, LLR-177.1i). `_commit_project_save` becomes the kickoff of S-b.
- **S-f, the parser callback (G-D; E1 S-f).**
  - `parse_a2l_file(path, progress=None)` passes `progress` to `build_section_tree(path, progress)` and returns the same dict as today (LLR-176.4a). Callers outside `app.py` (`change_service.py:3225`, `flow_execution_service.py:358`, `:461`, `variant_execution_service.py:2662`) keep calling it with one argument.
  - `build_section_tree` reports `progress(consumed, total)` where `total` is the file size taken at open and `consumed` is the raw byte position of the text wrapper's buffer (`handle.buffer.tell()`): it counts CRLF bytes, so the last report equals the size (p12b U3: text-mode line lengths are short by 1 byte per line). Reports are non-decreasing; the last report is `(total, total)` at the end of the read, so an A2L smaller than one chunk gets exactly 1 report (case_01, U3). No report on the `FileNotFoundError` soft-error path; an `OSError` still re-raises. How often it reports: Q-f1.
  - The app side: `_progress_forwarder(key, gen, n)` returns a callable for the worker. It forwards `self.call_from_thread(self.step_busy, key, gen, n, done, total)` only when `floor(100 * done / total)` changed since its last forward (so at most 101 blocking round trips per step), and always forwards the final `(total, total)`. It closes over `key`, `gen`, `n` only (no session read). The A2L worker and the project worker use it on step 2; the Save worker uses it on step 2 with `done` = files placed and `total` = files the plan places (LLR-177.5a; `_copy_project_subfolders` and the rows loop call it once per placement).
  - Whether the workers always pass `progress=`: Q-f2.
- **S-g, the project install handler (G-A; LLR-176.3, LLR-177.1f, .1g, .1h).**
  - `_on_project_loaded(prepared)`: `prepared.refusal` → `self.end_busy("project_load", gen, prepared.refusal)` with 0 resets (post-10 C58). Else `self.step_busy("project_load", gen, 4)` and `self.call_after_refresh(self._install_prepared_project, prepared)` — the step name is painted before the install's work starts (LLR-176.3; the `call_after_refresh` idiom of `app.py:8708`).
  - `_install_prepared_project(prepared)` runs in **one** main-thread callback with no `await`: `_reset_project_session()` (its one call site, LLR-165.1 / -177.1g), `_declared_regions`, `_store_a2l_cache`, the A2L-only attach, the document into the service and panel, `current_project`, `current_project_dir`, `_variant_set`, the image install (`_pending_variant_id`, then `_apply_loaded_file`), the MAC install, `active_id`, the announcement, `_last_load_announcement`, labels, flow session folder, the Load-result panel when routed, and the end tail **last**: `self.end_busy("project_load", gen, safe_text(announcement.summary_line()).plain)` (the summary is the outcome, 12a A12-42; the project and file line is stored with `set_file_status` before the end, 12a A12a-06; no `final_line`, E3 DF-1). Because `current_project` and the announcement are set inside the same callback, the 159 W-class test polls on `current_project == name` see a complete install.
  - The two installs vs one merged install: Q-g1.
- **S-h, the A2L cache (G-A; E1 A9, LLR-177.1d).**
  - `parse_a2l_cached(path, cached, progress)`: `stat` → key `(str(path.resolve()), st_mtime_ns, st_size)`; `cached` with the same key → return it (a hit, no parse); else `(key, parse_a2l_file(path, progress=progress))` (or `parse_a2l_file(path)` without a callback, Q-f2). Module-level and pure; it logs the hit / miss as today.
  - The request carries `self._a2l_cache_entry()` read on the main thread; the result carries the entry; the main-thread handler calls `_store_a2l_cache(entry)`. `_load_a2l_data_with_cache` is **retired** (E3 DF-7 / PR-6); its one test re-pins to `parse_a2l_cached`, and the C8 spy at `test_b100_project_homes.py:1996` (which monkeypatches the retired name) re-pins to `parse_a2l_cached` too.
  - The file-load worker (`_start_load_worker` → `_parse_loaded_file` → `_load_mac_file` / the S19 / HEX branch) also writes the cache off the main thread today (baseline `_load_a2l_data_with_cache`): Q-h1. The out-list form of PR-7 wins (E3 DF-8): `_parse_loaded_file(…, *, a2l_cache_out=None)` reads `_a2l_cache_entry()` itself and appends; `_start_load_worker` sets `PreparedLoad.a2l_cache = out[0] if out else None`.

## What Inc 12b consumes, unchanged (checked against the fixed files)

| 12b need | Seam that serves it |
|---|---|
| the newest session action and its painted label (S-a, S-c) | 12a S-b `self._busy.runs` (ordered), `_BusyRun.label` |
| `gen` in every request (S-b) | 12a `_busy_begin_action` / `begin_busy` return it; workers take it from the request |
| a failure end that is a no-op after success (S-d) | 12a `_busy_fail` (accepted P-1), `end_busy -> bool` |
| byte reports in the parse step; files placed in the placement step (S-f) | 12a `step_busy(key, gen, n, done, total)`; `a2l_load` step 2, `project_load` step 2, `save_project` step 2 (fixed Q-5) |
| a main-thread step painted before its work (S-g, LLR-176.3) | 12a `step_busy` paints synchronously; `a2l_load` step 3 `Build the tag table`, `project_load` step 4 `Install` |
| the project and file line at the end (S-g) | 12a `set_file_status(...)` stores it before the end (A12a-06); no `final_line` (E3 DF-1) |
| the quit question (S-c) | Inc 10 `ConfirmQuestionScreen(title, body, yes_label, no_label)`, `AUTO_FOCUS = "#confirm_no"`, `y` / `n` / `escape`, `_dismissed` guard |
| the re-derive before the worker (ruling Q1) | Inc 11 `_save_session_inputs` → `_decide_project_image` on the main thread |
| the prepared save the worker executes (S-b) | Inc 11 `_PreparedSave` (S-c), the router `_handle_save_dialog` unchanged |
| the load guard's entry (S-e) | Inc 10 `_confirm_then_load(kind, target, go)` |

12b needs no change to any fixed 9b / 10 / 11 / 12a signature. It changes the bodies of three 12a kickoffs (`finally` → `except BaseException` + re-raise, S-d) and the file-load ends (S-c), which 12a's design allows (no signature change).

## Open questions (one per undecided seam)

- **Q-a1 (S-a), do the four action starts also check?**
  - Option 1 (E1 C6 as written): only the 17 request entry points check. A programmatic start while busy is not refused: `support/b100_projects.py:383` `append_variant` (project load, 1 pause, `load_from_path`) races two session writers (census A9), and so does any future direct chain.
  - Option 2: also `if self._refuse_if_busy(): return` at the top of `load_from_path`, `load_a2l_from_path`, `_handle_load_project` and `_commit_project_save` (4 more lines). Every second session writer is then refused, loudly and deterministically, whatever the route; the 17 entry checks stay, because they must refuse before a dialog or the load question opens.
  - Recommendation: option 2. It makes "two writers at once" impossible by construction, which is the defect class HLR-177a removes. Cost: tests that chain a second action without waiting get a busy line (they are already in census A / B and are re-pinned anyway).
- **Q-b1 (S-b), the manifest writer's shape.**
  - Option 1 (E1 B4): `_write_and_verify_manifest(project_dir, variant_set, …) -> Optional[ManifestVerifyResult]` (None = not written), no attribute write, no painting; `_rewrite_project_manifest` assigns `_last_manifest_verify_result` and paints. Breaks census C9 (6 tests and 2 monkeypatches pin the `bool` return, the keyword set and the attribute).
  - Option 2: a new pure worker-side function `_write_manifest_for_save(project_dir, variant_set, base_dir, …) -> tuple[bool, Optional[ManifestVerifyResult], tuple[str, …]]` (ok, result, lines to paint) used only by the Save worker, and `_write_and_verify_manifest` keeps its signature and behaviour for its main-thread callers by calling it. C9's pins hold; the two monkeypatches of `_write_and_verify_manifest` in Save tests (`test_b100_document.py:815`, `test_b100_save_image.py:836`) must move to the new function.
  - Recommendation: option 2 (fewer re-pins, one shared core, the main-thread callers untouched).
- **Q-b2 (S-b), the image emit on the worker.**
  - `ChangeService.emit_and_verify` reads `self.last_summary` and `self.last_save_applied` / `not_applied`, and writes `summary.verify_result` (baseline Surprise 6).
  - Option 1: the worker calls the module functions directly (`save_patched_image`, `verify_written_image`) with the request's `SaveImageInput` (summary, applied / not-applied split), builds the same message, and returns the `VerifyResult` in `SaveOutcome.emit_verify`; the main-thread handler sets `summary.verify_result` before `adopt_rederived`. `ChangeService` is untouched (it is outside the 2-file cap).
  - Option 2: keep calling `self._change_service.emit_and_verify` from the worker with `summary=` given. It works today (no attribute assignment), but LLR-177.1e's census names `self._change_service`, and the summary is written off the main thread.
  - Recommendation: option 1.
- **Q-c1 (S-c), the file-load ends and their order.** Switching the file load to the end tail touches 12a's code at `_start_load_worker` (success end, `finally`), `_handle_load_error`, and `load_from_path`'s containment end and kickoff guard (5 sites). 12a finding F-7 keeps `_sync_loaded_file_to_project` **after** the end, posted by a second `call_from_thread`; with a quit pending, `exit()` runs at the end and the sync callback still lands afterwards (P12b-3), writing `project.json` on an app that is shutting down. Option 1: keep F-7's order (the sync completes after `exit()`; the log keeps its order). Option 2: move the end after the sync for the file load only (the log order changes: `Added variant …` before `Loaded <name>`, so HLR-176c's "last line = outcome" then also holds with a project open). Recommendation: option 2 — the quit rule "the end tail is the last statement" then holds for all four session actions, and F-7's declared exception goes away.
- **Q-c2 (S-c), `ctrl+q` while the quit question is open.** `quit` is not in `_LOAD_DIALOG_INERT_ACTIONS` and `ctrl+q` is a priority binding, so it reaches `action_quit` under the question and would stack a second one. Option 1: `action_quit` returns when a `ConfirmQuestionScreen` built by it is already on the stack (one `any(…)` over `screen_stack`, tested by identity of a marker attribute or by the title `Quit?`). Option 2: add `quit` to the inert set while a `ConfirmQuestionScreen` is on the stack — but that also blocks `ctrl+q` under the Inc 10 load question when idle, which exits today. Recommendation: option 1.
- **Q-d1 (S-d), `exit_on_error` for the three workers.** Every worker-step failure is caught in the body (LLR-177.2 … .2b), so the flag only decides what a **main-thread handler** defect does (it re-raises inside the worker's `call_from_thread`). Option 1 (E1 S-d): `exit_on_error=False` — the app keeps running; the `finally` ends the run with `<label> failed`; the traceback must then be logged explicitly (Textual stores it on the `Worker` only); the session may be half-installed. Option 2: Textual's default `exit_on_error=True` — a handler defect ends the app (`WorkerFailed`), as the same defect does today when the install runs on the main thread. Recommendation: option 2 (parity with the base for main-thread defects, loud; the worker-step failures, which are the ones LLR-177.2 covers, are caught either way). The same question applies to `_start_load_worker`, which keeps the default today.
- **Q-f1 (S-f), how often the parser reports.** Option 1 (E1 "at most once per chunk"): check `handle.buffer.tell()` after every line, report on change — 4 608 reports for case_06 and +0.59 s on the read loop (+12 % of the 5.01 s parse, p12b U3). Option 2: check the position once every 4 096 lines and at the end of the read — about 255 reports for case_06 (1 039 926 lines), a negligible cost, still ≥ 2 reports (LLR-176.4) and the last equal to the size. Option 3: report when the position crosses each 1/64 of the file — at most 65 reports, one comparison per check. Recommendation: option 2 (simple, bounded; the app-side forwarder caps the round trips at 101 either way).
- **Q-f2 (S-f), passing `progress=` when tests fake the parser.** Two tests replace `parse_a2l_file` with a one-parameter fake (census C6 `test_tui_app.py:403`, C7 `test_b100_project_check.py:704`); a third fake is tolerant (C8). Option 1: the workers always pass `progress=`; `parse_a2l_cached` calls `parse_a2l_file(path)` when it has no callback (the main-thread `_load_a2l_data_with_cache` has none, so C6 holds); C7's `_denied(path)` then raises `TypeError` inside the worker and the test passes for the wrong reason → re-pin `_denied` to `(path, *args, **kwargs)` (one line). Option 2: always call `parse_a2l_file(path, progress=progress)` → C6 and C7 both need the one-line re-pin. Recommendation: option 1 plus the C7 re-pin (no production branch exists only for tests: the no-callback call is the real main-thread path).
- **Q-g1 (S-g), two installs or one.** `test_b100_session_reset.py::test_tc_b100_08_reset_runs_once_before_the_first_install` pins `["reset", "install", "install"] * 2` for an S19 + MAC project (census C2). Option 1: the worker returns `image` and the merged `mac` separately and the handler installs both through `_apply_loaded_file` in that order, as the base does (the test holds; 2 view rebuilds as today). Option 2: one merged install (1 rebuild; the test is re-pinned to `["reset", "install"] * 2`). Recommendation: option 1 (base parity, no re-pin, the install path unchanged).
- **Q-h1 (S-h), the file-load worker's cache write.** E1 A9 says the cache write moves to the main thread "for every caller", which includes the existing file-load worker (`_parse_loaded_file`, reached also by the 12b work-area pick, LLR-177.1k). Option 1: declare it and leave it — it is outside the three 12b workers, outside LLR-177.1d's six probe runs, and fixing it changes 12a's `_start_load_worker` / `PreparedLoad` / `_apply_prepared_load` path. Option 2: `_start_load_worker` reads the entry at its start (an off-thread read of one attribute), `_parse_loaded_file` uses `parse_a2l_cached`, `PreparedLoad` gains `a2l_cache: Optional[A2LCacheEntry] = None`, and `_apply_prepared_load` stores it. Recommendation: option 2 if the orchestrator wants LLR-177.1d to hold for the pick it routes through that worker (LLR-177.1k); otherwise option 1 with a backlog row. I lean to option 2: the pick is a 12b route, and the off-main write is the defect LLR-177.1d names.

## Census consequences the orchestrator should see with these seams

- **E1's numbers.** 340 sites / 29 files / 11 no-app tests → **184 distinct sites / 26 files / 1 no-app test** (baseline-notes "Correction"). The ruling Q6 strategy is unchanged.
- **Not in E1's re-pin list:** census C1 (`_abort_save`'s `_variant_set` AST assert, from E1 B5), C5 (`test_no_new_parse_loaded_file_call_sites`), C9 (the manifest writer pins; avoided by Q-b1 option 2 except the 2 monkeypatches), C2 (only under Q-g1 option 2), C6 / C7 (Q-f2), C8 (re-point a spy).
- **E1 says two timing tests become vacuous; only one does** (`test_tc_b100_30_hostile_document_is_one_not_readable_under_one_second`).
- **TC-B100-09** needs exactly one new classification (`_quit_pending`) under these seams.
</content>
</invoke>

## Orchestrator rulings (2026-10-31): this file is now FIXED

The orchestrator owns this file. A prototype group proposes and never edits an interface alone.

- **Q-a1, yes.** The 4 action starts (`load_from_path`, `load_a2l_from_path`, `_handle_load_project`, `_commit_project_save`) also run the busy check, so a direct call races nothing.
- **Q-b1, new worker-side core.** `_write_and_verify_manifest` stays as it is; the 6 test pins hold.
- **Q-b2, direct calls.** The Save worker calls `save_patched_image` / `verify_written_image`, never `emit_and_verify`, which reads and writes service state (E1 contradiction 5).
- **Q-c1, yes.** The file-load end comes after `_sync_loaded_file_to_project` (matches 12a A12a-05).
- **Q-c2, yes.** `ctrl+q` while the quit question is open is ignored inside `action_quit`.
- **Q-d1, `exit_on_error=True`.** Every worker step catches its own failures; a defect in a main-thread handler stays loud.
- **Q-f1:** the parser reports when the buffer position is checked, every 4 096 lines.
- **Q-f2, yes.** Workers always pass `progress=`. Re-pin the one-line `_denied(path)` fake. The main-thread cache path calls without a callback.
- **Q-g1, yes.** The project install keeps two installs (image, then MAC); TC-B100-08 holds.
- **Q-h1, yes.** The file-load worker's off-main cache write moves to the main thread; `PreparedLoad` gains one field.
- **From 12a's E3 (binding):**
  - one exclusive worker group per busy key — **superseded for 12b by E3 DF-2 / P2-4: one distinct, non-exclusive group per busy key;**
  - a worker cancelled before it starts gets `end_busy` from its canceller (S12a-05) — **superseded for 12b by E3 DF-2: with a distinct non-exclusive group no worker is cancelled, so no canceller owes an `end_busy`;**
  - the quit-after-end check lives inside `end_busy` (A12a-07);
  - worker guards are `except BaseException` + end + re-raise (S12a-06).
