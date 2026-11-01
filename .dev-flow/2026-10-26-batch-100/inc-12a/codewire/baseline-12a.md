# Code-Wire baseline — batch-100 Inc 12a slice ("the progress indicator", the labels and the sweep) on main 8947666, designed post-9b / post-10 / post-11

Scope: the functions on the Inc 12a paths (HLR-176 … HLR-176d, LLR-176.1 … LLR-176.1s, LLR-176.2 … LLR-176.2d, LLR-173.2m, LLR-172.4e, .4f, .5i, .5j, .5k, .6b, .6c; E1-scope §3). Group G-A: the three status writers (`set_progress`, `set_file_status`, `set_status`), the 12 functions that hold the 24 `set_progress` sites (P-29), the synchronous install the project load reaches, and the Save project commit that LLR-176.2d hooks into. Group G-B: the palette builder that reads `BINDINGS`, the project list, the Workarea Files list, the typed-path classifier and router, the project load's listing match, the work-area pick, and the two 9b providers that read the suffix predicate and the classifier. Context: the suffix predicate (`recent_kind`), the lister, the one scrub.

Base: main `C:\Users\jjgh8\Github\s19_app` at `8947666` (Inc 9a merged), clean apart from the untracked `prototypes/load_projects/`. sha256 prefixes: `app.py` bbf04117fbf0, `styles.tcss` 781f04ed2cc3, `workspace.py` 0af4b9248923. Line numbers are `8947666` lines of `s19_app/tui/app.py` unless another file is named.

Post-9b / post-10 / post-11 nodes. Inc 9b, 10 and 11 run before 12a and are not in the code yet. A node one of them changes says so in `func:` ("post-9b", "post-10", "post-11") and gives the body their graph designs (`inc-9b-design/codewire/proto-9b-app.md`, `inc-10-design/codewire/proto-10-app.md`, `inc-11-design/codewire/proto-11-app.md`, and the three fixed `interfaces-*.md`). Four nodes exist only in those graphs and are marked "(post-9b / post-10 / post-11, from the graph; not yet in code)": `_load_workarea_file`, `_load_dialog_rows`, `_load_dialog_verdict`, `_commit_project_save`. They were left out of the extractor run (a node without code).

Example lines come from the probe `p12a` (this folder, run on a throwaway copy, baseline-notes "Probe"), from the E1 probes P12a-1 … P12a-4 (`../work/p*_*.out.txt`), from an existing test, or from a code read; each names its source. Every example states behaviour that holds on the base, unless it says "post-9b" / "post-10" / "post-11", where it holds on that graph. Where 12a turns a line RED, the line says so ("RED side of …"). `func:` says "12a changes: …" where a 12a requirement changes the function; a node with no "12a changes" is context.

## Nodes

S19TuiApp.set_progress
req: LLR-176.2, LLR-176.2a, LLR-176.1a, LLR-176.1k
in: int value; str? message = None
out: None
func: `bar.update(total=100, progress=max(0, min(100, value)))` on `#progress_bar`; a truthy `message` goes to the status log through `set_status`. No owner, no state: 24 call sites in 12 functions write it directly or through `call_from_thread` (P-29). 12a changes: signature kept (three test spies and one one-argument lambda replace it, §D.3); called only from inside the seam (LLR-176.2a). Whether the seam still passes a `message` (the begin and step lines logged as today) is interface question Q-3.
module: s19_app/tui/app.py
examples: (P12a-1, executed) AST census of `app.py` → 24 calls in 12 functions: `action_before_after_report` 1, `_start_before_after_worker` 3, `_trigger_generate_report` 1, `_start_generate_report_worker` 3 (one inside the nested `report_failed`), `_finish_generate_report` 1, `on_ab_diff_panel_report_requested` 1, `_start_diff_report_worker` 5, `load_from_path` 3, `load_a2l_from_path` 4, `_start_load_worker` 1, `_handle_load_error` 1 (holds on base; RED side of LLR-176.2a: 24 calls outside any seam)
examples: (probe p12a U1.1) a file load → spy values `[10, 50, 100]`, end bar `100`, and the two begin/step messages `Copying into workarea temp...`, `Parsing firmware.s19...` in the log (holds on base; RED side of LLR-176.1a: the base starts at 10, and of LLR-176.1k: the bar ends at 100)
examples: (test_report_progress::test_finish_generate_report_completes_bar) `set_progress(40)` then `_finish_generate_report(...)` → bar `100` (holds on base; RED side of LLR-176.1k)

> callers (extractor): `S19TuiApp.action_before_after_report` (direct, :4874); `S19TuiApp._trigger_generate_report` (direct, :5564); `S19TuiApp._finish_generate_report` (direct, :5794); `S19TuiApp.on_ab_diff_panel_report_requested` (direct, :6908); `S19TuiApp.load_from_path` (direct, :13045, :13053, :13067); `S19TuiApp.load_a2l_from_path` (direct, :13121, :13126, :13142, :13169); `S19TuiApp._handle_load_error` (direct, :15814). Not seen by the extractor (the method passed as a value to `call_from_thread`, 13 sites, P12a-1): `_start_before_after_worker` :4943, :4957, :4969; `_start_generate_report_worker` :5650, :5687, :5710; `_start_diff_report_worker` :6962, :6969, :6976, :6987, :6997; `_start_load_worker` :15781

S19TuiApp.set_file_status
req: LLR-176.1h, HLR-176d, LLR-176.1j
in: str message
out: None
func: `self.query_one("#status_text", Label).update(message)` at once; no check of a running action. The only `#status_text` query site in `app.py` (P12a-1). Two writers: `_apply_prepared_load` (the file state) and `_handle_load_project` (the project and file line; it passes a `Text` from `safe_text`, not a `str`). 12a changes: while any run exists, keep the message as the pending file state and paint nothing (LLR-176.1h); painted at once when no run exists (its boundary).
module: s19_app/tui/app.py
examples: (P12a-2, executed) across `load_from_path(case_01)`, `#status_text` takes `Ready.` then `Loaded firmware.s19 (S19 only)`, the second painted while the bar is at `50` (holds on base; RED side of HLR-176d / LLR-176.1h)
examples: (probe p12a U1.6) `_handle_load_project("P")` → `#status_text` ends `Loaded project 'P' -> firmware.s19` after two writes (the MAC/image install's file state, then the project line) (holds on base; post-12a the same final text through the final line, LLR-176.1j)
examples: (test_filename_markup_safety, :94) a hostile file name through `set_file_status` → painted verbatim, markup off (holds on base)

> callers (extractor): `S19TuiApp._handle_load_project` (direct, :11942); `S19TuiApp._apply_prepared_load` (direct, :15464)

S19TuiApp.set_status
req: LLR-176.1i
in: str message
out: None
func: `self._append_log_line(message)`: one status-log line, stripped, an empty message dropped, capped at `max(50, width)` characters, painted with markup off. Every action's result line goes through it. 12a changes: none; the end's outcome is written through it (LLR-176.1i).
module: s19_app/tui/app.py
examples: (probe p12a U1.4) an A2L load → log lines `Copying A2L into workarea temp...`, `Parsing firmware.a2l...`, `Loaded firmware.a2l`, `A2L loaded: firmware.a2l` (holds on base; the first three come from `set_progress` messages)
examples: (code read `_append_log_line`) `set_status("   ")` → 0 lines added (holds on base; the LLR-176.1i empty-outcome arm relies on it)

> callers (extractor): in the slice: `S19TuiApp.set_progress` (direct, :17945); `S19TuiApp.action_before_after_report` (:4857); `S19TuiApp._trigger_generate_report` (:5517, :5529, :5553, :5558, :5560); `S19TuiApp._finish_generate_report` (:5795); `S19TuiApp.on_ab_diff_panel_report_requested` (:6866); `S19TuiApp._handle_load_project` (10 direct sites, :11702 … :11871); `S19TuiApp._handle_save_dialog` (37 direct sites; 8 through unmarked helpers such as `_abort_save`); `S19TuiApp._load_path_from_user_input` (:12966); `S19TuiApp.load_from_path` (:13036, :13041, :13054); `S19TuiApp.load_a2l_from_path` (:13091, :13095, :13103, :13107, :13127, :13170); `S19TuiApp.load_selected_file` (:15083, :15094); `S19TuiApp._handle_load_error` (:15813). The workers' `call_from_thread(self.set_status, …)` sites are values, not calls. Outside the slice: more than 150 top-level sites (extract.json `top_level_sites`)

S19TuiApp.compose
req: LLR-176.1s, LLR-176.1
in:
out: ComposeResult widgets
func: the persistent status bar: `Horizontal#status_line` holding `Label("Ready.", id="status_text", markup=False)` and `Label("", id="status_context", markup=False)`, then `ProgressBar(total=100, id="progress_bar")`, then the 4 `#log_line_*` labels. `styles.tcss` gives `#status_line` `height: 1`, `#status_text` `width: 1fr; text-overflow: ellipsis`, `#progress_bar` `margin-top: 1`. No rule hides the bar. 12a changes: none (LLR-176.1s holds on base); 12a may add one `styles.tcss` rule (interface S-g).
module: s19_app/tui/app.py
examples: (probe p12a U3.4, P12a-2) at 118×54 idle → `#status_line` height `1`, `#progress_bar` region `(2, 46, 46, 1)`, `#log_line_1` y `47`; during a load the same (holds on base; LLR-176.1s is RED only as a mutation)
examples: (code read `:2819`) the start-up text of `#status_text` is `Ready.` (holds on base; the LLR-176.1j third arm hands back to it)

> callers (extractor): none listed (Textual calls it). It calls `S19TuiApp._build_palette_entries` (direct, :2767)

S19TuiApp.load_from_path
req: LLR-176.2, LLR-176.2c, HLR-176, HLR-176a, LLR-176.1h, AT-B100-17
in: Path path
out: None
func: post-9b (the CR9-1 `via_fallback` condition on the record step; otherwise the base body). Refusals before any progress: `resolve_input_path` → `None` → `File not found: <path>`; suffix not in `SUPPORTED_EXTENSIONS` → `Unsupported file type: <suffix>`. Then `set_progress(10, "Copying into workarea temp...")`; `copy_into_workarea` — `WorkareaContainmentError` → `set_progress(0, "")` + `Cannot load file: <exc>`; the recent record (post-9b condition); `set_progress(50, f"Parsing {copied.name}...")`; `_start_load_worker(copied)`; `call_later` of `refresh_files` and two log lines. The copy runs on the main thread (12b keeps it there, 12b ruling Q5). 12a changes: begin `file_load` in place of `set_progress(10, …)`; a step at the parse; the containment refusal after the begin ends the run with a failure outcome; the worker receives the run's generation (interface S-a / Q-1).
module: s19_app/tui/app.py
modify: [I/O: workarea temp]
examples: (probe p12a U1.1) `load_from_path(case_01/firmware.s19)` → spy `[10, 50, 100]`, log `Copying into workarea temp...`, `Parsing firmware.s19...`, `Loaded firmware.s19 (S19 only)`, `Loaded firmware.s19`, `#status_text` `Loaded firmware.s19 (S19 only)`, bar `100` (holds on base; RED side of HLR-176, LLR-176.1a, LLR-176.1k)
examples: (probe p12a U1.3) `copy_into_workarea` raising `WorkareaContainmentError` → spy `[10, 0]`, log `Copying into workarea temp...`, `Cannot load file: synthetic containment refusal`, bar `0` (holds on base; the reachable failure exit after the begin for LLR-176.2c)
examples: (P12a-3, executed) a generated S19 with 8 MiB of data (20 709 376 bytes) parses in `S19File` in 2.38 s, on the load worker (holds on base; the AT-B100-17 12a-half fixture)
examples: (proto-9b-app B24, post-9b) typed `j\x.s19` found only through the base-folder fallback → `1` load, `0` recent records

> callers (extractor): `S19TuiApp._load_path_from_user_input` (direct, :12942); post-10 inside `_confirm_then_load`'s `go` closure; `_handle_select_variant` (:7606, not marked)

S19TuiApp._start_load_worker
req: LLR-176.2, LLR-176.2c, LLR-176.1l, LLR-176.1q, HLR-176a
in: Path path; list[Path]? a2l_files = None
out: None
func: `@work(thread=True, exclusive=True, group="load")`, default `exit_on_error=True`. `_parse_loaded_file` inside `try` → any exception → `call_from_thread(_handle_load_error, path, exc)`, return; `None` → `_handle_load_error` with `Unsupported file type: <suffix>`; `_prepare_load_payload` (an exception falls back to `PreparedLoad(loaded=loaded)`); then `call_from_thread(_apply_prepared_load, …)`, `call_from_thread(set_progress, 100, f"Loaded {path.name}")`, and `_sync_loaded_file_to_project` when a project is open. Statements outside the two `try` blocks (the logger calls) are not guarded: a raise there escapes the worker and ends the app (12b P12b-2). 12a changes: steps and the end through `call_from_thread`; a `try` / `finally` that posts the end with a failure outcome on a raise (LLR-176.1l, interface S-e); it needs the run's generation (Q-1).
module: s19_app/tui/app.py
examples: (probe p12a U1.1) success → `_apply_prepared_load` then `set_progress(100, "Loaded firmware.s19")` on the main thread, in that order (holds on base)
examples: (probe p12a U1.2) `_parse_loaded_file` raising `RuntimeError` → log `Load failed: synthetic parse failure`, `Load failed`, spy `[10, 50, 100]`, bar `100` (holds on base; RED side of HLR-176c: the failed load leaves the bar at 100)
examples: (test_tui_variants, :228) AST: `_parse_loaded_file` is called in exactly `_install_project_image`, `_start_load_worker`, `load_selected_file` (holds on base; a 12a refactor of the worker keeps the call here)

> callers (extractor): `S19TuiApp.load_from_path` (direct, :13071)

S19TuiApp._handle_load_error
req: LLR-176.2c
in: Path path; Exception exc
out: None
func: main thread. Clears `_pending_variant_id`, logs an error, `set_status(f"Load failed: {exc}")`, then `set_progress(100, "Load failed")`. 12a changes: `end_busy(file_load, gen, "Load failed")` replaces the last call (LLR-176.2c's named mutant site); it needs the generation of the run it ends (Q-1).
module: s19_app/tui/app.py
examples: (probe p12a U1.2) → log `Load failed: synthetic parse failure`, then `Load failed`; bar `100` (holds on base; RED side of LLR-176.1k / HLR-176c)
examples: (grep) 0 test files call `_handle_load_error` directly (holds on base)

> callers (extractor): none listed: `_start_load_worker` passes it as a value to `call_from_thread` (:15742, :15745)

S19TuiApp._apply_prepared_load
req: LLR-176.1h, HLR-176d
in: PreparedLoad prepared; Path path; float load_started
out: None
func: main-thread install of a parsed file: session fields, caches, then `status_message = self._format_coexistence_status(loaded, path)`; `set_file_status(status_message)`; `_append_log_line(status_message)`; then the deferred view refreshes. Reached from the load worker (through `call_from_thread`) and synchronously from `load_selected_file` (project load, work-area image pick). 12a changes: none in its body; its `set_file_status` becomes the pending file state while a run exists (through `set_file_status`, LLR-176.1h).
module: s19_app/tui/app.py
examples: (P12a-2, executed) during a worker load, `Loaded firmware.s19 (S19 only)` reaches `#status_text` while the bar is at 50, before the load's last progress call (holds on base; RED side of HLR-176d)
examples: (probe p12a U1.1) the coexistence line is also appended to the log before the outcome `Loaded firmware.s19` (holds on base)

> callers (extractor): `S19TuiApp.load_selected_file` and `S19TuiApp._handle_load_project` (both through an unmarked helper, :15253, the deferred-install step); `_start_load_worker` passes it as a value to `call_from_thread` (:15779)

S19TuiApp.load_selected_file
req: LLR-176.2b, LLR-176.2d
in: Path path; list[Path]? a2l_files = None
out: None
func: the synchronous parse-and-install on the main thread (`_parse_loaded_file`, `_prepare_load_payload`, `_apply_prepared_load`). No progress call. Reached from `_handle_load_project` (the MAC install) and from the work-area image pick (`_load_from_item`; post-9b `_load_workarea_file`). The work-area pick is not one of the 7 long actions at 12a (12b LLR-177.1k moves it onto the file-load worker). 12a changes: none.
module: s19_app/tui/app.py
examples: (probe p12a U2.4) a `#files_list` pick of `fw.s19` that is a file symbolic link to a file outside the work area → `_parse_loaded_file` called on it, `current_file.path` = the link inside `W/temp` (holds on base; RED side of LLR-172.6b arm (c))
examples: (proto-10-app C39, post-10) `W/temp/x.s19` deleted between the question and `y` → `FileNotFoundError` in the parse → `1` status line starting `Load failed:`, session unchanged

> callers (extractor): `S19TuiApp._handle_load_project` (direct, :11920); `S19TuiApp._load_from_item` (direct, :13335)

S19TuiApp.load_a2l_from_path
req: LLR-176.2, LLR-176.2c, LLR-176.1l
in: Path path
out: None
func: post-9b (the CR9-1 condition on the record step). Main thread throughout. Refusals before progress: not found, `Unsupported A2L type`, the project guard (`validate_project_files` error, `Project already has an A2L file.`). Then `set_progress(10, "Copying A2L into workarea temp...")`; `copy_into_workarea` — `WorkareaContainmentError` → `set_progress(0, "")` + `Cannot load A2L: …`; record; `refresh_files()`; `set_progress(50, f"Parsing {copied.name}...")`; `_load_a2l_data_with_cache(copied)` (no `try`: a parse raise leaves the function); views, labels, the Loaded panel; `set_progress(100, f"Loaded {copied.name}")`; `set_status(f"A2L loaded: {copied.name}")`; focus re-home; sync to the project. 12a changes: begin `a2l_load` at the first progress call; steps at copy / parse / install; end on the containment refusal and on success; a `try` / `finally` ends the run with a failure outcome when the parse raises (LLR-176.1l). Its line is painted and cleared within one blocked call (declared invisibility, HLR-176a).
module: s19_app/tui/app.py
modify: [I/O: workarea temp]
examples: (probe p12a U1.4) `load_a2l_from_path(case_01/firmware.a2l)` → spy `[10, 50, 100]`, log `Copying A2L into workarea temp...`, `Parsing firmware.a2l...`, `Loaded firmware.a2l`, `A2L loaded: firmware.a2l`, bar `100` (holds on base; RED side of LLR-176.1k)
examples: (probe p12a U1.5) `_load_a2l_data_with_cache` raising `RuntimeError` → the exception leaves `load_a2l_from_path`; spy `[10, 50]`, bar left at `50`, no end line (holds on base; RED side of LLR-176.1l: the bar is left mid-fill)
examples: (proto-9b-app B10, post-9b) a `workarea` choice of `c.a2l` → this function, including its `copy_into_workarea` (an identical-file reuse), status `A2L loaded: c.a2l`

> callers (extractor): `S19TuiApp._load_path_from_user_input` (direct, :12939); `S19TuiApp._load_from_item` (direct, :13333); post-10 inside `_confirm_then_load`'s `go`

S19TuiApp.action_before_after_report
req: LLR-176.2, LLR-176.2c
in:
out: None
func: key `b` and the save-back control. On the UI thread: an optional report filter read and resolved (a fault → `Before/after report refused: …`, return, no progress); then `set_progress(15)` and `_start_before_after_worker(loaded path or None, project dir, filter, display name)`. 12a changes: begin `before_after` in place of `set_progress(15)`; the generation goes to the worker (Q-1).
module: s19_app/tui/app.py
examples: (probe p12a U1.15) nothing loaded → spy `[15, 0]`, log `Before/after report refused: No applied change summary - …`, bar `0` (holds on base; the refusal is decided in the worker, after the kickoff, so it is a failure exit after the begin)
examples: (test_before_after_report::test_at_038a_saveback_trigger_report_pair_reread_from_surfaced_path, :271) a real save-back then `b` → spy ends `100` (holds on base; RED side of LLR-176.1k: the re-pin reads the cleared bar)

> callers (extractor): none listed (key `b`, the save-back control)

S19TuiApp._start_before_after_worker
req: LLR-176.2, LLR-176.2c, LLR-176.1l, LLR-176.1q
in: Path? loaded_path; Path? project_dir; ReportFilterMatcher? report_filter; str source_name
out: None
func: `@work(thread=True, exclusive=True, group="before_after_report")`. `compose_before_after_report(...)` in a `try`: an exception → log, `call_from_thread(set_progress, 0)`, `Before/after report failed: …`; written → `call_from_thread(set_progress, 100)`, `Before/after report written: <md> | <html>`; refused → `call_from_thread(set_progress, 0)`, `Before/after report refused: …`. 3 exits, 3 `set_progress` sites. 12a changes: each exit posts the end through `call_from_thread` (its result line stays or becomes the outcome, Q-3); a `try` / `finally` covers the code outside the composer's `try`.
module: s19_app/tui/app.py
examples: (probe p12a U1.16) composer stubbed to a written result → spy `[15, 100]`, log `Before/after report written: …`, bar `100` (holds on base)
examples: (test_report_off_ui_thread::test_ac3_before_after_progress_never_sticks_mid_fill) the last spy value is `0` or `100` (holds on base; holds post-12a, where the last value is the cleared bar `0`)

> callers (extractor): `S19TuiApp.action_before_after_report` (direct, :4875)

S19TuiApp.on_report_viewer_screen_generate_requested
req: LLR-176.2
in: ReportViewerScreen.GenerateRequested message
out: None
func: stores the declared regions and calls `_trigger_generate_report(context_bytes, declared_regions)`. Caller-only node, listed so that the extractor shows the report's entry. 12a changes: none.
module: s19_app/tui/app.py
examples: (tests/test_tui_report_seam._generate_through_surface) the `#report_generate` press on `ReportViewerScreen` → this handler → `_trigger_generate_report` (holds on base)

> callers (extractor): none listed (Textual message dispatch)

S19TuiApp._trigger_generate_report
req: LLR-176.2, LLR-176.2c
in: int context_bytes; Sequence[DeclaredRegion] declared_regions = ()
out: None
func: UI-thread gate. Refusals before progress: no project variants; a report filter that does not read or parse; no manifest and no change file. Then one status line (`Report: no prior execution - running active scope...` or `Report: generating from last execution...`), `set_progress(15)`, `_start_generate_report_worker(...)`. 12a changes: begin `report` in place of `set_progress(15)`; the generation goes to the worker (Q-1).
module: s19_app/tui/app.py
examples: (probe p12a U1.11) a reportable project → log `Report: no prior execution - running active scope...`, `Executing variant 'a' (1 file(s))...`, `Variant 'a': ok - 1 change, 0 check`, `Report: reports/<stamp>-report.md`; spy `[15, 55, 100]`, bar `100` (holds on base; RED side of LLR-176.1k)
examples: (test_report_progress::test_kickoff_sets_bar_in_progress_before_worker) the worker stubbed out → bar `15`, `0 < p < 100` (holds on base; RED side of LLR-176.1a: the begin sets 0, so this test turns RED and is re-pinned)

> callers (extractor): `S19TuiApp.on_report_viewer_screen_generate_requested` (direct, :5460)

S19TuiApp._start_generate_report_worker
req: LLR-176.2, LLR-176.2c, LLR-176.1l, LLR-176.1q
in: Path project_dir; ProjectVariantSet variant_set; int context_bytes; tuple[Path, str, str, List[VariantExecutionResult]]? last; list[Path] fallback_batch; Sequence[DeclaredRegion] declared_regions = (); ReportFilterMatcher? report_filter = None
out: None
func: `@work(thread=True, exclusive=True, group="generate_report")`. The nested `report_failed(exc)` (the single tool-failure branch, TC-572: built once, called twice) logs, posts `set_progress(0)` and `Report failed: <type>: <exc>`. Span 1 (options + scope run, `status_callback` posts the variant lines): `ValueError` → `set_progress(0)` + `Report rejected: …`; other → `report_failed`. Then `set_progress(55)`; span 2 `generate_project_report` → `report_failed` on any exception; success → `call_from_thread(_finish_generate_report, report_path)`. 12a changes: a step before span 2 (the 55 site); the ends through `call_from_thread`; `report_failed` keeps being the single branch (TC-572 counts its source strings).
module: s19_app/tui/app.py
examples: (probe p12a U1.12) `generate_project_report` raising `RuntimeError` → log ends `Report failed: RuntimeError: synthetic report failure`, spy `[15, 55, 0]`, bar `0` (holds on base)
examples: (test_tui_report_attribution::test_at263_pin_progress_resets_to_zero_on_both_branches) the worker called directly, with `set_progress` replaced by a one-argument recorder → the failure and the rejection branches both record a last value `0` (holds on base; RED side under 12a: a direct call has no begin, so the seam writes nothing for it — census row)
examples: (test_tui_report_attribution::test_tc572_the_tool_failure_sequence_exists_exactly_once) the source holds `f"Report failed:` once and `report_failed(exc)` twice (holds on base; a structural pin 12a keeps)

> callers (extractor): `S19TuiApp._trigger_generate_report` (direct, :5565); direct test call `test_tui_report_attribution.py:109`

S19TuiApp._finish_generate_report
req: LLR-176.2c, LLR-176.1k
in: Path report_path
out: None
func: main thread, success only: drops `_last_execution`, `set_progress(100)`, `set_status(f"Report: {parent}/{name}")`. 12a changes: the end of the `report` run (success outcome); it needs the generation (Q-1).
module: s19_app/tui/app.py
examples: (probe p12a U1.11) → log `Report: reports/<stamp>-report.md`, bar `100` (holds on base; RED side of LLR-176.1k)
examples: (test_report_progress::test_report_generation_drives_progress_bar_to_100, :49) a real report → bar `100` (holds on base; RED side of LLR-176.1k, named for re-pin in E1 §D.3)

> callers (extractor): none listed: `_start_generate_report_worker` passes it as a value to `call_from_thread` (:5719); direct test call `test_report_progress.py:127`

S19TuiApp.on_ab_diff_panel_report_requested
req: LLR-176.2, LLR-176.2c
in: AbDiffPanel.ReportRequested event
out: None
func: UI thread. No comparison → `panel.set_status("No comparison yet — press Compare first.", "sev-warning")`, return (no progress). Then the generator kwargs (mem maps, destination, A2L / MAC records, check spec, flow changes), `set_progress(15)`, `_start_diff_report_worker(panel, result, kwargs, diff_source)`. 12a changes: begin `diff_report` in place of `set_progress(15)`; the generation goes to the worker (Q-1).
module: s19_app/tui/app.py
examples: (code read `:6858`) no completed comparison → 1 panel status line, 0 progress calls (holds on base; a refusal before the begin)
examples: (test_report_off_ui_thread::test_ac2_diff_generators_run_off_the_ui_thread) both generators run off the UI thread (holds on base)

> callers (extractor): none listed (Textual message dispatch)

S19TuiApp._start_diff_report_worker
req: LLR-176.2, LLR-176.2c, LLR-176.1l, LLR-176.1q
in: AbDiffPanel panel; object result; dict kwargs; str diff_source
out: None
func: `@work(thread=True, exclusive=True, group="diff_report")`. Every result line goes to the diff panel's status (`panel.set_status`), never to the status log. Markdown refused → `set_progress(0)` + `Report refused: …`; `set_progress(55)`; HTML generator; exception → `set_progress(0)` + `Diff report failed: …`; HTML refused → `set_progress(0)` + `HTML report refused: …`; success → `set_progress(100)` + `Diff report written: <md>  |  <html>`. 4 exits, 5 `set_progress` sites. 12a changes: a step at the 55 site; each exit posts the end; the outcome for the status log is interface question Q-3 (today this action writes no status-log line at all).
module: s19_app/tui/app.py
examples: (probe p12a U1.13) both generators stubbed to written → spy `[15, 55, 100]`, `0` status-log lines, bar `100` (holds on base; RED side of HLR-176c's "the status log's last line is the outcome" for this action)
examples: (probe p12a U1.14) markdown refused → spy `[15, 0]`, `0` status-log lines (holds on base)
examples: (test_report_off_ui_thread::test_ac4_diff_progress_never_sticks_mid_fill) success → spy ends `100`; refused → ends `0` (holds on base; RED side of LLR-176.1k for the success arm)

> callers (extractor): `S19TuiApp.on_ab_diff_panel_report_requested` (direct, :6909)

S19TuiApp._handle_load_project
req: LLR-176.2b, LLR-176.2c, LLR-176.1j, LLR-176.1h, LLR-172.5j, LLR-172.5k
in: str? name
out: None
func: post-10 (from proto-10-app; 9b's listing / gate / catch inside it from proto-9b-app). Main thread throughout; no progress call. Order: `None` → return; `_project_folder_refusal` (link / unreadable / outside lines); `exists()` → `Project not found: <pn(name)>` (post-9b S9b-5); the listing match (`list_projects()` + `os.path.normcase`, an `OSError` → `could not be read`, no match → `is not a project`), the `project.json` lstat gate and `_list_project_files` (post-9b); the A2L admission; no data or A2L; then (post-10 S10-01) variant set, manifest, the A2L read and `choose_install_set` with its all-`None` refusal before `_reset_project_session()`; then the A2L-only attach, the document reopen, `current_project`, the image install loop (`_install_project_image`), the MAC through `load_selected_file`, the announcement, `set_status(summary_line)`, `set_file_status(safe_text(status_line))`. Post-10 the interim closed-document line is gone, so the project line is the last writer of `#status_text`. 12a changes: begin `project_load` after the cheap refusals; steps; the summary line becomes the outcome and the project line the final line (LLR-176.1j, TC-B100-56); every exit after the begin ends the run; the listing match moves into `_listed_project_name` (LLR-172.5j) and the two refusal sentences read the one table (LLR-172.5k).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.current_project] (replace)
examples: (probe p12a U1.6) project `P` (`firmware.s19`, `firmware.a2l`, `project.json` without `files`) → spy `[]`, log `Loaded firmware.s19 (S19 only)`, `Loaded project 'P' -> firmware.s19 - variant 1 of 1, 1 problem - details: p`, `#status_text` `Loaded project 'P' -> firmware.s19` (holds on base; RED side of HLR-176: no progress line)
examples: (probe p12a U1.7) `Q` holding only `project.json` → `Project NOT loaded: 'Q' has no data or A2L file — load a file and Save project.`, spy `[]`, `#status_text` unchanged (holds on base; a refusal before the begin)
examples: (probe p12a U1.8, B9) the E13 `wa-files` seed (`project.json` with no `files` key beside `firmware.s19`) → `check_project_files` → 1 problem `('no digests saved', 'project.json')` (holds on base; OBS-9a-2 is that problem, by design)
examples: (P12a-4, executed) the `list_projects()` + `normcase` match is written in 2 functions, this one and `_typed_load_route` (holds on base; RED side of LLR-172.5j)
examples: (test_b100_announce.py:432) after a project load, `#status_text` reads `Loaded project 'P' -> firmware_1.s19` (holds on base and post-12a through the final line)

> callers (extractor): `S19TuiApp._route_load_project` (direct, :7478); 13 test files call it directly (post-10 census)

S19TuiApp._route_load_project
req: LLR-176.2b
in: str? name
out: None
func: post-10: `go` = `_handle_load_project(name)` then push `LoadResultScreen` when `_last_load_announcement` is a new object; `self._confirm_then_load("project", name, go)`. Caller-only context node. 12a changes: none (12b passes `routed=True` in a request instead, 12b S-e).
module: s19_app/tui/app.py
examples: (proto-10-app C29, post-10) nothing unsaved → `go()` at once, `current_project == "Q"`, 1 Load-result panel

> callers (extractor): `S19TuiApp._load_path_from_user_input` (direct, :12936); post-9b the router `_handle_load_dialog` (`project` kind, deferred)

S19TuiApp._handle_save_dialog
req: LLR-176.2d, LLR-176.2c
in: SaveProjectPayload? payload
out: None
func: post-11 (proto-11-app; base `:9447`–`:10605` holds the guard-and-plan half and the commit half in one body). The one-argument router: drop the per-open session; `None` → return; G1–G3 (nothing loaded, parent not a folder, parent ≠ work area); `prepared = confirmed or self._prepare_project_save(name, session)`; `prepared.refusal` → status line (+ toast on the direct path), return; else `self._commit_project_save(prepared, payload)`. No progress call, before or after Inc 11. 12a changes: none here; a refused save returns before the commit, so it never begins (LLR-176.2d's refused arm).
module: s19_app/tui/app.py
examples: (probe p12a U1.9, base body) `SaveProjectPayload(W, "S1")` with case_01 loaded → log `Project saved + manifest verified`, `Saved project to …\S1 (variant 'firmware')`, spy `[]`, bar unchanged (`100`, left by the earlier load) (holds on base; RED side of LLR-176.2d: 0 steps)
examples: (proto-11-app B11-61, post-11) a disguised clash `a b` → refused in preparation → `0` commits

> callers (extractor): none listed (the dismiss callback, read at push time); 56 direct call lines in 11 test files (Inc 11 census)

S19TuiApp._commit_project_save
req: LLR-176.2d, LLR-176.2c, LLR-176.1l
in: _PreparedSave prepared; SaveProjectPayload payload
out: None
func: (post-11, from the 11 graph; not yet in code) the base commit half `:9856`–`:10605`, moved unchanged except the Q10 edits and `panel.is_dirty`. Phases in order: (C1) `project_dir.mkdir(exist_ok=False)`; (C2) state snapshot and rollback lists; (C3) one `try`: `validate_project_files`, sub-folder copies (`_copy_project_subfolders`), the rows loop (pasted document, `emit_and_verify` or `place_into_workarea`, each checked by `_plan_row_mismatch`), top-level copies, variant rebuild, `gather_project_artifacts`, SEC7-3 manifest keep, `_write_and_verify_manifest`; every failure → `_abort_save` + a status line + return (11 sites); (C4) four `except` arms (`WorkareaPlacementError`, `WorkareaContainmentError`, `OSError` → `_abort_save` + line + return; any other `Exception` → `_abort_save` then re-raise, SEC-7); (C5) committed tail: `mark_saved`, `Saved project to …`, the kept note, links line, document lines, the MISMATCH re-paint, `current_project`, labels, `refresh_files`, flow session folder. Counts (base body): 10 returns, 19 `set_status`, 2 `notify`. No progress call. 12a changes: begin `save_project` at entry; one step per phase named in the action table; an end on every one of the 15 exits (11 abort returns, 3 `except` returns, the committed tail) and before the SEC-7 re-raise (LLR-176.1l, Q8: 12a guarantees only the end).
module: s19_app/tui/app.py
modify: [I/O: work area]
examples: (probe p12a U1.10, base body) `place_into_workarea` raising `OSError(28)` after the `mkdir` → `Project NOT saved: could not save — [Errno 28] synthetic no space. check the folder.`, `S2` removed by the rollback, `0` raises, spy `[]` (holds on base; the reachable failure exit after the begin for LLR-176.2c)
examples: (proto-11-app B11-66, post-11) every `return` after the first `mkdir` follows an `_abort_save` call; exactly `1` `except OSError` after the `mkdir`

> callers (extractor): not run (no code)

S19TuiApp._build_palette_entries
req: LLR-173.2m
in:
out: tuple[PaletteEntry, ...] entries
func: the command palette's entries, built 1:1 from `BINDINGS` (label = the binding description, action = the binding action), one entry per action. The key bar (`window_help.py`) and Textual's help panel read the same descriptions. 12a changes: none in code; its output follows the `BINDINGS` labels (`Load file` → `Load`, `Load project` → `Projects`).
module: s19_app/tui/app.py
examples: (probe p12a U3.1) → entries `('Load file', 'load_file')`, `('Load project', 'load_project')` (holds on base; RED side of LLR-173.2m)
examples: (probe p12a U3.2) `BINDINGS` rows `('ctrl+l', 'load_file', 'Load file')`, `('l', 'load_file', 'Load file')`, `('p', 'load_project', 'Load project')` (holds on base; `app.py:2122`, `:2127`, `:2135`)
examples: (test_b97_key_bar.py:36) `GLOBAL_TEXTS` pins `^l Load file` on row 1 at 118 and 220 columns, and `GLOBAL_TEXTS_80 = GLOBAL_TEXTS[:6]` at 80×24 (holds on base; RED side of LLR-173.2m)

> callers (extractor): `S19TuiApp.compose` (direct, :2767)

S19TuiApp.list_projects
req: LLR-172.4e
in:
out: List[str] projects
func: post-9b (proto-9b-app, ruling Q7): `sorted(self.workarea.iterdir())`; skip reserved homes (case-folded); skip a name ending in `.` or ` ` **only when `os.name == "nt"`** (E3 R14, CR9-9); skip what `_project_folder_refusal` refuses and non-folders; (post-9b) skip a folder `_folder_holds_project` finds empty (`False`), list it when unreadable (`None`). An `OSError` from `iterdir` propagates. 12a changes: drop the `os.name == "nt"` gate (LLR-172.4e).
module: s19_app/tui/app.py
examples: (probe p12a U2.8) on Windows, `fw-v1.` and `fw-v2 ` made through `\\?\` (each with `project.json`) beside `P` → `['P']` (holds on base; the Windows arm of LLR-172.4e already passes)
examples: (P12a-4, executed; code read `:12122`) the `os.name == "nt"` gate is present → on the Linux CI the same fixture lists 3 projects (holds on base; RED side of LLR-172.4e, Linux arm)
examples: (proto-9b-app B17, post-9b) `e` (empty) and `n` (`notes.txt` only) → not listed

> callers (extractor): `S19TuiApp._handle_load_project` (direct, :11714); `S19TuiApp._typed_load_route` (direct, :12871); `action_load_project` (:7441, not marked; post-9b no longer a caller); post-9b `_load_dialog_rows`

S19TuiApp.refresh_files
req: LLR-172.4f
in:
out: None
func: clears `#files_list` and appends one `ListItem(Label(safe_text(painted_names([name]))))` per path `list_workarea_files(self.workarea)` returns (the regular, non-link direct children of `W/temp`, sorted), with `item.data` = the on-disk name. No suffix filter (C7). 12a changes: keep only the names the loadable-suffix predicate accepts, the one 9b's `_load_dialog_rows` reads (`recent_kind(p) is not None`, interface S-h).
module: s19_app/tui/app.py
examples: (probe p12a U2.1) `W/temp` holds `a.s19`, `b.hex`, `c.mac`, `d.a2l`, `d.a2l.json`, `e.txt` → rows `['a.s19', 'b.hex', 'c.mac', 'd.a2l', 'd.a2l.json', 'e.txt']` (holds on base; RED side of LLR-172.4f: 6 rows, not 4)
examples: (proto-9b-app B37, post-9b) the Load dialog's files section over the same folder → 3 rows `a.s19`, `b.hex`, `c.a2l` (no `.mac` in that fixture) through `recent_kind`

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, :10601; post-11 in `_commit_project_save`); `S19TuiApp.load_a2l_from_path` (direct, :13134); `S19TuiApp.load_from_path` (direct, :13075, inside the `call_later` closure); `on_mount` (:7195) and `action_refresh_files` (:7327), not marked

S19TuiApp._typed_load_route
req: LLR-172.5i, LLR-172.5j
in: Path path
out: Tuple[str, str] route
func: post-9b (step 11 through `_folder_holds_project`; the inside-W data / A2L arms after the lstat walk). Relative text: `resolve_input_path` → `None` → `not found`; folder → `not a supported file`; by suffix. Absolute: `resolve_input_path`; the lexical inside test; outside by suffix; inside: lstat walk (`not found`, `unreadable`, `link`), one component, the `list_projects()` + `normcase` match (`not a project`), then the content test. "Never raises" is claimed for `OSError` only: `resolve_input_path` on a relative text holding NUL raises `ValueError`. 12a changes: a `ValueError` from either `resolve_input_path` call → `("refuse", "not found")` (LLR-172.5i); the match moves into `_listed_project_name` (LLR-172.5j).
module: s19_app/tui/app.py
examples: (probe p12a U2.6; P12a-4) `Path("fw\x00.s19")` → raises `ValueError: stat: embedded null character in path` (holds on base; RED side of LLR-172.5i, relative arm)
examples: (probe p12a U2.6) `Path(<tmp>\fw\x00.s19)` (absolute) → `("refuse", "not found")` (holds on base; the absolute arm already refuses, so LLR-172.5i's absolute arms are GREEN on base)
examples: (proto-9b-app B23, post-9b) `W/empty` → `("refuse", "not a project")` at the listing step

> callers (extractor): `S19TuiApp._load_path_from_user_input` (direct, :12934); post-9b `_load_dialog_verdict`

S19TuiApp._load_path_from_user_input
req: LLR-172.5i, LLR-172.5k
in: Path path
out: None
func: post-10 (the `typed` strip and the `_confirm_then_load` seam on the `data` / `a2l` arms). `_typed_load_route(path)`: `project` → `_route_load_project`; `a2l` / `data` → the question seam then the loader; `refuse` → one status line built by an `if` chain over the six reason words, the typed text through `painted_names`, then `safe_text(...).plain`. Two of the six sentences are the shared project refusals: `Project NOT loaded: '<t>' is not a project — pick a project in the list.` and `Project NOT loaded: '<t>' could not be read — check that the folder can be opened, then load again.` 12a changes: the NUL arm is refused through the classifier (LLR-172.5i); those two sentences read the one table (LLR-172.5k).
module: s19_app/tui/app.py
examples: (probe p12a U2.7) `Path("fw\x00.s19")` → the `ValueError` leaves this function (holds on base; RED side of LLR-172.5i: post-9b it would leave the deferred router callback)
examples: (probe p12a U4.1) AST, docstrings excluded: the literal `not a project` 2 times (`:12949` the reason test, `:12950` the sentence) and `could not be read` 1 time (`:12963`) in this function (holds on base; RED side of LLR-172.5k)
examples: (proto-9b-app B23 holds) a typed `<W>/empty` → `Project NOT loaded: '<W>\empty' is not a project — pick a project in the list.`

> callers (extractor): none marked (`on_mount` :7228 is not a node); post-9b `_handle_load_dialog` (`path`, `recent`, deferred)

S19TuiApp._load_from_item
req: LLR-172.6b, LLR-172.6c
in: ListItem item
out: None
func: post-9b: `filename = item.data`; empty → return; `self._load_workarea_file(filename)`. Base body (`:13325`): `candidate = W/temp/<filename>`; `candidate.exists()` (follows a link); an A2L suffix → `load_a2l_from_path(candidate)`, else `load_selected_file(candidate)`. No `lstat`, no size check. 12a changes: none here (the re-check is in `_load_workarea_file`).
module: s19_app/tui/app.py
examples: (probe p12a U2.2) `fw.s19` listed, then replaced by a folder `fw.s19` → `_parse_loaded_file` called on it, log `Load failed: [Errno 13] Permission denied: …` (holds on base; RED side of LLR-172.6b arm (a): a parse is attempted)
examples: (probe p12a U2.3) replaced by a junction `fw.s19` to a folder outside the work area → `_parse_loaded_file` called, `Load failed: [Errno 13] …` (holds on base; RED side of arm (b))
examples: (probe p12a U2.4) replaced by a file symbolic link to `<tmp>/outside.s19` → parsed and installed (`current_file.path` = the link) (holds on base; RED side of arm (c); the privilege was available on this host)
examples: (probe p12a U2.5) `DEFAULT_COPY_SIZE_CAP_BYTES` patched to 1 024: `edge.s19` (1 024 bytes) and `big.s19` (1 025 bytes) → both parsed (holds on base; RED side of LLR-172.6c for the 1 025 arm)

> callers (extractor): `S19TuiApp.on_list_view_selected` (direct, :13183)

S19TuiApp.on_list_view_selected
req: LLR-172.6b
in: ListView.Selected event
out: None
func: `#files_list` → `_load_from_item(event.item)`; other lists jump or filter. Caller-only node. 12a changes: none.
module: s19_app/tui/app.py
examples: (code read `:13180`) `enter` on a `#files_list` row → `_load_from_item` with that `ListItem` (holds on base)

> callers (extractor): none listed (Textual message dispatch)

S19TuiApp._load_workarea_file
req: LLR-172.6b, LLR-172.6c
in: str name
out: None
func: (post-10, from the 10 graph; not yet in code; 9b's G1 node). `candidate = self.workarea / WORKAREA_TEMP / name`; `if not candidate.exists(): return` (silent, 9b B88); `kind = "attach"` for a MAC or A2L suffix, else `"image"`; `go` = log `Loading from workarea selection: %s`, then `load_a2l_from_path(candidate)` for an A2L suffix, else `load_selected_file(candidate)`; `self._confirm_then_load(kind, name, go)`. 12a changes: at pick time, before the question, `os.lstat(candidate)`: not `S_ISREG` or a reparse point → `not a regular file` / `pick another file`, nothing loads; `st_size > workspace.DEFAULT_COPY_SIZE_CAP_BYTES` (read at call time) → `too large to open` + the name / `load a smaller file`, nothing loads (LLR-172.6b, .6c; interface S-i).
module: s19_app/tui/app.py
examples: (proto-9b-app B87, post-9b) twin fixtures, a `#files_list` pick and `LoadChoice("workarea", "x.s19")` → equal session digests, `0` `copy_into_workarea` calls
examples: (proto-10-app C38, post-10) D set; `x.mac`, `c.a2l` → `0` questions; `x.s19`, `x.hex` → `1` question each, on both surfaces
examples: (proto-9b-app B88, post-9b) the file deleted after the dialog opened → `0` loads, `0` status lines

> callers (extractor): not run (no code); post-9b callers `_load_from_item` and `_handle_load_dialog` (`workarea` kind)

S19TuiApp._load_dialog_rows
req: LLR-172.4f
in:
out: list[LoadRow] rows
func: (post-9b, from the 9b graph; not yet in code) the Load dialog's `rows` callable. Its work-area section is `[p for p in list_workarea_files(self.workarea) if recent_kind(p) is not None]`: the loadable-suffix predicate LLR-172.4f shares with `refresh_files`. 12a changes: none (it is the predicate's other reader).
module: s19_app/tui/app.py
examples: (proto-9b-app B37, post-9b) `W/temp` holds `a.s19`, `b.hex`, `c.a2l`, `d.a2l.json`, `e.txt`, `.staging/` → 3 file rows; no suffix filter → 5 rows (its negative control)
examples: (proto-9b-app B40, post-9b) `W/temp` holding only `d.a2l.json` → the token line `no work-area files — l loads a file`

> callers (extractor): not run (no code)

S19TuiApp._load_dialog_verdict
req: LLR-172.5i
in: LoadChoice choice
out: Optional[tuple[str, str]] verdict
func: (post-9b, from the 9b graph; not yet in code) `project` / `workarea` → `None` with no filesystem call; `path` / `recent` → `_typed_load_route(Path(choice.value))`, `refuse` → `_TYPED_REFUSAL_TOKENS[reason]`. No `try` (9b R-5): a `ValueError` from the classifier leaves the dialog's key handler and the app stops (`exit_on_error`). 12a changes: none here; the NUL arm is fixed in the classifier, so the verdict paints `not found` / `check the path` (LLR-172.5i's dialog arms).
module: s19_app/tui/app.py
examples: (proto-9b-app B48, post-9b) `LC("path", "<tmp>/missing.s19")` → `("not found", "check the path")`, the dialog stays open
examples: (proto-9b-app B55, post-9b) `LC("workarea", "x.s19")` → `None` with `0` `os.lstat` calls (so the pick-time re-check of LLR-172.6b cannot live here without breaking B55)

> callers (extractor): not run (no code)

recent_kind
req: LLR-172.4f
in: Path path
out: Optional[str] kind
func: `PureWindowsPath(str(path)).suffix.casefold()` mapped through `S19_EXTENSIONS` / `HEX_EXTENSIONS` / `MAC_EXTENSIONS` / `A2L_EXTENSIONS` (read at call time) → `"s19"`, `"hex"`, `"mac"`, `"a2l"`, else `None`. Pure, never raises. The loaders' own suffix sets. 12a changes: none; `refresh_files` becomes its second reader.
module: s19_app/tui/workspace.py
examples: (P12a-4, executed) the loadable suffixes are `.hex .ihex .mac .s19 .srec` and `.a2l` (holds on base)
examples: (code read) `d.a2l.json` → suffix `.json` → `None`; `F.S19` → `"s19"`; `x` (no suffix) → `None` (holds on base)

> callers (extractor): `S19TuiApp.load_from_path` and `S19TuiApp.load_a2l_from_path` (through an unmarked helper, `workspace.py:2239`, `:2456`: the recent-source record); post-9b `_load_dialog_rows`, `_load_dialog_preview`

list_workarea_files
req: LLR-172.4f
in: Path workarea
out: list[Path] files
func: one `os.scandir` of `W/temp`: the regular, non-link direct children, sorted; `[]` when missing or unreadable (LLR-172.4, LLR-172.4d skips a trailing dot or space on every platform). 12a changes: none.
module: s19_app/tui/workspace.py
examples: (probe p9b F8, holds) `['w.a2l', 'w.a2l.json', 'w.s19', 'x.s19']` (holds on base)
examples: (probe p12a U2.1) `.a2l.json` and `.txt` files are returned (holds on base; the filter belongs to the readers)

> callers (extractor): `S19TuiApp.refresh_files` (direct, :7319)

painted_names
req: LLR-176.1r
in: Sequence[str] names; int limit = PAINTED_NAME_LIMIT; int clip = 120
out: str painted
func: the batch's one category scrub: Cc, Cf, Zl, Zp removed, an unpaired surrogate as U+FFFD, each name clipped to `clip` characters ending in `…`, at most `limit` names joined. 12a changes: none; the progress line's names go through it (LLR-176.1r).
module: s19_app/tui/services/project_gather_service.py
examples: (proto-9b-app B33, holds) `x` + U+202E + `R` → `xR`; a 130-character name → 120 characters ending in `…` (holds on base)

> callers (extractor): `S19TuiApp.refresh_files` (direct, :7321); `S19TuiApp._load_path_from_user_input` (direct, :12944); `S19TuiApp._handle_load_project` (direct, :11686, :11718, :11735, :11775, :11776, :11805, :11810); `S19TuiApp._handle_save_dialog` (direct 5, through unmarked helpers 15)