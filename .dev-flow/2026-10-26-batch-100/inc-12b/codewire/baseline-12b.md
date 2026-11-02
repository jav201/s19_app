# Code-Wire baseline — batch-100 Inc 12b slice ("project load, Save project and the A2L parse on workers") on main 8947666, designed post-9b / post-10 / post-11 / post-12a

Scope: the functions on the Inc 12b paths (HLR-177 … HLR-177c, LLR-177.1 … LLR-177.5a, LLR-176.3, LLR-176.4 … LLR-176.4b; E1-scope §3, groups G-A … G-D): the project load and every helper its worker would reach (G-A); the Save project router, its commit half and the helpers the Save worker would reach, with the change-service methods the commit calls (G-B); the A2L attach, the work-area pick, the existing file-load worker, the 17 request entry points that get the busy refusal and the key guard (G-C); the parser entry point and its read loop in `a2l.py` (G-D); and the Inc 12a seam and Inc 10 modal that 12b consumes unchanged. Base: main `<HOME>\Github\s19_app` at `8947666` (Inc 9a merged), sha256 prefixes `app.py` bbf04117fbf0 (the bytes the 9b, 10, 11 and 12a baselines read), `a2l.py` 6d12c964344b. Line numbers are base lines. The checkout was only read.

Example lines come from the probe `p12b` (`probe-p12b.py`, output `probe-p12b.out.txt`), from the E1 probes P12b-1 … P12b-7 (`../work/`), from an existing test, from a code read, or from a line of the fixed 9b / 10 / 11 / 12a graphs; each names its source. Every example states behaviour that holds on the base unless it says post-9b / post-10 / post-11 / post-12a. `func:` says "12b changes: …" where an Inc 12b requirement changes the function; a node with no "12b changes" is context the change relies on. A node that an earlier increment creates is marked "(post-<inc>, from the <inc> graph; not yet in code)"; the extractor does not see it.

## Nodes

S19TuiApp._handle_load_project
req: HLR-177, LLR-177.1, LLR-177.1d, LLR-177.1e, LLR-177.1f, LLR-177.1g, LLR-177.2, LLR-176.3
in: Optional[str] name
out: None
func: the whole project load, synchronous on the main thread (`:11675`–`:11961`). Base order: `None` → log, return; the folder check `_project_folder_refusal` (link / unreadable / outside lines); `exists()`; the listing match against `list_projects()` (`OSError` → `could not be read`; unlisted → `is not a project`); `validate_project_files` (cardinality error line); the A2L admission (lstat, regular, not a reparse point, under `DEFAULT_COPY_SIZE_CAP_BYTES`); the "no data or A2L" / "no project.json" refusal; then `_reset_project_session()` (`:11821`); `build_variant_set`, `read_project_manifest`, `_declared_regions` (a session write), `check_project_files` (the digest check), the recorded variant; the A2L parse `_load_a2l_data_with_cache` (raise → a `not readable` problem); `choose_install_set` and the all-`None` refusal; the A2L-only in-place attach (`current_a2l_path`, `current_a2l_data`, `update_a2l_view`); `_reopen_active_document`; `current_project`, `current_project_dir`, `_variant_set`; the image loop `_install_project_image` with the next-valid fallback; `active_id`; the MAC install `load_selected_file(install.mac, a2l_files)` (`:11920`), which merges the MAC into the image just installed; `compose_load_announcement`, `_last_load_announcement`, summary line, `set_file_status`, the interim discard line, log, labels, flow session folder. Post-9b: the listing uses `_list_project_files` (link-safe) and `_a2l_admission`, a `project.json` lstat gate, and a catch around the listing (9b graph). Post-10: the reset moves after every read and refusal (S10-01/S10-05: `build_variant_set`, the manifest read, `check_project_files`, the A2L read and the all-`None` refusal run before the reset; only `_declared_regions` stays after), `_reset_project_session()` returns `None`, the interim discard line is deleted, `No supported files in project:` paints through `painted_names` (10 graph C48–C58). Post-12a: `gen = _busy_begin_action("project_load", name)` after the cheap refusals; `try / finally: _busy_fail`; `step_busy` 2 before the A2L read, 3 before the image loop, 4 before the MAC install; the all-`None` refusal and the success end through `end_busy` (success passes `final_line` = the project and file line) (12a graph A12-42 … A12-45). 12b changes: the cheap refusals stay in the request frame; the reads (variant set, manifest, digest check, A2L parse, image parses with the fallback, MAC parse merged with its own image, document read) move to a worker over an immutable request; the reset, the installs and the announcement move to a main-thread install handler; no install inline (E1 A1–A4).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.current_project] (replace)
examples: (E1 P12b-5) case_06 `firmware.s19` + `.mac` + `.a2l` as `P` → wall 5.81 s, 0 ticks of a 0.1 s timer during the call, ran on the main thread (holds on base; RED side of HLR-177 / LLR-177.1c)
examples: (probe p12b U1, LLR-177.1f planned arm, executed) case_01 `firmware.s19` + `.mac` + `.a2l` as `P2`, cold → session digest `('P2\firmware.s19', 'f254f33fe5405d40', 'P2', 'P2\firmware.a2l', 'P2\firmware.mac', 0)`; the same `P2` loaded over an open image `p1img.s19` → the identical digest, `_session_snapshot()` differing only in `_image_generation` and `log_lines` (holds on base: the reset runs before the parses)
examples: (probe p12b U1) case_06 as `P6`, cold → digest `('P6\firmware.s19', 'f917cd2dca22da9a', 'P6', 'P6\firmware.a2l', 'P6\firmware.mac', 0)`, wall 7.34 s on the loaded host (holds on base; the LLR-177.1f base digest for case_06)
examples: (probe p12b U4) one base project load assigns 49 app attributes, among them `current_file`, `current_project`, `current_project_dir`, `current_a2l_path`, `current_a2l_data`, `_variant_set`, `_change_service`, `_declared_regions`, `_pending_variant_id`, `_last_load_announcement`, `_a2l_cache_key`, `_a2l_cache_data` (holds on base; the set a 12b worker must not write, LLR-177.1d)
examples: (12a graph A12-44, post-12a) `Q` holding only `project.json` → `Project NOT loaded: 'Q' has no data or A2L file — load a file and Save project.`, 0 begins (a cheap refusal; stays in the request frame after 12b, LLR-177.1's "4 of 4")

> callers (extractor): `S19TuiApp._route_load_project` (direct, app.py:7478)

S19TuiApp._route_load_project
req: LLR-177.1h, LLR-178.3
in: Optional[str] name
out: None
func: post-10 (from the 10 graph; base `:7449` has the same core): `go` = `before = self._last_load_announcement`; `_handle_load_project(name)`; push `LoadResultScreen(announcement)` with `_handle_load_result` only when `_last_load_announcement` now holds a new object (identity); then `_confirm_then_load("project", name, go)`. Post-10 the parameter is `name: str` (A10-01 removed the `None` arm); `in:` gives the base signature. 12b changes: no identity check after the call (the install has not run when a worker load returns); the request carries `routed=True` and the install handler opens the panel (LLR-177.1h).
module: s19_app/tui/app.py
examples: (9b probe p9b U8, holds on base) name `[b]P` → one `LoadResultScreen` pushed after the synchronous load
examples: (E1 LLR-177.1h negative control, code read `:7478`–`:7482`) a worker load returns before the announcement is composed → the identity test sees the previous object → 0 panels (RED for the base shape once the load is a worker)

> callers (extractor): unmarked site `_load_path_from_user_input` app.py:12936; `LoadProjectScreen`'s dismiss callback (a value, not seen)

S19TuiApp._reset_project_session
req: LLR-177.1g, LLR-165.1
in:
out: int discarded_unsaved
func: the one project reset seam (`:11385`): rebinds the change service, clears the image, MAC, A2L, variant set, caches and panels (S1–S13). Base signature `-> int` (the outgoing entry count, `out:` above); post-10 `-> None` (10 graph C51). One call site, inside `_handle_load_project`. 12b changes: its caller moves to the project-load install handler, after the worker step succeeded and before the first install (LLR-177.1g; LLR-165.1's caller clause, E1 §C.1).
module: s19_app/tui/app.py
examples: (test `test_b100_session_reset.py::test_tc_b100_08_call_site_census`, :271) exactly 1 `_reset_project_session` call site in `s19_app/` (holds on base; re-pinned to the install handler at 12b)
examples: (10 graph C58, post-10) an A2L-only project whose A2L does not read → refusal, 0 resets, the session unchanged (holds post-10; LLR-177.1g's failure arm keeps it)

> callers (extractor): `S19TuiApp._handle_load_project` (direct, app.py:11821)

S19TuiApp._install_project_image
req: LLR-177.1, LLR-177.1d, LLR-177.1e
in: VariantDescriptor variant; Sequence[Path] a2l_files
out: Optional[str] reason
func: (`:12044`) sets `self._pending_variant_id` (a session write), parses with `_parse_loaded_file(variant.path, a2l_files)` (any exception → "not an S19 or HEX file"), rejects `None` / empty `mem_map`, else installs through `_apply_loaded_file`. One caller. 12b changes: the parse half moves to the project worker (pure, explicit inputs); the `_pending_variant_id` write and the apply half move to the install handler (E1 A6, may dissolve).
module: s19_app/tui/app.py
examples: (code read `:12076`, `:12091`) `_pending_variant_id` is written before the parse and cleared on a rejected image (holds on base; a worker running this body writes the session off the main thread → RED for LLR-177.1d)
examples: (test `test_tui_variants.py::test_no_new_parse_loaded_file_call_sites`, :196) the `_parse_loaded_file` call sites are exactly `_install_project_image`, `_start_load_worker`, `load_selected_file` (holds on base; a new pure parse caller breaks this pin)

> callers (extractor): `S19TuiApp._handle_load_project` (direct, app.py:11903)

S19TuiApp._reopen_active_document
req: LLR-177.1, LLR-177.1d, LLR-177.1e
in: Path project_dir; Optional[ProjectManifest] manifest; Optional[dict] a2l_context
out: Optional[ProjectFileProblem] problem
func: (`:11963`) no manifest / damaged / no `active_document` → `None`; one `recorded_document_state(project_dir, text, a2l_context)` read; `ok` → `document.source_path = …`, `self._change_service.document = document` (a session write), `panel.mark_loaded()`, `_patch_editor_load_tail(panel)`; other outcomes → one `not readable` problem. 12b changes: the read (`recorded_document_state`) moves to the worker; the service and panel install to the install handler (E1 A7).
module: s19_app/tui/app.py
examples: (code read `:12033`) the reopened document is assigned to the live service (holds on base; on a worker it would be an off-main session write, LLR-177.1d)

> callers (extractor): `S19TuiApp._handle_load_project` (direct, app.py:11886)

recorded_document_state
req: LLR-177.1
in: Path project_dir; str text; Optional[dict] a2l_context = None
out: RecordedDocumentState state
func: module-level in `app.py` (`:1873`): one read of the recorded change document, outcome `ok` / `missing` / `link` / `too_large` / `unreadable` / `io_error` with the parsed document. Touches no app state, so it can run on a worker unchanged.
module: s19_app/tui/app.py
examples: (code read) it takes only paths and the A2L payload, and reads no `self.` attribute (holds on base; worker-safe as is)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, app.py:9750); `S19TuiApp._reopen_active_document` (direct, app.py:12017)

choose_install_set
req: LLR-177.1
in: ProjectVariantSet variant_set; Optional[str] recorded; Sequence[Path] data_files; Sequence[Path] a2l_files; Sequence[str] unreadable = ()
out: InstallSet install
func: module-level (`:1593`): the recorded variant when valid, else the next valid one in `(name.lower(), name)` order; the MAC and A2L to attach. Pure. Unchanged by 12b; the worker's image fallback calls it as the base loop does.
module: s19_app/tui/app.py
examples: (9b graph, holds on base) a recorded variant that is unreadable → the next valid variant (LLR-169.6)

> callers (extractor): `S19TuiApp._handle_load_project` (direct, app.py:11869, app.py:11910)

S19TuiApp._parse_loaded_file
req: LLR-177.1e, LLR-177.1f, LLR-177.1d
in: Path path; Optional[list[Path]] a2l_files = None
out: Optional[LoadedFile] loaded
func: (`:15099`) suffix dispatch: S19 / HEX → `build_loaded_s19` / `build_loaded_hex` with `a2l_path = a2l_files[0] or self.current_a2l_path` and `a2l_data = self._load_a2l_data_with_cache(a2l_path) or self.current_a2l_data`, then `_merge_primary_with_existing_mac` (reads `self.current_file`); MAC → `_load_mac_file`, then `_merge_mac_with_existing_primary` (reads `self.current_file`); else `None`. Its log lines read `self.current_project`. Called by the file-load worker today, so it already runs off the main thread there. 12b changes: a pure sibling with explicit A2L data and the primary to merge with, and no `self.current_*` read (E1 A8, guess), for the project worker; the cache write leaves it (A9).
module: s19_app/tui/app.py
examples: (probe p12b U2, LLR-177.1e / .1f hazard, executed) no image open: `_parse_loaded_file(P2/firmware.mac)` → `file_type mac`, path `firmware.mac`; with `p1img.s19` open: the same call → `file_type s19`, path `p1img.s19`, MAC `firmware.mac` (the MAC merged into the previous image) (holds on base; the RED side of LLR-177.1f for a worker that runs before the reset)
examples: (probe p12b U2) with `p1img.s19` open (no MAC), `_parse_loaded_file(P2/firmware.s19)` → no MAC carried (holds on base)

> callers (extractor): `S19TuiApp._install_project_image` (direct, app.py:12078); `S19TuiApp._start_load_worker` (direct, app.py:15743); `S19TuiApp.load_selected_file` (direct, app.py:15080)

S19TuiApp._merge_mac_with_existing_primary
req: LLR-177.1e, LLR-177.1f
in: LoadedFile mac_loaded
out: LoadedFile merged
func: (`:14425`) `existing = self.current_file`; no S19/HEX primary → the MAC as is; else a `LoadedFile` with the primary's image and the MAC's records. Its twin `_merge_primary_with_existing_mac` (`:14371`) carries an existing MAC onto a new primary. Both read the live session.
module: s19_app/tui/app.py
examples: (probe p12b U2) see `_parse_loaded_file`: the merge target is whatever `current_file` holds at call time (holds on base)

> callers (extractor): `S19TuiApp._parse_loaded_file` (direct, app.py:15197)

S19TuiApp._load_mac_file
req: LLR-177.1e
in: Path path; Optional[list[Path]] a2l_files = None
out: LoadedFile loaded
func: (`:14140`) `parse_mac_file(path)`, a one-byte placeholder `mem_map` per address, `a2l_path = a2l_files[0] or self.current_a2l_path`, `a2l_data = _load_a2l_data_with_cache(a2l_path) or self.current_a2l_data`. Reads the session when `a2l_files` is empty.
module: s19_app/tui/app.py
examples: (code read `:14210`, `:14217`) the A2L fallback reads `current_a2l_path` / `current_a2l_data` (holds on base; on a worker the census of LLR-177.1e names it unless the request passes the A2L)

> callers (extractor): `S19TuiApp._parse_loaded_file` (direct, app.py:15187)

S19TuiApp._load_a2l_data_with_cache
req: LLR-177.1d, LLR-177.5
in: Optional[Path] path
out: Optional[dict[str, Any]] a2l_data
func: (`:15816`) key = (resolved path, mtime, size); a hit returns `self._a2l_cache_data`; a miss calls `parse_a2l_file(path)` and assigns `_a2l_cache_key` / `_a2l_cache_data`. Reached from the file-load worker today (`_parse_loaded_file`), so the base already writes the cache off the main thread. 12b changes: a pure parse (with the byte callback) on the worker, the cache write on the main thread, for every caller (E1 A9).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._a2l_cache_key] (replace), [Data: S19TuiApp._a2l_cache_data] (replace)
examples: (test `test_tui_app.py::test_a2l_cache_reuses_parse_for_unchanged_file`, :398) two calls on an unchanged file → `parse_a2l_file` called 1 time, equal results (holds on base; the fake takes `(path)` only)
examples: (E1 LLR-177.1d negative control, code read `:15851`–`:15852`) the file-load worker reaches the cache write (holds on base; RED for LLR-177.1d)

> callers (extractor): `S19TuiApp._handle_load_project` (direct, app.py:11858); `S19TuiApp._load_mac_file` (direct, app.py:14217); `S19TuiApp._parse_loaded_file` (direct, app.py:15151, app.py:15170); `S19TuiApp.load_a2l_from_path` (direct, app.py:13145)

S19TuiApp.load_selected_file
req: LLR-177.1k, LLR-177.1
in: Path path; Optional[list[Path]] a2l_files = None
out: None
func: (`:15047`) synchronous parse (`_parse_loaded_file`) and install (`_apply_loaded_file` → `_apply_prepared_load`); a parse error → `Load failed: …`; `None` → `Unsupported file type: …`. Callers today: the project MAC install (`:11920`) and the work-area pick (`_load_from_item`, post-9b `_load_workarea_file`). 88 direct test calls (E1). 12b changes: no product caller remains on the 12b paths (the pick moves to the file-load worker, LLR-177.1k; the project MAC parse moves to the project worker); the function stays for its direct test calls.
module: s19_app/tui/app.py
examples: (12a P12a-3, executed) a generated S19 with 8 MiB of data parses in 2.38 s on the main thread (holds on base; RED side of LLR-177.1k)

> callers (extractor): `S19TuiApp._handle_load_project` (direct, app.py:11920); `S19TuiApp._load_from_item` (direct, app.py:13335)

S19TuiApp._session_snapshot
req: LLR-177.1f, LLR-165.2
in:
out: dict snapshot
func: (`:11539`) the normalised projection of every attribute `S19TuiApp`'s source assigns (the LLR-165.2 census domain), minus `SNAPSHOT_EXCLUSIONS` (`:2019`–`:2060`, which already list `_a2l_cache_key`, `_a2l_cache_data`, `_last_manifest_verify_result`). Read-only. Unchanged by 12b; every new attribute 12b adds needs a classification (TC-B100-09).
module: s19_app/tui/app.py
examples: (probe p12b U1) cold `P2` vs `P2` over `p1img.s19` → differing names `['_image_generation', 'log_lines']` (holds on base)
examples: (test `test_b100_session_reset.py::test_tc_b100_09_domain_matches_the_live_source_census`) every `self.<name> =` in `S19TuiApp` is in the domain or the exclusions (holds on base; RED for each unclassified 12b attribute)

> callers (extractor): none listed (framework, key or message dispatch)

S19TuiApp.action_save_project
req: LLR-177.3d
in:
out: None
func: post-11 (from the 11 graph): nothing loaded → `Nothing to save: load a data file or A2L first.`, no push; else clears `_save_session` / `_save_confirmed` / `_save_painted_preview` and pushes `SaveProjectScreen(preview=…, confirm=…, initial_name=…, …)` with `_handle_save_dialog` as the callback. Base (`:7355`) pushes the old dialog unconditionally. Neither has a state check. 12b changes: the busy check first (LLR-177.3d).
module: s19_app/tui/app.py
examples: (E1 LLR-177.3d negative control, code read `:7355`) no state check exists (holds on base)

> callers (extractor): none listed (framework, key or message dispatch)

S19TuiApp._handle_save_dialog
req: LLR-177.1a, LLR-177.3d
in: Optional[SaveProjectPayload] payload
out: None
func: post-11 (from the 11 graph): the one-argument router: clear the per-open state; `None` → log; G1–G3 payload checks; `prepared` = the confirmed `_PreparedSave` when `payload.plan is prepared.plan` and the names match, else `_prepare_project_save(payload.project_name, session)`; `prepared.refusal` → status (+ toast on the direct path), return; else `_commit_project_save(prepared, payload)`. Base (`:9447`) is the whole save in one body. 56 direct call lines + 1 by reference (11 graph). 12b changes: none to the router's refusals (they stay synchronous); the commit it calls becomes a request build + worker start (E1 B1).
module: s19_app/tui/app.py
examples: (E1 P12b-6) right after P12b-5, `_handle_save_dialog('Q')` → wall 0.12 s, 0 ticks during the call, ran on the main thread; `Q` = `firmware.a2l, firmware.mac, firmware.s19, project.json` (holds on base)
examples: (11 graph B11-12, post-11) the 56 direct call lines and the call by reference run the router unchanged (holds post-11)

> callers (extractor): none listed (framework, key or message dispatch)

S19TuiApp._commit_project_save
req: LLR-177.1a, LLR-177.1d, LLR-177.1e, LLR-177.1j, LLR-177.2a, LLR-177.5a, LLR-164.4
in: _PreparedSave prepared; SaveProjectPayload payload
out: None
func: (post-11, from the 11 graph; post-12a, from the 12a graph; not yet in code) the base commit half `:9856`–`:10605`. Phases: (C1) `mkdir(exist_ok=False)` → `created_project_dir`; (C2) the `save_state` snapshot of `_variant_set`, `current_file.variant_id`, `_report_filter_path`, `current_project`, `current_project_dir` (`:9871`–`:9877`) and the rollback lists; `document = self._change_service.document`; (C3) one `try`: `validate_project_files`, `_copy_project_subfolders` (sub-folders), the rows loop (`_write_editor_document` for a pasted document; for the image row `self._change_service.record_save_entries()` then `self._change_service.emit_and_verify(image_step.derived, self.current_file.ranges, …, source_kind=self.current_file.file_type, s0_header=self.current_file.source_s0_header, source_image_path=self.current_file.path, …)` (`:10006`–`:10019`); else `place_into_workarea`; each checked by `_plan_row_mismatch`), top-level copies, **session writes inside the try**: `_report_filter_path = None` (`:10102`), `_variant_set = build_variant_set(…)` / `None` and `current_file.variant_id` (`:10109`–`:10124`); `gather_project_artifacts(…, active_template=self._last_template_path, …)`; the SEC7-3 keep; `_write_and_verify_manifest(…, declared_regions=self._declared_regions, …)`; (C4) `except WorkareaPlacementError` / `WorkareaContainmentError` / `OSError` → line (+ toast) + `_abort_save` + return; `except Exception` → log, `_abort_save`, `raise` (SEC-7, `:10412`–`:10425`); (C5) committed tail: `adopt_rederived` + `_surface_verify_result` when emitting, `mark_saved`, `Saved project to …`, kept note, links, `source_gone`, unrecorded lines, the document rebinding, `panel.mark_saved()` (`:10572`), document lines, MISMATCH re-paint from `self._last_manifest_verify_result` (`:10592`), `current_project`, `current_project_dir`, labels, `refresh_files`, flow session folder. Post-12a: begin `save_project` at entry, steps 2 / 3 / 4 at the phase boundaries, an end on each of the 10 abort exits and the tail, `finally: _busy_fail`; the SEC-7 re-raise kept. 12b changes: split into a main-thread request build, a Save worker (C1–C4, file writes only, per-file step reports), and a main-thread commit / failure handler (C5, the session writes, `adopt_rederived`); a non-`OSError` is rolled back and reported, not raised (ruling Q4) (E1 B1–B3).
module: s19_app/tui/app.py
modify: [I/O: work area]
examples: (probe p12b U4) a base copy-only Save assigns `_last_manifest_verify_result`, `_report_filter_path`, `_variant_set`, `current_project`, `current_project_dir` (holds on base; the session writes the commit handler must take over)
examples: (12a graph A12-48, holds on base for the line) `place_into_workarea` raising `OSError(28)` after the `mkdir` → `Project NOT saved: could not save — [Errno 28] synthetic no space. check the folder.`, the folder removed, 0 raises
examples: (test `test_b100_save_image.py::test_tc_b100_17_non_os_error_after_the_emit_rolls_back_then_surfaces`, :818) a non-`OSError` after the emit → rolled back, then raised out of `_handle_save_dialog` (holds on base; ruling Q4 re-pins it to a status line)
examples: (test `test_b100_save_guards.py::test_tc_b100_07_ast_census_every_post_creation_return_removes`, :801) every `return` after the first `mkdir` follows an `_abort_save` call; exactly 1 `except OSError` after the `mkdir` (holds on base; post-11 re-pinned to `_commit_project_save`)

> callers (extractor): not run (no code)

S19TuiApp._prepare_project_save
req: LLR-177.1a, LLR-177.1i
in: str name; Optional[_SaveSession] session = None
out: _PreparedSave prepared
func: (post-11, from the 11 graph; not yet in code) G4–G18 of the base `_handle_save_dialog`: name rules, clash loop, the session (computed after the name rules on the direct path), target checks, carry, plan, free space; writes no file and no `self.` attribute except the declared lazy-inventory fill. Every refusal is decided here, on the main thread. Unchanged by 12b: its refusals stay before any worker (LLR-177.1a's "10 of 10").
module: s19_app/tui/app.py
examples: (11 graph B11-19 … B11-34, post-11) each of the name, plan, free-space and source refusals returns a `_PreparedSave` with `refusal` set and writes 0 folders

> callers (extractor): not run (no code)

S19TuiApp._save_session_inputs
req: LLR-177.1i
in:
out: _SaveSession session
func: (post-11, from the 11 graph; not yet in code) once per dialog open, after the first frame: `image_step = _decide_project_image()` (the re-derive and render), the digests of the image / MAC / A2L, `emitted_record`, the payload sha256. On the direct path it runs inside `_prepare_project_save`, after the name rules. So since Inc 11 the re-derive runs on the main thread before the commit begins. Unchanged by 12b (ruling Q1).
module: s19_app/tui/app.py
examples: (11 graph B11-06, post-11) `action_save_project` calls no `_decide_project_image`; the first `preview` call (after the first refresh) builds the session

> callers (extractor): not run (no code)

S19TuiApp._decide_project_image
req: LLR-177.1i
in:
out: _ProjectImageStep step
func: (`:10607`) reads `self.current_file` and `self._change_service`; no patch → `emit=False`; else `service.rederive_for_save(…)` then `render_patched_image(…)` → `emit=True` with `derived`, `summary` and the payload. Main thread. Unchanged by 12b (ruling Q1: re-derive before the worker).
module: s19_app/tui/app.py
examples: (tests `test_b100_save_image.py` :286, :402, :1496) `step = app._decide_project_image()` inside `run_test` returns the step the save uses (holds on base)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, app.py:9706)

S19TuiApp._abort_save
req: LLR-177.1d, LLR-177.2a, LLR-164.4
in: Path project_dir; bool created_project_dir; Sequence[Path] placed_files; Sequence[Path] created_dirs; Tuple save_state; Sequence[Tuple[Path, bytes]] manifest_restores = (); Sequence[Tuple[Path, bytes]] kept_copies = ()
out: None
func: (`:9162`) restores the session from `save_state` (`_variant_set`, `_report_filter_path`, `current_file.variant_id`, `current_project`, `current_project_dir`), then the manifest restores (`_restore_manifest`), then unlinks exactly the placed files (link-safe, identity-checked) and removes the created folders deepest first; never raises. 11 callers inside the commit. 12b changes: the session-restore half goes (the worker never writes the session); the file rollback stays and runs on the worker (E1 B5).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._variant_set] (replace), [Data: S19TuiApp.current_project] (replace)
examples: (test `test_b100_save_guards.py::test_tc_b100_07_ast_census_every_post_creation_return_removes`, :888–:891) the AST pins `_abort_save` holding an `Attribute` `_variant_set` ("must restore the pre-save app state") (holds on base; RED once the restore half is removed)
examples: (12a graph A12-48) the `OSError(28)` arm leaves `W/S2` absent (holds on base)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, app.py:10030, app.py:10056, app.py:10090, app.py:10272, app.py:10340, app.py:10364, app.py:10377, app.py:10402 … (11))

S19TuiApp._write_and_verify_manifest
req: LLR-177.1d, LLR-177.1e
in: Path project_dir; Sequence[str] batch = (); Optional[Mapping[str, Sequence[str]]] assignments = None; Sequence[DeclaredRegion] declared_regions = (); Optional[Mapping[str, Sequence[str]]] gathered = None; Optional[Mapping[str, DerivedFrom]] derived_from = None; Optional[str] active_document = None; Optional[Callable[[Path], None]] on_written = None
out: bool ok
func: (`:11147`) reads `self._variant_set` (`None` → `True`, nothing written) and `self.base_dir`; assigns `self._last_manifest_verify_result = None`, writes with `write_project_manifest`; refused → `Manifest write failed` + toast, `False`; `on_written(written)`; `verify_written_manifest`; assigns `self._last_manifest_verify_result = result`; `_surface_manifest_verify_result(result)` (status + toast); `True`. Callers: the Save commit and `_rewrite_project_manifest`. 12b changes: returns its verify result instead of assigning the attribute, takes the variant set as an argument, and leaves the painting to a main-thread caller (E1 B4).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._last_manifest_verify_result] (replace)
examples: (test `test_b100_project_check.py::test_tc_b100_23_digest_changed_between_write_and_verify`, :264–:267) `app._write_and_verify_manifest(project_dir)` then `app._last_manifest_verify_result` read (holds on base; RED once the attribute is no longer assigned)
examples: (test `test_b100_project_check.py` :1421) `ok = app._write_and_verify_manifest(project)` → `False` on a refused write (holds on base; the bool return is pinned)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, app.py:10323); `S19TuiApp._rewrite_project_manifest` (direct, app.py:12495)

S19TuiApp._rewrite_project_manifest
req: LLR-177.1d
in: Path project_dir; Path placed; Optional[DerivedFrom] derived = None
out: bool ok
func: (`:12425`) the main-thread rewrite after a save-back, a variant append, a MAC / A2L sync: calls `_write_and_verify_manifest` and reads `self._last_manifest_verify_result` (`:12497`). Main thread, not on a 12b worker. 12b changes: assigns `_last_manifest_verify_result` from the returned result (E1 B4).
module: s19_app/tui/app.py
examples: (code read `:12497`) the caller reads the attribute the writer set (holds on base)

> callers (extractor): `S19TuiApp.load_a2l_from_path` (through an unmarked helper, app.py:12754); `S19TuiApp.on_patch_editor_panel_save_back_decision` (direct, app.py:4197); unmarked sites app.py:12680, app.py:12724 (the variant-append and MAC syncs)

S19TuiApp._copy_project_subfolders
req: LLR-177.5a, LLR-177.1a
in: Path source_dir; Path project_dir; Sequence[InventoryFile] copies; list[Path] placed_files; list[Path] created_dirs; Optional[Mapping[str, SavePlanRow]] carried = None
out: Optional[str] failure
func: (`:12208`) one `place_into_workarea` per plan copy entry, each destination guarded (`_guarded_destination`, `_path_traverses_reparse_point` with `self.workarea`), each landing recorded in `placed_files` / `created_dirs`; returns the first failure line or `None`. Called twice by a save-as (sub-folders, then top-level). It is the per-file loop of a 2 000-file save-as. 12b changes: runs on the Save worker and reports each file placed (LLR-177.5a).
module: s19_app/tui/app.py
modify: [I/O: work area]
examples: (8b measurement cited by E1) a 2 000-file save-as takes 14.0 s, all inside these two calls (holds on base)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, app.py:10079, app.py:9943)

S19TuiApp._write_editor_document
req: LLR-177.1e
in: SavePlanRow row; Path project_dir
out: tuple(Optional[PlacementResult] placed, Optional[Path] staged, Optional[str] failure)
func: (`:11057`) writes a pasted change document as a new file under the project home; reads `self._change_service.document` (`:11103`) and `self.workarea`. 12b changes: on the worker it must take the document's serialised bytes from the request (LLR-177.1e census).
module: s19_app/tui/app.py
examples: (code read `:11103`) `document = self._change_service.document` (holds on base; RED for LLR-177.1e's census on a worker)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, app.py:9981)

ChangeService.record_save_entries
req: LLR-177.1d
in:
out: tuple[tuple[int, ...], tuple[int, ...]] split
func: (`change_service.py:2181`) computes the applied / not-applied entry split and stores it in `self.last_save_applied`, `self.last_save_not_applied` (service state). Called by the Save commit just before the emit. 12b changes: called on the main thread before the worker starts (E1 B1).
module: s19_app/tui/services/change_service.py
examples: (code read `:2203`–`:2205`) assigns two service attributes (holds on base; a state change, so off-main it is RED for LLR-177.1d)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, app.py:10006); unmarked site `ChangeService.save_patched` change_service.py:2583

ChangeService.emit_and_verify
req: LLR-177.1a, LLR-177.1e
in: Dict[int, int] image; Sequence[Tuple[int, int]] ranges; Path dest_dir; str filename; str source_kind; int bytes_per_line = 32; Optional[bytes] s0_header = None; Optional[Path] source_image_path = None; Optional[ChangeSummary] summary = None; Optional[Path] workarea_root = None; Optional[Callable[[PlacementResult], None]] on_placed = None
out: ChangeActionResult result
func: (`change_service.py:2377`) `save_patched_image` places the image, `on_placed` fires, `verify_written_image` re-reads it; reads `self.last_summary` when `summary` is `None` and `self.last_save_applied` / `not_applied` for the message; writes `stamped.verify_result` on the summary object it was given. Assigns no service attribute. 12b changes: runs on the Save worker; its `self.*` reads and the summary write cross the thread (LLR-177.1e census; see baseline-notes Surprise 6).
module: s19_app/tui/services/change_service.py
modify: [I/O: work area]
examples: (code read `:2445`, `:2471`–`:2473`) `stamped = summary if summary is not None else self.last_summary`; `stamped.verify_result = verify` (holds on base)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, app.py:10007); unmarked site `ChangeService.save_patched` change_service.py:2626

ChangeService.adopt_rederived
req: LLR-177.1j
in: Dict[int, int] mem_map; Dict[int, int] derived; Optional[ChangeSummary] summary = None
out: None
func: (`change_service.py:2315`) the session view takes the re-derived image in place, so it equals what was saved (LLR-167.2). Called in the committed tail only when emitting, after `project.json` is on disk (review F4). 12b changes: called by the main-thread commit handler after the worker reports a committed save (LLR-177.1j).
module: s19_app/tui/services/change_service.py
examples: (test `test_b100_save_image.py::test_tc_b100_17_failed_manifest_write_adopts_nothing`, :836) `_write_and_verify_manifest` patched to `False` → 0 adopts, the session map keeps the source bytes (holds on base)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, app.py:10436); unmarked site `ChangeService.save_patched` change_service.py:2591

S19TuiApp.load_a2l_from_path
req: HLR-177, LLR-177.1b, LLR-177.1d, LLR-177.2b, LLR-177.5, LLR-176.3
in: Path path
out: None
func: (`:13087`) `resolve_input_path`; not found / unsupported suffix / project already has an A2L (`validate_project_files` of the open project) refusals; the size warning; `set_progress(10, …)`; `copy_into_workarea` (containment refusal → `Cannot load A2L: …`); recent record (post-9b: not when found through the fallback); `refresh_files`; `set_progress(50, …)`; `current_a2l_path = copied`; `current_a2l_data = _load_a2l_data_with_cache(copied)` (a raise leaves the function); `current_file.a2l_*`; `update_a2l_view()` (the tag-table build); labels, Loaded panel, `set_progress(100, …)`, `A2L loaded: <name>`, focus, `_sync_loaded_a2l_to_project`. Post-12a: begin `a2l_load` after the refusals, steps 2 and 3, ends through `end_busy`, `finally: _busy_fail` (12a graph A12-38 … A12-41). 12b changes: the main checks stay; a request, `begin_busy`, the A2L worker (copy unless in place, parse with the byte callback); the install / failure handler on the main thread paints step 3 before the tag-table build (E1 C1–C3).
module: s19_app/tui/app.py
modify: [I/O: workarea temp]
examples: (E1 P12b-4) the case_06 A2L → wall 8.76 s, 0 ticks during the call, ran on the main thread (holds on base)
examples: (E1 P12b-7) `parse_a2l_file(case_06)` alone takes 5.01 s of those 8.76 s (holds on base; the worker share)
examples: (probe p12b U4) one base A2L attach assigns `current_a2l_path`, `current_a2l_data`, `_a2l_cache_key`, `_a2l_cache_data` and 11 view caches (holds on base)
examples: (9b probe p9b F7, holds on base) `_load_from_item('w.a2l')` → `copy_into_workarea` called once (onto itself), `A2L loaded: w.a2l`

> callers (extractor): `S19TuiApp._load_from_item` (direct, app.py:13333); unmarked site `_load_path_from_user_input` app.py:12939

S19TuiApp._load_workarea_file
req: LLR-177.1b, LLR-177.1k, LLR-177.3a
in: str name
out: None
func: (post-9b G1, post-10, post-12a, from the 9b / 10 / 12a graphs; not yet in code) `candidate = self.workarea / WORKAREA_TEMP / name`; post-12a S-i: `os.lstat` (`FileNotFoundError` → silent return), not a regular file / reparse point → `File NOT loaded: … is not a regular file — pick another file.`, over the size cap → `… is too large to open — load a smaller file.`; post-10: `kind = "attach"` for a MAC or A2L suffix, else `image`; `go` = log, then `load_a2l_from_path(candidate)` for an A2L suffix, else `load_selected_file(candidate)`; `_confirm_then_load(kind, name, go)`. Callers: `_load_from_item` (`#files_list`) and the 9b router (`workarea` choice). 12b changes: the A2L arm starts the A2L worker in place (no copy); the data arm starts `_start_load_worker` in place, not `load_selected_file` (E1 C4, LLR-177.1k).
module: s19_app/tui/app.py
examples: (10 graph C38, post-10) `W/temp` holding `x.mac`, `c.a2l`, `x.s19`, `x.hex` with D set → questions 0, 0, 1, 1 on each surface
examples: (9b graph B87, post-9b) a `#files_list` pick and a router `workarea` choice of `x.s19` → equal session digests and 0 `copy_into_workarea` calls (the data arm)

> callers (extractor): not run (no code)

S19TuiApp._load_from_item
req: LLR-177.1k
in: ListItem item
out: None
func: base (`:13325`): `filename = item.data`; `candidate.exists()` → log, then `load_a2l_from_path(candidate)` for an A2L suffix, else `load_selected_file(candidate)`. Post-9b: `self._load_workarea_file(filename)`. Called from `on_list_view_selected` (`#files_list`).
module: s19_app/tui/app.py
examples: (9b probe p9b F7) `w.s19` → 0 copies; `w.a2l` → 1 copy; `w.a2l.json` → `Unsupported file type: .json` (holds on base)
examples: (tests) 3 direct calls: `test_b100_focus.py:364`, `test_b100_recents.py:944`, `test_b100_recents.py:2823` (holds on base; each pick then waits or reads at once, census)

> callers (extractor): unmarked site `on_list_view_selected` app.py:13183

S19TuiApp.update_a2l_view
req: LLR-176.3
in:
out: None
func: (`:16883`) rebuilds the A2L tag table, the enriched tags and the A2L panels from `current_a2l_data` and `current_file`. The main-thread share of an A2L attach (P12b-4 minus P12b-7: about 3.5 s for case_06), HLR-176's declared freeze. Unchanged by 12b; the install handler paints its step name before calling it (LLR-176.3).
module: s19_app/tui/app.py
examples: (E1 P12b-4, P12b-7) 8.76 s − 5.01 s ≈ 3.75 s of the case_06 attach is outside the parse (copy + this build) (holds on base)

> callers (extractor): `S19TuiApp._handle_load_project` (direct, app.py:11879); `S19TuiApp._install_project_image` (through an unmarked helper, app.py:15505); `S19TuiApp.action_unload_all` (through an unmarked helper, app.py:14578); `S19TuiApp.load_a2l_from_path` (direct, app.py:13152); `S19TuiApp.load_selected_file` (through an unmarked helper, app.py:15505); `S19TuiApp.on_loaded_artifacts_panel_unload_requested` (through an unmarked helper, app.py:14578)

S19TuiApp.load_from_path
req: LLR-177.3a, HLR-177a
in: Path path
out: None
func: (`:13005`) the typed / recent / variant file load: refusals, `set_progress(10)`, `copy_into_workarea` on the main thread, recent record, `set_progress(50)`, `_start_load_worker(copied)`. Post-9b: the fallback condition on the record. Post-12a: begin `file_load` after the refusals, `except BaseException: _busy_fail; raise`, step 2, `_start_load_worker(copied, gen=gen)` (12a graph A12-30 … A12-37). Its key `file_load` makes it a session action (ruling Q2). Unchanged by 12b in body (the copy stays on the main thread, ruling Q5).
module: s19_app/tui/app.py
modify: [I/O: workarea temp]
examples: (12a graph A12-30, post-12a) `load_from_path(case_01/firmware.s19)` → 1 begin `Loading firmware.s19`, spy `[0, 33, 66, 0]`, outcome `Loaded firmware.s19`
examples: (support `tests/support/b100_projects.py:383` `append_variant`) a project load, one pause, then `load_from_path` (holds on base; under 12b the project worker may still run when this call starts — see census)

> callers (extractor): unmarked sites `_load_path_from_user_input` app.py:12942, `_handle_select_variant` app.py:7611

S19TuiApp._start_load_worker
req: LLR-177.1k, LLR-177.4c
in: Path path; Optional[list[Path]] a2l_files = None
out: None
func: (`:15706`) `@work(thread=True, exclusive=True, group="load")`: `_parse_loaded_file` (raise → `call_from_thread(_handle_load_error, …)`; `None` → unsupported), `_prepare_load_payload`, `call_from_thread(_apply_prepared_load, …)`, `call_from_thread(set_progress, 100, …)`, then `_sync_loaded_file_to_project` when a project is open. Default `exit_on_error=True`. Post-12a: `gen` keyword-only and required (not in `in:`, which gives the base signature), `try / finally: call_from_thread(_busy_fail, "file_load", gen)`, step 3 before the install, the end through `end_busy` (12a graph). 12b changes: a second caller (`_load_workarea_file`'s data arm, in place); its end goes through the shared end tail so a confirmed quit can exit after it (E1 C9).
module: s19_app/tui/app.py
examples: (12a graph A12-33, post-12a) `_apply_prepared_load` raising → the `finally` ends the run, then `run_test` raises `WorkerFailed` (`exit_on_error`, E1 P12b-2)
examples: (E1 P12b-1, executed on Textual 8.2.8) a second worker in the same exclusive group cancels the first `Worker` object, but its thread keeps running and its `call_from_thread` callback still lands (`landed: [('second', …), ('first', …)]`) (holds on base; why the busy refusal is a state check)

> callers (extractor): `S19TuiApp.load_from_path` (direct, app.py:13071)

S19TuiApp._handle_load_error
req: LLR-177.4c
in: Path path; Exception exc
out: None
func: (`:15785`) clears `_pending_variant_id`, logs, `Load failed: <exc>`, `set_progress(100, "Load failed")`. Post-12a: takes `gen` (a third parameter), ends through `end_busy("file_load", gen, "Load failed")`. 12b changes: the end goes through the shared end tail (E1 C9).
module: s19_app/tui/app.py
examples: (12a graph A12-31, post-12a) a parse raise → log `['Load failed: synthetic parse failure', 'Load failed']`, 1 effective end

> callers (extractor): none listed (framework, key or message dispatch)

S19TuiApp.action_load_file
req: LLR-177.3
in:
out: None
func: base (`:7329`): logs, pushes `LoadFileScreen()` → `_handle_load_dialog`. Post-9b: pushes `LoadDialog(mode="path", …)` (9b graph). Keys `ctrl+l` (priority), `l`; palette `load_file`. No state check. 12b changes: the busy check first (LLR-177.3).
module: s19_app/tui/app.py
examples: (9b probe p9b F1) `l` → stack `['Screen', 'LoadFileScreen']` (holds on base)

> callers (extractor): none listed (framework, key or message dispatch)

S19TuiApp.action_load_project
req: LLR-177.3
in:
out: None
func: base (`:7439`): `list_projects()`; none → `No saved projects found.`; else pushes `LoadProjectScreen(projects)` → `_route_load_project`. Post-9b: pushes `LoadDialog(mode="list", highlight=…)` also with 0 projects. Keys `p`, `#ws_load_project_button`, palette `load_project`. 12b changes: the busy check first (LLR-177.3).
module: s19_app/tui/app.py
examples: (9b probe p9b U5) `p` with 7 listed folders → stack `['Screen', 'LoadProjectScreen']` (holds on base)

> callers (extractor): unmarked site `on_button_pressed` app.py:17635; key `p` and the palette

S19TuiApp._confirm_then_load
req: LLR-177.3a, LLR-174.4
in: QuestionKind kind; str target; Callable[[], None] go
out: None
func: (post-10, from the 10 graph; not yet in code) `items = _load_would_lose(kind)`; empty → `go()` at once; else push `ConfirmQuestionScreen(title, body, "Replace (y)", "Cancel (n)")`; `y` → `call_after_refresh(go)`; cancel → `_rehome_focus_after_load()`, 0 lines. Callers: `_route_load_project`, `_load_path_from_user_input` (data, a2l), `_load_workarea_file`, `_handle_select_variant`. 12b changes: the busy check at its top, before the guard (LLR-177.3a, E1 S-e).
module: s19_app/tui/app.py
examples: (10 graph C02, post-10) D set; a typed `b.s19`, a `#files_list` pick of `x.s19` and `v` to `firmware_b` → 3 questions, 1 per request

> callers (extractor): not run (no code)

S19TuiApp.action_select_variant
req: LLR-177.3b
in:
out: None
func: (`:7509`) no variant set → a status line; else pushes `SelectVariantScreen` → `_handle_select_variant`. Key `v`, palette `select_variant`, the Load-result panel's `v` (through `_handle_load_result`). No state check. 12b changes: the busy check first.
module: s19_app/tui/app.py
examples: (E1 LLR-177.3b negative control, code read `:7509`) no state check (holds on base)

> callers (extractor): unmarked site `_handle_load_result` app.py:7507; key `v` and the palette (dispatch by name)

S19TuiApp.action_unload_all
req: LLR-177.3c
in:
out: None
func: (`:14668`) `U`: unloads every artifact (image, MAC, A2L), clearing the session through the unload path. No state check. 12b changes: the busy check first.
module: s19_app/tui/app.py
examples: (E1 LLR-177.3c negative control, code read `:14668`) no state check (holds on base)

> callers (extractor): none listed (framework, key or message dispatch)

S19TuiApp.on_loaded_artifacts_panel_unload_requested
req: LLR-177.3c
in: LoadedArtifactsPanel.UnloadRequested message
out: None
func: (`:14636`) the Loaded panel's `[u]` on one slot (image, MAC or A2L) → unloads that artifact. No state check. 12b changes: the busy check first.
module: s19_app/tui/app.py
examples: (code read `:14636`) no state check (holds on base)

> callers (extractor): none listed (framework, key or message dispatch)

S19TuiApp.on_patch_editor_panel_action_requested
req: LLR-177.3e
in: PatchEditorPanel.ActionRequested event
out: None
func: (`:3886`) the Patch Editor dispatcher: reads `self._change_service`, `self.current_file`; actions `add_entry`, `edit_entry`, `remove_entry`, `load_doc`, `parse_paste`, `refresh_doc`, `validate_doc`, `apply_doc`, `save_doc`, `run_checks`, `execute_scope` (`PATCH_ACTIONS_V2`). No state check. 12b changes: one busy check at its top refuses every action (ruling Q3).
module: s19_app/tui/app.py
examples: (code read `:3949`–`:4060`) 11 action arms behind one handler, none checks a running action (holds on base; `save_doc` and `execute_scope` are refused too by a top-of-handler guard — baseline-notes Surprise 4)

> callers (extractor): none listed (framework, key or message dispatch)

S19TuiApp.on_patch_editor_panel_save_back_decision
req: LLR-177.3e
in: PatchEditorPanel.SaveBackDecision event
out: None
func: (`:4094`) the save-back of the patched image into the project (writes a variant, rewrites `project.json` through `_rewrite_project_manifest`). No state check. 12b changes: the busy check first.
module: s19_app/tui/app.py
examples: (test `test_b100_active_variant.py` :682) `app.on_patch_editor_panel_save_back_decision(PatchEditorPanel.SaveBackDecision("firmware.s19", 32))` writes a manifest (holds on base)

> callers (extractor): none listed (framework, key or message dispatch)

S19TuiApp.on_patch_editor_panel_undo_requested
req: LLR-177.3e
in: PatchEditorPanel.UndoRequested event
out: None
func: (`:4330`) the panel's undo → `_change_service.undo()` when `_patch_history_action_allowed()`. No busy check. 12b changes: the busy check first.
module: s19_app/tui/app.py
examples: (code read `:4330`) no state check beyond the history gate (holds on base)

> callers (extractor): none listed (framework, key or message dispatch)

S19TuiApp.on_patch_editor_panel_redo_requested
req: LLR-177.3e
in: PatchEditorPanel.RedoRequested event
out: None
func: (`:4358`) the panel's redo → `_change_service.redo()`. 12b changes: the busy check first.
module: s19_app/tui/app.py
examples: (code read `:4358`) no state check beyond the history gate (holds on base)

> callers (extractor): none listed (framework, key or message dispatch)

S19TuiApp.action_patch_undo
req: LLR-177.3e
in:
out: None
func: (`:4413`) the undo key → `self._change_service.undo()` (`:4436`). 12b changes: the busy check first.
module: s19_app/tui/app.py
examples: (code read `:4436`) the service undo runs with no state check (holds on base)

> callers (extractor): `S19TuiApp.on_patch_editor_panel_undo_requested` (direct, app.py:4356)

S19TuiApp.action_patch_redo
req: LLR-177.3e
in:
out: None
func: (`:4439`) the redo key → `self._change_service.redo()` (`:4462`). 12b changes: the busy check first.
module: s19_app/tui/app.py
examples: (code read `:4462`) the service redo runs with no state check (holds on base)

> callers (extractor): `S19TuiApp.on_patch_editor_panel_redo_requested` (direct, app.py:4381)

S19TuiApp.on_patch_editor_panel_edit_json_requested
req: LLR-177.3e
in: PatchEditorPanel.EditJsonRequested event
out: None
func: (`:4465`) opens the JSON editor on the document; its result replaces the document. 12b changes: the busy check first.
module: s19_app/tui/app.py
examples: (code read `:4465`) no state check (holds on base)

> callers (extractor): none listed (framework, key or message dispatch)

S19TuiApp.on_patch_editor_panel_entry_edit_json_requested
req: LLR-177.3e
in: PatchEditorPanel.EntryEditJsonRequested event
out: None
func: (`:4579`) opens the JSON editor on one entry; its result replaces the entry. 12b changes: the busy check first.
module: s19_app/tui/app.py
examples: (code read `:4579`) no state check (holds on base)

> callers (extractor): none listed (framework, key or message dispatch)

S19TuiApp.on_patch_editor_panel_change_file_selected
req: LLR-177.3e
in: PatchEditorPanel.ChangeFileSelected event
out: None
func: (`:6110`) the `#patch_doc_file_select` pick: the containment guard, then `_patch_editor_load(panel, candidate)`. Post-10: reads `panel.is_dirty` and pushes `LoadGuardScreen` when dirty (10 graph C59). 12b changes: the busy check first.
module: s19_app/tui/app.py
examples: (10 graph C59, post-10) a dirty panel → 1 `LoadGuardScreen`, 0 loads; a clean panel → the pick loads

> callers (extractor): none listed (framework, key or message dispatch)

S19TuiApp.on_patch_editor_panel_dirty_load_requested
req: LLR-177.3e
in: PatchEditorPanel.DirtyLoadRequested event
out: None
func: (`:6232`) the dirty-load guard popup (`LoadGuardScreen`); its accept arm loads the document. 12b changes: the busy check first.
module: s19_app/tui/app.py
examples: (code read `:6232`) no state check (holds on base)

> callers (extractor): none listed (framework, key or message dispatch)

S19TuiApp.check_action
req: LLR-177.4, LLR-177.4d
in: str action; tuple parameters
out: Optional[bool] allowed
func: base (`:8034`): window gates, then `super().check_action`. Post-9b / post-10 / post-11: first `action in _LOAD_DIALOG_INERT_ACTIONS and any(isinstance(s, (LoadDialog, ConfirmQuestionScreen, SaveProjectScreen)) for s in self.screen_stack)` → `False`, with `_LOAD_DIALOG_INERT_ACTIONS = {"load_file", "save_project", "focus_palette", "cycle_density"}`. `quit` is not in the set, so `ctrl+q` (Textual `App.BINDINGS`, `priority=True`) reaches `action_quit` under every modal. 12b: no change proposed by E1 (open question Q-c2 in the interfaces).
module: s19_app/tui/app.py
examples: (11 graph B11-07, post-11) with the Save dialog open, `ctrl+l`, `ctrl+s`, `ctrl+k`, `ctrl+d` are inert (4 of 4)
examples: (code read, Textual 8.2.8 `app.py:455`–`:462`, `:4460`–`:4462`) `ctrl+q` is a priority binding to `quit`; `App.action_quit` is `async` and calls `self.exit()` (holds on base; `S19TuiApp` defines no `action_quit`, `BINDINGS` holds `("q", "quit", "Quit")` at `:2126`)

> callers (extractor): unmarked sites window_help.py:1134, :1145 (the key bar); Textual `App.run_action` for every key and palette dispatch

S19TuiApp.begin_busy
req: HLR-177a, LLR-177.3f
in: BusyKey key; str label; Sequence[str] steps
out: int gen
func: (post-12a, from the 12a graph; not yet in code) main thread only: `last_gen += 1`; the first run records `restore`; a run under the same key is replaced; `runs[key] = _BusyRun(gen, label, steps, 1, 0.0, monotonic())` inserted last (the shown run); paints the line, bar 0, class `-busy`, one timer; returns `gen`. 12b reads `self._busy.runs` (ordered, newest last; `_BusyRun.label` already painted) for the busy check and writes nothing there (12a S-b).
module: s19_app/tui/app.py
examples: (12a graph A12-01, post-12a) `begin_busy("file_load", "Loading x.s19", (…3 steps))` → T reads `⠋ Loading x.s19  ·  step 1/3 Copy into the work area  ·  00:00`, `gen == 1`

> callers (extractor): not run (no code)

S19TuiApp.step_busy
req: LLR-177.5, LLR-177.5a, LLR-176.3
in: BusyKey key; int gen; int n; Optional[int] done = None; Optional[int] total = None
out: None
func: (post-12a, from the 12a graph; not yet in code) unknown key / stale `gen` → no-op; clamps `n`; `done / total` clamped to 0 … 1 and never falling within a step; repaints and sets the bar only for the shown run. Main thread; a worker posts it with `call_from_thread`. Synchronous paint (12b LLR-176.3 defers the step's work with `call_after_refresh`).
module: s19_app/tui/app.py
examples: (12a graph A12-07, post-12a) a 2-step run, step 2 with `done` 1, 2, 3, 4 MiB of 4 MiB → bar 62, 75, 87, 100

> callers (extractor): not run (no code)

S19TuiApp.end_busy
req: LLR-177.3h, LLR-177.4c
in: BusyKey key; int gen; str outcome; Optional[str] final_line = None
out: bool ended
func: (post-12a, from the 12a graph; not yet in code) unknown key / stale `gen` → `False`; outcome → one status-log line; removes the run; others remain → repaint the newest (a given `final_line` becomes `pending`, P-4); none remain → stop the timer, bar 0, paint `final_line` > `pending` > `restore`; `True`. The hand-back is complete when it returns (12b reads its quit flag after it).
module: s19_app/tui/app.py
examples: (12a graph A12-16, post-12a) a pending file state, then `end_busy(k, g, "o", final_line="Loaded project 'P' -> firmware.s19")` → T reads the final line

> callers (extractor): not run (no code)

S19TuiApp._busy_fail
req: LLR-177.2, LLR-177.2a, LLR-177.2b
in: BusyKey key; int gen
out: bool ended
func: (post-12a, from the 12a graph, accepted P-1; not yet in code) main thread: unknown / stale → `False`; else `end_busy(key, gen, f"{run.label} failed")`. A no-op after an effective end, so every `finally` can call it.
module: s19_app/tui/app.py
examples: (12a graph A12-72, post-12a) a file load that ended with `Loaded firmware.s19` → its worker's `finally` posts `_busy_fail` → `False`, 0 lines added

> callers (extractor): not run (no code)

ConfirmQuestionScreen.__init__
req: LLR-177.4, LLR-177.4a
in: str title; str body; str yes_label; str no_label
out: ConfirmQuestionScreen
func: (post-10, from the 10 graph and fixed interfaces; not yet in code) a `ModalScreen[bool]`: `AUTO_FOCUS = "#confirm_no"`; `y` → `True`, `n` / `escape` → `False`; labels as `rich.text.Text`; ids `#confirm_box`, `#confirm_title`, `#confirm_body`, `#confirm_buttons`, `#confirm_yes`, `#confirm_no`; a `_dismissed` guard. It imports nothing from `app.py` ("Inc 12 builds the quit question from it", 10 S-a). 12b reuses it unchanged with the quit texts (LLR-177.4a).
module: s19_app/tui/screens.py
examples: (10 graph, G-A Q1-2, post-10) the question opens with the focus on `#confirm_no`

> callers (extractor): not run (no code)

parse_a2l_file
req: LLR-176.4, LLR-176.4a, LLR-177.5
in: Path path
out: dict a2l_data
func: (`a2l.py:2627`) `build_section_tree(path)`, then record layouts, compu methods and tables, `extract_a2l_tags`, segment counts and logs; returns `path`, `sections`, `errors`, `tags`, `record_layouts_by_name`, `compu_methods_by_name`, `compu_tabs_by_name`. Pure (module logger only). Re-exported by `a2l_parse.py`; imported by name into `app.py` (`:40`), `change_service.py`, `flow_execution_service.py`, `variant_execution_service.py`. 12b changes: `parse_a2l_file(path, progress=None)`, the callback passed to the tree build; the result unchanged (LLR-176.4, .4a).
module: s19_app/tui/a2l.py
examples: (E1 P12b-7) the case_06 A2L parses in 5.01 s (holds on base)
examples: (code read `:2627`) the signature takes no callback (holds on base; RED side of LLR-176.4)
examples: (tests) 3 monkeypatches replace it with a one-parameter fake: `test_tui_app.py:403` (`fake_parse(path)`), `test_b100_project_check.py:704` (`_denied(path)`), and `test_b100_project_homes.py:1936` (`_parse(path, *args, **kwargs)`, tolerant) (holds on base; see census)

> callers (extractor): `S19TuiApp._load_a2l_data_with_cache` (direct, app.py:15850); `S19TuiApp.on_patch_editor_panel_action_requested` (through an unmarked helper, variant_execution_service.py:2662); unmarked sites change_service.py:3225, flow_execution_service.py:358, :461

build_section_tree
req: LLR-176.4
in: Path path
out: tuple(list[dict] sections, list[str] errors)
func: (`a2l.py:141`) one text-mode read (`utf-8`, `errors="replace"`), line by line, pushing / popping `/begin` / `/end` sections; `FileNotFoundError` → a soft error; other `OSError` re-raised. 12b changes: reports `(bytes_consumed, total_bytes)` from its read loop, bounded (E1 E2, seam S-f).
module: s19_app/tui/a2l.py
examples: (probe p12b U3) case_06 (37 742 888 bytes, CRLF): 1 039 926 lines; the text-mode line lengths sum to 36 702 962 bytes (short by 1 per line); `handle.buffer.tell()` read after each line takes 4 608 distinct values (one per 8 KiB refill), first 8 192, last 37 742 888 = the file size, non-decreasing (holds on base)
examples: (probe p12b U3) case_01 (1 444 bytes) → 1 distinct position, equal to the size (holds on base; "an A2L smaller than one progress chunk")
examples: (probe p12b U3) the read loop alone takes 0.073 s for case_06; with `buffer.tell()` after every line, 0.659 s (holds on base; a per-line probe costs about 12 % of the 5.01 s parse)
examples: (test `test_a2l_enriched.py::test_build_section_tree_canape_ext_meta_numeric`, :143) `build_section_tree(a2l)` returns `(sections, errors)` (holds on base)
</content>
</invoke>

> callers (extractor): `parse_a2l_file` (direct, a2l.py:2657)
