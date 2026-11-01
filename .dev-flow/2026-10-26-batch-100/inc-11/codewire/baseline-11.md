# Code-Wire baseline — batch-100 Inc 11 slice ("the Save project dialog") on main 8947666, designed post-9b / post-10

Scope: the functions on the Inc 11 paths (HLR-175 … HLR-175f, LLR-175.1 … LLR-175.6; E1-scope §3): the Save dialog Inc 11 rewrites (`SaveProjectScreen`), the action that opens it, the app's action gate, the Save handler `_handle_save_dialog` with the two halves the split separates, the image decision and the planner it calls, the planner and copy-list functions of `project_gather_service.py` (ruling Q10), the folder checks, the commit helpers the commit half keeps calling, and the unchanged helpers the new preparation will call (name rules, scrub, placement predictor, change-service readers). Base: main `8947666` (Inc 9a merged; clean). sha256 prefixes: `app.py` bbf04117fbf0 (identical to the 9a tree), `screens.py` 49d6efdc73e2, `styles.tcss` 781f04ed2cc3, `project_gather_service.py` 524c3409037c. Line numbers are `8947666` lines. The `styles.tcss` selectors are not functions: they are in baseline-notes "Selectors".

Post-9b / post-10 nodes. Two nodes are changed by an earlier increment that is not in the code yet: `S19TuiApp.check_action` (9b adds the `LoadDialog` guard, 10 adds `ConfirmQuestionScreen`) and `S19TuiApp._handle_save_dialog` (10 replaces `panel._dirty` by `panel.is_dirty` at :10576). Their `func:` gives the post-10 body, taken from `inc-9b-design/codewire/proto-9b-app.md` and `inc-10-design/codewire/proto-10-app.md`, and says "post-9b" / "post-10". One node exists only in the 10 graph: `PatchEditorPanel.is_dirty`, marked "(post-10, from the 10 graph; not yet in code)"; it was left out of the extractor run (a node without code).

Example lines come from the probe `p11b` run on a throwaway copy of this tree (baseline-notes "Probe"), from the E1 probes P11-1 … P11-4 (`inc-11-design/work/`, run on the 9a tree, whose `app.py` and `screens.py` are byte-identical to `8947666`), from an existing test, or from a code read; each names its source. Every example states behaviour that holds on the base. `func:` says "11 changes: …" where an Inc 11 requirement changes the function; a node with no "11 changes" is context the change relies on.

## Nodes

SaveProjectScreen.__init__
req: HLR-175f, LLR-175.3h, LLR-175.6
in: Path default_parent; list[tuple[str, str]]? variants = None; list[str]? candidate_files = None
out: SaveProjectScreen screen
func: keeps `default_parent` (the work area, from `action_save_project`), `variants` (`(variant_id, display)` pairs) and `candidate_files` (project-relative `.json` names) for the assignment rows (HLR-017, ruling Q4). No callable, no initial name, no plan. 11 changes: takes `preview`, `confirm`, `initial_name` (S-b) instead of `default_parent`; keeps `variants` / `candidate_files` and their attributes (`screen.variants`, `screen.candidate_files` are read by `test_tc304` / `test_tc305`).
module: s19_app/tui/screens.py
examples: (probe p11b U7) signature `(self, default_parent: 'Path', variants=None, candidate_files=None)` (holds on base)
examples: (test_tc305_screen_offers_only_in_project_candidate_files) a re-save of `proj` with `doc.json`, `extra.json` → `screen.candidate_files` lists them, never `project.json` (holds on base)

> callers (extractor): `S19TuiApp.action_save_project` (direct, :7399)

SaveProjectScreen._assignment_rows_enabled
req: HLR-175f, LLR-175.4i
in:
out: bool enabled
func: property: `bool(variants) and bool(candidate_files)` (D-NEWPROJ). Gates the assignment rows in `compose` and the composition read in `_collect_composition`. Unchanged by Inc 11 (ruling Q4); the rows move between `#save_summary` and `#save_ok` in the focus order (§C.4 census row).
module: s19_app/tui/screens.py
examples: (code read) a fresh save (no variant set) → `False`; a re-save of a 2-variant project with 2 candidates → `True` (holds on base)

> callers (extractor): none listed (property reads)

SaveProjectScreen.compose
req: HLR-175f, LLR-175.2, LLR-175.3i, LLR-175.4g, LLR-175.4h, LLR-175.4i
in:
out: ComposeResult widgets
func: builds `Container#load_dialog.modal-dialog` with Label "Save project folder under:" (`.modal-title`), `OsClipboardInput#project_parent_path`, `Container#save_browse_row` holding `Button#save_browse` ("Browse..."), Label "Project name (new folder name):", `OsClipboardInput#project_name`, then (rows enabled) Label + `SelectionList#assign_batch.assign-list` and per variant Label "Assign files to '<display>':" (markup ON: the display label is parsed) + `SelectionList#assign_<i>`, then `Container#saveproject_buttons.modal-buttons` with `Button#save_ok.modal-confirm` ("Save") and `Button#save_cancel` ("Cancel"). No `#save_where`, no `#save_summary`, no BINDINGS, no AUTO_FOCUS. 11 changes: rewritten (S2): `#save_box` outer id, `#project_name`, `#save_where`, focusable `#save_summary`, assignment rows, `#save_ok` "Save (alt+s)", `#save_cancel` "Cancel (esc)"; no parent field, no Browse; markup off.
module: s19_app/tui/screens.py
examples: (P11-2) `widgets #project_parent_path: 1 #save_browse: 1 #save_summary: 0 #save_where: 0` (holds on base; RED side of LLR-175.2, HLR-175f)
examples: (P11-2) `focused at open: OsClipboardInput project_parent_path` (holds on base; RED side of LLR-175.3d)
examples: (probe p11b U7) `id="load_dialog"` occurs 8 times in `screens.py`; this screen is one of them (holds on base; S-f)

> callers (extractor): none listed (framework)

SaveProjectScreen.on_mount
req: LLR-175.3h, LLR-175.5b
in:
out: None
func: one statement: `#project_parent_path.value = str(default_parent)`. The name field starts empty; nothing is computed. 11 changes: prefill `initial_name` selected (LLR-175.3h); after the first refresh start the first preview (LLR-175.5b).
module: s19_app/tui/screens.py
examples: (code read; P11-2) after open the parent field holds the work area and `#project_name` is `""` (holds on base; RED side of LLR-175.3h)

> callers (extractor): none listed (framework)

SaveProjectScreen._collect_composition
req: HLR-175f
in:
out: Tuple[Tuple[str, ...], dict] composition
func: rows disabled → `((), {})`; else `#assign_batch.selected` as `batch` and, per variant index, `#assign_<i>.selected` keyed by `variant_id` (D-KEY), empty selections omitted. Unchanged by Inc 11 (ruling Q4).
module: s19_app/tui/screens.py
examples: (test_tc304_screen_collects_per_variant_and_batch_assignment) batch `doc.json`, variant `b` → `extra.json` → payload `batch == ("doc.json",)`, `assignments == {"b": ("extra.json",)}` (holds on base)
examples: (test_tc306_screen_no_selection_yields_empty_composition) nothing selected → `batch == ()`, `assignments == {}` (holds on base)

> callers (extractor): `SaveProjectScreen.on_button_pressed` (direct, :685)

SaveProjectScreen.on_button_pressed
req: HLR-175c, HLR-175d, LLR-175.2a, LLR-175.3, LLR-175.3a, LLR-175.3b, LLR-175.3c, LLR-175.3f, LLR-175.4b
in: Button.Pressed event
out: None
func: `#save_cancel` → `dismiss(None)`; `#save_browse` → a tkinter folder picker writes `#project_parent_path`; `#save_ok` → strip parent and name; either empty → return (no feedback, P-19); else `dismiss(SaveProjectPayload(parent, name, batch, assignments))`. No check before the dismiss: every refusal is the handler's, after the dialog closed. `enter` in `#project_name` posts `Input.Submitted`, which nothing reads; `escape` is not bound (P-18). 11 changes: Cancel stays; Browse removed; Save / `alt+s` / `enter` → empty → token pair, stay (LLR-175.3b); else `confirm(name, painted plan)` → `None` dismiss with the work area as parent (LLR-175.2a), else repaint and stay (LLR-175.3f, LLR-175.4b).
module: s19_app/tui/screens.py
examples: (P11-2, P-19) empty name, `#save_ok` clicked → stack `['Screen', 'SaveProjectScreen']`, `'name is empty'` not painted (holds on base; RED side of HLR-175d)
examples: (P11-2, P-18) `escape` → stack still `['Screen', 'SaveProjectScreen']` (holds on base; RED side of HLR-175c)
examples: (test_tc034_modals_behavior_methods_intact) `#save_cancel` → dismiss `None`; parent + `Demo_Project` + `#save_ok` → a `SaveProjectPayload` (holds on base)

> callers (extractor): none listed (framework)

S19TuiApp.action_save_project
req: HLR-175f, LLR-175.3h, LLR-175.3j, LLR-175.5, LLR-175.5b
in:
out: None
func: the Save key (`ctrl+s` priority, shown; `s` hidden; palette entry "Save project" built 1:1 from `BINDINGS`). Logs what is loaded (nothing loaded is only a log line), builds `variants` / `candidate_files` when a variant set exists, and pushes `SaveProjectScreen(self.workarea, variants, candidate_files)` with `_handle_save_dialog` as the dismiss callback (read as an attribute at push time: `test_tui_manifest_save._capture_save_payload` replaces it with a one-argument lambda). Runs also while a modal is on top (priority binding). 11 changes: nothing loaded → status, no dialog (LLR-175.3j); push with the callables and the open project's name (LLR-175.3h); the session inputs after the first frame (LLR-175.5, .5b).
module: s19_app/tui/app.py
examples: (P11-2) nothing loaded, `ctrl+s` → stack `['Screen', 'SaveProjectScreen']` (holds on base; RED side of LLR-175.3j)
examples: (P11-2) `ctrl+s` with the Save dialog on top → stack `['Screen', 'SaveProjectScreen', 'SaveProjectScreen']` (holds on base and post-10: the guard does not name this screen; RED side of LLR-175.3g)

> callers (extractor): none listed (bindings and palette dispatch by action name)

S19TuiApp._assignment_candidate_files
req: HLR-175f
in:
out: list[str] names
func: `current_project_dir` absent → `[]`; else the sorted `*.json` regular files of the project folder, `project.json` excluded (D-SCOPING). Reads the folder on every dialog open. Unchanged by Inc 11.
module: s19_app/tui/app.py
examples: (test_tc305_screen_offers_only_in_project_candidate_files) a project holding `doc.json`, `extra.json`, `project.json` → `["doc.json", "extra.json"]` (holds on base)

> callers (extractor): `S19TuiApp.action_save_project` (direct, :7397)

S19TuiApp._variant_display_options
req: HLR-175f
in: ProjectVariantSet variant_set
out: list[tuple[str, str]] options
func: `(variant_id, display label)` pairs in set order, for the assignment rows and the variant picker. Unchanged by Inc 11.
module: s19_app/tui/app.py
examples: (test_tc304_screen_collects_per_variant_and_batch_assignment) project `proj` with `a.s19`, `b.s19` → ids `["a", "b"]` (holds on base)

> callers (extractor): `S19TuiApp.action_save_project` (direct, :7396); `S19TuiApp._handle_save_dialog` (through an unmarked helper, :17610) — unmarked sites: app.py:7539 (1)

S19TuiApp.check_action
req: LLR-175.3g
in: str action; tuple parameters
out: bool? allowed
func: post-10 (from proto-9b-app.md G3 and proto-10-app.md; base :8034 has only the window gates). First test: `action in _LOAD_DIALOG_INERT_ACTIONS and any(isinstance(s, (LoadDialog, ConfirmQuestionScreen)) for s in self.screen_stack)` → `False`; `_LOAD_DIALOG_INERT_ACTIONS = frozenset({"load_file", "save_project", "focus_palette", "cycle_density"})`. Then `confirm_attention` only on Flow Execution, `page_*_context` only on A2L / MAC, `hex_page_*` only on Workspace, then `super().check_action`. Also read by the key bar (`window_help.py:1134`, `:1145`). 11 changes: `SaveProjectScreen` joins the tuple of the whole-stack test (S-e, ruling Q3).
module: s19_app/tui/app.py
examples: (P11-2, P11-3; base) with the Save dialog open: `ctrl+l` → stack `['Screen', 'SaveProjectScreen', 'LoadFileScreen']`; `ctrl+s` → a second `SaveProjectScreen`; `ctrl+d` → density `['density-comfortable'] -> ['density-compact']` (holds on base; post-10 the same with `LoadDialog` for `ctrl+l`, because neither guard names the Save dialog; RED side of LLR-175.3g)
examples: (proto-10-app C45, post-10) with `ConfirmQuestionScreen` on top: `ctrl+l` / `ctrl+s` / `ctrl+k` / `ctrl+d` → 0 actions (holds post-10, not on base)

> callers (extractor): none listed — unmarked sites: window_help.py:1134, window_help.py:1145 (2; the key bar)

S19TuiApp._handle_save_dialog
req: HLR-175a, LLR-175.4a, LLR-175.4l, LLR-175.6, LLR-175.1a, LLR-175.1b, LLR-175.1c, LLR-175.1d, LLR-175.1e, LLR-175.1f, LLR-175.1g, LLR-175.1h, LLR-175.1i, LLR-175.1j, LLR-175.1k, LLR-175.1l, LLR-175.1m
in: SaveProjectPayload? payload
out: None
func: post-10 (one expression changed by Inc 10 at :10576, `panel._dirty` → `panel.is_dirty`; otherwise the base body). One method, `:9447`–`:10605` (1 159 lines). It has two halves, cut at `:9856` (the comment before `project_dir.mkdir`). **Guard-and-plan half, `:9447`–`:9855` (409 lines), writes no `self.` attribute, no file:**
  - (G0) `:9448`–`:9450` `payload is None` → log "Save project canceled.", return.
  - (G1) `:9451`–`:9454` nothing loaded → status `Nothing to save: load a data file or A2L first.`
  - (G2) `:9455`–`:9459` `resolve_input_path(payload.parent_folder, base_dir)` not a folder → `Parent folder not found or not a directory.`
  - (G3) `:9460`–`:9475` parent's real path ≠ the work area's (LLR-171.3) → `… is not the work area folder — choose the work area as the parent folder (…)`.
  - (G4) `:9476`–`:9486` blank name → `name is empty — type a project name.`
  - (G5) `:9487`–`:9497` `sanitize_project_name` empty → the same text.
  - (G6) `:9498`–`:9518` raw name, each `\`/`/` component, or sanitised name a device name → `'<typed>' is a device name — choose another name.` (typed name unscrubbed).
  - (G7) `:9519`–`:9530` sanitised name in `RESERVED_WORKAREA_HOMES` case-folded → `'<cleaned>' is a reserved name — choose another name.`
  - (G8) `:9531`–`:9540` over `PROJECT_NAME_MAX_CHARS` → `name too long (at most 64 characters) — shorten the name.`
  - (G9) `:9541`–`:9551` `len(workarea) + 1 + len(cleaned) + 53 > 259` → `path too long — shorten the name.`
  - (G10) `:9552`–`:9608` clash loop over `sorted(workarea.iterdir())`: same name case-folded, not reserved, not a reparse point, holding `project.json` or a data/A2L file (`OSError` → skipped, SEC2-1); the open project → `cleaned` rebinds to the on-disk spelling (LED .52(a)); another project and `typed != item.name` → `'<typed>' is already a project as '<item>' — choose another name.` (both unscrubbed). It does not call `list_projects`.
  - (G11) `:9609`–`:9637` image / MAC / A2L path that no longer exists → `source file missing: <name> — reload it or remove it from the project.` + toast.
  - (G12) `:9638`–`:9644` `project_dir = workarea / cleaned` (unresolved, SEC-1).
  - (G13) `:9645`–`:9677` `_project_folder_refusal(project_dir)`: `link` → `'<cleaned>' is a link or junction — choose another name.`; `unreadable` → `'<pn(cleaned)>' could not be read — check that the folder can be opened, then save again.`; other → the not-the-work-area text.
  - (G14) `:9678`–`:9697` `save_as_source = _save_as_source_for(project_dir)` (1st of 2 calls per save, R2-2), `source_gone`, `source_reason = _project_folder_refusal(save_as_source)`.
  - (G15) `:9698`–`:9790` `try:` `image_step = _decide_project_image()` (image loaded) else `_ProjectImageStep(emit=False)`; `existing = read_project_manifest(project_dir)`; the carry source (save as: the open project, unless refused or its manifest is a link; else the target); `target_carry = _manifest_carry(…)` unless damaged; `carried_derived`; `carried_active_document` through `recorded_document_state` (drop → `carried_document_line`); `emitted_record = _derived_record(…)` on an emit; `plan = _plan_project_save(project_dir, cleaned, image_step, derived=…, carried_active_document=…, source_reason=…)`.
  - (G16) `:9791`–`:9808` `except OSError` → `<file> could not be read: <strerror>. Nothing written.` + toast (no next step: LLR-175.1l).
  - (G17) `:9809`–`:9819` `plan.refusal` (the image step's blocked-entries text arrives here through the plan) → status + toast.
  - (G18) `:9820`–`:9855` new target: `shutil.disk_usage` `OSError` → `could not save — the free space of the work area could not be read — check the folder.`; `total_bytes > free` → `not enough free space (needs N bytes, M free) — free disk space or remove files from the project.` + toast.
  - Counts in this half (AST, `split-flow.out.txt`): 19 returns, 18 `set_status`, 4 `notify`.
  **Commit half, `:9856`–`:10605` (750 lines):** (C1) `:9856`–`:9868` `mkdir(exist_ok=False)` decides `created_project_dir`; (C2) `:9869`–`:9909` state snapshot, rollback lists, `document_class` (`classify_active_document(project_dir, …)`), `document_row` from `plan.rows`, `target_gathered`; (C3) `:9915`–`:10349` one `try`: `validate_project_files` → abort; sub-folder copies (`_copy_project_subfolders`); the rows loop (pasted document `_write_editor_document`, emit `emit_and_verify`, else `place_into_workarea`, each checked by `_plan_row_mismatch`); top-level copies; variant rebuild; `batch` / `assignments` from the payload else the carry; `gather_project_artifacts`; the recorded document; the merged `gathered`; SEC7-3 manifest keep; `_write_and_verify_manifest`; every failure exit → `_abort_save`; (C4) `:10350`–`:10425` the four `except` arms → `_abort_save`; (C5) `:10426`–`:10605` committed: `adopt_rederived` / `mark_saved`, `Saved project to …` (+ `— <plan.image>` on an emit), kept note, skipped-links line, `source_gone` line, unrecorded lines, the document rebinding (F5 (b) at `:10546`–`:10554`), the panel flag (post-10 `panel.is_dirty` at `:10576`), document lines, MISMATCH re-paint, `current_project` / `current_project_dir`, labels, `refresh_files`, flow session folder. Counts: 10 returns, 19 `set_status`, 2 `notify`.
  **What crosses the cut** (AST, names stored before `:9856` and read after it, loop-variable rebinds removed): `cleaned`, `project_dir`, `save_as_source`, `source_gone`, `image_step`, `existing`, `target_carry`, `carried_derived`, `carried_active_document`, `carried_document_line`, `emitted_record`, `plan` (12), plus `payload.batch` / `payload.assignments`. Prep-only: `typed_name`, `parent_resolved`, `reserved_folded`, `raw_components`, `open_project_folded`, `missing_sources`, `target_reason`, `source_reason`, `carry_dir`, `carry_manifest`, `carried_state`, `free_bytes`.
  11 changes: the guard-and-plan half moves to `_prepare_project_save` (G4–G18; G0–G3 read the payload and stay); the handler commits a prepared save, or prepares one for a bare payload (LLR-175.4l). The commit half keeps `mkdir` and every `_abort_save` exit inside `_handle_save_dialog` (TC-B100-07's AST census reads this function by name).
module: s19_app/tui/app.py
examples: (probe p11b U1) F-fresh `fresh1` → `['Project saved + manifest verified', "Saved project to …\\fresh1 (variant 'firmware')"]`, tree `['firmware.s19', 'project.json']`; per save `_save_as_source_for` 2, `_decide_project_image` 1, `_plan_project_save` 1, `_file_digest` 1, `_project_folder_refusal` 1; handler 26.2 ms (holds on base)
examples: (probe p11b U6) with project `ab` saved: `''`, `'   '`, `'!!!'` → `name is empty — type a project name.`; `con.txt`, `CON` → `is a device name — choose another name.`; `Reports` → `is a reserved name`; 65 × `a` → `name too long (at most 64 characters) — shorten the name.`; `a b` → `'a b' is already a project as 'ab' — choose another name.`; `AB` → the same naming `AB`; 0 new folders (holds on base; each refusal reaches the engineer only after the dialog closed, RED side of HLR-175b)
examples: (probe p11b U5, P11-2 for the dialog side) nothing loaded, direct call → `['Nothing to save: load a data file or A2L first.']`, no folder (holds on base)
examples: (test_tc_b100_07_ast_census_every_post_creation_return_removes) every `return` after the first `mkdir` in this function follows an `_abort_save` call; exactly 1 `except OSError` after the `mkdir` (holds on base)
examples: (test_tc_b100_31_document_with_an_identical_sibling_follows_its_landing, probe p11b U3) P records `patches/changes.json` beside an identical `patches/changes_1.json`, save as Q → the document is bound to `Q/patches/changes_1.json`, which exists (holds on base)

> callers (extractor): none listed in product code (it is passed as the dismiss callback at :7400). Tests: 56 direct call lines in 11 files plus 1 call by reference (`app.call_next(app._handle_save_dialog, …)`, `test_b100_save_image.py:880`); census in baseline-notes.

S19TuiApp._decide_project_image
req: LLR-175.5, LLR-175.1m, LLR-175.1n
in:
out: _ProjectImageStep step
func: the emit decision on data (LLR-167.1). Fast path: a non-`change` document, or no entry on an image that does not differ from its source → `emit=False`. Else `rederive_for_save` onto a copy; any `blocked` entry → `refusal="Project NOT saved: N blocked entry/entries (0x…) — fix them in the Patch Editor."`; `rederived_differs_from_source` false → copy; else `render_patched_image(..., source_kind=file_type)`; `None` → `refusal="… a patched <kind> image cannot be written — only S19 and HEX images carry change entries."`; else `emit=True` with the payload, name, `carried`, `applied_by_save`. Refreshes `document.issues` (as an apply does); writes no byte and no save record. Reads `self.current_file` (requires an image). Name-independent: the same result for every typed name. 11 changes: called once per dialog open by `_save_session_inputs` (LLR-175.5), after the first frame (LLR-175.5b).
module: s19_app/tui/app.py
examples: (probe p11b U3) P with a 1-entry document `0x80000010`, save as Q → emit, the success line ends `— firmware.s19 + 1 change entry, 1 applied by this save` (holds on base)
examples: (probe p11b U4 / U4b, LLR-175.1n reachability) a MAC-only session (`file_type` `mac`, `mem_map {0x80000000: 0}`, `ranges []`) plus 1 entry at `0x80000000` → the entry's disposition is `skipped-outside`, `emit False`, `refusal None`; the save completes as a copy with no line about the entry (holds on base; the `cannot be written` arm is not reached)
examples: (P11-1) the case_06 A2L digest is 26.1 ms best of 5; (P11-4) a 4 MiB patched image renders in 1 215 ms (holds on the 9a tree, same `app.py`)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, :9706)

S19TuiApp._plan_project_save
req: LLR-175.4, LLR-175.5, LLR-175.1i, LLR-175.6
in: Path project_dir; str project_name; _ProjectImageStep image_step; bool derived = False; str? carried_active_document = None; str? source_reason = None
out: SavePlan plan
func: target kind (`new` when nothing exists at the target; `open project` for the open project's name case-folded; else `merge`); `source_dir = _save_as_source_for(project_dir)` (the 2nd call per save, R2-2); refused source → token row 9; else for a save as `inventory_project_tree(source_dir)` (walks the open project, per call); the planned files: image (emit payload digest, or `_file_digest(image)`), MAC, A2L (`_file_digest` each), the document (pasted: serialised digest; file-backed: `classify_active_document` + `_file_digest(source)`); for an existing target the `exempt` MAC / A2L names (lstat + `_file_digest(target item)`); `plan_project_save(...)` with `_save_manifest_keys`. Raises `OSError` when a digested source cannot be read. 11 changes: takes the per-open session inputs (digests, image step) instead of digesting each call (LLR-175.5); called only inside `_prepare_project_save` (LLR-175.6).
module: s19_app/tui/app.py
examples: (probe p11b U2) P open (S19 + MAC + A2L), save `P` → `_file_digest` 3 calls, `_save_as_source_for` 2 calls; save as `Q2` → `_project_folder_refusal` 2 calls (target + source) (holds on base)
examples: (probe p11b U8) the save-as inventory of a 2 000-file project costs 189.4 ms best of 5, on every call (holds on base)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, :9783)

S19TuiApp._save_as_source_for
req: LLR-175.6
in: Path project_dir
out: Path? source
func: the open project's folder when the target does not exist (`os.path.lexists`) and that folder still exists; else `None`. A `PermissionError` counts as gone (backlog R2-1, unchanged by Inc 11). Called twice per save, by the handler and by the planner (backlog R2-2). 11 changes: evaluated once, in `_prepare_project_save` (Q10 closes R2-2).
module: s19_app/tui/app.py
examples: (probe p11b U1) `2` calls per save (holds on base)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, :9682); `S19TuiApp._plan_project_save` (direct, :10812)

S19TuiApp._project_folder_refusal
req: LLR-175.1f, LLR-175.1g
in: Path folder
out: str? reason
func: the one folder check (HLR-171b): not one plain component of the work area → `outside`; `lstat` absent → `None`; other `OSError` → `unreadable`; a link or reparse point → `link`; resolves outside → `outside`. Unchanged by Inc 11.
module: s19_app/tui/app.py
examples: (test_tc_b100_62_folder_check_permission_error_has_its_own_text[save target]) `lstat` of `W/P` raising `PermissionError` → 1 line `'P' could not be read — check that the folder can be opened, then save again` (holds on base)
examples: (test_at_b100_11_junction_project_is_not_listed_and_save_refuses_it) `W/evil` a junction, Save `evil` → 1 line holding `link or junction` (holds on base)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, :9647, :9694); `S19TuiApp.list_projects` (direct, :12127) — unmarked sites: app.py:11684 (1)

S19TuiApp._manifest_carry
req: LLR-175.4f
in: Path project_dir; ProjectManifest? manifest
out: dict carry
func: the carried records of a target or save-as source manifest (`derived_from`, `active_document`, `batch`, `assignments`, `gathered`), read once. Unchanged by Inc 11; LLR-175.4f's merge row reads the target's recorded active variant in the preparation, which this function does not return today (code read: no `active_variant` key in the carry).
module: s19_app/tui/app.py
examples: (code read) a damaged manifest → not called (`target_carry = {}`) (holds on base)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, :9732) — unmarked sites: app.py:12489 (1)

S19TuiApp._manifest_is_link
req: LLR-175.6
in: Path folder
out: bool is_link
func: SEC8b-3: `folder/project.json` is a link or reparse point, or cannot be inspected → `True`. Static. Unchanged by Inc 11.
module: s19_app/tui/app.py
examples: (code read) no `project.json` → `False` (holds on base)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, :9723)

S19TuiApp._derived_record
req: LLR-175.6
in: Path base_path; Mapping[int, int] derived_map
out: DerivedFrom? record
func: the `derived_from` record an emitted image writes (its base's digest), or `None` when the base cannot be read again. Unchanged by Inc 11.
module: s19_app/tui/app.py
examples: (code read; probe p11b U3) an emitting save records one `derived_from` entry for the emitted image (holds on base)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, :9779) — unmarked sites: app.py:4200 (1)

S19TuiApp._document_home_contained
req: LLR-175.4
in: Path project_dir; str home
out: bool contained
func: SEC8a-3: `_guarded_destination(project_dir / home, workarea)`; refused → `False` and a log line. Gates the document row in the plan. Unchanged by Inc 11.
module: s19_app/tui/app.py
examples: (code read) a home that is a junction → `False`, no document row (holds on base)

> callers (extractor): `S19TuiApp._plan_project_save` (direct, :10872, :10889)

S19TuiApp._abort_save
req: HLR-175a
in: Path project_dir; bool created_project_dir; Sequence[Path] placed_files; Sequence[Path] created_dirs; Tuple save_state; Sequence[Tuple[Path, bytes]] manifest_restores = (); Sequence[Tuple[Path, bytes]] kept_copies = ()
out: None
func: the one rollback (LED .52(b), .53): unlink exactly the placed files, remove the created folders, restore a replaced manifest, restore the app state. Commit half only. Unchanged by Inc 11.
module: s19_app/tui/app.py
examples: (test_tc_b100_07_ast_census_every_post_creation_return_removes) exactly one `_abort_save`; it holds `unlink`, `rmdir` and `_variant_set` (holds on base)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, 11 sites: :9924, :9949, :10030, :10056, :10090, :10272, :10340, :10364, :10377, :10402, :10416)

S19TuiApp._copy_project_subfolders
req: HLR-175a
in: Path source_dir; Path project_dir; Sequence[InventoryFile] copies; list[Path] placed_files; list[Path] created_dirs; Mapping[str, SavePlanRow]? carried = None
out: str? failure
func: the save-as copy of `plan.copies` (sub-folder entries first, then top-level, each checked against its `carried` row); returns a failure line or `None`. Commit half only. Unchanged by Inc 11.
module: s19_app/tui/app.py
examples: (probe p11b U3) save as Q copies `patches/changes_1.json` before the gather runs (holds on base)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, :9943, :10079)

S19TuiApp._write_editor_document
req: HLR-175a
in: SavePlanRow row; Path project_dir
out: Tuple[PlacementResult?, Path?, str?] written
func: writes the pasted change document as a new file in its home through one placement; returns the placement, a created home, or a failure line. Commit half only. Unchanged by Inc 11.
module: s19_app/tui/app.py
examples: (test_b100_document.py:672) a pasted document lands as `patches/changes_1.json` beside an older `changes.json` and is recorded (holds on base)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, :9981)

S19TuiApp._write_and_verify_manifest
req: HLR-175a, LLR-175.4f
in: Path project_dir; Sequence[str] batch = (); Mapping[str, Sequence[str]]? assignments = None; Sequence[DeclaredRegion] declared_regions = (); Mapping[str, Sequence[str]]? gathered = None; Mapping[str, DerivedFrom]? derived_from = None; str? active_document = None; Callable[[Path], None]? on_written = None
out: bool ok
func: writes and re-reads `project.json` (the active variant comes from `self._variant_set`, rebuilt from the saved files just before). Commit half only. Unchanged by Inc 11.
module: s19_app/tui/app.py
examples: (probe p11b U1) `Project saved + manifest verified` (holds on base)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, :10323) — unmarked sites: app.py:12495 (1)

S19TuiApp._unrecorded_document_lines
req: HLR-175a
in: Path project_dir; Path source; str home; str? document_class; bool copied; str? carried; str? carried_line
out: list[str] lines
func: the one true line about a file-backed change document the save does not record (E3 R3). Commit half only. Unchanged by Inc 11.
module: s19_app/tui/app.py
examples: (code read) a document recorded by the carried line → `[]` (holds on base)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, :10206)

S19TuiApp.list_projects
req: LLR-175.1c
in:
out: List[str] projects
func: post-9b (proto-9b-app.md, ruling Q7): the sorted direct child folders of the work area that pass `_project_folder_refusal`, skip reserved homes case-folded, and hold the §1.3 content (a regular non-link `project.json`, or a data / MAC / A2L file, `_folder_holds_project`). Base: no content test. Not called by Save today (G10 enumerates by itself). 11 changes: none required; E1-scope §5 lets `_prepare_project_save` use it for the clash if that shrinks G10, with TC-B100-05's clash arms as the check.
module: s19_app/tui/app.py
examples: (probe p9b U2, base) `['[b]P', 'ab', 'c', 'E', 'j', 'n', 's']` with `E` empty and `n` holding `notes.txt` (holds on base; post-9b `E`, `n` are not listed)

> callers (extractor): none listed in this graph — unmarked sites: app.py:7441, app.py:11714, app.py:12871 (3: the Load callers)

_file_digest
req: LLR-175.5, LLR-175.1l
in: Path path
out: Tuple[str, int] digest
func: SHA-256 hex digest and size of a file, streamed. Raises `OSError`. Called by `_plan_project_save` per source per call.
module: s19_app/tui/app.py
examples: (probe p11b U1 / U2) 1 call for an S19-only fresh save; 3 for S19 + MAC + A2L (holds on base)
examples: (P11-1) case_06 `firmware.a2l` 37 742 888 bytes → 26.1 ms best of 5 (holds on the 9a tree)

> callers (extractor): `S19TuiApp._plan_project_save` (direct, :10850, :10857, :10864, :10893, :10937)

_save_manifest_keys
req: LLR-175.4
in: Sequence[DeclaredRegion] declared_regions; bool derived = False; bool active_document = False
out: tuple[str, ...] keys
func: the `project.json` keys the writer writes (LED .45). Unchanged by Inc 11.
module: s19_app/tui/app.py
examples: (code read) `active_document=True` → the keys include `active_document` (holds on base)

> callers (extractor): `S19TuiApp._plan_project_save` (direct, :10947)

_plan_row_mismatch
req: HLR-175a, LLR-175.4a
in: SavePlanRow row; PlacementResult placed
out: str? mismatch
func: a landed placement against its plan row: a different path, or a reuse the plan did not predict (or the reverse) → a refusal line naming both. Checked for the image / MAC / A2L / pasted document rows only; a file-backed document row is skipped in the rows loop and placed by the gather, so it is never checked (probe p11b U3). Unchanged by Inc 11.
module: s19_app/tui/app.py
examples: (probe p11b U3) the plan's document row `changes.json new` and the landing `patches/changes_1.json` differ, and no mismatch line is painted (holds on base)

> callers (extractor): `S19TuiApp._copy_project_subfolders` (direct, :12324); `S19TuiApp._handle_save_dialog` (direct, :10052)

_plan_without_document_key
req: LLR-175.4
in: SavePlan plan
out: SavePlan plan
func: the same plan without `active_document` in its keys, when the document is known not to be recorded (commit half, `:10225`). After this, the executed plan is not the painted plan object (a `dataclasses.replace` copy, same rows). Unchanged by Inc 11.
module: s19_app/tui/app.py
examples: (code read) rows unchanged, keys minus `active_document` (holds on base)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, :10225)

_save_clears_panel_flag
req: HLR-175a
in: bool document_written; str paste_text; str? parsed_paste_text
out: bool clears
func: LLR-167.8: the Patch Editor flag clears only when a file now holds every entry and no unparsed paste text is left. Commit half. Unchanged by Inc 11.
module: s19_app/tui/app.py
examples: (code read) `document_written=True`, empty paste → `True` (holds on base)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, :10569)

plan_project_save
req: LLR-175.4, LLR-175.4a, LLR-175.1i
in: Path target; str target_kind; Sequence[PlannedFile] files; str image; Sequence[str] manifest_keys; str? refusal = None; ProjectInventory? inventory = None; int? size_cap = None; frozenset[str] exempt = frozenset()
out: SavePlan plan
func: the pure planner (B100-I17): passed refusal; save as: walk refusals, `_plan_copies`, the 2 000 ceiling; the second MAC / A2L rule; the per-file cap; then one row per planned file predicted by `predict_placement` (owner document row against `target/home`; non-owner home rows against `inventory.root/home`), one `carried` row `new` per top-level copy at `target/name` (never predicted), and the `project.json` row. 11 changes (ruling Q10, F5 remainder): predict the carried and the document rows against the tree the copy will produce.
module: s19_app/tui/services/project_gather_service.py
examples: (probe p11b U3) P records `patches/changes.json` + identical `patches/changes_1.json`, save as Q → rows `[('image', 'firmware.s19', 'new'), ('document', 'changes.json', 'new'), ('manifest', 'project.json', 'new')]`, copies `['patches/changes_1.json']`; Q then holds `patches/changes_1.json` and records it; the plan never names `changes_1.json` (holds on base; RED side of Q10 / HLR-175)
examples: (BACKLOG-CODE F5 remainder, review-increment-016 F5 (a)) session image `fw_2.s19` and an identical `fw.s19` in P → the carried row says `new fw.s19`; the copy reuses `Q/fw_2.s19` and the save aborts with the "remove the duplicate copy" line (holds on base; code read + `test_e4_r11_a3r2_5_…`)

> callers (extractor): `S19TuiApp._plan_project_save` (direct, :10942)

_plan_copies
req: LLR-175.4a
in: ProjectInventory inventory; Sequence[PlannedFile] files
out: tuple[tuple[PlannedFolder, ...], tuple[InventoryFile, ...], set[str]] copies
func: the save-as copy list: top-level files minus the row names and, when a MAC / A2L row is planned, every MAC / A2L file; sub-folder files minus the file a document row owns (its key goes to `owned`). Never compares bytes, so an identical sibling of the owned file stays in the copy list. 11 changes (Q10): may return what the prediction needs about siblings.
module: s19_app/tui/services/project_gather_service.py
examples: (probe p11b U3) owner `P/patches/changes.json` → `owned` holds it; copies `['patches/changes_1.json']` (holds on base)

> callers (extractor): `plan_project_save` (direct, :1614)

painted_names
req: LLR-175.4g
in: Sequence[str] names; int limit = PAINTED_NAME_LIMIT; int clip = 120
out: str painted
func: the batch's one name scrub (Cc / Cf / Zl / Zp removed, surrogates → U+FFFD, each clipped to 120 with "…", at most 10 joined then ", and K more"). Pure. Unchanged by Inc 11.
module: s19_app/tui/services/project_gather_service.py
examples: (docstring doctest) `["a", "b‮c"]`, limit `1` → "a, and 1 more" (holds on base)

> callers (extractor): `S19TuiApp._abort_save` (direct, :9266); `S19TuiApp._copy_project_subfolders` (direct, 6 sites :12277 … :12345); `S19TuiApp._handle_save_dialog` (direct, :9660, :10468, :10480, :10482, :10499; through an unmarked helper, :7321); `S19TuiApp._plan_project_save` (direct, :10823); `plan_project_save` (direct, 7 sites :1387 … :1639) — unmarked sites: the Load paths (app.py:11686 … :12944, 8 listed)

classify_active_document
req: LLR-175.4
in: Path project_dir; Path source; str home
out: tuple[str, str?] classified
func: the one document classifier (E3 R11): `in_home` / `outside` / `inside_elsewhere` / `missing`, with the landing name. Unchanged by Inc 11.
module: s19_app/tui/services/project_gather_service.py
examples: (probe p11b U3) save as Q of a document under `P/patches` → `outside` relative to Q, so a predicted row (holds on base)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, :9897; through `gather_project_artifacts`, project_gather_service.py:674); `S19TuiApp._plan_project_save` (direct, :10883); `plan_project_save` (direct, :1661)

inventory_project_tree
req: LLR-175.4, LLR-175.4e, LLR-175.5
in: Path project_dir
out: ProjectInventory inventory
func: one link-free walk of the open project (ceilings 2 000 files / 10 000 entries / depth 32). Writes and hashes nothing; never raises. Name-independent (it walks the open project, whatever the typed name). Unchanged by Inc 11.
module: s19_app/tui/services/project_gather_service.py
examples: (probe p11b U8) 2 000 files in `flows/` + `reports/` → folders `[('flows', 1000), ('reports', 1000)]`, 189.4 ms best of 5 (holds on base)

> callers (extractor): `S19TuiApp._plan_project_save` (direct, :10827)

sanitize_project_name
req: LLR-175.1, LLR-175.1h
in: str name
out: str? cleaned
func: `"".join(ch for ch in name.strip() if ch.isalnum() or ch in "-_")` or `None`. Unicode letters and digits pass (`isalnum`). Unchanged by Inc 11.
module: s19_app/tui/workspace.py
examples: (probe p11b U6) `a b` → `ab`; `!!!` → `None` (holds on base)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, :9487) — unmarked sites: crc_designer_view.py:1227, screens.py:792, flow_persistence_service.py:1019, :1495 (4)

is_windows_device_name
req: LLR-175.1b
in: str name
out: bool device
func: the shared device-name predicate: stem before the first dot, trailing spaces and dots stripped, superscript digits mapped, case-folded. Unchanged by Inc 11.
module: s19_app/tui/workspace.py
examples: (probe p11b U6) `con.txt`, `CON` → refused as a device name (holds on base)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, :9508, :10492); through `variant_execution_service.py:548` for `_plan_project_save`, `_write_and_verify_manifest`, `_save_manifest_keys`, `classify_active_document` (lifted) — unmarked sites: workspace.py:2237 (1)

predict_placement
req: LLR-175.4, LLR-175.4a
in: str | bytes digest_or_bytes; int size; Path destination; str name
out: PlacementResult predicted
func: the placement's own landing rule, without writing: the requested name and its `_<N>` names are the reuse candidates; an identical file is reused (`keep`), else the first free name (`new`). Unchanged by Inc 11 (Q10 changes what the planner passes it, not the function).
module: s19_app/tui/workspace.py
examples: (test_b100_reuse TC-B100-68) the prediction walks the same candidates as `place_into_workarea` (holds on base)

> callers (extractor): `plan_project_save` (direct, :1679)

resolve_input_path
req: LLR-175.2a
in: Path raw_path; Path base_dir
out: Path? resolved
func: an existing candidate as typed, else under the base or repo folder, else `None`. Read by G2 for the payload's parent. Unchanged by Inc 11.
module: s19_app/tui/workspace.py
examples: (probe p11b U1) parent `str(app.workarea)` → the work area (holds on base)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, :9455) — unmarked sites: 7 in app.py (load, A/B compare, report filter) and 6 in other modules

ChangeService.differs_from_last_saved
req: LLR-175.4d
in: dict[int, int]? mem_map
out: bool differs
func: B100-I18: the session image differs from the copy last loaded or saved. Inc 10's question is its first app caller; Inc 11's pending line is the second. Unchanged by Inc 11.
module: s19_app/tui/services/change_service.py
examples: (probe p10b U2, Inc 10 baseline) a patch that writes the bytes already there → `False` (holds on base)

> callers (extractor): none listed on base

ChangeService.image_differs_from_source
req: LLR-175.4c, LLR-175.4d
in: dict[int, int]? mem_map
out: bool differs
func: the journal's fast path: the session image differs from its source. Not the pending-line key (LLR-175.4d's negative control). Unchanged by Inc 11.
module: s19_app/tui/services/change_service.py
examples: (probe p11b U4b) the MAC-only session after `add_entry` (no apply) → `False` (holds on base)

> callers (extractor): `S19TuiApp._decide_project_image` (direct, :10650); `S19TuiApp._handle_save_dialog` (direct, :10443)

PatchEditorPanel.is_dirty
req: LLR-175.4l
in:
out: bool dirty
func: (post-10, from the 10 graph; not yet in code) read-only property over `_dirty` (interfaces-10 S-c). The commit half reads it at `:10576` after Inc 10. Unchanged by Inc 11.
module: s19_app/tui/screens_directionb.py
examples: (proto-10-app C53, post-10) the E3 R1 arm, document in its home, panel dirty → 1 line `Change document <name> has unsaved edits — …` (holds on base through `_dirty`)

> callers (extractor): not run (no code)

## Entities

[Data: S19TuiApp.BINDINGS]
desc: `ctrl+s` (priority, shown) and `s` (hidden) → `save_project`; the other priority keys `ctrl+k` → `focus_palette`, `ctrl+d` → `cycle_density`, `ctrl+l` → `load_file`. A priority binding runs under a modal (P11-2). The palette is built 1:1 from this table.

[Data: SaveProjectPayload]
desc: frozen dataclass `(parent_folder: str, project_name: str, batch: tuple[str, ...] = (), assignments: Mapping = {})` (`screens.py:149`). Built by the dialog and by 11 test files (56 direct handler calls). Unchanged by Inc 11 unless S-c adds an optional field.

[Data: SavePlan]
desc: frozen (`project_gather_service.py:1150`): `target`, `target_kind`, `rows` (tuple of frozen `SavePlanRow(role, source, landing, action)`), `image`, `manifest_keys`, `refusal`, `folders`, `skipped_links`, `copies`, `total_bytes`. Assigning a field raises `FrozenInstanceError`; `rows` is a tuple (LLR-175.4k holds for the type already).

[Data: _ProjectImageStep]
desc: frozen (`app.py:1651`): `emit`, `derived`, `summary`, `payload`, `name`, `carried`, `applied_by_save`, `refusal`.

[I/O: work area]
desc: `<base>/.s19tool/workarea`; the Save target is a direct child; `patches`, `temp` and the other reserved homes live beside the projects.

## Edges

[Outside: key ctrl+s] ──▶ S19TuiApp.action_save_project
when: always, also with a modal on top (priority; post-10 not while `LoadDialog` or `ConfirmQuestionScreen` is on the stack)
[Outside: key s] ──▶ S19TuiApp.action_save_project
when: the main screen has the focus chain (not priority)
S19TuiApp.action_save_project ──▶ SaveProjectScreen.__init__
SaveProjectScreen.on_button_pressed ──▶ S19TuiApp._handle_save_dialog
when: dismiss with a payload or `None` (callback passed to `push_screen`; not seen by the extractor)
S19TuiApp._handle_save_dialog ──▶ [I/O: work area]
