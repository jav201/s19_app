# Code-Wire prototype — Inc 11, group G-B (`s19_app/tui/app.py` + `s19_app/tui/services/project_gather_service.py`)

Stage E2 of the design-first pipeline (`dev-flow-v3-beta`) for Inc 11 ("the Save project dialog"). Graph only: no stub, mark or other change in `s19_app/` of any tree. New functions are nodes whose `func:` starts with "new". Base: main `8947666` plus the 9b graph (`../../inc-9b-design/codewire/proto-9b-app.md`) and the 10 graph (`../../inc-10-design/codewire/proto-10-app.md`). Line numbers are `8947666` lines of `app.py` unless another file is named. `check_action` and the `is_dirty` read in the Save commit start from the 10 graph.

Inputs: `../E1-requirements-draft.md`, `../E1-scope.md`, `../E1-rulings.md` (Q1–Q11), `../E2-rulings.md` (LLR-175.1n withdrawn; 56 + 1 direct calls; re-pins), `baseline-11.md` (G0–G18, C1–C5, the 12 crossing locals), `baseline-notes.md`, `interfaces-11.md` (FIXED; changes I need are in "Proposals to the orchestrator"). Two small probes ran on the throwaway copy `../work/tree` and on the checkout read-only (`PYTHONDONTWRITEBYTECODE=1`, `python -I`; `git status` of the checkout unchanged afterwards):
- `../work/gb/probe-gb-plans.py` → `probe-gb-plans.out.txt` (S1–S7) and `probe-gb-plans2.py` → `probe-gb-plans2.out.txt` (S8 `files`, S9 AT-B100-09 tree): the base plans of the scenarios (rows, kinds, image text, totals).
- `../work/gb/probe-gb-q10.py` → `probe-gb-q10.out.txt`: the Q10 prediction primitives.

Conventions:
- `W` = this work area (`<base>/.s19tool/workarea`). `pn(x)` = `painted_names([x])` (the batch's one scrub: Cc, Cf, Zl, Zp removed, an unpaired surrogate → U+FFFD, clipped to 120 characters ending in `…`).
- `PS(…)` is a `_PreparedSave`; `SP(where, rows, plan, refused)` is a `SavePreview`; a where line written `[i] x` is `("x", "info")`, `[r] x` is `("x", "refusal")`.
- "NS: " stands for the status prefix `Project NOT saved: `. Every refusal string below is quoted with the prefix spelled out where it is the status line, and without it where it is the dialog's where line.
- Fixtures are E1's (F-fresh, F-open, F-merge, F-saveas, F-pending, F-document, F-case06). case_01 sizes: `firmware.s19` 358 bytes, `firmware.mac` 33, `firmware.a2l` 1 444.
- "Session digest" is the E1 tuple. "Work-area listing" is the sorted set of every path under `W`.
- Every example states the Inc 11 target unless it says "holds on base".

## Owned nodes (15) and context

- **7 new (app.py):** `_prepare_project_save`, `_commit_project_save`, `_save_session_inputs`, `_current_save_session`, `_save_dialog_preview`, `_compose_save_preview`, `_confirm_project_save`.
- **5 changed (app.py):** `__init__` (3 attribute lines), `action_save_project`, `check_action` (post-10), `_handle_save_dialog` (router), `_plan_project_save`.
- **1 data node (app.py):** `_SaveSession`, `_PreparedSave` (the fixed S-c / S-d types) and the module constants `_SAVE_KIND_WORDS`, `_SAVE_ROW_LABELS`, `_SAVE_SUMMARY_CHANGED`, `_SAVE_REFUSAL_PREFIX`, `_UNSET`.
- **1 changed (project_gather_service.py, ruling Q10):** `plan_project_save` (changed: the document arm only). `_predict_in_copy` is dropped (A11-03 / S11-09); `_copy_project_subfolders` keeps its base body.
- **Unchanged, decision recorded:** `_plan_copies`. The document arm needs no new fact from it: the copied occupants are `copies` itself, which `plan_project_save` already holds.
- **Retired:** none. G4–G18 move out of `_handle_save_dialog` into `_prepare_project_save`, and C1–C5 into `_commit_project_save`; the method keeps its name and its one parameter.
- **Context (unchanged, with new or moved callers):** `_decide_project_image` (now called by `_save_session_inputs` only), `_save_as_source_for` (1 call per preparation, R2-2 closed), `_project_folder_refusal`, `_manifest_carry`, `_manifest_is_link`, `_derived_record` (now called by `_save_session_inputs` once per open, A11-01), `_file_digest`, `_abort_save`, `_write_editor_document`, `_write_and_verify_manifest`, `_unrecorded_document_lines`, `_plan_row_mismatch`, `_plan_without_document_key`, `_save_clears_panel_flag`, `painted_names`, `classify_active_document`, `inventory_project_tree`, `predict_placement`, `build_variant_set`, `manifest_keep_reason` (A11-05), `os.path.samefile` (S11-01), `ChangeService.differs_from_last_saved`, `PatchEditorPanel.is_dirty` (post-10).

**Imports.**
- `app.py`: `SavePreview` joins the `.screens` import (G-A exports it). `ProjectInventory` joins the `project_gather_service` import (typing of the P-1 field). Already imported: `SaveProjectScreen`, `LoadDialog` (9b), `ConfirmQuestionScreen` (10), `painted_names`, `build_variant_set`, `validate_project_files`, `manifest_is_damaged`, `PROJECT_PRIMARY_DATA_EXTENSIONS`, `replace` (`dataclasses`, :4). New uses, already in the module's set: `os.path.samefile` (S11-01) and `manifest_keep_reason` (A11-05).
- `project_gather_service.py`: `_match_identical` joins the `..workspace` import, beside the private names it already imports (`_find_workarea_root`, `_guarded_destination`, `_is_reparse_point`, `_path_traverses_reparse_point`). The document arm's digest goes through `_workspace._match_identical`, so `test_tc_b100_57_export_holds_no_byte_identity_rule` is re-pinned to also catch `Attribute` calls of `_hash_file` (A11-03).

## Nodes

S19TuiApp.__init__
req: LLR-175.5, LLR-175.4a
in: (unchanged)
out: None
func: changed: three attribute lines beside `self._variant_set` (:2323): `self._save_session: Optional[_SaveSession] = None` (ruling Q-1), `self._save_confirmed: Optional[_PreparedSave] = None` (proposal P-3) and `self._save_painted_preview: Optional[SavePreview] = None` (A11-08: the last preview the dialog painted). Nothing else.
callers: Textual app construction (unchanged).
module: s19_app/tui/app.py
examples: B11-01 (census H re-pin) `tests/test_b100_session_reset.py::test_tc_b100_09_domain_matches_the_live_source_census` turns RED with `unclassified census names: ['_save_confirmed', '_save_session', '_save_painted_preview']` until all three join `SNAPSHOT_EXCLUSIONS` with the reason "per-open Save dialog state; dropped when the Save router runs". After the re-pin: `0` unclassified. Negative control: the re-pin omitted → RED (holds as a census guard).

S19TuiApp.action_save_project
req: HLR-175f, LLR-175.3j, LLR-175.3h, LLR-175.5, LLR-175.5b
in:
out: None
func: changed (:7337). Steps:
- (1) Nothing loaded (`not self.current_file and not self.current_a2l_path`) → `self.logger.info("Save project action triggered with no loaded files.")`, `self.set_status("Nothing to save: load a data file or A2L first.")`, return. No push (ruling Q9). The text is G1's, character for character.
- (2) The two existing log lines (data file / A2L only), unchanged.
- (3) `variants` / `candidate_files` exactly as today (ruling Q4).
- (4) `self._save_session = None`; `self._save_confirmed = None`; `self._save_painted_preview = None`. A fresh open never sees a leftover (a test that captured the dismiss callback, `_capture_save_payload`, leaves them set).
- (5) `self.push_screen(SaveProjectScreen(preview=lambda name: self._save_dialog_preview(name, self._current_save_session()), confirm=self._confirm_project_save, initial_name=self.current_project, variants=variants, candidate_files=candidate_files), self._handle_save_dialog)`. The callback is read as an attribute at push time, as today. The lambda evaluates `self._current_save_session()` on every call, so the first `preview` call creates the session even for blank text.
- It computes nothing about the save itself: `0` calls of `_decide_project_image`, `_save_session_inputs`, `_file_digest` or `_prepare_project_save` in its body (LLR-175.5b; the dialog's first `preview` runs after the first refresh, S-d).
callers: `ctrl+s` (priority) and `s` (`BINDINGS`); palette entry `save_project` (dispatch by name; extractor: none listed). Under the post-11 `check_action` it no longer runs while a Save dialog, a Load dialog or the question is on the stack.
module: s19_app/tui/app.py
examples: B11-02 (LLR-175.3j) a fresh app, nothing loaded: `ctrl+s` → screen stack depth `1`, `1` new status line `Nothing to save: load a data file or A2L first.` (holds both tokens `Nothing to save` and `load a data file or A2L first`), `0` new paths. The palette entry `save_project` → the same (`2` of `2`). Negative control: executed on the 9a tree (P11-2): `open ctrl+s -> stack: ['Screen', 'SaveProjectScreen']` → RED.
examples: B11-03 (LLR-175.3j boundary) only `firmware.a2l` loaded → `ctrl+s` → depth `2`, top `SaveProjectScreen`. Negative control: a guard reading `self.current_file` alone → `0` dialogs → RED.
examples: B11-04 (HLR-175f, S-b) F-fresh, `ctrl+s` → the pushed screen got `initial_name=None`, `variants=[]`, `candidate_files=[]`; `screen.variants == []` and `screen.candidate_files == []` stay readable as attributes (tc304 / tc305). The callback passed to `push_screen` is the value of `app._handle_save_dialog` at push time: with `app._handle_save_dialog` replaced by a one-argument lambda before `ctrl+s`, a confirmed Save calls that lambda once with the payload (`_capture_save_payload` keeps working). Result `2` of `2`.
examples: B11-05 (LLR-175.3h, app half) F-open with `current_project == "P"` → `initial_name == "P"`. F-open where `P` was loaded by typing `<W>/p` on Windows → `current_project == "P"` (9a R3 stores the on-disk spelling) → `initial_name == "P"` (`2` of `2`). Negative control (code read, base): no `initial_name` → the field starts empty → RED. Prefilling and selecting the text is G-A's (S-b).
examples: B11-06 (LLR-175.5b, AST) the body of `action_save_project` holds `0` calls of `_decide_project_image`, `_save_session_inputs`, `_prepare_project_save` and `_file_digest`; the session exists after the push only once `preview` was called (`app._save_session is None` right after `push_screen` returns). Negative control: a mutation that calls `self._save_session_inputs()` before `push_screen` → the TC-B100-65 spy sees `app.screen` as the main screen at the first `_decide_project_image` call → RED.

S19TuiApp.check_action
req: LLR-175.3g
in: str action, tuple parameters
out: Optional[bool]
func: changed (post-10, :8034). The first test becomes `if action in _LOAD_DIALOG_INERT_ACTIONS and any(isinstance(s, (LoadDialog, ConfirmQuestionScreen, SaveProjectScreen)) for s in self.screen_stack): return False`. The action set (`load_file`, `save_project`, `focus_palette`, `cycle_density`) is 9b's, unchanged. Whole-stack test, not stack-top (ruling "Guard", 9b S9b-1, 10 C46). Then the window gates and `super().check_action`, unchanged. Docstring: the summary names the Save dialog beside the Load dialog and the question.
callers: Textual `App.run_action` (every binding and palette dispatch); `window_help.py:1134`, `:1145` (key bar; unmarked sites, baseline). Unchanged set.
module: s19_app/tui/app.py
examples: B11-07 (LLR-175.3g) F-fresh, `ctrl+s` opens the dialog. Then, with the dialog open: `ctrl+l` → depth `2`, `0` `LoadDialog`; `ctrl+s` → depth `2`, `0` second `SaveProjectScreen`; `ctrl+k` → the palette stays closed, the focus inside the dialog; `ctrl+d` → `#workspace_body` density classes unchanged. Result `4` of `4`. Negative control: executed on the 9a tree (P11-2, P11-3): `ctrl+l over Save dialog -> stack: ['Screen', 'SaveProjectScreen', 'LoadFileScreen']`, `ctrl+s over Save dialog -> stack: ['Screen', 'SaveProjectScreen', 'SaveProjectScreen']`, `ctrl+d over Save: density classes ['density-comfortable'] -> ['density-compact']` → RED. With the post-10 tuple alone (`LoadDialog`, `ConfirmQuestionScreen`), `ctrl+l` pushes a `LoadDialog` over Save → RED.
examples: B11-08 (whole stack) Save dialog open, `ctrl+p` (Textual's command palette over it), then `ctrl+s` → `0` Save pushes; `ctrl+l` → `0` `LoadDialog` (`2` of `2`). Negative control: `isinstance(self.screen, …)` → the palette is on top → `ctrl+s` pushes a second Save dialog → RED.
examples: B11-09 (no over-reach) dialog closed by `escape` → `ctrl+d` cycles the density `1` time; `ctrl+s` opens `1` dialog (`2` of `2`).
examples: B11-10 (declared, as 9b F-4) focus in `#project_name` holding `abc` with the cursor at 0: `ctrl+d` → `check_action` false → the `Input`'s own `delete,ctrl+d` binding → the field holds `bc`; the preview recomputes for `bc`. No app action runs, so LLR-175.3g holds (its threshold declares the field edit).

S19TuiApp._handle_save_dialog
req: HLR-175a, LLR-175.3c, LLR-175.4a, LLR-175.4l, LLR-175.2a, LLR-175.6
in: Optional[SaveProjectPayload] payload
out: None
func: changed (:9447): the one-argument router (S-c). Steps:
- (0) `session, confirmed = self._save_session, self._save_confirmed`; `self._save_session = None`; `self._save_confirmed = None`; `self._save_painted_preview = None`. The per-open state is dropped on every route out, including `None` (S-d).
- (1) G0 `payload is None` → `self.logger.info("Save project canceled.")`, return.
- (2) G1 nothing loaded → `set_status("Nothing to save: load a data file or A2L first.")`, `logger.info("Save project dismissed: no loaded file or A2L.")`, return.
- (3) G2 `resolve_input_path(Path(payload.parent_folder), self.base_dir)` not a folder → `Parent folder not found or not a directory.`; G3 real path ≠ the work area's → `Project NOT saved: {parent_resolved} is not the work area folder — choose the work area as the parent folder ({self.workarea}).` Both texts and their logs unchanged.
- (4) `prepared = confirmed` when `confirmed is not None and payload.plan is not None and confirmed.plan is payload.plan and confirmed.typed_name == payload.project_name` (ruling Q-2, identity). Otherwise `prepared = self._prepare_project_save(payload.project_name, session)` (the preparation computes the session lazily after the name rules when `session` is `None`, A11-09).
- (5) `prepared.refusal is not None` → `self.set_status(prepared.refusal)`; when `prepared.toast`: `self.notify(prepared.refusal, title="Project not saved", severity="error", timeout=10.0, markup=False)`; `self.logger.warning("Save project refused: %s", prepared.refusal)`; return.
- (6) `self._commit_project_save(prepared, payload)`.
- A refusal the dialog painted never reaches step 5: `confirm` returns `None` only for a prepared save with no refusal, so the dialog path raises no toast (ruling Q-6) by construction.
callers: `action_save_project` (dismiss callback, read at push time; extractor: none, a value). Tests: 56 direct call lines in 11 files plus 1 call by reference (`test_b100_save_image.py:880`), and `test_tui_manifest_save._capture_save_payload` replaces the attribute with a one-argument lambda.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._save_session] (cleared), [Data: S19TuiApp._save_confirmed] (cleared), [Data: S19TuiApp._save_painted_preview] (cleared)
examples: B11-11 (LLR-175.4l) twin fixtures, F-fresh each: on one, `ctrl+s`, type `fresh1`, wait for the summary, `alt+s`; on the other, `app._handle_save_dialog(SaveProjectPayload(str(app.workarea), "fresh1"))`. Both trees under `W/fresh1` are `['firmware.s19', 'project.json']` with equal file digests, and the session digests are equal (`1` of `1`). Negative control: a mutation where the router commits only `confirmed` (a direct payload has `plan None`) → the direct arm refuses or does nothing → RED.
examples: B11-12 (LLR-175.4l census) the 56 direct call lines and the call by reference pass unchanged against the gate baseline (`0` new failures). Their status texts are unchanged except by the scrub of G6 / G10 / G11 / G16 names through `painted_names`, which removes Cc, Cf, Zl and Zp, maps an unpaired surrogate to U+FFFD and clips at 120 characters ending in `…` (A11-15; none of the 57 sites types one). The by-reference call (`app.call_next(app._handle_save_dialog, payload)`) runs the router with `session None` → `_prepare_project_save` computes `_save_session_inputs()` after the name rules (A11-09), so `test_f2_unreadable_source_*`'s `open` patch, active only during that call, still reaches `_file_digest` (B11-31).
examples: B11-13 (LLR-175.4a, identity) F-fresh, `fresh1` painted, `alt+s`: G-A sets `payload.plan = screen.plan`; the router takes step (4)'s first arm, so the spy on `_commit_project_save` receives `prepared.plan is screen.plan` (`True`) and `prepared.plan == screen.plan` (`1` of `1`). Negative control: a router that always re-prepares → `prepared.plan is screen.plan` is `False` → RED.
examples: B11-14 (stale confirmed save) `_save_confirmed` holds a prepared save for `abc` with plan object `X`; a payload with `project_name "abc"` and `plan Y` (`Y == X`, `Y is not X`) → step (4) re-prepares (`1` call of `_prepare_project_save`). A payload with `plan X` and `project_name "abd"` → re-prepares. Result `2` of `2`. Negative control: matching on equality instead of identity → the first arm commits the stale object → the spy sees `0` preparations → RED.
examples: B11-15 (S-d) `escape` in the dialog → the router receives `None` → `app._save_session is None` and `app._save_confirmed is None` afterwards, `0` status lines, the work-area listing unchanged. A confirmed save → both `None` after the router returns. A refused direct payload → both `None`. A save-as direct payload that fills the lazy inventory → `app._save_session is None` afterwards (S11-10: the fill writes `self._save_session` only when `session is self._save_session`, and the router cleared it at step 0). Result `4` of `4`. Negative control: the fill writing `self._save_session = session` unconditionally → the next direct save reads the stale session → RED.
examples: B11-89 (S11-10, R2-02) save as `Q` by a direct payload (which fills the lazy inventory), then an applied patch, then a direct save of `R` → the save plans from a fresh session (`_save_session_inputs` runs again and `_decide_project_image` sees the patch) and `R` holds the patched image (`1` of `1`). Negative control: the fill writes `self._save_session` even though the router cleared it → `R` is planned from the stale pre-patch session and the patched image is not written → RED.
examples: B11-16 (LLR-175.2a, router half) base path of 150 characters, F-fresh, a save through the dialog → `Path(payload.parent_folder) == app.workarea` (G-A) and `W/fresh1` exists with parent `app.workarea` (`2` of `2`). Negative control: a payload whose parent is `app.base_dir` → `1` status line `Project NOT saved: <base> is not the work area folder — choose the work area as the parent folder (<W>).`, `0` new paths → RED for that mutation (LLR-171.3 holds).
examples: B11-17 (Q-6, direct path) F-fresh with `firmware.s19` deleted, direct payload `x` → `1` status line `Project NOT saved: source file missing: firmware.s19 — reload it or remove it from the project.` and `1` toast with title `Project not saved` (`prepared.toast`). Through the dialog the same session paints the line in `#save_where` and `alt+s` keeps the dialog open: `0` toasts, `0` dismisses (`2` of `2`).
examples: B11-18 (G1, direct) nothing loaded, direct payload `n` → `['Nothing to save: load a data file or A2L first.']`, no folder (holds on base, probe p11b U5).

S19TuiApp._prepare_project_save
req: LLR-175.6, LLR-175.1a, LLR-175.1b, LLR-175.1c, LLR-175.1d, LLR-175.1e, LLR-175.1f, LLR-175.1g, LLR-175.1h, LLR-175.1i, LLR-175.1j, LLR-175.1k, LLR-175.1l, LLR-175.1m, LLR-175.1, HLR-175b, LLR-175.4g
in: str name; Optional[_SaveSession] session = None
out: _PreparedSave prepared
func: new: G4–G18 of the base `_handle_save_dialog` (`:9476`–`:9855`), in the same order, writing no file and no `self.` attribute except the one declared lazy-inventory fill (S11-06). It logs the moved G15 `logger.warning` calls (the dropped / unreadable recorded document) on each recompute; the router logs a refusal once, and the `_derived_record` warning fires once per open in `_save_session_inputs` (A11-01). Every refusal returns `PS(refusal=<status text>, toast=…, plan=…)` through one local `_refused(text, toast=False, plan=None)` that fills the fields not yet known with neutral values (`cleaned` so far or `""`, `project_dir = self.workarea / cleaned` or `self.workarea`, `save_as_source None`, `source_gone None`, `image_step = session.image_step`, `existing None`, `target_carry {}`, `carried_derived {}`, the rest `None`); only `refusal` and `toast` are read on a refused save (router step 5, `_compose_save_preview`). Steps:
- (G4) `typed_name = name`; `not typed_name.strip()` → `NS name is empty — type a project name.`
- (G5) `cleaned = sanitize_project_name(typed_name)`; falsy → the same text.
- (G6) raw name, each `\` / `/` component, or `cleaned` a device name (`is_windows_device_name`) → `f"Project NOT saved: '{pn(typed_name)}' is a device name — choose another name."` (scrubbed, S-a).
- (G7) `cleaned.casefold()` in the case-folded `RESERVED_WORKAREA_HOMES` → `f"Project NOT saved: '{cleaned}' is a reserved name — choose another name."` (`cleaned` holds only letters, digits, `-`, `_`).
- (G8) `len(cleaned) > PROJECT_NAME_MAX_CHARS` → `NS name too long (at most 64 characters) — shorten the name.`
- (G9) `len(str(self.workarea)) + 1 + len(cleaned) + _SAVE_REPORT_SUFFIX_CHARS > _SAVE_FULL_PATH_LIMIT` → `NS path too long — shorten the name.`
- (G10) the clash loop over the sorted work-area listing, with the `try` around the whole `sorted(...)` (S11-03): `try: entries = sorted(self.workarea.iterdir()) except OSError` → `NS the work area could not be read — check that the folder can be opened, then save again.` (finding F-1, P-5, LLR-175.1o). Per `item` in `entries` (name compare first; reserved, reparse point, `OSError` → skip): the open project is decided by file identity — `os.path.samefile(item, self.current_project_dir)` when a project is open, with `OSError` meaning "not the same" — and only then `cleaned = item.name` (LED .52(a)); any other case-folded match (`typed_name != item.name`) → `f"Project NOT saved: '{pn(typed_name)}' is already a project as '{pn(item.name)}' — choose another name."` (S11-01: a case-folded folder that is not the open project is a disguised clash, LLR-175.1p).
- (after G10) `if session is None: session = self._save_session_inputs()` — on the direct path the name rules run before the session is computed (A11-09).
- (G11) `session.refusal is not None` → `_refused(session.refusal, toast=True)`. One check, at G11's place, for every session refusal (missing source, unreadable source, blocked entries); see finding F-2 for the order this moves.
- (G12) `project_dir = self.workarea / cleaned` (unresolved, SEC-1).
- (G13) `target_reason = self._project_folder_refusal(project_dir)`: `link` → `f"Project NOT saved: '{cleaned}' is a link or junction — choose another name."`; `unreadable` → `safe_text(f"Project NOT saved: '{pn(cleaned)}' could not be read — check that the folder can be opened, then save again.").plain`; other → the not-the-work-area text naming `project_dir.parent` and `self.workarea`.
- (G14) `save_as_source = self._save_as_source_for(project_dir)` — the one evaluation per preparation (R2-2 closed); `source_gone` and `source_reason` exactly as the base computes them.
- (G15) `try:` `image_step = session.image_step`; `existing = read_project_manifest(project_dir)`; the carry source, `target_carry`, `carried_derived`, `carried_active_document` and `carried_document_line` exactly as `:9715`–`:9782`; `emitted_record = session.emitted_record` (A11-01: computed once per open, not re-parsed per recompute). The lazy inventory (S11-06): when `save_as_source is not None`, `session.inventory is None`, `self.current_project_dir is not None` and `self._project_folder_refusal(self.current_project_dir) is None` → `inv = inventory_project_tree(self.current_project_dir)`; `session = dataclasses.replace(session, inventory=inv)`; `if session is self._save_session: self._save_session = session` (the one self write, and only when the session being prepared is the dialog's own live session — after the router cleared `_save_session` at step 0, a direct payload's local session is not `self._save_session`, so nothing leaks, S11-10 / R2-02). Then `plan = self._plan_project_save(project_dir, cleaned, image_step, derived=bool(carried_derived) or emitted_record is not None, carried_active_document=carried_active_document, source_reason=source_reason, save_as_source=save_as_source, digests=session.digests, inventory=session.inventory, payload_sha256=session.payload_sha256)`.
- (G16) `except OSError as exc` → `_refused(_unreadable_text(exc), toast=True)` with the session's text (below): a target manifest, a carried document or the exempt check that cannot be read.
- (G17) `plan.refusal is not None` → `_refused(plan.refusal, toast=True, plan=plan)` (the refused plan: 0 rows).
- (G18) `plan.target_kind == PLAN_TARGET_NEW`: `shutil.disk_usage(self.workarea).free`; `OSError` → `_refused("Project NOT saved: could not save — the free space of the work area could not be read — check the folder.")` (A11-02: `plan=None`); `plan.total_bytes > free` → `_refused(f"Project NOT saved: not enough free space (needs {plan.total_bytes} bytes, {free} free) — free disk space or remove files from the project.", toast=True)` (A11-02: `plan=None`).
- (P-4, inside the G15 `try`, A11-14 / S11-07) when `plan.target_kind == PLAN_TARGET_MERGE`: `data_files, _a2l, _err = validate_project_files(project_dir)`; `_err` set → `_refused(f"Project NOT saved: {_err}", toast=True, plan=plan)` (A11-07: the commit's "more than one MAC / A2L" refusal raised in the preparation; the C3 check stays as defence). Else, when the image row's landing suffix is in `PROJECT_PRIMARY_DATA_EXTENSIONS`: `names = {p.name: p for p in data_files}` plus the landing; `vset = build_variant_set(cleaned, list(names.values()))`; `active_variant = next((v.variant_id for v in vset.variants if v.path.name == landing.name), None)`. Otherwise `None`. This is the rule the commit follows (`:10109`–`:10120`: rebuild, then the filename match).
- (end) `PS(typed_name, cleaned, project_dir, save_as_source, source_gone, image_step, existing, target_carry, carried_derived, carried_active_document, carried_document_line, emitted_record, plan, refusal=None, toast=False[, active_variant])`.
- `_unreadable_text(exc)` (a module-level helper shared with `_save_session_inputs`; one text, two callers): `name = pn(Path(exc.filename).name) if exc.filename else "a source file"` → `f"Project NOT saved: {name} could not be read: {exc.strerror or exc} — check that the file can be opened, then save again. Nothing written."` (ruling Q11: the next step appended; `<name> could not be read` and `Nothing written.` stay, so `test_b100_save_image.py:932`, `:971` and the 7 `test_b99_staging` substring checks hold).
callers: `_handle_save_dialog` (router step 4), `_compose_save_preview` through `_save_dialog_preview`, `_confirm_project_save`. No other caller (LLR-175.6).
module: s19_app/tui/app.py
examples: B11-19 (LLR-175.1h; HLR-175d, preparation half) with `firmware.s19` loaded and `ab` saved: `''`, `'   '`, `'!!!'`, `'..'`, `'/'` → refusal `NS name is empty — type a project name.` each, `toast False`, `plan None` (`5` of `5`). Holds on base for `''`, `'   '`, `'!!!'` (probe p11b U6). Negative control: a preparation that returns no refusal for a blank name (leaving it to the dialog) → `confirm("")` returns `None` → the dialog dismisses → RED (Q-3 ruling).
examples: B11-20 (LLR-175.1b) `nul`, `CON`, `com1`, `LPT¹`, `con.txt`, `C O N` → refusals `NS 'nul' is a device name — choose another name.`, `NS 'CON' is a device name — choose another name.`, `NS 'com1' …`, `NS 'LPT¹' …`, `NS 'con.txt' …`, `NS 'C O N' …` (`6` of `6`; `C O N` is caught on its sanitised form `CON`). Negative control: only the sanitised form checked → `con.txt` (sanitised `contxt`) → no refusal → RED.
examples: B11-21 (LLR-175.1a) `reports`, `CRC`, `Splits`, `FLOWS`, `Temp` → `NS 'reports' is a reserved name — choose another name.`, `NS 'CRC' …`, `NS 'Splits' …`, `NS 'FLOWS' …`, `NS 'Temp' …` (`5` of `5`). Negative control: the comparison without `casefold` → `CRC` passes → RED.
examples: B11-22 (LLR-175.1d) 64 × `a` → no name refusal; 65 × `a` and 300 × `a` → `NS name too long (at most 64 characters) — shorten the name.` each (`3` of `3`). Negative control: the cap read as 65 → the 65 arm passes → RED.
examples: B11-23 (LLR-175.1e) a base folder whose work area text is `L0` characters long, and `L = 259 − 53 − 1 − L0`: an `L`-character name → no refusal; `L + 1` → `NS path too long — shorten the name.` (`2` of `2`). Negative control: `_SAVE_REPORT_SUFFIX_CHARS` dropped from the sum → the `L + 1` arm passes → RED.
examples: B11-24 (LLR-175.1c) F-merge with project `P2` open and `ab` saved: `a b` → `NS 'a b' is already a project as 'ab' — choose another name.`; `AB` → `NS 'AB' is already a project as 'ab' — choose another name.`; `ab` → no refusal, `plan.target_kind == "merge"` (`3` of `3`). Holds on base for the two refusal texts (probe p11b U6). Negative control: a clash compare without `casefold` → `AB` plans a new folder → RED.
examples: B11-25 (LLR-175.4g, refusal scrub) a project folder `[b]P` saved; typed `[b] P` → `NS '[b] P' is already a project as '[b]P' — choose another name.` (brackets kept, plain text). Typed `con` + U+202E + `.txt` → `NS 'con.txt' is a device name — choose another name.` (U+202E removed by `pn`). Result `2` of `2`. Negative control: the base text (`'{typed_name}'`, unscrubbed) → U+202E reaches `#save_where` → RED.
examples: B11-26 (LLR-175.1, LED .52(a)) F-open with `Ab` on disk and open (`current_project == "Ab"`): typed `ab` → `prepared.cleaned == "Ab"`, `project_dir == W / "Ab"`, `plan.target_kind == "open project"`, `refusal None`. Typed `Ab ` → `cleaned == "Ab"`, the same kind (`2` of `2`). Negative control: the rebind dropped → `cleaned == "ab"` and, on Windows, `plan.target_kind == "open project"` with `project_dir` spelled `ab` → the where line reads `ab` → RED at B11-45.
examples: B11-27 (LLR-175.1f, Windows only) `W/jt` a directory junction to `<tmp>/x` (made with `_winapi.CreateJunction`); typed `jt` → `NS 'jt' is a link or junction — choose another name.`, `0` files under `<tmp>/x` after `alt+s` (`1` of `1`). Not run where no junction can be made. Negative control: the link check removed → `plan.target_kind == "merge"` → RED.
examples: B11-28 (LLR-175.1g) `os.lstat` raising `PermissionError` for `W/P` (TC-B100-62 fixture pattern), typed `P` → `NS 'P' could not be read — check that the folder can be opened, then save again.` (`1` of `1`; holds on base through the handler). Negative control: `unreadable` mapped to no refusal → a kind is painted → RED.
examples: B11-29 (LLR-175.1i) target `m2` holding `other.mac` and a `project.json`, session S19 + `firmware.mac` → `NS 'm2' already has a MAC file (other.mac) — choose another name.`, `plan` is the refused plan (`rows == ()`); target `a2` holding `x.a2l`, session with `firmware.a2l` → `NS 'a2' already has an A2L file (x.a2l) — choose another name.`; save as of a project holding 2 001 copyable files (`SAVE_AS_FILE_CEILING` lowered to 2 000) → `NS 'P' has too many files to copy (over 2 000) — move files out of the project, then save again.` Result `3` of `3`, `toast True` each. The MAC text holds on base (probe gb-plans S6). Negative control: the plan refusal ignored and the plan's empty rows painted → `0` token pairs → RED at B11-48.
examples: B11-30 (LLR-175.1j) F-fresh, `fresh1`: the plan's `total_bytes` is `69632` (4 096 for the image, rounded, plus the 65 536 margin; probe gb-plans S1). `shutil.disk_usage` stubbed (TC only) to `free = 69631` → `NS not enough free space (needs 69632 bytes, 69631 free) — free disk space or remove files from the project.`, `toast True`; `free = 69632` → no refusal (`2` of `2`). Negative control: G18 left in the router only → the preview shows `fresh1 — new folder` and `alt+s` dismisses before the refusal → RED.
examples: B11-31 (LLR-175.1k / .1l / .1m through G11) the session's refusal is returned at G11's place, after the name rules: F-fresh with the work copy deleted, typed `ok` → `NS source file missing: firmware.s19 — reload it or remove it from the project.`; typed `CON` → the device refusal first (name rules precede G11, as on base). Result `2` of `2`.
examples: B11-32 (LLR-175.6, AST) `sanitize_project_name`, `is_windows_device_name` (name use), the `RESERVED_WORKAREA_HOMES` comparison, `PROJECT_NAME_MAX_CHARS`, `_project_folder_refusal(project_dir)` and `_plan_project_save` are called on the Save path only inside `_prepare_project_save` (`0` other sites). Declared exemptions: `is_windows_device_name` in the commit's unrecorded-file line (`:10492`, a gathered relative path, not the typed name) and `_project_folder_refusal(self.current_project_dir)` in `_save_session_inputs` (the source check that guards the session's walk, P-1). Negative control: the dialog side keeps its own copy of the reserved rule without `casefold` → census `1` extra site → RED.
examples: B11-33 (LLR-175.6, equality) 16 names, each with its fixture: the 15 refusal arms (9 name refusals — reserved, device, disguised clash, over 64, path too long, link target, unreadable target, no usable character, the case-folded-not-open-project arm — then plan refusal, free space, missing source, unreadable source, blocked entries, the work-area-unreadable arm of F-1), and `fresh1`: the dialog's where line equals the direct call's status line with `Project NOT saved: ` removed, character for character (`16` of `16`), and `fresh1` saves on both sides. Negative control: as B11-32's mutant → `Reports` paints nothing in the dialog while the direct call refuses → RED.
examples: B11-34 (F-1, work area unreadable; P-5 / LLR-175.1o; S11-03) `os.listdir` (the `Path.iterdir` listing) raising `PermissionError` for `W` only → `NS the work area could not be read — check that the folder can be opened, then save again.`, `0` raises from `preview()`, the app running (`1` of `1`). The TC stubs `os.listdir`, not `Path.iterdir` (S11-03: the `try` wraps `sorted(self.workarea.iterdir())`). Negative control: the catch removed → the `PermissionError` leaves `preview()` inside the dialog's timer → the app stops (`exit_on_error`) → RED.
examples: B11-35 (traces to LLR-171.3, the handler's work-area check; A11-15) the G13 `outside` arm is unreachable after G2/G3 and the sanitiser (E1-scope §5); the arm stays as defence with the base text. Its requirement is LLR-171.3 (the target must be a direct folder of the work area), not a dialog requirement.
examples: B11-82 (LLR-175.1p, S11-01; Windows arm) `strasse` open (`current_project_dir == W/"strasse"`) with `straße` present (an imported project). Typed `strasse` → the loop sees `straße` as a case-folded match that is not the open project (`os.path.samefile` false) → `NS 'strasse' is already a project as 'straße' — choose another name.`, `alt+s` keeps the dialog open, `0` files written, `straße/project.json` unchanged (`1` of `1`). Typed `straße` (its exact name) → `merges into an existing project`. Negative control: the open-project test kept on case-folding → `straße` is taken as the open project and the files land in `straße` → RED.
examples: B11-84 (A11-07, P-4) target `m2` holds two MAC files (`other.mac`, `third.mac`) and a `project.json`; the session is S19-only (no MAC role) → the plan's second-file rule does not fire, but P-4's `validate_project_files` returns `_err` → `NS Project already has more than one MAC file.`, `toast True`, `plan` is the (otherwise valid) plan (`1` of `1`). Negative control: the `_err` discarded (base) → the dialog paints `merges into an existing project`, then the commit refuses after the dialog closed → RED.

S19TuiApp._save_session_inputs
req: LLR-175.5, LLR-175.5b, LLR-175.1k, LLR-175.1l, LLR-175.1m
in:
out: _SaveSession session
func: new: what does not depend on the typed name, computed once per open (S-d, ruling Q-4). Opening and cancelling the dialog writes no file and no project state (A11-09). The re-derive refreshes `document.issues` (change_service.py, outside the cap) — a recomputation of derived state, not a user-visible write (R2-04). Steps:
- (1)–(2) merged into one `try` (S11-02): `try:` the missing-source test `missing = [p for p in (self.current_file.path if self.current_file else None, self.current_file.mac_path if self.current_file else None, self.current_a2l_path) if p is not None and not p.exists()]` (G11's test) — non-empty → `_SaveSession(_ProjectImageStep(emit=False), {}, f"Project NOT saved: source file missing: {pn(missing[0].name)} — reload it or remove it from the project.")` and return; `image_step = self._decide_project_image() if self.current_file else _ProjectImageStep(emit=False)`; `digests = {}`; when `self.current_file` and not `image_step.emit` → `digests[path] = _file_digest(path)`; MAC (`mac_path` set and `!= path`) → `_file_digest`; A2L → `_file_digest`. `except OSError as exc` → `_SaveSession(_ProjectImageStep(emit=False), {}, _unreadable_text(exc))` and return (a `PermissionError` from `Path.exists()` is now caught here, S11-02).
- (3) `emitted_record` (A11-01): when `image_step.emit` → `_derived_record(self.current_file.path, image_step.derived)`, else `None` — computed once per open, so a 4 MiB emitting image is parsed and hashed once, not on every recompute.
- (4) `payload_sha256` (S11-06): when `image_step.emit` → `hashlib.sha256(image_step.payload).hexdigest()`, else `None` — once per image generation.
- (5) `inventory` stays `None` here (S11-06: filled lazily at the first new-target preparation in `_prepare_project_save`).
- (6) `_SaveSession(image_step, digests, image_step.refusal, emitted_record=emitted_record, payload_sha256=payload_sha256)` with `inventory=None`. The file-backed document digest is NOT computed here (S11-05: recomputed in each preparation; the document is ≤ 1 MiB).
callers: `_current_save_session` (the dialog's first `preview` or `confirm` call); `_handle_save_dialog` step 4 (a direct payload, with no dialog session).
module: s19_app/tui/app.py
examples: B11-36 (LLR-175.5) F-case06 (37 742 888-byte A2L, 1 applied entry), `ctrl+s`, 20 keystrokes of `newname1234567890abc`, then `alt+s` → `_decide_project_image` `1` call; `_file_digest` `1` call per session file in `digests` — the A2L, the MAC when loaded, and the image only on the copy branch (F-case06's applied entry makes it emit, so `0` for the image) —; `hashlib.sha256` of the payload `1` call (S11-06, per image generation); `0` more during the keystrokes and `0` more at `alt+s` (spies filtered by path, Q-4). Negative control: a mutation that builds the session per preview → 20 keystrokes give ≥ `2` decisions → RED.
examples: B11-37 (LLR-175.5 budget, C-QA-5) F-case06: the summary painted within `2` s of `ctrl+s` on the Windows development host; the measured time goes in the packet. P11-1: the A2L digest is 26.1 ms best of 5 (holds on the 9a tree).
examples: B11-38 (S11-06, lazy inventory) a save-as fixture with 2 000 files (`bulk_files`): 20 keystrokes of a new name → `inventory_project_tree` `1` call (spy), not `20`; the prefilled update-the-open-project name never walks (`0` calls). p11b U8 measured 189.4 ms per walk on base. Negative control: the walk per plan → `≥ 2` walks → RED; LLR-175.5a's 300 ms final paint is then at risk.
examples: B11-39 (LLR-175.1k) F-fresh, the loaded work copy deleted after the load, `ctrl+s` → `session.refusal == "Project NOT saved: source file missing: firmware.s19 — reload it or remove it from the project."`, `0` calls of `_decide_project_image`. The MAC arm (`firmware.mac` deleted) and the A2L arm name `firmware.mac` / `firmware.a2l` (`3` of `3`). Negative control (code read, base): the test runs only after the dialog closed (`_handle_save_dialog`, LLR-155.4 arm) → RED.
examples: B11-40 (LLR-175.1l, S11-02) S19 + MAC loaded; `_file_digest` stubbed (TC only) to raise `PermissionError(13, "Permission denied", str(mac_path))` for the MAC → `session.refusal == "Project NOT saved: firmware.mac could not be read: Permission denied — check that the file can be opened, then save again. Nothing written."`, `0` raises, the app running (`1` of `1`). A second arm: `Path.exists()` raising `PermissionError` for the MAC (the missing-source test, now inside the `try`) → the same refusal, `0` raises (S11-02). Negative control: the `except OSError` removed → the exception leaves `preview()` → the app stops → RED; on base the text has no next step → the token `check that the file can be opened, then save again` absent → RED.
examples: B11-41 (LLR-175.1m) the TC-B100-57 document (1 blocked entry at `0x8000007C`) → `image_step.refusal == "Project NOT saved: 1 blocked entry (0x8000007C) — fix them in the Patch Editor."` and `session.refusal` the same string; `0` digests computed after it except the session files (`1` of `1`). Three blocked entries → `3 blocked entries (0x…, 0x…, 0x…)` (boundary). Negative control (code read, base): the refusal reaches the engineer only through the plan after the dialog closed → RED.
examples: B11-42 (LLR-175.1n, withdrawn) no example: E2-rulings withdraw it (p11b U4 / U4b: a MAC-only session's entries are `skipped-outside`, `emit False`, `refusal None`). `_decide_project_image`'s `cannot be written` branch stays untouched as defence; `_save_session_inputs` adds no line for it.
examples: B11-83 (A11-01) F-case06 with 1 applied entry (an emitting session): `ctrl+s`, 20 keystrokes, `alt+s` → `_derived_record` `1` call (spy), `0` more during the keystrokes and `0` at `alt+s`; the 4 MiB image is parsed and hashed once per open, not per recompute. Negative control: `emitted_record` computed in the preparation (base) → `≥ 2` `_derived_record` calls → RED.

S19TuiApp._current_save_session
req: LLR-175.5, LLR-175.5b
in:
out: _SaveSession session
func: new (internal, no seam): `if self._save_session is None: self._save_session = self._save_session_inputs()`; `return self._save_session`. The dialog's `preview` lambda and `_confirm_project_save` get the session through it, so the first of them — the dialog's first `preview`, after the first refresh (S-d) — computes it, and nothing recomputes it until the router clears it.
callers: the `preview` lambda pushed by `action_save_project`; `_confirm_project_save`.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._save_session] (set once per open)
examples: B11-43 (LLR-175.5b) a spy on `_decide_project_image` records, at its first call, that `app.screen` is a mounted `SaveProjectScreen` that has completed `1` refresh (`1` of `1`; the refresh half is G-A's first-preview timing). Negative control: as B11-06.
examples: B11-44 (once) 3 calls of `_current_save_session()` in a row → `1` call of `_save_session_inputs` and the same object `3` times (identity). After the router runs, the next call computes a new one (`2` of `2`).

S19TuiApp._save_dialog_preview
req: HLR-175, LLR-175.1, LLR-175.1h, LLR-175.6
in: str name; _SaveSession session
out: SavePreview preview
func: new (the fixed S-a / N3 signature). Blank text (`not name.strip()`) → `SP(where=((session.refusal.removeprefix(_SAVE_REFUSAL_PREFIX), "refusal"),) if session.refusal else (), rows=(), plan=None, refused=True)`: nothing is planned for no name, and nothing about the empty name is painted before Save (LLR-175.1h's negative control; the empty pair on Save comes from `confirm("")`, Q-3). A name-independent session refusal is shown at once even with an empty field (LLR-175.1k / .1l / .1m: "`ctrl+s` → 1 line"). Otherwise → `self._compose_save_preview(self._prepare_project_save(name, session))`. Either way it memoises the returned preview in `self._save_painted_preview` before returning (A11-08: `confirm` compares the fresh preview against it). It calls no placement or listing function itself (LLR-175.4's AST arm).
callers: the `preview` lambda of `action_save_project` (G-A calls it after the first refresh and from its 150 ms timer, S-g).
module: s19_app/tui/app.py
examples: B11-45 (LLR-175.1) F-fresh: `a b` → `where == ([i] ab — new folder,)`; `../evil` → `[i] evil — new folder`. F-open (`P` open): `P` → `[i] P — updates the open project`; `P ` → `[i] P — updates the open project`; `Ab` on disk and open, typed `ab` → `[i] Ab — updates the open project`. F-merge: `ab` → `[i] ab — merges into an existing project`. Result `6` of `6`, each where line plain text (`0` markup spans; G-A paints it with markup off). Negative control: executed on the 9a tree (P11-2): `typed 'a b' -> dialog text has 'ab' folder line? False` → RED; a case-sensitive kind compare → the `ab` / `Ab` arm says `merges into an existing project` → RED.
examples: B11-46 (blank) `""` and `"   "` with nothing refused → `SP((), (), None, True)`; with F-fresh minus its work copy → `SP(([r] source file missing: firmware.s19 — reload it or remove it from the project.,), (), None, True)` (`3` of `3`). Negative control: the blank arm painting `name is empty` → the open of F-fresh shows a refusal before any typing → LLR-175.1h's negative-control case reversed → RED (TC-B100-49 asserts `#save_where` holds no `name is empty` after `ctrl+s` with an empty field).
examples: B11-47 (LLR-175.1h live) `!!!` → `SP(([r] name is empty — type a project name.,), (), None, True)` painted by the recompute, before any Save (`1` of `1`; `..`, `/` the same). Negative control: the pair painted only on Save → `!!!` paints nothing before Save → RED.

S19TuiApp._compose_save_preview
req: HLR-175, LLR-175.4, LLR-175.4c, LLR-175.4d, LLR-175.4e, LLR-175.4f, LLR-175.4g, LLR-175.1i, LLR-175.4j, LLR-173.7
in: _PreparedSave prepared
out: SavePreview preview
func: new (internal): composes painted plain text from one prepared save; every name through `pn` / `painted_names`, one line per row (no `\n` in any string; G-A cuts with `…`, S-a). Steps:
- Refused (`prepared.refusal is not None`) → `SP(where=((prepared.refusal.removeprefix(_SAVE_REFUSAL_PREFIX), "refusal"),), rows=(), plan=prepared.plan, refused=True)`. `_SAVE_REFUSAL_PREFIX = "Project NOT saved: "`; every refusal the preparation returns starts with it. A refused plan paints no rows (LLR-175.1i).
- Else `plan = prepared.plan`, `root = Path(plan.target).resolve()`, `rel(p) = p.relative_to(root).as_posix()` (`ValueError` → `p.name`):
  - `where = ((f"{pn(prepared.cleaned)} — {kind}", "info"),)` with `kind = _SAVE_KIND_WORDS[plan.target_kind]`, except `new project in an existing folder` when `plan.target_kind == PLAN_TARGET_MERGE` and the folder holds no project (the §1.3 content test — `(project_dir / "project.json").is_file()` or any child file with a `PROJECT_DATA_EXTENSIONS` / `A2L_EXTENSIONS` suffix — is false, R2-08; A11-17: an existing folder that is not a project); `_SAVE_KIND_WORDS = {PLAN_TARGET_NEW: "new folder", PLAN_TARGET_OPEN: "updates the open project", PLAN_TARGET_MERGE: "merges into an existing project"}`.
  - rows, in this order:
    0. `pn(prepared.source_gone)` when `prepared.source_gone is not None` (A11-16: the open project's folder vanished, so the save-as becomes a fresh save);
    0b. `pn(prepared.carried_document_line)` when `prepared.carried_document_line is not None` (A11-16: the dropped document line);
    1. `plan.image` when non-empty (LLR-175.4c; `_plan_project_save` composes it with `pn` of the image name);
    2. `f"unsaved changes in {pn(self.current_file.path.name)}"` when `self.current_file` and `self._change_service.differs_from_last_saved(self.current_file.mem_map)` (LLR-175.4d);
    3. one row per plan row except `project.json`, in plan order: when the source is named and `row.source.name != row.landing.name` → `f"{_SAVE_ROW_LABELS[row.role]} {pn(row.source.name)} → {pn(rel(row.landing))} — {row.action}"`, else `f"{_SAVE_ROW_LABELS[row.role]} {pn(rel(row.landing))} — {row.action}"` (A11-12 / R2-05: the rename test compares the bare names `source.name != landing.name`, not `rel()`, so a file-backed document that is not renamed never paints a false `source → home-relative landing` arrow; `fw.s19 → fw_2.s19`, `patches/changes.json → changes_1.json`), with `_SAVE_ROW_LABELS = {"image": "image", "mac": "MAC", "a2l": "A2L", PLAN_ROLE_DOCUMENT: "document", PLAN_ROLE_CARRIED: "file"}`;
    4. one row per planned folder: `f"folder {pn(folder.name)}/ ({folder.file_count} {'file' if folder.file_count == 1 else 'files'}) — new"`;
    5. `plan.skipped_links` non-empty → `f"links or junctions not copied: {painted_names(plan.skipped_links)}"` (the first 10, then `, and K more`; LLR-175.4e);
    6. `prepared.active_variant` not `None` (P-4; merge with an S19 / HEX image row) → `f"active variant {pn(prepared.active_variant)} (before: {before})"` with `before = pn(prepared.existing.active_variant)` when `prepared.existing` is not `None`, not damaged (`manifest_is_damaged`) and records one, else `none recorded` (LLR-175.4f);
    7. the `project.json` row: `f"project.json — {row.action}"`; when `manifest_keep_reason(prepared.existing)` is set (the commit will back the manifest up) → `f"project.json — {row.action}; the current one {reason}, a copy is kept as project.json.previous-<UTC>"` (A11-05).
  - `SP(where, tuple(rows), plan, refused=False)`.
callers: `_save_dialog_preview`, `_confirm_project_save`.
module: s19_app/tui/app.py
examples: B11-48 (LLR-175.4, AT-B100-21 painted half; plan rows from probe gb-plans S1–S9, holding on base) the 7 scenarios, rows exactly:
- fresh (F-fresh, `fresh1`): `firmware.s19 unchanged copy` / `image firmware.s19 — new` / `project.json — new`.
- pending patch (F-pending: `P` open with S19 + MAC, 1 entry applied, not saved; save `P`): `firmware.s19 + 1 change entry, 0 applied by this save` / `unsaved changes in firmware.s19` / `image firmware.s19 → firmware_1.s19 — new` / `MAC firmware.mac — keep` / `document patches/changes.json — new` / `project.json — rewrite`.
- refused (target `m2` with a second MAC): rows `()`, where `[r] 'm2' already has a MAC file (other.mac) — choose another name.`.
- `files` (`P` open with S19 + MAC + A2L, save `P`; S8): `firmware.s19 unchanged copy` / `image firmware.s19 — keep` / `MAC firmware.mac — keep` / `A2L firmware.a2l — keep` / `project.json — rewrite`.
- document (F-document: F-fresh plus 1 pasted entry, `doc1`): `firmware.s19 + 1 change entry, 1 applied by this save` / `image firmware.s19 — new` / `document patches/changes.json — new` / `project.json — new`.
- merge (F-merge, `ab` saved with a different `firmware.s19`): `firmware.s19 unchanged copy` / `image firmware.s19 → firmware_1.s19 — new` / `active variant firmware_1 (before: firmware)` / `project.json — merge`.
- save-as (F-saveas: `P` open holding `flows/f1.json`, `patches/boost.json`, `reports/r.md`; save `Q`; S9: folders `[('flows', 1), ('patches', 1), ('reports', 1)]`): `firmware.s19 unchanged copy` / `image firmware.s19 — new` / `folder flows/ (1 file) — new` / `folder patches/ (1 file) — new` / `folder reports/ (1 file) — new` / `project.json — new`.
Each painted file row, folder row and `project.json` row equals the painted plan's `rows` / `folders` one for one by landing name and action word (`0` differences, `7` of `7`); the action words painted are only `new`, `keep`, `merge`, `rewrite` (`replace` is not produced, E3 R1). Negative control: a painter that drops `keep` rows → the pending scenario loses `MAC firmware.mac — keep` → RED; on base there is no summary (P11-2) → RED.
examples: B11-49 (LLR-175.4c) F-pending → `firmware.s19 + 1 change entry, 0 applied by this save`; F-document → `firmware.s19 + 1 change entry, 1 applied by this save`; F-fresh → `firmware.s19 unchanged copy`; an A2L-only session → no image line (`plan.image == ""`). Result `3` of `3` plus the empty boundary. Negative control: a description built from `image_differs_from_source` alone → F-document (image unchanged, 1 entry) says `unchanged copy` → RED.
examples: B11-50 (LLR-175.4d) F-pending → `1` line `unsaved changes in firmware.s19`; the same session after a Save project → `0` lines (probe gb-plans S2: `after save differs False`); F-fresh → `0`; patched, saved, patched again → `1`. A patch that writes the bytes already there → `0`. Result `4` of `4` plus the boundary. Negative control: the line keyed on `image_differs_from_source` → after a Save project the journal still shows the patch → `1` line → RED.
examples: B11-51 (LLR-175.4e, Windows only) a save as of `P` holding `1` directory junction `flows/jx` → `links or junctions not copied: flows/jx`; `12` junctions `j01` … `j12` at the top of `reports/` → `links or junctions not copied: reports/j01, reports/j02, reports/j03, reports/j04, reports/j05, reports/j06, reports/j07, reports/j08, reports/j09, reports/j10, and 2 more` (`2` of `2`). Negative control: the row omitted → `0` rows → RED.
examples: B11-52 (LLR-175.4f) F-merge, `ab` records `active_variant "firmware"`, the session image differs → `active variant firmware_1 (before: firmware)`; after `alt+s`, `ab/project.json` records `active_variant == "firmware_1"` (probe gb-plans S4b: `active_variant firmware_1`) (`2` of `2`). Same bytes (image row `keep firmware.s19`) → `active variant firmware (before: firmware)`. A target whose `project.json` records no active variant, or is damaged → `active variant firmware_1 (before: none recorded)` (`1`). Negative control: the row omitted → `0` → RED; the row naming the first variant by name (`firmware`) → the after-save equality fails → RED.
examples: B11-53 (LLR-175.4f, collision, P-4) target `ab` holding `firmware.hex`, session image `firmware.s19` (different bytes) lands as `firmware.s19` → stems collide → `active variant firmware.s19 (before: …)`, and after `alt+s` `active_variant == "firmware.s19"` (E6 duplicate-id rule, `build_variant_set`). Negative control: a stem-only prediction → `active variant firmware` → the after-save equality fails → RED.
examples: B11-54 (LLR-175.4g) a loaded file `[b]x.s19` → `[b]x.s19 unchanged copy` / `image [b]x.s19 — new`; a save as whose open project holds the top-level file `[i]f.json` → `file [i]f.json — new` (F-7: a sub-folder file is painted only through its folder row, so the draft's `flows/[i]f.json` arm is re-pinned to a top-level file); typed `[red]a` → `[i] reda — new folder`; the clash `[b]P` → B11-25; a file named `x` + U+202E + `y.s19` → `image xy.s19 — new` (U+202E absent). Each line's plain text equals the `pn` form, `0` markup spans (`5` of `5`). Negative control: G-A's summary with markup on → `[b]x.s19` paints `x.s19` in bold → RED.
examples: B11-55 (LLR-175.4j, G-B half) a 130-character top-level file in a save as → its `file …` row holds the name clipped by `pn` to 120 characters ending in `…` (F-7: the draft's 120-character sub-folder file never reaches a row), and `0` row strings contain `\n` over the 7 scenarios. The one-line height and the visible `…` at 118 columns are G-A's (S-a).
examples: B11-56 (LLR-175.1i) the 3 refused plans of B11-29 → `rows == ()`, `refused is True`, `plan.rows == ()` each (`3` of `3`). Negative control: a painter that paints a refused plan's rows and drops the refusal → `0` token pairs → RED.
examples: B11-57 (LLR-173.7, TC-B100-66 Save arm) every where line and row composed for the 6 scenarios (fresh, open project, merge, save as, a refusal, an empty Save) → `0` matches of `\bD\d+\b`, `\bO-\d+`, `VS-`, `LLR-`, `HLR-`.
examples: B11-58 (HLR-175, `a b`) F-fresh, `a b` → where `[i] ab — new folder`, rows `firmware.s19 unchanged copy` / `image firmware.s19 — new` / `project.json — new` (AT-B100-16 folder half).
examples: B11-85 (A11-05, manifest keep) a merge or open-project save whose `project.json` is damaged (or another schema, or unknown keys) → the `project.json` row reads `project.json — rewrite; the current one damaged, a copy is kept as project.json.previous-<UTC>`, and the commit writes `project.json.previous-<UTC>` beside it (`1` of `1`). Negative control: the row omitted → the dialog says only `project.json — rewrite` while the commit writes an unpainted `project.json.previous-<UTC>` → RED.
examples: B11-86 (A11-16) a save-as where the open project's folder vanished after the open → an info row `pn(prepared.source_gone)` (the save-as becomes a fresh save); a carried document that is dropped → an info row `pn(prepared.carried_document_line)` (`2` of `2`). Negative control: the lines painted only after the save → `0` rows before Save → RED.
examples: B11-87 (A11-17) an existing work-area folder `ab` that is not a project (empty, or `notes.txt` only) → where `[i] ab — new project in an existing folder` (`1` of `1`; the commit turns it into a project). Negative control: the kind painted `merges into an existing project` (base) → the kind word is false → RED.

S19TuiApp._confirm_project_save
req: HLR-175a, LLR-175.4b, LLR-175.3c, LLR-175.3f, LLR-175.3b, LLR-175.4a
in: str name; Optional[SavePlan] plan
out: Optional[SavePreview] verdict
func: new: the `confirm` callable (S-b, S-h). `session = self._current_save_session()`; `prepared = self._prepare_project_save(name, session)`; `fresh = self._compose_save_preview(prepared)`; `painted = self._save_painted_preview`. Then:
- refused → memoise `self._save_painted_preview = fresh`; `return fresh` (the dialog stays, Save stays focusable: LLR-175.3f; an empty name gives the empty pair: LLR-175.3b, Q-3).
- `plan is None or fresh.plan != plan or painted is None or (fresh.where, fresh.rows) != (painted.where, painted.rows)` (dataclass equality of the frozen plan, plus any `where` / `rows` line that does not come from the plan — the P-4 `active_variant` row among them, A11-08) → `changed = SP(fresh.where + ((_SAVE_SUMMARY_CHANGED, "refusal"),), fresh.rows, fresh.plan, False)` with `_SAVE_SUMMARY_CHANGED = "the summary changed — check it, then save again"`; memoise `self._save_painted_preview = fresh` (R2-01: the memo holds the fresh preview without the extra line, so a second Save with nothing changed goes through); `return changed` (LLR-175.4b, ruling Q6).
- otherwise `self._save_confirmed = replace(prepared, plan=plan)` — the painted object itself, equal to the fresh one — and `return None` (go).
callers: `SaveProjectScreen` save action (G-A: `alt+s`, `#save_ok`, `enter` in `#project_name`).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._save_confirmed] (set on go), [Data: S19TuiApp._save_painted_preview] (memoised on every return)
examples: B11-59 (LLR-175.4b arm 1) F-fresh, `abc` typed, `alt+s` within 50 ms of the last key: the painted plan is the one for `ab` (or `None` before the first recompute) → `confirm("abc", painted)` returns `SP(([i] abc — new folder, [r] the summary changed — check it, then save again), rows of abc, plan_abc, False)` and memoises the fresh preview without the extra line (`self._save_painted_preview == SP(([i] abc — new folder,), rows of abc, plan_abc, False)`, R2-01); `0` dismisses, `0` new paths. A second `alt+s` with nothing changed → `confirm("abc", plan_abc)` → `None` → `1` dismiss and `1` folder `abc` (R2-01: the memo is the fresh preview, so `fresh` equals `painted` and the second press goes through). Result `1` of `2`. Negative control: a confirm that stores the fresh prepared save and returns `None` → arm 1 saves a plan never painted (`1` dismiss, `0` token pairs) → RED; a confirm that memoises `changed` → the second press always repaints and never dismisses → RED.
examples: B11-60 (LLR-175.4b arm 2) F-merge, `ab` painted (`image firmware.s19 — keep`), then the test writes `ab/firmware.s19` with other bytes, then `alt+s` → the fresh plan's image row is `image firmware_1.s19 — new` ≠ the painted `keep` → the preview with `the summary changed — check it, then save again`, `0` dismisses, `0` new paths (`2` of `2` with B11-59).
examples: B11-61 (LLR-175.3f, G-B half) a disguised clash `a b` (B11-24 fixture) → `confirm("a b", None)` returns `SP(([r] 'a b' is already a project as 'ab' — choose another name.,), (), None, True)` on each press; `app._save_confirmed is None` (`1` of `1`). Negative control: a confirm returning `None` on a refusal → `1` dismiss → RED.
examples: B11-62 (LLR-175.3b, Q-3) `confirm("", None)` and `confirm("   ", None)` → `SP(([r] name is empty — type a project name.,), (), None, True)` each (`2` of `2`; G-A presses `alt+s`, `#save_ok`, `enter` for its 6 of 6). Negative control: a dialog-side check that never calls `confirm` for blank text → the AST census of LLR-175.6 counts a second empty-name rule → RED (Q-3 ruling).
examples: B11-63 (LLR-175.3c, G-B half) F-fresh, `fresh1` painted, then each of `alt+s`, a `#save_ok` click and `enter` in `#project_name` (3 fresh apps) → `confirm` returns `None` once each, `1` dismiss each, `1` folder `fresh1` holding `firmware.s19` and `project.json` (`3` of `3`). Negative control (code read, base): no `BINDINGS`, no `on_input_submitted` → `alt+s` and `enter` save nothing → RED.
examples: B11-64 (LLR-175.4k, G-B half) the plan in every `SavePreview` is the planner's frozen `SavePlan`: `plan.rows = ()` raises `FrozenInstanceError`; `plan.rows.append(x)` raises `AttributeError` (a tuple) (`2` of `3`; the third, `screen.plan = …`, is G-A's property). Before the first recompute `screen.plan is None` (G-A). Negative control: a preview carrying a list-based copy of the rows → the append succeeds → RED.
examples: B11-88 (A11-08, active_variant change) F-merge, `ab` painted (`active variant firmware_1 (before: firmware)`); then a data file `firmware_1.hex` appears in `ab` so the image row `firmware.s19` now collides by stem → `confirm("ab", plan_ab)` re-prepares; the plan rows are equal but the fresh active-variant row differs → `the summary changed — check it, then save again`, `0` dismisses, `0` new paths (`1` of `1`). Negative control: the equality on the plan alone (base) → `confirm` returns `None` and the save records `firmware_1.s19` while the dialog said `firmware_1` → RED.

S19TuiApp._commit_project_save
req: HLR-175a, LLR-175.4a
in: _PreparedSave prepared; SaveProjectPayload payload
out: None
func: new: the base commit half `:9856`–`:10605` (C1–C5), moved with its statements unchanged except as listed. First lines unpack the 12 crossing locals from `prepared` (`cleaned`, `project_dir`, `save_as_source`, `source_gone`, `image_step`, `existing`, `target_carry`, `carried_derived`, `carried_active_document`, `carried_document_line`, `emitted_record`, `plan`); `payload.batch` / `payload.assignments` are read where they are today (`:10138`–`:10145`). Changes:
- (a) post-10 (`:10576`): `panel._dirty` → `panel.is_dirty` (from the 10 graph, C52).
- (d) Q10, the document rebinding (`:10521`–`:10554`): when `document_row` is file-backed and its source is the session document (`os.path.normcase(os.path.abspath(document_row.source)) == os.path.normcase(os.path.abspath(document.source_path))`) and `row_relative` was computed, the document follows the row: `document_relative = row_relative`. The document arm now predicts the landing with `workspace._match_identical` (A11-03), so the base's F5 (b) substitution (`document_relative == row_relative and … → landed_document`) keeps only its defence role. The top-level copies keep the base behaviour (A11-03: the top-level prediction gap goes to backlog, so the `carried` map and `held_names` stay as on base).
- Everything else — `mkdir(exist_ok=False)`, `validate_project_files`, the copies, the rows loop with `_plan_row_mismatch`, the gather, the manifest keep and write, the 11 `_abort_save` exits, the 4 `except` arms, the committed tail and its texts — is the base body. `:10225` still replaces `plan` with `_plan_without_document_key(plan)` after the gather; LLR-175.4a's equality is read at this function's entry (ruling).
callers: `_handle_save_dialog` (router step 6). Tests: `test_tc_b100_07_ast_census_every_post_creation_return_removes` is re-pinned to read `_commit_project_save` by name (census H, one string).
module: s19_app/tui/app.py
modify: [I/O: work area] (the only writer in the Save path)
examples: B11-65 (LLR-175.4a, AT-B100-21 executed half) for the 7 scenarios of B11-48, `alt+s`: the spy on `_commit_project_save` receives `prepared.plan is screen.plan`, and the written tree equals that plan by full path and action — fresh `W/fresh1/{firmware.s19, project.json}`; pending `W/P/{firmware.mac, firmware.s19, firmware_1.s19, patches/changes.json, project.json}` (probe gb-plans S2); merge `W/ab/firmware_1.s19` new and `project.json` merged; save-as `W/Q/{firmware.s19, flows/f1.json, patches/boost.json, reports/r.md, project.json}`; the refused scenario `0` new paths (`7` of `7`). Negative control: a commit that re-plans without the document row → the document scenario writes `patches/changes.json` with no painted row → RED.
examples: B11-66 (TC-B100-07 re-pin, census H) in `_commit_project_save`: every `return` after the first `mkdir` follows an `_abort_save` call; exactly `1` `except OSError` after the `mkdir` (the base test with the function name changed). `_handle_save_dialog` holds `0` `mkdir` calls. Negative control: the router left holding `mkdir` → the re-pinned census finds `0` in `_commit_project_save` → RED.
examples: B11-67 (top-level gap, backlog; A11-03) `P` holds `fw_2.s19` (the loaded image) and an identical `fw.s19`; save as `Q` → the plan keeps `('carried','fw.s19','new')` (base), and the commit aborts with `the plan named fw.s19 (new) but the file landed at fw_2.s19 (keep) — save again.` `test_e4_r11_a3r2_5_top_level_copy_reusing_the_image_row_aborts` is NOT re-pinned (census I keeps its name). The top-level prediction gap is backlog (Inc 12a sweep).
examples: B11-68 (Q10 (d), F5 (b), TC-B100-31 holds) `P` records `patches/changes.json` beside an identical `patches/changes_1.json`; save as `Q` → the document is bound to `Q/patches/changes_1.json`, which exists, and `Q/project.json` records `active_document == "patches/changes_1.json"` (`2` of `2`; holds on base, probe p11b U3). Negative control: (d) dropped → `document_relative` (`patches/changes.json`) is in neither the copy list nor the row → the binding stays on `P/patches/changes.json` → TC-B100-31 RED.
examples: B11-69 (top-level gap, backlog; A11-03) a save as whose top-level copy would be a `keep` row → the `carried` map and `held_names` stay as on base; the `derived_from` record for a reused copy is not produced (code read; no current test reaches it).
examples: B11-70 (post-10, C53 holds) the E3 R1 arm: document recorded in the project home, panel dirty → `1` line `Change document <name> has unsaved edits — the project records the file as it is on disk; save it from the Patch Editor to keep them` (read through `panel.is_dirty`).

S19TuiApp._plan_project_save
req: LLR-175.5, LLR-175.4, LLR-175.1i, LLR-175.6, LLR-175.4g
in: Path project_dir; str project_name; _ProjectImageStep image_step; bool derived = False; str? carried_active_document = None; str? source_reason = None; keyword-only Path? save_as_source = _UNSET; Mapping[Path, Tuple[str, int]]? digests = None; ProjectInventory? inventory = None; str? payload_sha256 = None
out: SavePlan plan
func: changed (:10716). The fixed A4 keywords plus P-1's `inventory`, P-2's `_UNSET` sentinel and S11-06's `payload_sha256`. Rules:
- `save_as_source is not _UNSET` marks a call from the preparation: then `source_dir = save_as_source` as given (`_UNSET` means "no save-as source given; derive it", R2-08), and every session file's digest is read from `digests` — the image (copy case), the MAC and the A2L. The file-backed document is digested here in each preparation (S11-05: it left the session), with an `OSError` → no row and one warning per dialog open, not per recompute (`Save plan: change document not readable: …`, memoised on the session, S11-11).
- `save_as_source is _UNSET` (the positional caller `test_tc_b100_59_planning_writes_nothing_and_hashes_no_payload`, `:1497`) → `source_dir = self._save_as_source_for(project_dir)` and `_file_digest` per source, as today.
- `inventory` not `None` and a walk would run (`source_dir` set, `source_reason None`, no refusal) → use it; else `inventory_project_tree(source_dir)` as today.
- The image description uses the scrubbed name: `f"{pn(loaded.path.name)} + {carried} change entry/entries, {applied} applied by this save"` / `f"{pn(loaded.path.name)} unchanged copy"` (LLR-175.4g; the success line's `— {plan.image}` clause follows).
- Target kind is decided by file identity (S11-01): `os.path.samefile(project_dir, self.current_project_dir)` with `OSError` → "not the same", so a case-folded-but-distinct folder is never the open project.
- Token row 9, the emitted payload's sha256 (now read from `payload_sha256`, once per image generation, S11-06; the positional caller computes it per call), the pasted document, the exempt MAC / A2L check (`_file_digest` of a target item, per name, Q-4) and the `plan_project_save` call are unchanged.
callers: `_prepare_project_save` (G15, the only app caller, LLR-175.6); the test's positional call (`test_b100_save_image.py:1497`). Baseline extractor: `_handle_save_dialog` (:9783), which moves into `_prepare_project_save`.
module: s19_app/tui/app.py
examples: B11-71 (R2-2 closed) F-open `P`, save `P` through the router → `_save_as_source_for` `1` call (base: `2`, probe p11b U1 / U2); save as `Q2` → `1` call and `_project_folder_refusal` `2` calls (target, source) (`2` of `2`). Negative control: the planner recomputing the source when `digests` is given → `2` calls → RED.
examples: B11-72 (LLR-175.5) F-open (S19 + MAC + A2L), `digests` given → `0` `_file_digest` calls inside `_plan_project_save` for those 3 paths (base: `3`, probe p11b U2). The positional call with `digests=None` → `3`, and `test_tc_b100_59_…` holds (`0` bytes written, `hashed == []`, `[("firmware_1.s19","new"),("project.json","new")]` from `plan_project_save`) (`2` of `2`).
examples: B11-73 (S11-05, document digest per preparation) F-document file-backed (`P/patches/changes.json` loaded), 10 recomputes → `10` `_file_digest(P/patches/changes.json)` calls (the document digest left the session and is recomputed in each preparation, S11-05). With that file unreadable → `1` warning `Save plan: change document not readable: …` per dialog open (not per recompute, S11-11), `0` document rows in each plan (`2` of `2`). Negative control: the document digest cached in the session (the Q-4 design) → an edit to the document while the dialog is open is not seen by `confirm` and the written tree differs from the painted row → RED (S11-05).

S19TuiApp._copy_project_subfolders
req: HLR-175a
in: (unchanged)
out: Optional[str] failure
func: unchanged (the base body; the A11-03 top-level copy fix is dropped, so the `carried` map and the `parts[-1]` lookup stay as on base).
callers: `_commit_project_save` (2 sites; baseline: `_handle_save_dialog` :9943, :10079).
module: s19_app/tui/app.py
examples: B11-74 (A3R2-5 holds, M79) a carried `new` row whose copy lands elsewhere (a concurrent writer claimed `Q/notes.bin`) → `1` line `Project NOT saved: the plan named notes.bin (new) but the file landed at notes_1.bin (new) — save again.`, `Q` removed (holds on base for a `new` row).

Module data (app.py)
req: LLR-175.6, LLR-175.4b, LLR-175.1, LLR-175.4, LLR-173.7
in:
out:
func: new, module level beside `_ProjectImageStep` (:1651):
- `@dataclass(frozen=True) class _SaveSession: image_step: _ProjectImageStep; digests: Mapping[Path, Tuple[str, int]]; refusal: Optional[str]` — fixed S-d — plus `inventory: Optional[ProjectInventory] = None` (P-1), `emitted_record: Optional[DerivedFrom] = None` (A11-01) and `payload_sha256: Optional[str] = None` (S11-06).
- `@dataclass(frozen=True) class _PreparedSave` — the fixed S-c fields in the fixed order — plus `active_variant: Optional[str] = None` (P-4).
- `_SAVE_KIND_WORDS` (the A11-17 fourth word is picked in `_compose_save_preview`), `_SAVE_ROW_LABELS`, `_SAVE_SUMMARY_CHANGED`, `_SAVE_REFUSAL_PREFIX` (values in `_compose_save_preview` / `_confirm_project_save`), and `_UNSET` (the P-2 sentinel, module-level).
- `_unreadable_text(exc: OSError) -> str` (in `_prepare_project_save`).
callers: `_save_session_inputs` (builds `_SaveSession`, `_unreadable_text`), `_prepare_project_save` (builds `_PreparedSave`, `_unreadable_text`), `_compose_save_preview` (`_SAVE_KIND_WORDS`, `_SAVE_ROW_LABELS`, `_SAVE_REFUSAL_PREFIX`), `_confirm_project_save` (`_SAVE_SUMMARY_CHANGED`), `_handle_save_dialog` / `_commit_project_save` (read `_PreparedSave`). No node in the baseline (new names).
module: s19_app/tui/app.py
examples: B11-75 (§3 token rows) `_SAVE_SUMMARY_CHANGED` holds `the summary changed` and `check it, then save again` (the new §3 row, LLR-175.4b); the kind words equal the four informational phrases of §C.3 (`4` of `4`); `_unreadable_text(PermissionError(13, "Permission denied", "C:\\x\\m.mac"))` → `Project NOT saved: m.mac could not be read: Permission denied — check that the file can be opened, then save again. Nothing written.` (`1`). Negative control: a kind word changed → the §C.3 table equality fails → RED.

plan_project_save
req: LLR-175.4, LLR-175.4a, HLR-175a
in: (unchanged signature)
out: SavePlan plan
func: changed (ruling Q10, Q-5 narrowed by A11-03: the document arm only). Refusals, `_plan_copies`, the cap checks and every non-copying path are unchanged. Under `copying` (`target_kind == "new"` and an inventory):
- (owner document row) a file-backed document row whose source the copy list owns (`owns`) is predicted against the tree the copy produces, not the empty `target / home`: build `occupants = {c.relative.name: (c.size, inventory.root / c.relative) for c in copies if normcase(PurePosixPath(c.relative).parent.as_posix()) == normcase(planned.home)}` (the copied files in that home, with their sizes and source paths), then predict `(name_landed, reused)` through `_workspace._match_identical` with the copied occupants as the `listing` and `inventory.root / planned.home` as the `destination` — the one byte-identity rule, on real files, with no new comparison code (A11-03; it re-checks "regular file, not a reparse point, current size" before hashing, S11-09). When `_match_identical` finds no identical copy, the free-name walk is the same `_free_name` rule the commit uses — `_placed_name_candidates` against the copied names, `normcase` (R2-07) — so the painted landing is what the commit will write. Landing `Path(target).resolve() / planned.home / name_landed`; action `keep` when reused, else `new` (and only `new` counts in `total`). A non-owner home row is predicted against `inventory.root / home`, as today (DR-1).
- (top-level copies) unchanged from base (A11-03: the top-level prediction gap goes to backlog; `test_e4_r11_a3r2_5` is NOT re-pinned).
- Docstring: the Data Flow bullets name the copied tree as the prediction base for the document row; "no payload is hashed" becomes "no planned file is hashed; a document-row candidate's bytes are read only when a same-size occupant must be compared (the rule `_match_identical` applies to candidates)".
callers: `S19TuiApp._plan_project_save` (:10942); direct test calls in `test_b100_project_homes.py` (3 tests) and `test_b100_save_image.py` (4 tests), which have no identical siblings and keep their rows (E4 re-runs them).
module: s19_app/tui/services/project_gather_service.py
examples: B11-76 (Q10 document arm, F5 (b), A11-03) the p11b U3 fixture, save as `Q` → rows `[('image','firmware.s19','new'), ('document','patches/changes_1.json','keep'), ('manifest','project.json','new')]`, copies `['patches/changes_1.json']`; the saved `Q` holds `firmware.s19`, `patches/changes_1.json`, `project.json`, so the plan's file rows equal the tree (`0` differences). The painted row reads `document changes.json → patches/changes_1.json — keep` (R2-05: source `changes.json`, landing `changes_1.json`). Negative control: executed on base (probe p11b U3): `('document', 'changes.json', 'new')` while `Q` holds `patches/changes_1.json` → RED.
examples: B11-77 (top-level gap, backlog; A11-03) probe gb-plans S7's fixture → the plan keeps the base rows `[('image','fw_2.s19','new'), ('carried','fw.s19','new'), ('manifest','project.json','new')]`, total `73728`; the save aborts with `the plan named fw.s19 (new) but the file landed at fw_2.s19 (keep)` (`test_e4_r11_a3r2_5` is NOT re-pinned). The top-level prediction gap is backlog (Inc 12a sweep).
examples: B11-78 (no change elsewhere) `test_e4_r14_top_level_copy_counted_once_in_the_plan_total` → copies `['flows/f.json','notes.bin']`, carried `['notes.bin']`, total `86016` (holds; no occupant shares `notes.bin`'s size and name walk). The 7 direct `plan_project_save` tests keep their rows. A pasted document under copying → predicted against `P/patches` as today (`3` of `3`).
examples: B11-79 (top-level base behaviour, unchanged) `P` top level holds `a.bin` and an identical `a_1.bin` (sorted `a.bin` first) and the image `fw.s19` → the base `place_into_workarea` claims each copy's own name: `('carried','a.bin','new')` then `('carried','a_1.bin','new')` (`1` of `1`; unchanged by A11-03).

_predict_in_copy — retired (A11-03 / S11-09)
req: — (removed with the top-level arm)
func: dropped. The Q10 fix narrowed to the document row, which now goes through `_workspace._match_identical`; the top-level arm that used this helper is dropped, so the helper has no caller and is removed (S11-09 is moot).
module: s19_app/tui/services/project_gather_service.py

## Context nodes (unchanged)

- `S19TuiApp._decide_project_image` — unchanged. Its one caller moves from `_handle_save_dialog` (:9706) to `_save_session_inputs`; called once per dialog open (B11-36) and once per direct payload. The `cannot be written` arm stays as defence (LLR-175.1n withdrawn).
- `S19TuiApp._save_as_source_for` — unchanged; 1 call per preparation (B11-71). R2-1 (`PermissionError` counts as gone) stays in the backlog.
- `_plan_copies` — unchanged (decision above). Example B11-76 relies on its `owned` set as today.
- `painted_names`, `predict_placement`, `_match_identical`, `build_variant_set`, `ChangeService.differs_from_last_saved`, `classify_active_document`, `inventory_project_tree` — unchanged; new callers named in the nodes above.

## Entities

[Data: S19TuiApp._save_session]
desc: the per-open `_SaveSession` (ruling Q-1): `None` until the dialog's first `preview` or `confirm`; cleared by the router on every route out (S-d).
sequence:
  dialogOpen: S19TuiApp.action_save_project (session None) → push SaveProjectScreen → (first refresh) preview → S19TuiApp._current_save_session → S19TuiApp._save_session_inputs → S19TuiApp._decide_project_image (1) → _file_digest per session file → session set
  typing: SaveProjectScreen timer → preview → S19TuiApp._save_dialog_preview → S19TuiApp._prepare_project_save → S19TuiApp._plan_project_save (digests from the session) → plan_project_save → S19TuiApp._compose_save_preview → SavePreview (0 decisions, 0 session digests)
  escape: SaveProjectScreen dismiss(None) → S19TuiApp._handle_save_dialog (step 0 clears) → expect none (0 paths, digest unchanged)

[Data: S19TuiApp._save_confirmed]
desc: the prepared save `confirm` approved, holding the painted plan object (proposal P-3); read once by the router.
sequence:
  confirmGo: SaveProjectScreen save action → S19TuiApp._confirm_project_save → S19TuiApp._prepare_project_save → plan == painted → _save_confirmed = replace(prepared, plan=painted) → None → dismiss(payload with plan=painted) → S19TuiApp._handle_save_dialog (identity match) → S19TuiApp._commit_project_save
  confirmStale: … → S19TuiApp._confirm_project_save → plan != painted → SavePreview + `the summary changed` → expect none (dialog open, 0 paths)
  confirmRefused: … → S19TuiApp._confirm_project_save → refusal → SavePreview (refused) → expect none (dialog open, 0 paths, 0 toasts)

[I/O: work area]
desc: written only by `_commit_project_save`; read by the preparation (the clash scan, the target checks, the manifest, the planner's listing, free space).
sequence:
  directPayload: test → S19TuiApp._handle_save_dialog → S19TuiApp._save_session_inputs → S19TuiApp._prepare_project_save → S19TuiApp._commit_project_save → mkdir / placements / gather / manifest
  saveAsKeep: S19TuiApp._commit_project_save → S19TuiApp._copy_project_subfolders (carried by source name) → place_into_workarea reuses fw_2.s19 → _plan_row_mismatch (keep = keep) → expect none

## Callers and what changes for each

| Caller | Reaches | What changes for it |
|---|---|---|
| `ctrl+s`, `s`, palette `save_project` | `action_save_project` | nothing loaded → 1 status line, no dialog; otherwise the new keyword constructor; inert while a Save, Load or question modal is on the stack |
| `SaveProjectScreen` (G-A) | the `preview` lambda, `_confirm_project_save` | new callables (S-b); the session is computed at the first `preview` |
| `SaveProjectScreen` dismiss | `_handle_save_dialog` | the router commits the confirmed save by identity; `None` clears the session |
| 56 direct call lines + 1 by reference (11 files) | `_handle_save_dialog` | unchanged outcome; texts scrubbed only (B11-12) |
| `_capture_save_payload` (`test_tui_manifest_save`) | the attribute `_handle_save_dialog` | still called with one argument at dismiss (B11-04) |
| `test_tc_b100_07_…` | `_commit_project_save` | re-pinned name (B11-66) |
| `test_tc_b100_09_…` | `__init__` attributes | 3 names classified (B11-01) |
| `test_tc_b100_57_…` | `project_gather_service.py` | re-pinned to also catch `Attribute` calls of `_hash_file` (A11-03) |
| `test_e4_r11_a3r2_5_…` | `plan_project_save` | NOT re-pinned (A11-03: the top-level arm is dropped; the abort stays, B11-67) |
| `test_b100_save_image.py:1497` | `_plan_project_save` positional | unchanged (`digests None`, B11-72) |
| Textual `run_action`, key bar | `check_action` | the 4 priority actions also inert while `SaveProjectScreen` is on the stack |

## Seams with G-A (`screens.py`, `styles.tcss`), by interface id

| Id | G-B side (this design) | G-A must | Examples |
|---|---|---|---|
| S-a | `SavePreview` strings composed and scrubbed here; one line each, no `\n`; where lines `info` / `refusal`; a refusal's where line is the status text minus `Project NOT saved: `; `plan` is the planner's frozen object; `refused True` for every refusal and for blank text | paint every string with markup off; nowrap + ellipsis on rows; no re-scrub; no service call | B11-45 … B11-58 |
| S-b | `SaveProjectScreen(preview=…, confirm=self._confirm_project_save, initial_name=self.current_project, variants=…, candidate_files=…)` | keyword constructor; `alt+s` priority; `enter` → the same save action; prefill and select `initial_name` | B11-04, B11-05, B11-63 |
| S-c | the router matches `payload.plan is confirmed.plan` and `payload.project_name == confirmed.typed_name`; `confirm` stores the painted object | pass to `confirm` and to the payload the **same** name string and set `payload.plan = self.plan` (the object last painted); `parent_folder = str(work area)` | B11-13, B11-14, B11-16 |
| S-d | the session is created by the first `preview` (or `confirm`) call and cleared by the router | make the first `preview` call after the first refresh; dismiss `None` on `escape` / Cancel so the router clears the session | B11-06, B11-43, B11-15 |
| S-e | `check_action` whole-stack tuple `(LoadDialog, ConfirmQuestionScreen, SaveProjectScreen)` | export the class name unchanged | B11-07 … B11-10 |
| S-g | `preview` is synchronous and returns a fresh `SavePreview` | a 150 ms debounce (each keystroke resets the timer); call `preview(current text)` on each recompute, blank text included | B11-36, B11-46 |
| S-h | `confirm(name, plan)`: refused → refused preview; `plan is None`, the plan differs, or any `where` / `rows` line differs (the P-4 `active_variant` row among them, A11-08) → preview + `the summary changed — check it, then save again`; else `None` | pass `self.plan` (or `None`); on a non-`None` return repaint and stay; call `confirm("")` for blank text (Q-3) | B11-59 … B11-62, B11-88 |
| S-i | Q10 lives in `plan_project_save`; the dialog sees it only as rows | — | B11-76, B11-77 |
| Q-6 | a dialog refusal never reaches the router, so it never toasts | — | B11-17 |

## Findings

finding F-1 (requirement gap) a work area that cannot be listed stops the app from inside the dialog
anchor: S19TuiApp._prepare_project_save
seen: G10's `sorted(self.workarea.iterdir())` is not wrapped on base (`:9561`); today an `OSError` there leaves the dismiss callback. With the preparation running on every recompute, it would leave `preview()` inside the dialog's timer, and Textual's `exit_on_error` stops the app.
decision: designed (B11-34) with the LLR-175.1g token pair. Proposal P-5 gives the requirement text.

finding F-2 (order change, declared) session refusals move to G11's place
anchor: S19TuiApp._prepare_project_save
seen: the base checks a missing source at G11, an unreadable session file at G16 and blocked entries at G17 (through the plan, after token row 9). The session computes all three once per open, and the preparation checks `session.refusal` once, at G11.
effect: only combinations change. Blocked entries or an unreadable session file **plus** a link target, an unreadable target or a refused save-as source now paint the session refusal first, where the base painted the target or source refusal. No test combines them (census of TC-B100-04 … -07, -57, -62, `test_f2_*`: each arm has one fault).
decision: accepted for simplicity (one check, one place). E4 runs the 57 direct calls as the guard.

finding F-3 (closed by P-2) R2-2 closes through the sentinel
anchor: S19TuiApp._plan_project_save
seen: `None` was both "not a save as" and a real value.
decision: applied P-2 — `save_as_source` defaults to the module sentinel `_UNSET`, so "no save-as source given; derive it" is `_UNSET`, while an explicit `None` keeps meaning "not a save as".

finding F-4 (correctness gap, declared, not designed) the file-backed document's landing is predicted but never checked
anchor: S19TuiApp._commit_project_save
seen: the rows loop skips a file-backed document row and the gather places it (`_plan_row_mismatch` never runs for it, baseline). After Q10 the prediction is right for both F5 arms, but a concurrent change in `Q/<home>` between the plan and the gather would still land it elsewhere without a line.
decision: not designed (no requirement asks; adding an abort path widens the commit). Backlog candidate: compare `gather_outcome.active_document` with the row's landing and abort with the `the plan named` line.

finding F-5 (declared) stale session inputs
anchor: S19TuiApp._save_session_inputs
seen: digests, the image decision and the save-as inventory are read once per open (Q1, Q-4). A source file changed or a file added to the open project while the dialog is open is not seen by the plan or by the out-of-date check.
effect: the commit copies exactly `plan.copies` (a file added later is not copied) and places each row's source; a changed source lands where the placement puts it and `_plan_row_mismatch` aborts with `the plan named … — save again` when that differs from the row. Nothing is lost or overwritten.
decision: accepted (rulings Q1, Q-4).

finding F-7 (requirement text) two draft arms name text the summary never paints
anchor: S19TuiApp._compose_save_preview
seen: LLR-175.4 paints a save as at folder granularity (one row per sub-folder with its file count). LLR-175.4g's arm "a sub-folder file `flows/[i]f.json`" and LLR-175.4j's "120-character sub-folder file name" name a file that no row paints, so neither arm can fail.
decision: designed against a top-level file of the open project (a `file …` carried row, B11-54, B11-55). Proposal P-6 re-pins the two thresholds.

finding F-6 (A11-02) a free-space refusal carries `plan=None`
anchor: S19TuiApp._compose_save_preview / _prepare_project_save
seen: G18 refused a valid plan while carrying it, so `SavePreview.plan` / `SaveProjectScreen.plan` held a plan whose rows were never painted; a Save after freeing space could then commit that unpainted plan.
decision: the two G18 refusals now pass `plan=None` (A11-02), so a free-space refusal carries no plan and the next Save repaints with `the summary changed`. One rule for every refusal (LLR-175.1i's "in place of the summary rows").

finding F-8 (A11-03, backlog) the top-level copy prediction is dropped
anchor: project_gather_service.py plan_project_save
seen: Q-5 originally predicted both the document row and the top-level copied rows against the tree the copy produces. The prefer-removal rule narrows Q-5 to the document row only.
decision: the document row goes through `_workspace._match_identical`; the top-level copies keep the base behaviour and the prediction gap goes to backlog (Inc 12a sweep). `test_e4_r11_a3r2_5` is NOT re-pinned.

## Proposals to the orchestrator

- **P-1 (Q-4 ruling has no slot).** Ruling Q-4 computes the save-as inventory once per open, but the fixed `_SaveSession` has no field for it and the fixed `_plan_project_save` no parameter. Proposed: `_SaveSession.inventory: Optional[ProjectInventory] = None` (filled by `_save_session_inputs` when a project is open, its folder passes `_project_folder_refusal` and the image step is not refused) and the keyword-only `_plan_project_save(…, inventory: Optional[ProjectInventory] = None)` (`None` → walk as today). Without it, a 2 000-file save as walks for 189.4 ms on every recompute (p11b U8) against LLR-175.5a's 300 ms final paint. Evidence: B11-38.
- **P-2 (optional, F-3).** A module sentinel `_UNSET` as the default of `save_as_source` (and no coupling to `digests`). Only if the orchestrator prefers it to the convention.
- **P-3 (where the confirmed save lives).** Ruling Q-2 commits "the session's last confirmed `_PreparedSave`", but the fixed `_SaveSession` is frozen with no slot for it. Proposed: a second app attribute `S19TuiApp._save_confirmed: Optional[_PreparedSave]`, set by `confirm` on go, read and cleared by the router (TC-B100-09 classifies it with `_save_session`). Alternative: a `confirmed` field on `_SaveSession`, set with `dataclasses.replace` and re-assigned to `_save_session`.
- **P-4 (LLR-175.4f needs the predicted variant).** `_PreparedSave.active_variant: Optional[str] = None`, computed in the preparation with `build_variant_set` over the target's data files plus the image landing (the commit's rule). It keeps the listing inside the one preparation (LLR-175.4's AST arm) and makes the stem-collision case exact (B11-53). Without it, `_compose_save_preview` would list the target itself, or predict the stem only.
- **P-5 (F-1, new unwanted requirement).** "If the work area cannot be listed while the Save project dialog prepares a save, then the system shall paint `could not be read` and `check that the folder can be opened, then save again` in the Save project dialog." Threshold: `Path.iterdir` raising `PermissionError` for `W` → 1 where line, the dialog open, the app running, 0 new paths. Negative control: the catch removed → the app stops. Proposed under TC-B100-47 as LLR-175.1o, or folded into LLR-175.1g's threshold.
- **P-6 (F-7, draft thresholds).** LLR-175.4g: replace "a sub-folder file `flows/[i]f.json`" with "a top-level file `[i]f.json` of the open project in a save as". LLR-175.4j: replace "a 120-character sub-folder file name" with "a 130-character top-level file name of the open project in a save as". Both then name a painted row.
- **No other interface change.** `SavePreview`, `SaveProjectScreen`'s constructor, `SaveProjectPayload.plan`, the router's one parameter and `plan_project_save`'s signature are used as fixed.

## Design risks

- **R-1 (the split).** About 380 lines move to `_prepare_project_save` and 750 to `_commit_project_save`. Guards: the 57 direct calls (LLR-175.4l), TC-B100-05 / -07 / -31 / -59, and B11-33's 15-name equality. Moving the bodies verbatim (G4–G18 order, C1–C5 statements) is the rule; every intended change is listed in the node's `func:`.
- **R-2 (preparation cost per recompute).** One `iterdir` of `W` (the clash scan), the target checks, one `read_project_manifest`, the planner's target listing and `shutil.disk_usage` per recompute, at most about 7 per second while typing (150 ms). The heavy inputs are per open (P11-1, U8). E4 records the final-paint time for F-case06 (LLR-175.5a).
- **R-3 (copy digests).** The document arm reads a candidate's bytes through `_match_identical` only when a same-size occupant exists; bounded by the document home's copied files and the 256 MiB cap. Not measured.
- **R-4 (logs).** The preparation logs nothing; the router logs `Save project refused: <text>` once instead of the base's per-branch log texts. `grep` of `tests/` for those log texts → 0 hits.
- **R-5 (P-1 … P-4 pending).** The design assumes P-1, P-3 and P-4. If one is rejected, its fallback is named in the proposal; P-3 has no fallback that keeps ruling Q-2 without a slot.

## Windows-only arms (reported not run on the Linux CI, never passed)

B11-05 second arm (case), B11-26 (`Ab` / `ab` case), B11-27 (junction), B11-51 (junctions), B11-82 (`strasse` / `straße`).

## Requirement coverage (G-B)

| Requirement | Examples |
|---|---|
| HLR-175 (app half) | B11-45, B11-48, B11-58 |
| HLR-175a | B11-13, B11-63, B11-65 |
| HLR-175b (app half) | B11-19 … B11-31, B11-33, B11-61 |
| HLR-175c (router half) | B11-15 |
| HLR-175d (app half) | B11-19, B11-62 |
| HLR-175e (router half) | B11-16 |
| HLR-175f (app half) | B11-02, B11-03, B11-04 |
| LLR-175.1 | B11-26, B11-45, B11-87 |
| LLR-175.1a | B11-21 |
| LLR-175.1b | B11-20 |
| LLR-175.1c | B11-24 |
| LLR-175.1d | B11-22 |
| LLR-175.1e | B11-23 |
| LLR-175.1f | B11-27 |
| LLR-175.1g | B11-28 |
| LLR-175.1h | B11-19, B11-47 |
| LLR-175.1i | B11-29, B11-56, B11-84 |
| LLR-175.1j | B11-30 |
| LLR-175.1k | B11-31, B11-39, B11-46 |
| LLR-175.1l | B11-40, B11-75 |
| LLR-175.1m | B11-41 |
| LLR-175.1n | withdrawn (E2-rulings); B11-42 records it |
| LLR-175.1o | B11-34 |
| LLR-175.1p | B11-82 |
| LLR-175.2a (router half) | B11-16 |
| LLR-175.3b (app half) | B11-62 |
| LLR-175.3c (app half) | B11-63 |
| LLR-175.3f (app half) | B11-61 |
| LLR-175.3g | B11-07, B11-08, B11-09, B11-10 |
| LLR-175.3h (app half) | B11-05 |
| LLR-175.3j | B11-02, B11-03 |
| LLR-175.4 | B11-48, B11-78, B11-85, B11-86 |
| LLR-175.4a | B11-13, B11-14, B11-65, B11-76 |
| LLR-175.4b | B11-59, B11-60, B11-88 |
| LLR-175.4c | B11-49 |
| LLR-175.4d | B11-50 |
| LLR-175.4e | B11-51 |
| LLR-175.4f | B11-52, B11-53 |
| LLR-175.4g | B11-25, B11-54 |
| LLR-175.4j (app half) | B11-55 |
| LLR-175.4k (type half) | B11-64 |
| LLR-175.4l | B11-11, B11-12 |
| LLR-175.5 | B11-36, B11-37, B11-38, B11-44, B11-72, B11-73, B11-83 |
| LLR-175.5b (app half) | B11-06, B11-43 |
| LLR-175.6 | B11-32, B11-33 |
| LLR-173.7 (Inc 11 Save arm, app half) | B11-57 |
| AT-B100-21 (painted and executed halves, app side) | B11-48, B11-65 |
| AT-B100-16 (folder, clash halves, app side) | B11-58, B11-24 |
| Census re-pins (H, I) | B11-01, B11-66, B11-67 |
| Q10 / Q-5 (document arm) | B11-68, B11-76 |

**G-A only** (no G-B node; listed so nothing is lost): LLR-175.2, LLR-175.3, LLR-175.3a, LLR-175.3d, LLR-175.3e, LLR-175.3i, LLR-175.4h, LLR-175.4i, LLR-175.5a, and the G-A halves of LLR-175.2a (the payload's parent), LLR-175.3b, LLR-175.3c, LLR-175.3f, LLR-175.3h, LLR-175.4j, LLR-175.4k (the property), LLR-175.5b (the first refresh) and HLR-175c / HLR-175f.

**G-B requirements left uncovered: none.**
