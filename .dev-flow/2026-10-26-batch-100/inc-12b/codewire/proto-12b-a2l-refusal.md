# Code-Wire prototype — Inc 12b, prototype P-2: group G-C (`s19_app/tui/app.py`: the A2L attach, the work-area pick, the busy refusal, quit) and group G-D (`s19_app/tui/a2l.py`: the parser's byte callback)

Stage E2 of the design-first pipeline (`dev-flow-v3-beta`) for Inc 12b ("project load, Save project and the A2L parse on workers"). Graph only: no stub, mark or other change in `s19_app/` or `tests/` of any tree. New functions are nodes whose `func:` starts with "new". Base: main `8947666` (the lines of `baseline-12b.md`) plus the fixed graphs of Inc 9b (`../../inc-9b-design/codewire/proto-9b-app.md`), Inc 10 (`../../inc-10-design/codewire/proto-10-app.md`, `proto-10-dialog.md`), Inc 11 (`../../inc-11-design/codewire/proto-11-app.md`) and Inc 12a (`../../inc-12a-design/codewire/proto-12a-indicator.md`, `proto-12a-sweep.md`; 12a's seam is consumed unchanged except where A12a-07 places the quit check inside `end_busy`). Line numbers are `8947666` lines of `app.py` / `a2l.py` unless another file is named. Note: since the baseline, main moved to `2305c8b` (Inc 9b merged); `a2l.py` is byte-identical (sha256 prefix `6d12c964344b`), and the post-9b bodies quoted below (`_load_workarea_file`, `load_a2l_from_path`) were read on `2305c8b`.

Inputs: `../E1-requirements-draft.md`, `../E1-scope.md`, `../E1-rulings.md` (Q1–Q7), `../E2-rulings.md`, `baseline-12b.md`, `baseline-notes.md`, `interfaces-12b.md` (FIXED, with its orchestrator rulings and the binding 12a E3 carry-overs; what I need changed is in "Proposals to the orchestrator"), `../../inc-12a-design/codewire/interfaces-12a.md`, `../../inc-12a-design/E3-rulings.md`.

Probes (s19env Python 3.11, Textual 8.2.8, `python -I`, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONUTF8=1`, `LOCALAPPDATA=../work/localappdata-p2`; scripts and outputs in `../work/p2/`; the checkout was only imported, `git status` unchanged afterwards — only the untracked `prototypes/load_projects/` that was there before):
- `probe_p2_a2l.py` → `probe_p2_a2l.out.txt` (P2-a): the designed `build_section_tree` / `parse_a2l_file` edit applied to an in-memory copy of the two functions' source text (exec'd in the imported module's namespace; nothing written): report counts, the forwarder rule, result equality with and without the callback, and timing.
- `probe_p2_quit.py` → `probe_p2_quit.out.txt` (P2-b): a minimal Textual app (no `s19_app` import) with a sync `action_quit` override, a quit-question subclass, a held thread worker, a deferred install, and the exit from the end handler.
- `probe_p2_defer_raise.py` → `probe_p2_defer_raise.out.txt` (P2-c): a `call_after_refresh` callback that raises, behind an `except BaseException` guard.

Conventions:
- `W` = the work area (`<base>/.s19tool/workarea`); `T` = `str(app.query_one("#status_text", Label).render())`; "bar spy" = a class-level `set_progress` spy recording `value`; `pn(x)` = `painted_names([x])`.
- **Busy line** `B(label)` = `busy: <label> is running — wait for it to finish.` The labels are 12a's table rows through `_busy_begin_action`: A2L attach of `firmware.a2l` → `Loading firmware.a2l`; file load of `x.s19` → `Loading x.s19`; project load of `P` → `Loading project P`; Save project of `P1` → `Saving project P1`.
- **Held** = a forced slow step: the named module function, reached through the `app_module` attribute, is monkeypatched to wait on a `threading.Event` before calling the real one (A2L: `app_module.parse_a2l_cached` or `app_module.copy_into_workarea`; Save: `app_module.place_into_workarea`; project load: `app_module.read_project_manifest`). "Released" = the event set, then `wait_for_complete()` and 2 pauses.
- **Session digest** = the E1 tuple, image hash as in `baseline-notes.md` (U1).
- `QQ` = the quit question: `_QuitQuestionScreen(_QUIT_TITLE, _QUIT_BODY.format(label=…), _QUIT_YES, _QUIT_NO)`.
- Fixtures: case_01 (`firmware.s19` 358 bytes, `firmware.mac`, `firmware.a2l` 1 444 bytes), case_06 (`firmware.a2l` 37 742 888 bytes, 1 039 926 lines, 220 040 tags), project `P` = case_01's three files, `P1` = the save target, `big8.s19` = 12a's generated S19 with 8 MiB of data. Unless stated, `S19TuiApp(base_dir=tmp)` under `run_test(size=(118, 54))`.
- Example ids: `C12b-NN` (G-C), `D12b-NN` (G-D). Each example states the Inc 12b target unless it says "holds on base".

## Decisions on the fixed interface's open points (binding inputs that disagree)

| Point | Fixed text | Binding later text | Decision |
|---|---|---|---|
| The end tail | `_finish_session_action(key, gen, outcome, final_line=None)` = `end_busy` then `_exit_if_quit_pending`; `_fail_session_action` likewise (S-c) | 12a E3 A12a-07: "the quit-after-end check lives inside `end_busy`" (listed as binding at the foot of `interfaces-12b.md`, and in my brief); A12a-06: `end_busy(key, gen, outcome)` has no `final_line` | **The check goes inside `end_busy`** (its effective branch, after the hand-back). Every end path (`end_busy`, `_busy_fail`, `_handle_load_error`) then reaches it with no wrapper. `_finish_session_action` / `_fail_session_action` are **not created**; P-1's end sites call `end_busy` / `_busy_fail` directly (seam X12b-02, proposal P2-1). |
| Worker options | S-d: no `exclusive`, no shared group | 12a S12a-05: "one exclusive worker group per busy key … or uses a distinct group per key" | `@work(thread=True, group="a2l_load", exit_on_error=True)`: a distinct group per key, **not** exclusive. No worker can then be cancelled before its body runs, so no canceller owes an `end_busy` (S12a-05's hazard cannot occur). Q-d1: `exit_on_error=True`. |
| Worker guard | S-d body: inner `except Exception` + `finally: _fail_session_action` | 12a S12a-06: `except BaseException` + end + re-raise, "no unconditional `finally` cross-thread call after success" | The worker body's outer guard is `except BaseException: call_from_thread(_busy_fail, …); raise`. The success path posts only its done handler (C12b-40). |
| Q-c2 detection | "a `ConfirmQuestionScreen` built by it … by a marker attribute or by the title `Quit?`" | — | A private subclass `_QuitQuestionScreen(ConfirmQuestionScreen)` with no body; `action_quit` tests `isinstance`. No private attribute of `screens.py` is read, no app attribute is added (proposal P2-3). |

## Owned nodes (27) and context

- **New, data (4):** in `app.py` `SESSION_ACTION_KEYS` with the five text constants, `A2LAttachRequest` / `A2LAttachResult`, `_QuitQuestionScreen`; in `a2l.py` `A2LProgress` with `_PROGRESS_LINES`.
- **New, functions (10):** `_running_session_action`, `_refuse_if_busy`, `action_quit`, `_answer_quit`, `_exit_if_quit_pending`, `_progress_forwarder`, `_a2l_attach_worker`, `_on_a2l_attached`, `_install_attached_a2l`, `_on_a2l_attach_failed`.
- **Changed (10, app.py):** `__init__` (1 attribute), `end_busy` (12a: the quit check, A12a-07), `load_a2l_from_path`, `_load_workarea_file`, `load_from_path` (Q-a1 check only), `_start_load_worker` (Q-h1 out-list, E3 DF-8; `sync_project`, P2-2), `PreparedLoad` (1 field, Q-h1), `_apply_prepared_load` (1 store, Q-h1), `_confirm_then_load` (1 check), and one census node for the busy-check calls at the other 16 entry points and 4 Patch Editor continuations.
- **Changed (a2l.py, 2) and test list (1):** `build_section_tree`, `parse_a2l_file`; `tests/test_engine_unchanged.py::_ENGINE_PATHS`.
- **Not created:** `_finish_session_action`, `_fail_session_action` (decision table above).
- **Totals:** 27 nodes (G-C 23, G-D 4 counting the test list); 62 examples (C12b-01 … C12b-54, D12b-01 … D12b-08); 14 seams with P-1 (X12b-01 … X12b-14); 10 proposals.
- **Retired:** none.

**Imports.** `app.py`: `parse_a2l_cached` and `A2LCacheEntry` are G-A's module-level names (same file); `ConfirmQuestionScreen` is already imported from `.screens` after Inc 10; `A2LProgress` joins the existing `from .a2l import describe_curve_tag` (`app.py:214`; annotation only), so `a2l_parse.py` is not touched (it re-exports `parse_a2l_file` as the same function object, `a2l_parse.py:3-8`, so `progress=` reaches it). `a2l.py`: `import os` and `Callable` (joins the `typing` import).

## Nodes

SESSION_ACTION_KEYS / _BUSY_LINE / _QUIT_TITLE / _QUIT_BODY / _QUIT_YES / _QUIT_NO
req: HLR-177a, LLR-177.3f, LLR-177.4a, LLR-173.7 (TC-B100-66 extension)
in:
out: module constants
func: new (fixed S-a, S-c), module level beside 12a's `_BUSY_ACTIONS`. `SESSION_ACTION_KEYS: frozenset[BusyKey] = frozenset({"file_load", "a2l_load", "project_load", "save_project"})` (ruling Q2: reports overlap). `_BUSY_LINE = "busy: {label} is running — wait for it to finish."`. `_QUIT_TITLE = "Quit?"`. `_QUIT_BODY = "still working: {label} — wait, or quit after it finishes"`. `_QUIT_YES, _QUIT_NO = "Quit (y)", "Stay (n)"`. The dash is U+2014 in both templates.
callers: `_running_session_action` (the key set); `_refuse_if_busy` (`_BUSY_LINE`); `action_quit` (the four quit texts); TC-B100-66 (scan).
module: s19_app/tui/app.py
examples: C12b-50 (LLR-173.7, TC-B100-66 extension) the regexes `\bD\d+\b`, `\bO-\d+`, `VS-`, `LLR-`, `HLR-`, `US-`, `TC-`, `AT-` over the five text constants, and over the painted busy line and quit question of C12b-04 and C12b-19 → 0 matches (6 strings). Negative control: a mutant `_BUSY_LINE = "busy (VS-PD-3): {label} …"` → 1 match → RED.

_QuitQuestionScreen
req: LLR-177.4, LLR-177.4a, Q-c2
in: str title; str body; str yes_label; str no_label (inherited)
out: a `ConfirmQuestionScreen` (a `ModalScreen[bool]`)
func: new, private, module level in `app.py`: `class _QuitQuestionScreen(ConfirmQuestionScreen): """The quit question (HLR-177b); a subclass only so ``action_quit`` can recognise it on the stack (Q-c2)."""` — no body. It inherits `AUTO_FOCUS = "#confirm_no"`, the `y` / `n` / `escape` bindings, the `Text` labels and the `_dismissed` guard (Inc 10). `check_action`'s whole-stack `isinstance(s, (LoadDialog, ConfirmQuestionScreen, SaveProjectScreen))` test also covers it, so `ctrl+l`, `ctrl+s`, `ctrl+k`, `ctrl+d` are inert under it (Inc 10 C45, unchanged). Proposal P2-3.
callers: `action_quit` (push and the stack test).
module: s19_app/tui/app.py
examples: see C12b-18 (focus on `#confirm_no`), C12b-20 (Q-c2), C12b-19 (texts). Probe P2-b Q1 (executed, the same shape on a minimal app): `stack ['Screen', 'QuitQuestion'] focused no`.

S19TuiApp.__init__
req: LLR-165.2 (TC-B100-09 extension), HLR-177c
in: (unchanged)
out: None
func: changed: one attribute line beside 12a's `self._busy = _BusyState()`: `self._quit_pending: bool = False`. It is the only new app attribute of Inc 12b (requests and results are never stored on the app; seam X12b-08). Test side: `tests/test_b100_session_reset.py` `SNAPSHOT_EXCLUSIONS["_quit_pending"] = "quit confirmed while a session action runs; UI control state, not session state (Inc 12b)"`.
callers: Textual app construction (unchanged).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._quit_pending] (initial False)
examples: C12b-49 (LLR-165.2, TC-B100-09) `test_tc_b100_09_domain_matches_the_live_source_census` before the exclusion entry → RED with `unclassified census names: ['_quit_pending']` (exactly 1 name from both P-1 and P-2 together, seam X12b-08); after the entry → 0 unclassified. Negative control: the entry left out → RED. A mutant that stores the A2L request as `self._a2l_request` → 2 unclassified → RED.

S19TuiApp._running_session_action
req: HLR-177a, LLR-177.3f, LLR-177.4, LLR-177.4d
in:
out: Optional[_BusyRun] run
func: new (fixed S-a). Main thread only. `return next((run for key, run in reversed(self._busy.runs.items()) if key in SESSION_ACTION_KEYS), None)`. Reads `self._busy.runs` (12a S-b: ordered, newest last; `_BusyRun.label` already painted); writes nothing.
callers: `_refuse_if_busy`, `action_quit`, `_exit_if_quit_pending`.
module: s19_app/tui/app.py
examples: C12b-01 (S-a, ruling Q2) synthetic runs through `begin_busy` with 12a's labels: (a) `report` then `save_project` → the `save_project` run; (b) `save_project` then `report` (the report is the shown run) → still the `save_project` run; (c) `report` alone → `None`; (d) no run → `None`; (e) `file_load` then `a2l_load` → the `a2l_load` run (the newest session run). Result 5 of 5. Negative control: a mutant that returns the newest run of any key → arm (b) returns the report run, and the busy line would name `Generating the project report` → RED.

S19TuiApp._refuse_if_busy
req: HLR-177a, LLR-177.3, LLR-177.3a, LLR-177.3b, LLR-177.3c, LLR-177.3d, LLR-177.3e, LLR-177.3f, LLR-177.3g, LLR-177.3h
in:
out: bool refused
func: new (fixed S-a). Steps:
- (1) `run = self._running_session_action()`; `run is None` → `return False`.
- (2) `self.set_status(_BUSY_LINE.format(label=run.label))` — one status-log line (`#log_line_*`, markup off); never `#status_text` (12a's indicator keeps it, HLR-176d).
- (3) `self.logger.info("Request refused while busy: %s", run.label)`.
- (4) `return True`.
- No `focus`, no `push_screen`, no `notify`, no session write (LLR-177.3g). Call form at every site: `if self._refuse_if_busy(): return` as the site's first statement (the census node below lists the sites).
callers: the 16 entry points and 4 continuations of the census node; `_confirm_then_load` (2 sites); the 4 action starts `load_from_path`, `load_a2l_from_path` (this group), `_handle_load_project` (G-A), `_commit_project_save` (G-B) (Q-a1, seam X12b-01).
module: s19_app/tui/app.py
examples: C12b-02 (LLR-177.3f, LLR-177.3g) idle → `False`, 0 log lines, 0 INFO lines. During a Save of `P1` held at `place_into_workarea` → `True`; `log_lines[-1] == "busy: Saving project P1 is running — wait for it to finish."`; the log grew by exactly 1; T still reads the progress line (`<glyph> Saving project P1  ·  step 2/4 Place the files  ·  <mm:ss>`); `app.focused`, the screen-stack depth and the session digest equal their values before; 0 toasts (`app._notifications` unchanged). Result 2 + 6. Negative control: code read on base, no busy state exists (E1 HLR-177a control) → RED; a mutant that paints the line with `set_file_status` → T changes → RED.
examples: C12b-03 (HLR-177a boundary, ruling Q2) a report held open (`begin_busy("report", "Generating the project report", …)`) and no session run → `l` → `LoadDialog` on the stack, 0 busy lines. Negative control: a mutant whose `SESSION_ACTION_KEYS` holds `report` → 1 busy line, 0 dialogs → RED.
examples: C12b-04 (LLR-177.3f hostile name) a project folder `[b]P` loaded and held at its worker step → `l` → the line `busy: Loading project [b]P is running — wait for it to finish.` painted with 0 markup spans (`#log_line_4` render has no style spans); a folder named `A` + U+202E + `B` → `busy: Loading project AB is running — wait for it to finish.` (the label came through `_busy_begin_action`'s one `painted_names`, 12a Q-2). 0 decision ids. Result 3 of 3. Negative control: a mutant that paints a fixed `busy` with no label → the label arm RED.

Busy-check census (the other 16 entry points and 4 Patch Editor continuations)
req: HLR-177a, LLR-177.3, LLR-177.3b, LLR-177.3c, LLR-177.3d, LLR-177.3e, LLR-177.3g
in: (each site's own parameters, unchanged)
out: None
func: changed: each site gains `if self._refuse_if_busy(): return` as its first statement. Nothing else changes in these bodies.
- Entry points (fixed S-a list minus `_confirm_then_load`, which has its own node): `action_load_file`, `action_load_project`, `action_select_variant`, `action_unload_all`, `on_loaded_artifacts_panel_unload_requested`, `action_save_project` (G-B's node body; only this line is G-C's, seam X12b-01), `on_patch_editor_panel_action_requested` (top of the dispatcher, before `service = self._change_service`, so all 11 `PATCH_ACTIONS_V2` arms and the unsupported-action arm are refused — `save_doc`, `execute_scope`, `validate_doc`, `run_checks` included; baseline Surprise 4, E2 ruling "LLR-177.3e"), `on_patch_editor_panel_save_back_decision`, `on_patch_editor_panel_undo_requested`, `on_patch_editor_panel_redo_requested`, `action_patch_undo`, `action_patch_redo`, `on_patch_editor_panel_edit_json_requested`, `on_patch_editor_panel_entry_edit_json_requested`, `on_patch_editor_panel_change_file_selected` (before the F1 containment guard), `on_patch_editor_panel_dirty_load_requested`.
- Continuations (the results of a modal opened while idle; proposal P2-5): `_apply_changeset_json_edit` (the `ChangeSetJsonScreen` result; LLR-177.3e's threshold names "an edit-JSON result"), `_apply_entry_json_edit` (the `EntryJsonScreen` result; "an entry edit-JSON result"), and the accept arm of the two `LoadGuardScreen` `_answer` closures (in `on_patch_editor_panel_dirty_load_requested` and, post-10, in `on_patch_editor_panel_change_file_selected`), placed after the cancel arm and before `_patch_editor_load`. These modals do not make `ctrl+s` / `ctrl+l` inert (`check_action` covers only `LoadDialog`, `ConfirmQuestionScreen`, `SaveProjectScreen`), so a Save can start over them; without the check their result would change the document during the save, and the save's `panel.mark_saved()` would mark it saved (ruling Q3's silent loss).
- `on_patch_editor_panel_undo_requested` calls `action_patch_undo`; the outer check refuses first, so 1 line per refusal (the same for redo).
callers: Textual key, palette and message dispatch (unchanged); `on_button_pressed` (`#ws_load_project_button` → `action_load_project`, unchanged); `_handle_load_result` (`v` → `action_select_variant`, unchanged); the modals' dismiss callbacks (continuations, unchanged).
module: s19_app/tui/app.py
examples: C12b-05 (HLR-177a) during a Save of `P1` held at `place_into_workarea`, with a case_01 image loaded, one patched byte applied and `W/temp/x.s19` listed: `l`; a `#files_list` pick of `x.s19`; `v`; `U`; `app.on_patch_editor_panel_save_back_decision(PatchEditorPanel.SaveBackDecision("firmware.s19", 32))`; a Patch apply (`panel.request_action("apply_doc")`); a Patch undo (`ctrl+z` on the Patch window, i.e. `action_patch_undo`); `ctrl+s` → 8 lines, each `busy: Saving project P1 is running — wait for it to finish.`; the session digest unchanged after each; the screen-stack depth 1 after each (8 of 8). Released → `Saved project to …` paints and the save completes. Negative control: code read on base (no busy state; Save runs synchronously, P12b-6) → RED. Mutation: `action_select_variant` without its check → `SelectVariantScreen` pushed → depth 2 → RED.
examples: C12b-06 (LLR-177.3) during a project load of `P` held at `read_project_manifest`: `l`, `ctrl+l`, `p`, a click on `#ws_load_project_button`, the palette entries `load_file` and `load_project` (selected through the app palette) → 6 lines `busy: Loading project P is running — wait for it to finish.`, 0 `LoadDialog` on the stack (6 of 6). Negative control: code read on base, `action_load_file` pushes the dialog unconditionally (`:7329`) → RED.
examples: C12b-09 (LLR-177.3b) during a held Save of `P1` with project `PV` open: `v` and the palette entry `select_variant` → 2 lines `busy: Saving project P1 is running — wait for it to finish.`, 0 `SelectVariantScreen` (2 of 2). Negative control: code read `:7509` → RED.
examples: C12b-10 (LLR-177.3c) during a held Save of `P1` with case_01's image, MAC and A2L loaded: `U` and the Loaded panel's `[u]` on the A2L slot (`LoadedArtifactsPanel.UnloadRequested("a2l")`) → 2 lines, the session digest unchanged, `current_a2l_path` unchanged (2 of 2). Negative control: code read `:14668` → RED.
examples: C12b-11 (LLR-177.3d) during a project load of `P` held at its worker step: `ctrl+s`, `s` and the palette entry `save_project` → 3 lines `busy: Loading project P is running — wait for it to finish.`, 0 `SaveProjectScreen`; during a held Save of `P1`: `ctrl+s` → 1 line `busy: Saving project P1 is running — wait for it to finish.` (4 of 4). Negative control: code read `:7355` → RED.
examples: C12b-12 (LLR-177.3e, ruling Q3, Surprise 4) during a held Save of `P1`, one entry in the document and a patched image: the dispatcher actions `apply_doc`, `add_entry`, `edit_entry`, `remove_entry`, `load_doc`, `parse_paste`, `refresh_doc`, `validate_doc`, `run_checks`, `save_doc`, `execute_scope`; `UndoRequested`, `RedoRequested`; a `SaveBackDecision`; `EditJsonRequested`; `EntryEditJsonRequested` → 16 busy lines; after each, the image SHA-256 and `[e.to_dict() for e in service.document.entries]` equal their values before, and 0 screens were pushed (16 of 16). Negative control: a mutant that refuses only `apply_doc` and undo (the old list) → the `add_entry` arm adds an entry that the save's committed tail then marks saved (`panel.mark_saved()`) although no file holds it → RED.
examples: C12b-13 (LLR-177.3e continuations, P2-5) four arms, each opened while idle, then a Save of `P1` started over the modal with `ctrl+s` (not inert under these modals) and held: (a) `ChangeSetJsonScreen` open → its result `'{"entries": []}'` reaches `_apply_changeset_json_edit` → 1 busy line, the document's entries unchanged; (b) `EntryJsonScreen` result → `_apply_entry_json_edit` → 1 line, the entry unchanged; (c) the dirty-load `LoadGuardScreen` accepted → 1 line, 0 `_patch_editor_load` calls; (d) the dropdown `LoadGuardScreen` (post-10) accepted → 1 line, 0 loads. Released → the save's tail runs `panel.mark_saved()` over the document as it was when the save began; the document file on disk and the panel hold the same entries (4 of 4). Negative control: a mutant without the continuation checks → arm (a) replaces the entries during the save, and the tail marks a document saved that no file holds → RED.
examples: C12b-14 (LLR-177.3g, focus arms) during a held Save of `P1`: focus on `#files_list`, then `l`; focus on `#search_input` (an `Input`), then `ctrl+l` (`l` would type); focus on the rail, then `p` → 3 refusals; for each, `app.focused` is the same widget object, the stack depth is 1 and the digest is unchanged (3 × 3). Negative control: a mutant that focuses the status log before painting → the focus arm RED.

S19TuiApp.#patch_paste_text read-only during a project load
req: HLR-177a (the E1 Q3 family), S12b-04
in: (none)
out: None
func: new (E3 S12b-04). While a `project_load` run exists, the Patch Editor's `#patch_paste_text` TextArea is read-only: the project-load begin (`_handle_load_project` step 2, after `_busy_begin_action("project_load", …)`) sets `text_area.readonly = True`, and `end_busy`'s hand-back for a `project_load` run clears it (`readonly = False`). 2 lines, no new state (seam X-15 with P-1). Save is unaffected (the commit reads the paste text at commit time, and a changed buffer keeps the panel dirty); a project load's install reset would otherwise clear a paste the user typed during the ~5.8 s worker step with no question asked (the load question was already answered).
callers: `_handle_load_project` (set), `end_busy` (clear).
module: s19_app/tui/app.py
modify: [UI: PatchEditorPanel.#patch_paste_text.readonly]
examples: C12b-55 (E3 S12b-04) `P6` loaded with `read_project_manifest` held on a forced slow step; during the hold the user presses keys over `#patch_paste_text` → the TextArea's `readonly` is `True`, so the typed text is not inserted and the panel does not turn dirty; after the install (the run ended), `readonly` is `False` and typing inserts normally (3 of 3). Negative control: a design that leaves the TextArea editable during the load → the install's reset empties the typed text with no question → RED.

S19TuiApp._confirm_then_load
req: LLR-177.3a, LLR-174.4 (TC-B100-72 extension), HLR-177a
in: QuestionKind kind; str target; Callable[[], None] go
out: None
func: changed (post-10 body; Inc 10 graph C02–C09). Steps:
- (0) New first statement: `if self._refuse_if_busy(): return` — before `_load_would_lose`, so the load question is never pushed while busy (fixed S-e, LLR-177.3a).
- (1)–(3) unchanged: `items`; empty → `go()` at once; else push `ConfirmQuestionScreen(title, body, "Replace (y)", "Cancel (n)")` with the local `answer`.
- (4) unchanged: the replace arm stays `self.call_after_refresh(go)`. The deferred `go_if_idle` re-check is **removed** (E3 A12b-03, P2-6 reversed: the palette offers only system commands here, `focus_palette` is inert under the question, and non-priority keys do not pass a modal, so the window `go_if_idle` guarded cannot be reached).
- The cancel arm is unchanged.
callers: `_route_load_project` (G-A's `go`), `_load_path_from_user_input` (a2l and data arms), `_load_workarea_file`, `_handle_select_variant` (post-10; not in code at base, extractor not run). Unchanged set.
module: s19_app/tui/app.py
examples: C12b-07 (LLR-177.3a, TC-B100-72 extension) a case_01 image with one patched byte (unsaved), project `PV` open, and an A2L attach of case_06 held at `parse_a2l_cached`: a `#files_list` pick of `x.s19`, and a direct `app._handle_select_variant("firmware_b")` (the selector's dismiss callback) → 2 lines `busy: Loading firmware.a2l is running — wait for it to finish.`; 0 `ConfirmQuestionScreen` pushed; the session digest unchanged; `_pending_variant_id is None` (the stamp sits inside `go`). Result 4 of 4. Negative control: a mutant that runs the busy check after the question (inside `go` only) → 1 question pushed before the refusal → RED.

S19TuiApp.action_quit
req: HLR-177b, LLR-177.4, LLR-177.4a, LLR-177.4d, Q-c2
in:
out: None
func: new, a sync override of Textual's `async App.action_quit` (`textual/app.py:4460`; `run_action` awaits either form, baseline Surprise 10). Steps:
- (1) `run = self._running_session_action()`; `run is None` → `self.exit()`; return (LLR-177.4d).
- (2) `any(isinstance(s, _QuitQuestionScreen) for s in self.screen_stack)` → return (Q-c2: `ctrl+q` is a priority binding and `quit` is not inert, so it reaches here under the question; probe P2-b Q1).
- (3) `self.push_screen(_QuitQuestionScreen(_QUIT_TITLE, _QUIT_BODY.format(label=run.label), _QUIT_YES, _QUIT_NO), self._answer_quit)`. The question starts on `#confirm_no` by its own `AUTO_FOCUS`.
callers: `q` (`BINDINGS` `("q", "quit", "Quit")`, non-priority: a modal keeps it, LLR-174.2g); `ctrl+q` (Textual `App.BINDINGS`, priority); the palette entry `quit` (built from `BINDINGS`). Test: `test_b97_key_bar.py:1238` monkeypatches `S19TuiApp.action_quit` (holds, census C13).
module: s19_app/tui/app.py
modify: [Data: App.screen_stack] (push 1 question while a session action runs)
examples: C12b-18 (LLR-177.4, HLR-177b) during a Save of `P1` held at `place_into_workarea`: `q` → stack `['Screen', '_QuitQuestionScreen']`, `app.focused.id == "confirm_no"`, `app.is_running`; `n`; `ctrl+q` → the same; `n`; the palette entry `quit` → the same (3 × 3). Negative control: code read on base, `S19TuiApp` defines no `action_quit`; Textual's calls `self.exit()` → 0 questions → RED. Probe P2-b Q1 (executed, minimal app): `busy q -> ['question'] stack ['Screen', 'QuitQuestion'] focused no`.
examples: C12b-19 (LLR-177.4a) the question of C12b-18 paints `#confirm_title` `Quit?`, `#confirm_body` `still working: Saving project P1 — wait, or quit after it finishes`, `#confirm_yes` `Quit (y)`, `#confirm_no` `Stay (n)`; `Replace` occurs 0 times in the 4 strings; 0 decision ids (6 of 6). Boundary, each 12b action as the running one: an A2L attach of case_06 held → body `still working: Loading firmware.a2l — wait, or quit after it finishes`; a project load of `P` held → body `still working: Loading project P — wait, or quit after it finishes`. Negative control: a mutant that pushes the Inc 10 load-question texts → `Replace (y)` painted → RED.
examples: C12b-20 (Q-c2) with the question of C12b-18 open: `ctrl+q` → stack depth unchanged (2), still 1 `_QuitQuestionScreen`, `action_quit` entered twice (spy) (2 of 2). Probe P2-b Q1 (executed): `busy ctrl+q under the question -> quit-ignored quit_calls 2 stack depth 2`. Negative control: step (2) removed → a second question stacked (depth 3) → RED.
examples: C12b-27 (LLR-177.4d) no session action: `q` → the app exits, 0 questions, `return_code == 0`; a fresh app, `ctrl+q` → the same (2 of 2). The Inc 10 load question open and idle: `q` → the question keeps the key (non-priority binding under a modal), 0 exits, `app.is_running` (1). With only a report held open: `q` → exits at once (a report is not a session action). Result 4 of 4. Negative control: a mutant that always asks → the idle arm pushes a question → RED. Probe P2-b Q1: `idle q -> ['exit-idle'] running app: False`.

S19TuiApp._answer_quit
req: LLR-177.4b, LLR-177.4c, HLR-177c
in: Optional[bool] quit
out: None
func: new (fixed S-c). `self._quit_pending = bool(quit)`, then `self._exit_if_quit_pending()`. `False` / `None` (Stay, `n`, `escape`, an immediate `enter` on `#confirm_no`) → the flag is `False` and nothing else happens; a second question answered Stay therefore cancels an earlier confirmed quit (a deliberate reading of "Stay keeps the app running"; E1 §5 lets a second question open). `True` → the flag is set, and the app exits at once when no session action still runs (the action ended while the question was open), else at the action's end (`end_busy`).
callers: `_QuitQuestionScreen`'s dismiss callback (from `action_quit`).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._quit_pending]
examples: C12b-21 (LLR-177.4b) during a held Save of `P1`, three questions answered `n`, `escape`, and an immediate `enter` → each closes the question, `app.is_running`, `_quit_pending is False`; released → `Saved project to <W>\P1 (variant 'firmware')` paints (the outcome line, 12a A12-46 form) and the app still runs (3 of 3). Negative control: a mutant that exits on any answer → the `n` arm stops the app → RED.
examples: C12b-26 (boundaries) (a) the action ends while the question is open, then `y` → the app exits at once (`_running_session_action() is None`); (b) `q`, `y` (pending), then `q` again → a second question (the first is closed) → `n` → `_quit_pending is False`; released → the save completes and the app keeps running (2 of 2). Probe P2-b Q4 (executed, arm (a)): `stale y -> […, 'answer True', 'exit-after-end'] running app: False`, `return_code 0`. Negative control for (b): `_quit_pending = _quit_pending or bool(quit)` → the app exits after the save although the last answer was Stay → RED.

S19TuiApp._exit_if_quit_pending
req: LLR-177.4c, HLR-177c, LLR-177.3h
in:
out: None
func: new (fixed S-c). `if self._quit_pending and self._running_session_action() is None: self.exit()`. Never waits on a thread (P12b-3; a main-thread wait would deadlock with the worker's blocking `call_from_thread`). Called from `_answer_quit` and from inside `end_busy` (A12a-07).
callers: `_answer_quit`; `end_busy` (effective branch).
module: s19_app/tui/app.py
examples: see C12b-22 … C12b-25, C12b-28.

S19TuiApp.end_busy
req: LLR-177.4c, LLR-177.3h, HLR-177c (12a's LLR-176.1f … .1o unchanged)
in: BusyKey key; int gen; str outcome
out: bool ended
func: changed (12a node, A12a-07). Steps (1)–(5) exactly as 12a's node: the outcome line; the generation check (`False`, nothing else); remove the run; repaint the newest remaining run, or the last-end hand-back (timer stopped, `-busy` removed, bar 0, `file_state` painted). New step (5b), immediately before `return True`: `self._exit_if_quit_pending()`. So every effective end — the session handlers' end calls, `_busy_fail`, `_handle_load_error` — reaches the quit check after its hand-back, and a stale end (`False`) does not. **Rule for every session action's main-thread end handler (fixed S-c, unchanged): the end call is its last statement**, so a confirmed quit exits after everything the handler does (seam X12b-02).
callers: 12a's list (unchanged), plus `_install_attached_a2l`, `_on_a2l_attach_failed` (G-C) and P-1's handlers (`_on_project_loaded` refusal arm, `_install_prepared_project`, `_on_project_load_failed`, `_on_project_saved`). Not in code at base (extractor not run).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._busy] (unchanged), [Process: app exit] (when a quit is pending and no session run remains)
examples: C12b-22 (LLR-177.4c, save arm; seam X12b-02 / X12b-11) a Save of `P1` held at `place_into_workarea`: `q`, `y` → `app.is_running` while held (1); released → the app exits (`return_code == 0`), and `W/P1/project.json` exists and `verify_written_manifest(W/P1, …)` reports verified (2). Negative control: a mutant that exits on `y` → the app stops while the step is held → RED. Executed P12b-3: after `App.exit()` a worker's callback still lands on a stopped app, so exiting at once would run the save's end handler on a stopped app.
examples: C12b-23 (LLR-177.4c, HLR-177c error arm; E3 S12b-01) as C12b-22, but the held `place_into_workarea` raises `OSError(28, "synthetic no space")` after release → the Save worker rolls back (G-B); `_on_project_saved`'s failure arm sets `_quit_pending = False`, so the app **keeps running** with the failure line as `log_lines[-1]` and the failure toast shown; `W/P1` does not exist; 0 partial folders under `W`; the pasted entries are kept (3 of 3). Negative control: the exit-at-once mutant → the app stops before the rollback reports → RED.
examples: C12b-24 (LLR-177.4c, project-load arm; seam X12b-02) a project load of `P` held at `read_project_manifest`: `q`, `y`; released → G-A's install runs (its end is last) and the app exits; at exit `current_project == "P"` and `current_file.path.name == "firmware.s19"`; 0 `ERROR` records in the log (1 of 1). Negative control: a mutant whose `_install_prepared_project` calls `end_busy` before `_reset_project_session` and the installs → the app exits before the install → `current_project` is still the previous value at exit → RED.
examples: C12b-25 (LLR-177.4c, A2L arm) an A2L attach of case_01 held at `parse_a2l_cached`: `q`, `y`; released → `_install_attached_a2l` runs (`current_a2l_path == W/temp/firmware.a2l`, `update_a2l_view` entered once, spy) and its end is the last statement, then the app exits, `return_code == 0` (3 of 3). Negative control: 12a's order (the end before `update_a2l_view`) → the app exits with `update_a2l_view` entered 0 times → RED. Probe P2-b Q3 (executed, the same shape): `after y while held -> running app: True`; `released -> […, 'on_done: step painted', 'install', 'exit-after-end', …] running app: False`; `return_code 0`.
examples: C12b-28 (step 5b scope) (a) `_quit_pending = True`, a report held open and a Save ending → the app exits at the Save's end (the report is not a session action); (b) a Save held and a report ending → no exit (a session run remains); (c) a stale `end_busy("save_project", 99, "x")` → `False`, no exit (3 of 3). Negative control: a check placed only in G-B's handler (the S-c wrapper form) → a file load ending through `_handle_load_error` (12a `end_busy("file_load", gen, "Load failed")`) with a quit pending does not exit → RED.

S19TuiApp._progress_forwarder
req: LLR-177.5, LLR-177.5a, LLR-176.1q
in: BusyKey key; int gen; int n
out: A2LProgress forward
func: new (fixed S-f; G-C1 writes it, P-1 calls it). Returns a closure for the worker thread:
- `last: list[Optional[int]] = [None]`;
- `def forward(done: int, total: int) -> None:` `pct = (100 * done) // total if total > 0 else 0`; `if pct != last[0] or done >= total:` `last[0] = pct`; `self.call_from_thread(self.step_busy, key, gen, n, done, total)`;
- `return forward`.
- It forwards at most once per percent plus every report at or past the total, so at most about 101 blocking round trips per step (`call_from_thread` waits for the main thread). It closes over `key`, `gen`, `n` and reads no session attribute (LLR-177.1e). It is created and called on the worker; `step_busy` runs on the main thread (LLR-176.1q).
callers: `_a2l_attach_worker` (step 2, bytes); G-A's project worker (step 2, bytes); G-B's Save worker (step 2, `done` = files placed, `total` = files the plan places) (seam X12b-03).
module: s19_app/tui/app.py
examples: C12b-33 (S-f) `f = app._progress_forwarder("a2l_load", g, 2)` called on a `threading.Thread` with `(0, 400)`, `(1, 400)`, `(2, 400)`, `(4, 400)`, `(400, 400)`, `(400, 400)`, with `app.call_from_thread` replaced by a recorder → 4 forwards `[(0, 400), (4, 400), (400, 400), (400, 400)]`, each as `(app.step_busy, "a2l_load", g, 2, done, 400)` (1 sequence equality). `total = 0` → `(0, 0)` forwarded once (pct 0, `done >= total`). Probe P2-a V2 (executed with the designed callback): case_06 → 254 reports, 101 forwarded (`pct 0 … 100`); case_01 → 1 report, 1 forwarded. Negative control: a mutant that forwards every report → 6 forwards here, 254 for case_06 → RED.

A2LAttachRequest / A2LAttachResult
req: LLR-177.1e, LLR-177.1b
in:
out: types
func: new (fixed S-b), frozen dataclasses exactly as `interfaces-12b.md`: `A2LAttachRequest(source: Path, copy: bool, temp_dir: Path, workarea: Path, record_recent: bool, a2l_cache: Optional[A2LCacheEntry], gen: int)`; `A2LAttachResult(request: A2LAttachRequest, path: Path, entry: A2LCacheEntry, parse_seconds: float)` (E3 A12b-04: `copy_seconds` is dropped — the worker logs it and `_install_attached_a2l` reads only `parse_seconds`). Built on the main thread (request) and on the worker (result); never stored on the app.
callers: `load_a2l_from_path` (builds the request); `_a2l_attach_worker` (reads it, builds the result); `_on_a2l_attached`, `_install_attached_a2l`, `_on_a2l_attach_failed` (read them).
module: s19_app/tui/app.py
examples: C12b-54 (LLR-177.1e, the request half) `dataclasses.is_dataclass(A2LAttachRequest)` and `A2LAttachRequest.__dataclass_params__.frozen` (2); `_a2l_attach_worker`'s one parameter is annotated `A2LAttachRequest` (1). Assigning `request.copy = True` raises `FrozenInstanceError` (1). Negative control: a plain `@dataclass` request → `frozen` is `False` → RED.

S19TuiApp.load_a2l_from_path
req: HLR-177, LLR-177.1b, LLR-177.1e, LLR-177.3h, Q-a1, LLR-176.2c (re-derived)
in: Path path; keyword-only bool copy = True
out: None
func: changed (post-9b body, post-12a begin / steps / ends). The function becomes the main-thread kickoff (fixed S-b, S-d). Steps:
- (1) `if self._refuse_if_busy(): return` (Q-a1: an action start).
- (2) Unchanged refusals, before any begin: `resolve_input_path`; `A2L file not found: <path>`; `Unsupported A2L type: <suffix>`; the open project's guard (`validate_project_files` → its error line, or `Project already has an A2L file.`); the large-A2L warning (`normalized.stat()`).
- (3) The recent decision, on the main thread (post-9b rule): `typed = Path(str(path).strip().strip('"')).expanduser()`; `via_fallback = normalized.is_absolute() and not typed.is_absolute()`; `outside = not contained_in_workarea(normalized, self.workarea)`; `record = outside and not via_fallback`; `outside and via_fallback` → the INFO line `Recent source not recorded (found through the fallback): %r` (now at the kickoff). The store write itself moves to the install handler (proposal P2-9).
- (4) `gen = self._busy_begin_action("a2l_load", normalized.name)` (12a, replaces `set_progress(10, …)`).
- (5) `try:` `request = A2LAttachRequest(source=normalized, copy=copy, temp_dir=self.workarea / WORKAREA_TEMP, workarea=self.workarea, record_recent=record, a2l_cache=self._a2l_cache_entry(), gen=gen)`; when `not copy`: `self.step_busy("a2l_load", gen, 2)` (no copy step; 12a allows a skipped step); `self._a2l_attach_worker(request)`; `except BaseException: self._busy_fail("a2l_load", gen); raise` — 12a's `finally` becomes `except BaseException` because the run now outlives the function (fixed S-d, 12a F-1 / P-7).
- Gone from this body (moved to the worker and the handlers): `copy_into_workarea`, `record_recent_source`, `refresh_files`, the `A2L copy complete` log, `current_a2l_path` / `current_a2l_data`, `_load_a2l_data_with_cache`, `current_file.a2l_*`, `update_a2l_view`, labels, Loaded panel, the outcome, the focus re-home, `_sync_loaded_a2l_to_project`.
- `copy=False` is used only by `_load_workarea_file` (the file is already in `W/temp`; 12a's pick-time re-check enforces the link and size rules there, so 9b's self-copy, A9b-05, goes).
callers: baseline extractor: `_load_from_item` (direct, :13333) and the unmarked site `_load_path_from_user_input` :12939. After 12b: `_load_path_from_user_input` (inside the post-10 `go`; typed, recent and the start-up `load_path`), `_load_workarea_file` (`go`, `copy=False`). `_load_from_item` reaches it only through `_load_workarea_file` (post-9b). Tests: 28 direct sites in 10 files (census pass 4); the W sites poll and hold, the P / N sites are re-pinned (census A7 and the 12a examples, "Re-pins" below).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._busy] (begin)
examples: C12b-29 (LLR-177.1b, HLR-177 A2L arm) a thread-id spy on `copy_into_workarea` and `parse_a2l_cached` (recording `threading.get_ident()` against the `run_test` thread): a typed `<tmp>/cal.a2l` (Load dialog), a recent `<tmp>/cal2.a2l`, a Workarea Files pick of `c.a2l`, and `S19TuiApp(load_path=<tmp>/cal3.a2l)` (start-up) → the parse ran off the main thread 4 of 4; the copy ran off the main thread for the 3 copying routes (3 of 3); the pick made 0 `copy_into_workarea` calls (1). Each ends with `A2L loaded: <name>`. Negative control: executed P12b-4 on base, `load_a2l_from_path(case_06)`: `ran on main thread True`, wall 8.76 s, 0 ticks → RED.
examples: C12b-30 (LLR-177.1b success sequence, LLR-176.2c re-derived) `load_a2l_from_path(case_01/firmware.a2l)`, then `wait_for_complete()` and 2 pauses: 1 begin `Loading firmware.a2l`; `step_busy` calls `[2 (worker, after the copy), 2 with (1444, 1444) (the one byte report), 3 (main)]`; bar spy `[0, 33, 66, 66, 0]`; log lines added `['A2L loaded: firmware.a2l']`; `current_a2l_path == W/temp/firmware.a2l`; `app._a2l_cache_key[0] == str((W/temp/firmware.a2l).resolve())`; 1 effective end; T reads the file state it read before (`Ready.`); `_busy.runs == {}`. Result 8 of 8. Negative control: executed p12a U1.4 on base, spy `[10, 50, 100]`, 4 log lines → RED.
examples: C12b-31 (LLR-177.1c, A2L arm) a 0.1 s `set_interval` counter started before `load_a2l_from_path(case_06/firmware.a2l)` → at least 10 ticks between the worker's start (spy on `_a2l_attach_worker`'s first statement) and `_on_a2l_attached` (P2-a: the parse alone takes 6.6 s on the loaded host). Negative control: executed P12b-4, 0 ticks during 8.76 s → RED.
examples: C12b-41 (refusals before the begin, Q-a1) a missing `x.a2l` → `A2L file not found: x.a2l`; an existing `x.txt` → `Unsupported A2L type: .txt`; project `P` (which holds `firmware.a2l`) open → `Project already has an A2L file.`; each with 0 begins and 0 worker starts (3 of 3; holds post-12a, A12-41). During a held Save of `P1`: `load_a2l_from_path(<tmp>/cal.a2l)` → 1 busy line and 0 `resolve_input_path` calls (spy) (1). Negative control: a begin placed before the refusals → the missing-file arm records 1 begin → RED; the busy check placed after `resolve_input_path` → 1 resolve call → RED.
examples: C12b-42 (recents, P2-9) a typed `<tmp>/src/cal.a2l` → after the install the store's first entry is `<tmp>\src\cal.a2l` (1); the same with `parse_a2l_cached` forced to raise `ValueError` → the store bytes are unchanged (1, a declared change from base, where the record ran before the parse); a relative `cal.a2l` found only through the base-folder fallback → not recorded, with the INFO line (1) (holds post-9b for the last arm). Negative control: a mutant that records at the kickoff → the failed-parse arm changes the store bytes → RED.

S19TuiApp._a2l_attach_worker
req: HLR-177, LLR-177.1b, LLR-177.1c, LLR-177.1d, LLR-177.1e, LLR-177.2b, LLR-177.5, LLR-176.1l, LLR-176.1q
in: A2LAttachRequest request
out: None
func: new, `@work(thread=True, group="a2l_load", exit_on_error=True)` (decision table; Q-d1). Reads only `request` (plus `self.call_from_thread`, `self.logger`, `self._progress_forwarder`, and the module functions `copy_into_workarea`, `parse_a2l_cached`, `time.perf_counter`). Body:
```python
try:
    try:
        started = time.perf_counter()
        if request.copy:
            path = copy_into_workarea(request.source, request.temp_dir, workarea_root=request.workarea)
            copy_seconds = time.perf_counter() - started
            self.logger.info("A2L copy complete: path=%s size_bytes=%d copy_seconds=%.3f",
                             path, path.stat().st_size, copy_seconds)
            self.call_from_thread(self.step_busy, "a2l_load", request.gen, 2)
        else:
            path, copy_seconds = request.source, 0.0
        parse_started = time.perf_counter()
        entry = parse_a2l_cached(path, request.a2l_cache,
                                 progress=self._progress_forwarder("a2l_load", request.gen, 2))
        result = A2LAttachResult(request, path, entry, time.perf_counter() - parse_started)   # copy_seconds dropped (E3 A12b-04)
    except Exception as exc:                      # the worker step's own failures (LLR-177.2b)
        if not isinstance(exc, WorkareaContainmentError):
            self.logger.exception("A2L attach failed: %s", request.source)
        self.call_from_thread(self._on_a2l_attach_failed, request, exc)
        return
    self.call_from_thread(self._on_a2l_attached, result)   # outside the inner try
except BaseException:
    self.call_from_thread(self._busy_fail, "a2l_load", request.gen)   # S12a-06; no-op after an end
    raise
```
- `progress=` is always passed (ruling Q-f2); a cache hit makes no report (the bar steps 33 → 66 at step 3).
- A handler raising on the main thread re-raises inside the worker's `call_from_thread` (12a probe ga-timer C1) → the outer guard ends the run with `Loading <name> failed` → `WorkerFailed` (Q-d1, loud).
callers: `load_a2l_from_path` (step 5). Textual runs it on a thread.
module: s19_app/tui/app.py
modify: [I/O: workarea temp] (the copy)
examples: C12b-35 (LLR-177.1d, A2L arms) a test subclass whose `__setattr__` records `(name, threading.get_ident())`, and a `ChangeService` method recorder: an A2L attach of case_01 (success) and one with `parse_a2l_cached` forced to raise → 0 writes from a thread other than the main thread (2 runs); the success run writes `current_a2l_path`, `current_a2l_data`, `_a2l_cache_key`, `_a2l_cache_data` and the view caches of baseline U4, all on the main thread. Negative control: code read on base, the file-load worker reaches `_load_a2l_data_with_cache`'s cache write (`:15851`–`:15852`); a mutant that assigns `self.current_a2l_data` in the worker → 1 off-main write → RED.
examples: C12b-36 (LLR-177.1e, AST census, A2L arm) over the post-12b `app.py`: the body of `_a2l_attach_worker` and of every `app.py` method it calls (`_progress_forwarder`; `call_from_thread` targets are values, run on the main thread, and are excluded) → 0 reads of `self.current_file`, `self.current_project`, `self.current_project_dir`, `self.current_a2l_path`, `self.current_a2l_data`, `self._variant_set`, `self._change_service` (1 count = 0). Negative control: the base body of `load_a2l_from_path` moved into a worker → it reads `self.current_project` and `self.current_file` → 2 → RED.
examples: C12b-37 (LLR-177.2b, parse arm) `parse_a2l_cached` forced to raise `ValueError("synthetic parse")` for case_01's A2L, with `p0.a2l` attached before → `log_lines[-1] == "File NOT loaded: 'firmware.a2l' could not be read — check that the file can be opened, then load again."`; `current_a2l_path` and `current_a2l_data` are those of `p0.a2l` (identity); `app.is_running`; 1 effective end with that outcome; 1 ERROR record with a traceback (`logger.exception`); `W/temp` lists `firmware.a2l` (`refresh_files` ran; the copy landed). Result 6 of 6. Negative control: executed P12b-2, an exception escaping a `@work(thread=True)` body ends the app (`WorkerFailed`, return code 1) → RED.
examples: C12b-38 (LLR-177.2b, copy arm) `copy_into_workarea` forced to raise `PermissionError(13, "synthetic denied")` → the same line for `firmware.a2l`; the A2L state unchanged; `app.is_running`; 0 `parse_a2l_cached` calls (4 of 4). Negative control: a worker whose catch covers only the parse → the copy's `PermissionError` escapes → `WorkerFailed` (P12b-2) → RED.
examples: C12b-39 (the containment arm; 12a A12-39 holds) `copy_into_workarea` forced to raise `WorkareaContainmentError("synthetic containment refusal")` → `log_lines[-1] == "Cannot load A2L: synthetic containment refusal"`; 0 lines holding `could not be read`; 0 ERROR records (a WARNING `A2L load rejected by workarea guard: …`); 1 effective end (4 of 4). Negative control: a failure handler without the containment branch → `File NOT loaded: 'firmware.a2l' could not be read — …` painted instead → RED.
examples: C12b-40 (LLR-176.1l, A2L worker arm; S12a-06) (a) `app._on_a2l_attached` patched to raise `RuntimeError("forced")` → an `end_busy` spy records `("a2l_load", g, "Loading firmware.a2l failed")` returning `True` before `run_test` raises `WorkerFailed`; (b) a successful attach posts no `_busy_fail` (spy: 0 calls; 1 effective end) (2 of 2). Negative control: the outer guard removed → arm (a) records 0 ends → RED.
examples: C12b-43 (LLR-176.1q, A2L arm) a thread-id probe on `Label.update` of T and `ProgressBar.update` during the case_06 attach (about 101 forwarded reports) → 0 writes off the main thread (1). Negative control: a mutant forwarder that calls `self.step_busy(…)` directly → at least 1 off-main write → RED.

S19TuiApp._on_a2l_attached
req: LLR-176.3, LLR-177.1d
in: A2LAttachResult result
out: None
func: new (main thread, through `call_from_thread`). `self.step_busy("a2l_load", result.request.gen, 3)` paints `step 3/3 Build the tag table` synchronously, then `self.call_after_refresh(self._install_attached_a2l, result)`, so the step name reaches the screen before the tag-table build blocks the loop (LLR-176.3; the `call_after_refresh` idiom of `app.py:8708`). It writes no session attribute. The run stays in `_busy.runs` until the install's end, so refusals and the quit question still apply during the deferral.
callers: `_a2l_attach_worker` (value passed to `call_from_thread`).
module: s19_app/tui/app.py
examples: C12b-34 (LLR-176.3, the A2L arm) a wrapper around `app.step_busy` that, after the real call with `key == "a2l_load"` and `n == 3`, schedules `app.call_after_refresh(lambda: seen.append(T))`; attach case_06 → `seen == ["<glyph> Loading firmware.a2l  ·  step 3/3 Build the tag table  ·  <mm:ss>"]` (the read ran before the install, FIFO, so before `update_a2l_view`) (1 equality, matched as `^[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏] Loading firmware\.a2l  ·  step 3/3 Build the tag table  ·  \d\d:\d\d$`). Negative control: a mutant that calls `self._install_attached_a2l(result)` directly → the install (and its end) runs first → `seen` holds the file state (`Ready.`) → RED.

S19TuiApp._install_attached_a2l
req: LLR-177.1b, LLR-177.1d, LLR-177.4c, HLR-177c, LLR-176.1l
in: A2LAttachResult result
out: None
func: new (main thread, deferred by `_on_a2l_attached`). One callback with no `await`. `req = result.request`; `copied = result.path`; `gen = req.gen`; then `try:`
- (1) `if req.record_recent and not record_recent_source(req.source): self.logger.warning("Recent sources not updated: %r", str(req.source))`;
- (2) `self.refresh_files()`;
- (3) `self._store_a2l_cache(result.entry)` (G-A, seam X12b-05); `self.current_a2l_path = copied`; `self.current_a2l_data = result.entry[1]`; `self._log_a2l_parse_summary(copied, self.current_a2l_data, result.parse_seconds)`;
- (4) `if self.current_file: self.current_file.a2l_path = copied; self.current_file.a2l_data = self.current_a2l_data`;
- (5) the timed `self.update_a2l_view()` with the base's slow / complete log lines (the tag-table build, HLR-176's declared freeze, about 3.5 s for case_06);
- (6) `self.update_project_labels()`; `self._refresh_loaded_panel()`; `self._rehome_focus_after_load()`; `self.logger.info("A2L loaded: %s", copied)`; `if self.current_project: self._sync_loaded_a2l_to_project()` — moved **before** the end (12a had them after), so the end is the last statement (proposal P2-10);
- (7) last: `self.end_busy("a2l_load", gen, safe_text(f"A2L loaded: {painted_names([copied.name])}").plain)` (12a A12a-03 text).
- `except BaseException: self._busy_fail("a2l_load", gen); raise` — the deferred callback is outside the worker, so it needs its own guard for "every exit ends its run" (LLR-176.1l, TC-B100-50); the raise then stops the app (probe P2-c: `run_test raised RuntimeError … return_code 1`, the guard ran first).
callers: `_on_a2l_attached` (through `call_after_refresh`).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.current_a2l_path] (replace), [Data: S19TuiApp.current_a2l_data] (replace), [Data: S19TuiApp._a2l_cache_key / _a2l_cache_data] (through G-A's store), [I/O: recent-sources store]
examples: C12b-30, C12b-25, C12b-42 above.
examples: C12b-52 (LLR-176.1l, the deferred arm) `app.update_a2l_view` patched to raise `RuntimeError("forced view")` during a case_01 attach → the `end_busy` spy records `("a2l_load", g, "Loading firmware.a2l failed")` → `True`, then `run_test` raises `RuntimeError` with `return_code == 1` (2 of 2; the shape of probe P2-c). Negative control: the guard removed → 0 ends recorded, the run and its timer left → RED.
examples: C12b-53 (end order, P2-10; LLR-177.4c) project `P2` (no A2L: `firmware.s19` + `project.json`) open; attach `<tmp>/cal.a2l` → `_sync_loaded_a2l_to_project` places it in `W/P2` and rewrites `project.json`; the last log line is `A2L loaded: cal.a2l` (the sync's own lines, if any, come before it) (2 of 2). Negative control: 12a's order (sync after the end) → with a quit pending, `exit()` runs before the sync's manifest rewrite → `W/P2/project.json` lacks `cal.a2l` → RED.

S19TuiApp._on_a2l_attach_failed
req: LLR-177.2b, LLR-177.3h, LLR-177.4c
in: A2LAttachRequest request; BaseException exc
out: None
func: new (main thread, through `call_from_thread`). Writes no session attribute. Steps:
- (1) `isinstance(exc, WorkareaContainmentError)` → `self.logger.warning("A2L load rejected by workarea guard: %s", exc)`; `self._quit_pending = False` (E3 S12b-01); `self.end_busy("a2l_load", request.gen, f"Cannot load A2L: {exc}")`; return (12a A12-39 text; not a `could not be read` failure, fixed S-b).
- (2) Otherwise: `if request.copy: self.refresh_files()` (a copy may have landed in `W/temp`); `self._quit_pending = False` (E3 S12b-01: a failed attach keeps the app running so the failure line is the last log line); then last: `self.end_busy("a2l_load", request.gen, f"File NOT loaded: '{painted_names([request.source.name])}' could not be read — check that the file can be opened, then load again.")` (E1 §D.3 new token row; the `File NOT loaded: '<name>' <reason> — <step>.` shape of the typed-path refusals, `app.py` post-9b :13542). `end_busy` writes it through `safe_text(...).plain`.
callers: `_a2l_attach_worker` (value passed to `call_from_thread`).
module: s19_app/tui/app.py
examples: C12b-37, C12b-38, C12b-39 above; C12b-15 below.

S19TuiApp._load_workarea_file
req: LLR-177.1k, LLR-177.1b, LLR-177.3a
in: str name
out: None
func: changed (post-9b G1 node, in code on `2305c8b`; post-10 question; post-12a pick-time re-check inside `go`, S12a-03). Steps:
- (1)–(3) unchanged: `candidate = self.workarea / WORKAREA_TEMP / name`; `os.lstat` before the question (`FileNotFoundError` → silent return); `kind` = `attach` for a MAC or A2L suffix, else `image`; `self._confirm_then_load(kind, name, go)` (its own busy checks, node above).
- In `go`, after 12a's re-check (`not a regular file` / `too large to open` lines) and the log line `Loading from workarea selection: %s`:
  - A2L arm: `self.load_a2l_from_path(candidate, copy=False)` (fixed S-e; in place, 0 copies; LLR-177.1b).
  - Data arm (fixed S-e, LLR-177.1k): `gen = self._busy_begin_action("file_load", candidate.name)`; `try:` `self.step_busy("file_load", gen, 2)`; `self._start_load_worker(candidate, gen=gen, sync_project=False)`; `except BaseException: self._busy_fail("file_load", gen); raise`. `load_selected_file` is no longer called here. `sync_project=False` keeps the base's pick behaviour, which never appends the file to the open project (proposal P2-2).
callers: `_load_from_item` (`#files_list`; extractor caller of that wrapper: `on_list_view_selected`, direct :13183); `_handle_load_dialog` (`workarea`, deferred). Unchanged set. Tests: `test_b100_focus.py:364`, `test_b100_recents.py:944`, `:2823` (`_load_from_item`), `test_b100_load_dialog.py` (`tc_b100_40`, the 0-copy spy at :593–:611) — each now waits for the worker (re-pins below).
module: s19_app/tui/app.py
examples: C12b-44 (LLR-177.1k) `big8.s19` (8 MiB of data) placed in `W/temp`; (a) a `#files_list` pick and (b) a Load dialog `workarea` row, each on its own app → the parse (`_parse_loaded_file` spy) records a non-main thread id; a 0.1 s timer ticks at least 10 times during it (12a P12a-3: 2.38 s of parse); 0 `copy_into_workarea` calls; the session digest equals that of a twin app that runs the base's synchronous `load_selected_file(W/temp/big8.s19)` (4 of 4 per surface, 8). Negative control: code read on base, `_load_from_item` → `load_selected_file` parses on the main thread (`:13325`–`:13335`) → 0 ticks → RED.
examples: C12b-45 (LLR-177.1k with a project open, P2-2) project `P` open (case_01), `W/temp/x.s19` listed → pick `x.s19` → 0 `_sync_loaded_file_to_project` calls (spy); `sorted(p.name for p in (W/"P").iterdir())` unchanged; `project.json` bytes unchanged; `_variant_set` ids unchanged (4 of 4). Negative control: `_start_load_worker(candidate, gen=gen)` with the default `sync_project=True` → `Added variant …`, `x.s19` copied into `W/P`, `project.json` rewritten → RED.
examples: C12b-46 (the pick on 12a's indicator; re-pins 12a A12-73) a pick of `W/temp/x.s19` (case_01 bytes), then `wait_for_complete()` and 2 pauses → 1 begin `Loading x.s19`; `step_busy` calls `[2 (main), 3 (worker)]`; bar spy `[0, 33, 66, 0]`; log lines added `['Loaded x.s19 (S19 only)', 'Loaded x.s19']`; T reads `Loaded x.s19 (S19 only)`; 1 effective end. A pick of `W/temp/firmware.mac` with case_01's image loaded → the same worker attaches it (`current_file.mac_path.name == "firmware.mac"`, the image unchanged) (2 arms). Negative control: 12a's body (`load_selected_file`) → 0 begins → RED.
examples: C12b-48 (race, holds post-12a) the question for `x.s19` open (a patched byte unsaved), the test deletes `W/temp/x.s19`, `y` → `go`'s `os.lstat` raises `FileNotFoundError` → silent return, 0 begins, digest unchanged (3 of 3). Negative control: a mutant that begins `file_load` before the re-check → 1 begin for a file that is never parsed → RED.

S19TuiApp.load_from_path
req: Q-a1, HLR-177a, LLR-177.3h
in: Path path
out: None
func: changed (post-12a body, otherwise unchanged): new first statement `if self._refuse_if_busy(): return`, before the `dialog_callback_entry` log line. The refusal does not touch `_pending_variant_id` (its other refusal arms clear it, but here a running action may own a pending stamp; the variant route's stamp is guarded earlier, in `_confirm_then_load`'s deferred check, P2-6). The copy stays on the main thread (ruling Q5).
callers: baseline extractor: unmarked sites `_load_path_from_user_input` :12942, `_handle_select_variant` :7611 (both inside post-10 `go`). Unchanged. Support helper `tests/support/b100_projects.py:383` (`append_variant`, census A9).
module: s19_app/tui/app.py
examples: C12b-17 (Q-a1, the 4 action starts) during an A2L attach of case_06 held at `parse_a2l_cached`: `app.load_from_path(case_01/firmware.s19)`, `app.load_a2l_from_path(<tmp>/other.a2l)`, `app._handle_load_project("P")` (G-A's start), `app._handle_save_dialog(SaveProjectPayload(str(W), "S9"))` (reaches G-B's `_commit_project_save` after the Inc 11 preparation) → 4 lines `busy: Loading firmware.a2l is running — wait for it to finish.`; `list(app._busy.runs) == ["a2l_load"]` after each; `W/S9` absent; `current_project` unchanged (4 + 3). `support/b100_projects.append_variant` called right after a project load whose worker is still held → 1 busy line, loud and deterministic (census A9; the helper is re-pinned to wait). Negative control: interfaces Q-a1 option 1 (only the 17 entry points) → `load_from_path` begins `file_load` beside `a2l_load` → 2 session runs → RED.

S19TuiApp._start_load_worker
req: LLR-177.1k, LLR-177.1d (Q-h1), LLR-177.4c
in: Path path; Optional[list[Path]] a2l_files = None; keyword-only int gen; keyword-only bool sync_project = True (proposal P2-2)
out: None
func: changed (post-12a body: `@work(thread=True, group="load")` (not exclusive, E3 DF-2), `except BaseException` guard, step 3, end after the sync, A12a-05). 12b changes:
- (a) Q-h1 (ruled yes; the out-list form, E3 DF-8 / PR-7): `out: list[A2LCacheEntry] = []`; the parse stays G-A's `_parse_loaded_file(path, a2l_files, *, a2l_cache_out=out)`, which reads `self._a2l_cache_entry()` itself and appends the entry it used or made, writing no `_a2l_cache_*`. After `_prepare_load_payload` (or its fallback `PreparedLoad(loaded=loaded)`): `prepared.a2l_cache = out[0] if out else None` before the hand-off. (No `cache_in` read at the worker start and no tuple-returning parse.)
- (b) The sync: `if sync_project and self.current_project: self.call_from_thread(self._sync_loaded_file_to_project)` (unchanged order: apply, sync, then the end — Q-c1, already 12a's A12a-05).
- The end goes through `end_busy`, which now holds the quit check (A12a-07); nothing else changes at the end sites.
callers: baseline extractor: `load_from_path` (direct, :13071). After 12b: `load_from_path` (`gen=gen`), `_load_workarea_file` (data arm, `gen=gen, sync_project=False`).
module: s19_app/tui/app.py
examples: C12b-47 (LLR-177.1d, Q-h1) case_01's `firmware.a2l` attached, then `app._a2l_cache_key = None` (forcing a miss); a `__setattr__` recorder; pick `W/temp/x.s19` → `_a2l_cache_key` and `_a2l_cache_data` are written once each, on the main thread (inside `_apply_prepared_load`), and `_a2l_cache_key[0] == str(app.current_a2l_path.resolve())` (3 of 3). Negative control: code read on base, `_start_load_worker` → `_parse_loaded_file` → `_load_a2l_data_with_cache` assigns both on the load worker (`:15851`–`:15852`) → RED.

PreparedLoad
req: LLR-177.1d (Q-h1)
in:
out: type
func: changed: one field after the existing ones, `a2l_cache: Optional[A2LCacheEntry] = None` (ruling Q-h1: "`PreparedLoad` gains one field"). Written on the worker before the hand-off, read on the main thread by `_apply_prepared_load`. `_apply_loaded_file`'s synchronous `PreparedLoad(loaded=loaded)` leaves it `None`.
callers: `_prepare_load_payload`, `_start_load_worker`, `_apply_loaded_file`, `_apply_prepared_load` (unchanged set).
module: s19_app/tui/app.py
examples: see C12b-47.

S19TuiApp._apply_prepared_load
req: LLR-177.1d (Q-h1)
in: PreparedLoad prepared; Path path; float load_started
out: None
func: changed: new first statement `if prepared.a2l_cache is not None: self._store_a2l_cache(prepared.a2l_cache)` (G-A's main-thread store, seam X12b-05). Nothing else changes.
callers: `_start_load_worker` (value passed to `call_from_thread`); `_apply_loaded_file` (direct, `app.py` post-9b :15924). Unchanged.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._a2l_cache_key / _a2l_cache_data] (through G-A's store)
examples: see C12b-47.

A2LProgress / _PROGRESS_LINES (a2l.py)
req: LLR-176.4
in:
out: module names
func: new in `a2l.py`: `A2LProgress = Callable[[int, int], None]` (fixed S-f: `(bytes_consumed, total_bytes)`); `_PROGRESS_LINES = 4096` (ruling Q-f1: the buffer position is checked every 4 096 lines). Imports: `import os`; `Callable` joins `from typing import …`.
callers: `build_section_tree`, `parse_a2l_file` (annotation); `app.py` (`A2LProgress` annotation of `_progress_forwarder`).
module: s19_app/tui/a2l.py
examples: see D12b-01.

build_section_tree
req: LLR-176.4, LLR-176.4a
in: Path path; Optional[A2LProgress] progress = None
out: tuple(list[dict] sections, list[str] errors)
func: changed (`a2l.py:141`). The base read loop is unchanged; three lines are added:
- (1) inside `with path.open("r", encoding="utf-8", errors="replace") as handle:`, first: `total = os.fstat(handle.fileno()).st_size` (the size taken at open, fixed S-f);
- (2) first statement of the `for line_number, raw in enumerate(handle, 1):` body: `if progress is not None and line_number % _PROGRESS_LINES == 0: progress(handle.buffer.tell(), total)` — the raw byte position of the text wrapper's buffer (`handle.tell()` is disabled during iteration; the buffer position counts CRLF bytes, so it reaches the size, baseline U3);
- (3) after the loop, still inside the `with`: `if progress is not None: progress(total, total)` — the final report, so a file shorter than 4 096 lines gets exactly 1 report.
- No report on the `FileNotFoundError` soft-error path (the open failed); an `OSError` during the read still re-raises (unchanged), with no final report. Docstring: `Args` gains `progress`; `Data Flow` gains "report (bytes consumed, total) every 4 096 lines and once at the end of the read".
callers: baseline extractor: `parse_a2l_file` (direct, a2l.py:2657). Test `test_a2l_enriched.py:143` calls it with one argument (holds).
module: s19_app/tui/a2l.py
examples: D12b-01 (LLR-176.4) case_06 with a recording callback → 254 calls; first `(147456, 37742888)`; last `(37742888, 37742888)`; the consumed values non-decreasing; every `total == 37742888` (5 assertions; probe P2-a V1, executed with this edit: `reports 254 first (147456, 37742888) last (37742888, 37742888) non-decreasing True totals-equal True`). Negative control: code read on base, `build_section_tree(path)` takes no callback (`a2l.py:141`) → `TypeError` → RED; a mutant that reports only once at the end → 1 call (fewer than 2) → RED.
examples: D12b-02 (LLR-176.4 boundary, smaller than one chunk) case_01 (53 lines) → exactly 1 call, `(1444, 1444)` (probe P2-a V1: `reports 1 first (1444, 1444) last (1444, 1444)`). Negative control: a mutant without step (3) → 0 calls → RED.
examples: D12b-03 (LLR-176.4 empty) no callback → `build_section_tree(case_06)` returns the same `(sections, errors)` as the base function (probe P2-a V3/V4); a missing file with a callback → `errors == ['File not found.']` and 0 calls (probe P2-a: `missing file -> errors ['File not found.'] reports []`) (2 of 2).
examples: D12b-06 (OSError path) a `Path.open` stand-in that returns a real text handle on a 6 000-line A2L whose iterator raises `OSError(5, "synthetic read error")` when it reaches line 5 000 → the `OSError` re-raises out of `build_section_tree` (unchanged), the callback saw exactly 1 call `(<buffer position at line 4096>, <size>)` and no final `(total, total)` (2 of 2). Negative control: a mutant that reports the final value in a `finally` → `(total, total)` after a failed read → RED.
examples: D12b-07 (cost, Q-f1) case_06 tree read: base 1.067 s, designed without a callback 0.983 s, designed with a callback 0.982 s on the loaded host (probe P2-a V4) — the 4 096-line check adds no measurable cost (baseline U3 measured +0.59 s for a per-line `tell()`). Ruling Q-f1's evidence; no pass threshold rests on a timing (negative control: a per-line check mutant, measured at +0.59 s in U3, is the cost this choice avoids; it is not a gated test).

parse_a2l_file
req: LLR-176.4, LLR-176.4a, LLR-177.5
in: Path path; Optional[A2LProgress] progress = None
out: dict a2l_data
func: changed (`a2l.py:2627`): `sections, errors = build_section_tree(path, progress)`; everything else unchanged, so the returned dict is the same with or without a callback (LLR-176.4a). Docstring `Args` gains `progress`. The callback covers only the tree read: the tag, record-layout and compu extraction that follows reports nothing (finding F-1).
callers: baseline extractor: `S19TuiApp._load_a2l_data_with_cache` (direct, app.py:15850) → after 12b G-A's `parse_a2l_cached` (with `progress=` on the workers, without it on the main-thread cache path, ruling Q-f2); unmarked one-argument sites `change_service.py:3225`, `flow_execution_service.py:358`, `:461`, `variant_execution_service.py:2662` (unchanged); tests `test_tui_a2l.py`; 3 monkeypatched fakes (census C6, C7, C8: G-A's re-pins).
module: s19_app/tui/a2l.py
examples: D12b-04 (LLR-176.4a) the parse with a callback and without one, compared with the base function's result: case_06 → equal dicts (220 040 tags, 0 errors); case_01 → equal dicts (3 tags, 0 errors) (2 equalities each, 4; probe P2-a V3: `equal(original, designed+callback) True; equal(original, designed no callback) True`). Negative control: a mutant that sets `"errors": errors + ["progress"]` when a callback is given → the comparison RED.
examples: D12b-08 (callers unchanged) AST over `s19_app/`: every `parse_a2l_file(` call outside `app.py` passes exactly 1 positional argument and 0 keywords (4 sites) (1). Negative control: a mutant signature `parse_a2l_file(path, progress)` with no default → the 4 sites raise `TypeError` → RED.

tests/test_engine_unchanged.py::_ENGINE_PATHS
req: LLR-176.4b
in:
out: list
func: changed (test file): the commented `# "s19_app/tui/a2l.py",` line becomes the entry `"s19_app/tui/a2l.py",`, and the batch-95 unfreeze note is replaced by "UNFROZEN for batch-100 Inc 12b (the parser's byte callback, LLR-176.4); re-frozen by the same increment." TC-027 (`git diff --name-only main`) then fails on the increment branch until the merge (declared, E1 LLR-176.4b note).
callers: `test_tc027_engine_modules_unchanged_vs_main`.
module: tests/test_engine_unchanged.py
examples: D12b-05 (LLR-176.4b) `"s19_app/tui/a2l.py" in _ENGINE_PATHS` (1); after the merge, TC-027 reports 0 changed engine paths against `main` (owed after the merge). Negative control: code read on base, the entry is commented out (`tests/test_engine_unchanged.py:125-133`) → RED.

## Context nodes (unchanged)

- `S19TuiApp.update_a2l_view` — unchanged; its caller on the attach path becomes `_install_attached_a2l` (was `load_a2l_from_path`, extractor direct :13152).
- `S19TuiApp.check_action` — unchanged by 12b: `quit` stays outside `_LOAD_DIALOG_INERT_ACTIONS` (Q-c2 is handled inside `action_quit`); the post-10/11 whole-stack test covers `_QuitQuestionScreen`.
- `ConfirmQuestionScreen` (Inc 10) — unchanged; subclassed by `_QuitQuestionScreen`.
- `S19TuiApp._handle_load_error` — unchanged after 12a; its `end_busy` now carries the quit check.
- `S19TuiApp._sync_loaded_a2l_to_project` — unchanged; called before the A2L end (P2-10).
- `S19TuiApp.load_selected_file` — unchanged; it loses the work-area pick as a caller (its remaining product caller is G-A's business; 88 direct test calls).
- `S19TuiApp._load_path_from_user_input`, `_handle_select_variant`, `_handle_load_dialog`, `_handle_load_result` — unchanged; their continuations reach the checks through `_confirm_then_load` and the action starts.
- `S19TuiApp.begin_busy`, `step_busy`, `_busy_fail`, `_busy_begin_action` (12a) — unchanged.

## Entities

[Data: S19TuiApp._busy]
desc: 12a's run state; Inc 12b reads `runs` only (the newest session run and its painted label) and writes nothing in it.
sequence:
  refuse: <entry point> → S19TuiApp._refuse_if_busy → S19TuiApp._running_session_action → (run) → set_status busy line → expect none (no focus, no push, no session write)
  reportOverlaps: begin_busy report → <entry point> → S19TuiApp._refuse_if_busy → None → expect the request runs
  afterEnd: S19TuiApp.end_busy (run removed) → <entry point> → S19TuiApp._refuse_if_busy → None → the request runs

[Data: S19TuiApp._quit_pending]
desc: set only by `_answer_quit`; read only by `_exit_if_quit_pending`. Classified as UI control state (TC-B100-09).
sequence:
  idleQuit: q → S19TuiApp.action_quit → (no session run) → App.exit
  askStay: q → S19TuiApp.action_quit → push _QuitQuestionScreen → n → S19TuiApp._answer_quit(False) → expect none (flag False, app running)
  askQuit: q → S19TuiApp.action_quit → push _QuitQuestionScreen → y → S19TuiApp._answer_quit(True) → S19TuiApp._exit_if_quit_pending (run remains) → … → <end handler> → S19TuiApp.end_busy → S19TuiApp._exit_if_quit_pending → App.exit
  staleYes: … → <end handler> → end_busy → y → S19TuiApp._answer_quit(True) → S19TuiApp._exit_if_quit_pending → App.exit
  secondCtrlQ: ctrl+q (question open) → S19TuiApp.action_quit → expect none

[I/O: workarea temp] and [Data: S19TuiApp.current_a2l_path / current_a2l_data]
desc: the A2L copy lands on the worker; the session takes the attach only in the main-thread install.
sequence:
  attach: S19TuiApp.load_a2l_from_path → _refuse_if_busy → refusals → _busy_begin_action → A2LAttachRequest → S19TuiApp._a2l_attach_worker (thread) → copy_into_workarea → call_from_thread step_busy 2 → parse_a2l_cached (forwarder: ≤101 step_busy 2 posts) → call_from_thread S19TuiApp._on_a2l_attached → step_busy 3 → call_after_refresh S19TuiApp._install_attached_a2l → record_recent_source → refresh_files → _store_a2l_cache → current_a2l_* → update_a2l_view → labels / panel / focus / sync → end_busy (outcome; quit check) 
  workareaPick: S19TuiApp._load_workarea_file → _confirm_then_load → go → load_a2l_from_path(copy=False) → step_busy 2 (main) → _a2l_attach_worker (no copy) → … as attach
  attachFails: _a2l_attach_worker → (raise) → logger.exception → call_from_thread S19TuiApp._on_a2l_attach_failed → refresh_files → end_busy "File NOT loaded: '<name>' could not be read — …" → expect none (A2L state unchanged)
  containment: _a2l_attach_worker → copy_into_workarea raises WorkareaContainmentError → _on_a2l_attach_failed → end_busy "Cannot load A2L: …"
  handlerRaises: _a2l_attach_worker → call_from_thread _on_a2l_attached raises → except BaseException → call_from_thread _busy_fail → raise → WorkerFailed

[Process: work-area data pick]
desc: the pick reuses the file-load worker in place.
sequence:
  dataPick: S19TuiApp._load_workarea_file → _confirm_then_load → go (re-check) → _busy_begin_action file_load → step_busy 2 → S19TuiApp._start_load_worker(sync_project=False) (thread) → parse (G-A, cache entry out) → step_busy 3 → _apply_prepared_load (store cache) → end_busy "Loaded <name>" → expect none (0 project sync)

[UI: status log]
desc: the busy line is one status-log line per refused request; the quit question paints only in its modal.

## Callers and what changes for each

Each row is checked against the baseline's `> callers (extractor)` note for that node (a node with no code on base says so).

| Node | Baseline callers (extractor / census) | After 12b |
|---|---|---|
| `load_a2l_from_path` | `_load_from_item` direct :13333; unmarked `_load_path_from_user_input` :12939; 28 test sites / 10 files | `_load_path_from_user_input` (post-10 `go`); `_load_workarea_file` (`copy=False`); `_load_from_item` only through `_load_workarea_file` (post-9b); tests re-pinned where P / N |
| `_load_workarea_file` | not run (no code at base; in code on `2305c8b`): `_load_from_item`, `_handle_load_dialog` | unchanged set |
| `_load_from_item` | unmarked `on_list_view_selected` :13183 | unchanged |
| `load_from_path` | unmarked `_load_path_from_user_input` :12942, `_handle_select_variant` :7611 | unchanged set; busy check first |
| `_start_load_worker` | `load_from_path` direct :13071 | + `_load_workarea_file` data arm |
| `_handle_load_error` | none listed (value to `call_from_thread`) | unchanged |
| `update_a2l_view` | `load_a2l_from_path` direct :13152 (+ 5 others) | `_install_attached_a2l` replaces `load_a2l_from_path`; others unchanged |
| `action_load_file`, `action_save_project`, `action_unload_all`, `on_loaded_artifacts_panel_unload_requested`, the Patch Editor handlers | none listed (dispatch) | unchanged dispatch; check first |
| `action_load_project` | unmarked `on_button_pressed` :17635; key `p`, palette | unchanged; check first |
| `action_select_variant` | unmarked `_handle_load_result` :7507; key `v`, palette | unchanged; check first |
| `action_patch_undo` / `action_patch_redo` | `on_patch_editor_panel_undo_requested` direct :4356 / `…_redo_requested` :4381 | unchanged; the outer handler refuses first |
| `_confirm_then_load` | not run (no code at base) | unchanged set (5 routes) |
| `check_action` | unmarked `window_help.py:1134`, `:1145`; Textual `run_action` | unchanged |
| `end_busy`, `_busy_fail` | not run (no code at base) | + G-C's and P-1's 12b handlers |
| `parse_a2l_file` | `_load_a2l_data_with_cache` direct app.py:15850; unmarked `change_service.py:3225`, `flow_execution_service.py:358`, `:461`; `variant_execution_service.py:2662` (lifted) | G-A's `parse_a2l_cached` (with or without `progress=`); the 4 external one-argument sites unchanged |
| `build_section_tree` | `parse_a2l_file` direct a2l.py:2657 | unchanged; + the optional second argument |
| `action_quit` (NEW) | — (Textual's `App.action_quit` via `q`, `ctrl+q`, palette) | the override; `test_b97_key_bar.py:1238` monkeypatch holds |
| `_refuse_if_busy`, `_running_session_action`, `_answer_quit`, `_exit_if_quit_pending`, `_progress_forwarder`, the A2L worker and handlers (NEW) | — | listed in their nodes |

## Seams with P-1 (G-A project load, G-B Save project; same file `app.py`), by id

| Id | Where | P-2 side (this design) | P-1 must | Example |
|---|---|---|---|---|
| X12b-01 | the busy check at P-1's starts (Q-a1) and in `action_save_project` | `_refuse_if_busy()` (one definition); the check line in `action_save_project` is in G-C's census node | `if self._refuse_if_busy(): return` as the first statement of `_handle_load_project` (G-A) and `_commit_project_save` (G-B); no second copy of the check; no other busy test | C12b-17, C12b-11 |
| X12b-02 | the end tail | the quit check inside `end_busy` (A12a-07); `_finish_session_action` / `_fail_session_action` not created (P2-1) | end sites call `end_busy(key, gen, outcome)` / `_busy_fail(key, gen)` directly, as the **last statement** of each end handler (`_on_project_loaded` refusal arm, `_install_prepared_project` after the Load-result panel, `_on_project_load_failed`, `_on_project_saved` both arms); no `final_line` — store the project and file line with `set_file_status(...)` before the end (A12a-06, 12a A12-42) | C12b-22 … C12b-24 |
| X12b-03 | `_progress_forwarder(key, gen, n)` | defined as in its node; ≤ about 101 forwards per step, always the final | call it on the worker only: G-A `("project_load", gen, 2)` → `parse_a2l_cached(…, progress=…)`; G-B `("save_project", gen, 2)` with `done` = files placed, `total` = the plan's placements (LLR-177.5a) | C12b-33 |
| X12b-04 | `parse_a2l_cached(path, cached, progress)` (G-A) | the A2L worker always passes `progress=` (Q-f2); tests hold or fail it through `app_module.parse_a2l_cached` | keep it a module-level name in `app.py` that calls `parse_a2l_file(path, progress=progress)` when a callback is given and `parse_a2l_file(path)` when not | C12b-29, C12b-37 |
| X12b-05 | `_a2l_cache_entry()` / `_store_a2l_cache(entry)` (G-A) | read on the main thread in `load_a2l_from_path`; read again by `_parse_loaded_file` on the file-load worker (the out-list form, E3 DF-8); stored on the main thread in `_install_attached_a2l` and `_apply_prepared_load` | keep both main-thread helpers with these names and the `A2LCacheEntry` shape | C12b-30, C12b-47 |
| X12b-06 | the Q-h1 parse on the file-load worker | `_start_load_worker` passes `a2l_cache_out=out` and sets `PreparedLoad.a2l_cache = out[0] if out else None` | give the worker `_parse_loaded_file(path, a2l_files, *, a2l_cache_out=None)`, which reads `_a2l_cache_entry()` itself, appends the entry it used or made and writes no `_a2l_cache_*` (the out-list form, E3 DF-8 / PR-7; a tuple return would break 12a's patches and 9 direct test calls) | C12b-47 |
| X12b-07 | worker options | `group="a2l_load"`, not exclusive, `exit_on_error=True`; outer `except BaseException` → `_busy_fail` → re-raise; no `finally` cross-thread call on success (S12a-06) | the same shape for the project and Save workers (distinct groups `project_load`, `save_project`; never the `"load"` group) | C12b-40 |
| X12b-08 | new app attributes | `_quit_pending` only | add no `self.<name> =` (requests and results are never stored on the app), so TC-B100-09 sees exactly 1 new name | C12b-49 |
| X12b-09 | `_reset_project_session` | — | must not touch `_quit_pending` or `_busy` | C12b-24 |
| X12b-10 | the routed Load-result panel | — | push `LoadResultScreen` before the end call in `_install_prepared_project`; with a quit pending the app then exits after the push | C12b-24 |
| X12b-11 | the held Save step in G-C's examples | C12b-05, -09 … -14, -18 … -23 hold `app_module.place_into_workarea` | call `place_into_workarea` (and `_copy_project_subfolders`' placements) through the `app.py` module name, so the hold reaches the worker | C12b-05 |
| X12b-12 | the held project-load step | C12b-06, -11, -16, -24 hold `app_module.read_project_manifest` | call `read_project_manifest` through the `app.py` module name on the worker | C12b-06 |
| X12b-13 | `_route_load_project`'s `go` | G-A's `lambda: self._handle_load_project(name, routed=True)` runs unchanged (no deferred `go_if_idle` check, E3 A12b-03) | nothing more (its own start check, X12b-01, also refuses) | C12b-07 |
| X12b-14 | TC-B100-51 re-derived (12a A12-28 fixture) | the `a2l_load` rows move: begin `load_a2l_from_path`; step 2 `_a2l_attach_worker` (through `call_from_thread`) or `load_a2l_from_path` (`copy=False`); step 3 `_on_a2l_attached`; ends `_install_attached_a2l`, `_on_a2l_attach_failed` | re-key the `project_load` and `save_project` rows to their workers and handlers | C12b-51 |

## Re-pins owed by P-2's changes (by grep and reading; not executed — host busy)

| # | Test or helper | Why | Disposition |
|---|---|---|---|
| R-1 | 12a examples A12-38 … A12-41 (`test_b100_busy.py`, written at 12a E4) | the A2L attach is now a worker: bar spy `[0, 33, 66, 66, 0]` (C12b-30); A12-40's `RuntimeError` out of `load_a2l_from_path` becomes the `could not be read` line (C12b-37) | re-pin to C12b-30, C12b-37, C12b-39, C12b-41 |
| R-2 | 12a A12-73 (the work-area pick runs no begin) | the pick now begins `file_load` (C12b-46) | re-pin |
| R-3 | 12a A12-28 rows 19–22 (TC-B100-51 fixture) | the `a2l_load` sites move (X12b-14) | re-key (C12b-51) |
| R-4 | census A7 `test_help_toggle_and_a2l_panel.py:90` (P) and the other P / N `load_a2l_from_path` sites of census pass 4 | one pause after a worker attach | wait helper (ruling Q6) |
| R-5 | `_load_from_item` sites `test_b100_focus.py:364`, `test_b100_recents.py:944`, `:2823`; `test_b100_load_dialog.py::test_tc_b100_40_…`, the 0-copy spy at :593–:611 | the data pick and the A2L pick are now workers | wait helper; assertions hold |
| R-6 | census A9 `tests/support/b100_projects.py:383` `append_variant` | `load_from_path` is refused while the project worker runs (Q-a1) | the helper waits for the project load first |
| R-7 | `test_examples_pilot_gifs.py:231` (`press("q")`, census C14) | if a session worker still runs at that frame, `q` asks instead of exiting | holds when the test waits first; at risk otherwise |
| R-8 | tests reading `log_lines[-1]` after an A2L attach with a project open (`test_b100_active_variant.py`, `test_b100_save_image.py`, `test_tui_commandbar.py` reference both) | P2-10 moves the sync before the outcome | read each at E4; the last line is now `A2L loaded: …` |
| R-9 | `tests/test_engine_unchanged.py` | `a2l.py` re-listed; TC-027 RED on the branch | owed after the merge (D12b-05) |
| R-10 | `test_b100_session_reset.py` `SNAPSHOT_EXCLUSIONS` | `_quit_pending` | 1 entry (C12b-49) |

## Findings

finding F-1 (declared, LLR-177.5 / HLR-176) the bar stalls at the end of the parse step
anchor: parse_a2l_file
seen: probe P2-a V4 (executed): the case_06 tree read takes 1.0 s of a 6.6 s parse; the tag, record-layout and compu extraction (5.5 s) consumes no input bytes and reports nothing. So during the attach the bar goes 33 → 66 in about 1 s and holds at 66 (`step 2/3 Parse`) for about 5.5 s, while the glyph and the elapsed time keep moving (the event loop is free).
decision: declared. LLR-176.4 ("bytes consumed") and LLR-177.5 ("≥ 2 increases within the parse step") hold. Reporting progress through the tag extraction would need a second callback inside `extract_a2l_tags` (a wider frozen-engine crossing). Recorded for the UX note of AT-B100-17.

finding F-2 (requirement made infeasible as written without P2-2) the file-load worker appends a picked file to the open project
anchor: S19TuiApp._start_load_worker
seen: `_start_load_worker` ends with `if self.current_project: call_from_thread(self._sync_loaded_file_to_project)` (the variant append, `app.py` post-9b :16447); the base pick (`load_selected_file`) never syncs. Routed through the worker unchanged, a pick with a project open copies the file into the project and rewrites `project.json`.
decision: proposal P2-2 (`sync_project: bool = True`, keyword-only; the pick passes `False`). Without it, LLR-177.1k's "the session digest equals that of the base's synchronous pick" fails whenever a project is open (C12b-45 RED), and the requirement must be rewritten to accept the append.

finding F-3 (P2-5) the Patch Editor's modal results can arrive during a save
anchor: busy-check census
seen: `ChangeSetJsonScreen`, `EntryJsonScreen` and `LoadGuardScreen` do not make `ctrl+s` / `ctrl+l` inert; a Save can start over them, and their results then change the document while the save runs — the ruling Q3 hazard. LLR-177.3e's own threshold lists "an edit-JSON result and an entry edit-JSON result".
decision: the 4 continuations check too (C12b-13). Cost: the JSON text the engineer typed is dropped with the busy line (risk D-3).

finding F-4 (P2-6, reversed) a deferred load continuation can outlive the check before the question
anchor: S19TuiApp._confirm_then_load
seen: the Textual command palette (`ctrl+p`) opens over the load question (Inc 10 C46) and can start a session action; `go` then runs after `y`.
decision: **reversed by E3 A12b-03** — the palette offers only system commands here (`textual/app.py:1336-1376`), `focus_palette` is inert under the question, and non-priority keys do not pass a modal, so the window `go_if_idle` guarded cannot be reached. `go_if_idle` and C12b-08 are removed.

finding F-5 (declared, P2-9) an A2L that fails to parse is no longer recorded in the recents
anchor: S19TuiApp.load_a2l_from_path
seen: base records the source after the copy and before the parse; 12b records in the install handler.
decision: recorded only on success (C12b-42). No requirement pins the old order (grep: no test records a failing A2L).

finding F-6 (12a carry-over contradiction in the fixed file) `final_line` and the S-c wrappers
anchor: S19TuiApp.end_busy
seen: `interfaces-12b.md` S-c / S-g still name `final_line` and `_finish_session_action`, which 12a's E3 A12a-06 / A12a-07 (binding, listed in the same file) supersede.
decision: designed to A12a-06 / -07 (decision table); proposal P2-1 asks the orchestrator to correct S-c, S-g and the end-site list.

## Proposals to the orchestrator

All of the proposals below were ruled by the E3 rulings, except P2-6, which E3 A12b-03 reversed (`go_if_idle` and C12b-08 are removed).

- **P2-1 (interfaces S-c, S-g).** Drop `_finish_session_action` / `_fail_session_action` and `final_line`: the quit check lives inside `end_busy` (A12a-07) and the file state is stored with `set_file_status` (A12a-06). End sites call `end_busy(key, gen, outcome)` / `_busy_fail(key, gen)` as their last statement. If the orchestrator keeps the names, they become one-line delegations with no `final_line`, and the check stays in `end_busy` either way.
- **P2-2 (12a's fixed `_start_load_worker` signature, F-2).** Add `sync_project: bool = True` (keyword-only, additive); the work-area pick passes `False`. Alternative: accept the append and rewrite LLR-177.1k's threshold for an open project.
- **P2-3 (additive, private).** `_QuitQuestionScreen(ConfirmQuestionScreen)` with no body, for the Q-c2 identity test. Alternative: read `ConfirmQuestionScreen._question_title` from `app.py` (a private attribute of `screens.py`, which the codebase avoids — Inc 10 C52 removed `panel._dirty`).
- **P2-4 (S-d vs S12a-05).** Workers use a distinct group per key and no `exclusive`; confirm this reading of "one exclusive worker group per busy key … or uses a distinct group per key" for P-1's workers too (X12b-07).
- **P2-5 (F-3).** The 4 Patch Editor continuations run the busy check. Alternative: leave them and declare the window (a save started over a JSON editor can mark an unsaved edit saved).
- **P2-6 (F-4).** `_confirm_then_load` re-checks before its deferred `go`.
- **P2-7 (Q-a1 detail).** `load_from_path`'s busy refusal leaves `_pending_variant_id` untouched (a running action may own the stamp).
- **P2-8 (F-1).** Add a sentence to AT-B100-17's parse half or LLR-177.5's note: "the bar reaches the end of the parse step after the A2L text is read (about 1 s of 6.6 s for case_06) and holds there while the tags are extracted".
- **P2-9 (F-5).** Accept "a failed A2L attach records nothing in the recents".
- **P2-10 (12a F-7, A2L half).** `_sync_loaded_a2l_to_project` and the focus re-home move before the A2L end, so the end is the last statement (as Q-c1 did for the file load); with a project open the outcome becomes the last log line.

## Design risks

- **D-1 (re-indent).** `load_a2l_from_path` shrinks (its tail moves to `_install_attached_a2l`); reviewers compare the moved block with `git diff -w --color-moved`.
- **D-2 (shutdown race).** If the app is already closing, a worker's `call_from_thread` raises `RuntimeError`; the inner `except Exception` then posts the failure handler, which raises too, and the outer guard's `_busy_fail` post raises as well, hiding the first error (12a R-2, not probed).
- **D-3 (P2-5 cost).** A JSON edit confirmed while a session action runs is dropped (busy line); the engineer re-opens the editor after the action.
- **D-4 (palette quit while a quit question is open).** The palette is inert under the question (`focus_palette` is in the inert set), so only `ctrl+q` reaches `action_quit` there (C12b-20).
- **D-5 (exit and reports).** A quit confirmed during a session action exits at that action's end even when a report worker still runs (reports are not session actions, ruling Q2); the report's output can be cut. The same is true of an idle quit today.
- **D-6 (off-thread cache read).** `_parse_loaded_file` reads `_a2l_cache_key` / `_a2l_cache_data` off the main thread (ruling Q-h1, the out-list form of E3 DF-8); a torn read needs a main-thread cache store during a file-load run, which the refusal excludes for the session actions (test-only).
- **D-7 (A2L stall, F-1).** About 5.5 s of the case_06 attach show a full step-2 bar.

## Platform notes

No Windows-only arm. Every path is built with `Path`; the painted names use the platform separator only where an example quotes a full path (C12b-21, C12b-42).

## Requirement coverage (P-2: G-C and G-D)

| Requirement | Examples |
|---|---|
| HLR-177 (A2L arm; the project and Save arms are P-1's) | C12b-29, C12b-31 |
| HLR-177a | C12b-05, C12b-03, C12b-17 |
| HLR-177b | C12b-18 |
| HLR-177c | C12b-22, C12b-23, C12b-25 |
| LLR-177.1b | C12b-29, C12b-30 |
| LLR-177.1c (A2L arm; project and Save arms P-1's) | C12b-31 |
| LLR-177.1d (A2L arms and the file-load cache, Q-h1) | C12b-35, C12b-47 |
| LLR-177.1e (A2L worker) | C12b-36, C12b-54 |
| LLR-177.1k | C12b-44, C12b-45, C12b-46 |
| LLR-177.2b | C12b-37, C12b-38 (and C12b-39, the containment boundary) |
| LLR-177.3 | C12b-06 |
| LLR-177.3a | C12b-07 |
| LLR-177.3b | C12b-09 |
| LLR-177.3c | C12b-10 |
| LLR-177.3d | C12b-11 |
| LLR-177.3e | C12b-12, C12b-13 |
| LLR-177.3f | C12b-02, C12b-04 |
| LLR-177.3g | C12b-02, C12b-14 |
| LLR-177.3h | C12b-15, C12b-16 |
| LLR-177.4 | C12b-18 |
| LLR-177.4a | C12b-19 |
| LLR-177.4b | C12b-21 |
| LLR-177.4c | C12b-22, C12b-23, C12b-24, C12b-25, C12b-26, C12b-28, C12b-53 |
| LLR-177.4d | C12b-27 |
| LLR-177.5 (A2L arm; the project arm is P-1's) | C12b-32, C12b-33 |
| LLR-176.3 (A2L arm; the project install arm is G-A's) | C12b-34 |
| LLR-176.4 | D12b-01, D12b-02, D12b-03, D12b-06 |
| LLR-176.4a | D12b-04 |
| LLR-176.4b | D12b-05 |
| LLR-174.4 (TC-B100-72 extension) | C12b-07 |
| LLR-165.2 (TC-B100-09 extension) | C12b-49 |
| LLR-176.1l (A2L worker and deferred install arms) | C12b-40, C12b-52 |
| LLR-176.1q (A2L arm) | C12b-43 |
| LLR-176.2 / .2c / .2d (TC-B100-51, A2L rows) | C12b-30, C12b-51 |
| LLR-173.7 (TC-B100-66 extension) | C12b-50 |
| Q-c2 | C12b-20 |
| Q-a1 | C12b-17, C12b-41 |

The examples not written out above:
- C12b-15 (LLR-177.3h, A2L arms) three attaches of case_01, each followed by `l`: one that succeeds; one whose copy raises `WorkareaContainmentError` (reported: `Cannot load A2L: …`); one whose `parse_a2l_cached` raises `ValueError` (the `could not be read` line) → after each, `l` pushes `LoadDialog` and 0 busy lines are painted (3 of 3). Negative control: a mutant whose `_on_a2l_attach_failed` paints the line with `set_status` and never calls `end_busy` → the run stays in `_busy.runs` → `l` paints `busy: Loading firmware.a2l is running — wait for it to finish.` → RED.
- C12b-16 (LLR-177.3h, project arms; seam X12b-02) a project load of `P` that installs; one of `A2LONLY` whose A2L does not parse (`No supported files in project: A2LONLY`, the post-10 refusal through G-A's `_on_project_loaded`); one whose `read_project_manifest` raises `ValueError` (G-A's `could not be read` failure, LLR-177.2) → after each, `l` opens `LoadDialog` (3 of 3). Negative control: the state-left-set mutant of C12b-15 on G-A's failure handler → RED.
- C12b-32 (LLR-177.5, A2L arm) attach case_06 and read `#progress_bar`'s progress on the main thread in a 0.05 s polling loop while `step 2/3` is shown → the value increases at least 2 times within step 2 (from 33 towards 66), never above 66 in step 2, and the forwarded reports number at most 101 (`call_from_thread` spy on `step_busy` with `key == "a2l_load"` and a `done` argument). Afterwards the bar holds at 66 until `step 3/3` (F-1). Negative control: a mutant whose worker passes no callback → the bar moves by step only (33, then 66 at step 3) → 0 increases within step 2 → RED.
- C12b-51 (LLR-176.2, TC-B100-51 re-key) the AST walk of 12a's A12-28, with the `a2l_load` rows re-keyed per X12b-14, finds: `_busy_begin_action("a2l_load", …)` in `load_a2l_from_path`; `step_busy` with `"a2l_load"` and `2` as a `call_from_thread` argument in `_a2l_attach_worker` and directly in `load_a2l_from_path`; `step_busy(…, 3)` in `_on_a2l_attached`; `end_busy("a2l_load", …)` in `_install_attached_a2l` and `_on_a2l_attach_failed` (6 of 6). Negative control: the end left out of `_on_a2l_attach_failed` → the census names it → RED.

**P-2 requirements left uncovered: none.**

**Infeasible as written:** LLR-177.1k's twin-digest arm with a project open, unless proposal P2-2 is accepted (F-2). Everything else is feasible in `app.py` and `a2l.py`.
