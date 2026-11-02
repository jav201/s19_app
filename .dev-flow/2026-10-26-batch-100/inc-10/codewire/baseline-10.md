# Code-Wire baseline — batch-100 Inc 10 slice ("one short question before unsaved work is lost") on main `8947666`

Scope: the functions on the Inc 10 paths (HLR-174 … HLR-174d, LLR-174.1 … LLR-174.4c, plus the arms of LLR-165.3, LLR-166.1, LLR-167.8, LLR-173.7 that Inc 10 owes; E1-scope §3): the four image-replacing routes and their leaves (`_handle_load_dialog`, `_route_load_project`, `_load_path_from_user_input`, `_load_from_item` / `_load_workarea_file`, `_handle_select_variant`, the Load-result panel's `v`), the three unsaved flags and their readers and writers (D: `ChangeService.differs_from_last_saved` / `mark_saved`; W: the five writers of `PatchEditorPanel._dirty` and its one private outside reader in `_handle_save_dialog`; F: `FlowBuilderPanel.is_dirty`), the project load with the interim closed-document line and the reset, the action gate `check_action`, the two existing confirm modals the new question must not copy (`ConfirmDiscardScreen`) or must keep (`LoadGuardScreen` and its route), the focus re-home, and the one name scrub. Base: `<HOME>\Github\s19_app` at `8947666` (Inc 9a merged), read only; probes and the extractor ran on a `git archive` copy of that commit. Line numbers are `8947666` lines.

Inc 9b runs before Inc 10 and is not in the code. Where 9b changes a node, `func:` adds "post-9b: …" from `interfaces-9b.md` and `proto-9b-app.md` (E3 r2), and the examples still state what holds on `8947666`. The two nodes 9b creates are marked "(post-9b, from the 9b graph; not yet in code)"; they have no code to mark, so the extractor ran on a copy of this graph without them (baseline-notes "Extractor").

Example lines come from the probe `p10b` (this folder, `probe-p10b.py` / `probe-p10b.out.txt`), the E1 probe `p10` (`../work/probe_p10.out.txt`, the 9a tree, same code as `8947666`), an existing test, or a code read; each names its source. Every example holds on `8947666` unless it says "post-9b" or "after Inc 10". `func:` says "Inc 10 changes: …" where an Inc 10 requirement changes the function; a node with no "Inc 10 changes" is context.

## Nodes

ConfirmDiscardScreen.__init__
req: LLR-174.2a, LLR-174.2p
in: str target
out: ConfirmDiscardScreen screen
func: the Flow Builder's own discard question (OQ-3 / LLR-003.6): keeps the flow stem it will name. Its texts are fixed in `compose`, not parameters. Unchanged by Inc 10 (it stays the Flow Builder's guard); it is the closest existing `ModalScreen[bool]` and the pattern LLR-174.2a / .2p must not copy.
module: s19_app/tui/screens.py
examples: (code read, `screens.py:921`) `ConfirmDiscardScreen("t")` → `target == "t"`; title, body and labels are literals in `compose` (holds on base; RED side of LLR-174.2a's "parameters")

> callers (extractor): none listed — unmarked sites: app.py:3449 (1) (the Flow Builder's own Load, behind `panel.is_dirty`)

ConfirmDiscardScreen.compose
req: LLR-174.2, LLR-174.2b, LLR-174.2d, LLR-174.2p
in:
out: ComposeResult widgets
func: `Container#load_dialog.modal-dialog` with a `Label` title "Discard unsaved flow edits?", a `markup=False` hint naming the target, and `Container#flowdiscard_buttons.modal-buttons` holding `Button#flow_discard_ok` ("Discard", `.modal-confirm`) and `Button#flow_discard_cancel` ("Cancel"). No `AUTO_FOCUS`, no `BINDINGS`: the focus lands on the first button (Discard), and `escape` / `n` do nothing. `on_button_pressed` dismisses `True` / `False`. Unchanged by Inc 10.
module: s19_app/tui/screens.py
examples: (probe p10b U12) pushed → `focused.id == "flow_discard_ok"`, buttons `['Discard', 'Cancel']` (holds on base; the RED side of LLR-174.2b and of LLR-174.2p's labels)
examples: (probe p10b U12, P-18 shape) `escape`, then `n` → the stack still ends in `ConfirmDiscardScreen`, `0` answers (holds on base; RED side of LLR-174.2d)

> callers (extractor): none listed

LoadGuardScreen.compose
req: LLR-174.2j, LLR-174.2b
in:
out: ComposeResult widgets
func: the Patch Editor's own dirty-load warning (batch-94, LLR-005.2): `Vertical.modal-dialog` with `Label#load_guard_title` "Unsaved changes will be lost", a `markup=False` `Static#load_guard_body`, and `Horizontal#load_guard_buttons` with `Button#load_guard_accept` "Accept loss and load" / `Button#load_guard_cancel` "Cancel". `AUTO_FOCUS = "#load_guard_cancel"`; `BINDINGS = [escape → cancel]`. No `y` / `n` keys. Unchanged by Inc 10 (LLR-174.2j keeps it); its focus and escape shape is the one the new question follows.
module: s19_app/tui/screens_directionb.py
examples: (probe p10b U11) pushed → `focused.id == "load_guard_cancel"`; `y`, `a`, `l`, `p`, `s`, `q` → stack still `['Screen', 'LoadGuardScreen']`, `0` answers (holds on base: a modal blocks the non-priority app keys `l` / `p`)
examples: (probe p10b U11) an immediate `enter` → answer `False` (the focused Cancel), stack `['Screen']`; `escape` → answer `False` (holds on base)

> callers (extractor): none listed

LoadGuardScreen.on_button_pressed
req: LLR-174.2j
in: Button.Pressed event
out: None
func: `#load_guard_accept` → `dismiss(True)`; `#load_guard_cancel` → `dismiss(False)`; both `event.stop()`. Unchanged by Inc 10.
module: s19_app/tui/screens_directionb.py
examples: (test_at_b94_07_dirty_load_cancel_keeps) Cancel → the document and the dirty flag kept (holds on base)

> callers (extractor): none listed

PatchEditorPanel.request_action
req: LLR-174.1c
in: str action
out: None
func: posts the panel's `ActionRequested`; for an entries-table edit (Add / Edit / Remove) it sets `self._dirty = True` first (writer w1, `:5634`) and repaints the marker. Unchanged by Inc 10; one of the five writers LLR-174.1c's reader must follow.
module: s19_app/tui/screens_directionb.py
examples: (code read, `screens_directionb.py:5633-5634`) `request_action("add_entry")` → `_dirty is True` (holds on base)
examples: (probe p10b U2) an entry added through `ChangeService.add_entry` (not the panel) → `_dirty is False`: W follows the panel's inputs only, never the service document (holds on base)

> callers (extractor): `PatchEditorPanel.on_button_pressed` (direct, :5795, :5811)

PatchEditorPanel.on_text_area_changed
req: LLR-174.1c, LLR-174.2m
in: TextArea.Changed event
out: None
func: for `#patch_paste_text`, writer w2 (`:5558`): any edit in the paste buffer sets `_dirty = True`, then repaints the marker and the gauge. `clear_paste_buffer` prevents this message, so the reset's clear never sets the flag. Unchanged by Inc 10.
module: s19_app/tui/screens_directionb.py
examples: (code read, `:5552-5560`) typing one character in `#patch_paste_text` → `_dirty is True` (holds on base)

> callers (extractor): none listed (framework: `TextArea.Changed`)

PatchEditorPanel.on_button_pressed
req: LLR-174.2j
in: Button.Pressed event
out: None
func: the panel's button router; `#patch_doc_load_button` reads the private flag: `_dirty` → post `DirtyLoadRequested(path_text)` (the app pushes `LoadGuardScreen`); clean → `request_action("load_doc")`. Inside the panel's own module, so LLR-174.1c's census (outside `screens_directionb.py`) does not count it. Unchanged by Inc 10.
module: s19_app/tui/screens_directionb.py
examples: (probe p10b U13) `_dirty = True`, `#patch_doc_load_button` pressed → stack `['Screen', 'LoadGuardScreen']` (holds on base; LLR-174.2j's kept route)

> callers (extractor): none listed (framework)

PatchEditorPanel.mark_saved
req: LLR-174.1c, LLR-167.8
in:
out: None
func: writer w3: `_dirty = False`, repaint. Called by `app.py` after a clean document save and after Save project when the files hold every entry (`_handle_save_dialog` `:10572`, `_save_clears_panel_flag`). Unchanged by Inc 10.
module: s19_app/tui/screens_directionb.py
examples: (code read, `:5813-5821`) `_dirty = True`, `mark_saved()` → `_dirty is False` (holds on base)

> callers (extractor): `S19TuiApp._handle_save_dialog` (direct, :10572); — unmarked sites: app.py:4036 (1)

PatchEditorPanel.mark_loaded
req: LLR-174.1c
in:
out: None
func: writer w4: `_dirty = False`, repaint. Called after a document load, and by `_reset_project_session` (`app.py:11535`) right after `clear_paste_buffer` (LED .55(b)): every project load that reaches the reset leaves W false. Unchanged by Inc 10.
module: s19_app/tui/screens_directionb.py
examples: (probe p10b U6) a project load `PV` that reaches the reset → `W after = False` (holds on base)

> callers (extractor): `S19TuiApp._handle_load_project` (through an unmarked helper; 1 site(s)); `S19TuiApp._reset_project_session` (direct, :11535); — unmarked sites: app.py:6177 (1)

PatchEditorPanel.mark_pasted
req: LLR-174.1c, LLR-174.2m
in:
out: None
func: the fifth writer (batch-97 Inc-4): `_dirty = True` after Parse pasted replaces the document. The attribute docstring at `:4808-4815` still says "exactly four sites" (w1–w4) and omits it (E1 §5). Unchanged by Inc 10 in behaviour; the docstring is in the file Inc 10 touches (S-c).
module: s19_app/tui/screens_directionb.py
examples: (code read, `:5850-5860`; caller `app.py:3982`) Parse pasted succeeds → `mark_pasted()` → `_dirty is True` (holds on base)

> callers (extractor): — unmarked sites: app.py:3982 (1)

FlowBuilderPanel.is_dirty
req: LLR-174.1b, LLR-174.2n
in:
out: bool dirty
func: read-only property over `self._dirty`, set by `_mark_dirty` (a chain edit), cleared by `mark_saved` / `set_blocks`. The public reader pattern LLR-174.1c copies for the Patch Editor. A project load neither clears nor reads it (ruling Q1). Unchanged by Inc 10.
module: s19_app/tui/flow_screens.py
examples: (probe p10b U1) a fresh app → `False`
examples: (probe p10b U10; E1 probe p10) `_mark_dirty()`, then a project load `PV` → `is_dirty` still `True` (holds on base; ruling Q1: the question says the flow "has unsaved changes", not that it is lost)

> callers (extractor): none listed (a property; the extractor resolves calls only — readers: `app.py:3444`, the Flow Builder's own Load guard, by code read)

FlowBuilderPanel.current_flow
req: LLR-174.2n
in:
out: Flow flow
func: property: `Flow(name=self._flow_name, blocks=…, funnel=…)`. The name is the display name; a never-named flow is `"flow"`. Unchanged by Inc 10; the composer reads `.name` for the `flow <name>` item.
module: s19_app/tui/flow_screens.py
examples: (probe p10b U1) a fresh app → `current_flow.name == "flow"` (holds on base; LLR-174.2n's default-name arm `flow flow`)

> callers (extractor): none listed (a property; readers are the Save flow paths, by code read)

ChangeService.differs_from_last_saved
req: LLR-174.1, LLR-174.1a, LLR-174.1b, HLR-174a
in: dict[int, int]? mem_map
out: bool differs
func: the unsaved-image predicate D (B100-I18, LLR-167.5): `False` for `None`; any recorded address of the dict last recorded now holding another byte, or any journaled unrecorded address no longer holding its source byte → `True`. Its docstring names "the Inc 10 load question (no app caller before it)". Unchanged by Inc 10; the guard is its first app caller.
module: s19_app/tui/services/change_service.py
examples: (probe p10b U2) a clean load, then a patch writing the byte already there → `False` (holds on base; HLR-174a boundary)
examples: (probe p10b U2) a clean load, then a patch changing one byte → `True` (holds on base)
examples: (probe p10b U4) after a Workarea pick replaced the patched image → `False` (the new image is clean; the 2 document entries stay) (holds on base)
examples: (test_tc_b100_58_mac_attach_keeps_an_unsaved_patch_unsaved; probe p10b U3) an unsaved patch, then a MAC attach → still `True` (holds on base)
examples: (probe p10b-undo, unit) saved map, patch applied → `True`; then `undo()` alone → `0` entries but the byte still patched → `True`; then `apply` of the empty document → the byte restored → `False` (holds on base; E1's boundary "a patch applied then undone → 0 questions" holds only for undo plus apply)

> callers (extractor): none listed (no app caller on base)

ChangeService.mark_saved
req: LLR-174.1, HLR-174a
in: dict[int, int]? mem_map
out: None
func: records the image as saved: `_saved_map = mem_map` and the recorded bytes. Called by the load install (`app.py:15352`, the copy last loaded), the save-back (`:4187`) and Save project (`:10446`). Unchanged by Inc 10.
module: s19_app/tui/services/change_service.py
examples: (test_tc_b100_58_save_project_records_the_saved_state) patch, Save project → `differs_from_last_saved(...)` is `False` (holds on base; HLR-174a "patched → Save project → data load")
examples: (probe p10b U7; E1 probe p10) right after a project load → D `False`, so the Load-result panel's `v` meets no unsaved image by keys (holds on base; ruling Q5)

> callers (extractor): `S19TuiApp._handle_load_project` (through an unmarked helper; 1 site(s)); `S19TuiApp._handle_save_dialog` (direct, :10446); `S19TuiApp.load_selected_file` (through an unmarked helper; 1 site(s)); — unmarked sites: app.py:4187 (1)

painted_names
req: LLR-174.2i, LLR-174.2k, LLR-174.2l, LLR-174.2n, LLR-174.2o
in: Sequence[str] names; int limit = PAINTED_NAME_LIMIT; int clip = 120
out: str painted
func: the batch's one name scrub: removes Cc, Cf, Zl, Zp, turns an unpaired surrogate into U+FFFD, clips each name to `clip` characters (`…`), joins at most `limit` names. Pure; markup is not parsed (the caller paints with markup off). Unchanged by Inc 10; the question composer calls it once per name.
module: s19_app/tui/services/project_gather_service.py
examples: (probe p10b U0) `["[b]x.s19"]` → `"[b]x.s19"`; `["a\u202eb.s19"]` → `"ab.s19"`; `["n" * 130]` → 120 characters ending in `…` (holds on base)

> callers (extractor): `S19TuiApp._handle_load_project` (direct, :11686, :11718, :11735, :11775, :11776, :11805, :11810); `S19TuiApp._handle_save_dialog` (direct, :10468, :10480, :10482, :10499, :9660); `S19TuiApp._handle_save_dialog` (through an unmarked helper; 16 site(s)); `S19TuiApp._load_path_from_user_input` (direct, :12944); `S19TuiApp.load_a2l_from_path` (through an unmarked helper; 1 site(s)); `S19TuiApp.on_mount` (through an unmarked helper; 1 site(s))

S19TuiApp.action_load_file
req: HLR-174, LLR-174.2h
in:
out: None
func: the Load key (`ctrl+l` priority, `l`): pushes `LoadFileScreen()` with `_handle_load_dialog` as its dismiss callback. Runs under any modal through its priority binding. post-9b: pushes `LoadDialog(mode="path", …)` → `_handle_load_dialog`, and `check_action` makes it inert while a `LoadDialog` is anywhere on the stack. Inc 10 changes: none in body; LLR-174.2h makes it inert while the question is on the stack too (through `check_action`).
module: s19_app/tui/app.py
examples: (probe p10b U11, LLR-174.2h executed on base with a stand-in `ModalScreen[bool]`) `LoadGuardScreen` open, `ctrl+l` → `load_file` runs, stack `['Screen', 'LoadGuardScreen', 'LoadFileScreen']` (holds on base; the RED side of LLR-174.2h, whose E1 control was `planned`)

> callers (extractor): none listed

S19TuiApp.check_action
req: LLR-174.2h
in: str action; tuple parameters
out: bool? allowed
func: gates actions by window only: `confirm_attention` on Flow Execution, `page_*_context` on A2L / MAC, `hex_page_*` on Workspace, else `App.check_action`. No modal test on base. post-9b (G3, S9b-1): first test `action in _LOAD_DIALOG_INERT_ACTIONS and any(isinstance(s, LoadDialog) for s in self.screen_stack)` → `False`. Inc 10 changes: the same test also for the question's screen type (S-f, ruling Q4).
module: s19_app/tui/app.py
examples: (probe p10b U11) under `LoadGuardScreen`: `ctrl+l` → `load_file` ran; `ctrl+s` → `save_project` ran, stack `['Screen', 'LoadGuardScreen', 'SaveProjectScreen']`; `ctrl+k` → `focus_palette` ran; `ctrl+d` → `cycle_density` ran (4 of 4 run; holds on base; RED side of LLR-174.2h)
examples: (post-9b, from proto-9b-app B90) with a `LoadDialog` open the 4 keys run no app action; a screen type other than `LoadDialog` is not in the test, so a question pushed over the main screen still lets them run (the RED side Inc 10 closes)

> callers (extractor): none listed — unmarked sites: window_help.py:1134, window_help.py:1145 (the key bar dims a key this returns False for)

S19TuiApp._handle_load_dialog
req: HLR-174, LLR-174.4, LLR-174.4a, LLR-174.4b
in: Path? path
out: None
func: base: `LoadFileScreen`'s dismiss callback: `None` → return; else log `modal_dismiss_scheduled`, flush, `call_after_refresh(self._load_path_from_user_input, path)`. post-9b (the one router, `Optional[LoadChoice]`): `None` → `_rehome_focus_after_load()`; else log and defer through `call_after_refresh`: `project` → `_route_load_project(value)`, `workarea` → `_load_workarea_file(value)`, `path` / `recent` → `_load_path_from_user_input(Path(value))`. 9b's own note: "Inc 10 inserts the load question at this seam". Inc 10 changes: placement decision S-d — with the seam in the leaves, the router itself stays as 9b writes it (no seam here), so a typed project folder is asked once (LLR-174.4a).
module: s19_app/tui/app.py
examples: (probe p10b U5; E1 probe p10) a patched image, `_handle_load_dialog(<tmp>/other.s19)` → stack `['Screen']`, `current_file.path.name == "other.s19"`: the patch is replaced with no question (holds on base; RED side of HLR-174 / LLR-174.4)
examples: (test_handle_load_dialog_defers_load_until_after_modal_dismiss) a `Path` → `_load_path_from_user_input` scheduled with `call_after_refresh`, not run inside the dismiss (holds on base; the same deferral S-b asks of `go`)

> callers (extractor): none listed (dismiss callback)

S19TuiApp._route_load_project
req: LLR-174.1b, LLR-174.3, LLR-174.3a, LLR-174.4, LLR-174.4a
in: str? name
out: None
func: runs `_handle_load_project(name)`, then pushes `LoadResultScreen(announcement)` (dismiss → `_handle_load_result`) when `_last_load_announcement` holds a new object. Callers: base — the `LoadProjectScreen` dismiss and `_load_path_from_user_input` (`project`); post-9b — `_handle_load_dialog` (`project`) and `_load_path_from_user_input`. Its docstring: "A direct `_handle_load_project` call (tests, fixtures) meets no modal." Inc 10 changes: the seam with kind `project` before `_handle_load_project` (S-d), so the guard reads D / F / W before the reset and `go` is the existing body.
module: s19_app/tui/app.py
examples: (probe p10b U6) a patched image with `4` document entries, `_route_load_project("PV")` → stack `['Screen', 'LoadResultScreen']`, `current_project == "PV"`, no question (holds on base; RED side of LLR-174.1b)
examples: (probe p10b U9) `M2` (1 data + 2 MAC files) with D and W → refused before the reset: `0` reset calls, D still `True`, W still `True`, session unchanged, no `LoadResultScreen` (holds on base; LLR-174.3c's outcome already holds for the body `go` will run)

> callers (extractor): `S19TuiApp._load_path_from_user_input` (direct, :12936)

S19TuiApp._handle_load_result
req: HLR-174, LLR-174.4
in: str? choice
out: None
func: the Load-result panel's dismiss callback: `LOAD_RESULT_SELECT_VARIANT` (`v` / `#result_variant`) → `action_select_variant()`. Unchanged by Inc 10: the panel's `v` reaches the seam through `_handle_select_variant` (A8).
module: s19_app/tui/app.py
examples: (probe p10b U7) `_handle_load_result("select_variant")` → stack `['Screen', 'SelectVariantScreen']` (holds on base)

> callers (extractor): none listed (dismiss callback)

S19TuiApp.action_select_variant
req: HLR-174, LLR-174.4
in:
out: None
func: the `v` key (and palette, and the panel's `v`): no variant set → status "No project variants to select."; else pushes `SelectVariantScreen(project, options, active_index)` with `_handle_select_variant` as dismiss callback. Unchanged by Inc 10.
module: s19_app/tui/app.py
examples: (probe p10b U7) after project `PV` → `SelectVariantScreen` pushed (holds on base)

> callers (extractor): `S19TuiApp._handle_load_result` (direct, :7507)

S19TuiApp._handle_select_variant
req: HLR-174, LLR-174.1, LLR-174.2o, LLR-174.4
in: str? variant_id
out: None
func: `None` → log, return; descriptor lookup ("Variant not found: …"); missing file ("Variant file missing: …"); then `self._pending_variant_id = variant_id` and `load_from_path(descriptor.path)`. Inc 10 changes: the seam with kind `image` after the descriptor checks; the `_pending_variant_id` stamp must move inside `go` (on base it is set before the load, so a stamp before a cancelled question would leak into the next install).
module: s19_app/tui/app.py
examples: (probe p10b U8; E1 probe p10) project `PV`, patched, `_handle_select_variant("firmware_b")` → stack `['Screen']`, active `firmware_b`, D `False`: the patch is replaced with no question (holds on base; RED side of HLR-174)
examples: (probe p10b U8) `load_from_path` spied → `1` call `('firmware_b.s19', 'firmware_b')`: `_pending_variant_id` is already set when the load runs (holds on base; the target name of LLR-174.2o is `descriptor.path.name`)

> callers (extractor): none listed (dismiss callback)

S19TuiApp._load_path_from_user_input
req: LLR-174.4, LLR-174.4a, LLR-174.4b
in: Path path
out: None
func: the typed-path router: `_typed_load_route(path)` → `project` → `_route_load_project(value)`; `a2l` → `load_a2l_from_path(path)`; `data` → `load_from_path(path)`; `refuse` → one status line. Callers: `on_mount` (start-up `load_path`) and the Load router. Inc 10 changes: `data` → kind `attach` when the suffix is `.mac`, else `image`; `a2l` → `attach` (no question); `project` unchanged (the seam is in `_route_load_project`); `refuse` unchanged (LLR-174.4b).
module: s19_app/tui/app.py
examples: (probe p10b U3) a patched image, `_load_path_from_user_input(<tmp>/typed.mac)` → stack `['Screen']`, image `firmware.s19` kept, MAC `typed.mac` attached, the patched byte kept, D `True` (holds on base; an attach loses nothing, LLR-174.1a / .4b)
examples: (probe p9b U4, baseline-9b; same code on base) `<workarea>/E` (empty) → status "Project NOT loaded: … is not a project — pick a project in the list." (holds on base)

> callers (extractor): `S19TuiApp.on_mount` (direct, :7228)

S19TuiApp._typed_load_route
req: LLR-174.4b
in: Path path
out: tuple(str action, str value)
func: classifies one typed path from metadata only: `("project", name)`, `("a2l", "")`, `("data", "")` or `("refuse", reason)`. `data` covers every `SUPPORTED_EXTENSIONS` suffix, MAC included: the action does not tell an image from an attach. Unchanged by Inc 10 (a 9a / 9b function; changing its return set re-pins TC-B100-3x).
module: s19_app/tui/app.py
examples: (probe p10b U3) `<tmp>/typed.mac` → `("data", "")`; `<tmp>/typed2.MAC` → `("data", "")`; `<tmp>/other.s19` → `("data", "")` (holds on base; the kind must come from the suffix, LLR-174.4b)
examples: (probe p10b-q4) a typed absolute `<tmp>\x.mac.` (the file `x.mac` exists) → `("refuse", "not a supported file")`, 1 refusal line, the image and MAC unchanged; `Path("x.mac.").suffix == ""` and `recent_kind(Path("x.mac."))` is `None` (holds on base; interface question Q-4)

> callers (extractor): `S19TuiApp._load_path_from_user_input` (direct, :12934)

S19TuiApp.load_from_path
req: LLR-174.4
in: Path path
out: None
func: the data / MAC load: resolve, suffix check, `copy_into_workarea` into `temp/`, record when outside, `_start_load_worker(copied)`; the worker's parse merges a MAC onto the current image (`_merge_mac_with_existing_primary`). Unchanged by Inc 10; inside every `go` of a data route.
module: s19_app/tui/app.py
examples: (probe p10b U3) a typed `.mac` → the current image kept, MAC attached (holds on base)
examples: (probe p10b U5) a typed `.s19` → the image replaced (holds on base)

> callers (extractor): `S19TuiApp._handle_select_variant` (direct, :7611); `S19TuiApp._load_path_from_user_input` (direct, :12942)

S19TuiApp.load_a2l_from_path
req: LLR-174.1a, LLR-174.4b, LLR-174.4c
in: Path path
out: None
func: the synchronous A2L attach: resolve, suffix, open-project guard, copy, record, parse, views, "A2L loaded: …". Leaves the image and the change document alone. Unchanged by Inc 10.
module: s19_app/tui/app.py
examples: (code read; HLR-174a scene list) an unsaved patch, then an A2L load → the image map untouched, D unchanged (holds on base)

> callers (extractor): `S19TuiApp._load_from_item` (direct, :13333); `S19TuiApp._load_path_from_user_input` (direct, :12939)

S19TuiApp.load_selected_file
req: LLR-174.4c
in: Path path; list[Path]? a2l_files = None
out: None
func: the in-place synchronous load of a file already in the work area (parse through `_parse_loaded_file`, install). A `.mac` merges onto the current image. Unchanged by Inc 10.
module: s19_app/tui/app.py
examples: (E1 probe p10) a patched image, `load_selected_file(<temp>/firmware.mac)` → stack `['Screen']`, the patched byte kept, D `True` (holds on base; a work-area MAC is an attach, LLR-174.4c)

> callers (extractor): `S19TuiApp._handle_load_project` (direct, :11920); `S19TuiApp._load_from_item` (direct, :13335)

S19TuiApp._load_from_item
req: LLR-174.4, LLR-174.4c
in: ListItem item
out: None
func: base: the Workarea Files pick: `item.data` → `workarea/temp/<name>`; exists → `.a2l` → `load_a2l_from_path`, else `load_selected_file`. post-9b: a 3-line wrapper over `_load_workarea_file(item.data)`. Inc 10 changes: none (the seam is in `_load_workarea_file`, which both surfaces share).
module: s19_app/tui/app.py
examples: (probe p10b U4; E1 probe p10) a patched image, pick `prg.s19` → stack `['Screen']`, `current_file.path.name == "prg.s19"`, the 2 document entries kept (holds on base; RED side of HLR-174, P-42)

> callers (extractor): `S19TuiApp.on_list_view_selected` (direct, :13183)

S19TuiApp.on_list_view_selected
req: LLR-174.4c
in: ListView.Selected event
out: None
func: routes `ListView.Selected` by list id; `files_list` → `_load_from_item(event.item)`. Unchanged by Inc 10.
module: s19_app/tui/app.py
examples: (test_tc_b100_12_workarea_files_pick_rehomes_focus) a `#files_list` pick → that file loads and the focus is re-homed (holds on base)

> callers (extractor): none listed (framework)

S19TuiApp.on_mount
req: LLR-174.4
in:
out: None
func: start-up; a command-line `load_path` → `_load_path_from_user_input(load_path)`. LLR-174.4's census exempts it: nothing is unsaved at mount, so the guard cannot ask there. Unchanged by Inc 10.
module: s19_app/tui/app.py
examples: (code read, `app.py:7226-7228`) `load_path` given → one typed-route call before any edit, D `False` (holds on base)

> callers (extractor): none listed (framework)

S19TuiApp._handle_load_project
req: LLR-174.3b, LLR-174.3c, LLR-165.3
in: str? name
out: None
func: the project load: refusals (folder, not listed, `validate_project_files` error, A2L, no data) all before the reset; then `discarded_unsaved = self._reset_project_session()` (`:11821`), the installs, the announcement, and the interim line `Closed the Patch Editor document (N entries); unsaved changes were not kept` when N > 0 (`:11943-11953`). Pushes no screen. post-9b: the `_list_project_files` listing, the `project.json` gate and an `OSError` catch (9b). Inc 10 changes: delete the interim block (LLR-165.3, ruling Q2); still no push and no seam inside (LLR-174.3b).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.current_project] (replace)
examples: (probe p10b U6) 4 document entries, project `PV` → status `Closed the Patch Editor document (4 entries); unsaved changes were not kept`, while W was `False` before the load (the entries came from the service, not the panel) (holds on base; the line is false for a document with no unsaved panel edits, ruling Q2)
examples: (test_tc_b100_10_interim_discard_notice, test_tc_b100_10_notice_names_every_discarded_entry) the interim line pinned (holds on base; RED after Inc 10, re-pinned to 0 lines)
examples: (probe p10b U9) `M2` with 2 MAC files → refused before the reset, `0` resets (holds on base)

> callers (extractor): `S19TuiApp._route_load_project` (direct, :7478)

S19TuiApp._reset_project_session
req: LLR-165.3, LLR-174.3, LLR-174.3a
in:
out: int discarded
func: resets S1–S13, rebinds `ChangeService()`, clears the paste buffer and calls `panel.mark_loaded()`; returns the outgoing document's entry count, read only by the interim line. Inc 10 changes: its return loses its only reader (E1 A10; keep or drop is G-B's, 2 tests monkeypatch it and pass the value through).
module: s19_app/tui/app.py
examples: (probe p10b U6) 4 outgoing entries → returns `4` (holds on base)
examples: (probe p10b U6) after it, D `False` and W `False` (holds on base)

> callers (extractor): `S19TuiApp._handle_load_project` (direct, :11821)

S19TuiApp._handle_save_dialog
req: LLR-174.1c, LLR-167.8
in: SaveProjectPayload? payload
out: None
func: Save project; on success with a mounted panel: `_save_clears_panel_flag(...)` → `panel.mark_saved()`; elif the document is recorded in the project home and `panel._dirty` (`:10576`, the one private read of the flag outside `screens_directionb.py`) → a status line that the panel's edits are in no file. Inc 10 changes: `panel._dirty` → `panel.is_dirty` (LLR-174.1c, ruling Q6).
module: s19_app/tui/app.py
examples: (E1 probe p10) `private reads of panel._dirty in app.py: 1 [10576]` (holds on base; RED side of LLR-174.1c)

> callers (extractor): none listed (dismiss callback)

S19TuiApp._rehome_focus_after_load
req: LLR-166.1
in:
out: None
func: when `default_screen.focused` fails `_focus_needs_rehome` (or is `None`), focus the displayed window's target through `Screen.set_focus`; a healthy focus is left alone; never moves a focus inside an open modal. post-9b: also run by the router on a `None` result (A9b-03). Inc 10 changes: none in body; run once on a cancelled question (LLR-166.1's Inc 10 arm, E1 A13).
module: s19_app/tui/app.py
examples: (test_tc_b100_12_stale_text_input_in_a_content_window_is_rehomed) a stale text `Input` focus → moved to the window's target (holds on base)

> callers (extractor): `S19TuiApp.load_a2l_from_path` (direct, :13173); `S19TuiApp.load_selected_file` (through an unmarked helper; 1 site(s))

S19TuiApp.on_patch_editor_panel_dirty_load_requested
req: LLR-174.2j
in: PatchEditorPanel.DirtyLoadRequested event
out: None
func: pushes `LoadGuardScreen()` with a local `_answer(accepted)` closure: `False` → status "Patch Editor: load cancelled — changes kept."; `True` → `_patch_editor_load(panel, path_text)`. The closure-continuation shape `_confirm_then_load` can follow. Unchanged by Inc 10 (LLR-174.2j).
module: s19_app/tui/app.py
examples: (test_at_b94_06_dirty_load_accept_loss) Accept → the typed document loads (holds on base)
examples: (probe p10b U13) a dirty panel's Load → `LoadGuardScreen` pushed (holds on base)

> callers (extractor): none listed (message handler)

LoadDialog.__init__
req: HLR-174, LLR-174.4
in: str mode; str? highlight; Callable rows; Callable verdict; Callable preview
out: LoadDialog screen
func: (post-9b, from the 9b graph; not yet in code) `ModalScreen[Optional[LoadChoice]]`; dismisses a `LoadChoice(kind, value)` only after `verdict` returned `None`, `None` on Cancel / escape; outer id `#load_box`. Its dismiss callback is the one router `_handle_load_dialog`. Unchanged by Inc 10: the question comes after the dialog has closed (E1 §5 observation 1), so `n` does not reopen it.
module: s19_app/tui/screens.py
examples: (post-9b, proto-9b-app B07–B13) `LC("project", "ab")`, `LC("workarea", "x.s19")`, `LC("path", text)`, `LC("recent", text)` → the router defers the matching leaf through `call_after_refresh`

> callers (extractor): not run (no code)

S19TuiApp._load_workarea_file
req: LLR-174.4, LLR-174.4c
in: str name
out: None
func: (post-9b, from the 9b graph; not yet in code) G1: `candidate = workarea/temp/name`; exists → A2L suffix → `load_a2l_from_path(candidate)`, else `load_selected_file(candidate)`. Shared by the `#files_list` pick (`_load_from_item`) and the dialog's `workarea` choice. Inc 10 changes: the seam with kind by suffix (`.mac` / `.a2l` → `attach`, else `image`), before the load and after `candidate.exists()` (LLR-174.4c).
module: s19_app/tui/app.py
examples: (post-9b, proto-9b-app B87) a `#files_list` pick of `x.s19` and `LC("workarea", "x.s19")` → equal session digests, `0` `copy_into_workarea` calls

> callers (extractor): not run (no code)

## Entities

[Data: S19TuiApp.BINDINGS]
desc: the priority keys `ctrl+l` → `load_file`, `ctrl+s` → `save_project`, `ctrl+k` → `focus_palette`, `ctrl+d` → `cycle_density` run under any modal (probe p10b U11). `v` → `select_variant`; `l` (hidden) → `load_file`. Non-priority app keys do not reach the app under a modal (probe p10b U11: `l`, `p` inert under `LoadGuardScreen`).

[Data: _LOAD_DIALOG_INERT_ACTIONS]
desc: (post-9b, not yet in code) `frozenset({"load_file", "save_project", "focus_palette", "cycle_density"})`, read by `check_action` with the `LoadDialog` stack test. Inc 10 widens the screen test, not the set.

[Data: PatchEditorPanel._dirty]
desc: W. Writers: w1 `request_action` (entry edit), w2 `on_text_area_changed` (paste typing), w3 `mark_saved`, w4 `mark_loaded`, w5 `mark_pasted`. Readers in its module: the doc-load guard, the marker, the JSON stamp. Reader outside: `app.py:10576` (private). No public reader on base (probe p10b U0: `is_dirty` absent).

[Data: S19TuiApp._pending_variant_id]
desc: stamped by `_handle_select_variant` before `load_from_path`, consumed by the install (`_apply_prepared_load`). A stamp left by a cancelled request would label the next install.

[Data: S19TuiApp.current_project]
desc: the open project's on-disk name; the question's title source (LLR-174.2k).

[Data: App.screen_stack]
desc: base: a load over unsaved work leaves `['Screen']` on every route (probe p10b U3–U8). A question would be one `ModalScreen[bool]` on top.

## Edges

[Outside: key v] ──▶ S19TuiApp.action_select_variant
[Outside: key ctrl+l] ──▶ S19TuiApp.action_load_file
when: always, also with a modal on top (priority)
[Data: PatchEditorPanel._dirty] ──▶ S19TuiApp._handle_save_dialog
when: private read, `app.py:10576`
