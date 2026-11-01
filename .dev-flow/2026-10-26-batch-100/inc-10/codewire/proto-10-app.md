# Code-Wire prototype — Inc 10, group G-B (`s19_app/tui/app.py`)

Stage E2 of the design-first pipeline (`dev-flow-v3-beta`) for Inc 10 ("one short question before unsaved work is lost"). Graph only: no stub, mark or other change in `s19_app/` of any tree. New functions are nodes whose `func:` starts with "new". Base: main `8947666` (Inc 9a merged) plus the 9b graph (`../../inc-9b-design/codewire/proto-9b-app.md`, `interfaces-9b.md`); line numbers are `8947666` lines of `s19_app/tui/app.py` unless another file is named. The router `_handle_load_dialog`, `_load_workarea_file` and `check_action` start from 9b's design.

Inputs: `../E1-requirements-draft.md`, `../E1-scope.md`, `../E1-rulings.md` (Q1–Q8), `../E2-rulings.md` (undo boundary, `_pending_variant_id`, census, `ConfirmDiscardScreen`), `baseline-10.md`, `baseline-notes.md`, `interfaces-10.md` (FIXED; this file proposes two clarifications, no signature change). One small pure probe was run: `../work/gb/probe-gb-strip.py` (output `probe-gb-strip.out.txt`).

Conventions:
- `D` = the unsaved image (`ChangeService.differs_from_last_saved(current_file.mem_map)`); `W` = the Patch Editor dirty flag (`PatchEditorPanel.is_dirty`, G-A); `F` = the Flow Builder dirty flag (`FlowBuilderPanel.is_dirty`).
- `pn(x)` = `painted_names([x])` (the batch's one scrub). `Q(title, body)` = a `ConfirmQuestionScreen(title, body, "Replace (y)", "Cancel (n)")` pushed on top of the stack. "The question" is that screen.
- `W` as a folder name never appears; the work area is `<W>`. `<tmp>` = a temporary folder outside the base folder.
- "Session digest" and "kept work" as in the draft's conventions (digest: `current_file.path`, image SHA-256, `current_project`, `current_a2l_path`, MAC path; kept work adds the Patch Editor entry count and flag, the Flow Builder blocks and flag, and the recent-store SHA-256).
- Every example states the Inc 10 target unless it says "holds on base".

## Placement and counts (S-d, fixed)

The seam lives in the four leaves; the 9b router is unchanged. One question per request:

| Request | Path | Seam calls |
|---|---|---|
| typed project folder | router → `_load_path_from_user_input` (project arm, no seam) → `_route_load_project` (seam) | 1 |
| project row | router → `_route_load_project` | 1 |
| typed / recent data or A2L | router → `_load_path_from_user_input` (data / a2l arm) | 1 |
| `v`, the panel's `v` | `SelectVariantScreen` dismiss → `_handle_select_variant` | 1 |
| Workarea, either surface | router or `_load_from_item` → `_load_workarea_file` | 1 |
| start-up `load_path` | `on_mount` → `_load_path_from_user_input` | 1 (nothing unsaved → `go()` at once) |

## Owned nodes (13) and context (5)

- **3 new:** `_confirm_then_load`, `_load_would_lose`, `_load_question_text`.
- **9 changed:** `_route_load_project`, `_load_path_from_user_input`, `_load_workarea_file` (post-9b), `_handle_select_variant`, `check_action` (post-9b), `_handle_load_project`, `_reset_project_session`, `_handle_save_dialog`, `on_patch_editor_panel_change_file_selected`.
- **1 data node:** the module type aliases `QuestionKind`, `UnsavedItem`.
- **Retired:** none. (The interim closed-document block inside `_handle_load_project` is deleted; it is not a node.)
- **Context (unchanged, new or confirmed callers):** `_rehome_focus_after_load`, `_handle_load_dialog` (9b), `_load_from_item` (9b), `on_patch_editor_panel_dirty_load_requested`, `on_mount`.

**Imports (app.py):**
- `ConfirmQuestionScreen` joins the `.screens` import (after 9b's `LoadChoice`, `LoadDialog`).
- `Literal` joins the `typing` import (not imported on base; the aliases are evaluated at run time even under `from __future__ import annotations`).
- Already imported: `MAC_EXTENSIONS`, `A2L_EXTENSIONS` (`.workspace`, :250-262), `painted_names`, `FlowBuilderPanel`, `PatchEditorPanel`, `Callable`.

## Nodes

Module type aliases (data)
req: LLR-174.4, LLR-174.4b, LLR-174.4c, HLR-174d
in:
out:
func: new, module level in `app.py`, exactly as `interfaces-10.md`:
- `QuestionKind = Literal["image", "attach", "project"]`;
- `UnsavedItem = tuple[Literal["image", "document", "flow"], str]` — (kind, raw unscrubbed name); `document` carries `""`.
module: s19_app/tui/app.py
examples: C01 (unit, closed set) `typing.get_args(QuestionKind) == ("image", "attach", "project")` (`1` of `1`). Every `_confirm_then_load(` call in `app.py` (AST) passes a string literal or a name bound only to one of those three literals as `kind` → `5` call sites (`_route_load_project` 1, `_load_path_from_user_input` 2, `_load_workarea_file` 1, `_handle_select_variant` 1), `0` other literals. Negative control: a site passing `"data"` → census RED.

S19TuiApp._confirm_then_load
req: HLR-174, HLR-174a, HLR-174b, HLR-174c, LLR-174.1, LLR-174.1a, LLR-174.1b, LLR-174.2, LLR-174.2p, LLR-174.3, LLR-174.3a, LLR-174.4, LLR-174.4a, LLR-166.1 (Inc 10 arm)
in: QuestionKind kind, str target, Callable[[], None] go
out: None
func: new (B100-I20; S-b). The one load seam. Steps:
- (1) `items = self._load_would_lose(kind)`.
- (2) `items == []` → `go()` at once, then return. No question, no log. Every caller already runs after its own modal popped (the 9b router defers through `call_after_refresh`; a dismiss callback runs after the pop), so this is the base behaviour of each route, unchanged.
- (3) Otherwise `title, body = self._load_question_text(kind, target, items)`, then `self.push_screen(ConfirmQuestionScreen(title, body, "Replace (y)", "Cancel (n)"), answer)`, where `answer(replace)` is a local closure (the shape of `on_patch_editor_panel_dirty_load_requested`'s `_answer`):
  - `self.logger.info("Load question answered: replace=%s kind=%s", bool(replace), kind)` (diagnostic only; the cancel paints nothing, so the log is the one trace);
  - `replace` truthy → `self.call_after_refresh(go)`: the question has popped before any load work runs (the 9b router's reason, :12999);
  - else → `self._rehome_focus_after_load()` and nothing more: `0` status lines (ruling Q3), no reset, no flag change, `go` never called (LLR-174.3a, LLR-166.1 Inc 10 arm). A `None` (not expected from the modal, S-a) is treated as cancel by the same truthiness test.
- The seam never reads `_dirty` (LLR-174.1c); it holds no `try/except`.
callers: `_route_load_project`, `_load_path_from_user_input` (data and a2l arms), `_load_workarea_file`, `_handle_select_variant`. No other caller (C05 census).
module: s19_app/tui/app.py
modify: [Data: App.screen_stack] (push 1 question when items is non-empty)
examples: C02 (HLR-174, LLR-174.2, LLR-174.4) `fw.s19` loaded, one byte patched (D), no project. Through keys: `l`, type `<tmp>/b.s19`, `enter` → stack `['Screen', 'ConfirmQuestionScreen']` (depth `+1`, `1` push) and, while it is on top, the session digest equals the digest before the request; the top screen was built with labels `Replace (y)` / `Cancel (n)`. The same with a `#files_list` pick of `x.s19` and with `v` to `firmware_b` in project `PV` → `3` questions, `1` per request. Result `3` of `3`. Negative control (holds on base, probe p10b U4/U5/U8): each route leaves `['Screen']` and replaces the image → RED.
examples: C03 (HLR-174b) the C02 arms answered `y` → after the refresh `current_file.path.name` is `b.s19`, `x.s19` and `firmware_b.s19` respectively, and the question is gone (stack `['Screen']`). The project arm: `PV` open with W, row `Q`, `y` → `current_project == "Q"` and `1` `LoadResultScreen`. Result `4` of `4`. Negative control: a mutation whose `answer` drops `go` on `True` → `0` loads → RED.
examples: C04 (HLR-174c, LLR-174.3a) a project load `Q` with D, F and W set, and a data load `<tmp>/b.s19` with D; each cancelled by `n`, by `escape` and by an immediate `enter` (focus on `#confirm_no`, G-A) → session digest and kept work unchanged, `0` calls of `go` (spy), `0` calls of `_reset_project_session` (spy), `0` new status lines. Result `6` of `6`. Negative control: a mutation that calls `go` before pushing → the cancelled project arm finds the Patch Editor empty → RED.
examples: C05 (LLR-174.4, AST census of `app.py` after Inc 10) every call of `load_selected_file`, `load_from_path`, `load_a2l_from_path` and `_handle_load_project` is (a) inside a nested function passed as the third argument of `_confirm_then_load`, or (b) inside `_handle_load_project` (the MAC install, :11920), or (c) `load_from_path`'s own worker start → `0` bypasses. `_route_load_project`'s callers (`_handle_load_dialog`, `_load_path_from_user_input` project arm) are exempt because its body is the seam (F-7, proposal P-2). Negative control: the base tree (`_load_from_item` :13333/:13335, `_handle_select_variant` :7611, `_load_path_from_user_input` :12939/:12942) → `6` bypasses → RED.
examples: C06 (LLR-174.4a) with D and W: typed `<W>/P` (router → typed route → project route) → `1` question; a recent `C:\s\fw.s19` → `1`; a project row `P` → `1`. After `y` on each, `0` further `ConfirmQuestionScreen` pushes until the load ends (spy on `push_screen` by screen type). Result `3` of `3`. Negative control: a mutation that also guards `_load_path_from_user_input`'s project arm → the typed `<W>/P` asks `2` times → RED.
examples: C07 (LLR-174.3) project `P` open with W; load `Q` → `y`; an order spy on `ConfirmQuestionScreen.dismiss` and `_reset_project_session` → order `["dismiss", "reset"]`, `1` reset. Re-load `P` itself with W → the same order, `1` reset. Result `2` of `2`. Negative control: a mutation that runs `go` before the push → order `["reset", "dismiss"]` → RED.
examples: C08 (LLR-166.1 Inc 10 arm, §C.2) Patch window, focus on `#patch_entry_address_input` (an `Input`), D set: `ctrl+l`, type `<tmp>/b.s19`, `enter` → question → `n` → `focused.id == "patch_entry_address_input"` **(corrected at close — LLR-166.1 governs: a visible, healthy `Input` keeps the focus, so the landing is the `Input`, not `patch_editor_panel`; the oracle is a spy count of 1 on `_rehome_focus_after_load`, SR-1)**. Workspace window, focus on `#files_list`, D set: pick `x.s19` → question → `escape` → `focused.id == "files_list"` (a healthy focus kept). Result `2` of `2`. Negative control: a mutation whose cancel branch skips `_rehome_focus_after_load` → the spy count is `0` (not `1`) → RED (M36).
examples: C09 (HLR-174a, nothing asked, timing) nothing unsaved: a `#files_list` pick of `x.s19` → `go` runs synchronously inside the `_confirm_then_load` call (`0` `call_after_refresh` scheduled by the seam, spy) and `0` pushes — the base timing of the route, so the 255 non-asking route calls of the census (baseline-notes run A) behave as on base.

S19TuiApp._load_would_lose
req: LLR-174.1, LLR-174.1a, LLR-174.1b, LLR-174.1c, HLR-174a, HLR-174d
in: QuestionKind kind
out: list[UnsavedItem] items
func: new (the guard, E1 A2; S-e). Reads state only, writes nothing; `query_one` raises if a panel is not mounted (both panels always live on the default screen in a running app). Steps:
- (1) `kind == "attach"` → `[]` at once (no read of D, W or F; LLR-174.1a).
- (2) `cur = self.current_file`; if `self._change_service.differs_from_last_saved(cur.mem_map if cur is not None else None)` → append `("image", cur.path.name)`. (`differs_from_last_saved(None)` is `False`, so `cur` is not `None` when this appends.)
- (3) `kind == "project"` only:
  - `panel = self.query_one("#patch_editor_panel", PatchEditorPanel)`; `panel.is_dirty` → append `("document", "")`;
  - `flow = self.query_one("#flow_panel", FlowBuilderPanel)`; `flow.is_dirty` → append `("flow", flow.current_flow.name)`.
- Order is image, document, flow. `image` kind returns at most the image item (W and F never count for an image replacement: the image replacement keeps the document, probe p10 "document entries after WORKAREA pick: 1").
callers: `_confirm_then_load` only.
module: s19_app/tui/app.py
examples: C10 (LLR-174.1, LLR-174.1a, LLR-174.1b; the 24-cell table) for each kind × D × F × W (flags forced: D by a real one-byte patch, W by `panel.request_action("add_entry")`, F by `flow._mark_dirty()`), `bool(_load_would_lose(kind))`: `image` → `True` exactly in the 4 cells with D; `attach` → `False` in all 8; `project` → `False` only in the cell D = F = W = 0. Totals `11` ask, `13` load, `24` of `24`. Negative controls (the LED .17 enumeration): drop D → `5` cells wrong; drop F → `1`; drop W → `1`; an attach that asks on D → `4` → RED.
examples: C11 (HLR-174d item order) D (`a.s19`), W and F (flow `patch_chain`), kind `project` → `[("image", "a.s19"), ("document", ""), ("flow", "patch_chain")]`. D and F → `[("image", "a.s19"), ("flow", "patch_chain")]`. W only → `[("document", "")]`. Kind `image` with D, W, F → `[("image", "a.s19")]`. Result `4` of `4`.
examples: C12 (HLR-174a boundaries, 0 items each) a patch that writes the byte already there (probe p10b U2: D `False`); patched → Save project (`mark_saved`, test_tc_b100_58) → `image`; patched → save-back → `image`; patched → `ctrl+z` → Apply of the now-empty document (byte restored, probe p10b-undo `D = False`) → `image`. Result `4` of `4`.
examples: C13 (E2-rulings undo boundary) patched → `ctrl+z` alone (the entry undone, the byte still `0xaa`, probe p10b-undo `D = True`) → `image` → `[("image", "fw.s19")]` → the data load asks (`1` question). Patched → Save project → patched again → `[("image", …)]` → `1` question. Result `2` of `2`. Negative control: a guard keyed on the document entry count → the undo-alone arm finds `0` entries and loads without asking → RED.
examples: C14 (LLR-174.1a, attach keeps the patch) an unsaved patch, `_load_would_lose("attach")` → `[]` with `0` calls of `differs_from_last_saved` (spy); a MAC attach then keeps the patched byte and D stays `True` (probe p10b U3) (`2` of `2`).
examples: C16 (LLR-174.1c) the flag is read through `panel.is_dirty` (G-A property): with `PatchEditorPanel.is_dirty` patched to a property returning `True` while `_dirty` is `False` → `("document", "")` is present (`1` of `1`). Negative control: a guard reading `panel._dirty` → item absent → RED (and the C52 AST census).

S19TuiApp._load_question_text
req: LLR-174.2i, LLR-174.2k, LLR-174.2l, LLR-174.2m, LLR-174.2n, LLR-174.2o, LLR-174.2q, HLR-174d, LLR-173.7 (Inc 10 arm)
in: QuestionKind kind, str target, list[UnsavedItem] items
out: tuple[str, str] (title, body)
func: new (the composer, E1 A3; ruling Q-3). Pure over `current_project`, `current_file` and the arguments; every name goes through `painted_names` exactly once (Q-2: the one scrub place). Steps:
- (1) `current` = `pn(self.current_project)` if `self.current_project`, else `pn(self.current_file.path.name)` if `self.current_file is not None`, else the literal `the current session`. `title = f"Replace {current}?"` (LLR-174.2k).
- (2) Each item paints as: `image` → `pn(name)`; `document` → `Patch Editor entries`; `flow` → `f"flow {pn(name)}"`.
- (3) `joined` = the single name; for 2 or 3 names `", ".join(names[:-1]) + " and " + names[-1]` (`A and B`, `A, B and C`).
- (4) `shown_target` = `f"project {pn(target)}"` for `kind == "project"`, else `pn(target)` (LLR-174.2o).
- (5) `body = f"There are unsaved changes in {joined}. Load {shown_target} anyway?"`: the token `unsaved changes` once and two sentence ends outside names (LLR-174.2q).
- It returns plain `str`; G-A paints both with markup off (S-a).
callers: `_confirm_then_load` only.
module: s19_app/tui/app.py
examples: C17 (LLR-174.2k, LLR-174.2l, LLR-174.2o; data load, no project) `current_file.path.name == "fw.s19"`, kind `image`, target `b.s19`, items `[("image", "fw.s19")]` → title `Replace fw.s19?`, body `There are unsaved changes in fw.s19. Load b.s19 anyway?`.
examples: C18 (HLR-174d, LLR-174.2m, LLR-174.2n; 3 items) project `P` open, image `a.s19`, kind `project`, target `Q`, items `[("image","a.s19"), ("document",""), ("flow","patch_chain")]` → title `Replace P?`, body `There are unsaved changes in a.s19, Patch Editor entries and flow patch_chain. Load project Q anyway?`.
examples: C19 (2 items; default flow name) same, items `[("image","a.s19"), ("flow","flow")]` → body `There are unsaved changes in a.s19 and flow flow. Load project Q anyway?`.
examples: C20 (1 item, W only) items `[("document","")]` → body `There are unsaved changes in Patch Editor entries. Load project Q anyway?`. Together with C18 and C19: `3` of `3` (HLR-174d threshold). Negative control: a mutation naming only `items[0]` → C18 holds `a.s19` only → RED.
examples: C21 (LLR-174.2k neither) no project, no image, F dirty, kind `project`, target `Q` → title `Replace the current session?`, body `There are unsaved changes in flow flow. Load project Q anyway?`. With C17 and C18: `3` of `3`. Negative control: a mutation that always uses the image name → C18's title `Replace a.s19?` → RED.
examples: C22 (LLR-174.2o, one target per route) row `Q` → `Load project Q anyway?`; typed `<tmp>/b.s19` → `Load b.s19 anyway?`; Workarea `x.hex` → `Load x.hex anyway?`; `v` to `firmware_b` → `Load firmware_b.s19 anyway?` (`4` of `4`). Negative control: a mutation that names `current_file.path.name` as the target → the typed arm paints `Load fw.s19 anyway?` → RED.
examples: C23 (LLR-174.2l, project load) D with `fw.s19`, kind `project` → the body holds `fw.s19`; with C17: `2` of `2`. Negative control: a mutation that names the project instead of the image → C17 (no project) misses `fw.s19` → RED.
examples: C24 (LLR-174.2m) W only → `Patch Editor entries` present (C20); D only (kind `project`, items `[("image","fw.s19")]`) → absent. `2` of `2`. Negative control: a mutation adding the document item on D → present in the D-only arm → RED.
examples: C25 (LLR-174.2q) the bodies of C17, C19 and C18 (1, 2, 3 items) → `unsaved changes` occurs exactly `1` time in each, and the count of `.` / `?` outside the painted names is `2` in each (`3` of `3`). Negative control: a sentence per item → C18 has `4` ends → RED.
examples: C26 (LLR-174.2i, literal names) image `[b]x.s19` → title `Replace [b]x.s19?`, body item `[b]x.s19`; flow `[red]f` → item `flow [red]f`; project `[i]P` as the open project → title `Replace [i]P?`, and as the target → `Load project [i]P anyway?`; image `a` + U+202E + `b.s19` → `ab.s19`; a 130-character image name → 120 characters ending in `…`. Each painted name equals `painted_names([name])` (`5` of `5` plus the clip arm). The `0` spans half is G-A's (markup off). Negative control: a composer passing the raw name → the U+202E arm keeps U+202E → RED.
examples: C27 (LLR-173.7 Inc 10 arm, §C.4) the title and body of C17 (1 item), C18 (3 items, project target) and C21, plus the two labels `Replace (y)` / `Cancel (n)` → `0` matches of `\bD\d+\b`, `\bO-\d+`, `VS-`, `LLR-`, `HLR-` (`5` strings). Negative control: a decision id (UX-18's strings) copied into the body → RED.

S19TuiApp._route_load_project
req: LLR-174.1b, LLR-174.3, LLR-174.3a, LLR-174.3c, LLR-174.4, LLR-174.4a, LLR-167.8 (Inc 10 arm)
in: str name
out: None
func: changed (:7449). Steps:
- (1) `go` = the base body as a local closure: `before = self._last_load_announcement`; `self._handle_load_project(name)`; `announcement = self._last_load_announcement`; push `LoadResultScreen(announcement)` with `_handle_load_result` only when it is a new object.
- (2) `self._confirm_then_load("project", name, go)` (target = the raw on-disk name, Q-2).
- Docstring "Used by" becomes `_handle_load_dialog` (project) and `_load_path_from_user_input` (project arm), and states that the seam is here, so `_handle_load_project` asks nothing.
callers: `_handle_load_dialog` (`project`, deferred; post-9b) and `_load_path_from_user_input` (project arm; extractor: direct :12936). Unchanged set. Tests: `test_b100_project_homes.py:1117`, `:1154`, `:1945` (nothing unsaved → `go()` at once, unchanged).
module: s19_app/tui/app.py
examples: C28 (LLR-174.1b, project kind) `_route_load_project("PV")` with a patched image and W (probe p10b U6 shape) → `1` question, stack `['Screen', 'ConfirmQuestionScreen']`, `current_project` unchanged while it is on top. `y` → `current_project == "PV"`, `1` `LoadResultScreen`. Negative control (holds on base, probe p10b U6): stack `['Screen', 'LoadResultScreen']` with no question → RED.
examples: C29 (HLR-174a, LLR-174.1b boundaries) project `P` open, nothing unsaved, row `Q` → `0` questions, `current_project == "Q"`. Patched + 1 Patch Editor entry (W) → Save project → row `Q` → `0` questions. Re-load the open `P` with nothing unsaved → `0`. Result `3` of `3`. Negative control: the `pb_A` rule "ask when a project is open" → the first arm asks → RED.
examples: C30 (LLR-174.3c) listed project `M2` (1 data file, 2 MAC files) with D and W → `1` question → `y` → `1` refusal line (the 2-MAC refusal of `_list_project_files`), `0` `_reset_project_session` calls, session digest unchanged, D still `True`, W still `True`, the entry count unchanged, `0` `LoadResultScreen` (`5` of `5`; the body's outcome holds on base, probe p10b U9). Negative control: a mutation that clears the flags or resets when `y` is pressed → D or W `False` after the refusal → RED.
examples: C31 (LLR-167.8 Inc 10 arm, §C.3) an entry pasted, Save project (the files hold every entry, `panel.mark_saved()`) → a project load through the Load dialog → `0` questions. A Save project refused (the flag stays set) → the same load → `1` question whose body holds `Patch Editor entries`. Result `2` of `2`. Negative control: a mutation that skips `panel.mark_saved()` → the first arm asks → RED.

S19TuiApp._load_path_from_user_input
req: LLR-174.4, LLR-174.4a, LLR-174.4b, LLR-174.1, LLR-174.1a, HLR-174
in: Path path
out: None
func: changed (:12905), the `a2l` and `data` arms only:
- `action, value = self._typed_load_route(path)` (unchanged; reads metadata only).
- `project` → `self._route_load_project(value)` (unchanged; asked there, LLR-174.4a).
- New, before the two arms: `typed = Path(str(path).strip().strip('"'))` — pure, no filesystem call; the same strip `_typed_load_route` (:12796) and `resolve_input_path` (`workspace.py:2024`) apply. The 9b dialog passes the field text verbatim (9b S-a), so a quoted or padded path reaches here with the quotes (probe gb-strip: `Path('"C:\t\x.mac"').suffix == '.mac"'`, stripped `'.mac'`). F-1, P-1.
- `a2l` → `self._confirm_then_load("attach", typed.name, lambda: self.load_a2l_from_path(path))`.
- `data` → `resolved = resolve_input_path(path, self.base_dir)`; `kind = "attach"` only when the resolved suffix is in `MAC_EXTENSIONS` and equals the typed suffix, else `"image"` (fail closed; a `None` resolve gives `image` too); the target is `(resolved or typed).name`. **(corrected at close — CR10-01/SEC10-01: the kind comes from the resolved path, never the typed text.)** `self._confirm_then_load(kind, target, lambda: self.load_from_path(path))`. The loaders still receive the raw `path`, as on base.
- `refuse` → the one status line, unchanged; no question (LLR-174.4b race arm).
callers: `_handle_load_dialog` (`path`, `recent`; deferred, post-9b); `on_mount` (start-up `load_path`; extractor: direct :7228). Unchanged set.
module: s19_app/tui/app.py
examples: C33 (LLR-174.4b, 5 arms) `fw.s19` loaded with D and W; typed through the dialog: `<tmp>/typed.mac` → `0` questions, MAC attached, patched byte kept, D `True`; `<tmp>/cal.a2l` → `0`, status `A2L loaded: cal.a2l`; `<tmp>/b.s19` → `1` question (body `There are unsaved changes in fw.s19. Load b.s19 anyway?`); `<W>/P` → `1` question whose body holds `Patch Editor entries` (project kind via `_route_load_project`); `<tmp>/gone.s19` deleted after the dialog's verdict (the route classifies `not found`) → `0` questions and `1` line `File NOT loaded: '<tmp>\gone.s19' not found — check the path.`. Result `5` of `5`. Negative control: a mutation that keys the kind on the dismiss kind (`path` → image) → the `.mac` arm asks → RED.
examples: C34 (Q-4 case) typed `<tmp>/typed2.MAC` → kind `attach`, `0` questions (probe p10b U3: `_typed_load_route` gives `("data", "")` for it). Negative control: a case-sensitive test `typed.suffix in MAC_EXTENSIONS` → asks → RED.
examples: C35 (F-1, quoted and padded text) D set; the dialog's field text `"<tmp>\typed.mac"` (with the quotes) → the route accepts it (`("data", "")`) → kind `attach`, `0` questions. Field text `  <tmp>\b.s19  ` → kind `image`, body ends `Load b.s19 anyway?` (no trailing spaces, no quote). Result `2` of `2`. Negative control: the Q-4 rule read on the raw `path` → the quoted MAC asks as an image and the body says `Load typed.mac" anyway?` → RED.
examples: C36 (HLR-174b recent) a recent `C:\s\fw.s19` with D → `1` question → `y` → the work copy of `fw.s19` installed and the store's first entry is that path (the 9a record after the load). `n` → the store's SHA-256 unchanged (HLR-174c boundary "a typed path whose recent entry would be recorded"). Result `2` of `2`.
examples: C37 (start-up, LLR-174.4) `S19TuiApp(load_path=<tmp>/fw.s19)` → `on_mount` → `_load_path_from_user_input` → `_load_would_lose("image")` → `[]` (D `False` for `None`) → `go()` at once; `0` questions, `fw.s19` loaded (holds on base for the load).

S19TuiApp._load_workarea_file
req: LLR-174.4, LLR-174.4c, LLR-174.1, LLR-174.1a, HLR-174
in: str name
out: None
func: changed (post-9b G1 node). `candidate = self.workarea / WORKAREA_TEMP / name`; `if not candidate.exists(): return` (silent, as 9b B88). Then `kind = "attach" if candidate.suffix.lower() in (MAC_EXTENSIONS | A2L_EXTENSIONS) else "image"` (LLR-174.4c, case-folded); `go` = the 9b body: log `Loading from workarea selection: %s`, then `load_a2l_from_path(candidate)` for an A2L suffix, else `load_selected_file(candidate)`. `self._confirm_then_load(kind, name, go)` (target = the on-disk name). The `exists()` check stays before the seam: a vanished file asks nothing.
callers: `_load_from_item` (`#files_list`, post-9b wrapper); `_handle_load_dialog` (`workarea`, deferred). Both unchanged.
module: s19_app/tui/app.py
examples: C38 (LLR-174.4c, 8 arms) D set; `W/temp` holds `x.mac`, `c.a2l`, `x.s19`, `x.hex`. From the Load dialog's `workarea` rows and from `#files_list` → questions `0`, `0`, `1`, `1` on each surface (`8` of `8`). Upper case `X.MAC` → `0` on both. Negative control: a suffix-blind mutation (always `image`) → the `.mac` and `.a2l` arms ask → RED.
examples: C39 (race, F-6) D set, pick `x.s19` → question open; the test deletes `W/temp/x.s19`; `y` → `go` → `load_selected_file` → `_parse_loaded_file` raises `FileNotFoundError` → `1` status line starting `Load failed:`, the session digest unchanged (the patched image stays, D `True`). Declared: loss-free, no re-check inside `go` (rule 2). Negative control: none needed (pre-existing loader behaviour); the RED for loss would be an install of an empty image.

S19TuiApp._handle_select_variant
req: LLR-174.4, LLR-174.1, LLR-174.2o, HLR-174, LLR-174.3d (E2-rulings)
in: Optional[str] variant_id
out: None
func: changed (:7558). The `None` and no-set arms are unchanged and run before the seam (they ask nothing). The `Variant not found` and `Variant file missing` lines paint through `painted_names` (S10-04): `Variant not found: {painted_names([variant_id])}` and `Variant file missing: {painted_names([descriptor.path.name])}`, one call each. `load_from_path`'s own `File not found` / `Load failed` lines (C43's race outcome) stay raw and go to a backlog row (Inc 12a sweep, S10-04). Then:
- `go` = local closure: `self.logger.info("Activating variant '%s' via load pipeline: %s", variant_id, descriptor.path)`; `self._pending_variant_id = variant_id`; `self.load_from_path(descriptor.path)`.
- `self._confirm_then_load("image", descriptor.path.name, go)`.
- The stamp is set only inside `go` (E2-rulings): on base it is set before the load (probe p10b U8), so a stamp outside `go` would survive a cancel and label the next install (`_apply_prepared_load` :15337-15345).
- Docstring Data Flow: "Stamp `_pending_variant_id` on the main thread, then dispatch" gains "inside the confirmed continuation".
callers: `action_select_variant` (`SelectVariantScreen` dismiss; `v`, palette, and the panel's `v` through `_handle_load_result` → `action_select_variant`). Tests: `test_tui_patch_variant.py` (direct; census: D `False` in both recorded calls), `test_tui_variants.py`. Unchanged set.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._pending_variant_id] (only inside `go`)
examples: C40 (HLR-174, `v` by keys) project `PV` (`firmware_a` active, `firmware_b`), one byte patched; `v`, pick `firmware_b`, `enter` → `1` question with body `There are unsaved changes in firmware_a.s19. Load firmware_b.s19 anyway?` and title `Replace PV?`; `y` → active `firmware_b`, `load_from_path` called `1` time with `firmware_b.s19`. Negative control (holds on base, probe p10b U8): no question, active `firmware_b` → RED.
examples: C41 (HLR-174 / LLR-174.4 panel `v`, forced state, ruling Q5) right after project `PV` loads, D is `False` (probe p10b U7); the test forces D by `monkeypatch.setattr(app._change_service, "differs_from_last_saved", lambda m: True)` (declared private call); the Load-result panel's `v` → `SelectVariantScreen` → `firmware_b` → `1` question; `n` → active `firmware_a`, digest unchanged (`2` of `2`).
examples: C42 (LLR-174.3d, E2-rulings) as C40, but `n` → `_pending_variant_id is None` (unchanged), `0` `load_from_path` calls, `_variant_set.active_id == "firmware_a"`. Then a `#files_list` pick of `other.s19` answered `y` → after the install `current_file.variant_id is None` and `_variant_set.active_id == "firmware_a"`. Result `2` of `2`. Negative control: the stamp left before the seam (base order) → `_pending_variant_id == "firmware_b"` after `n`, and the later install stamps `other.s19` as `firmware_b` and makes it active → RED.
examples: C43 (race) the C40 question open, the test deletes `firmware_b.s19`, `y` → `go` → `load_from_path` → `File not found: …` status (:13033-13037), `_pending_variant_id` cleared back to `None` by that arm, session unchanged. Declared, loss-free.
examples: C44 (nothing unsaved) `v` → `firmware_b` with D `False` → `0` questions, `load_from_path` called synchronously inside the dismiss callback, as on base (p10b U8 order: stamp, then load).
examples: C60 (S10-04, painted refusal lines) a variant id holding a soft hyphen after `v` with no matching descriptor → the line paints `Variant not found: vX` (soft hyphen removed); a `descriptor.path` name `a` + U+202E + `b.s19` that does not exist → `Variant file missing: ab.s19`; `_handle_load_project("A" + U+202E + "B")` on a project with no data file → `No supported files in project: AB`. Each of the three lines paints one `painted_names` call. Result `3` of `3`. Negative control: the raw-name lines on base → U+202E stays and reverses the painted line → RED.

S19TuiApp.check_action
req: LLR-174.2h
in: str action, tuple parameters
out: Optional[bool]
func: changed (post-9b G3, :8034). The first test becomes `if action in _LOAD_DIALOG_INERT_ACTIONS and any(isinstance(s, (LoadDialog, ConfirmQuestionScreen)) for s in self.screen_stack): return False`. The action set is 9b's, unchanged (`load_file`, `save_project`, `focus_palette`, `cycle_density`). Then the window gates and `super().check_action`, unchanged. Docstring: the summary names the question beside the Load dialog.
callers: Textual `App.run_action` (every key binding and palette dispatch); `window_help.py:1134`, `:1145` (the key bar dims a key this returns `False` for; unmarked sites). Unchanged set.
module: s19_app/tui/app.py
examples: C45 (LLR-174.2h) D set, a data load asks; with the question on top: `ctrl+l` → depth unchanged, the question on top, `0` calls of `action_load_file` (spy); `ctrl+s` → `0` `action_save_project`; `ctrl+k` → `0` `action_focus_palette`; `ctrl+d` → `0` `action_cycle_density`. Result `4` of `4`. Negative control (executed on base with a stand-in modal, probe p10b U11: all four ran, `ctrl+l` stacked `LoadFileScreen`, `ctrl+s` stacked `SaveProjectScreen`); with 9b's guard alone (`LoadDialog` only) the question is not in the test → `ctrl+l` pushes a `LoadDialog` over the question → RED.
examples: C46 (whole stack) with the question on top, `ctrl+p` (Textual command palette over it), then `ctrl+s` → `0` `SaveProjectScreen` pushes; `ctrl+l` → `0` `LoadDialog` (`2` of `2`). Negative control: a stack-top test (`isinstance(self.screen, …)`) → the palette is on top → `ctrl+s` saves → RED.
examples: C47 (no over-reach) the question answered (`n`), then `ctrl+l` → `1` `LoadDialog`; `ctrl+d` → the density cycles `1` time (`2` of `2`).

S19TuiApp._handle_load_project
req: LLR-165.3, LLR-174.3b, LLR-174.3c
in: Optional[str] name
out: None
func: changed (:11675). (a) `discarded_unsaved = self._reset_project_session()` (:11821) becomes `self._reset_project_session()`, and its comment loses "The outgoing document's entry count returns for the interim closed-document notice below (LED .55(a))". (b) The block `if discarded_unsaved: … self.set_status(f"Closed the Patch Editor document ({discarded_unsaved} entries); unsaved changes were not kept")` (:11943-11953, with its comment) is deleted (ruling Q2): the announcement's status line is again the last writer of `#status_text` before the INFO log (LLR-178.2's stated order). (c) The A2L read and the all-`None` install check move before the reset (S10-01): `variant_set = build_variant_set(name, data_files)`, `manifest = read_project_manifest(project_dir)`, the `recorded` read and the `a2l_context` read (the `_load_a2l_data_with_cache` call and its unreadable arm) run before `self._reset_project_session()`, then `install = choose_install_set(...)` and its all-`None` refusal fire before the reset too; only `self._declared_regions = …` (a write) stays after it, so every refusal now precedes the reset and LLR-174.3c covers them all. (d) The refusal line paints the name through `painted_names` (S10-04): `No supported files in project: {painted_names([name])}`. No push, no seam, no other change (9b's listing, gate and catch stay as 9b designs them).
callers: `_route_load_project` (inside `go`; extractor: direct :7478); 13 test files call it directly (§5.4).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.current_project] (replace, unchanged)
examples: C48 (LLR-165.3 Inc 10 arm) `4` document entries added through the service, project `PV` loaded directly → `0` status lines holding `Closed the Patch Editor document` (probe p10b U6 printed `1` on base → RED there). Re-pin of TC-B100-10: `test_tc_b100_10_interim_discard_notice` (`test_b100_session_reset.py:587`) and `test_tc_b100_10_notice_names_every_discarded_entry` (`:629`) now assert `0` closed-document lines; `test_tc_b100_10_no_discard_notice_when_nothing_unsaved` (`:603`) holds unchanged. Negative control: a mutation that keeps the block → `1` line → RED.
examples: C49 (LLR-174.3b) a direct `_handle_load_project("P")` with D, F and W → `0` questions (`0` `push_screen` calls of `ConfirmQuestionScreen`), `current_project == "P"`. AST of the function body → `0` calls of `push_screen` and `0` of `_confirm_then_load` (`2` of `2`). Negative control: the guard moved into the handler → the direct call pushes `1` question → RED (and the 13 direct-call test files wait on a modal).
examples: C50 (status order) a project load over `1` document entry → the last status line `_handle_load_project` writes is the announcement's summary line (base: the interim line followed it, probe p10b U6).
examples: C58 (LLR-174.3c, S10-01 arm; probe_sec_refuse) image `fw.s19` loaded with 2 unsaved Patch Editor entries (W); pick project `A2LONLY` holding only `cal.a2l` with the A2L unreadable (ACL deny-read) → `1` question → `y` → `1` refusal line `No supported files in project: A2LONLY`, `0` `_reset_project_session` calls, and the session unchanged — `current_file` still `fw.s19`, the entry count still `2`, W still `True`, D still `True` (the A2L read ran before the reset). Result `5` of `5`. Negative control: the base order (the reset before the A2L read) → after `y` `current_file is None`, `0` entries, W `False` → RED (probe_sec_refuse).

S19TuiApp._reset_project_session
req: LLR-165.3
in:
out: None
func: changed (:11385), ruling Q-7: signature `-> None`. Delete `discarded_unsaved = len(self._change_service.document.entries)` (:11446) and `return discarded_unsaved` (:11537). Docstring: `Returns` becomes `None`; the Data Flow bullet "Read the outgoing document's entry count BEFORE the rebind discards it" is removed. Every reset step (S1–S13, the rebind, `clear_paste_buffer`, `mark_loaded`) is unchanged.
callers: `_handle_load_project` (the one call site, :11821; `test_tc_b100_08_call_site_census` keeps `1`). Test stubs (`test_b100_project_homes.py:918`, `test_b100_recents.py:415`, `test_b100_session_reset.py:206-223`, `:254`) pass the value through; no caller reads it.
module: s19_app/tui/app.py
examples: C51 (Q-7) after a project load over `4` entries → `_reset_project_session()` returned `None` (spy), D `False` and W `False` after it (probe p10b U6 holds for the state half). The four stub sites pass (census, baseline-notes "Checked and unchanged"). Negative control: a caller that still reads the value (`if self._reset_project_session():`) → AST census of `app.py` finds `1` read → RED.

S19TuiApp._handle_save_dialog
req: LLR-174.1c
in: Optional[SaveProjectPayload] payload
out: None
func: changed at one expression (:10576): `and panel._dirty` → `and panel.is_dirty`. The comment `# E3 R1: recorded as on disk; the panel's edits are in no file. Inc 10 adds the panel's public dirty reader.` loses its second sentence. Behaviour unchanged.
callers: `SaveProjectScreen` dismiss (unchanged).
module: s19_app/tui/app.py
examples: C52 (LLR-174.1c census) AST of `s19_app/` outside `screens_directionb.py`: attribute reads `._dirty` on a value obtained from `query_one(..., PatchEditorPanel)` → `0` (base: `1`, `app.py:10576`, E1 p10). `flow_screens.py`'s own `self._dirty` reads are a different class and not counted. Negative control: the base line → `1` → RED.
examples: C53 (unchanged behaviour) the E3 R1 arm: document recorded in the project home, panel dirty → `1` line `Change document <name> has unsaved edits — the project records the file as it is on disk; save it from the Patch Editor to keep them` (holds on base through `_dirty`, holds after through `is_dirty`).

S19TuiApp.on_patch_editor_panel_change_file_selected
req: LLR-174.2t
in: PatchEditorPanel.ChangeFileSelected event
out: None
func: changed (:6110). The F1 containment guard stays first (unchanged; the outside-patches-folder line returns without loading). Then: `panel = self.query_one("#patch_editor_panel", PatchEditorPanel)`; `if panel.is_dirty:` push the existing `LoadGuardScreen` exactly as the Load button's `on_patch_editor_panel_dirty_load_requested` does (an `_answer` closure whose accept arm calls `self._patch_editor_load(panel, str(candidate))` and whose cancel arm sets the same `Patch Editor: load cancelled — changes kept.` status line), and do not load; `else:` `self._patch_editor_load(panel, str(candidate))` at once. The dropdown pick therefore replaces no entry while the panel is dirty; the clean pick keeps the base behaviour (`load` + `mark_loaded` clears the flag).
callers: Textual message dispatch (`PatchEditorPanel.ChangeFileSelected`, the `#patch_doc_file_select` pick). Unchanged set.
module: s19_app/tui/app.py
examples: C59 (LLR-174.2t) 2 unsaved entries (W via `panel.request_action("add_entry")`), the `#patch_doc_file_select` pick of `second.json` → `1` `LoadGuardScreen` pushed, `0` `_patch_editor_load` calls, the entry count still `2`, W still `True`; cancel → the same, `0` loads. A clean panel (W `False`) → the same pick → `0` `LoadGuardScreen`, `_patch_editor_load` runs, the document becomes `second.json`'s entries and `mark_loaded` clears the flag. Result `2` of `2` (dirty arm + clean arm). Negative control: no `is_dirty` read before the load (base) → the dirty pick replaces the entries (`1` entry, W `False`) with `0` guards → RED (probe_sec_dropdown).

## Context nodes (unchanged)

- `S19TuiApp._rehome_focus_after_load` — unchanged (:8490). New caller: `_confirm_then_load`'s `answer` on cancel (C08). It reads `default_screen.focused`, so it never moves a focus inside the question.
- `S19TuiApp._handle_load_dialog` — 9b's router, unchanged by Inc 10 (S-d). Example C06 (one question per request).
- `S19TuiApp._load_from_item` — 9b's wrapper over `_load_workarea_file`, unchanged. Example C38 (`#files_list` surface).
- `S19TuiApp.on_patch_editor_panel_dirty_load_requested` — unchanged; still pushes `LoadGuardScreen` and never calls `_confirm_then_load`. Example C54 below.
- `S19TuiApp.on_mount` — unchanged; example C37.

examples: C54 (LLR-174.2j) a dirty Patch Editor, then its `#patch_doc_load_button` → `1` `LoadGuardScreen`, `0` `ConfirmQuestionScreen` (holds on base for the guard, probe p10b U13). AST: `on_patch_editor_panel_dirty_load_requested` holds `0` calls of `_confirm_then_load`. Negative control: a mutation routing `DirtyLoadRequested` through the seam → `0` `LoadGuardScreen` → RED.

## Re-pins owed by G-B's changes (E2-rulings census)

examples: C55 (AT-B100-03 re-pin, §C.5) `test_at_b100_03_project_load_over_unsaved_work_saves_only_p2[size0]` and `[size1]` (`test_b100_session_reset.py:775`): after the P2 pick, wait for `ConfirmQuestionScreen`, assert its body holds `Patch Editor entries` (W set by writer w1 and w2; run A: D `False`, F `False`, W `True` → body `There are unsaved changes in Patch Editor entries. Load project P2 anyway?`), press `y`; delete the two interim assertions (`:879-880`, `:945-946`). Every other assertion stays. Negative control: run B (baseline-notes) — a question nobody answers → `timed out waiting for the Load-result panel` → RED before the re-pin.
examples: C56 (TC-B99-40 re-pin, new in the census) `test_tc_b99_40_strip_shows_new_file_source_byte` (`test_b99_editor_image.py:468`): Apply on file A sets D; loading file B through the dialog asks (image kind) → after the 9b re-pin of `_load_fixture`, press `y` at the question; B loads and the strip shows B's source byte. Negative control: run B → `did not settle: load status line` → RED before the re-pin.
examples: C57 (TC-B100-10) see C48.

## Entities

[Data: App.screen_stack]
desc: one `ConfirmQuestionScreen` on top while a guarded request waits; none when nothing is unsaved.
sequence:
  askAndReplace: leaf → S19TuiApp._confirm_then_load → S19TuiApp._load_would_lose (items) → S19TuiApp._load_question_text → push ConfirmQuestionScreen → (y) answer(True) → call_after_refresh(go) → loader
  askAndCancel: leaf → S19TuiApp._confirm_then_load → push ConfirmQuestionScreen → (n / escape / enter on Cancel) answer(False) → S19TuiApp._rehome_focus_after_load → expect none (digest, kept work, store unchanged; 0 status lines)
  nothingLost: leaf → S19TuiApp._confirm_then_load → S19TuiApp._load_would_lose ([]) → go() at once
  typedProject: S19TuiApp._handle_load_dialog → S19TuiApp._load_path_from_user_input (project arm, no seam) → S19TuiApp._route_load_project → S19TuiApp._confirm_then_load (1 question)

[Data: S19TuiApp._pending_variant_id]
desc: written by `_handle_select_variant` only inside `go`; a cancelled question leaves it as it was (C42).
sequence:
  variantCancel: S19TuiApp._handle_select_variant → S19TuiApp._confirm_then_load → (n) → expect none (stamp unchanged)
  variantReplace: … → (y) → go → stamp → S19TuiApp.load_from_path → _apply_prepared_load (consumes the stamp)

[State: project-session reset]
desc: runs only inside `_route_load_project`'s `go`, after the answer (LLR-174.3), and only when `_handle_load_project` passes its refusals (LLR-174.3c).
sequence:
  projectConfirm: S19TuiApp._route_load_project → S19TuiApp._confirm_then_load → (y) → go → S19TuiApp._handle_load_project → S19TuiApp._reset_project_session (returns None) → installs → LoadResultScreen
  projectRefused: … → (y) → go → S19TuiApp._handle_load_project (refuse before reset) → expect none (0 resets, D/W kept)

## Callers and what changes for each

| Caller | Reaches | What changes for it |
|---|---|---|
| 9b router `project` | `_route_load_project` | may meet the question (project kind) before the load |
| 9b router `path` / `recent` | `_load_path_from_user_input` | data → image or attach by the stripped suffix; a2l → attach; project → asked in `_route_load_project` |
| 9b router `workarea`, `#files_list` via `_load_from_item` | `_load_workarea_file` | image or attach by suffix |
| `SelectVariantScreen` dismiss (`v`, palette, panel `v`) | `_handle_select_variant` | image question; the stamp moves into `go` |
| `on_mount` | `_load_path_from_user_input` | nothing unsaved → `go()` at once; unchanged |
| direct test calls of `_handle_load_project` (13 files) | `_handle_load_project` | no question; the interim line is gone (2 TC-B100-10 tests re-pinned) |
| `_handle_load_project` | `_reset_project_session` | returns `None`; the value had one reader, deleted |
| Textual `run_action`, key bar | `check_action` | the four priority actions are also inert while the question is anywhere on the stack |
| 5 test runs (E2-rulings census) | — | AT-B100-03 ×2 and TC-B99-40 answer `y`; TC-B100-10 ×2 assert 0 lines |
| `PatchEditorPanel.ChangeFileSelected` (the `#patch_doc_file_select` pick) | `on_patch_editor_panel_change_file_selected` | dirty → `LoadGuardScreen`, no load; clean → load as before (S10-02) |

## Seams with G-A (`screens.py`, `screens_directionb.py`, `styles.tcss`)

| Id | Seam | G-B side (this design) | G-A must | Example |
|---|---|---|---|---|
| S-a | the modal contract | push `ConfirmQuestionScreen(title, body, "Replace (y)", "Cancel (n)")`; `title` / `body` already scrubbed plain `str`; `answer` treats a truthy result as replace, anything else as cancel | dismiss `True` (y, `#confirm_yes`) / `False` (n, escape, `#confirm_no`); paint all four texts with markup off (labels as `rich.text.Text`, Q-1); `AUTO_FOCUS = "#confirm_no"` | C02, C04, C26 |
| S-a2 | one answer per question | `answer` runs `go` once per call, so a second `True` would load twice | the `_dismissed` guard as the first line of the close (Q-5) | C06 |
| S-c | `PatchEditorPanel.is_dirty` | read in `_load_would_lose` (project kind) and in `_handle_save_dialog`; `0` reads of `_dirty` | a read-only property over `_dirty`; the five writers unchanged | C16, C52, C53 |
| S-f | priority keys | `check_action` whole-stack test with `(LoadDialog, ConfirmQuestionScreen)`; imports the class from `.screens` | the class name `ConfirmQuestionScreen` exported from `screens.py` | C45–C47 |
| S-g | ids | tests address `#confirm_yes`, `#confirm_no`; G-B writes no id | the ids of `interfaces-10.md` S-g | C02 |
| S-h | focus after the close | cancel → `_rehome_focus_after_load()` (reads `default_screen.focused`) | the modal leaves the focus to Textual's restore on pop | C08 |

## Findings

finding F-1 the Q-4 MAC test on the raw `Path` misreads quoted or padded field text
anchor: S19TuiApp._load_path_from_user_input
seen: the 9b dialog passes the field text verbatim (9b S-a), the router builds `Path(choice.value)`, and `_typed_load_route` strips spaces and quotes before it classifies (:12796). Probe gb-strip: `Path('"C:\t\x.mac"').suffix == '.mac"'`, `.name == 'x.mac"'`; after `str(p).strip().strip('"')` → `.mac`, `x.mac`.
effect: on the raw `Path`, a quoted MAC path would ask as an image (one needless question), and every quoted target would paint with a trailing `"` in `Load <target> anyway?`.
decision: designed: the rule `suffix.lower() in MAC_EXTENSIONS` and the target name read `typed = Path(str(path).strip().strip('"'))`, the same strip the classifier and `resolve_input_path` apply (C35). Signature unchanged; written as proposal P-1 for the orchestrator to confirm in `interfaces-10.md`.

finding F-2 the draft's "applied then undone" boundary contradicts the probe
anchor: S19TuiApp._load_would_lose
seen: the draft (HLR-174a boundary, LLR-174.1 threshold) still says "a patch applied then undone → 0 questions". `p10b-undo`: `undo()` alone leaves the byte patched (D `True`); only undo plus Apply restores it.
decision: the design follows E2-rulings (C12: undo + Apply → 0; C13: undo alone → 1). The draft text is not yet corrected; the orchestrator owes that edit.

finding F-3 LLR-174.3d has no text in the draft yet
anchor: S19TuiApp._handle_select_variant
decision: C42 is written against the ruling. Proposed statement (unwanted form): "If the engineer cancels the question of a variant switch, then the system shall leave the pending variant selection unchanged." Threshold: `n` → the pending stamp unchanged and the next confirmed load stamps no variant (2 of 2). Negative control: the stamp set before the seam → RED.

finding F-4 load call sites when the file vanishes during the question
anchor: S19TuiApp._load_workarea_file
decision: declared (C39, C43): the leaves check existence before the seam and `go` does not re-check. A file deleted while the question is open gives the loader's own failure line (`Load failed: …` for a work-area pick, `File not found: …` for a variant), and the session stays as it was. A re-check inside `go` would duplicate each leaf's guard for no loss avoided.

finding F-5 one needless question for `W\temp\x.mac.`
anchor: S19TuiApp._load_path_from_user_input
decision: as `interfaces-10.md` Q-4 declares: the inside-work-area branch drops the trailing dot (CR9-3), the stripped suffix is `""`, so the route asks as an image; on `y`, `load_from_path` refuses `Unsupported file type`. Nothing is lost.

finding F-6 the key bar during the question
anchor: S19TuiApp.check_action
seen: `window_help.py:1134/:1145` dim a key `check_action` refuses. While the question is open, the main screen's key bar (behind the dimmed modal) may paint `ctrl+l` / `ctrl+s` / `ctrl+k` / `ctrl+d` dimmed.
decision: declared, no requirement; the same exposure 9b already has under `LoadDialog`.

finding F-7 LLR-174.4's AST census needs a precise rule
anchor: S19TuiApp._confirm_then_load
seen: the draft says every call of `load_selected_file`, `load_from_path`, `load_a2l_from_path` and `_route_load_project` reachable from a binding, list event or dismiss callback "runs inside the seam's continuation". Under S-d, `_route_load_project` holds the seam itself, so its call in `_load_path_from_user_input`'s project arm (and in the router) is not inside a continuation, and the census as written would flag it.
decision: proposal P-2. C05 uses the rule: the three loaders and `_handle_load_project` are called only inside a `go` passed to `_confirm_then_load`, inside `_handle_load_project`, or as `load_from_path`'s worker start; `_route_load_project` is the project seam and its callers are exempt. With that rule the start-up `on_mount` exemption is not needed either: its load also runs inside `go`.

## Proposals to the orchestrator

- **P-1 (clarification of Q-4, no signature change).** "A path is a MAC path when `Path(str(path).strip().strip('"')).suffix.lower() in MAC_EXTENSIONS`; the question's target is that stripped path's `name`." Reason F-1, evidence `../work/gb/probe-gb-strip.out.txt`.
- **P-2 (LLR-174.4 threshold wording).** Replace the census clause with: "AST census of `app.py`: every call of `load_selected_file`, `load_from_path`, `load_a2l_from_path` and `_handle_load_project` is inside a continuation passed to the load seam, inside `_handle_load_project`, or is `load_from_path`'s worker start; `_route_load_project`'s body is the project seam (0 bypasses)." Reason F-7.
- **P-3 (draft text).** Correct the undo boundary (F-2) and add LLR-174.3d (F-3), as E2-rulings already decided.
- No change to any signature in `interfaces-10.md`.

## Design risks

- **R-1 (the dialog does not come back).** The question comes after the Load dialog has closed (E1 §5); after `n` the engineer opens Load again. No requirement asks otherwise.
- **R-2 (asked, then refused).** A project's own checks run after `y` (C30): the engineer may see a question and then a refusal line for one request. LLR-174.3c makes it loss-free.
- **R-3 (race during the question).** F-4: loss-free, one loader failure line.
- **R-4 (headless tests).** A test that reads W or F through the panels must mount the app; every route test already does under `run_test` (A10-02).
- **R-5 (cost).** The guard runs `differs_from_last_saved` once per request: O(journaled + recorded addresses), the map is never iterated (its docstring). Two `query_one` calls for a project load only.
- **R-6 (out of scope, rulings Q7 / Q8).** Unload over a patched image and the Flow Execution panel's flow sets lose or move unsaved work with no question; backlog rows at the close.
- **R-7 (load worker already running, S10-03).** A load worker that is already running installs without a check: during a large parse the engineer can patch the image still on screen, and the worker's `_apply_prepared_load` installs with 0 questions. Declared, no guard in Inc 10; routed to 12b (its ruling Q3 refuses Patch Editor changes while a session-writing action runs).

## Windows-only arms (reported not run on the Linux CI, never passed)

C35's backslash text is written with `os.sep` on CI; none of G-B's examples needs a junction or a Windows-only name.

## Requirement coverage (G-B)

| Requirement | Examples |
|---|---|
| HLR-174 | C02, C28, C40, C41 |
| HLR-174a | C09, C12, C29, C14 |
| HLR-174b | C03, C36, C40 |
| HLR-174c | C04, C36 |
| HLR-174d | C11, C18, C19, C20 |
| LLR-174.1 | C10, C12, C13 |
| LLR-174.1a | C10, C14, C33 |
| LLR-174.1b | C10, C28, C29 |
| LLR-174.1c (app half) | C16, C52, C53 |
| LLR-174.2 (push half) | C02 |
| LLR-174.2b (reach half: the question from each of the 4 routes) | C02, C28 |
| LLR-174.2h | C45, C46, C47 |
| LLR-174.2i (composer half) | C26 |
| LLR-174.2j | C54 |
| LLR-174.2k | C17, C18, C21 |
| LLR-174.2l | C17, C23 |
| LLR-174.2m | C20, C24 |
| LLR-174.2n | C18, C19 |
| LLR-174.2o | C22 |
| LLR-174.2p (labels passed) | C02 |
| LLR-174.2q | C25 |
| LLR-174.2t | C59 |
| LLR-174.3 | C07 |
| LLR-174.3a | C04 |
| LLR-174.3b | C49 |
| LLR-174.3c | C30, C58 |
| LLR-174.3d | C42 |
| LLR-174.4 | C01, C05, C37, C41 |
| LLR-174.4a | C06 |
| LLR-174.4b | C33, C34, C35 |
| LLR-174.4c | C38 |
| LLR-165.3 (Inc 10 arm) | C48, C51 |
| LLR-166.1 (Inc 10 arm) | C08 |
| LLR-167.8 (Inc 10 arm) | C31 |
| LLR-173.7 (Inc 10 arm) | C27 |
| AT-B100-15 (G-B half) | C02, C03, C04, C13, C18, C29 |
| AT-B100-03 (re-pin) | C55 |
| TC-B100-10 (re-pin) | C48 |
| TC-B99-40 (re-pin) | C56 |

**G-A only** (no G-B node; listed so nothing is lost): LLR-174.2a, LLR-174.2c, LLR-174.2d, LLR-174.2e, LLR-174.2f, LLR-174.2g, LLR-174.2r, LLR-174.2s, the property half of LLR-174.1c, the modal halves of LLR-174.2, LLR-174.2b, LLR-174.2i and LLR-174.2p.

**G-B requirements left uncovered: none.**
