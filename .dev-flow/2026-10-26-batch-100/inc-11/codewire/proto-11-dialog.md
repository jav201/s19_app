# Code-Wire prototype — Inc 11, group G-A (`screens.py` + `styles.tcss`)

Stage E2 of the design-first pipeline for Inc 11 ("the Save project dialog"). This is the graph only. Nothing in `s19_app/` changes, and the repo `C:\Users\jjgh8\Github\s19_app` (`8947666`) stays read-only. New code is a node whose `func:` starts with "new". The shared interfaces are those in `interfaces-11.md` (fixed, with its §Orchestrator rulings Q-1 … Q-6, split, guard). This group changes none of them; what it needs beyond them is written under "Proposals to the orchestrator". G-B (`app.py` + `project_gather_service.py`) writes its prototype in parallel; the seams are listed under "Seams with G-B".

**Base and inputs.**
- Code: `8947666` (Inc 9a merged). Inc 9b and Inc 10 are designed but not merged. This graph builds on `../../inc-9b-design/codewire/proto-9b-dialog.md` (the `_dismissed` guard, R-GA-1, the `priority=True` `alt+<letter>` binding A9b-01, the nowrap rule that is not inherited) and `../../inc-10-design/codewire/proto-10-dialog.md` (Q-5 guard, fully-visible oracle, labels as `rich.text.Text` per Inc 10 ruling P-GA10-1). The 9b work tree `C:\Users\jjgh8\Github\s19_app-b100-inc9b` (uncommitted 9b code) was read for the post-9b import list and `test_tc_b100_64_the_dialog_reads_nothing_itself`; it was not changed. `SaveProjectScreen` is at `screens.py:488-685`, `SaveProjectPayload` at `:149-181`, the modal rules at `styles.tcss:1563-1597`, `:1732-1777`. Post-9b line numbers shift; nodes cite symbols.
- Requirements: `../E1-requirements-draft.md` §A, §B. LLR-175.1n is withdrawn (`../E2-rulings.md`). Rulings: `../E1-rulings.md` (Q1–Q11), `../E2-rulings.md`, `interfaces-11.md` §Orchestrator rulings (binding).
- Baseline: `baseline-11.md` (6 `screens.py` nodes), `baseline-notes.md` (probe p11b U7; census A–I; extractor callers).
- Verdict surface: `prototypes/load_projects/variants/pc_B.py`, `_pc_common.py`, `png/pc_B.pc.118.png` (read only): name field focused with the open project's name, a folder line with its kind, a "what will be saved" table, `Save (alt+s)` / `Cancel (esc)`, dialog `80%` wide capped at 130 columns.
- Textual: 8.2.8 (`importlib.metadata.version("textual")` in `s19env`).

**Probe p11-ga (executed in this session).** Python `s19env`, `python -I`, `env -u NO_COLOR PYTHONDONTWRITEBYTECODE=1 PYTHONUTF8=1 LOCALAPPDATA=../work/localappdata-GA`, `App.run_test` on the real `S19TuiApp`, imported from a copy of `../work/tree/s19_app` at `../work/ga/tree` (byte-identical `styles.tcss`, sha256 `781f04ed2cc3`, before the edit) whose `styles.tcss` got the C1–C3 rules of this graph after `.assign-list` (inside the modal block). Scripts and outputs: `../work/ga/probe_p11_ga.py` (+ `.out.txt`), `../work/ga/probe_p11_ga2.py` (+ `.out.txt`). `probe_p11_ga.py` holds a throwaway skeleton `G` of this graph's `SaveProjectScreen` (S1–S9; the real `SavePlan` / `SavePlanRow` / `SaveProjectPayload`; fake `preview` / `confirm`) used to check the steps; it omits `_collect_composition` and is not a stub; it never goes into the repository. In the `.out.txt` files the `—` shows as `�` (console code page). Facts the examples use:
- **K1.** At 118×54 with `initial_name="P"`: ids in DOM order `save_box`, `project_name`, `save_where`, `save_summary`, `saveproject_buttons`, `save_ok`, `save_cancel`; `focused.id == "project_name"`; value `'P'`, `selection == Selection(start=0, end=1)`; `preview` called once, with `'P'`; at that call `app.screen` is the dialog and `#project_name.region.width == 86`; `#save_box` (13, 17, 92, 19) with 2 rows. Typing `x` → value `'x'`, preview calls `['P', 'x']`.
- **K2.** No `initial_name`: value `''`; `preview` called once, with `''`; `plan is None`; `#save_where` paints `''` (the fake returns an empty preview for blank text).
- **K3.** `escape` with the focus on `#project_name`, `#save_summary`, `#save_ok`, `#save_cancel` → `CB == [None]`, stack `['Screen']`, `confirm` 0 calls (4 of 4).
- **K4.** `initial_name="fresh1"`, painted: `alt+s`, `enter` in the field, click `#save_ok`, `enter` on a focused `#save_ok` → `confirm` 1 call `('fresh1', <the painted plan object>)` (identity `True`), dismiss `SaveProjectPayload(parent_folder='C:\\wa\\.s19tool\\workarea', project_name='fresh1', …)`, depth 1 (4 of 4). Click / `enter` on `#save_cancel` → `None`, `confirm` 0 calls (2 of 2).
- **K5.** A posted `events.Key("alt+s", character="s")` with the focus in `#project_name` (value `fresh1`, cursor at the end) → dismiss with `project_name == 'fresh1'` (no `s` typed), depth 1.
- **K6.** Field `''` and `'   '`, each with `alt+s`, a click on `#save_ok` and `enter` in the field → `confirm` called with the text verbatim (`''` / `'   '`), 0 dismisses, `#save_where` paints `name is empty — type a project name` and has the class `refusal` (6 of 6).
- **K7.** `s`, `q`, `l`, `p`, `v`, `y` pressed → field `'sqlpvy'`, depth 2, 0 dismisses; preview calls `['', 's', 'sqlp', 'sqlpvy']` (Pilot waits for idle between presses, so the debounce grouped them).
- **K8.** (probe history, superseded by the debounce ruling A11-13: the throttle's leading edge gave 2 recomputes; the debounce in S5 gives 1) 20 keys `a` … `t` posted with `asyncio.sleep(0.01)` between them (they arrive inside 15 ms): the old throttle design → 2 recomputes `['a', 'abcdefghijklmnopqrst']`, the final name painted 141 ms after the last key, field `'abcdefghijklmnopqrst'`. Mutant "recompute per keystroke" → 20 recomputes. Mutant "no trailing run" → 1 recompute `['a']`, `#save_where` stays `a   new folder` while the field holds 20 letters.
- **K9.** (probe history, superseded by the debounce ruling A11-13: no leading edge; the debounce recomputes 150 ms after the last change, S5-3) One key after a quiet period > 150 ms → under the throttle the `preview` ran inside the `Changed` handler; under the debounce it runs 150 ms later.
- **K10.** Typed `a b`, the fake refuses it with `'a b' is already a project as 'ab' — choose another name`: `#save_where` paints that line, 0 rows, `plan is None`; `alt+s` → 0 dismisses; `tab`, `tab` → focus `save_ok`, `can_focus` `True`, `disabled` `False`; `enter` → 0 dismisses, the line still painted, `confirm` 2 calls.
- **K11.** `abc` posted, then `alt+s` 20 ms later with the trailing recompute pending and the painted plan the one for `a` → 0 dismisses; `#save_where` `abc   new folder\nthe summary changed — check it, then save again`; 400 ms later unchanged, no timer pending; a second `alt+s` → dismiss `('C:\\wa\\.s19tool\\workarea', 'abc')`, `confirm` received the repainted plan object (identity `True`). Mutant "the trailing timer is not stopped when `confirm` repaints" → 400 ms later `#save_where` is `abc   new folder` (the token pair erased).
- **K12.** Guarded `_close(None); _close(None)` → `CB == [None]`, stack `['Screen']`. Unguarded → `ScreenStackError: Can't pop screen; there must be at least one screen on the stack`.
- **K13.** `plan` before any paint → `None`; `screen.plan = PLAN("x")` → `AttributeError: property 'plan' of 'G' object has no setter`; `plan.rows = ()` → `FrozenInstanceError`; `plan.rows.append(1)` → `AttributeError: 'tuple' object has no attribute 'append'`.
- **K14.** Literal names: `#save_where` `[red]a   new folder`, 0 spans; rows `new  [b]x.s19`, `new  flows/[i]f.json`, 0 spans each; assignment label `Label(…, markup=False)` paints `Assign files to '[b]x':`, 0 spans; `SelectionList` prompt `Text("[i]doc.json")` paints `[i]doc.json`, 0 spans; a refusal line `'[b]P' is already a project as '[b]P' — choose another name`, 0 spans. Mutants: a `str` prompt → `doc.json`, 1 span; `Label` with markup on → `Assign files to 'x':`, 1 span; `Static(markup=True).update(str)` → `new  x.s19`, 1 span.
- **K15.** `ROWS300` at 118×54: `#save_summary` (16, 13, 86, 27), `#save_box` (13, 4, 92, 46), `#save_ok` (68, 45, 16, 3) and `#save_cancel` (86, 45, 16, 3) fully visible; every row height 1; row 0 width 80, its rendered line ends with `…`. At 220×60: summary (48, 13, 124, 30), box (45, 4, 130, 52), ok (138, 51, 16, 3), cancel (156, 51, 16, 3) fully visible; row 0 width 118, ends with `…`. `tab` × 4 from `#project_name` → `save_summary`, `save_ok`, `save_cancel`, `project_name`; `shift+tab` × 4 → `save_cancel`, `save_ok`, `save_summary`, `project_name`. `tab`, `end` → focus `save_summary`, `scroll_y == max_scroll_y` (275 at 118×54, 272 at 220×60), the last row's region (18, 38, 80, 1) inside the summary.
- **K16.** Layout mutants, 118×54, `ROWS300`: summary `max-height` unbounded (box keeps `max-height: 90%`) → summary height 302, both buttons still fully visible, the last row at y = 313, outside the screen; summary and box unbounded → box (12, -7, 91, 317), `#save_ok` at y = 305, not visible. A row allowed to wrap (`text-wrap: wrap; height: auto`) → the 131-character row is 2 high. `#save_summary.can_focus = False` → `tab` from the field lands on `save_ok`.
- **K17.** Row repaint cost at 118×54: 2 → 300 rows: the paint call 203 ms, rows mounted after 360 ms; 300 → 300 rows (in-place `update`) 78 ms including one pause; 300 → 2 rows 94 ms.
- **K18.** With 2 variants and 2 candidate files: `tab` × 6 from `#project_name` → `save_summary`, `assign_batch`, `assign_0`, `assign_1`, `save_ok`, `save_cancel`.
- **K19.** Priority keys with the dialog open, field `abcdef`, cursor at 3. Base `check_action`: `ctrl+l` → stack `[…, G, LoadFileScreen]`; `ctrl+s` → `[…, G, SaveProjectScreen]`; `ctrl+d` → density class changed. With the S-e rule modelled (`action in INERT and any(isinstance(s, G) for s in screen_stack)` → `False`): 0 screens pushed, density unchanged; `ctrl+k` → field `abc` (Input `delete_right_all`), `ctrl+d` → field `abcef` (Input `delete_right`).
- **K20.** `escape` posted while a trailing recompute is pending → `CB == [None]`, 0 `preview` calls after it (400 ms). `escape` after a refusal was painted and `alt+s` refused → `CB == [None]`, `confirm` 1 call.
- **K21.** Names checked in `textual/` 8.2.8 (`grep -rnw`): `plan` 0, `_plan` 0, `_preview_fn` 0, `_confirm_fn` 0, `_initial_name` 0, `_live` 0, `_trailing` 0, `_shown` 0, `_mark_shown` 0, `_dismissed` 0, `_paint` 0, `_recompute` 0, `_first_preview` 0, `_stop_trailing` 0, `action_save` 0, `action_cancel` 0, `candidate_files` 0. `_ready` 2 (`App._ready`, `app.py:3457`, `:3522`), so it is not used. `_close` 2 (markdown token strings, as in 9b / 10). `variants` 12 (docstrings and `Button` "variants" prose; the attribute is `Button.variant`), kept because tests read `screen.variants`.

**Fixtures used by the examples.**
- `WA` = the app's work area (`app.workarea`; `C:\wa\.s19tool\workarea` in the probe).
- `PLAN(n)` = `SavePlan(target=WA / n, target_kind="new", rows=(), image="firmware.s19 unchanged copy", manifest_keys=())`. G-A treats a plan as an opaque value: what matters is identity and `target`.
- `PV(n)` = `SavePreview(where=((f"{n}   new folder", "info"),), rows=(f"new  {n}/firmware.s19", f"new  {n}/project.json"), plan=PLAN(n), refused=False)`. The words are fake values standing for G-B's composed text; the dialog paints whatever it gets.
- `PV_REFUSED(line)` = `SavePreview(where=((line, "refusal"),), rows=(), plan=None, refused=True)`.
- `PV_EMPTY` = `SavePreview(where=(), rows=(), plan=None, refused=False)`.
- `F` = a preview fake that records each call and its time: blank text → `PV_EMPTY`; a name in its refuse map → `PV_REFUSED(map[name])`; otherwise `PV(n)`, with one memoised `PLAN(n)` object per name.
- `C` = a confirm fake that records `(name, plan)`: blank → `PV_REFUSED("name is empty — type a project name")`; refused name → that refusal; `plan is` the memoised plan → `None`; otherwise it replaces the memoised plan with a new object and returns `PV(n)` plus the where line `("the summary changed — check it, then save again", "refusal")`.
- `CB` = a list the dismiss callback appends to.
- `ROWS300` = row 0 `new  flows/` + `f`×120 + `.json` (131 characters), then 299 rows `new  flows/f000.json` … `new  flows/f298.json`.
- "Painted" text = `str(widget.visual)`; "0 spans" = `len(widget.visual.spans) == 0`. `#save_where` painted = the where texts joined by `"\n"`.
- "Fully visible" (Inc 10) = for `geo = screen.find_widget(w)`: `geo.region == geo.region.intersection(geo.clip)`, `screen.region.contains_region(geo.region)` and `geo.region.height >= 1`.

**Counts.**
- **16 nodes:** 2 new module-level nodes (V `SavePreview` + aliases, I1 the typing import), 1 changed data node (Y `SaveProjectPayload.plan`), 8 code nodes for the rewritten `SaveProjectScreen` (S1 `__init__` + class attributes, S2 `compose`, S4 `on_mount` / `_first_preview`, S5 `on_input_changed` / `_recompute` / `_stop_trailing`, S9 `_paint`, S6 `action_save` + its triggers, S7 `action_cancel` / `_close`, S8 `plan`), 4 selector nodes (C1–C4) and 1 retirement node (R1). `_assignment_rows_enabled` and `_collect_composition` are unchanged code (their caller moves; see "Callers").
- 4 entities, 69 example lines (each with its requirement, exact inputs, exact outputs and a RED condition or a RED side on base).
- 11 design decisions (D-GA11-1 … D-GA11-11), 8 risks (R-GA11-1 … R-GA11-8), 11 seams (SC-1 … SC-11).
- 4 proposals to the orchestrator (P-GA11-1 … P-GA11-4), 0 interface changes adopted on our own.
- G-A requirements without an example: 0 (table at the end). LLR-175.1n: withdrawn, no example.
- Source files G-A touches: `screens.py`, `styles.tcss`.

## Nodes

SavePreview (+ WhereKind, WhereLine)
req: HLR-175, HLR-175b, LLR-175.1, LLR-175.4, LLR-175.4g, LLR-175.4b, LLR-175.3f
in: tuple[WhereLine, ...] where; tuple[str, ...] rows; Optional[SavePlan] plan; bool refused
out: SavePreview preview
func: new, module level in `screens.py`, right after `SaveProjectPayload` (S-a, fixed):
  - `WhereKind = Literal["info", "refusal"]`; `WhereLine = tuple[str, WhereKind]`.
  - `@dataclass(frozen=True) class SavePreview` with the four fields in the interface order. No defaults, no validation, no methods. Docstring in the codebase's Summary / Args / Data Flow shape: "Built only by the app (`_save_dialog_preview`, the confirm step); the dialog paints it and never builds one" (SC-1, SC-2).
  - `Literal` and `Callable` are imported from `typing` post-9b (`screens.py:6` in the 9b tree), so no new module. The `SavePlan` annotation goes through I1.
module: s19_app/tui/screens.py
examples: [V-1] (S-a) `SavePreview(where=(("ab   new folder", "info"),), rows=("new  ab/firmware.s19",), plan=None, refused=False)` → `.where[0][1] == "info"`; `p.rows = ()` → `dataclasses.FrozenInstanceError`; two equal-valued previews compare equal (target (11)). RED if: a mutable (non-frozen) dataclass → the assignment succeeds
examples: [V-2] (S-a, LLR-175.6 G-A share) AST: the only `SavePreview(` call sites in `s19_app/` are in `app.py` (G-B); 0 in `screens.py` (target (11)). RED if: the dialog builds its own `SavePreview` for blank text (a second decider, D-GA11-1)

I1 `screens.py` typing import (changed `TYPE_CHECKING` block)
req: S-a ("imports `SavePlan` for typing only"), LLR-175.4 (AST arm), 9b LLR-173.6l
in: —
out: —
func: changed. One line inside the existing `if TYPE_CHECKING:` block: `from .services import project_gather_service`. Annotations then read `project_gather_service.SavePlan` (they are strings at run time through `from __future__ import annotations`, `screens.py:1`). The module name `.services` is already imported (`from .services import operation_service`), so the set of imported module names stays the post-9b set, and 9b's `test_tc_b100_64_the_dialog_reads_nothing_itself` arm 2 (`modules - SCREENS_MODULES_AT_BASE == set()`) stays green. Nothing is imported at run time; the dialog calls no service. See P-GA11-1 for the alternative.
module: s19_app/tui/screens.py
examples: [I1-1] (9b LLR-173.6l arm 2) AST of `screens.py` after Inc 11: the set of `("." * level) + module` names equals the post-9b set (0 new): `.services` is in `SCREENS_MODULES_AT_BASE` (read in the 9b tree, `tests/test_b100_load_dialog.py:2794`) (target (11)). RED if: `from .services.project_gather_service import SavePlan` → 1 new name `.services.project_gather_service` → TC-B100-64 arm 2 RED
examples: [I1-2] (S-a) `python -I -c "import s19_app.tui.screens as s; print('project_gather_service' in vars(s))"` → `False` (the import is typing-only) (target (11)). RED if: the import is placed outside `TYPE_CHECKING` → `True` (a run-time service import in the dialog module)

SaveProjectPayload (changed: field `plan`)
req: HLR-175a, LLR-175.4a, LLR-175.4l, interfaces Q-2
in: str parent_folder; str project_name; tuple[str, ...] batch = (); Mapping assignments = {}; Optional[SavePlan] plan = None
out: SaveProjectPayload payload
func: changed (interfaces Q-2). One field added last: `plan: Optional[project_gather_service.SavePlan] = field(default=None, compare=False)`. `field` is already imported (`screens.py:4`). Docstring `Args` gains: "plan: the plan the Save dialog painted and confirmed; `None` for a payload built without the dialog (LLR-175.4l). Not part of equality." `parent_folder`'s docstring changes from "as entered or browsed" to "the work area (the dialog sets it; LLR-175.2a)". The 4 existing fields, their order and defaults are unchanged, so the 56 direct handler calls and the 11 test files that build the payload stay valid.
module: s19_app/tui/screens.py
examples: [Y-1] (LLR-175.4l G-A share) `SaveProjectPayload(parent_folder=str(WA), project_name="P9")` → `.plan is None`, `.batch == ()`, `.assignments == {}` (the 56 call lines build it this way) (target (11)). RED if: `plan` added without a default → `TypeError: missing 1 required positional argument: 'plan'` in every direct call
examples: [Y-2] (Q-2) `a = SaveProjectPayload(str(WA), "ab", plan=PLAN("ab"))`, `b = SaveProjectPayload(str(WA), "ab")` → `a == b` (`compare=False`); `a.plan is not None`; `a.plan = None` → `FrozenInstanceError` (target (11)). RED if: `compare=True` → `a != b`

SaveProjectScreen.__init__ (+ class attributes)
req: HLR-175f, LLR-175.3, LLR-175.3c, LLR-175.3d, LLR-175.3e, LLR-175.3h, LLR-175.6, Q4
in: keyword-only: preview: Callable[[str], SavePreview]; confirm: Callable[[str, Optional[SavePlan]], Optional[SavePreview]]; initial_name: Optional[str] = None; variants: Optional[List[Tuple[str, str]]] = None; candidate_files: Optional[List[str]] = None
out: SaveProjectScreen (a `ModalScreen[Optional[SaveProjectPayload]]`)
func: rewritten (S1, S3; S-b fixed signature).
  - **Class attributes.**
    - `AUTO_FOCUS = "#project_name"` (LLR-175.3d).
    - `BINDINGS = [Binding("escape", "cancel", show=False), Binding("alt+s", "save", show=False, priority=True)]`. `priority=True` because a non-priority `alt+<letter>` loses to the focused `Input` (9b A9b-01). No binding for a plain letter (LLR-175.3e) and none for `ctrl+l` / `ctrl+s` / `ctrl+k` / `ctrl+d` (S-e is G-B's). The action names `save` / `cancel` are not in `_LOAD_DIALOG_INERT_ACTIONS` (`load_file`, `save_project`, `focus_palette`, `cycle_density`), so the app's guard never blocks them.
    - No `DEFAULT_CSS` (TC-033: the class's own `__dict__` must hold none).
  - **`__init__`** calls `super().__init__()`, then stores `_preview_fn = preview`, `_confirm_fn = confirm`, `_initial_name = initial_name`, `self.variants = list(variants or [])`, `self.candidate_files = list(candidate_files or [])` (attribute names unchanged: `test_tc304` / `test_tc305` read them), and sets `_plan = None`, `_live = False`, `_trailing = None` (a Textual `Timer` or `None`), `_shown = False`, `_dismissed = False`. Names checked free (K21); never `_closed` / `_closing` (9b R-GA-1) and never `_ready` (`App._ready`). It calls neither callable (S4 makes the first call).
  - `default_parent` and the attribute `self.default_parent` are gone (R1).
  - Docstring rewritten: Summary (name, target line, summary, Save / Cancel; the plan comes from the app); Args (the five keywords); Data Flow (first preview after the first refresh; 150 ms debounce; Save → `confirm`; dismiss payload); Dependencies "Used by: `S19TuiApp.action_save_project`".
module: s19_app/tui/screens.py
examples: [S1-1] (S-b) `inspect.signature(SaveProjectScreen.__init__)` → parameters `self, *, preview, confirm, initial_name=None, variants=None, candidate_files=None`; `SaveProjectScreen(WA)` (the old positional form) → `TypeError` (census A re-pins) (target (11)). RED side: base signature `(self, default_parent, variants=None, candidate_files=None)` (p11b U7)
examples: [S1-2] (S-b) `SaveProjectScreen(preview=F.preview, confirm=C.confirm)` constructed, not pushed → `F` 0 calls, `C` 0 calls; `screen.plan is None` (K13) (target (11)). RED if: `__init__` calls `preview("")` → 1 call before any frame (LLR-175.5b)
examples: [S1-3] (Q4) `variants=[("a","a.s19"),("b","b.s19")]`, `candidate_files=["doc.json","extra.json"]` → `screen.variants == [("a","a.s19"),("b","b.s19")]`, `screen.candidate_files == ["doc.json","extra.json"]`, `_assignment_rows_enabled is True`; with `variants=None` → `[]`, `False` (target (11), unchanged meaning). RED if: the attributes renamed (e.g. `_variants`) → `test_tc304` / `test_tc305` fail on `screen.variants`
examples: [S1-4] (TC-033) `SaveProjectScreen.__dict__.get("DEFAULT_CSS", "")` → `""`; `SaveProjectScreen.AUTO_FOCUS == "#project_name"`; `[(b.key, b.action, b.priority) for b in SaveProjectScreen.BINDINGS]` → `[("escape","cancel",False), ("alt+s","save",True)]` (target (11)). RED if: `Binding("alt+s", "save")` without priority → [S6-3] types `s` into the field instead of saving (A9b-01)
examples: [S1-5] (LLR-175.3e, K7) the dialog open, focus in `#project_name`, keys `s`, `q`, `l`, `p`, `v`, `y` → the field holds `sqlpvy`, stack depth 2, 0 dismisses, 0 status lines added (1 of 1) (target (11)). RED if: a mutant `Binding("s", "save")` on the screen → the field misses `s` and the save runs (declared: on base the modal already blocks the app's non-priority letters, so the RED is the mutation)

SaveProjectScreen.compose
req: HLR-175f, LLR-175.2, LLR-175.3i, LLR-175.4g, LLR-175.4h, LLR-175.4i, LLR-175.4j, LLR-175.3h, LLR-173.7
in: (self) `_initial_name`, `variants`, `candidate_files`, `_assignment_rows_enabled`
out: ComposeResult (one widget tree)
func: rewritten (S2). One tree, in this DOM order (the order is the `tab` order, K15, K18):
  - `Container(id="save_box", classes="modal-dialog")` holding:
    - `Label("Project name", classes="modal-title")`;
    - `OsClipboardInput(value=self._initial_name or "", placeholder="letters, digits, - and _", id="project_name")`. It stays an `OsClipboardInput` (batch-31 AC-2: `test_ac2_paste_reaches_project_name_input`). `select_on_focus` stays at the Textual default `True`, so the auto focus selects the prefilled name (K1; LLR-175.3h). The value set at construction posts no `Changed` that the dialog acts on (`_live` is `False`). The `Input` holds the raw prefilled name — a Textual `Input` does not interpret markup, and its `value` is what `preview` / `confirm` read and what the save uses (S11-12); only labels and `Static` text elsewhere go through `painted_names`.
    - `Static("", id="save_where", markup=False)`;
    - `VerticalScroll(id="save_summary")`, empty; focusable by default (`ScrollableContainer.can_focus`), with `home` / `end` / `pageup` / `pagedown` / `up` / `down` bindings (LLR-175.4i). Rows are mounted by S9.
    - only when `_assignment_rows_enabled`: `Label("Project-wide batch files (.json):", classes="modal-title", markup=False)`, `SelectionList[str](*[(Text(n), n) for n in self.candidate_files], id="assign_batch", classes="assign-list")`, then per variant index `i`: `Label(f"Assign files to '{display}':", classes="modal-title", markup=False)` and `SelectionList[str](*[(Text(n), n) …], id=f"assign_{i}", classes="assign-list")`. Ids, classes, order and values are unchanged (Q4). The two changes are literal painting: `markup=False` on the labels and `Text` prompts (D-GA11-8, K14).
    - `Container(Button("Save (alt+s)", id="save_ok", classes="modal-confirm"), Button("Cancel (esc)", id="save_cancel"), id="saveproject_buttons", classes="modal-buttons")`.
  - No `#project_parent_path`, no `#save_browse_row`, no `#save_browse`, no `id="load_dialog"` (R1). The class `.modal-dialog` stays (TC-033 queries `.modal-dialog`, `.modal-title`, `.modal-confirm`).
  - The button labels are fixed literals with no name in them, so they stay `str` (as `Load (alt+l)` in 9b).
module: s19_app/tui/screens.py
examples: [S2-1] (HLR-175f, VS-PC-3, K1) pushed at 118×54 → exactly 1 each of `#save_box`, `#project_name`, `#save_where`, `#save_summary`, `#saveproject_buttons`, `#save_ok`, `#save_cancel`, in that DOM order; 1 `.modal-dialog`, 1 `.modal-title`, 1 `.modal-confirm`; stack depth 2 (target (11)). RED side: base `#save_summary: 0 #save_where: 0` (P11-2)
examples: [S2-2] (LLR-175.2) the same push at 118×54 and 220×60 → `len(screen.query("#project_parent_path")) == 0`, `len(screen.query("#save_browse")) == 0`, `len(screen.query("#save_browse_row")) == 0` (2 of 2 sizes) (target (11)). RED side: base `#project_parent_path: 1 #save_browse: 1` (P11-2)
examples: [S2-3] (LLR-175.3i) painted: `#save_ok` `Save (alt+s)`, `#save_cancel` `Cancel (esc)`; title `Project name`; placeholder `letters, digits, - and _` (target (11)). RED side: base labels `Save` / `Cancel` (code read)
examples: [S2-4] (LLR-173.7, TC-B100-66 G-A share) the regexes `\bD\d+\b`, `\bO-\d+`, `VS-`, `LLR-`, `HLR-` over every string literal of the `SaveProjectScreen` class body (`Project name`, `letters, digits, - and _`, `Project-wide batch files (.json):`, `Assign files to '…':`, `Save (alt+s)`, `Cancel (esc)`) → 0 matches (target (11)). RED if: the pc_B hint `Projects are saved only in the work area (.s19tool/workarea). Browse is gone (D7).` is shipped → 1 match (`D7`)
examples: [S2-5] (LLR-175.4g G-A share, K14) `variants=[("b","[b]x")]`, `candidate_files=["[i]doc.json"]` → the assignment label paints `Assign files to '[b]x':` with 0 spans; the `#assign_batch` option 0 visual paints `[i]doc.json` with 0 spans (2 of 2) (target (11)). RED if: `Label(f"Assign files to '{display}':")` (markup on, base) → `Assign files to 'x':`, 1 span; a `str` prompt → `doc.json`, 1 span (executed, K14)
examples: [S2-6] (LLR-175.4, LLR-175.6 G-A share; S-a AST arm) AST census of the `SaveProjectScreen` class body → 0 calls to `sanitize_project_name`, `is_windows_device_name`, `predict_placement`, `place_into_workarea`, `list_projects`, `os.listdir`, `iterdir`, `_project_folder_refusal`, `plan_project_save`; 0 `Name` / `Attribute` reads of `Path` (target (11)). RED if: a mutant that sanitises the name in the dialog to paint the folder → 1 call to `sanitize_project_name` (`screens.py` imports it for the flow-name dialog, `:42`, `:792`)
examples: [S2-7] (LLR-175.4i, K18) `variants` of 2 and 2 candidates → `tab` × 6 from `#project_name` → `save_summary`, `assign_batch`, `assign_0`, `assign_1`, `save_ok`, `save_cancel` (target (11)). RED if: the assignment rows composed after the buttons → `save_ok` comes 2nd

SaveProjectScreen.on_mount (+ `_first_preview`)
req: LLR-175.5b, LLR-175.3h, LLR-175.3d, LLR-175.5, HLR-175
in: (self)
out: None (schedules the first preview)
func: rewritten (S4). The base statement (`#project_parent_path.value = …`) is gone.
  - `on_mount()` → `self.call_after_refresh(self._first_preview)`. Nothing is computed before the first frame (LLR-175.5b: the app's image decision runs inside the first `preview` call, SC-1). The focus comes from `AUTO_FOCUS`, which selects the prefilled name (K1).
  - `_first_preview()` (new helper): `if self._dismissed: return`; `self._live = True`; `self._recompute()` (S5). It is the only place `_live` becomes `True`.
module: s19_app/tui/screens.py
examples: [S4-1] (LLR-175.5b G-A share, K1) pushed at 118×54 with `initial_name="P"` → `F` called exactly once by the time the first frame settles, with `"P"`; at that call `app.screen is screen` and `screen.query_one("#project_name").region.width == 86` (laid out) (target (11)). RED if: the first `preview` is called in `__init__` or `compose` → at that call the dialog is not the active screen / has no region (follows from the push order; not executed)
examples: [S4-2] (LLR-175.3h G-A share, K1) `initial_name="P"` → value `P`, `selection == Selection(0, 1)`, `focused.id == "project_name"`, `#save_where` paints `P   new folder` from `PV("P")`; `x` typed → value `x` (the selection is replaced), `F` calls `["P", "x"]` (3 assertions) (target (11)). RED side: base `on_mount` fills only `#project_parent_path`; the name starts empty (code read)
examples: [S4-3] (LLR-175.3h boundary, K2) `initial_name=None` → value `""`, `F` called once with `""`, `screen.plan is None`, `#save_where` paints `""` with `F` returning `PV_EMPTY` (target (11)). RED if: a mutant that prefills `app.current_project` itself when `initial_name is None` → a non-empty field with no project open
examples: [S4-4] (LLR-175.3d, K1) `ctrl+s` route modelled by a push → `app.focused.id == "project_name"` (target (11)). RED side: base `focused at open: OsClipboardInput project_parent_path` (P11-2)
examples: [S4-5] (S-d, LLR-175.5 G-A share) open, then 0 keys for 1 s → `F` 1 call in total; the dialog makes no other call to the app (target (11)). RED if: a mutant that also calls `preview` from `on_mount` directly → 2 calls at open

SaveProjectScreen.on_input_changed (+ `_recompute`, `_stop_trailing`)
req: LLR-175.5a, LLR-175.1, HLR-175, LLR-175.1h
in: Input.Changed event
out: None (a recompute now, or one trailing recompute scheduled)
func: new (S5, S-g). Constant `SAVE_RECOMPUTE_S = 0.150` at module level (seconds; LLR-175.5a). A debounce, not a throttle (ruling P-GA11-1, A11-13): each keystroke resets the timer; no `time` clock, no `_last_run`, no leading edge.
  - **`on_input_changed(event)`.**
    1. If `event.input.id != "project_name"`, or `not self._live`, or `self._dismissed`: return. A change before the first frame is read by `_first_preview` anyway.
    2. `self._stop_trailing()`.
    3. `self._trailing = self.set_timer(SAVE_RECOMPUTE_S, self._recompute)` — one recompute 150 ms after the last change.
  - **`_recompute()`.** `if self._dismissed: return`; `self._stop_trailing()`; `self._paint(self._preview_fn(self.query_one("#project_name", Input).value))`. The text goes to `preview` verbatim (not stripped), also when blank (D-GA11-1). The call is synchronous (S-g).
  - **`_stop_trailing()`.** `if self._trailing is not None: self._trailing.stop(); self._trailing = None`.
  - No `import time` (P-GA11-1: the debounce needs no clock, so the 9b census set is unchanged).
module: s19_app/tui/screens.py
examples: [S5-1] (LLR-175.5a, debounce, A11-13) open, then 20 keys `a` … `t` 10 ms apart → each keystroke resets the 150 ms timer, so `F` is called once with `abcdefghijklmnopqrst` (1 ≤ 3); the field holds the full text after the last key; `#save_where` paints `abcdefghijklmnopqrst   new folder` ≤ 300 ms after the last key (3 assertions) (target (11)). RED if: a recompute per keystroke → 20 calls
examples: [S5-2] (LLR-175.5a negative control) a mutant that never fires the trailing run → `F` 0 calls; `#save_where` stays empty while the field holds 20 letters → RED
examples: [S5-3] (LLR-175.5a boundary) one key `q` → `F` called once with `"q"` 150 ms later; `screen._trailing is None` after the recompute (target (11)). RED if: a mutant that fires immediately on every change (no debounce) → the burst of [S5-1] gives 20 calls
examples: [S5-4] (LLR-175.5a boundary) two bursts `ab`, a 400 ms pause, `cd` (each 10 ms apart) → `F` calls `["ab", "abcd"]`: each burst gives one recompute 150 ms after its last key (2 calls) (target (11), derived). RED if: a mutant that also fires on the first key of a burst → extra calls
examples: [S5-5] (LLR-175.1 G-A share) `F` returns `SavePreview(where=(("Ab   updates the open project","info"),), rows=(), plan=PLAN("Ab"), refused=False)` for `ab` → after typing `ab` and 200 ms, `#save_where` paints exactly `Ab   updates the open project`, 0 spans (the kind and the on-disk name are G-B's) (target (11)). RED side: base dialog paints nothing on a name change (P11-2: `'ab' folder line? False`)
examples: [S5-6] (LLR-175.1h G-A share) `F` refuses `!!!` with `name is empty — type a project name` → after typing `!!!` and 200 ms (no Save), `#save_where` paints `name is empty — type a project name` with the class `refusal`, 0 rows (target (11)). RED if: a mutant that calls `preview` only on Save → nothing painted before Save
examples: [S5-7] (S-g, K20) `ab` posted, `escape` 20 ms later with the trailing run pending → `CB == [None]`; `F` 0 calls in the next 400 ms (the timer stopped in `_close`, and `_recompute` returns on `_dismissed`) (target (11)). RED if: `_close` leaves the timer running and `_recompute` lacks the guard → 1 call to `query_one` on an unmounted screen (`NoMatches`) 150 ms later

SaveProjectScreen._paint
req: HLR-175, LLR-175.4, LLR-175.4g, LLR-175.4j, LLR-175.1i, LLR-175.4k, LLR-175.4c, LLR-175.4d, LLR-175.4e, LLR-175.4f
in: SavePreview p
out: None (`#save_where`, `#save_summary` rows, `_plan` set)
func: new (S9), the only writer of `_plan`, `#save_where` and the summary rows.
  1. `self._plan = p.plan`; `self._shown = False`; `self.call_after_refresh(self._mark_shown)` (S11-04). `_mark_shown()` (new helper): `if not self._dismissed: self._shown = True`.
  2. `where = query_one("#save_where", Static)`; `where.update(Text("\n".join(text for text, _kind in p.where)))`; `where.set_class(p.refused or any(kind == "refusal" for _t, kind in p.where), "refusal")`. A `rich.text.Text` is never parsed as markup and the `Static` is `markup=False` (K14). No per-line style, so the visual has 0 spans (D-GA11-4).
  3. `box = query_one("#save_summary", VerticalScroll)`; `have = list(box.query(Static))`.
  4. For each `(w, row)` in `zip(have, p.rows)`: `w.update(Text(row))` (in place, K17).
  5. If `len(p.rows) > len(have)`: `box.mount_all([Static(Text(r), markup=False) for r in p.rows[len(have):]])`.
  6. For each `w` in `have[len(p.rows):]`: `w.remove()`.
  Rows are painted in the given order, one widget per row, never sorted, filtered, cut or joined: G-B composes every row (SC-1, SC-6). The one-line rule is CSS (C3). A refused preview carries 0 rows, so the summary empties (LLR-175.1i).
module: s19_app/tui/screens.py
examples: [S9-1] (LLR-175.4 G-A share) `_paint(SavePreview(where=(("ab   merges into an existing project","info"),), rows=("keep  ab/firmware.s19", "new  ab/firmware_1.s19", "rewrite  ab/project.json"), plan=PLAN("ab"), refused=False))` → 3 row widgets painting exactly those 3 strings in that order; `screen.plan is` that `PLAN("ab")` object (target (11)). RED if: a mutant that drops rows starting `keep` → 2 rows (the LLR-175.4 negative control at the G-A layer)
examples: [S9-2] (LLR-175.4g G-A share, K14) `initial_name="[red]a"`, `F` rows `("new  [b]x.s19", "new  flows/[i]f.json")` → `#save_where` `[red]a   new folder`, rows `new  [b]x.s19` and `new  flows/[i]f.json`, each with 0 spans (3 of 3) (target (11)). RED if: rows built as `Static(row)` with markup on (`Static(markup=True).update(str)`) → `new  x.s19` with 1 span (executed, K14)
examples: [S9-3] (LLR-175.4g G-A share, K14) a refusal line `'[b]P' is already a project as '[b]P' — choose another name` → painted verbatim, 0 spans (target (11)). RED if: the where line painted through a markup `Static` → `'P' is already…` with 1 bold span
examples: [S9-4] (LLR-175.1i G-A share) after [S9-1] (3 rows), `_paint(PV_REFUSED("target already has a MAC file (m.mac) — choose another name"))` → 0 row widgets once the removal settles; `#save_where` paints that line with the class `refusal`; `screen.plan is None` (target (11)). RED if: a mutant that keeps the previous rows on a refused preview → 3 stale rows under a refusal
examples: [S9-5] (LLR-175.4j G-A share, K15) `ROWS300` at 118×54 → every row region height 1; row 0 (131 characters) width 80 and its rendered line ends with `…`; at 220×60 row 0 width 118, ends with `…` (target (11)). RED if: the row widgets allowed to wrap → row 0 height 2 (executed, K16)
examples: [S9-6] (LLR-175.4c / .4d / .4e / .4f G-A share) `rows=("firmware.s19 + 1 change entry, 0 applied by this save", "unsaved changes in firmware.s19", "links or junctions not copied: flows/j1", "active variant firmware_1 (was firmware)")` (the row text is G-B's; these are the requirement tokens) → 4 rows painted verbatim in that order (target (11)). RED if: a mutant that sorts the rows → `active variant …` painted first
examples: [S9-7] (K17, performance record) 2 → 300 rows: the paint call 203 ms, mounted after 360 ms; 300 → 300 in place 78 ms; 300 → 2 rows 94 ms (target (11); see R-GA11-3). RED if: a mutant that removes and re-mounts every row on each paint → the 300 → 300 case costs about as much as 2 → 300 (360 ms) instead of 78 ms
examples: [S9-8] (D-GA11-4) `where=(("abc   new folder","info"), ("the summary changed — check it, then save again","refusal"))`, `refused=False` → `#save_where` paints `abc   new folder\nthe summary changed — check it, then save again`, has the class `refusal`, 0 spans; `where=(("ab   new folder","info"),)` → the class removed (2 of 2) (target (11)). RED if: the class set from `refused` alone → the out-of-date line (kind `refusal`, `refused=False`) is not bold
examples: [S9-9] (A11-12, A11-05 G-A share) rows composed by G-B with a rename (`file fw.s19 → fw_2.s19 — keep`) and a manifest-keep row (`project.json — rewrite; the current one damaged, a copy is kept as project.json.previous-<UTC>`) → painted verbatim, one widget each, 0 spans, in the given order (target (11)). RED if: the dialog re-parses or cuts a `→` row → the source name is lost → RED.

SaveProjectScreen.action_save (+ on_input_submitted, on_button_pressed `#save_ok`)
req: HLR-175a, HLR-175b, HLR-175d, HLR-175e, LLR-175.2a, LLR-175.3b, LLR-175.3c, LLR-175.3f, LLR-175.4a, LLR-175.4b, LLR-175.6, LLR-175.1a … LLR-175.1m (G-A share)
in: (self) `#project_name.value`, `_plan`
out: either `_close(payload)`, or a repaint with the dialog left open
func: new (S6). Triggers, each calling `action_save()`:
  - `alt+s` from any focus (the `priority=True` screen binding, K5);
  - `enter` in `#project_name` (`on_input_submitted`: `if event.input.id == "project_name": event.stop(); self.action_save()`; ruling Q8);
  - `#save_ok` by click or by `enter` on the focused button (`on_button_pressed`: `event.stop()`; `save_ok` → `action_save()`, `save_cancel` → `action_cancel()`).
  Steps:
  0. `if self._dismissed: return` (a second queued Save skips `confirm`).
  1. `name = query_one("#project_name", Input).value` (verbatim); `painted = self._plan if self._shown else None` (S11-04: a save queued on the dialog before the first paint is marked shown passes `None`, so `confirm` repaints with `the summary changed` instead of saving a plan nobody saw; SR-11-2, corrected at close).
  2. `again = self._confirm_fn(name, painted)`. Always called: also for blank text (ruling Q-3: the empty pair comes from the one preparation), also when the painted preview is refused (D-GA11-2). `#save_ok` is never disabled (LLR-175.3f).
  3. If `again is not None`: `self._stop_trailing()`; `self._paint(again)`; return. The repaint counts as a recompute, and the pending trailing run is dropped, so it cannot erase the `the summary changed` pair a moment later (K11; LLR-175.4b).
  4. If `painted is None` (G-B answered "go" for a plan nobody painted; SC-2 forbids it): `logger.warning("Save dialog: confirm accepted no painted plan; repainting")`; `self._recompute()`; return. Fail loud, never dismiss without a plan.
  5. `batch, assignments = self._collect_composition()` (unchanged, Q4).
  6. `self._close(SaveProjectPayload(parent_folder=str(painted.target.parent), project_name=name, batch=batch, assignments=assignments, plan=painted))`. The parent is the folder that holds the painted plan's target, which is this work area (D-GA11-3, SC-7; LLR-175.2a). `plan` is the painted object itself (Q-2; LLR-175.4a; SC-3).
module: s19_app/tui/screens.py
examples: [S6-1] (LLR-175.3c G-A share, K4) `initial_name="fresh1"`, painted `PV("fresh1")`; each of `alt+s`, `enter` in the field, a click on `#save_ok`, `enter` on a focused `#save_ok` (4 fresh apps) → `C` called once with `("fresh1", P)` where `P is screen.plan` (the painted object); `CB == [SaveProjectPayload(parent_folder=str(WA), project_name="fresh1")]`, `CB[0].plan is P`; depth 1 (4 of 4) (target (11)). RED side: base has no `BINDINGS` and no `on_input_submitted`, so `alt+s` and `enter` save nothing (code read)
examples: [S6-2] (LLR-175.2a G-A share, HLR-175e) [S6-1]'s payload → `Path(CB[0].parent_folder) == WA` (`PLAN("fresh1").target.parent`); with `WA` under a 150-character base path → the same equality (2 of 2) (target (11)). RED if: a mutant that sets `parent_folder=str(self.app.base_dir)` → `base_dir != WA`, and G-B's router refuses `not the work area folder` (LLR-175.2a's negative control)
examples: [S6-3] (A9b-01, K5) the focus in `#project_name` holding `fresh1` with the cursor at the end, posted `events.Key("alt+s", character="s")` (the terminal shape; Pilot builds `character=None`) → dismiss with `project_name == "fresh1"`; 0 characters typed (target (11)). Test note for E4: post the event directly. RED if: the binding without `priority=True` → the field becomes `fresh1s` and nothing is dismissed
examples: [S6-4] (LLR-175.3b G-A share, HLR-175d, K6) field `""` and `"   "`, each with `alt+s`, a click on `#save_ok` and `enter` in the field → `C` called with `""` / `"   "` (verbatim); 0 dismisses; `#save_where` paints `name is empty — type a project name` with the class `refusal` (6 of 6) (target (11)). RED if: the base rule `if not name: return` (no `confirm` call) → `#save_where` stays empty (executed on base, P11-2: `'name is empty'? False`)
examples: [S6-5] (LLR-175.3f, HLR-175b G-A share, K10) `F` / `C` refuse `a b` with `'a b' is already a project as 'ab' — choose another name`; typed `a b`, then `alt+s` → 0 dismisses, the line painted; `tab`, `tab` → focus `save_ok`, `can_focus is True`, `disabled is False`; `enter` → 0 dismisses, the line still painted, `C` 2 calls (target (11)). RED if: `#save_ok.disabled = True` while refused → `tab` never reaches it; RED if: a mutant that dismisses when the painted preview was refused without calling `confirm` → 1 dismiss
examples: [S6-6] (LLR-175.1a … LLR-175.1m G-A share) for each refusal line `L` among `'Reports' is a reserved name — choose another name`, `'CON' is a device name — choose another name`, `name too long (at most 64 characters) — shorten the name` (p11b U6 texts), `source file missing: firmware.s19 — reload it or remove it from the project`, `1 blocked entry (0x8000007C) — fix them in the Patch Editor`: `F` and `C` return `PV_REFUSED(L)` → `L` painted before Save; `alt+s` → `L` painted, 0 dismisses (5 of 5; the texts and their order are G-B's) (target (11)). RED if: a mutant that paints refusals only after the dialog closes (the base flow) → 0 lines before Save and 1 dismiss on `alt+s`
examples: [S6-7] (LLR-175.4b G-A share, K11) open with 300 ms quiet; `abc` typed 10 ms apart; `alt+s` 20 ms after the last key (trailing run pending, painted plan `PLAN("a")`) → `C` called with `("abc", PLAN("a") object)`; 0 dismisses; `#save_where` `abc   new folder\nthe summary changed — check it, then save again`; after 400 ms the same text and `screen._trailing is None`; a second `alt+s` → 1 dismiss `("…workarea", "abc")` with `CB[0].plan is` the repainted plan (4 assertions) (target (11)). RED if: step 3 omits `_stop_trailing()` → 400 ms later the pair is erased (`abc   new folder` only; executed, K11); RED if: a mutant that dismisses with a freshly computed plan → 1 dismiss, 0 token pairs (LLR-175.4b's negative control)
examples: [S6-8] (LLR-175.4b arm 2 G-A share) painted `PV("ab")` (merge); then the test makes `C` return `SavePreview(where=(("ab   merges into an existing project","info"), ("the summary changed — check it, then save again","refusal")), rows=("new  ab/firmware_1.s19",), plan=PLAN2, refused=False)` → after `alt+s`: 0 dismisses, the row `new  ab/firmware_1.s19` painted, `screen.plan is PLAN2` (target (11)). RED if: a mutant that keeps `_plan` from before the repaint → `screen.plan` is the old `PLAN("ab")` and the next Save mismatches forever
examples: [S6-9] (D-GA11-3 / SC-2 failure path) `C` returns `None` while `screen.plan is None` (a contract breach) → 0 dismisses, 1 warning log line `Save dialog: confirm accepted no painted plan; repainting`, `F` called once more (target (11)). RED if: the dialog dismisses anyway → `AttributeError: 'NoneType' object has no attribute 'target'`
examples: [S6-10] (Q4 G-A share) 2 variants, 2 candidates; `#assign_batch` selects `doc.json`, `#assign_1` selects `extra.json`; Save → `CB[0].batch == ("doc.json",)`, `CB[0].assignments == {"b": ("extra.json",)}` (TC-304's assertion, unchanged) (target (11); `_collect_composition` is the base code). RED if: `action_save` builds the payload without `_collect_composition()` → `batch == ()`, `assignments == {}`
examples: [S6-11] (D-GA11-2, LLR-175.6 G-A share) `confirm` is called for every Save request: over [S6-1], [S6-4], [S6-5], [S6-7] → 1 `C` call per press, 0 presses decided by the dialog alone (target (11)). RED if: a mutant that dismisses straight away when the painted preview is not refused (no `confirm`) → [S6-7] saves a plan nobody saw
examples: [S6-12] (S11-04, corrected at close) a stub `preview` that sleeps 300 ms; a Save queued on the dialog itself (`screen.call_next(screen.action_save)`) before the first paint is marked shown → `C` called with `(name, None)` (the preview not yet shown), `0` dismisses, `#save_where` paints `the summary changed — check it, then save again` once the frame settles; a second `alt+s` → `1` dismiss (`1` of `1`). RED if: a mutant that passes `self._plan` regardless of `_shown` → `confirm` sees the plan equal and returns `None` → `1` dismiss of a plan nobody saw → RED.

SaveProjectScreen.action_cancel (+ `#save_cancel`, `_close`)
req: HLR-175c, LLR-175.3, LLR-175.3a, interfaces S-b (`_dismissed`), LLR-166.1
in: (self)
out: `dismiss(None)`
func: new (S7). `action_cancel()` → `self._close(None)`. Triggers: `escape` (screen binding; `Input`, `VerticalScroll`, `Button` and `SelectionList` bind no `escape`, K3) and `#save_cancel` (click or `enter`, through `on_button_pressed`, S6).
  `_close(result)` (new helper), the only way out:
  1. `if self._dismissed: return` (the first line; 9b A9b-02, Inc 10 Q-5);
  2. `self._dismissed = True`;
  3. `self._stop_trailing()`;
  4. `self.dismiss(result)`.
  The dialog writes no file. On `None`, G-B's `_handle_save_dialog(None)` drops the session (S-d). Focus after close is SC-8.
module: s19_app/tui/screens.py
examples: [S7-1] (LLR-175.3, HLR-175c, K3) `initial_name="fresh1"` painted; `escape` with the focus on each of `#project_name`, `#save_summary`, `#save_ok`, `#save_cancel` → `CB == [None]`, stack depth 1, `C` 0 calls (4 of 4) (target (11)). RED side: base `escape -> stack: ['Screen', 'SaveProjectScreen']` (P11-2)
examples: [S7-2] (LLR-175.3a, K4) a click on `#save_cancel` and a focused `enter` on it, each with `fresh1` typed → `CB == [None]`, `C` 0 calls (2 of 2) (target (11)). RED if: `save_cancel` routed to `action_save` → `C` 1 call and 1 payload
examples: [S7-3] (HLR-175c boundary, K20) after a refusal painted and `alt+s` refused, `escape` → `CB == [None]`, `C` still 1 call (target (11)). RED if: a mutant that sets `_dismissed` on a refused Save → `escape` is ignored and the dialog stays
examples: [S7-4] (S-b guard, K12) `screen._close(None); screen._close(None)` in one tick → `CB == [None]`, stack `['Screen']`, 0 exceptions (target (11)). RED if: step 1 removed → `ScreenStackError: Can't pop screen; there must be at least one screen on the stack` (executed, K12)
examples: [S7-5] (9b R-GA-1 carried over) the flag is named `_dismissed`: `escape` returns from `pilot.press` (K3). RED if: renamed `_closed` (a `MessagePump` attribute, 9b K11) → `escape` hangs → RED by timeout (target (11))

SaveProjectScreen.plan (property)
req: LLR-175.4k, HLR-175a, LLR-175.4a
in: (self) `_plan`
out: Optional[SavePlan] plan
func: new (S8), read-only: `@property def plan(self) -> Optional[project_gather_service.SavePlan]: return self._plan`. No setter. The value is the object of the last painted `SavePreview` (S9 step 1): `None` before the first paint and for a preview with no plan (empty name, name refusal); a refused `SavePlan` when G-B paints a plan refusal. `SavePlan` is frozen and its `rows` a tuple (`project_gather_service.py:1150`), so the value cannot change.
module: s19_app/tui/screens.py
examples: [S8-1] (LLR-175.4k, K13) before the first paint `screen.plan is None`; `screen.plan = PLAN("x")` → `AttributeError` (`property 'plan' of 'SaveProjectScreen' object has no setter`); `screen.plan.rows = ()` after [S9-1] → `FrozenInstanceError`; `screen.plan.rows.append(1)` → `AttributeError` (a tuple) (4 of 4) (target (11)). RED if: `plan` as a plain attribute → the assignment succeeds
examples: [S8-2] (LLR-175.4a G-A share) after [S6-1], the plan read from `screen.plan` just before `alt+s` `is` `CB[0].plan` (the dismissed payload carries the painted object) (target (11)). RED if: a mutant that dismisses with `plan=None` → G-B's router prepares fresh and the identity test of Q-2 never holds
examples: [S8-3] (LLR-175.4k boundary) `_paint(SavePreview(where=(("too many files to copy — move files out of the project, then save again","refusal"),), rows=(), plan=REFUSED, refused=True))` with `REFUSED = SavePlan(target=WA/"Q", target_kind="new", rows=(), image="", manifest_keys=(), refusal="too many files to copy …")` → `screen.plan is REFUSED`, `len(screen.plan.rows) == 0` (target (11)). RED if: `_paint` keeps `_plan` only for non-refused previews → `screen.plan` stays the previous plan

C1 `#save_box` (new)
req: HLR-175f, LLR-175.4h
in: —
out: dialog box
func: new rule inside the Calm Dark modal block of `styles.tcss`, placed after `.assign-list` (and so before `/* --- Report viewer modal`), with a section comment `/* --- Save project dialog (batch-100 increment 11, HLR-175) … */`:
  - `#save_box { width: 80%; max-width: 130; max-height: 90%; }`
  `.modal-dialog` still gives border, background, colour, `padding: 1 2` and `height: auto`; the id wins on width (pc_B `DIALOG_WIDTH = ("80%", 130)`). `max-height: 90%` keeps the box, and so its docked buttons, on screen (K16). The marker comment `/* --- Calm Dark modal re-skin (batch-02 increment 8, LLR-015.1) ---` stays byte-identical (9b A9b-12). No hex colour (TC-033). The shared selector `.modal-dialog, #load_dialog` is 9b's (it becomes `.modal-dialog`); Inc 11 does not touch it.
module: s19_app/tui/styles.tcss
examples: [C1-1] (HLR-175f, K1, K15) `#save_box` region: 118×54 with 2 rows (13, 17, 92, 19); 118×54 with `ROWS300` (13, 4, 92, 46); 220×60 with `ROWS300` (45, 4, 130, 52) (target (11)). RED if: `#save_box` without `max-width: 130` → at 220×60 the box is 176 wide (80 %)
examples: [C1-2] (TC-033) `_modal_css_block()` (the slice from the marker to `/* --- Activity rail`) contains `#save_box`, `#save_where`, `#save_summary` and 0 matches of `#[0-9A-Fa-f]{6}\b`; `grep -c "Calm Dark modal re-skin (batch-02 increment 8" styles.tcss` → 1 (target (11)). RED if: the rules are placed after `/* --- Activity rail` → the block lacks them (the TC-033 scan would not see a hex there)
examples: [C1-3] (no regression) the other 7 modals that keep `id="load_dialog"` get no `#save_box` rule: their regions are unchanged (code read: the selector names only this id) (target (11)). RED if: the rule written as `.modal-dialog { width: 80%; … }` → every modal widens

C2 `#save_where`, `#save_where.refusal` (new)
req: LLR-175.1, HLR-175b, LLR-175.3b
in: —
out: —
func: new.
  - `#save_where { height: auto; padding: 0 1; margin-bottom: 1; }` — the target line and any refusal wrap, so a long reason with addresses stays readable (not one-line: only summary rows are one line).
  - `#save_where.refusal { text-style: bold; }` — the class set by S9 step 2. No colour: the single accent rule (TC-033).
module: s19_app/tui/styles.tcss
examples: [C2-1] (HLR-175b) after [S6-5], `#save_where.has_class("refusal")` and its computed `text_style` includes `bold`; after [S4-2] (`P   new folder`) the class is absent (2 of 2) (target (11)). RED if: `#save_where.refusal` rule missing → the refusal paints in the normal weight (class present, `bold` absent)
examples: [C2-2] (LLR-175.1m G-A share) a 200-character blocked-entries line at 118×54 → `#save_where` height ≥ 2 (wraps) and its painted text equals the line (target (11)). RED if: `#save_where` given `text-wrap: nowrap` → height 1 and the addresses cut on screen

C3 `#save_summary`, `#save_summary:focus`, `#save_summary Static` (new)
req: LLR-175.4h, LLR-175.4i, LLR-175.4j
in: —
out: —
func: new.
  - `#save_summary { height: auto; max-height: 50vh; border: round $rule; background: $bg-base; padding: 0 1; }` — sized by its rows up to half the screen height, then it scrolls (K15: 27 rows at 54, 30 at 60).
  - `#save_summary:focus { border: round $accent-calm; }`
  - `#save_summary Static { height: 1; text-wrap: nowrap; text-overflow: ellipsis; }` — on the row widgets themselves: `text-wrap` / `text-overflow` are not inherited in Textual 8.2.8 (9b S9b-8 note in the 9b tree's `styles.tcss`).
module: s19_app/tui/styles.tcss
examples: [C3-1] (LLR-175.4h, K15) `ROWS300` at 118×54 → `#save_ok` (68, 45, 16, 3) and `#save_cancel` (86, 45, 16, 3) fully visible; at 220×60 → (138, 51, 16, 3) and (156, 51, 16, 3) fully visible (2 of 2) (target (11)). RED if: summary and box both unbounded (`max-height` removed from `#save_summary` and `#save_box`) → box (12, -7, 91, 317), `#save_ok` at y = 305, not visible (executed, K16). NOT RED: the summary alone unbounded leaves both buttons visible (docked; executed, K16) — see P-GA11-2
examples: [C3-2] (LLR-175.4i, K15) `ROWS300` at 118×54: `tab` from `#project_name` → `save_summary`; `end` → `scroll_y == max_scroll_y` (275) and the last row's region (18, 38, 80, 1) inside `#save_summary`'s region; `tab` order `project_name → save_summary → save_ok → save_cancel → project_name`, `shift+tab` the reverse (3 assertions) (target (11)). RED if: `#save_summary.can_focus = False` → `tab` lands on `save_ok` (executed, K16); RED if: the summary alone unbounded → the last row at y = 313, outside the screen (executed, K16)
examples: [C3-3] (LLR-175.4j, K15, K16) the row rule makes row 0 of `ROWS300` 1 high at 118 and 220 columns, ending with `…`. RED if: `#save_summary Static` without `text-wrap: nowrap` → height 2 (executed with `text-wrap: wrap; height: auto`, K16) (target (11))
examples: [C3-3b] (LLR-175.4h boundary) a 1-row summary at 118×54 → `#save_summary` height 3 (1 row + border), buttons fully visible (target (11)). RED if: `#save_summary { height: 1fr }` → a 1-row summary takes the whole remaining box

C4 `#saveproject_buttons` (unchanged id; no rule)
req: LLR-175.4h
in: —
out: —
func: no new rule. The container keeps the class `modal-buttons` (`layout: horizontal; dock: bottom; align-horizontal: right; padding-top: 1`), which pins Save and Cancel to the bottom of `#save_box` (K15, K16). As in 9b's `#load_buttons`, no selector of its own is needed; E1's C4 is met by the shared rule plus C1's `max-height`.
module: s19_app/tui/styles.tcss
examples: [C4-1] (LLR-175.4h) `grep -c "#saveproject_buttons" s19_app/tui/styles.tcss` → 0; the regions of [C3-1] hold (target (11)). RED if: a `#saveproject_buttons { dock: none; }` rule is added → [C3-1]'s buttons leave the screen with `ROWS300` when the box is unbounded

R1 Save dialog parent field, Browse and the shared id (retired)
req: LLR-175.2, HLR-175e, D7, S-f
in: —
out: —
func: retired from `SaveProjectScreen`: the `default_parent` parameter and attribute; `Label("Save project folder under:")`; `OsClipboardInput#project_parent_path` with its placeholder `C:\path\to\parent\folder`; `Container#save_browse_row` and `Button#save_browse` (`Browse...`); the label `Project name (new folder name):`; the `save_browse` branch of `on_button_pressed` with its `tkinter` / `filedialog` import (`screens.py:658-671`); the strip-and-return rule of the base Save branch (P-19); `id="load_dialog"` on this screen (7 other modals keep it). The batch-31 comment about `project_parent_path` staying a stock `Input` goes with the field. `tkinter` stays imported elsewhere in `screens.py` (it is in the 9b module set), so the module census is unchanged.
module: s19_app/tui/screens.py
examples: [R1-1] (LLR-175.2) `grep -c "project_parent_path\|save_browse" s19_app/tui/screens.py` → 0; `grep -c 'id="load_dialog"' s19_app/tui/screens.py` → 7 (base 8, p11b U7) (target (11)). RED if: the Browse branch kept → 1 `save_browse` match
examples: [R1-2] (re-pin census, from baseline-notes A, B) tests naming the retired surface: `#project_parent_path` in `test_b99_staging.py` (6 nodes) and `test_tui_directionb.py:3090`; `SaveProjectScreen(tmp_path)` / `(default_parent=…)` in `test_tui_directionb.py` (`_MODAL_SPECS`, `test_tc034`) and `test_loadfilescreen_input.py:912` (target: re-pinned by the tester; count after → 0). RED if: a test still builds `SaveProjectScreen(tmp_path)` → `TypeError` at collection of that test

## Entities

[state: live]
desc: `SaveProjectScreen._live` (bool, starts `False`). Becomes `True` once, in `_first_preview`, after the first refresh. While `False`, `on_input_changed` ignores changes (the first preview reads the field anyway). It keeps the app's image decision after the first frame (LLR-175.5b).
sequence:
  write: S1 `__init__` (= False) → S4 `on_mount` → `call_after_refresh` → `_first_preview` (= True) → S5 `_recompute`
  read: S5 `on_input_changed` step 1 (!)

[state: painted plan]
desc: `SaveProjectScreen._plan` (Optional[SavePlan]). Written only by S9 `_paint`, from the preview `preview` or `confirm` returned. Read by S8 `plan`, and by S6 as the second argument of `confirm` and as the payload's `plan` and `parent_folder` source.
sequence:
  paint: S5 `_recompute` → G-B `preview(text)` → S9 `_paint` (`_plan = p.plan`) (!)
  save: S6 `action_save` → G-B `confirm(text, _plan)` → `None` → S7 `_close(payload with plan=_plan)` | a preview → S9 `_paint` (stay)

[state: recompute timer]
desc: `SaveProjectScreen._trailing` (Optional[Timer]). One trailing timer at most. Each keystroke resets it (a 150 ms debounce, S5). Stopped by `_recompute` (it is the run), by a `confirm` repaint (S6 step 3) and by `_close`.
sequence:
  change: Input.Changed → S5 (reset the timer: `set_timer(150 ms, _recompute)`)
  stop: S5 `_recompute` | S6 step 3 | S7 `_close` → `_stop_trailing` (!)

[state: shown]
desc: `SaveProjectScreen._shown` (bool, starts `False`). Set `False` in `_paint` and `True` by `_mark_shown` after the next refresh. A Save while `False` passes `None` as the painted plan, so `confirm` repaints with `the summary changed` (S11-04).
sequence:
  paint: S9 `_paint` (False) → `call_after_refresh` → `_mark_shown` (True)
  read: S6 `action_save` step 1

[state: dismissed]
desc: `SaveProjectScreen._dismissed` (bool, starts `False`). Checked first in `_close`, `action_save`, `_recompute` and `_first_preview`, so a queued Save, a pending timer or a second close after the dismiss does nothing.
sequence:
  close: S7 `_close` (if `_dismissed`: return; else `_dismissed = True`, stop the timer) → `dismiss(result)` → G-B `_handle_save_dialog(result)`

## Callers checked against the baseline extractor

| Node | Callers after Inc 11 | Baseline (`extract-baseline/extract.json`, `baseline-11.md`) | Verdict |
|---|---|---|---|
| V `SavePreview` | constructed by G-B `_save_dialog_preview` (N3) and the confirm step; read by S9 | new type, no baseline caller | consistent; 0 G-A constructors ([V-2]) |
| I1 typing import | — | — | — |
| Y `SaveProjectPayload` | S6 `action_save` (dialog); 56 direct test call lines + 1 by reference (unchanged, default `plan=None`); G-B router reads `.plan` | `[Data: SaveProjectPayload]`: built by the dialog and 11 test files | consistent; the field is additive |
| S1 `SaveProjectScreen.__init__` | G-B `action_save_project` (push, keyword form); census A tests re-pinned | `S19TuiApp.action_save_project` (direct, `app.py:7399`) | same caller, new call form (S-b) |
| S2 `compose` | framework | none listed (framework) | consistent |
| S4 `on_mount` / `_first_preview` | framework; `_first_preview` ← `call_after_refresh` only | `on_mount`: none listed (framework) | consistent; `_first_preview` new, 1 caller |
| S5 `on_input_changed` / `_recompute` / `_stop_trailing` | framework (`Input.Changed`); `_recompute` ← S4, S5, the timer, S6 step 4; `_stop_trailing` ← S5, S6, S7 | n/a (new) | consistent |
| S9 `_paint` | S5 `_recompute`, S6 step 3 | n/a (new) | consistent; the only writer of `_plan` |
| S6 `action_save` (+ `on_input_submitted`, `on_button_pressed`) | the `alt+s` binding (Textual `run_action`); `Input.Submitted`; `Button.Pressed` | `on_button_pressed`: none listed (framework) | consistent; the extractor cannot see bindings (baseline-notes "Calls the extractor cannot see") |
| S7 `action_cancel` / `_close` | the `escape` binding; S6 (`save_cancel`); `_close` ← S6, S7 only | n/a (new) | consistent |
| S8 `plan` | tests (AT-B100-21, TC-B100-65); S6 reads `_plan` directly | n/a (new) | consistent; no product reader outside the dialog |
| `_collect_composition` (unchanged code) | S6 `action_save` step 5 | `SaveProjectScreen.on_button_pressed` (direct, `screens.py:685`) | the one caller moves from the base Save branch to `action_save`; behaviour unchanged |
| `_assignment_rows_enabled` (unchanged code) | S2, `_collect_composition` | none listed (property reads) | unchanged |
| `_handle_save_dialog` (G-B) | the dismiss callback of the push in `action_save_project` | dismiss callback `:7400`, invisible to the extractor | unchanged call shape: one positional argument (S-c; `_capture_save_payload` keeps working) |

## Seams with G-B (`app.py` + `project_gather_service.py`)

| Id | Seam | G-A promise | G-B duty | Examples naming it |
|---|---|---|---|---|
| SC-1 | `preview(text)` (S-a, S-g) | first call after the first refresh (S4), then once per debounce window (S5: each keystroke resets the 150 ms timer, one recompute 150 ms after the last change); the text verbatim, also blank or spaces; synchronous; the result painted verbatim, markup off, one widget per row, rows in order | return a `SavePreview` and never raise; the first call builds the per-open session (S-d, LLR-175.5, LLR-175.5b); compose every string (target line and kind, LLR-175.1; refusals LLR-175.1a … .1m; rows LLR-175.4, .4c … .4f); for blank text decide what is live — recommended: no `name is empty` pair live (LLR-175.1h's mutant, LLR-175.3b) and session refusals may show | S4-1, S4-3, S5-1, S5-5, S5-6, S9-1, S6-6 |
| SC-2 | `confirm(text, plan)` (S-h, Q-3) | called on every Save request (`alt+s`, `enter` in the field, `#save_ok`), with the text verbatim and the painted plan object or `None`; `None` → dismiss; a preview → paint it, stop the trailing run, stay | re-prepare with the same session; refusal → refused preview (blank → `name is empty — type a project name`, Q-3); `prepared.plan != plan` → fresh preview plus `("the summary changed — check it, then save again", "refusal")`; `None` only when they are equal and `plan is not None` | S6-1, S6-4, S6-5, S6-7, S6-8, S6-9, S6-11 |
| SC-3 | the dismiss payload (S-b, Q-2, S-c) | `SaveProjectPayload(parent_folder=str(plan.target.parent), project_name=<text verbatim>, batch, assignments, plan=<painted object>)`; `None` on cancel | the router commits the confirmed prepared save when it matches the payload; `_handle_save_dialog(None)` drops the session. Identity: `payload.plan` is the painted object, not the plan `confirm` recomputed (see P-GA11-3) | S6-1, S6-2, S8-2 |
| SC-4 | construction (S-b) | keyword-only; `initial_name` prefilled and selected; `variants` / `candidate_files` meaning unchanged | push from `action_save_project` with `initial_name=` the open project's on-disk name (LLR-175.3h boundary: the on-disk case, e.g. `Ab`), `None` with no project open; import `SavePreview` from `.screens` (no `__init__.py` export needed) | S1-1, S4-2, S4-3 |
| SC-5 | priority keys (S-e) | the dialog binds none of `ctrl+l` / `ctrl+s` / `ctrl+k` / `ctrl+d`; its actions are `save` / `cancel` | `SaveProjectScreen` in the whole-stack tuple of `check_action` (LLR-175.3g). Then `ctrl+k` / `ctrl+d` reach `#project_name`'s own bindings and edit the text (K19; declared in LLR-175.3g's threshold) | S1-4 |
| SC-6 | painted text (LLR-175.4g, .4j) | no scrub, no rewrite, no cut; markup off everywhere | every name through `painted_names`; no `"\n"` inside a where line or a row (a row widget is 1 high) | S9-2, S9-3, S9-5 |
| SC-7 | `SavePlan.target` | the payload parent is `str(painted.target.parent)` | `target` is `workarea / <folder>` "as the app names it" (`SavePlan` docstring), so its parent is `self.workarea` and the router's parent check (G2–G3) passes. G-B's S-c row writes the duty as `parent_folder = str(work area)`: the same value by construction; E3 checks that no G-B path builds `target` from a resolved or re-cased parent | S6-2 |
| SC-8 | focus after close (LLR-166.1) | `dismiss` pops the screen; Textual restores the main screen's last focus | assert the TC-B100-12 arm if one is added | S7-1 |
| SC-9 | nothing loaded (LLR-175.3j) | the dialog has no state for it | never push the dialog; paint `Nothing to save` / `load a data file or A2L first` | — (G-B) |
| SC-10 | the 9b import census (TC-B100-64 arm 2) | I1 adds no module name; S5 adds no `time` (the debounce needs no clock, A11-13) | none; the orchestrator's call (P-GA11-1, rejected) | I1-1 |
| SC-11 | the variant labels in the assignment rows (Q4) | painted literally (`markup=False`, `Text` prompts) | `_variant_display_options` is unchanged, so its labels are not scrubbed (P-GA11-4) | S2-5 |

## Findings

### Design decisions taken inside the interface (no interface change)

- **D-GA11-1** The dialog paints exactly what `preview` / `confirm` return, also for blank text. It never builds a `SavePreview` and never filters a line. S-a says G-B composes every string; a dialog-side "blank → paint nothing" rule would be a second decider (LLR-175.6). The blank-text live behaviour is G-B's (SC-1).
- **D-GA11-2** `confirm` is called for every Save request: blank text (ruling Q-3), a refused painted preview, an out-of-date one. The dialog never short-circuits on `refused`, so a state that changed since the paint is always re-decided by the one preparation. `#save_ok` is never disabled (LLR-175.3f).
- **D-GA11-3** The payload's `parent_folder` is `str(painted.target.parent)`. The fixed constructor carries no work area, and the painted plan's target is `workarea / <folder>`. A dismiss without a painted plan is refused loudly (S6 step 4).
- **D-GA11-4** `#save_where` is one `Static(markup=False)` painted with a plain `Text` of the lines joined by `"\n"`, with no per-line style, so it always has 0 spans and tests can read it as plain text. A refusal shows as the class `refusal` (bold) on the whole widget when `refused` is true or any line has the kind `refusal`.
- **D-GA11-5** The summary is one `Static(markup=False)` per row inside `VerticalScroll#save_summary`, updated in place, with only the difference mounted or removed (K17). Rows then have their own regions (LLR-175.4i / .4j thresholds read row regions).
- **D-GA11-6** Debounce: each keystroke resets the 150 ms timer, and one recompute runs 150 ms after the last change (S5, ruling P-GA11-1 / A11-13); there is no leading edge and no `time` clock. A `confirm` repaint counts as a recompute and stops the trailing timer (K11).
- **D-GA11-7** The first preview runs from `call_after_refresh` in `on_mount`; changes before it are ignored (`_live`), because the first preview reads the field.
- **D-GA11-8** The assignment rows keep their ids, order and values (Q4); their labels get `markup=False` and their prompts `rich.text.Text`, so a variant or file name with brackets paints literally (LLR-175.4g: "every name … in the Save project dialog"). `Text` is already imported (`screens.py:10`).
- **D-GA11-9** Strings: title `Project name` (interface S-b), placeholder `letters, digits, - and _` (pc_B), buttons `Save (alt+s)` / `Cancel (esc)` (pc_B, LLR-175.3i) as `str` literals (no name inside, as `Load (alt+l)` in 9b).
- **D-GA11-10** Private names checked free in Textual 8.2.8 (K21); `_live` instead of `_ready` (`App._ready`).
- **D-GA11-11** No `DEFAULT_CSS` on the screen (TC-033); the 6 new rules sit in the modal block right after `.assign-list`, with tokens only.

### Design risks

finding R-GA11-1 E1's negative control for LLR-175.4h does not go RED
anchor: C3; LLR-175.4h ("mutation: `#save_summary` with `height: auto` and no scroll → the buttons are pushed below the screen"); K16
seen: with the summary unbounded but `#save_box { max-height: 90% }` kept, the docked buttons stay fully visible at 118×54; only the summary is clipped (its last row at y = 313).
cause: `.modal-buttons` is `dock: bottom` inside a box whose height is capped (the Inc 10 K9 finding again).
effect: the stated mutant passes LLR-175.4h's test; it goes RED on LLR-175.4i instead (last row unreachable).
decision: P-GA11-2 (a RED control that is executed).

finding R-GA11-2 `ctrl+k` and `ctrl+d` edit the name field under the guard
anchor: SC-5; LLR-175.3g; K19
seen: with the S-e rule, `ctrl+k` deletes right of the cursor (`abcdef` → `abc`) and `ctrl+d` deletes one character (`abcef`).
effect: no app action runs, so LLR-175.3g holds; its threshold already declares this (Textual `Input` bindings). The name changes, and the debounce repaints the plan for it.
decision: accept, as declared (9b R-GA-3).

finding R-GA11-3 Mounting 300 rows takes about 360 ms
anchor: S9 steps 5–6; LLR-175.5a ("final paint ≤ 300 ms"); K17
seen: a change from 2 to 300 rows takes 203 ms in the paint call and 360 ms until mounted; in-place updates of 300 rows take 78 ms; 300 → 2 takes 94 ms.
effect: LLR-175.5a's arm (20 keystrokes on a plan whose row count does not jump) is met (K8: 141 ms). The first time a name turns the plan into a 300-row save as, the final paint can take about 360 ms. The paint call blocks the event loop for about 200 ms at that moment.
decision: accept for Inc 11; E4 records the time in the packet (C-QA-5 style). If a test arm jumps to 300 rows inside the 300 ms window, the fix is a row pool (hide unused rows instead of removing them), local to S9.

finding R-GA11-4 The payload's plan is the painted object, not the plan `confirm` recomputed
anchor: S6 step 6; interfaces Q-2 ("the commit matches it by identity"), S-h ("keeps the prepared save for the router"); SC-3
seen: G-A sends `plan=self._plan`, the object the last `preview` / `confirm` returned. G-B's confirm compares `prepared.plan != plan` by equality, so `prepared.plan` is a new, equal object.
effect: if the router tests `prepared.plan is payload.plan`, the test fails for every dialog save and the router prepares again. The save stays correct, but the "executed = painted" identity (LLR-175.4a) and the "once per open" counts (LLR-175.5) can break.
decision: P-GA11-3 (one sentence for the interface). G-B's prototype already does it: `self._save_confirmed = replace(prepared, plan=plan)` (`proto-11-app.md`, the confirm node), and its router tests `confirmed.plan is payload.plan`. The two graphs agree; only the fixed interface text is silent.

finding R-GA11-5 The `SavePlan` typing import adds a module name in its natural form
anchor: I1; 9b `test_tc_b100_64_the_dialog_reads_nothing_itself` arm 2
seen: `SCREENS_MODULES_AT_BASE` (9b tree, `tests/test_b100_load_dialog.py:2794`) holds `.services` but not `.services.project_gather_service`; `TYPE_CHECKING` imports count (`.services.variant_execution_service` is in the set for that reason).
effect: `from .services.project_gather_service import SavePlan` turns TC-B100-64 RED at Inc 11.
decision: I1 uses `from .services import project_gather_service` (0 new names); P-GA11-1.

finding R-GA11-6 (superseded by A11-13) `import time` would add a module name to the same census
anchor: S5; TC-B100-64 arm 2
seen: `time` is not in `SCREENS_MODULES_AT_BASE`. The old throttle needed a monotonic clock; the debounce needs no clock and adds no module.
effect: none — TC-B100-64 arm 2 stays green, because S5 imports no `time`.
decision: superseded (A11-13; the P-GA11-1 clock recommendation is rejected).

finding R-GA11-7 A Save before the first frame repaints instead of saving
anchor: S6 step 2 with `_plan is None`; SC-2
seen: `confirm(text, None)` never matches (S-h).
effect: an `alt+s` typed before the first preview gets the fresh preview plus `the summary changed`; a second `alt+s` saves. Practically unreachable (the first frame comes in milliseconds), and it is the R-PC behaviour (never save a plan nobody saw).
decision: accept.

finding R-GA11-8 Assignment-row labels are literal but not scrubbed
anchor: S2 (Q4); SC-11; LLR-175.4g
seen: `variants` display labels come from `_variant_display_options` (unchanged, G-B) without `painted_names`; G-A paints them with markup off (D-GA11-8).
effect: brackets paint literally; a U+202E in a variant file name would still reach the label. LLR-175.4g's threshold arms do not cover the assignment rows.
decision: P-GA11-4 (optional, G-B).

### Undecidable points the requirements leave open (each with the recommendation the graph follows)

- **U-1** What the dialog shows for blank text before Save. Recommendation: whatever G-B's `preview` returns; G-B paints no `name is empty` pair live for blank text (SC-1).
- **U-2** The look of a refusal in `#save_where`. Recommendation: bold on the whole widget, no colour, no prefix glyph (D-GA11-4).
- **U-3** The summary's height cap. Recommendation: `max-height: 50vh` (27 rows at 54, 30 at 60; K15).
- **U-4** The title and placeholder. Recommendation: `Project name` (interface) and `letters, digits, - and _` (pc_B).

## Proposals to the orchestrator

- **P-GA11-1 (9b census, TC-B100-64 arm 2; R-GA11-5).** Inc 11's `screens.py` needs a typing-only reference to `SavePlan` (I1). The clock half below is rejected (A11-13: the 150 ms recompute is a debounce on `set_timer`, which needs no clock).
  - Typing: I1 uses `from .services import project_gather_service` inside `TYPE_CHECKING` (module name `.services`, already in the set). No test change. Alternative: `from .services.project_gather_service import SavePlan` plus `.services.project_gather_service` added to `SCREENS_MODULES_AT_BASE`. Recommendation: the first (it mirrors Inc 10's ruling P-GA10-1: keep 9b's census green with zero edits).
  - Clock: REJECTED (A11-13, P-GA11-1). The 150 ms recompute is a debounce on `set_timer`; each keystroke resets the timer, so no `time` clock is needed and no module is added. TC-B100-64 arm 2 is unchanged.
- **P-GA11-2 (requirement text, LLR-175.4h).** E1's negative control does not go RED (executed, K16). Replace it with: "a mutation that removes `max-height` from both `#save_summary` and `#save_box` → at 118×54 `#save_ok` lies at y = 305, outside the screen → RED" (executed, K16). Also sharpen "inside the visible screen region" to "fully visible: each button's region equals its clipped region, lies inside the screen region and is at least 1 high" (as Inc 10 P-GA10-2). The summary-only mutant stays useful as LLR-175.4i's second RED control (executed).
- **P-GA11-3 (interface wording, Q-2 / S-h / S-c; R-GA11-4).** State in S-h: "when `prepared.plan == plan`, G-B keeps the prepared save with its `plan` replaced by the painted object (`dataclasses.replace(prepared, plan=plan)`), so the router's `prepared.plan is payload.plan` holds." Otherwise the identity test of Q-2 never passes for a dialog save. G-A sends the painted object either way. G-B's prototype already follows this wording, so the proposal only records it in the fixed text.
- **P-GA11-4 (optional, Q4 rows; R-GA11-8).** Have G-B pass the variant display labels through `painted_names` before the push, so every name in the dialog is scrubbed, not only the summary and the target line. One line in `action_save_project`; no G-A change.
- **Interface changes adopted on our own:** none.

## Requirement coverage (G-A scope)

| Requirement | Examples (node) |
|---|---|
| HLR-175 (G-A share: target line and summary painted while open) | S4-2, S5-5, S9-1, S9-6 |
| HLR-175a (G-A share: Save dismisses the painted plan) | S6-1, S6-7, S8-2 |
| HLR-175b (G-A share: refusal painted before Save, dialog stays) | S5-6, S6-5, S6-6, C2-1 |
| HLR-175c | S7-1, S7-3 |
| HLR-175d (G-A share: empty Save asks the preparation, stays) | S6-4 |
| HLR-175e (G-A share: no parent field; parent = work area) | S2-2, S6-2 |
| HLR-175f (G-A share: one dialog, 5 ids, focus, layout) | S2-1, S4-4, C1-1 |
| LLR-175.1 (G-A share: the line painted on change) | S5-5 |
| LLR-175.1a, .1b, .1d, .1k, .1m (G-A share: painted before Save, Save stays) | S6-6 |
| LLR-175.1c (G-A share) | S6-5, S9-3 |
| LLR-175.1e, .1f, .1g, .1j, .1l (G-A share: same mechanism as S6-6) | S6-6, S6-5 |
| LLR-175.1h (G-A share: painted live, not only on Save) | S5-6 |
| LLR-175.1i (G-A share: 0 rows under a plan refusal) | S9-4, S8-3 |
| LLR-175.2 | S2-2, R1-1 |
| LLR-175.2a (G-A share) | S6-2 |
| LLR-175.3 | S7-1 |
| LLR-175.3a | S7-2 |
| LLR-175.3b (G-A share) | S6-4 |
| LLR-175.3c (G-A share) | S6-1, S6-3 |
| LLR-175.3d | S4-4, S1-4 |
| LLR-175.3e | S1-5, S1-4 |
| LLR-175.3f | S6-5 |
| LLR-175.3g (G-A share: binds none of the 4 keys) | S1-4 (bindings list), seam SC-5 (K19) |
| LLR-175.3h (G-A share: prefill selected) | S4-2, S4-3 |
| LLR-175.3i | S2-3, S6-1 (`alt+s` pressed), S7-1 (`escape` pressed) |
| LLR-175.4 (G-A share: one row widget per row, in order) | S9-1, S2-6, S9-9 |
| LLR-175.4a (G-A share: payload carries the painted object) | S6-1, S8-2 |
| LLR-175.4b (G-A share) | S6-7, S6-8, S6-12 |
| LLR-175.4c, .4d, .4e, .4f (G-A share: rows painted verbatim) | S9-6 |
| LLR-175.4g (G-A share: markup off) | S9-2, S9-3, S2-5 |
| LLR-175.4h | C3-1, C3-3b, C1-1, C4-1 |
| LLR-175.4i | C3-2, S2-7 |
| LLR-175.4j (G-A share: rows never wrap) | S9-5, C3-3 |
| LLR-175.4k | S8-1, S8-3 |
| LLR-175.4l (G-A share: the payload field defaults to `None`) | Y-1 |
| LLR-175.5 (G-A share: one preview at open, none while idle) | S4-5 |
| LLR-175.5a | S5-1, S5-2, S5-3, S5-4 |
| LLR-175.5b (G-A share: first preview after the first refresh) | S4-1, S1-2 |
| LLR-175.6 (G-A share: the dialog decides nothing) | S2-6, S6-11, V-2 |
| LLR-173.7 (TC-B100-66 extension, G-A strings) | S2-4 |
| interfaces Q-2 (payload field) | Y-2 |
| interfaces S-b guard (`_dismissed`) | S7-4, S7-5 |
| TC-B100-64 arm 2 (9b census) | I1-1, I1-2 |

**Seams: requirements owned by G-B, with no G-A node or only a G-A share already covered above.**
- LLR-175.1a … LLR-175.1m: the refusal rules, their order and texts (`_prepare_project_save`, SC-1, SC-2).
- LLR-175.1n: withdrawn (E2-rulings); no example in either group.
- LLR-175.3g: `check_action` (SC-5).
- LLR-175.3j: `action_save_project` with nothing loaded (SC-9).
- LLR-175.4, .4c, .4d, .4e, .4f: the row composition (SC-1, SC-6).
- LLR-175.4a, LLR-175.4l: the router and the commit (SC-3; P-GA11-3).
- LLR-175.5: the per-open session (S-d).
- LLR-175.6: the one preparation and its AST census over `app.py`.
- LLR-166.1: focus after close (SC-8).

G-A requirements without an example: 0.
