# Code-Wire prototype — Inc 9b, group G-A (`screens.py` + `styles.tcss`)

Stage E2 of the design-first pipeline for Inc 9b ("the Load dialog"). This is the graph only. Nothing in `s19_app/` changes, and the 9a worktree `C:\Users\jjgh8\Github\s19_app-b100-inc9a` stays read-only. New code is a node whose `func:` starts with "new". The shared interfaces are those in `interfaces-9b.md` (fixed). This group changes none of them; the one scope change it proposes is under "Proposals". G-B (`app.py`) writes its prototype in parallel. The seams are listed under "Seams with G-B".

**Base and inputs.**
- Code: the 9a tree (`4fef292`; `screens.py` and `styles.tcss` are byte-identical there). `LoadFileScreen` is at `screens.py:184-227`, `LoadProjectScreen` at `screens.py:696-735`. The shared modal rules are at `styles.tcss:1576-1597`, `:1732-1765`. `OsClipboardInput` is at `os_clipboard_input.py:432`.
- Requirements: `../E1-requirements-draft.md` §A, §B. LLR-173.2m is dropped (ruling Q8).
- Slice: `../E1-scope.md` §3 (S1–S9, R1, R2, C1–C4). Rulings: `../E1-rulings.md` (Q1–Q10).
- Textual: 8.2.8 (`importlib.metadata.version("textual")` in `s19env`).

**Probe p9b-ga (executed in this session).** Run with Python `s19env`, `python -I`, Textual 8.2.8, `App.run_test`. The scripts are in `scratchpad\probe-9b-ga\` (`probe.py`, `probe2.py`, `probe3.py`) and import no repository code. `probe3.py` is a throwaway skeleton of this graph (S1–S9, C1–C4), used to check the steps. It is not a stub and never goes into the repository. The examples use these facts:
- **K1.** `OptionList.__init__` calls `action_first()` only when options are passed at construction (`_option_list.py:297-299`). `add_options` leaves `highlighted = None`.
- **K2.** `up` / `down` skip disabled options (`find_next_enabled`). Setting `highlighted` to a disabled index by code keeps that index and posts no `OptionHighlighted` (`watch_highlighted`, `:929-937`).
- **K3.** A click on an enabled option sets `highlighted` and calls `action_select()`, so it posts the same `OptionSelected` that `enter` posts (`_on_click`, `:721-730`).
- **K4.** A `Key` event reaches the screen's `on_key` (it bubbles from the focused widget) before the non-priority bindings are checked (`App._on_key` → `_check_bindings`, `app.py:4341-4343`). So `event.stop()` in `LoadDialog.on_key` stops `OptionList`'s `enter` binding. Probe: with the intercept, `enter` on the list posts 0 `OptionSelected`; without it, it posts 1.
- **K5.** A printable key with the list focused, redirected in the screen's `on_key`, lands in `#load_path`, and no app binding runs. The stack depth stays 2 for `p`, `l`, `q`, `s`, `r` and `?`.
- **K6.** An app `priority=True` binding (`ctrl+l`) runs while a modal is open. It does not run once `App.check_action` returns `False` for it. This is a scratch app, not `S19TuiApp`; it informs LLR-173.2e (seam SA-5).
- **K7.** The focus chain follows DOM order: `#load_path`, `#load_list`, `#load_preview` (a `VerticalScroll`, focusable even when empty), `#load_ok`, `#load_cancel`, and wraps back to `#load_path`. `shift+tab` gives the reverse.
- **K8.** `OptionList(markup=False)` with `str` prompts paints `[b]P` and `[@click=app.bell]Q` literally, with 0 spans. A `Static(markup=False)` updated with `rich.text.Text` paints `[b]v.s19` literally, with 0 spans.
- **K9.** With `#load_list { text-wrap: nowrap; text-overflow: ellipsis; }` a 120-character row is 1 line high at 99 columns. Without that rule the same row is 2 lines high (the LLR-173.6n mutant).
- **K10.** The screen gets `on_resize` on a terminal resize. With the C1–C4 rules at 54 rows the regions are:
  - 99 cols: stacked; `#load_list` (5, 10, 89, 15); `#load_preview` (5, 25, 89, 19).
  - 100 cols: side by side; list (5, 10, 45, 34); preview (50, 7, 45, 37).
  - 118 cols: side by side; list (5, 10, 53, 34); preview (58, 7, 54, 37); `#load_box` (2, 3, 113, 48).
  - A live resize from 118 to 99 → stacked.
- **K11.** `MessagePump` owns `self._closed` and `self._closing` (11 and 9 uses in `message_pump.py` / `dom.py` / `widget.py` / `screen.py`). A dialog attribute named `_closed` made a `dismiss` fired from a binding (`escape`, `alt+l`) hang forever. Renamed `_dismissed`, the same scenarios pass. See R-GA-1.
- **K12.** `Screen.AUTO_FOCUS` falls back to the app's `"*"`, so in list mode `#load_path` gets the focus first and `on_mount` then moves it to `#load_list`. Two `DescendantFocus` events arrive (path, then list). The final focus and source are `#load_list` / `list`, and exactly 1 preview request is made.

**Fixtures used by the examples** (each is the return value of the `rows` callable; labels are already painted by G-B):
- `ROWS_A` = index 0 `("projects", "Projects", None)` · 1 `("projects", "ab", LoadChoice("project", "ab"))` · 2 `("projects", "cd", LoadChoice("project", "cd"))` · 3 `("workarea", "Work area", None)` · 4 `("workarea", "a.s19", LoadChoice("workarea", "a.s19"))` · 5 `("workarea", "c.a2l", LoadChoice("workarea", "c.a2l"))` · 6 `("recent", "Recent", None)` · 7 `("recent", "fw.s19 (s19)", LoadChoice("recent", "C:\src\fw.s19"))`.
- `ROWS_EMPTY` = `Projects`(h) · `no projects — ctrl+s saves a project`(None) · `Work area`(h) · `no work-area files — l loads a file`(None) · `Recent`(h) · `no recent sources`(None). Six rows, all with choice `None`.
- `ROWS_FILEONLY` = `Projects`(h) · `no projects — ctrl+s saves a project`(None) · `Work area`(h) · `x.s19` → `LoadChoice("workarea", "x.s19")` (index 3).
- `ROWS_LONG` holds one row of each kind:
  - project label `P`×119 + `…`, value `P`×130;
  - file label `f`×119 + `…`, value `f`×130 + `.s19`;
  - recent label `r`×120 + ` (s19)`, value `C:\` + `r`×296 + `.s19`.
- `ROWS_MANY` = `Projects`(h) + 20 project rows `p00` … `p19`.
- `ROWS_HOSTILE` = `Projects`(h) · `[b]P` → `LoadChoice("project", "[b]P")` · `[@click=app.bell]Q` → `LoadChoice("project", "[@click=app.bell]Q")`.
- `V` = a verdict fake that records each call and returns `None`. `V_REFUSE(pair)` returns `pair` for every call.
- `P` = a preview fake that records `choice` and returns `[(f"{kind}:{value}", True), ("note", False)]` (synchronous; there is no `deliver`).
- "Painted" text = the plain text of the widget's visual: `str(widget.visual)` for a `Static`, `str(option.prompt)` for an option.

**Counts.**
- **16 nodes:** 9 code nodes (S1 one data type plus 3 type aliases; S2–S9 eight method groups of the new `LoadDialog`), 4 selector groups (C1–C4), 2 retirement nodes (R1, R2) and 1 re-export node (PSC-1).
- 2 entities, 104 example lines.
- 9 design decisions (D-GA-1, D-GA-2, D-GA-4 … D-GA-10), 8 risks (R-GA-1, R-GA-3 … R-GA-9), 9 seams (SA-1 … SA-9).
- 1 scope change (PSC-1, accepted) and 0 proposed interface changes.
- G-A requirements without an example: 0 (table at the end).

## Nodes

LoadChoice
req: LLR-173.1, LLR-173.3d, HLR-173b, HLR-173c
in: LoadKind kind; str value
out: LoadChoice choice
func: new, `@dataclass(frozen=True)` at `screens.py` module level, after `SaveProjectPayload` (S-a, fixed). It comes with three new module-level aliases:
  - `LoadKind = Literal["project", "workarea", "recent", "path"]`;
  - `LoadRow = tuple[str, str, Optional[LoadChoice]]` (S-c);
  - `PreviewLine = tuple[str, bool]` (S-d).
  `value` is always `str`: the on-disk project name, the on-disk work-area file name, the recorded path text, or the typed text. There is no runtime check on `kind`. The only producers are G-B's `rows` (three kinds) and `LoadDialog` (`path`, from the field). Equal by value, hashable, immutable. `typing.Literal` / `Callable` come from `typing`, which `screens.py` already imports, so no new module is added (LLR-173.6l).
module: s19_app/tui/screens.py
examples: [S1-1] (LLR-173.1) `LoadChoice("project", "ab") == LoadChoice("project", "ab")` → `True`; `hash` equal; `{LoadChoice("path", "x")}` has 1 element after adding it twice (target (9b))
examples: [S1-2] (LLR-173.1) `c = LoadChoice("recent", "C:\src\fw.s19"); c.value = "y"` → raises `dataclasses.FrozenInstanceError`; `c.value` still `C:\src\fw.s19` (target (9b))
examples: [S1-3] (LLR-173.1, LLR-173.3d) `LoadChoice("workarea", "a" + "\x9b" + "S.s19").value` → the same 7 characters, U+009B kept. The type holds the on-disk name; painting is G-B's (target (9b))
examples: [S1-4] (LLR-173.1, HLR-173b) the 4 kinds `project`, `workarea`, `recent`, `path` construct; `repr(LoadChoice("path", "C:\t\a.s19"))` → `LoadChoice(kind='path', value='C:\\t\\a.s19')` (probe p9b-ga) (target (9b))

LoadDialog.__init__ / compose
req: HLR-173, LLR-173.2c, LLR-173.3, LLR-173.3a, LLR-173.3b, LLR-173.3c, LLR-173.6l, LLR-173.7
in: mode: Literal["path","list"]; highlight: Optional[str]; rows: Callable[[], list[LoadRow]]; verdict: Callable[[LoadChoice], Optional[tuple[str,str]]]; preview: Callable[[LoadChoice], list[PreviewLine]]
out: LoadDialog (a `ModalScreen[Optional[LoadChoice]]`)
func: new (S-b, fixed signature, keyword-only).
  - **`__init__`** calls `super().__init__()` and stores the five arguments as `_mode`, `_highlight`, `_rows_fn`, `_verdict`, `_preview_fn`. It sets `_rows: list[LoadRow] = []`, `_source = mode` (`"path"` / `"list"`; S-f) and `_dismissed = False`. These names are checked free in Textual 8.2.8; never `_closed` / `_closing` (K11, R-GA-1). It calls none of the callables: `rows` is called in S3.
  - **`BINDINGS`** = `[Binding("escape", "cancel", show=False), Binding("alt+l", "load", show=False, priority=True)]`.
  - **`compose`** yields one tree in this DOM order (the order is the `tab` order, K7):
    - `Container(id="load_box", classes="modal-dialog")` holding:
      - `Label("Load", classes="modal-title")`;
      - `Horizontal(id="load_panes")` holding:
        - `Container(id="load_left")` holding `OsClipboardInput(placeholder="C:\path\to\file.s19, .hex, .mac, .a2l, or a project folder", id="load_path", restrict=r"[^\x00-\x1f\x7f]*")` (the same class as today's `#load_path`, so Windows `ctrl+v` keeps working, R-GA-7; the `restrict=` rejects C0 control characters U+0000–U+001F and U+007F, S9b-4) and `OptionList(id="load_list", markup=False)`, empty;
        - `VerticalScroll(Static("", markup=False), id="load_preview")`. This is focusable, and `up` / `down` / `pageup` / `pagedown` scroll a long preview (D-GA-6).
      - `Static("", id="load_reason", markup=False)`;
      - `Container(Button("Load (alt+l)", id="load_ok", classes="modal-confirm"), Button("Cancel (esc)", id="load_cancel"), id="load_buttons", classes="modal-buttons")`.
  - **Module constants (new):**
    - `LOAD_NOTHING_SELECTED = ("nothing selected", "pick a row or type a path")`;
    - `LOAD_MARK = "● "` (U+25CF U+0020).
  - The class references nothing from `s19_app.tui.services.*`, `s19_app.tui.workspace`, `os` or `pathlib` (LLR-173.6l). `Path` stays a module import used by other classes, but the dialog never names it.
  - Every widget used is already imported by `screens.py` (`Container`, `Horizontal`, `VerticalScroll`, `Label`, `Static`, `Button`, `OsClipboardInput`). `OptionList` comes from `textual.widgets`, which is already imported. `Option` is not imported (D-GA-4). So there are 0 new modules.
module: s19_app/tui/screens.py
examples: [S2-1] (HLR-173) `LoadDialog(mode="list", highlight=None, rows=lambda: ROWS_A, verdict=V, preview=P)` pushed at 118×54 → exactly 1 each of `#load_box`, `#load_panes`, `#load_left`, `#load_path`, `#load_list` (an `OptionList`), `#load_preview`, `#load_reason`, `#load_buttons`, `#load_ok`, `#load_cancel`; the stack depth is 2 (probe p9b-ga) (target (9b))
examples: [S2-2] (HLR-173, LLR-173.7) painted text: the title `Load`; the `#load_path` placeholder `C:\path\to\file.s19, .hex, .mac, .a2l, or a project folder`; `#load_ok` `Load (alt+l)`; `#load_cancel` `Cancel (esc)`; `#load_reason` `` (empty); `#load_preview` `` (empty) (target (9b))
examples: [S2-3] (LLR-173.7) the regexes `\bD\d+\b`, `\bO-\d+`, `VS-`, `LLR-`, `HLR-` over the 6 G-A strings of [S2-2] plus `LOAD_NOTHING_SELECTED` and `LOAD_MARK` → 0 matches (target (9b))
examples: [S2-4] (LLR-173.2c, probe p9b-ga K7) focus on `#load_path`, then 5 × `tab` → `load_list`, `load_preview`, `load_ok`, `load_cancel`, `load_path` (5 of 5); from `#load_path`, 5 × `shift+tab` → `load_cancel`, `load_ok`, `load_preview`, `load_list`, `load_path` (5 of 5) (target (9b))
examples: [S2-5] (LLR-173.2c negative control) a mutant whose preview is a plain `Static(id="load_preview")` (not focusable) → the 2nd `tab` from `#load_path` lands on `load_ok` → RED (target (9b))
examples: [S2-6] (LLR-173.6l) AST census of the `LoadDialog` class body → 0 `Name` / `Attribute` nodes bound to imports from `s19_app.tui.services`, `s19_app.tui.workspace`, `os`, `pathlib` (`Path` included); the set of modules `screens.py` imports equals the 9a set (0 new) (target (9b))
examples: [S2-7] (LLR-173.6l negative control) a mutant whose `compose` calls `list_workarea_files(...)` → census 1 and 1 new import (`from .workspace import list_workarea_files`) → RED; a mutant using `from textual.widgets.option_list import Option` → 1 new module → RED (D-GA-4) (target (9b))
examples: [S2-8] (S-b) `LoadDialog(...)` with spies as the 3 callables → 0 calls during `__init__`; `rows` called exactly once, at mount (target (9b))
examples: [S2-9] (A9b-01, LLR-173.2f / LLR-173.2g) posted `events.Key("alt+l", character="l")` (the terminal / xterm shape; Pilot builds `character=None` for a modifier, so Pilot cannot show this) with the focus on `#load_path` holding a valid typed path → the load runs and 0 characters are typed into the field. Test note for E4: E4 posts `events.Key("alt+l", character="l")` directly (target (9b))
examples: [S2-10] (S9b-4) pasted clipboard text `a\x00.s19` into `#load_path` → the field holds `a.s19` (the NUL is rejected by `restrict=` in `Input.replace`), 0 raises (target (9b))

LoadDialog.on_mount
req: LLR-173.2, LLR-173.2a, LLR-173.2b, LLR-173.4l, LLR-173.4d, LLR-173.4e, LLR-173.4f, LLR-173.4g, LLR-173.3, LLR-173.3a, LLR-173.3b, LLR-173.6m
in: (self) `_rows_fn`, `_highlight`, `_mode`
out: list filled; highlight set; focus set; panes class set
func: new. Steps:
  1. `self._rows = list(self._rows_fn())`. Called once. G-B never raises from it (SA-1).
  2. `lst = query_one("#load_list", OptionList)`, then `lst.add_options([label for _s, label, _c in self._rows])`. The order is kept exactly as given, with no sort or filter (LLR-173.4l, G-A share). The prompts are `str` and the list was built with `markup=False`, so nothing is parsed (K8; LLR-173.3, LLR-173.3a, LLR-173.3b, G-A share).
  3. For each `i` with `self._rows[i][2] is None`, call `lst.disable_option_at_index(i)`. Headings and empty / problem token lines are then disabled: they cannot be highlighted by key or click, and cannot be loaded (K2, K3; LLR-173.4d, LLR-173.4e, LLR-173.4f, LLR-173.4g, LLR-173.4l, G-A share).
  4. `lst.highlighted = self._initial_index()`. `add_options` left it `None` (K1). `_initial_index` (new helper) returns the first match of:
     - (a) a row whose choice is `kind == "project" and value == _highlight`;
     - (b) the first row of kind `project`;
     - (c) the first row with a choice;
     - (d) `None`.
     The same rule applies in both modes (D-GA-9).
  5. `query_one("#load_list" if _mode == "list" else "#load_path").focus()` (K12).
  6. `self._apply_stack(self.app.size.width)` (S9).
  Setting `highlighted` posts `OptionHighlighted`, and the focus posts `DescendantFocus`. Both are handled in S7, which makes exactly 1 preview request in list mode and 0 in path mode (the field is empty).
module: s19_app/tui/screens.py
examples: [S3-1] (LLR-173.2b, probe p9b-ga) `mode="list"`, `highlight="cd"`, `ROWS_A` → `focused.id == "load_list"`, `highlighted == 2`, highlighted prompt `cd` (target (9b))
examples: [S3-2] (LLR-173.2b) `mode="list"`, `highlight=None`, `ROWS_A` → `highlighted == 1` (`ab`) (probe p9b-ga) (target (9b))
examples: [S3-3] (LLR-173.2b) `mode="list"`, `highlight="gone"` (not listed), `ROWS_A` → `highlighted == 1` (`ab`) (target (9b))
examples: [S3-4] (LLR-173.2b, LLR-173.2a 0-project arm) `mode="list"`, `ROWS_FILEONLY` → `highlighted == 3`, prompt `x.s19`; the painted row 1 is `no projects — ctrl+s saves a project`, disabled (probe p9b-ga) (target (9b))
examples: [S3-5] (LLR-173.2b negative control) a mutant that always sets `highlighted = 0` → [S3-1] highlights `Projects` (index 0) → RED; a mutant that keeps `None` → [S3-1] `highlighted is None` → RED (target (9b))
examples: [S3-6] (LLR-173.2, LLR-173.2a, G-A share) `mode="path"` → `focused.id == "load_path"`; `mode="list"` → `focused.id == "load_list"` (2 of 2, probe p9b-ga) (target (9b))
examples: [S3-7] (LLR-173.2 negative control) a mutant that focuses `#load_list` in both modes → `mode="path"` gives `load_list` → RED (target (9b))
examples: [S3-8] (LLR-173.4l, G-A share) `ROWS_A` → the 8 painted prompts in order `Projects`, `ab`, `cd`, `Work area`, `a.s19`, `c.a2l`, `Recent`, `fw.s19 (s19)`; `options[i].disabled` is `True` exactly for i ∈ {0, 3, 6} (target (9b))
examples: [S3-9] (LLR-173.4l negative control) a mutant that sorts the labels → `Projects` is no longer index 0 → RED (target (9b))
examples: [S3-10] (LLR-173.4d, LLR-173.4e, LLR-173.4f, G-A share) `ROWS_EMPTY` → 6 options, all disabled; `highlighted is None`; `down` → `highlighted` stays `None` (K2) (target (9b))
examples: [S3-11] (LLR-173.4g, G-A share) the rows `Recent`(h), `too large — the next load starts a new list`(None) → that line painted literally and disabled (target (9b))
examples: [S3-12] (LLR-173.3, LLR-173.3a, LLR-173.3b, G-A share, probe p9b-ga K8) `ROWS_HOSTILE` → prompts `[b]P` and `[@click=app.bell]Q`, each visual with 0 spans; a click on the `[@click=app.bell]Q` row → 0 `app.bell` calls (target (9b))
examples: [S3-13] (LLR-173.3 negative control) a mutant that builds the list with `OptionList(id="load_list")` (markup on) → `[b]P` painted as `P` with 1 bold span → RED (target (9b))

LoadDialog.on_key
req: LLR-173.2d, HLR-173c, LLR-173.2f
in: events.Key event
out: none (side effects: focus, field text, a load request)
func: new. Keys reach it from the focused descendant before any non-priority binding (K4). Steps:
  1. `f = self.focused`. If `None`, return.
  2. If `event.key == "escape"`: call `event.stop()`, `event.prevent_default()`, then `self.action_cancel()` and return. Escape is taken here, at the same hop as `enter`, so queued `escape`, `enter` keep their arrival order (A9b-06); the screen's `escape` binding stays as the fallback.
  3. If `event.key == "enter"` and `f.id` is `"load_list"` or `"load_preview"`: call `event.stop()`, `event.prevent_default()`, then `self.action_load()` and return. This stops `OptionList`'s own `enter` → `OptionSelected`, so the dialog loads on `enter` and never on `OptionSelected`, which a click also posts (K3; D-GA-1). `enter` on the preview loads what the last of list / path names (HLR-173c boundary).
  4. If `f.id == "load_list"` and `event.is_printable`: call `event.stop()` and `event.prevent_default()`. Then `inp = query_one("#load_path")`, `inp.value = inp.value + event.character`, `inp.cursor_position = len(inp.value)`, `self._source = "path"`, `self._schedule_preview(None)` (A9b-R2-2: the preview clears when a printable key moves the source to the path field), `inp.focus()`. The redirect is itself the decision, so `_source` changes at once, before the focus message lands (A9b-06).
  5. Otherwise, do nothing: `up`, `down`, `home`, `end`, `pageup`, `pagedown` and `tab` keep their bindings. `enter` on a button keeps the button's own press.
  `#load_path` handles printable keys itself, and `Input` stops them (`check_consume_key`), so step 4 never sees typing in the field.
module: s19_app/tui/screens.py
examples: [S4-1] (LLR-173.2d, probe p9b-ga K5) list focused, field empty; each of `p`, `l`, `q`, `s`, `r`, `?` (`question_mark`) → `focused.id == "load_path"`, the field text is that one character, the stack depth stays 2, 0 app actions (6 of 6) (target (9b))
examples: [S4-2] (LLR-173.2d) list focused; `down`, `up`, `tab` → the field text stays `` and the focus is `load_list`, `load_list`, `load_preview` respectively; `enter` → the load path of S5, not the field (4 of 4, probe p9b-ga) (target (9b))
examples: [S4-3] (LLR-173.2d) field `C:\t`, list focused, `x` → field `C:\tx`, cursor at 5, focus `load_path` (target (9b))
examples: [S4-4] (LLR-173.2d negative control) a mutant without step 4 → `p` leaves the field `` → RED. Declared: the "0 app actions" arm holds on the mutant too, because a modal stops the app's non-priority bindings (K5) (target (9b))
examples: [S4-5] (LLR-173.2f, HLR-173c, probe p9b-ga K4) `ROWS_A`, list mode (row 1 highlighted), `down`, `down`, `enter` → the verdict is called once with `LoadChoice("workarea", "a.s19")` and the dismiss value is `LoadChoice("workarea", "a.s19")`; 0 `OptionSelected` reach the screen (target (9b))
examples: [S4-6] (LLR-173.2j negative control, D-GA-1) a mutant that drops step 3 and loads in `on_option_list_option_selected` → a single click on row 2 dismisses → RED ([S7-4]) (target (9b))
examples: [S4-7] (HLR-173c boundary) list mode (`ab` highlighted), focus moved to `#load_preview` by `tab`, `enter` → dismiss `LoadChoice("project", "ab")` (probe p9b-ga) (target (9b))
examples: [S4-8] (A9b-06a) list focused, field empty; the keys `C`, `enter` queued while the loop is busy → step 4 sets `_source = "path"` at once, so the `enter` loads `LoadChoice("path", "C")`, not the highlighted row (target (9b))
examples: [S4-9] (A9b-06b) list mode (`ab` highlighted); `escape`, `enter` queued → `escape` is handled first (step 2) and closes with `None`; the later `enter` reaches a dismissed dialog → 0 loads, 0 exceptions (A9b-02's guard) (target (9b))
examples: [S4-10] (A9b-R2-2) list mode (`ab` previewed, `● project:ab` painted); press `C` → step 4 sets `_source = "path"` and calls `_schedule_preview(None)` → the preview body is empty, and `P` is called `0` more times (target (9b))

LoadDialog.action_load (+ on_input_submitted, on_button_pressed `#load_ok`)
req: HLR-173c, HLR-173d, LLR-173.2f, LLR-173.2g, LLR-173.2h, LLR-173.2i, LLR-173.3d, LLR-173.4k, LLR-173.5, LLR-173.5a, LLR-173.5b, LLR-173.5c, LLR-173.5d, LLR-173.5e, LLR-173.4d, HLR-173b
in: (self) `_source`, `#load_list.highlighted`, `#load_path.value`
out: either `dismiss(choice)`, or `#load_reason` painted with the dialog left open
func: new. There are 4 triggers, and each calls `action_load()`:
  - `enter` in the list or the preview (S4 step 3);
  - `enter` in `#load_path` (`on_input_submitted`: `if event.input.id == "load_path": event.stop(); self.action_load()`);
  - `alt+l` from any focus (the screen binding);
  - `#load_ok` (`on_button_pressed`: `event.stop()`; `load_ok` → `action_load()`, `load_cancel` → `action_cancel()`), activated by click or by `enter` on the button.
  Steps:
  0. `if self._dismissed: return` (A9b-R2-6: a second queued load request skips the verdict and the `_say`, so a dismissed dialog is never written to).
  1. `choice = self._row_choice() if self._source == "list" else self._path_choice()`.
     - `_row_choice()` (new helper): `i = #load_list.highlighted`; returns `None` if `i is None`, else `self._rows[i][2]`. That is the very `LoadChoice` object G-B built, never one rebuilt from the label (LLR-173.3d).
     - `_path_choice()` (new helper): `t = #load_path.value`; returns `None` if `t.strip() == ""`, else `LoadChoice("path", t)`, with `t` verbatim and not stripped (S-a "typed text (verbatim)"; R-GA-6).
  2. `choice is None` → `self._say(*LOAD_NOTHING_SELECTED)` and return. This covers an empty field when the field is the source (LLR-173.2h), and no highlighted row or a disabled row when the list is the source (LLR-173.2i, LLR-173.4d). No dismiss.
  3. `pair = self._verdict(choice)`. It is called for every kind; G-B returns `None` for `project` / `workarea` (D-GA-5). If `pair is not None` → `self._say(*pair)` and return. The dialog stays open and `#load_path.value` is not touched (HLR-173d, LLR-173.4k, LLR-173.5 … LLR-173.5e).
  4. Otherwise `self._close(choice)` (S6).
  `_say(reason, step)` (new helper) does `query_one("#load_reason", Static).update(f"{reason} — {step}")`: one U+2014 with a space on each side, markup off (D-GA-8). It is the only writer of `#load_reason`. Nothing clears it except the next `_say` (R-GA-4).
module: s19_app/tui/screens.py
examples: [S5-1] (LLR-173.2g, HLR-173c, probe p9b-ga) path mode, typed `C:\t\a.s19`, `enter` → `V` called once with `LoadChoice("path", "C:\t\a.s19")`; dismiss `LoadChoice("path", "C:\t\a.s19")`; stack depth 1 (target (9b))
examples: [S5-2] (LLR-173.2g) the same text with `alt+l` → the same dismiss; with a click on `#load_ok` → the same dismiss (3 of 3 with [S5-1], probe p9b-ga) (target (9b))
examples: [S5-3] (LLR-173.2g boundary) path mode with `ROWS_A` (row 1 `ab` highlighted while the field is the source), typed `C:\t\a.s19`, `enter` → dismiss `LoadChoice("path", "C:\t\a.s19")`, not `ab` (target (9b))
examples: [S5-4] (LLR-173.2g negative control) a mutant that always takes the highlighted row → [S5-3] dismisses `LoadChoice("project", "ab")` → RED (target (9b))
examples: [S5-5] (LLR-173.2f boundary, probe p9b-ga) path mode, typed `C:\x.s19`, `tab` (into the list, `ab` highlighted), `enter` → dismiss `LoadChoice("project", "ab")` (target (9b))
examples: [S5-6] (LLR-173.2f) list mode, the 3 triggers × 3 highlighted rows (`cd` row 2, `c.a2l` row 5, `fw.s19 (s19)` row 7): `enter` / `alt+l` / `#load_ok` → 9 dismisses with `LoadChoice("project", "cd")`, `LoadChoice("workarea", "c.a2l")`, `LoadChoice("recent", "C:\src\fw.s19")` (9 of 9) (target (9b))
examples: [S5-7] (LLR-173.2f negative control) a mutant that always takes the field → [S5-6] dismisses nothing (the field is empty: the `nothing selected` pair) → RED (target (9b))
examples: [S5-8] (LLR-173.2h, HLR-173d, probe p9b-ga) path mode, field `` then `enter` → `#load_reason` painted `nothing selected — pick a row or type a path`, field ``, stack depth 2; field `   ` (3 spaces) then `enter` → the same painted text, field `   ` (2 of 2), `V` 0 calls (target (9b))
examples: [S5-9] (LLR-173.2h negative control) a mutant that `return`s silently on empty text (today's `LoadFileScreen`, `screens.py:224-225`) → `#load_reason` `` → RED (target (9b))
examples: [S5-10] (LLR-173.2i, probe p9b-ga) list mode with `ROWS_EMPTY`, `enter` → `nothing selected — pick a row or type a path`, stack depth 2, `V` 0 calls (target (9b))
examples: [S5-11] (LLR-173.2i, LLR-173.4d, G-A share, probe p9b-ga) list mode with `ROWS_A`, `#load_list.highlighted = 0` (the heading, set by code: K2), `enter` → `nothing selected — pick a row or type a path`, 0 dismisses; the same with `highlighted = 1` in `ROWS_FILEONLY` (the `no projects` line) (2 of 2) (target (9b))
examples: [S5-12] (LLR-173.2i negative control) a mutant that dismisses with `LoadChoice("project", <label>)` when the choice is `None` → [S5-11] dismisses `LoadChoice("project", "Projects")` → RED (target (9b))
examples: [S5-13] (LLR-173.5, probe p9b-ga) path mode, `V_REFUSE(("not found", "check the path"))`, typed `C:\t\missing.s19`, `enter` → `#load_reason` `not found — check the path`; field `C:\t\missing.s19`; stack depth 2; `V` 1 call (target (9b))
examples: [S5-14] (LLR-173.5a) `V_REFUSE(("not a supported file", "check the path"))`, typed `C:\t\notes.txt` → `not a supported file — check the path`, field `C:\t\notes.txt`, 0 dismisses (target (9b))
examples: [S5-15] (LLR-173.5b) `V_REFUSE(("not a project", "pick a project in the list"))`, typed `C:\wa\temp` → `not a project — pick a project in the list`, field kept, 0 dismisses (target (9b))
examples: [S5-16] (LLR-173.5c) `V_REFUSE(("outside the work area", "copy the folder into the work area"))`, typed `C:\t\P` → `outside the work area — copy the folder into the work area`, 0 dismisses (target (9b))
examples: [S5-17] (LLR-173.5d) `V_REFUSE(("link or junction", "pick a project in the list"))`, typed `C:\wa\jx` → `link or junction — pick a project in the list`, 0 dismisses (target (9b))
examples: [S5-18] (LLR-173.5e) `V_REFUSE(("could not be read", "check that the folder can be opened, then load again"))`, typed `C:\wa\ab` → `could not be read — check that the folder can be opened, then load again`, 0 dismisses, 0 raises (target (9b))
examples: [S5-19] (LLR-173.5 … LLR-173.5e negative control) a mutant that dismisses before calling `verdict` → [S5-13] dismisses `LoadChoice("path", "C:\t\missing.s19")` and `#load_reason` stays `` → RED (target (9b))
examples: [S5-20] (LLR-173.4k, HLR-173b, G-A share) list mode, `ROWS_A`, row 7 highlighted, `V_REFUSE(("not found", "check the path"))`, `enter` → `V` called with `LoadChoice("recent", "C:\src\fw.s19")`; `#load_reason` `not found — check the path`; 0 dismisses (target (9b))
examples: [S5-21] (HLR-173b, G-A share) list mode, row 7 highlighted, `V`, `enter` → dismiss `LoadChoice("recent", "C:\src\fw.s19")`: the recorded text, unchanged (target (9b))
examples: [S5-22] (LLR-173.3d, G-A share) `ROWS_HOSTILE`, row 1 (`[b]P`) highlighted, `enter` → the dismiss value `is` the object at `rows()[1][2]` (identity), `value == "[b]P"`; with `ROWS_LONG` row 3 → `value == "f"×130 + ".s19"` (131 + 4 characters), not the clipped label (target (9b))
examples: [S5-23] (LLR-173.3d negative control) a mutant that builds `LoadChoice(kind, label)` from the prompt → [S5-22]'s `ROWS_LONG` arm dismisses `f`×119 + `…` → RED (target (9b))
examples: [S5-24] (HLR-173d) after [S5-13], the text edited to `C:\t\a.s19` with `V`, `enter` → dismiss `LoadChoice("path", "C:\t\a.s19")`. The stale reason does not block a load (R-GA-4) (target (9b))

LoadDialog.action_cancel (+ `#load_cancel`, `_close`)
req: HLR-173e, LLR-173.2k, LLR-173.2l, LLR-173.1, LLR-166.1
in: (self)
out: `dismiss(None)`
func: new. `action_cancel()` → `self._close(None)`. The triggers are `escape` (on_key step 2, with the screen binding as a fallback; from any focus: `Input`, `OptionList`, `VerticalScroll` and `Button` do not bind `escape`, as probe p9b-ga showed) and `#load_cancel` (click or `enter`, through `on_button_pressed`, S5).
  `_close(result)` (new helper) is the only way out:
  1. `if self._dismissed: return` (A9b-02: the first line — two queued load/close requests dismiss once, and a second `dismiss` never pops the stack);
  2. `self._dismissed = True`;
  3. `self.dismiss(result)`.
  The dialog writes no file and calls no callable here, so the session digest and the store bytes are G-B's to keep unchanged. Focus after close is SA-7.
module: s19_app/tui/screens.py
examples: [S6-1] (LLR-173.2k, HLR-173e, probe p9b-ga) `escape` with the focus on each of `#load_path`, `#load_list`, `#load_preview`, `#load_ok` → 4 dismisses with `None`, stack depth 1, `V` 0 calls (4 of 4) (target (9b))
examples: [S6-2] (LLR-173.2l, probe p9b-ga) `#load_cancel` focused + `enter` → dismiss `None`; a click on `#load_cancel` → dismiss `None` (2 of 2) (target (9b))
examples: [S6-3] (LLR-173.2l negative control) a mutant mapping `load_cancel` to `action_load` with an empty field → `nothing selected — pick a row or type a path` and 0 dismisses → RED (target (9b))
examples: [S6-4] (HLR-173e boundary) after [S5-13] (a refusal painted), `escape` → dismiss `None`, `V` still 1 call (target (9b))
examples: [S6-6] (R-GA-1, probe p9b-ga K11) the attribute holding the closed state is named `_closed` (mutant) → `escape` never returns from `pilot.press` (hang) → RED by timeout; named `_dismissed` → dismiss `None` (target (9b))
examples: [S6-7] (LLR-173.1) the dismiss value types over [S5-1], [S5-6], [S5-21], [S6-1]: `LoadChoice` (kinds `path`, `project`, `workarea`, `recent`) or `None`, and never `Path` or `str` (5 of 5) (target (9b))
examples: [S6-8] (A9b-02) two `enter` presses queued while the synchronous preview blocks the loop → the first dismisses once; the second reaches `_close` with `_dismissed` set and returns at once → 1 dismiss, 0 `ScreenStackError` (target (9b))

LoadDialog highlight / focus handlers
req: LLR-173.2j, HLR-173a, LLR-173.4j
in: OptionList.OptionHighlighted; events.DescendantFocus
out: one preview paint, `self.show_preview(self._preview_fn(choice))`, per highlight
func: new. These handlers keep the preview showing what a load right now would load (D-GA-2):
  - **`on_descendant_focus(event)` (S-f).** If `event.widget.id` is `"load_list"` or `"load_path"`, set `src` to `"list"` or `"path"`. If `src != self._source`, set `_source = src` and call `self._schedule_preview(self._row_choice() if src == "list" else None)`. Focus on the preview or a button changes nothing.
  - **`on_option_list_option_highlighted(event)`.** If `_source == "list"`, call `_schedule_preview(self._row_choice())`. Textual posts it only for enabled rows (K2).
  - **No `on_input_changed` handler** (A9b-07): while the path field is the source the preview shows no lines, so a field edit makes no preview request.
  - **No `on_option_list_option_selected` handler.** A click only highlights (K3, LLR-173.2j).
  - **`_schedule_preview(choice)` (new helper).**
    1. Clear the preview body: `query_one("#load_preview Static").update("")`, so no `●` of the previous target stays visible.
    2. If `choice is None`, return (the preview stays empty — this is also the whole-field-source case, A9b-07).
    3. `self.show_preview(self._preview_fn(choice))` — the preview is synchronous and returns the lines (A9b-04); the dialog paints what it returns. The dialog touches no path itself (LLR-173.4j, G-A share).
module: s19_app/tui/screens.py
examples: [S7-1] (HLR-173a, probe p9b-ga) list mode, `ROWS_MANY` (`p00` highlighted, its preview painted); then 19 × `down` → `P` called once per highlight, with each row's choice (`20` calls, the last `LoadChoice("project", "p19")`) (target (9b))
examples: [S7-4] (LLR-173.2j, probe p9b-ga K3) list mode, `ROWS_A`, one click on row 2 (`cd`) → `highlighted == 2`, stack depth 2; a double click (`times=2`) on row 2 → `highlighted == 2`, stack depth 2, `V` 0 calls (2 of 2) (target (9b))
examples: [S7-5] (LLR-173.2j) a click on row 3 (`Work area`, disabled) → `highlighted` unchanged, 0 dismisses (target (9b))
examples: [S7-6] (D-GA-2, probe p9b-ga) list mode, `ROWS_A`, `highlight="cd"` → on highlight `P` calls `[LoadChoice("project", "cd")]` (1 call, though the auto focus touched `#load_path` first: K12); the preview painted `● project:cd` / `note` (target (9b))
examples: [S7-7] (D-GA-2) path mode, `ROWS_A` → `P` 0 calls and the preview `` (row 1 is highlighted, but the field is the source and is empty) (probe p9b-ga) (target (9b))
examples: [S7-8] (D-GA-2, A9b-07) path mode, type `C:\t\a.s19` → `P` 0 calls, the preview empty (the field is the source: no typed-file preview); then `tab` (into the list, `ab`) → 1 call, with `LoadChoice("project", "ab")`; the preview shows `● project:ab` / `note` (target (9b))
examples: [S7-9] (D-GA-2) list mode, the preview of `ab` painted; `down` → `_schedule_preview` clears the body, then `P` returns `cd`'s lines synchronously, so the preview shows `● project:cd` / `note` (target (9b))
examples: [S7-10] (LLR-173.4j, G-A share) list mode, `ROWS_A`, row 7 highlighted → `P` called with `LoadChoice("recent", "C:\src\fw.s19")`; the dialog itself makes 0 calls among `os.stat`, `os.lstat`, `os.scandir`, `os.listdir`, `open`, `os.path.exists`, `Path.exists` / `is_file` / `resolve` (a counting spy around the dialog with `P` as a no-op) (target (9b))

LoadDialog.show_preview
req: LLR-173.3c, HLR-173a, LLR-173.6k
in: list[PreviewLine] lines
out: `#load_preview` body painted
func: new (S8, fixed signature: `show_preview(self, lines: list[PreviewLine])`; A9b-04 removed the generation and the stale check).
  1. Build `body = "\n".join((LOAD_MARK + text) if marked else text for text, marked in lines)`. The `● ` prefix goes only on marked lines, and unmarked lines get no indent (S-d).
  2. `query_one("#load_preview Static", Static).update(Text(body))`. A `rich.text.Text` is never parsed as markup, and the `Static` is `markup=False` as well (LLR-173.3c, K8).
  It runs on the event loop, called only by the dialog (S7); `preview()` returns the lines synchronously (SA-3). The mark decisions (which lines are marked) are G-B's (HLR-173a, LLR-173.6, LLR-173.6b, LLR-173.6k); the dialog paints `●` exactly where `marked` is `True`.
module: s19_app/tui/screens.py
examples: [S8-1] (HLR-173a, G-A share) `show_preview([("Variants", False), ("b.s19", True), ("a.s19", False), ("MAC", False), ("m.mac", True)])` → painted `Variants\n● b.s19\na.s19\nMAC\n● m.mac`; 2 `●` (target (9b))
examples: [S8-2] (HLR-173a negative control) a mutant that prefixes `● ` to every line → [S8-1] paints 5 `●` → RED; a mutant that prefixes none → 0 `●` → RED (target (9b))
examples: [S8-6] (LLR-173.3c, G-A share, probe p9b-ga K8) `show_preview([("[b]v.s19", True), ("[s]f", False), ("[i]m.mac", True), ("[u]c.a2l", True)])` → painted `● [b]v.s19\n[s]f\n● [i]m.mac\n● [u]c.a2l`, 0 spans (target (9b))
examples: [S8-7] (LLR-173.3c negative control) a mutant using `Static(markup=True).update(body)` with a `str` → `[b]v.s19` painted bold, without the brackets → RED (target (9b))
examples: [S8-8] (LLR-173.6k, G-A share) `show_preview([("could not be read", False), ("check that the folder can be opened, then load again", False)])` → painted `could not be read\ncheck that the folder can be opened, then load again`, 0 `●` (target (9b))
examples: [S8-9] (S9b-8) `show_preview([("r"×300, False)])` → the preview line's region height is 1 (nowrap + ellipsis, C4) (target (9b))

LoadDialog.on_resize
req: LLR-173.6m
in: events.Resize event
out: `#load_panes` class `stacked` set or removed
func: new.
  - `on_resize(event)` → `self._apply_stack(event.size.width)`.
  - `_apply_stack(width)` (new helper) → `query_one("#load_panes").set_class(width < 100, "stacked")`.
  - Also called from `on_mount` with `self.app.size.width` (S3 step 6).
  - The layout itself is C3 / C4. The break is 100: "narrower than 100 columns" means `width <= 99`.
module: s19_app/tui/screens.py
examples: [S9-1] (LLR-173.6m, probe p9b-ga K10) 99×54 → `stacked`; `#load_list` (5, 10, 89, 15); `#load_preview` (5, 25, 89, 19); `preview.y (25) >= list.y + list.height (25)` (target (9b))
examples: [S9-2] (LLR-173.6m) 100×54 → not stacked; list (5, 10, 45, 34), preview (50, 7, 45, 37), `preview.x (50) >= list.x + list.width (50)`; 118×54 → list (5, 10, 53, 34), preview (58, 7, 54, 37), `58 >= 58` (2 of 2) (target (9b))
examples: [S9-3] (LLR-173.6m, live resize) open at 118×54, `resize_terminal(99, 54)` → `stacked`, list (5, 10, 89, 15), preview (5, 25, 89, 19) (target (9b))
examples: [S9-4] (LLR-173.6m negative control) a mutant with `width < 118` → 100×54 is stacked → RED (target (9b))

C1 `.modal-dialog` + `#load_box` (changed + new)
req: HLR-173, LLR-173.6m
in: —
out: dialog box
func: changed and new. The shared selector `.modal-dialog, #load_dialog` (`styles.tcss:1581-1582`) becomes `.modal-dialog` alone, so the five other modals keep `#load_dialog` unchanged (B-3). `LoadDialog`'s container carries the class and the id `#load_box`, which names only this dialog. Its body (border, background, colour, padding, `width: 70%`, `height: auto`) is unchanged for the other modals. New rule: `#load_box { width: 96%; max-width: 160; height: 90%; }`. The comment block at `styles.tcss:1563-1574` stays byte-identical (A9b-12): `_modal_css_block()` locates the modal block by its literal first line `Calm Dark modal re-skin (batch-02 increment 8`, so it is not reworded.
module: s19_app/tui/styles.tcss
examples: [C1-1] (HLR-173, probe p9b-ga K10) 118×54 → `#load_box` region (2, 3, 113, 48); 99×54 → (2, 3, 95, 48) (target (9b))
examples: [C1-2] (C1, no regression) `SaveProjectScreen` (`.modal-dialog`, no `#load_box`) keeps `width: 70%` → its region width at 118 columns is 82 (70 % of 118, rounded down); unchanged from the 9a tree (target (9b); the number is to be read on the 9a tree at E4)
examples: [C1-3] (HLR-173, C1) `#load_box` keeps the accent border `round $accent-calm` and the background `$bg-panel` (through `.modal-dialog`) (target (9b))

C2 `#variant_list` (changed)
req: (VS-PA-3, retirement)
in: —
out: —
func: changed. `#project_list, #variant_list` (`styles.tcss:1762`) → `#variant_list`, with the body unchanged. `#project_list` is retired with R2. `SelectVariantScreen`'s `#variant_list` keeps `border: round $rule; background: $bg-base; height: 10;`.
module: s19_app/tui/styles.tcss
examples: [C2-1] (VS-PA-3) `grep -c "project_list" s19_app/tui/styles.tcss` → 0; `grep -c "#variant_list" …` → 1 (target (9b))
examples: [C2-2] (no regression) `SelectVariantScreen` → `#variant_list` region height 10, unchanged (target (9b))

C3 `#load_panes`, `#load_panes.stacked` (new)
req: LLR-173.6m
in: —
out: —
func: new.
  - `#load_panes { layout: horizontal; height: 1fr; }`
  - `#load_panes.stacked { layout: vertical; }` (id + class wins over `Horizontal`'s `DEFAULT_CSS`, K10)
  - `#load_panes.stacked #load_left, #load_panes.stacked #load_preview { width: 100%; }`
module: s19_app/tui/styles.tcss
examples: [C3-1] (LLR-173.6m) the regions of [S9-1] … [S9-3] (probe p9b-ga) (target (9b))
examples: [C3-2] (LLR-173.6m negative control) a mutant without the `.stacked` rule → 99×54 keeps the side-by-side regions (`preview.y < list.y + list.height`) → RED (target (9b))

C4 `#load_left`, `#load_list`, `#load_preview`, `#load_reason`, `#load_buttons` (new)
req: LLR-173.6n, LLR-173.2c, HLR-173d
in: —
out: —
func: new.
  - `#load_left { width: 1fr; height: 1fr; }`
  - `#load_list { height: 1fr; border: round $rule; background: $bg-base; text-wrap: nowrap; text-overflow: ellipsis; }`
  - `#load_list:focus { border: round $accent-calm; }`
  - `#load_preview { width: 1fr; height: 1fr; border: round $rule; background: $bg-base; padding: 0 1; text-wrap: nowrap; text-overflow: ellipsis; }` (S9b-8: a preview line never wraps, so a continuation line can never start with `●`)
  - `#load_preview:focus { border: round $accent-calm; }`
  - `#load_reason { height: auto; padding: 0 1; text-style: bold; }`
  - `#load_buttons` carries the class `modal-buttons` and needs no rule of its own (the shared `.modal-buttons` docks at the bottom).
  - `#load_path` takes `.modal-dialog Input` / `:focus` unchanged.
  - Colours come only from the existing tokens (`$rule`, `$bg-base`, `$accent-calm`): no new hue (TC-033 single-accent rule).
module: s19_app/tui/styles.tcss
examples: [C4-1] (LLR-173.6n, probe p9b-ga K9) `ROWS_LONG` at 99, 100 and 118 × 54 → every option height 1 (the set of `_heights` values `{1}`) (9 of 9: 3 rows × 3 widths) (target (9b))
examples: [C4-2] (LLR-173.6n negative control, probe p9b-ga K9) a mutant without `text-wrap: nowrap` → at 99×54 the 120-character rows are 2 lines high (heights `{1, 2}`) → RED (target (9b))
examples: [C4-3] (LLR-173.2c) `#load_list` focused → border colour `$accent-calm`; `#load_preview` focused → `$accent-calm`; neither focused → `$rule` (target (9b))
examples: [C4-4] (HLR-173d) after [S5-13], `#load_reason` region height 1 at 118×54, and the text `not found — check the path` is fully visible (not clipped) (target (9b))
examples: [C4-5] (S9b-8) `#load_preview` holds a 300-character line at 45 columns → the line region height is 1 (nowrap + ellipsis, as `#load_list`'s K9 rule) (target (9b))

R1 `LoadFileScreen` (retired)
req: VS-PA-3, Q9
in: —
out: —
func: retired. The class (`screens.py:184-227`) is deleted, and its role passes to `LoadDialog(mode="path", …)`. The ids `#load_path`, `#load_ok` and `#load_cancel` survive with new semantics; the outer container id is `#load_box`, not `#load_dialog` (B-3). `#loadfile_buttons` becomes `#load_buttons` (0 test references).
  Behaviour changes the re-pins meet:
  - the constructor now needs the 5 keyword arguments (no zero-argument form);
  - the dismiss value is `LoadChoice("path", text)`, not `Path(text)`;
  - the text is passed verbatim (`LoadFileScreen` stripped it);
  - an empty Load paints `nothing selected — pick a row or type a path` instead of returning silently;
  - a refused path now stays in the dialog (verdict).
  `#load_path` stays an `OsClipboardInput`, so the clipboard tests keep their widget.
  In-file docstrings that name the class are reworded to "the Load dialog": `screens.py:281`, `:1686`, `:1996` (3 lines, G-A).
module: s19_app/tui/screens.py
examples: [R1-1] (Q9) `grep -c "class LoadFileScreen" s19_app/tui/screens.py` → 0; `python -c "import s19_app.tui"` → exits 0, which needs PSC-1 (target (9b))
examples: [R1-2] (re-pin census, 9a tree, `grep` over `tests/*.py`, executed in this session) `LoadFileScreen` → 13 files / 59 lines / 60 occurrences (target: re-pinned by the tester to `LoadDialog`; count after → 0)

R2 `LoadProjectScreen` (retired)
req: VS-PA-3, Q9
in: —
out: —
func: retired. The class (`screens.py:696-735`) is deleted, and its role passes to `LoadDialog(mode="list", highlight=current_project, …)`. The retired ids map as follows:
  - `#project_list` → `#load_list`. It is an `OptionList`: read `.highlighted`, not `.index`. With headings, project *i* (0-based) sits at index *i* + 1.
  - `#project_ok` → `#load_ok`.
  - `#project_cancel` → `#load_cancel`.
  - `#loadproject_buttons` → `#load_buttons` (0 test references).
  Behaviour changes the re-pins meet:
  - the dismiss value is `LoadChoice("project", name)`, not `str`;
  - the callback is `_handle_load_dialog` (G-B), not `_route_load_project`;
  - with 0 projects the dialog opens (LLR-173.2a), where today it paints `No saved projects found.`;
  - the open project is highlighted on open.
  In-file docstrings that name the class are reworded: `screens.py:817`, `:953` (2 lines, G-A). `SelectVariantScreen` keeps its own `ListView` and is not part of 9b.
module: s19_app/tui/screens.py
examples: [R2-1] (Q9) `grep -c "class LoadProjectScreen" s19_app/tui/screens.py` → 0; `grep -cE "project_list|project_ok|project_cancel" s19_app/tui/screens.py s19_app/tui/styles.tcss` → 0 and 0 (target (9b))
examples: [R2-2] (re-pin census, 9a tree, executed in this session) `LoadProjectScreen` → 17 files / 56 lines / 57 occurrences; `project_list|project_ok|project_cancel` → 18 files / 50 lines / 71 occurrences (target: 0 after the re-pins)

PSC-1 `s19_app/tui/__init__.py` (re-export change)
req: VS-PA-3, Q9
in: —
out: —
func: changed. Line 32: `LoadFileScreen, LoadProjectScreen` → `LoadChoice, LoadDialog` in the `.screens` import. `__all__` lines 61-62: `"LoadFileScreen"`, `"LoadProjectScreen"` → `"LoadChoice"`, `"LoadDialog"`. No other change. Without it, deleting the two classes (R1, R2) breaks every `import s19_app.tui…` (R-GA-5).
module: s19_app/tui/__init__.py
examples: [P1-1] (Q9, PSC-1) `python -c "import s19_app.tui"` → exits 0; `from s19_app.tui import LoadChoice, LoadDialog` → both resolve; `LoadFileScreen` / `LoadProjectScreen` are no longer exported.

## Entities

[state: load source]
desc: `LoadDialog._source` ∈ {`"path"`, `"list"`}. It starts at `mode` and changes in `on_descendant_focus` when `#load_list` or `#load_path` gains the focus (S-f), and in `on_key` step 4 when the printable-key redirect runs (A9b-06: the redirect is itself the decision). Focus on the preview or a button leaves it as it was.
sequence:
  write: S2 `__init__` (= mode) → S7 `on_descendant_focus` (on a change: `_schedule_preview` of the new source) → S4 `on_key` step 4 (= "path")
  read: S5 `action_load` (row vs typed text) → S7 highlight handler (preview only while the list is the source) (!)

[state: dismissed]
desc: `LoadDialog._dismissed` (bool, starts at `False`). The one guard left after A9b-04 removed the generation: `_close` returns at once when it is already set, so two queued close/load requests dismiss once.
sequence:
  request: S7 `_schedule_preview` (clear body) → G-B `preview(choice)` returns lines (synchronous) → S8 `show_preview(lines)` paints (!)
  close: S6 `_close` (if `_dismissed`: return; else `_dismissed = True`) → `dismiss`

## Seams with G-B (`app.py`)

| Id | Seam | G-A promise | G-B duty | Examples naming it |
|---|---|---|---|---|
| SA-1 | `rows()` (S-c) | called once, in `on_mount`, on the event loop; order kept; `choice is None` rows disabled; labels painted verbatim with markup off; `section_id` is not read by the dialog | return the 3 sections in the order projects, work area, recents, each under a heading row (`Projects`, `Work area`, `Recent`) and with the empty / problem token lines as `None` rows (LLR-173.4 … LLR-173.4h); labels already through `painted_names` + `safe_text` and clipped (LLR-173.3 … LLR-173.3b); values the on-disk names / recorded text (LLR-173.3d); never raise; touch no recent's path (LLR-173.4j) | S3-8, S3-10, S3-11, S3-12, S5-22 |
| SA-2 | `verdict(choice)` (S-b) | called once per load request after the empty check, for every kind (D-GA-5), with the typed text verbatim; a pair is painted `reason — step` and the dialog stays | `None` for `project` / `workarea`; the typed-route classification for `path` and `recent` with the §3 token pairs (LLR-173.4k, LLR-173.5 … LLR-173.5e); strip or refuse surrounding spaces (R-GA-6); catch `OSError` (LLR-173.5e); never raise; metadata only, on the event loop | S5-1, S5-13 … S5-20 |
| SA-3 | `preview(choice)` (S-e) | called for every highlight, never for a path-field edit (A9b-07: the preview stays empty while the field is the source); returns the lines synchronously and the dialog paints them | project → a synchronous build (Q2); recent → store facts only, 0 filesystem calls (LLR-173.4i, LLR-173.4j); file → marks (LLR-173.6b, LLR-173.6c); an `OSError` → the `could not be read` lines, no mark (LLR-173.6k); never raise | S7-1, S7-10, S8-1 |
| SA-4 | the dismiss value | `LoadChoice` (the same object the row held) or `None`, only after `verdict` returned `None` | push with `self._handle_load_dialog` at both sites (LLR-173.1e); route the 4 kinds (LLR-173.1a … LLR-173.1f) | S5-21, S5-22, S6-7 |
| SA-5 | priority keys (S-g) | the dialog binds none of `ctrl+l` / `ctrl+s` / `ctrl+k` / `ctrl+d` | `check_action` returns `False` for `load_file`, `save_project`, `focus_palette`, `cycle_density` while `isinstance(self.screen, LoadDialog)` (LLR-173.2e). Probe p9b-ga K6 shows that the mechanism works on Textual 8.2.8 (scratch app); the probe on `S19TuiApp` is still owed. See R-GA-3 for what `ctrl+k` / `ctrl+d` then do in `#load_path` | — (G-B) |
| SA-6 | push sites | `mode="path"` focuses `#load_path`, `mode="list"` focuses `#load_list` | `l` / `ctrl+l` / palette `load_file` → `mode="path"`; `p` / `#ws_load_project_button` / palette `load_project` → `mode="list"`, also with 0 projects (LLR-173.2, LLR-173.2a); `highlight=self.current_project`; the imports at `app.py:81`, `:83` become `LoadChoice`, `LoadDialog` | S3-6 |
| SA-7 | focus after close (LLR-166.1, TC-B100-12) | `dismiss` pops the screen; Textual restores the focus the main screen had | assert the TC-B100-12 9b arms (`escape`, a cancelled load) on `S19TuiApp` | S6-1 |
| SA-8 | package exports | `screens.py` no longer defines `LoadFileScreen` / `LoadProjectScreen` | none in `app.py`; `s19_app/tui/__init__.py:32,61,62` must change (PSC-1, orchestrator) | R1-1 |
| SA-9 | token table (CR9-7) | the dialog owns one pair, `LOAD_NOTHING_SELECTED`; every other pair arrives through `verdict` / `preview` / `rows` | G-B's token table (guess G2) holds the typed-refusal, empty-section and store-problem pairs; the §3 preface cites `LOAD_NOTHING_SELECTED` for the empty Load | S5-8 |

## Findings

### Design decisions taken inside the interface (no interface change)

- **D-GA-1** The dialog loads from the list on `enter` intercepted in `LoadDialog.on_key` (K4), never on `OptionList.OptionSelected`, which a click also posts (K3). This meets LLR-173.2j with stock `OptionList`, with no subclass and no `_on_click` override.
- **D-GA-2** The preview always shows the current load target. A highlight in the list asks for a preview, and only while the list is the source. While the path field is the source the preview shows no lines (A9b-07). A change of source to the list asks again. Otherwise the `●` marks could describe the row while Enter loads the typed text, against HLR-173a's "exactly the set a load installs".
- **D-GA-4** Options are added as `str` prompts to `OptionList(markup=False)` and disabled by index (`disable_option_at_index`). `Option` lives in `textual.widgets.option_list`, a module `screens.py` does not import today, so importing it would break LLR-173.6l's "0 new modules".
- **D-GA-5** `verdict` is called for every kind, and G-B answers `None` for `project` / `workarea`. The dialog has one load path and does not branch on kind.
- **D-GA-6** `#load_preview` is a `VerticalScroll` holding one `Static(markup=False)`. It is focusable (LLR-173.2c), and a long preview (many variants and problems) scrolls by key instead of being clipped. `enter` on it loads (HLR-173c boundary).
- **D-GA-7** Button labels `Load (alt+l)` and `Cancel (esc)` follow the codebase's `Close (esc)` (`LoadResultScreen`) and the operator's rule of a visible key on each modal button. The labels are not fixed by a requirement; E3 may rule.
- **D-GA-8** `#load_reason` paints `<reason> — <step>` (U+2014), the separator the status-line refusals use (`app.py:12946-12959`).
- **D-GA-9** The initial highlight rule is the same in both modes. In path mode the highlight is set but asks for no preview (D-GA-2), and `tab` into the list lands on that row (LLR-173.2f boundary).
- **D-GA-10** Dialog attributes use names checked free in Textual 8.2.8: `_mode`, `_highlight`, `_rows_fn`, `_verdict`, `_preview_fn`, `_rows`, `_source`, `_dismissed` (K11).

### Design risks

finding R-GA-1 An attribute name that shadows Textual internals hangs the dialog
anchor: LoadDialog.__init__, `_close`; probe p9b-ga K11
seen: `MessagePump` uses `self._closed` and `self._closing`. In the scratch skeleton, a dialog attribute `_closed = True` set before `dismiss` made `escape` and `alt+l` (a `dismiss` fired from a binding) never return.
cause: the screen's message pump read the dialog's flag as its own "closed" state.
effect: the app freezes on `escape` or Load.
decision: D-GA-10. The implementer keeps the names in this graph. Example [S6-6] is the guard. Any new private attribute on a `Screen` subclass is to be grepped against `textual/` first.

finding R-GA-3 With the S-g guard, `ctrl+k` and `ctrl+d` edit the path field (seam SA-5)
anchor: SA-5; LLR-173.2e
seen: Textual 8.2.8 `Input` binds `ctrl+k` → `delete_right_all` and `ctrl+d` (with `delete`) → `delete_right` (`_input.py:120-138`). When `check_action` returns `False` for the app's priority binding, the key is forwarded to the focused widget.
cause: on the main screen the priority app bindings always shadow these `Input` keys. In the dialog they no longer do.
effect: `ctrl+k` with `#load_path` focused deletes the text right of the cursor. No app action runs, so LLR-173.2e holds, but the field changes.
decision: accept (standard field editing). The alternative is a `priority=True` no-op binding for the 4 keys on `LoadDialog`, which moves the S-g guard into G-A and is an interface change; it is not proposed. E3 may rule.

finding R-GA-4 `#load_reason` keeps a refusal after the text is edited
anchor: S5 `_say`; E1-scope §5 observation 3
seen: nothing clears `#load_reason` but the next load request.
effect: a stale `not found — check the path` stays visible while a corrected path is typed. The next load repaints or closes ([S5-24]).
decision: n/a at 9b (no requirement). If a later increment wants it, clearing `#load_reason` on a field edit is a one-line event requirement.

finding R-GA-5 Retiring both screens breaks `import s19_app.tui` (seam SA-8)
anchor: R1, R2; `s19_app/tui/__init__.py:32` (`from .screens import LoadFileScreen, LoadProjectScreen, …`), `:61`, `:62` (`__all__`)
seen: the package re-exports both classes (read on the 9a tree in this session).
effect: deleting the classes in `screens.py` alone makes every `import s19_app.tui…` raise `ImportError`, and the whole suite fails at collection.
decision: accepted scope change PSC-1 (E2-rulings PSC-1; node PSC-1). The alternative of keeping aliases (`LoadFileScreen = LoadDialog`) contradicts ruling Q9 and would keep tests passing against a different contract. Not recommended.

finding R-GA-6 The typed text is passed verbatim (seam SA-2)
anchor: S5 `_path_choice`; S-a ("typed text (verbatim)")
seen: `LoadFileScreen` stripped the value (`screens.py:222`). S-a fixes it verbatim.
effect: `  C:\t\a.s19 ` reaches `verdict` and the router with its spaces.
decision: G-B strips or refuses (SA-2). The dialog only treats a spaces-only text as empty (LLR-173.2h).

finding R-GA-7 The path field must stay an `OsClipboardInput`
anchor: S2 compose; `tests/test_loadfilescreen_input.py` (32 tests, 18 lines naming `LoadFileScreen`), `tests/test_clipboard_tk_singleton.py`
seen: Windows `ctrl+v` goes through `OsClipboardInput.action_paste` (`os_clipboard_input.py:432-470`).
effect: a plain `Input` would drop the OS paste path, and those tests would fail for a real reason, not a re-pin.
decision: S2 uses `OsClipboardInput(id="load_path")`.

finding R-GA-8 `enter` on the preview loads
anchor: S4 step 3; HLR-173c boundary
seen: the requirement counts the focus on the preview as "asks to load", and the last of list / path decides.
effect: an engineer reading the preview who presses `enter` starts a load. Scrolling uses the arrow keys and page keys, not `enter`.
decision: accept, as the requirement asks.

finding R-GA-9 (A9b-R2-5, declared) `escape`, then `alt+l` queued while the loop is busy loads instead of closing
anchor: S4 step 2 (escape in `on_key`); S2 `alt+l` priority binding
seen: `alt+l` is a `priority=True` binding, taken in `App.on_event` before any key is forwarded to the screen's `on_key`; `escape` is taken in the screen's `on_key`, after forwarding. So a queued `escape`, `alt+l` runs `alt+l` first and loads instead of closing.
effect: the wrong outcome for a rare double-key type-ahead; A9b-02's guard prevents a crash, not the wrong result.
decision: declare as a design risk; making `escape` priority would only invert `enter`, `escape`. No code change (A9b-R2-5).

### Undecidable points the requirements leave open (each with the recommendation the graph follows)

- **U-1** The preview latency for recent and file rows: none — the preview is synchronous (Q2 removed the rest timer).
- **U-2** The preview while the field is the source: no lines, empty or typed (A9b-07 extends the empty-body rule).
- **U-3** The button labels. Recommendation: `Load (alt+l)` / `Cancel (esc)` (D-GA-7).
- **U-4** Whether a refusal is cleared on edit. Recommendation: not cleared (R-GA-4).

### Proposals

- **PSC-1 (scope change, accepted, not an interface change).** Add `s19_app/tui/__init__.py` as Inc 9b's 4th source file, at the cap of 4.
  - Line 32: `LoadFileScreen, LoadProjectScreen` → `LoadChoice, LoadDialog`.
  - `__all__` lines 61-62: `"LoadFileScreen"`, `"LoadProjectScreen"` → `"LoadChoice"`, `"LoadDialog"`.
  - No other change. It is mechanical, owned by G-A (it re-exports `screens.py`).
  - Without it R1 / R2 cannot land (R-GA-5).
  - The stale docstring at `os_clipboard_input.py:470` (names `LoadFileScreen`) is left alone and goes to the backlog (it would be a 5th file).
- **Proposed interface changes:** none.

## Retirement plan (R1, R2) — reverse census for the tester

Executed in this session on the 9a tree (`4fef292` + 9a's uncommitted changes, which do not touch `screens.py` or `styles.tcss`) with `grep -rlE / -rhE / -rohE <pattern> tests --include=*.py`. Counts only; the tester re-pins.

**Totals.**

| Pattern | Files | Lines | Occurrences | E1 §5.4 said |
|---|---|---|---|---|
| `LoadFileScreen` | 13 | 59 | 60 | 13 / 60 (occurrences) |
| `LoadProjectScreen` | 17 | 56 | 57 | 17 / 57 |
| `project_list\|project_ok\|project_cancel` | 18 | 50 | 71 | 17 / 63 (pattern without `project_cancel`) |
| union of the three | 21 | — | — | — |
| `load_path\|load_ok\|load_cancel` (ids that survive) | 33 | 138 | 191 | — |

**Reference kinds.**
- Import lines naming either class: 35 lines in 20 files.
- `isinstance(…, LoadFileScreen|LoadProjectScreen)` lines: 52.
- SVG snapshots holding the old titles `Load file (S19` or `Load project:`: 0. No snapshot rebaseline comes from R1 / R2. The label rebaselines are Inc 12a's (Q8).

**Per file** (lines naming `LoadFileScreen` | `LoadProjectScreen` | `project_list/ok/cancel`):

| File | LFS | LPS | ids |
|---|---|---|---|
| tests/test_b100_active_variant.py | 5 | 3 | 2 |
| tests/test_b100_announce.py | 0 | 2 | 2 |
| tests/test_b100_document.py | 3 | 2 | 2 |
| tests/test_b100_focus.py | 5 | 6 | 3 |
| tests/test_b100_project_check.py | 3 | 2 | 2 |
| tests/test_b100_project_homes.py | 3 | 6 | 4 |
| tests/test_b100_recents.py | 3 | 0 | 2 |
| tests/test_b100_reuse.py | 3 | 2 | 3 |
| tests/test_b100_save_guards.py | 3 | 3 | 2 |
| tests/test_b100_save_image.py | 3 | 3 | 2 |
| tests/test_b100_session_reset.py | 0 | 3 | 2 |
| tests/test_b97_load_project_dialog.py | 0 | 3 | 3 |
| tests/test_b99_crc_region.py | 0 | 2 | 2 |
| tests/test_b99_export.py | 2 | 2 | 2 |
| tests/test_b99_load_project.py | 0 | 3 | 8 |
| tests/test_b99_patch_truth.py | 0 | 0 | 4 |
| tests/test_b99_staging.py | 0 | 2 | 3 |
| tests/test_b99_truncation.py | 0 | 2 | 2 |
| tests/test_clipboard_tk_singleton.py | 2 | 0 | 0 |
| tests/test_loadfilescreen_input.py | 18 | 0 | 0 |
| tests/test_tui_directionb.py | 6 | 10 | 0 |

**Non-test references.**
- `app.py:81`, `:83`, `:7332`, `:7447`, plus docstrings `:12972`, `:12993`: G-B.
- `s19_app/tui/__init__.py:32,61,62`: PSC-1.
- `screens.py` docstrings `:281`, `:817`, `:953`, `:1686`, `:1996`: G-A, reworded.
- `styles.tcss:1563-1574` comment, `:1581-1582`, `:1762`: C1, C2.
- `os_clipboard_input.py:470`: backlog.

**Re-pin rules for the tester** (mechanical, from R1 / R2):
1. Construct `LoadDialog(mode=…, highlight=…, rows=…, verdict=…, preview=…)` or drive the app keys (`l` / `p`).
2. Assert a `LoadChoice` dismiss.
3. Read `#load_list.highlighted` with heading offsets.
4. `#project_ok` → `#load_ok`, `#project_cancel` → `#load_cancel`.
5. Expect the dialog to open with 0 projects.

## Requirement coverage (G-A scope)

| Requirement | Examples (node) |
|---|---|
| HLR-173 | S2-1, S2-2 (one dialog, ids, strings), C1-1, C1-3 |
| HLR-173a (G-A share: paint `●` where marked) | S8-1, S8-2, S7-1, S7-6, S7-8 |
| HLR-173b (G-A share: recent dismiss, refusal in dialog) | S5-20, S5-21, S1-4 |
| HLR-173c | S4-5, S4-7, S5-1 … S5-7 |
| HLR-173d | S5-8, S5-13 … S5-19, S5-24, C4-4 |
| HLR-173e | S6-1, S6-4 |
| LLR-173.1 | S1-1 … S1-4, S6-7 |
| LLR-173.2 (G-A share: focus by mode) | S3-6, S3-7 |
| LLR-173.2a (G-A share: list focus, 0 projects) | S3-4, S3-6 |
| LLR-173.2b | S3-1 … S3-5 |
| LLR-173.2c | S2-4, S2-5, C4-3 |
| LLR-173.2d | S4-1 … S4-4 |
| LLR-173.2f | S4-5, S5-5, S5-6, S5-7 |
| LLR-173.2g | S5-1 … S5-4 |
| LLR-173.2h | S5-8, S5-9 |
| LLR-173.2i | S5-10, S5-11, S5-12 |
| LLR-173.2j | S7-4, S7-5, S4-6 |
| LLR-173.2k | S6-1 |
| LLR-173.2l | S6-2, S6-3 |
| LLR-173.3 (G-A share: markup off) | S3-12, S3-13 |
| LLR-173.3a (G-A share) | S3-12 (same mechanism; G-B's 7 hostile names go through it) |
| LLR-173.3b (G-A share) | S3-12 (same mechanism) |
| LLR-173.3c (G-A share) | S8-6, S8-7 |
| LLR-173.3d (G-A share: row object returned) | S5-22, S5-23, S1-3 |
| LLR-173.4d / .4e / .4f / .4g (G-A share: token lines disabled, not loadable) | S3-10, S3-11, S5-11 |
| LLR-173.4j (G-A share: the dialog makes no filesystem call) | S7-10, S2-6 |
| LLR-173.4k (G-A share) | S5-20 |
| LLR-173.4l (G-A share: order kept, headings disabled) | S3-8, S3-9 |
| LLR-173.5 | S5-13, S5-19 |
| LLR-173.5a | S5-14 |
| LLR-173.5b | S5-15 |
| LLR-173.5c | S5-16 |
| LLR-173.5d | S5-17 |
| LLR-173.5e | S5-18 |
| LLR-173.6k (G-A share: painted without `●`) | S8-8 |
| LLR-173.6l | S2-6, S2-7, S2-8 |
| LLR-173.6m | S9-1 … S9-4, C3-1, C3-2 |
| LLR-173.6n | C4-1, C4-2, C4-5, S8-9 |
| LLR-173.7 (G-A strings) | S2-3 |
| VS-PA-3 / Q9 (retirement) | R1-1, R1-2, R2-1, R2-2, C2-1 |

**Seams: requirements owned by G-B (`app.py`), with no G-A node or only a G-A share already covered above.**
- LLR-173.1a, LLR-173.1b, LLR-173.1c, LLR-173.1e, LLR-173.1f: the router (SA-4).
- LLR-173.2e: the priority keys (SA-5, R-GA-3).
- LLR-173.4, LLR-173.4a, LLR-173.4b, LLR-173.4c, LLR-173.4h: the sources and labels (SA-1).
- LLR-173.4i: the recent preview content (SA-3).
- LLR-173.6, LLR-173.6a, LLR-173.6b, LLR-173.6c, LLR-173.6d, LLR-173.6f: marks, panel and preview lines (SA-3).
- LLR-173.6k: the catch (SA-3).
- LLR-173.3, LLR-173.3a, LLR-173.3b: the `painted_names` scrub and clip (SA-1).
- LLR-172.1n (CR9-1), LLR-172.4 (the census widened with LLR-173.4b), LLR-178.3 (the panel from the project route).
- LLR-166.1 (focus after close, SA-7).
- The Q7 reverse census of tests that list an empty folder: G-B / E2 baseline.

LLR-173.2m: removed from 9b (ruling Q8). It has no example.
