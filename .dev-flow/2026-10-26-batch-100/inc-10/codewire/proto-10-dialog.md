# Code-Wire prototype — Inc 10, group G-A (`screens.py` + `screens_directionb.py` + `styles.tcss`)

Stage E2 of the design-first pipeline for Inc 10 ("one short question before unsaved work is lost"). This is the graph only. Nothing in `s19_app/` changes, and the repo `<HOME>\Github\s19_app` (`8947666`) stays read-only. New code is a node whose `func:` starts with "new". The shared interfaces are those in `interfaces-10.md` (fixed). This group changes none of them; two changes it needs are written under "Proposals to the orchestrator". G-B (`app.py`) writes its prototype in parallel; the seams are listed under "Seams with G-B".

**Base and inputs.**
- Code: `8947666` (Inc 9a merged). Inc 9b is designed but not merged; this graph builds on `../../inc-9b-design/codewire/proto-9b-dialog.md` (the `_dismissed` guard, R-GA-1, the `.modal-dialog` box) and `interfaces-9b.md` (S-g: the whole-stack `check_action` test, `_LOAD_DIALOG_INERT_ACTIONS`). `ConfirmDiscardScreen` is at `screens.py:907-947`, `LoadGuardScreen` at `screens_directionb.py:4286`, the `_dirty` attribute comment at `screens_directionb.py:4808-4815`, the modal rules at `styles.tcss:1576-1597`, `:1732-1746`. Post-9b line numbers in `screens.py` shift; nodes cite symbols.
- Requirements: `../E1-requirements-draft.md` §A, §B, §C.4. Rulings: `../E1-rulings.md` (Q1–Q8), `../E2-rulings.md`, and `interfaces-10.md` §Orchestrator rulings (Q-1 … Q-7, binding).
- Baseline: `baseline-10.md`, `baseline-notes.md` (probe p10b U0–U13; extractor callers).
- Textual: 8.2.8 (`importlib.metadata.version("textual")` in `s19env`).

**Probe p10-ga (executed in this session).** Python `s19env`, `python -I`, `env -u NO_COLOR PYTHONDONTWRITEBYTECODE=1 PYTHONUTF8=1 LOCALAPPDATA=../work/localappdata-GA`, Textual 8.2.8, `App.run_test` on the real `S19TuiApp` (so the real `styles.tcss` applies), imported from a `git archive 8947666` copy at `../work/ga/tree`. Scripts and outputs: `../work/ga/probe_p10_ga.py` (+ `.out.txt`), `probe_p10_ga2.py` (+ `.out.txt`), `probe_p10_ga3.py` (+ `.out.txt`). `probe_p10_ga.py` holds a throwaway skeleton `Q` of this graph's `ConfirmQuestionScreen` (the S-a contract, Content labels, the `_dismissed` guard) used to check the steps; it is not a stub and never goes into the repository. `probe_p10_ga3.py` adds a read-only `is_dirty` property to `PatchEditorPanel` at runtime in the probe process only. Facts the examples use:
- **K1.** Pushed at 118×54 → stack `['Screen', 'Q']`, `focused.id == "confirm_no"`, buttons `[('confirm_yes', 'Replace (y)'), ('confirm_no', 'Cancel (n)')]`, `0` `Input` / `TextArea`, ids `confirm_box`, `confirm_title`, `confirm_body`, `confirm_buttons` present once each. Painted title `Replace fw.s19?`, body `There are unsaved changes in fw.s19. Load b.s19 anyway?`.
- **K2.** `y` → `[True]`, `n` → `[False]`, `escape` → `[False]`, each with the focus on `#confirm_no` and on `#confirm_yes` (6 of 6); stack back to `['Screen']`. Immediate `enter` → `[False]`; `tab`, `enter` → focus `confirm_yes`, `[True]`; `tab`, `tab`, `enter` → focus `confirm_yes`, `confirm_no`, `[False]` (the chain wraps over the two buttons); `shift+tab`, `enter` → `[True]`.
- **K3.** A click on `#confirm_yes` → `[True]`; on `#confirm_no` → `[False]`.
- **K4.** `a`, `l`, `p`, `s`, `q`, `space`, `?`, `v` → stack still `['Screen', 'Q']`, `0` answers, focus still `confirm_no` (a modal stops the non-priority app keys; `Button` binds only `enter`, p10b U0, so `space` presses nothing).
- **K5.** Base `check_action`: `ctrl+l` under the question → `load_file` ran, stack `['Screen', 'Q', 'LoadFileScreen']` (the RED side of LLR-174.2h, as p10b U11 with `LoadGuardScreen`). With the S-f rule modelled (`action in INERT and any(isinstance(s, Q) for s in screen_stack)` → `False`): `ctrl+l`, `ctrl+s`, `ctrl+k`, `ctrl+d` with the focus on each button → `0` actions ran, stack `['Screen', 'Q']`, `0` answers, focus unchanged. The forwarded keys reach a `Button`, which binds none of them, so nothing changes (contrast 9b R-GA-3, where `Input` edits text).
- **K6.** Labels as `Content`: `Content("[b]Quit (y)")` paints `[b]Quit (y)`, 0 spans. Title `Label(markup=False)` paints `[b]Quit?`, 0 spans; body `Static(markup=False)` paints `A save is [red]running[/red].`, 0 spans. The str-label mutant (`Button("[b]Quit (y)")`) paints `Quit (y)` with 1 span (Textual `Button.validate_label` → `Content.from_text` parses a `str`). The quit arm paints exactly `Quit?`, `A save is running.`, `Quit (y)`, `Stay (n)`; `Replace` count 0; `y` → `[True]`.
- **K7.** Guarded `_close(True); _close(False)` in one tick → answers `[True]`, stack `['Screen']`. Without the guard (mutant) → `ScreenStackError: Can't pop screen; there must be at least one screen on the stack`, and the callback list was already spent (Q-5 was "not probed on base"; this executes it).
- **K8.** Layout with the real stylesheet, title `Replace ` + 120 characters (`n`×119 + `…`) + `?`, body `There are unsaved changes in <120>, Patch Editor entries and flow <120>. Load project <120> anyway?`. Each button's region equals its visible region (`region ∩ clip`) and lies inside the screen region:
  - 99×54: `#confirm_box` (16, 17, 67, 20), body 10 rows; `#confirm_yes` (46, 32, 16, 3), `#confirm_no` (64, 32, 16, 3);
  - 118×54: box (18, 18, 81, 18), body 8 rows; yes (62, 31, 16, 3), no (80, 31, 16, 3);
  - 220×60: box (34, 23, 152, 14), body 4 rows; yes (149, 32, 16, 3), no (167, 32, 16, 3);
  - 118×54 with the short load question (K1 strings): box (18, 21, 81, 11); yes (62, 27, 16, 3), no (80, 27, 16, 3);
  - beyond the requirement: 99×24 box (16, 2, 67, 20) and 80×24 box (13, 1, 54, 21), both buttons fully visible.
- **K9.** E1's LLR-174.2r mutant (`#confirm_box` height 7) does **not** go RED: the `.modal-buttons` row is `dock: bottom`, so both buttons stay fully visible at all four sizes (99×54: yes (46, 25, 16, 3), no (64, 25, 16, 3)); the body is clipped instead. Two mutants that do go RED (`probe_p10_ga2`): `min-width: 120` on `#confirm_box` → at 99×54 `#confirm_yes` visible width 14 of 16 and `#confirm_no` 0 of 16; height 7 with `#confirm_buttons` undocked → both buttons 0 visible rows. See P-GA10-2.
- **K10.** Reader over the writers (runtime property, probe 3): fresh `False`; w1 `request_action("add_entry")` → `True`; w3 `mark_saved()` → `False`; `request_action("validate_doc")` (not a writer) → `False`; w2 typing `x` in `#patch_paste_text` → `True`; w4 `mark_loaded()` → `False`; w5 `mark_pasted()` → `True`; `mark_loaded()` then `clear_paste_buffer()` (not a writer) → `False`. `panel.is_dirty = True` → `AttributeError: property of 'PatchEditorPanel' object has no setter`, `_dirty` unchanged; `fset is None`.
- **K11.** Names checked in `textual/` (8.2.8, `grep -rn "\b<name>\b"`): `_dismissed` 0, `_question_title` 0, `_question_body` 0, `_yes_label` 0, `_no_label` 0, `action_answer` 0, `_close` 2 (both are markdown token strings, not attributes). `title` **is** taken: `Screen.title` is a `Reactive[str | None]` (`screen.py:236`). See R-GA10-1.

**Fixtures used by the examples.**
- `LOADQ` = (`"Replace fw.s19?"`, `"There are unsaved changes in fw.s19. Load b.s19 anyway?"`, `"Replace (y)"`, `"Cancel (n)"`) — the 1-item load question as G-B's composer builds it (interfaces Q-3).
- `QUITQ` = (`"Quit?"`, `"A save is running."`, `"Quit (y)"`, `"Stay (n)"`) — LLR-174.2a's quit arm.
- `HOSTILE` = (`"[b]Quit?"`, `"A save is [red]running[/red]."`, `"[b]Quit (y)"`, `"Stay (n)"`).
- `LONG120` = `"n"*119 + "…"` (U+2026), the clip `painted_names` gives a 130-character name (p10b U0). `LONGQ` = (`"Replace " + LONG120 + "?"`, `"There are unsaved changes in " + LONG120 + ", Patch Editor entries and flow " + LONG120 + ". Load project " + LONG120 + " anyway?"`, `"Replace (y)"`, `"Cancel (n)"`) — the 3-item, longest-name question.
- `CB` = a list the dismiss callback appends to (`push_screen(ConfirmQuestionScreen(*args), CB.append)`).
- "Painted" text = `str(widget.visual)` for `Label` / `Static`, `button.label.plain` for a `Button`; "0 spans" = `len(...spans) == 0`.
- "Fully visible" = for `geo = screen.find_widget(w)`: `geo.region == geo.region.intersection(geo.clip)` and `screen.region.contains_region(geo.region)`.

**Counts.**
- **8 nodes:** 5 new code nodes for `ConfirmQuestionScreen` (Q1 `__init__` + class attributes, Q2 `compose`, Q3 `on_button_pressed`, Q4 `action_answer`, Q5 `_close`), 1 new property (P1 `PatchEditorPanel.is_dirty`), 1 changed comment (P2), 1 unchanged-stylesheet record (C1). 1 retired node (I1: the `textual.content` import, dropped by P-GA10-1 Option A).
- 2 entities, 37 example lines.
- 4 design decisions (D-GA10-1 … D-GA10-4), 6 risks (R-GA10-1 … R-GA10-6), 9 seams (SB-1 … SB-9).
- 2 proposals to the orchestrator (P-GA10-1, P-GA10-2), 0 proposed interface changes adopted on our own.
- G-A requirements without an example: 0 (table at the end).
- Source files G-A touches: `screens.py`, `screens_directionb.py`. `styles.tcss`: 0 changes (ruling Q-6 probed, K8). Slice with G-B's `app.py`: 3 files.

## Nodes

ConfirmQuestionScreen.__init__ (+ class attributes)
req: HLR-174, LLR-174.2, LLR-174.2a, LLR-174.2b, LLR-174.2c, LLR-174.2d, LLR-174.2g, LLR-174.2h
in: str title; str body; str yes_label; str no_label
out: ConfirmQuestionScreen (a `ModalScreen[bool]`)
func: new (S-a, fixed signature, positional), placed in `screens.py` right after `ConfirmDiscardScreen` and before `SelectVariantScreen`.
  - **Class attributes.**
    - `AUTO_FOCUS = "#confirm_no"` (LLR-174.2b).
    - `BINDINGS = [Binding("y", "answer(True)", show=False), Binding("n", "answer(False)", show=False), Binding("escape", "answer(False)", show=False)]`. Nothing else at screen level: no `enter` (the focused `Button` owns it, p10b U0, LLR-174.2e), no `s` (VS-PB-2), no catch-all (K4: a modal already stops the non-priority app keys, LLR-174.2g). No `priority=True` binding (D-GA10-3).
  - **`__init__`** calls `super().__init__()`, then stores the four arguments as `_question_title`, `_question_body`, `_yes_label`, `_no_label`, and sets `_dismissed = False`. Never `self.title` (R-GA10-1, K11). Never `_closed` / `_closing` (9b R-GA-1). The arguments are already-painted plain `str`; the screen neither scrubs nor rewrites them (SB-5).
  - Docstring in the codebase's Summary / Args / Dependencies shape: "Used by: `S19TuiApp._confirm_then_load` (the load question); Inc 12 builds the quit question from it."
  - The class references nothing from `app.py`, `s19_app.tui.services.*` or `s19_app.tui.workspace` (S-a).
module: s19_app/tui/screens.py
examples: [Q1-1] (LLR-174.2, HLR-174) `ConfirmQuestionScreen(*LOADQ)` pushed on `S19TuiApp` at 118×54 → stack grows by 1 to `['Screen', 'ConfirmQuestionScreen']`; 2 `Button`s with ids `confirm_yes`, `confirm_no`; 0 other buttons; 0 `Input` / `TextArea` (4 of 4; probe p10-ga K1). RED if: the `pb_B` variant adds `Button("Save first (s)", id="confirm_save")` → 3 buttons (target (10))
examples: [Q1-2] (LLR-174.2b, HLR-174c) the same push → `app.focused.id == "confirm_no"` (K1). RED if: `AUTO_FOCUS = "#confirm_yes"` → `confirm_yes`; also RED: no `AUTO_FOCUS` (the `ConfirmDiscardScreen` shape, p10b U12: the first button gets the focus) → `confirm_yes` (target (10))
examples: [Q1-3] (LLR-174.2g, LLR-174.2 VS-PB-2) open with `LOADQ`; press `a`, `l`, `p`, `s`, `q`, `space`, `?`, `v` → stack still `['Screen', 'ConfirmQuestionScreen']` (0 screens pushed), `CB == []`, focus `confirm_no` (8 of 8; K4). RED if: the `pb_B` binding `Binding("s", "save_first")` → `s` leaves the question; RED if: a `Binding("space", "answer(True)")` → `space` closes it (target (10))
examples: [Q1-4] (LLR-174.2h, G-A share; seam SB-3) with `check_action` extended by S-f (`ConfirmQuestionScreen` in the whole-stack test), focus on `#confirm_no` and then on `#confirm_yes`: `ctrl+l`, `ctrl+s`, `ctrl+k`, `ctrl+d` → `0` calls of `action_load_file`, `action_save_project`, `action_focus_palette`, `action_cycle_density` (spies); stack `['Screen', 'ConfirmQuestionScreen']`; `CB == []`; focus unchanged (2 × 4; K5 modelled). RED if: S-f not applied (base `check_action`) → `ctrl+l` runs `load_file` and the stack becomes `['Screen', 'ConfirmQuestionScreen', 'LoadFileScreen']` (executed, K5 base) (target (10))
examples: [Q1-5] (LLR-174.2a, S-a) a spy on the four constructor arguments: `ConfirmQuestionScreen(*QUITQ)` stores them unchanged (`_question_title == "Quit?"` …); `screen.title is None` (the `Screen.title` reactive is not touched). RED if: `self.title = title` → `screen.title == "Quit?"` (R-GA10-1) (target (10))
examples: [Q1-6] (S-a) AST census of the `ConfirmQuestionScreen` class body → 0 names bound to imports from `s19_app.tui.app`, `s19_app.tui.services`, `s19_app.tui.workspace`. RED if: a mutant that calls `painted_names` inside the screen → census 1 (target (10))

ConfirmQuestionScreen.compose
req: HLR-174, HLR-174d, LLR-174.2, LLR-174.2a, LLR-174.2i, LLR-174.2p, LLR-174.2q, LLR-174.2r, LLR-173.7
in: (self) `_question_title`, `_question_body`, `_yes_label`, `_no_label`
out: ComposeResult (one widget tree)
func: new. Yields exactly one tree, in this DOM order (the order is the `tab` order, K2):
  - `Container(id="confirm_box", classes="modal-dialog")` holding:
    - `Label(self._question_title, id="confirm_title", classes="modal-title", markup=False)`;
    - `Static(self._question_body, id="confirm_body", markup=False)`;
    - `Container(id="confirm_buttons", classes="modal-buttons")` holding:
      - `Button(Text(self._yes_label), id="confirm_yes", classes="modal-confirm")`;
      - `Button(Text(self._no_label), id="confirm_no")`.
  - Every text widget paints with markup off. A `Button` parses a `str` label as markup (`Button.validate_label` → `Content.from_text`, K6), so each label is passed as `rich.text.Text` (P-GA10-1 Option A), which paints literally with 0 new modules; `Text` is already imported (`screens.py:10`).
  - Outer id `#confirm_box`, never `#load_dialog` (8 modals share it) nor `#load_box` (9b's) (S-g).
  - Style comes only from the shared rules: `.modal-dialog` (`width: 70%`, `height: auto`, accent border, panel background, `padding: 1 2`), `.modal-title`, `.modal-buttons` (`dock: bottom`, right-aligned), `.modal-confirm` (the accent on `#confirm_yes`). No new selector (C1, ruling Q-6, K8).
  - The screen paints no string of its own: all 4 painted strings arrive as parameters (D-GA10-2).
module: s19_app/tui/screens.py
examples: [Q2-1] (LLR-174.2a, LLR-174.2p G-A share) `ConfirmQuestionScreen(*LOADQ)` → painted `#confirm_title` `Replace fw.s19?`; `#confirm_body` `There are unsaved changes in fw.s19. Load b.s19 anyway?`; `#confirm_yes` `Replace (y)`; `#confirm_no` `Cancel (n)` (4 of 4; K1). RED if: labels swapped onto the ids (`Button(Text(no_label), id="confirm_yes")`) → `#confirm_yes` paints `Cancel (n)` (target (10))
examples: [Q2-2] (LLR-174.2a) `ConfirmQuestionScreen(*QUITQ)` → painted `Quit?`, `A save is running.`, `Quit (y)`, `Stay (n)`; the substring `Replace` occurs 0 times across the 4 painted strings (5 of 5 with the count; K6). RED if: a mutant that hard-codes `Button("Replace (y)", id="confirm_yes")` → the quit arm paints `Replace (y)`, count 1 (target (10))
examples: [Q2-3] (LLR-174.2i G-A share, Q-1) `ConfirmQuestionScreen(*HOSTILE)` → title `[b]Quit?` with 0 spans; body `A save is [red]running[/red].` with 0 spans; `#confirm_yes` `[b]Quit (y)` with 0 spans (3 of 3; K6). RED if: `Button(self._yes_label, …)` (a `str` label) → `#confirm_yes` paints `Quit (y)` with 1 span (executed, K6); RED if: `Label(title, markup=True)` → `Quit?` (target (10))
examples: [Q2-4] (LLR-174.2i G-A share; seam SB-5) title `Replace ab.s19?` built by G-B from a name holding U+202E (`painted_names(["a\u202eb.s19"]) == "ab.s19"`, p10b U0) → painted exactly `Replace ab.s19?`, 15 characters, 0 U+202E. G-A passes the text through unchanged; the scrub is G-B's (target (10))
examples: [Q2-5] (LLR-174.2r, ruling Q-6) `ConfirmQuestionScreen(*LONGQ)` at 99×54, 118×54 and 220×60, and `LOADQ` at 118×54 → `#confirm_yes` and `#confirm_no` fully visible at each size: 99×54 yes (46, 32, 16, 3), no (64, 32, 16, 3); 118×54 yes (62, 31, 16, 3), no (80, 31, 16, 3); 220×60 yes (149, 32, 16, 3), no (167, 32, 16, 3); 118×54 short yes (62, 27, 16, 3), no (80, 27, 16, 3) (4 of 4; K8). RED if: `#confirm_box { min-width: 120; }` → at 99×54 `#confirm_no` visible width 0 (executed, K9). NOT RED: E1's `#confirm_box { height: 7; }` mutant leaves both buttons fully visible (executed, K9; P-GA10-2) (target (10))
examples: [Q2-6] (LLR-174.2r, layout record) `#confirm_box` regions with `LONGQ`: 99×54 (16, 17, 67, 20), body 10 rows; 118×54 (18, 18, 81, 18), body 8 rows; 220×60 (34, 23, 152, 14), body 4 rows; the title row is 1 high at each width (`Label` clips the 129-character title, no wrap) (K8). RED if: a mutant that sets `#confirm_box { height: 7; }` → body visible rows 1 or fewer while the buttons stay (the body clip is not a requirement; recorded, R-GA10-2) (target (10))
examples: [Q2-7] (LLR-174.2q, HLR-174d G-A share) `#confirm_body` is exactly 1 `Static` and paints the body argument verbatim: with the 3-item body of `LONGQ` → `str(visual)` equals the argument character for character, `unsaved changes` occurs once, sentence ends `.` / `?` outside names = 2. The count rule is G-B's; G-A promises no split, no reflow of text, no added punctuation. RED if: a mutant that yields one `Static` per sentence → 2 body widgets (target (10))
examples: [Q2-8] (LLR-173.7, TC-B100-66 G-A share) the regexes `\bD\d+\b`, `\bO-\d+`, `VS-`, `LLR-`, `HLR-` over every string literal in the `ConfirmQuestionScreen` class body that reaches a widget → 0 literals (the screen paints only its parameters), so 0 matches; with `QUITQ` and `LOADQ` → 0 matches over the painted text. RED if: a mutant that paints `VS-PB-1` as a hint → 1 match (target (10))

ConfirmQuestionScreen.on_button_pressed
req: LLR-174.2e, LLR-174.2f, HLR-174b, HLR-174c
in: Button.Pressed event
out: None (`_close(True)` / `_close(False)`)
func: new. `event.stop()`; `confirm_yes` → `self._close(True)`; `confirm_no` → `self._close(False)`; any other id → nothing (there is none). Triggers: a click (LLR-174.2f) and `enter` on the focused button, through `Button`'s own `enter` → `press` binding (p10b U0; LLR-174.2e). `event.stop()` keeps the message from bubbling to the app.
module: s19_app/tui/screens.py
examples: [Q3-1] (LLR-174.2f, HLR-174b) a click on `#confirm_yes` → `CB == [True]`, stack `['Screen']`; a click on `#confirm_no` → `CB == [False]` (2 of 2; K3). RED if: no `on_button_pressed` (a mutant that ignores `Button.Pressed`) → the click leaves the question open, `CB == []` (target (10))
examples: [Q3-2] (LLR-174.2e, HLR-174c) immediate `enter` → `CB == [False]`; `tab`, `enter` → focus trail `confirm_yes`, `CB == [True]`; `tab`, `tab`, `enter` → trail `confirm_yes`, `confirm_no`, `CB == [False]` (3 of 3; K2). RED if: a screen-level `Binding("enter", "answer(True)")` → the immediate `enter` gives `True` (target (10))
examples: [Q3-3] (LLR-174.2e boundary) `shift+tab`, `enter` → `CB == [True]` (the chain wraps backward to `#confirm_yes`; K2). RED if: `confirm_yes` built with `can_focus=False` → `shift+tab` stays on `confirm_no`, `CB == [False]` (target (10))
examples: [Q3-4] (HLR-174c, LLR-174.2e) a `y` binding press after the focus moved to `#confirm_yes` by `tab` still gives `True`, and `enter` with the focus on `#confirm_no` gives `False`: the answer depends on the key or the focused button, never on the other (see [Q4-1]) (target (10))

ConfirmQuestionScreen.action_answer
req: LLR-174.2c, LLR-174.2d, HLR-174b, HLR-174c
in: bool value
out: None (`_close(value)`)
func: new. `self._close(value)`. Reached only through the three screen bindings; Textual parses `answer(True)` / `answer(False)` as a `bool` literal. `escape` is bound here even though no label shows it (LLR-174.2d); `y` and `n` are the keys the labels show (the "every shown key is verified" rule, §3 preface).
module: s19_app/tui/screens.py
examples: [Q4-1] (LLR-174.2c, HLR-174b) `y` with the focus on `#confirm_no` → `CB == [True]`; `y` with the focus on `#confirm_yes` → `CB == [True]` (2 of 2; K2). RED if: no `y` binding → the question stays open, `CB == []` (target (10))
examples: [Q4-2] (LLR-174.2d, HLR-174c) `n` and `escape`, each with the focus on `#confirm_no` and on `#confirm_yes` → `CB == [False]` four times, stack `['Screen']` each time (4 of 4; K2). RED if: no `escape` binding (the `ConfirmDiscardScreen` P-18 shape, p10b U12) → `escape` leaves the stack ending in the question, `CB == []` (target (10))
examples: [Q4-3] (LLR-174.2a quit arm) `ConfirmQuestionScreen(*QUITQ)`, `y` → `CB == [True]`; a fresh one, `n` → `CB == [False]` (2 of 2; K6). RED if: a mutant binding `y` to `answer(False)` → `[False]` (target (10))
examples: [Q4-4] (S-a: never `None`) over [Q3-1], [Q3-2], [Q4-1], [Q4-2] → every value delivered to `CB` is a `bool` (11 values, 0 `None`). RED if: an `escape` mapped to `dismiss()` with no argument → `None` delivered (target (10))

ConfirmQuestionScreen._close
req: Q-5 (A9b-02 copied), LLR-174.2c, LLR-174.2d, LLR-174.2e, LLR-174.2f
in: bool result
out: `dismiss(result)` once
func: new helper, the only way out:
  1. `if self._dismissed: return` (ruling Q-5: the first line);
  2. `self._dismissed = True`;
  3. `self.dismiss(result)`.
  Textual's `dismiss` calls the result callback and then `app.pop_screen()` every time it is called (`screen.py:2048-2081`), so without step 1 a second queued answer pops the screen under the question (K7). The screen writes no file and calls nothing of the app; the continuation is G-B's (SB-2).
module: s19_app/tui/screens.py
examples: [Q5-1] (Q-5) `scr._close(True); scr._close(False)` in one tick → `CB == [True]`, stack `['Screen']`, 0 exceptions (K7). RED if: step 1 removed → `ScreenStackError: Can't pop screen; there must be at least one screen on the stack` (executed, K7) (target (10))
examples: [Q5-2] (Q-5, key path) `y`, `n` queued while the loop is busy → 1 answer (`True`), 1 pop. RED if: step 1 removed → a second pop attempt (as [Q5-1]) (target (10))
examples: [Q5-3] (9b R-GA-1 carried over) the flag is named `_dismissed`: `escape` returns from `pilot.press` and `CB == [False]`. RED if: renamed `_closed` (a `MessagePump` attribute, 9b K11) → `escape` hangs → RED by timeout (target (10))

PatchEditorPanel.is_dirty
req: LLR-174.1c, LLR-174.1b, LLR-174.2m, LLR-167.8
in: (self) `_dirty`
out: bool dirty
func: new (S-c), a read-only property placed right after `mark_pasted` (the last writer), copying `FlowBuilderPanel.is_dirty` (`flow_screens.py:1353-1356`):
  ```
  @property
  def is_dirty(self) -> bool:
      """Whether either editor region holds unsaved edits (LLR-174.1c).

      The one reader of ``_dirty`` outside this module: the app's load
      guard and ``_handle_save_dialog`` read it here, never the private
      attribute. No setter: only the five writers change the flag.
      """
      return self._dirty
  ```
  No setter, no side effect, no repaint. The in-module readers (the doc-load guard `on_button_pressed`, the marker `_refresh_dirty_indicator`, the JSON stamp, the ledger subtitle) keep reading `self._dirty` (LLR-174.1c counts reads outside the module only; surgical change).
module: s19_app/tui/screens_directionb.py
examples: [P1-1] (LLR-174.1c) the reader follows the writers: fresh `False`; w1 `request_action("add_entry")` → `True`; w3 `mark_saved()` → `False`; w2 typing `x` in `#patch_paste_text` → `True`; w4 `mark_loaded()` → `False`; w5 `mark_pasted()` → `True` (5 writer transitions of 5; K10). RED if: the property returns a cached value set in `__init__` → stays `False` after w1 (target (10))
examples: [P1-2] (LLR-174.1c boundary) not writers: `request_action("validate_doc")` after `mark_saved()` → `False`; `mark_loaded()` then `clear_paste_buffer()` → `False` (2 of 2; K10). RED if: a mutant property `return self._dirty or bool(buffer.text)` → `True` while text stays in the buffer after `mark_loaded` (target (10))
examples: [P1-3] (LLR-174.1c, S-c "no setter") `panel.is_dirty = True` → `AttributeError: property of 'PatchEditorPanel' object has no setter`, `_dirty` unchanged; `PatchEditorPanel.is_dirty.fset is None` (2 of 2; K10). RED if: a setter is added → the assignment flips `_dirty` (target (10))
examples: [P1-4] (LLR-174.1c, base) `hasattr(PatchEditorPanel, "is_dirty")` → `False` on `8947666` (p10b U0) → `True` after Inc 10. RED side: base (target (10))
examples: [P1-5] (LLR-174.1c census half, seam SB-4) AST of `s19_app/` outside `screens_directionb.py` → 0 `Attribute(attr="_dirty")` reads on a `PatchEditorPanel` value; on base 1 (`app.py:10576`, E1 p10). The `app.py` edit is G-B's; G-A supplies the reader (target (10))
examples: [P1-6] (compatibility) the 10 test files that read or write `panel._dirty` directly (`test_tui_patch_editor_b94.py:941` writes `panel._dirty = False`) still pass: the property reads the same attribute, and writing `_dirty` is untouched (code read, `grep -rn "_dirty" tests/*.py`, this session) (target (10))
examples: [P1-7] (LLR-174.2j, unchanged route) `_dirty = True`, `#patch_doc_load_button` pressed → stack `['Screen', 'LoadGuardScreen']`, 0 `ConfirmQuestionScreen` (p10b U13; the panel's own doc-load guard still reads `self._dirty` in-module). RED if: a mutant routing `DirtyLoadRequested` through the question → 0 `LoadGuardScreen` (G-B side) (target (10))

PatchEditorPanel.__init__ `_dirty` attribute comment (changed comment only)
req: LLR-174.1c (S-c), E1 §5
in: —
out: —
func: changed, comment only, no code. `screens_directionb.py:4808-4815` becomes:
  ```
  #: The dirty flag (batch-94, LLR-005.1). Set while unsaved edits exist
  #: in EITHER editor region (the entries or the paste buffer); cleared
  #: by a successful save or load. Readers in this module: the Load guard,
  #: the ledger's border subtitle and the JSON stamp (batch-97 D4).
  #: Outside this module it is read only through ``is_dirty``
  #: (LLR-174.1c): the app's load guard and ``_handle_save_dialog``.
  #: Writer census (C-15.1, five sites): w1 ``request_action`` (entry
  #: edit) · w2 ``on_text_area_changed`` (paste typing) · w3
  #: ``mark_saved`` · w4 ``mark_loaded`` · w5 ``mark_pasted`` (Parse
  #: pasted, batch-97 Inc-4).
  ```
  `clear_paste_buffer` is not a writer (it prevents `TextArea.Changed`) and is not listed.
module: s19_app/tui/screens_directionb.py
examples: [P2-1] (S-c) `grep -c "exactly four sites" s19_app/tui/screens_directionb.py` → 0 (base 1, `:4812`); `grep -c "w5 \`\`mark_pasted\`\`" …` → 1. RED if: the comment is left as is → 1 (target (10))
examples: [P2-2] (no regression) no test pins the comment text (`grep -rn "exactly four sites\|four sites" tests/` → 0 hits; `test_tui_patch_editor_b94.py` names `C-15.1` only in docstrings, `:44`, `:881`) (code read, this session) (target (10))

C1 `styles.tcss` (unchanged; ruling Q-6 record)
req: LLR-174.2r, ruling Q-6
in: —
out: —
func: unchanged. The question takes `.modal-dialog` (`width: 70%`, `height: auto`) and `.modal-buttons` (`dock: bottom`). The probe found no clip at 99, 118 or 220 columns (K8), nor at 99×24 / 80×24, so no `#confirm_box` selector is added and `styles.tcss` leaves the slice (3 source files). The `pb_A` widths (`width: 60%; max-width: 72; min-width: 44`) are not copied. If E4's layout arm clips anyway, the one selector to propose is `#confirm_box { max-height: 100%; }`; not needed on this evidence.
module: s19_app/tui/styles.tcss
examples: [C1-1] (Q-6) `git diff --stat 8947666.. -- s19_app/tui/styles.tcss` after Inc 10 → empty for Inc 10's own commits; `grep -c "confirm_box" s19_app/tui/styles.tcss` → 0 (target (10))
examples: [C1-2] (LLR-174.2r) the regions of [Q2-5] hold with the stylesheet unchanged (K8) (target (10))
examples: [C1-3] (no regression) `ConfirmDiscardScreen` and `LoadGuardScreen` keep their regions: neither carries `#confirm_box` and no rule changed (code read) (target (10))

## Entities

[state: question dismissed]
desc: `ConfirmQuestionScreen._dismissed` (bool, starts `False`). The guard copied from 9b (Q-5): `_close` returns at once when it is already set, so two queued answers dismiss once and pop once.
sequence:
  answer: Q4 `action_answer` (y / n / escape) or Q3 `on_button_pressed` (click / enter) → Q5 `_close` (if `_dismissed`: return; else `_dismissed = True`) → `dismiss(bool)` → G-B `answer` callback (SB-2) (!)

[Data: PatchEditorPanel._dirty] (changed readers)
desc: W. Writers unchanged: w1 `request_action`, w2 `on_text_area_changed`, w3 `mark_saved`, w4 `mark_loaded`, w5 `mark_pasted`. In-module readers unchanged (read `_dirty`). Outside readers after Inc 10: only through P1 `is_dirty` — G-B's `_load_would_lose` (new) and `_handle_save_dialog` (was the private read at `app.py:10576`).
sequence:
  write: w1 | w2 | w3 | w4 | w5 → `_dirty`
  read: P1 `is_dirty` → G-B `_load_would_lose` (`document` item) · G-B `_handle_save_dialog` (!)

## Callers checked against the baseline extractor

| Node | Callers after Inc 10 | Baseline (`extract-baseline/extract.json`, `baseline-10.md`) | Verdict |
|---|---|---|---|
| Q1 `ConfirmQuestionScreen.__init__` | G-B `_confirm_then_load` (`push_screen`, new); Inc 12 quit question (later) | new class, no baseline caller | consistent; 1 new caller, G-B's |
| Q2 `compose` | framework | `ConfirmDiscardScreen.compose`: none listed (framework) — same kind | consistent |
| Q3 `on_button_pressed` | framework (`Button.Pressed`) | `LoadGuardScreen.on_button_pressed`: none listed (framework) — same kind | consistent |
| Q4 `action_answer` | the 3 screen bindings (Textual `run_action`) | n/a (new) | consistent; extractor cannot see bindings (baseline-notes "Calls the extractor cannot see") |
| Q5 `_close` | Q3, Q4 only | n/a (new) | consistent |
| P1 `PatchEditorPanel.is_dirty` | G-B `_load_would_lose` (new), G-B `_handle_save_dialog` (property read) | `[Data: PatchEditorPanel._dirty]`: one outside reader, `app.py:10576` (`_handle_save_dialog`, private); the extractor lists no property reads | the one baseline outside reader moves to P1; 0 other outside readers (`grep -n "\._dirty" s19_app/tui/*.py` outside `screens_directionb.py` and the Flow panels: 1 hit, `app.py:10576`) |
| P2 comment | — | — | — |
| writers w1–w5 (unchanged, context) | `PatchEditorPanel.on_button_pressed` → `request_action` (:5795, :5811); `_handle_save_dialog` → `mark_saved` (:10572) + `app.py:4036`; `_reset_project_session` → `mark_loaded` (:11535) + `app.py:6177`; `app.py:3982` → `mark_pasted` | same lines in the baseline | unchanged by G-A |
| `LoadGuardScreen` (context, unchanged) | `on_patch_editor_panel_dirty_load_requested` (dismiss callback `_answer`) | none listed (dismiss callback) | unchanged (LLR-174.2j) |
| `ConfirmDiscardScreen` (context, unchanged) | `app.py:3449` (the Flow Builder's own Load) | `app.py:3449` | unchanged; not reused (E2-rulings) |

## Seams with G-B (`app.py`)

| Id | Seam | G-A promise | G-B duty | Examples naming it |
|---|---|---|---|---|
| SB-1 | constructor (S-a) | `ConfirmQuestionScreen(title, body, yes_label, no_label)`, 4 positional `str`; paints them verbatim with markup off; ids `#confirm_box`, `#confirm_title`, `#confirm_body`, `#confirm_buttons`, `#confirm_yes`, `#confirm_no` | push it from `_confirm_then_load` with `("Replace (y)", "Cancel (n)")` (LLR-174.2p) and the composer's `(title, body)`; import it from `.screens` in the `app.py` import list next to `ConfirmDiscardScreen` (`app.py:77`); no `__init__.py` export (keeps the slice at 3 files) | Q1-1, Q2-1 |
| SB-2 | dismiss value | exactly one `bool` per question, never `None`: `True` = replace (`y`, click / `enter` on `#confirm_yes`), `False` = cancel (`n`, `escape`, click / `enter` on `#confirm_no`); the callback runs through `call_next` after the pop | `True` → `call_after_refresh(go)` so the question has popped before the load (S-b); `False` → `_rehome_focus_after_load()` only, 0 status lines (Q3) | Q3-1, Q4-1, Q4-2, Q4-4, Q5-1 |
| SB-3 | priority keys (S-f) | the screen binds none of `ctrl+l` / `ctrl+s` / `ctrl+k` / `ctrl+d`; with the keys inert, the forwarded key reaches a `Button`, which binds none of them (K5): no field edit, unlike 9b R-GA-3 | `check_action`: `action in _LOAD_DIALOG_INERT_ACTIONS and any(isinstance(s, (LoadDialog, ConfirmQuestionScreen)) for s in self.screen_stack)` → `False` (LLR-174.2h) | Q1-4 |
| SB-4 | the public reader (S-c) | `PatchEditorPanel.is_dirty`, read-only, follows the five writers | replace `panel._dirty` at `app.py:10576` with `panel.is_dirty`; read W only through it in `_load_would_lose`; a panel that is not mounted counts as not dirty (S-e) | P1-1 … P1-5 |
| SB-5 | painted text (LLR-174.2i, .2k–.2o, .2q) | no scrub, no rewrite, no split; 0 own strings | compose title and body through `painted_names` (the batch's one scrub), the `Q-3` sentence, `unsaved changes` once, ending `Load <target> anyway?` | Q2-1, Q2-3, Q2-4, Q2-7 |
| SB-6 | labels (LLR-174.2p) | each label painted on its id, `rich.text.Text` (Q-1) | pass `Replace (y)` / `Cancel (n)` in that order | Q2-1 |
| SB-7 | focus after close (LLR-166.1 Inc 10 arm) | `dismiss` pops the screen; Textual restores the main screen's last focus; the question moves no focus outside itself | on `False`, `_rehome_focus_after_load()` (TC-B100-12: an `Input` focus re-homed, a healthy focus kept) | Q4-2 |
| SB-8 | one modal per request (LLR-174.4a) | a question never pushes a screen of its own (Q1-3: 0 pushes while open) | the seam sits in the four leaves, once per request (S-d) | Q1-3 |
| SB-9 | the 9b import census (TC-B100-64 arm 2) | labels are `rich.text.Text` (`Text` is already imported at `screens.py:10`), so `screens.py` gains 0 modules | none; TC-B100-64 arm 2 stays green | Q2-3 |

## Findings

### Design decisions taken inside the interface (no interface change)

- **D-GA10-1** The four constructor arguments are stored as `_question_title`, `_question_body`, `_yes_label`, `_no_label`: names checked free in Textual 8.2.8 (K11). `title` is a `Screen` reactive and is never assigned (R-GA10-1).
- **D-GA10-2** The screen owns 0 painted literals. Every painted string arrives as a parameter, so LLR-173.7's scan of the question is a scan of G-B's composer plus the quit arm's caller, and the modal is reusable for Inc 12 without edits (LLR-174.2a).
- **D-GA10-3** No `priority=True` binding on the screen. `y` / `n` / `escape` are ordinary screen bindings; the four app priority keys are made inert by G-B's `check_action` (S-f), the same mechanism 9b uses, not by shadow bindings in G-A.
- **D-GA10-4** `is_dirty` sits after `mark_pasted` and in-module readers keep `self._dirty` (surgical; LLR-174.1c counts outside reads only). `LoadGuardScreen` and the panel's doc-load guard are byte-identical (LLR-174.2j).

### Design risks

finding R-GA10-1 Storing the title as `self.title` would set the screen's title reactive
anchor: Q1 `__init__`; Textual `screen.py:236` (`title: Reactive[str | None]`), K11
seen: `Screen.title` overrides the app title while the screen is active (Textual docs in `screen.py:209-221`).
effect: the app header (if shown) would read the question's title; the attribute name looks natural and would pass a quick review.
decision: D-GA10-1; example [Q1-5] guards it.

finding R-GA10-2 Under a fixed box height the body is clipped silently while the buttons stay
anchor: Q2 compose; C1; K9
seen: `.modal-buttons` is `dock: bottom`, so a short box keeps both buttons and cuts the body (99×54, height 7: body visible 1 row or fewer).
effect: no requirement covers the body's visibility; LLR-174.2r only guards the buttons. With `height: auto` (the shared rule) the body is fully visible at every probed size, down to 80×24.
decision: keep `height: auto` (no new selector). P-GA10-2 asks for a negative control that actually goes RED; adding "the body fully visible" to LLR-174.2r is offered as an option there.

finding R-GA10-3 The `Content` import trips 9b's import census
anchor: I1; 9b LLR-173.6l / TC-B100-64 arm 2
seen: `screens.py` does not import `textual.content` on `8947666` (`grep -n "Content" s19_app/tui/screens.py` → 0 hits).
effect: TC-B100-64's "0 new modules over the 9a tree" arm goes RED at Inc 10 if Q-1 stays `Content`. It is not in baseline-notes' breaking census (that test does not exist on `8947666`).
decision: P-GA10-1.

finding R-GA10-4 A second `dismiss` pops the screen below the question
anchor: Q5; Textual `screen.py:2048-2081`; K7
seen: without the guard, two closes in one tick → `ScreenStackError`.
effect: a crash on a double answer (two queued keys, or a key plus a click).
decision: Q-5 guard, first line of `_close` ([Q5-1], [Q5-2]).

finding R-GA10-5 `enter` acts on whichever button holds the focus
anchor: Q3; LLR-174.2e
seen: after `tab`, an `enter` replaces (K2).
effect: an engineer who tabs once and presses `enter` replaces; this is the requirement's own rule (LLR-174.2e), and the focus starts on Cancel (LLR-174.2b).
decision: accept, as the requirement asks.

finding R-GA10-6 A long title is clipped to one row
anchor: Q2 compose (`Label#confirm_title`); K8
seen: with `LONGQ` the 129-character title is 1 row high at 99, 118 and 220 columns, so at 99 and 118 columns its end (the `?` and part of the name) is cut on screen. The widget's painted text still holds the whole string.
effect: LLR-174.2k's threshold reads the painted string and passes; an engineer with a 120-character project name sees a cut title. The body names the same items in full (it wraps).
decision: accept for Inc 10 (no requirement covers on-screen title width; the names are already clipped to 120 by `painted_names`). If wanted later, `#confirm_title { text-wrap: wrap; }` is one selector; not proposed now.

### Undecidable points the requirements leave open

- None for G-A. The label strings, the title and the body are G-B's (interfaces Q-3); the box size is ruled by Q-6 and the probe.

## Proposals to the orchestrator

- **P-GA10-1 (interface wording, S-a / ruling Q-1, conflict with 9b TC-B100-64).** Ruling Q-1 ("labels are plain `Content`") needs `from textual.content import Content` in `screens.py` (I1), the file's only new module. 9b's LLR-173.6l threshold, arm 2, says `screens.py` gains 0 modules over the 9a tree, so TC-B100-64 would go RED at Inc 10.
  - Option A (recommended): pass each label as `rich.text.Text(label)`. `Text` is already imported (`screens.py:10`), and `Content.from_text(Text("[b]Quit (y)"))` paints `[b]Quit (y)` with 0 spans, the same literal result (executed, [I1-2]). The intent of Q-1 (no markup on labels) is kept; the wording of S-a changes from "plain `Content`" to "a `rich.text.Text`".
  - Option B: keep `Content`, and add TC-B100-64 arm 2 to Inc 10's breaking census, re-pinned to "the post-9b set plus `textual.content`" (1 more re-pinned test).
  - Until ruled, this graph follows Q-1 (Option B's code); the switch is one import line and two constructor calls in Q2.
- **P-GA10-2 (requirement text, LLR-174.2r).** E1's negative control ("a mutation that fixes the box height at 7 rows → the 99-column arm clips the buttons") does not go RED: the buttons are docked at the bottom and stay fully visible; the body is clipped instead (executed, K9).
  - Replace the negative control with: "a mutation setting `min-width: 120` on `#confirm_box` → at 99 columns `#confirm_no` has 0 visible columns → RED" (executed, K9). The undocked-buttons-plus-height-7 mutant is a second RED control (executed).
  - Sharpen the threshold's "inside the screen region" to "fully visible: each button's region equals its clipped region and lies inside the screen region"; as written, a button cut by its own box could still be "inside the screen region".
  - Optional: add "and the body fully visible" to the threshold, which would also make the height-7 mutant RED (R-GA10-2). Not required by the current statement.
- **Proposed interface changes adopted on our own:** none.
- **Ruling Q-6 outcome:** no clip at 99 columns (K8). No `styles.tcss` selector; the slice is 3 source files.

## Requirement coverage (G-A scope)

| Requirement | Examples (node) |
|---|---|
| HLR-174 (G-A share: one modal question) | Q1-1, Q2-1 |
| HLR-174b (G-A share: replace answer) | Q3-1, Q4-1 |
| HLR-174c (G-A share: cancel answer, focus on Cancel) | Q1-2, Q3-2, Q4-2 |
| HLR-174d (G-A share: one modal, body painted whole) | Q2-7 |
| LLR-174.1b (G-A share: W readable) | P1-1 |
| LLR-174.1c (reader half; census half via SB-4) | P1-1, P1-2, P1-3, P1-4, P1-5, P1-6 |
| LLR-174.2 | Q1-1, Q1-3 |
| LLR-174.2a | Q1-5, Q2-1, Q2-2, Q4-3 |
| LLR-174.2b | Q1-2 |
| LLR-174.2c | Q4-1 |
| LLR-174.2d | Q4-2 |
| LLR-174.2e | Q3-2, Q3-3, Q3-4 |
| LLR-174.2f | Q3-1 |
| LLR-174.2g | Q1-3 |
| LLR-174.2h (G-A share: no priority binding, the screen type for S-f) | Q1-4 |
| LLR-174.2i (G-A share: markup off) | Q2-3, Q2-4 |
| LLR-174.2j (G-A share: `LoadGuardScreen` and the doc-load guard unchanged) | P1-7, C1-3 |
| LLR-174.2m (G-A share: W readable) | P1-1 |
| LLR-174.2p (G-A share: each label on its id) | Q2-1 |
| LLR-174.2q (G-A share: body verbatim in one widget) | Q2-7 |
| LLR-174.2r | Q2-5, Q2-6, C1-2 |
| LLR-167.8 (G-A share: `mark_saved` clears what `is_dirty` reads) | P1-1 |
| LLR-173.7 (G-A share: 0 own literals) | Q2-8 |
| Q-5 (`_dismissed` guard) | Q5-1, Q5-2, Q5-3 |
| S-c comment fix | P2-1, P2-2 |
| Q-6 (styles probe) | C1-1, C1-2, Q2-5 |

**Seams: requirements owned by G-B (`app.py`), with no G-A node or only a G-A share already covered above.**
- HLR-174a, LLR-174.1, LLR-174.1a, LLR-174.1b: the guard `_load_would_lose` (SB-4 reads W).
- LLR-174.2k, LLR-174.2l, LLR-174.2m, LLR-174.2n, LLR-174.2o, LLR-174.2q (count rule): the composer (SB-5).
- LLR-174.2h: `check_action` (SB-3).
- LLR-174.2i: the `painted_names` scrub (SB-5).
- LLR-174.2p: the two label literals (SB-6).
- LLR-174.3, LLR-174.3a, LLR-174.3b, LLR-174.3c: the reset order (SB-2: `go` after `True`).
- LLR-174.4, LLR-174.4a, LLR-174.4b, LLR-174.4c: placement in the four leaves (SB-8).
- LLR-165.3 (interim line removed), LLR-166.1 (focus on cancel, SB-7), LLR-167.8 (the question arm), the `_pending_variant_id` LLR-174.3d (E2-rulings).

G-A requirements without an example: 0.
