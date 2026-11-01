# E1 — Inc 10 requirements scope and E2 slice

**Run.** Stage E1 of the design-first pipeline (`dev-flow-v3-beta` skill) for Inc 10. PLAN.md row 10: "confirm before replacing unsaved work (image, project, dirty flow) — CW-U-5, O-3 — screens, app (+ styles) — gate P-B". §5.5 row 10 lists `screens.py`, `app.py`, `styles.tcss` and `screens_directionb.py`: 4 files, at the cap. Prototype verdict: P-B variant A (`pb_A`).

**Source.**
- The replacement text is `E1-requirements-draft.md` in this folder. Nothing has been merged into `01-requirements.md` yet.
- Requirement text was read from the 9a worktree (`s19_app-b100-inc9a`, `4fef292` plus 9a's uncommitted changes) on 2026-10-31. During this run that worktree was removed after Inc 9a merged (`e28edeb`). The same code and text are now `8947666` in `s19_app-b100-inc9b`, and every cited line was re-checked there. That worktree holds no 9b code yet (`class LoadDialog`: 0 hits).
- This E1 designs against the tree as it will be after 9b (`inc-9b-design/codewire/interfaces-9b.md`): `LoadDialog`, `LoadChoice`, the one router `_handle_load_dialog`, the shared work-area body `_load_workarea_file` (9b G1), and the guard `check_action` / `_LOAD_DIALOG_INERT_ACTIONS` (9b G3).
- Code is cited by symbol.

**Premises in scope.**
- P-17 (a load over a patched image asks nothing), P-32 (`LoadGuardScreen`, `ConfirmDiscardScreen`), P-42 (the Workarea pick and `v` bypass the dialog's route), P-43 (the Patch Editor flag has no public reader).
- The interim line of LLR-165.3 / LED .55(a): the only hit for "Interim, until Inc 10" in `01-requirements.md`.
- The 9b seam note on `_handle_load_dialog` ("Inc 10 inserts the load question at this seam").
- The arm extensions owed at Inc 10 by the TC / AT re-pin tables:
  - TC-B100-12 (question `n`);
  - TC-B100-70 (the project-load question arm);
  - TC-B100-72 (all four routes);
  - AT-B100-15 (written);
  - AT-B100-03 (answers `y`);
  - TC-B100-66 (the question's painted text).

**Counts.**
- **Before:** 5 requirements in scope (HLR-174; LLR-174.1 … LLR-174.4), with 14 "shall"s (HLR-174: 8; LLR-174.1: 1; LLR-174.2: 2; LLR-174.3: 2; LLR-174.4: 1; counted by script) and about 30 behaviours. HLR-174 alone holds about 12 behaviours.
- **After E1:** 36 single-"shall" requirements, all owed new at Inc 10:
  - 5 HLRs: HLR-174, HLR-174a, HLR-174b, HLR-174c, HLR-174d;
  - 31 LLRs: LLR-174.1 (+ .1a, .1b, .1c), LLR-174.2 (+ .2a … .2r, 18 suffixes), LLR-174.3 (+ .3a, .3b, .3c), LLR-174.4 (+ .4a, .4b, .4c).
- **Outside the count**, edited or extended at Inc 10 with their statements unchanged, except LLR-165.3, which loses its interim sentence:
  - LLR-165.3 (TC-B100-10: the interim line removed);
  - LLR-166.1 (TC-B100-12: question `n` / `escape`);
  - LLR-167.8 (TC-B100-70: the project-load question arm);
  - LLR-173.7 (TC-B100-66: the question's painted text).

**Per EARS form (36 in scope):** event (E) 20 · ubiquitous (U) 12 · unwanted (UW) 4 · state 0 · optional 0. Checked by script: every Statement holds exactly 1 "shall", and no other field of a requirement block holds the word.

**Base probe.** Executed on the 9a tree by this E1: `work/probe_p10.py`, with output in `work/probe_p10.out.txt` (read-only; `LOCALAPPDATA` = `work/localappdata`; the fixtures were in a temporary folder outside the repo). Decisive lines:
- `P43 public reader: hasattr(PatchEditorPanel,'is_dirty') = False | FlowBuilderPanel.is_dirty is property = True`
- `P43 private reads of panel._dirty in app.py: 1 [10576]`
- `after apply: D = True` / `MAC attach over patch: stack ['Screen'] | byte kept = True | D = True`
- `document entries after WORKAREA pick (image replace keeps the document): 1`
- `WORKAREA pick over patch: stack ['Screen'] | file = prg.s19 | patched image kept = False`
- `LOAD DIALOG router over patch: stack ['Screen'] | file = other.s19`
- `project PV loaded: stack ['Screen'] | D right after project load = False`
- `VARIANT switch over patch: stack ['Screen'] | active = firmware_b | D = False`
- `FLOW dirty across project load: is_dirty after = True` (ruling Q1)
- `table cells 24 ask 11 load 13`

**Other negative controls:**
- executed: P-17 and P-42 on `1d677ba`; the LED .17 enumeration (drop D → 5, drop F → 1, drop W → 1, an attach asking on D → 4);
- code reads: Textual 8.2.8 for LLR-174.2e (`Button` binds only `enter`) and LLR-174.2h (the priority chain);
- planned: the executed probe of LLR-174.2h, at the E2 baseline (it needs 9b's guard).

## 1 · Scope list

| Id | Statement (short) | EARS | Threshold (pass) | Negative control |
|---|---|---|---|---|
| HLR-174 | A route that would lose unsaved work asks one question before the session changes | E | 3 key routes + panel `v` (forced) → 4 questions, digest unchanged while asking | probe: 3 routes `['Screen']`; P-17 |
| HLR-174a | A load that loses nothing does not ask | E | 7 scenes → 0 questions | `pb_A` "project open asks"; attach-asks mutant |
| HLR-174b | Replace runs the load that asked | E | `y` on 4 routes → 4 loads | drop-`go` mutant |
| HLR-174c | Cancel leaves the session and kept work unchanged | E | 2 loads × 3 cancel keys → 6 unchanged, 0 status lines | focus-on-yes mutant |
| HLR-174d | One question names every unsaved item | U | 3 / 2 / 1 items | first-item-only mutant |
| LLR-174.1 | Image replacement asks iff D | E | 8 cells + 5 boundaries | drop-D (4 wrong); probe |
| LLR-174.1a | An attach never asks | E | 8 cells + patch kept after MAC / A2L | attach-on-D (4 wrong); probe `byte kept = True` |
| LLR-174.1b | A project load asks iff D, F or W | E | 8 cells (7 / 1); P open → 0; saved → 0 | drop F / W / D (1 each); `pb_A` rule |
| LLR-174.1c | The Patch Editor flag is read only through a public reader | U | AST 0 private reads; reader follows 5 writers | probe: no reader, 1 private read `:10576` |
| LLR-174.2 | One modal, exactly `#confirm_yes` / `#confirm_no` | E | +1 screen, 2 buttons, 0 inputs, 0 pushes | `pb_B` third button |
| LLR-174.2a | The modal takes title, text and labels as parameters | U | quit arm: 4 strings, `y` / `n` act | hard-coded label mutant |
| LLR-174.2b | The focus starts on `#confirm_no` | E | 4 routes | `AUTO_FOCUS` yes mutant |
| LLR-174.2c | `y` → replace | E | 2 focus positions | unbound `y` |
| LLR-174.2d | `n` / `escape` → cancel | E | 2 keys × 2 focus positions | unbound `escape` (P-18 shape) |
| LLR-174.2e | `enter` → the focused button | E | immediate / `tab` / `tab tab` | screen-level `enter` mutant |
| LLR-174.2f | A click → that button's answer | E | 2 of 2 | ignore-`Pressed` mutant |
| LLR-174.2g | Any other key keeps the question open | UW | 6 keys | `pb_B` `s` binding |
| LLR-174.2h | Priority keys inert under the question | UW | 4 keys, depth unchanged, 0 app actions | code read; probe `planned` |
| LLR-174.2i | Names painted literally | U | 5 hostile names | markup-on mutant |
| LLR-174.2j | The Patch Editor's own load keeps `LoadGuardScreen` | U | 1 guard, 0 questions | reroute mutant |
| LLR-174.2k | Title `Replace <current>?` | U | project / image / neither | image-always mutant |
| LLR-174.2l | The unsaved image named by file name | E | data and project loads | project-instead mutant |
| LLR-174.2m | `Patch Editor entries` named when W | E | W only / D only | name-on-D mutant |
| LLR-174.2n | `flow <name>` named when F | E | named / default / absent | drop-item mutant |
| LLR-174.2o | Ends `Load <target> anyway?` | U | 4 routes | current-as-target mutant |
| LLR-174.2p | Labels `Replace (y)` / `Cancel (n)` | U | 2 + 2 keys pressed | `ConfirmDiscardScreen` labels |
| LLR-174.2q | "unsaved changes", at most 2 sentences | U | 1 / 2 / 3 items | sentence-per-item mutant |
| LLR-174.2r | Both buttons on screen | U | 3 widths with 120-character names + 1 | fixed-height mutant |
| LLR-174.3 | The reset runs after the answer | E | order spy, 2 of 2 | reset-first mutant |
| LLR-174.3a | Cancel → no reset | UW | 3 cancel keys → 0 resets | reset-first mutant |
| LLR-174.3b | The project-load handler asks nothing | U | direct call → 0 questions; AST 0 pushes | guard-in-handler mutant |
| LLR-174.3c | A confirmed project load refused before the reset keeps the work | UW | 2-MAC project, `y` → 5 checks | clear-on-`y` mutant |
| LLR-174.4 | One guard for every route | U | 4 routes + AST 0 bypasses | probe; P-42 |
| LLR-174.4a | At most one question per request | E | typed project / recent / row → 1 each | double-guard mutant |
| LLR-174.4b | A typed / recent path takes its kind from the classification | E | `.mac` / `.a2l` / `.s19` / folder / refused → 0 / 0 / 1 / 1 / 0 | dismiss-kind mutant |
| LLR-174.4c | A work-area file takes its kind from its suffix | E | 4 suffixes × 2 surfaces | suffix-blind mutant |

| AT / TC | Owner | Inc 10 share |
|---|---|---|
| AT-B100-15 | HLR-174 (question half), HLR-174a (after-save half), HLR-174b (replace half), HLR-174c (keep half), HLR-174d (items half) | written: patch by keys, Load → the question names the image with the focus on Cancel; `enter` keeps the patch (hex view); `y` loads; the Workarea pick and `v` ask the same; patch + Flow Builder edits → project → both named; Save project → the same load asks nothing |
| AT-B100-03 | HLR-165 | re-pinned: answers `y`; the two interim-line assertions deleted (§C.5) |
| TC-B100-44 | LLR-174.1, LLR-174.1a, LLR-174.1b, LLR-174.1c | full |
| TC-B100-45 | LLR-174.2, LLR-174.2a … LLR-174.2r | full |
| TC-B100-46 | LLR-174.3, LLR-174.3a, LLR-174.3b, LLR-174.3c | full |
| TC-B100-72 | LLR-174.4, LLR-174.4a, LLR-174.4b, LLR-174.4c | full (Inc 12b adds the worker refusal) |
| TC-B100-10 | LLR-165.3 | the interim line removed; 2 nodes re-pinned |
| TC-B100-12 | LLR-166.1 | question `n` (an `Input` focus re-homed) and `escape` (a healthy focus kept) |
| TC-B100-70 | LLR-167.8 | the project-load question arm: 0 after Save project, 1 after a refused one |
| TC-B100-66 | LLR-173.7 | the question in 3 scenes plus the quit-parameter arm |

**29148 check.** Every requirement above is singular (1 "shall", checked by script), states a numeric threshold and a negative control, and names functions only in its trace.

Declared exceptions:
- **Shared response, several triggers.** LLR-174.2d (`n` / `escape`) and LLR-174.2f (two buttons, each with its own answer named by the button) hold OR triggers with one rule; their thresholds test each trigger. The same rule as 9b's LLR-173.2 / LLR-173.2a.
- **"If and only if".** LLR-174.1 and LLR-174.1b state both directions of one decision. Both directions are tested cell by cell (8 cells each), and HLR-174a holds the "does not ask" side at the HLR level.
- **Forced state.** The panel's `v` arm (HLR-174, LLR-174.4) sets D through a private call in a TC. By keys the panel opens only on an image just recorded as saved (probe), so no AT can reach it (ruling Q5).
- **Planned control.** LLR-174.2h's negative control is a code read; its executed probe is `planned` for the E2 baseline, after 9b's guard exists.
- **Race arm.** LLR-174.4b's refused arm (a file removed between the dialog's verdict and the routing) is made by deleting the file in the test after the dialog closes.

## 2 · Defects fixed in place (old → new)

| Defect | Old | New |
|---|---|---|
| HLR-174 compound | 1 statement, about 12 behaviours, 8 "shall"s, 1 AT | HLR-174 … HLR-174d, one "shall" each; AT-B100-15 split into halves under one id (as 9a did with AT-B100-12 and 9b with AT-B100-14) |
| LLR-174.1 compound table | 1 statement holding three kinds and the D / F / W definitions | one event per kind (LLR-174.1, .1a, .1b) and the public-reader rule (LLR-174.1c) |
| LLR-174.2 compound | 2 "shall"s with about 8 behaviours (parameters, items, focus, keys, `enter`, `safe_text`, no second modal, `LoadGuardScreen` kept) | LLR-174.2 … LLR-174.2j, one behaviour each |
| Unmeasurable | "the question shall be short and name what would be lost" | tokens: title, 3 item forms, target, labels, `unsaved changes` in at most 2 sentences (LLR-174.2k … LLR-174.2q); layout (LLR-174.2r); token row §D.3 |
| Incorrect claim (Q1) | "Flow Builder edits not saved (lost by a project load)" | probe: a project load keeps the builder's blocks and its flag → the question names the flow as holding unsaved changes, not as lost (LLR-174.2n, LLR-174.2q); clearing it is ruling Q1's alternative |
| Infeasible arm (Q5) | AT-B100-15 and LLR-174.4 "the panel's `v` → 1 question" with an unsaved patch | probe: `D right after project load = False`; the panel opens only after a project load → TC arm with a forced state, AT covers 3 key routes |
| Weaker scrub | LLR-174.2 "render names through `safe_text`" (C0 / C1 only) | `painted_names` with markup off, the batch's one scrub (LLR-174.2i) |
| Cross-increment clause | LLR-174.4 "It runs the guard (LLR-174.1) and the worker refusal (LLR-177.1)" | the worker refusal is Inc 12b's → informative note; TC-B100-72 "Extended at Inc 12b" |
| Misplaced clause | LLR-174.4 "`_handle_load_project` called directly by tests is not a route and meets no modal" | LLR-174.3b (ubiquitous, with an AST census of the handler) |
| Missing failure path | a confirmed project load then refused by `validate_project_files` (a listed folder with 2 MAC files) | LLR-174.3c: the work is kept |
| Missing failure path | priority keys under the question | LLR-174.2h (ruling Q4) |
| Missing failure path | a key outside the set | LLR-174.2g (was "invalid" in the boundary catalog only) |
| Missing requirement | how a route knows its kind: a typed `.mac` goes through `load_from_path` (`_typed_load_route` returns `data`), yet it is an attach | LLR-174.4b (classification + suffix), LLR-174.4c (work-area suffix) |
| Missing requirement | one question per request: a typed project folder passes the router, the typed-path route and the project route | LLR-174.4a |
| Missing requirement | a click on a button | LLR-174.2f |
| Stale interim (LED .55(a)) | LLR-165.3 "Interim, until Inc 10 lands the question … Inc 10 replaces this line with the question, and its test arm is re-pinned there" | the sentence removed; 0 closed-document lines; TC-B100-10 and AT-B100-03 re-pinned (ruling Q2) |
| Unnamed private read (P-43) | `app.py:10576` reads `panel._dirty` (Inc 8b E3 R1: "Inc 10 adds the panel's public dirty reader") | LLR-174.1c moves it to `PatchEditorPanel.is_dirty` |
| Missing cancel feedback decision | the prototype paints `Load cancelled: …`; the requirement is silent | HLR-174c: 0 status lines (ruling Q3) |
| Stale IFC | COMPONENT `load_question` `INPUTS: unsaved_items: list[str]`, consumer `_handle_load_dialog` | `title, body, yes_label, no_label`; consumer `_confirm_then_load` (§D.5) |

## 3 · Slice for E2

Names come from the requirements, the 9a tree and the 9b interfaces. **(guess)** marks a node the requirements imply but do not name; it may end up inline. Sources: `screens.py`, `app.py`, `styles.tcss`, `screens_directionb.py` (§5.5 row 10: 4 files, at the cap).

Tests (not capped):
- `tests/test_b100_confirm.py` (new: TC-B100-44, -45, -46, -72, AT-B100-15);
- `tests/test_b100_session_reset.py` (TC-B100-10: 2 nodes re-pinned; AT-B100-03 re-pinned);
- `tests/test_b100_focus.py` (TC-B100-12 Inc 10 arms);
- `tests/test_b100_save_image.py` (TC-B100-70 Inc 10 arm);
- `tests/test_b100_load_dialog.py` (TC-B100-66 extension; 9b's file);
- the route-caller re-pins the E2 census finds (first cut: `test_tui_patch_variant.py`, `test_b100_active_variant.py`, `test_loadfilescreen_input.py`).

### `screens_directionb.py` — 1 new node

| # | Node | What | Requirement |
|---|---|---|---|
| S1 | `PatchEditorPanel.is_dirty` (NEW, read-only property) | returns the flag; no writer changes; the docstring's reader list gains the load guard | 174.1c |

### `screens.py` — 1 new class with 3–4 methods

| # | Node | What | Requirement |
|---|---|---|---|
| Q1 | the question modal (NEW, `ModalScreen[bool]`; name is E2's, for example `ConfirmQuestionScreen`) `__init__(title, body, yes_label, no_label)` | parameters only, already-painted plain text | 174.2a |
| Q2 | `compose` | title, body (markup off), `#confirm_yes`, `#confirm_no`; outer id not `#load_dialog` | 174.2, .2i, .2p, .2r |
| Q3 | `BINDINGS` (`y`, `n`, `escape`) + `AUTO_FOCUS = "#confirm_no"` | the key contract | 174.2b, .2c, .2d, .2g |
| Q4 | `on_button_pressed` | `True` for `confirm_yes`, `False` for `confirm_no` | 174.2e, .2f |

### `app.py` — 7 changed + 2 new (+3 guesses)

| # | Node | What changes | Requirement |
|---|---|---|---|
| A1 | `S19TuiApp._confirm_then_load(kind, target, go)` (NEW, B100-I20) | runs the guard; when it asks, pushes the question and calls `go` after the modal pops on `True`; on `False` nothing, plus the cancel focus re-home | 174.1, .1a, .1b, .2, .3, .3a, .4, .4a |
| A2 | the guard `_load_would_lose(kind) -> list[item]` (NEW, guess: may be inline in A1) | D (`differs_from_last_saved(current_file.mem_map)`), F (`FlowBuilderPanel.is_dirty`), W (`PatchEditorPanel.is_dirty`) by kind | 174.1, .1a, .1b, .1c |
| A3 | the question text composer `_load_question_text(items, target)` (NEW, guess) | title, items, target, through `painted_names` | 174.2i, .2k … .2q |
| A4 | `_handle_load_dialog` (9b) | `project` → the seam (project kind), or leave it to A5; E2 picks the one placement that asks once | 174.4, .4a |
| A5 | `_route_load_project` | the seam with kind `project` before `_handle_load_project` (callers: the router, the typed-path route) | 174.1b, .3, .3a, .4 |
| A6 | `_load_path_from_user_input` | `data` → image or attach by suffix (`.mac`); `a2l` → attach; through the seam; `project` unchanged (A5 asks); `refuse` → the line, no question | 174.4b |
| A7 | `_load_workarea_file` (9b G1; `_load_from_item` is its wrapper) | the seam with kind by suffix | 174.4c, .4 |
| A8 | `_handle_select_variant` | the seam (image kind) after the descriptor checks, before `load_from_path`; covers `v` and the panel's `v` | 174.4 |
| A9 | `_handle_load_project` | delete the interim line block (`:11943-11953`); no push, no seam inside | 165.3, 174.3b |
| A10 | `_reset_project_session` (guess) | its `int` return (the discarded count) loses its one reader; keep or drop is E2's (2 tests monkeypatch it and pass the value through) | 165.3 |
| A11 | `check_action` (9b G3) | the inert set also while the question is on top | 174.2h |
| A12 | `_handle_save_dialog` (the E3 R1 read) | `panel._dirty` → `panel.is_dirty` | 174.1c |
| A13 | the cancel focus re-home (guess: `_rehome_focus_after_load` called on `False`) | LLR-166.1's question arm | 166.1 |

### `styles.tcss` — 0 or 1 selector

| # | Selector | What | Requirement |
|---|---|---|---|
| C1 | the question box (guess: its own id, for example `#confirm_box`) | width as `pb_A` (60%, max 72, min 44), `height: auto` | 174.2r |

**Node count:**
- **Firm:** `screens_directionb.py` 1; `screens.py` 4 (1 class); `app.py` 9 changed or new (A1, A4 … A9, A11, A12); `styles.tcss` 0–1.
- **With the guesses:** up to 18 code nodes.
- That is above ~8, so E2 runs by file group:
  - G-A `screens.py` + `screens_directionb.py` + `styles.tcss`: the modal, the reader and the box (6 nodes).
  - G-B `app.py`: the seam, the guard, the composer, the five route edits, the interim removal, the priority guard and the private read (9–12 nodes). If G-B must split further: G-B1 is the seam, guard and composer (A1, A2, A3, A13); G-B2 is the route edits and clean-ups (A4 … A12).
- **Source files:** 4 at most, at the cap. `styles.tcss` is touched only if LLR-174.2r needs it. `s19_app/tui/__init__.py` is not touched (the modal is imported from `s19_app.tui.screens`).

**Callers checked (9a tree; 9b changes noted):**
- `_handle_select_variant` ← the `SelectVariantScreen` dismiss in `action_select_variant` ← `v` (`BINDINGS`), the palette entry, and `_handle_load_result` (the panel's `v`). Tests: `test_tui_patch_variant.py` (direct, plus 2 monkeypatch sites), `test_tui_variants.py`.
- `_load_from_item` ← `on_list_view_selected` (`#files_list`). After 9b it wraps `_load_workarea_file`, which the dialog's `workarea` choice also calls. Tests: 3 files, 7 references.
- `_route_load_project` ← the 9b router (`project`), `_load_path_from_user_input` (`project`). Tests: 1 file, 3 references.
- `_load_path_from_user_input` ← the 9b router (`path`, `recent`), `on_mount` (the start-up `load_path`). Tests: 4 files, 19 references.
- `_handle_load_project` ← `_route_load_project` only; 13 test files call it directly (§5.4), and LLR-174.3b keeps them modal-free.
- `_reset_project_session` ← `_handle_load_project` (one call site, TC-B100-08 census). It is monkeypatched in `test_b100_project_homes.py:918` and `test_b100_recents.py:415`.
- `load_selected_file` ← `_load_from_item` / G1, and `_handle_load_project` (inside, after the seam). `load_from_path` ← `_load_path_from_user_input`, `_handle_select_variant`. `load_a2l_from_path` ← `_load_path_from_user_input`, `_load_from_item` / G1.

**Unchanged context:**
- `ChangeService.differs_from_last_saved` / `mark_saved` (`change_service.py`, Inc 5);
- `FlowBuilderPanel.is_dirty` / `current_flow` (`flow_screens.py`);
- `LoadGuardScreen` and `on_patch_editor_panel_dirty_load_requested`;
- `ConfirmDiscardScreen` (the Flow Builder's own load);
- `_typed_load_route`;
- `painted_names`;
- `_merge_mac_with_existing_primary` (it keeps the image, probe);
- `LoadResultScreen`.

**Seams to fix before E2 (in one file, by the orchestrator):**
- S-a the modal contract: `__init__(title: str, body: str, yes_label: str, no_label: str)` → `ModalScreen[bool]`, where `True` is replace. The texts arrive already painted (plain `str`); the modal paints with markup off.
- S-b `_confirm_then_load(kind: Literal["image", "attach", "project"], target: str, go: Callable[[], None]) -> None`. `go` runs through `call_after_refresh` after the question pops (as the 9b router defers), or directly when nothing is asked.
- S-c `PatchEditorPanel.is_dirty -> bool` (property).
- S-d placement: the one place per route where the seam is called, chosen so a typed project folder asks once (LLR-174.4a). Candidate: the leaves `_route_load_project`, `_load_path_from_user_input` (`data` / `a2l` only), `_load_workarea_file`, `_handle_select_variant`. The start-up `on_mount` load passes through `_load_path_from_user_input` and asks nothing, because nothing is unsaved at mount.
- S-e the item model passed to the composer: an ordered list of (kind ∈ {`image`, `document`, `flow`}, name).
- S-f the priority guard: one more screen type in 9b's `check_action` condition.
- S-g the question's outer id (not `#load_dialog`) and whether `styles.tcss` changes.

## 4 · Open questions

Recommendations and the alternatives are in `E1-rulings-proposed.md` (Q1 … Q8). The draft text follows each recommendation; a different ruling changes the ids named there.

## 5 · Observations

- **The question comes after the Load dialog has closed.** The 9b router dismisses the dialog, then routes, so on `n` the dialog does not come back, and the engineer opens Load again. No requirement asks to reopen it. If E3 wants that, it is one event requirement (and it changes the 9b router).
- **Asked, then refused.** For a project pick the project's own checks run after the answer (the question cannot sit inside `_handle_load_project`). A `y` may therefore be followed by a refusal line. LLR-174.3c makes that loss-free; the engineer sees two prompts' worth of text for one failed load.
- **An image replacement keeps the Patch Editor document** (probe: 1 entry after the Workarea pick). That is why W counts only for a project load (LLR-174.1b), as the table already says.
- **The writer census in the panel's docstring is stale.** It says "exactly four sites" (w1–w4), but `mark_pasted` (batch-97) is a fifth writer that sets the flag. LLR-174.1c's threshold tests all five. The docstring is in `screens_directionb.py`, which Inc 10 touches; fixing the comment is E2's call (same file, no requirement).
- **Unload and flow sets** lose or move unsaved work with no question. Both are outside HLR-174 (rulings Q7, Q8) and become backlog rows at the close.
- **Direct-call tests.** If E2 puts the seam inside `_handle_select_variant` or `_load_workarea_file`, a test that patches and then calls them directly meets the question. The first-cut census names `test_tui_patch_variant.py` (AT-035a/b drive `_handle_select_variant` directly). The per-node census is owed at the E2 baseline.
- **The interim line's count** came from `_reset_project_session`'s return value. Once the line is removed, that return has no reader (node A10). Two tests monkeypatch the reset and pass the value through, so dropping the return is a 2-test re-pin.
- **LLR-165.3 keeps two normative clauses** after the interim sentence is removed (the rebind; no reset method). It is Inc 3's, outside this scope, and left for the batch's EARS pass.
- **No backlog row is routed to Inc 10** (search of `.dev-flow/BACKLOG-CODE.md`). SEC9-2 touches `_load_from_item` but stays with its TOCTOU row.
- **The 9a worktree was removed mid-run** (Inc 9a merged, `e28edeb`). No probe or read was affected: the probe finished before the removal, and the cited lines were re-checked on `8947666`.
