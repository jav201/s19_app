# E1 — Inc 9b requirements scope and E2 slice

**Run.** Stage E1 of the design-first pipeline (`design-first-increment` skill) for Inc 9b (PLAN.md row 9b: "the Load dialog — Load request, D10, CW-U-12/13, markup off"; sources `screens.py`, `app.py`, `styles.tcss`).

**Source.** The replacement text is `E1-requirements-draft.md` in this folder; nothing has been merged into `01-requirements.md` yet. Requirement line numbers refer to `01-requirements.md` in the 9a tree as read on 2026-10-31. That tree is `4fef292` plus 9a's uncommitted changes, and another agent is editing it. Code is cited by symbol.

**Premises in scope.** P-18, P-19, P-20, P-24, P-30, S-07, plus the 9a rulings routed here: C4, C7, Q9, CR9-1 and CR9-11.

**Routed out.** VS-PA-4 labels → Inc 12a (Q8). The load-tail `Loaded {path.name}` status lines → backlog (Inc 12a sweep, S9b-5).

**Counts.**
- **Before:** 8 requirements in scope (HLR-173; LLR-173.1 … LLR-173.7), holding about 45 "shall"/behaviour clauses. HLR-173 alone had about 20 behaviours and 12 "shall"s. 1 9a design gap (CR9-1) and 1 9a test gap (CR9-11) are routed here.
- **After E1:** 64 single-"shall" requirements, all owed new at 9b:
  - 6 HLRs (HLR-173, HLR-173a … HLR-173e);
  - 57 LLRs under HLR-173 (LLR-173.1 … LLR-173.7 with their suffixes);
  - 1 LLR under HLR-172 (LLR-172.1n, CR9-1).
- **Outside the count:** these are extended at 9b with their text unchanged:
  - LLR-166.1 (TC-B100-12: dialog `escape`, cancelled load);
  - LLR-172.4 (TC-B100-37: the census widened, via LLR-173.4b);
  - LLR-178.3 (the panel opens from the dialog's project route, via LLR-173.1a).

**Per EARS form (64 in scope):** event (E) 27 · state (S) 2 · ubiquitous (U) 13 · unwanted (UW) 22 · optional 0. Checked by script: every Statement holds exactly 1 "shall", and no other field holds the word.

**Base probe.** None was executed at this E1. The other agent's long run owns the 9a worktree, and E1 writes nothing there. The negative controls are:
- **executed probes:** P-18, P-19 and P-20 on `1d677ba`; CR9-1 on the 9a tree (`review-increment-017.md`). `LoadFileScreen` and `LoadProjectScreen` are byte-identical at `4fef292` and in the 9a tree (`git status`: `screens.py`, `styles.tcss` unmodified).
- **code reads:** on the 9a tree, and on Textual 8.2.8 for LLR-173.2d, LLR-173.2e and LLR-173.2j.
- **executed:** LLR-173.2e's probe (S9b-1, at the E3 baseline: `ctrl+p` over the dialog, then `ctrl+s`).

## 1 · Scope list

| Id | Statement (short) | EARS | Threshold (pass) | Negative control |
|---|---|---|---|---|
| HLR-173 | Opening Load shows one dialog: path field, one list (projects, files, recents), preview pane | E | 2+2+3 rows in 3 sections; `[b]P` literal; 99 cols stacked, 118 side by side | P-20 executed (no list) |
| HLR-173a | `●` marks exactly the variant, MAC, A2L a load installs | U | 7 of 7 cases `●` = Loaded panel | first-variant mutant |
| HLR-173b | Loading a recent row loads its recorded path | E | restart, recent, Enter → example loaded, first in store | P-20 (no list) |
| HLR-173c | A load takes the highlighted row if the list was more recent than the path field, else the typed path | E | 12 of 12 (3 triggers × 4) | P-19 executed |
| HLR-173d | Empty or refused Load: dialog open, text kept, reason + step in `#load_reason` | UW | 7 token pairs, 0 dismisses | P-19 executed |
| HLR-173e | `escape` closes, session unchanged | E | 4 focus positions → digest same | P-18 executed |
| LLR-173.1 | Dialog closes with no result or one `LoadChoice` (4 kinds) | U | 4 kinds + `None` | code read: `Path` / `str` today |
| LLR-173.1a | `project` choice → route that opens the Load-result panel | E | `current_project`, 1 panel | direct `_handle_load_project` |
| LLR-173.1b | `workarea` choice → loaded as the Workarea Files pick | E | 0 `copy_into_workarea` calls (data arm); names in `temp/` same | `load_from_path` mutant (spy) |
| LLR-173.1c | `path` choice → typed-path route | E | data, A2L, project 3 of 3 | `load_from_path` mutant |
| LLR-173.1e | One app handler receives every result | U | AST: 2 push sites, 1 callback | code read: 2 callbacks today |
| LLR-173.1f | `recent` choice → recorded text unchanged through the typed route | E | data, A2L, store first, missing → 0 loads | base-relative mutant |
| LLR-173.1g | Picked project unreadable → 1 status line `could not be read`, session unchanged | UW | 1 of 1 | no-catch mutant |
| LLR-173.2 | `l` / `ctrl+l` → focus `#load_path` | E | 2 of 2 + `#load_list` exists | code read; list-first mutant |
| LLR-173.2a | `p` / `#ws_load_project_button` → focus `#load_list` (also with 0 projects) | E | 3 of 3 | code read: `No saved projects found.` |
| LLR-173.2b | Open project's row highlighted, else first project | E | 3 of 3 | row-0 mutant |
| LLR-173.2c | `tab` order path → list → preview → OK → Cancel → path | E | 5 + 5 (reverse) | preview unfocusable |
| LLR-173.2d | Printable key in the list → typed into `#load_path` | E | 6 keys; 4 navigation keys not redirected | no-redirect mutant (app-action arm declared) |
| LLR-173.2e | `ctrl+l/s/k/d` inert while open | UW | 4 of 4, stack depth 2; `ctrl+p` then `ctrl+s`/`ctrl+l` → 0 pushes | S9b-1 probe executed |
| LLR-173.2f | Load with list more recent → row choice | E | 9 + 1 | typed-text mutant |
| LLR-173.2g | Load with path more recent → `path` choice | E | 3 of 3 | row mutant |
| LLR-173.2h | Empty / spaces text → `nothing selected` pair | UW | 2 of 2 | P-19 |
| LLR-173.2i | No loadable row highlighted → `nothing selected` pair | UW | 2 of 2 | heading-dismiss mutant |
| LLR-173.2j | Click highlights, never loads | E | 1 click, 1 double click → 0 dismisses | load-on-`Selected` mutant |
| LLR-173.2k | `escape` → no result | E | 4 | P-18 |
| LLR-173.2l | `#load_cancel` → no result | E | 2 of 2 | cancel→load mutant |
| LLR-173.3 | Project rows painted literally | U | 4 hostile names | code read `screens.py:712`; `safe_text`-only mutant |
| LLR-173.3a | File rows painted literally | U | 7 of 7 | `Label(name)` mutant |
| LLR-173.3b | Recent rows painted literally | U | 3 of 3 | `Label(path)` mutant |
| LLR-173.3c | Preview names painted literally | U | 5 of 5 | markup-on mutant |
| LLR-173.3d | A pick loads the on-disk name | E | 3 of 3 | label-as-value mutant |
| LLR-173.4 | Projects section = project list | E | 2 rows of 5 folders | iterdir mutant |
| LLR-173.4a | A folder with no `project.json` / data / A2L is not listed | UW | 5 of 5 | code read: `list_projects` lists it |
| LLR-173.4b | Files section = one lister, loadable suffixes only; census widened | E | 3 rows of 6; widened census 1; spy 1 | literal-`"temp"` second lister; no filter |
| LLR-173.4c | Recents section = store read, in order | E | 3 of 3 | sorted mutant |
| LLR-173.4d | 0 projects → `no projects` / `ctrl+s saves a project` | UW | 1 | paints-nothing mutant |
| LLR-173.4e | 0 file rows → `no work-area files` / `l loads a file` | UW | 2 of 2 | lister-empty-only mutant |
| LLR-173.4f | 0 recents, no problem → `no recent sources` | UW | 2 of 2 | paints-nothing mutant |
| LLR-173.4g | Store problem → word + next step | UW | 2 of 2 | problem-ignored mutant |
| LLR-173.4h | Recent row = file name + kind | U | 1 + long path one line | size/date mutant |
| LLR-173.4i | Recent preview = full path, kind, `checked when loaded`, no `●` | E | 3 of 3 | code read `pa_C.preview_file` |
| LLR-173.4j | 0 filesystem calls on a recent before load | U | 0 calls over 3 paths | stat-on-highlight mutant |
| LLR-173.4k | Missing recent picked → dialog open, `not found` / `check the path` | UW | 1, store unchanged | dismiss mutant |
| LLR-173.4l | List order projects, files, recents, headings not loadable | U | 6 of 6 | recents-first mutant |
| LLR-173.4m | Project list unreadable → token line in the projects section, others still load | UW | 1 of 1 | no-catch mutant |
| LLR-173.4n | A linked file in a project folder is neither listed nor installed | UW | 1 linked + 1 regular `.s19` → 1 row, 1 mark, 1 install, 0 opens | follows-links helper → 2 rows |
| LLR-173.5 | Typed not found → pair in dialog | UW | 2 of 2 | code read: status line after close |
| LLR-173.5a | Typed not a supported file (incl. relative folder, trailing dot) → pair | UW | 3 of 3 | same |
| LLR-173.5b | Typed non-project folder → pair | UW | 4 of 4 | same |
| LLR-173.5c | Typed outside folder / manifest → pair | UW | 2 of 2 | same |
| LLR-173.5d | Typed path through a link → pair | UW | 2 of 2 | same |
| LLR-173.5e | Typed unreadable folder → pair (the CR9-6 arms) | UW | 2 of 2 | same; catch-removed mutant |
| LLR-173.6 | Project `●` = install rule, no variant unreadable | E | 4 of 4 | first-variant mutant |
| LLR-173.6a | Install ≠ mark → panel names opened variant and reason | UW | 2 of 2 | reason-dropped mutant (base passes, declared) |
| LLR-173.6b | File row `●` = file + kept MAC, A2L | E | 4 of 4 | file-only mutant |
| LLR-173.6c | While a project is open: active-variant note on a data-file row | S | 3 of 3 | always-note mutant |
| LLR-173.6d | Preview lists the variants | E | 1 | marked-only mutant |
| LLR-173.6f | Preview states the manifest | E | 3 of 3 | exists-means-ok mutant |
| LLR-173.6k | Preview `OSError` → `could not be read` pair, no `●` | UW | 2 of 2 | no-catch mutant |
| LLR-173.6l | Dialog fed only through `app.py` callables | U | AST 0 refs; 0 new imports | direct-lister mutant |
| LLR-173.6m | Below 100 columns: preview below list | S | 99 / 100 / 118 + resize | break-at-118 mutant |
| LLR-173.6n | One line per list row | U | 9 of 9 | wrap mutant |
| LLR-173.7 | No decision id in painted text | U | 0 matches over the 9b surfaces | prototype "D10" strings |
| LLR-172.1n | Source found only through the relative fallback → store unchanged (CR9-1) | UW | 4 of 4 | CR9-1 probe executed (`R\x.s19` recorded) |

| AT / TC | Owner | 9b share |
|---|---|---|
| AT-B100-14 | HLR-173 (list half), HLR-173a (preview), HLR-173b (recent), HLR-173c (Enter), HLR-173d (empty), HLR-173e (escape) | written at 9b: one chain — load (record), restart, open Load, recent, Enter; project highlight, `●` = Loaded panel; `escape`; empty Load; `[b]P` |
| AT-B100-03, -04, -05, -06, -07, -08, -09, -10, -11, -19, -20 | earlier HLRs | re-pinned at 9b (project picks through `p` + the highlighted row + `enter`; AT-B100-11 reads `#load_list`) |
| TC-B100-40 | LLR-173.1, LLR-173.1a, LLR-173.1b, LLR-173.1c, LLR-173.1e, LLR-173.1f, LLR-173.1g | full |
| TC-B100-41 | LLR-173.2, LLR-173.2a … LLR-173.2l | full |
| TC-B100-42 | LLR-173.3, LLR-173.3a … LLR-173.3d | full |
| TC-B100-43 | LLR-173.4, LLR-173.4a … LLR-173.4m | full |
| TC-B100-63 | LLR-173.5, LLR-173.5a … LLR-173.5e | full |
| TC-B100-64 | LLR-173.6, LLR-173.6a, LLR-173.6b, LLR-173.6c, LLR-173.6d, LLR-173.6f, LLR-173.6k, LLR-173.6l, LLR-173.6m, LLR-173.6n, LLR-173.4n | full |
| TC-B100-66 | LLR-173.7 | 9b surfaces; Inc 10, 11, 12a extend |
| TC-B100-34 | LLR-172.1n | the CR9-1 arms |
| TC-B100-37 | LLR-172.4 | the census widened (LLR-173.4b) |
| TC-B100-12 | LLR-166.1 | dialog `escape`, cancelled load (already indexed for 9b) |

**29148 check.** Every requirement above is singular (1 "shall", checked by script), states a numeric threshold and a negative control, and names functions only in its trace.

Declared exceptions:
- **Shared response, several triggers.** These hold OR triggers with one identical response; their thresholds test each trigger: LLR-173.2 (`l` / `ctrl+l`), LLR-173.2a (`p` / button), LLR-173.2f and LLR-173.2g (`enter` / `alt+l` / `#load_ok`). The 9a run split OR triggers only where the responses differed (LLR-172.5 / LLR-172.5a).
- **RED only as a mutation.** On the 9a tree these hold already, so each RED is a mutation: LLR-173.2d's "0 app actions" arm (Textual 8.2.8 modal binding chain) and LLR-173.6a (the Inc 7 panel behaviour).
- **Platform-dependent arms.** Reported not run, never passed, when the platform cannot make the fixture: the junction arms (LLR-173.4, LLR-173.5d, LLR-172.1n), `TEMP` (LLR-173.5b), U+009B folder names (LLR-173.3) and the surrogate file name (LLR-173.3a).
- **Executed control.** LLR-173.2e's negative control is a code read whose probe is executed (S9b-1, at the E3 baseline).
- **Live semantics.** LLR-173.6b's third arm ("as the install keeps them") reads the install's MAC carry. E2 must state it from `_apply_prepared_load` before the example is written; the oracle (`●` = Loaded panel) holds either way.

## 2 · Defects fixed in place (old → new)

| Defect | Old | New |
|---|---|---|
| HLR-173 compound | 1 statement, about 20 behaviours, 12 "shall"s, 1 AT | HLR-173 … HLR-173e, one "shall" each; AT-B100-14 split into six halves under one id (as 9a did with AT-B100-12) |
| Cross-increment clause | LLR-173.1 "The load question (HLR-174) runs in this router" | removed from 9b; informative note on LLR-173.1e; Inc 10 owns it (LLR-174.4) |
| Infeasible negative control | LLR-173.1 "routing `workarea` through `load_from_path` → 1 new copy" | the Inc 1 identical-file reuse (G-005) makes that copy a no-op → `copy_into_workarea` call spy (LLR-173.1b) |
| Ambiguous precedence | "when `#load_list` had the focus last" / "when the list has the focus" | "held the focus more recently than `#load_path`" (HLR-173c, LLR-173.2f, LLR-173.2g); the focus on the preview or a button no longer leaves it undefined |
| Undefined "nothing selected" | the list always has a highlighted row by default | two arms: empty text with the path field more recent (LLR-173.2h); no loadable row, a heading included (LLR-173.2i) |
| Weaker scrub | LLR-173.3 "through `safe_text`" (C0 / C1 only; keeps U+202E and surrogates) | `painted_names` with markup off, the batch's one scrub (8b S3R2-4, LLR-172.6) |
| Infeasible in the cap | LLR-173.4 "a recent source missing on pick shall … drop the entry"; HLR-173 boundary "the entry removed"; token `the entry was removed` | no store function removes one entry, and `workspace.py` is outside 9b's cap → the entry stays; token `check the path` (Q3) |
| Unverifiable | LLR-173.4 "cancelled when the highlight moves" (a Python thread cannot be cancelled) | the preview is synchronous, so no cancellation is needed (A9b-04) |
| Stale reference | LLR-173.5 "the matching tokens (LLR-172.5)"; LED .82 split them into LLR-172.5b … LLR-172.5h (9a E1 §5 observation) | 6 requirements, each naming its own pair (LLR-173.5 … LLR-173.5e) |
| Infeasible equality | HLR-173 / LLR-173.6 "The files installed by a load shall be the files the preview marked" | the preview reads no image, so a 0-byte recorded variant is marked and skipped at install → the mark rule assumes no unreadable variant (LLR-173.6), and the difference is named in the panel (LLR-173.6a) |
| False census | LLR-173.6 "`screens.py` imports no service module" | `screens.py` imports `operation_service`, `report_service`, `entropy_service` and `report_addendum` at `4fef292` → census of the dialog class plus "0 new modules" (LLR-173.6l) |
| Missing failure path | priority app keys under the modal | LLR-173.2e (Textual 8.2.8: priority bindings walk the full chain, App included) |
| Undecided (9a C4 / Q9) | `list_projects` lists an empty folder; a typed empty folder is `not a project` | LLR-173.4a (§1.3 decides the list too) |
| Undecided (9a C7) | `.a2l.json` dumps in the work-area files | LLR-173.4b: loadable suffixes only (dialog section; the main `#files_list` is unchanged) |
| Undecided store problem | 9a Q6: "so 9b can paint it in the recents section" — no requirement | LLR-173.4g + 1 token row (Q5) |
| Stale reverse census (§5.4) | `LoadFileScreen` 4 / 10; `LoadProjectScreen` 7 / 7 | 13 files / 60 references; 17 / 57 (`#project_list` / `project_ok` 17 / 63) |
| Feasibility gap | "a click shall select a row and not load it" | Textual 8.2.8 posts `OptionList.Selected` for a click and for `enter` (`_option_list.py:721-730`) → LLR-173.2j states the mutant; E2 must not load on that message |
| Unrecorded design gap (CR9-1) | a relative source found by the fallback is recorded in resolved form (link followed; UNC refused with 1 warning per load) | LLR-172.1n: not recorded (Q1) |
| Census reach (CR9-11) | the one-lister census sees only `WORKAREA_TEMP` | widened to the literal `"temp"` + a runtime spy (LLR-173.4b; TC-B100-37 row) |

## 3 · Slice for E2

Names come from the requirements and the 9a tree. **(guess)** marks a node the requirements imply but do not name; it may end up inline. Sources: `screens.py`, `app.py`, `styles.tcss`, `s19_app/tui/__init__.py` (§5.5 row 9b: 4 files; PSC-1).

Tests (not capped):
- `tests/test_b100_load_dialog.py` (new);
- `tests/test_b100_recents.py` (CR9-1 arms, census widening);
- `tests/test_b100_focus.py` (TC-B100-12 9b arms);
- re-pins in 13 + 17 test files;
- `tests/test_loadfilescreen_input.py`;
- 35 SVG snapshot files.

### `screens.py` — 0 changed + 2 new types with 9 new methods; 2 classes retired

| # | Node | What | Requirement |
|---|---|---|---|
| S1 | `LoadChoice` (NEW, frozen dataclass, B100-I8) | `kind` ∈ {`project`, `workarea`, `recent`, `path`}, `value: str` | 173.1 |
| S2 | `LoadDialog(ModalScreen[Optional[LoadChoice]])` `__init__` / `compose` | callables from the app; open mode (`path` / `list`); the `pa_C` ids; sections with headings that cannot be loaded; `#load_preview` focusable | 173.2c, .4l, .6l |
| S3 | `LoadDialog.on_mount` | focus by open mode; open project highlighted | 173.2, .2a, .2b |
| S4 | `LoadDialog.on_key` | printable key in the list → `#load_path` | 173.2d |
| S5 | `LoadDialog.action_load` (+ `on_input_submitted`, `#load_ok`) | list-vs-path precedence (focus tracking); verdict callback before dismiss; empty-Load tokens | 173.2f … .2i, .4k, .5 … .5e |
| S6 | `LoadDialog.action_cancel` (+ `#load_cancel`) | dismiss `None` | 173.2k, .2l |
| S7 | `LoadDialog` highlight handler | request preview, paint the returned lines; never load on `Selected` | 173.2j |
| S8 | `LoadDialog.show_preview(lines)` | paint the returned lines; markup off | 173.3c |
| S9 | `LoadDialog.on_resize` | toggle the stacked class below 100 columns | 173.6m |
| R1 | `LoadFileScreen` (retired) | replaced by S2 | VS-PA-3 |
| R2 | `LoadProjectScreen` (retired) | replaced by S2 | VS-PA-3 |

### `app.py` — 7 changed + 5 new (+2 guesses)

| # | Node | What changes | Requirement |
|---|---|---|---|
| A2 | `S19TuiApp.action_load_file` | push `LoadDialog` (path mode) → `_handle_load_dialog` | 173.2, .1e |
| A3 | `S19TuiApp.action_load_project` | push `LoadDialog` (list mode, open project), also with 0 projects | 173.2a, .2b, .1e |
| A4 | `S19TuiApp._handle_load_dialog` | the one router: `LoadChoice` or `Path` → project / workarea / recent / path | 173.1a … .1f |
| A5 | `S19TuiApp.list_projects` | §1.3 content test (Q7) | 173.4, .4a |
| A6 | `S19TuiApp.load_from_path` | no record when found only through the fallback | 172.1n |
| A7 | `S19TuiApp.load_a2l_from_path` | same | 172.1n |
| N1 | `_load_dialog_rows()` (NEW) | 3 sections: painted labels + on-disk values; loadable-suffix filter; empty and store-problem token lines | 173.3, .3a, .3b, .3d, .4 … .4h, .4l |
| N2 | `_load_dialog_verdict(choice) -> Optional[(reason, step)]` (NEW) | `_typed_load_route` for `path` and `recent` (after Enter only) | 173.4k, .5 … .5e |
| N3 | `_load_dialog_preview(choice)` (NEW) | recent → store facts only; file → N5; project → synchronous build (variants, manifest state, install set; no `check_project_files`); `OSError` → token | 173.4i, .4j, .6, .6b, .6c, .6d, .6f, .6k |
| N5 | `_file_preview_marks(path)` (NEW) | file + MAC / A2L the install keeps; project-open note | 173.6b, .6c |
| G1 | `_load_workarea_file(name)` (guess) | `_load_from_item`'s body shared by the list pick and the `workarea` choice | 173.1b |
| G2 | `_typed_refusal_tokens(reason)` (guess) | one reason → (token, step) table for the status line and `#load_reason` (partly closes CR9-7) | 173.5 … .5e |
| G3 | `check_action` or guards in the 4 priority actions (guess) | inert while `LoadDialog` is the screen | 173.2e |

**Callers checked (9a tree):**
- `action_load_file` ← `ctrl+l` / `l` (`BINDINGS`), palette entry `load_file`.
- `action_load_project` ← `p`, `on_button_pressed` (`#ws_load_project_button`), palette entry `load_project`.
- `_handle_load_dialog` ← `action_load_file`; `tests/test_tui_app.py:1275,1304` and `tests/test_b100_active_variant.py:210` re-pin to `LoadChoice("path", str(p))` (A9b-08).
- `_load_path_from_user_input` ← `_handle_load_dialog`, `on_mount` (the start-up `load_path`; status-line refusals unchanged).
- `list_projects` ← `action_load_project`, `_handle_load_project`, `_typed_load_route`, plus 7 test files (`tests/test_b100_project_homes.py`, `test_b100_recents.py`, `test_b100_save_guards.py`, `test_b100_save_image.py`, `test_b99_load_project.py`, `test_tui_app.py`, `test_tui_helpers.py`). The reverse census of tests that list an empty folder is owed at E2 (Q7).
- **Test notes (E2, F-1):** the Q7 reverse census names 5 tests that list or load an empty folder and each fails once `list_projects` applies §1.3; all 5 are re-pinned: TC-B100-32 `[no project.json]` (`tests/test_b100_project_homes.py:1016`, LLR-171.2e retired) → `is not a project` / `pick a project in the list`; `tests/test_tui_app.py:367` and `tests/test_tui_helpers.py:132` (give both folders a `project.json`); `tests/test_b99_load_project.py:154` TC-B99-35 (give `P1` / `P2` content and one reserved home content); `tests/test_tui_directionb.py:9072` (re-pin to `isinstance(app.screen, LoadDialog)`).
- **Test notes (E3 r2, R2-N4; corrected at close, A9b-R3-1):** the TC-B100-38 "route: validate_project_files" arm is re-pinned in `tests/test_b100_recents.py` to patch `_list_project_files` (the named scan helper), which now exercises F-12's catch in `_handle_load_project` — the 9b slice lists through `_list_project_files`, so `validate_project_files` is no longer on the route. The B19 / B23 injections move to `_list_project_files`.
- `load_from_path` / `load_a2l_from_path` ← `_load_path_from_user_input`, `_handle_select_variant` (inside, not recorded), `_load_from_item` (inside).

**Unchanged context:** `_typed_load_route`, `_route_load_project`, `_handle_load_project`, `choose_install_set` (Inc 7), `_build_palette_entries` (reads `BINDINGS`), `refresh_files` (the main list keeps its rows; C7 stays in the backlog for `#files_list`), `painted_names` (`project_gather_service.py`), `safe_text` (`utils.py`), `list_workarea_files`, `read_recent_sources`, `recent_kind`, `RecentEntry` (`workspace.py`).

### `styles.tcss` — 2 changed + 7 new selectors

| # | Selector | What | Requirement |
|---|---|---|---|
| C1 | `.modal-dialog, #load_dialog` | `#load_dialog` gets its own width (two panes) | 173, .6m |
| C2 | `#project_list, #variant_list` | drop `#project_list` (retired) | VS-PA-3 |
| C3 | `#load_panes`, `#load_panes.stacked` | horizontal / vertical | 173.6m |
| C4 | `#load_left`, `#load_list`, `#load_preview`, `#load_reason`, `#load_buttons` | sizes; one-line rows; focus border | 173.6n, .2c |

**Node count:**
- **Firm:** `screens.py` 9 (2 new types + 7 handlers; 2 retired classes); `app.py` 11 (7 changed + 4 new); `styles.tcss` 9 selectors; `s19_app/tui/__init__.py` 1 (re-export: `LoadChoice`, `LoadDialog`).
- **With the guesses:** up to 23 code nodes.
- That is far above ~8, so E2 runs by file group:
  - G-A `screens.py` + `styles.tcss` (the dialog widget and its layout; 9 nodes + CSS).
  - G-B `app.py` (router, providers, worker, `list_projects`, CR9-1; 12–15 nodes).
  - G-B is still above 8. If E2 must split it further, cut it into G-B1 (router + bindings + `list_projects` + CR9-1: A2 … A7) and G-B2 (providers + worker: N1 … N5).
- **Source files:** 4, at the cap of 4 (PSC-1 adds `s19_app/tui/__init__.py`, which re-exports `LoadChoice` and `LoadDialog`). The Q3 alternative (`workspace.py`) is no longer available; it would be a 5th file.

**Seams to fix before E2 (in one file, by the orchestrator):**
- S-a `LoadChoice`: field names and types; `value` is always `str` (the on-disk name, the recorded path text, or the typed text).
- S-b `LoadDialog.__init__` contract:
  - `mode` (`"path"` / `"list"`);
  - `highlight` (project name or `None`);
  - `rows()` → sections;
  - `verdict(choice)` → `None` or `(reason_token, step_token)`;
  - `preview(choice)` → `list[PreviewLine]`.
- S-c row model: `(section, label: str (already painted, plain), choice: Optional[LoadChoice])`; `choice is None` marks headings and token lines.
- S-d preview model: lines of `(text: str, marked: bool)`, already painted; `●` is added by the dialog only where `marked`.
- S-e threading: N2 runs on the event loop (metadata only, as today's typed route); N3 runs on the event loop and returns the lines synchronously for every kind (Q2: the project preview reads only metadata and the bounded `project.json`). There is no `deliver` and no generation.
- S-f precedence state: the dialog records which of `#load_list` / `#load_path` gained the focus last (a focus-event handler, not `self.focused` at load time).
- S-g priority keys (LLR-173.2e): the guard sits in `App.check_action` and reads the whole screen stack (S9b-1). The app already imports `LoadDialog`.

## 4 · Open questions

Recommendations and the alternatives are in `E1-rulings-proposed.md` (Q1 … Q10). The draft text follows each recommendation; a different ruling changes the ids named there.

## 5 · Observations

- The verdict runs twice: once in the dialog (N2, before dismiss) and once in the router (`_load_path_from_user_input` re-classifies). A path that changes between the two gets the status-line refusal of LLR-172.5b … LLR-172.5h after the dialog has closed. This is acceptable and needs no requirement.
- A recent on a mapped network drive is touched at Enter (`resolve_input_path` → `exists()`), as §6 "Known gap" already declares. LLR-173.4j covers only the time before Enter.
- After a refusal is painted, nothing clears `#load_reason` when the text is edited. No requirement asks for it; the next load request repaints it. If E3 wants it, it is one event requirement.
- The main-screen `#files_list` still lists `.a2l.json` dumps (C7). Only the dialog section filters (LLR-173.4b). The main list stays in the backlog.
- CR9-7 (refusal lines written twice or three times): 9b adds a third consumer (`#load_reason`). The guess node G2 would make one table, so a ruling at E2 can close the token half of CR9-7 at no extra file.
- `pa_C` uses an `OptionList` with disabled header options; the shipped `#load_list` type is open (Q10). It changes how tests read the highlight, not any requirement.
- No row of `.dev-flow/BACKLOG-CODE.md` is routed to 9b yet: the 9a close has not written CR9-1, CR9-11, C4 or C7 there (`inc-9a/E5-corrective-notes.md` item 7). This E1 decides all four, so at the 9a close they can be written as "decided at 9b E1 (LED .NN)" instead of open rows.

## Q2 verification

Branch applied: **synchronous** — every remaining project-preview step reads only metadata and the bounded `project.json`, so the worker `_project_preview_worker`, LLR-173.6h and LLR-173.6j are removed, and the project preview returns its lines inside the `preview()` call like the other kinds (A9b-04). `check_project_files` (LLR-173.6g) reads whole image contents and is removed from the preview; problems stay on the Load-result panel after Enter (HLR-178). The preview reads no image and follows no link (S9b-2).

| Step | Function (file:line) | What it reads | Verdict |
|---|---|---|---|
| file-list scan | link-safe scan in `_load_dialog_preview` | `lstat` / `is_file(follow_symlinks=False)` only; no linked child's target is followed (S9b-2) | metadata, no link follow |
| variant set | `build_variant_set` (`workspace.py:1929`) | file names, suffixes and stems only; no `open`/`read` | metadata |
| manifest | `read_project_manifest` (`variant_execution_service.py:1438`), after the `project.json` lstat regular-file gate | `project.json` bytes capped at `MANIFEST_SIZE_CAP_BYTES` (1 MiB), plus a lstat walk of up to 1 000 manifest entries; a non-regular `project.json` is not opened | bounded `project.json` (allowed); no link follow (S9b-2) |
| damaged check | `manifest_is_damaged` (`variant_execution_service.py:2032`) | the already-parsed `manifest.issues`; no file access | metadata |
| install set | `choose_install_set` (`app.py:1593`) | pure over `variant_set`, `recorded`, `data_files`, `a2l_files`; no file access | metadata |
| problems | `check_project_files` (`manifest_writer.py:1221`) | hashes whole image files | **contents → removed (LLR-173.6g)** |
