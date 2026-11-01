# Code-Wire baseline notes — Inc 10 slice on `8947666`

## Numbers

| Item | Value |
|---|---|
| Graph | `baseline-10.md` (this folder) |
| Base | `C:\Users\jjgh8\Github\s19_app` at `8947666` (Inc 9a merged), read only. Every probe and the extractor ran on `work/tree`, a `git archive 8947666` copy (removed after the run, with `work/marked`) (`s19_app`, `tests`, `examples`, `tools`, `pyproject.toml`, `setup.py`). The probes printed the import line `…\inc-10-design\work\tree\s19_app`. No git command that changes state was run on the repo; its only untracked entry (`prototypes/load_projects/`) was there before. |
| Nodes | 37. `screens.py` 2 (`ConfirmDiscardScreen.__init__`, `.compose`). `screens_directionb.py` 8 (`LoadGuardScreen.compose`, `.on_button_pressed`; `PatchEditorPanel.request_action`, `.on_text_area_changed`, `.on_button_pressed`, `.mark_saved`, `.mark_loaded`, `.mark_pasted`). `flow_screens.py` 2 (`FlowBuilderPanel.is_dirty`, `.current_flow`). `change_service.py` 2 (`ChangeService.differs_from_last_saved`, `.mark_saved`). `project_gather_service.py` 1 (`painted_names`). `app.py` 20 (`action_load_file`, `check_action`, `_handle_load_dialog`, `_route_load_project`, `_handle_load_result`, `action_select_variant`, `_handle_select_variant`, `_load_path_from_user_input`, `_typed_load_route`, `load_from_path`, `load_a2l_from_path`, `load_selected_file`, `_load_from_item`, `on_list_view_selected`, `on_mount`, `_handle_load_project`, `_reset_project_session`, `_handle_save_dialog`, `_rehome_focus_after_load`, `on_patch_editor_panel_dirty_load_requested`). Post-9b (no code) 2: `LoadDialog.__init__`, `S19TuiApp._load_workarea_file`. |
| Nodes Inc 10 changes (per `func:`) | 7 on base: `check_action` (S-f), `_route_load_project`, `_load_path_from_user_input`, `_handle_select_variant` (S-d seam), `_handle_load_project` (interim block removed), `_reset_project_session` (return, Q-7), `_handle_save_dialog` (`is_dirty`). Plus 1 post-9b: `_load_workarea_file` (seam). `_handle_load_dialog`, `_load_from_item` and `action_load_file` are changed by 9b and left alone by Inc 10 under the S-d placement. New with no code (not nodes here): `ConfirmQuestionScreen` (G-A), `PatchEditorPanel.is_dirty` (G-A), `_confirm_then_load`, `_load_would_lose`, `_load_question_text` (G-B). |
| Example lines | 57, 1 to 5 per node. Each names a probe step (p10b U0–U13, p10b-q4, p10b-undo, E1 p10, p9b U4), an existing test, or a code read. All hold on `8947666` unless marked "post-9b". Where Inc 10 turns a line RED, the line says "RED side of …". |
| Caller lines | one `> callers (extractor): …` note per node, from `extract-baseline/extract.json`, converted to `8947666` line numbers (marked line minus the marks above it). "direct": the site is inside the caller's `def`; "through an unmarked helper": the extractor lifted it. `mark_saved` is a name shared by `PatchEditorPanel`, `ChangeService` and `FlowBuilderPanel`; the 7 ambiguous resolutions were split by reading each site's text (`_change_service.mark_saved(` → ChangeService; `panel.mark_saved()` → PatchEditorPanel; `panel.mark_saved(saved.stem)` → FlowBuilderPanel, not a node, dropped). |
| Extractor | `codewire_extract.py` (v3.1 core), s19env Python, on `work/marked` (a copy of `work/tree/s19_app` in a throwaway `git init` repo) with `work/graph-extract.md` (this graph minus the 2 post-9b nodes). Exit 0: 35 marks, 35 graph nodes, 29 real calls, 0 findings (0 drift), 7 ambiguous resolutions (above), 0 parse failures. |
| Marks | 35, written by `codewire_marks.py` into `work/marked` only. The repo has 0 marks. |
| Lint | not run (the brief forbids it). |
| Report | `extract-baseline/diff-report.md`, `extract-baseline/extract.json` |

## Probe

`probe-p10b.py` (this folder; output `probe-p10b.out.txt`), plus two small ones: `probe-p10b-q4.py` (Q-4, output `probe-p10b-q4.out.txt`) and `probe-p10b-undo.py` (LLR-174.1 boundary, output `probe-p10b-undo.out.txt`). Interpreter `C:/Users/jjgh8/anaconda3/envs/s19env/python.exe -I`, env `PYTHONDONTWRITEBYTECODE=1 PYTHONUTF8=1 LOCALAPPDATA=<folder>/work/localappdata`, `NO_COLOR` unset; fixtures in a `tempfile` folder outside the repo, removed at the end.

```text
U0 Button.BINDINGS keys: ['enter']
U0 PatchEditorPanel.is_dirty exists: False
U0 painted_names: '[b]x.s19' 'ab.s19' 120 …
U0 Path suffixes: '' '.mac'
U1 flow default: 'flow' is_dirty False
U2 same-byte patch: D = False
U2 real patch: D = True | entries 2 | W = False
U3 _typed_load_route(typed.mac) = ('data', '') | typed2.MAC = ('data', '') | other.s19 = ('data', '')
U3 typed .mac over patch: stack ['Screen'] | file firmware.s19 | mac typed.mac | byte kept True | D = True
U4 WORKAREA pick over patch: stack ['Screen'] | file prg.s19 | D = False | entries kept 2
U5 LOAD DIALOG router over patch: stack ['Screen'] | file other.s19
U6 project PV over 4 entries: stack ['Screen', 'LoadResultScreen'] | reset returns [4] | D after = False | W after = False | current_project PV
U6 status log interim lines: ['Closed the Patch Editor document (4 entries); unsaved changes were not kept']
U7 D right after project load = False (the panel's v meets D = False by keys)
U7 panel v route: stack ['Screen', 'SelectVariantScreen']
U8 _handle_select_variant('firmware_b'): load_from_path calls [('firmware_b.s19', 'firmware_b')] (pending id set before the load)
U8 VARIANT switch over patch: stack ['Screen'] | active firmware_b | D = False
U9 project M2 (2 MAC) over D+W: stack ['Screen'] | resets [] | D = True | W = True | session same True
U10 FLOW dirty across project load: is_dirty True | name flow
U11 LoadGuardScreen focus: load_guard_cancel
U11 after y a l p s q: stack ['Screen', 'LoadGuardScreen'] | answers []
U11 ctrl+l under LoadGuardScreen: ran ['load_file'] | stack ['Screen', 'LoadGuardScreen', 'LoadFileScreen']
U11 ctrl+s under LoadGuardScreen: ran ['load_file', 'save_project'] | stack ['Screen', 'LoadGuardScreen', 'SaveProjectScreen']
U11 ctrl+k, ctrl+d: ran ['load_file', 'save_project', 'focus_palette', 'cycle_density'] | stack ['Screen', 'LoadGuardScreen'] | density [] -> []
U11 escape -> answers [False] | stack ['Screen']
U11 immediate enter on LoadGuardScreen -> answers [False, False] | stack ['Screen']
U12 ConfirmDiscardScreen focus: flow_discard_ok | buttons ['Discard', 'Cancel']
U12 escape, n -> stack ['Screen', 'ConfirmDiscardScreen'] | answers []
U13 Patch Editor Load while dirty: stack ['Screen', 'LoadGuardScreen']
Q4 PureWindowsPath('x.mac.').suffix = '' | recent_kind = None
Q4 exists(typed 'x.mac.') = True | route = ('refuse', 'not a supported file')
Q4 after typed 'x.mac.': file firmware.s19 | mac None | last status ["File NOT loaded: '<tmp>\\x.mac.' is not a supported file — check the path."]
UNDO applied: byte 0xaa D = True
UNDO after undo (no re-apply): entries 0 byte 0xaa D = True
UNDO after undo + apply: byte 0x11 D = False
```

(The `…` in U0 printed as a replacement glyph in the console; the string ends in U+2026. U11's density list reads the app's classes, where the density class does not live; `cycle_density` ran, which is the point. The first U11 `escape` in the script reached `LoadGuardScreen` after the focus was cleared; both cancel paths answered `False`.)

What the probe settles:
- **The premises still hold on `8947666`:** P-17 / P-42 (U4, U5, U8: the three routes replace a patched image with stack `['Screen']`); P-43 (U0: no public reader; E1 p10: 1 private read at `app.py:10576`).
- **LLR-174.2h's `planned` control is now executed** (U11). It used a stand-in `ModalScreen[bool]` (`LoadGuardScreen`), because neither the question nor 9b's guard exists. All 4 priority actions run under it, `ctrl+l` stacks `LoadFileScreen` and `ctrl+s` stacks `SaveProjectScreen`. Under 9b's guard, which is keyed on `LoadDialog`, a question pushed over the main screen behaves the same way, so S-f is needed.
- **Ruling Q1** (U10): F survives a project load.
- **Ruling Q5** (U7): D is false right after a project load, so the panel's `v` cannot meet D by keys.
- **LLR-174.3c's outcome already holds for the body `go` will run** (U9): a listed project with 2 MAC files is refused before the reset, with D and W kept.
- **Ruling Q2** (U6): the interim line paints for any non-empty outgoing document, even when W was false. The 4 entries came through the service, not the panel.
- **The typed `.mac` is an attach** (U3): `_typed_load_route` cannot tell it from an image (`data`), and the trailing-dot form is refused before routing (Q4).
- **`_handle_select_variant` stamps `_pending_variant_id` before the load** (U8), so the stamp belongs inside `go`.

## Census of existing tests that break when the slice changes

**Result: 5 test runs (4 test functions) break when the slice changes.**
- Executed:
  - 3 runs (2 functions) meet the question: AT-B100-03 ×2 and TC-B99-40.
  - Run B shows them failing: `3 failed in 60.97s`.
- By code read: 2 functions pin the interim line (TC-B100-10 ×2).
- AT-B100-03 also pins the interim line in two assertion blocks; it is already counted above.
- No other existing test reaches a load route while D, W or F is set.

**Method (executed, not a reading):**
1. A throwaway pytest plugin, `work/plug/census10_plugin.py`, wraps the four leaves at class level at runtime. The leaves are `_handle_select_variant`, `_load_from_item` (post-9b: `_load_workarea_file`), `_load_path_from_user_input` and `_route_load_project` (counted once per request when it is called from the typed route).
2. For every call it records the kind S-d gives it and the flags the guard would read:
   - D: `differs_from_last_saved`;
   - F: `FlowBuilderPanel.is_dirty`;
   - W: the panel's `_dirty`.

   It then applies the asks rule (`image` → D; `project` → D or F or W; `attach` / refusal / start-up → never). The repo source is not edited.
3. **Run A (recorder)** ran 52 test files in 4 parallel shards on `work/tree`. The files were chosen by grep for the route names, `press("v")`, `files_list`, `load_ok` / `load_path=`, `LoadFileScreen` / `LoadProjectScreen` / `project_ok`, `press("p")`, `ws_load_project_button`, `result_variant`, `SelectVariantScreen`, the interim text, `_reset_project_session`, `load_selected_file(`, and the helpers `b100_projects` / `b97_fixtures`.
   - Totals: 2,005 passed, 7 failed, 16 errors, 6 skipped, 1 xfailed.
   - Coverage: 401 route calls in 260 test runs across 26 files.
   - Calls by route, kind and whether the guard would ask:

     | Route | Kind | Asks | Calls |
     |---|---|---|---|
     | `_load_path_from_user_input` | image | no | 198 |
     | `_load_path_from_user_input` | image | **yes** | 1 |
     | `_load_path_from_user_input` | attach | no | 32 |
     | `_load_path_from_user_input` | refuse | no | 31 |
     | `_load_path_from_user_input` | start-up | no | 15 |
     | `_load_path_from_user_input` | project (passed on) | no | 8 |
     | `_route_load_project` | project | no | 72 |
     | `_route_load_project` | project | **yes** | 2 |
     | `_route_load_project` | `None` | no | 26 |
     | `_load_from_item` | image | no | 9 |
     | `_load_from_item` | attach | no | 1 |
     | `_handle_select_variant` | image | no | 6 |
4. **Run B (mutant)** ran on the 3 recorded test ids. It used the same wrapper, but a call whose guard would ask returns without loading, which is what a question nobody answers does. Result: 3 of 3 failed.
5. Evidence in `work/`:
   - `census-files.txt`, `shard-00…03`;
   - `census-record-00…03.jsonl`, `pytest-record-00…03.txt`;
   - `census-ask-ids.txt`;
   - `census-mutant.jsonl`, `pytest-mutant.txt`.

**Run A failures and errors: none recorded an asking event, so none is a census row.**
- 7 failures:
  - 3 perf bounds: `test_b100_active_variant.py::test_tc_b100_20_…[variant-append]`, `[save-project]`, and `test_b100_save_guards.py::test_tc_b100_05_…`;
  - 2 `test_b100_project_check.py::test_tc_b100_61_…` folder-ceiling cases;
  - 2 palette goldens, `test_tui_commandbar.py::test_at_b78_03_…` and `::test_at_b78_14_…`.

  All of them ran under 4 parallel shards on a loaded machine; 9b's census saw the same families.
- 16 errors:
  - 12 in `test_id_registry.py`, which needs `.dev-flow/` (not copied);
  - `test_tui_snapshot.py::test_cv04_…`;
  - `test_tui_variants.py::test_variant_help_modal_fits_at_both_sizes`;
  - `test_unload_feature.py::test_ac5_…`;
  - the teardown of `test_tui_patch_variant.py::test_tc_035_7_…`. That one is the session guard `conftest.py:74` ("the real recent-sources store changed"): the 4 shards and the probe shared one `LOCALAPPDATA` folder, so it is an artifact of this run.

  Not triaged further.

### Tests that break

| # | Test (file:line of the def) | Why | Today | After Inc 10 | Re-pin |
|---|---|---|---|---|---|
| 1 | `tests/test_b100_session_reset.py:781` `test_at_b100_03_project_load_over_unsaved_work_saves_only_p2[size0]` | W set (entry + paste draft), project P2 through the Load project dialog → `_route_load_project`: asks (run A: D False, F False, W True) | loads P2; interim line asserted (`:879-880`, `:945-946`) | run B: `AssertionError: timed out waiting for the Load-result panel` | E1 §C.5: wait for the question, assert `Patch Editor entries`, press `y`; delete the two interim assertions |
| 2 | same, `[size1]` | same | same | same | same |
| 3 | `tests/test_b99_editor_image.py:468` `test_tc_b99_40_strip_shows_new_file_source_byte` | Apply on file A (`#patch_doc_apply_button`), then load file B through the Load dialog (`_load_fixture`, `:166`, typed path) → image kind with D True: asks | B loads | run B: `AssertionError: did not settle: load status line` | after the 9b re-pin of `_load_fixture` (LoadFileScreen retired), press `y` at the question (or record A as saved first). **Not in E1's first cut.** |
| 4 | `tests/test_b100_session_reset.py:587` `test_tc_b100_10_interim_discard_notice` | asserts `Closed the Patch Editor document (1 entries); …` (`:598-599`) after a direct `_handle_load_project` | passes | RED (the line is deleted, ruling Q2) | E1 §D.1: re-pin to 0 closed-document lines |
| 5 | `tests/test_b100_session_reset.py:629` `test_tc_b100_10_notice_names_every_discarded_entry` | asserts the `(3 entries)` line (`:634-635`) | passes | RED | same |

### Checked and unchanged

- `tests/test_b100_session_reset.py:603` `test_tc_b100_10_no_discard_notice_when_nothing_unsaved` asserts the line is absent (`:622`). It holds.
- The `_reset_project_session` stubs:
  - `test_b100_project_homes.py:918`;
  - `test_b100_recents.py:415`;
  - `test_b100_session_reset.py:206-223`, `:254` (`-> int` stubs returning `0` or the original).

  No caller reads the value after Inc 10, so they hold with or without Q-7. `test_tc_b100_08_call_site_census` (exactly 1 reset call site) holds, because Inc 10 keeps that one site.
- **E1's first-cut files.**
  - `test_tui_patch_variant.py`: 2 recorded route calls, both D False. The other AT-035 arms replace `_handle_select_variant` on the instance or drive the dropdown, so no patched image meets the variant switch.
  - `test_b100_active_variant.py`: 36 calls, 0 asking.
  - `test_loadfilescreen_input.py`: 0 route calls; it tests the input widget.

  None breaks under Inc 10. (They are 9b re-pins where they drive `LoadFileScreen` or `_handle_load_dialog(Path)`.)
- **LLR-174.1c's census** is over `s19_app/` only. The 10 test files that read `panel._dirty` (for example `test_tui_patch_editor_b94.py:395`) are outside it and unchanged. No test counts the panel's dirty writers, so the docstring fix (S-c) breaks nothing.
- **`check_action` (S-f):** no existing test pushes a `ConfirmQuestionScreen`, so adding the screen type changes no existing test.

**Reach limits.**
- A test that replaces a route on the instance (`app._handle_select_variant = …`) bypasses the class-level wrapper.
- A test that reaches a route without any grep token is outside run A.
- Tests that call `_handle_load_project` directly are not routes (LLR-174.3b) and were not wrapped. Only the interim-line ones break, rows 4–5.

## Selectors (`styles.tcss`, not graph nodes)

| Selector (line) | Rule | Used by | Inc 10 |
|---|---|---|---|
| `ModalScreen` (`:1576`) | `align: center middle`, dimmed base | every modal | unchanged |
| `.modal-dialog, #load_dialog` (`:1581`) | border, panel background, `padding: 1 2`, `width: 70%`, `height: auto` | 8 modals with `id="load_dialog"` (9b count) and the `.modal-dialog` class | the question uses `.modal-dialog` with its own id `#confirm_box` (Q-6: no new rule needed for LLR-174.2r) |
| `.modal-title` (`:1591`) | accent, bold | all modals | `#confirm_title` reuses it |
| `.modal-buttons`, `.modal-buttons Button`, `.modal-confirm` (`:1732`–`:1746`) | horizontal, docked bottom; confirm in the accent colour | the modal button rows | `#confirm_buttons`, `#confirm_yes` reuse them |
| `pb_A`'s `#load_dialog` width rules (`prototypes/load_projects/variants/pb_A.py`, `on_mount`: 60%, max 72, min 44) | inline styles in the throwaway prototype | `pb_A` only | not copied as an id; Q-6 option 2 if E4's layout arm clips |

## Calls the extractor cannot see

- Dismiss callbacks passed to `push_screen`:
  - `action_load_file` → `_handle_load_dialog`;
  - `action_select_variant` → `_handle_select_variant`;
  - `_route_load_project` → `_handle_load_result`;
  - `on_patch_editor_panel_dirty_load_requested` → `_answer`.

  The question's `answer` callback will be one more.
- `call_after_refresh` targets: `_handle_load_dialog` → `_load_path_from_user_input` (and post-9b, the four leaves).
- Framework handlers: the screens' `compose` / `on_button_pressed`, `on_text_area_changed`, `on_list_view_selected`, `on_mount`, `check_action` (Textual `run_action`; also `window_help.py:1134` / `:1145`, the key bar).
- Property reads: `FlowBuilderPanel.is_dirty`, `.current_flow`, and the future `PatchEditorPanel.is_dirty`.

## Load call sites (LLR-174.4's AST census, executed as a grep on base)

`grep -n "self\.load_selected_file(\|self\.load_from_path(\|self\.load_a2l_from_path(\|self\._route_load_project(\|self\._start_load_worker(" s19_app/tui/app.py` → 8 sites, all in the slice:
- `:7611` (`_handle_select_variant`);
- `:11920` (`_handle_load_project`, the MAC install, inside `_route_load_project`'s `go`);
- `:12936`, `:12939`, `:12942` (`_load_path_from_user_input`);
- `:13071` (`load_from_path` → worker);
- `:13333`, `:13335` (`_load_from_item`, which becomes `_load_workarea_file` post-9b).

No other module calls them, so no route outside the four leaves can bypass the seam.

## Wall time

About 2 h 10 min by the shell clock (run A, 4 shards, took 48 min of it). See steps.log.
