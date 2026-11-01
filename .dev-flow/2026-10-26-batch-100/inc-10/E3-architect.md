PASS-WITH-NOTES

# Inc 10 — E3 architect review (round 1)

Scope read: `E1-scope.md`, `E1-rulings.md`, `E2-rulings.md`, `E1-requirements-draft.md`, `codewire/interfaces-10.md`, `codewire/baseline-10.md`, `codewire/baseline-notes.md`, `codewire/proto-10-dialog.md` (G-A), `codewire/proto-10-app.md` (G-B); the 9b base (`inc-9b-design/E3-rulings.md`, `E3-architect.md`) and the 9b implementation in `C:\Users\jjgh8\Github\s19_app-b100-inc9b` (uncommitted, read only); Textual 8.2.8 sources in `s19env`. Code citations marked "9b:" are lines of the 9b worktree's `s19_app/tui/app.py` (they differ from `8947666` lines).

Executed in this review (throwaway, under `work/e3-architect/`): a route census on the 9b worktree's tests (the E2 census ran on `8947666` tests only). See "Census on the 9b tests" below.

Counts: HIGH 0 · MAJOR 1 · MINOR 7 · NIT 3.

## Findings

| Id | Severity | Where | Defect | Evidence | Proposal |
|---|---|---|---|---|---|
| A10-01 | MAJOR | G-B `_route_load_project` step (1); example C32; C05; E2-rulings P-2; LLR-174.4 | The accepted census rule (E2-rulings P-2: "the three loaders and `_handle_load_project` may be called only inside a `go` passed to the seam, inside `_handle_load_project`, or as `load_from_path`'s worker start. Callers of `_route_load_project` are exempt") flags G-B's own design: step (1) calls `self._handle_load_project(None)` in `_route_load_project`'s body, outside any `go`. C05 lists only (a) inside a `go`, (b) inside `_handle_load_project`, (c) the worker start, so the TC-B100-72 AST census goes RED on the designed code. The two ways out are both bad: E4 makes the census exempt the whole body of `_route_load_project`, which also blinds it to the LLR-174.3 "reset before asking" mutant (`_handle_load_project(name)` before the seam) in the one route where order matters; or E4 changes the design ad hoc. The arm is dead after 9b. The router passes `result.value` (a `str`) and returns early on `None` (9b: `_handle_load_dialog`, `if result is None: … return`). The typed route passes the `name` from `("project", name)`. No test calls `_route_load_project(None)` (grep `tests/*.py`: only `"P"` at `test_b100_project_homes.py:1126/:1163/:1947`). The E2 census's 26 `None` calls came from the `LoadProjectScreen` dismiss, which 9b retires. | proto-10-app.md:127 (step 1), :70 (C05), :137 (C32); E2-rulings.md:11; 9b: `_handle_load_dialog` body, `_route_load_project` callers; `grep -rn "_route_load_project(None" tests s19_app` → 0 hits | **Remove** step (1) and example C32. Narrow the parameter to `name: str` (both shipped callers pass a `str`). The census then holds as accepted, with no exemption for the body. `_handle_load_project`'s own `None` arm stays as it is: direct test calls still reach it. |
| A10-02 | MINOR | G-B `_load_would_lose` step (3); interfaces S-e "A panel that is not mounted counts as not dirty"; example C15 | The guard fails open. If `query_one("#patch_editor_panel", PatchEditorPanel)` or `query_one("#flow_panel", FlowBuilderPanel)` raises for any reason, the `except Exception` turns W or F into "clean", and the project load resets the session with no question: silent loss of exactly the work HLR-174 protects. In a running app both panels always live on the default screen, and `App.query_one` searches the default screen even with modals on top (Textual 8.2.8 `app.py:941-943` `_get_dom_base` → `default_screen`). So the catch serves only an unmounted unit call (C15). C15 traces to no requirement, and it is the only reason for the code. This goes against the batch's fail-loud rule. Scenario: a later edit renames `#flow_panel`, or the type check raises `WrongType`. F reads False on every load, the TCs that force F through the panel go RED, but production code shipped between runs loses edits silently. | proto-10-app.md:84-85, :94 (C15); interfaces-10.md:86; Textual `dom.py:1462-1503`, `app.py:941-943` | **Remove** both `try/except` blocks and example C15; let `query_one` raise. Drop the S-e tolerance sentence from interfaces-10.md. R-4 (headless tests) then reads "a test must mount the app", which every route test already does under `run_test`. |
| A10-03 | MINOR | G-A `ConfirmQuestionScreen._close` (`_dismissed` guard); examples Q5-1…Q5-3; the race examples C39, C43 | Code with no requirement. The `_dismissed` guard is shipped code that handles a failure path: two answers queued in one tick, executed by K7 as a `ScreenStackError` crash without the guard. It traces only to ruling Q-5, and no LLR-174.* names it. Q5-1…Q5-3 are orphan examples. The batch rule requires code → requirement on every change, and the E1 ledger states "every failure path its own unwanted-behaviour requirement" (draft §E). The race of a file deleted while the question is open (C39, C43) is in the same state, but it adds no code, so it can stay a declared risk. | proto-10-dialog.md:114-126 (Q5 node, `req: Q-5 (A9b-02 copied)`), :18 (K7); draft §E "What changed" | Add one unwanted-form LLR under LLR-174.2, for example LLR-174.2s: "If a second answer reaches the question after the first, then the system shall act on the first answer only." Threshold: Q5-1 (`_close(True); _close(False)` → 1 callback `True`, 1 pop, 0 exceptions). Negative control: guard removed → `ScreenStackError` (K7, executed). Re-trace Q5-1…Q5-3 to it. |
| A10-04 | MINOR | LLR-174.2b threshold ("the question opened from each of the 4 routes → `focused.id == "confirm_no"`"); G-B coverage row "LLR-174.2b (reach half) C02, C28" | No example asserts the focus per route. C02 and C28 assert the stack depth and the labels, not the focus. C41 (the panel `v`) is not even listed. Only G-A Q1-2 checks the focus, and only for a direct push. The threshold (4 of 4) has no example behind it. It is also redundant: Textual applies `AUTO_FOCUS` inside `push_screen` itself (`app.py:2953` `next_screen._update_auto_focus()`), whoever calls it. | draft LLR-174.2b; proto-10-app.md:360; proto-10-dialog.md:61 (Q1-2); Textual `app.py:2945-2954` | **Remove** the per-route arm: cut LLR-174.2b's threshold to "the question pushed → `focused.id == "confirm_no"` (1 of 1)", which Q1-2 covers. HLR-174c's immediate-`enter` arm (C04) already proves the focus on two real routes. If the 4-route arm is kept, add a `focused.id` assertion to C02, C28 and C41. |
| A10-05 | MINOR | HLR-174 and HLR-174a statements vs LLR-174.1b (F) and ruling Q1 | Inconsistent trigger. HLR-174 asks when a load "would lose unsaved work", and HLR-174a loads without the question when it "would lose no unsaved work". Ruling Q1, probe U10 and draft §2 all establish that a project load does **not** lose the Flow Builder edits: they stay, and a later save writes them into the new project. Yet LLR-174.1b asks on F alone (the cell D = 0, W = 0, F = 1 → ask), and LLR-174.2k's "neither" arm is that same F-only scene. In that cell HLR-174a, as written, requires no question and LLR-174.1b requires one. A verifier reading the HLR finds the design non-compliant. HLR-174a's 7 scenes contain no F-only scene, so no test sees the clash. | draft:37, :67, :182, :323; E1-rulings Q1; baseline-notes U10 | Reword the trigger of both HLRs to the flags, not to loss: "…requests a load while unsaved work it would replace or move to another project exists (D for an image replacement; D, W or F for a project load)". HLR-174a takes the negation. No code change. |
| A10-06 | MINOR | LLR-174.2g statement ("a key other than `y`, `n`, `escape`, `enter`, `tab` or `shift+tab` … keep the question open with the session unchanged") | The statement claims more than the design delivers. `ctrl+q` is Textual's own `priority=True` App binding (`quit`). It is not in `_LOAD_DIALOG_INERT_ACTIONS`, and the S-f test does not make it inert. With D set and the question open, `ctrl+q` exits the app and the unsaved patch is gone. `ctrl+p` (priority, the command palette) opens over the question, and its system "Quit" command does the same. The 6-key threshold tests none of these, so the false statement passes. | Textual `app.py:454-462` (`ctrl+q`, `priority=True`), `app.py:880-889` (palette binding, `priority=True`); 9b: `_LOAD_DIALOG_INERT_ACTIONS` = {`load_file`, `save_project`, `focus_palette`, `cycle_density`}; proto-10-app.md C46 (palette opens over the question) | Narrow the statement to non-priority keys: "a key that no priority binding holds". Priority keys are LLR-174.2h's subject. Add an informative note: `ctrl+q` / the palette's Quit under the question belong to Inc 12's quit question. Add no guard here. |
| A10-07 | MINOR | interfaces-10.md S-a (:43 "G-A passes each label as plain `Content` (Q-1)"); G-A Q2 `compose`, I1, SB-6, SB-9, R-GA10-3; G-B seam row S-a ("labels as plain `Content`, Q-1") | Ruling P-GA10-1 Option A (labels as `rich.text.Text`) is not carried into the artifacts the implementer reads. G-A's Q2 node still builds `Button(Content(self._yes_label), …)`, and its I1 node still adds `from textual.content import Content`. An implementer who follows the node adds `textual.content` to `screens.py`, and 9b's TC-B100-64 arm 2 goes RED: `SCREENS_MODULES_AT_BASE` holds `rich.text` but not `textual.content`, and the test asserts `modules - SCREENS_MODULES_AT_BASE == set()`. The interfaces file contradicts its own ruling block (:126). | interfaces-10.md:43 vs :126; proto-10-dialog.md:76-77, :128-135; proto-10-app.md:284; 9b: `tests/test_b100_load_dialog.py` `SCREENS_MODULES_AT_BASE` and the final assert of `test_tc_b100_64_the_dialog_reads_nothing_itself` | Design-fix pass: S-a says `rich.text.Text(label)`. In G-A Q2, use `Button(Text(self._yes_label), …)` / `Button(Text(self._no_label), …)`. **Delete** node I1. Q2-3's RED arm stays (the `str` label). R-GA10-3 and SB-9 close. |
| A10-08 | MINOR | interfaces-10.md Q-4 ruling (:129); draft LLR-174.4 threshold (:447) | Two more accepted rulings are not applied in the fixed texts. The brief excludes only P-3 and P-GA10-2. (a) G-B P-1 (accepted): the MAC test and the target read `Path(str(path).strip().strip('"'))`. interfaces-10.md still fixes `path.suffix.lower() in MAC_EXTENSIONS` on the raw path, which C35 shows misreads quoted text (`.mac"`). (b) G-B P-2 (accepted): the draft's census clause still lists `_route_load_project` among the checked calls and keeps the `on_mount` exemption, which P-2 drops. | E2-rulings.md:10-11; interfaces-10.md:129; draft:447; proto-10-app.md:146, :154 (C35) | Apply both in the E3 design-fix pass: interfaces Q-4 gets P-1's wording; the LLR-174.4 threshold gets P-2's rule (with A10-01 applied, no body exemption is needed). |
| A10-09 | NIT | G-A seam SB-2 ("the callback runs inside `dismiss`, before the pop completes") vs interfaces S-b ("a dismiss callback runs through `call_next` after the pop") | G-A's sentence is wrong for Textual 8.2.8. `Screen.dismiss` calls `ResultCallback.__call__`, which only queues the callback (`requester.call_next(callback, result)`), then calls `app.pop_screen()`, which removes the screen from the stack synchronously. The `answer` closure therefore runs after the pop. No behaviour depends on it, because G-B defers `go` through `call_after_refresh` either way. | Textual `screen.py:2064-2067`, `screen.py:140-143`; proto-10-dialog.md:228 | Correct SB-2's wording to match S-b. |
| A10-10 | NIT | LLR-174.3c threshold ("refused by `validate_project_files`"); G-B C30 | The trace is stale against the 9b base. After 9b, `_handle_load_project` takes the 2-MAC refusal from `_list_project_files` (A9b-R3-4: the "more than one MAC / A2L" string lives there), not from `validate_project_files`. The outcome is unchanged: the refusal still comes before `_reset_project_session` (9b: `_handle_load_project`, the `error` return precedes `discarded_unsaved = self._reset_project_session()`). | draft:435; inc-9b-design/E3-rulings.md R3-4; 9b `app.py` `_handle_load_project` | Replace `validate_project_files` with `_list_project_files` in LLR-174.3c's threshold and C30. |
| A10-11 | NIT | baseline-notes census table (`test_b100_session_reset.py:781`, `:879-880`, `:945-946`); draft §D.4 | The line numbers are `8947666` lines. 9b edits `tests/test_b100_session_reset.py`, where AT-B100-03's `def` now sits at `:775`. A re-pin that follows the cited lines lands on the wrong lines. | 9b worktree `grep -n "def test_at_b100_03" tests/test_b100_session_reset.py` → `:775` | Cite tests by node id only, or re-cite against the 9b tree at E4. |

## Census on the 9b tests (executed)

**Result: the E2 breaking census holds for the 9b tests. No breaking test is missing.**

**Why this was run.** The E2 census ran on `8947666`'s tests. 9b edits 28 test files and adds `tests/test_b100_load_dialog.py`, so its re-pinned paths (`LoadDialog`, `_load_workarea_file`) had not been censused.

**Method.**
- Run on the 29 test files that 9b changes or adds, in the 9b worktree.
- The E2 plugin was copied to `work/e3-architect/plug/census10b_plugin.py`. Its only change: it wraps `_load_workarea_file` instead of `_load_from_item`, so both work-area surfaces are counted.
- `python -m pytest` was run from the worktree root. `s19_app.__file__` printed the worktree path, not the main checkout.
- 4 shards, each with its own `LOCALAPPDATA` under `work/e3-architect/`, `-p no:cacheprovider`.

**Totals.**
- 1,429 passed, 9 failed, 1 xfailed.
- 392 route calls.
- Asking events: 3, the same three the E2 census already lists:
  - `test_tc_b99_40_strip_shows_new_file_source_byte` (image kind, D);
  - `test_at_b100_03_…[size0]` and `[size1]` (project kind, W).

**Route calls by kind.**

| Route | Kind | Asks | Calls |
|---|---|---|---|
| `_load_path_from_user_input` | image | no | 206 |
| `_load_path_from_user_input` | image | yes | 1 |
| `_load_path_from_user_input` | attach | no | 36 |
| `_load_path_from_user_input` | refuse | no | 32 |
| `_load_path_from_user_input` | project | no | 10 |
| `_load_workarea_file` | image | no | 15 |
| `_load_workarea_file` | attach | no | 4 |
| `_route_load_project` | project | no | 85 |
| `_route_load_project` | project | yes | 2 |
| `_handle_select_variant` | image | no | 1 |

`tests/test_b100_load_dialog.py` reaches the routes with nothing unsaved in every arm.

**The 9 failures.** None recorded an asking event, so none is an Inc 10 census row. They belong to the unreviewed 9b worktree or this machine:
- 5 perf or ceiling bounds: TC-B100-05, TC-B100-61 ×4. Same families as the E2 run.
- 2 link arms on Windows: `test_e4_llr_171_2g_…`, `test_tc_b100_32_…[link]`.
- 2 dialog arms that fail on `NoMatches '#load_list'` / `'#load_reason'`: `test_ac7_workspace_load_project_button`, `test_at_b99_13_…`.

Not triaged further. These are 9b's E4 business.

## Checked and fine

- **Route coverage, ask-once.**
  - Every route that can replace unsaved work reaches exactly one seam call under S-d:
    - typed path, recent pick, project row and work-area row through the 9b router (9b: `_handle_load_dialog` dispatches `project` → `_route_load_project`, `workarea` → `_load_workarea_file`, `path` / `recent` → `_load_path_from_user_input`);
    - `p` and `#ws_load_project_button` → `action_load_project` → `LoadDialog(mode="list")` → the same router (9b: `action_load_project`; `on_button_pressed` `ws_load_project_button`) — not named in the graph, but covered;
    - `#files_list` → `_load_from_item` → `_load_workarea_file`;
    - `v`, the palette entry, and the Load-result panel `v` → `action_select_variant` → `_handle_select_variant`;
    - start-up `load_path` → `_load_path_from_user_input`.
  - A typed project folder asks once: the project arm passes to `_route_load_project` without its own seam.
  - Load call sites in the 9b `app.py` (`grep` for `load_selected_file(`, `load_from_path(`, `load_a2l_from_path(`, `_handle_load_project(`, `_start_load_worker(`) are all in those leaves, inside `_handle_load_project` (the MAC install), or the worker start. There are 0 callers in other modules. `tools/e13/run.py:135` calls `_route_load_project("P")` on a fresh app (nothing unsaved → `go()` at once, unchanged).
  - Out of scope by ruling, not missed: unload (Q7), Flow Execution sets (Q8), the Patch Editor's own doc load (`LoadGuardScreen`, LLR-174.2j), the Flow Builder's own load (`ConfirmDiscardScreen`).
- **No second question can stack.** Under the question the non-priority route keys (`l`, `p`, `v`, list picks) are blocked by the modal binding chain (Textual `app.py:3966-3989`, `_modal_binding_chain`). The four priority loaders are inert under S-f. The answer callback is queued on the pump that pushed the question (Textual `app.py:2946-2951`), which is the App for every route.
- **Unsaved predicate.**
  - D: `ChangeService.differs_from_last_saved` (9b worktree `change_service.py:2098-2142`, `False` for `None`, O(journal + recorded)).
  - W: the only writers of the document outside load or paste are panel actions that set `_dirty` (9b: `on_patch_editor_panel_action_requested` → `service.add_entry` / `edit_entry` / `remove_entry` after `request_action` sets w1); `load_doc` comes from a file; `parse_paste` → `mark_pasted` (w5).
  - F: `FlowBuilderPanel.is_dirty` (`flow_screens.py:1353-1356`); `current_flow` builds a frozen dataclass with no validation (`flow_model.py:537`), so reading `.name` cannot raise.
  - An image replacement leaves `current_project`, the document and the builder alone (9b: `_apply_prepared_load` touches only the image, the pending stamp and `mark_saved`). That is why W and F count for a project load only.
  - A MAC-only session cannot hold D: Apply needs ranges, and the MAC loader gives empty ones. So "an attach never asks" has no hidden image-replacing MAC case.
- **9b graph consistency.**
  - `check_action` (9b: `any(isinstance(s, LoadDialog) for s in self.screen_stack)`, `_LOAD_DIALOG_INERT_ACTIONS` at `:318`) matches S-f's base.
  - `_load_workarea_file` (9b: `exists()`, then `A2L_EXTENSIONS` → `load_a2l_from_path`, else `load_selected_file`) matches G-B's `go`.
  - `MAC_EXTENSIONS` and `A2L_EXTENSIONS` are sets (`workspace.py:111-112`), so `|` works.
  - The router stays as 9b writes it.
  - `_reset_project_session`'s only call site and the refusals before it are as G-B states.
- **Recent store on cancel.** `record_recent_source` is called only inside `load_from_path` and `load_a2l_from_path` (9b `:13659`, `:13735`), both inside `go`. A cancelled typed path leaves the store unchanged.
- **Textual 8.2.8 behaviour.**
  - `ModalScreen[bool]` dismiss runs the callback once per call (K7 executed; A10-03 for the trace).
  - `AUTO_FOCUS` is applied at push (`app.py:2953`).
  - Priority bindings walk App → screen and go through `run_action` / `check_action` (`app.py:3979-3987`).
  - `Button.validate_label` → `Content.from_text`, which parses a `str` as markup, takes a `Text` through `from_rich_text`, and returns a `Content` unchanged (`_button.py:403-405`, `content.py:254-262`). Option A (`Text`) is therefore literal.
  - `App.query_one` searches the default screen (`app.py:941-943`).
- **The 9b tests Inc 10 could break by structure.**
  - TC-B100-40's push-site census counts only `LoadDialog` pushes.
  - TC-B100-64 arm 2 is safe once A10-07 is applied.
  - `SCREENS_MODULES_AT_BASE` already holds `rich.text`.
- **Requirement ↔ example coverage.** Every LLR-174.* and HLR-174* has at least one example in G-A or G-B, except the per-route focus arm (A10-04). Orphan examples are A10-01 (C32), A10-02 (C15) and A10-03 (Q5-*). The P2 comment node and C1 are records, not behaviour.
- **Simplicity.** The `attach` kind passing through the seam (always `[]`) looks removable, but it is kept by the census rule and by Inc 12b's worker refusal in the same seam (LLR-174.4 note). It is not a finding.

## Round 2

PASS-WITH-NOTES — 0 HIGH · 0 MAJOR · 0 MINOR · 3 NIT.

Narrow check of the design-fix pass against `E3-rulings.md`. Only the three items the orchestrator named were checked.

| Item | Status | Evidence |
|---|---|---|
| (1) A10-01 | CLOSED | `proto-10-app.md` `_route_load_project`: `in: str name`; step (1) is now the `go` closure that calls `_handle_load_project(name)`; step (2) is the seam; C32 is gone. The census in the LLR-174.4 threshold (draft :479) holds on the designed code: the only `_handle_load_project` call outside the handler sits inside that `go`. The loaders are called only inside `go`s, inside `_handle_load_project` (the MAC install), or by the worker start. The new S10-02 node calls `_patch_editor_load`, which the census does not count. |
| (2) A10-07, A10-08 | APPLIED | Implementer-facing text uses `rich.text.Text`: interfaces S-a :43; G-A Q2 `Button(Text(...))` (:76-77); SB-6 and SB-9; the G-B S-a row (:293). Node I1 is retired (:39). Interfaces Q-4 carries P-1's strip (:128). The draft's LLR-174.4 census carries P-2, with no `on_mount` exemption (:479). The remaining `Content` mentions are history only: the K6 probe record, the open-question text Q-1 (:109), and R-GA10-3 / P-GA10-1. |
| (3) S10-01, S10-02, LLR-174.2s/.2t/.3d | No new MAJOR | See the checks below. |

**S10-01 (reads moved before the reset).** Checked against the 9b `_handle_load_project`:
- The moved calls are all reads: `build_variant_set`, `read_project_manifest`, `check_project_files`, the `recorded` read, `_load_a2l_data_with_cache` and `choose_install_set`.
- `_load_a2l_data_with_cache` writes only `_a2l_cache_key` / `_a2l_cache_data`. That cache is stat-keyed, and `_reset_project_session` does not clear it, so the cache ends in the same state in either order.
- The reset remains the one call site (TC-B100-08 holds).
- `_declared_regions` (a write) stays after the reset.
- Every refusal now comes before the reset.

**S10-02 (the dropdown guard).**
- The node reuses `LoadGuardScreen` and `_patch_editor_load`, the same shape as the Load button.
- No existing test picks from `#patch_doc_file_select` while the panel is dirty. The only programmatic pick is `test_b97_patch_editor.py:1458`, on a clean panel. So the guard breaks no test.

**The new LLRs.** LLR-174.2s, .2t and .3d are each one unwanted-form "shall" with a threshold and an executed or stated negative control.

### Round 2 notes

| Id | Severity | Where | Defect | Proposal |
|---|---|---|---|---|
| A10-R2-1 | NIT | interfaces-10.md S-d :62 | The text still says "A `None` name returns first, with no question". That is stale after A10-01 (the node takes `name: str`). | Delete the sentence. |
| A10-R2-2 | NIT | proto-10-dialog.md R-GA10-3 (:251-255) | The risk still reads as live and is anchored on the retired node I1. | Mark it "closed by P-GA10-1 Option A (I1 retired)". |
| A10-R2-3 | NIT | G-B `on_patch_editor_panel_change_file_selected`, C59 | After a cancelled guard, `#patch_doc_file_select` keeps showing the picked file while the document holds the old entries. Picking that same file again fires no `Select.Changed`: Textual posts it only when the value changes. To retry, the engineer must pick another file or use the Load button. Nothing is lost. | Declare it in the risks, or reset the Select to `Select.NULL` in the cancel arm (one line). |
