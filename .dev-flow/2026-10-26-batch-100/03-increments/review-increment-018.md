PASS-WITH-NOTES

# Code Review — Increment 018 (batch-100 Inc 9b: the unified Load dialog), stage E5

Reviewer: `code-reviewer`. I worked independently of the authors and read the tree only. I edited no source or test file.
Tree: `<HOME>/Github/s19_app-b100-inc9b`, branch `b100-inc9b`, commit `741cc07`. Diff reviewed: `git diff 8947666..741cc07 -- s19_app tests`.

## Verdict

PASS-WITH-NOTES. Counts: 0 HIGH, 1 MAJOR, 3 MINOR, 2 NIT.

- **Source code.** I found no correctness defect in the four source files. The router, all four routes, the guard, the shared lister, the A2L admission and the `project.json` gate match the approved graph and the Round 3 addenda.
- **The MAJOR finding is in a test, not in the code.** In the priority-key test, the `ctrl+k` arm cannot fail. I proved this with a probe: a mutant that drops `focus_palette` from the guard survives the test, while the other three drops turn it RED.
- **Status in this flow's terms.** OK to advance, with notes. No HIGH is open. CR9b-01 is a one-assertion fix to the test. I recommend applying it before close, because the code it should prove is correct by reading, but no test currently checks it.

## Scope reviewed

- Source, read in full:
  - `s19_app/tui/screens.py`: `LoadChoice`, `LoadDialog` (182–549), and the five docstring rewordings.
  - `s19_app/tui/__init__.py` (the re-exports).
  - `s19_app/tui/styles.tcss`: C1–C4 and the SR-1 rule.
  - `s19_app/tui/app.py`, the whole +803 diff:
    - constants (295–319);
    - `action_load_file` / `action_load_project` (7364–7495);
    - `_load_dialog_rows` / `_verdict` / `_preview` and `_file_preview_marks` (7532–7835);
    - `check_action` (8394–8420);
    - `_handle_load_project` (12043–12330);
    - `list_projects`, `_folder_holds_project`, `_list_project_files` and `_a2l_admission` (12499–12780);
    - `_typed_load_route` (13330–13472);
    - `_handle_load_dialog` (13538–13589);
    - `load_from_path` / `load_a2l_from_path` (record steps);
    - `_load_from_item` / `_load_workarea_file`.
- Tests:
  - `tests/support/b100_load_dialog.py`, in full;
  - `tests/test_b100_load_dialog.py`: the fixtures, Fakes, every TC-B100-40 function, and the TC-B100-41/-63/-64 functions named below;
  - the full diffs of the re-pins in `test_b100_recents.py`, `test_b100_focus.py`, `test_b99_load_project.py`, `test_b100_project_homes.py`, `test_b100_project_check.py`, `test_tui_directionb.py`, `test_tui_app.py`, `test_tui_helpers.py`, `test_loadfilescreen_input.py`, `test_clipboard_tk_singleton.py`, `test_b100_active_variant.py`, `test_b100_announce.py`, `test_b97_load_project_dialog.py`, `test_id_registry.py` and `test_b100_reuse.py`;
  - the assertion lines of the other b99 and b100 re-pins.
- Design checked against:
  - `codewire/interfaces-9b.md`;
  - `proto-9b-app.md`, nodes and examples B01–B103;
  - `proto-9b-dialog.md`, S3–S9;
  - E1, E2 and E3 rulings (Round 3 addenda);
  - `E4-app-notes.md`, `E4-dialog-notes.md`, and `E4-integration-notes.md` with SR-1 … SR-7.
- New tests: 141 in total. That is 133 items in `test_b100_load_dialog.py` (78 functions, some parametrised), plus 4 in `test_b100_recents.py` (TC-B100-34 ×3, TC-B100-37) and 4 in `test_b100_focus.py` (2 functions × 2).

## Findings

| Id | Sev | Tag | Where | Defect | Evidence | Fix |
|---|---|---|---|---|---|---|
| CR9b-01 | MAJOR | impl | `tests/test_b100_load_dialog.py:1114-1117`, `:1137` (`test_tc_b100_41_priority_keys_are_inert_while_the_dialog_is_open`) | The `ctrl+k` arm reads `app.focused`, which is the focus of the top screen (the dialog). `action_focus_palette` calls `CommandBar.open_palette()` on the default screen, under the modal. So if `focus_palette` leaves the guard, the palette opens behind the dialog while `app.focused` stays inside it, and the arm passes anyway. Of the four members of LLR-173.2e's inert set, `focus_palette` is the one that no test proves. | **Probe executed** (`scratchpad/rev9b-cr/probe_cr_priority.py`): `_LOAD_DIALOG_INERT_ACTIONS` minus one action, then the test is run. Dropping `cycle_density`, `save_project` or `load_file` turns it RED. Dropping `focus_palette` leaves it **GREEN** ("mutant dropping focus_palette survived"). Failure scenario: a later edit removes `focus_palette` from the set → `ctrl+k` with the dialog open opens and focuses the command-bar palette on the hidden main screen. The test stays green. | Assert on the screen under the modal. Record `app.screen_stack[0].focused` (or the CommandBar's open state) before `ctrl+k`, and assert it is unchanged after. Re-run the probe: the `focus_palette` drop must turn RED. |
| CR9b-02 | MINOR | impl | `tests/test_b100_load_dialog.py:767`, `:788` (`test_tc_b100_40_recent_choice_loads_the_recorded_text_unchanged`) | B13 says that after the recent `fw.s19` loads, "the store's first entry is that path again". The test seeds `[fw, cal, gone]`, loads `fw`, then `cal`, and asserts `fw in paths[:2]`. Without the `fw` re-record, the store after the `cal` record is `[cal, fw, gone]`, which is the same as with it. So that half of the arm cannot fail. | **By reading.** `record_recent_source` puts the new entry first and de-duplicates by `normcase` (`workspace.py:2431`). Seed `[fw, cal, gone]` → record `cal` → `[cal, fw, gone]`, with or without the `fw` record. A mutant that skips `record_recent_source` for a `recent` choice passes this assertion. | Seed with `fw` last, for example `[gone, cal, fw]`. Read the store after the `fw` load and before the `cal` load, then assert `paths[0] == str(src / "fw.s19")`. |
| CR9b-03 | MINOR | design-gap | `app.py:13412-13424` (walk) with `:13425-13436` (S9b-7), `:300` (`"link"` tokens), `:13525-13529` (status sentence) | S9b-7 moved the in-work-area data/A2L returns after the `lstat` walk. As a result, a typed data file inside W that is a link, or that sits under a linked folder, is now refused `link`. On 9a it loaded, because the data return came before the walk (removed lines at old 12841-12844). The refusal is correct, but its wording is written for projects: the dialog paints `link or junction — pick a project in the list`, and the status reads `Project NOT loaded: '…' passes through a link or junction — pick a project in the list.` That text is shown for a file, and the step points at the wrong remedy. The graph names this behaviour change for folders named `x.s19` only, not for linked files. | **By reading.** Failure scenario: `W/temp/fw.s19` is a symlink to a real S19 and the user types its full path → verdict `("link or junction", "pick a project in the list")`. The engineer is told to pick a project, but they typed a file. | Declare the behaviour change in the packet risks, and either (a) accept the wording, or (b) give the file case its own step (`check the path`). That would be a classifier reason such as `("refuse", "link file")` and one more `_TYPED_REFUSAL_TOKENS` key. The orchestrator rules. |
| CR9b-04 | MINOR | impl | `s19_app/tui/os_clipboard_input.py:470`; `REQUIREMENTS.md:309`, `:914`, `:960`, `:1261`, `:6477`; `docs/architecture.md:670` | References to the retired classes remain outside the slice. `OsClipboardInput`'s docstring still lists `Used by: LoadFileScreen`. `REQUIREMENTS.md` traces R-TUI-043 and the project-load row to `LoadFileScreen` / `LoadProjectScreen`, and **LLR-151.1** ("On Load, LoadProjectScreen shall dismiss …") is still `active`. `architecture.md:670` says `_handle_load_dialog` "keeps accepting a `Path`", which A9b-08 retired. Inside `s19_app/` and the four source files, nothing else names the retired classes or ids (grep: 0 code references). | **By reading** (`grep -rn 'LoadFileScreen\|LoadProjectScreen'` outside `.dev-flow`). Failure scenario: a later trace audit reads LLR-151.1 as active against a class that does not exist, so the ledger and the code disagree. | At close: mark LLR-151.1 superseded (by LLR-173.2f / LLR-173.3d) and re-point the R-TUI-043 code traces to `LoadDialog`. Fix the docstring line in `os_clipboard_input.py` (one line, outside the 4-file cap, so it needs a ruling or goes to the backlog). Correct `architecture.md:670`. |
| CR9b-05 | NIT | impl | `app.py:7577`, `:7718`, `:7776` (token line), `:12120`, `:12202`, `:12211` (status block); `_TYPED_REFUSAL_TOKENS["unreadable"]` at `:301-304` | The same "could not be read — check that the folder can be opened, then load again" pair is written out 3 more times beside the table that already holds it. The new `Project NOT loaded: '…' could not be read …` status block is pasted 3 times in `_handle_load_project`. The S9b-2 gate's `except OSError` branch and its non-regular branch paint the same line. | By reading. Failure scenario: a later wording change edits the table and misses a copy, so the preview and the verdict disagree. That is drift only, with no behaviour defect today. | Add one module constant, `_UNREADABLE_LINE = " — ".join(_TYPED_REFUSAL_TOKENS["unreadable"])`. Fold the gate into one condition (`manifest_stat` unreadable or not `S_ISREG` → one status line). |
| CR9b-06 | NIT | impl | `screens.py` `LoadDialog.on_mount` (≈347), `on_key` (≈392), `action_load` (≈442), `_schedule_preview` (≈516) | PROJECT_RULES.md asks for full docstring sections on helpers that "encode non-obvious rules". These methods encode the source precedence (S-f), the escape-before-enter order (A9b-06) and the clear-then-paint rule, but they use a one-line summary plus `Data Flow`, with no `Summary:` header and no `Dependencies` section. The `LoadChoice` / `LoadDialog` class docstrings and every new `app.py` function follow the contract. | By reading. There is no failure scenario: this is convention only. | Add `Summary:` and `Dependencies` (`Uses` / `Used by`) to `action_load` and `on_key` at least. |

## Checked and fine

- **Router `_handle_load_dialog` (`app.py:13538-13589`).**
  - `None` re-homes the focus and schedules nothing.
  - `project` → `_route_load_project` (Load-result panel); `workarea` → `_load_workarea_file`; `path` / `recent` → `_load_path_from_user_input(Path(value))`.
  - Every route goes through `call_after_refresh`, there is no else arm (closed `Literal`), and the log line carries `kind` / `value`.
  - **Probe executed** (`probe_cr_rehome.py`): a mutant that returns on `None` with no re-home turns both `test_tc_b100_12_load_dialog_close_*` arms RED (stale input, and the P-16 table). The A9b-03 tests can fail.
- **The four routes, end to end.**
  - Project pick → `_handle_load_project` matches the listing (9a R3).
  - Work-area data → `load_selected_file` in place, with 0 copies (`_load_workarea_file` keeps the 9a body; A9b-05 A2L route kept).
  - Typed path → `_typed_load_route`, run twice (verdict, then router). This is harmless and classifies metadata only.
  - Recent → absolute branch; a missing recent → `resolve_input_path` returns `None` → `not found` (no base-folder fallback for a drive-rooted text).
- **Verdict.** `project` / `workarea` return `None` with no filesystem call. `path` / `recent` go through `_TYPED_REFUSAL_TOKENS`, whose keys cover all 6 refuse literals (B57). There is no catch (R-5).
- **Guard `check_action`.** It covers the whole stack (S9b-1). The action names match `BINDINGS` (`app.py:2155-2158`). The non-priority keys `p` / `l` / `s` are cut at the modal by Textual's `_modal_binding_chain` (`textual/screen.py:449-455`), so `load_project` does not need to be in the set. Textual's system command palette exposes no app actions.
- **Dialog.**
  - `on_key` order: escape, then enter on list/preview, then the printable redirect with `_source` switched at once and the preview cleared.
  - `_dismissed` is the first line of both `action_load` and `_close` (A9b-02, R2-6).
  - `alt+l` is priority. `_row_choice` returns the very row object (LLR-173.3d). `_path_choice` keeps the text verbatim.
  - `restrict=` takes effect on typed and pasted text: `OsClipboardInput.action_paste` → `Input.replace` → `check_allowed_value` (`textual/widgets/_input.py:985-1012`). The programmatic redirect appends only printable characters.
  - Markup: `OptionList(markup=False)` plus `Text(...)` into a `markup=False` `Static`.
- **Preview equals install.** The preview and `_handle_load_project` share `_list_project_files`, `_a2l_admission` and `choose_install_set`, with the same `recorded` derivation.
  - More than one MAC or A2L → every mark `False`, and the install refuses with the status line (A9b-R3-5).
  - A non-regular `project.json` → one `could not be read` line, 0 marks (R3-1); an absent file is not a refusal.
  - `_list_project_files` returns the 9a 3-tuple and the 9a error strings word for word (A9b-R3-2/-4). Its rules are the same as `validate_project_files` except for the no-follow test (LLR-173.4n).
- **`_handle_load_project`.** The S9b-2 gate sits before `_reset_project_session()` (`:12224`), so the refusal leaves the session unchanged (B99). The F-12 catch wraps the listing. `Project not found` and `A2L loaded:` go through `painted_names` (S9b-5).
- **`list_projects` / `_folder_holds_project`.** The listing fails open on `None` (B19). The SR-2 cost (one listing per non-manifest folder at each open, verdict and pick) is declared.
- **`load_from_path` / `load_a2l_from_path` `via_fallback`** follow the B24–B30 condition exactly and make no filesystem call.
- **Deleted screens.** `screens.py`, `app.py`, `__init__.py` and `styles.tcss` hold 0 references to `LoadFileScreen` / `LoadProjectScreen` / `#project_list` / `#project_ok` / `#project_cancel` / `#loadproject_buttons` / `#loadfile_buttons`. The shared selector was narrowed to `.modal-dialog`, and every one of the six remaining `id="load_dialog"` modals also carries `classes="modal-dialog"` (`screens.py:929`, `1058`, `1128`, `1219`, `1279`, `2412`), so none of them loses its styling. Only the references in CR9b-04 remain, all outside the slice.
- **Re-pins.** Read in full; none weakens what its test proved.
  - TC-B100-32 (F-1) and the list-projects census (Q7): content is added to each listed folder, and TC-B99-35 got *stronger*, because `patches` now holds an `.s19` too.
  - AT-B99-13 got stronger: the third arm now asserts `focused.id == "load_ok"`. The empty boundary moved to LLR-173.2h under SR-4.
  - TC-B100-38: "route: validate_project_files" → `_list_project_files` (A9b-R3-1), same intent.
  - test_ac7: a bounded wait only.
  - TC-B100-61: the paint clock starts when the load returns (SR-3). The base never had the load inside `pressed` either, so the property is unchanged, and the load keeps its own 1 s bound.
  - All `LoadProjectScreen` drivers: click-the-row → arrow-key highlight. Click-the-row coverage survives in AT-B99-13 arm 2 (`click_row`) and in `test_tc_b100_41_click_highlights_and_never_loads`.
  - TC033: both dialog modes are checked.
- **New tests: intent and ability to fail.** Every function read states its why and its negative control.
  - Probe-confirmed RED: the three remaining guard members, and the A9b-03 re-home.
  - By reading:
    - the S9b-2 arms count opens with a `realpath` spy;
    - the LLR-173.4n arm counts opens of the link target;
    - preview-equals-install compares `●` names with the Loaded panel on 4 + 4 fixtures;
    - the type-ahead and double-enter arms post queued keys.
  - The only vacuous arms found are CR9b-01 and CR9b-02.
- **Evidence (QA lane, noted only).** `green-02` is recorded as 127 passed / 1 failed (SEC6-5 timing, SR-7). `green-02b` passed 3/3 on rerun. The batch-end battery owes a quiet-host run.

## Evidence states

| Item | State |
|---|---|
| Diff read in full (source) | `executed` |
| Tests read: support module and re-pin diffs in full; new file by function (TC-B100-40 all; -41/-63/-64 arms named above) | `executed` |
| Probe: guard members (`probe_cr_priority.py`, 4 mutants: 3 RED, 1 survived) | `executed` |
| Probe: A9b-03 re-home (`probe_cr_rehome.py`, 2 mutants, 2 RED) | `executed` |
| CR9b-02, CR9b-03, CR9b-04 | `executed` (by reading) |
| Full suite / touched modules | `not-run` (out of lane; batch-end battery) |
| Security lens | `n/a — security-reviewer's lane` |

Probe folder: `<HOME>/AppData/Local/Temp/claude/C--Users-<USER>-clde/a8feab43-c248-4ccb-86cf-122b894659b2/scratchpad/rev9b-cr/`.

## Evidence checklist

- ✓ Diff read in full: `screens.py:182-549`, `app.py` +803 hunks (cited above), `styles.tcss:1578-1840`, `__init__.py:32,61-62`.
- ✓ Correctness pass: None/empty/error paths (verdict on blank text never reached, V-1; `rows()` `OSError` only from `list_projects`, caught; preview `OSError` caught; `_close` re-entry).
- ✓ Simplicity pass: no premature abstraction. G1, `_a2l_admission` and `_list_project_files` are each shared by 2+ callers. Duplication noted in CR9b-05.
- ✓ Reuse checked: `choose_install_set`, `list_workarea_files`, `read_recent_sources`, `painted_names`, `_rehome_focus_after_load` are reused, not re-implemented.
- ✓ Tests reviewed for intent; two vacuous arms found (CR9b-01 executed, CR9b-02 by reading).
- ✓ Verdict explicit: PASS-WITH-NOTES; no HIGH open.

## Packet §4b `Independent review` cell (code-reviewer part)

`code-reviewer` · PASS-WITH-NOTES (OK to advance, with notes; 0 HIGH · 1 MAJOR · 3 MINOR · 2 NIT) · no HIGH to resolve. CR9b-01 (MAJOR, test only): the `ctrl+k` arm of the priority-key test cannot fail (probe: dropping `focus_palette` from the guard survives); fix recommended before close.
