# Code-Wire graph — Inc 12 (every dialog and action reachable, every Check Editor widget shown; Escape closes the Reports dialog), batch-101

Stage E2 of the design-first flow (`dev-flow-v3-beta`), corrected at E3 (`../E3-rulings.md`; split D-5 B: the `flow_screens.py` nodes, group G4, moved to `../../inc-12b/codewire/graph-inc12b.md`). Graph only: no stub, mark or declaration in any tree. Base `2d1e2b1` (product `e07fb00`). Requirements `../01-requirements.md`, slice `../E1-slice.md`, rulings `../E1-rulings.md` (E3: §7), cases `../02-test-cases.md`. Notation: Code-Wire v3.1 (the Code-Wire repository's `docs/Notation-Grammar.md`), as in Inc 9's `inc-9/codewire/graph-inc9.md` (branch `b101-inc9`, not yet on main) and `../../inc-8/codewire/graph-inc8.md`.

How to read it:
- One file holds the baseline and the prototype. Every node's `func:` starts with **unchanged**, **changed** (then "was: … / now: …", the baseline first), **new** or **removed** (then "was: … / now: absent"). Context nodes (unchanged) are here because a changed node calls them, a removed node's function now lives in them, or their examples are the oracle of a row.
- Example sources are the case ids of `02-test-cases.md`; `B` = the E1 pilot (`../evidence-e1/i12e1-pilot-transcript.txt`), `C` = the E1 census (`../evidence-e1/i12e1-census-transcript.txt`), `R` = read (E3: the architect's AST read, `../E3-architect.md`). Every example states the Inc 12 target unless it says "holds on base" or "the base".
- "Closed" = no `ReportViewerScreen` on the screen stack and the app's main screen on top. **Reports project** = `proj1` with two files in `reports/` and `filters/f1.json` (the cases' fixture).
- The graph follows the orchestrator's rulings (`../E1-rulings.md`: D-1 A, D-2 A, D-3 A, D-5 B, D-6 A, D-7 A, D-8 A, D-9 A, D-10 A) and the E3 rulings (`../E3-rulings.md`).

### Groups for E4 (file ownership) and interfaces — pinned here, changed only by an orchestrator ruling

| Group | Files | Owns nodes |
|---|---|---|
| G1 dialogs | `s19_app/tui/screens.py`; docs `docs/user-guide/ch16-reports.md`, `ch18-flow-execution.md`, `DOSSIER.md` (rows F-33, F-34, F-35, F-51; on the merged tree); tests `tests/test_b101_reach_and_reports_escape.py` and `tests/test_b101_help_legend_docs.py` (tester G-T1, also AT-I12-1, AT-I12-2) | `VariantHelpScreen`, `ReportViewerScreen.action_close_reports`, `[Data: ReportViewerScreen.BINDINGS]`, `[Data: VARIANT_HELP_TEXT]`, `[I/O: docs/user-guide/ch16-reports.md, ch18-flow-execution.md]`, `[I/O: docs/user-guide/DOSSIER.md §5]` |
| G2 app | `s19_app/tui/app.py`; tests G-T1 (the same file) | `S19TuiApp.action_view_main`, `.action_view_alt`, `.action_view_mac`, `._jump_to_validation_issue`, `._jump_to_validation_issue_object`, `._format_validation_issue_line`, `._update_issues_hex_pane` |
| G3 Check Editor | `s19_app/tui/screens_directionb.py`; tests `tests/test_b101_shown_widgets.py` (tester G-T2, also AT-I12-3) | `CheckEditorPanel.compose`, `CheckEditorPanel.on_button_pressed` |

G4 Flow (`s19_app/tui/flow_screens.py`) moved to Inc 12b at E3 (D-5 B).

| Interface | Pinned form | Producer → consumers |
|---|---|---|
| I-1 Reports Escape | `ReportViewerScreen.BINDINGS` = `[Binding("question_mark", "show_window_usage_help", "Window help", show=False), Binding("escape", "close_reports", "Close", show=False)]` (not `priority`); `ReportViewerScreen.action_close_reports(self) -> None` logs `ReportViewerScreen dismissed by Esc.` and calls `self.dismiss(None)`; it posts no message | G1 → G-T1 (R-DLG.2, R-DLG.15), TC-706's binding census (`tests/test_window_usage_help.py:625-627`) |
| I-3 the removed names | after Inc 12 no source or test names `VariantHelpScreen`, `VARIANT_HELP_TEXT`, `action_view_main`, `action_view_alt`, `action_view_mac`, `_jump_to_validation_issue`, `_jump_to_validation_issue_object`, `_format_validation_issue_line` or `#check_preview_toggle_button` (except `window_help.py`'s three docstrings, BL-I12-1). Checked at integration by a grep of the merged `s19_app/` and `tests/` before the GREEN run, the empty result recorded (S-3). The flow ids and the painter family are Inc 12b's I-3 | G1–G3 → G-T1, G-T2; the testers of Inc 9, 10a, 10b (`../E1-rulings.md` §5) |
| I-4 the visible oracles | the addendum: `#check_tab_addendum` → `#check_addendum_preview`; windows: keys `1`, `2`, `3` or `action_show_screen`. The chain, session and kind oracles are Inc 12b's I-4 | unchanged producers → G-T1, G-T2 |
| I-5 the census definitions (corrected at E3, E3A-01, E3A-02) | *dialog* = a `ModalScreen` subclass; *opener* = a construction of it outside its own body, inside a reached function (a subclass's opener counts for its base). *action* = an `action_<name>` method of any class. *action string* = a string literal, not a docstring, that is wholly `<name>`, `<name>(<args>)`, `app.<name>` or `screen.<name>` (a binding's or a palette entry's action, or a `run_action` argument), or the target of an `@click=` link. *reach* = an action string naming `<name>`; a `BINDINGS` action declared on a toolkit base class of the method's class (`CappedTextArea(TextArea)`, `OsClipboardInput(Input)`); or a call or reference `.action_<name>` inside a reached function. *reached function* = an action that has a reach, a method the toolkit dispatches by name (`on_*`, `_on_*`, `compose`, `watch_*`, `validate_*`, dunders), or a function a reached function calls or passes (fixpoint; references count). Message words, docstrings and comments never count. Stated limit: a product binding's action string counts for every action of that name (no class scope; no instance on base). Base (R, re-measured at E4): 3 of 83 actions without a reach, 1 of 22 dialogs without an opener; after: 0 of 80, 0 of 21 | G-T1 (R-DLG.14/1, R-SHELL-KEYS.3/1) |
| I-6 Inc 10a | `S19TuiApp._jump_to_validation_issue_object` is removed; 10a's slice #11 and its issue-jump cases (R-TUI-018.1/5, R-TUI-018.3/1, R-TUI-040.12/2) are withdrawn in 10a's committed records (addendum "Inc 12 D-2", `d68cb9f` on `b101-inc10`; E3A-07) | the orchestrator → Inc 10a |
| I-7 Inc 12b | no code edge: no Inc 12 node calls a node of 12b, nor the reverse; 12b removes no action and no dialog, so I-5's counts do not move. Shared: DOSSIER F-35 and `_FIXED` owned by Inc 12 (it merges second; if the order flips, the increment that merges second marks F-35); CTX-SHELL terms identical in both records (the first to merge folds them); `tests/test_tui_directionb.py` (the TC-011 docstring and comment here, two flow nodes there: disjoint hunks); `tests/test_id_registry.py` (+2 here, +1 there, each re-measured at its integration). R-DLG.15/2 adds its CHECK block through the kind chip, so it holds before and after 12b | Inc 12 ↔ Inc 12b |
| I-8 Inc 9 (docs seams) | Inc 9 edits `ch18-flow-execution.md` (`:113`), `DOSSIER.md` (F-45, F-46) and `tests/test_b101_help_legend_docs.py` (`_FIXED` 11 → 13); Inc 12 makes its ch18, DOSSIER, `_FIXED` and `_GUIDE_PASSAGES` edits on the tree after Inc 9 (E3A-04) | Inc 9 → G1, G-T1 |

Order inside E4: G1 … G3 in parallel (disjoint files; no implementer consumes another's interface); G-T1, G-T2 in parallel. Merge order: Inc 9 → Inc 12b → Inc 12, last in the `app.py` chain after 10a and 10b. Integration on that merged tree: the I-3 grep (S-3) and the census re-run of `../E1-slice.md` §5 before the GREEN run; DOSSIER F-35 is marked only if Inc 12b is on main.

## Nodes

VariantHelpScreen
req: R-DLG.14
in:
out: None
func: removed (D-1 A). was: a `ModalScreen[None]` with the title "About the variant selector", `#variant_help_body` (the text `[Data: VARIANT_HELP_TEXT]`) and Close, dismissed by Close; no part of the system constructs it (its opener, the Patch Editor variant selector, left in batch 94). / now: absent, with its constant and comment (`screens.py:1070-1153`).
module: s19_app/tui/screens.py
examples: (R-DLG.14/1) census of the tree under test → `VariantHelpScreen` is not a dialog of it; 0 dialogs without an opener; at least `21` dialogs
examples: (R-DLG.14/1 neg, the base) census → `22` dialogs, 1 without an opener: `VariantHelpScreen` (C)
examples: (R-DLG.14/1, E3A-02) an opener counts only inside a reached function: one hop up on the base, `LoadResultScreen` ← `_install_prepared_project`, `FileRefChooserScreen` ← `_open_file_ref_chooser`, `WindowHelpScreen` ← `open_window_help` (R)
examples: (holds after) `test_at067a_variant_info_button_opens_help_modal` and `test_tc336_tc337_help_message_pushes_modal_with_content` still assert that the opener and its message are gone

ReportViewerScreen.action_close_reports
req: R-DLG.2
in:
out: None
func: new (D-7 A; I-1). Run by Escape through `[Data: ReportViewerScreen.BINDINGS]`; logs `ReportViewerScreen dismissed by Esc.` and calls `dismiss(None)` — what Close does (`ReportViewerScreen.on_button_pressed`): it posts no message, so no report is generated and no typed filter path is applied (R-DLG.9).
module: s19_app/tui/screens.py
modify: [Data: App.screen_stack] (replace)
examples: (R-DLG.2/1) Reports project, the focus on `#report_list`, `escape` → closed; `reports/` holds `2` files; the status line as before (base: open, B)
examples: (R-DLG.2/1, U-2) the widget focused before `t` and the shown window recorded → after `escape` the same widget focused and the same window shown; one Close press in place of `escape` gives the same (the reference)
examples: (R-DLG.2/3) `x` typed in `#report_declared_regions`, `escape`, `t` → closed, then the box text `""`
examples: (R-DLG.2/5) `abc` typed in `#report_filter_path`, `escape`, `t` → the path box `""` and the dropdown blank
examples: (R-DLG.2/7) the focus on `#report_generate`, `escape` → closed; `2` files
examples: (R-DLG.2/7 neg) mutant: the action posts `GenerateRequested` before the dismiss → `3` files → RED
examples: (R-DLG.2/9) the focus on `#open_folder_reports`, `escape` → closed; the folder spy counts `0` calls
examples: (R-DLG.2/11) Empty Reports project, `t` (the focus on `#window_help_reports`), `escape` → closed (base: open, B)
examples: (R-DLG.2/2, /4, /6, /8, /10) the focus on `#report_markdown_scroll`, `#report_filter_select` (list closed), `#report_context_bytes` (`9` typed), `#report_close`, `#window_help_reports`, `escape` → closed each time
examples: (R-DLG.2/1 neg, the base) no Escape binding → after `escape` the top screen is still `ReportViewerScreen` from each of the 10 places (B lines 35-44)
examples: (AT-I12-1) `t`, `enter`, `escape` → closed, the focus back on the widget of before `t`; `t`, tab to `#report_filter_path`, `abc`, `escape` → closed; `t` → the path box `""`

ReportViewerScreen.on_button_pressed
req: R-DLG.2
in: Button.Pressed event
out: None
func: unchanged. Close (`#report_close`) logs `ReportViewerScreen dismissed by close.` and calls `dismiss(None)` (`:3479-3482`); Generate parses `#report_context_bytes`, posts `GenerateRequested` to the app and dismisses (`:3483-3506`). The oracle of "what Close does".
module: s19_app/tui/screens.py
examples: (holds on base) Close pressed → the top screen is the main screen (B line 50)
examples: (R-DLG.2/1 reference, holds on base) Close pressed → the widget focused before `t` has the focus again, in the same window (R: `dismiss(None)` with no callback; the main screen keeps its `focused`)
examples: (holds on base) Generate with `64` in `#report_context_bytes` → `GenerateRequested` posted to the app, then the dialog closes

WindowHelpScreen.action_close_window_help
req: R-DLG.2
in:
out: None
func: unchanged. The help window's own Escape (`window_help.py:688`, `:745-747`): logs `WindowHelpScreen dismissed by escape.` and dismisses the help window only.
module: s19_app/tui/window_help.py
modify: [Data: App.screen_stack] (replace)
examples: (R-DLG.2/12, holds on base) `question_mark` on `#report_list` → the stack ends `ReportViewerScreen`, `WindowHelpScreen`; `escape` → the top screen is `ReportViewerScreen` (B lines 48-49)

FlowBlockEditScreen.action_cancel
req: R-DLG.15
in:
out: None
func: unchanged (E3 U-4; test only). The Edit block dialog's Escape: a plain `Binding("escape", "cancel", "Cancel", show=False)` (`screens.py:1924`, not priority) runs `action_cancel` → `dismiss(None)` (`:2136-2137`); the app's callback leaves the chain unchanged on `None` (`app.py:4103-4106`). Its gating dropdown `#flow_edit_gating` (`:1977-1987`, a CHECK block) is the app's other dialog dropdown; while its list is open the list's own Escape runs first (`[Outside: dropdown list]`).
module: s19_app/tui/screens.py
modify: [Data: App.screen_stack] (replace)
examples: (R-DLG.15/2, holds on base) a CHECK block with gating `advisory` in Edit block; `#flow_edit_gating` focused, `enter`, `down`, `escape` → the list closed; `FlowBlockEditScreen` on top; the gating `advisory`
examples: (R-DLG.15/2) a second `escape` → Edit block closed; block 1 of the chain keeps gating `advisory`
examples: (R-DLG.15/2 neg) mutant: the open list's Escape applies the highlighted option → the gating `block-own-op` → RED

S19TuiApp.action_view_reports
req: R-DLG.2
in:
out: None
func: unchanged. Key `t`: with a project open, pushes `ReportViewerScreen(<project name>, <reports newest first>, …)` (`app.py:6277-6343`); without one, the status `Reports: no active project - load a project first.`
module: s19_app/tui/app.py
modify: [Data: App.screen_stack] (append)
examples: (R-DLG.2/1 precondition, holds on base) Reports project, `t` → `ReportViewerScreen` on top, the focus on `#report_list` (B line 32)
examples: (R-DLG.2/11 precondition, holds on base) Empty Reports project, `t` → the empty text, the focus on `#window_help_reports` (B line 53)

S19TuiApp.on_key
req: R-DLG.2, R-DLG.15
in: events.Key event
out: None
func: unchanged. Its Escape branch takes the focus out of one of the six find and go-to boxes only (`_FIND_GOTO_INPUT_IDS`, `app.py:10736-10741`); none of them is in a dialog, so it never acts on the Reports dialog's Escape and never stops it.
module: s19_app/tui/app.py
examples: (R-DLG.2/5) the focus on `#report_filter_path` (not a find or go-to box), `escape` → the dialog's binding runs → closed
examples: (R-DLG.15/1, holds on base) the filter dropdown open and its highlight moved to `f1.json` with `down` → the toolkit's dropdown list takes the Escape first (`[Outside: dropdown list]`); the dialog stays; the dropdown blank; no `Report filter:` status; after `escape`, `t` the dropdown blank
examples: (R-DLG.15/1 neg) mutant: the open list's Escape applies the highlighted option → the dropdown reads `f1.json` → RED

S19TuiApp.action_view_main
req: R-SHELL-KEYS.3
in:
out: None
func: removed (D-2 A). was: "Legacy alias: activate the Workspace rail screen (superseded by key ``1``)", `action_show_screen("workspace")`; no binding, palette entry or call reaches it. / now: absent; key `1` runs `show_screen('workspace')`.
module: s19_app/tui/app.py
examples: (R-SHELL-KEYS.3/1) census → no `action_view_main`; 0 actions without a reach; at least `80` actions
examples: (R-SHELL-KEYS.3/1 neg, the base) census → 3 actions without a reach: `S19TuiApp.action_view_main`, `S19TuiApp.action_view_alt`, `S19TuiApp.action_view_mac` (R, E3A-01; the loose E1 census, C lines 57-66, gave 2)
examples: (AT-I12-2) `1` → the shown window `workspace` (B line 15)

S19TuiApp.action_view_alt
req: R-SHELL-KEYS.3
in:
out: None
func: removed (D-2 A). was: the alias of key `2`, `action_show_screen("a2l")`; its one call is in `_jump_to_validation_issue_object` (`app.py:16840`), which no reached function calls, so it has no reach (I-5). / now: absent with its caller; key `2` runs `show_screen('a2l')`.
module: s19_app/tui/app.py
examples: (R-SHELL-KEYS.3/1) census → no `action_view_alt`
examples: (the base, E3A-01) its one call `app.py:16840` lies in `S19TuiApp._jump_to_validation_issue_object`, whose one caller `_jump_to_validation_issue` has none → no reach (R); the loose E1 census counted that call (C line 58)
examples: (R-SHELL-KEYS.3/1 neg) mutant: `action_view_alt` restored with `_jump_to_validation_issue` and `_jump_to_validation_issue_object` → the census names `S19TuiApp.action_view_alt` → RED
examples: (AT-I12-2) `2` → the shown window `a2l` (B line 13)

S19TuiApp.action_view_mac
req: R-SHELL-KEYS.3
in:
out: None
func: removed (D-2 A). was: the alias of key `3`, `action_show_screen("mac")`, with no reach. / now: absent; key `3` runs `show_screen('mac')`.
module: s19_app/tui/app.py
examples: (R-SHELL-KEYS.3/1) census → no `action_view_mac`
examples: (R-SHELL-KEYS.3/1 neg) mutant: `action_view_mac` restored → the census names `S19TuiApp.action_view_mac` → RED
examples: (R-SHELL-KEYS.3/1 neg, E3A-01) mutant: an `action_copy` with no binding on a class that is not a toolkit widget → the census names it → RED (a message word `copy` is not a reach)
examples: (R-SHELL-KEYS.3/1, E3A-01) `CappedTextArea.action_copy`, `.action_paste`, `.action_cut` and the same three of `OsClipboardInput` → reached through the toolkit's `TextArea` / `Input` bindings
examples: (AT-I12-2) `3` → the shown window `mac` (B line 14)

S19TuiApp._jump_to_validation_issue
req: R-SHELL-KEYS.3
in: ListItem item
out: None
func: removed (D-2 A, D3-7). was: "Legacy ListView adapter": builds a `ValidationIssue` stub from `item.data` and calls `_jump_to_validation_issue_object`; no product caller since batch 29. / now: absent with `tests/test_tui_app.py::test_jump_to_validation_issue_prefers_address`.
module: s19_app/tui/app.py
examples: (holds on base, the defect) census → product call sites `0` (C line 69)
examples: (AT-I12-2) `enter` on an issue row → `S19TuiApp.on_issue_row_selected` runs (unchanged); the Issues window stays shown

S19TuiApp._jump_to_validation_issue_object
req: R-SHELL-KEYS.3
in: ValidationIssue issue
out: None
func: removed (D-2 A, D3-7; I-6). was: refresh the issues peek, then with an address the three hex views and the status `Issue at 0x<8 hex>: <code>`, else the A2L tag of the issue's symbol, `action_view_alt()` and `Issue symbol focused: <symbol>`; its one caller is `_jump_to_validation_issue`. / now: absent. Inc 10a's slice #11 is withdrawn (I-6, `d68cb9f`).
module: s19_app/tui/app.py
examples: (holds on base, the defect) census → product call sites `1`, from `S19TuiApp._jump_to_validation_issue` (`app.py:16752`, C line 68)
examples: (R-SHELL-KEYS.3/1) census → no `_jump_to_validation_issue_object`; `action_view_alt` has no reach left, so it goes too

S19TuiApp._format_validation_issue_line
req: R-SHELL-KEYS.3
in: ValidationIssue issue
out: str line
func: removed (D-2 A, D3-7). was: `[<SEVERITY>] <code> | <artifact> | sym=<symbol or -> addr=<0x8 hex or -> line=<n or -> | <message>`; no product caller. / now: absent; `test_validation_issue_filtering_and_format` keeps its filter assertions and drops the three that read it.
module: s19_app/tui/app.py
examples: (holds on base, the defect) census → product call sites `0` (C line 70)
examples: (test edit) `_filtered_validation_issues()` with mode `error` → 1 issue, code `CROSS_X` (unchanged assertions)

S19TuiApp._update_issues_hex_pane
req: R-SHELL-KEYS.3
in: int? address
out: None
func: changed (docstring and comment only). was: "Used by: ``_jump_to_validation_issue_object``"; the comment "a headless unit-test call to the jump path". / now: "Used by: ``on_issue_row_selected``"; the comment "a call with no mounted screen". Behaviour unchanged (R-ISSUES-HEXPANE-001.1, .2).
module: s19_app/tui/app.py
examples: (AT-I12-2, holds on base) an issue whose address is in the image selected → `#issues_hex_pane` paints the hex window around that address
examples: (R-ISSUES-HEXPANE-001.2, holds on base) an issue with no address → `(issue has no address — nothing to show)`

S19TuiApp.on_issue_row_selected
req: R-SHELL-KEYS.3
in: IssueRow.Selected event
out: None
func: unchanged. The one route of an Issues row selection (`app.py:17154-17175`): `_update_issues_hex_pane(event.address)`; it switches no window.
module: s19_app/tui/app.py
examples: (AT-I12-2, holds on base) the release case 08 image with `firmware_issues.a2l` (`tools/synth/make_release_case.py`), Issues window (key `5`), `enter` on the first issue row with an address in the image → the Issues window is still shown; the peek paints that address

S19TuiApp.action_show_screen
req: R-SHELL-KEYS.3
in: str screen_key
out: None
func: unchanged here (Inc 10a's slice #15 changes its focus landing). Shows the window of `screen_key` and hides the others; keys `1`, `2`, `3` bind `show_screen('workspace')`, `('a2l')`, `('mac')` (`app.py:2721-2723`).
module: s19_app/tui/app.py
examples: (AT-I12-2, holds on base) `2`, `3`, `1` → `_active_screen_key` `a2l`, `mac`, `workspace` (B lines 13-15)
examples: (test edit) `tests/test_tui_goto_marker.py::test_goto_focus_not_cleared_on_tab_switch` with `action_show_screen("a2l")`, `("mac")`, `("workspace")` in place of the aliases → `_goto_focus_address` still `0x1040`

CheckEditorPanel.compose
req: R-CHKED-058
in:
out: ComposeResult widgets
func: changed (D-3 A). was: the second action row `#check_actions_row2` holds `#check_fields_count` and the button `Addendum preview` (`#check_preview_toggle_button`) with `display = False` (`:7827-7834`); the docstring says it "stays mounted and hidden". / now: the row holds `#check_fields_count` alone; the docstring sentence goes; every other widget and the layout are unchanged.
module: s19_app/tui/screens_directionb.py
examples: (R-CHKED-058/1) walk [opened with the demo A2L; Fields; JSON; Addendum] → 0 ids never shown; `47` ids in the population (the union of the ids mounted over the four states, E3A-03)
examples: (R-CHKED-058/1 neg, the base) the same walk → never shown: `check_preview_toggle_button` (B line 19)
examples: (test edit TC-B97-08) every id of `CE_IDS_9C7BEAF` (now `35`) is mounted

CheckEditorPanel.on_button_pressed
req: R-CHKED-058
in: Button.Pressed event
out: None
func: changed (D-3 A). was: a branch `check_preview_toggle_button` → `_show_tab("check_tab_addendum")` (`:7940-7943`), which no key or click can reach. / now: the branch goes; the tab chips keep `_show_tab` (`:7920-7923`).
module: s19_app/tui/screens_directionb.py
examples: (AT-I12-3) the focus on `#check_tab_addendum`, `enter` → `#check_addendum_preview` shown, its text starting `## Checks`

CheckEditorPanel._show_tab
req: R-CHKED-058
in: str chip_id
out: None
func: unchanged. Switches the card to the chip's pane and marks that chip selected (`:7862-7868`); the Addendum chip carries the removed button's function.
module: s19_app/tui/screens_directionb.py
examples: (R-CHKED-058/1, holds on base) `check_tab_addendum` → `#check_addendum_preview` shown (B line 20)

## Entities

[Data: ReportViewerScreen.BINDINGS]
desc: `screens.py:3164-3171`. was: `[Binding("question_mark", "show_window_usage_help", "Window help", show=False)]`. now: the same plus `Binding("escape", "close_reports", "Close", show=False)`, not `priority` (I-1). A priority binding would run before the open dropdown list's own Escape and close the dialog under it (the negative control of R-DLG.15).

[Data: VARIANT_HELP_TEXT]
desc: `screens.py:1070-1088`, the body text of `VariantHelpScreen`; removed with it (D-1 A).

[Data: App.screen_stack]
desc: the toolkit's stack of screens; "closed" means no `ReportViewerScreen` on it.

[Data: S19TuiApp.BINDINGS]
desc: `app.py:2689-2760`, unchanged; keys `1`, `2`, `3` → `show_screen('workspace')`, `('a2l')`, `('mac')`; `t` → `view_reports`. The palette is built from it and `EXTRA_PALETTE_ENTRIES` (`app.py:9921-9967`); none of the removed aliases is in either.

[I/O: docs/user-guide/ch16-reports.md, ch18-flow-execution.md]
desc: changed (cited R-DOC-GUIDE.1; E3A-04, U-5; written by G1 on the tree after Inc 9). ch16 `:60`: the row `Open reports/, ?, Close · chips, button · 16.1` becomes two rows, `Open reports/, ?` with How `chips` and `Close` with How ``button / `esc` ``, both Capture 16.1; `:26` unchanged. ch18 `:172-173`: "Close it with **Close** — `esc` does not close this viewer (finding F-51)." becomes "Close it with **Close** or `esc`." Each passage is one `_GUIDE_PASSAGES` entry, appended last. Examples (entities take no `examples:` field): (R-DOC-GUIDE.1/13) `ch16-reports.md` contains ``button / `esc` `` and not ``Open reports/, `?`, Close``; (R-DOC-GUIDE.1/14) `ch18-flow-execution.md` contains ``**Close** or `esc`.`` and not ``esc` does not close this viewer``.

[I/O: docs/user-guide/DOSSIER.md §5]
desc: changed (cited R-DOC-GUIDE.2; E3A-04 + U-1). The Kind cell of rows F-33 (`:742`), F-34 (`:743`), F-35 (`:744`) and F-51 (`:760`) gains ` · fixed in 1.0.0`; the Finding and Evidence cells stay. `_FIXED` (`tests/test_b101_help_legend_docs.py`) gains the four by named supersession, 13 → 17 on the tree after Inc 9. F-35 is marked only when Inc 12b is on main (Inc 12 merges second); otherwise Inc 12 marks three (`_FIXED` 16) and 12b marks F-35. Examples (test edits): the F-51 row's Kind reads `usability, live · fixed in 1.0.0` and the F-35 row's `dead widget, code · fixed in 1.0.0`; `test_r_doc_guide_2_1_fixed_rows_marked` asserts `len(_FIXED) == 17`; `test_r_doc_guide_2_2_no_other_row_marked` keeps the marked set equal to `_FIXED`.

[Outside: escape]
desc: the Escape key, pressed while a dialog is the top screen.

[Outside: dropdown list]
desc: the toolkit's open dropdown list (`SelectOverlay`, textual 8.2.8 `widgets/_select.py:51`: `escape` → dismiss the list, without applying the highlighted option, `:161`); it holds the focus while open, so its binding runs before the dialog's. The Reports filter dropdown and the Edit block gating dropdown both open one.

[Outside: rail keys]
desc: the keys `1`, `2`, `3` (and `5` for Issues) that AT-I12-2 presses.

[Interface: Reports dialog]
desc: `ReportViewerScreen`: the report list, the report view, the declared-regions box, the filter dropdown and path box, the context-bytes box, Generate, Close, `📂 Open reports/`, `?`.
offers: (R-DLG.2/8) "escape" → ReportViewerScreen.action_close_reports
offers: (R-DLG.2/8) "Close" → ReportViewerScreen.on_button_pressed

## Edges

[Outside: escape] ──▶ ReportViewerScreen.action_close_reports
when: the Reports dialog is the top screen and none of its dropdown lists is open (R-DLG.2)
[Outside: escape] ──▶ [Outside: dropdown list]
when: the Reports filter dropdown's list or the Edit block gating dropdown's list is open (R-DLG.15); the dialog's binding does not run
[Outside: escape] ──▶ FlowBlockEditScreen.action_cancel
when: Edit block is the top screen and none of its dropdown lists is open (R-DLG.15/2, the second Escape)
[Data: ReportViewerScreen.BINDINGS] ──▶ ReportViewerScreen.action_close_reports
ReportViewerScreen.action_close_reports ──▶ [Data: App.screen_stack]
FlowBlockEditScreen.action_cancel ──▶ [Data: App.screen_stack]
ReportViewerScreen.on_button_pressed ──▶ [Data: App.screen_stack]
when: Close or Generate
S19TuiApp.action_view_reports ──▶ [Data: App.screen_stack]
when: `t` with a project open
WindowHelpScreen.action_close_window_help ──▶ [Data: App.screen_stack]
when: Escape in the help window opened from the Reports dialog (R-DLG.2/12)
[Outside: rail keys] ──▶ S19TuiApp.action_show_screen
[Data: S19TuiApp.BINDINGS] ──▶ S19TuiApp.action_show_screen
S19TuiApp.on_issue_row_selected ──▶ S19TuiApp._update_issues_hex_pane
CheckEditorPanel.on_button_pressed ──▶ CheckEditorPanel._show_tab
when: a tab chip, the Addendum chip included

## Findings

> E2-1 (for E3, D-5; resolved at E3: D-5 B applied). Size after the split: 5 active rows and 19 nodes here (3 changed, 1 new, 7 removed, 8 context — `FlowBlockEditScreen.action_cancel` added at E3 for R-DLG.15/2), 10 entities, 13 edges; 3 source files. Inc 12b holds 2 rows and 17 nodes (`../../inc-12b/codewire/graph-inc12b.md`). Before the split: 7 rows, 35 nodes, 11 entities, 18 edges.
> E2-2 (for E3, D-2; I-6; closed at E3). Inc 10a's cases R-TUI-018.1/5 ("Issues, key `5`, Enter → the main, A2L and MAC views show the issue's address second") and R-TUI-040.12/2 rested on `_jump_to_validation_issue_object`, which no product route runs: Enter on an issue row runs `on_issue_row_selected`, which repaints the Issues peek only. The orchestrator ruled 10a under D-2 A, and 10a's addendum is committed (`d68cb9f`, E3A-07).
> E2-3 (for E3, D-7, D-8). The Escape binding is a plain screen binding. The pilot found no focusable place of the dialog that takes Escape (`Input`, `ListView` bind none; the `TextArea` only with `tab_behavior="indent"`, and this one is `focus`), so a plain binding closes from all 10 places; the open dropdown list's own Escape runs first, which R-DLG.15 keeps, and it applies no highlighted option (`_select.py:161`). A priority binding would close the dialog under an open list; R-DLG.15's negative control is that mutant. Edit block shares the mechanism (R-DLG.15/2).
> E2-4 (for E3, D-10; corrected at E3, E3A-01). The action census counts only operator paths: exact action strings, toolkit bindings declared on a toolkit base class of the action's class, and calls or references inside reached functions (I-5). Message words never count, so `CappedTextArea.action_copy` / `.action_paste` and `OsClipboardInput.action_copy` / `.action_paste` are reached through the toolkit's bindings and not through the words "paste" or "copy" in messages (`app.py:8084`, `flow_screens.py:2263`, `app.py:319`); a call from dead code is not a reach, so `action_view_alt` is without one on the base. Base 3 of 83 (R), after 0 of 80; re-measured on the LAN host at E4.
> E2-5. Coverage of the requirement → node map: R-DLG.14: `VariantHelpScreen`; R-SHELL-KEYS.3: `S19TuiApp.action_view_main`, `.action_view_alt`, `.action_view_mac`, `._jump_to_validation_issue`, `._jump_to_validation_issue_object`, `._format_validation_issue_line`, `._update_issues_hex_pane`, `.on_issue_row_selected`, `.action_show_screen`; R-CHKED-058: `CheckEditorPanel.compose`, `.on_button_pressed`, `._show_tab`; R-DLG.2: `ReportViewerScreen.action_close_reports`, `.on_button_pressed`, `WindowHelpScreen.action_close_window_help`, `S19TuiApp.action_view_reports`, `S19TuiApp.on_key`; R-DLG.15: `S19TuiApp.on_key`, `FlowBlockEditScreen.action_cancel`, `[Outside: dropdown list]`, `[Data: ReportViewerScreen.BINDINGS]`; the cited R-DOC-GUIDE.1 and R-DOC-GUIDE.2: the two `[I/O: …]` entities, whose examples sit in their `desc:` (Code-Wire v3.1 entities take no `examples:` field). Every active row and every case of `../02-test-cases.md` (R-DLG.14/1, R-SHELL-KEYS.3/1, R-CHKED-058/1, R-DLG.2/1 … /12, R-DLG.15/1, /2, R-DOC-GUIDE.1/13, /14, AT-I12-1 … -3) has at least one concrete example.
