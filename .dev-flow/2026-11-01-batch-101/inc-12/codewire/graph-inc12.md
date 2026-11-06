# Code-Wire graph — Inc 12 (every dialog, action and widget reachable; Escape closes the Reports dialog), batch-101

Stage E2 of the design-first flow (`dev-flow-v3-beta`). Graph only: no stub, mark or declaration in any tree. Base `2d1e2b1` (product `e07fb00`). Requirements `../01-requirements.md`, slice `../E1-slice.md`, rulings `../E1-rulings.md`, cases `../02-test-cases.md`. Notation: Code-Wire v3.1 (the Code-Wire repository's `docs/Notation-Grammar.md`), as in Inc 9's `inc-9/codewire/graph-inc9.md` (branch `b101-inc9`, not yet on main) and `../../inc-8/codewire/graph-inc8.md`.

How to read it:
- One file holds the baseline and the prototype. Every node's `func:` starts with **unchanged**, **changed** (then "was: … / now: …", the baseline first), **new** or **removed** (then "was: … / now: absent"). Context nodes (unchanged) are here because a changed node calls them, a removed node's function now lives in them, or their examples are the oracle of a row.
- Example sources are the case ids of `02-test-cases.md`; `B` = the E1 pilot (`../evidence-e1/i12e1-pilot-transcript.txt`), `C` = the E1 census (`../evidence-e1/i12e1-census-transcript.txt`). Every example states the Inc 12 target unless it says "holds on base" or "the base".
- "Closed" = no `ReportViewerScreen` on the screen stack and the app's main screen on top. **Reports project** = `proj1` with two files in `reports/` and `filters/f1.json` (the cases' fixture).
- The graph follows the E1 recommendations (`../E1-rulings.md` §3): D-1 A, D-2 A, D-3 A, D-4 A, D-5 A, D-6 A, D-7 A, D-8 A, D-9 A, D-10 A. Under D-2 B the three `_jump_to_validation_issue*` / `_format_validation_issue_line` nodes become one changed node (the call at `app.py:16840` re-pointed); under D-5 B group G4 moves to Inc 12b as it stands.
- The 14 module names of the painter family that only other family members read (`_Grid`, six helper functions and seven constants) are one entity, `[Code: canvas grid helpers]`: they go together, their only example is the census, and no test names them (C lines 177-186). The four `FlowBuilderPanel` methods and `_flow_block_label`, which tests or callers name, are nodes.

### Groups for E4 (file ownership) and interfaces — pinned here, changed only by an orchestrator ruling

| Group | Files | Owns nodes |
|---|---|---|
| G1 dialogs | `s19_app/tui/screens.py`; tests `tests/test_b101_reach_and_reports_escape.py` (tester G-T1, also AT-I12-1, AT-I12-2) | `VariantHelpScreen`, `ReportViewerScreen.action_close_reports`, `[Data: ReportViewerScreen.BINDINGS]`, `[Data: VARIANT_HELP_TEXT]` |
| G2 app | `s19_app/tui/app.py`; tests G-T1 (the same file) | `S19TuiApp.action_view_main`, `.action_view_alt`, `.action_view_mac`, `._jump_to_validation_issue`, `._jump_to_validation_issue_object`, `._format_validation_issue_line`, `._update_issues_hex_pane` |
| G3 Check Editor | `s19_app/tui/screens_directionb.py`; tests `tests/test_b101_shown_widgets.py` (tester G-T2, also AT-I12-3) | `CheckEditorPanel.compose`, `CheckEditorPanel.on_button_pressed` |
| G4 Flow | `s19_app/tui/flow_screens.py`; tests G-T2 (the walks) and G-T3 (the 36 re-pointed nodes, `../E1-slice.md` §5) | `FlowBuilderPanel.__init__`, `.set_session_dir`, `.compose`, `._refresh_blocks`, `.on_button_pressed`, `.on_mount`, `.on_select_changed`, `._canvas_text`, `._layout`, `._block_rows`, `._blocks_text`, `_flow_block_label`, `FlowExecutionPanel.compose`, `FlowExecutionPanel.on_mount`, `[Code: canvas grid helpers]`, `[Data: FlowBuilderPanel._kind]`, `[Doc: flow_screens docstrings]` |

| Interface | Pinned form | Producer → consumers |
|---|---|---|
| I-1 Reports Escape | `ReportViewerScreen.BINDINGS` = `[Binding("question_mark", "show_window_usage_help", "Window help", show=False), Binding("escape", "close_reports", "Close", show=False)]` (not `priority`); `ReportViewerScreen.action_close_reports(self) -> None` logs `ReportViewerScreen dismissed by Esc.` and calls `self.dismiss(None)`; it posts no message | G1 → G-T1 (R-DLG.2, R-DLG.15), TC-706's binding census (`tests/test_window_usage_help.py:625-627`) |
| I-2 the Flow Builder kind | `FlowBuilderPanel._kind: str`, `BLOCK_SOURCE` at construction, written only by the kind chip branch of `on_button_pressed`, read by `+ Add` and by `on_mount`'s first `_sync_kind_dependent_visibility`; no widget holds it. Tests choose a kind by pressing `#flow_palette_<kind>` and read its painted effect (`.flow-kind-tag`, the chip's `chip-selected`, the inputs shown), never `_kind` | G4 → G-T2, G-T3 |
| I-3 the removed names | after Inc 12 no source or test names `VariantHelpScreen`, `VARIANT_HELP_TEXT`, `action_view_main`, `action_view_alt`, `action_view_mac`, `_jump_to_validation_issue`, `_jump_to_validation_issue_object`, `_format_validation_issue_line`, `#check_preview_toggle_button`, `#flow_help`, `#flow_canvas`, `#flow_blocks`, `#flow_kind`, `#flow_ext_session`, `#fx_help`, or a member of the painter family (except `window_help.py`'s three docstrings, BL-I12-1) | G1–G4 → G-T1, G-T2, G-T3; the testers of Inc 9, 10a, 10b (`../E1-rulings.md` §5) |
| I-4 the visible oracles | the chain: `#flow_pipeline` (cards), its frame title `chain · <n> block(s)`; the session: `#flow_name_strip`; the kind: `.flow-kind-tag`, `KindChip` `chip-selected`; the addendum: `#check_tab_addendum` → `#check_addendum_preview`; windows: keys `1`, `2`, `3` or `action_show_screen` | unchanged producers → G-T2, G-T3 |
| I-5 the census definitions | dialog = a `ModalScreen` subclass; opener = a construction of it outside its own body (a subclass's opener counts for its base); action = an `action_<name>` method of any class; reach = a string literal that is not a docstring naming `<name>`, `<name>(…)`, `app.<name>` or `screen.<name>`, a `BINDINGS` action of a toolkit base class of the method's class, or a call `.action_<name>(` from another function | G-T1 (R-DLG.14/1, R-SHELL-KEYS.3/1) |
| I-6 Inc 10a | `S19TuiApp._jump_to_validation_issue_object` is removed; 10a's slice #11 and its cases R-TUI-018.1/5 and R-TUI-040.12/2 need the orchestrator's ruling before 10a's E4 (`../E1-rulings.md` D-2) | the orchestrator → Inc 10a |

Order inside E4: G1 … G4 in parallel (disjoint files; no implementer consumes another's interface); G-T1, G-T2, G-T3 in parallel. Integration after Inc 9, 10a and 10b merge: the census of `../E1-slice.md` §5 is re-run on the merged tree before the GREEN run.

## Nodes

VariantHelpScreen
req: R-DLG.14
in:
out: None
func: removed (D-1 A). was: a `ModalScreen[None]` with the title "About the variant selector", `#variant_help_body` (the text `[Data: VARIANT_HELP_TEXT]`) and Close, dismissed by Close; no part of the system constructs it (its opener, the Patch Editor variant selector, left in batch 94). / now: absent, with its constant and comment (`screens.py:1070-1153`).
module: s19_app/tui/screens.py
examples: (R-DLG.14/1) census of the tree under test → `VariantHelpScreen` is not a dialog of it; 0 dialogs without an opener; at least `21` dialogs
examples: (R-DLG.14/1 neg, the base) census → `22` dialogs, 1 without an opener: `VariantHelpScreen` (C)
examples: (holds after) `test_at067a_variant_info_button_opens_help_modal` and `test_tc336_tc337_help_message_pushes_modal_with_content` still assert that the opener and its message are gone

ReportViewerScreen.action_close_reports
req: R-DLG.2
in:
out: None
func: new (D-7 A; I-1). Run by Escape through `[Data: ReportViewerScreen.BINDINGS]`; logs `ReportViewerScreen dismissed by Esc.` and calls `dismiss(None)` — what Close does (`ReportViewerScreen.on_button_pressed`): it posts no message, so no report is generated and no typed filter path is applied (R-DLG.9).
module: s19_app/tui/screens.py
modify: [Data: App.screen_stack] (replace)
examples: (R-DLG.2/1) Reports project, the focus on `#report_list`, `escape` → closed; `reports/` holds `2` files; the status line as before (base: open, B)
examples: (R-DLG.2/3) `x` typed in `#report_declared_regions`, `escape`, `t` → closed, then the box text `""`
examples: (R-DLG.2/5) `abc` typed in `#report_filter_path`, `escape`, `t` → the path box `""` and the dropdown blank
examples: (R-DLG.2/7) the focus on `#report_generate`, `escape` → closed; `2` files
examples: (R-DLG.2/7 neg) mutant: the action posts `GenerateRequested` before the dismiss → `3` files → RED
examples: (R-DLG.2/9) the focus on `#open_folder_reports`, `escape` → closed; the folder spy counts `0` calls
examples: (R-DLG.2/11) Empty Reports project, `t` (the focus on `#window_help_reports`), `escape` → closed (base: open, B)
examples: (R-DLG.2/2, /4, /6, /8, /10) the focus on `#report_markdown_scroll`, `#report_filter_select` (list closed), `#report_context_bytes` (`9` typed), `#report_close`, `#window_help_reports`, `escape` → closed each time
examples: (R-DLG.2/1 neg, the base) no Escape binding → after `escape` the top screen is still `ReportViewerScreen` from each of the 10 places (B lines 35-44)
examples: (AT-I12-1) `t`, `enter`, `escape` → closed; `t`, tab to `#report_filter_path`, `abc`, `escape` → closed; `t` → the path box `""`

ReportViewerScreen.on_button_pressed
req: R-DLG.2
in: Button.Pressed event
out: None
func: unchanged. Close (`#report_close`) logs `ReportViewerScreen dismissed by close.` and calls `dismiss(None)` (`:3479-3482`); Generate parses `#report_context_bytes`, posts `GenerateRequested` to the app and dismisses (`:3483-3506`). The oracle of "what Close does".
module: s19_app/tui/screens.py
examples: (holds on base) Close pressed → the top screen is the main screen (B line 50)
examples: (holds on base) Generate with `64` in `#report_context_bytes` → `GenerateRequested` posted to the app, then the dialog closes

WindowHelpScreen.action_close_window_help
req: R-DLG.2
in:
out: None
func: unchanged. The help window's own Escape (`window_help.py:688`, `:745-747`): logs `WindowHelpScreen dismissed by escape.` and dismisses the help window only.
module: s19_app/tui/window_help.py
modify: [Data: App.screen_stack] (replace)
examples: (R-DLG.2/12, holds on base) `question_mark` on `#report_list` → the stack ends `ReportViewerScreen`, `WindowHelpScreen`; `escape` → the top screen is `ReportViewerScreen` (B lines 48-49)

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
examples: (R-DLG.15/1, holds on base) the filter dropdown open → the toolkit's dropdown list takes the Escape first (`[Outside: dropdown list]`); the dialog stays

S19TuiApp.action_view_main
req: R-SHELL-KEYS.3
in:
out: None
func: removed (D-2 A). was: "Legacy alias: activate the Workspace rail screen (superseded by key ``1``)", `action_show_screen("workspace")`; no binding, palette entry or call reaches it. / now: absent; key `1` runs `show_screen('workspace')`.
module: s19_app/tui/app.py
examples: (R-SHELL-KEYS.3/1) census → no `action_view_main`; 0 actions without a reach; at least `80` actions
examples: (R-SHELL-KEYS.3/1 neg, the base) census → 2 actions without a reach: `S19TuiApp.action_view_main`, `S19TuiApp.action_view_mac` (C lines 57-66)
examples: (AT-I12-2) `1` → the shown window `workspace` (B line 15)

S19TuiApp.action_view_alt
req: R-SHELL-KEYS.3
in:
out: None
func: removed (D-2 A). was: the alias of key `2`, `action_show_screen("a2l")`; reached only by the call in `_jump_to_validation_issue_object` (`app.py:16840`), which no product route runs. / now: absent with its caller; key `2` runs `show_screen('a2l')`.
module: s19_app/tui/app.py
examples: (R-SHELL-KEYS.3/1) census → no `action_view_alt`
examples: (holds on base, the defect) census → its one reach is `app.py:16840` in `S19TuiApp._jump_to_validation_issue_object` (C line 58)
examples: (AT-I12-2) `2` → the shown window `a2l` (B line 13)

S19TuiApp.action_view_mac
req: R-SHELL-KEYS.3
in:
out: None
func: removed (D-2 A). was: the alias of key `3`, `action_show_screen("mac")`, with no reach. / now: absent; key `3` runs `show_screen('mac')`.
module: s19_app/tui/app.py
examples: (R-SHELL-KEYS.3/1) census → no `action_view_mac`
examples: (R-SHELL-KEYS.3/1 neg) mutant: `action_view_mac` restored → the census names `S19TuiApp.action_view_mac` → RED
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
func: removed (D-2 A, D3-7; I-6). was: refresh the issues peek, then with an address the three hex views and the status `Issue at 0x<8 hex>: <code>`, else the A2L tag of the issue's symbol, `action_view_alt()` and `Issue symbol focused: <symbol>`; its one caller is `_jump_to_validation_issue`. / now: absent. Inc 10a's slice #11 changes it (I-6).
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
examples: (AT-I12-2, holds on base) Issues window (key `5`), `enter` on the first issue row with an address in the image → the Issues window is still shown; the peek paints that address

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
examples: (R-CHKED-058/1) walk [opened with the demo A2L; Fields; JSON; Addendum] → 0 widgets never shown; `47` widgets with an id
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

FlowBuilderPanel.__init__
req: R-TUI-059.25
in:
out: None
func: changed (D-4 A; I-2). was: no kind attribute (the hidden select `#flow_kind` holds the kind, value `source` at compose). / now: `self._kind: str = BLOCK_SOURCE` beside `_blocks`, `_flow_name`, … , commented as the kind the chips chose.
module: s19_app/tui/flow_screens.py
examples: (R-TUI-059.25/1) the Flow Builder opened → the kind tag `◉ LOAD`, the LOAD chip marked `chip-selected`, `#flow_ref` shown with the label `image file`

FlowBuilderPanel.set_session_dir
req: R-TUI-059.25
in: str path
out: None
func: changed (D-5 A). was: stores `_session_dir`, then when mounted updates the hidden `#flow_ext_session` (`session: <path> — on confirm, the output file is copied here`, or `session: (no active project)`) and the ribbon (`:1587-1597`). / now: stores `_session_dir` and, when mounted, refreshes the ribbon only (R-FB-RIB.2).
module: s19_app/tui/flow_screens.py
examples: (AT-I12-3, holds on base) a project open → `#flow_name_strip` shows `session` and the tail of the project folder
examples: (test edit TC-B100-31) the session folder after `q` is read from `#flow_name_strip`, not from `#flow_ext_session`

FlowBuilderPanel.compose
req: R-TUI-059.25
in:
out: ComposeResult widgets
func: changed (D-4 A, D-5 A). was: also yields the help label `#flow_help` (`:1607-1612`), `#flow_canvas` and `#flow_blocks` painted from `_canvas_text()` / `_blocks_text()` (`:1619-1620`), the select `#flow_kind` as the first child of `#flow_add_row` (`:1627`) and `#flow_ext_session` (`:1692-1693`). / now: none of the five; every other part in the order of CTX-BUILDER (R-TUI-059.21).
module: s19_app/tui/flow_screens.py
examples: (R-TUI-059.25/1) walk [opened; the 7 kind chips; Variables open; the Add notice; 3 LOAD blocks] → 0 widgets never shown; `48` widgets with an id
examples: (R-TUI-059.25/1 neg, the base) the same walk → never shown: `flow_blocks`, `flow_canvas`, `flow_ext_session`, `flow_help`, `flow_kind` (B line 25)

FlowBuilderPanel._refresh_blocks
req: R-TUI-059.25
in:
out: None
func: changed (D-5 A). was: repaints the hidden `#flow_blocks` and `#flow_canvas` (`:2109-2110`), then the pipeline, its frame title, the legend and the ribbon. / now: the pipeline (`pipeline_text`), its frame title, the legend and the ribbon only.
module: s19_app/tui/flow_screens.py
examples: (R-TUI-059.25/1) 3 × (`prg.s19`, `+ Add`) → the pipeline paints `3` LOAD cards; the frame title `chain · 3 blocks`
examples: (the base) the same Adds → the hidden canvas painted `3` times and the hidden list `3` times (B line 23)

FlowBuilderPanel.on_button_pressed
req: R-TUI-059.25
in: Button.Pressed event
out: None
func: changed (D-4 A; I-2). was: a kind chip sets the hidden select (`#flow_kind`, `:2506`), syncs the add form and clears the notice; `+ Add` reads the kind from the select (`:2515`). / now: a kind chip sets `self._kind`, then `_sync_kind_dependent_visibility(kind)` and the cleared notice as before; `+ Add` reads `self._kind`; the other branches are unchanged.
module: s19_app/tui/flow_screens.py
modify: [Data: FlowBuilderPanel._kind] (replace)
examples: (R-TUI-059.25/1) `#flow_palette_check` pressed → the kind tag `✓ CHECK`; `#flow_gating` shown; the CHECK chip marked (R-FB-ADD.1)
examples: (AT-I12-3) `space` on the `✓ CHECK` chip, `baseline.chk.json` typed, `enter` on `+ Add` → the pipeline paints `1` CHECK card (R-FB-ADD.3)
examples: (R-TUI-059.25/1) the LOAD chip, `#flow_ref` empty, `+ Add` → the notice `Add needs image file — nothing added` shown (R-FB-ADD.4, holds on base)
examples: (the base) each of the 7 chips pressed → the hidden select's value equals the chip's kind (B line 22)

FlowBuilderPanel.on_mount
req: R-TUI-059.25
in:
out: None
func: changed (D-4 A, D-5 A). was: hides `#flow_help`, `#flow_canvas`, `#flow_blocks`, `#flow_kind`, `#flow_ext_session` (`:2584-2589`), syncs the add form to the select's value, hides the funnel editor and list, and paints. / now: no hide loop; the first sync reads `self._kind`; the funnel editor and list still start hidden (Variables shows them); the rest unchanged.
module: s19_app/tui/flow_screens.py
examples: (R-TUI-059.25/1) opened → `#flow_funnel_editor` hidden; after `#flow_funnel_toggle` → shown (B: the walk displays it)

FlowBuilderPanel.on_select_changed
req: R-TUI-059.25
in: Select.Changed event
out: None
func: changed (D-4 A). was: `flow_kind` → `_sync_kind_dependent_visibility(event.value)`; `flow_ext_mode` → relabel the command box (`:2606-2616`). / now: the `flow_ext_mode` branch only (R-FB-ADD.14, .15).
module: s19_app/tui/flow_screens.py
examples: (holds on base) the EXT-STEP chip, mode set to Manual → the label `instruction`, the placeholder `what the human does`

FlowBuilderPanel._sync_kind_dependent_visibility
req: R-TUI-059.25
in: str kind
out: None
func: unchanged. Shows the chosen kind's inputs only, tags the add row with the kind's glyph and name, and marks its chip (`:2618-2652`): every visible effect of the kind.
module: s19_app/tui/flow_screens.py
examples: (R-TUI-059.25/1, holds on base) `a2b` → `#flow_ref_a`, `#flow_ref_b` and their Browse chips shown, `#flow_ref` hidden; the tag `⏚ A2B-DIFF`

FlowBuilderPanel._name_strip_text
req: R-TUI-059.25
in:
out: Text ribbon
func: unchanged. `ribbon_text(_flow_name, _dirty, kinds, _session_dir, width)` (`:1708-1723`): the ribbon carries the session that `#flow_ext_session` mirrored.
module: s19_app/tui/flow_screens.py
examples: (AT-I12-3, holds on base) a project open → the ribbon holds `session` and the project folder's tail

pipeline_text
req: R-TUI-059.25
in: Sequence[FlowBlock] blocks; int card_w; int spare = 0; Callable? resolver = None
out: Text pipeline
func: unchanged. The visible chain: one row of cards joined by cables (`:1083-1161`); the re-pointed tests read the chain here instead of `#flow_blocks` and `#flow_canvas` (I-4).
module: s19_app/tui/flow_screens.py
examples: (R-TUI-059.25/1, holds on base) 3 LOAD blocks of `prg.s19` → 3 cards headed `◉ LOAD`, joined by cables
examples: (R-FB-RIB.3, holds on base) a hostile ref added → the pipeline paints it as text, no injected style (as `tests/test_b97_flow_builder.py::test_at_b97_08_hostile_and_nul_refs_never_crash_or_inject` reads it): the surface the re-pointed markup-safety nodes move to

FlowBuilderPanel._canvas_text
req: R-TUI-059.25
in:
out: Text canvas
func: removed (D-5 A). was: the batch-94 framed grid with file chips, box blocks and cables (`:1955-2094`), painted into the hidden `#flow_canvas` at compose and on every `_refresh_blocks`. / now: absent with `[Code: canvas grid helpers]`.
module: s19_app/tui/flow_screens.py
examples: (R-TUI-059.25/1) census → no `_canvas_text` in `flow_screens.py`; no test names it (C line 178)
examples: (the base) one paint with 3 blocks: `0.33` ms on the LAN host (B line 24)

FlowBuilderPanel._layout
req: R-TUI-059.25
in:
out: tuple(list positions, dict chips, int height)
func: removed (D-5 A). was: the canvas layout (`:1912-1953`); its one caller is `_canvas_text`. / now: absent. (`FlowExecutionPanel._layout`, an attribute holding a `LaneLayout`, is another name and stays.)
module: s19_app/tui/flow_screens.py
examples: (R-TUI-059.25/1) census → the method is absent; `FlowExecutionPanel._layout` is untouched (C line 160, 176)

FlowBuilderPanel._block_rows
req: R-TUI-059.25
in: FlowBlock block; int index
out: list rows
func: removed (D-5 A). was: the IO rows of one canvas block (`:1857-1910`), read by `_layout` and `_canvas_text` only. / now: absent.
module: s19_app/tui/flow_screens.py
examples: (R-TUI-059.25/1) census → absent (C line 161)

FlowBuilderPanel._blocks_text
req: R-TUI-059.25
in:
out: Text listing
func: removed (D-5 A). was: the numbered list `<n>. <label>` (or `(no blocks yet)`) painted into the hidden `#flow_blocks` (`:2096-2104`). / now: absent; the 9 test nodes that read `#flow_blocks` read the pipeline (I-4).
module: s19_app/tui/flow_screens.py
examples: (the base) no block → `(no blocks yet)`; one LOAD `prg.s19` (S19) → `1. LOAD  prg.s19  (s19)`
examples: (test edit) `tests/test_flow_crc_ui.py::test_at128_crc_node_renders_and_shows_status` reads the CRC card of `#flow_pipeline` in place of `_blocks_text()`

_flow_block_label
req: R-TUI-059.25
in: FlowBlock block
out: str label
func: removed (D-5 A). was: the one-line label of the hidden list (`:373-398`; it still reads `REPORT  (generation deferred - FB-P1b)`, false since batch 60, S16 D16-6); its one caller is `_blocks_text`. / now: absent; its two direct tests are rewritten against the card text or removed (`../E1-slice.md` §5).
module: s19_app/tui/flow_screens.py
examples: (the base) `CheckBlock("c.json")` → a label starting `CHECK`; `SourceBlock("img.s19")` → starting `LOAD`
examples: (R-TUI-059.25/1) census → absent; no source names it

FlowExecutionPanel.compose
req: R-FX-SCR.4
in:
out: ComposeResult widgets
func: changed (D-5 A). was: also yields the help label `#fx_help` (`:3320-3326`) between the run row and the set row. / now: without it; the parts in the order of CTX-FXSCREEN (R-FX-SCR.2).
module: s19_app/tui/flow_screens.py
examples: (R-FX-SCR.4/1) walk [no lane; `flash_chain` imported; its Run waiting; the set saved as `s`] → 0 widgets never shown; `34` widgets with an id after the import
examples: (R-FX-SCR.4/1 neg, the base) the same walk → never shown: `fx_help` (B line 27)

FlowExecutionPanel.on_mount
req: R-FX-SCR.4
in:
out: None
func: changed (D-5 A). was: fills the set name, hides `#fx_help` and `#fx_required`, clears the notice and lays out (`:3348-3354`). / now: the same without the `#fx_help` line; `#fx_required` still starts hidden and is shown while a lane waits (`:4190`).
module: s19_app/tui/flow_screens.py
examples: (R-FX-SCR.4/1) the Run of `flash_chain` waiting → `#fx_required` shown (`log + output file: REQUIRED for flash_chain · press c to confirm`)

## Entities

[Data: ReportViewerScreen.BINDINGS]
desc: `screens.py:3164-3171`. was: `[Binding("question_mark", "show_window_usage_help", "Window help", show=False)]`. now: the same plus `Binding("escape", "close_reports", "Close", show=False)`, not `priority` (I-1). A priority binding would run before the open dropdown list's own Escape and close the dialog under it (the negative control of R-DLG.15).

[Data: VARIANT_HELP_TEXT]
desc: `screens.py:1070-1088`, the body text of `VariantHelpScreen`; removed with it (D-1 A).

[Data: App.screen_stack]
desc: the toolkit's stack of screens; "closed" means no `ReportViewerScreen` on it.

[Data: S19TuiApp.BINDINGS]
desc: `app.py:2689-2760`, unchanged; keys `1`, `2`, `3` → `show_screen('workspace')`, `('a2l')`, `('mac')`; `t` → `view_reports`. The palette is built from it and `EXTRA_PALETTE_ENTRIES` (`app.py:9921-9967`); none of the removed aliases is in either.

[Data: FlowBuilderPanel._kind]
in: str
desc: new (D-4 A; I-2): the block kind the chips chose, `BLOCK_SOURCE` at construction; replaces the hidden select `#flow_kind` as the holder.

[Code: canvas grid helpers]
desc: removed with `FlowBuilderPanel._canvas_text` (D-5 A): `_Grid` (`:585-634`), `_plc_block` (`:637-659`), `_chip` (`:662-668`), `_wire_bend` (`:671-684`), `_wire_drop` (`:687-713`), `_block_width` (`:559-563`), `_short_ext` (`:566-571`), `_CANVAS_COLS` (`:547`), `_BLOCK_W` (`:550`), `_EXT_BLOCK_W` (`:556`), `_S_WIRE` (`:576`), `_S_LABEL` (`:578`), `_S_VALUE` (`:579`), `_S_HEAD` (`:581`) and the comments that introduce them. Each is read only by members of the family (C lines 162-175); no other module and no test names one. Kept: `_S_RULE`, `_S_DIM`, `_S_OUT`, `_S_ERR`, `_join_lines`, `_binding_label` (read elsewhere).

[Doc: flow_screens docstrings]
desc: no behaviour. The module docstring's "fb_a doctrine" paragraph (`:12-20`: the framed canvas, its box blocks and cables, the ledger strip `#flow_blocks`) is rewritten to the shipped surface (the pipeline of cards and the kind chips with the add form); `KindChip` (`:1284-1286`) names the panel's kind, not `#flow_kind`; `FlowBuilderPanel` (`:1389-1390`) drops the sentence on the hidden canvas and list. Inc 9 rewrites the same module docstring's import sentences (`:5-10`, `:32-33`): adjacent hunks.

[Outside: escape]
desc: the Escape key, pressed while a dialog is the top screen.

[Outside: dropdown list]
desc: the toolkit's open dropdown list (`SelectOverlay`, textual 8.2.8 `widgets/_select.py:51`: `escape` → dismiss the list); it holds the focus while open, so its binding runs before the dialog's.

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
when: the filter dropdown's list is open (R-DLG.15); the dialog's binding does not run
[Data: ReportViewerScreen.BINDINGS] ──▶ ReportViewerScreen.action_close_reports
ReportViewerScreen.action_close_reports ──▶ [Data: App.screen_stack]
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
FlowBuilderPanel.on_button_pressed ──▶ [Data: FlowBuilderPanel._kind]
when: a kind chip `#flow_palette_<kind>`
[Data: FlowBuilderPanel._kind] ──▶ FlowBuilderPanel.on_button_pressed
when: `+ Add` builds the block of that kind
[Data: FlowBuilderPanel._kind] ──▶ FlowBuilderPanel.on_mount
FlowBuilderPanel.on_button_pressed ──▶ FlowBuilderPanel._sync_kind_dependent_visibility
FlowBuilderPanel.on_mount ──▶ FlowBuilderPanel._sync_kind_dependent_visibility
FlowBuilderPanel._refresh_blocks ──▶ pipeline_text
FlowBuilderPanel.set_session_dir ──▶ FlowBuilderPanel._name_strip_text

## Findings

> E2-1 (for E3, D-5). Size: 7 active rows and 35 nodes (12 changed, 1 new, 12 removed, 10 context); the 14 grid helpers are the one entity `[Code: canvas grid helpers]`, all removed together, and no test names one. With each of its 7 helper functions as a node (the 7 constants stay entities) the graph would hold 42 nodes. G4 alone is 17 nodes and carries the 36 re-pointed test nodes; it depends on no `app.py` change, so D-5 B (Inc 12b) moves it whole if the orchestrator wants it off the serial `app.py` chain.
> E2-2 (for E3, D-2; I-6). Inc 10a's cases R-TUI-018.1/5 ("Issues, key `5`, Enter → the main, A2L and MAC views show the issue's address second") and R-TUI-040.12/2 rest on `_jump_to_validation_issue_object`, which no product route runs: Enter on an issue row runs `on_issue_row_selected`, which repaints the Issues peek only. On 10a's E4 those cases fail for that reason, or pass only through a direct call of the dead adapter (a partial test). Under D-2 A the orchestrator rules 10a before its E4 (drop slice #11 and the two cases, or mark them not-testable); under D-2 B, Inc 12 re-points one line inside the function 10a edits.
> E2-3 (for E3, D-7, D-8). The Escape binding is a plain screen binding. The pilot found no focusable place of the dialog that takes Escape (`Input`, `ListView` bind none; the `TextArea` only with `tab_behavior="indent"`, and this one is `focus`), so a plain binding closes from all 10 places; the open dropdown list's own Escape runs first, which R-DLG.15 keeps. A priority binding would close the dialog under an open list; R-DLG.15's negative control is that mutant.
> E2-4 (for E3, D-10). The action census reads the toolkit's bindings and skips docstrings: without the first, `CappedTextArea.action_cut` and `OsClipboardInput.action_cut` (reached through `Input` / `TextArea` `ctrl+x` → `cut`) are false findings; with docstrings, a mention of an action's name in prose would count as a reach (C lines 55-66).
> E2-5. Coverage of the requirement → node map: R-DLG.14: `VariantHelpScreen`; R-SHELL-KEYS.3: `S19TuiApp.action_view_main`, `.action_view_alt`, `.action_view_mac`, `._jump_to_validation_issue`, `._jump_to_validation_issue_object`, `._format_validation_issue_line`, `._update_issues_hex_pane`, `.on_issue_row_selected`, `.action_show_screen`; R-CHKED-058: `CheckEditorPanel.compose`, `.on_button_pressed`, `._show_tab`; R-TUI-059.25: the `FlowBuilderPanel` nodes, `pipeline_text`, `_flow_block_label`; R-FX-SCR.4: `FlowExecutionPanel.compose`, `.on_mount`; R-DLG.2: `ReportViewerScreen.action_close_reports`, `.on_button_pressed`, `WindowHelpScreen.action_close_window_help`, `S19TuiApp.action_view_reports`, `S19TuiApp.on_key`; R-DLG.15: `S19TuiApp.on_key`, `[Outside: dropdown list]`, `[Data: ReportViewerScreen.BINDINGS]`. Every active row and every case of `../02-test-cases.md` (R-DLG.14/1, R-SHELL-KEYS.3/1, R-CHKED-058/1, R-TUI-059.25/1, R-FX-SCR.4/1, R-DLG.2/1 … /12, R-DLG.15/1, AT-I12-1 … -3) has at least one concrete example.
