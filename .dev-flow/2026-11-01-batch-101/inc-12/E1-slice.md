# Inc 12 — E1 slice: every file and function to change, counted and mapped (corrected at E3)

Base `2d1e2b1` (product tree `e07fb00`). Line numbers are on the base tree. Graph: `codewire/graph-inc12.md`. Rows: `01-requirements.md`; decisions: `E1-rulings.md` §3 and the orchestrator rulings (D-1 A, D-2 A, D-3 A, D-5 **B**, D-6 A, D-7 A, D-8 A, D-9 A, D-10 A) and `E3-rulings.md`. **Split at E3 (D-5 B):** the `flow_screens.py` part (D-4, D16-6: 9 changed functions, the painter family, the docstrings, the 39 re-pointed test nodes) is `../inc-12b/E1-slice.md`. Census and pilot: `evidence-e1/i12e1-census-transcript.txt` (C), `evidence-e1/i12e1-pilot-transcript.txt` (B).

## 1. Summary

| File | Functions | Rows |
|---|---|---|
| `s19_app/tui/screens.py` | removed: the class `VariantHelpScreen` (`:1091-1153`) and its constant `VARIANT_HELP_TEXT` with its comment (`:1070-1088`); changed: `ReportViewerScreen.BINDINGS` (`:3164-3171`, + the Escape binding); new: `ReportViewerScreen.action_close_reports` | R-DLG.14, R-DLG.2, R-DLG.15 |
| `s19_app/tui/app.py` | removed: `S19TuiApp.action_view_main` (`:10753-10755`), `action_view_alt` (`:10757-10759`), `action_view_mac` (`:10761-10763`), `_jump_to_validation_issue` (`:16738-16752`), `_jump_to_validation_issue_object` (`:16802-16842`), `_format_validation_issue_line` (`:16879-16886`); changed: the docstring of `_update_issues_hex_pane` (`:16779-16781`, "Used by"); no module-level change | R-SHELL-KEYS.3 |
| `s19_app/tui/screens_directionb.py` | changed: `CheckEditorPanel.compose` (`:7708-7845`: the button `:7827-7834` and the docstring sentence `:7712-7714`), `CheckEditorPanel.on_button_pressed` (`:7912-7959`: the branch `:7940-7943`) | R-CHKED-058 |

Moved to Inc 12b at E3: `s19_app/tui/flow_screens.py` (R-TUI-059.25, R-FX-SCR.4; `../inc-12b/E1-slice.md` §1).

**Totals:** **3 source files of the 4 allowed.** 3 changed functions (`_update_issues_hex_pane` in its docstring only), 1 changed binding list, 1 new method; removed: 1 class, 6 methods and 1 constant in `screens.py` and `app.py`. Unchanged and only called or read: `S19TuiApp.action_show_screen` (keys `1`, `2`, `3`), `S19TuiApp.action_view_reports` (`t`), `S19TuiApp.on_issue_row_selected`, `S19TuiApp.on_key`, `ReportViewerScreen.on_button_pressed`, `WindowHelpScreen.action_close_window_help`, `CheckEditorPanel._show_tab`, `FlowBlockEditScreen.action_cancel` (R-DLG.15/2, test only; E3 U-4). Before the split: 4 source files, 12 changed functions, 3 changed docstrings outside functions and the painter family of 19 names.

Not source (written at E4, on the tree where Inc 9 and Inc 12b have merged; `E1-rulings.md` §5):
- `docs/user-guide/ch18-flow-execution.md:172-173` — "Close it with **Close** — `esc` does not close this viewer (finding F-51)." → "Close it with **Close** or `esc`." (E3 U-5).
- `docs/user-guide/ch16-reports.md:60` — the row `| Open reports/, `?`, Close | chips, button | 16.1 |` becomes two rows: `| Open reports/, `?` | chips | 16.1 |` and `| Close | button / `esc` | 16.1 |` (E3 U-5). `:26` is not changed: it lists the buttons and stays true (U-5 marks its edit optional; not taken).
- `docs/user-guide/DOSSIER.md` §5 — the Kind cell of rows F-33 (`:742`), F-34 (`:743`), F-35 (`:744`) and F-51 (`:760`) gains ` · fixed in 1.0.0` (the F-05 form, U-5). F-35 is marked here only if Inc 12b is on main when Inc 12 integrates; otherwise Inc 12 marks three rows and 12b marks F-35 (E3A-04 + U-1). W24 row 10 (`:578`) stays as found (U-5).
- `tests/b97_fixtures.py:128-148` (the frozen Check Editor id set, a test fixture); `tests/test_b101_help_legend_docs.py` (`_FIXED` and two `_GUIDE_PASSAGES` entries, §5).

## 2. Function map

| Function | File:line (base) | Change | Rows |
|---|---|---|---|
| `VariantHelpScreen` (class), `VARIANT_HELP_TEXT` | `screens.py:1070-1153` | **removed** (D-1 A): the comment block, the constant and the class; nothing else in the tree names them except three docstrings of `window_help.py` (`:12`, `:627`, `:661`, D-6: backlog BL-I12-1) | R-DLG.14 |
| `ReportViewerScreen.BINDINGS` | `screens.py:3164-3171` | + `Binding("escape", "close_reports", "Close", show=False)` after the `?` binding; not `priority` (D-7 A, the `LegendScreen` idiom `:2701-2703`); the comment above it gains one line for Escape | R-DLG.2, R-DLG.15 |
| `ReportViewerScreen.action_close_reports` (new) | `screens.py`, after `action_show_window_usage_help` (`:3173-3174`) | `logger.info("ReportViewerScreen dismissed by Esc.")`; `self.dismiss(None)` — what Close does (`on_button_pressed`, `:3479-3482`, unchanged): no message posted, so no report is generated and no typed filter path is applied (R-DLG.9) | R-DLG.2 |
| `S19TuiApp.action_view_main`, `.action_view_alt`, `.action_view_mac` | `app.py:10753-10763` | **removed** (D-2 A); keys `1`, `2`, `3` keep `show_screen('workspace' / 'a2l' / 'mac')` (`app.py:2721-2723`, unchanged) | R-SHELL-KEYS.3 |
| `S19TuiApp._jump_to_validation_issue`, `._jump_to_validation_issue_object`, `._format_validation_issue_line` | `app.py:16738-16752`, `:16802-16842`, `:16879-16886` | **removed** (D-2 A, D3-7); the first has no product caller and is the only caller of the second; the second holds the only call of `action_view_alt` (`:16840`); the third has no product caller (C lines 67-70). `ListItem`, `ValidationIssue`, `ValidationSeverity` stay imported (16, 19, 74 other uses) | R-SHELL-KEYS.3 |
| `S19TuiApp._update_issues_hex_pane` | `app.py:16754-16800` | docstring only: "Used by" names `on_issue_row_selected` in place of `_jump_to_validation_issue_object` (`:16780-16781`); the comment at `:16783` ("a headless unit-test call to the jump path") names the removed path and is reworded to "a call with no mounted screen" | R-SHELL-KEYS.3 |
| `CheckEditorPanel.compose` | `screens_directionb.py:7708-7845` | the `toggle` button `#check_preview_toggle_button` (`:7827-7834`) goes; `#check_actions_row2` keeps `#check_fields_count` (its CSS rule `styles.tcss:2751` stays); the docstring sentence "``#check_preview_toggle_button`` stays mounted and hidden, its function carried by the Addendum tab chip" (`:7713-7714`) goes | R-CHKED-058 |
| `CheckEditorPanel.on_button_pressed` | `screens_directionb.py:7912-7959` | the branch `check_preview_toggle_button` → `_show_tab("check_tab_addendum")` (`:7940-7943`) goes; the tab chips keep `_show_tab` (`:7920-7923`) | R-CHKED-058 |

Moved to Inc 12b at E3: the `FlowBuilderPanel` and `FlowExecutionPanel` rows, the painter family and the `flow_screens.py` docstrings (`../inc-12b/E1-slice.md` §2).

## 3. Callers read (rule 8: read before you write)

- `VariantHelpScreen`: no construction outside its body (C line 16); `window_help.py` names it in three docstrings only. `tests/test_tui_variants.py` pushes it in one node; the module's other two variant-help nodes assert the retired opener and message are gone.
- `action_view_main` / `_mac`: no binding, no palette entry (the palette is built 1:1 from `S19TuiApp.BINDINGS` plus `EXTRA_PALETTE_ENTRIES`, `app.py:9921-9967`), no call (C lines 57-59, B lines 9-11). `action_view_alt`: one call, `app.py:16840`, in `_jump_to_validation_issue_object` ← `_jump_to_validation_issue` ← no product caller (C lines 67-70); under the corrected *reach* (E3A-01) that call is not a reach, so the base has 3 actions without one. The Issues window posts `IssueRow.Selected`, handled by `on_issue_row_selected` → `_update_issues_hex_pane` only (`app.py:17154-17175`); `on_data_table_row_selected` documents that Issues rows are not dispatched there since batch-29 (`app.py:16287-16289`).
- `_update_issues_hex_pane` ← `on_issue_row_selected` (`:17175`) and the removed `_jump_to_validation_issue_object` (`:16828`); its no-screen guard stays (a headless call is still possible from tests).
- `ReportViewerScreen` ← `S19TuiApp.action_view_reports` (`app.py:6335`, key `t`); its Close (`:3479-3482`) dismisses with `None` and posts nothing; Generate posts `GenerateRequested` to the app then dismisses (`:3483-3506`). The app-level `on_key` (`app.py:10676-10751`) acts on Escape only when the focus is in one of the six find/go-to boxes (`_FIND_GOTO_INPUT_IDS`), none of them in a dialog. The Reports help window `WindowHelpScreen` has its own Escape (`window_help.py:688`, `action_close_window_help` `:745`). No focusable place of the dialog takes Escape: `Input` and `ListView` bind none, the `TextArea` takes it only with `tab_behavior="indent"` (the dialog's box is `focus`, B line 33), `SelectOverlay` binds Escape to close its list (textual 8.2.8 `widgets/_select.py:51`) and does not apply the highlighted option (`:161`, E3 U-3).
- `FlowBlockEditScreen` ← `S19TuiApp.on_flow_builder_panel_edit_requested` (`app.py:4109`; the Flow Builder's Edit chip `#flow_edit` with `#flow_pick`); its plain `Binding("escape", "cancel")` (`screens.py:1924`) runs `action_cancel` → `dismiss(None)` (`:2136-2137`), and `None` changes no block (`app.py:4103-4106`). Its gating dropdown `#flow_edit_gating` (`:1977-1987`) is the app's other dialog dropdown (E3 U-4). Not changed.
- `#check_preview_toggle_button`: no product query (C line 101); the only route to its function is the Addendum tab chip (`_CARD_TABS`, `:7182-7186`).

## 4. Overlaps with pending increments

Merge order (D-5 B, E3): Inc 9 → Inc 12b (after Inc 9; parallel with 10a and 10b) → Inc 12, last in the `app.py` chain after Inc 10a and 10b. Inc 12's E4 integrates on main after all of them.

| Function, region or file touched by Inc 12 | Also touched by | How |
|---|---|---|
| `S19TuiApp._jump_to_validation_issue_object` | **Inc 10a** (its slice #11, withdrawn) | ruled for 10a in the committed addendum "Inc 12 D-2" (`d68cb9f` on `b101-inc10`, `inc-10/E3-rulings.md`): 10a dropped #11 and the issue-jump cases before its E4 (E3A-07, S-3) |
| `S19TuiApp.action_view_main` / `_alt` / `_mac` | none in product; **Inc 10a**'s testers may extend `tests/test_tui_goto_marker.py`, whose `test_goto_focus_not_cleared_on_tab_switch` calls them | 10a's window-switch rule forbids `action_view_*` (`d68cb9f`); at integration, the grep of the merged tree for every I-3 name (S-3) catches any call left |
| `S19TuiApp.action_show_screen` (called, not changed) | **Inc 10a** (#15, focus landing) | none: Inc 12 only calls it (AT-I12-2) |
| `S19TuiApp._jump_to_validation_issue`, `._format_validation_issue_line`, `._update_issues_hex_pane` | none | — |
| `screens.py`, `screens_directionb.py` | none of Inc 9, 10a, 10b, 12b | — |
| `docs/user-guide/ch18-flow-execution.md`, `DOSSIER.md`; `tests/test_b101_help_legend_docs.py` | **Inc 9** (ch18 `:113`, DOSSIER F-45, F-46; `_FIXED` 11 → 13, `b101-inc9` `9120d91c`) | other lines; Inc 12 edits them on the merged tree (E3A-04) |
| DOSSIER F-35, `_FIXED`; `tests/test_tui_directionb.py`; `tests/test_id_registry.py` | **Inc 12b** (no code edge) | F-35 and `_FIXED` are Inc 12's (it merges second); `test_tui_directionb.py`: Inc 12 edits the TC-011 docstring and comment, 12b two flow nodes — disjoint hunks; `EXPECTED_SCANNED_TEST_FILES`: +2 here, +1 in 12b, each re-measured at its own integration |

Inc 10b touches `app.py` (`_note_image_bytes_written` and three new helpers) and `segment_split_view.py`: no function shared with Inc 12. Inc 12 makes no module-level change in `app.py`.

## 5. Nodes touched (existing test node names)

Census on the base tree (AST of `tests/test_*.py`, a node's own source plus the module helpers it names, two hops; C lines 35-42, 74-87, 188-198). Each node keeps its name; the lane that edits it is given.

**Removed (2 nodes, G-T1):**
- `tests/test_tui_variants.py::test_variant_help_modal_fits_at_both_sizes` (pushes `VariantHelpScreen`) and its module constant `_VARIANT_HELP_TOKENS` (`:481`), read by no other node (D-1).
- `tests/test_tui_app.py::test_jump_to_validation_issue_prefers_address` (calls `_jump_to_validation_issue`, D-2).

**Changed assertions or drivers (G-T1):**
- `tests/test_tui_app.py::test_validation_issue_filtering_and_format`: its last three lines read `_format_validation_issue_line` and go; the filter assertions stay.
- `tests/test_tui_goto_marker.py::test_goto_focus_not_cleared_on_tab_switch`: the three alias calls become `action_show_screen("a2l")`, `("mac")`, `("workspace")`; the assertion (`_goto_focus_address == 0x1040`) is unchanged.
- `tests/test_window_usage_help.py::test_tc706_seat_census_header_row_and_window_section`: the pinned `ReportViewerScreen.BINDINGS` list gains `("escape", "close_reports", False)` (`:625-627`); the module docstring's mention of the `VariantHelpScreen` pattern (`:8`) is reworded.
- `tests/test_tui_directionb.py`: the TC-011 docstring's "retained legacy-alias methods" and the comment at `:6578-6582` and `:6608-6610` describe the aliases Inc 12 removes and are reworded (moved to G-T1 at E3; Inc 12b's G-T3 edits two flow nodes of the same file, disjoint hunks). `::test_tc011_every_pre_batch_action_keeps_a_keyboard_path` passes unchanged (the rail actions `show_screen(...)` are in `BINDINGS`; the `hasattr` arm goes unused).
- `tests/test_b101_help_legend_docs.py` (E3A-04 + U-1; on the tree after Inc 9 and Inc 12b): `_FIXED` gains `F-33`, `F-34`, `F-35`, `F-51` with a comment naming Inc 12 (13 → 17; named supersession of R-DOC-GUIDE.2, as Inc 6 and Inc 9 did), and `test_r_doc_guide_2_1_fixed_rows_marked`'s `len(_FIXED) == 13` becomes `== 17`; `test_r_doc_guide_2_2_no_other_row_marked` keeps its set equality. If Inc 12b is not on main when Inc 12 integrates, `F-35` is left out here (`== 16`) and 12b adds it. `_GUIDE_PASSAGES` gains the two entries of cases R-DOC-GUIDE.1/13, /14 (`02-test-cases.md`), appended last.
- QC-BC (run at E5, no edit expected): the nodes that open the Reports dialog and press Escape — `tests/test_b100_focus.py::test_at_b100_04_focus_lands_and_single_keys_reach_their_screens`, `tests/test_b101_help_legend_docs.py::test_r_whelp_7_2_question_mark_paints_the_approved_copy`, `tests/test_b99_export.py::test_at_b99_11_sanitised_mac_only_second_export_takes_suffix`, `tests/test_window_usage_help.py::test_tc706_close_and_escape_dismiss`, `::test_tc706_focused_question_mark_opens_same_modal` (C lines 191-196): each presses Escape inside a help window or after closing Reports by click, so Escape now closing the Reports dialog changes none of their paths; E5 runs them.

**Changed assertions (G-T2, Check Editor):**
- `tests/test_b97_check_editor.py::test_tc_b97_61_every_control_displayed_in_its_home` ("the toggle is mounted, not displayed" → the toggle id is not mounted; the docstring's sentence on it) and `::test_tc_b97_08_census_rows_and_one_docked_row` (36 → 35 ids); the fixture `tests/b97_fixtures.CE_IDS_9C7BEAF` drops `check_preview_toggle_button` and its guard becomes `len == 35` (`:139`, `:148`).

Moved to Inc 12b at E3: the re-pointed Flow Builder nodes (lane G-T3, 39 nodes in 13 files with Inc 9's three, E3A-05; `../inc-12b/E1-slice.md` §5).

The census is re-run on the merged tree at integration (tests that Inc 9, 10a, 10b or 12b add before Inc 12's E4 are in it then). **Integration check (S-3):** before the GREEN run, grep the merged `s19_app/` and `tests/` for every removed name of I-3 (`codewire/graph-inc12.md`) and record the empty result (the census cannot see a call of an action that no longer exists).

## 6. Tests to write (E4)

Two new files, one per tester (disjoint ownership): G-T1 `tests/test_b101_reach_and_reports_escape.py` (R-DLG.14/1, R-SHELL-KEYS.3/1, R-DLG.2/1 … /12, R-DLG.15/1, /2, AT-I12-1, AT-I12-2: 18 cases) plus the two passages R-DOC-GUIDE.1/13, /14 in `tests/test_b101_help_legend_docs.py` (20 cases), and G-T2 `tests/test_b101_shown_widgets.py` (R-CHKED-058/1, AT-I12-3: 2 cases, with its own walk helper; no helper module shared with Inc 12b). Ownership of existing test files: G-T1 — `test_tui_variants.py`, `test_tui_app.py`, `test_tui_goto_marker.py`, `test_window_usage_help.py`, `test_b101_help_legend_docs.py`, `test_tui_directionb.py` (the TC-011 docstring and comment only); G-T2 — `test_b97_check_editor.py`, `b97_fixtures.py`. `tests/test_id_registry.py`'s `EXPECTED_SCANNED_TEST_FILES` is re-measured at integration (+2 files). The censuses (R-DLG.14/1, R-SHELL-KEYS.3/1) read the source with `ast` under I-5 (exact action strings; reached callers only, references included; no docstring, comment or message word; the toolkit's bindings), assert their population size, and carry the negative controls of `02-test-cases.md`; their base numbers (3 of 83 actions, 1 of 22 dialogs) are re-measured on the LAN host before they enter the test. The state walk (R-CHKED-058/1) drives each state through the product's controls (tab chips), never by setting widget state directly, and pins its population as the union of the ids mounted over the walked states. 22 cases: G-T1 20, G-T2 2.
