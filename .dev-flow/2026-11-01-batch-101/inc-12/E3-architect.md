# Inc 12 — E3 code-free design review: architect

Batch 2026-11-01-batch-101, increment 12 (every dialog, action and widget reachable; Escape closes the Reports dialog). Base `2d1e2b1`, records commit `4b5f1bb`. The product tree on the branch equals main (`git diff --stat 2d1e2b1 HEAD -- s19_app tests docs` is empty).

**Records read:** `01-requirements.md`, `02-test-cases.md`, `E1-slice.md`, `E1-rulings.md` (with the orchestrator rulings at its end: D-2 A, D-5 B), `codewire/graph-inc12.md`, `steps.log`, both E1 transcripts and `evidence-e1/i12e1-census.py`.

**Code read on the base tree:**
- `screens.py` :1070-1153, :2695-2710, :3030-3050, :3095-3180, :3275-3420, and its handler outline to :3506.
- `app.py` :2715-2740, :10670-10763, :16736-16890, :17150-17178.
- `screens_directionb.py` :7708-7716, :7820-7840, :7912-7960.
- `flow_screens.py` :1585-1630, :2104-2122, :2500-2520, :2582-2617, :3316-3356, and every line naming a removed id.
- `window_help.py` :185-212, :850-925.

**Tests read:** `test_tui_directionb.py` :6495-6700, `test_tui_app.py` :630-700, `test_tui_goto_marker.py` :490-512, `test_window_usage_help.py` :600-640, `test_b100_focus.py` :1160-1200, `test_b101_help_legend_docs.py` :1780-1966, `test_b97_key_bar.py` :305-330 and :620-690, `b97_fixtures.py` :120-150, `b97_probes.py` :120-140.

**Toolkit read:** textual 8.2.8, from an installed copy on this PC, read as text only: `app.py` :3966-3989, `widgets/_select.py` :40-60 and :292, `widgets/_input.py` :138-140, `widgets/_text_area.py` :370-391 and :1820-1840.

**Other increments read:**
- Inc 9 on `b101-inc9` (`9120d91c`): the three-dot diff and `tests/test_b101_flow_names_ui.py` :135-160.
- Inc 10a and 10b on `b101-inc10` (`205550f7`, plus its uncommitted record edits): `inc-10/E3-rulings.md` :48-50, `inc-10/E1-slice.md` :3-68, `inc-10/02-test-cases.md` :7-46, `inc-10/01-requirements.md` :6-48.

**Run:** nothing that imports `s19_app`. Two read-only AST scripts parsed the source text with `python -I`:
- `reach_audit.py` classifies the source of each action's reach.
- `opener_audit.py` finds the function that holds each dialog construction and counts its references.

Both scripts are in the session scratchpad (`C:\Users\jjgh8\AppData\Local\Temp\claude\107abb51e32da120\e5f4854c-ff03-4b96-961e-71e14eb1ee40\scratchpad\`). They are not evidence. Their results below are `executed` on this PC as source reads only. Every base count they imply must be re-measured on the LAN host at E4.

## Verdict: FAIL

1 MAJOR, 7 MINOR, no HIGH. The design needs no redesign:
- Removing each dead dialog, action and widget is right: D-1 A, D-2 A, D-3 A, D-4 A.
- D-7 A's plain screen binding is confirmed against the toolkit source (§2).
- D-5 B splits along a seam with no code edge (§3).

**What blocks.** One record defect blocks E4. The action census counts reaches that no operator path runs: a call from dead code, and any English word in a message. So R-SHELL-KEYS.3 cannot fail when the removed D3-7 chain comes back, and D-10's reason ("the census catches the next dead action") does not hold (E3A-01). The fix is a record edit.

**Per part after the split.** Inc 12 is FAIL (E3A-01). The Inc 12b rows (R-TUI-059.25, R-FX-SCR.4) have no blocking finding: they are PASS-WITH-NOTES, with E3A-03 and E3A-05 to fold in.

## 1. Findings

| Id | Severity | Row / node | Finding | Proposed fix |
|---|---|---|---|---|
| E3A-01 | MAJOR | R-SHELL-KEYS.3 (`01-requirements.md:38`) · CTX-KEYS *Reach* (`:27`) · I-5 (`graph-inc12.md:27`) · the census fixture (`02-test-cases.md:6`) · R-SHELL-KEYS.3/1 (`:15`) · D3-7 (`01-requirements.md:55`) · D-10 (`E1-rulings.md:45`, `:86`) | US-I12-1 asks for "no action that no operator path reaches". The census counts a reach that is not an operator path. Two failure shapes, both on base. **(a) Dead callers count.** The call `app.py:16840` sits in `_jump_to_validation_issue_object`. Its one caller, `_jump_to_validation_issue`, has none (`app.py:16752`, census transcript :68-69). The census counts that call as the reach of `action_view_alt` (transcript :58), as the row's Base column admits. So a revert that restores `action_view_alt` with the D3-7 trio, which is the base, keeps R-SHELL-KEYS.3/1 GREEN. AT-I12-2 holds on base, so no case can fail on it. Four of the seven removed `app.py` functions are traced (`:55`) to a row whose test cannot see them. **(b) Prose counts.** The census splits every non-docstring literal into words (`i12e1-census.py:189-191`). On base, 4 of the 83 actions are "reached" only by messages: `CappedTextArea.action_copy` and `.action_paste`, `OsClipboardInput.action_copy` and `.action_paste`. The messages: `app.py:8084` "…(clipboard paste failed?)", `flow_screens.py:2263` "Paste refused: …", `app.py:319` "copy the folder into the work area". The AST audit found no exact action string for them, no binding on their own class and no call. Their real reach is the toolkit's `ctrl+c` / `ctrl+v` (`_input.py:139-140`, `_text_area.py:380-391`), and the census reads that arm only when no word matches. A future dead `action_copy`, `action_save`, `action_refresh` or `action_cancel` therefore passes. **(c) The script and I-5 differ.** The script's toolkit arm is name-global over all of textual (`:197-205`). I-5 says "a toolkit base class of the method's class". Product bindings are matched name-global too: seven classes define `action_cancel`, and today each has its own binding, so there is no instance yet. **Consequence.** D-10's reason holds only for an action with a unique name and no caller at all. This increment's own `action_view_alt` is the counterexample. | Records only; the census is E4 code. **1. Redefine an action string.** In *Reach* and I-5, an action string is a literal that is wholly `name`, `name(<args>)`, `app.name` or `screen.name` (a binding's or a palette entry's action, or a `run_action` argument), or the target of an `@click=` link. A toolkit binding counts when it is declared on a toolkit base class of the action's class (`CappedTextArea(TextArea)`, `OsClipboardInput(Input)`). **2. Count only calls from a reached function.** A reached function is an action that has a reach, a method the toolkit dispatches by name (`on_*`, `_on_*`, `compose`, `watch_*`, `validate_*`, dunders), or a function that a reached function calls or passes. Search backward from each call-only action. On base these are `view_alt` and the four paging actions; the paging actions are reached through `action_page_*_context` and `on_button_pressed`. **3. Update the threshold.** Base: 3 of 83 without a reach (`view_main`, `view_alt`, `view_mac`; derived by reading, to re-measure at E4). After: 0 of 80. Six overrides are reached through the toolkit: `action_cut`, `action_copy` and `action_paste` of the two clipboard widgets. **4. Add two negative controls.** Restoring `action_view_alt` with `_jump_to_validation_issue` and `_jump_to_validation_issue_object` → the census names `S19TuiApp.action_view_alt` → RED. An unbound `action_copy` on a class that is not a toolkit widget → RED. **5. Mirror the change** in R-SHELL-KEYS.3/1's expected result and in graph E2-4. |
| E3A-02 | MINOR | R-DLG.14 (`01-requirements.md:37`) · I-5 | The opener census has the same dead-caller arm: "a construction … in another part of the system" also counts a construction in a function that nothing runs. **No instance on base.** One hop up, every dialog other than `VariantHelpScreen` is constructed inside a toolkit-dispatched handler or action, or inside a function referenced elsewhere: `LoadResultScreen` ← `_install_prepared_project` (`app.py:14580`), `FileRefChooserScreen` ← `_open_file_ref_chooser` (`:4283`), `BulkParameterAddScreen` ← `CheckEditorPanel._open_parameter_bulk_add` (`screens_directionb.py:7895`), `WindowHelpScreen` ← `open_window_help` (`window_help.py:653`), and so on (AST audit, one hop only). | Apply E3A-01 (2) to openers. Otherwise state the limit in the threshold ("a construction in any function"). |
| E3A-03 | MINOR | R-CHKED-058 (`:44`); in 12b, R-TUI-059.25 (`:45`) and R-FX-SCR.4 (`:46`) · CTX-SHELL · the state-walk fixture (`02-test-cases.md:7`) | **The rows promise more than the walk checks.** The rows say "every widget". Their thresholds and the walk count only widgets that have an id. The windows also compose id-less widgets (labels, rows, containers), and an id-less widget that is never shown passes. **The population is not pinned.** "Mounted in the window" does not say in which state. Flow Execution mounts its lane widgets on import ("34 after the import", graph :345). | Write "every widget with an id" in the three rows, or put it in CTX-SHELL. Fix the population as the union of ids mounted in any walked state, and assert ≥ N on that union. |
| E3A-04 | MINOR | Slice §1 "Not source" (`E1-slice.md:16`) · `E1-rulings.md:64` · `tests/test_b101_help_legend_docs.py:1924-1966`, `:1797-1830` | **The fixed-set guard.** `test_r_doc_guide_2_2_no_other_row_marked` pins the set of DOSSIER rows marked "fixed in 1.0.0". On main that is `_FIXED` with `len == 11`; Inc 9 takes it to 13. Marking F-33, F-34, F-35 and F-51 at E4 turns `_2_2` RED unless `_FIXED` grows. No lane owns the file. **The guide passages.** The ch16:60 and ch18:172-173 edits have no `_GUIDE_PASSAGES` entry (R-DOC-GUIDE.1), the form every other user-guide fix in this batch takes. | Give G-T1 `tests/test_b101_help_legend_docs.py`. Add F-33, F-34 and F-51 to `_FIXED` and update the count. F-35 is added only by whichever of Inc 12 and Inc 12b merges second (§3). Add a passage for ch18 (absent "`esc` does not close this viewer", present "`esc`") and one for ch16:60. Inc 9 also edits this file and ch18, so make these edits on the merged tree. |
| E3A-05 | MINOR | 12b, lane G-T3 (`E1-slice.md:85-96`) | Inc 9's new helper `_add_load_block` (`tests/test_b101_flow_names_ui.py:143-154` on `b101-inc9`) waits on `panel.query_one("#flow_kind", Select).value == BLOCK_SOURCE` (`:149`). Three Inc 9 nodes drive it: `test_r_flow_file_12_1_save_after_clear_holds_own_name`, `test_r_fb_save_8_1_refused_home_status` and `test_at_i9_3_linked_homes_refuse_saves`. The E1 census ran before this file reached main. `E1-rulings.md:59` foresaw the case, and it is now confirmed. | 12b's re-point list becomes 39 nodes in 13 files. The helper waits instead on the LOAD chip's `chip-selected` mark, or on `.flow-kind-tag` reading `◉ LOAD`. |
| E3A-06 | MINOR | R-DLG.2 threshold (`01-requirements.md:52`) · the canon fold | R-DLG.2 is shared by all 21 dialogs, but its threshold covers the Reports dialog only ("12/12"). After Inc 12, seven dialogs still ignore Escape (`E1-rulings.md:17`, D7-20). The S7 review records this row as "Partly". A fold that copies "12/12" marks the row as met. | Add to the Base column: "Partly after Inc 12. Reports: yes. Select variant, Save flow, Load flow, Discard unsaved flow edits?, Edit entry JSON, CRC write confirmation, Operations: no (D7-20)". The CTX-DIALOG "Esc today" column carries the same state. |
| E3A-07 | MINOR | AT-I12-2 (`02-test-cases.md:33`) · I-6 (`graph-inc12.md:28`) | **A withdrawn case as fixture.** AT-I12-2's precondition is "the fixture of Inc 10a's R-TUI-018.1/5", and the 10a addendum withdraws that case (`inc-10/02-test-cases.md:17`). **An uncommitted interface.** The addendum itself (`inc-10/E3-rulings.md:48-50`, `E1-slice.md:27`, `:68`, `02-test-cases.md:7`) is not committed: `git status` on `b101-inc10` shows 5 modified records. | Cite `tools/synth/make_release_case.py` (case 08 with `firmware_issues.a2l`) and the issue row directly. Commit the 10a addendum before 10a's E4, so that I-6 rests on a committed record. |
| E3A-08 | MINOR | R-DLG.15/1 (`02-test-cases.md:31`) | R-DLG.15 says "close **only** that dropdown list". The case checks that `expanded` is false and that the dialog is on top. It does not check that the dropdown's selection did not change. | Add the selection: the dropdown's value unchanged (blank) and no `FilterSelected` posted. After `t` reopens the dialog, the dropdown is blank. |

## 2. The checks the dispatch named

| Check | Result | Evidence |
|---|---|---|
| The graph builds every row (was/now vs base) | ✓ **Lines and claims.** Each changed or removed node's base line range and its "was" claim match the source: `screens.py` :1070-1153, the Reports `BINDINGS` :3169-3171 and its comment from :3164, Close :3479-3482; `app.py` :10753-10763, :16738-16752, :16754-16800 (the "Used by" text at :16780-16781, the comment at :16783), :16802-16842, :16879-16886, the Escape branch of `on_key` at :10736-10741, `on_issue_row_selected` at :17154-17175, the rail keys at :2721-2723; `screens_directionb.py` :7712-7714, :7827-7834, :7940-7943; `flow_screens.py` :1590-1596, :1607-1612, :1619-1620, :1627, :1693, :2109-2110, :2506, :2515, :2584-2589, :2594, :2609-2610, :3320-3326, :3350. **Counts.** The node count reconciles: 35 nodes (12 changed, 1 new, 12 removed, 10 context), 11 entities and 18 edges. **Rows.** Every active row maps to at least one node (E2-5), and every case has an example. | the lines listed |
| The removals leave no live reader | ✓ **Product.** Outside their own bodies, the removed names appear only in `window_help.py` :12, :627 and :661 (docstrings, BL-I12-1). **Tests.** They appear only in the nodes of slice §5. **Docs.** They appear only in history and review files and in the DOSSIER rows. **Nothing new is left dead.** `_focus_a2l_tag_absolute_index` keeps a live caller (`app.py:16690`). `styles.tcss` has no rule on any removed id. In 12b, `_KIND_OPTIONS` stays used by the chips (`:1623`), as do `RIBBON_NO_SESSION` (`:1206`, `:1212`) and `Select` (`flow_ext_mode`). **Exceptions.** Two items are not in the slice: E3A-04 (doc guard) and E3A-05 (Inc 9 helper). | `grep` over `s19_app/`, `tests/`, `docs/` for every name and id of I-3; `styles.tcss` |
| Escape mechanism (D-7 A, R-DLG.15) | ✓ **Screen binding.** Non-priority bindings walk `screen._modal_binding_chain` from the focused widget upward (`textual/app.py:3966-3989`). So the open list's `SelectOverlay` binding `escape → dismiss` (`_select.py:51`) runs before the dialog's binding. **Negative control.** Priority bindings walk `reversed(_binding_chain)`, from the app down. A priority binding on the dialog therefore fires first, so R-DLG.15's negative control is a real mutant. **Focusable places.** `TextArea` takes Escape only with `tab_behavior == "indent"` (`_text_area.py:1829-1834`). `Select`, when closed, binds `enter,down,space,up` only (`:292`). **App handler.** The app's `on_key` stops Escape only for the six find and go-to inputs. **Precedent.** `LegendScreen` already uses this idiom (`screens.py:2701-2703`, `:3037-3044`), with the same log text form. **Not run.** Nothing here was executed. | textual 8.2.8 source; `app.py:10736-10741` |
| Interface with Inc 9 | ✓ **No shared function.** Inc 9 changes `app.py` only at :4013-4592 (three-dot diff from `2d1e2b1`), and `flow_screens.py` only in its module docstring (hunks `@@ -3,11`, `@@ -29,8`). Both are disjoint from Inc 12 and 12b. **One test seam.** Inc 9's new UI test reads `#flow_kind` (E3A-05). **Merge seams.** `ch18`, `DOSSIER.md` and `test_b101_help_legend_docs.py` (E3A-04). | `git -C …-inc9 diff 2d1e2b1...HEAD` |
| Interface with Inc 10a | ✓ The D-2 ruling has been applied in 10a's records. Slice #11 is withdrawn. R-TUI-018.1/5, R-TUI-018.3/1 and R-TUI-040.12/2 are withdrawn and kept by id, with R-TUI-018.3/3 added. A window-switch rule forbids `action_view_*`. TC-012's alias change stays with Inc 12. `action_show_screen` (#15) is only called by Inc 12, so there is no conflict. **One gap:** these 10a records are uncommitted (E3A-07). | `inc-10/E1-slice.md:27`, `:51`, `:68`; `inc-10/02-test-cases.md:7`, `:17`, `:29`, `:46` |
| Interface with Inc 10b | ✓ No shared function and no shared file. `b101-inc10` has no product change since its merge base. | three-dot diff, empty outside `.dev-flow/` |
| Requirement quality (strict EARS, ISO 29148) | ✓ with notes. **Form.** Each of the 7 rows has one `shall` and one response, with the system as subject. R-DLG.2's "When … while …" is not a form defect: the canon itself has 34 rows of that shape (`grep '| When | When … while' REQUIREMENTS.md`). **Thresholds and controls.** Every threshold is numeric, and every row has a negative control that fails on base. **Notes.** *Verifiable* and *complete* fall short on R-SHELL-KEYS.3 (E3A-01). R-CHKED-058 promises more than its walk checks (E3A-03). | `01-requirements.md:37-53` |
| Case oracles exact and able to fail | ✓ with notes. **R-DLG.2/1–/11.** Each fails on base (the pilot shows the dialog still open from 10/10 focus places and on the empty dialog, transcript :35-44 and :54). Each "nothing more changes" clause can fail. /3 and /5 can fail because reopening re-seeds the box from the project (`screens.py:3301-3307`) and posts the filter only on `Input.Submitted` (`:3448-3476`). /7 counts files, which a Generate path would change. /9 counts spy calls. **Regression guards.** /12, AT-I12-2 and AT-I12-3 hold on base and guard against regressions. **Notes.** E3A-07 and E3A-08. | the case table; pilot transcript |
| The census rows are sound and not vacuous | **R-DLG.14:** ✓ non-vacuous (population asserted, `VariantHelpScreen` restore → RED), with one limit (E3A-02). **R-SHELL-KEYS.3:** non-vacuous for `view_main` and `view_mac`, but unsound for dead callers and prose (E3A-01). **Widget walks:** ✓ each fails on base (pilot :19, :25, :27) and asserts its population. Their scope needs stating (E3A-03). | as cited |
| The D-5 split is clean | ✓ No code edge between the halves. The cuts and shared items are in §3. | §3 |

## 3. Split map for D-5 B

**Inc 12** keeps three source files: `screens.py`, `app.py` and `screens_directionb.py`.

| Kind | Inc 12 | Inc 12b (`flow_screens.py` alone) |
|---|---|---|
| Stories | US-I12-1; US-I12-3; US-I12-2 narrowed to the Check Editor | US-I12b-1: the Flow Builder and Flow Execution half of US-I12-2 ("hold only widgets some state shows; no hidden copy repainted on every change") |
| Rows | R-DLG.14, R-SHELL-KEYS.3, R-CHKED-058, R-DLG.15 (new); R-DLG.2 (changed): 5 | R-TUI-059.25, R-FX-SCR.4 (new): 2 |
| Definitions | CTX-DIALOG (*opener*, *dropdown list*, the Reports Esc row); CTX-KEYS (*action*, *reach*, corrected per E3A-01); CTX-SHELL (*shown widget*, *state of a window*) | CTX-SHELL with the same text; whichever merges first folds it, and the other cites it |
| Cases | R-DLG.14/1, R-SHELL-KEYS.3/1, R-CHKED-058/1, R-DLG.2/1–/12, R-DLG.15/1; AT-I12-1, AT-I12-2; AT-I12-3 cut to its Check Editor half (`=`, tab to `#check_tab_addendum`, `enter` → `## Checks`): 16 + 3 AT = 19 | R-TUI-059.25/1, R-FX-SCR.4/1; AT-I12b-1, the Flow half of AT-I12-3 (`8`, tab to `#flow_palette_check`, `space`, `baseline.chk.json`, `+ Add` → `✓ CHECK` tag, gating shown, one CHECK card, ribbon `session`): 2 + 1 AT = 3 |
| Graph nodes | 18: `VariantHelpScreen`, `ReportViewerScreen.action_close_reports`, `.on_button_pressed`, `WindowHelpScreen.action_close_window_help`, `S19TuiApp.action_view_reports`, `.on_key`, `.action_view_main`, `.action_view_alt`, `.action_view_mac`, `._jump_to_validation_issue`, `._jump_to_validation_issue_object`, `._format_validation_issue_line`, `._update_issues_hex_pane`, `.on_issue_row_selected`, `.action_show_screen`, `CheckEditorPanel.compose`, `.on_button_pressed`, `._show_tab`. That is 3 changed, 1 new, 7 removed, 7 context | 17: `FlowBuilderPanel.__init__`, `.set_session_dir`, `.compose`, `._refresh_blocks`, `.on_button_pressed`, `.on_mount`, `.on_select_changed`, `._sync_kind_dependent_visibility`, `._name_strip_text`, `pipeline_text`, `._canvas_text`, `._layout`, `._block_rows`, `._blocks_text`, `_flow_block_label`, `FlowExecutionPanel.compose`, `.on_mount`. That is 9 changed, 5 removed, 3 context |
| Entities | 8: `[Data: ReportViewerScreen.BINDINGS]`, `[Data: VARIANT_HELP_TEXT]`, `[Data: App.screen_stack]`, `[Data: S19TuiApp.BINDINGS]`, `[Outside: escape]`, `[Outside: dropdown list]`, `[Outside: rail keys]`, `[Interface: Reports dialog]` | 3: `[Data: FlowBuilderPanel._kind]`, `[Code: canvas grid helpers]`, `[Doc: flow_screens docstrings]` |
| Edges | 11 (graph :396-412) | 7 (graph :413-421) |
| Interfaces | I-1, I-5, I-6; the dialog, action and Check Editor names of I-3; the Check Editor oracle and window keys of I-4 | I-2; the flow ids and painter family of I-3; the pipeline, ribbon and kind oracles of I-4 |
| Decisions and code changes | D-1, D-2, D-3, D-6–D-10; CODE-CHANGES D7-10, D6-12 (first half), D3-7, D9-8, D7-20 (Reports); BL-I12-1…4 | D-4, D-5 (D16-6); the `flow_screens.py` docstrings |
| New tests | `tests/test_b101_reach_and_reports_escape.py` (G-T1); `tests/test_b101_shown_widgets.py` (G-T2: R-CHKED-058/1 and the AT-I12-3 half, with its own walk helper) | a new file such as `tests/test_b101_flow_shown_widgets.py` (the two walks and AT-I12b-1, with its own walk helper; no shared helper module, so neither increment waits for the other) |
| Existing test nodes | G-T1 as in slice §5, plus the TC-011 docstring and the comment in `tests/test_tui_directionb.py` :6578-6582 and :6608-6610 (they describe the aliases Inc 12 removes; slice §5 gave them to G-T3), plus `tests/test_b101_help_legend_docs.py` (E3A-04); G-T2 as in slice §5 | G-T3: the 36 nodes in 12 files, plus the 3 Inc 9 nodes (E3A-05): 39 nodes in 13 files |
| Docs | `ch16:60`, `ch18:172-173`, DOSSIER F-33, F-34, F-51 | none of its own |
| Pinned notes for in-flight testers (`E1-rulings.md:62`) | the aliases, the jump trio, `VariantHelpScreen`, `#check_preview_toggle_button` | the seven flow ids and the painter family |
| Findings of this review | E3A-01, -02, -03 (R-CHKED-058), -04, -06, -07, -08 | E3A-03 (its two rows), E3A-05 |

**Cross-dependencies that remain.** None in code. No Inc 12 node calls a node of 12b, and none of 12b calls one of Inc 12. 12b removes no action and no dialog, so the R-DLG.14 and R-SHELL-KEYS.3 counts do not move. Four ties remain, all in records or test files:
- **DOSSIER F-35 and `_FIXED`.** F-35 is fixed only when both halves land. Whichever of the two merges second marks it and adds it to `_FIXED`. By the schedule that is Inc 12, which stays last in the `app.py` chain.
- **CTX-SHELL terms.** Both records carry the terms with identical text.
- **`tests/test_tui_directionb.py`.** Inc 12 edits the TC-011 docstring and 12b edits two flow nodes. The hunks are disjoint, so this is a textual merge.
- **`tests/test_id_registry.py`.** `EXPECTED_SCANNED_TEST_FILES` grows by 2 for Inc 12 and by 1 for 12b. Each increment re-measures it at its own integration.

12b's E4 still waits for Inc 9's merge, for the module docstring and for E3A-05.

## 4. Design assessment

**Removal over wiring (D-1 A, D-2 A, D-3 A, D-4 A).** This is right, and it matches the skill's rule "prefer removing a feature over guarding it":
- Wiring `VariantHelpScreen` or a jump from an issue would add UI that the P0 ruling excludes.
- D-2 A's cost to the other increment is already paid in 10a's addendum.
- Under D-4 A, the panel's `_kind` replaces a hidden widget as the place the state lives. The kind chips then become the one way to set it, and the tests have to drive the product route.

**D-7 A.** The smallest change, and it holds in every focus place (§2). D-8 A brings the shared row in line with what the toolkit actually does, without relaxing it for dialogs that have no dropdown.

**D-10 A.** A census is the right instrument because it guards the class of defect. It holds only if its definition of a reach matches that claim (E3A-01). With the strict action string and the rule on reached callers, the base gives 3 of 83, exactly the F-34 set. D-10's "no allowlist" still holds: the six clipboard overrides pass through the toolkit arm.

**D-5 B.** The split is right. It takes 39 test-node edits off the serial `app.py` chain, and the seam is a file boundary with no code edge.

## 5. Risks

| Risk | Kind | Note |
|---|---|---|
| The two censuses become project-wide guards. Any later increment that adds a dialog or action before its opener goes RED | process | Intended. A false RED can come from an action that is only passed as a callback (`call_later(self.action_x)`). The reached-caller rule must count references, not only calls (E3A-01 (2)). |
| The census reports a dead action as reached | evidence | E3A-01. As written, the D3-7 removal has no RED-able test. |
| Inc 10a's interface rests on uncommitted records | process | E3A-07. |
| Doc and guard seams with Inc 9 (`ch18`, `DOSSIER.md`, `test_b101_help_legend_docs.py`) | merge | E3A-04. Make the edits on the merged tree. |
| The base numbers in this review come from reading on this PC, not from a run | evidence | `3 of 83` and the four prose-only reaches are `executed` as AST reads only. Re-measure them on the LAN host at E4 before they enter a threshold. |

**Cost and latency:** n/a. The only runtime effect, two hidden repaints of 0.33 ms per chain change (pilot :23-24), leaves with 12b.

## 6. Evidence checklist

| Item | State | Evidence |
|---|---|---|
| Constraints stated | ✓ | The 4-source-file cap (slice §1), the P0 no-UI ruling (D-1, D-9), the merge order Inc 9 → 10a/10b → 12 (slice §4), and the operator's rule of no `s19_app` run on this PC (header) |
| 2+ alternatives where a real decision exists | ✓ | D-2 (A, B, C), D-5 (A, B, C), D-7 (A, B, C), D-10 (A, B); the definition of a reach (E3A-01: the loose census, a strict string with reached callers, or a narrowed claim, §7) |
| Constraints that do not apply marked n/a | ✓ | Cost and latency n/a (§5); no remote run |
| Recommendation tied to constraints | ✓ | §4; E3A-01 is tied to US-I12-1 and to D-10's own reason |
| Risks listed | ✓ | §5 |
| Diagram | n/a | The flows are short and are the graph's edges; the split is a table (§3) |
| What would change the verdict | ✓ | §7 |
| Two-layer requirements | ✓ | **Behavioural chain:** US-I12-1 → AT-I12-2, US-I12-2 → AT-I12-3, US-I12-3 → AT-I12-1. **Functional chain:** US → rows → cases → slice. After the split, US-I12b-1 needs AT-I12b-1 (§3) |

## 7. What would change the verdict

The verdict becomes PASS-WITH-NOTES for Inc 12 when E3A-01 is applied:
- *Reach* and I-5 are redefined.
- The threshold and the base number are corrected.
- The `view_alt`-with-D3-7 negative control is added.

The MINOR rows can be folded in at the correction pass or at E4.

**An alternative the orchestrator can rule instead:** keep the loose census, and write down the narrower claim:
- In D-10 and in the *Reach* definition: "catches an action that no code names".
- In BL: the D3-7 removal recorded as not verified.

That also clears the MAJOR, but it leaves US-I12-1's "no operator path" without a test. The architect prefers the fix.
