# Inc 10 E4 — tester notes (independent tester)

Written from the design only: `E1-requirements-draft.md`, `E1-scope.md`, `E1-rulings.md`, `E2-rulings.md`, `E3-rulings.md` (round-2 rows marked T: S10-06, A10-R2-3), `codewire/interfaces-10.md`, `codewire/proto-10-dialog.md`, `codewire/proto-10-app.md`. No line of the Inc 10 implementation was read. The base code (`741cc07`) was read to find setup paths, and small probes were run against it in a scratch folder. Those probes drive only base behaviour (loads, patching by keys, Save project, the variant selector, Flow Builder add, the held-file A2L read).

- New file: `tests/test_b100_load_question.py` — 45 test functions, 52 collected nodes; with the 5 re-pinned nodes, 57 nodes run. Two of the functions are parametrized: 4 layout sizes and 5 replace routes.
- Re-pinned: 4 functions, 5 nodes, in `tests/test_b100_session_reset.py` and `tests/test_b99_editor_image.py`.
- RED transcript: `.dev-flow/2026-10-26-batch-100/evidence/inc-10/red-01-vs-base.txt`.
- GREEN: `not-run`. The implementation is not finished. The full suite and whole touched modules wait for the batch-end battery (operator override, 2026-10-31).

## 1. Requirement → test map

Every name below is in `tests/test_b100_load_question.py` unless another file is named.

| Requirement | Test(s) | Arm its negative control turns RED |
|---|---|---|
| HLR-174 | `test_at_b100_15_load_over_unsaved_work_asks_one_question_per_route`, `test_tc_b100_72_every_route_asks_and_cancel_keeps_the_session` | the base: each route loads with no question |
| HLR-174a | `test_tc_b100_44_saved_states_load_without_asking`, `test_tc_b100_44_attach_asks_nothing_and_keeps_the_patch`, `test_tc_b100_44_project_load_asks_iff_a_flag_is_set`, AT (after-save half) | `pb_A` "ask when a project is open"; an attach asking on D |
| HLR-174b | `test_tc_b100_72_replace_runs_the_load_on_every_route[load dialog/workarea/v/panel v/project]`, `test_tc_b100_72_one_question_per_request`, AT (replace half) | answer drops `go` |
| HLR-174c | `test_tc_b100_46_cancel_keeps_the_session_and_runs_no_reset` (6 arms), AT (keep half) | focus on `#confirm_yes` first; `go` before the push |
| HLR-174d | `test_tc_b100_45_body_says_unsaved_changes_once_in_two_sentences`, `..._patch_editor_entries_named_only_when_w`, `..._flow_item_named_with_its_flow_name`, AT (items half) | only the first item named |
| LLR-174.1 | `test_tc_b100_44_twenty_four_cells_ask_by_kind`, `test_tc_b100_44_saved_states_load_without_asking`, `test_tc_b100_44_undo_alone_and_repatch_after_save_ask` | drop D; a guard keyed on the entry count |
| LLR-174.1a | `test_tc_b100_44_twenty_four_cells_ask_by_kind`, `test_tc_b100_44_attach_asks_nothing_and_keeps_the_patch` | the round-2 rule (attach asks on D) |
| LLR-174.1b | `test_tc_b100_44_twenty_four_cells_ask_by_kind`, `test_tc_b100_44_project_load_asks_iff_a_flag_is_set` | drop F or W; the `pb_A` rule |
| LLR-174.1c | `test_tc_b100_44_patch_editor_reader_follows_its_writers`, `test_tc_b100_44_no_private_dirty_read_outside_the_panel`, `test_tc_b100_44_guard_reads_the_public_reader` | a cached reader; a setter; the `panel._dirty` read |
| LLR-174.2 | `test_tc_b100_45_one_modal_with_replace_and_cancel` | the `pb_B` third button |
| LLR-174.2a | `test_tc_b100_45_modal_builds_from_its_parameters` | a hard-coded `Replace (y)` |
| LLR-174.2b | `test_tc_b100_45_focus_starts_on_cancel_on_every_route` | `AUTO_FOCUS = "#confirm_yes"` |
| LLR-174.2c | `test_tc_b100_45_y_replaces_with_the_focus_on_either_button` | no `y` binding |
| LLR-174.2d | `test_tc_b100_45_n_and_escape_cancel_with_the_focus_on_either_button` | no `escape` binding |
| LLR-174.2e | `test_tc_b100_45_enter_answers_with_the_focused_button` | a screen-level `enter` → replace |
| LLR-174.2f | `test_tc_b100_45_click_answers_with_the_clicked_button` | `Button.Pressed` ignored |
| LLR-174.2g | `test_tc_b100_45_other_keys_leave_the_question_open` | the `pb_B` `s` binding |
| LLR-174.2h | `test_tc_b100_45_priority_keys_are_inert_under_the_question` (4 keys × 2 focus, the palette arm, the no-over-reach arm) | 9b's guard alone (`LoadDialog` only) |
| LLR-174.2i | `test_tc_b100_45_names_paint_literally`, `test_tc_b100_45_modal_builds_from_its_parameters` (hostile strings) | markup on; a raw name; a `str` button label |
| LLR-174.2j | `test_tc_b100_45_patch_editor_load_keeps_its_own_guard` | `DirtyLoadRequested` routed through the question |
| LLR-174.2k | `test_tc_b100_45_title_names_what_is_replaced` | always the image name |
| LLR-174.2l | `test_tc_b100_45_unsaved_image_is_named_by_its_file_name` | the project named instead |
| LLR-174.2m | `test_tc_b100_45_patch_editor_entries_named_only_when_w` | named on D |
| LLR-174.2n | `test_tc_b100_45_flow_item_named_with_its_flow_name` | the flow item dropped |
| LLR-174.2o | `test_tc_b100_45_load_target_named_per_route` | the current file named as the target |
| LLR-174.2p | `test_tc_b100_45_one_modal_with_replace_and_cancel` (labels on their ids; `n` and `y` act) | `ConfirmDiscardScreen` labels |
| LLR-174.2q | `test_tc_b100_45_body_says_unsaved_changes_once_in_two_sentences` | one sentence per item |
| LLR-174.2r | `test_tc_b100_45_buttons_and_body_stay_fully_visible[99x54, 118x54, 220x60 long; 118x54 short]` | `min-width: 120`; height 7 with the buttons undocked |
| LLR-174.2s | `test_tc_b100_45_a_second_answer_is_ignored` | the `_dismissed` guard removed |
| LLR-174.2t | `test_tc_b100_45_change_file_dropdown_keeps_the_guard` (+ A10-R2-3 re-pick arm) | no `is_dirty` read; the Select not reset |
| LLR-174.3 | `test_tc_b100_46_reset_runs_after_the_answer` | reset before asking |
| LLR-174.3a | `test_tc_b100_46_cancel_keeps_the_session_and_runs_no_reset` | reset before asking |
| LLR-174.3b | `test_tc_b100_46_project_load_handler_asks_nothing` | the guard moved into the handler |
| LLR-174.3c | `test_tc_b100_46_refused_project_after_yes_keeps_the_work` (M2), `test_tc_b100_46_unreadable_a2l_project_after_yes_keeps_the_work` (S10-01 / C58; Windows only) | flags cleared on `y`; the base order |
| LLR-174.3d | `test_tc_b100_46_cancelled_variant_switch_keeps_the_pending_selection` | the stamp set before the seam |
| LLR-174.4 | `test_tc_b100_72_every_route_asks_and_cancel_keeps_the_session`, `test_tc_b100_72_every_load_call_passes_the_seam` (AST, rule P-2 / A10-08) | the base tree: 6 bypasses |
| LLR-174.4a | `test_tc_b100_72_one_question_per_request` | the router and the project route both guarded |
| LLR-174.4b | `test_tc_b100_72_typed_path_takes_its_kind_from_the_classification` | the kind keyed on the dismiss kind; the MAC test on the raw quoted text |
| LLR-174.4c | `test_tc_b100_72_workarea_file_takes_its_kind_from_its_suffix` | a suffix-blind rule |
| LLR-165.3 (Inc 10 arm) | `tests/test_b100_session_reset.py::test_tc_b100_10_interim_discard_notice`, `::test_tc_b100_10_notice_names_every_discarded_entry` (re-pinned) | the interim block kept |
| LLR-166.1 (Inc 10 arm, §C.2) | `test_tc_b100_12_cancelled_question_rehomes_the_focus` | the cancel skips the re-home |
| LLR-167.8 (Inc 10 arm, §C.3) | `test_tc_b100_70_project_load_asks_only_while_the_document_is_unsaved` | Save project skips `mark_saved` |
| LLR-173.7 (Inc 10 arm, §C.4) | `test_tc_b100_66_question_text_holds_no_decision_ids`, `test_tc_b100_45_modal_imports_nothing_from_the_app` | a decision id in the text |
| S-a contract (Q1-6) | `test_tc_b100_45_modal_imports_nothing_from_the_app` | `painted_names` inside the screen |
| AT-B100-15 | `test_at_b100_15_load_over_unsaved_work_asks_one_question_per_route` | the base: Load over a patch asks nothing |
| AT-B100-03 (re-pin) | `tests/test_b100_session_reset.py::test_at_b100_03_project_load_over_unsaved_work_saves_only_p2[size0/size1]` | — |
| TC-B99-40 (re-pin) | `tests/test_b99_editor_image.py::test_tc_b99_40_strip_shows_new_file_source_byte` | — |

**Uncovered requirements:** none in the draft. The table at the end of §4 lists the examples that are not tests.

**Live-guard controls.** A test whose main arms say "0 questions" also makes one request in the same session that must ask. Without that control, a 0-question arm passes on a tree that has no guard at all. These tests carry one: `saved_states` (the unsaved control arm), `attach` (a data load), `project_load_asks_iff` (the D, W and F arms), `patch_editor_load_keeps_its_own_guard` (the data-load arm), `project_load_handler_asks_nothing` (the route arm), `tc_b100_70` (the refused-save arm).

## 2. Re-pinned tests (the E2-rulings census: 5 nodes)

| Node | Reason | What changed (what it proves is kept) |
|---|---|---|
| `tests/test_b100_session_reset.py::test_tc_b100_10_interim_discard_notice` | ruling Q2 removes the `Closed the Patch Editor document (N entries)…` line | asserts 0 closed-document lines and that the loaded-project summary is the freshest line (it was: the interim line is the freshest) |
| `tests/test_b100_session_reset.py::test_tc_b100_10_notice_names_every_discarded_entry` | same | 3 entries → still 0 closed-document lines, and the summary is the freshest line |
| `tests/test_b100_session_reset.py::test_at_b100_03_project_load_over_unsaved_work_saves_only_p2[size0]` and `[size1]` | the P2 load over the unsaved P1 entry and draft now asks (§C.5) | `_open_project_through_dialog` gained an optional `question` list. For the P2 pick it waits for the question, records its body, asserts the body names `Patch Editor entries`, and presses `y`. The two interim-line assertions are deleted (the `_wait_for` on the freshest line and the final `in log_lines` check). Every other assertion stays. The P1 call is unchanged. |
| `tests/test_b99_editor_image.py::test_tc_b99_40_strip_shows_new_file_source_byte` | the Apply on file A leaves D set, so loading B asks (E2 census, new) | `_load_fixture` gained an optional `answer`. The file-B load passes `answer="y"`, waits for the question, and answers it. The strip assertions are unchanged, and the other callers of `_load_fixture` are unchanged. |

`test_tc_b100_10_no_discard_notice_when_nothing_unsaved` is unchanged, as the census says.

## 3. RED on base

- Base `741cc07`; `s19_app.__file__` = `<scratchpad>\base10\s19_app\__init__.py` (the header of the transcript).
- Final run: one complete pytest run of the new file and the 5 re-pinned nodes, on the final test files. Their SHA-256 values are in the transcript header. Result: **57 failed of 57** (52 new nodes + 5 re-pinned), 0 passed, 0 errors, 573 s. The live-guard control now reads `(0 questions, b.s19 loaded, D True)`, so it is RED for the right reason. An earlier complete run, on the file before two test fixes (the missing patch in the live-guard control arm, and a `#files_list` click that would itself select a row), gave 57 failed of 57.
- No collection error. Every failure is behavioural, of one of these kinds:

| Reason | Tests |
|---|---|
| `timed out waiting for the load question`: the base loads with no question | every route test and AT-B100-15; the re-pinned AT-B100-03 ×2 and TC-B99-40 |
| `ImportError: ConfirmQuestionScreen` (the modal is new) | the modal-alone tests: parameters, `y`, `n` / `escape`, `enter`, click, layout ×4, second answer |
| `AttributeError: _load_would_lose` | the 24-cell table |
| `AttributeError: PatchEditorPanel.is_dirty` | the reader-follows-writers test |
| AST census assertion | private `_dirty` read (`app.py:10944`); seam census (6 bypasses: `_route_load_project`, `_handle_select_variant`, `_load_path_from_user_input` ×2, `_load_workarea_file` ×2); the class is missing from `screens.py` |
| session assertion | the change-file dropdown: the dirty pick loads `second.json` (entries 2 → 1, no guard); the work-area kind table: `x.s19` / `x.hex` give 0 questions; the TC-B100-10 re-pins: the interim line is still the freshest line |
| live-guard control | saved states: the unsaved control asks 0 questions |

Where a test reaches a later arm on base, that arm's own behaviour also shows the defect. In the held-A2L probe, the A2L-only refusal leaves `current_file = None` after the reset, which is the negative control of C58.

## 4. Examples not turned into tests

| Example | Why |
|---|---|
| AT keep half "the hex view still shows the patched byte" | On the base the hex view does not repaint the applied bytes after Apply: the probe at 220×60 shows row `0x80000070` still reading `3C`. At 118 columns the column at offset `C` is clipped. The AT reads the kept patch from the session image (`mem_map[0x8000007C] == 0xDE`) and from the painted Loaded panel instead. |
| C37 start-up load asks nothing | Holds on the base and cannot go RED. It is kept by the existing start-up tests. |
| C39, C43 (a file deleted while the question is open) | Declared loss-free design notes. They have no requirement or threshold. |
| C50 (status order), C51 (`_reset_project_session` returns `None`, ruling Q-7), C53 (the E3 R1 line unchanged) | C50 is covered by the TC-B100-10 re-pins (the summary is the freshest line). C51 is an interface ruling with no requirement id. C53 holds on the base and its existing test covers it. |
| P2-1 (the `_dirty` comment text), C1-1 (`styles.tcss` unchanged), C01 (the `QuestionKind` literal set) | These check code text, not behaviour, so they belong to code review. The seam census asserts each leaf calls the seam, which covers C01's use. |
| Q1-5 `screen.title is None` | Weakened to "the title reactive is not the question title". The app may set a screen title of its own, and the risk R-GA10-1 is exactly the question's title landing there. |
| Q5-1 through `_close` | Driven through the fixed-interface `action_answer` twice in one tick instead. That is the same path, and `_close` is not in `interfaces-10.md`. |
| C46 palette arm | `ctrl+p` may not open Textual's palette in this app. The arm then degrades to "no save, no Load dialog pushed", which is still asserted. Whether the palette opened is recorded, not asserted. |

## 5. Design ambiguities met

1. **File name.** The draft's "Executed verification" lines cite `tests/test_b100_confirm.py`; the brief requires `tests/test_b100_load_question.py`. The tests follow the brief, so the draft commands need the path at merge.
2. **`X.MAC` vs `x.mac`.** LLR-174.4c's upper-case arm `X.MAC` cannot sit beside `x.mac` on a case-insensitive volume. The test uses `U.MAC`.
3. **LLR-174.2g key list.** The threshold lists 6 keys; G-A Q1-3 / K4 list 8 (adding `?` and `v`). The test uses 8.
4. **LLR-174.2r body.** The draft (after P-GA10-2) says "each of the three regions"; the G-A examples check the buttons only. The test checks all three regions plus area > 0.
5. **LLR-174.1c census scope.** "a read of `_dirty` on a `PatchEditorPanel` value" cannot be typed by an AST. The test counts every `<x>._dirty` load with `x` other than `self` outside `screens_directionb.py`. That is stricter, since a Flow Builder flag read from outside would also count; there are 0 today.
6. **C07 order spy.** Specified on `ConfirmQuestionScreen.dismiss`. The test instead records the question push and the reset in order, plus whether a question was on the stack at the reset. It is observably equivalent and needs no patch of the new class.
7. **C08 landing.** The design expects `patch_editor_panel` after `n` with a visible Patch Editor `Input` focused before `ctrl+l`. LLR-166.1 keeps a visible Find input in the active window. If the re-home rule treats the patch address input like the Find input, this arm and LLR-166.1 disagree. The test follows the design (C08).
8. **C42 active variant.** That `active_id` stays `firmware_a` after a data pick inside an open project relies on the pick not appending a variant. A base probe confirms this (`active firmware_a`, `variant_id None`).
9. **C55 body.** The design gives the exact AT-B100-03 body. The re-pin asserts only that it contains `Patch Editor entries`, so a later wording change in the composer does not break HLR-165's AT.
10. **LLR-174.2t cancel arm.** The draft threshold says "the entry count and the flag unchanged". A10-R2-3 adds the Select reset. The test asserts `select.is_blank()` after the cancel and that the same pick fires the guard again.

## 6. Environment limits

- `test_tc_b100_46_unreadable_a2l_project_after_yes_keeps_the_work` is Windows only, because it uses an exclusively held file. It is reported `not-run` elsewhere.
- Every run used `env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=.`, with `LOCALAPPDATA` set to a scratch folder. The session guard of `tests/conftest.py` stayed active, and the real `%LOCALAPPDATA%\s19_app` was not touched.
- GREEN against the implementation is `not-run`. Two implementers are still editing, and the full suite waits for the batch-end battery.
