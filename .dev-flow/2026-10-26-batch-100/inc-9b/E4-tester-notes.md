# Inc 9b — E4 tester notes (the unified Load dialog)

Independent tester, stage E4. The tests were written from the design only: `E1-requirements-draft.md`, `E1-scope.md`, `codewire/interfaces-9b.md`, `codewire/proto-9b-dialog.md`, `codewire/proto-9b-app.md`, `E1-rulings.md`, `E2-rulings.md` and `E3-rulings.md` (the round-3 T rows). No line of the implementers' in-progress code was read or run.

Evidence states use the seven words of `/dev-flow`. Nothing here is `approved`: approval belongs to the reviewers.

## 1 · What was written

| File | What | Items |
|---|---|---|
| `tests/test_b100_load_dialog.py` (new) | TC-B100-40, -41, -42, -43, -63, -64, -66 and AT-B100-14. 75 functions. | 133 |
| `tests/support/b100_load_dialog.py` (new) | Drivers and readers of the one Load dialog. Every 9b symbol is imported lazily, so each file collects on the base revision. | — |
| `tests/test_b100_recents.py` (4 new functions) | TC-B100-34: LLR-172.1n, 3 functions (the junction arm with control arm 4, the base-only arm with control arm 3, the A2L arm B30 / F-6). TC-B100-37: the widened census plus the runtime spy at dialog open. | 4 |
| `tests/test_b100_focus.py` (2 new functions) | TC-B100-12 Inc 9b arms (A9b-03): `escape` and a cancelled load, starting from a stale input and from the P-16 shape. | 4 |

**Total new: 141 test items.** Re-pins are in §3.

## 2 · Requirement → test map

All tests are in `tests/test_b100_load_dialog.py` unless another file is named. `[n]` is the number of parametrized items.

| Requirement | Tests |
|---|---|
| HLR-173 | `test_tc_b100_43_sections_hold_the_projects_files_and_recents`, `test_tc_b100_42_project_rows_are_painted_literally[markup bold]` (`[b]P`), `test_tc_b100_64_panes_stack_below_100_columns[3]`, `test_at_b100_14_one_load_dialog_from_record_to_reopen` |
| HLR-173a | `test_tc_b100_64_project_preview_marks_equal_the_install[4]`, `test_tc_b100_64_file_row_preview_marks_what_the_session_keeps[4]`, `test_tc_b100_41_preview_follows_the_load_target`, `test_tc_b100_41_printable_key_clears_the_preview`, AT-B100-14 step 4 |
| HLR-173b | `test_tc_b100_40_recent_choice_loads_the_recorded_text_unchanged`, `test_tc_b100_43_missing_recent_is_explained_inside_the_dialog`, AT-B100-14 step 2 |
| HLR-173c | `test_tc_b100_41_load_with_the_list_last_takes_the_highlighted_row[9]`, `test_tc_b100_41_load_with_the_path_last_takes_the_typed_text[3]`, AT-B100-14 step 2 |
| HLR-173d | `test_tc_b100_41_empty_or_spaces_text_is_explained[2]`, all `test_tc_b100_63_*`, AT-B100-14 step 6 |
| HLR-173e | `test_tc_b100_41_escape_closes_with_no_result_from_every_focus`, AT-B100-14 step 5 |
| LLR-173.1 | `test_tc_b100_40_load_choice_is_a_frozen_value_of_four_kinds`, `test_tc_b100_40_dialog_dismisses_a_load_choice_per_kind_or_none`, `test_tc_b100_40_retired_load_screens_are_gone` |
| LLR-173.1a (+ LLR-178.3) | `test_tc_b100_40_project_choice_opens_the_load_result_panel` |
| LLR-173.1b | `test_tc_b100_40_workarea_data_choice_loads_in_place_with_no_copy`, `test_tc_b100_40_workarea_a2l_choice_equals_the_files_list_pick` |
| LLR-173.1c | `test_tc_b100_40_path_choice_takes_the_typed_route` |
| LLR-173.1e | `test_tc_b100_40_one_router_receives_every_dialog_result` |
| LLR-173.1f | `test_tc_b100_40_recent_choice_loads_the_recorded_text_unchanged` |
| LLR-173.1g | `test_tc_b100_40_unreadable_picked_project_paints_one_status_line` |
| LLR-173.2 | `test_tc_b100_41_l_and_ctrl_l_open_the_dialog_on_the_path_field` |
| LLR-173.2a | `test_tc_b100_41_p_and_the_button_open_the_dialog_on_the_list` |
| LLR-173.2b | `test_tc_b100_41_list_opens_on_the_open_project`, `test_tc_b100_41_open_project_highlight_falls_back_to_the_first_project` |
| LLR-173.2c | `test_tc_b100_41_tab_order_wraps_both_ways` |
| LLR-173.2d | `test_tc_b100_41_printable_key_in_the_list_types_into_the_path_field[6]`, `test_tc_b100_41_navigation_keys_in_the_list_are_not_redirected` |
| LLR-173.2e (S9b-1) | `test_tc_b100_41_priority_keys_are_inert_while_the_dialog_is_open` |
| LLR-173.2f | `test_tc_b100_41_load_with_the_list_last_takes_the_highlighted_row[9]`, `test_tc_b100_41_text_in_the_field_then_tab_into_the_list_loads_the_row` |
| LLR-173.2g (A9b-01) | `test_tc_b100_41_load_with_the_path_last_takes_the_typed_text[3]`, `test_tc_b100_41_alt_l_with_the_focus_on_the_path_field_loads_and_types_nothing` |
| LLR-173.2h | `test_tc_b100_41_empty_or_spaces_text_is_explained[2]` |
| LLR-173.2i | `test_tc_b100_41_no_loadable_row_highlighted_is_explained` |
| LLR-173.2j | `test_tc_b100_41_click_highlights_and_never_loads` |
| LLR-173.2k | `test_tc_b100_41_escape_closes_with_no_result_from_every_focus` |
| LLR-173.2l | `test_tc_b100_41_cancel_closes_with_no_result` |
| A9b-02 / A9b-06a / A9b-06b / A9b-R2-2 | `test_tc_b100_41_double_enter_dismisses_once`, `test_tc_b100_41_type_ahead_c_then_enter_loads_the_typed_text`, `test_tc_b100_41_type_ahead_escape_then_enter_closes_with_none`, `test_tc_b100_41_printable_key_clears_the_preview` |
| LLR-173.3 | `test_tc_b100_42_project_rows_are_painted_literally[4]` |
| LLR-173.3a | `test_tc_b100_42_work_area_file_rows_are_painted_literally[7]` |
| LLR-173.3b | `test_tc_b100_42_recent_rows_are_painted_literally[3]` |
| LLR-173.3c | `test_tc_b100_42_preview_names_are_painted_literally` |
| LLR-173.3d | `test_tc_b100_42_a_pick_loads_the_on_disk_name` |
| LLR-173.4 / LLR-173.4l | `test_tc_b100_43_sections_hold_the_projects_files_and_recents` (Windows: junction) |
| LLR-173.4a | `test_tc_b100_43_a_folder_that_is_not_a_project_is_not_listed[5]`; typed `<W>/e` in `test_tc_b100_63_typed_folder_that_is_not_a_project_is_explained[empty folder]` |
| LLR-173.4b | `test_tc_b100_43_files_section_is_the_one_lister_filtered_to_loadable_files`; `tests/test_b100_recents.py::test_tc_b100_37_widened_census_and_one_enumeration_at_dialog_open` |
| LLR-173.4c | `test_tc_b100_43_recents_section_is_the_store_read_in_order[3]` |
| LLR-173.4d | `test_tc_b100_43_empty_projects_section_paints_its_tokens` |
| LLR-173.4e | `test_tc_b100_43_empty_files_section_paints_its_tokens[2]` |
| LLR-173.4f | `test_tc_b100_43_empty_recents_section_paints_its_token[2]` |
| LLR-173.4g | `test_tc_b100_43_store_problem_is_painted_in_the_recents_section[2]` |
| LLR-173.4h | `test_tc_b100_43_recent_row_shows_the_file_name_and_kind_only` |
| LLR-173.4i | `test_tc_b100_43_recent_preview_shows_the_store_facts_only` |
| LLR-173.4j | `test_tc_b100_43_no_filesystem_call_touches_a_recent_before_load` |
| LLR-173.4k | `test_tc_b100_43_missing_recent_is_explained_inside_the_dialog` |
| LLR-173.4m | `test_tc_b100_43_unreadable_project_list_says_so` |
| LLR-173.4n | `test_tc_b100_64_linked_file_in_a_project_is_neither_listed_nor_installed` |
| LLR-173.5 … LLR-173.5e | `test_tc_b100_63_typed_path_not_found_is_explained[2]`, `…_unsupported_file_…[3]`, `…_folder_that_is_not_a_project_…[4]`, `…_outside_the_work_area_…[2]`, `…_through_a_junction_…[2]`, `…_cannot_be_read_…[2]` |
| S9b-4 / S9b-7 (R3-2) | `test_tc_b100_63_pasted_nul_is_not_inserted`, `test_tc_b100_63_folder_named_like_a_data_file` |
| LLR-173.6 | `test_tc_b100_64_project_preview_marks_equal_the_install[4]` |
| LLR-173.6a | `test_tc_b100_64_a_load_that_installs_another_variant_names_it` |
| LLR-173.6b | `test_tc_b100_64_file_row_preview_marks_what_the_session_keeps[4]` |
| LLR-173.6c | `test_tc_b100_64_open_project_note_on_a_data_file_row` |
| LLR-173.6d | `test_tc_b100_64_project_preview_lists_every_variant` |
| LLR-173.6f (R3-1) | `test_tc_b100_64_project_preview_states_the_manifest[3]` |
| LLR-173.6k | `test_tc_b100_64_project_preview_read_error_says_so[2]` |
| LLR-173.6l | `test_tc_b100_64_the_dialog_reads_nothing_itself` |
| LLR-173.6m | `test_tc_b100_64_panes_stack_below_100_columns[3]`, `test_tc_b100_64_panes_restack_on_a_live_resize` |
| LLR-173.6n | `test_tc_b100_64_list_rows_never_wrap[3]` |
| S9b-2 / R2-N5 / R3-1, S9b-8, B78 (A9b-R3-5) | `test_tc_b100_64_project_json_that_is_not_a_regular_file_is_refused`, `test_tc_b100_64_preview_line_never_wraps`, `test_tc_b100_64_more_than_one_mac_marks_nothing` |
| LLR-173.7 | `test_tc_b100_66_painted_text_carries_no_decision_id` |
| LLR-172.1n | `tests/test_b100_recents.py::test_tc_b100_34_source_found_through_a_junction_fallback_is_not_recorded`, `…_source_found_only_in_the_base_folder_is_not_recorded`, `…_a2l_found_only_through_the_fallback_is_not_recorded` |
| LLR-166.1 (9b arms) | `tests/test_b100_focus.py::test_tc_b100_12_load_dialog_close_rehomes_a_stale_input_focus[2]`, `…_load_dialog_close_from_the_p16_shape_lands_on_the_target[2]` |

**Uncovered requirements: none.** Every in-scope id has at least one arm. The arms that are platform-dependent are listed in §6.

## 3 · Re-pinned tests

The re-pins are mechanical: rulings Q9 (both screens deleted), Q7 / F-1 (an empty folder is not a project), A9b-08 (LLR-173.1d retired) and A9b-R3-1. Each test keeps what it proves and changes only how it reaches the dialog:
- `#project_list` → `#load_list` (arrow keys or a row click);
- `#project_ok` / `#project_cancel` → `#load_ok` / `#load_cancel`;
- `isinstance(…, LoadFileScreen|LoadProjectScreen)` → `is_load_dialog`;
- `push_screen(LoadFileScreen())` → `push_screen(bare_path_dialog())`.

| File | Re-pinned (function or driver) | Reason |
|---|---|---|
| `tests/test_b100_active_variant.py` | the `_handle_load_dialog(src)` call (TC-B100-19/20 scene) → `LoadChoice("path", str(src))`; drivers `_load_file_through_dialog`, `_load_through_dialog_until`, `_open_project_through_dialog` (AT-B100-06, AT-B100-20) | A9b-08; Q9 |
| `tests/test_b100_announce.py`, `test_b100_document.py`, `test_b100_project_check.py`, `test_b100_save_guards.py`, `test_b100_save_image.py`, `test_b100_session_reset.py`, `test_b100_reuse.py`, `test_b99_crc_region.py`, `test_b99_export.py`, `test_b99_staging.py` | the project and file dialog drivers (row → arrow-key highlight + `#load_ok`; screen class → `is_load_dialog`). In `test_b99_export.py`, two class-name checks are now `is_load_dialog`. | Q9 |
| `tests/test_b99_truncation.py`, `test_b99_patch_truth.py` | project pick by `click_row` + `#load_ok` (their comments name a click); `patch_truth` first checks the row is listed (`section_prompts`) | Q9 |
| `tests/test_b100_focus.py` | `_assert_p_opens_the_project_dialog` (`#load_cancel`); `test_tc_b100_12_split_join_window_target_is_its_table`, `…_modal_keeps_its_focus_while_a_load_finishes`, `…_bad_default_focus_is_rehomed_behind_a_modal` (`is_load_dialog`); `_open_project_and_wait_for_the_panel`, `_load_file_through_dialog` | Q9 |
| `tests/test_b100_project_homes.py` | `_at_open_project`, `_at_load_file`; `_at_listed_projects` → `section_prompts(screen, "Projects")`; `test_tc_b100_32_empty_folder_is_refused_before_any_reset[no project.json]` → `is not a project` / `pick a project in the list` | Q9; F-1 (LLR-171.2e retired) |
| `tests/test_b100_recents.py` | `_at_load_file` (`is_load_dialog`); `test_tc_b100_38_unreadable_folder_paints_could_not_be_read`: the arm id changes from `route: validate_project_files` to `route: _list_project_files`, and it now patches `S19TuiApp._list_project_files` | Q9; A9b-R3-1 |
| `tests/test_b97_load_project_dialog.py` | opens with `action_load_project`, highlights `proj_b` with the arrows, clicks `#load_ok`; the final check reads `"LoadDialog"` | Q9 |
| `tests/test_b99_load_project.py` | `_project_list_names` → Projects section. `test_tc_b99_35_reserved_homes_are_not_projects`: P1, P2 and the reserved `patches` home each get a `.s19`, so it is the reserved-name rule (not emptiness) that keeps `patches` off the list. AT-B99-13: the three pick paths (down + `#load_ok`; `click_row` P2 + `#load_ok`; down, two tabs to `#load_ok` asserted, `enter`). AT-B99-13 empty boundary: the dialog opens with the disabled `no projects` line; Load paints `nothing selected`; `escape`; the file stays loaded. | Q9; Q7; LLR-173.2a / .2i |
| `tests/test_tui_app.py` | `test_list_projects_skips_files_and_sorts_names` (each folder gets a `project.json`); `test_handle_load_dialog_defers_load_until_after_modal_dismiss` → `LoadChoice("path", …)`. The `None` test is unchanged (it never passed a bare `Path`). | Q7; A9b-08 |
| `tests/test_tui_helpers.py` | `test_list_projects_ignores_temp` (each folder gets a `project.json`) | Q7 |
| `tests/test_tui_directionb.py` | the TC-033 modal tables (`_MODAL_SPECS`, `_build_modal`, the DEFAULT_CSS census, the render test) now build `LoadDialog` in path mode and in list mode; `test_ac7_workspace_load_project_button` uses `is_load_dialog`, and its `demo_project` gets a `project.json` | Q9; Q7 |
| `tests/test_loadfilescreen_input.py` (11 push sites), `tests/test_clipboard_tk_singleton.py` | `push_screen(bare_path_dialog())`; reworded docstrings and messages; test names kept | Q9 |

The census after the re-pins: `grep -rnE "LoadFileScreen|LoadProjectScreen|project_list|project_ok|project_cancel" tests` hits only history text:
- the support module's docstring;
- the CW-U-1 history line in `test_b97_load_project_dialog.py`;
- the `list_projects` test names `test_tc_b100_38_project_list_*`;
- the helper name `_project_list_names`.

## 4 · RED on base

- **Base:** `8947666` (scratch worktree `base9b`; 0 modified files under `s19_app/`).
- **How:** the test files were copied in. `s19_app.__file__` is printed in the header and points into `base9b`.
- **Transcript:** `.dev-flow/2026-10-26-batch-100/evidence/inc-9b/red-01-vs-base.txt`.

One complete run: started `2026-10-31T16:20:38-06:00`, finished `16:43:20`. Each count below is read from that run's own output.

| Part | Command scope | Result | State |
|---|---|---|---|
| 1 | `tests/test_b100_load_dialog.py` (every test) | **133 failed**, 0 passed, 0 skipped (21 min 17 s) | `failed` on base, as required |
| 2 | the 4 new functions in `tests/test_b100_recents.py` | **4 failed** | `failed` on base, as required |
| 3 | the 2 new functions in `tests/test_b100_focus.py` (4 items) | **4 failed** | `failed` on base, as required |
| 4 | a sample of 13 re-pinned items (not the whole re-pin set) | 6 failed, 7 passed | `executed` (a re-pin need not be RED; see below) |

**RED count: 141 of 141 new items fail on base.** None errored at collection, and none skipped. Every RED is behavioural (an assertion, or the import or attribute of a symbol the 9b design adds); none comes from a typo or a collection error. The reasons, counted from the transcript's `--tb=line` lines:

| Reason | Items | Why it is the right RED |
|---|---|---|
| `AssertionError: timed out waiting for the Load dialog` | 86 + 4 (focus) | The key (`l`, `p`, `ctrl+l`, the button) opens the base's `LoadFileScreen` / `LoadProjectScreen`, which is not the one Load dialog. Base facts: no list (P-20); `escape` ignored (P-18); an empty Load says nothing (P-19). |
| `ImportError: cannot import name 'LoadDialog'` | 35 | The dialog-level tests push the new dialog. Its class does not exist before 9b. |
| `ImportError: cannot import name 'LoadChoice'` | 7 | The one result type does not exist (the base dismisses a `Path` or a `str`). |
| `AttributeError: ... has no attribute '_list_project_files'` | 2 | The link-safe lister (R2-N2) is new; LLR-173.1g and LLR-173.6k inject there. |
| `AssertionError: assert not True` (retired screens) | 1 | `LoadFileScreen` still exists. |
| `AssertionError: []` (router census) | 1 | 0 push sites construct `LoadDialog` (LLR-173.1e). |
| `AssertionError: screens.py defines no LoadDialog class` | 1 | The LLR-173.6l census has no class to read. |
| `AssertionError: [(<B or R path>, 's19'), ('C:\seed\s.s19', 's19')]` | 3 | LLR-172.1n. The store gained the source found through the fallback. In the junction arm that is `R\x.s19`, the link followed, which is the executed CR9-1 probe's result. |
| `AssertionError: l did not open the Load dialog` | 1 | The widened TC-B100-37 spy arm sees no Load dialog. Its census arm holds on the base (declared, §7). |

Part 4 (sample of re-pins).
- **RED for the expected reason:**
  - `test_handle_load_dialog_defers_load_until_after_modal_dismiss` (`ImportError` of `LoadChoice`);
  - TC-B100-32 `[no project.json]` (the base still paints the retired `has no project.json` line);
  - TC-B100-38 `[route: _list_project_files]` (`AttributeError`);
  - `test_b97_load_project_dialog` and `test_ac7_workspace_load_project_button` (no Load dialog);
  - `test_loadfilescreen_auto_focus_lands_on_input` (`ImportError` of `LoadDialog`).
- **Pass on base, as expected.** These 7 re-pins only add content to folders or keep unchanged arms: the two `list_projects` tests, TC-B99-35, TC-B100-32 `[no data or A2L file]` and three TC-B100-38 arms.
- The full re-pinned modules were not run (operator override); their state is `not-run`.

Cosmetic: the Part 4 header line holds one mis-encoded dash byte (the run script's echo). It does not touch any result line.

## 5 · Oracle control (not the RED evidence; recorded for the reviewers)

Some tests could be wrong about Textual's mechanics, so I checked them against a throwaway reference: my own reading of the G-A graph and a reduced G-B, applied to a scratch copy of the base (`scratchpad/e4tester9b/refcheck`, never shipped, never shown to the implementers). The reference is not evidence that the product passes. It only shows that each test can pass against a design-conforming dialog and that it fails on its mutant.
- **Dialog-level tests:** 37 of 37 passed.
- **App-level tests:** 91 of 94 passed. Of the 3 that failed:
  - **2 defective tests, repaired.** The A2L twin's `temp/` name set counted the private `.staging` home. The button arm clicked `#ws_load_project_button` in a bare session, where it is hidden; it now loads a file first, as AT-B99-13 does.
  - **1 failure in my reference**, not in the test: S9b-7 (a folder named `ab.s19`).
- **New `test_b100_focus.py` arms and the widened census:** passed (5).
- **LLR-172.1n arms:** RED without the CR9-1 condition (the store gained `R\x.s19`, the executed probe's result), then GREEN with it (3 of 3).
- **Mutants killed (9 of 9):**
  - `alt+l` without `priority=True` (field becomes `…a.s19l`);
  - `_close` without the `_dismissed` guard (`ScreenStackError`);
  - `_source` set only on focus (dismisses the row);
  - Escape handled only as a binding (Enter loads `ab`);
  - no `restrict=` (NUL kept);
  - loading on `OptionSelected`;
  - an unfocusable preview;
  - highlight always at row 0;
  - no preview clear on the redirect.

## 6 · Examples not turned into tests, and limits

| Example | Why not |
|---|---|
| B03 (identity of the 3 bound methods), B57 / B94 (census of `_TYPED_REFUSAL_TOKENS` / `_RECENT_PROBLEM_STEPS`), B93 (decision-id scan of those constants) | Design-internal names that the fixed interface does not freeze. The behaviour is covered: LLR-173.6l census, the 6 painted refusal pairs, the TC-B100-66 scan of painted refusals. |
| B77 (over-cap A2L left unmarked), B100 (S9b-5: a project renamed between open and Enter, name painted scrubbed), B88 / F-11 (deleted work-area file loads silently), B95 (verdict and route race) | B77 is a boundary of HLR-173a with no threshold of its own. B100 and B95 need a timed race between dialog open and Enter. B88 is a declared pre-existing behaviour with no requirement. |
| C1-1, C1-2, C1-3, C2-2, C4-3, C4-4 (box geometry, Save dialog width, border colours, `#load_reason` fully visible) | Styling with no requirement threshold. The layout requirements LLR-173.6m and LLR-173.6n are tested. |
| B08 (`LC("project","AB")` case match) | Its own note says such a value can only come from a test. LLR-172.5g's arm is in 9a. |

Platform and environment limits:
- **Windows only.** These arms are reported `not-run`, never passed, elsewhere:
  - the junction arms: `test_tc_b100_43_sections_hold_the_projects_files_and_recents`, `test_tc_b100_63_typed_path_through_a_junction_is_explained[2]`, the LLR-172.1n junction arm;
  - `[TEMP]`;
  - the store-write arms (`STORE_WRITE`: LLR-172.1f needs a drive-rooted `LOCALAPPDATA`): AT-B100-14, TC-B100-66, LLR-173.1f, LLR-173.4k and the 3 LLR-172.1n functions.
- **Volume-dependent.** The U+009B and surrogate names skip with a named reason where the volume refuses them. The file-symlink arms (LLR-173.4n, S9b-2) skip where `os.symlink` raises (R3-3); a symlink could be made in this run. S9b-2 uses a FIFO off Windows and a symlink named `project.json` on Windows.
- **Not run here.** The full suite and the whole re-pinned modules were not run (operator override 2026-10-31: batch-end battery). GREEN against the implementation was not run: the implementers were still editing.

## 7 · Design ambiguities met

1. **LLR-173.1g injection point.** The threshold says "`PermissionError` injected into `validate_project_files`". R2-N2 moved the project listing to `_list_project_files`, and B96 injects there. The test follows B96.
2. **LLR-173.4i "full recorded path" against S9b-8.** S9b-8 makes preview lines nowrap with an ellipsis, so a long path is painted clipped. The test reads the preview's content text (full), not the painted strip. The requirement text should say which one is meant.
3. **B14 against `_focus_needs_rehome`.**
   - B14 starts from a focused `search_input`. With a file loaded, a visible Find input is healthy and keeps its focus: `test_tc_b100_12_visible_find_input_keeps_its_focus`, a 9a/Inc 6 arm.
   - So a correct router would not move it, and B14 as written cannot pass.
   - The 9b arms start from a stale input (the hidden A2L Find field) and from the P-16 shape (the hidden Split / Join table). Both shapes make the re-home observable.
4. **Wording the requirements leave open, which the tests tolerate:**
   - the recent row (`fw.s19 (s19)` in G-B; requirement: the file name, then the kind) is matched by regex;
   - preview lines: the file name is the last word of a marked line; the manifest state is a token in an unmarked line holding "project";
   - the project-open note: an unmarked line holding "active variant" and the painted project name. This note's wording is the G-B design's, and the test depends on it.
5. **`.staging` in "the set of names in `temp/` unchanged"** (LLR-173.1b). The A2L arm's identical-file reuse goes through the copy step, which may create the private `.staging` home. The test compares file names and leaves `.staging` out.
6. **LLR-173.2e `ctrl+k` / `ctrl+d` (R-GA-3 / F-4).** The keys run no app action, but they still edit `#load_path`. The test checks only "no app action, focus stays in the dialog".
7. **TC-B100-66 "refusal-token constants".** The constant names are design-internal. The test scans the painted refusals instead.
8. **Declared non-RED arms (by design):**
   - the "0 app actions" arm of LLR-173.2d (a modal already blocks non-priority app keys);
   - LLR-173.6a's panel arm (Inc 7 behaviour);
   - the census arm of the widened TC-B100-37 (holds on the base).

   These are RED only as mutations. On the base each of these tests is still RED, through its other arm or because no dialog exists.
9. **Fixture text.** `_COLLIDING_PATH` in `tests/test_loadfilescreen_input.py` (pre-existing) contains a Windows user name. It was left as is, because it is outside the re-pin scope; the backlog can replace it with `username_subject`.

## 8 · Evidence checklist

- [x] Every test named exists on disk at the cited path and function name (collected: 133 + 4 + 4 items).
- [x] Each result is read from ONE complete run's own output, with the command quoted in the transcript header (`red-01-vs-base.txt`).
- [x] RED on base captured, base `8947666` named, `s19_app.__file__` printed.
- [x] Each test asserts an observable outcome: screen stack, focus id, painted text, dismiss value, session, Loaded panel, store bytes, status log.
- [x] No uncovered requirement; the examples not turned into tests are named in §6.
- [x] Environment limits declared (§6).
- [x] No real PII, credentials or client data in the new fixtures. The pre-existing `_COLLIDING_PATH` is noted in §7.
- [x] Only the seven evidence states are used.
