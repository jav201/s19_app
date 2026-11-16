# Inc 8 E4 - test-r (retarget tester)

Base `d5d48685`; retarget commit `da3c7a27` (branch `b103-inc8-tests`). Evidence state of every "GREEN with the Inc 8 code" claim: `not-run` (no implementation in this tree; the integrator runs the 15 files after the merge). RED-on-base transcripts are `executed` (below). Runner `<runner>`, python `s19ci`; `s19_app.__file__` was printed at the top of each transcript (`<scratch>/base/s19_app/__init__.py` for the before set, `<scratch>/tree/s19_app/__init__.py` for the retargeted set).

## 1. Before set: the 15 files at base `d5d48685` (git archive; `-n 2`, `timeout 300`)

| file | result | notes |
|---|---|---|
| test_b100_session_reset | 3 failed, 17 passed | pre-existing: tc_b100_09_domain_matches_the_live_source_census, tc_b100_08_reset_runs_once_before_the_first_install, tc_b100_09_twelve_b_adds_exactly_the_quit_flag (PENDING P-038) |
| test_b101_symbol_reads | 24 passed | |
| test_b102_patch_picker | 17 passed | |
| test_b103_picker_editor | 33 passed | |
| test_b103_picker_model | 44 passed | |
| test_b97_chips_help | 2 failed, 77 passed | pre-existing: tc_b97_32_patch_help_names_every_label, at_b97_14_help_chip_opens_a_body_covering_the_screen[patch]. The retargeted run on the same product had 79 passed: not diagnosed (load or order) |
| test_b97_flow_execution | 1 failed, 71 passed, 3 skipped | pre-existing: tc_b97_23_waiting_card_past_the_viewport_is_brought_into_view[deep-size1]. Run with a one-commit scratch git repo holding `b514b07:styles.tcss`, so the byte-equality arm runs instead of skipping |
| test_b97_patch_editor | 38 passed | |
| test_b97_width | 184 passed | |
| test_tui_directionb | not recorded | see O-1 |
| test_tui_patch_big | 24 passed | |
| test_tui_patch_card | 1 failed, 25 passed | pre-existing: tc080_2_c7_purity_probe |
| test_tui_patch_editor_v2 | 52 passed | |
| test_tui_patch_layout | 9 passed | |
| test_tui_snapshot | 8 failed, 25 passed | pre-existing: 6 a2l cells + patch-comfortable-80x24 and 120x30 (snapshot drift on `<runner>`) |

O-1: the before-set summary line for `test_tui_directionb` was lost in my log extraction (the header grep skipped it); I did not re-run it. The retargeted run shows 2 failed / 182 passed of 184 for that file.

## 2. Retargeted set on the base product (RED evidence, commit `da3c7a27`, full `git archive`)

Expected: every retargeted test goes RED on base for the missing new element, and nothing else moves.

| file | result on base | RED because |
|---|---|---|
| test_b100_session_reset | 6 failed | 3 pre-existing + at_b100_03[x2], tc_b100_10_reset_leaves_the_patch_editor_clean: `#patch_inspector` has no ledger subtitle on base |
| test_b101_symbol_reads | 5 failed | no `patch_tab_script` chip (entry-JSON flows) |
| test_b102_patch_picker | 1 failed | pe_06 shared_grammar: table and full-name line are displayed on base |
| test_b103_picker_editor | 4 failed | r011/1, r011/2, r020/1, r020/2: picker controls are not on the tab the Inspector chip shows |
| test_b103_picker_model | 1 failed | r017_2: picker not reachable through the Inspector chip |
| test_b97_chips_help | 79 passed | TC-B97-32 touched only through `PATCH_TABS`; the loops guard `if panel.query(...)` |
| test_b97_flow_execution | 1 failed (+3 skipped as before) | css_section_is_scoped: the three `supersede(...)` calls find their `before` text exactly once; the final `startswith` assertion fails because base still has the rules |
| test_b97_patch_editor | 4 failed | tab_chips (no script chip), keyboard_order, one_filled_element, at_b97_17 |
| test_b97_width | 10 failed, 135 passed (run alone, `timeout 1500`) | `patch_tab_script` / `#patch_sheet_win` missing: tc_b97_34 painted, tc_b97_37 x6, tc_b97_38 blank x2, at_b97_16 |
| test_tui_directionb | 2 failed, 182 passed | at065a, tc332: title `INSPECTOR` != `LANDS IN` |
| test_tui_patch_big | 1 failed, 23 passed | at075a_titles: `#patch_inspector` title/subtitle on the script tab |
| test_tui_patch_card | 3 failed, 23 passed | at080d x2 (picker buttons are in `patch_win_a2l`, no longer a home) + pre-existing c7 |
| test_tui_patch_editor_v2 | 52 passed | the retargeted helpers are no-ops on base (an absent chip is guarded) |
| test_tui_patch_layout | 6 failed, 3 passed | `#patch_sheet_win`, `patch_tab_script` absent |
| test_tui_snapshot | 6 failed, 25 passed, 2 xfailed | a2l pre-existing; the two patch cells now xfail |

No failure outside the pre-existing set came from an import or syntax error (all 15 files AST-parsed on this PC and imported on `<runner>`).

## 3. Retarget table (file -> node -> old -> new -> requirement)

| file | node | old selector / expectation | new | row |
|---|---|---|---|---|
| test_b102_patch_picker | `A2L_TAB`, `show_a2l_tab` (16 nodes) | `#patch_tab_a2l` | `#patch_tab_inspector` | R-TUI-063.3, R-PE-DEF.3 |
| test_b102_patch_picker | tc_b102_pe_06_shared_grammar_surfaces | table + full-name line displayed | mounted, not displayed; other surfaces displayed | R-PE-DEF.2 |
| test_b102_patch_picker | tc_b102_pe_add_patch_a2l_surfaces_contained | unchanged (hidden widgets drop out of `region.width > 0`) | - | R-PICKER-CORRECT.020 |
| test_b103_picker_editor | `_show_patch_a2l` | `#patch_tab_a2l` | `#patch_tab_inspector` | R-TUI-063.3 |
| test_b103_picker_editor | r020/1, r020/2 | table and full-name in the displayed/contained list | asserted hidden; Use button and status `scroll_visible` before measuring | R-PE-DEF.2, R-PICKER-CORRECT.020 |
| test_b103_picker_model | `_show_panel` | `#patch_tab_a2l` | `#patch_tab_inspector` | R-TUI-063.3 |
| test_b97_chips_help | `PATCH_TABS` only (TC-B97-32, law 2) | inspector, json, checks, a2l | script, inspector, json, checks | R-TUI-063.3 |
| test_b97_flow_execution | css_section_is_scoped (law 3) | - | 3 `supersede(...)` entries `INC8 Inc 8 R-TUI-063.1 / .3 / R-PE-DEF.2`; `startswith` not edited | R-TUI-063.1, .3, R-PE-DEF.2 |
| test_b97_patch_editor | `TABS`, tab_chips_nine_activations | 3 chips, `% 3`, 9 | 4 chips, `% len(TABS)`, `3 * len(TABS)` | R-TUI-063.3 |
| test_b97_patch_editor | `_groups` (TC-B97-41) | ledger group before the chips | `FILTER_ROW` group; ledger group in the script tab | R-TUI-063.1, R-PE-DEF.2 |
| test_b97_patch_editor | HOMES `patch_win_script` (TC-B97-60) | `when` None | `patch_tab_script` | R-TUI-063.3 |
| test_b97_patch_editor | `strip_on_inspector` (new helper), tc_b97_39 x2, tc_b97_40 x2, at_b97_02, at_b97_17 | Inspector shown by default | Inspector chip pressed first, or script chip to read the ledger | R-TUI-063.4 |
| test_b97_patch_editor | PE_IDS_9C7BEAF subset (law 1) | - | no edit | - |
| test_b97_width | tc_b97_35 chip list | inspector, json, checks, a2l | script, inspector, json, checks | R-TUI-063.3 |
| test_b97_width | `_patch_reading`, tc_b97_34 painted | ledger and strip read together | async, each read on its own tab | R-TUI-063.3 |
| test_b97_width | tc_b97_37 | JSON tab only | script then JSON tab, members merged | R-TUI-063.3 |
| test_b97_width | tc_b97_38 no-blank-row (law 4), at_b97_16 | `outside=#patch_main` | `_blank_outside(sheet window, LANDS IN)`; assertion unchanged | R-PE-DEF.1.1 |
| test_b100_session_reset | 4 subtitle reads, entry-form click | `#patch_win_script` subtitle; form on the default tab | `#patch_inspector`; Inspector chip first | R-PE-041, R-TUI-063.4 |
| test_b101_symbol_reads | `entry_json_confirm` | one tab | select row on the script tab, click Edit JSON on the Inspector tab | R-TUI-063.3 |
| test_tui_patch_big | at075a | titles PATCH SCRIPT / CHECKS / JSON | `LANDS IN` on `#patch_inspector`; script chip pressed before the post-add subtitle read | R-TUI-063.6, R-PE-041 |
| test_tui_patch_card | `_BUTTON_HOMES`, `_open_patch` | `patch_win_a2l`; Inspector default | `patch_filter_row`; Inspector chip pressed | R-TUI-063.3, R-PE-DEF.2 |
| test_tui_patch_editor_v2 | `_click`, `_click_entry_json` | scroll `#patch_win_script` | script chip in the tab map; Inspector chip + scroll `#patch_pane_inspector` | R-TUI-063.3 |
| test_tui_directionb | `PATCH_DOC_SECTION_TITLE`, label reader | `PATCH SCRIPT` on `#patch_win_script` | `LANDS IN` on `#patch_inspector` | R-TUI-063.6, .7 |
| test_tui_patch_layout | `_COLUMN_IDS`, `_assert_two_columns` | side by side | sheet above landing pane, same x | R-TUI-063.1, .2 |
| test_tui_patch_layout | `_BUTTON_HOMES`, `_TAB_FOR_HOME`, tc46_1 titles | a2l home; per-tab titles | filter row; script tab; `LANDS IN` x3 | R-TUI-063.3, .6, R-PE-DEF.2 |
| test_tui_snapshot | `_batch103_inc8_patch_drift_marks` | - | `xfail(strict=False)` on the 2 patch cells until the canonical-CI regen (HT-09); SVGs untouched | R-TUI-063.1 |

Untouched on purpose: TC-B97-59 (law 5), `tests/b97_fixtures.py` (E3A-08), both snapshot SVGs (law 6).

## 4. Assertion-removal check

`git diff -U0 d5d48685 -- tests | grep '^-.*assert'` gave 8 removed assert lines, each replaced by an equivalent on the new place: `len(results) == 9` -> `3 * len(TABS)` (R-TUI-063.3); `reached == {...}` -> same plus `script` (R-TUI-063.3); three title asserts -> `LANDS IN` (R-TUI-063.6); `lx < ix and ly == iy` -> sheet above landing pane (R-TUI-063.1/.2); two title asserts of tc46_1 -> one dict equality (R-TUI-063.6). No assertion deleted without a replacement; no assertion of the six laws edited. 0 CR in the diff. The tree also holds other testers' new files; the diff stat for my 15 files is in `git show --stat da3c7a27`.

## 5. Ruling requests and open items (nothing deleted; each test stays in place)

- RR-1 `test_tc_b97_02_ledger_grows_with_the_panel` (height >= 7) and `test_at_b97_01` (all 6 rows paint) vs R-PE-DEF.1.1 (landing pane 9 rows, ledger scrolls inside it). Cannot pass by requirement; needs a ruling on the new bound. Same class: tc_b97_37 `len(set(rows[1:7])) == 6`.
- RR-2 `test_tc_b97_40_*`: `_CHIPS_BELOW_FOLD`, `pane.contains_region` and the 2-row spacing against a 6-content-row Inspector pane (E3A-09). The numbers are measurements; re-measure at integration (not hand-counted).
- RR-3 `test_at064b`: `script_rows_at_scroll0` lists `patch_doc_entry_buttons`, which is in the Inspector pane now (hidden on the default tab).
- RR-4 `test_tc_b102_pe_02`, `test_r011_*` (/1, /3): `space` / `enter` pressed on the picker table, which R-PE-DEF.2 hides. Whether a hidden table still takes focus is unverified (E5 pilot). If not, the toggle moves to the Include button.
- RR-5 flow-execution supersessions: the texts assume the implementer deleted whole rules (`#patch_main`, the two `#patch_win_a2l` rules) and dropped `#patch_win_a2l` from the height selector list. I did not see the implementers' CSS. Any other in-place edit of a b514b07 rule (`#patch_win_script`, `#patch_inspector`, focus-within, `#patch_param_table`) needs its own `supersede` entry. The integrator replaces `INC8` with the merge sha and reconciles each `after`.
- O-2 TC-B97-04 `("#patch_win_script", "width", "2fr")` absent: unaffected unless the new CSS sets it.
- O-3 Not audited line by line: `test_tui_directionb.py` (9,347 lines) and `test_tui_patch_editor_v2.py` (4,105 lines) beyond a grep for the layout ids; other patch tests there may assume the Inspector default tab.
- Deviation: one scratch file was written under `/tmp` on `<runner>` (HT-06) and removed in the same command. The first retargeted run (incomplete tarball) was contaminated and discarded; the numbers above are from the `git archive` re-run.
