# Inc 7 — black-box acceptance cases (keys and dialogs, across G-L and G-V)

Format: `roles/tester.md`. Each AT drives the real app headless through keys and the terminal paste message on case 08 (`tools/synth/make_release_case.py --seed 20260001`, `firmware.s19` then `firmware.a2l`), at 118×54 unless named; the expected values come from `01-requirements.md` and the P1/P2 transcripts (`evidence-e1/`), computed in the test, never retyped. Planned file: `tests/test_b103_a2l_list_at.py`. No clipboard is read or written: the paste is posted as the terminal's paste message (I-1's test seam for Ctrl+V and right-click is G-L's).

| Case | Example | Test name | Coverage | Verifies |
|---|---|---|---|---|
| AT-B103-I7-1/1 | the G2 list posted as a paste into `#a2l_tags_filter_input` | `test_at_b103_i7_1_list_mode_from_paste` | full | R-A2L-LIST.006, .007, .009, .011, .012, .016, .017, .022, .033 |
| AT-B103-I7-1/2 | then ↓ ↓ enter in the table | `test_at_b103_i7_1_jump_from_list` | full | R-A2L-LIST.031 (`Tag at 0x00804FD0`) |
| AT-B103-I7-1/3 | then Esc in the filter box | `test_at_b103_i7_1_esc_back_to_text` | full | R-A2L-LIST.032, .008 (462 rows) |
| AT-B103-I7-2/1 | alt+p, the G2 list pasted into the text area | `test_at_b103_i7_2_window_live_status` | full | R-A2L-LIST.040, .042, .046–.050 |
| AT-B103-I7-2/2 | `0042 val` on the add line, enter | `test_at_b103_i7_2_add_from_dropdown` | full | R-A2L-LIST.061, .057 (13 names) |
| AT-B103-I7-2/3 | alt+f | `test_at_b103_i7_2_apply_to_viewer` | full | R-A2L-LIST.053 (13 rows, list mode) |
| AT-B103-I7-3/1 | `cuvre_00` typed in the filter box | `test_at_b103_i7_3_dropdown_typo` | full | R-A2L-LIST.060, .063–.065 (`8 of 20+ similar names`) |
| AT-B103-I7-3/2 | ↓ tab | `test_at_b103_i7_3_tab_completes` | full | R-A2L-LIST.068, .069 (box `CURVE_0002`, 1 row) |
| AT-B103-I7-4/1 | the G2 list applied, jump to #3, at 118×54 | `test_at_b103_i7_4_layout_118` | full | R-A2L-LIST.080 (every hex row whole) |
| AT-B103-I7-4/2 | the same at 220×60 | `test_at_b103_i7_4_layout_220` | full | R-A2L-LIST.081, R-TUI-069.6 |

10 cases over 4 acceptance tests. Keys that only a real Windows Terminal can prove (alt+p, alt+f, alt+a delivery): the pilot P-1 of `E1-rulings.md` D-11, not these headless cases.
