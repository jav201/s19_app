# Inc 10a E4 tester H (hex navigation) - notes

Node file: `tests/test_b101_hex_jump.py`, 39 test functions, 41 collected nodes (one parametrised over `main`, `a2l`, `mac`). No product file touched.
RED run: base `e07fb00f9fc13afd314d0334fac683fe33b29b6c` + Inc 9 diff (ff678242), LAN Linux host, detached worktree `s19_i10h`, `s19_app.__file__` resolved inside the worktree. Command: `env -u NO_COLOR python -m pytest -q -p no:cacheprovider -rfs tests/test_b101_hex_jump.py -n 3 --dist load` (see deviation 1). Transcript (redacted, one complete run): `.dev-flow/2026-11-01-batch-101/evidence/inc-10/red-01-tester-h-base.txt`. Summary: **36 failed, 4 passed, 1 skipped in 317.70s**. State: `executed` on base. GREEN on the integrated tree: `not-run` (implementers still editing). No `serial_timing` node.
Guards run with the file in place (same worktree, `-p no:xdist`): `tests/test_address_census.py` and `tests/test_suite_hygiene.py` pass (101 passed); `tests/test_id_registry.py::test_tc607_scanned_corpus_matches_the_declared_bound` fails 270 vs 269 only because of this file (expected; the integrator re-measures with tester F's file too).

## How the nodes read and drive
- Drive = keys, buttons and tables: rail keys `1` `2` `3` `4`; `g` / `/` then the text, Tab, Enter; the tag-find box then Tab, Enter; `.` `,` `+`; Enter on the Data Sections list and on a MAC table row (cursor placed with `move_cursor`); a real double click on a Memory Map region row (`_double_click_region_row` of `tests/test_tui_directionb.py`). Loading uses `app.load_selected_file` / `load_a2l_from_path` and `settle_workers`, as the other Inc 13/14 files do; the page size 3 goes through `_apply_viewer_setting` (the settings menu's own handler; 3 is not a menu option).
- Oracles = what is painted: the plain text of `#hex_view`, `#alt_hex_view`, `#mac_hex_view` (hex row = line starting `> ` or two spaces + `0x`), scroll offsets and regions of the scroll containers, and `StatusLog.since(mark)`. The marker address fields (`_goto_focus_address`, `_alt_...`, `_mac_...`) are read only in R-TUI-040.12 nodes (the requirement says "marker address is cleared").
- Waits: every wait is `wait_until`; fix-only states use `FIX_WAIT` = 10 s so a missing behaviour fails with the painted rows in the message; each negative read follows the action's own status line (or, for section jumps, the window moving).
- Expected addresses come from the case table or from the independent regular-expression read of `firmware.a2l` (VALUE_0200) and from `app.current_file.row_bases` only for "the present row before / at or after" (preconditions assert the shape first).
- Preconditions asserted (Inc 9 RR-3): marker present before every failed go-to / continued search (1 marked line at `0x50` and the field `0x50`); MAC row `0x1000` is the first view row before the 018.1/12 jumps; the chosen region is not the first view row; the MAC table row of `0x00FF0000` has `no` / `no`; the tag `OUT_OF_RANGE_1` is listed at `0x00D00000`; section 2 starts at `0x00040000`; page size is 3 after the setting.

## Cases -> nodes, RED on base
All fix-dependent waits fail with the painted state in the message (base behaviour, not a harness error).

| Case | Node | Base result and the reason |
|---|---|---|
| R-TUI-018.1/1 | `test_r_tui_018_1_1_main_goto_target_is_second_row` | RED: first rows `0x00000000, 0x00000010`, expected `0x950, 0x960` |
| R-TUI-018.1/2 | `test_r_tui_018_1_2_main_find_next_hit_is_second_row` | RED: first rows `0x0081FA60...` |
| R-TUI-018.1/3 | `test_r_tui_018_1_3_section_jump_shows_range_start_second` | RED: first rows `0x0000FA00...`, expected `0x0000FFF0, 0x00040000` (status clause: finding F-3) |
| R-TUI-018.1/4 | `test_r_tui_018_1_4_map_open_in_hex_snapped_row_second` | RED: first rows `0x0, 0x10`, expected `0xF0, 0x100` |
| R-TUI-018.1/6 | `test_r_tui_018_1_6_a2l_goto_target_is_second_row` | RED: `0x560...` (row 65) |
| R-TUI-018.1/7 | `test_r_tui_018_1_7_a2l_search_hit_is_second_row` | RED: `0x0081FC50...` |
| R-TUI-018.1/8 | `test_r_tui_018_1_8_a2l_tag_find_shows_tag_row_second` | RED: `0x00805680...`, expected `0x805A70, 0x805A80` |
| R-TUI-018.1/9 | `test_r_tui_018_1_9_mac_goto_target_is_second_row` | RED: `0x560...` |
| R-TUI-018.1/10 | `test_r_tui_018_1_10_mac_search_hit_is_second_row` | RED: `0x0081FC50...` |
| R-TUI-018.1/11 | `test_r_tui_018_1_11_jump_to_last_present_row_still_second` | RED: first rows `0x00C006E0...` (page floor), expected `0xC00FE0, 0xC00FF0` |
| R-TUI-018.1/12 | `test_r_tui_018_1_12_mac_row_below_image_counts_as_row_above` | RED: main view `0x1000, 0x8000`, expected `0x8010, 0x8020` (A2L / MAC arms not reached; same loop) |
| R-TUI-018.1/13 | `test_r_tui_018_1_13_target_row_inside_pane_at_80x24[main]` | SKIPPED by name: pane 1 line high (finding F-1) |
| | `...[a2l]`, `...[mac]` | RED: rows `0x560...`; the pane-geometry clause is reached only once the rows are right (not shown RED, see F-1) |
| (extension) | `test_r_tui_018_1_13b_main_target_row_inside_pane_at_100x30` | RED: rows `0x0, 0x10` (main arm at a size whose pane has 7 lines) |
| R-TUI-018.2/1 | `test_r_tui_018_2_1_main_jump_resets_both_axes` | RED: scroll `(10, 40)` after the jump |
| R-TUI-018.2/2, /3 | `test_r_tui_018_2_2_a2l_jump_resets_both_axes`, `..._2_3_mac_...` | RED: scroll `(0, 40)` after the jump (x has no range, F-2) |
| R-TUI-018.3/2 | `test_r_tui_018_3_2_a2l_tag_outside_image_lands_on_snapped_row` | RED: rows `0x0, 0x10` (no start index, centred), expected `0xC00FE0, 0xC00FF0` |
| R-TUI-018.3/3 | `test_r_tui_018_3_3_mac_record_outside_image_lands_on_snapped_row` | RED: rows `0x00C00C00...` (64 context rows) |
| R-TUI-018.4/1 | `test_r_tui_018_4_1_first_view_row_shown_first_and_miss_keeps_it` | PASSES on base (standing guard, as the case's Base column says) |
| R-TUI-040.4/1, /2, /3 | `test_r_tui_040_4_1_main_...`, `_4_2_a2l_...`, `_4_3_mac_...` | RED: second row not `0x960` (rows `0x0`, `0x560`, `0x560`) |
| R-TUI-040.8/1, /2, /3 | `test_r_tui_040_8_1_main_...`, `_8_2_a2l_...`, `_8_3_mac_...` | PASS on base (standing guards) |
| R-TUI-040.8/4 | `test_r_tui_040_8_4_miss_after_jump_to_last_row_keeps_window` | RED at the jump (`0x00C006E0`, the page floor); the miss clause is reached only with the fix (F-8) |
| R-TUI-040.11/1, /2, /3 | `test_r_tui_040_11_1_main_miss_...`, `_11_2_main_empty_box_...`, `_11_3_main_invalid_...` | RED: 1 marked line `> 0x00000050` remains |
| R-TUI-040.11/4, /5 | `test_r_tui_040_11_4_a2l_miss_...`, `_11_5_mac_invalid_...` | RED: 1 marked line remains |
| R-TUI-040.12/1 | `test_r_tui_040_12_1_section_jump_removes_main_marker` | RED: marker address field still `80` (0x50) (F-5) |
| R-TUI-040.12/3 | `test_r_tui_040_12_3_map_open_in_hex_removes_main_marker` | RED: marker address field still `80` |
| R-TUI-040.12/4, /5, /6 | `test_r_tui_040_12_4_continued_main_...`, `_12_5_continued_a2l_...`, `_12_6_continued_mac_...` | RED: second row not the hit (`0x0081FA60` / `0x0081FC70`) |
| R-TUI-007.3/1 | `test_r_tui_007_3_1_next_page_follows_the_shown_window` | RED at go-to row 151 (`0x8000`, start 0); the `.` clause not separately observable on base (F-8) |
| R-TUI-007.5/1 | `test_r_tui_007_5_1_next_page_keeps_a_window_holding_the_last_row` | RED at go-to row 949 (`0xB200` = row 800); `.` clause as above |
| R-TUI-007.8/1 | `test_r_tui_007_8_1_pages_count_the_row_added_for_a_mac_record` | RED: after the first `.` the page is still `0x1000, 0x8000, 0x8010` |

Not mine: R-TUI-040.12/7 and R-TUI-007.3/2 (existing nodes, `covered` / `partial`). Withdrawn cases R-TUI-018.1/5, R-TUI-018.3/1, R-TUI-040.12/2 have no node. Uncovered by this file: none of group H's rows; GREEN not run.

## Standing guards (pass on base) and why each still has a failure mode
- R-TUI-040.8/1, /2, /3 (`test_r_tui_040_8_*`): compare every painted row (text from column 3) before and after a missed go-to. Fail if a miss re-renders from another window (row 0 or the page floor) or changes any row. Base passes because it does not re-render at all (requirements: Base "Yes (no re-render)").
- R-TUI-018.4/1: first row `0x00000000` with no "showing from" line after a go-to of 0, and still first after a miss, in each view. Fails if the jump start is not floored at 0 (the last row would be painted) or a miss re-renders elsewhere. Base passes by the requirement's own Base column.
- Painted-only "0 marked lines" is also true on base where the marker row is outside the new window; those nodes (040.12/1, /3, /4-6) therefore also assert the marker address field and the second row, which are RED on base (F-5).

## Findings for the integrator
1. **F-1 (infeasible arm, case wording).** R-TUI-018.1/13 main arm: at 80 x 24 the Workspace `#hex_scroll` is 1 line high (measured: region 31 x 1; A2L pane 5 lines, MAC pane 7), so no second row can lie inside it, whatever the fix. The main arm skips by name with the measured height; the A2L and MAC arms run. Added extension node `..._13b_main_...` at 100 x 30 (pane 7 lines). Decide: reword the case (arms, or a larger size for main) or accept the pane height as a layout finding.
2. **F-2 (case precondition).** R-TUI-018.2/2 and /3 start from x 10, y 40; the A2L and MAC panes have no horizontal range (x stays 0), only the main pane reaches x 10. The nodes scroll to y 40 (and x where it exists) and assert the achieved state is not (0, 0) before the jump, then (0, 0) after.
3. **F-3 (case wording).** R-TUI-018.1/3 (and the status of 040.12/1) quote `Section at 0x00040000`. `_jump_to_section` writes no status; that line belongs to open R-TUI-009.2 / D4-16 (not in Inc 10a). The nodes use the window moving as the positive sign.
4. **F-4 (case wording / realisability).** R-TUI-040.12/4-6: `BUILD_ID` has one hit in case 08, so "Find Next again" returns `Search text not found.` and clears the anchor on base. The nodes search `19TOOL` (hits: banner at `0x00000001`, then the config block), go-to `0x50` between, and the second Find Next shows the config hit second. If the design resets the search anchor on a go-to, the node still holds (it searches forward from the first visible row).
5. **F-5 (oracle strength).** On base the marker row leaves the window after a section jump, a map open and a search, so "0 marked lines" is true without the fix. The RED of 040.12/1 and /3 is the marker address field; 040.12/4-6 are RED by the second row too. The case text "`.` then `,` back to the first page: still 0" is weak (paging clears the marker anyway); kept as written.
6. **F-6 (group F interplay).** On base a rail key leaves the focus on a hidden Workspace text box (`search_input`), so the next `g` is typed into it. `show()` clears a stray text-box focus after the window is laid out; group F owns the focus landing itself.
7. **F-7.** `EXPECTED_SCANNED_TEST_FILES` (`tests/test_id_registry.py`) must be bumped for this file (and F's): 269 -> 270 with H alone.
8. **F-8 (RED reason mixing).** R-TUI-007.3/1, 007.5/1 and 040.8/4 reach their paging / miss clause only after a jump that base already places wrongly, so on base they are RED at the jump precondition; the `.` and miss clauses are asserted after it and are first observable on the fixed tree.
9. **F-9 (MAC table).** The record of `0x00FF0000` sits on page 3 of the MAC table (page 100, 209 records); R-TUI-018.3/3 pages with `+` twice.

## Deviations from the brief
1. `--dist load` instead of `--dist loadfile`: one file would run on a single worker under loadfile (about 20 minutes); `-n 3` as instructed.
2. The cases that name the settings menu for page size 3 call `_apply_viewer_setting("hex_rows_page_size", 3)` (the menu handler) because 3 is not an offered option.

Remote worktree `s19_i10h` removed; helpers and run files deleted from the host.
