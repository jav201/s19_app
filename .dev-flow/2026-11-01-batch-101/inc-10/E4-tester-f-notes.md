# Inc 10a E4 tester F (unload state and focus landing) - notes

Node file: `tests/test_b101_unload_focus.py`, 35 test functions = 46 nodes (R-SHELL-FOCUS.2/5 is parametrised over 12 rail keys). No product file touched.
RED run: base `e07fb00f` (origin/main) + Inc 9 diff (ff678242), LAN Linux host, detached worktree `s19_i10f` (removed), `s19_app.__file__` resolved inside the worktree. Command: `env -u NO_COLOR python -m pytest -q -p no:cacheprovider -rfs --tb=short --show-capture=no tests/test_b101_unload_focus.py -n 3 --dist load`. Deviation from the brief: `--dist load` instead of `--dist loadfile` (one file under loadfile is one worker, 16 min; `load` took 4 min 39 s). Transcript (redacted, one complete run): `.dev-flow/2026-11-01-batch-101/evidence/inc-10/red-01-tester-f-base.txt`. Summary: **41 failed, 5 passed in 279.23s**. State: `executed` on base. GREEN on the integrated tree: `not-run`. No `serial_timing` node (waits only, no wall-clock bound).

## How the nodes read and drive
- App cases run through `projects.run_app(base, scenario, size=(120, 56))` (118 x 54 measured); `LOCALAPPDATA` isolated by the autouse fixture; no OS clipboard.
- Case 08 (seed 20260001, 1.0 MB) is a module fixture; fixture three and the bad-checksum / no-terminator / Cf-named S19s are written in the test.
- `[u]`: a `Button.press()` on the Loaded-panel button whose `name` is the slot (focus not moved, so "from files_list" holds); `[u]` focused + Enter in R-SHELL-FOCUS.3/1; `U` and rail keys by `pilot.press`; windows by keys or `action_show_screen`; Split / Join by `action_open_split_join_export` (the palette entry's action).
- Reads: `#status_text`, `#log_line_4` (newest message), `#ws_stats` loader line, Loaded panel slots, `default_screen.focused`, files under `<workarea>/splits` and `<workarea>/<project>` (SHA-256), `#confirm_title` / `#confirm_body`.
- Waits: `wait_until` for every sign (message, window, focus landing, load); negative assertions follow a positive wait (message or landing, plus a sentinel rail key after `a`, `e` / Enter so earlier keys are known processed).
- Emulated preconditions are asserted: focus put on a widget (`put_focus` waits for it), Split / Join hidden, every row ticked before the EXPORT trigger (`#sje_stats` has no `nothing selected`), the unsaved Patch Editor entry survives the unload (`is_dirty`), reference MAC-only loader count is 2.

## Cases -> nodes, RED on base
| Case | Node | Base result and reason |
|---|---|---|
| R-WS-LOADED.18/1 | `test_r_ws_loaded_18_1_unload_mac_slot_sets_file_status` | RED: `#status_text` `Loaded firmware.mac (S19+MAC)` |
| .18/2 | `..._18_2_unload_all_sets_file_status` | RED: same stale status |
| .18/3 | `..._18_3_unload_primary_slot_sets_file_status` | RED: same |
| .18/4 | `..._18_4_unload_a2l_slot_sets_file_status` | RED: `Loaded firmware.s19 (S19 only)` |
| .14/1 | `..._14_1_unload_all_with_nothing_loaded` | RED: newest `Unloaded all artifacts.` |
| .14/2 | `..._14_2_unload_all_in_an_a2l_only_session` | PASS (standing guard, below) |
| .16/1 | `..._16_1_primary_diagnostics_go_with_it` | RED: `Loader 1 err` stays |
| .16/3 | `..._16_3_mac_diagnostics_stay_after_a_primary_unload` | RED: 1 error (primary's) vs 2 (MAC-only reference) |
| .19/1 | `..._19_1_save_after_primary_unload_writes_no_image` | RED: `P6` holds `unloaded_primary.s19` |
| .19/2 | `..._19_2_save_without_unload_writes_the_image` | PASS (control, below) |
| .20/1 | `..._20_1_load_question_names_the_mac_after_a_primary_unload` | RED: `Replace unloaded_primary.s19?` |
| R-TUI-012L.8/1 | `test_r_tui_012l_8_1_load_status_drops_a_cf_character` | RED: U+202E kept in status |
| 012L.8/2 | `..._8_2_mac_name_of_the_plus_mac_arm_is_painted` | RED: `Loaded three.s19 (S19+MAC: m<U+200B>x.mac)` |
| 012L.8/3 | `..._8_3_integrity_notice_arm_paints_the_name` | RED: `Loaded fw<U+202E>gpj.s19 with integrity notices: S19-NO-TERMINATOR` |
| R-SHELL-STATUS.7/1 | `test_r_shell_status_7_1_project_load_line_has_no_format_character` | RED: `-> fw<U+202E>gpj.s19` |
| .7/2 | `..._7_2_project_load_line_scrubs_the_mac_name` | RED: U+202E and U+200B kept |
| R-SHELL-FOCUS.2/1 | `test_r_shell_focus_2_1_key_2_puts_focus_on_the_tag_table` | RED: focus `ws_load_project_button` area 0 |
| .2/2 | `..._2_2_esc_in_split_join_focuses_the_workspace_target` | RED: nothing focused |
| .2/3 | `..._2_3_rail_key_in_split_join_focuses_that_window` | RED: nothing focused |
| .2/5 | `..._2_5_every_rail_key_lands_on_its_target[<12 windows>]` | RED x12: focus stays `ws_load_project_button` (area 0) |
| .2/6 | `..._2_6_synchronous_clear_decides_and_enter_runs_nothing` | RED: focus not cleared synchronously (`patch_doc_validate_button`) |
| .2/7 | `..._2_7_the_later_of_two_rail_keys_wins` | RED: focus `ws_load_project_button` |
| .3/1 | `..._3_1_unload_that_removes_the_focused_button_rehomes_focus` | RED: nothing focused after the unload |
| .3/2 | `..._3_2_unload_with_nothing_focused_lands_on_the_target` | RED: `sje_table` area 0 |
| .4/1 | `..._4_1_unload_all_keeps_a_healthy_list_focus` | RED: `sje_table` |
| .4/2 | `..._4_2_unload_all_keeps_a_rail_items_focus` | RED: `sje_table` |
| .5/1 | `..._5_1_empty_state_window_uses_the_fallback` | RED: focus stays `rail_item_workspace`, expected `rail_item_issues` |
| R-SEG-OPEN.6/1 | `test_r_seg_open_6_1_unload_keeps_the_focus_out_of_the_hidden_window` | RED: `sje_table` |
| .6/3 | `..._6_3_in_place_write_keeps_the_focus_out_of_the_hidden_window` | PASS (standing guard) |
| .6/4 | `..._6_4_esc_leaves_no_focus_in_the_closed_window` | PASS (standing guard) |
| .6/5 | `..._6_5_rail_key_leaves_no_focus_in_the_closed_window` | PASS (standing guard) |
| .7/1 | `..._7_1_keys_after_a_mac_unload_export_nothing` | RED: 4 files `firmware_range_00..03.s19` |
| .7/2 | `..._7_2_keys_after_unload_all_export_nothing` | RED: message `nothing selected ...` (no files, see finding 3) |
| .7/3 | `..._7_3_keys_stay_inert_while_hidden_even_with_focus_inside` | RED: 4 files |
| .7/4 | `..._7_4_export_button_writes_nothing_while_hidden` | RED: 4 files (rows ticked first) |

## Standing guards (pass on base) and why each still has a failure mode
- `14_2` (A2L-only `U`): base `all` always proceeds. Fails if the new "Nothing to unload." early return ignores `current_a2l_path`, or the A2L slot is not cleared.
- `19_2` (control): shows the oracle sees an image file when one is loaded (`P7/unloaded_primary.s19`, same SHA-256), so `19/1` can fail; fails if Save project stops writing the image.
- `6_3` (in-place write): base's write hook calls no `refresh_window`. Fails if a write (Inc 10b) takes the hidden table's focus. Re-run at 10b's E5.
- `6_4`, `6_5` (Esc / rail key close): base leaves nothing focused, so "no focus inside the closed window" holds. Fail if a close or switch leaves `sje_table` focused. Their landing is already asserted RED in `2_2` / `2_3`.

## Findings for the integrator
1. Proposed test names are not in `02-test-cases.md`; I used `test_r_<row>_<n>_<slug>`. Cases with no `F planned` were not written: R-WS-LOADED.13/1, .16/2, R-TUI-012L.8/4, R-SHELL-FOCUS.2/4 (existing `test_tc_b97_64...` to be re-pinned by its owner), R-SEG-OPEN.1/1, .6/2.
2. R-TUI-012L.8/2 wording: loading the MAC onto a loaded image paints `Loaded <mac> (S19+MAC)` with no MAC name; the `+MAC: <name>)` arm appears when the MAC is loaded first and the image second. The node uses that order.
3. R-SEG-OPEN.7/2: after `U` there is no image to export, so base writes 0 files; the case's "(base: 4 files)" does not hold. The node is RED on base through the hidden window's `e` painting `nothing selected`. Nodes 7/1-7/3 therefore also assert no `nothing selected` message.
4. "Issues Report: 0 loader diagnostics" (R-WS-LOADED.16/1, /3) is observed through the Workspace loader-facts line (`Loader N err`) and the Loaded panel; loader diagnostics are not listed in the Issues window on base, so no Issues-window text is asserted.
5. On base, `p` after an unload is dead (the focus is on the hidden table). Nodes 20/1 and STATUS.7/x put the focus on `files_list` before `p`, so their RED reason is the status / question text, not the dead key.
6. R-SHELL-FOCUS.5/1 uses the Issues empty state (all Issues widgets paint area 0 with nothing loaded, probed on base): expected focus = first shown focusable non-text widget else `rail_item_issues`.
7. R-SHELL-FOCUS.2/6 reads `app._patches_dir()` (private) to place the one-entry document; `tests/test_id_registry.py` `EXPECTED_SCANNED_TEST_FILES` needs the new file added at integration. `test_address_census.py` / `test_suite_hygiene.py` were not run (rule 6); selectors are literals or f-strings, file is ASCII (Cf characters written as escapes).
