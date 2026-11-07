# Inc 10a — E5 mutant table (hex navigation, unload state, focus)

Batch 2026-11-01-batch-101, increment 10a. Executor: E5 unit (single-unit mutant run, DeepSeek).
Base commit: `09b4808a0344de05d9d64cd55362ac7058a8c17f` (origin/main; branch `b101-inc10` head `54a0eb2` = the E4 tree, pre-corrective — E5-rulings.md: "the mutant table runs on the pre-corrective tree").
Tree: `09b4808a` + `git diff --binary 09b4808a -- s19_app tests docs README.md` of the branch, applied to a detached worktree.

All runs on LAN Linux host 2 only (`<USER>@LAN host 2`, Python 3.11.18, `env -u NO_COLOR`); nothing
importing `s19_app` ran on the Windows PC. Each mutant was applied **one at a time** in a `cp -a` copy of
the base worktree (`<HOME>/work/s19_i10mut_m<NN>`), the mutation was verified to have landed
(`s19_app.__file__` points at the copy), only the row's guard nodes were run from the copy (cwd = the copy),
and the copy was then deleted. Every row's guard nodes were confirmed GREEN on the unmutated base first
(baseline: 96 passed + 1 skip by name over the H/F/X/acceptance files; 21 passed over the `test_b100_focus`
set; 5 passed over the two `test_b100_workers` quit nodes — all serial for the quit nodes).

Transcripts: `evidence/inc-10/mut-01.txt` … `mut-38.txt` (each prints the base commit, the mutation diff,
`s19_app.__file__` and the exact command line; home paths and account names redacted).

Sources: the E5 mutant table and the M-R rows of `E4-integration-notes.md` (§3, §6, §7); node names drop the
`test_r_` prefix. Files: **H** `tests/test_b101_hex_jump.py`, **F** `tests/test_b101_unload_focus.py`,
**X** `tests/test_b97_flow_execution.py`. M-R3's nodes are in `tests/test_b100_focus.py`, M-R5's in
`tests/test_b100_workers.py`, M-R4's `test_at_i11_5_…` in `tests/test_b101_inc11_acceptance.py`.

| M | Row | Mutation | Nodes | Result (killed / survived) | Killing node(s) / failure line | Transcript |
|---|---|---|---|---|---|---|
| M1 | R-TUI-018.1 | `update_hex_view`: the focused start back to the page floor `(snapped // page) * page` | H `tui_018_1_1…`, `_1_2…`, `_1_3…`, `_1_4…`, `_1_11…`, `_1_12…`, `_1_13b…`, `tui_040_4_1…` | KILLED (8/8) | `tui_018_1_1…` `section jump to 0x00040000: first rows [0x0000FA00, 0x0000FA10], expected [0x0000FFF0, 0x00040000]` | `mut-01.txt` |
| M2 | R-TUI-018.2 | `update_hex_view`: `_reset_scroll_to_top("#hex_scroll")` removed | H `tui_018_2_1…` | KILLED | `tui_018_2_1…` `main: scroll is (10, 40) after the jump, was (10, 40)` | `mut-02.txt` |
| M3 | R-TUI-018.2 (A2L / MAC) | `_handle_goto_alt` / `_handle_goto_mac`: `reset_scroll=False` on a hit | H `tui_018_2_2…`, `_2_3…` | KILLED (2/2) | `tui_018_2_2…` `a2l: scroll is (0.0, 40) after the jump, was (0.0, 40)` | `mut-03.txt` |
| M4 | R-TUI-018.3 | `_row_start_for_near_top_focus`: `row_bases.index(focus_base)` (exact, `None` when absent) | H `tui_018_3_2…`, `_3_3…` | KILLED (2/2) | `tui_018_3_2…` `A2L tag find OUT_OF_RANGE_1: first rows [0x00000000, 0x00000010], expected [0x00C00FE0, 0x00C00FF0]` | `mut-04.txt` |
| M5 | R-TUI-018.4 | `_row_start_for_near_top_focus`: `j − context_rows` without `max(0, …)` | H `tui_018_4_1…` | KILLED | `tui_018_4_1…` `a2l: first row [0x00C00FF0] after the miss` | `mut-05.txt` |
| M6 | R-TUI-018.1/12, R-TUI-007.8 (A10-03) | `_hex_view_rows`: return `row_bases` (no MAC rows) | H `tui_018_1_12…`, `tui_007_8_1…` | KILLED (2/2) | `tui_018_1_12…` `main go-to 0x00008020: first rows [0x00008000, 0x00008010], expected [0x00008010, 0x00008020]` | `mut-06.txt` |
| M7 | R-TUI-040.11 | `_handle_goto`: no `update_hex_view()` on a failure | H `tui_040_11_1…`, `_11_2…`, `_11_3…` | KILLED (3/3) | `tui_040_11_1…` `main after go-to '': 1 marked line(s) ['> 0x00000050 …']` | `mut-07.txt` |
| M8 | R-TUI-040.11 (A2L / MAC) | `_handle_goto_alt` / `_mac`: no re-render on a failure | H `tui_040_11_4…`, `_11_5…` | KILLED (2/2) | `tui_040_11_4…` `a2l after go-to '0xFFFFFFF0': 1 marked line(s) ['> 0x00000050 …']` | `mut-08.txt` |
| M9 | R-TUI-040.8 | `_handle_goto` failure: `update_hex_view(0)` (re-render from row 0) | H `tui_040_8_1…` | KILLED | `tui_040_8_1…` `main: the miss changed the rows (200 before, 200 after)` | `mut-09.txt` |
| M10 | R-TUI-040.12 | `update_hex_view`: the marker clear for a new focus removed | H `tui_040_12_1…`, `_12_3…`, `_12_4…` | KILLED (3/3) | `tui_040_12_1…` `after the section jump: the marker address field still holds 80` | `mut-10.txt` |
| M11 | R-TUI-040.12 (A2L / MAC) | `update_alt_hex_view` / `update_mac_hex_view`: the marker clear removed | H `tui_040_12_5…`, `_12_6…` | KILLED (2/2) | `tui_040_12_5…` `a2l after the continued search: the marker address field still holds 80` | `mut-11.txt` |
| M-P | R-TUI-007.5 | `action_hex_page_next`: `min(max_start, start + page)` | H `tui_007_5_1…` | KILLED | `tui_007_5_1…` `'.' press 1: first row [0x0000B200], expected [0x0000BB40]` | `mut-12.txt` |
| M-W | R-TUI-040.8/4 | `update_hex_view`: the page-floor clamp for a render without a focus | H `tui_040_8_4…` | KILLED | `tui_040_8_4…` `jump to the last present row: first rows [0x00C006E0, 0x00C006F0], expected [0x00C00FE0, 0x00C00FF0]` | `mut-13.txt` |
| M12 | R-TUI-007.8 | `action_hex_page_next`: `total = len(row_bases)` | H `tui_007_8_1…` | KILLED | `tui_007_8_1…` `after the first '.': [0x00001000, 0x00008000, 0x00008010], expected [0x00008020]` | `mut-14.txt` |
| M13 | R-WS-LOADED.18 | `_apply_unload`: the `set_file_status` call removed | F `ws_loaded_18_1…` … `_18_4…` | KILLED (4/4) | `ws_loaded_18_2…` `assert 'Loaded firmw…mac (S19+MAC)' == 'Unloaded all artifacts.'` | `mut-15.txt` |
| M14 | R-WS-LOADED.13 | `_apply_unload`: `set_file_status` → `set_status` (the message painted twice) | F `ws_loaded_13_1…` | KILLED | `ws_loaded_13_1…` `['Loaded firmware.s19 …', 'Loaded firmware.mac …', 'Unloaded MAC.', 'Unloaded MAC.']` | `mut-16.txt` |
| M15 | R-WS-LOADED.14 | `_apply_unload`: the `Nothing to unload.` return removed | F `ws_loaded_14_1…` (`_14_2…` must stay GREEN) | KILLED (1/1; `_14_2…` GREEN) | `ws_loaded_14_1…` `assert 'Unloaded all artifacts.' == 'Nothing to unload.'` | `mut-17.txt` |
| M16 | R-WS-LOADED.16 | `_unload_primary`: `errors` kept | F `ws_loaded_16_1…`, `_16_3…` | KILLED (2/2) | `ws_loaded_16_1…` `Coverage: —` | `mut-18.txt` |
| M17 | R-WS-LOADED.19, .20 | `_unload_primary`: `path` kept | F `ws_loaded_19_1…`, `_20_1…` | KILLED (2/2) | `ws_loaded_19_1…` `P6 holds image files: ['unloaded_primary.s19']` | `mut-19.txt` |
| M18 | R-TUI-012L.8 | `_format_coexistence_status`: `path.name` raw | F `tui_012l_8_1…`, `_8_3…`, `_8_5…` (`_8_4…` GREEN) | KILLED (3/3; `_8_4…` GREEN) | `tui_012l_8_1…` `'Loaded fw\u202egpj.s19 (S19 only)'` | `mut-20.txt` |
| M19 | R-TUI-012L.8/2 | `_format_coexistence_status`: the MAC name raw | F `tui_012l_8_2…` | KILLED | `tui_012l_8_2…` `assert ['U+200B'] == []` | `mut-21.txt` |
| M20 | R-SHELL-STATUS.7 | `set_file_status`: the `painted_names` filter removed | F `shell_status_7_1…`, `_7_2…` | KILLED (2/2) | `shell_status_7_1…` `"Loaded project 'PB' -> fw\u202egpj.s19"` | `mut-22.txt` |
| M21 | R-SHELL-FOCUS.2 | `action_show_screen`: no landing scheduled | F `shell_focus_2_1…`, `_2_2…`, `_2_3…`, `_2_5…`, `_2_7…`; X `test_tc_b97_64_arriving…` | KILLED (18/18) | `shell_focus_2_1…` `the focus never landed on #window_help_a2l; it is no widget focused` | `mut-23.txt` |
| M22 | R-SHELL-FOCUS.2/6 (D-8 (1)) | `action_show_screen`: the synchronous clear removed | F `shell_focus_2_6…` | KILLED | `shell_focus_2_6…` `the focus was not cleared synchronously: Button#patch_doc_validate_button (region area 10)` | `mut-24.txt` |
| M23 | R-SHELL-FOCUS.2/7 (AR2-2) | `_land_focus`: the stale-switch return removed | F `shell_focus_2_7…` | SURVIVED | — (the stale landing runs first and the later one moves the focus again) | `mut-25.txt` |
| M-L | I-D3 | `_land_focus`: `layout_waits` default 0 | F `shell_focus_2_7…` | SURVIVED | — (the landing ran after `#screen_mac` was laid out, 3/3) | `mut-26.txt` |
| M24 | R-SHELL-FOCUS.3 | `_apply_unload`: no landing scheduled | F `shell_focus_3_1…`, `_3_2…`, `seg_open_6_1…` | KILLED (3/3) | `shell_focus_3_1…` `the focus never landed on #window_help_workspace; it is no widget focused` | `mut-27.txt` |
| M25 | R-SHELL-FOCUS.4 | `_land_focus`: move unconditionally | F `shell_focus_4_2…` | KILLED | `shell_focus_4_2…` `the focus never landed on #rail_item_workspace; it is WindowHelpChip#window_help_workspace (region area 3)` | `mut-28.txt` |
| M26 | R-SHELL-FOCUS.5 | `_resolve_focus_target`: no fallback (context node; one-line mutation) | F `shell_focus_5_1…` | KILLED | `shell_focus_5_1…` `the focus never landed on #rail_item_issues; it is GroupedIssuesPanel#validation_issues_groups (region area 0)` | `mut-29.txt` |
| M27 | R-SEG-OPEN.6 | `refresh_window`: the `hidden` test removed (= M-R) | F `seg_open_6_1…`, `_6_2…` | KILLED (1/1; `_6_1…` GREEN — its end-state check is fixed by the unload landing) | `seg_open_6_2…` `the load focused ['sje_table'] inside the hidden window` | `mut-30.txt` |
| M28 | R-SEG-OPEN.7 | `SplitJoinWindow.check_action` removed | F `seg_open_7_3…` | SURVIVED | — (the pre-corrective `/7/3` never observes the `a` key's selection; `e` is refused by `action_export`'s own guard) | `mut-31.txt` |
| M29 | R-SEG-OPEN.7/4 (SR2-1) | `action_export`: the `hidden` return removed | F `seg_open_7_4…` | KILLED | `seg_open_7_4…` `['firmware_range_00.s19', 'firmware_range_01.s19', 'firmware_range_02.s19', 'firmware_range_03.s19']` | `mut-32.txt` |
| M30 | R-SEG-OPEN.1 | `refresh_window`: the table focus removed | F `shell_focus_2_2…`, `_2_3…`, `seg_open_6_4…`, `_6_5…` | KILLED (4/4) | `seg_open_6_4…` `the focus never landed on #sje_table; it is Button#ws_load_project_button (region area 0)` | `mut-33.txt` |
| M-R1 | R-TUI-007.9 (E4-R1) | `_apply_prepared_load`: the `_hex_window_start = 0` reset removed | H `tui_007_9_1…` | KILLED | `tui_007_9_1…` `the load after the deep jump: first rows [0x00008020], expected [0x00008000, 0x00008010, 0x00008020]` | `mut-34.txt` |
| M-R3 | HLR-166 (E4-R3) | `_rehome_placeholder_focus_after_load`: return at once | `tests/test_b100_focus.py` `test_tc_b100_12_first_load_from_the_startup_rail_focus…`, the 10 I-D14 nodes, `every_window…[a2l]`, `test_tc_b100_13_a2l_only_load_with_no_image` | KILLED (13/13) | `test_tc_b100_12_load_file_tail_rehomes_focus` `timed out waiting for the focus to settle on the window's target #files_list …` | `mut-35.txt` |
| M-R4 | R-TUI-020.1 / R-SHELL-FOCUS.2/1 (E4-R4) | `_SWITCH_LANDING_TARGETS = {}` | `test_at_i11_5…`, F `shell_focus_2_1…`, `_2_5…[a2l]` | KILLED (3/3) | `shell_focus_2_1…` `the focus never landed on #window_help_a2l; it is DataTable#a2l_tags_list (region area 1600)` | `mut-36.txt` |
| M-R5 | HLR-177c (E4-R5) | `_load_tree_gone`: return False | `tests/test_b100_workers.py` `test_tc_b100_53_confirmed_quit_waits_for_the_end[project]`, `…_during_a_routed_project_load_exits_cleanly` | KILLED (2/2) | `test_tc_b100_53_confirmed_quit_waits_for_the_end[project]` `textual.widget.MountError: Can't mount widget(s) before Container(id='ws_memstrip') is mounted` | `mut-37.txt` |
| M-R6 | R-TUI-020.1 MAC arm / R-SHELL-FOCUS.2/3, /2/5, /2/7 (E4-R6) | `_SWITCH_LANDING_TARGETS` without its `mac` entry | F `tui_020_1_mac_arm…`, `shell_focus_2_3…`, `_2_5…[mac]`, `_2_7…` | KILLED (4/4) | `shell_focus_2_7…` `the focus never landed on #mac_page_prev_button; it is DataTable#mac_records_list (region area 360)` | `mut-38.txt` |

## Score

- Total mutants run: **38** (no row skipped).
- Killed: **35**.
- Survived: **3** — M23, M-L, M28.

  - **M23** (the stale-switch return removed) is the **expected survivor** (the table's "may survive"):
    equivalent — the stale `2` landing runs first and is superseded by the later `3` landing, which
    moves the focus again, so no observable changes.
  - **M-L** (`layout_waits` default 0) survived on this host, **environment-sensitive, not equivalent**:
    `/2/7` only fails when the landing runs before the shown window's layout. The laptop's `int-08`
    (pre-E4-R6 tree) saw `#screen_mac` at area 0 and went RED; on the final tree here the landing
    consistently runs after `#screen_mac` is laid out (3/3 passes), so `/2/7` does not trigger the
    I-D3 race. This is a coverage gap of the guard node, not a proof the wait is dead.
  - **M28** (`check_action` guard removed) survived, **coverage gap**: the pre-corrective `/7/3` only
    checks that `e` writes nothing — refused by `action_export`'s own hidden guard (M29's target) — and
    never observes the `a` key's selection, so removing `check_action`'s hidden guard changes no asserted
    observable. E5-rulings.md SE5-2 accepts strengthening `/7/3` to reopen the window and assert the hidden
    `a` ticked nothing, which kills M28 on the corrective tree.

- Mutation score (killed / (total − expected survivors)): **35 / 37 = 94.6%**.
- Raw kill ratio (killed / total): **35 / 38 = 92.1%**.

## Notes

- One row's "Expected RED" list did not fully turn red: **M27** — `seg_open_6_1` (unload) stays GREEN under
  the mutation because its end-state check is repaired by the unload landing; `seg_open_6_2` (load) kills
  it (the node records every focus during a load-over). M27 is still KILLED.
- `M15` (`_14_2…`) and `M18` (`_8_4…`) keep their GREEN control arms exactly as the table requires.
- The base was the **pre-corrective** E4 tree (`54a0eb2`), per E5-rulings.md: "the mutant table runs on the
  pre-corrective tree; the corrective re-runs the mutants of the code it changes". The corrective's
  re-runs (M28 under SE5-2, the QA-3 split of M8, etc.) are not part of this record.
