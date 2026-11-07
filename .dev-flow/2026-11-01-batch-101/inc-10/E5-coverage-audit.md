# Inc 10a — E5 coverage audit

Batch 2026-11-01-batch-101, increment 10a, design-first flow (`dev-flow-v3-beta`, E5: "someone who did not write the test cases re-checks their `full`/`partial` marks and coverage"). Mode: **validation**. This record audits marks, oracles and results; no test was run. Auditor: the QA reviewer agent. It wrote no case, no node and no run.

- **Worktree:** `<HOME>/Github/s19_app-b101-inc10`, branch `b101-inc10`, head `54a0eb2` (the merge of `09b4808` into the branch).
- **Records read:** `01-requirements.md` (27 active rows), `02-test-cases.md` (83 active cases, 3 withdrawn), `E4-integration-notes.md` (runs int-01 … int-23, I-D1 … I-D27, §6, §7, the mutant table), `E4-rulings.md`, `E4-tester-h-notes.md`, `E4-tester-f-notes.md`, and the transcripts in `../evidence/inc-10/`.
- **Tests read:** `tests/test_b101_hex_jump.py` (**H**), `tests/test_b101_unload_focus.py` (**F**), and every test file the increment edited (`git diff 09b4808 -- tests`): `test_b97_flow_execution.py` (**X**), `test_tui_commandbar.py`, `test_b100_focus.py`, `test_b100_session_reset.py`, `test_id_registry.py`. Also read: the existing nodes the cases name, the support drivers the nodes call (`tests/support/timing.py`, `b100_save_dialog.py`, `b100_load_dialog.py`, `test_tui_directionb.py::_double_click_region_row`).
- **Product code read:** the go-to handlers (`app.py:21501-21676`), `action_hex_page_next` (`:11295`), `_reset_scroll_to_top` (`:20015`), `_resolve_focus_target` (`:10576`), `_FOCUS_TARGETS` / `_SWITCH_LANDING_TARGETS` (`:9935-9963`), the load tail's status write (`:18957-18959`), `set_file_status` (`:21702`) and `load_selected_file` (`:18503`).

`02-test-cases.md` is not edited here; the marks below are this audit's proposal for it. Inc 10b (`../inc-10b/`) is out of scope.

## 1. Verdict

**PASS-WITH-NOTES** for coverage, with one gate item open: **the 3/3-run threshold of every row is not yet met on the final tree** (QA-1). It is owed by E5's gate run before `04-validation.md`. No HIGH or MAJOR finding. Four MINOR findings and six NITs (§7).

- **Nodes.** Every node the 83 cases name exists: H 42 nodes, F 52 nodes, and the named existing nodes, counted by AST and grep. Every H/F function is named by a case, none is extra, and every scenario node runs its scenario (re-checked after I-D27). No node drives a withdrawn case (R-TUI-018.1/5, R-TUI-018.3/1, R-TUI-040.12/2), the issue jump or `action_view_*`.
- **Coverage marks: 79 `full`, 4 `partial`, 0 `gap`** (before: 82 / 1 / 0). Marks changed: 3 of 83 (4 %).
  - R-TUI-012L.8/2 and /3 → `partial` (QA-4).
  - R-TUI-007.3/2 → `partial` (QA-5).
  - R-TUI-040.12/7 stays `partial`.
- **Row thresholds (arms): 25 of 27 met on Linux.**
  - R-TUI-040.11 is met for 5 of its 9 view × failure arms (QA-3).
  - R-TUI-012L.8 is short of "the newest message line =" on its `+MAC:` and integrity-notice arms (QA-4).
  - Runs: 3/3 is met for no row on the final tree (QA-1).
- **Results.** 81 cases executed and passed on the final tree (int-21; 4 nodes also in int-20e). Two cases have no run on the final tree: R-TUI-040.12/7 and R-TUI-007.3/2. Their last run is int-16 on `c9513e1c`, before E4-R6 and the `09b4808` merge (QA-2).
- **Wait rule:** followed, with three small deviations (QA-6).
- **Window-switch rule:** followed.
- **Windows:** no case node has a Windows-only arm, and none ran on Windows (§6).

## 2. Evidence checks made by this audit

- **The final-tree runs ran the head's code.** I recomputed with git plumbing only: a scratch index and object directory, the repository's objects as alternates, and nothing written to the worktree.
  - `09b4808` + the head's 10 changed files under `s19_app tests docs README.md` gives **`6fc60136…`**.
  - It differs from int-20e … int-23's tree **`ba8da175…`** only in two comment lines of `tests/test_id_registry.py`. `EXPECTED_SCANNED_TEST_FILES = 272` is in both.
  - Writing the clone's comment back (int-20-setup) gives `ba8da175…` exactly.
  - The other 9 blobs equal `f92fa41`'s, which int-20-setup shows equal to the clone's staged blobs. int-20e … int-23 therefore ran the head's product and test code byte for byte, the comment aside.
- **The round-1 tree.** `2f54c7d` + `e8af53c`'s increment = **`c9513e1c…`** (recomputed). This is the tree of int-12 … int-19, which lacks E4-R6 (`_SWITCH_LANDING_TARGETS["mac"]`) and Inc 12b's 17 files of `09b4808`. int-01 ran `7324ef32…` and int-10 ran `b3b7935e…`; both predate E4-R1 … R6, which changed every load (`_apply_prepared_load`) and every rail-key landing.
- **What ran on the final tree:**
  - int-21: H, F, the 6 edited or guarding files and `test_at_i11_5_…`. `-q`, totals only: `1 failed, 309 passed, 1 skipped`. The failure is the known `test_at_b78_03_…`; the skip is the 80 × 24 main arm, by name. H and F are collected whole, so each of their 94 nodes passed, that skip aside.
  - int-20e: the 4 E4-R6 nodes, `4 passed`.
  - int-22: the 7 law guards, `218 passed`.
  - int-23: `serial_timing` over 15 files, `2 passed`. H and F have no `serial_timing` node.
- **Not run on the final tree:**
  - the QC-BC set (int-16, 121 files);
  - `test_tui_goto_marker.py`, `test_tui_app.py`, `test_unload_feature.py`, `test_segment_split_window.py`;
  - the I-D13 importers beyond `test_at_i11_5_…`;
  - the HLR-177c nodes (int-13a–c, `c9513e1c`).
- **Transcripts.** Every run prints its command and `s19_app.__file__`. int-13a and int-14 print an empty `index tree` line (QA-10).
- **RED evidence.**
  - Base: `red-01-tester-h-base.txt` (36 failed, 4 standing guards, 1 skip) and `red-01-tester-f-base.txt` (41 failed, 5 standing guards).
  - The nodes written or changed at E4: int-09, int-09b, int-19c.
  - Mutants run at E4: M-L, M-P, M-W (int-08); M-R (int-08b); M-R1, M-R3, M-R4, M-R5 (int-18a–d); M-R6 (int-20).
  - The rest of the mutant table is E5's (in progress; two helper scripts `.mut_*_tmp.py` sit untracked in this folder and are not this audit's).
- **Executors.** This audit executed none of the runs.
  - int-01 … int-11: the first E4 integrator (Opus).
  - int-12 … int-19: the second E4 integrator (Opus).
  - int-20 … int-23: the third E4 integrator (Opus).
  - All the above ran on the LAN Linux laptop.
  - red-01: testers H and F (Sonnet), on a LAN Linux host.
- **Product reads that decide oracles.**
  - **Load status.** The line is formed once in the shared load tail (`app.py:18957-18959`) and written twice: to `set_file_status`, which scrubs Cc / Cf / Zl / Zp again (`:21702`), and to the message line. So `#status_text` cannot show an R-TUI-012L.8 defect; only the message line can (QA-4).
  - **Scroll reset.** The three views reset scroll through one helper, `scroll_home` (`:20015`), so the main view's x arm exercises the A2L and MAC calls' x reset.
  - **Go-to failures.** Each view's go-to has three separate failure branches (`:21565`, `:21579`, `:21590` A2L; `:21639`, `:21653`, `:21664` MAC; QA-3).
  - **`.` is synchronous** (`:11295`, `update_hex_view` in the action), so a read after `pilot.press` sees its result (QA-6).
  - **`load_selected_file` has no product caller.** The shipped loads go through `_start_load_worker` and reach the same `_apply_prepared_load` (QA-8).
- **trace_check** (`python -I …/dev-flow-v3-beta/trace_check.py --req …/inc-10/01-requirements.md --base 09b4808 --src s19_app`; it reads text and git only): `3 US, 27 active requirements (0 withdrawn), 1 gap(s)`. The gap is EVID, expected before `04-validation.md`. I-D24's SLICE gap is gone after the merge.

## 3. Per case

Node names drop the `test_r_` prefix.

**Column key**

- **Route:** the stimulus; preconditions set by code are named.
- **Oracle:** what the node asserts.
- **Wait:** ✓ = every read follows a `wait_until` sign of the stimulus.
- **Evidence (final tree):** int-21 = `ba8da175` ≡ head; for 3/3 see QA-1.
- **Mark:** Δ = changed by this audit.

`executed` means the run passed; the case table's word `verified` is read as that (QA-10).

| # | Case | Node | Route | Oracle | Wait | Evidence (final tree) | Mark |
|---|---|---|---|---|---|---|---|
| 1 | R-TUI-018.1/1 | H `tui_018_1_1_…` | `g`, text, Tab, Enter | rows `0x950`, `0x960`; `... showing from 0x00000950` | ✓ | executed int-21 | full |
| 2 | R-TUI-018.1/2 | H `tui_018_1_2_…` | `/`, `BUILD_ID`, Tab, Enter | status `Found at 0x00C00050` exact; rows `0xC00040`, `0xC00050` | ✓ | int-21 | full |
| 3 | R-TUI-018.1/3 | H `tui_018_1_3_…` | section list focused, cursor set, Enter key | window moved; rows [present row before, `0x40000`] | ✓ | int-21 | full |
| 4 | R-TUI-018.1/4 | H `tui_018_1_4_…` | `4`, real double click on a region row | Workspace shown; rows [before, at or after the cell's row] | ✓ | int-21 | full |
| 5 | R-TUI-018.1/6 | H `tui_018_1_6_…` | `2`, go-to keys | rows `0x950`, `0x960` | ✓ | int-21 | full |
| 6 | R-TUI-018.1/7 | H `tui_018_1_7_…` | `2`, `/` | status exact; rows | ✓ | int-21 | full |
| 7 | R-TUI-018.1/8 | H `tui_018_1_8_…` | tag-find box `.focus()` (precondition), typed, Tab, Enter | rows [above, `VALUE_0200`'s row]; address from a regex read of the A2L | ✓ | int-21 | full |
| 8 | R-TUI-018.1/9 | H `tui_018_1_9_…` | `3`, go-to keys | rows `0x950`, `0x960` | ✓ | int-21 | full |
| 9 | R-TUI-018.1/10 | H `tui_018_1_10_…` | `3`, `/` | status; rows | ✓ | int-21 | full |
| 10 | R-TUI-018.1/11 | H `tui_018_1_11_…` | go-to the last row | rows; exactly 2 rows; no `window limited` | ✓ | int-21 | full |
| 11 | R-TUI-018.1/12 | H `tui_018_1_12_…` | keys `1` `2` `3`, go-to | per view: before `0x1000`, `0x8000`, `0x8010`; after `0x8010`, `0x8020` | ✓ | int-21 | full |
| 12 | R-TUI-018.1/13 | H `tui_018_1_13_…[a2l]`, `[mac]` (80 × 24); `…_13b_…` main (100 × 30) | go-to keys | target line inside the scroll region, `scroll_y` 0 | ✓ | int-21; `[main]` at 80 × 24 skipped by name (pane 1 line, BL-I10-2) | full |
| 13 | R-TUI-018.2/1 | H `tui_018_2_1_…` | scroll to (10, 40), both asserted > 0; go-to | `scroll_x` 0, `scroll_y` 0 | ✓ | int-21 | full |
| 14 | R-TUI-018.2/2 | H `tui_018_2_2_…` | y 40 (no x range at 118 × 54); go-to | (0, 0); x trivially 0 (QA-7) | ✓ | int-21 | full |
| 15 | R-TUI-018.2/3 | H `tui_018_2_3_…` | as #14 | as #14 | ✓ | int-21 | full |
| 16 | R-TUI-018.3/2 | H `tui_018_3_2_…` | `firmware_issues.a2l`; tag find `OUT_OF_RANGE_1` (`0x00D00000` asserted) | rows `0xC00FE0`, `0xC00FF0` | ✓ | int-21 | full |
| 17 | R-TUI-018.3/3 | H `tui_018_3_3_…` | `+` pages the table; cursor set; Enter key | status `MAC tag at 0x00FF0000`; rows `0xC00FE0`, `0xC00FF0` | ✓ | int-21 | full |
| 18 | R-TUI-018.4/1 | H `tui_018_4_1_…` | go-to `0x0`, then `0xFFFFFFF0`, per view | first row `0x0`; no `showing from`; first row kept after the miss status | ✓ | int-21; standing guard, only M5 can fail it (QA-9) | full |
| 19 | R-TUI-040.4/1 | H `tui_040_4_1_…` | go-to `0x965` | status `Goto 0x00000965`; rows; second row `> ` | ✓ | int-21 | full |
| 20 | R-TUI-040.4/2 | H `tui_040_4_2_…` | as #19, A2L | as #19 | ✓ | int-21 | full |
| 21 | R-TUI-040.4/3 | H `tui_040_4_3_…` | as #19, MAC | as #19 | ✓ | int-21 | full |
| 22 | R-TUI-040.8/1 | H `tui_040_8_1_…` (+ TC-007) | marker at `0x50` (asserted); miss | miss status; rows equal from column 3 | ✓ | int-21; TC-007 int-16 only | full |
| 23 | R-TUI-040.8/2 | H `tui_040_8_2_…` | as #22, A2L | as #22 | ✓ | int-21; standing guard, no mutant (QA-9) | full |
| 24 | R-TUI-040.8/3 | H `tui_040_8_3_…` | as #22, MAC | as #22 | ✓ | int-21; as #23 | full |
| 25 | R-TUI-040.8/4 | H `tui_040_8_4_…` | last row, then miss | rows equal; first row index 26 544 | ✓ | int-21; M-W RED (int-08) | full |
| 26 | R-TUI-040.11/1 | H `tui_040_11_1_…` | marker `[0x50]`; miss | 0 marked lines | ✓ | int-21 | full |
| 27 | R-TUI-040.11/2 | H `tui_040_11_2_…` | empty box | status exact; 0 marked | ✓ | int-21 | full |
| 28 | R-TUI-040.11/3 | H `tui_040_11_3_…` | `zz` | status exact; 0 marked | ✓ | int-21 | full |
| 29 | R-TUI-040.11/4 | H `tui_040_11_4_…` | A2L miss | 0 marked | ✓ | int-21 | full (row short, QA-3) |
| 30 | R-TUI-040.11/5 | H `tui_040_11_5_…` | MAC `zz` | 0 marked | ✓ | int-21 | full (row short, QA-3) |
| 31 | R-TUI-040.12/1 | H `tui_040_12_1_…` | marker (field and paint); section Enter; `.`, `,` | field `None`, 0 marked; 0 after `.` and after `,` (each after the window moved) | ✓ | int-21 | full |
| 32 | R-TUI-040.12/3 | H `tui_040_12_3_…` | `4`, double click | field `None`, 0 marked | ✓ | int-21 | full |
| 33 | R-TUI-040.12/4 | H `tui_040_12_4_…` | `/19TOOL` twice, go-to `0x50` between | second hit (`0x00C0…`) is the second row; field `None`; 0 marked | ✓ | int-21 | full |
| 34 | R-TUI-040.12/5 | H `tui_040_12_5_…` | as #33, A2L | as #33 | ✓ | int-21 | full |
| 35 | R-TUI-040.12/6 | H `tui_040_12_6_…` | as #33, MAC | as #33 | ✓ | int-21 | full |
| 36 | R-TUI-040.12/7 | `test_tui_goto_marker.py` ×3 | actions called | the field, not paint | — | **none on the final tree**: int-16 (`c9513e1c`), int-02 (QA-2) | partial |
| 37 | R-TUI-007.3/1 | H `tui_007_3_1_…` | 1 000 rows; go-to row 151; `.` | first row = row 350 | ✓ | int-21 | full |
| 38 Δ | R-TUI-007.3/2 | `test_tui_app.py::test_hex_page_actions_only_work_in_main_view` | `action_hex_page_*` called, `update_hex_view` stubbed, `current_file` assigned | `_hex_window_start` 5, then 0 (a field) | — | **none on the final tree**: int-16, int-02 (QA-2) | full → **partial** (QA-5) |
| 39 | R-TUI-007.5/1 | H `tui_007_5_1_…` | go-to row 949; `.` ×3 | first row = row 948 after each `.` | read right after the press (QA-6) | int-21; M-P RED (int-08) | full |
| 40 | R-TUI-007.8/1 | H `tui_007_8_1_…` | page size 3 by `_apply_viewer_setting` (QA-8); `.` ×2 | `[0x1000, 0x8000, 0x8010]` → `[0x8020]` → `[0x8020]` | 2nd read right after the press (QA-6) | int-21 | full |
| 41 | R-TUI-007.9/1 | H `tui_007_9_1_…` | go-to row 949; load fixture three (`load_selected_file`, QA-8) | rows `0x8000`, `0x8010`, `0x8020`; exactly 3; no `showing from` | ✓ | int-21 (and int-12); M-R1 RED (int-18a) | full |
| 42 | R-WS-LOADED.18/1 | F `ws_loaded_18_1_…` | `[u]` button press (focus left) | newest `Unloaded MAC.`; `#status_text` `Unloaded MAC.` | message waited; status read after `settle` (QA-6) | int-21 | full |
| 43 | R-WS-LOADED.18/2 | F `ws_loaded_18_2_…` | `U` | as #42, `Unloaded all artifacts.` | as #42 | int-21 | full |
| 44 | R-WS-LOADED.18/3 | F `ws_loaded_18_3_…` | `[u]` primary | `Unloaded primary image.` | as #42 | int-21 | full |
| 45 | R-WS-LOADED.18/4 | F `ws_loaded_18_4_…` | `[u]` A2L | `Unloaded A2L.` | as #42 | int-21 | full |
| 46 | R-WS-LOADED.13/1 | F `ws_loaded_13_1_…` (+ 2 existing) | `[u]` MAC, then `U` | newest each; each painted exactly once | ✓ | int-21; `test_unload_feature.py` int-16 only | full |
| 47 | R-WS-LOADED.14/1 | F `ws_loaded_14_1_…` | `U`, fresh app | newest `Nothing to unload.`; status `Ready.` | ✓ | int-21 | full |
| 48 | R-WS-LOADED.14/2 | F `ws_loaded_14_2_…` | A2L only; `U` | `Unloaded all artifacts.`; A2L slot `(none)` | ✓ | int-21; standing guard (M15 keeps it GREEN) | full |
| 49 | R-WS-LOADED.16/1 | F `ws_loaded_16_1_…` | `[u]` primary | `Loader 0 err` or absent; `bad.s19` in no slot; no `integrity notices` | ✓ | int-21 | full (QA-7) |
| 50 | R-WS-LOADED.16/2 | F `ws_loaded_16_2_…` (+ unit) | `[u]` primary, no MAC | no file; 3 views `No file loaded.` | ✓ | int-21; standing guard | full |
| 51 | R-WS-LOADED.16/3 | F `ws_loaded_16_3_…` | `[u]` primary, `firmware_issues.mac` | loader errors == the MAC-only reference (asserted 2) | ✓ | int-21 | full |
| 52 | R-WS-LOADED.19/1 | F `ws_loaded_19_1_…` | `ctrl+s` dialog, click Save | `Saved project to`; MAC in `P6`; no `.s19`/`.hex`; no image SHA-256; no `unloaded_primary` | ✓ | int-21 | full |
| 53 | R-WS-LOADED.19/2 | F `ws_loaded_19_2_…` | as #52, no unload (control) | `P7/unloaded_primary.s19` SHA-256 = image | ✓ | int-21 | full |
| 54 | R-WS-LOADED.20/1 | F `ws_loaded_20_1_…` | Patch entry by `request_action` (precondition); `p`, Load dialog, Enter | title `Replace firmware.mac?`; no `unloaded_primary` in title or body | ✓ | int-21 | full (QA-8) |
| 55 | R-TUI-012L.8/1 | F `tui_012l_8_1_…` | load (QA-8) | status and newest = `Loaded fwgpj.s19 (S19 only)`; 0 bad characters | ✓ | int-21 | full |
| 56 Δ | R-TUI-012L.8/2 | F `tui_012l_8_2_…` | MAC, then image | status ends `+MAC: mx.mac)`; 0 bad characters in status + newest; **newest not asserted to be the load line** | ✓ | int-21 | full → **partial** (QA-4) |
| 57 Δ | R-TUI-012L.8/3 | F `tui_012l_8_3_…` | no-terminator S19 | status starts with the painted prefix; as #56 | ✓ | int-21 | full → **partial** (QA-4) |
| 58 | R-TUI-012L.8/4 | F `tui_012l_8_4_…` | case 08 | status exact; the line among painted lines | ✓ | int-21; standing guard | full |
| 59 | R-TUI-012L.8/5 | F `tui_012l_8_5_…` | 130-character name | status = `Loaded ` + 119 + `…` + ` (S19 only)` | ✓ | int-21 | full |
| 60 | R-SHELL-STATUS.7/1 | F `shell_status_7_1_…` | Save dialog; `U`; `p` Load dialog, Enter | status exact `Loaded project 'PB' -> fwgpj.s19`; 0 bad | ✓ | int-21 | full |
| 61 | R-SHELL-STATUS.7/2 | F `shell_status_7_2_…` | as #60 + MAC | `… -> fwgpj.s19 + mx.mac` | ✓ | int-21 | full |
| 62 | R-SHELL-FOCUS.2/1 | F `shell_focus_2_1_…` | `2` | `window_help_a2l` with a region, inside `#screen_a2l`, held | ✓ | int-21 (and int-12); M-R4 RED (int-18c) | full |
| 63 | R-SHELL-FOCUS.2/2 | F `shell_focus_2_2_…` | palette action; Esc | Workspace; `files_list` | ✓ | int-21 | full |
| 64 | R-SHELL-FOCUS.2/3 | F `shell_focus_2_3_…` | palette action; `3` | `mac_page_prev_button` inside `#screen_mac` | ✓ | int-20e, int-21; RED int-20 | full |
| 65 | R-SHELL-FOCUS.2/4 | X `test_tc_b97_64_…[rail]`, `[none]` | `]` | `fx_panel` polled; `c` confirms 1 | ✓ | int-21 | full |
| 66 | R-SHELL-FOCUS.2/5 | F `shell_focus_2_5_…` ×12 | each rail key | focus is the target **or inside it** (QA-7); target shown | ✓ | int-21; `[mac]` int-20e, RED int-20; `[a2l]` RED int-18c | full |
| 67 | R-SHELL-FOCUS.2/6 | F `shell_focus_2_6_…` | `action_show_screen("workspace")`, Enter with no await | focus `None` synchronously; `files_list`; 0 `Validate:` | ✓ | int-21 | full |
| 68 | R-SHELL-FOCUS.2/7 | F `shell_focus_2_7_…` | two actions, no await (QA-8) | `mac_page_prev_button`, held | ✓ | int-20e, int-21; RED int-20 | full |
| 69 | R-SHELL-FOCUS.3/1 | F `shell_focus_3_1_…` | `[u]` focused, Enter key | `Unloaded MAC.`; `files_list` with a region | ✓ | int-21 | full |
| 70 | R-SHELL-FOCUS.3/2 | F `shell_focus_3_2_…` | focus `None`; `U` | the Workspace fallback, computed from the tree; none in Split / Join | ✓ | int-21 | full |
| 71 | R-SHELL-FOCUS.4/1 | F `shell_focus_4_1_…` | `[u]` MAC, focus left on `files_list` | `files_list` held; none in Split / Join | ✓ | int-21 (and int-12); base RED int-19c; M25 cannot fail it | full |
| 72 | R-SHELL-FOCUS.4/2 | F `shell_focus_4_2_…` | rail item focused; `U` | rail item kept | read after 10 pauses, no re-assert (QA-6) | int-21 | full |
| 73 | R-SHELL-FOCUS.5/1 | F `shell_focus_5_1_…` | nothing loaded; `5` | target area 0 asserted; first shown non-text widget, else the rail item | ✓ | int-21 | full |
| 74 | R-SEG-OPEN.6/1 | F `seg_open_6_1_…` | `U` | after the fallback landing: none in Split / Join | ✓ | int-21 | full |
| 75 | R-SEG-OPEN.6/2 | F `seg_open_6_2_…` | load again (QA-8) | every `set_focus` recorded, none inside; ends `files_list` | ✓ | int-21 | full |
| 76 | R-SEG-OPEN.6/3 | F `seg_open_6_3_…` | `6`; `load_doc` and `apply_doc` posted (QA-8) | `Apply:`; byte written; none inside | ✓ | int-21; standing guard | full |
| 77 | R-SEG-OPEN.6/4 | F `seg_open_6_4_…` | Esc | hidden; none inside | ✓ | int-21; standing guard | full |
| 78 | R-SEG-OPEN.6/5 | F `seg_open_6_5_…` | `3` | as #77 | ✓ | int-21; standing guard | full |
| 79 | R-SEG-OPEN.1/1 | F `open_split_join` step of 4 nodes (+ `test_segment_split_window.py`) | palette action | `sje_table` focused with a region | ✓ | int-21; the existing file int-16 only | full |
| 80 | R-SEG-OPEN.7/1 | F `seg_open_7_1_…` | `[u]` MAC; `a`, `e`; sentinel `2` | 0 files under `splits`; no `Exported` / `nothing selected` | ✓ | int-21 | full |
| 81 | R-SEG-OPEN.7/2 | F `seg_open_7_2_…` | `U`; as #80 | as #80 | ✓ | int-21 | full |
| 82 | R-SEG-OPEN.7/3 | F `seg_open_7_3_…` | focus put on hidden `sje_table`; as #80 | as #80 | ✓ | int-21 | full |
| 83 | R-SEG-OPEN.7/4 | F `seg_open_7_4_…` | `a` (rows ticked, asserted), Esc, focus on hidden `sje_export`, Enter, sentinel | 0 files; no `Exported` / `nothing selected` | ✓ | int-21 | full |

## 4. Per row: thresholds (Linux)

"Arms" = the threshold's stimuli and observables; "runs" = 3/3 runs on the final tree, which no row meets yet (QA-1).

| Row | Arms met | Cases | Note |
|---|---|---|---|
| R-TUI-018.1 | yes | /1–/4, /6–/13 | The 80 × 24 main arm is a layout limit (BL-I10-2); the threshold names no size |
| R-TUI-018.2 | yes | /1–/3 | The x clause is exercised in the main view only; A2L and MAC share the helper (QA-7) |
| R-TUI-018.3 | yes | /2, /3 | Main arm `n/a — no shipped main-view jump has a target without a present row` (Inc 12 D-2) |
| R-TUI-018.4 | yes | /1 | Standing guard; M5 is its only failing evidence (pending) |
| R-TUI-040.4 | yes | /1–/3 | |
| R-TUI-040.8 | yes | /1–/4 | /2, /3 have no isolating mutant (QA-9) |
| R-TUI-040.11 | **no: 5 of 9** | /1–/5 | A2L empty and invalid, MAC empty and miss have no case (QA-3) |
| R-TUI-040.12 | yes | /1, /3–/6 (+ /7 partial) | |
| R-TUI-007.3 | yes | /3/1 + R-TUI-007.5/1 (the 949 arm) | /3/2 partial (QA-5); 007.3/1's `.` clause has no isolating mutant (QA-9) |
| R-TUI-007.5 | yes | /1 | |
| R-TUI-007.8 | yes | /1 | |
| R-TUI-007.9 | yes | /1 | |
| R-WS-LOADED.18 | yes | /1–/4 | |
| R-WS-LOADED.13 | yes | /1 | |
| R-WS-LOADED.14 | yes | /1, /2 | |
| R-WS-LOADED.16 | yes | /1–/3 | The "Issues Report" clause cannot hold a loader diagnostic (QA-7) |
| R-TUI-012L.8 | **no: 2 arms short** | /1–/5 | `+MAC:` and integrity-notice arms: "the newest message line =" unasserted (QA-4) |
| R-WS-LOADED.19 | yes | /1, /2 | |
| R-WS-LOADED.20 | yes | /1 | |
| R-SHELL-STATUS.7 | yes | /1, /2 | |
| R-SHELL-FOCUS.2 | yes | /1–/7 | |
| R-SHELL-FOCUS.3 | yes | /1 (+ /2) | |
| R-SHELL-FOCUS.4 | yes | /1, /2 | M25 can fail /2 only |
| R-SHELL-FOCUS.5 | yes | /1 | |
| R-SEG-OPEN.6 | yes | /1–/5 | |
| R-SEG-OPEN.7 | yes | /1–/4 | /3, /4 load case 08 S19 without the MAC the threshold heads its arms with (QA-10) |
| R-SEG-OPEN.1 | yes | /1 | |

## 5. E4 case-text changes: do they still meet their rows?

- **I-D8 (tester H F-1 … F-8, tester F 2–6): yes**, with one note.
  - **F-1:** the main arm at 100 × 30; at 80 × 24 the pane is 1 line, a product layout limit kept as BL-I10-2.
  - **F-2:** x has no range at 118 × 54 (QA-7).
  - **F-3:** the window move is the positive sign; the threshold names no status.
  - **F-4:** `19TOOL` has two hits.
  - **F-5:** the threshold names the marker-address field.
  - **F-8:** M-P and M-W are RED.
  - **F 2:** MAC first, then image, reaches the `+MAC:` arm. Its oracle is short (QA-4).
  - **F 3:** stronger: `nothing selected` added.
  - **F 4:** the loader-facts line is the observable (QA-7).
  - **F 6:** the Issues empty state.
- **I-D6 (R-SHELL-FOCUS.3/2, R-SEG-OPEN.6/1): yes.** R-SHELL-FOCUS.3's threshold is the `[u]` arm (/3/1). The fallback is computed from the requirement text, not read from the product.
- **E4-R2 (R-SHELL-FOCUS.4/1): yes.** The amended arm is met (base RED, int-19c). The arm cannot tell "keep" from "move to the target", because `files_list` is both. /4/2 carries M25, as the notes say.
- **E4-R4 (R-SHELL-FOCUS.2/1, /2/5 `[a2l]`): yes.** M-R4 is RED, int-18c.
- **E4-R6 (R-SHELL-FOCUS.2/3, /2/5 `[mac]`, /2/7) and the R-TUI-020.1 MAC node: yes.**
  - RED 4/4 on the pre-E4-R6 copy (int-20); GREEN in int-20e and int-21.
  - The threshold's MAC arm (I-D25) is met.
  - The landing's PgDn is pinned by `test_r_tui_020_1_mac_arm_…`, which waits for the landing inside `#screen_mac` before PgDn.
- **I-D9, I-D10 (nodes written at integration, case /8/5 added): yes.**

## 6. Windows

**No case node has a Windows-only arm, and none ran on Windows.**

- H, F and the cited existing nodes carry no platform skip or branch (grep).
- The one skip in this increment's nodes is the 80 × 24 main arm. It is a geometry skip, by name, on every platform.
- The Windows-only arms that int-14, int-16 and int-17 skipped belong to other files. They are not Inc 10a cases: junctions, share-mode locks, case-insensitive volumes and Win32 name rules (int-16: 187 skipped, 90 lines `SKIPPED`).
- **State: `not-run` (operator rule) for all 83 cases.** No Windows run is owed by this increment's rows.

## 7. Findings

| Id | Severity | Finding | Fix |
|---|---|---|---|
| QA-1 | MINOR (gate item) | **The 3/3-run threshold is met for no row on the final tree.** The case table defines every row's `3/3` as runs ("Each expected count is per run; threshold 3/3 runs"), and Inc 5's E5 met the same rule with three runs on the final tree (C-5). Final-tree runs: <ul><li>79 cases: 1 (int-21; the `[mac]` arm of /2/5 also int-20e);</li><li>R-SHELL-FOCUS.2/3 and /2/7: 2 (int-20e, int-21);</li><li>R-TUI-040.12/7 and R-TUI-007.3/2: 0.</li></ul>The other runs the Result cells cite (int-01, int-10, int-12) ran older trees. Those trees predate E4-R1 … R6, which changed every load and every rail-key landing these nodes go through | In E5's gate run (executor: the orchestrator), run H, F and X's TC-B97-64 two more times on the head tree. Print `CMD:` and the tree. Re-cite each Result as `executed 3/3 (int-21, <run>, <run>)` |
| QA-2 | MINOR | **Two cases, and the sets that support them, have no run on the final tree.** <ul><li>R-TUI-040.12/7 and R-TUI-007.3/2: their only nodes last ran in int-16 (`c9513e1c`), which lacks E4-R6 and Inc 12b.</li><li>Supplementary existing nodes, same: TC-007, `test_unload_feature.py`, `test_segment_split_window.py`.</li><li>Also not re-run on the final tree: the QC-BC set and the I-D13 importers beyond `test_at_i11_5_…` (the notes' §7.3 lists both), and the HLR-177c nodes (E4-R5's 3/3, int-13a–c on `c9513e1c`).</li></ul>E4-R6 moves the focus after `3` to Page Prev, so Enter after `3` now pages back (I-D23). 57 test files press rail keys from a pilot (I-D12's grep) | Run the QC-BC set (int-16's 121 files), the 4 importers and the HLR-177c nodes on the head tree in E5's gate run. Re-cite 040.12/7 and 007.3/2 |
| QA-3 | MINOR | **R-TUI-040.11 is met for 5 of its 9 arms.** The threshold reads "0 lines start with `> ` after a miss, an empty box or an invalid address, **in each of the three views**". The cases cover main ×3, A2L miss and MAC invalid. The A2L empty and invalid arms and the MAC empty and miss arms are separate branches, each with its own marker clear and re-render (`app.py:21565`, `:21579`; `:21639`, `:21664`). A defect in any of them passes every node | Parametrise `tui_040_11_4_…` and `_11_5_…` over the three inputs (`0xFFFFFFF0` / miss text, empty / `Goto address is empty.`, `zz` / `Invalid address format.`), each after the `[0x50]` marker precondition. Add cases R-TUI-040.11/6 … /9. Split M8 into one mutant per branch, each expected RED on its arm |
| QA-4 | MINOR | **R-TUI-012L.8/2 and /3 are short of their row.** The threshold reads "`#status_text` **and the newest message line** = the painted line … the same for the `+MAC:` and the integrity-notice arms". The two cases and nodes assert only the status suffix or prefix and "0 bad characters in status + newest". `set_file_status` scrubs the status again (`app.py:21702`), so the status clauses cannot fail under the row's negative control. Only the message line can, and the node never asserts that the newest line is the load line. A message line with a wrong name but no bad character passes. Today the load tail writes one message (`:18959`), so the check is not vacuous in practice, but the oracle is weaker than the row | Assert `newest_message(app) == status_text(app) == "Loaded three.s19 (S19+MAC: mx.mac)"` in /8/2, and the full expected line in /8/3 (the prefix plus `S19-NO-TERMINATOR`, as painted). Add "the newest message line =" to both cases' Expected. Show M18 and M19 RED on them. Mark → `full` |
| QA-5 | NIT | **R-TUI-007.3/2 is a unit node, not a drive.** `test_hex_page_actions_only_work_in_main_view` assigns `current_file`, stubs `update_hex_view` and calls the actions. It reads `_hex_window_start`, not the painted window. Same shape as /7's `partial` | Mark `partial` (done here), or add an H node: `write_rows(…, 12)`, page 5, then `.` and `,` as keys; wait for the first row at row 5, then row 0 |
| QA-6 | NIT | **Wait-rule deviations; none makes a node vacuous.** <ul><li>007.5/1 (3 presses) and 007.8/1 (its second press) read "window kept" right after `pilot.press`. `.` renders synchronously (`app.py:11295`), and M-P turned 007.5/1 RED, so the read sees the press.</li><li>F reads positive values after `settle()` (8 × `pause`) instead of polling them: `#status_text` in 18/x, the dialog title in 20/1. A slow paint fails, it does not pass.</li><li>4/2 reads the kept rail-item focus after 10 pauses and does not re-assert it after the landing, as 4/1 does.</li></ul> | When next touched: after each `.`, poll a sign (for example `_hex_window_start` unchanged for two refreshes, or a sentinel key); poll the status and title with `wait_until`; give 4/2 /4/1's `settle` + re-assert |
| QA-7 | NIT | **Oracle relaxations, kept `full`.** <ul><li>2/5 accepts a focus *inside* the target container (`focus_matches_target`). A landing on a text box inside `patch_editor_panel` would pass; its docstring promises a fallback branch the code does not accept.</li><li>018.2/2 and /3: `scroll_x == 0` holds trivially (no horizontal range at 118 × 54). The x reset is the same `scroll_home` helper the main arm proves.</li><li>16/1 accepts an absent loader-facts line. The threshold names "the Issues Report", which holds no loader diagnostic (`validate_artifact_consistency` takes no loader errors).</li><li>4/1 waits for `Unloaded MAC.` in the log, not as the newest line.</li></ul> | 2/5: exact id, except windows whose documented landing is a descendant (Map's region row), and assert it is not an `Input` / `TextArea`; fix the docstring. 018.2: measure the A2L and MAC panes at 80 × 24; if they have an x range, add x 10 there, else record `n/a — no horizontal range`. 16: drop "the Issues Report" from the threshold at the canon fold |
| QA-8 | NIT | **Stimulus routes that bypass the shipped control; each enters the tail the row is about.** <ul><li>Loads by `load_selected_file`, which no product code calls: R-TUI-007.9/1, R-TUI-012L.8/1–/5, R-SEG-OPEN.6/2. The Load dialog and the workarea list go through `_start_load_worker`, whose busy run owns `#status_text` until it ends (HLR-176d), and reach the same `_apply_prepared_load`.</li><li>`apply_doc` posted as a message: R-SEG-OPEN.6/3.</li><li>Page size by `_apply_viewer_setting`: 007.8/1; the case says "settings menu".</li><li>A project load through the Load dialog: 20/1; the case says "Workspace project list".</li><li>Two `action_show_screen` calls: 2/7; the case says "post `3`".</li></ul> | Name the entry point in each case's Inputs. Drive one arm of R-TUI-012L.8 and R-TUI-007.9 through the Load dialog or the workarea list, and assert after the busy run ends |
| QA-9 | NIT | **Mutant coverage.** <ul><li>E4 ran M-L, M-P, M-W, M-R, M-R1, M-R3–M-R6; M1–M30 are E5's (in progress).</li><li>No isolating mutant exists for: R-TUI-040.8/2 and /3 (the table has M9 for main only), R-TUI-007.3/1's `.` clause (the base formula also gives 350), and R-TUI-018.4/1 beyond M5.</li><li>M25 cannot fail 4/1; M23 may survive.</li></ul> | `E5-mutants.md`: add **M9b**, the A2L / MAC failure re-render from row 0 (`start = 0`), expected RED on 040.8/2 and /3. Add the per-branch M8 split (QA-3) and M18 / M19 on /8/2 and /8/3 after QA-4. Record 007.3/1's `.` clause as having no failing evidence beyond base |
| QA-10 | NIT | **Record hygiene.** <ul><li>Result cells name no executor, and they mix four trees without saying which is final.</li><li>`verified` is not one of the seven evidence words; read it as `executed`.</li><li>int-13a and int-14 print an empty `index tree` line; int-13b and c show `c9513e1c`.</li><li>R-SEG-OPEN.7/3 and /4 load case 08 S19 without the MAC the threshold heads its arms with (harmless: the export needs the image only).</li><li>The `02-test-cases.md` header still carries the int-01 era sentence "R-SHELL-FOCUS.4/1 is `failed` and STOPPED", corrected only two paragraphs later.</li></ul> | When the Result cells are re-cited (QA-1): name the executor and mark the final-tree run. Re-record or annotate int-13a and int-14 with their tree. State the S19-only precondition in R-SEG-OPEN.7's threshold, or load the MAC |

## 8. Not run by this audit

No test was run, and nothing that imports `s19_app` ran on this Windows PC. The only commands were:

- file reads and greps;
- git plumbing in a scratch index and object directory (§2: two tree recomputations, one blob written there);
- AST and text scripts under `python -I` (node counts, scenario-call check, case-table counts);
- `trace_check.py` under `python -I`.

The scratch folder was removed afterwards. The results cited are the E4 integrators' and the testers' runs (§2), none executed by this audit.

## 9. Totals

| | Before | After |
|---|---|---|
| Active cases | 83 (47 normal, 36 robustness); 3 withdrawn, no node | 83 |
| Coverage `full` / `partial` / `gap` | 82 / 1 / 0 | 79 / 4 / 0 |
| Marks changed | — | 3 (4 %): R-TUI-012L.8/2, /3, R-TUI-007.3/2 |
| Row thresholds, arms (Linux) | 27 claimed | 25 of 27 (R-TUI-040.11 5/9 arms; R-TUI-012L.8 two arms short) |
| Row thresholds, 3/3 runs on the final tree | claimed | 0 of 27 (1 run for 79 cases, 2 for 2, 0 for 2; QA-1) |
| Results on the final tree | 83 `verified (linux, …)` | 81 `executed` (int-21; 4 also int-20e); 2 with no final-tree run (QA-2) |
| Windows | `not_run` | `not-run` for all 83; no Windows-only arm |
| Cases or nodes to add | — | QA-3: 4 cases (parametrise 2 nodes); QA-4: 2 assertions; QA-5: optional, 1 node; QA-9: M9b and the M8 split |
