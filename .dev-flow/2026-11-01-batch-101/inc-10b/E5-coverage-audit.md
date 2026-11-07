# Inc 10b — E5 coverage audit

Batch 2026-11-01-batch-101, increment 10b, design-first flow (`dev-flow-v3-beta`, E5: "someone who did not write the test cases re-checks their `full`/`partial` marks and coverage"). Mode: **validation** (an audit of marks, oracles, thresholds and results; no test was run). Auditor: the QA reviewer agent, which wrote no case, no node and no run. Worktree `<HOME>/Github/s19_app-b101-inc10`, branch `b101-inc10`, head `08ed10f`.

Inputs:
- the records: `01-requirements.md` (10 active rows), `02-test-cases.md` (19 cases + QC-TM-10b-1), `E4-integration-notes.md` (int-01 … int-07, I-D1 … I-D10, O-1), `E4-tester-w-notes.md`, `E1-rulings.md`, `codewire/graph-inc10b.md`, and the transcripts in `../evidence/inc-10b/`;
- the tests: `tests/test_b101_inplace_views.py` (**W**); the only other edited test file, `tests/test_id_registry.py` (`git diff 569e446 -- tests`: 272 → 273); and the support helpers the nodes call (`tests/support/b100_save_dialog.py`, `tests/support/timing.py`);
- the product code the nodes enter: in `app.py` the hook and its three new methods; in `segment_split_view.py`, `note_image_bytes_written` and `_dest_dir`.

`02-test-cases.md` is not edited; the marks below are this audit's proposal for it. Result words are the record's own (`verified` / `failed` / `not_run`, the v3 flow's), and each names its executor.

## 1. Verdict

**PASS-WITH-NOTES on coverage. The rows' `3/3` run threshold is not met (QA-1, MAJOR), and that holds E5's close until the 3/3 runs land.** The findings (§6) are 1 MAJOR (an owed run, not a test defect), 1 MINOR and 6 NITs.

- **Coverage: 19 `full`, 0 `partial`, 0 `gap`; no mark changed.**
  - All 19 nodes the cases name exist (19 named, 19 non-serial nodes defined, plus the QC-TM node; none extra).
  - Each drives a shipped writer: Patch Editor Apply, the entry Edit then *Write file*, or `ctrl+s` through the Save project dialog.
  - Each switches views the shipped way (rail keys, the palette) and asserts the case's exact values after a `wait_until` (§3).
- **Values: met on all 10 rows on the final tree. Runs: `3/3` met on none.**
  - On the final tree `9cf01b02…` only two GREEN runs of W count: **int-07** (all 19 nodes) and **int-01b** (R-SEG-PREV.21/1, /2, .22/1).
  - So 16 cases stand at 1/3 and 3 at 2/3 (§4).
  - int-01 ran tree `5a4fdd38…`. It had the same product and the same 18 node bodies, but it is not the final tree, so it does not count.
  - R-SEG-OPEN.6/3 (Inc 10a's case, owed a re-run at 10b's E5) has 1 run on the final tree (int-02).
- **The E4 case-text changes I-D3 … I-D7 still meet their rows** (§5.1).
  - I-D5 is a strengthening, measured both ways: under M-D the delivered body passes (int-06a) and the corrected body fails (int-06b).
  - I-D4 leaves a threshold text that no test can meet literally (QA-4).
- **O-1 rulings** (§5.2):
  - **A10-08: no node owed.** The arm cannot be reached through any shipped route, so its mutant is equivalent there (QA-3).
  - **R2-7: a case is owed (QA-2).** A written value wider than its column is a shipped-route defect. The mutant `update_width=False` passes all 19 nodes, and the nodes' cell oracle (`get_row_at`) could not see a cut value anyway.
- **Negative controls.**
  - Run and RED, one mutant at a time: M-A, M-B, M-C1–C3, M-D and M-F (int-06, int-06b).
  - The rest are `pending mutants` (QA-5). For those rows the only RED is base RED, which equals the control's behaviour.
  - R-TUI-004.8's window clause is RED under no run (QA-4).
- **Windows: no Windows-only arm; nothing owed by coverage.** All 19 cases stay `not_run` on Windows by the operator's rule (§5.3).

## 2. Evidence checks made by this audit

- **The trees are the commits.**
  - **Method.** Git plumbing only: a scratch index and a scratch object directory, the repository's objects as alternates, nothing written to the worktree, and no `s19_app` import.
  - **Final tree.** Base `09b4808`, plus the `08ed10f` blobs of the 11 files that `git diff --name-only 09b4808 08ed10f -- s19_app tests docs README.md` names, gives **`9cf01b02…`**. That is the tree of int-01b, int-02 … int-05, int-06, int-06b and int-07.
  - **Delivered tree.** The same with `aedeadd` gives **`298f77fe…`**, the tree of int-01a.
  - **The test blobs.** W's blob at `08ed10f` is `fc9a09a2…`, the blob int-06 and int-06b print. At `aedeadd` it is `f08184ad…`, the blob int-06a prints.
  - **What differs.** `git diff f08184ad fc9a09a2` touches only `test_r_seg_prev_22_1_…` (the `tab` step and its docstring), and `git diff aedeadd 08ed10f` touches no `s19_app` file. So int-01 (tree `5a4fdd38…` = delivered + I-D2) ran the final product and the final bodies of 18 nodes, but not the final tree.
- **Per-node results come from whole-file totals.**
  - Every transcript is `-q`.
  - int-07 reads `31 passed`. That is 19 W non-serial nodes plus 12 `test_id_registry.py` nodes (int-01a shows `1 failed, 11 deselected`). There is no skip, no deselection and no failure, so every W node passed.
  - int-01b (`-k "prev_22 or prev_21"`) reads `3 passed`: 21/1, 21/2 and 22/1.
  - Every int-* transcript prints the base, the index tree, `s19_app.__file__` (the clone or the mutant copy) and `CMD:`.
- **Base RED** (`red-01-tester-w-base.txt`).
  - The base is `09b4808` + Inc 10a, run with the delivered test file.
  - Run 1 reads `18 failed, 1 passed`. The pass is R-SEG-PREV.21/2, the standing guard. Each failure line names the painted value.
  - In run 2 the QC node fails on the missing method.
- **Mutants** (int-06, int-06a, int-06b). Each run used a mutant copy of the final tree with the exact edit printed, one mutant per run. Each mutant is RED at the clause it targets: test lines 798, 877, 1081, 1135 and 1250, and the M-F wait.
- **Executors.**
  - int-01 … int-07: the E4 integrator (Opus) on the LAN Linux laptop.
  - red-01: tester W (Sonnet) on the LAN Linux host.

  This audit executed none of them.
- **Product routes read, not run.**
  - **The hook.** `_note_image_bytes_written` calls the three notices outside every `try` (`app.py:18801-18815`). Its three callers are unchanged.
  - **The export home.** It is `workarea/splits/` or the project's `splits/` (`segment_split_view.py:1661-1670`). The work area lies under the node's `tmp_path/app`, so `joined_files(tmp_path)` sees an export wherever the destination points (I-D7 holds).
  - **A focus address.** In `update_hex_view` it clears the go-to marker (`app.py:20232-20233`) and resets the scroll (`:20251-20252`). The start row it computes keeps one row above the target (`_row_start_for_near_top_focus`, `context_rows=1`, `:20271`). §5.1 and QA-4 use this.
- **Waits.**
  - Every assertion that a state did not change follows a `wait_until` on a positive state in the same node.
  - A `settle()` comes before such an assertion only after a positive wait (R-SEG-PREV.22/1).
  - The Save project dialog helper (`b100_save_dialog.wait_for`) is a bounded wall-clock poll inside the shared driver, not a single `pause()`. The node's own `wait_until` on `Saved project to` follows it.
- **trace_check.** Run as `python -I …/dev-flow-v3-beta/trace_check.py --req …/inc-10b/01-requirements.md --base 569e446 --src s19_app`; it reads text and git only. It reports `1 US, 10 active requirements (0 withdrawn), 1 gap`. The gap is `EVID` (no `04-validation.md` yet), as at E4.

## 3. Per case

Node names drop the `test_r_` prefix. "Route" names the stimulus. Some preconditions are set by API: `load_selected_file`, `load_a2l_from_path`, `DataTable.scroll_to` / `move_cursor`, the filter menu's `index`, and fields set by value. They are accepted as preconditions, not stimuli (QA-7). "Sign" is the repaint sign of I-D6. Δ marks a case whose text E4 corrected.

| # | Case | Node (W) | Route | Oracle | RED shown | GREEN on final tree | Verdict |
|---|---|---|---|---|---|---|---|
| 1 | R-A2L-048/1 | `a2l_048_1_apply_shows_in_the_tag_table` | key `6`, path field, Load, Apply; key `2` | yes: (`147`, `147`) waited for; the precondition (`108`, `108`) and the byte `6C` asserted | base (`108`, `108`); the cache-kept mutant pending | int-07 | full · verified (linux, int-07; E4 integrator) · 1/3 |
| 2 | R-A2L-048/2 | `a2l_048_2_save_project_commit_…` | apply; entry Edit to `55` (image `93` asserted); key `2`; `ctrl+s` dialog | yes: (`85`, `85`) waited for with the A2L Explorer displayed, no re-show | base (`108`, `108`) | int-07 | full · as #1 |
| 3 | R-A2L-048/3 | `a2l_048_3_save_back_…` | as #2 up to the Edit; JSON tab clicked, *Write file* waited for shown, then pressed; key `2` | yes: (`85`, `85`); image `55` asserted | base | int-07 | full · as #1 |
| 4 | R-A2L-049/1 | `a2l_049_1_first_shown_row_is_kept` | apply, after the round-trip control | yes: `scroll_y` 30, the same tag at it, the same listed tags, all after the sign (`147`) | sign on base; the clause under M-A (`scroll_y 0, was 30`) | int-07 | full · as #1 |
| 5 | R-A2L-049/2 | `a2l_049_2_…_with_a_value_filter` | as #4, with the Raw filter `1` (more than 41 rows and `VALUE_0001` listed, both asserted) | yes, as #4 | sign on base; M-A | int-07 | full · as #1 |
| 6 | R-A2L-105/1 | `a2l_105_1_highlighted_row_is_kept` | apply, after the round-trip control | yes: cursor 40, the same tag; the card names it and equals its text before | sign on base; M-A (`the cursor moved to row 0`) | int-07 | full · as #1 |
| 7 | R-A2L-106/1 | `a2l_106_1_value_filter_rows_stay_listed` | Raw filter `108`; apply | yes: listed with (`147`, `147`) (waited for); the row count and `tags a-b / T` unchanged | base (`108`); M-F (`paints None`) | int-07 | full · as #1 |
| 8 | R-TUI-004.7/1 | `tui_004_7_1_…_main_hex_view` | apply; key `1` | yes: `0x8010` = `FF FF FF AA FF FF FF FF`; the painted rows unchanged | base (`FF FF FF FF …`); the re-render-removed mutant pending | int-07 | full · as #1 |
| 9 | R-TUI-004.7/2 Δ I-D3 | `tui_004_7_2_…_a2l_hex_view` | apply `11`; Edit to `AA` (image `11` asserted); *Write file*; key `2` | yes: the `#alt_hex_view` row; rows unchanged; `AA` can come only from the save-back | base | int-07 | full · as #1 |
| 10 | R-TUI-004.7/3 | `tui_004_7_3_…_mac_hex_view` | document loaded, not applied (`FF` asserted); `ctrl+s`; key `3` | yes: the `#mac_hex_view` row; rows unchanged | base | int-07 | full · as #1 |
| 11 | R-TUI-004.8/1 | `tui_004_8_shown_window_is_kept[main]` | go-to by `g` and keys; `scroll_to` (10, 40); round trip; apply; key `1` | yes for the case: first rows `[0x950, 0x960]` and the scroll unchanged, after the written byte at `0x965`. The reached scroll is asserted `> 0`, not `== (10, 40)` (QA-4) | sign on base; the scroll clause under M-B (`(0, 0), was (10, 40)`); the window clause under none (QA-4) | int-07 | full · as #1 |
| 12 | R-TUI-004.8/2 Δ I-D4 | `…[a2l]` | as #11, key `2` | as #11; reached `(0.0, 40)` (int-06) | M-B (`(0.0, 0), was (0.0, 40)`) | int-07 | full · as #1 |
| 13 | R-TUI-004.8/3 Δ I-D4 | `…[mac]` | as #11, key `3` | as #12 | M-B | int-07 | full · as #1 |
| 14 | R-TUI-004.9/1 | `tui_004_9_1_markers_survive_a_write` | a go-to in each view; round trip; apply; keys `1`, `2`, `3` | yes: the marked lines are `[0x960]` in each view, each read after that view's written-byte wait | sign on base; M-C1, M-C2, M-C3, one per view | int-07 | full · as #1 |
| 15 | R-SEG-PREV.21/1 | `seg_prev_21_1_…` | palette by keys; `p` `m` `g`; `down` / `space`; `ctrl+s` | yes: the blocks equal `BAND_TWO` (the plan the window hands the band, `#sje_band._blocks`); the painted state line `⚠ 2 B …`; the window still shown; `BB CC` written | base (the band keeps `conflict 1`) | int-01b, int-07 | full · verified (linux, int-01b, int-07; E4 integrator) · 2/3 |
| 16 | R-SEG-PREV.21/2 Δ I-D7 | `seg_prev_21_2_…` | opened and ticked on the unwritten fixture (`ready — e exports`); Esc; apply; palette | yes: `BAND_ONE`, offset 19, `⚠ 1 B …`, ticks `{0, 2}` | standing guard: passes on base by design (red-01) | int-01b, int-07 | full · as #15 |
| 17 | R-SEG-PREV.22/1 Δ I-D5 | `seg_prev_22_1_…` | as #15, plus `tab` to `#sje_export` (asserted) | yes: the focus id after is `sje_export`, read after the `BAND_TWO` wait | M-D: the delivered body passes (int-06a), the corrected body is RED (int-06b). Base RED by reading only: red-01 ran the delivered body (QA-8) | int-01b, int-07 | full · as #15 |
| 18 | R-SEG-EXP.15/1 Δ I-D7 | `seg_exp_15_1_…` | guard scene; `e`; `ctrl+s`; `e` | yes: `— e will ask` after the commit; `— e again to confirm` after `e`; 0 `*_joined*` files under the test folder | base (the arm survives); the arm-kept mutant pending | int-07 | full · as #1 |
| 19 | R-SEG-EXP.15/2 Δ I-D7 | `seg_exp_15_2_…` | as #18 up to the arm; Esc; key `6`, Apply; palette; `e` | yes: `— e will ask` on the open, armed after `e`, 0 files | base (armed on reopen) | int-07 | full · as #1 |

## 4. Per row: thresholds (Linux)

| Row | Threshold (values) | Cases | Values met | `3/3` on final tree | Note |
|---|---|---|---|---|---|
| R-A2L-048 | `6C` → `93`: Raw and Physical `147` | /1 (/2 and /3 are the other writers) | yes | 1/3 (int-07) | The widening arm (R2-7) has no case (QA-2) |
| R-A2L-049 | row 30 first shown; the same tag after; with no filter and with a Raw filter | /1, /2 | yes | 1/3 | |
| R-A2L-105 | cursor 40, the same tag, the card names it | /1 | yes | 1/3 | |
| R-A2L-106 | filter `108`: listed, `147`, `tags a-b / T` unchanged | /1 | yes | 1/3 | |
| R-TUI-004.7 | the `0x8010` row in the three panes after keys `1`, `2`, `3`; one case per writer; no jump | /1 … /3 | yes | 1/3 | Read as one pane per writer (each case pairs one writer with one key). The hook takes no argument and refreshes every pane, so no path depends on the writer and the pane together. The apply also paints all three panes in 004.8 and 004.9. No case reads a pane that was displayed during the write (QA-6) |
| R-TUI-004.8 | go-to `0x960`, scroll (10, 40); write at `0x965`; first row `0x950` and the scroll kept | /1 … /3 | yes, with I-D4 | 1/3 | The threshold's x 10 cannot be reached in the A2L and MAC panes, and its text is not amended. The window clause is RED under no run (QA-4) |
| R-TUI-004.9 | one `> ` line per view, at `0x960` | /1 | yes | 1/3 | |
| R-SEG-PREV.21 | a commit while displayed: `BAND_TWO`, `⚠ 2 B …` | /1 (/2 is a regression case) | yes | 2/3 (int-01b, int-07) | The row names "the stats line", but the threshold gives it no value (QA-6) |
| R-SEG-PREV.22 | the focus before = the focus after | /1 | yes (I-D5) | 2/3 | |
| R-SEG-EXP.15 | disarmed by a commit while displayed and by a hidden apply then reopen; the next `e` arms, 0 files | /1, /2 | yes | 1/3 | |
| *(Inc 10a)* R-SEG-OPEN.6/3 | as its row | — | — | 1/3 (int-02, whole-file total) | Its re-run is owed at 10b's E5 (`E1-rulings.md` §1) |

## 5. Rulings

### 5.1 The E4 case-text changes

- **I-D3 (R-TUI-004.7/2): meets the row.** The save-back is still the writer under test. The node shows the image holds `11` before and `AA` after, and the pane paints `AA`. The row's "one case per writer" holds.
- **I-D4 (R-TUI-004.8/2, /3): meets the row's statement, not its threshold text.**
  - The A2L and MAC panes have no horizontal range at 118 × 54 (Inc 10a F-2), so their x can be neither kept nor lost.
  - Comparing the reached scroll `(0.0, 40)` before and after the write is therefore the whole observable there.
  - The threshold still reads "(10, 40) in each view", which no test can meet. Amend it (QA-4).
- **I-D5 (R-SEG-PREV.22/1): a strengthening, measured both ways.** int-06a shows the delivered body passing under M-D, and int-06b shows the corrected body failing under it. The threshold is unchanged.
- **I-D6 (the repaint sign): meets the rows, with one exception.** Each of the 8 sign-first nodes, and 106/1's listing clause, is shown RED at its own clause under the row's negative control (int-06, int-06b). The exception is R-TUI-004.8's window clause (QA-4):
  - The row's own control is a re-render that jumps to the written address `0x965`.
  - `0x965` lies in the go-to row `0x960`, and the jump keeps that row second, so the window stays at `0x950`. The jump only resets the scroll and clears the marker.
  - M-B, which was run as a scroll reset only, catches that at the scroll clause; the marker half belongs to M-C.
  - No run shows the window clause failing.
- **I-D7 (R-SEG-PREV.21/2, R-SEG-EXP.15): meets the rows.** The `*_joined*` scan covers every export home (§2).

### 5.2 O-1: the two graph examples with no case

**A10-08 — "no `#check_editor_panel` → the three notices still run": no node owed.**
- The panel is composed once, in the Check Editor section (`app.py:4779`).
- `App.query_one` searches the default screen, not the active one (Textual 8.2.8, `textual/app.py:941-943`). So the query finds the panel even while the Save project dialog is the active screen.
- On the three shipped writers the `checks = None` arm cannot run. The mutant "back to `except Exception: return`" is equivalent on every shipped route. Only a headless path that calls the hook without composing the app reaches the arm.
- Record it so in `E5-mutants.md`, and mark the graph example as a design note, since it cites no case (QA-3).
- Two other graph examples cite no case either. Neither has an observable beyond "no raise":
  - `(no A2L)` is executed by the 9 nodes that load no A2L, and a raise in the hook would fail them.
  - Whether the unset-`_alt_first_visible_address` arm runs is not established by this audit.

**R2-7 — a written value wider than its column: a case is owed (QA-2).**
- The A2L table's columns are auto-width (`add_columns` with no width, `app.py:8781-8800`).
- In Textual 8.2.8 a column widens on a cell update only with `update_width=True` (`textual/widgets/_data_table.py:909-911`). It is painted at its stored `content_width` (`:246-248`).
- So without the flag, a wider value is cut to the column's old width. `False` is the call's default, so dropping the flag is the natural defect.
- Whether the cut shows a leading part of the number (`655` for `65535`) depends on the app's `Text` overflow, which this audit did not measure. Either way the painted cell would not read the written value, and that value is what R-A2L-048 states.
- Every write in the catalogue keeps or narrows the width (`108` → `147`, `108` → `85`). So `update_width=False` passes all 19 nodes.
- `raw_phys` reads `get_row_at`, the stored cell, which holds the full value even when the painted cell is cut. A widening node must therefore read the painted line, or at least the column's width.
- The synth generator emits UWORD, ULONG, SWORD and SLONG objects (`tools/synth/make_release_case.py:97-99`), so the case can be built on case 08.

### 5.3 Windows

No W node branches on the platform or skips. No node writes outside `tmp_path`, and none depends on links, locks or case folding. **No Windows-only arm, so coverage owes no Windows run.** The 19 cases stay `not_run` (Windows) by the operator's rule. This audit ran nothing that imports `s19_app` on the Windows PC.

### 5.4 QC-TM-10b-1 (not a coverage item)

- **Result: executed** in int-05 by the E4 integrator, on the final tree in the serial lane: `0.023 s / 1.000 s`, margin 97.7 %.
- **The node** wraps the real method on the app instance and times one real apply. It is marked `serial_timing` and calls `report_margin`.
- **Scale.** The A2L measured is the generator's fixed 462-object inventory, the same as case 08's. So the figure bounds 462 tags only (I-D8's residual) and says nothing about a larger real A2L.

## 6. Findings

| Id | Severity | Finding | Fix |
|---|---|---|---|
| QA-1 | MAJOR (a gate item; not a test defect) | **No row meets its `3/3` run threshold on the final tree.** On `9cf01b02…` only int-07 (19 nodes) and int-01b (3 nodes) count. 16 cases stand at 1/3; R-SEG-PREV.21/1, /2 and .22/1 stand at 2/3. int-01 ran tree `5a4fdd38…` and does not count. R-SEG-OPEN.6/3 (Inc 10a) has 1 run on this tree (int-02). E4 listed the 3/3 runs as not run | **Executor: the orchestrator**, on the LAN Linux host, never the Windows PC. Run W's 19 non-serial nodes 3 times on the commit's tree, and `tests/test_b101_unload_focus.py -k seg_open_6_3` 3 times. Use a fresh process for each run, and print `CMD:`, the index tree and `s19_app.__file__` as int-07 does. Cite each run (e5-01 … e5-03) in the Result cells. If QA-2's case is folded in, run after it lands, because it changes the tree |
| QA-2 | MINOR | **R2-7 has no case, and its mutant survives** (§5.2). A Raw or Physical value written wider than its column would be painted cut, so the cell would not read the written bytes. `update_width=False` (the call's default) passes all 19 nodes, and the nodes' cell oracle cannot see a cut | Add **R-A2L-048/4** (robustness): case 08 + A2L, key `2`; a filter or page on which every shown Raw cell is narrower than the value to be written; apply a UWORD or ULONG tag's bytes for a wider value (e.g. `FF FF` → `65535`); key `2`. Expected: that row's **painted** line holds the full value; the column's `content_width` is at least the value's width; the first shown row and the cursor are unchanged. Add mutant **M-W** (`update_width=False`), expected RED. Base is RED at the value. Cite the case id in `graph-inc10b.md`'s R2-7 example |
| QA-3 | NIT | **A10-08's arm cannot be reached by any shipped route; no node owed** (§5.2). E4's For-E5 list carries its mutant as "not run" | In `E5-mutants.md`, record "the Check Editor block back to `except Exception: return`" as **equivalent on shipped routes**, citing `app.py:4779` and Textual `app.py:941-943`. Mark the graph's A10-08 example (and `(no A2L)`) as design notes with no case. Optional: a headless unit node that removes the panel and calls the hook, marked `partial` (no product route) |
| QA-4 | NIT | **R-TUI-004.8 has three gaps.** (a) Its window clause is RED under no run: on this geometry the row's jump control lands on the same window, and M-B is a scroll reset only (§5.1). (b) The scroll reached before the write is asserted `> 0`, not equal to the case's (10, 40) or (0, 40); int-06 prints the values reached, but no assertion pins them. (c) After I-D4 the threshold text still says "(10, 40) in each view" | (a) Add mutant **M-B2**: `start_row=None` in the A2L or MAC re-render, or `_hex_window_start = 0` before `update_hex_view()`. It is expected RED at the window clause. (b) In the node, assert the scroll equals (10, 40) for `main` and (0, 40) for `a2l` and `mac`. (c) Amend the threshold to "(10, 40) where the pane has a horizontal range, else (0, 40)" |
| QA-5 | NIT | **Mutants still pending.** For these rows the only RED evidence is base RED, which equals the control's behaviour. The mutants: (1) the hex re-render removed from the hook (004.7/1–3); (2) the enrichment cache kept (048/1–3, 106/1); (3) `_bump()` → `_sync()` and the hidden branch → `pass` (EXP.15/1, /2); (4) the hook call removed from the save-back caller and from the commit caller (048/2, /3, 004.7/2, /3, PREV.21/1, EXP.15/1). No E5 mutant run exists yet | Run them in `E5-mutants.md`, one at a time in a copy, together with M-W (QA-2) and M-B2 (QA-4). Each must be RED at its node |
| QA-6 | NIT | **Arms the thresholds do not reach.** (a) R-SEG-PREV.21 names "the stats line", but neither its threshold nor any node reads that line after the commit. (b) No node reads a hex pane that was displayed during the write: every hex case writes with the Patch Editor in front. R-A2L-048/2's commit runs with the A2L Explorer (and its hex pane) displayed, but the node reads only the table | Optional. (a) In 21/1, assert the stats line after the commit (its `fill` changes with the band), and give the row a value for it. (b) In R-A2L-048/2, also assert that the `#alt_hex_view` row `0x00000000` holds `55` after the commit; this observes the displayed-pane path |
| QA-7 | NIT | **Route claims the nodes do not check.** Load, Apply and the entry Edit are pressed with `Button.press()` and no wait for the button to be shown. The route is plausibly shown: Load and Apply sit in docked rows (`screens_directionb.py:5236-5276`), and Edit sits in `patch_pane_inspector`, the switcher's initial pane (`:4980-5006`). The Inc 6 audit made a press on a hidden tab a route `partial`. The preconditions set by API, and the band read through `_blocks`, are accepted | Wait for `region.width > 0` before each press, as `write_file` does, or use `pilot.click`. No mark changes |
| QA-8 | NIT | **Record hygiene in `02-test-cases.md`.** (1) The Result cells cite int-01 without its tree (`5a4fdd38…`), and they name no executor. (2) R-SEG-PREV.22/1 claims "base RED at the re-planned band", but red-01 ran the delivered body; for the corrected body the claim is inferred, not run. (3) The Coverage column holds the test mark `full`, where the v3 flow's coverage word is `covered` (as Inc 13 writes it) | Cite `int-07 (final tree)` and `int-01b`, and name the E4 integrator. Mark int-01 as "same product, tree `5a4fdd38…`". On 22/1, write "base RED by reading (red-01 ran the delivered body)". Optionally, write `covered` in Coverage and keep `full` in Tests |

## 7. Evidence checklist

- ✓ **Mode declared:** validation (header).
- ✓ **Expected results:** exact values in all 19 cases (§3).
- ✓ **Edge and robustness:** 3 robustness cases (049/2, 106/1, EXP.15/2) and 1 standing regression guard (21/2). The width boundary is missing (QA-2).
- ✓ **Regression:** the QC-BC set, the other importers and the law guards ran on the final tree (int-02 … int-04, E4). This audit does not rule on them.
- ✓ **No real PII or secrets:** fixtures only (seed 20260001 and synthetic S19 files).
- ✗ **Executor in the record:** the record does not name the executor of each case's result (QA-8). Every run is traceable in its own transcript.
- ✓ **Layer B:** each output is read through the shipped surface: the painted Statics, the table cells, the stats lines and the files on disk. The band is read through the window's plan (QA-7).
- ✗ **Every named output observed:** not met. The R2-7 width (QA-2) and the stats line (QA-6) are not observed.
- ✓ **No unfilled template.**

## 8. Not run by this audit

No test was run, and nothing that imports `s19_app` ran on the Windows PC. The only commands were:

- file reads and greps, including the installed Textual 8.2.8 source, read as text;
- git plumbing in a scratch index and object directory (§2), removed afterwards;
- `trace_check.py` under `python -I`.

The results above come from the E4 integrator's runs (int-01 … int-07) and tester W's base runs (red-01).

## 9. Totals

| | Before | After |
|---|---|---|
| Active cases | 19 | 19, plus 1 owed (R-A2L-048/4, QA-2) |
| Coverage `full` / `partial` / `gap` | 19 / 0 / 0 | 19 / 0 / 0 |
| Marks changed | — | 0 |
| Row values met (Linux, final tree) | 10 claimed | 10 of 10 |
| Rows meeting `3/3` | not run (E4) | 0 of 10: 8 rows at 1/3; R-SEG-PREV.21 and .22 at 2/3. R-SEG-OPEN.6/3 at 1/3 (QA-1) |
| Negative controls RED | 7 mutants (int-06, int-06b) | 7 run. Pending: the 4 groups of QA-5, M-W (QA-2) and M-B2 (QA-4). A10-08's mutant is equivalent on shipped routes (QA-3) |
| Windows | `not_run` for 19 | `not_run` for 19; no Windows-only arm, none owed |
