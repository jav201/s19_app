# Inc 7 E4 — integration record (integrator I7, pass 1)

**STATE / NEXT STEP (pass 1 ends here for the context budget; 2026-11-14T05:06-06:00 from `date`).** Done: merge; 16 failures fixed (4 code, 12 test); rulings P-085 (b)-(e) and P-087 (a)-(d) applied; case files folded; trace_check 1 gap (EVID, expected before E5). L 111/111, V 116/116, AT 10/10 GREEN. **Ruling P-085 (a) hit its stop condition** (find box clipped at 120x30 and 160x40, both 118 columns or wider): the tail stays on the filter box; reported, not redesigned.
**Next (pass 2):** (1) `test_r_copy_07_7` arm e3a-24c is RED on the tree and GREEN on base (F-I7-3): fix the drag geometry test-side or rule it; (2) run `test_tc_b100_08_reset_runs_once_before_the_first_install` on base to tell pre-existing from Inc 7; (3) read the re-run-only logs still running when pass 1 stopped (`tree-RR-inc12`, `-b103refresh`, `-b102refresh`, `-inplace`, `-quit` in the runner scratch `~/work/zq-e4-7-int/logs/`, volatile); (4) laws on an exact clone with `main` = origin/main (`laws.sh` in the scratch; `test_id_registry.py` needs the clone) plus `tests/test_tui_app.py -k a2l` (P-087 b touched `_filter_a2l_tags`); (5) the two timing arms when the runner's 1-min load is < 2; (6) re-run trace_check and paste it; delete the runner scratch `~/work/zq-e4-7-int/` (PF-04).

Tree `b103-inc7`, base `63791549`. Integrator I7 (claude-opus-5-5), sole writer. Inputs: `E4-impl.md` (C7, tip `beaa6493`), `E4-test.md` + `02-test-cases-T.md` (T7, `b103-inc7-tests` tip `38e45ece`), orchestrator rulings P-085 (a)–(e) and P-087 (a)–(d) (kept outside the repo). Runner `<runner>`: HT-02 environment (HOME basename `<runner-home>`), `-p no:cacheprovider`, `-n` ≤ 2, `timeout 300`, `s19_app.__file__` the first line of every transcript; RED with the base tree `63791549` as cwd, GREEN with the tree (`git archive` of the named commit). Transcripts stayed on the runner scratch (deleted at the end, PF-04); their result lines are pasted here.

## Commits

| Step | Commit | What |
|---|---|---|
| 1 | `f131c85f` | `git merge --no-ff b103-inc7-tests`; `steps.log` conflict resolved, both sides in time order |
| 3 | `15e606f5` | code fixes (requirement wins), below |
| 3 | `6917b3b6` | test alignments (no assertion weakened), below |
| 3 | `223c1f0b` | two more test alignments after the first GREEN run (rows 15, 16) |

## Failures and fixes (step 3)

First run of T7's tests on C7's tree `f131c85f`: L `11 failed, 100 passed`; V chunks `1 failed, 23 passed` / `1 failed, 23 passed` / `2 failed, 22 passed` / `4 failed, 20 passed` / `1 failed, 19 passed`; AT `3 failed, 7 passed`. Each failure, its cause, side and requirement:

| # | Test(s) | Cause | Side | Requirement | Fix |
|---|---|---|---|---|---|
| 1 | `test_r_a2l_list_051_1` | the cap line `  similar names are shown for the first 10 missing names` was never painted | code | R-A2L-LIST.051 | `_paint_similar` appends it when more than 10 names are missing; `_request_similar` paints through `_paint_similar` (`15e606f5`) |
| 2 | `test_r_a2l_list_017_2` | counts line `● 0 found` with mode Invalid; the glossary "found count" is found + hidden | code | R-A2L-LIST.017/2, CTX "found count" | `_counts_line`: found = FOUND + HIDDEN (`15e606f5`) |
| 3 | `test_r_a2l_list_078_2`, `_078_3` | `AttributeError` in `_kind_cell(None)`: a duplicate of a missing name has no tag (32,768 × `a`) | code | R-A2L-LIST.078/2; .013–.015 | `list_row_cells` leaves the cells after Status blank when the entry has no tag (`15e606f5`); RED = the crash on `f131c85f` |
| 4 | `test_r_a2l_list_008_3`, `_023_2` | after the A2L unload the mode tag stayed `LIST` (chips and missing line not repainted) | code | R-A2L-LIST.008/3, .023/2 (E3A-08) | `update_a2l_view`'s unload branch calls `_paint_a2l_filter_chips()` (`15e606f5`) |
| 5 | `test_r_paste_1_4`, `test_r_a2l_list_034_3` | the helper's after-paste probe `box._take_paste(...)` was itself a hook call the spies recorded | test | R-PASTE.1/4, R-A2L-LIST.034/3 | probe opt-in (`probe=True` only in `test_r_paste_1_1`, `_1_2`, which assert it) (`6917b3b6`) |
| 6 | `test_r_a2l_list_084_1`, `_085_1`, `_085_3` | `worker_errors` returned `[CancelledError()]`: Textual 8 stores its own shutdown cancellation as `Worker.error` on every worker still running at exit, whatever the product does | test | R-A2L-LIST.084, .085 ("0 exceptions") | `worker_errors` leaves out `asyncio.CancelledError` only (`6917b3b6`); `app._exception is None` and "nothing painted" still asserted |
| 7 | `test_r_a2l_list_046_1`, `_046_2`, AT `test_at_b103_i7_2_window_live_status` | the ribbon is its own line `#a2l_list_ribbon` under the counts (T7 assumed one widget) | test | R-A2L-LIST.046; P-087 (c) | read counts + `\n` + ribbon (`counts_block`) (`6917b3b6`) |
| 8 | `test_r_a2l_list_075_2` | asserted 11 similar slots; only the first 10 missing names are ranked (R-A2L-LIST.051; ".. ≤ 20 in all") | test | R-A2L-LIST.075/2 | 10 slots and `NOSUCH_010` never ranked (tighter) (`6917b3b6`) |
| 9 | `test_r_a2l_list_030_1` | `highlight(1)` moved the cursor to the row it was on: no `RowHighlighted`, the card kept its placeholder (the same in text mode) | test | R-A2L-LIST.030/1 | `highlight` steps off the row first (`6917b3b6`) |
| 10 | `test_r_tui_069_6_1`, `_069_7_1…3` | the card is a `RichLog` (shipped `A2LDetailCard`), no `update` | test | R-TUI-069.6/.7 | `_paint_card` writes as `show_tag` does (`6917b3b6`) |
| 11 | `test_r_a2l_list_072_1` | read the first preparation (the empty list prepared before any A2L, R-A2L-LIST.072/2), not the one the attach starts | test | R-A2L-LIST.072/1 | read the call made after the attach (`6917b3b6`) |
| 12 | AT `test_at_b103_i7_2_window_live_status`, `_add_from_dropdown` | expected the text area's commas removed; no requirement normalises the pasted text | test | R-A2L-LIST.041, .057 | compare `parse_parameter_list(text)` with the names (`6917b3b6`) |
| 13 | AT `test_at_b103_i7_3_tab_completes` | read column 1 (`Length`); the shipped text-mode order is Address, Length, Tag | test | AT-B103-I7-3/2 | column 2 (`6917b3b6`) |
| 15 | `test_r_tui_069_7_1` (second run) | the 220x60 card is auto-height, grows to its cap 8 before it scrolls; T7 wrote `size.height + 4` lines (2 + 4) | test | R-TUI-069.7/1 ("4 lines longer than its height", wide cap 8) | count from the cap when the card has one (`223c1f0b`) |
| 16 | `test_r_a2l_list_072_1` (second run) | an empty list is also prepared on the way into the attach | test | R-A2L-LIST.072/1-2 | read the preparation that holds names (`223c1f0b`) |
| 14 | census `test_r_tui_044_1_18…`, `test_r_paste_18_8…`, `test_r_paste_19_1_and_33_1…` | 41 / 8 on the built tree | test | ruling P-085 (d) | counts set to 41 / 8 (49/49) with the reason in the census docstring (`6917b3b6`) |

## GREEN on `6917b3b6` (`223c1f0b` for the two V nodes of rows 15-16)

| File | Result | Load (1-min) |
|---|---|---|
| `tests/test_b103_label_list.py` | `111 passed in 40.16s` | 2.28 |
| `tests/test_b103_a2l_list_view.py` (5 chunks of 24) | `24 passed` / `24 passed` / `24 passed` / `1 failed, 23 passed` / `1 failed, 19 passed`; the two (`test_r_tui_069_7_1`, `test_r_a2l_list_072_1`) after `223c1f0b`: `4 passed` (with `069_7_2`, `_7_3`) | 2-5 |
| `tests/test_b103_a2l_list_at.py` | `10 passed in 86.69s` | ~4 |
| R1 `tests/test_b103_clipboard_core.py` | `85 passed, 2 skipped` (census 41 / 8) | 5.74 |
| R1 `tests/test_b103_clipboard_windows.py` | `77 skipped` (WinCI only; the find box is hit at its size 160x48 on the tree, probe below) | 4.88 |
| R2 `test_b103_clipboard_matrix.py -k a2l` / `test_b103_copy_paste_matrix.py` 5 cells / `test_b102_clipboard.py` | `1 passed` / `5 passed` / `20 passed` | ~4.9 |
| R2 `tests/test_b103_clipboard_tail.py` (not retargeted, ruling a) | `1 failed, 26 passed, 8 skipped`: `test_r_copy_07_7` (F-I7-3; on base `1 passed`) | 4.41 |
| R3 `tests/test_b100_session_reset.py` | `3 failed, 17 passed`: `tc_b100_09_domain…` and `…twelve_b…` pre-existing (P-038, `_right_gesture`; `twelve_b` now also lists the two Inc 7 names, both classified in `SNAPSHOT_EXCLUSIONS`); `tc_b100_08_reset_runs_once…` (`'install' is not in list`) not yet compared with base | 4.31 |
| R3 `test_tui_snapshot.py -k a2l` | `1 passed, 6 xfailed` (live mark F-R11-1) | 4.65 |
| R3 `test_id_registry.py` | `11 errors` = "could not locate the repository root" (needs a git checkout): pass 2 runs it on the clone | 4.67 |
| re-run `test_tui_directionb.py` 5 tc019/tc020 nodes | `5 passed` | 4.67 |
| re-run `test_b103_a2l_filter_teardown.py` | `1 passed` (P-002 guard kept) | ~4.5 |
| re-run `test_b103_inc12_tag_table.py`, the one-name filter files | running when pass 1 stopped (pass 2) | |

RED: on base `63791549` T7's runs stand (`E4-test.md`: L 108 errors + 1 failed, V 108 RED, AT 10 failed). The code fixes' RED is the first run on `f131c85f` (rows 1-4). Timing arms `R-A2L-LIST.078/3` and `.035` passed inside the file runs: **not decided (load)**, 1-min load 2.28 and above (HT-08).

## Rulings applied

- **P-085 (a) tail retarget: stop condition met, reported.** Probe (`Screen.get_widget_at` at the box's centre; no A2L, and case 08 loaded, give the same): on the tree `#a2l_tag_find_input` is hit at 118x54, 160x48 and 220x60, and is **clipped at 120x30 and 160x40** (centre outside the filter row: `<NoWidget>` / `Label#alt_hex_title`), also at 80x24, 80x30 and 100x30. On base it was clipped at 118x54 too, which is why T7's retarget went RED on base. 120x30 and 160x40 are 118 columns or wider, so this is **finding F-I7-1 (layout) against E3R2 "find controls in the filter row"**: the row is `layout: horizontal` with no wrap or scroll, so what does not fit is cut. Not redesigned; the tail stays on the filter box (`:472`, `:2702`) with this reason. Windows sites (WinCI, 160x48): the box is hit there on the tree and on base, so T7's retarget of those 14 sites stands (unverified until WinCI runs).
- **P-085 (b) R-A2L-LIST.076** U+0085: wording item 1 below.
- **P-085 (c) R-A2L-LIST.025/3:** T7 renamed the fixture tag before the mode-All arm (fixture fixed to the requirement); green; wording item 2.
- **P-085 (d) census:** counted on the built tree: 41 OsClipboardInput kinds (+ the paste window's `AddNameInput` `#a2l_list_add`), 8 multi-line boxes (+ `CappedTextArea` `#a2l_list_text`); counts and docstring changed with that reason; green.
- **P-085 (e)** no markup AST guard with a file list in `tests/`: MINOR, recorded only (P-026).
- **P-087 (a)** dropdown position: E5 capture round, nothing here.
- **P-087 (b)** `_a2l_mode_keeps` is the one source of truth (`_filter_a2l_tags` calls it; same predicate, `15e606f5`); `test_tui_app.py -k a2l` runs in pass 2.
- **P-087 (c)** tests aligned to the built ids (none renamed in code): paste window `#a2l_list_counts`, `#a2l_list_ribbon` (its own line), `#a2l_list_preview`, `#a2l_list_more`, `#a2l_list_missing`, `#a2l_list_similar`, `#a2l_list_note`, `#a2l_list_text`, `#a2l_list_add`, `#a2l_list_add_suggest`, `#a2l_list_apply`, `#a2l_list_cancel`, `#a2l_list_dialog`; viewer `#a2l_filter_mode_tag`, `#a2l_list_chips`, `#a2l_list_missing`, `#a2l_filter_suggest`, `#a2l_paste_list_button`, `#a2l_filter_all` / `_invalid` / `_inmem` (class `-on`), `#a2l_tags_filter_input`, `#a2l_tag_find_input`.
- **P-087 (d)** C7's not-run items: the two refresh files are queued (pass 2 reads them); write-route rows `.036/3-5` green in V (partial, T7); the 160x40 / 80x24 rows of V green; id registry in pass 2 on the clone.

## Findings for the orchestrator

- **F-I7-1 (layout; ruling a's stop-and-report):** find box clipped at 120x30 and 160x40 (above).
- **F-I7-2 (observation, operator-visible, for the E5 capture round):** in every probe the filter box and the find box get a 6-cell region with 0 content columns (both `width: 1fr` in a row whose buttons take the width), on base and on the tree.
- **F-I7-3 (regression, pass 2):** `test_r_copy_07_7` arm e3a-24c: at 118x54 the stacked layout puts `#alt_hex_view` at y 37 under the detail card; the arm's drag (2,1) -> (40,5) now selects the card's text too, so "three distinct lines" fails. Base passes. R-COPY.07/7 does not depend on the layout: a test-side geometry fix is expected, but the test is not in E1-slice's retarget list.
- **F-I7-4 (decision, DF-04 b):** a duplicate of a missing name shows blank cells after Status (it has no tag), as R-A2L-LIST.015 does for the missing name; before the fix it crashed the preview (32,768 names).
- Shipped behaviour, both modes: with the cursor on row 1 after a filter change the card keeps its placeholder until the cursor moves.

## Inc 7 wording list (DF-04 b; the orchestrator moves these)

1. **R-A2L-LIST.076** threshold: U+0085 cannot be in a pasted name (the I-5 parser splits there); only surfaces fed by A2L tag names (row of a found name, card, dropdown row) can show it. Example the missing line, preview row and similar line with a name without U+0085 (2 U+FFFD).
2. **R-A2L-LIST.025/3** last arm: "the same text with mode All, so nothing matches" needs "over an A2L with no tag of that name".
3. **R-PASTE.19/1** (and E3A-01 rows 6/7): 47/47 -> 49/49 text boxes (41 single-line, 8 multi-line) after Inc 7.
4. **R-A2L-LIST.015**: "a missing name" -> "a missing name or a duplicate of one" (F-I7-4).
5. **R-TUI-069.7** example: "4 lines longer than its height" -> "4 lines longer than its height cap (8 wide, 5 short; 14 rows stacked)".

## trace_check (repository root, after the `Files` paragraph of `01-requirements.md`)

```
python <skill>/trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-7/01-requirements.md --base 63791549 --src s19_app
EVID   no 04-validation.md beside .dev-flow/2026-11-05-batch-103/inc-7/01-requirements.md
trace_check: 4 US, 96 active requirements (0 withdrawn), checks run: US, CASE, TEST, SLICE, EVID, 1 gap(s)
```
The first run gave a second gap, `SLICE s19_app/tui/a2l_label_list.py changed since 63791549 and no requirement file names it` (the new module was named only in the slice); closed by the `Files (E4, integrator I7)` paragraph. The EVID line is expected before E5.

## For the next workers (at most 3 lines)
- Mutants: the `.084/.085` "after close" arms cannot see a removed `is_running` check, because `_work` swallows `RuntimeError` from `call_from_thread` (and `worker_errors` now ignores Textual's `CancelledError`); expect such mutants to survive unless the `except` goes too.
- New lines to mutate: the cap line in `_paint_similar`; found = FOUND + HIDDEN in `_counts_line`; `entry.tag is None` in `list_row_cells`; `_paint_a2l_filter_chips()` in the unload branch.
- Never decide the two timing arms above a 1-min load of 2 (HT-08).
