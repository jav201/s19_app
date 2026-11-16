# Inc 9 product fixes after E5 FAIL: F-X9-2 (diagnosed, stop-and-report), F-X9-5/6/7, W-8 (FX9b, relevo-13)

Model claude-opus-5-5 (software-dev). Tree `b103-inc9`, start tip `4c891ea9`. Rulings (orchestrator, PENDING P-098):
F-X9-2 MAJOR = product defect, fix to the requirement, .82/1's window includes the record stage, stop and report if the
fix needs a new process model, a pinned `codewire/` interface or files outside Inc 9's slice beyond the history refresh
call site; F-X9-5, F-X9-6, F-X9-7, W-8 small fixes test-first; F-X9-3, F-X9-8, F-X9-9 deferred to P-026.
Runner scratch `~/work/zq-fx9b/` (HT-02 env, HOME basename `<runner-home>` read from `RUNNER_HOME_NAME`,
`s19_app.__file__` atop every transcript, timing runs alone at `-n 0` once the 1-min load is < 2). Probes, scripts and
transcripts: `evidence-e4/fixes-fx9b/` (redacted: `~`, `<user>`, `<runner-home>`).

## State / next step
- F-X9-5, F-X9-6, F-X9-7, W-8: fixed, one commit each, every new node RED on `4c891ea9` and GREEN after; fresh clone
  inc9 321 / inc8 371 passed, laws 117 / 3 skipped / 2 base-identical failures.
- **F-X9-2: STOP AND REPORT (brief clause).** Measured cause below. Neither half can be fixed inside Inc 9's slice:
  the keys during an encode are slowed by any computing worker thread (GIL contention, not product UI work), and the
  record stage's 1.39 s UI-thread block is 85 % code outside Inc 9's slice (Inc 8's sheet, the ledger card, the JSON
  view). No product change was made for F-X9-2. Options with files and line counts: §F-X9-2 options.
- Next (orchestrator): choose an F-X9-2 option (O-A … O-F); 29_2 and 82_1 stay RED on the tree until then.

## F-X9-2 - keys during LARGE's preview / record encode (R-PE-BENCH.29/2, .82/1)

### Diagnosis (skill `diagnose`; probes on `4c891ea9`, scratch only, one run each; the typist is X9's `_typist`)
Each key is split into **wait** (the send from the input thread -> the sheet's action starts) and **action** (the action
runs, incl. the sheet's `_paint`). Sources: `probes/test_fx9b_probe*.py`; transcripts `p1-*`, `p2-*`, `p3-*`.

**1. Keys while a worker computes (29_2, and 82_1 before the encode returns).**

| Probe (load before) | Phase | keys | p50 | max | wait p50 / max | reading |
|---|---|---|---|---|---|---|
| `p1-arrival` (1.84) | preview encode, arrival at 27.6 s | 87 | - | 0.531 s | max 0.481 | the slow keys are WAITS during the encode; the arrival itself costs 0.015 s and no key near it is slow |
| `p2-arrival_swi-0` (1.78) | preview encode | 79 | 0.182 s | 0.484 s | max 0.362 | baseline of the what-if |
| `p2-arrival_swi-0.0005` (1.10) | preview encode, `sys.setswitchinterval(0.0005)` | 100 | 0.201 s | 0.391 s | max 0.367 | a 10x shorter switch interval leaves the waits as they are |
| `p3-phases` (1.86) | worker spins pure Python (no product code) | 19 | 0.161 s | 0.345 s | 0.104 / 0.289 | ANY computing thread gives the same latency ... |
| `p3-phases` (1.86) | the real encode | 148 | 0.159 s | 0.425 s | 0.117 / 0.376 | ... as the encode |
| `p3-phases` (1.86) | idle worker, 5 s after the arrival | 59 | 0.015 s | 0.110 s | 0.001 / 0.056 | the product's own key cost |

Reading: the key costs 0.015 s (p50) with the worker idle and ~0.16 s (p50, tails 0.35-0.53 s) while ANY worker thread
runs Python, the encode or a pure spin alike. The action itself is mostly 0.04-0.08 s (paint p50 0.045 s); the time is
spent waiting for the UI thread to run. This is CPython GIL contention between the UI thread and the worker; the
switch-interval what-if refutes the simple "5 ms handoff per loop turn" model, so the exact mechanism is not proven
(hypothesis: long C-level steps that do not yield, plus the UI loop's frame work being stretched). FX9's `spin` probe
showed the same class of effect but measured it with the vacuous `pilot.press` (2.2 s idle wait). The product's UI
thread does nothing wrong here; the bound is missed because the worker shares the interpreter. 29_2 is therefore a
tail-latency miss (0.53-0.56 s on a 0.5 s bound), load-sensitive.

**2. The record stage (82_1 after the encode returns).** Wall clock per part, no profiler (`p2-parts-0`, load 1.79;
cProfile `p1-record` for the call tree), all on the UI thread in ONE block:

| Part (file, owner) | Time | Note |
|---|---|---|
| `_stage_bench_record` total (`app/patch.py`, Inc 9) | **1.388 s** | the key sent just before it waited 1.81 s (`p2-parts-0`), 1.86 s with swi 0.0005 (`p2-parts-0.0005`) |
| - `ChangeService.stage_record` (Inc 9) | 0.019 s | |
| - `_refresh_patch_history_view` (`app/patch.py`, batch-48 et seq., shared with undo / redo) | 1.352 s | the parts below |
| -- `serialize_change_document` (`changes/io.py`) | 0.168 s | the JSON of a 1,048,576-value entry |
| -- `_render_before_after_card` (`patch_editor/entries.py`) | 0.238 s | reads `mem.get` for every address of the 1 MiB span (+ lead / trail) |
| -- `_show_document` -> `TextArea.load_text` (`patch_editor/document.py`) | 0.597 s | of which `TextArea.find_matching_bracket` **0.455 s**: Textual scans 3.1 M character locations for the bracket at the cursor of the read-only JSON view |
| -- `ArrayBenchSheet.set_document` -> Inc 8 `StagingSheet.set_document` (`patch_editor/sheet.py`, `definition_sheet.py`) | 0.339 s | Inc 8 `build_row` / `_staged_by_bytes` / `StagedOverlay` over every byte, then `_paint` 0.097 s incl. Inc 9's `_max_staged_delta` 0.089 s |
| After the block: `_paint` (Inc 9 `_delta_text` -> `_max_staged_delta` over 1 M values) | 0.261 s | on EVERY paint of a staged LARGE row with no edit, i.e. every key after the stage |
| After the block: `_render_before_after_card` again (DataTable `RowHighlighted`) | 0.521 s | |

Inc 9's own share of the 1.39 s block is 0.11 s (stage 0.019 + `_max_staged_delta` 0.089); the rest is code outside
Inc 9's slice. Even with every cheap fix (O-B + O-C + O-D below) the block stays ~0.6 s (serialize 0.17 + TextArea load
without the bracket scan ~0.14 + Inc 8 rows ~0.24), so meeting .82/1 also needs the refresh split into steps below
~0.4 s each with the event loop turning between them (O-E), or the rows' work moved off the UI thread.

### F-X9-2 options (none applied)
| Id | Change | Files (lines) | Effect (measured parts) | Gate |
|---|---|---|---|---|
| O-A | Run the bench encode (and decode) in a separate process (the worker thread only waits on it) | `bench_sheet.py` `_run_job` (~25) + a small module for the child entry (~40) | removes the contention of part 1 (keys back to ~0.015 s p50, the `idle` row) for 29_2 and 82_1's encode | **new process model** -> architect / orchestrator; pickling of `Definition` / overlay snapshot (1 MiB) per job |
| O-B | `TextArea(..., match_cursor_bracket=False)` on the read-only JSON view | `patch_editor/document.py:315-319` (1) | -0.455 s of the block | file outside the slice (batch-97 D3 view) |
| O-C | Read only the bytes the before/after card shows (it paints at most `row_cap` rows) | `patch_editor/entries.py:243-281` (~8) and maybe `screens_directionb/shared.py:466-575` (~4) | -0.238 s in the block, -0.521 s on the RowHighlighted after it | files outside the slice (batch-48 LLR-080) |
| O-D | Compute the staged max-Δ once when the staged values arrive (worker), not per paint | `definition_bench.py` (~6), `bench_sheet.py` (~4); BenchState gains one field | -0.089 s in the block, -0.24 s on every later key of a staged LARGE row | in Inc 9's slice; additive field of I-9.1 `BenchState` (pinned in `codewire/graph-inc9.md`) |
| O-E | Split the post-stage refresh into steps with the loop turning between them (`call_later` chain: rows / card / JSON / sheet) | `app/patch.py` `_refresh_patch_history_view` + `patch_editor/entries.py` `refresh_entries` (~20) | turns one 1.39 s block into steps of <= 0.6 s (<= 0.34 s with O-B, O-C) | shared refresh path of undo / redo / load (batch-48 writer census); files outside the slice |
| O-F | Inc 8 `set_document`: build only the changed rows / skip the per-byte staged scan for rows the entry does not touch | `definition_sheet.py` `build_row` / `_staged_by_bytes` (~15), `patch_editor/sheet.py:176-190` (~5) | -0.24 s | Inc 8 interface I-8.4 / I-8.5 (read-only for Inc 9) |

My recommendation: O-A for .29/2 and the encode window of .82/1 (the only option that removes the contention), and
O-B + O-C + O-D + O-E for the record stage (all small; O-E is what bounds the single block). Without O-A, .29/2 stays a
tail miss of ~10 % on a 0.5 s bound and is load-sensitive; no requirement text was weakened and X9's timer is unchanged.

## Small fixes (one commit each; RED on `4c891ea9`, GREEN after; `rg-red.txt` / `rg-green.txt`, `-n 2`)
RED run: **8 failed** (each on the defect it names); GREEN run: **8 passed** (same 8 nodes, fixed tree).

| Finding | Commit | Fix | Nodes (RED reason on `4c891ea9`) |
|---|---|---|---|
| F-X9-5 (the brief and E5 say R-PE-BENCH.18; the strip formula is CTX-PE-BENCH array row cells under R-PE-BENCH.11) | `7ad32e0d` | `bench_sheet._derive`: strip width = the Current width - 1 - the count's width - 1 | new `w_select::test_r_pe_bench_11_a_strip_of_more_columns_than_its_room_keeps_the_count_visible` (painted `████████████████ …·`: 16 blocks, count cut) |
| F-X9-6 | `ec054b7f` | `op_line`: the where stays whole; when name + where exceed Inc 8's 28-cell name label the name is cut with one `…` | new `b_detail::test_r_pe_bench_50_the_2d_array_name_keeps_its_where_whole` (29 > 28 cells) |
| F-X9-7 | `4d84dc78` | `definition_bench.count_text(n, word)`: singular for 1 in the New cell, the op line's `on <k> …` and the notices verdict | new `b_cells::test_r_pe_bench_15_one_changed_cell_or_point_is_singular`, `b_detail::test_r_pe_bench_66_one_notice_is_singular`; updated to the ruling: `b_detail` 50/2, 50/3, `w_stage` 15/16/18 (each RED on `1 pts` / `1 cells` / `1 notices`) |
| W-8 | `4c52ea99` | `bench_detail`: values None + a refusal + no decode running -> `✗ refused: <message>` (plain) in place of the decoding line | new `b_detail::test_r_pe_bench_21_a_refused_decode_says_refused_not_decoding` (showed `decoding 1048576 values …`; control: a new decode shows the decoding line again) |

Decisions recorded (memory "decide and record"): F-X9-6 keeps Inc 8's 28-cell label and cuts the name rather than
widening the label (the bar layout of Inc 8 at the 80-column floor stays as approved; the full name stays on the sheet
row); the alternative (a wider bench label) is for the operator's page. F-X9-7 also makes `1 pts` singular (`1 pt`):
same rule, same cell. W-8 covers a refused decode only: a job that RAISED (`_run_job` maps it to `None`) still leaves
the decoding line (no refusal to show) - open item below.

### Operator-visible text changes (old -> new), provisional for the final page (P-059)
| Where | Old | New |
|---|---|---|
| Current cell of a row with more grid columns than the strip room (VB1D, 40 elements, Current width 18) | `████████████████ …` (count cut, New `·` glued to it) | `████████ 40` |
| op line name, 2-D VAL_BLK x0..1, y0..1 | `VAL_BLK_DEF_0001[x0..1,y0..1` (label cut) | `VAL_BLK_DEF_00…[x0..1,y0..1]` |
| New cell, k = 1 | `1 cells` / `1 pts` | `1 cell` / `1 pt` |
| op line tail, k = 1 | `Set on 1 cells` / `Set on 1 pts` | `Set on 1 cell` / `Set on 1 pt` |
| op line verdict, one notice | ` ▲ 1 notices` | ` ▲ 1 notice` |
| bench after a refused decode | `decoding 6 values …` | `✗ refused: <message>` |

Requirement texts still read the plural for k = 1 (CTX-PE-BENCH op line and array row cells, R-PE-BENCH.50/2 case
`Set on 1 pts`) and W-8's line is not yet in R-PE-BENCH.21 / CTX: the canon edit is the orchestrator's (PP-06, P-026).

## Timing nodes on the fixed head `4c52ea99` (each alone, `-n 0`, `-m serial_timing`, load < 2 read before each)
Tree: `git archive 4c52ea99` (`scripts/chain4.sh`, log `transcripts/chain4-log.txt`). rtx shared with MU7; every run's
1-min load read before it was < 2 (the "after" load includes the run's own UI + worker threads).

| Node | Tree | Load before -> after | Result | Transcript |
|---|---|---|---|---|
| 29_1 | head | 1.57 -> 1.06 | **GREEN** 0.244 s (51.2 % margin) | `t-head-29_1.txt` |
| 29_2 | head | 1.06 -> 1.91 | **RED** `slowest press 0.560 s` (F-X9-2 open; X9: 0.561 s) | `t-head-29_2.txt` |
| 82_1 | head | 1.91 -> 2.66 | **RED** `slowest press 1.872 s` (F-X9-2 open; X9: 1.950 s) | `t-head-82_1.txt` |
| 20_1 | head | 1.61 -> 1.52 | **GREEN** 0.155 s (69.1 % margin) | `t-head-20_1.txt` |
| 29_2 | head + X9 arrival mutant (`scripts/mutant-arrival.py`) | 1.52 -> 1.00 | **RED** 0.959 s | `t-marr-29_2.txt`, `t-marr-diff.txt` |
| 29_2 | head + FX9 stall mutant (`scripts/mutant-stall.py`) | 1.00 -> 0.98 | **RED** 1.122 s | `t-mstall-29_2.txt`, `t-mstall-diff.txt` |
| 82_1 | head + FX9 stall mutant | 0.98 -> 1.08 | **RED** 2.861 s | `t-mstall-82_1.txt` |

The mutants stay RED and above the head's own times (0.959 / 1.122 > 0.560; 2.861 > 1.872), so the instrument still
separates them; with 29_2 / 82_1 RED on the head itself they prove only that, not a margin. Deviation: FX9's
`mutant-stall.diff` did not apply to the archive (CRLF from `git archive` under `core.autocrlf=true`); it was applied
as the line-ending-neutral `scripts/mutant-stall.py` (same two lines, `t-mstall-diff.txt`) before its runs started.

## Fresh clone
Bundle clone of `b103-inc9` at `77f73c2c` (the record commit before this one; `scripts/chain5.sh`, one run per file,
`-n 2`, `timeout 300`), `s19_app.__file__` = `~/work/zq-fx9b/clone/s19_app/__init__.py` atop every transcript
(`transcripts/clone/c-*.txt`, summary `chain5-log.txt`; load 0.59 at the start, 1.91 at the end).

| Set | Result |
|---|---|
| `tests/test_b103_inc9_*.py` (12 files, `-m "not serial_timing and not slow"`; timing nodes ran alone above) | **321 passed**, 0 failed (X9: 316, + 5 new nodes) |
| `tests/test_b103_inc8_*.py` (14 files) | **371 passed**, 0 failed |
| Laws: `test_id_registry`, `test_suite_hygiene`, `test_requirements_canon`, `test_address_census`, `test_deps_seam_law`, `test_no_private_tokens`, `test_engine_unchanged` | **117 passed, 3 skipped, 2 failed** - the two base-identical failures only: `test_canon_rows_hold_the_obligation_word_once`, `test_at_b83_08_tree_holds_no_assembled_selectors`; `test_r_tst_070_2` green (no record spells the runner HOME basename) |

26_2 (slow, the deselect path) not re-run: no change touches the deselect branch (F-X9-5 changes `_derive`'s width only).

## Files
- Product: `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` (F-X9-5), `s19_app/tui/definition_bench_view.py`
  (F-X9-6, F-X9-7, W-8), `s19_app/tui/definition_bench.py` (F-X9-7). 3 source files.
- Tests: `tests/test_b103_inc9_w_select.py`, `tests/test_b103_inc9_b_detail.py`, `tests/test_b103_inc9_b_cells.py`,
  `tests/test_b103_inc9_w_stage.py`.
- Records: this file, `steps.log`, `evidence-e4/fixes-fx9b/` (probes, scripts, mutant scripts, transcripts).

## Open items
- F-X9-2 (MAJOR): options O-A … O-F above; 29_2 / 82_1 RED.
- W-8 for a job that raised (no refusal object): the bench keeps the decoding line; small, needs a ruling on the text.
- Requirement canon: plural texts for k = 1 and W-8's line (above).
- Deferred as ruled: F-X9-3, F-X9-8, F-X9-9 (F-X9-9's `plain()` per paint is not part of the measured cost: `_paint` is
  0.045 s p50 on LARGE).

## Evidence checklist
- [x] Tests: every result above is one complete run's own output (`executed`); RED states `failed` on `4c891ea9`
  (`rg-red.txt`, 8 failed) and on the mutants; timing verdicts read at load < 2 before each run (`chain4-log.txt`).
  F-X9-2's fix: `not-run` (stop-and-report; no product change).
- [x] No secrets; records redacted (`~`, `<user>`, `<runner-home>`); the redaction needles scanned: 0 hits.
- [x] No destructive command on work without a commit; rtx scratch deleted by explicit list (below); no push.
- [x] File count: 3 source files (cap 4) + 4 test files.
- [x] 0 CR in the committed diffs.

## Commits
`7ad32e0d` F-X9-5, `ec054b7f` F-X9-6, `4d84dc78` F-X9-7, `4c52ea99` W-8, `77f73c2c` record step 5, then this record's
final commit. No push.

## Scratch deleted (explicit list, only paths I created)
`~/work/zq-fx9b/`: `base probe red green head marr mstall clone out home x tmp fx9b.bundle head.tar tests.tar fix.tar
run.sh waitload.sh probe1.sh probe2.sh chain3.sh chain4.sh chain5.sh redgreen.sh nodes.txt test_fx9b_probe.py
test_fx9b_probe2.py test_fx9b_probe3.py mutant-arrival.py mutant-stall.py mutant-stall.diff`, then the empty folder.
Local: the FX9b work folder outside the repo.
