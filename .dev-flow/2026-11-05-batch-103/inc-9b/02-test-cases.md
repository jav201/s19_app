# Inc 9b — test cases (E1)

One row per alternative of a requirement (`roles/tester.md` format: `<requirement id>/<n> | example id | test name | full or partial`), plus the objective and the class (N normal, R robustness, T timing). The **test name** and the **full / partial** mark are the tester's at E4; a case's result comes from the test run, never from this file. Expected values are the requirement's exact values; examples `EX-BC*` are in `codewire/graph-inc9b.md`. Timing cases (T) run alone (`-n 0`) on the quiet host of CTX-PE-BENCH, `uptime` printed beside each result (HT-08); the gap and latency numbers are read from the app's own clock (`time.monotonic`) at each tick and key handling, never from the pilot's `press` return (`E1-slice.md` §5, cause K1). Gated jobs use Inc 9's held-job fixture. Groups for E4: W (the cue: `bench_sheet.py`, `definition_bench_view.py`), S (the stepped write and refresh: `app/patch.py`, `patch_editor/panel.py`), AT (cross-group, real app).

| Case | Example | Objective — verify that … (expected) | Class | Group | Test name (E4) | full / partial (E4) |
|---|---|---|---|---|---|---|
| R-PE-BENCH.94/1 | EX-BC1 | LARGE selected: busy border (#f5c26b) and a busy title holding `decode LARGE` at a tick 0.2–0.5 s after the key | T | AT | | |
| R-PE-BENCH.94/2 | EX-BC1 | VAL_BLK_DEF_0001 +Δ 5 applied, preview gated: busy title holds `preview VAL_BLK_DEF_0001` within 0.5 s of Enter | T | AT | | |
| R-PE-BENCH.94/3 | EX-BC1 | alt+s on VAL_BLK_DEF_0001, encode gated: busy title holds `stage VAL_BLK_DEF_0001` within 0.5 s of alt+s | T | AT | | |
| R-PE-BENCH.94/4 | EX-BC2 | LARGE selected while another row's summary decode is gated running: the cue shows `decode LARGE` although LARGE's decode has not started | R | W | | |
| R-PE-BENCH.95/1 | EX-BC3 | MAP_DEF_0001's decode gated 0.15 s then released: at no tick the busy colour or a title other than `STAGING SHEET` | N | W | | |
| R-PE-BENCH.95/2 | EX-BC3 | page turn, summary decodes gated 1 s: idle look at every tick | N | W | | |
| R-PE-BENCH.96/1 | EX-BC4 | pending time 1.7 s, decode of LARGE: title = `STAGING SHEET` + two spaces + ` <f> BUSY · decode LARGE · 1.7 s · keys still work ` (`<f>` one of the spinner frames) | N | W | | |
| R-PE-BENCH.96/2 | EX-BC4 | the pill segment's style: bold, foreground #0a0e1b, background #f5c26b; `STAGING SHEET  ` keeps the title colour | N | W | | |
| R-PE-BENCH.96/3 | EX-BC4 | job words: `preview` for a preview, `stage` for a record stage (the title text of .94/2 and .94/3) | N | W | | |
| R-PE-BENCH.97/1 | EX-BC5 | LARGE's real decode, 5 s from the cue's first tick: every two successive ticks paint different titles | T | AT | | |
| R-PE-BENCH.97/2 | EX-BC5 | the frames follow `◐ ◓ ◑ ◒` cyclically, one step per tick, none skipped | N | W | | |
| R-PE-BENCH.97/3 | EX-BC5 | gaps between changed titles: median ≤ 0.2 s, max ≤ 0.5 s | T | AT | | |
| R-PE-BENCH.98/1 | EX-BC6 | LARGE Set `7` on 256 × 16 cells, alt+s: from the encode's end to the cue's leave, max gap ≤ 0.5 s and ≥ 1 tick between the write and the refresh's end | T | AT | | |
| R-PE-BENCH.98/2 | EX-BC6 | the stepped stage writes the entry byte-equal to base's for the same edit (R-PE-BENCH.70's bytes) | N | S | | |
| R-PE-BENCH.99/1 | EX-BC7 | `down` pressed when the write step ends: handled within 1.0 s | T | AT | | |
| R-PE-BENCH.100/1 | EX-BC8 | LARGE's gated decode released: idle look within 0.3 s, values shown | N | W | | |
| R-PE-BENCH.100/2 | EX-BC8 | VAL_BLK_DEF_0001's gated preview released (` ✓`): idle look within 0.3 s | N | W | | |
| R-PE-BENCH.100/3 | EX-BC8 | alt+s on VAL_BLK_DEF_0001 written: idle look within 0.3 s of the refresh's last step; title `STAGING SHEET` | N | AT | | |
| R-PE-BENCH.101/1 | EX-BC9 | preview refusal (Set `60`): idle look within 0.3 s | R | W | | |
| R-PE-BENCH.101/2 | EX-BC9 | record stage refused by its encode (Set `60`, R-PE-BENCH.74): idle look within 0.3 s | R | AT | | |
| R-PE-BENCH.101/3 | EX-BC9 | record stage refused at its write, A2L unloaded (R-PE-BENCH.76): idle look within 0.3 s | R | S | | |
| R-PE-BENCH.101/4 | EX-BC9 | record stage refused at its write, a session action running (R-PE-BENCH.83): idle look within 0.3 s | R | S | | |
| R-PE-BENCH.101/5 | EX-BC9 | record stage stale, Undo during its encode (R-PE-BENCH.78): idle look within 0.3 s | R | AT | | |
| R-PE-BENCH.101/6 | EX-BC9 | a decode whose worker raises (result `None`): idle look within 0.3 s | R | W | | |
| R-PE-BENCH.102/1 | EX-BC10 | LARGE's decode gated, `down` to DISPLAY_0001: idle look within 0.3 s while LARGE's worker still runs | R | W | | |
| R-PE-BENCH.102/2 | EX-BC10 | LARGE's decode gated, a filter keystroke leaves LARGE off the page: idle look within 0.3 s | R | W | | |
| R-PE-BENCH.103/1 | EX-BC11 | name `[@click=app.quit]X[/]`: shown literally in the title, no link, the app keeps running | R | W | | |
| R-PE-BENCH.103/2 | EX-BC11 | name `A[b]B`: shown literally | R | W | | |
| R-PE-BENCH.104/1 | EX-BC12 | name with `\x1b[2J`: title shows `�[2J` | R | W | | |
| R-PE-BENCH.104/2 | EX-BC12 | name with U+0085: title shows U+FFFD | R | W | | |
| R-PE-BENCH.105/1 | EX-BC13 | 300-character name at 80 columns: top border row holds `BUSY`, the cut name ending `…`, the pending time and ` keys still work ` | R | W | | |
| R-PE-BENCH.105/2 | EX-BC13 | the same at 118 columns | R | W | | |
| R-PE-BENCH.105/3 | EX-BC13 | the same at 220 columns | R | W | | |
| R-PE-BENCH.105/4 | EX-BC13 | a 1-character name at 80 columns: not cut, no `…` | N | W | | |
| R-PE-BENCH.106/1 | EX-BC14 | Undo handled between two refresh steps: ledger rows, JSON view text and sheet marks equal a full refresh of the undone document | R | S | | |
| R-PE-BENCH.106/2 | EX-BC14 | Apply handled between two refresh steps: the same check | R | S | | |

**Count** (counted by `awk` over the table, not by hand): 36 cases for 13 requirements (T 7, N 11, R 18); groups W 21, S 5, AT 10.
