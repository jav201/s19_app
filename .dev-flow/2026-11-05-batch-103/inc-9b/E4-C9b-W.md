# Inc 9b E4 - C9b-W hand-back (group W, 7 nodes)

Files: `s19_app/tui/definition_bench_view.py` (`BUSY_COLOR`, `busy_title`), `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` (`busy_job`, `on_mount`, `_enqueue`, `_job_done`, `record_done`, `_busy_tick` + helpers `_busy_window`, `_busy_stage_name`, `_busy_idle_look`). Runner rtx, HT-02 env (HOME `<runner-home>`), `-n 0`, load 0.69 (quiet), `s19_app.__file__` = `<runner>/work/zq-e4-9b-c9bw/tree/s19_app/__init__.py`. Probe (scratch only, not committed): 3 nodes, `3 passed`.

| Example | Result |
|---|---|
| EX-BC4 | held: plain `STAGING SHEET   ◐ BUSY · decode LARGE · 1.7 s · keys still work `, span `bold #0a0e1b on #f5c26b` |
| EX-BC5 | held: frames 1 / 4 give `◓ BUSY` / `◐ BUSY`; titles differ across 0.35 s of real ticks |
| EX-BC11, BC12 | held (pure): literal `[@click=app.quit]X[/]`, `A�[2J`; title set as a `Text` object |
| EX-BC13 | held (pure): rooms 66 / 106 / 190 give a 66 / 106 / 190 character title, name cut ending `…`, ends ` keys still work `; 1-char name uncut |
| busy_job (BC1/2/9/10/3) | held (pure) |
| EX-BC1 (app) | held: MAP_DEF_0001 decode gated, painted top border row `╭─ STAGING SHEET   ◑ BUSY · decode MAP_DEF_0001 · 0.3 s · keys still work`, border `('round', #f5c26b)` |
| EX-BC10 (app) | held: `down` to DISPLAY_0001 -> title `STAGING SHEET`, painted top row plain, `_busy_asked == {}`; accent border `#91abec` back (focus within) |
| EX-BC8/BC9 (cue half) | held: `_stage_name` set + ask 1 s old -> `stage VAL_BLK_DEF_0001`; `record_done` -> idle title, rule border `#1b233a` painted, `_stage_name None` |
| EX-BC3 | held in part: 0.5 s idle at mount, title `STAGING SHEET`; the 0.15 s gated decode not run |
| EX-BC2, BC6/7/14 | not run here (EX-BC2 follows from `busy_job` reading the selected row's `state.job`; BC6/7/14 are group S) |

Deviations / notes (for the orchestrator to rule):
1. The graph says `on_mount` runs `StagingSheet.on_mount` first. Textual already calls every class's `on_mount` along the MRO, so `ArrayBenchSheet.on_mount` only creates the timer (no `super()` call, which would run the base twice).
2. Added module constant `definition_bench_view.BUSY_COLOR = Style.parse(EDIT).color.get_truecolor().hex` (derived, no new literal) so the pill and the border share one colour. Also constants `BUSY_GRACE_S = 0.2`, `BUSY_TICK_S = 0.1` in `bench_sheet.py`.
3. The ask time of a decode starts at the row's first ask (load / selection), as the graph says ("first ask kept"); on a freshly loaded page the first row's pending time already counts from load.
4. `border_title` read back as `str` returns Textual's markup of the `Text`; tests read the painted top border row, not the attribute.
5. Inline-border mutations are guarded by a "cue on" flag (`_busy_idle_title` is not None), so an idle tick does no `refresh()`.
