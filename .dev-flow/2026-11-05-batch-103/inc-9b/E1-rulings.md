# Inc 9b — E1 rulings: design input, decisions, visible provisional choices, backlog

Base `09001bbc`. Model Opus, E1 + E2 by one agent (DF-03). Requirements `01-requirements.md`, slice `E1-slice.md`, graph `codewire/graph-inc9b.md`.

## 1. Sources and what the approved design fixes

- **Operator verdict, proto8 item PROGRESO = P3** (`s19-proto8-review/verdicts-proto8.json`, `s19-PENDING.md` P-130), verbatim: "Está muy bien la idea, sólo falta agregar el detalle del spinner o barra de progreso. Me gusta la idea porque el color y el cuadro indica que la ventana está trabajando." Fixed by the approved look (captures `proto8/captures/base.P3.busy.118x54.f1.png`, `.f2.png`, `base.P3.busy.220x60.f1.png`, `.f2.png`): the amber sheet border, the pill in the STAGING SHEET title `◐ BUSY · <job> <name> · <s> s · keys still work` in dark bold on amber. Added by the verdict: a spinner or a progress bar inside the pill (VP-1, VP-2).
- **P-127** (required), verbatim: "Sobre el indicador de progreso, necesitamos tenerlo, de otra manera los usuarios forzarán terminado de la aplicación." → the cue must stay live through the record-stage block: O-E (P-126/P-128), R-PE-BENCH.98.
- **P-126 / P-129 (FX9f):** R-PE-BENCH.29/2 and .82/1 relaxed 0.5 → 1.0 s by the operator; O-A / O-E in the backlog; now O-E is in scope. Not changed here (R-1).
- **Prototype facts used** (`proto8/ROUND.md` §Progress indicator, sidecars): the cue was a 0.1 s UI-thread timer keyed on the running job (`_active_job`); it ticked 56–70 times in ~10 s during LARGE's decode (median gap 0.12–0.17 s, max 0.38–0.45 s); it showed nothing in the 0.89–2.50 s between the key and the job start (cause not measured, `E1-slice.md` §5); every design froze during the record-stage block (~0.5–0.9 s; 0.674 s after FX9d, `../inc-9/E4-fixes-fx9d.md`).
- The prototype's amber `#f5c26b` is Inc 9's edit colour (C9 D-6, kept by the operator, P-125), already a CLAIMED hue of the census (`tests/test_tui_patch_json.py:830-831`, FX9e); the pill's dark text `#0a0e1b` is `insight_style.DEPTH_BG` (census exclusion `:853`). No new colour literal (ED-1).

## 2. Rulings on rows

- **R-1 — R-PE-BENCH.29 and .82 unchanged** (brief item 4). Whether O-E restores 0.5 s is measured at E4 (`E1-slice.md` §6); a proposal goes to the operator only with that measurement.
- **R-2 — R-PE-BENCH.99 bounds the key at 1.0 s during the write and refresh**, the bound the operator already accepted for .82/1, so the new row promises nothing O-E has not shown; its negative control is a 1.3 s stall (FX9f's re-aimed controls), because base's 0.674 s block would pass 1.0 s.
- **R-3 — The cue keys on the ask, not on the running job.** `BenchState.job` (`definition_bench.py:135`) is set when the selection handler asks for the decode (`bench_sheet.py:506`) and when an apply asks for a preview (`:422`); a record stage is busy from `_enqueue("record")` until `record_done`. This covers the prototype's blind gap whatever its cause (R-PE-BENCH.94/4).
- **R-4 — No row for "the key→job gap shall be under N s".** The gap's cause is unmeasured (K1 is probably the driver itself); the user-visible bound is R-PE-BENCH.94 (cue within 0.5 s of the key). If E4's diagnosis finds a product cause worth a bound (K2–K6), it comes back as a finding with its own row (DF-04 c: new → backlog or next increment).

## 3. Engineering decisions (not visible)

- **ED-1 — Inline style, no stylesheet edit.** The bench sheet sets `styles.border = ("round", <busy colour>)` on `#patch_sheet_win` and clears the rule for the idle look; the busy colour is taken from `definition_bench_view.EDIT` (no new literal). Alternative: a `-busy` class with a rule in `styles.tcss` (cleaner CSS, beats `:focus-within` by order) — rejected because `styles.tcss` is the file Inc 8b most likely edits, and the class needs a rule placed after `:2920-2923`. Consequence: one Textual behaviour to pilot (clearing an inline border returns to the stylesheet, `E1-slice.md` §4.2).
- **ED-2 — O-E as a chain of `call_after_refresh` steps with a document token.** Four steps (serialize; ledger + card + JSON view; staging sheet; checks and enable states), each reading the service when it runs. Between steps the loop runs keys, ticks and other changes; an Undo, Redo, Apply or load between steps runs its own synchronous refresh, which paints the latest document; the chain sees the token change and skips its remaining steps (R-PE-BENCH.106). The record hold (`_held`) lasts until the chain ends, so no second record stage writes mid-refresh (R-PE-BENCH.28's single job). Alternatives: O-F (the refresh off the UI thread: widgets must be touched on the UI thread, so it only moves serialization), O-A (encode in a process: removes the GIL tail of .29/2, a much larger change; stays in the backlog).
- **ED-3 — The tick is paused when nothing is asked**, resumed by `_enqueue`; no idle 10 Hz timer to perturb Inc 9's timing nodes.
- **ED-4 — The pill is a pure function in `definition_bench_view.py`** (Inc 9's split: pure render beside the widget), testable without an app.
- **ED-5 — The spinner advances per tick that runs, not by wall clock**, so a stalled loop shows a stalled spinner (the cue never claims life it does not have).

## Visible, provisional (operator page)

Each is decided provisionally (DF-02 / DF-09) and the rows follow the choice; the orchestrator puts them on one page.

- **VP-1 — Spinner, not a progress bar.** Choice: a spinner. Why: a bar needs a known total, and none of the busy jobs reports one — I-2's `decode_values` / `encode_values` give no progress callback (`a2l_definition.py` is read only), and the write and refresh are 4 unequal steps (0.02–0.25 s). Alternative: an indeterminate sweep bar (prototype P2, ~16 cells) inside the pill. Consequence of the choice: one cell, the approved pill keeps its width. Of the alternative: ~16 cells more; at 80 columns long names are cut sooner; it looks like progress but measures none.
- **VP-2 — Spinner glyphs `◐ ◓ ◑ ◒`.** Choice: rotate the approved `◐` through its four quarters, one per 0.1 s tick (a turn in 0.4 s). Alternative: the braille spinner of P1 `⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏`. Consequence: the choice keeps the glyph of the approved capture; the braille one is finer and smoother but a different mark from what the operator approved.
- **VP-3 — Job words `decode`, `preview`, `stage`.** Choice: `stage` for a record stage (the op line says `alt+s stage record`). Alternative: `record`. Consequence: none on width (5 vs 6 letters); the wording the user reads in the op line vs the internal job name.
- **VP-4 — A 0.2 s grace before the cue shows.** Choice: no cue for a job that ends within 0.2 s of its ask. Alternative: show at once. Consequence: with the grace, selecting a small curve or map never flashes amber; the cue still appears within 0.5 s of the key (R-PE-BENCH.94). Without it, every bench selection and every small preview flashes the border for a tick, and "the window is working" becomes noise.
- **VP-5 — The seconds count from the key, not from the job's start.** Choice: from the ask, so a job waiting behind another (K2) shows its wait. Alternative: from the worker's start. Consequence: honest waiting time vs smaller numbers that hide the queue.
- **VP-6 — Which jobs show the cue.** Choice: the selected row's decode and preview, and every record stage (even after the user moved to another row, since it still writes the document). Not shown: page summaries and staged decodes of other rows (≤ 4,096 elements, milliseconds). Alternative: any bench job. Consequence: no amber on page turns; a record stage keeps the cue while the user browses.
- **VP-7 — A long name is cut with `…` to keep the pill whole.** Choice: cut the name so spinner, BUSY, job word, seconds and "keys still work" stay visible. Alternative: let the border crop the title's end. Consequence: with the alternative a long A2L name pushes the seconds and "keys still work" out of view.
- **Note (approved, not provisional):** the amber is Inc 9's edit colour, close (≤ 1.5°) to the app's orange3 and WAITING_HUMAN cues (FX9e, P-123); the operator chose P3 for that colour ("el color y el cuadro indica que la ventana está trabajando"), so the border and the edited cells now share one hue with two meanings (edited cell; window working). Listed so the page can show it once.

## 4. Backlog (deferred; DF-04 c)

- **BL-9b-1** A decode or encode whose result is discarded (the user left the row) runs to its end on its thread and holds the single-job queue (K2): up to ~11 s for LARGE before the next row's decode starts. A cancellable job needs O-A (a process) or an I-2 change. The cue shows the wait honestly meanwhile (VP-5).
- **BL-9b-2** Undo, Redo, Apply, bytes-entry stage and load keep the synchronous refresh (`_refresh_patch_history_view`): an Undo of LARGE's record still blocks the UI ~0.5–0.7 s with no cue. The same step runner could serve them (one-line change per site) — a scope extension, not asked.
- **BL-9b-3** A cue for long jobs outside the bench (file load, execute): out of scope.
- **BL-9b-4** O-A for R-PE-BENCH.29/2 (GIL tail of the preview encode), as FX9f left it.
- **BL-9b-5** The census comment of `#f5c26b` (`tests/test_tui_patch_json.py:830-831`) names only "edited-cell foreground"; the busy border reuses it. A test-side role note at E4 (no new literal, so the census passes either way).

## 5. Interfaces, risks and notes

- Interfaces: graph §Interfaces (I-9b.1 … I-9b.3) and `E1-slice.md` §7 (Inc 8b and the E4 order).
- **E3:** not required by the skill's two conditions unless Inc 8b's slice touches `#patch_sheet_win` or the four source files (`E1-slice.md` §7): the increment reads and writes nothing outside the program, and I-9b.1 is additive with a default every current caller keeps. The new risk is O-E's interleaving (keys, Undo, Apply, a second alt+s between steps): bounded by R-PE-BENCH.106 and the record hold, and left to the one E5 code-and-security review.
- **Risk:** the timing rows (.94/1–3, .97, .98, .99) are host-load sensitive; they are decided on the quiet host only (HT-08) and their margins recorded.

## P9b addendum (E4 prep, merged base `e4485817`)

No requirement row changes: every pilot result fits the rows as written (R-PE-BENCH.98's 0.5 s gap, .99's 1.0 s key, .105's room B, .95/.100/.101/.102's idle look). Two engineering decisions are corrected to the design by the pilots (DF-04 a, defects found before code):

- **ED-1 amended.** The idle look clears the four inline edge rules (`border_top`, `border_right`, `border_bottom`, `border_left`) and then refreshes the window; "clear the rule" (`clear_rule("border")`) is a no-op in Textual 8.2.8, and a clear without a refresh leaves the busy border painted (P2, F-9b-6). The busy colour is `Style.parse(definition_bench_view.EDIT).color` (#f5c26b): `EDIT` is a style string (F-9b-5). Still no new colour literal and no stylesheet edit.
- **ED-2 amended.** The refresh steps are chained by `set_timer(STEP_GAP_S, …)` with STEP_GAP_S = 0.1 s, not by `call_after_refresh`: the screen runs after-refresh callbacks at once when nothing is dirty, so no key and no paint landed between steps (0/3), while a 0.1 s gap let both through (3/3) (P1, F-9b-4). `set_timer(0, …)` is forbidden (its timer task dies; the hold would never be released). Cost: three gaps add about 0.3 s to the time the cue shows after a record stage (EX-BC6: block 0.67–0.69 s of steps → about 1.0 s with the gaps), every gap painting a tick.
- **EX-BC13** (graph) uses the measured room B = 66 at 80 columns (was 76, an estimate); B = 106 at 118 and 190 at 220.

