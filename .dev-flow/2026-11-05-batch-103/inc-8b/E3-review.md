# Inc 8b — E3 code-free design review (shared interfaces; design and security lens, one round)

Batch `2026-11-05-batch-103`, increment 8b, stage E3, model Opus (claude-opus-5-5, architect as the single E3 reviewer, relevo-15). Read at `b103-inc8b` `b370efc8`; Inc 9b read at `b103-inc9b` `3daea03d` (`git show`, not edited). Inputs: `01-requirements.md`, `02-test-cases.md`, `E1-rulings.md`, `E1-slice.md`, `codewire/graph-inc8b.md`, `evidence-e1/examples_inc8b-transcript.txt`; the callers in `s19_app/` and `tests/` (grep of the tree); Textual 8.2.8 source (the project's version) for the scroller question. Line numbers are as of `09001bbc` (= this branch's source).

## Verdict

**FAIL — 4 MAJOR open.** None needs a redesign. Each one can be fixed with a targeted edit to the requirements, the graph and the slice (fixes below). After those edits are in and ruled, the graph can go to E4 with no second E3 round. Exception: if the corrector changes an interface signature beyond the ones named here, E3 looks at that change again.

Counts: BLOCKER 0 · MAJOR 4 · MEDIUM 4 · MINOR 4 · INFO 3.

## Findings

| Id | Sev | Tag | Where | Problem | Proposed fix |
|---|---|---|---|---|---|
| E3-8b-01 | MAJOR | design-gap | `01-requirements.md:216-217`, `:219`; `02-test-cases.md:115-119`; `graph-inc8b.md:96`, `:363`, `:412`; `E1-rulings.md:39` (§3, twice); `E1-slice.md:11`, `:66`, `:78`; `evidence-e1/trace_check-e1.txt:2-3`; `steps.log:2` | Inc 8b's new rows R-PE-BENCH.94 and .95 use the same ids as Inc 9b's R-PE-BENCH.94 … .106 (inc-9b `01-requirements.md`, graph §Coverage). Confirmed. | Renumber .94 → **R-PE-BENCH.107** and .95 → **R-PE-BENCH.108** at every place listed under answer 3. Both ids are free in this tree and in Inc 9b's. Regenerate `trace_check-e1.txt`; do not hand-edit it. In `steps.log:2`, append a correction line; never rewrite a logged line. |
| E3-8b-02 | MAJOR | design-gap | `bench_sheet.py:305-312` (`ArrayBenchSheet._bench_geometry`, used by `_reveal` `:316` and `action_page` `:378`); graph `StagingSheet._paint`, `detail_lines` | `_bench_geometry` repeats the bench canvas geometry: `canvas_shape(body.content_size.width, …, visible − 1)` with `visible = height − 1`. After Inc 8b, `bench_detail` gets **V − 4** for its width (detail_lines) and a room of **body − 3** (visible = body − 2). The body's own width is no longer V: it is `width: auto` = 143 at V = 111, 195 at V = 195. So `_bench_geometry` believes there are more columns, and one more row, than are painted. `window_for` then leaves the cursor in a column or row that is not painted. This breaks R-PE-BENCH.36 (the window moves the least that shows the cursor) at 80 and 118 columns. `bench_sheet.py` is not in the slice, and the graph does not name this caller. | Pin a new StagingSheet interface `StagingSheet._detail_geometry() -> tuple[int, int]` = (`_view_width()` − 4, visible − 1). `_paint`, `_fit_window` and `ArrayBenchSheet._bench_geometry` all use it, so the three can never drift apart again. Add `bench_sheet.py` (only `_bench_geometry`) to the slice, group W. Add R-PE-BENCH.36 to the rows E4 re-runs, with one case: LARGE at 80×24 and at 118×54, cursor right past the last painted column → the window moves and the cursor cell is painted. |
| E3-8b-03 | MAJOR | design-gap | graph `StagingSheet.compose`, `[Interface: #patch_sheet_grid]`; slice W1/W2; prototype `proto8_app.py:689`, `:700` | The graph does not say which widget class the scroller is. The prototype used `ScrollableContainer`. In Textual 8.2.8 that class is `can_focus=True` and carries the bindings `left`, `right`, `home`, `end`, `pageup`, `pagedown` … (`textual/containers.py:32`, `:48-59`). It sits between the focused body and `StagingSheet` in the binding chain, so its bindings win. `action_scroll_left` / `_right` raise `SkipAction` only when horizontal scroll is not allowed (`textual/widget.py`, `action_scroll_left`). At V < G scroll is allowed, so **← and → scroll the grid instead of choosing an enum entry** (R-PE-DEF.33 / Inc 8's `choose`) at 80 and 118 columns. Home and End reach the scroller's `scroll_home` / `scroll_end`, which animate, not `action_scroll_grid` (R-PE-DEF.94's x = 32 read right after the key). The scroller also adds a Tab stop. Copying the prototype would ship all three defects. | Pin `#patch_sheet_grid` as a plain `textual.containers.Container`: not focusable, no bindings, CSS `overflow-x: auto; overflow-y: hidden; scrollbar-size-horizontal: 1`. `action_scroll_grid` calls `scroll_to(x=…, animate=False)`. Add cases: R-PE-DEF.33/3 — 118×54, ENUM_0001 selected, → → `(●) 2 RUN` and scroll x stays 0. R-PE-DEF.94/6 — x is 32 right after End, with no wait. R-PE-DEF.92/3 — the Tab order of the Patch Editor is unchanged and the scroller never holds the focus. |
| E3-8b-04 | MAJOR | design-gap | graph `limits_cell` (no guard on the value); R-PE-DEF.106; `definition_sheet.py:717-724` (`_track_index`); `a2l_definition.py:573-580` (`_read_limits`) | The mark position `round(pos × 15)` raises `ValueError` when pos is NaN. This happens when (a) the current or new value is NaN — a FLOAT32_IEEE word read from erased flash `FF FF FF FF` decodes to NaN, and the decoder keeps it (`display_text` prints `nan`, `a2l_definition.py:3373-3376`); or (b) the limits are finite but their span overflows (±1.7e308 with value 1e308). Run (the formula copied into a standalone script, no product import, `python -I -B`): `FLOAT32 erased 0xFFFFFFFF current, limits -40..150 -> ValueError cannot convert float NaN to integer`; `finite limits +-1.7e308, value 1e308 -> ValueError …`; `value inf -> (17, True)`. R-PE-DEF.106 guards only non-finite **limits**. The A2L reader never produces those: `_read_limits` turns a non-finite limit word into "no limit". So the guard sits on an unreachable path, while the reachable crash in the paint path has no row. | New row **R-PE-DEF.114** (If): "If the value of a track mark, or its position, is not a finite number, then the system shall show the track without that mark." 3/3: DISPLAY_0001 with a FLOAT32_IEEE copy whose image word is `FF FF FF FF` → the track with no `●`, no exception; limits ±1.7e308 with value 1e308 → no exception, `┤` at 25; value inf → `▶` at 25 (it holds today). Negative control: no guard → `ValueError` RED. Graph `limits_cell`: "a mark whose value or pos is not finite is left off". Keep R-PE-DEF.106 (one `isfinite` check costs nothing), but its cases build the Definition directly (E3-8b-09). |
| E3-8b-05 | MEDIUM | design-gap | `sheet.py:66` (`StagingSheet > #patch_sheet_body { height: 1fr; }`); slice W2 | Once the body is the scroller's child, the child selector `StagingSheet > #patch_sheet_body` no longer matches. W2 pins only `width: auto`. With no height rule the body is as tall as its own text, so `visible = body − 2` takes its own output as input (R-PE-DEF.81). The prototype needed a second rule for this (`proto8_app.py:731-733`). `tests/support/b103_inc8_s2.py:116`, `:145` sets the old selector in the test harness. | Pin both rules in W2: `StagingSheet > #patch_sheet_grid { height: 1fr; … }` and `#patch_sheet_grid > #patch_sheet_body { height: 1fr; width: auto; }`. E4 changes the harness CSS. The existing R-PE-DEF.81/4 case (body height 8 → visible 6) catches a missing rule. |
| E3-8b-06 | MEDIUM | design-gap | graph `card_lines` (`in: str title`), CTX `card`; R-PE-DEF.70/.71/.112; cases | The card is a new place where text is painted: the A2L name in the title, enum texts in the options row. Neither the definition nor the graph says that card widths are counted in terminal cells, or that the title goes through the plain-text clean. No case puts a control character, markup or a wide character in a card. The graph example `C.name_esc.fit26` (EX-8B-C1) has no case. | Card definition: "widths in terminal cells; title and rows are CTX-PE-DEF plain text". Add cases: R-PE-DEF.71/4 — a name `A\x1b[2J` → title `A�[2J …`; R-PE-DEF.70/6 — an enum text `[@click=app.quit]OFF[/]` in the card, shown literally; R-PE-DEF.112/3 — a name `温度`×200 → the top line is 139 cells and `╮` ends at the cap; R-PE-DEF.96/6 — `C.name_esc.fit26`. |
| E3-8b-07 | MEDIUM | impl | CTX `limits cell` ("a second mark on a taken cell moves one cell right"); graph `limits_cell` | When both marks land on cell 16, moving the second one right puts it on cell 17 — the `┤` at offset 25. That breaks R-PE-DEF.104's "`┤` at 25" on exactly the alignment the operator objected to. The base moves it left at the end (`definition_sheet.py:740`). | Definition: "… moves one cell right, or one cell left from cell 16". Example: DISPLAY_0001 current 150, value 149.9 → `◆` and `●` on cells 15 and 16 (offsets 23, 24), `┤` at 25. One case under R-PE-DEF.104. |
| E3-8b-08 | MEDIUM | design-gap (Inc 9b) | inc-9b `E1-slice.md` §6 (O-E measured "at the base `09001bbc` and at the Inc 9b tip") | Inc 9b's E4 starts from Inc 8b's merge (answer 8). Its tip then also carries Inc 8b's heavier paint: 143-cell rows, grounds, cards, and `set_document` → `_paint`, which is step 3 and the largest step. A comparison with `09001bbc` mixes Inc 8b's cost into O-E's result, and the proposal to restore R-PE-BENCH.82/1 to 0.5 s rests on that comparison. | Not an inc-8b edit. The orchestrator writes into Inc 9b's E4 brief: measurement base = Inc 8b's merge commit. |
| E3-8b-09 | MINOR | design-gap | R-PE-DEF.106 threshold; transcript `L.cell.upper_nan` (`'     0 … nan '`) | The row names "DISPLAY_0001 copies" (lower −40), but the transcript's upper-nan cell has lower `0`. Both cases cannot come from the A2L reader (E3-8b-04). | Reword: "a Definition built directly with …". Recompute `upper_nan` with lower −40, or name the fixture the transcript used. |
| E3-8b-10 | MINOR | impl | graph `limits_cell(row, value, width, tone="")` | The cell is always 34 cells, but the graph does not say what `width` still does. Inc 8 tests call `limits_cell(row, None, 16)` (`tests/test_b103_inc8_s1.py:503`). | Graph func: "`width` is not used (the Limits width is fixed); kept so the call shape holds", as D-1 does for `sheet_widths`. The `:503` test is retired at E4. |
| E3-8b-11 | MINOR | impl | graph `_SheetBody.on_resize` example (118×54 → 80×24 changes both axes) | With a terminal resize that changes only the width, the body's own size can stay 143 × h. Textual still sends Resize when the container size changes (`textual/widget.py:4126-4141`), so this is expected to work. But no example covers it, and the bench canvas's re-layout depends on it. | Add case R-PE-DEF.81/5: 118×54 → 220×54 with MAP_DEF_0001 expanded → bench lines ≤ 195 and the ground to 195. |
| E3-8b-12 | MINOR | design-gap | `E1-rulings.md` §4; `insight_style.py:75-84` | The verdict-hue rule widens GREEN inside `#patch_editor_panel` from "a check passed" to "passed or staged (`●`)". The operator saw this in D's captures, but it restates an operator rule (batch-48 Inc-2b), and only §4 records it. | Add it to the operator page as a visible line (with V8b-1 … 12): "GREEN = ✓ passed or ● staged". |
| E3-8b-13 | INFO | — | slice group S | Group S is one file with 20 nodes, more than the "about 8 nodes" per agent. Ownership is by file, so S cannot be split without a module split, and DF-05 defers P3. | One implementer for S, with two testers: render rows and card/limits. |
| E3-8b-14 | INFO | — | R-PE-DEF.97 (selected and zebra grounds over 0 … 142) vs R-PE-DEF.107 (expanded ground over max(G, V)) | At 220 columns the row grounds stop at cell 142 while the expanded ground runs to 194. The design is consistent; this is only a visible seam. | Check against `D.off.sheet.220x60.png` at E5. |
| E3-8b-15 | INFO | — | CTX-PE-BENCH | Both increments amend CTX-PE-BENCH: Inc 8b the "array row cells" term, Inc 9b the "busy job" term. The terms do not overlap. | Merge both when the requirements are folded into the canon at batch end. |

## Answers

**1. Callers** (grep of `s19_app/` and `tests/`):

| Interface | Product callers | Does the new contract hold unchanged? | Test callers (E4 re-aims; never weakens) |
|---|---|---|---|
| `sheet_widths(width)` | `sheet.py:327`; `bench_sheet.py:138` (`.current` → `_strip_width`) | **Yes** (D-1: returns 20; the argument is unused). | `test_b103_inc8_s1.py:52, 66, 74, 366, 370, 397, 426, 459, 471, 481, 491, 510, 518, 596`; `test_b103_inc9_b_cells.py:47` (Current 18 → 20); `test_b103_inc9_w_select.py:224` |
| `summary_strip(values, grid, width)` | `bench_sheet.py:288` (`_strip_width − len(count) − 2`) | **Yes**: 20 − count width − 2 equals the CTX strip width; R-PE-BENCH.11's examples (17, 16, 17) match. | `test_b103_inc9_b_cells.py:62, 83, 144, 280-323` (8-level oracle `EX.strip_chart`, `"▁ █"`) |
| `bench_cells(row, state, widths)` | `bench_sheet.py:592` (`KindOps.cells`), called by `row_line` `definition_sheet.py:831` | **Yes**: same shape, Limits 34 = `widths.limits`. | `test_b103_inc9_b_cells.py:57, 91-145, 227, 397` (`"-"` keeps its plain text) |
| `detail_lines(row, preview, width, state, room)` | `sheet.py:329`, `:420`; reaches `bench_detail` through `KindOps.detail` | **Yes** for the two sheet calls once they pass `_view_width()`. **No** for the geometry the bench repeats: `bench_sheet.py:305-312` (E3-8b-02). | `test_b103_inc8_s1_detail.py:50, 233, 248` |
| `row_line(…, state=None, odd=False)` | `sheet.py:339` | **Yes**: a keyword after `state`; the positional calls in tests stay valid. | `test_b103_inc8_s1.py:54, 366-441, 599-602`; the helpers `tests/support/b103_inc8_s2.py:187` and `test_b103_inc8_at.py:215` read painted lines |
| `limits_cell(row, value, width, tone="")` | `_stock_cells` (`definition_sheet.py:807`) only | Yes (group S's own call) | `test_b103_inc8_s1.py:460-520` (retired forms) |
| `range_cell`, `limit_slot` (new) | `limits_cell`, `bench_cells` | new | — |
| `header_line` | `sheet.py:333` | yes | `test_b103_inc8_s1.py:74, 427` |

Orchestrator's provisional ruling: **confirmed, with one correction.** Inc 8b's E4 runs first and owns the one `bench_sheet.py` edit that is needed. That edit is not at `:138`, `:288` or `:592` — those calls hold as they are. It is `_bench_geometry` at `:305-312`, through the new `_detail_geometry()` (E3-8b-02). The slice must add `bench_sheet.py` to group W. Inc 9b's E4 starts from Inc 8b's merge.

**2. Inc 9b compatibility: yes.** Inc 9b can be built on Inc 8b's contracts with no change to either graph, apart from E3-8b-01 (ids) and E3-8b-08 (measurement base). Checked:
- I-9b.3: the busy cue on `#patch_sheet_win`. Inc 8b touches neither the window, its title or subtitle, `layout.py`, nor `styles.tcss`. The new scroller sits inside the sheet.
- I-9b.1: `refresh_entries(…, sheet=False)` + `refresh_sheet_document()` → `set_document` → `_paint`. Inc 8b does not change `set_document`, and its `_paint` stays the single repaint entry.
- I-9b.2: `record_done` is not touched by Inc 8b.
- `ArrayBenchSheet.on_mount` calls `StagingSheet.on_mount`, which Inc 8b does not change.
- `busy_title` uses `name_echo` and `definition_bench_view.py`; Inc 8b changes neither.
- `bench_sheet.py`: the two increments edit disjoint functions (Inc 8b `_bench_geometry`; Inc 9b `_enqueue`, `_job_done`, `record_done`, and new methods).
- Inc 9b's `_busy_tick` does not call `_paint`, so the heavier paint does not land on every tick.

**3. Id clash: confirmed.** These places carry Inc 8b's R-PE-BENCH.94 / .95. Every other ".94"/".95" in `inc-8b/` belongs to R-PE-DEF.94/.95 and stays.
- `01-requirements.md`: rows `:216` (.94) and `:217` (.95); the count line `:219`.
- `02-test-cases.md`: cases `:115-117` (.94/1 … /3) and `:118-119` (.95/1, /2).
- `codewire/graph-inc8b.md`: §Coverage row `:96`; node `summary_strip` `req:` `:363`; finding F-1 `decision:` `:412`.
- `E1-rulings.md`: §3, `:39`, which names both ids.
- `E1-slice.md`: group B row `:11`; function map B1 `:66`; owner row `:78`. (`:10` and `:77` are R-PE-DEF.94/.95 and stay.)
- `evidence-e1/trace_check-e1.txt`: `:2-3`. Regenerate this file; do not edit it.
- `steps.log`: `:2`. Append a correction line.
- Evidence scripts and evidence names: none. `examples_inc8b.py`, `f_r14_1_probe.py`, the transcripts and the Code-Wire reports do not carry these ids. The examples are keyed `S.*`, not by row id.

New ids: .94 → **R-PE-BENCH.107**, .95 → **R-PE-BENCH.108**.

**4. Grid D and Limits alignment** (operator, A3: "estandarizar los valores, unidades y líneas para que se mantengan alineadas en toda la columna"): **yes, by construction, at 80, 118 and 220.** The grid widths do not depend on V, so the Limits column starts at 87 at every width. Every row kind lays out the 34 cells the same way:

| Offsets | Content |
|---|---|
| 0-6 | lower slot, unit letter at 6 |
| 7 | space |
| 8 / 25 | `├` / `┤` |
| 16 | `…` or `-` |
| 26 | space |
| 27-33 | upper slot, unit letter at 33 |

Kinds checked: scalar, enum, bit mask, the bench range form, and the text / refused no-limits form.

I recomputed, from the definitions, the transcript's limits-cell values `L.cell.DISPLAY_0001.cur143.5.new25.5`, `MASK_FIELD_0001.cur174.new255` and `ENUM_0001.cur1`: positions (`◆` 14, `●` 23; cell 11/16; cell 6), length 34, and `├` at 8 / `┤` at 25. I also recomputed:
- strips: CURVE → `▄▆▃▇▁` (levels 4 6 3 7 1); 40 points in 17 cells → 14 cells;
- bit tables: `1A E7 → 1F F7`, changed bits 10, 8, 4; ULONG changed bits 21, 18, 17, width 75;
- the hex-grid ASCII guide at 56;
- grid sums: G = 143, gutters 28 … 142, End = 32 / 70 / 0.

All agree with the graph's examples.

Inconsistencies found:
- `L.cell.upper_nan` (E3-8b-09).
- The collision rule at cell 16 can move `┤` (E3-8b-07).

Note (no finding): at the reference width 118, the first view position cuts the Limits column at cell 110, so the upper slot and Δ are reached by End or the scrollbar. D's approved 118 capture has the same grid and scrollbar (V8b-2 already notes the cut).

**5. Colour tokens and the hue census: passes `tests/test_tui_patch_json.py` as written (by reading; not run, HT-01).**

`tc079_5c` (`:1031-1108`) sweeps every `#xxxxxx` in `s19_app/**/*.py|.tcss`. Against that sweep:
- **The one new literal**, `#1c2547`, must land in `_EXCLUDED_LITERALS` in the **same E4 merge**; otherwise 5c is RED. Its reason must state val 27.8%, which is above the DEPTH stack's 22.7%; the ruling's text does.
- **Every other foreground the sheet paints is already claimed** (GREEN, YELLOW, RED, PURPLE, HILITE) or excluded as achromatic (VALUE, DGRAY), and the DEPTH grounds are excluded (`:850-866`). So `tc079_5` sees the same set of claimants, and MAGENTA's optimum does not move.
- **No exclusion goes stale.** `#1c2438` and `#101828` stay in `ramp_style` (`definition_bench.py:469`, `:477`), which `definition_bench_view.py:155`, `:421` still use. Group B edits lines below `:477`, so the reason's line numbers still hold.
- **No claim goes stale.** Rich `green` / `red` are excused by the `named` set (`:1100`), so the sheet dropping them breaks nothing.
- **No test pins** `definition_sheet._OK` / `_WARN` / `_BAD` / `_ACCENT`, or rich `green` / `yellow` in the Inc 8/9 tests (grep: none).
- **The docstring edit** at `insight_style.py:75-84`: no test reads that text. `test_import_census.py:360` reads only `def microbar`. Any hex quoted in the new comment must be a claimed one.

The verdict-hue rule is consistent with `json_highlight.py:97-103`; MAGENTA keeps its meaning. One operator-page line is still owed (E3-8b-12).

**6. Hostile input.**

Covered, each with an `If` row and an example:

| Input | Row |
|---|---|
| name, unit and enum text too wide, wide characters, 10,000 characters | R-PE-DEF.96 |
| huge limits | .105 |
| upper ≤ lower | .76 |
| non-finite limits | .106 (built directly; E3-8b-09) |
| masks wider than 16 bits | .109 |
| short last hex row | .110 |
| non-printable bytes | .111 |
| over-wide card line or title | .112 |

Control characters and markup: Inc 8's .70 and .71 are `U` rows over "every text the staging sheet paints". They still apply, but the new card path has no case (E3-8b-06).

**Not covered:** a NaN value or an overflowing span in the track — a reachable crash (E3-8b-04, MAJOR).

**7. F-R14-1: yes, both stated causes are removed.**
1. *Cell covered by the text colour:* the strip no longer uses `ramp_style`'s `█`. It is DGRAY with no ground (R-PE-BENCH.95→.108), so the row's ground shows behind it. The third cause, an unstyled chart strip in the brightest foreground, is fixed by the same DGRAY.
2. *Full-height blocks touching the rows around them:* the top level is `▇` (7/8), so every strip cell keeps at least 1/8 of ground at its top. A block in row r ends at the bottom of its cell, and the cell below starts with that gap (R-PE-BENCH.94→.107). E5 confirms it in a real capture with `f_r14_1_probe.py`. The bench canvas keeps its own `█` blocks inside the expanded object, where no strip sits next to them.

**8. Slice size and the E4 worker groups** (7 source files after E3-8b-02; each group ≤ 4; disjoint ownership):

| Group | Source files | Nodes | Tester owns (tests uncapped) |
|---|---|---|---|
| **S — render** | `definition_sheet.py` | 20 (+ R-PE-DEF.114 in `limits_cell`) | S tests; Inc 8 S1 tests re-aimed |
| **B — bench strip and limits, rule text** | `definition_bench.py`, `insight_style.py` (comment) | 2 + `_BLOCKS` + comment | B tests; Inc 9 cell tests re-aimed; the `_EXCLUDED_LITERALS["#1c2547"]` entry in `tests/test_tui_patch_json.py` |
| **W — widget, bench geometry, picker, help** | `patch_editor/sheet.py`, `patch_editor/bench_sheet.py` (`_bench_geometry` only), `a2l_parameter_picker.py`, `window_help.py` | 8 + `_detail_geometry` + `_bench_geometry` | W tests; harness CSS `tests/support/b103_inc8_s2.py`; R-PE-BENCH.36 re-run |

Then the AT tester (keys and dialogs across the groups: ←/→ on an enum and Home/End at 80, 118 and 220; Tab order) and the integrator.

Order inside Inc 8b: the graph pins S's names (`range_cell`, `limit_slot`, `header_rule`, the style constants, `row_line(odd=)`), so S, B and W can be implemented in parallel. B's and W's tests that import S's new names run after S lands.

**E4 order across increments: confirmed — Inc 8b first, Inc 9b from Inc 8b's merge.** Reasons:
- Both edit `bench_sheet.py` (E3-8b-02), which is Inc 9b's own §7 trigger.
- The ids must be renumbered first.
- Inc 9b's measurement base must include Inc 8b (E3-8b-08).

## Test cases' full / partial marks (reviewer rule 4)

Not applicable at this stage. Columns 5 and 6 of `02-test-cases.md` stay empty by design until E4 (the tester fills them; line 3 of the file). There was nothing to re-check.

## Checks not run, and why

- **No pytest, no app run, no Textual pilot** (HT-01 on this PC). This covers:
  - the scroller's binding pre-emption (E3-8b-03): read in Textual 8.2.8's source, state `not-run`; E4 adds cases R-PE-DEF.33/3, .94/6, .92/3;
  - the height selector (E3-8b-05);
  - the width-only resize (E3-8b-11);
  - the census pass (answer 5): by reading only.
- **E3-8b-04 was reproduced** with the product's formula copied into a standalone script (`python -I -B`, no `s19_app` import). It was not reproduced through `decode_definition`. That FLOAT32 `FF FF FF FF` decodes to NaN is read, not run (`a2l_definition.py:3211-3218` → `_decode_scalar`; `display_text` handles `nan`).
- **The prototype PNG captures were not opened.** Only the sidecar text `D.off.sheet.118x54.png.txt` was read (answer 4).
- **Inc 9b's requirements, cases and rulings** were read only where they touch these interfaces: slice, graph, ids. Inc 9b itself was not reviewed.
