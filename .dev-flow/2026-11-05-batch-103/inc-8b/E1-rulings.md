# Inc 8b — E1 rulings: rows changed, F-R14-1, colour tokens and the hue census, decisions, visible provisional choices, backlog

Batch `2026-11-05-batch-103`, increment 8b, stage E1, 2026-11-14, model Opus (E1 + E2 worker, DF-03). Base `09001bbc`. Requirements `01-requirements.md`; slice `E1-slice.md`; graph `codewire/graph-inc8b.md`.

## 1. Sources and what the approved design fixes

- **Verdict** (`s19-proto8-review/verdicts-proto8.json`, read in full; P-130): A rejected; B rejected with the note "la más consistente con el diseño actual"; C no verdict; **D chosen with changes**, note verbatim: "Esta variante es la que tiene mejor organización. El único detalle que persiste como problema es la desalineación de los indicadores con líneas en la columna de "limits". Tenemos que buscar la manera de estandarizar los valores, unidades y líneas para que se mantengan alineadas en toda la columna."; progress P3 (Inc 9b's); general note empty. Follow-up (P-130): "D + tarjeta de bits de B".
- **The approved look** = the real captures `proto8/captures/D.off.sheet.118x54.png`, `D.off.sheet.220x60.png`, `D.off.number.118x54.png`, `D.off.text.118x54.png` (grid, tokens) and `B.off.sheet.118x54.png`, `B.off.text.118x54.png` (the card), read on branch `b103-proto8` `3db20532`; prototype source `proto8/proto8_app.py` (`paint_d` `:473-504`, `_gutter` `:507-518`, `restyle_row` `:93-121`, `_box` `:227-237`, `_bit_table` `:240-278`, `_hex_grid` `:281-310`, tokens `:36-39`).
- **What D's captures show that the operator objected to** (`D.off.sheet.118x54.png.txt` body): `0 ├◆…●┤ 1` vs `-40 ├…┤ 150` — the track starts after a lower of its own width; `0 … 65.5k` and `-1.00k … 1.00k` on the bench rows have no track and start the range at the column start. R-PE-DEF.104 fixes all three with fixed slots.
- **A defect in B's card the captures show** (DF-04 a, fixed to the design): on a span whose last hex-grid row is short (V171 ASCII, 42 B, row `+20`) the ASCII guide follows the last byte instead of its column (`B.off.text.118x54.png`). R-PE-DEF.110.

## 2. Rows changed, retired or checked (with reasons)

| Row | Change | Reason |
|---|---|---|
| R-PE-DEF.5 | header line with gutters, fixed starts | D (A3) |
| R-PE-DEF.6 | retired → .89, .90 | the grid widths no longer depend on the view (A3: "replaces R-PE-DEF.6/.7") |
| R-PE-DEF.7 | retired → .92, .93, .95, .96, .107 | the grid is wider than the view at 118 and scrolls; each half of .7 gets its own row |
| R-PE-DEF.21 | the aligned limits cell; the "track under 6 cells" case gone | operator note on D; the Limits width is fixed at 34, so the track is always 18 |
| R-PE-DEF.33 | the enum options sit in the card | V-11 (the expanded object stands apart); B's card frame |
| R-PE-DEF.34 | bit strip → bit table | V-8, B's card |
| R-PE-DEF.35 | text rows → hex grid | V-9, B's card |
| R-PE-DEF.76 | `lo … hi` → the range form | alignment |
| R-PE-DEF.81 | visible = body − 2; examples recomputed | the header rule takes a line |
| R-PE-DEF.85 | + Home and End | the new keys must be in the help (R-WHELP.12, TC-B97-32) |
| R-PE-BENCH.5 | lines ≤ V once the trailing ground is removed | the expanded ground pads each line to max(G, V) |
| R-PE-BENCH.11 | seven levels; grid strips by column-mean level | F-R14-1 (§3) |
| R-PE-BENCH.17 | the range form | alignment of bench rows with scalar rows |
| R-PE-DEF.31 | **checked, unchanged** | A3 lists .31 among the rows B's card changes. B's card head is the same definition line, word for word (`B.off.sheet.118x54.png`: `└ IDENTICAL phys = (word & 0x0001) >> 0 · …`); its bar and ground are R-PE-DEF.107; nothing in .31's text or examples changes. |
| R-PE-DEF.15, .20, .22 … .28, .30, .36 … .41, .70, .71, .79; R-PE-BENCH.13, .18 | checked, unchanged | texts unchanged; their styles are .97 … .101, the clip is .96, the card is plain text under .70/.71 |

## 3. F-R14-1 — the summary strip's white bars (cause, requirement, fix)

**Cause, from the code and the capture** (`evidence-e1/f_r14_1_probe.py`, transcript `f_r14_1_probe-transcript.txt`, on `proto8/captures/base.off.sheet.118x54.png`, the unpatched base):
1. **The grid strip shows its foreground, not its ramp.** `summary_strip` (`definition_bench.py:521-526`) draws `█` with `ramp_style(step)` = `#ffffff on <ramp>` for steps 0–5 and `#101828 on <ramp>` for 6–11 (`:467-478`, the bench canvas's text colours). A full block covers the cell with its foreground, so every grid cell is white or near-black and the ramp never shows: the probe reads MAP_DEF_0001's cells as `(16,24,40)`, `(255,255,255)`, `(16,24,40)`, `(255,255,255)` — steps `10 3 8 4` of EX-G2 split by the `< 6` rule.
2. **Full-height blocks join across rows.** The chart strip's top level is `█` (`_BLOCKS = "▁▂▃▄▅▆▇█"`, `:434`, level 1 + round(t × 7)) and the grid strip is all `█`; Windows Terminal draws block elements edge to edge in the cell, so a full block touches the block of the row above or below. The probe: `joined cells CURVE_DEF_0001 -> MAP_DEF_0001 = [1, 3]`, `MAP_DEF_0001 -> VAL_BLK_DEF_0001 = [1]` — the white cells of three rows stack into the "tall bars" (`▇` of CURVE over the two white MAP cells over the white VAL_BLK cell).
3. The chart strip has no style at all (`line.append(_BLOCKS[...])`), so it is painted in the default foreground (#e9e9e9, the probe's `(233,233,233)`), the brightest thing in the sheet.

**Requirement the cue must meet:** R-PE-BENCH.107 (no strip block taller than 7/8 of the cell: a ground gap stays above every block, so two rows never join) and R-PE-BENCH.108 (the strip in the dim style, no ground of its own). R-PE-BENCH.11 changes its examples. (E3R1: ids renumbered from .94 / .95, which are Inc 9b's; E3-8b-01.)

**Fix in the graph** (`summary_strip`, `EX-8B-F1` … `F3`): seven levels `▁ … ▇`, level 1 + round(t × 6); a grid strip draws one block per sampled column at the level of its finite mean (the ramp colour is dropped from the strip; the bench canvas keeps its ramp); the strip is painted DGRAY with no background. Before → after: CURVE `▅▇▄█▁` → `▄▆▃▇▁`; MAP (shaded `████`) → `▆▃▅▃`; VAL_BLK (shaded `███`) → `▄▃▄` (`S.*`). Side effect: the strip width now comes from the fixed Current width (20), so F-X9r-1 (VB1D strip painted 8 blocks where 16 fit at 220, width read before layout) goes away with it.

## 4. Colour tokens, the verdict-hue rule and the hue census

**Tokens** (CTX-PE-DEF sheet styles): every colour is an existing `insight_style` / `render.format` constant except the selected-row ground. D's prototype (`proto8_app.py:36-39`) used FG `#e9e9e9` = VALUE, DG `#969aad` = DGRAY, ACCENT `#91abec` = HILITE, GREEN `#54efae`, PURPLE `#b565f3`, YELLOW `#f6ff8f`, RED `#fd8383`, ODD `#131a2c` = DEPTH_ODD_ROW, BAND `#1b233a` = DEPTH_BORDER, CARD `#0f1525` = DEPTH_PANEL, BG `#0a0e1b` = DEPTH_BG, and SEL `#1c2547` (new).

**The verdict-hue rule — one rule, stated, with its consequence.** Today `insight_style.py:75-84` says GREEN / YELLOW / RED are "claimed as verdicts" inside `#patch_editor_panel`, and `json_highlight.py:97-103` keeps them out of the JSON view for that reason; the shipped sheet already paints rich `green` on `●` and `✓`, `yellow` on `▲`, `red` on `✗` (`definition_sheet.py:32`, `:788`, `:887-888`, `:921`), and D's tokens add GREEN for a staged row's New and Δ.
- **Rule (CTX-PE-DEF "verdict hues", R-PE-DEF.101):** inside `#patch_editor_panel` GREEN, YELLOW and RED are state hues that ride their glyph — GREEN with `✓` (passed) or `●` (staged), YELLOW with `▲` (notice, partial), RED with `✗` (failed, refused); a hue is painted there only on a line that carries its glyph, and a cue that is not a state never takes them. (E3R1, E3-8b-12: the widening of GREEN to `●` staged is also a row of the CTX-PE-DEF style table and goes to the operator as V8b-13, §6.)
- **Consequence:** a staged row may be GREEN because its line carries `●`; a pending row whose preview gave a notice stays in the pending style (the prototype's YELLOW tone on its New and Δ had no `▲` on that line — dropped, R-PE-DEF.99/2); a refused row's RED is lawful because its Δ reads `✗ refused`; the paste gauge (MAGENTA) and the JSON tokens are unchanged; `json_highlight.py:97-103` stays true and is not edited. The docstring edit at `insight_style.py:75-84` (group B, a comment only) replaces "claimed as **verdicts**" with this rule; its text is in the graph (`insight_style.MAGENTA (docstring)`).
- **Second consequence (no new hue):** the sheet stops painting the rich named `green` / `yellow` / `red`; it paints the palette's GREEN #54efae, YELLOW #f6ff8f and RED #fd8383, which the census already claims. Rich `yellow` (#808000) was never in `_CLAIMED_HUES` (the census's known gap for named styles, `test_tui_patch_json.py:1048-1053`); the sheet no longer uses it.

**Hue census entries this change needs** (`tests/test_tui_patch_json.py`, test-side, E4 group B's tester):
- `_EXCLUDED_LITERALS["#1c2547"]` = "staging-sheet selected-row ground (definition_sheet.py) — background fill (val 27.8%), not a foreground cue". Same law as the DEPTH stack and `#1c2438` (`:850-866`). It is above the 22.7% the DEPTH comment names, so the reason states the value; it paints no glyph.
- **No `_CLAIMED_HUES` entry:** every foreground the sheet paints is already claimed (GREEN, YELLOW, RED, PURPLE, HILITE) or excluded as achromatic (VALUE, DGRAY). So `test_tc079_5_magenta_hue_distance` sees the same claimant set and MAGENTA's optimum does not move.
- **No stale entry:** `definition_sheet.py` keeps `_ACCENT = "#91abec"` only if the implementation keeps the literal; if it imports HILITE instead, `#91abec` stays swept elsewhere (`insight_style.py:68`), so `tc079_5c`'s stale-claim check is unaffected either way. `ramp_style` (`#1c2438`, `#101828`) keeps its bench canvas sites (`definition_bench_view.py:155`, `:421`), so those exclusions stay live after the strip stops using it.

## 5. Decisions (not visible; ruled here)

- **D-1 `sheet_widths(width)` keeps its signature** and returns the grid widths whatever `width` is. Inc 9's `bench_sheet.py:138` calls it for the strip width; keeping the call valid means Inc 8b does not touch `bench_sheet.py`, which Inc 9b is likely to own (the busy cue). The parameter is unused after the change; the docstring says why.
- **D-2 One layout for the Limits column:** two 7-cell slots and an 18-cell track at fixed offsets for every row kind; rows without a track use the same slots with `…` (range) or `-` (no limits) at the track's centre (offset 16). "Unidades" is read as the short number's unit letter (`k`, `M`, `G`): it gets its own cell, so the letters stack in one column and the digits align on their last digit. (The engineering unit has its own column, Unit, just left of Limits.)
- **D-3 Overflow of a slot:** a short number wider than 6 cells (|x| ≥ 999.5e9) takes the exponent form `<d>e<exp>` (at most 6 cells up to |x| ≈ 1.8e308); ±inf and nan are 3–4 cells; a limit that is not finite takes the range form (no track position is computed from it: `round(nan)` raises today, `definition_sheet.py:724`).
- **D-4 The expanded object's widths:** the kind's detail is laid out for V − 4 (the bench sizes its canvas to what is visible, as today); every line is cut at max(G, V) − 4 and padded with the expanded ground to max(G, V); a card is at most max(G, V) − 4 wide, so at 80 columns the bit card (73) and the hex card (78) are reached by scrolling instead of being cut.
- **D-5 Bit table for words wider than 16 bits:** one block per 16 bits (B's prototype drew one row per word: a 32-bit mask would be 123 cells, a 64-bit one 219).
- **D-6 The card title of a bit mask keeps "other bits kept"** (the dropped second line of Inc 8's bit strip said it); the mask line of the old strip is the table's `mask` row now.
- **D-7 `_SheetBody.on_resize` finds its sheet among its ancestors**, not as its parent: the grid scroller sits between them (the prototype hit the same, `proto8_app.py:720-723`).
- **D-8 The zebra counts page positions** (`row_line(…, odd=…)`, the sheet passes `position % 2`): a stable stripe while the window scrolls.
- **D-9 The F-R14-1 fix lands in `definition_bench.py`** (Inc 9's module) as two function edits and one constant; Inc 9 is merged (`b751be53`), so this is an ordinary change of a shipped module, not a seam exception.

## 6. Visible, provisional (operator page)

Each was decided here so the work could go on (DF-02 / DF-09); the orchestrator puts them on one page.

| Id | Choice (provisional) | Alternative | Consequence of the choice | Consequence of the alternative |
|---|---|---|---|---|
| V8b-1 | Home / End scroll the grid to its first / last view position (R-PE-DEF.94) | shift+← / shift+→ by one column start | two keys, no conflict: shift+arrows are the bench's cell-selection keys (`bench_sheet.py:51-54`); at 80 columns the middle columns are reached by the mouse or the scrollbar only | finer stepping, but the same key means two things depending on which part of the sheet has the focus |
| V8b-2 | the last view position may cut the leftmost visible column on its left with no mark (at V = 111 it starts 3 cells into Kind) | snap the last position to a column start (pad the grid on the right) | no cut-cell mark yet (backlog item 5 of PLAN keeps it open) | needs a padded virtual width; one more rule |
| V8b-3 | range form (bench rows, upper ≤ lower, not finite): `…` at the track's centre, the rest of the track blank | a dim dashed line `┄` across the track | the slots align with the ruler rows; nothing looks like a ruler that has no marker | lines run down the whole column, but a range could be read as a ruler without its marks |
| V8b-4 | no limits: `-` at the track's centre (offset 16) | `-` right-aligned in the lower slot | the "no range" mark sits where `…` sits on a range row | it reads as a missing lower only |
| V8b-5 | the unit letter of a short number gets its own cell (`  65.5k`, ` -1.00k`) | the unit letter inside the 6 number cells | the letters stack in one column; digits align by their last digit | one cell narrower slot; `k` and the last digit share a column |
| V8b-6 | the summary strip: seven-level blocks for curves and for grids (column means), in DGRAY | the grid strip as `▇` in its ramp colour as foreground, no ground | one cue for every array kind, no row joins its neighbour, no new colour | keeps the ramp link to the bench canvas, but step 0 (#1c2438) vanishes on the dark, zebra and selected grounds |
| V8b-7 | a pending row whose preview gave a notice keeps the pending style (PURPLE); `▲` YELLOW stays on the formula tail | the prototype's YELLOW tone on the row's New and Δ | obeys the verdict-hue rule (no `▲` on the row's line) | YELLOW without its glyph on the row line |
| V8b-8 | changed bytes and bits are also underlined (the pending style's colour-free cue) | colour only, as in B's prototype | R-PE-DEF.103 holds: the change shows with NO_COLOR | no cue without colour on the hex grid |
| V8b-9 | the filter icon `▽` (`▽ Pick`, D's prototype source `proto8_app.py:49`) | `⧩` (A and C) or `▼` (B) | matches D; `▽` is a 1-cell glyph in Windows Terminal | another glyph the operator may read better as a filter |
| V8b-10 | a number row has no card: its expanded object is the definition line on the band | B's number card (`raw … │ bytes … │ limits … │ ✓`) | no repeat of the formula tail | a fuller card; the same facts twice on the screen |
| V8b-11 | enum options keep their Inc 8 text inside the card (`( ) 0 OFF   (●) 1 IDLE …`) | B's enum card (`│` between entries, `←→ choose · ⏎ stage`) | Inc 8's approved wording kept; only the frame is new | B's look, a text change on a row the operator approved at Inc 8 |
| V8b-12 | the bench detail (canvas, legend, tools, bytes) also gets the `┊` bar and the expanded ground (V-11 for every row kind) | bar and ground on Inc 8's kinds only | one look for every expanded object; the bench canvas is laid out 4 cells narrower | the bench keeps its full width; two looks for "expanded" |
| V8b-13 | (E3R1, E3-8b-12) inside `#patch_editor_panel`, GREEN = `✓` passed **or `●` staged** (CTX-PE-DEF style table, row "verdict hue"); this widens batch-48 Inc-2b's GREEN = "a check passed" | GREEN for `✓` only; a staged row's `●`, New and Δ in another hue | a staged row reads GREEN as in D's approved captures | no restated operator rule; staged needs a hue of its own (a new census claimant) |

## 7. Backlog (deferred; DF-04 "new → defer")

1. B's number card (V8b-10's alternative).
2. The keycap look of the sheet's border subtitle (D's `↵ edit · ↑↓ row` capture); it lives in `layout.py`, which Inc 9b's busy pill (border title and colour of `#patch_sheet_win`) is likely to own.
3. A frozen mark + Parameter column while the grid scrolls (not in D; the names scroll away at the last view position).
4. Snapping the last view position to a column start, or marking a left-cut cell (V8b-2; PLAN backlog item 5).
5. The help window's own colour guides (V-12), not in A3's scope.
6. A real-capture check that `▽` renders as a hollow triangle in Windows Terminal (D's 118 capture shows a filled-looking glyph at that size; E5 capture verdict).

## 8. Interfaces pinned or changed (and their users)

- **Changed, used by Inc 9 (merged; no Inc 9b use known):** `sheet_widths(width) -> SheetWidths` returns the fixed grid widths (`bench_sheet.py:138` reads `.current`); `detail_lines(row, preview, width, state, room)` — the kind's detail is laid out for `width` = V − 4 and each returned line carries the bar and ground (Inc 9's `KindOps.detail` for array, curve and map rows is called through it); `summary_strip(values, grid, width)` (same signature, new levels and style); `bench_cells(row, state, widths)` (same signature, Limits through `range_cell`).
- **New, pinned here:** `range_cell(lower, upper) -> Text` and `limit_slot(x) -> Text` in `definition_sheet.py` (users: `limits_cell`, Inc 9's `bench_cells`); `row_line(…, odd: bool = False)` (one more keyword, default keeps old calls valid; user: `StagingSheet._paint`); `header_rule() -> Text`.
- **E3R1 (E3-8b-02, E3-8b-03):** new `StagingSheet._detail_geometry() -> tuple[int, int]` (users: `_paint`, `_fit_window`, `ArrayBenchSheet._bench_geometry`); `ArrayBenchSheet._bench_geometry` (`bench_sheet.py`, that one function) now uses it, so `bench_sheet.py` leaves the list below for that function only; `#patch_sheet_grid` is a plain `textual.containers.Container`.
- **Not touched, so Inc 9b may own them:** `bench_sheet.py` (all but `_bench_geometry`, E3R1), `definition_bench_view.py`, `app/patch.py`, `layout.py`, `panel.py`, `styles.tcss`, the `#patch_sheet_win` border title and subtitle.
- **Shared files with Inc 9b: unknown until its graph names its files.** If Inc 9b changes `sheet.py` (`StagingSheet`), `definition_sheet.py`, `definition_bench.py` or `insight_style.py`, the E4 order follows A3 (Inc 9b starts from Inc 8b's merge).

## 9. Is E3 needed?

Not under A3's rule as far as this side can see: the graph pins no interface Inc 9b is known to use, and nothing reads or writes outside the program (the new inputs are two keys and A2L numbers already parsed). Two conditions would make it needed: Inc 9b's graph naming `StagingSheet.compose` / `_paint` (the scroller and the paint order) or `detail_lines`; or the orchestrator wanting the verdict-hue rule reviewed, since it restates an operator rule (batch-48 Inc-2b) for a whole panel. In either case one reviewer on those nodes only.
