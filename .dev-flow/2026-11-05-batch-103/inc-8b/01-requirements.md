# Inc 8b — Patch Editor staging sheet: grid D, colour tokens, aligned Limits, bit and text card — requirements (E1)

Batch `2026-11-05-batch-103`, increment 8b, stage E1, 2026-11-14, model Opus (E1 + E2 by one agent, DF-03). Base `09001bbc` (`b103-inc9` `b751be53` + E0 amendment A3); every line number is "as of `09001bbc`". Authority: `../PLAN.md` amendment A3; the operator's proto8 verdict (variant **D (grid)** chosen with one change — the Limits column's indicators, values, units and lines aligned down the whole column — plus **B's bit card on expand**; progress is Inc 9b's); prototype record `proto8/ROUND.md` on the throwaway branch `b103-proto8` `3db20532` (never merged; its PNG captures of D and B are the approved look). Inc 8's rows: `../inc-8/01-requirements.md` (CTX-PE-DEF, R-PE-DEF); Inc 9's: `../inc-9/01-requirements.md` (CTX-PE-BENCH, R-PE-BENCH). Rulings: `E1-rulings.md`. Slice: `E1-slice.md`. Cases: `02-test-cases.md`. Graph: `codewire/graph-inc8b.md`. E3 corrections (E3R1, targeted edits from `E3-rulings.md`): `E3R1-changes.md`; E4 addenda: `E3-addenda.md`.

This file holds only what Inc 8b adds or changes. A changed Inc 8 or Inc 9 row keeps its id and is restated here in full; a retired row is restated with `— Withdrawn` and its replacing ids; every other Inc 8 and Inc 9 row stands as written there.

Base column codes: **R** read in the code at `09001bbc`; **C** read in a real Windows Terminal capture of proto8 (`proto8/captures/<name>.png` and its `.png.txt` sidecar, branch `b103-proto8`); **E** computed by `evidence-e1/examples_inc8b.py` (stdlib only, the formulas of this file; transcript `evidence-e1/examples_inc8b-transcript.txt`, keys `G.*`, `W.*`, `C.*`, `L.*`, `S.*`, `B.*`, `T.*`, `E.*`); **P** proposal that needs a pilot at E4 (a layout or input not yet shown to reach the app). Data: DEFC = `tools/synth/make_release_case.py --case definitions`, seed 20260001 (facts in `../inc-8/evidence-e1/pilot_inc8-transcript.txt` and `../inc-9/codewire/graph-inc9.md` EX-A1 … A3); V171 = `examples/case_00_public/ASAP2_Demo_V171.a2l` with Inc 8's hand image. View widths: V = 111 at 118 columns and 195 at 220 (the sheet body's content width, header length in `proto8/captures/base.off.sheet.118x54.png.txt` and `…220x60.png.txt`); V = 73 at 80 columns is assumed (the same 7 cells of chrome) and measured at E4. **E4 measurement (I8b):** through the real Patch Editor in the headless pilot the grid scroller's content width is V = 70 at 80×24, 110 at 118×54 and 194 at 220×60, on base 48af05ff and on the merged tree alike (`evidence-e4/i8b/probe-geometry-*.txt`); the rows below that tie a terminal size to a V use these, and the `G.view.*` / `G.end.*` keys were regenerated from the corrected script. Rows that name a V alone (V = 111, 73, 195 as a parameter) are unchanged.

## User stories

- **US-103-05** — "The Patch Editor edits a parameter by its A2L definition: scalars, enums, bit masks, text, curves, maps and value blocks." Inc 8b gives the staging sheet the look the operator chose at proto8: the grid with fixed columns, gutters, a header rule and a horizontal scrollbar; the prototype's colour tokens back, each with a glyph or text cue; one aligned layout for the Limits column of every row kind; B's card for bit masks, text and enums when a row expands; a filter icon; the expanded object set apart from the table; and the fix of the summary-strip defect F-R14-1.

## Scope

- **In:** the grid (fixed natural column widths, `│` gutters, header rule, horizontal scroll with a scrollbar and Home / End); the sheet styles (CTX-PE-DEF style table) and the verdict-hue rule that reconciles `insight_style.py:75-84`; the aligned limits cell and its overflow rules, for scalar, enum and bit-mask rows and for bench rows (R-PE-BENCH.17); B's card (bit table with nibble guides, hex/ASCII grid, enum options framed); the expanded ground and `┊` bar under the selected row (V-11, every row kind, the bench included); `▽ Pick` (V-2); the help line for the scroll keys; F-R14-1 (the summary strip of array rows, R-PE-BENCH.11).
- **Out (to the backlog, `E1-rulings.md` §7):** B's number card (`raw … │ bytes … │ limits …`, a repeat of the formula tail); the keycap look of the border subtitle (D's `↵ edit · ↑↓ row`); a frozen Parameter column while scrolling; snapping the scroll to column starts; the help window's own colour guides (V-12); Inc 9b's progress cue (its own increment); any I-2 change.

## Definitions (CTX-PE-DEF amendments — terms and formats only)

Each term below replaces the term of the same name in `../inc-8/01-requirements.md` §Definitions, or is new (marked **new**). CTX-PE-DEF's other terms stand.

```text
filter row       One terminal row above the sheet: the shared picker's filter input, its status
                 `<n> of <m> shown`, Prev, `Page <p>/<q>`, Next, Include parameter, Add list. The
                 compact filter row paints Prev, Next and Include parameter `<`, `>` and `▽ Pick`
                 (Inc 8b: the filter icon `▽`, V-2).
staging sheet    The window with border title `STAGING SHEET` and its subtitle (unchanged). Top to
                 bottom: the grid scroller (the header line, the header rule, the sheet rows of the
                 row window, the expanded object under the selected row, and the horizontal
                 scrollbar while the grid is wider than the view), then the formula bar on its
                 last line, outside the scroller.
view width (new) V = the visible content width of the grid scroller, in cells.
grid (new)       The header line, the header rule and the sheet rows, each G = 143 cells wide:
                 the 2-cell mark column, then each column followed by its gutter `│`.
grid widths      (replaces "column widths") Parameter 26, Kind 10, Current 20, New 16, Unit 8,
                 Limits 34, Δ 20, at every view width; a gutter is 1 cell; G = 2 + Σ(width + 1)
                 = 143. Column starts: Parameter 2, Kind 29, Current 40, New 61, Unit 78,
                 Limits 87, Δ 122; gutters at 28, 39, 60, 77, 86, 121, 142. Widths and lengths are
                 counted in terminal cells (a wide character such as `温` is 2 cells): a cell wider
                 than its column shows the longest start that fits in the column's width − 1
                 cells, then one `…`, then spaces to the width.
header line      `  ` then each column's label, left-aligned and padded to its width, then `│`.
header rule (new) `━━` then, per column, `━` × its width and `┿`.
row window       The sheet rows painted. The grid body fills the grid scroller's height less its
                 scrollbar row (E3R1). visible = the grid body's height − 2 (the header line and
                 the header rule); room = visible − 1 (the expanded object is cut to `room` lines,
                 so the selected row is always painted); need = 1 + its lines after the cut. `top`
                 moves as before (CTX-PE-DEF of Inc 8, E3R1 E3A-01, E3R2 E3A-14).
scroll range (new) The grid scroller's horizontal position x, 0 … max(0, G − V). First view
                 position: x = 0. Last view position: x = max(0, G − V) (33 at V = 110, 73 at
                 V = 70, 0 at V = 194; E4-measured V, see the Data note above).
limits cell      (replaced) Exactly the Limits width, 34 cells: `<lower slot> <track> <upper slot>`.
                 slot: 7 cells — the slot text's number right-aligned in the first 6 cells, its
                 unit letter (`k`, `M` or `G` of the short number) in the 7th, else a space there.
                 slot text: the short number of the limit when it is at most 6 cells, else its
                 exponent form.
                 exponent form: one significant digit, `<d>e<exponent>` (4.29e12 → `4e12`,
                 −1.7e308 → `-2e308`).
                 track: 18 cells (the Limits width − 2 slots − 2 spaces) at offsets 8 … 25 of the
                 cell: `├`, `─` × 16, `┤`; `●` at the current value, `◆` at the preview or staged
                 value; a value below lower is `◀` on the left end, above upper `▶` on the right
                 end; a value v in range sits on cell 1 + round(pos × 15), kept within 1 … 16,
                 pos = (v − lower)/(upper − lower), computed on halves (v/2 − lower/2)/(upper/2 − lower/2) only when
                 upper − lower overflows, so a finite span always has a finite pos (E4, R-PE-DEF.117; E5: the
                 halves of a subnormal span such as 0 … 5e-324 are both 0, R-PE-DEF.117/4); a second mark on a taken cell moves one cell
                 right, or one cell left from cell 16 (so no mark lands on `┤`, E3R1).
                 enum: the stored values; bit mask: the field values.
                 no-position form (new, E3R1): both slots and the track `├`, `─` × 7, `?`, `─` × 8,
                 `┤` with no `●`, `◆`, `◀` or `▶` (`?` at offset 16 of the limits cell) — while the
                 current or the new value is not a finite number, or the pos of a value in range
                 is not (since E4 a finite span always gives a finite pos, R-PE-DEF.117). It takes precedence over `◀` and `▶`.
                 range form: both slots, the track's 18 cells blank but for `…` at its cell 8
                 (offset 16 of the limits cell) — while upper is not greater than lower, while a
                 limit is not finite, and on bench rows.
                 no-limits form: 34 cells blank but for `-` at offset 16 — no lower or no upper
                 limit (text rows, refused rows, an array without limits).
expanded object (new) The lines under the selected row: its detail lines (the definition line, then
                 its card). Each line is `  ┊ ` (the bar) then its content, on the expanded ground
                 across max(G, V) cells. The kind's detail is laid out for V − 4 cells and every
                 line is cut at max(G, V) − 4 cells with one `…`.
card (new)       A framed block in the expanded object, after the definition line, for an enum, a
                 bit-mask or a text row: `╭─ <title> ─…─╮`, one `│ <card row padded> │` per card
                 row, `╰─…─╯`; inner width = the widest card row + 2 (at least the title + 4),
                 at most the cap − 2; cap = max(G, V) − 4. Every card width is counted in
                 terminal cells, as the grid widths are (E3R1). title: `<name> · choose one`
                 (enum), `<name> · bit editor · other bits kept` (bit mask), `<name> · text editor
                 · 16 B per row` (text). The title and every card row are CTX-PE-DEF plain text;
                 the title is cut with one `…` to the inner width − 4 cells, a card row wider than
                 the inner width − 2 cells with one `…` (the clip of the grid widths). A number
                 row has no card.
enum options     (unchanged text) the card rows of an enum: the options line, then
                 `↔ choose · enter stage`.
bit table        (replaces "bit strip") The card rows of a bit mask, one block per 16 bits of the
                 word (a word of 8 bits: one block of 8), high bits first. A block is 4 lines:
                   `bit    ` then per bit its number right-aligned in 3 cells,
                   `before ` then per bit its value in the image's word, right-aligned in 3,
                   `mask   ` then per bit `  ■` under the mask, else `  ·`,
                   `after  ` then per bit its value in the word after the preview (else the
                            staged word, else the image's), right-aligned in 3;
                 after every bit whose number is a multiple of 4, the nibble guide ` │`. On the
                 first block only, each line then ends with ` hex`, ` <before bytes>`,
                 ` <mask as 2 hex digits per byte>`, ` <after bytes>` (bytes `XX XX` in span
                 order). A bit that is not held by the image: `?`.
hex grid         (replaces "text rows") The card rows of a text row: the head
                 `off │ +0 +1 … +7 │ +8 … +F │ ASCII`, then one row per 16 of the span's first
                 64 bytes: `+<offset, 2 upper hex> │` then ` XX` per byte (the bytes after the
                 preview) with ` │` after the 8th, three spaces per missing byte of a short last
                 row, then ` │ ` and one ASCII character per byte: the byte's character for
                 U+0020 … U+007E, else `·`. Then `… <n> more B` when the span is longer than
                 64 bytes (R-PE-DEF.79).
sheet styles (new) The style of each element the sheet paints; the table under this block.
verdict hues (new) Inside `#patch_editor_panel`, GREEN #54efae, YELLOW #f6ff8f and RED #fd8383 are
                 state hues and ride their glyph: GREEN with `✓` (a check or an encode passed) or
                 `●` (staged), YELLOW with `▲` (a notice, a partial check), RED with `✗` (failed,
                 refused). A hue is painted there only on a line that carries its glyph; a cue
                 that is not a state (the paste gauge, a JSON token) never takes them.
pending style (new) bold PURPLE #b565f3; on a byte of the hex grid or a bit of the bit table's
                 after row that differs from the image, also underlined.
```

Sheet styles (the colour-free cue is what carries the meaning without colour; R-PE-DEF.103):

| Element | Marks | Style | Colour-free cue |
|---|---|---|---|
| text | names, current values, card values | VALUE #e9e9e9 (the selected row's name bold) | — |
| dim | kind word, unit, `·` of a row with no edit, the Limits text and track, the definition line after `└`, card labels (`bit`, `before`, `mask`, `after`, `off`, `+0`…), bits and bytes outside the mask or unchanged, the summary strip | DGRAY #969aad | — |
| header | header labels | bold DGRAY | the header rule under them |
| rule | header rule `━` `┿`, gutters `│`, nibble and hex-grid guides `│`, card frame, the bar `┊`, `└` | HILITE #91abec | the glyphs |
| selected | the selected row's ground; `▶` | ground #1c2547 (new literal, a background); `▶` bold HILITE | `▶` and the bold name |
| zebra | the ground of every second painted row (odd page position) | DEPTH_ODD_ROW #131a2c | none needed (decoration) |
| staged | New and Δ of a staged row that is not pending; the mark's `●`; the track's `◆` | bold GREEN #54efae | `●` in the mark; Δ ends `staged` |
| pending | New and Δ of a pending row (an encode with a notice included); the mark's `◆`; the track's `◆` | the pending style | `◆` in the mark |
| refused | New and Δ of a pending row whose preview is a refusal | bold RED #fd8383 | `✗ refused` in Δ |
| current marker | the track's `●` | bold VALUE | `●` |
| in limits / notice / refused tail | `✓ in limits`, `▲ <notice>`, `✗ <message>` of the formula tail | GREEN / YELLOW / RED | `✓` / `▲` / `✗` |
| after bytes | the after bytes of the formula tail's `<before> → <after>` | the pending style without underline | `→` |
| key hint | `enter stage ↓` of the formula tail | bold DEPTH_BG #0a0e1b on HILITE | the words |
| mask mark | `■` of the bit table | bold HILITE | `■` against `·` |
| expanded ground | every expanded-object line | ground DEPTH_BORDER #1b233a | the `┊` bar |
| card ground | inside the card frame | ground DEPTH_PANEL #0f1525 | the frame |
| verdict hue (E3R1, operator verdict V8b-13) | inside `#patch_editor_panel`: GREEN = `✓` passed **or `●` staged** (this widens batch-48 Inc-2b's GREEN = "a check passed"); YELLOW = `▲` notice or partial; RED = `✗` failed or refused | GREEN #54efae, YELLOW #f6ff8f, RED #fd8383, only on a line that carries the glyph (the verdict hues above) | `✓` / `●` / `▲` / `✗` |

CTX-PE-BENCH amendment (replaces the Current and Limits clauses of "array row cells" in `../inc-9/01-requirements.md`):

```text
array row cells  Current: the summary strip, then ` <element count>`; strip width = the Current
                 width (20) − 1 − the count's width − 1. chart: one block per sampled point
                 (every k-th, k = ⌈n / strip width⌉) at level 1 + round(t × 6) of `▁▂▃▄▅▆▇`
                 (t = (v − lo)/(hi − lo) over the finite values, 0 when lo = hi; a point that is
                 not finite: a space); grid: one block per sampled grid column at the level of
                 the mean of its finite values (none: a space). The strip is painted in the dim
                 style with no ground. A row not yet summarised: `… <count>`; more than 4,096
                 elements not decoded: `<count> values` (unchanged).
                 Limits: the range form of CTX-PE-DEF; the no-limits form without both limits.
```

## Requirements

Threshold = the number of independently asserted cases that must pass (`n/n`). Negative control = a mutant of the product that must turn the case's test RED. Example keys name lines of `evidence-e1/examples_inc8b-transcript.txt`; graph examples (`EX-8B-…`) are in `codewire/graph-inc8b.md`.

### M1 · The grid (D; replaces R-PE-DEF.6 and .7)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-PE-DEF.5 | U | The system shall show the staging sheet's header line of CTX-PE-DEF. | 3/3 at V = 73, 111, 195: the body's first line equals `G.header_line` (labels at 2, 29, 40, 61, 78, 87, 122; `│` at 28, 39, 60, 77, 86, 121, 142). | Drop the gutter after Kind → `Current` at 39 RED. | US-103-05 | changed at Inc 8b E1 (was: the labels at the starts the width class gives, Kind and Unit hidden below W 100) | R `definition_sheet.py:140-151`; C `D.off.sheet.118x54.png`; E `G.*` |
| R-PE-DEF.6 | U | The system shall size the sheet's columns by the column widths of CTX-PE-DEF. — Withdrawn | — | — | US-103-05 | retired at Inc 8b E1: the grid widths do not depend on the view width; replaced by R-PE-DEF.89 and .90 | R `definition_sheet.py:123-137` |
| R-PE-DEF.7 | U | The system shall paint no sheet row, detail line or formula bar wider than the staging sheet. — Withdrawn | — | — | US-103-05 | retired at Inc 8b E1: the grid (143 cells) is wider than the view at 118 and scrolls; replaced by R-PE-DEF.92, .93 (scroll), .95 (the formula bar), .96 (the wide-character clip) and R-PE-DEF.107 (the expanded object's cut) | R |
| R-PE-DEF.89 | U | The system shall give the sheet's columns the grid widths of CTX-PE-DEF at every view width. | 3/3 at V = 73, 111, 195: on the DEFC page every row's cells start at the column starts (`G.start.*`) and every row line is 143 cells. | Keep Inc 8's width classes → at V = 73 Kind is hidden and Current starts at 18 RED. | US-103-05 | new (A3, D) | C `D.off.sheet.118x54.png.txt` (145-cell lines, D's prototype widths); E `G.grid_width` |
| R-PE-DEF.90 | U | The system shall paint a `│` gutter after each column of every sheet row. | 2/2 at V = 111: every DEFC row line has `│` at 28, 39, 60, 77, 86, 121, 142; a row named with 40 characters keeps `│` at 28. | No gutter after a clipped cell → the 40-character case RED. | US-103-05 | new (A3, D) | C `D.off.sheet.*` |
| R-PE-DEF.91 | U | The system shall show the header rule of CTX-PE-DEF on the line under the header line. | 1/1: the body's second line equals `G.header_rule` (143 cells, `┿` at each gutter). | No rule → the second line is the first row RED. | US-103-05 | new (A3, D) | C `D.off.sheet.*`; E `G.header_rule` |
| R-PE-DEF.92 | While | While the grid is wider than the view width, the system shall show a horizontal scrollbar under the sheet rows. | 3/3: at 80×24 and 118×54 the grid scroller's horizontal scrollbar is shown and its virtual width is 143 (`G.scrollbar.80cols`, `.118cols`); with the scrollbar shown, the Patch Editor's Tab order is the base's and the scroller never holds the focus. | `overflow-x: hidden` on the scroller → RED; the prototype's focusable `ScrollableContainer` as the scroller → one more Tab stop RED. | US-103-05 | new (A3, D); E3R1 (E3-8b-03: the scroller takes no focus) | P (layout measured at E4); C `D.off.sheet.118x54.png` (the bar under the rows) |
| R-PE-DEF.93 | While | While the grid is not wider than the view width, the system shall show no horizontal scrollbar. | 1/1: at 220×60 (V = 194) the scroller shows no horizontal scrollbar and the body takes the scrollbar's row. | `overflow-x: scroll` → RED. | US-103-05 | new (A3, D) | P; C `D.off.sheet.220x60.png` (no bar) |
| R-PE-DEF.94 | When | When the operator presses Home or End while the staging sheet's body holds the focus, the system shall scroll the grid to its first or last view position of CTX-PE-DEF. | 4/4: V = 110 (118×54): End → x = 33, then Home → x = 0 (`G.end.118cols`); V = 70 (80×24): End → 73; V = 194 (220×60): End → 0; V = 110: x read right after End, with no wait, is 33 (no animation). (E4: V measured; E1 wrote 111/32, 73/70, 195/0.) | No binding → x stays 0 at V = 110 RED; End scrolls by one cell → x = 1 RED; an animated scroll (the scroller's own `scroll_end`) → x < 33 right after End RED. | US-103-05 | new (A3: "shown, not driven" in ROUND.md); E3R1 (E3-8b-03: no animation) | R home/end reach the app on Windows Terminal (`window_help.py:713-714` binds them in the shipped help window); not bound by the bench (`bench_sheet.py:51-64`) nor the app (`app/core.py:190-240`) |
| R-PE-DEF.95 | U | The system shall paint the formula bar no wider than the staging sheet. | 3/3 at 80, 118 and 220 columns: the bar's region width ≤ the sheet window's content width; the `x`×300 refusal tail ends in `…` and fits (R-PE-DEF.41). | Compose the bar inside the grid scroller → 143 cells at 80 RED. | US-103-05 | new (the formula-bar half of R-PE-DEF.7) | R `sheet.py:120-131` |
| R-PE-DEF.96 | If | If a sheet cell's text is wider than its column, then the system shall show the longest start of it that fits in the column's width − 1 cells, then `…`. | 6/6: a name `温度`×14 → `C.name_wide.fit26` (12 characters, 25 cells, `…`, one pad cell); a unit `温度温度温度` → `C.unit_wide.fit8`; an enum entry text of 300 `X` → Current `C.enum_long.current20`; a 10,000-character name → `C.name_10000.fit26` with at most 120 characters read; a unit of 40 characters → `C.unit_40.fit8` and the Limits column still starts at 87; boundary: a name `A\x1b[2JB` (6 cells, not wider) → `C.name_esc.fit26` (cleaned, no `…`, padded to 26). | A `len()` clip → the wide case 50 cells RED; a clip that cleans the whole text (spy on `plain`) → 10,000 characters RED; a clip on every text → `…` on the boundary case RED. | US-103-05 | new (the cells case of R-PE-DEF.7; hostile names, units and enum texts); E3R1 (E3-8b-06: the boundary case gives EX-8B-C1's `C.name_esc.fit26` a case) | R `definition_sheet.py:64-97` |
| R-PE-DEF.81 | When | When the selected row or the shown page changes, the system shall paint the sheet rows of the row window of CTX-PE-DEF. | 5/5 at 118×54, a 200-name software_a page: 40 × down → the selected row's line and its expanded object lie inside the grid body's content region; then up past the first painted row → the selected row is the first painted row; the selection moved down onto an enum row of that page on the window's last line → its definition line and card inside the region; a stand-in kind with 10 detail lines at the 12-row minimum (grid body 8, visible 6) → the selected row painted and its expanded object cut to 5 lines (`W.standin_10_detail.h8.painted`); the test host at 118×54 (no chrome): grid scroller 53 rows, grid body 52, visible 50 (`W.harness_118x54.*`). | Paint every row from row 0 → the first case RED; visible = body − 1 (Inc 8's, no rule line) → the last row under the region RED; no height rule for the body under the scroller → the body as tall as its own text, visible ≠ 50 RED. | US-103-05 | changed at Inc 8b E1 (visible = body − 2: the header rule; the enum case now a card; was: visible 8, cut to 7); E3R1 (E3-8b-05: the body's height under the scroller) | R `sheet.py:325-334`; E `W.*` |

### M2 · Sheet styles (D's colour tokens; the verdict-hue rule)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-PE-DEF.97 | U | The system shall paint each element of the staging sheet that the sheet styles of CTX-PE-DEF name in its style. | 12/12, one case per row of the table that does not depend on a row's state (text, dim, header, rule, selected, zebra, current marker, after bytes, key hint, mask mark, expanded ground and card ground), read from the rendered `Text` spans of the DEFC page at V = 111 (colour and ground resolved to hex). | Gutters in DGRAY → the rule case RED; no zebra ground → RED; the selected ground missing → RED. | US-103-05 | new (A3: D's colour tokens; operator V-1/V-3/V-5/V-7 "the prototype's colour back") | C `D.off.*.png`; R today `definition_sheet.py:31-32`, `:788`, `:792`, `:806` (accent and named colours) |
| R-PE-DEF.98 | While | While a row is staged and not pending, the system shall paint its New and Δ cells, its mark's `●` and its track's `◆` in the staged style. | 3/3: DISPLAY_0001 staged 25.5 → New `25.5`, Δ `-118.0 staged`, `●` bold #54efae; MASK_FIELD_0001 staged 255 → the same on `255 (0xFF)` and `+81`; VAL_BLK_DEF_0001 staged with no bench edit → `●` and Δ `max \|Δ\| … staged`. | Rich `green` (#008000) for `●` (today) → RED; New unstyled (today) → RED. | US-103-05 | new (A3) | R `definition_sheet.py:788-808`; C `D.off.sheet.118x54.png` (staged green) |
| R-PE-DEF.99 | While | While a row is pending, the system shall paint its New and Δ cells, its mark's `◆` and its track's `◆` in the pending style. | 3/3: DISPLAY_0001 `25.5` → New, Δ `-118.0 (-62.1%)` and `◆` bold #b565f3; DISPLAY_0001 `175` (an encode with a notice) → the pending style; VAL_BLK_DEF_0001 with a bench edit → `◆` and New `2 cells`. | The prototype's YELLOW tone for a notice → the `175` case RED; the accent #91abec (today) → RED. | US-103-05 | new (A3; the "pending style" Inc 8 named at `:139` and `:221` and never defined) | C `D.off.sheet.118x54.png` (pending purple) |
| R-PE-DEF.100 | If | If a pending row's preview is a refusal, then the system shall paint its New and Δ cells in the refused style. | 1/1: DISPLAY_0001 `250` → New `250`, Δ `✗ refused`, bold #fd8383. | Keep the pending style → RED. | US-103-05 | new (A3) | R `definition_sheet.py:782-785` |
| R-PE-DEF.101 | U | The system shall paint the verdict hues of CTX-PE-DEF in the staging sheet only on a line that carries their glyph. | 4/4 over every painted line of the DEFC page with a staged row, a pending row, `175` and `250` rows, and the formula bar for each: a span in #54efae lies on a line holding `●` or `✓`; #f6ff8f on a line holding `▲`; #fd8383 on a line holding `✗`; no span is rich `green`, `yellow` or `red`. | A staged row whose mark cell is cleared but whose New is GREEN → RED; the YELLOW tone on the `175` row (no `▲` on its line) → RED. | US-103-05 | new (reconciles `insight_style.py:75-84`, E1-rulings §4) | R `insight_style.py:75-84`, `json_highlight.py:97-103`, `definition_sheet.py:32` |
| R-PE-DEF.102 | U | The system shall underline each byte of the hex grid and each bit of the bit table's after row that differs from the image. | 2/2: V171 ASCII pending `ABC` → offsets 0 … 9 and their ASCII characters underlined (`T.V171.pendingABC.changed_offsets`), no other byte; MASK_FIELD_0001 pending `255` → bits 10, 8, 4 of the after row underlined (`B.MASK_FIELD_0001.pending255.changed_bits`), no other bit. | Underline the mask bits → bit 11 underlined RED; colour only → no underline RED. | US-103-05 | new (the pending style's colour-free cue) | E `T.*`, `B.*` |
| R-PE-DEF.103 | Where | Where the terminal shows no colour, the system shall show every glyph and text of the staging sheet that it shows with colour. | 1/1: the DEFC page (a staged, a pending and a refused row; MASK_FIELD_0001 expanded) painted with `NO_COLOR=1` and without: equal plain texts holding `●`, `◆`, `▶`, `✗ refused`, `■`, and the same underlined cells. | A cue drawn as colour only (the pending `◆` replaced by a purple-ground space) → the texts differ RED. | US-103-05 | new (A3: "a text/glyph cue so the meaning survives without colour") | P (NO_COLOR keeps bold and underline in Textual 8.2.8: pilot at E4) |

### M3 · The Limits column (operator note on D)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-PE-DEF.21 | U | The system shall show each row's limits cell of CTX-PE-DEF in the Limits column. | 5/5: DISPLAY_0001 pending 25.5 → `L.cell.DISPLAY_0001.cur143.5.new25.5` (`   -40  ├─────◆────────●─┤    150 `); MASK_FIELD_0001 pending 255 → `L.cell.MASK_FIELD_0001.cur174.new255`; ENUM_0001 → `L.cell.ENUM_0001.cur1`; a preview of 175 → `▶` at offset 25 (`L.cell.DISPLAY_0001.new175`); a preview of −45 → `◀` at offset 8. | Place `●` by the stored value (287) → RED; Inc 8's track after a lower of its own width → `├` at 4 RED. | US-103-05 | changed at Inc 8b E1 (was: `<short lower> <track> <short upper>`, track = Limits − 12; the "track under 6 cells" case is gone: the Limits width is fixed at 34) | R `definition_sheet.py:727-754`; E `L.cell.*` |
| R-PE-DEF.104 | U | The system shall place every limits cell's track, range mark, no-limits mark and slots at the fixed offsets of CTX-PE-DEF in the Limits column. | 15/15 rows (`L.cell.*.offsets`, `L.bench.*.offsets`): `├` at 8 and `┤` at 25 on DISPLAY_0001, MASK_FIELD_0001, MASK_BIT_0001, ENUM_0001, `neg_big`, `huge`; `…` at 16 on limits 5 5 and 9 1, lower −inf, upper nan, CURVE_DEF_0001, MAP_DEF_0001, VAL_BLK_DEF_0001; `-` at 16 on V171 ASCII (text) and a refused row; the unit letters of `  65.5k`, ` -1.00k`, `  -655k` in the slot's last cell (offset 6 or 33); both marks on cell 16 (DISPLAY_0001 current 150, value 149.9) → `◆` at 23, `●` at 24, `┤` at 25 (`L.cell.DISPLAY_0001.cur150.new149.9`). | Left-aligned slots → `├` at 2 for a lower `0` RED; a range form without slots (`0 … 65.5k`) → `…` at 2 RED; the unit letter inside the 6 number cells → `k` at 5 RED; the second mark moved right at cell 16 → `◆` on offset 25 and no `┤` RED. | US-103-05 | new (operator, P-130: "estandarizar los valores, unidades y líneas para que se mantengan alineadas en toda la columna"); E3R1 (E3-8b-07: the collision at cell 16) | C `D.off.sheet.118x54.png.txt` (`0 ├` vs `-40 ├`, `0 … 65.5k`); E `L.*` |
| R-PE-DEF.105 | If | If a limit's short number is wider than 6 cells, then the system shall write the limit in its exponent form of CTX-PE-DEF in its slot. | 3/3 + boundary: 4.29e12 → `  4e12 `; 999.6e9 → `  1e12 `; −1.7e308 → `-2e308 ` (`L.slot.*`); boundary 999.4e9 → `   999G` (the short number fits). | Clip the short number (`4.29e…`) → RED; no exponent form → `4.29e+03G` fills 9 cells and `├` moves to 10 RED. | US-103-05 | new (hostile A2L numbers: huge limits) | E `L.short.*`, `L.slot.*` |
| R-PE-DEF.106 | If | If a row's lower or upper limit is not finite, then the system shall show its limits cell in the range form of CTX-PE-DEF. | 2/2: DISPLAY_0001 copies with LOWER_LIMIT −inf → `L.cell.lower_-inf`; with UPPER_LIMIT nan → `L.cell.upper_nan`; no exception. | Place the marks over the infinite span → `round(nan)` raises `ValueError` RED. | US-103-05 | new (hostile A2L numbers) | R `definition_sheet.py:717-735` (no finiteness check before `round`); P (whether the A2L reader yields ±inf or nan for `1e999` / `NaN`: pilot at E4; if it never does, the case builds the Definition directly) |
| R-PE-DEF.114 | If | If a row's current or new value, or the position of a value in range on its track, is not a finite number, then the system shall show its limits cell in the no-position form of CTX-PE-DEF. | 2/2 (E4: the span-overflow case moved to R-PE-DEF.117/1, where it has a position): a DISPLAY_0001 copy with a FLOAT32_IEEE record layout whose image bytes are `FF FF FF FF` (current NaN, `L.float32.FFFFFFFF`) → `L.cell.float32_erased` (`?` at offset 16, no `●`), no exception; DISPLAY_0001 current 143.5 with a new value of +inf → `L.cell.DISPLAY_0001.new_inf` (no `▶`). | No guard → `round(nan)` raises `ValueError` in the first case RED; the beyond-end rule kept for +inf → `▶` at 25 in the third RED. | US-103-05 | new at Inc 8b E3R1 (E3-8b-04: a reachable crash in the paint path; the ruling fixes one no-position form) | R `definition_sheet.py:717-724` (`_track_index`, no finiteness check before `round`); `a2l_definition.py:3211-3218` (FLOAT32 decode keeps NaN: read, not run); E `L.cell.float32_erased`, `L.cell.span_overflow`, `L.cell.DISPLAY_0001.new_inf` |
| R-PE-DEF.76 | If | If a row's upper limit is not greater than its lower limit, then the system shall show its limits cell in the range form of CTX-PE-DEF. | 2/2: DISPLAY_0001 copies with limits `5 5` → `L.cell.limits_5_5`; `9 1` → `L.cell.limits_9_1`; no exception. | The plain division → `ZeroDivisionError` RED; Inc 8's `5 … 5` → `…` at 2 RED. | US-103-05 | changed at Inc 8b E1 (was: `<short lower> … <short upper>`) | R `definition_sheet.py:735-736`; E `L.cell.limits_*` |
| R-PE-BENCH.17 | U | The system shall show a bench row's Limits cell in the range form of CTX-PE-DEF, or in its no-limits form without both limits. | 3/3: CURVE_DEF_0001 → `L.bench.CURVE_DEF_0001`; MAP_DEF_0001 → `L.bench.MAP_DEF_0001`; an array with no limits → `-` at offset 16. | Inc 9's `0 … 65.5k` → `…` at 2 RED; the scalar track → `├` RED. | US-103-05 | changed at Inc 8b E1 (was: `<short lower> … <short upper>`, or `-`) | R `definition_bench.py:632-637` |

### M4 · The expanded object and B's card (V-8, V-9, V-11)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-PE-DEF.107 | U | The system shall paint every line of the expanded object of CTX-PE-DEF after the `┊` bar, on the expanded ground, cut at max(G, V) − 4 cells. | 4/4 at V = 111: DISPLAY_0001 selected → one line `  ┊ └ LINEAR phys = 0.5*raw · …`, its ground #1b233a over cells 0 … 142; MASK_FIELD_0001 → every card line after the bar; MAP_DEF_0001 (a bench row) → every bench line after `  ┊ `; a definition line of 300 cells (a 250-character record layout name) → cut at 139 cells with `…`. | No bar on the bench's lines → RED; the ground on the text only → cell 142 without ground RED; no cut → 304 cells RED. | US-103-05 | new (V-11: "the expanded object stands apart from the table") | C `D.off.sheet.*` (`┊` band), `B.off.sheet.118x54.png` (card) |
| R-PE-BENCH.5 | U | The system shall paint no bench line wider than the view width of CTX-PE-DEF once its trailing ground is removed, no op line wider than the staging sheet, and no more bench lines than the rows the sheet leaves for the detail. | 5/5: at 80, 118 and 220 columns (V = 70, 110, 194, E4-measured), MAP_DEF_0001 and LARGE: every bench line, `rstrip`ped of its ground spaces, ≤ V cells (the bar + V − 4); the op line ≤ the sheet's content width; room 1 → the definition line only; room 0 → no bench line; no exception in any. | Lay the bench out for max(G, V) − 4 → LARGE at 80 is 139 cells RED; chart height `max(4, …)` → the room 1 case RED. | US-103-05 | changed at Inc 8b E1 (was: every painted line ≤ the sheet's content width; the expanded ground now pads each line to max(G, V)) | R `../inc-9/01-requirements.md` R-PE-BENCH.5; E `G.detail_cap.*` |
| R-PE-DEF.108 | While | While an enum, bit-mask or text row is selected, the system shall show its card of CTX-PE-DEF after its definition line. | 3/3: ENUM_0001 → `E.card.ENUM_0001.line0` … `line3`; MASK_FIELD_0001 → `B.card.MASK_FIELD_0001.line0` … `line5` (73 cells); V171 ASCII → top line `T.card.V171.line0` (78 cells). | No frame → RED; a card on a number row (DISPLAY_0001) → more than one expanded line RED. | US-103-05 | new (V-8, V-9, V-11; B's card) | C `B.off.sheet.118x54.png`, `B.off.text.118x54.png` |
| R-PE-DEF.33 | While | While an enum row is selected, the system shall show its enum options of CTX-PE-DEF in its card. | 3/3: ENUM_0001 → card row 1 `( ) 0 OFF   (●) 1 IDLE   ( ) 2 RUN   ( ) 3 FAULT   default "UNKNOWN_STATE"`, row 2 `↔ choose · enter stage`; after choosing RUN → `(●) 2 RUN`; at 118×54 (the grid wider than the view), ENUM_0001 selected and the body focused, → once → `(●) 2 RUN` and the grid's scroll x stays 0. | Mark the current entry after a choice → RED; the prototype's `ScrollableContainer` as the grid scroller (its `right` binding wins) → x > 0 and `(●) 1 IDLE` kept RED. | US-103-05 | changed at Inc 8b E1 (was: after the definition line); E3R1 (E3-8b-03: ← and → reach the sheet under the scroller) | B `DEFC.ENUM_0001.enum_entries`; E `E.card.*` |
| R-PE-DEF.34 | While | While a bit-mask row is selected, the system shall show its bit table of CTX-PE-DEF in its card. | 3/3: MASK_FIELD_0001 at start → `B.MASK_FIELD_0001.start.line0` … `line3`; pending 255 → `B.MASK_FIELD_0001.pending255.line3` (`after … │ 1F F7`); MASK_BIT_0001 pending 0 → `B.MASK_BIT_0001.pending0.line2` (one `■`, bit 0) and `line3` (`… 1A E6`). | The after row from the unmasked word only → `1A E7` RED; no nibble guides → the line 57 cells RED. | US-103-05 | changed at Inc 8b E1 (was: the bit strip, `bit 15…0 <bits>   word <before> → <after>` + the mask line) | B `DEFC.MASK_*.bit_mask`, `word.image = 1a e7`; C `B.off.sheet.118x54.png`; E `B.*` |
| R-PE-DEF.35 | While | While a text row is selected, the system shall show its hex grid of CTX-PE-DEF in its card. | 2/2: V171 ASCII at start → `T.V171.start.line0` … `line3`; pending `ABC` → `T.V171.pendingABC.line1` (`+00 │ 41 42 43 00 … │ ABC·…`), offsets 0 … 9 in the pending style. | 8 bytes per row → RED; no ASCII column → RED. | US-103-05 | changed at Inc 8b E1 (was: the text rows, `+<offset> <bytes>`) | C `B.off.text.118x54.png`; E `T.*` |
| R-PE-DEF.109 | If | If a bit-mask word is wider than 16 bits, then the system shall show one bit-table block per 16 bits, high bits first. | 1/1: a ULONG copy of MASK_FIELD_0001 with mask 0x00FF0000, word `12 34 56 78`, pending 0x12 → `B.ULONG_FF0000.pending0x12.line0` … `line7` (75 cells; hex only on the first block). | One row of 32 bits → 123 cells RED. | US-103-05 | new (hostile A2L: 32- and 64-bit masks) | P (a ULONG BIT_MASK copy of the DEFC case at E4); E `B.ULONG_*` |
| R-PE-DEF.110 | If | If the shown bytes of a text row end inside a hex-grid row, then the system shall keep that row's ASCII guide at the column of a full row. | 1/1: V171 ASCII (42 B) → the `│` before the ASCII column at 56 on every line (`T.V171.start.ascii_guide_cols`). | Put the guide after the last byte (B's prototype) → 35 on row `+20` RED. | US-103-05 | new (alignment; B's prototype misaligned it, `B.off.text.118x54.png`, DF-04 a) | C `B.off.text.118x54.png` (row `+20`); E `T.*.ascii_guide_cols` |
| R-PE-DEF.111 | If | If a byte of the hex grid is outside U+0020 … U+007E, then the system shall show `·` for it in the ASCII column. | 1/1: bytes `00 1B 7F 80 FF 41 20 7E` → `·····A ~` (`T.hostile.ascii`). | `chr(b)` for every byte → ESC painted RED. | US-103-05 | new (hostile span bytes) | E `T.hostile.ascii` |
| R-PE-DEF.112 | If | If a card line is wider than the card's cap of CTX-PE-DEF, then the system shall cut it at the cap with one `…`. | 2/2: an enum of 300 entries → `E.card.300_entries.line1` (139 cells, `… │` at its end); a 300-character name → the card's top line 139 cells, the title cut with `…`. | Wrap the line → more lines RED; no cap → a line of 7,000 cells RED. | US-103-05 | new (hostile enum texts and names) | E `E.card.300_entries.*` |
| R-PE-DEF.115 | If | If a card's title or a card row holds a control character or a markup tag, then the system shall show that text in the card as CTX-PE-DEF plain text. | 3/3: an enum named `A\x1b[2J` → `E.card.name_esc.line0` (`A�[2J`); an enum entry text `A\x1b[2J` → `E.card.row_esc.line1`; an enum entry text `[@click=app.quit]OFF[/]` → `E.card.markup.line1`, shown literally with no action link; no exception in any. | The title built from the raw name → ESC in the painted line RED; the card row rendered with markup on → `OFF` without its tags RED. | US-103-05 | new at Inc 8b E3R1 (E3-8b-06: the card is a new place where A2L text is painted) | R `definition_sheet.py:53-55` (`plain`); E `E.card.name_esc.*`, `E.card.row_esc.*`, `E.card.markup.*` |
| R-PE-DEF.116 | If | If a card's title or a card row holds a wide character, then the system shall paint every line of that card at the card's width in terminal cells, each wide character counting 2 cells. | 3/3: an enum named `温度`×200 → `E.card.name_wide200.line0` (139 cells in 73 characters, the title ending `…`); an enum entry text `温度` → `E.card.enum_wide.line0` … `line3`, 79 cells each (the row's `│` under `╮`); an enum entry text `温度`×100 → `E.card.enum_wide100.line1` (139 cells, ending `… │`). | Card widths by `len()` → the `温度` row 2 cells wider than its frame RED; the 200-name top line wider than the cap RED. | US-103-05 | new at Inc 8b E3R1 (E3-8b-06: widths in terminal cells) | E `E.card.name_wide200.*`, `E.card.enum_wide.*`, `E.card.enum_wide100.*` |
| R-PE-DEF.117 | If | If a row's limit is beyond the float range, or the span between its finite limits is, then the system shall show its limits cell of CTX-PE-DEF with each value in range at its proportion of the span. | 3/3: a DISPLAY_0001 copy with limits −1.7e308 … 1.7e308 and current 1e308 → `L.cell.span_overflow` (`●` at 21, pos 0.79); the same with current −1.7e308 → `L.cell.span_overflow.lower_end` (`●` at 9); ENUM_0001 with its last entry's raw 2**1100 → `L.cell.enum_beyond_float` (the range form, `inf` in the upper slot) and its row line paints; (E5) limits 0 … 5e-324 (a subnormal span whose halves are both 0) with current 0 → `●` at 9, with current 5e-324 → `●` at 24, no exception. | pos = (v − lower)/(upper − lower) on the full values → the span is inf, pos 0, `●` at 9 for 1e308 RED (or `?` under R-PE-DEF.114's guard); `isfinite` on the raw 2**1100 → `OverflowError` RED; pos on halves for every span → `ZeroDivisionError` on 0 … 5e-324 RED. | US-103-05 | new at Inc 8b E4 (orchestrator ruling on C8b-S's unguarded edge and T8b-S1's E3R1 "observed, not ruled" cell-1 mark; DF-04 a); case /4 added at E5 (X8b finding E5-8b-1) | R `definition_sheet.py` `_bounds`, `_track_index`, `_has_position` at 0bbc6f79; E `L.cell.span_overflow*`, `L.cell.enum_beyond_float` |

### M5 · Filter icon and help (V-2)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-PE-DEF.113 | U | The system shall paint the Include parameter control of the filter row as `▽ Pick`. | 2/2: the label is `▽ Pick` at 118×54; at 80×24 the filter row's seven controls — the filter input, the status, the page previous button, the page label, the page next button, the Include control and the bulk control (`#patch_param_filter`, `_status`, `_page_prev_button`, `_page_label`, `_page_next_button`, `_include_button`, `_bulk_button`; named at E4 from AT-B103-I8B-8) — keep a non-zero region inside the panel (R-PICKER-CORRECT.020). | The label `Pick` → RED. | US-103-05 | new (V-2) | R `a2l_parameter_picker.py:740-745`; C `D.off.sheet.118x54.png` |
| R-PE-DEF.85 | U | The system shall state in the Patch Editor's help section that in the staging sheet ↑ and ↓ select a row, Enter moves to the formula input, ← and → choose an enum entry, Home and End scroll the grid to its first and last columns, and Escape returns from the formula input to the sheet. | 1/1: one `STAGING SHEET — …` line whose effect holds `↑↓`, `enter`, `←→`, `home`, `end` and `esc`. | Drop the scroll clause → RED. | US-103-05 | changed at Inc 8b E1 (+ Home and End, R-PE-DEF.94) | R `window_help.py:71-73` |

### M6 · The summary strip (F-R14-1, DF-04 a: a defect, fixed to the design)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-PE-BENCH.11 | U | The system shall show a summarised bench row's Current cell as its summary strip and its element count. | 3/3 at the Current width 20: CURVE_DEF_0001 → `▄▆▃▇▁ 5`; MAP_DEF_0001 → `▆▃▅▃ 12`; VAL_BLK_DEF_0001 → `▄▃▄ 6` (`S.after.current.*`). | Count only → RED; Inc 9's eight levels → `▅▇▄█▁` RED. | US-103-05 | changed at Inc 8b E1 (F-R14-1: levels 1 … 7, column-mean levels for a grid; was EX-G1 `▅▇▄█▁ 5`, EX-G2 ramp-shaded `█`) | R `definition_bench.py:491-527`; E `S.*` |
| R-PE-BENCH.107 | U | The system shall draw each cell of a summary strip with a block no taller than seven eighths of the cell. | 2/2: the DEFC CURVE, MAP and VAL_BLK strips hold only `▁ … ▇` and spaces (no `█`); a ramp of 40 points in 17 cells → `S.wide.40_points_in_17`. E5 real capture at 118×54: `f_r14_1_probe.py` prints `joined cells … = []` for both row pairs. | Eight levels → `█` in CURVE RED. | US-103-05 | new (F-R14-1); E3R1 renumbered from .94 (E3-8b-01: .94 … .106 are Inc 9b's) | C `evidence-e1/f_r14_1_probe-transcript.txt` (`joined cells CURVE_DEF_0001 -> MAP_DEF_0001 = [1, 3]` on base) |
| R-PE-BENCH.108 | U | The system shall paint each summary strip in the dim style of CTX-PE-DEF with no ground of its own. | 2/2: the three strips' spans have colour #969aad and no background; on the selected row and on a zebra row the strip's cells show the row's ground. | Inc 9's `ramp_style` on the grid strip (`#ffffff on #…`) → RED. | US-103-05 | new (F-R14-1); E3R1 renumbered from .95 (E3-8b-01) | C `f_r14_1_probe-transcript.txt` (MAP cells #101828 or #ffffff, the ramp's text colours, never its ground) |

### M7 · The bench window under the V − 4 detail (E3-8b-02)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-PE-BENCH.36 | When | When the cursor moves outside the window, the system shall move the window the least that shows the cursor. | 5/5: Inc 9's three cases (LARGE at 118×54: cursor down past the last shown grid row → the window's first row +1; pagedown from row 0 with a 20-row window → cursor row 20, window rows 1..20; MAP_DEF_0001 (fits) → window unchanged); LARGE at 80×24 and at 118×54, the cursor moved right past the last painted canvas column → the window's first column +1 and the cursor's cell is painted (the window is shaped for the detail the sheet paints: `W.detail_geometry.*`). | Re-centre the window → RED; the window shaped from the body's own width and its height − 1 (the base, `W.bench_geometry.base.*`) → at 80×24 the cursor's column is not painted RED. | US-103-05 | changed at Inc 8b E3R1 (E3-8b-02: the cases at 80 and 118 columns; text unchanged) | R `bench_sheet.py:305-312` (`_bench_geometry`: the body's width, visible = height − 1), `:316`, `:378`; `../inc-9/01-requirements.md` R-PE-BENCH.36; E `W.detail_geometry.*`, `W.bench_geometry.base.*` |

**Count:** 43 active rows in this file — 29 new (R-PE-DEF.89 … .117; .114 … .116 added at E3R1, .117 at E4), 8 changed Inc 8 rows (R-PE-DEF.5, .21, .33, .34, .35, .76, .81, .85), 2 new Inc 9-family rows (R-PE-BENCH.107, .108; renumbered at E3R1 from .94, .95), 4 changed Inc 9 rows (R-PE-BENCH.5, .11, .17, .36; .36 added at E3R1); 2 retired Inc 8 rows (R-PE-DEF.6, .7). Every active row has a numeric threshold and a negative control. Under the cap of about 80.

**Rows checked and left unchanged** (`E1-rulings.md` §2): R-PE-DEF.31 (the definition line's words do not change; its bar and ground are R-PE-DEF.107), .15 and .20 (plain text; the clip is now R-PE-DEF.96), .22 … .28 (texts unchanged; their styles are .97 … .100), .30 (one expanded object), .36 … .41 (the formula bar's texts), .70, .71 (plain text covers the card and the title), .79 (`… <n> more B`, now the hex grid's last card row), R-PE-BENCH.13 (`… <count>`), .18 (the bench mark's glyph; its style is .98 / .99).
