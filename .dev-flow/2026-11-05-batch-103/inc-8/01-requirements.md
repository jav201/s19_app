# Inc 8 — Patch Editor: edit by definition (scalars, enums, bit masks, text) — requirements (E1)

Batch `2026-11-05-batch-103`, increment 8. Stage E1, 2026-11-13, model Opus (E1 + E2 by one agent, DF-03). Base `91d5ae56` (batch-modular `2dbd7d5a` + the `patch_editor` split); every line number is "as of `91d5ae56`". Authority: `../PLAN.md` (commission US-103-05, Inc 8 and Inc 9 rows, I-1, I-2, I-4, I-5, A1, A2); `../design/G2-verdict-2026-11-12.md` q1 `q1_pe=approve` (the mix: pe_B's staging sheet as the base, pe_C's benches for arrays — Inc 9); `../inc-2/E3-rulings.md` (E3S-04a, E3A-07 + E3S-08, E3S-11); `../inc-2/codewire/graph-inc2.md` §Interfaces (I-2 and its consumer notes). Open decisions: `E1-rulings.md` §3 (each row below follows the recommended option; the rows another option would change are named there). Slice: `E1-slice.md`. Cases: `02-test-cases.md`. Evidence: `evidence-e1/`.

**E3R2 (2026-11-13, model Opus):** the re-review's rulings (`E3-rulings.md` §E3R2 corrections) are applied the same way, marked `E3R2 (<finding>)`; new row R-PE-DEF.88; examples in `evidence-e1/examples_e3r2-transcript.txt`.

**E3R1 (2026-11-13, model Opus):** the E3 rulings (`E3-rulings.md`) are applied in place. A row or CTX term changed by E3R1 says `E3R1 (<finding>)` in its Status or after its text; the new rows are R-PE-DEF.74 … .87 and the changed canon row R-PE-110. Their computed examples are in `evidence-e1/examples_e3r1-transcript.txt` (keys `W.*`, `C.*`, `L.*`, `T.*`, `F.*`, `M.*`, `X.*`) and the E3 probe `E3-security.md` §Evidence (keys `P1` … `P4`).

Base column codes: **R** read in the code at `91d5ae56`; **B** pilot run on `<runner>` (`evidence-e1/pilot_inc8-transcript.txt`, key named); **P** proposal that needs a pilot at E4 (an input or terminal behaviour not yet shown to reach the app).

## User stories

- **US-103-05** — "The Patch Editor edits a parameter by its A2L definition: scalars, enums, bit masks, text, curves, maps and value blocks." Inc 8 delivers scalars (numbers), enums (TAB_VERB / COMPU_VTAB), bit masks and ASCII text, in the approved pe mix's staging sheet; curves, maps and value blocks are Inc 9 (bench views inside this sheet).
- **US-103-04** — "The Patch Editor uses the same parameter selector as the Check Editor …". Inc 8 keeps that selector as the sheet's source (its filter, paging, include and Add list) and keeps `Use parameter` reachable (rows R-PE-DEF.60 … .62, R-PICKER-CORRECT.011, .020).

## Scope

- **In:** the Patch Editor layout of the approved mix (filter row, STAGING SHEET, LANDS IN pane, file row, document row, legend); one sheet row per picker-page parameter with its current value decoded through I-2; the selected row's detail; the formula bar that previews and stages one edit; staging into the change document over the staging overlay (masked words re-encoded); markup-off and control-character rendering of every I-2 string the sheet paints; shortening a long message where it is painted; hostile formula input; the row window that keeps the selected row in view; the per-kind operations that Inc 9 extends (E3A-02); the Patch Editor help section (E3A-06); the busy gate of a stage (E3S-03).
- **Out:** curves, maps, value blocks and their benches (Inc 9); the apply cue and the export dock (Inc 10, `patch_editor/actions.py`); view levels (backlog item 1); the picker's own list/paste/autocomplete features (Inc 7); any I-2 change (`a2l_definition.py` is read only); a per-field unstage key (`E1-rulings.md` D-4).

## Definitions (CTX-PE-DEF — terms and formats only)

```text
filter row       One terminal row above the sheet: the shared picker's filter input, its status
                 `<n> of <m> shown`, Prev, `Page <p>/<q>`, Next, Include parameter, Add list. The
                 picker's own table and full-name line are not shown (they still exist). Prev,
                 Next and Include parameter name the controls; the compact filter row paints
                 them `<`, `>` and `Pick` (Inc 6, 6d178973; wording note E5-capture-facts F-1).
staging sheet    The window with border title `STAGING SHEET` and border subtitle
                 `enter edit · ↑↓ row` (E3R2, E3A-15: Inc 9's integrator appends
                 ` · arrays open the bench` when the bench lands; provisional, V-13).
                 Top to bottom: the header line, the sheet rows of the row window (page order),
                 the detail under the selected row, the formula bar on its last line.
row window       The sheet rows painted. visible = the sheet body's height − 1 (the header line);
                 room = visible − 1: the selected row's detail lines are cut to `room` lines, so the
                 selected row is always painted (E3R2, E3A-14); need = 1 + its detail lines after
                 the cut. The first painted row `top` starts at row 0; when the selected row or the
                 page changes, `top` becomes the selected row if that row is above `top`, becomes
                 selected + need − visible if the selected row's last detail line would fall below
                 the body, and else stays. Rows top … top + visible − need are painted (E3R1, E3A-01).
bench            Inc 9's view of an array, curve or map row inside the sheet. Inc 8 has no bench;
                 its rows name the bench only where Inc 9 relies on an Inc 8 rule (E3R1, Inc 9 C-5).
landing pane     The window with border title `LANDS IN`: tab chips Patch script, Inspector, JSON,
                 Checks over one pane.
  Patch script   The ledger (CTX-PE-LEDGER) with no border of its own.
  Inspector      Today's Inspector pane (strip, entry form, Add/Edit/Remove/Edit JSON, tally) plus
                 the `Use parameter` row and its status line, moved from the retired A2L tab.
header line      `Parameter`, `Kind`, `Current`, `New`, `Unit`, `Limits`, `Δ`, each at the start of
                 its column; the 2-cell mark column has no label.
column widths    W = the sheet's content width (cells).
                 W ≥ 160: Parameter 24, Kind 10, Current 44, New 20, Unit 8, Δ 22.
                 100 ≤ W < 160: Parameter 18, Kind 9, Current 18, New 13, Unit 7, Δ 16.
                 W < 100: Parameter 16, Kind 0, Current 14, New 12, Unit 0, Δ 10.
                 Limits = W − 2 − the other columns − 1, capped at 64; a column of width 0 is not
                 shown. Widths and lengths are counted in terminal cells (a wide character such as
                 `温` is 2 cells): a cell wider than its column shows the longest start that fits in
                 the column's width − 1 cells, then one `…` (E3R1, E3A-12).
row kind         number (a definition of kind "number" with no bit mask), bit mask (kind "number"
                 with a bit mask), enum, text; `none` for a refused definition. Any other kind
                 ("array", "curve", "map", "") is its I-2 kind word.
kind operations  What a row's kind decides: its formula label, whether it has an editor, its
                 current and staged value, its staged state, its preview, its detail lines, its
                 stage request, and optionally its cells and its formula bar. Inc 8 defines them for
                 number, bit mask, enum and text; Inc 9 adds array, curve and map. Every other row
                 kind takes the fallback operations (E3R1, E3A-02).
editor           A row has an editor when its kind operations give one: number, bit mask and enum
                 rows always; a text row while its span is at most 4,096 bytes (E3R1, E3S-04);
                 rows with the fallback operations never.
kind word        The object's type word: the definition's char type (VALUE, ASCII, …);
                 `MEASUREMENT` for a measurement; `?` when the definition gives neither.
image            The source view of the loaded S19/HEX image: its memory map with, at every
                 address an Apply journaled, the byte held before that Apply — the map the
                 before/after strip reads (batch-99 HLR-157). The sheet and the stage read this
                 one map (E3R1, E3S-01).
page A2L         The A2L parse payload the picker last described its definitions from, kept with
                 them; every decode and preview the sheet makes uses it, never the app's loaded A2L
                 read at paint time (E3R2, E3A-13). None while no A2L is loaded.
staged overlay   The image with the bytes of every document entry written over it, in document
                 order (the I-2 consumer note's overlay).
current value    I-2 decode of the definition over the image.
staged value     I-2 decode of the definition over the staged overlay.
staged row       A number, bit-mask, enum or text row whose staged value text differs from its
                 current value text; a row with the fallback operations, or a text row whose span
                 is longer than 4,096 bytes, where a byte of a document entry inside the span
                 differs from the image's byte at that address (E3R1, E3A-02; E3R2, E3S-10: one
                 pass over those entry bytes, bounded by the document, never a walk of the span).
formula text     The text in the formula input; it belongs to the selected row and stays with that
                 row when the selection moves. base text: a text row's current text; empty for any
                 other row. A row is pending while its formula text differs from its base text
                 (E3R1, E3A-11).
row fill         The text the formula input takes when a row becomes selected: the row's formula
                 text while it is pending, else its base text (E3R1, E3A-11).
preview          I-2 encode of the pending formula text over the staged overlay (an `Encoded` or a
                 `Refusal`) and, for an `Encoded`, I-2 decode over the overlay with its bytes.
stage            A write of one row's edit into the change document: a formula-bar stage (Enter
                 in the formula input) or, once Inc 9 lands, a bench's record stage (E3R1, Inc 9 E-2).
value text       number: the decoded `text`. enum: `<stored> <entry text>` when an entry matched,
                 else the decoded `text`. bit mask: `<field> (0x<field>)`, the field in upper-case
                 hex with at least 2 digits. text: `"<text>"`. Span not held by the image: `--`.
                 Refused definition: `refused`. Fallback operations: `<n> values`, n the
                 definition's element count, or `--` when it gives none (E3R1, E3A-02). A text
                 row whose span is longer than 4,096 bytes: `<n> B`, n the span's length, with no
                 decode (E3R2, E3S-10).
Δ text           number, staged: `<signed Δ> staged`; number, pending: `<signed Δ> (<signed p>%)`,
                 p = 100·Δ/(upper − lower) with one decimal while upper > lower, or `<signed Δ>`
                 without both limits;
                 Δ = new physical − current physical, written with the definition's display rule.
                 enum: `<old stored> → <new stored>`. bit mask: `<signed field Δ>`. text:
                 `<n> chars`, n = the span positions whose byte changes.
short number     |x| < 1000: x rounded to one decimal, a trailing `.0` dropped; else 3 significant
                 digits and `k`, `M` or `G` (655350 → `655k`, 4294967295 → `4.29G`).
limits cell      `<short lower> <track> <short upper>`; track = Limits width − 12 cells,
                 `├`, `─`…, `┤`; `●` at the current value, `◆` at the preview or staged value; a
                 value below lower is `◀` on the left end, above upper `▶` on the right end; a value v
                 in range sits on cell 1 + round(pos × (track − 3)), kept within 1 … track − 2,
                 pos = (v − lower)/(upper − lower) (defined while upper > lower), and a second mark on a taken cell moves one cell
                 right (E2 correction: the cell rule was implicit). A track
                 under 6 cells gives `<short lower> … <short upper>`. No lower or upper limit: `-`.
                 enum: the stored values; bit mask: the field values.
mark             Cell 1: `▶` on the selected row, else space. Cell 2: `●` staged, else `◆` pending,
                 else space.
definition line  `└ <conversion> <formula> · <datatype> <format> <order>[ · <record layout>] · 0x<address> · <n> B`;
                 ` · <record layout>` only when the definition names one (I-2 names none for a
                 scalar, so Inc 8's scalar lines have none; E3R1, Inc 9 C-6).
                 conversion: the method's type word, or NO_COMPU_METHOD. formula: IDENTICAL or
                 NO_COMPU_METHOD `phys = raw`; LINEAR `phys = <a>*raw + <b>` (`<a>*` left out when
                 a = 1, ` + <b>` when b = 0); TAB_VERB `<n> pairs`; any other type: none. Under a bit
                 mask `raw` is written `(word & <mask>) >> <shift>`. format: Inc 6's element format
                 label (`u16`, `s16`, `f32`, `text`). order: `big-endian` or `little-endian`.
                 address: 8 upper-case hex digits. n: the span's byte length. A text row's
                 definition line is `└ text · 0x<address> · <n> B`.
enum options     `( ) <stored> <text>` per table entry in table order, `(●)` on the chosen one,
                 3 spaces between entries, then `default "<default text>"` when the table has one;
                 a second line `↔ choose · enter stage`.
bit strip        `bit <w−1>…0 <one cell per bit, high bit first>   word <before> → <after>`, the
                 bits under the mask marked, before/after as `XX XX` in span order; a second line
                 `mask <mask word> · field = (word & mask) >> <shift> · other bits kept`.
text rows        Rows of up to 16 span bytes: `+<offset, 2 upper hex> <bytes after the preview>`,
                 a byte that differs from the image in the pending style; at most 4 rows (the
                 span's first 64 bytes) (E3R1, E3S-04).
formula bar      `<name> <label> <input> <tail>`. label: number and enum `new =`, bit mask
                 `field =`, text `text =`. input: 18 cells wide, at most 4,096 characters.
formula tail     number, enum, bit mask with an `Encoded` preview: `<unit>  (<lower> … <upper>)  raw
                 <current stored>→<preview stored> · <before bytes> → <after bytes>  <verdict>`;
                 `(<lower> … <upper>)` only while the bar is at least 110 cells wide; bytes: the
                 first 8 of the span as `XX XX …`, then `…` when longer; verdict `✓ in limits`, or
                 `▲ <notice>` when the encode gave a notice. With a `Refusal`: `✗ <message>`. Text:
                 `<n>/<span> chars · NUL-padded`. Then the key hint `enter stage ↓`. The whole tail is
                 cut at the bar's right edge with one `…`.
plain text       Painted with markup off; every U+0000 … U+001F, U+007F, U+0080 … U+009F replaced
                 by U+FFFD (I-2 consumer notes E3S-04a, E3A-25/E3S-19).
name echo        A name or file word in a status message: at most its first 256 characters, each
                 control character as U+FFFD, then `…` when longer (the R-A2L-DEF.151/7 rule).
```

## Requirements

Threshold = the number of independently asserted cases that must pass (`n/n`). Negative control = a mutant of the product that must turn the case's test RED. Examples (`EX-…`) are in `codewire/graph-inc8.md` and come from `evidence-e1/pilot_inc8-transcript.txt` (DEFC = `tools/synth/make_release_case.py --case definitions`, seed 20260001; V171 = `examples/case_00_public/ASAP2_Demo_V171.a2l` with the hand image of the pilot).

### M1 · Layout (CTX-PE, CTX-PE-DEF)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-TUI-063.1 | U | The system shall show the Patch Editor as the identity ribbon, the filter row, the staging sheet, the landing pane, the file row, the document row and the legend, top to bottom. | 2/2: at 118×54 and 220×60 the seven regions' `region.y` are strictly increasing in that order. | Compose the landing pane before the sheet → order RED. | US-103-05 | changed (was: ribbon, ledger beside inspector, file row, document row, legend) | R `layout.py:36-86` |
| R-TUI-063.2 | U | The system shall keep the ledger beside the inspector at every terminal width. — Withdrawn | — | — | US-103-05 | retired: the mix stacks the sheet over the landing pane (G2 q1); replaced by R-PE-DEF.1 | R `layout.py:41` |
| R-PE-DEF.1 | U | The system shall give the landing pane 9 rows and the staging sheet every row that the other regions leave. — Withdrawn | — | — | US-103-05 | retired at E3R1: split into R-PE-DEF.1.1 and .1.2 (Inc 9 C-5, E3A-05 c) | absent (R) |
| R-PE-DEF.1.1 | While | While no bench is shown, the system shall give the landing pane 9 rows and the staging sheet every row that the other shown regions leave. | 3/3: at 118×54 and 220×60, landing pane height = 9 and sheet height = panel height − the other shown regions' heights; at 118×54 with a 4-row stand-in for Inc 10's export dock yielded inside the document controls (I-8.3), the same equation over the seven other regions. | Give the sheet a fixed height → the 220×60 case RED. | US-103-05 | new; E3R1 (E3A-05 c: "other shown regions", dock case) | absent (R) |
| R-PE-DEF.1.2 | While | While a bench is shown, the system shall give the landing pane 6 rows. | 1/1: at 118×54 with the panel in its bench state (the `-bench` class Inc 9's sheet sets), landing pane height = 6 and the sheet takes the 3 rows. | No `-bench` rule → height 9 RED. | US-103-05 | new, E3R1 (Inc 9 C-5; provisional, V-13) | P (the bench is Inc 9's; Inc 8 pins the rule) |
| R-PE-DEF.74 | U | The system shall give the staging sheet window at least 12 rows. | 2/2: at 80×24 the sheet window's height ≥ 12 (the panel scrolls, R-TUI-064.3); at 118×54 with the 4-row stand-in dock, ≥ 12. | No minimum height → the 80×24 case RED. | US-103-05 | new, E3R1 (E3A-05 b, E3A-09) | P (layout measured at E4); code `styles.tcss` (E4 trace) |
| R-TUI-063.3 | U | The system shall give the landing pane the tab chips Patch script, Inspector, JSON and Checks. | 1/1: the chips' labels in order equal the four. | Keep the A2L chip → RED. | US-103-05 | changed (was: Inspector, JSON, Checks, A2L) | R `panel.py:110-115` |
| R-TUI-063.4 | When | When the Patch Editor is first shown, the system shall show the Patch script tab. | 1/1: after mount the shown pane is the ledger's and its chip is selected. | Initial pane `patch_pane_inspector` → RED. | US-103-05 | changed (was: the Inspector tab) | R `layout.py:58-60` |
| R-TUI-063.6 | U | The system shall give the landing pane the border title `LANDS IN`. | 4/4: one per shown tab. | Keep the per-tab titles → RED. | US-103-05 | changed (was: When … INSPECTOR, JSON, CHECKS or A2L after the tab) | R `panel.py:711-719` |
| R-TUI-063.7 | U | The system shall give the ledger the border title `PATCH SCRIPT`. — Withdrawn | — | — | US-103-05 | retired: the ledger has no border inside the landing pane (G2 q1 capture) | R `layout.py:40` |
| R-PE-041 | While | While the Patch script or Inspector tab is shown, the system shall show the ledger subtitle of CTX-PE-LEDGER as the landing pane's border subtitle. | 4/4: 0 entries, `1 entry`, `3 entries`, `3 entries ●` with the dirty flag. | Drop the subtitle with the ledger border → RED. | US-103-05 | changed (was: U, on the ledger's own border) | R `entries.py:146-150`, `panel.py:623-635` |
| R-PE-DEF.2 | U | The system shall show the picker's filter, status, Prev, page label, Next, Include parameter and Add list in the filter row. | 1/1: each of the seven has a non-zero region on the filter row's `y`; `#patch_param_table` has `display` false. | Compose the picker inside a tab → RED. | US-103-04 | new; E5 wording (capture facts F-1: Prev, Next and Include parameter are control names, painted `<`, `>`, `Pick`) | absent (R `a2l_picker.py:221-242`) |
| R-PICKER-CORRECT.011 | When | When the Patch Editor is shown, the system shall present the shared pick-mode selector with include and `Add list` controls and no duplicate Check ids. | 3/3 as before, through the filter row: Patch include control, `#patch_param_bulk_button`, both editors mounted, every `patch_param_*` / `check_param_*` id unique. | Highlight mode or a duplicate id → RED. | US-103-04 | changed (trigger was: When the Patch A2L tab is shown) | R |
| R-PICKER-CORRECT.020 | When | When the Patch Editor uses its pick controls, the system shall keep its filter row, Use parameter row and use-status line contained at supported widths. | 2/2 real layouts at 80×24 and 118×54: every named surface has a non-zero region inside the panel (after scrolling where R-TUI-064.3 allows), no horizontal overflow. | A fixed-width filter row wider than 80 → RED. | US-103-04 | changed (was: the A2L tab's surfaces) | R |
| R-PE-DEF.3 | U | The system shall show the `Use parameter` row and its status line in the Inspector tab, under the entry form. | 1/1: both are descendants of `#patch_pane_inspector`, below `#patch_entry_bytes_input`. | Leave them on a hidden container → RED. | US-103-04 | new | absent (R `a2l_picker.py:224-242`) |
| R-PE-DEF.4 | While | While the staging sheet holds the focus, the system shall paint its border in the accent colour. | 2/2: focus on the sheet → accent `#91abec`; focus in the file row → rule colour. | Remove the `:focus-within` rule → RED. | US-103-05 | new | absent |
| R-PE-DEF.5 | U | The system shall show the staging sheet's header line of CTX-PE-DEF. | 3/3 at W = 96, 118, 200: the labels at the starts the column widths give. | Swap New and Current → RED. | US-103-05 | new | absent |
| R-PE-DEF.6 | U | The system shall size the sheet's columns by the column widths of CTX-PE-DEF. | 3/3: W = 96 (Kind and Unit hidden), 118, 200; each cell's start equals the sum of the widths before it. | A fixed 118-column table → W = 96 RED. | US-103-05 | new | absent; code `definition_sheet.py` (E4 trace) |
| R-PE-DEF.7 | U | The system shall paint no sheet row, detail line or formula bar wider than the staging sheet. | 4/4: at 80, 118 and 220 columns, every painted line's cell length ≤ the sheet's content width; at W = 118 a name `温度`×6 and a unit `温度温度` → Parameter `温度温度温度温度…` (17 cells), Unit `温度温…` (7 cells). | Drop the Limits cap → 220 RED; a `len()`-based clip → the wide-character case RED (24 and 8 cells). | US-103-05 | new; E3R1 (E3A-12: cells case) | B `C.name.w18.cells`, `C.unit.w7.cells` |

### M2 · Rows of the sheet (CTX-PE-DEF)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-PE-DEF.10 | When | When the picker's shown page changes, the system shall show one sheet row per parameter of that page, in page order. | 3/3: a population, a filter `MASK`, a page turn of 201 names; row names equal `visible_params`. | Rows from `filtered_params` → page-turn RED. | US-103-05 | new | absent (R `a2l_picker.py:209-219`) |
| R-PE-DEF.11 | When | When the picker's shown page changes, the system shall build the page's rows from the definitions and the page A2L that the picker last populated from. | 3/3: an A2L reload that changes ENUM_0001's table → the row shows the new entry text; a page turn and a filter change → 0 `describe_definitions` calls (canon R-PICKER-CORRECT.019); the app's loaded A2L replaced by one whose COMPU_METHOD gives DISPLAY_0001 the factor 1.0 while the picker still holds its old population → Current `143.5`, and after the picker repopulates → `287.0`. | A describe at each page change → the spy counts 1 → RED; definitions kept across a signature change → the reload case RED; the app's A2L read at paint time with the old definitions → `287.0` before the repopulation RED. | US-103-05 | new; E3R1 (E3A-04: the picker's population describe is reused, was: describe at each page change); E3R2 (E3A-13: the page A2L travels with the definitions); E5 (P-045: `287` → `287.0`, the decoded text of the Current column, decimals 1) | R `a2l_parameter_picker.py:606-608` (one describe per population); I-4 signature (Inc 5) |
| R-PE-DEF.12 | When | When the picker's shown page changes, the system shall paint the sheet within 0.5 s for a page of 200 parameters. | 2/2 on `<runner>`, Python 3.11, median of 5 ≤ 0.5 s, `uptime` recorded beside it (HT-08): software_a (13,990 tags), the first 200 addressed names over an image that holds every span byte; hostile: a page of 200 copies of the V171 ASCII object widened to 1,048,576 bytes at one address, the image holding that span, the document holding one 42-byte entry inside it. | One `describe_definition` per row (200 × ≈ 0.12 s) → RED; a full decode of each hostile span over the image and the overlay (≈ 400 × the `S.decode_1MiB` time) → RED. | US-103-05 | new; E3R1 (E3A-04: full image; the empty-image figure of EX-C1 was vacuous); E3R2 (E3S-10: the hostile page) | B E3 probe `P1.decode_200.full_image.median_s = 0.0008`, `P1.describe_definition[1].median_s = 0.1167` (load 9.5, ratios only); B `S.*` (`examples_e3r2-transcript.txt`) |
| R-PE-DEF.13 | If | If the shown page has no parameter, then the system shall show the sheet line `No parameters on this page: type a filter above.` | 2/2: a filter that matches nothing; an A2L with no addressed tag. | Paint an empty sheet → RED. | US-103-05 | new | absent |
| R-PE-DEF.14 | If | If no A2L is loaded, then the system shall show the sheet line `Load an A2L file to edit parameters by definition.` | 2/2: no A2L at start; an A2L unloaded. | Paint the no-page line → RED. | US-103-05 | new | absent |
| R-PE-DEF.15 | U | The system shall show each row's name, clipped to the Parameter column, as plain text. | 2/2: `ASAM.C.ASCII.UBYTE.NUMBER_42` at W = 118 → `ASAM.C.ASCII.UBYT…`; a name holding `[b]` → shown literally. | Markup on → the `[b]` case RED. | US-103-05 | new | absent |
| R-PE-DEF.16 | U | The system shall show each row's kind word in the Kind column. | 3/3: DEFC ENUM_0001 `VALUE`, V171 ASCII `ASCII`, a measurement `MEASUREMENT`. | Show the I-2 `kind` (`enum`) → RED. | US-103-05 | new | B `DEFC.ENUM_0001.char_type = 'VALUE'` |
| R-PE-DEF.17 | U | The system shall show each row's current value text in the Current column. | 4/4: DISPLAY_0001 `143.5`; ENUM_0001 `1 IDLE`; MASK_FIELD_0001 `174 (0xAE)`; V171 ASCII `"Hello ASAM"`. | Show the stored value for a number → `287` RED. | US-103-05 | new | B `DEFC.*.decode`, `V171.*.decode` |
| R-PE-DEF.18 | If | If the image does not hold every byte of a row's span, then the system shall show `--` in its Current column. | 2/2: no image; an image missing DISPLAY_0001's second byte. | Zero-fill the missing byte → RED. | US-103-05 | new | absent |
| R-PE-DEF.75 | U | The system shall show `<n> values`, n the definition's element count, in the Current column of each row with the fallback operations. | 2/2: a DEFC DISPLAY_0001 copy of kind `cuboid` (no operations) with element count 24 → `24 values`; the same with no element count → `--`. | Decode it through I-2 → `--` from `A2L-DEF-ELEMENTS` for the first case RED. | US-103-05 | new, E3R1 (E3A-02) | B `F.page200.*` (until Inc 9 lands, software_a's arrays and curves take this rule: 4 and 8 values) |
| R-PE-DEF.88 | If | If a text row's span is longer than 4,096 bytes, then the system shall show `<n> B`, n the span's length, in its Current column. | 2/2: a V171 ASCII copy widened to 4,097 bytes → `4097 B`; to 1,048,576 bytes → `1048576 B`. | Decode the span → `"AAAA…` RED. | US-103-05 | new, E3R2 (E3S-10) | B `S.*` |
| R-PE-DEF.19 | If | If a row's definition carries a refusal, then the system shall show `refused` in its Current column. | 2/2: two describe refusals of I-2 — a name declared twice (`A2L-DEF-NAME`) and a BIT_MASK keyword with no readable mask (`A2L-DEF-MASK`). | Decode a refused definition → exception or a value RED. | US-103-05 | new | I-2 refusal codes (graph-inc2) |
| R-PE-DEF.20 | U | The system shall show each row's unit in the Unit column as plain text. | 2/2: DISPLAY_0001 `deg C`; a unit `"%\x1b"` → `%�`. | Raw unit → the ESC case RED. | US-103-05 | new | B `DEFC.DISPLAY_0001.unit = 'deg C'` |
| R-PE-DEF.21 | U | The system shall show each row's limits cell of CTX-PE-DEF in the Limits column. | 4/4: DISPLAY_0001 at W = 118 (`-40`, `150`, ● at 143.5); a track under 6 cells → `-40 … 150`; no limits → `-`; a preview of 175 → `▶` on the right end. | Place `●` by stored value → RED. | US-103-05 | new | B `DEFC.DISPLAY_0001.limits` |
| R-PE-DEF.76 | If | If a row's upper limit is not greater than its lower limit, then the system shall show its limits cell as `<short lower> … <short upper>`. | 2/2: DISPLAY_0001 copies with limits `5 5` → `5 … 5` and `9 1` → `9 … 1`, no exception. | The plain division → `ZeroDivisionError` RED. | US-103-05 | new, E3R1 (E3S-05) | B `L.limits_5_5.cell`, `L.limits_9_1.cell`, `L.negative_control.plain_division` |
| R-PE-DEF.77 | If | If a row's upper limit is not greater than its lower limit, then the system shall show its pending Δ text without the percent. | 2/2: the same copies, pending `25.5` → `-118.0`. | The plain division → `ZeroDivisionError` RED. | US-103-05 | new, E3R1 (E3S-05) | B `L.*.pending_25.5.delta` |
| R-PE-DEF.22 | U | The system shall show `▶` in the mark column of the selected row. | 2/2: first row at start; third row after two downs. | Mark every row → RED. | US-103-05 | new | absent |
| R-PE-DEF.23 | While | While a row is staged, the system shall show `●` in its mark column and its staged value text in its New column. | 4/4: DISPLAY_0001 staged `25.5`; MASK_FIELD_0001 staged `255` → `255 (0xFF)`; ENUM_0001 staged `RUN` → `2 RUN`; the `cuboid` copy of R-PE-DEF.75 with a raw entry over its span → `●`. | Read New from the formula text → RED after the selection moves; staged state from a decode for the fallback → the `cuboid` case RED. | US-103-05 | new; E3R1 (E3A-02: fallback case) | B `ENC.*` |
| R-PE-DEF.24 | While | While a row is pending with an encodable preview, the system shall show `◆` in its mark column and the preview's value text in its New column. | 3/3: DISPLAY_0001 `25.5` → `25.5`; ENUM_0001 `RUN` → `2 RUN`; V171 ASCII selected then left with its row fill unchanged → no `◆` (not pending). | Echo the typed text: typed `25.50` shows `25.50` where the preview's text is `25.5` → RED; pending = any formula text → the V171 case RED. | US-103-05 | new; E3R1 (E3A-11: base-text case) | B `ENC.DISPLAY_0001.'25.5'` |
| R-PE-DEF.25 | If | If a pending row's preview is a refusal, then the system shall show its formula text, clipped to the New column, in its New column. | 2/2: DISPLAY_0001 `abc` → `abc`; `x`×300 → its start and `…`. | Show the refusal code → RED. | US-103-05 | new | B `ENC.DISPLAY_0001.'abc'` |
| R-PE-DEF.26 | U | The system shall show each staged or pending row's Δ text of CTX-PE-DEF in its Δ column. | 5/5: DISPLAY_0001 pending 25.5 → `-118.0 (-62.1%)`; DISPLAY_0001 staged 25.5 → `-118.0 staged`; ENUM_0001 RUN → `1 → 2`; MASK_FIELD_0001 255 → `+81`; V171 ASCII `ABC` → `10 chars`. | p over the extended limits → `-47.2%` RED. | US-103-05 | new | B; Δ = 25.5 − 143.5 |
| R-PE-DEF.27 | If | If a pending row's preview is a refusal, then the system shall show `✗ refused` in its Δ column. | 1/1: DISPLAY_0001 `250`. | Show the previous Δ → RED. | US-103-05 | new | B `ENC.DISPLAY_0001.'250'` |
| R-PE-DEF.28 | While | While a row is neither staged nor pending, the system shall show `·` in its New column and an empty Δ column. | 1/1: DISPLAY_0001 at start. | Show the current value in New → RED. | US-103-05 | new | absent |

### M3 · Detail and formula bar (CTX-PE-DEF)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-PE-DEF.30 | While | While a row is selected, the system shall show its detail lines under it and no detail line under any other row. | 2/2: select row 1, then row 3: detail moves, row 1 has none. | Keep every expanded row → RED. | US-103-05 | new | absent |
| R-PE-DEF.31 | U | The system shall start the selected row's detail with its definition line of CTX-PE-DEF. | 4/4: DISPLAY_0001 `└ LINEAR phys = 0.5*raw · SWORD s16 big-endian · 0x00800020 · 2 B`; ENUM_0001 `└ TAB_VERB 4 pairs · UBYTE u8 big-endian · 0x00800000 · 1 B`; MASK_FIELD_0001 `└ IDENTICAL phys = (word & 0x0FF0) >> 4 · UWORD u16 big-endian · 0x00800010 · 2 B`; V171 ASCII `└ text · 0x00810200 · 42 B`; a DISPLAY_0001 copy naming record layout `RL_U16` → `└ LINEAR phys = 0.5*raw · SWORD s16 big-endian · RL_U16 · 0x00800020 · 2 B`. | Leave out `>> <shift>` → MASK RED; drop the layout word → the `RL_U16` case RED. | US-103-05 | new; E3R1 (Inc 9 C-6: the layout word when named; 4/4 → 5/5) | B `DEFC.*` fields; `record_layout = None` for every scalar (D-7 A stands) |
| R-PE-DEF.32 | If | If the selected row's definition carries a refusal, then the system shall show its refusal message as the detail line `└ <message>`. | 1/1: a name declared twice → `└ <A2L-DEF-NAME message>`. | Show the definition line → RED. | US-103-05 | new | I-2 |
| R-PE-DEF.33 | While | While an enum row is selected, the system shall show its enum options of CTX-PE-DEF after the definition line. | 2/2: ENUM_0001 → `(●) 1 IDLE` chosen at start, `default "UNKNOWN_STATE"`; after choosing RUN → `(●) 2 RUN`. | Mark the current entry after a choice → RED. | US-103-05 | new | B `DEFC.ENUM_0001.enum_entries`, `.default_text` |
| R-PE-DEF.34 | While | While a bit-mask row is selected, the system shall show its bit strip of CTX-PE-DEF after the definition line. | 2/2: MASK_FIELD_0001 at start `word 1A E7 → 1A E7`; pending 255 → `word 1A E7 → 1F F7`. | Strip from the unmasked word only → RED. | US-103-05 | new | B `DEFC.word.image = 1a e7`, `ENC.MASK_FIELD_0001.'255'` |
| R-PE-DEF.35 | While | While a text row is selected, the system shall show its text rows of CTX-PE-DEF after the definition line. | 2/2: V171 ASCII at start → 3 rows `+00`, `+10`, `+20`; pending `ABC` → `+00 41 42 43 00 …`, 10 bytes in the pending style. | 8 bytes per row → RED. | US-103-05 | new | B `V171.ENC.ASCII.'ABC'` |
| R-PE-DEF.36 | While | While the selected row has no editor, the system shall show the formula tail `edit <kind word> objects in the Inspector tab` and keep the formula input disabled. | 4/4: a refused row; the `cuboid` copy of R-PE-DEF.75; a V171 ASCII copy widened to 4,097 bytes → `edit ASCII objects in the Inspector tab`, input disabled; boundary: widened to 4,096 bytes → the input enabled and the text tail. | Enable the input → RED; no span bound → the 4,097 case RED. | US-103-05 | new; E3R1 (Inc 9 C-9: the curve case moves to R-PE-BENCH.3; E3S-04: the span bound) | B `T.span_4096`, `T.span_4097` |
| R-PE-DEF.37 | U | The system shall show the formula bar of CTX-PE-DEF for the selected row on the staging sheet's last line. | 4/4 labels: DISPLAY_0001 `new =`, ENUM_0001 `new =`, MASK_FIELD_0001 `field =`, V171 ASCII `text =`; name at the bar's start. | One label for all → RED. | US-103-05 | new | absent |
| R-PE-DEF.38 | When | When a text row becomes selected, the system shall fill the formula input with its row fill. | 2/2: V171 ASCII → `Hello ASAM`; V171 ASCII edited to `ABC`, another row selected, then V171 again → `ABC`. | Leave it empty → RED; always the current text → the `ABC` case RED. | US-103-05 | new; E3R1 (E3A-11: row fill, was: its current text) | B `V171.…decode` |
| R-PE-DEF.39 | When | When a row other than a text row becomes selected, the system shall fill the formula input with that row's pending formula text. | 2/2: a row never edited → empty; DISPLAY_0001 left pending at `25.5`, then re-selected → `25.5`. | Clear pending text on move → RED. | US-103-05 | new | absent |
| R-PE-DEF.40 | When | When the formula text changes, the system shall show the selected row's formula tail of CTX-PE-DEF for its preview. | 4/4: DISPLAY_0001 `25.5` → `deg C  (-40 … 150)  raw 287→51 · 01 1F → 00 33  ✓ in limits  enter stage ↓`; `175` → `▲ DISPLAY_0001: 175 is outside the limits -40..150 and inside the extended limits -50..200`; `abc` → `✗ DISPLAY_0001: 'abc' is not a number`; V171 ASCII `ABC` → `3/42 chars · NUL-padded  enter stage ↓`. | Preview over the image, not the overlay → the masked case of .51 RED. | US-103-05 | new | B `ENC.DISPLAY_0001.*`, `V171.ENC.ASCII.'ABC'` |
| R-PE-DEF.41 | If | If the formula tail is wider than the formula bar, then the system shall cut it at the bar's right edge with one `…`. | 2/2: the `x`×300 refusal (289-character message) at 118 and 220 columns ends in `…` and fits. | Wrap the tail → RED. | US-103-05 | new | B `ENC.DISPLAY_0001."<300 x 'x'>".message_len = 289` (E3S-11) |
| R-PE-DEF.42 | If | If a typed or pasted text would make the formula text longer than 4,096 characters, then the system shall leave the formula text unchanged. | 3/3: a 65,536-character paste into an empty input → empty; 200 characters pasted onto 4,000 → the 4,000 unchanged; 5,000 typed characters → the first 4,096 (each later key leaves it unchanged). | No `max_length` → RED. | US-103-05 | new; E3R1 (E3S-06: the toolkit refuses the whole insert; was: keep the first 4,096) | B E3 probe `P4.paste_65536.value_len = 0`, `P4.paste_200_more.value_len = 4000`, `P4.typed_5000.value_len = 4096` |
| R-PE-DEF.78 | While | While the selected row has no editor, the system shall keep the formula input empty. | 2/2: a V171 ASCII copy widened to 4,097 bytes → input value `""`; widened to 1,048,576 bytes (I-2's cap) → `""`. | Fill the current text → 4,097 characters RED. | US-103-05 | new, E3R1 (E3S-04 b) | B E3 probe `P3.decode_1MiB.text_len = 1048576`, `P4.programmatic_5000.value_len = 5000` |
| R-PE-DEF.79 | If | If a text row's span is longer than 64 bytes, then the system shall show the line `… <n> more B` after its fourth text row, n = the span's length − 64. | 3/3: 65 bytes → `… 1 more B`; 4,097 → `… 4033 more B`; 1,048,576 → `… 1048512 more B`, 6 detail lines in all. | Paint every text row → 65,536 rows for the 1 MiB case RED. | US-103-05 | new, E3R1 (E3S-04 a) | B `T.span_*` |
| R-PE-DEF.80 | If | If a text that the system writes into the formula input is longer than 4,096 characters, then the system shall write its first 4,096 characters. | 1/1: an enum entry text of 5,000 characters chosen with right → input value of 4,096 characters. | A direct `value =` → 5,000 characters RED. | US-103-05 | new, E3R1 (E3S-04: every fill route) | B `T.fill_cap.enum_text_5000 = 4096`; E3 probe `P4.programmatic_5000.value_len = 5000` |

### M4 · Keys (CTX-PE-DEF)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-PE-DEF.45 | When | When the operator presses up or down while the staging sheet holds the focus, the system shall select the row above or below. | 4/4: down, down, up; up on the first row keeps it. | Wrap around → RED. | US-103-05 | new | P (keys reach a focusable `Static`: E4 pilot); code `sheet.py` (E4 trace) |
| R-PE-DEF.46 | When | When the operator presses Enter while the staging sheet holds the focus, the system shall move the focus to the formula input. | 1/1. | No binding → RED. | US-103-05 | new | P |
| R-PE-DEF.47 | When | When the operator presses left or right while an enum row is selected and the staging sheet holds the focus, the system shall choose the previous or next table entry and set the formula text to its text. | 3/3: ENUM_0001 from IDLE: right → RUN, right → FAULT, right → FAULT (no wrap). | Set the stored value as text → `2` RED (A2L-DEF-ENUM, `ENC.ENUM_0001.'2'`). | US-103-05 | new | B `ENC.ENUM_0001.'2'` refuses a stored number |
| R-PE-DEF.48 | When | When the operator presses Escape in the formula input, the system shall clear the selected row's pending formula text and move the focus to the staging sheet. | 1/1: DISPLAY_0001 pending `25.5` → no `◆`, focus on the sheet. | Keep the text → RED. | US-103-05 | new | P |
| R-PE-DEF.49 | When | When the selected row changes, the system shall make the picker's highlighted parameter the selected row's parameter. | 2/2: select row 3 → `highlighted_parameter["name"]` is row 3's name; after a page turn, row 1's. | Leave the picker cursor at 0 → RED. | US-103-04 | new | R `a2l_parameter_picker.py:524-560` |
| R-PE-DEF.81 | When | When the selected row or the shown page changes, the system shall paint the sheet rows of the row window of CTX-PE-DEF. | 4/4 at 118×54, a 200-name software_a page: 40 × down → the selected row's line and its detail lines lie inside `#patch_sheet_body`'s content region; then up past the first painted row → the selected row is the first painted row; the selection moved down onto an enum row of that page (3 detail lines) on the window's last line → its 3 detail lines inside the region; a stand-in kind with 10 detail lines at the 12-row minimum (visible 8) → the selected row painted and its detail cut to 7 lines. | Paint every row from row 0 → the first case RED (the selected row on body line 40); no cut → the stand-in case paints no row RED. | US-103-05 | new, E3R1 (E3A-01); E3R2 (E3A-14: the detail is cut, the row always painted) | B `W.row_window*`, `W.down_x40_from_0.*`, `W.negative_control.*`; `W2.*` (`examples_e3r2-transcript.txt`) |

### M5 · Staging (S8 document, I-2 consumer notes)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-PE-DEF.50 | When | When the operator presses Enter in the formula input and its preview is an encode, the system shall write the encoded span into the change document. | 4/4: DISPLAY_0001 `25.5` → one bytes entry at 0x800020 `00 33`; ENUM_0001 `RUN` → `02` at 0x800000; MASK_FIELD_0001 `255` → `1F F7` at 0x800010; V171 ASCII `ABC` → 42 bytes at 0x810200. | Stage through `add_symbol_entry` (the pre-I-2 encode) → the masked case RED. | US-103-05 | new | B `ENC.*`; R `change_service.py:1253-1329` (today's symbol add) |
| R-PE-DEF.51 | U | The system shall encode a staged edit over the staged overlay. | 3/3 (E3A-07/E3S-08 AT): MASK_FIELD_0001 `255` then MASK_BIT_0001 `0`, and the reverse order; after Apply both decode as typed (`255`, `0`), word `1F F6`; MASK_FIELD_0001 `255` staged, Apply, Remove of that entry, then MASK_BIT_0001 `0` staged → the entry is `1A E6` and MASK_FIELD_0001 decodes `174`. | Encode over the image → first-staged field reverts (`174` or `1`) RED; encode over the live (applied) map → `1F F6`, the removed field back, RED. | US-103-05 | new; E3R1 (E3S-01: one source image, the Apply-and-Remove case) | B `ORDER.*.decode`, `ORDER.*.no_overlay.decode`; E3 probe `P2.after_apply_and_remove.*` |
| R-PE-DEF.52 | When | When a staged edit's span equals the span of an entry in the document, the system shall replace that entry with a bytes entry of the encoded span. | 3/3: DISPLAY_0001 staged `25.5` then `30` → one entry `00 3C`; the two-masked-fields order → one entry at 0x800010; a `string` entry of 42 characters at 0x810200, then V171 ASCII `XYZ` staged, saved and read back → `"type": "bytes"`, V171 decodes `XYZ`. | Append a second entry → `CHG-COLLISION` RED; replace only the bytes of a `string` entry → the reload decodes the old text RED. | US-103-05 | new; E3R1 (E3S-02: replace the entry, was: its bytes) | R `validate.py:45-75` (collision), `changes/io.py:1544-1550` (writer); B `X.*` |
| R-PE-DEF.53 | When | When a staged edit's span intersects no entry of the document, the system shall append a bytes entry whose symbol is the row's name. | 1/1: DISPLAY_0001 → entry `symbol == "DISPLAY_0001"`, `entry_type == "bytes"`. | Symbol `None` → RED. | US-103-05 | new | R `model.py:80-112` (`symbol`) |
| R-PE-DEF.54 | When | When a staged edit replaces an entry, the system shall keep that entry's symbol. | 1/1: MASK_FIELD_0001 then MASK_BIT_0001 → `symbol == "MASK_FIELD_0001"`. | Overwrite the symbol → RED. | US-103-05 | new; E3R1 (E3S-02: "replaces an entry", was: "an entry's bytes") | D-3 A |
| R-PE-DEF.55 | If | If a staged edit's span intersects an entry of the document without equalling its span, then the system shall refuse the stage with the status `Patch Editor: <name> overlaps the entry at 0x<X> — remove that entry first.` | 2/2: a raw bytes entry at 0x800021 (1 byte), then stage DISPLAY_0001; an entry 0x80001F…0x800020. Document unchanged. | Replace the partial entry → RED. | US-103-05 | new | absent |
| R-PE-DEF.56 | If | If the preview is a refusal when the operator presses Enter in the formula input, then the system shall leave the document unchanged. | 3/3: `abc`, `250`, `WALK`. | Stage the image bytes → RED. | US-103-05 | new | B `ENC.*` refusals |
| R-PE-DEF.57 | If | If the preview is a refusal when the operator presses Enter in the formula input, then the system shall show the status `Patch Editor: <message>`. | 3/3: `Patch Editor: DISPLAY_0001: 250 is outside the extended limits -50..200`; `… 'abc' is not a number`; `Patch Editor: ENUM_0001: 'WALK' is not a text of VT_DEF_STATE`. | Show the code only → RED. | US-103-05 | new | B |
| R-PE-DEF.58 | When | When a stage writes the document, the system shall show the status `Patch Editor: <name> staged as <text> (<n> B at 0x<X>).` | 3/3: `Patch Editor: DISPLAY_0001 staged as 25.5 (2 B at 0x800020).`; `Patch Editor: ENUM_0001 staged as RUN (1 B at 0x800000).`; a V171 ASCII copy widened to 4,000 bytes staged with 300 × `x` → `<text>` is 256 × `x` then `…`. | Show `entry added.` → RED; an unbounded `<text>` → the 300-character case RED. | US-103-05 | new; E3R1 (E3A-03, E3S-04 d: `<name>` and `<text>` are name echoes; `<text>` = the shown text the caller passes, here the staged value's decoded `text`) | absent |
| R-PE-DEF.59 | When | When a stage writes the document and its encode gave a notice, the system shall show the status `Patch Editor: <notice>`. | 1/1: DISPLAY_0001 `175` → the status line is exactly `Patch Editor: DISPLAY_0001: 175 is outside the limits -40..150 and inside the extended limits -50..200`. | Drop the notice → RED; report it as an issue → the line reads `[…] warning: …` RED. | US-103-05 | new; E3R1 (E3A-10: a line of its own, not an issue line) | B `ENC.DISPLAY_0001.'175'` (R-A2L-DEF.44); R `app/patch.py:1180-1184` (issue lines) |
| R-PE-DEF.60 | When | When a formula-bar stage writes the document, the system shall select the row after the staged row. | 4/4: DISPLAY_0001 staged → the next row selected; the last row staged → stays; DISPLAY_0001 staged after the selection moved down two rows before the stage was handled → the row after DISPLAY_0001; a stage reported with no advance (the record-stage call of Inc 9) → the selection unchanged. | Keep the selection → RED; select from the current selection → the third case RED. | US-103-05 | new; E3R1 (E3A-07: after the staged row by name; Inc 9 C-8: formula-bar stages only) | absent (pe_B "enter stage ↓") |
| R-PE-DEF.82 | When | When a formula-bar stage writes the document, the system shall clear the staged row's pending formula text. | 2/2: DISPLAY_0001 `25.5` staged, then Undo → DISPLAY_0001 shows no `◆`; staged, then DISPLAY_0001 selected again → the input is empty. | Keep the pending text → `◆` after the Undo RED. | US-103-05 | new, E3R1 (E3A-07) | absent |
| R-PE-DEF.61 | When | When a stage writes the document, the system shall add one undo step. | 1/1: stage, Undo → the document before the stage; `history_depths()["undo"]` +1. | No `_push_history` → RED. | US-103-05 | new | R `change_service.py:971-993` |
| R-PE-034 | When | When the document changes through Add, Edit, Remove, Parse pasted, a stage, undo, redo or a per-entry JSON edit, the system shall set the dirty flag. | +1/1 for the stage: dirty after DISPLAY_0001 `25.5`. | No writer for the stage → RED. | US-103-05 | changed (+ "a stage") | R `actions.py` writer census (C-15.1) |
| R-PE-035 | If | If an Add, Edit, Remove or stage is refused, then the system shall keep the dirty flag as it was. | +2/2 for the stage: `abc` refused with the flag clear, and with it set. | Set the flag before the encode → RED. | US-103-05 | changed (+ "or stage") | R |
| R-PE-DEF.62 | When | When the document changes, the system shall repaint every row's staged state from the staged overlay. | 4/4: Undo of a stage → `●` gone; Remove of the 0x800010 entry → both masked rows unstaged; Parse pasted of a document with the DISPLAY_0001 entry → `●` on DISPLAY_0001; MASK_FIELD_0001 `255` staged over word `1A E7`, then an image whose word is `1A E6` → MASK_BIT_0001 shows `●` and New `1 (0x01)`. | Track staged rows in the sheet only → the Undo case RED; keep the rows of the old image → the new-image case RED. | US-103-05 | new; E3R1 (E3S-08: the new-image cue) | B `M.*` |
| R-PE-110 | While | While a session action runs, the system shall refuse Add, Edit, Remove, Load, a dropdown pick, Refresh, Parse pasted, Validate, Apply loaded changes, Save, Run checks, Execute scope, Undo and Redo (buttons, Ctrl+Z and Ctrl+Y), Write file, a stage, both Edit JSON popups and their results, and the accept of the unsaved-changes popup. | +1/1 for the stage: a session action held running (the existing busy fixture) → Enter on DISPLAY_0001 `25.5` → the busy line, document unchanged, dirty flag unchanged. Inc 9's record stage is its R-PE-BENCH.83 case. | No busy check in the stage → RED. | US-103-05 | changed, E3R1 (E3S-03, Inc 9 E-2: + "a stage" of CTX-PE-DEF, the formula-bar stage and the record stage) | R `app/shell.py:425-447`, `app/patch.py:145` (the Patch actions' gate) |
| R-PE-DEF.63 | If | If no A2L is loaded when a stage acts, then the system shall refuse the stage with the status `Patch Editor: no A2L is loaded — nothing staged.` | 1/1: A2L unloaded between the selection and Enter. | Stage with the old definition → RED. | US-103-05 | new | absent |
| R-PE-DEF.64 | When | When a stage acts, the system shall describe the row's parameter again with the A2L loaded at that moment. | 1/1: reload an A2L that moves DISPLAY_0001 to 0x800030, stage before the page repaints → the entry lands at 0x800030. | Use the page's definition → 0x800020 RED. | US-103-05 | new | I-2 note: "a consumer never clears `shared_with` and re-describes after an A2L change" |

### M6 · Plain text and hostile content (I-2 consumer notes E3S-04a, E3A-25/E3S-19)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-PE-DEF.70 | U | The system shall paint every name, unit, value text, enum text, default text, notice, refusal message and formula text in the staging sheet as plain text. | 5/5 (textual 8.2.8): an enum text `A[/x]B` (raises `MarkupError` with markup on), `[@click=app.quit]OFF[/]` (no action link), a unit `Map[b]x` (all characters shown), the formula text `A[b]` in its refusal tail; a row named `A[/x]B` selected → no exception, the formula bar's name shows `A[/x]B`. | Render one cell as a markup `str` → RED; the bar's name as a markup `Label` → the last case RED. | US-103-05 | new; E3R1 (E3S-07: the formula bar's name) | `../inc-2/E3-security.md` E3S-04 T1–T3 |
| R-PE-DEF.71 | U | The system shall replace every control character of CTX-PE-DEF plain text by U+FFFD in every text the staging sheet paints. | 3/3: an enum text `A\x1b[2J` → `A�[2J`; a name with NUL; a unit with U+0085. | Paint the raw word → RED. | US-103-05 | new | B `ENC.DISPLAY_0001.'A[b]\x1b[2J'` (I-2 cleans its messages; sheet cells are raw words) |
| R-PE-DEF.72 | U | The system shall write a name in an Inc 8 status message as its name echo of CTX-PE-DEF. | 2/2: R-PE-DEF.55 with a 300-character name → 256 characters and `…`; a name with ESC → U+FFFD. | Unbounded name → RED. | US-103-05 | new | absent (I-2's echo is private, `a2l_definition.py:370`) |
| R-PE-DEF.73 | U | The system shall show every status message of the Patch Editor's stage as plain text. | 1/1: the `A[b]` refusal on the status line shows `[b]`. | `markup=True` status → RED. | US-103-05 | new | R `patch.py:1155-1186` (`set_status`) |

### M7 · Help section (canon R-WHELP.12; law TC-B97-32 / LLR-148.6) — E3R1 (E3A-06)

The help text is visible: its wording is batched with V-1 on the review page (DF-09, `E1-rulings.md` §6 V-12). Each case reads the section through TC-B97-32's `label — effect` parser (`tests/test_b97_chips_help.py:1012-1025`).

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-PE-DEF.83 | U | The system shall describe the Patch Editor in its help section's first step as the filter row, the STAGING SHEET and LANDS IN with the Patch script, Inspector, JSON and Checks tabs. | 2/2: step 1 names the three regions and the four tabs; no step names an A2L tab, `A2L PARAMETERS`, "on the left" or "on the right". | Keep today's step 1 → RED. | US-103-05 | new, E3R1 (E3A-06) | R `window_help.py:61-110` |
| R-PE-DEF.84 | U | The system shall give the Patch Editor's help section a `Patch script — <effect>` line that names the ledger of the document's entries. | 1/1: the parsed line `Patch script` exists, its effect non-empty and holding `entries`. | No line → TC-B97-32 lists `Patch script` as missing RED. | US-103-05 | new, E3R1 (E3A-06) | R `test_b97_chips_help.py:1102-1103` |
| R-PE-DEF.85 | U | The system shall state in the Patch Editor's help section that in the staging sheet ↑ and ↓ select a row, Enter moves to the formula input, ← and → choose an enum entry, and Escape returns from the formula input to the sheet. | 1/1: one `STAGING SHEET — …` line whose effect holds `↑↓`, `enter`, `←→` and `esc`. | Drop the line → RED. | US-103-05 | new, E3R1 (E3A-06) | absent |
| R-PE-DEF.86 | U | The system shall give the Patch Editor's help section one `label — effect` line for each formula label `new =`, `field =` and `text =`. | 3/3: each of the three labels has a line whose effect names Enter as the stage key. | Only a `new =` line → the `field =` case RED. | US-103-05 | new, E3R1 (E3A-06) | R `test_b97_chips_help.py:1027-1041` (an input's label is the `Label` left of it) |
| R-PE-DEF.87 | U | The system shall state in the Patch Editor's help section that Use parameter, on the Inspector tab, uses the staging sheet's selected row. | 1/1: the parsed `Use parameter` effect holds `Inspector` and `selected row`, and not `A2L tab`. | Today's line → RED. | US-103-05 | new, E3R1 (E3A-06) | R `window_help.py:83-85` |

**Count:** 89 active rows — 79 new (R-PE-DEF.1.1, .1.2, .2 … .7, .10 … .28, .30 … .42, .45 … .49, .50 … .64, .70 … .88), 10 changed (R-TUI-063.1, .3, .4, .6, R-PE-041, R-PE-034, R-PE-035, R-PE-110, R-PICKER-CORRECT.011, .020), 3 retired (R-TUI-063.2, .7, R-PE-DEF.1). E3R1 added 16 (R-PE-DEF.1.1, .1.2, .74 … .87), changed R-PE-110, and retired R-PE-DEF.1 by its split; it changed 17 rows in place (R-PE-DEF.7, .11, .12, .23, .24, .31, .36, .38, .42, .51, .52, .54, .58, .59, .60, .62, .70; each says `E3R1` in its Status). E3R2 added R-PE-DEF.88 and changed R-PE-DEF.11, .12 and .81 in place (Status `E3R2`). Over the cap of about 80, under the stop line of about 90 (`E3-rulings.md`). Planned cases: `02-test-cases.md`. Every active row has a numeric threshold and a negative control.

**Rows another ruling would change** (`E1-rulings.md` §3): D-1 B → R-TUI-063.3 loses Inspector and R-PE-DEF.3 is withdrawn, with the entry-form rows of S10.3 (`R-PE-020` … `R-PE-033`) and R-PICKER-CORRECT.005 … .008, .016 left with no reachable control; D-1 C → R-TUI-063.3 keeps an A2L chip and R-PE-DEF.3 is withdrawn; D-2 B → R-PE-041 stays as it was and the ledger keeps a border; D-3 B → R-PE-DEF.54 says the symbol is dropped; D-4 A → one key row and one unstage row are added; D-6 B → R-PE-DEF.6 and .7 describe a horizontal scroll; D-7 B → I-2 fills the layout word for scalars, which R-PE-DEF.31 then paints (since E3R1 it paints a named one).
