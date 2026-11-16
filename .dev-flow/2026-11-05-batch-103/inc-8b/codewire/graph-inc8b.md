# Inc 8b — Code-Wire graph: staging sheet grid D, colour tokens, aligned Limits, B's card, F-R14-1 (E2 prototype)

Batch `2026-11-05-batch-103`, increment 8b, stage E2, 2026-11-14, model Opus (E1 + E2 by one agent, DF-03). Base `09001bbc`. Code-Wire `v3.1.0-8-gb6cd30d` (README v3.2), core only: one node per function the change adds or touches, examples taken from the requirements (`../01-requirements.md`) and computed by `../evidence-e1/examples_inc8b.py` (keys of `examples_inc8b-transcript.txt`), each writable as a test that fails before the change. This graph writes only the differences: a node here replaces the node of the same module and name in `../../inc-8/codewire/graph-inc8.md` or `../../inc-9/codewire/graph-inc9.md` (`--layered`, this graph last); every other node of those graphs stands.

E3R1 (targeted corrections from `../E3-rulings.md`; list in `../E3R1-changes.md`): new nodes `StagingSheet._detail_geometry` and `ArrayBenchSheet._bench_geometry`; the scroller pinned as a plain `Container`; the no-position form and the cell-16 collision in `limits_cell`; card widths in cells and plain text in `card_lines`; R-PE-BENCH.94 / .95 renumbered .107 / .108.

Inputs: `../01-requirements.md` (38 active rows at E2; 42 after E3R1), `../02-test-cases.md` (113 cases at E2; 130 after E3R1), `../E1-rulings.md` (D-1 … D-9 ruled, V8b-1 … V8b-12 provisional: each node follows the provisional choice; `[V8b-n]` marks a line another choice would change), `../E1-slice.md` (groups S, W, B).

### Baseline (code in scope at `09001bbc`, real callers)

Extractor run in a throwaway clone (marks `--layered --graph graph-inc8.md --graph graph-inc9.md`: 90 marks, 2 nodes replaced by the later graph; extract over `definition_sheet.py`, `patch_editor/sheet.py`, `definition_bench.py`, `a2l_parameter_picker.py`: 45 marks, 72 real calls, 0 parse failures). Rulings on its list: the 62 drift lines are Inc 8 / Inc 9 nodes outside this slice or type spellings (`X | None` vs `X?`), none in a node this graph changes; the 2 "no def" (`PatchEditorPanel._TABS`, `WINDOW_HELP_SECTIONS`) are data, kept as data nodes (report `../evidence-e1/cw-e1-baseline-diff-report.md`; runner `../evidence-e1/cw8b-run.py`, home paths redacted to `~`). E2 re-run with this graph layered last (`../evidence-e1/cw-e2-layered-diff-report.md`): every changed node of this graph found its code; "no def" only for the 7 new functions not written yet and the 2 data nodes; rulings on its drift lines: `tone` (limits_cell, _stock_cells) and `odd` (row_line) are the new keywords of this design; `_detail_enum` / `_detail_mask` / `_detail_text` have unannotated parameters in the code (E4 may annotate, no contract change); the other lines are Inc 8 / Inc 9 nodes outside this slice; `_SheetBody.on_resize`'s type spelled `events.Resize` after the run (lint exit 0, `../evidence-e1/cw-lint-e2.txt`). Real callers of the changed nodes (lines at `09001bbc`):
- `sheet_widths` ← `StagingSheet._paint` (`sheet.py:327`), `ArrayBenchSheet._start_next` (`bench_sheet.py:138`, Inc 9: `.current` for the strip width).
- `header_line` ← `StagingSheet._paint` (`sheet.py:333`). `row_line` ← `StagingSheet._paint` (`sheet.py:339`). `detail_lines` ← `StagingSheet._paint` (`sheet.py:329`), `StagingSheet._fit_window` (`sheet.py:420`).
- `limits_cell` ← `_stock_cells` (`definition_sheet.py:807`). `_bit_strip` ← `_detail_mask` (`:548`); `_text_rows` ← `_detail_text` (`:572`). `_mark` ← `row_line` (`:827`). `_verdict` ← `_scalar_tail` (`:909`).
- `summary_strip` ← `ArrayBenchSheet._derive` (`bench_sheet.py:288`). `bench_cells` ← the bench's `KindOps.cells` entry (`bench_sheet.py:592`, called by `row_line`).
- `_SheetBody.on_resize` ← Textual (resize event). `StagingSheet.compose` ← Textual; `ArrayBenchSheet` inherits it (`bench_sheet.py`, no override).
- E3R1 (E3-8b-02, from the E3 review's grep): `ArrayBenchSheet._bench_geometry` (`bench_sheet.py:305-312`) ← `ArrayBenchSheet._reveal` (`:316`), `ArrayBenchSheet.action_page` (`:378`); it repeats the detail geometry (the body's width, visible = height − 1) and calls `canvas_shape` (`definition_bench_view.py:279`), as `bench_detail` (`:307`) does with the width and room `detail_lines` passes.

### Groups (file ownership; `../E1-slice.md` §1)

| Group | Files | Nodes |
|---|---|---|
| S — sheet render | `s19_app/tui/definition_sheet.py` | 20 (7 new) |
| B — bench strip and limits, rule text | `definition_bench.py`, `insight_style.py` (comment) | 2 (+ the comment in §Entities) |
| W — widget, bench geometry, picker label, help | `patch_editor/sheet.py`, `patch_editor/bench_sheet.py` (`_bench_geometry` only), `a2l_parameter_picker.py`, `window_help.py` | 10 (3 new; 1 data node) |

### Interfaces

**Consumed, pinned elsewhere, unchanged:** I-2 (`Definition`, `Decoded`, `Refusal`, `Encoded`); I-8.1 `StagedOverlay`; I-8.4 `StagingSheet` (`show_page`, `set_document`, `selected_name`, `select_after`, `states`, `_paint`, the overridable actions); I-8.5 `KindOps` and `_KIND_OPS` (the bench's `cells`, `mark`, `detail`); I-9.1 `ArrayBenchSheet` (subclass of `StagingSheet`, inherits `compose` and `_paint`).

**Changed here (users named):**
- `sheet_widths(width) -> SheetWidths` — the grid widths at every width (user: `bench_sheet.py:138`, unchanged call).
- `detail_lines(row, preview, width, state, room)` — `width` is the view width V; the kind's `detail` gets V − 4; every returned line carries `  ┊ ` and the expanded ground over max(G, V) (user: `StagingSheet._paint`, `_fit_window`; the bench's `KindOps.detail` is called through it).
- `row_line(…, state=None, odd=False)` — one keyword more (user: `StagingSheet._paint`).
- `limits_cell(row, value, width, tone="")` — one keyword more (user: `_stock_cells`).
- `summary_strip(values, grid, width)`, `bench_cells(row, state, widths)` — same signatures, new output.
- E3R1: `ArrayBenchSheet._bench_geometry(state, grid) -> tuple[int, int]` — same signature; its shape now comes from `StagingSheet._detail_geometry()` (users: `_reveal`, `action_page`, unchanged).

**New, pinned here:** `GRID_WIDTH = 143`; `header_rule(widths) -> Text` (E4 I8b, orchestrator ruling: the implementation's signature `header_rule(widths: SheetWidths)` wins, as the node's `in:` already said); `limit_slot(x) -> Text`; `range_cell(lower, upper) -> Text`; `card_lines(title, rows, cap) -> list[Text]`; `bit_table(row, preview) -> list[Text]`; `hex_grid(row, preview) -> list[Text]`; `StagingSheet.action_scroll_grid(where)`; `StagingSheet._view_width() -> int`; `StagingSheet._detail_geometry() -> tuple[int, int]` (E3R1); the scroller id `#patch_sheet_grid`, a plain `textual.containers.Container` (E3R1: not focusable, no bindings). Style constants of `definition_sheet.py`: `_TEXT = VALUE`, `_DIM = DGRAY`, `_RULE = HILITE`, `_STAGED = GREEN`, `_PENDING = PURPLE`, `_REFUSED = RED`, `_NOTICE = YELLOW`, `_SELECTED_GROUND = "#1c2547"`, `_ODD_GROUND = DEPTH_ODD_ROW`, `_EXPANDED_GROUND = DEPTH_BORDER`, `_CARD_GROUND = DEPTH_PANEL`, `_KEY_INK = DEPTH_BG` (imported from `insight_style` / `render.format`, the only new literal is the selected ground).

### Examples (data; `EX-8B-*` ids are cited by the cases)

| Id | Fixture | Values (transcript keys of `../evidence-e1/examples_inc8b-transcript.txt`) |
|---|---|---|
| EX-8B-G1 | the grid widths | `G.header_line`, `G.header_rule` (143 cells) |
| EX-8B-G2 | DEFC page at V = 73, 111, 195 | `G.start.*` (2, 29, 40, 61, 78, 87, 122), `G.gutter_after.*` (28 … 142), `G.grid_width` 143 |
| EX-8B-G3 | 80×24, 118×54, 220×60 | `G.scrollbar.*` True, True, False |
| EX-8B-G4 | End / Home | `G.end.*` 70, 32, 0 |
| EX-8B-G5 | the formula bar | ≤ the sheet window's content width; R-PE-DEF.41's `x`×300 tail |
| EX-8B-G6 | keys under the scroller (E3R1) | 118×54: `→` on ENUM_0001 → `(●) 2 RUN`, x stays 0; x right after End `32` (no wait); the Tab order unchanged, `#patch_sheet_grid` never focused |
| EX-8B-W1 | row window | `W.visible.h8` 6, `W.room.h8` 5, `W.standin_10_detail.h8.painted` 5; test host at 118×54 `W.harness_118x54.*` (grid 53, body 52, visible 50; E3R1) |
| EX-8B-W2 | detail geometry (E3R1) | `W.detail_geometry.V111.h20` (107, 17), `W.detail_geometry.V73.h8` (69, 5), `W.detail_geometry.V195.h20` (191, 17); base `W.bench_geometry.base.*` (143, 18), (143, 6) |
| EX-8B-C1 | hostile cells | `C.name_wide.fit26`, `C.unit_wide.fit8`, `C.enum_long.current20`, `C.name_10000.fit26`, `C.unit_40.fit8`, `C.name_esc.fit26` |
| EX-8B-S1 … S6 | DEFC page with DISPLAY_0001 staged 25.5, pending `25.5`, `175`, `250`; MASK_FIELD_0001 staged 255; VAL_BLK_DEF_0001 staged / with a bench edit | the styles of CTX-PE-DEF sheet styles |
| EX-8B-L1 | DEFC scalar rows | `L.cell.DISPLAY_0001.*`, `L.cell.MASK_FIELD_0001.cur174.new255`, `L.cell.MASK_BIT_0001.cur1.new0`, `L.cell.ENUM_0001.cur1` |
| EX-8B-L2 | offsets | `L.cell.*.offsets`, `L.bench.*.offsets`, `L.offset.*` (track 8 … 25, range mark 16, unit cells 6 and 33) |
| EX-8B-L3 | slots | `L.short.*`, `L.slot.*` |
| EX-8B-L4 | range form | `L.cell.limits_5_5`, `L.cell.limits_9_1`, `L.cell.lower_-inf`, `L.cell.upper_nan`, `L.cell.no_limits` |
| EX-8B-L5 | bench rows | `L.bench.CURVE_DEF_0001`, `L.bench.MAP_DEF_0001`, `L.bench.VAL_BLK_DEF_0001` |
| EX-8B-L6 | collision at cell 16 (E3R1) | `L.cell.DISPLAY_0001.cur150.new149.9` (`◆` 23, `●` 24, `┤` 25) |
| EX-8B-L7 | no-position form (E3R1) | `L.float32.FFFFFFFF` nan, `L.cell.float32_erased`, `L.cell.span_overflow`, `L.cell.DISPLAY_0001.new_inf` (`?` at 16) |
| EX-8B-E1 | expanded object at V = 111 | bar `  ┊ `, ground #1b233a over 143 cells, cut at 139 content cells (`G.detail_cap.V111`) |
| EX-8B-E2 | bench lines | each ≤ V once rstripped (V = 73, 111, 195) |
| EX-8B-K1 … K3 | cards | `E.card.ENUM_0001.*`, `B.card.MASK_FIELD_0001.*`, `T.card.V171.*`, `E.card.300_entries.*`, `E.card.cap.V111` |
| EX-8B-K4 | hostile card text (E3R1) | `E.card.name_esc.line0`, `E.card.row_esc.line1`, `E.card.markup.line1` |
| EX-8B-K5 | wide card text (E3R1) | `E.card.name_wide200.*` (139 cells), `E.card.enum_wide.*` (79 cells), `E.card.enum_wide100.line1` (139 cells) |
| EX-8B-B1, B2 | bit tables | `B.MASK_FIELD_0001.*`, `B.MASK_BIT_0001.pending0.*`, `B.ULONG_FF0000.pending0x12.*` |
| EX-8B-T1 … T3 | hex grids | `T.V171.start.*`, `T.V171.pendingABC.*`, `T.hostile.ascii`, `T.span65.more` |
| EX-8B-P1, P2 | filter row, help | `▽ Pick`; the `STAGING SHEET — …` help effect |
| EX-8B-F1 … F3 | strips | `S.after.*`, `S.wide.40_points_in_17`, `S.flat.all_equal`; before: `S.before.*`; capture probe `f_r14_1_probe-transcript.txt` |

### Coverage — every requirement → nodes and examples (owner group)

| Requirement | Nodes | Examples | Group |
|---|---|---|---|
| R-PE-DEF.5 | header_line | EX-8B-G1 | S |
| R-PE-DEF.89 | sheet_widths, row_line | EX-8B-G2 | S |
| R-PE-DEF.90 | row_line | EX-8B-G2, C1 | S |
| R-PE-DEF.91 | header_rule, StagingSheet._paint | EX-8B-G1 | S (+W) |
| R-PE-DEF.92, .93 | StagingSheet.compose | EX-8B-G3, G6 (.92/3) | W |
| R-PE-DEF.94 | StagingSheet.action_scroll_grid | EX-8B-G4, G6 (.94/6) | W |
| R-PE-DEF.95 | StagingSheet.compose | EX-8B-G5 | W |
| R-PE-DEF.96 | row_line (through `_text_cell` / `clip`, unchanged) | EX-8B-C1 | S |
| R-PE-DEF.81 | StagingSheet._paint, StagingSheet._fit_window, StagingSheet._detail_geometry, _SheetBody.on_resize, StagingSheet.on_resize (E4), StagingSheet.compose (height rules) | EX-8B-W1 | W |
| R-PE-BENCH.36 | StagingSheet._detail_geometry, ArrayBenchSheet._bench_geometry | EX-8B-W2 | W |
| R-PE-DEF.97 | header_line, header_rule, _definition_line (E4), _mark, _stock_cells, row_line, detail_lines, card_lines, _scalar_tail, bit_table | EX-8B-S1 | S |
| R-PE-DEF.98, .99, .100 | _tone, _mark, row_line, limits_cell | EX-8B-S2, S3, S4 | S |
| R-PE-DEF.101 | _tone, _verdict, formula_tail, row_line | EX-8B-S5 | S (+B comment) |
| R-PE-DEF.102 | bit_table, hex_grid | EX-8B-B1, T2 | S |
| R-PE-DEF.103 | row_line, bit_table, hex_grid | EX-8B-S6 | S |
| R-PE-DEF.21 | limits_cell, limit_slot | EX-8B-L1 | S |
| R-PE-DEF.104 | limit_slot, range_cell, limits_cell | EX-8B-L2, L6 (.104/7) | S |
| R-PE-DEF.105 | limit_slot | EX-8B-L3 | S |
| R-PE-DEF.106, .76 | range_cell, limits_cell | EX-8B-L4 | S |
| R-PE-DEF.114 | limits_cell | EX-8B-L7 | S |
| R-PE-BENCH.17 | bench_cells, range_cell | EX-8B-L5 | B (+S) |
| R-PE-DEF.107 | detail_lines, StagingSheet._paint | EX-8B-E1 | S (+W) |
| R-PE-BENCH.5 | detail_lines, StagingSheet._view_width | EX-8B-E2 | W (+S) |
| R-PE-DEF.108 | card_lines, _detail_enum, _detail_mask, _detail_text | EX-8B-K1 | S |
| R-PE-DEF.33 | _detail_enum; StagingSheet.compose (.33/3: the scroller binds no key) | EX-8B-K1, G6 (.33/3) | S (+W) |
| R-PE-DEF.34 | bit_table, _detail_mask | EX-8B-B1 | S |
| R-PE-DEF.35 | hex_grid, _detail_text | EX-8B-T1, T2 | S |
| R-PE-DEF.109 | bit_table | EX-8B-B2 | S |
| R-PE-DEF.110, .111 | hex_grid | EX-8B-T1, T3 | S |
| R-PE-DEF.112 | card_lines | EX-8B-K3 | S |
| R-PE-DEF.115 | card_lines | EX-8B-K4 | S |
| R-PE-DEF.116 | card_lines | EX-8B-K5 | S |
| R-PE-DEF.117 | limits_cell | EX-8B-L7 | S (E4) |
| R-PE-DEF.113 | A2LParameterPicker.compose | EX-8B-P1 | W |
| R-PE-DEF.85 | WINDOW_HELP_SECTIONS | EX-8B-P2 | W |
| R-PE-BENCH.11, .107, .108 | summary_strip | EX-8B-F1, F2, F3 | B |

### Node count

34 nodes (E4 I8b: + `StagingSheet.on_resize` (W), `_definition_line` (S), both recorded from the implementers' deviations): group S 21 (`_definition_line`, `sheet_widths`, `header_line`, `header_rule`, `limit_slot`, `range_cell`, `limits_cell`, `_tone`, `_mark`, `_stock_cells`, `row_line`, `detail_lines`, `card_lines`, `bit_table`, `hex_grid`, `_detail_enum`, `_detail_mask`, `_detail_text`, `_verdict`, `_scalar_tail`, `formula_tail`), group B 2 (`summary_strip`, `bench_cells`), group W 11 (`StagingSheet.compose`, `StagingSheet.action_scroll_grid`, `StagingSheet._view_width`, `StagingSheet._detail_geometry` (E3R1), `StagingSheet._paint`, `StagingSheet._fit_window`, `_SheetBody.on_resize`, `StagingSheet.on_resize` (E4), `ArrayBenchSheet._bench_geometry` (E3R1), `A2LParameterPicker.compose`, `WINDOW_HELP_SECTIONS` (data), plus `StagingSheet.BINDINGS` and `StagingSheet.DEFAULT_CSS` in §Entities). Removed: `_bit_strip`, `_text_rows` (Inc 8 graph nodes of those names are retired by this graph; their callers now call `bit_table`, `hex_grid`).

## Nodes

sheet_widths
req: R-PE-DEF.89
in: int width
out: SheetWidths widths
func: the grid widths of CTX-PE-DEF whatever the width (D-1: kept so `bench_sheet.py:138` reads `.current` = 20 without an edit); the parameter is unused
module: s19_app/tui/definition_sheet.py
examples: (EX-8B-G2) width `73` → mark `2`, name `26`, kind `10`, current `20`, new `16`, unit `8`, limits `34`, delta `20`
examples: (EX-8B-G2) width `111` → the same widths; width `195` → the same widths (no stretch)

header_line
req: R-PE-DEF.5, R-PE-DEF.97
in: SheetWidths widths
out: Text line
func: two spaces, then each label left-aligned to its width and `│`; labels bold DGRAY, gutters HILITE; 143 cells
module: s19_app/tui/definition_sheet.py
examples: (EX-8B-G1) the grid widths → `G.header_line`: `"Parameter"` at `2`, `"Kind"` at `29`, `"Current"` at `40`, `"Limits"` at `87`, `"Δ"` at `122`; `│` at `28` and `142`
examples: (EX-8B-S1) the grid widths → label spans `bold #969aad`, gutter spans `#91abec`

header_rule
req: R-PE-DEF.91, R-PE-DEF.97
in: SheetWidths widths
out: Text line
func: `━━`, then per column `━` × its width and `┿`; all in HILITE; 143 cells
module: s19_app/tui/definition_sheet.py
examples: (EX-8B-G1) the grid widths → `G.header_rule`, length `143`, `┿` at `28`, `39`, `60`, `77`, `86`, `121`, `142`

limit_slot
req: R-PE-DEF.104, R-PE-DEF.105
in: float x
out: Text slot
func: 7 cells: the slot text's number right-aligned in 6 cells and its unit letter (k, M, G) in the 7th, else a space; slot text = the short number when at most 6 cells, else the exponent form `<d>e<exp>`
module: s19_app/tui/definition_sheet.py
examples: (EX-8B-L3) x `-40` → `"   -40 "`; x `65535` → `"  65.5k"`; x `-1000` → `" -1.00k"`; x `-655350` → `"  -655k"`
examples: (EX-8B-L3) x `4.29e12` → `"  4e12 "`; x `999.6e9` → `"  1e12 "`; x `-1.7e308` → `"-2e308 "`; boundary x `999.4e9` → `"   999G"`
examples: (EX-8B-L3) x inf → `"   inf "`; x -inf → `"  -inf "`; x nan → `"   nan "`

range_cell
req: R-PE-DEF.76, R-PE-DEF.104, R-PE-DEF.106, R-PE-BENCH.17
in: float? lower; float? upper
out: Text cell
func: 34 cells in the dim style: both limits → lower slot, space, 18-cell track blank but for `…` at its cell 8, space, upper slot; a missing limit → blank but for `-` at offset 16 [V8b-3, V8b-4]
module: s19_app/tui/definition_sheet.py
examples: (EX-8B-L5) lower `0`, upper `65535` → `"     0          …            65.5k"`; lower `-1000`, upper `1000` → `" -1.00k         …            1.00k"`
examples: (EX-8B-L4) lower `5`, upper `5` → `"     5          …               5 "`; lower `9`, upper `1` → `"     9          …               1 "`
examples: (EX-8B-L4) lower None, upper `150` → `-` at offset `16`, length `34`; lower -inf, upper `150` → `"  -inf          …             150 "`

limits_cell
req: R-PE-DEF.21, R-PE-DEF.76, R-PE-DEF.98, R-PE-DEF.99, R-PE-DEF.104, R-PE-DEF.106, R-PE-DEF.114, R-PE-DEF.117
in: SheetRow row; object value; int width; str tone = ""
out: Text cell
func: no bounds → `range_cell(None, None)`; upper ≤ lower or a bound not finite → `range_cell(lower, upper)` (no position is computed); guard (E3R1, R-PE-DEF.114): the current value or `value` not finite, or (v − lower)/(upper − lower) not finite for a value in range → the no-position form (lower slot, space, `├ ─×7 ? ─×8 ┤` dim, space, upper slot; no mark), before any `round`; else lower slot, space, track `├ ─×16 ┤` with `●` (bold VALUE) at the current value and `◆` (the row's tone) at `value`, `◀`/`▶` beyond an end, the second mark on a taken cell one cell right, or one cell left from cell 16 (E3R1: never onto `┤`), space, upper slot; text and track dim; (E4, R-PE-DEF.117) a limit or enum bound beyond the float range is read as ±inf (so the range form), and a value's position is (v/2 − lower/2)/(upper/2 − lower/2), which never overflows for finite limits
module: s19_app/tui/definition_sheet.py
examples: (EX-8B-L1) DISPLAY_0001 current `143.5`, value `25.5`, tone `bold #b565f3` → `"   -40  ├─────◆────────●─┤    150 "`, `◆` at `14` in `bold #b565f3`, `●` at `23` in `bold #e9e9e9`
examples: (EX-8B-L1) DISPLAY_0001 value `175` → `▶` at `25`; value `-45` → `◀` at `8`
examples: (EX-8B-L1) MASK_FIELD_0001 current `174`, value `255` → `"     0  ├──────────●────◆┤    255 "`; ENUM_0001 current `1` → `"     0  ├─────●──────────┤      3 "`
examples: (EX-8B-L4) DISPLAY_0001 copy with limits `5 5` → `"     5          …               5 "`, no exception; copy with LOWER_LIMIT -inf → `"  -inf          …             150 "`, no exception (base: `round(nan)` raises)
examples: (EX-8B-L2) V171 ASCII (text, no bounds) → `-` at `16`
examples: (EX-8B-L6) DISPLAY_0001 current `150`, value `149.9` (both on cell 16) → `"   -40  ├──────────────◆●┤    150 "`, `◆` at `23`, `●` at `24`, `┤` at `25` (a move right would cover `┤`)
examples: (EX-8B-L7) a DISPLAY_0001 copy, FLOAT32_IEEE, image `FF FF FF FF` → current nan → `"   -40  ├───────?────────┤    150 "`, no exception (base: `round(nan)` raises `ValueError`)
examples: (EX-8B-L7) limits `-1.7e308` … `1.7e308`, current `1e308` (pos = inf/inf = nan) → `"-2e308  ├───────?────────┤  2e308 "`, no exception; DISPLAY_0001 current `143.5`, value inf → `"   -40  ├───────?────────┤    150 "` (no `▶`)
examples: (EX-8B-L7) limits `-1.7e308` … `1.7e308`, current `1e308` → `L.cell.span_overflow`, `●` at `21`; ENUM_0001 with an entry raw `2**1100` → `L.cell.enum_beyond_float` (E4, R-PE-DEF.117)

_tone
req: R-PE-DEF.98, R-PE-DEF.99, R-PE-DEF.100, R-PE-DEF.101
in: SheetRow row; bool is_pending; Preview? preview; str? glyph = None
out: str style
func: the row's New/Δ style: a glyph from `KindOps.mark` decides for a bench row (`◆` pending, `●` staged); else pending with a Refusal preview → bold RED; pending → bold PURPLE (a notice included) [V8b-7]; staged → bold GREEN; else ""
module: s19_app/tui/definition_sheet.py
examples: (EX-8B-S3) DISPLAY_0001 pending `25.5` → `"bold #b565f3"`; pending `175` (a notice) → `"bold #b565f3"`
examples: (EX-8B-S4) DISPLAY_0001 pending `250` (Refusal) → `"bold #fd8383"`
examples: (EX-8B-S2) DISPLAY_0001 staged, not pending → `"bold #54efae"`; glyph `◆` (VAL_BLK_DEF_0001 with a bench edit) → `"bold #b565f3"`; neither → `""`

_mark
req: R-PE-DEF.97, R-PE-DEF.98, R-PE-DEF.99
in: bool selected; bool staged; bool pending; str? glyph = None
out: Text mark
func: cell 1 `▶` bold HILITE when selected; cell 2 `●` bold GREEN staged, else `◆` the pending style, else space (a `KindOps.mark` glyph replaces cell 2's choice)
module: s19_app/tui/definition_sheet.py
examples: (EX-8B-S2) selected `True`, staged `True`, pending `False` → `"▶●"`, `▶` `bold #91abec`, `●` `bold #54efae` (base: rich `green`)
examples: (EX-8B-S3) selected `False`, staged `False`, pending `True` → `" ◆"`, `◆` `bold #b565f3` (base: `#91abec`)

_stock_cells
req: R-PE-DEF.97
in: SheetRow row; SheetWidths widths; bool is_pending; str? pending; Preview? preview; object new; str tone
out: tuple(Text kind, Text current, Text new, Text limits, Text delta)
func: Kind dim; Current in the text style; New and Δ plain (row_line paints the tone over them for every kind); Limits from limits_cell with the tone
module: s19_app/tui/definition_sheet.py
examples: (EX-8B-S1) DISPLAY_0001 at start → kind `"VALUE"` in `#969aad`, current `"143.5"` in `#e9e9e9`, new `"·"` in `#969aad`

row_line
req: R-PE-DEF.89, R-PE-DEF.90, R-PE-DEF.96, R-PE-DEF.97, R-PE-DEF.98, R-PE-DEF.99, R-PE-DEF.100, R-PE-DEF.101, R-PE-DEF.103
in: SheetRow row; SheetWidths widths; bool selected; str? pending; Preview? preview; object state = None; bool odd = False
out: Text line
func: the mark, then each cell fitted to its grid width (the clip of CTX-PE-DEF) and `│` in HILITE; New and Δ stylized with `_tone` for every kind (bench cells included); ground #1c2547 when selected, else DEPTH_ODD_ROW when odd; exactly 143 cells
module: s19_app/tui/definition_sheet.py
examples: (EX-8B-G2) DISPLAY_0001, the grid widths → `│` at `28`, `39`, `60`, `77`, `86`, `121`, `142`; length `143`
examples: (EX-8B-C1) a name `温度`×14 → cells 2 … 27 `C.name_wide.fit26`; a unit `温度温度温度` → cells 78 … 85 `C.unit_wide.fit8`; a 40-character name → `│` at `28`
examples: (EX-8B-S2) DISPLAY_0001 staged 25.5 → New `"25.5"` and Δ `"-118.0 staged"` in `bold #54efae`, `●` on the same line
examples: (EX-8B-S3) DISPLAY_0001 pending `175` → New and Δ in `bold #b565f3`, no `#f6ff8f` span on the line (base: New in `bold #91abec`)
examples: (EX-8B-S4) DISPLAY_0001 pending `250` → Δ `"✗ refused"` in `bold #fd8383`
examples: (EX-8B-S1) selected `True` → ground `#1c2547` over cells 0 … 142; odd `True` → ground `#131a2c`; odd `False` → no ground
examples: (EX-8B-S6) the DEFC page rendered with NO_COLOR and without → the same plain text, `●`, `◆`, `▶`, `✗ refused` present

detail_lines
req: R-PE-DEF.107, R-PE-BENCH.5
in: SheetRow row; Preview? preview; int width; object state = None; int? room = None
out: list[Text] lines
func: width = the view width V; the kind's detail laid out for V − 4; each line cut at max(GRID_WIDTH, V) − 4 cells with one `…`, after `  ┊ ` (HILITE), padded with the expanded ground to max(GRID_WIDTH, V) [V8b-12]
module: s19_app/tui/definition_sheet.py
examples: (EX-8B-E1) DISPLAY_0001, width `111` → one line `"  ┊ └ LINEAR phys = 0.5*raw · SWORD s16 big-endian · 0x00800020 · 2 B"` then ground `#1b233a` to `143` cells
examples: (EX-8B-E1) a DISPLAY_0001 copy naming a 250-character record layout, width `111` → content cut at `139` cells ending `…`, line `143` cells
examples: (EX-8B-E2) MAP_DEF_0001 (bench), width `73` → every line starts `"  ┊ "` and is ≤ `73` cells once rstripped; width `195` → ≤ `195`
examples: (EX-8B-K1) MASK_FIELD_0001 → the definition line, then the 6 card lines, each after `"  ┊ "`

card_lines
req: R-PE-DEF.108, R-PE-DEF.112, R-PE-DEF.115, R-PE-DEF.116, R-PE-DEF.97
in: str title; list[Text] rows; int cap
out: list[Text] lines
func: `╭─ <title> ─…─╮`, `│ <row> │` per row, `╰─…─╯` in HILITE on the card ground; every width in terminal cells (a wide character 2, E3R1); inner width = widest row + 2 (at least the title + 4), at most cap − 2; the title and each row through `plain` (markup off, controls U+FFFD, E3R1); a row wider than inner − 2 cells cut with one `…`, the title cut to inner − 4 cells (the grid's clip, by cells); every line the same cell width
module: s19_app/tui/definition_sheet.py
examples: (EX-8B-K1) title `"ENUM_0001 · choose one"`, the two enum rows, cap `139` → `E.card.ENUM_0001.line0` … `line3`, top line 78 cells
examples: (EX-8B-K1) title `"MASK_FIELD_0001 · bit editor · other bits kept"`, the bit table, cap `139` → `B.card.MASK_FIELD_0001.line0` … `line5`, `73` cells
examples: (EX-8B-K3) title `"BIG_ENUM · choose one"`, one row of 300 entries, cap `139` → `E.card.300_entries.line1`, `139` cells, ending `"… │"`
examples: (EX-8B-K3) a title of a 300-character name, cap `139` → top line `139` cells, the title ending `…`
examples: (EX-8B-K4) title `"A\x1b[2J · choose one"` → `E.card.name_esc.line0` (`"╭─ A�[2J · choose one ─…╮"`); an enum row with `A\x1b[2J` → `E.card.row_esc.line1`; a row with `[@click=app.quit]OFF[/]` → `E.card.markup.line1`, the tags shown literally
examples: (EX-8B-K5) a title of `温度`×200, cap `139` → `E.card.name_wide200.line0`, `139` cells in `73` characters; an enum row with `温度` → `E.card.enum_wide.line0` … `line3`, `79` cells each; a row with `温度`×100 → `E.card.enum_wide100.line1`, `139` cells ending `"… │"`

bit_table
req: R-PE-DEF.34, R-PE-DEF.102, R-PE-DEF.109
in: SheetRow row; Preview? preview
out: list[Text] rows
func: one block of 4 lines (bit, before, mask, after) per 16 bits, high first, nibble guide ` │` after every bit multiple of 4; hex column on the first block only; mask bits in the text style, others dim; `■` bold HILITE; an after bit that differs from the image in the pending style, underlined; `?` for a bit the image does not hold
module: s19_app/tui/definition_sheet.py
examples: (EX-8B-B1) MASK_FIELD_0001 at start (word `1A E7`, mask `0x0FF0`) → `B.MASK_FIELD_0001.start.line0` … `line3`, last line `"after    0  0  0  1 │  1  0  1  0 │  1  1  1  0 │  0  1  1  1 │ 1A E7"`
examples: (EX-8B-B1) MASK_FIELD_0001 pending `255` → line 3 `"after    0  0  0  1 │  1  1  1  1 │  1  1  1  1 │  0  1  1  1 │ 1F F7"`, bits `10`, `8`, `4` underlined in `bold #b565f3`, no other bit underlined
examples: (EX-8B-B1) MASK_BIT_0001 pending `0` → mask line `"mask     ·  ·  ·  · │  ·  ·  ·  · │  ·  ·  ·  · │  ·  ·  ·  ■ │ 0001"`, after `… 1A E6`
examples: (EX-8B-B2) ULONG mask `0x00FF0000`, word `12 34 56 78`, pending `0x12` → `8` lines, first `"bit     31 30 29 28 │ 27 26 25 24 │ 23 22 21 20 │ 19 18 17 16 │ hex"`, fifth `"bit     15 14 13 12 │ 11 10  9  8 │  7  6  5  4 │  3  2  1  0 │"`, width `75`

hex_grid
req: R-PE-DEF.35, R-PE-DEF.102, R-PE-DEF.110, R-PE-DEF.111, R-PE-DEF.79
in: SheetRow row; Preview? preview
out: list[Text] rows
func: head `off │ +0 … +7 │ +8 … +F │ ASCII`; per 16 of the first 64 span bytes `+XX │` and ` XX` per byte (after the preview), ` │` after the 8th, 3 spaces per missing byte, ` │ ` and one ASCII character per byte (`·` outside U+0020 … U+007E); offsets and zero bytes dim, a changed byte and its ASCII character in the pending style, underlined; `… <n> more B` past 64
module: s19_app/tui/definition_sheet.py
examples: (EX-8B-T1) V171 ASCII at start → `"+00 │ 48 65 6C 6C 6F 20 41 53 │ 41 4D 00 00 00 00 00 00 │ Hello ASAM······"`; row `+20` `"+20 │ 00 00 00 00 00 00 00 00 │ 00 00                   │ ··········"`; the ASCII guide at `56` on all 4 lines
examples: (EX-8B-T2) V171 ASCII pending `ABC` → `"+00 │ 41 42 43 00 00 00 00 00 │ 00 00 00 00 00 00 00 00 │ ABC·············"`, offsets `0` … `9` underlined in `bold #b565f3`
examples: (EX-8B-T3) bytes `00 1B 7F 80 FF 41 20 7E` → ASCII `"·····A ~"`; a span of 65 bytes → last row `"… 1 more B"`

_detail_enum
req: R-PE-DEF.33, R-PE-DEF.108
in: SheetRow row; Preview? preview; int width; object state; int room
out: list[Text] lines
func: the definition line, then card_lines(`<name> · choose one`, [the enum options line, `↔ choose · enter stage`], max(GRID_WIDTH − 4, width)) [V8b-11]
module: s19_app/tui/definition_sheet.py
examples: (EX-8B-K1) ENUM_0001 at start, width `107` → `"└ TAB_VERB 4 pairs · UBYTE u8 big-endian · 0x00800000 · 1 B"`, then `E.card.ENUM_0001.line0` … `line3`
examples: (EX-8B-K1) ENUM_0001 after choosing RUN → card row `"( ) 0 OFF   ( ) 1 IDLE   (●) 2 RUN   ( ) 3 FAULT   default \"UNKNOWN_STATE\""`

_detail_mask
req: R-PE-DEF.34, R-PE-DEF.108
in: SheetRow row; Preview? preview; int width; object state; int room
out: list[Text] lines
func: the definition line, then card_lines(`<name> · bit editor · other bits kept`, bit_table(row, preview), max(GRID_WIDTH − 4, width))
module: s19_app/tui/definition_sheet.py
examples: (EX-8B-K1) MASK_FIELD_0001 pending `255`, width `107` → `"└ IDENTICAL phys = (word & 0x0FF0) >> 4 · UWORD u16 big-endian · 0x00800010 · 2 B"`, then 6 card lines, `73` cells each

_detail_text
req: R-PE-DEF.35, R-PE-DEF.108
in: SheetRow row; Preview? preview; int width; object state; int room
out: list[Text] lines
func: the definition line, then card_lines(`<name> · text editor · 16 B per row`, hex_grid(row, preview), max(GRID_WIDTH − 4, width))
module: s19_app/tui/definition_sheet.py
examples: (EX-8B-K1) V171 ASCII, width `107` → `"└ text · 0x00810200 · 42 B"`, then `T.card.V171.line0` (`78` cells) and 4 hex rows

_verdict
req: R-PE-DEF.101
in: Preview preview
out: Text verdict
func: `▲ <notice>` in YELLOW #f6ff8f, else `✓ in limits` in GREEN #54efae (base: rich `yellow` / `green`)
module: s19_app/tui/definition_sheet.py
examples: (EX-8B-S5) DISPLAY_0001 `25.5` → `"✓ in limits"` in `#54efae`; `175` → `"▲ DISPLAY_0001: 175 is outside the limits -40..150 and inside the extended limits -50..200"` in `#f6ff8f`

_scalar_tail
req: R-PE-DEF.97
in: SheetRow row; Preview preview; int width
out: Text tail
func: as Inc 8, with `raw` dim, the after bytes of `<before> → <after>` in the pending style (no underline), the verdict from _verdict, and `enter stage ↓` bold DEPTH_BG on HILITE
module: s19_app/tui/definition_sheet.py
examples: (EX-8B-S1) DISPLAY_0001 `25.5` → `"deg C  (-40 … 150)  raw 287→51 · 01 1F → 00 33  ✓ in limits  enter stage ↓"`, `00 33` in `bold #b565f3`, `enter stage ↓` in `bold #0a0e1b on #91abec`

formula_tail
req: R-PE-DEF.101
in: SheetRow row; Preview? preview; int width
out: Text tail
func: as Inc 8; a Refusal's `✗ <message>` in RED #fd8383 (base: rich `red`)
module: s19_app/tui/definition_sheet.py
examples: (EX-8B-S4) DISPLAY_0001 `250` → `"✗ DISPLAY_0001: 250 is outside the extended limits -50..200"` in `#fd8383`

StagingSheet.compose
req: R-PE-DEF.92, R-PE-DEF.93, R-PE-DEF.95, R-PE-DEF.81, R-PE-DEF.33
in: (none)
out: ComposeResult widgets
func: the body inside a horizontal grid scroller `#patch_sheet_grid`, a plain `textual.containers.Container` (E3R1: `can_focus` False, no BINDINGS — never `ScrollableContainer`, which is focusable and binds left, right, home, end, pageup, pagedown); CSS `StagingSheet > #patch_sheet_grid { height: 1fr; overflow-x: auto; overflow-y: hidden; scrollbar-size-horizontal: 1; }` and `#patch_sheet_grid > #patch_sheet_body { height: 1fr; width: auto; }` (E3R1: the body fills the scroller less its scrollbar row; width auto = the painted 143 or V); the formula bar row after the scroller, outside it
module: s19_app/tui/screens_directionb/patch_editor/sheet.py
examples: (EX-8B-G3) 118×54 → `#patch_sheet_grid` shows a horizontal scrollbar, virtual width `143`; 80×24 → shown; 220×60 → not shown
examples: (EX-8B-G5) 80×24 → `#patch_sheet_bar` region width ≤ the sheet window's content width (`#patch_sheet_bar` is not a descendant of `#patch_sheet_grid`)
examples: (EX-8B-W1) test host at 118×54 (no chrome) → `#patch_sheet_grid` height `53`, `#patch_sheet_body` height `52` (`W.harness_118x54.*`); without the body rule the body is as tall as its own text
examples: (EX-8B-G6) 118×54, ENUM_0001 selected, body focused, `right` → `StagingSheet.action_choose(1)` runs (`(●) 2 RUN`), the scroller's x stays `0`; Tab through the Patch Editor → the same stops as the base, `#patch_sheet_grid` never `App.focused`

StagingSheet.action_scroll_grid
req: R-PE-DEF.94
in: str where
out: None
func: `home` → the scroller's x = 0; `end` → x = max(0, GRID_WIDTH − V); through `scroll_to(x=…, animate=False, immediate=True)` (E3R1; `immediate=True` added at E4 by C8b-W and recorded by I8b, DF-04 b: without it the scroll lands on the next refresh, so x read right after End is still 0, R-PE-DEF.94/6); bound to `home` and `end` in `StagingSheet.BINDINGS` (the formula input keeps its own home/end) [V8b-1, V8b-2]
module: s19_app/tui/screens_directionb/patch_editor/sheet.py
examples: (EX-8B-G4) 118×54, body focused, where `"end"` → scroll x `33`; then `"home"` → `0` (E4: V measured 110; E1 wrote 32 at V 111)
examples: (EX-8B-G4) 80×24, `"end"` → `73` (V 70); 220×60, `"end"` → `0`
examples: (EX-8B-G6) 118×54, `"end"` → x read right after the call, with no pause, is `32` (an animated scroll reads less)

StagingSheet._view_width
req: R-PE-DEF.107, R-PE-BENCH.5
in: (none)
out: int width
func: the grid scroller's visible content width; 111 before the first layout (the 118-column fallback minus the chrome)
module: s19_app/tui/screens_directionb/patch_editor/sheet.py
examples: (EX-8B-E2) 118×54 → `111`; 220×60 → `195`; before mount → `111`

StagingSheet._detail_geometry
req: R-PE-DEF.81, R-PE-DEF.107, R-PE-BENCH.5, R-PE-BENCH.36
in: (none)
out: tuple(int width, int room)
func: (E3R1) the width and room the selected row's detail is laid out for: (_view_width() − 4, visible − 1) with visible = the body height − 2 (fallback height 20); the one source for `_paint`, `_fit_window` and `ArrayBenchSheet._bench_geometry`, so the three never drift apart
module: s19_app/tui/screens_directionb/patch_editor/sheet.py
examples: (EX-8B-W2) _view_width `111`, body height `20` → `(107, 17)`; `73`, `8` → `(69, 5)`; `195`, `20` → `(191, 17)`

StagingSheet._paint
req: R-PE-DEF.81, R-PE-DEF.91, R-PE-DEF.107
in: (none)
out: None
func: as Inc 8, with header_line and header_rule as the first two lines, visible = body height − 2, row_line(…, odd = position % 2), detail_lines with the room of _detail_geometry() and width = _view_width() (detail_lines lays the kind out for width − 4, which is _detail_geometry()'s width); the body text is the grid (143 cells, or V when wider)
module: s19_app/tui/screens_directionb/patch_editor/sheet.py
examples: (EX-8B-W1) 118×54, 200 names, 40 × down → the selected row's line and its expanded object inside `#patch_sheet_body`'s content region
examples: (EX-8B-W1) a stand-in kind with 10 detail lines, body height `8` → visible `6`, the selected row painted and `5` expanded lines

StagingSheet._fit_window
req: R-PE-DEF.81
in: (none)
out: None
func: as Inc 8 with visible = body height − 2 and the detail measured with the room of _detail_geometry() for _view_width()
module: s19_app/tui/screens_directionb/patch_editor/sheet.py
examples: (EX-8B-W1) body height `8` (visible `6`), selected row `10`, top `0`, 3 detail lines → top `8` (selected + need − visible = 10 + 4 − 6)

ArrayBenchSheet._bench_geometry
req: R-PE-BENCH.36
in: BenchState state; Grid grid
out: tuple(int rows_shown, int cols_shown)
func: (E3R1, E3-8b-02) `canvas_shape(width, grid, state.origin, room)` with (width, room) = `self._detail_geometry()`, the same width and room `bench_detail` gets through `detail_lines`; replaces the base's own geometry (the body's width, visible = height − 1); callers `_reveal` and `action_page` unchanged
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
examples: (EX-8B-W2) V `111`, body height `20` → canvas_shape over `(107, 17)` (base: `(143, 18)`, one row and 36 columns more than are painted)
examples: (EX-8B-W2) LARGE at 80×24 (V `73`) and at 118×54 (V `111`), cursor moved right past the last painted canvas column → `window_for` moves the window's first column by `1` and the cursor's cell is painted (base: the cursor lands in a column that is not painted)

_SheetBody.on_resize
req: R-PE-DEF.81
in: events.Resize event
out: None
func: repaint the StagingSheet found among the body's ancestors (the grid scroller is the body's parent now) (D-7)
module: s19_app/tui/screens_directionb/patch_editor/sheet.py
examples: (EX-8B-W1) a resize from 118×54 to 80×24 → `_paint` runs once on the sheet (base: `self.parent` is the scroller, no repaint)

StagingSheet.on_resize
req: R-PE-DEF.81
in: events.Resize event
out: None
func: repaint the sheet (`_paint`) on the sheet's own resize. Recorded at E4 (C8b-W's deviation, DF-04 b): a resize that changes only the terminal's width leaves the body at 143 × h (its width is `auto`), so the body gets no Resize and `_SheetBody.on_resize` never runs (E3-8b-11's premise corrected); the sheet's own width does change
module: s19_app/tui/screens_directionb/patch_editor/sheet.py
examples: (EX-8B-W1) MAP_DEF_0001 expanded at 118×54, the terminal widened to 220×54 → the bench lines are re-laid out for V `194` (R-PE-DEF.81/6)

_definition_line
req: R-PE-DEF.31, R-PE-DEF.97, R-PE-DEF.107
in: SheetRow row
out: Text line
func: `└ ` in the rule style (HILITE), then the definition text in the dim style; the plain text unchanged from Inc 8. Recorded at E4 (C8b-S's restyle outside the graph, DF-04 b): the sheet-styles table names `└` under rule and "the definition line after `└`" under dim
module: s19_app/tui/definition_sheet.py
examples: (EX-8B-S1) DISPLAY_0001 → `└` in `#91abec`, `LINEAR phys = 0.5*raw · …` in `#969aad`

A2LParameterPicker.compose
req: R-PE-DEF.113
in: (none)
out: ComposeResult widgets
func: as today, with the compact Include parameter label `▽ Pick` (the Check Editor's `Include parameter` unchanged) [V8b-9]
module: s19_app/tui/a2l_parameter_picker.py
examples: (EX-8B-P1) Patch Editor (compact) → `#patch_param_include_button` label `"▽ Pick"`; Check Editor → `"Include parameter"`

WINDOW_HELP_SECTIONS
req: R-PE-DEF.85
in: (none)
out: tuple sections
func: the Patch Editor section's STAGING SHEET line gains "home end scroll the grid to its first and last columns"
module: s19_app/tui/window_help.py
examples: (EX-8B-P2) the parsed `STAGING SHEET` effect → holds `"↑↓"`, `"enter"`, `"←→"`, `"home"`, `"end"`, `"esc"`

summary_strip
req: R-PE-BENCH.11, R-PE-BENCH.107, R-PE-BENCH.108
in: BenchValues values; Grid grid; int width
out: Text strip
func: chart: one block per k-th point at level 1 + round(t × 6) of `▁▂▃▄▅▆▇`; grid: one block per k-th column at the level of its finite mean; a point or column with no finite value → space; all in DGRAY, no background (base: `█` with `ramp_style`, eight levels) [V8b-6]
module: s19_app/tui/definition_bench.py
examples: (EX-8B-F1) CURVE_DEF_0001 values `37818 52215 28375 58106 11719`, width `17` → `"▄▆▃▇▁"` (base `"▅▇▄█▁"`), every span `#969aad`, bgcolor None
examples: (EX-8B-F1) MAP_DEF_0001 (4 × 3, lo `-890`, hi `843`), width `16` → `"▆▃▅▃"` (base: 4 × `█` with ramp steps `10 3 8 4`); VAL_BLK_DEF_0001 (3 × 2), width `17` → `"▄▃▄"`
examples: (EX-8B-F2) 40 rising points, width `17` → `"▁▁▂▂▃▃▄▄▅▅▆▆▇▇"`; 3 equal points → `"▁▁▁"`; no `█` in any

bench_cells
req: R-PE-BENCH.17, R-PE-BENCH.11, R-PE-DEF.104
in: SheetRow row; BenchState? state; SheetWidths widths
out: tuple(Text kind, Text current, Text new, Text limits, Text delta)
func: as Inc 9, with Limits = range_cell(lower, upper) (the range form, or the no-limits form)
module: s19_app/tui/definition_bench.py
examples: (EX-8B-L5) CURVE_DEF_0001 → limits `"     0          …            65.5k"`; MAP_DEF_0001 → `" -1.00k         …            1.00k"`; an array without limits → `-` at `16`
examples: (EX-8B-F1) CURVE_DEF_0001 summarised → current `"▄▆▃▇▁ 5"`

## Entities

[Interface: #patch_sheet_grid]
desc: the horizontal grid scroller inside StagingSheet: a plain textual.containers.Container (E3R1, E3-8b-03: not focusable, no BINDINGS, so it holds no Tab stop and takes no key from the focused body); CSS height 1fr, overflow-x auto, overflow-y hidden, scrollbar-size-horizontal 1; holds #patch_sheet_body (height 1fr, width auto); its scroll_x is the grid's view position (0 … max(0, GRID_WIDTH − V)), set only by action_scroll_grid (animate False) and the scrollbar's mouse use

[Data: StagingSheet.BINDINGS]
desc: Inc 8's up, down, enter, left, right, plus `home` → scroll_grid("home") and `end` → scroll_grid("end"), shown False. Key owners (E3R1): ← and → are StagingSheet's (action_choose on an enum row), Home and End are StagingSheet's (action_scroll_grid); the formula input keeps its own ← → Home End while it has the focus; #patch_sheet_grid binds none

[Data: StagingSheet.DEFAULT_CSS]
desc: (E3R1, E3-8b-05) `StagingSheet > #patch_sheet_grid { height: 1fr; overflow-x: auto; overflow-y: hidden; scrollbar-size-horizontal: 1; }`, `#patch_sheet_grid > #patch_sheet_body { height: 1fr; width: auto; }` (replaces `StagingSheet > #patch_sheet_body { height: 1fr; }`, which no longer matches a grandchild); `StagingSheet > #patch_sheet_bar { height: 1; }` and the bar's rules unchanged

[Data: insight_style.MAGENTA comment]
desc: lines 75-84 restate the verdict-hue rule of CTX-PE-DEF: inside #patch_editor_panel GREEN, YELLOW and RED are state hues that ride their glyph (✓ or ● GREEN, ▲ YELLOW, ✗ RED), painted only on a line that carries the glyph; a cue that is not a state (the gauge, a JSON token) never takes them. Comment only; group B.

[Data: tests/test_tui_patch_json.py _EXCLUDED_LITERALS]
desc: + "#1c2547": staging-sheet selected-row ground (definition_sheet.py), a background fill (val 27.8%), not a foreground cue. No _CLAIMED_HUES entry (no new foreground hue). Test-side; group B's tester.

## Edges

[Outside: key home] ──▶ StagingSheet.action_scroll_grid
when: App.focused is #patch_sheet_body (the formula input handles home itself)
[Outside: key end] ──▶ StagingSheet.action_scroll_grid
when: App.focused is #patch_sheet_body
[Outside: key left] ──▶ StagingSheet.action_choose
when: App.focused is #patch_sheet_body and the selected row is an enum (#patch_sheet_grid binds no key; E3R1)
[Outside: key right] ──▶ StagingSheet.action_choose
when: App.focused is #patch_sheet_body and the selected row is an enum (#patch_sheet_grid binds no key; E3R1)
StagingSheet.action_scroll_grid ──▶ [Interface: #patch_sheet_grid].scroll_x
StagingSheet._paint ──▶ [Interface: #patch_sheet_grid]
[Interface: #patch_sheet_grid] ──▶ StagingSheet._view_width
[Interface: #patch_sheet_grid] ──▶ StagingSheet._detail_geometry
StagingSheet._detail_geometry ──▶ ArrayBenchSheet._bench_geometry

## Findings

finding F-1 The summary strip paints white or near-black bars that join across rows (F-R14-1)
anchor: summary_strip
seen: the base capture probe: MAP cells (16,24,40) or (255,255,255), never the ramp ground; chart cells (233,233,233); joined cells across the three array rows [1, 3] and [1]
cause: `█` with ramp_style shows its foreground (the bench canvas's text colours) over the whole cell; full-height blocks touch the row above and below in Windows Terminal; the chart strip has no style
effect: tall white bars over the Current column of curve, map and value-block rows
decision: seven levels, column-mean levels for grids, DGRAY, no ground (R-PE-BENCH.107, .108, renumbered at E3R1 from .94, .95; R-PE-BENCH.11's examples change)

finding F-2 B's hex grid moves the ASCII guide on a short last row
anchor: hex_grid
seen: `B.off.text.118x54.png` row `+20` of a 42-byte span: the `│` before ASCII right after the 10th byte
cause: the prototype appended the guide after the last byte written (`proto8_app.py:300-303`)
effect: the ASCII column of the last row starts 21 cells left of the others: the misalignment the operator objects to on D
decision: three spaces per missing byte; the guide at a full row's column (R-PE-DEF.110)

finding F-3 A limit that is not finite raises in the track
anchor: limits_cell
seen: `_track_index` computes `round(pos × (track − 3))`; pos is nan when a bound is infinite or nan
cause: no finiteness check before the position (`definition_sheet.py:717-735`)
effect: `ValueError` while painting the sheet, if the A2L reader yields ±inf or nan for a limit (pilot at E4)
decision: the range form for any bound that is not finite; no position computed (R-PE-DEF.106)

finding F-4 The sheet body's resize no longer reaches the sheet
anchor: _SheetBody.on_resize
seen: `on_resize` repaints `self.parent` only when it is a StagingSheet (`sheet.py:49-52`)
cause: the grid scroller becomes the body's parent
effect: no repaint on a terminal resize; the prototype hit it (`proto8_app.py:720-723`)
decision: find the StagingSheet among the ancestors (D-7)

finding F-5 The sheet paints rich named colours the hue census cannot see
anchor: _verdict
seen: `_OK, _WARN, _BAD = "green", "yellow", "red"` (`definition_sheet.py:32`); rich `yellow` is in neither `_CLAIMED_HUES` nor `_EXCLUDED_LITERALS`
cause: named styles are invisible to the hex sweep (`test_tui_patch_json.py:1048-1053`, the stated gap)
effect: a verdict-like hue inside the Patch Editor outside the census
decision: the palette hexes GREEN, YELLOW, RED (claimed) replace the named colours in the sheet (R-PE-DEF.101/4)

finding F-6 A focusable scroller would take ← → Home End from the sheet (E3-8b-03)
anchor: StagingSheet.compose
seen: Textual 8.2.8 `ScrollableContainer` is `can_focus=True` and binds left, right, home, end, pageup, pagedown (`textual/containers.py:32`, `:48-59`, read at E3); the prototype used it (`proto8_app.py:689`, `:700`)
cause: the scroller sits between the focused body and StagingSheet in the binding chain, so its bindings win while horizontal scroll is allowed (V < G)
effect: → scrolls the grid instead of choosing an enum entry at 80 and 118 columns; Home and End animate; one more Tab stop
decision: a plain `Container`, no focus, no bindings; `scroll_to(x=…, animate=False)` (R-PE-DEF.33/3, .92/3, .94/6)

finding F-7 The bench repeats the detail geometry and drifts from the painted detail (E3-8b-02)
anchor: ArrayBenchSheet._bench_geometry
seen: `bench_sheet.py:305-312` uses the body's width and visible = height − 1
cause: after Inc 8b the detail is laid out for V − 4 with room = body − 3, and the body is `width: auto` (143 or V)
effect: `window_for` keeps the cursor in a column or row that is not painted (R-PE-BENCH.36 broken at 80 and 118)
decision: `StagingSheet._detail_geometry()` is the one source for `_paint`, `_fit_window` and `_bench_geometry`

finding F-8 A value or position that is not finite raises in the track (E3-8b-04)
anchor: limits_cell
seen: E3 run of the copied formula: FLOAT32 `FF FF FF FF` current (NaN) → `ValueError`; limits ±1.7e308 with value 1e308 → `ValueError`
cause: no finiteness check on the value or on pos before `round` (`definition_sheet.py:717-724`); a FLOAT32 decode keeps NaN
effect: the sheet's paint raises on a row read from erased flash
decision: the no-position form for a current or new value, or a pos, that is not finite (R-PE-DEF.114; the ruling fixes one form, `?` at offset 16)
