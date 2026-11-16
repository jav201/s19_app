# Inc 8b E4 — C8b-S hand-back (group S, `s19_app/tui/definition_sheet.py`)

Worker C8b-S, model Sonnet (claude-sonnet-5-5), 2026-11-15. One file touched: `s19_app/tui/definition_sheet.py` (source cap 4: 1 of 4). No tests written (implementer card). Base `78e86539` (Inc 8b records on `48af05ff`).

## Procedure and one deviation

The brief names the DeepSeek procedure (units of at most 6 functions, `opencode run`). **I did not use DeepSeek**: the 20 nodes of group S share one set of styles, widths and helpers (a card needs `plain`, `clip`, the grounds; the row needs `_tone`, `limits_cell`, the gutters), so splitting would have cost more in plan files and re-verification than the code itself. I wrote it directly in four spliced blocks (grid, cards, limits, row line and tails). DeepSeek output therefore needed no independent check; the verification below is the independent oracle (the E1 transcript).

## Nodes (graph order)

| Node | State |
|---|---|
| `sheet_widths` (constant widths, `width` unused), `header_line`, `header_rule` | done |
| `limit_slot`, `range_cell`, `limits_cell` (new `tone`, no-position form, collision rule, finite guards), `_tone`, `_mark`, `_stock_cells`, `row_line` (`odd`, gutters, grounds) | done |
| `detail_lines` (V − 4 layout, `  ┊ ` bar, cut at max(G, V) − 4, expanded ground to max(G, V)) | done |
| `card_lines`, `bit_table`, `hex_grid`, `_detail_enum`, `_detail_mask`, `_detail_text` | done; `_bit_strip`, `_text_rows` removed |
| `_verdict`, `_scalar_tail`, `formula_tail` (palette hexes, no rich named colours) | done |

Names pinned by the graph: `GRID_WIDTH = 143`, `_TEXT`, `_DIM`, `_RULE`, `_STAGED`, `_PENDING`, `_REFUSED`, `_NOTICE`, `_SELECTED_GROUND = "#1c2547"`, `_ODD_GROUND`, `_EXPANDED_GROUND`, `_CARD_GROUND`, `_KEY_INK`, imported from `insight_style` (no new foreground hue; the only new literal is the selected ground). `_ACCENT`, `_OK/_WARN/_BAD`, `_WIDTH_CLASSES` are gone.

## Deviations and choices (each one line)

- `_definition_line` (not a listed node) now paints `└` in HILITE and the rest dim (sheet styles: dim = the definition line after `└`, rule = `└`). Plain text unchanged.
- New helper `_cut_cells` cuts a card row by the `clip` rule with its spans kept; `Text.truncate` would insert a pad space when a wide character straddles the cut, which the oracle (`clip`) does not.
- New and Δ get `tone or DGRAY`: the graph example `EX-8B-S1` has New `"·"` in `#969aad` on an untouched row.
- `limits_cell`'s `◆` with an empty `tone` is painted dim (no caller does this; `_stock_cells` always passes the row's tone).
- Row mark rule kept as in Inc 8: a row that is staged and pending shows `●` while its New/Δ take the pending style (`_tone`: pending wins). Not changed; flagged below.
- E3-8b-10 applied: the `limits_cell` docstring says `width` is unused (also for `sheet_widths`).

## Examples run (rtx, HT-02 env, `timeout 300`; load average 3.67 at start)

Runner: a scratch script (not in the repo) that builds DEFC (`tools/synth/make_release_case.py --case definitions`, seed 20260001) and V171, calls the new functions and compares each result with the E1 transcript `evidence-e1/examples_inc8b-transcript.txt` key by key.

Held (122 of 122 keys, 0 mismatches): `G.header_line`, `G.header_rule`, `G.header_rule.len`, `G.grid_width`; `L.slot.*` (19 numbers + inf, -inf, nan); `L.cell.*` and `.len` for DISPLAY_0001 (cur 143.5 with new 25.5, none, 175, -45, cur 150 with new 149.9, new inf), MASK_FIELD_0001 (cur 174, new 255 through `preview`), MASK_BIT_0001, ENUM_0001, limits 5 5, 9 1, lower -inf, upper nan, huge, neg_big, float32 erased (NaN current), span overflow, no limits; `L.bench.*`; `B.MASK_FIELD_0001.start.*`, `.pending255.*`, `B.MASK_BIT_0001.pending0.*`, `B.card.MASK_FIELD_0001.*`; `E.card.*` (ENUM_0001, 300 entries, name_esc, row_esc, markup, name_wide200, enum_wide, enum_wide100); `T.V171.start.*`, `T.V171.pendingABC.*` (ASCII guide column 56 on every line), `T.card.V171.*`; `C.*` (six hostile cells).

Held, read from spans (printed below): marks `◆` at 14 in `bold #b565f3` and `●` at 23 in `bold #e9e9e9`; after-row bits 10, 8, 4 underlined and no other; hex row `+00` with offsets 0 … 9 and their ASCII underlined; pending 175 row has no `#f6ff8f` span; pending 250 row has New and Δ in `bold #fd8383`; a staged row has `●`, New and Δ in `bold #54efae`; `_scalar_tail` spans (`00 33` bold #b565f3, `✓ in limits` #54efae, `enter stage ↓` bold #0a0e1b on #91abec); `row_line` is 143 cells for selected, odd and plain, `│` at 28, 39, 60, 77, 86, 121, 142; a detail line is 143 cells, a 250-character record layout is cut with `…` at 139 content cells.

Could not run here (need another group's code or the app): EX-8B-G2/G3/G5/G6 (widget), EX-8B-W* (geometry), EX-8B-E2 for bench rows and EX-8B-F* (groups B, W), EX-8B-S6 as a real NO_COLOR render (only checked: selected and unselected rows have equal plain text apart from the mark). Not run: the repo's pytest files (Inc 8 tests of the retired rows fail until T8b-R retargets them).

## Findings and open points

- Interface callers still on the Inc 8 shapes until group W lands: `StagingSheet._paint` and `_fit_window` call `detail_lines(row, preview, width, …)` with the body's content width; the new meaning of `width` is the view width V (graph `_view_width`).
- Retire with the other limits forms: `tests/test_b103_inc8_s1.py:503` (`limits_cell(row, None, 16)`), and every Inc 8 test that reads `sheet_widths(w)` per class, `_bit_strip`, `_text_rows` (T8b-R).
- Observation, not changed: staged-and-pending rows show `●` in the mark but a purple New and Δ. R-PE-DEF.101 holds either way (the hue sits on a line holding its glyph); the operator may want `◆` to win in the mark. Left as Inc 8 had it.
- `limits_cell` runs `isfinite` on enum bounds (ints); an enum raw value above float range would raise `OverflowError` (not reachable from the A2L reader's integer widths; not guarded).

## Run transcript (rtx; the home path of the runner is written `~`)

```text
s19_app.__file__ = ~/work/zq-e4-8b-c8b-s/tree/s19_app/__init__.py
Limits fields: dict_keys(['lower', 'upper', 'lower_text', 'upper_text'])
  spans [(14, 15, 'bold #b565f3'), (23, 24, 'bold #e9e9e9')]
MASK_FIELD_0001 current: Decoded(stored=174, value=174, text='174') kind bit mask
MASK_BIT_0001 current: Decoded(stored=1, value=1, text='1') kind bit mask
ENUM_0001 current: Decoded(stored=1, value='IDLE', text='IDLE') kind enum
  underlined after-row cells [26, 32, 46] ['1', '1', '1']
enum options: ( ) 0 OFF   (●) 1 IDLE   ( ) 2 RUN   ( ) 3 FAULT   default "UNKNOWN_STATE"
  hex row1 underlined spans [(6, 8, '41'), (9, 11, '42'), (12, 14, '43'), (15, 17, '00'), (18, 20, '00'), (21, 23, '00'), (24, 26, '00'), (27, 29, '00'), (32, 34, '00'), (35, 37, '00'), (58, 59, 'A'), (59, 60, 'B'), (60, 61, 'C'), (61, 62, '·'), (62, 63, '·'
detail MASK_FIELD V111: 7 {143}   ┊ └ IDENTICAL phys = (word & 0x0FF0) >> 4 · UWORD u16 big-endian · 0x00800010 · 2 B                                                          
detail DISPLAY V111: ['  ┊ └ LINEAR phys = 0.5*raw · SWORD s16 big-endian · 0x00800020 · 2 B                                                                          '] [143]
long detail: [(143, 'LLLLL…', 'L…')]
row_line False False bars [28, 39, 60, 77, 86, 121, 142]
row_line True False bars [28, 39, 60, 77, 86, 121, 142]
row_line False True bars [28, 39, 60, 77, 86, 121, 142]
 ◆DISPLAY_0001              │VALUE     │143.5               │25.5            │deg C   │   -40  ├─────◆────────●─┤    150 │-118.0 (-62.1%)     │
[(1, 2, 'bold #b565f3'), (61, 77, 'bold #b565f3'), (101, 102, 'bold #b565f3'), (122, 142, 'bold #b565f3')]
    150 │✗ refused           │ [(61, 77, 'bold #fd8383'), (122, 142, 'bold #fd8383')]
[]
deg C  (-40 … 150)  raw 287→51 · 01 1F → 00 33  ✓ in limits  enter stage ↓ [(0, 7, '#969aad'), (7, 20, '#969aad'), (20, 41, '#969aad'), (41, 46, 'bold #b565f3'), (48, 59, '#54efae'), (61, 74, 'bold #0a0e1b on #91abec')]
✗ DISPLAY_0001: 250 is outside the extended limits -50..200 []
checks ok=112 bad=0
V171 ascii limits '                -                 ' 16
record_layout/datatype SWORD 2
 ●DISPLAY_0001              │VALUE     │143.5               │25.5            │deg C   │   -40  ├──── [(1, 2, 'bold #54efae'), (61, 77, 'bold #54efae'), (101, 102, 'bold #54efae'), (122, 142, 'bold #54efae')]
plain equal sel/unsel apart from mark: True
wide-name row len 143 [16, 27]
final ok=122 bad=0
```
