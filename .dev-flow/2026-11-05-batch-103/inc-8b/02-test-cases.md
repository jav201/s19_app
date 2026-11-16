# Inc 8b — test cases (E1)

One row per alternative of a requirement (`roles/tester.md` format: `<requirement id>/<n> | example id | test name | full or partial`), plus the objective and the class (N normal, R robustness: hostile input, a boundary or a failure path). The **test name** and the **full / partial** columns are the E4 tester's; they stay empty at E1. Every expected value is a key of `evidence-e1/examples_inc8b-transcript.txt` or an `EX-8B-*` example of `codewire/graph-inc8b.md`; a test loads the key or recomputes it and never retypes a position or a width (tester rule 2). The withdrawn rows R-PE-DEF.6 and .7 have no case; their Inc 8 tests are retired or re-aimed at E4 (`E1-slice.md` §4).

| Case | Example | Objective — verify that … (expected) | Class | Test name (E4) | full / partial (E4) |
|---|---|---|---|---|---|
| R-PE-DEF.5/1 | EX-8B-G1 | V = 111: body line 1 = `G.header_line` | N | | |
| R-PE-DEF.5/2 | EX-8B-G1 | V = 73: the same line (Kind and Unit shown, no width class) | R | | |
| R-PE-DEF.5/3 | EX-8B-G1 | V = 195: the same line (the grid does not stretch) | N | | |
| R-PE-DEF.89/1 | EX-8B-G2 | V = 111, DEFC page: every row's cells start at `G.start.*`; each row line 143 cells | N | | |
| R-PE-DEF.89/2 | EX-8B-G2 | V = 73: the same starts (Kind at 29, Current at 40) | R | | |
| R-PE-DEF.89/3 | EX-8B-G2 | V = 195: the same starts, line 143 cells (no stretch to 195) | N | | |
| R-PE-DEF.90/1 | EX-8B-G2 | V = 111: `│` at 28, 39, 60, 77, 86, 121, 142 on every DEFC row | N | | |
| R-PE-DEF.90/2 | EX-8B-C1 | a row named with 40 characters: `│` still at 28 | R | | |
| R-PE-DEF.91/1 | EX-8B-G1 | body line 2 = `G.header_rule` (143 cells) | N | | |
| R-PE-DEF.92/1 | EX-8B-G3 | 118×54: the grid scroller's horizontal scrollbar shown, virtual width 143 | N | | |
| R-PE-DEF.92/2 | EX-8B-G3 | 80×24: the same | R | | |
| R-PE-DEF.92/3 | EX-8B-G6 | 118×54, scrollbar shown: the Patch Editor's Tab order equals the base's; `#patch_sheet_grid` never holds the focus | R | | |
| R-PE-DEF.93/1 | EX-8B-G3 | 220×60: no horizontal scrollbar; the body takes its row | N | | |
| R-PE-DEF.94/1 | EX-8B-G4 | 118×54, body focused: End → scroll x 33 (V = 110, E4-measured) | N | | |
| R-PE-DEF.94/2 | EX-8B-G4 | then Home → x 0 | N | | |
| R-PE-DEF.94/3 | EX-8B-G4 | 80×24: End → x 73 (V = 70) | R | | |
| R-PE-DEF.94/4 | EX-8B-G4 | 220×60: End → x 0 (no scroll range) | R | | |
| R-PE-DEF.94/5 | EX-8B-G4 | formula input focused: End moves the input's cursor, x unchanged | R | | |
| R-PE-DEF.94/6 | EX-8B-G6 | 118×54, body focused: x read right after End, with no wait or pause, is 33 (no animation) | R | | |
| R-PE-DEF.95/1 | EX-8B-G5 | 80×24: the formula bar's region width ≤ the sheet window's content width | R | | |
| R-PE-DEF.95/2 | EX-8B-G5 | 118×54: the same | N | | |
| R-PE-DEF.95/3 | EX-8B-G5 | 220×60: the same; the `x`×300 refusal tail ends in `…` | R | | |
| R-PE-DEF.96/1 | EX-8B-C1 | name `温度`×14 → `C.name_wide.fit26` (25 cells + `…` … 26 with the pad) | R | | |
| R-PE-DEF.96/2 | EX-8B-C1 | unit `温度温度温度` → `C.unit_wide.fit8` | R | | |
| R-PE-DEF.96/3 | EX-8B-C1 | enum entry text 300 × `X` → Current `C.enum_long.current20` | R | | |
| R-PE-DEF.96/4 | EX-8B-C1 | a 10,000-character name → `C.name_10000.fit26`; `plain` sees ≤ 120 characters (spy) | R | | |
| R-PE-DEF.96/5 | EX-8B-C1 | a unit of 40 characters → `C.unit_40.fit8`; the Limits column starts at 87 | R | | |
| R-PE-DEF.96/6 | EX-8B-C1 | boundary: a name `A\x1b[2JB` (6 cells, not wider) → `C.name_esc.fit26`: cleaned, no `…`, padded to 26 | R | | |
| R-PE-DEF.81/1 | EX-8B-W1 | 118×54, 200 names: 40 × down → the selected row and its expanded object inside the body | N | | |
| R-PE-DEF.81/2 | EX-8B-W1 | then up past the first painted row → the selected row is the first painted row | N | | |
| R-PE-DEF.81/3 | EX-8B-W1 | an enum row on the window's last line → its definition line and card inside the body | N | | |
| R-PE-DEF.81/4 | EX-8B-W1 | stand-in kind with 10 detail lines, body 8 → row painted, 5 lines (`W.standin_10_detail.h8.painted`) | R | | |
| R-PE-DEF.81/5 | EX-8B-W1 | the test host at 118×54 (no chrome): `#patch_sheet_grid` 53 rows, `#patch_sheet_body` 52, visible 50 (`W.harness_118x54.*`) | N | | |
| R-PE-DEF.97/1 | EX-8B-S1 | text: names and current values #e9e9e9; the selected name bold | N | | |
| R-PE-DEF.97/2 | EX-8B-S1 | dim: kind, unit, `·`, Limits text, definition line after `└` #969aad | N | | |
| R-PE-DEF.97/3 | EX-8B-S1 | header: labels bold #969aad | N | | |
| R-PE-DEF.97/4 | EX-8B-S1 | rule: `━`, `┿`, gutters, guides, frame, `┊`, `└` #91abec | N | | |
| R-PE-DEF.97/5 | EX-8B-S1 | selected: ground #1c2547 over the selected row; `▶` bold #91abec | N | | |
| R-PE-DEF.97/6 | EX-8B-S1 | zebra: ground #131a2c on odd page positions, none on even | N | | |
| R-PE-DEF.97/7 | EX-8B-S1 | current marker: the track's `●` bold #e9e9e9 | N | | |
| R-PE-DEF.97/8 | EX-8B-S1 | after bytes: `00 33` (`S.after_bytes.DISPLAY_0001.25.5`, DISPLAY_0001 pending 25.5; E4 corrected the hand-typed `1F F6`) of the tail in bold #b565f3, not underlined | N | | |
| R-PE-DEF.97/9 | EX-8B-S1 | key hint: `enter stage ↓` bold #0a0e1b on #91abec | N | | |
| R-PE-DEF.97/10 | EX-8B-S1 | mask mark: `■` bold #91abec | N | | |
| R-PE-DEF.97/11 | EX-8B-S1 | expanded ground: #1b233a on every expanded line | N | | |
| R-PE-DEF.97/12 | EX-8B-S1 | card ground: #0f1525 inside the frame | N | | |
| R-PE-DEF.98/1 | EX-8B-S2 | DISPLAY_0001 staged 25.5: New, Δ, `●`, the track's `◆` bold #54efae | N | | |
| R-PE-DEF.98/2 | EX-8B-S2 | MASK_FIELD_0001 staged 255: the same | N | | |
| R-PE-DEF.98/3 | EX-8B-S2 | VAL_BLK_DEF_0001 staged, no bench edit: `●` and `max \|Δ\| … staged` | N | | |
| R-PE-DEF.99/1 | EX-8B-S3 | DISPLAY_0001 `25.5`: New, Δ, `◆` bold #b565f3 | N | | |
| R-PE-DEF.99/2 | EX-8B-S3 | DISPLAY_0001 `175` (notice): the pending style, not YELLOW | R | | |
| R-PE-DEF.99/3 | EX-8B-S3 | VAL_BLK_DEF_0001 with a bench edit: `◆`, New `2 cells` pending style | N | | |
| R-PE-DEF.100/1 | EX-8B-S4 | DISPLAY_0001 `250`: New `250`, Δ `✗ refused` bold #fd8383 | R | | |
| R-PE-DEF.101/1 | EX-8B-S5 | every #54efae span lies on a line holding `●` or `✓` | N | | |
| R-PE-DEF.101/2 | EX-8B-S5 | every #f6ff8f span lies on a line holding `▲` | R | | |
| R-PE-DEF.101/3 | EX-8B-S5 | every #fd8383 span lies on a line holding `✗` | R | | |
| R-PE-DEF.101/4 | EX-8B-S5 | no span is rich `green`, `yellow` or `red` | N | | |
| R-PE-DEF.102/1 | EX-8B-T2 | V171 `ABC`: offsets 0 … 9 and their ASCII characters underlined, no other | N | | |
| R-PE-DEF.102/2 | EX-8B-B1 | MASK_FIELD_0001 `255`: after-row bits 10, 8, 4 underlined, no other | N | | |
| R-PE-DEF.103/1 | EX-8B-S6 | `NO_COLOR=1` vs colour: equal plain texts with `●`, `◆`, `▶`, `✗ refused`, `■`; same underlines | R | | |
| R-PE-DEF.21/1 | EX-8B-L1 | DISPLAY_0001 pending 25.5 → `L.cell.DISPLAY_0001.cur143.5.new25.5` | N | | |
| R-PE-DEF.21/2 | EX-8B-L1 | MASK_FIELD_0001 pending 255 → `L.cell.MASK_FIELD_0001.cur174.new255` | N | | |
| R-PE-DEF.21/3 | EX-8B-L1 | ENUM_0001 → `L.cell.ENUM_0001.cur1` | N | | |
| R-PE-DEF.21/4 | EX-8B-L1 | preview 175 → `▶` at offset 25 (`L.cell.DISPLAY_0001.new175`) | R | | |
| R-PE-DEF.21/5 | EX-8B-L1 | preview −45 → `◀` at offset 8 (`L.cell.DISPLAY_0001.new-45`) | R | | |
| R-PE-DEF.104/1 | EX-8B-L2 | `├` 8, `┤` 25 on DISPLAY_0001, MASK_FIELD_0001, MASK_BIT_0001, ENUM_0001 | N | | |
| R-PE-DEF.104/2 | EX-8B-L2 | `├` 8, `┤` 25 on `neg_big` and `huge` | R | | |
| R-PE-DEF.104/3 | EX-8B-L2 | `…` 16 on limits 5 5, 9 1, lower −inf, upper nan | R | | |
| R-PE-DEF.104/4 | EX-8B-L2 | `…` 16 on CURVE, MAP, VAL_BLK (bench rows) | N | | |
| R-PE-DEF.104/5 | EX-8B-L2 | `-` 16 on V171 ASCII and a refused row | R | | |
| R-PE-DEF.104/6 | EX-8B-L2 | unit letters of `  65.5k`, ` -1.00k`, `  -655k` at offset 6 or 33 | N | | |
| R-PE-DEF.104/7 | EX-8B-L6 | DISPLAY_0001 current 150, value 149.9 (both on cell 16) → `L.cell.DISPLAY_0001.cur150.new149.9`: `◆` 23, `●` 24, `┤` 25 | R | | |
| R-PE-DEF.105/1 | EX-8B-L3 | 4.29e12 → `  4e12 ` | R | | |
| R-PE-DEF.105/2 | EX-8B-L3 | 999.6e9 → `  1e12 ` | R | | |
| R-PE-DEF.105/3 | EX-8B-L3 | −1.7e308 → `-2e308 ` | R | | |
| R-PE-DEF.105/4 | EX-8B-L3 | boundary 999.4e9 → `   999G` | R | | |
| R-PE-DEF.106/1 | EX-8B-L4 | LOWER_LIMIT −inf → `L.cell.lower_-inf`, no exception | R | | |
| R-PE-DEF.106/2 | EX-8B-L4 | UPPER_LIMIT nan → `L.cell.upper_nan`, no exception | R | | |
| R-PE-DEF.114/1 | EX-8B-L7 | DISPLAY_0001 copy, FLOAT32_IEEE, image `FF FF FF FF` (current NaN, `L.float32.FFFFFFFF`) → `L.cell.float32_erased`, `?` at 16, no `●`, no exception | R | | |
| R-PE-DEF.114/2 | EX-8B-L7 | withdrawn at E4: this input now has a position and is R-PE-DEF.117/1 | — | | |
| R-PE-DEF.114/3 | EX-8B-L7 | DISPLAY_0001 current 143.5, new +inf → `L.cell.DISPLAY_0001.new_inf` (no `▶`) | R | | |
| R-PE-DEF.76/1 | EX-8B-L4 | limits 5 5 → `L.cell.limits_5_5` | R | | |
| R-PE-DEF.76/2 | EX-8B-L4 | limits 9 1 → `L.cell.limits_9_1` | R | | |
| R-PE-BENCH.17/1 | EX-8B-L5 | CURVE_DEF_0001 → `L.bench.CURVE_DEF_0001` | N | | |
| R-PE-BENCH.17/2 | EX-8B-L5 | MAP_DEF_0001 → `L.bench.MAP_DEF_0001` | N | | |
| R-PE-BENCH.17/3 | EX-8B-L5 | an array without limits → `-` at offset 16 | R | | |
| R-PE-DEF.107/1 | EX-8B-E1 | DISPLAY_0001: one line `  ┊ └ LINEAR …`, ground #1b233a over cells 0 … 142 | N | | |
| R-PE-DEF.107/2 | EX-8B-E1 | MASK_FIELD_0001: every card line after the bar | N | | |
| R-PE-DEF.107/3 | EX-8B-E1 | MAP_DEF_0001 (bench): every bench line after `  ┊ ` | N | | |
| R-PE-DEF.107/4 | EX-8B-E1 | a 300-cell definition line → cut at 139 cells with `…` | R | | |
| R-PE-BENCH.5/1 | EX-8B-E2 | 80 columns, MAP_DEF_0001 and LARGE: each bench line rstripped ≤ 70 cells (V, E4-measured) | R | | |
| R-PE-BENCH.5/2 | EX-8B-E2 | 118 columns: ≤ 110 cells; the op line ≤ the sheet's content width | N | | |
| R-PE-BENCH.5/3 | EX-8B-E2 | 220 columns: ≤ 194 cells | N | | |
| R-PE-BENCH.5/4 | EX-8B-E2 | room 1 → the definition line only | R | | |
| R-PE-BENCH.5/5 | EX-8B-E2 | room 0 → no bench line, no exception | R | | |
| R-PE-DEF.108/1 | EX-8B-K1 | ENUM_0001 → `E.card.ENUM_0001.line0` … `line3` | N | | |
| R-PE-DEF.108/2 | EX-8B-K1 | MASK_FIELD_0001 → `B.card.MASK_FIELD_0001.line0` … `line5` | N | | |
| R-PE-DEF.108/3 | EX-8B-K1 | V171 ASCII → `T.card.V171.line0` (78 cells) | N | | |
| R-PE-DEF.108/4 | EX-8B-K1 | DISPLAY_0001 (number) → exactly one expanded line, no card | R | | |
| R-PE-DEF.33/1 | EX-8B-K2 | ENUM_0001 at start → card row 1 with `(●) 1 IDLE`, row 2 `↔ choose · enter stage` | N | | |
| R-PE-DEF.33/2 | EX-8B-K2 | after choosing RUN → `(●) 2 RUN` | N | | |
| R-PE-DEF.33/3 | EX-8B-G6 | 118×54 (grid wider than the view), ENUM_0001 selected, body focused: → once → `(●) 2 RUN`, scroll x stays 0 | R | | |
| R-PE-DEF.34/1 | EX-8B-B1 | MASK_FIELD_0001 at start → `B.MASK_FIELD_0001.start.line0` … `line3` | N | | |
| R-PE-DEF.34/2 | EX-8B-B1 | pending 255 → `B.MASK_FIELD_0001.pending255.line3` | N | | |
| R-PE-DEF.34/3 | EX-8B-B1 | MASK_BIT_0001 pending 0 → `B.MASK_BIT_0001.pending0.line2`, `line3` | N | | |
| R-PE-DEF.35/1 | EX-8B-T1 | V171 ASCII at start → `T.V171.start.line0` … `line3` | N | | |
| R-PE-DEF.35/2 | EX-8B-T2 | pending `ABC` → `T.V171.pendingABC.line1`; offsets 0 … 9 pending style | N | | |
| R-PE-DEF.109/1 | EX-8B-B2 | ULONG mask 0x00FF0000 → `B.ULONG_FF0000.pending0x12.line0` … `line7` | R | | |
| R-PE-DEF.110/1 | EX-8B-T1 | V171 (42 B): the ASCII guide at 56 on every line | R | | |
| R-PE-DEF.111/1 | EX-8B-T3 | bytes `00 1B 7F 80 FF 41 20 7E` → `·····A ~` | R | | |
| R-PE-DEF.112/1 | EX-8B-K3 | 300 enum entries → `E.card.300_entries.line1` (139 cells) | R | | |
| R-PE-DEF.112/2 | EX-8B-K3 | a 300-character name → the card's top line 139 cells, title cut with `…` | R | | |
| R-PE-DEF.115/1 | EX-8B-K4 | an enum named `A\x1b[2J` → `E.card.name_esc.line0` (`A�[2J`; no ESC in the painted text) | R | | |
| R-PE-DEF.115/2 | EX-8B-K4 | an enum entry text `A\x1b[2J` → `E.card.row_esc.line1` | R | | |
| R-PE-DEF.115/3 | EX-8B-K4 | an enum entry text `[@click=app.quit]OFF[/]` → `E.card.markup.line1`, literal, no action link, no exception | R | | |
| R-PE-DEF.116/1 | EX-8B-K5 | an enum named `温度`×200 → `E.card.name_wide200.line0`: 139 cells, 73 characters, title ends `…` | R | | |
| R-PE-DEF.116/2 | EX-8B-K5 | an enum entry text `温度` → `E.card.enum_wide.line0` … `line3`, 79 cells each | R | | |
| R-PE-DEF.117/1 | EX-8B-L7 | limits −1.7e308 … 1.7e308, current 1e308 → `L.cell.span_overflow`, `●` at 21, `┤` at 25, no exception | R | | |
| R-PE-DEF.117/2 | EX-8B-L7 | ENUM_0001, last entry raw 2**1100 → `L.cell.enum_beyond_float` (`inf` upper slot, `…` at 16); its row line paints | R | | |
| R-PE-DEF.117/3 | EX-8B-L7 | limits −1.7e308 … 1.7e308, current −1.7e308 → `L.cell.span_overflow.lower_end`, `●` at 9 | N | | |
| R-PE-DEF.117/4 | EX-8B-L7 | limits 0 … 5e-324 (halves both 0): current 0 → `●` at 9; current 5e-324 → `●` at 24; no `?`, no exception (E5, X8b) | R | | |
| R-PE-DEF.116/3 | EX-8B-K5 | an enum entry text `温度`×100 → `E.card.enum_wide100.line1`, 139 cells, ends `… │` | R | | |
| R-PE-DEF.113/1 | EX-8B-P1 | 118×54: the Include parameter control's label is `▽ Pick` | N | | |
| R-PE-DEF.113/2 | EX-8B-P1 | 80×24: the seven filter-row controls (filter, status, page prev / label / next, Include, bulk) keep a non-zero region inside the panel | R | | |
| R-PE-DEF.85/1 | EX-8B-P2 | the `STAGING SHEET — …` help effect holds `↑↓`, `enter`, `←→`, `home`, `end`, `esc` | N | | |
| R-PE-BENCH.11/1 | EX-8B-F1 | CURVE_DEF_0001 → `▄▆▃▇▁ 5` | N | | |
| R-PE-BENCH.11/2 | EX-8B-F1 | MAP_DEF_0001 → `▆▃▅▃ 12` | N | | |
| R-PE-BENCH.11/3 | EX-8B-F1 | VAL_BLK_DEF_0001 → `▄▃▄ 6` | N | | |
| R-PE-BENCH.107/1 | EX-8B-F1 | the three DEFC strips hold only `▁ … ▇` and spaces | N | | |
| R-PE-BENCH.107/2 | EX-8B-F2 | 40 points in 17 cells → `S.wide.40_points_in_17` (top level `▇`) | R | | |
| R-PE-BENCH.107/3 | EX-8B-F3 | E5 real WT capture 118×54: `f_r14_1_probe.py` → `joined cells … = []` for both row pairs | N | | |
| R-PE-BENCH.108/1 | EX-8B-F1 | the three strips: colour #969aad, no background | N | | |
| R-PE-BENCH.108/2 | EX-8B-F1 | on the selected row and a zebra row: the strip cells show the row's ground | R | | |
| R-PE-BENCH.36/4 | EX-8B-W2 | LARGE at 80×24 (V = 73): cursor right past the last painted canvas column → the window's first column +1, the cursor's cell painted (`W.detail_geometry.V73.*`) | R | | |
| R-PE-BENCH.36/5 | EX-8B-W2 | LARGE at 118×54 (V = 110): cursor down past the last painted canvas row → the window's first row +1, the cursor's cell painted (`W.detail_geometry.V111.*`; E4: "down", not "right" — at this V every column of the 16-column grid is painted, so no column lies past it) | N | | |

R-PE-BENCH.36/1 … /3 stand as written in `../inc-9/` (E4 re-runs them with /4 and /5).

**Count:** 133 cases for 43 active requirements (N 69, R 64; R-PE-DEF.114/2 withdrawn). E5 (X8b) added R-PE-DEF.117/4. E4 (I8b) added R-PE-DEF.117/1 … /3 and corrected .94/1, /3, /6, .97/8, .113/2, R-PE-BENCH.5/1 … /3, .36/5 (see `E4-integration.md`). Before E4: 130 cases for 42 active requirements (N 68, R 62). E3R1 added 17: R-PE-DEF.33/3, .81/5, .92/3, .94/6, .96/6, .104/7, .114/1 … /3, .115/1 … /3, .116/1 … /3, R-PE-BENCH.36/4, /5; it renumbered R-PE-BENCH.94/* → .107/* and .95/* → .108/* (E3-8b-01).
