# Inc 8b — E1 slice: the files and functions to add or change, counted and mapped

Base `09001bbc`; every line number is "as of `09001bbc`". Rows: `01-requirements.md`. Decisions: `E1-rulings.md` §5 (D-1 … D-9) and the provisional choices of §6. Callers: Code-Wire extractor `v3.1.0-8-gb6cd30d` (README v3.2) over the layered graphs of Inc 8 and Inc 9 in a throwaway clone (`codewire/graph-inc8b.md` §Baseline; clone deleted after the run).

## 1. Source files and groups (cap: 4 source files per worker group)

E3R1 (`E3-rulings.md`): the E4 groups are **S**, **B** and **W** as below; W gains `bench_sheet.py` for `ArrayBenchSheet._bench_geometry` only (E3-8b-02) and holds 4 source files, at the cap.

| Group | Source files | Functions | Rows |
|---|---|---|---|
| **S — sheet render (pure)** | `s19_app/tui/definition_sheet.py` | 20 (7 new, 13 changed; 2 removed) | R-PE-DEF.5, .21, .33, .34, .35, .76, .89, .90, .91, .96 … .112, .114, .115, .116 (render half), R-PE-BENCH.17 (`range_cell`) |
| **B — bench strip, bench limits, rule text** | `s19_app/tui/definition_bench.py`; `s19_app/tui/insight_style.py` (comment only) | 2 changed + 1 constant; 1 docstring | R-PE-BENCH.11, .17, .107, .108; R-PE-DEF.101 (the rule's statement) |
| **W — sheet widget, bench geometry, picker label, help** | `s19_app/tui/screens_directionb/patch_editor/sheet.py`; `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` (`ArrayBenchSheet._bench_geometry` only; `:138`, `:288`, `:592` unchanged); `s19_app/tui/a2l_parameter_picker.py`; `s19_app/tui/window_help.py` | 9 (sheet 7: 3 new, 4 changed; bench_sheet 1 changed; picker 1 changed) + help: 1 data line | R-PE-DEF.81, .92, .93, .94, .95, .107 (paint half), .113, .85, .33/3 (keys); R-PE-BENCH.5, .36 |
| **T — tests (not source)** | `tests/test_tui_patch_json.py` (`_EXCLUDED_LITERALS` + `#1c2547`); `tests/support/b103_inc8_s2.py` (the harness CSS for the body under `#patch_sheet_grid`, E3-8b-05); Inc 8 / Inc 9 tests that assert the retired widths or old looks (§4) | — | the hue census; regression |

**Source files: 7** — `definition_sheet.py`, `definition_bench.py`, `insight_style.py`, `patch_editor/sheet.py`, `patch_editor/bench_sheet.py` (one function), `a2l_parameter_picker.py`, `window_help.py`. **Functions: 31** (10 new, 21 changed) — S 20, B 2, W 9 — plus 2 removed, 2 class attributes (`StagingSheet.DEFAULT_CSS`, `StagingSheet.BINDINGS`), 2 module constants (`_BLOCKS` of `definition_bench.py`; the style constants of `definition_sheet.py`), 1 help line and 1 docstring. **Not touched:** `bench_sheet.py` other than `_bench_geometry`, `definition_bench_view.py`, `app/patch.py`, `layout.py`, `panel.py`, `styles.tcss` (E1-rulings §8).

**Build order:** S first (W and B import its new names: `header_rule`, `range_cell`, `limit_slot`, the style constants, `row_line(odd=…)`); W and B in parallel after S's names are fixed (they are pinned in the graph, so W's and B's testers can start at once). E4 staffing (E3-8b-13): S one implementer and two testers (render rows; card and limits); B and W one implementer and one tester each; then the AT tester (keys and dialogs across the groups: ←/→ on an enum, Home/End at 80, 118 and 220, Tab order) and the integrator. Inc 8b's E4 runs before Inc 9b's (E3 answer 8).

## 2. Function map

### Group S — `s19_app/tui/definition_sheet.py`

| # | Function | New / changed | Rows |
|---|---|---|---|
| S1 | `sheet_widths(width) -> SheetWidths` (`:130-137`) | changed: the grid widths at every width (D-1) | .89 |
| S2 | `header_line(widths) -> Text` (`:140-151`) | changed: gutters, header style | .5, .97 |
| S3 | `header_rule(widths) -> Text` (E4: the graph corrected to the landed signature, orchestrator ruling) | new | .91, .97 |
| S4 | `limit_slot(x: float) -> Text` | new: 7-cell slot, exponent form | .104, .105 |
| S5 | `range_cell(lower, upper) -> Text` | new: range and no-limits forms | .76, .104, .106, R-PE-BENCH.17 |
| S6 | `limits_cell(row, value, width) -> Text` (`:727-754`) | changed: slots, 18-cell track, range form for upper ≤ lower and non-finite limits, no-position form for a value or position that is not finite (E3R1), the collision rule at cell 16 (E3R1), marker styles | .21, .76, .104, .106, .114, .98, .99 |
| S7 | `_tone(row, is_pending, preview) -> str` | new: staged / pending / refused / none | .98, .99, .100, .101 |
| S8 | `_mark(selected, staged, pending, glyph) -> Text` (`:791-797`) | changed: token styles (`_GLYPH_STYLES` GREEN / PURPLE) | .98, .99, .97 |
| S9 | `_stock_cells(row, widths, is_pending, pending, preview, new) -> tuple` (`:800-809`) | changed: dim Kind and Current-style cells; tone left to `row_line` | .97 |
| S10 | `row_line(row, widths, selected, pending, preview, state=None, odd=False) -> Text` (`:812-841`) | changed: gutters, New/Δ tone for every kind, zebra and selected ground | .89, .90, .96, .97 … .101 |
| S11 | `detail_lines(row, preview, width, state=None, room=None) -> list[Text]` (`:847-857`) | changed: bar, expanded ground, cut at max(G, V) − 4 (D-4) | .107, R-PE-BENCH.5 |
| S12 | `card_lines(title, rows, cap) -> list[Text]` | new: frame, card ground, title cut; widths in terminal cells, title and rows as plain text (E3R1) | .108, .112, .115, .116, .97 |
| S13 | `bit_table(row, preview) -> list[Text]` | new (replaces `_bit_strip` `:528-544`) | .34, .102, .109 |
| S14 | `hex_grid(row, preview) -> list[Text]` | new (replaces `_text_rows` `:551-568`) | .35, .102, .110, .111, .79 (kept) |
| S15 | `_detail_enum` (`:524-525`), `_detail_mask` (`:547-548`), `_detail_text` (`:571-572`) | changed: definition line + card | .33, .34, .35, .108 |
| S16 | `_verdict(preview) -> Text` (`:884-888`) | changed: palette GREEN / YELLOW (constants `_OK`, `_WARN`, `_BAD` `:32`) | .101 |
| S17 | `_scalar_tail(row, preview, width) -> Text` (`:901-911`) | changed: after bytes in the pending style, key hint keycap, `raw` dim | .97 |
| S18 | `formula_tail(row, preview, width) -> Text` (`:914-926`) | changed: refusal in RED #fd8383 (via `_BAD`) | .101 |
| — | removed: `_bit_strip`, `_text_rows` | replaced by S13, S14 | — |

S15 counts 3 functions: group S has 20 changed-or-new functions in all (S1 … S18 with S15 as 3), 7 of them new.

### Group W — `patch_editor/sheet.py`, `a2l_parameter_picker.py`, `window_help.py`

| # | Function | New / changed | Rows |
|---|---|---|---|
| W1 | `StagingSheet.compose()` (`sheet.py:120-131`) | changed: the body inside a horizontal grid scroller (`#patch_sheet_grid`, a plain `textual.containers.Container`: not focusable, no bindings; E3-8b-03); the bar outside | .92, .93, .95, .33/3 |
| W2 | `StagingSheet.DEFAULT_CSS`, `StagingSheet.BINDINGS` (`:64-80`) | changed: `StagingSheet > #patch_sheet_grid { height: 1fr; overflow-x: auto; overflow-y: hidden; scrollbar-size-horizontal: 1; }` and `#patch_sheet_grid > #patch_sheet_body { height: 1fr; width: auto; }` replace `StagingSheet > #patch_sheet_body { height: 1fr; }` (E3-8b-05); `home`, `end` | .81, .92, .93, .94 |
| W3 | `StagingSheet.action_scroll_grid(where: str)` | new: `"home"` → x 0; `"end"` → max(0, G − V); `scroll_to(x=…, animate=False)` (E3-8b-03) | .94 |
| W4 | `StagingSheet._view_width() -> int` | new: the scroller's visible content width (fallback 118 − 7) | .107, R-PE-BENCH.5 |
| W5 | `StagingSheet._paint()` (`:312-354`) | changed: header + rule, visible = h − 2, `odd` per position, detail width and room from `_detail_geometry()`, cut at max(G, V) − 4 | .81, .91, .107 |
| W6 | `StagingSheet._fit_window()` (`:404-423`) | changed: visible = h − 2, detail width and room from `_detail_geometry()` | .81 |
| W10 | `StagingSheet._detail_geometry() -> tuple[int, int]` | new (E3-8b-02): (`_view_width()` − 4, visible − 1), visible = body height − 2; the one source of the detail's width and room | .81, .107, R-PE-BENCH.5, .36 |
| W11 | `ArrayBenchSheet._bench_geometry(state, grid) -> tuple[int, int]` (`bench_sheet.py:305-312`) | changed (E3-8b-02): `canvas_shape(*…)` from `_detail_geometry()` instead of the body's width and height − 1; callers `_reveal` (`:316`) and `action_page` (`:378`) unchanged | R-PE-BENCH.36 |
| W7 | `_SheetBody.on_resize(event)` (`:49-52`) | changed: the sheet among the ancestors (D-7) | .81 |
| W8 | `A2LParameterPicker.compose()` → nested `page_controls()` (`a2l_parameter_picker.py:725-747`) | changed: compact label `▽ Pick` | .113 |
| W9 | `WINDOW_HELP_SECTIONS` Patch Editor `STAGING SHEET — …` line (`window_help.py:71-73`) | changed: + `home end scroll the grid to its first and last columns` | .85 |

W counts 9 functions (W1, W3 … W8, W10, W11; 3 new) plus W2 (class attributes) and W9 (data).

### Group B — `definition_bench.py`, `insight_style.py`

| # | Function | New / changed | Rows |
|---|---|---|---|
| B1 | `summary_strip(values, grid, width) -> Text` (`definition_bench.py:491-527`) and `_BLOCKS` (`:434`) | changed: 7 levels, column-mean levels for grids, DGRAY, no ground | R-PE-BENCH.11, .107, .108 |
| B2 | `bench_cells(row, state, widths)` (`:605-637`) | changed: Limits through `range_cell` | R-PE-BENCH.17, R-PE-DEF.104 |
| B3 | `insight_style.MAGENTA` comment (`insight_style.py:75-84`) | changed (comment only): the verdict-hue rule of CTX-PE-DEF | R-PE-DEF.101 |

## 3. Requirement → owner group

Every row has one owner group; a row whose evidence needs two groups names both (render + paint).

| Rows | Owner |
|---|---|
| R-PE-DEF.5, .21, .33, .34, .35, .76, .89, .90, .91, .96, .97, .98, .99, .100, .101, .102, .103, .104, .105, .106, .108, .109, .110, .111, .112, .114, .115, .116 | S (.33/3, the keys under the scroller, with W1) |
| R-PE-DEF.81, .92, .93, .94, .95, .107, .113, .85; R-PE-BENCH.5, .36 | W (.107 and R-PE-BENCH.5 with S11) |
| R-PE-BENCH.11, .17, .107, .108 | B (.17 with S5) |

## 4. Existing tests the change moves (E4: re-aim, never weaken)

- Inc 8 tests of R-PE-DEF.6 / .7 (width classes, `W = 96` hiding Kind and Unit, every line ≤ the sheet width) — retired with the rows; their wide-character cases move to R-PE-DEF.96, their bar case to .95.
- Inc 8 tests of .5, .21, .33 … .35, .76, .81 (old header starts, `├` after the lower's width, the bit strip, the text rows, `5 … 5`, visible = h − 1) — re-aimed at the new examples.
- Inc 9 tests of R-PE-BENCH.11 (EX-G1 `▅▇▄█▁ 5`, EX-G2 ramp steps on `█`), .17 (`0 … 65.5k`), .5 (line ≤ width) — re-aimed; F-X9r-1's 220 case now holds by construction. Inc 9's R-PE-BENCH.36 tests re-run with the new /4 and /5 (E3R1).
- The harness CSS of `tests/support/b103_inc8_s2.py` (`:116`, `:145`) follows W2's selectors (E3-8b-05).
- E4 addenda from E3: `E3-addenda.md` (E3-8b-09 … 11).
- Snapshot / capture tests that pin the sheet's look (`tests/test_tui_snapshot.py` if it covers the Patch Editor) — E4 lists them; a snapshot update is evidence only with the PNG checked.
- Law guards to run at E5: the hue census (`test_tc079_*`), the help parser (`test_b97_chips_help.py`, TC-B97-32), key-binding and markup-safety guards named in the repository's `CLAUDE.md`.
