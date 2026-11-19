# check-G4 (unit G4b tree = G4 driver fix + G4b 4 re-pins, uncommitted over 3afebf90)

**Verdict: GO** (one note on row 2's canon mapping, below). Checker: Sonnet tester, independent. Copies on rtx deleted. Diff: `frontB\diffs\G4.diff`.

| # | Check | Evidence |
|---|---|---|
| 1 | Diff hygiene | chkdiff: files=1 (`tests/test_b103_inc12_tag_table.py`, the only allowed file), CR=0, skipadd=0, defs removed-not-readded: none, no new sleep. 72 lines (+54/-18). No user/host tokens. |
| 2 | Intent | See per-test table below. No loosened assertion; the product is untouched. |
| 3 | GREEN | 4 nodes `-n 0`: 4 passed (82.9s). Whole file `-n 4`: 112 passed (335s). Base had 13 failed / 99 passed: all 13 now GREEN, none turned RED. |
| 4 | Negative controls | I re-applied all 4 of the worker's mutations plus one of mine in separate copies, each on its own node: all RED (see table). |
| 5 | Laws | Six law files serially: 3 failed / 112 passed / 2 skipped = exactly the base-red set (`test_r_tst_070_2`, canon two-shall, address census). The census lists the same 8 sites in `test_b103_a2l_refresh` / `test_b103_picker_model`, none in the inc12 file. |
| 6 | Worker claims | Verified: file 112 passed; 4 nodes pass; diff stat 54+/18-; CR=0; RED lines of rows 1, 2, 3, 4 reproduce verbatim; row 2's deviation (the grouped mutation leaves it GREEN because SYN_MAP_W has no display id) is accurate by reading the fixture. No false claim found. |

## Per-test: does the re-pin still verify its canon row, or is it only weaker?
| Test | Canon row | Verifies it? | Mutation (my run) -> RED line |
|---|---|---|---|
| `test_r_tui_042a_8_1_name_line_with_a_display_identifier` | 042a.8 (`:1139`) | YES, and stricter in shape. First logical line is exactly `✓ SYN_DISP_W  0x1C2D3E00` (display id in line 1) and exactly one logical line `name <full 48-char name>`. It no longer proves the name is painted on screen, only that the card's content puts it on its own line, which is what the row says. | name appended to the identifier line -> `- ✓ SYN_DISP_W  0x1C2D3E00 / + … SYN_MAP_LLL…_END` |
| `test_at_b103_i12_1_no_glued_or_cut_values` | AT-B103-I12-1 (first-line `name  addr`). NOTE: not 042a.8: the SYNMAP fixture has no display id, so 8 does not apply to it. | YES for what it asserts: the first logical line keeps name and address separated by two spaces; the other invariants of the AT are untouched. | glue name+address -> `'✓ SYN_MAP_W0x1C2D3E00' != '✓ SYN_MAP_W  0x1C2D3E00'`. The brief's own mutation (name on the id line) leaves it GREEN, as the worker said. |
| `test_r_tui_042a_7_2_1_description_break_run` | 042a.7.2 (`:1138`), 7.1 (`:1137`) | YES, and stricter: the logical desc line equals `desc SYN  desc part two` (a single space where LF+TAB were); the no-TAB/CR and no-introducers screen assertions are kept. | break run removed (`""`) -> `'desc SYN  descpart two'`. The brief's "verbatim" mutation (no scrub) -> same RED, because `safe_text` still strips the controls; so the "one space" part is proven by the removal mutation. |
| `test_r_tui_042a_7_1_6_limits` | 042a.7.1 (`:1137`) | YES. Same assertions (limits line painted after a scroll with `max_scroll_y > 0`, `scroll_y > 0`, no introducers); only the terminal size changed to 100x24, where the card is capped at 5 rows (`-short` regime) so the 6 logical lines overflow. The scroll condition the case is about exists again. Cost: the case no longer runs in the stacked 118x54 layout, so it says nothing about that layout. | limits line dropped (`if False`) -> `AssertionError` on `'limits ' in full` |

## Gaps / notes
- Rows 1-3 read the logical text (`card.render().plain`), not the painted rows, so soft-wrap geometry at 118x54 is no longer covered by these tests (by the brief's order; the canon rows do not require a one-line layout).
- Row 4 relies on the `-short` stylesheet max-height 5 (R-A2L-LIST.083) staying in place; if that changes, the node fails loudly (`max_scroll_y > 0`).
- G4 driver (`_show_a2l`): real `down`/`up` key presses plus a bounded 15 s wait on the card text; the single-row case uses `move_cursor(column=1)` then `column=0` (not a key press). G4's own negative control (show_tag no-op) was not re-run by me: the file is GREEN with it and 5 other mutations RED in my runs; flagged as not re-run.
