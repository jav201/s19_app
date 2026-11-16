# Inc 8 — acceptance test cases (E4, AT tester `test-at`)

Author: AT tester (E4), model claude-sonnet-5-5. Black-box: every case drives the real app (`S19TuiApp` under Textual's pilot) with the synthetic definitions case (`tools/synth/make_release_case.py --case definitions`, seed 20260001: `definitions.a2l` + `definitions.s19`, DEFC) loaded through the app's own loaders, through the shipped surface (keys, filter row, sheet, formula input, ledger, help chip). No product module of Inc 8 is imported. Expected values are never retyped: byte spans, Δ and refusal messages are computed in the test by the committed I-2 model (`a2l_definition.describe_definition` / `encode_definition` / `decode_definition`) over the app's own parsed A2L and image; status-line wording and mark glyphs come from the requirement rows cited.

An AT asserts the operator-visible outcome only. The unit cases of the four group testers (layout, rows, detail, staging, keys, help text per row) are not repeated here.

Files: `tests/test_b103_inc8_at.py` (AT-1 … AT-5, AT-7 … AT-9), `tests/test_b103_inc8_at_help.py` (AT-6).

## Acceptance tests

| AT | Chain (one node each, C-18) | Node |
|---|---|---|
| AT-B103-I8-1 | filter `_0001` → page → Tab to the sheet → down to DISPLAY_0001 → Enter → type `25.5` → preview tail → Enter stages → ledger entry, status, advance, dirty mark | `test_b103_inc8_at.py::test_at_b103_i8_1_filter_page_row_formula_stage_advances_and_marks_dirty` |
| AT-B103-I8-2 | type a pending formula, Escape → focus back on the sheet, pending cleared, still in the Patch Editor | `test_b103_inc8_at.py::test_at_b103_i8_2_escape_in_the_formula_input_stays_in_the_sheet` |
| AT-B103-I8-3 | up/down/left/right on the sheet, Enter, Enter on an enum row stages the chosen entry | `test_b103_inc8_at.py::test_at_b103_i8_3_arrow_keys_select_rows_and_choose_enum_entries` |
| AT-B103-I8-4 | paste longer than 4,096 characters into the formula input is refused | `test_b103_inc8_at.py::test_at_b103_i8_4_paste_over_4096_characters_is_refused` |
| AT-B103-I8-5a | no A2L → the sheet's load line | `test_b103_inc8_at.py::test_at_b103_i8_5a_no_a2l_shows_the_load_line` |
| AT-B103-I8-5b | A2L unloaded between typing and Enter → status, nothing staged | `test_b103_inc8_at.py::test_at_b103_i8_5b_a2l_unloaded_before_enter_stages_nothing` |
| AT-B103-I8-6 | the Patch Editor help window shows the new rows | `test_b103_inc8_at_help.py::test_at_b103_i8_6_help_window_shows_the_new_rows` |
| AT-B103-I8-7 | refused formulas (`abc`, `250`, `WALK`) stage nothing, show the message, keep the dirty flag (negative control of AT-1's readers) | `test_b103_inc8_at.py::test_at_b103_i8_7_refused_formula_stages_nothing` |
| AT-B103-I8-8 | two masked fields of one word staged in either order, Apply → both decode as typed, word from the model | `test_b103_inc8_at.py::test_at_b103_i8_8_two_masked_fields_stage_over_the_overlay` (2 params) |
| AT-B103-I8-9 | a filter that matches nothing → the type-a-filter line | `test_b103_inc8_at.py::test_at_b103_i8_9_filter_matching_nothing_shows_the_line` |

## Cases (requirement → AT)

Format as `roles/tester.md`: `<requirement id>/<n> | example id | test name | full or partial`. `<n>` is the case number of `02-test-cases.md` the AT also observes end to end; "full" = the product itself produces what the test asserts through the shipped key / widget route. A row marked partial says why.

| Case | Example | Objective — the operator sees … | Class | Test name | full / partial |
|---|---|---|---|---|---|
| R-PE-DEF.10/2 | EX-R1 | filter `_0001` → one sheet row per matching parameter of the page, in page order | N | AT-1 | full |
| R-PE-DEF.13/1 | EX-R3 | filter that matches nothing → `No parameters on this page: type a filter above.` | R | AT-9 | full |
| R-PE-DEF.14/1 | EX-R3 | no A2L at start → `Load an A2L file to edit parameters by definition.` | R | AT-5a | full |
| R-PE-DEF.22/1 | EX-K1 | exactly one `▶` row, the first row at start | N | AT-3 | full |
| R-PE-DEF.22/2 | EX-K1 | the `▶` row follows the keys | N | AT-1, AT-3 | full |
| R-PE-DEF.23/1 | EX-S1 | DISPLAY_0001 staged → `●` in its mark column and `25.5` in New | N | AT-1 | full |
| R-PE-DEF.23/3 | EX-S2 | ENUM_0001 staged `RUN` → New `2 RUN` | N | AT-3 | full |
| R-PE-DEF.27/1 | EX-P7 | DISPLAY_0001 `250` → `✗ refused` is painted in the Δ column of the pending row | R | AT-7 | full |
| R-PE-DEF.40/1 | EX-P1 | `25.5` typed → the tail shows `✓ in limits` | N | AT-1 | full |
| R-PE-DEF.42/1 | EX-H3 | 65,536-character paste into the empty input → empty | R | AT-4 | partial: a posted `events.Paste`, not a real bracketed paste (manual item M-2) |
| R-PE-DEF.42/2 | EX-H3 | 200 characters pasted onto 4,000 → the 4,000 unchanged | R | AT-4 | partial: same |
| R-PE-DEF.42/4 | EX-H3 | positive control: a paste of exactly 4,096 characters is accepted | N | AT-4 | partial: same (control for AT-4's refusal) |
| R-PE-DEF.45/1 | EX-K1 | down → row 2 | N | AT-3 | full (Linux pilot; Windows Terminal delivery: manual item M-1) |
| R-PE-DEF.45/2 | EX-K1 | down → row 3 | N | AT-3 | full |
| R-PE-DEF.45/3 | EX-K1 | up → row 2 | N | AT-3 | full |
| R-PE-DEF.45/4 | EX-K1 | up on row 1 → stays | R | AT-3 | full |
| R-PE-DEF.46/1 | EX-K1 | Enter on the sheet → focus in the formula input | N | AT-1, AT-2, AT-3 | full |
| R-PE-DEF.47/1 | EX-P2 | ENUM_0001 from IDLE, right → input `RUN` | N | AT-3 | full |
| R-PE-DEF.47/2 | EX-P2 | right → `FAULT` | N | AT-3 | full |
| R-PE-DEF.47/3 | EX-P2 | right on FAULT → `FAULT`; left → `RUN` | R | AT-3 | full |
| R-PE-DEF.48/1 | EX-P1 | pending `25.5`, Escape → pending gone (New `·`, no Δ), focus on the sheet, still in the Patch Editor | N | AT-2 | partial: Linux pilot Escape; Windows Terminal Escape routing: manual item M-3 |
| R-PE-DEF.50/1 | EX-S1 | Enter → one bytes entry at the model's address with the model's bytes | N | AT-1 | full |
| R-PE-DEF.50/2 | EX-S2 | ENUM_0001 `RUN` → the model's one-byte entry | N | AT-3 | full |
| R-PE-DEF.51/1 | EX-O1 | MASK_FIELD `255` then MASK_BIT `0`, Apply → decode `255`, `0`, word from the model | N | AT-8 (param 1) | full |
| R-PE-DEF.51/2 | EX-O2 | MASK_BIT `0` then MASK_FIELD `255`, Apply → same | N | AT-8 (param 2) | full |
| R-PE-DEF.52/2 | EX-O1 | the two masked fields → one document entry at the word's address | N | AT-8 | full |
| R-PE-DEF.53/1 | EX-S1 | DISPLAY_0001 → entry symbol `DISPLAY_0001`, type bytes | N | AT-1 | full |
| R-PE-DEF.54/1 | EX-O1 | MASK_FIELD then MASK_BIT → the one entry keeps symbol `MASK_FIELD_0001` | N | AT-8 | full |
| R-PE-DEF.56/1 | EX-P3 | `abc` → document unchanged | R | AT-7 | full |
| R-PE-DEF.56/2 | EX-P7 | `250` → unchanged | R | AT-7 | full |
| R-PE-DEF.56/3 | EX-P8 | `WALK` on ENUM_0001 → unchanged | R | AT-7 | full |
| R-PE-DEF.57/1 | EX-P7 | `250` → `Patch Editor: <I-2 message>` | R | AT-7 | full |
| R-PE-DEF.57/2 | EX-P3 | `abc` → `Patch Editor: <I-2 message>` | R | AT-7 | full |
| R-PE-DEF.57/3 | EX-P8 | `WALK` → `Patch Editor: <I-2 message>` | R | AT-7 | full |
| R-PE-DEF.58/1 | EX-S1 | `Patch Editor: DISPLAY_0001 staged as 25.5 (<n> B at 0x<X>).`, n and X from the model | N | AT-1 | full |
| R-PE-DEF.58/2 | EX-S2 | `Patch Editor: ENUM_0001 staged as RUN (<n> B at 0x<X>).` | N | AT-3 | full |
| R-PE-DEF.60/1 | EX-S1 | stage → the row after the staged row is selected | N | AT-1 | full |
| R-PE-DEF.63/1 | EX-F2 | A2L unloaded between typing and Enter → `Patch Editor: no A2L is loaded — nothing staged.`, nothing staged | R | AT-5b | partial: the unload is the app's `_apply_unload("a2l")` (the loaded-artifacts unload button calls it); reachability of the input after the repaint is the open question of the report |
| R-PE-DEF.82/2 | EX-S11 | staged, DISPLAY_0001 selected again → the input is empty | N | AT-1 | full |
| R-PE-034/1 | EX-S1 | stage → dirty flag set (ledger subtitle carries `●`) | N | AT-1 | full |
| R-PE-035/1 | EX-P3 | `abc` refused with the flag clear → stays clear | R | AT-7 | full |
| R-PE-035/2 | EX-P3 | `abc` refused with the flag set (after a good stage) → stays set | R | AT-7 | full |
| R-PE-041/2 | EX-L3 | one entry → ledger subtitle `1 entry` | N | AT-1 | full |
| R-PE-041/4 | EX-L3 | dirty → subtitle ends `●` (`1 entry ●`) | N | AT-1 | full |
| R-PE-DEF.83/1 | EX-HL1 | help step 1 names the filter row, STAGING SHEET, LANDS IN and the four tabs | N | AT-6 | full |
| R-PE-DEF.83/2 | EX-HL1 | no A2L tab / `A2L PARAMETERS` / "on the left" / "on the right" | R | AT-6 | full |
| R-PE-DEF.84/1 | EX-HL1 | `Patch script — …` line holding `entries` | N | AT-6 | full |
| R-PE-DEF.85/1 | EX-HL1 | `STAGING SHEET — …` line holding `↑↓`, `enter`, `←→`, `esc` | N | AT-6 | full |
| R-PE-DEF.86/1 | EX-HL1 | `new =` line naming Enter | N | AT-6 | full |
| R-PE-DEF.86/2 | EX-HL1 | `field =` line | N | AT-6 | full |
| R-PE-DEF.86/3 | EX-HL1 | `text =` line | N | AT-6 | full |
| R-PE-DEF.87/1 | EX-HL1 | `Use parameter` effect holds `Inspector`, `selected row`, not `A2L tab` | N | AT-6 | full |

## Negative controls (per file)

- `test_b103_inc8_at.py`: AT-7 is the control of AT-1's readers — the same ledger, status, subtitle and mark readers, run after a refused formula, must read "nothing staged, not dirty". An AT-1 reader that always says "staged" fails AT-7; an AT-7 reader that always says "nothing" fails AT-1. Every new-path test is also RED on the base tree (no `#patch_sheet_body`), see `E4-test-at.md`.
- `test_b103_inc8_at_help.py`: the same parser run on the `check_editor` section finds no `STAGING SHEET` line (a parser that finds one anywhere fails).
- The AT-1 pre-state asserts (0 entries, `0 entries`, no `●`) are the before-the-trigger controls.

## Uncovered by the ATs (named)

- R-PE-DEF.1.1 … .7 layout, widths, header, focus border: the layout group's.
- R-PE-DEF.12 timing, .31 … .36 detail lines, .70 … .73 hostile text, R-PE-DEF.55, .59, .64: the group testers'.
- R-PE-DEF.24 `◆`: the pending mark is shared with `▶` on the selected row, so the AT observes pending through New and Δ instead (R-PE-DEF.26 cells).
- Inc 9 benches (R-PE-DEF.1.2, R-PE-DEF.60/4): Inc 9's integration.
- Windows-only pilots: `E4-test-at.md` §Manual items M-1 … M-3.
