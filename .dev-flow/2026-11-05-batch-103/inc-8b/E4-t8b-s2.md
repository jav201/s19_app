# Inc 8b E4 - T8b-S2 hand-back (tester, group S: card and detail)

Model: claude-sonnet-5-5. Tree: tester tree, branch `b103-inc8b-tests`, base `48af05ff` (no Inc 8b product code). Test file: `tests/test_b103_inc8b_s2.py` (36 tests). The product was never read: every expected value is a key of `evidence-e1/examples_inc8b-transcript.txt` (loaded by key) or the requirement text; positions are found in the painted text. All tests drive `definition_sheet.detail_lines` (the base's entry point), so the new `card_lines`, `bit_table`, `hex_grid` are reached through it and every RED below is an assertion (no import error).

## Case table (requirement/case -> test, state)

State of every row: `executed` (RED on base, one run, below). GREEN is the integrator's. full = the product itself produces what the test asserts.

| Case | Test (tests/test_b103_inc8b_s2.py) | full/partial |
|---|---|---|
| R-PE-DEF.108/1 | test_r_pe_def_108_1_an_enum_row_shows_its_definition_line_then_a_framed_card | full |
| R-PE-DEF.108/2 | test_r_pe_def_108_2_a_bit_mask_row_shows_a_six_line_card_of_73_cells | full |
| R-PE-DEF.108/3 | test_r_pe_def_108_3_a_text_row_shows_its_card_top_line_of_78_cells | full |
| R-PE-DEF.108/4 | test_r_pe_def_108_4_a_number_row_has_no_card | full (GREEN on base: unchanged behaviour, a guard) |
| R-PE-DEF.33/1, /2 | test_r_pe_def_33_1_..., test_r_pe_def_33_2_... | full (/3 is the AT tester's) |
| R-PE-DEF.34/1, /2, /3 | test_r_pe_def_34_1_..., _34_2_..., _34_3_... | full |
| R-PE-DEF.35/1, /2 | test_r_pe_def_35_1_..., test_r_pe_def_35_2_... | full |
| R-PE-DEF.102/1 | test_r_pe_def_102_1_the_changed_bytes_and_their_ascii_are_underlined (+ negative control `..._nothing_is_underlined_before_an_edit`) | full |
| R-PE-DEF.102/2 | test_r_pe_def_102_2_the_after_bits_that_differ_from_the_image_are_underlined (+ negative control) | full |
| R-PE-DEF.109/1 | test_r_pe_def_109_1_a_32_bit_mask_word_is_two_blocks_of_16_high_bits_first (ULONG copy via `replace`, bytes `12 34 56 78` in the image) | full |
| R-PE-DEF.110/1 | test_r_pe_def_110_1_the_ascii_guide_is_on_the_same_column_... | full |
| R-PE-DEF.111/1 | test_r_pe_def_111_1_a_byte_outside_the_printable_range_shows_a_dot_in_the_ascii_column | full |
| R-PE-DEF.79 (kept) | test_r_pe_def_79_4_a_span_over_64_bytes_ends_its_card_with_the_cut_line (new place of the cut line) | full |
| R-PE-DEF.112/1, /2 | test_r_pe_def_112_1_..., test_r_pe_def_112_2_... | full |
| R-PE-DEF.115/1, /2, /3 | test_r_pe_def_115_1_..., _115_2_..., _115_3_... | full |
| R-PE-DEF.116/1, /2, /3 | test_r_pe_def_116_1_..., _116_2_..., _116_3_... | full |
| R-PE-DEF.107/1 | test_r_pe_def_107_1_the_one_line_of_a_number_row_is_on_the_bar_and_the_expanded_ground (ground #1b233a on every cell 0..142) | full |
| R-PE-DEF.107/2 | test_r_pe_def_107_2_every_card_line_of_a_mask_row_follows_the_bar | partial (bar and 143-cell fill; the ground colour is asserted on /1 only) |
| R-PE-DEF.107/3 | test_r_pe_def_107_3_every_bench_line_of_an_array_row_follows_the_bar | partial (same) |
| R-PE-DEF.107/4 | test_r_pe_def_107_4_a_definition_line_wider_than_the_cut_is_cut_at_139_cells | full |
| R-PE-BENCH.5/1..3 | test_r_pe_bench_5_1_2_3_no_bench_line_is_wider_than_the_view[73-80, 111-118, 195-220] (MAP_DEF_0001 and LARGE) | full |
| R-PE-BENCH.5/4 | test_r_pe_bench_5_4_room_one_shows_the_definition_line_only | full |
| R-PE-BENCH.5/5 | test_r_pe_bench_5_5_room_zero_shows_no_bench_line_and_no_exception | full (GREEN on base: a guard) |

## Commands and RED on base 48af05ff (one complete run each)

trace_check (`/tmp` transcript pasted): `python -I -B <skill>/trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-8b/01-requirements.md --tests tests --ids R-PE-DEF.33 R-PE-DEF.34 R-PE-DEF.35 R-PE-DEF.102 R-PE-DEF.107 R-PE-DEF.108 R-PE-DEF.109 R-PE-DEF.110 R-PE-DEF.111 R-PE-DEF.112 R-PE-DEF.115 R-PE-DEF.116 R-PE-BENCH.5`
-> `trace_check: 13 active requirements match --ids, checks run: CASE, TEST, 0 gap(s)` (exit 0).

RED: rtx, isolated env of the common block (`HOME` basename `<runner-home>`; redacted at E4 by I8b under HT-11, the law `test_r_tst_070_2` reads the basename as an identity), tree = `git`-tracked tester tree shipped by tar, `pytest -p no:cacheprovider -n 2 -q --tb=line tests/test_b103_inc8b_s2.py -rA`, `timeout 300`; host load printed (`uptime`), nothing here is timing. Result: `34 failed, 2 passed`; the 2 passed are the two guards marked above. Every failure line is an `AssertionError` / `assert False` / `assert a == b` at a test line (the first run's IndexError/StopIteration were hardened into assertions before this capture).

```
<scratch>/tree/s19_app/__init__.py
 00:12:14 up 2 days,  9:00,  5 users,  load average: 2.32, 1.00, 0.39
bringing up nodes...
bringing up nodes...

FFFFFFFFFFF.FFFFFFFFFFFFFFFFFFFFFFF.                                     [100%]
=================================== FAILURES ===================================
<scratch>/tree/tests/test_b103_inc8b_s2.py:101: AssertionError: 3 expanded lines only: ['└ TAB_VERB 4 pairs · UBYTE u8 big-endian · 0x00800000 · 1 B', '( ) 0 OFF   (●) 1 IDLE   ( ) 2 RUN   ( ) 3 FAULT   default "UNKNOWN_STATE"', '↔ choose · enter stage']
<scratch>/tree/tests/test_b103_inc8b_s2.py:171: assert False
<scratch>/tree/tests/test_b103_inc8b_s2.py:222: assert False
<scratch>/tree/tests/test_b103_inc8b_s2.py:180: AssertionError: ['└ IDENTICAL phys = (word & 0x0FF0) >> 4 · UWORD u16 big-endian · 0x00800010 · 2 B', 'bit 15…0 0001111111110111   word 1A E7 → 1F F7', 'mask 0x0FF0 · field = (word & mask) >> 4 · other bits kept']
<scratch>/tree/tests/test_b103_inc8b_s2.py:235: AssertionError: (0, 'mask 0x0FF0 · field = (word & mask) >> 4 · other bits kept')
<scratch>/tree/tests/test_b103_inc8b_s2.py:243: AssertionError: assert False
<scratch>/tree/tests/test_b103_inc8b_s2.py:101: AssertionError: 3 expanded lines only: ['└ IDENTICAL phys = (word & 0x0001) >> 0 · UWORD u16 big-endian · 0x00800010 · 2 B', 'bit 15…0 0001101011100110   word 1A E7 → 1A E6', 'mask 0x0001 · field = (word & mask) >> 0 · other bits kept']
<scratch>/tree/tests/test_b103_inc8b_s2.py:139: AssertionError: no framed bit table: ['└ IDENTICAL phys = (word & 0x0FF0) >> 4 · UWORD u16 big-endian · 0x00800010 · 2 B', 'bit 15…0 0001111111110111   word 1A E7 → 1F F7', 'mask 0x0FF0 · field = (word & mask) >> 4 · other bits kept']
<scratch>/tree/tests/test_b103_inc8b_s2.py:139: AssertionError: no framed bit table: ['└ IDENTICAL phys = (word & 0x0FF0) >> 4 · UWORD u16 big-endian · 0x00800010 · 2 B', 'bit 15…0 0001101011100111   word 1A E7 → 1A E7', 'mask 0x0FF0 · field = (word & mask) >> 4 · other bits kept']
<scratch>/tree/tests/test_b103_inc8b_s2.py:292: AssertionError: ['└ IDENTICAL phys = (word & 0x00FF0000) >> 16 · ULONG u32 big-endian · 0x00800010 · 4 B', 'bit 31…0 00010010000100100101011001111000   word 12 34 56 78 → 12 12 56 78', 'mask 0x00FF0000 · field = (word & mask) >> 16 · other bits kept']
<scratch>/tree/tests/test_b103_inc8b_s2.py:111: AssertionError: ('T.card.V171.line0', '+00 41 42 43 00 00 00 00 00 00 00 00 00 00 00 00 00')
<scratch>/tree/tests/test_b103_inc8b_s2.py:373: AssertionError: ['└ text · 0x00810200 · 8 B', '+00 00 1B 7F 80 FF 41 20 7E']
<scratch>/tree/tests/test_b103_inc8b_s2.py:385: AssertionError: assert False
<scratch>/tree/tests/test_b103_inc8b_s2.py:404: AssertionError: assert False
<scratch>/tree/tests/test_b103_inc8b_s2.py:414: assert False
<scratch>/tree/tests/test_b103_inc8b_s2.py:425: assert False
<scratch>/tree/tests/test_b103_inc8b_s2.py:307: AssertionError: (0, '+10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')
<scratch>/tree/tests/test_b103_inc8b_s2.py:314: AssertionError: assert False
<scratch>/tree/tests/test_b103_inc8b_s2.py:432: assert False
<scratch>/tree/tests/test_b103_inc8b_s2.py:328: assert 0 == 3
<scratch>/tree/tests/test_b103_inc8b_s2.py:439: assert False
<scratch>/tree/tests/test_b103_inc8b_s2.py:346: assert 0 == 3
<scratch>/tree/tests/test_b103_inc8b_s2.py:452: assert False
<scratch>/tree/tests/test_b103_inc8b_s2.py:362: assert [-7, -7] == [56, 56, 56, 56]
<scratch>/tree/tests/test_b103_inc8b_s2.py:465: AssertionError: (0, '( ) 0 温度   (●) 1 IDLE   ( ) 2 RUN   ( ) 3 FAULT   default "UNKNOWN_STATE"')
<scratch>/tree/tests/test_b103_inc8b_s2.py:474: AssertionError: assert False
<scratch>/tree/tests/test_b103_inc8b_s2.py:492: AssertionError: assert False
<scratch>/tree/tests/test_b103_inc8b_s2.py:504: AssertionError: assert 3 == 7
<scratch>/tree/tests/test_b103_inc8b_s2.py:512: AssertionError: assert (11 > 1 and False)
<scratch>/tree/tests/test_b103_inc8b_s2.py:525: AssertionError: assert 107 == 139
<scratch>/tree/tests/test_b103_inc8b_s2.py:536: AssertionError: assert ([<text '└ IDENTICAL phys = raw · SWORD s16 big-endian · RL_DEF_MAP · 0x00800070 …' [] ''>, <text '            224     ... '#ffffff on #313D59')] ''>, <text '                                                                     ' [] ''>, ...] and False)
<scratch>/tree/tests/test_b103_inc8b_s2.py:536: AssertionError: assert ([<text '└ IDENTICAL phys = raw · SWORD s16 big-endian · RL_DEF_MAP · 0x00800070 · 32 B' [] ''>, <text '              2...')] ''>, <text '                                                                                         ' [] ''>, ...] and False)
<scratch>/tree/tests/test_b103_inc8b_s2.py:552: AssertionError: assert (1 == 1 and False)
<scratch>/tree/tests/test_b103_inc8b_s2.py:536: AssertionError: assert ([<text '└ IDENTICAL phys = raw · SWORD s16 big-endian · RL_DEF_MAP · 0x00800070 · 32 B' [] ''>, <text '              2...')] ''>, <text '                                                                                         ' [] ''>, ...] and False)
==================================== PASSES ====================================
=========================== short test summary info ============================
PASSED tests/test_b103_inc8b_s2.py::test_r_pe_def_108_4_a_number_row_has_no_card
PASSED tests/test_b103_inc8b_s2.py::test_r_pe_bench_5_5_room_zero_shows_no_bench_line_and_no_exception
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_33_1_the_enum_options_sit_in_the_card_with_the_choose_hint
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_108_1_an_enum_row_shows_its_definition_line_then_a_framed_card
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_33_2_after_choosing_run_the_mark_moves_to_run
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_108_2_a_bit_mask_row_shows_a_six_line_card_of_73_cells
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_34_1_the_bit_table_at_start_shows_before_mask_after
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_34_2_the_after_row_reads_the_whole_word_not_the_field
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_34_3_a_single_bit_mask_marks_one_bit_and_keeps_the_other_bits
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_102_2_the_after_bits_that_differ_from_the_image_are_underlined
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_102_2_nothing_is_underlined_before_an_edit
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_109_1_a_32_bit_mask_word_is_two_blocks_of_16_high_bits_first
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_108_3_a_text_row_shows_its_card_top_line_of_78_cells
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_111_1_a_byte_outside_the_printable_range_shows_a_dot_in_the_ascii_column
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_79_4_a_span_over_64_bytes_ends_its_card_with_the_cut_line
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_112_1_a_300_entry_enum_is_cut_at_the_card_cap_with_one_ellipsis
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_112_2_a_300_character_name_cuts_the_title_not_the_frame
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_115_1_an_escape_in_the_card_title_is_painted_as_the_replacement_character
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_35_1_a_text_row_at_start_shows_the_hex_grid_16_per_row
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_35_2_pending_bytes_are_in_the_pending_colour_and_the_others_are_not
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_115_2_an_escape_in_a_card_row_is_painted_as_the_replacement_character
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_102_1_the_changed_bytes_and_their_ascii_are_underlined
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_115_3_a_markup_tag_in_a_card_row_is_literal_text_with_no_action
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_102_1_nothing_is_underlined_before_an_edit
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_116_1_a_wide_character_title_is_cut_by_cells_to_the_card_cap
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_110_1_the_ascii_guide_is_on_the_same_column_of_every_row_of_a_short_last_row
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_116_2_a_wide_row_keeps_the_frame_square_at_79_cells
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_116_3_a_wide_row_longer_than_the_cap_is_cut_by_cells
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_107_1_the_one_line_of_a_number_row_is_on_the_bar_and_the_expanded_ground
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_107_2_every_card_line_of_a_mask_row_follows_the_bar
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_107_3_every_bench_line_of_an_array_row_follows_the_bar
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_def_107_4_a_definition_line_wider_than_the_cut_is_cut_at_139_cells
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_bench_5_1_2_3_no_bench_line_is_wider_than_the_view[73-80]
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_bench_5_1_2_3_no_bench_line_is_wider_than_the_view[111-118]
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_bench_5_4_room_one_shows_the_definition_line_only
FAILED tests/test_b103_inc8b_s2.py::test_r_pe_bench_5_1_2_3_no_bench_line_is_wider_than_the_view[195-220]
34 failed, 2 passed in 1.37s
```

## Deviations, findings, gaps

- Fixture validity: the ULONG case (R-PE-DEF.109) and the 8-byte hostile ASCII case build Definitions with `dataclasses.replace` of I-2 output and run through the base's own preview (the base already shows `12 12 56 78`), so they are not hand-built stand-ins.
- Helper check (not a test): the column readers (`hex_rows`, `mask_after_style_columns`) were run once on rtx over the oracle's own card text (guides at 56, tokens 16/16/10, bit columns end on the header digit), so a correct render can pass them.
- Gap: R-PE-DEF.97/12 (card ground #0f1525) and the bar glyph/ground colour on card and bench lines (107/2, /3) are not asserted here; the colour tokens are T8b-S1's (.97). R-PE-DEF.103 (NO_COLOR keeps the underline) is not covered in this file.
- Gap: bit-table `?` for a bit the image does not hold (graph `bit_table` func) has no case in `02-test-cases.md`; not tested.
- R-PE-BENCH.5 is listed under group W in the roster but lives at `detail_lines`; covered here, T8b-BW should not duplicate it.
- For T8b-R: Inc 8 tests that assume the old lines (`tests/test_b103_inc8_s1_detail.py` `test_r_pe_def_33_*` (3 lines), `_34_*` (bit strip), `_35_*` (`+00 ` rows), `_79_*` (`len(out) == 6`), `_31_*` where they pin lines without the `  ┊ ` bar) break by design.
- Environment: nothing run on this PC (HT-01); no full suite; GREEN not run (integrator's). Scratch on rtx removed.
