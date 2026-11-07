# Inc 11 E4 — test faults for the tester pass (DeepSeek implementer)

The reader's product code (`a2l.py`, `a2l_extract.py`, `a2l_definition.py`) now
passes the implementation side of the integration. Every remaining failure in
run 3/5 is a fault on the test side, listed below by file. Nothing here is
changed in the product tree.

## 0. `tests/test_b103_a2l_reader_perf.py` — READ.52

- **Memory (the four `*_memory` arms) is a measurement artifact, not a reader
  fault.** The reader's true peak, measured in a fresh process, is
  `610 MB` (case_06, base 535 MB = 1.14×) and `98 MB` (software_a, base 95 MB
  = 1.03×) — inside the 2× bound. The arms' `_peak_mb` forks the pytest
  process (whose `ru_maxrss` is inflated by the `_min_time` 15-parses with GC
  off), so `ru_maxrss` is inherited and every arm reports the same ~6.43 GB.
  Fix `_peak_mb` to measure in a process whose parent has not accumulated the
  timing runs (or record the parent RSS and subtract it).
- **Time (the three `*_time` arms) is a real 2×** (case_06 11.7 s vs 5.9 s;
  software_a 1.36 s vs 0.65 s), above the 1.5× bound. The reader streams per
  line and tokenises the slow path with one compiled regex (the E3 ruling's
  fix), and the per-word diagnostic loop is now a compiled regex; this is the
  remaining gap, reported to the orchestrator for a ruling per
  `E3-rulings.md` ("if 1.5× is not reachable the implementer stops and the
  orchestrator rules with the measurement").

## 1. `tests/test_b103_a2l_reader.py` — synthetic-case faults (14)

- `test_r_a2l_read_1_cr_cr_lf_counts_two_ends` (`:214`) — `sec["start_line"] * 2
  - 1 == sec["end_line"]` computes `5 == 49`. PROJECT in the LF file spans lines
  2–25, so CR CR LF gives `start_line` 3 and `end_line` 49. The assertion mixes
  the doubled start into the end formula. Correct: `end_line == 49` (or
  `2*25 - 1`).
- `test_r_a2l_001_2_comment_not_read` (`:490`, LENGTH case) — `LENGTH 4` under
  the `FULL` UWORD header disagrees under the sizes rule (`4` vs the one count
  `1 × 2`), so the length is `None`, not `4`. Add `MATRIX_DIM 2` (agreeing) or
  expect `None`.
- `test_r_a2l_001_2_mod_common_comment_not_read` (`:505`) — the MEASUREMENT `X`
  is appended after `/end PROJECT`, outside the MODULE, so it never inherits
  MOD_COMMON's byte order. Put `X` inside the MODULE.
- `test_r_a2l_read_7_comment_between_digits_splits` (`:112`) — R-A2L-READ.23
  takes the tag name from the first word: "Synthetic map" → `Synthetic`.
- `test_r_a2l_read_12_cut_section_no_tag` (`:602`) — `_body()` appends
  `/end MODULE`, which closes the cut MEASUREMENT as the innermost section
  (R-A2L-READ.21), so a tag is produced. The [B13] shape needs a file with no
  trailing `/end` words (not `_body`).
- `test_r_a2l_read_14_words_after_close_carry_closing_line` (`:673`) — asserts
  `Line 5`, but `_body()`'s 19-line HDR puts the closing line at 23.
- `test_r_a2l_read_54_axis_pts_named_later` (`:804`) — searches
  `data["sections"]` (top level) for AXIS_PTS, which is nested inside MODULE.
  Recurse through `children`.
- `test_r_a2l_read_28_short_header_error` (`:1010`) and
  `test_r_a2l_read_62_short_characteristic_no_field` (`:112`) — name
  "Synthetic map" → first word `Synthetic`.
- `test_r_a2l_read_66_name_cut_256` (`:460`) — the two MEASUREMENTs carry zero
  header words (no datatype/conversion/limits), so `.28`'s 1–5-word error is
  never produced. Give them a 1–5-word header.
- `test_r_a2l_read_38_length_bounds` (`:1334`) and
  `test_r_a2l_read_39_length_error` (`:1341`) — `LENGTH 1048576` (and the other
  values) under a UWORD header disagrees with the one count `1 × 2`, so the
  length is `None` and no `.39` error fires. Use the case-07 form (no datatype)
  or an agreeing `MATRIX_DIM`.
- `test_r_a2l_read_38_definition_stays_refused` (`:1418`) — the `Definition`
  dataclass field is `refusal` (singular), not `refusals`.
- `test_r_a2l_read_67_not_closed` (`:1213`) — same as the cut-section case:
  `_body()`'s `/end MODULE` closes the MEASUREMENT.

## 2. `tests/support/b103_a2l_ref.py` — the oracle diverges from the reader on two counts

`test_r_a2l_read_48_tracked_files_equal_ref` now runs (the shared-string guard
is fixed) and stops at the first tag divergence; two oracle bugs follow it:

- `_read_span` reads a TYPEDEF_CHARACTERISTIC deposit as `theader[2]` (the
  ASAP2 1.6 with-address form). V171 is ASAP2 1.7.1, whose typedef has no
  MemoryAddress, so the deposit is `theader[1]`; `theader[2]` is MaxDiff and the
  VALUE/ASCII/MAP typedef INSTANCEs lose their length. Read `theader[1]` unless
  it is a number word (an address).
- `_read_tag` computes a CURVE/MAP length as the element size (1), not the
  inline-axis layout span (25/51, as AT-102 and the batch-55 base pin). The
  oracle should call `_layout_span(layout, axis_counts)` with the inline axis
  counts for the CURVE/MAP family.

## 3. `tests/fixtures/b103_i11/e07fb00_tags.jsonl` — `R-A2L-READ.49`

The fixture keeps the e07fb00 name `UNKNOWN` for the V161/V171 ASCII
CHARACTERISTIC. R-A2L-READ.23/4 names it `ASAM.C.ASCII.UBYTE.NUMBER_42`, so the
reader's tag is not in the fixture's expected set. Regenerate the fixture with
the new name.

## 4. `tests/test_a2l_multiline_headers.py`

- `test_at101_hostile_comment_corpus[unterminated_block_eats_mandatory]` and
  `[unterminated_quote]` — an unclosed `/*` or `"` now swallows
  `/end CHARACTERISTIC` (R-A2L-READ.10/.15), so the section has no `/end` word
  and no tag is produced (R-A2L-READ.12). These cases must expect `char is None`
  (or close the construct before `/end`).
- `test_at101_megabyte_unterminated_block_is_linear` — same; an unterminated
  `/*` gives no tag.

## 5. `tests/test_b101_a2l_blocks_and_segments.py:371`

`test_r_a2l_036_2_open_quote_ends_at_line` pins the base "string ends at its
line" behaviour. R-A2L-READ.14/.15 make an unterminated quote span to EOF
(`quoted string not closed`), so the MEMORY_SEGMENT has no record words and
base/size/offset are `None`. Close the quote on line 1 (or expect the new
error and no record words).

## 6. `tests/test_suite_hygiene.py:403`

`test_r_tst_002_every_timing_arm_carries_serial_timing` flags
`tests/test_b103_a2l_reader_perf.py::test_r_a2l_read_52_words_no_exception_and_one_error`,
which carries `@pytest.mark.serial_timing` but is not a timing arm. Drop the
marker (or exclude it from the rule).

## 7. `tests/test_b103_a2l_definition.py` — Inc 2a pins the old reader (24)

- `V171_ASCII = "UNKNOWN"` → R-A2L-READ.23/4 renames it; every test that uses
  `V171_ASCII` fails with `UNKNOWN: no tag of that name` (3_1, 33_1, 33_3, 34_1,
  34_2, 137_1, 58_1_1, 58_2_14, `at_b103_i2_1`).
- `test_r_a2l_def_58_2_15_v171_unclosed_begin` pins `v171["errors"]` truthy;
  V171 now has 0 errors (R-A2L-READ.17).
- `test_r_a2l_def_7_2_1…4`, `test_r_a2l_def_9_1`, `test_r_a2l_def_4_1` pin a
  LENGTH/DATA_SIZE that disagrees with the datatype under the sizes rule (D-6
  revised, R-A2L-READ.61), so the tag has no length and the refusal is
  `A2L-DEF-ADDRESS: no address or no length`.
- `test_r_a2l_def_58_2_20…23` (5,000 hex digits) pin the base `int(x, 0)`
  reading; R-A2L-READ.34 caps a number word at 16 hex digits, so the length is
  absent and the refusal is `no address or no length`.
- `test_r_a2l_def_139_3_commented_out_old_copy…` — R-A2L-READ.12: a commented
  copy gives no tag, so it is not a second declaration.
- `test_r_a2l_def_58_2_24_deep_nesting…` — R-A2L-READ.64 caps nesting at 32.
- `test_r_a2l_def_151_4` / `151_5` — the number rule (R-A2L-READ.34/.63) no
  longer accepts the oversized words those cases write.
