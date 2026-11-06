# Inc 2 — E1 slice: every file and function to add or change, counted and mapped

Base `332f8ca` (product tree `e07fb00`). Line numbers are as of `e07fb00`. Rows: `01-requirements.md`; decisions: `E1-rulings.md` §3 (the slice follows the recommended options; a different ruling is noted per item); interface I-2: `E1-rulings.md` §4. Real callers: `evidence-e1/i2e1-callers-transcript.txt` (Code-Wire v3.1.0 extractor over a throwaway copy of `e07fb00`, one mark per def, base line numbers).

## 1. Summary

| File | Functions | Rows |
|---|---|---|
| `s19_app/tui/a2l_definition.py` (**new**, the one source file of the increment) | 22 new functions and 6 frozen dataclasses (§2) | R-A2L-DEF.1 … .58; cited R-A2L-010, 011, 022 … 027, 030, 031, 033, 040, 043 … 045, 051, 053 … 058.3, 059, 061 … 063 |
| `tools/synth/make_release_case.py` (test-data tooling, not counted toward the source cap: PLAN D6) | 3 new functions; 1 changed (`main`, a `--case` option) (§4) | R-A2L-DEF.59 … .63 |
| `s19_app/tui/a2l.py` and every other source file | **unchanged** (`a2l.py` frozen; 7 private helpers and 2 public functions reused, §3) | — |

Count: 1 source file (cap 4). Graph nodes: 22 in the new module + 4 in the synth tool = 26 (PLAN estimate ~16; cap 40). No split (`E1-rulings.md` D-13).

## 2. New module `s19_app/tui/a2l_definition.py`

Pure: imports the standard library and `s19_app.tui.a2l` only (no `textual`, no I/O). Types (frozen dataclasses, no logic): `Refusal`, `Limits`, `EnumEntry`, `Definition`, `Decoded`, `Encoded` (I-2, `E1-rulings.md` §4).

| # | Function (new) | Does | Rows |
|---|---|---|---|
| 1 | `describe_definition(name, a2l_data) -> Definition` | I-2 entry: finds the tag, builds every field, applies the refusal order | .1 … .9, .24; cited R-A2L-010, 011, 024 … 027 |
| 2 | `_find_tag(name, a2l_data) -> tuple[dict, dict] \| None` | the first tag with exactly that name, and its own section: the same-position MEASUREMENT/CHARACTERISTIC section of a pre-order walk of `a2l_data["sections"]` (the walk order of `extract_a2l_tags`, `a2l.py:2592-2773`) | .5, .6 |
| 3 | `_object_kind(tag, conversion_type) -> tuple[str \| None, str]` | number / enum / text, or the `<kind>` text of a refusal | .1, .2, .3, .4 |
| 4 | `_resolve_datatype(tag, a2l_data) -> str \| None` | the tag's datatype, else its record layout's (`_resolve_record_layout`), else the datatype the deposit name spells (wraps S2 D2-8) | .8, .9; cited R-A2L-022, 023 |
| 5 | `_read_method_record(method_name, sections) -> dict \| None` | the COMPU_METHOD as the *conversion method record*: type, format, unit, COEFFS, COEFFS_LINEAR, COMPU_TAB_REF, comments left out; returns a dict of `extract_compu_methods`' shape so the reused conversion takes it | .10, .11, .12, .23; cited R-A2L-031, 033 |
| 6 | `_read_enum_table(table_name, sections) -> tuple[str, tuple[EnumEntry, ...], str \| None] \| None` | a COMPU_VTAB or COMPU_VTAB_RANGE read as the *enum table* format: entries in file order, default text | .13 … .17 |
| 7 | `_read_object_lines(section) -> dict` | the object's FORMAT, EXTENDED_LIMITS, PHYS_UNIT / UNIT and BIT_MASK words, comments left out | .18, .20, .21, .22; cited R-A2L-030 |
| 8 | `_check_bit_mask(mask, datatype) -> Refusal \| None` | 0, wider than the datatype, or on a float | .19 |
| 9 | `_display_decimals(display_format) -> int \| None` | the *display format* grammar; `None` when it gives no decimals; cap 17 | .35, .36, .37 |
| 10 | `decode_definition(definition, a2l_data, image) -> Decoded \| Refusal` | I-2: the definition's refusal, else the stored value, its value and display text | .25, .26, .28, .56, .58; cited R-A2L-040, 051, 053 … 058.3, 061 … 063 |
| 11 | `_read_stored_value(definition, image) -> int \| float \| bytes \| Refusal` | the span's bytes (missing count), the raw read (`_decode_scalar`, plus binary16), the masked field | .26, .27; cited R-A2L-043, 044, 045 |
| 12 | `_enum_text(definition, stored) -> str` | first matching pair or range, else the default text, else `<raw> (no text)` | .29 … .32; cited R-A2L-059 |
| 13 | `_ascii_text(raw: bytes) -> str` | bytes before the first 0x00, U+FFFD for a non-printable byte | .33, .34 |
| 14 | `display_text(definition, value) -> str` | the number display rules (I-2: Inc 3 reuses it per element) | .35 … .39 |
| 15 | `encode_definition(definition, a2l_data, text, image) -> Encoded \| Refusal` | I-2: the encode order, the bytes of the whole span from the address | .25, .53, .56, .57, .58 |
| 16 | `_parse_number_text(text) -> float \| None` | the *number text* grammar (not `float()`) | .40 |
| 17 | `_check_limits(definition, limit_value, text) -> Refusal \| str \| None` | refusal, the extended-limits notice, or nothing | .43, .44, .45 |
| 18 | `_encode_number(definition, a2l_data, value) -> bytes \| Refusal` | the encode direction through `encode_physical_to_raw_bytes` on a copy of the tag with no limits (its flags are not used: .43 … .45 and .54 replace them) and the record of #5 as its method table | .41, .42 |
| 19 | `_merge_bit_mask(definition, field: int, image) -> bytes \| Refusal` | the field shifted into the mask, the other bits from the image | .26, .46, .47 |
| 20 | `_encode_enum(definition, text) -> int \| Refusal` | the first entry with the text → its raw value (a range's min); packed through #18 with no conversion | .48, .49 |
| 21 | `_encode_ascii(definition, text) -> bytes \| Refusal` | length, printable ASCII, 0x00 padding | .50, .51, .52 |
| 22 | `_agrees_at_display_precision(definition, decoded, value) -> bool` | the CTX-A2L-DEF rule (decimals, 15 digits, FLOAT32/FLOAT64 digits) | .54, .55 |

Depends on a ruling: #6's range half and #12's range half (D-4); #17's extended branch (D-7); #22 and the guard in #15 (D-3); #2's exact match (D-10); #5, #6, #7 reading the sections themselves (D-2); the private imports of §3 (D-9).

## 3. Reused, unchanged (callers read: rule 8)

| Reused (all `s19_app/tui/a2l.py`, frozen) | Kind | Real callers today (C) | Used by (#) |
|---|---|---|---|
| `encode_physical_to_raw_bytes` (`:2368`) | public | `resolve_symbol_entry` (`services/change_service.py:649`) ← `ChangeService.add_symbol_entry` (`:1297`) ← none in product | 18, 20 |
| `parse_begin_meta` (`:255`) | public | `extract_a2l_tags`, `extract_record_layouts`, `extract_compu_methods`, `extract_compu_tables` | 2, 5, 6 |
| `_flatten_body_tokens` (`:422`) | private | `assemble_characteristic_header`, the AXIS_DESCR capture of `extract_a2l_tags` | 5, 6, 7 |
| `_split_line_respecting_quotes` (`:319`) | private | many parse helpers | 7 |
| `_collect_sections_by_name` (`:698`) | private | `extract_record_layouts`, `extract_compu_methods`, `extract_compu_tables` | 5, 6 |
| `_apply_compu_method` (`:1891`) | private | `enrich_a2l_tags_with_values` (`:2909`), `describe_curve_tag` (`:3155`, `:3202`), `_decode_external_axis_points` (`:3304`) | 10 |
| `_decode_scalar` (`:1811`) | private | `_decode_raw_value` (`:1830`, `:1834`), `_decode_component_run` (`:2975`) | 11 |
| `_resolve_record_layout` (`:1241`) | private | `_infer_length_characteristic` (`:1227`), `encode_physical_to_raw_bytes` (`:2490`), `enrich_a2l_tags_with_values` (`:2887`) | 4 |
| `_to_float` (`:293`), `DATATYPE_SIZES` (`:14`), `DATATYPE_STRUCT_CODES` (`:64`), `MAX_A2L_DECODE_BYTES` (`:62`) | private / public | many | 4, 9, 11, 16, 17 |

Read and not used by the model: `describe_curve_tag` (`:2993`; caller `S19TuiApp.action_a2l_describe_tag`, `app.py:9776`) — Inc 3's CURVE/MAP reuse; `parse_parameter_list` (`a2l_parameter_picker.py:75`; caller `BulkParameterAddScreen._apply_list`, `screens.py:1019`) — I-5, untouched; `extract_compu_methods` / `extract_compu_tables` (`:843`, `:898`; caller `parse_a2l_file` `:2832-2833`) — their side tables are passed through to #18 for COMPU_TAB numeric tables only; `enrich_a2l_tags_with_values` (`:2878`; callers `a2l_service.enrich_tags_and_render` `services/a2l_service.py:20`, `validate_characteristic` `:3472`) — the tag table's decode, not reused (it ignores BIT_MASK, TAB_VERB, binary16, ASCII). Defects of all of them: `E1-rulings.md` §5.

## 4. `tools/synth/make_release_case.py` (D6; D-5 A, D-6 A)

| # | Function | New / changed | Does | Rows |
|---|---|---|---|---|
| S1 | `build_definition_objects(rng: random.Random) -> tuple[dict[str, tuple[int, bytearray]], list[dict]]` | new | one calibration region; an enum VALUE (TAB_VERB method, COMPU_VTAB of ≥ 3 pairs and a DEFAULT_VALUE, stored value a pair's raw), two VALUEs with disjoint BIT_MASKs (one bit, several bits) on one word, one LINEAR VALUE with FORMAT, PHYS_UNIT and EXTENDED_LIMITS wider than its limits; planned values in the object list | .60, .61, .62 |
| S2 | `emit_definitions_a2l(regions, objects) -> str` | new | the case's A2L (own MOD_COMMON, RECORD_LAYOUTs, methods, tables, objects) | .60, .61, .62 |
| S3 | `generate_definitions_case(out_dir: Path, seed: int) -> dict[str, Path]` | new | writes `firmware.s19` (the existing `emit_s19`) and `firmware.a2l` | .60 … .63 |
| S4 | `main(argv)` (`:1048-1058`) | changed | `--case {release,definitions}`, default `release`; `release` runs `generate` exactly as today | .59, .63 |

Unchanged and reused by S3: `emit_s19` (`:532`), `_s3_line`, `_s0_line`, `_s7_line`, `_fmt_addr`, `_pack_scalar`. Unchanged and **not** called by the new case: `compute_region_sizes`, `build_objects`, `generate`, every case 08 emitter — so case 08's code path and its random-number sequence are not touched (the in-process rebuild of `tests/support/b101_demo_image.py:41-48` included). Callers of `main`: the `__main__` guard and `tests/test_synth_release_case.py::test_cli_entry_point` (subprocess, no `--case`: default). Callers of `generate`: `tests/test_synth_release_case.py:59`, `tests/test_b101_a2l_blocks_and_segments.py:119`, `tests/test_b101_check_spec_keep.py:123`, `tests/test_b101_inc11_acceptance.py:105`, `tests/test_b101_symbol_reads.py:93` (all unchanged; their outputs are pinned by .59).

## 5. Tests (E4 testers; not capped)

Proposed: `tests/test_b103_a2l_definition.py` (S2.7a … c, the cited rows, AT-B103-I2-1 and -3, and the D-9 guard that imports each private helper of §3 and checks its parameters) and `tests/test_b103_synth_definitions_case.py` (S2.7d, AT-B103-I2-2). The pin test (.59) reads its 22 digests from this record's transcript values, written into the test as constants with the transcript path in a comment. Existing tests are not edited.

## 6. Overlaps

| Touched by Inc 2 | Also touched by | How |
|---|---|---|
| `s19_app/tui/a2l_definition.py` | **Inc 3** (same file, after Inc 2) | Inc 3 adds functions and `Definition` fields with defaults; it changes none of §2's signatures (I-2 §4); its rows continue at R-A2L-DEF.64 |
| `tools/synth/make_release_case.py` | **Inc 3** (COM_AXIS, D6) | Inc 3 extends S1 and S2 of the definitions case; case 08 stays pinned by .59 |
| consumers of I-2 | Inc 6, Inc 8, Inc 9 | they call §2's #1, #10, #14, #15 only |
| case 08 outputs | batch-101 Inc 10, 11, 12 tests (another session) | read-only fixtures; .59 pins them |
| any other file of Inc 1a, 1b, 4 or batch-101 | — | none shared |
