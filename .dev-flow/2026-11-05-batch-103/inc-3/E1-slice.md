# Inc 3 — E1 slice: every file and function to add or change, counted and mapped

Base `9ae92c3` (product tree `e07fb00`). Line numbers are as of `e07fb00`. Rows: `01-requirements.md`; decisions: `E1-rulings.md` §3 (the slice follows the recommended options; a different ruling is noted per item); interface: `E1-rulings.md` §4 (I-2 extension). Real callers: `evidence-e1/i3e1-callers-transcript.txt` (Code-Wire v3.1.0 extractor over a throwaway copy of `e07fb00`, one mark per def, base line numbers). The module `s19_app/tui/a2l_definition.py` does not exist at `e07fb00`: Inc 2 creates it (`../inc-2/E1-slice.md` §2, its graph in E2 now); "changed" below means a function of Inc 2's slice that Inc 3 extends.

## 1. Summary

| File | Functions | Rows |
|---|---|---|
| `s19_app/tui/a2l_definition.py` (Inc 2's new module; the one source file of this increment) | 19 new functions, 3 new frozen dataclasses, `Definition` gains 6 fields with defaults; 4 of Inc 2's functions changed (§2) | R-A2L-DEF.64 … .132, .140 … .147 (.116, .117 split into .1 and .2 at E3; .147 at E3 round 2); cited R-A2L-DEF.5 … .7, .26, .58, .137, R-A2L-010, 011, 019, 024 … 027 |
| `tools/synth/make_release_case.py` (test-data tooling, not counted toward the source cap: PLAN D6) | 1 new function; 2 of Inc 2's new functions changed (§4) | R-A2L-DEF.133 … .135; cited .59, .63 |
| `s19_app/tui/a2l.py` and every other source file | **unchanged** (`a2l.py` frozen; private helpers reused, §3) | — |

Count: 1 source file (cap 4). Graph nodes: 19 new + 4 changed in the module, 1 new + 2 changed in the synth = 26 (PLAN estimate ~14; cap 40). No split (`E1-rulings.md` D-17).

## 2. `s19_app/tui/a2l_definition.py`

Types (frozen dataclasses, no logic; I-2 §4): `AxisDefinition`, `DecodedAxis`, `DecodedValues`; `Definition` gains `shape`, `element_count`, `index_mode`, `values_offset`, `record_layout`, `axes` (defaults keep Inc 2's scalars unchanged); `Position` is a type alias.

| # | Function | New / changed | Does | Rows |
|---|---|---|---|---|
| 1 | `describe_definition(name, a2l_data) -> Definition` | changed (Inc 2 #1) | dispatches the new kinds to #5; Inc 2's scalar path unchanged | .64 … .66, .104; cited .5, .6, .7 |
| 2 | `_object_kind(tag, conversion_type) -> tuple[str \| None, str]` | changed (Inc 2 #3) | gives array (VAL_BLK, MATRIX_DIM value count > 1 MEASUREMENT), curve, map; CUBOID and beyond keep A2L-DEF-KIND | .64 … .66 |
| 3 | `decode_definition(...)` | changed (Inc 2 #10) | the A2L-DEF-ELEMENTS refusal for the new kinds | .120 |
| 4 | `encode_definition(...)` | changed (Inc 2 #15) | the same refusal for one text | .120 |
| 5 | `_describe_array(tag, section, a2l_data, base) -> Definition` | new | builds shape, element count, byte length, record layout, values, axes in the array refusal order; fills every field it could read on a refusal | .67 … .81, .104 |
| 6 | `_read_matrix_dim(section) -> tuple[int, ...] \| Refusal \| None` | new | the MATRIX_DIM words, comments left out; trailing 1s dropped | .67, .71 |
| 7 | `_array_shape(tag, section, datatype, matrix) -> tuple[int, ...] \| Refusal` | new | MATRIX_DIM, else NUMBER, else length ÷ size; the LENGTH/DATA_SIZE check | .67 … .70, .74, .76 |
| 8 | `_read_record_layout(name, a2l_data, owner) -> RecordLayout \| Refusal` | new | the RECORD_LAYOUT lines comments left out: components, layout keywords (FIX_NO_AXIS_PTS, ALIGNMENT, DIRECT), index modes, point orders, address types, datatypes, positions | .82 … .87, .90 |
| 9 | `_place_components(layout, counts) -> dict[str, int] \| Refusal` | new | the offsets, by `_walk_record_layout_components` on a cleaned layout (components in position order + the layout's ALIGNMENT lines) | .75, .77, .88 |
| 10 | `_check_module_alignment(layout, counts, section, a2l_data) -> Refusal \| None` | new | MOD_COMMON's ALIGNMENT lines of the object's module; the offsets again with them; the refusal when an offset moves (D-7 C: withdrawn under A or B) | .89 |
| 11 | `_read_axis(axis_section, letter, layout, a2l_data) -> AxisDefinition \| Refusal` | new | the axis header words; kind; point count; STD component / FIX points / COM object; MONOTONY; the point element definition through Inc 2's builders | .91 … .103, .141 … .143 |
| 12 | `_find_axis_object(ref, a2l_data) -> tuple[dict, list[str]] \| None` | new | the AXIS_PTS section of that name in a pre-order walk of `a2l_data["sections"]`, and its header words | .94, .96, .97, .113 |
| 13 | `_fixed_points(axis_words, axis_section) -> tuple[float, ...] \| None` | new | FIX_AXIS_PAR, FIX_AXIS_PAR_DIST, FIX_AXIS_PAR_LIST (D-10 A) | .98, .99, .110 … .112, .141, .142 |
| 14 | `_element_definition(definition, position) -> Definition` | new | the element definition of one element or axis point: Inc 2's scalar fields, the component datatype, the element name, the address of its bytes | .105, .121, .122 |
| 15 | `decode_values(definition, a2l_data, image) -> DecodedValues \| Refusal` | new (I-2) | the definition's refusal, the record's bytes (Inc 2's A2L-DEF-BYTES), current counts, every element and axis point in element order | .105, .119, .124; cited .26, .58 |
| 16 | `_element_offset(definition, index) -> int` | new | ROW_DIR and COLUMN_DIR (D-2 A) | .106, .107 |
| 17 | `_point_offset(axis, k) -> int` | new | INDEX_INCR and INDEX_DECR | .108, .109 |
| 18 | `_current_count(axis, record) -> int \| Refusal` | new | NO_AXIS_PTS from the record, FIX_NO_AXIS_PTS, else the point count; 0 / above / below (D-3 A) | .90, .115 … .117 |
| 19 | `_decode_axis(definition, axis, a2l_data, image, record) -> DecodedAxis \| Refusal` | new | STD from the record, FIX from its points, COM from its axis object's record in that object's byte order, none (D-8 A) | .100, .113, .114, .118 |
| 20 | `_decode_stored(element_definition, a2l_data, stored) -> Decoded \| Refusal` | new, or the second half of Inc 2's `decode_definition` split out (the E2 graph decides) | conversion and display text of a stored value that has no bytes (a FIX_AXIS point) | .110 … .112 |
| 21 | `encode_values(definition, a2l_data, edit, image) -> Encoded \| Refusal` | new (I-2) | the array encode order: decode the record, positions, fixed / shared / no-points refusals, each element through Inc 2's `encode_definition` on its element definition, the monotony of X then Y; the whole record from the image with the edited bytes | .122 … .130; cited .58 |
| 22 | `_breaking_point(axis, stored_points) -> int \| None` | new | the monotony rule (D-5 A) | .129 |
| 23 | `element_name(definition, position) -> str` | new (I-2) | `<name>[i,j]`, `<name>.X[k]` | .121, .125 |

Not a function: the round-trip rows .131 and .132 are properties of #21 with #15 (tested as properties, `02-test-cases.md`).

Depends on a ruling: #16's COLUMN_DIR half and .80's guard (D-2); #18's partial refusal (D-3); #21's shared-axis refusal (D-4); #22 (D-5); #7's NUMBER and LENGTH branches (D-6); #10 (D-7); #19's no-points branch (D-8); #11's axis-kind refusal (D-9); #13, #20 (D-10); #11's conversion and count source (D-11); #8, #9 reading the sections and reusing the walk (D-12).

## 3. Reused, unchanged (callers read: rule 8)

| Reused (all `s19_app/tui/a2l.py`, frozen) | Kind | Real callers today (C) | Used by (#) |
|---|---|---|---|
| `_walk_record_layout_components` (`:1538`) | private | `_record_layout_full_span` (`:1805`), `_resolve_record_layout_components` (`:1740`), `_encode_curve_record_bytes` (`:2280`), `_decode_external_axis_points` (`:3278`) | 9, 10 |
| `_strip_a2l_comments` (`:353`) | private | `_flatten_body_tokens` (`:456`) | 6, 8, 11, 12 |
| `_flatten_body_tokens` (`:422`) | private | `assemble_characteristic_header` (`:653`), `extract_a2l_tags` walk (`:2729`) | 11, 12, 13 |
| `_split_line_respecting_quotes` (`:319`), `parse_begin_meta` (`:255`) | private / public | many parse helpers (R, not in the census) | 8, 12 |
| `_byte_order_from_section_lines`, `_normalize_byte_order` (`:311`, `:302`) | private | `extract_a2l_tags` (`:2587`, `:2682`, `:2757`) (R, not in the census) | 19 (the axis object's byte order, R-A2L-024 … 027) |
| `DATATYPE_SIZES` (`:14`), `_DATATYPE_ALIGNMENT_DIRECTIVE` (`:37`), `_ALIGNMENT_DIRECTIVES` (`:56`), `MAX_A2L_DECODE_BYTES` (`:62`) | public / private | many | 7, 8, 9, 10 |
| Inc 2's `_read_method_record`, `_read_enum_table`, `_read_object_lines`, `_check_bit_mask`, `_read_stored_value`, `_enum_text`, `display_text`, `_encode_number`, `_merge_bit_mask`, `_encode_enum`, `_check_limits`, `_agrees_at_display_precision` | Inc 2 new | Inc 2's slice | 11, 14, 15, 20, 21 (per element) |

Inc 2's D-9 guard test (imports each private `a2l.py` helper and checks its parameters) gains the five private names above that Inc 2 does not already import (`_walk_record_layout_components`, `_strip_a2l_comments`, `_byte_order_from_section_lines`, `_DATATYPE_ALIGNMENT_DIRECTIVE`, `_ALIGNMENT_DIRECTIVES`).

Read and **not** reused (each carries a defect an Inc 3 row contradicts, `E1-rulings.md` §5): `describe_curve_tag` (`:2993`; caller `S19TuiApp.action_a2l_describe_tag`, `app.py:9776`), `render_curve_description` (`:3347`; caller `CurveDescriptionScreen.compose`, `a2l_describe.py:70`), `_axis_counts_resolving_external` (`:1348`; callers `describe_curve_tag` `:3079`, `extract_a2l_tags` `:2788`), `_decode_external_axis_points` (`:3254`; caller `describe_curve_tag` `:3172`), `_axis_compu_method` (`:2982`; caller `describe_curve_tag` `:3137`), `_decode_component_run` (`:2953`; callers `describe_curve_tag` `:3147`, `:3195`, `_decode_external_axis_points` `:3298`), `_inline_axis_counts` (`:1277`; callers `extract_a2l_tags` walk `:2744`, `_encode_curve_record_bytes` `:2275`, `_decode_external_axis_points` `:3272`), `_encode_curve_record_bytes` (`:2195`; caller `encode_physical_to_raw_bytes` `:2462`, whose only caller is `resolve_symbol_entry`, `change_service.py:649`, with no product caller above it), `_infer_length_characteristic` / `_infer_length_measurement` (`:1187`, `:1164`; caller the `extract_a2l_tags` walk `:2723`, `:2721`). `A2LParameterPicker.set_parameters` (`a2l_parameter_picker.py:526`; callers `CheckEditorPanel.set_a2l_parameters` `screens_directionb.py:7303`, `PatchEditorPanel.set_a2l_parameters` `:5388`) is Inc 6's; it will read #1's `element_count` and `byte_length`.

## 4. `tools/synth/make_release_case.py` (D6; D-15 A)

| # | Function | New / changed | Does | Rows |
|---|---|---|---|---|
| S1 | `build_definition_objects(rng)` | changed (Inc 2's S1) | appends the array objects of S5 to the definitions case's object list and image, after Inc 2's objects (Inc 2's planned values do not move) | .133 … .135 |
| S2 | `emit_definitions_a2l(regions, objects)` | changed (Inc 2's S2) | writes the new RECORD_LAYOUTs (single-size components only), the AXIS_PTS object, the AXIS_DESCRs, the methods, the MAP and VAL_BLK | .133 … .135 |
| S5 | `_definition_array_objects(rng, cursor) -> list[dict]` | new | plans the two COM_AXIS curves and their axis object (strictly increasing points, count = max), the STD/FIX map (COLUMN_DIR, nX ≠ nY ≥ 3), the 2-D ROW_DIR VAL_BLK (n1 ≠ n2 ≥ 2), each with its planned values per element index | .133 … .135 |

Unchanged: Inc 2's `generate_definitions_case` (S3) and `main` (S4); every case 08 function (`compute_region_sizes`, `build_objects`, `generate`, the emitters): case 08's code path and random-number sequence are not touched (Inc 2's R-A2L-DEF.59 pin). Callers of the case 08 functions are Inc 2's census (`../inc-2/E1-slice.md` §4).

## 5. Tests (E4 testers; not capped)

Proposed: `tests/test_b103_a2l_definition_arrays.py` (S2.7e … S2.7h, the cited-row cases, AT-B103-I3-1, -3, -4) and additions to Inc 2's `tests/test_b103_synth_definitions_case.py` (S2.7i, AT-B103-I3-2). Existing tests are not edited. The D-9 guard test of Inc 2 gains the names of §3.

## 6. Overlaps

| Touched by Inc 3 | Also touched by | How |
|---|---|---|
| `s19_app/tui/a2l_definition.py` | **Inc 2** (creates it; E2 now) | Inc 3 changes 4 of Inc 2's functions (§2 #1 … #4) and adds fields with defaults; no Inc 2 signature changes (I-2 §4). Inc 3's E2 waits for Inc 2's graph (the brief's order) |
| `tools/synth/make_release_case.py` | **Inc 2** (the definitions case) | Inc 3 extends Inc 2's S1 and S2 and adds S5; case 08 stays pinned by .59 |
| Inc 2's records | Inc 2's next record pass | the case changes of `E1-rulings.md` D-14 |
| consumers of I-2 | Inc 6, Inc 9 | they call §2's #1, #15, #21, #23 |
| any file of Inc 1a, 1b, 4 or batch-101 | — | none shared |

## 7. Split (amendment A2)

Amendment A2 (`../PLAN.md`) splits the increment as it splits Inc 2. **3a**, the read side, runs on Inc 2a. **3b**, the write side, waits for Inc 2b and Inc 11. The current contracts are the graph's (`codewire/graph-inc3.md`, "Rebase on Inc 2's E3" and "Split (amendment A2)"); §2's table is E1's. The rebase on Inc 2's E3 changed four entries of it:
- **#1** is now `describe_definitions` (Inc 2's E3A-01: `describe_definition` delegates to it and is unchanged).
- **#12 `_find_axis_object`** and E2's **`_module_common`** are lookups in maps that `describe_definitions`'s one walk builds (`axis_pts_by_name`, `mod_common_of`), not walks per object (E3A-32); `_collect_sections_by_name` is no longer reused (§3).
- E2's **`_conversion_fields`** reads Inc 2's `compu_methods_by_name` / `compu_tables_by_name` and returns the method record's `coeffs_linear`, `coeffs`, `compu_tab_ref` (E3A-03); **#14 `_element_definition`** is a `dataclasses.replace` of the object's definition (E3A-22).
- **#20 `_decode_stored`** converts from the definition's method fields, never from `sections` (E3A-03).
- The coverage pass before 3a's E3 (`E2-rulings.md`, orchestrator rulings on the rebase and split) changed one more: **#13 `_fixed_points`** gains `point_count` and gives, beside the points and `None` (.98), `"unreadable"` (.141) and the count it gives when that is not the point count (.99), so it never builds more than 1,048,576 points (.142). #11 `_read_axis` gains .141 … .143. No function is added; the counts below do not change.
- The E3 round-1 correction (`E3-rulings.md`) changes four more and adds one:
  - **#13 `_fixed_points`** now builds the stored points of a FIX_AXIS at decode only, from `AxisDefinition.fixed_rule` (the FIX parameters), called by #19 `_decode_axis` after #15 has found the record's bytes in the image (E3A-01 = E3S3-02). #11 `_read_axis` reads and checks those parameters (.98, .99, .141) and builds no point.
  - **#18 `_current_count`** reads only a NO_AXIS_PTS count from the image, in a count datatype (E3A-22, E3S3-01). It tests the count positively: equal to the point count, else PARTIAL from 1 up, else CURRENT (E3A-13, E3S3-05).
  - **#10 `_check_module_alignment`** reports an unreadable MOD_COMMON ALIGNMENT line (R-A2L-DEF.144, E3A-09).
  - **#8 `_read_record_layout`** refuses a float NO_AXIS_PTS datatype (.86) and a component line with extra words (.84/7).
  - **`_describe_one`**, Inc 2a's per-name function (`a2l_definition.py:324-572` at `82f5f8e5`), joins the changed 3a functions (E3A-04). It holds the kind branch to #5, the VALUE's R-A2L-DEF.145 check and the element count `None` of a kind `""` definition. `_conversion_fields` takes its `:406-430` and `:496-530`, with Inc 2a's tests as the guard and no 2a test edited for it.
- The E3 round-2 correction (`E3-rulings.md`, "Round 2 rulings") changes eight contracts and adds no function (the counts below do not change):
  - **#11 `_read_axis`** computes a FIX axis's first and last points exactly from its parameters and refuses a magnitude above 2^53 or a shift that is not a whole number of at most 62 (R-A2L-DEF.147, E3S3-09, -10). **#13 `_fixed_points`** computes every point the same exact way, so the decode cannot overflow.
  - **#1 `describe_definitions`** starts `reads`, a map keyed by section identity. **#8 `_read_record_layout`** (gains `maps`) and E2's **`_module_common`** (takes `maps`, gives the MOD_COMMON's read form) read each RECORD_LAYOUT and MOD_COMMON once per walk; **#10 `_check_module_alignment`** reads that form and no line (E3S3-11). #8 also gives `<word>` `(none)` for a missing datatype word (E3S3-08).
  - **#5 `_describe_array`** and **`_describe_one`** give shape `()`, no element count and no byte length to a map with an axis not read and to a definition refused by .145 (E3A-24).

| Side | Functions (§2 number, or added at E2) | Count |
|---|---|---|
| 3a | #1 `describe_definitions` (changed), #2 `_object_kind` (changed), #3 `decode_definition` (changed), #5 `_describe_array`, #6 `_read_matrix_dim`, #7 `_array_shape`, #8 `_read_record_layout`, #9 `_place_components`, #10 `_check_module_alignment`, #11 `_read_axis`, #12 `_find_axis_object`, #13 `_fixed_points`, #14 `_element_definition`, #15 `decode_values`, #16 `_element_offset`, #17 `_point_offset`, #18 `_current_count`, #19 `_decode_axis`, #20 `_decode_stored`, #23 `element_name`, `_conversion_fields` (E2), `_module_common` (E2), `_describe_one` (changed; Inc 2a's, E3A-04) | 23 |
| 3a, synth (§4) | S1 `build_definition_objects`, S2 `emit_definitions_a2l` (changed), S5 `_definition_array_objects` | 3 |
| 3b | #4 `encode_definition` (changed; Inc 2b's function), #21 `encode_values`, #22 `_breaking_point` | 3 |
| 3b, added inside a 3a function | `describe_definitions`: the AXIS_PTS entries of R-A2L-DEF.138's span index (Inc 2 E3 census ruling; R-A2L-DEF.140, counted, `01-requirements.md` S2.7h) | — |

What each side reuses from §3:
- **3a** imports, beyond Inc 2a's list, `_walk_record_layout_components`, `_strip_a2l_comments`, `_split_line_respecting_quotes` (back in D-9's list, graph baseline), `_byte_order_from_section_lines`, `_DATATYPE_ALIGNMENT_DIRECTIVE`, `_ALIGNMENT_DIRECTIVES`, `MAX_A2L_DECODE_BYTES`. It reuses Inc 2a's own helpers (E3A-04): `_clean` (U+FFFD, R-A2L-DEF.137), `_finite_number` (the FIX words, .141), `_read_limits` (the axis limits), `_parse_bit_mask`, `_read_count` (the rule of CTX *whole number*), `_with_refusal` and `_fmt_address` (`<address>`).
- **3b** reuses Inc 2b's encode functions per element; `_encode_curve_record_bytes` stays unused (it is the oracle of the negative controls of R-A2L-DEF.123/4 and .132).

Source files and consumers:
- **Source files.** Each side touches 1 source file, `s19_app/tui/a2l_definition.py`. The synth tool is 3a only and is not counted (PLAN D6).
- **Consumers (§6).** Inc 6 needs only 3a (#1's `element_count`, `byte_length`, `kind`, `shape`). Inc 9 also needs #21, which is 3b.

Tests (§5):
- **3a** adds its cases to `tests/test_b103_a2l_definition_arrays.py` (S2.7e, S2.7f, S2.7g's 3a cases, the cited cases, AT-B103-I3-1's and -3's 3a arms, AT-B103-I3-4), updates the Inc 2 tests D-14 changes, and adds S2.7i and AT-B103-I3-2's 3a arm to `tests/test_b103_synth_definitions_case.py`.
- **3b** adds S2.7h, .120/2, .121/1, .121/2 and the edit arms to the same two files.
