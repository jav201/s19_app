# Code-Wire graph — Inc 3 (A2L definition model II: arrays and axes), batch-103

Stage E2 of the design-first flow (`dev-flow-v3-beta`). Graph only: no stub, mark or declaration in any tree. Base `batch-103` at `3404110` (product tree `e07fb00`). Requirements `../01-requirements.md` (R-A2L-DEF.64 … .135), cases `../02-test-cases.md`, rulings `../E1-rulings.md` (orchestrator rulings at its end: D-1 A … D-17, D-7 **C**, D-14 carried here), slice `../E1-slice.md`, plan `../../PLAN.md` (I-2, A1). Notation: Code-Wire v3.1.0 (`e436a08`, `docs/Notation-Grammar.md`), as in `../../inc-2/codewire/graph-inc2.md`.

**This is a delta file.** Its base is Inc 2's design, which is not code yet: `../../inc-2/codewire/graph-inc2.md` (43 nodes, as corrected by Inc 2's E3 rounds 1–5 and split by amendment A2) with `../../inc-2/E2-rulings.md` (P-1 `bit_mask_text` accepted; the I-2 extension D-1 pinned) and `../../inc-2/E3-rulings.md` (this file is rebased on it: "Rebase on Inc 2's E3" below). This file holds only the nodes Inc 3 adds or changes, plus five unchanged `a2l.py` functions Inc 3 newly reuses or reads. Every other Inc 2 node is cited by name and keeps its Inc 2 contract and examples (for example `_read_method_record`, `_read_enum_table`, `_read_stored_value`, `_enum_text`, `display_text`, `_encode_number`, `_merge_bit_mask`, `_encode_enum`, `_check_limits`, `_check_bit_mask`, `_display_decimals`, `_parse_number_text`, `_agrees_at_display_precision`, `_find_tag`, `_resolve_datatype`, `_read_object_lines`, `describe_definition` (it delegates to `describe_definitions`, Inc 2's E3A-01), `generate_definitions_case`, `main`, and the `a2l.py` context `_flatten_body_tokens`, `_decode_scalar`, `_apply_compu_method`, `parse_begin_meta`, `_to_float`). Inc 2a is at E4 and Inc 2b waits for Inc 11; nothing here edits Inc 2's files.

How to read it:
- Every node's `func:` starts with **unchanged** (baseline context), **changed** ("was: … / now: …"; the base is Inc 2's graph) or **new**. `a2l.py` is frozen: no node of it changes.
- Example sources are the case ids of `../02-test-cases.md` (`R-A2L-DEF.N/k`, `R-A2L-0NN/arr-k`, `AT-B103-I3-k`) and, for the Inc 2 cases this increment changes (D-14), Inc 2's ids marked **changed**. Evidence (all tool output, `evidence-e2/`): **B3** = probe 1 (`i3e2-probe-transcript.txt`, tags `[P…]`), **B3b** = probe 2 (`i3e2-probe2-transcript.txt`, `[Q…]`), **B3c** = probe 3 (`i3e2-probe3-transcript.txt`, `[R…]`), **C3** = this stage's caller census (`i3e2-extract-census-transcript.txt`), **B1** / **C1** = the E1 pilot and census (`../evidence-e1/`), **R** = read in the code at `e07fb00`. The probes parse every fixture with the app's own parser and run a **throwaway simulation** of this graph's rules (in the probe files only) — so an example value is the fixture's real content passed through the rule written here. All runs: LAN host cachyos-rtx, Python 3.11.18, read-only clone at `e07fb00`, HOME/XDG/LOCALAPPDATA under `/tmp/b103-e2-3/home`, no display, no clipboard.
- Fixtures as in `../02-test-cases.md`: **V171** (little-endian; MOD_COMMON `ALIGNMENT_BYTE 1`, `ALIGNMENT_WORD 2`, `ALIGNMENT_LONG 4`, `ALIGNMENT_FLOAT32_IEEE 4`, `ALIGNMENT_FLOAT64_IEEE 4`), **SOFTA**, **CHECK**, **UPD1**, **UPD2**, **C08** (1 MiB, seed 20260001), **DEFC** (pinned below), **INLINE3** (MOD_COMMON `MSB_FIRST`, no ALIGNMENT; INLINE methods have format `%.3`). **AX8(c, p…)** is the V171 axis object's 9-byte record. An image is an address → byte mapping.
- An example whose E1 case cannot hold on a correct model is written with the corrected input or the PROPOSED reading and listed in `## Findings`.

### Rebase on Inc 2's E3 (2026-11-06, `../E2-rulings.md` "Rebase on Inc 2's E3 corrections")

What this pass changed, against Inc 2's I-2 as `graph-inc2.md` now pins it (targeted edits; the rows of `../01-requirements.md` keep their text):
- **The changed describe node is `describe_definitions`** (E3A-01): `describe_definition` is now `describe_definitions([name], a2l_data)[name]` and every rule lives in the batch walk, so Inc 3's change lands there; `describe_definition` is unchanged and every example below is written per name, through it.
- **Lookups in the one walk (E3A-32).** The AXIS_PTS sections by name and each object's MOD_COMMON (by identity, from the enclosing MODULE) are maps built in `describe_definitions`'s single walk, beside Inc 2's method and table maps; `_find_axis_object`, `_module_common` and `_conversion_fields` are lookups in them. Cost measured (Interfaces, *Lookups*): ≈ 1.0 s for software_a against R-A2L-DEF.136's 2.0 s.
- **The method record on the definition (E3A-03, E3A-22).** `coeffs_linear`, `coeffs` and `compu_tab_ref` have no defaults: `_conversion_fields` returns them, an axis's points definition carries its own method's, every element definition is a `dataclasses.replace` of its object's, and `_decode_stored` converts from those fields, never from `sections`.
- **Rows split by Inc 2's E3:** R-A2L-DEF.7 → .7.1 / .7.2 (an array's byte length meets .7.2's bounds), .58 → .58.1 / .58.2; the cited cases `.7/arr-k`, `.58/arr-k` are now `.7.1/arr-k`, `.58.1/arr-k`.
- **R-A2L-DEF.139 replaces the first-tag rule (E3S-35):** case R-A2L-DEF.5/arr-1 changes and R-A2L-DEF.139/arr-1 is added (finding R-1).
- **R-A2L-DEF.137 (U+FFFD):** every Inc 3 message echoes a file or operator word as Inc 2's do.
- **E2 rulings applied:** P-2 `count_datatype` and E2-1 accepted; E2-6 accepted.
- **Split (amendment A2):** 3a / 3b, section "Split (amendment A2)" below. The findings of Inc 2's E3 that apply to this design are listed, with their coverage, in `../E2-rulings.md` (facts; the orchestrator rules).
- **Coverage pass before 3a's E3** (`../E2-rulings.md`, orchestrator rulings on the rebase and split): cases for R-A2L-DEF.7.2, .137 and E3S-01 on arrays and axes; .58.2's hostile reads (CTX-A2L-DEF *whole number*: no `int()` on a word of more than 9 digits; R-A2L-DEF.141 the FIX_AXIS words and points, .142 the point counts, .143 the axis object's record); the precision rule and E3S-06 on elements (3b: .122/5 … /7, two objects in .131's grid); R-A2L-DEF.140 counted (3b); the D-14 cases written into `../02-test-cases.md`. No node, edge or entity is added; `_fixed_points` gains `point_count`.
- **E3 round-1 correction** (`../E3-rulings.md`; findings `../E3-architect.md` E3A-NN, `../E3-security.md` E3S3-NN). The changes:
  - **FIX points at decode** (E3A-01 = E3S3-02). The I-2 field `fixed_points` becomes `fixed_rule`, the FIX parameters. `_read_axis` checks them in O(1) and builds no point; `_fixed_points` builds the points at decode, for `_decode_axis`.
  - **Count datatype** (E3S3-01, -05; E3A-13, -22). A NO_AXIS_PTS count must have an integer datatype (R-A2L-DEF.86). `_current_count` tests the count positively, reads the image only, and refuses a count below 1 as CURRENT.
  - **Kind and element count.** A MEASUREMENT with a multi-value MATRIX_DIM line is an array whatever its leading 1s (E3A-02). An unknown element count is `None` (E3A-03).
  - **Nodes.** `_describe_one` is added as a changed node (E3A-04). The axis header is read from `[meta] + lines` (E3A-05; CG-4).
  - **New rows.** R-A2L-DEF.144 (an unreadable MOD_COMMON alignment, E3A-09), .145 (a MATRIX_DIM on a CURVE, MAP or VALUE, E3A-10), .146 (`decode_values` on a scalar kind, E3A-18, E2-5).
  - **Splits.** .116 / .117 become .116.1 / .116.2 and .117.1 / .117.2 (E3A-07).
  - **Other fixes.** A component line with extra words (E3A-08); the address word (E3A-14); .91's message (E3A-15); .119/2 → .105/5 (E3A-16); .110/2 and .84/6 (E3A-17).
  - **Consumer notes** (E3S3-03, -04). The .136 estimate is ≈ 1.2–1.3 s (E3A-12).
  - **Cost** (cachyos-rtx, Python 3.11.18, throwaway `i3e3c-fix-probe.py`, transcript in the session scratchpad `…\scratchpad\e3c3\`, host `/tmp/b103-e3c-3/`). Describing 50 FIX curves at the cap plus 50 FIX maps of two such axes takes 0.031 s and a 0.14 MiB peak; the round-1 rule takes 214 s and 6,007 MiB (F1). One 1,048,576-point FIX axis built at decode takes 0.965 s and 48 MiB (F2). Inc 2a's software_a describe takes 1.007 s (median, F3).

### Groups for E4 (file ownership)

| Group | Files | Owns nodes |
|---|---|---|
| G1 model | `s19_app/tui/a2l_definition.py` (Inc 2's new module); tests `tests/test_b103_a2l_definition_arrays.py` (tester G-T1: S2.7e … h, the cited-row cases, AT-B103-I3-1, -3, -4) and the Inc 2 tests D-14 changes (`tests/test_b103_a2l_definition.py`: R-A2L-DEF.4/1, /2, /3, /7, .24/1, AT-B103-I2-3) | the 26 module nodes below: 5 changed (`_describe_one` added at E3, E3A-04), 21 new |
| G2 synth | `tools/synth/make_release_case.py` (additive, A1 rule 2); tests: additions to `tests/test_b103_synth_definitions_case.py` (tester G-T2: S2.7i, AT-B103-I3-2) | `build_definition_objects`, `emit_definitions_a2l`, `_definition_array_objects` |

As in Inc 2, one implementer can cover G1 and G2 (no G2 node imports `s19_app`; the seam is the DEFC object list, I-D below). **Order:** Inc 3a's E4 starts on the tree that holds Inc 2a's implemented module (3a extends three of its functions); Inc 3b's E4 on the tree that holds Inc 2b's (after Inc 11; 3b extends `encode_definition`); D-9's rename guard test gains the private `a2l.py` names of the baseline table.

### Baseline — existing code in scope, with real callers

| Function (`a2l.py`, frozen) | Inc 3 use | Real callers today (C3, base line numbers) |
|---|---|---|
| `_walk_record_layout_components` (`:1538`) | **reused** by `_place_components` on a cleaned layout (D-12 A) | `_decode_external_axis_points` (`:3278`), `_encode_curve_record_bytes` (`:2280`), `_record_layout_full_span` (`:1805`), `_resolve_record_layout_components` (`:1740`) |
| `_strip_a2l_comments` (`:353`) | **reused** to clean layout and object lines while keeping line ends | `_flatten_body_tokens` (`:456`) |
| `_split_line_respecting_quotes` (`:319`) | **reused** to split a cleaned line (back in D-9's import list; Inc 2 dropped it, its E2-14) | 10 functions of `a2l.py` (`:313`, `:456`, `:482`, `:613`, `:674`, `:718`, `:795`, `:848`, `:873`, `:909`, `:913`, `:2712`) |
| `_byte_order_from_section_lines` (`:311`) | **reused** for the axis object's and the module's byte order (R-A2L-024 … 027, R-A2L-DEF.114) | `extract_a2l_tags.<locals>._module_byte_order` (`:2587`), `extract_record_layouts` (`:723`) |
| `_flatten_body_tokens`, `_decode_scalar` (Inc 2 context; `_collect_sections_by_name` is no longer reused: the AXIS_PTS lookup is a map of `describe_definitions`'s walk, E3A-32) | reused: AXIS_PTS and axis header words, the count component | as in Inc 2's graph (C3 confirms: `:714`, `:846`, `:902`; `:653`, `:2729`; `:1830`, `:1834`, `:2975`) |
| `_encode_curve_record_bytes` (`:2195`) | **not reused** (D-12 A; BL-I3-7) | `encode_physical_to_raw_bytes` (`:2462`) ← `resolve_symbol_entry` (`services/change_service.py:649`) ← no product caller (C1) |
| `describe_curve_tag`, `_axis_counts_resolving_external`, `_decode_external_axis_points`, `_inline_axis_counts`, `_infer_length_*` | **not reused** (D-12 A; BL-I3-1 … -6) | E1's census (`../evidence-e1/i3e1-callers-transcript.txt`); `describe_curve_tag` ← `S19TuiApp.action_a2l_describe_tag` (`app.py:9776`, C3) |
| Inc 2a's helpers (`a2l_definition.py` at `82f5f8e5`, not `a2l.py`; E3A-04): `_clean` (`:135`), `_finite_number` (`:151`), `_fmt_address` (`:162`), `_parse_bit_mask` (`:170`), `_read_count` (`:192`), `_read_limits` (`:231`), `_with_refusal` (`:575`) | **reused**: U+FFFD in every Inc 3 message (R-A2L-DEF.137), the FIX words (.141), `<address>`, the mask word, the CTX *whole number* rule (`_read_count`'s 1 to 9 ASCII digits), the axis limits, a refusal on a built definition | Inc 2a's `_describe_one` (`:324-572`) and its helpers |
| `A2LParameterPicker.set_parameters` (`a2l_parameter_picker.py:526`) | not touched; Inc 6 replaces its 1-element size with `element_count` / `byte_length` | `CheckEditorPanel.set_a2l_parameters` (`screens_directionb.py:7303`), `PatchEditorPanel.set_a2l_parameters` (`:5388`) (C3) |

### Interfaces — pinned here, changed only by an orchestrator ruling

**I-2 extension (D-1 A, pinned in `../../inc-2/E2-rulings.md`).** Module `s19_app/tui/a2l_definition.py`; imports the standard library and `s19_app.tui.a2l` only; pure; never raises on file or image content. Added exactly as the ruling pins (§4 of `../E1-rulings.md`):

```text
Definition gains, after refusal, with defaults (Inc 2's fields unchanged, `coeffs_linear`, `coeffs`, `compu_tab_ref` and 2b's `shared_with` included, as graph-inc2.md pins them):
    shape: tuple[int, ...] = ()
    element_count: int | None = 1                                        <- None when unknown: E3A-03, ruled (../E3-rulings.md)
    index_mode: str | None = None
    values_offset: int = 0
    record_layout: str | None = None
    axes: tuple[AxisDefinition, ...] = ()
AxisDefinition(letter, axis_kind, point_count, points, point_order, offset, count_offset, fixed_count,
               fixed_rule, axis_object, axis_object_address, axis_object_record, monotony, has_points,
               count_datatype = None)                                    <- count_datatype: P-2, accepted (../E2-rulings.md)
                                                                         <- fixed_rule replaces fixed_points: E3A-01, ruled (../E3-rulings.md)
DecodedAxis(letter: str, points: tuple[Decoded | Refusal, ...] | None)
DecodedValues(values: tuple[Decoded | Refusal, ...], axes: tuple[DecodedAxis, ...])
Position = tuple[int, ...] | tuple[str, int]

decode_values(definition: Definition, a2l_data: dict, image: Mapping[int, int]) -> DecodedValues | Refusal
encode_values(definition: Definition, a2l_data: dict, edit: Mapping[Position, str],
              image: Mapping[int, int]) -> Encoded | Refusal
element_name(definition: Definition, position: Position) -> str
```

Values pinned by this graph (meanings the ruling left open; no name or type changes):
- `kind` gains `"array"`, `"curve"`, `"map"`; `""` stays for `A2L-DEF-NAME` and for the kinds still outside (CUBOID, CUBE_4, CUBE_5, MAP_BLOCK, vendor kinds).
- On an array, curve or map: `datatype` = the FNC_VALUES component's datatype (the MEASUREMENT header's for a MEASUREMENT array); `byte_length` = R-A2L-DEF.74 / .75's (the layout reading's end on an `A2L-DEF-ALIGNMENT` refusal; an array's product as computed, which R-A2L-DEF.7.2 refuses above 1,048,576 bytes; `None` when it cannot be computed — a curve or map whose walk stops past `MAX_A2L_DECODE_BYTES`, E2-7, then refused by .7.1); `shape` `()` and `element_count` `None` when no shape could be read, and `element_count` `None` on every definition of kind `""` (`A2L-DEF-NAME`, `A2L-DEF-KIND`): an unknown count is absent, never `0` or `1` (E3A-03, ruled; it replaces E2-11's `0`); `index_mode` the FNC_VALUES word, or the MEASUREMENT's LAYOUT word, else `"ROW_DIR"` for a MEASUREMENT; `values_offset` the FNC_VALUES offset (`0` for a MEASUREMENT); `record_layout` the layout name (`None` for a MEASUREMENT); `axes` X first, those built before a refusal. The conversion fields (`conversion_type` … `default_text`, `coeffs_linear`, `coeffs`, `compu_tab_ref`, `bit_mask`, `bit_mask_text`, limits, format, unit) are the object's: the fields every element definition takes, by `dataclasses.replace` (E3A-03, E3A-22).
- `AxisDefinition.points` is a `Definition` of the axis's points: `name` `<name>.X`, `section` `"AXIS_DESCR"`, `char_type` `None`, `kind` `"number"` or `"enum"` (TAB_VERB), `address` `None` (each point's comes from `_element_definition`), `byte_length` the point datatype's size (`None` for FIX), `datatype` the AXIS_PTS component's (the axis object's AXIS_PTS_X for COM; `None` for FIX), `byte_order` the object's (the axis object's for COM, R-A2L-DEF.114), the conversion fields of the axis header's method (`_conversion_fields`, with that method record's `coeffs_linear`, `coeffs`, `compu_tab_ref`: Inc 2 E3 R2.2), `bit_mask_text` `None`, `shared_with` (2b) `None`, `limits` the axis header's two limit words, `extended_limits` `None`, `bit_mask` `None`, `display_format` the axis FORMAT else the method's, `unit` the method's else `""`, `refusal` the R-A2L-DEF.103 candidate or `None`.
- `point_order` `None` for FIX; `offset`, `count_offset` are offsets in the object's record (STD, FIX) or in the axis object's record (COM), `None` when absent; `fixed_count` the FIX_NO_AXIS_PTS line of the same layout; `fixed_rule` FIX only (`None` for STD and COM), the FIX parameters and no point (E3A-01 = E3S3-02, ruled): (`"PAR"`, (o, s, n)), (`"PAR_DIST"`, (o, d, n)) or (`"PAR_LIST"`, the list's numbers in file order), each number an `int` where integral, else a `float`. The stored points are computed only at decode (`_fixed_points`, called by `_decode_axis` after `decode_values` has found the record's bytes in the image), so they never outnumber the record's bytes: a FIX axis's point count is at most the element count, which is at most the byte length, which R-A2L-DEF.7.2 bounds at 1,048,576. Inc 6 and Inc 9 read the points only through `decode_values` (`DecodedValues.axes`); no consumer reads `fixed_rule`; `axis_object_record` (COM) a `Definition` with `name` the AXIS_PTS name, `section` `"AXIS_PTS"`, `kind` `""`, `address`, `byte_length` the end of its record, `byte_order`, `record_layout` its layout, every other field empty (`None`, `""` or `()`, each stated: no Inc 2 field has a default, E3A-22); `monotony` `"STRICT_MON"` when absent; `has_points` `False` only for R-A2L-DEF.100 (a FIX axis has points that are not in memory).
- **P-2, accepted** (`../E2-rulings.md`): `AxisDefinition` gains `count_datatype: str | None = None` last, the NO_AXIS_PTS component's datatype. Reason: the current count (R-A2L-DEF.115) is read from bytes whose datatype the pinned fields do not hold — V171's count is UBYTE, DEFC's UWORD (B3b Q6). Consumers read fields by name and never construct one. Alternative if refused: `_current_count` re-reads the layout from `a2l_data` at decode (the definition then does not describe its own record).
- `Position`: an element index is a tuple of `len(shape)` ints (a curve's `(x,)`); an axis point is `("X", k)` or `("Y", k)`. A position of any other form is not an element index (`A2L-DEF-INDEX`, R-A2L-DEF.125), its `<position>` text `<name>[` + its items joined by `,` + `]`.
- *Edit order* (CTX-A2L-DEF) as the order of the dict keys sorted by: axis points first, X before Y, by point index; then element indexes, the last index most significant (element order); a malformed position sorts after all of them, in the edit's own order. `encode_values` checks positions (R-A2L-DEF.125) in this order.
- `Encoded` unchanged: `address` the record's address, `data` the whole record (`byte_length` bytes), `notices` the elements' notices in edit order, each naming its element (R-A2L-DEF.121). An empty edit gives the record as the image holds it.
- New refusal codes (27; E1's "25" miscounts, E2-12): `A2L-DEF-SHAPE`, `-MATRIX`, `-INDEX-MODE`, `-LAYOUT`, `-LAYOUT-VALUES`, `-LAYOUT-PART`, `-LAYOUT-MODE`, `-LAYOUT-DATATYPE`, `-LAYOUT-POSITION`, `-ALIGNMENT`, `-AXES`, `-AXIS-KIND`, `-AXIS-MAX`, `-AXIS-REF`, `-AXIS-LAYOUT`, `-AXIS-FIX`, `-AXIS-FIX-COUNT`, `-LAYOUT-AXIS`, `-AXIS-CURRENT`, `-AXIS-PARTIAL` (describe or decode); `-AXIS-BYTES` (decode); `-ELEMENTS`, `-INDEX`, `-AXIS-FIXED`, `-AXIS-SHARED`, `-AXIS-NONE`, `-MONOTONY` (encode; `-ELEMENTS` also the single decode). `A2L-DEF-LENGTH` is reused with the array message of R-A2L-DEF.76. The coverage pass adds messages under existing codes: `A2L-DEF-AXIS-FIX` (R-A2L-DEF.141), `A2L-DEF-AXIS-MAX` (.142), `A2L-DEF-AXIS-REF` (.143), and in 3b 2b's `A2L-DEF-OVERLAP` for an AXIS_PTS record (.140); the E3 correction adds `A2L-DEF-ALIGNMENT` (.144, the MOD_COMMON line), `A2L-DEF-MATRIX` (.145, a MATRIX_DIM on a CURVE, MAP or VALUE), and `A2L-DEF-AXIS-CURRENT` for a count below 1 (.116.2). Messages are the rows' texts exactly.
- `decode_values` / `encode_values` on a definition of kind `number`, `enum` or `text` (E2-5): the decode gives `DecodedValues((decode_definition(…),), ())` — row R-A2L-DEF.146 (E3A-18); the encode (3b, no row yet) takes only the position `(0,)` → `encode_definition`, any other position `A2L-DEF-INDEX`.
- Consumers: Inc 6 reads `kind`, `element_count`, `byte_length`, `shape` (also from a refused definition); Inc 9 reads `shape`, `index_mode`, `axes`, `DecodedValues` and builds `edit` from the operator's cells; neither calls `a2l._encode_curve_record_bytes` (BL-I3-7). Inc 2's consumer notes hold for every Inc 3 string (markup off, E3S-04a; raw file words, E3A-25 / E3S-19) and, in 3b, for `shared_with` (E3S-45 (iii)). Inc 6 reads an unknown element count as `element_count is None` (E3A-03).
- **Consumer obligations from 3a's E3** (they bind Inc 6 and Inc 9; no model change):
  - **Large decodes (E3S3-03).** One `decode_values` may give up to 1,048,576 elements (R-A2L-DEF.7.2) plus as many points per axis, a FIX axis's computed then. Measured at about 10–12 µs and 156–216 B per element (`../evidence-e3/sec-bench-transcript.txt` [B1]): about 11 s and about 200 MiB per 1,048,576 elements, plus 0.97 s and 48 MiB to build one 1,048,576-point FIX axis (`i3e3c-fix-probe` F2). A UI consumer reads `element_count` / `byte_length` first, decodes off the UI thread, and pages what it shows; it never decodes a large object synchronously. This is owed to Inc 9's E1 as a row and an AT (decode a 1 MiB object without blocking the UI); the orchestrator adds that PLAN row, which this pass cannot edit.
  - **Markup (E3S3-04).** These are Inc 3's new strings, rendered by Inc 6 and Inc 9, that carry file words: `shape` and `index_mode` texts, element names `<name>[i,j]`, axis point names `<name>.X[k]`, enum element and axis point display texts, and every Inc 3 refusal message. `_clean` replaces control characters but leaves `[` and `]`. Each consumer therefore renders them with markup off (`markup=False`, `Content`, or `escape`) and extends the AST markup law-guard (`tests/test_filename_markup_safety.py`) to its render modules, per Inc 2's E3S-04 / E3S-22.
- **Messages (R-A2L-DEF.137, Inc 2).** Every Inc 3 refusal message echoes a word from the file or the operator (`<layout>`, `<component>`, `<word>`, `<ref>`, `<dims>`, `<name>` and the element and axis names built from it) with U+FFFD for U+0000–U+001F, U+007F and U+0080–U+009F, as `describe_definitions` does; each element's display text comes from `_decode_stored`, which keeps Inc 2's replacement.
- **Lookups (E3A-32).** `describe_definitions`'s one walk of `a2l_data["sections"]` builds, beside Inc 2's maps (objects, `compu_methods_by_name`, `compu_tables_by_name`), two more, passed to Inc 3's nodes as `maps`: `axis_pts_by_name` (each AXIS_PTS section in file order, filed under the first word of its *AXIS_PTS header*, `_flatten_body_tokens([meta] + lines)`) and `mod_common_of` (each MEASUREMENT, CHARACTERISTIC and AXIS_PTS section, by identity, → the MOD_COMMON child of the MODULE the walk is in, taken from the MODULE's children when the walk enters it; `None` outside a MODULE). The method and table records come from Inc 2's maps. No Inc 3 node walks the tree per object, so R-A2L-DEF.136 holds for Inc 3's kinds. Measured on cachyos-rtx (Python 3.11.18, clone `e07fb00`; throwaway cost prototype `i3reb-cost-probe.py`, transcript cited in `../E2-rulings.md`), software_a: the walk with the two maps `43.78` ms (Inc 2's walk alone `34.63` ms); Inc 3's per-object reads through the maps (every object's MATRIX_DIM line; for its 101 VAL_BLK, 158 CURVE, 11 MAP the record layout read and placed twice, 180 AXIS_DESCR headers, 161 COM axis objects' headers and layouts; 196 MEASUREMENT arrays) median `0.247` s; Inc 2's describe prototype (`../../inc-2/evidence-e3/arch-r2-probe.py`) median `0.740` s; together ≈ `0.995` s against .136's `2.0` s. With the per-object walks of the E2 graph the estimate was ≈ 3.3 s (E3A-32). **Re-measured at E3 (E3A-12):** Inc 2a's real describe is `0.932` s (`../evidence-e3/i3e3a-arch-probe-transcript.txt` Q1) and `1.007` s (`i3e3c-fix-probe` F3, medians of 3); the two maps add `8.4` ms (Q2) and Inc 3's reads `0.261` s (Q3). The estimate is **≈ 1.2–1.3 s** (Q4: `1.201`, or `1.293` with the reads scaled by 2a's real-to-prototype ratio): the bound holds with about 35 % margin. E4's .136 run is the evidence.

**I-D (G2 → the testers, test data only), extended.** Each Inc 3 DEFC object dict has Inc 2's keys (`name`, `section`, `kind`, `datatype`, `conversion`, `address`, `length`, `big_endian`, `raw_bytes`, `physical`, `low`, `high`, `bit_mask`) with `section` `"CHARACTERISTIC"` or `"AXIS_PTS"`, `kind` `"CURVE"`, `"MAP"`, `"VAL_BLK"` or `"AXIS_PTS"`, `length` the record's bytes, `raw_bytes` the record, `physical` `None`, `bit_mask` `None`; and `shape` (tuple), `planned_stored` and `planned_text` as tuples in element order (an AXIS_PTS object: its points), `axes` (a tuple of dicts `letter`, `axis_kind`, `planned_stored`, `planned_text`, `axis_object`). Inc 2's four objects keep their scalar keys.

**I-5** (label-list parser): not consumed and not changed.

### The definitions case additions (DEFC), pinned (D-15 A; R-A2L-DEF.133 … .135)

Inc 2's region, MOD_COMMON (`MSB_FIRST`, `ALIGNMENT_BYTE 1`, `ALIGNMENT_WORD 2`), methods and four objects are unchanged. **Draw order** continues Inc 2's five draws, so Inc 2's planned values do not move (B3 P8 reproduces enum `1`, bit `1`, field `174`, display `287`): (6) the axis object's points, `sorted(rng.sample(range(1, 2000), 5))`; (7) `CURVE_DEF_0001`'s 5 values, `rng.randrange(65536)` each; (8) `CURVE_DEF_0002`'s 5, the same; (9) `MAP_DEF_0001`'s axis X, `sorted(rng.sample(range(0, 1000), 4))`; (10) its 12 values, `rng.randint(-1000, 1000)` each in element order; (11) `VAL_BLK_DEF_0001`'s 6 stored values, `rng.randint(-800, 800)` each in element order. The planned record bytes overlay the fill at `0x800040 … 0x80009B` (Inc 2's bytes end at `0x800021`). With seed 20260001 (B3 P8, B3b Q6, B3c R3):

| Object | Address, bytes | Planned (element order) |
|---|---|---|
| `AXIS_DEF_0001` (AXIS_PTS, `RL_DEF_AXIS`, max 5, `CM_DEF_LIN`) | `0x800040`, 12: `00 05 01 e5 02 7b 02 b8 03 3c 03 85` | count `5`; stored `485 635 696 828 901`; texts `242.500 317.500 348.000 414.000 450.500` |
| `CURVE_DEF_0001` (COM_AXIS → `AXIS_DEF_0001`, `RL_U16`, `CM_DEF_IDENT`) | `0x800050`, 10: `93 ba cb f7 6e d7 e2 fa 2d c7` | `37818 52215 28375 58106 11719` |
| `CURVE_DEF_0002` (the same axis) | `0x800060`, 10: `80 f6 5f dd 60 73 08 db 9a 74` | `33014 24541 24691 2267 39540` |
| `MAP_DEF_0001` (`RL_DEF_MAP`; X STD 4 points `MONOTONY STRICT_INCREASE`; Y FIX `FIX_AXIS_PAR_DIST 10 5 3`; COLUMN_DIR) | `0x800070`, 32: X `00 e0 02 41 02 88 03 8d`, values at offset 8 + 2·(y + 3x) | X `224 577 648 909`; Y `10 15 20`; (0,0) `472`, (1,0) `132`, (2,0) `610`, (3,0) `330`, (0,1) `709`, (1,1) `-890`, (2,1) `-383`, (3,1) `-636`, (0,2) `843`, (1,2) `-485`, (2,2) `730`, (3,2) `-556` |
| `VAL_BLK_DEF_0001` (`MATRIX_DIM 3 2`, `RL_DEF_S16_ROW`, `CM_DEF_FINE`, `FORMAT "%.1"`, limits −50..50) | `0x800090`, 12: `02 e1 00 db 02 7c fe 63 fe 75 ff 2a` | stored `737 219 636 -413 -395 -214`; texts `36.9 11.0 31.8 -20.7 -19.8 -10.7` |

```text
    /begin RECORD_LAYOUT RL_DEF_AXIS      NO_AXIS_PTS_X 1 UWORD | AXIS_PTS_X 2 UWORD INDEX_INCR DIRECT
    /begin RECORD_LAYOUT RL_DEF_MAP       AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT | FNC_VALUES 2 SWORD COLUMN_DIR DIRECT
    /begin RECORD_LAYOUT RL_DEF_S16_ROW   FNC_VALUES 1 SWORD ROW_DIR DIRECT
    /begin COMPU_METHOD CM_DEF_FINE "synthetic fine LINEAR conversion"   LINEAR "%.3" "units"   COEFFS_LINEAR 0.05 0
    /begin AXIS_PTS AXIS_DEF_0001 "synthetic common axis"   0x00800040 NO_INPUT_QUANTITY RL_DEF_AXIS 0 CM_DEF_LIN 5 0 1000
    /begin CHARACTERISTIC CURVE_DEF_0001 "synthetic curve on the common axis"   CURVE 0x00800050 RL_U16 0 CM_DEF_IDENT 0 65535
      /begin AXIS_DESCR   COM_AXIS NO_INPUT_QUANTITY CM_DEF_LIN 5 0 1000   AXIS_PTS_REF AXIS_DEF_0001
    /begin CHARACTERISTIC CURVE_DEF_0002 "synthetic second curve on the common axis"   CURVE 0x00800060 … (the same AXIS_DESCR)
    /begin CHARACTERISTIC MAP_DEF_0001 "synthetic map"   MAP 0x00800070 RL_DEF_MAP 0 CM_DEF_IDENT -1000 1000
      /begin AXIS_DESCR   STD_AXIS NO_INPUT_QUANTITY CM_DEF_IDENT 4 0 1000   MONOTONY STRICT_INCREASE
      /begin AXIS_DESCR   FIX_AXIS NO_INPUT_QUANTITY CM_DEF_IDENT 3 0 100   FIX_AXIS_PAR_DIST 10 5 3
    /begin CHARACTERISTIC VAL_BLK_DEF_0001 "synthetic 2-D value block"   VAL_BLK 0x00800090 RL_DEF_S16_ROW 0 CM_DEF_FINE -50 50
      MATRIX_DIM 3 2   FORMAT "%.1"
```

(The block shows the content; in the written file every `/begin` has its `/end` and every component, keyword and header has its own line, as B3b Q6 parsed it with 0 errors. The Inc 3 lines follow Inc 2's in the same MODULE: layouts after Inc 2's layouts, `CM_DEF_FINE` after `CM_DEF_LIN`, the AXIS_PTS and the four CHARACTERISTICs after Inc 2's objects.) Single-size components only (UWORD/SWORD), so D-7's check never refuses a DEFC object (B3b Q6: both readings give the same offsets). `CM_DEF_FINE` (a = 0.05) instead of Inc 2's `CM_DEF_LIN` (a = 0.5) so R-A2L-DEF.132's negative control can drift (E2-6).

### Inc 2 cases this increment changes (D-14 ruling)

| Inc 2 case | Inc 2 expectation | Inc 3 expectation (node) |
|---|---|---|
| R-A2L-DEF.4/1, /2, /3 (C08 `VAL_BLK_0001`, `CURVE_0001`, `MAP_0001`) | `A2L-DEF-KIND` | withdrawn: kinds `array`, `curve`, `map` (R-A2L-DEF.64/5, .65/3, .66/2; `describe_definitions`) |
| R-A2L-DEF.4/7 (V171 `ASAM.M.MATRIX_DIM_16_1.UBYTE.IDENTICAL`) | `A2L-DEF-KIND` `… MATRIX_DIM 16 MEASUREMENT object` | withdrawn: kind `array`, shape `(16,)` (R-A2L-DEF.67/4) |
| R-A2L-DEF.4/9, new (D-14) | — | V171 `ASAM.C.CUBE_4.ROW_DIR` → `A2L-DEF-KIND` `ASAM.C.CUBE_4.ROW_DIR: the system has no definition for a CUBE_4 object` (the tag gives `char_type` `CUBE_4`, address `0x810590`, B3c R1); threshold 5/5 with /4, /5, /6 and Inc 2's later /8 (E3A-09). The cases of this table are in `../02-test-cases.md`, "Inc 2 cases this increment changes" |
| R-A2L-DEF.24/1 (INLINE MEASUREMENT `MA`, `MATRIX_DIM 4`, no ECU_ADDRESS) | `A2L-DEF-KIND` | input becomes INLINE3 CUBOID `CB` whose address word is `0xZZ` (the tag gives `char_type` `CUBOID`, address `None`, B3c R2) → `A2L-DEF-KIND` (kind before address); `MA` itself is now an array and gives `A2L-DEF-ADDRESS` (R-A2L-DEF.7/arr-2) |
| AT-B103-I2-3 (C08 clean and issues: every defined object builds and decodes) | clean: 322 objects, 0 refusals; issues: 1 `A2L-DEF-METHOD`, 1 `A2L-DEF-NAME` (R-A2L-DEF.139), the `A2L-DEF-BYTES` refusals | scoped to the kinds `number`, `enum`, `text` (the same 322 and the same issues refusals); the 140 arrays, curves and maps of each A2L give `A2L-DEF-ELEMENTS` on a single decode and are AT-B103-I3-3's |
| R-A2L-DEF.58.1/1, /2 | unchanged in effect | still hold: the single calls on arrays return a refusal value and leave both inputs unchanged; R-A2L-DEF.58.1/arr-1, /arr-2 cover the array calls |
| R-A2L-DEF.5/1, .139/1 … /3 | unchanged | hold; Inc 3's own R-A2L-DEF.5/arr-1 changes with them (finding R-1) |

### Coverage — every requirement → nodes and examples

Every row has at least one concrete example; none is uncovered. Example ids are the case ids on the nodes' `examples:` lines.

| Rows | Nodes | Examples |
|---|---|---|
| R-A2L-DEF.64 … .66 | `describe_definitions`, `_describe_one`, `_object_kind` | .64/1 … /6; .65/1 … /3; .66/1 … /3 |
| R-A2L-DEF.67, .71 | `_read_matrix_dim`, `_object_kind`, `_describe_array` | .67/1 … /5; .71/1 … /5 |
| R-A2L-DEF.68 … .70, .76 | `_array_shape`, `_describe_array` | .68/1, /2; .69/1, /2; .70/1; .76/1, /2 |
| R-A2L-DEF.72 … .75, .77 | `_describe_array`, `_place_components` | .72/1 … /3; .73/1 … /9; .74/1 … /4; .75/1 … /4; .77/1 … /3 |
| R-A2L-DEF.78 … .81 | `_describe_array`, `_conversion_fields` | .78/1, /2; .79/1; .80/1, /2; .81/1 … /5 (/4 under E2-1; /5 E3S-01) |
| R-A2L-DEF.145 | `_read_matrix_dim`, `_describe_array` (curve, map), `_describe_one` (VALUE) | .145/1 … /3 |
| R-A2L-DEF.82 … .87 | `_read_record_layout`, `_describe_array` | .82/1, /2; .83/1; .84/1 … /7; .85/1 … /4; .86/1 … /3; .87/1, /2 |
| R-A2L-DEF.88 | `_place_components` | .88/1 … /3 |
| R-A2L-DEF.89, .144 | `_check_module_alignment`, `_module_common`, `_describe_array` | .89/1 … /3; .144/1 … /3 |
| R-A2L-DEF.90 | `_read_record_layout`, `_read_axis`, `_current_count` | .90/1, /2 |
| R-A2L-DEF.91 | `_describe_array` | .91/1 … /3 |
| R-A2L-DEF.92 … .99, .101 | `_read_axis`, `_find_axis_object` | .92/1 … /4; .93/1 … /3; .94/1 … /3; .95/1 … /3; .96/1 … /4; .97/1, /2; .98/1; .99/1, /2; .101/1, /2 |
| R-A2L-DEF.100 | `_read_axis`, `_decode_axis` | .100/1 … /3 |
| R-A2L-DEF.102, .103 | `_read_axis`, `_conversion_fields`, `_describe_array` | .102/1 … /4; .103/1, /2 |
| R-A2L-DEF.104 | `_describe_array` | .104/1 … /3 |
| R-A2L-DEF.141 … .143 | `_read_axis`, `_fixed_points` (.141/7's points, at decode) | .141/1 … /7; .142/1 … /5; .143/1 … /4 |
| R-A2L-DEF.105 | `decode_values`, `_element_definition`, `_decode_stored`, `_decode_axis` | .105/1 … /5 |
| R-A2L-DEF.106, .107 | `_element_offset`, `decode_values` | .106/1 … /3; .107/1 … /3 |
| R-A2L-DEF.108, .109 | `_point_offset`, `_decode_axis` | .108/1, /2; .109/1, /2 |
| R-A2L-DEF.110 … .112 | `_fixed_points`, `_decode_stored`, `_decode_axis` | .110/1, /2; .111/1 … /3; .112/1 |
| R-A2L-DEF.113, .114 | `_decode_axis`, `_find_axis_object`, `_read_axis` | .113/1, /2; .114/1, /2 |
| R-A2L-DEF.115, .116.1, .116.2, .117.1, .117.2 | `_current_count` (.115, .116.2, .117.2), `_read_axis` (.116.1, .117.1) | .115/1, /2; .116.1/3; .116.2/1, /2, /4; .117.1/2; .117.2/1, /3 |
| R-A2L-DEF.118 | `_decode_axis` | .118/1, /2 |
| R-A2L-DEF.119 | `decode_values`, `_decode_stored` | .119/1 |
| R-A2L-DEF.120 | `decode_definition`, `encode_definition` | .120/1, /2 |
| R-A2L-DEF.121 | `element_name`, `_element_definition` | .121/1 … /3 |
| R-A2L-DEF.146 | `decode_values` | .146/1 |
| R-A2L-DEF.122 … .130 | `encode_values`, `_breaking_point` | .122/1 … /7; .123/1 … /4; .124/1 … /3; .125/1 … /3; .126/1, /2; .127/1, /2; .128/1; .129/1 … /9; .130/1 … /3 |
| R-A2L-DEF.131, .132 | `encode_values`, `decode_values` | .131/1; .132/1 (with the DEFC instances) |
| R-A2L-DEF.140 (3b) | `describe_definitions` (the AXIS_PTS entries of the span index), `encode_definition` (2b's step 9) | .140/1 … /3 |
| R-A2L-DEF.133 … .135 | `_definition_array_objects`, `build_definition_objects`, `emit_definitions_a2l` | .133/1; .134/1; .135/1 |
| cited R-A2L-DEF.5, .6, .139, .7.1, .7.2, R-A2L-010, 011, 024, 026 | `describe_definitions`, `_describe_array` | .5/arr-1; .6/arr-1; .139/arr-1; .7.1/arr-1 … /arr-3; .7.2/arr-1 … /arr-3; 010/arr-1; 011/arr-1; 024/arr-1; 026/arr-1 |
| cited R-A2L-DEF.136 | `describe_definitions` (the walk's maps, E3A-32) | .136/arr-1 |
| cited R-A2L-DEF.137 | `_describe_array`, `_read_axis`, `decode_values` | .137/arr-1 … /arr-4 |
| cited R-A2L-DEF.58.2 | `_read_matrix_dim`, `_array_shape`, `_read_record_layout`, `_check_module_alignment`, `_read_axis`, `_current_count` | .58.2/arr-1 … /arr-9 |
| cited R-A2L-DEF.26, .58.1 | `decode_values`, `encode_values` | .26/arr-1; .58.1/arr-1, /arr-2 |
| cited R-A2L-DEF.59, .63 | `build_definition_objects` (case 08 untouched) | .59/arr-1; .63/arr-1 |
| cited R-A2L-019 | `_read_axis` | 019/arr-1 |
| Inc 2 cases changed (D-14) | `describe_definitions`, `_describe_one`, `_object_kind`, `decode_definition` | R-A2L-DEF.4/9, .24/1, AT-B103-I2-3 (table above; cases in `../02-test-cases.md`) |
| AT-B103-I3-1 … -4 | `describe_definitions`, `decode_values`, `encode_values`; G2 for -2 | each AT's example lines |

**Node count:** 34 nodes in this file — 21 new in the module (the slice's 19 plus `_conversion_fields` and `_module_common`, E2-3), 5 changed Inc 2 nodes (`describe_definitions` — the E2 graph changed `describe_definition`, which now delegates to it, E3A-01 —, `_describe_one` — Inc 2a's per-name function, added at the E3 correction, E3A-04 —, `_object_kind`, `decode_definition`, `encode_definition`), 1 new and 2 changed Inc 2 nodes in the synth, 0 removed, 5 unchanged `a2l.py` context nodes. The slice (new + changed) is 29 (E1 counted 26; +2, E2-3; +1, E3A-04). Inc 2's 43 + Inc 3's 28 slice nodes = 71 for the module and synth together, which is why this is a delta file. Entities 9, edges 13. Under the cap of 40 for this file. Per side: "Split (amendment A2)" below.

**Checked against the base code** (`evidence-e2/i3e2-extract-check-transcript.txt`): the Code-Wire v3.1.0 extractor over a throwaway copy of `e07fb00` with a mark on each of the 5 existing nodes of this file and `--path` on the slice files → `0` contract drifts (inputs, types, defaults, outputs, modules of the 5 match); the `28` findings are all "Graph node without mark (no code yet)", the 28 slice nodes — so the run exits 1 until E4 writes them, as the method expects. `codewire_lint.py` on this file (`evidence-e2/i3e2-lint-transcript.txt`): `nodes=33 entities=9 edges=13 findings=15 not read=0`. Real callers: `evidence-e2/i3e2-extract-census-transcript.txt` (every def of the copy marked, base line numbers).

### Split (amendment A2): nodes, edges and I-2 per side

Amendment A2 (`../../PLAN.md`) splits Inc 3 as it splits Inc 2. **3a** is the read side: describe, decode and display of arrays, curves, maps and VAL_BLKs, the synth objects, and the element count and byte length Inc 6 needs; it runs on Inc 2a and today's reader. **3b** is the write side: the encode of elements and axis points, the monotony on an edit, and the AXIS_PTS spans in R-A2L-DEF.138's index; it waits for Inc 2b and Inc 11 and is re-reviewed with 2b's guards. Rows and cases per side: `../01-requirements.md` and `../02-test-cases.md`, "Split (amendment A2)". The node texts describe the whole of Inc 3; where a 3a node holds a 3b part, the list after the table names it.

| Side | Nodes | Count |
|---|---|---|
| 3a, changed (G1) | `describe_definitions`, `_describe_one` (E3A-04), `_object_kind`, `decode_definition` | 4 |
| 3a, new (G1) | `_conversion_fields`, `_describe_array`, `_read_matrix_dim`, `_array_shape`, `_read_record_layout`, `_place_components`, `_check_module_alignment`, `_module_common`, `_read_axis`, `_find_axis_object`, `_fixed_points`, `_element_definition`, `element_name`, `decode_values`, `_element_offset`, `_point_offset`, `_current_count`, `_decode_axis`, `_decode_stored` | 19 |
| 3a, new and changed (G2) | `build_definition_objects`, `emit_definitions_a2l` (changed); `_definition_array_objects` (new) | 3 |
| 3a, unchanged context | `_walk_record_layout_components`, `_strip_a2l_comments`, `_split_line_respecting_quotes`, `_byte_order_from_section_lines` | 4 |
| 3b, changed (G1) | `encode_definition` (2b's node) | 1 |
| 3b, new (G1) | `encode_values`, `_breaking_point` | 2 |
| 3b, unchanged context | `_encode_curve_record_bytes` (the oracle of R-A2L-DEF.123/4's and .132's negative controls) | 1 |

That is 34 nodes: 30 in 3a and 4 in 3b. The slice (new and changed nodes) is 29: 26 in 3a and 3 in 3b.

**What 3b adds to 3a nodes** (they keep their name, inputs and outputs):
- **`describe_definitions`.** 2b's span index and `shared_with` (Inc 2's), plus the AXIS_PTS spans of the round-4b census ruling (`../../inc-2/E3-rulings.md`: "AXIS_PTS spans join the index in Inc 3"): every AXIS_PTS whose address the A2L declares, with the span of its record as `_read_axis` places it, filed as 2b files a tag. Row R-A2L-DEF.140 (`../01-requirements.md` S2.7h, 3b, counted by the orchestrator's ruling on the split) states it; cases .140/1 … /3. The index entries of Inc 3's own kinds keep the tag's byte length as 2b writes it (the tag table's first MATRIX_DIM number, BL-I3-2; none for a NUMBER-sized VAL_BLK, BL-I3-3): E3S-40's index part, listed in `../E2-rulings.md`.
- **`_read_axis`.** The `monotony` field is read in 3a (it is part of `AxisDefinition`); only 3b's `_breaking_point` uses it.
- **`_element_definition`.** In 3b it is the input of each element's `encode_definition`; as a `replace` of the object's definition it carries 2b's `shared_with`, so 2b's step 9 refuses every element of an object that shares bytes (`encode_definition` below).
- **`decode_values`.** 3b's encode order starts with it (R-A2L-DEF.124), and the round trip reads with it (.131, .132).
- **Examples.** An example on a 3a node waits for 3b when it cites a 3b row or case or an edit arm: `_element_definition`'s .126/1 and .127/1 inputs; `element_name`'s .121/1, .121/2, .125/1 … /3 and .121/1 neg; the edit arm of .58.1/arr-1 and /arr-2 on `describe_definitions` and `decode_values`; the edit arm of AT-B103-I3-1 … -3.

**Edges and entities.** 2 edges are 3b: `[Data: image] ──▶ encode_values` and `encode_values ──▶ _breaking_point`; the other 11 are 3a. The 9 entities are 3a (`Encoded` is Inc 2b's).

**E4 groups.** G1 splits as the table does: 3a's tester G-T1 takes S2.7e, S2.7f, the 3a cases of S2.7g, the cited cases, the build-and-decode arms of AT-B103-I3-1 and -3, AT-B103-I3-4 and the D-14 Inc 2 cases; 3b's tester takes S2.7h, the encode cases of .120 and .121 and the edit arms. G2 is all 3a; AT-B103-I3-2's edit arms wait for 3b.

**3a's I-2 extension:** `Definition`'s six defaulted fields (`element_count` `None` when unknown, E3A-03); `AxisDefinition` (`count_datatype` included; `fixed_rule` in place of `fixed_points`, E3A-01), `DecodedAxis`, `DecodedValues`, `Position`; `decode_values` (also on a scalar kind, R-A2L-DEF.146) and `element_name`; `describe_definition(s)` and `decode_definition` on the new kinds (`decode_definition` gives `A2L-DEF-ELEMENTS`); the codes `-SHAPE`, `-MATRIX`, `-INDEX-MODE`, `-LAYOUT`, `-LAYOUT-VALUES`, `-LAYOUT-PART`, `-LAYOUT-MODE`, `-LAYOUT-DATATYPE`, `-LAYOUT-POSITION`, `-ALIGNMENT`, `-AXES`, `-AXIS-KIND`, `-AXIS-MAX`, `-AXIS-REF`, `-AXIS-LAYOUT`, `-AXIS-FIX`, `-AXIS-FIX-COUNT`, `-LAYOUT-AXIS`, `-AXIS-CURRENT`, `-AXIS-PARTIAL`, `-AXIS-BYTES`, `-ELEMENTS` (22), and `A2L-DEF-LENGTH`'s array message.

**What 3b adds to I-2:** `encode_values` (also on a scalar kind, E2-5); `encode_definition` on the new kinds (`-ELEMENTS`); the codes `-INDEX`, `-AXIS-FIXED`, `-AXIS-SHARED`, `-AXIS-NONE`, `-MONOTONY` (5); the *edit order* and the `Encoded` of a whole record; the AXIS_PTS index entries.

**Interface note.** 3b changes no name, type, value or meaning that 3a defines; it adds a function, codes and refusals. Inc 3's defaulted fields follow `refusal`, so they stay valid next to 2b's `shared_with` whichever lands first. No 3a function writes: a 3a consumer (Inc 6) only describes, decodes and displays.

## Nodes

### Changed Inc 2 nodes (`s19_app/tui/a2l_definition.py`)

describe_definitions
req: R-A2L-DEF.64, R-A2L-DEF.65, R-A2L-DEF.66, R-A2L-DEF.4, R-A2L-DEF.5, R-A2L-DEF.6, R-A2L-DEF.139, R-A2L-DEF.24, R-A2L-DEF.58.1, R-A2L-DEF.136, R-A2L-DEF.137, R-A2L-010, R-A2L-011, R-A2L-024, R-A2L-026, R-A2L-DEF.140
in: Iterable[str] names; dict a2l_data
out: dict[str, Definition] definitions
func: changed (rebased on Inc 2's E3: E3A-01, E3A-32). was: Inc 2's (`graph-inc2.md` `describe_definitions`): one walk that builds the name maps; per name `_find_tag`, the scalar fields, Inc 2's refusal order; every kind but number, enum and text refused `A2L-DEF-KIND`. / now: the same walk also builds `axis_pts_by_name` and `mod_common_of` (Interfaces, *Lookups*), handed with Inc 2's method and table maps to Inc 3's nodes as `maps`; per name the same lookup (R-A2L-DEF.5, .6, .139) and scalar fields, the method and table fields read through `_conversion_fields` (the same values, the same refusals in the same order); `_read_matrix_dim(section)` gives the MATRIX_DIM words; `kind` = `_object_kind(tag, conversion_type, words)`; for `array`, `curve` or `map` the definition is `_describe_array(tag, section, a2l_data, base, maps)`, `base` = the Definition of those scalar fields (the method record's `coeffs_linear`, `coeffs`, `compu_tab_ref` included) with that kind, the mask refusal recorded while reading the object record, and refusal `None` (Inc 2's refusal order is not applied to these kinds; the array refusal order is). Every other kind exactly as Inc 2. Messages as R-A2L-DEF.137. In Inc 2a's code these per-name rules live in `_describe_one` (`a2l_definition.py:324-572`), named below as a changed node (E3A-04); this node keeps the one walk and its maps. `describe_definition(name, a2l_data)` is unchanged (`describe_definitions([name], a2l_data)[name]`): the examples below are written per name, through it. 3b's part (the AXIS_PTS index entries, R-A2L-DEF.140): "Split (amendment A2)".
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.64/1) V171 `ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR` → kind `array`, refusal `None` (Inc 2: `A2L-DEF-KIND`)
examples: (R-A2L-DEF.64/2, /3) V171 `ASAM.C.ARRAY.SWORD.MATRIX_DIM_6.ROW_DIR` → `array`; `ASAM.M.MATRIX_DIM_8_4_2.UBYTE.IDENTICAL` → `array`, section `MEASUREMENT` (B3 P5)
examples: (R-A2L-DEF.64/4) SOFTA `AljxdUybv__Mylof2.XqtqovICCYa_UatfexuoUgpWibdew` (the first VAL_BLK, `NUMBER 4`) → `array`, refusal `None` (B3 P6)
examples: (R-A2L-DEF.64/5, changed R-A2L-DEF.4/1) C08 clean `VAL_BLK_0001` → `array`, refusal `None`
examples: (R-A2L-DEF.64/1 neg) mutant: Inc 2's `A2L-DEF-KIND` kept for a VAL_BLK → RED
examples: (R-A2L-DEF.65/1 … /3, changed R-A2L-DEF.4/2) V171 `ASAM.C.CURVE.COM_AXIS`, `ASAM.C.CURVE.FIX_AXIS.PAR_DIST`, C08 `CURVE_0001` → kind `curve`
examples: (R-A2L-DEF.66/1 … /3, changed R-A2L-DEF.4/3) V171 `ASAM.C.MAP.COM_AXIS.FIX_AXIS`, C08 `MAP_0001`, DEFC `MAP_DEF_0001` → kind `map`
examples: (R-A2L-DEF.4/9, D-14) V171 `ASAM.C.CUBE_4.ROW_DIR` → refusal `A2L-DEF-KIND` `ASAM.C.CUBE_4.ROW_DIR: the system has no definition for a CUBE_4 object`, kind `""`, address `0x810590` (B3c R1); Inc 2's /4 CUBOID, /5 `MB`, /6 `VK` unchanged
examples: (changed R-A2L-DEF.24/1, D-14) INLINE3 CUBOID `CB` with address word `0xZZ` → `A2L-DEF-KIND` `CB: the system has no definition for a CUBOID object` (address `None`, B3c R2: kind before address)
examples: (R-A2L-DEF.5/arr-1, rebased, finding R-1) INLINE3 a VAL_BLK `DUPA` (`MATRIX_DIM 2`) at 0x20 and a VAL_BLK `dupa` (`MATRIX_DIM 2`) at 0x10 → for `DUPA` address `0x20`, kind `array`, refusal `None` (`dupa` is another name)
examples: (R-A2L-DEF.139/arr-1) INLINE3 two VAL_BLKs `DUPA` (`MATRIX_DIM 2`) at 0x10 and 0x20 → refusal `A2L-DEF-NAME` `DUPA: the A2L declares that name more than once`, kind `""` (the E2 graph gave the first tag, `0x10`: the rule E3S-35 removed)
examples: (R-A2L-DEF.136/arr-1) SOFTA, `describe_definitions` of every tag name (13,990) with Inc 3's kinds → ≤ 2.0 s (median of 3, cachyos-rtx); estimated ≈ 1.2–1.3 s (Interfaces, *Lookups*, re-measured at E3, E3A-12)
examples: (R-A2L-DEF.136/arr-1 neg) mutant: `_find_axis_object` and `_module_common` as per-object walks (the E2 graph) → ≈ 3.3 s (E3A-32) → RED
examples: (R-A2L-DEF.6/arr-1) C08 clean `curve_0001` → refusal `A2L-DEF-NAME` `curve_0001: no tag of that name in the A2L`
examples: (R-A2L-010/arr-1, R-A2L-026/arr-1) V171 `…MATRIX_DIM_3_4.ROW_DIR` → address `0x810100`, byte order `little` (MOD_COMMON `MSB_LAST`); (R-A2L-011/arr-1) `…MATRIX_DIM_8_4_2…` → address `0x13A30` (B3 P1)
examples: (R-A2L-024/arr-1) C08 `VAL_BLK_0001` → byte order `big` (its `BYTE_ORDER MSB_FIRST` line, B3 P7)
examples: (R-A2L-DEF.58.1/arr-1, /arr-2) V171 and C08 clean: a deep copy of `a2l_data` before building every array, curve and map equals it after → `True`
examples: (R-A2L-DEF.140/1 … /3, 3b) INLINE3 AXIS_PTS `AXS` at 0x10 (`RL_AXS`, max 4: record 0x10 … 0x14) and UBYTE VALUE `VS` at 0x14 → `VS`'s `shared_with` names `AXS` (the AXIS_PTS entry of the span index, the span of the record as `_read_axis` places it); `VS` at 0x15 → `shared_with` `None`; `AXS` with the address word `0xZZ`, `VS` at 0x10 → `shared_with` `None`
examples: (R-A2L-DEF.140/1 neg) mutant: AXIS_PTS left out of the index (2b as written) → `shared_with` `None`, `VS` encodes → RED

_describe_one
req: R-A2L-DEF.64, R-A2L-DEF.65, R-A2L-DEF.66, R-A2L-DEF.145, R-A2L-DEF.4, R-A2L-DEF.5, R-A2L-DEF.6, R-A2L-DEF.139, R-A2L-DEF.24, R-A2L-DEF.73, R-A2L-DEF.137
in: str name; dict tags_by_name; dict object_sections_by_name; dict compu_methods_by_name; dict compu_tables_by_name; dict a2l_data; dict maps
out: Definition definition
func: changed (E3A-04: Inc 2a's per-name function, `a2l_definition.py:324-572` at `82f5f8e5`; `describe_definitions` calls it once per name). was: Inc 2a's: `_find_tag`, the scalar fields, the method record read inline (`:406-430`), `_object_kind(tag, conversion_type)`, Inc 2's refusal order with the METHOD → CONVERSION → TABLE → TABLE-EMPTY steps inline (`:496-530`); every kind but number, enum and text refused `A2L-DEF-KIND`. / now: gains `maps` (the walk's `axis_pts_by_name` and `mod_common_of`). The method and table steps go through `_conversion_fields`: the same values, refusals and order, guarded by Inc 2a's tests, none of them edited for it. `_read_matrix_dim(section)` gives the MATRIX_DIM words. `kind` = `_object_kind(tag, conversion_type, words)`. For `array`, `curve` or `map` the result is `_describe_array(tag, section, a2l_data, base, maps)`. A VALUE that has a multi-value MATRIX_DIM line gets `A2L-DEF-MATRIX` `<name>: the system cannot read MATRIX_DIM <dims> on a VALUE`, checked right after the kind (R-A2L-DEF.145, E3A-10). Every definition of kind `""` (`A2L-DEF-NAME`, `A2L-DEF-KIND`) gets `element_count` `None` (E3A-03). Every other kind is exactly as Inc 2a. Messages go through Inc 2a's `_clean` (R-A2L-DEF.137).
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.64/6) INLINE3 UBYTE MEASUREMENT `MD161` (`ECU_ADDRESS 0x10`, `MATRIX_DIM 1 6 1`) → `_describe_array` → kind `array`, shape `(1, 6)`, element count `6`, byte length `6`, refusal `None`
examples: (R-A2L-DEF.64/6 neg) mutant: Inc 2a's branch kept (the tag's first number `1`) → kind `number`, byte length `1` (`../evidence-e3/i3e3a-arch-probe-transcript.txt` Q7) → RED
examples: (R-A2L-DEF.145/2) INLINE3 UWORD VALUE `VMD` at 0x10 (`MATRIX_DIM 2 2`) → `A2L-DEF-MATRIX` `VMD: the system cannot read MATRIX_DIM 2 2 on a VALUE`
examples: (R-A2L-DEF.145/2 neg) mutant: the line ignored (Inc 2a) → `VMD` a UWORD number with no refusal → RED
examples: (R-A2L-DEF.4/9, E3A-03) V171 `ASAM.C.CUBE_4.ROW_DIR` → `A2L-DEF-KIND`, kind `""`, element count `None` (not the default `1`)
examples: (holds from Inc 2a, R-A2L-DEF.11/1, .13/1) the conversion refusals through `_conversion_fields`: Inc 2a's messages and order unchanged

_object_kind
req: R-A2L-DEF.64, R-A2L-DEF.65, R-A2L-DEF.66, R-A2L-DEF.71, R-A2L-DEF.4
in: dict tag; str | None conversion_type; tuple[str, ...] | None matrix_words = None
out: tuple[str | None, str] kind
func: changed. was: `(kind, kind_text)` with VAL_BLK, CURVE, MAP and a MEASUREMENT whose tag `matrix_dim` is not `None`/`1` → (`None`, the `<kind>` text). / now: gains `matrix_words` (the words of the MATRIX_DIM line, `_read_matrix_dim`; `None` for no line; E2-10): a VAL_BLK → (`array`, `VAL_BLK`); a CURVE → (`curve`, `CURVE`); a MAP → (`map`, `MAP`); a MEASUREMENT that has a *multi-value MATRIX_DIM line* (CTX: present and not 1 to 3 words each `1` — a number above 1 whatever its leading or inner 1s, `1 6 1`, and a malformed line, E3A-02) → (`array`, `MEASUREMENT`), so R-A2L-DEF.71 refuses a malformed one; every other case as Inc 2 (VALUE, ASCII, a MEASUREMENT with no MATRIX_DIM line or all `1`s → its scalar kind; CUBOID, CUBE_4, MAP_BLOCK, vendor kinds → (`None`, the kind as written)). The tag's first-number `matrix_dim` is no longer read (BL-I3-2).
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.64/1) CHARACTERISTIC `VAL_BLK` → (`array`, `VAL_BLK`)
examples: (R-A2L-DEF.65/1) `CURVE` → (`curve`, `CURVE`); (R-A2L-DEF.66/1) `MAP` → (`map`, `MAP`)
examples: (R-A2L-DEF.66/1 neg) mutant: a MAP given the kind curve → RED
examples: (R-A2L-DEF.64/3) MEASUREMENT, words `8` `4` `2` → (`array`, `MEASUREMENT`); (changed R-A2L-DEF.4/7) words `16` `1` → (`array`, `MEASUREMENT`)
examples: (R-A2L-DEF.64/6, E3A-02) MEASUREMENT, words `1` `6` `1` → (`array`, `MEASUREMENT`); (R-A2L-DEF.71/5) words `4` `x` → (`array`, `MEASUREMENT`)
examples: (R-A2L-DEF.64/6 neg) mutant: Inc 2a's code, the tag's first number (`1`) → (`number`, `MEASUREMENT`) → RED
examples: (holds from Inc 2, R-A2L-DEF.1/2) MEASUREMENT, no MATRIX_DIM line, `IDENTICAL` → (`number`, `MEASUREMENT`); words `1` `1` → (`number`, `MEASUREMENT`)
examples: (R-A2L-DEF.4 new case) `CUBE_4` → (`None`, `CUBE_4`); (R-A2L-DEF.4/4) `CUBOID` → (`None`, `CUBOID`)

decode_definition
req: R-A2L-DEF.120, R-A2L-DEF.25, R-A2L-DEF.137
in: Definition definition; dict a2l_data; Mapping[int, int] image
out: Decoded | Refusal result
func: changed. was: Inc 2's: the definition's refusal; `_read_stored_value`; then the text / enum / number conversion (the number from the definition's method fields, E3A-03; `Decoded.text` with U+FFFD, R-A2L-DEF.137). / now: the definition's refusal (R-A2L-DEF.25); then, for kind `array`, `curve` or `map`, `A2L-DEF-ELEMENTS` `<name>: it holds <n> values — decode and encode it value by value` (`<n>` = `element_count`); then `_read_stored_value` (a refusal passes through) and `_decode_stored(definition, a2l_data, stored)` — the conversion half moved there unchanged (slice #20, decided here). Every Inc 2 example of this node holds.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.120/1) V171 `ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR`, image SWORD 1 … 12 at 0x810100 → refusal `A2L-DEF-ELEMENTS` `ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR: it holds 12 values — decode and encode it value by value` (base: the tag table's raw `1`, B1 line 12)
examples: (R-A2L-DEF.120/1 neg) mutant: the first element decoded as the value → `Decoded(1, 1, "1")` → RED
examples: (R-A2L-DEF.25 on an array) V171 `ASAM.C.CURVE.STD_AXIS` → its `A2L-DEF-ALIGNMENT` refusal, not `A2L-DEF-ELEMENTS`
examples: (changed AT-B103-I2-3) C08 clean: the `322` objects of kind number, enum or text decode with `0` refusals (Inc 2's B2 P5f); each of the `140` arrays, curves and maps gives `A2L-DEF-ELEMENTS`; `firmware_issues.a2l`: Inc 2's refusals unchanged (`1` `A2L-DEF-METHOD`, `1` `A2L-DEF-NAME` `VALUE_0001: the A2L declares that name more than once`, `5` `A2L-DEF-BYTES`), its `140` arrays, curves and maps `A2L-DEF-ELEMENTS`
examples: (holds from Inc 2, R-A2L-040/def-1) V171 `ASAM.C.SCALAR.SWORD.IDENTICAL`, image 34 12 → stored `4660`, text `4660`

encode_definition
req: R-A2L-DEF.120, R-A2L-DEF.25, R-A2L-DEF.140
in: Definition definition; dict a2l_data; str text; Mapping[int, int] image
out: Encoded | Refusal result
func: changed (3b; it is 2b's node). was: Inc 2's encode order (1) … (10) (step 9 the shared-bytes refusal of R-A2L-DEF.138). / now: (1) the definition's refusal; (1b) kind `array`, `curve` or `map` → `A2L-DEF-ELEMENTS` (the R-A2L-DEF.120 message); then Inc 2's (2) … (10) unchanged. `encode_values` calls it once per edited element on that element's definition (kind number or enum); that definition carries its object's `shared_with` (a `replace`), so step 9 refuses the element of an object that shares bytes, `<name>` its element name and `<address>` its own address (a reading for 3b's re-review, `../E2-rulings.md`).
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.120/2) V171 `…MATRIX_DIM_3_4.ROW_DIR`, `5` → `A2L-DEF-ELEMENTS` `ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR: it holds 12 values — decode and encode it value by value`; no bytes
examples: (holds from Inc 2, R-A2L-DEF.41/2) V171 `ASAM.C.SCALAR.SWORD.IDENTICAL`, `  -5 ` → `Encoded(0x810004, FB FF, ())`
examples: (R-A2L-DEF.140/1, /2, 3b) INLINE3 `VS` at 0x14 (shared with `AXS`), `35` → step 9's `A2L-DEF-OVERLAP` `VS: its bytes at 0x14 are shared with AXS`, no bytes; `VS` at 0x15 → `Encoded(0x15, 23, ())`

### New nodes: building (`s19_app/tui/a2l_definition.py`)

_conversion_fields
req: R-A2L-DEF.81, R-A2L-DEF.102, R-A2L-DEF.103
in: str name; str | None method_name; dict compu_methods_by_name; dict compu_tables_by_name
out: tuple[dict, Refusal | None] conversion
func: new (E2-3: factored out of Inc 2's `describe_definitions`, so an object and each axis read a method one way; rebased: lookups in the walk's maps, E3A-32). `method_name` `None` or `NO_COMPU_METHOD` → fields `conversion_type` `None`, `kind` `number`, `coeffs_linear` / `coeffs` / `compu_tab_ref` `None`, no table, refusal `None`. Else `_read_method_record(method_name, compu_methods_by_name)`; `None` → `A2L-DEF-METHOD` `<name>: the conversion method <method> is not declared in the A2L`; a type word outside IDENTICAL, LINEAR, RAT_FUNC, TAB_INTP, TAB_NOINTP, TAB_VERB → `A2L-DEF-CONVERSION`; TAB_VERB → `kind` `enum`, the COMPU_TAB_REF word as `enum_table`, `_read_enum_table(enum_table, compu_tables_by_name)` → `None` → `A2L-DEF-TABLE`, no entries → `A2L-DEF-TABLE-EMPTY`. Gives the fields `conversion_type`, `kind`, `coeffs_linear`, `coeffs`, `compu_tab_ref` (the record's words, E3A-03: an axis's points definition carries its own method's), `record_format`, `record_unit`, `enum_table`, `enum_entries`, `default_text` and the first refusal (Inc 2's order: METHOD, CONVERSION, TABLE, TABLE-EMPTY), `<name>` as given, messages as R-A2L-DEF.137.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.103/1) `CA.X`, `CM_GONE` → refusal `A2L-DEF-METHOD` `CA.X: the conversion method CM_GONE is not declared in the A2L`
examples: (R-A2L-DEF.103/1 neg) mutant: the object's name passed for an axis → `CA: the conversion method CM_GONE is not declared in the A2L` → RED
examples: (R-A2L-DEF.103/2) `MA.Y`, `CM_V` (`TAB_VERB "%.0" ""`, no COMPU_TAB_REF) → `A2L-DEF-TABLE` `MA.Y: the table (none) of CM_V is not declared in the A2L`
examples: (R-A2L-DEF.102/1) `ASAM.C.MAP.STD_AXIS.STD_AXIS.Y`, `CM.TAB_VERB.NO_DEFAULT_VALUE` → kind `enum`, enum table `CM.TAB_VERB.NO_DEFAULT_VALUE.REF`, refusal `None` (V171 `:3091-3094`)
examples: (R-A2L-DEF.81/1, /2) `VC`, `CM_GONE` → `VC: the conversion method CM_GONE is not declared in the A2L`; `VT`, `CM_V` with `COMPU_TAB_REF VT_GONE` → `VT: the table VT_GONE of CM_V is not declared in the A2L`
examples: (holds from Inc 2, R-A2L-DEF.11/1, .12/1, .13/1, .17/1) the same inputs give the same refusals through `describe_definitions`
examples: (R-A2L-DEF.102/4, rebased) INLINE3 COM_AXIS naming `CM_A` (`CM(LINEAR 2 0)`) → `coeffs_linear` (`2.0`, `0.0`) — the axis method's, not the axis object's `CM_B` (`3`, `0`) — so `_decode_stored` converts the points without `sections` (E3A-03)

_describe_array
req: R-A2L-DEF.67, R-A2L-DEF.68, R-A2L-DEF.69, R-A2L-DEF.70, R-A2L-DEF.71, R-A2L-DEF.72, R-A2L-DEF.73, R-A2L-DEF.74, R-A2L-DEF.75, R-A2L-DEF.76, R-A2L-DEF.77, R-A2L-DEF.78, R-A2L-DEF.79, R-A2L-DEF.80, R-A2L-DEF.81, R-A2L-DEF.82, R-A2L-DEF.83, R-A2L-DEF.89, R-A2L-DEF.91, R-A2L-DEF.103, R-A2L-DEF.104, R-A2L-DEF.144, R-A2L-DEF.145, R-A2L-DEF.7.1, R-A2L-DEF.7.2, R-A2L-DEF.137
in: dict tag; dict | None section; dict a2l_data; Definition base; dict maps
out: Definition definition
func: new. Builds an array, curve or map in the *array refusal order*, each step filling its fields when its inputs exist and the definition keeping the first refusal: (1) MATRIX_DIM: words malformed → `A2L-DEF-MATRIX` `<name>: MATRIX_DIM <dims> is not 1 to 3 whole numbers of at least 1`; a curve or map with a multi-value MATRIX_DIM line → `A2L-DEF-MATRIX` `<name>: the system cannot read MATRIX_DIM <dims> on a <kind>` (R-A2L-DEF.145, E3A-10); (1b, E2-1 accepted) a MEASUREMENT array without a datatype → `A2L-DEF-DATATYPE`; (2) VAL_BLK, curve, map: `_read_record_layout(tag record layout, a2l_data, name)`: `None` → `A2L-DEF-LAYOUT` `<name>: the record layout <layout> is not declared in the A2L`; a refusal (positions, parts, modes, component datatypes) passes; no FNC_VALUES → `A2L-DEF-LAYOUT-VALUES` `<name>: the record layout <layout> holds no FNC_VALUES`; `datatype` and `index_mode` from FNC_VALUES. A MEASUREMENT: `datatype` the header's, `index_mode` its LAYOUT word else `ROW_DIR`, no layout; (3) curve, map: not 1 / 2 AXIS_DESCR children → `A2L-DEF-AXES` `<name>: a <kind> declares <n> AXIS_DESCR and needs <m>` (E3A-15); `_read_axis(name, letter, axis section, layout, a2l_data, maps)` for X then Y, each axis all its checks before the next (a refusal passes; E2-4, confirmed by E3A-11); `shape` = the point counts, X first. Array: `shape` = `_array_shape(tag, section, datatype, matrix)`; (4) three dimensions and COLUMN_DIR → `A2L-DEF-INDEX-MODE` `<name>: the system cannot read COLUMN_DIR in three dimensions`; (5) `element_count` = the product of `shape` (`None` when no shape was read, E3A-03); VAL_BLK, curve, map: `_place_components(layout, shape)` → `values_offset`, STD axes' `offset` / `count_offset` / `count_datatype` / `fixed_count`; `_check_module_alignment` on the layout (with `_module_common(section, maps["mod_common_of"])`) and on each COM axis object's layout (with its axis object's) → an unreadable MOD_COMMON line of a class a component follows → `A2L-DEF-ALIGNMENT` `<name>: the MOD_COMMON line ALIGNMENT_<class> <word> cannot be read` (R-A2L-DEF.144, E3A-09); a moved component → `A2L-DEF-ALIGNMENT` `<name>: <component> of the record layout <layout> lies at offset <a>, or at <b> under the MOD_COMMON alignment`; `byte_length` = element count × the datatype's size (array, R-A2L-DEF.74) or the walk's end (curve, map, R-A2L-DEF.75); (6) `_array_shape`'s `A2L-DEF-SHAPE` or `A2L-DEF-LENGTH`; (7) no address, or no byte length → `A2L-DEF-ADDRESS` `<name>: the object has no address or no length` (R-A2L-DEF.7.1); then Inc 2's span bounds on the address and the byte length (R-A2L-DEF.7.2: below 1 or above 1,048,576 bytes, a negative address, or a last byte above 0xFFFFFFFF) → `A2L-DEF-ADDRESS` `<name>: its span of <length> bytes at <address> cannot be read`; (8) the values' refusals (R-A2L-DEF.81): the conversion refusal of `base` (`_conversion_fields`), then the mask refusal `describe_definitions` recorded while reading the object record (2a's R-A2L-DEF.19 clauses; 2b's join when 2b lands), or `_check_bit_mask` false on `datatype` → `A2L-DEF-MASK` `<name>: the bit mask <mask> cannot be applied to <datatype>`; (9) the axis points' refusals, X then Y (`points.refusal`, R-A2L-DEF.103). Returns `dataclasses.replace(base, …)` with the array fields and that refusal (every Inc 2 field kept, E3A-22).
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.67/1, .73/1, .74/1, .77/1, .7.1/arr-1) V171 `ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR` → shape `(3, 4)`, element count `12`, byte length `24`, datatype `SWORD`, index mode `ROW_DIR`, values offset `0`, record layout `RL.FNC.SWORD.ROW_DIR`, refusal `None` (base: matrix_dim `3`, length `None`, element count `1`, B3 P1, B1 line 12)
examples: (R-A2L-DEF.67/1 neg) mutant: the first number only (`a2l.py`'s) → shape `(3,)` → RED
examples: (R-A2L-DEF.77/2) `…MATRIX_DIM_3_4.COLUMN_DIR` → datatype `SWORD`, index mode `COLUMN_DIR`, values offset `0`
examples: (R-A2L-DEF.67/2) `…MATRIX_DIM_6.ROW_DIR` → shape `(6,)`, byte length `12`
examples: (R-A2L-DEF.67/3, .73/2, .74/2) `ASAM.M.MATRIX_DIM_8_4_2.UBYTE.IDENTICAL` → shape `(8, 4, 2)`, element count `64`, datatype `UBYTE`, byte length `64` (base: tag length `8`)
examples: (R-A2L-DEF.67/4, changed R-A2L-DEF.4/7) `ASAM.M.MATRIX_DIM_16_1.UBYTE.IDENTICAL` → shape `(16,)`, address `0x13A30`, byte length `16`
examples: (R-A2L-DEF.67/5) SOFTA `AIP_EGZ.URB_EHC_EdGiiqKprxgmn_CGN.SWN_QDB_SPO_Bf_UuiBrt16_Wyyhvo` (`MATRIX_DIM 8 1 1`) → shape `(8,)`, refusal `A2L-DEF-ADDRESS` (no software_a MEASUREMENT has an address, Inc 2 E2-3) (B3 P6)
examples: (R-A2L-DEF.68/1, .74/3) SOFTA `AljxdUybv__Mylof2.XqtqovICCYa_UatfexuoUgpWibdew` (`NUMBER 4`, layout `FNC_VALUES 0 SWORD ROW_DIR DIRECT`) → shape `(4,)`, byte length `8`, refusal `None` (base: length `None`, B3 P6)
examples: (R-A2L-DEF.69/1, .73/5, .74/4) C08 clean `VAL_BLK_0001` (`LENGTH 256`, UWORD) → shape `(128,)`, element count `128`, byte length `256`, address `0x800000`
examples: (R-A2L-DEF.72/1, .73/3) V171 `ASAM.C.CURVE.FIX_AXIS.PAR_DIST` → shape `(6,)`; `ASAM.C.CURVE.COM_AXIS` → shape `(8,)`, element count `8`
examples: (R-A2L-DEF.72/2, .73/4) V171 `ASAM.C.MAP.COM_AXIS.FIX_AXIS` → shape `(8, 3)`, element count `24`
examples: (R-A2L-DEF.72/2 neg) mutant: axes taken Y first → shape `(3, 8)` → RED
examples: (R-A2L-DEF.72/3, .73/6, .73/7) C08 `MAP_0001` → shape `(8, 8)`, `64`; `CURVE_0001` → `32`
examples: (R-A2L-DEF.73/8) V171 `ASAM.C.CURVE.STD_AXIS` → refusal `A2L-DEF-ALIGNMENT`, element count `8`, byte length `25` (the layout reading)
examples: (R-A2L-DEF.75/1, /2) V171 `ASAM.C.CURVE.COM_AXIS` → byte length `16`; `ASAM.C.MAP.COM_AXIS.FIX_AXIS` → `48` (base: `None`, B1 line 16; B3 P3)
examples: (R-A2L-DEF.75/1 neg) mutant: the axis object's 9 bytes added → `25` → RED
examples: (R-A2L-DEF.75/3, /4) C08 `CURVE_0001` → `64`; `MAP_0001` → `128`
examples: (R-A2L-DEF.77/3) INLINE3 `CS` = C(STD(4); `NO_AXIS_PTS_X 1 UBYTE`, `AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT`, `FNC_VALUES 3 SWORD ROW_DIR DIRECT`) → datatype `SWORD`, index mode `ROW_DIR`, values offset `5` (B3b Q1)
examples: (R-A2L-DEF.77/3 neg) mutant: the layout's first datatype word → `UBYTE` → RED
examples: (R-A2L-DEF.78/1, /2) INLINE3 UBYTE MEASUREMENT `MC` (`MATRIX_DIM 3 2`, `LAYOUT COLUMN_DIR`) → index mode `COLUMN_DIR`; with `LAYOUT ROW_DIR` → `ROW_DIR` (B3b Q2: the tag table keeps matrix_dim `3`, length `3`)
examples: (R-A2L-DEF.79/1) V171 `ASAM.M.MATRIX_DIM_8_2.UBYTE.IDENTICAL` → index mode `ROW_DIR`, shape `(8, 2)`
examples: (R-A2L-DEF.80/1, /2) INLINE3 `M3` (`MATRIX_DIM 2 2 2`, `LAYOUT COLUMN_DIR`) → `A2L-DEF-INDEX-MODE` `M3: the system cannot read COLUMN_DIR in three dimensions`; `V3` (FNC_VALUES COLUMN_DIR) → `V3: the system cannot read COLUMN_DIR in three dimensions`
examples: (R-A2L-DEF.81/1, /2) INLINE3 `VC` → `A2L-DEF-METHOD` `VC: the conversion method CM_GONE is not declared in the A2L`; `VT` → `A2L-DEF-TABLE` `VT: the table VT_GONE of CM_V is not declared in the A2L`
examples: (R-A2L-DEF.81/3) INLINE3 UWORD MAP `MZ` with `BIT_MASK 0` → `A2L-DEF-MASK` `MZ: the bit mask 0 cannot be applied to UWORD`
examples: (R-A2L-DEF.81/4, E2-1) INLINE3 MEASUREMENT `MF` `FOO CM_IDENT 0 0 0 1`, `ECU_ADDRESS 0x10`, `MATRIX_DIM 4` → `A2L-DEF-DATATYPE` `MF: the object declares no datatype the system can read` (under the order as E1 wrote it: `A2L-DEF-ADDRESS`, no byte length)
examples: (R-A2L-DEF.81/1 neg) mutant: arrays skip Inc 2's checks (identity on an undeclared method) → a definition with no refusal → RED
examples: (R-A2L-DEF.82/1, .104/1) CHECK `Curve_ExternalAxis` (undeclared layout and dangling `AXIS_PTS_REF Axis_0`) → `A2L-DEF-LAYOUT` `Curve_ExternalAxis: the record layout Curve_ExternalAxis_RecordLayout is not declared in the A2L` (B3 P6)
examples: (R-A2L-DEF.104/1 neg) mutant: the axes checked before the layout → `A2L-DEF-AXIS-REF` → RED
examples: (R-A2L-DEF.82/2) INLINE3 `VG` → `VG: the record layout RL_GONE is not declared in the A2L`
examples: (R-A2L-DEF.83/1) INLINE3 `CF` (layout `RL_AX` = `AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT`) → `A2L-DEF-LAYOUT-VALUES` `CF: the record layout RL_AX holds no FNC_VALUES`
examples: (R-A2L-DEF.91/1 … /3) INLINE3 CURVE `C2` with two `STD(2)` axes → `A2L-DEF-AXES` `C2: a CURVE declares 2 AXIS_DESCR and needs 1`; MAP `M1` with one → `M1: a MAP declares 1 AXIS_DESCR and needs 2`; CURVE `C0` with none → `C0: a CURVE declares 0 AXIS_DESCR and needs 1` (E3A-15)
examples: (R-A2L-DEF.91/2 neg) mutant: a MAP's single axis used as X with Y of count 1 → shape `(n, 1)` → RED
examples: (R-A2L-DEF.104/2, /3) INLINE3 `VQ` (`MATRIX_DIM 0`, layout `RL_GONE`) → `A2L-DEF-MATRIX`; a CURVE with a RES_AXIS whose layout holds `RESERVED 2 BYTE` → `A2L-DEF-LAYOUT-PART`
examples: (R-A2L-DEF.7.1/arr-2) INLINE3 UBYTE MEASUREMENT `MA0` (`MATRIX_DIM 4`, no ECU_ADDRESS) → `A2L-DEF-ADDRESS` `MA0: the object has no address or no length`, shape `(4,)`
examples: (R-A2L-DEF.89/1, /2) V171 `ASAM.C.CURVE.STD_AXIS` → `A2L-DEF-ALIGNMENT` `ASAM.C.CURVE.STD_AXIS: FNC_VALUES of the record layout RL.CURVE.SWORD.SBYTE.DECR lies at offset 9, or at 10 under the MOD_COMMON alignment`; `ASAM.C.MAP.STD_AXIS.STD_AXIS` → `ASAM.C.MAP.STD_AXIS.STD_AXIS: FNC_VALUES of the record layout RL.MAP.SWORD.SBYTE.SBYTE.INCR lies at offset 11, or at 12 under the MOD_COMMON alignment` (B3 P3, P5)
examples: (AT-B103-I3-1, build) V171's 40 VAL_BLK, MATRIX_DIM MEASUREMENT, CURVE, MAP, CUBOID and CUBE_4 objects → 11 arrays, 6 curves and 3 maps with no refusal; 8 curves and 5 maps `A2L-DEF-ALIGNMENT` (every STD_AXIS record: `…CURVE.STD_AXIS`, `.DISCRETE`, `ASAM.C.CURVE_AXIS`, the two MONOTONY curves, `DEPENDENT.CURVE_1 … _3`; `…MAP.STD_AXIS.STD_AXIS`, `.DISCRETE`, `DEPENDENT.MAP_1 … _3`); 2 curves `A2L-DEF-AXIS-KIND` (`CURVE_AXIS`, `RES_AXIS`); 5 `A2L-DEF-KIND` (3 CUBOID, 2 CUBE_4) (B3 P5 tally)
examples: (AT-B103-I3-3, build) C08 `firmware.a2l` and `firmware_issues.a2l` → each `60` VAL_BLK (element count `128`), `60` CURVE (`32`), `20` MAP (`64`), `0` refusals (B3 P7)
examples: (AT-B103-I3-4) SOFTA → `101` VAL_BLK, `158` CURVE, `11` MAP with `0` refusals (none `A2L-DEF-AXIS-REF`, none `A2L-DEF-LAYOUT-PART`); element counts = NUMBER, the axis object's max axis points, or the AXIS_DESCR's; its `196` MEASUREMENT arrays give `A2L-DEF-ADDRESS` (B3 P6)
examples: (R-A2L-DEF.81/5, E3S-01) INLINE3 UWORD VAL_BLK `VZ` (`MATRIX_DIM 2`, `BIT_MASK 0xZZ`) → `A2L-DEF-MASK` `VZ: the bit mask 0xZZ cannot be applied to UWORD` (step 8: a mask word the system cannot read, 2a's clause of R-A2L-DEF.19)
examples: (R-A2L-DEF.81/5 neg) mutant: an unreadable mask word read as no mask (the unmasked path, which writes the whole word) → refusal `None` → RED
examples: (R-A2L-DEF.7.2/arr-1, /arr-2) INLINE3 UBYTE VAL_BLK `VH` at 0x10 (`MATRIX_DIM 1048577`) → `A2L-DEF-ADDRESS` `VH: its span of 1048577 bytes at 0x10 cannot be read`, shape `(1048577,)`, element count `1048577`; UWORD VAL_BLK `VW` at 0xFFFFFFF0 (`MATRIX_DIM 3 4`) → `VW: its span of 24 bytes at 0xFFFFFFF0 cannot be read`
examples: (R-A2L-DEF.7.2/arr-3) INLINE3 UBYTE MEASUREMENT `MH` at 0x10 (`MATRIX_DIM 1024 1024`) → refusal `None`, byte length `1048576`
examples: (R-A2L-DEF.7.2/arr-1 neg) mutant: .7.2's bounds not applied to an array's computed length → a definition of `1048577` bytes → RED
examples: (R-A2L-DEF.7.1/arr-3) INLINE3 `CBIG` = C(STD(600000); `AXIS_PTS_X 1 UWORD …`, `FNC_VALUES 2 UWORD …`) → `_place_components` `None` (the walk stops past `MAX_A2L_DECODE_BYTES`) → byte length `None` → `A2L-DEF-ADDRESS` `CBIG: the object has no address or no length`, shape `(600000,)`
examples: (R-A2L-DEF.137/arr-1, /arr-4) INLINE3 `VG` naming the layout `RL\x1bX` → `A2L-DEF-LAYOUT` `VG: the record layout RL�X is not declared in the A2L`; `VX` with `MATRIX_DIM 3 \x1b` → `A2L-DEF-MATRIX` `VX: MATRIX_DIM 3 � is not 1 to 3 whole numbers of at least 1`
examples: (R-A2L-DEF.137/arr-1 neg) mutant: the layout word echoed raw → an ESC in the message → RED
examples: (R-A2L-DEF.73/9, E3A-03) INLINE3 `VX` (`MATRIX_DIM 3 0`) → `A2L-DEF-MATRIX`, shape `()`, element count `None`
examples: (R-A2L-DEF.73/9 neg) mutant: E2-11's `0`, or the default `1` → RED
examples: (R-A2L-DEF.145/1, /3) INLINE3 `CMD` = C(STD(2); `FNC_VALUES 1 UWORD ROW_DIR DIRECT`) with `MATRIX_DIM 4` → `A2L-DEF-MATRIX` `CMD: the system cannot read MATRIX_DIM 4 on a CURVE`; with `MATRIX_DIM 1` → refusal `None`, shape `(2,)`
examples: (R-A2L-DEF.144/1) INLINE3 MOD_COMMON `ALIGNMENT_WORD x`, `CA2` of R-A2L-DEF.88/2 → `A2L-DEF-ALIGNMENT` `CA2: the MOD_COMMON line ALIGNMENT_WORD x cannot be read`

_read_matrix_dim
req: R-A2L-DEF.67, R-A2L-DEF.71, R-A2L-DEF.145, R-A2L-DEF.58.2
in: dict | None section
out: tuple[tuple[str, ...], tuple[int, ...] | None] | None matrix
func: new. The object's lines with comments left out (`_strip_a2l_comments` on the joined lines, split back at line ends, each line split by `_split_line_respecting_quotes`); the first line whose first word is `MATRIX_DIM`: `(words after it, shape)`; `shape` = those words as whole numbers (CTX-A2L-DEF *whole number*: 1 to 9 ASCII digits; `int()` runs only on such a word, so a longer one cannot raise, R-A2L-DEF.58.2) with every trailing `1` left out, keeping one — `None` when there is no word, more than three, or a word that is not a whole number of at least 1. `None` when there is no such line. (E1's slice had `tuple | Refusal | None`; the message needs the name, so `_describe_array` composes it, E2-10.)
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.67/1) V171 `…MATRIX_DIM_3_4.ROW_DIR` → (`3`, `4`), `(3, 4)` (B3 P1)
examples: (R-A2L-DEF.67/4) `MATRIX_DIM 16 1   /* describes a 2-dim object … */` → (`16`, `1`), `(16,)`
examples: (R-A2L-DEF.67/4 neg) mutant: trailing 1s kept → `(16, 1)` → RED
examples: (R-A2L-DEF.67/5) `MATRIX_DIM 8 1 1` → `(8,)`; (R-A2L-DEF.135/1) DEFC `MATRIX_DIM 3 2` → `(3, 2)`
examples: (R-A2L-DEF.71/1 … /4) `MATRIX_DIM 3 0` → (`3`, `0`), `None`; `2 2 2 2` → `None`; `x` → `None`; `MATRIX_DIM` alone → (), `None` (`<dims>` `(none)`)
examples: (R-A2L-DEF.71/1 neg) mutant: `3 0` read as shape `(3, 0)` → element count `0` → RED
examples: (R-A2L-DEF.58.2/arr-1) `MATRIX_DIM` and a 5,000-digit word → (the word), `None` → `_describe_array` gives `A2L-DEF-MATRIX`; no exception
examples: (R-A2L-DEF.58.2/arr-1 neg) mutant: `int(word)` on any digit run → `ValueError` (CPython 3.11: more than 4,300 digits) → RED
examples: (R-A2L-DEF.1/2, holds) V171 `ASAM.M.SCALAR.UBYTE.IDENTICAL` (no MATRIX_DIM line) → `None`

_array_shape
req: R-A2L-DEF.68, R-A2L-DEF.69, R-A2L-DEF.70, R-A2L-DEF.76, R-A2L-DEF.58.2
in: dict tag; dict | None section; str | None datatype; tuple[tuple[str, ...], tuple[int, ...] | None] | None matrix
out: tuple[int, ...] | Refusal | None shape
func: new (D-6 A). The MATRIX_DIM shape; else, for a VAL_BLK, the first NUMBER line's whole number (CTX *whole number*); else the first LENGTH or DATA_SIZE line's whole number divided by the datatype's size — not a whole multiple → `A2L-DEF-SHAPE` `<name>: its length <length> is not a whole number of <datatype> values`. Then a LENGTH or DATA_SIZE **line** (the object's own lines; the tag's inferred length is not read, B3 P1) whose number differs from element count × size → `A2L-DEF-LENGTH` `<name>: its length <length> differs from the <bytes> bytes of <count> <datatype> values`. `None` when nothing gives a shape (then `_describe_array` gives `A2L-DEF-ADDRESS`). A NUMBER word that is not a whole number of at least 1 is passed over (E2-7).
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.68/1) SOFTA `AljxdUybv__Mylof2.XqtqovICCYa_UatfexuoUgpWibdew`, `NUMBER 4` → `(4,)`
examples: (R-A2L-DEF.68/1 neg) mutant: NUMBER ignored → `None` → `A2L-DEF-ADDRESS` → RED
examples: (R-A2L-DEF.68/2) INLINE3 `VB10`, `NUMBER 10` → `(10,)`
examples: (R-A2L-DEF.69/1) C08 `VAL_BLK_0001`, `LENGTH 256`, UWORD → `(128,)`; (R-A2L-DEF.69/2) INLINE3 `VS6`, SWORD, `LENGTH 6` → `(3,)`
examples: (R-A2L-DEF.69/1 neg) mutant: the length taken as the element count → `(256,)` → RED
examples: (R-A2L-DEF.70/1) INLINE3 `VS`, UWORD, `LENGTH 5` → `A2L-DEF-SHAPE` `VS: its length 5 is not a whole number of UWORD values`
examples: (R-A2L-DEF.70/1 neg) mutant: rounded down → `(2,)` → RED
examples: (R-A2L-DEF.76/1, /2) INLINE3 `VL` (UWORD, `MATRIX_DIM 4`, `LENGTH 6`) → `A2L-DEF-LENGTH` `VL: its length 6 differs from the 8 bytes of 4 UWORD values`; `ML` (UBYTE MEASUREMENT, `MATRIX_DIM 4 2`, `DATA_SIZE 4`) → `ML: its length 4 differs from the 8 bytes of 8 UBYTE values`
examples: (R-A2L-DEF.76/1 neg) mutant: the LENGTH line preferred → shape `(3,)` → RED
examples: (R-A2L-DEF.58.2/arr-2) INLINE3 `VN5` (`NUMBER` and a 5,000-digit word, no MATRIX_DIM or LENGTH) → the NUMBER word passed over → `None` → `_describe_array` gives `A2L-DEF-ADDRESS` `VN5: the object has no address or no length`; no exception
examples: (holds on base) V171 `ASAM.M.MATRIX_DIM_8_4_2.UBYTE.IDENTICAL`: no LENGTH or DATA_SIZE line (the tag's `8` is inferred) → `(8, 4, 2)`, no `A2L-DEF-LENGTH` (B3 P1)

_read_record_layout
req: R-A2L-DEF.82, R-A2L-DEF.84, R-A2L-DEF.85, R-A2L-DEF.86, R-A2L-DEF.87, R-A2L-DEF.90, R-A2L-DEF.58.2
in: str | None name; dict a2l_data; str owner
out: dict | Refusal | None layout
func: new (D-12 A). `a2l_data["record_layouts_by_name"][name]`; not there → `None`. Its lines with comments left out (as `_read_matrix_dim`), each classified: a *component* (first word FNC_VALUES, AXIS_PTS_X, AXIS_PTS_Y, NO_AXIS_PTS_X, NO_AXIS_PTS_Y, and at most the words CTX *component* lists for it — 5, or 3 for NO_AXIS_PTS_X|Y; a line with more is a part, its `<component>` the first extra word, E3A-08); a *layout keyword* (FIX_NO_AXIS_PTS_X/Y with a whole number, ALIGNMENT_<class> with a whole number of at least 1, a line holding only DIRECT; positions and these numbers are CTX *whole numbers*: 1 to 9 ASCII digits, `int()` only on such a word, R-A2L-DEF.58.2); anything else a *part*. Then, the first that applies, `<name>` = `owner`: positions of the components not distinct whole numbers → `A2L-DEF-LAYOUT-POSITION` `<name>: the positions of the record layout <layout> do not give one order`; the first part (file order) → `A2L-DEF-LAYOUT-PART` `<name>: the record layout <layout> holds <component>, which the system cannot read` (also a second line of one component, and a layout keyword with a bad number, E2-7); in position order, a FNC_VALUES mode not ROW_DIR / COLUMN_DIR, an AXIS_PTS order not INDEX_INCR / INDEX_DECR, an address type not DIRECT → `A2L-DEF-LAYOUT-MODE` `<name>: the record layout <layout> stores <component> as <word>, which the system cannot read` (`(none)` for a missing word); a component datatype outside UBYTE, SBYTE, UWORD, SWORD, ULONG, SLONG, A_UINT64, A_INT64, FLOAT16_IEEE, FLOAT32_IEEE, FLOAT64_IEEE, or a NO_AXIS_PTS_X|Y datatype that is not a *count datatype* (an integer one, so the count `_current_count` reads is always an `int`, E3S3-01) → `A2L-DEF-LAYOUT-DATATYPE` `<name>: the record layout <layout> gives <component> the datatype <word>, which the system cannot read`. Else the dict `name`, `components` (word tuples in position order), `alignment` (the ALIGNMENT word tuples), `fixed` (`{"X": n, "Y": n}` from FIX_NO lines).
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.77/1) V171 `RL.FNC.SWORD.ROW_DIR` → components ((`FNC_VALUES`, `1`, `SWORD`, `ROW_DIR`, `DIRECT`),)
examples: (R-A2L-DEF.88 input) V171 `RL.CURVE.SWORD.SBYTE.DECR` (trailing `/* current number of axis points */`) → components `NO_AXIS_PTS_X 1 UBYTE`, `AXIS_PTS_X 2 SBYTE INDEX_DECR DIRECT`, `FNC_VALUES 3 SWORD ROW_DIR DIRECT` (B3 P2)
examples: (R-A2L-DEF.82/2) `RL_GONE` → `None`
examples: (R-A2L-DEF.84/1 … /5) INLINE3 `RL_P` adding `RESERVED 3 BYTE` → `A2L-DEF-LAYOUT-PART` `CP: the record layout RL_P holds RESERVED, which the system cannot read`; `AXIS_RESCALE_X 3 UBYTE 5 INDEX_INCR DIRECT` → `… holds AXIS_RESCALE_X, which …`; `IDENTIFICATION 3 UWORD` → `… holds IDENTIFICATION, which …`; `AXIS_PTS_Z 3 UBYTE INDEX_INCR DIRECT` → `… holds AXIS_PTS_Z, which …`; `SRC_ADDR_X 3` → `… holds SRC_ADDR_X, which …`
examples: (R-A2L-DEF.84/1 neg) mutant: the unknown line skipped → FNC_VALUES offsets shift (a definition) → RED
examples: (R-A2L-DEF.84/6, E3A-17) INLINE3 `RL_P` adding `STATIC_RECORD_LAYOUT` → `… holds STATIC_RECORD_LAYOUT, which …`
examples: (R-A2L-DEF.84/7, E3A-08) INLINE3 `RL_P2` with `NO_AXIS_PTS_X 1 UBYTE AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT` on one line → `A2L-DEF-LAYOUT-PART` `CP2: the record layout RL_P2 holds AXIS_PTS_X, which the system cannot read`
examples: (R-A2L-DEF.84/7 neg) mutant: the extra words ignored → the frozen walk puts FNC_VALUES at `1`, not `5` (`../evidence-e3/i3e3a-arch-probe-transcript.txt` Q8) → RED
examples: (holds on base) V171 `RL.AXIS_PTS.RES_AXIS` → `A2L-DEF-LAYOUT-PART` naming `NO_RESCALE_X` (its first part, B3 P2)
examples: (R-A2L-DEF.85/1 … /4) INLINE3 `RL_A` = `FNC_VALUES 1 UWORD ALTERNATE_WITH_X DIRECT` → `A2L-DEF-LAYOUT-MODE` `VA: the record layout RL_A stores FNC_VALUES as ALTERNATE_WITH_X, which the system cannot read`; `AXIS_PTS_X 1 UBYTE INDEX_X DIRECT` → `… stores AXIS_PTS_X as INDEX_X, which …`; `FNC_VALUES 1 UWORD ROW_DIR PBYTE` → `… stores FNC_VALUES as PBYTE, which …`; `FNC_VALUES 1 UWORD` → `… stores FNC_VALUES as (none), which …`
examples: (R-A2L-DEF.85/1 neg) mutant: ALTERNATE_WITH_X read as ROW_DIR → a definition → RED
examples: (R-A2L-DEF.86/1, /2) INLINE3 `RL_D` = `FNC_VALUES 1 FOO ROW_DIR DIRECT` → `A2L-DEF-LAYOUT-DATATYPE` `VD: the record layout RL_D gives FNC_VALUES the datatype FOO, which the system cannot read`; `RL_B` with `AXIS_PTS_X 1 BYTE INDEX_INCR DIRECT` → `… gives AXIS_PTS_X the datatype BYTE, which …`
examples: (R-A2L-DEF.86/2 neg) mutant: `DATATYPE_SIZES` used (BYTE is one byte) → a definition → RED
examples: (R-A2L-DEF.86/3, .58.2/arr-9, E3S3-01) INLINE3 `RL_CQ` with `NO_AXIS_PTS_X 1 FLOAT16_IEEE` → `A2L-DEF-LAYOUT-DATATYPE` `CQ: the record layout RL_CQ gives NO_AXIS_PTS_X the datatype FLOAT16_IEEE, which the system cannot read`; with `FLOAT32_IEEE` → `… the datatype FLOAT32_IEEE …`; 0 exceptions at describe and decode
examples: (R-A2L-DEF.86/3 neg) mutant: a float count datatype admitted → the decode compares `None` (FLOAT16) or takes `range(nan)` (FLOAT32) → `TypeError` (`../E3-security.md` [G1]) → RED
examples: (R-A2L-DEF.87/1, /2) INLINE3 `RL_Q` with two components at position `2` → `A2L-DEF-LAYOUT-POSITION` `<name>: the positions of the record layout RL_Q do not give one order`; a position word `x` → the same message
examples: (R-A2L-DEF.90/1) SOFTA `Hldoj[5].hg16.uc16.MXW3.QMGZFJ_TGXVUC` (`AXIS_PTS_X 1 SWORD …`, `FNC_VALUES 2 SWORD …`, `FIX_NO_AXIS_PTS_X 5`) → fixed `X` `5` (B3 P6)
examples: (R-A2L-DEF.90/2) UPD1 `Map_InternalAxis_RecordLayout` → fixed `X` `4`, `Y` `3` (B3 P6)
examples: (R-A2L-DEF.90/1 neg) mutant: FIX_NO_AXIS_PTS_X treated as a part (the base walk) → `A2L-DEF-LAYOUT-PART` → RED
examples: (R-A2L-DEF.58.2/arr-3) INLINE3 `RL_Q` with a 5,000-digit position word → `A2L-DEF-LAYOUT-POSITION` `<name>: the positions of the record layout RL_Q do not give one order`; no exception
examples: (R-A2L-DEF.58.2/arr-4, /arr-5) INLINE3 `RL_Z` with `FIX_NO_AXIS_PTS_X` and a 5,000-digit word → `A2L-DEF-LAYOUT-PART` `CZ: the record layout RL_Z holds FIX_NO_AXIS_PTS_X, which the system cannot read`; `RL_CA2` with `ALIGNMENT_WORD` and a 5,000-digit word → `CA2: the record layout RL_CA2 holds ALIGNMENT_WORD, which the system cannot read`; no exception

_place_components
req: R-A2L-DEF.75, R-A2L-DEF.77, R-A2L-DEF.88
in: dict layout; tuple[int, ...] counts
out: tuple[dict[str, int], int] | None placed
func: new (D-12 A). Calls the unchanged `_walk_record_layout_components({"lines": the layout's ALIGNMENT lines + its components in position order, each as text}, list(counts))` — `counts` is the shape: the walk sizes FNC_VALUES by their product and AXIS_PTS_X / AXIS_PTS_Y by the first / second (an array's layout holds no AXIS_PTS, E2-7). Gives (`{component: offset}`, the last component's end); `None` when the walk gives `None` (only past `MAX_A2L_DECODE_BYTES` once the layout is read by `_read_record_layout`, E2-7). (E1's slice had `dict | Refusal`; the end is the curve's byte length, E2-10.)
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.88/1) INLINE3 `CA2` (`NO_AXIS_PTS_X 1 UBYTE`, `AXIS_PTS_X 2 UBYTE …`, `ALIGNMENT_WORD 2`, `FNC_VALUES 3 UWORD …`), `(2,)` → NO_AXIS_PTS_X `0`, AXIS_PTS_X `1`, FNC_VALUES `4`; end `8` (B3b Q1)
examples: (R-A2L-DEF.88/1 neg) mutant: the alignment line dropped → FNC_VALUES `3` → RED
examples: (R-A2L-DEF.88/2) `CA2` without `ALIGNMENT_WORD 2` → `0`, `1`, `3`; end `7`
examples: (R-A2L-DEF.88/3) INLINE3 lines `FNC_VALUES 2 UWORD …` then `AXIS_PTS_X 1 UWORD …`, `(2,)` → AXIS_PTS_X `0`, FNC_VALUES `4`; end `8`
examples: (R-A2L-DEF.88/3 neg) mutant: the line order passed (the base walk's) → FNC_VALUES `0` → RED
examples: (R-A2L-DEF.75/1, /2) V171 `RL.FNC.SWORD.ROW_DIR`, `(8,)` → FNC_VALUES `0`, end `16`; `(8, 3)` → end `48` (B3 P3)
examples: (R-A2L-DEF.77/3) INLINE3 `RL_CS`, `(4,)` → FNC_VALUES `5`, end `13`; (R-A2L-DEF.115/2) `RL_MN`, `(3, 2)` → `0`, `1`, `2`, `5`, `7`, end `19` (B3b Q1)
examples: (holds on base) V171 `RL.CURVE.SWORD.SBYTE.DECR`, `(8,)` → `0`, `1`, `9`, end `25` (the tag table's length, B3 P3); DEFC `RL_DEF_MAP`, `(4, 3)` → AXIS_PTS_X `0`, FNC_VALUES `8`, end `32` (B3b Q6)

_check_module_alignment
req: R-A2L-DEF.89, R-A2L-DEF.144, R-A2L-DEF.58.2
in: dict layout; tuple[int, ...] counts; dict | None mod_common
out: tuple[str, int, int] | tuple[str, str] | None moved
func: new (D-7 C; rebased: it takes the MOD_COMMON that `_module_common` looked up, E3A-32). `mod_common`'s ALIGNMENT lines for the classes the layout declares none of and one of its components follows; a line of such a class whose number is not a CTX *whole number* of at least 1 (no `int()` on a word of more than 9 digits) → (`ALIGNMENT_<class>`, the word or `(none)`) — no longer left out (R-A2L-DEF.144, E3A-09; E2-7's choice); none → `None`. Else `_place_components` on the layout with those lines added; the first component in position order whose offset differs → (component, offset under the layout's lines, offset under MOD_COMMON's); none differs → `None`. `_describe_array` writes the message. (E1's slice had `Refusal | None`; the message needs the object's name, E2-10.)
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.89/1) V171 `RL.CURVE.SWORD.SBYTE.DECR`, `(8,)`, `ASAM.C.CURVE.STD_AXIS`'s MOD_COMMON → (`FNC_VALUES`, `9`, `10`) (B3 P3: end `25` vs `26`)
examples: (R-A2L-DEF.89/1 neg) mutant: the check left out → a definition with values at `9` → RED
examples: (R-A2L-DEF.89/2) V171 `RL.MAP.SWORD.SBYTE.SBYTE.INCR`, `(4, 5)` → (`FNC_VALUES`, `11`, `12`)
examples: (R-A2L-DEF.89/3) C08 `CURVE_0001` (`RL_U16`, `(32,)`, MOD_COMMON `ALIGNMENT_WORD 2`) → `None` (FNC_VALUES at `0` both ways)
examples: (R-A2L-DEF.58.2/arr-6, changed at E3) INLINE3 MOD_COMMON `ALIGNMENT_WORD` and a 5,000-digit word, `CA2` of R-A2L-DEF.88/2, `(2,)` → (`ALIGNMENT_WORD`, the word) → `A2L-DEF-ALIGNMENT` `CA2: the MOD_COMMON line ALIGNMENT_WORD <the word> cannot be read`; no exception
examples: (R-A2L-DEF.144/1 … /3) INLINE3 MOD_COMMON `ALIGNMENT_WORD x`, `CA2` of .88/2 → (`ALIGNMENT_WORD`, `x`); the same with `CA2` of .88/1 (its own `ALIGNMENT_WORD 2`) → `None`, offsets `0`, `1`, `4`; MOD_COMMON `ALIGNMENT_LONG x` (no LONG component) → `None`, offsets `0`, `1`, `3`
examples: (R-A2L-DEF.144/1 neg) mutant: the line left out (the round-1 graph) → `None`, values at `3` → RED
examples: (holds on base) V171 `RL.AXIS_PTS.SBYTE.DECR`, `(8,)` (UBYTE, SBYTE) → `None`; SOFTA (MOD_COMMON `ALIGNMENT_BYTE 1` only) → `None` for every layout; DEFC layouts → `None` (B3 P3, P6; B3b Q6)

_module_common
req: R-A2L-DEF.89, R-A2L-DEF.114
in: dict section; dict mod_common_of
out: dict | None mod_common
func: new (E2-3, E2-8; rebased, E3A-32). A lookup by identity, `mod_common_of[id(section)]`, in the map that `describe_definitions`'s one walk builds: the MOD_COMMON child of the MODULE in whose subtree `section` lies, carried down the pre-order walk from the MODULE's children (never by line numbers: V171's MODULE has no `end_line`, B3 P0; the E2 graph walked the tree per call, about 4 ms each on software_a, E3A-32); `None` when the section lies under no MODULE or the MODULE has no MOD_COMMON. Read by `_check_module_alignment` (its ALIGNMENT lines) and by `_read_axis` (the module byte order of an axis object, R-A2L-026).
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.89/1) V171, the section of `ASAM.C.CURVE.STD_AXIS` → the MOD_COMMON holding `BYTE_ORDER MSB_LAST`, `ALIGNMENT_BYTE 1`, `ALIGNMENT_WORD 2`, `ALIGNMENT_LONG 4`, `ALIGNMENT_FLOAT32_IEEE 4`, `ALIGNMENT_FLOAT64_IEEE 4` (B3 P2)
examples: (R-A2L-DEF.114/2) INLINE3, the section of `AXO` → the MOD_COMMON holding `BYTE_ORDER MSB_FIRST` and no ALIGNMENT line
examples: (holds on base) V171's 28 MEASUREMENT sections never closed (one-line `/begin IF_DATA … /end IF_DATA`, E2-8) nest later objects under them; the walk still finds the one MODULE above them (B3 P0)
examples: (rebased, cost) SOFTA: the one walk files `14,056` sections under their MOD_COMMON (`i3reb-cost-probe` Q2)

_read_axis
req: R-A2L-DEF.90, R-A2L-DEF.92, R-A2L-DEF.93, R-A2L-DEF.94, R-A2L-DEF.95, R-A2L-DEF.96, R-A2L-DEF.97, R-A2L-DEF.98, R-A2L-DEF.99, R-A2L-DEF.100, R-A2L-DEF.101, R-A2L-DEF.102, R-A2L-DEF.114, R-A2L-DEF.116.1, R-A2L-DEF.117.1, R-A2L-019, R-A2L-DEF.141, R-A2L-DEF.142, R-A2L-DEF.143, R-A2L-DEF.58.2, R-A2L-DEF.137
in: str name; str letter; dict axis_section; dict layout; dict a2l_data; dict maps
out: AxisDefinition | Refusal axis
func: new (D-4 A, D-8 A, D-9, D-10 A, D-11 A; rebased: lookups in `maps`, E3A-32). The axis header = `_flatten_body_tokens([meta] + axis lines)`: the words on its `/begin AXIS_DESCR` line first (CTX *axis header*, E3A-05, CG-4; the one-line AXIS_DESCR and I-11.1's `meta_line` key are Inc 11's); child sections are not in it; `<axis name>` = `<name>.<letter>`. In this order (E2-4): kind word not STD_AXIS, FIX_AXIS, COM_AXIS → `A2L-DEF-AXIS-KIND` `<axis name>: the system cannot read an axis of the kind <word>`. COM: no AXIS_PTS_REF, `_find_axis_object(ref, maps["axis_pts_by_name"])` `None`, or its address word not a number (CTX *address word*: an optional `-`, then `0x`/`0X` and 1 to 8 hex digits, or 1 to 10 ASCII digits, read only then — `0x81_0340`, `0o17`, `+0x10` are not numbers, E3A-14 — so no `int()` runs on a longer word, R-A2L-DEF.58.2) → `A2L-DEF-AXIS-REF` `<axis name>: the A2L declares no axis object <ref> with an address`; its layout (header word 5) through `_read_record_layout(…, name)`: `None` or no AXIS_PTS_X → `A2L-DEF-AXIS-LAYOUT` `<axis name>: the axis object <ref> has no record layout with AXIS_PTS_X` (its other refusals pass). The *max axis points* — the header's (STD, FIX) or the axis object's (COM, word 8) — not a whole number (CTX: 1 to 9 ASCII digits) of at least 1 → `A2L-DEF-AXIS-MAX` `<axis name>: the axis declares no point count the system can read`; above 1,048,576 → `A2L-DEF-AXIS-MAX` `<axis name>: the axis declares <n> points, more than 1048576` (R-A2L-DEF.142: a record of more points cannot fit the 1 MiB the system reads); else `point_count`. FIX — the parameters are read and checked here and no point is built (E3A-01 = E3S3-02; the round-1 `_fixed_points` built them at describe): the first of `FIX_AXIS_PAR o s n`, `FIX_AXIS_PAR_DIST o d n` (header words) and the numbers of the FIX_AXIS_PAR_LIST child in file order; none → `A2L-DEF-AXIS-FIX` `<axis name>: the fixed axis gives no points` (R-A2L-DEF.98); o, s, d or a list number not a finite number (Inc 2a's `_finite_number`: `1e400`, `inf`, `nan` are not), `n` not a CTX *whole number*, or the first or the last point not finite — the last alone, `o + (n − 1)·2^s` or `o + (n − 1)·d`, `2^s` in IEEE double only for `s` < 1024 (for `s` ≥ 1024 and `n` ≥ 2 point 1 lies above the largest double; no integer power is computed) → `A2L-DEF-AXIS-FIX` `<axis name>: the fixed axis gives a point the system cannot read` (R-A2L-DEF.141); `n` (or the list's length) not `point_count` → `A2L-DEF-AXIS-FIX-COUNT` `<axis name>: the fixed axis gives <k> points and declares <n>` (R-A2L-DEF.99); else `fixed_rule` = (`"PAR"`, (o, s, n)), (`"PAR_DIST"`, (o, d, n)) or (`"PAR_LIST"`, the numbers), each an `int` where integral. The work is O(1) for PAR and PAR_DIST and O(list length) for a list, whose numbers grow with the file text; `_fixed_points` builds the points at decode. The object's layout holds `AXIS_PTS_<letter>` and the kind is not STD → `A2L-DEF-LAYOUT-AXIS` `<name>: the record layout <layout> holds AXIS_PTS_<letter> for an axis of the kind <word>`; STD without it → `has_points` `False`. The fixed count (the object's layout; the axis object's for COM) 0 or above `point_count` → `A2L-DEF-AXIS-CURRENT` `<axis name>: the record holds <c> points, outside 1 to <n>`; below → `A2L-DEF-AXIS-PARTIAL` `<axis name>: the record holds <c> of its <n> points — a record with fewer points than its maximum is not supported` (R-A2L-DEF.116.1, .117.1: the definition's refusals, E3A-07). Then `points` (the pinned element Definition) with `_conversion_fields(<axis name>, the header's method word, maps["compu_methods_by_name"], maps["compu_tables_by_name"])` (its `coeffs_linear`, `coeffs`, `compu_tab_ref` included; every field stated, E3A-22), the header's limits and FORMAT, the component's datatype; the MONOTONY word; COM: the axis object's address, its record placed by `_place_components(its layout, (point_count,))` (the placement `None` — past `MAX_A2L_DECODE_BYTES` —, a negative address, or a last byte, address + end − 1, above 0xFFFFFFFF → `A2L-DEF-AXIS-REF` `<axis name>: the record of the axis object <ref> at <address> cannot be read`, R-A2L-DEF.143) → `offset`, `count_offset`, `count_datatype` in that record, `axis_object_record` with its byte order (its BYTE_ORDER line, else its layout's, else that of `_module_common(its section, maps["mod_common_of"])`, else `little`).
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.92/1, /2) V171 `ASAM.C.CURVE.CURVE_AXIS` → `A2L-DEF-AXIS-KIND` `ASAM.C.CURVE.CURVE_AXIS.X: the system cannot read an axis of the kind CURVE_AXIS`; `ASAM.C.CURVE.RES_AXIS` → `ASAM.C.CURVE.RES_AXIS.X: the system cannot read an axis of the kind RES_AXIS` (B3 P5)
examples: (R-A2L-DEF.92/2 neg) mutant: RES_AXIS read as COM_AXIS through its AXIS_PTS_REF → an axis object `ASAM.C.AXIS_PTS.RESCALE` → RED
examples: (R-A2L-DEF.92/3) INLINE3 `CK` (`FOO_AXIS NO_INPUT CM_IDENT 2 0 255`) → `CK.X: the system cannot read an axis of the kind FOO_AXIS`
examples: (R-A2L-DEF.92/4, E3A-05) INLINE3 `CB1` whose `STD_AXIS NO_INPUT CM_IDENT 4 0 255` stands on its `/begin AXIS_DESCR` line (`meta`) → axis kind `STD_AXIS`, point count `4`, offset `0`, refusal `None` — the AxisDefinition of the multi-line form
examples: (R-A2L-DEF.92/4 neg) mutant: the header read from the section's lines only → no kind word (the section's lines hold none) → `A2L-DEF-AXIS-KIND` → RED (public corpus: 71 multi-line AXIS_DESCRs in 14 files have their header there; V171 and SOFTA 0 of 231, Q6)
examples: (R-A2L-DEF.93/1 … /3) V171 `ASAM.C.CURVE.FIX_AXIS.PAR_DIST` → point count `6`; C08 `CURVE_0001` → `32`; DEFC `MAP_DEF_0001` X → `4`
examples: (R-A2L-DEF.94/1, R-A2L-019/arr-1) V171 `ASAM.C.CURVE.COM_AXIS` → axis kind `COM_AXIS`, point count `8` from `ASAM.C.AXIS_PTS.UBYTE_8`, axis object address `0x810340`, offset `1`, count offset `0`, count datatype `UBYTE`, point order `INDEX_DECR`, axis object record byte length `9`, byte order `little` (B3 P3)
examples: (R-A2L-DEF.94/2) INLINE3 COM_AXIS saying `8`, axis object `AXO` saying `5` → point count `5` (element count `5`)
examples: (R-A2L-DEF.94/2 neg) mutant: the AXIS_DESCR's count → `8` → RED
examples: (R-A2L-DEF.94/3) SOFTA `AltuzMlp_fmqszLuM_wc2H_qCs_ydlb` (`AXIS_PTS_REF RdqcrLhy_lzkkrZkA_ik2E_yOc_unub`) → point count `8` (its axis object's max) (B3 P6)
examples: (R-A2L-DEF.95/1 … /3) INLINE3 `CX` (STD max `x`) → `A2L-DEF-AXIS-MAX` `CX.X: the axis declares no point count the system can read`; FIX max `0` with `FIX_AXIS_PAR_DIST 0 1 0` → the same message; `AXO` max `-3` → the same message
examples: (R-A2L-DEF.95/2 neg) mutant: `0` accepted → element count `0` → RED
examples: (R-A2L-DEF.96/1 … /3) INLINE3 `CR`: no AXIS_PTS_REF → `A2L-DEF-AXIS-REF` `CR.X: the A2L declares no axis object (none) with an address`; `AXIS_PTS_REF AX_GONE` → `CR.X: the A2L declares no axis object AX_GONE with an address`; `AXO` address `0xZZ` → `CR.X: the A2L declares no axis object AXO with an address`
examples: (R-A2L-DEF.96/4, E3A-14) INLINE3 `AXO` with address word `0x81_0340` → `CR.X: the A2L declares no axis object AXO with an address`; mutant: `int(word, 0)` → address `0x810340` → RED
examples: (R-A2L-DEF.97/1, /2) INLINE3 `AXO` naming `RL_GONE` → `A2L-DEF-AXIS-LAYOUT` `CR.X: the axis object AXO has no record layout with AXIS_PTS_X`; `AXO`'s layout `FNC_VALUES 1 UWORD ROW_DIR DIRECT` → the same message
examples: (R-A2L-DEF.97/2 neg) mutant: the axis object's FNC_VALUES read as its points (`a2l.py:3280-3283`) → points → RED
examples: (R-A2L-DEF.98/1) INLINE3 `FN` (FIX_AXIS max 4, no parameters) → `A2L-DEF-AXIS-FIX` `FN.X: the fixed axis gives no points`
examples: (R-A2L-DEF.99/1, /2) INLINE3 `FC` max 6, `FIX_AXIS_PAR_DIST 0 1 4` → `A2L-DEF-AXIS-FIX-COUNT` `FC.X: the fixed axis gives 4 points and declares 6`; a FIX_AXIS_PAR_LIST `1 2 3 4 5` → `FC.X: the fixed axis gives 5 points and declares 6` (B3b Q2: the list is a child section)
examples: (R-A2L-DEF.99/2 neg) mutant: the list padded to 6 → no refusal → RED
examples: (R-A2L-DEF.100/1 … /3) C08 `CURVE_0001` X, `MAP_0001` X and Y (layout `RL_U16` = FNC_VALUES only) → `has_points` `False`, no refusal (B3 P7)
examples: (R-A2L-DEF.100/1 neg) mutant: `A2L-DEF-LAYOUT-AXIS` given → RED
examples: (R-A2L-DEF.101/1, /2) INLINE3 `RL_FX` holding `AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT` for a FIX_AXIS → `A2L-DEF-LAYOUT-AXIS` `<name>: the record layout RL_FX holds AXIS_PTS_X for an axis of the kind FIX_AXIS`; for the COM_AXIS of R-A2L-DEF.94/2 → `… for an axis of the kind COM_AXIS`
examples: (R-A2L-DEF.102/1) V171 `ASAM.C.MAP.STD_AXIS.STD_AXIS` Y (on the refused definition) → points kind `enum`, enum table `CM.TAB_VERB.NO_DEFAULT_VALUE.REF`, datatype `SBYTE`, limits `-128`..`127` (B3 P2)
examples: (R-A2L-DEF.102/2) V171 `ASAM.C.CURVE.COM_AXIS` X → points kind `number`, method `CM.IDENTICAL`, limits `0`..`255`, datatype `SBYTE` (the axis object's AXIS_PTS_X)
examples: (R-A2L-DEF.102/3) INLINE3 `CL` (`STD_AXIS NO_INPUT CM_HALF 4 0 100` + `FORMAT "%.1"`, `CM_HALF` = `CM(LINEAR 0.5 0)`) → kind `number`, method `CM_HALF`, display format `%.1`, datatype `UWORD`
examples: (R-A2L-DEF.102/4) INLINE3 COM_AXIS naming `CM_A`, its axis object `CM_B` → method `CM_A`
examples: (R-A2L-DEF.102/3 neg) mutant: the object's conversion used for its axis → method `CM_IDENT` → RED
examples: (R-A2L-DEF.114/1, /2) INLINE3 `AXO` with `BYTE_ORDER MSB_LAST` (module `MSB_FIRST`) → axis object byte order `little`; with none → `big` (B3b Q2)
examples: (R-A2L-DEF.116.1/3) INLINE3 `CZ` (`FIX_NO_AXIS_PTS_X 0`, STD(4)) → `A2L-DEF-AXIS-CURRENT` `CZ.X: the record holds 0 points, outside 1 to 4`
examples: (R-A2L-DEF.117.1/2) UPD2 `Curve_InternalAxis_bad_axis_size` (`FIX_NO_AXIS_PTS_X 4`, max 8) → `A2L-DEF-AXIS-PARTIAL` `Curve_InternalAxis_bad_axis_size.X: the record holds 4 of its 8 points — a record with fewer points than its maximum is not supported` (B3 P6)
examples: (R-A2L-DEF.90/1) SOFTA `NetuuiuqMjuxzsputa.QMZ_TCF_XzxkyMorlrc_Qf32` (layout `Hldoj[5]…`) → fixed count `5` = point count `5`, element count `5`, byte length `20` (B3 P6)
examples: (R-A2L-DEF.90/2) UPD1 `Map_InternalAxis` → Y fixed count `3`, shape `(4, 3)`, byte length `62` (B3 P6)
examples: (R-A2L-DEF.141/1 … /6) INLINE3 `FS` (point count 4): `FIX_AXIS_PAR 0 1024 4` (point 1 = 2^1024; `2.0**1024` raises `OverflowError`, so it is not computed); `FIX_AXIS_PAR 0 1000000000 4`, within 1.0 s; `FIX_AXIS_PAR_DIST 1e400 1 4`; `FIX_AXIS_PAR_DIST nan 1 4`; the list `1 nan 3 4`; `FIX_AXIS_PAR_DIST 0 1` and a 5,000-digit count → `A2L-DEF-AXIS-FIX` `FS.X: the fixed axis gives a point the system cannot read`
examples: (R-A2L-DEF.141/3 neg) mutant: the points computed unchecked → (`inf`, `inf`, `inf`, `inf`), a definition → RED; (/2 neg) `2**s` as an integer → seconds and about 125 MB → RED
examples: (R-A2L-DEF.141/7) `FS` max `2`, `FIX_AXIS_PAR 0 1023 2` → `fixed_rule` (`"PAR"`, (`0`, `1023`, `2`)), refusal `None` (its points at decode: `_fixed_points`)
examples: (R-A2L-DEF.110/1, .111/1, .112/1, E3A-01) `FIX_AXIS_PAR 0 2 4` → `fixed_rule` (`"PAR"`, (`0`, `2`, `4`)); V171 `…FIX_AXIS.PAR_DIST` → (`"PAR_DIST"`, (`1`, `1`, `6`)); `…FIX_AXIS.PAR_LIST` → (`"PAR_LIST"`, (`-1`, `4`, `6`, `8`, `9`, `10`)); no point built
examples: (R-A2L-DEF.99/1, with R-A2L-DEF.142) point count 4, `FIX_AXIS_PAR_DIST 0 1 999999999` → `A2L-DEF-AXIS-FIX-COUNT` `….X: the fixed axis gives 999999999 points and declares 4`, no point built
examples: (R-A2L-DEF.142/1 … /3) INLINE3 `FB` (FIX max `1048577`) → `A2L-DEF-AXIS-MAX` `FB.X: the axis declares 1048577 points, more than 1048576` (no FIX parameter checked, no point built); `CW` (STD max `999999999`) → `CW.X: the axis declares 999999999 points, more than 1048576`; `CR` with `AXO` max `1048577` → `CR.X: the axis declares 1048577 points, more than 1048576`
examples: (R-A2L-DEF.142/4) INLINE3 `CU` (STD max `1048576`, layout FNC_VALUES UBYTE only) → point count `1048576`, `has_points` `False`, no refusal (element count and byte length `1048576`)
examples: (R-A2L-DEF.142/1 neg) mutant: no upper bound → the record passes 1 MiB → `A2L-DEF-ADDRESS` → RED
examples: (R-A2L-DEF.142/5, E3A-01 = E3S3-02) one INLINE3 file of 50 FIX curves at max `1048576` (UBYTE values) and 50 FIX maps of two such axes → every axis a `fixed_rule` and no point; describing every name: model 0.031 s, peak 0.14 MiB (`i3e3c-fix-probe` F1) against 1.0 s and 50 MiB; curves refusal `None`, maps `A2L-DEF-ADDRESS` (.7.1)
examples: (R-A2L-DEF.142/5 neg) mutant: the points built at describe (the round-1 graph) → 214 s, 6,007 MiB → RED
examples: (R-A2L-DEF.143/1 … /3) INLINE3 `CR`, `AXO` (max 5, `AXIS_PTS_X 1 UWORD …`, 10 bytes) at `-0x10` → `A2L-DEF-AXIS-REF` `CR.X: the record of the axis object AXO at -0x10 cannot be read`; at 0xFFFFFFF7 → `CR.X: the record of the axis object AXO at 0xFFFFFFF7 cannot be read`; at 0x40 with max `600000` → placement `None` → `CR.X: the record of the axis object AXO at 0x40 cannot be read`
examples: (R-A2L-DEF.143/4) `AXO` at 0xFFFFFFF6 → axis object address `0xFFFFFFF6`, record byte length `10`, no refusal
examples: (R-A2L-DEF.143/2 neg) mutant: the bounds left out → an axis object record ending at `0x100000000` → RED
examples: (R-A2L-DEF.137/arr-2) INLINE3 `CR` with `AXIS_PTS_REF AX\x1bGONE` → `A2L-DEF-AXIS-REF` `CR.X: the A2L declares no axis object AX�GONE with an address`
examples: (R-A2L-DEF.58.2/arr-7, /arr-8) INLINE3 `CX` with a 5,000-digit max → `A2L-DEF-AXIS-MAX` `CX.X: the axis declares no point count the system can read`; `CR` with a 5,000-digit decimal address word for `AXO` → `A2L-DEF-AXIS-REF` `CR.X: the A2L declares no axis object AXO with an address`; no exception

_find_axis_object
req: R-A2L-DEF.94, R-A2L-DEF.96, R-A2L-DEF.97, R-A2L-DEF.113
in: str ref; dict axis_pts_by_name
out: tuple[dict, list[str]] | None found
func: new (BL-I3-1 wrapped; rebased, E3A-32). A lookup in the `axis_pts_by_name` map that `describe_definitions`'s one walk builds (each AXIS_PTS section in file order, filed under the first word of its *AXIS_PTS header*, `_flatten_body_tokens([meta] + lines)`): the first section of `ref` and that header; `None` when the map has no `ref`. (The E2 graph walked `_collect_sections_by_name(sections, "AXIS_PTS")` per call: 3.96 ms each on software_a, E3A-32.) The tags are not searched (an AXIS_PTS section is not a tag).
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.113/1) V171 `ASAM.C.AXIS_PTS.UBYTE_8` → header `ASAM.C.AXIS_PTS.UBYTE_8`, `Common axis for `, `0x810340`, `ASAM.M.SCALAR.UBYTE.IDENTICAL`, `RL.AXIS_PTS.SBYTE.DECR`, `0`, `CM.IDENTICAL`, `8`, `0`, `255`, … (B3 P3)
examples: (R-A2L-DEF.113/1, holds on base) the same name among the tags → `False` (B3 P3; why `a2l.py` never resolves it, BL-I3-1)
examples: (R-A2L-DEF.96/2) INLINE3 `AX_GONE` → `None`
examples: (R-A2L-DEF.113/2) DEFC `AXIS_DEF_0001` → `0x00800040`, `RL_DEF_AXIS`, max `5` (B3b Q6)

_fixed_points
req: R-A2L-DEF.110, R-A2L-DEF.111, R-A2L-DEF.112, R-A2L-DEF.141
in: tuple[str, tuple[int | float, ...]] fixed_rule
out: tuple[int | float, ...] points
func: new (D-10 A; changed at the E3 correction, E3A-01 = E3S3-02 — the round-1 node took the axis words, built the points at describe and gave `None`, `"unreadable"` or a count: those checks are `_read_axis`'s now, and the signature loses `axis_words`, `axis_section`, `point_count`). The stored points of a FIX_AXIS from its `fixed_rule`, which `_read_axis` has checked: `"PAR"` (o, s, n) → `o + k·2^s` (`2^s` in IEEE double: `_read_axis` admitted only `s` < 1024, or `n` = 1); `"PAR_DIST"` (o, d, n) → `o + k·d`, k = 0 … n − 1; `"PAR_LIST"` → its numbers in file order; each an `int` where integral, else a `float`. Called only by `_decode_axis`, at decode, after `decode_values` has found the record's bytes in the image, so it builds at most as many points as the record has bytes (≤ 1,048,576, R-A2L-DEF.7.2); never at describe. Measured: 1,048,576 points in 0.965 s and 48 MiB (`i3e3c-fix-probe` F2, cachyos-rtx).
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.110/1) (`"PAR"`, (`0`, `2`, `4`)) → (`0`, `4`, `8`, `12`) (B3b Q4)
examples: (R-A2L-DEF.110/1 neg) mutant: `o + k·s` → (`0`, `2`, `4`, `6`) → RED
examples: (R-A2L-DEF.110/2, E3A-17) (`"PAR"`, (`0`, `0`, `4`)) → (`0`, `1`, `2`, `3`); the `o + k·s` mutant → (`0`, `0`, `0`, `0`) → RED
examples: (R-A2L-DEF.111/1 … /3) V171 (`"PAR_DIST"`, (`1`, `1`, `6`)) → (`1` … `6`); (`0`, `4`, `6`) → (`0`, `4`, `8`, `12`, `16`, `20`); (`1`, `1`, `3`) → (`1`, `2`, `3`) (B3 P2)
examples: (R-A2L-DEF.112/1) V171 `ASAM.C.CURVE.FIX_AXIS.PAR_LIST`'s (`"PAR_LIST"`, (`-1`, `4`, `6`, `8`, `9`, `10`)) → (`-1`, `4`, `6`, `8`, `9`, `10`) (B3 P2)
examples: (R-A2L-DEF.112/1 neg) mutant: the list sorted → RED (it is already sorted; /1 is `partial` for this mutant, E2-13); the point index → (`0` … `5`) → RED
examples: (R-A2L-DEF.141/7) (`"PAR"`, (`0`, `1023`, `2`)) → (`0`, 2^1023 as an `int`)
examples: (R-A2L-DEF.142/5 neg) mutant: called at describe for every FIX axis (the round-1 graph) → the 100 objects of /5 in 214 s and 6,007 MiB → RED

_element_definition
req: R-A2L-DEF.105, R-A2L-DEF.121, R-A2L-DEF.122
in: Definition definition; tuple[int, ...] | tuple[str, int] position
out: Definition element
func: new (rebased: a `dataclasses.replace`, so every other field — the method fields `coeffs_linear`, `coeffs`, `compu_tab_ref` and 2b's `shared_with` included — is the object's, E3A-03, E3A-22). An element index → `definition` with `name` = `element_name(definition, index)`, `kind` `enum` for a TAB_VERB conversion else `number`, `address` = `definition.address + _element_offset(definition, index)`, `byte_length` = the datatype's size, the array fields at their defaults, `refusal` `None`. An axis point `(letter, k)` → that axis's `points` (a `replace` likewise) with `name` = `element_name(…)` and `address` = the object's address (STD) or the axis object's (COM) + `_point_offset(axis, k)`; `None` for FIX.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.105/1) V171 `…MATRIX_DIM_3_4.ROW_DIR`, `(1, 0)` → name `ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR[1,0]`, kind `number`, address `0x810102`, byte length `2`, datatype `SWORD`, limits `-400`..`400`, extended `-1000`..`1000`, display format `%8.4`
examples: (R-A2L-DEF.107/1) `…COLUMN_DIR`, `(1, 0)` → address `0x810128`
examples: (R-A2L-DEF.127/1 input) V171 `ASAM.C.CURVE.COM_AXIS`, (`X`, `3`) → name `ASAM.C.CURVE.COM_AXIS.X[3]`, address `0x810345` (`0x810340` + 1 + (8 − 1 − 3)), datatype `SBYTE`, limits `0`..`255`, byte order `little`
examples: (R-A2L-DEF.126/1 input) V171 `ASAM.C.CURVE.FIX_AXIS.PAR_DIST`, (`X`, `0`) → address `None`
examples: (R-A2L-DEF.105/2) INLINE3 `VE` (TAB_VERB `CM_E`), `(1,)` → kind `enum`, address `0x11`

element_name
req: R-A2L-DEF.121, R-A2L-DEF.125
in: Definition definition; tuple[int, ...] | tuple[str, int] position
out: str name
func: new (I-2). An element index → `<name>[<i>]`, `<name>[<i>,<j>]` or `<name>[<i>,<j>,<k>]`; an axis point → `<name>.<letter>[<k>]`; zero-based; any position, also one that is not of the object (R-A2L-DEF.125's `<position>`).
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.121/1) `V`, `(1, 2)` → `V[1,2]`; (R-A2L-DEF.121/2) `C`, (`X`, `1`) → `C.X[1]`; (R-A2L-DEF.119/1) `VR`, `(1,)` → `VR[1]`
examples: (R-A2L-DEF.125/1 … /3) `ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR`, `(3, 0)` → `ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR[3,0]`; `(0, 0, 0)` → `…ROW_DIR[0,0,0]`; (`X`, `0`) → `…ROW_DIR.X[0]`
examples: (R-A2L-DEF.121/1 neg) mutant: the object's name used → `V: 'abc' is not a number` → RED

### New nodes: decoding

decode_values
req: R-A2L-DEF.105, R-A2L-DEF.106, R-A2L-DEF.107, R-A2L-DEF.119, R-A2L-DEF.121, R-A2L-DEF.146, R-A2L-DEF.26, R-A2L-DEF.58.1, R-A2L-DEF.131, R-A2L-DEF.132, R-A2L-DEF.137
in: Definition definition; dict a2l_data; Mapping[int, int] image
out: DecodedValues | Refusal result
func: new (I-2). The definition's refusal; a scalar kind → `DecodedValues((decode_definition(…),), ())` (R-A2L-DEF.146, E2-5). The record `address … address + byte_length − 1`: `n` addresses not in the image → `A2L-DEF-BYTES` `<name>: <n> of its <length> bytes are not in the image` (Inc 2's message). Each axis, X then Y: `_decode_axis` (a refusal is the result; a FIX axis's points are computed there, after the record check above, E3A-01). Then each element in element order: `_element_definition`, `_read_stored_value`, `_decode_stored` — a refusal in that element's place (R-A2L-DEF.119). `DecodedValues(values, axes)`. Reads `image` and `a2l_data` only. One result can hold 1,048,576 elements and as many points per axis: Interfaces, *Consumer obligations* (E3S3-03).
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.105/1) V171 `…MATRIX_DIM_3_4.ROW_DIR`, image SWORD 1 … 12 (little) at 0x810100 → `12` values, texts `1` … `12` in address order (base: raw `1` only, B1 line 12)
examples: (R-A2L-DEF.105/2) INLINE3 `VE`, image 01 00 at 0x10 → `VE[0]` text `ON`, `VE[1]` text `OFF`
examples: (R-A2L-DEF.105/3) INLINE3 `VN` (`CM(LINEAR 0.5 0)`, `FORMAT "%.1"`), image 00 03 00 04 → texts `1.5`, `2.0`
examples: (R-A2L-DEF.105/3 neg) mutant: IDENTICAL whatever the method → `3`, `4` → RED
examples: (R-A2L-DEF.105/4) INLINE3 `VM` (`BIT_MASK 0x0F00`), image 12 34 0A 00 → stored `2`, `10`
examples: (R-A2L-DEF.106/1) the image of /105/1 → (1,0) `2`, (0,1) `4`, (2,3) `12` (B3 P4)
examples: (R-A2L-DEF.106/1 neg) mutant: the COLUMN_DIR rule → (1,0) `5` → RED
examples: (R-A2L-DEF.106/2) V171 `ASAM.M.MATRIX_DIM_8_4_2.UBYTE.IDENTICAL`, bytes 0 … 63 at 0x13A30 → (1,1,1) `41`, (7,3,1) `63`
examples: (R-A2L-DEF.106/3) V171 `ASAM.C.MAP.COM_AXIS.FIX_AXIS`, SWORD 0 … 23 at 0x810440 and AX8(8, 46 3C 32 28 1E 14 0A 00) → (1,2) `17`, (7,0) `7`, (0,1) `8`; axis X `0` … `70`; axis Y `1`, `2`, `3`
examples: (R-A2L-DEF.107/1) V171 `…COLUMN_DIR`, SWORD 1 … 12 at 0x810120 → (1,0) `5`, (0,1) `2`, (2,3) `12`
examples: (R-A2L-DEF.107/2) C08 clean `MAP_0001` → (x,y) = the plan's value number 8·x + y: (0,0) `15412`, (0,1) `15423`, (1,2) `15522` (big-endian, B3 P7)
examples: (R-A2L-DEF.107/3) C08 `CURVE_0001` → (x) = value number x: (0) `57199`, (1) `57206`, (2) `57213`
examples: (R-A2L-DEF.119/1, .121/3) INLINE3 `VR` (`CM(RAT_FUNC 1 0 1 0 0 1)`, limits 0..10, `MATRIX_DIM 3`), image 00 05 00 00 00 0A → `VR[0]` value `2.0` text `2.000`; `VR[1]` refusal `A2L-DEF-DECODE` `VR[1]: RAT_FUNC has no real root for this value`; `VR[2]` value `3.0` (B3b Q5)
examples: (R-A2L-DEF.119/1 neg) mutant: the whole decode refused at the first failing element → RED
examples: (R-A2L-DEF.137/arr-3) INLINE3 the `VR` of R-A2L-DEF.119/1 named `V\x1bR` → element 1's refusal `A2L-DEF-DECODE` `V�R[1]: RAT_FUNC has no real root for this value` (the element name built from the name, U+FFFD in the message)
examples: (R-A2L-DEF.26/arr-1) V171 `…3_4.ROW_DIR`, 23 of the 24 bytes → `A2L-DEF-BYTES` `ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR: 1 of its 24 bytes are not in the image`
examples: (R-A2L-DEF.134/1, .108/2) DEFC `MAP_DEF_0001` → axis X `224`, `577`, `648`, `909`; Y `10`, `15`, `20`; (0,0) `472`, (1,0) `132`, (3,0) `330`, (0,1) `709`, (1,2) `-485`, (3,2) `-556` (B3b Q6)
examples: (R-A2L-DEF.135/1) DEFC `VAL_BLK_DEF_0001` → (0,0) `36.9`, (1,0) `11.0`, (2,0) `31.8`, (0,1) `-20.7`, (1,1) `-19.8`, (2,1) `-10.7` (B3c R3)
examples: (R-A2L-DEF.135/1 neg) mutant: read as COLUMN_DIR → `4` of `6` cells differ from the plan → RED (B3b Q6)
examples: (AT-B103-I3-1, decode) V171 with the AT's image → the 20 objects with no refusal decode; the 3×4 twins read the same bytes in the two orders; `ASAM.C.CURVE.COM_AXIS`, `_2` and the COM/FIX maps read one axis `0` … `70`; the FIX curves `1` … `6`, `0` … `20`, `-1` … `10`
examples: (R-A2L-DEF.58.1/arr-1) V171 with every record and both axis objects in the image: a deep copy of `a2l_data` and of the image before decoding every array, curve and map equals both after → `True`
examples: (R-A2L-DEF.146/1, E3A-18) V171 `ASAM.C.SCALAR.SWORD.IDENTICAL`, image 34 12 at 0x810004 → `DecodedValues((Decoded(4660, 4660, "4660"),), ())`
examples: (R-A2L-DEF.146/1 neg) mutant: `A2L-DEF-ELEMENTS` or `DecodedValues((), ())` for a scalar kind → RED

_element_offset
req: R-A2L-DEF.106, R-A2L-DEF.107
in: Definition definition; tuple[int, ...] index
out: int offset
func: new (D-2 A). The byte offset in the record: `values_offset` + size × (ROW_DIR: `i + n1·j + n1·n2·k`; COLUMN_DIR: `j + n2·i` for two indexes, `i` for one), `n1`, `n2` the shape's numbers.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.106/1) V171 3×4 ROW_DIR SWORD: (1,0) → `2`; (0,1) → `6`; (2,3) → `22`
examples: (R-A2L-DEF.107/1) 3×4 COLUMN_DIR: (1,0) → `8`; (0,1) → `2`; (2,3) → `22` (B3 P4)
examples: (R-A2L-DEF.106/2) 8×4×2 UBYTE ROW_DIR: (1,1,1) → `41`
examples: (R-A2L-DEF.107/2) C08 `MAP_0001` 8×8 UWORD COLUMN_DIR: (1,2) → `20` (value number `10`)
examples: (R-A2L-DEF.134/1) DEFC `MAP_DEF_0001` (values offset 8, 4×3 SWORD COLUMN_DIR): (1,0) → `14` (B3b Q6)

_point_offset
req: R-A2L-DEF.108, R-A2L-DEF.109
in: AxisDefinition axis; int k
out: int offset
func: new. The byte offset of point k in its record (the object's for STD, the axis object's for COM): `offset` + size × k for INDEX_INCR, `offset` + size × (n − 1 − k) for INDEX_DECR, n = `point_count`, size of `points.datatype`.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.108/1) INLINE3 `CI` (offset 1, UBYTE, INDEX_INCR, 4 points): k = 0 → `1`, k = 3 → `4`
examples: (R-A2L-DEF.109/1) V171 axis object (offset 1, SBYTE, INDEX_DECR, 8 points): k = 0 → `8`, k = 7 → `1`
examples: (R-A2L-DEF.109/1 neg) mutant: INDEX_INCR read (base) → points `70`, `60`, … `0` → RED
examples: (R-A2L-DEF.109/2) INLINE3 `CD` (INDEX_DECR, 4 points): k = 0 → `4`

_current_count
req: R-A2L-DEF.115, R-A2L-DEF.116.2, R-A2L-DEF.117.2, R-A2L-DEF.86, R-A2L-DEF.58.2
in: AxisDefinition axis; bytes record
out: int | Refusal count
func: new (D-3 A; changed at the E3 correction: E3A-13, E3A-22, E3S3-01, E3S3-05). `count_offset` `None` (no NO_AXIS_PTS component for the axis: a FIX_NO_AXIS_PTS count was checked at describe, R-A2L-DEF.116.1, .117.1, so `fixed_count` is not read again, E3A-22) → `point_count`. Else c = `_decode_scalar(record[count_offset : count_offset + size], count_datatype, points.byte_order)` (P-2); `count_datatype` is a count datatype (R-A2L-DEF.86), so c is an `int`. Tested positively (E3A-13): c an `int` equal to `point_count` → the count; c an `int` from 1 to `point_count` − 1 → `A2L-DEF-AXIS-PARTIAL` `<axis name>: the record holds <c> of its <n> points — a record with fewer points than its maximum is not supported` (R-A2L-DEF.117.2); anything else — below 1, a negative count of a signed datatype included (E3S3-05), above `point_count`, or not an `int` (not reachable under .86; kept so that no comparison can raise, E3S3-01) → `A2L-DEF-AXIS-CURRENT` `<axis name>: the record holds <c> points, outside 1 to <n>` (R-A2L-DEF.116.2; `<c>` in decimal, `(none)` when there is none).
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.115/1) V171 `ASAM.C.CURVE.COM_AXIS` X, axis object record AX8(8, …) → `8`
examples: (R-A2L-DEF.115/2) INLINE3 `MN` (counts 3, 2), count bytes 03 02 → X `3`, Y `2`
examples: (R-A2L-DEF.115/1 neg) mutant: the count byte ignored (base) → AX8(5, …) gives 8 points → RED
examples: (R-A2L-DEF.116.2/1, /2) AX8(0, …) → `A2L-DEF-AXIS-CURRENT` `ASAM.C.CURVE.COM_AXIS.X: the record holds 0 points, outside 1 to 8`; AX8(9, …) → `ASAM.C.CURVE.COM_AXIS.X: the record holds 9 points, outside 1 to 8`
examples: (R-A2L-DEF.117.2/1) AX8(5, …) → `A2L-DEF-AXIS-PARTIAL` `ASAM.C.CURVE.COM_AXIS.X: the record holds 5 of its 8 points — a record with fewer points than its maximum is not supported`
examples: (R-A2L-DEF.117.2/1 neg) mutant: the first 5 points read at their static offsets → points → RED
examples: (R-A2L-DEF.117.2/3) INLINE3 `MN`, count bytes 02 02 → `MN.X: the record holds 2 of its 3 points — a record with fewer points than its maximum is not supported`
examples: (R-A2L-DEF.133/1) DEFC `AXIS_DEF_0001`, count word 00 05 (UWORD, big) → `5` (B3b Q6)
examples: (R-A2L-DEF.116.2/4, E3S3-05) INLINE3 `CN` (`NO_AXIS_PTS_X 1 SBYTE`, 4 points), count byte FF → `A2L-DEF-AXIS-CURRENT` `CN.X: the record holds -1 points, outside 1 to 4`
examples: (R-A2L-DEF.116.2/4 neg) mutant: the round-1 rule ("below → partial") → `A2L-DEF-AXIS-PARTIAL` `CN.X: the record holds -1 of its 4 points …` → RED

_decode_axis
req: R-A2L-DEF.100, R-A2L-DEF.108, R-A2L-DEF.109, R-A2L-DEF.110, R-A2L-DEF.111, R-A2L-DEF.112, R-A2L-DEF.113, R-A2L-DEF.114, R-A2L-DEF.118, R-A2L-DEF.105
in: Definition definition; AxisDefinition axis; dict a2l_data; Mapping[int, int] image; bytes record
out: DecodedAxis | Refusal decoded
func: new (D-4 A, D-8 A). FIX → `DecodedAxis(letter, tuple(_decode_stored(the point's element definition, a2l_data, p) for p in _fixed_points(axis.fixed_rule)))`: the points are computed here, at decode, once `decode_values` has found the record's bytes (E3A-01). No current count is read for a FIX axis: its count is the parameters', checked at describe. STD with `has_points` `False` → `DecodedAxis(letter, None)`. STD → `_current_count(axis, record)`, then each point k: `_read_stored_value` of its element definition, `_decode_stored`. COM → the axis object's record bytes: `k` of them not in the image → `A2L-DEF-AXIS-BYTES` `<axis name>: <k> of the <bytes> bytes of the axis object <ref> are not in the image`; then `_current_count` on that record and the points from it, in the axis object's byte order.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.108/1) INLINE3 `CI`, image 04, 0A 14 1E 28, 8 value bytes → X `10`, `20`, `30`, `40`
examples: (R-A2L-DEF.109/1, .113/1, .115/1) V171 `ASAM.C.CURVE.COM_AXIS` and `ASAM.C.CURVE.COM_AXIS_2`, AX8(8, 46 3C 32 28 1E 14 0A 00) at 0x810340 → both X `0`, `10`, `20`, `30`, `40`, `50`, `60`, `70` (base: `70` … `0` in memory order, B1 line 14; B3 P4)
examples: (R-A2L-DEF.113/1 neg) mutant: the points read from the curve's own record → RED
examples: (R-A2L-DEF.109/2) INLINE3 `CD`, point bytes 28 1E 14 0A → `10`, `20`, `30`, `40`
examples: (R-A2L-DEF.110/1, /2) INLINE3 `FIX_AXIS_PAR 0 2 4` → stored `0`, `4`, `8`, `12`; `FIX_AXIS_PAR 0 0 4` → `0`, `1`, `2`, `3`
examples: (R-A2L-DEF.111/1 … /3) V171 `…FIX_AXIS.PAR_DIST` → `1` … `6` (base: `0` … `5`, B1 line 19); `…FIX_AXIS.PAR` → `0`, `4`, … `20`; `ASAM.C.MAP.COM_AXIS.FIX_AXIS` Y → `1`, `2`, `3`
examples: (R-A2L-DEF.112/1) V171 `…FIX_AXIS.PAR_LIST` → `-1`, `4`, `6`, `8`, `9`, `10` (base: `0` … `5`, B1 line 20)
examples: (R-A2L-DEF.100/1) C08 `CURVE_0001` X → `DecodedAxis("X", None)`; the 32 values still decoded
examples: (R-A2L-DEF.113/2, .133/1) DEFC `CURVE_DEF_0001` and `CURVE_DEF_0002` → both X texts `242.500`, `317.500`, `348.000`, `414.000`, `450.500` (stored `485`, `635`, `696`, `828`, `901`) (B3b Q6)
examples: (R-A2L-DEF.114/1, /2) INLINE3 `AXO` `MSB_LAST`, point 0 bytes 02 01 → `258`; no BYTE_ORDER (module `MSB_FIRST`) → `513` (B3b Q2)
examples: (R-A2L-DEF.114/1 neg) mutant: the curve's byte order used → `513` → RED
examples: (R-A2L-DEF.118/1, /2) V171 `ASAM.C.CURVE.COM_AXIS`, the image holding its 16 bytes only → `A2L-DEF-AXIS-BYTES` `ASAM.C.CURVE.COM_AXIS.X: 9 of the 9 bytes of the axis object ASAM.C.AXIS_PTS.UBYTE_8 are not in the image`; plus 8 of the axis object's bytes → `ASAM.C.CURVE.COM_AXIS.X: 1 of the 9 bytes of the axis object ASAM.C.AXIS_PTS.UBYTE_8 are not in the image`
examples: (R-A2L-DEF.118/1 neg) mutant: missing points read as 0 (`_extract_raw_bytes`' placeholder) → points → RED
examples: (R-A2L-DEF.105/5, the round-1 .119/2, E3A-16) INLINE3 MAP with enum axis Y (`VT_E`), Y stored 1, 7 → Y[0] `ON`, Y[1] `7 (no text)`; every value decoded

_decode_stored
req: R-A2L-DEF.105, R-A2L-DEF.110, R-A2L-DEF.111, R-A2L-DEF.112, R-A2L-DEF.119, R-A2L-DEF.137
in: Definition definition; dict a2l_data; int | float | bytes stored
out: Decoded | Refusal result
func: new (slice #20: the second half of Inc 2's `decode_definition`, moved unchanged). Text → `Decoded(None, s, s)`, `s = _ascii_text(stored)`; enum → `Decoded(stored, the entry text or None, _enum_text(definition, stored))`; number → `value = stored` for `NO_COMPU_METHOD`, else `_apply_compu_method(stored, the method record built from the definition's fields — `conversion_type`, `coeffs_linear`, `coeffs`, `compu_tab_ref` (never `_read_method_record` or `sections`, E3A-03; an axis point's are its axis method's), a2l_data["compu_tabs_by_name"], (limits.lower, limits.upper))`; status `error` → `A2L-DEF-DECODE` `<name>: <conversion error>`; else `Decoded(stored, value, display_text(definition, value))`; `Decoded.text` with U+FFFD as R-A2L-DEF.137 (Inc 2's rule, moved with the code). The one place a FIX_AXIS point (a stored value with no bytes) becomes a `Decoded`.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.111/1) `ASAM.C.CURVE.FIX_AXIS.PAR_DIST.X[0]` (`CM.IDENTICAL`, no datatype), stored `1` → `Decoded(1, 1, "1")`
examples: (R-A2L-DEF.112/1) the PAR_LIST point `-1` → text `-1`
examples: (R-A2L-DEF.119/1) `VR[1]` (RAT_FUNC 1 0 1 0 0 1, limits 0..10), stored `0` → `A2L-DEF-DECODE` `VR[1]: RAT_FUNC has no real root for this value` (B3b Q5)
examples: (R-A2L-DEF.105/2) `VE[0]` (enum), stored `1` → `Decoded(1, "ON", "ON")`
examples: (holds from Inc 2, R-A2L-054/def-1) C08 `VALUE_0019`, stored `12830` → value `12930.0`, text `12930.0` (Inc 2's decode, now through this node)

### New nodes: encoding

encode_values
req: R-A2L-DEF.121, R-A2L-DEF.122, R-A2L-DEF.123, R-A2L-DEF.124, R-A2L-DEF.125, R-A2L-DEF.126, R-A2L-DEF.127, R-A2L-DEF.128, R-A2L-DEF.129, R-A2L-DEF.130, R-A2L-DEF.131, R-A2L-DEF.132, R-A2L-DEF.58.1
in: Definition definition; dict a2l_data; Mapping[tuple[int, ...] | tuple[str, int], str] edit; Mapping[int, int] image
out: Encoded | Refusal result
func: new (I-2; D-4 A, D-5 A). The *array encode order*: (1) `decode_values` — a refusal is the result (R-A2L-DEF.124); (2) positions in edit order: not an element index of `shape` nor a point index of one of its axes → `A2L-DEF-INDEX` `<name>: <position> is not a value or axis point of it` (`<position>` = `element_name`); (3) the record = its image bytes; each edit in edit order: a FIX point → `A2L-DEF-AXIS-FIXED` `<axis point name>: the points of a fixed axis are not stored in the image`; a COM point → `A2L-DEF-AXIS-SHARED` `<axis point name>: the points of the common axis <ref> are not edited through <name>`; a point of an axis with no points → `A2L-DEF-AXIS-NONE` `<axis point name>: the record layout <layout> holds no points for this axis`; else `encode_definition(_element_definition(definition, position), a2l_data, text, the image under the record so far)` — a refusal is the result; its bytes go to the element's offset; its notices kept; (4) for axis X, then Y, when the edit changes one of its points: the stored points of the new record in point index order → `_breaking_point` → k → `A2L-DEF-MONOTONY` `<axis point name>: <point text> breaks the <rule> order of the axis` (point k's name, its display text decoded from the new record); (5) `Encoded(address, the record, notices)`. Reads `image` and `a2l_data`; writes neither.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.122/1) INLINE3 `VN` (`CM(LINEAR 0.5 0)`), image 00 03 00 04, {(0,): `2.5`} → element 0 stored `5`; data `00 05 00 04` (the whole record)
examples: (R-A2L-DEF.122/1 neg) mutant: raw integers packed with no conversion → `2.5` refused or stored `2` → RED
examples: (R-A2L-DEF.122/2) INLINE3 `VE`, image 01 00, {(1,): `ON`} → data `01 01`
examples: (R-A2L-DEF.122/3) INLINE3 `VX` (limits 0..10), {(0,): `11`} → `A2L-DEF-LIMITS` `VX[0]: 11 is outside the limits 0..10`
examples: (R-A2L-DEF.122/4) INLINE3 STD(`CM_TWO` = `CM(LINEAR 2 0)`, 4 0 500), points stored 1 2 3 4, {(`X`, `3`): `10`} → point 3 stored `5` (bytes `00 05` at record offset 6)
examples: (R-A2L-DEF.122/5) INLINE3 FLOAT64_IEEE `VP` (`MATRIX_DIM 2`, `CM(LINEAR 1 1e10)`, `FORMAT "%"`), {(1,): `1.0000001`} → `A2L-DEF-PRECISION` `VP[1]: 1.0000001 cannot be stored at the display precision — the nearest stored value is 1` (each element through Inc 2's step 8: FLOAT64 never at 6 digits, E3S-07)
examples: (R-A2L-DEF.122/6) INLINE3 A_UINT64 `VU` (`CM(IDENTICAL)`), {(0,): `9007199254740993`} → `A2L-DEF-PRECISION` `VU[0]: 9007199254740993 cannot be stored at the display precision — the nearest stored value is 9007199254740992` (exact integers, E3S-09)
examples: (R-A2L-DEF.122/7) INLINE3 UWORD TAB_INTP `VL4` (`0 0.0`, `10 1.0`, `FORMAT "%.1"`, limits and extended limits `0`..`0.55`), image 00 00 00 00, {(1,): `0.55`} → `A2L-DEF-EXTENDED` `VL4[1]: 0.6 is outside the extended limits 0..0.55` (the written value, E3S-06)
examples: (R-A2L-DEF.122/7 neg) mutant: the element's limits checked on the typed value only → bytes for `0.6` → RED
examples: (R-A2L-DEF.121/1) INLINE3 `V` (`MATRIX_DIM 3 4`), {(1, 2): `abc`} → `A2L-DEF-NUMBER` `V[1,2]: 'abc' is not a number`
examples: (R-A2L-DEF.121/2) INLINE3 `C` (`STD_AXIS NO_INPUT CM_S8 4 -100 100`, SBYTE points 10 20 30 40), {(`X`, `1`): `120`} → `A2L-DEF-LIMITS` `C.X[1]: 120 is outside the limits -100..100`
examples: (R-A2L-DEF.123/1) V171 `…3_4.ROW_DIR`, image SWORD 1 … 12, {(1, 0): `-7`} → address `0x810100`, `24` bytes, bytes 2–3 `F9 FF`, every other byte as the image (B3 P4)
examples: (R-A2L-DEF.123/2) `…3_4.COLUMN_DIR` at 0x810120, the same edit → bytes 8–9 `F9 FF`
examples: (R-A2L-DEF.123/2 neg) mutant: COLUMN_DIR edited at the ROW_DIR offset → bytes 2–3 → RED
examples: (R-A2L-DEF.123/3) INLINE3 `CD` (points 10 20 30 40 as 28 1E 14 0A), {(`X`, `0`): `5`} → record byte 4 (axis offset 1 + 3) `05`; points `5`, `20`, `30`, `40` (STRICT_MON holds)
examples: (R-A2L-DEF.123/4) INLINE3 `CI`, {(2,): `9`} → record byte 0 still `04`; bytes 9–10 `00 09`
examples: (R-A2L-DEF.123/4 neg) mutant: non-value components zero-filled (`_encode_curve_record_bytes`) → byte 0 `00` → RED
examples: (R-A2L-DEF.124/1, .130/1) V171 `ASAM.C.CURVE.COM_AXIS`, the image of /118/1, {(0,): `1`} and {(`X`, `0`): `1`} → `A2L-DEF-AXIS-BYTES` (the R-A2L-DEF.118/1 message); no bytes
examples: (R-A2L-DEF.124/1 neg) mutant: values encoded without decoding the axis → bytes → RED
examples: (R-A2L-DEF.124/2) AX8(5, …), {(0,): `1`} → the `A2L-DEF-AXIS-PARTIAL` refusal of R-A2L-DEF.117.2/1
examples: (R-A2L-DEF.124/3) INLINE3 `VB` (`MATRIX_DIM 2` at 0x10), image 0x10 … 0x12 → `A2L-DEF-BYTES` `VB: 1 of its 4 bytes are not in the image`
examples: (R-A2L-DEF.125/1 … /3) V171 `…3_4.ROW_DIR`, {(3, 0): `1`} → `A2L-DEF-INDEX` `ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR: ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR[3,0] is not a value or axis point of it`; {(0, 0, 0): `1`} → `…: ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR[0,0,0] is not a value or axis point of it`; {(`X`, `0`): `1`} → `…: ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR.X[0] is not a value or axis point of it`
examples: (R-A2L-DEF.125/1 neg) mutant: (3,0) wrapped to (0,1) → bytes → RED
examples: (R-A2L-DEF.126/1, /2) V171 `ASAM.C.CURVE.FIX_AXIS.PAR_DIST`, {(`X`, `0`): `0`} → `A2L-DEF-AXIS-FIXED` `ASAM.C.CURVE.FIX_AXIS.PAR_DIST.X[0]: the points of a fixed axis are not stored in the image`; `ASAM.C.MAP.COM_AXIS.FIX_AXIS`, {(`Y`, `2`): `4`} → `ASAM.C.MAP.COM_AXIS.FIX_AXIS.Y[2]: the points of a fixed axis are not stored in the image`
examples: (R-A2L-DEF.127/1) V171 `ASAM.C.CURVE.COM_AXIS`, image of /109/1, {(`X`, `3`): `35`} → `A2L-DEF-AXIS-SHARED` `ASAM.C.CURVE.COM_AXIS.X[3]: the points of the common axis ASAM.C.AXIS_PTS.UBYTE_8 are not edited through ASAM.C.CURVE.COM_AXIS` (base: the curve refused whole, B1 line 27)
examples: (R-A2L-DEF.127/1 neg) mutant: the point written into the axis object's record → a second span → RED
examples: (R-A2L-DEF.127/2, AT-B103-I3-2) DEFC `CURVE_DEF_0001`, {(`X`, `0`): `242.500`} → `CURVE_DEF_0001.X[0]: the points of the common axis AXIS_DEF_0001 are not edited through CURVE_DEF_0001`
examples: (R-A2L-DEF.128/1) C08 `CURVE_0001`, {(`X`, `0`): `1`} → `A2L-DEF-AXIS-NONE` `CURVE_0001.X[0]: the record layout RL_U16 holds no points for this axis`
examples: (R-A2L-DEF.129/1 … /9) INLINE3 `CM1` (UBYTE points, IDENTICAL, 0..255) through `_breaking_point`: STRICT_INCREASE {X[2]: `20`} → `A2L-DEF-MONOTONY` `CM1.X[2]: 20 breaks the STRICT_INCREASE order of the axis`; STRICT_DECREASE (40 30 20 10) {X[1]: `45`} → `CM1.X[1]: 45 breaks the STRICT_DECREASE order of the axis`; MON_INCREASE {X[2]: `20`} → accepted, points `10`, `20`, `20`, `40`; MON_INCREASE {X[2]: `15`} → `CM1.X[2]: 15 breaks the MON_INCREASE order of the axis`; MON_DECREASE (40 30 20 10) {X[2]: `35`} → `CM1.X[2]: 35 breaks the MON_DECREASE order of the axis`; no MONOTONY {X[3]: `30`} → `CM1.X[3]: 30 breaks the STRICT_MON order of the axis`; MONOTONOUS {X[1]: `5`} → `CM1.X[2]: 30 breaks the MONOTONOUS order of the axis`; NOT_MON {X[1]: `50`} → accepted, `10`, `50`, `30`, `40`; STRICT_INCREASE {X[1]: `35`} → `CM1.X[2]: 30 breaks the STRICT_INCREASE order of the axis` (B3b Q3)
examples: (R-A2L-DEF.129/1 neg) mutant: no monotony check (base) → accepted → RED; texts compared (`100` < `20`) → RED
examples: (R-A2L-DEF.130/2) INLINE3 `CM1` (no MONOTONY), {(`X`, `1`): `abc`, (0,): `abc`} → `CM1.X[1]: 'abc' is not a number`
examples: (R-A2L-DEF.130/3) INLINE3 `CM1` STRICT_INCREASE, {(`X`, `1`): `50`, (2,): `x`} → `CM1[2]: 'x' is not a number` (the values before the monotony)
examples: (R-A2L-DEF.130/3 neg) mutant: the monotony checked first → `CM1.X[2]: 30 breaks …` → RED
examples: (R-A2L-DEF.131/1) instances: V171 `…COLUMN_DIR` {(1,0): `-7`} → decodes `-7`; DEFC `MAP_DEF_0001` {(1,0): `123`} → bytes `00 7b` at record offset `14` (0x80007E), decodes `123`; DEFC `VAL_BLK_DEF_0001` {(1,1): `-12.5`} → stored `-250`, bytes `ff 06` at offset `8` (0x800098), decodes `-12.5`; the 17-significant-digit texts of the six VAL_BLK values encode back to `737`, `219`, `636`, `-413`, `-395`, `-214`; `12.34` → `A2L-DEF-ENCODE` (raw 246.8, not counted); ≥ `200` accepted edits over the case's objects, `0` that do not agree (B3b Q6, B3c R3)
examples: (R-A2L-DEF.131/1 neg) mutant: INDEX_DECR written as INCR → `CD`'s point 0 lands at byte 1 → RED
examples: (R-A2L-DEF.131/1, the precision rule's branches on elements) INLINE3 `VL01` (UWORD, `CM(LINEAR 0.1 0)`, `FORMAT "%.15"`), {(0,): `4.1`} → stored `41`, accepted (p = 4.1000000000000005: only the 15-significant-digit clause agrees); INLINE3 `VF32` (FLOAT32_IEEE, IDENTICAL, `FORMAT "%.15"`), {(0,): `0.1`} → bytes `3d cc cc cd`, accepted (FLOAT32's 6-digit clause)
examples: (R-A2L-DEF.131/1 neg) mutant: the 15-significant-digit clause left out → `4.1` on `VL01` refused → RED; the 6-digit clause left out → `0.1` on `VF32` refused → RED
examples: (R-A2L-DEF.132/1) every edit of .131/1 → `0` unedited elements or points whose stored value changes; every record byte outside the edited cells equal to the image's
examples: (R-A2L-DEF.132/1 neg) mutant: the whole record re-encoded from every element's display text → DEFC `VAL_BLK_DEF_0001` stores `738`, `220`, `636`, `-414`, `-396`, `-214` (`4` cells drift) → RED (B3c R3)
examples: (AT-B103-I3-2) DEFC through the app's loaders: `MAP_DEF_0001` {(`X`, `1`): `600`} → bytes `02 58` at 0x800072, axis `224`, `600`, `648`, `909`; {(`X`, `2`): `100`} → `MAP_DEF_0001.X[2]: 100 breaks the STRICT_INCREASE order of the axis` (B3b Q6); the common-axis edit as /127/2
examples: (AT-B103-I3-1, edit) V171: one value of each of the 20 decodable objects, its own decoded text plus 1 → applied, decoded: the new value there, every other value unchanged; the 3×4 twins' (1,0) edit lands at offsets 2 and 8
examples: (R-A2L-DEF.58.1/arr-1, /arr-2) V171 and C08: one cell each edited to its own decoded text → deep copies of `a2l_data` and the image before equal both after → `True`

_breaking_point
req: R-A2L-DEF.129
in: AxisDefinition axis; tuple[int | float, ...] stored_points
out: int | None k
func: new (D-5 A). The *monotony rule* of `axis.monotony` on the stored points in point index order: the first k from 1 such that points 0 … k do not follow the rule (STRICT_INCREASE each greater; STRICT_DECREASE each smaller; MON_INCREASE not smaller; MON_DECREASE not greater; STRICT_MON all greater or all smaller; MONOTONOUS all not smaller or all not greater; NOT_MON any); `None` when every prefix follows it. Numbers compared, never texts. Only `encode_values` calls it, and only for an axis the edit changes (an axis read from the image is never refused for its order).
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.129/1) STRICT_INCREASE, (`10`, `20`, `20`, `40`) → `2`
examples: (R-A2L-DEF.129/6) STRICT_MON, (`10`, `20`, `30`, `30`) → `3`
examples: (R-A2L-DEF.129/7) MONOTONOUS, (`10`, `5`, `30`, `40`) → `2`
examples: (R-A2L-DEF.129/9) STRICT_INCREASE, (`10`, `35`, `30`, `40`) → `2` (an unedited point breaks)
examples: (R-A2L-DEF.129/3, /8) MON_INCREASE (`10`, `20`, `20`, `40`) → `None`; NOT_MON (`10`, `50`, `30`, `40`) → `None` (B3b Q3)

### Synth (`tools/synth/make_release_case.py`, G2)

build_definition_objects
req: R-A2L-DEF.133, R-A2L-DEF.134, R-A2L-DEF.135, R-A2L-DEF.63
in: random.Random rng
out: tuple[dict[str, tuple[int, bytearray]], list[dict]] built
func: changed (D-15 A). was: Inc 2's: the 256-byte `cal` region (fill, then Inc 2's planned bytes, draws 1 … 5), the three empty region keys, Inc 2's four objects. / now: the same, then `_definition_array_objects(rng, 0x800040)` (draws 6 … 11) appended to the object list, their `raw_bytes` written over the fill at their addresses. Touches no case 08 function and no other random sequence.
module: tools/synth/make_release_case.py
examples: (R-A2L-DEF.63/arr-1) seed 20260001, twice → the same 9 objects and the same 256 region bytes; Inc 2's `ENUM_0001` raw `1`, mask word `0x1AE7`, display bytes `01 1f` unchanged (B3 P8)
examples: (R-A2L-DEF.63/arr-1 neg) mutant: Inc 3's draws taken before Inc 2's → Inc 2's planned values move → R-A2L-DEF.60/1 RED
examples: (R-A2L-DEF.59/arr-1) case 08 at 1 MiB and 10 MiB → Inc 2's 22 pinned digests (case 08's functions are not called)

emit_definitions_a2l
req: R-A2L-DEF.133, R-A2L-DEF.134, R-A2L-DEF.135
in: dict[str, tuple[int, bytearray]] regions; list[dict] objects
out: str text
func: changed (D-15 A). was: Inc 2's DEFC text. / now: the same text with, in the same MODULE, the layouts `RL_DEF_AXIS`, `RL_DEF_MAP`, `RL_DEF_S16_ROW` after Inc 2's, the method `CM_DEF_FINE` after `CM_DEF_LIN`, then the AXIS_PTS `AXIS_DEF_0001` and the CHARACTERISTICs `CURVE_DEF_0001`, `CURVE_DEF_0002`, `MAP_DEF_0001`, `VAL_BLK_DEF_0001` after Inc 2's objects, as pinned above; one keyword, component and header per line; `\n` line ends; addresses as `_fmt_addr` writes them.
module: tools/synth/make_release_case.py
examples: (R-A2L-DEF.133/1) both curves' AXIS_DESCR hold `AXIS_PTS_REF AXIS_DEF_0001`; `RL_DEF_AXIS` holds `NO_AXIS_PTS_X 1 UWORD` and `AXIS_PTS_X 2 UWORD INDEX_INCR DIRECT`; the AXIS_DESCR method `CM_DEF_LIN` (`COEFFS_LINEAR 0.5 0`); the app's parser reads the text with `0` errors (B3b Q6)
examples: (R-A2L-DEF.133/1 neg) mutant: each curve given its own AXIS_PTS → RED; the count word written `00 00` → the decode gives `A2L-DEF-AXIS-CURRENT` → RED
examples: (R-A2L-DEF.134/1) `MAP_DEF_0001`: X `STD_AXIS … 4 0 1000` with `MONOTONY STRICT_INCREASE`, its points in `RL_DEF_MAP`; Y `FIX_AXIS … 3 0 100` with `FIX_AXIS_PAR_DIST 10 5 3`; `FNC_VALUES 2 SWORD COLUMN_DIR DIRECT`; nX `4` ≠ nY `3`
examples: (R-A2L-DEF.134/1 neg) mutant: the values written ROW_DIR under the COLUMN_DIR line → the decode differs from the plan → RED
examples: (R-A2L-DEF.135/1) `VAL_BLK_DEF_0001`: `MATRIX_DIM 3 2`, `FNC_VALUES 1 SWORD ROW_DIR DIRECT`, `CM_DEF_FINE` (`COEFFS_LINEAR 0.05 0`), `FORMAT "%.1"`
examples: (R-A2L-DEF.135/1 neg) mutant: a square `MATRIX_DIM 3 3` → a transposed read can pass → RED by the threshold n1 ≠ n2

_definition_array_objects
req: R-A2L-DEF.133, R-A2L-DEF.134, R-A2L-DEF.135
in: random.Random rng; int cursor
out: list[dict] objects
func: new (D-15 A; G2). Plans, from `cursor` (`0x800040`), the five Inc 3 objects of the pinned table with draws 6 … 11 in that order, each with the I-D keys: the records packed big-endian by `_pack_scalar` (the MAP's values at offset 8 + 2·(y + 3·x), its own COLUMN_DIR rule; the VAL_BLK's at 2·(i + 3·j)); `planned_text` by the display rule (IDENTICAL integers; `CM_DEF_LIN` `%.3`; `CM_DEF_FINE` `%.1` on `stored × 0.05`).
module: tools/synth/make_release_case.py
examples: (R-A2L-DEF.133/1) seed 20260001 → `AXIS_DEF_0001` at `0x800040`, raw `00 05 01 e5 02 7b 02 b8 03 3c 03 85`, planned stored `485`, `635`, `696`, `828`, `901` (strictly increasing), texts `242.500` … `450.500`; `CURVE_DEF_0001` values `37818`, `52215`, `28375`, `58106`, `11719` (B3 P8)
examples: (R-A2L-DEF.134/1) `MAP_DEF_0001` at `0x800070`, `32` bytes, axis X `224`, `577`, `648`, `909`, (1,2) planned `-485` at its COLUMN_DIR offset (B3 P8)
examples: (R-A2L-DEF.135/1) `VAL_BLK_DEF_0001` at `0x800090`, raw `02 e1 00 db 02 7c fe 63 fe 75 ff 2a`, planned texts `36.9`, `11.0`, `31.8`, `-20.7`, `-19.8`, `-10.7` (B3c R3)

### Unchanged context (`s19_app/tui/a2l.py`, frozen)

_walk_record_layout_components
req: R-A2L-DEF.88, R-A2L-DEF.75
in: dict layout; list[int] axis_counts
out: Optional[list[dict]] components
func: unchanged (frozen `a2l.py:1538`, private; D-12 A). Every layout line in **line order** into components with aligned offsets (the layout's own ALIGNMENT lines), `None` on an unknown line, RESERVED without a count, a FIX_NO_AXIS_PTS line, or past 1 MiB. Reused only through `_place_components`, which hands it a cleaned layout in position order. Real callers (C3): `_decode_external_axis_points` (`:3278`), `_encode_curve_record_bytes` (`:2280`), `_record_layout_full_span` (`:1805`), `_resolve_record_layout_components` (`:1740`).
module: s19_app/tui/a2l.py
examples: (holds on base, B1 P11) `[AXIS_PTS_X …, FNC_VALUES …, FIX_NO_AXIS_PTS_X 5]` with `[5]` → `None` (BL-I3-5)
examples: (holds on base, B3 P3) the cleaned V171 `RL.CURVE.SWORD.SBYTE.DECR` with `[8]` → offsets `0`, `1`, `9`, end `25`

_strip_a2l_comments
req: R-A2L-DEF.67, R-A2L-DEF.84
in: str text
out: str text
func: unchanged (frozen `a2l.py:353`, private). Removes `/* … */` and `//` comments, keeping quoted text and the line ends. Reused by `_read_matrix_dim` and `_read_record_layout` (lines kept, unlike `_flatten_body_tokens`). Real caller (C3): `_flatten_body_tokens` (`:456`).
module: s19_app/tui/a2l.py
examples: (holds on base, its docstring) `'CURVE /* c */ 0x1  // tail\nRL'` → `'CURVE  0x1  \nRL'`
examples: (holds on base, B3 P1) V171 `MATRIX_DIM 16 1   /* describes … */` → words `16`, `1`

_split_line_respecting_quotes
req: R-A2L-DEF.67, R-A2L-DEF.84
in: str line
out: list[str] tokens
func: unchanged (frozen `a2l.py:319`, private). Splits one line on spaces, a quoted text one token. Called by `_read_matrix_dim` and `_read_record_layout` on each cleaned line (it joins D-9's import list again). Real callers (C3): 10 functions of `a2l.py`.
module: s19_app/tui/a2l.py
examples: (holds on base, B3 P2) `AXIS_PTS_X 2 SBYTE INDEX_DECR DIRECT` → (`AXIS_PTS_X`, `2`, `SBYTE`, `INDEX_DECR`, `DIRECT`)

_byte_order_from_section_lines
req: R-A2L-DEF.114, R-A2L-024, R-A2L-025, R-A2L-026
in: list[str] lines
out: Optional[str] byte_order
func: unchanged (frozen `a2l.py:311`, private). The first `BYTE_ORDER <word>` line → `big` / `little` / `None`. Reused by `_read_axis` for the axis object's own line and for the module's MOD_COMMON. Real callers (C3): `extract_a2l_tags.<locals>._module_byte_order` (`:2587`), `extract_record_layouts` (`:723`).
module: s19_app/tui/a2l.py
examples: (holds on base, B3b Q2) INLINE3 `AXO`'s lines with `BYTE_ORDER MSB_LAST` → `little`; V171's axis object → `None` (its byte order comes from MOD_COMMON, B3 P3)

_encode_curve_record_bytes
req: to trace
in: dict tag; list[Any] values; Optional[dict] compu_methods_by_name; Optional[dict] compu_tabs_by_name; Optional[dict] record_layouts_by_name
out: tuple[Optional[tuple[int, ...]], Optional[str], list[str]] result
func: unchanged (frozen `a2l.py:2195`, private). The latent curve encode: writes `0` into NO_AXIS_PTS_X, the points in the order given whatever INDEX_DECR, the object's method for its axis points, no monotony check, COM_AXIS refused whole (BL-I3-7). No Inc 3 node calls it; it is the oracle of R-A2L-DEF.123/4's and .132's negative controls. Real caller (C3): `encode_physical_to_raw_bytes` (`:2462`) ← `resolve_symbol_entry` (`change_service.py:649`) ← no product caller (C1).
module: s19_app/tui/a2l.py
examples: (holds on base, B1 P12a) 8 increasing points + 8 values on `RL.CURVE.SWORD.SBYTE.DECR` → first bytes `00` `00` `0A` … (the count byte `0`, the points in the order given)
examples: (holds on base, B1 P12b, P12c) a non-monotonic axis → accepted; `ASAM.C.CURVE.COM_AXIS` → `array values are not supported`

## Entities

[Data: Definition]
desc: I-2's frozen dataclass with Inc 3's six defaulted fields (pinned above). Built only by `describe_definitions` (through `_describe_array` for the Inc 3 kinds) and by `_element_definition` (one element or point); read by every decode and encode node; consumers read it by field name.

[Data: AxisDefinition]
desc: I-2's frozen dataclass of one axis (pinned above; `count_datatype` P-2, accepted); built by `_read_axis`, its offsets completed by `_describe_array`.

[Data: DecodedAxis]
desc: I-2 `DecodedAxis(letter, points)`; `points` `None` for an axis with no points (R-A2L-DEF.100).

[Data: DecodedValues]
desc: I-2 `DecodedValues(values, axes)`; `values` in element order, each a `Decoded` or the `Refusal` in its place (R-A2L-DEF.119).

[Data: record layout]
desc: the dict `_read_record_layout` gives: `name`, `components` (word tuples in position order), `alignment`, `fixed`; private to the module.

[Data: a2l_data]
desc: the `parse_a2l_file` payload; Inc 3 reads `tags`, `sections` (object lines, AXIS_DESCR and FIX_AXIS_PAR_LIST children; the AXIS_PTS sections and MODULE / MOD_COMMON only through the maps of `describe_definitions`'s one walk, E3A-32), `record_layouts_by_name` (lines, byte order), `compu_tabs_by_name`; never writes (R-A2L-DEF.58).

[Data: image]
desc: any `Mapping[int, int]` address → byte; read only; `Encoded` is applied by the caller.

[I/O: DEFC files]
desc: `firmware.s19` and `firmware.a2l` that `generate_definitions_case` (Inc 2, unchanged) writes; with Inc 3 they hold the five objects pinned above.

[I/O: case 08 files]
desc: the 22 pinned digests (R-A2L-DEF.59); no Inc 3 node writes them.

## Edges

[Data: a2l_data].sections ──▶ _read_matrix_dim
describe_definitions ──▶ _find_axis_object
when: through `axis_pts_by_name`, built in the one walk of `sections` (E3A-32)
describe_definitions ──▶ _module_common
when: through `mod_common_of`, built in the one walk of `sections` (E3A-32)
[Data: a2l_data].record_layouts_by_name ──▶ _read_record_layout
describe_definitions ──▶ _conversion_fields
when: through Inc 2's `compu_methods_by_name` and `compu_tables_by_name` (E3A-32)
describe_definitions ──▶ [Data: Definition]
_read_axis ──▶ [Data: AxisDefinition]
[Data: image] ──▶ decode_values
[Data: image] ──▶ _decode_axis
when: the axis is a COM_AXIS (the axis object's record lies outside the object's record)
[Data: image] ──▶ encode_values
decode_values ──▶ [Data: DecodedValues]
emit_definitions_a2l ──▶ [I/O: DEFC files]
encode_values ──▶ _breaking_point
when: the edit changes a point of that axis

## Findings

finding E2-1 the MEASUREMENT datatype case cannot hold under the array refusal order as written
anchor: _describe_array
seen: R-A2L-DEF.81/4 (`MF`: MEASUREMENT `FOO`, `ECU_ADDRESS 0x10`, `MATRIX_DIM 4`) expects `A2L-DEF-DATATYPE`; an array's byte length is element count × the datatype's size (R-A2L-DEF.74), so with no datatype there is no length and "address and length (.7)", which CTX-A2L-DEF places before "the values' refusals (.81)", gives `A2L-DEF-ADDRESS` first — the same shape as Inc 2's E2-6, but here no LENGTH line can fix the fixture (the length is computed, not read)
cause: the array refusal order puts R-A2L-DEF.8's check among the values' refusals, after a step that needs the datatype
effect: as written, R-A2L-DEF.81's `.8` alternative is unreachable for a MEASUREMENT array (a VAL_BLK's datatype is R-A2L-DEF.86's); /4 fails on a correct model
decision: PROPOSED for E3 — the graph is written for it: a MEASUREMENT array's datatype (R-A2L-DEF.8) is checked right after MATRIX_DIM (.71) in the array refusal order (CTX-A2L-DEF gains that one item); /4 then holds as written. Alternative: keep the order and change /4's expected result to `A2L-DEF-ADDRESS` (and drop `.8` from R-A2L-DEF.81's text). Ruled: accepted (`../E2-rulings.md`)

finding E2-2 the current count needs the count component's datatype, which AxisDefinition does not hold
anchor: _current_count
seen: R-A2L-DEF.115 reads NO_AXIS_PTS_X / _Y from the image; V171's count is UBYTE, DEFC's UWORD (B3b Q6), and the pinned `AxisDefinition` fields give the count's offset but not its datatype
cause: the I-2 extension pinned by the orchestrator omits it
effect: without it `_current_count` must re-read the layout from `a2l_data` at decode
decision: PROPOSED P-2 (Interfaces): `count_datatype: str | None = None`, last, defaulted; the graph is written for it. Ruled: accepted (`../E2-rulings.md`)

finding E2-3 two nodes beyond the slice
anchor: _conversion_fields
seen: an axis builds its points' definition from a method word exactly as an object does (R-A2L-DEF.102, .103 with the axis name); Inc 2's `describe_definitions` does it inline. The axis object's byte order (R-A2L-026) and the MOD_COMMON alignment (R-A2L-DEF.89) both need the object's MODULE, which the section dict cannot give (no parent link)
cause: writing the examples of `_read_axis` and `_check_module_alignment`
effect: `_conversion_fields` (new, factored from Inc 2's `describe_definitions`, which keeps every example) and `_module_common` (new); the slice grows from 26 to 28 nodes
decision: accepted at E3 (`../E3-architect.md` §2; no security objection); E3A-04 names the node against Inc 2a's `_describe_one`. For E3 to accept with the graph; the alternative to `_conversion_fields` repeats Inc 2's METHOD → CONVERSION → TABLE → TABLE-EMPTY sequence inside `_read_axis` (two copies of one refusal order)

finding E2-4 the axis checks run axis by axis
anchor: _read_axis
seen: CTX-A2L-DEF's array refusal order lists "axis kind (.92), axis object (.96) … FIX_NO current count (.116, .117)" without saying whether axis X's checks all come before axis Y's
cause: no case has two failing axes
effect: two readings (axis-major or check-major) differ only for a map with two bad axes
decision: the graph pins axis-major (all of X's checks, then Y's), as R-A2L-DEF.103 orders the axes; E3 to confirm. Confirmed at E3 (E3A-11): written into CTX *array refusal order*

finding E2-5 no row covers decode_values / encode_values on a scalar definition
anchor: decode_values
seen: R-A2L-DEF.120 refuses the single calls on an array; nothing says what the element calls do on a number, enum or text definition
cause: consumers were expected to branch on `kind`
effect: an implementer would choose
decision: PROPOSED for E3 — the graph pins the one-element reading (Interfaces); alternative: a refusal, which needs a new code and message from E1. Ruled at E3 (E3A-18): the decode's reading is row R-A2L-DEF.146 (case /1); the encode half waits for 3b, with no row yet

finding E2-6 the DEFC VAL_BLK's conversion is LINEAR 0.05, not Inc 2's 0.5
anchor: _definition_array_objects
seen: R-A2L-DEF.132's negative control re-encodes every element from its display text; under `CM_DEF_LIN` (a = 0.5) and `%.1` every value is exact at one decimal, so the mutant cannot drift; under `CM_DEF_FINE` (a = 0.05) it stores `738`, `220`, `636`, `-414`, `-396`, `-214` for `737`, `219`, `636`, `-413`, `-395`, `-214` (B3c R3)
cause: D-15 fixes "LINEAR a ≠ 1, `%.1`", not a
effect: one new method line in DEFC; the 17-significant-digit round trip still holds within the encode's 1e-6 integrality tolerance (B3c R3)
decision: pinned in the DEFC table

finding E2-7 inputs no row covers; the graph fails closed
anchor: _read_record_layout
seen: 0 tracked uses of each (C1 shapes, B3 P5/P6): a malformed FIX_AXIS_PAR / _PAR_DIST / _PAR_LIST word (→ `A2L-DEF-AXIS-FIX`); a FIX_NO_AXIS_PTS or ALIGNMENT line with a bad number, or a second line of one component (→ `A2L-DEF-LAYOUT-PART` naming it); an AXIS_PTS_<letter> component for an axis the object does not have, or in a VAL_BLK's layout (→ `A2L-DEF-LAYOUT-AXIS` with `<word>` `(none)`); a malformed NUMBER word (passed over: the LENGTH rule applies); a MEASUREMENT `LAYOUT` word other than ROW_DIR / COLUMN_DIR (→ `A2L-DEF-LAYOUT-MODE` with `<layout>` `(none)`, `<component>` `LAYOUT`); a malformed MOD_COMMON ALIGNMENT line (left out); a MEASUREMENT `MATRIX_DIM` that is malformed (an array, so R-A2L-DEF.71 refuses it, not a scalar); a record longer than `MAX_A2L_DECODE_BYTES` (no byte length → `A2L-DEF-ADDRESS`; the cap bounds the decode of a hostile MATRIX_DIM); a NO_AXIS_PTS component in the object's own layout for a COM axis (placed, not read)
cause: the rows cover the tracked shapes
effect: each is decided here, not by an implementer
decision: for E3 (the security reviewer for the size cap); a ruling that wants rows sends them to E1. Rebase: the size cap is now Inc 2's R-A2L-DEF.7.2 for an array (its byte length as computed, refused above 1,048,576 bytes); a curve or map whose walk stops past the cap has no byte length (.7.1). The hostile shapes Inc 3 adds are listed in `../E2-rulings.md` (rebase list). Coverage pass: the malformed FIX words have a row (R-A2L-DEF.141, its own message under `A2L-DEF-AXIS-FIX`), the point counts a bound (.142), the axis object's record a span check (.143), the whole-number reads a CTX format (*whole number*; cases .58.2/arr-1 … /arr-8); the NUMBER word passed over, a layout keyword with a bad number (.84's refusal) and a MOD_COMMON line left out keep this finding's choices, now with cases. E3 correction: the MOD_COMMON line is no longer left out — R-A2L-DEF.144 refuses it (E3A-09); a component line with extra words is a part (.84/7, E3A-08); a malformed MEASUREMENT MATRIX_DIM is an array by CTX *multi-value MATRIX_DIM line* (.71/5, E3A-02); a NO_AXIS_PTS count takes a count datatype only (.86/3, E3S3-01); the other choices accepted (`../E3-architect.md` §2)

finding E2-8 V171's section tree nests 28 MEASUREMENTs
anchor: _module_common
seen: (B3 P0) `Unclosed /begin sections detected`: 28 MEASUREMENT sections and the MODULE have no `end_line`; every such MEASUREMENT holds a one-line `/begin IF_DATA … /end IF_DATA`, which `build_section_tree` opens and never closes, so the MEASUREMENT's `/end` closes the IF_DATA and later sections nest under it
cause: a frozen `a2l.py` parse defect (new backlog row BL-I3-11)
effect: pre-order walks (`_collect_sections_by_name`, Inc 2's pairing) are unaffected (B3 P1, P2: every object found, its MATRIX_DIM words right); a MODULE found by line range would fail — `_module_common` walks by identity
decision: identity walk; BL-I3-11 to the batch backlog

finding E2-9 describe cost grows for a COM_AXIS curve
anchor: _read_axis
seen: Inc 2's E2-10: one walk of software_a's sections costs 3.9 – 9.1 ms; an Inc 3 definition adds `_module_common` (one walk) and, per COM axis, `_find_axis_object` (one walk) and the alignment's second `_find_axis_object`
cause: I-2 takes the parse payload, which has no index by name (pure module)
effect: about 35 ms per COM_AXIS curve on software_a; Inc 6 must describe only the rows it shows (Inc 2's E2-10 A)
decision: for E3 with Inc 2's E2-10. Rebased (Inc 2's E3A-01, E3A-32): every lookup is a map of `describe_definitions`'s one walk; software_a in one batch describe ≈ `0.995` s (Interfaces, *Lookups*), so Inc 6 may describe every row at once. Re-measured at E3: ≈ 1.2–1.3 s (E3A-12); a hostile file of FIX axes at the cap no longer costs describe anything per point (E3A-01, R-A2L-DEF.142/5)

finding E2-10 deviations from the E1 slice
anchor: _describe_array
seen: `_object_kind` gains `matrix_words` (the tag keeps only MATRIX_DIM's first number); `_read_matrix_dim` gives (words, shape) and `_check_module_alignment` gives (component, a, b) — `_describe_array` writes their messages, which need the name (as Inc 2's E2-14 did for `_check_bit_mask`); `_array_shape` may give `None` (no shape: `A2L-DEF-ADDRESS`); `_place_components` gives (offsets, end), the end being R-A2L-DEF.75's byte length; `_read_axis` gains `name`; `_decode_stored` is decided as Inc 2's `decode_definition` second half moved (no duplicate); the two nodes of E2-3
cause: writing the examples
effect: 28 slice nodes (E1: 26)
decision: accepted at E3 (`../E3-architect.md` §2). The E3 correction adds two more deviations: `_check_module_alignment` also gives (`ALIGNMENT_<class>`, word) for an unreadable MOD_COMMON line (E3A-09), and `_fixed_points` takes `fixed_rule` only (E3A-01); the slice is 29 with `_describe_one` (E3A-04)

finding E2-11 an array with no readable shape reports element count 0
anchor: _describe_array
seen: `Definition.element_count` defaults to 1 (Inc 2's scalars); a refused array whose shape could not be read (`A2L-DEF-MATRIX`, a MAX refusal, no NUMBER and no LENGTH) has no element count
cause: the default fits scalars only
effect: with 1, Inc 6 would show a refused array as one element — PE-D1 again
decision: pinned `shape` `()` and `element_count` `0` for that case; Inc 6 reads `0` as unknown. Ruled at E3 (E3A-03): `element_count` `None` — an unknown count is absent, never `0` or `1` — also on a definition of kind `""`; R-A2L-DEF.73 holds unchanged (case /9)

finding E2-12 E1 counts 25 refusal codes; the rows define 27
anchor: describe_definitions
seen: `grep` over `01-requirements.md` gives 28 distinct codes in Inc 3's rows, `A2L-DEF-LENGTH` reused
cause: a count in E1's rulings §1 and the slice
effect: none on the design
decision: the Interfaces list holds the 27; E1's text to correct at its next pass

finding E2-13 R-A2L-DEF.112/1's "sorted" mutant cannot turn it RED
anchor: _fixed_points
seen: V171's FIX_AXIS_PAR_LIST is `-1 4 6 8 9 10`, already in increasing order (B3 P2); 2 tracked lists, both this one
cause: the only fixture
effect: the negative control "the list sorted" stays GREEN; the second control (the point index) carries the row
decision: E4's tester adds an INLINE3 list out of order (`5 1 3 2 4 9`) for the sorted mutant, or marks /1 `partial` for it

finding E2-14 AT-B103-I3-1's V171 expectations, counted
anchor: decode_values
seen: (B3 P5) V171 has 40 objects of the Inc 3 kinds and the kinds still outside: 11 arrays, 6 curves, 3 maps with no refusal; 8 curves and 5 maps `A2L-DEF-ALIGNMENT`, among them `ASAM.C.CURVE_AXIS` (a STD_AXIS curve used as an axis) and `ASAM.C.DEPENDENT.CURVE_1 … _3`, `MAP_1 … _3`; 2 `A2L-DEF-AXIS-KIND`; 5 `A2L-DEF-KIND`
cause: the AT names the shapes, not the counts
effect: the tester's expected list is fixed here
decision: the AT example uses these counts; the AT's image must also hold `ASAM.C.DEPENDENT.CURVE_4`, `MAP_4`, `ARRAY_1 … _4` and `ASAM.C.MAP.COM_AXIS.FIX_AXIS_2`'s records (or the AT decodes only the objects whose records it lists)

finding E2-15 the graph against the code and the parser
anchor: _walk_record_layout_components
seen: (C3 check) `marks=5 graph_nodes=33 calls=2 findings=28`, every finding "Graph node without mark (no code yet)", `0` drifts on the 5 `a2l.py` nodes; (lint) `nodes=33 entities=9 edges=13 findings=15 not read=0`
cause: the method's two tool checks
effect: the contracts of the reused frozen helpers are the code's; the 28 slice nodes exist only here
decision: E4 marks the new and changed nodes in a throwaway copy and reruns `i3e2-extract.sh check`; done = `0` drifts and every example a test that fails before and passes after. After the E3 round-1 correction, `codewire_lint.py` (v3.1.0 `e436a08`) on this file: `nodes=34 entities=9 edges=13 findings=16 not read=0`

finding R-1 (rebase) R-A2L-DEF.5/arr-1 expected the first tag of a name declared twice
anchor: describe_definitions
seen: the E2 example gave two VAL_BLKs `DUPA` at 0x10 and 0x20 the address `0x10`; Inc 2's E3 removed the first-tag rule (E3S-35): R-A2L-DEF.5 now uses the one tag of a name, and R-A2L-DEF.139 refuses a name declared more than once (`A2L-DEF-NAME` `<name>: the A2L declares that name more than once`)
cause: the case was written against Inc 2's E1 rows
effect: on a correct model the case fails; for an array the hazard is the one E3S-35 names (a commented-out old copy is a live tag and the first of its name)
decision: rebased — R-A2L-DEF.5/arr-1 becomes `DUPA` at 0x20 beside `dupa` at 0x10 (case included); the old input becomes R-A2L-DEF.139/arr-1 (`../02-test-cases.md`; cited rows in `../01-requirements.md`). The same first-of-the-name lookup remains for the AXIS_PTS map and the parser's record-layout map (last of the name): listed in `../E2-rulings.md`; reader-rooted, owned by Inc 11 (orchestrator ruling on the split; `../01-requirements.md` "Split (amendment A2)")
