# Inc 2 — E1 rulings: scope, canon changes, decisions

Base: branch `batch-103` at `332f8ca` (product tree `e07fb00`). Rows: `01-requirements.md`. Cases: `02-test-cases.md`. Slice: `E1-slice.md`. Evidence (all tool output, `evidence-e1/`):
- `i2e1-pilot.py` → `i2e1-pilot-transcript.txt` (B): the base tree's parse, decode and encode on real A2L shapes; LAN host <runner>, Python 3.11.18, the read-only clone at `e07fb00` (`s19_app.__file__` printed on line 5), HOME/XDG/LOCALAPPDATA under `/tmp/b103-e1-2/home`, no display, no clipboard.
- `i2e1-case08-hashes.py` → `i2e1-case08-hashes-transcript.txt` (C): 22 SHA-256 digests of case 08 (seed 20260001, 10 MiB and 1 MiB, two runs each, 0 mismatches), written under `/tmp/b103-e1-2/out` on the same host.
- `i2e1-callers.py` → `i2e1-callers-transcript.txt` (C): the Code-Wire v3.1.0 extractor (`codewire_extract.py`, commit `e436a08`, tree-identical to the `ebc3bb7` PLAN pins) over a throwaway copy of `git archive e07fb00 s19_app` with one mark per def; real callers of every reused function, base line numbers.
- `i2e1-a2l-shapes.txt` (C): keyword census of the 35 tracked `.a2l` files. `i2e1-id-census.txt` (C): `R-A2L-DEF` unused.

## 1. Scope

**In (US-103-05, PLAN Inc 2):**
- A new pure module, proposed path `s19_app/tui/a2l_definition.py` (beside `a2l.py`; no `textual` import, no file or clipboard I/O). It builds the *definition* of one scalar A2L object, decodes its stored bytes into a value and a display text, and encodes an operator's text into the bytes of its span.
- Scalar kinds: number, enum (TAB_VERB over COMPU_VTAB, and COMPU_VTAB_RANGE under D-4 A), BIT_MASK fields, ASCII texts, FORMAT and PHYS_UNIT for display (PHYS_UNIT through the cited R-A2L-030), EXTENDED_LIMITS against LOWER/UPPER limits. Every failure path is its own `If` row with its exact message (R-A2L-DEF.4 … .9, .11 … .13, .17, .19, .21, .24 … .26, .28, .31, .32, .34, .36 … .40, .42, .43 … .45, .47, .49, .51, .52, .54, .57).
- The round trip as two requirements: numbers (R-A2L-DEF.55, with the exact rule *agree at the display precision* of CTX-A2L-DEF) and texts (R-A2L-DEF.56); the guard that refuses a value that would break it (R-A2L-DEF.54).
- D6 synth extension, additive (A1 rule 2): case 08's 22 output files pinned by SHA-256 (R-A2L-DEF.59) and a new *definitions case* with an enum object and two BIT_MASK objects (R-A2L-DEF.60 … .63).

**Out (with reason):**
- VAL_BLK, MATRIX_DIM arrays, STD/FIX/COM_AXIS, AXIS_PTS, CURVE and MAP — Inc 3 (PLAN). They get the A2L-DEF-KIND refusal here (R-A2L-DEF.4); Inc 3 adds its kinds to CTX-A2L-DEF's *defined object* list, so the row's wording does not change, only its case list.
- The editors and the picker — Inc 8, Inc 9, Inc 6 (they consume I-2, §4).
- FLOAT16_IEEE **encode**: the reused encode refuses it (B line 31) and no tracked A2L declares a FLOAT16 object (`i2e1-a2l-shapes.txt`: the one `FLOAT16_IEEE` line is `ALIGNMENT_FLOAT16_IEEE 1`, `software_b.a2l:849`). It stays a reason of R-A2L-DEF.42. The FLOAT16 **decode** is in (cited R-A2L-045).
- BIT_OPERATION, ENCODING, STATUS_STRING_REF, DEFAULT_VALUE_NUMERIC: BIT_OPERATION and ENCODING appear in 0 tracked files; STATUS_STRING_REF (23 lines, 2 files) names a status table for a numeric method — showing a status text for a sentinel raw value is a feature of its own; DEFAULT_VALUE_NUMERIC (4 lines) belongs to COMPU_TAB, a number table. Backlog BL-I2-14.
- An ASCII object whose datatype is not one byte wide: every tracked ASCII object is UBYTE-based (the ASAM demo states it, V171 `:3969`). Not guarded.
- Any change to `a2l.py` (frozen) or to the tag table's own decode: every defect found there is a backlog row (§5), wrapped in the model where an Inc 2 row needs it (D-2).
- `parse_parameter_list` and I-5: no Inc 2 row parses a label list (§5).

## 2. Changes to existing canon rows and notes

- **Rows:** none changed, none split, none retired. The cited rows (`01-requirements.md`, "Cited rows") keep their text; the model meets them, and their cases on the model are in `02-test-cases.md`.
- **New context note CTX-A2L-DEF** (terms, formats, lists only), placed after CTX-MAC in S2. Its lists that rows cite: *defined object*, *encode reasons*, *refusal order*, *encode order*, *agree at the display precision*.
- **CTX-A2L-VALUE**, one line (with D-4 A): `TAB_VERB    a COMPU_VTAB of raw → text pairs.` becomes `TAB_VERB    a COMPU_VTAB of raw → text pairs, or a COMPU_VTAB_RANGE of raw ranges → text.` R-A2L-059 keeps its text (it names COMPU_VTAB); the range rows are R-A2L-DEF.15 and .30.
- **New subsection** S2.7 · *A value by its A2L definition (CTX-A2L-DEF)*, after S2.6, blocks S2.7a … S2.7d (D-11 for S2.7d). Its "Replaces:" line: nothing (new behaviour); it notes that `encode_physical_to_raw_bytes` had no canon row before (S2 review, "Passed to other groups"; S10 D10-13).

## 3. Decisions — PROPOSED, awaiting orchestrator ruling

Each: options, the consequence of each, my recommendation. The rows are written for the recommendation; a different ruling withdraws or rewrites the rows named.

**D-1 · Interface I-2** — see §4. PROPOSED — awaiting orchestrator ruling. Recommendation: §4 as written.

**D-2 · Where the definition reads its A2L facts.** `a2l.py`'s side tables lose what the scalar kinds need: TAB_VERB is not a recognised conversion type (B lines 6-10), a commented COMPU_METHOD header loses its type, format and table (B line 9), the COMPU_VTAB texts are sorted and a numeric text becomes a float (R `a2l.py:916-920`), DEFAULT_VALUE and COMPU_VTAB_RANGE are dropped (B lines 13-15), FORMAT, EXTENDED_LIMITS and PHYS_UNIT are not read (B lines 18-21), and a deposit-spelled datatype is guessed by size (S2 D2-8).
- A — the model reads the COMPU_METHOD record, the enum table and the object's own lines itself from `a2l_data["sections"]`, comments left out (by `a2l.py`'s `_flatten_body_tokens`), and reuses `a2l.py` for everything else: the tag list (address, length, byte order, record layout), the numeric conversion (`_apply_compu_method`), the raw read (`_decode_scalar`, plus binary16), the encode direction (`encode_physical_to_raw_bytes`). Consequence: Inc 2's rows hold on every tracked shape; the tag table and the definition can show different things for the same object (TAB_VERB text, a masked field, a PHYS_UNIT) until the backlog rows reach `a2l.py`.
- B — the model uses `a2l.py`'s side tables as they are and patches TAB_VERB only. Consequence: R-A2L-DEF.2/3, .10/4, .14/3, .15, .16, .20, .22, .23/2 cannot pass; BalanceTube's and every a2ltool method's formats come back None.
- Recommendation: **A**. It is the "reason to wrap" the brief allows; the tag table's own defects stay backlog rows (§5).

**D-3 · Encode precision policy.**
- A — reuse `encode_physical_to_raw_bytes` for the encode direction as it is (a raw must be within 1e-6 of an integer for an integer datatype, B line 26), then decode the bytes back and refuse a value that does not *agree at the display precision* (R-A2L-DEF.54). Consequence: the round trip holds by construction; an off-grid value is refused with the encode's own reason (`the converted raw value 1.5 is not integral`); the TAB_INTP write that the encode only flags (`… - the write proceeds as <y>`, `a2l.py:2097-2103`) is accepted when it agrees at the display precision and refused otherwise. A FLOAT32 value with the a2ltool format `%.15` passes on FLOAT32's 6 digits (B line 33), so float parameters stay editable.
- B — snap to the nearest storable value within the display precision (round the inverted raw, decode, accept when it agrees). Consequence: friendlier for a coarse format (`1.25` on a 0.1 step with `%.1` is written as 1.2 or 1.3), but it needs `a2l.py`'s private inversion `_invert_physical_to_raw` with a rounding step the encode does not have, and it changes TAB_NOINTP from "exact table value" (the encode's rule, and the S2 review's note "writing must be exact, so the asymmetry looks right") to "nearest at display precision".
- Recommendation: **A** for Inc 2; B can follow with Inc 8's editor if the operator asks for snapping (the rows .41, .42, .54 change then).

**D-4 · COMPU_VTAB_RANGE.** 98 range lines in 4 tracked files, 69 range tables in software_a alone (`i2e1-a2l-shapes.txt`).
- A — in: entries (R-A2L-DEF.15), decode within min..max, both included (.30), encode to the entry's min (.48 via *enum entry*'s raw value). Three rows. Assumption to flag, not a checked fact: ASAM MCD-2 MC may treat the max as exclusive for a float raw; I could not read the standard here. Every tracked range table is integer (`0 0`, `4 7`, `100 100`), where both ends are included.
- B — out: one refusal row in place of .15 and .30 (`<name>: the range table <table> is not supported`). Consequence: every software_a enum on a range table is not editable.
- Recommendation: **A**.

**D-5 · The synth extension's shape (A1 rule 2: a new case or an opt-in option).**
- A — a new case: `make_release_case.py` gains a separate entry (`--case definitions`, default `release`) that builds its own small image (one calibration region) and A2L. `build_objects`, `generate` and every emitter of case 08 keep their code; case 08's random-number sequence is not touched. Inc 3 adds COM_AXIS to the same new case.
- B — an opt-in flag on case 08 (`--with-definitions`) that appends the objects after case 08's inventory. Consequence: case 08's code path changes (one more branch inside `build_objects` or `emit_a2l`), so a mistake moves the fixtures that `tests/support/b101_demo_image.py` rebuilds in process (`compute_region_sizes` + `build_objects(regions, Random(20260001))`) — the hash pin catches the file outputs, not that in-process path.
- Recommendation: **A**. The pin (R-A2L-DEF.59) is over CR LF read as LF, because `Path.write_text` writes CR LF on Windows; the 10 MiB arm is `slow`.

**D-6 · What the definitions case carries.** The brief asks for an enum and a BIT_MASK object.
- A — those, plus one LINEAR VALUE with a FORMAT line, a PHYS_UNIT line and EXTENDED_LIMITS wider than its limits (R-A2L-DEF.62): three lines on one more object. Consequence: Inc 8's acceptance tests get one generated fixture with every scalar kind; Inc 2 still tests the real shapes on the ASAM demo.
- B — enum and BIT_MASK only; R-A2L-DEF.62 withdrawn.
- Recommendation: **A**.

**D-7 · Limits and extended limits on encode.** Today's encode flags a value outside the limits and writes it (B line 27), and `encode_physical_to_raw_bytes` has no product caller (C: `ChangeService.add_symbol_entry` has 0 callers), so no operator sees that policy today.
- A — outside the limits with no extended limits: refuse (.43); outside the limits inside the extended limits: accept with a notice (.44); outside the extended limits: refuse (.45). The *limit value* of an enum is its entry's raw value (the V171 demo's note at `:3243`: the limits of a verbal conversion bound the internal value).
- B — flag and proceed everywhere, as the existing encode does; .43 and .45 become notices.
- Recommendation: **A** (the ASAM meaning of the two limit pairs). Inc 8 decides how the notice is confirmed on screen.

**D-8 · An object that names an undeclared COMPU_METHOD.** The canon (R-A2L-051, 052: "If a tag has no conversion method") does not say whether naming an undeclared method counts as "no conversion method"; the tag table treats it so (identity, `compu method missing`, B line 34) and `tests/test_synth_release_case.py:277-278` asserts it.
- A — the definition refuses (R-A2L-DEF.11); the canon rows stay as they are; backlog BL-I2-10 clarifies R-A2L-051/052 at the next `a2l.py` unfreeze (whether the tag table should show a conversion error, as R-A2L-064 does for a missing table).
- B — also rewrite R-A2L-051 and 052 now to include the undeclared case (two changed rows, holding on base).
- Recommendation: **A**. Writing raw = physical through an unknown conversion is a wrong edit the operator cannot see; the tag table's reading is a separate decision for S2's owner.

**D-9 · Reusing private helpers of the frozen `a2l.py`.** The model needs `_flatten_body_tokens`, `_split_line_respecting_quotes`, `_collect_sections_by_name`, `_apply_compu_method`, `_decode_scalar`, `_resolve_record_layout`, `_to_float` (`E1-slice.md` §3). No product module imports a private `a2l.py` name today (R: `git grep "from .a2l import"`).
- A — import them, list them once at the top of the new module, and pin them with one test that imports each and checks its signature, so an unfreeze that renames one fails loudly. CLAUDE.md's rule "add new public symbols to `a2l.py`" cannot be followed while the file is frozen; backlog BL-I2-15 publishes them at the next unfreeze.
- B — copy the helpers into the new module. Consequence: duplicated parse and conversion code, the brief's "reuse, do not duplicate" broken.
- Recommendation: **A**.

**D-10 · How a definition names its object.** The picker, the Check Editor and the Patch Editor key parameters by name (`A2LParameterPicker._param_rows[name]`, R `a2l_parameter_picker.py:559-560`).
- A — by name: the first tag in file order with exactly that name (R-A2L-DEF.5, .6). The tag's own lines are found as the same-position MEASUREMENT/CHARACTERISTIC section of a pre-order walk of `a2l_data["sections"]` (the walk order of `extract_a2l_tags`, R `a2l.py:2592-2773`), so a duplicate name still reads its own lines.
- B — by the tag dict the caller holds. Consequence: an enriched row (a new dict, `a2l.py:2926-2928`) loses identity with the parse's tag, so the lookup needs the name anyway.
- C — by name ignoring case, as the symbol path does (R-CHG-SYM.7). Consequence: no caller of I-2 has a typed name (they pick from the ledger), and a case-only twin would be silently merged.
- Recommendation: **A**.

**D-11 · Where the rows go at the fold.** `trace_check.py --canon` requires every active row in `REQUIREMENTS.md`. The synth rows are test-data tooling; S0.2 retired the old generator's rows (HLR-152, "not delivered").
- A — fold all 63 rows into the new S2.7, the four synth rows as S2.7d · *Test data* (they pin a fixture that 6 test files and batch-101's Inc 10, 11, 12 read).
- B — fold S2.7a … c; mark .59 … .63 `— Withdrawn` at the batch end and keep them as this increment's record. Consequence: the pin loses its trace.
- Recommendation: **A**.

**D-12 · Exact texts and display rules proposed by E1 (the orchestrator may rule any of them).**
- Refusal codes `A2L-DEF-<WORD>` and every message text of the rows (house style: `<name>: …`, an em dash before a hint, as the Patch Editor's change-document messages).
- No-text enum value: `<raw> (no text)` (R-A2L-DEF.32).
- A non-printable byte in a text shown as U+FFFD (R-A2L-DEF.34); encode accepts printable ASCII only (R-A2L-DEF.52), so the shown text never encodes into a different byte silently.
- No decimals → the 15-significant-digit text (`%.15g`), not `repr` (R-A2L-DEF.37); more than 17 decimals → 17 (R-A2L-DEF.36); an integer datatype with no conversion or IDENTICAL shows an integer whatever the decimals (R-A2L-DEF.38: the a2ltool default `%.15` on every SWORD would otherwise read `-5.000000000000000`); the format's `<length>` is not used as padding (R-A2L-DEF.35).
- A text object holds up to its byte length, no terminator reserved, padded with 0x00 (R-A2L-DEF.50; V171 `:3972-3973` allows a 0-terminated string shorter than NUMBER, not a required terminator).
- Enum texts match with case, after the spaces at both ends are left out; the default text is not an entry (R-A2L-DEF.48, .49).
- Recommendation: as written.

**D-13 · Split.** 63 rows and about 21 graph nodes plus 3 in the synth (`E1-slice.md` §1), under the caps of 80 and 40. No split proposed.

## 4. Interface I-2 — PROPOSED ruling (decode / encode / describe one A2L object)

Producer: Inc 2 (scalars), extended by Inc 3 (arrays, axes). Consumers: Inc 6 (the picker's true size and format label; the array length after Inc 3), Inc 8 and Inc 9 (the editors). Module `s19_app/tui/a2l_definition.py`; pure (stdlib + `a2l.py`), never raises on file or image content.

```text
Refusal(code: str, message: str)                                    frozen dataclass
Limits(lower: float | None, upper: float | None,
       lower_text: str, upper_text: str)                            the text as the file writes it
EnumEntry(raw: float, raw_max: float | None, text: str)            raw_max None for a COMPU_VTAB pair
Definition(                                                         frozen dataclass, fields in this order
    name: str, section: str, char_type: str | None,
    kind: str,                         "number" | "enum" | "text"   (Inc 3 adds its kinds)
    address: int | None, byte_length: int | None,
    datatype: str | None, byte_order: str,                          "big" | "little"
    bit_mask: int | None, bit_mask_text: str | None,
    conversion_type: str | None, method_name: str | None,
    display_format: str | None, decimals: int | None, unit: str,
    limits: Limits, extended_limits: Limits | None,
    enum_table: str | None, enum_entries: tuple[EnumEntry, ...], default_text: str | None,
    coeffs_linear: tuple[float | None, float | None] | None,        the method record's coefficients
    coeffs: tuple[float | None, ...] | None,                        and table reference (E3A-03, E3A-22)
    compu_tab_ref: str | None,
    shared_with: str | None,            R-A2L-DEF.138; no default, after compu_tab_ref, before refusal
    refusal: Refusal | None,           set when the object cannot be edited; every field
                                       it could read is still filled
    shape: tuple[int, ...] = (),
    element_count: int | None = 1,
    index_mode: str | None = None,
    values_offset: int = 0,
    record_layout: str | None = None,
    axes: tuple[AxisDefinition, ...] = (),                         Inc 3a fields, after refusal
    _name_echo: str | None = None,     private (P-2; compare=False, repr=False)
    _table_form: _EnumForm | _TabForm | None = None)   private (P-2; compare=False, repr=False)
Decoded(stored: int | float | None, value: int | float | str | None, text: str)
Encoded(address: int, data: bytes, notices: tuple[str, ...])

describe_definition(name: str, a2l_data: dict) -> Definition
decode_definition(definition: Definition, a2l_data: dict,
                  image: Mapping[int, int]) -> Decoded | Refusal
encode_definition(definition: Definition, a2l_data: dict, text: str,
                  image: Mapping[int, int]) -> Encoded | Refusal
display_text(definition: Definition, value: int | float) -> str     the number display rules,
                                                                    reused by Inc 3 per element
```

- **Error type:** no exception for file or image content; a `Refusal` value (the house style of `encode_physical_to_raw_bytes`, "never raises on untrusted tag/value content"). Codes are stable for tests; messages are the rows' texts.
- **Inputs:** `a2l_data` is the parse payload of `parse_a2l_file` (`sections`, `tags`, `compu_methods_by_name`, `compu_tabs_by_name`, `record_layouts_by_name`) — the model reads, never writes it (R-A2L-DEF.58). `image` is any address → byte mapping (the loaded file's `mem_map`, or a staging overlay such as a `ChainMap` an editor builds), read only.
- **Inc 3 extends without changing these names:** `Definition` gains fields with defaults (`elements`, `axes`, `shape`), `kind` gains values, and new functions decode or encode one element or axis; the scalar fields above keep their meaning for each element; `display_text` stays the one display rule; the A2L-DEF-KIND message is unchanged.
- **Inc 6 reads** `byte_length`, `datatype` and `kind` even from a refused definition; its format label (PE-D2) is Inc 6's row, composed from `datatype`.

## 5. Reuse: what the rows restate, and defects found in the reused code

Real callers are from `evidence-e1/i2e1-callers-transcript.txt` (C); line numbers as of `e07fb00`.

| Reused | Real callers today | Behaviour the new rows restate | Defects found (`a2l.py` frozen → backlog; wrapped where an Inc 2 row needs it) |
|---|---|---|---|
| `encode_physical_to_raw_bytes` (`a2l.py:2368`) | `resolve_symbol_entry` (`change_service.py:649`) ← `ChangeService.add_symbol_entry` (`:1297`) ← **no product caller** | the encode direction per conversion type (R-A2L-DEF.41), its refusal reasons verbatim (.42), packing in the tag's byte order (.53, partly). Not restated: its limits flag (replaced by .43 … .45), its TAB_INTP flag (superseded by .54), its CURVE/MAP limb (Inc 3) | **BL-I2-1** a BIT_MASK tag is written whole: the bits outside the mask are overwritten (B line 17: `35` on `BITMASK_0FF0` → bytes 23 00). Latent today (no product caller), HIGH once a caller exists. Wrapped: .46. **BL-I2-2** a TAB_VERB method is refused with an empty type name, `conversion type '' is not supported` (B line 29), because `a2l.py` never reads TAB_VERB. Wrapped: .48. **BL-I2-7** FLOAT16 refused (B line 31). |
| `_invert_physical_to_raw` (`a2l.py:2106`) | `encode_physical_to_raw_bytes` (`:2512`), `_encode_curve_record_bytes` (`:2332`) | used through the encode only | **BL-I2-8** its return annotation `tuple[Optional[float], Optional[str]]` (`:2110`) does not match the 3-tuple it returns (`:2165`, `:2192`). |
| `_apply_compu_method` (`a2l.py:1891`) | `enrich_a2l_tags_with_values` (`:2909`), `describe_curve_tag` (`:3155`, `:3202`), `_decode_external_axis_points` (`:3304`) | none: the conversion is the cited S2.3 rows | TAB_VERB falls to `unknown_method` (B line 11) — known S2 D2-5; the model never sends it a TAB_VERB method. |
| `_decode_scalar` / `_decode_raw_value` (`a2l.py:1811`, `:1821`) | `_decode_raw_value` (`:1830`, `:1834`), `_decode_component_run` (`:2975`); `enrich_a2l_tags_with_values` (`:2897`) | none (cited R-A2L-043 … 045) | **BL-I2-7** binary16 gives None (B line 25), S2 D2-9. Wrapped: the model reads binary16 itself. |
| `_resolve_record_layout` (`a2l.py:1241`) | `_infer_length_characteristic` (`:1227`), `encode_physical_to_raw_bytes` (`:2490`), `enrich_a2l_tags_with_values` (`:2887`) | none (cited R-A2L-022) | **BL-I2-13** the deposit-name fallback picks the first datatype of the same size, `__SWORD_Z` → UWORD (S2 D2-8, R-A2L-023 "Partly"). Wrapped: the model takes the datatype the name spells (cited case R-A2L-023/def-1). |
| `extract_compu_methods` / `extract_compu_tables` (`a2l.py:843`, `:898`) | `parse_a2l_file` (`:2832`, `:2833`) | none (D-2 A: the model reads the record itself) | **BL-I2-2** TAB_VERB not in `COMPU_CONVERSION_KEYWORDS` (B line 10). **BL-I2-3** a commented header line loses type, format and COMPU_TAB_REF (B line 9, BalanceTube; S2 D2-11's per-line comment handling). **BL-I2-16** COMPU_VTAB texts that look numeric become floats and the pairs are re-sorted (R `:916-920`); DEFAULT_VALUE dropped; COMPU_VTAB_RANGE not read (B lines 12-15). |
| `extract_a2l_tags` (`a2l.py:2572`) | `parse_a2l_file` (`:2834`) | none (address, length, byte order are cited rows) | **BL-I2-4** PHYS_UNIT not read; `UNIT` cut at the first space (B line 18; S2 D2-6, R-A2L-030 "Partly"). **BL-I2-5** the tag table's decode ignores BIT_MASK (B line 16: 4660 for a field of 35); S2 has no row saying the table shows the field — propose one at the next unfreeze. **BL-I2-6** a CHARACTERISTIC whose name is on the line after `/begin` is named `UNKNOWN` (B line 23, V171's ASCII object), and an ASCII object decodes as one byte (B line 24). |
| `describe_curve_tag` (`a2l.py:2993`) | `S19TuiApp.action_a2l_describe_tag` (`app.py:9776`) | none in Inc 2 (its scalar header is the description window, R-A2L-118, unchanged). Inc 3 should reuse its R5 component walk for CURVE/MAP. | **BL-I2-9** its unit takes the method's unit before the tag's (`:3048`), the reverse of R-A2L-030/031 (S2 D2-6, R-A2L-032 "No"); a method with no unit hides the tag's UNIT. |
| `a2l_data["sections"]` (`parse_a2l_file` payload) | every A2L consumer | read by the model for the method record, the enum tables and the object's FORMAT / EXTENDED_LIMITS / PHYS_UNIT / BIT_MASK lines (R-A2L-DEF.10, .14 … .16, .18, .20 … .23) | **BL-I2-12** V171 parses with `Unclosed /begin sections detected.` (pilot transcript line 4); cause not investigated — the probed V171 objects all resolve. |
| `parse_parameter_list` (`a2l_parameter_picker.py:75`) | `BulkParameterAddScreen._apply_list` (`screens.py:1019`) | **none**: no Inc 2 row parses a label list; I-5 is unchanged and Inc 2 does not call it | **BL-I2-11** minor: the return annotation is `list`, not `list[str]`, and the docstring has no Data Flow / Dependencies sections (PROJECT_RULES). No functional defect found: an A2L identifier holds no space, comma or semicolon. |

Also read: `A2LParameterPicker.set_parameters` (`a2l_parameter_picker.py:526`) ← `CheckEditorPanel.set_a2l_parameters` (`screens_directionb.py:7303`), `PatchEditorPanel.set_a2l_parameters` (`:5388`) — the `u<bits>` format label (`:559`) is PE-D2, Inc 6's; it will read `datatype` from I-2.

**Backlog rows (ordered by consequence):** BL-I2-1 (BIT_MASK overwrite in the shared encode), BL-I2-5 (table shows the container for a masked tag), BL-I2-2 + BL-I2-16 (TAB_VERB and its table in the tag table: R-A2L-059 "No"), BL-I2-3 (commented method headers), BL-I2-4 + BL-I2-9 (units, R-A2L-030 … 032), BL-I2-6 (name on the next line; ASCII one byte), BL-I2-13 (deposit datatype), BL-I2-7 (FLOAT16), BL-I2-10 (R-A2L-051/052 wording, D-8), BL-I2-14 (STATUS_STRING_REF, DEFAULT_VALUE_NUMERIC), BL-I2-15 (publish the private helpers, D-9), BL-I2-12 (V171 unclosed section), BL-I2-8 and BL-I2-11 (annotations, docstrings). All need an `a2l.py` unfreeze except BL-I2-11.

## 6. Real A2L shapes checked (beyond the synth)

`evidence-e1/i2e1-a2l-shapes.txt`, over the 35 tracked `.a2l` files:
- **Enums:** TAB_VERB on 378 lines in 10 files; COMPU_VTAB in 9 files (107); COMPU_VTAB_RANGE in 4 files (98 lines; 69 range tables in software_a); DEFAULT_VALUE on 272 lines. Header shapes: V171 (long identifier and `TAB_VERB 3` on their own body lines), a2ltool 1.60 (`/begin COMPU_VTAB name "desc" TAB_VERB 5` on one line), BalanceTube (`/* type */ TAB_VERB`, one keyword per commented line).
- **BIT_MASK** on 272 lines in 10 files; software_a's masks include single bits (0x80, 0x40, …), runs (0x3, 0x3FF, 0xF0) and 0xFFFFFF on ULONG; V171 puts three masked objects on one word (0x810002: 0xFFFF, 0x0FF0, 0x0001, 0x0010).
- **FORMAT** on 5 116 lines; the strings include `%.15` (4 975, the a2ltool default), `%` (11), `%0.0`, `%3.12` (decimals above the length), `%17.15`; case 08 writes `%.0f` / `%.1f` (a trailing `f`). The display-format grammar of CTX-A2L-DEF reads all of them.
- **EXTENDED_LIMITS** (78 lines, 2 files), **PHYS_UNIT** (151, 2), ASCII objects with NUMBER in 6 files; ENCODING, BIT_OPERATION 0.

## 7. What E1 could not check

- The ASAM MCD-2 MC standard text (D-4's float range end; D-12's terminator reading): not available offline; marked as assumptions.
- `encode_physical_to_raw_bytes` for every reason: B checked four (lines 26-31); the others are read in the code (`a2l.py:2106-2192`, `:2495-2556`) and get their own E4 cases (R-A2L-DEF.42/1 … /11).
- The 10 MiB pin on Windows (CR LF): the threshold reads CR LF as LF; no Windows run was made (Windows runs are not allowed here).
- `trace_check.py` on this increment: it needs `04-validation.md` and tests, so it runs at E5.

## Orchestrator rulings (2026-11-06T16:18:57-06:00, Opus 5.5)

All recommendations accepted: D-1 A (I-2 as written, `Refusal` value), D-2 A, D-3 A, D-4 A (E3 checks the COMPU_VTAB_RANGE upper-end rule; if unsure, the row states the rule the system applies), D-5 A (`--case definitions`, case 08 untouched and hash-pinned), D-6 A, D-7 A, D-8 A, D-9 A (rename guard test), D-10 A, D-11 A (S2.7 "A value by its A2L definition"), D-12 A (E3 reviews the texts), D-13 no split. The 16 defects of §5 go to the batch backlog; the BIT_MASK whole-word write is ranked first (no product caller today; Inc 8 must not use that encode for masks). Inc 3 continues at R-A2L-DEF.64.
