# Code-Wire graph — Inc 2 (A2L definition model I: scalar kinds), batch-103

Stage E2 of the design-first flow (`dev-flow-v3-beta`). Graph only: no stub, mark or declaration in any tree. Base `batch-103` at `28757a9` (product tree `e07fb00`). Requirements `../01-requirements.md` (R-A2L-DEF.1 … .63), cases `../02-test-cases.md`, rulings `../E1-rulings.md` (orchestrator rulings at its end: D-1 A … D-13, all accepted), slice `../E1-slice.md`, plan `../../PLAN.md` (I-2, A1). Notation: Code-Wire v3.1.0 (`e436a08`, `docs/Notation-Grammar.md`), as in batch-101's `inc-12/codewire/graph-inc12.md`.

How to read it:
- One file holds the baseline and the prototype. Every node's `func:` starts with **unchanged** (baseline context: a new node calls it, or it is the oracle of a row), **changed** ("was: … / now: …") or **new**. `a2l.py` is frozen: no node of it changes.
- Example sources are the case ids of `02-test-cases.md` (`R-A2L-DEF.N/k`, `R-A2L-0NN/def-k`, `AT-B103-I2-k`). Evidence: **B2** = this stage's probe (`evidence-e2/i2e2-probe-transcript.txt`, tag `[P…]`), **B2b** = probe 2 (`evidence-e2/i2e2-probe2-transcript.txt`), **C2** = this stage's caller census (`evidence-e2/i2e2-extract-census-transcript.txt`), **B1** / **C1** = the E1 pilot and census (`../evidence-e1/`), **R** = read in the code at `e07fb00`. All runs: LAN host cachyos-rtx, Python 3.11.18, read-only clone at `e07fb00`, isolated HOME/XDG/LOCALAPPDATA, no display, no clipboard.
- Fixtures as in `02-test-cases.md`: **V171** (little-endian, MOD_COMMON `MSB_LAST`), **SOFTA**, **TUBE**, **C08** (1 MiB, seed 20260001), **DEFC** (the definitions case, pinned below), **INLINE** (big-endian). An image is an address → byte mapping; "image 34 12 at 0x810002" means those two bytes there and nothing else unless stated.
- Every example states the Inc 2 target. "holds on base" marks a baseline fact.
- An example whose E1 case input or expectation could not hold is written with the corrected input and listed in `## Findings` (E2-3 … E2-8); the case text itself is E1's to correct.

### Groups for E4 (file ownership)

| Group | Files | Owns nodes |
|---|---|---|
| G1 model | `s19_app/tui/a2l_definition.py` (new); tests `tests/test_b103_a2l_definition.py` (tester G-T1: S2.7a … c, the cited rows, AT-B103-I2-1, -3, the D-9 rename guard) | the 22 nodes of module `s19_app/tui/a2l_definition.py` |
| G2 synth | `tools/synth/make_release_case.py` (changed, additive); tests `tests/test_b103_synth_definitions_case.py` (tester G-T2: S2.7d, AT-B103-I2-2) | `build_definition_objects`, `emit_definitions_a2l`, `generate_definitions_case`, `main` |

**One implementer covers G1 and G2** (operator brief for this increment): the synth part is 4 nodes and shares no code with the module — no G2 node imports `s19_app`, no G1 node imports the generator. The only seam is test data: AT-B103-I2-2 and R-A2L-DEF.60 … .62 read the DEFC object list (keys pinned under I-D below) and parse DEFC's files with the app's loaders. Testers split by group as usual.

### Interfaces — pinned here, changed only by an orchestrator ruling

**I-2 (produced by Inc 2; E1-rulings §4, ruled D-1 A).** Module `s19_app/tui/a2l_definition.py`; imports the standard library and `s19_app.tui.a2l` only; no `textual`, no file or clipboard I/O; never raises on file or image content (every failure is a `Refusal` value). Exactly:

```text
Refusal(code: str, message: str)                                    frozen dataclass
Limits(lower: float | None, upper: float | None,
       lower_text: str, upper_text: str)                            frozen dataclass
EnumEntry(raw: float, raw_max: float | None, text: str)            frozen dataclass; raw_max None for a COMPU_VTAB pair
Definition(                                                         frozen dataclass, fields in this order
    name: str, section: str, char_type: str | None,
    kind: str,
    address: int | None, byte_length: int | None,
    datatype: str | None, byte_order: str,
    bit_mask: int | None, bit_mask_text: str | None,                 <- bit_mask_text: PROPOSED P-1
    conversion_type: str | None, method_name: str | None,
    display_format: str | None, decimals: int | None, unit: str,
    limits: Limits, extended_limits: Limits | None,
    enum_table: str | None, enum_entries: tuple[EnumEntry, ...], default_text: str | None,
    refusal: Refusal | None)
Decoded(stored: int | float | None, value: int | float | str | None, text: str)      frozen dataclass
Encoded(address: int, data: bytes, notices: tuple[str, ...])                          frozen dataclass

describe_definition(name: str, a2l_data: dict) -> Definition
decode_definition(definition: Definition, a2l_data: dict, image: Mapping[int, int]) -> Decoded | Refusal
encode_definition(definition: Definition, a2l_data: dict, text: str, image: Mapping[int, int]) -> Encoded | Refusal
display_text(definition: Definition, value: int | float) -> str
```

Values pinned by this graph (meanings the §4 text left open; no name or type changes):
- `kind` is `"number"`, `"enum"` or `"text"`; it is `""` on a definition refused `A2L-DEF-NAME` or `A2L-DEF-KIND` (no scalar kind applies). Inc 3 replaces `""` by its kinds for the objects it adds.
- `section` is `"MEASUREMENT"` or `"CHARACTERISTIC"`, `""` for `A2L-DEF-NAME`. `byte_order` is `"big"` or `"little"` (`"little"` for `A2L-DEF-NAME`, R-A2L-027).
- `Limits.lower_text` / `upper_text` hold the word as the file writes it when `_to_float` reads it as a number, else `""` — so a message composes `<lower>..<upper>` from them directly (R-A2L-DEF.43/3 `..100`). No limit words: `Limits(None, None, "", "")`.
- `method_name` is the conversion word of the object (`"NO_COMPU_METHOD"` included); `conversion_type` is the record's type word, `None` for `NO_COMPU_METHOD` and for a record with no type word.
- `decimals` is the display format's decimals capped at 17 (R-A2L-DEF.36), `None` when it gives none.
- `Decoded`: number → `stored` the stored value (the masked field under a bit mask), `value` the physical value, `text` = `display_text(definition, value)`; enum → `stored` the stored value, `value` the matched entry's text or `None`, `text` the display text (entry, default, or `<raw> (no text)`); text → `stored` `None`, `value` and `text` the decoded string.
- `Encoded.address` = `definition.address`; `data` = the whole span (`byte_length` bytes); `notices` = the R-A2L-DEF.44 notice when one applies, else `()`.
- Refusal codes (stable for tests): `A2L-DEF-NAME`, `-KIND`, `-ADDRESS`, `-DATATYPE`, `-LENGTH`, `-METHOD`, `-CONVERSION`, `-TABLE`, `-TABLE-EMPTY`, `-MASK` (describe); `-BYTES`, `-DECODE` (decode); `-NUMBER`, `-ENCODE`, `-LIMITS`, `-EXTENDED`, `-MASK-VALUE`, `-ENUM`, `-TEXT-LENGTH`, `-TEXT-CHAR`, `-PRECISION` (encode; `-BYTES` too). Messages are the rows' texts exactly.

**P-1 PROPOSED (needs an orchestrator ruling; the graph is written for it).** `Definition` gains `bit_mask_text: str | None` right after `bit_mask`: the BIT_MASK word as the file writes it. Reason: the encode refusal `A2L-DEF-MASK-VALUE` (R-A2L-DEF.47) names `<mask>` "as the file writes it" (`0x0FF0`, `0x00F0`, `0x0A`), and the encode holds only the definition; the integer cannot give the text back (`BIT_MASK 16` vs `0x10`, `0x0FF0` vs `0xFF0`). Consumers read fields by name and never construct a `Definition`, so the position does not reach them. Alternative if refused: print `<mask>` as `0x` + the hex digits of the datatype's width (holds for every .47 case, not for a decimal mask) and amend the placeholder.

**How Inc 3 extends I-2 without changing what Inc 2 defines.**
- `Definition` gains fields **with defaults, after `refusal`** (`elements`, `axes`, `shape`, as §4 names them); no Inc 2 field changes name, type, order or meaning. `Decoded` / `Encoded` likewise only gain defaulted fields.
- `kind` gains Inc 3's values; `"number"`, `"enum"`, `"text"` keep their meaning, and each element of an Inc 3 object follows the scalar rules of this graph.
- Inc 3 adds its kinds to CTX-A2L-DEF's *defined object* list; `A2L-DEF-KIND` and its message `<name>: the system has no definition for a <kind> object` stay for every kind still outside it. Inc 3 inserts its own checks into the refusal order without reordering Inc 2's codes.
- New functions decode or encode one element or axis; the four I-2 functions keep their signatures; `display_text` stays the one number display rule (Inc 3 calls it per element). Inc 3 reuses the private helpers of this module freely; they are not part of I-2.
- Inc 6 reads `byte_length`, `datatype` and `kind` even from a refused definition (this graph fills them for every refusal but `A2L-DEF-NAME`; a VAL_BLK reads `kind` `""` until Inc 3). Inc 8 and Inc 9 call `describe_definition` once per edited parameter, `decode_definition` to show it, `encode_definition` to stage it; they never call `a2l.encode_physical_to_raw_bytes` for a masked object (ruling: the BIT_MASK whole-word write, BL-I2-1).
- Cost (B2 P4g): `describe_definition` walks the section tree about four times (one object walk, one method lookup, up to two table lookups); on software_a (13 990 tags) one walk costs 3.9 – 9.1 ms, so one call costs about 20 ms. A consumer must not call it for every row of a whole A2L (14 000 × 20 ms ≈ 5 min). Recorded as finding E2-10 for E3 and for Inc 6.

**I-5** (label-list parser): not consumed and not changed by Inc 2 (`parse_parameter_list` is baseline context only).

**I-D (G2 → the testers, test data only).** The DEFC object list (`build_definition_objects` output) has one dict per object with the keys of case 08's list (`name`, `section`, `kind`, `datatype`, `conversion`, `address`, `length`, `big_endian`, `raw_bytes`, `physical`, `low`, `high`) plus `bit_mask` (`int` or `None`), `planned_stored` and `planned_text` (the display text the model must give for the planned bytes). The files are `firmware.s19` and `firmware.a2l` in `--out`.

### The definitions case (DEFC), pinned (D-5 A, D-6 A; R-A2L-DEF.60 … .63)

One calibration region of 256 bytes at `0x00800000` (`CAL_BASE`); the other three region keys hold empty byte arrays so the existing `emit_s19` writes the case unchanged (E2-15). Draw order from `random.Random(seed)`, pinned: (1) the 256 fill bytes, `rng.randrange(256)` each, in address order; (2) the enum's raw, `rng.choice([0, 1, 2, 3])`; (3) the one-bit field, `rng.randrange(2)`; (4) the multi-bit field, `rng.randrange(256)`; (5) the display object's raw, `rng.randint(-80, 300)`. Then the planned bytes overlay the fill. With seed 20260001 (B2 P8, a simulation of this order): enum raw `1`, bit `1`, field `174`, display raw `287` (physical `143.5`); the fill word at +0x10 is `0x1787`, the planned word `0x1AE7` (bytes `1a e7`), the display bytes `01 1f`.

```text
ASAP2_VERSION 1 71
/begin PROJECT SYNTH_DEFINITIONS_DEMO "Synthetic definitions demo project"
  /begin MODULE ECU_DEFINITIONS "Synthetic definitions demo module"
    /begin MOD_COMMON ""
      BYTE_ORDER MSB_FIRST
      ALIGNMENT_BYTE 1
      ALIGNMENT_WORD 2
    /end MOD_COMMON
    /begin MEMORY_SEGMENT cal DATA FLASH INTERN FLASH 0x00800000 0x000100
    /end MEMORY_SEGMENT
    /begin RECORD_LAYOUT RL_U8            FNC_VALUES 1 UBYTE COLUMN_DIR DIRECT   (one line each, as case 08)
    /begin RECORD_LAYOUT RL_U16           FNC_VALUES 1 UWORD COLUMN_DIR DIRECT
    /begin RECORD_LAYOUT RL_S16           FNC_VALUES 1 SWORD COLUMN_DIR DIRECT
    /begin COMPU_METHOD CM_DEF_ENUM "synthetic verbal conversion"   TAB_VERB "%.0" ""   COMPU_TAB_REF VT_DEF_STATE
    /begin COMPU_VTAB VT_DEF_STATE "synthetic states" TAB_VERB 4
      0 "OFF"   1 "IDLE"   2 "RUN"   3 "FAULT"   DEFAULT_VALUE "UNKNOWN_STATE"     (one pair per line)
    /begin COMPU_METHOD CM_DEF_IDENT "synthetic IDENTICAL conversion"   IDENTICAL "%.0" ""
    /begin COMPU_METHOD CM_DEF_LIN "synthetic LINEAR conversion"   LINEAR "%.3" "units"   COEFFS_LINEAR 0.5 0
    /begin CHARACTERISTIC ENUM_0001 "synthetic enum"             VALUE 0x00800000 RL_U8 0 CM_DEF_ENUM 0 3
    /begin CHARACTERISTIC MASK_BIT_0001 "synthetic one-bit field"     VALUE 0x00800010 RL_U16 0 CM_DEF_IDENT 0 1      BIT_MASK 0x0001
    /begin CHARACTERISTIC MASK_FIELD_0001 "synthetic multi-bit field" VALUE 0x00800010 RL_U16 0 CM_DEF_IDENT 0 255    BIT_MASK 0x0FF0
    /begin CHARACTERISTIC DISPLAY_0001 "synthetic display object"     VALUE 0x00800020 RL_S16 0 CM_DEF_LIN -40 150
      EXTENDED_LIMITS -50 200   FORMAT "%.1"   PHYS_UNIT "deg C"                  (one keyword per line)
  /end MODULE
/end PROJECT
```

(The block shows the content; every `/begin` has its `/end` and every keyword its own line in the written file. Planned texts: `ENUM_0001` → `IDLE`, `MASK_BIT_0001` → `1`, `MASK_FIELD_0001` → `174`, `DISPLAY_0001` → `143.5`.) Inc 3 adds COM_AXIS objects to the same case.

### Coverage — every requirement → nodes and examples

Every row has at least one concrete example; none is uncovered. Example ids are the case ids written on the nodes' `examples:` lines.

| Rows | Nodes | Examples |
|---|---|---|
| R-A2L-DEF.1 | `describe_definition`, `_object_kind` | .1/1 … /4 |
| R-A2L-DEF.2 | `describe_definition`, `_object_kind`, `_read_method_record`, `_read_object_lines` (TUBE fill) | .2/1 … /3 |
| R-A2L-DEF.3 | `_object_kind`, `describe_definition` | .3/1, /2 |
| R-A2L-DEF.4 | `_object_kind`, `describe_definition` | .4/1 … /7 |
| R-A2L-DEF.5, .6 | `_find_tag`, `describe_definition` | .5/1, /2; .6/1, /2 |
| R-A2L-DEF.7 | `describe_definition` | .7/1, /2 |
| R-A2L-DEF.8, .9 | `_resolve_datatype`, `describe_definition` | .8/1, /2 (corrected, E2-6); .9/1 |
| R-A2L-DEF.10 … .12 | `_read_method_record`, `describe_definition` | .10/1 … /4; .11/1; .12/1 … /3 |
| R-A2L-DEF.13 … .17 | `_read_enum_table`, `describe_definition` | .13/1, /2; .14/1 … /3; .15/1, /2; .16/1, /2; .17/1, /2 |
| R-A2L-DEF.18, .19 | `_read_object_lines`, `_check_bit_mask`, `describe_definition` | .18/1 … /3 (/3 corrected, E2-4); .19/1 … /3 |
| R-A2L-DEF.20 … .23 | `_read_object_lines`, `_display_decimals`, `describe_definition` | .20/1, /2; .21/1, /2; .22/1, /2; .23/1, /2 |
| R-A2L-DEF.24, .25 | `describe_definition`, `decode_definition`, `encode_definition` | .24/1 … /3; .25/1, /2 |
| R-A2L-DEF.26, .27 | `_read_stored_value`, `_merge_bit_mask` | .26/1, /2; .27/1 … /3 |
| R-A2L-DEF.28 | `decode_definition` | .28/1, /2, /3 (corrected, E2-5) |
| R-A2L-DEF.29 … .32 | `_enum_text` | .29/1; .30/1 … /4; .31/1, /2; .32/1, /2 |
| R-A2L-DEF.33, .34 | `_ascii_text`, `decode_definition` | .33/1 … /3; .34/1, /2 |
| R-A2L-DEF.35 … .39 | `display_text`, `_display_decimals` | .35/1 … /4; .36/1; .37/1 … /4; .38/1 (corrected, E2-4), /2; .39/1 … /3 |
| R-A2L-DEF.40 | `_parse_number_text`, `encode_definition` | .40/1 … /7 |
| R-A2L-DEF.41, .42 | `_encode_number`, `encode_definition` | .41/1 … /6 (/4 and /6 corrected, E2-7); .42/1 … /11 |
| R-A2L-DEF.43 … .45 | `_check_limits` | .43/1 … /4; .44/1, /2; .45/1, /2 |
| R-A2L-DEF.46, .47 | `_merge_bit_mask`, `encode_definition` | .46/1 … /3; .47/1 … /3 |
| R-A2L-DEF.48, .49 | `_encode_enum` | .48/1 … /3; .49/1 … /3 |
| R-A2L-DEF.50 … .52 | `_encode_ascii` | .50/1 … /3; .51/1; .52/1 … /3 |
| R-A2L-DEF.53 | `encode_definition` | .53/1 … /4 |
| R-A2L-DEF.54, .55 | `encode_definition`, `_agrees_at_display_precision` | .54/1, /2; .55/1 |
| R-A2L-DEF.56 | `encode_definition`, `decode_definition` | .56/1 |
| R-A2L-DEF.57 | `encode_definition` | .57/1 … /3 |
| R-A2L-DEF.58 | `describe_definition`, `decode_definition`, `encode_definition` | .58/1, /2 |
| R-A2L-DEF.59 | `main`, `generate` | .59/1, /2 |
| R-A2L-DEF.60 … .62 | `build_definition_objects`, `emit_definitions_a2l` | .60/1; .61/1; .62/1 |
| R-A2L-DEF.63 | `generate_definitions_case`, `main` | .63/1 |
| cited R-A2L-010, 011, 022 … 027, 030, 031, 033 | `describe_definition`, `_resolve_datatype`, `_read_object_lines`, `_read_method_record` | each row's `/def-k` |
| cited R-A2L-040, 043 … 045 | `_read_stored_value` | each row's `/def-k` |
| cited R-A2L-051, 053 … 058.3, 061 … 063, 059 | `decode_definition`, `_enum_text` | each row's `/def-k` (058.3 corrected, E2-5) |
| cited R-A2L-014 (PROPOSED, E2-1) | `describe_definition` | TUBE fill |
| AT-B103-I2-1 … -3 | the four I-2 nodes; G2 for -2 | AT-B103-I2-1 (corrected expectation, E2-8), -2, -3 |

**Node count:** 40 nodes in this graph — 25 new (22 in `a2l_definition.py`, 3 in the synth), 1 changed (`main`), 0 removed, 14 unchanged context (10 of `a2l.py`, 1 of `a2l_parameter_picker.py`, 3 of the synth: `generate`, `emit_s19`, `_pack_scalar`). The slice (new + changed) is 26, as E1 counted; under the cap of 40. Entities 10, edges 14.

**Checked against the base code** (`evidence-e2/i2e2-extract-check-transcript.txt`): the Code-Wire v3.1.0 extractor over a throwaway copy of `e07fb00` with a mark on each of the 15 existing nodes (the 14 unchanged ones and `main`) and `--path` on the four files → `0` contract drifts (inputs, types, defaults, outputs, modules all match); the `25` findings are all "Graph node without mark (no code yet)", the 25 new nodes — so the run exits 1 until E4 writes them, as the method expects. `codewire_lint.py` on this file (`evidence-e2/i2e2-lint-transcript.txt`): `nodes=40 entities=10 edges=14 findings=15 not read=0`. Real callers: `evidence-e2/i2e2-extract-census-transcript.txt` (every def of the copy marked, base line numbers).

## Nodes

describe_definition
req: R-A2L-DEF.1, R-A2L-DEF.2, R-A2L-DEF.3, R-A2L-DEF.4, R-A2L-DEF.5, R-A2L-DEF.6, R-A2L-DEF.7, R-A2L-DEF.8, R-A2L-DEF.9, R-A2L-DEF.11, R-A2L-DEF.12, R-A2L-DEF.13, R-A2L-DEF.17, R-A2L-DEF.19, R-A2L-DEF.23, R-A2L-DEF.24, R-A2L-DEF.58, R-A2L-010, R-A2L-011, R-A2L-014, R-A2L-022, R-A2L-023, R-A2L-024, R-A2L-025, R-A2L-026, R-A2L-027, R-A2L-030, R-A2L-031
in: str name; dict a2l_data
out: Definition definition
func: new (I-2 entry). `_find_tag(name, a2l_data)`; none → refused `A2L-DEF-NAME` `<name>: no tag of that name in the A2L` (other fields empty, `kind` `""`). Else reads every field it can: the object record (`_read_object_lines(section)`); for a MEASUREMENT whose tag lacks them, the header words fill `datatype`, the conversion word, the limit words and, with a datatype, the length = size × MATRIX_DIM (1 when absent) (E2-1; R-A2L-014); `address` and `byte_length` from the tag; `datatype` = `_resolve_datatype`; `byte_order` = the tag's `effective_byte_order` (R-A2L-024 … 027 as the tag table applies them); `method_name` = the tag's conversion word; the record `_read_method_record(method_name, sections)` unless `NO_COMPU_METHOD`; `conversion_type` = its type word; `kind` = `_object_kind`; `display_format` = the object's FORMAT word, else the record's format (R-A2L-DEF.22, .23); `decimals` = `_display_decimals`; `unit` = the object's first PHYS_UNIT or UNIT word, else the record's unit, else `""`; `limits`, `extended_limits` (two number words, else `None`); for kind number or enum `bit_mask` = the BIT_MASK word read as `0x` + hex digits or decimal digits (E2-12), `bit_mask_text` = the word; for kind enum `enum_table` = the record's COMPU_TAB_REF word and `_read_enum_table(enum_table, sections)` → `enum_entries`, `default_text`. Then the first refusal of the refusal order: kind → `A2L-DEF-KIND` `<name>: the system has no definition for a <kind> object`; no address or no length → `A2L-DEF-ADDRESS` `<name>: the object has no address or no length`; number/enum without a datatype → `A2L-DEF-DATATYPE` `<name>: the object declares no datatype the system can read`; number/enum length ≠ the datatype's size → `A2L-DEF-LENGTH` `<name>: its length <length> differs from the <size> bytes of <datatype>`; a method other than `NO_COMPU_METHOD` with no record → `A2L-DEF-METHOD` `<name>: the conversion method <method> is not declared in the A2L`; a type outside IDENTICAL, LINEAR, RAT_FUNC, TAB_INTP, TAB_NOINTP, TAB_VERB (FORM, unknown, none) → `A2L-DEF-CONVERSION` `<name>: the conversion type <type> of <method> is not supported` (`<type>` `(none)` for no word); enum with no table word or no such COMPU_VTAB / COMPU_VTAB_RANGE → `A2L-DEF-TABLE` `<name>: the table <table> of <method> is not declared in the A2L` (`<table>` `(none)`); enum with no entries → `A2L-DEF-TABLE-EMPTY` `<name>: the table <table> has no entries`; `_check_bit_mask` false → `A2L-DEF-MASK` `<name>: the bit mask <mask> cannot be applied to <datatype>`. Reads `a2l_data` and never writes it (the tag is copied before the MEASUREMENT fill).
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.1/1, R-A2L-010/def-1, R-A2L-022/def-1, R-A2L-026/def-1) V171 `ASAM.C.SCALAR.SWORD.IDENTICAL` → kind `number`, address `0x810004`, byte length `2`, datatype `SWORD`, byte order `little`, method `CM.IDENTICAL`, conversion type `IDENTICAL`, display format `%3.0`, unit `hours`, limits `-10000`..`20000`, extended `-32268`..`32267`, refusal `None` (B2 P2, P3)
examples: (R-A2L-DEF.1/2, R-A2L-011/def-1, R-A2L-DEF.22/2) V171 `ASAM.M.SCALAR.UBYTE.IDENTICAL` → kind `number`, section `MEASUREMENT`, address `0x13A00`, datatype `UBYTE`, display format `%5.0` (the FORMAT word, its trailing comment left out)
examples: (R-A2L-DEF.1/3) SOFTA `AAB_CHYEAQ1_DXZTD_NLPMJIM_2_IGTLL_AWV_CHZTO.SwaxfqdawbZkcwtx` (MEASUREMENT, `UWORD NO_COMPU_METHOD`) → kind `number`, method `NO_COMPU_METHOD`, conversion type `None`, refusal `A2L-DEF-ADDRESS` `AAB_CHYEAQ1_DXZTD_NLPMJIM_2_IGTLL_AWV_CHZTO.SwaxfqdawbZkcwtx: the object has no address or no length` (no software_a MEASUREMENT has an address: 0 of 10 538, B2 P4h; E2-4)
examples: (R-A2L-DEF.1/4, R-A2L-024/def-1) C08 clean `VALUE_0001` → kind `number`, address `0x0`, datatype `UBYTE`, byte order `big`, refusal `None`
examples: (R-A2L-DEF.2/1, R-A2L-DEF.10/1, R-A2L-DEF.14/1, R-A2L-DEF.16/1) V171 `ASAM.C.SCALAR.SWORD.TAB_VERB_DEFAULT_VALUE` → kind `enum`, conversion type `TAB_VERB`, enum table `CM.TAB_VERB.DEFAULT_VALUE.REF`, entries (`1`, `SawTooth`), (`2`, `Square`), (`3`, `Sinus`) in that order, default text `unknown signal type`, refusal `None` (base: `conversion_type` None, B1 line 6)
examples: (R-A2L-DEF.2/2, R-A2L-DEF.10/3) SOFTA `ACN_ULWY.FVH_MUGP_O_SBW_RTD_NJZ_MKE_WODEYLMQXZ46_OXATIRMZ_YOQJZI` (VALUE at `0x0`, method `RKR_KC_VVOYJDA`, record `RKR_KC_VVOYJDA "" TAB_VERB …` on the /begin line) → kind `enum`, conversion type `TAB_VERB`, enum table `CXP_GM_YQTODIW` (a COMPU_VTAB_RANGE), entries (`0`..`0`, `xrbci`), (`1`..`1`, `buyz`), refusal `None` (B2 P4b, P4l)
examples: (R-A2L-DEF.2/3, R-A2L-DEF.10/4, R-A2L-DEF.23/2, R-A2L-014, E2-1) TUBE `model.MainClass.gameController.sm` (every header line commented; the tag table gives datatype `None`, conversion `None`, length `None`, B2 P1a) → the record words `UBYTE`, `esdl_model_GameControllerStatemachineStates`, `1`, `100.0`, `0`, `3` fill the tag → kind `enum`, datatype `UBYTE`, byte length `1`, address `0x0`, conversion type `TAB_VERB`, display format `%12.4`, entries (`0`, `Idle`), (`3`, `GameRunning`), (`2`, `NotInScoringZone`), (`1`, `IncreaseScore`), default text `Error`, limits `0`..`3`, refusal `None` (B2 P1b … P1e)
examples: (R-A2L-DEF.3/1) V171 `UNKNOWN` (the ASCII object at 0x810200, BL-I2-6) → kind `text`, byte length `42`, address `0x810200`, refusal `None`
examples: (R-A2L-DEF.3/2) C08 clean `ASCII_0001` → kind `text`, byte length `32`, address `0xC00000`
examples: (R-A2L-DEF.4/1) C08 clean `VAL_BLK_0001` → refusal `A2L-DEF-KIND` `VAL_BLK_0001: the system has no definition for a VAL_BLK object`; kind `""`, address `0x800000`, byte length `256`, datatype `UWORD`
examples: (R-A2L-DEF.4/2, /3) C08 `CURVE_0001` → `CURVE_0001: the system has no definition for a CURVE object` (address `0x803DE0`, byte length `64`); `MAP_0001` → `MAP_0001: the system has no definition for a MAP object` (`0x804EC0`, `128`)
examples: (R-A2L-DEF.4/4) V171 `ASAM.C.CUBOID.COM_AXIS.FIX_AXIS.STD_AXIS` → `ASAM.C.CUBOID.COM_AXIS.FIX_AXIS.STD_AXIS: the system has no definition for a CUBOID object` (B2 P2y)
examples: (R-A2L-DEF.4/5, /6) INLINE `MB` (MAP_BLOCK) → `MB: the system has no definition for a MAP_BLOCK object`; `VK` (kind `DIRECT_X` at 0x10) → `VK: the system has no definition for a DIRECT_X object`, address `0x10`
examples: (R-A2L-DEF.4/7) V171 `ASAM.M.MATRIX_DIM_16_1.UBYTE.IDENTICAL` → `ASAM.M.MATRIX_DIM_16_1.UBYTE.IDENTICAL: the system has no definition for a MATRIX_DIM 16 MEASUREMENT object`; address `0x13A30`, byte length `16`
examples: (R-A2L-DEF.6/1, /2) V171 `NO_SUCH_TAG` → refusal `A2L-DEF-NAME` `NO_SUCH_TAG: no tag of that name in the A2L`, kind `""`, address `None`; C08 clean `value_0001` → `value_0001: no tag of that name in the A2L`
examples: (R-A2L-DEF.7/1, /2) INLINE MEASUREMENT `NA` (UBYTE, no ECU_ADDRESS) → refusal `A2L-DEF-ADDRESS` `NA: the object has no address or no length`; ASCII `NL` at 0x10 (deposit `RL_U8`, no NUMBER/MATRIX_DIM/LENGTH) → `NL: the object has no address or no length`
examples: (R-A2L-DEF.8/1, /2, E2-6) INLINE VALUE `ND` at 0x10 with `LENGTH 2` whose RECORD_LAYOUT `RL_X` holds `FNC_VALUES 1 FOO ROW_DIR DIRECT` → refusal `A2L-DEF-DATATYPE` `ND: the object declares no datatype the system can read`; MEASUREMENT `NM` `FOO NO_COMPU_METHOD 0 0 0 1`, ECU_ADDRESS 0x10, `LENGTH 1` → `NM: the object declares no datatype the system can read` (without the LENGTH line both give `A2L-DEF-ADDRESS` first: no datatype, no length)
examples: (R-A2L-DEF.9/1) INLINE UWORD VALUE `LX` at 0x10 with `LENGTH 4` → refusal `A2L-DEF-LENGTH` `LX: its length 4 differs from the 2 bytes of UWORD`
examples: (R-A2L-DEF.11/1) C08 `firmware_issues.a2l` `MISSING_CM` → refusal `A2L-DEF-METHOD` `MISSING_CM: the conversion method CM_MISSING is not declared in the A2L`; datatype `UBYTE`, address `0xC00000` (base: identity, B1 lines 32, 34)
examples: (R-A2L-DEF.12/1 … /3) INLINE `FX` naming `CM_F` (`FORM "%.1" ""`) → `A2L-DEF-CONVERSION` `FX: the conversion type FORM of CM_F is not supported`; `QX` naming `CM_Q` (type `FOO`) → `QX: the conversion type FOO of CM_Q is not supported`; `EX` naming `CM_E` (`/begin COMPU_METHOD CM_E "d"`, nothing more) → `EX: the conversion type (none) of CM_E is not supported`
examples: (R-A2L-DEF.13/1, /2) INLINE `EN` naming `CM_V` (`TAB_VERB "%.0" ""`, no COMPU_TAB_REF) → `A2L-DEF-TABLE` `EN: the table (none) of CM_V is not declared in the A2L`; with `COMPU_TAB_REF VT_GONE` → `EN: the table VT_GONE of CM_V is not declared in the A2L`
examples: (R-A2L-DEF.17/1, /2) INLINE `E0` on `VT_0 "" TAB_VERB 0` → `A2L-DEF-TABLE-EMPTY` `E0: the table VT_0 has no entries`; `EN2` on `VT_N "" TAB_VERB X` then `0 "A"` → `EN2: the table VT_N has no entries`
examples: (R-A2L-DEF.18/3, E2-4) SOFTA `Adt_UhsihQwbpns._9_.NfwzbMcockRrbkj` (MEASUREMENT ULONG, `BIT_MASK 0xFFFFFF`) → bit mask `16777215`, bit mask text `0xFFFFFF`, refusal `A2L-DEF-ADDRESS` (not `A2L-DEF-MASK`); INLINE ULONG VALUE `M24` at 0x10 with `BIT_MASK 0xFFFFFF` → bit mask `16777215`, refusal `None` (no software_a object with that mask has an address, B2 P4j)
examples: (R-A2L-DEF.19/1 … /3) INLINE UWORD `M0` `BIT_MASK 0` → `A2L-DEF-MASK` `M0: the bit mask 0 cannot be applied to UWORD`; UBYTE `MW` `BIT_MASK 0x100` → `MW: the bit mask 0x100 cannot be applied to UBYTE`; FLOAT32_IEEE `MF` `BIT_MASK 0x1` → `MF: the bit mask 0x1 cannot be applied to FLOAT32_IEEE`
examples: (R-A2L-DEF.23/1, R-A2L-031/def-1) V171 `ASAM.C.SCALAR.UBYTE.IDENTICAL` (no FORMAT, no PHYS_UNIT; `CM.IDENTICAL` `%3.0` `hours`) → display format `%3.0`, unit `hours`, decimals `0`
examples: (R-A2L-DEF.24/1 … /3) INLINE MEASUREMENT `MA` (`MATRIX_DIM 4`, no ECU_ADDRESS) → `A2L-DEF-KIND`; MEASUREMENT `AM` (no ECU_ADDRESS, names `CM_GONE`) → `A2L-DEF-ADDRESS`; UBYTE VALUE `TM` naming `CM_V` (`COMPU_TAB_REF VT_GONE`) with `BIT_MASK 0` → `A2L-DEF-TABLE`
examples: (R-A2L-DEF.24/2 neg) mutant: the method checked before the address → `AM` gives `A2L-DEF-METHOD` → RED
examples: (R-A2L-023/def-1) INLINE VALUE `DS` with deposit `__SWORD_Z` and a RECORD_LAYOUT `__SWORD_Z` naming no datatype → datatype `SWORD` (the tag table's guess is `UWORD`, BL-I2-13)
examples: (R-A2L-025/def-1, R-A2L-027/def-1) INLINE VALUE on `RL_BL` (`BYTE_ORDER MSB_LAST`) → byte order `little`; INLINE with no BYTE_ORDER anywhere → `little`
examples: (R-A2L-030/def-1, /def-2) SOFTA `BcpGxvlbvneyoAudnMhl.DRCDJ_XNIFM_DSURLVD_VSJMQJBMW` (`PHYS_UNIT "V"`) → unit `V` (base: tag unit `None`, B2 P4f); INLINE `PHYS_UNIT "deg C"` → unit `deg C`
examples: (R-A2L-033/def-1) INLINE VALUE naming `/begin COMPU_METHOD CM_B "d" LINEAR "%.1" "km/h"` with `COEFFS_LINEAR 1 0` → unit `km/h`, display format `%.1`
examples: (R-A2L-DEF.58/1, /2) V171 and C08 clean: a deep copy of `a2l_data` taken before building every defined object equals `a2l_data` after → `True` (the MEASUREMENT fill works on a copy of the tag)

_find_tag
req: R-A2L-DEF.5, R-A2L-DEF.6
in: str name; dict a2l_data
out: tuple[dict, dict | None] | None found
func: new (D-10 A). The first tag of `a2l_data["tags"]` whose `name` equals `name`, case included, and its own section: the MEASUREMENT / CHARACTERISTIC section at the same position in file order (`_collect_sections_by_name` for both names, sorted by `start_line` — the order `extract_a2l_tags` walks); the section is `None` when that position's section names another object (`parse_begin_meta`). `None` when no tag has the name. Reads only.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.5/1) INLINE with two UWORD VALUEs `DUP` at 0x10 and 0x20 → the tag with address `0x10` and the section of the first `DUP`
examples: (R-A2L-DEF.5/1 neg) mutant: the last tag of the name → address `0x20` → RED
examples: (R-A2L-DEF.5/2, E2-9) C08 `firmware_issues.a2l` `VALUE_0001` (declared twice) → the first tag, address `0x0` (the duplicate has the same address `0x0`, B2 P5h, so this case cannot tell first from last; /1 carries the row)
examples: (R-A2L-DEF.6/2) C08 clean `value_0001` → `None` (B2 P5i: 0 tags of that spelling)
examples: (holds on base) the pairing: V171 `118` tags, `118` object sections, `118` with the same name at the same position; SOFTA `13990` of `13990`; TUBE `111` of `111` (B2 P0)

_object_kind
req: R-A2L-DEF.1, R-A2L-DEF.2, R-A2L-DEF.3, R-A2L-DEF.4
in: dict tag; str | None conversion_type
out: tuple[str | None, str] kind
func: new. `(kind, kind_text)`: a CHARACTERISTIC of `char_type` `ASCII` → (`text`, `ASCII`); `VALUE` → (`enum` when `conversion_type` is `TAB_VERB`, else `number`, `VALUE`); a MEASUREMENT whose `matrix_dim` is `None` or `1` → (`enum` / `number`, `MEASUREMENT`); every other object → (`None`, the `<kind>` text): the CHARACTERISTIC kind as the file writes it (`VAL_BLK`, `CURVE`, `MAP`, `CUBOID`, `MAP_BLOCK`, a vendor kind), `MATRIX_DIM <n> MEASUREMENT`, or `(none)` for a CHARACTERISTIC whose header gave no kind (E2-13).
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.1/2) MEASUREMENT, `matrix_dim` `None`, `IDENTICAL` → (`number`, `MEASUREMENT`)
examples: (R-A2L-DEF.2/1) VALUE, `TAB_VERB` → (`enum`, `VALUE`)
examples: (R-A2L-DEF.3/1) ASCII, `IDENTICAL` → (`text`, `ASCII`)
examples: (R-A2L-DEF.4/7) MEASUREMENT, `matrix_dim` `16` → (`None`, `MATRIX_DIM 16 MEASUREMENT`)
examples: (R-A2L-DEF.4/7 neg) mutant: every MEASUREMENT a scalar → `ASAM.M.MATRIX_DIM_16_1.UBYTE.IDENTICAL` kind `number` → RED

_resolve_datatype
req: R-A2L-DEF.8, R-A2L-DEF.9, R-A2L-022, R-A2L-023
in: dict tag; dict a2l_data
out: str | None datatype
func: new. The tag's `datatype` (MEASUREMENT header, DATA_TYPE line, or the E2-1 fill) when it is a key of `DATATYPE_SIZES`; else `_resolve_record_layout(record_layout_name, record_layouts_by_name)`'s `decode_type` when that word is in the layout's tokens (R-A2L-022); else the datatype the deposit name spells: the `DATATYPE_SIZES` key `<dt>` for which the upper-cased deposit holds `__<dt>_Z` or equals `<dt>` (R-A2L-023; wraps BL-I2-13, where the layout helper takes the first datatype of the same size); else `None`.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-022/def-1) V171 `ASAM.C.SCALAR.SWORD.IDENTICAL` (deposit `RL.FNC.SWORD.ROW_DIR`) → `SWORD` (B2 P2)
examples: (R-A2L-023/def-1) INLINE `DS`, deposit `__SWORD_Z`, layout naming no datatype → `SWORD` (the layout helper gives `UWORD`)
examples: (R-A2L-023/def-1 neg) mutant: the layout helper's guess kept → `UWORD`; the decode of FF FB shows `65531` → RED
examples: (R-A2L-DEF.38/1) SOFTA `AlyjmQyfk.GrsaEjbkyQmicdevPjq_GpqJraTjkq._1_` (deposit `__VBFES_C`, layout `SWORD`) → `SWORD` (B2 P4i)
examples: (R-A2L-DEF.8/2) INLINE MEASUREMENT `NM` with datatype `FOO` → `None`

_read_method_record
req: R-A2L-DEF.10, R-A2L-DEF.11, R-A2L-DEF.12, R-A2L-DEF.23, R-A2L-031, R-A2L-033
in: str method_name; list[dict] sections
out: dict | None record
func: new (D-2 A). The first COMPU_METHOD section in file order whose first record word is `method_name`, read as the *conversion method record*: the words of `_flatten_body_tokens([meta] + lines)` (comments left out, the /begin line's words first) — `<name> <long identifier> <type> <format> <unit>`, then the keyword groups `COEFFS` + 6 words, `COEFFS_LINEAR` + 2 words, `COMPU_TAB_REF` + 1 (a word that is not a number gives `None`, as `_to_float` reads it). Returns a dict of `extract_compu_methods`' keys (`name`, `long_identifier`, `conversion_type`, `format`, `unit`, `coeffs_linear`, `coeffs`, `compu_tab_ref`, `formula` `None`, `lines`) so `_apply_compu_method` and `encode_physical_to_raw_bytes` take it unchanged; a missing positional word is `None`. `None` when no section has the name.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.10/1) V171 `CM.TAB_VERB.DEFAULT_VALUE` (long identifier on its own line) → conversion type `TAB_VERB`, format `%12.0`, unit `""`, COMPU_TAB_REF `CM.TAB_VERB.DEFAULT_VALUE.REF` (B2 P3; base: `None`, B1 line 6)
examples: (R-A2L-DEF.10/2) V171 `CM.IDENTICAL` → `IDENTICAL`, format `%3.0`, unit `hours`
examples: (R-A2L-DEF.10/4) TUBE `esdl_model_GameControllerStatemachineStates` (`/* type */ TAB_VERB` …) → `TAB_VERB`, format `%12.4`, unit `""`, COMPU_TAB_REF `esdl_model_GameControllerStatemachineStates_vtab` (B2 P1c; the side table gives `None` for all four, B2 P1d)
examples: (R-A2L-DEF.10/1 neg) mutant: the type read per line from the first word (`a2l.py`'s) → `CM.TAB_VERB.DEFAULT_VALUE` type `None` → RED
examples: (R-A2L-055/def-1) INLINE `COEFFS_LINEAR 2` (one word) → coeffs_linear [`2.0`, `None`] (b missing → 0 in the conversion)
examples: (R-A2L-DEF.11/1) C08 issues `CM_MISSING` → `None`

_read_enum_table
req: R-A2L-DEF.13, R-A2L-DEF.14, R-A2L-DEF.15, R-A2L-DEF.16, R-A2L-DEF.17
in: str table_name; list[dict] sections
out: tuple[str, tuple[EnumEntry, ...], str | None] | None table
func: new (D-2 A, D-4 A). The first COMPU_VTAB or COMPU_VTAB_RANGE section in file order whose first record word is `table_name`, read as the *enum table* from its record words (`_flatten_body_tokens([meta] + lines)`): COMPU_VTAB `<name> <long id> TAB_VERB <n>` then pairs `<raw> <text>`; COMPU_VTAB_RANGE `<name> <long id> <n>` then triples `<min> <max> <text>`; entries read in file order, at most `n`, stopping at a `DEFAULT_VALUE` word or the end; an entry whose raw, min or max `_to_float` does not read is skipped; a count that is not a number gives no entries; the text is kept as text (never a float). The word after `DEFAULT_VALUE` is the default text. Returns (section kind, entries, default text), or `None` when no such section.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.14/1, R-A2L-DEF.16/1) V171 `CM.TAB_VERB.DEFAULT_VALUE.REF` → (`COMPU_VTAB`, (EnumEntry(`1.0`, `None`, `SawTooth`), EnumEntry(`2.0`, `None`, `Square`), EnumEntry(`3.0`, `None`, `Sinus`)), `unknown signal type`) (B2 P3)
examples: (R-A2L-DEF.14/2) SOFTA `zIzbovMkwaNungk_ZHDJ` (used by MEASUREMENT `QUUU_Ywjznkkjwj.AuooouPgqj`, refused `A2L-DEF-ADDRESS`) → first entry raw `-1.0`, text `NMUF_MSWGZ_SPTKAGRI` (B2 P4c)
examples: (R-A2L-DEF.14/3) INLINE `VT_A "" TAB_VERB 2` `2 "B"` `1 "10"` → entries (`2.0`, `B`), (`1.0`, `10`) in that order; the second text is the string `10`
examples: (R-A2L-DEF.14/3 neg) mutant: the side table (sorted by raw, numeric text as a float) → first raw `1.0`, text `10.0` → RED
examples: (R-A2L-DEF.15/1, R-A2L-DEF.16/2) V171 `CM.VTAB_RANGE.DEFAULT_VALUE.REF` → (`COMPU_VTAB_RANGE`, `11` entries, first EnumEntry(`0.0`, `1.0`, `Zero_to_one`), last EnumEntry(`105.0`, `105.0`, `hundredfive`)), default text `out of range value`
examples: (R-A2L-DEF.15/2) SOFTA the first range table `AET_ES_RLBM_AjzY.Ruffte_MG_WIN_JljHYWzox_RBR_2_Lolzhsf_RdzyhoEgzz.UQA_SscVOMjkb` → `5` entries, first (`0.0`, `0.0`, `BPQ_UQKPL_XLDM_EM_SPFMDDQDOEMCT`) (B2 P4d)
examples: (R-A2L-DEF.17/1, /2) INLINE `VT_0 "" TAB_VERB 0` → entries `()`; `VT_N "" TAB_VERB X` then `0 "A"` → entries `()`
examples: (R-A2L-DEF.13/2) INLINE `VT_GONE` → `None`

_read_object_lines
req: R-A2L-DEF.2, R-A2L-DEF.18, R-A2L-DEF.20, R-A2L-DEF.21, R-A2L-DEF.22, R-A2L-030
in: dict | None section
out: dict lines
func: new (D-2 A; extended at E2, E2-1). The *object record*: the words of `_flatten_body_tokens([meta] + lines)` of the object's section, comments left out. Gives `header` (the first 8 words of a MEASUREMENT: name, long identifier, datatype, conversion, resolution, accuracy, lower, upper; the first 9 of a CHARACTERISTIC: name, long identifier, kind, address, deposit, max diff, conversion, lower, upper), and, from the words after the header, the first of each: `format` (the word after FORMAT), `extended_limits` (the two words after EXTENDED_LIMITS when `_to_float` reads both, else `None`), `unit` (the word after the first PHYS_UNIT or UNIT, quotes left out, R-A2L-030), `bit_mask` (the word after BIT_MASK). Section `None` → every key empty. Child sections (IF_DATA, ANNOTATION, AXIS_DESCR) are not in the words.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.18/1) V171 `ASAM.C.SCALAR.UWORD.IDENTICAL.BITMASK_0FF0` → bit mask word `0x0FF0`, format `%5.0`, extended limits (`0`, `65535`) (B2 P2)
examples: (R-A2L-DEF.18/2) INLINE `MD` with `BIT_MASK 16` → bit mask word `16` (the definition: `16`)
examples: (R-A2L-DEF.20/1, R-A2L-DEF.22/1) V171 `ASAM.C.SCALAR.SBYTE.IDENTICAL` → extended limits (`-128`, `127`), format `%6.1` (the method's is `%3.0`)
examples: (R-A2L-DEF.20/2) V171 `ASAM.C.SCALAR.FLOAT64_IEEE.IDENTICAL` → extended limits (`-10000.0`, `20000.0`) (B2 P2z)
examples: (R-A2L-DEF.21/1, /2) INLINE `XL1` with `EXTENDED_LIMITS 0` (the next word is a keyword) → extended limits `None`; `XL2` with `EXTENDED_LIMITS a b` → `None`
examples: (R-A2L-DEF.22/2) V171 `ASAM.M.SCALAR.UBYTE.IDENTICAL` (`FORMAT "%5.0"    /* Note: … */`) → format `%5.0`
examples: (R-A2L-030/def-2) V171 `ASAM.C.SCALAR.UWORD.IDENTICAL.BITMASK_0001` (`PHYS_UNIT ""`) → unit `""` (the method's `hours` is not used)
examples: (E2-1) TUBE `model.MainClass.gameController.sm` → header words `UBYTE`, `esdl_model_GameControllerStatemachineStates`, `1`, `100.0`, `0`, `3` after the name and `""` (B2 P1b)

_check_bit_mask
req: R-A2L-DEF.19
in: int mask; str datatype
out: bool fits
func: new. True when `mask > 0`, the datatype is not FLOAT16_IEEE, FLOAT32_IEEE or FLOAT64_IEEE, and `mask < 1 << (8 × DATATYPE_SIZES[datatype])`. (E1's slice had it return the refusal; it returns the test and `describe_definition` writes the message, which needs the name and the mask word — E2-14.)
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.19/1) `0`, `UWORD` → `False`
examples: (R-A2L-DEF.19/2) `0x100`, `UBYTE` → `False`
examples: (R-A2L-DEF.19/2 neg) mutant: the bits at or above the width dropped (`mask & 0xFF`) → `0x100` on UBYTE accepted → RED
examples: (R-A2L-DEF.19/3) `0x1`, `FLOAT32_IEEE` → `False`
examples: (R-A2L-DEF.18/3) `0xFFFFFF`, `ULONG` → `True`; `0xFFFF`, `UWORD` (V171 `ASAM.C.SCALAR.UWORD.IDENTICAL`) → `True`

_display_decimals
req: R-A2L-DEF.35, R-A2L-DEF.36, R-A2L-DEF.37
in: str | None display_format
out: int | None decimals
func: new. Reads the *display format* `%[<length>][.<decimals>]` optionally ended by `f` (ASCII digits); gives `min(<decimals>, 17)`; `None` when the text gives no decimals or is not of that form.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.35/1) `%4.2` → `2`; (R-A2L-054/def-1) `%.1f` → `1`; `%0.0` → `0`
examples: (R-A2L-DEF.36/1) `%.40` → `17`
examples: (R-A2L-DEF.37/1 … /4) `None` → `None`; `%` → `None`; `%12` → `None`; `x5.1` → `None`

decode_definition
req: R-A2L-DEF.25, R-A2L-DEF.26, R-A2L-DEF.28, R-A2L-DEF.33, R-A2L-DEF.56, R-A2L-DEF.58, R-A2L-040, R-A2L-051, R-A2L-053, R-A2L-054, R-A2L-055, R-A2L-056, R-A2L-057, R-A2L-058.1, R-A2L-058.2, R-A2L-058.3, R-A2L-061, R-A2L-062, R-A2L-063
in: Definition definition; dict a2l_data; Mapping[int, int] image
out: Decoded | Refusal result
func: new (I-2). The definition's refusal when it has one (R-A2L-DEF.25). Else `_read_stored_value(definition, image)` (a refusal passes through). Text → `Decoded(None, s, s)` with `s = _ascii_text(raw)`. Enum → `Decoded(stored, the entry text or None, _enum_text(definition, stored))`. Number → `value = stored` for `NO_COMPU_METHOD`, else `_apply_compu_method(stored, the record, a2l_data["compu_tabs_by_name"], (limits.lower, limits.upper))` with the record of `_read_method_record`; a status `error` → `A2L-DEF-DECODE` `<name>: <conversion error>`; else `Decoded(stored, value, display_text(definition, value))`. Reads `image` and `a2l_data` only.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-040/def-1) V171 `ASAM.C.SCALAR.SWORD.IDENTICAL`, image 34 12 at 0x810004 → stored `4660`, text `4660`
examples: (R-A2L-044/def-1, R-A2L-053/def-1) the same, image FB FF → `-5`; image 07 00 → value `7`, text `7`
examples: (R-A2L-051/def-1) INLINE UBYTE `NO_COMPU_METHOD`, image 07 → value `7`
examples: (R-A2L-054/def-1) C08 clean `VALUE_0019` (UWORD, `CM_LIN_OFF`, big, at 0x40118) → stored `12830`, value `12930.0`, text `12930.0` (B2 P5n)
examples: (R-A2L-055/def-1) INLINE `COEFFS_LINEAR 2`, stored 3 → value `6.0`
examples: (R-A2L-056/def-1) C08 clean `VALUE_0004` (SLONG, `CM_RAT`, little, at 0x3C) → stored `510`, value `970.0`, text `970.0`
examples: (R-A2L-057/def-1) INLINE `CM(RAT_FUNC 1 0 0 0 0 1)`, limits 0..10, stored 9 → value `3.0`
examples: (R-A2L-061/def-1) C08 clean `MEASUREMENT_0001` (UWORD, `CM_TAB_INTP`, big, at 0x50) → stored `200`, value `20.0`, text `20.0`
examples: (R-A2L-062/def-1) the same with image 01 F4 (stored 500) → value `40.0`
examples: (R-A2L-063/def-1) C08 clean `MEASUREMENT_0002` (UWORD, `CM_TAB_NOINTP`, little, at 0x64), image 06 00 → value `20.0` (raw 4 nearest)
examples: (R-A2L-DEF.28/1, R-A2L-058.1/def-1) INLINE UWORD `R1` with `CM(RAT_FUNC 0 0 5 0 0 1)`, image 00 07 → refusal `A2L-DEF-DECODE` `R1: RAT_FUNC has no solution for this value`
examples: (R-A2L-DEF.28/2, R-A2L-058.2/def-1) `R2` with `CM(RAT_FUNC 1 0 1 0 0 1)`, image 00 00 → `R2: RAT_FUNC has no real root for this value`
examples: (R-A2L-DEF.28/3, R-A2L-058.3/def-1, E2-5) `R3` with `CM(RAT_FUNC 0 1 1 0 1 1)`, image 00 02 → `R3: RAT_FUNC root has a zero denominator` (B2b; the E1 input `0 1 0 0 1 0`, stored 1, gives `RAT_FUNC has no solution for this value`)
examples: (R-A2L-DEF.28/1 neg) mutant: the stored value shown as the value → `7` → RED
examples: (R-A2L-DEF.25/1) C08 issues `MISSING_CM`, the clean image → the `A2L-DEF-METHOD` refusal of R-A2L-DEF.11/1, no `Decoded`
examples: (R-A2L-DEF.25/1 neg) mutant: a refused definition decoded by identity → `Decoded` → RED
examples: (R-A2L-DEF.33/1) V171 `UNKNOWN`, image `Hello ASAM` + 32 × 00 at 0x810200 → `Decoded(None, "Hello ASAM", "Hello ASAM")`
examples: (R-A2L-DEF.33/2) C08 clean `ASCII_0001` → text `HW_REV=00.01.00.00` (B2 P5d)
examples: (R-A2L-059/def-1) V171 `ASAM.C.SCALAR.SWORD.TAB_VERB_DEFAULT_VALUE`, image 02 00 at 0x810004 → `Decoded(2, "Square", "Square")` (base: raw 2, unknown method, B1 line 11)
examples: (AT-B103-I2-3) C08 clean: every one of the `322` defined objects (B2 P5f) builds and decodes with `0` refusals; `firmware_issues.a2l`: `1` `A2L-DEF-METHOD` (`MISSING_CM`) at build and `5` `A2L-DEF-BYTES` at decode — `OUT_OF_RANGE_1: 1 of its 1 bytes are not in the image`, `OUT_OF_RANGE_2: …`, `OUT_OF_RANGE_3: …`, `SPAN_OVER_1: 2 of its 4 bytes are not in the image`, `SPAN_OVER_2: 3 of its 4 bytes are not in the image` (B2 P5g)

_read_stored_value
req: R-A2L-DEF.26, R-A2L-DEF.27, R-A2L-043, R-A2L-044, R-A2L-045
in: Definition definition; Mapping[int, int] image
out: int | float | bytes | Refusal stored
func: new. The span `address … address + byte_length − 1`: `n` addresses not in `image` → `A2L-DEF-BYTES` `<name>: <n> of its <length> bytes are not in the image`. Else the bytes (`image[a] & 0xFF`): kind text → the bytes; a bit mask → `(int.from_bytes(span, byte_order) & mask) >> shift`, unsigned (`shift` = the 0 bits below the lowest 1 bit); FLOAT16_IEEE → IEEE 754 binary16 (`struct` `e`; `_decode_scalar` gives `None`, BL-I2-7); else `_decode_scalar(span, datatype, byte_order)`.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.26/1) INLINE UWORD `MB2` at 0x10, image holds 0x10 only → `A2L-DEF-BYTES` `MB2: 1 of its 2 bytes are not in the image`
examples: (R-A2L-DEF.26/1 neg) mutant: a missing byte read as 0 → a stored value → RED
examples: (R-A2L-DEF.27/1, R-A2L-DEF.38/2) V171 `…BITMASK_0FF0`, image 34 12 at 0x810002 (word `0x1234`) → `35` (base: `4660`, B1 line 16)
examples: (R-A2L-DEF.27/1 neg) mutant: the shift taken from the highest mask bit → not `35` → RED
examples: (R-A2L-DEF.27/2) V171 `…BITMASK_0010`, image 10 00 → `1`
examples: (R-A2L-DEF.27/3) INLINE (big) SWORD `SM` mask `0xFF00`, image F0 F0 → `240` (the field is unsigned)
examples: (R-A2L-043/def-1) INLINE (big) UWORD, image 12 34 → `4660`
examples: (R-A2L-045/def-1 … /def-3) INLINE (big) FLOAT16_IEEE, image 3C 00 → `1.0` (base: `None`, B2 P6); FLOAT32_IEEE, image 3F C0 00 00 → `1.5`; FLOAT64_IEEE, image of −2.25 → `-2.25`
examples: (R-A2L-DEF.39/1 … /3) INLINE (big) FLOAT32 `F1`, image 7F C0 00 00 / 7F 80 00 00 / FF 80 00 00 → `nan` / `inf` / `-inf` as floats (B2 P7)

_enum_text
req: R-A2L-DEF.29, R-A2L-DEF.30, R-A2L-DEF.31, R-A2L-DEF.32, R-A2L-059
in: Definition definition; int | float stored
out: str text
func: new. The text of the first entry in file order that holds `stored`: a pair whose raw equals it, or a range with `min ≤ stored ≤ max` (both ends included; D-4 A, E3 to confirm the upper end). No entry → the default text when there is one, else `<raw> (no text)` with `<raw>` the integer text of an integral stored value, else its `%.15g` text.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.29/1) INLINE `VT_D` `1 "A"` `1 "B"`, stored 1 → `A`
examples: (R-A2L-DEF.29/1 neg) mutant: a dict built in file order (the last wins) → `B` → RED
examples: (R-A2L-DEF.30/1 … /4) V171 `…VTAB_RANGE_DEFAULT_VALUE`, stored 0 → `Zero_to_one`; 1 → `Zero_to_one`; 5 → `four_to_seven`; 100 → `hundred`
examples: (R-A2L-DEF.30/2 neg) mutant: the max excluded → stored 1 gives `out of range value` → RED
examples: (R-A2L-DEF.31/1, /2) V171 `…TAB_VERB_DEFAULT_VALUE`, stored 9 → `unknown signal type`; `…VTAB_RANGE_DEFAULT_VALUE`, stored 10 → `out of range value`
examples: (R-A2L-DEF.32/1, /2) V171 `…TAB_VERB_NO_DEFAULT_VALUE` (entries 2 … 7), stored 1 → `1 (no text)`; `…VTAB_RANGE_NO_DEFAULT_VALUE`, stored 10 → `10 (no text)`
examples: (R-A2L-059/def-2) INLINE (big) UWORD enum `ME` with `BIT_MASK 0x00F0` on `VT_M` (`0 "OFF"`, `1 "ON"`), image 00 10 → stored `1` → `ON`

_ascii_text
req: R-A2L-DEF.33, R-A2L-DEF.34
in: bytes raw
out: str text
func: new. The bytes before the first 0x00 (all of them when none is 0x00), each 0x20 … 0x7E as its ASCII character and every other byte as U+FFFD.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.33/1) `Hello ASAM` + 32 × 00 → `Hello ASAM`
examples: (R-A2L-DEF.33/3) 42 × 0x41 → 42 × `A`
examples: (R-A2L-DEF.33/1 neg) mutant: the 0x00 bytes kept → a 42-character text → RED
examples: (R-A2L-DEF.34/1) 41 42 07 43 00 … → `AB�C` (the four characters A, B, U+FFFD, C)
examples: (R-A2L-DEF.34/2) C3 A9 00 … → `��` (two U+FFFD; Latin-1 would give `Ã©` → RED)

display_text
req: R-A2L-DEF.35, R-A2L-DEF.36, R-A2L-DEF.37, R-A2L-DEF.38, R-A2L-DEF.39
in: Definition definition; int | float value
out: str text
func: new (I-2; Inc 3 calls it per element). In this order: a value that is not finite → `nan`, `inf`, `-inf`; an integer datatype (not FLOAT16/32/64) whose conversion is `NO_COMPU_METHOD` or IDENTICAL → the integer text, no point (R-A2L-DEF.38); `decimals` not `None` → exactly that many digits after the point, rounded to nearest, a tie to even (Python's `f"{value:.{d}f}"` on the binary value), no padding; else the 15-significant-digit text (`"%.15g" % value`). No unit.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.35/1) LINEAR a = 0.1, UWORD, `%4.2`, value of stored 123 (`12.3`) → `12.30`
examples: (R-A2L-DEF.35/1 neg) mutant: the length used as padding → `12.30` with a leading space → RED; `%g` → `12.3` → RED
examples: (R-A2L-DEF.35/2 … /4) FLOAT64 `%.0`, `2.5` → `2`; `%8.4`, `3.14159` → `3.1416`; `%.2`, `0.125` → `0.12` (B2 P7)
examples: (R-A2L-DEF.36/1) FLOAT64 `%.40`, `0.1` → `0.10000000000000001`
examples: (R-A2L-DEF.37/1 … /4) LINEAR 0.1 UWORD, no format, `0.30000000000000004` → `0.3`; FLOAT64 `%`, `1234567.0` → `1234567`; `%12`, `1e-07` → `1e-07`; `x5.1`, `12.5` → `12.5`
examples: (R-A2L-DEF.37/1 neg) mutant: `repr` → `0.30000000000000004` → RED
examples: (R-A2L-DEF.38/1, E2-4) SOFTA `AlyjmQyfk.GrsaEjbkyQmicdevPjq_GpqJraTjkq._1_` (SWORD, `NO_COMPU_METHOD`, `FORMAT "%.15"`, at `0x0`), image FB FF → `-5`
examples: (R-A2L-DEF.38/1 neg) mutant: the 15 decimals applied → `-5.000000000000000` → RED
examples: (R-A2L-DEF.38/2) V171 `…BITMASK_0FF0` (`%5.0`), field 35 → `35`; (AT-B103-I2-1) V171 `ASAM.C.SCALAR.SBYTE.IDENTICAL` (`%6.1`), 120 → `120`
examples: (R-A2L-DEF.39/1 … /3) FLOAT32 `%.2`, NaN / +inf / −inf → `nan` / `inf` / `-inf`
examples: (R-A2L-DEF.54/1) `MEASUREMENT_0001` with `%.3`, `5.1` → `5.100`

encode_definition
req: R-A2L-DEF.25, R-A2L-DEF.26, R-A2L-DEF.40, R-A2L-DEF.47, R-A2L-DEF.53, R-A2L-DEF.54, R-A2L-DEF.55, R-A2L-DEF.56, R-A2L-DEF.57, R-A2L-DEF.58
in: Definition definition; dict a2l_data; str text; Mapping[int, int] image
out: Encoded | Refusal result
func: new (I-2). The *encode order*: (1) the definition's refusal; (2) kind text → `_encode_ascii(definition, text)` (spaces kept) → `Encoded(address, data, ())`; else `t` = `text` without the spaces (U+0020) at both ends; (3) number → `_parse_number_text(t)`, `None` → `A2L-DEF-NUMBER` `<name>: '<t>' is not a number`; enum → `_encode_enum(definition, t)` (a refusal passes through); the result is the *limit value*; (4) `_check_limits(definition, limit value, t)` (a refusal passes through; a text is the notice); (5) `_encode_number(definition, a2l_data, limit value)` (a refusal passes through); (6) a bit mask → `field = _decode_scalar(bytes, datatype, byte_order)` and `data = _merge_bit_mask(definition, field, t, image)` (a refusal passes through) — the bytes of step 5 are never the result for a masked definition (BL-I2-1, E2-11); else `data` = those bytes; (7) number → `decode_definition(definition, a2l_data, {address + i: b})` over the new bytes only; a refusal or a value that `_agrees_at_display_precision` rejects → `A2L-DEF-PRECISION` `<name>: <t> cannot be stored at the display precision — the nearest stored value is <stored>` (`<stored>` = `display_text` of the decoded value); (8) `Encoded(address, data, notices)`. Reads `image` and `a2l_data`; writes neither.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.40/1 … /7) V171 `ASAM.C.SCALAR.SWORD.IDENTICAL`, `` / `abc` / `1,5` / `1_000` / `nan` / `inf` / `0x10` → refusal `A2L-DEF-NUMBER` `ASAM.C.SCALAR.SWORD.IDENTICAL: '' is not a number` / `…: 'abc' is not a number` / `…: '1,5' is not a number` / `…: '1_000' is not a number` / `…: 'nan' is not a number` / `…: 'inf' is not a number` / `…: '0x10' is not a number`
examples: (R-A2L-DEF.41/2) V171 `ASAM.C.SCALAR.SWORD.IDENTICAL`, `  -5 ` → `Encoded(0x810004, FB FF, ())`
examples: (R-A2L-DEF.53/1, /2) INLINE (big) UWORD `B1` at 0x20, `4660` → address `0x20`, data `12 34`; INLINE UWORD `B2` at 0x20 with `BYTE_ORDER MSB_LAST`, `4660` → data `34 12` (B2 P6)
examples: (R-A2L-DEF.53/3) V171 `UNKNOWN`, `ABC` → address `0x810200`, `42` bytes
examples: (R-A2L-DEF.53/4, R-A2L-DEF.46/1) V171 `…BITMASK_0FF0`, image 0F F0 at 0x810002, `35` → address `0x810002`, data `3F F2` (word `0xF23F`), 2 bytes (base: `23 00`, B1 line 17)
examples: (R-A2L-DEF.46/1 neg) mutant: the bytes of `_encode_number` returned for a masked definition (the whole-word write) → `23 00` → RED
examples: (R-A2L-DEF.26/2) V171 `…BITMASK_0FF0`, an empty image, `35` → refusal `A2L-DEF-BYTES` `ASAM.C.SCALAR.UWORD.IDENTICAL.BITMASK_0FF0: 2 of its 2 bytes are not in the image`
examples: (R-A2L-DEF.25/2) C08 issues `MISSING_CM`, `7` → the `A2L-DEF-METHOD` refusal, no bytes
examples: (R-A2L-DEF.54/1) C08 clean `MEASUREMENT_0001` (`CM_TAB_INTP`, limits `0`..`50`) with `FORMAT "%.3"` added to its MEASUREMENT, `5.07` → the encode gives stored 51 (B2 P5j) → decoded `5.1` → `|5.1 − 5.07|` = 0.03 > 0.0005 → refusal `A2L-DEF-PRECISION` `MEASUREMENT_0001: 5.07 cannot be stored at the display precision — the nearest stored value is 5.100`
examples: (R-A2L-DEF.54/1 neg) mutant: step 7 left out (the flagged write of the reused encode) → bytes `00 33` → RED
examples: (R-A2L-DEF.54/2) the same object as generated (method format `%.1f`), `5.07` → `Encoded(0x50, 00 33, ())` (0.03 ≤ 0.05)
examples: (R-A2L-DEF.55/1) grid instances: FLOAT32 IDENTICAL, no format, `0.1` → stored `0.10000000149011612`, accepted (its `%.6g` text `0.1` equals, B2 P7); UWORD LINEAR 0.1, `%8.4`, `12.3` → stored `123`, accepted; UWORD mask `0x0FF0` IDENTICAL, `35` → accepted, decodes `35`; UWORD LINEAR 0.1, `12.34` → refusal `A2L-DEF-ENCODE` (`the converted raw value 123.4 is not integral`), not counted as accepted; ≥ `300` accepted, `0` that do not agree
examples: (R-A2L-DEF.55/1 neg) mutants: the bytes packed in the opposite byte order → decoded ≠ value → refused for precision → RED; the mask shift off by one → RED; LINEAR inverted as (x + b) / a → RED
examples: (R-A2L-DEF.56/1) V171 `…TAB_VERB_DEFAULT_VALUE` `Square` → `02 00` → decodes `Square`; C08 `ASCII_0001` `HW_REV=00.01.00.00` → its 18 bytes + 14 × 00 → decodes `HW_REV=00.01.00.00`; ≥ `32` texts, `0` that come back different
examples: (R-A2L-DEF.57/1) V171 `UNKNOWN`, a 43-character text holding `é` → `A2L-DEF-TEXT-LENGTH`
examples: (R-A2L-DEF.57/2) INLINE SWORD `L1` (LINEAR a = 2, limits −100..100, no extended), `301` → `A2L-DEF-LIMITS` (not `A2L-DEF-ENCODE` for 150.5)
examples: (R-A2L-DEF.57/3) INLINE SWORD `MN` (mask `0x00F0`, limits −100..100), an empty image, `-1` → `A2L-DEF-BYTES` (not `A2L-DEF-MASK-VALUE`)
examples: (R-A2L-DEF.57/3 neg) mutant: the mask checked before the image bytes → `A2L-DEF-MASK-VALUE` → RED
examples: (R-A2L-DEF.58/1, /2) V171 and C08: each defined object encoded with its own decoded text over the image → a deep copy of the image and of `a2l_data` taken before equals both after → `True`
examples: (AT-B103-I2-1, E2-8) V171, image `Hello ASAM`+32 × 00 at 0x810200, 34 12 at 0x810002, 02 00 at 0x810004, 00 at 0x810000 and 0x810001; in this order, each: decode, encode, apply the bytes, decode: `…TAB_VERB_DEFAULT_VALUE` `Square` → `Sinus` (03 00); `…TAB_VERB_NO_DEFAULT_VALUE` `orange` → `violet` (07 00); `…VTAB_RANGE_DEFAULT_VALUE` `four_to_seven` → `hundred` (64 00); `…BITMASK_0FF0` `35` → `200` (word `0x1C84`); `…BITMASK_0001` `0` → `1` (`0x1C85`); `…BITMASK_0010` `0` → `1` (`0x1C95`); `UNKNOWN` `Hello ASAM` → `ABC`; `ASAM.C.SCALAR.SBYTE.IDENTICAL` `0` → `120` (78, with the notice); `ASAM.C.SCALAR.UBYTE.IDENTICAL` `0` → `20` (14); `ASAM.C.SCALAR.SWORD.IDENTICAL` `100` → `-5` (FB FF). After the three mask writes every bit outside each write's mask is unchanged; `…BITMASK_0FF0` then decodes `201` (its mask holds bit 4, which `…BITMASK_0010` set)
examples: (AT-B103-I2-2) DEFC: `ENUM_0001` `IDLE` → `FAULT` (`03`); `MASK_FIELD_0001` `174` → `3` (word `0x1037`), `MASK_BIT_0001` still `1`; `MASK_BIT_0001` `1` → `0` (`0x1036`); `DISPLAY_0001` `143.5` → `-12.5` (`FF E7`); every other byte of the region unchanged

_parse_number_text
req: R-A2L-DEF.40, R-A2L-DEF.41
in: str text
out: float | None value
func: new. The *number text* grammar on the whole (already trimmed) text: `[+|-]` then ASCII digits with an optional point and digits, or a point and digits, then optionally `e`/`E`, an optional sign and digits; the value is `float(text)`; anything else → `None` (no `float()` grammar: no `_`, `,`, hex, `nan`, `inf`, no Unicode digits).
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.40/1 … /7) `` / `abc` / `1,5` / `1_000` / `nan` / `inf` / `0x10` → `None`
examples: (R-A2L-DEF.40/4 neg) mutant: `float()` grammar → `1_000` gives `1000.0` → RED
examples: (R-A2L-DEF.41/6) `+1.5e2` → `150.0`; `.5` → `0.5`; `1.` → `1.0`; `+2e1` → `20.0`; `-5` → `-5.0`

_check_limits
req: R-A2L-DEF.43, R-A2L-DEF.44, R-A2L-DEF.45
in: Definition definition; float limit_value; str text
out: Refusal | str | None outcome
func: new (D-7 A). `outside` = below a declared lower limit or above a declared upper limit. In order: outside and no extended limits → `A2L-DEF-LIMITS` `<name>: <text> is outside the limits <lower>..<upper>`; extended limits and the value outside them → `A2L-DEF-EXTENDED` `<name>: <text> is outside the extended limits <elower>..<eupper>`; outside (and inside the extended limits) → the notice `<name>: <text> is outside the limits <lower>..<upper> and inside the extended limits <elower>..<eupper>`; else `None`. Texts from `Limits.*_text`.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.43/1, /2) INLINE SWORD `L1` (LINEAR a = 2, limits −100..100), `-101` → `A2L-DEF-LIMITS` `L1: -101 is outside the limits -100..100`; `200` → `L1: 200 is outside the limits -100..100`
examples: (R-A2L-DEF.43/1 neg) mutant: flag and proceed (the reused encode's limb) → bytes → RED
examples: (R-A2L-DEF.43/3) INLINE MEASUREMENT `L3` `UBYTE NO_COMPU_METHOD 0 0 x 100`, `101` → `L3: 101 is outside the limits ..100`
examples: (R-A2L-DEF.43/4) V171 `ASAM.M.SCALAR.UBYTE.VTAB_RANGE_NO_DEFAULT_VALUE` (limits `0`..`101`), `hundredtwo` (raw 102) → `ASAM.M.SCALAR.UBYTE.VTAB_RANGE_NO_DEFAULT_VALUE: hundredtwo is outside the limits 0..101`
examples: (R-A2L-DEF.44/1, /2) V171 `ASAM.C.SCALAR.SBYTE.IDENTICAL` (limits −100..100, extended −128..127), `120` → the notice `ASAM.C.SCALAR.SBYTE.IDENTICAL: 120 is outside the limits -100..100 and inside the extended limits -128..127`, then data `78`; `-128` → `…: -128 is outside the limits -100..100 and inside the extended limits -128..127`, data `80`
examples: (R-A2L-DEF.45/1, /2) the same object, `-129` → `A2L-DEF-EXTENDED` `ASAM.C.SCALAR.SBYTE.IDENTICAL: -129 is outside the extended limits -128..127`; V171 `ASAM.C.SCALAR.UBYTE.IDENTICAL` (extended 0..256), `257` → `ASAM.C.SCALAR.UBYTE.IDENTICAL: 257 is outside the extended limits 0..256`
examples: (R-A2L-DEF.45/2 neg) mutant: the extended limits ignored → `257` refused by the UBYTE range (`A2L-DEF-ENCODE`) → RED

_encode_number
req: R-A2L-DEF.41, R-A2L-DEF.42
in: Definition definition; dict a2l_data; float value
out: bytes | Refusal data
func: new (D-3 A). The encode direction, through the unchanged `encode_physical_to_raw_bytes` on a tag view built from the definition — `char_type` `None`, `matrix_dim` `None`, `datatype`, `length` = `byte_length`, `effective_byte_order` = `byte_order`, `compu_method_name` = `method_name` (`NO_COMPU_METHOD` for kind enum: the stored value is the entry's raw, BL-I2-2), `lower_limit` / `upper_limit` `None` (its limits flag and its TAB_INTP flag are not used: .43 … .45 and .54 replace them) — with `{method_name: the record}` as its method table, `a2l_data["compu_tabs_by_name"]`, and no record layouts. Its bytes (the stored value as the datatype, in the byte order) or `A2L-DEF-ENCODE` `<name>: <reason>` with its reason verbatim.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.41/1) INLINE UBYTE `N0`, `NO_COMPU_METHOD`, `7.0` → `07`
examples: (R-A2L-DEF.41/2) V171 SWORD IDENTICAL, `-5.0` → `FB FF` (B2 P6)
examples: (R-A2L-DEF.41/3) C08 clean `VALUE_0019` (UWORD, `CM_LIN_OFF` a = 1, b = 100, big), `150.0` → `00 32` (stored 50, B2 P5j)
examples: (R-A2L-DEF.41/3 neg) mutant: LINEAR inverted as (x + b) / a → stored 250 → RED
examples: (R-A2L-DEF.41/4, E2-7) C08 clean `VALUE_0004` (SLONG, `CM_RAT`, little; case 08 has no UWORD `CM_RAT` object), `100.0` → `4B 00 00 00` (stored 75)
examples: (R-A2L-DEF.41/5) C08 clean `MEASUREMENT_0002` (`CM_TAB_NOINTP`, little), `15.0` → `03 00` (stored 3)
examples: (R-A2L-DEF.41/6, E2-7) C08 clean `MEASUREMENT_0001` (`CM_TAB_INTP`, big), `20` and `+2e1` → `00 C8` (stored 200); `VALUE_0002` (UWORD, `CM_LIN_10`, limits `0`..`655350`), `.5` → `A2L-DEF-ENCODE` `VALUE_0002: the converted raw value 0.05 is not integral`, `1.` → `VALUE_0002: the converted raw value 0.1 is not integral` (number texts, refused by the encode direction)
examples: (R-A2L-DEF.42/1 … /4) INLINE `E1` `CM(LINEAR 0 5)`, `5` → `E1: LINEAR conversion coefficient a is zero`; `E2` `CM(RAT_FUNC 0 1 0 0 0 0)`, `3` → `E2: RAT_FUNC denominator is zero`; `E3` TAB_NOINTP `COMPU_TAB_REF TB_GONE`, `1` → `E3: lookup table missing or empty`; `E4` TAB_INTP on a COMPU_TAB `0 "a"`, `1 "b"`, `1` → `E4: lookup table has no numeric entries` (B2 P6)
examples: (R-A2L-DEF.42/5, /6) C08 `MEASUREMENT_0002`, `12` → `MEASUREMENT_0002: the value 12.0 is not a table value - the nearest table values are 10.0 and 15.0`; `MEASUREMENT_0001`, `45` → `MEASUREMENT_0001: the value 45.0 is outside the table range [0.0, 40.0]` (B2 P5j)
examples: (R-A2L-DEF.42/7 … /11) INLINE `E7` FLOAT64 `CM(LINEAR 1e-300 0)`, `1e300` → `E7: the converted raw value is not finite`; `E8` SWORD `CM(LINEAR 2 0)`, `3` → `E8: the converted raw value 1.5 is not integral`; `E9` SWORD `CM(LINEAR 2 0)`, `1e9` → `E9: the converted raw value 500000000 is outside the SWORD range`; `E10` FLOAT16_IEEE, `1.0` → `E10: datatype FLOAT16_IEEE is not supported`; `E11` FLOAT32_IEEE, `1e39` → `E11: the raw value does not pack as FLOAT32_IEEE: float too large to pack with f format` (B2 P6)
examples: (R-A2L-DEF.42/8 neg) mutant: the reason dropped → `E8: refused` → RED

_merge_bit_mask
req: R-A2L-DEF.26, R-A2L-DEF.46, R-A2L-DEF.47
in: Definition definition; int field; str text; Mapping[int, int] image
out: bytes | Refusal data
func: new. First the image bytes of the span: `n` missing → `A2L-DEF-BYTES` (the R-A2L-DEF.26 message). Then `field < 0`, or `field << shift` with a 1 bit outside the mask → `A2L-DEF-MASK-VALUE` `<name>: <text> does not fit the bit mask <mask>` (`<mask>` = `bit_mask_text`, P-1). Else `word = int.from_bytes(span, byte_order)`, `(word & ~mask) | (field << shift)`, as `byte_length` bytes in the byte order: every bit outside the mask kept. (`text` was added to E1's signature for the message, E2-14.)
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.46/1) V171 `…BITMASK_0FF0` (little), image 0F F0 (word `0xF00F`), field `35` → `3F F2` (word `0xF23F`, B2 P7)
examples: (R-A2L-DEF.46/2) V171 `…BITMASK_0001`, image 34 12, field `1` → `35 12` (word `0x1235`)
examples: (R-A2L-DEF.46/3) DEFC `MASK_FIELD_0001` (big), the planned word `0x1AE7`, field `3` → `10 37`; then `MASK_BIT_0001` decodes `1` and `MASK_FIELD_0001` decodes `3`
examples: (R-A2L-DEF.47/1) V171 `…BITMASK_0FF0`, image 0F F0, `256` (limits 0..255: the extended-limits notice, then) → `A2L-DEF-MASK-VALUE` `ASAM.C.SCALAR.UWORD.IDENTICAL.BITMASK_0FF0: 256 does not fit the bit mask 0x0FF0`
examples: (R-A2L-DEF.47/1 neg) mutant: the field cut to the mask (`& mask`) → writes `0` → RED
examples: (R-A2L-DEF.47/2) INLINE SWORD `MN` mask `0x00F0`, image 00 00, `-1` (the encode's bytes FF FF read back as `-1`) → `MN: -1 does not fit the bit mask 0x00F0`
examples: (R-A2L-DEF.47/3) INLINE UBYTE `MC` mask `0x0A` (shift 1), image 00: `2` → `MC: 2 does not fit the bit mask 0x0A`; `5` → `0A`

_encode_enum
req: R-A2L-DEF.48, R-A2L-DEF.49
in: Definition definition; str text
out: float | Refusal raw
func: new. The raw value of the first entry in file order whose text equals `text`, case included (a range's min); the default text is not an entry; no such entry → `A2L-DEF-ENUM` `<name>: '<text>' is not a text of <table>`. (E1's slice said `int`; an entry's raw is a `float` in I-2, E2-14.)
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.48/1) V171 `…TAB_VERB_DEFAULT_VALUE`, `Square` → `2.0` (then data `02 00`; base: `conversion type '' is not supported`, B1 line 29)
examples: (R-A2L-DEF.48/2) V171 `…VTAB_RANGE_DEFAULT_VALUE`, `four_to_seven` → `4.0` (data `04 00`)
examples: (R-A2L-DEF.48/3) INLINE `VT_X` `1 "X"` `2 "X"` on UBYTE `EX2`, `X` → `1.0` (data `01`)
examples: (R-A2L-DEF.48/3 neg) mutant: the last entry with the text → `2.0` → RED
examples: (R-A2L-DEF.49/1 … /3) V171 `…TAB_VERB_DEFAULT_VALUE`, `square` / `unknown signal type` / `` → `A2L-DEF-ENUM` `ASAM.C.SCALAR.SWORD.TAB_VERB_DEFAULT_VALUE: 'square' is not a text of CM.TAB_VERB.DEFAULT_VALUE.REF` / `…: 'unknown signal type' is not a text of CM.TAB_VERB.DEFAULT_VALUE.REF` / `…: '' is not a text of CM.TAB_VERB.DEFAULT_VALUE.REF`

_encode_ascii
req: R-A2L-DEF.50, R-A2L-DEF.51, R-A2L-DEF.52
in: Definition definition; str text
out: bytes | Refusal data
func: new. More characters than `byte_length` → `A2L-DEF-TEXT-LENGTH` `<name>: the text has <k> characters — at most <length> fit`; else the first character outside U+0020 … U+007E → `A2L-DEF-TEXT-CHAR` `<name>: '<character>' is not a printable ASCII character`; else the ASCII bytes followed by 0x00 up to `byte_length`.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.50/1) V171 `UNKNOWN` (42 bytes), `ABC` → `41 42 43` + 39 × `00`
examples: (R-A2L-DEF.50/1 neg) mutant: no padding → 3 bytes → RED
examples: (R-A2L-DEF.50/2, /3) a 42-character text → those 42 bytes; `` → 42 × `00`
examples: (R-A2L-DEF.51/1) 43 characters → `A2L-DEF-TEXT-LENGTH` `UNKNOWN: the text has 43 characters — at most 42 fit`
examples: (R-A2L-DEF.52/1 … /3) `café` → `A2L-DEF-TEXT-CHAR` `UNKNOWN: 'é' is not a printable ASCII character`; `A\tB` → the tab character between the quotes; `A�` → `UNKNOWN: '�' is not a printable ASCII character` (the U+FFFD character)

_agrees_at_display_precision
req: R-A2L-DEF.54, R-A2L-DEF.55
in: Definition definition; float decoded; float value
out: bool agrees
func: new (D-3 A). The CTX-A2L-DEF rule: `decimals` = d not `None` → `|decoded − value| ≤ 0.5 × 10^(−d)`; else their `%.15g` texts are equal; for FLOAT32_IEEE and FLOAT64_IEEE also true when the `%.6g` texts or the `%.15g` texts are equal.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.54/1) d = 3, `5.1`, `5.07` → `False`
examples: (R-A2L-DEF.54/2) d = 1, `5.1`, `5.07` → `True`
examples: (R-A2L-DEF.55/1) FLOAT32, d = 15 (`%.15`), `0.10000000149011612`, `0.1` → `True` (`%.6g` both `0.1`; B1 line 33)
examples: (R-A2L-DEF.55/1) SWORD, no decimals, `-5`, `-5.0` → `True`

build_definition_objects
req: R-A2L-DEF.60, R-A2L-DEF.61, R-A2L-DEF.62
in: random.Random rng
out: tuple[dict[str, tuple[int, bytearray]], list[dict]] built
func: new (D-5 A, D-6 A; G2). The DEFC regions and object list, pinned above: the 256-byte `cal` region at `CAL_BASE` (fill then planned bytes, in the pinned draw order), the keys `boot`, `app`, `config` with empty byte arrays (E2-15), and the four objects `ENUM_0001`, `MASK_BIT_0001`, `MASK_FIELD_0001`, `DISPLAY_0001` with the I-D keys. Uses `_pack_scalar` for the planned SWORD and UBYTE bytes; touches no case 08 function and no other random sequence.
module: tools/synth/make_release_case.py
examples: (R-A2L-DEF.60/1) seed 20260001 → `ENUM_0001`: address `0x800000`, raw byte `01`, planned stored `1`, planned text `IDLE` (B2 P8)
examples: (R-A2L-DEF.61/1) → `MASK_BIT_0001` bit mask `1` and `MASK_FIELD_0001` bit mask `4080`, both at `0x800010`, disjoint (`1 & 4080` = `0`), popcounts `1` and `8`; word bytes `1a e7`; planned texts `1` and `174`
examples: (R-A2L-DEF.61/1 neg) mutant: the two masks overlap (`0x0FF0` and `0x0010`) → RED
examples: (R-A2L-DEF.62/1) → `DISPLAY_0001`: bytes `01 1f` (raw `287`), planned text `143.5`, low `-40`, high `150`

emit_definitions_a2l
req: R-A2L-DEF.60, R-A2L-DEF.61, R-A2L-DEF.62
in: dict[str, tuple[int, bytearray]] regions; list[dict] objects
out: str text
func: new (G2). The DEFC A2L text pinned above (own PROJECT, MODULE, MOD_COMMON `BYTE_ORDER MSB_FIRST`, one MEMORY_SEGMENT, RECORD_LAYOUTs `RL_U8`, `RL_U16`, `RL_S16`, methods `CM_DEF_ENUM` (TAB_VERB, `COMPU_TAB_REF VT_DEF_STATE`), `CM_DEF_IDENT`, `CM_DEF_LIN`, the COMPU_VTAB `VT_DEF_STATE` with 4 pairs and `DEFAULT_VALUE "UNKNOWN_STATE"`, the four CHARACTERISTICs), one keyword per line, `\n` line ends, addresses as `_fmt_addr` writes them.
module: tools/synth/make_release_case.py
examples: (R-A2L-DEF.60/1) the text holds `TAB_VERB 4`, the pairs `0 "OFF"` … `3 "FAULT"`, `DEFAULT_VALUE "UNKNOWN_STATE"`; the app's parser + this graph's `describe_definition("ENUM_0001")` → kind `enum`, `4` entries, default text `UNKNOWN_STATE`
examples: (R-A2L-DEF.60/1 neg) mutant: the method written like case 08's (`TAB_NOINTP` over a COMPU_VTAB) → kind `number` → RED
examples: (R-A2L-DEF.61/1) → `BIT_MASK 0x0001` under `MASK_BIT_0001` and `BIT_MASK 0x0FF0` under `MASK_FIELD_0001`, both headers at `0x00800010`
examples: (R-A2L-DEF.62/1, R-A2L-030/def-2) → under `DISPLAY_0001`: `EXTENDED_LIMITS -50 200`, `FORMAT "%.1"`, `PHYS_UNIT "deg C"`; the definition: unit `deg C`, display format `%.1`, limits `-40`..`150`, extended `-50`..`200`
examples: (R-A2L-DEF.62/1 neg) mutant: `UNIT` written for `PHYS_UNIT` → RED (the row asks for a PHYS_UNIT line)

generate_definitions_case
req: R-A2L-DEF.60, R-A2L-DEF.61, R-A2L-DEF.62, R-A2L-DEF.63
in: Path out_dir; int seed
out: dict[str, Path] paths
func: new (G2). Creates `out_dir`; `build_definition_objects(random.Random(seed))`; writes `firmware.s19` (`emit_s19(regions, BOOT_BASE)`, unchanged) and `firmware.a2l` (`emit_definitions_a2l`) with `Path.write_text(…, encoding="utf-8")`; returns `{"s19": …, "a2l": …}`. No wall clock, no file of case 08.
module: tools/synth/make_release_case.py
examples: (R-A2L-DEF.63/1) seed 20260001 into two folders → `firmware.s19` and `firmware.a2l` byte-identical across the two (`2` of `2` files)
examples: (R-A2L-DEF.63/1 neg) mutant: a date written into the A2L header → RED
examples: (AT-B103-I2-2) the files loaded by the app's A2L parser and `S19File` → the image holds `256` bytes at `0x800000 … 0x8000FF`; each object decodes to its planned text (`IDLE`, `1`, `174`, `143.5`)

main
req: R-A2L-DEF.59, R-A2L-DEF.63
in: list[str] argv
out: int code
func: changed (D-5 A; G2). was: `--out`, `--seed` (default 20260001), `--size-mb` (default 10.0); `generate(Path(out), seed, size_mb)`; prints one line per file; returns 0 (`make_release_case.py:1048-1058`). / now: the same plus `--case {release,definitions}`, default `release`; `release` runs exactly the old body; `definitions` runs `generate_definitions_case(Path(out), seed)` (`--size-mb` not used) and prints its two lines the same way. Callers: the `__main__` guard (`:1061-1062`) and `tests/test_synth_release_case.py::test_cli_entry_point` (subprocess, no `--case`) (R; the census cannot tell this `main` from `cli.py`'s, C2).
module: tools/synth/make_release_case.py
examples: (R-A2L-DEF.59/1) `--out <tmp> --seed 20260001 --size-mb 1`, no `--case` → the 11 files with the 1 MiB pin digests, `firmware.s19` `f5592b511a561c463bf89679b784aea9d9fa552d5aa9b06a17f8e91cd87ea49b` … `README.txt` `1ac1b52e1ddb13ffc0fcf45113ec01ce759992bde87730bfae63c647924506ed` (C1 hash transcript, the `1 |` rows), each over the bytes with CR LF read as LF
examples: (R-A2L-DEF.59/2) `--size-mb 10` → the 11 `10 |` digests, `firmware.s19` `cb0cd7f1a07488aecbcb0928d75b4ae57bb5373f2ff4c097147aac41e2a7c2d9` … (`slow`)
examples: (R-A2L-DEF.59/1 neg) mutant: one object added to case 08's inventory → the S19, HEX, A2L and MAC digests change → RED
examples: (R-A2L-DEF.63/1) `--case definitions --out <tmp>` → `0`; the folder holds `firmware.s19` and `firmware.a2l` only

encode_physical_to_raw_bytes
req: R-A2L-DEF.41, R-A2L-DEF.42, R-A2L-DEF.53
in: dict tag; Any physical_value; Optional[dict] compu_methods_by_name = None; Optional[dict] compu_tabs_by_name = None; Optional[dict] record_layouts_by_name = None
out: tuple[Optional[tuple[int, ...]], Optional[str], list[str]] result
func: unchanged (frozen `a2l.py:2368`). The encode direction per conversion type, the refusal reasons, packing in the tag's byte order; flags (not refusals) for a value outside the tag's limits and for an off-grid TAB_INTP write. It ignores BIT_MASK: a masked tag is written whole (BL-I2-1). Real callers (C2): `resolve_symbol_entry` (`services/change_service.py:649`) ← `ChangeService.add_symbol_entry` (`:1297`) ← no product caller (C1). After Inc 2 also `_encode_number`, always with a mask-free tag view and limits `None`.
module: s19_app/tui/a2l.py
examples: (holds on base, B2 P5j) C08 `VALUE_0019`, `150.0`, limits removed → (`(0, 50)`, `None`, `[]`); `MEASUREMENT_0001`, `5.07` → (`(0, 51)`, `None`, [`the value 5.07 is not a table value - the write proceeds as 5.1`])
examples: (holds on base, BL-I2-1, B2 P6) a UWORD IDENTICAL tag, little, `35.0` → (`(35, 0)`, `None`, `[]`): the whole word, the field unshifted — the write the graph never returns for a masked definition
examples: (holds on base, B1 line 27) SWORD LINEAR a = 2, limits −100..100, `200` → bytes and the flag `the value 200.0 is outside the tag's declared limits [-100.0, 100.0] - the write proceeds`

describe_curve_tag
req: to trace
in: dict tag; Optional[dict] a2l_data; Optional[Dict[int, int]] mem_map
out: dict description
func: unchanged (frozen `a2l.py:2993`). The E9 parameter description of one CHARACTERISTIC (header, CURVE/MAP records); no Inc 2 node calls it (Inc 3's reuse candidate for the R5 component walk). Its unit takes the method's unit before the tag's (BL-I2-9). Real caller (C2): `S19TuiApp.action_a2l_describe_tag` (`app.py:9776`).
module: s19_app/tui/a2l.py
examples: (holds on base, C2) callers → `S19TuiApp.action_a2l_describe_tag` only; `0` callers in the Inc 2 graph

parse_parameter_list
req: to trace
in: str text
out: list tokens
func: unchanged (`a2l_parameter_picker.py:75`; I-5). Splits a pasted label list on new lines, CR, commas, semicolons and spaces, order and repeats kept. No Inc 2 node calls it; no Inc 2 row parses a label list. Real caller (C2): `BulkParameterAddScreen._apply_list` (`screens.py:1019`).
module: s19_app/tui/a2l_parameter_picker.py
examples: (holds on base, R: its docstring) `"Alpha\nBeta, Gamma; Delta   Alpha"` → `['Alpha', 'Beta', 'Gamma', 'Delta', 'Alpha']`; `" ,;\n "` → `[]`

parse_begin_meta
req: R-A2L-DEF.5
in: str meta
out: tuple[str, Optional[str]] parsed
func: unchanged (frozen `a2l.py:255`, public). The section name and long identifier of a /begin line's rest; `UNKNOWN` for an empty rest. Used by `_find_tag` to check the pairing. Real callers (C2): `extract_a2l_tags.<locals>.walk` (`a2l.py:2601`, `:2732`), `extract_compu_methods` (`:859`), `extract_compu_tables` (`:903`), `extract_record_layouts` (`:715`).
module: s19_app/tui/a2l.py
examples: (holds on base, B2 P2) V171's ASCII object, rest `""` → (`UNKNOWN`, `None`)

_flatten_body_tokens
req: R-A2L-DEF.10, R-A2L-DEF.14, R-A2L-DEF.15, R-A2L-DEF.18, R-A2L-DEF.20, R-A2L-DEF.22
in: list[str] lines
out: list[str] tokens
func: unchanged (frozen `a2l.py:422`, private, D-9 A). Joins the lines, removes `/* … */` and `//` comments across them, splits respecting quotes (a quoted text is one token without its quotes, `""` an empty token). The model's one tokenizer for every record (method, table, object). Real callers (C2): `assemble_characteristic_header` (`a2l.py:653`), `extract_a2l_tags.<locals>.walk` (`:2729`).
module: s19_app/tui/a2l.py
examples: (holds on base, B2 P1b) TUBE `model.MainClass.gameController.sm`, [meta] + lines → `model.MainClass.gameController.sm`, `""`, `UBYTE`, `esdl_model_GameControllerStatemachineStates`, `1`, `100.0`, `0`, `3`, `ECU_ADDRESS`, `0x0`

_split_line_respecting_quotes
req: to trace
in: str line
out: list[str] tokens
func: unchanged (frozen `a2l.py:319`, private). No new node calls it (the model tokenizes through `_flatten_body_tokens`, which calls it), so it leaves D-9's import list and its rename guard (E2-14). Real callers (C2): 10 functions of `a2l.py`, `_flatten_body_tokens` (`:456`) among them.
module: s19_app/tui/a2l.py
examples: (holds on base, C2) callers → `10` functions, all in `a2l.py`; `0` in the Inc 2 graph

_collect_sections_by_name
req: R-A2L-DEF.5, R-A2L-DEF.10, R-A2L-DEF.14
in: list[dict] sections; str target_name
out: list[dict] found
func: unchanged (frozen `a2l.py:698`, private, D-9 A). Every section of that name, pre-order. Used by `_find_tag`, `_read_method_record`, `_read_enum_table`. Real callers (C2): `extract_compu_methods` (`:846`), `extract_compu_tables` (`:902`), `extract_record_layouts` (`:714`).
module: s19_app/tui/a2l.py
examples: (holds on base, B2 P4g) software_a, `COMPU_METHOD` → `3.91` ms per call; the two object kinds walked and sorted → `9.13` ms

_apply_compu_method
req: R-A2L-051, R-A2L-053, R-A2L-054, R-A2L-055, R-A2L-056, R-A2L-057, R-A2L-058.1, R-A2L-058.2, R-A2L-058.3, R-A2L-061, R-A2L-062, R-A2L-063
in: Any raw_value; Optional[dict] method; dict[str, dict] compu_tables_by_name; Optional[tuple[Optional[float], Optional[float]]] limits = None
out: tuple[Any, str, str] result
func: unchanged (frozen `a2l.py:1891`, private, D-9 A). Raw → physical for IDENTICAL, LINEAR, RAT_FUNC (inverted, limits choose the root), TAB_INTP, TAB_NOINTP; `(value, status, error)`. TAB_VERB falls to `unknown_method` (S2 D2-5): `decode_definition` never sends it an enum. Real callers (C2): `enrich_a2l_tags_with_values` (`a2l.py:2909`), `describe_curve_tag` (`:3155`, `:3202`), `_decode_external_axis_points` (`:3304`); after Inc 2 also `decode_definition`.
module: s19_app/tui/a2l.py
examples: (holds on base, B2 P5k) `CM_TAB_INTP`, `500` → (`40.0`, `ok`, ``); `51` → (`5.1`, `ok`, ``)
examples: (holds on base, B2b) `RAT_FUNC 0 1 1 0 1 1`, `2` → (`None`, `error`, `RAT_FUNC root has a zero denominator`)

_decode_scalar
req: R-A2L-043, R-A2L-044, R-A2L-045
in: bytes raw; str decode_type; str decode_endian
out: Any value
func: unchanged (frozen `a2l.py:1811`, private, D-9 A). `struct.unpack` of one datatype in `big`/`little` order; `None` for FLOAT16_IEEE (BL-I2-7, wrapped in `_read_stored_value`). Real callers (C2): `_decode_raw_value` (`a2l.py:1830`, `:1834`), `_decode_component_run` (`:2975`); after Inc 2 also `_read_stored_value` and `encode_definition` (the field of a masked encode).
module: s19_app/tui/a2l.py
examples: (holds on base, B2 P6) `FB FF`, `SWORD`, `little` → `-5`; `12 34`, `UWORD`, `big` → `4660`; `3C 00`, `FLOAT16_IEEE`, `big` → `None`

_resolve_record_layout
req: R-A2L-022, R-A2L-023
in: Optional[str] layout_name; dict[str, dict] record_layouts_by_name
out: Optional[dict] layout
func: unchanged (frozen `a2l.py:1241`, private, D-9 A). The layout's first datatype token as `decode_type`; with none, the first datatype of the size `sizeof_from_deposit` gives (BL-I2-13: `__SWORD_Z` → `UWORD`). Real callers (C2): `_infer_length_characteristic` (`a2l.py:1227`), `encode_physical_to_raw_bytes` (`:2490`), `enrich_a2l_tags_with_values` (`:2887`); after Inc 2 also `_resolve_datatype`.
module: s19_app/tui/a2l.py
examples: (holds on base, B2 P2) V171 `RL.FNC.SWORD.ROW_DIR` → decode type `SWORD`; SOFTA `__VBFES_C` → `SWORD` (B2 P4i)

_to_float
req: R-A2L-DEF.14, R-A2L-DEF.20, R-A2L-DEF.21, R-A2L-DEF.43
in: Any value
out: Optional[float] number
func: unchanged (frozen `a2l.py:293`, private, D-9 A). `float(value)` or `None`. The model's reader for limit, extended-limit, coefficient and table-entry words (the same reading as the tag table's, so a hexadecimal table raw is skipped in both). Real callers (C2): 10 functions of `a2l.py`.
module: s19_app/tui/a2l.py
examples: (holds on base, R) `-100` → `-100.0`; `x` → `None`; `None` → `None`

generate
req: R-A2L-DEF.59
in: Path out_dir; int seed; float size_mb
out: dict[str, Path] paths
func: unchanged (`make_release_case.py:1014`). Writes the 11 files of case 08; the oracle of the pin. Not called by any new node. Real callers: `main` (`:1055`, C2) and the tests `tests/test_synth_release_case.py:59`, `tests/test_b101_a2l_blocks_and_segments.py:119`, `tests/test_b101_check_spec_keep.py:123`, `tests/test_b101_inc11_acceptance.py:105`, `tests/test_b101_symbol_reads.py:93` (R; the extractor leaves tests out); `tests/support/b101_demo_image.py:41-48` rebuilds `build_objects` in process (R).
module: tools/synth/make_release_case.py
examples: (holds on base, C1) seed 20260001, 1 MiB, two runs → `22` digests over the two sizes, `0` run-to-run mismatches

emit_s19
req: R-A2L-DEF.63
in: dict[str, tuple[int, bytearray]] regions; int entry_point
out: str text
func: unchanged (`make_release_case.py:532`). An S0 line, S3 lines of 32 bytes for the regions `boot`, `app`, `cal`, `config` in that order (each key must exist: `_iter_regions`), an S7 line. Reused by `generate_definitions_case`. Real callers (C2): `generate` (`:1034`, `:1036`).
module: tools/synth/make_release_case.py
examples: (R) DEFC regions (`cal` 256 bytes, the others empty) → `1` S0 line, `8` S3 lines from `0x00800000`, `1` S7 line

_pack_scalar
req: R-A2L-DEF.60, R-A2L-DEF.62
in: str datatype; int raw; bool big_endian
out: bytes data
func: unchanged (`make_release_case.py:265`). `struct.pack` of one value of `DATATYPE_META`'s datatypes. Reused by `build_definition_objects`. Real callers (C2): `_scalar_value` (`:321`, `:355`), `_changed_scalar_bytes` (`:732`).
module: tools/synth/make_release_case.py
examples: (holds on base, B2 P8) `SWORD`, `287`, `True` → `01 1f`; `UBYTE`, `1`, `True` → `01`

## Entities

[Data: Definition]
desc: I-2's frozen dataclass (fields and pinned values above). Built only by `describe_definition`; read by `decode_definition`, `encode_definition`, `display_text` and every private helper; consumers (Inc 6, 8, 9) read it by field name.

[Data: Refusal]
desc: I-2 `Refusal(code, message)`: the one error value of the module; codes and messages pinned above.

[Data: Limits]
desc: I-2 `Limits(lower, upper, lower_text, upper_text)`; `*_text` is `""` for a side whose word is not a number.

[Data: EnumEntry]
desc: I-2 `EnumEntry(raw, raw_max, text)`; `raw_max` `None` for a COMPU_VTAB pair; the text is never converted to a number.

[Data: Decoded]
desc: I-2 `Decoded(stored, value, text)`, per kind as pinned above.

[Data: Encoded]
desc: I-2 `Encoded(address, data, notices)`: the whole span from the address; the caller applies it (the module writes nothing).

[Data: a2l_data]
desc: the `parse_a2l_file` payload; the model reads `tags`, `sections`, `record_layouts_by_name`, `compu_tabs_by_name` and never writes (R-A2L-DEF.58). It does not read `compu_methods_by_name` (D-2 A: it reads the records itself).

[Data: image]
desc: any `Mapping[int, int]` address → byte (a loaded file's `mem_map`, or an editor's staging overlay); read only.

[I/O: case 08 files]
desc: the 11 files `generate` writes; pinned by R-A2L-DEF.59 (22 SHA-256 digests, CR LF read as LF); no Inc 2 node writes them.

[I/O: DEFC files]
desc: `firmware.s19` and `firmware.a2l` that `generate_definitions_case` writes into `--out`; read by the testers through the app's loaders.

## Edges

[Data: a2l_data] ──▶ describe_definition
[Data: a2l_data].sections ──▶ _find_tag
[Data: a2l_data].tags ──▶ _find_tag
[Data: a2l_data].sections ──▶ _read_method_record
[Data: a2l_data].sections ──▶ _read_enum_table
[Data: a2l_data].record_layouts_by_name ──▶ _resolve_datatype
[Data: a2l_data].compu_tabs_by_name ──▶ decode_definition
[Data: a2l_data].compu_tabs_by_name ──▶ _encode_number
describe_definition ──▶ [Data: Definition]
[Data: image] ──▶ _read_stored_value
[Data: image] ──▶ _merge_bit_mask
when: the definition has a bit mask (an unmasked encode never reads the image)
generate_definitions_case ──▶ [I/O: DEFC files]
generate ──▶ [I/O: case 08 files]
main ──▶ generate
when: `--case` is absent or `release`

## Findings

finding E2-1 the BalanceTube MEASUREMENTs reach the definition with no datatype, conversion, limits or length
anchor: describe_definition
seen: (B2 P1a) TUBE `model.MainClass.gameController.sm`: the tag table gives datatype `None`, conversion `None`, length `None` — every header line carries a comment, so no line has the 6 words `parse_measurement_header` needs; R-A2L-DEF.2/3 (kind enum), .10/4 through the object and .23/2 (`%12.4`) cannot hold from the tag alone
cause: `a2l.py`'s MEASUREMENT header read is per line without comment stripping (a defect not in E1's §5: new backlog row BL-I2-17, `a2l.py` frozen)
effect: without a wrap the definition is `A2L-DEF-ADDRESS` (no length) with kind `number`; every BalanceTube enum MEASUREMENT stays uneditable
decision: PROPOSED for E3 — `_read_object_lines` gives the header words (comment-free, `_flatten_body_tokens`) and `describe_definition` fills datatype, conversion word, limit words and the R-A2L-014 length when the tag lacks them; R-A2L-014 joins the cited rows (`01-requirements.md`, "Cited rows"); E1 adds its case on the definition; no node is added (deviation from the E1 slice: `_read_object_lines` grows)

finding E2-2 BalanceTube is also the only fixture of R-A2L-DEF.23/2
anchor: _read_method_record
seen: (B2 P1c, P1d) the commented COMPU_METHOD header reads `TAB_VERB`, `%12.4`, `""`, `COMPU_TAB_REF …_vtab` from the record words; the side table gives `None` for all four (BL-I2-3)
cause: as E2-1, on the method side (already BL-I2-3)
effect: none beyond E2-1 once the object fill exists
decision: covered by the record reading of D-2 A; no change

finding E2-3 software_a MEASUREMENTs have no address
anchor: describe_definition
seen: (B2 P4h) `0` of `10538` software_a MEASUREMENTs have an address (the file has no ECU_ADDRESS line; R-A2L-012); the cases R-A2L-DEF.1/3, .14/2, .15/2 and .18/3 name MEASUREMENTs, so their definitions carry `A2L-DEF-ADDRESS`
cause: the fixture, not the design: a refused definition still carries kind, entries and mask ("every field it could read")
effect: .1/3, .14/2, .15/2 hold as written (they assert fields, not the absence of a refusal)
decision: noted on the examples; see E2-4 for the two that cannot hold

finding E2-4 two E1 cases on software_a cannot hold as written
anchor: display_text
seen: R-A2L-DEF.38/1 decodes "the MEASUREMENT of R-A2L-DEF.1/3 (SWORD, NO_COMPU_METHOD, FORMAT "%.15")": that object is UWORD with no FORMAT and no address (B2 P4a), so the decode gives `A2L-DEF-ADDRESS`; R-A2L-DEF.18/3 expects "no refusal" on a MEASUREMENT with `BIT_MASK 0xFFFFFF`, which has no address (B2 P4e; none with that mask has one, P4j)
cause: E1 case inputs chosen without the address
effect: as written, both cases fail on a correct model
decision: the graph's examples use `AlyjmQyfk.GrsaEjbkyQmicdevPjq_GpqJraTjkq._1_` (SWORD VALUE at 0x0, NO_COMPU_METHOD, `%.15`, B2 P4i) for .38/1, and for .18/3 the mask `16777215` with refusal `A2L-DEF-ADDRESS` (not MASK) plus an INLINE ULONG `M24` with no refusal; E1 corrects `02-test-cases.md`

finding E2-5 the RAT_FUNC zero-denominator case input gives another error
anchor: decode_definition
seen: (B2 P6, B2b) `CM(RAT_FUNC 0 1 0 0 1 0)`, stored 1 → `RAT_FUNC has no solution for this value` (a − r·d = 0 and b − r·e = 0); `CM(RAT_FUNC 0 1 1 0 1 1)`, stored 2 → `RAT_FUNC root has a zero denominator`
cause: E1 case input of R-A2L-DEF.28/3 and R-A2L-058.3/def-1
effect: as written, /3 asserts the wrong text on a correct model
decision: the graph uses the corrected input; E1 corrects both cases

finding E2-6 the datatype refusal cases have no length, so the address refusal comes first
anchor: describe_definition
seen: R-A2L-DEF.8/1 (`ND`, layout `FNC_VALUES 1 FOO …`) and .8/2 (`NM`, datatype `FOO`) give no length to the tag table (no datatype to size it), so the refusal order gives `A2L-DEF-ADDRESS` before `A2L-DEF-DATATYPE`
cause: the fixtures, under the ruled refusal order
effect: as written, both cases expect the wrong code
decision: the graph adds `LENGTH 2` / `LENGTH 1` to the two fixtures; E1 corrects the cases (the refusal order stays)

finding E2-7 case 08 has no UWORD CM_RAT object, and the FLOAT32 CM_LIN_10 object refuses `.5` by its limits
anchor: _encode_number
seen: (B2 P5c) the generator pairs `CM_RAT` only with ULONG or SLONG (its spec arithmetic: conversion index 3 of 6 and datatype index len % 4); the first `CM_RAT` object is `VALUE_0004` (SLONG). The first FLOAT32 `CM_LIN_10` object `VALUE_0012` has limits `143.098`..`429.294`, so `.5` gives `A2L-DEF-LIMITS`, not an encode-direction refusal
cause: E1 case inputs of R-A2L-DEF.41/4 and /6
effect: as written, /4 names no object and /6's "refused only by the encode direction" fails
decision: the graph uses `VALUE_0004` (`100` → `4B 00 00 00`) and `VALUE_0002` (UWORD `CM_LIN_10`, limits 0..655350: `.5` and `1.` refused as not integral); E1 corrects both cases

finding E2-8 V171's masks 0x0FF0 and 0x0010 overlap
anchor: encode_definition
seen: bit 4 is in both `ASAM.C.SCALAR.UWORD.IDENTICAL.BITMASK_0FF0` and `…BITMASK_0010` (V171 `:3657-3698`); after AT-B103-I2-1's writes the 0FF0 field reads `201`, not the `200` it was given
cause: the ASAM demo shares one word between overlapping representations ("It is allowed to use the same address for multiple characteristics", V171 note)
effect: the AT's "the three masked objects keep each other's bits across the three writes" cannot hold for any correct model
decision: the graph's AT example asserts that each write keeps every bit outside its own mask and states the 0FF0 field's `201`; E1 corrects AT-B103-I2-1. DEFC's two masks are disjoint (R-A2L-DEF.61), so AT-B103-I2-2 keeps the stronger claim

finding E2-9 R-A2L-DEF.5/2 cannot tell the first tag from the last
anchor: _find_tag
seen: (B2 P5h) both `VALUE_0001` tags of `firmware_issues.a2l` sit at `0x0` with the same deposit, method, limits and byte order
cause: the generator copies the clean object into the duplicate (R-VAL-031's fault is the name, not the content)
effect: the negative control (the last tag used) stays GREEN on /2
decision: /2 is a `partial` case; /1 (INLINE `DUP` at 0x10 and 0x20) carries the row; E4's tester marks it so

finding E2-10 one describe_definition call costs about 20 ms on software_a
anchor: describe_definition
seen: (B2 P4g) one walk of the object sections with the sort `9.13` ms, one `_collect_sections_by_name` `3.91` ms, on 13 990 tags; a call does about four such walks
cause: I-2 takes the parse payload, which has no index by name; the module keeps no state (pure)
effect: a consumer that describes every row of a large A2L (Inc 6's picker) would wait minutes (≈ 14 000 × 20 ms)
decision: PROPOSED for E3 — (A) I-2 stays per object and Inc 6 describes only the rows it shows or picks; (B) I-2 gains `describe_definitions(names, a2l_data) -> dict[str, Definition]` that walks once. Recommendation A for Inc 2 (no consumer exists yet; Inc 6's E1 measures its own row count)

finding E2-11 how a masked encode avoids the whole-word write
anchor: encode_definition
seen: the ruling forbids routing a new node through the BIT_MASK whole-word encode (BL-I2-1: `35` on `BITMASK_0FF0` → `23 00`); the encode direction itself lives only in `encode_physical_to_raw_bytes`
cause: the reused encode packs the stored value as the whole datatype and does not read BIT_MASK
effect: the graph calls it on a mask-free tag view to get the stored value only; for a masked definition its bytes are read back to an integer (`_decode_scalar`) and never returned; the bytes come from `_merge_bit_mask` (negative control R-A2L-DEF.46/1 neg)
decision: PROPOSED for E3 to confirm this reading of the ruling. The alternative computes the stored value through the private `_invert_physical_to_raw` (an eighth private import, its annotation defect BL-I2-8) and repeats the integral, range and pack limbs in the module (duplicated code); not recommended

finding E2-12 a BIT_MASK word that is not a number
anchor: describe_definition
seen: no row covers it; 0 such words in the 35 tracked files (census over `examples/`: every BIT_MASK word is `0x…` or decimal digits)
cause: R-A2L-DEF.18 defines the mask only for a number word
effect: with no rule the object would be edited as a whole word
decision: PROPOSED for E3 — fail closed: `A2L-DEF-MASK` with that word (`<name>: the bit mask <mask> cannot be applied to <datatype>`), R-A2L-DEF.19's condition gaining "is not a number"; or drop it (no tracked shape) and leave the gap recorded

finding E2-13 a CHARACTERISTIC whose header gave no kind
anchor: _object_kind
seen: a CHARACTERISTIC header with fewer than 7 parameters gives `char_type` `None` in the tag table; R-A2L-DEF.4's `<kind>` is "the CHARACTERISTIC kind as the file writes it"
cause: no tracked shape; no row names it
effect: the message needs a text
decision: the graph writes `(none)`, as `<type>` and `<table>` do; E3 to confirm

finding E2-14 deviations from the E1 slice
anchor: describe_definition
seen: `_check_bit_mask` returns `bool` (the message needs the name and the mask word, which `describe_definition` holds); `_merge_bit_mask` gains `text` (the `A2L-DEF-MASK-VALUE` message); `_encode_enum` returns `float` (EnumEntry raw is a float in I-2); `_read_object_lines` reads the header words (E2-1); `encode_definition` reuses `decode_definition` for the precision decode (no extra node); D-9's import list holds 6 private helpers (`_split_line_respecting_quotes` is not called by any new node) plus the public `parse_begin_meta`, `encode_physical_to_raw_bytes`, `DATATYPE_SIZES` — `DATATYPE_STRUCT_CODES` and `MAX_A2L_DECODE_BYTES` are not used
cause: writing the examples
effect: node count unchanged (22 + 4); the rename guard of D-9 covers the 6
decision: for E3 to accept with the graph

finding E2-15 the existing emit_s19 needs all four region keys
anchor: build_definition_objects
seen: (R) `emit_s19` iterates `boot`, `app`, `cal`, `config` through `_iter_regions` (`make_release_case.py:527-530`); a dict without `boot` raises `KeyError`
cause: case 08's emitter assumes its four regions
effect: DEFC's one region needs the other keys present
decision: `build_definition_objects` returns the three other keys with empty byte arrays at their bases, so `emit_s19` is reused unchanged (E1 slice: "the existing `emit_s19`")
