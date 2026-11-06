# Inc 2 — test cases (ISO/IEC/IEEE 29119-3), E1

One case per coverage item `<requirement id>/<n>` of `01-requirements.md` (one alternative of one requirement), the cases of the cited canon rows the definition model must meet, and the acceptance cases `AT-B103-I2-1` … `-3` (batch-scoped ids, outside the global pool). Written at E1, before any test: **Tests** is empty, **Coverage** is `gap` and **Result** is `not_run` everywhere; testers fill them at E4. Class: *normal* for a `When` or `U` row, *robustness* for an `If` row. Expected results are the requirement's exact values and texts. The model is pure: every case calls it directly (I-2, `E1-rulings.md` §4) — "the definition of N" is what the model builds for the name N on the fixture, "decode" and "encode `<text>`" are its decode and encode over the case's image.

Common fixtures:
- **V171** — `examples/case_00_public/ASAP2_Demo_V171.a2l`, parsed by the app's A2L parser (`MOD_COMMON BYTE_ORDER MSB_LAST`: little-endian). The image is a byte map the test builds with the listed bytes at the object's address and nothing else.
- **SOFTA** — `examples/case_00_public/software_a.a2l` (a2ltool 2.6.0, ASAP2 1.60), parsed likewise.
- **TUBE** — `examples/case_00_public/BalanceTube_STMicro.a2l` (commented COMPU_METHOD headers `/* type */ TAB_VERB`).
- **C08** — the release case: `tools/synth/make_release_case.py` with seed 20260001 at 1 MiB into `tmp_path`; `firmware.a2l` and `firmware_issues.a2l` parsed by the app's parser; the image read from `firmware.s19` by the app's S19 loader; planned values from the generator's object list.
- **DEFC** — the definitions case (D-5 A): the generator's definitions case, seed 20260001, into `tmp_path`; its A2L parsed and its S19 loaded by the app's loaders; planned values from the generator's own object list.
- **INLINE** — an A2L the test writes into `tmp_path`: one PROJECT and MODULE, `MOD_COMMON` with `BYTE_ORDER MSB_FIRST`, RECORD_LAYOUTs `RL_U8`, `RL_S8`, `RL_U16`, `RL_S16`, `RL_U32`, `RL_F16`, `RL_F32`, `RL_F64` (`FNC_VALUES 1 <datatype> ROW_DIR DIRECT`), plus the objects, methods and tables the case names; parsed by the app's parser. A method written `CM(<type> <coeffs>)` is a COMPU_METHOD with that type, format `"%.3"`, unit `""` and those coefficients.

## Cases of the requirements

| Case | Objective | Class | Preconditions | Inputs | Expected result | Tests | Coverage | Result |
|---|---|---|---|---|---|---|---|---|
| R-A2L-DEF.1/1 | Verify that a VALUE with a non-TAB_VERB method is a number | normal | V171 | the definition of `ASAM.C.SCALAR.SWORD.IDENTICAL` | kind number, no refusal | | gap | not_run |
| R-A2L-DEF.1/2 | Verify that a scalar MEASUREMENT is a number | normal | V171 | the definition of `ASAM.M.SCALAR.UBYTE.IDENTICAL` | kind number | | gap | not_run |
| R-A2L-DEF.1/3 | Verify that NO_COMPU_METHOD gives a number | normal | SOFTA | the definition of the first MEASUREMENT whose method is `NO_COMPU_METHOD` | kind number | | gap | not_run |
| R-A2L-DEF.1/4 | Verify on case 08 | normal | C08 clean | the definition of `VALUE_0001` | kind number | | gap | not_run |
| R-A2L-DEF.2/1 | Verify a TAB_VERB VALUE whose method's long identifier is on its own line | normal | V171 | the definition of `ASAM.C.SCALAR.SWORD.TAB_VERB_DEFAULT_VALUE` | kind enum (base: `conversion_type` None, B line 6) | | gap | not_run |
| R-A2L-DEF.2/2 | Verify an a2ltool TAB_VERB object (long identifier on the /begin line) | normal | SOFTA | the definition of the first object whose method record has the type TAB_VERB | kind enum (base: 0 of 163 methods typed, B line 8) | | gap | not_run |
| R-A2L-DEF.2/3 | Verify a commented TAB_VERB header | normal | TUBE | the definition of the first object naming `esdl_model_GameControllerStatemachineStates` | kind enum (base: None, B line 9) | | gap | not_run |
| R-A2L-DEF.3/1 | Verify that an ASCII CHARACTERISTIC is a text | normal | V171 | the definition of the ASCII object at 0x810200 (`NUMBER 42`; the parser names it `UNKNOWN`, BL-I2-6) | kind text, byte length 42 | | gap | not_run |
| R-A2L-DEF.3/2 | Verify on case 08 | normal | C08 clean | the definition of `ASCII_0001` | kind text, byte length 32 | | gap | not_run |
| R-A2L-DEF.4/1 | Verify the refusal for a VAL_BLK | robustness | C08 clean | the definition of `VAL_BLK_0001` | refusal `A2L-DEF-KIND`, message `VAL_BLK_0001: the system has no definition for a VAL_BLK object`; address and byte length 256 still given | | gap | not_run |
| R-A2L-DEF.4/2 | Verify the refusal for a CURVE | robustness | C08 clean | `CURVE_0001` | `CURVE_0001: the system has no definition for a CURVE object` | | gap | not_run |
| R-A2L-DEF.4/3 | Verify the refusal for a MAP | robustness | C08 clean | `MAP_0001` | `MAP_0001: the system has no definition for a MAP object` | | gap | not_run |
| R-A2L-DEF.4/4 | Verify the refusal for a CUBOID | robustness | V171 | the first CUBOID CHARACTERISTIC | `<name>: the system has no definition for a CUBOID object` | | gap | not_run |
| R-A2L-DEF.4/5 | Verify the refusal for a MAP_BLOCK | robustness | INLINE: a `MAP_BLOCK` CHARACTERISTIC `MB` | `MB` | `MB: the system has no definition for a MAP_BLOCK object` | | gap | not_run |
| R-A2L-DEF.4/6 | Verify the refusal for a vendor kind | robustness | INLINE: a CHARACTERISTIC `VK` of kind `DIRECT_X` at 0x10 (B6 salvage keeps its address) | `VK` | `VK: the system has no definition for a DIRECT_X object` | | gap | not_run |
| R-A2L-DEF.4/7 | Verify the refusal for an array MEASUREMENT | robustness | V171 | `ASAM.M.MATRIX_DIM_16_1.UBYTE.IDENTICAL` | `ASAM.M.MATRIX_DIM_16_1.UBYTE.IDENTICAL: the system has no definition for a MATRIX_DIM 16 MEASUREMENT object` | | gap | not_run |
| R-A2L-DEF.5/1 | Verify that the first tag of a name is used | normal | INLINE: two UWORD VALUEs `DUP` at 0x10 and 0x20 | the definition of `DUP` | address 0x10 | | gap | not_run |
| R-A2L-DEF.5/2 | Verify on the duplicate of case 08 | normal | C08 `firmware_issues.a2l` | the definition of `VALUE_0001` | the address of the clean `VALUE_0001` (the generator's first object) | | gap | not_run |
| R-A2L-DEF.6/1 | Verify the refusal for an unknown name | robustness | V171 | `NO_SUCH_TAG` | refusal `A2L-DEF-NAME`, `NO_SUCH_TAG: no tag of that name in the A2L` | | gap | not_run |
| R-A2L-DEF.6/2 | Verify that the name is matched with its case | robustness | C08 clean | `value_0001` | `value_0001: no tag of that name in the A2L` | | gap | not_run |
| R-A2L-DEF.7/1 | Verify the refusal for no address | robustness | INLINE: a UBYTE MEASUREMENT `NA` with no ECU_ADDRESS | `NA` | refusal `A2L-DEF-ADDRESS`, `NA: the object has no address or no length` | | gap | not_run |
| R-A2L-DEF.7/2 | Verify the refusal for no length | robustness | INLINE: an ASCII CHARACTERISTIC `NL` at 0x10 with no NUMBER, MATRIX_DIM or LENGTH | `NL` | `NL: the object has no address or no length` | | gap | not_run |
| R-A2L-DEF.8/1 | Verify the refusal for an unreadable layout datatype | robustness | INLINE: a VALUE `ND` at 0x10 whose RECORD_LAYOUT `RL_X` has `FNC_VALUES 1 FOO ROW_DIR DIRECT` | `ND` | refusal `A2L-DEF-DATATYPE`, `ND: the object declares no datatype the system can read` | | gap | not_run |
| R-A2L-DEF.8/2 | Verify the refusal for an unknown MEASUREMENT datatype | robustness | INLINE: MEASUREMENT `NM` `FOO NO_COMPU_METHOD 0 0 0 1`, ECU_ADDRESS 0x10 | `NM` | `NM: the object declares no datatype the system can read` | | gap | not_run |
| R-A2L-DEF.9/1 | Verify the refusal for a length that is not the datatype's | robustness | INLINE: a UWORD VALUE `LX` at 0x10 with `LENGTH 4` | `LX` | refusal `A2L-DEF-LENGTH`, `LX: its length 4 differs from the 2 bytes of UWORD` | | gap | not_run |
| R-A2L-DEF.10/1 | Verify the type of a multi-line V171 method | normal | V171 | the method record of `CM.TAB_VERB.DEFAULT_VALUE` (via the definition of `ASAM.C.SCALAR.SWORD.TAB_VERB_DEFAULT_VALUE`) | conversion type TAB_VERB | | gap | not_run |
| R-A2L-DEF.10/2 | Verify the type of an IDENTICAL method | normal | V171 | `CM.IDENTICAL` (via `ASAM.C.SCALAR.UBYTE.IDENTICAL`) | IDENTICAL | | gap | not_run |
| R-A2L-DEF.10/3 | Verify the type of an a2ltool method | normal | SOFTA | the method of R-A2L-DEF.2/2 | TAB_VERB | | gap | not_run |
| R-A2L-DEF.10/4 | Verify the type of a commented header | normal | TUBE | `esdl_model_GameControllerStatemachineStates` | TAB_VERB | | gap | not_run |
| R-A2L-DEF.11/1 | Verify the refusal for an undeclared method | robustness | C08 `firmware_issues.a2l` | `MISSING_CM` | refusal `A2L-DEF-METHOD`, `MISSING_CM: the conversion method CM_MISSING is not declared in the A2L` (base: identity, B lines 32, 34) | | gap | not_run |
| R-A2L-DEF.12/1 | Verify the refusal for FORM | robustness | INLINE: UWORD VALUE `FX` naming `CM_F` (`FORM "%.1" ""`, `FORMULA "X1*2"`) | `FX` | refusal `A2L-DEF-CONVERSION`, `FX: the conversion type FORM of CM_F is not supported` | | gap | not_run |
| R-A2L-DEF.12/2 | Verify the refusal for an unlisted type | robustness | INLINE: `CM_Q` of type `FOO` | `QX` naming it | `QX: the conversion type FOO of CM_Q is not supported` | | gap | not_run |
| R-A2L-DEF.12/3 | Verify the refusal for a record with no type | robustness | INLINE: `/begin COMPU_METHOD CM_E "d"` with no further word | `EX` naming it | `EX: the conversion type (none) of CM_E is not supported` | | gap | not_run |
| R-A2L-DEF.13/1 | Verify the refusal for an enum with no table | robustness | INLINE: UBYTE VALUE `EN` naming `CM_V` (`TAB_VERB "%.0" ""`, no COMPU_TAB_REF) | `EN` | refusal `A2L-DEF-TABLE`, `EN: the table (none) of CM_V is not declared in the A2L` | | gap | not_run |
| R-A2L-DEF.13/2 | Verify the refusal for a dangling table | robustness | INLINE: `CM_V` with `COMPU_TAB_REF VT_GONE` | `EN` | `EN: the table VT_GONE of CM_V is not declared in the A2L` | | gap | not_run |
| R-A2L-DEF.14/1 | Verify the pairs of a V171 COMPU_VTAB | normal | V171 | the definition of `ASAM.C.SCALAR.SWORD.TAB_VERB_DEFAULT_VALUE` | entries (1, `SawTooth`), (2, `Square`), (3, `Sinus`) in that order | | gap | not_run |
| R-A2L-DEF.14/2 | Verify a negative raw first | normal | SOFTA | the enum definition using the COMPU_VTAB whose first pair is `-1 "…"` | first entry raw −1 | | gap | not_run |
| R-A2L-DEF.14/3 | Verify file order and a numeric text | normal | INLINE: `/begin COMPU_VTAB VT_A "" TAB_VERB 2` `2 "B"` `1 "10"` | the enum using `VT_A` | entries (2, `B`), (1, `10`) in that order; the second text is the string `10` (base: sorted and a float, R `a2l.py:916-920`) | | gap | not_run |
| R-A2L-DEF.15/1 | Verify the triples of a V171 COMPU_VTAB_RANGE | normal | V171 | `ASAM.C.SCALAR.SWORD.VTAB_RANGE_DEFAULT_VALUE` | 11 entries; first (0, 1, `Zero_to_one`); last (105, 105, `hundredfive`) | | gap | not_run |
| R-A2L-DEF.15/2 | Verify an a2ltool range table | normal | SOFTA | the enum using the first COMPU_VTAB_RANGE of the file | 5 entries, first (0, 0, the file's text) | | gap | not_run |
| R-A2L-DEF.16/1 | Verify the default text of a COMPU_VTAB | normal | V171 | `ASAM.C.SCALAR.SWORD.TAB_VERB_DEFAULT_VALUE` | default text `unknown signal type` | | gap | not_run |
| R-A2L-DEF.16/2 | Verify the default text of a range table | normal | V171 | `ASAM.C.SCALAR.SWORD.VTAB_RANGE_DEFAULT_VALUE` | `out of range value` | | gap | not_run |
| R-A2L-DEF.17/1 | Verify the refusal for a count of 0 | robustness | INLINE: `VT_0 "" TAB_VERB 0` | the enum using it, `E0` | refusal `A2L-DEF-TABLE-EMPTY`, `E0: the table VT_0 has no entries` | | gap | not_run |
| R-A2L-DEF.17/2 | Verify the refusal for a count that is not a number | robustness | INLINE: `VT_N "" TAB_VERB X` then `0 "A"` | `EN2` using it | `EN2: the table VT_N has no entries` | | gap | not_run |
| R-A2L-DEF.18/1 | Verify a hexadecimal mask | normal | V171 | `ASAM.C.SCALAR.UWORD.IDENTICAL.BITMASK_0FF0` | bit mask 0x0FF0 | | gap | not_run |
| R-A2L-DEF.18/2 | Verify a decimal mask | normal | INLINE: UWORD VALUE `MD` with `BIT_MASK 16` | `MD` | bit mask 16 | | gap | not_run |
| R-A2L-DEF.18/3 | Verify a 24-bit mask on a ULONG | normal | SOFTA | the first MEASUREMENT with `BIT_MASK 0xFFFFFF` (ULONG) | bit mask 0xFFFFFF, no refusal | | gap | not_run |
| R-A2L-DEF.19/1 | Verify the refusal for mask 0 | robustness | INLINE: UWORD VALUE `M0` with `BIT_MASK 0` | `M0` | refusal `A2L-DEF-MASK`, `M0: the bit mask 0 cannot be applied to UWORD` | | gap | not_run |
| R-A2L-DEF.19/2 | Verify the refusal for a mask wider than the datatype | robustness | INLINE: UBYTE VALUE `MW` with `BIT_MASK 0x100` | `MW` | `MW: the bit mask 0x100 cannot be applied to UBYTE` | | gap | not_run |
| R-A2L-DEF.19/3 | Verify the refusal for a mask on a float | robustness | INLINE: FLOAT32_IEEE VALUE `MF` with `BIT_MASK 0x1` | `MF` | `MF: the bit mask 0x1 cannot be applied to FLOAT32_IEEE` | | gap | not_run |
| R-A2L-DEF.20/1 | Verify integer extended limits | normal | V171 | `ASAM.C.SCALAR.SBYTE.IDENTICAL` | extended limits −128..127; limits −100..100 | | gap | not_run |
| R-A2L-DEF.20/2 | Verify decimal extended limits | normal | V171 | the first object with `EXTENDED_LIMITS -10000.0 20000.0` | extended limits −10000.0..20000.0 | | gap | not_run |
| R-A2L-DEF.21/1 | Verify that one number gives no extended limits | robustness | INLINE: `XL1` with `EXTENDED_LIMITS 0` | `XL1` | no extended limits | | gap | not_run |
| R-A2L-DEF.21/2 | Verify that words give no extended limits | robustness | INLINE: `XL2` with `EXTENDED_LIMITS a b` | `XL2` | no extended limits | | gap | not_run |
| R-A2L-DEF.22/1 | Verify that FORMAT overrides the method format | normal | V171 | `ASAM.C.SCALAR.SBYTE.IDENTICAL` (`FORMAT "%6.1"`, method `%3.0`) | display format `%6.1` | | gap | not_run |
| R-A2L-DEF.22/2 | Verify FORMAT with a trailing comment | normal | V171 | `ASAM.M.SCALAR.UBYTE.IDENTICAL` (`FORMAT "%5.0"    /* Note: … */`) | `%5.0` | | gap | not_run |
| R-A2L-DEF.23/1 | Verify the method format as fallback | normal | V171 | `ASAM.C.SCALAR.UBYTE.IDENTICAL` (no FORMAT line) | `%3.0` | | gap | not_run |
| R-A2L-DEF.23/2 | Verify the format of a commented header | normal | TUBE | the object of R-A2L-DEF.2/3 | `%12.4` (base: None, B line 9) | | gap | not_run |
| R-A2L-DEF.24/1 | Verify kind before address | robustness | INLINE: MEASUREMENT `MA` with `MATRIX_DIM 4`, no ECU_ADDRESS | `MA` | `A2L-DEF-KIND` | | gap | not_run |
| R-A2L-DEF.24/2 | Verify address before method | robustness | INLINE: MEASUREMENT `AM` with no ECU_ADDRESS naming `CM_GONE` | `AM` | `A2L-DEF-ADDRESS` | | gap | not_run |
| R-A2L-DEF.24/3 | Verify table before mask | robustness | INLINE: UBYTE VALUE `TM` naming `CM_V` (`COMPU_TAB_REF VT_GONE`) with `BIT_MASK 0` | `TM` | `A2L-DEF-TABLE` | | gap | not_run |
| R-A2L-DEF.25/1 | Verify that decode gives the definition's refusal | robustness | C08 `firmware_issues.a2l` with the clean image | decode `MISSING_CM` | the `A2L-DEF-METHOD` refusal of R-A2L-DEF.11/1; no value | | gap | not_run |
| R-A2L-DEF.25/2 | Verify that encode gives the definition's refusal | robustness | as /1 | encode `7` | the same refusal; no bytes | | gap | not_run |
| R-A2L-DEF.26/1 | Verify the refusal for a missing byte at decode | robustness | INLINE: UWORD VALUE `MB2` at 0x10; image holds 0x10 only | decode | refusal `A2L-DEF-BYTES`, `MB2: 1 of its 2 bytes are not in the image` | | gap | not_run |
| R-A2L-DEF.26/2 | Verify the refusal for missing bytes at a masked encode | robustness | V171; an empty image | encode `35` on `ASAM.C.SCALAR.UWORD.IDENTICAL.BITMASK_0FF0` | `ASAM.C.SCALAR.UWORD.IDENTICAL.BITMASK_0FF0: 2 of its 2 bytes are not in the image` | | gap | not_run |
| R-A2L-DEF.27/1 | Verify a multi-bit field | normal | V171; image 34 12 at 0x810002 (word 0x1234) | decode `…BITMASK_0FF0` | stored value 35; display text `35` (base: 4660, B line 16) | | gap | not_run |
| R-A2L-DEF.27/2 | Verify a single-bit field | normal | V171; image 10 00 at 0x810002 | decode `…BITMASK_0010` | stored value 1 | | gap | not_run |
| R-A2L-DEF.27/3 | Verify that the field of a signed datatype is unsigned | normal | INLINE (big-endian): SWORD VALUE `SM` at 0x10, `BIT_MASK 0xFF00`, method none; image F0 F0 | decode | stored value 240 | | gap | not_run |
| R-A2L-DEF.28/1 | Verify the RAT_FUNC no-solution error | robustness | INLINE: UWORD VALUE `R1` with `CM(RAT_FUNC 0 0 5 0 0 1)`; image 00 07 | decode | refusal `A2L-DEF-DECODE`, `R1: RAT_FUNC has no solution for this value` | | gap | not_run |
| R-A2L-DEF.28/2 | Verify the RAT_FUNC no-real-root error | robustness | INLINE: `R2` with `CM(RAT_FUNC 1 0 1 0 0 1)`; image 00 00 | decode | `R2: RAT_FUNC has no real root for this value` | | gap | not_run |
| R-A2L-DEF.28/3 | Verify the RAT_FUNC zero-denominator error | robustness | INLINE: `R3` with `CM(RAT_FUNC 0 1 0 0 1 0)`; image 00 01 | decode | `R3: RAT_FUNC root has a zero denominator` | | gap | not_run |
| R-A2L-DEF.29/1 | Verify the first of two entries with one raw | robustness | INLINE: `VT_D "" TAB_VERB 2` `1 "A"` `1 "B"`; UBYTE enum `ED` at 0x10; image 01 | decode | display text `A` | | gap | not_run |
| R-A2L-DEF.30/1 | Verify a range's min | normal | V171; image 00 00 at 0x810004 | decode `ASAM.C.SCALAR.SWORD.VTAB_RANGE_DEFAULT_VALUE` | `Zero_to_one` | | gap | not_run |
| R-A2L-DEF.30/2 | Verify a range's max | normal | V171; image 01 00 | as /1 | `Zero_to_one` | | gap | not_run |
| R-A2L-DEF.30/3 | Verify inside a range | normal | V171; image 05 00 | as /1 | `four_to_seven` | | gap | not_run |
| R-A2L-DEF.30/4 | Verify a one-value range | normal | V171; image 64 00 | as /1 | `hundred` | | gap | not_run |
| R-A2L-DEF.31/1 | Verify the default text of a COMPU_VTAB | robustness | V171; image 09 00 | decode `ASAM.C.SCALAR.SWORD.TAB_VERB_DEFAULT_VALUE` | `unknown signal type` | | gap | not_run |
| R-A2L-DEF.31/2 | Verify the default text of a range table | robustness | V171; image 0A 00 | decode `…VTAB_RANGE_DEFAULT_VALUE` | `out of range value` | | gap | not_run |
| R-A2L-DEF.32/1 | Verify an unmatched value with no default (pairs) | robustness | V171; image 01 00 | decode `ASAM.C.SCALAR.SWORD.TAB_VERB_NO_DEFAULT_VALUE` | `1 (no text)` | | gap | not_run |
| R-A2L-DEF.32/2 | Verify an unmatched value with no default (ranges) | robustness | V171; image 0A 00 | decode `ASAM.C.SCALAR.SWORD.VTAB_RANGE_NO_DEFAULT_VALUE` | `10 (no text)` | | gap | not_run |
| R-A2L-DEF.33/1 | Verify a 0x00-ended text | normal | V171; image `Hello ASAM` + 32 × 00 at 0x810200 | decode the ASCII object | `Hello ASAM` (base: 72, B line 24) | | gap | not_run |
| R-A2L-DEF.33/2 | Verify a case 08 text | normal | C08 clean | decode `ASCII_0001` | the planned string of `ASCII_0001` | | gap | not_run |
| R-A2L-DEF.33/3 | Verify a text with no 0x00 | normal | V171; image 42 × `A` | decode the ASCII object | 42 × `A` | | gap | not_run |
| R-A2L-DEF.34/1 | Verify a control byte | robustness | V171; image `AB` 07 `C` 00 … | decode the ASCII object | `AB�C` | | gap | not_run |
| R-A2L-DEF.34/2 | Verify bytes above 0x7E | robustness | V171; image C3 A9 00 … | decode the ASCII object | `��` | | gap | not_run |
| R-A2L-DEF.35/1 | Verify two decimals | normal | INLINE: UWORD `D1` with `CM(LINEAR 0.1 0)`, `FORMAT "%4.2"`; image 00 7B | decode | `12.30` | | gap | not_run |
| R-A2L-DEF.35/2 | Verify zero decimals, a tie | normal | INLINE: FLOAT64 `D2`, method none, `FORMAT "%.0"`; image of 2.5 | decode | `2` | | gap | not_run |
| R-A2L-DEF.35/3 | Verify four decimals | normal | INLINE: FLOAT64 `D3`, `FORMAT "%8.4"`; image of 3.14159 | decode | `3.1416` | | gap | not_run |
| R-A2L-DEF.35/4 | Verify an exact binary tie | normal | INLINE: FLOAT64 `D4`, `FORMAT "%.2"`; image of 0.125 | decode | `0.12` | | gap | not_run |
| R-A2L-DEF.36/1 | Verify the cap at 17 decimals | robustness | INLINE: FLOAT64 `D5`, `FORMAT "%.40"`; image of 0.1 | decode | `0.10000000000000001` | | gap | not_run |
| R-A2L-DEF.37/1 | Verify no format | robustness | INLINE: UWORD `D6` with `CM(LINEAR 0.1 0)` whose format word is `""`; image 00 03 | decode | `0.3` | | gap | not_run |
| R-A2L-DEF.37/2 | Verify `%` | robustness | INLINE: FLOAT64 `D7`, `FORMAT "%"`; image of 1234567.0 | decode | `1234567` | | gap | not_run |
| R-A2L-DEF.37/3 | Verify a length with no decimals | robustness | INLINE: FLOAT64 `D8`, `FORMAT "%12"`; image of 1e-07 | decode | `1e-07` | | gap | not_run |
| R-A2L-DEF.37/4 | Verify an unreadable format | robustness | INLINE: FLOAT64 `D9`, `FORMAT "x5.1"`; image of 12.5 | decode | `12.5` | | gap | not_run |
| R-A2L-DEF.38/1 | Verify integer text under many decimals | robustness | SOFTA | decode the MEASUREMENT of R-A2L-DEF.1/3 (SWORD, `NO_COMPU_METHOD`, `FORMAT "%.15"`) over an image of −5 | `-5` | | gap | not_run |
| R-A2L-DEF.38/2 | Verify integer text of an IDENTICAL field | robustness | V171; image as R-A2L-DEF.27/1 | decode `…BITMASK_0FF0` (`%5.0`) | `35` | | gap | not_run |
| R-A2L-DEF.39/1 | Verify NaN | robustness | INLINE: FLOAT32 `F1`, `FORMAT "%.2"`; image 7F C0 00 00 | decode | `nan` | | gap | not_run |
| R-A2L-DEF.39/2 | Verify +inf | robustness | as /1; image 7F 80 00 00 | decode | `inf` | | gap | not_run |
| R-A2L-DEF.39/3 | Verify −inf | robustness | as /1; image FF 80 00 00 | decode | `-inf` | | gap | not_run |
| R-A2L-DEF.40/1 | Verify the refusal for an empty text | robustness | V171 | encode `` on `ASAM.C.SCALAR.SWORD.IDENTICAL` | refusal `A2L-DEF-NUMBER`, `ASAM.C.SCALAR.SWORD.IDENTICAL: '' is not a number` | | gap | not_run |
| R-A2L-DEF.40/2 | Verify letters | robustness | as /1 | `abc` | `…: 'abc' is not a number` | | gap | not_run |
| R-A2L-DEF.40/3 | Verify a decimal comma | robustness | as /1 | `1,5` | `…: '1,5' is not a number` | | gap | not_run |
| R-A2L-DEF.40/4 | Verify an underscore | robustness | as /1 | `1_000` | `…: '1_000' is not a number` (base: `float()` takes it) | | gap | not_run |
| R-A2L-DEF.40/5 | Verify nan | robustness | as /1 | `nan` | `…: 'nan' is not a number` | | gap | not_run |
| R-A2L-DEF.40/6 | Verify inf | robustness | as /1 | `inf` | `…: 'inf' is not a number` | | gap | not_run |
| R-A2L-DEF.40/7 | Verify hexadecimal | robustness | as /1 | `0x10` | `…: '0x10' is not a number` | | gap | not_run |
| R-A2L-DEF.41/1 | Verify no conversion | normal | INLINE: UBYTE `N0` at 0x10, `NO_COMPU_METHOD`, limits 0..255 | encode `7` | bytes 07 | | gap | not_run |
| R-A2L-DEF.41/2 | Verify IDENTICAL, with spaces and a sign | normal | V171 | encode `  -5 ` on `ASAM.C.SCALAR.SWORD.IDENTICAL` | bytes FB FF (stored −5) | | gap | not_run |
| R-A2L-DEF.41/3 | Verify LINEAR with an offset | normal | C08 clean | encode `150` on the first UWORD object with `CM_LIN_OFF` (a = 1, b = 100) | stored 50 | | gap | not_run |
| R-A2L-DEF.41/4 | Verify RAT_FUNC | normal | C08 clean | encode `100` on the first UWORD object with `CM_RAT` | stored 75 | | gap | not_run |
| R-A2L-DEF.41/5 | Verify TAB_NOINTP | normal | C08 clean | encode `15` on the first object with `CM_TAB_NOINTP` | stored 3 | | gap | not_run |
| R-A2L-DEF.41/6 | Verify TAB_INTP, and the forms `+2e1`, `.5`, `1.` | normal | C08 clean | encode `20`, `+2e1` on the first object with `CM_TAB_INTP`; `.5` and `1.` on an object with `CM_LIN_10` whose stored values allow them | `20` and `+2e1` → stored 200; `.5` and `1.` accepted as 0.5 and 1.0 (refused only by the encode direction, never as number texts) | | gap | not_run |
| R-A2L-DEF.42/1 | Verify `LINEAR conversion coefficient a is zero` | robustness | INLINE: SWORD `E1` with `CM(LINEAR 0 5)`, limits −1000..1000 | encode `5` | refusal `A2L-DEF-ENCODE`, `E1: LINEAR conversion coefficient a is zero` | | gap | not_run |
| R-A2L-DEF.42/2 | Verify `RAT_FUNC denominator is zero` | robustness | INLINE: UWORD `E2` with `CM(RAT_FUNC 0 1 0 0 0 0)` | encode `3` | `E2: RAT_FUNC denominator is zero` | | gap | not_run |
| R-A2L-DEF.42/3 | Verify `lookup table missing or empty` | robustness | INLINE: UWORD `E3` with `CM(TAB_NOINTP)` and `COMPU_TAB_REF TB_GONE` | encode `1` | `E3: lookup table missing or empty` | | gap | not_run |
| R-A2L-DEF.42/4 | Verify `lookup table has no numeric entries` | robustness | INLINE: `E4` with `CM(TAB_INTP)` naming a COMPU_TAB whose pairs are `0 "a"`, `1 "b"` | encode `1` | `E4: lookup table has no numeric entries` | | gap | not_run |
| R-A2L-DEF.42/5 | Verify the TAB_NOINTP nearest values | robustness | C08 clean | encode `12` on the object of R-A2L-DEF.41/5 | `<name>: the value 12.0 is not a table value - the nearest table values are 10.0 and 15.0` | | gap | not_run |
| R-A2L-DEF.42/6 | Verify the TAB_INTP range | robustness | C08 clean | encode `45` on the object of R-A2L-DEF.41/6 | `<name>: the value 45.0 is outside the table range [0.0, 40.0]` | | gap | not_run |
| R-A2L-DEF.42/7 | Verify `the converted raw value is not finite` | robustness | INLINE: FLOAT64 `E7` with `CM(LINEAR 1e-300 0)`, limits −1e308..1e308 | encode `1e300` | `E7: the converted raw value is not finite` | | gap | not_run |
| R-A2L-DEF.42/8 | Verify `not integral` | robustness | INLINE: SWORD `E8` with `CM(LINEAR 2 0)`, limits −1000..1000 | encode `3` | `E8: the converted raw value 1.5 is not integral` (B line 26) | | gap | not_run |
| R-A2L-DEF.42/9 | Verify the datatype range | robustness | INLINE: SWORD `E9` with `CM(LINEAR 2 0)`, limits −1e10..1e10 | encode `1e9` | `E9: the converted raw value 500000000 is outside the SWORD range` (B line 28) | | gap | not_run |
| R-A2L-DEF.42/10 | Verify FLOAT16 | robustness | INLINE: FLOAT16_IEEE `E10`, method none | encode `1.0` | `E10: datatype FLOAT16_IEEE is not supported` (B line 31) | | gap | not_run |
| R-A2L-DEF.42/11 | Verify a float that does not pack | robustness | INLINE: FLOAT32_IEEE `E11`, method none, no limits | encode `1e39` | `E11: the raw value does not pack as FLOAT32_IEEE: float too large to pack with f format` | | gap | not_run |
| R-A2L-DEF.43/1 | Verify below the lower limit | robustness | INLINE: SWORD `L1` with `CM(LINEAR 2 0)`, limits −100..100, no EXTENDED_LIMITS | encode `-101` | refusal `A2L-DEF-LIMITS`, `L1: -101 is outside the limits -100..100` (base: flag and proceed, B line 27) | | gap | not_run |
| R-A2L-DEF.43/2 | Verify above the upper limit | robustness | as /1 | encode `200` | `L1: 200 is outside the limits -100..100` | | gap | not_run |
| R-A2L-DEF.43/3 | Verify one declared side | robustness | INLINE: MEASUREMENT `L3` UBYTE `NO_COMPU_METHOD 0 0 x 100` (the lower limit word is not a number), ECU_ADDRESS 0x10 | encode `101` | `L3: 101 is outside the limits ..100` | | gap | not_run |
| R-A2L-DEF.43/4 | Verify an enum entry above the limits | robustness | V171; image 00 at 0x13A00's object | encode `hundredtwo` on `ASAM.M.SCALAR.UBYTE.VTAB_RANGE_NO_DEFAULT_VALUE` (limits 0..101) | `ASAM.M.SCALAR.UBYTE.VTAB_RANGE_NO_DEFAULT_VALUE: hundredtwo is outside the limits 0..101` | | gap | not_run |
| R-A2L-DEF.44/1 | Verify the notice above the limits | robustness | V171 | encode `120` on `ASAM.C.SCALAR.SBYTE.IDENTICAL` | bytes 78; notice `ASAM.C.SCALAR.SBYTE.IDENTICAL: 120 is outside the limits -100..100 and inside the extended limits -128..127` | | gap | not_run |
| R-A2L-DEF.44/2 | Verify the notice at the extended lower limit | robustness | V171 | encode `-128` on the same | bytes 80; notice `…: -128 is outside the limits -100..100 and inside the extended limits -128..127` | | gap | not_run |
| R-A2L-DEF.45/1 | Verify below the extended limits | robustness | V171 | encode `-129` on `ASAM.C.SCALAR.SBYTE.IDENTICAL` | refusal `A2L-DEF-EXTENDED`, `ASAM.C.SCALAR.SBYTE.IDENTICAL: -129 is outside the extended limits -128..127` | | gap | not_run |
| R-A2L-DEF.45/2 | Verify above the extended limits | robustness | V171 | encode `257` on `ASAM.C.SCALAR.UBYTE.IDENTICAL` | `ASAM.C.SCALAR.UBYTE.IDENTICAL: 257 is outside the extended limits 0..256` | | gap | not_run |
| R-A2L-DEF.46/1 | Verify a multi-bit write | normal | V171; image 0F F0 at 0x810002 (word 0xF00F) | encode `35` on `…BITMASK_0FF0` | bytes 3F F2 (word 0xF23F) (base: 23 00, B line 17) | | gap | not_run |
| R-A2L-DEF.46/2 | Verify a single-bit write | normal | V171; image 34 12 | encode `1` on `…BITMASK_0001` | bytes 35 12 | | gap | not_run |
| R-A2L-DEF.46/3 | Verify two fields of one big-endian word | normal | DEFC | encode a new value on the multi-bit object, then decode both masked objects over the image with those bytes applied | the multi-bit object decodes to the new value; the single-bit object to its planned value | | gap | not_run |
| R-A2L-DEF.47/1 | Verify a value wider than the mask | robustness | V171; image 0F F0 | encode `256` on `…BITMASK_0FF0` | refusal `A2L-DEF-MASK-VALUE`, `ASAM.C.SCALAR.UWORD.IDENTICAL.BITMASK_0FF0: 256 does not fit the bit mask 0x0FF0` | | gap | not_run |
| R-A2L-DEF.47/2 | Verify a negative value | robustness | INLINE: SWORD `MN` at 0x10, `BIT_MASK 0x00F0`, limits −100..100; image 00 00 | encode `-1` | `MN: -1 does not fit the bit mask 0x00F0` | | gap | not_run |
| R-A2L-DEF.47/3 | Verify a non-contiguous mask | robustness | INLINE: UBYTE `MC` at 0x10, `BIT_MASK 0x0A`; image 00 | encode `2` (bit 2 once shifted by 1) | `MC: 2 does not fit the bit mask 0x0A`; encode `5` → bytes 0A (normal control) | | gap | not_run |
| R-A2L-DEF.48/1 | Verify a COMPU_VTAB text | normal | V171 | encode `Square` on `ASAM.C.SCALAR.SWORD.TAB_VERB_DEFAULT_VALUE` | bytes 02 00 (base: refused, B line 29) | | gap | not_run |
| R-A2L-DEF.48/2 | Verify a range text | normal | V171 | encode `four_to_seven` on `…VTAB_RANGE_DEFAULT_VALUE` | bytes 04 00 | | gap | not_run |
| R-A2L-DEF.48/3 | Verify the first of two entries with one text | normal | INLINE: `VT_X "" TAB_VERB 2` `1 "X"` `2 "X"`; UBYTE enum `EX2` | encode `X` | bytes 01 | | gap | not_run |
| R-A2L-DEF.49/1 | Verify that case counts | robustness | V171 | encode `square` on `…TAB_VERB_DEFAULT_VALUE` | refusal `A2L-DEF-ENUM`, `ASAM.C.SCALAR.SWORD.TAB_VERB_DEFAULT_VALUE: 'square' is not a text of CM.TAB_VERB.DEFAULT_VALUE.REF` | | gap | not_run |
| R-A2L-DEF.49/2 | Verify that the default text is not an entry | robustness | V171 | encode `unknown signal type` | `…: 'unknown signal type' is not a text of CM.TAB_VERB.DEFAULT_VALUE.REF` | | gap | not_run |
| R-A2L-DEF.49/3 | Verify an empty text | robustness | V171 | encode `` | `…: '' is not a text of CM.TAB_VERB.DEFAULT_VALUE.REF` | | gap | not_run |
| R-A2L-DEF.50/1 | Verify a short text and its padding | normal | V171; image 42 × `Z` | encode `ABC` on the ASCII object | bytes 41 42 43 then 39 × 00 (42 bytes) | | gap | not_run |
| R-A2L-DEF.50/2 | Verify a text of the full length | normal | V171 | encode a 42-character text | those 42 bytes, no 00 | | gap | not_run |
| R-A2L-DEF.50/3 | Verify an empty text | normal | V171 | encode `` | 42 × 00 | | gap | not_run |
| R-A2L-DEF.51/1 | Verify the refusal for a text too long | robustness | V171 | encode a 43-character text | refusal `A2L-DEF-TEXT-LENGTH`, `<name>: the text has 43 characters — at most 42 fit` | | gap | not_run |
| R-A2L-DEF.52/1 | Verify a non-ASCII letter | robustness | V171 | encode `café` | refusal `A2L-DEF-TEXT-CHAR`, `<name>: 'é' is not a printable ASCII character` | | gap | not_run |
| R-A2L-DEF.52/2 | Verify a tab | robustness | V171 | encode `A\tB` | `<name>: '\t' is not a printable ASCII character` (the tab character itself between the quotes) | | gap | not_run |
| R-A2L-DEF.52/3 | Verify U+FFFD | robustness | V171 | encode `A�` | `<name>: '�' is not a printable ASCII character` | | gap | not_run |
| R-A2L-DEF.53/1 | Verify the span of a big-endian UWORD | normal | INLINE (big-endian): UWORD `B1` at 0x20 | encode `4660` | address 0x20, bytes 12 34 | | gap | not_run |
| R-A2L-DEF.53/2 | Verify the span of a little-endian UWORD | normal | INLINE: UWORD `B2` at 0x20 with `BYTE_ORDER MSB_LAST` | encode `4660` | address 0x20, bytes 34 12 | | gap | not_run |
| R-A2L-DEF.53/3 | Verify the span of a text | normal | V171 | encode `ABC` on the ASCII object | address 0x810200, 42 bytes | | gap | not_run |
| R-A2L-DEF.53/4 | Verify the span of a masked UWORD | normal | V171; image 0F F0 | encode `35` on `…BITMASK_0FF0` | address 0x810002, 2 bytes (the word, not the field) | | gap | not_run |
| R-A2L-DEF.54/1 | Verify the precision refusal | robustness | C08 clean, the object of R-A2L-DEF.41/6 given `FORMAT "%.3"` (the case's A2L with that one line added) | encode `5.07` | refusal `A2L-DEF-PRECISION`, `<name>: 5.07 cannot be stored at the display precision — the nearest stored value is 5.100` | | gap | not_run |
| R-A2L-DEF.54/2 | Verify that the same value passes at one decimal | robustness | C08 clean, that object as generated (`"%.1f"`) | encode `5.07` | accepted; stored 51; no notice | | gap | not_run |
| R-A2L-DEF.55/1 | Verify the number round trip | normal | INLINE grid (each conversion of R-A2L-DEF.41 × the datatypes it allows of UBYTE, SWORD, ULONG, FLOAT32_IEEE, FLOAT64_IEEE × MSB_FIRST and MSB_LAST × formats `%.0`, `%8.4`, none; the integer datatypes also with a multi-bit and a one-bit mask: 0x0FF0 and 0x0001, UBYTE 0x0F and 0x01) | for each object: the 17-significant-digit text of the decoded value of ≥ 3 stored values, and ≥ 2 typed decimals; encode, then decode the bytes | ≥ 300 accepted values; 0 that do not agree at the display precision; 0 refused for precision among those taken from decoded stored values | | gap | not_run |
| R-A2L-DEF.56/1 | Verify the text round trip | normal | V171, C08 clean | every entry text of `CM.TAB_VERB.DEFAULT_VALUE.REF`, `CM.TAB_VERB.NO_DEFAULT_VALUE.REF`, `CM.VTAB_RANGE.DEFAULT_VALUE.REF` (raw held by no earlier entry) on an object using it; the 10 planned strings on case 08's ASCII objects; `` and a 42-character text on V171's ASCII object; encode, then decode the bytes | 0 texts that come back different (≥ 32 texts) | | gap | not_run |
| R-A2L-DEF.57/1 | Verify text length before characters | robustness | V171 | encode a 43-character text holding `é` on the ASCII object | `A2L-DEF-TEXT-LENGTH` | | gap | not_run |
| R-A2L-DEF.57/2 | Verify limits before the encode direction | robustness | INLINE: SWORD `L1` of R-A2L-DEF.43/1 | encode `301` | `A2L-DEF-LIMITS` | | gap | not_run |
| R-A2L-DEF.57/3 | Verify image bytes before the mask | robustness | INLINE: `MN` of R-A2L-DEF.47/2; an empty image | encode `-1` | `A2L-DEF-BYTES` | | gap | not_run |
| R-A2L-DEF.58/1 | Verify that V171 and its image are unchanged | normal | V171 with an image holding every defined object | build, decode and encode (its own decoded text) every defined object | a deep copy of the parse payload and of the image taken before equals both after | | gap | not_run |
| R-A2L-DEF.58/2 | Verify that case 08 is unchanged | normal | C08 clean | as /1 over every defined object | as /1 | | gap | not_run |
| R-A2L-DEF.59/1 | Verify the 1 MiB pin | normal | the generator of the tree under test | seed 20260001, `--size-mb 1`, no case option, into `tmp_path` | the 11 SHA-256 values of the `1 \|` rows of `evidence-e1/i2e1-case08-hashes-transcript.txt`, each over the bytes with CR LF read as LF (PR lane) | | gap | not_run |
| R-A2L-DEF.59/2 | Verify the 10 MiB pin | normal | as /1 | `--size-mb 10` | the 11 values of the `10 \|` rows (`slow`) | | gap | not_run |
| R-A2L-DEF.60/1 | Verify the definitions case's enum | normal | DEFC | the case's enum object and its COMPU_VTAB | ≥ 3 pairs; a DEFAULT_VALUE; the definition's kind enum; decode → the text of the planned pair | | gap | not_run |
| R-A2L-DEF.61/1 | Verify the definitions case's two masks | normal | DEFC | the two masked objects | one address; masks disjoint; popcounts 1 and ≥ 2; decode → the planned fields | | gap | not_run |
| R-A2L-DEF.62/1 | Verify the definitions case's display object | normal | DEFC | the object with FORMAT, PHYS_UNIT and EXTENDED_LIMITS | the three lines present; extended lower < lower and extended upper > upper; the definition's unit is the PHYS_UNIT text | | gap | not_run |
| R-A2L-DEF.63/1 | Verify that the definitions case is deterministic | normal | the generator | the definitions case twice, seed 20260001, into two folders | every file byte-identical | | gap | not_run |

## Cases of the cited canon rows (the definition model must meet them; rows unchanged)

| Case | Objective | Class | Preconditions | Inputs | Expected result | Tests | Coverage | Result |
|---|---|---|---|---|---|---|---|---|
| R-A2L-010/def-1 | Verify the address from a CHARACTERISTIC header | normal | V171 | the definition of `ASAM.C.SCALAR.SWORD.IDENTICAL` | address 0x810004 | | gap | not_run |
| R-A2L-011/def-1 | Verify the address from ECU_ADDRESS | normal | V171 | `ASAM.M.SCALAR.UBYTE.IDENTICAL` | address 0x13A00 | | gap | not_run |
| R-A2L-022/def-1 | Verify the datatype from the record layout | normal | V171 | `ASAM.C.SCALAR.SWORD.IDENTICAL` (`RL.FNC.SWORD.ROW_DIR`) | datatype SWORD | | gap | not_run |
| R-A2L-023/def-1 | Verify the datatype the deposit name spells | normal | INLINE: a VALUE `DS` with deposit `__SWORD_Z` and a RECORD_LAYOUT of that name naming no datatype; image FF FB (big-endian) | the definition; decode | datatype SWORD; display text `-5` (the tag table reads UWORD, S2 D2-8) | | gap | not_run |
| R-A2L-024/def-1 | Verify the tag's BYTE_ORDER | normal | C08 clean | `VALUE_0001` (`BYTE_ORDER MSB_FIRST`) | byte order big | | gap | not_run |
| R-A2L-025/def-1 | Verify the record layout's BYTE_ORDER | normal | INLINE: `RL_BL` with `BYTE_ORDER MSB_LAST`, a VALUE using it | the definition | byte order little | | gap | not_run |
| R-A2L-026/def-1 | Verify MOD_COMMON's BYTE_ORDER | normal | V171 | `ASAM.C.SCALAR.SWORD.IDENTICAL` | byte order little | | gap | not_run |
| R-A2L-027/def-1 | Verify the default byte order | normal | INLINE without MOD_COMMON BYTE_ORDER | a UWORD VALUE | byte order little | | gap | not_run |
| R-A2L-030/def-1 | Verify PHYS_UNIT | normal | SOFTA | the CHARACTERISTIC with `PHYS_UNIT "V"` (B line 18) | unit `V` (base: None) | | gap | not_run |
| R-A2L-030/def-2 | Verify a unit with a space | normal | INLINE: `PHYS_UNIT "deg C"` | the definition | unit `deg C` | | gap | not_run |
| R-A2L-031/def-1 | Verify the method's unit | normal | V171 | `ASAM.C.SCALAR.UBYTE.IDENTICAL` (no PHYS_UNIT; `CM.IDENTICAL` unit `hours`) | unit `hours` | | gap | not_run |
| R-A2L-033/def-1 | Verify a unit on the /begin line | normal | INLINE: `/begin COMPU_METHOD CM_B "d" LINEAR "%.1" "km/h"` with `COEFFS_LINEAR 1 0` | a VALUE naming it | unit `km/h`, display format `%.1` | | gap | not_run |
| R-A2L-040/def-1 | Verify the raw bytes are read from the image | normal | V171; image 34 12 at 0x810004 | decode `ASAM.C.SCALAR.SWORD.IDENTICAL` | stored value 4660 | | gap | not_run |
| R-A2L-043/def-1 | Verify the byte order of the read | normal | INLINE (big-endian) UWORD; image 12 34 | decode | 4660 | | gap | not_run |
| R-A2L-044/def-1 | Verify two's complement | normal | V171; image FB FF at 0x810004 | decode `ASAM.C.SCALAR.SWORD.IDENTICAL` | `-5` | | gap | not_run |
| R-A2L-045/def-1 | Verify FLOAT16 | normal | INLINE: FLOAT16_IEEE VALUE (big-endian), method none; image 3C 00 | decode | 1.0 (base: no value, B line 25) | | gap | not_run |
| R-A2L-045/def-2 | Verify FLOAT32 | normal | INLINE: FLOAT32_IEEE; image 3F C0 00 00 | decode | 1.5 | | gap | not_run |
| R-A2L-045/def-3 | Verify FLOAT64 | normal | INLINE: FLOAT64_IEEE; image of −2.25 | decode | −2.25 | | gap | not_run |
| R-A2L-051/def-1 | Verify NO_COMPU_METHOD | normal | INLINE: UBYTE `NO_COMPU_METHOD`; image 07 | decode | 7 | | gap | not_run |
| R-A2L-053/def-1 | Verify IDENTICAL | normal | V171; image 07 00 | decode `ASAM.C.SCALAR.SWORD.IDENTICAL` | 7 | | gap | not_run |
| R-A2L-054/def-1 | Verify LINEAR | normal | C08 clean | decode the first object with `CM_LIN_OFF` | its planned physical value | | gap | not_run |
| R-A2L-055/def-1 | Verify LINEAR with b missing | normal | INLINE: `COEFFS_LINEAR 2` | decode stored 3 | 6.0 | | gap | not_run |
| R-A2L-056/def-1 | Verify RAT_FUNC | normal | C08 clean | decode the first object with `CM_RAT` | its planned physical value | | gap | not_run |
| R-A2L-057/def-1 | Verify the root inside the limits | normal | INLINE: `CM(RAT_FUNC 1 0 0 0 0 1)` (raw = p²), limits 0..10; image of 9 | decode | 3.0 | | gap | not_run |
| R-A2L-058.1/def-1 | Verify the no-solution error | robustness | as R-A2L-DEF.28/1 | decode | the message of R-A2L-DEF.28/1 | | gap | not_run |
| R-A2L-058.2/def-1 | Verify the no-real-root error | robustness | as R-A2L-DEF.28/2 | decode | the message of R-A2L-DEF.28/2 | | gap | not_run |
| R-A2L-058.3/def-1 | Verify the zero-denominator error | robustness | as R-A2L-DEF.28/3 | decode | the message of R-A2L-DEF.28/3 | | gap | not_run |
| R-A2L-059/def-1 | Verify the COMPU_VTAB text | normal | V171; image 02 00 at 0x810004 | decode `ASAM.C.SCALAR.SWORD.TAB_VERB_DEFAULT_VALUE` | `Square` (base: raw 2 with unknown method, B line 11) | | gap | not_run |
| R-A2L-059/def-2 | Verify the text of a masked enum | normal | INLINE: UWORD enum `ME` with `BIT_MASK 0x00F0` on `VT_M` (`0 "OFF"`, `1 "ON"`); image 00 10 (big-endian) | decode | `ON` | | gap | not_run |
| R-A2L-061/def-1 | Verify TAB_INTP | normal | C08 clean | decode the first object with `CM_TAB_INTP` | its planned physical value | | gap | not_run |
| R-A2L-062/def-1 | Verify TAB_INTP outside the table | normal | C08 clean, image holding 500 for that object | decode | 40.0 | | gap | not_run |
| R-A2L-063/def-1 | Verify TAB_NOINTP nearest | normal | C08 clean, image holding 6 for the object with `CM_TAB_NOINTP` | decode | 20.0 (raw 4 is nearest) | | gap | not_run |

## Acceptance cases (black-box at I-2, real shapes)

| Case | Objective | Class | Preconditions | Inputs | Expected result | Tests | Coverage | Result |
|---|---|---|---|---|---|---|---|---|
| AT-B103-I2-1 | Verify the ASAM demo's scalar kinds end to end (US-103-05) | normal | V171; an image holding `Hello ASAM` at the ASCII object, 0x1234 at 0x810002, 2 at 0x810004, 0 at 0x810000, 0x810001 | for `…TAB_VERB_DEFAULT_VALUE`, `…TAB_VERB_NO_DEFAULT_VALUE`, `…VTAB_RANGE_DEFAULT_VALUE`, `…BITMASK_0FF0`, `…BITMASK_0001`, `…BITMASK_0010`, the ASCII object, `ASAM.C.SCALAR.SBYTE.IDENTICAL`, `ASAM.C.SCALAR.UBYTE.IDENTICAL`, `ASAM.C.SCALAR.SWORD.IDENTICAL`: build, decode, encode a new accepted value, apply the bytes to the image, decode again | every object decodes to the text its A2L gives the bytes; after each write the object decodes to the new value; the three masked objects at 0x810002 keep each other's bits across the three writes — rows R-A2L-DEF.2, .3, .14, .15, .27, .30, .33, .44, .46, .48, .50, .55, .56 and cited R-A2L-059 | | gap | not_run |
| AT-B103-I2-2 | Verify the definitions case through the app's loaders (US-103-05) | normal | DEFC | each object of the case: build, decode, encode its planned value's text and a second value, apply, decode | each decodes first to its planned value, then to the second value; the image outside the written spans is unchanged — rows R-A2L-DEF.60, .61, .62 and .46, .55, .56 | | gap | not_run |
| AT-B103-I2-3 | Verify case 08 with the model (US-103-05) | normal | C08 clean and issues | build and decode every defined object of both A2Ls | 0 refusals on the clean A2L; on the issues A2L exactly one A2L-DEF-METHOD (`MISSING_CM`) and the A2L-DEF-BYTES refusals of the objects outside the image; the 22 case files equal the pin — rows R-A2L-DEF.11, .26, .58, .59 | | gap | not_run |

**Counts:** 169 cases of the 63 rows (S2.7a 63, S2.7b 36, S2.7c 64, S2.7d 6), 32 cases of 28 cited canon rows, and 3 acceptance cases: 204 cases. Negative controls (the mutant of each row, run at E5 in a copy of the tree): `01-requirements.md`, column "Negative control".
