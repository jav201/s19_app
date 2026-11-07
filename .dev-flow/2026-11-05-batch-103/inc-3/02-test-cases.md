# Inc 3 — test cases (ISO/IEC/IEEE 29119-3), E1

One case per coverage item `<requirement id>/<n>` of `01-requirements.md` (one alternative of one requirement), the cases of the cited rows the array model must meet, and the acceptance cases `AT-B103-I3-1` … `-4` (batch-scoped ids, outside the global pool). Written at E1, before any test: **Tests** is empty, **Coverage** is `gap` and **Result** is `not_run` everywhere; testers fill them at E4. Class: *normal* for a `When` or `U` row, *robustness* for an `If` row. Expected results are the requirement's exact values and texts. The model is pure: every case calls it directly (I-2 as extended, `E1-rulings.md` §4) — "the definition of N" is what the model builds for the name N; "decode" is the decode of every element and axis point over the case's image; "edit {p: t, …}" is the encode of that edit over the image; "single decode" / "single encode" are Inc 2's one-value calls.

Common fixtures (Inc 2's V171, SOFTA, C08 and DEFC as defined in `../inc-2/02-test-cases.md`, plus):
- **V171** — `examples/case_00_public/ASAP2_Demo_V171.a2l` (little-endian; `MOD_COMMON` `ALIGNMENT_BYTE 1`, `ALIGNMENT_WORD 2`, `ALIGNMENT_LONG 4`, `ALIGNMENT_FLOAT32_IEEE 4`, `ALIGNMENT_FLOAT64_IEEE 4`). Addresses used: `ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR` 0x810100, `…COLUMN_DIR` 0x810120, `…MATRIX_DIM_6.ROW_DIR` 0x810140, MEASUREMENTs `ASAM.M.MATRIX_DIM_*` 0x13A30, `ASAM.C.CURVE.STD_AXIS` 0x810300, `ASAM.C.CURVE.COM_AXIS` 0x810320, `ASAM.C.CURVE.COM_AXIS_2` 0x810330, axis object `ASAM.C.AXIS_PTS.UBYTE_8` 0x810340 (record `NO_AXIS_PTS_X` UBYTE + `AXIS_PTS_X` SBYTE INDEX_DECR, 9 bytes), `ASAM.C.CURVE.FIX_AXIS.PAR_DIST` 0x810350, `….PAR` 0x810360, `….PAR_LIST` 0x810370, `ASAM.C.MAP.STD_AXIS.STD_AXIS` 0x810400, `ASAM.C.MAP.COM_AXIS.FIX_AXIS` 0x810440. **AX8(c, p…)** = the axis object's record: count byte c then the 8 SBYTE bytes p (memory order).
- **SOFTA** — `examples/case_00_public/software_a.a2l` (a2ltool shapes; addresses 0x0, no image: building only).
- **CHECK**, **UPD1**, **UPD2** — `examples/case_00_public/check_test.a2l`, `update_test1.a2l`, `update_test2.a2l`, parsed by the app's parser.
- **C08** — case 08 at 1 MiB, seed 20260001 (Inc 2's), with the generator's object list as the plan (`raw_bytes` per object, values in memory order).
- **DEFC** — the definitions case with this increment's objects (R-A2L-DEF.133 … .135), its plan from the generator's object list.
- **INLINE3** — an A2L the test writes into `tmp_path`: one PROJECT and MODULE, `MOD_COMMON` with `BYTE_ORDER MSB_FIRST` and **no** ALIGNMENT line; Inc 2's INLINE record layouts and `CM(<type> <coeffs>)` methods; and, per case, the record layouts, objects, AXIS_DESCRs and AXIS_PTS objects the case names, every component line written in full (`<component> <position> <datatype> <mode or order> DIRECT`). A curve written `C(<axis>; <layout lines>)` is a UWORD CURVE CHARACTERISTIC at 0x100 with `CM_IDENT`, limits 0..65535, one AXIS_DESCR `<axis>`; `STD(n)` is `STD_AXIS NO_INPUT CM_IDENT <n> 0 255`. The image is a byte map the test builds.

## Cases of the requirements

| Case | Objective | Class | Preconditions | Inputs | Expected result | Tests | Coverage | Result |
|---|---|---|---|---|---|---|---|---|
| R-A2L-DEF.64/1 | Verify that a 2-D VAL_BLK is an array | normal | V171 | the definition of `ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR` | kind array, no refusal (base: Inc 2's A2L-DEF-KIND) | | gap | not_run |
| R-A2L-DEF.64/2 | Verify a 1-D VAL_BLK | normal | V171 | `ASAM.C.ARRAY.SWORD.MATRIX_DIM_6.ROW_DIR` | kind array | | gap | not_run |
| R-A2L-DEF.64/3 | Verify a MATRIX_DIM MEASUREMENT | normal | V171 | `ASAM.M.MATRIX_DIM_8_4_2.UBYTE.IDENTICAL` | kind array | | gap | not_run |
| R-A2L-DEF.64/4 | Verify an a2ltool VAL_BLK | normal | SOFTA | the first VAL_BLK of the file (`NUMBER 4`) | kind array | | gap | not_run |
| R-A2L-DEF.64/5 | Verify case 08's VAL_BLK | normal | C08 clean | `VAL_BLK_0001` | kind array | | gap | not_run |
| R-A2L-DEF.65/1 | Verify a COM_AXIS curve | normal | V171 | `ASAM.C.CURVE.COM_AXIS` | kind curve | | gap | not_run |
| R-A2L-DEF.65/2 | Verify a FIX_AXIS curve | normal | V171 | `ASAM.C.CURVE.FIX_AXIS.PAR_DIST` | kind curve | | gap | not_run |
| R-A2L-DEF.65/3 | Verify case 08's curve | normal | C08 clean | `CURVE_0001` | kind curve | | gap | not_run |
| R-A2L-DEF.66/1 | Verify a COM/FIX map | normal | V171 | `ASAM.C.MAP.COM_AXIS.FIX_AXIS` | kind map | | gap | not_run |
| R-A2L-DEF.66/2 | Verify case 08's map | normal | C08 clean | `MAP_0001` | kind map | | gap | not_run |
| R-A2L-DEF.66/3 | Verify the definitions case's map | normal | DEFC | its MAP | kind map | | gap | not_run |
| R-A2L-DEF.67/1 | Verify a 2-D shape | normal | V171 | `…MATRIX_DIM_3_4.ROW_DIR` | shape 3×4 (base: matrix_dim 3, B line 7) | | gap | not_run |
| R-A2L-DEF.67/2 | Verify a 1-D shape | normal | V171 | `…MATRIX_DIM_6.ROW_DIR` | shape 6 | | gap | not_run |
| R-A2L-DEF.67/3 | Verify a 3-D shape | normal | V171 | `ASAM.M.MATRIX_DIM_8_4_2.UBYTE.IDENTICAL` | shape 8×4×2 (base: 8, B line 9) | | gap | not_run |
| R-A2L-DEF.67/4 | Verify a trailing 1 | normal | V171 | `ASAM.M.MATRIX_DIM_16_1.UBYTE.IDENTICAL` | shape 16 | | gap | not_run |
| R-A2L-DEF.67/5 | Verify two trailing 1s | normal | SOFTA | the first MEASUREMENT with `MATRIX_DIM 8 1 1` | shape 8 | | gap | not_run |
| R-A2L-DEF.68/1 | Verify the a2ltool NUMBER | robustness | SOFTA | the first VAL_BLK (`NUMBER 4`) | shape 4 (base: no length, B line 11) | | gap | not_run |
| R-A2L-DEF.68/2 | Verify NUMBER 10 | robustness | INLINE3: UWORD VAL_BLK `VB10` at 0x10, `RL_U16`, `NUMBER 10` | `VB10` | shape 10 | | gap | not_run |
| R-A2L-DEF.69/1 | Verify case 08's LENGTH-only VAL_BLK | robustness | C08 clean | `VAL_BLK_0001` (`LENGTH 256`, UWORD) | shape 128 | | gap | not_run |
| R-A2L-DEF.69/2 | Verify a small LENGTH-only VAL_BLK | robustness | INLINE3: SWORD VAL_BLK `VS6`, `RL_S16`, `LENGTH 6` | `VS6` | shape 3 | | gap | not_run |
| R-A2L-DEF.70/1 | Verify the refusal for a length that is not whole values | robustness | INLINE3: UWORD VAL_BLK `VS`, `RL_U16`, `LENGTH 5` | `VS` | refusal `A2L-DEF-SHAPE`, `VS: its length 5 is not a whole number of UWORD values` | | gap | not_run |
| R-A2L-DEF.71/1 | Verify a 0 in MATRIX_DIM | robustness | INLINE3: UWORD VAL_BLK `VX`, `MATRIX_DIM 3 0` | `VX` | refusal `A2L-DEF-MATRIX`, `VX: MATRIX_DIM 3 0 is not 1 to 3 whole numbers of at least 1` | | gap | not_run |
| R-A2L-DEF.71/2 | Verify four numbers | robustness | INLINE3: `MATRIX_DIM 2 2 2 2` | `VX` | `VX: MATRIX_DIM 2 2 2 2 is not 1 to 3 whole numbers of at least 1` | | gap | not_run |
| R-A2L-DEF.71/3 | Verify a word | robustness | INLINE3: `MATRIX_DIM x` | `VX` | `VX: MATRIX_DIM x is not 1 to 3 whole numbers of at least 1` | | gap | not_run |
| R-A2L-DEF.71/4 | Verify an empty line | robustness | INLINE3: `MATRIX_DIM` alone | `VX` | `VX: MATRIX_DIM (none) is not 1 to 3 whole numbers of at least 1` | | gap | not_run |
| R-A2L-DEF.72/1 | Verify a curve's shape | normal | V171 | `ASAM.C.CURVE.FIX_AXIS.PAR_DIST` | shape 6 | | gap | not_run |
| R-A2L-DEF.72/2 | Verify a map's shape, X first | normal | V171 | `ASAM.C.MAP.COM_AXIS.FIX_AXIS` | shape 8×3 | | gap | not_run |
| R-A2L-DEF.72/3 | Verify case 08's map | normal | C08 clean | `MAP_0001` | shape 8×8 | | gap | not_run |
| R-A2L-DEF.73/1 | Verify the count of a 2-D array (PE-D1) | normal | V171 | `…MATRIX_DIM_3_4.ROW_DIR` | element count 12 (base: 1, B line 12) | | gap | not_run |
| R-A2L-DEF.73/2 | Verify a 3-D MEASUREMENT | normal | V171 | `…MATRIX_DIM_8_4_2…` | 64 | | gap | not_run |
| R-A2L-DEF.73/3 | Verify a COM_AXIS curve | normal | V171 | `ASAM.C.CURVE.COM_AXIS` | 8 | | gap | not_run |
| R-A2L-DEF.73/4 | Verify a COM/FIX map | normal | V171 | `ASAM.C.MAP.COM_AXIS.FIX_AXIS` | 24 | | gap | not_run |
| R-A2L-DEF.73/5 | Verify case 08's VAL_BLK | normal | C08 clean | `VAL_BLK_0001` | 128 | | gap | not_run |
| R-A2L-DEF.73/6 | Verify case 08's curve | normal | C08 clean | `CURVE_0001` | 32 | | gap | not_run |
| R-A2L-DEF.73/7 | Verify case 08's map | normal | C08 clean | `MAP_0001` | 64 | | gap | not_run |
| R-A2L-DEF.73/8 | Verify the count on a refused definition | normal | V171 | `ASAM.C.CURVE.STD_AXIS` | refusal A2L-DEF-ALIGNMENT; element count 8 | | gap | not_run |
| R-A2L-DEF.74/1 | Verify the byte length of a 2-D array | normal | V171 | `…MATRIX_DIM_3_4.ROW_DIR` | byte length 24 (base: None, B line 7) | | gap | not_run |
| R-A2L-DEF.74/2 | Verify a 3-D MEASUREMENT | normal | V171 | `…MATRIX_DIM_8_4_2…` | datatype UBYTE (the header's); byte length 64 (base: 8, B line 9) | | gap | not_run |
| R-A2L-DEF.74/3 | Verify an a2ltool VAL_BLK | normal | SOFTA | the first VAL_BLK | 4 × the size of its FNC_VALUES datatype | | gap | not_run |
| R-A2L-DEF.74/4 | Verify case 08's VAL_BLK | normal | C08 clean | `VAL_BLK_0001` | 256 | | gap | not_run |
| R-A2L-DEF.75/1 | Verify a COM_AXIS curve | normal | V171 | `ASAM.C.CURVE.COM_AXIS` | byte length 16 (base: None, B line 16) | | gap | not_run |
| R-A2L-DEF.75/2 | Verify a COM/FIX map | normal | V171 | `ASAM.C.MAP.COM_AXIS.FIX_AXIS` | 48 | | gap | not_run |
| R-A2L-DEF.75/3 | Verify case 08's curve | normal | C08 clean | `CURVE_0001` | 64 | | gap | not_run |
| R-A2L-DEF.75/4 | Verify case 08's map | normal | C08 clean | `MAP_0001` | 128 | | gap | not_run |
| R-A2L-DEF.76/1 | Verify a LENGTH that differs | robustness | INLINE3: UWORD VAL_BLK `VL`, `MATRIX_DIM 4`, `LENGTH 6` | `VL` | refusal `A2L-DEF-LENGTH`, `VL: its length 6 differs from the 8 bytes of 4 UWORD values` | | gap | not_run |
| R-A2L-DEF.76/2 | Verify a DATA_SIZE that differs | robustness | INLINE3: UBYTE MEASUREMENT `ML` at 0x10, `MATRIX_DIM 4 2`, `DATA_SIZE 4` | `ML` | `ML: its length 4 differs from the 8 bytes of 8 UBYTE values` | | gap | not_run |
| R-A2L-DEF.77/1 | Verify the values of a ROW_DIR VAL_BLK | normal | V171 | `…MATRIX_DIM_3_4.ROW_DIR` | values: SWORD, ROW_DIR, offset 0 | | gap | not_run |
| R-A2L-DEF.77/2 | Verify the COLUMN_DIR twin | normal | V171 | `…MATRIX_DIM_3_4.COLUMN_DIR` | SWORD, COLUMN_DIR, offset 0 | | gap | not_run |
| R-A2L-DEF.77/3 | Verify a curve whose layout starts with a count | normal | INLINE3: `CS` = C(STD(4); `NO_AXIS_PTS_X 1 UBYTE`, `AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT`, `FNC_VALUES 3 SWORD ROW_DIR DIRECT`) | `CS` | SWORD, ROW_DIR, offset 5 (base: the tag table reads UBYTE, B line 36) | | gap | not_run |
| R-A2L-DEF.78/1 | Verify LAYOUT COLUMN_DIR | normal | INLINE3: UBYTE MEASUREMENT `MC` at 0x10, `MATRIX_DIM 3 2`, `LAYOUT COLUMN_DIR` | `MC` | index mode COLUMN_DIR | | gap | not_run |
| R-A2L-DEF.78/2 | Verify LAYOUT ROW_DIR | normal | INLINE3: `MC` with `LAYOUT ROW_DIR` | `MC` | ROW_DIR | | gap | not_run |
| R-A2L-DEF.79/1 | Verify the default index mode | robustness | V171 | `ASAM.M.MATRIX_DIM_8_2.UBYTE.IDENTICAL` | ROW_DIR | | gap | not_run |
| R-A2L-DEF.80/1 | Verify the refusal for a 3-D COLUMN_DIR MEASUREMENT | robustness | INLINE3: UBYTE MEASUREMENT `M3`, `MATRIX_DIM 2 2 2`, `LAYOUT COLUMN_DIR` | `M3` | refusal `A2L-DEF-INDEX-MODE`, `M3: the system cannot read COLUMN_DIR in three dimensions` | | gap | not_run |
| R-A2L-DEF.80/2 | Verify a 3-D COLUMN_DIR VAL_BLK | robustness | INLINE3: UWORD VAL_BLK `V3`, `MATRIX_DIM 2 2 2`, layout `FNC_VALUES 1 UWORD COLUMN_DIR DIRECT` | `V3` | `V3: the system cannot read COLUMN_DIR in three dimensions` | | gap | not_run |
| R-A2L-DEF.81/1 | Verify an undeclared method on an array | robustness | INLINE3: UWORD VAL_BLK `VC`, `MATRIX_DIM 3`, method `CM_GONE` | `VC` | refusal `A2L-DEF-METHOD`, `VC: the conversion method CM_GONE is not declared in the A2L` | | gap | not_run |
| R-A2L-DEF.81/2 | Verify a dangling enum table on an array | robustness | INLINE3: UBYTE VAL_BLK `VT`, `MATRIX_DIM 2`, method `CM_V` (`TAB_VERB`, `COMPU_TAB_REF VT_GONE`) | `VT` | `VT: the table VT_GONE of CM_V is not declared in the A2L` | | gap | not_run |
| R-A2L-DEF.81/3 | Verify a zero mask on a map | robustness | INLINE3: UWORD MAP `MZ` with two STD axes (layout `AXIS_PTS_X 1 UWORD …`, `AXIS_PTS_Y 2 UWORD …`, `FNC_VALUES 3 UWORD ROW_DIR DIRECT`) and `BIT_MASK 0` | `MZ` | `MZ: the bit mask 0 cannot be applied to UWORD` | | gap | not_run |
| R-A2L-DEF.81/4 | Verify an unknown MEASUREMENT datatype | robustness | INLINE3: MEASUREMENT `MF` `FOO CM_IDENT 0 0 0 1`, `ECU_ADDRESS 0x10`, `MATRIX_DIM 4` | `MF` | `MF: the object declares no datatype the system can read` | | gap | not_run |
| R-A2L-DEF.82/1 | Verify an undeclared layout (real file) | robustness | CHECK | `Curve_ExternalAxis` | refusal `A2L-DEF-LAYOUT`, `Curve_ExternalAxis: the record layout Curve_ExternalAxis_RecordLayout is not declared in the A2L` | | gap | not_run |
| R-A2L-DEF.82/2 | Verify an undeclared layout on a VAL_BLK | robustness | INLINE3: UWORD VAL_BLK `VG`, layout `RL_GONE`, `MATRIX_DIM 2` | `VG` | `VG: the record layout RL_GONE is not declared in the A2L` | | gap | not_run |
| R-A2L-DEF.83/1 | Verify a layout with no FNC_VALUES | robustness | INLINE3: `CF` = C(STD(4); `AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT`), layout named `RL_AX` | `CF` | refusal `A2L-DEF-LAYOUT-VALUES`, `CF: the record layout RL_AX holds no FNC_VALUES` | | gap | not_run |
| R-A2L-DEF.84/1 | Verify RESERVED | robustness | INLINE3: `CP` = C(STD(2); `AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT`, `FNC_VALUES 2 UWORD ROW_DIR DIRECT`, `RESERVED 3 BYTE`), layout `RL_P` | `CP` | refusal `A2L-DEF-LAYOUT-PART`, `CP: the record layout RL_P holds RESERVED, which the system cannot read` | | gap | not_run |
| R-A2L-DEF.84/2 | Verify AXIS_RESCALE_X | robustness | INLINE3: as /1 with `AXIS_RESCALE_X 3 UBYTE 5 INDEX_INCR DIRECT` | `CP` | `… holds AXIS_RESCALE_X, which …` | | gap | not_run |
| R-A2L-DEF.84/3 | Verify IDENTIFICATION | robustness | INLINE3: as /1 with `IDENTIFICATION 3 UWORD` | `CP` | `… holds IDENTIFICATION, which …` | | gap | not_run |
| R-A2L-DEF.84/4 | Verify a Z axis on a curve | robustness | INLINE3: as /1 with `AXIS_PTS_Z 3 UBYTE INDEX_INCR DIRECT` | `CP` | `… holds AXIS_PTS_Z, which …` | | gap | not_run |
| R-A2L-DEF.84/5 | Verify SRC_ADDR_X | robustness | INLINE3: as /1 with `SRC_ADDR_X 3` | `CP` | `… holds SRC_ADDR_X, which …` | | gap | not_run |
| R-A2L-DEF.85/1 | Verify an ALTERNATE mode | robustness | INLINE3: VAL_BLK `VA`, `MATRIX_DIM 2`, layout `RL_A` = `FNC_VALUES 1 UWORD ALTERNATE_WITH_X DIRECT` | `VA` | refusal `A2L-DEF-LAYOUT-MODE`, `VA: the record layout RL_A stores FNC_VALUES as ALTERNATE_WITH_X, which the system cannot read` | | gap | not_run |
| R-A2L-DEF.85/2 | Verify an unknown point order | robustness | INLINE3: C(STD(2); `AXIS_PTS_X 1 UBYTE INDEX_X DIRECT`, `FNC_VALUES 2 UWORD ROW_DIR DIRECT`) | the curve | `… stores AXIS_PTS_X as INDEX_X, which …` | | gap | not_run |
| R-A2L-DEF.85/3 | Verify a pointer address type | robustness | INLINE3: `VA` with `FNC_VALUES 1 UWORD ROW_DIR PBYTE` | `VA` | `… stores FNC_VALUES as PBYTE, which …` | | gap | not_run |
| R-A2L-DEF.85/4 | Verify a missing mode | robustness | INLINE3: `VA` with `FNC_VALUES 1 UWORD` | `VA` | `… stores FNC_VALUES as (none), which …` | | gap | not_run |
| R-A2L-DEF.86/1 | Verify an unknown values datatype | robustness | INLINE3: VAL_BLK `VD`, `MATRIX_DIM 2`, layout `RL_D` = `FNC_VALUES 1 FOO ROW_DIR DIRECT` | `VD` | refusal `A2L-DEF-LAYOUT-DATATYPE`, `VD: the record layout RL_D gives FNC_VALUES the datatype FOO, which the system cannot read` | | gap | not_run |
| R-A2L-DEF.86/2 | Verify BYTE on an axis component | robustness | INLINE3: C(STD(2); `AXIS_PTS_X 1 BYTE INDEX_INCR DIRECT`, `FNC_VALUES 2 UWORD ROW_DIR DIRECT`), layout `RL_B` | the curve | `… gives AXIS_PTS_X the datatype BYTE, which …` | | gap | not_run |
| R-A2L-DEF.87/1 | Verify two components at one position | robustness | INLINE3: C(STD(2); `AXIS_PTS_X 2 UWORD INDEX_INCR DIRECT`, `FNC_VALUES 2 UWORD ROW_DIR DIRECT`), layout `RL_Q` | the curve | refusal `A2L-DEF-LAYOUT-POSITION`, `<name>: the positions of the record layout RL_Q do not give one order` | | gap | not_run |
| R-A2L-DEF.87/2 | Verify a position that is not a number | robustness | INLINE3: as /1 with the first line `AXIS_PTS_X x UWORD INDEX_INCR DIRECT` | the curve | the same message | | gap | not_run |
| R-A2L-DEF.88/1 | Verify a declared ALIGNMENT | normal | INLINE3: `CA2` = C(STD(2); `NO_AXIS_PTS_X 1 UBYTE`, `AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT`, `ALIGNMENT_WORD 2`, `FNC_VALUES 3 UWORD ROW_DIR DIRECT`) | `CA2` | component offsets 0, 1, 4; byte length 8 | | gap | not_run |
| R-A2L-DEF.88/2 | Verify a packed layout | normal | INLINE3: `CA2` without `ALIGNMENT_WORD 2` | `CA2` | offsets 0, 1, 3; byte length 7 | | gap | not_run |
| R-A2L-DEF.88/3 | Verify the position order | normal | INLINE3: C(STD(2); `FNC_VALUES 2 UWORD ROW_DIR DIRECT`, `AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT`) (lines in that order) | the curve | AXIS_PTS_X at 0, FNC_VALUES at 4 | | gap | not_run |
| R-A2L-DEF.89/1 | Verify the alignment refusal on the ASAM curve | robustness | V171 | `ASAM.C.CURVE.STD_AXIS` | refusal `A2L-DEF-ALIGNMENT`, `ASAM.C.CURVE.STD_AXIS: FNC_VALUES of the record layout RL.CURVE.SWORD.SBYTE.DECR lies at offset 9, or at 10 under the MOD_COMMON alignment` | | gap | not_run |
| R-A2L-DEF.89/2 | Verify it on the ASAM map | robustness | V171 | `ASAM.C.MAP.STD_AXIS.STD_AXIS` | `ASAM.C.MAP.STD_AXIS.STD_AXIS: FNC_VALUES of the record layout RL.MAP.SWORD.SBYTE.SBYTE.INCR lies at offset 11, or at 12 under the MOD_COMMON alignment` | | gap | not_run |
| R-A2L-DEF.89/3 | Verify no refusal where the readings agree | robustness | C08 clean (`MOD_COMMON` `ALIGNMENT_WORD 2`) | `CURVE_0001` | no refusal (FNC_VALUES at 0 under both readings) | | gap | not_run |
| R-A2L-DEF.90/1 | Verify FIX_NO_AXIS_PTS_X | normal | SOFTA | the first CURVE whose layout is `Hldoj[5].hg16.uc16.MXW3.QMGZFJ_TGXVUC` | current count 5 (base: no record, B line 23) | | gap | not_run |
| R-A2L-DEF.90/2 | Verify FIX_NO_AXIS_PTS_Y | normal | UPD1 | the MAP whose layout holds `FIX_NO_AXIS_PTS_Y` | current count of axis Y = that line's number | | gap | not_run |
| R-A2L-DEF.91/1 | Verify a curve with two axes | robustness | INLINE3: a CURVE `C2` with two `STD(2)` axes | `C2` | refusal `A2L-DEF-AXES`, `C2: a CURVE needs 1 axes and it declares 2` | | gap | not_run |
| R-A2L-DEF.91/2 | Verify a map with one axis | robustness | INLINE3: a MAP `M1` with one axis | `M1` | `M1: a MAP needs 2 axes and it declares 1` | | gap | not_run |
| R-A2L-DEF.91/3 | Verify a curve with none | robustness | INLINE3: a CURVE `C0` with no AXIS_DESCR | `C0` | `C0: a CURVE needs 1 axes and it declares 0` | | gap | not_run |
| R-A2L-DEF.92/1 | Verify CURVE_AXIS | robustness | V171 | `ASAM.C.CURVE.CURVE_AXIS` | refusal `A2L-DEF-AXIS-KIND`, `ASAM.C.CURVE.CURVE_AXIS.X: the system cannot read an axis of the kind CURVE_AXIS` | | gap | not_run |
| R-A2L-DEF.92/2 | Verify RES_AXIS | robustness | V171 | `ASAM.C.CURVE.RES_AXIS` | `ASAM.C.CURVE.RES_AXIS.X: the system cannot read an axis of the kind RES_AXIS` | | gap | not_run |
| R-A2L-DEF.92/3 | Verify an unlisted kind | robustness | INLINE3: C(`FOO_AXIS NO_INPUT CM_IDENT 2 0 255`; `FNC_VALUES 1 UWORD ROW_DIR DIRECT`) named `CK` | `CK` | `CK.X: the system cannot read an axis of the kind FOO_AXIS` | | gap | not_run |
| R-A2L-DEF.93/1 | Verify a FIX_AXIS count | normal | V171 | `ASAM.C.CURVE.FIX_AXIS.PAR_DIST` | axis X point count 6 | | gap | not_run |
| R-A2L-DEF.93/2 | Verify a STD_AXIS count | normal | C08 clean | `CURVE_0001` | 32 | | gap | not_run |
| R-A2L-DEF.93/3 | Verify the definitions case's map | normal | DEFC | its MAP, axis X | its planned point count | | gap | not_run |
| R-A2L-DEF.94/1 | Verify a COM_AXIS count | normal | V171 | `ASAM.C.CURVE.COM_AXIS` | axis X point count 8 | | gap | not_run |
| R-A2L-DEF.94/2 | Verify that the axis object's count wins | normal | INLINE3: COM_AXIS `COM_AXIS NO_INPUT CM_IDENT 8 0 255` + `AXIS_PTS_REF AXO`; axis object `AXO` max 5, layout `AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT`; curve layout `FNC_VALUES 1 UWORD ROW_DIR DIRECT` | the curve | point count 5, element count 5 | | gap | not_run |
| R-A2L-DEF.94/3 | Verify an a2ltool COM_AXIS | normal | SOFTA | the first CURVE with a COM_AXIS | point count = its axis object's max axis points (read from the file text) | | gap | not_run |
| R-A2L-DEF.95/1 | Verify a word as the max | robustness | INLINE3: C(`STD_AXIS NO_INPUT CM_IDENT x 0 255`; …) named `CX` | `CX` | refusal `A2L-DEF-AXIS-MAX`, `CX.X: the axis declares no point count the system can read` | | gap | not_run |
| R-A2L-DEF.95/2 | Verify a FIX_AXIS max of 0 | robustness | INLINE3: FIX_AXIS max `0` with `FIX_AXIS_PAR_DIST 0 1 0` | the curve | the same message | | gap | not_run |
| R-A2L-DEF.95/3 | Verify an axis object max of −3 | robustness | INLINE3: as R-A2L-DEF.94/2 with `AXO` max `-3` | the curve | the same message | | gap | not_run |
| R-A2L-DEF.96/1 | Verify a COM_AXIS with no reference | robustness | INLINE3: COM_AXIS with no AXIS_PTS_REF, curve `CR` | `CR` | refusal `A2L-DEF-AXIS-REF`, `CR.X: the A2L declares no axis object (none) with an address` | | gap | not_run |
| R-A2L-DEF.96/2 | Verify a dangling reference | robustness | INLINE3: `AXIS_PTS_REF AX_GONE` | `CR` | `CR.X: the A2L declares no axis object AX_GONE with an address` | | gap | not_run |
| R-A2L-DEF.96/3 | Verify an axis object with no address | robustness | INLINE3: `AXO` with address word `0xZZ` | `CR` | `CR.X: the A2L declares no axis object AXO with an address` | | gap | not_run |
| R-A2L-DEF.97/1 | Verify an undeclared axis layout | robustness | INLINE3: `AXO` naming `RL_GONE` | `CR` | refusal `A2L-DEF-AXIS-LAYOUT`, `CR.X: the axis object AXO has no record layout with AXIS_PTS_X` | | gap | not_run |
| R-A2L-DEF.97/2 | Verify an axis layout with no AXIS_PTS_X | robustness | INLINE3: `AXO`'s layout = `FNC_VALUES 1 UWORD ROW_DIR DIRECT` | `CR` | the same message | | gap | not_run |
| R-A2L-DEF.98/1 | Verify a FIX_AXIS with no parameters | robustness | INLINE3: C(`FIX_AXIS NO_INPUT CM_IDENT 4 0 255`; `FNC_VALUES 1 UWORD ROW_DIR DIRECT`) named `FN` | `FN` | refusal `A2L-DEF-AXIS-FIX`, `FN.X: the fixed axis gives no points` | | gap | not_run |
| R-A2L-DEF.99/1 | Verify a FIX_AXIS_PAR_DIST count that differs | robustness | INLINE3: `FC` = FIX_AXIS max 6 with `FIX_AXIS_PAR_DIST 0 1 4` | `FC` | refusal `A2L-DEF-AXIS-FIX-COUNT`, `FC.X: the fixed axis gives 4 points and declares 6` | | gap | not_run |
| R-A2L-DEF.99/2 | Verify a short list | robustness | INLINE3: `FC` max 6 with a FIX_AXIS_PAR_LIST `1 2 3 4 5` | `FC` | `FC.X: the fixed axis gives 5 points and declares 6` | | gap | not_run |
| R-A2L-DEF.100/1 | Verify case 08's curve axis | robustness | C08 clean | `CURVE_0001` | axis X has no points; no refusal | | gap | not_run |
| R-A2L-DEF.100/2 | Verify case 08's map axis X | robustness | C08 clean | `MAP_0001` | axis X has no points | | gap | not_run |
| R-A2L-DEF.100/3 | Verify case 08's map axis Y | robustness | C08 clean | `MAP_0001` | axis Y has no points; no refusal | | gap | not_run |
| R-A2L-DEF.101/1 | Verify in-record points for a FIX_AXIS | robustness | INLINE3: C(`FIX_AXIS NO_INPUT CM_IDENT 2 0 255` + `FIX_AXIS_PAR_DIST 0 1 2`; `AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT`, `FNC_VALUES 2 UWORD ROW_DIR DIRECT`), layout `RL_FX` | the curve | refusal `A2L-DEF-LAYOUT-AXIS`, `<name>: the record layout RL_FX holds AXIS_PTS_X for an axis of the kind FIX_AXIS` | | gap | not_run |
| R-A2L-DEF.101/2 | Verify in-record points for a COM_AXIS | robustness | INLINE3: the COM_AXIS of R-A2L-DEF.94/2 with that layout | the curve | `… holds AXIS_PTS_X for an axis of the kind COM_AXIS` | | gap | not_run |
| R-A2L-DEF.102/1 | Verify an enum axis | normal | V171 | `ASAM.C.MAP.STD_AXIS.STD_AXIS`, axis Y (on the refused definition) | point definition: kind enum, table `CM.TAB_VERB.NO_DEFAULT_VALUE.REF`, datatype SBYTE, limits −128..127 | | gap | not_run |
| R-A2L-DEF.102/2 | Verify a COM_AXIS point definition | normal | V171 | `ASAM.C.CURVE.COM_AXIS`, axis X | kind number, method `CM.IDENTICAL`, limits 0..255, datatype SBYTE | | gap | not_run |
| R-A2L-DEF.102/3 | Verify the axis's own conversion and FORMAT | normal | INLINE3: `CL` = C(`STD_AXIS NO_INPUT CM_HALF 4 0 100` + `FORMAT "%.1"`, `CM_HALF` = `CM(LINEAR 0.5 0)`; `AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT`, `FNC_VALUES 2 UWORD ROW_DIR DIRECT`) | `CL`, axis X | kind number, method `CM_HALF`, display format `%.1`, datatype UWORD | | gap | not_run |
| R-A2L-DEF.102/4 | Verify that the AXIS_DESCR's method is used for a COM_AXIS | normal | INLINE3: the COM_AXIS of R-A2L-DEF.94/2 naming `CM_A` (`CM(LINEAR 2 0)`), its axis object naming `CM_B` (`CM(LINEAR 3 0)`) | axis X | method `CM_A` | | gap | not_run |
| R-A2L-DEF.103/1 | Verify an axis method that is not declared | robustness | INLINE3: `CA` = C(`STD_AXIS NO_INPUT CM_GONE 2 0 255`; `AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT`, `FNC_VALUES 2 UWORD ROW_DIR DIRECT`) | `CA` | refusal `A2L-DEF-METHOD`, `CA.X: the conversion method CM_GONE is not declared in the A2L` | | gap | not_run |
| R-A2L-DEF.103/2 | Verify an enum axis with no table | robustness | INLINE3: MAP `MA`, axis Y `STD_AXIS NO_INPUT CM_V 2 0 255` with `CM_V` = `TAB_VERB "%.0" ""` and no COMPU_TAB_REF | `MA` | `MA.Y: the table (none) of CM_V is not declared in the A2L` | | gap | not_run |
| R-A2L-DEF.104/1 | Verify the layout before the axis object | robustness | CHECK | `Curve_ExternalAxis` | `A2L-DEF-LAYOUT` (not A2L-DEF-AXIS-REF) | | gap | not_run |
| R-A2L-DEF.104/2 | Verify MATRIX_DIM before the layout | robustness | INLINE3: VAL_BLK `VQ`, `MATRIX_DIM 0`, layout `RL_GONE` | `VQ` | `A2L-DEF-MATRIX` | | gap | not_run |
| R-A2L-DEF.104/3 | Verify the layout parts before the axis kind | robustness | INLINE3: a CURVE with a RES_AXIS whose layout holds `RESERVED 2 BYTE` | the curve | `A2L-DEF-LAYOUT-PART` | | gap | not_run |
| R-A2L-DEF.105/1 | Verify integer elements | normal | V171; image SWORD 1 … 12 at 0x810100 | decode `…MATRIX_DIM_3_4.ROW_DIR` | 12 elements; display texts `1` … `12` in address order (base: raw 1 only, B line 12) | | gap | not_run |
| R-A2L-DEF.105/2 | Verify enum elements | normal | INLINE3: UBYTE VAL_BLK `VE`, `MATRIX_DIM 2`, method `CM_E` (`TAB_VERB`, `VT_E`: `0 "OFF"`, `1 "ON"`); image 01 00 at 0x10 | decode | `VE[0]` → `ON`, `VE[1]` → `OFF` | | gap | not_run |
| R-A2L-DEF.105/3 | Verify converted elements | normal | INLINE3: UWORD VAL_BLK `VN`, `MATRIX_DIM 2`, `CM(LINEAR 0.5 0)`, `FORMAT "%.1"`; image 00 03 00 04 | decode | `1.5`, `2.0` | | gap | not_run |
| R-A2L-DEF.105/4 | Verify masked elements | normal | INLINE3: UWORD VAL_BLK `VM`, `MATRIX_DIM 2`, `BIT_MASK 0x0F00`; image 12 34 0A 00 | decode | stored 2, 10 | | gap | not_run |
| R-A2L-DEF.106/1 | Verify ROW_DIR on a 2-D array | normal | V171; image SWORD 1 … 12 at 0x810100 | decode `…3_4.ROW_DIR` | (1,0) = 2, (0,1) = 4, (2,3) = 12 | | gap | not_run |
| R-A2L-DEF.106/2 | Verify ROW_DIR in three dimensions | normal | V171; image bytes 0 … 63 at 0x13A30 | decode `…MATRIX_DIM_8_4_2…` | (1,1,1) = 41, (7,3,1) = 63 | | gap | not_run |
| R-A2L-DEF.106/3 | Verify a ROW_DIR map | normal | V171; image SWORD 0 … 23 at 0x810440 and AX8(8, 46 3C 32 28 1E 14 0A 00) at 0x810340 | decode `ASAM.C.MAP.COM_AXIS.FIX_AXIS` | (1,2) = 17, (7,0) = 7, (0,1) = 8 | | gap | not_run |
| R-A2L-DEF.107/1 | Verify COLUMN_DIR on a 2-D array | normal | V171; image SWORD 1 … 12 at 0x810120 | decode `…3_4.COLUMN_DIR` | (1,0) = 5, (0,1) = 2, (2,3) = 12 | | gap | not_run |
| R-A2L-DEF.107/2 | Verify case 08's map | normal | C08 clean | decode `MAP_0001` | every (x,y) = the plan's value number 8·x + y | | gap | not_run |
| R-A2L-DEF.107/3 | Verify case 08's curve | normal | C08 clean | decode `CURVE_0001` | every (x) = the plan's value number x | | gap | not_run |
| R-A2L-DEF.108/1 | Verify INDEX_INCR points | normal | INLINE3: `CI` = C(STD(4); `NO_AXIS_PTS_X 1 UBYTE`, `AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT`, `FNC_VALUES 3 UWORD ROW_DIR DIRECT`); image 04, 0A 14 1E 28, 8 value bytes | decode | points 10, 20, 30, 40 | | gap | not_run |
| R-A2L-DEF.108/2 | Verify the definitions case's map axis | normal | DEFC | decode its MAP | axis X = its planned points | | gap | not_run |
| R-A2L-DEF.109/1 | Verify INDEX_DECR on the ASAM axis object | normal | V171; image SWORD values at 0x810320 and AX8(8, 46 3C 32 28 1E 14 0A 00) | decode `ASAM.C.CURVE.COM_AXIS` | points 0, 10, 20, 30, 40, 50, 60, 70 (base: 70 … 0, B line 14) | | gap | not_run |
| R-A2L-DEF.109/2 | Verify INDEX_DECR in a record | normal | INLINE3: `CD` = `CI` with `INDEX_DECR`; point bytes 28 1E 14 0A | decode | 10, 20, 30, 40 | | gap | not_run |
| R-A2L-DEF.110/1 | Verify FIX_AXIS_PAR | normal | INLINE3: C(`FIX_AXIS NO_INPUT CM_IDENT 4 0 255` + `FIX_AXIS_PAR 0 2 4`; `FNC_VALUES 1 UWORD ROW_DIR DIRECT`); image 8 bytes | decode | stored points 0, 4, 8, 12 | | gap | not_run |
| R-A2L-DEF.111/1 | Verify PAR_DIST 1 1 6 | normal | V171; image SWORD 0 … 5 at 0x810350 | decode `ASAM.C.CURVE.FIX_AXIS.PAR_DIST` | points 1, 2, 3, 4, 5, 6 (base: 0 … 5, B line 19) | | gap | not_run |
| R-A2L-DEF.111/2 | Verify PAR_DIST 0 4 6 | normal | V171; image at 0x810360 | decode `ASAM.C.CURVE.FIX_AXIS.PAR` | 0, 4, 8, 12, 16, 20 | | gap | not_run |
| R-A2L-DEF.111/3 | Verify a fixed map axis | normal | V171; image of R-A2L-DEF.106/3 | decode `ASAM.C.MAP.COM_AXIS.FIX_AXIS` | axis Y 1, 2, 3 | | gap | not_run |
| R-A2L-DEF.112/1 | Verify FIX_AXIS_PAR_LIST | normal | V171; image at 0x810370 | decode `ASAM.C.CURVE.FIX_AXIS.PAR_LIST` | −1, 4, 6, 8, 9, 10 (base: 0 … 5, B line 20) | | gap | not_run |
| R-A2L-DEF.113/1 | Verify two curves on one axis object | normal | V171; values at 0x810320 and 0x810330, AX8(8, 46 3C 32 28 1E 14 0A 00) | decode `ASAM.C.CURVE.COM_AXIS` and `ASAM.C.CURVE.COM_AXIS_2` | both axes 0, 10, … 70 (base: unresolved, B line 18) | | gap | not_run |
| R-A2L-DEF.113/2 | Verify the definitions case's shared axis | normal | DEFC | decode its two COM_AXIS curves | both axes = the planned points of the one axis object | | gap | not_run |
| R-A2L-DEF.114/1 | Verify the axis object's own byte order | normal | INLINE3 (MSB_FIRST): the curve of R-A2L-DEF.94/2 with `AXO` `BYTE_ORDER MSB_LAST`, point 0 bytes 02 01 | decode | point 0 = 258 | | gap | not_run |
| R-A2L-DEF.114/2 | Verify the module byte order for the axis object | normal | INLINE3: `AXO` with no BYTE_ORDER, point 0 bytes 02 01 | decode | point 0 = 513 | | gap | not_run |
| R-A2L-DEF.115/1 | Verify the axis object's count | normal | V171; image of R-A2L-DEF.109/1 | decode `ASAM.C.CURVE.COM_AXIS` | current count 8; 8 points | | gap | not_run |
| R-A2L-DEF.115/2 | Verify two count components | normal | INLINE3: MAP `MN` (point counts 3 and 2; `NO_AXIS_PTS_X 1 UBYTE`, `NO_AXIS_PTS_Y 2 UBYTE`, `AXIS_PTS_X 3 UBYTE …`, `AXIS_PTS_Y 4 UBYTE …`, `FNC_VALUES 5 UWORD ROW_DIR DIRECT`); count bytes 03 02 | decode | current counts 3, 2 | | gap | not_run |
| R-A2L-DEF.116/1 | Verify a count of 0 | robustness | V171; AX8(0, …) | decode `ASAM.C.CURVE.COM_AXIS` | refusal `A2L-DEF-AXIS-CURRENT`, `ASAM.C.CURVE.COM_AXIS.X: the record holds 0 points, outside 1 to 8` | | gap | not_run |
| R-A2L-DEF.116/2 | Verify a count above the max | robustness | V171; AX8(9, …) | decode `ASAM.C.CURVE.COM_AXIS` | `….X: the record holds 9 points, outside 1 to 8` | | gap | not_run |
| R-A2L-DEF.116/3 | Verify FIX_NO_AXIS_PTS_X 0 | robustness | INLINE3: C(STD(4); `AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT`, `FNC_VALUES 2 UWORD ROW_DIR DIRECT`, `FIX_NO_AXIS_PTS_X 0`) named `CZ` | the definition of `CZ` | `CZ.X: the record holds 0 points, outside 1 to 4` | | gap | not_run |
| R-A2L-DEF.117/1 | Verify a partial record in the image | robustness | V171; AX8(5, …) | decode `ASAM.C.CURVE.COM_AXIS` | refusal `A2L-DEF-AXIS-PARTIAL`, `ASAM.C.CURVE.COM_AXIS.X: the record holds 5 of its 8 points — a record with fewer points than its maximum is not supported` (base: 8 points read, B line 15) | | gap | not_run |
| R-A2L-DEF.117/2 | Verify a partial record by FIX_NO (real file) | robustness | UPD2 | the definition of `Curve_InternalAxis_bad_axis_size` | `Curve_InternalAxis_bad_axis_size.X: the record holds 4 of its 8 points — a record with fewer points than its maximum is not supported` | | gap | not_run |
| R-A2L-DEF.117/3 | Verify the X axis of a map | robustness | INLINE3: `MN` of R-A2L-DEF.115/2; count bytes 02 02 | decode | `MN.X: the record holds 2 of its 3 points — …` | | gap | not_run |
| R-A2L-DEF.118/1 | Verify an axis object outside the image | robustness | V171; image holding the 16 bytes at 0x810320 only | decode `ASAM.C.CURVE.COM_AXIS` | refusal `A2L-DEF-AXIS-BYTES`, `ASAM.C.CURVE.COM_AXIS.X: 9 of the 9 bytes of the axis object ASAM.C.AXIS_PTS.UBYTE_8 are not in the image` | | gap | not_run |
| R-A2L-DEF.118/2 | Verify one byte missing | robustness | V171; as /1 plus the axis object's first 8 bytes | decode | `….X: 1 of the 9 bytes of the axis object ASAM.C.AXIS_PTS.UBYTE_8 are not in the image` | | gap | not_run |
| R-A2L-DEF.119/1 | Verify one failing element | robustness | INLINE3: UWORD VAL_BLK `VR`, `MATRIX_DIM 3`, `CM(RAT_FUNC 1 0 1 0 0 1)`, limits 0..10; image 00 05 00 00 00 0A | decode | `VR[0]` 2.0; `VR[1]` refusal `A2L-DEF-DECODE`, `VR[1]: RAT_FUNC has no real root for this value`; `VR[2]` 3.0 | | gap | not_run |
| R-A2L-DEF.119/2 | Verify an unmatched enum point among others | robustness | INLINE3: MAP with enum axis Y (`VT_E` of R-A2L-DEF.105/2), Y points stored 1, 7 | decode | Y[0] `ON`; Y[1] `7 (no text)`; every value decoded | | gap | not_run |
| R-A2L-DEF.120/1 | Verify the single-value decode refusal | robustness | V171; image of R-A2L-DEF.106/1 | single decode `…3_4.ROW_DIR` | refusal `A2L-DEF-ELEMENTS`, `ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR: it holds 12 values — decode and encode it value by value` | | gap | not_run |
| R-A2L-DEF.120/2 | Verify the single-text encode refusal | robustness | V171 | single encode `5` on the same | the same refusal; no bytes | | gap | not_run |
| R-A2L-DEF.121/1 | Verify an element name in a refusal | normal | INLINE3: UWORD VAL_BLK `V`, `MATRIX_DIM 3 4`; image of 24 bytes | edit {(1,2): `abc`} | `V[1,2]: 'abc' is not a number` | | gap | not_run |
| R-A2L-DEF.121/2 | Verify an axis point name | normal | INLINE3: `C` = C(`STD_AXIS NO_INPUT CM_S8 4 -100 100`, `CM_S8` IDENTICAL; `AXIS_PTS_X 1 SBYTE INDEX_INCR DIRECT`, `FNC_VALUES 2 SWORD ROW_DIR DIRECT`); points 10 20 30 40 | edit {X[1]: `120`} | `C.X[1]: 120 is outside the limits -100..100` | | gap | not_run |
| R-A2L-DEF.121/3 | Verify the name in a decode refusal | normal | as R-A2L-DEF.119/1 | decode | the refusal text begins `VR[1]: ` | | gap | not_run |
| R-A2L-DEF.122/1 | Verify a converted element edit | normal | INLINE3: `VN` of R-A2L-DEF.105/3 | edit {(0): `2.5`} | element 0 stored 5 | | gap | not_run |
| R-A2L-DEF.122/2 | Verify an enum element edit | normal | INLINE3: `VE` of R-A2L-DEF.105/2; image 01 00 | edit {(1): `ON`} | element 1 stored 1; bytes 01 01 | | gap | not_run |
| R-A2L-DEF.122/3 | Verify an element outside its limits | normal | INLINE3: UWORD VAL_BLK `VX` (`MATRIX_DIM 2`, limits 0..10, no EXTENDED_LIMITS) | edit {(0): `11`} | refusal `A2L-DEF-LIMITS`, `VX[0]: 11 is outside the limits 0..10` | | gap | not_run |
| R-A2L-DEF.122/4 | Verify a converted axis point edit | normal | INLINE3: C(`STD_AXIS NO_INPUT CM_TWO 4 0 500`, `CM_TWO` = `CM(LINEAR 2 0)`; `AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT`, `FNC_VALUES 2 UWORD ROW_DIR DIRECT`); points stored 1 2 3 4 | edit {X[3]: `10`} | point 3 stored 5 | | gap | not_run |
| R-A2L-DEF.123/1 | Verify the ROW_DIR bytes of an edit | normal | V171; image SWORD 1 … 12 at 0x810100 | edit {(1,0): `-7`} on `…3_4.ROW_DIR` | address 0x810100, 24 bytes; bytes 2–3 F9 FF; every other byte as the image (base: no array encode, B line 28) | | gap | not_run |
| R-A2L-DEF.123/2 | Verify the COLUMN_DIR bytes | normal | V171; image SWORD 1 … 12 at 0x810120 | edit {(1,0): `-7`} on `…3_4.COLUMN_DIR` | address 0x810120; bytes 8–9 F9 FF; every other byte as the image | | gap | not_run |
| R-A2L-DEF.123/3 | Verify an INDEX_DECR point edit | normal | INLINE3: `CD` of R-A2L-DEF.109/2 | edit {X[0]: `5`} | the byte at the axis offset + 3 is 05; every other byte as the image | | gap | not_run |
| R-A2L-DEF.123/4 | Verify that the count byte is kept | normal | INLINE3: `CI` of R-A2L-DEF.108/1 | edit {(2): `9`} | record byte 0 still 04 (base: 00, B line 25) | | gap | not_run |
| R-A2L-DEF.124/1 | Verify an edit with the axis object missing | robustness | V171; image of R-A2L-DEF.118/1 | edit {(0): `1`} on `ASAM.C.CURVE.COM_AXIS` | the A2L-DEF-AXIS-BYTES refusal of R-A2L-DEF.118/1; no bytes | | gap | not_run |
| R-A2L-DEF.124/2 | Verify an edit on a partial record | robustness | V171; AX8(5, …) | edit {(0): `1`} | the A2L-DEF-AXIS-PARTIAL refusal of R-A2L-DEF.117/1 | | gap | not_run |
| R-A2L-DEF.124/3 | Verify an edit with a record byte missing | robustness | INLINE3: UWORD VAL_BLK `VB`, `MATRIX_DIM 2` at 0x10; image 0x10 … 0x12 only | edit {(0): `1`} | refusal `A2L-DEF-BYTES`, `VB: 1 of its 4 bytes are not in the image` | | gap | not_run |
| R-A2L-DEF.125/1 | Verify an index past the shape | robustness | V171 | edit {(3,0): `1`} on `…3_4.ROW_DIR` | refusal `A2L-DEF-INDEX`, `ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR: ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR[3,0] is not a value or axis point of it` | | gap | not_run |
| R-A2L-DEF.125/2 | Verify an index of the wrong length | robustness | V171 | edit {(0,0,0): `1`} on the same | `…: …ROW_DIR[0,0,0] is not a value or axis point of it` | | gap | not_run |
| R-A2L-DEF.125/3 | Verify an axis point of an array | robustness | V171 | edit {X[0]: `1`} on the same | `…: ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR.X[0] is not a value or axis point of it` | | gap | not_run |
| R-A2L-DEF.126/1 | Verify a fixed curve axis | robustness | V171 | edit {X[0]: `0`} on `ASAM.C.CURVE.FIX_AXIS.PAR_DIST` | refusal `A2L-DEF-AXIS-FIXED`, `ASAM.C.CURVE.FIX_AXIS.PAR_DIST.X[0]: the points of a fixed axis are not stored in the image` | | gap | not_run |
| R-A2L-DEF.126/2 | Verify a fixed map axis | robustness | V171; image of R-A2L-DEF.106/3 | edit {Y[2]: `4`} on `ASAM.C.MAP.COM_AXIS.FIX_AXIS` | `ASAM.C.MAP.COM_AXIS.FIX_AXIS.Y[2]: the points of a fixed axis are not stored in the image` | | gap | not_run |
| R-A2L-DEF.127/1 | Verify a common axis point | robustness | V171; image of R-A2L-DEF.109/1 | edit {X[3]: `35`} on `ASAM.C.CURVE.COM_AXIS` | refusal `A2L-DEF-AXIS-SHARED`, `ASAM.C.CURVE.COM_AXIS.X[3]: the points of the common axis ASAM.C.AXIS_PTS.UBYTE_8 are not edited through ASAM.C.CURVE.COM_AXIS` (base: the curve refused whole, B line 27) | | gap | not_run |
| R-A2L-DEF.127/2 | Verify the definitions case's shared axis | robustness | DEFC | edit {X[0]: its point 0's display text} on its first COM_AXIS curve | the A2L-DEF-AXIS-SHARED refusal naming its axis object | | gap | not_run |
| R-A2L-DEF.128/1 | Verify an axis with no points | robustness | C08 clean | edit {X[0]: `1`} on `CURVE_0001` | refusal `A2L-DEF-AXIS-NONE`, `CURVE_0001.X[0]: the record layout RL_U16 holds no points for this axis` | | gap | not_run |
| R-A2L-DEF.129/1 | Verify STRICT_INCREASE | robustness | INLINE3: `CM1` = C(`STD_AXIS NO_INPUT CM_IDENT 4 0 255` + `MONOTONY STRICT_INCREASE`; `AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT`, `FNC_VALUES 2 UWORD ROW_DIR DIRECT`); points 10 20 30 40 | edit {X[2]: `20`} | refusal `A2L-DEF-MONOTONY`, `CM1.X[2]: 20 breaks the STRICT_INCREASE order of the axis` (base: written, B line 26) | | gap | not_run |
| R-A2L-DEF.129/2 | Verify STRICT_DECREASE | robustness | INLINE3: `CM1` with `STRICT_DECREASE`, points 40 30 20 10 | edit {X[1]: `45`} | `CM1.X[1]: 45 breaks the STRICT_DECREASE order of the axis` | | gap | not_run |
| R-A2L-DEF.129/3 | Verify that MON_INCREASE takes an equal point | normal | INLINE3: `CM1` with `MON_INCREASE` | edit {X[2]: `20`} | accepted; points 10 20 20 40 | | gap | not_run |
| R-A2L-DEF.129/4 | Verify MON_INCREASE | robustness | INLINE3: as /3 | edit {X[2]: `15`} | `CM1.X[2]: 15 breaks the MON_INCREASE order of the axis` | | gap | not_run |
| R-A2L-DEF.129/5 | Verify MON_DECREASE | robustness | INLINE3: `CM1` with `MON_DECREASE`, points 40 30 20 10 | edit {X[2]: `35`} | `CM1.X[2]: 35 breaks the MON_DECREASE order of the axis` | | gap | not_run |
| R-A2L-DEF.129/6 | Verify the default rule | robustness | INLINE3: `CM1` with no MONOTONY line | edit {X[3]: `30`} | `CM1.X[3]: 30 breaks the STRICT_MON order of the axis` | | gap | not_run |
| R-A2L-DEF.129/7 | Verify MONOTONOUS | robustness | INLINE3: `CM1` with `MONOTONOUS` | edit {X[1]: `5`} | `CM1.X[2]: 30 breaks the MONOTONOUS order of the axis` | | gap | not_run |
| R-A2L-DEF.129/8 | Verify NOT_MON | normal | INLINE3: `CM1` with `NOT_MON` | edit {X[1]: `50`} | accepted; points 10 50 30 40 | | gap | not_run |
| R-A2L-DEF.129/9 | Verify that an unedited point can break the order | robustness | INLINE3: `CM1` with `STRICT_INCREASE` | edit {X[1]: `35`} | `CM1.X[2]: 30 breaks the STRICT_INCREASE order of the axis` | | gap | not_run |
| R-A2L-DEF.130/1 | Verify the decode before the shared axis | robustness | V171; image of R-A2L-DEF.118/1 | edit {X[0]: `1`} on `ASAM.C.CURVE.COM_AXIS` | `A2L-DEF-AXIS-BYTES` | | gap | not_run |
| R-A2L-DEF.130/2 | Verify the axis before the values | robustness | INLINE3: `CM1` with no MONOTONY line | edit {X[1]: `abc`, (0): `abc`} | `CM1.X[1]: 'abc' is not a number` | | gap | not_run |
| R-A2L-DEF.130/3 | Verify each edit before the monotony | robustness | INLINE3: `CM1` with `STRICT_INCREASE` | edit {X[1]: `50`, (2): `x`} | `CM1[2]: 'x' is not a number` | | gap | not_run |
| R-A2L-DEF.131/1 | Verify the edit round trip | normal | V171 (3×4 twins; `ASAM.C.MAP.COM_AXIS.FIX_AXIS` values), INLINE3 (`CD` points), DEFC (MAP values and axis X; VAL_BLK) | for each object ≥ 20 edits of 1 to 3 positions; texts = the 17-significant-digit texts of decoded stored values of other cells plus typed decimals inside the limits; encode, apply, decode | ≥ 200 accepted edits; 0 edited cells that do not agree at their display precision | | gap | not_run |
| R-A2L-DEF.132/1 | Verify that unedited cells keep their bytes | normal | the edits of R-A2L-DEF.131/1 | compare each record before and after | 0 unedited elements or points with a changed stored value; every record byte outside the edited cells equal to the image's | | gap | not_run |
| R-A2L-DEF.133/1 | Verify the definitions case's common axis | normal | DEFC | its two COM_AXIS curves and their axis object | one AXIS_PTS named by both; its layout holds `NO_AXIS_PTS_X` (image value = its max axis points) and `AXIS_PTS_X … INDEX_INCR DIRECT`; the AXIS_DESCR method LINEAR with a ≠ 1; stored points strictly increasing; decode → both axes = the planned physical points, values = the planned values | | gap | not_run |
| R-A2L-DEF.134/1 | Verify the definitions case's map | normal | DEFC | its MAP | axis X STD_AXIS with `MONOTONY STRICT_INCREASE` and points in the record; axis Y FIX_AXIS with FIX_AXIS_PAR_DIST; FNC_VALUES COLUMN_DIR; nX ≠ nY, both ≥ 3; decode → every (x,y) = its planned value | | gap | not_run |
| R-A2L-DEF.135/1 | Verify the definitions case's VAL_BLK | normal | DEFC | its VAL_BLK | `MATRIX_DIM n1 n2`, n1 ≠ n2, both ≥ 2; `FNC_VALUES … ROW_DIR DIRECT`; LINEAR a ≠ 1; `FORMAT "%.1"`; decode → every (i,j) = its planned value | | gap | not_run |

## Cases of the cited rows (rows unchanged)

| Case | Objective | Class | Preconditions | Inputs | Expected result | Tests | Coverage | Result |
|---|---|---|---|---|---|---|---|---|
| R-A2L-DEF.5/arr-1 | Verify that the one tag of an array's name is used, case included | normal | INLINE3: a VAL_BLK `DUPA` (MATRIX_DIM 2) at 0x20 and a VAL_BLK `dupa` (MATRIX_DIM 2) at 0x10 | the definition of `DUPA` | address 0x20, kind array, no refusal (`dupa` is another name; rebased: the first-tag rule is gone, E3S-35) | | gap | not_run |
| R-A2L-DEF.139/arr-1 | Verify the refusal for an array name declared twice | robustness | INLINE3: two VAL_BLKs `DUPA` (MATRIX_DIM 2) at 0x10 and 0x20 | the definition of `DUPA` | refusal `A2L-DEF-NAME`, `DUPA: the A2L declares that name more than once` (the input of E1's .5/arr-1) | | gap | not_run |
| R-A2L-DEF.6/arr-1 | Verify the name's case for a curve | robustness | C08 clean | `curve_0001` | `curve_0001: no tag of that name in the A2L` | | gap | not_run |
| R-A2L-DEF.7.1/arr-1 | Verify that an array's length is its byte length | robustness | V171 (the tag has no length, B line 7) | `…3_4.ROW_DIR` | no A2L-DEF-ADDRESS refusal; byte length 24 | | gap | not_run |
| R-A2L-DEF.7.1/arr-2 | Verify an array with no address | robustness | INLINE3: UBYTE MEASUREMENT `MA0`, `MATRIX_DIM 4`, no ECU_ADDRESS | `MA0` | `MA0: the object has no address or no length` | | gap | not_run |
| R-A2L-DEF.26/arr-1 | Verify missing record bytes | robustness | V171; image of 23 of the 24 bytes at 0x810100 | decode `…3_4.ROW_DIR` | `ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR: 1 of its 24 bytes are not in the image` | | gap | not_run |
| R-A2L-DEF.58.1/arr-1 | Verify unchanged inputs on V171 | normal | V171 with an image holding every array, curve and map record and both axis objects | build, decode and edit (one cell each, its own decoded text) every array, curve and map | a deep copy of the parse payload and of the image taken before equals both after | | gap | not_run |
| R-A2L-DEF.58.1/arr-2 | Verify unchanged inputs on case 08 | normal | C08 clean | as /arr-1 over its 140 arrays, curves and maps | as /arr-1 | | gap | not_run |
| R-A2L-DEF.136/arr-1 | Verify that describing every object stays fast with Inc 3's kinds (E3A-32) | normal | SOFTA | `describe_definitions` of every tag name (13,990): 101 VAL_BLK, 158 CURVE (161 COM axes), 11 MAP and 196 MEASUREMENT arrays among them | finishes within 2.0 s (median of 3 runs, cachyos-rtx, Python 3.11.18, `serial_timing`); the rebase's cost prototype gives about 1.0 s | | gap | not_run |
| R-A2L-DEF.59/arr-1 | Verify case 08's pin with Inc 3's synth | normal | the generator of the tree under test | Inc 2's R-A2L-DEF.59/1 and /2 | the 22 pinned digests | | gap | not_run |
| R-A2L-DEF.63/arr-1 | Verify the extended definitions case is deterministic | normal | the generator | the definitions case twice into two folders | every file byte-identical | | gap | not_run |
| R-A2L-010/arr-1 | Verify a VAL_BLK address | normal | V171 | `…3_4.ROW_DIR` | address 0x810100 | | gap | not_run |
| R-A2L-011/arr-1 | Verify a MEASUREMENT array address | normal | V171 | `…MATRIX_DIM_8_4_2…` | address 0x13A30 | | gap | not_run |
| R-A2L-024/arr-1 | Verify case 08's array byte order | normal | C08 clean | `VAL_BLK_0001` | the byte order its BYTE_ORDER line gives; decode = the plan | | gap | not_run |
| R-A2L-026/arr-1 | Verify the module byte order of an array | normal | V171 | `…3_4.ROW_DIR` | byte order little | | gap | not_run |
| R-A2L-019/arr-1 | Verify the axis object's points are counted | normal | V171 | `ASAM.C.CURVE.COM_AXIS` | point count 8 from `ASAM.C.AXIS_PTS.UBYTE_8` | | gap | not_run |

## Acceptance cases (black-box at I-2, real shapes)

| Case | Objective | Class | Preconditions | Inputs | Expected result | Tests | Coverage | Result |
|---|---|---|---|---|---|---|---|---|
| AT-B103-I3-1 | Verify the ASAM demo's arrays and axes end to end (US-103-05) | normal | V171; an image holding SWORD 1 … 12 at 0x810100 and at 0x810120, bytes 0 … 63 at 0x13A30, SWORD values at 0x810320, 0x810330, 0x810350, 0x810360, 0x810370, 0x810440, and AX8(8, 46 3C 32 28 1E 14 0A 00) | build every VAL_BLK, MATRIX_DIM MEASUREMENT, CURVE and MAP of the file; decode those without a refusal; edit one value of each, apply, decode | the 3×4 twins read the same bytes in the two orders and the edit (1,0) lands at offsets 2 and 8; the two COM_AXIS curves and the COM/FIX map read one axis 0 … 70; the three FIX curves read 1 … 6, 0 … 20, −1 … 10; the STD_AXIS curves and map are refused with A2L-DEF-ALIGNMENT, the CURVE_AXIS and RES_AXIS curves with A2L-DEF-AXIS-KIND, CUBOID and CUBE_4 with A2L-DEF-KIND; each edited object decodes to its new value and keeps every other value — rows R-A2L-DEF.64 … .67, .72 … .75, .89, .92, .105 … .109, .111 … .113, .115, .123, .131, .132 | | gap | not_run |
| AT-B103-I3-2 | Verify the definitions case through the app's loaders (US-103-05) | normal | DEFC loaded by the app's A2L parser and S19 loader | each array, curve and map: build, decode, edit one value (and one STD_AXIS point of the map), apply, decode; edit a point of the common axis; edit the map's axis X out of order | first decodes = the plan; edited cells = the new values, every other cell and every byte outside the edited spans unchanged; the common-axis edit refused with A2L-DEF-AXIS-SHARED; the out-of-order edit refused with A2L-DEF-MONOTONY — rows R-A2L-DEF.127, .129, .131 … .135 | | gap | not_run |
| AT-B103-I3-3 | Verify case 08's arrays with the model (US-103-05) | normal | C08 clean and issues | build, decode and edit (one value each) every VAL_BLK, CURVE and MAP of both A2Ls | 60 VAL_BLK, 60 CURVE, 20 MAP per A2L, 0 refusals; element counts 128, 32, 64; decodes = the plan (MAP COLUMN_DIR); edits land and keep the other cells; the 22 case files equal the pin — rows R-A2L-DEF.69, .73, .100, .107, .123, .131, .132, R-A2L-DEF.59 | | gap | not_run |
| AT-B103-I3-4 | Verify the element counts Inc 6 reads on the a2ltool file (US-103-05, PE-D1) | normal | SOFTA (no image) | build every VAL_BLK, CURVE and MAP | for each: element count = the count the test takes from the file text (NUMBER, or the axis object's max axis points for a COM_AXIS, or the AXIS_DESCR's); 0 A2L-DEF-AXIS-REF and 0 A2L-DEF-LAYOUT-PART refusals; every refusal listed by code in the test's log — rows R-A2L-DEF.64, .68, .73, .74, .90, .94 | | gap | not_run |

**Counts:** 195 cases of the 72 rows (S2.7e 58, S2.7f 61, S2.7g 40, S2.7h 33, S2.7i 3), 16 cases of 14 cited rows (the rebase on Inc 2's E3 added R-A2L-DEF.139/arr-1 and .136/arr-1 and renamed `.7/arr-k` → `.7.1/arr-k`, `.58/arr-k` → `.58.1/arr-k`), and 4 acceptance cases: 215 cases. Negative controls (the mutant of each row, run at E5 in a copy of the tree): `01-requirements.md`, column "Negative control".

## Split (amendment A2)

The cases split by side, following `01-requirements.md` "Split (amendment A2)": **3a** is the read side, which runs on Inc 2a; **3b** is the write side, which waits for Inc 2b and Inc 11. A case that serves both sides stays in 3a, and its edit arm waits for 3b. A 3b case keeps **Tests** empty, **Coverage** `gap` and **Result** `not_run` until 3b's E4. Thresholds do not change: a 3a row whose cases wait reaches its N/N at 3b (.120 has 1 of 2 cases in 3a, .121 1 of 3).

| Rows | 3a cases | 3b cases |
|---|---|---|
| R-A2L-DEF.64 … .81 (S2.7e) | every case (58) | — |
| R-A2L-DEF.82 … .104 (S2.7f) | every case (61) | — |
| R-A2L-DEF.105 … .119 | every case (35) | — |
| R-A2L-DEF.120 | /1 (single decode) | /2 (single encode) |
| R-A2L-DEF.121 | /3 (decode refusal) | /1, /2 (edit refusals) |
| R-A2L-DEF.122 … .132 (S2.7h) | — | every case (33) |
| R-A2L-DEF.133 … .135 (S2.7i) | every case (3) | — |
| cited R-A2L-DEF.5, .6, .139, .7.1, .26, .59, .63, .136, R-A2L-010, 011, 024, 026, 019 | every `/arr-k` case (14) | — |
| cited R-A2L-DEF.58.1 | /arr-1, /arr-2 (the edit arm waits) | — |
| AT-B103-I3-1 | 3a arm: build every array, curve, map, CUBOID and CUBE_4 of V171 and decode those without a refusal (the twins, the shared axis, the three FIX forms, the refusals by code) | waiting arm: edit one value of each, apply, decode (rows .123, .131, .132) |
| AT-B103-I3-2 | 3a arm: build and decode each DEFC array, curve and map to the plan (rows .133 … .135) | waiting arm: the edits, the common-axis refusal (.127), the out-of-order refusal (.129), .131, .132 |
| AT-B103-I3-3 | 3a arm: build and decode every VAL_BLK, CURVE and MAP of both A2Ls (60, 60, 20 each, 0 refusals, element counts 128, 32, 64, decodes = the plan) | waiting arm: the edits land and keep the other cells (rows .123, .131, .132) |
| AT-B103-I3-4 | the whole case (building only; Inc 6's element counts) | — |

The Inc 2 cases that D-14 changes (R-A2L-DEF.4's case list, .24/1, AT-B103-I2-3; `codewire/graph-inc3.md` "Inc 2 cases this increment changes") describe and decode only: they are 3a.

**Split counts.**
- **3a: 179 cases.** These are 159 cases of the 61 3a rows (S2.7e 58, S2.7f 61, S2.7g 37, S2.7i 3), the 16 cited cases and the 4 acceptance cases. In 5 of them an arm waits for 3b: .58.1/arr-1, .58.1/arr-2, AT-B103-I3-1, -2 and -3.
- **3b: 36 cases.** S2.7g 3 (.120/2, .121/1, .121/2) and S2.7h 33 (.122 … .132). The proposed R-A2L-DEF.140 (`01-requirements.md`) would add 3 cases to 3b.
- **Total: 215 cases** (213 at E2, plus the rebase's .139/arr-1 and .136/arr-1).
