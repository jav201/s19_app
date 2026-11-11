# Inc 6 — E2 test-case ledger (ISO/IEC/IEEE 29119-3)

Stage E1/E2 design, amended at E5 for the Check missing-length design gap. **Counts: 77 cases = 77 threshold alternatives; 56 `normal`, 21 `robustness`; 21/21 requirements mapped. Tests entries are unassigned, coverage `gap`, results `not_run`.** No execution or verification is claimed.

## Product-route and oracle rules

- Drive the shipping `S19TuiApp` through Textual `run_test()`/Pilot, the real A2L/image load routes, editor tabs, keys and buttons. Population through the panel's public `set_a2l_parameters` is allowed for focused component cases; acceptance rows load real A2L text. Read painted cells/full-name/status and actual entry inputs, not only internal state.
- `ARR12`: MEASUREMENT, MATRIX_DIM 2 3, UWORD, address `0x1000`, declared length 12, enriched `byte_size=2`. `VB4`: CHARACTERISTIC VAL_BLK, UBYTE, address `0x2000`, length 4, enriched `byte_size=1`. `MAP10`: a valid MAP record at `0x3000`, whole declared length 10. `TXT5`: ASCII at `0x4000`, NUMBER/length 5.
- Non-uniform image oracles: ARR12 bytes `00 01 02 03 04 05 06 07 08 09 0A 0B`; VB4 `10 11 12 13`; TXT5 `41 42 43 44 45`. MAP10 uses `20 21 22 23 24 25 26 27 28 29`. Expected values are pinned here, never derived from the picker or enriched decode.
- `REFUSED`: four valid reader fixtures whose final tag length is absent: R1 VALUE on UWORD layout with conflicting LENGTH 4; R2 VAL_BLK MATRIX_DIM 4 plus NUMBER 5; R3 VALUE LENGTH 0; R4 VAL_BLK with invalid MATRIX_DIM. R5 is MEASUREMENT `LENGTH 99999999999`. All retain a readable address and enriched `byte_size=None`; no test repairs their A2L to make the happy path pass.
- Datatype expectations: UBYTE/BYTE→`u8`; SBYTE→`s8`; UWORD/WORD→`u16`; SWORD→`s16`; ULONG/LONG→`u32`; SLONG→`s32`; A_UINT64→`u64`; A_INT64→`s64`; FLOAT16_IEEE→`f16`; FLOAT32_IEEE→`f32`; FLOAT64_IEEE→`f64`. ARR12→`u16`; TXT5→`text`; UWORD unit `%`→`u16 %`; unknown/absent→`?`.
- `DESCRIBE` is a spy on `describe_definitions`, used only for call counts/arguments. `REBUILD` counts ledger rebuilds. `DOC` snapshots entries, dirty flag and undo/redo checkpoints. `READ` counts image lookups. Spies never replace visible/value assertions.
- Geometry cases assert actual widget regions and operability at the stated terminal size, not just `render()` strings. Every negative assertion (wrong size/format, missing exact status, forbidden byte/document write, extra describe/rebuild) is part of its case.

## Ledger

| Case | Objective | Class | Preconditions | Product-route inputs | Exact expected result and negative assertions | Tests | Coverage | Result |
|---|---|---|---|---|---|---|---|---|
| R-PICKER-CORRECT.001/1 | Verify that Check stores scalar declared length | normal | Scalar UWORD row length 2, byte_size 2 | Populate Check | Size 2; no byte_size-derived alternative. | — | gap | not_run |
| R-PICKER-CORRECT.001/2 | Verify that Check stores array declared length | normal | ARR12 row, byte_size 2 | Populate Check | Size 12, not 2/1; row remains ARR12. | — | gap | not_run |
| R-PICKER-CORRECT.001/3 | Verify that Patch stores scalar declared length | normal | Scalar UWORD row length 2, byte_size 2 | Populate Patch | Size 2; no enriched fallback. | — | gap | not_run |
| R-PICKER-CORRECT.001/4 | Verify that Patch stores array declared length | normal | ARR12 row, byte_size 2 | Populate Patch | Size 12, not 2/1; highlighted read model agrees. | — | gap | not_run |
| R-PICKER-CORRECT.002/1 | Verify whole MATRIX_DIM length in both editors | normal | ARR12 loaded through real A2L route | Open Check and Patch ledgers | Both size 12 and same full-length read model; no element size 2. | — | gap | not_run |
| R-PICKER-CORRECT.002/2 | Verify whole VAL_BLK length in both editors | normal | VB4 loaded | Open both ledgers | Both size 4, not 1. | — | gap | not_run |
| R-PICKER-CORRECT.002/3 | Verify whole MAP record length in both editors | normal | MAP10 loaded | Open both ledgers | Both size 10, not one decode unit. | — | gap | not_run |
| R-PICKER-CORRECT.002/4 | Verify whole ASCII length in both editors | normal | TXT5 loaded | Open both ledgers | Both size 5, not 1; format remains text under .003. | — | gap | not_run |
| R-PICKER-CORRECT.003/1 | Verify UBYTE format | normal | UBYTE length 1 | Populate both | `u8`; no signed/float label. | — | gap | not_run |
| R-PICKER-CORRECT.003/2 | Verify SBYTE format | normal | SBYTE length 1 | Populate both | `s8`, never `u8`. | — | gap | not_run |
| R-PICKER-CORRECT.003/3 | Verify BYTE format | normal | BYTE length 1 | Populate both | `u8`. | — | gap | not_run |
| R-PICKER-CORRECT.003/4 | Verify UWORD format | normal | UWORD length 2 | Populate both | `u16`. | — | gap | not_run |
| R-PICKER-CORRECT.003/5 | Verify SWORD format | normal | SWORD length 2 | Populate both | `s16`, never `u16`. | — | gap | not_run |
| R-PICKER-CORRECT.003/6 | Verify WORD format | normal | WORD length 2 | Populate both | `u16`. | — | gap | not_run |
| R-PICKER-CORRECT.003/7 | Verify ULONG format | normal | ULONG length 4 | Populate both | `u32`. | — | gap | not_run |
| R-PICKER-CORRECT.003/8 | Verify SLONG format | normal | SLONG length 4 | Populate both | `s32`, never `u32`. | — | gap | not_run |
| R-PICKER-CORRECT.003/9 | Verify LONG format | normal | LONG length 4 | Populate both | `u32`. | — | gap | not_run |
| R-PICKER-CORRECT.003/10 | Verify A_UINT64 format | normal | A_UINT64 length 8 | Populate both | `u64`. | — | gap | not_run |
| R-PICKER-CORRECT.003/11 | Verify A_INT64 format | normal | A_INT64 length 8 | Populate both | `s64`, never `u64`. | — | gap | not_run |
| R-PICKER-CORRECT.003/12 | Verify FLOAT16 format | normal | FLOAT16_IEEE length 2 | Populate both | `f16`, never `u16`. | — | gap | not_run |
| R-PICKER-CORRECT.003/13 | Verify FLOAT32 format | normal | FLOAT32_IEEE length 4 | Populate both | `f32`, never `u32`. | — | gap | not_run |
| R-PICKER-CORRECT.003/14 | Verify FLOAT64 format | normal | FLOAT64_IEEE length 8 | Populate both | `f64`, never `u64`. | — | gap | not_run |
| R-PICKER-CORRECT.003/15 | Verify array format uses element datatype | normal | ARR12 length 12 | Populate both | `u16`, never `u96`/`u8`. | — | gap | not_run |
| R-PICKER-CORRECT.003/16 | Verify ASCII format | normal | TXT5 length 5 | Populate both | `text`, never `u40`. | — | gap | not_run |
| R-PICKER-CORRECT.003/17 | Verify unit follows element format | normal | UWORD length 2, unit `%` | Populate both | Exact `u16 %`; one separating space. | — | gap | not_run |
| R-PICKER-CORRECT.003/18 | Verify unknown format is not fabricated | robustness | Unknown/absent datatype, length 3 | Populate both | Exact `?`, never `u24`. | — | gap | not_run |
| R-PICKER-CORRECT.004/1 | Verify R1 length stays missing | robustness | R1 loaded, byte_size None | Populate both | `size is None` in both; never 1/2. | — | gap | not_run |
| R-PICKER-CORRECT.004/2 | Verify R2 length stays missing | robustness | R2 loaded, byte_size None | Populate both | `size is None` in both; never 1/2. | — | gap | not_run |
| R-PICKER-CORRECT.004/3 | Verify R3 length stays missing | robustness | R3 loaded, byte_size None | Populate both | `size is None` in both; never 1/2. | — | gap | not_run |
| R-PICKER-CORRECT.004/4 | Verify R4 length stays missing | robustness | R4 loaded, byte_size None | Populate both | `size is None` in both; never 1/2. | — | gap | not_run |
| R-PICKER-CORRECT.005/1 | Verify Use refuses R1 without bytes | robustness | R1 highlighted, Bytes nonempty sentinel, DOC armed | Press real Use parameter | Bytes empty; exact `Parameter has no length — Bytes not prefilled.`; DOC equal; 0 byte reads. | — | gap | not_run |
| R-PICKER-CORRECT.005/2 | Verify Use refuses R2 without bytes | robustness | R2 highlighted, DOC armed | Press Use | Same exact refusal/empty Bytes/DOC/0 reads; no one-element prefill. | — | gap | not_run |
| R-PICKER-CORRECT.005/3 | Verify Use refuses R3 without bytes | robustness | R3 highlighted, DOC armed | Press Use | Same exact refusal/empty Bytes/DOC/0 reads. | — | gap | not_run |
| R-PICKER-CORRECT.005/4 | Verify Use refuses R4 without bytes | robustness | R4 highlighted, DOC armed | Press Use | Same exact refusal/empty Bytes/DOC/0 reads. | — | gap | not_run |
| R-PICKER-CORRECT.005/5 | Verify Use refuses huge-length reader refusal | robustness | R5 loaded and highlighted, DOC armed | Press Use | Same exact refusal; no 1-byte or giant read, DOC equal. | — | gap | not_run |
| R-PICKER-CORRECT.006/1 | Verify Use transfers whole VAL_BLK | normal | VB4 fully mapped `10 11 12 13`, DOC armed | Highlight VB4; Use | Address `0x00002000`; Bytes exactly `10 11 12 13`; DOC equal. | — | gap | not_run |
| R-PICKER-CORRECT.006/2 | Verify Use transfers whole matrix array | normal | ARR12 fully mapped `00`…`0B`, DOC armed | Highlight ARR12; Use | Address `0x00001000`; Bytes exactly all 12 non-uniform bytes; DOC equal. | — | gap | not_run |
| R-PICKER-CORRECT.006/3 | Verify Use transfers whole ASCII object | normal | TXT5 fully mapped `41`…`45`, DOC armed | Highlight TXT5; Use | Address `0x00004000`; Bytes exactly `41 42 43 44 45`; DOC equal. | — | gap | not_run |
| R-PICKER-CORRECT.007/1 | Verify no image cannot fabricate array bytes | robustness | ARR12, no image, DOC armed | Use | Address `0x00001000`; Bytes empty; exact `Parameter address loaded; image bytes unavailable.`; DOC equal. | — | gap | not_run |
| R-PICKER-CORRECT.007/2 | Verify missing middle byte cannot zero-fill | robustness | ARR12 mapped except address `0x1005`, DOC armed | Use | Bytes empty, same unavailable text, DOC equal; no `00` substituted at offset 5 and no 11-byte result. | — | gap | not_run |
| R-PICKER-CORRECT.008/1 | Verify over-cap read is skipped | robustness | Length cap+1, full-coverage READ spy, DOC armed | Use | 0 lookups; Bytes empty; exact existing `<size>-byte over-cap` status; DOC equal. | — | gap | not_run |
| R-PICKER-CORRECT.008/2 | Verify exact-cap read is attempted | normal | Length cap with full coverage | Use | Exactly cap bytes in ascending order; no over-cap status. | — | gap | not_run |
| R-PICKER-CORRECT.009/1 | Verify scalar spec match retains name | normal | Scalar at 0x1000 length 2; spec address/size 2 | Load spec into Check | Named parameter included at 2; no memory row; spec bytes preserved. | — | gap | not_run |
| R-PICKER-CORRECT.009/2 | Verify full array spec match retains name | normal | ARR12; spec address 0x1000/size 12 | Load spec | ARR12 included at 12; no memory row; exact 12 spec bytes retained. | — | gap | not_run |
| R-PICKER-CORRECT.009/3 | Verify element-sized array spec does not steal name | normal | ARR12; spec address 0x1000/size 2 | Load spec | ARR12 not included from that entry; one unlabelled memory row at 0x1000 size 2 with exact spec bytes. | — | gap | not_run |
| R-PICKER-CORRECT.010/1 | Verify unchanged full length keeps spec inclusion | normal | ARR12 spec size 12 included; same length new A2L generation | Reload A2L and settle Check | ARR12 remains included at 12 with original spec bytes; no memory row. | — | gap | not_run |
| R-PICKER-CORRECT.010/2 | Verify changed full length demotes spec entry | normal | ARR12 spec size 12; new generation length 8 | Reload A2L | ARR12 not re-included; memory row preserves original address, size 12 and bytes; no size-2 substitute. | — | gap | not_run |
| R-PICKER-CORRECT.011/1 | Verify Patch presents include control | normal | Patch A2L tab visible | Show tab; toggle highlighted row with space then enter | Include control visible; pick toggles on then off with SelectionChanged; no document mutation. | — | gap | not_run |
| R-PICKER-CORRECT.011/2 | Verify Patch presents Add list | normal | Patch A2L tab visible | Inspect `#patch_param_bulk_button` | Exactly one visible enabled `Add list` bound to Patch picker. | — | gap | not_run |
| R-PICKER-CORRECT.011/3 | Verify both editors' ids and modes coexist | normal | Check and Patch mounted | Inspect both picker families and toggle each | All `check_param_*`/`patch_param_*` ids unique; each has independent picks/events. | — | gap | not_run |
| R-PICKER-CORRECT.012/1 | Verify Patch bulk modal opens empty | normal | No picks; Patch A2L tab | Press Add list | One shared modal, multiline focused area, exact instruction, Include matches and Close; bound to Patch. | — | gap | not_run |
| R-PICKER-CORRECT.012/2 | Verify Patch bulk modal opens with prior pick | normal | Alpha already picked | Press Add list | Same one modal/focus/exact controls; Alpha remains picked and target is Patch. | — | gap | not_run |
| R-PICKER-CORRECT.013/1 | Verify mixed Patch bulk include and counts | normal | Alpha picked; source Alpha/Beta; DOC armed | Paste `Beta, Missing; Alpha`; Include | Picks Alpha,Beta; included 1/already 1/not found 1/first Missing; DOC equal. | — | gap | not_run |
| R-PICKER-CORRECT.013/2 | Verify duplicate new token counts once | normal | Beta source, no picks | Paste `Beta Beta` | Beta once; included 1/already 0/not found 0. | — | gap | not_run |
| R-PICKER-CORRECT.013/3 | Verify duplicate prior pick counts once | normal | Alpha already picked | Paste `Alpha Alpha` | Alpha once; included 0/already 1/not found 0. | — | gap | not_run |
| R-PICKER-CORRECT.013/4 | Verify case variant misses exactly | normal | Source `Alpha` only | Paste `alpha` | No picks; included 0/already 0/not found 1/first `alpha`. | — | gap | not_run |
| R-PICKER-CORRECT.014/1 | Verify exact mixed summary | normal | Alpha picked; Alpha/Beta/Gamma source | Paste `Beta,Alpha,Gamma`; Include | Exact `Included 1 · already included 1 · not found 1 — first missing: Gamma`. | — | gap | not_run |
| R-PICKER-CORRECT.014/2 | Verify zero-parsed summary is inert | robustness | Existing Alpha pick | Paste separators/whitespace only; Include | Exact `No listed parameters found.`; Alpha remains; counts not fabricated. | — | gap | not_run |
| R-PICKER-CORRECT.014/3 | Verify parsed no-match summary names first | normal | Source Alpha/Beta | Paste `Gamma Delta`; Include | Included 0/already 0/not found 2 and first Gamma; no generic zero-parsed text. | — | gap | not_run |
| R-PICKER-CORRECT.015/1 | Verify successful bulk does not rebuild or write document | normal | Patch page/filter and DOC/REBUILD armed | Include Beta; close | Beta picked/mark visible; page/filter unchanged; REBUILD 0; DOC equal. | — | gap | not_run |
| R-PICKER-CORRECT.015/2 | Verify Cancel is inert | robustness | Existing Alpha; Beta unpicked; DOC/REBUILD armed | Type Beta; Cancel | Picks only Alpha; REBUILD 0; DOC equal; no Beta mark. | — | gap | not_run |
| R-PICKER-CORRECT.015/3 | Verify Escape is inert | robustness | Same as /2 | Type Beta; Escape | Same inert result; no selection/document/ledger delta. | — | gap | not_run |
| R-PICKER-CORRECT.016/1 | Verify Use after bulk transfers highlighted ARR12 only | normal | ARR12 and VB4 bulk-picked; ARR12 highlighted; image full | Use | Exactly ARR12's 12 bytes; both picks retained; DOC equal; no VB4 bytes added. | — | gap | not_run |
| R-PICKER-CORRECT.016/2 | Verify Use after bulk transfers highlighted VB4 only | normal | Same picks; VB4 highlighted | Use | Exactly `10 11 12 13`; both picks retained; DOC equal. | — | gap | not_run |
| R-PICKER-CORRECT.017/1 | Verify hostile parameter name is literal and replaced | robustness | Name contains `[red]`, ESC, NUL and C1 | Populate both and read cells/full name | Literal brackets, zero markup spans, U+FFFD for each control, no raw control/exception. | — | gap | not_run |
| R-PICKER-CORRECT.017/2 | Verify hostile unit is literal and replaced | robustness | UWORD unit contains `[link=e]`, ESC and DEL | Populate both | Literal `u16 [link=e]` with U+FFFD replacements, zero spans/raw controls. | — | gap | not_run |
| R-PICKER-CORRECT.017/3 | Verify long UWORD format/unit is bounded on both picker surfaces | robustness | UWORD; 400-cell hostile unit containing `[red]`, ESC, NUL and C1 | Populate both at 80 and 118 columns; read ledger cell and full-name line | At each width, exact literal `u16 ` plus the U+FFFD-normalized unit, clipped to each surface's cell budget with visible `…`, in BOTH the ledger cell and full-name line; zero markup spans/raw controls, no overflow/exception; datatype remains `u16`, never `?`. | — | gap | not_run |
| R-PICKER-CORRECT.018/1 | Verify equal signature preserves state and avoids describe | normal | Filter/page/picks set; DESCRIBE armed | Populate same signature again | 0 describes; filter/page/picks byte-identical; no rebuild. | — | gap | not_run |
| R-PICKER-CORRECT.018/2 | Verify changed signature describes once per picker | normal | Generation 1 ARR12; generation 2 length/format changed | Reload A2L with both visible | Exactly 1 describe per picker containing all names; both paint new length/format; no per-row calls. | — | gap | not_run |
| R-PICKER-CORRECT.018/3 | Verify None signature always repopulates and resets state | normal | Rows length 2; real A2L data; DESCRIBE armed; non-default filter/page/picks seeded before each call | Call twice with signature=None, reseeding filter/page/picks before each call | Both calls return True; after each call filter/page are at defaults and picks are empty; two real populations paint current rows; one describe per call with all names and actual A2L data; no equal-signature no-op. | — | gap | not_run |
| R-PICKER-CORRECT.018/4 | Verify Inc 5 reload refreshes both without re-entry | normal | Check/Patch visible throughout; A2L1 ARR12 length 12 | Load A2L2 same name length 8 | Both size 8/current format before outcome, 1 describe each, no manual refresh or editor re-entry. | — | gap | not_run |
| R-PICKER-CORRECT.019/1 | Verify 13,990-object batch describe budget | normal | software_a-shaped 13,990-object fixture; Linux serial_timing | Populate picker; median 3 | Median ≤2.0 s; one batch call/all names; normalized count 13,990; no timeout. | — | gap | not_run |
| R-PICKER-CORRECT.019/2 | Verify that filter/page rebuilds never describe | normal | Populated 13,990 rows; DESCRIBE armed | 20 filter/page rebuilds | 0 describes; each mounts ≤200 rows; current formats unchanged. | — | gap | not_run |
| R-PICKER-CORRECT.020/1 | Verify Patch controls fit and operate at 80×24 | normal | Patch A2L tab at 80×24 | Measure regions; toggle include; open/close bulk | Every named visible surface non-zero and inside panel; no horizontal overflow; both actions work. | — | gap | not_run |
| R-PICKER-CORRECT.020/2 | Verify Patch controls fit and operate at 118×54 | normal | Patch A2L tab at 118×54 | Same geometry/actions | Same containment/operability; no regression of Use/status/page controls. | — | gap | not_run |
| R-PICKER-CORRECT.021/1 | Verify that Validate refuses an included missing length before any action | robustness | R1 included with full image coverage; ActionRequested, image-read and document-write spies armed | Press Validate | Exact `Check Editor: parameter has no length — validate/write refused.`; 0 actions, 0 reads and 0 writes; no one-byte substitution. | — | gap | not_run |
| R-PICKER-CORRECT.021/2 | Verify that Write refuses an included missing length before any action | robustness | Same as .021/1 | Press Write | Same exact refusal and zero action/read/write; existing included fields remain unchanged and no one-byte document is emitted. | — | gap | not_run |

## Coverage reconciliation

- Requirement totals: .001=4, .002=4, .003=18, .004=4, .005=5, .006=3, .007=2, .008=2, .009=3, .010=2, .011=3, .012=2, .013=4, .014=3, .015=3, .016=2, .017=3, .018=4, .019=2, .020=2, .021=2; sum **77**.
- Robustness: .003/18 (1), .004/1–4 (4), .005/1–5 (5), .007/1–2 (2), .008/1 (1), .014/2 (1), .015/2–3 (2), .017/1–3 (3), .021/1–2 (2). The robustness total is **21**, and normal is **56**, matching the header.
- R5 is explicitly additional to the four shapes of .004, making .005 five cases. No expected value is read from enriched output. ARR12 and VB4 distinguish full length from layout element size; non-uniform bytes distinguish truncation and zero-fill.
