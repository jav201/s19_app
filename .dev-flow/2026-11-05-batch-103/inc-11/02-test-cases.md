# Inc 11 — test cases (ISO/IEC/IEEE 29119-3), E1

One case per coverage item `<requirement id>/<n>` of `01-requirements.md`, plus the acceptance cases `AT-B103-I11-1` … `AT-B103-I11-3`. Written at E1, before any test: **Tests** is empty, **Coverage** is `gap` and **Result** is `not_run` everywhere (the testers fill them at E4). Every A2L text here is synthetic; no operator data. **E1 addendum (2026-11-06, after E2; `E2-rulings.md`):** 16 cases added (the E2 corpus-class reductions `[K…]` and `[L1]` of `codewire/evidence-e2/i11e2-corpus-shapes.py`; R-A2L-016/1, /2; R-A2L-READ.53/1) and 4 changed (READ.39/1, .43/2, .48/2, .49/1): 166 cases and 3 acceptance cases.

## Common fixtures

- **HDR** — the frame every shape sits in: `ASAP2_VERSION 1 71`, `/begin PROJECT P ""`, `/begin MODULE M ""`, a MOD_COMMON with `BYTE_ORDER MSB_FIRST`, `/begin COMPU_METHOD CM_ID "" IDENTICAL "%.0" ""`, record layouts `RL_U8`, `RL_U16` and `RL_U32` (`FNC_VALUES 1 <type> ROW_DIR DIRECT`), `/begin TYPEDEF_MEASUREMENT T_U16 "" UWORD CM_ID 0 0 0 65535`, and the closing `/end MODULE`, `/end PROJECT`. This is `header()` in `evidence-e1/e1-census.py`.
- **MEAS(X, body…)** — `/begin MEASUREMENT X ""`, ` UWORD CM_ID 0 0 0 65535`, the body lines, `/end MEASUREMENT`. This is `meas()` in the census.
- **SYNMAP** — the synthetic MAP of `evidence-e1/e1-pilot-explorer-widths.py`:
  - `SYN_MAP_W` at 0x1C2D3E00, on `RL_SYN_MAP` (NO_AXIS_PTS_X, NO_AXIS_PTS_Y, FNC_VALUES UWORD);
  - two FIX_AXIS axes of 87 and 13 points, length 2266;
  - an S19 image holding its 2266 bytes.
- **Tracked files** — the 35 tracked `.a2l` files (`git ls-files '*.a2l'`).
- **Reference reading (REF)** — a lexer and field reader written in the tests, importing nothing from the reader. It applies the definitions of `01-requirements.md`. `evidence-e1/e1-census.py` (`ref_lex`, `ref_tree`, `split_header`, `ref_fields`) is its E1 model; E4 writes its own.
- **Hostile corpus** — 153 shapes, every one synthetic:
  - RP-A1 … A29 (29 shapes plus A26b and A26c; line ends, blanks, encodings);
  - RP-B1 … B40 (40 shapes; adjacency);
  - RP-C-* (47 shapes; Inc 2's E3 security shapes);
  - RP-D1 … D4 (INSTANCE and BLOB), from `e1-census.py`;
  - G0 and H1a … H3g (20 shapes), from `e1-probe-glue.py`;
  - K1, K1c, K2, K3, K4, K5, K5b, K7 and K7b (9 shapes; the E2 corpus-class reductions, CG-1), from `codewire/evidence-e2/i11e2-corpus-shapes.py`, each written from a class's structure description only and framed as that script frames it (its HDR has no `T_U16`; K7b declares it).
  Each counts once in R-A2L-READ.48/2.
- **Real Explorer** — the app started headless (`tests/support/b100_projects.run_app`) with the size of the case. The flow is: `load_selected_file(image)`, `load_a2l_from_path(a2l)`, then the workers drain. Key `2` shows the A2L Explorer, and the cursor goes on row 0. The painted lines are read back from `render_line(y).text` of `#a2l_tags_list` and `#a2l_detail_card`.

## Cases

| Case | Objective | Class | Preconditions | Inputs | Expected result | Tests (full / partial) | Coverage | Result |
|---|---|---|---|---|---|---|---|---|
| R-A2L-READ.1/1 | Verify that CRLF reads as LF | normal | tracked files | each file with every LF replaced by CRLF | tags, sections (line numbers included) and parse errors equal to the LF reading, 35/35 | | gap | not_run |
| R-A2L-READ.1/2 | Verify that a lone CR reads as LF | normal | tracked files | each file with every LF replaced by CR | as /1, 35/35 | | gap | not_run |
| R-A2L-READ.1/3 | Verify that mixed line ends read as LF | normal | tracked files | each file with its line ends cycling CRLF, CR, LF | as /1, 35/35 | | gap | not_run |
| R-A2L-READ.1/4 | Verify that CR CR LF counts two line ends | robustness | HDR | RP-A4 | tags and errors as the LF reading; each CR CR LF counts 2 line ends (a CR, then a CRLF), so line *k* of the LF file is line 2*k* − 1 | | gap | not_run |
| R-A2L-READ.2/1 | Verify that LF, CR and space end a word | normal | HDR, MEAS(X) | `ECU_ADDRESS<sep>0x1234`, sep ∈ {LF, CR, space} | address 0x1234, 3/3 | | gap | not_run |
| R-A2L-READ.2/2 | Verify that HT, VT and FF end a word | normal | as /1 | sep ∈ {HT, VT, FF} | address 0x1234, 3/3 | | gap | not_run |
| R-A2L-READ.3/1 | Verify that a non-blank character stays in its word | robustness | HDR, MEAS(X) | `ECU_ADDRESS 0x1234<c>`, c ∈ {U+00A0, U+0085, U+2028, U+2029, U+001C, U+001E, U+FEFF, U+200B, U+0000} | tag X has no address, 9/9 | | gap | not_run |
| R-A2L-READ.3/2 | Verify that NBSP between the keyword and its word joins them | robustness | as /1 | `ECU_ADDRESS<U+00A0>0x1234` | no address (one word `ECU_ADDRESS\u00a00x1234`) | | gap | not_run |
| R-A2L-READ.4/1 | Verify the unexpected-character error | robustness | as .3/1 | the 9 inputs of .3/1 on line 20 | exactly one error each: `Line 20: unexpected character U+00A0`, `… U+0085`, `… U+2028`, `… U+2029`, `… U+001C`, `… U+001E`, `… U+FEFF`, `… U+200B`, `… U+0000` | | gap | not_run |
| R-A2L-READ.4/2 | Verify that such a character in a comment or string gives no error | normal | HDR | `/* ° µ */` and `"°C"` on body lines | 0 errors | | gap | not_run |
| R-A2L-READ.4/3 | Verify that the tracked files give no unexpected-character error | normal | tracked files | each file | 0 such errors over 35 files | | gap | not_run |
| R-A2L-READ.4/4 | Verify that a Latin-1 byte (U+FFFD, R-A2L-001.7) gives the error in a word and none in a comment or string | robustness | HDR, written as Latin-1 bytes | [L1]: `/* 20 °C */` on its own line; MEAS(XL1, `ECU_ADDRESS 0x70`) with long identifier `"Temp °C"`; MEAS(`XL1_°`, `ECU_ADDRESS 0x72`) with its `/begin` on line <n>; each `°` the byte 0xB0 | each 0xB0 read as U+FFFD; exactly one error, `Line <n>: unexpected character U+FFFD` (the name word); none for the comment and the long identifier (XL1's long identifier `Temp <U+FFFD>C`) | | gap | not_run |
| R-A2L-READ.5/1 | Verify that a BOM before ASAP2_VERSION is dropped | normal | HDR | `\ufeff` + the file (RP-A8) | the reading equals the file without the BOM | | gap | not_run |
| R-A2L-READ.5/2 | Verify that a BOM before /begin PROJECT is dropped | robustness | HDR without ASAP2_VERSION | RP-A9 | PROJECT is a section; 0 errors | | gap | not_run |
| R-A2L-READ.6/1 | Verify the UTF-16 LE refusal | robustness | HDR | bytes `FF FE` + the text in UTF-16 LE (RP-A10) | errors = [`File is UTF-16 encoded; save it as UTF-8 and load it again.`]; 0 tags | | gap | not_run |
| R-A2L-READ.6/2 | Verify the UTF-16 BE refusal | robustness | HDR | bytes `FE FF` + UTF-16 BE | as /1 | | gap | not_run |
| R-A2L-001.2/1 | Verify that an old ECU_ADDRESS in a block comment is not read | robustness | HDR | RP-B7 | address 0x1234 | | gap | not_run |
| R-A2L-001.2/2 | Verify that an old BYTE_ORDER in a block comment is not read | robustness | HDR | RP-B37 | byte order little (MSB_LAST) | | gap | not_run |
| R-A2L-001.2/3 | Verify that an old MATRIX_DIM in a block comment is not read | robustness | HDR | RP-B27 | MATRIX_DIM 4, length 8 | | gap | not_run |
| R-A2L-001.2/4 | Verify that a BIT_MASK in a comment is not read | robustness | HDR | Inc 2 shape M (`/* BIT_MASK 0x0FF0 */`) | BIT_MASK word none | | gap | not_run |
| R-A2L-001.2/5 | Verify that an old LENGTH in a block comment is not read | robustness | HDR | MEAS(X, `ECU_ADDRESS 0x10`, `LENGTH 4`, `/*`, `LENGTH 2`, `*/`) | length 4 | | gap | not_run |
| R-A2L-001.2/6 | Verify that an ECU_ADDRESS behind // is not read | robustness | HDR | RP-B8 | address 0x1234 | | gap | not_run |
| R-A2L-001.2/7 | Verify that a commented ECU_ADDRESS before the live one on its line is not read | robustness | HDR | RP-B9 | address 0x1234 | | gap | not_run |
| R-A2L-001.2/8 | Verify that a commented MOD_COMMON BYTE_ORDER is not read | robustness | HDR with MOD_COMMON `/*`↵`BYTE_ORDER MSB_LAST`↵`*/`↵`BYTE_ORDER MSB_FIRST` | MEAS(X, `ECU_ADDRESS 0x10`) | X's byte order big | | gap | not_run |
| R-A2L-001.2/9 | Verify that a comment before the live ECU_ADDRESS on its line is not read | robustness | HDR | [K5b]: MEAS(XK5B, `/* moved */ ECU_ADDRESS 0x1234`) | address 0x1234 | | gap | not_run |
| R-A2L-READ.7/1 | Verify that a comment between address digits and digits splits them | robustness | HDR, RL_SYN_U16 | H2a (`MAP 0x1C2D3E00/*c*/4026 …`) | address 0x1C2D3E00 (not 0x1C2D3E004026); `4026` is a separate word | | gap | not_run |
| R-A2L-READ.7/2 | Verify that a multi-line comment glued on both sides splits | robustness | as /1 | H2b | address 0x1C2D3E00 | | gap | not_run |
| R-A2L-READ.7/3 | Verify that a comment glued after an ECU_ADDRESS word splits | robustness | HDR | RP-B1 | address 0x1234 | | gap | not_run |
| R-A2L-READ.7/4 | Verify that a comment glued on both sides of the keyword splits | robustness | HDR | RP-B4 | address 0x1234 | | gap | not_run |
| R-A2L-READ.7/5 | Verify that BIT_MASK/*b*/0x0FF0 reads keyword and word | robustness | HDR | Inc 2 shape G | BIT_MASK word `0x0FF0` | | gap | not_run |
| R-A2L-READ.7/6 | Verify that a header word glued to a comment and a keyword splits | robustness | HDR | Inc 2 shape F (`65535/* upper */BIT_MASK 0x0FF0`) | upper limit `65535`; BIT_MASK word `0x0FF0` | | gap | not_run |
| R-A2L-READ.8/1 | Verify that a block comment ends at its first */ | robustness | HDR | MEAS(X, `/* a /* b */ ECU_ADDRESS 0x1234`) | address 0x1234 | | gap | not_run |
| R-A2L-READ.8/2 | Verify that comments do not nest | robustness | HDR | RP-B40 (`/* a /* b */ c */`) | `c` is a word of X; the error of .11 for the `*/` | | gap | not_run |
| R-A2L-READ.9/1 | Verify a line comment ended by LF | normal | HDR | MEAS(X, `// c`, `ECU_ADDRESS 0x1234`) | address 0x1234 | | gap | not_run |
| R-A2L-READ.9/2 | Verify a line comment ended by CRLF | normal | as /1, CRLF | as /1 | address 0x1234 | | gap | not_run |
| R-A2L-READ.9/3 | Verify a line comment ended by a lone CR | normal | as /1, CR | as /1 | address 0x1234 | | gap | not_run |
| R-A2L-READ.10/1 | Verify the comment-not-closed error | robustness | HDR | `/* never closed` on line 20, then MEAS(X, `ECU_ADDRESS 0x1234`) | error `Line 20: comment not closed`; no tag X | | gap | not_run |
| R-A2L-READ.11/1 | Verify the stray */ error | robustness | HDR | `*/` alone on line 20 | error `Line 20: */ without /*` | | gap | not_run |
| R-A2L-READ.11/2 | Verify the stray */ after a nested comment | robustness | HDR | RP-B40 on line 22 | error `Line 22: */ without /*` | | gap | not_run |
| R-A2L-READ.11/3 | Verify that the tracked files give no stray */ error | normal | tracked files | each file | 0 such errors | | gap | not_run |
| R-A2L-READ.12/1 | Verify that a commented-out old copy is no tag | robustness | HDR | RP-B28 | exactly 1 tag X, address 0x1234; 0 `A2L_DUPLICATE_SYMBOL` | | gap | not_run |
| R-A2L-READ.12/2 | Verify that a commented-out object alone is no tag | robustness | HDR | RP-B29 | 0 tags X | | gap | not_run |
| R-A2L-READ.12/3 | Verify that a copy behind // on every line is no tag | normal | HDR | RP-B30 | 0 tags X | | gap | not_run |
| R-A2L-001.3.1/1 | Verify that a quoted string with a blank is one word | normal | HDR | `/begin MEASUREMENT X "a b"` | long identifier `a b` | | gap | not_run |
| R-A2L-001.3.1/2 | Verify the empty string | normal | HDR | `""` long identifier | one word, long identifier empty (no description) | | gap | not_run |
| R-A2L-001.3.1/3 | Verify that comment marks inside a string stay | normal | HDR | `"x/*y*/z"` | long identifier `x/*y*/z` | | gap | not_run |
| R-A2L-001.3.2/1 | Verify that `\\` before the closing quote ends the string | robustness | HDR | RP-B24 (`"C:\\"`) | long identifier `C:\\`; address 0x2000 | | gap | not_run |
| R-A2L-001.3.2/2 | Verify that `\"` does not end the string | normal | HDR | `"a\"b"` | one word `a\"b` | | gap | not_run |
| R-A2L-001.3.2/3 | Verify `\\` followed by `\"` | robustness | HDR | `"\\\""` | one word `\\\"` | | gap | not_run |
| R-A2L-READ.13/1 | Verify that /* in a string opens no comment | normal | HDR | MEAS(X, `FORMAT "/* x"`, `ECU_ADDRESS 0x1234`) | address 0x1234 | | gap | not_run |
| R-A2L-READ.13/2 | Verify that // in a string opens no comment | normal | HDR | MEAS(X, `PHYS_UNIT "// x"`, `ECU_ADDRESS 0x1234`) | address 0x1234 | | gap | not_run |
| R-A2L-READ.13/3 | Verify that /begin in a string opens no section | robustness | HDR | MEAS(X, `PHYS_UNIT "/begin MEASUREMENT Q"`, `ECU_ADDRESS 0x1234`) | 1 tag; no tag Q | | gap | not_run |
| R-A2L-READ.13/4 | Verify that /end in a multi-line string closes nothing | robustness | HDR | Inc 2 shape L7 | X's BIT_MASK word `0x0FF0`; X ends at its own /end | | gap | not_run |
| R-A2L-READ.14/1 | Verify that a string over line ends is one word | robustness | HDR | an ANNOTATION_TEXT string with two line ends | one word; the object's later BIT_MASK read | | gap | not_run |
| R-A2L-READ.15/1 | Verify the quoted-string-not-closed error | robustness | HDR | Inc 2 shape H, the quote on line 22 | error `Line 22: quoted string not closed` | | gap | not_run |
| R-A2L-READ.16/1 | Verify that a quote ends the name | robustness | HDR | RP-B20 (`X"long"`) | tag X, long identifier `long` | | gap | not_run |
| R-A2L-READ.16/2 | Verify that a quote ends the FORMAT string before a keyword | robustness | HDR | Inc 2 shape U | BIT_MASK word `0x0FF0` | | gap | not_run |
| R-A2L-READ.16/3 | Verify that a quote after the address word splits it | robustness | HDR | H2d | address 0x1C2D3E00 | | gap | not_run |
| R-A2L-001.1/1 | Verify a /begin after other words on a line | robustness | HDR | Inc 2 J4 | IF_DATA is a child of SX; SX's BIT_MASK word `0x0FF0` | | gap | not_run |
| R-A2L-001.1/2 | Verify a /begin after a comment on its line | normal | HDR | `/* c */ /begin MEASUREMENT X ""` … | tag X | | gap | not_run |
| R-A2L-001.1/3 | Verify an /end after words on its line | normal | HDR | MEAS(X, `ECU_ADDRESS 0x1234 /end MEASUREMENT`) without its own /end line | tag X closed on that line; 0 errors | | gap | not_run |
| R-A2L-001.1/4 | Verify two one-line INSTANCEs on one line | robustness | HDR (its `T_U16`) | [K7b]: one line `/begin INSTANCE IK7 "" T_U16 0x20 /end INSTANCE /begin INSTANCE IK7B "" T_U16 0x40 /end INSTANCE`, then MEAS(XK7B, `ECU_ADDRESS 0x60`) | two INSTANCE sections, each with `start_line` = `end_line`; spans IK7 at 0x20 and IK7B at 0x40; tag XK7B at 0x60; 0 errors | | gap | not_run |
| R-A2L-READ.17/1 | Verify that V171's one-line IF_DATA close | normal | `ASAP2_Demo_V171.a2l` | the file | 0 parse errors; 30/30 IF_DATA closed on their line; every MEASUREMENT at depth 3 | | gap | not_run |
| R-A2L-READ.17/2 | Verify a one-line IF_DATA before ECU_ADDRESS | robustness | HDR | RP-B13 | address 0x1234 | | gap | not_run |
| R-A2L-READ.17/3 | Verify a one-line IF_DATA before BYTE_ORDER | robustness | HDR | Inc 2 C1 | byte order little | | gap | not_run |
| R-A2L-READ.18/1 | Verify upper-case /BEGIN … /END | normal | HDR | `/BEGIN MEASUREMENT X ""` … `/END MEASUREMENT` | tag X | | gap | not_run |
| R-A2L-READ.18/2 | Verify mixed case | normal | HDR | `/Begin` … `/eNd` | tag X | | gap | not_run |
| R-A2L-READ.19/1 | Verify that /beginMEASUREMENT is no /begin | robustness | HDR | RP-B31 | no section `X`; error `Line <n>: /end MEASUREMENT does not close /begin MODULE` | | gap | not_run |
| R-A2L-READ.19/2 | Verify that /endX closes nothing | robustness | HDR | MEAS(X, `/endX`) | X closes at its own /end; `/endX` a word of X | | gap | not_run |
| R-A2L-READ.20/1 | Verify the keyword on the line after /begin | normal | HDR | `/begin`↵`MEASUREMENT X ""`… | tag X | | gap | not_run |
| R-A2L-READ.20/2 | Verify a comment between /begin and its keyword | normal | HDR | `/begin /*c*/ MEASUREMENT X ""`… | tag X | | gap | not_run |
| R-A2L-001.4/1 | Verify a stray /end at the start of a line | robustness | HDR | `/end X` on line 30 after `/end PROJECT` | error `Line 30: /end without /begin` | | gap | not_run |
| R-A2L-001.4/2 | Verify a stray /end after words | robustness | as /1 | `junk /end X` on line 30 | as /1 | | gap | not_run |
| R-A2L-001.5/1 | Verify /end IF_DATA closing a MEASUREMENT | robustness | HDR | MEAS(X) whose /end reads `/end IF_DATA` on line 23 | error `Line 23: /end IF_DATA does not close /begin MEASUREMENT` | | gap | not_run |
| R-A2L-001.5/2 | Verify /end MEASUREMENT closing an IF_DATA | robustness | HDR | MEAS(X, `/begin IF_DATA XCP`) with no `/end IF_DATA`, its /end on line 23 | error `Line 23: /end MEASUREMENT does not close /begin IF_DATA` | | gap | not_run |
| R-A2L-READ.21/1 | Verify that an /end closes the innermost section | robustness | as .001.5/1 | as .001.5/1 | X closed at line 23 (after the error) | | gap | not_run |
| R-A2L-READ.22/1 | Verify the /include error | robustness | `merge_inc_test.a2l` | the file | exactly one error `Line <n>: /include <file> is not read`, `<file>` the word without quotes | | gap | not_run |
| R-A2L-READ.22/2 | Verify that /include in a comment gives no error | normal | HDR | `/* /include "x.a2l" */` | 0 errors | | gap | not_run |
| R-A2L-READ.23/1 | Verify the name on the next line | robustness | HDR | RP-B16 | tag X | | gap | not_run |
| R-A2L-READ.23/2 | Verify the name after a comment | robustness | HDR | RP-B19 | tag X | | gap | not_run |
| R-A2L-READ.23/3 | Verify a name glued to a comment | robustness | HDR | RP-B18 | tag X | | gap | not_run |
| R-A2L-READ.23/4 | Verify V161 and V171's UNKNOWN | normal | V161, V171 | the files | a CHARACTERISTIC `ASAM.C.ASCII.UBYTE.NUMBER_42` at 0x810200 in each; 0 tags `UNKNOWN` | | gap | not_run |
| R-A2L-READ.23/5 | Verify two MEASUREMENTs written one word per line | robustness | HDR | [K1]: twice `/begin MEASUREMENT` ↵ name ↵ `"long id"` ↵ `UWORD` ↵ `CM_ID` ↵ `0` ↵ `0` ↵ `0` ↵ `65535` ↵ `ECU_ADDRESS` ↵ address ↵ `/end MEASUREMENT`, names `XK1`, `XK1B`, addresses `0x1234`, `0x1236` | tags `XK1` at 0x1234 and `XK1B` at 0x1236, datatype UWORD, length 2; 0 tags `UNKNOWN`; 0 `A2L_DUPLICATE_SYMBOL` | | gap | not_run |
| R-A2L-READ.23/6 | Verify a CHARACTERISTIC written one word per line | robustness | HDR | [K1c]: `/begin CHARACTERISTIC` ↵ `CK1` ↵ `"long id"` ↵ `VALUE` ↵ `0x2000` ↵ `RL_U16` ↵ `0` ↵ `CM_ID` ↵ `0` ↵ `65535` ↵ `/end CHARACTERISTIC` | tag `CK1`, kind VALUE, address 0x2000, deposit RL_U16 | | gap | not_run |
| R-A2L-READ.24/1 | Verify the long identifier on a body line | normal | V161, V171 | the files | 73 + 116 tags get their long identifier (e.g. V171 `ASAM.M.SCALAR.UBYTE.IDENTICAL` → `Scalar measurement`) | | gap | not_run |
| R-A2L-READ.24/2 | Verify no long identifier when the next word is not a string | normal | `case_07_stress_smoke/firmware.a2l` | the file | 12/12 tags with no long identifier and their e07fb00 address | | gap | not_run |
| R-A2L-READ.25/1 | Verify BalanceTube's commented MEASUREMENT headers | normal | BalanceTube | the file | 104/104 MEASUREMENTs with datatype and length (e.g. `model.MainClass.gameController.sm` UBYTE, 1) | | gap | not_run |
| R-A2L-READ.25/2 | Verify the virtual MEASUREMENT of V161 and V171 | normal | V161, V171 | the files | `ASAM.M.VIRTUAL.SCALAR.SWORD.PHYSICAL` datatype SWORD, length 2, conversion `CM.VIRTUAL.EXTERNAL_VALUE` | | gap | not_run |
| R-A2L-READ.25/3 | Verify the header on the /begin line | robustness | HDR | RP-B14 | datatype UWORD, length 2 | | gap | not_run |
| R-A2L-READ.25/4 | Verify the header over commented lines | robustness | HDR | RP-B15 | datatype UWORD, length 2 | | gap | not_run |
| R-A2L-READ.25/5 | Verify a header written one word per line | robustness | HDR | [K2]: `/begin MEASUREMENT XK2 ""` ↵ `UWORD` ↵ `CM_ID` ↵ `0` ↵ `0` ↵ `0` ↵ `65535` ↵ `ECU_ADDRESS 0x1234` ↵ `/end MEASUREMENT` | datatype UWORD, length 2, address 0x1234 | | gap | not_run |
| R-A2L-READ.25/6 | Verify the header of a one-line MEASUREMENT holding a one-line IF_DATA | robustness | HDR | [K5]: one line `/begin MEASUREMENT XK5 "d" FLOAT64_IEEE NO_COMPU_METHOD 0 0 -100 100  ECU_ADDRESS 0x18 ECU_ADDRESS_EXTENSION 3 READ_WRITE /begin IF_DATA XCP /begin DAQ_EVENT FIXED_EVENT_LIST EVENT 0x0 /end DAQ_EVENT /end IF_DATA /end MEASUREMENT` | datatype FLOAT64_IEEE, length 8 | | gap | not_run |
| R-A2L-READ.26/1 | Verify the CHARACTERISTIC header on the /begin line | robustness | HDR | RP-B23 | address 0x2000, kind VALUE, deposit RL_U16 | | gap | not_run |
| R-A2L-READ.26/2 | Verify a header over lines with comments | robustness | HDR | RP-B22 | address 0x2000 | | gap | not_run |
| R-A2L-READ.26/3 | Verify an address glued to a comment and the deposit | robustness | HDR | RP-B21 / Inc 2 A4 | address 0x10 or 0x2000 as written; deposit RL_U16 | | gap | not_run |
| R-A2L-READ.26/4 | Verify a full header on the /begin line before ECU_ADDRESS_EXTENSION | robustness | HDR | [K3]: `/begin CHARACTERISTIC CK3 "d" VALUE 0x1000 RL_U16 0 CM_ID 100 10000` ↵ `ECU_ADDRESS_EXTENSION 0` ↵ `BYTE_ORDER MSB_LAST` ↵ `PHYS_UNIT "ms"` ↵ `STEP_SIZE 1` ↵ `/end CHARACTERISTIC` | kind VALUE, address 0x1000, deposit RL_U16, length 2 | | gap | not_run |
| R-A2L-READ.26/5 | Verify an extended-kind header on the /begin line before NUMBER | robustness | HDR | [K4]: `/begin CHARACTERISTIC CK4 "d" CUBE_5 0x123 RL_U16 1 CM_ID 0 10` ↵ `NUMBER 10000` ↵ `READ_ONLY` ↵ `FORMAT "%3.3"` ↵ `STEP_SIZE 1` ↵ `/end CHARACTERISTIC` | kind CUBE_5, address 0x123, deposit RL_U16 | | gap | not_run |
| R-A2L-READ.27/1 | Verify that case 07 keeps its reading | normal | case 07 | the file | 12/12 tags as e07fb00 (address, length, limits, unit) | | gap | not_run |
| R-A2L-READ.27/2 | Verify that a short header ends at BIT_MASK | robustness | HDR | Inc 2 shape C | datatype UWORD; BIT_MASK word `0x0FF0`; upper limit none | | gap | not_run |
| R-A2L-READ.27/3 | Verify a CHARACTERISTIC with no kind keeps its ECU_ADDRESS | normal | HDR | `/begin CHARACTERISTIC Q`, `ECU_ADDRESS 0x10`, `LENGTH 2` | address 0x10, length 2 | | gap | not_run |
| R-A2L-READ.27/4 | Verify that ECU_ADDRESS_EXTENSION after a full header is no header word | robustness | HDR | [K3] (as .26/4) | `ECU_ADDRESS_EXTENSION` and `BYTE_ORDER` read as keywords: kind not `ECU_ADDRESS_EXTENSION`, address not 0x0, deposit not `BYTE_ORDER`; byte order little | | gap | not_run |
| R-A2L-READ.27/5 | Verify that NUMBER after a full header is no header word | robustness | HDR | [K4] (as .26/5) | `NUMBER` read as a keyword: kind not `NUMBER`, address not 0x2710, deposit not `READ_ONLY` | | gap | not_run |
| R-A2L-READ.28/1 | Verify the short MEASUREMENT header error | robustness | HDR | Inc 2 shape C, /begin on line 20 | `Line 20: MEASUREMENT SX has 5 of its 6 header words` | | gap | not_run |
| R-A2L-READ.28/2 | Verify the short CHARACTERISTIC header error | robustness | HDR | H3c's header, /begin on line 20 | `Line 20: CHARACTERISTIC Synthetic map has 6 of its 7 header words` | | gap | not_run |
| R-A2L-READ.28/3 | Verify no header error on the tracked files | normal | tracked files | each file | 0 such errors | | gap | not_run |
| R-A2L-READ.28/4 | Verify the error for a 4-word MEASUREMENT header | robustness | HDR | [K7]: `/begin MEASUREMENT XK7 "" UWORD CM_ID 0 0` on line 20 ↵ `ECU_ADDRESS 0x10` ↵ `/end MEASUREMENT` | error `Line 20: MEASUREMENT XK7 has 4 of its 6 header words`; datatype UWORD, length 2 | | gap | not_run |
| R-A2L-READ.29/1 | Verify the address on the next line | robustness | HDR | RP-B5 | address 0x1234 | | gap | not_run |
| R-A2L-READ.29/2 | Verify the address two lines down | robustness | HDR | RP-B6 | address 0x1234 | | gap | not_run |
| R-A2L-READ.29/3 | Verify the mask word on the next line | robustness | HDR | Inc 2 shape N | BIT_MASK word `0x0FF0` | | gap | not_run |
| R-A2L-READ.29/4 | Verify MATRIX_DIM numbers over two lines | robustness | HDR | MEAS(X, `ECU_ADDRESS 0x10`, `MATRIX_DIM 2`, `3`) | MATRIX_DIM 6, length 12 | | gap | not_run |
| R-A2L-READ.30/1 | Verify two keywords on one line | robustness | HDR | RP-B12 | address 0x1234, byte order little | | gap | not_run |
| R-A2L-READ.30/2 | Verify a BIT_MASK after a one-line IF_DATA on its line | robustness | HDR | Inc 2 J3 | BIT_MASK word `0x0FF0` | | gap | not_run |
| R-A2L-READ.30/3 | Verify an ECU_ADDRESS mid-line in a one-line MEASUREMENT | robustness | HDR | [K5] (as .25/6) | address 0x18; 0 errors | | gap | not_run |
| R-A2L-READ.31/1 | Verify that an IF_DATA's address words are not the tag's | normal | HDR | MEAS(X, `ECU_ADDRESS 0x1234`, `/begin IF_DATA ETK KP_BLOB 0x9999 /end IF_DATA`) | address 0x1234 | | gap | not_run |
| R-A2L-READ.31/2 | Verify that an ANNOTATION_TEXT's BIT_MASK is not the tag's | normal | HDR | Inc 2 shape W | BIT_MASK word none | | gap | not_run |
| R-A2L-READ.31/3 | Verify that an AXIS_DESCR's BYTE_ORDER is not the tag's | normal | HDR | a CURVE whose AXIS_DESCR holds `BYTE_ORDER MSB_LAST` | the tag's byte order big | | gap | not_run |
| R-A2L-READ.32/1 | Verify two ECU_ADDRESS | robustness | HDR | MEAS(X, `ECU_ADDRESS 0x10` line 22, `ECU_ADDRESS 0x20` line 23) | error `Line 23: ECU_ADDRESS is declared twice in MEASUREMENT X`; address 0x20 (D-6 A) | | gap | not_run |
| R-A2L-READ.32/2 | Verify two BYTE_ORDER | robustness | HDR | as /1 with BYTE_ORDER | error `… BYTE_ORDER is declared twice …` | | gap | not_run |
| R-A2L-READ.32/3 | Verify two BIT_MASK | robustness | HDR | Inc 2 shape P | error `… BIT_MASK is declared twice in MEASUREMENT SX` | | gap | not_run |
| R-A2L-READ.32/4 | Verify no duplicate on the tracked files | normal | tracked files | each file | 0 such errors | | gap | not_run |
| R-A2L-READ.33/1 | Verify the display identifier without its comment | normal | V161, V171 | the files | 6/6 tags (e.g. `ASAM.M.SCALAR.UBYTE.IDENTICAL` → `DI.ASAM.M.SCALAR.UBYTE.IDENTICAL`); the detail card's first line holds no `/*` | | gap | not_run |
| R-A2L-READ.33/2 | Verify a synthetic display identifier | normal | HDR | RP-A29 | `XM_disp` | | gap | not_run |
| R-A2L-READ.34/1 | Verify hexadecimal words | normal | HDR | ECU_ADDRESS `0x1234`, `0X1234`, `0x0000000000001234` | 0x1234, 3/3 | | gap | not_run |
| R-A2L-READ.35/1 | Verify a decimal word with a leading zero | normal | HDR | RP-B32 (`010`) | address 10 | | gap | not_run |
| R-A2L-READ.35/2 | Verify a decimal word | normal | HDR | `ECU_ADDRESS 4096` | address 4096 | | gap | not_run |
| R-A2L-READ.36/1 | Verify that the underscore word is no number | robustness | HDR | RP-B33, H2e | no address, 2/2 | | gap | not_run |
| R-A2L-READ.36/2 | Verify that signed words are no number | robustness | HDR | RP-B35, `+16` | no address, 2/2 | | gap | not_run |
| R-A2L-READ.36/3 | Verify that fullwidth and 0b words are no number | robustness | HDR | RP-B34, `0b101` | no address, 2/2 | | gap | not_run |
| R-A2L-READ.37/1 | Verify the MATRIX_DIM product of the tracked tags | normal | V161, V171, update_test1, update_test2 | the files | the 14 listed tags' MATRIX_DIM = the product; their length from it | | gap | not_run |
| R-A2L-READ.37/2 | Verify MATRIX_DIM 2 2 | normal | HDR | RP-B26 | MATRIX_DIM 4, length 8 | | gap | not_run |
| R-A2L-READ.38/1 | Verify that lengths 0 and −5 give no length | robustness | HDR | MEAS(X, `ECU_ADDRESS 0x10`, `LENGTH 0`) and `LENGTH -5` | no length, 2/2 | | gap | not_run |
| R-A2L-READ.38/2 | Verify that lengths above 1 MiB give no length | robustness | HDR | `LENGTH 1048577`, Inc 2 H3 (`LENGTH 99999999999`), H1 (ASCII `NUMBER 1000000000000`) | no length, 3/3 | | gap | not_run |
| R-A2L-READ.38/3 | Verify that 1 MiB itself keeps its length | normal | HDR | `LENGTH 1048576` | length 1048576 | | gap | not_run |
| R-A2L-READ.39/1 | Verify the length error | robustness | as .38/1, /2 | the 4 inputs of .38/1, /2 that hold a number word (`LENGTH 0`, `LENGTH 1048577`, `LENGTH 99999999999`, ASCII `NUMBER 1000000000000`), X's /begin on line 20 | `Line 20: MEASUREMENT X has the length 0, outside 1 to 1048576 bytes` (and 1048577, 99999999999; `CHARACTERISTIC SX … 1000000000000`), 4/4; `LENGTH -5` is not an input: `-5` is not a number word (R-A2L-READ.36), so there is no length to print (F-E2-3) | | gap | not_run |
| R-A2L-016/1 | Verify a VAL_BLK sized by its layout's datatype and MATRIX_DIM | robustness | HDR | [K6]: `/begin CHARACTERISTIC CK6 ""` ↵ `VAL_BLK 0x3000 RL_U16 0 CM_ID 0 65535` ↵ `MATRIX_DIM 4` ↵ `/end CHARACTERISTIC` | length 8 (UWORD, the FNC_VALUES datatype of `RL_U16`, × 4) | | gap | not_run |
| R-A2L-016/2 | Verify a tracked VAL_BLK on a layout whose name carries no size | normal | `ASAP2_Demo_V161.a2l` | the file | `ASAM.C.ARRAY.SWORD.MATRIX_DIM_6.ROW_DIR` (layout `RL.FNC.SWORD.ROW_DIR`, `MATRIX_DIM 6 1 1`) length 12 | | gap | not_run |
| R-A2L-READ.53/1 | Verify a VAL_BLK sized by NUMBER when it has no MATRIX_DIM | robustness | HDR | [K6b]: `/begin CHARACTERISTIC CK6B ""` ↵ `VAL_BLK 0x3010 RL_U16 0 CM_ID 0 65535` ↵ `NUMBER 4` ↵ `/end CHARACTERISTIC` | length 8 (UWORD × 4) | | gap | not_run |
| R-A2L-READ.40/1 | Verify a BLOB span | normal | HDR | RP-D1 | span (B1, BLOB, 0x10, 2) | | gap | not_run |
| R-A2L-READ.40/2 | Verify the tracked BLOBs | normal | tracked files | each file | 7 BLOB spans | | gap | not_run |
| R-A2L-READ.40/3 | Verify that a commented-out BLOB is no span | robustness | HDR | RP-D4 | 0 spans | | gap | not_run |
| R-A2L-READ.41/1 | Verify the tracked INSTANCEs | normal | tracked files | each file | 82 INSTANCE spans with their address words | | gap | not_run |
| R-A2L-READ.42/1 | Verify an INSTANCE of a TYPEDEF_MEASUREMENT | normal | HDR | RP-D2 | span (I1, INSTANCE, 0x10, 2) | | gap | not_run |
| R-A2L-READ.42/2 | Verify the INSTANCE's MATRIX_DIM | normal | HDR | RP-D3 | length 10 | | gap | not_run |
| R-A2L-READ.43/1 | Verify an INSTANCE of a VALUE typedef | normal | V171 | the file | `ASAM_I_SCALAR_VALUE_UWORD_SINGLE` at 0x810000, length 2 | | gap | not_run |
| R-A2L-READ.43/2 | Verify an INSTANCE of a VAL_BLK typedef | normal | HDR | a TYPEDEF_CHARACTERISTIC VAL_BLK on RL_U16 with `MATRIX_DIM 3` (E1 addendum, F-E2-5: was `NUMBER 3`, which R-A2L-016 does not size), INSTANCE `MATRIX_DIM 2` | length 12 (UWORD, the FNC_VALUES datatype of `RL_U16` (CG-2), × 3 × 2) | | gap | not_run |
| R-A2L-READ.43/3 | Verify an INSTANCE of an ASCII typedef | normal | HDR | ASCII typedef `NUMBER 8` | length 8 | | gap | not_run |
| R-A2L-READ.44/1 | Verify an INSTANCE of a TYPEDEF_BLOB | normal | HDR | `TYPEDEF_BLOB TB "" 6`, INSTANCE of it | length 6 | | gap | not_run |
| R-A2L-READ.44/2 | Verify an INSTANCE of a TYPEDEF_STRUCTURE with MATRIX_DIM | normal | HDR | `TYPEDEF_STRUCTURE TS "" 12`, INSTANCE `MATRIX_DIM 3` | length 36 | | gap | not_run |
| R-A2L-READ.45/1 | Verify an INSTANCE of a TYPEDEF_AXIS | robustness | HDR | INSTANCE of a TYPEDEF_AXIS | span with no length | | gap | not_run |
| R-A2L-READ.45/2 | Verify an INSTANCE of a CURVE typedef | robustness | HDR | INSTANCE of a CURVE TYPEDEF_CHARACTERISTIC | span with no length | | gap | not_run |
| R-A2L-READ.45/3 | Verify an INSTANCE of an unknown typedef | robustness | HDR | INSTANCE naming `T_NONE` | span with no length | | gap | not_run |
| R-A2L-READ.46/1 | Verify BLOB sizes 0 and 1048577 | robustness | HDR | two BLOBs | no length, 2/2 | | gap | not_run |
| R-A2L-READ.46/2 | Verify an INSTANCE with MATRIX_DIM 4294967296 | robustness | HDR | INSTANCE of T_U16 | no length | | gap | not_run |
| R-A2L-READ.48/1 | Verify the reader against REF on the tracked files | normal | tracked files, REF | each file | 0 differences on the fields of the row; ≤ 120 s | | gap | not_run |
| R-A2L-READ.48/2 | Verify the reader against REF on the hostile corpus | robustness | hostile corpus, REF | 153 shapes | 0 differences, 153/153 | | gap | not_run |
| R-A2L-READ.49/1 | Verify no regression outside the listed defects | normal | tracked files; the e07fb00 readings saved as a fixture at E4 (taken on a clean checkout of `e07fb00`, transcript kept) | each file | 234,428 tags identical on the six fields; tag count per file equal; the 226 listed tags differ as the list says (E1 addendum: +3 by R-A2L-016, +101 by R-A2L-READ.53) | | gap | not_run |
| R-TUI-042a.2/1 | Verify a gap between cells at 220 and 160 columns | normal | Real Explorer, SYNMAP | 220×50, 160×50 | `0x1C2D3E00` and `2266` in separate cells with ≥ 1 blank between; `0x1C2D3E002266`, `SYN_MAP_W0x1C2D3E00`, `17921792` and `unknown0..` painted 0 times | | gap | not_run |
| R-TUI-042a.2/2 | Verify a gap between cells at 118, 100 and 80 columns | normal | as /1 | 118×50, 100×50, 80×50 | as /1 for every cell shown | | gap | not_run |
| R-A2L-READ.50/1 | Verify the summary header without its comment | normal | HDR | RP-A27 | the A2L Sections line of XH reads `- CHARACTERISTIC XH "one-line header" VALUE 0x00003000 RL_U32 0 CM_ID 0 100 (lines …)` | | gap | not_run |
| R-A2L-READ.50/2 | Verify that two blanks show as one | normal | HDR | `VALUE  0x00003000` in the /begin line | one blank | | gap | not_run |
| R-A2L-READ.50/3 | Verify a quoted word keeps its quotes in the summary | normal | HDR | `"one-line header"` | shown with its quotes | | gap | not_run |
| R-A2L-READ.51/1 | Verify that control characters in a long identifier show as U+FFFD | robustness | HDR | RP-A21, RP-A23, and the same with VT, FF, U+001C, U+0085, U+2028, U+2029, NUL | each shows U+FFFD; the summary lines all match `^(\s*- |A2L |\.\.\. |No A2L)` or are empty (0 broken), 9/9 | | gap | not_run |
| R-A2L-076/1 | Verify that a file with parse errors lists its sections | normal | `merge_inc_test.a2l` after the fix | the summary | `A2L parse errors:` with its error, then `A2L Sections:` with its sections | | gap | not_run |
| R-A2L-076/2 | Verify the same for an inline file with an error | robustness | HDR + a stray `/end X` | the summary | errors, then sections | | gap | not_run |
| R-A2L-077/1 | Verify that a file with parse errors lists its tags | normal | as .076/2 with MEAS(X, `ECU_ADDRESS 0x10`) | the summary | `A2L Tags:` with `- MEASUREMENT X: 0x00000010 len=2 mem=unknown` | | gap | not_run |
| R-A2L-READ.52/1 | Verify the parse time | normal | cachyos-rtx; the e07fb00 medians measured in the same session | case_06 and software_a, 3 runs each | median ≤ 1.5 × e07fb00's median, 2/2 | | gap | not_run |

## Acceptance cases (black box, through the app)

| Case | Objective | Class | Preconditions | Inputs | Expected result | Tests | Coverage | Result |
|---|---|---|---|---|---|---|---|---|
| AT-B103-I11-1 | Verify that the A2L Explorer never paints an address joined to another cell (the operator's symptom) | normal | Real Explorer, SYNMAP | widths 220, 160, 118, 100, 80; cursor on the row | the row paints `0x1C2D3E00` with a blank after it; the detail card's first line `✓ SYN_MAP_W  0x1C2D3E00`; no 12-digit hex string painted | | gap | not_run |
| AT-B103-I11-2 | Verify that a commented-out old copy changes nothing the operator sees | normal | Real Explorer; an image at 0x1234 | RP-B28 loaded | 1 row `X` at `0x00001234`; the Issues screen holds no `A2L_DUPLICATE_SYMBOL`; the Workspace A2L summary lists 1 tag | | gap | not_run |
| AT-B103-I11-3 | Verify that V171 loads clean and its summary shows sections and tags | normal | Real app, `ASAP2_Demo_V171.a2l` | load it | status `A2L loaded: ASAP2_Demo_V171.a2l` (no parse errors); the Workspace A2L summary holds `A2L Sections:` and `A2L Tags:` | | gap | not_run |

## E5 evidence, not a test (CG-6)

At E5 the corpus differential (`run_corpus_differential`, `codewire/graph-inc11.md`) runs on the runner only, as evidence: the 158 files of `../../design/a2l-corpus/manifest.tsv`, each file's sha256 checked against the manifest before it is read, next to the 35-file no-regression set. It is no case of this file and no CI test; its transcript (counts and positions only, no file text) goes to `inc-11/evidence-e5/`.
