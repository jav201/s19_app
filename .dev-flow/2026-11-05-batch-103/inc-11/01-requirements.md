# Inc 11 — A2L reader: comments, quoted strings, line ends, one-line IF_DATA, INSTANCE/BLOB: requirements (E1)

Batch 2026-11-05-batch-103, increment 11 (amendment A2: `s19_app/tui/a2l.py` unfrozen for this increment). Branch `batch-103`, product tree `e07fb00`. Stage E1 of `dev-flow-v3-beta`. Open decisions are in `E1-rulings.md` §3 (PROPOSED, awaiting the orchestrator). The rows below follow the recommended option of each; a different ruling changes the rows it names. **E1 addendum (2026-11-06, after E2; authority `E2-rulings.md`):** CG-1, CG-2 (R-A2L-016 only; see the notes under G), CG-3 (R-A2L-READ.53), CG-5 A, CG-6 and F-E2-3 are applied here.

Form column: U = ubiquitous, When = event, If = unwanted behaviour. "Base" column: what `e07fb00` does today, and how it is known:
- **C** = the E1 census on cachyos-rtx (Python 3.11.18, textual 8.2.8, clone `e07fb00`, 0 changed files): `evidence-e1/e1-census.py` in three modes, `chars`, `fixtures` and `repro`. Their transcripts are `e1-chars-transcript.txt`, `e1-fixtures-transcript.txt` and `e1-repro-transcript.txt`, and the lists are `e1-fx-*.jsonl`.
  - **REF** is the census's own reference lexer. It is written for the census and imports nothing from `s19_app`. It applies the definitions below.
  - **CANON(file)** is the same file written out again from REF's words, in the layout today's reader handles.
  - A tag that today's reader gives differently from CANON(file) is a tag its word rules get wrong.
- **B** = a pilot on cachyos-rtx.
  - `evidence-e1/e1-pilot-explorer-widths.py` drives the real app headless. It loads a synthetic MAP and an image, shows the A2L Explorer at 5 widths, and reads back the painted lines (`e1-widths-transcript.txt`, tags `[W<width>]`).
  - `evidence-e1/e1-pilot-glued-cells.py` paints a tag row headless. The table is a stand-in built with the product's DataTable arguments (`app.py:8516-8521`) and the product's own row cells, so this evidence is partial.
  - `evidence-e1/e1-probe-glue.py` runs the hypotheses about the glued address.
- **R** = read in the code, not run.
- **K** = the E2 corpus-class reductions on the base reader: `codewire/evidence-e2/i11e2-corpus-shapes.py` (synthetic shapes written from each class's structure description only), transcript `i11e2-corpus-shapes-transcript.txt`, tags `[K1]` … `[L1]`.
- **A** = the E1-addendum census: the base reader (this tree's `a2l.py`; `git diff e07fb00` empty) over the 35 tracked files on the addendum's Windows host (Python 3.12.7; 234,654 tags, as C). A scratch script, not kept; E4's fixture of R-A2L-READ.49/1 re-takes these counts on cachyos-rtx.

Tags in `[...]` cite a transcript line, for example `[RP-B7]`, `[H2a]` or `[P3]`.

Row status:
- **changed**: the canon row is corrected here (`E1-rulings.md` §1).
- **new**: a new canon row. Each id was checked unused in `REQUIREMENTS.md`, `docs/requirements/review/`, `C:\Users\jjgh8\Github\s19w\review\`, every `.dev-flow/*/` folder, and `git grep` on `b101-inc9`, `b101-inc10`, `b101-inc12` and `b101-inc12b`. The family `R-A2L-READ` occurs nowhere.
- **cited**: a canon row whose text stays, but which the code does not meet today. This increment's code must meet it.

## User stories

### US-103-07 — an A2L file is read as it is written (operator report, 2026-11-07)

As the operator, I want every address, length and name that the system shows from an A2L file to be exactly what the file declares. Where the file is malformed, I want a parse error that names the line. So I never act on an address shown with an adjacent character, or on an address the file does not declare.

The operator's words: «las direcciones de memoria a veces se reportan incluso con caracteres contiguos como salto de línea… es un riesgo muy alto tener problemas con lectura de a2l» (`design/operator-report-a2l-reader.md`).

The operator added evidence on 2026-11-07, relayed by the orchestrator. It is not saved here, by the operator's request. The A2L Explorer showed a CHARACTERISTIC's address with four extra hex digits appended. The same row showed the Region and Limits cells read as one word.

### US-103-05 (enabler) — the definition model rests on a reader it can trust

As the Patch Editor's definition model (Inc 2b, Inc 3b, Inc 6 and Inc 8), I want the tag table and the section tree free of these misreadings: comment, string, one-line IF_DATA, INSTANCE/BLOB and commented-out object. Then the write-path guards (R-A2L-DEF.19, .138 and .139) no longer have to work around the reader's defects one shape at a time (`inc-2/E3-rulings.md`, "Why the rounds do not converge").

### US-103-02 (part) — the A2L views show only the objects the file declares

As the operator, I want the A2L Explorer, the Workspace A2L summary, the Issues screen and the MAC View to show only live objects. A MEASUREMENT or CHARACTERISTIC that the file comments out is not a tag, and it is not a duplicate symbol.

## Reproduction of the operator's symptom (scope item 1)

**Reproduced, synthetic data only.** Two mechanisms give an address with extra digits appended. A third puts a line break right after an address.

1. **The tag table paints adjacent cells with no gap. This is the operator's case: a view defect, not a reader defect.** The table is built with `cell_padding=0` (`app.py:8520`), as the canon row R-TUI-042a.2 asks.
   - The **real app** was driven headless (`evidence-e1/e1-pilot-explorer-widths.py`, `e1-widths-transcript.txt`). The test object is a synthetic MAP at `0x1C2D3E00`, with two axis-count fields and 87 × 13 UWORD values. The reader computes its length, 2266, and reads its address right [W220: reader address 0x1c2d3e00].
   - At 220, 160, 118, 100 and 80 columns, the painted row reads `SYN_MAP_W0x1C2D3E002266`: the name, the Address cell and the computed Length cell, as one string [W220 … W80].
   - At 220 and 160 columns, the same row also paints Raw+Physical as `17921792` and Region+Limits+Unit as `unknown0..4095%.0`.
   - The detail card shows `✓ SYN_MAP_W  0x1C2D3E00`, separated and right [W… card].
   - The four extra digits are therefore the length, computed by the reader. They are not read from the file, which agrees with the operator's search of the real file.
   - A stand-in table with the product's arguments shows the same with `cell_padding=0`, and neither string with `cell_padding=1` [P3].
   - No address or length format string in `a2l.py`, `a2l_render.py`, `app.py`, `screens_directionb.py`, `a2l_parameter_picker.py` or `render/hexview.py` joins two values without a separator. That grep rules out the string-concatenation hypothesis (H6).
   - Fix: R-TUI-042a.2, in `app.py`. The row is outside `a2l.py`; it is ruled at D-1.
2. **The reader glues a comment's neighbours.** The CHARACTERISTIC header is read through `_strip_a2l_comments`, which removes a comment without leaving a word break (`a2l.py:406-411`).
   - `MAP 0x1C2D3E00/*c*/4026 …` gives the address `0x1C2D3E004026` [H2a]. A block comment that runs to the next line does the same [H2b].
   - Python's `int(x, 0)` reads `0x1C2D3E00_4026` as `0x1C2D3E004026` [H2e].
   - Test TC-097 pins the glue (`tests/test_a2l_multiline_headers.py:389`: `"CURVE/*c*/0x1" == "CURVE0x1"`).
   - Fix: R-A2L-READ.7 and .36.
3. **A line break right after an address, in the Workspace A2L summary.** The summary text is split with `str.splitlines()` (`services/a2l_service.py:26`). That call also breaks lines at VT, FF, FS, GS, RS, NEL, U+2028 and U+2029.
   - When one of these stands after the address word of a `/begin` line, the A2L Sections line breaks right after the address [RP-A19, A20, A24, A25, A26, A26b, A26c].
   - U+001E inside a long identifier does the same [RP-A21].
   - Fix: R-A2L-READ.50 and .51.

**Ruled out:** the hypotheses that a separator glues an address to the next number (H1), and that a missing name shifts the address (H3).
- NUL, U+200B and U+FEFF next to an address keep it in one unreadable word, so the address is lost [H1a–H1c].
- CR, VT and NBSP split the word, so the next number becomes a header word and the length is lost [H1d–H1f].
- A quoted name in place of the name reads the address right [H3a].
- AXIS_DESCR headers on their `/begin` line send the FIX_AXIS_PAR numbers into the axis point counts, and the length is lost [H3e]. No address is affected.

**Other wrong readings found** (every class has rows below):
- An address is lost:
  - glued to a comment [RP-B1, B2, B4, H2f];
  - after a comment [RP-B3, B9];
  - on the next line [RP-B5, B6];
  - after a one-line IF_DATA [RP-B13];
  - on a header that is on the `/begin` line [RP-B23];
  - after NUL, U+FEFF or the cp1252 NBSP byte [RP-A15, A16, A22].
- An address is wrong:
  - a commented-out ECU_ADDRESS line wins [RP-B7, C-B3];
  - a commented-out old copy is a tag [RP-B28, B29].
- The byte order is wrong: a BYTE_ORDER after a one-line IF_DATA, inside a comment, or second on a line [RP-B12, B37, C-C1, C-C2].
- A length is wrong: a MATRIX_DIM inside a comment [RP-B27]; MATRIX_DIM read by its first number [B26: REF 4, reader 2].
- A name is lost: on the next line, glued to a comment, or glued to its long identifier [RP-B16, B18, B19, B20].
- The datatype is lost or wrong: a MEASUREMENT header on its `/begin` line or spread over lines [RP-B14, B15].
- The mask word is kept with a comment glued to it [RP-B38].
- The file encoding:
  - A UTF-16 file loads with 0 tags and 0 errors [RP-A10, A11].
  - A BOM before `/begin PROJECT` loses the PROJECT section [RP-A9].
- CRLF, a lone CR, mixed line ends and CR CR LF read exactly as LF [RP-A1–A5, A28]. That is true today, and R-A2L-READ.1 keeps it.
- On the 35 tracked files, CANON finds 110 tags read wrongly and 189 tags with other fields wrong. MATRIX_DIM finds 14 more. See R-A2L-READ.49 and "Defect tags at e07fb00".

## Definitions (additions and changes to CTX-A2L-FILE and CTX-A2L-TAG; terms only)

- **line end** (CTX-A2L-FILE, new): LF, CRLF or a lone CR.
- **blank** (new): space U+0020, horizontal tab U+0009, vertical tab U+000B or form feed U+000C.
- **comment** (changed): outside a quoted string, either a block comment or a line comment.
  - A block comment is the text from `/*` to the first `*/` after it. Comments do not nest.
  - A line comment is the text from `//` to the next line end.
- **quoted string** (changed): the text between a `"` and the next `"` that is not escaped. Inside it, a backslash and the character after it form one escaped pair, for example `\"` or `\\`.
- **word** (new): a quoted string, or a run of word characters.
- **word character** (new): any character that is not a blank, not a line end, not `"`, and not the `/` that starts `/*` or `//`.
- **section** (changed): a block from a `/begin` word to its matching `/end` word.
  - The word after `/begin` is the section's keyword (`<NAME>`).
  - The section's **header** is its words after the keyword and before its first child section, its first keyword, or its `/end`.
  - A section's **own words** are its words outside its child sections.
- **number word** (new): `0x` or `0X` followed by 1 to 16 hexadecimal digits; or 1 to 20 decimal digits. ASCII only.
- **header words** (CTX-A2L-TAG, new):
  - MEASUREMENT, 6: datatype, conversion, resolution, accuracy, lower limit, upper limit.
  - CHARACTERISTIC, 7: kind, address, deposit, maximum difference, conversion, lower limit, upper limit.
- **keyword** (CTX-A2L-TAG, new): one of the words that may stand among a MEASUREMENT's or CHARACTERISTIC's own words, with its argument count (*arity*):
  - ADDRESS_TYPE 1, ARRAY_SIZE 1, BIT_MASK 1, BYTE_ORDER 1, CALIBRATION_ACCESS 1, COMPARISON_QUANTITY 1;
  - DISCRETE 0, DISPLAY_IDENTIFIER 1, ECU_ADDRESS 1, ECU_ADDRESS_EXTENSION 1, ENCODING 1, ERROR_MASK 1;
  - EXTENDED_LIMITS 2, FORMAT 1, GUARD_RAILS 0, LAYOUT 1, MATRIX_DIM 1 to 3, MAX_REFRESH 2;
  - MODEL_LINK 1, NUMBER 1, PHYS_UNIT 1, READ_ONLY 0, READ_WRITE 0, REF_MEMORY_SEGMENT 1, STEP_SIZE 1, SYMBOL_LINK 2;
  - and the tool extensions the reader reads today: DATA_SIZE 1, LENGTH 1, DATA_TYPE 1, FUNCTION 1, COMPU_METHOD 1, FORMULA 1, UNIT 1, LOWER_LIMIT 1, UPPER_LIMIT 1, VIRTUAL 0, CALIBRATABLE 0, DEPOSIT 1.
- **MATRIX_DIM** (CTX-A2L-TAG, changed): the product of the 1 to 3 numbers after the MATRIX_DIM keyword; 1 when there is none. Rows R-A2L-014 and R-A2L-016 cite it.
- **datatype (CHARACTERISTIC)** (CTX-A2L-TAG, new at the E1 addendum, CG-2): the datatype of the FNC_VALUES of the CHARACTERISTIC's record layout; when the layout names none, the datatype its deposit name spells out (as R-A2L-022 and R-A2L-023 take it). Rows R-A2L-015, R-A2L-016 and R-A2L-READ.53 cite it.
- **declared span** (CTX-A2L-TAG, new): an INSTANCE or BLOB of the A2L file, given as its name, its kind (`INSTANCE` or `BLOB`), its address, and a length or no length. Declared spans are not tags.
- **reference reading** (new): the reading of an A2L file under these definitions and the rows of S2.1 and S2.2, by a lexer written for the tests that does not import the reader. It is the oracle of R-A2L-READ.48.
- **hostile corpus** (new): the shapes listed under "Common fixtures" in `02-test-cases.md`: at least 60 shapes, every class this file names.
- **defect tags at e07fb00** (new): the tags listed at the end of this file.

## Requirements

### A. The text: line ends, blanks, encodings (US-103-07)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-A2L-READ.1 | U | The system shall read a CRLF or a lone CR in an A2L file as one line end, as it reads an LF. | 105/105: the 35 tracked files rewritten with CRLF, with lone CR and with mixed line ends each give the same tags, sections (line numbers included) and parse errors as the LF file | the file read with `newline=""` (CR kept in words) → the CRLF reading differs | 07 | new | true today, so the row keeps it through the rewrite: C [RP-A1–A5, A28] |
| R-A2L-READ.2 | U | The system shall end a word at a blank or a line end. | 6/6: LF, CR, space, HT, VT and FF between `ECU_ADDRESS` and `0x1234` each give the address 0x1234 | VT and FF left out of the blanks → 2 cases give no address | 07 | new | partly: Unicode `str.isspace` also ends a word at NBSP, NEL, FS–US, U+2028 and U+2029 (C [RP-A14, A18]; R `a2l.py:327`, `:2663`) |
| R-A2L-READ.3 | U | The system shall read every character other than a blank, a line end, a double quote and the start of a comment as a word character. | 9/9: U+00A0, U+0085, U+2028, U+2029, U+001C, U+001E, U+FEFF, U+200B and U+0000, each written right after `0x1234` in `ECU_ADDRESS 0x1234`, give the tag no address | `str.isspace` used as the separator → the U+00A0 case reads 0x1234 | 07 | new | no: NBSP and U+2028 split words [RP-A14, A18]; NUL and U+FEFF stay in the word [RP-A16, A22] |
| R-A2L-READ.4 | If | If a word outside comments and quoted strings holds a character outside U+0021 … U+007E, then the system shall record the parse error `Line <n>: unexpected character U+<XXXX>`. | 10/10: the 9 characters of .3, and a Latin-1 byte read as U+FFFD (R-A2L-001.7) in a name word ([L1]), each give exactly one error, whose `<n>` is the line and whose `<XXXX>` is 4 or more uppercase hex digits; the same byte in a comment or a quoted string gives none ([L1]); 0 errors on the 35 tracked files (C: no such character outside comments and strings) | the check removed → 0 errors → RED | 07 | new | no error; the address is lost silently (C [RP-A15, A16, A22]); a Latin-1 byte gives U+FFFD and no error (K [L1]) |
| R-A2L-READ.5 | When | When an A2L file starts with the UTF-8 byte order mark, the system shall read the file from the byte after the mark. | 2/2: BOM + `ASAP2_VERSION …`, and BOM + `/begin PROJECT …`, give the reading of the same file without the BOM | the mark kept → the second gives `/end without /begin` and no PROJECT | 07 | new | no: the BOM is kept as U+FEFF; a BOM before `/begin PROJECT` loses the section and gives `Line <n>: /end without /begin` (C [RP-A9]); V171 and BalanceTube carry a BOM before `ASAP2_VERSION`, which is harmless today (C [CH]) |
| R-A2L-READ.6 | If | If an A2L file starts with a UTF-16 byte order mark, then the system shall record the parse error `File is UTF-16 encoded; save it as UTF-8 and load it again.` | 2/2 (`FF FE`, `FE FF`): exactly this one error and 0 tags | the check removed → 0 errors → RED | 07 | new | no: 0 tags and 0 errors, so the load reports `A2L loaded: <file>` (C [RP-A10, A11]) |

### B. Comments (US-103-07, US-103-05, US-103-02)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-A2L-001.2 | U | The system shall read no word from the text of a comment. | 9/9 shapes give the live value: an old ECU_ADDRESS, BYTE_ORDER, MATRIX_DIM, BIT_MASK and LENGTH each inside `/* … */` after the live one; an ECU_ADDRESS behind `//`; an ECU_ADDRESS in `/* … */` before the live one on its line; MOD_COMMON's BYTE_ORDER inside a comment before the live one; a comment before the live ECU_ADDRESS on its line ([K5b]) | the tag walk reads raw lines again → the ECU_ADDRESS shape gives the old address → RED | 07, 05 | changed | no: raw lines are read, and the last ECU_ADDRESS, MATRIX_DIM and BYTE_ORDER win (C [RP-B7, B27, B37, C-B3, C-C2]; MOD_COMMON: Inc 2 [C3]); a `//` line is right today [RP-B8]; [K5b] gives no address (K) |
| R-A2L-READ.7 | U | The system shall read a comment as a word break. | 6/6: `0x1C2D3E00/*c*/4026` (CHARACTERISTIC header) gives the address 0x1C2D3E00 and a separate word 4026; `ECU_ADDRESS 0x1234/*c*/`, `ECU_ADDRESS/*c*/0x1234`, `BIT_MASK/*b*/0x0FF0`, `65535/*u*/BIT_MASK 0x0FF0` and `VALUE 0x2000/* x↵ */RL_U16` each read as their words | a comment removed with no break → the first case gives 0x1C2D3E004026 → RED | 07, 05 | new | no: glued in the CHARACTERISTIC header (`0x1C2D3E004026`, C [H2a, H2b]; Inc 2 shapes F, G, C5); a raw word elsewhere, so the address is lost [RP-B1, B4, B21, B22]; test TC-097 pins the glue (`tests/test_a2l_multiline_headers.py:389`) |
| R-A2L-READ.8 | U | The system shall end a block comment at the first `*/` after its `/*`. | 2/2: in `/* a /* b */ ECU_ADDRESS 0x1234`, the address is read; in `/* a /* b */ c */`, `c` is a word and `*/` gives .11's error | comments counted as nested → the first case gives no address | 07 | new | true for the header path (`a2l.py:406-411`); other paths do not read comments [RP-B40] |
| R-A2L-READ.9 | U | The system shall end a line comment at the next line end. | 3/3: `// c` ended by LF, CRLF and a lone CR; the next line's `ECU_ADDRESS 0x1234` is read | the comment run to the end of the body → no address | 07 | new | true in the header path (`a2l.py:412-416`); other paths keep `//` text (C [RP-B2]) |
| R-A2L-READ.10 | If | If a block comment is still open at the end of an A2L file, then the system shall record the parse error `Line <n>: comment not closed`. | 1/1: `<n>` = the line of its `/*`; nothing after the `/*` is read | the check removed → no error | 07 | new | no error; the header path swallows the rest of the body (`a2l.py:410`) |
| R-A2L-READ.11 | If | If `*/` stands outside a comment and outside a quoted string, then the system shall record the parse error `Line <n>: */ without /*`. | 2/2: a stray `*/` alone; the `*/` left behind by `/* a /* b */ c */`; 0 errors on the 35 tracked files (C [CH]: `stray_close_comment` 0) | the check removed → 0 errors | 07 | new | no error (C [RP-B40]: REF diag `stray */`, reader silent) |
| R-A2L-READ.12 | U | The system shall create no tag from a MEASUREMENT or CHARACTERISTIC section that stands inside a comment. | 3/3: a commented-out old copy above the live object gives 1 tag, at the live address; a commented-out object with no live copy gives 0 tags; a copy behind `//` on every line gives 0 tags; 0 `A2L_DUPLICATE_SYMBOL` issues from such a copy | the builder opens `/begin` inside a comment → 2 tags, the first at the old address → RED | 02, 07, 05 | new | no: the old copy is a tag and comes first of its name (C [RP-B28, B29]; Inc 2 E3S-35 [P1, P2]); 0 tracked files hold one (C) |

### C. Quoted strings (US-103-07)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-A2L-001.3.1 | U | The system shall read a quoted string as one word, without its quotes. | 3/3: `"a b"`, `""` and `"x/*y*/z"` each one word with the text between the quotes | strings split at blanks → `"a b"` gives two words | 07 | changed | true per line today (`a2l.py:331-339`) |
| R-A2L-001.3.2 | U | The system shall read a backslash in a quoted string together with the character after it, so that neither `\"` nor `\\` ends the string. | 3/3: `"C:\\"` ends at its last quote (long identifier `C:\\`, then the header is read); `"a\"b"` is one word `a\"b`; `"\\\""` is one word | the escape test `text[i-1] != "\\"` kept → `"C:\\"` swallows the quote → the long identifier holds `C:\\"` → RED | 07 | changed (split from .3) | no: `\\"` does not end a string (C [RP-B24]); 0 tracked strings end in `\\"` (C: 23 strings in software_a hold `\\`) |
| R-A2L-READ.13 | U | The system shall read no comment, /begin or /end from the text of a quoted string. | 4/4: `"/* x"`, `"// x"`, `"/begin MEASUREMENT Q"` and `"/end MEASUREMENT"` (Inc 2's L7 shape) each stay one word; the tag count and nesting do not change | `/end` inside a string closes a section → L7 closes the object early | 07, 05 | new | no for a string over several lines (Inc 2 [R4-L7]); the header path keeps `/*` in strings (`a2l.py:395-405`) |
| R-A2L-READ.14 | U | The system shall read a quoted string that spans line ends as one word. | 1/1: an ANNOTATION_TEXT string holding two line ends and `/end ANNOTATION_TEXT` is one word, and the object's later `BIT_MASK 0x0FF0` is read; 0 tracked files hold one (C: `multiline_strings` 0) | strings closed at the line end → the `/end` inside it closes a section | 07 | new | no: the quote state restarts on each line (`a2l.py:319-345`) |
| R-A2L-READ.15 | If | If a quoted string is still open at the end of an A2L file, then the system shall record the parse error `Line <n>: quoted string not closed`. | 1/1: `<n>` = the line of the opening `"`; Inc 2's shape H (`FORMAT "%5.0` and no closing quote in the file) | the check removed → no error | 07 | new | no error; the string ends at its line, so the words after it on later lines are read (C [RP-B39]) |
| R-A2L-READ.16 | U | The system shall end a word at a double quote. | 3/3: `X"long"` after `/begin MEASUREMENT` gives the name `X` and the long identifier `long`; `"%5.0"BIT_MASK 0x0FF0` gives a FORMAT word and a BIT_MASK keyword (Inc 2 shape U); `0x1C2D3E00"4026"` gives the address 0x1C2D3E00 and a string word | the quote kept inside words → `X"long"` is one name → RED | 07 | new | no: `X"long"` gives no tag (C [RP-B20]); `0x1C2D3E00"4026"` gives no address [H2d] |

### D. Sections (US-103-05, US-103-07)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-A2L-001.1 | When | When the operator loads an A2L file, the system shall build its sections from its /begin and /end words, wherever those words stand on a line. | 4/4 shapes: a `/begin IF_DATA` after `ECU_ADDRESS 0x10` on one line (Inc 2 J4, J5); `/begin` after a comment on its line; `/end` after words on its line; two one-line INSTANCEs on one line ([K7b]); each gives the REF tree | sections read only at the start of a line → J4's IF_DATA is never opened | 05, 07 | changed (was "from its /begin and /end lines") | no: only a line that starts with `/begin` or `/end` is read (`a2l.py:201`, `:219`); [K7b] gives `Unclosed /begin sections detected.` (K) |
| R-A2L-READ.17 | U | The system shall close a section whose /begin and /end stand on one line at that /end. | V171: 30/30 one-line IF_DATA closed on their line; 0 parse errors (today `Unclosed /begin sections detected.`); every MEASUREMENT at depth 3 (PROJECT › MODULE › MEASUREMENT) | the rest of a `/begin` line kept as its header → V171 gives `Unclosed /begin sections detected.` again | 05, 07 | new | no: V171's 30 one-line IF_DATA stay open, its MEASUREMENTs nest under each other, and later keyword lines fall into the IF_DATA (C [CH] `lines_begin_and_end` 30; [RP-B13, C-J1, C-C1]; BL-I2-12, BL-I3-11) |
| R-A2L-READ.18 | U | The system shall read /begin and /end in any letter case. | 2/2: `/BEGIN … /END` and `/Begin … /eNd` give the same tree as lower case | case-sensitive match → no section | 07 | new | true (`a2l.py:201`, `:219` use `lower()`) |
| R-A2L-READ.19 | U | The system shall read a word that starts with /begin or /end and holds more characters as an ordinary word. | 2/2: `/beginMEASUREMENT X ""` opens no section, so the file's `/end MEASUREMENT` gives R-A2L-001.5's error; `/endX` closes nothing | prefix match kept → `/beginMEASUREMENT X` opens a section named `X` with no error | 07 | new | no: a section named `X` is opened silently and the object is lost (C [RP-B31]) |
| R-A2L-READ.20 | U | The system shall take the word after a /begin word as the section's keyword, wherever that word stands. | 2/2: `/begin` at the end of a line with `MEASUREMENT` on the next line; `/begin /*c*/ MEASUREMENT` | the keyword read from the same line only → `UNKNOWN` | 07 | new | no: the keyword must be on the `/begin` line (`a2l.py:203-204`, `"UNKNOWN"`) |
| R-A2L-001.4 | If | If an /end word has no open section, then the system shall record the parse error `Line <n>: /end without /begin`. | 2/2: a stray `/end X` at the start of a line; one after other words on a line | the check removed → no error | 07 | changed ("line" → "word") | true for a line that starts with `/end` (`a2l.py:224-225`) |
| R-A2L-001.5 | If | If an /end word names a section other than the one it closes, then the system shall record the parse error `Line <n>: /end <name> does not close /begin <name>`. | 2/2: `/end IF_DATA` closing a MEASUREMENT; `/end MEASUREMENT` closing an IF_DATA; the first `<name>` is the /end's word and the second the open section's keyword | the name check removed → no error → RED | 07 | changed ("line" → "word") | **no: not implemented**; the builder never compares names (R `a2l.py:219-226`; C [RP-B13]: V171's shape gives only `Unclosed …`) |
| R-A2L-READ.21 | When | When the system reads an /end word, the system shall close the innermost open section. | 1/1: `/end IF_DATA` with a MEASUREMENT innermost closes the MEASUREMENT (after .001.5's error) | the stack searched for the name → a different tree | 07 | new | true (`a2l.py:221-223`) |
| R-A2L-READ.22 | If | If an A2L file holds an /include word outside comments and quoted strings, then the system shall record the parse error `Line <n>: /include <file> is not read`. | 2/2: `merge_inc_test.a2l` gives exactly this error with `<file>` = the next word without its quotes; `/include` in a comment gives none | the check removed → 0 errors | 07, 05 | new | no: `/include` is ignored, so the included objects are missing (C [CH] `include` 1; Inc 2 E3S-37 [A5]) |

### E. The words of a tag (US-103-07, US-103-05)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-A2L-READ.23 | U | The system shall take a tag's name from the first word after its section keyword, whether that word stands on the /begin line or on a later line. | 6/6: the name on the next line; after a comment on the `/begin` line; glued to a comment (`X/*c*/`); V161's and V171's `ASAM.C.ASCII.UBYTE.NUMBER_42` (today `UNKNOWN`); two MEASUREMENTs ([K1]) and a CHARACTERISTIC ([K1c]) whose `/begin` stands alone on its line and whose words stand one per line give `XK1`, `XK1B` and `CK1` | the name read from the `/begin` line only → `UNKNOWN` | 07, 02 | new | no (C [RP-B16, B18, B19]; fixtures: 1 tag `UNKNOWN` in V161 and in V171); [K1] and [K1c] give `UNKNOWN`, and [K1]'s two objects one `A2L_DUPLICATE_SYMBOL` (K) |
| R-A2L-READ.24 | When | When the word after a tag's name is a quoted string, the system shall take that string as the tag's long identifier. | V161 73/73 and V171 116/116 tags whose long identifier stands on a body line get it; a tag with no quoted string there gets none, so case 07's 12 tags keep their address | the long identifier read from the `/begin` line only → 189 tags get none | 07 | new | no: only the `/begin` line is read (C [FX-other]: 189 tags; [RP-B17]) |
| R-A2L-READ.25 | U | The system shall take a MEASUREMENT's header words from the words that follow its name and long identifier, across line ends and comments. | 6/6: BalanceTube's 104/104 MEASUREMENTs get their datatype and length; V161 and V171 `ASAM.M.VIRTUAL.SCALAR.SWORD.PHYSICAL` get datatype SWORD and length 2; the header on the `/begin` line, the header over 6 commented lines, the header one word per line ([K2]) and the header of a one-line MEASUREMENT that holds a one-line IF_DATA ([K5]) each read | the header read from one body line with 6 words → BalanceTube gives datatype none | 07, 05 | new | no: one body line with 6 or more raw words (`a2l.py:660-667`). BalanceTube 104 lose their datatype and length. In V161 and V171 the conversion line with its comment is taken as the header, so the datatype reads `CM.VIRTUAL.EXTERNAL_VALUE` (C [FX-classes]; [RP-B14, B15]; BL-I2-17). [K2] and [K5] give datatype none (K) |
| R-A2L-READ.26 | U | The system shall take a CHARACTERISTIC's header words from the words that follow its name and long identifier, across line ends and comments, the /begin line included. | 5/5: the header on the `/begin` line gives address 0x2000; a header over lines with comments; `VALUE 0x10/* c */RL_U16 …` gives address 0x10 and deposit `RL_U16`; a full header on the `/begin` line followed by `ECU_ADDRESS_EXTENSION 0` ([K3]) gives kind VALUE, address 0x1000 and deposit `RL_U16`; `CUBE_5 0x123 RL_U16 …` on the `/begin` line followed by `NUMBER 10000` ([K4]) gives kind CUBE_5 and address 0x123 | the header read from the body lines only → the first gives no address | 07, 05 | new | no: body lines only (`a2l.py:2608`; C [RP-B23, B21, B22]; Inc 2 E3S-25, A4); [K3] gives kind `ECU_ADDRESS_EXTENSION` and address 0x0, [K4] kind `NUMBER` and address 0x2710 (K) |
| R-A2L-READ.27 | If | If a word in a header position of a MEASUREMENT or CHARACTERISTIC is a keyword, then the system shall end the header before that word. | 5/5: case 07's MEASUREMENTs (no long identifier, no header) keep address, length, limits and unit; `UWORD CM_ID 0 0 0 BIT_MASK 0x0FF0` reads BIT_MASK as a keyword (Inc 2 shape C); a CHARACTERISTIC with no kind keeps its ECU_ADDRESS address; the keywords after a full header on the `/begin` line, `ECU_ADDRESS_EXTENSION` ([K3]) and `NUMBER` ([K4]), are never header words | a fixed count of 6 or 7 header words → case 07's 12 tags lose their address → RED (C: CANON's first variant) | 07, 05 | new | partly: case 07 reads right because the header line is skipped. Shape C swallows `BIT_MASK` as the upper limit (C [RP-C-C]); [K3] and [K4] take a body keyword as the kind (K) |
| R-A2L-READ.28 | If | If a MEASUREMENT has 1 to 5 header words, or a CHARACTERISTIC 1 to 6, then the system shall record the parse error `Line <n>: <section> <name> has <k> of its <m> header words`. | 4/4: shape C (`MEASUREMENT SX has 5 of its 6 header words`); a CHARACTERISTIC with 6; [K7] (`MEASUREMENT XK7 has 4 of its 6 header words`); 0 errors on the 35 tracked files (C [FX-total]: `short_header` 0; case 07 has 0 header words) | the check removed → no error | 07, 05 | new | no error; a short header reads silently (C [RP-C-C]); [K7] gives datatype none and no error (K) |
| R-A2L-READ.29 | U | The system shall read a keyword's argument words from the words that follow it in the same section, whether they stand on its line or on later lines. | 4/4: `ECU_ADDRESS`↵`0x1234`; `ECU_ADDRESS`↵`/* moved */`↵`0x1234`; `BIT_MASK`↵`0x0FF0` (Inc 2 shape N); `MATRIX_DIM 2`↵`3` | arguments read from the keyword's line only → no address | 07, 05 | new | no (C [RP-B5, B6, C-N]) |
| R-A2L-READ.30 | U | The system shall read every keyword among a tag's own words, wherever it stands on its line. | 3/3: `ECU_ADDRESS 0x1234 BYTE_ORDER MSB_LAST` gives byte order little; a one-line IF_DATA followed by `BIT_MASK 0x0FF0` on its line (Inc 2 J3) gives the mask; a one-line MEASUREMENT with `ECU_ADDRESS 0x18` mid-line before a nested one-line IF_DATA ([K5]) gives address 0x18 | only the first word of a line is a keyword → byte order big → RED | 07, 05 | new | no (C [RP-B12, C-J3]); [K5] gives no address and `Unclosed /begin sections detected.` (K) |
| R-A2L-READ.31 | U | The system shall read a tag's keywords from its own words only. | 3/3: an `ECU_ADDRESS` or `KP_BLOB 0x10` inside an IF_DATA, a `BIT_MASK` inside an ANNOTATION_TEXT (Inc 2 W), and a BYTE_ORDER inside an AXIS_DESCR are not the tag's | child sections' words read → the IF_DATA's address taken | 05 | new | true for lines inside a well-built child (C [RP-C-K, C-W]); wrong once the tree is wrong (.17) |
| R-A2L-READ.32 | If | If a keyword stands more than once among a tag's own words, then the system shall record the parse error `Line <n>: <keyword> is declared twice in <section> <name>`. | 3/3: two ECU_ADDRESS (the value is the last, D-6), two BYTE_ORDER, two BIT_MASK (Inc 2 shape P); `<n>` = the line of the second; 0 errors on the 35 tracked files (C [FX-total]: `dup_keyword` 0) | the check removed → no error | 07, 05 | new | no error; the last line wins for ECU_ADDRESS, LENGTH, BYTE_ORDER and BIT_MASK in the tag walk (R `a2l.py:2661-2714`) |
| R-A2L-READ.33 | U | The system shall take a tag's display identifier from the word after its DISPLAY_IDENTIFIER keyword. | 6/6 V161 and V171 tags whose line carries `/* optional display identifier */` show only the identifier in the detail card's first line; `DISPLAY_IDENTIFIER XM_disp /* shown name */` gives `XM_disp` | the raw tail kept → the card shows the comment text before the address | 07 | new | no: the raw rest of the line, comment included (C [FX-other]: 6 tags; [RP-A29]) |

### F. Number words (US-103-07)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-A2L-READ.34 | When | When the system reads an address, length or count word that is `0x` or `0X` followed by 1 to 16 hexadecimal digits, the system shall read the word as a hexadecimal number. | 3/3: `0x1234`, `0X1234` and `0x0000000000001234` | `0X` refused → no address | 07 | new | true (`int(x, 0)`; C [RP-B36]) |
| R-A2L-READ.35 | When | When the system reads an address, length or count word of 1 to 20 decimal digits, the system shall read the word as a decimal number, leading zeros included. | 2/2: `010` gives 10; `4096` gives 4096 | `int(x, 0)` kept → `010` gives no address → RED | 07 | new | no: `010` gives no address (C [RP-B32]); 0 tracked words have a leading zero (grep) |
| R-A2L-READ.36 | If | If an address, length or count word is neither a hexadecimal nor a decimal number word, then the system shall read it as no number. | 6/6 give no number: `0x12_34`, `0x1C2D3E00_4026`, `-0x10`, `+16`, fullwidth `１２` and `0b101`; 0 tracked words of these shapes (grep) | `int(x, 0)` kept → `0x1C2D3E00_4026` gives 0x1C2D3E004026 → RED | 07 | new | no: `0x12_34` → 0x1234, `0x1C2D3E00_4026` → 0x1C2D3E004026, `-0x10` → −16, fullwidth → 12 (C [RP-B33, B34, B35, H2e]) |

### G. Lengths (US-103-05, US-103-07)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-A2L-READ.37 | U | The system shall take a tag's MATRIX_DIM as the product of the numbers that follow its MATRIX_DIM keyword. | 14/14 tracked tags with several numbers (V161 4, V171 8, update_test1 1, update_test2 1; list below) get the product; `MATRIX_DIM 2 2` UWORD gives length 8 | the first number only → `MATRIX_DIM 2 2` gives 4 → RED | 05, 07 | new (CTX MATRIX_DIM changed) | no: the first number (C [FX-extra]; [RP-B26]; Inc 2 E3S-40) |
| R-A2L-READ.38 | If | If a tag's length is below 1 or above 1,048,576 bytes, then the system shall give the tag no length. | 5/5: `LENGTH 0`, `LENGTH -5`, `LENGTH 1048577`, `LENGTH 99999999999` (Inc 2 H3), ASCII `NUMBER 1000000000000` (H1) give no length; `LENGTH 1048576` keeps it; 0 tracked tags out of bounds (C [FX-total]) | the cap removed → H3 keeps 99,999,999,999 → RED | 05, 07 | new | no: kept, and only the raw value is refused (R-A2L-042; C [RP-C-H1, C-H3]; Inc 2 E3S-39) |
| R-A2L-READ.39 | If | If a tag's length is below 1 or above 1,048,576 bytes, then the system shall record the parse error `Line <n>: <section> <name> has the length <length>, outside 1 to 1048576 bytes`. | 4/4 for .38's cases that hold a number word (`LENGTH 0`, `LENGTH 1048577`, `LENGTH 99999999999`, ASCII `NUMBER 1000000000000`), `<n>` = the tag's `/begin` line, `<length>` in decimal; `LENGTH -5` is not counted: `-5` is not a number word (R-A2L-READ.36), so the tag has no length to print (F-E2-3, ruled at E2) | the error removed | 07 | new | no error |
| R-A2L-016 | If | If a VAL_BLK CHARACTERISTIC has no DATA_SIZE or LENGTH line, then the system shall take its length as the size of its datatype × its MATRIX_DIM. | 2/2: [K6] a VAL_BLK on `RL_U16` (FNC_VALUES UWORD) with `MATRIX_DIM 4` gives length 8; V161's `ASAM.C.ARRAY.SWORD.MATRIX_DIM_6.ROW_DIR` (layout `RL.FNC.SWORD.ROW_DIR`, FNC_VALUES SWORD, `MATRIX_DIM 6 1 1`) gives 12 | the layout's datatype resolved for VALUE only (the base rule) → [K6] gives no length → RED | 05, 07 | cited (code to meet; CTX *datatype (CHARACTERISTIC)*; E1 addendum, CG-2) | no: a VAL_BLK whose layout name carries no size gets no length, because the layout's datatype is resolved for VALUE only (R `a2l.py:1218-1229`; K [K6]); 12 tracked VAL_BLKs have this shape (A: V161 3, V171 7, update_test1 1, update_test2 1), 9 of them already defect tags, 3 added to the list below |
| R-A2L-READ.53 | If | If a VAL_BLK CHARACTERISTIC has no MATRIX_DIM and has a NUMBER keyword, then the system shall take its length as the size of its datatype × the number after NUMBER. | 1/1: [K6b] a VAL_BLK on `RL_U16` (FNC_VALUES UWORD) with `NUMBER 4` and no MATRIX_DIM gives length 8 | NUMBER ignored for VAL_BLK → [K6b] gives no length → RED | 05, 07 | new (E1 addendum, CG-3; the ASAP2 1.6 form) | no: no length (K [K6b]); 101 tracked VAL_BLKs of `software_a.a2l` have this shape (A) and join the defect tags below |

Notes from the E1 addendum (open, for E3):
- **R-A2L-READ.53 and R-A2L-013.** The row is written as ruled ("as proposed"). It names no DATA_SIZE or LENGTH condition, so a VAL_BLK with both a LENGTH and a NUMBER meets R-A2L-013 and .53, with different lengths. No case covers that shape; 0 tracked VAL_BLKs have both (A: 101 tracked VAL_BLKs have a NUMBER line, none of them a LENGTH or DATA_SIZE line).
- **CG-2's R-A2L-017 part is not applied.** R-A2L-017 takes an ASCII's length "from its NUMBER line", and the base meets that today (`a2l.py:1230-1231`). The case CG-2 proposed for it, [K6c] (an ASCII on `RL_U8` with `MATRIX_DIM 8` and no NUMBER → 8), has no NUMBER line, so its expected 8 traces to no row. A ruling is owed, for example a split of R-A2L-017 into a NUMBER form and a datatype × MATRIX_DIM form. 0 tracked ASCII CHARACTERISTICs have this shape (A).

### H. INSTANCE and BLOB spans (US-103-05)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-A2L-READ.40 | When | When the system reads a BLOB section, the system shall list a declared span with the BLOB's name, its address word as address and its size word as length. | 7/7 tracked BLOBs (C [FX-extra]); `/begin BLOB B1 "" 0x10 2` gives (B1, BLOB, 0x10, 2) | BLOB left out → 6 spans | 05 | new | no: BLOBs are read into no list (C [RP-D1]) |
| R-A2L-READ.41 | When | When the system reads an INSTANCE section, the system shall list a declared span with the INSTANCE's name and its address word as address. | 82/82 tracked INSTANCEs listed (C [FX-total]) | INSTANCE left out → 0 | 05 | new | no (C [RP-D2]) |
| R-A2L-READ.42 | When | When an INSTANCE names a TYPEDEF_MEASUREMENT, the system shall take the span's length as the size of the typedef's datatype × the typedef's MATRIX_DIM × the INSTANCE's MATRIX_DIM. | 2/2: `T_U16` gives 2; with `MATRIX_DIM 5` on the INSTANCE gives 10 | the INSTANCE's MATRIX_DIM ignored → 2 | 05 | new | no |
| R-A2L-READ.43 | When | When an INSTANCE names a TYPEDEF_CHARACTERISTIC of kind VALUE, VAL_BLK or ASCII, the system shall take the span's length as the length that R-A2L-015, R-A2L-016 or R-A2L-017 gives the typedef × the INSTANCE's MATRIX_DIM. | 3/3 (one per kind); V171's `ASAM_I_SCALAR_VALUE_UWORD_SINGLE` gives 2 (Inc 2 E3S-37) | the typedef's length not taken → no length | 05 | new | no |
| R-A2L-READ.44 | When | When an INSTANCE names a TYPEDEF_BLOB or a TYPEDEF_STRUCTURE, the system shall take the span's length as the typedef's size word × the INSTANCE's MATRIX_DIM. | 2/2 | the size word not read → no length | 05 | new | no (C: 52 tracked INSTANCEs of a TYPEDEF_STRUCTURE, 1 of a TYPEDEF_BLOB) |
| R-A2L-READ.45 | If | If the system cannot size an INSTANCE by R-A2L-READ.42 to .44, then the system shall list its span with no length. | 3/3: an INSTANCE of a TYPEDEF_AXIS, of a CURVE TYPEDEF_CHARACTERISTIC, of a typedef the file does not declare; tracked: 1 TYPEDEF_AXIS, 2 unknown typedefs (C [FX-total]) | a guessed length (e.g. 1) → RED | 05 | new | no span at all |
| R-A2L-READ.46 | If | If a declared span's length is below 1 or above 1,048,576 bytes, then the system shall list the span with no length. | 3/3: BLOB size 0, 1048577; an INSTANCE with `MATRIX_DIM 4294967296` | the cap removed → the BLOB keeps 1048577 | 05 | new | no |

### I. The reader against the reference, and no regression (US-103-07, US-103-05)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-A2L-READ.48 | U | The system shall give every A2L file the tags, declared spans and parse errors that the reference reading of that file gives. | (a) the 35 tracked files and (b) the hostile corpus (≥ 60 shapes) pass N/N with 0 differences. Compared: every tag's name, long identifier, address, datatype, byte order, BIT_MASK word, MATRIX_DIM, kind, deposit and conversion; the length of every MEASUREMENT, VALUE, VAL_BLK and ASCII tag and of every declared span; for a CURVE or MAP, its axis point counts and record layout name; the parse-error texts with their lines. (a) runs ≤ 120 s on cachyos-rtx | any one of .2, .7, .12, .17 or .25 reverted → ≥ 1 difference on (a) or (b) → RED | 07, 05 | new | no: 110 tags of 4 files and 189 more on other fields differ from CANON (C [FX-total], [FX-other]); 48 WRONG, 4 LOST, 2 PHANTOM and 6 WRONG(ref) of 104 shapes (C [RP-total]) |
| R-A2L-READ.49 | U | The system shall give every tag of the 35 tracked fixture files, other than the defect tags at e07fb00, the same name, address, length, datatype, byte order and BIT_MASK word as e07fb00 gives. | 234,428/234,428 tags identical on the six fields (234,654 tags − the 226 listed); per file, the tag count equals e07fb00's (35/35; V161 and V171 rename `UNKNOWN`, they gain none); the 226 listed tags take REF's values | a fixed header count (no keyword stop, .27) → case 07's 12 tags lose their address → RED | 07, 05 | new | the list below is today's defect set (C; the addendum's 104 tags: A) |

### J. What the views show (US-103-07)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-TUI-042a.2 | U | The system shall show at least one blank column between adjacent cells of the tag table. | 5/5 widths (220, 160, 118, 100 and 80 columns; real A2L Explorer, headless): in the painted row of the synthetic MAP, every pair of adjacent cells that is shown has at least one blank column between them; `0x1C2D3E002266`, `SYN_MAP_W0x1C2D3E00`, `17921792` and `unknown0..` are painted 0 times | `cell_padding=0` → `0x1C2D3E002266` painted at 5/5 widths → RED | 07 | changed (was "with no padding between cells"); **outside `a2l.py`** (`app.py`), D-1 | no: `cell_padding=0` (`app.py:8520`) paints Name+Address+Length as one string at every width (B [W220 … W80]); this is the operator's symptom |
| R-A2L-READ.50 | U | The system shall show a section's header in the A2L summary as its header words joined by single spaces. | 3/3: `VALUE 0x00003000/*old 0x1000*/ RL_U32` shows `VALUE 0x00003000 RL_U32`; two blanks show as one; a quoted word shows with its quotes | the raw `/begin` line text kept → the comment is shown | 07 | new | no: the raw rest of the `/begin` line (`a2l.py:3633-3637`; C [RP-A27]; [FX-extra] `meta_with_comment` 1) |
| R-A2L-READ.51 | U | The system shall show each character U+0000 … U+001F, U+007F … U+009F, U+2028 and U+2029 of a file word as U+FFFD in the A2L summary. | 9/9: VT, FF, U+001C, U+001E, U+0085, U+2028, U+2029, ESC and NUL in a long identifier each show as U+FFFD, and every summary line ends at a line end the summary itself writes (0 broken lines) | the characters passed through → the A2L Sections line breaks after the address → RED | 07 | new | no: the summary line breaks right after the address (C [RP-A19–A21, A24–A26c]) |
| R-A2L-076 | When | When the system shows the A2L summary, the system shall list the sections under the heading `A2L Sections:`, one `- <name> <header> (lines <first>-<last>)` line each, indented by depth. | 2/2: a file with parse errors (V171 before the fix; `merge_inc_test.a2l` after it) lists its errors, then its sections | the early return kept → only the errors are shown | 07, 02 | cited (code to meet) | **no**: with any parse error the summary shows only the errors (R `a2l.py:3650-3652`) |
| R-A2L-077 | When | When the system shows the A2L summary, the system shall list the tags under the heading `A2L Tags:`, one `- <section> <name>: <address> len=<length> mem=<region> <tag status text>` line each. | 1/1 as .076 | as .076 | 07, 02 | cited (code to meet) | **no**, as .076 |

### K. Load time (US-103-07)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-A2L-READ.52 | U | The system shall parse an A2L file within 1.5 times the time the e07fb00 reader takes for the same file on the same host. | case_06 (36.7 MB) and software_a (5.1 MB), median of 3 runs each, ≤ 1.5 × the e07fb00 median, measured on cachyos-rtx in the same session | a per-character Python loop with string concatenation → over the bound | 07 | new | **proposal: the base time is not measured yet** (pilot owed at E2; the census time 21.9 s for case_06 includes REF and two parses, C [FX]) |

Cited and unchanged (the code keeps meeting them): R-A2L-001.6, R-A2L-001.7, R-A2L-004.1 … .13 (progress per byte: .11), R-A2L-005.1, R-A2L-005.2 (INSTANCE and BLOB stay out of the tags: they are declared spans), R-A2L-010 … 015 and R-A2L-017 … 036 (the field rules, now over the words of .23 … .33; R-A2L-016 is cited to meet, in G), R-A2L-042, R-A2L-075, R-VAL-036 (an address above 0xFFFFFFFF stays and raises `A2L_ADDRESS_EXCEEDS_32BIT`).

Id R-A2L-READ.47 is not used: its draft, "no tag from INSTANCE or BLOB", is R-A2L-005.2 itself, so it was dropped before the record was written.

**Count:** 52 new rows (R-A2L-READ.1 … .46 and .48 … .53); 7 changed rows (R-A2L-001.1, .2, .3.1, .3.2 from .3, .4, .5; R-TUI-042a.2); 3 cited rows the code must now meet (R-A2L-016, R-A2L-076, .077). That is 62 rows in scope, with 0 retired, 3 CTX terms changed and 1 CTX term added (*datatype (CHARACTERISTIC)*). The E1 addendum added R-A2L-READ.53 and R-A2L-016, and changed the thresholds of R-A2L-001.1, .001.2, READ.4, .23, .25 … .28, .30, .39 and .49.

## Defect tags at e07fb00 (the exceptions of R-A2L-READ.49)

From `evidence-e1/e1-fx-defects.jsonl` and `e1-fx-extra.jsonl` (C). Each tag takes REF's values after the change.

| File | Tags | Field today → after |
|---|---|---|
| `examples/case_00_public/BalanceTube_STMicro.a2l` | all 104 MEASUREMENTs | datatype none → the header's datatype; length none → its size (e.g. `model.MainClass.gameController.sm` UBYTE, 1) |
| `examples/case_00_public/ASAP2_Demo_V161.a2l` | `ASAM.M.VIRTUAL.SCALAR.SWORD.PHYSICAL` | datatype `CM.VIRTUAL.EXTERNAL_VALUE` → SWORD; length none → 2 |
| same | `UNKNOWN` (CHARACTERISTIC at 0x810200) | name → `ASAM.C.ASCII.UBYTE.NUMBER_42` |
| same | `ASAM.M.MATRIX_DIM_8_2_1.UBYTE.IDENTICAL`, `ASAM.M.MATRIX_DIM_8_4_2.UBYTE.IDENTICAL`, `ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR`, `ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.COLUMN_DIR` | length from the first MATRIX_DIM number → from the product (8 2 1, 8 4 2, 3 4 1, 3 4 1) |
| `examples/case_00_public/ASAP2_Demo_V171.a2l` | `ASAM.M.VIRTUAL.SCALAR.SWORD.PHYSICAL` | as in V161 |
| same | `UNKNOWN` (CHARACTERISTIC at 0x810200) | name → `ASAM.C.ASCII.UBYTE.NUMBER_42` |
| same | `ASAM.M.MATRIX_DIM_8_2.UBYTE.IDENTICAL`, `ASAM.M.MATRIX_DIM_8_4_2.UBYTE.IDENTICAL`, `ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR`, `ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.COLUMN_DIR`, `ASAM.C.DEPENDENT.ARRAY_1` … `_4` | length from the product (8 2, 8 4 2, 3 4 ×6) |
| `examples/case_00_public/update_test1.a2l` | `Measurement_Matrix` | length from 5 4 |
| `examples/case_00_public/update_test2.a2l` | `Characteristic_ValBlk_matrix_dim` | length from 5 6 7 |
| `examples/case_00_public/ASAP2_Demo_V161.a2l` | `ASAM.C.ARRAY.SWORD.MATRIX_DIM_6.ROW_DIR` (E1 addendum, R-A2L-016) | length none → 12 (SWORD × 6) |
| `examples/case_00_public/ASAP2_Demo_V171.a2l` | `ASAM.C.ARRAY.SWORD.MATRIX_DIM_6.ROW_DIR` (E1 addendum, R-A2L-016) | length none → 12 (SWORD × 6) |
| `examples/case_00_public/update_test1.a2l` | `Characteristic_ValBlk` (E1 addendum, R-A2L-016) | length none → 20 (FLOAT32_IEEE × 5) |
| `examples/case_00_public/software_a.a2l` | 101 VAL_BLK CHARACTERISTICs with a NUMBER line and no MATRIX_DIM (E1 addendum, R-A2L-READ.53) | length none → the size of the layout's datatype × NUMBER (layout datatypes: SWORD 86, UWORD 10, FLOAT32_IEEE 4, UBYTE 1) |

That is 104 + (1 + 1 + 4) + (1 + 1 + 8) + 1 + 1 = **122 tags** at E1. The E1 addendum adds 3 (R-A2L-016) + 101 (R-A2L-READ.53), so **226 tags** (A).

Correction at the E1 addendum (A): the VAL_BLK entries above (V161's and V171's `ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.*`, V171's `ASAM.C.DEPENDENT.ARRAY_1` … `_4`, and update_test2's `Characteristic_ValBlk_matrix_dim`) have no length at e07fb00, not a first-number length: their layouts (`RL.FNC.SWORD.*`, `float32_RecordLayout`) name no size. After the change they take the size of the layout's datatype × the MATRIX_DIM product (R-A2L-016 with R-A2L-READ.37).

The following also change, and are allowed under R-A2L-READ.49 because they fall outside its six fields:
- the long identifier of 72 + 1 V161 tags and 111 + 5 V171 tags (R-A2L-READ.24);
- the display identifier of 6 tags (.33);
- V171's parse error `Unclosed /begin sections detected.`, which goes;
- `merge_inc_test.a2l`, which gains `Line 5: /include … is not read` (`<n>` to be confirmed at E4);
- the summary text of every file whose `/begin` lines carry comments (.50).
