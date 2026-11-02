# S2 — A2L & MAC symbols: context notes and strict EARS rows (2026-10-30)

Input: `REQUIREMENTS.by-module.md` chapter S2 (lines 564–917): 8 blocks of unnumbered "shall" lists, plus 16 rows (R-A2L-001 … 007, R-TUI-019, 020, 037, 039, 068 … 071, R-A2L-ISSUE-RECONCILE-002).
Code: `base/s19_app/tui/a2l.py`, `mac.py`, `a2l_describe.py`, `services/a2l_service.py`, the S2 functions of `app.py`, the `#a2l_*` / `#mac_*` rules of `styles.tcss`. Two read-only code readings gave every fact with `file:line`; I re-checked the four that change rows the most (the A2L summary pane is still on screen, COMPU_VTAB is read but never applied, the `get_*` API has no caller, the CLI-style facts in section 6). No test was run.
Reconciled with s19_app 570b4b5 (batch-100) on 2026-11-01: rows and cites in S2.1 (the A2L load rows R-A2L-004.x) and S2.6 Reading (R-MAC-010, 011) verified at 570b4b5; the parser rows of S2.1 … S2.3 keep their cells (`a2l.py` changed only by the progress report, D2-32); other cites refer to 093a7c0.

Result:
- **Context notes first** (section 3): six notes, one per subchapter, terms and formats only (rule E6).
- **Rows** (section 4): 211 rows, all in one of the five EARS forms, one `shall` each; none needed another form; none uses `Where`.
- **Decisions** (section 5): 29, each with a recommendation already applied to the rows. Mark only what you object to.
- The rules E1–E7 are the ones in `review/S1-ears-strict.md` section 1, unchanged.

---

## 1. How S2 was written before

Two shapes of text:
- **The 8 unnumbered blocks** (structural parsing, RECORD_LAYOUT, raw extraction, raw decoding, COMPU_METHOD, decode validation, viewer, output API) state the A2L engine as lists: "shall parse and retain the following", "shall expose indexed maps", "shall provide `raw_value`, `decode_error`". No ids, so nothing traces to them; most items are data-structure names.
- **The 16 rows** are a mix of one-line wishes (R-A2L-001 … 007) and batch-era rows that carry function names, call order, CSS values and amendment history (R-TUI-037, 039, 068, 069, RECONCILE-002).

## 2. What did not make sense

| Where | What did not make sense | Fix |
|---|---|---|
| Byte-order block | Precedence "1 tag, 2 layout, 3 existing tag endian, 4 default little". Step 3 is the same token as step 1, so it can never apply. The code has a step the text omits: BYTE_ORDER in the module's MOD_COMMON, before the default. | Rows follow the code (R-A2L-024 … 027); the dead step goes (D2-2). |
| COMPU_METHOD table | FORM: "guarded/unsupported unless safe evaluation is enabled". Nothing can enable it, and the formula text is never even read. | FORM is plainly not converted (R-A2L-060, D2-4). |
| COMPU_METHOD table | TAB_VERB is not in the table, yet the parsing block requires COMPU_VTAB. The code reads COMPU_VTAB and never uses it; a TAB_VERB tag shows its raw number as "unknown method". | Show the verbal text (R-A2L-059, D2-5). |
| Viewer block | Fallback text "`n/a`, `ERR`, `MISS`, or equivalent". `MISS` appears nowhere in the code; `ERR` only as `ERR (<reason>)` in the Workspace summary; "or equivalent" cannot be tested. | One row per fallback with its exact text (S2.5). |
| Viewer block | "Unit display precedence: UNIT, then COMPU_METHOD unit". True for the table only; the description window uses the opposite order and the detail card has no fallback. `UNIT "deg C"` is read as `"deg`. | One unit rule for every surface (R-A2L-030 … 032, D2-6). |
| Raw extraction block | Requires the field `overlap_conflict`. Nothing ever sets it; it is always `False`. `missing_ranges` is a list of single addresses, not ranges. | Field names leave the requirements; the dead field goes (D2-26). |
| Decode validation block | Requires detecting "layout missing, compu method missing, byte order unresolved, size mismatch". These checks exist only inside `validate_characteristic`, which nothing calls; "byte order unresolved" can never happen (the default always applies). | Removed with the API (D2-1). |
| Output API block | `get_raw_value`, `get_physical_value`, `validate_characteristic`: no caller in the app, and each one always describes the **first** tag of the file, whatever name is asked (a test marks it `xfail`). | Removed (D2-1). |
| R-A2L-002 | Three responses in one row; "readable" cannot be tested; "the A2L view tile" is not named on screen (it is the A2L summary in the Workspace "Context" pane). | Split, with the exact text (S2.4). |
| R-A2L-003 | "via a keyboard binding": which key, which file, where. | Key `j`, the path and the messages (R-A2L-003.1 … .5). |
| R-A2L-006 vs R-TUI-068 | 12 columns in one row, 16 cells in the other. | The 16 columns as built (CTX-A2L-SCREEN, D2-28). |
| R-A2L-007 | The `Invalid` filter does not show the red rows: it misses rows turned red by an issue and includes white (checked, absent) rows. | Invalid = red (R-A2L-007.7, D2-14). |
| R-TUI-019 / 020 | Written as history: "without removing existing shortcuts", "must continue to route". | Present-tense rows per key and button. |
| R-TUI-037 / 039 | CSS values (`3fr`, `min-width: 82`) and batch history inside the row. | The proportions as the operator sees them. |
| RECONCILE-002 | Function names, O(1) lookup, call order inside `update_a2l_view`. The behaviour is one sentence. | Three rows (R-A2L-080 … 082). |
| R-TUI-068 | The requirement is a return type (`tuple[Text, ...]`). Its amendment says per-cell accents are built but never visible. | Observable rows; the hidden accents go (D2-29). |
| R-TUI-069 | Handler names, and a Textual rule ("members shall not be named `_nodes`") that is a design constraint, not product behaviour. | Card rows; the naming rule moves to the design notes (D2-27). |
| R-TUI-071 | X, Y, N defined by class attributes. With no S19/HEX loaded the strip reads `0 of 0`, even when rows say `OK`. | Terms in CTX-MAC; the no-image case gets its own text (D2-24). |

Counts for the old text: 8 blocks with no id; 16 rows, all with more than one response or with implementation names; 6 statements the code contradicts (byte order, FORM, `MISS`, unit precedence, `overlap_conflict`, the API).

---

## 3. Context notes (informative)

Each subchapter opens with its note. A note defines terms and formats; it never says what the system does (rule E6). Rows cite the notes.

### CTX-A2L-FILE · An A2L file (S2.1)

```text
A2L file        An ASAM MCD-2 MC text file that describes the variables of an ECU.
section         A block from a line that starts with /begin <NAME> to its matching
                /end <NAME>. Sections nest. The words after <NAME> on the /begin
                line are the section's header.
module          A MODULE section. MOD_COMMON inside it holds module-wide defaults.
comment         Text between /* and */, or from // to the end of the line.
quoted string   Text between double quotes; \" inside it is a quote character.
parse error     A defect in the section structure of the file.
tag             A MEASUREMENT or CHARACTERISTIC section, at any depth.
  MEASUREMENT     A value the ECU computes (read-only in calibration).
  CHARACTERISTIC  A value stored in memory that calibration can change. Its kind is
                  VALUE (one value), VAL_BLK (an array), ASCII (a string), CURVE
                  (values over one axis), MAP (over two axes), CUBOID, MAP_BLOCK.
multi-value tag A tag that holds more than one value: VAL_BLK, CURVE, MAP, CUBOID,
                MAP_BLOCK, or a MEASUREMENT whose MATRIX_DIM is more than 1.
A2L load        Loading an A2L file into the session from a typed .a2l path or a recent
                entry of the Load dialog, a .a2l file of the Workarea Files list, or the
                start-up path (routes and copies: S5, S7).
A2L load steps  The steps the progress line (S6) names for an A2L load, in order:
                1 Copy into the work area · 2 Parse · 3 Build the tag table.
```

### CTX-A2L-TAG · What a tag declares (S2.2)

```text
address         Where the tag starts in ECU memory. A CHARACTERISTIC states it in its
                header; an ECU_ADDRESS line states it for either kind.
length          The number of bytes the tag occupies from its address.
datatype        UBYTE, SBYTE, UWORD, SWORD, ULONG, SLONG, A_UINT64, A_INT64 (1, 1, 2,
                2, 4, 4, 8, 8 bytes; S = signed, two's complement), FLOAT16_IEEE,
                FLOAT32_IEEE, FLOAT64_IEEE (2, 4, 8 bytes).
record layout   A RECORD_LAYOUT section a CHARACTERISTIC names: the order, datatype
                and alignment of the values in its memory record.
deposit name    The record layout name. Some tool chains encode the datatype in it,
                for example __SWORD_Z.
byte order      big (MSB_FIRST or BIG_ENDIAN) or little (MSB_LAST or LITTLE_ENDIAN).
conversion method  The COMPU_METHOD a tag names. NO_COMPU_METHOD names none.
unit            The physical unit of a tag's value, for example "kOhm".
limits          The lower and upper limit a tag declares for its physical value.
memory region   flash, ram or unknown: the MEMORY_SEGMENT that holds the address.
                RAM or VARIABLE segments are ram; FLASH, ROM or CODE are flash.
virtual         A tag with a VIRTUAL line: computed, with no memory of its own.
function group  The FUNCTION a tag declares.
access          read_only (READ_ONLY) or calibratable (CALIBRATABLE).
source          formula: the tag names a conversion method other than NO_COMPU_METHOD,
                or has a FORMULA line. assigned: otherwise.
axis            An AXIS_DESCR of a CURVE or MAP: its points are either in the same
                record (inline) or in another section (AXIS_PTS_REF, external).
```

### CTX-A2L-VALUE · From bytes to a physical value (S2.3)

```text
tag span        The bytes from the tag's address, as many as its length.
raw bytes       The tag span read from the image (CTX-IMAGE of S1).
raw value       The raw bytes read as the tag's datatype, in its byte order.
physical value  The raw value after the tag's conversion method.
conversion status  ok · identity (no conversion method: physical = raw) ·
                unknown method · unsupported · error · missing (no raw value).
conversion error   The conversion status error, with a message.
Conversion methods (ASAM MCD-2 MC):
  IDENTICAL   physical = raw.
  LINEAR      physical = a × raw + b (COEFFS_LINEAR a b).
  RAT_FUNC    raw = (a·p² + b·p + c) / (d·p² + e·p + f), solved for p (COEFFS a … f).
  TAB_INTP    a COMPU_TAB of raw → physical pairs, interpolated.
  TAB_NOINTP  a COMPU_TAB of raw → physical pairs, not interpolated.
  TAB_VERB    a COMPU_VTAB of raw → text pairs.
  FORM        a formula in text.
```

### CTX-A2L-CHECK · Checking tags against the image (S2.4)

```text
primary image   The image of the S19 or Intel HEX file the project loads (S1).
checked tag     A tag the system compared with a primary image: it has an address and
                a length, and a primary image is loaded.
in image        A checked tag whose every span byte is in the primary image.
out of image    A checked tag with at least one span byte missing.
schema complete A tag that has an address, or is virtual.
A2L issue       A validation issue (S3) about the A2L file, with a severity and,
                when it is about one tag, that tag's name (its symbol).
A2L summary     The text the Workspace "Context" pane shows for the loaded A2L.
tag status text  OK (in image) · OUT(image) (out of image) · ERR (<reason>)
                (schema not complete) · nothing (not checked).
```

### CTX-A2L-SCREEN · The A2L Explorer (S2.5)

```text
A2L Explorer    The screen with the tag table (left, with its filter bar, page bar
                and summary line) and the hex pane (right, with the detail card on top).
tag table columns, in order:
  Tag       in-image glyph, a space, the name
  Address   the address as 0x + 8 uppercase hexadecimal digits
  Length    the length in bytes
  Source    assigned or formula
  Raw       the raw value
  Physical  the physical value
  InMem     yes (in image) · no (out of image) · n/a (not checked)
  Region    the memory region
  Limits    <lower>..<upper>
  Unit      the unit
  Bits      the BIT_MASK value
  Endian    the byte order as declared
  Virt      yes or no
  Func      the function group
  Access    the access
  Dtype     the datatype
in-image glyph  ✓ in image · ⚠ out of image · · not checked (D2-16).
row colour      red: the tag needs attention · green: in image · white: out of image,
                or computed (virtual or formula) · grey: not checked.
filter          A text, a filter field and a filter mode that select the rows shown.
filter field    all, name, address, length, raw_value, physical_value, source,
                in_memory, limits, unit, bits, endian, virtual, function_group,
                access, datatype, description, memory_region.
filter mode     All · Invalid (red rows) · In-Memory (in image).
page            A run of consecutive rows of a table; its size is the page size.
detail card     The box above the hex pane that shows the highlighted tag.
description window  The window that describes one CHARACTERISTIC: its axes, its
                point table and the shape of its values.
highlighted row The row under the table cursor.
selected row    A row the operator confirms with Enter or a click.
```

### CTX-MAC · MAC files and the MAC View (S2.6)

```text
MAC file        A text file that maps tag names to addresses, one per line.
MAC line        <name> = <address>. Spaces around = are allowed.
  name          Letters, digits, _ and -.
  address       Hexadecimal, with or without a 0x prefix. A=10 means 0x10.
comment line    A line whose first non-blank character is #.
MAC record      One MAC line, with its line number, name, address and parse result.
MAC-only session  A session with a MAC file and no primary image.
MAC status      (conditions; the order that decides between them is R-MAC-030)
  ERR_PARSE           the line is not a valid MAC line
  NO_ADDR             the record has no address
  A2L_ADDR_MISMATCH   an A2L tag has the same name and another address
  NOT_IN_A2L          an A2L file is loaded and no tag has the name
  OUT_OF_IMAGE        a primary image is loaded and the address is not in it
  NO_A2L              no A2L file is loaded
  OK                  an A2L tag has the same name and the same address
name match      Same name, ignoring case.
A2L↔MAC match   A MAC record and an A2L tag with an address that name-match and
                have the same address.
MAC View columns, in order: Tag, Address, InA2L, InMem, Status, SourceLine,
                ParseErr, A2LMatch.
coverage strip  The line above the MAC table: MAC→S19 coverage and A2L↔MAC matches.
```

---

## 4. The chapter, rewritten

Form column: U = ubiquitous. "Code today": **Yes** (read from the code), **Yes; tested** (a test asserts it), **Partly** or **No** with the decision that changes the code.

### S2.1 · Reading an A2L file (CTX-A2L-FILE)

Replaces: the "A2L Structural Parsing" block, R-A2L-001, R-A2L-004, R-A2L-005.

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-A2L-001.1 | When | When the operator loads an A2L file, the system shall build its sections from its /begin and /end lines. | Yes; tested. |
| R-A2L-001.2 | U | The system shall ignore the text of comments when it builds sections. | Partly: a comment line that starts with /begin opens a section (D2-11). |
| R-A2L-001.3 | U | The system shall read a quoted string as one value, without its quotes. | Yes; tested. |
| R-A2L-001.4 | If | If an /end line has no open section, then the system shall record the parse error `Line <n>: /end without /begin`. | Yes. |
| R-A2L-001.5 | If | If an /end line names a section other than the one it closes, then the system shall record the parse error `Line <n>: /end <name> does not close /begin <name>`. | No: accepted silently (D2-11). |
| R-A2L-001.6 | If | If a section is still open at the end of the file, then the system shall record the parse error `Unclosed /begin sections detected.` | Yes; tested. |
| R-A2L-001.7 | If | If an A2L file holds bytes that are not valid UTF-8, then the system shall read each such byte as the character U+FFFD. | Yes. |
| R-A2L-005.1 | When | When the system reads an A2L file, the system shall create one tag for each MEASUREMENT and each CHARACTERISTIC section, at any depth. | Yes; tested. |
| R-A2L-005.2 | When | When the system reads an A2L file, the system shall create no tag from any other section. | Yes; tested. |
| R-A2L-004.1 | When | When an A2L file loads with no parse error, the system shall show the status `A2L loaded: <file name>`. | Yes; tested (`test_tc_b100_51_a2l_load_ends_once_on_success`, `test_tc_b100_53_every_a2l_attach_route_parses_on_a_worker`). |
| R-A2L-004.2 | If | If an A2L file loads with parse errors, then the system shall show the status `A2L loaded with <n> parse errors: <file name>`. | No: says `A2L loaded` (D2-13; re-verified at 570b4b5, `app.py:15352-15356`). |
| R-A2L-004.3 | If | If the A2L file is missing, or its size cannot be read, when the system starts the A2L load, then the system shall show the status `A2L file not found: <path>`. | Yes; tested (`test_tc_b100_54_a2l_attach_refuses_when_its_folder_or_file_vanished`). A typed path that does not exist is refused first by the Load dialog (D2-30). |
| R-A2L-004.4 | If | If the file to load as A2L does not end in `.a2l`, then the system shall show the status `Unsupported A2L type: <extension>`. | Yes; untested as a status (`test_tc_b100_51_a2l_load_ends_once_on_success` checks that a `.txt` begins no load). |
| R-A2L-004.5 | If | If the project already has an A2L file, then the system shall show the status `Project already has an A2L file.` | Yes (`app.py:15225`). |
| R-A2L-004.6 | If | If the system cannot copy or parse the A2L file, then the system shall show the status `File NOT loaded: '<file name>' could not be read — check that the file can be opened, then load again.` | Yes; tested (`test_tc_b100_54_a2l_worker_failure_keeps_the_session`, `test_tc_b100_50_a2l_raise_ends_the_action_first`: a parse that raises ends the load once with this text). Text from batch-100 (D2-31). |

**(from batch-100 HLR-177, HLR-176, HLR-165: LLR-177.1b, 177.2b, 177.2c, 177.5, 176.4, 165.4)**

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-A2L-004.7 | If | If the system cannot copy or parse the A2L file, then the system shall keep the A2L file and the tags that were loaded before the attempt. | Yes; tested (`test_tc_b100_54_a2l_worker_failure_keeps_the_session`). |
| R-A2L-004.8 | If | If the work-area guard (S5) refuses the copy of the A2L file, then the system shall show the status `Cannot load A2L: <reason>`. | Yes; tested (`test_tc_b100_54_a2l_worker_failure_keeps_the_session`, `test_tc_b100_51_a2l_load_ends_once_on_a_containment_refusal`). |
| R-A2L-004.9 | If | If the open project's folder cannot be read when the system starts the A2L load, then the system shall show the status `A2L NOT loaded: project '<project name>' could not be read — check that the folder can be opened, then load again.` | Yes; tested (`test_tc_b100_54_a2l_attach_refuses_when_its_folder_or_file_vanished`). |
| R-A2L-004.10 | While | While the system copies or parses an A2L file, the system shall keep processing input and screen updates. | Yes; tested (`test_tc_b100_53_case06_a2l_attach_keeps_the_loop_free_and_reports_parse_bytes`, `test_tc_b100_53_every_a2l_attach_route_parses_on_a_worker`). |
| R-A2L-004.11 | While | While the system parses an A2L file, the system shall move the progress bar within the parse step in proportion to the bytes of the file read so far. | Yes; tested (`test_tc_b100_73_case06_reports_bytes_and_parses_the_same`, `test_tc_b100_73_small_a2l_reports_once_and_parses_the_same`, `test_at_b100_17_parse_half_case06_a2l_by_keys`, `test_tc_b100_53_case06_project_load_keeps_the_loop_free_and_reports_parse_bytes`). |
| R-A2L-004.12 | When | When the system loads an A2L file from the Workarea Files list, the system shall show its progress line at the Parse step from the start of the load. | Yes; tested (`test_tc_b100_53_in_place_a2l_pick_starts_at_the_parse_step`). |
| R-A2L-004.13 | When | When the operator loads a primary image after unloading the A2L file, the system shall show no A2L tags. | Yes; tested (`test_tc_b100_11_bare_s19_reload_after_unload_shows_no_a2l_tags`, `test_tc_b100_11_unload_all_clears_the_parsed_a2l`, `test_tc_b100_11_unload_a2l_alone_clears_the_parsed_a2l`). |

### S2.2 · What a tag declares (CTX-A2L-TAG)

Replaces: the "RECORD_LAYOUT Interpretation" block, the byte-order precedence, the unit precedence of the "Viewer" block.

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-A2L-010 | When | When the system reads a CHARACTERISTIC, the system shall take its address from its header. | Yes; tested. |
| R-A2L-011 | If | If a tag has an ECU_ADDRESS line, then the system shall take the tag's address from that line. | Yes; tested. |
| R-A2L-012 | If | If a MEASUREMENT has no ECU_ADDRESS line, then the system shall give it no address. | Yes. |
| R-A2L-013 | If | If a tag has a DATA_SIZE or LENGTH line, then the system shall take its length from that line. | Yes; tested. |
| R-A2L-014 | If | If a MEASUREMENT has no DATA_SIZE or LENGTH line, then the system shall take its length as the size of its datatype × its MATRIX_DIM (1 when absent). | Yes; tested. |
| R-A2L-015 | If | If a VALUE CHARACTERISTIC has no DATA_SIZE or LENGTH line, then the system shall take its length as the size of its datatype. | Yes; tested. |
| R-A2L-016 | If | If a VAL_BLK CHARACTERISTIC has no DATA_SIZE or LENGTH line, then the system shall take its length as the size of its datatype × its MATRIX_DIM. | Yes. |
| R-A2L-017 | If | If an ASCII CHARACTERISTIC has no DATA_SIZE or LENGTH line, then the system shall take its length from its NUMBER line. | Yes. |
| R-A2L-018 | If | If a CURVE or MAP has no DATA_SIZE or LENGTH line, then the system shall take its length as the size of its whole record: the components of its record layout, with their alignment, for its number of axis points. | Partly: a deposit name with a datatype gives one element's size (D2-7). |
| R-A2L-019 | If | If an axis of a CURVE or MAP takes its points from another section, then the system shall count the points of that section. | Yes; tested. |
| R-A2L-020 | If | If the system cannot determine a tag's length, then the system shall give the tag no length. | Yes; tested. Includes CUBOID, MAP_BLOCK, an unknown record-layout line, a record over 1 MiB. |
| R-A2L-021 | If | If a tag has a DATA_TYPE line, then the system shall take its datatype from that line. | Yes; tested. |
| R-A2L-022 | If | If a CHARACTERISTIC's record layout names a datatype, then the system shall take the tag's datatype from the record layout. | Yes; tested. |
| R-A2L-023 | If | If a CHARACTERISTIC's record layout names no datatype, then the system shall take the datatype the deposit name spells out. | Partly: today the size is guessed from the name, so `__SWORD_Z` reads as UWORD and `__FLOAT32_IEEE_Z` as ULONG (D2-8). |
| R-A2L-024 | If | If a tag has a BYTE_ORDER line, then the system shall use that byte order for the tag. | Yes; tested. |
| R-A2L-025 | If | If a tag has no BYTE_ORDER line and its record layout has one, then the system shall use the record layout's byte order. | Yes. |
| R-A2L-026 | If | If neither a tag nor its record layout has a BYTE_ORDER line, then the system shall use the BYTE_ORDER of the MOD_COMMON of the tag's module. | Yes; tested. |
| R-A2L-027 | If | If no BYTE_ORDER applies to a tag, then the system shall use little-endian. | Yes. |
| R-A2L-028 | If | If a BYTE_ORDER line holds a value that is not a byte order, then the system shall raise the WARNING issue `A2L_UNKNOWN_BYTE_ORDER` for that tag. | No: ignored silently (D2-3). |
| R-A2L-029 | If | If a BYTE_ORDER line holds a value that is not a byte order, then the system shall apply the next rule of R-A2L-024 … 027. | Yes. |
| R-A2L-030 | If | If a tag has a UNIT or PHYS_UNIT line, then the system shall take as its unit the whole value of that line, without quotes. | Partly: PHYS_UNIT ignored, quotes kept, `"deg C"` cut to `"deg` (D2-6). |
| R-A2L-031 | If | If a tag has no UNIT or PHYS_UNIT line, then the system shall take as its unit the unit of its conversion method. | Partly: only the tag table does it (D2-6). |
| R-A2L-032 | U | The system shall show the same unit for a tag in the tag table, the detail card and the description window. | No: three different rules today (D2-6). |
| R-A2L-033 | U | The system shall read a conversion method's unit from its conversion line, whether that line is the /begin line or a later one. | Partly: on the /begin line the format is read as the unit (D2-6). |
| R-A2L-034 | U | The system shall give each tag the memory region of the MEMORY_SEGMENT that holds its address. | Yes; tested. |
| R-A2L-035 | If | If no MEMORY_SEGMENT holds a tag's address, then the system shall give the tag the memory region unknown. | Yes; tested. |
| R-A2L-036.1 | When | When the system reads a MEMORY_SEGMENT block, the system shall take the first word after `/begin MEMORY_SEGMENT` as the segment's name. | Yes; tested (`test_tc682_quoted_names_and_the_offset_field`). |
| R-A2L-036.2 | When | When the system reads a MEMORY_SEGMENT block, the system shall take as its record line the first line that splits into at least five words, a quoted text counting as one word. | Yes; tested (`test_tc682_quoted_demo_a2l_segments_parse_to_full_rows`). |
| R-A2L-036.3 | When | When the system reads a MEMORY_SEGMENT record line, the system shall take its fourth word as the segment's base and its fifth word as the segment's size. | Yes; tested (`test_tc682_unquoted_fixture_rows_parse_byte_identically`). |
| R-A2L-036.4 | If | If the base word of a MEMORY_SEGMENT record line is not a number, then the system shall give the segment no base and no size. | Yes; untested. |
| R-A2L-036.5 | If | If the size word of a MEMORY_SEGMENT record line is not a number, then the system shall give the segment no size. | Yes; untested. |
| R-A2L-036.6 | When | When a MEMORY_SEGMENT record line has a sixth word that is a number, the system shall take it as the segment's offset. | Yes; tested (`test_tc682_quoted_names_and_the_offset_field`). |

### S2.3 · From bytes to a physical value (CTX-A2L-VALUE)

Replaces: the "Raw Memory Extraction", "Raw Value Decoding" and "COMPU_METHOD Execution" blocks.

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-A2L-040 | When | When every byte of a tag's span is in the image, the system shall read the tag's raw bytes. | Yes. |
| R-A2L-041 | If | If a byte of a tag's span is not in the image, then the system shall give the tag no raw value. | Yes. |
| R-A2L-042 | If | If a tag's length is more than 1 MiB, then the system shall give the tag no raw value. | Yes. |
| R-A2L-043 | U | The system shall read a tag's raw value as its datatype, in its byte order. | Yes; tested. |
| R-A2L-044 | U | The system shall read a signed datatype as two's complement. | Yes; tested. |
| R-A2L-045 | U | The system shall read FLOAT16_IEEE, FLOAT32_IEEE and FLOAT64_IEEE as IEEE 754 binary16, binary32 and binary64. | Partly: FLOAT16 gives no value (D2-9). |
| R-A2L-046 | If | If a tag has no datatype the system can read, then the system shall give the tag no raw value. | Yes. |
| R-A2L-047 | If | If a tag is a multi-value tag, then the system shall give it one raw value per element. | No: the first element is read as a single value (D2-10). |
| R-A2L-050 | If | If a tag has no raw value, then the system shall give it the conversion status missing. | Yes. |
| R-A2L-051 | If | If a tag has no conversion method, then the system shall give it a physical value equal to its raw value. | Yes. |
| R-A2L-052 | If | If a tag has no conversion method, then the system shall give it the conversion status identity. | Yes (status text `identity_fallback`). |
| R-A2L-053 | When | When a tag's conversion method is IDENTICAL, the system shall give it a physical value equal to its raw value. | Yes; tested. |
| R-A2L-054 | When | When a tag's conversion method is LINEAR, the system shall give it the physical value a × raw + b. | Yes; tested. |
| R-A2L-055 | If | If a LINEAR conversion method lacks a or b, then the system shall use 1 for a missing a and 0 for a missing b. | Yes. |
| R-A2L-056 | When | When a tag's conversion method is RAT_FUNC, the system shall give it the physical value that solves the RAT_FUNC equation for its raw value. | Yes; tested. |
| R-A2L-057 | If | If a RAT_FUNC equation has two solutions, then the system shall take the one inside the tag's limits, or the one closer to 0 when both or neither are inside. | Yes; tested. |
| R-A2L-058.1 | If | If a RAT_FUNC equation has no solution for a tag's raw value, then the system shall give the tag the conversion error `RAT_FUNC has no solution for this value`. | Yes; tested. |
| R-A2L-058.2 | If | If a RAT_FUNC equation has no real root for a tag's raw value, then the system shall give the tag the conversion error `RAT_FUNC has no real root for this value`. | Yes; tested. |
| R-A2L-058.3 | If | If every root of a RAT_FUNC equation has a zero denominator, then the system shall give the tag the conversion error `RAT_FUNC root has a zero denominator`. | Yes; tested. |
| R-A2L-059 | When | When a tag's conversion method is TAB_VERB, the system shall give it the text its COMPU_VTAB pairs with its raw value. | No: shown as raw with status unknown method (D2-5). |
| R-A2L-060 | When | When a tag's conversion method is FORM, the system shall give it the conversion status unsupported. | Yes. |
| R-A2L-061 | When | When a tag's conversion method is TAB_INTP, the system shall interpolate its physical value linearly between the two table pairs around its raw value. | Yes; tested. |
| R-A2L-062 | If | If a TAB_INTP raw value is outside the table, then the system shall give the physical value of the nearest end of the table. | Yes; tested. |
| R-A2L-063 | When | When a tag's conversion method is TAB_NOINTP, the system shall give it the physical value of the table pair whose raw value is nearest to its raw value. | Yes. |
| R-A2L-064 | If | If a conversion method names a table that does not exist, then the system shall give the tag the conversion error `lookup table missing`. | Yes. |
| R-A2L-065 | If | If a conversion method names an empty table, then the system shall give the tag the conversion error `lookup table is empty`. | Yes. |
| R-A2L-066 | If | If a tag's conversion method has a type this list does not name, then the system shall give it the conversion status unknown method. | Yes. |

### S2.4 · Checking tags against the image (CTX-A2L-CHECK)

Replaces: the "A2L Decode Validation" block, R-A2L-002, R-A2L-ISSUE-RECONCILE-002 (the issue half is in S2.5).

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-A2L-070 | When | When an A2L file and a primary image are both loaded, the system shall check each tag that has an address and a length against the image. | Yes; tested. |
| R-A2L-071 | If | If only a MAC file is loaded besides the A2L file, then the system shall check no tag. | No: placeholder bytes make a 1-byte tag "in image" (D2-20). |
| R-A2L-072 | If | If a tag has no address and is not virtual, then the system shall mark its schema as not complete. | Yes; tested. |
| R-A2L-073 | If | If a checked tag's physical value is outside its limits, then the system shall mark the value as outside the limits. | Yes. |
| R-A2L-074 | When | When an A2L file is loaded, the system shall show the A2L summary in the Workspace "Context" pane. | Yes; tested. |
| R-A2L-075 | When | When the system shows the A2L summary, the system shall list the parse errors under the heading `A2L parse errors:`, one `- <error>` line each. | Yes; tested. |
| R-A2L-076 | When | When the system shows the A2L summary, the system shall list the sections under the heading `A2L Sections:`, one `- <name> <header> (lines <first>-<last>)` line each, indented by depth. | Partly: hidden when any parse error exists (D2-12). |
| R-A2L-077 | When | When the system shows the A2L summary, the system shall list the tags under the heading `A2L Tags:`, one `- <section> <name>: <address> len=<length> mem=<region> <tag status text>` line each. | Partly: hidden when any parse error exists (D2-12). |
| R-A2L-078 | If | If the A2L summary has more than 500 lines, then the system shall replace the rest with the line `... truncated <k> additional tag lines ...`. | Yes; tested. |
| R-A2L-079 | If | If no A2L file is loaded, then the system shall show `No A2L loaded.` in the A2L summary. | Yes. |

### S2.5 · The A2L Explorer (CTX-A2L-SCREEN)

Replaces: the "A2L Viewer" block, R-A2L-003, 006, 007, R-TUI-019, 020, 037, 068, 069, R-A2L-ISSUE-RECONCILE-002. File-derived text on this screen follows S1's R-TUI-103 family (the A2L Explorer joins its list of views).

**Layout and table**

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-037.1 | While | While the A2L Explorer is shown, the system shall give the tag table 4/7 of the screen width. | Yes; tested. |
| R-TUI-037.2 | While | While the A2L Explorer is shown, the system shall give the hex pane 3/7 of the screen width. | Yes; tested. |
| R-TUI-042a.1 | While | While the operator scrolls the tag table, the system shall keep its column header visible. | Yes; tested. From R-TUI-042 (a), S3 D3-2. |
| R-TUI-042a.2 | U | The system shall show the tag table with no padding between cells. | Yes; tested. From R-TUI-042 (a), S3 D3-2. |
| R-A2L-006.1 | When | When the system shows the tag table, the system shall show the columns CTX-A2L-SCREEN lists, in that order. | Yes; tested. |
| R-A2L-006.2 | When | When the system shows a tag in the tag table, the system shall start its Tag cell with its in-image glyph. | Partly: `·` also for out of image (D2-16). |
| R-A2L-006.3 | If | If a tag has no name, then the system shall show `UNKNOWN` in its Tag cell. | Yes. |
| R-A2L-006.4 | If | If a tag has no address, then the system shall show `n/a` in its Address cell. | Yes. |
| R-A2L-006.5 | If | If a tag has no length, then the system shall show `n/a` in its Length cell. | Yes. |
| R-A2L-006.6 | If | If a tag has no raw value, then the system shall leave its Raw cell blank. | Yes. |
| R-A2L-006.7 | If | If a tag has a raw value and no physical value, then the system shall show `n/a` in its Physical cell. | Yes; tested. |
| R-A2L-006.8 | If | If a tag has no raw value, then the system shall leave its Physical cell blank. | Yes; tested. |
| R-A2L-006.9 | If | If a tag is a multi-value tag, then the system shall show `<n> values` in its Raw cell and its Physical cell. | No: the first element is shown (D2-10). |
| R-A2L-006.10 | If | If a tag declares one limit only, then the system shall leave the other side of `..` blank in its Limits cell. | Partly: shows `None` (D2-17). |
| R-A2L-006.11 | If | If a tag declares no limits, then the system shall leave its Limits cell blank. | Yes. |
| R-A2L-006.12 | If | If a tag has no value for Unit, Bits, Endian, Func, Access or Dtype, then the system shall leave that cell blank. | Yes. |
| R-TUI-068.1 | When | When the system shows the tag table, the system shall shade every other row. | Yes. |
| R-TUI-068.2 | When | When the system shows the tag table, the system shall show under it the summary `Page <p>/<P> \| tags <a>-<b> / <T> (page size <S>; +/- to change page)  ·  <K> in image`, where K counts the filtered tags that are in image. | Yes; tested. |
| R-TUI-068.3 | If | If no A2L file is loaded, then the system shall show `No A2L tags.` as the summary. | Yes. |
| R-TUI-068.4 | If | If the filter matches no tag, then the system shall show `No tag matches the filter.` as the summary. | No: shows `No A2L tags.` (D2-19). |

**Row colour** (colour names are the palette of S3 CTX-LEGEND; today the A2L and MAC tables use terminal colours instead, S3 D3-18)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-A2L-080 | If | If an ERROR A2L issue names a tag, ignoring case, then the system shall show the tag's row red. | Yes; tested. |
| R-A2L-081 | If | If a WARNING A2L issue names a tag, then the system shall not change the tag's row colour. | Yes; tested. |
| R-A2L-082 | If | If an A2L issue names no tag shown in the table, then the system shall change no row. | Yes; tested. |
| R-A2L-083 | If | If no ERROR A2L issue names a tag and its schema is not complete, then the system shall show its row red. | Yes; tested. |
| R-A2L-084 | If | If no row-colour rule above applies and the tag is in image, then the system shall show its row green. | Yes; tested. |
| R-A2L-085 | If | If no row-colour rule above applies and the tag is out of image, then the system shall show its row white. | Yes; tested. |
| R-A2L-086 | If | If no row-colour rule above applies and the tag is virtual or its source is formula, then the system shall show its row white. | Yes; tested. |
| R-A2L-087 | If | If no row-colour rule above applies, then the system shall show the tag's row grey. | Yes; tested. |
| R-A2L-088 | When | When the system colours a row, the system shall apply the colour to every cell of the row. | Yes. |

**Filter**

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-A2L-007.1 | When | When the operator stops typing in the filter box for 0.15 s, the system shall show only the tags whose filter field contains the filter text, ignoring case. | Yes; tested. |
| R-A2L-007.2 | If | If the filter field is `all`, then the system shall match the filter text against every filter field. | Yes. |
| R-A2L-007.3 | When | When the operator presses the `Field: <field>` button, the system shall open the list of filter fields with the current one marked `(*)`. | Yes. |
| R-A2L-007.4 | When | When the operator picks a filter field, the system shall show `Field: <field>` on the button. | Yes. |
| R-A2L-007.5 | When | When the system matches the filter text against the address field, the system shall compare it with the address as the table shows it. | No: compared with the decimal value (D2-15). |
| R-A2L-007.6 | When | When the operator presses `All`, the system shall show the tags the filter text selects, whatever their status. | Yes; tested. |
| R-A2L-007.7 | When | When the operator presses `Invalid`, the system shall show only the tags whose row is red. | Partly: misses issue-red rows, includes white ones (D2-14). |
| R-A2L-007.8 | When | When the operator presses `In-Memory`, the system shall show only the tags that are in image. | Yes; tested. |
| R-A2L-007.9 | When | When the operator picks a filter mode, the system shall mark its button as active. | No (D2-19). |
| R-A2L-007.10 | When | When the filter changes, the system shall show the first page of the table. | Yes; tested. |

**Find**

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-A2L-090 | When | When the operator presses `Find next`, the system shall move the cursor to the next filtered tag, after the current one, whose shown fields contain the find text, ignoring case. | Yes; tested. |
| R-A2L-091 | If | If no filtered tag after the current one matches, then the system shall continue the search from the first filtered tag. | Yes. |
| R-A2L-092 | When | When the operator edits the find text, the system shall start the next search from the first filtered tag. | Yes. |
| R-A2L-093 | When | When a find moves to a tag, the system shall show the page that holds it. | Yes. |
| R-A2L-094 | When | When a find moves to a tag, the system shall show its address near the top of the hex pane. | Partly: highlighted, not placed near the top (D2-18). |
| R-A2L-095 | When | When a find moves to a tag, the system shall show the status `Tag find: <name> (row <i>)`. | Yes. |
| R-A2L-096 | If | If no filtered tag matches the find text, then the system shall show the status `Tag find: no match.` | Yes. |
| R-A2L-097 | If | If the find text is empty, then the system shall show the status `Tag find query is empty.` | Yes. |
| R-A2L-098 | If | If the tag table is empty, then the system shall show the status `No A2L tags to search.` | Yes. |
| R-A2L-099 | When | When the system compares the find text with the address, the system shall compare it with the address as the table shows it. | No: compared with the decimal value (D2-15). |

**Paging** (both tables; the MAC table is in S2.6)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-019.1 | While | While the operator has set no page size for the tag table, the system shall show 200 rows per page of it. | Yes; tested. |
| R-TUI-019.2 | While | While the operator has set no page size for the MAC table, the system shall show 100 rows per page of it. | Yes; tested. |
| R-TUI-019.3 | When | When the operator opens the page-size choice in the viewer settings, the system shall offer 25, 50, 100, 150 and 200. | Yes; tested. |
| R-TUI-019.6 | When | When the operator sets a page size for a table, the system shall show that many rows per page of it. | Yes; tested. |
| R-TUI-019.4 | When | When the operator presses `Page Next` under a table, the system shall show the next page of that table. | Yes; tested. |
| R-TUI-019.5 | When | When the operator presses `Page Prev` under a table, the system shall show the previous page of that table. | Yes; tested. |
| R-TUI-020.1 | When | When the operator presses `+` or PgDn on the A2L Explorer or the MAC View, the system shall show the next page of the table of that screen. | Yes; tested. |
| R-TUI-020.2 | When | When the operator presses `-` or PgUp on the A2L Explorer or the MAC View, the system shall show the previous page of the table of that screen. | Yes; tested. |
| R-TUI-020.3 | If | If the operator asks for the next page while the last page is shown, then the system shall keep the last page. | Yes; tested. |
| R-TUI-020.4 | If | If the operator asks for the previous page while the first page is shown, then the system shall keep the first page. | Yes; tested. |
| R-TUI-020.5 | If | If the operator presses `+` or `-` on a screen other than the A2L Explorer and the MAC View, then the system shall change no page. | Yes; tested. |

**Detail card**

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-069.1 | When | When a row of the tag table becomes the highlighted row, the system shall show that tag in the detail card. | Yes; tested. |
| R-TUI-069.2 | If | If no row is highlighted, then the system shall show `Highlight a tag to inspect its fields.` in the detail card. | Yes. |
| R-TUI-069.3 | When | When the system shows a tag in the detail card, the system shall show on its first line the in-image glyph, the tag's display identifier or name, and its address. | Yes; tested. |
| R-TUI-069.4 | When | When the system shows a tag in the detail card, the system shall show the lines `desc <description>`, `unit <unit> · conv <conversion method>`, `layout <record layout>`, `byteorder <byte order>` and `limits <lower>..<upper>`. | Yes; tested. |
| R-TUI-069.5 | If | If a detail-card field has no value, then the system shall leave out its line. | Yes. |
| R-TUI-069.6 | U | The system shall show the detail card at most 5 lines high, above the hex view. | Yes; tested. |
| R-TUI-069.7 | If | If the detail card's content is longer than 5 lines, then the system shall let the operator scroll it. | Yes. |

**Selecting a row**

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-A2L-100 | When | When the operator selects a tag row, the system shall show the tag's address near the top of the hex pane. | Yes; tested. |
| R-A2L-101 | When | When the operator selects a tag row, the system shall highlight in the hex pane the tag's span, up to 4,096 bytes. | Yes; tested. |
| R-A2L-102 | If | If the selected tag has no length, then the system shall highlight 1 byte. | Yes. |
| R-A2L-103 | When | When the operator selects a tag row, the system shall show the status `Tag at <address>`. | Yes; tested. |
| R-A2L-104 | If | If the selected tag has no address, then the system shall leave the hex pane unchanged. | Yes. |

**Export to JSON**

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-A2L-003.1 | When | When the operator presses `j`, the system shall write the parsed A2L data to `<work area>/temp/<A2L file stem>.a2l.json`. | Yes; tested. |
| R-A2L-003.2 | When | When the system writes the A2L JSON file, the system shall replace a file of the same name. | Yes. |
| R-A2L-003.3 | When | When the system has written the A2L JSON file, the system shall show the status `A2L JSON saved: <path>`. | Yes; tested. |
| R-A2L-003.4 | If | If no A2L file is loaded when the operator presses `j`, then the system shall show the status `No A2L data to export.` | Yes. |
| R-A2L-003.5 | If | If the system cannot write the A2L JSON file, then the system shall show the status `Cannot save A2L JSON: <reason>`. | No: the error is not caught (D2-25). |

**Description window**

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-A2L-110 | When | When the operator presses `d` on the A2L Explorer with a row highlighted, the system shall open the description window for that tag. | Yes. |
| R-A2L-111 | If | If no row is highlighted when the operator presses `d`, then the system shall show the status `A2L: no tag row under the cursor.` | Yes. |
| R-A2L-112 | When | When the system opens the description window, the system shall title it `Parameter: <name>`. | Yes. |
| R-A2L-113 | When | When the description window shows a CURVE or MAP, the system shall show its kind, name, description, address, byte count, unit and conversion method. | Yes; tested. |
| R-A2L-114 | When | When the description window shows a CURVE or MAP, the system shall show one `Axis <i>:` line per axis. | Yes; tested. |
| R-A2L-115 | When | When the description window shows a CURVE or MAP whose values are in the image, the system shall show the table of its axis points and values. | Yes; tested. |
| R-A2L-116 | If | If a value in the point table is outside the tag's limits, then the system shall mark it `(!)`. | Yes; tested. |
| R-A2L-117 | When | When the description window shows a CURVE or MAP whose values are in the image, the system shall show the shape of its values as a one-line bar chart after `y shape:`. | Yes; tested. |
| R-A2L-118 | If | If the tag is not a CURVE or MAP, then the system shall show its value after `Scalar value:` and the line `(this characteristic is not a CURVE/MAP - no point table)`. | Yes; tested. |
| R-A2L-119 | If | If the point table of a CURVE or MAP cannot be built, then the system shall show `Status: <reason> - point table unavailable`. | Yes; tested. |
| R-A2L-119a | When | When the operator presses `Close` or Esc in the description window, the system shall close the window. | Yes; tested. |

### S2.6 · MAC files and the MAC View (CTX-MAC)

Replaces: R-TUI-039, R-TUI-070, R-TUI-071; MAC behaviour no row stated.

**Reading**

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-MAC-001 | When | When the system reads a MAC file, the system shall skip empty lines and comment lines. | Yes. |
| R-MAC-002 | When | When the system reads a MAC file, the system shall create one MAC record from every other line. | Yes; tested. |
| R-MAC-003 | U | The system shall number MAC lines by their physical position in the file, from 1. | Yes. |
| R-MAC-004 | If | If a MAC line does not hold exactly one `=`, then the system shall record on its MAC record the parse error `Line <n>: expected one '=' separator`. | Yes; tested. |
| R-MAC-005 | If | If the name of a MAC line is not a valid name, then the system shall record on its MAC record the parse error `Line <n>: invalid tag name`. | Yes; tested. |
| R-MAC-006 | If | If the address of a MAC line is not a valid address, then the system shall record on its MAC record the parse error `Line <n>: invalid hex address`. | Yes; tested. |
| R-MAC-007 | If | If a MAC line has a parse error, then the system shall read the line that follows it. | Yes; tested. |
| R-MAC-008 | If | If a MAC file cannot be read, then the system shall create no MAC record. | Yes. |
| R-MAC-009 | If | If a MAC file cannot be read, then the system shall record the diagnostic `Failed to read file: <reason>`. | Yes. |
| R-MAC-010 | When | When a MAC file loads without a primary image, the system shall show the status `Loaded <file name> (MAC only)`. | Yes; tested. |
| R-MAC-011 | When | When a MAC file loads with a primary image, the system shall show the status `Loaded <image name> (S19+MAC: <MAC file name>)`. | Partly: on some load paths the `: <MAC file name>` part is left out (not traced which). |

**Status of a MAC record**

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-MAC-030 | If | If more than one MAC status applies to a record, then the system shall give it the first in this order: ERR_PARSE, NO_ADDR, A2L_ADDR_MISMATCH, NOT_IN_A2L, OUT_OF_IMAGE, NO_A2L, OK. | Partly: OUT_OF_IMAGE comes before the A2L statuses today and hides an address mismatch (D2-21). |
| R-MAC-031 | When | When the system shows a MAC record, the system shall colour its row red for ERR_PARSE, NO_ADDR and A2L_ADDR_MISMATCH. | Yes. |
| R-MAC-032 | When | When the system shows a MAC record, the system shall colour its row pale yellow for NOT_IN_A2L. | No: orange today (S3 D3-18). |
| R-MAC-033 | When | When the system shows a MAC record, the system shall colour its row white for OUT_OF_IMAGE. | Yes. |
| R-MAC-034 | When | When the system shows a MAC record, the system shall colour its row grey for NO_A2L. | Yes. |
| R-MAC-035 | When | When the system shows a MAC record, the system shall colour its row green for OK. | Yes. |

**MAC View**

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-039.1 | While | While the MAC View is shown, the system shall give the hex pane the larger of 82 columns and 3/7 of the screen width. | Yes; tested. |
| R-TUI-039.2 | While | While the MAC View is shown, the system shall give the MAC table the rest of the screen width. | Yes; tested. |
| R-MAC-040 | When | When the system shows the MAC table, the system shall show the columns CTX-MAC lists, in that order. | Yes. |
| R-MAC-041 | If | If a MAC record has no valid name, then the system shall show `(invalid)` in its Tag cell. | Yes. |
| R-MAC-042 | If | If a MAC record has no address, then the system shall show `n/a` in its Address cell. | Yes. |
| R-MAC-043 | If | If no primary image is loaded, then the system shall show `n/a` in every InMem cell. | Yes; tested. |
| R-MAC-044 | When | When the system shows a MAC record whose name matches an A2L tag, the system shall show `<section>:<name>` of the first such tag in its A2LMatch cell. | Yes. |
| R-TUI-070.1 | When | When the system shows a MAC record, the system shall start its Tag cell with its status glyph. | Yes; tested. |
| R-TUI-070.2 | If | If a MAC record has a parse error, then the system shall show the glyph `✗` in red. | Yes; tested. |
| R-TUI-070.3 | If | If a MAC record is out of the primary image, then the system shall show the glyph `⚠` in orange. | Yes; tested. |
| R-TUI-070.4 | If | If a MAC record is in the primary image, then the system shall show the glyph `✓` in green. | Yes; tested. |
| R-TUI-070.5 | If | If a MAC record was not checked against a primary image, then the system shall show the glyph `·` in grey. | Yes; tested. |
| R-MAC-050 | When | When the system shows the MAC table, the system shall show under it the summary `Page <p>/<P> \| rows <a>-<b> / <T> (page size <S>; +/- for MAC page)` followed by one count per MAC status. | Partly: Neutral counts warnings and info together (D2-22). |
| R-MAC-051 | If | If a primary image is loaded, then the system shall show under the MAC summary the line `Coverage MAC->S19=<x>%  A2L->S19=<y>%  A2L<->MAC=<z>%`. | Yes. |
| R-MAC-052 | If | If no MAC file is loaded, then the system shall show `No MAC loaded.` as the MAC summary. | Yes. |
| R-MAC-053 | If | If a loaded MAC file has no MAC record, then the system shall show `MAC file has no records.` as the MAC summary. | No: shows `No MAC loaded.` (D2-23). |
| R-MAC-054 | When | When the operator selects a MAC row, the system shall show its address near the top of the MAC hex pane. | Yes; tested. |
| R-MAC-055 | When | When the operator selects a MAC row, the system shall show the status `MAC tag at <address>`. | Yes; tested. |
| R-MAC-056 | If | If the selected MAC row has a parse error, then the system shall leave the hex pane unchanged. | Yes; tested. |

**Coverage strip**

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-071.1 | While | While a MAC file with at least one MAC record is loaded, the system shall show the coverage strip above the MAC table. | Yes; tested. |
| R-TUI-071.2 | If | If no MAC file with a MAC record is loaded, then the system shall hide the coverage strip. | Yes; tested. |
| R-TUI-071.3 | While | While a primary image is loaded, the system shall show the coverage strip as `MAC→S19 <X> of <Y> <bar>  ·  A2L↔MAC <N> matches`. | Yes; tested. |
| R-TUI-071.4 | While | While no primary image is loaded, the system shall show the coverage strip as `MAC→S19 no image  ·  A2L↔MAC <N> matches`. | No: shows `0 of 0` and `0 matches` (D2-24). |
| R-TUI-071.5 | U | The system shall count as Y the MAC records with a valid name and address. | Yes; tested. |
| R-TUI-071.6 | U | The system shall count as X the records of Y whose address is in the primary image. | Yes; tested. |
| R-TUI-071.7 | U | The system shall count as N the A2L↔MAC matches. | Yes; tested. |
| R-TUI-071.8 | U | The system shall draw the bar as 5 cells, filled in proportion to X / Y. | Yes; tested. |
| R-TUI-071.9 | If | If Y is 0, then the system shall draw the bar with no cell filled. | Yes; tested. |

---

## 5. Decisions: recommendation applied

D2-n are S2's decisions. "Code change" items become backlog for the batch that takes this chapter in.

**Requirement follows the code (no code change)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D2-2 | Byte order: the text omits MOD_COMMON and lists a step that can never apply. | Rows follow the code: tag → record layout → MOD_COMMON → little-endian (R-A2L-024 … 027). The dead step is removed from the code. |
| D2-4 | FORM: "unsupported unless safe evaluation is enabled"; nothing can enable it. | State it plainly: FORM is not converted (R-A2L-060). No speculative row for a switch that does not exist. |
| D2-28 | R-A2L-006 lists 12 columns, R-TUI-068 builds 16. | The 16 columns as built (CTX-A2L-SCREEN). |
| D2-27 | Layout rows carry CSS values and batch history; R-TUI-069 carries a Textual naming rule (`_nodes`, `_context`). | Rows state the proportions the operator sees. The naming rule is a real constraint, but of the code, not of the product: it moves to the design notes (`docs/ARCHITECTURE.md`). |
| D2-30 | Batch-100 (Inc 9a, 9b) replaced `LoadFileScreen`, the old code pointer of R-A2L-004, with the Load dialog: an A2L file is loaded from a typed `.a2l` path or a recent entry (copied), a `.a2l` file of the Workarea Files list (read in place, `app.py:15615`), or the start-up path. The dialog's typed-path rule refuses a path that does not exist or has no supported suffix before the A2L load starts (`app.py:14812-14829`, `:14990-14993`). | Keep R-A2L-004.3 and .4 as the use-time look of the A2L load (the file can go between the dialog and the load, `app.py:15190-15201`, `:15231-15235`); the routes, the refusal texts of the dialog and the copy rules stay S5's and S7's. "A2L load" is defined in CTX-A2L-FILE. |
| D2-31 | Batch-100 HLR-177 (Inc 12b, LLR-177.2b) moved the A2L copy and parse to a worker; a copy or parse that fails now ends with `File NOT loaded: '<file name>' could not be read — check that the file can be opened, then load again.` and keeps the A2L loaded before (`app.py:15361-15378`). `Cannot load A2L: <reason>` remains, for the work-area guard only (`app.py:15364-15368`). The review's R-A2L-004.6 gave `Cannot load A2L: <reason>` for any read failure; at 093a7c0 that text was painted for the guard only, and a parse exception escaped the handler (S5 D5-15). | Batch-100 wins (more recent, tested): R-A2L-004.6 takes the `could not be read` text; R-A2L-004.7 keeps the earlier A2L; R-A2L-004.8 keeps `Cannot load A2L:` for the guard. LLR-177.2c adds the two use-time refusals (R-A2L-004.3 size arm, R-A2L-004.9). |
| D2-32 | Batch-100 HLR-176 / HLR-177 (Inc 12a, 12b) show a progress line for the A2L load (S6 owns the line, its spinner, elapsed time and end rules). The A2L-specific parts: the copy and parse run off the screen's thread (`app.py:15273-15307`); the parser reports the bytes it has read every 4,096 lines and once at the end (`a2l.py:151`, `:197`, `:230`), forwarded to the bar within step 2 (`app.py:20494-20524`); an in-place pick starts at step 2 (`app.py:15265-15266`). `a2l.py` changed only by that report: with no report asked, the parse is the one of 093a7c0 (LLR-176.4a). LLR-165.4 (Inc 3, `1f5dd02`, already at 093a7c0 with no S2 row; `app.py:16843-16851`) drops the parsed A2L on unload, so a later primary load re-attaches no stale tags. | Rows R-A2L-004.10 … .13 (rule D-9: the A2L part lives here; the line's format and end rules are S6's and are not repeated). The parser rows of S2.1 … S2.3 keep their cells. |
| D2-33 | Tests that verify implementation only (not cited as row evidence): `test_tc_b100_73_a2l_py_is_listed_in_the_frozen_engine_guard` (frozen-engine list, LLR-176.4b), `test_tc_b100_73_no_fstat_without_a_callback` and `test_tc_b100_73_one_argument_callers_outside_the_app_are_unchanged` (call shape), `test_tc_b100_73_no_report_without_a_file_and_none_without_a_callback` and `test_tc_b100_73_a_failed_read_reports_no_final_total` (callback mechanics). The parse cache (`parse_a2l_cached`, `_store_a2l_cache`, `A2LAttachRequest` / `Result`, LLR-177.1d / .1e) is worker mechanics. | No rows. The reasons stay in the batch records. |

**Remove (rule use/defer/delete)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D2-1 | `get_raw_value`, `get_physical_value`, `validate_characteristic`: no caller in the app, and each always answers about the **first** tag of the file. The "decode validation" checks live only there. | Remove the three functions, their tests and the two blocks ("Output API", "Decode validation"). The checks that matter for the operator stay as rows: schema complete, in image, value outside limits. |
| D2-26 | `overlap_conflict` is always `False`; `missing_ranges` is a list of single addresses that nothing displays. | Remove `overlap_conflict` from the code; field names leave the requirements. |
| D2-29 | Per-cell accents of the tag table (R-TUI-068 amendment E) are built and never visible, because the row colour replaces them. | Remove the accent code. |

**Code change: correct a defect**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D2-3 | A BYTE_ORDER value that is not a byte order is ignored silently, so the tag may decode with the wrong order and nobody sees it. | Raise the WARNING issue `A2L_UNKNOWN_BYTE_ORDER` for the tag (R-A2L-028). The new code goes to the issue list of S3. |
| D2-5 | TAB_VERB is not recognised: COMPU_VTAB is read and never used; the tag shows its raw number with "unknown method". Enumerations (`ON`/`OFF`, gear names) are common in calibration files. | Show the COMPU_VTAB text (R-A2L-059). |
| D2-6 | Units: `UNIT "deg C"` reads as `"deg`; PHYS_UNIT is ignored; three surfaces use three precedence rules; a conversion line on the /begin line puts the format where the unit belongs. | One rule everywhere: the tag's UNIT or PHYS_UNIT (whole text, no quotes), else the conversion method's unit (R-A2L-030 … 033). |
| D2-7 | A CURVE or MAP whose deposit name spells a datatype gets the length of one element, not of its whole record. | Always the whole record (R-A2L-018). This also fixes how much of the image the tag is checked against. |
| D2-8 | With no datatype in the record layout, the datatype is guessed from the deposit name by size: `__SWORD_Z` becomes UWORD (sign lost), `__FLOAT32_IEEE_Z` becomes ULONG (float read as integer). Wrong values, shown as correct. | Take the datatype the name spells out; if it spells none, no raw value (R-A2L-023, 046). |
| D2-9 | FLOAT16_IEEE has a known size but decodes to nothing. | Decode it (Python reads binary16 directly) (R-A2L-045). |
| D2-10 | A multi-value tag (CURVE, MAP, VAL_BLK, MATRIX_DIM > 1) shows its first element in Raw and Physical as if it were the tag's value; a MEASUREMENT with MATRIX_DIM 2 gives a size-mismatch error. | Read one value per element; the table shows `<n> values`; the description window keeps the points (R-A2L-047, R-A2L-006.9). |
| D2-11 | Comments are stripped only in two places, so a commented-out `/begin` opens a section; `/end FOO` closes `/begin BAR` silently. | Strip comments before building sections; a mismatched /end is a parse error (R-A2L-001.2, 001.5). |
| D2-12 | The A2L summary hides all sections and tags as soon as one parse error exists. | Show the errors first, then the sections and tags (R-A2L-076, 077). |
| D2-13 | `A2L loaded: <name>` also appears when the file had parse errors, which then show only as issues. | `A2L loaded with <n> parse errors: <name>` (R-A2L-004.2). |
| D2-14 | The `Invalid` filter misses rows that are red because of an issue and includes white rows. | Invalid = the red rows (R-A2L-007.7). |
| D2-15 | Filter and find compare the address with its decimal value, not the `0x…` the table shows; the filter also drops zero values. | Compare with the text as shown (R-A2L-007.5, R-A2L-099). |
| D2-16 | The A2L glyph `·` means both "not checked" and "out of image". | Same glyphs as the MAC View: ✓ in image, ⚠ out of image, · not checked (CTX-A2L-SCREEN). |
| D2-17 | A one-sided limit shows `None..100` in the table and `..100` in the card. | `..100` in both (R-A2L-006.10). |
| D2-18 | Find highlights the tag in the hex pane but does not bring it near the top, unlike row selection. | Same as row selection (R-A2L-094). |
| D2-19 | The filter-mode buttons show no active state; `No A2L tags.` appears both with nothing loaded and with a filter that matches nothing. | Mark the active mode; `No tag matches the filter.` for the second case (R-A2L-007.9, R-TUI-068.4). |
| D2-20 | In a MAC-only session the hex view gets a placeholder byte 0 at each MAC address; a 1-byte A2L tag at one of them reads as "in image" (false green). | With no primary image, no tag is checked (R-A2L-071). The placeholder may stay for the hex view, but it is not an image. |
| D2-21 | A MAC record out of the image shows OUT_OF_IMAGE (info) even when its address disagrees with the A2L (error). | Errors first (R-MAC-030). |
| D2-22 | The MAC summary's `Neutral` count lumps warnings and info together. | One count per status (R-MAC-050). |
| D2-23 | An empty MAC file shows `No MAC loaded.` while the status line says it loaded; `No MAC records parsed.` exists in the code but can never appear. | `MAC file has no records.` (R-MAC-053). |
| D2-24 | With no S19/HEX loaded, the coverage strip reads `0 of 0 … 0 matches` even when rows say `OK`. | `MAC→S19 no image  ·  A2L↔MAC <N> matches`, with N counted (R-TUI-071.4). |
| D2-25 | A failed JSON write is not caught. | Status `Cannot save A2L JSON: <reason>` (R-A2L-003.5). |

**Passed to other groups** (rows there, not here)

- **S3** (issue producers): `A2L_UNRECOGNIZED_BLOCK` flags standard blocks (MOD_COMMON, MOD_PAR, AXIS_DESCR) as unrecognised: false warnings on every real file. `A2L_BROKEN_REFERENCE` misses nested `/begin REF_CHARACTERISTIC` blocks. `A2L_INVALID_ADDRESS` can never fire. Plus the new `A2L_UNKNOWN_BYTE_ORDER` (D2-3).
- **S4**: every parse-OK MAC address gets an orange overlay in the hex view.
- **S6 / S7**: the MAC View has no header or `?` chip unlike the A2L Explorer; the A2L help text still describes a "section tree".
- **S10** (Patch Editor): `encode_physical_to_raw_bytes` (physical → raw) lives in `a2l.py` but is Patch Editor behaviour; its rows go there. Note for that review: decoding TAB_NOINTP takes the nearest pair (R-A2L-063) while encoding refuses a value not in the table. Reading approximates, writing must be exact, so the asymmetry looks right.
- **S1**: the A2L Explorer (table and detail card) and the MAC View join the list of views in R-TUI-103 (file text shown verbatim, no control characters, no markup). Updated in `S1-ears-strict.md`.

Code-change items for the batch: D2-3, D2-5 … D2-25, plus the removals D2-1, D2-26, D2-29.

---

**Received from later groups** (after S6–S17 were written)

- **S17**: the MEMORY_SEGMENT reading rules (S0 LLR-137.4) are A2L reading, so they are rows here: R-A2L-036.1 … .6 (rule D-9). S17 keeps only which segments give rows (R-SEG-SRC.6). "Number" means decimal or `0x` hexadecimal.
- **S11**: R-A2L-004.5 (A2L load refused while the open project has an A2L) stays here; S11 cites it (R-PROJ-002.7) and gives the MAC the same rule (D11-30).
- **S6**: the viewer settings that set the A2L and MAC page sizes of R-TUI-019.3 are S6 rows.
- **S10**: the encoder rows S2 passed to S10 are deferred with the symbol input (S10 D10-13, D10-42).

**Reconciled with batch-100 (s19_app 570b4b5)**

- Rows added (7): R-A2L-004.7 … .13 (a failed load keeps the earlier A2L; the guard text; the unreadable project folder; input and screen kept live; parse progress by bytes; the in-place pick at the Parse step; no stale tags after an unload).
- Rows changed (2): R-A2L-004.3 (adds the size-read arm), R-A2L-004.6 (the `could not be read` text, D2-31). Cells changed: R-A2L-004.1 (now tested), .4 (test named).
- Cells re-checked, unchanged: R-A2L-004.2 (still No, D2-13), .5; R-MAC-010, 011 (the MAC load functions only take their inputs as arguments now; texts unchanged, `app.py:17791`).
- Rows retired: none. Decisions added: D2-30 … D2-33. Decisions superseded: none (R-A2L-004.6's old text is a row change, D2-31).
- Passed (scratch `passed-sweep.md`): S5 (a failed A2L load records no recent source), S6 (the A2L load steps and progress rows live here), S11 (the A2L sync's unreadable-folder line).
- Consolidation (items from S5 and S6): cell changed R-A2L-004.6 (cites `test_tc_b100_50_a2l_raise_ends_the_action_first`, uncited by S6). Already here: the failure text and the kept A2L (R-A2L-004.6, .7, D2-31), the guard text (R-A2L-004.8), the early refusals (R-A2L-004.3, .9), the A2L load as a long action (R-A2L-004.1, .10 … .12), the TC-B100-73 nodes (R-A2L-004.11, D2-33). The A2L slot with no primary is S5's (R-WS-LOADED.3).

## 6. Counts

| | Old S2 | Strict |
|---|---:|---:|
| Requirement statements | 8 unnumbered blocks + 16 rows | 224 rows (209 + 2 from S3 D3-2 + 6 MEMORY_SEGMENT rows from S17 + 7 from batch-100) |
| With an id | 16 | 224 (`ears_lint.py` counts only rows that carry an id) |
| Statements the code contradicts | 6 | 0 (each now says what the code does, or names the decision that changes the code) |
| Rows by form: U / When / While / If / Where | — | 15 / 81 / 12 / 116 / 0 |
| Rows that could not be written in EARS | — | 0 |
| Decisions | — | 33 (8 follow the code, 3 remove, 22 correct a defect) |

Checked by script: every row has exactly one `shall`, starts with its form's opening words, `If` rows have `, then the system shall`, `When`/`While` rows have `, the system shall`, no row uses "unless" or "only if", no id repeats.
