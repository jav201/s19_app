# S1 — strict EARS pass over the part-67 proposal (2026-10-30)

Input: `review/S1-chapter-proposed.md` (part 67 B, waiting for a verdict). Code read again: `base/s19_app/core.py`, `hexfile.py`, `cli.py`, `range_index.py`, `version.py`. No test was run.
Code: Reconciled with s19_app 570b4b5 (batch-100) on 2026-11-01: rows and cites in S1.5 (CTX-TEXT, R-TUI-103 … 103b) and decision D-16 verified at 570b4b5; other cites refer to 093a7c0.

Result: **every row is now one sentence, one of the five EARS forms, one `shall`, one response.** No row needed a sixth form. No row uses `Where` (reason in rule E4).

Revision 2 (same day): the open decisions are no longer asked; each has a recommendation, **already applied to the rows** (section 4). Mark only what you object to. The biggest effect: the command-line tool is removed (the README already calls it deprecated), so S1.6 keeps only the version row. 55 proposed rows become 72 (126 before the tool was removed).

---

## 1. Rules applied

- **E1 · Form.** Each row is exactly one of:
  - `The system shall <response>.` (ubiquitous: always true)
  - `When <event>, the system shall <response>.` (something happens at a point in time)
  - `While <state>, the system shall <response>.` (a state of the system that lasts)
  - `If <unwanted condition>, then the system shall <response>.` (a defect in the input, a missing file, a bad argument)
  - `Where <feature>, the system shall <response>.` (a feature a build or configuration may include or leave out)
  The subject is always "the system", never "it", "the loader" or "the parsed record".
- **E2 · Singular.** One `shall`, one verb, one object. No second sentence, no "and" between two responses, no "only if" or "unless" inside the response. An "only when" becomes two rows (one says when it happens, one says when it does not).
- **E3 · Alternatives in a condition.** A condition may list alternatives of the same kind ("type 03 or type 05") only when every alternative gets exactly the same response; each alternative is one test case. Where the response differs by format (S19 vs Intel HEX), the row is split. A condition may also join facts with "and" when all must hold at once (R-READ-006.1: the tally is at most 0xFFFF **and** differs from the S5 count). Each still has one response.
- **E4 · Pattern meaning.** `While` is for a state of the system (the address base the reader is using), never for a property of a record or a line. `Where` is for an optional feature, never for a command option: a command option is an event (`When the operator runs dump-by-range with --output <path>`). S1 has no optional feature, so no row uses `Where`.
- **E5 · Exact text.** A row that produces a message fixes its exact text, with `<placeholders>`, so a test can compare it.
- **E6 · Context notes define, rows require.** A context note holds terms, formats and lists that rows cite. Any sentence in a note that says what the system *does* moves to a row.
- **E7 · Ids.** A row split from an existing row keeps its id with `.1`, `.2` …; a new row gets a new id. Renumbering is for the batch.

---

## 2. What did not make sense in the proposal

These are the rows that broke more than form. Form-only breaks (two responses in one row, "it" as subject) are counted in section 5.

| Row (proposal) | What did not make sense | Fix |
|---|---|---|
| R-READ-002 | "load the same records and the same image": the same as what? The row names no second load to compare with. | Ubiquitous: `The system shall treat CR, LF and CR LF as line ends.` |
| R-VAL-002 | Trigger "When the system rejects a line" is the system's own response. The row then repeats what every reject row already says. | Dropped. One generic reject row, one "exactly one diagnostic" row, one precedence row, one "keep reading" row (R-VAL-002.1 … .4). |
| R-PARSE-001 … 005, R-HEX-004 … 006 | No precedence. A line with two defects (bad address *and* bad checksum) satisfies two rows, so two diagnostics are required; the code records one. The rows contradict the code and each other. | Line defects are listed in check order in the context note; R-VAL-002.3 says the first one gives the message. |
| R-READ-006 | Says nothing of the limits the code applies on purpose: S5 is compared only while the tally is at most 0xFFFF (S6: 0xFFFFFF), and rejected lines that start with S1/S2/S3 count toward the tally. As written, the row asks for a mismatch notice the code deliberately does not give. | "Data-record tally" defined in CTX-S19; the limit is in the condition (R-READ-006.1, .2). |
| R-HEX-009 | "While the address base is 0" is also true after a type-04 record with value 0, or a type-02 record with value 0, and the 02 rule wraps at 64 KiB. Two rows apply to the same byte. | `While no address-base record has been applied …` |
| R-HEX-005 | "a diagnostic that names the field": no text, so no test can check it. | One row per field with an exact message (Q-C). |
| R-IMG-006 | "every count derived from them": which counts? Not verifiable. | Row keeps only `place in the image only bytes of data records`; ranges and overlaps follow from the definitions in CTX-IMAGE. |
| R-LOG-001 | "the diagnostic count": the log's `errors=` counts diagnostics **and** integrity notices, and the two formats log different fields. | Two rows with the exact log text (Q-G). |
| R-CLI-005 | `--output` exists only for `dump-by-range`, not for `dump` or `dump-all`. The "`.` for an unprintable byte" rule is false for bytes 0x80–0xFF: the code prints `�`. | Split per command; the 0x80–0xFF case marked "Partly". |
| R-CLI-003 | The `Endian:` line has no stated rule, so it cannot be verified (an S19 file carries no byte order; the value is a guess). | Row kept, Q-F asks whether to drop the line. |
| R-CLI-007 | "`Error: <reason>`": reason not given, not verifiable. | One row per refusal with its exact reason. |
| R-CLI-001 | "read no file": `version` takes no file argument. Not necessary (29148). | Dropped. |
| R-VAL-001a/b, R-HEX-007a | `While a data record is invalid`: a record being invalid is not a state of the system (E4). | `If a data record is invalid, then …` |

Context notes that carried behaviour (E6):
- CTX-S19: "Files are written in uppercase; a reader takes a–f as the same digits" → rows R-PARSE-006 and R-CLI-008.3.
- CTX-LOAD: "Lines after it are not records" → R-READ-007.1. The list of integrity-notice codes → the codes live only in rows R-READ-005 … 008.
- CTX-CLI: "Addresses: printed as …", "Ranges: printed by …" → restated as format terms (`hex address`, `range line`) that rows use.

Context notes that were incomplete:
- CTX-LOAD "A load gives" omitted the ranges, overlap addresses and out-of-order records that rows report. Now `load result` lists them.
- CTX-LOAD "diagnostic … the stage that failed": no row says which stage each defect has, so that part of the definition is never verifiable (Q-A).

---

## 3. The chapter, rewritten

Form column: U = ubiquitous, When, While, If, Where. "Code today" is from reading the code unless it says tested.

### S1.1 · Reading a file

```text
CTX-LOAD  Loading a file
  line              One physical line of the file, without the whitespace around it.
  empty line        A line with no characters left.
  line number       The position of a line in the file, from 1. Empty lines count.
  record            A line parsed into type, count, address, data and checksum.
  end of reading    S19: the first S7, S8 or S9 record (the terminator).
                    Intel HEX: the first type-01 record (the EOF record).
  trailing line     A line that is not empty and comes after the end of reading.
  valid text        A line whose bytes are valid UTF-8 (D-3).
  load result       What a load gives its caller: the records, the image (CTX-IMAGE),
                    the ranges, the overlap addresses, the diagnostics, the integrity
                    notices and, for S19, the out-of-order records.
  diagnostic        A finding about one line: its line number, the line text and a
                    message.
  integrity notice  A finding about the whole file: a code and a message, no line number.
  line defect       A reason to reject a line. L-1 applies to both formats; CTX-S19 and
                    CTX-HEX list the rest. All are checked in order: L-1 first.
    L-1  the line is not valid text.
  reject the line   No record is created from the line, and none of its bytes enter
                    the image.
```

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-READ-001.1 | When | When the system reads an empty line, the system shall create no record from it. | Does it; tested. |
| R-READ-001.2 | When | When the system reads an empty line, the system shall record no diagnostic for it. | Does it; tested. |
| R-READ-002 | U | The system shall treat CR, LF and CR LF as line ends. | Does it; tested for HEX, read from the code for S19. |
| R-VAL-002.1 | If | If a line before the end of reading has a line defect, then the system shall reject the line. | Does it for S19 and HEX, except L-1 in S19: code changes (D-3). |
| R-VAL-002.2 | If | If a line before the end of reading has one or more line defects, then the system shall record exactly one diagnostic for it. | Does it; tested. |
| R-VAL-002.3 | If | If a line has more than one line defect, then the system shall give its diagnostic the message of the first defect in check order. | Does it for S19; HEX after Q-C. |
| R-VAL-002.4 | If | If a line has a line defect, then the system shall read the line that follows it. | Partly: L-1 stops an S19 load today; code changes (D-3). |
| R-READ-003 | If | If a line has defect L-1, then the system shall record the diagnostic `Invalid UTF-8: not valid UTF-8 text`. | HEX yes; S19 no: code changes (D-3). |
| R-READ-004.1 | If | If the file to load does not exist, then the system shall end the load with a file-not-found error. | Does it; tested. |
| R-READ-004.2 | If | If the file to load does not exist, then the system shall give no load result. | Does it; tested. |
| R-READ-005 | If | If an S19 file has no terminator, then the system shall attach the integrity notice `S19-NO-TERMINATOR`. | Does it; tested (batch-99). From HLR-154 (decision 10). |
| R-READ-006.1 | If | If the data-record tally of an S19 file is at most 0xFFFF and differs from the count in its S5 record, then the system shall attach the integrity notice `S19-COUNT-MISMATCH`. | Does it; tested (batch-99). From LLR-154.1 (decision 10). |
| R-READ-006.2 | If | If the data-record tally of an S19 file is at most 0xFFFFFF and differs from the count in its S6 record, then the system shall attach the integrity notice `S19-COUNT-MISMATCH`. | Does it (read from the code). From LLR-154.1 (decision 10). |
| R-READ-006.3 | If | If an S19 file holds more than one S5 record or more than one S6 record, then the system shall compare the data-record tally with the count in the last record of that type. | Does it (read from the code). New (Q-H). |
| R-READ-007.1 | If | If a file has trailing lines, then the system shall create no record from them. | Does it; tested (batch-99). |
| R-READ-007.2 | If | If a file has trailing lines, then the system shall record no diagnostic for them. | Does it; tested (batch-99). |
| R-READ-007.3 | If | If an S19 file has trailing lines, then the system shall attach the integrity notice `S19-AFTER-TERMINATOR`. | Does it; tested (batch-99). |
| R-READ-007.4 | If | If an Intel HEX file has trailing lines, then the system shall attach the integrity notice `HEX-AFTER-EOF`. | Does it; tested (batch-99). |
| R-READ-007.5 | If | If a file has trailing lines, then the system shall state their number in its after-the-end integrity notice. | Does it; tested (batch-99). |
| R-READ-008 | If | If an Intel HEX file has no EOF record, then the system shall attach the integrity notice `HEX-NO-EOF`. | Does it; tested (batch-99). From LLR-154.2 (decision 10). |
| R-LOG-001.1 | When | When the load of an S19 file ends, the system shall write the INFO log line `S19 load summary: path=<path> records=<n> errors=<e> validation_errors=<v> parse_errors=<p>`. | Does it; tested. `<e>` counts diagnostics and integrity notices together (Q-G). |
| R-LOG-001.2 | When | When the load of an Intel HEX file ends, the system shall write the INFO log line `HEX load summary: path=<path> records=<n> addresses=<a> errors=<e>`. | Does it; tested. Same as the row above (Q-G). |

### S1.2 · S19 records

```text
CTX-S19  Motorola S-record (S19)
  A line:  S | type (1 digit) | count (2) | address (4, 6 or 8) | data | checksum (2)
  hexadecimal     The characters 0-9, A-F and a-f, in a fixed-width field, with no
                  prefix, sign, space or separator (decision 1).
  count           The number of bytes in address + data + checksum.
  length          4 + 2 × count characters.
  checksum rule   The checksum is the ones' complement of the low byte of the sum of
                  the count, address and data bytes.
  Types:   S0 header (2 address bytes) · S1/S2/S3 data (2/3/4) · S4 not used ·
           S5/S6 record count, held in the address field (2/3) ·
           S7/S8/S9 terminator (4/3/2).
  data record     An S1, S2 or S3 record.
  data-record tally  The number of data records, plus the rejected lines before the
                  terminator that start with S1, S2 or S3.
  invalid record  A record that does not follow the checksum rule. It is not rejected.
  Line defects, in check order (after L-1):
    S-1  the line does not start with S, or has fewer than 4 characters.
    S-2  the type is not one of S0, S1, S2, S3, S5, S6, S7, S8, S9.
    S-3  the count is not hexadecimal.
    S-4  the length differs from the length the count gives.
    S-5  the count is less than the address bytes of the type + 1.
    S-6  the address is not hexadecimal.
    S-7  a data byte is not hexadecimal.
    S-8  the checksum is not hexadecimal.
  Example: S313000020001011012C000200010F00000000323A
```

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-PARSE-001 | If | If an S19 line has defect S-1, then the system shall record the diagnostic `Invalid S-record format: <line>`. | Does it; tested. |
| R-PARSE-001b | If | If an S19 line has defect S-2, then the system shall record the diagnostic `Unsupported S-record type: <type>`. | Does it; tested. |
| R-PARSE-002 | If | If an S19 line has defect S-3, then the system shall record the diagnostic `Invalid byte count hex: <count>`. | Partly: a sign, a space, `0x`, `_` pass today (decision 1). |
| R-PARSE-002a | If | If an S19 line has defect S-4, then the system shall record the diagnostic `Length mismatch: expected <n> chars, found <m>`. | Does it; tested. |
| R-PARSE-003a | If | If an S19 line has defect S-5, then the system shall record the diagnostic `Line too short for address field`. | Does it (read from the code); untested. |
| R-PARSE-003 | If | If an S19 line has defect S-6, then the system shall record the diagnostic `Invalid address hex: <address>`. | Partly, as R-PARSE-002 (decision 1). |
| R-PARSE-004 | If | If an S19 line has defect S-7, then the system shall record the diagnostic `Invalid data byte hex: <xx>` for the first such byte. | Partly, as R-PARSE-002 (decision 1). |
| R-PARSE-005 | If | If an S19 line has defect S-8, then the system shall record the diagnostic `Invalid checksum hex: <xx>`. | Partly, as R-PARSE-002 (decision 1). |
| R-PARSE-006 | U | The system shall read the hexadecimal digits a–f as the same values as A–F. | Does it (decision 1). |
| R-VAL-001.1 | If | If an S19 record does not follow the checksum rule, then the system shall mark the record invalid. | Does it; tested. |
| R-VAL-001.2 | If | If an S19 record does not follow the checksum rule, then the system shall record the diagnostic `Checksum mismatch: expected <XX>, found <YY>`. | Does it; tested. |

### S1.3 · Intel HEX records

```text
CTX-HEX  Intel HEX
  A line:  : | count (2) | offset (4) | type (2) | data (2 × count) | checksum (2)
  hexadecimal     As CTX-S19.
  length          11 + 2 × count characters.
  checksum rule   The sum of all bytes after the colon, checksum included, is 0
                  modulo 256.
  Types:   00 data · 01 end of file · 02 extended segment address ·
           03 start segment address · 04 extended linear address ·
           05 start linear address.
  data record          A type-00 record.
  address-base record  A type-02 or type-04 record.
  segment base    The 2 data bytes of a type-02 record, read as one number, × 16.
  linear base     The 2 data bytes of a type-04 record, read as one number, × 0x10000.
  invalid record  A record that does not follow the checksum rule. It is not rejected.
  Line defects, in check order (after L-1):
    H-1  the line does not start with ':'.
    H-2  the line has fewer than 11 characters.
    H-3  the count is not hexadecimal.
    H-4  the length differs from the length the count gives.
    H-5  the offset is not hexadecimal.
    H-6  the type is not hexadecimal.
    H-7  the type is not one this note lists (Q-D).
    H-8  a data byte is not hexadecimal.
    H-9  the checksum is not hexadecimal.
  Example: :080200009D187F5FB9B8019061
```

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-HEX-004 | If | If an Intel HEX line has defect H-1, then the system shall record the diagnostic `Missing ':' prefix`. | Does it; tested. |
| R-HEX-005.1 | If | If an Intel HEX line has defect H-2, then the system shall record the diagnostic `Line too short: <n> chars`. | No: Python's raw text (Q-C). |
| R-HEX-005.2 | If | If an Intel HEX line has defect H-3, then the system shall record the diagnostic `Invalid byte count hex: <xx>`. | No: Python's raw text (Q-C, decision 1). |
| R-HEX-006 | If | If an Intel HEX line has defect H-4, then the system shall record the diagnostic `Length mismatch: expected <n>, found <m>`. | Partly: only when every field parses; a short line gives Python's text (Q-C). |
| R-HEX-005.3 | If | If an Intel HEX line has defect H-5, then the system shall record the diagnostic `Invalid address hex: <xxxx>`. | No: Python's raw text (Q-C, decision 1). |
| R-HEX-005.4 | If | If an Intel HEX line has defect H-6, then the system shall record the diagnostic `Invalid record type hex: <xx>`. | No: Python's raw text (Q-C, decision 1). |
| R-HEX-005.5 | If | If an Intel HEX line has defect H-8, then the system shall record the diagnostic `Invalid data byte hex: <xx>` for the first such byte. | No: Python's raw text (Q-C, decision 1). |
| R-HEX-005.6 | If | If an Intel HEX line has defect H-9, then the system shall record the diagnostic `Invalid checksum hex: <xx>`. | No: Python's raw text (Q-C, decision 1). |
| R-HEX-007.1 | If | If an Intel HEX record does not follow the checksum rule, then the system shall mark the record invalid. | Does it; tested. |
| R-HEX-007.2 | If | If an Intel HEX record does not follow the checksum rule, then the system shall record the diagnostic `Checksum mismatch`. | Does it; tested. |
| R-HEX-008 | If | If an Intel HEX line has defect H-7, then the system shall record the diagnostic `Unsupported record type: <XX>`. | Message: does it; tested. Rejection: no, the record is kept today (Q-D). |
| R-HEX-009 | While | While no address-base record has been applied, the system shall place each data byte at the record offset + the byte index. | Does it; tested. |
| R-HEX-001 | While | While the most recently applied address-base record is type 04, the system shall place each data byte at the linear base + the record offset + the byte index. | Does it; tested. |
| R-HEX-001a.1 | If | If a type-04 record does not hold exactly 2 data bytes, then the system shall keep the current address base. | Does it; tested. |
| R-HEX-001a.2 | If | If a type-04 record does not hold exactly 2 data bytes, then the system shall record the diagnostic `Invalid extended linear address record length`. | Does it; tested. |
| R-HEX-002 | While | While the most recently applied address-base record is type 02, the system shall place each data byte at the segment base + ((the record offset + the byte index) mod 0x10000). | Partly: no wrap at 64 KiB (decision 4). |
| R-HEX-002a.1 | If | If a type-02 record does not hold exactly 2 data bytes, then the system shall keep the current address base. | Does it; tested. |
| R-HEX-002a.2 | If | If a type-02 record does not hold exactly 2 data bytes, then the system shall record the diagnostic `Invalid extended segment address record length`. | Does it; tested. |
| R-HEX-003.1 | When | When the system reads a type-03 or type-05 record, the system shall add no byte to the image. | Does it; tested. |
| R-HEX-003.2 | When | When the system reads a type-03 or type-05 record, the system shall keep the current address base. | Does it; tested. |
| R-HEX-003.3 | When | When the system reads a type-03 or type-05 record that follows the checksum rule, the system shall record no diagnostic for it. | Does it; tested. |

### S1.4 · The memory image

```text
CTX-IMAGE  The memory image
  image             The address → byte pairs a load builds.
  range             A maximal run of consecutive image addresses. Its start is
                    included; its end (one past the last byte) is not.
  gap               The addresses between two consecutive ranges.
  overlap address   An address that more than one data record writes.
  out-of-order record  A data record whose start address is lower than the start
                    address of the data record before it.
  span              A start address and a length.
```

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-IMG-006 | U | The system shall place in the image only bytes of data records. | Does it; tested (batch-99). From HLR-153 (decision 10). |
| R-IMG-001 | If | If more than one data record writes an address, then the system shall keep in the image the byte of the data record that comes last in the file. | Does it; no S1 test pins it. |
| R-IMG-002.1 | If | If a file has overlap addresses, then the system shall include each one in the load result. | S19: does it; tested. HEX: no, code changes (Q-E). |
| R-IMG-002.2 | If | If a file has overlap addresses, then the system shall list them in ascending order. | S19: does it; tested. HEX: as above. |
| R-IMG-003 | If | If an S19 file has an out-of-order record, then the system shall include in the load result its line number, its start address and the start address of the data record before it. | Partly: the "line number" is the record position today; code changes (D-5). S19 only (Q-E). |
| R-IMG-004.1 | When | When a load ends, the system shall include the ranges of the image in the load result. | Does it; tested. |
| R-IMG-004.2 | When | When a load ends, the system shall list the ranges in ascending order of start address. | Does it; tested. |
| R-IMG-005.1 | When | When a caller asks whether a span that one range holds whole lies in the image, the system shall answer yes. | Does it; tested. |
| R-IMG-005.2 | When | When a caller asks whether a span that no single range holds whole lies in the image, the system shall answer no. | Does it; tested. |
| R-IMG-005.3 | If | If a caller asks whether a span of length 0 or less lies in the image, then the system shall answer no. | Does it; tested. |
| R-VAL-001a | If | If a data record is invalid, then the system shall place its data bytes in the image. | Does it (decision 2). |
| R-VAL-001b | If | If a data record is invalid, then the system shall mark as invalid each range that holds its bytes. | Does it; computed in the display code (decisions 2, 9). |
| R-HEX-007a | If | If an Intel HEX address-base record is invalid, then the system shall apply its address base. | Does it (decision 2). |

### S1.5 · Text from a file, on screen

```text
CTX-TEXT  Text from a file, on screen
  file-derived text  Any text the system takes from a loaded or imported file:
                     symbol names, issue codes and messages, file names, region labels.
  control character  U+0000-U+001F (C0), U+007F (DEL), U+0080-U+009F (C1).
  break character    Tab (U+0009), line feed (U+000A), carriage return (U+000D).
                     They are control characters too.
  markup             Square-bracket text that the screen library could read as a
                     style or a link, for example [red].
  safe-text views    The Memory Map, the Issues view, the Checks view, the Flow screens,
                     the Split/Join view (D-7), the A2L Explorer (table and detail
                     card), the MAC View (added from S2, tested there), the
                     Workarea Files list and the status line (added from S5), the
                     message lines (S6), the Select variant, Save project and
                     Reports dialog lists (S7, S11), the Reports
                     dialog's report view with its Markdown structure kept (S12),
                     the verify-mismatch notice (S8), the Patch Editor and its
                     Checks tab, the Check Editor (S9, S10), the CRC Designer and
                     the Operations dialog result area (S13), the A2B Diff (S14);
                     from batch-100: the Load dialog (S7), the load question (S5),
                     the Load-result panel (S11), the progress line, the busy line
                     and the quit question (S6).
  painted name       A file or project name with every character of Unicode
                     category Cc, Cf, Zl or Zp removed, every unpaired surrogate
                     shown as U+FFFD, and cut to 120 characters ending in "…"
                     (as S7 CTX-LOADDLG defines it).
  painted-name views The safe-text views and lines whose group rows show a name
                     as its painted name: the Workarea Files list and the load
                     question (S5), the progress line, the busy line and the
                     quit question (S6), the Load dialog (S7), the Save project
                     dialog, the Load-result panel and the project-load status
                     lines (S11). The file status after a file load is not one
                     (D-16).
```

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-103.1 | When | When the system displays file-derived text other than a painted name in one of the safe-text views, the system shall show each run of break characters as one space. | No: removes them today; code and one test change (D-6). A painted name removes them (D-16). |
| R-TUI-103 | When | When the system displays file-derived text in one of the safe-text views, the system shall display no other control character. | Does it where the safe-text function is used (D-7). The status line and the message lines: every line passes it since batch-100 Inc 12a (`app.py:20161-20175`, `:20192-20211`; tested, `test_tc_b100_50_control_bytes_never_reach_the_status_log`; S6 D6-28 done). Painted names: tested in their groups (`test_tc_b100_42_project_rows_are_painted_literally`, `test_tc_b100_53_busy_line_paints_a_hostile_name_literally`). |
| R-TUI-103a | When | When the system displays file-derived text other than a painted name in one of the safe-text views, the system shall display every other character unchanged and in the same order. | Does it; tested. A painted name removes Cf, Zl and Zp characters and cuts at 120 characters (D-16). |
| R-TUI-103b | When | When the system displays file-derived text in one of the safe-text views, the system shall apply no markup that the text spells out. | Partly: the Select variant dialog (title and list) and the Reports dialog list still read markup (S7 D7-28, S11 D11-38); elsewhere tested. Example `sensor[red]` shows as the 11 characters `sensor[red]`. |

### S1.6 · Version

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-VER-001 | When | When the system reports its version, the system shall report the version declared in the package metadata. | Partly: the version is written in two files; code changes to one source (D-14). |

The command-line tool (`python -m s19_app.cli`) is removed (D-11): its 59 strict rows, CTX-CLI, D-12, D-13 and Q-F go with it. The rows stay in revision 1 of this file (`review/archive/S1-ears-strict.rev1.md`) if the decision is reversed.

---

## 4. Decisions: recommendation applied

Every open point now carries a recommendation, and the rows above already follow it. "Code changes" means a backlog item for the s19 batch that takes this chapter in. D-n is decision n of the old part 67; Q-x came from this pass. D-1 (what counts as hexadecimal) was decided on 2026-10-29.

| # | The situation | Recommendation (applied) | What changes |
|---|---|---|---|
| D-2 | A record with a wrong checksum: today its bytes stay in the image and its range is shown invalid. | **Keep as today.** The operator sees the data and the warning; refusing would hide what is in the file. Whether export or patching should stop on such a range is for S8/S17, not S1. | Nothing. |
| D-3 + Q-B | A byte the S19 reader cannot decode stops the whole load; the HEX reader rejects only that line. "Valid text" for S19 depends on the machine's character set (cp1252 on Windows). | **Like HEX: valid text = UTF-8; reject the line and keep reading.** Both readers behave the same and the result no longer depends on the machine. | Small code change in the S19 reader, one test. |
| D-4 | Intel HEX segment mode (type 02): a record that runs past offset 0xFFFF lands 64 KiB higher instead of wrapping. | **Wrap, as the Intel HEX standard says.** The project's own sample file already expects the wrap; it becomes the test. | Small code change, test from the sample file. |
| D-5 | Out-of-order findings say "line N", but N is the record's position, wrong after any blank or rejected line. | **Physical line number**, as for every other finding. | Small code change, one test with a blank line. |
| D-6 | Tab or line break in a symbol name or message: the screen removes it, so `a⏎b` shows as `ab`. | **Show each run of tab / line breaks as one space.** Words stay apart and the layout still never breaks. | Small code change; the test that pins removal changes. |
| D-7 | The safe-display rule binds one function; ~150 places call it; nobody knows whether a screen shows file text without it. | **The named views now, plus a backlog item to sweep the other screens** (the sweep is S4's review). The S2 review added the A2L Explorer and the MAC View, which already meet the rule. | Backlog item only. |
| D-8 | Two checks can never fire (data length vs count; the count re-check): earlier checks always catch the case first. | **Remove them from the requirements and from the code.** Rule use/defer/delete: code that never runs is deleted. | ~10 lines removed, no behaviour change. |
| D-9 | "A range holding a bad-checksum record is shown invalid" is S1 behaviour computed by S4 display code. | **A row lives with the behaviour (S1), with a pointer in S4.** Requirements are grouped by what the system does, not by which file does it; the same rule holds for every later group. | Pointer in S4. |
| D-10 | S1 rules (image holds only data records; end-record notices) sat in S0's table. | **Moved into S1** (R-IMG-006, R-READ-005 … 008), pointers left in S0. HLR-153's second sentence (how an image is *written*) goes to the S8/S17 review. | Done in the rows. |
| D-11 | The command-line tool: runnable only as `python -m s19_app.cli`, 6 known defects, 2 of 15 behaviours tested. The README already says "the surface is going away … not being fixed". | **Remove it.** It would cost 59 rows and 6 fixes for a surface the project already dropped. D-12, D-13 and Q-F disappear with it. | One removal item (cli.py, its tests, the README section). |
| D-14 | The version is written twice (pyproject.toml and s19_app/version.py), both 0.1.0, nothing checks they agree. Reports print it. | **One source:** `version.py` keeps it; pyproject reads it (`dynamic = ["version"]`). | Two-line change in pyproject.toml. |
| D-15 | Three helper functions nothing uses; source comments carry batch history and requirement ids. | **Remove the helpers. Keep the requirement ids in comments** (code → requirement trace is mandatory); drop batch narrative only when a file is touched anyway. | Backlog item. |
| D-16 | Conflict (batch-100, s19_app 570b4b5). R-TUI-103.1 and 103a (break characters as one space; every other character unchanged, D-6) against batch-100's painted names (LLR-173.3 … .3c, LLR-174.2i, LLR-176.1r, LLR-177.4a; `painted_names`, `project_gather_service.py:967-1009`): every Cc, Cf, Zl and Zp character is removed and a name is cut at 120 characters with "…". The Load dialog, the load question, the Save project dialog, the Load-result panel, the progress and busy lines and the quit question show names this way; the file status after a file load (`Loaded <name> (S19 only)` …, `app.py:17775-17792`) passes only the safe-text function and keeps format characters such as U+202E (batch backlog SE5-12a-2, open). The Load project dialog of this list is gone (Inc 9b). | **Batch-100 wins for painted names** (more recent, tested, and removing a bidi override is the safer rule; S7 D7-12). CTX-TEXT defines "painted name" and the painted-name views; R-TUI-103.1 and 103a leave painted names out; R-TUI-103 and 103b hold for them. "Load project" leaves the safe-text list; the batch-100 views join it. | Nothing in the code. The file status's format characters stay with the batch backlog (SE5-12a-2). |
| Q-A | The old note said a diagnostic carries "the stage that failed". The stage is shown only in a log warning, never on screen. | **Drop it from the definition.** The message already names the problem. | Nothing in the code. |
| Q-C | A bad Intel HEX field gives Python's raw text (`invalid literal for int() with base 16: ''`), and a short line never reaches the length check. | **Same per-field wording as S19, and the length check before the field checks.** Messages become testable and both formats read alike. | Code change in the HEX reader, tests per message. |
| Q-D | Unknown record type: S19 rejects the line; Intel HEX keeps a record with no bytes. | **Reject in both** (new HEX defect H-7). Same input defect, same outcome. | Small code change. |
| Q-E | Only S19 reports overlap addresses; two Intel HEX records writing the same address overwrite each other silently. | **Report overlaps for Intel HEX too** (silent overwrite can hide data). Out-of-order stays S19-only: the order of records changes nothing in the image. | Code change in the HEX reader; the screen shows the count where it shows S19's. |
| Q-G | The load summary log line counts diagnostics and integrity notices together in `errors=`. | **Keep the log text as is.** The rows say exactly what `errors=` counts; tests already pin it. | Nothing. |
| Q-H | With two S5 (or S6) records, the code compares with the last one; no row said so. | **State it** (R-READ-006.3). | Nothing in the code. |

Code-change items for the batch: D-3, D-4, D-5, D-6, D-8, D-11, D-14, Q-C, Q-D, Q-E. Backlog only: D-7, D-15.

---

**Received from later groups** (after S6–S17 were written)

- **Safe-text views**: S6, S7, S8, S9, S10, S11, S12, S13 and S14 each named views that show file-derived text; all are now in CTX-TEXT, so R-TUI-103, 103.1, 103a and 103b cover them. S16: the Flow windows were already listed. S17: the Split/Join view is listed, but its table, naming line and output labels skip the safe-text function today (S17 D17-21); the D-7 sweep covers it.
- **D-2 answered downstream**: save-back writes the bytes of a bad-checksum record and warns (S8 D8-26); the export does the same (S17 D17-34). S1 stays "keep as today".

**Reconciled with batch-100 (s19_app 570b4b5)**

- CTX-TEXT: "Load project" left the safe-text views (dialog retired, Inc 9b; S7 D7-12); the Load dialog, the load question, the Load-result panel, the progress line, the busy line and the quit question joined them (from S5, S6, S7, S11 and the sweep).
- CTX-TEXT: terms "painted name" and "painted-name views" added (from S5, S6, S7, S11).
- Rows changed in text: R-TUI-103.1, R-TUI-103a leave painted names out (D-16; batch-100 wins, S7 D7-12).
- "Code today" changed: R-TUI-103 (status line and message lines scrubbed since Inc 12a, S6 D6-28 done); R-TUI-103b Yes → Partly (Select variant and Reports lists still read markup, S7 D7-28, S11 D11-38).
- Decision added: D-16 (conflict). Superseded: none (D-6 stands for text that is not a painted name). Open and not ours: the file status keeps format characters (SE5-12a-2).

## 5. Counts

| | Proposal (part 67 B) | Strict |
|---|---:|---:|
| Rows | 55 | 72 (126 with the command-line tool) |
| Rows with more than one response or sentence (E2) | 35 (28 by script, 7 by reading) | 0 |
| Rows with "it" as subject (E1) | 9 | 0 |
| Rows with the wrong pattern (E4) | 9 | 0 |
| Findings that did not make sense (section 2 table) | 13 | 0 |
| Context-note sentences that carried behaviour (E6) | 5 | 0 |
| Rows by form: U / When / While / If / Where | — | 3 / 16 / 3 / 50 / 0 |
| Rows that could not be written in EARS | — | 0 |

Checked by script on the strict table: every row has exactly one `shall`, starts with its form's opening words, every `If` row has `, then the system shall`, and every row's subject is "the system".
