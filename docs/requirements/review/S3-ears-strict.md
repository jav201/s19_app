# S3 — Validation, issues & legend: context notes and strict EARS rows (2026-10-30)

Input: `REQUIREMENTS.by-module.md` chapter S3 (lines 918–1319): 3 unnumbered policy blocks (A2L row colours, MAC row colours, Issues severity policy), 2 colour amendments (C, F), and 10 rows (R-TUI-025, R-TUI-042, R-ISSUES-HEXPANE-001, R-ISSUES-RELATED-001, R-LEGEND-SOURCE-001, R-LEGEND-MODAL-001, R-LEGEND-GEOMETRY-001, R-A2L-ISSUE-RECONCILE-001, R-TUI-047, R-TUI-055).
Code: `s19_app/validation/` (engine, rules, model), `tui/services/validation_service.py`, `tui/issues_view.py`, `tui/legend.py`, `tui/color_policy.py`, `tui/screens.py::LegendScreen`, the S3 functions of `app.py`. Two read-only code readings gave every fact with `file:line`; I re-checked the one with the most impact myself (D3-9). No test was run.
Reconciled with s19_app 570b4b5 (batch-100) on 2026-11-01: the "Code today" cell of R-LEGEND-010 (the Load-result panel) verified at 570b4b5; other cites refer to 093a7c0.

Result:
- **Context notes first** (section 3): CTX-ISSUE, CTX-ISSUES-SCREEN, CTX-LEGEND.
- **Rows** (section 4): every row in one of the five EARS forms, one `shall`; none needed another form; none uses `Where`. Counts in section 6.
- **Decisions** (section 5): 25, each with a recommendation already applied. Mark only what you object to.
- Rules E1–E7: `review/S1-ears-strict.md` section 1.

---

## 1. How S3 was written before

- **Three policy blocks** list what each colour or severity "shall" cover (A2L Red/Green/White/Grey, MAC Red/Yellow/Green/White/Grey, Issues Errors/Warnings/Optional info). No ids; they describe intentions, several of which the code never built.
- **Two amendments** (C, F) record a palette change with before/after hex values and the reasoning of batch-47.
- **Ten rows**, most of them a paragraph each with function names, CSS rules, measurements and amendment history (R-TUI-042 alone is ~100 lines).

## 2. What did not make sense

| Where | What did not make sense | Fix |
|---|---|---|
| Issues policy, "Optional info" | Three INFO categories (valid but not image-backed, not checked without a primary image, virtual objects). **None exists**: no producer emits them. | Removed from the requirements (D3-6). INFO gets one real meaning (D3-5). |
| Issues policy, "Errors" | Lists empty MAC name, invalid MAC address, invalid A2L address field type. The codes exist but can never fire: the parsers reject those cases earlier, as MAC parse errors. | Unreachable codes removed (D3-4). |
| Issues policy, "Errors" | Lists broken GROUP/FUNCTION references as an error; the code raises a WARNING, and only for the one-line form. The standard `/begin REF_CHARACTERISTIC` block form is never checked. | WARNING, both forms (R-VAL-033, D3-13). |
| Issues policy, "Warnings" | "duplicate-address alias when policy emits warning": there is no policy setting; the parameter is never passed, and its documented value `error` does nothing. | Fixed severities per kind of shared address (R-VAL-022 … 024, D3-5). |
| Issues policy, "Warnings" | "symbol-only-in-A2L". In the most common session (S19/HEX + A2L, no MAC) **every** tag with an address gets `A2L symbol '<x>' missing from MAC.`; with S19 + MAC and no A2L, every MAC record gets the mirror warning. | Only when the other file is loaded (R-VAL-045, 046, D3-9). |
| Whole chapter | A2L structure checks (parse errors, duplicates, unknown blocks, broken references) run **only when an S19/HEX is loaded**. An A2L loaded alone, or with a MAC only, reports nothing. | Whenever an A2L is loaded (R-VAL-030, D3-10). |
| MAC row policy | "Yellow `#f6ff8f`" for warning rows. The MAC table paints them `orange3`. The legend says "Pale yellow". The A2L and MAC tables use terminal colours (`red`, `green`, `grey70`), not the legend's palette (`#fd8383`, `#54efae`, `#969aad`). | One palette for every surface (CTX-LEGEND, D3-18). |
| Legend content | The MAC "Pale yellow" row says "duplicate-address alias, overlap ambiguity"; those never colour a MAC row (the row colour comes from the record's status). The A2L "Red" row says "malformed required field, hard-error duplicate"; a row is red when an ERROR issue names it or it has no address. | Legend rows rewritten from what each screen does (D3-19). |
| R-TUI-025 | "preserving … row-level jump-to-source". The jump code exists but nothing calls it since batch-29; selecting an issue only fills the hex peek. | Rows state the peek; the dead code goes (D3-7). |
| R-TUI-042 | Three unrelated features in one row: A2L table density (S2), the grouped Issues view (S3), Workspace coverage signals (S5). | Split by owner (D3-2). |
| R-LEGEND-SOURCE-001 | "shall be defined in `legend.py` … shall NOT be added to `color_policy.py`": a file-placement rule (keep a frozen file untouched), not behaviour. | Row: the window and the report show the same rows; the placement rule goes to the design notes (D3-3). |
| R-LEGEND-GEOMETRY-001 | Measurements in columns per button, CSS values, focus-chain history. | Rows the operator can check: buttons visible at 80 and 120 columns, window inside the screen, key reachable. |
| R-A2L-ISSUE-RECONCILE-001 | One row with the producer, its dedup key, both merge points, the MAC-view cache key and `id(current_file)`. | Two rows (R-VAL-035, R-VAL-014); the cache mechanics are design. |
| R-TUI-055 | Producer name, file line, merge branches inside the row. | One row (R-VAL-036). |

Counts for the old text: 3 policy blocks with no id; 10 rows, all with more than one response or with implementation names; 9 statements the code contradicts or never built (3 INFO categories, 3 unreachable error codes, the alias policy, the reference severity, the warning colour).

---

## 3. Context notes (informative)

### CTX-ISSUE · Validation issues (S3.1, S3.2)

```text
issue           A finding the system reports about the loaded files: a code, a severity,
                a message, an artifact, and when known a symbol, an address, a line
                number and related artifacts.
severity        ERROR (data wrong or unusable) · WARNING (something to check) ·
                INFO (expected, shown for completeness).
artifact        The file kind the issue is about: a2l, mac, s19, hex, or cross (a
                disagreement between files).
symbol          The tag or MAC name the issue is about.
issue list      All issues of the current session, after duplicates are dropped.
same issue      Two issues equal in code, severity, message, artifact, symbol, address
                and line number.
session         primary session: an S19 or Intel HEX file is loaded (the primary image,
                S2 CTX-A2L-CHECK). MAC-only session: a MAC file and no primary image.
                A2L-only session: an A2L file and neither of the others.
shared address  A MAC address that two or more valid MAC records name. Its kind:
  hard conflict      a name of the group is defined twice in the MAC file, or the A2L
                     puts one of the group's names at a different address
  segment ambiguity  the address is an overlap address of the primary image (S1)
  bit-field sharing  a name contains bit, flag, _b, .b or mask
  alias candidate    any other shared address
coverage        MAC→S19 = MAC records in the image / valid MAC records.
                A2L→S19 = checked tags in image / checked tags.
                A2L↔MAC = A2L↔MAC matches (S2 CTX-MAC) / names in both files.
```

### CTX-ISSUES-SCREEN · The Issues screen (S3.3)

```text
Issues screen   Title "Issues Report"; a button row (Issues: All, Errors, Warnings,
                Legend); the severity strip; the issue list (left) beside the hex peek
                (right); the summary line.
severity strip  Errors <E> <bar>  Warnings <W> <bar>  Info <I> <bar>
                Each bar is 5 cells; filled cells = round(count / total × 5).
summary line    total=<T> | errors=<E> | warnings=<W> | info=<I> | filter=<all|error|warning>
                | page <p>/<P> rows <a>-<b>/<F>
group header    ✗ ERRORS  (<n>) · ⚠ WARNINGS  (<n>) · • INFO  (<n>)   (two spaces)
issue row       code chip (the code, or -) · detail (<symbol or ->  <address or no-addr>
                <message>, two spaces apart) · related (the related artifacts joined by
                ", ", or -)
filter mode     all · error (ERROR issues) · warning (WARNING issues).
issue page      40 consecutive issues of the filtered list.
hex peek        The bytes around the selected issue's address: its 16-byte row, the 6
                rows before and the 6 rows after.
```

### CTX-LEGEND · Colours and the legend (S3.4)

```text
palette         The colours every colour-coded surface uses:
  Red          #fd8383   error · needs attention
  Pale yellow  #f6ff8f   warning
  Cyan         #7dd3fc   info
  Green        #54efae   ok · verified
  Grey         #969aad   not checked
  White        the default text colour: valid, nothing to report
  Yellow       bold yellow   the search / go-to focus in a hex view
  Orange       orange3       MAC-specific cue: the ⚠ glyph and the MAC address mark
                             in a hex view
legend          The table that explains each colour, per block:
  A2L
    Red          An ERROR issue names the tag, or the tag has no address and is not
                 virtual.
    Green        In image: every byte of the tag is in the loaded S19/HEX.
    White        Out of image, or computed (virtual, or with a conversion method).
    Grey         Not checked: no S19/HEX loaded, or the tag has no address or length.
  MAC
    Red          The line does not parse, or its address differs from the A2L tag of
                 the same name.
    Pale yellow  No A2L tag has this name.
    White        The address is not in the loaded S19/HEX.
    Grey         No A2L file is loaded.
    Green        An A2L tag has the same name and the same address.
    Orange ⚠     The address is not in the loaded S19/HEX (status glyph).
  Issues
    Errors       Data wrong or unusable: parse errors, rejected lines, file integrity
                 notices, duplicate names, A2L↔MAC address mismatch, hard address
                 conflicts, tags with no address.
    Warnings     Something to check: addresses out of the image or overlapped, names in
                 one file only, alias or ambiguous shared addresses, unknown blocks,
                 broken references, addresses over 32 bits, unknown byte order.
    Info         Expected, shown for completeness: MAC names that share an address as
                 bit fields.
  Hex
    Yellow       Search / go-to focus.
    Orange       MAC address.
legend window   A window with the title "Classification legend": a card pane (sample
                lines of the current screen, annotated) and a key pane (the legend
                blocks for the current screen). On the Memory Map: the map sheet in
                place of both panes.
map sheet       Four boxes in one column, each a title and its lines:
  Entropy bands — <window size> B windows, bits/byte
                One band row per band of S4 CTX-ENTROPY, in band order:
                "<glyph>  <band>  <range>  <meaning>"; then the row
                "╱  unmapped gap  (fold)  address hole between runs — not a band".
                <window size>: the entropy window of S4 CTX-ENTROPY, 256.
  Map anatomy   For the band bar, the ruler, the band chips and the stats line of S4
                CTX-MAP: a sample line, then one line that says what it shows.
  Region row    A sample region row (S4 CTX-MAP), then the field line
                "glyph · start · size · size vs largest · A2L sym · band · ↵ opens hex".
  Map keys      The Memory Map's key line (S4 R-TUI-062.10).
```

---

## 4. The chapter, rewritten

Form column: U = ubiquitous. "Code today": **Yes** (read from the code), **Yes; tested**, **Partly** / **No** with the decision that changes the code.

### S3.1 · Building the issue list (CTX-ISSUE)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-VAL-010 | When | When the system adds an issue to the issue list, the system shall remove ANSI escape sequences from its message. | Yes; tested. |
| R-VAL-011 | When | When the system adds an issue to the issue list, the system shall remove the characters U+0000–U+001F and U+007F from its message. | Yes; tested. |
| R-VAL-012 | If | If an issue message is longer than 500 characters, then the system shall cut it to 500 characters ending in `…[truncated]`. | Yes; tested. |
| R-VAL-013 | If | If the issue list would hold the same issue twice, then the system shall keep only the first. | Partly: integrity-notice issues skip this step (D3-14). |
| R-VAL-014 | When | When the operator loads an S19, Intel HEX, A2L or MAC file, the system shall rebuild the issue list. | Yes; tested. |
| R-VAL-015 | If | If no file is loaded, then the system shall hold an empty issue list. | Yes; tested. |
| R-VAL-016 | If | If a load has an integrity notice (S1 R-READ-005 … 008), then the system shall raise an ERROR issue whose code is the notice's code and whose message is the notice's text. | Yes; tested (S19-NO-TERMINATOR only). |
| R-VAL-017 | If | If a load records a line diagnostic (S1), then the system shall raise the ERROR issue `LOAD_LINE_DIAGNOSTIC` with the diagnostic's line number and message. | No: line diagnostics reach only a count and the log (D3-14). |
| R-VAL-018 | If | If a MAC file cannot be read, then the system shall raise the ERROR issue `MAC_READ_FAILED` with the read error as its message. | No (D3-14). |

### S3.2 · Issue producers (CTX-ISSUE)

**MAC**

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-VAL-020 | If | If a MAC record has a parse error, then the system shall raise the ERROR issue `MAC_PARSE_ERROR` with the record's line number and its parse error as the message. | Yes; tested. |
| R-VAL-021 | If | If two or more valid MAC records have the same name, ignoring case, then the system shall raise one ERROR issue `MAC_DUPLICATE_NAME` with the message `MAC symbol '<name>' is defined multiple times.` | Partly: the name is lower-cased (D3-17). |
| R-VAL-022 | If | If a shared address is a hard conflict, then the system shall raise one ERROR issue `MAC_DUPLICATE_ADDRESS` for it. | Yes; tested. |
| R-VAL-023 | If | If a shared address is a segment ambiguity or an alias candidate, then the system shall raise one WARNING issue `MAC_DUPLICATE_ADDRESS` for it. | Yes; tested. |
| R-VAL-024 | If | If a shared address is a bit-field sharing, then the system shall raise one INFO issue `MAC_DUPLICATE_ADDRESS` for it. | No: WARNING today (D3-5). |
| R-VAL-025 | When | When the system raises `MAC_DUPLICATE_ADDRESS`, the system shall give it the message `Address <address> has duplicate MAC symbols (<kind>): <names>.` | Yes; tested. |

**A2L** (any session with an A2L file)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-VAL-030 | If | If the A2L file has a parse error (S2 R-A2L-001.4 … 001.6), then the system shall raise the ERROR issue `A2L_STRUCTURE_ERROR` with the parse error as its message. | Partly: only in a primary session (D3-10). |
| R-VAL-031 | If | If two or more tags have the same name, ignoring case, then the system shall raise one ERROR issue `A2L_DUPLICATE_SYMBOL` with the message `A2L symbol '<name>' is defined multiple times.` | Partly: primary session only (D3-10); name lower-cased (D3-17). |
| R-VAL-032 | If | If an A2L section's name is not a block name of ASAM MCD-2 MC, then the system shall raise the WARNING issue `A2L_UNRECOGNIZED_BLOCK` with the section's line number and the message `Unrecognized A2L block '<NAME>'.` | Partly: 21 standard names (MOD_COMMON, AXIS_DESCR …) are raised too, then shown as INFO with a note (D3-12); primary session only (D3-10). |
| R-VAL-033 | If | If a GROUP or FUNCTION refers, inline or in a child REF_CHARACTERISTIC, REF_MEASUREMENT, DEF_CHARACTERISTIC, IN_MEASUREMENT or OUT_MEASUREMENT block, to a name that no tag has, then the system shall raise the WARNING issue `A2L_BROKEN_REFERENCE` with the message `<GROUP\|FUNCTION> references unknown symbol '<name>'.` | Partly: child blocks are not checked (D3-13); primary session only (D3-10). |
| R-VAL-034 | U | The system shall compare a reference with tag names respecting case. | Yes. |
| R-VAL-035 | If | If a tag's schema is not complete (S2 R-A2L-072) and no ERROR A2L issue names it, then the system shall raise the ERROR issue `A2L_TAG_SCHEMA_INCOMPLETE` with the message `A2L tag '<name>' is schema-incomplete: <reason>.` | Yes; tested. |
| R-VAL-036 | If | If a tag's address is more than 0xFFFFFFFF, then the system shall raise the WARNING issue `A2L_ADDRESS_EXCEEDS_32BIT` with the message `A2L tag '<name>' address <address> exceeds the 32-bit address range (> 0xFFFFFFFF).` | Yes; tested. |
| R-VAL-037 | If | If a tag's BYTE_ORDER value is not a byte order (S2 R-A2L-028), then the system shall raise the WARNING issue `A2L_UNKNOWN_BYTE_ORDER` with the message `A2L tag '<name>' has unknown byte order '<value>'.` | No (S2 D2-3). |
| R-VAL-038 | If | If an A2L issue would name an unnamed tag, then the system shall use `Unnamed A2L tag at address <address>` in its message, or `Unnamed A2L tag (no address recorded)` when the tag has no address. | Yes; tested. |

**Between files** (primary session)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-VAL-040 | If | If a valid MAC record's address is not in the primary image, then the system shall raise the WARNING issue `CROSS_MAC_S19_OUT_OF_RANGE` with the message `MAC symbol '<name>' address <address> not present in S19 image.` | Yes; tested. |
| R-VAL-041 | If | If a valid MAC record's address is an overlap address of the primary image, then the system shall raise the WARNING issue `CROSS_MAC_S19_OVERLAP_AMBIGUOUS` with the message `MAC symbol '<name>' points to overlapped S19 address <address>.` | Partly: S19 only, re-read from the file on disk (D3-15). |
| R-VAL-042 | If | If a checked tag is out of image (S2 CTX-A2L-CHECK), then the system shall raise the WARNING issue `CROSS_A2L_S19_OUT_OF_RANGE` with the message `A2L symbol '<name>' range is not fully present in S19 image.` | Partly: a tag with no length is checked as 1 byte (D3-16). |
| R-VAL-043 | If | If any byte of a checked tag's span is an overlap address, then the system shall raise the WARNING issue `CROSS_A2L_S19_OVERLAP_AMBIGUOUS` with the message `A2L symbol '<name>' points to overlapped S19 address <address>.` | Partly: start address only, S19 only (D3-15). |
| R-VAL-044 | If | If an A2L tag and a valid MAC record have the same name, ignoring case, and different addresses, then the system shall raise the ERROR issue `TRIPLE_NAME_ADDRESS_MISMATCH` with the message `Symbol '<name>' has address mismatch (A2L=<address>, MAC=<address>).` | Yes; tested. |
| R-VAL-045 | If | If a MAC file is loaded and a tag with an address has no valid MAC record of the same name, then the system shall raise the WARNING issue `CROSS_A2L_ONLY_SYMBOL` with the message `A2L symbol '<name>' missing from MAC.` | Partly: also raised for every tag when no MAC is loaded (D3-9). |
| R-VAL-046 | If | If an A2L file is loaded and a valid MAC record has no tag of the same name, then the system shall raise the WARNING issue `CROSS_MAC_ONLY_SYMBOL` with the message `MAC symbol '<name>' missing from A2L.` | Partly: also raised for every record when no A2L is loaded (D3-9). |
| R-VAL-047 | When | When the system names a tag or MAC record in an issue, the system shall use the name as the file writes it, from its first occurrence. | Partly: lower-cased in five codes (D3-17). |
| R-VAL-048 | When | When the system raises `TRIPLE_NAME_ADDRESS_MISMATCH`, the system shall give the issue the A2L tag's address. | No: no address (D3-17). |

**Coverage**

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-VAL-050 | U | The system shall compute MAC→S19 coverage as CTX-ISSUE defines it, in percent. | Yes; tested. |
| R-VAL-053 | U | The system shall compute A2L→S19 coverage as CTX-ISSUE defines it, in percent. | Partly: a tag with no length counts as 1 byte (D3-16). |
| R-VAL-054 | U | The system shall compute A2L↔MAC coverage as CTX-ISSUE defines it, in percent. | Yes; tested. |
| R-VAL-051 | If | If the count a coverage divides by is 0, then the system shall give that coverage as 0.0 %. | Yes; tested. |
| R-VAL-052 | If | If no primary image is loaded, then the system shall compute no coverage. | Yes (all counts 0; shown as such, see S2 D2-24). |

### S3.3 · The Issues screen (CTX-ISSUES-SCREEN)

Replaces: R-TUI-025, R-TUI-042 part (b), R-ISSUES-HEXPANE-001, R-ISSUES-RELATED-001. File-derived text here follows S1's R-TUI-103 family (the Issues view is on its list).

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-025.1 | While | While the Issues screen is shown, the system shall give the issue list 2/3 of the width. | Yes; tested. |
| R-TUI-025.18 | While | While the Issues screen is shown, the system shall give the hex peek 1/3 of the width. | Yes; tested. |
| R-TUI-025.2 | When | When the system shows the Issues screen, the system shall show the severity strip with the counts of the whole issue list. | Yes; tested. |
| R-TUI-025.3 | When | When the system shows the Issues screen, the system shall show the summary line. | Yes; tested. |
| R-TUI-042b.1 | When | When the system shows an issue page, the system shall group its issues by severity in the order ERROR, WARNING, INFO. | Yes; tested. |
| R-TUI-042b.2 | When | When the system shows a group, the system shall head it with its group header, counting the issues of that severity in the whole filtered list. | Yes; tested. |
| R-TUI-042b.3 | If | If an issue page holds no issue of a severity, then the system shall show no header for that severity. | Yes; tested. |
| R-TUI-042b.4 | When | When the system shows an issue, the system shall show its issue row in the colour of its severity. | Yes; tested. |
| R-ISSUES-RELATED-001 | When | When the system shows an issue row, the system shall show the issue's related artifacts joined by `, `, or `-` when it has none. | Yes; tested. |
| R-TUI-025.4 | When | When the operator presses `Issues: All`, the system shall show every issue. | Yes; tested. |
| R-TUI-025.5 | When | When the operator presses `Errors`, the system shall show only ERROR issues. | Yes; tested. |
| R-TUI-025.6 | When | When the operator presses `Warnings`, the system shall show only WARNING issues. | Yes; tested. |
| R-TUI-025.7 | When | When the operator picks a filter mode, the system shall mark its button as active. | No: only `filter=` in the summary shows it (D3-22). |
| R-TUI-025.8 | When | When the filter mode changes, the system shall show the first issue page. | Yes; tested. |
| R-TUI-025.9 | When | When the operator presses PgDn on the Issues screen, the system shall show the next issue page. | Yes; tested. |
| R-TUI-025.10 | When | When the operator presses PgUp on the Issues screen, the system shall show the previous issue page. | Yes; tested. |
| R-TUI-025.11 | If | If the operator asks for the next issue page while the last one is shown, then the system shall keep the last page. | Yes; tested. |
| R-TUI-025.12 | If | If the operator asks for the previous issue page while the first one is shown, then the system shall keep the first page. | Yes; tested. |
| R-TUI-025.13 | If | If the filtered list has more than one issue page, then the system shall show `More issues on other pages — use PgUp/PgDn to page.` under the list. | Yes; tested. |
| R-TUI-025.14 | If | If the issue list is empty, then the system shall show `No validation issues.` as the summary line. | Yes; tested. |
| R-TUI-025.15 | If | If the issue list is not empty and the filter mode matches no issue, then the system shall show `No issue matches the filter.` as the summary line. | No: shows `No validation issues.` (D3-22). |
| R-TUI-025.16 | When | When the operator presses Down on the issue list, the system shall move the focus to the next issue row. | No: only Tab moves between rows (D3-23). |
| R-TUI-025.17 | When | When the operator presses Up on the issue list, the system shall move the focus to the previous issue row. | No (D3-23). |
| R-ISSUES-HEXPANE-001.1 | When | When the operator selects an issue row whose issue has an address, the system shall show the hex peek of that address. | Yes; tested. |
| R-ISSUES-HEXPANE-001.2 | If | If the selected issue has no address, then the system shall show `(issue has no address — nothing to show)` in the hex peek. | Yes; tested. |
| R-ISSUES-HEXPANE-001.3 | When | When the operator loads a file, the system shall clear the hex peek. | No: the old bytes stay (D3-24). |

### S3.4 · Colours and the legend (CTX-LEGEND)

Replaces: the A2L and MAC colour blocks (their rules are S2 R-A2L-080 … 088 and R-MAC-031 … 035), amendments C and F, R-LEGEND-SOURCE-001, R-LEGEND-MODAL-001, R-LEGEND-GEOMETRY-001, R-TUI-047.

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-LEGEND-010 | U | The system shall draw every severity colour, on every screen, from the palette of CTX-LEGEND. | Partly: the A2L and MAC tables use terminal colours; MAC warnings are orange, not pale yellow (D3-18). The Load-result panel (batch-100, S11 R-LOADRES-14 … .16) uses the palette (`screens.py:1711-1777`). |
| R-LEGEND-011 | U | The system shall show the legend rows of CTX-LEGEND. | Partly: the A2L, MAC and Issues rows say things the screens do not do (D3-19). |
| R-LEGEND-SOURCE-001 | U | The system shall show the same legend rows in the legend window and in the project report. | Yes; tested. |
| R-TUI-047 | U | The system shall name each colour of the Hex block after the style the hex view uses for it. | Yes; tested. |
| R-LEGEND-MODAL-001.1 | When | When the operator presses `k` outside a text box, the system shall open the legend window. | Yes; tested. |
| R-LEGEND-MODAL-001.2 | When | When the operator presses `Legend` on the MAC View or the Issues screen, the system shall open the legend window. | Yes; tested. |
| R-LEGEND-MODAL-001.3 | If | If no file is loaded, then the system shall still open the legend window with its blocks. | Yes; tested. |
| R-LEGEND-MODAL-001.4 | When | When the legend window opens on the A2L Explorer, the system shall show the A2L block. | Yes; tested. |
| R-LEGEND-MODAL-001.5 | When | When the legend window opens on the MAC View, the system shall show the MAC block. | Yes; tested. |
| R-LEGEND-MODAL-001.6 | When | When the legend window opens on the Issues or Checks screen, the system shall show the Issues block. | Yes; tested. |
| R-LEGEND-MODAL-001.7 | When | When the legend window opens on the Workspace, the Patch Editor or the A↔B diff, the system shall show the Hex block. | Partly: the Workspace shows no block (D3-20). |
| R-LEGEND-MODAL-001.8 | When | When the legend window opens on a screen other than the Memory Map that has no block of its own, the system shall show every block. | Yes; tested (`test_n1_unmapped_screen_shows_full_table`). The Memory Map exception is D3-27. |
| R-LEGEND-MODAL-001.9 | When | When the system shows a legend row, the system shall show it as `<classification> — <meaning>` in its colour. | Partly: Hex rows have no colour (D3-20). |
| R-LEGEND-MODAL-001.10 | When | When the legend window opens on the Workspace, the A2L Explorer, the MAC View or the Issues screen, the system shall show in the card pane sample lines of that screen, written as the screen writes them. | Partly: the Issues card differs from the real rows (D3-21). |
| R-LEGEND-MODAL-001.11 | When | When the legend window opens, the system shall put the focus on `Close`. | Yes; tested. |
| R-LEGEND-MODAL-001.12 | When | When the operator presses `Close` or Esc in the legend window, the system shall close it. | Yes; tested. |
| R-LEGEND-GEOMETRY-001.1 | While | While the screen is at least 120 columns wide, the system shall show the card pane on the left, 3/5 of the window width. | Yes; tested. |
| R-LEGEND-GEOMETRY-001.6 | While | While the screen is at least 120 columns wide, the system shall show the key pane on the right, 2/5 of the window width. | Yes; tested. |
| R-LEGEND-GEOMETRY-001.2 | While | While the screen is less than 120 columns wide, the system shall show the key pane above the card pane. | Yes; tested. |
| R-LEGEND-GEOMETRY-001.3 | U | The system shall keep the legend window inside the screen. | Yes; tested. |
| R-LEGEND-GEOMETRY-001.4 | If | If the key pane's rows do not fit its height, then the system shall let the operator scroll it. | Yes; tested. |
| R-LEGEND-GEOMETRY-001.5 | While | While the screen is 80 columns wide or more, the system shall show the `Legend` buttons of the MAC View and the Issues screen whole. | Yes; tested. |

**The map sheet** (from S0 HLR-132, HLR-134)

Focus on `Close` and closing with Esc: R-LEGEND-MODAL-001.11, .12 (tested on the sheet: `test_esc_dismisses_the_sheet`). The keys the `Map keys` box names: S4 R-TUI-062.10 (D4-21). No text from a file appears in the sheet.

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-LEGEND-MAP.1 | When | When the legend window opens on the Memory Map, the system shall show the map sheet of CTX-LEGEND in place of the card pane and the key pane. | Yes; tested (`test_tc676_sheet_four_grouped_boxes`). |
| R-LEGEND-MAP.2 | When | When the system shows the map sheet, the system shall show one band row per band of S4 CTX-ENTROPY, in band order. | Yes; tested (`test_tc677_sheet_band_rows_equal_live_build`, `test_tc677_band_key_mutated_upstream_flows_through`). |
| R-LEGEND-MAP.3 | When | When the system shows a band row of the map sheet, the system shall show it in its band's colour. | Yes; tested (`test_tc676_sheet_four_grouped_boxes`). |
| R-LEGEND-MAP.4 | While | While the terminal is at least 80 columns by 24 rows, the system shall show each line of the map sheet on one row of its box. | Yes; tested at 80 × 24 and 120 × 36 (`test_tc680_sheet_no_wrapped_lines`). |
| R-LEGEND-MAP.5 | U | The system shall show the lines of the map sheet as plain text, never as markup. | Yes; tested for the band rows (`test_tc676_sheet_four_grouped_boxes`). |

---

## 5. Decisions: recommendation applied

**Requirement follows the code, or moves (no code change)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D3-1 | The A2L and MAC colour blocks restate rules S2 now has as rows; the "Notes" on tag length restate S2 R-A2L-013 … 020. | The rules live in S2 (the screen that shows them). S3 keeps the legend that explains them. |
| D3-2 | R-TUI-042 bundles three features of three groups. | (a) A2L table density → two rows added to S2 (R-TUI-042a.1/.2). (b) → S3.3. (c) Workspace coverage signals → S5. |
| D3-3 | R-LEGEND-SOURCE-001 requires a file placement to keep a frozen file untouched. | Row: the window and the report show the same rows. The placement rule goes to the design notes. |
| D3-27 | `k` on the Memory Map opens the legend window with a four-box sheet and no legend block (`screens.py:1296-1305`, `:1341-1355`; the map maps to no block, `app.py:7306`). No row described the sheet (S0 HLR-132, HLR-134), and R-LEGEND-MODAL-001.8 asked for every block there. | Rows follow the code: R-LEGEND-MODAL-001.8 leaves out the Memory Map; the sheet is CTX-LEGEND "map sheet" and R-LEGEND-MAP.1 … .5. Its key line stays S4's (R-TUI-062.10, D4-21). |

**Remove (rule use/defer/delete)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D3-4 | `MAC_EMPTY_NAME`, `MAC_INVALID_ADDRESS`, `A2L_INVALID_ADDRESS` and the "valid unresolved" kind of shared address cannot fire with the real parsers; `CROSS_S19_HEX_OVERLAP` exists only in an `xfail` test. | Remove the code paths and that test. The real cases arrive as `MAC_PARSE_ERROR`. |
| D3-5 | `alias_policy`: never passed, so always "warn"; its documented value "error" does nothing. INFO has no real producer once D3-12 removes the display triage. | Remove the parameter. Fixed severities: hard conflict ERROR, alias candidate or segment ambiguity WARNING, bit-field sharing INFO (several flags in one byte are normal in ECU code). INFO then has one meaning. |
| D3-6 | Three "Optional info" categories that nothing produces. The A2L table already shows checked / not checked / virtual per row. | Remove from the requirements and the legend; do not build them (they would repeat the table as hundreds of issues). |
| D3-7 | `_jump_to_validation_issue` and `_jump_to_validation_issue_object` (jump to the A2L screen, status texts) and `_format_validation_issue_line` have had no caller since batch-29. | Remove them and their tests. Selecting an issue shows the hex peek. A jump from an issue to its tag would be a new row, if you want it. |
| D3-8 | The issue page size setting is never written (always 40) and the "capped" branch can never run. | Remove both; the page is 40 issues. |

**Code change: correct a defect**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D3-9 | **The largest one.** S19/HEX + A2L with no MAC: every tag with an address gets `A2L symbol '<x>' missing from MAC.` (WARNING). S19 + MAC with no A2L: every MAC record gets the mirror warning. The Issues list fills with noise in the most common session. | Raise them only when the other file is loaded (R-VAL-045, 046). |
| D3-10 | A2L structure checks run only in a primary session: an A2L alone, or with a MAC, reports no parse error, duplicate or broken reference. | Run them whenever an A2L is loaded (R-VAL-030 … 033). |
| D3-11 | In a primary session the A2L structure rules run twice; dedup hides it, except that one call path reports every inline reference as broken. | Run them once. |
| D3-12 | The recognised-block list has 15 names; standard blocks (MOD_COMMON, MOD_PAR, AXIS_DESCR …) are raised as WARNING, and the Issues view then re-labels 21 of them as INFO with a long note. | Put the standard names in the rule; drop the display triage and its note. `A2L_UNRECOGNIZED_BLOCK` then means a block the standard does not have. |
| D3-13 | `A2L_BROKEN_REFERENCE` checks only the one-line form; the standard child-block form is never checked (and is itself flagged as unknown). | Check both forms (R-VAL-033). Keep WARNING: a broken group reference does not change any value. |
| D3-14 | Rejected lines and checksum failures (S1 diagnostics) reach the operator only as a count and the log; a MAC read failure never becomes an issue; integrity notices skip dedup and are missing from the report object. | Each becomes an issue (R-VAL-017, 018), all through the same dedup (R-VAL-013). This also answers S1's open point O1 (should the Issues panel list each diagnostic): yes. |
| D3-15 | Overlap issues: S19 only (never HEX), computed by re-reading the file on disk, and for a tag only its start address. | Use the loaded image's overlap addresses (S1 R-IMG-002, both formats) and the whole tag span. |
| D3-16 | A tag with an address and no length is "not checked" (grey) in the table, but the issue check treats it as 1 byte and may warn it is out of range. | Same rule as the table: no length, not checked, no issue. |
| D3-17 | Five codes lower-case the name (`MAC_DUPLICATE_NAME`, `A2L_DUPLICATE_SYMBOL`, the triple and both "only" codes), so the issue shows `engspeed` for `EngSpeed`; `TRIPLE_NAME_ADDRESS_MISMATCH` carries no address, so its hex peek is empty. | The name as written (first occurrence); the triple issue carries the A2L address (R-VAL-047, 048). |
| D3-18 | Three palettes: Issues rows use the legend's (`#fd8383` …), the A2L and MAC tables use terminal colours (`red`, `green`, `grey70`), and MAC warning rows are `orange3` while the legend says pale yellow. | One palette (CTX-LEGEND) everywhere. Orange stays as the MAC-only cue (⚠ glyph, hex mark). S2 rows R-MAC-032 updated to pale yellow. |
| D3-19 | Legend rows describe intentions, not what the screens do (MAC pale yellow "alias, overlap"; A2L red "malformed field"; Issues "Optional info"). | Rows rewritten from the S2 and S3 rules (CTX-LEGEND). |
| D3-20 | Hex legend rows show the colour word but no colour; the Workspace (whose hex view uses both colours) shows no block. | Hex rows in their colour; Workspace shows the Hex block. |
| D3-21 | The Issues card shows `✗ ERRORS (3)` and `symbol · 0xADDR · message`; the screen shows `✗ ERRORS  (3)` and two-space separators, and the card's "Info rows appear only under All" is false. | Card text copied from the real output. |
| D3-22 | Filter buttons have no active state; `No validation issues.` also appears when the filter is the cause. | Mark the active button; `No issue matches the filter.` (same fix as S2 D2-19). |
| D3-23 | Issue rows can be reached only with Tab. | Up/Down move between rows. |
| D3-24 | The hex peek keeps the previous file's bytes after a new load. | Clear it on load. |
| D3-25 | The two overlay styles are defined twice (`color_policy.py` and `render/format.py`); a colour test still encodes WARNING as "orange". | One definition; fix the test. |

**Passed to other groups**

- **S2**: R-TUI-042 (a) → rows R-TUI-042a.1/.2 added there; S2's colour rows now name palette colours (D3-18).
- **S4** (Memory Map): its key line says "j k select", but `j` exports the A2L JSON and `k` opens the legend; the region rows take only ↑/↓/Enter.
- **S5** (Workspace): R-TUI-042 (c), the coverage micro-bars, memory strip and stat pane.
- **S12** (reports): R-LEGEND-REPORT-001 (the report's `## Legend` section) stays there; it must follow R-LEGEND-SOURCE-001.

Code-change items for the batch: D3-9 … D3-25, plus the removals D3-4 … D3-8.

---

**Received from later groups** (after S6–S17 were written)

| # | The situation | Recommendation (applied) |
|---|---|---|
| D3-26 | Colours outside the one palette (D3-18): patch teal `#56e0d6` for changed strip bytes, magenta `#f586da` for the paste gauge, four JSON hues (S10); check outcomes ✓ ✗ ◐ · in green / red / pale yellow / grey and the Spec dropdown's CHECK / PATCH labels (S9). The legend has no block for them. | Every colour-coded surface maps onto the one palette and has a legend block. Visual, so **prototype first**: the round shows the Patch Editor, the Checks tab and the legend with the mapped colours. |

- **S12**: the report's legend section prints the same rows as the legend window (R-LEGEND-SOURCE-001), so D3-19 reaches the report with no S12 change.
- **S7**: the legend dialog's rows stay here (R-LEGEND-MODAL-001, R-LEGEND-GEOMETRY-001).

**Received from later groups** (after all groups were written)

- S3.1 (S0, HLR-132 and HLR-134: the Memory Map legend sheet) → rows R-LEGEND-MAP.1 … .5 and CTX-LEGEND "map sheet"; R-LEGEND-MODAL-001.8 leaves out the Memory Map; D3-27.

**Reconciled with batch-100 (s19_app 570b4b5)**

- From S11: the Load-result panel (batch-100 HLR-178) paints its OK colour, warning colour and `not readable` mark from the palette of CTX-LEGEND (green `#54efae`, pale yellow `#f6ff8f`, red `#fd8383`, grey `#969aad` for labels; `screens.py:1711-1777`, `insight_style.py:64-66`, `render/format.py:12-18`). The rows are S11's (R-LOADRES-14 … .16); "Code today" of R-LEGEND-010 names the panel. No S3 row added, changed in text or retired; no decision.

## 6. Counts

| | Old S3 | Strict |
|---|---:|---:|
| Requirement statements | 3 policy blocks + 2 amendments + 10 rows | 91 rows |
| Statements the code contradicts or never built | 9 | 0 |
| Rows by form: U / When / While / If / Where | — | 10 / 37 / 7 / 37 / 0 |
| Rows that could not be written in EARS | — | 0 |
| Decisions | — | 27 (4 follow the code or move, 5 remove, 17 correct a defect, 1 prototype first: D3-26 from S9/S10) |

Checked by script: one `shall` per row, correct opening words per form, `If … then`, no "unless" / "only if", no repeated id.
