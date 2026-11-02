# S12 — Project reports: context notes and strict EARS rows (2026-10-30)

Input: `REQUIREMENTS.by-module.md` chapter S12 (lines 5018–5829): 14 primary rows — R-RPT-001, R-RPT-002, R-LEGEND-REPORT-001, R-RPT-ISSUE-FIELDS-001, R-RPT-ADDENDUM-001, R-RPT-ADDENDUM-002, R-RPT-REGION-SKIP-001, R-RPT-FILTER-001, R-TUI-077, R-TUI-078 (withdrawn), R-TUI-097, R-TUI-098, R-TUI-101, R-TUI-102. Also the items other groups passed to S12 (S3 legend, S4 entropy, S7 Reports dialog, S11 region box and last execution) and the Reports part of S0 HLR-139.
Code: `s19_app/tui/services/report_service.py`, `report_filter.py`, `report_addendum.py`, `markdown_safety.py`; in `screens.py` `ReportViewerScreen`, `_parse_declared_regions`, `_hardened_markdown_parser`; the S12 functions of `app.py` (`action_view_reports`, the filter handlers, `_trigger_generate_report`, `_start_generate_report_worker`, `_finish_generate_report`, `_log_report_event`, `format_report_log_line`, `_scan_report_filter_files`); `render/hexview.py::render_hex_view` where the report uses it. Read directly, every fact with `file:line`. No test was run.
Reconciled with s19_app 570b4b5 (batch-100) on 2026-11-01: rows and cites in S12.13 and S12.14 (the report start, worker and finish, `app.py:6016-6400`) verified at 570b4b5; other cites refer to 093a7c0.

Result:
- **Context notes first** (section 3): CTX-RPT-FILE, CTX-RPT-CELLS, CTX-RPT-HEX, CTX-RPT-TEXT, CTX-RPT-BUDGET, CTX-RPT-ADDENDUM, CTX-RPT-FILTER, CTX-RPT-DIALOG, CTX-RPT-RUN. Each report's file format (name, place, sections, field order, encoding) is in CTX-RPT-FILE.
- **Rows** (section 4): one EARS form each, one `shall`; none needed another form; none uses `Where`. Counts in section 6.
- **Decisions** (section 5), each with a recommendation already applied to the rows. No visual change came up, so no prototype round is asked.
- Absorbed from other groups: S3's legend item (S12.2, note under the table); S4's low confidence (R-RPT-ENT.3); S7's Reports dialog (S12.9, S12.12, S12.13); S11's region box and last execution (S12.9, S12.13); S14's note that other reports are listed in no order (D12-23); S15's citation of R-TUI-097 (R-TUI-097.1). Rows owned by S12 with S7 as second group (R-RPT-002, R-RPT-ADDENDUM-002, R-RPT-REGION-SKIP-001) are written here.
- Rules E1–E7: `review/S1-ears-strict.md` section 1. Code changes: `cc-S12.md` (to be merged into `review/CODE-CHANGES.md`). Nothing is changed in the code yet.

---

## 1. How S12 was written before

- Two rows from the first report batch (R-RPT-001, 002): one paragraph each, listing five report contents, a window formula, two caps, a viewer cap and the activity rail in one sentence.
- Five short rows from later batches (legend, issue fields, declared regions, skip notice): mostly true, but written against code names (`DeclaredRegion`, `ValueError`, `_scrub_issue_message`, `include_legend=False`).
- R-RPT-FILTER-001: one 23-line sentence with about 20 responses, covering three different reports.
- R-TUI-077 … R-TUI-102: about 600 lines of batch records — measurements, "non-claims", mutant rosters, test lists, corrections of earlier corrections. The statements are a few lines each; most of it is how a batch reasoned, not what the product does.
- R-TUI-078: withdrawn, kept as history.
- Missing: the Entropy section, the empty-section texts, the status texts of generation, the log lines, the progress bar, the `## Omitted content` block, the viewer texts.

## 2. What did not make sense

| Where | What did not make sense | Fix |
|---|---|---|
| R-RPT-001 | "Size caps … truncate with an explicit in-document marker": the code has six caps, each with its own text; no text is given, so no test can compare. | One row per cap with its exact text (S12.3, S12.4, S12.6, S12.8, S12.9). |
| R-RPT-001 | "Reports live only under the gitignored `.s19tool/` tree": gitignore is a property of the repository, not of the product. | Row: the report is written under `<project>/reports/` (R-RPT-001.1). |
| R-RPT-002 | "the activity rail stays at exactly eight items": the rail is S6's; "invoking the service entry point constructs no Textual App": a design rule; no operator can reach the service without the app (S1 removed the command-line tool, D-11). | Out (D12-2, D12-3). |
| R-LEGEND-REPORT-001 | "`include_legend=False` shall omit it": nothing in the product sets this switch (`app.py:5192-5198` passes only five fields); only tests do. Same for `include_entropy`. | Legend and Entropy always written; switches removed (D12-11). |
| R-RPT-ADDENDUM-001 | A data model: a class name, one `ValueError` per field, a private function name. The operator sees a skipped line and a cleaned name. | Rows on what the dialog does with a line (S12.9). |
| R-RPT-ADDENDUM-002 | "modifications … whose address falls within": a change entry spans several bytes; which address? The code uses the start address and lists every entry, applied or not (`report_service.py:2957`). | "hit" defined in CTX-RPT-ADDENDUM (D12-9). |
| R-RPT-REGION-SKIP-001 | "the two sites mutually exclusive per line": code structure. | Rows on the skipped line and the notice only. |
| R-RPT-FILTER-001 | One sentence for the filter file, the dropdown, the path box, three reports, a thread rule ("resolved ONCE per run on the UI thread"), a test policy ("golden-pinned … byte-identical") and an escaping rule. | Split into 58 rows (S12.10, S12.11). The before/after and A↔B diff parts go to S14. Thread rule and golden policy out (D12-1, D12-2). |
| R-RPT-FILTER-001 | "an item matches on symbol": the code matches the entry's linkage symbol only (`report_service.py:1552-1556`), while the Symbol cell shows the entry's own symbol first (`:1918`). A filter on the name the reader sees can hide that row. | Match either symbol (R-RPT-FILTER-001.50, D12-27). |
| R-TUI-077 | Escaping "at the COMPOSER", "exactly once, at the line-assembly site", "explicit per-site limit", "leaf module": where the code does it. The observable rule is what a Markdown reader shows. | CTX-RPT-TEXT + rows R-TUI-077.1 … .4; the rest is design (D12-2). |
| R-TUI-078 | Withdrawn before merge; the text stays as history. | Out (D12-4). |
| R-TUI-097 | A shared encoder function and the accounting rule of `_line_bytes`: design. The observable part: the file has LF line ends on every host, and the size ceiling holds for the bytes on disk. | R-TUI-097.1, R-TUI-102.7. |
| R-TUI-098 | "consume the candidate set in a single pass … independent of `R`", "bound its own resident allocation": performance design, with six non-claims that say the bound does not hold for the report as a whole. | Rows keep the cap and its notice (R-TUI-098.1 … .3); the rest is design (D12-2). |
| R-TUI-101 | "bound their own resident allocation … materialise no intermediate full-population list": memory inside two functions; the requirement itself says no whole-report memory claim is made. | Rows keep the row caps, the byte cell cap and the address cell form (S12.6); residency is design (D12-2). |
| R-TUI-102 | "every `Length` cell shall render without raising for every `int` difference": a length is the byte count of an entry (`changes/model.py:193`, `apply.py:330`), at most 1 MiB, so the branch for huge lengths can never run. | Row: length in decimal (R-TUI-102.8); the unreachable branch is removed (D12-12). |
| Window heading | `Window 0x<low>-0x<high>:` gives the first address after the window (`report_service.py:2260`; tested: `Window 0x00000FC0-0x00001060:`), while the addendum heading `(0x<start>-0x<end>)` gives the last address inside the region (`:3025`). One notation, two meanings, in one document. | Both give the last address inside (R-RPT-001.39, D12-26). |
| Filter path box | Its hint says `filter path (blank = full report)` (`screens.py:1712`), but a blank submit is ignored (`:1855-1857`). | Blank clears the filter (R-RPT-FILTER-001.14, D12-21). |
| Context bytes box | Generate new report with a value that is not a whole number does nothing: no message, the dialog stays (`screens.py:1866-1871`). | `Report rejected: …` (R-RPT-002.13, D12-20). |

Context notes that carried behaviour (E6): none; the old chapter had no context notes.

---

## 3. Context notes (informative)

### CTX-RPT-FILE · The project report file (S12.1 … S12.5)

```text
report file      <project>/reports/<timestamp>-report.md     (<project>: S11 CTX-PROJECT)
  <timestamp>    The UTC time of generation, YYYYMMDDTHHMMSSZ, e.g. 20261030T121500Z.
  same second    The next names of the same second are <timestamp>-01-report.md …
                 <timestamp>-99-report.md.
report name      A file name of the form <timestamp>-report.md or <timestamp>-NN-report.md.
encoding         UTF-8 text, LF line ends, Markdown with GitHub tables.
sections, in this order (a section that a rule leaves out keeps the others in order):
  title          # Project report: <project>
  filter block   ## Report filter applied                 (only with a filter; CTX-RPT-FILTER)
  header lines   - Project: <project>
                 - Generated (UTC): <time>
                 - Tool version: <version>                (S1 R-VER-001)
                 - Context bytes: <c>
                 - Execution mode: <mode>
                 - Assignment source: <source>
  inventory      ## Variant inventory      table: Variant · File · Type · Active
  overview       ## Consolidated overview  table: Variant · Status · Changes applied ·
                                           Checks passed · Checks failed · Checks uncheckable
  legend         ## Legend                 one "### <block>" per block of S3 CTX-LEGEND
  per reported variant, in run order:
    ## Variant: <variant id>
    ### Modified files        modified-file lines (CTX-RPT-CELLS)
    ### Modifications         table: Address · Length · Before · After · Linkage · Symbol
    ### Declaration errors    issue lines (CTX-RPT-CELLS)
    ### Checklists            per check document: #### Checklist: <path>, the count line,
                              table: Address · Length · Expected · Actual · Result
    ### Memory regions        hexdump blocks (CTX-RPT-HEX)
    ### Entropy               band lines
  addendum       ## Addendum: declared regions             (only with declared regions)
  appendix       ## Truncation appendix                    (only with truncation notes)
  omitted block  ## Omitted content                        (only when a section was left out)
Each heading and each table is followed by one blank line.
<time>           ISO 8601 with the UTC offset, e.g. 2026-10-30T12:15:00.123456+00:00
                 (microseconds left out when they are 0).
<c>              Context bytes: a whole number from 0 to 4096; 64 by default.
<mode>           The scope of the reported run (S11 CTX-EXEC), written as:
                 active-only (scope active) · batch (scope all) ·
                 per-assignment (scope assignments).
<source>         manifest (the run took its documents from project.json) ·
                 default (it did not).
reported variant A variant of the reported run (S11 CTX-EXEC), with its run status ok or error.
Type             s19 or hex.    Active: yes for the project's active variant, else no.
Changes applied  The number of the variant's change entries with disposition applied
                 (S8 CTX-APPLY).
Checks passed …  The variant's aggregate counts (S9 CTX-CHECK), summed over its check
                 documents.
band lines       - **<band>**: <n> window(s)[ (<k> low-confidence)]
                 (bands and low confidence: S4 CTX-ENTROPY)
```

### CTX-RPT-CELLS · Lines and cells (S12.3, S12.6)

```text
hex address      0x + uppercase hexadecimal digits, no leading zeros (0x1F00).
address cell     0x + uppercase hexadecimal digits, at least 8 (0x00001F00).
length cell      The entry's byte count, in decimal.
byte cell        Each byte as two uppercase hexadecimal digits, one space apart (01 AB FF);
                 - when the entry has no such bytes (Before of an entry not applied,
                 Actual of an entry not read).
byte cell cap    171 bytes per cell.
symbol cell      The entry's own symbol; when it has none, its linkage symbol (S8
                 R-CHG-LINK.3); when it has neither, -.
Linkage          mac-linked · a2l-linked · both · standalone (S8 CTX-APPLY).
Result           pass · fail · uncheckable (S9 CTX-CHECK).
modified-file    - `<document path>` (applied entries: <n>)[ - saved as `<saved path>`]
line             (in-memory document) stands, without backticks, for a document with no file.
<path>           In "#### Checklist: <path>" and its notices: `<document path>`, or
                 (in-memory document).
issue line       - [<code>] <severity>: <message>[ @ <hex address>][ symbol=<symbol>]
                 [ related=<artifact>,<artifact>…]
                 (issue, code, symbol, related artifacts: S3 CTX-ISSUE;
                 severity: error · warning · info)
count line       Passed: <p> - Failed: <f> - Uncheckable: <u>
kept rows        The rows of a table that pass the report filter (all rows when no filter
                 is selected). The row caps count kept rows.
row cap          200 kept rows per variant: Modifications rows, and Checklists rows
                 counted over all the variant's check documents.
```

### CTX-RPT-HEX · Hexdumps (S12.4)

```text
applied entry    A change entry of the run with disposition applied (S8 CTX-APPLY); its
                 span is start … end, end exclusive.
image            The variant's image after its run (S11 CTX-EXEC).
image top        The highest address of the image, plus 1.
window           For an applied entry and context <c>: from (start − c) rounded down to a
                 multiple of 16, not below 0, up to (end + c) rounded up to a multiple of
                 16, not above the image top rounded up to a multiple of 16; the upper
                 bound exclusive. Windows that overlap or touch are one window.
region cap       128 applied entries per variant (their windows are dumped).
block            Window 0x<first address, 8 digits>-0x<last address, 8 digits>:
                 (blank line)
                 ```text
                 [... window limited to 512 rows ...]
                 up to 512 rows, one per 16 addresses of the window
                 ```
                 (blank line)
row              0x<row address, 8 digits>  <16 cells, one space apart>  |<16 characters>|
                 cell: the byte as two uppercase hexadecimal digits; two spaces for an
                 address not in the image.
                 character: the byte when it is 0x20-0x7E, else "."; an address not in the
                 image also shows ".". (The screens' row format is S4 CTX-HEX.)
```

### CTX-RPT-TEXT · Text from a file, in a report (S12.7)

```text
file-derived text  Text a report takes from a file, a folder name or the operator: the
                   project name, variant ids, file names, file types, run statuses,
                   linkages, symbols, issue codes, messages and related artifacts, check
                   results, the filter file name, region names. (Screens: S1 CTX-TEXT.)
report-safe text   The text after these steps, in this order:
                   1. each tab, CR and LF becomes one space;
                   2. each character of Unicode category Cc, Cf, Cs, Zl or Zp becomes �;
                   3. white space at both ends is removed;
                   4. text longer than the field limit is cut to the limit, white space at
                      its end removed, and "… (truncated)" added;
                   5. a backslash goes before each \ & | * _ [ ] < > # ~ / . @ and `;
                   6. a leading - + or = gets a backslash before it; a leading
                      <1 to 9 digits>) gets a backslash before the );
                   7. empty text becomes (empty).
path text          Steps 1 to 3, then each backtick becomes �, then empty text becomes
                   (empty). Never cut. Written between two backticks.
field limit        region name 80 · issue message 500 · every other field 512 characters.
Markdown reader    A CommonMark reader with GitHub tables, links made from bare web
                   addresses, and raw HTML turned on (markdown-it "gfm-like" defaults).
shows as text      Shows the characters of the value and opens no link, image, raw HTML,
                   heading, list, quote, rule, code span, emphasis, strikethrough or new
                   table cell.
```

### CTX-RPT-BUDGET · Size of a report (S12.8)

```text
size budget       2,097,152 bytes (2 MiB).
line cost         The line's UTF-8 bytes + 1.
section           A part the system admits or leaves out as a whole:
                  preamble: the filter block, the inventory, the overview, the legend;
                  per variant: Modified files, Modifications, Declaration errors,
                  Checklists, the Memory regions heading with its empty text, each
                  hexdump block, Entropy;
                  after the variants: the addendum.
section kind      preamble · modified-files · modifications · declaration-errors ·
                  checklists · memory-regions · entropy · addendum
always written    The title, the header lines, each variant heading, the TRUNCATED lines
                  of a Memory regions section, the truncation appendix and the omitted
                  block. They do not count against the size budget.
variant share     The larger of: (size budget left after the legend) ÷ (number of
                  reported variants), and 624 bytes.
size ceiling      2,097,152 + 63,726 + 1,321 × <number of reported variants> bytes on a
                  64-bit host, for variant ids of at most 255 UTF-16 units (a file name).
truncation note   Variant '<variant id>': <the text of a Memory regions TRUNCATED line
                  without its "> TRUNCATED: " prefix>
appendix          ## Truncation appendix
                  (blank line)
                  - <truncation note>          at most 64, taken one per variant in turn
                  [- <n> further note(s) across <d> variant(s) not itemised (cap: 64 notes).]
                  (blank line)
omitted block     ## Omitted content
                  (blank line)
                  - <kind>: sections <s>, lines <l>, bytes <b>[ (variants <list>)]
                  one line per section kind with a section left out, in kind order;
                  <b>: the summed line cost of what was left out;
                  <list>: up to 8 variant positions (0 = first in run order), ", "
                  between them, then " +<k> more" for the others.
                  (blank line)
```

### CTX-RPT-ADDENDUM · Declared regions (S12.9)

```text
declared region   A name and an address range start … end, both included (region rules:
                  S11 CTX-MANIFEST).
region box        The Reports dialog's multi-line box: one region per line,
                  <name>,<start>,<end>. Pre-filled from the kept regions (S11 S11.12).
region number     A whole number in decimal (no leading zero), or after 0x (hexadecimal),
                  0o (octal) or 0b (binary); _ may stand between digits; a leading -
                  makes it negative.
skipped line      A line of the region box that is not blank and either does not hold
                  exactly three comma-separated fields, or holds a field that is not a
                  region number, or breaks the region rules.
hit               modification: a change entry of a reported variant, any disposition,
                  whose start address is in the region;
                  change-file issue: an issue of a change document of a reported variant
                  whose address is in the region;
                  check-file issue: the same for a check document.
hit line          - modification @ <hex address> (variant <variant id>)
                  - issue [<code>] @ <hex address> (variant <variant id>)
hit order         Variants in run order; per variant, each change document's entries and
                  then its issues, document by document; then the check documents' issues.
addendum          ## Addendum: declared regions
                  (blank line)
                  per region, in the order of the region box:
                  ### <name> (<hex start>-<hex end>)
                  its hit lines, or None.
                  its truncation notices
                  (blank line)
hit cap           200 hits of one kind per region.
```

### CTX-RPT-FILTER · The report filter (S12.10, S12.11)

```text
filter file      A UTF-8 JSON file of at most 4,194,304 bytes (4 MiB):
                   {"format": "s19app-report-filter", "version": "1.0",
                    "include": {"symbols": [<pattern>, …],
                                "addresses": [{"start": <a>, "end": <b>}, …]}}
                 include, symbols and addresses may be left out: an empty list.
                 At most 4096 patterns and 4096 ranges.
<a>, <b>         A JSON whole number, or text "0x<hexadecimal digits>"; 0 ≤ a < b ≤ 2^32;
                 b is exclusive.
filters folder   <project>/filters/
filter selection The filter file the next project report and before/after report use
                 (S14), or none. One per session.
pattern match    A name matches a pattern when it is equal to it, or matches it as a
                 case-sensitive wildcard pattern (* ? [set]).
matched set      The filter's address ranges, plus, for each loaded A2L tag and MAC record
                 (S2) whose name matches a pattern, address … address + size, end
                 exclusive; size: the tag's byte size when it is above 0, else 1; MAC: 1.
item match       An entry matches when its own symbol or its linkage symbol matches a
                 pattern, or its span shares an address with the matched set.
filtered parts   The Modifications rows, the Checklists rows and the applied entries whose
                 windows are dumped. Every other section is written in full.
filter block     ## Report filter applied
                 (blank line)
                 - Filter file: <filter file name>
                 - Modifications rows: shown <s> of <t> (hidden <h>)
                 - Checklist rows: shown <s> of <t> (hidden <h>)
                 - Applied regions: shown <s> of <t> (hidden <h>)
                 - Note: windows seeded by matched regions may include excluded addresses
                   as merged context.
                 (blank line)
                 <s>, <t>, <h>: matching, all, not matching; summed over the reported
                 variants; Applied regions counts applied entries.
zero-match text  filter matched 0 of <n> items          (<n>: the items before the filter)
diagnostic       One text per fault of a filter file (S12.10). <path>: the path as typed,
                 in single quotes. <value>, <key>: the value or key as found — text in
                 single quotes, a number as its digits, null as None, true as True.
                 <error>: the text of the reader's error. <field>:
                 include.addresses[<i>].start or include.addresses[<i>].end; <i> counts
                 from 0.
```

### CTX-RPT-DIALOG · The Reports dialog (S12.12)

```text
Reports dialog    Title "Reports (project '<project>'):" with the 📂 Open reports/ chip and
                  the ? chip (S7 CTX-HELP); then, top to bottom:
  report list     The project's report files, or the empty text
                  "No reports in this project yet - use 'Generate new report' below."
  report view     The selected report file, rendered as Markdown.
  region box      Label "Declared regions (name,start,end per line):" (CTX-RPT-ADDENDUM).
  filter row      "Filter:", the filter dropdown (a blank option, then the filter files),
                  the filter path box (hint "filter path (blank = full report)").
  bottom row      "Context bytes:" box (64 when the dialog opens), the buttons
                  Generate new report and Close.
report files      The .md files of <project>/reports/. Flow reports use the report name
                  form too (S15 CTX-FLOWREPORT); before/after, diff and chain-set reports
                  do not (S14, S15).
list order        Report names first, newest first by (timestamp, NN), a name with no NN
                  counting as 00; then the other report files, by name.
viewer cap        4,194,304 bytes (twice the size budget).
too-large text    "This report file is larger than the viewer cap and was not rendered. It
                  remains available on disk."
unreadable text   "This report file could not be read."
Dialog behaviour common to all dialogs (Escape, focus, button keys, paste limit): S7.
```

### CTX-RPT-RUN · Generating a report (S12.13, S12.14)

```text
kept execution    The results of the last "Execute over variants" run (S11 S11.13), kept
                  with the project folder they belong to.
new run           A run of the active variant's documents (S11 CTX-EXEC, scope active)
                  that the report starts itself.
progress bar      The progress bar of the status bar (S6).
report progress line  The progress line (S6) of a project report: label
                  `Generating the project report`; steps 1 `Prepare the results`,
                  2 `Write the report`.
log line          report kind=project source=<project folder name> output=<report path
                  or -> outcome=<outcome>
                  <outcome>: ok · rejected: <reason> · failed: <error type> ·
                  refused: <status text>
<error type>      The name of the error, e.g. FileExistsError, OSError.
```

---

## 4. The chapter, rewritten

Form column: U = ubiquitous. "Code today": **Yes; tested** (test name given), **Yes; untested**, **Yes** (not checked for a test), **Partly** / **No** with the decision.

### S12.1 · The report file (CTX-RPT-FILE)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-RPT-001.1 | When | When the system generates a project report, the system shall write it as one report file in `<project>/reports/`. | Yes; tested (test_filename_regex_and_same_second_collision). |
| R-RPT-001.2 | When | When the system generates a project report, the system shall name the file `<timestamp>-report.md` after the UTC time of generation. | Yes; tested (test_filename_regex_and_same_second_collision). |
| R-RPT-001.3 | If | If that name is taken, then the system shall use the first free name from `<timestamp>-01-report.md` to `<timestamp>-99-report.md`. | Yes; tested (test_filename_regex_and_same_second_collision). |
| R-RPT-001.4 | If | If all 100 names of that second are taken, then the system shall refuse the report with the status `Report failed: FileExistsError: 100 reports already exist for second <timestamp> - refusing to overwrite an existing report`. | Yes; untested. |
| R-RPT-001.5 | If | If `<project>/reports/` does not exist when the system writes a report, then the system shall create it. | Yes; tested (test_reports_dir_created_on_demand_stays_neutral). |
| R-TUI-097.1 | U | The system shall write a report file as UTF-8 text with LF line ends on every host. | Yes; tested (test_at172b_the_unpatched_report_is_exactly_the_encoder_output; test_at175_written_report_carries_no_cr_on_a_crlf_host runs on Windows only). |
| R-RPT-001.6 | U | The system shall write the sections of a report in the order of CTX-RPT-FILE. | Yes; tested (test_full_report_content). |
| R-RPT-001.7 | U | The system shall write no report content to the log. | Yes; tested (test_format_report_log_line_is_metadata_only, test_entropy_section_confidentiality_no_raw_bytes_or_logging). |

### S12.2 · Header, inventory, overview, legend

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-RPT-001.8 | When | When the system writes a report, the system shall start it with the title and the header lines of CTX-RPT-FILE. | Yes; tested (test_full_report_content). |
| R-RPT-001.9 | When | When the system writes a report built from the kept execution, the system shall write that execution's scope as the execution mode. | Yes; tested (test_generate_trigger_calls_service_and_drops_results). |
| R-RPT-001.10 | When | When the system writes a report built from the kept execution, the system shall write that execution's assignment source. | Yes; tested (test_generate_trigger_calls_service_and_drops_results). |
| R-RPT-001.11 | When | When the system writes a report built from a new run, the system shall write `- Execution mode: active-only`. | Yes; untested. |
| R-RPT-001.12 | When | When the system writes a report built from a new run of a project that has a `project.json`, the system shall write `- Assignment source: manifest`. | Yes; untested. |
| R-RPT-001.13 | When | When the system writes a report built from a new run of a project that has no `project.json`, the system shall write `- Assignment source: default`. | Yes; untested. |
| R-RPT-001.14 | When | When the system writes a report, the system shall write one inventory row per variant of the project, in the project's variant order. | Yes; tested (test_full_report_content). |
| R-RPT-001.15 | When | When the system writes a report, the system shall write one overview row per reported variant, in run order. | Yes; tested (test_full_report_content). |
| R-LEGEND-REPORT-001.1 | When | When the system writes a report, the system shall write the legend section with one `### <block>` part per block of S3 CTX-LEGEND. | Yes; tested (test_report_includes_legend_with_documented_rows). |
| R-LEGEND-REPORT-001.2 | When | When the system writes a legend row whose label is its colour name, the system shall write it as `- **<label>** — <meaning>`. | Yes; tested (test_legend_lines_renders_shared_table). |
| R-LEGEND-REPORT-001.3 | When | When the system writes a legend row whose label is not its colour name, the system shall write it as `- **<label>** (<colour>) — <meaning>`. | Yes; tested (test_legend_lines_renders_shared_table). |

The legend rows themselves, and the rule that the report and the legend window show the same rows, are S3's (R-LEGEND-SOURCE-001, R-LEGEND-011).

### S12.3 · The sections of a variant (CTX-RPT-FILE, CTX-RPT-CELLS)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-RPT-001.16 | When | When the system writes a reported variant, the system shall write the heading `## Variant: <variant id>`. | Yes; tested (test_full_report_content). |
| R-RPT-001.17 | When | When the system writes a variant's Modified files section, the system shall write one modified-file line per change document of the run with at least one applied entry, in run order. | Yes; tested (test_full_report_content). |
| R-RPT-001.18 | If | If no change document of the variant's run has an applied entry, then the system shall write `No files were modified for this variant.` in its Modified files section. | Yes; tested (test_full_report_content). |
| R-RPT-001.19 | When | When the system writes a variant's Modifications section, the system shall write one table row per change entry of the run, in document order. | Yes; tested (test_full_report_content). |
| R-RPT-001.20 | When | When the system writes a Modifications row, the system shall fill Address, Length, Before, After, Linkage and Symbol from the entry's change summary (S8 CTX-APPLY) as CTX-RPT-CELLS defines them. | Yes; tested (test_full_report_content). |
| R-RPT-001.21 | If | If the variant's run has no change entry, then the system shall write `No change entries were executed for this variant.` in its Modifications section. | Yes; tested (test_full_report_content). |
| R-RPT-001.22 | When | When the system writes a variant's Declaration errors section, the system shall write one issue line per issue of its change documents and then of its check documents, in run order. | Yes; tested (test_full_report_content). |
| R-RPT-ISSUE-FIELDS-001.1 | When | When the system writes an issue line for an issue with an address, the system shall add ` @ <hex address>` after the message. | Yes; tested (test_report_issue_line_shows_address_symbol_related, test_report_issue_address_zero_renders). |
| R-RPT-ISSUE-FIELDS-001.2 | If | If the issue has no address, then the system shall write no address part in its issue line. | Yes; tested (test_report_issue_without_address_has_no_hex). |
| R-RPT-ISSUE-FIELDS-001.3 | When | When the system writes an issue line for an issue with a symbol, the system shall add ` symbol=<symbol>`. | Yes; tested (test_report_issue_line_shows_address_symbol_related). |
| R-RPT-ISSUE-FIELDS-001.4 | If | If the issue has no symbol, then the system shall write no symbol part in its issue line. | Yes; untested. |
| R-RPT-ISSUE-FIELDS-001.5 | When | When the system writes an issue line for an issue with related artifacts, the system shall add ` related=<artifacts>` with the artifacts separated by commas. | Yes; tested (test_report_issue_line_shows_address_symbol_related). |
| R-RPT-ISSUE-FIELDS-001.6 | If | If the issue has no related artifact, then the system shall write no related part in its issue line. | Yes; untested. |
| R-RPT-001.23 | If | If the variant has no issue, then the system shall write `None.` in its Declaration errors section. | Yes. |
| R-RPT-001.24 | If | If a variant has more than 200 issues, then the system shall write the issue lines of the first 200. | Yes; tested (test_tc397_declaration_errors_are_capped_with_a_visible_marker). |
| R-RPT-001.25 | If | If a variant has more than 200 issues, then the system shall add the line `> TRUNCATED: <n> of <total> declaration errors omitted (cap: 200 issues per variant).` after them. | Yes; tested (test_tc397_declaration_errors_are_capped_with_a_visible_marker). |
| R-RPT-001.26 | When | When the system writes a check document of a variant's Checklists section, the system shall write the heading `#### Checklist: <path>`. | Yes; tested (test_full_report_content). |
| R-RPT-001.27 | When | When the system writes a check document of a variant's Checklists section, the system shall write its count line with the document's aggregate counts before any filter. | Yes; tested (test_full_report_content). |
| R-RPT-001.28 | When | When the system writes a check document of a variant's Checklists section, the system shall write one table row per entry with Address, Length, Expected, Actual and Result, in document order. | Yes; tested (test_full_report_content). |
| R-RPT-001.29 | If | If the variant's run has no check document, then the system shall write `No checklists were executed for this variant.` in its Checklists section. | Yes; tested (test_full_report_content). |

### S12.4 · Hexdumps (CTX-RPT-HEX)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-RPT-001.30 | When | When the system writes a variant's Memory regions section, the system shall write one block per window of its applied entries, in address order. | Yes; tested (test_full_report_content). |
| R-RPT-001.31 | U | The system shall compute each window as CTX-RPT-HEX defines it. | Yes; tested (test_window_math_region_at_address_zero, test_window_math_region_at_image_top, test_window_math_adjacent_windows_merge, test_report_level_edge_windows). |
| R-RPT-001.32 | U | The system shall write each block's rows in the row format of CTX-RPT-HEX inside a fenced code block marked `text`. | Yes; tested (test_at161_an_all_backtick_image_cannot_close_the_hexdump_fence). |
| R-RPT-001.39 | When | When the system writes a block, the system shall head it `Window 0x<first address>-0x<last address>:` with both addresses inside the window. | No: the second address is the first address after the window (D12-26). |
| R-RPT-001.33 | If | If a window has more than 512 rows, then the system shall write its first 512 rows after the line `... window limited to 512 rows ...`. | Yes. |
| R-RPT-001.34 | If | If the variant's run has no applied entry, then the system shall write `No modified regions.` in its Memory regions section. | Yes; tested (test_full_report_content). |
| R-RPT-001.35 | If | If the variant's image after the run is not available, then the system shall write `Post-change memory map unavailable - hexdumps omitted.` in its Memory regions section. | Yes; untested. |
| R-RPT-001.36 | If | If a variant has more than 128 applied entries, then the system shall dump the windows of the first 128 in document order. | Yes; tested (test_region_cap_marker_exact_omitted_count). |
| R-RPT-001.37 | If | If a variant has more than 128 applied entries, then the system shall write `> TRUNCATED: <n> of <total> modified regions omitted (cap: 128 regions per variant).` before its blocks. | Yes; tested (test_region_cap_marker_exact_omitted_count). |
| R-RPT-001.38 | If | If some blocks of a variant were left out by the size budget, then the system shall write `> TRUNCATED: <n> hexdump block(s) omitted (report size cap: 2097152 bytes).` after its blocks. | Yes; tested (test_total_bytes_cap_marker). |
| R-RPT-001.40 | When | When the system writes a TRUNCATED line in a Memory regions section, the system shall add its truncation note to the truncation appendix. | Yes; tested (test_region_cap_marker_exact_omitted_count). |

### S12.5 · Entropy (from S4)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-RPT-ENT.1 | When | When the system writes a reported variant, the system shall write an Entropy section after its Memory regions section. | Yes; tested (test_report_contains_entropy_section_on_disk). |
| R-RPT-ENT.2 | When | When the system writes an Entropy section, the system shall write one band line per band of S4 CTX-ENTROPY that holds a window of the variant's image, in band order. | Yes; tested (test_entropy_lines_shape_direct_call). |
| R-RPT-ENT.3 | If | If some of a band's windows are low confidence (S4 R-ENT-004), then the system shall add ` (<k> low-confidence)` to its band line. | Yes. |
| R-RPT-ENT.4 | If | If the variant's image holds no byte, then the system shall write `No mapped bytes - entropy not computed.` in its Entropy section. | Yes; tested (test_entropy_lines_empty_mem_map_no_crash). |
| R-RPT-ENT.5 | U | The system shall write no byte value in an Entropy section. | Yes; tested (test_entropy_section_confidentiality_no_raw_bytes_or_logging). |

### S12.6 · Cells and row caps (CTX-RPT-CELLS)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-101.1 | If | If a variant has more than 200 kept Modifications rows, then the system shall write the first 200. | Yes; tested (test_at240_modifications_admits_at_most_the_cap). |
| R-TUI-101.2 | If | If a variant has more than 200 kept Modifications rows, then the system shall add `> TRUNCATED: Modifications: <n> of <kept> rows omitted (cap: MAX_REPORT_ROWS_PER_VARIANT = 200 rows per variant).` under the table. | Yes; tested (test_tc543_notice_names_the_constant_its_value_and_the_total, test_at244_notice_counts_the_kept_rows_not_the_population). |
| R-TUI-101.3 | If | If a variant has more than 200 kept Checklists rows over all its check documents, then the system shall write the first 200. | Yes; tested (test_at241_checklist_cap_is_summed_across_check_files, test_tc546_cap_is_summed_over_three_check_files). |
| R-TUI-101.4 | If | If a check document loses kept rows to the row cap, then the system shall add `> TRUNCATED: Checklist: <path>: <n> of <kept> rows omitted (cap: MAX_REPORT_ROWS_PER_VARIANT = 200 rows per variant).` with that document's own counts. | Yes; tested (test_at245_saturated_check_file_states_its_own_drop). |
| R-TUI-101.5 | If | If a check document with kept rows comes after the row cap is spent, then the system shall write no table header for it. | Yes; tested (test_tc547_saturated_file_omits_the_table_header). |
| R-TUI-101.6 | If | If a byte cell would hold more than 171 bytes, then the system shall write the first 171 followed by ` … (+<n> more bytes)`. | Yes; tested (test_at242_byte_cell_is_bounded_and_states_the_elided_count, test_at243_checklist_byte_cells_are_bounded). |
| R-TUI-101.7 | U | The system shall write an address cell with at least 8 hexadecimal digits. | Yes; tested (test_full_report_content). |
| R-TUI-101.8 | If | If an address has more than 16 hexadecimal digits, then the system shall write `0x`, its first 16 digits and ` … (+<n> more hex digits)` in its address cell. | Yes; tested (test_at246_truncated_address_cannot_read_as_a_complete_one, test_tc549_elided_count_comes_from_the_value_not_the_raw_string). |
| R-TUI-102.8 | U | The system shall write a length cell in decimal. | Yes; tested (test_tc566_in_domain_values_render_decimally_and_keep_their_sign). |

### S12.7 · Text from files (CTX-RPT-TEXT)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-077.1 | When | When the system writes file-derived text into a report, the system shall write it as report-safe text with its field limit. | Yes; tested (test_census_every_planted_field_renders_verbatim, test_mode_a_neutralises_and_preserves). |
| R-TUI-077.2 | When | When the system writes a file path into a report, the system shall write it as path text. | Yes; tested (test_at162_paths_render_without_inserted_escapes, test_mode_b_never_truncates). |
| R-TUI-077.3 | U | The system shall write file-derived text into a report so that a Markdown reader shows it as text. | Yes; tested (test_at157_no_planted_field_produces_markup_in_the_app_viewer, test_at158_exported_file_is_inert_under_a_default_reader). |
| R-TUI-077.4 | U | The system shall keep every table row of a report at the column count of its table. | Yes; tested (test_at159_hostile_symbol_cannot_shift_table_columns, test_every_table_row_keeps_its_header_content). |

Known limit (informative): readers with extra syntax (`:emoji:`, `$…$`, `==mark==`) are not covered by "a Markdown reader" (CTX-RPT-TEXT); the old R-TUI-077 called this residual risk RR-1.

### S12.8 · Size budget (CTX-RPT-BUDGET)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-102.1 | When | When a section's line cost fits both the size budget left and the variant share left, the system shall admit the section into the report. | Yes; tested (test_tc574_reservation_and_budget_must_BOTH_admit). |
| R-TUI-102.2 | If | If a section does not fit, then the system shall leave the whole section out. | Yes; tested (test_tc557_a_refused_batch_does_not_grow_the_document). |
| R-TUI-102.3 | When | When the system has left a section out, the system shall still admit each later section that fits. | Yes; tested (test_tc558_refusal_does_not_latch). |
| R-TUI-102.4 | U | The system shall write the always-written lines of CTX-RPT-BUDGET whatever budget is left. | Yes; tested (test_at264_every_variant_heading_survives_a_fully_exhausted_budget, test_at255_pin_exhausted_report_is_still_usable). |
| R-TUI-102.5 | U | The system shall give each reported variant the variant share of CTX-RPT-BUDGET. | Yes; tested (test_at254_no_variant_vanishes_when_the_budget_is_spent_early, test_tc556_reservation_floor_covers_a_real_minimal_variant_record). |
| R-TUI-102.6 | If | If the system left a section out, then the system shall end the report with the omitted block of CTX-RPT-BUDGET. | Yes; tested (test_at253_every_drop_is_disclosed_with_its_byte_total, test_tc560_disclosed_bytes_equal_the_refused_line_bytes, test_tc561_disclosure_line_count_is_bounded_by_the_closed_label_set). |
| R-TUI-102.7 | U | The system shall keep a report file within the size ceiling of CTX-RPT-BUDGET. | Yes; tested (test_at250_document_never_exceeds_the_stated_ceiling, test_at251_ceiling_holds_across_the_variant_count, test_at252_ceiling_holds_across_the_check_file_count). |
| R-TUI-102.9 | If | If a truncation note exists, then the system shall write the appendix of CTX-RPT-BUDGET after the addendum. | Yes; tested (test_region_cap_marker_exact_omitted_count). |
| R-TUI-102.10 | If | If there are more than 64 truncation notes, then the system shall write 64 of them, taken one per variant in turn. | Yes; tested (test_tc559_appendix_retention_is_round_robin_not_first_come). |
| R-TUI-102.11 | If | If there are more than 64 truncation notes, then the system shall add `- <n> further note(s) across <d> variant(s) not itemised (cap: 64 notes).` to the appendix. | Yes; tested (test_tc559_appendix_retention_is_round_robin_not_first_come). |

### S12.9 · Declared regions and the addendum (CTX-RPT-ADDENDUM)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-RPT-ADDENDUM-002.1 | When | When the operator presses Generate new report, the system shall take as declared regions the lines of the region box that are neither blank nor skipped lines, in box order. | Yes; tested (test_declared_region_in_dialog_reaches_report_addendum, test_parse_declared_regions_handles_hex_dec_and_skips_malformed). |
| R-RPT-ADDENDUM-001.1 | When | When the system reads a line of the region box, the system shall remove the white space around each field. | Yes. |
| R-RPT-ADDENDUM-001.2 | When | When the system reads a line of the region box, the system shall read start and end as region numbers. | Yes; tested (test_parse_declared_regions_handles_hex_dec_and_skips_malformed). |
| R-RPT-ADDENDUM-001.3 | When | When the system reads a region name from the region box, the system shall remove its control characters and terminal escape sequences. | Yes; tested (test_name_is_scrubbed_of_control_and_ansi). |
| R-RPT-ADDENDUM-001.4 | If | If a region name is longer than 80 characters, then the system shall cut it to 80 characters ending in `…[truncated]`. | Yes; tested (test_name_is_length_capped). |
| R-RPT-REGION-SKIP-001.1 | If | If a line of the region box is a skipped line, then the system shall leave it out of the declared regions. | Yes; tested (test_skipped_malformed_line_counted, test_skipped_invalid_line_counted). |
| R-RPT-REGION-SKIP-001.2 | If | If one or more lines of the region box are skipped lines, then the system shall show the notice `<n> region line(s) skipped`. | Yes; tested (test_skipped_malformed_line_counted, test_parse_returns_skip_count). |
| R-RPT-REGION-SKIP-001.3 | If | If no line of the region box is a skipped line, then the system shall show no skip notice. | Yes; tested (test_zero_skip_suppresses_notify, test_all_valid_no_skip_message). |
| R-RPT-REGION-SKIP-001.4 | U | The system shall count no blank line of the region box as skipped. | Yes; tested (test_skipped_count_excludes_blank). |
| R-RPT-ADDENDUM-002.2 | When | When the system writes a report with declared regions, the system shall write the addendum of CTX-RPT-ADDENDUM after the last reported variant. | Yes; tested (test_addendum_lists_region_with_mods_and_issues). |
| R-RPT-ADDENDUM-002.3 | If | If a report has no declared region, then the system shall write no addendum. | Yes; tested (test_tc485_addendum_is_guarded_by_a_non_empty_declared_region_set). |
| R-RPT-ADDENDUM-002.4 | When | When the system writes a declared region in the addendum, the system shall list its hit lines in hit order over all reported variants. | Yes; tested (test_addendum_lists_region_with_mods_and_issues, test_tc494_emission_order_is_result_summary_interleaved). |
| R-RPT-ADDENDUM-002.5 | U | The system shall take an address as in a declared region when it is at least start and at most end. | Yes; tested (test_addendum_membership_inclusive_at_bounds, test_membership_is_inclusive_at_both_bounds). |
| R-RPT-ADDENDUM-002.6 | If | If a declared region has no hit, then the system shall write `None.` under its heading. | Yes; tested (test_addendum_region_with_no_hits_shows_none). |
| R-RPT-ADDENDUM-002.7 | When | When a hit lies in several declared regions, the system shall list it under each of them. | Yes; tested (test_tc486_membership_is_sound_over_nested_overlapping_regions, test_tc487_duplicate_and_equal_start_nested_regions_each_emit). |
| R-TUI-098.1 | If | If more than 200 hits of one kind fall in one declared region, then the system shall list the first 200 of that kind in hit order. | Yes; tested (test_tc483_above_the_bound_is_capped_and_line_count_is_bounded, test_tc482_exactly_at_the_bound_renders_k_hits_and_no_notice). |
| R-TUI-098.2 | If | If more than 200 hits of one kind fall in one declared region, then the system shall add under that region `> TRUNCATED: <kind> hits in this region were capped at 200; <n> more not listed (variants affected: <variants>).` | Yes; tested (test_at197_notice_names_cut_class_dropped_count_and_exact_variant_set, test_at203_notice_sits_under_the_flooded_regions_subsection). |
| R-TUI-098.3 | When | When the system writes such a notice, the system shall name in `<variants>` the first 8 variants that lost a hit of that kind, then `+<k> more` for the others. | Yes; tested (test_tc490_notice_caps_the_variant_list_with_a_plus_n_more_remainder, test_at202_a_variant_that_lost_nothing_is_never_named). |

`<kind>`: modification · change-file issue · check-file issue. Keeping the regions for the next project save, the pre-filled box and the manifest form are S11's (R-RPT-REGION-PERSIST-001.x, 002.x, R-RPT-ADDENDUM-PERSIST-001.x).

### S12.10 · Report filter: reading a filter file (CTX-RPT-FILTER)

Each diagnostic row's message is one of the diagnostics the refusal status of R-RPT-FILTER-001.19 lists.

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-RPT-FILTER-001.18 | When | When the system generates a project report with a filter selected, the system shall read the filter file again. | Yes. |
| R-RPT-FILTER-001.22 | If | If the filter path names no file, then the system shall give the diagnostic `report filter path could not be resolved: <path>`. | Yes; tested (test_unresolvable_path_is_one_error). |
| R-RPT-FILTER-001.23 | If | If the filter path is a link, then the system shall give the diagnostic `report filter path is a symlink and was refused: <path>`. | Yes; tested (test_symlink_refused_at_read_time). |
| R-RPT-FILTER-001.24 | If | If the filter path names something that is not a regular file, then the system shall give the diagnostic `report filter path is not a regular file: <path>`. | Yes; tested (test_directory_path_refused_as_non_regular_file). |
| R-RPT-FILTER-001.25 | If | If the filter file is larger than 4,194,304 bytes, then the system shall give the diagnostic `report filter file is <n> bytes, over the 4194304-byte read cap — the file was not read`. | Yes; tested (test_over_cap_file_rejected_before_read). |
| R-RPT-FILTER-001.26 | If | If the filter file is larger than 4,194,304 bytes, then the system shall read none of its content. | Yes; tested (test_over_cap_file_rejected_before_read). |
| R-RPT-FILTER-001.27 | If | If the filter file is not UTF-8, then the system shall give the diagnostic `report filter file is not valid UTF-8: <error>`. | Yes; tested (test_non_utf8_bytes_is_one_error_no_exception). |
| R-RPT-FILTER-001.28 | If | If the filter file cannot be read, then the system shall give the diagnostic `report filter file could not be read: <error>`. | Yes; untested. |
| R-RPT-FILTER-001.29 | If | If the filter text is not JSON, then the system shall give the diagnostic `report filter is not valid JSON: <error>`. | Yes; tested (test_malformed_json_is_errors_no_exception). |
| R-RPT-FILTER-001.30 | If | If the top level of the filter text is not a JSON object, then the system shall give the diagnostic `report filter top level must be a JSON object`. | Yes; tested (test_non_object_top_level_is_errors_no_exception). |
| R-RPT-FILTER-001.31 | If | If `format` is missing or is not `s19app-report-filter`, then the system shall give the diagnostic `'format' must be 's19app-report-filter', got <value>`. | Yes; tested (test_wrong_format, test_missing_format). |
| R-RPT-FILTER-001.32 | If | If `version` is missing or is not `1.0`, then the system shall give the diagnostic `'version' must be '1.0', got <value>`. | Yes; tested (test_wrong_version, test_missing_version). |
| R-RPT-FILTER-001.33 | If | If the top level has a key other than `format`, `version` and `include`, then the system shall give the diagnostic `unknown top-level key <key>` for that key. | Yes; tested (test_unknown_top_level_key). |
| R-RPT-FILTER-001.34 | If | If `include` is not a JSON object, then the system shall give the diagnostic `'include' must be a JSON object`. | Yes; untested. |
| R-RPT-FILTER-001.35 | If | If `include` has a key other than `symbols` and `addresses`, then the system shall give the diagnostic `unknown 'include' key <key>` for that key. | Yes; tested (test_unknown_include_key). |
| R-RPT-FILTER-001.36 | If | If `include.symbols` is not a list, then the system shall give the diagnostic `'include.symbols' must be a list`. | Yes; tested (test_non_list_symbols). |
| R-RPT-FILTER-001.37 | If | If `include.symbols` holds more than 4096 patterns, then the system shall give the diagnostic `'include.symbols' declares <n> patterns, over the 4096-pattern ceiling`. | Yes; tested (test_symbols_ceiling_boundary_exact). |
| R-RPT-FILTER-001.38 | If | If a pattern is not text, then the system shall give the diagnostic `'include.symbols[<i>]' must be a string, got <value>`. | Yes; tested (test_non_string_pattern_names_its_index). |
| R-RPT-FILTER-001.39 | If | If `include.addresses` is not a list, then the system shall give the diagnostic `'include.addresses' must be a list`. | Yes; tested (test_non_list_addresses). |
| R-RPT-FILTER-001.40 | If | If `include.addresses` holds more than 4096 ranges, then the system shall give the diagnostic `'include.addresses' declares <n> ranges, over the 4096-range ceiling`. | Yes; tested (test_addresses_ceiling_boundary_exact). |
| R-RPT-FILTER-001.41 | If | If a range is not a JSON object, then the system shall give the diagnostic `'include.addresses[<i>]' must be a JSON object`. | Yes; untested. |
| R-RPT-FILTER-001.42 | If | If a range's start or end is true or false, then the system shall give the diagnostic `'<field>' must be an integer or '0x' hex string, got a boolean`. | Yes; untested. |
| R-RPT-FILTER-001.43 | If | If a range's start or end is text starting with `0x` that is not hexadecimal, then the system shall give the diagnostic `'<field>' is not a parsable hex string: <value>`. | Yes; tested (test_non_parsable_address_names_its_key). |
| R-RPT-FILTER-001.44 | If | If a range's start or end is missing, or is neither a whole number nor text starting with `0x`, then the system shall give the diagnostic `'<field>' must be an integer or '0x' hex string, got <value>`. | Yes; tested (test_missing_address_key_names_its_key). |
| R-RPT-FILTER-001.45 | If | If a range's start is below 0, then the system shall give the diagnostic `'include.addresses[<i>].start' (<start>) is outside the pinned address domain (must be >= 0)`. | Yes; tested (test_negative_start_rejected). |
| R-RPT-FILTER-001.46 | If | If a range's end is above 2^32, then the system shall give the diagnostic `'include.addresses[<i>].end' (0x<end>) is outside the pinned address domain (must be <= 2^32)`. | Yes; tested (test_end_over_address_space_rejected). |
| R-RPT-FILTER-001.47 | If | If a range's start is not below its end, then the system shall give the diagnostic `'include.addresses[<i>]': 'start' (0x<start>) must be less than 'end' (0x<end>) — 'end' is exclusive`. | Yes; tested (test_start_equal_to_end_rejected, test_start_greater_than_end_rejected). |
| R-RPT-FILTER-001.48 | When | When the system reads a filter text, the system shall give one diagnostic per fault it finds. | Yes; tested (test_n_fault_file_yields_at_least_n_diagnostics). |
| R-RPT-FILTER-001.49 | If | If a filter file has no `include`, `symbols` or `addresses` key, then the system shall read that key as an empty list. | Yes; tested (test_d10a_missing_include_keys_parse_ok_and_match_only_present). |

### S12.11 · Report filter: selection and use (CTX-RPT-FILTER)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-RPT-FILTER-001.1 | When | When the system opens the Reports dialog, the system shall list in the filter dropdown the `.json` files of the filters folder, sorted by name. | Yes; tested (test_tc316_scan_sorted_symlink_skipped_absent_dir_and_validate). |
| R-RPT-FILTER-001.2 | If | If a `.json` file of the filters folder is a link, then the system shall leave it out of the filter dropdown. | Yes; tested (test_tc316_scan_sorted_symlink_skipped_absent_dir_and_validate). |
| R-RPT-FILTER-001.3 | U | The system shall show filter file names in the filter dropdown as plain text, never as markup. | Yes; tested (test_at_056b_hostile_filename_populates_and_renders_literally). |
| R-RPT-FILTER-001.4 | When | When the operator picks a filter file in the dropdown, the system shall make it the filter selection. | Yes; tested (test_at_056a_dropdown_selection_filters_both_triggers). |
| R-RPT-FILTER-001.5 | When | When the operator makes a filter file the filter selection, the system shall show the status `Report filter: <file name>`. | Partly: over 50 characters the status is `<file name>` alone (D12-22). |
| R-RPT-FILTER-001.6 | When | When the operator picks the blank option of the dropdown, the system shall clear the filter selection. | Yes. |
| R-RPT-FILTER-001.7 | When | When the operator clears the filter selection, the system shall show the status `Report filter: none (full report)`. | Yes; untested. |
| R-RPT-FILTER-001.8 | When | When the operator submits a filter path, the system shall find the file by the path-input rules of S5.3. | Partly: also searches up to 6 parent folders for a repository root (D5-8, S5). |
| R-RPT-FILTER-001.9 | If | If the submitted filter path names no file, then the system shall show the status `Filter path not found: <path>`. | Yes; tested (test_tc317_typed_path_resolution_and_swap_refusals). |
| R-RPT-FILTER-001.10 | If | If the submitted filter path is a link, then the system shall show the status `Filter path is a symlink - refused: <path>`. | Yes; tested (test_tc317_typed_path_resolution_and_swap_refusals). |
| R-RPT-FILTER-001.11 | If | If the submitted filter path names something that is not a file, then the system shall show the status `Filter path is not a file: <path>`. | Yes; untested. |
| R-RPT-FILTER-001.12 | If | If the system refuses a submitted filter path, then the system shall keep the filter selection it had. | Yes. |
| R-RPT-FILTER-001.13 | When | When the system accepts a submitted filter path, the system shall make that file the filter selection. | Yes; tested (test_at_056d_typed_path_valid_filters_missing_refuses). |
| R-RPT-FILTER-001.14 | When | When the operator submits a blank filter path, the system shall clear the filter selection. | No: a blank submit is ignored, although the box's hint says `blank = full report` (D12-21). |
| R-RPT-FILTER-001.15 | When | When the system opens the Reports dialog while the filter selection is a file of the filters folder, the system shall show that file in the dropdown. | Yes. |
| R-RPT-FILTER-001.58 | When | When the system opens the Reports dialog while the filter selection is a file outside the filters folder, the system shall show its path in the filter path box. | Yes. |
| R-RPT-FILTER-001.16 | When | When the system loads a project, a file or a variant, or saves a project, the system shall clear the filter selection. | Yes; tested (test_at_056a3_project_switch_resets_selection_next_report_unfiltered). |
| R-RPT-FILTER-001.17 | U | The system shall apply the filter selection to every project report until the selection changes. | Yes; tested (test_at_056a_dropdown_selection_filters_both_triggers). |
| R-RPT-FILTER-001.19 | If | If a filter file gives a diagnostic when the operator generates a project report, then the system shall show the status `Project report refused: <diagnostics>` with the diagnostics separated by `; `. | Yes; tested (test_at_053a_invalid_filter_refuses_both_surfaces_zero_files). |
| R-RPT-FILTER-001.20 | If | If the system refuses a project report for its filter, then the system shall write no report file. | Yes; tested (test_at_053a_invalid_filter_refuses_both_surfaces_zero_files). |
| R-RPT-FILTER-001.21 | If | If the system refuses a project report for its filter, then the system shall run no variant. | Yes; tested (test_tc_generate_refusal_half_invalid_filter_refuses_before_worker). |
| R-RPT-FILTER-001.50 | U | The system shall match an entry against the filter as CTX-RPT-FILTER "item match" defines it. | Partly: the entry's own symbol is not tried, only its linkage symbol (D12-27). |
| R-RPT-FILTER-001.51 | When | When the system writes a filtered report, the system shall write only the Modifications rows that match the filter. | Yes; tested (test_tc314_filtered_sections_and_audit_header). |
| R-RPT-FILTER-001.52 | When | When the system writes a filtered report, the system shall write only the Checklists rows that match the filter. | Yes; tested (test_tc314_filtered_sections_and_audit_header). |
| R-RPT-FILTER-001.53 | When | When the system writes a filtered report, the system shall dump only the windows of the applied entries that match the filter. | Yes; tested (test_tc314_filtered_sections_and_audit_header). |
| R-RPT-FILTER-001.54 | When | When the system writes a filtered report, the system shall write the filter block of CTX-RPT-FILTER right after the title. | Yes; tested (test_tc314_filtered_sections_and_audit_header, test_at_055a_generate_surface_filtered_report_with_audit_header). |
| R-RPT-FILTER-001.55 | If | If no item of a variant's Modifications, Checklists or Memory regions section matches the filter, then the system shall write the zero-match text in place of that section's content. | Yes; tested (test_tc314_zero_match_notice_report_still_written, test_at_055c_generate_surface_zero_match_notice). |
| R-RPT-FILTER-001.56 | When | When the system writes a filtered report, the system shall write every section other than the filtered parts in full. | Yes. |
| R-RPT-FILTER-001.57 | U | The system shall write the filter file name in the filter block as report-safe text. | Yes; tested (test_tc318_hostile_filter_name_and_patterns_sanitized). |

The same filter selection drives the before/after report, and the A↔B diff report ignores it: those rows are S14's.

### S12.12 · The Reports dialog and the report view (CTX-RPT-DIALOG)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-RPT-002.1 | When | When the operator asks for the Reports dialog with a project open, the system shall open the Reports dialog of CTX-RPT-DIALOG. | Yes; tested (test_report_viewer_lists_newest_first). |
| R-RPT-002.2 | If | If no project is open when the operator asks for the Reports dialog, then the system shall show the status `Reports: no active project - load a project first.` | Yes; tested (test_view_reports_no_project_neutral_status). |
| R-RPT-002.3 | When | When the system opens the Reports dialog, the system shall list the project's report files in the list order of CTX-RPT-DIALOG. | Partly: files that are not report names follow in the order the file system gives (D12-23). Report names: tested (test_list_project_reports_order). |
| R-RPT-002.4 | If | If the project has no report file, then the system shall show the empty text of CTX-RPT-DIALOG in place of the report list. | Yes; tested (test_empty_reports_dir_empty_state). |
| R-RPT-002.5 | When | When the operator selects a report file in the list, the system shall show it in the report view, rendered as Markdown. | Yes; tested (test_select_renders_markdown_open_links_false). |
| R-RPT-002.6 | If | If the selected file is larger than the viewer cap, then the system shall show the too-large text in the report view. | Yes; tested (test_oversized_report_refused). |
| R-RPT-002.7 | If | If the selected file cannot be read, then the system shall show the unreadable text in the report view. | Yes; untested. |
| R-RPT-002.8 | If | If the selected file holds a byte sequence that is not UTF-8, then the system shall show `�` in its place. | Yes; untested. |
| R-RPT-002.9 | When | When the operator clicks a link in the report view, the system shall open nothing. | Yes; tested (test_select_renders_markdown_open_links_false). |
| R-RPT-002.10 | U | The system shall show a bare web address in the report view as text, not as a link. | Yes; tested (test_at011_hardened_parser_kills_links_and_raw_html_keeps_tables, test_at011_report_viewer_uses_the_hardened_parser). |
| R-RPT-002.11 | U | The system shall show raw HTML in the report view as text. | Yes; tested (test_at011_hardened_parser_kills_links_and_raw_html_keeps_tables). |
| R-RPT-002.27 | While | While the screen is at least 80 columns wide, the system shall show the whole Reports dialog, the filter row and Generate new report included. | Yes; tested (test_report_dialog_with_region_input_fits_80_and_120_cols, test_at_056a2_selector_row_and_generate_visible_at_both_regimes). |
| R-RPT-CHIP.1 | When | When the operator presses the `📂 Open reports/` chip of the Reports dialog, the system shall open `<project>/reports/` in the system's file manager. | Yes. |

The key that opens the dialog (`t`, every window) is S6's; Escape, focus, and the plain-text rule for the report list are S7's (R-DLG.2, R-DLG.7, R-DLG.13); the Reports help window is S7's (R-WHELP.6). R-RPT-CHIP.1 comes from S0 HLR-139; the chip mechanism itself has no rows yet (passed to S5).

### S12.13 · Generating a report (CTX-RPT-RUN)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-RPT-002.12 | When | When the operator presses Generate new report with a whole number in the context-bytes box, the system shall close the Reports dialog. | Yes; tested (test_declared_region_in_dialog_reaches_report_addendum). |
| R-RPT-002.13 | If | If the context-bytes box does not hold a whole number when the operator presses Generate new report, then the system shall show the status `Report rejected: context_bytes must be an integer in 0..4096, got '<text>' - the value is rejected, not clamped`. | No: nothing happens; the dialog stays open with no message (D12-20). |
| R-RPT-002.14 | If | If the context bytes are outside 0 … 4096, then the system shall show the status `Report rejected: context_bytes must be an integer in 0..4096, got <n> - the value is rejected, not clamped`. | Yes; tested (test_at261_out_of_domain_operator_input_is_still_a_rejection, test_context_bytes_out_of_domain_rejected, `test_tc_b100_51_report_ends_once_on_a_failure` rejected arm). |
| R-RPT-002.15 | If | If the open project has no variant when the operator generates a report, then the system shall show the status `Report: no project variants - load a project first.` | Yes; untested. |
| R-RPT-002.16 | When | When the kept execution belongs to the open project, the system shall build the report from it. | Yes; tested (test_generate_trigger_calls_service_and_drops_results). |
| R-RPT-002.17 | When | When the system builds a report from the kept execution, the system shall show the status `Report: generating from last execution...`. | Yes. |
| R-RPT-002.18 | If | If no kept execution belongs to the open project, then the system shall build the report from a new run. | Yes; tested (test_report_seam_writes_real_file_on_disk). |
| R-RPT-002.19 | When | When the system starts a new run for a report, the system shall show the status `Report: no prior execution - running active scope...`. | Yes. |
| R-RPT-002.20 | If | If no kept execution belongs to the open project, the project has no `project.json` and no change or check document is loaded, then the system shall show the status `Report: no manifest and no loaded change/check file - nothing to report.` | Yes; untested. |
| R-RPT-002.21 | U | The system shall keep the screen responsive while it builds and writes a project report. | Yes. |
| R-RPT-002.22 | When | When the system has written a report, the system shall show the status `Report: reports/<file name>`. | Yes; tested (test_report_seam_surfaces_written_path_in_status, `test_tc_b100_51_report_ends_once_on_success`; `app.py:6397-6399`). |
| R-RPT-002.23 | When | When the system has written a report, the system shall drop the kept execution. | Yes; tested (test_generate_trigger_calls_service_and_drops_results). |
| R-RPT-002.24 | If | If the new run or the writing of the report fails, then the system shall show the status `Report failed: <error type>: <reason>`. | Partly: an error of kind ValueError during the new run shows `Report rejected: <reason>` (D12-24; re-verified at 570b4b5: the `except ValueError` still wraps the new run, `app.py:6252-6290`). Writing: tested (test_at260_a_valueerror_from_the_generator_is_the_tools_failure, `test_tc_b100_51_report_ends_once_on_a_failure`). |
| R-RPT-002.25 | If | If the system rejects a report or the report fails, then the system shall leave no report file. | Yes; tested (test_at262_pin_neither_path_leaves_a_report_behind). |
| R-RPT-002.26 | If | If the system rejects a report or the report fails, then the system shall keep the kept execution. | Yes. |

**(from batch-100 HLR-177a: LLR-177.3i)** Keeping the declared regions for the next project save is S11's (R-RPT-REGION-PERSIST-001.1); this row is the exception while a session action runs.

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-RPT-002.28 | While | While a file load, an A2L load, a project load or a Save project runs, the system shall keep the session's declared regions unchanged when the operator presses Generate new report. | Yes; tested (`test_tc_b100_53_report_generate_keeps_the_regions_of_a_running_save`). The report itself still runs with the box's regions (D12-29). |

### S12.14 · Progress and log (CTX-RPT-RUN)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-RPT-LOG.1 | When | When the system starts a project report, the system shall show the report progress line at step 1. | Yes; tested (test_kickoff_sets_bar_in_progress_before_worker, `test_tc_b100_50_each_worker_action_begins_with_a_progress_line`). Was 15 % (D12-28). |
| R-RPT-LOG.2 | When | When the system starts writing a project report after its run is ready, the system shall move the report progress line to step 2. | Yes; tested (test_report_generation_drives_progress_bar_then_clears_it: the bar reads 50 %). Was 55 % (D12-28). |
| R-RPT-LOG.3 | When | When the system has written a project report, the system shall end the report's long action (S6 CTX-BUSY) once. | Yes; tested (test_report_generation_drives_progress_bar_then_clears_it, test_finish_generate_report_clears_bar, `test_tc_b100_51_report_ends_once_on_success`: one end, bar 0 → 50 → 0 %). The bar returns to 0 % when no other long action runs (S6 R-PROGRESS-END.3); 100 % is never shown. Was 100 % (D12-28, D12-30). |
| R-RPT-LOG.4 | If | If the system rejects a project report or the report fails, then the system shall end the report's long action (S6 CTX-BUSY) once. | Yes; tested (test_failed_report_resets_progress_bar_to_zero, test_at263_pin_progress_resets_to_zero_on_both_branches, `test_tc_b100_51_report_ends_once_on_a_failure`: a failed run 0 → 50 → 0 %, a rejection before step 2 0 → 0 %). Was "set the progress bar to 0 %" (D12-30). |
| R-RPT-LOG.5 | When | When the system has written a report, the system shall log at INFO the log line with outcome `ok`. | Yes; tested (test_log_report_event_success_is_info, test_report_line_reaches_s19tui_log_file). |
| R-RPT-LOG.6 | If | If the system rejects a report, then the system shall log at WARNING the log line with outcome `rejected: <reason>`. | Yes; tested (test_log_report_event_failure_is_warning). |
| R-RPT-LOG.7 | If | If a report fails, then the system shall log at WARNING the log line with outcome `failed: <error type>`. | Yes; tested (test_tc571_the_failure_path_logs_a_failure_not_a_rejection). |
| R-RPT-LOG.8 | If | If a report fails, then the system shall write the error's traceback to the log. | Yes. |
| R-RPT-LOG.9 | If | If the system refuses a project report before it runs (no variant, nothing to report, filter refused), then the system shall log at WARNING the log line with outcome `refused: <status text>`. | No: these refusals are shown on the status line only (D12-25). |

---

## 5. Decisions: recommendation applied

**Requirement follows the code, or moves (no code change)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D12-1 | R-TUI-077, 097, 098, 101, 102 and R-RPT-FILTER-001 carry batch records: measurements, non-claims, mutant rosters, test lists, golden policy ("byte-identical to the pre-batch output"), corrections of earlier corrections. | Out of the requirements; they stay in their batch records. The tests stay. |
| D12-2 | Design rules inside requirements: the leaf escaping module and its circular-import reason (077), the shared encoder and the `_line_bytes` accounting (097), single-pass and `R`-independent candidate use (098), producer memory bounds and "no full-population list" (101), the admission seam `_EmissionGate` (102), filter resolution on the UI thread (FILTER), the headless service (002), the `DeclaredRegion` model (ADDENDUM-001). | Move to the design notes. Rows keep only what an operator or a reader of the file can observe. |
| D12-3 | R-RPT-002: "the activity rail stays at exactly eight items". | The rail and the `t` key are S6's rows. |
| D12-4 | R-TUI-078 (path redaction) was withdrawn before merge; host paths in reports are a backlog item (MAJOR) in the project's backlog. | Out of the requirements. The report writes the document paths as the run gives them (R-TUI-077.2); the backlog item stays where it is. |
| D12-5 | The report writes the run scope as `active-only` / `batch` / `per-assignment` (`report_service.py:503-507`), while status lines and S11 use `active` / `all` / `assignments`. | Keep the report words (existing reports stay comparable); CTX-RPT-FILE maps them. |
| D12-6 | In a hexdump, an address not in the image shows `.` in the text column (`render/hexview.py:275`), like a byte outside 0x20-0x7E; the screens show a space (S4 CTX-HEX). | Keep: the hex column shows two spaces for such an address, which tells them apart. CTX-RPT-HEX states it. |
| D12-7 | A written report drops the kept execution (`app.py:5310`), so the next report runs the active variant only. | Keep (the kept execution holds every variant's image). The status says which source a report uses (R-RPT-002.17, .19). |
| D12-8 | Region numbers are read with prefixes 0x, 0o, 0b and `_` between digits; a decimal with a leading zero (`0100`) is a skipped line (`screens.py:1474`). | Keep; CTX-RPT-ADDENDUM states it. S11's pre-fill writes decimal with no leading zero, so its lines are never skipped. |
| D12-9 | The addendum takes a change entry by its start address only, and lists entries of every disposition (`report_service.py:2955-2968`). | Keep; "hit" is defined in CTX-RPT-ADDENDUM. |
| D12-10 | Report-safe text differs from screen-safe text (S1 CTX-TEXT): a control character becomes `�` rather than disappearing, and each tab or line break is one space. | Keep: a report is a record, so a lost character is shown. CTX-RPT-TEXT defines it for reports only. |
| D12-28 | Batch-100 HLR-176 (Inc 12a, `6057896`; the busy-line verdict of its prototype round) replaced the report's fixed bar values 15 / 55 / 100 / 0 % with the shared progress line: the start paints `Generating the project report` at step 1 with the bar at 0, the worker moves to step 2 (50 %), and every end writes the outcome to the status log and returns the bar to 0 (`app.py:6153`, `:6309`, `:6397-6399`). The old tests were re-pinned and renamed (`…_drives_progress_bar_then_clears_it`, `…_finish_generate_report_clears_bar`). The review's R-RPT-LOG.1 … .3 still named 15, 55 and 100 %. | Batch-100 wins (more recent, prototyped and ruled): R-RPT-LOG.1 … .3 rewritten to the report progress line (CTX-RPT-RUN); R-RPT-LOG.4 keeps 0 %. The line's format, spinner, elapsed time and end rules are S6's. |
| D12-30 | R-RPT-LOG.3 and .4 (D12-28) set the progress bar to 0 % at every report end. S6 R-PROGRESS-END.3 sets it to 0 % only when the last running long action ends; while another long action runs, the bar shows that action's value (`end_busy`, `app.py:20338-20349`). A report can run during a session action (R-RPT-002.28), so the two rows disagreed in that case. Both describe the end of the report's progress. | Rows follow the code and S6: R-RPT-LOG.3, .4 end the report's long action once (the TC-B100-51 nodes check one end and the bar 0 → 50 → 0 %); the bar value and the outcome line at the end are S6's (R-PROGRESS-END.1, .3). |
| D12-29 | Batch-100 LLR-177.3i (Inc 12b, CR12b-3): while a session action runs, Generate new report still runs the report with the box's regions but leaves the session's declared regions as they were (`app.py:6044-6049`), since a running Save writes them to `project.json` and a running project load replaces them. Reports are not session actions, so a report is never refused as busy. | Row R-RPT-002.28. The regions kept for the next save stay S11's rows. |

**Remove (rule use/defer/delete)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D12-11 | `ReportOptions.include_legend` and `include_entropy` (`report_service.py:592-593`): the product never sets them (`app.py:5192-5198`); only tests turn them off. | Remove both switches and their off-tests; the legend and the Entropy section are always written (R-LEGEND-REPORT-001.1, R-RPT-ENT.1). |
| D12-12 | `_format_length` renders lengths too long for decimal as hexadecimal, with a sign (`report_service.py:1352-1366`); `_format_address` carries a sign branch (`:1257-1261`). A length is the byte count of an entry (`changes/model.py:193`, `apply.py:330`), at most 1 MiB, and the change-file reader admits no negative address. Neither branch can run. | Remove both branches and their tests; length in decimal (R-TUI-102.8). |
| D12-13 | `DeclaredRegion.contains` (`report_addendum.py:95-97`) is used only by tests, as their oracle. | Move it into the tests. |

**Code change: correct a defect**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D12-20 | Generate new report with a context-bytes value that is not a whole number does nothing: the dialog stays, no message (`screens.py:1866-1871`). | Show the same rejection status as for an out-of-range number (R-RPT-002.13). |
| D12-21 | The filter path box hint says `blank = full report` (`screens.py:1712`), but a blank submit is ignored (`:1855-1857`); a filter chosen by path can only be cleared through the dropdown. | A blank submit clears the filter selection (R-RPT-FILTER-001.14). |
| D12-22 | The filter confirmation drops `Report filter: ` when it is longer than 50 characters (`app.py:4941-4944`), a rule from when the status line was 50 wide; the status line now takes the terminal width (`app.py:15250`). | Always `Report filter: <file name>` (R-RPT-FILTER-001.5). |
| D12-23 | `.md` files of `reports/` that are not report names (the before/after, diff and chain-set reports of S14 and S15 among them) are listed in the order the file system returns them (`report_service.py:1456-1466`). | List them by name (R-RPT-002.3). |
| D12-24 | The rejection branch covers the new run (`app.py:5172-5206`), so an error of kind ValueError raised while running the variants is shown as `Report rejected:`, as if the operator had typed a wrong value. | Only the context-bytes check is a rejection; a failure of the run is `Report failed:` (R-RPT-002.24). |
| D12-25 | Refusals before the run (no variant, nothing to report, filter refused, `app.py:5033-5074`) are not logged, while `_log_report_event` states that no report action is silent in the log (`app.py:5252-5254`). | Log them with outcome `refused: <status text>` (R-RPT-LOG.9). |
| D12-26 | `Window 0x<low>-0x<high>:` gives the first address after the window (`report_service.py:2260`); the addendum's `(0x<start>-0x<end>)` gives the last address inside (`:3025`). | Write the last address inside the window (R-RPT-001.39). Every golden with a hexdump changes once. |
| D12-27 | The filter matches an entry by its linkage symbol only (`report_service.py:1552-1556`), while the Symbol cell shows the entry's own symbol first (`:1918`). A filter on the name the reader sees can hide that row. | Match the entry's own symbol or its linkage symbol (R-RPT-FILTER-001.50). |

**Prototype first**

None. No S12 finding changes the screen layout, widths, colours or glyphs. (The decimal pre-fill of the region box is S11's D11-41.)

**Passed to other groups**

- **S1**: the Reports dialog's report view shows text from a file: the system's own reports (already report-safe, CTX-RPT-TEXT) and any other `.md` file placed in `reports/`, rendered as Markdown with links and raw HTML off. Add the report view to the safe-text views for control characters and markup, keeping Markdown structure; the report list and the filter dropdown are already on S7's list (D7-28).
- **S3**: the report's legend section (R-LEGEND-REPORT-001.1 … .3) prints the same rows as the legend window; S3's D3-19 legend changes reach the report through R-LEGEND-SOURCE-001 with no S12 change.
- **S4**: R-ENT-004 (low confidence) is now shown in the report by R-RPT-ENT.3. The report's hexdump row format (CTX-RPT-HEX, `render/hexview.py:250-277`) differs from the screens' row format of CTX-HEX; S4 owns the renderer.
- **S5**: the 📂 folder chips have no rows anywhere (S0 HLR-139, LLR-139.1, LLR-139.2, LLR-148.10; S9 and S10 point to S5). S12 keeps only the Reports target (R-RPT-CHIP.1). The filter path box follows S5.3, so D5-8 applies to it (R-RPT-FILTER-001.8).
- **S6**: the `t` key and the palette entry that open the Reports dialog.
- **S7**: the Reports dialog's common behaviour (Escape D7-20, focus, button keys D7-31). R-RPT-002.13 adds a status where R-DLG.10 only keeps the dialog open.
- **S11**: reports read the kept execution of S11.13 (CTX-RPT-RUN); D12-24 moves the new run out of the rejection branch. The region box's Generate keeps the regions for the next save (R-RPT-REGION-PERSIST-001.1).
- **S14**: the filter selection also drives the before/after report (status `Before/after report refused: <diagnostics>`, `app.py:4373-4376`) and is ignored by the A↔B diff report; S14 writes those rows citing CTX-RPT-FILTER and S12.10. The log line format (`format_report_log_line`) is shared with kinds `before-after` and `diff`.
- **S15**: the flow report writer uses the same UTF-8 / LF rule (`flow_report_service.write_flow_report`); S15 cites R-TUI-097.1.
- **S0**: HLR-139's Reports part is now R-RPT-CHIP.1.

---

**Received from later groups** (after all groups were written)

- S12.1 (S3: the report's legend follows R-LEGEND-SOURCE-001; S3's defect items) → covered by R-LEGEND-REPORT-001.1 … .3; S3's changes reach the report with no S12 change (note above).
- S12.2 (S4: low confidence) → covered by R-RPT-ENT.3.
- S12.3 (S7: the Reports dialog) → covered by S12.9, S12.12, S12.13 (R-RPT-002.x, R-RPT-ADDENDUM-002.x, R-RPT-REGION-SKIP-001.x).
- S12.4 (S11: region box, Generate, the last execution) → covered by R-RPT-ADDENDUM-002.1, R-RPT-002.16 … .18, .23; keeping the regions is S11's (R-RPT-REGION-PERSIST-001.1, 002.3), keeping the execution is S11 R-VAR-002.42.
- S12.5 (S14, absorbed: the filter and the before/after and diff reports; LF) → covered by the note under S12.11 and R-TUI-097.1; the rows are S14's.
- S12.6 (S14: other reports in `reports/`, listed in no order) → covered by CTX-RPT-DIALOG ("report files", "list order") and R-RPT-002.3 (D12-23: by name).
- S12.7 (S15, absorbed: R-TUI-097.1; the flow report's name and budget) → covered by R-TUI-097.1 and CTX-RPT-DIALOG (flow reports use the report name form).

**Reconciled with batch-100 (s19_app 570b4b5)**

- Rows added (1): R-RPT-002.28 (Generate keeps the session's regions while a session action runs, LLR-177.3i).
- Rows changed (3): R-RPT-LOG.1, .2, .3 (the report progress line replaces 15 / 55 / 100 %, D12-28). Cells changed (tests named or renamed): R-RPT-002.14, .22, .24, R-RPT-LOG.4. R-RPT-002.24 re-verified: still Partly (D12-24).
- Rows retired: none. Decisions added: D12-28, D12-29. Decisions superseded: none (the old values were row text, D12-28).
- Passed (scratch `passed-sweep.md`): S6 (the report action's label and steps are named in CTX-RPT-RUN), S11 (R-RPT-REGION-PERSIST-001.1 cites R-RPT-002.28 as its exception).
- Consolidation (items from S6, S11): rows changed in text R-RPT-LOG.3, .4 (end the report's long action once; the bar at the end is S6 R-PROGRESS-END.3), decision D12-30 added. Checked against S6 CTX-BUSY and the tests: label `Generating the project report`, steps `Prepare the results` · `Write the report`, bar 0 → 50 → 0 % (`test_tc_b100_51_report_ends_once_on_success`); the renamed tests (`…_drives_progress_bar_then_clears_it`, `…_finish_generate_report_clears_bar`) are the names cited. Already here: R-RPT-002.28 and its S11 cite. Not verified: whether `q` during a report quits at once (S6) and whether such a quit can leave a half-written report file.

## 6. Counts

| | Old S12 | Strict |
|---|---:|---:|
| Requirement statements | 14 rows (1 withdrawn) | 192 rows (191 + 1 from batch-100) |
| Statements the code contradicts or that are not product behaviour | 10 (002 rail and headless; LEGEND switch never set; ADDENDUM-001 data model; FILTER thread and golden rules, symbol match; 077 placement rules; 078 withdrawn; 097 encoder design; 098 memory design; 101 memory design; 102 unreachable length branch) | 0 |
| Rows by form: U / When / While / If / Where | — | 22 / 74 / 2 / 94 / 0 |
| Rows that could not be written in EARS | — | 0 |
| Decisions | — | 24 (13 follow the code or move, 3 remove, 8 correct a defect, 0 prototype first; numbers not contiguous) |

Checked by script (`ears_lint.py`): one `shall` per row, correct opening words per form, `If … then`, no "unless" / "only if", final period, no repeated id across `review/`.
