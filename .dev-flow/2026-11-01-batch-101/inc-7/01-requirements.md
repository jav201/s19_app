# Inc 7 — the before/after report names itself; written reports carry whole hex windows; the Markdown diff report escapes its text: requirements (E1)

Batch 2026-11-01-batch-101, increment 7. Base: `e266395` (branch `b101-inc7` = main). Stage E1 of the design-first flow (`dev-flow-v3-beta`).
Findings: F-42 (= CODE-CHANGES D14-15; DOSSIER §5, guide ch21.1, captures ch21-01 … 03), F6-1 (BACKLOG-CODE HIGH), D14-10 (P0 ruling: joins Inc 7). Scope, decisions and reasons: `E1-rulings.md`. Slice: `E1-slice.md`. Test cases: `02-test-cases.md`. Graph: `codewire/graph-inc7.md`.

Form column: U = ubiquitous, E = event (`When`), S = state (`While`), N = unwanted (`If … then`), O = optional (`Where`). Canon rows are cited by their `REQUIREMENTS.md` id; "new" rows get new ids in the owning S14 groups (checked absent from the canon at `e266395`). "Base" = what `e266395` does, measured by a read-only probe of the base tree from the session scratchpad unless a file:line is given.

## User stories

### US-BAR-1 — the before/after report names itself and its inputs
As the operator who applied a change document and wrote the patched image, I want the before/after report to be titled as a before/after report and to use the A2L and the MAC I have loaded, so that the file says what it is and its header and Runs table name the artifacts and symbols the patch touched. (F-42: titled "Diff report", `a2l=absent; mac=absent`, Symbols `-` although the A2L is loaded.)

### US-HEXWIN-1 — a written report carries every hex window whole
As the operator reading a written diff or before/after report, I want each hex window written from its first row to its last, so that the bytes of a long run are in the file and the Markdown and HTML copies of one report agree. (F6-1: every window cut at 512 rows; R-CMP-006.7 and batch-09 decision G-9 keep caps on the screen only.)

### US-MDESC-1 — names and paths stay plain text in the Markdown report
As the operator opening a diff report in a Markdown reader, I want image labels, paths and symbol names shown exactly as text, so that a name holding `_`, `*`, `|`, `<`, `[` or a backtick neither formats nor breaks the report. (D14-10, R-CMP-004.9.)

## Definitions

- **Diff report, before/after report, hex window, symbols.** S14 CTX-DIFFREPORT and CTX-BEFOREAFTER. The flow-A2B report (S15) is a diff report, Markdown only.
- **Hex window rows.** One row per 16 addresses, from the window's first address (a multiple of 16) up to its end: `0x<address, 8 hex digits>  <16 byte cells>  |<16 ASCII cells>|`; a byte cell is two uppercase hex digits, or two spaces where the image maps no byte; an ASCII cell is the byte's character for 0x20 … 0x7E, else `.`. (The format today; unchanged.)
- **Cap line.** A line `... window limited to <n> rows ...` or `... output truncated at <n> bytes ...` (the screen's hex-view caps, `render/hexview.py:231`, `:244`).
- **Label field.** In the Markdown file of a diff report: an image label and a variant id in the header's image lines; each symbol name in the Runs table, the Change-entry linkage table and the Flow change attribution section; each change-document reference in the Flow change attribution section; the filter file name in the `## Report filter applied` block.
- **Path field.** In the Markdown file of a diff report: the image path in each header image line (`path=` …), and the original image, saved patched image and change document paths of the `## Before/after provenance` section.
- **Control-stripped value.** The value with every character U+0000 … U+001F and U+007F removed (today's rule for the before/after provenance and linkage values, R-BEFORE-AFTER-REPORT-001.21).
- **Report-safe text, path text, field limit.** S12 CTX-RPT-TEXT.
- **Loaded A2L.** The A2L payload the session holds (S2). **Loaded MAC.** The MAC file the loaded image carries; none when no MAC file has been loaded, even though the loaded image then holds an empty MAC record list.
- **Artifact lines.** The two header lines `- Image <A or B> artifacts: summary=<s>; a2l=<status>[ (<covered>/<total>)]; mac=<status>[ (<covered>/<total>)]` (CTX-DIFFREPORT header).

## Requirements

### F-42 — the before/after report names itself and its inputs (US-BAR-1)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-BEFORE-AFTER-REPORT-001.32 | U | The system shall write `# Before/after report` as the first line of the before/after report's Markdown file. **new** | 1/1 composer report; 1/1 report written by key `b`; with a report filter the line at index 2 stays `## Report filter applied` (1/1) | title left as the constant `# Diff report` → RED; title chosen for every report → R-CMP-004.1/1 RED | US-BAR-1 | No: `# Diff report` (`diff_report_service.py:922`) |
| R-BEFORE-AFTER-REPORT-001.33 | U | The system shall write `<title>Before/after report</title>` in the head of the before/after report's HTML file. **new** | 1/1, and 0 `<title>Diff report</title>` in that file | `<title>` left constant → RED | US-BAR-1 | No: `<title>Diff report</title>` (`:2576`) |
| R-BEFORE-AFTER-REPORT-001.34 | U | The system shall write `<h1>Before/after report</h1>` as the first heading of the before/after report's HTML file. **new** | 1/1; with a report filter the next line is `<h2>Report filter applied</h2>` (1/1) | `<h1>` left constant → RED | US-BAR-1 | No: `<h1>Diff report</h1>` (`:1821`) |
| R-CMP-004.1 | U | The system shall write the sections of CTX-DIFFREPORT in their order. (canon, unchanged; in scope as the guard that a diff report keeps its title `# Diff report`) | a diff report without provenance: line 1 `# Diff report`, `<title>Diff report</title>`, `<h1>Diff report</h1>`, 3/3 | title switched by any input other than the before/after provenance → RED | US-BAR-1 | Yes |
| R-BEFORE-AFTER-REPORT-001.35 | E | When the system writes the before/after report, the system shall compute both images' artifact lines against the loaded A2L and the loaded MAC. **new** | example of `02-test-cases.md`: 2/2 artifact lines `summary=both; a2l=used (1/2); mac=used (1/1)`; through key `b`: 2/2 lines with `a2l=used (<k>/<n>)`, n = the loaded A2L's tags with an address | the composer stops forwarding the A2L to the compare → `a2l=absent` → RED | US-BAR-1 | No: `a2l=absent; mac=absent` always (`before_after_service.py:328-339` passes no artifact) |
| R-CMP-003.2 | N | If no A2L or no MAC is loaded, then the system shall give that artifact the status absent. (canon, unchanged; in scope for the before/after report) | no MAC loaded (image holds an empty MAC list): 2/2 lines `mac=absent`; no A2L loaded: 2/2 lines `a2l=absent` | the app forwards the image's empty MAC list → `mac=unused (0/0)` → RED | US-BAR-1 | Yes (nothing is forwarded today); at risk from the fix |
| R-BEFORE-AFTER-REPORT-001.24 | U | The system shall fill the run table's Symbols column of the before/after report from the loaded A2L and MAC. (canon, unchanged) | composer: 1/1 run row names the A2L tag and 1/1 the MAC record at an address in the run, both files; key `b` with the A2L loaded: the Symbols cell of the run that holds the tag's address names it (1/1) | the composer stops forwarding the A2L tags to the generators → `-` → RED | US-BAR-1 | No: `-` always (generators get no `a2l_records` / `mac_records`, `before_after_service.py:349-357`) |
| R-CMP-004.5 | U | The system shall fill the Symbols column as CTX-DIFFREPORT symbols. (canon, unchanged: a symbol is named when its address lies in the run) | a run inside a tag's extent that does not hold the tag's address: `-` (1/1), the run that holds the address: the name (1/1) | membership by extent overlap → the first cell names the tag → RED | US-BAR-1 | Yes |

### F6-1 — whole hex windows in every written report (US-HEXWIN-1)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-CMP-004.14 | U | The system shall write every row of each hex window, from the window's first address to its end, into each diff report file. **new** | a 10,240-byte changed run (images map exactly the run): 644/644 rows in each of the 4 Markdown blocks (diff `-`, diff `+`, A, B); a 69,632-byte only-B run: 4,356/4,356 rows in the Markdown B block and in the HTML B window; 0 cap lines in either file; Markdown and HTML row counts equal per window | (a) the 512-row cap restored → 512 rows + `... window limited to 512 rows ...` → RED; (b) the rows rendered through the screen's hex view with `max_rows` = the window's rows → the 69,632-byte window stops after 4,100 rows with `... output truncated at 65536 bytes ...` → RED | US-HEXWIN-1 | No: Markdown 512 rows + 1 cap line per block (1,026 lines in the diff block); HTML only-B window 512 rows + 1 cap line; HTML changed pane already whole (644) |

### D14-10 — the Markdown diff report writes its text inert (US-MDESC-1)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-CMP-004.9 | U | The system shall write image labels, paths and symbol names into the Markdown file as inert text. — Withdrawn: split into R-CMP-004.9.1 (label fields) and R-CMP-004.9.2 (path fields); "inert" is now the S12 definitions | — | — | US-MDESC-1 | — |
| R-CMP-004.9.1 | U | The system shall write each label field into the Markdown file of a diff report as the report-safe text (S12 CTX-RPT-TEXT) of its control-stripped value, with the field limit 512. **new (split of .9)** | 9/9 cases of `02-test-cases.md` (image label, variant id, Runs symbols, linkage symbol, flow-attribution document and symbol, filter file name, 600-character symbol, ordinary file name), each the exact escaped text; every table row keeps its cell count | (a) the Runs Symbols cell written raw → `INSIDE_SYM` → RED; (b) the escaper applied twice (a producer that pre-escapes, `flow_execution_service.py:984`) → `\\[red\\]` → RED; (c) the escaper applied to the HTML file → R-CMP-004.8/1 RED | US-MDESC-1 | No: header labels, variant id, Runs symbols raw (`diff_report_service.py:879-880`, `:1012`); linkage and flow-attribution values pass `_md_cell` only (`|` escaped, `<b>` raw, `:288`); filter name control-stripped only (`:509`) |
| R-CMP-004.9.2 | U | The system shall write each path field into the Markdown file of a diff report as the path text (S12 CTX-RPT-TEXT) of its control-stripped value. **new (split of .9)** | a path with a backtick: `�` in its place, 4/4 fields (2 image paths, 2 provenance paths), the code span closed once; an ordinary path: byte-identical to today (`<RUN-ROOT>/img.s19`) | (a) path written raw → the backtick closes the code span → RED; (b) report-safe text used for a path → `/tmp/a\.s19` → RED | US-MDESC-1 | No: image path raw in its code span (`:880`); provenance paths `_md_cell` in a code span (`:554-555`) |
| R-CMP-004.8 | U | The system shall HTML-escape every value it embeds in the HTML file. (canon, unchanged; in scope as the guard that the Markdown escaping stays out of the HTML file) | HTML label of `A_b.s19`: `A_b.s19`, 0 backslashes added (1/1) | Markdown escaper applied to the HTML → `A\_b\.s19` → RED | US-MDESC-1 | Yes |
| R-BEFORE-AFTER-REPORT-001.21 | U | The system shall remove control characters from the provenance and linkage values in both files. (canon, unchanged; must still hold after the escaper change) | symbol `CTL\x01SYM`: `CTLSYM` in both files, 0 `\x01` (2/2) | control stripping dropped before the escaper → `CTL�SYM` in the Markdown file → RED | US-MDESC-1 | Yes |
| R-BEFORE-AFTER-REPORT-001.22 | U | The system shall escape `\|` in the Markdown linkage cells. (canon, unchanged; must still hold) | symbol EVIL, pipe, SYM: the Markdown cell holds EVIL, a backslash, the pipe, SYM; the row keeps 9 cells (1/1) | escaper without `\|` → 10 cells → RED | US-MDESC-1 | Yes |

## Requirement-level changes recorded here (applied to the canon at integration)

- R-CMP-004.9 split into R-CMP-004.9.1 and R-CMP-004.9.2 (rule E7). New rows: R-BEFORE-AFTER-REPORT-001.32 … .35, R-CMP-004.14.
- CTX-BEFOREAFTER gains the term `title  "# Before/after report" (Markdown line 1); "Before/after report" as the HTML <title> and first <h1>. Every other part of the header is CTX-DIFFREPORT's.`
- CTX-DIFFREPORT gains the terms `label field`, `path field` and `control-stripped value` (Definitions above), and its `header` term reads `"# Diff report" (the before/after report: CTX-BEFOREAFTER title)`.
- Golden and pinned-text changes these rows cause: `E1-rulings.md` §3.
