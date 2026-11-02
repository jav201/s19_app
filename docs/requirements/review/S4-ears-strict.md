# S4 — Hex view & Memory Map: context notes and strict EARS rows (2026-10-30)

Input: `REQUIREMENTS.by-module.md` chapter S4 (lines 1320–2185, 866 lines): 22 blocks — R-TUI-004, 007, 009, 010, 017, 018, 038, 040, 026 (superseded), 041, R-WS-HEXROW-001, R-TUI-050/051 (retired), 060, 061, 062, 067, 072, 073, 074, and R-TUI-103's band-bar clause (its safe-text clause is in S1). Earlier analysis: `review/weak-point-check.md` (ambiguity families H1–H7).
Code: `s19_app/render/hexview.py`, `format.py`, `tui/services/entropy_service.py`, `tui/entropy_style.py`, the Memory Map parts of `tui/screens_directionb.py`, the S4 functions of `app.py`, the `#hex_*`, `#map_*`, `band-*` rules of `styles.tcss`. Two read-only code readings, every fact with `file:line`. No test was run.

Result:
- **Context notes first** (section 3): CTX-HEX, CTX-ENTROPY, CTX-MAP. They answer the ambiguity families H1–H7 of the weak-point check.
- **Rows** (section 4): one EARS form each, one `shall`; none needed another form; none uses `Where`. Counts in section 6.
- **Decisions** (section 5), each with a recommendation already applied to the rows. Visual changes (glyphs, widths, tick placement) are marked **prototype first**: per the TUI rule, a prototype round with real captures and your verdict comes before any implementation.
- Rules E1–E7: `review/S1-ears-strict.md` section 1. Code changes go to `review/CODE-CHANGES.md`.

---

## 1. How S4 was written before

- Eight short hex-view rows from the first batches ("readable", "should provide context", "truncate safely").
- Memory Map rows that are mostly history: R-TUI-041 runs ~139 lines, of which the statement is ~17; R-TUI-060 and 062 carry multi-batch amendments, counterfactual transcripts and test-vacuity notes. The current contract is in the amendments, not in the statements.
- Subchapter headings named after batches ("§35 Change-doc label clarity · A2L >32-bit WARNING …" holds the Memory Map rows).

## 2. What did not make sense

| Where | What did not make sense | Fix |
|---|---|---|
| R-TUI-062 | Statement: "single-click → hex". Its own amendments and the code: one click inspects, a double click opens hex. R-TUI-073 still says "the R-TUI-062 single-click → hex contract stays intact". | Rows follow the code (R-TUI-062.1, .2, D4-20). |
| R-TUI-062 / map texts | The key line says `↑↓ / j k select · … double-click / ↵ open hex`; the inspector subtitle says `↑↓ · ↵ hex`; every row ends in `↵`. In the code Enter only inspects, arrows only move focus, and `j`/`k` export the A2L JSON and open the legend. A keyboard user cannot reach the hex view from the map at all. | Enter opens hex, arrows inspect, the key line names only real keys (D4-21). |
| R-TUI-073 vs R-TUI-074 | The row's symbol count uses "tag address inside the region"; the inspector lists tags whose extent overlaps it. A tag that starts before a region and runs into it is listed but not counted. | One relation, extent overlap (D4-22). |
| R-TUI-074 | "a hex peek of up to 3 rows". The peek fills the inspector's height, 8 bytes per row, and shows bytes past the region's end. | Rows follow the code (R-TUI-074.6 … .8). |
| R-TUI-041 | The statement still describes the retired cell grid and an "Open in Hex View" button; the stats strip lists "largest-gap bytes", computed but never shown. | Grid and button gone from the rows; largest gap removed (D4-28). |
| R-TUI-061 | "At a glance" histogram + sparkline docked beside the band bar. Retired in batch-93; one line of chips replaced it. The histogram and sparkline code remains, unused. | Rows describe the chips; dead code removed (D4-31). |
| R-TUI-061 / 062 | "≥ 120 columns side by side, < 120 stacked". The map actually switches on its own panel width: < 86 columns stacked. | Rows follow the code (R-TUI-061.4, .5). |
| R-TUI-010 | "occupy the full right column height". There is no right column: the hex view is the middle of three Workspace panes. | Restated (R-TUI-010). |
| R-TUI-007 | "should provide context … truncate large outputs safely": "should", "context" and "safely" cannot be tested. | The window, its size and its notice lines (S4.2). |
| R-TUI-017 / 040 | Find next and go-to run only from their buttons; Enter in either input does nothing. | Enter runs them (D4-1). |
| R-TUI-040 | "the typed address": no notation stated. The input reads `1000` as decimal and rejects `ABCD`, although its placeholder says `Goto 0xADDR` and every address in the app is shown in hex. | Hexadecimal, with or without `0x` (D4-7). |
| R-TUI-018 / 040 | Where the target lands differs by view and by action: main view somewhere in its page with no scroll, A2L/MAC search and go-to on row 65, selections near the top. | One rule: the target row is second from the top (D4-2). |
| R-TUI-038 | "resumes from the first address visible" holds, but all three hex views share one search state: a query typed in the MAC view continues from a hit in the Workspace, and its highlight appears in all three. | One search state per view (D4-4). |
| R-TUI-050 / 051 | Retired (entropy viewer modal), still ~80 lines of text. | Marked retired; the code is confirmed gone. |
| R-TUI-103 (band-bar clause) | Shares its id with an unrelated safe-text rule (S1). | New ids R-TUI-103B.x here. |

---

## 3. Context notes (informative)

### CTX-HEX · Hex views (S4.1 … S4.6)

```text
hex view        A pane that shows image bytes as hex rows:
  main          Workspace, middle pane: the whole image of the primary file.
  A2L hex       A2L Explorer, right pane: the image, focused on the selected tag.
  MAC hex       MAC View, right pane: the image, focused on the selected MAC record.
  hex peek      Issues and Checks screens: 13 rows around the selected entry's address.
  diff hex      A↔B diff: the two images side by side.
  result hex    Operations window: the output image of an operation, from address 0.
hex row         16 bytes from an address that is a multiple of 16 (the row base).
present row     A hex row with at least one byte in the image.
row format      <marker><address>  <16 × "XX ">|<16 text characters>|
                marker: "> " on the target row, else two spaces.
                address: 0x + 8 uppercase hexadecimal digits.
                text: the byte as a character when it is 0x20-0x7E, else ".".
                A byte not in the image: three spaces in hex, one space in text.
byte class      00 or FF: grey #969aad · 0x20-0x7E: cyan #7dd3fc · other: light #e9e9e9.
hex page        A run of consecutive present rows; its size is the hex page size
                (25, 50, 100, 150 or 200 rows, set in the viewer settings).
target          The address a go-to, a search hit or a selection asks a hex view to show.
target row      The present row that holds the target, or, when none does, the first
                present row after it, or the last present row (snapping).
focus colour    bold yellow: a search hit, or the selected A2L tag's span.
MAC mark        orange3 on the byte at a valid MAC record's address.
notice line     A line above the rows that explains the window:
                ... window limited to <n> rows ...
                ... showing from <address> ...
                ... address <address> not present ...
address input   The text typed in a go-to box.
```

### CTX-ENTROPY · The entropy model (S4.7)

```text
entropy window  256 consecutive image bytes. Windows start at each range's start, every
                256 bytes; the last window of a range may be shorter. No window crosses
                a gap.
entropy         Shannon entropy of the window's bytes: H = -Σ p·log2 p over the 256
                byte values, in bits per byte, 0.0 to 8.0.
low confidence  A window with fewer than 64 bytes.
band            constant/padding  0.0 ≤ H < 1.0   glyph ·  colour #6b7280
                low               1.0 ≤ H < 5.0   glyph ░  colour #5fb98a
                medium            5.0 ≤ H < 7.2   glyph ▒  colour #d9a35b
                high/random       7.2 ≤ H ≤ 8.0   glyph ▓  colour #e06c75
                (A value on a cutoff belongs to the higher band.)
```

### CTX-MAP · The Memory Map (S4.8)

```text
image span      From the lowest image address to one past the highest.
mapped bytes    The number of addresses in the image.
gap             The addresses between two consecutive ranges (S1 CTX-IMAGE).
coverage        mapped bytes / image span × 100, shown with 4 decimals.
region          A maximal run of consecutive entropy windows with the same band and no
                address break between them. A region has exactly one band; its size is
                a multiple of 256 bytes except at a range's end.
Memory Map      Title, header line, the map pane (band bar, ruler, band chips, region
                list) beside or above the inspector, and the stats line.
band bar        One row: one segment per region, coloured and filled with its band glyph;
                one ╱ column between two regions with a gap between them.
ruler           One row of address labels under the band bar: 8 uppercase hex digits, no 0x.
band chip       <glyph> <regions of that band> <share of mapped bytes>%
region row      " <glyph> 0x<start> <size> [<micro-bar>] <symbols> <band>   ↵"
                size: human-readable, binary units (B, KiB, MiB …, one decimal)
                micro-bar: 4 cells, filled in proportion to region size / largest region
                symbols: the number of named tags whose extent overlaps the region
                band: const, low, medium or high/rand
tag extent      From a tag's address, as many bytes as its length (1 when unknown).
inspector       The pane that describes the selected region: Status, Region, Size,
                Band, Symbols (count, then one name per line), Peek.
peek row        <address, 8 hex digits>  <8 bytes as hh, ·· for a byte not in the image>
stats line      " Mapped <mapped> / <span> span (<coverage>%) · <ranges> ranges (<valid>
                valid) · <gaps> gaps · <issues> issues"; compact form when the line is
                narrower than 84 columns:
                "Mapped <mapped> / <span> <coverage>% · <ranges> rng (<valid> ok) ·
                <gaps> gaps · <issues> iss"
memory strip    The one-row band above the Workspace panes: the whole image span cut
                into cells of equal size.
```

---

## 4. The chapter, rewritten

Form column: U = ubiquitous. "Code today": **Yes**, **Yes; tested**, **Partly** / **No** with the decision.

### S4.1 · Hex rows (CTX-HEX)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-004.1 | U | The system shall show every hex row in the row format of CTX-HEX. | Partly: the diff hex uses another renderer (D4-15). |
| R-TUI-004.2 | U | The system shall show only present rows in the main, A2L and MAC hex views. | Yes; tested. |
| R-TUI-004.3 | If | If a valid MAC record's address is outside the image, then the system shall add the row that holds it to the main, A2L and MAC hex views. | Yes; tested. |
| R-TUI-004.4 | If | If an address of a shown row is not in the image, then the system shall show it as blank in both the hex and the text column. | Partly: the diff hex shows `.` in text (D4-15). |
| R-TUI-004.5 | U | The system shall colour each byte of the hex column by its byte class. | Yes; tested. |
| R-TUI-004.6 | U | The system shall show image bytes as plain text, never as markup. | Yes; tested. |

### S4.2 · Window and paging

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-007.1 | U | The system shall show the main hex view one hex page at a time. | Yes; tested. |
| R-TUI-007.2 | While | While the operator has set no hex page size, the system shall use 200 rows. | Yes. |
| R-TUI-007.3 | When | When the operator presses `.` on the Workspace, the system shall show the next hex page. | Partly: the binding names the key `period`; Textual 8.2.8 reports a real `.` press as `full_stop`, so it may never fire; the tests press `period`. Reproduce first (S6 D6-20). |
| R-TUI-007.4 | When | When the operator presses `,` on the Workspace, the system shall show the previous hex page. | Yes; tested. |
| R-TUI-007.5 | If | If the operator asks for the next hex page while the last one is shown, then the system shall keep the last page. | Yes; tested. |
| R-TUI-007.6 | If | If the operator asks for the previous hex page while the first one is shown, then the system shall keep the first page. | Yes; tested. |
| R-TUI-007.7 | If | If the operator presses `,` or `.` on a screen other than the Workspace, then the system shall leave every hex view unchanged. | No: the hidden Workspace view pages (D4-8). |
| R-TUI-007.8 | U | The system shall count the rows added for MAC records (R-TUI-004.3) in the hex pages of the main view. | No: the pages drift (D4-10). |
| R-TUI-007.9 | When | When the operator loads a file, the system shall show the first hex page. | No: the old page index is kept (D4-14). |
| R-TUI-007.10 | If | If more present rows follow the shown window, then the system shall show the notice line `... window limited to <n> rows ...`. | Yes; tested. |
| R-TUI-007.11 | If | If the shown window does not start at the first present row, then the system shall show the notice line `... showing from <address> ...`. | Partly: adds "(context preserved)" even when none is kept (D4-11). |
| R-TUI-007.12 | While | While the A2L or MAC hex view has no target, the system shall show it from the first present row. | Yes. |
| R-TUI-007.13 | If | If no file is loaded, then the system shall show `No file loaded.` in each hex view. | Yes. |
| R-TUI-007.14 | If | If a loaded file has no present row, then the system shall show `No data available.` in each hex view. | Yes. |

### S4.3 · Go to an address

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-040.1 | When | When the operator presses `g` on the Workspace, the A2L Explorer or the MAC View, the system shall put the focus in that screen's go-to box. | Yes; tested. |
| R-TUI-040.2 | When | When the operator presses `Goto` or Enter in a go-to box, the system shall go to the address typed in it. | Partly: Enter does nothing (D4-1). |
| R-TUI-040.3 | U | The system shall read an address input as hexadecimal, with or without a `0x` or `0X` prefix. | Partly: bare digits are read as decimal, `ABCD` is refused (D4-7). |
| R-TUI-040.4 | If | If the address is in the image, then the system shall show its target row second from the top of the hex view. | Partly: the main view shows its page, A2L and MAC show it on row 65 (D4-2). |
| R-TUI-040.5 | If | If the address is in the image, then the system shall mark its row with `> `. | Yes; tested. |
| R-TUI-040.6 | If | If the address is in the image, then the system shall show the status `Goto <address>`. | Yes; tested. |
| R-TUI-040.7 | If | If the address is not in the image, then the system shall show the status `Address <address> not in loaded file.` | Yes; tested. |
| R-TUI-040.8 | If | If the address is not in the image, then the system shall leave the hex view's rows unchanged. | Yes; tested. |
| R-TUI-040.9 | If | If the go-to box is empty, then the system shall show the status `Goto address is empty.` | Yes; tested. |
| R-TUI-040.10 | If | If the go-to box does not hold an address, then the system shall show the status `Invalid address format.` | Yes; tested. |
| R-TUI-040.11 | If | If a go-to fails, then the system shall remove the view's `> ` marker. | Partly: an address outside the image keeps the old marker (D4-6). |
| R-TUI-040.12 | When | When a hex view pages, starts a new search, jumps to a new target or loads a file, the system shall remove its `> ` marker. | Partly: a section selection and a Memory Map jump keep it (D4-6). |

### S4.4 · Search

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-017.1 | When | When the operator presses `Find Next` or Enter in a search box, the system shall find the next place where the image holds the search text, ignoring the case of ASCII letters. | Partly: Enter does nothing (D4-1). |
| R-TUI-017.2 | U | The system shall find a search text only inside one range, never across a gap. | Yes. |
| R-TUI-017.3 | If | If the search text differs from the last search of that view, then the system shall search from the start of the image. | Yes. |
| R-TUI-017.4 | If | If the search text is the last search of that view, then the system shall search from the byte after its last hit. | Yes; tested. |
| R-TUI-038 | If | If the view has paged, jumped to another target, or missed since its last hit, then the system shall search from the first shown row. | Yes; tested. |
| R-TUI-017.5 | U | The system shall keep the search text, last hit and highlight of each hex view apart from the others. | No: the three views share them (D4-4). |
| R-TUI-017.6 | When | When a search finds the text, the system shall draw the found bytes in the focus colour. | Yes; tested. |
| R-TUI-017.7 | When | When a search finds the text, the system shall show its row as the target row. | Partly: placement as R-TUI-040.4 (D4-2). |
| R-TUI-017.8 | When | When a search finds the text, the system shall show the status `Found at <address>`. | Yes; tested. |
| R-TUI-017.9 | If | If the search finds nothing, then the system shall show the status `Search text not found.` | Yes; tested. |
| R-TUI-017.10 | If | If the search box is empty, then the system shall show the status `Search text is empty.` | Yes; tested. |
| R-TUI-017.11 | If | If no file is loaded when the operator searches, then the system shall show the status `No file loaded.` | Yes; tested. |

### S4.5 · Jumps and marks

Selecting an A2L tag or a MAC record is in S2 (R-A2L-100 … 104, R-MAC-054 … 056); these rows set where any jump lands.

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-018.1 | When | When a hex view jumps to a target, the system shall show the target row second from the top. | Partly: only tag and MAC selections do (D4-2). |
| R-TUI-018.2 | When | When a hex view jumps to a target, the system shall scroll the view back to its left edge. | Partly: only tag and MAC selections do (D4-2). |
| R-TUI-018.3 | If | If no present row holds the target, then the system shall use the target row of CTX-HEX (the next present row, or the last). | Partly: the main view only; A2L and MAC show a "not present" notice (D4-3). |
| R-TUI-009.1 | When | When the operator selects a range in the Workspace section list, the system shall jump the main hex view to the range's start. | Yes. |
| R-TUI-009.2 | When | When the operator selects a range in the Workspace section list, the system shall show the status `Section at <address>`. | No: no status (D4-16). |
| R-HEX-MARK.1 | When | When the system shows the main, A2L or MAC hex view, the system shall draw the MAC mark on the byte at each valid MAC record's address. | Yes. |
| R-HEX-MARK.2 | If | If a byte has both the focus colour and the MAC mark, then the system shall draw it in the focus colour. | Yes; tested. |
| R-HEX-MARK.3 | When | When the system shows a hex peek, the system shall mark the row that holds the entry's address with `> `. | No (D4-15). |

### S4.6 · Layout

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-010 | While | While the Workspace is shown, the system shall give the main hex view the whole height of the middle pane. | Yes; tested. |
| R-WS-HEXROW-001.1 | While | While the Workspace is shown, the system shall show each hex row on one line. | Yes; tested. |
| R-WS-HEXROW-001.2 | If | If the middle pane is narrower than a hex row, then the system shall let the operator scroll it sideways. | Yes; tested. |
| R-WS-HEXROW-001.3 | While | While the Workspace is shown, the system shall keep its three panes visible. | Yes; tested. |
| R-HEX-LAYOUT.1 | If | If the A2L or MAC hex pane is narrower than a hex row, then the system shall let the operator scroll it sideways. | Unverified: the MAC pane's 82-column floor includes its border, leaving ~78 columns for an 81-column row (D4-13). |

### S4.7 · Entropy (CTX-ENTROPY)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-ENT-001 | When | When a primary image loads, the system shall compute its entropy windows once. | Yes. |
| R-ENT-002 | U | The system shall cut the image into entropy windows as CTX-ENTROPY defines them. | Yes; tested. |
| R-ENT-003 | U | The system shall give each entropy window its entropy and its band. | Yes; tested. |
| R-ENT-004 | If | If an entropy window has fewer than 64 bytes, then the system shall mark it low confidence. | Yes; tested. |
| R-ENT-005 | If | If the primary image is unloaded, then the system shall drop its entropy windows. | Yes. |

### S4.8 · The Memory Map (CTX-MAP)

**Header, layout, empty states**

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-060.1 | When | When the Memory Map shows an image with entropy windows, the system shall show the header `Entropy bands - <regions> region(s), <mapped bytes> mapped`, with the size human-readable. | Partly: raw byte count (D4-33). |
| R-TUI-060.2 | U | The system shall build the Memory Map's regions as CTX-MAP defines them. | Yes; tested. |
| R-TUI-061.4 | While | While the Memory Map panel is at least 86 columns wide, the system shall show the inspector beside the map pane. | Yes; tested. |
| R-TUI-061.6 | While | While the Memory Map panel is at least 86 columns wide, the system shall make the inspector 44 columns wide. | Yes; tested. |
| R-TUI-061.5 | While | While the Memory Map panel is less than 86 columns wide, the system shall show the inspector under the map pane. | Yes; tested. |
| R-TUI-060.3 | If | If no file is loaded, then the system shall show `No file loaded - press Ctrl+L (or 'l') to load a file, or 'p' to load a saved project.` instead of the Memory Map. | Yes; tested. |
| R-TUI-060.4 | If | If no primary image is loaded and another file is, then the system shall show the header `No S19/HEX image loaded.` | No: says `No file loaded …` (D4-26). |
| R-TUI-060.5 | If | If the primary image has no entropy windows, then the system shall show the header `No entropy detail for this image.` | Yes; tested. |
| R-MAP-PANE.1 | When | When the Memory Map shows regions, the system shall title the map pane `Memory Map`. | Yes; tested (`test_tc656_chrome_pane_titles_and_subtitles`). From S0 HLR-125. |
| R-MAP-PANE.2 | When | When the Memory Map shows regions, the system shall show under the map pane the subtitle `<regions> regions · ░▒▓ k`. | Yes; tested (`test_tc656_chrome_pane_titles_and_subtitles`). From S0 HLR-125. |

**Band bar, ruler, chips**

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-103B.1 | U | The system shall size the band bar to the width the bar has on screen. | Yes; tested. |
| R-TUI-103B.2 | U | The system shall give each region at least one column of the band bar. | Yes; tested. |
| R-TUI-103B.3 | U | The system shall give each gap between two regions exactly one column of the band bar, drawn as `╱`. | Yes; tested. |
| R-TUI-103B.4 | U | The system shall share the remaining columns among the regions in proportion to their mapped bytes, by largest remainder. | Yes; tested. |
| R-TUI-103B.5 | U | The system shall keep every band-bar column inside the bar. | Partly: with more regions than columns the bar overflows (D4-23, prototype first). |
| R-TUI-072.1 | U | The system shall label the ruler at each region start and at the last mapped byte. | Yes; tested. |
| R-TUI-072.2 | If | If the labels do not fit the ruler, then the system shall keep the first and last label and as many evenly spaced others as fit. | Yes; tested. |
| R-TUI-072.3 | U | The system shall place each ruler label under the column of the band bar where its address starts. | No: labels are spread at equal widths (D4-27, prototype first). |
| R-TUI-061.1 | When | When the Memory Map shows regions, the system shall show one band chip per band that has regions, in band order. | Yes; tested. |
| R-TUI-062.9 | When | When the operator clicks a band-bar segment, the system shall act as for a click on its region row. | Yes; tested. |

**Region list and inspector**

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-073.1 | When | When the Memory Map shows regions, the system shall show one region row per region, in address order. | Yes; tested. |
| R-TUI-073.2 | If | If the map pane leaves fewer than 43 columns for the row, then the system shall leave out the micro-bar. | Yes; tested. Presence flips twice between 106 and 124 terminal columns (D4-25, prototype first). |
| R-TUI-073.3 | U | The system shall count in a region row's symbols the named tags whose extent overlaps the region. | No: counts tag addresses inside the region, named or not (D4-22). |
| R-TUI-073.4 | U | The system shall keep the columns of the region rows aligned for any size and symbol count. | No: sizes of 10.0 KiB or more and counts of 100 or more push the columns (D4-23, prototype first). |
| R-TUI-062.1 | When | When the operator clicks a region row once, the system shall select the region and show it in the inspector. | Yes; tested. |
| R-TUI-062.2 | When | When the operator double-clicks a region row, the system shall open the main hex view at the region's start. | Yes; tested. |
| R-TUI-062.3 | When | When the operator presses Enter on a region row, the system shall open the main hex view at the region's start. | No: Enter only inspects (D4-21). |
| R-TUI-062.4 | When | When the operator presses Down in the region list, the system shall select the next region and show it in the inspector. | Partly: the focus moves, the inspector does not change (D4-21). |
| R-TUI-062.11 | When | When the operator presses Up in the region list, the system shall select the previous region and show it in the inspector. | Partly: as R-TUI-062.4 (D4-21). |
| R-TUI-062.5 | If | If the first or last region is selected, then the system shall keep it when the operator moves past it. | Yes; tested. |
| R-TUI-062.6 | When | When the Memory Map is drawn again, the system shall select the region that starts at the same address as the one selected before, or the first region when there is none. | Yes; tested. |
| R-TUI-062.7 | When | When the Memory Map is drawn again, the system shall stay on the Memory Map. | Yes; tested. |
| R-TUI-062.8 | When | When the system opens the main hex view from the Memory Map, the system shall switch to the Workspace and jump to the region's start (S4.5). | Partly: no status, the old marker stays (D4-6, D4-16). |
| R-TUI-074.1 | If | If no region is selected, then the system shall show `Click a region to inspect it.` and `Double-click to open in hex.` in the inspector. | Yes; tested. |
| R-TUI-074.2 | When | When the inspector shows a region, the system shall title it `Inspector — <start address>`. | Yes; tested. |
| R-TUI-074.3 | When | When the inspector shows a region, the system shall show its Status: `VALID` or `INVALID` from the validity of its range (S1 R-VAL-001b). | Yes; tested. |
| R-TUI-074.4 | When | When the inspector shows a region, the system shall show its first and last address. | Yes; tested. |
| R-TUI-074.10 | When | When the inspector shows a region, the system shall show its size, human-readable. | Yes; tested. |
| R-TUI-074.11 | When | When the inspector shows a region, the system shall show its band glyph and name. | Yes; tested. |
| R-TUI-074.5 | When | When the inspector shows a region, the system shall list the names of the tags whose extent overlaps it, ordered by address then name. | Yes; tested. |
| R-TUI-074.6 | When | When the inspector shows a region, the system shall show peek rows from the 8-byte boundary at or before the region's start. | Yes; tested. |
| R-TUI-074.7 | When | When the inspector shows peek rows, the system shall show as many as fit the inspector's height. | Yes; tested. |
| R-TUI-074.8 | If | If a peek byte is not in the image, then the system shall show it as `··`. | Yes; tested. |
| R-TUI-074.9 | If | If a symbol name is wider than the inspector, then the system shall cut it and end it with `…`. | Yes. |

**Stats line, key line**

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-041.1 | When | When the Memory Map shows an image, the system shall show the stats line of CTX-MAP, with sizes human-readable. | Yes; tested. |
| R-TUI-041.2 | If | If the stats line is narrower than 84 columns, then the system shall show its compact form. | Yes; tested. |
| R-TUI-041.3 | U | The system shall count in the stats line's issues every issue of the issue list (S3). | Yes. |
| R-TUI-041.4 | U | The system shall keep the Memory Map's stats line in view at every scroll position of the region list. | Yes; tested at 120 × 36 and 80 × 24 (`test_tc662_stats_one_line_adaptive_visible`). From S0 LLR-129.1. |
| R-TUI-062.10 | U | The system shall name in the Memory Map's key line, inspector subtitle and row glyphs only keys that the Memory Map handles. | No: `j k select` and `↵ open hex` are false today (D4-21). |

**Memory strip** (shown on the Workspace)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-067.1 | U | The system shall show at most as many memory-strip cells as the strip has columns. | Yes; tested. |
| R-TUI-067.5 | U | The system shall make every memory-strip cell cover the same number of addresses. | Yes; tested. |
| R-TUI-067.6 | U | The system shall start no memory-strip cell beyond the image span. | No: the last cells may start past it and show as gaps (D4-35). |
| R-TUI-067.2 | When | When the image has entropy windows, the system shall show each strip cell with the glyph and colour of the band that covers most of its bytes. | Yes; tested. |
| R-TUI-067.3 | If | If a strip cell holds no image byte, then the system shall show it as `╱` in grey. | Yes; tested. |
| R-TUI-067.4 | If | If the image has no entropy windows, then the system shall show each strip cell as `█` in the colour of its range validity (valid green, invalid red, gap grey). | Yes; tested. |

---

## 5. Decisions: recommendation applied

**Requirement follows the code (no code change)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D4-17 | R-TUI-010 names a "right column" that no longer exists. | The hex view is the Workspace's middle pane, full height (R-TUI-010). |
| D4-18 | R-TUI-007 "context … truncate safely". | The window, page size and notice lines (S4.2). |
| D4-20 | R-TUI-062 "single click → hex"; the code and its amendments: one click inspects, two navigate. | Follow the code (R-TUI-062.1, .2). |
| D4-29 | R-TUI-061 "≥ 120 / < 120 columns". | The map's own panel width, 86 columns (R-TUI-061.4, .5). |
| D4-34 | R-TUI-074 "peek of up to 3 rows". | The peek fills the inspector's height, 8 bytes a row (R-TUI-074.6 … .8). |
| D4-36 | R-TUI-050 / 051 (entropy viewer modal) and R-TUI-026 (cell grid). | Retired; the code is confirmed gone. Their text leaves the chapter. |
| D4-37 | R-TUI-061 at-a-glance histogram and sparkline. | Retired in batch-93; the band chips are the row (R-TUI-061.1). |

**Remove (rule use/defer/delete)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D4-11 | The 65,536-byte truncation can never trigger (512 rows × 16 = 8,192 bytes); `(context preserved)` appears on plain paging. | Remove the dead limit; the notice reads `... showing from <address> ...`. |
| D4-12 | `_jump_to_tag`, `_jump_to_mac_record` and `PreparedLoad.mac_highlights` have no caller. | Remove (the issue-jump code is S3 D3-7). |
| D4-28 | "Largest gap" is computed and never shown. | Remove from the code and the requirement; the stats line is already full. |
| D4-31 | `build_detail_text`, `covering_range`, `issues_in_window`, `symbol_list_text`, `band_histogram`, the sparkline functions, `entropy_ramp_glyph`, the `#map_open_hex_button` CSS and two duplicated narrow-width CSS rules: no production use. | Remove them and their tests. |

**Code change: correct a defect**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D4-1 | Enter in a search or go-to box does nothing; only the buttons run them. | Enter runs them (R-TUI-017.1, R-TUI-040.2). |
| D4-2 | A target lands in a different place depending on the view and the action. | One rule: second row from the top, scrolled to the left edge (R-TUI-018.1, .2). |
| D4-3 | Snapping to the next present row exists only in the main view; A2L and MAC show "not present". | Same snapping everywhere (R-TUI-018.3). |
| D4-4 | One search state for three views. | One per view (R-TUI-017.5). |
| D4-6 | A failed go-to outside the image keeps the old marker; a section or map jump keeps it too. | Every failed go-to and every jump clears it (R-TUI-040.11, .12). |
| D4-7 | Go-to reads `1000` as decimal and refuses `ABCD`; every address the app shows is hex, and the placeholder says `0xADDR`. | Always hexadecimal, prefix optional (R-TUI-040.3). Same reading as MAC addresses (S2). |
| D4-8 | `,` and `.` page the hidden Workspace view from any screen. | Only on the Workspace (R-TUI-007.7). |
| D4-10 | Rows added for MAC records outside the image are not counted in paging, so pages drift. | Count them (R-TUI-007.8). |
| D4-13 | The MAC hex pane's 82-column floor includes its border: ~78 columns for an 81-column row, and the A2L/MAC views cannot scroll sideways. Not yet seen on screen. | Capture it first; if it wraps, let both panes scroll sideways like the Workspace (R-HEX-LAYOUT.1). |
| D4-14 | A new file keeps the previous file's page index. | First page on load (R-TUI-007.9). |
| D4-15 | The diff hex uses its own renderer (`.` for an absent byte, no marker column); hex peeks mark no row. | One renderer for every hex view; peeks mark the entry's row (R-TUI-004.1, R-HEX-MARK.3). |
| D4-16 | Selecting a section or opening hex from the map shows no status, unlike tag and MAC selections. | `Section at <address>` (R-TUI-009.2). |
| D4-21 | The map promises `↵ open hex` and `j k select`; Enter only inspects, arrows only move focus, `j`/`k` belong to other actions. A keyboard user cannot reach hex from the map. | Enter opens hex, arrows select and inspect, the key line names real keys only (R-TUI-062.3, .4, .10). |
| D4-22 | Row symbol count (tag address inside, named or not) and inspector list (extent overlap, named only) disagree. | Both use extent overlap over named tags; the count equals the list (R-TUI-073.3). |
| D4-26 | With only a MAC or A2L loaded the map header says `No file loaded`. | `No S19/HEX image loaded.` (R-TUI-060.4). |
| D4-33 | The header shows raw bytes, the stats line human-readable sizes. | Human-readable in both (R-TUI-060.1). |
| D4-35 | The strip's last cells can start past the image and show as gaps. | No cell beyond the span (R-TUI-067.1). |

**Prototype first** (visual; a prototype round with real captures and your verdict before any implementation)

| # | The situation | What the round must answer |
|---|---|---|
| D4-23 | Region-row columns shift with sizes ≥ 10.0 KiB or counts ≥ 100; the band bar overflows when there are more regions than columns. | Field widths that hold real firmware values; what the bar does with more regions than columns. |
| D4-24 | The micro-bar's empty cell `░` is also the low band's glyph. | Another empty glyph. |
| D4-25 | The micro-bar appears, disappears and reappears between 106 and 124 terminal columns (the rail widens at 120). | A threshold that only ever moves one way. |
| D4-27 | Ruler labels are spread at equal widths, so a label does not sit under its address. | Labels under their segment starts, and what to drop when they collide. |

**Passed to other groups**

- **S2**: the A2L and MAC hex panes follow S4.5 (placement, snapping) — their selection rows stay in S2.
- **S3**: the hex peek's marked row (R-HEX-MARK.3); the legend's Hex block names the focus colour and MAC mark of CTX-HEX.
- **S5**: the Workspace section list (R-TUI-009) and the memory strip's place on the Workspace.
- **S6**: the hex page size in the viewer settings, shared with the A2L and MAC tables (S2 R-TUI-019.3).
- **S12**: the report reads `low confidence` (R-ENT-004); the map does not show it.

---

**Received from later groups** (after S6–S17 were written)

- **S6**: the `.` key (Hex+) is bound under a name Textual does not send (S6 D6-20); R-TUI-007.3 now reads Partly. `g` stays R-TUI-040.1; Enter in the boxes stays D4-1.
- **S12**: low confidence (R-ENT-004) is now also printed in the report (R-RPT-ENT.3). The report's hexdump rows (S12 CTX-RPT-HEX) differ from the screens' rows of CTX-HEX. Keep both: the report is a file format owned by S12, and D4-15 ("one renderer") covers the screens only.

**Received from later groups** (after all groups were written)

- S4.1 (S0 residuals of HLR-125 and LLR-129.1: map pane title and subtitle, stats line in view) → rows R-MAP-PANE.1, .2 (`screens_directionb.py:2609-2610`; both cleared when there is no region, `:2552-2553`) and R-TUI-041.4 (the stats line sits outside the scrolling body, `screens_directionb.py:2437`).

## 6. Counts

| | Old S4 | Strict |
|---|---:|---:|
| Requirement statements | 22 blocks (3 retired) | 117 rows |
| Statements the code contradicts, or that no longer match the screen | 9 (062 click, 062/073 Enter and keys, 073/074 symbol relation, 074 peek, 041 grid/button/largest gap, 061 dock, 061/062 breakpoint, 010 right column, 040 notation) | 0 |
| Rows by form: U / When / While / If / Where | — | 27 / 41 / 8 / 41 / 0 |
| Rows that could not be written in EARS | — | 0 |
| Decisions | — | 32 (7 follow the code, 4 remove, 17 correct a defect, 4 prototype first; numbers are not contiguous) |

Checked by script: one `shall` per row, correct opening words per form, `If … then`, no "unless" / "only if", no repeated id.
