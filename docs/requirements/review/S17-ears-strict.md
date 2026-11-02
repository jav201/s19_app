# S17 — Split / Join / Export: context notes and strict EARS rows (2026-10-30)

Input: `REQUIREMENTS.by-module.md` chapter S17 (lines 6715–6721). The chapter has **no `R-*` row**. The behaviour is written only in S0's table of retired batch ids: HLR-135, HLR-136, HLR-137 and LLR-135.1 … 137.4 (lines 240–265, batch-95), and HLR-160 with LLR-160.1 … 160.5 (lines 422, 456–460, batch-99, the export names and placement).
Code: `s19_app/segment_ops.py`, `s19_app/tui/segment_split_view.py`, the S17 entries of `app.py` (`_compose_screen_split_join`, `action_open_split_join_export`) and the window refresh on every load (`app.py:12578-12612`); the destination guard and placement of `tui/workspace.py` and the emitters of `tui/changes/io.py` as far as the export uses them. Tests read: `tests/test_segment_ops.py`, `tests/test_segment_split_window.py`, `tests/test_b99_export.py`. Read only; no test was run.
Reconciled with s19_app 570b4b5 (batch-100) on 2026-11-01: `segment_split_view.py`, `segment_ops.py` and the placement functions of `workspace.py` did not change after 093a7c0 (batch-100 Inc 1, LLR-163.4 and LLR-163.6, landed before it); the rows of S17.7 and S17.8 that state reuse were checked against batch-100 and their test cites added at 570b4b5; other cites refer to 093a7c0.

Result:
- **Context notes first** (section 3): CTX-SJE, CTX-SJE-PLAN, CTX-SJE-BAND, CTX-SJE-FORMAT, CTX-SJE-NAME, CTX-SJE-TEXT, and CTX-SJE-LAYOUT (the current screen design, informative only).
- **Rows** (section 4): all new ids `R-SEG-*` (no row existed). One EARS form each, one `shall`; none needed another form; none uses `Where`. Sub-headings name the S0 id each part comes from. Counts in section 6.
- **Decisions** (section 5), each with a recommendation already applied; visual changes marked **prototype first**.
- Absorbed from other reviews: S1 D-2 (export of invalid ranges → D17-34), S8 "Passed to S17" (empty S0, terminator 0 → D17-33, D17-8), S6 CTX-SHELL (palette-only window → D17-11).
- Rules E1–E7: `review/S1-ears-strict.md` section 1. Code changes: `cc-S17.md` (scratch), for `review/CODE-CHANGES.md`. Nothing is changed in the code yet.

---

## 1. How S17 was written before

- No requirement row. The chapter only says that its behaviour lives in S0's table of retired batch ids.
- HLR-135 and LLR-135.1 … 135.4: a screen design written as `shall` — the "V1 cockpit chassis", pane widths in columns (58, 54, 40, 30), hex colours per glyph, "12–14 runs per row", the `.db-pane` CSS idiom, and SVG frames "pinned byte-level" as the oracle.
- HLR-136 / LLR-136.x: the content of split and join exports, mixed with the colour encoding of the preview and ruling ids (Q1/8a, 8f, P-9, "the round's 7c recommendation").
- HLR-137 / LLR-137.x: an implementation recipe ("shall ride: a range slicer composing the shipped get_memory_map + set_bytes_at + emitters"), plus an A2L parser change with its fixtures and consumer lines.
- HLR-160 / LLR-160.x (batch-99): export names, containment and placement, mixed with function names (`place_group_into_workarea`, NEW, B99-I2a), `os.replace` and private staging.

## 2. What did not make sense

| Where | What did not make sense | Fix |
|---|---|---|
| Chapter S17 | No row. A reader of the chapter finds no requirement for an export feature that writes files. | Rows written from the S0 ids (D17-1, D17-12). |
| HLR-135, LLR-135.1 … 135.4 | Layout, colours, run counts and CSS as `shall`; SVG frames as the oracle (a test method, not behaviour). | Current design in CTX-SJE-LAYOUT (informative); changes go through prototype rounds (D17-2). |
| HLR-137, LLR-137.1, 137.3 | How the code is built ("compose", "one gap-fill pass", "none ships today"). | What the files hold: S17.6 (D17-3). |
| LLR-137.4 | A2L parser rules (quoted names, offset field, byte-identical fixtures, consumer lines). | S2's (D17-4); S17 keeps only which MEMORY_SEGMENTs give rows. |
| LLR-137.2, HLR-136 | "BIN writing exactly size flat bytes from the segment base (intra-range gaps not padded)": both can be true only for a range with no hole. The sidecar holds the address of the BIN's first byte, not always the segment base. | BIN = bytes in address order; sidecar = first byte's address (D17-7); a BIN with holes is refused (D17-30). |
| LLR-136.5 | "The naming pattern shall default to ‹stem›_‹segment›": nothing can change it. | Fixed names (D17-5). |
| LLR-136.4 | "user-configurable (one control, cycled or typed)": two values only. "a reason naming the offending span": the status names no address. | Two values (D17-6); text with the first address (D17-27). |
| LLR-135.5 | "any state change (… naming) shall disarm": naming cannot change; editing the manual localities is a change the code misses. | R-SEG-EXP.9 (D17-25). |
| LLR-136.6 | Zero coverage asks for a confirm, but join concat never asks. | D17-22. |
| LLR-136.2 / summary | Join concat packs from the lowest selected base; the summary says `packed from base 0x00000000`. | D17-23. |
| LLR-160.1 | Device-name prefix (CON, COM1 …): every name starts with `<stem>_`, so no file name can be a device name. | Removed (D17-14). |
| All S0 ids | Ruling ids, batch history, "the round's #2 recommendation", file and function placement. | Out (process records). |

---

## 3. Context notes (informative)

### CTX-SJE · Terms (S17.1 … S17.4)

```text
window          Split / Join / Export. The palette opens it (S6 R-TUI-021.10); it has
                no rail item and no rail key.
loaded file     The session's primary (S5 CTX-FILES), or the MAC file in a MAC-only
                session. Its image and ranges: S1 CTX-LOAD.
source          Where the table's rows come from. One is shown at a time:
                ranges · manual · a2l.
row             A name, a base (first address) and a size in bytes.
row span        The addresses base … base + size − 1.
<ii>            A row's position, from 00, at least two digits.
locality line   One line of the manual box: <start>-<end>, two hexadecimal numbers, each
                with or without 0x or 0X. <end> is the last address.
                Example: 0x0000EB00-0x0000EBFF is 256 bytes.
manual box      The multi-line box of the manual source (S7 CTX: multi-line box).
covered byte    An address of a row span that the loaded image holds.
coverage        full (every address of the span covered) · partial · zero (none).
selection       The ticked rows of one source. Each source has its own.
mode            split · join.
gaps            split: skip · fill.    join: concat · fill.
pad byte        0x00 or 0xFF.
format          S19 · HEX · BIN. File extension <ext>: s19, hex, bin.
destination     project: <work area>/<project>/splits/
                common:  <work area>/splits/            (work area: S5 CTX-WORKAREA)
stem            The name of the loaded file without its extension.
export request  The e key, or the EXPORT button.
confirm         A second export request that the system asks for (CTX-SJE-PLAN).
```

### CTX-SJE-PLAN · What an export holds (S17.5, S17.6, S17.8)

```text
export file     A file the export writes: one per selected row in split mode, one for
                all selected rows in join mode. A BIN file comes with its sidecar.
split file      An export file of split mode. join file: the one of join mode.
empty file      An export file whose selected rows hold no covered byte.
join span       Join fill: the lowest selected base … the highest last address of the
                selected rows.
join gap        The addresses of the join span that no selected row spans.
conflict byte   An address of a join gap where the loaded image holds a byte that
                differs from the pad byte.
fill file       A split file with gaps fill, or the join file with join fill.
guard file      A fill file whose span is at least 1 MiB (1,048,576 bytes) and whose
                pad bytes are at least 50 % of that span.
guard span      The span of the largest guard file.
```

### CTX-SJE-BAND · Preview band classes (S17.5)

```text
data       the export writes the image's byte at this address
fill       the export writes the pad byte at this address
conflict   a conflict byte
context    the loaded image holds this address; no export file does
absent     neither the loaded image nor an export file holds this address
band span  split and join fill: the lowest to the highest address of the loaded image
           and the selected row spans. join concat: the bytes of the join file, from
           its first.
```

### CTX-SJE-FORMAT · Export file formats (S17.6)

```text
S19 export      An S19 file by S8.7 (R-S19-EMIT.1 … .10, CTX-WRITE), with at most 32
                data bytes per data record.
HEX export      An Intel HEX file by S8.7 (R-HEX-EMIT-001.1 … .10, CTX-WRITE).
BIN file        The export file's bytes, nothing else: no address, no header, no
                record structure.
sidecar         One line, 0x<A8> and a line end, ASCII.
line end        CR LF on Windows, LF on other systems.
<A8>            An address as 8 uppercase hexadecimal digits.
```

### CTX-SJE-NAME · Export file names (S17.7)

```text
segment part    The row name with every character outside A-Z a-z 0-9 _ - replaced by
                _, cut to its first 100 characters.
split name      <stem>_<segment part>.<ext>
join name       <stem>_joined.<ext>
sidecar name    The BIN file's name with .addr in place of .bin.
numbered name   <name>_<N>.<ext>, N = 1, 2, … (S5 CTX-WORKAREA).
name limit      200 characters, counting a two-digit numbered suffix and the extension.
path limit      260 characters, the full path.
staging path    <work area>/temp/.staging/stage-<8 characters>/<name>: where a file is
                written before it is placed.
copy limit      256 MiB, 268,435,456 bytes (S5 CTX-WORKAREA).
```

### CTX-SJE-TEXT · Texts (S17.3, S17.5, S17.7, S17.8)

```text
notice            A status-line text that also shows as a notification.
size              <n> B below 1 KiB · <x.x> KiB below 1 MiB · <x.xx> MiB from 1 MiB.
<pct>             A percentage with 2 decimals.
file(s)           "file" when the count is 1, else "files".
<raw>             A row name through S1's safe-text rule, first 80 characters.
dropped list      Up to 3 dropped manual lines, without surrounding whitespace, joined
                  by ", ", then " (+<k> more)" when there are more.
split summary     Selected <k>/<n> <noun> · <size> · export → <FORMAT> × <k> file(s) ·
                  intra_gap=<skip|fill>, then " (pad 0x<PP>)" for fill, then
                  " → <destination folder>". One line. <size>: the covered bytes.
concat summary    Join <k> <noun> → 1 file · join=concat · <size> packed from base
                  0x<A8> · <FORMAT> → <destination folder>
fill summary      Join <k> <noun> → 1 file · join=fill · span 0x<A8>–0x<A8> = <size>
                  (packed <size>) · pad 0x<PP> · <FORMAT> → <destination folder>
                  (first and last address of the join span)
  <noun>          segments (a2l) · ranges (ranges) · localities (manual)
confirm reasons   "span guard: <guard span size> span from <size> of data (<pct>% pad)"
                  and "<n> empty file(s) — 0 B of source", in that order, joined by
                  " — ", each when it applies.
refusal notice    Export refused: <reason>, then " — segment <raw> → <segment part>"
                  for each row the reason is about.
written list      "wrote <name>" for up to 3 written files, joined by "; ", then
                  "; +<k> more wrote" when more; then "; reused <name>, <name>, <name>"
                  (" +<k> more" when more) when files were reused.
part-way notice   Export failed: Export stopped: <error>. Already written: <names, or
                  nothing>, then "; reused: <names>" when files were reused.
```

### CTX-SJE-LAYOUT · The screen today (informative; changes need a prototype round)

```text
Left        SEGMENTS chip line (a2l(<n>) ranges(<n>) manual(<n>), the shown source as
            ‹name(n)›, "[a]ll [n]one"), the table, the manual box (manual source only),
            then one line each: MODE, INTRA GAP / JOIN GAPS (+ PAD when fill), FORMAT,
            DEST, NAMING (‹stem›_‹segment› → <sample>).
Right       Pane titled PREVIEW: output label, band, per-file rows, legend, ruler,
            stats (two lines: metrics, state line), summary, EXPORT  e button.
Widths      Measured screen width ≥ 118: preview 58 columns, band 54 cells.
            < 100: preview 30, per-file rows hidden, stats show the state line only.
            Between: preview 40.
Band        data ▓ #91abec · fill ░ #6b7280 · conflict ▒ #f6ff8f · context · #46557a ·
            absent (space). Every run of one class keeps at least one cell.
Table row   ●/○ selected, name, base 0x<A8>, size, coverage:
            ✓ <size> (green #54efae) · ◐ <covered> of <size> (amber #d9a35b) ·
            ✗ 0 B of <size> (red #fd8383). Narrower tiers shorten the name and the
            coverage text, then drop the size.
Per-file    Split mode with 1 to 6 files: <file label> <band> <size>; an empty file:
rows        ∅ empty — 0 B of source in span.
Output      join: <stem>_joined.<ext> · split: <n> file(s) · ‹<first selected row name>›
label
Ruler       0x<first> … 0x<middle> … 0x<last> address of the band span.
Legend      ▓ data ░ pad ▒ conflict · source ctx (narrow: data pad clash src).
```

---

## 4. The chapter, rewritten

Form column: U = ubiquitous. "Code today": **Yes**, **Yes; tested** (test name), **Yes; untested**, **Partly** / **No** / **Unverified** with the decision.

### S17.1 · Opening and closing (from S0 HLR-135, LLR-135.6)

The palette entry and closing by a rail key are S6's (R-TUI-021.10, R-TUI-021.11, R-TUI-022.2); the window's keys in the key bar and its help section are S7's.

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-SEG-OPEN.1 | When | When the operator opens the window, the system shall focus its table. | Yes. |
| R-SEG-OPEN.2 | When | When the operator presses Esc in the window, the system shall show the window that was shown before it opened. | Yes; tested (test_opening_the_window_hides_the_rail_screens_and_returns_on_esc). |
| R-SEG-OPEN.3 | When | When the operator opens the window again with the same loaded file, the system shall show the source, selections and settings it had. | Yes. |
| R-SEG-OPEN.4 | When | When the loaded file changes, the system shall clear the selections of the ranges and a2l sources. | Yes. |
| R-SEG-OPEN.5 | When | When the loaded file changes, the system shall keep the text of the manual box. | Yes. |
| R-SEG-OPEN.6 | While | While the window is hidden, the system shall keep the focus out of it. | Unverified: every load and unload refreshes the hidden window, and the refresh focuses its table (D17-38). |

### S17.2 · Sources and the table (from S0 LLR-135.7)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-SEG-SRC.1 | When | When the operator opens the window for the first time in a session, the system shall show the ranges source. | Yes; tested (test_default_tab_is_ranges_with_and_without_an_a2l). |
| R-SEG-SRC.2 | When | When the operator presses `t`, the system shall show the next source in the order ranges, manual, a2l, ranges. | Yes. |
| R-SEG-SRC.3 | U | The system shall show the number of rows of each source beside the source's name. | Yes; tested (test_a2l_tab_without_a2l_renders_the_neutral_note_and_stays_clickable). |
| R-SEG-SRC.4 | U | The system shall list in the ranges source one row per range of the loaded image, in address order. | Yes; tested (test_tc710_split_from_each_source_naming). |
| R-SEG-SRC.5 | U | The system shall name the rows of the ranges source `range_<ii>`. | Yes; tested (test_tc710_split_from_each_source_naming). |
| R-SEG-SRC.6 | U | The system shall list in the a2l source one row per MEMORY_SEGMENT of the session's A2L that has a base and a size above 0. | Partly: a size of 0 or below also gives a row (D17-37). |
| R-SEG-SRC.7 | U | The system shall name each row of the a2l source after its MEMORY_SEGMENT. | Yes; tested (test_tc710_split_from_each_source_naming). |
| R-SEG-SRC.8 | If | If a MEMORY_SEGMENT has no name, then the system shall name its row `segment_<ii>`, where `<ii>` is the segment's position among the A2L's MEMORY_SEGMENTs. | Yes; untested. |
| R-SEG-SRC.9 | If | If no A2L is loaded, then the system shall show in the a2l source the note `no A2L loaded — load one (^L) or use ranges/manual`. | Yes; tested (test_a2l_tab_without_a2l_renders_the_neutral_note_and_stays_clickable). |
| R-SEG-SRC.10 | If | If the session's A2L has no MEMORY_SEGMENT with a base and a size above 0, then the system shall show in the a2l source the note `the A2L has no MEMORY_SEGMENT with a base and a size`. | No: it shows `no A2L loaded — …` (D17-36). |
| R-SEG-SRC.11 | If | If the loaded image has no range, then the system shall show in the ranges source the note `no ranges — load an image (^L) or switch to manual`. | Yes. |
| R-SEG-SRC.12 | If | If the manual box holds no locality line, then the system shall show in the manual source the note `type localities (0xSTART-0xEND, one per line)`. | Yes. |
| R-SEG-SRC.13 | When | When the system shows a table row, the system shall show the row's name, base and coverage. | Yes. |
| R-SEG-SRC.14 | When | When the system shows a table row, the system shall show whether the row is selected. | Yes. |
| R-SEG-SRC.15 | When | When the operator presses up or `k`, the system shall move the table cursor one row up. | Yes. |
| R-SEG-SRC.16 | When | When the operator presses down or `j`, the system shall move the table cursor one row down. | Yes. |
| R-SEG-SRC.17 | When | When the operator presses space, the system shall switch the selection of the row under the cursor. | Yes. |
| R-SEG-SRC.18 | When | When the operator presses `a`, the system shall select every row of the shown source. | Yes; tested (test_tc710_split_from_each_source_naming). |
| R-SEG-SRC.19 | When | When the operator presses `n`, the system shall clear the selection of the shown source. | Yes. |
| R-SEG-SRC.20 | When | When the operator shows another source, the system shall keep the selection of every source. | Yes. |

### S17.3 · Manual localities (from S0 LLR-135.7)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-SEG-MAN.1 | When | When the operator edits the manual box, the system shall list one manual row per locality line, in line order. | Yes; tested (test_manual_parser_tolerant_forms_and_inclusive_end). |
| R-SEG-MAN.2 | U | The system shall name the rows of the manual source `locality_<ii>`. | Yes; tested (test_tc710_split_from_each_source_naming). |
| R-SEG-MAN.3 | U | The system shall read the end of a locality line as the last address of the locality. | Yes; tested (test_manual_parser_tolerant_forms_and_inclusive_end). |
| R-SEG-MAN.4 | U | The system shall ignore spaces and tabs in a locality line. | Yes; tested (same). |
| R-SEG-MAN.5 | U | The system shall accept each number of a locality line with or without `0x` or `0X`. | Yes; tested (same). |
| R-SEG-MAN.6 | U | The system shall ignore empty lines of the manual box. | Yes; untested. |
| R-SEG-MAN.7 | If | If a line of the manual box is not a locality line, then the system shall list no row for it. | Yes; tested (same). |
| R-SEG-MAN.8 | If | If the end of a locality line is below its start, then the system shall list no row for it. | Yes; tested (same). |
| R-SEG-MAN.9 | When | When the set of lines dropped from the manual box changes and is not empty, the system shall show the status `manual: dropped <dropped list>`. | Yes; untested. |

### S17.4 · Settings (from S0 HLR-136, LLR-136.4, LLR-136.5)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-SEG-SET.1 | When | When the system starts, the system shall set the mode to split. | Yes. |
| R-SEG-SET.2 | When | When the system starts, the system shall set the gaps to skip. | Yes. |
| R-SEG-SET.3 | When | When the system starts, the system shall set the pad byte to 0x00. | Yes; tested (test_pad_byte_defaults_to_zero_and_is_configurable). |
| R-SEG-SET.4 | When | When the system starts, the system shall set the format to S19. | Yes. |
| R-SEG-SET.5 | When | When the system starts, the system shall set the destination to project. | Yes. |
| R-SEG-SET.6 | When | When the operator presses `m`, the system shall switch the mode between split and join. | Yes. |
| R-SEG-SET.7 | When | When the mode changes to join, the system shall set the gaps to concat. | Yes. |
| R-SEG-SET.8 | When | When the mode changes to split, the system shall set the gaps to skip. | Yes. |
| R-SEG-SET.9 | When | When the operator presses `g` in split mode, the system shall switch the gaps between skip and fill. | Yes. |
| R-SEG-SET.10 | When | When the operator presses `g` in join mode, the system shall switch the gaps between concat and fill. | Yes. |
| R-SEG-SET.11 | When | When the operator presses `p`, the system shall switch the pad byte between 0x00 and 0xFF. | Yes; tested (test_pad_byte_defaults_to_zero_and_is_configurable). |
| R-SEG-SET.12 | When | When the operator presses `f`, the system shall change the format in the order S19, HEX, BIN, S19. | Yes. |
| R-SEG-SET.13 | When | When the operator presses `d`, the system shall switch the destination between project and common. | Yes. |
| R-SEG-SET.14 | If | If no project is open, then the system shall export to the common destination. | Yes; tested (test_destination_follows_the_change1_scoped_homes). |

### S17.5 · The preview (from S0 HLR-135, HLR-136, LLR-135.5, LLR-136.6)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-SEG-PREV.1 | When | When the rows, the selection or a setting changes, the system shall update the preview. | Yes. |
| R-SEG-PREV.2 | When | When the system shows the preview band, the system shall show each address of the band span in the class of CTX-SJE-BAND that the planned export gives it. | Partly: in split with gaps skip, the uncovered part of each selected row shows as fill (D17-24). |
| R-SEG-PREV.3 | While | While no row is selected and the loaded image has no range, the system shall show in the band `· nothing selected — tick a row with ␣ or press a for all`. | Yes. |
| R-SEG-PREV.4 | When | When the system shows the naming line, the system shall show as its sample the name the export would give its first file. | Partly: the sample is built from the raw row name, not the segment part (D17-20). |
| R-SEG-PREV.5 | While | While split mode is chosen with no row selected, the system shall show the naming sample `<stem>_segment.<ext>`. | Yes. |
| R-SEG-PREV.6 | While | While no row is selected, the system shall show the state line `∅ nothing selected — tick a row (␣) or press a`. | Yes. |
| R-SEG-PREV.7 | If | If the planned export has a conflict byte, then the system shall show the state line `⚠ <size> would clobber source — abort on export`. | Partly: a guard file hides it (D17-27); tested (test_tc710_plan_conflict_abort_matches_engine). |
| R-SEG-PREV.8 | If | If the planned export has a guard file and no conflict byte, then the system shall show the state line `⚠ GUARD  <guard span size> span — e will ask`. | Partly: join fill only (D17-32); tested (test_export_cues_name_the_bound_export_key). |
| R-SEG-PREV.9 | If | If the planned export has an empty file, no guard file and no conflict byte, then the system shall show the state line `⚠ <n> empty file(s) — 0 B of source — e will ask`. | Partly: an empty join concat file is not counted (D17-22). |
| R-SEG-PREV.10 | While | While the confirm is armed, the system shall show `— e again to confirm` in place of `— e will ask` in the state line. | Yes; tested (test_export_cues_name_the_bound_export_key). |
| R-SEG-PREV.11 | If | If a row is selected and the planned export has no conflict byte, no guard file and no empty file, then the system shall show the state line `ready — e exports`. | Yes; tested (test_export_cues_name_the_bound_export_key). |
| R-SEG-PREV.12 | While | While split mode is chosen with a row selected, the system shall show the stats line `<n> file(s) · <size> data`. | Yes. |
| R-SEG-PREV.13 | While | While split mode is chosen and the planned files hold pad bytes, the system shall end the stats line with `  ·  <size> pad`. | Yes. |
| R-SEG-PREV.14 | While | While join concat is chosen with a row selected, the system shall show the stats line `packed <size>  ·  concat: offsets remapped, no pads`. | Yes. |
| R-SEG-PREV.15 | While | While join fill is chosen with a row selected, the system shall show the stats line `packed <size>  ·  span <size>  ·  fill <pct>%`. | Yes; tested (test_guard_chip_renders_on_the_demo_case). |
| R-SEG-PREV.16 | While | While split mode is chosen, the system shall show the split summary of CTX-SJE-TEXT. | Yes; untested. |
| R-SEG-PREV.17 | While | While join concat is chosen with a row selected, the system shall show the concat summary of CTX-SJE-TEXT. | No: the base is always `0x00000000` (D17-23). |
| R-SEG-PREV.18 | While | While join fill is chosen with a row selected, the system shall show the fill summary of CTX-SJE-TEXT. | Partly: the span ends at the address after the last one (D17-29). |
| R-SEG-PREV.19 | While | While join mode is chosen with no row selected, the system shall show the summary `Join mode — select at least one range to join`. | Yes. |

### S17.6 · What an export holds (from S0 HLR-136, HLR-137, LLR-160.3)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-SEG-OUT.1 | When | When the system exports in split mode, the system shall write one export file per selected row. | Yes; tested (test_tc710_split_from_each_source_naming). |
| R-SEG-OUT.2 | When | When the system exports in split mode with gaps skip, the system shall put in each split file the covered bytes of its row span, at their addresses. | Yes; tested (test_split_skip_writes_only_the_covered_sub_ranges). |
| R-SEG-OUT.3 | When | When the system exports in split mode with gaps fill, the system shall put in each split file every address of its row span, with the pad byte where the image holds no byte. | Yes; tested (test_split_fill_pads_only_inside_the_files_own_span). |
| R-SEG-OUT.4 | If | If a split file is an empty file, then the system shall write it with no data byte. | Yes; tested (test_zero_coverage_requires_confirm_then_writes). |
| R-SEG-OUT.5 | When | When the system exports in join mode, the system shall write one export file for all selected rows. | Yes; tested (test_export_formats_join_byte_level). |
| R-SEG-OUT.6 | When | When the system exports in join concat, the system shall put in the join file the covered bytes of the selected rows, in ascending order of base, back to back from the lowest selected base. | Yes; tested (test_join_concat_packs_ascending_from_the_lowest_base). |
| R-SEG-OUT.7 | When | When the system exports in join fill, the system shall put in the join file every address of the join span, with the pad byte where no selected row has a covered byte. | Yes; tested (test_join_fill_keeps_original_offsets_and_ctx_cells). |
| R-SEG-OUT.8 | U | The system shall take the bytes of an export only from addresses inside the ranges of the loaded image. | Yes; tested (test_tc_b99_30_mac_only_export_writes_no_data_record). |
| R-SEG-OUT.9 | When | When the system writes a BIN file, the system shall write its bytes in ascending address order. | Yes; tested (test_tc684_bin_bytes_are_in_address_order_exact_length). |
| R-SEG-OUT.10 | When | When the system writes a BIN file, the system shall write a sidecar that holds the address of the BIN file's first byte. | Yes; tested (test_export_formats_split_byte_level). |
| R-SEG-OUT.11 | If | If a BIN file holds no byte, then the system shall write in its sidecar the lowest base of its selected rows. | Partly: join concat writes `0x00000000` (D17-22); tested for split (test_zero_coverage_requires_confirm_then_writes). |
| R-SEG-OUT.12 | If | If a BIN split file with gaps skip would hold covered bytes that are not contiguous, then the system shall refuse the export with the reason `"<name>" has gaps; a BIN file cannot keep their addresses — choose gaps fill (g)`. | No: the bytes after a gap are written at the wrong offset (D17-30). |
| R-SEG-OUT.13 | When | When the system writes an S19 file of an export, the system shall write it as an S19 export of CTX-SJE-FORMAT. | Yes; tested (test_export_formats_split_byte_level). |
| R-SEG-OUT.14 | When | When the system writes an S19 file of an export from an image loaded from an S19 file, the system shall write the source's S0 data in the S0 record. | No: the S0 record has no data (D17-33). |
| R-SEG-OUT.15 | When | When the system writes an S19 file of an export, the system shall write address 0 in the terminator. | Yes (D17-8). |
| R-SEG-OUT.16 | When | When the system writes a HEX file of an export, the system shall write it as a HEX export of CTX-SJE-FORMAT. | Yes; tested (test_export_formats_split_byte_level). |
| R-SEG-OUT.17 | When | When the system writes an S19 file, a HEX file or a sidecar of an export, the system shall end each line with the line end of CTX-SJE-FORMAT. | Yes; untested. |
| R-SEG-OUT.18 | If | If an export file holds bytes of an invalid range (S8 CTX-SAVEBACK), then the system shall show the warning notification `Warning: <n> invalid source ranges exported, first at 0x<A8>`. | No: nothing is said (D17-34). |

### S17.7 · Names and placement (from S0 HLR-160, LLR-160.1, 160.2, 160.4, 160.5)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-SEG-NAME.1 | When | When the system plans a split export, the system shall give each split file the split name of CTX-SJE-NAME. | Yes; tested (test_tc710_split_from_each_source_naming). |
| R-SEG-NAME.2 | When | When the system plans a join export, the system shall give the join file the join name of CTX-SJE-NAME. | Yes; tested (test_export_formats_join_byte_level). |
| R-SEG-NAME.3 | When | When the system plans a BIN file, the system shall give its sidecar the sidecar name of CTX-SJE-NAME. | Yes; tested (test_export_formats_split_byte_level). |
| R-SEG-NAME.4 | U | The system shall shorten the stem of an export file name so that the name stays within the name limit. | Yes; tested (test_tc_b99_28_sanitiser_hostile_set_and_boundaries). |
| R-SEG-NAME.5 | If | If no file is loaded, then the system shall use the stem `output`. | Yes. |
| R-SEG-PLACE.1 | When | When the system writes an export, the system shall create the destination folder if it does not exist. | Yes; tested (test_destination_follows_the_change1_scoped_homes). |
| R-SEG-PLACE.2 | When | When the system shows or refreshes the window, the system shall create no folder. | Yes. |
| R-SEG-PLACE.3 | If | If the destination holds a file with the same content as an S19 or HEX export file, under its name or one of its numbered names, then the system shall reuse that file. | Yes; tested (test_tc_b99_31_changed_bytes_take_the_next_free_name: the third export reuses `t_isle_1.s19`, re-pinned by LLR-163.4; `test_tc_b100_57_identical_reexport_to_existing_suffix_is_reused`). |
| R-SEG-PLACE.4 | If | If the name of an S19 or HEX export file is taken in the destination by a different content, then the system shall write the file under the lowest free numbered name. | Yes; tested (test_tc_b99_31_changed_bytes_take_the_next_free_name). |
| R-SEG-PLACE.5 | If | If the destination holds a BIN file and a sidecar with the same contents as a planned pair, under the pair's names or one shared numbered suffix, then the system shall reuse both files. | Partly: only under the pair's own names (D17-35); tested for those (test_tc_b99_31_bin_pair_placed_under_one_suffix; on Windows also when only the letter case differs: `test_tc_b100_57_group_word_compares_case_folded`). |
| R-SEG-PLACE.6 | If | If a BIN pair is not reused and one of its names is taken in the destination, then the system shall write both files under the lowest numbered suffix that is free for both names. | Yes; tested (test_tc_b99_31_orphan_sidecar_claims_the_pair_suffix). |
| R-SEG-PLACE.7 | If | If the destination folder is not inside the work area, then the system shall refuse the export with the notice `Export refused: Refusing to place: destination is not contained inside <base>/.s19tool/workarea/: <path>`. | Yes. |
| R-SEG-PLACE.8 | If | If the path to the destination folder passes through a link (S5 CTX-WORKAREA), then the system shall refuse the export with the notice `Export refused: Refusing to place: destination traverses a symbolic link or reparse point: <path>`. | Yes; tested (test_tc_b99_29_junction_destination_is_refused, refusal only). |
| R-SEG-PLACE.9 | If | If the destination folder cannot be created, then the system shall refuse the export with the notice `Export refused: Refusing to export: destination cannot be created: <folder> (<error>)`. | Yes; untested. |
| R-SEG-PLACE.10 | If | If a link exists at the name of an export file, then the system shall refuse the export with the reason `"<name>" already exists as a link or reparse point — refusing to write through it`. | Yes; tested (test_tc_b99_29_existing_symlink_at_final_name_is_refused). |
| R-SEG-PLACE.11 | If | If the full path of an export file with a two-digit numbered suffix would exceed the path limit, then the system shall refuse the export with the reason `"<name>" resolves to <n> characters — over the platform limit of 260`. | Yes; tested (test_tc_b99_41_over_long_full_path_refused_at_plan_time). |
| R-SEG-PLACE.12 | If | If the staging path of an export file with a two-digit numbered suffix would exceed the path limit, then the system shall refuse the export with the reason `"<name>" stages at <n> characters — over the platform limit of 260`. | Yes; untested. |
| R-SEG-PLACE.13 | If | If two export file names are equal when compared case-folded, then the system shall refuse the export with the reason `export names collide (compared case-folded): "<name>" (segment <raw>) and "<name>" (segment <raw>)`. | Yes; tested (test_tc_b99_41_case_folded_collision_refuses_before_any_write). |
| R-SEG-PLACE.14 | If | If an export file would be larger than the copy limit, then the system shall refuse the export with the reason `"<name>" would be <n> bytes — over the copy limit of 268435456 bytes`. | Partly: refused only when that file is placed, after earlier files are written, as a part-way notice (D17-31). |
| R-SEG-PLACE.15 | If | If the system refuses an export with a reason, then the system shall show the reason as the refusal notice of CTX-SJE-TEXT. | Yes; tested (test_tc_b99_29_hostile_segment_name_renders_literally). |
| R-SEG-PLACE.16 | If | If the system refuses an export, then the system shall write no file of it. | Yes; tested (test_tc_b99_41_one_refused_name_refuses_the_whole_set). |
| R-SEG-PLACE.17 | If | If writing a BIN pair fails, then the system shall leave neither file of the pair in the destination. | Yes; tested (test_tc_b99_31_forced_failure_rolls_back_every_own_claim). |
| R-SEG-PLACE.18 | If | If writing an export fails after a file is placed, then the system shall show the part-way notice of CTX-SJE-TEXT. | Yes; tested (test_tc_b99_41_part_way_failure_status_names_the_first_file). |

### S17.8 · Exporting (from S0 HLR-136, LLR-135.5, LLR-136.4, LLR-136.6)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-SEG-EXP.1 | When | When the operator makes an export request, the system shall start an export. | Yes; tested (test_export_cues_name_the_bound_export_key). |
| R-SEG-EXP.2 | If | If no row is selected when an export starts, then the system shall show the status `nothing selected — tick a row with ␣ or press a`. | Yes. |
| R-SEG-EXP.3 | If | If the planned export has a conflict byte, then the system shall refuse it with the notice `Export aborted: <n> source byte(s) in a padded gap differ from the pad byte 0x<PP>, first at 0x<A8>. Nothing written.` | Partly: refused, but with a status and a notification of other texts that name no address (D17-27); tested (test_tc710_plan_conflict_abort_matches_engine). |
| R-SEG-EXP.4 | If | If two selected rows of a join export share an address, then the system shall refuse it with the notice `Export aborted: rows 0x<A8>–0x<A8> and 0x<A8>–0x<A8> overlap. Nothing written.` | Partly: refused, but as `export aborted: join concat: overlapping ranges …` with internal words and ends one past the last address; the preview warns of nothing (D17-26); tested in the engine (test_tc685_overlapping_ranges_abort_instead_of_clobbering). |
| R-SEG-EXP.5 | If | If an export starts while the confirm is not armed and the planned export has a guard file or an empty file, then the system shall arm the confirm without writing. | Partly: no guard for split fill (D17-32); no confirm for an empty join concat file (D17-22); tested (test_tc708_guard_two_step_arm_disarm_rearm_confirm, test_zero_coverage_requires_confirm_then_writes). |
| R-SEG-EXP.6 | When | When the system arms the confirm, the system shall show the warning notification `<confirm reasons> — press e again to confirm`. | Yes; tested (test_export_cues_name_the_bound_export_key). |
| R-SEG-EXP.7 | When | When an export starts while the confirm is armed, the system shall write the export. | Yes; tested (test_tc708_guard_two_step_arm_disarm_rearm_confirm). |
| R-SEG-EXP.8 | When | When the operator changes the selection, the source, the mode, the gaps, the pad byte, the format or the destination, the system shall disarm the confirm. | Yes; tested for the format (test_tc708_guard_two_step_arm_disarm_rearm_confirm). |
| R-SEG-EXP.9 | When | When the operator edits the manual box, the system shall disarm the confirm. | No (D17-25). |
| R-SEG-EXP.10 | When | When the loaded file changes, the system shall disarm the confirm. | Yes. |
| R-SEG-EXP.11 | When | When an export is written or refused, the system shall disarm the confirm. | Yes. |
| R-SEG-EXP.12 | When | When every file of an export is written or reused, the system shall show the status `Exported <n> file(s): <written list> → <destination folder>`. | Partly: `Exported 1 files` (D17-28); tested in part (test_at_b99_11_sanitised_mac_only_second_export_takes_suffix; the `wrote` / `reused` word of each file: `test_tc_b100_57_identical_reexport_to_existing_suffix_is_reused`, `test_tc_b100_57_group_word_compares_case_folded`). |
| R-SEG-EXP.13 | When | When every file of an export is written or reused, the system shall show the notification `Exported <n> file(s): <written list>`. | Partly: `Exported 1 files` (D17-28). |
| R-SEG-EXP.14 | If | If an export fails for a reason that no other row of S17.7 or S17.8 names, then the system shall show the notice `Export failed: <error>`. | Partly: `export failed: <error>` (D17-28). |

---

## 5. Decisions: recommendation applied

**Requirement follows the code, or moves (no code change)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D17-1 | The chapter has no requirement row; its behaviour is only in S0's retired ids HLR-135, 136, 137 and LLR-135.1 … 137.4. | Rows written here under "(from S0 …)" sub-headings; S0 keeps a pointer to S17 for each id. |
| D17-2 | HLR-135, LLR-135.1 … 135.4 and the first sentence of HLR-136 prescribe the screen design (chassis, widths 118/100/58/54/40/30, hex colours, glyph per class, run counts, gantt cap 6, `.db-pane`, SVG frames as oracle). | Not requirements. The current design is CTX-SJE-LAYOUT (informative). A change to it needs a prototype round. |
| D17-3 | HLR-137, LLR-137.1 and 137.3 describe how the engine is composed ("ride", "compose get_memory_map + set_bytes_at", "one gap-fill pass", "none ships today", the new-module placement). | Out (design and history). What the files hold is S17.6. |
| D17-4 | LLR-137.4 changes the A2L parser (quoted MEMORY_SEGMENT names, the offset field, fixtures, consumers at `a2l.py:1448`, `:1676`). | Parser rows go to S2. S17 keeps only which MEMORY_SEGMENTs give rows (R-SEG-SRC.6). |
| D17-5 | LLR-136.5: "the naming pattern shall default to ‹stem›_‹segment›". Nothing can change it (`segment_split_view.py:1488`; never assigned again). | Fixed names (R-SEG-NAME.1, .2). No edit control proposed. |
| D17-6 | LLR-136.4: pad byte "cycled or typed". `p` switches 0x00 ↔ 0xFF only (`segment_split_view.py:1998-2000`). | Two values (R-SEG-SET.11). A typed pad byte would be a new feature: not proposed. |
| D17-7 | LLR-137.2: "exactly size flat bytes from the segment base (intra-range gaps not padded)" and "the base address" in the sidecar. The code writes the file's bytes in order and, in the sidecar, the first planned address (`segment_split_view.py:791-802`); with a leading hole that is the first covered byte, which is what makes the pair readable. | BIN and sidecar rows follow the code (R-SEG-OUT.9, .10). The hole case: D17-30. |
| D17-8 | S8 D8-29 asked: the export writes terminator address 0 (`io.py:1823`). | Keep 0: a split or joined part need not hold the source's start address (R-SEG-OUT.15). |
| D17-9 | With no file loaded, manual localities can be exported: header-only or 0-byte files named `output_…`, after the empty-file confirm. | Keep: the confirm tells the operator (R-SEG-NAME.5, R-SEG-EXP.5). |
| D17-10 | Destination project with no open project writes to `<work area>/splits/` (`project_gather_service.py:632-633`); the summary shows that folder. | Keep (R-SEG-SET.14). |
| D17-11 | LLR-135.6 and S6 CTX-SHELL: palette entry, no rail key; footer and help. | The palette and rail rows stay S6's (R-TUI-021.10, .11, R-TUI-022.2); the key bar and help stay S7's. Esc is here (R-SEG-OPEN.2). |
| D17-12 | HLR-160 / LLR-160.1 … 160.5 (batch-99) are Split / Join / Export behaviour but sit in S0 apart from HLR-135 … 137; they name functions (`place_group_into_workarea`, NEW, B99-I2a), `os.replace` and staging. | Absorbed as S17.7; the design parts go. S0 keeps a pointer. |
| D17-44 | Batch-100 HLR-163 (Inc 1, before 093a7c0): LLR-163.6 makes the export take each file's `wrote` / `reused` word from the placement it performed, with no byte-identity rule of its own; LLR-163.4 re-pins `test_tc_b99_31_changed_bytes_take_the_next_free_name` so a third export of the same changed bytes reuses `t_isle_1.s19` and says `reused`. The rows already say this: R-SEG-PLACE.3 (reuse under the name or a numbered name), R-SEG-EXP.12 and CTX-SJE-TEXT's written list (`wrote` / `reused`). `segment_split_view.py` is unchanged since 093a7c0. | No row change; cites added (TC-B100-57). `test_tc_b100_57_export_holds_no_byte_identity_rule` verifies implementation only (a source census) and is not row evidence. |

**Remove (rule use/defer/delete)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D17-13 | `segment_ops.slice_ranges` (`segment_ops.py:117-135`) and `segment_ops.write_bin_with_sidecar` (`:196-220`) are called only by tests; the window writes BIN pairs through its own plan and placement. | Remove both and their tests. |
| D17-14 | The sanitiser prefixes `_` to device names and normalises superscript digits (`segment_split_view.py:622-624`), and falls back to `segment_<index>` for an empty name (`:627`). Every export name starts with `<stem>_` (`:630-656`; the stem is never empty, `:1608-1612`), so no name can be a device name; and no row name is empty (A2L rows without a name get `segment_<ii>`, `:1581`). Both branches have no effect. | Remove both branches and their test cases. The segment part is CTX-SJE-NAME. |

**Code change: correct a defect**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D17-20 | The naming sample, the output label and the per-file labels use the raw row name (`segment_split_view.py:1652-1659`, `:1897-1902`, `:459`); the file is written with the segment part (`:790-806`). An A2L segment `'PrgCode'` previews as `prg_'PrgCode'.bin` and is written as `prg__PrgCode_.bin` (test_tc710_split_from_each_source_naming). | Preview the names the export writes (R-SEG-PREV.4). |
| D17-21 | The table, naming line, output label and per-file rows show A2L names without S1's safe-text function (`segment_split_view.py:1261`, `:1278`, `:1410-1412`). The window is on S1's safe-text list. | Use the safe-text function there (S1 R-TUI-103). Backlog only; rows are S1's. |
| D17-22 | Join concat: the plan sets the empty-file count to 0 (`segment_split_view.py:404-407`), so an empty join file is written with no confirm; its BIN sidecar says `0x00000000` (`:800`, `segment_ops.py:454-455`). | Count it as an empty file (R-SEG-PREV.9, R-SEG-EXP.5); sidecar = lowest selected base (R-SEG-OUT.11). |
| D17-23 | The concat summary prints the band's low end, which is 0 for concat (`segment_split_view.py:405`, `:1829`): always `packed from base 0x00000000`. The file starts at the lowest selected base (`segment_ops.py:447-456`). | Print the real base (R-SEG-PREV.17). |
| D17-24 | In split mode the band marks every selected row span as fill whatever the gaps (`segment_split_view.py:427-429`). With gaps skip the files hold no pad there. | Fill only with gaps fill; else absent (R-SEG-PREV.2). |
| D17-25 | An edit of the manual box only repaints (`segment_split_view.py:2154-2156`); the other changes also disarm (`:1936-1938`). The rows of a confirmed plan can change after the first `e`. | Disarm (R-SEG-EXP.9). |
| D17-26 | Two selected rows that overlap (A2L segments or typed localities) in join mode: the preview merges them silently (`segment_split_view.py:330-336`); the engine refuses with `join concat: overlapping ranges 0x…-0x… and 0x…-0x… — export aborted (on_gap_conflict=abort)` (`segment_ops.py:257-263`), shown as `export aborted: …` (`segment_split_view.py:2079`). | One plain text with last addresses (R-SEG-EXP.4). |
| D17-27 | A conflict gives the status `export aborted — <size> would clobber source (the ▒ bytes); the fill cannot overwrite real bytes` and a notification of another text (`segment_split_view.py:2020-2029`); neither names an address, though LLR-136.4 asks for it. The state line shows the guard and hides the conflict (`:1729-1741`), while the export refuses on the conflict first (`:2017`). | One notice naming the count and the first address (R-SEG-EXP.3); conflict before guard in the state line (R-SEG-PREV.7, .8). |
| D17-28 | `Exported 1 files` (`segment_split_view.py:2139`, `:2141`); `export failed: <error>` (`:2122`) next to `Export failed: …` (`:2112`). | `file(s)` rule and one capitalised outcome word (R-SEG-EXP.12 … .14). |
| D17-29 | The fill summary prints `0x<base>–0x<base + span>` (`segment_split_view.py:1831-1836`) and the overlap message prints end addresses one past the range; the manual box and the ruler use the last address. | Last address everywhere (R-SEG-PREV.18, R-SEG-EXP.4). |
| D17-30 | A BIN split file with gaps skip writes the covered bytes back to back (`segment_ops.py:170-175`); after a hole every byte sits at the wrong offset, and the sidecar cannot tell. | Refuse, naming the file (R-SEG-OUT.12). |
| D17-31 | A file above the copy limit is refused only when it is placed (`workspace.py:1146-1147` through `segment_split_view.py:983-997`): after the whole file is built in memory and staged, after earlier files of the same export are written, with a message that names the staging path. Join fill builds one entry per address of the span (`segment_ops.py:396-398`); the guard's own demo plans a 384 MiB span (test_guard_chip_renders_on_the_demo_case). | Refuse at plan time, before any file (R-SEG-PLACE.14). Measure the memory use of fills under the limit in the batch. |
| D17-32 | The guard covers join fill only (`segment_split_view.py:480-485`). A split fill of an A2L segment of several MiB with little data writes a mostly-pad file with no question; LLR-136.6 says such segments are the norm. | Same guard per split fill file (CTX-SJE-PLAN guard file, R-SEG-PREV.8, R-SEG-EXP.5). |
| D17-33 | S8 asked. The S19 export writes an empty S0 (`segment_ops.py:502-505` → `io.py:1816-1817`), though the loaded file keeps the source's S0 (`load_service.py:61-64`). HLR-153 (batch-99): an image loaded from an S19 and written as S19 carries its S0. | Write the source's S0 data (R-SEG-OUT.14), as S8 D8-27 does for the save-back. |
| D17-34 | S1 D-2 asked. Bytes of an invalid range are exported; S19 and HEX files get new, valid checksums; nothing is said. | Export and warn, as S8 D8-26 (R-SEG-OUT.18). |
| D17-35 | A single file is reused under a numbered name too (test_tc_b99_31_changed_bytes_take_the_next_free_name); a BIN pair only under its own names (`workspace.py:1625-1630`). Each re-export of an unchanged pair after a change writes one more `_<N>` pair. | Reuse an identical pair under any shared suffix (R-SEG-PLACE.5). |
| D17-36 | The a2l note says `no A2L loaded — …` whenever the a2l source is empty (`segment_split_view.py:1715-1717`), also when an A2L is loaded with no usable MEMORY_SEGMENT. | Own note (R-SEG-SRC.10). |
| D17-37 | A MEMORY_SEGMENT with a size of 0 or below gives a row (`segment_split_view.py:1578-1582`); in join mode it raises `inverted range`, shown as `export failed: …`. | No row (R-SEG-SRC.6). |
| D17-38 | Every load and unload refreshes the window (`app.py:12578-12612`), and the refresh focuses its table (`segment_split_view.py:1699-1702`) even while the window is hidden; Textual's focus check reads visibility, not display (`textual/widget.py:2368-2375`, installed copy). If the focus lands there, `e`, `a` or space act on a hidden window. Not reproduced. | Reproduce in the batch; focus only while shown (R-SEG-OPEN.6). |

**Prototype first** (visual; prototype round with real captures and your verdict before implementation)

| # | The situation | What the round must answer |
|---|---|---|
| D17-40 | Coverage marks: zero coverage is red (`#fd8383`, the palette's "error"), though LLR-136.6 calls it the norm; partial is amber `#d9a35b`, outside the palette of S3 CTX-LEGEND (`segment_split_view.py:116-118`, `:1264-1269`, `:1283-1292`). | Which palette colour and glyph each coverage state takes. |
| D17-41 | In join concat the ruler shows `0x00000000 … 0x<packed − 1>` (`segment_split_view.py:405`, `:1913`); the join file starts at the lowest selected base. | Show the file's real addresses, or label the ruler as offsets. |
| D17-42 | The legend says `pad`, `clash`, `src` (`segment_split_view.py:1416-1436`); the stats say `fill`, the state line `clobber`, the classes data/fill/conflict/context. | One word per class on every surface. |
| D17-43 | The pad byte shows only with gaps fill (`segment_split_view.py:1382-1384`), but `p` changes it in every state, unseen. | Show the pad byte always, or make `p` act only with fill. |

**Passed to other groups**

- **S0**: pointers for HLR-135, 136, 137, LLR-135.1 … 137.3, HLR-160, LLR-160.1 … 160.5: their rows now live in S17 (D17-1, D17-12). LLR-137.4 goes to S2 (D17-4).
- **S1**: the Split / Join / Export table, naming line, output label and per-file rows show A2L names without the safe-text function (D17-21). Answer to D-2: export and warn (D17-34).
- **S2**: LLR-137.4, the MEMORY_SEGMENT parse (quoted names, offset field), belongs to the A2L reading rows; S17 uses only base, size and name.
- **S5**: the export places files with S5's same-content and numbered-name rules, guard texts and copy limit (R-TUI-006.1, .2, R-TUI-002.4, .5); the BIN pair reuse rule (D17-35); `splits/` is a work-area folder the Workarea Files list does not show.
- **S6**: R-TUI-021.10 / .11 and R-TUI-022.2 stay the palette and rail rows of this window; Esc is R-SEG-OPEN.2.
- **S7**: the window's keys in the key bar (`space a n t m g f p d e esc`), its help section, and the manual box as a multi-line box (paste limit). Printable keys typed in the manual box are text, so `t` and `e` act only with the focus outside it.
- **S8**: answer to "S17: export writes through S8.7 with an empty S0 … and terminator address 0": S0 carried (D17-33), terminator 0 kept (D17-8). The export uses 32 data bytes per S19 record and has no Width control.
- **S11**: the project home `<project>/splits/` is created only by an export (R-SEG-PLACE.1, .2); `splits` is in the reserved work-area homes of the project list (LLR-162.2, S11's).

---

**Received from later groups** (after all groups were written)

- S17.1 (S8: empty S0 and terminator address 0) → covered by D17-33 (R-SEG-OUT.14, the source's S0 is written) and D17-8 (R-SEG-OUT.15, address 0 kept). Every other whole-image writer keeps the source's address (S8 R-S19-EMIT.11, S11 D11-42, S13 D13-28, S15 D15-14); Split / Join / Export alone keeps 0, because a part need not hold the source's start address.
- S17.2 (S13: the extract and split the deleted placeholders promised) → covered by S17.5 … S17.8; S13 D13-13 deletes the placeholders.

**Reconciled with batch-100 (s19_app 570b4b5)**

- Rows added, changed or retired: none. Cells changed (tests named): R-SEG-PLACE.3, R-SEG-PLACE.5 (still Partly, D17-35), R-SEG-EXP.12 (still Partly, D17-28).
- Decisions added: D17-44. Decisions superseded: none.
- D17-38 re-checked at 570b4b5: the load tails re-home the focus (batch-100 HLR-166, `app.py:9695`, already at 093a7c0), but an unload still refreshes the hidden window with no re-home (`app.py:16855-16867`); it stays open and unreproduced.

## 6. Counts

| | Old S17 | Strict |
|---|---:|---:|
| Requirement statements | 0 rows; 4 HLR + 22 LLR in S0's table (HLR-135, 136, 137, 160) | 123 rows |
| Statements that are design, process or contradicted by the code | 11 (HLR-135, LLR-135.1–135.4 design; HLR-137, LLR-137.1, 137.3 implementation; LLR-137.4 belongs to S2; LLR-136.5 "default"; LLR-137.2 self-contradiction) | 0 |
| Rows by form: U / When / While / If / Where | — | 12 / 60 / 13 / 38 / 0 |
| Rows that could not be written in EARS | — | 0 |
| Decisions | — | 38 (13 follow the code or move, 2 remove, 19 correct a defect, 4 prototype first; numbers not contiguous) |

Checked by script (`ears_lint.py`): one `shall` per row, correct opening words per form, `If … then`, no "unless" / "only if", no repeated id across the review files.
