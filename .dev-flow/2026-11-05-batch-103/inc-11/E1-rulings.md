# Inc 11 — E1 rulings: canon changes and open decisions

Batch 2026-11-05-batch-103, increment 11. Author: E1 agent (Opus 5.5), 2026-11-06. Rows: `01-requirements.md`. Cases: `02-test-cases.md`. Slice: `E1-slice.md`. Evidence: `evidence-e1/`.

**Confidentiality (operator, 2026-11-07).** The operator's sample of the real file was used only to choose the hypotheses. No name, address or number from it is written in this folder, its scripts or its transcripts. A scan of `evidence-e1/` for the sample's address and digits returns 0 hits. No copy of the sample was ever made on the runner. Every shape in the evidence is synthetic.

## 1. Canon rows changed in place

| Row | Was | Now | Reason |
|---|---|---|---|
| R-A2L-001.1 | "…build its sections from its /begin and /end **lines**." | "…from its /begin and /end **words**, wherever those words stand on a line." | A `/begin` or `/end` that does not start its line is part of the file's structure. V171's 30 one-line IF_DATA and Inc 2's J4 and J5 show that a line-based reading is wrong (BL-I2-12, BL-I3-11). |
| R-A2L-001.2 | "…ignore the text of comments **when it builds sections**." | "The system shall read no word from the text of a comment." | The old scope was too narrow. Today the tag walk reads keyword lines inside comments (RP-B7, B27, B37; Inc 2 B3, C2, C3), and a `/begin` inside a comment opens a section (Inc 2 L, L2, E3S-35). The rule must hold for every word, not only for sections. |
| R-A2L-001.3 → .3.1, .3.2 | "…read a quoted string as one value, without its quotes." | .3.1 "…as one word, without its quotes." and .3.2, the backslash pair | Split, because the escape rule has its own failure: today `"C:\\"` does not close (RP-B24). "Value" becomes "word" to match the new definitions. |
| R-A2L-001.4 | "If an /end **line** has no open section…" | "If an /end **word** …" | Follows .001.1. The text of the message is unchanged. |
| R-A2L-001.5 | "If an /end **line** names a section other than the one it closes…" | "If an /end **word** …" | Follows .001.1. **The code does not implement this row today**: `build_section_tree` never compares names (`a2l.py:219-226`), and V171 gives only `Unclosed …`. The row stays as it is, and Inc 11's code must meet it. |
| R-TUI-042a.2 | "The system shall show the tag table with no padding between cells." | "The system shall show at least one blank column between adjacent cells of the tag table." | **This row causes the operator's symptom.** With no padding, the Address cell and the computed Length cell paint as one hex string at every width from 80 to 220 columns. So do Region+Limits and Raw+Physical [W220 … W80]. A requirement is never changed to match the code, but this row was itself the defect: the padding is the one thing that tells two numbers apart. The row lives outside `a2l.py`: see D-1. |

## 2. Context notes changed or added

- **CTX-A2L-FILE.**
  - *Comment*, *quoted string* and *section* are reworded, in the terms given in `01-requirements.md` § Definitions.
  - *Line end*, *blank*, *word*, *word character*, *number word*, *reference reading* and *hostile corpus* are added.
  - The old note said "The words after <NAME> on the /begin line are the section's header". That clause is wrong for the 189 V161 and V171 objects whose long identifier stands on a body line, and for BalanceTube's commented MEASUREMENT headers.
- **CTX-A2L-TAG.**
  - *MATRIX_DIM* is now the product of its numbers (D-7). R-A2L-014 and R-A2L-016 cite this term, so their texts do not change but their outcome does, for 14 tracked tags.
  - *Header words*, *keyword* (with the arity list) and *declared span* are added.

## 3. Open decisions — PROPOSED, awaiting the orchestrator's ruling

### D-1 — R-TUI-042a.2 (the operator's symptom) is a row in `app.py`, outside `a2l.py`. Which increment owns it?

- **A (recommended): Inc 11 owns it.** One argument changes: `cell_padding=0` → `1` at `app.py:8520` (`S19TuiApp._compose_screen_a2l`). Inc 11 then has 2 source files: `a2l.py` and `app.py`.
  - No batch-101 branch has a hunk near it. `b101-inc10`'s nearest hunks are at `:4593` and `:10048`; `b101-inc12b`'s last is at `:4582`; `b101-inc9` touches flow handlers.
  - Consequence: each of the 16 columns gains 2 cells of width. At 118 columns the tag pane, 60 cells wide [W118], shows fewer columns. That interacts with backlog item 5 ("A2L Explorer at 118 columns: … the Length column is empty"). Inc 7's layout owns the full fix of that item.
  - Amendment A1 rule 3 holds `app.py` work until batch-101 Inc 10a and Inc 12 merge, so the orchestrator may choose to defer this one edit to after that merge.
- **B: route it to Inc 5 or Inc 7** (W1/W2, which own `app.py` A2L views). Consequence: the operator's symptom stays visible until W1 or W2 lands, and Inc 11 closes with US-103-07 only partly met.
- **C: keep `cell_padding=0` and paint a separator** (for example `│`) in the cells. This costs one column per cell, as A does, and adds a glyph. It does not help more than A.

### D-2 — Which characters separate words?

- **A (recommended, rows .2 to .4): only the ASCII blanks and line ends.** Every other character stays in its word. Outside comments and strings it gives the parse error of .4.
  - Consequence: a NBSP or U+2028 next to an address makes that word unreadable. Today it splits the word silently.
  - On the 35 tracked files the change costs 0: no such character stands outside comments and strings [CH].
- **B: keep Unicode `str.isspace`.** Consequence: NBSP, NEL, FS–US, U+2028 and U+2029 still split words with no message. Characters that are not blanks, such as U+200B and U+FEFF, still lose the address silently.

### D-3 — UTF-16 files

- **A (recommended, row .6): refuse with a parse error.** The message tells the operator to save the file as UTF-8. No new decode path is added.
- **B: decode the file as UTF-16 by its BOM.** It is friendlier, but it adds a second encoding path to the reader. The progress callback counts bytes, which then no longer match characters.
- Today the file loads with 0 tags and reports `A2L loaded: <file>` [RP-A10, A11].

### D-4 — May a quoted string span line ends?

- **A (recommended, rows .14 and .15): yes.** An unterminated string then runs to the end of the file and gives `Line <n>: quoted string not closed`. That fails loud, and every object after it is lost, which the error makes visible. Inc 2's L7 then reads correctly. There are 0 multi-line strings in the tracked files.
- **B: a string ends at its line end, with an error.** The damage stays local, but an ANNOTATION_TEXT that holds `/end` lines misreads silently after the error line (L7).

### D-5 — `/include`

- **A (recommended, row .22): record the parse error `Line <n>: /include <file> is not read`.**
- **B: read the included file.** This needs path resolution against the A2L's folder, a recursion bound and a work-area guard. It is a new file input, and so a security review item. 1 tracked file uses `/include` (`merge_inc_test.a2l`).

### D-6 — A keyword declared twice among a tag's own words

- **A (recommended): record the error of .32, and keep the last value.** That is today's choice for ECU_ADDRESS, LENGTH, BYTE_ORDER and BIT_MASK in the tag walk. **Inc 2b must refuse to edit an object whose line span holds a parse error.** Every new error names its line, so Inc 2b can do that without a reader flag.
- **B: give the tag no value for that keyword.** This fails closed for ECU_ADDRESS. It does not for BYTE_ORDER, which falls back to the layout, the module or little-endian, so it could pick a wrong frame silently.
- 0 tracked tags declare a keyword twice.

### D-7 — MATRIX_DIM as the product of its numbers (row .37)

- **A (recommended): Inc 11 owns it.** It is a reader rule, Inc 2's E3S-40 and Inc 3 rest on it, and it changes 14 tracked tags (listed).
- **B: leave it to the definition model** (Inc 2b, Inc 3). The tag table then keeps the first number, and the Explorer, the image check and the Memory Map keep showing short lengths for these 14 tags.

### D-8 — Where INSTANCE and BLOB go

- **A (recommended, rows .40 to .46): a separate list of declared spans in the parse payload, not tags.** R-A2L-005.2 stays as it is. Inc 2b's overlap index (R-A2L-DEF.138, E3S-37) reads the list. Nothing the operator sees changes.
- **B: make them tags shown in the A2L Explorer.** That is a visible change, so it needs a prototype round (E0 rule). It changes R-A2L-005.2, the tag counts, the MAC View matches and the `CROSS_A2L_ONLY_SYMBOL` issues. Backlog, if wanted.

### D-9 — The summary hides everything when a file has a parse error

`render_a2l_view` returns only the errors (`a2l.py:3650-3652`), against R-A2L-076 and R-A2L-077.

- **A (recommended): Inc 11 makes the code meet those rows.** This increment adds new parse errors (.4, .6, .10, .11, .15, .22, .28, .32 and .39). Without this fix, a file that gains one would lose its whole summary.
- **B: backlog.** `merge_inc_test.a2l` would then show only its new `/include` error.

### D-10 — Where `//` and `/*` open a comment

- **A (recommended, the C rule): anywhere outside a quoted string.** The glued `0x1234//c` and `0x1C2D3E00/*c*/4026` then read right. The cost is two hostile test inputs, `x[link=file:///etc]` and `LINK_x[link=file:///etc]` (`tests/test_tui_a2l_issue_recolor.py:103-118`, `:436-507`). Neither is a valid ASAM identifier, and each holds `//`. Their intent, an OSC-8 link token, can be carried by a token without `//`, such as `x[link=https:x]`, or by a quoted long identifier. Those tests are not in TC-032's protected set.
- **B: only at the start of a word.** The tests stay as they are, but `0x1234//c` keeps losing its address silently.

### D-11 — A header that is short, or missing

- **A (recommended, rows .27 and .28): a header ends at the first keyword.** With 1 to 6 words it is an error. With 0 words it is accepted silently: case 07's MEASUREMENTs are written that way, and 12 tags keep their reading.
- **B: a fixed count of 6 or 7 words.** That is strict ASAM, but case 07's 12 tags lose their address, as CANON's first variant showed.

### D-12 — Split?

60 rows in scope, against the 80 cap. Graph estimate: about 25 nodes (20 changed functions and 4 new; `E1-slice.md` §1), under the 40 cap. **No split is proposed.** If the orchestrator wants one, the boundary is the tokenizer and tree (sections A to G, J and K: 53 rows) against INSTANCE/BLOB (section H: 7 rows, plus .48's span comparison). The PLAN guess was about 30 rows; the difference comes from the encoding, header and view rows that the reproduction found.

## 4. Tests that pin today's defects, and the guards

These are E4 work, written here so that no tester mistakes them for regressions.

- **`tests/test_a2l_multiline_headers.py:389` (TC-097)** asserts `_strip_a2l_comments("CURVE/*c*/0x1") == "CURVE0x1"`. That is the glue that produces `0x<address><digits>` [H2a]. The assertion changes to a word break (R-A2L-READ.7); `:387` changes the same way.
- **`tests/test_b101_a2l_blocks_and_segments.py:281-293`** (`test_r_val_032_3_v171_one_line_if_data`) asserts V171's `Unclosed /begin sections detected.`, labelled "parser limit, backlog". After the change V171 has 0 errors (R-A2L-READ.17), and the test asserts that instead. R-VAL-032.3's IF_DATA exemption must still hold, so its assertion `_unrecognized(issues) == []` stays.
- **`tests/test_tui_a2l_issue_recolor.py`**: see D-10.
- **The freeze guards** fail on any `a2l.py` diff against `main`:
  - TC-027, `tests/test_engine_unchanged.py:120-151`;
  - TC-031, `tests/test_tui_directionb.py:6518-6529`, `:7046`, `:7069`;
  - the freeze arm of TC-B94-18, `tests/test_tui_issues_triage_b94.py:269-290`.

  The unfreeze removes `tui/a2l.py` from the guard set in the same PR. The re-freeze is a separate PR after the merge (`CLAUDE.md`, Engine-frozen guard).
- **TC-032** (`tests/test_tui_directionb.py:6533-6543`, `:7117`) forbids editing `test_tui_a2l.py`, `test_validation_a2l.py`, `test_validation_engine.py` and `test_color_policy_round_trip.py`, so those must pass unchanged. **Not checked at E1** whether any of them asserts a value this increment changes. E2 runs them on the base tree with the reader change emulated, or E4 runs them first.
- **Guards expected to stay green** (the consumer census): the V161 counts (`test_a2l_f841_cleanup.py:98-107`, `test_a2l_multiline_headers.py:111`, `:166`, `test_b97_check_editor.py`, 75 rows), the V171 segments (`test_a2l_enriched.py:171-216`), and the generated fixtures (`test_b101_a2l_blocks_and_segments.py:491`, `test_synth_release_case.py`).

## 5. What the change alters downstream (scope item 4)

Source: a read-only consumer census (`git grep` plus reads over `s19_app/` and `tests/`; Explore agent, 2026-11-06), summarised here. "Alters" means what the operator sees after the change.

| View or consumer | Reads | What changes |
|---|---|---|
| **Workspace A2L summary** (`services/a2l_service.py:10-27` → `render_a2l_view`; painted by `app.py:20147-20178`) | errors; sections (name, meta, lines); tags (name, address, length, region) | V171's summary today is 2 lines of error. After the change it lists sections and tags (D-9). Comment text leaves the header lines (.50). Control characters show as U+FFFD (.51). Commented-out copies leave the tag list. |
| **Loaded panel** (`screens_directionb.py:2036-2100`) | `len(a2l_data["tags"])` | The "N tags" count drops by each commented-out copy. Under D-8 A, INSTANCE and BLOB add nothing. |
| **A2L Explorer table** (`app.py:20286-20473`), filter (`:20475-20520`), row colour (`:819-874`) | name, address, length, limits, unit, bits, endian, datatype, description | A blank column between cells (R-TUI-042a.2). The 122 listed tags change: BalanceTube's 104 gain datatype and length, the 14 MATRIX_DIM tags get the product length, and V161/V171's `UNKNOWN` gets its name. The description filter now matches 189 more tags. A red row caused by a commented duplicate disappears. |
| **Detail card** (`app.py:1278-1341`) and description window (`:9725-9777`) | display identifier, name, address, description, byte order | No comment text before the address (.33, 6 tags). The `desc` line appears for 189 V161/V171 tags. A byte order read from a comment is gone. |
| **Issues screen** (`validation/rules.py:463-565`; `engine.py:112-148`; `validation_service.py:81-248`) | errors, tags, sections | `A2L_STRUCTURE_ERROR` goes for V171 and appears for files with new errors. `A2L_DUPLICATE_SYMBOL` goes for commented copies. `A2L_UNRECOGNIZED_BLOCK` may appear for blocks that an unclosed one-line IF_DATA hid under the exemption (none expected for V171). `A2L_BROKEN_REFERENCE` reads raw GROUP lines, which is unchanged unless E2 stores the lines without comments. `CROSS_A2L_S19_OUT_OF_RANGE` and coverage move with the 14 product lengths. |
| **MAC View** (`app.py:1074-1137`, `:17977-18153`) | tag name, address | `InA2L`, `Status` and `A2LMatch` change only for commented copies and renamed tags. |
| **Memory Map** (`app.py:19504-19546` → `screens_directionb.py:1135-1197`) | address, byte size | Symbol extents move for the 14 product lengths and the 104 BalanceTube tags. |
| **Check Editor and Patch Editor pickers** (`a2l_parameter_picker.py:526-560`); symbol resolution (`changes/io.py:1057-1174`) | name, address, length | A saved change document whose byte count matches today's length for one of the 14 MATRIX_DIM tags is skipped with `CHG-SYMBOL-VALUE` (drift). A symbol that was a commented-out copy becomes `CHG-SYMBOL-UNRESOLVED`. With the length cap, the "over the decode cap" status (`screens_directionb.py:5483-5487`) can no longer fire for sizes taken from the tag length. |
| **Reports, diff, flows and variants** (`report_filter.py:712-733`, `compare_service.py:301-310`, `diff_report_service.py:884-918`, `flow_execution_service.py:381-528`, `variant_execution_service.py:2552-2665`) | tags (address, size, name) | Symbol ranges and attributions move as in the rows above. The parse itself is the same call, so no consumer code changes. |
| **Segment split view** (`segment_split_view.py:1603-1650`) | `extract_memory_segments(sections)` | No change expected: V171 keeps its 4 segments. |
| **Facades** (`a2l_parse.py`, `a2l_extract.py`, `a2l_render.py`, `a2l_validate.py`, `tui/__init__.py`) | re-exports | The same names and signatures. Under D-8 A, `extract_declared_spans` is re-exported from `a2l_extract.py` (`CLAUDE.md` rule). |

## 6. Batch-101 overlaps (scope item 4)

- **`a2l.py`:** `git diff e07fb00...<branch> -- s19_app/tui/a2l.py` is empty for every `b101-*` branch (inc2 … inc16, inc12b, canon, p0).
- **The reader's consumers:** `b101-inc10` changes `app.py` (hex view), `segment_split_view.py` (hunks at `:1740` and `:2079`, outside `_a2l_rows` `:1603-1650`) and `hexview.py`. None of its lines reads `a2l_data`, the tags or the sections (`git diff … | grep`). `b101-inc9` and `b101-inc12b` change flow and Check Editor code. No hunk of any branch falls in `app.py:8456-8530`, which holds R-TUI-042a.2's edit.
- **Conclusion:** there is no textual overlap. The only behavioural contact is through tests that load V171 or BalanceTube on those branches: their expected tag fields change by the list in `01-requirements.md`. The integrator runs them after the merge.

## 7. Found, outside this increment's rows (proposed for the backlog)

- **BL-I11-1. The Unit cell shows the COMPU_METHOD's format, not its unit.** `CM_SYN "" IDENTICAL "%.0" "rpm"` paints `%.0` in the Unit column [P1, W220]. Likely the same class as BL-I2-4 and BL-I2-9 (R-A2L-031, R-A2L-033). It is in `a2l.py`, but it is a field rule, not a word rule. It could join Inc 11 as one row on the orchestrator's word.
- **BL-I11-2. An AXIS_DESCR whose header stands on its `/begin` line takes the FIX_AXIS_PAR numbers as its header**, so a CURVE or MAP loses its length [H3e]. A third AXIS_DESCR with no axis kind gives no length [H3g]. Rows .1 and .20 with the header rule would fix the first. E2 must decide whether AXIS_DESCR joins the header rows (.25 and .26) or Inc 3.
- **BL-I11-3. A2L Explorer at narrow widths**: columns that do not fit are cut off without a mark [W118: `Li`, W80: 4 columns shown]. This is part of PLAN backlog item 5; Inc 7's layout owns it.
- **Inc 2b obligation (D-6):** refuse an encode of any object whose line span holds a parse error. Every new error carries `Line <n>:`.

## Orchestrator rulings (2026-11-06T22:10:40-06:00, Opus 5.5)

**The operator's field symptom is reproduced** (a synthetic MAP; nothing of the operator's sample stored): a **view** defect — the A2L tag table is built with `cell_padding=0` (canon R-TUI-042a.2), so the Address and Length cells paint as one string (`0x<addr><length>`), and Region/Limits likewise (`unknown0..<max>`). The reader reads both values correctly; the detail card shows them correctly. Separately, the reader itself glues a comment between an address and digits, and an underscore, into a 12-digit address (TC-097 pins the comment glue).

All recommendations accepted: **D-1 A** (Inc 11 owns the padding fix in `app.py`; R-TUI-042a.2 changes in place; because it is visible, E5 takes real Windows Terminal captures before/after at 118x54 and 220x60 and shows them to the operator), D-2 A, D-3 A, D-4 A, D-5 A (`/include` → a parse error; support is backlog), D-6 A, D-7 A, D-8 A, D-9 A, D-10 A, D-11 A, D-12 no split (60 rows). Inc 11's source files: `a2l.py`, `app.py`, `a2l_extract.py`.
