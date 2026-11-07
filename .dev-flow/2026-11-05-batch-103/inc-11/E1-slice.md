# Inc 11 — E1 slice: the files and functions to change, counted and mapped

Base: product tree `e07fb00`; line numbers are as of `e07fb00`. Rows are in `01-requirements.md` and decisions in `E1-rulings.md` §3. The slice follows each decision's recommended option; a different ruling is noted per item.

Real callers come from `evidence-e1/e1-callers-transcript.txt`. That run used the Code-Wire v3.1.0 extractor (`git -C C:\Users\jjgh8\Github\code-wire describe --tags` = `v3.1.0`, commit `e436a08`) over a throwaway `git archive e07fb00 s19_app` copy in the scratchpad, with one `# node:` mark per def: 1,996 marks, 3,771 calls, 0 parse failures. The script is `evidence-e1/e1-callers.py`, adapted from Inc 2's `i2e1-callers.py`. The copy was deleted after the run.

## 1. Summary

| File | Functions | Rows |
|---|---|---|
| `s19_app/tui/a2l.py` (unfrozen, A2) | 19 changed; 4 new (below) | every R-A2L-READ row, R-A2L-001.1 … .5, R-A2L-076, .077 |
| `s19_app/tui/app.py` | 1 changed: `S19TuiApp._compose_screen_a2l` (`:8456`; its argument at `:8520`) | R-TUI-042a.2 (D-1 A; with D-1 B this file leaves the slice) |
| `s19_app/tui/a2l_extract.py` | its re-export list gains `extract_declared_spans` (`CLAUDE.md`: new public symbols in `a2l.py`, re-exported by the matching facade) | R-A2L-READ.40 … .46 (with D-8 B this file leaves the slice) |

**Totals:** 3 source files of the 4 allowed. 20 changed functions, 4 new functions, 1 changed re-export list. Graph estimate: about 25 nodes, under the 40 cap. Tests and fixtures are not counted (see `E1-rulings.md` §4).

## 2. Function map

| # | Function | File:line (base) | Change | Real callers (C) | Rows |
|---|---|---|---|---|---|
| 1 | `build_section_tree` | `a2l.py:154` | Builds the tree from the word stream of #20, not from line starts. `/begin` and `/end` are whole words anywhere, in any case. The keyword is the next word. An `/end` closes the innermost section and checks its name. One-line sections close. Comments and strings hold no structure. The BOM is dropped; UTF-16 is refused. `/include` gives an error. The `lines` of each node are kept for the line readers (E2 decides whether they are stored with comments as word breaks); `start_line` and `end_line` count line ends as R-A2L-READ.1 does. Progress per bytes (R-A2L-004.11) stays. | `parse_a2l_file` `:2829` | R-A2L-001.1, .001.2, .001.4, .001.5, .001.6; READ.1, .5, .6, .10, .11, .13 … .15, .17 … .22, .52 |
| 2 | `parse_begin_meta` | `a2l.py:255` | The name and long identifier come from the section's first words, the `/begin` line or later lines (via #1's header words), not from the `/begin` line's raw rest | `extract_a2l_tags.<locals>.walk` `:2601`, `:2732`; `extract_compu_methods` `:859`; `extract_compu_tables` `:903`; `extract_record_layouts` `:715` | READ.23, .24 |
| 3 | `_parse_first_field` | `a2l.py:269` | The escape pair (`\\` does not escape the quote after it); words end at ASCII blanks | `parse_begin_meta` `:260`, `:263` | R-A2L-001.3.2; READ.2 |
| 4 | `_split_line_respecting_quotes` | `a2l.py:319` | ASCII blanks only; the escape pair; a `"` ends an unquoted word | 10 callers: `_byte_order_from_section_lines` `:313`, `_flatten_body_tokens` `:456`, `_parse_compu_method_conversion_from_body` `:795`, `_parse_link_map_line` `:674`, `walk` `:2712`, `extract_compu_methods` `:848`, `:873`, `extract_compu_tables` `:909`, `:913`, `extract_record_layouts` `:718`, `parse_characteristic_header` `:613`, `parse_measurement_header` `:482` | READ.2, .3, .16; R-A2L-001.3.1, .3.2 |
| 5 | `_strip_a2l_comments` | `a2l.py:353` | A comment leaves a word break; the escape pair; `*/` outside a comment and an open comment are reported (or #20 replaces it, an E2 choice) | `_flatten_body_tokens` `:456`; tests TC-097 (`tests/test_a2l_multiline_headers.py:387-389`, changed, `E1-rulings.md` §4) | READ.7 … .11 |
| 6 | `_flatten_body_tokens` | `a2l.py:422` | Follows #4 and #5 | `assemble_characteristic_header` `:653`; `walk` `:2729` (AXIS_DESCR) | READ.7, .29 |
| 7 | `parse_measurement_header` | `a2l.py:480` | Reads the 6 header words from a word list, not one line; the list ends at a keyword | `_first_header_line` `:663`; `walk` `:2604` | READ.25, .27 |
| 8 | `_first_header_line` | `a2l.py:656` | Replaced by the header words of #1 and #22: no "first line with 6 words" (its MEASUREMENT branch is the BalanceTube and V171 defect) | `walk` `:2603` | READ.25, .28 |
| 9 | `_characteristic_from_tokens` | `a2l.py:498` | The header starts after the name and long identifier and ends at a keyword; the address via #21 | `assemble_characteristic_header` `:653`; `parse_characteristic_header` `:613` | READ.26, .27, .36 |
| 10 | `_extended_kind_anchor` | `a2l.py:581` | `int(x, 0)` → #21 | `_characteristic_from_tokens` `:559` | READ.34 … .36 |
| 11 | `assemble_characteristic_header` | `a2l.py:616` | Includes the `/begin` line's words | `walk` `:2608` | READ.26 |
| 12 | `_byte_order_from_section_lines` | `a2l.py:311` | Reads the section's words, so no BYTE_ORDER inside a comment | `extract_a2l_tags.<locals>._module_byte_order` `:2587`; `extract_record_layouts` `:723` | R-A2L-001.2; READ.31 |
| 13 | `_memory_segment_record_words` | `a2l.py:982` | Its own scanner removes a comment without a word break (`:1003-1040`) and uses `isspace`; it follows #20 | `extract_memory_segments.<locals>.walk` `:1091` | READ.2, .7; R-A2L-036.1 … .6 (cited) |
| 14 | `extract_a2l_tags` (and its `walk`) | `a2l.py:2572` | Reads every keyword among the tag's own words, wherever it stands on its line, with its arguments across lines (arity list). Keywords inside comments or child sections are not read. A keyword declared twice gives the .32 error (D-6 A: the last wins). The display identifier is the word after DISPLAY_IDENTIFIER. Numbers via #21. | `parse_a2l_file` `:2834` | R-A2L-001.2; READ.12, .29 … .33, .36 |
| 15 | `_infer_length_measurement` | `a2l.py:1164` | The MATRIX_DIM product; the length cap via #23 | `walk` `:2721` | READ.37, .38 |
| 16 | `_infer_length_characteristic` | `a2l.py:1187` | The MATRIX_DIM product; NUMBER via #21; the cap | `walk` `:2723` | READ.37, .38 |
| 17 | `parse_a2l_file` | `a2l.py:2797` | The payload gains the key `declared_spans` (#22); the length errors join `errors` | `parse_a2l_cached` (`app.py:948`, `:950`); `run_flow` (`flow_execution_service.py:381`, `:500`); `execute_variant_plan` (`variant_execution_service.py:2665`) | READ.39, .40, .52 |
| 18 | `iter_section_lines` | `a2l.py:3627` | Shows a section's header as its words joined by single spaces; control characters as U+FFFD | `render_a2l_view` `:3657` | READ.50, .51 |
| 19 | `render_a2l_view` | `a2l.py:3644` | Lists the errors, then the sections, then the tags; no early return; U+FFFD in file words | `enrich_tags_and_render` (`services/a2l_service.py:26`) ← 5 callers (`app.py:20136`, `:18844`; `compare_service.py:305`; `variant_execution_service.py:2553`; `flow_execution_service.py:399`) | R-A2L-076, .077 (cited); READ.51 |
| 20 (new) | `_lex_a2l_words` | `a2l.py` (new) | One linear pass over the decoded text: line ends (CRLF, CR, LF), blanks, block and line comments as word breaks, quoted strings with the escape pair, words with their line numbers; reports an unexpected character, an open comment or string, and a stray `*/` | `build_section_tree` (#1); possibly #5 and #13 (E2) | READ.1 … .4, .7 … .11, .13 … .16; R-A2L-001.2, .3.1, .3.2 |
| 21 (new) | `_number_word` | `a2l.py` (new) | `0x`/`0X` + 1 to 16 hex digits, or 1 to 20 decimal digits (leading zeros allowed) → int; anything else → no number | #9, #10, #14, #15, #16, #22 | READ.34 … .36 |
| 22 (new) | `extract_declared_spans` | `a2l.py` (new) | Lists the BLOB and INSTANCE spans and sizes each INSTANCE by its typedef (TYPEDEF_MEASUREMENT, TYPEDEF_CHARACTERISTIC VALUE/VAL_BLK/ASCII, TYPEDEF_BLOB, TYPEDEF_STRUCTURE) × its MATRIX_DIM; otherwise no length; the cap | #17; re-exported by `a2l_extract.py` | READ.40 … .46 |
| 23 (new) | `_bounded_length` | `a2l.py` (new) | Applies the 1 … `MAX_A2L_DECODE_BYTES` (`a2l.py:62`) bound and gives .39's error text | #15, #16, #14 (DATA_SIZE/LENGTH), #22 | READ.38, .39, .46 |
| 24 | `S19TuiApp._compose_screen_a2l` | `app.py:8456` (`cell_padding=0` at `:8520`) | `cell_padding=1` | `S19TuiApp.compose` `app.py:3385` | R-TUI-042a.2 |

`parse_characteristic_header` (`:611`, caller `_first_header_line` `:665`) and `_parse_link_map_line` (`:670`) follow #4 with no change of their own. `extract_record_layouts` (`:711`) and `extract_compu_methods` (`:843`) read raw `lines`. Whether those lines are stored with comments as word breaks (one change in #1, covering every line reader) or each reader moves to words is the main E2 design choice. The rows hold either way, because R-A2L-001.2 is ubiquitous. BL-I11-1 (`E1-rulings.md` §7) would add `extract_compu_methods` if the orchestrator brings it in.

## 3. Interfaces

- **The `parse_a2l_file` payload (every A2L consumer, `E1-rulings.md` §5):** the keys stay the same, and a new key `declared_spans` is added (a list of `{name, kind, address, length}`). The tag dicts keep their keys and value types.
- **New parse-error texts** (`errors`, shown through R-A2L-004.2 and `A2L_STRUCTURE_ERROR`): `Line <n>: unexpected character U+<XXXX>`; `File is UTF-16 encoded; save it as UTF-8 and load it again.`; `Line <n>: comment not closed`; `Line <n>: */ without /*`; `Line <n>: quoted string not closed`; `Line <n>: /include <file> is not read`; `Line <n>: <section> <name> has <k> of its <m> header words`; `Line <n>: <keyword> is declared twice in <section> <name>`; `Line <n>: <section> <name> has the length <length>, outside 1 to 1048576 bytes`. R-A2L-001.5's existing text becomes live.
- **Consumer obligation:** Inc 2b (I-2, write side) refuses an encode of an object whose line span holds a parse error (D-6), and reads `declared_spans` into the R-A2L-DEF.138 index (E3S-37). Inc 3b adds AXIS_PTS. These belong to their E1s; they are noted here so the interface is pinned before their E2.
