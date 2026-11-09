# Code-Wire graph — Inc 11 (A2L reader: comments, quoted strings, line ends, one-line IF_DATA, INSTANCE/BLOB; the tag-table padding), batch-103

Stage E2 of `dev-flow-v3-beta`. Graph only: no stub, mark or declaration in any tree. Base `05e43d8a` on `batch-103` (product tree `main` `e07fb00`). Requirements `../01-requirements.md` (60 rows at E2; 62 after the E1 addendum), cases `../02-test-cases.md`, rulings `../E1-rulings.md` (all of D-1 … D-12 accepted, its "Orchestrator rulings" section), slice `../E1-slice.md`, E1 evidence `../evidence-e1/`. Notation: Code-Wire v3.1.0 (`C:\Users\<user>\Github\code-wire`, tag `v3.1.0` = `e436a08`), `docs/Notation-Grammar.md`; layout as `b101-inc12:.dev-flow/2026-11-01-batch-101/inc-12/codewire/graph-inc12.md`. Corpus evidence (the orchestrator, 2026-11-06): `../../design/a2l-corpus/` (158 public files; only derived counts are cited, no file content). **E3 correction, round 1 (2026-11-06; `../E3-rulings.md`):** every E3A-*/E3S-* fix applied in the nodes below (80 rows, 249 cases); 5 nodes added (`_tag_sizes`, `_echo_word`, `_CappedErrors` new in `a2l.py`; `S19TuiApp._build_a2l_table_cells` changed in `app.py`; `_describe_one` changed in Inc 2a's `a2l_definition.py`, the 4th source file); DE-3 revised, DE-6 widened, DE-8 … DE-10 added; "last wins" is gone (D-6 revised). The E3C census and cost probe are source E3C of `../01-requirements.md`. **E3 correction, round 2 (2026-11-07; `../E3-rulings.md` "Round 2 rulings"):** E3S-18, -19, -21 … -25 and E3A-18, -19, -22, -23 applied in the nodes below (80 rows, 262 cases); 2 nodes added (`_build_section_tree_into` new, `enrich_a2l_tags_with_values` changed; 39 nodes); DE-8 and DE-10 extended; I-11.8 (g) widened and (j) added. E3A-17 = E3S-20 (Address and Length first, `fixed_columns=2`) is **not** applied: its row would pass the 80-row bound, so the tag-table rows are proposed for a separate increment; the two `app.py` nodes stand as round 1 left them. **Split (2026-11-07; `../E3-rulings.md` "Round-2 correction rulings"):** the view nodes `S19TuiApp._compose_screen_a2l` and `S19TuiApp._build_a2l_table_cells` are **Inc 12's** (`../../inc-12/`), with R-TUI-042a.2, .3, their cases and AT-B103-I11-1 (AT-B103-I12-1 there); they stay below for history, marked `moved (Inc 12)`, and Inc 12's E2 draws them again with R-TUI-042a.4 and .5. Inc 11's graph: 37 nodes over 78 rows, files `a2l.py`, `a2l_extract.py`, `a2l_definition.py`. Source `e3c2` = the round-2 correction's runs on <runner> (`/tmp/b103-e3c2-11/`, clone `e07fb00`, 0 changed files; scripts and transcripts copied in the scratchpad folder `e3c2-11`).

How to read it:
- One file holds the baseline and the prototype. Every node's `func:` starts with **unchanged**, **changed** (then "was: … / now: …"), **new** or **removed**. Context nodes (unchanged) are here because a changed node calls them, a consumer reads what they return, or they keep a canon row.
- Example sources: the case ids of `02-test-cases.md` (`R-A2L-READ.7/1`, `AT-B103-I11-1`); `C` = the E1 census (`../evidence-e1/e1-repro-transcript.txt` tags `[RP-…]`, `e1-fixtures-transcript.txt` `[FX…]`, `e1-glue-transcript.txt` `[H…]`, `e1-widths-transcript.txt` `[W…]`); `K` = the E2 corpus reductions on the base reader (`evidence-e2/i11e2-corpus-shapes-transcript.txt`, tags `[K1]` … `[L1]`); `LS` = the E2 lexer model's outputs (`evidence-e2/i11e2-lexer-shapes-transcript.txt`; a throwaway feasibility model of `_lex_a2l_lines`, not product code); `P1`, `P2` = the E2 timing pilots (`evidence-e2/i11e2-pilot-time-transcript.txt`, `i11e2-pilot-time2-transcript.txt`); `X` = the extractor run (`evidence-e2/i11e2-extract-transcript.txt`); `A` = the E1-addendum census (`../01-requirements.md` source A); `R` = read in the code at `e07fb00`. Every example states the Inc 11 target unless it says "the base" or "holds on base".
- `HDR`, `MEAS(X, …)` and `SYNMAP` are the common fixtures of `02-test-cases.md`; `↵` is a line end. Every A2L text is synthetic.
- **Canonical text**: a run of words joined by one space; a quoted word keeps its quotes and its escape pairs as in the file (`"a\"b"`), so `_split_line_respecting_quotes` reads it back as the same word. A **run** is the words of one source line that stand between two child sections, or between a child section and the line's start or end.

### Design decisions taken at E2 (each is in a node; the orchestrator may overrule)

| Id | Decision | Why | Rows |
|---|---|---|---|
| DE-1 | The lexer is a **generator over the file's lines** (`_lex_a2l_lines`) that yields `(line, canonical text)`; the builder appends a canonical line as it is and splits only a line that holds `/begin`, `/end` or `/include` | P1: a lexer returning every word as a list, and a builder walking every word, take 7.3× the base tree on case_06 and project to **2.04×** the base parse, over R-A2L-READ.52's 1.5×, at 2.5× the base tree's peak memory. P2 (this shape): **1.37×** (case_06) and **1.34×** (software_a), tree peak 388 MB against base 257 MB | READ.52 |
| DE-2 | The file is still read line by line through `path.open(…)` in text mode (universal newlines), with the progress report every 4 096 lines and `os.fstat` only with a callback | `tests/test_b100_a2l_progress.py` pins that mechanism (TC-B100-73: a read failing at line 5 000 leaves exactly one report; 0 `fstat` calls without a callback); universal newlines are R-A2L-READ.1 | READ.1, R-A2L-004.11 |
| DE-3 | Section nodes keep their six keys; `meta` and `lines` hold **canonical text** (no comment text, single spaces, word breaks at comments); `meta` = the own words on the keyword's line before any child; `lines` = the later runs, and an empty entry `""` where each child section opens. Two keys are added: `meta_line`, `line_numbers` (**PROPOSED**, I-11.1) | E1's CANON(file) is exactly this layout for every section that is not a tag, and the E1 census shows the e07fb00 line readers give REF's values on it except the listed defects [FX-total]; so every line reader (record layouts, compu methods, compu tables, link maps, memory segments, `validation/rules.py` (frozen), Inc 2a, Inc 3a) meets R-A2L-001.2 with no change of its own. A "first run" `meta` was tried and rejected: 1 MOD_COMMON (BalanceTube), every AXIS_DESCR (V161 17, V171 51, software_a 180) and 3 MEMORY_SEGMENTs (software_a) have their keyword alone on its line, so their readers would lose their first line (grep of the 35 files). **Revised at E3 (E3A-01):** for a section of a *named kind* (`[Data: _NAMED_KINDS]`) whose keyword line holds none of its own words, `meta` = the canonical text of its first line that holds own words, joined by the next own word's line when that first line is the name alone and the next word is quoted (the long identifier); those runs leave `lines`, and `meta_line` = the name's line. So every `parse_begin_meta` reader, Inc 2a's walk and the summary name such a section with no consumer change; unnamed kinds (MOD_COMMON, AXIS_DESCR, IF_DATA …) keep the rule above | R-A2L-001.2, READ.1–.3, .7, .23, .24, .50, .54 |
| DE-4 | The tag reader reads **words**, not lines: `_section_words` → `_tag_header` (name, long identifier, header words to the first keyword) → `_tag_keyword_lines` (one canonical "keyword + arguments" text per keyword, by arity); the existing field rules then run on those texts | the base field loop (`a2l.py:2661-2714`) and `_infer_length_*` keep their line form, so R-A2L-010 … 036 keep their code; E1's CANON layout put each keyword on its own line in the same way | READ.23–.33, .37 |
| DE-5 | `_strip_a2l_comments` is **kept** (a comment becomes one space) | Inc 3's graph reuses it (`inc-3/codewire/graph-inc3.md:709`); removing it is a change to another increment's interface, so it is PROPOSED only (F-E2-6) | READ.7 |
| DE-6 | A LENGTH, DATA_SIZE, NUMBER, MATRIX_DIM or ARRAY_SIZE keyword that *gives no number* (a missing argument, a word that is not a number word, MATRIX_DIM with more than 3 words) gives **no length and no inference** (widened at E3, E3S-08: `MATRIX_DIM x4` is no longer 1) | R-A2L-014 … 017 infer only when there is no DATA_SIZE or LENGTH; R-A2L-READ.38/1 asks `LENGTH -5` → no length, and `-5` is no number word (.36); base inferred from the datatype (R `a2l.py:2669-2673`, `:2720`) | READ.36, .38, .61 |
| DE-7 | A short CHARACTERISTIC header (1 to 6 words) gives **no header field** (the error of .28 only); a short MEASUREMENT header gives its words by position | .27/2 asks datatype `UWORD` from a 5-word MEASUREMENT header (Inc 2 shape C); TC-099 pins the fail-closed rule (`tests/test_a2l_multiline_headers.py:441-446`). E1's REF model reads a short CHARACTERISTIC address by position (`e1-census.py:567`): F-E2-4. Now a row (R-A2L-READ.62, E3A-06), so the E4 REF reads it from the rows | READ.27, .28, .62 |
| DE-8 (E3) | **D-6 revised: fail closed.** Disagreeing address words (two ECU_ADDRESS, or a CHARACTERISTIC's header address and its ECU_ADDRESS), an ECU_ADDRESS that gives no number, and a BIT_MASK or BYTE_ORDER standing twice with different arguments give **no address**; disagreeing sizes (CTX *sizes*: DATA_SIZE, LENGTH, NUMBER, ARRAY_SIZE, the MATRIX_DIM product, and the datatype × MATRIX_DIM when a DATA_SIZE or LENGTH stands) give **no length**; each with .59's error. Agreeing duplicates keep the value (with .32's error). **Round 2:** sizes form two groups (byte sizes DATA_SIZE, LENGTH; counts NUMBER, ARRAY_SIZE, the MATRIX_DIM product, or the one count 1), each always compared within itself and across in bytes when the element size is known (E3S-19); the CURVE/MAP family compares its byte sizes with its layout span only, and any refused length is final (E3S-23); a header address that is no number word, a BIT_MASK or BYTE_ORDER with a missing argument, and a surplus number word after ECU_ADDRESS or BIT_MASK give no address (E3S-21, -22, -24); a tag with no length gets no enriched byte size (E3S-18) | E3S-03: no write consumer reads `errors`, and the drift check compares against the same last-wins value; the E2-addendum ruling already failed sizes closed. E3C: 0 tracked tags with two sizes or two address words, so READ.49 is untouched | READ.32, .59, .60, .61, R-A2L-013 … 017 |
| DE-9 (E3) | **A keyword is never an argument.** `_tag_keyword_lines` ends a keyword's arguments at the next unquoted keyword, a place mark or the end of the own words (`arity` words at most; MATRIX_DIM takes them all); a shortfall, or MATRIX_DIM with 0 or more than 3 words, appends .58's error | E3S-02: `BYTE_ORDER`↵`BIT_MASK 0x0FF0` swallowed the mask, `ECU_ADDRESS_EXTENSION`↵`ECU_ADDRESS 0x1234` the address; the base, line-based, read both right; REF shared the mechanism, so the shapes join the hostile corpus | READ.29, .58 |
| DE-10 (E3) | **Bounded reading.** A NUL byte refuses the file (one error); errors pass through `_CappedErrors` (100 texts, then one `… <k> more parse errors`), so no list grows past 101 even on a binary; nesting stops at 32 levels; every file word in an error text goes through `_echo_word` (64 characters, U+FFFD outside U+0021 … U+007E). **Round 2:** `_CappedErrors` is a small class, not a `list` (E3A-19); the public `build_section_tree` returns `as_list()`; no pattern scans across lines, and an open string's continuation is found with `str.find` or the unrolled pattern, never a per-character alternation (E3A-18: 1,005 MB on one 8.5 MB string) | E3A-02 (1,003,075 errors for UTF-16 without a BOM), E3S-04 (`RecursionError` past ~990 levels closes the app via the flow Run), E3S-07 (a 1 MB echoed word), E3S-11 | READ.55, .56, .64, .65, .66 |

### Groups for E4 (file ownership) and interfaces — pinned here, changed only by an orchestrator ruling

| Group | Files | Owns nodes |
|---|---|---|
| G1 reader | `s19_app/tui/a2l.py`, `s19_app/tui/a2l_extract.py`, and (E3 correction) `s19_app/tui/a2l_definition.py` once Inc 2a has merged to `batch-103` | every node with `module: s19_app/tui/a2l.py` that is new, changed or removed; `[Data: a2l_extract.__all__]`; `_describe_one` |
| G2 app — **moved (Inc 12)**, 2026-11-07 | `s19_app/tui/app.py` (one argument, `:8520`; the Tag cell, `:20389`); doc row DOSSIER F-09 is the integrator's | `S19TuiApp._compose_screen_a2l`, `S19TuiApp._build_a2l_table_cells` (Inc 12's) |
| G-T1 reader tests | new `tests/test_b103_a2l_reader.py`, new `tests/support/b103_a2l_ref.py`, new fixture `tests/fixtures/b103_i11/e07fb00_tags.jsonl`; the changed tests of `../E1-rulings.md` §4 (TC-097, `test_b101_a2l_blocks_and_segments.py:281-293`, `test_tui_a2l_issue_recolor.py` per D-10, the freeze guards and TC-B100-73's `_ENGINE_PATHS` check `test_b100_a2l_progress.py:226-238`) | `ref_read_a2l`, `[I/O: e07fb00 tag fixture]` |
| G-T2 app tests | AT-B103-I11-1 … 3, R-TUI-042a.2/1, /2 and R-TUI-042a.3/1 … /4 (real Explorer, headless; after the split, 2026-11-07: AT-B103-I11-2 and -3 only — AT-B103-I11-1, the R-TUI-042a cases and the padding's snapshot drift are Inc 12's; whether Inc 11's reader changes alone move an `a2l-*` baseline is not checked here, so Inc 11's E4 runs the 6 baselines on its own tree); the 6 `a2l-*` snapshot baselines (`tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[a2l-*].svg`) are regenerated in the canonical CI env (`snapshot-regen.yml`, textual 8.2.8), never locally | — |
| E5 evidence (runner only, never a CI test) | `inc-11/evidence-e5/` scripts and transcripts | `run_corpus_differential`, `[I/O: public A2L corpus]` |

| Interface | Pinned form | Producer → consumers |
|---|---|---|
| I-11.1 section node (**PROPOSED**: content and two keys) | a dict `{"name": str, "meta": str, "meta_line": int, "start_line": int, "end_line": int, "lines": list[str], "line_numbers": list[int], "children": list[dict]}`. `name` = the keyword (the word after `/begin`, quotes left out). `start_line` = the line of the `/begin` word; `end_line` = the line of the `/end` word, absent while unclosed (as base). `meta` = the canonical text of the section's own words on the keyword's line, before any child section; `""` when none; `meta_line` = the keyword's line. `lines` = the canonical text of each later run, in file order, and `""` where each child opens; `line_numbers[i]` = the line of `lines[i]` (of a `""` entry: the child's `start_line`). Comment-only and blank lines give no entry (base kept them, raw). `len(lines) == len(line_numbers)`. **E3 correction:** for a named kind whose keyword line holds no own word, `meta` and `meta_line` follow DE-3 as revised (the name's line, and the long identifier's line when the name stands alone), so `meta` holds the section's *begin words* in every case. Every reader takes the two new keys with `.get`, `meta_line` defaulting to `start_line` and `line_numbers` to `None` (a word's line is then the section's `start_line`), because protected tests hand-build sections without them (`tests/test_tui_a2l.py:71-190`, TC-032; E3A-10). E3A-11 (drop both keys) was considered and not taken: DE-3's revision sets `meta_line`, and .32, .58 and .63 name the keyword's or word's line from `line_numbers` (US-103-07: "a parse error that names the line") | `build_section_tree` → every `a2l.py` line reader; `validation/rules.py:488-565` (frozen; reads `name`, `start_line`, GROUP/FUNCTION `lines`); `segment_split_view.py:1620` (via `extract_memory_segments`); `app.py:19136` (counts); Inc 2a `a2l_definition.py` (`meta`, `lines`, `name`, `children`); Inc 3a (`lines`, `end_line`) |
| I-11.2 parse payload | `parse_a2l_file` returns the base keys `path`, `sections`, `errors`, `tags`, `record_layouts_by_name`, `compu_methods_by_name`, `compu_tabs_by_name` with the base types, and the new key `declared_spans: list[dict]`, each `{"name": str, "kind": "BLOB" or "INSTANCE", "address": int or None, "length": int or None}` in file order (E1-slice §3) | `parse_a2l_file` → every consumer of `../E1-rulings.md` §5; Inc 2b (R-A2L-DEF.138 index) |
| I-11.3 tag dict | the base 29 keys and value types (`a2l.py:2610-2639`) unchanged; value changes only as `../01-requirements.md` "Defect tags at e07fb00" lists, plus descriptions (189), display identifiers (6), `matrix_dim` = the product (14), and the objects whose header stands on the `/begin` line | `extract_a2l_tags` → views, validation, pickers, reports (E1 §5) |
| I-11.4 functions other increments import (signatures **unchanged**) | Inc 2a: `DATATYPE_SIZES`, `MAX_A2L_DECODE_BYTES`, `_apply_compu_method`, `_decode_scalar`, `_flatten_body_tokens(lines: list[str]) -> list[str]`, `_resolve_record_layout`, `_to_float`, `parse_begin_meta(meta: str) -> tuple[str, Optional[str]]` (`b103-inc2a-code:s19_app/tui/a2l_definition.py:25-34`). Inc 3a (graph): `_walk_record_layout_components`, `_strip_a2l_comments(text: str) -> str`, `_split_line_respecting_quotes(line: str) -> list[str]`, `_byte_order_from_section_lines(lines: list[str]) -> Optional[str]`. Behaviour changes on raw input only: `_flatten_body_tokens`, `_strip_a2l_comments` (a comment is a word break) and `_split_line_respecting_quotes` (ASCII blanks, escape pairs, a `"` ends a word); on canonical input each gives the base tokens | `a2l.py` → Inc 2a, Inc 3a |
| I-11.5 `extract_a2l_tags` (**PROPOSED**) | `extract_a2l_tags(sections: list[dict], record_layouts_by_name: Optional[dict[str, dict]] = None, compu_methods_by_name: Optional[dict[str, dict]] = None, errors: Optional[list[str]] = None) -> list[dict]` — a fourth parameter `errors`, default `None`, receives the tag errors (.28, .32, .39); `None` drops them, so every base call keeps its result | `a2l.py` (public, `a2l_extract.py`, `tui/__init__.py:12`) → `parse_a2l_file` |
| I-11.6 parse-error texts and order | the 9 new texts of `../E1-slice.md` §3 and the 7 the E3 correction adds there, R-A2L-001.5's text now live, `Unclosed /begin sections detected.` and `File not found.` as base. Order in `errors`: the lexer's and the builder's errors in file order, then `Unclosed /begin sections detected.`, then the tag errors in tag order (per tag: not closed, header, arguments and number words in word order, duplicates, `declares the …`, length). A UTF-16 file (READ.6), a file holding a NUL byte (READ.55) and a file nesting deeper than 32 (READ.64) give exactly one error. The list holds at most 100 texts and then one `… <k> more parse errors` (`_CappedErrors`, READ.56); every file word in a text is echoed by `_echo_word` (READ.66) | `build_section_tree`, `extract_a2l_tags` → R-A2L-004.2 status, `A2L_STRUCTURE_ERROR` (`validation/rules.py:492-500`), the A2L summary (R-A2L-075) |
| I-11.7 facade | `a2l_extract.__all__` = `["enrich_a2l_tags_with_values", "extract_a2l_tags", "extract_declared_spans"]` (`CLAUDE.md`: new public symbols re-exported by the matching facade); `a2l_parse`, `a2l_render`, `a2l_validate`, `tui/__init__` unchanged | G1 → importers |
| I-11.8 consumer obligations (ruled at E2; (a) moot and (f) … (i) added at the E3 correction) | (a) **moot after E3A-01** (DE-3 revised: a named kind's name on a later line is in `meta`, so `parse_begin_meta(meta)` names it; was: Inc 2a/2b name a section by its first own word); (b) after Inc 11, Inc 2a's text-of-the-object checks (`bit_mask_letters`, `ends_open`, `begin_inside`, R-A2L-DEF.19's two messages) see canonical text: `ends_open` and `begin_inside` can no longer be `True`, and a BIT_MASK inside a comment no longer counts — Inc 2a tests on comment shapes and R-A2L-DEF.3's `UNKNOWN` change outcome, and Inc 2b (A2: "re-checked against the fixed reader") re-rules them; (c) Inc 2b refuses an encode of an object whose `[start_line, end_line]` holds the line of a parse error (D-6 as revised), refuses every write while a stray-`*/`, unclosed-comment or unclosed-string error exists (those errors can stand outside the object's span, E3S-09 (a)), and treats `… <k> more parse errors` as a file-level refusal (the lines past the cap are unknown, E3S-11); (d) Inc 2b reads `declared_spans` into R-A2L-DEF.138's index; (e) Inc 3a reads canonical `lines` and needs no comment stripping, and builds a MATRIX_DIM shape from the tag's own words (`_tag_keyword_lines`), not from "the first line whose first word is MATRIX_DIM", so length and shape agree (E3A-12; one Inc 3a case); (f) **Inc 11 removes Inc 2a's MEASUREMENT header fill** (`a2l_definition.py:377-398` at `82f5f8e5`; node `_describe_one`), which re-derived a length the reader refused (E3S-05 (b)); Inc 2a merges to `batch-103` before Inc 11's E4, and Inc 11's E4 re-points Inc 2a's tests that pinned the fill (R-A2L-014/def-1 holds through R-A2L-READ.25); Inc 2a's row text "else the size of its datatype × its MATRIX_DIM" (`../../inc-2/01-requirements.md:51`, `:233`) is for the orchestrator to re-word; (g) **Inc 6** (PLAN row 6) removes the picker's `int(row.get("byte_size") or 1)` (`a2l_parameter_picker.py:557`) and "Use parameter"'s `int(parameter.get("size") or 1)` (`screens_directionb.py:5477`): a missing length is refused with `Parameter has no length — Bytes not prefilled.`; its acceptance includes a MEASUREMENT with `LENGTH 99999999999` through "Use parameter" → refused (E3S-05 (a), (g)); **widened at round 2 (E3S-18):** the picker row, "Use parameter" and the Check Editor field take their size from the tag's `length` (or I-2's byte length), never from `enrich_a2l_tags_with_values`'s `byte_size` (the layout's one-element size for a tag with a length, PE-D1), and Inc 6's acceptance adds [B6] and the VAL_BLK `MATRIX_DIM 4` + `NUMBER 5` pair through "Use parameter" → refused; (h) the flow owner (outside the slice): `run_flow` catches `Exception` around its two `parse_a2l_file` calls, as the load worker does (E3S-04); (i) Inc 3a builds the external-axis name index once per parse (`a2l.py:1424`, O(tags × axes); E3S-16, and E3A-09's backlog item, routed to the one owner); (j) round 2, with CG-4: Inc 3a reads a RECORD_LAYOUT's FNC_VALUES datatype from its components wherever they stand — `_resolve_record_layout` (`a2l.py:1241-1275`) reads only the first body line, so 868 corpus layouts that start with another component (AXIS_PTS_X 720) and 121 that carry their components on the `/begin` line give no datatype, as at e07fb00 (E3A-22) | Inc 11 → Inc 2a, 2b, 3a, 6; the flow owner |

PLAN interfaces: I-2 (the definition model) consumes I-11.1 … I-11.4; I-1, I-3, I-4 and I-5 are not touched.

Order inside E4: G1 and G2 in parallel (disjoint files); G-T1 and G-T2 in parallel. The re-freeze of `a2l.py` is a separate PR after the merge (`CLAUDE.md`, Engine-frozen guard). Merge position: before Inc 2b, 3b, 6 and 8 (PLAN Inc 11); after Inc 2a, which merges to `batch-103` before Inc 11's E4 (E3-rulings), so I-11.8 (b) and (f) apply to the merged tree.

### Baseline: the code in scope at e07fb00, with its real callers

Extractor: Code-Wire v3.1.0 over a throwaway `git archive e07fb00 s19_app` copy, one mark per baseline node (each replacing the blank line above its def, so every line number is e07fb00's): `evidence-e2/i11e2-extract.sh`, transcript `evidence-e2/i11e2-extract-transcript.txt` (X). Run 1 (the 22 baseline nodes): 21 contracts equal, **1 drift** — `graph input errors not a parameter of extract_a2l_tags` (I-11.5, PROPOSED); exit 1 for that reason only. Run 2 (the whole graph): the same drift plus the 10 new nodes "without mark (no code yet)". Lint: 32 nodes, 11 entities, 19 edges, 8 findings, `0` lines not read. The callers below are the E1 full-mark census (`../evidence-e1/e1-callers-transcript.txt`, one mark on every def), confirmed by X for the marked nodes; X, which marks only the 22, attributes a call made in an unmarked function to the nearest marked def above it (e.g. `parse_a2l_file` → `_split_line_respecting_quotes` at `:718`, which is `extract_record_layouts`).

| Function (`a2l.py` unless named) | Base line | Real callers (X) | Inc 11 |
|---|---|---|---|
| `build_section_tree` | `:154` | `parse_a2l_file` (`:2829`) | changed |
| `parse_begin_meta` | `:255` | `extract_a2l_tags.<locals>.walk` (`:2601`, `:2732`), `extract_compu_methods` (`:859`), `extract_compu_tables` (`:903`), `extract_record_layouts` (`:715`); Inc 2a | unchanged (the walk's `:2601` call goes) |
| `_parse_first_field` | `:269` | `parse_begin_meta` (`:260`, `:263`) | changed |
| `_split_line_respecting_quotes` | `:319` | 10 functions (`:313`, `:456`, `:482`, `:613`, `:674`, `:718`, `:795`, `:848`, `:873`, `:909`, `:913`, `:2712`); Inc 3a | changed |
| `_strip_a2l_comments` | `:353` | `_flatten_body_tokens` (`:456`); Inc 3a; TC-097 | changed (no `a2l.py` caller after) |
| `_flatten_body_tokens` | `:422` | `assemble_characteristic_header` (`:653`), `walk` (`:2729`, AXIS_DESCR); Inc 2a | changed |
| `_byte_order_from_section_lines` | `:311` | `_module_byte_order` (`:2587`), `extract_record_layouts` (`:723`); Inc 3a | unchanged |
| `parse_measurement_header` | `:480` | `_first_header_line` (`:663`), `walk` (`:2604`) | changed |
| `_characteristic_from_tokens` | `:498` | `assemble_characteristic_header` (`:653`), `parse_characteristic_header` (`:613`) | changed |
| `_extended_kind_anchor` | `:581` | `_characteristic_from_tokens` (`:559`) | changed |
| `parse_characteristic_header` | `:611` | `_first_header_line` (`:665`); tests | unchanged (no product caller after) |
| `assemble_characteristic_header` | `:616` | `walk` (`:2608`); facade `a2l_parse`; tests | unchanged (no product caller after) |
| `_first_header_line` | `:656` | `walk` (`:2603`) | removed |
| `_memory_segment_record_words` | `:982` | `extract_memory_segments.<locals>.walk` (`:1091`) | changed |
| `_a2l_number` | `:949` | `extract_memory_segments.<locals>.walk` (`:1101`, `:1104`, `:1116`) | unchanged (a second number rule: F-E2-8) |
| `_infer_length_measurement` | `:1164` | `walk` (`:2721`) | changed |
| `_infer_length_characteristic` | `:1187` | `walk` (`:2723`); tests `test_a2l_record_layout_length.py` (9 calls with `[]`) | changed |
| `extract_a2l_tags` | `:2572` | `parse_a2l_file` (`:2834`) | changed |
| `enrich_a2l_tags_with_values` (round 2) | `:2878` (`byte_size` at `:2890`) | `enrich_tags_and_render` (`services/a2l_service.py:20`), `a2l.py:3472` (R, `grep`) | changed (E3S-18) |
| `parse_a2l_file` | `:2797` | `parse_a2l_cached` (`app.py:948`, `:950`), `run_flow` (`flow_execution_service.py:381`, `:500`), `execute_variant_plan` (`variant_execution_service.py:2665`) | changed |
| `iter_section_lines` | `:3627` | `render_a2l_view` (`:3657`) | changed |
| `render_a2l_view` | `:3644` | `enrich_tags_and_render` (`services/a2l_service.py:26`) ← `S19TuiApp._compute_a2l_enriched_tags` (`app.py:20136`), `S19TuiApp._prepare_load_payload` (`:18844`), `_a2l_addresses` (`compare_service.py:305`), `_execute_one_variant` (`variant_execution_service.py:2553`), `run_flow` (`flow_execution_service.py:399`) | changed |
| `S19TuiApp._compose_screen_a2l` | `app.py:8456` (`cell_padding=0` at `:8520`) | `S19TuiApp.compose` (`app.py:3385`) | changed — moved (Inc 12) |
| `S19TuiApp._build_a2l_table_cells` (E3) | `app.py:20389` | `update_a2l_tags_view` (R, its docstring and the call site) | changed — moved (Inc 12) |
| `_describe_one` (E3; Inc 2a's `a2l_definition.py`, branch `b103-inc2a-code` `82f5f8e5`, not on `e07fb00`) | `a2l_definition.py:324` | `describe_definitions` (R; Inc 2a) | changed (its fill `:377-398` removed) |
| `validate_a2l_structure` | `validation/rules.py:463` (frozen) | `validate_a2l_internal_issues` (`a2l.py:3716`), `validation/engine.py:71` (X) | unchanged (context) |

### Consumers that see a change (what the operator or a test sees)

| Consumer | Reads | Change |
|---|---|---|
| A2L Explorer table (`app.py:20286-20473`) | the 16 cells | (the padding and the Tag cap: moved to Inc 12, 2026-11-07) a blank column between cells (R-TUI-042a.2); the 227 listed tags (122 at E1, 226 after the E1 addendum, 227 after the E3 correction); names, kinds and addresses of objects whose header stands on the `/begin` line (corpus classes 3–5); each of the 16 columns 2 cells wider, so fewer columns fit at 118 (PLAN backlog 5, Inc 7); a name wider than 34 cells cut to 16 + `…` + 17 (R-TUI-042a.3: 9,969 tracked names, E3C), so Address and Length stay whole at 118 |
| A2L Explorer Raw/Physical cells, Check Editor and Patch Editor pickers, "Use parameter" (`app.py:7665-7690`, `a2l_parameter_picker.py:557`, `screens_directionb.py:5477`) | the enriched rows | round 2 (E3S-18): a tag with no length has `byte_size` None and no decoded value — 187 tracked CURVE/MAP/CUBOID/CUBE_4 tags lose the first-element value they show at e07fb00 (`../01-requirements.md` "also change"); the pickers fall to Inc 6's `or 1` until Inc 6 refuses them (I-11.8 (g)) |
| A2L JSON export (`app.py:9721`) | the whole payload | gains `declared_spans`, `meta_line`, `line_numbers` and canonical `meta`/`lines` (E3A-14; the user-facing change list, no row) |
| A2L snapshot baselines (6 `a2l-*` SVGs, `tests/test_tui_snapshot.py:391-395`) | the painted A2L screen | (the padding's drift: moved to Inc 12, 2026-11-07) drift from the padding; regenerated in the canonical CI env (G-T2) |
| DOSSIER F-09 (`docs/user-guide/DOSSIER.md:718`) | the live defect "columns run together" | (moved to Inc 12, 2026-11-07) closed by R-TUI-042a.2 (the integrator marks it) |
| Workspace A2L summary (`app.py:20147-20178`) | `render_a2l_view` | errors, then sections, then tags (R-A2L-076, .077); no comment text in section lines (.50); U+FFFD for control characters (.51); V171 lists its sections |
| Issues screen (`validation/rules.py`, frozen) | `errors`, tags, `sections` | `A2L_STRUCTURE_ERROR` goes for V171 and comes for the new errors; `A2L_DUPLICATE_SYMBOL` goes for commented copies and for the `UNKNOWN` collapse (corpus class 1: 137,243 objects); `A2L_BROKEN_REFERENCE` no longer reads a symbol from a comment on a GROUP or FUNCTION line (canonical `lines`) |
| Loaded panel, MAC View, Memory Map, pickers, symbol resolution, reports, diff, flows, variants | tags | as `../E1-rulings.md` §5 |
| Segment split view (`segment_split_view.py:1620`) | `extract_memory_segments` | none expected (V171 keeps 4 segments) |
| Inc 2a (`a2l_definition.py`) | `meta`, `lines`, tags | I-11.8 (a), (b) |
| Tests that pin base behaviour | | TC-097 (`test_a2l_multiline_headers.py:387-389`), `test_b101_a2l_blocks_and_segments.py:281-293`, `test_tui_a2l_issue_recolor.py:103-118`, `:436-507` (D-10), TC-027 / TC-031 / TC-B94-18 freeze arms, TC-B100-73 `_ENGINE_PATHS` (`test_b100_a2l_progress.py:226-238`); TC-099 and AT-097 … AT-099 (`test_a2l_multiline_headers.py:100-170`) hold unchanged |

### Batch-101 overlaps (checked 2026-11-06 at E2)

- `git log --oneline origin/main -5`: `09b4808a`, `61895883`, `f481e8af` (Merge Inc 12b), `b13a1f30`, `9087b8ab`. `git diff --stat e07fb00 origin/main -- s19_app/tui/a2l.py s19_app/tui/a2l_extract.py s19_app/tui/app.py`: only `app.py`, 33+/5−, hunks at `:3997-4590` (flow handlers, Inc 9 / 12b); none near `:8456-8530` and none reads `a2l_data`, tags or sections.
- Branches not on `origin/main`: only `b101-inc10` (`80038ed6`): its committed `app.py` hunks (`:45`, `:1833-1874`, `:2616`, `:3997-4593`, `:10009` onward) and its uncommitted worktree hunks (`:2838`, `:9942`, `:10663` onward, in its own numbering) avoid `:8456-8530`; the only A2L word in its diff is a doctest's `a2l_data=None` (`_unload_primary`). `b101-inc12` (`8a25e5fb`) holds records only; its I-3 keeps the button id `a2l_tag_find_next` at `app.py:8506`, two lines above Inc 11's edit, untouched. Every other `b101-*` branch is an ancestor of `origin/main`.
- `a2l.py` and `a2l_extract.py`: no change on any branch or worktree. **No overlap.** Behavioural contact only through tests that load V171 or BalanceTube (E1-rulings §6).

### Corpus classes (orchestrator evidence, 2026-11-06) → the node that fixes each

| Class (corpus count) | Reduction (K, base reading) | Fixed by | Row |
|---|---|---|---|
| 1 name `UNKNOWN` — `/begin` alone on its line, one word per line (137,243) | [K1] two such MEASUREMENTs → both `UNKNOWN`, no address, datatype None, one `A2L_DUPLICATE_SYMBOL`; [K1c] CHARACTERISTIC → `UNKNOWN`, address right | `_section_words` + `_tag_header` (the name is the first own word, any line); E3A-01: the same class in COMPU_METHOD (8,422), COMPU_VTAB (4,338), FUNCTION (4,522), AXIS_PTS (751), RECORD_LAYOUT (144) → `build_section_tree` (DE-3 revised: `meta` holds a named kind's name) | READ.23/5, /6 (CG-1, applied); READ.54/1 … /6 |
| 2 MEASUREMENT datatype None (121,299) | [K2] header one word per line → datatype None, length None | `_tag_header` (header words across line ends) + `parse_measurement_header` | READ.25/5 (CG-1) |
| 3 CHARACTERISTIC kind misread, header on the `/begin` line (657) | [K3] → kind `ECU_ADDRESS_EXTENSION`, deposit `BYTE_ORDER` (the B6 salvage anchors on a body keyword) | `_tag_header` reads the header from `meta`; it stops at a keyword, so `_extended_kind_anchor` never sees a body keyword | READ.26/4, .27/4 |
| 4 wrong address, header on the `/begin` line (805) | [K3] → `0x0`; [K4] `CUBE_5 0x123` → kind `NUMBER`, address `0x2710` | as class 3 | READ.26/4, /5, .27/4, /5 |
| 5 address None, ECU_ADDRESS mid-line or after a comment (729) | [K5] one-line MEASUREMENT with a nested IF_DATA → address None, `Unclosed /begin sections detected.`; [K5b] `/* moved */ ECU_ADDRESS 0x1234` → None | `build_section_tree` (one-line sections close) + `_tag_keyword_lines` (a keyword anywhere among own words) + `_lex_a2l_lines` (no comment word) | R-A2L-001.1, READ.17, .25/6, .30/3, R-A2L-001.2/9 |
| 6 CHARACTERISTIC length None with its layout in the file (17,000) | [K6d] VALUE one word per line → 4 (holds on base); [K6] VAL_BLK on `RL_U16` with `MATRIX_DIM 4` → None; [K6b] VAL_BLK `NUMBER 4` → None; [K6c] ASCII `MATRIX_DIM 8` → None | partly: the header rule fixes the objects whose deposit word is lost (classes 1, 3); a VAL_BLK or ASCII on a layout whose name carries no size stays None — since the E1 addendum `_infer_length_characteristic` sizes such a VAL_BLK (CG-2, CG-3) | R-A2L-016/1 (CG-2), R-A2L-READ.53/1 (CG-3); [K6c] → R-A2L-017/1 (R-A2L-017 changed in place at the E3 correction, as ruled at E2); ARRAY_SIZE (2,070 corpus objects, E3A-04) → R-A2L-READ.57; CURVE/MAP/CUBE → CG-4 (Inc 3a) |
| 7 short headers (19), `/begin` after code (1) | [K7] 4-word header → datatype None, no error; [K7b] two one-line INSTANCEs on one line → `Unclosed /begin sections detected.` | `extract_a2l_tags` (.28's error); `build_section_tree` | READ.28/4, R-A2L-001.1/4 |
| Latin-1 input (11 files) | [L1] `0xB0` → U+FFFD in the long identifier and in the name word, 0 errors | `_lex_a2l_lines`: U+FFFD in a word gives .4's error; in a string or comment none | R-A2L-001.7 + READ.4/4 (CG-5 A) |

### Corpus gaps — PROPOSED rows for the orchestrator (E1 addendum follows)

| Id | Proposed row (EARS) or routing | Threshold, negative control | Evidence |
|---|---|---|---|
| CG-1 | No new row: add the class 1–5 and 7 reductions K1, K1c, K2, K3, K4, K5, K5b, K7, K7b to the hostile corpus (R-A2L-READ.48/2) and to the thresholds of READ.23 (K1, K1c), .25 (K2, K5), .26 and .27 (K3, K4), .30 (K5), .28 (K7), R-A2L-001.1 (K7b) | as in this graph's examples; mutant: the name read from `meta` only → K1 gives `UNKNOWN` → RED | [K1] … [K7b] |
| CG-2 | R-A2L-016 and R-A2L-017 change status from "cited and unchanged" to **cited (code to meet)**, with the CTX-A2L-TAG term *datatype (CHARACTERISTIC)*: the datatype of the FNC_VALUES of its record layout. The base resolves a layout's datatype for VALUE only (`a2l.py:1218-1229`) | [K6] VAL_BLK `RL_U16` `MATRIX_DIM 4` → length `8`; [K6c] ASCII `RL_U8` `MATRIX_DIM 8` → `8`; TC R-A2L-READ.43/2 needs it too (its typedef sits on `RL_U16`); mutant: the VALUE-only resolution kept → [K6] None → RED. **Risk:** it enlarges R-A2L-READ.49's defect list by every tracked VAL_BLK/ASCII on such a layout (count owed: a census at the E1 addendum) | [K6], [K6c]; corpus `LEN_NONE_CHAR_VAL_BLK` 14,317, `…ASCII` 28 |
| CG-3 | New row R-A2L-READ.53 (`If`): "If a VAL_BLK CHARACTERISTIC has no MATRIX_DIM and has a NUMBER keyword, then the system shall take its length as the size of its datatype × the number after NUMBER." (ASAP2 1.6 form) | [K6b] → `8`; mutant: NUMBER ignored for VAL_BLK → None → RED | [K6b] |
| CG-4 | Routing, no Inc 11 row: CURVE, MAP, CUBOID, CUBE_4, CUBE_5 lengths (corpus 2,256 + 2,180 + 17 + 8 + 6), the AXIS_DESCR header on its `/begin` line (BL-I11-2) and the ~60 RECORD_LAYOUT components the fixtures lack go to Inc 3 (axes and layouts); CUBE_4/CUBE_5 into `CHARACTERISTIC_KINDS` is Inc 3's call (the B6 salvage already gives their kind and address: [K4] after the change) | — | corpus summary |
| CG-5 | Latin-1: (A, recommended) no new row — R-A2L-001.7 reads each non-UTF-8 byte as U+FFFD; inside a word R-A2L-READ.4 records `Line <n>: unexpected character U+FFFD`, inside a string or a comment nothing; the E5 corpus run counts these errors on the 11 files. (B) a second decode (cp1252) when UTF-8 fails — a second encoding path, refused for UTF-16 at D-3 | (A): [L1] → 1 error for `XL1_<U+FFFD>`, 0 for the comment and the long identifier | [L1] |
| CG-6 | E5 evidence run (not a row, not a CI test): `run_corpus_differential` on the 158 files of `../../design/a2l-corpus/manifest.tsv` (sha256 checked first), on the runner only, next to the 35-file no-regression set | node `run_corpus_differential` | — |

Ruled at E2 (`../E2-rulings.md`) and applied by the E1 addendum (2026-11-06): CG-1 (the 9 reductions K1 … K7b in the hostile corpus, now 153 shapes, and each as a case); CG-2 for R-A2L-016 only (R-A2L-017 reads its NUMBER line and is met on base, so its part and [K6c] were not applied: `../01-requirements.md` § G notes); CG-3 (R-A2L-READ.53); CG-4 to Inc 3a; CG-5 A (READ.4/4); CG-6 (`../02-test-cases.md` § E5 evidence). CG-2's census (`../01-requirements.md`, source A): 12 tracked VAL_BLKs on a layout whose name carries no size (9 already defect tags, 3 added), 101 tracked VAL_BLKs with a NUMBER and no MATRIX_DIM (added, READ.53), 0 such ASCII; R-A2L-READ.49's exceptions 122 → 226. At the E3 correction: R-A2L-017 changed in place (the E2-addendum ruling; [K6c] is R-A2L-017/1), and V161's ARRAY_SIZE tag joins the list (R-A2L-READ.57): 227 exceptions, 234,427 identical.

### Coverage — every requirement → node(s) and example(s)

| Requirement | Node(s) | Example(s) |
|---|---|---|
| R-A2L-READ.1 | `_lex_a2l_lines`, `build_section_tree` | READ.1/1–/4 |
| R-A2L-READ.2 | `_lex_a2l_lines`, `_split_line_respecting_quotes` | READ.2/1, /2 |
| R-A2L-READ.3 | `_lex_a2l_lines`, `_number_word` | READ.3/1–/3 |
| R-A2L-READ.4 | `_lex_a2l_lines`, `extract_a2l_tags` (quoted name) | READ.4/1–/6 (/4 = [L1]) |
| R-A2L-READ.5 | `build_section_tree` | READ.5/1, /2 |
| R-A2L-READ.6 | `build_section_tree`, `parse_a2l_file` | READ.6/1, /2 |
| R-A2L-READ.55 | `_lex_a2l_lines`, `build_section_tree` | READ.55/1–/6 |
| R-A2L-READ.56 | `_CappedErrors`, `parse_a2l_file`, `build_section_tree`, `_build_section_tree_into` | READ.56/1–/4 |
| R-A2L-READ.66 | `_echo_word`, `build_section_tree`, `extract_a2l_tags` | READ.66/1–/3 |
| R-A2L-001.2 | `_lex_a2l_lines`, `extract_a2l_tags` | 001.2/1–/9 (/9 = [K5b]) |
| R-A2L-READ.7 | `_lex_a2l_lines`, `_strip_a2l_comments`, `extract_a2l_tags` | READ.7/1–/6 |
| R-A2L-READ.8 | `_lex_a2l_lines` | READ.8/1, /2 |
| R-A2L-READ.9 | `_lex_a2l_lines` | READ.9/1–/3 |
| R-A2L-READ.10 | `_lex_a2l_lines` | READ.10/1 |
| R-A2L-READ.11 | `_lex_a2l_lines` | READ.11/1–/3 |
| R-A2L-READ.12 | `build_section_tree`, `extract_a2l_tags` | READ.12/1–/4, AT-B103-I11-2 |
| R-A2L-001.3.1 | `_lex_a2l_lines`, `_tag_header` | 001.3.1/1–/3 |
| R-A2L-001.3.2 | `_lex_a2l_lines`, `_parse_first_field`, `_split_line_respecting_quotes` | 001.3.2/1–/4 |
| R-A2L-READ.13 | `_lex_a2l_lines`, `build_section_tree` | READ.13/1–/4 |
| R-A2L-READ.14 | `_lex_a2l_lines` | READ.14/1, /2 |
| R-A2L-READ.15 | `_lex_a2l_lines` | READ.15/1 |
| R-A2L-READ.16 | `_lex_a2l_lines`, `_split_line_respecting_quotes`, `_line_words` | READ.16/1–/3 |
| R-A2L-001.1 | `build_section_tree` | 001.1/1–/4 (/4 = [K7b]) |
| R-A2L-READ.17 | `build_section_tree` | READ.17/1–/3, [K5] |
| R-A2L-READ.18 | `build_section_tree` | READ.18/1, /2 |
| R-A2L-READ.19 | `build_section_tree` | READ.19/1, /2 |
| R-A2L-READ.20 | `build_section_tree` | READ.20/1, /2 |
| R-A2L-READ.54 | `build_section_tree`, `parse_begin_meta`, `_describe_one` | READ.54/1–/7 |
| R-A2L-001.4 | `build_section_tree` | 001.4/1, /2 |
| R-A2L-001.5 | `build_section_tree` | 001.5/1, /2 |
| R-A2L-READ.21 | `build_section_tree` | READ.21/1 |
| R-A2L-READ.22 | `build_section_tree` | READ.22/1, /2 |
| R-A2L-READ.64 | `build_section_tree` | READ.64/1–/4 |
| R-A2L-READ.65 | `build_section_tree`, `_lex_a2l_lines`, `parse_a2l_file`, `render_a2l_view` | READ.65/1–/5 |
| R-A2L-READ.23 | `_section_words`, `_tag_header`, `extract_a2l_tags` | READ.23/1–/6 (/5 = [K1], /6 = [K1c]) |
| R-A2L-READ.24 | `_tag_header`, `build_section_tree` (named kinds) | READ.24/1–/3 |
| R-A2L-READ.25 | `_tag_header`, `parse_measurement_header` | READ.25/1–/6 (/5 = [K2], /6 = [K5]) |
| R-A2L-READ.26 | `_tag_header`, `_characteristic_from_tokens` | READ.26/1–/5 (/4 = [K3], /5 = [K4]) |
| R-A2L-READ.27 | `_tag_header`, `parse_measurement_header` | READ.27/1–/5 (/4 = [K3], /5 = [K4]) |
| R-A2L-READ.28 | `extract_a2l_tags` | READ.28/1–/4 (/4 = [K7]) |
| R-A2L-READ.62 | `extract_a2l_tags` | READ.62/1–/3, READ.28/2 |
| R-A2L-READ.29 | `_tag_keyword_lines` | READ.29/1–/6 (/5 = [B8], /6 = [B9]) |
| R-A2L-READ.58 | `_tag_keyword_lines` | READ.58/1–/5 |
| R-A2L-READ.30 | `_tag_keyword_lines` | READ.30/1–/3 (/3 = [K5]) |
| R-A2L-READ.31 | `_section_words`, `build_section_tree` | READ.31/1–/3 |
| R-A2L-READ.32 | `extract_a2l_tags` | READ.32/1–/4 |
| R-A2L-READ.59 | `extract_a2l_tags`, `_tag_sizes` | READ.59/1–/7 |
| R-A2L-READ.60 | `extract_a2l_tags`, `_tag_keyword_lines` | READ.60/1–/8 |
| R-A2L-READ.67 | `extract_a2l_tags` | READ.67/1–/3 |
| R-A2L-READ.33 | `_tag_keyword_lines`, `extract_a2l_tags` | READ.33/1, /2 |
| R-A2L-READ.34 | `_number_word` | READ.34/1 |
| R-A2L-READ.35 | `_number_word` | READ.35/1, /2 |
| R-A2L-READ.36 | `_number_word`, `_characteristic_from_tokens`, `_extended_kind_anchor` | READ.36/1–/3, READ.7/1 |
| R-A2L-READ.63 | `extract_a2l_tags`, `_number_word` | READ.63/1–/5 |
| R-A2L-READ.37 | `_tag_keyword_lines`, `_infer_length_measurement`, `_infer_length_characteristic` | READ.37/1, /2, READ.29/4 |
| R-A2L-READ.38 | `_bounded_length`, `extract_a2l_tags`, `_describe_one` | READ.38/1–/4 |
| R-A2L-READ.39 | `extract_a2l_tags` | READ.39/1 (4/4; F-E2-3 ruled at E2) |
| R-A2L-013 | `_tag_sizes`, `extract_a2l_tags` | 013/1, /2 |
| R-A2L-014 | `_infer_length_measurement` | 014/1, /2 |
| R-A2L-READ.57 | `_infer_length_measurement`, `_tag_sizes` | READ.57/1, /2 |
| R-A2L-016 | `_infer_length_characteristic`, `extract_declared_spans` | 016/1, /2; READ.43/2 |
| R-A2L-READ.53 | `_infer_length_characteristic` | READ.53/1 |
| R-A2L-017 | `_infer_length_characteristic` | 017/1–/3 (/1 = [K6c]) |
| R-A2L-READ.61 | `_tag_sizes`, `extract_a2l_tags`, `_describe_one`, `enrich_a2l_tags_with_values` | READ.61/1–/9 |
| R-A2L-READ.40 | `extract_declared_spans` | READ.40/1–/3 |
| R-A2L-READ.41 | `extract_declared_spans` | READ.41/1 |
| R-A2L-READ.42 | `extract_declared_spans` | READ.42/1, /2 |
| R-A2L-READ.43 | `extract_declared_spans` | READ.43/1–/3 (/2's fixture fixed at the E1 addendum, F-E2-5) |
| R-A2L-READ.44 | `extract_declared_spans` | READ.44/1, /2 |
| R-A2L-READ.45 | `extract_declared_spans` | READ.45/1–/3 |
| R-A2L-READ.46 | `extract_declared_spans`, `_bounded_length` | READ.46/1, /2 |
| R-A2L-READ.48 | `ref_read_a2l`, `parse_a2l_file` | READ.48/1, /2 |
| R-A2L-READ.49 | `[I/O: e07fb00 tag fixture]`, `parse_a2l_file` | READ.49/1, /2 |
| R-TUI-042a.2 | `S19TuiApp._compose_screen_a2l` — moved (Inc 12) | R-TUI-042a.2/1, /2, AT-B103-I11-1 (moved (Inc 12)) |
| R-TUI-042a.3 | `S19TuiApp._build_a2l_table_cells` — moved (Inc 12) | R-TUI-042a.3/1–/4, AT-B103-I11-1 (moved (Inc 12)) |
| R-A2L-READ.50 | `build_section_tree` (canonical `meta` = begin words), `iter_section_lines` | READ.50/1–/4 (F-E2-2 ruled at E3: begin words) |
| R-A2L-READ.51 | `iter_section_lines`, `render_a2l_view` | READ.51/1 |
| R-A2L-076 | `render_a2l_view`, `iter_section_lines` | 076/1–/3, AT-B103-I11-3 |
| R-A2L-077 | `render_a2l_view` | 077/1 |
| R-A2L-READ.52 | `build_section_tree`, `_lex_a2l_lines`, `parse_a2l_file` | READ.52/1, /2 (base medians measured: P1, P2; E3A-09 re-measure; E3C cost; round 2: e07fb00 peak RSS 535 MB, 95 MB, 70.9 MB, E3A-18) |

Requirements without an example: **none** (80 rows; every row above has a node with an example; 78 in scope after the split, 2026-11-07). READ.39/1 (F-E2-3) and READ.43/2 (F-E2-5) were ruled at E2 and applied by the E1 addendum.

### Node count

37 nodes after the E3 correction: **new 11** (`_lex_a2l_lines`, `_line_words`, `_section_words`, `_tag_header`, `_tag_keyword_lines`, `_number_word`, `_bounded_length`, `extract_declared_spans`; E3: `_tag_sizes`, `_echo_word`, `_CappedErrors`), **changed 15** in `a2l.py` (`build_section_tree`, `_parse_first_field`, `_split_line_respecting_quotes`, `_strip_a2l_comments`, `_flatten_body_tokens`, `parse_measurement_header`, `_characteristic_from_tokens`, `_extended_kind_anchor`, `_memory_segment_record_words`, `_infer_length_measurement`, `_infer_length_characteristic`, `extract_a2l_tags`, `parse_a2l_file`, `iter_section_lines`, `render_a2l_view`) + 2 in `app.py` (`S19TuiApp._compose_screen_a2l`; E3: `S19TuiApp._build_a2l_table_cells`) + 1 in `a2l_definition.py` (E3: `_describe_one`) = 18, **removed 1** (`_first_header_line`), **context 5** (`parse_begin_meta`, `_byte_order_from_section_lines`, `assemble_characteristic_header`, `parse_characteristic_header`, `validate_a2l_structure`), **test-side and evidence 2** (`ref_read_a2l`, `run_corpus_differential`). Under the 40 cap; no split. **After the round-2 correction: 39 nodes** — new 12 (+ `_build_section_tree_into`, E3A-19), changed 16 in `a2l.py` (+ `enrich_a2l_tags_with_values`, E3S-18), so 19 changed in all. E3A-17 = E3S-20 (Address and Length first and fixed) is not applied (its row would be the 81st); applied, it would change the two `app.py` nodes and add the column-label method (`app.py:8733`) as a 40th. **After the split (2026-11-07): 37 nodes** — the 2 `app.py` nodes are Inc 12's (`moved (Inc 12)` below), so 17 changed in all (16 in `a2l.py`, 1 in `a2l_definition.py`); new 12, removed 1, context 5, test-side and evidence 2 unchanged.

Deviations from `../E1-slice.md`: 4 new functions there, 8 here (the tag walk's new logic is split into `_line_words`, `_section_words`, `_tag_header`, `_tag_keyword_lines` so each row has a node with its own examples); `_lex_a2l_words` is named `_lex_a2l_lines` and yields lines (DE-1); `parse_begin_meta` (#2), `assemble_characteristic_header` (#11) and `_byte_order_from_section_lines` (#12) stay unchanged — their rows hold through canonical `meta`/`lines` (DE-3) and the tag reader's own name rule; `_strip_a2l_comments` (#5) is kept, not replaced (DE-5); `_first_header_line` (#8) is removed. Files: the same 3, and from the E3 correction 4 (`a2l_definition.py`, I-11.8 (f); slice #25 … #29).

## Nodes

_lex_a2l_lines
req: R-A2L-READ.1, R-A2L-READ.2, R-A2L-READ.3, R-A2L-READ.4, R-A2L-001.2, R-A2L-READ.7, R-A2L-READ.8, R-A2L-READ.9, R-A2L-READ.10, R-A2L-READ.11, R-A2L-001.3.1, R-A2L-001.3.2, R-A2L-READ.13, R-A2L-READ.14, R-A2L-READ.15, R-A2L-READ.16, R-A2L-READ.52, R-A2L-READ.55, R-A2L-READ.56, R-A2L-READ.65
in: Iterable[str] lines; _CappedErrors errors (from `_build_section_tree_into`)
out: Iterator[tuple[int, str]] canonical
func: new (DE-1). One pass over the text lines (an element may end with `\n`; a `\r\n` or `\r` inside an element is a line end too), yielding `(line, canonical text of the words that start on that line)` for every line that holds a word; line *k* of the input is line `k`, and every line end inside an element or inside a quoted string counts. Blanks = space, HT, VT, FF; a word ends at a blank, a line end, a `"` or the `/` that starts `/*` or `//`. Outside a quoted string: `/*` … the first `*/` and `//` … the line end are word breaks and give no word; a word holding `*/` stays a word and appends `Line <n>: */ without /*`; a word holding a character outside U+0021 … U+007E appends `Line <n>: unexpected character U+<XXXX>` (its first such character, 4 or more uppercase hex digits), once per word. A quoted string is one word with its quotes and its escape pairs (`\` + the next character, when that character is not a line end; a `\` before a line end is an ordinary character and the line end counts, E3S-12) kept, and may run over line ends; an open string's parts are kept in a list and joined once when it closes, never re-joined per line (E3S-14). An unclosed block comment appends `Line <n>: comment not closed` (`<n>` its `/*` line), an unclosed string `Line <n>: quoted string not closed` (its opening quote's line); either ends the reading. Three tiers keep it within the time bound: tier 1 applies only when every character of the line without its line end is in U+0020 … U+007E (`re.search(r"[^\x21-\x7e ]", body)` finds nothing; `body.isascii() and body.isprintable()` is the same test, E3C cost: 0.23 µs per line) and the line holds single spaces only and no `"` or `/`, and such a line is its own canonical text after `strip(" ")`; a line with quotes but no comment mark and no backslash is split by one pattern; every other line is scanned token by token (P2). Every strip and split of the reader's word path names its blank set (`strip(" \t\x0b\x0c")`, `split(" ")` on canonical text); no bare `strip()`, `split()`, `isspace()` or `splitlines()`, and no `\s` or `\d` without `re.ASCII` (E3S-06; G-T1 adds an AST guard over `_lex_a2l_lines`, `_line_words`, `_section_words`, `_tag_header`, `_tag_keyword_lines`, `_number_word`, `_tag_sizes` and the field loop of `extract_a2l_tags`). **NUL (READ.55):** a tier-1 line holds no U+0000; a tier-2 or tier-3 line that holds one ends the reading, `errors` is reset to the single text `File is not UTF-8 text; save it as UTF-8 and load it again.`, and the generator returns (`build_section_tree` then gives no section). A generator: nothing is held but the current line and an open string's parts. **Round 2.** (E3A-18) An open string's continuation on each line is found with `str.find('"', i)` plus a backslash count, or with the unrolled pattern `"[^"\\]*(?:\\.[^"\\]*)*"`, never with a per-character alternation such as P2's `"(?:[^"\\]|\\.)*"` (1,005 MB on READ.52/2's 8.5 MB string, against 29 MB unrolled and 41 MB for the parts list); no pattern runs across lines or over the whole file. (E3S-25) Each word carries the line it starts on: when a string closes on a later line, the words after its closing quote are yielded as their own item with that closing line, so an `/end` there gets that line as `end_line` and an error there names it.
module: s19_app/tui/a2l.py
modify: errors (append)
examples: (R-A2L-READ.7/1, LS) `["MAP 0x1C2D3E00/*c*/4026 RL 0 CM 0 1"]` → `(1, "MAP 0x1C2D3E00 4026 RL 0 CM 0 1")`; errors `[]` (base: the comment strip glues `0x1C2D3E004026`, C [H2a])
examples: (R-A2L-READ.7/2, LS) `["MAP 0x1C2D3E00/* old", " */4026 RL"]` → `(1, "MAP 0x1C2D3E00 4026 RL")` (base C [H2b])
examples: (R-A2L-READ.2/1, /2, LS) `ECU_ADDRESS` then HT, VT or FF, then `0x1234`, one per line → `(1, "ECU_ADDRESS 0x1234")`, `(2, "ECU_ADDRESS 0x1234")`, `(3, "ECU_ADDRESS 0x1234")`
examples: (R-A2L-READ.3/1, R-A2L-READ.4/1, LS) `["ECU_ADDRESS 0x1234<U+00A0>", "ECU_ADDRESS 0x1234<U+2028>"]` → the words `0x1234<U+00A0>` and `0x1234<U+2028>` kept whole; errors `Line 1: unexpected character U+00A0`, `Line 2: unexpected character U+2028` (the 8 characters of .3/1 the same; U+0000 is READ.55's)
examples: (R-A2L-READ.3/3, R-A2L-READ.4/5, E3S-06) `["/begin CHARACTERISTIC CX \"\" VALUE 0x2000<U+0085> RL_U16 0 CM_ID 0 65535"]` → the word `0x2000<U+0085>` kept whole (the line is not tier 1: U+0085 is outside U+0020 … U+007E); errors `Line 1: unexpected character U+0085` (base: `str.strip`/`split` drop U+0085 and read 0x2000, E3S-06 [M1])
examples: (R-A2L-READ.55/3, E3A-02) `["A", "ECU_ADDRESS 0x1234<U+0000>", "B"]` → `(1, "A")` only; errors `["File is not UTF-8 text; save it as UTF-8 and load it again."]` (base: the word kept and no error, C [RP-A16])
examples: (R-A2L-001.3.2/4, E3S-12) `['A "a\\', '"', "/end X"]` → `(1, 'A "a\\\n"')`, `(3, "/end X")`: the string runs from line 1 to line 2, and `/end X` stays on line 3 (E1's REF paired `\` with the line end and gave line 2)
examples: (R-A2L-READ.56/2) 400,000 lines each holding the word `é` → `errors` holds 100 texts and then `… 399900 more parse errors`; the generator still yields every line
examples: (R-A2L-READ.3/2) `ECU_ADDRESS<U+00A0>0x1234` → one word `ECU_ADDRESS<U+00A0>0x1234` and its error (base: NBSP splits it, C [RP-A14])
examples: (R-A2L-READ.4/2) `/* ° µ */` and `PHYS_UNIT "°C"` → errors `[]`
examples: (R-A2L-READ.4/4, CG-5 [L1]) a Latin-1 `0xB0` read as U+FFFD (R-A2L-001.7): in `/* 20 <U+FFFD>C */` and `"Temp <U+FFFD>C"` → no error; in the word `XL1_<U+FFFD>` → `Line <n>: unexpected character U+FFFD` (base: 0 errors, K [L1])
examples: (R-A2L-READ.1/4, LS) `["A\r\r\nB\r\nC\rD"]` → `(1, "A")`, `(3, "B")`, `(4, "C")`, `(5, "D")`
examples: (R-A2L-READ.8/1) `/* a /* b */ ECU_ADDRESS 0x1234` → `(1, "ECU_ADDRESS 0x1234")`
examples: (R-A2L-READ.8/2, R-A2L-READ.11/2, LS) `/* a /* b */ c */ ECU_ADDRESS 0x1234` → `(1, "c */ ECU_ADDRESS 0x1234")`; errors `Line 1: */ without /*`
examples: (R-A2L-READ.9/3, LS) `["// c\rECU_ADDRESS 0x1234"]` → `(2, "ECU_ADDRESS 0x1234")`
examples: (R-A2L-READ.10/1, LS) `["A", "/* never closed", "ECU_ADDRESS 0x1234"]` → `(1, "A")` only; errors `Line 2: comment not closed`
examples: (R-A2L-READ.11/1) `*/` alone on line 20 → `(20, "*/")`; errors `Line 20: */ without /*`
examples: (R-A2L-001.3.2/1, LS) `/begin CHARACTERISTIC X "C:\\"` → `(1, '/begin CHARACTERISTIC X "C:\\"')`, the string closed at its last quote (base: `\\"` does not close, C [RP-B24])
examples: (R-A2L-001.3.2/2, LS) `"a\"b" X` → `(1, '"a\"b" X')`
examples: (R-A2L-READ.13/1, LS) `FORMAT "/* x" ECU_ADDRESS 0x1234` → `(1, 'FORMAT "/* x" ECU_ADDRESS 0x1234')`
examples: (R-A2L-READ.14/1, LS; round 2, E3S-25) `['A "x', '/end ANNOTATION_TEXT', 'y" BIT_MASK 0x0FF0']` → `(1, 'A "x\n/end ANNOTATION_TEXT\ny"')`, `(3, "BIT_MASK 0x0FF0")` (round 1 gave one item on line 1)
examples: (R-A2L-READ.14/2, E3S-25) `['FORMAT "a', 'b" é /end MEASUREMENT']` as lines 4 and 5 → `(4, 'FORMAT "a\nb"')`, `(5, "é /end MEASUREMENT")`; errors `Line 5: unexpected character U+00E9` (round 1: line 4)
examples: (R-A2L-READ.65/5, R-A2L-READ.52/2, E3A-18) one 10 MB string on one line → one item; peak memory within READ.52's bound (the unrolled scan: 29 MB on the 8.5 MB file; P2's alternation: 1,005 MB → RED)
examples: (R-A2L-READ.15/1, LS) `["A", 'FORMAT "%5.0', "B"]` → `(1, "A")`, `(2, "FORMAT")`; errors `Line 2: quoted string not closed`
examples: (R-A2L-READ.16/1, LS) `/begin MEASUREMENT X"long"` → `(1, '/begin MEASUREMENT X "long"')`
examples: (R-A2L-READ.16/3) `MAP 0x1C2D3E00"4026"` → `(1, 'MAP 0x1C2D3E00 "4026"')`
examples: (R-A2L-001.2/6, on one line, R) `ECU_ADDRESS 0x1234 // ECU_ADDRESS 0x9999` → `(1, "ECU_ADDRESS 0x1234")`
examples: (R-A2L-READ.52/1, P2) case_06 (36.7 MB): this shape's tree build `3.22` s against the base tree `1.025` s and the base parse `5.898` s — projection `1.37`× (bound `1.50`); software_a `1.34`×

_line_words
req: R-A2L-READ.16, R-A2L-001.3.1
in: str text
out: list[str] words
func: new. Splits one canonical text into its words: at each single space outside a quoted word; a quoted word keeps its quotes (so `w[0] == '"'` tells a quoted word). The inverse of the join `_lex_a2l_lines` makes.
module: s19_app/tui/a2l.py
examples: (R-A2L-001.3.1/1) `'X "a b" UWORD'` → `["X", '"a b"', "UWORD"]`
examples: (R-A2L-READ.16/1) `'X "long"'` → `["X", '"long"']`
examples: (R-A2L-001.3.1/2) `'X ""'` → `["X", '""']`

build_section_tree
req: R-A2L-001.1, R-A2L-001.2, R-A2L-001.4, R-A2L-001.5, R-A2L-001.6, R-A2L-001.7, R-A2L-READ.1, R-A2L-READ.5, R-A2L-READ.6, R-A2L-READ.12, R-A2L-READ.13, R-A2L-READ.17, R-A2L-READ.18, R-A2L-READ.19, R-A2L-READ.20, R-A2L-READ.21, R-A2L-READ.22, R-A2L-READ.24, R-A2L-READ.31, R-A2L-READ.50, R-A2L-READ.54, R-A2L-READ.55, R-A2L-READ.56, R-A2L-READ.64, R-A2L-READ.65, R-A2L-READ.66, R-A2L-004.11, R-A2L-READ.52
in: Path path; A2LProgress? progress = None
out: tuple(list[dict] sections, list[str] errors)
func: changed (DE-2, DE-3; I-11.1). was: line-based — a line starting with `/begin` opens a section (keyword = its second blank-split part, `UNKNOWN` when none; `meta` = the raw rest), a line starting with `/end` closes the innermost, every other line is appended raw; no name check; comments and strings not read; `Unclosed /begin sections detected.` at the end. / now: opens `path` as base (text mode, `utf-8`, errors `replace`, universal newlines; `os.fstat` only with a callback; a report `(handle.buffer.tell(), total)` every 4 096 lines and `(total, total)` after the read; an `OSError` other than a missing file re-raised before the final report). First, if the file's first two bytes are `FF FE` or `FE FF`, returns `([], ["File is UTF-16 encoded; save it as UTF-8 and load it again."])`; a UTF-8 BOM is dropped. Then feeds the lines to `_lex_a2l_lines` and builds the tree from its canonical lines: a line with no `/` (or none of `/begin`, `/end`, `/include` in any case) is appended to the innermost section as one run; another line is split by `_line_words`, where a word equal to `/begin` or `/end` in any letter case (and only such a whole word) is structure: `/begin` opens a section whose keyword is the next word wherever it stands (later lines included); `/end` closes the innermost open section and consumes the next word as its name — a name other than the section's keyword appends `Line <n>: /end <name> does not close /begin <keyword>`, no open section appends `Line <n>: /end without /begin`; an `/include` word appends `Line <n>: /include <next word without quotes> is not read` and stays a word. Own words go to `meta` (the keyword's line, before any child) or to a run in `lines` with its line in `line_numbers`; a child section leaves `""` in its parent's `lines`. **E3 correction (DE-3 revised, R-A2L-READ.54, E3A-01):** when a section's keyword is in `[Data: _NAMED_KINDS]` and its keyword line holds none of its own words, its first run that holds own words becomes `meta` (`meta_line` = that run's line) and leaves `lines`; when that run is the name alone and the next own word is a quoted word, the run holding it joins `meta` too (the long identifier, READ.24). Every `parse_begin_meta` reader then names the section, and readers of `[meta] + lines` see the same word order. The word after `/begin` or `/end` is consumed whatever it is (`/begin /end X` opens a section whose keyword is `/end`; E3S-13). A `/begin` or `/end` with no word after it in the file is an ordinary word. Words outside every section are dropped (as base). `Unclosed /begin sections detected.` stays. **Bounds (DE-10):** `errors` is a `_CappedErrors` (READ.56); a `/begin` that would open a 33rd level resets `errors` to `Line <n>: sections nested deeper than 32` and returns `([], errors)` (READ.64), so no recursive reader (`extract_record_layouts`, `extract_a2l_tags`, `extract_memory_segments`, `iter_section_lines`, `extract_declared_spans`) ever walks deeper than 32 (READ.65); a NUL refusal from `_lex_a2l_lines` returns `([], errors)` (READ.55); `/end`'s and `/include`'s file words go through `_echo_word` (READ.66). **Round 2 (E3A-19):** every rule above lives in `_build_section_tree_into`; `build_section_tree` is the public facade (`a2l_parse.py`, called by tests): it creates a `_CappedErrors`, calls `_build_section_tree_into(path, progress, errors)` and returns `(sections, errors.as_list())`, so a direct caller gets the `… <k> more parse errors` marker.
module: s19_app/tui/a2l.py
examples: (R-A2L-001.1/1, Inc 2 J4) `MEAS(SX, " ECU_ADDRESS 0x10 /begin IF_DATA XCP", "  KP_BLOB 0x10", " /end IF_DATA", " BIT_MASK 0x0FF0")` → SX `meta` `SX ""`, `lines` `["UWORD CM_ID 0 0 0 65535", "ECU_ADDRESS 0x10", "", "BIT_MASK 0x0FF0"]`; its child IF_DATA `meta` `XCP`, `lines` `["KP_BLOB 0x10"]`; errors `[]` (base: IF_DATA never opened, C [RP-C-J4])
examples: (R-A2L-001.1/2) `/* c */ /begin MEASUREMENT X ""` … → a MEASUREMENT section, `meta` `X ""`
examples: (R-A2L-001.1/3) `MEAS(X, " ECU_ADDRESS 0x1234 /end MEASUREMENT")` with no `/end` line of its own → X closed on that line, `lines` end with `ECU_ADDRESS 0x1234`; errors `[]`
examples: (R-A2L-001.1/4, [K7b]) `/begin INSTANCE IK7 "" T_U16 0x20 /end INSTANCE /begin INSTANCE IK7B "" T_U16 0x40 /end INSTANCE` on one line → two INSTANCE sections, `meta` `IK7 "" T_U16 0x20` and `IK7B "" T_U16 0x40`, both with `start_line` = `end_line`; errors `[]` (base: `Unclosed /begin sections detected.`, K)
examples: (R-A2L-READ.17/1) `ASAP2_Demo_V171.a2l` → errors `[]`; the 30 one-line IF_DATA closed on their line; every MEASUREMENT at depth `3` (base: `Unclosed /begin sections detected.`, MEASUREMENTs nested, C [CH])
examples: (R-A2L-READ.17/2) RP-B13 → X's `lines` `["UWORD CM_ID 0 0 0 65535", "", "ECU_ADDRESS 0x1234"]`, its IF_DATA `meta` `ETK KP_BLOB 0x10 INTERN 1 RASTER 2`
examples: (R-A2L-READ.17, [K5]) `/begin MEASUREMENT XK5 "d" FLOAT64_IEEE NO_COMPU_METHOD 0 0 -100 100  ECU_ADDRESS 0x18 ECU_ADDRESS_EXTENSION 3 READ_WRITE /begin IF_DATA XCP /begin DAQ_EVENT FIXED_EVENT_LIST EVENT 0x0 /end DAQ_EVENT /end IF_DATA /end MEASUREMENT` → XK5 `meta` `XK5 "d" FLOAT64_IEEE NO_COMPU_METHOD 0 0 -100 100 ECU_ADDRESS 0x18 ECU_ADDRESS_EXTENSION 3 READ_WRITE`, `lines` `[""]`, child IF_DATA › DAQ_EVENT; errors `[]` (base: `Unclosed /begin sections detected.`, K)
examples: (R-A2L-READ.18/1, /2) `/BEGIN MEASUREMENT X ""` … `/END MEASUREMENT` and `/Begin` … `/eNd` → the same tree as lower case
examples: (R-A2L-READ.19/1) RP-B31 `/beginMEASUREMENT X ""` … `/end MEASUREMENT` → no section X; `/beginMEASUREMENT` is a word of MODULE; errors `Line <n>: /end MEASUREMENT does not close /begin MODULE` (base: a section named `X`, C [RP-B31])
examples: (R-A2L-READ.19/2) `MEAS(X, " /endX")` → `/endX` a word of X; X closes at its own `/end`
examples: (R-A2L-READ.20/1) `/begin` ↵ `MEASUREMENT X ""` … → a MEASUREMENT section, `meta` `X ""`, `meta_line` = `start_line` + `1`
examples: (R-A2L-READ.20/2) `/begin /*c*/ MEASUREMENT X ""` → a MEASUREMENT section (base: keyword `/*c*/`, R `a2l.py:203-204`)
examples: (R-A2L-001.4/1, /2) `/end X` or `junk /end X` on line 30 after `/end PROJECT` → errors `["Line 30: /end without /begin"]`
examples: (R-A2L-001.5/1) MEAS(X) whose last line is `/end IF_DATA` on line 23 → errors `Line 23: /end IF_DATA does not close /begin MEASUREMENT`; X `end_line` `23`
examples: (R-A2L-001.5/2, R-A2L-READ.21/1) `MEAS(X, " /begin IF_DATA XCP")` with no `/end IF_DATA`, X's `/end` on line 23 → `Line 23: /end MEASUREMENT does not close /begin IF_DATA`; the IF_DATA `end_line` `23` (the innermost closes); later `Unclosed /begin sections detected.`
examples: (R-A2L-READ.22/1) `merge_inc_test.a2l` → exactly one `Line <n>: /include included.a2l is not read` (`<n>` the line of its `/include` word, confirmed at E4)
examples: (R-A2L-READ.22/2) `/* /include "x.a2l" */` → errors `[]`
examples: (R-A2L-READ.12/1) RP-B28 → exactly 1 MEASUREMENT section X, its `lines` `["UWORD CM_ID 0 0 0 65535", "ECU_ADDRESS 0x1234"]` (base: 2 sections, the first at the old address, C [RP-B28])
examples: (R-A2L-READ.12/2, /3) RP-B29, RP-B30 → 0 MEASUREMENT sections
examples: (R-A2L-READ.13/3) `MEAS(X, ' PHYS_UNIT "/begin MEASUREMENT Q"', " ECU_ADDRESS 0x1234")` → 1 MEASUREMENT section; no section Q
examples: (R-A2L-READ.13/4, Inc 2 L7) the ANNOTATION_TEXT string holding `/end` lines → X ends at its own `/end`; X's `lines` end with `BIT_MASK 0x0FF0`
examples: (R-A2L-READ.31/1) `MEAS(X, " ECU_ADDRESS 0x1234", " /begin IF_DATA ETK KP_BLOB 0x9999 /end IF_DATA")` → `KP_BLOB 0x9999` in the IF_DATA's `meta`, not in X's words
examples: (R-A2L-READ.5/1) `\ufeff` + HDR … → the same tree as without the mark
examples: (R-A2L-READ.5/2) RP-A9 (BOM, then `/begin PROJECT`) → PROJECT a section; errors `[]` (base: `Line <n>: /end without /begin`, C [RP-A9])
examples: (R-A2L-READ.6/1, /2) bytes `FF FE` + the text in UTF-16 LE, and `FE FF` + UTF-16 BE → `([], ["File is UTF-16 encoded; save it as UTF-8 and load it again."])` (base: 0 tags, 0 errors, C [RP-A10])
examples: (R-A2L-READ.1/1 … /3) the 35 tracked files with CRLF, lone CR, or cycling CRLF/CR/LF → the sections (`start_line`, `end_line`, `meta_line`, `line_numbers` included) and errors of the LF file, 35/35 each
examples: (R-A2L-READ.1/4) RP-A4 (CR CR LF) → the LF reading with line *k* at `2k − 1`
examples: (R-A2L-READ.50/1, RP-A27) `/begin CHARACTERISTIC XH "one-line header" VALUE 0x00003000/*old 0x1000*/ RL_U32 0 CM_ID 0 100` → `meta` `XH "one-line header" VALUE 0x00003000 RL_U32 0 CM_ID 0 100` (base: the raw rest with the comment, C [RP-A27])
examples: (R-A2L-READ.54/1, E3A-01) `/begin COMPU_METHOD` (line 30) ↵ `CM_LIN "" LINEAR "%.2" "rpm"` ↵ `COEFFS_LINEAR 2 0` ↵ `/end COMPU_METHOD` → the COMPU_METHOD section `meta` `CM_LIN "" LINEAR "%.2" "rpm"`, `meta_line` `31`, `lines` `["COEFFS_LINEAR 2 0"]` — the layout `extract_compu_methods` reads on base for a one-line `/begin` (base: `meta` `""`, so `CM_LIN` is named `UNKNOWN`)
examples: (R-A2L-READ.24/3) `/begin COMPU_METHOD` ↵ `CM_LID` ↵ `"engine speed"` ↵ `LINEAR "%.2" "rpm"` ↵ `COEFFS_LINEAR 1 0` → `meta` `CM_LID "engine speed"`, `lines` `["LINEAR \"%.2\" \"rpm\"", "COEFFS_LINEAR 1 0"]` (the body reader finds `LINEAR` on the first line of `lines`)
examples: (R-A2L-READ.54/3) `/begin RECORD_LAYOUT` ↵ `RL_K1` ↵ `FNC_VALUES 1 UWORD ROW_DIR DIRECT` → `meta` `RL_K1`, `lines` `["FNC_VALUES 1 UWORD ROW_DIR DIRECT"]`
examples: (R-A2L-READ.54/7, holds as base) BalanceTube's MOD_COMMON (keyword alone on its line; MOD_COMMON is not a named kind) → `meta` `""`, its first line still in `lines` (DE-3's reason); software_a's 3 MEMORY_SEGMENTs → `meta` = their first run, and `extract_memory_segments` (`[meta, *lines]`) reads the same words as e07fb00
examples: (R-A2L-READ.64/1, /2) 33 nested `/begin A`, one per line (the 33rd on line 33) or all on line 1 → `([], ["Line 33: sections nested deeper than 32"])`, `([], ["Line 1: sections nested deeper than 32"])` (base: depth > ~990 raises `RecursionError` later in a walker, E3S-04 [H1])
examples: (R-A2L-READ.64/3) 32 nested levels → 32 nested sections, errors `[]`
examples: (R-A2L-READ.65/1, /2) 5,000 levels, or 50,000 `/begin` lines with no `/end` → the READ.64 result; no exception
examples: (R-A2L-READ.55/1) HDR written as UTF-16 LE with no BOM → `([], ["File is not UTF-8 text; save it as UTF-8 and load it again."])` (base: 0 sections, 0 errors; E3A-02 [u16])
examples: (E3S-13) `/begin /end X` ↵ `/end /end` → one section with keyword `/end`, closed by the second line's `/end /end`; REF reads it the same (hostile corpus)
examples: (R-A2L-004.11, holds as base) case_06 with a callback → reports rise, `seen[-1]` = `(size, size)`, at most `lines // 4096 + 1` reports (TC-B100-73); a read failing at line 5 000 → exactly `1` report, then `OSError`
examples: (R-A2L-READ.52/1) see `_lex_a2l_lines`; the base medians measured in the same session (P1, P2): case_06 parse `5.898` s (bound `8.85` s), software_a `0.653` s (bound `0.98` s)
examples: (R-A2L-READ.56/4, E3A-19) 150 stray `/end X` lines → `errors` a plain `list` of 101 entries, the last `… 50 more parse errors` (round 1: the capper itself, 100 entries and no marker)

_build_section_tree_into
req: R-A2L-READ.56, R-A2L-READ.64, R-A2L-READ.65
in: Path path; A2LProgress? progress; _CappedErrors errors
out: list[dict] sections
modify: errors (append, reset)
func: new (round 2, E3A-19). The builder of `build_section_tree` — every rule and example of that node — writing its errors into the `_CappedErrors` it is given instead of one of its own. `parse_a2l_file` calls it with the capper it then passes to `extract_a2l_tags`, so the builder's and the tag reader's errors share one cap of 100.
module: s19_app/tui/a2l.py
examples: (R-A2L-READ.56, I-11.6, via `parse_a2l_file`) 60 builder errors and 60 tag errors → the payload's `errors` holds 101 entries, the last `… 20 more parse errors`

_parse_first_field
req: R-A2L-001.3.2, R-A2L-READ.2
in: str meta
out: tuple(str first, str rest)
func: changed. was: a quoted first field closes at a `"` whose previous character is not `\` (so `\\"` does not close); an unquoted one ends at Unicode whitespace (`split`). / now: a `\` and the character after it are one pair, so `\"` does not close and `\\"` does; an unquoted field ends at an ASCII blank, a line end or a `"`.
module: s19_app/tui/a2l.py
examples: (R-A2L-001.3.2/1) `'"C:\\" VALUE'` → (`C:\\`, `VALUE`) (base: (`C:\\" VALUE`, `""`), R `a2l.py:277`)
examples: (R-A2L-001.3.2/2) `'"a\"b" X'` → (`a\"b`, `X`)
examples: (R-A2L-READ.2) `"X\x0cY"` → (`X`, `Y`); `"X\u00a0Y"` → (`X\u00a0Y`, `""`)

parse_begin_meta
req: R-A2L-001.3.1, R-A2L-READ.54
in: str meta
out: tuple[str, Optional[str]] parsed
func: unchanged (`a2l.py:255`, public facade `a2l_parse`). The name and long identifier of a section's `meta`; `UNKNOWN` for an empty `meta`. No longer called for MEASUREMENT and CHARACTERISTIC by `extract_a2l_tags` (their name comes from `_tag_header`); still the name rule of record layouts, compu methods, compu tables, AXIS_DESCR and Inc 2a. Its result moves only through `_parse_first_field` and the canonical `meta`.
module: s19_app/tui/a2l.py
examples: (holds on base) `'RL_U16'` → (`RL_U16`, `None`); `'CM_ID "" IDENTICAL "%.0" ""'` → (`CM_ID`, `None`)
examples: (the base, I-11.8 a) a CHARACTERISTIC whose name stands on the line after its keyword, `meta` `""` → (`UNKNOWN`, `None`) — so a consumer naming sections by it disagreed with the tag's name
examples: (R-A2L-READ.54, E3A-01) the same CHARACTERISTIC after DE-3's revision, `meta` `CK1 "long id"` → (`CK1`, `long id`); a COMPU_METHOD `meta` `CM_LIN "" LINEAR "%.2" "rpm"` → (`CM_LIN`, `None`); an AXIS_PTS `meta` `AP_K1 "" 0x3000 NO_INPUT_QUANTITY RL_U16 0 CM_ID 4 0 100` → (`AP_K1`, `None`)

_split_line_respecting_quotes
req: R-A2L-READ.2, R-A2L-READ.3, R-A2L-READ.16, R-A2L-001.3.1, R-A2L-001.3.2
in: str line
out: list[str] tokens
func: changed (I-11.4). was: words end at Unicode whitespace (`isspace`); a quoted word closes at a `"` not preceded by `\`; an unquoted word runs through a `"`. / now: words end at an ASCII blank or a line end; a `\` and the next character are one pair inside a quoted word; a `"` ends an unquoted word and starts a quoted one. A quoted word is returned without its quotes (as base). On canonical text it returns exactly the words `_lex_a2l_lines` joined.
module: s19_app/tui/a2l.py
examples: (R-A2L-READ.16/2, Inc 2 U) `'FORMAT "%5.0"BIT_MASK 0x0FF0'` → `["FORMAT", "%5.0", "BIT_MASK", "0x0FF0"]` (base: `%5.0` then `BIT_MASK` glued to the quote's run, C [RP-C-U])
examples: (R-A2L-READ.2/2) `"ECU_ADDRESS\x0c0x1234"` → `["ECU_ADDRESS", "0x1234"]`
examples: (R-A2L-READ.3) `"ECU_ADDRESS 0x1234\u2028"` → `["ECU_ADDRESS", "0x1234\u2028"]` (base: `["ECU_ADDRESS", "0x1234"]`)
examples: (R-A2L-001.3.2/3) `'"\\\"" X'` → `["\\\"", "X"]`
examples: (holds on base, Inc 3 B3 P2) `AXIS_PTS_X 2 SBYTE INDEX_DECR DIRECT` → `["AXIS_PTS_X", "2", "SBYTE", "INDEX_DECR", "DIRECT"]`

_strip_a2l_comments
req: R-A2L-READ.7
in: str text
out: str text
func: changed (DE-5; I-11.4). was: removes `/* … */` and `// …` (to the next `\n`) outside quoted text with nothing in their place, so the words on both sides join; a `\` before `"` keeps a string open. / now: each comment is replaced by one space; the escape pair as in `_split_line_respecting_quotes`. No `a2l.py` caller after Inc 11 (`_flatten_body_tokens` lexes); kept for Inc 3a (F-E2-6).
module: s19_app/tui/a2l.py
examples: (R-A2L-READ.7, TC-097) `"CURVE/*c*/0x1"` → `"CURVE 0x1"` (base: `"CURVE0x1"`, `tests/test_a2l_multiline_headers.py:389`)
examples: (TC-097) `"A /* c\n more c */ B"` → `"A   B"`
examples: (holds on base) `'"a */ b // c http://d"'` → itself

_flatten_body_tokens
req: R-A2L-001.2, R-A2L-READ.7
in: list[str] lines
out: list[str] tokens
func: changed (I-11.4). was: `\n`-join → `_strip_a2l_comments` (a comment glues its neighbours) → `_split_line_respecting_quotes`. / now: the words of `_lex_a2l_lines(lines, <a throwaway list>)`, quoted words without their quotes. On canonical `meta`/`lines` (every product caller after Inc 11) the base tokens; on raw text a comment is a word break.
module: s19_app/tui/a2l.py
examples: (holds on base, TC-098) `['"a b" VALUE', "0x1 RL"]` → `["a b", "VALUE", "0x1", "RL"]`; `['"a\\"b" X']` → the tokens `_split_line_respecting_quotes` gives
examples: (holds on base, TC-100) `["STD_AXIS X CM /* c */", "8", "-128 127"]` → `["STD_AXIS", "X", "CM", "8", "-128", "127"]`
examples: (R-A2L-READ.7) `["CURVE/*c*/0x810300 RL"]` → `["CURVE", "0x810300", "RL"]` (base: `["CURVE0x810300", "RL"]`)
examples: (holds on base, Inc 2 B2 P1b) BalanceTube `model.MainClass.gameController.sm`, `[meta] + lines` → starts `model.MainClass.gameController.sm`, `""`, `UBYTE`

_section_words
req: R-A2L-READ.23, R-A2L-READ.29, R-A2L-READ.31
in: dict section
out: list[tuple[str, int]] words
func: new (DE-4). The section's own words in file order, each `(canonical word, line)`: the words of `meta` at `meta_line`, then the words of each `lines[i]` at `line_numbers[i]` (`_line_words`); a `""` entry gives the place mark `("", line)` (a child section). Child sections' words are never in it.
module: s19_app/tui/a2l.py
examples: (R-A2L-READ.23/1, RP-B16) `/begin MEASUREMENT` ↵ ` X ""` ↵ ` UWORD CM_ID 0 0 0 65535` ↵ ` ECU_ADDRESS 0x1234`, `/begin` on line 20 → `[("X", 21), ('""', 21), ("UWORD", 22), …, ("65535", 22), ("ECU_ADDRESS", 23), ("0x1234", 23)]`
examples: (R-A2L-READ.31/1) X of RP-B13 → `[("X", …), ('""', …), ("UWORD", …), …, ("", <IF_DATA start>), ("ECU_ADDRESS", …), ("0x1234", …)]`; no `KP_BLOB`
examples: (R-A2L-READ.31/2, Inc 2 W) a MEASUREMENT whose ANNOTATION_TEXT holds `"BIT_MASK 0x0FF0"` → no `BIT_MASK` word of its own

_tag_header
req: R-A2L-READ.23, R-A2L-READ.24, R-A2L-READ.25, R-A2L-READ.26, R-A2L-READ.27, R-A2L-001.3.1
in: str section_name; list[tuple[str, int]] words
out: tuple(str name, Optional[str] long_identifier, list[str] header, int rest)
func: new (DE-4). `name` = the first word (a quoted word without its quotes; `UNKNOWN` when there is none); `long_identifier` = the second word without its quotes when it is quoted (`None` when it is not quoted or is `""`; a `""` is still consumed); `header` = the next words, at most `_HEADER_WORDS[section_name]` (MEASUREMENT `6`, CHARACTERISTIC `7`, BLOB `2`, INSTANCE `2`, TYPEDEF_MEASUREMENT `6`, TYPEDEF_CHARACTERISTIC `6`, TYPEDEF_BLOB `1`, TYPEDEF_STRUCTURE `1`), ending before the first unquoted keyword of `_TAG_KEYWORD_ARITY` or the first place mark; `rest` = the index of the first word after the header.
module: s19_app/tui/a2l.py
examples: (R-A2L-READ.23/1) MEASUREMENT, the words of RP-B16 → (`X`, `None`, `["UWORD", "CM_ID", "0", "0", "0", "65535"]`, `8`)
examples: (R-A2L-READ.23/5, [K1]) `/begin MEASUREMENT` ↵ `XK1` ↵ `"long id"` ↵ `UWORD` ↵ `CM_ID` ↵ `0` ↵ `0` ↵ `0` ↵ `65535` ↵ `ECU_ADDRESS` ↵ `0x1234` → (`XK1`, `long id`, `["UWORD", "CM_ID", "0", "0", "0", "65535"]`, `8`) (base: `UNKNOWN`, datatype None, no address, K)
examples: (R-A2L-READ.23/6, [K1c]) CHARACTERISTIC `CK1` one word per line → (`CK1`, `long id`, `["VALUE", "0x2000", "RL_U16", "0", "CM_ID", "0", "65535"]`, `9`) (base: name `UNKNOWN`, K)
examples: (R-A2L-READ.23/2, /3) RP-B19 `/begin MEASUREMENT /* c */ X ""` and RP-B18 `X/*c*/ ""` → name `X`
examples: (R-A2L-READ.24/1) V171 `ASAM.M.SCALAR.UBYTE.IDENTICAL` (long identifier on the next line) → long identifier `Scalar measurement` (base: `None`, C [FX-other])
examples: (R-A2L-READ.24/2) `case_07_stress_smoke/firmware.a2l` → `long_identifier` `None` for 12/12 tags, `header` `[]`
examples: (R-A2L-001.3.1/1, /3) `X "a b"` → long identifier `a b`; `X "x/*y*/z"` → `x/*y*/z`
examples: (R-A2L-001.3.1/2) `X ""` → long identifier `None`, rest after the `""`
examples: (R-A2L-READ.25/1) BalanceTube `model.MainClass.gameController.sm` (header over 6 commented lines) → header `["UBYTE", "esdl_model_GameControllerStatemachineStates", "1", "100.0", "0", "3"]` (Inc 2 B2 P1b)
examples: (R-A2L-READ.25/5, [K2]) `/begin MEASUREMENT XK2 ""` ↵ `UWORD` ↵ `CM_ID` ↵ `0` ↵ `0` ↵ `0` ↵ `65535` ↵ `ECU_ADDRESS 0x1234` → header `["UWORD", "CM_ID", "0", "0", "0", "65535"]` (base: datatype None, length None, K)
examples: (R-A2L-READ.25/3, RP-B14) `/begin MEASUREMENT X "" UWORD CM_ID 0 0 0 65535` → header from `meta`: `["UWORD", "CM_ID", "0", "0", "0", "65535"]`
examples: (R-A2L-READ.26/1, RP-B23) `/begin CHARACTERISTIC X "d" VALUE 0x2000 RL_U16 0 CM_ID 0 65535` → (`X`, `d`, `["VALUE", "0x2000", "RL_U16", "0", "CM_ID", "0", "65535"]`, `9`)
examples: (R-A2L-READ.26/3, RP-B21) `VALUE 0x2000/*c*/RL_U16 0 CM_ID 0 65535` → header `["VALUE", "0x2000", "RL_U16", "0", "CM_ID", "0", "65535"]`
examples: (R-A2L-READ.26/4, R-A2L-READ.27/4, [K3]) `/begin CHARACTERISTIC CK3 "d" VALUE 0x1000 RL_U16 0 CM_ID 100 10000` ↵ `ECU_ADDRESS_EXTENSION 0` ↵ `BYTE_ORDER MSB_LAST` … → header `["VALUE", "0x1000", "RL_U16", "0", "CM_ID", "100", "10000"]`; `ECU_ADDRESS_EXTENSION` never a header word (base: kind `ECU_ADDRESS_EXTENSION`, address `0x0`, deposit `BYTE_ORDER`, K)
examples: (R-A2L-READ.26/5, R-A2L-READ.27/5, [K4]) `/begin CHARACTERISTIC CK4 "d" CUBE_5 0x123 RL_U16 1 CM_ID 0 10` ↵ `NUMBER 10000` … → header `["CUBE_5", "0x123", "RL_U16", "1", "CM_ID", "0", "10"]` (base: kind `NUMBER`, address `0x2710`, K)
examples: (R-A2L-READ.27/2, Inc 2 C) `UWORD CM_ID 0 0 0 BIT_MASK 0x0FF0` after `SX ""` → header `["UWORD", "CM_ID", "0", "0", "0"]` (5 words; BIT_MASK is the first keyword)
examples: (R-A2L-READ.27/3) `/begin CHARACTERISTIC Q` ↵ `ECU_ADDRESS 0x10` ↵ `LENGTH 2` → (`Q`, `None`, `[]`, `1`)
examples: (R-A2L-READ.27/1) case_07's MEASUREMENTs (no long identifier, no header) → header `[]` for 12/12

_tag_keyword_lines
req: R-A2L-READ.29, R-A2L-READ.30, R-A2L-READ.31, R-A2L-READ.33, R-A2L-READ.37, R-A2L-READ.58
in: list[tuple[str, int]] words; int start; list[str]? errors = None
out: list[tuple[str, int]] keyword_lines
modify: errors (append)
func: new (DE-4; DE-9 at the E3 correction). From `words[start:]`: each unquoted word that is a key of `_TAG_KEYWORD_ARITY` (the CTX-A2L-TAG keyword list with its arities) gives one item `(canonical "<KEYWORD> <arg> …", line of the keyword)`. Its argument words are the words after it up to the next unquoted keyword, the next place mark or the end of `words` (**a keyword is never an argument**, E3S-02): the first `arity` of them, and for MATRIX_DIM all of them. Fewer than `arity`, or a MATRIX_DIM with 0 or more than 3, appends `Line <keyword line>: <keyword> has <k> of its <m> arguments` (`<m>` = `1 to 3` for MATRIX_DIM; R-A2L-READ.58) and the item carries the words it has, so the caller's field rule finds no value (an ECU_ADDRESS with none gives no address, READ.60; a size keyword gives no number, READ.61). A word after a keyword's arguments that is neither a keyword nor an argument is dropped (base: a line not starting with a keyword was ignored; E3C: 0 such words on the 35 tracked files). **Round 2 (E3S-24):** when such a word is a number word after an ECU_ADDRESS, DATA_SIZE, LENGTH, NUMBER, ARRAY_SIZE or BIT_MASK keyword (a *surplus number word*), the item carries it too and .58's error is appended with `<k>` = its argument and surplus number words, so the keyword gives no number and the field rule finds no value; any other surplus word is still dropped silently (`3E00` in `ECU_ADDRESS 0x1C2D 3E00` is no number word: open, `../01-requirements.md` READ.58). **E3A-23:** the duplicate, address, size and number-word checks of `extract_a2l_tags` run on these items inside this one keyword pass, not as a second pass over the texts (READ.52's margin was 0.12 at round 2).
module: s19_app/tui/a2l.py
examples: (R-A2L-READ.29/1, RP-B5) `ECU_ADDRESS` (line 23) ↵ `0x1234` (line 24) → `[("ECU_ADDRESS 0x1234", 23)]` (base: no address, C [RP-B5])
examples: (R-A2L-READ.29/2, RP-B6) `ECU_ADDRESS` ↵ `/* moved */` ↵ `0x1234` → `[("ECU_ADDRESS 0x1234", 23)]`
examples: (R-A2L-READ.29/3, Inc 2 N) `BIT_MASK` ↵ `0x0FF0` ↵ `ECU_ADDRESS 0x10` → `[("BIT_MASK 0x0FF0", …), ("ECU_ADDRESS 0x10", …)]`
examples: (R-A2L-READ.29/4) `ECU_ADDRESS 0x10` ↵ `MATRIX_DIM 2` ↵ `3` → `[("ECU_ADDRESS 0x10", …), ("MATRIX_DIM 2 3", …)]`
examples: (R-A2L-READ.30/1, RP-B12) `ECU_ADDRESS 0x1234 BYTE_ORDER MSB_LAST` → `[("ECU_ADDRESS 0x1234", 23), ("BYTE_ORDER MSB_LAST", 23)]` (base: byte order big, C [RP-B12])
examples: (R-A2L-READ.30/2, Inc 2 J3) `/begin IF_DATA ETK KP_BLOB 0x10 /end IF_DATA BIT_MASK 0x0FF0` → `[…, ("BIT_MASK 0x0FF0", …)]`
examples: (R-A2L-READ.30/3, [K5]) XK5's words after its header → `[("ECU_ADDRESS 0x18", 1), ("ECU_ADDRESS_EXTENSION 3", 1), ("READ_WRITE", 1)]`
examples: (R-A2L-READ.33/2, RP-A29) `DISPLAY_IDENTIFIER XM_disp /* shown name */` → `("DISPLAY_IDENTIFIER XM_disp", …)`
examples: (R-A2L-READ.37/2, RP-B26) `MATRIX_DIM 2 2` → `("MATRIX_DIM 2 2", …)`
examples: (R-A2L-READ.31/3) a CURVE whose AXIS_DESCR holds `BYTE_ORDER MSB_LAST` → no `BYTE_ORDER` item (the axis words are the child's)
examples: (R-A2L-READ.29/5, R-A2L-READ.58/1, E3S [B8]) `BYTE_ORDER` (line 23) ↵ `BIT_MASK 0x0FF0` (line 24) → `[("BYTE_ORDER", 23), ("BIT_MASK 0x0FF0", 24)]`; errors `Line 23: BYTE_ORDER has 0 of its 1 arguments` (E2 design: `("BYTE_ORDER BIT_MASK", 23)` and `0x0FF0` dropped, E3S-02)
examples: (R-A2L-READ.29/6, R-A2L-READ.58/1, [B9]) `ECU_ADDRESS_EXTENSION` (line 22) ↵ `ECU_ADDRESS 0x1234` → `[("ECU_ADDRESS_EXTENSION", 22), ("ECU_ADDRESS 0x1234", 23)]`; errors `Line 22: ECU_ADDRESS_EXTENSION has 0 of its 1 arguments`
examples: (R-A2L-READ.58/2) `MAX_REFRESH 1` ↵ `ECU_ADDRESS 0x10` → `("MAX_REFRESH 1", …)`, `("ECU_ADDRESS 0x10", …)`; errors `… MAX_REFRESH has 1 of its 2 arguments`
examples: (R-A2L-READ.58/3) `MATRIX_DIM 2 3 4 5` → `("MATRIX_DIM 2 3 4 5", …)`; errors `… MATRIX_DIM has 4 of its 1 to 3 arguments`; `MATRIX_DIM` ↵ `ECU_ADDRESS 0x10` → `("MATRIX_DIM", …)`; `… MATRIX_DIM has 0 of its 1 to 3 arguments`
examples: (R-A2L-READ.63/4, E3S [B10]) `MATRIX_DIM x4` → `("MATRIX_DIM x4", …)` (one argument word; `extract_a2l_tags` gives .63's error and no length)
examples: (holds as quoted, R-A2L-READ.29) `PHYS_UNIT "LENGTH"` → `("PHYS_UNIT \"LENGTH\"", …)`: a quoted word is never a keyword
examples: (R-A2L-READ.58/5, R-A2L-READ.60/8, R-A2L-READ.61/7, E3S-24) `ECU_ADDRESS 0x1C2D 0x3E00`, `LENGTH 2 4`, `BIT_MASK 0x0FF0 0x00FF` on line 22 → `("ECU_ADDRESS 0x1C2D 0x3E00", 22)`, `("LENGTH 2 4", 22)`, `("BIT_MASK 0x0FF0 0x00FF", 22)`; errors `Line 22: ECU_ADDRESS has 2 of its 1 arguments`, `… LENGTH has 2 of its 1 arguments`, `… BIT_MASK has 2 of its 1 arguments` (round 1: the surplus word dropped, address `0x1C2D`, length `2`, 0 errors)
examples: (R-A2L-READ.60/6, E3S-21) `BYTE_ORDER` ↵ `LENGTH 2` → `("BYTE_ORDER", …)`, `("LENGTH 2", …)`; `… BYTE_ORDER has 0 of its 1 arguments` (`extract_a2l_tags` then gives no address)

_number_word
req: R-A2L-READ.3, R-A2L-READ.34, R-A2L-READ.35, R-A2L-READ.36
in: str word
out: Optional[int] value
func: new. `0x` or `0X` followed by 1 to 16 ASCII hex digits → that value; 1 to 20 ASCII decimal digits → that value in base 10, leading zeros included; any other word (a sign, `_`, `0b`/`0o`, a non-ASCII digit, a longer run, a quoted word) → `None`. Replaces `int(x, 0)` for every address, length and count word of a tag or span. The test is `re.fullmatch(r"0[xX][0-9A-Fa-f]{1,16}|[0-9]{1,20}", word)` before `int` (ASCII classes only, never `\d` or `isdigit()`, E3S-06 [M2]).
module: s19_app/tui/a2l.py
examples: (R-A2L-READ.34/1) `0x1234`, `0X1234`, `0x0000000000001234` → `4660` each
examples: (R-A2L-READ.35/1, /2) `010` → `10` (base `int("010", 0)` raises, so no address, C [RP-B32]); `4096` → `4096`
examples: (R-A2L-READ.36/1) `0x12_34` → `None`; `0x1C2D3E00_4026` → `None` (base `int(x, 0)` = `0x1C2D3E004026`, C [H2e])
examples: (R-A2L-READ.36/2, /3) `-0x10`, `+16`, `１２` (fullwidth), `0b101` → `None` each
examples: (R-A2L-READ.3/1) `0x1234<U+00A0>` → `None`
examples: (R-A2L-READ.38, H3) `99999999999` (11 digits) → `99999999999` (a number; the cap removes it)

_bounded_length
req: R-A2L-READ.38, R-A2L-READ.46
in: Optional[int] length
out: Optional[int] length
func: new. `length` when it is an int from 1 to `MAX_A2L_DECODE_BYTES` (`1048576`, `a2l.py:62`), else `None`. The caller records R-A2L-READ.39's error for a tag.
module: s19_app/tui/a2l.py
examples: (R-A2L-READ.38/3) `1048576` → `1048576`
examples: (R-A2L-READ.38/1, /2) `0`, `1048577`, `99999999999`, `1000000000000` → `None` each
examples: (R-A2L-READ.46/2) `2 × 4294967296` → `None`

_tag_sizes
req: R-A2L-013, R-A2L-READ.57, R-A2L-READ.59, R-A2L-READ.61
in: list[tuple[str, int]] keyword_lines; Optional[int] element_size; str? kind = None; Optional[int] span = None
out: tuple(bool agree, Optional[int] smallest, Optional[int] largest, bool no_number)
func: new (E3 correction; DE-8; CTX *sizes*; regrouped at round 2, E3S-19, E3S-23). From the `_tag_keyword_lines` items, two groups: **byte sizes**, the number after each DATA_SIZE and LENGTH (as written); **counts**, the number after each NUMBER and ARRAY_SIZE and the MATRIX_DIM product when a MATRIX_DIM stands, or the one count 1 when a DATA_SIZE or LENGTH stands and none of those does. The byte sizes are compared with each other and the counts with each other, always; with `element_size` known, each count × `element_size` is compared with the byte sizes as well, and `smallest`/`largest` are in bytes. For `kind` in CURVE, MAP, CUBOID, CUBE_4 and CUBE_5, the counts take no part, and the byte sizes are compared with `span` (the layout span the caller computes) when it is known. `agree` = every compared pair equal, or nothing to compare; `smallest` and `largest` feed .59's text; `no_number` = a size keyword *gives no number* (CTX). `element_size` is the caller's: `DATATYPE_SIZES[datatype]` for a MEASUREMENT, the size of the record layout's FNC_VALUES datatype or of the deposit name for a CHARACTERISTIC (CTX *datatype (CHARACTERISTIC)*), `None` when unknown.
module: s19_app/tui/a2l.py
examples: (R-A2L-READ.59/2, R-A2L-READ.61/1, E3S [B5]) `["DATA_SIZE 2", "LENGTH 8"]`, `2` → (`False`, `2`, `8`, `False`)
examples: (R-A2L-READ.59/2, [B6]) a VALUE's `["LENGTH 4"]`, `2` → (`False`, `2`, `4`, `False`)
examples: (R-A2L-READ.59/2) a VAL_BLK's `["MATRIX_DIM 4", "NUMBER 5"]`, `2` → (`False`, `8`, `10`, `False`); an ASCII's `["NUMBER 8", "MATRIX_DIM 4"]`, `1` → (`False`, `4`, `8`, `False`)
examples: (R-A2L-READ.59/3) `["MATRIX_DIM 4", "NUMBER 5"]`, `None` → (`False`, `4`, `5`, `False`) (elements)
examples: (R-A2L-READ.61/3, R-A2L-013/2) `["MATRIX_DIM 2", "LENGTH 4"]`, `2` → (`True`, `4`, `4`, `False`); `["ARRAY_SIZE 4", "MATRIX_DIM 4"]`, `2` → (`True`, `8`, `8`, `False`)
examples: (R-A2L-READ.61/2) `["MATRIX_DIM x4"]` → `no_number` `True`; `["LENGTH"]` (no argument) → `True`; `["MATRIX_DIM 2 3 4 5"]` → `True`
examples: (holds on the tracked files, E3C) every tracked tag → `agree` `True`, `no_number` `False`
examples: (R-A2L-READ.59/6, R-A2L-READ.61/6, E3S-19) `["DATA_SIZE 2", "LENGTH 8"]`, `None` → (`False`, `2`, `8`, `False`) (round 1: DATA_SIZE and LENGTH left out, `agree` `True`, the reader picked one); `["LENGTH 4", "LENGTH 8"]`, `None` → (`False`, `4`, `8`, `False`)
examples: (R-A2L-READ.59/7, R-A2L-READ.61/8, E3S-23) `["LENGTH 2264"]`, `2`, `MAP`, `2266` → (`False`, `2264`, `2266`, `False`); `["LENGTH 2266"]`, `2`, `MAP`, `2266` → (`True`, `2266`, `2266`, `False`) (round 1: compared with 2 × MATRIX_DIM 1 → `False`, 2 and 2266); a MAP's `["MATRIX_DIM 4", "NUMBER 5"]` → `agree` `True` (counts take no part)
examples: (CTX *sizes*, the one count 1) an ASCII's `["NUMBER 8", "LENGTH 8"]`, `1` → (`True`, `8`, `8`, `False`); [B6]'s `["LENGTH 4"]`, `2` → (`False`, `2`, `4`, `False`) as round 1
examples: (R-A2L-READ.61/7, E3S-24) `["LENGTH 2 4"]` → `no_number` `True`

_echo_word
req: R-A2L-READ.66
in: str word
out: str text
func: new (E3S-07; DE-10). The word's first 64 characters, each character outside U+0021 … U+007E replaced by U+FFFD, then `…` when the word had more than 64. Every `<file>`, `<name>`, `<keyword>` and `<word>` slot of an error text goes through it (R-A2L-001.5, READ.22, .28, .32, .39, .58, .59, .63, .67), so no error text holds a line end, an ESC or more than 64 characters of one file word.
module: s19_app/tui/a2l.py
examples: (R-A2L-READ.66/1) a 1,000,000-character word holding LF and ESC → its first 64 characters with U+FFFD for each LF and ESC, then `…` (65 characters; base: no base text echoes a word, E3S-07 [M4] gave 1,000,029 under the E2 design)
examples: (R-A2L-READ.66/2) a 64-character name → itself; a 65-character name → its first 64 characters and `…`
examples: (R-A2L-READ.66/3) `<ESC>X` → `<U+FFFD>X`
examples: (R-A2L-READ.63/1) `１２` → `<U+FFFD><U+FFFD>`

_CappedErrors
req: R-A2L-READ.56, R-A2L-READ.65
in: int cap = 100
out: list[str] errors
func: new (E3A-02 (b); DE-10). A small class, not a `list` subclass (round 2, E3A-19): `append`, `reset` and `as_list()` are its only methods, so an `extend`, `+=` or `insert` that E4 might write raises instead of passing the cap silently. `append` keeps the first 100 texts and only counts the rest in `dropped`; `reset(text)` empties it and keeps the one text (READ.55, .64); `as_list()` gives a plain list of the texts and, when `dropped` > 0, the one text `… <dropped> more parse errors` after them. `parse_a2l_file` creates it, passes it to `_build_section_tree_into` and then to `extract_a2l_tags(…, errors=…)`, and puts `as_list()` in the payload; the public `build_section_tree` creates its own and returns its `as_list()` (round 2), so every consumer of `errors` (R-A2L-004.2, `validation/rules.py:492-500`, `render_a2l_view`, the log of `app.py:19154-19156`) sees at most 101 entries with no change of its own, and no list grows past 100 texts even on a binary file.
module: s19_app/tui/a2l.py
examples: (R-A2L-READ.56/1) 100 appends → `as_list()` of 100 texts; 101 appends → the first 100 and `… 1 more parse errors`
examples: (R-A2L-READ.56/3, E3S [H10]) 200,000 appends → 101 entries, the last `… 199900 more parse errors`; memory for 100 texts and one int (base: 200,000 errors, 200,000 issues, a 6.9 MB summary)
examples: (R-A2L-READ.56/4, E3A-19) `errors.extend(["x"])`, `errors += ["x"]`, `errors.insert(0, "x")` → each raises (`AttributeError` or `TypeError`); round 1's `list` subclass took all three past the cap silently

parse_measurement_header
req: R-A2L-READ.25, R-A2L-READ.27
in: str line
out: Optional[dict] header
func: changed (DE-7). was: `None` unless the line splits into 6 or more words whose first is not in `MEASUREMENT_BODY_KEYWORDS`; then the first 6 by position. / now: the words of `line` by position up to the first keyword of `_TAG_KEYWORD_ARITY`, at most 6 (`datatype`, `conversion`, `resolution`, `accuracy`, `lower_limit`, `upper_limit`; a missing one `None`; `address_inline` `None`); `None` when there is no word before a keyword. `extract_a2l_tags` passes `" ".join(header)`.
module: s19_app/tui/a2l.py
examples: (R-A2L-READ.25) `"UWORD CM_ID 0 0 0 65535"` → datatype `UWORD`, upper limit `65535`
examples: (R-A2L-READ.27/2) `"UWORD CM_ID 0 0 0"` → datatype `UWORD`, lower limit `0`, upper limit `None` (base: `None`, so datatype None)
examples: (holds on base, `tests/test_a2l_enriched.py:159-160`) `"ECU_ADDRESS 0x1000"` → `None`

_characteristic_from_tokens
req: R-A2L-READ.26, R-A2L-READ.36
in: list[str] tokens
out: Optional[dict] header
func: changed. was: anchor on the first `CHARACTERISTIC_KINDS` token (else `_extended_kind_anchor`), 7 params, address `int(params[1], 0)` (`ValueError` → `None`). / now: the same, with the address `_number_word(params[1])`. `extract_a2l_tags` passes only the header words, so a body keyword is never a candidate.
module: s19_app/tui/a2l.py
examples: (R-A2L-READ.7/1, H2a) the header `["MAP", "0x1C2D3E00", "4026", …]` → `address_inline` `472727040` (`0x1C2D3E00`) (base: `0x1C2D3E004026`, C [H2a])
examples: (R-A2L-READ.36, H2e) `["MAP", "0x1C2D3E00_4026", "RL", "0", "CM", "0", "1"]` → `address_inline` `None`
examples: (holds on base, TC-099) `["VALUE", "0x10", "RL"]` → `None`; `["desc", "CURVE", "0x20", "RL", "0", "CM", "0", "255"]` → kind `CURVE`, address `32`

_extended_kind_anchor
req: R-A2L-READ.26, R-A2L-READ.36
in: list[str] tokens
out: Optional[int] anchor
func: changed. was: the first token that is not a kind, not in `MEASUREMENT_BODY_KEYWORDS` and not an `int(x, 0)` number, followed by an `int(x, 0)` number and 6 more tokens. / now: `_number_word` in place of `int(x, 0)`; on header words only (via `_characteristic_from_tokens` from `extract_a2l_tags`).
module: s19_app/tui/a2l.py
examples: (R-A2L-READ.26/5, [K4]) `["CUBE_5", "0x123", "RL_U16", "1", "CM_ID", "0", "10"]` → `0` (kind `CUBE_5`, address `0x123`)
examples: (the base, [K3]) on the body tokens `["ECU_ADDRESS_EXTENSION", "0", "BYTE_ORDER", "MSB_LAST", "PHYS_UNIT", "ms", "STEP_SIZE", "1"]` → `0`, which is the base defect (K); after Inc 11 these tokens never reach it

_memory_segment_record_words
req: R-A2L-READ.2, R-A2L-READ.7, R-A2L-001.2
in: dict sec
out: tuple(list[tuple[str, int, bool]] words, list[str] texts)
func: changed. was: its own scan of `meta` and each line: a comment removed with no word break, words at `isspace`, the quote state reset per text. / now: `texts` = `[meta, *lines]` (canonical, already without comments); `words` = `_line_words` of each text, quoted words without their quotes and flagged. R-A2L-036.1 … .6 hold as base.
module: s19_app/tui/a2l.py
examples: (holds on base, R-A2L-036) V161 `ECU_Code` → usage `DATA`, kind `FLASH`, base `0x16000`, size `0x86C` (`tests/test_a2l_enriched.py` QUOTED_DEMO_EXPECTATIONS)
examples: (R-A2L-READ.7) `/begin MEMORY_SEGMENT S "" DATA FLASH INTERN 0x1000/*c*/0x200 -1` → base `4096`, size `512` (base, R `a2l.py:1028-1031`: one word `0x10000x200`, so no base)

_infer_length_measurement
req: R-A2L-READ.37, R-A2L-READ.36, R-A2L-013, R-A2L-014, R-A2L-READ.57, R-A2L-READ.61
in: list[str] lines; Optional[dict] header
out: Optional[int] length
func: changed. was: `DATA_SIZE` and `MATRIX_DIM` by `int(parts[1], 0)` per line; the first MATRIX_DIM number; DATA_SIZE × MATRIX_DIM when both stand; ARRAY_SIZE ignored. / now: `lines` are `_tag_keyword_lines` texts; numbers by `_number_word`; MATRIX_DIM = the product of its numbers (1 when absent); a DATA_SIZE or LENGTH → that number (R-A2L-013); else an ARRAY_SIZE → the datatype's size × its number (R-A2L-READ.57, E3A-04); else the datatype's size × MATRIX_DIM (R-A2L-014). The caller gives `None` instead when `_tag_sizes` says the sizes disagree or a size keyword gives no number (DE-6, DE-8; R-A2L-READ.61). The cap is the caller's.
module: s19_app/tui/a2l.py
examples: (R-A2L-READ.37/2) `["ECU_ADDRESS 0x1234", "MATRIX_DIM 2 2"]`, datatype `UWORD` → `8` (base `4`, C [RP-B26])
examples: (R-A2L-READ.37/1) V161 `ASAM.M.MATRIX_DIM_8_4_2.UBYTE.IDENTICAL` → `64` (base `8`)
examples: (R-A2L-READ.29/4) `["MATRIX_DIM 2 3"]`, UWORD → `12`
examples: (holds on base) `[]`, datatype `SWORD` → `2`
examples: (R-A2L-READ.57/1, E3A-04) V161 `ASAM.M.ARRAY_SIZE_16.UBYTE.IDENTICAL` `["ECU_ADDRESS …", "ARRAY_SIZE 16"]`, UBYTE → `16` (base `1`)
examples: (R-A2L-READ.57/2) `["ECU_ADDRESS 0x10", "ARRAY_SIZE 4"]`, UWORD → `8`
examples: (R-A2L-013/2) `["ECU_ADDRESS 0x10", "MATRIX_DIM 2", "LENGTH 4"]`, UWORD → `4` (holds on base, where the walk reads LENGTH, R `a2l.py:2669-2673`)

_infer_length_characteristic
req: R-A2L-READ.37, R-A2L-READ.36, R-A2L-READ.38, R-A2L-013, R-A2L-015, R-A2L-016, R-A2L-017, R-A2L-READ.53, R-A2L-READ.61
in: list[str] lines; Optional[dict] header; Optional[dict[str, dict]] record_layouts_by_name = None
out: Optional[int] length
func: changed. was: `LENGTH`, `MATRIX_DIM`, `NUMBER` by `int(parts[1], 0)`; the first MATRIX_DIM number. / now: `_tag_keyword_lines` texts; numbers by `_number_word`; MATRIX_DIM = the product; an unreadable LENGTH or NUMBER word → `None` (DE-6). E1 addendum: the layout's datatype (CTX *datatype (CHARACTERISTIC)*) is resolved for VAL_BLK as for VALUE (CG-2, R-A2L-016); a VAL_BLK with a NUMBER and no MATRIX_DIM → the datatype's size × NUMBER (CG-3, R-A2L-READ.53); a VAL_BLK with neither → `None`, as base. E3 correction: an ASCII → the number after NUMBER, else its MATRIX_DIM (R-A2L-017 changed in place, the E2 ruling; [K6c]); the caller gives `None` instead when `_tag_sizes` says the sizes disagree or a size keyword gives no number (R-A2L-READ.61).
module: s19_app/tui/a2l.py
examples: (R-A2L-READ.37/1) V161 `ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR` (`MATRIX_DIM 3 4 1`, layout `RL.FNC.SWORD.ROW_DIR`) → `24` with R-A2L-016 (base `None`: the layout's name carries no size, `../01-requirements.md` source A)
examples: (R-A2L-READ.38/2, H1) ASCII with `["NUMBER 1000000000000"]` → `1000000000000` (the caller caps it)
examples: (holds on base, `tests/test_a2l_record_layout_length.py:53`) `[]`, VALUE on `_RL_U16` → `2`
examples: (R-A2L-016/1, [K6]) `["MATRIX_DIM 4"]`, VAL_BLK on `RL_U16` (FNC_VALUES UWORD) → `8` (base `None`, K)
examples: (R-A2L-016/2) V161 `ASAM.C.ARRAY.SWORD.MATRIX_DIM_6.ROW_DIR` (`MATRIX_DIM 6 1 1`, layout `RL.FNC.SWORD.ROW_DIR`) → `12` (base `None`, source A)
examples: (R-A2L-READ.53/1, [K6b]) `["NUMBER 4"]`, VAL_BLK on `RL_U16`, no MATRIX_DIM → `8` (base `None`, K)
examples: (R-A2L-017/1, [K6c]) `["MATRIX_DIM 8"]`, ASCII on `RL_U8`, no NUMBER → `8` (base `None`, K)
examples: (R-A2L-017/2, holds on base) `["NUMBER 8"]`, ASCII → `8`

extract_a2l_tags
req: R-A2L-005.1, R-A2L-005.2, R-A2L-001.2, R-A2L-READ.4, R-A2L-READ.7, R-A2L-READ.12, R-A2L-READ.23, R-A2L-READ.28, R-A2L-READ.30, R-A2L-READ.32, R-A2L-READ.33, R-A2L-READ.36, R-A2L-READ.38, R-A2L-READ.39, R-A2L-013, R-A2L-READ.59, R-A2L-READ.60, R-A2L-READ.61, R-A2L-READ.62, R-A2L-READ.63, R-A2L-READ.66, R-A2L-READ.67
in: list[dict] sections; dict[str, dict]? record_layouts_by_name = None; dict[str, dict]? compu_methods_by_name = None; list[str]? errors = None
out: list[dict] tags
func: changed (DE-4, DE-6, DE-7; I-11.3, I-11.5). was: name and long identifier from `parse_begin_meta(meta)`; the MEASUREMENT header from `_first_header_line` (the first line with 6 words), the CHARACTERISTIC header from `assemble_characteristic_header(lines)`; the field loop over raw `lines` keyed on each line's first word with `int(x, 0)`; the last line wins; no error. / now: per MEASUREMENT or CHARACTERISTIC section, `words = _section_words(section)`; `(name, long id, header, rest) = _tag_header(…)`; the MEASUREMENT header via `parse_measurement_header(" ".join(header))`, the CHARACTERISTIC header via `_characteristic_from_tokens(header)` when it has 7 words; a header of 1 to 5 (MEASUREMENT) or 1 to 6 (CHARACTERISTIC) words appends `Line <start_line>: <section> <name> has <k> of its <m> header words`; the base field loop runs over `_tag_keyword_lines(words, rest)` (`parts = text.split(" ")`, as base on canonical text), with `_number_word` for ECU_ADDRESS, DATA_SIZE and LENGTH, the MATRIX_DIM product, DISPLAY_IDENTIFIER = its one argument; the second and every later occurrence of a keyword appends `Line <its line>: <keyword> is declared twice in <section> <name>`. **D-6 revised at E3 (DE-8, E3S-03; "the last wins" is gone):** the address is `None` when the address words (the header address and every ECU_ADDRESS argument) give two different addresses, when an ECU_ADDRESS gives no number (missing argument, or not a number word: never the header address, [B3b]), or when a BIT_MASK or BYTE_ORDER stands twice with different arguments (R-A2L-READ.60); the length is `None` when `_tag_sizes` says the sizes disagree or a size keyword gives no number (R-A2L-READ.61); either disagreement appends `Line <start_line>: <section> <name> declares the <sizes|addresses> <a> and <b>` (R-A2L-READ.59; addresses as `0x%08X`); agreeing duplicates keep their value. An argument of ECU_ADDRESS, DATA_SIZE, LENGTH, NUMBER, MATRIX_DIM or ARRAY_SIZE, or a CHARACTERISTIC's header address word, that is not a number word appends `Line <its line>: <keyword or "address"> <word> is not a number` (R-A2L-READ.63). A CHARACTERISTIC with 1 to 6 header words takes no field from them (R-A2L-READ.62, DE-7). A quoted name word holding a character outside U+0021 … U+007E appends .4's `Line <n>: unexpected character U+<XXXX>` (E3S-10). A MEASUREMENT or CHARACTERISTIC section with no `end_line` gives no tag and appends `Line <start_line>: <section> <name> is not closed` (R-A2L-READ.12, .67; E3S-09). Every file word in these texts goes through `_echo_word` (R-A2L-READ.66). The final length (inline, inferred, layout span, and the external-axis post-pass) through `_bounded_length`, a tag length outside 1 … 1048576 appending `Line <start_line>: <section> <name> has the length <length>, outside 1 to 1048576 bytes`. Errors go to `errors` when it is given (a list or `parse_a2l_file`'s `_CappedErrors`; only `append` is called). AXIS_DESCR capture, link maps, byte-order fallbacks, memory region and the post-pass as base. **Round 2.** No address also when one address word is no number word — a CHARACTERISTIC's header address included, so `0x20_00` with `ECU_ADDRESS 0x3000` is never `0x3000` (E3S-22) — when a BIT_MASK or BYTE_ORDER has fewer argument words than its arity (E3S-21), and when ECU_ADDRESS or BIT_MASK has a surplus number word (E3S-24). `_tag_sizes` gets the kind and, for the CURVE/MAP family, the layout span the base step computes (E3S-23). A tag whose length READ.38 or .61 refused is marked in the walk (a local set: no new tag key, I-11.3 holds), and the inline-axis step, the layout-span step and the external-axis post-pass skip it, so the refusal is final.
module: s19_app/tui/a2l.py
modify: errors (append)
examples: (R-A2L-001.2/1, RP-B7) X with `ECU_ADDRESS 0x1234`, then `ECU_ADDRESS 0x9999` inside `/* … */` → address `4660` (base `0x9999`, C [RP-B7])
examples: (R-A2L-001.2/2, /3, RP-B37, RP-B27) → byte order `little`; MATRIX_DIM `4`, length `8`
examples: (R-A2L-001.2/4, Inc 2 M) `/* BIT_MASK 0x0FF0 */` → `bit_org` `None`
examples: (R-A2L-001.2/5) `ECU_ADDRESS 0x10`, `LENGTH 4`, `/*`, `LENGTH 2`, `*/` → length `4`
examples: (R-A2L-001.2/6, /7, RP-B8, RP-B9) → address `4660`
examples: (R-A2L-001.2/8) MOD_COMMON `/*` ↵ `BYTE_ORDER MSB_LAST` ↵ `*/` ↵ `BYTE_ORDER MSB_FIRST`, `MEAS(X, " ECU_ADDRESS 0x10")` → X `effective_byte_order` `big`
examples: (R-A2L-READ.7/1, H2a) SYNMAP-like CHARACTERISTIC `MAP 0x1C2D3E00/*c*/4026 …` → address `0x1C2D3E00`, never `0x1C2D3E004026`
examples: (R-A2L-READ.7/3 … /6, RP-B1, RP-B4, Inc 2 G, F) → address `4660`, `4660`; `bit_org` `0x0FF0`; upper limit `65535` and `bit_org` `0x0FF0`
examples: (R-A2L-READ.12/1, AT-B103-I11-2) RP-B28 → exactly `1` tag `X`, address `4660` (base: 2 tags, the first `0x9999`, C [RP-B28])
examples: (R-A2L-READ.23/4) V161 and V171 → a CHARACTERISTIC `ASAM.C.ASCII.UBYTE.NUMBER_42` at `0x810200` each; `0` tags `UNKNOWN`
examples: (R-A2L-READ.23/5, [K1]) the two one-word-per-line MEASUREMENTs → `XK1` at `0x1234` and `XK1B` at `0x1236`, datatype `UWORD`, length `2`, description `long id`; no `A2L_DUPLICATE_SYMBOL` (base: both `UNKNOWN`, one duplicate issue, K)
examples: (R-A2L-READ.26/4, [K3]) → `CK3` kind `VALUE`, address `0x1000`, deposit `RL_U16`, length `2`, byte order `little` (base: kind `ECU_ADDRESS_EXTENSION`, address `0x0`, K)
examples: (R-A2L-READ.26/5, [K4]) → `CK4` kind `CUBE_5`, address `0x123`, deposit `RL_U16` (base: kind `NUMBER`, address `0x2710`, K)
examples: (R-A2L-READ.30/3, R-A2L-READ.25/6, [K5]) → `XK5` address `0x18`, datatype `FLOAT64_IEEE`, length `8`; errors `[]` (base: address None, `Unclosed …`, K)
examples: (R-A2L-001.2/9, [K5b]) `/* moved */ ECU_ADDRESS 0x1234` → address `0x1234` (base: None, K)
examples: (R-A2L-READ.25/1) BalanceTube → 104/104 MEASUREMENTs with datatype and length (`model.MainClass.gameController.sm` `UBYTE`, `1`)
examples: (R-A2L-READ.25/2) V161 and V171 `ASAM.M.VIRTUAL.SCALAR.SWORD.PHYSICAL` → datatype `SWORD`, length `2`, conversion `CM.VIRTUAL.EXTERNAL_VALUE`
examples: (R-A2L-READ.26/1, RP-B23) → address `0x2000`, kind `VALUE`, deposit `RL_U16`
examples: (R-A2L-READ.27/1) case_07 → 12/12 tags with their e07fb00 address, length, limits and unit
examples: (R-A2L-READ.27/3) `/begin CHARACTERISTIC Q` ↵ `ECU_ADDRESS 0x10` ↵ `LENGTH 2` → address `16`, length `2`, no error
examples: (R-A2L-READ.28/1, Inc 2 C, `/begin` on line 20) → `Line 20: MEASUREMENT SX has 5 of its 6 header words`; datatype `UWORD`, `bit_org` `0x0FF0`, upper limit `None`
examples: (R-A2L-READ.28/4, [K7]) `/begin MEASUREMENT XK7 "" UWORD CM_ID 0 0` on line 20 → `Line 20: MEASUREMENT XK7 has 4 of its 6 header words`; datatype `UWORD`, length `2` (base: datatype None, no error, K)
examples: (R-A2L-READ.28/2, H3c, `/begin` on line 20) → `Line 20: CHARACTERISTIC Synthetic map has 6 of its 7 header words`; address `None`, kind `None` (DE-7, R-A2L-READ.62)
examples: (R-A2L-READ.28/3, R-A2L-READ.32/4) the 35 tracked files → `0` such errors
examples: (R-A2L-READ.32/1, R-A2L-READ.59/1, R-A2L-READ.60/1) `ECU_ADDRESS 0x10` line 22, `ECU_ADDRESS 0x20` line 23, `/begin` on line 20 → `Line 23: ECU_ADDRESS is declared twice in MEASUREMENT X`, `Line 20: MEASUREMENT X declares the addresses 0x00000010 and 0x00000020`; address `None` (the E2 design: `32`, the last; E3S-03 [B4])
examples: (R-A2L-READ.32/2, /3, R-A2L-READ.60/3, Inc 2 P) → `Line <n>: BYTE_ORDER is declared twice in MEASUREMENT X`; `Line <n>: BIT_MASK is declared twice in MEASUREMENT SX`; address `None` each (their arguments differ)
examples: (R-A2L-READ.60/4) two `ECU_ADDRESS 0x10` → address `16` and .32's error only; two `BIT_MASK 0x0FF0` → address kept, `bit_org` `0x0FF0`
examples: (R-A2L-READ.59/1, R-A2L-READ.60/1, E3S [B3]) `/begin CHARACTERISTIC XD "" VALUE 0x2000 RL_U16 0 CM_ID 0 65535` (line 20) ↵ `ECU_ADDRESS 0x3000` → address `None`; `Line 20: CHARACTERISTIC XD declares the addresses 0x00002000 and 0x00003000` (base: `0x3000`, silently)
examples: (R-A2L-READ.60/1, [B3b]) the same with `ECU_ADDRESS 0x30_00` → address `None` (never `0x2000`); `Line 21: ECU_ADDRESS 0x30_00 is not a number`
examples: (R-A2L-READ.60/2) `ECU_ADDRESS` ↵ `BIT_MASK 0x0FF0` → address `None`, `bit_org` `0x0FF0`; .58's error from `_tag_keyword_lines`
examples: (R-A2L-READ.59/2, R-A2L-READ.61/1, [B5], [B6]) UWORD `DATA_SIZE 2` + `LENGTH 8` → length `None`, `… declares the sizes 2 and 8`; VALUE on `RL_U16` + `LENGTH 4` → length `None`, `… declares the sizes 2 and 4` (base: `8` and `4`, E3S-03)
examples: (R-A2L-READ.61/3) UWORD `ARRAY_SIZE 4` + `MATRIX_DIM 4` → `8`; UWORD `MATRIX_DIM 2` + `LENGTH 4` → `4`; no `declares` error
examples: (R-A2L-READ.61/2, R-A2L-READ.63/4, [B10]) `MATRIX_DIM x4` → length `None`; `Line <n>: MATRIX_DIM x4 is not a number` (base: matrix 1, length 2, E3S-08)
examples: (R-A2L-READ.63/1) `ECU_ADDRESS 0x12_34` on line 22 → address `None`; `Line 22: ECU_ADDRESS 0x12_34 is not a number`
examples: (R-A2L-READ.62/1, R-A2L-READ.28/2, H3c) a 6-word CHARACTERISTIC header → address `None`, `char_type` `None`, deposit `None`; .28's error
examples: (R-A2L-READ.4/6, E3S-10) `/begin MEASUREMENT "Torque<ESC>Max" ""` on line 20 → `Line 20: unexpected character U+001B`
examples: (R-A2L-READ.12/4, R-A2L-READ.67/1, E3S [B13]) a MEASUREMENT X cut after `ECU_ADDRESS 0x12` (no `end_line`), `/begin` on line 20 → no tag; `Line 20: MEASUREMENT X is not closed` (base: a tag at `0x12`)
examples: (R-A2L-READ.66/2) a 65-character name in .28's error → its first 64 characters and `…`
examples: (R-A2L-READ.33/1) V161/V171 `ASAM.M.SCALAR.UBYTE.IDENTICAL` → `display_identifier` `DI.ASAM.M.SCALAR.UBYTE.IDENTICAL` (base: with `/* optional display identifier */`, C [FX-other]); 6/6
examples: (R-A2L-READ.33/2, RP-A29) → `XM_disp`
examples: (R-A2L-READ.36/1, RP-B33) `ECU_ADDRESS 0x12_34` → address `None`
examples: (R-A2L-READ.38/1, /2, R-A2L-READ.39/1, `/begin` on line 20) `LENGTH 0` → length `None`, `Line 20: MEASUREMENT X has the length 0, outside 1 to 1048576 bytes`; `LENGTH 1048577` → `… 1048577 …`; `LENGTH 99999999999` → `… 99999999999 …`; ASCII `NUMBER 1000000000000` → `Line 20: CHARACTERISTIC SX has the length 1000000000000, outside 1 to 1048576 bytes`
examples: (R-A2L-READ.38/1, DE-6) `LENGTH -5` → length `None`, no length error (`-5` is no number word; F-E2-3)
examples: (R-A2L-READ.38/3) `LENGTH 1048576` → `1048576`
examples: (R-A2L-005.2, holds on base) INSTANCE, BLOB and TYPEDEF_* sections → no tag
examples: (I-11.5, holds on base) `errors` not given → the same tags; no error list
examples: (R-A2L-READ.60/6, E3S-21) MEAS(X, `ECU_ADDRESS 0x10`, `BYTE_ORDER`, `LENGTH 2`) and MEAS(X, `ECU_ADDRESS 0x10`, `BIT_MASK`, `BYTE_ORDER MSB_FIRST`) → address `None` each (round 1: `0x10`, with the fallback byte order or the full-width mask)
examples: (R-A2L-READ.60/7, E3S-22) `/begin CHARACTERISTIC XG "" VALUE 0x20_00 RL_U16 0 CM_ID 0 65535` ↵ `ECU_ADDRESS 0x3000` → address `None`; `Line <n>: address 0x20_00 is not a number` (round 1: `0x3000`)
examples: (R-A2L-READ.59/6, R-A2L-READ.61/6, E3S-19, `/begin` on line 20) a MEASUREMENT with no header, `ECU_ADDRESS 0x10`, `DATA_SIZE 2`, `LENGTH 8` → length `None`; `Line 20: MEASUREMENT XN declares the sizes 2 and 8` (round 1: one of 2 or 8, 0 errors)
examples: (R-A2L-READ.61/8, R-A2L-READ.59/7, E3S-23) SYNMAP with `LENGTH 2264` → length `None` and `… declares the sizes 2264 and 2266`; with `LENGTH x4` → `None` (round 1: the CURVE/MAP step then gave the span 2266); with `LENGTH 2266` → `2266`, no error

extract_declared_spans
req: R-A2L-READ.40, R-A2L-READ.41, R-A2L-READ.42, R-A2L-READ.43, R-A2L-READ.44, R-A2L-READ.45, R-A2L-READ.46
in: list[dict] sections; dict[str, dict]? record_layouts_by_name = None
out: list[dict] spans
func: new (D-8 A; I-11.2, I-11.7). Walks every section at any depth in file order. A BLOB → `{"name", "kind": "BLOB", "address", "length"}` from `_tag_header("BLOB", …)`: header word 1 by `_number_word`, header word 2 by `_number_word` then `_bounded_length`. An INSTANCE → its header words (typedef name, address word); its `MATRIX_DIM` product `m` from `_tag_keyword_lines` (1 when absent); the length by the typedef of that name: TYPEDEF_MEASUREMENT → `DATATYPE_SIZES[datatype]` × the typedef's MATRIX_DIM × `m`; TYPEDEF_CHARACTERISTIC of kind VALUE, VAL_BLK or ASCII → `_infer_length_characteristic(<its keyword lines>, {"char_type": kind, "deposit": deposit}, record_layouts_by_name)` × `m`; TYPEDEF_BLOB or TYPEDEF_STRUCTURE → its size word × `m`; any other typedef, a CURVE/MAP typedef, or a name the file does not declare → `None`; every length through `_bounded_length`. No error is recorded for a span.
module: s19_app/tui/a2l.py
examples: (R-A2L-READ.40/1, RP-D1) `/begin BLOB B1 "" 0x10 2` → `[{"name": "B1", "kind": "BLOB", "address": 16, "length": 2}]`
examples: (R-A2L-READ.40/2) the 35 tracked files → `7` BLOB spans (V171 `ASAM.C.BLOB.TRANSFORMER_TEST` at `0x812000`, `16`)
examples: (R-A2L-READ.40/3, RP-D4) a commented-out BLOB → `[]`
examples: (R-A2L-READ.41/1) the 35 tracked files → `82` INSTANCE spans with their address words
examples: (R-A2L-READ.42/1, /2, RP-D2, RP-D3) `I1 "" T_U16 0x10` → (`I1`, `INSTANCE`, `16`, `2`); `I2 "" T_U16 0x20` with `MATRIX_DIM 5` → length `10`
examples: (R-A2L-READ.43/1) V171 `ASAM_I_SCALAR_VALUE_UWORD_SINGLE` → address `0x810000`, length `2`
examples: (R-A2L-READ.43/2, F-E2-5 applied) a VAL_BLK typedef on `RL_U16` with `MATRIX_DIM 3`, INSTANCE `MATRIX_DIM 2` → `12` (R-A2L-016 with the layout's datatype, CG-2)
examples: (R-A2L-READ.43/3) an ASCII typedef `NUMBER 8` → `8`
examples: (R-A2L-READ.44/1, /2) `TYPEDEF_BLOB TB "" 6` → `6`; `TYPEDEF_STRUCTURE TS "" 12`, INSTANCE `MATRIX_DIM 3` → `36`
examples: (R-A2L-READ.45/1 … /3) an INSTANCE of a TYPEDEF_AXIS, of a CURVE TYPEDEF_CHARACTERISTIC, of `T_NONE` → `length` `None` each (tracked: 1 TYPEDEF_AXIS, 2 unknown, C [FX-total])
examples: (R-A2L-READ.46/1, /2) BLOB sizes `0` and `1048577` → `length` `None`; INSTANCE of T_U16 with `MATRIX_DIM 4294967296` → `None`
examples: (R-A2L-READ.41, R-A2L-001.1/4, [K7b]) the two one-line INSTANCEs → `IK7` at `0x20`, `IK7B` at `0x40`, length `2` each

parse_a2l_file
req: R-A2L-READ.6, R-A2L-READ.39, R-A2L-READ.40, R-A2L-READ.48, R-A2L-READ.49, R-A2L-READ.52, R-A2L-READ.55, R-A2L-READ.56, R-A2L-READ.64, R-A2L-READ.65
in: Path path; A2LProgress? progress = None
out: dict payload
func: changed (I-11.2, I-11.6). was: `build_section_tree` → record layouts, compu methods, compu tables → `extract_a2l_tags` → the 7-key payload. / now: the same, with one `_CappedErrors` it creates, filled first by `_build_section_tree_into(path, progress, errors)` (round 2, E3A-19; not the public `build_section_tree`) and then by `extract_a2l_tags(…, errors=errors)`, the payload's `errors` = its `as_list()` (at most 100 texts and one `… <k> more parse errors`, READ.56), and the 8th key `declared_spans` = `extract_declared_spans(sections, record_layouts_by_name)`. A refused file (UTF-16, NUL, nesting past 32) gives `sections` `[]`, so `tags` and `declared_spans` are `[]`. Because no section is deeper than 32 levels, no walker recurses past 32 and the read raises nothing but `OSError` (READ.65; E3S-04).
module: s19_app/tui/a2l.py
examples: (R-A2L-READ.6/1) a UTF-16 LE file → `errors` `["File is UTF-16 encoded; save it as UTF-8 and load it again."]`, `tags` `[]`, `declared_spans` `[]`
examples: (R-A2L-READ.40/1) RP-D1 → `declared_spans` `[{"name": "B1", "kind": "BLOB", "address": 16, "length": 2}]`, `tags` without B1
examples: (R-A2L-READ.48/1) the 35 tracked files → tags, spans and errors equal to `ref_read_a2l` on the compared fields, `0` differences, within `120` s on <runner>
examples: (R-A2L-READ.49/1) the 35 tracked files → 234,427 tags identical to `[I/O: e07fb00 tag fixture]` on the six fields; the tag count per file equal (35/35); the 227 listed tags equal to the values written for them in the fixture (class D1 … D7) and to REF's
examples: (R-A2L-READ.49/2) the seven class reductions → D1 UWORD, `2`; D2 SWORD, `CM_ID`, `2`, `0x40`; D3 `CK1` at `0x2000`; D4 `8`; D5 `8` and `24`; D6 `8`; D7 `8` (hand-written in the case, not taken from REF)
examples: (R-A2L-READ.55/2) 5 MiB of seeded random bytes holding NUL → `errors` `["File is not UTF-8 text; save it as UTF-8 and load it again."]`, `sections` `[]`, `tags` `[]` (E3A-02: the E2 contract gave 51,810 errors)
examples: (R-A2L-READ.56/3, R-A2L-READ.65/3) 200,000 stray `/end` lines → `errors` of 101 entries, the last `… 199900 more parse errors`; no exception
examples: (R-A2L-READ.65/4) the hostile corpus with 1,000 seeded byte mutations per shape → no exception other than `OSError`, and `render_a2l_view` of each payload raises nothing
examples: (R-A2L-READ.17/1) V171 → `errors` `[]` (base `["Unclosed /begin sections detected."]`)
examples: (R-A2L-READ.52/1) case_06 and software_a, median of 3 → at most `1.5` × the e07fb00 median measured in the same session (P2: base `5.898` s and `0.653` s); round 2 (E3A-18): peak RSS at most `2` × e07fb00's (`535` MB and `95` MB at E3 round 2)

enrich_a2l_tags_with_values
req: R-A2L-READ.61
in: dict a2l_data; Optional[dict[int, int]] mem_map
out: list[dict] enriched
func: changed (round 2, E3S-18; `a2l.py:2878`, not on the graph before). was: `byte_size = (layout_meta or {}).get("byte_size") or tag.get("length")` (`:2890`), so a tag with no length still got its layout's one-element size, and a value was decoded from those bytes and fed to the Explorer, the Check Editor picker and "Use parameter" / now: `byte_size = None` when `tag.get("length")` is `None` (no bytes read, `raw_value` and `physical_value` `None`, `conversion_status` as base for no value); a tag with a length keeps the base expression (the layout's element size first — the full-length size for the pickers is Inc 6's, PE-D1, I-11.8 (g)). No new key; the enriched keys and types are the base's.
module: s19_app/tui/a2l.py
examples: (R-A2L-READ.61/9, E3S-18) [B6] (`length` `None`), with an image holding `0x11 0x11` at its address → `byte_size` `None`, `raw_value` `None`, `physical_value` `None` (base: `byte_size` `2`, `raw_value` `4369`, E3S [EN])
examples: (R-A2L-READ.61/9) the VAL_BLK `MATRIX_DIM 4` + `NUMBER 5`, `LENGTH 0` on a VALUE, `MATRIX_DIM x4` on a VAL_BLK → `byte_size` `None` each (base: `2` each)
examples: (holds as base) a VALUE on `RL_U16` with length `2` → `byte_size` `2`, its value decoded
examples: (tracked files, `e3c2-bytesize`) e07fb00: 300 tags with `length` `None` and a `byte_size` (CURVE 162, MAP 19, CUBOID 4, CUBE_4 2, VAL_BLK 113) → after Inc 11 the 113 VAL_BLKs have a length (D5, D6) and the other 187 `byte_size` `None`

_first_header_line
req: R-A2L-READ.25
in: str section_name; list[str] lines
out: tuple(Optional[str] line, list[str] lines)
func: removed. was: the first non-empty line that `parse_measurement_header` (6 words, first not a keyword) or `parse_characteristic_header` accepts — the BalanceTube and V161/V171 defect (C [FX-classes]). / now: absent; `_tag_header` gives the header words.
module: s19_app/tui/a2l.py
examples: (the base) BalanceTube `model.MainClass.gameController.sm` → `None` (no line of 6 words), so datatype None (C [FX-list])
examples: (the base, [K2]) the one-word-per-line header → `None`

assemble_characteristic_header
req: R-A2L-READ.26
in: list[str] lines
out: Optional[dict] header
func: unchanged (`a2l.py:616`, public facade `a2l_parse`). `_characteristic_from_tokens(_flatten_body_tokens(lines))`. No product caller after Inc 11 (the walk uses `_tag_header`); kept for the facade and its tests.
module: s19_app/tui/a2l.py
examples: (holds on base, `tests/test_a2l_multiline_headers.py:508-512`) `['"desc"', "CURVE 0x810300 /* c */", "RL.X 0 CM 0 255"]` → kind `CURVE`, address `8455936`, deposit `RL.X`; `["ECU_ADDRESS 0x10", "LENGTH 4"]` → `None`

parse_characteristic_header
req: R-A2L-READ.26
in: str line
out: Optional[dict] header
func: unchanged (`a2l.py:611`, back-compat shim). No product caller after `_first_header_line` goes.
module: s19_app/tui/a2l.py
examples: (holds on base, `tests/test_a2l_multiline_headers.py:484-495`) `"VALUE 0x80000010 RL_U8 0 CM_IDENT 0 255"` → kind `VALUE`, address `2147483664`

_byte_order_from_section_lines
req: R-A2L-001.2, R-A2L-READ.31
in: list[str] lines
out: Optional[str] byte_order
func: unchanged (`a2l.py:311`; Inc 3a reuses it). The first `BYTE_ORDER <word>` line → `big` / `little` / `None`. On canonical MOD_COMMON and RECORD_LAYOUT `lines` a commented BYTE_ORDER is gone, so R-A2L-001.2 holds with no change (E1 slice #12 named it changed).
module: s19_app/tui/a2l.py
examples: (R-A2L-001.2/8) MOD_COMMON canonical `lines` `["BYTE_ORDER MSB_FIRST"]` (the `MSB_LAST` line was inside a comment) → `big` (base, raw lines: `little`, Inc 2 [C3])

validate_a2l_structure
req: R-A2L-READ.12
in: dict a2l_data; list[dict]? tags = None
out: list[ValidationIssue] issues
func: unchanged (`validation/rules.py:463`, frozen). Errors → `A2L_STRUCTURE_ERROR`; a name on more than one tag → `A2L_DUPLICATE_SYMBOL`; GROUP/FUNCTION `lines` → `A2L_BROKEN_REFERENCE`. It sees Inc 11 only through the payload.
module: s19_app/validation/rules.py
examples: (R-A2L-READ.12/1) RP-B28 → `0` `A2L_DUPLICATE_SYMBOL` (base: `1`)
examples: (R-A2L-READ.23/5, [K1]) → `0` `A2L_DUPLICATE_SYMBOL` (base: `A2L symbol 'unknown' is defined multiple times.`, K)

iter_section_lines
req: R-A2L-READ.50, R-A2L-READ.51, R-A2L-076
in: List[dict] sections; int depth = 0
out: List[str] lines
func: changed. was: `"{indent}- {name} {meta} (lines {start}-{end})"` with the raw `meta`. / now: the same line over the canonical `meta`, which holds the section's *begin words* (F-E2-2 ruled at E3: the words on the keyword's line, or a named kind's name and long identifier on a later line, E3A-05), each character U+0000 … U+001F, U+007F … U+009F, U+2028 and U+2029 of `name` and `meta` replaced by U+FFFD; empty begin words give `"{indent}- {name} (lines {start}-{end})"`, one blank (R-A2L-076).
module: s19_app/tui/a2l.py
examples: (R-A2L-READ.50/1, RP-A27) XH → `- CHARACTERISTIC XH "one-line header" VALUE 0x00003000 RL_U32 0 CM_ID 0 100 (lines <a>-<b>)` (base: `… 0x00003000/*old 0x1000*/ RL_U32 …`, C [RP-A27])
examples: (R-A2L-READ.50/2) `VALUE  0x00003000` on the `/begin` line → one blank between them
examples: (R-A2L-READ.50/3) → `"one-line header"` with its quotes
examples: (R-A2L-READ.51/1, RP-A21) `"one-line<U+001E>header"` → `"one-line<U+FFFD>header"`, the line unbroken
examples: (R-A2L-READ.50/4) V161 `ASAM.C.ASCII.UBYTE.NUMBER_42` (named on the line after its keyword) → `- CHARACTERISTIC ASAM.C.ASCII.UBYTE.NUMBER_42 … (lines <a>-<b>)` (base: `- CHARACTERISTIC  (lines <a>-<b>)`)
examples: (R-A2L-076/3) `/begin MOD_COMMON` ↵ `"" BYTE_ORDER MSB_FIRST` ↵ `/end MOD_COMMON` → `- MOD_COMMON (lines <a>-<b>)` (base: two blanks)

render_a2l_view
req: R-A2L-075, R-A2L-076, R-A2L-077, R-A2L-READ.51
in: dict? a2l_data; list[dict]? tag_checks = None; int? max_tag_lines = None
out: str text
func: changed. was: any parse error → only `A2L parse errors:` and its lines (`a2l.py:3650-3652`). / now: `No A2L loaded.` for no payload; else, in this order and separated by one empty line, the block `A2L parse errors:` + `- <error>` lines when there are errors, the block `A2L Sections:` + `iter_section_lines` when there are sections, then `A2L Tags:` + the base tag lines (truncation as base); `No A2L sections found.` only when there is neither an error nor a section; every line's characters U+0000 … U+001F, U+007F … U+009F, U+2028, U+2029 replaced by U+FFFD before the join, so `str.splitlines()` (`services/a2l_service.py:26`) breaks only at the joins.
module: s19_app/tui/a2l.py
examples: (R-A2L-076/1, R-A2L-077, AT-B103-I11-3) `merge_inc_test.a2l` → `A2L parse errors:` ↵ `- Line <n>: /include included.a2l is not read` ↵ `` ↵ `A2L Sections:` ↵ … (base: the errors only)
examples: (R-A2L-076/2, R-A2L-077/1) HDR + a stray `/end X` + `MEAS(X, " ECU_ADDRESS 0x10")` → the errors block, then `A2L Sections:`, then `A2L Tags:` with `- MEASUREMENT X: 0x00000010 len=2 mem=unknown`
examples: (R-A2L-READ.51/1) a long identifier holding VT, FF, U+001C, U+001E, U+0085, U+2028, U+2029, ESC or BEL (a NUL byte refuses the file, READ.55) → U+FFFD in its line; every summary line matches `^(\s*- |A2L |\.\.\. |No A2L)` or is empty, 9/9 (base: the line breaks after the address, C [RP-A19 … A26c])
examples: (R-A2L-075, holds on base) `{"errors": ["E1"], "sections": [], "tags": []}` → `A2L parse errors:\n- E1`

S19TuiApp._compose_screen_a2l
req: R-TUI-042a.2
in:
out: Container screen
func: moved (Inc 12), 2026-11-07; Inc 12's E2 draws it again (with `fixed_columns` and the column order, R-TUI-042a.4). changed (D-1 A; G2). was: `DataTable(id="a2l_tags_list", zebra_stripes=True, cursor_type="row", cell_padding=0)` (`app.py:8516-8521`), so adjacent cells paint with no gap. / now: `cell_padding=1`; nothing else in the screen changes (the `density-compact` class and the pane padding stay, AT-038b).
module: s19_app/tui/app.py
examples: (R-TUI-042a.2/1, AT-B103-I11-1, real Explorer, SYNMAP) widths 220 and 160 → the painted row holds `0x1C2D3E00` and `2266` in separate cells with at least one blank between; `0x1C2D3E002266`, `SYN_MAP_W0x1C2D3E00`, `17921792` and `unknown0..` painted `0` times (base: `✓ SYN_MAP_W0x1C2D3E002266  formula17921792    yes  unknown0..4095%.0`, C [W220])
examples: (R-TUI-042a.2/2) widths 118, 100, 80 → the same for every cell shown (base: `SYN_MAP_W0x1C2D3E002266` at every width, C [W118 … W80])
examples: (AT-B103-I11-1) the detail card's first line `✓ SYN_MAP_W  0x1C2D3E00` (holds on base, C [W220 card])
examples: (holds on base, AT-038b) `#a2l_tags_pane` keeps the class `density-compact`

S19TuiApp._build_a2l_table_cells
req: R-TUI-042a.3
in: dict tag
out: tuple[Text, ...] cells
func: moved (Inc 12), 2026-11-07; Inc 12's E2 draws it again (the cap sized from the width left, R-TUI-042a.5). changed (E3 correction; E3A-03, E3S-01; G2). was: the Tag cell is `safe_text(f"{glyph} {name_text}")` with the whole name, so the Tag column takes the page's longest name and, at 118 with `cell_padding=1`, a 46 … 54-character name pushes the Address cell to the pane edge, cut with no mark (`0x1C2D3E0` … `0`). / now: when `name_text` is wider than 34 cells (`rich.cells.cell_len`), the cell shows its first 16 cells, `…` and its last 17 cells, so the Tag cell is at most 36 cells (glyph, blank, name) and Tag + Address + Length take at most 58 of the 60 cells at 118 (36 + 10 + 6, each + 2 padding); names that share a prefix stay distinct by their ends. The other 15 cells, `safe_text`, the styles and the detail card (which keeps the full name) are unchanged. A visible change: E5's captures go to the operator.
module: s19_app/tui/app.py
examples: (R-TUI-042a.3/1, real Explorer, LONGMAP(48), 118×54) the row paints the Tag cell `✓ SYN_MAP_LLLLLLLL…LLLLLLLLLLLLL_END` (36 cells), then `0x1C2D3E00` and `2266` whole (the E2 design: `0x1C2D3`, E3S-01 [V w=118 pad=1 name_len=48])
examples: (R-TUI-042a.3/3) a 34-character name → whole; a 35-character name → its first 16 characters, `…`, its last 17
examples: (R-TUI-042a.3/4, holds on base) the detail card for LONGMAP(48) → the 48-character name whole and `0x1C2D3E00`
examples: (R-TUI-042a.3, tracked) V161 `ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.COLUMN_DIR` (44 characters) → `ASAM.C.ARRAY.SWO…IM_3_4.COLUMN_DIR`; `….ROW_DIR` (41) → `ASAM.C.ARRAY.SWO…X_DIM_3_4.ROW_DIR`

_describe_one
req: R-A2L-READ.38, R-A2L-READ.61, R-A2L-READ.54
in: str name; dict[str, list[dict]] tags_by_name; dict[str, list[dict]] object_sections_by_name; dict[str, dict] compu_methods_by_name; dict[str, dict] compu_tables_by_name; dict a2l_data
out: Definition definition
func: changed (E3 correction; E3S-05 (b), I-11.8 (f); G1, after Inc 2a merges). Inc 2a's file `s19_app/tui/a2l_definition.py` (`b103-inc2a-code` `82f5f8e5`, `:324`). was: the MEASUREMENT header fill (`:377-398`, "E2-1 / R-A2L-014"): a tag lacking them took its datatype, conversion and limits from the object's header tokens and, with a datatype, `length = DATATYPE_SIZES[datatype] × matrix_dim` whenever `tag["length"] is None` — so a length the reader refused (`LENGTH 0`, disagreeing sizes) came back as the datatype's size and passed the span and datatype refusals (`:468-494`). / now: the fill is removed; the definition takes the tag's datatype, conversion, limits and length as the reader gives them (R-A2L-READ.25 reads the header the fill worked around), so a refused length stays `None` and the refusal `A2L-DEF-ADDRESS` (`<name>: the object has no address or no length`) follows. The tag copy (`:374`, R-A2L-DEF.58.1) and every other line stay. With DE-3 revised (R-A2L-READ.54), Inc 2a's walk files a section named on a later line under its name.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-READ.38/4) UWORD MEAS(X, `ECU_ADDRESS 0x10`, `LENGTH 0`) → `byte_length` `None`, refusal `A2L-DEF-ADDRESS` (with the fill: `2`, no refusal, E3S-05 (b))
examples: (R-A2L-READ.61/4) UWORD MEAS(X) with two LENGTH `4` and `8` → `byte_length` `None`, refusal `A2L-DEF-ADDRESS` (with the fill: `2`)
examples: (holds after Inc 11, Inc 2a R-A2L-014/def-1) BalanceTube `model.MainClass.gameController.sm` → byte length `1`, datatype `UBYTE`, now from the reader (R-A2L-READ.25), not from the fill
examples: (R-A2L-READ.54/6) [K1c] with `FORMAT "%5.1"` → display format `%5.1` (base: the section `UNKNOWN`, so `_read_object_lines(None)` drops FORMAT, E3A-01)

ref_read_a2l
req: R-A2L-READ.48, R-A2L-READ.49
in: str text
out: dict reading
func: new, test side (G-T1; `tests/support/b103_a2l_ref.py`). The reference reading: imports nothing from `s19_app`; written from `../01-requirements.md` § Definitions and rows S2.1/S2.2 only, never from the reader's code. Its own lexer (a **character loop** like E1's `ref_lex`, not a regex, after the BOM and line-end normalisation: ASCII blanks; `/* … */` and `//` as word breaks; strings with escape pairs over line ends, a `\` before a line end ordinary; stray `*/`; unexpected characters; the NUL refusal), its own tree (whole-word `/begin`/`/end` in any case, the keyword the next token whatever it is, innermost close with the name check, the nesting cap, a named kind's name and long identifier into its begin words), its own header split (name; long identifier when quoted; 6 or 7 words to the first keyword or child; short MEASUREMENT headers by position, short CHARACTERISTIC headers giving no field, R-A2L-READ.62) and keyword reader (the arity list, a keyword never an argument, MATRIX_DIM's words to the next keyword, duplicates; D-6 as revised: disagreeing address words, BIT_MASK or BYTE_ORDER → no address, disagreeing sizes → no length, never "the last wins"), its own number words, sizes, cap, echo and spans. Returns `{"sections": [{keyword, name, begin_words, start_line, end_line, runs: [(text, line)], children}], "tags": [{name, long_identifier, address, datatype, byte_order, bit_mask, matrix_dim, kind, deposit, conversion, length, axis_counts, record_layout}], "spans": [{name, kind, address, length}], "errors": [(text, line)]}` (sections added at the E3 correction, E3A-08 (1)). A static guard runs first (E3A-08 (3)): an AST walk shows no `import` of `s19_app`, and no string literal of `tests/support/b103_a2l_ref.py` longer than 8 characters occurs in `a2l.py`. The comparison is field by field on R-A2L-READ.48's list, errors as a sorted multiset. Shape model: `../evidence-e1/e1-census.py` (`ref_lex`, `ref_tree`, `split_header`, `ref_fields`); E4 writes its own, and its mutant check (`.2`, `.7`, `.12`, `.17` or `.25` reverted in the reader → ≥ 1 difference) proves it can fail.
module: tests/support/b103_a2l_ref.py
examples: (R-A2L-READ.48/2) the hostile corpus (the 162 shapes of `02-test-cases.md`: 144 + the 9 CG-1 reductions K1 … K7b + the 9 E3 shapes B3, B3b, B5, B6, B7, B8, B9, B13 and `/begin /end X`) → `0` differences on sections, tags, spans and errors, 162/162
examples: (R-A2L-READ.48/2, E3S [B8]) `BYTE_ORDER` ↵ `BIT_MASK 0x0FF0` → REF: `bit_mask` `0x0FF0`, errors `[("BYTE_ORDER has 0 of its 1 arguments", 23)]` — the E2 model consumed `BIT_MASK` as the argument and shared the reader's bug (E3S-02)
examples: (R-A2L-READ.48/2) RP-B40 → errors `[("*/ without /*", <line>)]`, X's address `4660`
examples: (R-A2L-READ.48 neg) the reader with `_tag_header` reading the name from `meta` only → [K1] differs (`UNKNOWN`) → RED

run_corpus_differential
req: R-A2L-READ.48, R-A2L-READ.52
in: Path manifest; Path files_dir
out: dict report
func: new, E5 evidence only (CG-6; runner only, never a CI test; never committed corpus content). Checks every file's sha256 against `../../design/a2l-corpus/manifest.tsv` (158 unique files, duplicates by content skipped), then reads each with the reader under test and with `ref_read_a2l`, and the e07fb00 reader for the time ratio; writes per class (the census's 12 classes and the 7 of this graph's corpus table) the count before and after, every difference as `(n, line, field, reader, REF)` with no file text, and the time ratio per file. Expected after Inc 11: classes 1, 3, 4, 5 → `0` objects; class 2 → `0` for every MEASUREMENT whose header REF reads; class 6 → the VAL_BLK/ASCII remainder of CG-2/CG-3 and the CURVE/MAP of CG-4, counted; class 7 → `19` header errors; the `U+FFFD` word errors counted on the 11 Latin-1 files (CG-5); every file of 1 MB or more within `1.5` × its e07fb00 time (E3A-09: the ratio is noise on the 243-byte files); the E3 classes counted too (named kinds named on a later line, ARRAY_SIZE objects, disagreeing sizes: E3A-01, -04, -13). Transcript in `inc-11/evidence-e5/`.
module: .dev-flow/2026-11-05-batch-103/inc-11/evidence-e5/i11e5-corpus.py
examples: (CG-6) manifest `n` = `154` (25,274,051 bytes) → its sha256 first, then the reading; a mismatch stops that file with `sha256 mismatch`
examples: (corpus class 1) `NAME_UNKNOWN_FROM_EMPTY_BEGIN_META` `137243` (base) → `0`

## Entities

[Data: A2L section node]
in: dict
desc: I-11.1. Keys `name`, `meta`, `meta_line`, `start_line`, `end_line`, `lines`, `line_numbers`, `children`; `meta` and `lines` canonical text; `""` in `lines` where a child opens.

[Data: A2L parse payload]
in: dict
desc: I-11.2. The base 7 keys plus `declared_spans`; `errors` in the I-11.6 order.

[Data: A2L tag dict]
in: dict
desc: I-11.3. The base 29 keys, unchanged types.

[Data: _TAG_KEYWORD_ARITY]
in: dict[str, int]
desc: the CTX-A2L-TAG keyword list with its arities, MATRIX_DIM as 1 to 3 numbers; distinct from `MEASUREMENT_BODY_KEYWORDS` (`a2l.py:113`, kept for `_extended_kind_anchor` and `parse_measurement_header`'s callers). E3 correction: a key is never an argument word (DE-9).

[Data: _NAMED_KINDS]
in: frozenset[str]
desc: E3 correction (E3A-01, CTX *named kind*): AXIS_PTS, BLOB, CHARACTERISTIC, COMPU_METHOD, COMPU_TAB, COMPU_VTAB, COMPU_VTAB_RANGE, FRAME, FUNCTION, GROUP, INSTANCE, MEASUREMENT, MEMORY_SEGMENT, MODULE, PROJECT, RECORD_LAYOUT, TRANSFORMER, every TYPEDEF_ keyword, UNIT. `build_section_tree` moves such a section's name (and long identifier) from a later line into `meta`.

[Data: _HEADER_WORDS]
in: dict[str, int]
desc: the header word count per section kind (MEASUREMENT 6, CHARACTERISTIC 7, BLOB 2, INSTANCE 2, TYPEDEF_MEASUREMENT 6, TYPEDEF_CHARACTERISTIC 6, TYPEDEF_BLOB 1, TYPEDEF_STRUCTURE 1).

[Data: a2l_extract.__all__]
in: list[str]
desc: I-11.7. Gains `extract_declared_spans`.

[I/O: A2L file]
desc: the file `build_section_tree` reads: UTF-8 (a BOM dropped), UTF-16 refused, a file holding a NUL byte refused (E3 correction), LF/CRLF/CR line ends; at most 32 levels of nesting.

[I/O: e07fb00 tag fixture]
desc: `tests/fixtures/b103_i11/e07fb00_tags.jsonl`: for each of the 35 tracked files, its tag count and each tag's six fields (name, address, length, datatype, byte order, BIT_MASK word), taken on a clean checkout of `e07fb00` with the transcript kept (02-test-cases R-A2L-READ.49/1). The oracle of R-A2L-READ.49: 234,654 tags, of which 234,427 must stay identical; the exceptions are the 227 tags of `../01-requirements.md` "Defect tags at e07fb00" (BalanceTube 104, V161 8, V171 11, update_test1 2, update_test2 1, software_a 101), each with its six expected values written in the fixture by its class's rule (D1 … D7, each pinned by a hand-written synthetic reduction, READ.49/2; E3A-08 (2)), and equal to REF's. The E1 addendum's census (source A) added 3 VAL_BLKs (R-A2L-016) and 101 (R-A2L-READ.53); 0 tracked ASCII on a layout whose name carries no size. The E3 correction added V161's ARRAY_SIZE tag (R-A2L-READ.57).

[I/O: public A2L corpus]
desc: `~/a2l-corpus/files/` on <runner> only (licenses mixed: never copied into the repo); identity by `../../design/a2l-corpus/manifest.tsv` sha256.

[Interface: A2L Explorer tag table]
desc: (the view rows: moved to Inc 12, 2026-11-07) `#a2l_tags_list`, the 16 cells of `_build_a2l_table_cells`; one blank column between cells after Inc 11, and a Tag cell of at most 36 cells (R-TUI-042a.3).

[Interface: Workspace A2L summary]
desc: `render_a2l_view` through `enrich_tags_and_render` (`services/a2l_service.py:26`, `.splitlines()`), painted at `app.py:20147-20178`.

## Edges

[I/O: A2L file] ──▶ build_section_tree
_lex_a2l_lines.out ──▶ build_section_tree.in
build_section_tree ──▶ [Data: A2L section node]
[Data: A2L section node] ──▶ _section_words
[Data: A2L section node].meta ──▶ iter_section_lines
[Data: A2L section node].lines ──▶ _byte_order_from_section_lines
[Data: A2L section node].lines ──▶ validate_a2l_structure
[Data: _TAG_KEYWORD_ARITY] ──▶ _tag_header
[Data: _TAG_KEYWORD_ARITY] ──▶ _tag_keyword_lines
[Data: _HEADER_WORDS] ──▶ _tag_header
extract_a2l_tags ──▶ [Data: A2L tag dict]
parse_a2l_file ──▶ [Data: A2L parse payload]
[Data: A2L parse payload] ──▶ render_a2l_view
[Data: A2L parse payload] ──▶ validate_a2l_structure
[Data: A2L tag dict] ──▶ S19TuiApp._compose_screen_a2l
render_a2l_view ──▶ [Interface: Workspace A2L summary]
S19TuiApp._compose_screen_a2l ──▶ [Interface: A2L Explorer tag table]
[I/O: e07fb00 tag fixture] ──▶ parse_a2l_file
[I/O: public A2L corpus] ──▶ run_corpus_differential
[Data: _NAMED_KINDS] ──▶ build_section_tree
_CappedErrors ──▶ build_section_tree
_CappedErrors ──▶ parse_a2l_file
_tag_keyword_lines.out ──▶ _tag_sizes.in
_tag_sizes ──▶ extract_a2l_tags
_echo_word ──▶ extract_a2l_tags
_echo_word ──▶ build_section_tree
[Data: A2L tag dict] ──▶ S19TuiApp._build_a2l_table_cells
S19TuiApp._build_a2l_table_cells ──▶ [Interface: A2L Explorer tag table]
[Data: A2L parse payload] ──▶ _describe_one
_CappedErrors ──▶ _build_section_tree_into
_build_section_tree_into ──▶ build_section_tree
_build_section_tree_into ──▶ parse_a2l_file
[Data: A2L parse payload] ──▶ enrich_a2l_tags_with_values

## Findings

finding F-E2-1 the naive lexer misses R-A2L-READ.52
anchor: _lex_a2l_lines
seen: (P1) a lexer returning all words as one list and a builder walking every word: case_06 tree `7.154` s against the base tree `0.974` s; projection `2.04`× the base parse (bound 1.5×); peak `646.7` MB against the base tree's `257.1` MB
cause: per-word Python work on 36.7 MB (pilot 1), and all word lists held at once
effect: the bound of R-A2L-READ.52 fails unless the lexer streams and keeps plain lines untouched
decision: DE-1 (generator, three tiers; P2: `1.37`× and `1.34`×, peak `388.1` MB). E4 re-measures with the real line-driven reader (P2 read the whole text; the product reads lines, DE-2). Memory is not a requirement; the tree's peak rises ~1.5× on case_06 (risk, noted)

finding F-E2-2 R-A2L-READ.50's "header" and the summary line
anchor: iter_section_lines
seen: CTX *section header* = the words after the keyword up to the first child, keyword or `/end`, across lines; R-A2L-READ.50's three cases all have the header on the `/begin` line; E1-rulings §5 expects only "comment text leaves the header lines"
cause: for a section whose header spans lines (every V161/V171 MEASUREMENT with its long identifier on a body line), "header" and "the words on the keyword's line" differ; for a section with no keyword list (COMPU_METHOD, RECORD_LAYOUT) the CTX header runs to its `/end`
effect: showing the CTX header would lengthen most summary lines (e.g. every COMPU_METHOD with its COEFFS)
decision: PROPOSED — the graph shows the canonical `meta` (the words on the keyword's line); E3 rules on rewording R-A2L-READ.50 to "its words on the line of its keyword, joined by single spaces". **Ruled at E3 (E3-rulings, E3A-05):** "header" = the words on the keyword's line; CTX *begin words* replaces CTX *section header*; R-A2L-READ.50 and R-A2L-076 reworded on it (with a named kind's name and long identifier from a later line, E3A-01)

finding F-E2-3 R-A2L-READ.39/1's `-5` input contradicts R-A2L-READ.36
anchor: extract_a2l_tags
seen: R-A2L-READ.38/1 and .39/1 list `LENGTH -5` among the lengths below 1; R-A2L-READ.36/2 makes `-0x10` and `+16` no number word, so `-5` is no number either
cause: a length that is not a number has no value to print in `<length>`
effect: .39/1 cannot reach 5/5
decision: PROPOSED — `LENGTH -5` gives no length (DE-6, meets .38/1) and no length error; .39/1 becomes 4/4 (0, 1048577, 99999999999, `NUMBER 1000000000000`). Ruled at E2; applied at the E1 addendum (R-A2L-READ.39's threshold 4/4, with the reason)

finding F-E2-4 E1's REF model reads a short CHARACTERISTIC header by position
anchor: ref_read_a2l
seen: `../evidence-e1/e1-census.py:567` takes the address from the second header word whatever the count; TC-099 (`tests/test_a2l_multiline_headers.py:441-446`) pins fail-closed for fewer than 7 params
cause: no row says how a short CHARACTERISTIC header is read
effect: the E4 REF and the reader could disagree on H3c-like shapes (R-A2L-READ.48/2)
decision: DE-7 (fail closed: no header field; the error of .28); E4's REF follows it; E3 may rule otherwise. **Ruled at E3 (E3A-06):** a row, R-A2L-READ.62, so the REF author reads it from the rows

finding F-E2-5 TC R-A2L-READ.43/2 cannot pass on the rows as written
anchor: extract_declared_spans
seen: the case's typedef is a VAL_BLK on `RL_U16` with `NUMBER 3`; R-A2L-016 sizes a VAL_BLK by MATRIX_DIM, and the base resolves a layout's datatype for VALUE only ([K6]: VAL_BLK on `RL_U16` → None)
cause: two gaps, CG-2 and CG-3
effect: the expected `12` is unreachable without CG-2 (and CG-3 for the NUMBER form)
decision: PROPOSED — accept CG-2 (and CG-3), or change the case to a VAL_BLK on a layout whose name carries its size (e.g. `RL.FNC.UWORD.ROW_DIR` style with `__UWORD_Z`) with `MATRIX_DIM 3`. Ruled at E2 (CG-2, CG-3 accepted); applied at the E1 addendum: the case's typedef is a VAL_BLK on `RL_U16` with `MATRIX_DIM 3`, sized by R-A2L-016 as R-A2L-READ.43 cites it

finding F-E2-6 `_strip_a2l_comments` is pinned by Inc 3's graph
anchor: _strip_a2l_comments
seen: `inc-3/codewire/graph-inc3.md:709` reuses it in `_read_matrix_dim` and `_read_record_layout`; after Inc 11 no `a2l.py` code calls it
cause: Inc 3a was designed on the raw reader
effect: removing it breaks Inc 3a; keeping it leaves a function whose only callers are another module and a test
decision: kept with the word-break change (DE-5); PROPOSED for the orchestrator: remove it once Inc 3a reads canonical lines (I-11.8 e)

finding F-E2-7 R-A2L-016 and R-A2L-017 are cited as met but are not
anchor: _infer_length_characteristic
seen: [K6] VAL_BLK on `RL_U16` with `MATRIX_DIM 4` → length None; [K6c] ASCII `RL_U8` `MATRIX_DIM 8` → None (K); corpus `LEN_NONE_CHAR_VAL_BLK` 14,317
cause: the layout's datatype is resolved for VALUE only (`a2l.py:1218-1229`); `sizeof_from_deposit` reads only names like `__UWORD_Z`
effect: R-A2L-016/.017's "size of its datatype" is unmet for project-named layouts
decision: CG-2 (PROPOSED, E1 addendum). Ruled at E2; applied at the E1 addendum for R-A2L-016 (cited, code to meet). R-A2L-017 takes an ASCII's length from its NUMBER line, which the base meets, so its part and [K6c] (an ASCII sized by MATRIX_DIM) were not applied: a ruling is owed. Ruled at E2 (addendum section) and applied at the E3 correction: R-A2L-017 changed in place (NUMBER, else MATRIX_DIM); [K6c] is R-A2L-017/1

finding F-E2-8 two number-word rules in one module
anchor: _number_word
seen: `_a2l_number` (`a2l.py:949`, MEMORY_SEGMENT, batch-101 Inc 11): a sign allowed, at most 8 hex or 10 decimal digits; CTX *number word* (R-A2L-READ.34 … .36): no sign, up to 16 hex or 20 decimal digits
cause: two rows families define number words differently (R-A2L-036.x and R-A2L-READ.34 … .36)
effect: none on the 35 files; a reviewer may expect one rule
decision: both kept (different rows); flagged for the canon fold-in (one CTX term, or two named terms)
