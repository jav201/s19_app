# Code-Wire graph — Inc 11 (A2L reader: comments, quoted strings, line ends, one-line IF_DATA, INSTANCE/BLOB; the tag-table padding), batch-103

Stage E2 of `dev-flow-v3-beta`. Graph only: no stub, mark or declaration in any tree. Base `05e43d8a` on `batch-103` (product tree `main` `e07fb00`). Requirements `../01-requirements.md` (60 rows), cases `../02-test-cases.md`, rulings `../E1-rulings.md` (all of D-1 … D-12 accepted, its "Orchestrator rulings" section), slice `../E1-slice.md`, E1 evidence `../evidence-e1/`. Notation: Code-Wire v3.1.0 (`C:\Users\jjgh8\Github\code-wire`, tag `v3.1.0` = `e436a08`), `docs/Notation-Grammar.md`; layout as `b101-inc12:.dev-flow/2026-11-01-batch-101/inc-12/codewire/graph-inc12.md`. Corpus evidence (the orchestrator, 2026-11-06): `../../design/a2l-corpus/` (158 public files; only derived counts are cited, no file content).

How to read it:
- One file holds the baseline and the prototype. Every node's `func:` starts with **unchanged**, **changed** (then "was: … / now: …"), **new** or **removed**. Context nodes (unchanged) are here because a changed node calls them, a consumer reads what they return, or they keep a canon row.
- Example sources: the case ids of `02-test-cases.md` (`R-A2L-READ.7/1`, `AT-B103-I11-1`); `C` = the E1 census (`../evidence-e1/e1-repro-transcript.txt` tags `[RP-…]`, `e1-fixtures-transcript.txt` `[FX…]`, `e1-glue-transcript.txt` `[H…]`, `e1-widths-transcript.txt` `[W…]`); `K` = the E2 corpus reductions on the base reader (`evidence-e2/i11e2-corpus-shapes-transcript.txt`, tags `[K1]` … `[L1]`); `LS` = the E2 lexer model's outputs (`evidence-e2/i11e2-lexer-shapes-transcript.txt`; a throwaway feasibility model of `_lex_a2l_lines`, not product code); `P1`, `P2` = the E2 timing pilots (`evidence-e2/i11e2-pilot-time-transcript.txt`, `i11e2-pilot-time2-transcript.txt`); `X` = the extractor run (`evidence-e2/i11e2-extract-transcript.txt`); `R` = read in the code at `e07fb00`. Every example states the Inc 11 target unless it says "the base" or "holds on base".
- `HDR`, `MEAS(X, …)` and `SYNMAP` are the common fixtures of `02-test-cases.md`; `↵` is a line end. Every A2L text is synthetic.
- **Canonical text**: a run of words joined by one space; a quoted word keeps its quotes and its escape pairs as in the file (`"a\"b"`), so `_split_line_respecting_quotes` reads it back as the same word. A **run** is the words of one source line that stand between two child sections, or between a child section and the line's start or end.

### Design decisions taken at E2 (each is in a node; the orchestrator may overrule)

| Id | Decision | Why | Rows |
|---|---|---|---|
| DE-1 | The lexer is a **generator over the file's lines** (`_lex_a2l_lines`) that yields `(line, canonical text)`; the builder appends a canonical line as it is and splits only a line that holds `/begin`, `/end` or `/include` | P1: a lexer returning every word as a list, and a builder walking every word, take 7.3× the base tree on case_06 and project to **2.04×** the base parse, over R-A2L-READ.52's 1.5×, at 2.5× the base tree's peak memory. P2 (this shape): **1.37×** (case_06) and **1.34×** (software_a), tree peak 388 MB against base 257 MB | READ.52 |
| DE-2 | The file is still read line by line through `path.open(…)` in text mode (universal newlines), with the progress report every 4 096 lines and `os.fstat` only with a callback | `tests/test_b100_a2l_progress.py` pins that mechanism (TC-B100-73: a read failing at line 5 000 leaves exactly one report; 0 `fstat` calls without a callback); universal newlines are R-A2L-READ.1 | READ.1, R-A2L-004.11 |
| DE-3 | Section nodes keep their six keys; `meta` and `lines` hold **canonical text** (no comment text, single spaces, word breaks at comments); `meta` = the own words on the keyword's line before any child; `lines` = the later runs, and an empty entry `""` where each child section opens. Two keys are added: `meta_line`, `line_numbers` (**PROPOSED**, I-11.1) | E1's CANON(file) is exactly this layout for every section that is not a tag, and the E1 census shows the e07fb00 line readers give REF's values on it except the listed defects [FX-total]; so every line reader (record layouts, compu methods, compu tables, link maps, memory segments, `validation/rules.py` (frozen), Inc 2a, Inc 3a) meets R-A2L-001.2 with no change of its own. A "first run" `meta` was tried and rejected: 1 MOD_COMMON (BalanceTube), every AXIS_DESCR (V161 17, V171 51, software_a 180) and 3 MEMORY_SEGMENTs (software_a) have their keyword alone on its line, so their readers would lose their first line (grep of the 35 files) | R-A2L-001.2, READ.1–.3, .7, .23 |
| DE-4 | The tag reader reads **words**, not lines: `_section_words` → `_tag_header` (name, long identifier, header words to the first keyword) → `_tag_keyword_lines` (one canonical "keyword + arguments" text per keyword, by arity); the existing field rules then run on those texts | the base field loop (`a2l.py:2661-2714`) and `_infer_length_*` keep their line form, so R-A2L-010 … 036 keep their code; E1's CANON layout put each keyword on its own line in the same way | READ.23–.33, .37 |
| DE-5 | `_strip_a2l_comments` is **kept** (a comment becomes one space) | Inc 3's graph reuses it (`inc-3/codewire/graph-inc3.md:709`); removing it is a change to another increment's interface, so it is PROPOSED only (F-E2-6) | READ.7 |
| DE-6 | A LENGTH, DATA_SIZE or NUMBER word that is not a number word gives **no length and no inference** | R-A2L-014 … 017 infer only when there is no DATA_SIZE or LENGTH; R-A2L-READ.38/1 asks `LENGTH -5` → no length, and `-5` is no number word (.36); base inferred from the datatype (R `a2l.py:2669-2673`, `:2720`) | READ.36, .38 |
| DE-7 | A short CHARACTERISTIC header (1 to 6 words) gives **no header field** (the error of .28 only); a short MEASUREMENT header gives its words by position | .27/2 asks datatype `UWORD` from a 5-word MEASUREMENT header (Inc 2 shape C); for a CHARACTERISTIC no row reads a short header, and TC-099 pins the fail-closed rule (`tests/test_a2l_multiline_headers.py:441-446`). E1's REF model reads a short CHARACTERISTIC address by position (`e1-census.py:567`): F-E2-4 | READ.27, .28 |

### Groups for E4 (file ownership) and interfaces — pinned here, changed only by an orchestrator ruling

| Group | Files | Owns nodes |
|---|---|---|
| G1 reader | `s19_app/tui/a2l.py`, `s19_app/tui/a2l_extract.py` | every node with `module: s19_app/tui/a2l.py` that is new, changed or removed; `[Data: a2l_extract.__all__]` |
| G2 app | `s19_app/tui/app.py` (one argument, `:8520`); doc row DOSSIER F-09 is the integrator's | `S19TuiApp._compose_screen_a2l` |
| G-T1 reader tests | new `tests/test_b103_a2l_reader.py`, new `tests/support/b103_a2l_ref.py`, new fixture `tests/fixtures/b103_i11/e07fb00_tags.jsonl`; the changed tests of `../E1-rulings.md` §4 (TC-097, `test_b101_a2l_blocks_and_segments.py:281-293`, `test_tui_a2l_issue_recolor.py` per D-10, the freeze guards and TC-B100-73's `_ENGINE_PATHS` check `test_b100_a2l_progress.py:226-238`) | `ref_read_a2l`, `[I/O: e07fb00 tag fixture]` |
| G-T2 app tests | AT-B103-I11-1 … 3 and R-TUI-042a.2/1, /2 (real Explorer, headless); the 6 `a2l-*` snapshot baselines (`tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[a2l-*].svg`) are regenerated in the canonical CI env (`snapshot-regen.yml`, textual 8.2.8), never locally | — |
| E5 evidence (runner only, never a CI test) | `inc-11/evidence-e5/` scripts and transcripts | `run_corpus_differential`, `[I/O: public A2L corpus]` |

| Interface | Pinned form | Producer → consumers |
|---|---|---|
| I-11.1 section node (**PROPOSED**: content and two keys) | a dict `{"name": str, "meta": str, "meta_line": int, "start_line": int, "end_line": int, "lines": list[str], "line_numbers": list[int], "children": list[dict]}`. `name` = the keyword (the word after `/begin`, quotes left out). `start_line` = the line of the `/begin` word; `end_line` = the line of the `/end` word, absent while unclosed (as base). `meta` = the canonical text of the section's own words on the keyword's line, before any child section; `""` when none; `meta_line` = the keyword's line. `lines` = the canonical text of each later run, in file order, and `""` where each child opens; `line_numbers[i]` = the line of `lines[i]` (of a `""` entry: the child's `start_line`). Comment-only and blank lines give no entry (base kept them, raw). `len(lines) == len(line_numbers)` | `build_section_tree` → every `a2l.py` line reader; `validation/rules.py:488-565` (frozen; reads `name`, `start_line`, GROUP/FUNCTION `lines`); `segment_split_view.py:1620` (via `extract_memory_segments`); `app.py:19136` (counts); Inc 2a `a2l_definition.py` (`meta`, `lines`, `name`, `children`); Inc 3a (`lines`, `end_line`) |
| I-11.2 parse payload | `parse_a2l_file` returns the base keys `path`, `sections`, `errors`, `tags`, `record_layouts_by_name`, `compu_methods_by_name`, `compu_tabs_by_name` with the base types, and the new key `declared_spans: list[dict]`, each `{"name": str, "kind": "BLOB" or "INSTANCE", "address": int or None, "length": int or None}` in file order (E1-slice §3) | `parse_a2l_file` → every consumer of `../E1-rulings.md` §5; Inc 2b (R-A2L-DEF.138 index) |
| I-11.3 tag dict | the base 29 keys and value types (`a2l.py:2610-2639`) unchanged; value changes only as `../01-requirements.md` "Defect tags at e07fb00" lists, plus descriptions (189), display identifiers (6), `matrix_dim` = the product (14), and the objects whose header stands on the `/begin` line | `extract_a2l_tags` → views, validation, pickers, reports (E1 §5) |
| I-11.4 functions other increments import (signatures **unchanged**) | Inc 2a: `DATATYPE_SIZES`, `MAX_A2L_DECODE_BYTES`, `_apply_compu_method`, `_decode_scalar`, `_flatten_body_tokens(lines: list[str]) -> list[str]`, `_resolve_record_layout`, `_to_float`, `parse_begin_meta(meta: str) -> tuple[str, Optional[str]]` (`b103-inc2a-code:s19_app/tui/a2l_definition.py:25-34`). Inc 3a (graph): `_walk_record_layout_components`, `_strip_a2l_comments(text: str) -> str`, `_split_line_respecting_quotes(line: str) -> list[str]`, `_byte_order_from_section_lines(lines: list[str]) -> Optional[str]`. Behaviour changes on raw input only: `_flatten_body_tokens`, `_strip_a2l_comments` (a comment is a word break) and `_split_line_respecting_quotes` (ASCII blanks, escape pairs, a `"` ends a word); on canonical input each gives the base tokens | `a2l.py` → Inc 2a, Inc 3a |
| I-11.5 `extract_a2l_tags` (**PROPOSED**) | `extract_a2l_tags(sections: list[dict], record_layouts_by_name: Optional[dict[str, dict]] = None, compu_methods_by_name: Optional[dict[str, dict]] = None, errors: Optional[list[str]] = None) -> list[dict]` — a fourth parameter `errors`, default `None`, receives the tag errors (.28, .32, .39); `None` drops them, so every base call keeps its result | `a2l.py` (public, `a2l_extract.py`, `tui/__init__.py:12`) → `parse_a2l_file` |
| I-11.6 parse-error texts and order | the 9 new texts of `../E1-slice.md` §3, R-A2L-001.5's text now live, `Unclosed /begin sections detected.` and `File not found.` as base. Order in `errors`: the lexer's and the builder's errors in file order, then `Unclosed /begin sections detected.`, then the tag errors in tag order (per tag: header, duplicates, length). A UTF-16 file gives exactly one error | `build_section_tree`, `extract_a2l_tags` → R-A2L-004.2 status, `A2L_STRUCTURE_ERROR` (`validation/rules.py:492-500`), the A2L summary (R-A2L-075) |
| I-11.7 facade | `a2l_extract.__all__` = `["enrich_a2l_tags_with_values", "extract_a2l_tags", "extract_declared_spans"]` (`CLAUDE.md`: new public symbols re-exported by the matching facade); `a2l_parse`, `a2l_render`, `a2l_validate`, `tui/__init__` unchanged | G1 → importers |
| I-11.8 consumer obligations (**PROPOSED**, for the orchestrator to route) | (a) Inc 2a/2b name a MEASUREMENT or CHARACTERISTIC section by its first own word — the first word of `_flatten_body_tokens([meta] + lines)`, which Inc 2a already computes as `header[0]` in `_read_object_lines` — not by `parse_begin_meta(meta)`, or a name on a later line (V161/V171 `ASAM.C.ASCII.UBYTE.NUMBER_42`, corpus class 1) gives `UNKNOWN` on the section and the true name on the tag; (b) after Inc 11, Inc 2a's text-of-the-object checks (`bit_mask_letters`, `ends_open`, `begin_inside`, R-A2L-DEF.19's two messages) see canonical text: `ends_open` and `begin_inside` can no longer be `True`, and a BIT_MASK inside a comment no longer counts — Inc 2a tests on comment shapes and R-A2L-DEF.3's `UNKNOWN` change outcome, and Inc 2b (A2: "re-checked against the fixed reader") re-rules them; (c) Inc 2b refuses an encode of an object whose `[start_line, end_line]` holds the line of a parse error (D-6 A); (d) Inc 2b reads `declared_spans` into R-A2L-DEF.138's index; (e) Inc 3a reads canonical `lines` and needs no comment stripping | Inc 11 → Inc 2a, 2b, 3a |

PLAN interfaces: I-2 (the definition model) consumes I-11.1 … I-11.4; I-1, I-3, I-4 and I-5 are not touched.

Order inside E4: G1 and G2 in parallel (disjoint files); G-T1 and G-T2 in parallel. The re-freeze of `a2l.py` is a separate PR after the merge (`CLAUDE.md`, Engine-frozen guard). Merge position: before Inc 2b, 3b, 6 and 8 (PLAN Inc 11); after Inc 2a if 2a merges first, in which case I-11.8 (b) applies to the merged tree.

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
| `parse_a2l_file` | `:2797` | `parse_a2l_cached` (`app.py:948`, `:950`), `run_flow` (`flow_execution_service.py:381`, `:500`), `execute_variant_plan` (`variant_execution_service.py:2665`) | changed |
| `iter_section_lines` | `:3627` | `render_a2l_view` (`:3657`) | changed |
| `render_a2l_view` | `:3644` | `enrich_tags_and_render` (`services/a2l_service.py:26`) ← `S19TuiApp._compute_a2l_enriched_tags` (`app.py:20136`), `S19TuiApp._prepare_load_payload` (`:18844`), `_a2l_addresses` (`compare_service.py:305`), `_execute_one_variant` (`variant_execution_service.py:2553`), `run_flow` (`flow_execution_service.py:399`) | changed |
| `S19TuiApp._compose_screen_a2l` | `app.py:8456` (`cell_padding=0` at `:8520`) | `S19TuiApp.compose` (`app.py:3385`) | changed |
| `validate_a2l_structure` | `validation/rules.py:463` (frozen) | `validate_a2l_internal_issues` (`a2l.py:3716`), `validation/engine.py:71` (X) | unchanged (context) |

### Consumers that see a change (what the operator or a test sees)

| Consumer | Reads | Change |
|---|---|---|
| A2L Explorer table (`app.py:20286-20473`) | the 16 cells | a blank column between cells (R-TUI-042a.2); the 122 listed tags; names, kinds and addresses of objects whose header stands on the `/begin` line (corpus classes 3–5); each of the 16 columns 2 cells wider, so fewer columns fit at 118 (PLAN backlog 5, Inc 7) |
| A2L snapshot baselines (6 `a2l-*` SVGs, `tests/test_tui_snapshot.py:391-395`) | the painted A2L screen | drift from the padding; regenerated in the canonical CI env (G-T2) |
| DOSSIER F-09 (`docs/user-guide/DOSSIER.md:718`) | the live defect "columns run together" | closed by R-TUI-042a.2 (the integrator marks it) |
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
| 1 name `UNKNOWN` — `/begin` alone on its line, one word per line (137,243) | [K1] two such MEASUREMENTs → both `UNKNOWN`, no address, datatype None, one `A2L_DUPLICATE_SYMBOL`; [K1c] CHARACTERISTIC → `UNKNOWN`, address right | `_section_words` + `_tag_header` (the name is the first own word, any line) | READ.23 (covers it; threshold addendum PROPOSED, CG-1) |
| 2 MEASUREMENT datatype None (121,299) | [K2] header one word per line → datatype None, length None | `_tag_header` (header words across line ends) + `parse_measurement_header` | READ.25 (covers it; CG-1) |
| 3 CHARACTERISTIC kind misread, header on the `/begin` line (657) | [K3] → kind `ECU_ADDRESS_EXTENSION`, deposit `BYTE_ORDER` (the B6 salvage anchors on a body keyword) | `_tag_header` reads the header from `meta`; it stops at a keyword, so `_extended_kind_anchor` never sees a body keyword | READ.26, .27 |
| 4 wrong address, header on the `/begin` line (805) | [K3] → `0x0`; [K4] `CUBE_5 0x123` → kind `NUMBER`, address `0x2710` | as class 3 | READ.26, .27 |
| 5 address None, ECU_ADDRESS mid-line or after a comment (729) | [K5] one-line MEASUREMENT with a nested IF_DATA → address None, `Unclosed /begin sections detected.`; [K5b] `/* moved */ ECU_ADDRESS 0x1234` → None | `build_section_tree` (one-line sections close) + `_tag_keyword_lines` (a keyword anywhere among own words) + `_lex_a2l_lines` (no comment word) | R-A2L-001.1, READ.17, .30, R-A2L-001.2 |
| 6 CHARACTERISTIC length None with its layout in the file (17,000) | [K6d] VALUE one word per line → 4 (holds on base); [K6] VAL_BLK on `RL_U16` with `MATRIX_DIM 4` → None; [K6b] VAL_BLK `NUMBER 4` → None; [K6c] ASCII `MATRIX_DIM 8` → None | partly: the header rule fixes the objects whose deposit word is lost (classes 1, 3); a VAL_BLK or ASCII on a layout whose name carries no size stays None — **no row** | CG-2, CG-3 (PROPOSED); CURVE/MAP/CUBE → CG-4 |
| 7 short headers (19), `/begin` after code (1) | [K7] 4-word header → datatype None, no error; [K7b] two one-line INSTANCEs on one line → `Unclosed /begin sections detected.` | `extract_a2l_tags` (.28's error); `build_section_tree` | READ.28, R-A2L-001.1 |
| Latin-1 input (11 files) | [L1] `0xB0` → U+FFFD in the long identifier and in the name word, 0 errors | `_lex_a2l_lines`: U+FFFD in a word gives .4's error; in a string or comment none | R-A2L-001.7 + READ.4; CG-5 (PROPOSED) |

### Corpus gaps — PROPOSED rows for the orchestrator (E1 addendum follows)

| Id | Proposed row (EARS) or routing | Threshold, negative control | Evidence |
|---|---|---|---|
| CG-1 | No new row: add the class 1–5 and 7 reductions K1, K1c, K2, K3, K4, K5, K5b, K7, K7b to the hostile corpus (R-A2L-READ.48/2) and to the thresholds of READ.23 (K1, K1c), .25 (K2, K5), .26 and .27 (K3, K4), .30 (K5), .28 (K7), R-A2L-001.1 (K7b) | as in this graph's examples; mutant: the name read from `meta` only → K1 gives `UNKNOWN` → RED | [K1] … [K7b] |
| CG-2 | R-A2L-016 and R-A2L-017 change status from "cited and unchanged" to **cited (code to meet)**, with the CTX-A2L-TAG term *datatype (CHARACTERISTIC)*: the datatype of the FNC_VALUES of its record layout. The base resolves a layout's datatype for VALUE only (`a2l.py:1218-1229`) | [K6] VAL_BLK `RL_U16` `MATRIX_DIM 4` → length `8`; [K6c] ASCII `RL_U8` `MATRIX_DIM 8` → `8`; TC R-A2L-READ.43/2 needs it too (its typedef sits on `RL_U16`); mutant: the VALUE-only resolution kept → [K6] None → RED. **Risk:** it enlarges R-A2L-READ.49's defect list by every tracked VAL_BLK/ASCII on such a layout (count owed: a census at the E1 addendum) | [K6], [K6c]; corpus `LEN_NONE_CHAR_VAL_BLK` 14,317, `…ASCII` 28 |
| CG-3 | New row R-A2L-READ.53 (`If`): "If a VAL_BLK CHARACTERISTIC has no MATRIX_DIM and has a NUMBER keyword, then the system shall take its length as the size of its datatype × the number after NUMBER." (ASAP2 1.6 form) | [K6b] → `8`; mutant: NUMBER ignored for VAL_BLK → None → RED | [K6b] |
| CG-4 | Routing, no Inc 11 row: CURVE, MAP, CUBOID, CUBE_4, CUBE_5 lengths (corpus 2,256 + 2,180 + 17 + 8 + 6), the AXIS_DESCR header on its `/begin` line (BL-I11-2) and the ~60 RECORD_LAYOUT components the fixtures lack go to Inc 3 (axes and layouts); CUBE_4/CUBE_5 into `CHARACTERISTIC_KINDS` is Inc 3's call (the B6 salvage already gives their kind and address: [K4] after the change) | — | corpus summary |
| CG-5 | Latin-1: (A, recommended) no new row — R-A2L-001.7 reads each non-UTF-8 byte as U+FFFD; inside a word R-A2L-READ.4 records `Line <n>: unexpected character U+FFFD`, inside a string or a comment nothing; the E5 corpus run counts these errors on the 11 files. (B) a second decode (cp1252) when UTF-8 fails — a second encoding path, refused for UTF-16 at D-3 | (A): [L1] → 1 error for `XL1_<U+FFFD>`, 0 for the comment and the long identifier | [L1] |
| CG-6 | E5 evidence run (not a row, not a CI test): `run_corpus_differential` on the 158 files of `../../design/a2l-corpus/manifest.tsv` (sha256 checked first), on the runner only, next to the 35-file no-regression set | node `run_corpus_differential` | — |

### Coverage — every requirement → node(s) and example(s)

| Requirement | Node(s) | Example(s) |
|---|---|---|
| R-A2L-READ.1 | `_lex_a2l_lines`, `build_section_tree` | READ.1/1–/4 |
| R-A2L-READ.2 | `_lex_a2l_lines`, `_split_line_respecting_quotes` | READ.2/1, /2 |
| R-A2L-READ.3 | `_lex_a2l_lines`, `_number_word` | READ.3/1, /2 |
| R-A2L-READ.4 | `_lex_a2l_lines` | READ.4/1–/3, [L1] |
| R-A2L-READ.5 | `build_section_tree` | READ.5/1, /2 |
| R-A2L-READ.6 | `build_section_tree`, `parse_a2l_file` | READ.6/1, /2 |
| R-A2L-001.2 | `_lex_a2l_lines`, `extract_a2l_tags` | 001.2/1–/8 |
| R-A2L-READ.7 | `_lex_a2l_lines`, `_strip_a2l_comments`, `extract_a2l_tags` | READ.7/1–/6 |
| R-A2L-READ.8 | `_lex_a2l_lines` | READ.8/1, /2 |
| R-A2L-READ.9 | `_lex_a2l_lines` | READ.9/1–/3 |
| R-A2L-READ.10 | `_lex_a2l_lines` | READ.10/1 |
| R-A2L-READ.11 | `_lex_a2l_lines` | READ.11/1–/3 |
| R-A2L-READ.12 | `build_section_tree`, `extract_a2l_tags` | READ.12/1–/3, AT-B103-I11-2 |
| R-A2L-001.3.1 | `_lex_a2l_lines`, `_tag_header` | 001.3.1/1–/3 |
| R-A2L-001.3.2 | `_lex_a2l_lines`, `_parse_first_field`, `_split_line_respecting_quotes` | 001.3.2/1–/3 |
| R-A2L-READ.13 | `_lex_a2l_lines`, `build_section_tree` | READ.13/1–/4 |
| R-A2L-READ.14 | `_lex_a2l_lines` | READ.14/1 |
| R-A2L-READ.15 | `_lex_a2l_lines` | READ.15/1 |
| R-A2L-READ.16 | `_lex_a2l_lines`, `_split_line_respecting_quotes`, `_line_words` | READ.16/1–/3 |
| R-A2L-001.1 | `build_section_tree` | 001.1/1–/3, [K7b] |
| R-A2L-READ.17 | `build_section_tree` | READ.17/1–/3, [K5] |
| R-A2L-READ.18 | `build_section_tree` | READ.18/1, /2 |
| R-A2L-READ.19 | `build_section_tree` | READ.19/1, /2 |
| R-A2L-READ.20 | `build_section_tree` | READ.20/1, /2 |
| R-A2L-001.4 | `build_section_tree` | 001.4/1, /2 |
| R-A2L-001.5 | `build_section_tree` | 001.5/1, /2 |
| R-A2L-READ.21 | `build_section_tree` | READ.21/1 |
| R-A2L-READ.22 | `build_section_tree` | READ.22/1, /2 |
| R-A2L-READ.23 | `_section_words`, `_tag_header`, `extract_a2l_tags` | READ.23/1–/4, [K1], [K1c] |
| R-A2L-READ.24 | `_tag_header` | READ.24/1, /2 |
| R-A2L-READ.25 | `_tag_header`, `parse_measurement_header` | READ.25/1–/4, [K2], [K5] |
| R-A2L-READ.26 | `_tag_header`, `_characteristic_from_tokens` | READ.26/1–/3, [K3], [K4] |
| R-A2L-READ.27 | `_tag_header`, `parse_measurement_header` | READ.27/1–/3, [K3] |
| R-A2L-READ.28 | `extract_a2l_tags` | READ.28/1–/3, [K7] |
| R-A2L-READ.29 | `_tag_keyword_lines` | READ.29/1–/4 |
| R-A2L-READ.30 | `_tag_keyword_lines` | READ.30/1, /2, [K5] |
| R-A2L-READ.31 | `_section_words`, `build_section_tree` | READ.31/1–/3 |
| R-A2L-READ.32 | `extract_a2l_tags` | READ.32/1–/4 |
| R-A2L-READ.33 | `_tag_keyword_lines`, `extract_a2l_tags` | READ.33/1, /2 |
| R-A2L-READ.34 | `_number_word` | READ.34/1 |
| R-A2L-READ.35 | `_number_word` | READ.35/1, /2 |
| R-A2L-READ.36 | `_number_word`, `_characteristic_from_tokens`, `_extended_kind_anchor` | READ.36/1–/3, READ.7/1 |
| R-A2L-READ.37 | `_tag_keyword_lines`, `_infer_length_measurement`, `_infer_length_characteristic` | READ.37/1, /2, READ.29/4 |
| R-A2L-READ.38 | `_bounded_length`, `extract_a2l_tags` | READ.38/1–/3 |
| R-A2L-READ.39 | `extract_a2l_tags` | READ.39/1 (4 of its 5 inputs; F-E2-3) |
| R-A2L-READ.40 | `extract_declared_spans` | READ.40/1–/3 |
| R-A2L-READ.41 | `extract_declared_spans` | READ.41/1 |
| R-A2L-READ.42 | `extract_declared_spans` | READ.42/1, /2 |
| R-A2L-READ.43 | `extract_declared_spans` | READ.43/1, /3; /2 with a fixture fix (F-E2-5) |
| R-A2L-READ.44 | `extract_declared_spans` | READ.44/1, /2 |
| R-A2L-READ.45 | `extract_declared_spans` | READ.45/1–/3 |
| R-A2L-READ.46 | `extract_declared_spans`, `_bounded_length` | READ.46/1, /2 |
| R-A2L-READ.48 | `ref_read_a2l`, `parse_a2l_file` | READ.48/1, /2 |
| R-A2L-READ.49 | `[I/O: e07fb00 tag fixture]`, `parse_a2l_file` | READ.49/1 |
| R-TUI-042a.2 | `S19TuiApp._compose_screen_a2l` | R-TUI-042a.2/1, /2, AT-B103-I11-1 |
| R-A2L-READ.50 | `build_section_tree` (canonical `meta`), `iter_section_lines` | READ.50/1–/3 (reading of "header": F-E2-2) |
| R-A2L-READ.51 | `iter_section_lines`, `render_a2l_view` | READ.51/1 |
| R-A2L-076 | `render_a2l_view` | 076/1, /2, AT-B103-I11-3 |
| R-A2L-077 | `render_a2l_view` | 077/1 |
| R-A2L-READ.52 | `build_section_tree`, `_lex_a2l_lines`, `parse_a2l_file` | READ.52/1 (base medians measured: P1, P2) |

Requirements without an example: **none**. Two examples depend on a ruling: READ.39/1's `-5` input (F-E2-3) and READ.43/2's fixture (F-E2-5).

### Node count

32 nodes: **new 8** (`_lex_a2l_lines`, `_line_words`, `_section_words`, `_tag_header`, `_tag_keyword_lines`, `_number_word`, `_bounded_length`, `extract_declared_spans`), **changed 15** (`build_section_tree`, `_parse_first_field`, `_split_line_respecting_quotes`, `_strip_a2l_comments`, `_flatten_body_tokens`, `parse_measurement_header`, `_characteristic_from_tokens`, `_extended_kind_anchor`, `_memory_segment_record_words`, `_infer_length_measurement`, `_infer_length_characteristic`, `extract_a2l_tags`, `parse_a2l_file`, `iter_section_lines`, `render_a2l_view`) + 1 in `app.py` (`S19TuiApp._compose_screen_a2l`) = 16, **removed 1** (`_first_header_line`), **context 5** (`parse_begin_meta`, `_byte_order_from_section_lines`, `assemble_characteristic_header`, `parse_characteristic_header`, `validate_a2l_structure`), **test-side and evidence 2** (`ref_read_a2l`, `run_corpus_differential`). Under the 40 cap; no split.

Deviations from `../E1-slice.md`: 4 new functions there, 8 here (the tag walk's new logic is split into `_line_words`, `_section_words`, `_tag_header`, `_tag_keyword_lines` so each row has a node with its own examples); `_lex_a2l_words` is named `_lex_a2l_lines` and yields lines (DE-1); `parse_begin_meta` (#2), `assemble_characteristic_header` (#11) and `_byte_order_from_section_lines` (#12) stay unchanged — their rows hold through canonical `meta`/`lines` (DE-3) and the tag reader's own name rule; `_strip_a2l_comments` (#5) is kept, not replaced (DE-5); `_first_header_line` (#8) is removed. Files: the same 3.

## Nodes

_lex_a2l_lines
req: R-A2L-READ.1, R-A2L-READ.2, R-A2L-READ.3, R-A2L-READ.4, R-A2L-001.2, R-A2L-READ.7, R-A2L-READ.8, R-A2L-READ.9, R-A2L-READ.10, R-A2L-READ.11, R-A2L-001.3.1, R-A2L-001.3.2, R-A2L-READ.13, R-A2L-READ.14, R-A2L-READ.15, R-A2L-READ.16, R-A2L-READ.52
in: Iterable[str] lines; list[str] errors
out: Iterator[tuple[int, str]] canonical
func: new (DE-1). One pass over the text lines (an element may end with `\n`; a `\r\n` or `\r` inside an element is a line end too), yielding `(line, canonical text of the words that start on that line)` for every line that holds a word; line *k* of the input is line `k`, and every line end inside an element or inside a quoted string counts. Blanks = space, HT, VT, FF; a word ends at a blank, a line end, a `"` or the `/` that starts `/*` or `//`. Outside a quoted string: `/*` … the first `*/` and `//` … the line end are word breaks and give no word; a word holding `*/` stays a word and appends `Line <n>: */ without /*`; a word holding a character outside U+0021 … U+007E appends `Line <n>: unexpected character U+<XXXX>` (its first such character, 4 or more uppercase hex digits), once per word. A quoted string is one word with its quotes and its escape pairs (`\` + the next character) kept, and may run over line ends. An unclosed block comment appends `Line <n>: comment not closed` (`<n>` its `/*` line), an unclosed string `Line <n>: quoted string not closed` (its opening quote's line); either ends the reading. Three tiers keep it within the time bound: a line with only single spaces and no `"`, `/`, HT, VT or FF is its own canonical text after stripping its blanks; a line with quotes but no comment mark and no backslash is split by one pattern; every other line is scanned token by token (P2). A generator: nothing is held but the current line.
module: s19_app/tui/a2l.py
modify: errors (append)
examples: (R-A2L-READ.7/1, LS) `["MAP 0x1C2D3E00/*c*/4026 RL 0 CM 0 1"]` → `(1, "MAP 0x1C2D3E00 4026 RL 0 CM 0 1")`; errors `[]` (base: the comment strip glues `0x1C2D3E004026`, C [H2a])
examples: (R-A2L-READ.7/2, LS) `["MAP 0x1C2D3E00/* old", " */4026 RL"]` → `(1, "MAP 0x1C2D3E00 4026 RL")` (base C [H2b])
examples: (R-A2L-READ.2/1, /2, LS) `ECU_ADDRESS` then HT, VT or FF, then `0x1234`, one per line → `(1, "ECU_ADDRESS 0x1234")`, `(2, "ECU_ADDRESS 0x1234")`, `(3, "ECU_ADDRESS 0x1234")`
examples: (R-A2L-READ.3/1, R-A2L-READ.4/1, LS) `["ECU_ADDRESS 0x1234<U+00A0>", "ECU_ADDRESS 0x1234<U+2028>"]` → the words `0x1234<U+00A0>` and `0x1234<U+2028>` kept whole; errors `Line 1: unexpected character U+00A0`, `Line 2: unexpected character U+2028` (the 9 characters of .3/1 the same, `U+0000` included)
examples: (R-A2L-READ.3/2) `ECU_ADDRESS<U+00A0>0x1234` → one word `ECU_ADDRESS<U+00A0>0x1234` and its error (base: NBSP splits it, C [RP-A14])
examples: (R-A2L-READ.4/2) `/* ° µ */` and `PHYS_UNIT "°C"` → errors `[]`
examples: (R-A2L-READ.4/3, CG-5 [L1]) a Latin-1 `0xB0` read as U+FFFD (R-A2L-001.7): in `/* 20 <U+FFFD>C */` and `"Temp <U+FFFD>C"` → no error; in the word `XL1_<U+FFFD>` → `Line <n>: unexpected character U+FFFD` (base: 0 errors, K [L1])
examples: (R-A2L-READ.1/4, LS) `["A\r\r\nB\r\nC\rD"]` → `(1, "A")`, `(3, "B")`, `(4, "C")`, `(5, "D")`
examples: (R-A2L-READ.8/1) `/* a /* b */ ECU_ADDRESS 0x1234` → `(1, "ECU_ADDRESS 0x1234")`
examples: (R-A2L-READ.8/2, R-A2L-READ.11/2, LS) `/* a /* b */ c */ ECU_ADDRESS 0x1234` → `(1, "c */ ECU_ADDRESS 0x1234")`; errors `Line 1: */ without /*`
examples: (R-A2L-READ.9/3, LS) `["// c\rECU_ADDRESS 0x1234"]` → `(2, "ECU_ADDRESS 0x1234")`
examples: (R-A2L-READ.10/1, LS) `["A", "/* never closed", "ECU_ADDRESS 0x1234"]` → `(1, "A")` only; errors `Line 2: comment not closed`
examples: (R-A2L-READ.11/1) `*/` alone on line 20 → `(20, "*/")`; errors `Line 20: */ without /*`
examples: (R-A2L-001.3.2/1, LS) `/begin CHARACTERISTIC X "C:\\"` → `(1, '/begin CHARACTERISTIC X "C:\\"')`, the string closed at its last quote (base: `\\"` does not close, C [RP-B24])
examples: (R-A2L-001.3.2/2, LS) `"a\"b" X` → `(1, '"a\"b" X')`
examples: (R-A2L-READ.13/1, LS) `FORMAT "/* x" ECU_ADDRESS 0x1234` → `(1, 'FORMAT "/* x" ECU_ADDRESS 0x1234')`
examples: (R-A2L-READ.14/1, LS) `['A "x', '/end ANNOTATION_TEXT', 'y" BIT_MASK 0x0FF0']` → one item `(1, 'A "x\n/end ANNOTATION_TEXT\ny" BIT_MASK 0x0FF0')`
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
req: R-A2L-001.1, R-A2L-001.2, R-A2L-001.4, R-A2L-001.5, R-A2L-001.6, R-A2L-001.7, R-A2L-READ.1, R-A2L-READ.5, R-A2L-READ.6, R-A2L-READ.12, R-A2L-READ.13, R-A2L-READ.17, R-A2L-READ.18, R-A2L-READ.19, R-A2L-READ.20, R-A2L-READ.21, R-A2L-READ.22, R-A2L-READ.31, R-A2L-READ.50, R-A2L-004.11, R-A2L-READ.52
in: Path path; A2LProgress? progress = None
out: tuple(list[dict] sections, list[str] errors)
func: changed (DE-2, DE-3; I-11.1). was: line-based — a line starting with `/begin` opens a section (keyword = its second blank-split part, `UNKNOWN` when none; `meta` = the raw rest), a line starting with `/end` closes the innermost, every other line is appended raw; no name check; comments and strings not read; `Unclosed /begin sections detected.` at the end. / now: opens `path` as base (text mode, `utf-8`, errors `replace`, universal newlines; `os.fstat` only with a callback; a report `(handle.buffer.tell(), total)` every 4 096 lines and `(total, total)` after the read; an `OSError` other than a missing file re-raised before the final report). First, if the file's first two bytes are `FF FE` or `FE FF`, returns `([], ["File is UTF-16 encoded; save it as UTF-8 and load it again."])`; a UTF-8 BOM is dropped. Then feeds the lines to `_lex_a2l_lines` and builds the tree from its canonical lines: a line with no `/` (or none of `/begin`, `/end`, `/include` in any case) is appended to the innermost section as one run; another line is split by `_line_words`, where a word equal to `/begin` or `/end` in any letter case (and only such a whole word) is structure: `/begin` opens a section whose keyword is the next word wherever it stands (later lines included); `/end` closes the innermost open section and consumes the next word as its name — a name other than the section's keyword appends `Line <n>: /end <name> does not close /begin <keyword>`, no open section appends `Line <n>: /end without /begin`; an `/include` word appends `Line <n>: /include <next word without quotes> is not read` and stays a word. Own words go to `meta` (the keyword's line, before any child) or to a run in `lines` with its line in `line_numbers`; a child section leaves `""` in its parent's `lines`. A `/begin` or `/end` with no word after it in the file is an ordinary word. Words outside every section are dropped (as base). `Unclosed /begin sections detected.` stays.
module: s19_app/tui/a2l.py
examples: (R-A2L-001.1/1, Inc 2 J4) `MEAS(SX, " ECU_ADDRESS 0x10 /begin IF_DATA XCP", "  KP_BLOB 0x10", " /end IF_DATA", " BIT_MASK 0x0FF0")` → SX `meta` `SX ""`, `lines` `["UWORD CM_ID 0 0 0 65535", "ECU_ADDRESS 0x10", "", "BIT_MASK 0x0FF0"]`; its child IF_DATA `meta` `XCP`, `lines` `["KP_BLOB 0x10"]`; errors `[]` (base: IF_DATA never opened, C [RP-C-J4])
examples: (R-A2L-001.1/2) `/* c */ /begin MEASUREMENT X ""` … → a MEASUREMENT section, `meta` `X ""`
examples: (R-A2L-001.1/3) `MEAS(X, " ECU_ADDRESS 0x1234 /end MEASUREMENT")` with no `/end` line of its own → X closed on that line, `lines` end with `ECU_ADDRESS 0x1234`; errors `[]`
examples: (R-A2L-001.1, [K7b]) `/begin INSTANCE IK7 "" T_U16 0x20 /end INSTANCE /begin INSTANCE IK7B "" T_U16 0x40 /end INSTANCE` on one line → two INSTANCE sections, `meta` `IK7 "" T_U16 0x20` and `IK7B "" T_U16 0x40`, both with `start_line` = `end_line`; errors `[]` (base: `Unclosed /begin sections detected.`, K)
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
examples: (R-A2L-004.11, holds as base) case_06 with a callback → reports rise, `seen[-1]` = `(size, size)`, at most `lines // 4096 + 1` reports (TC-B100-73); a read failing at line 5 000 → exactly `1` report, then `OSError`
examples: (R-A2L-READ.52/1) see `_lex_a2l_lines`; the base medians measured in the same session (P1, P2): case_06 parse `5.898` s (bound `8.85` s), software_a `0.653` s (bound `0.98` s)

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
req: R-A2L-001.3.1
in: str meta
out: tuple[str, Optional[str]] parsed
func: unchanged (`a2l.py:255`, public facade `a2l_parse`). The name and long identifier of a section's `meta`; `UNKNOWN` for an empty `meta`. No longer called for MEASUREMENT and CHARACTERISTIC by `extract_a2l_tags` (their name comes from `_tag_header`); still the name rule of record layouts, compu methods, compu tables, AXIS_DESCR and Inc 2a. Its result moves only through `_parse_first_field` and the canonical `meta`.
module: s19_app/tui/a2l.py
examples: (holds on base) `'RL_U16'` → (`RL_U16`, `None`); `'CM_ID "" IDENTICAL "%.0" ""'` → (`CM_ID`, `None`)
examples: (I-11.8 a) a CHARACTERISTIC whose name stands on the line after its keyword, `meta` `""` → (`UNKNOWN`, `None`) — so a consumer naming sections by it disagrees with the tag's name

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
examples: (R-A2L-READ.23, [K1]) `/begin MEASUREMENT` ↵ `XK1` ↵ `"long id"` ↵ `UWORD` ↵ `CM_ID` ↵ `0` ↵ `0` ↵ `0` ↵ `65535` ↵ `ECU_ADDRESS` ↵ `0x1234` → (`XK1`, `long id`, `["UWORD", "CM_ID", "0", "0", "0", "65535"]`, `8`) (base: `UNKNOWN`, datatype None, no address, K)
examples: (R-A2L-READ.23, [K1c]) CHARACTERISTIC `CK1` one word per line → (`CK1`, `long id`, `["VALUE", "0x2000", "RL_U16", "0", "CM_ID", "0", "65535"]`, `9`) (base: name `UNKNOWN`, K)
examples: (R-A2L-READ.23/2, /3) RP-B19 `/begin MEASUREMENT /* c */ X ""` and RP-B18 `X/*c*/ ""` → name `X`
examples: (R-A2L-READ.24/1) V171 `ASAM.M.SCALAR.UBYTE.IDENTICAL` (long identifier on the next line) → long identifier `Scalar measurement` (base: `None`, C [FX-other])
examples: (R-A2L-READ.24/2) `case_07_stress_smoke/firmware.a2l` → `long_identifier` `None` for 12/12 tags, `header` `[]`
examples: (R-A2L-001.3.1/1, /3) `X "a b"` → long identifier `a b`; `X "x/*y*/z"` → `x/*y*/z`
examples: (R-A2L-001.3.1/2) `X ""` → long identifier `None`, rest after the `""`
examples: (R-A2L-READ.25/1) BalanceTube `model.MainClass.gameController.sm` (header over 6 commented lines) → header `["UBYTE", "esdl_model_GameControllerStatemachineStates", "1", "100.0", "0", "3"]` (Inc 2 B2 P1b)
examples: (R-A2L-READ.25, [K2]) `/begin MEASUREMENT XK2 ""` ↵ `UWORD` ↵ `CM_ID` ↵ `0` ↵ `0` ↵ `0` ↵ `65535` ↵ `ECU_ADDRESS 0x1234` → header `["UWORD", "CM_ID", "0", "0", "0", "65535"]` (base: datatype None, length None, K)
examples: (R-A2L-READ.25/3, RP-B14) `/begin MEASUREMENT X "" UWORD CM_ID 0 0 0 65535` → header from `meta`: `["UWORD", "CM_ID", "0", "0", "0", "65535"]`
examples: (R-A2L-READ.26/1, RP-B23) `/begin CHARACTERISTIC X "d" VALUE 0x2000 RL_U16 0 CM_ID 0 65535` → (`X`, `d`, `["VALUE", "0x2000", "RL_U16", "0", "CM_ID", "0", "65535"]`, `9`)
examples: (R-A2L-READ.26/3, RP-B21) `VALUE 0x2000/*c*/RL_U16 0 CM_ID 0 65535` → header `["VALUE", "0x2000", "RL_U16", "0", "CM_ID", "0", "65535"]`
examples: (R-A2L-READ.26, R-A2L-READ.27, [K3]) `/begin CHARACTERISTIC CK3 "d" VALUE 0x1000 RL_U16 0 CM_ID 100 10000` ↵ `ECU_ADDRESS_EXTENSION 0` ↵ `BYTE_ORDER MSB_LAST` … → header `["VALUE", "0x1000", "RL_U16", "0", "CM_ID", "100", "10000"]`; `ECU_ADDRESS_EXTENSION` never a header word (base: kind `ECU_ADDRESS_EXTENSION`, address `0x0`, deposit `BYTE_ORDER`, K)
examples: (R-A2L-READ.26, [K4]) `/begin CHARACTERISTIC CK4 "d" CUBE_5 0x123 RL_U16 1 CM_ID 0 10` ↵ `NUMBER 10000` … → header `["CUBE_5", "0x123", "RL_U16", "1", "CM_ID", "0", "10"]` (base: kind `NUMBER`, address `0x2710`, K)
examples: (R-A2L-READ.27/2, Inc 2 C) `UWORD CM_ID 0 0 0 BIT_MASK 0x0FF0` after `SX ""` → header `["UWORD", "CM_ID", "0", "0", "0"]` (5 words; BIT_MASK is the first keyword)
examples: (R-A2L-READ.27/3) `/begin CHARACTERISTIC Q` ↵ `ECU_ADDRESS 0x10` ↵ `LENGTH 2` → (`Q`, `None`, `[]`, `1`)
examples: (R-A2L-READ.27/1) case_07's MEASUREMENTs (no long identifier, no header) → header `[]` for 12/12

_tag_keyword_lines
req: R-A2L-READ.29, R-A2L-READ.30, R-A2L-READ.31, R-A2L-READ.33, R-A2L-READ.37
in: list[tuple[str, int]] words; int start
out: list[tuple[str, int]] keyword_lines
func: new (DE-4). From `words[start:]`, place marks skipped: each unquoted word that is a key of `_TAG_KEYWORD_ARITY` (the CTX-A2L-TAG keyword list with its arities) gives one item `(canonical "<KEYWORD> <arg> …", line of the keyword)`, its arguments being the next `arity` words (any words, as REF consumes them); MATRIX_DIM takes the next 1 to 3 words that are number words (`_number_word`), and stays alone when none follows. A word that is neither a keyword nor an argument is dropped (base: a line not starting with a keyword was ignored).
module: s19_app/tui/a2l.py
examples: (R-A2L-READ.29/1, RP-B5) `ECU_ADDRESS` (line 23) ↵ `0x1234` (line 24) → `[("ECU_ADDRESS 0x1234", 23)]` (base: no address, C [RP-B5])
examples: (R-A2L-READ.29/2, RP-B6) `ECU_ADDRESS` ↵ `/* moved */` ↵ `0x1234` → `[("ECU_ADDRESS 0x1234", 23)]`
examples: (R-A2L-READ.29/3, Inc 2 N) `BIT_MASK` ↵ `0x0FF0` ↵ `ECU_ADDRESS 0x10` → `[("BIT_MASK 0x0FF0", …), ("ECU_ADDRESS 0x10", …)]`
examples: (R-A2L-READ.29/4) `ECU_ADDRESS 0x10` ↵ `MATRIX_DIM 2` ↵ `3` → `[("ECU_ADDRESS 0x10", …), ("MATRIX_DIM 2 3", …)]`
examples: (R-A2L-READ.30/1, RP-B12) `ECU_ADDRESS 0x1234 BYTE_ORDER MSB_LAST` → `[("ECU_ADDRESS 0x1234", 23), ("BYTE_ORDER MSB_LAST", 23)]` (base: byte order big, C [RP-B12])
examples: (R-A2L-READ.30/2, Inc 2 J3) `/begin IF_DATA ETK KP_BLOB 0x10 /end IF_DATA BIT_MASK 0x0FF0` → `[…, ("BIT_MASK 0x0FF0", …)]`
examples: (R-A2L-READ.30, [K5]) XK5's words after its header → `[("ECU_ADDRESS 0x18", 1), ("ECU_ADDRESS_EXTENSION 3", 1), ("READ_WRITE", 1)]`
examples: (R-A2L-READ.33/2, RP-A29) `DISPLAY_IDENTIFIER XM_disp /* shown name */` → `("DISPLAY_IDENTIFIER XM_disp", …)`
examples: (R-A2L-READ.37/2, RP-B26) `MATRIX_DIM 2 2` → `("MATRIX_DIM 2 2", …)`
examples: (R-A2L-READ.31/3) a CURVE whose AXIS_DESCR holds `BYTE_ORDER MSB_LAST` → no `BYTE_ORDER` item (the axis words are the child's)

_number_word
req: R-A2L-READ.3, R-A2L-READ.34, R-A2L-READ.35, R-A2L-READ.36
in: str word
out: Optional[int] value
func: new. `0x` or `0X` followed by 1 to 16 ASCII hex digits → that value; 1 to 20 ASCII decimal digits → that value in base 10, leading zeros included; any other word (a sign, `_`, `0b`/`0o`, a non-ASCII digit, a longer run, a quoted word) → `None`. Replaces `int(x, 0)` for every address, length and count word of a tag or span.
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
examples: (R-A2L-READ.26, [K4]) `["CUBE_5", "0x123", "RL_U16", "1", "CM_ID", "0", "10"]` → `0` (kind `CUBE_5`, address `0x123`)
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
req: R-A2L-READ.37, R-A2L-READ.36, R-A2L-014
in: list[str] lines; Optional[dict] header
out: Optional[int] length
func: changed. was: `DATA_SIZE` and `MATRIX_DIM` by `int(parts[1], 0)` per line; the first MATRIX_DIM number. / now: `lines` are `_tag_keyword_lines` texts; numbers by `_number_word`; MATRIX_DIM = the product of its numbers (1 when absent); an unreadable DATA_SIZE word → `None` with no inference (DE-6). The cap is the caller's.
module: s19_app/tui/a2l.py
examples: (R-A2L-READ.37/2) `["ECU_ADDRESS 0x1234", "MATRIX_DIM 2 2"]`, datatype `UWORD` → `8` (base `4`, C [RP-B26])
examples: (R-A2L-READ.37/1) V161 `ASAM.M.MATRIX_DIM_8_4_2.UBYTE.IDENTICAL` → `64` (base `8`)
examples: (R-A2L-READ.29/4) `["MATRIX_DIM 2 3"]`, UWORD → `12`
examples: (holds on base) `[]`, datatype `SWORD` → `2`

_infer_length_characteristic
req: R-A2L-READ.37, R-A2L-READ.36, R-A2L-READ.38, R-A2L-015, R-A2L-016, R-A2L-017
in: list[str] lines; Optional[dict] header; Optional[dict[str, dict]] record_layouts_by_name = None
out: Optional[int] length
func: changed. was: `LENGTH`, `MATRIX_DIM`, `NUMBER` by `int(parts[1], 0)`; the first MATRIX_DIM number. / now: `_tag_keyword_lines` texts; numbers by `_number_word`; MATRIX_DIM = the product; an unreadable LENGTH or NUMBER word → `None` (DE-6). The VALUE-only layout resolution stays (CG-2 would widen it).
module: s19_app/tui/a2l.py
examples: (R-A2L-READ.37/1) V161 `ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR` (`MATRIX_DIM 3 4 1`) → `24` (base `6`)
examples: (R-A2L-READ.38/2, H1) ASCII with `["NUMBER 1000000000000"]` → `1000000000000` (the caller caps it)
examples: (holds on base, `tests/test_a2l_record_layout_length.py:53`) `[]`, VALUE on `_RL_U16` → `2`
examples: (CG-2, [K6]) `["MATRIX_DIM 4"]`, VAL_BLK on `RL_U16` → `None` today and after Inc 11 unless CG-2 is accepted (then `8`)

extract_a2l_tags
req: R-A2L-005.1, R-A2L-005.2, R-A2L-001.2, R-A2L-READ.7, R-A2L-READ.12, R-A2L-READ.23, R-A2L-READ.28, R-A2L-READ.30, R-A2L-READ.32, R-A2L-READ.33, R-A2L-READ.36, R-A2L-READ.38, R-A2L-READ.39
in: list[dict] sections; dict[str, dict]? record_layouts_by_name = None; dict[str, dict]? compu_methods_by_name = None; list[str]? errors = None
out: list[dict] tags
func: changed (DE-4, DE-6, DE-7; I-11.3, I-11.5). was: name and long identifier from `parse_begin_meta(meta)`; the MEASUREMENT header from `_first_header_line` (the first line with 6 words), the CHARACTERISTIC header from `assemble_characteristic_header(lines)`; the field loop over raw `lines` keyed on each line's first word with `int(x, 0)`; the last line wins; no error. / now: per MEASUREMENT or CHARACTERISTIC section, `words = _section_words(section)`; `(name, long id, header, rest) = _tag_header(…)`; the MEASUREMENT header via `parse_measurement_header(" ".join(header))`, the CHARACTERISTIC header via `_characteristic_from_tokens(header)` when it has 7 words; a header of 1 to 5 (MEASUREMENT) or 1 to 6 (CHARACTERISTIC) words appends `Line <start_line>: <section> <name> has <k> of its <m> header words`; the base field loop runs over `_tag_keyword_lines(words, rest)` (`parts = text.split(" ")`, as base on canonical text), with `_number_word` for ECU_ADDRESS, DATA_SIZE and LENGTH, the MATRIX_DIM product, DISPLAY_IDENTIFIER = its one argument; the second and every later occurrence of a keyword appends `Line <its line>: <keyword> is declared twice in <section> <name>` and the last wins (D-6 A); the final length (inline, inferred, layout span, and the external-axis post-pass) through `_bounded_length`, a tag length outside 1 … 1048576 appending `Line <start_line>: <section> <name> has the length <length>, outside 1 to 1048576 bytes`. Errors go to `errors` when it is a list. AXIS_DESCR capture, link maps, byte-order fallbacks, memory region and the post-pass as base.
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
examples: (R-A2L-READ.23, [K1]) the two one-word-per-line MEASUREMENTs → `XK1` at `0x1234` and `XK1B` at `0x1236`, datatype `UWORD`, length `2`, description `long id`; no `A2L_DUPLICATE_SYMBOL` (base: both `UNKNOWN`, one duplicate issue, K)
examples: (R-A2L-READ.26, [K3]) → `CK3` kind `VALUE`, address `0x1000`, deposit `RL_U16`, length `2`, byte order `little` (base: kind `ECU_ADDRESS_EXTENSION`, address `0x0`, K)
examples: (R-A2L-READ.26, [K4]) → `CK4` kind `CUBE_5`, address `0x123`, deposit `RL_U16` (base: kind `NUMBER`, address `0x2710`, K)
examples: (R-A2L-READ.30, [K5]) → `XK5` address `0x18`, datatype `FLOAT64_IEEE`, length `8`; errors `[]` (base: address None, `Unclosed …`, K)
examples: (R-A2L-001.2/7, [K5b]) `/* moved */ ECU_ADDRESS 0x1234` → address `0x1234` (base: None, K)
examples: (R-A2L-READ.25/1) BalanceTube → 104/104 MEASUREMENTs with datatype and length (`model.MainClass.gameController.sm` `UBYTE`, `1`)
examples: (R-A2L-READ.25/2) V161 and V171 `ASAM.M.VIRTUAL.SCALAR.SWORD.PHYSICAL` → datatype `SWORD`, length `2`, conversion `CM.VIRTUAL.EXTERNAL_VALUE`
examples: (R-A2L-READ.26/1, RP-B23) → address `0x2000`, kind `VALUE`, deposit `RL_U16`
examples: (R-A2L-READ.27/1) case_07 → 12/12 tags with their e07fb00 address, length, limits and unit
examples: (R-A2L-READ.27/3) `/begin CHARACTERISTIC Q` ↵ `ECU_ADDRESS 0x10` ↵ `LENGTH 2` → address `16`, length `2`, no error
examples: (R-A2L-READ.28/1, Inc 2 C, `/begin` on line 20) → `Line 20: MEASUREMENT SX has 5 of its 6 header words`; datatype `UWORD`, `bit_org` `0x0FF0`, upper limit `None`
examples: (R-A2L-READ.28, [K7]) `/begin MEASUREMENT XK7 "" UWORD CM_ID 0 0` on line 20 → `Line 20: MEASUREMENT XK7 has 4 of its 6 header words`; datatype `UWORD`, length `2` (base: datatype None, no error, K)
examples: (R-A2L-READ.28/2, H3c, `/begin` on line 20) → `Line 20: CHARACTERISTIC Synthetic map has 6 of its 7 header words`; address `None` (DE-7)
examples: (R-A2L-READ.28/3, R-A2L-READ.32/4) the 35 tracked files → `0` such errors
examples: (R-A2L-READ.32/1) `ECU_ADDRESS 0x10` line 22, `ECU_ADDRESS 0x20` line 23 → `Line 23: ECU_ADDRESS is declared twice in MEASUREMENT X`; address `32`
examples: (R-A2L-READ.32/2, /3, Inc 2 P) → `Line <n>: BYTE_ORDER is declared twice in MEASUREMENT X`; `Line <n>: BIT_MASK is declared twice in MEASUREMENT SX`
examples: (R-A2L-READ.33/1) V161/V171 `ASAM.M.SCALAR.UBYTE.IDENTICAL` → `display_identifier` `DI.ASAM.M.SCALAR.UBYTE.IDENTICAL` (base: with `/* optional display identifier */`, C [FX-other]); 6/6
examples: (R-A2L-READ.33/2, RP-A29) → `XM_disp`
examples: (R-A2L-READ.36/1, RP-B33) `ECU_ADDRESS 0x12_34` → address `None`
examples: (R-A2L-READ.38/1, /2, R-A2L-READ.39/1, `/begin` on line 20) `LENGTH 0` → length `None`, `Line 20: MEASUREMENT X has the length 0, outside 1 to 1048576 bytes`; `LENGTH 1048577` → `… 1048577 …`; `LENGTH 99999999999` → `… 99999999999 …`; ASCII `NUMBER 1000000000000` → `Line 20: CHARACTERISTIC SX has the length 1000000000000, outside 1 to 1048576 bytes`
examples: (R-A2L-READ.38/1, DE-6) `LENGTH -5` → length `None`, no length error (`-5` is no number word; F-E2-3)
examples: (R-A2L-READ.38/3) `LENGTH 1048576` → `1048576`
examples: (R-A2L-005.2, holds on base) INSTANCE, BLOB and TYPEDEF_* sections → no tag
examples: (I-11.5, holds on base) `errors` not given → the same tags; no error list

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
examples: (R-A2L-READ.43/2, F-E2-5) a VAL_BLK typedef on `RL_U16` with `MATRIX_DIM 3`, INSTANCE `MATRIX_DIM 2` → `12` only with CG-2 (the layout `RL_U16` names no size); with the case's `NUMBER 3` → `12` only with CG-3
examples: (R-A2L-READ.43/3) an ASCII typedef `NUMBER 8` → `8`
examples: (R-A2L-READ.44/1, /2) `TYPEDEF_BLOB TB "" 6` → `6`; `TYPEDEF_STRUCTURE TS "" 12`, INSTANCE `MATRIX_DIM 3` → `36`
examples: (R-A2L-READ.45/1 … /3) an INSTANCE of a TYPEDEF_AXIS, of a CURVE TYPEDEF_CHARACTERISTIC, of `T_NONE` → `length` `None` each (tracked: 1 TYPEDEF_AXIS, 2 unknown, C [FX-total])
examples: (R-A2L-READ.46/1, /2) BLOB sizes `0` and `1048577` → `length` `None`; INSTANCE of T_U16 with `MATRIX_DIM 4294967296` → `None`
examples: (R-A2L-READ.41, [K7b]) the two one-line INSTANCEs → `IK7` at `0x20`, `IK7B` at `0x40`, length `2` each

parse_a2l_file
req: R-A2L-READ.6, R-A2L-READ.39, R-A2L-READ.40, R-A2L-READ.48, R-A2L-READ.49, R-A2L-READ.52
in: Path path; A2LProgress? progress = None
out: dict payload
func: changed (I-11.2, I-11.6). was: `build_section_tree` → record layouts, compu methods, compu tables → `extract_a2l_tags` → the 7-key payload. / now: the same, with `extract_a2l_tags(…, errors=errors)` appending the tag errors after the builder's, and the 8th key `declared_spans` = `extract_declared_spans(sections, record_layouts_by_name)`.
module: s19_app/tui/a2l.py
examples: (R-A2L-READ.6/1) a UTF-16 LE file → `errors` `["File is UTF-16 encoded; save it as UTF-8 and load it again."]`, `tags` `[]`, `declared_spans` `[]`
examples: (R-A2L-READ.40/1) RP-D1 → `declared_spans` `[{"name": "B1", "kind": "BLOB", "address": 16, "length": 2}]`, `tags` without B1
examples: (R-A2L-READ.48/1) the 35 tracked files → tags, spans and errors equal to `ref_read_a2l` on the compared fields, `0` differences, within `120` s on cachyos-rtx
examples: (R-A2L-READ.49/1) the 35 tracked files → 234,532 tags identical to `[I/O: e07fb00 tag fixture]` on the six fields; the tag count per file equal (35/35); the 122 listed tags with REF's values
examples: (R-A2L-READ.17/1) V171 → `errors` `[]` (base `["Unclosed /begin sections detected."]`)
examples: (R-A2L-READ.52/1) case_06 and software_a, median of 3 → at most `1.5` × the e07fb00 median measured in the same session (P2: base `5.898` s and `0.653` s)

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
examples: (R-A2L-READ.23, [K1]) → `0` `A2L_DUPLICATE_SYMBOL` (base: `A2L symbol 'unknown' is defined multiple times.`, K)

iter_section_lines
req: R-A2L-READ.50, R-A2L-READ.51, R-A2L-076
in: List[dict] sections; int depth = 0
out: List[str] lines
func: changed. was: `"{indent}- {name} {meta} (lines {start}-{end})"` with the raw `meta`. / now: the same line over the canonical `meta` (F-E2-2), each character U+0000 … U+001F, U+007F … U+009F, U+2028 and U+2029 of `name` and `meta` replaced by U+FFFD.
module: s19_app/tui/a2l.py
examples: (R-A2L-READ.50/1, RP-A27) XH → `- CHARACTERISTIC XH "one-line header" VALUE 0x00003000 RL_U32 0 CM_ID 0 100 (lines <a>-<b>)` (base: `… 0x00003000/*old 0x1000*/ RL_U32 …`, C [RP-A27])
examples: (R-A2L-READ.50/2) `VALUE  0x00003000` on the `/begin` line → one blank between them
examples: (R-A2L-READ.50/3) → `"one-line header"` with its quotes
examples: (R-A2L-READ.51/1, RP-A21) `"one-line<U+001E>header"` → `"one-line<U+FFFD>header"`, the line unbroken

render_a2l_view
req: R-A2L-075, R-A2L-076, R-A2L-077, R-A2L-READ.51
in: dict? a2l_data; list[dict]? tag_checks = None; int? max_tag_lines = None
out: str text
func: changed. was: any parse error → only `A2L parse errors:` and its lines (`a2l.py:3650-3652`). / now: `No A2L loaded.` for no payload; else, in this order and separated by one empty line, the block `A2L parse errors:` + `- <error>` lines when there are errors, the block `A2L Sections:` + `iter_section_lines` when there are sections, then `A2L Tags:` + the base tag lines (truncation as base); `No A2L sections found.` only when there is neither an error nor a section; every line's characters U+0000 … U+001F, U+007F … U+009F, U+2028, U+2029 replaced by U+FFFD before the join, so `str.splitlines()` (`services/a2l_service.py:26`) breaks only at the joins.
module: s19_app/tui/a2l.py
examples: (R-A2L-076/1, R-A2L-077, AT-B103-I11-3) `merge_inc_test.a2l` → `A2L parse errors:` ↵ `- Line <n>: /include included.a2l is not read` ↵ `` ↵ `A2L Sections:` ↵ … (base: the errors only)
examples: (R-A2L-076/2, R-A2L-077/1) HDR + a stray `/end X` + `MEAS(X, " ECU_ADDRESS 0x10")` → the errors block, then `A2L Sections:`, then `A2L Tags:` with `- MEASUREMENT X: 0x00000010 len=2 mem=unknown`
examples: (R-A2L-READ.51/1) a long identifier holding VT, FF, U+001C, U+001E, U+0085, U+2028, U+2029, ESC or NUL → U+FFFD in its line; every summary line matches `^(\s*- |A2L |\.\.\. |No A2L)` or is empty, 9/9 (base: the line breaks after the address, C [RP-A19 … A26c])
examples: (R-A2L-075, holds on base) `{"errors": ["E1"], "sections": [], "tags": []}` → `A2L parse errors:\n- E1`

S19TuiApp._compose_screen_a2l
req: R-TUI-042a.2
in:
out: Container screen
func: changed (D-1 A; G2). was: `DataTable(id="a2l_tags_list", zebra_stripes=True, cursor_type="row", cell_padding=0)` (`app.py:8516-8521`), so adjacent cells paint with no gap. / now: `cell_padding=1`; nothing else in the screen changes (the `density-compact` class and the pane padding stay, AT-038b).
module: s19_app/tui/app.py
examples: (R-TUI-042a.2/1, AT-B103-I11-1, real Explorer, SYNMAP) widths 220 and 160 → the painted row holds `0x1C2D3E00` and `2266` in separate cells with at least one blank between; `0x1C2D3E002266`, `SYN_MAP_W0x1C2D3E00`, `17921792` and `unknown0..` painted `0` times (base: `✓ SYN_MAP_W0x1C2D3E002266  formula17921792    yes  unknown0..4095%.0`, C [W220])
examples: (R-TUI-042a.2/2) widths 118, 100, 80 → the same for every cell shown (base: `SYN_MAP_W0x1C2D3E002266` at every width, C [W118 … W80])
examples: (AT-B103-I11-1) the detail card's first line `✓ SYN_MAP_W  0x1C2D3E00` (holds on base, C [W220 card])
examples: (holds on base, AT-038b) `#a2l_tags_pane` keeps the class `density-compact`

ref_read_a2l
req: R-A2L-READ.48, R-A2L-READ.49
in: str text
out: dict reading
func: new, test side (G-T1; `tests/support/b103_a2l_ref.py`). The reference reading: imports nothing from `s19_app`; written from `../01-requirements.md` § Definitions and rows S2.1/S2.2 only, never from the reader's code. Its own lexer (a single regex pass over the whole text after the BOM and line-end normalisation: ASCII blanks; `/* … */` and `//` as word breaks; strings with escape pairs over line ends; stray `*/`; unexpected characters), its own tree (whole-word `/begin`/`/end` in any case, the keyword the next token, innermost close with the name check), its own header split (name; long identifier when quoted; 6 or 7 words to the first keyword or child; short MEASUREMENT headers by position, short CHARACTERISTIC headers giving no field, DE-7) and keyword reader (the arity list, MATRIX_DIM 1–3 numbers, last wins, duplicates), its own number words, cap and spans. Returns `{"tags": [{name, long_identifier, address, datatype, byte_order, bit_mask, matrix_dim, kind, deposit, conversion, length, axis_counts, record_layout}], "spans": [{name, kind, address, length}], "errors": [(text, line)]}`. The comparison is field by field on R-A2L-READ.48's list, errors as a sorted multiset. Shape model: `../evidence-e1/e1-census.py` (`ref_lex`, `ref_tree`, `split_header`, `ref_fields`); E4 writes its own, and its mutant check (`.2`, `.7`, `.12`, `.17` or `.25` reverted in the reader → ≥ 1 difference) proves it can fail.
module: tests/support/b103_a2l_ref.py
examples: (R-A2L-READ.48/2) the hostile corpus (144 shapes of `02-test-cases.md` + the 11 reductions K1 … L1, CG-1) → `0` differences, 155/155
examples: (R-A2L-READ.48/2) RP-B40 → errors `[("*/ without /*", <line>)]`, X's address `4660`
examples: (R-A2L-READ.48 neg) the reader with `_tag_header` reading the name from `meta` only → [K1] differs (`UNKNOWN`) → RED

run_corpus_differential
req: R-A2L-READ.48, R-A2L-READ.52
in: Path manifest; Path files_dir
out: dict report
func: new, E5 evidence only (CG-6; runner only, never a CI test; never committed corpus content). Checks every file's sha256 against `../../design/a2l-corpus/manifest.tsv` (158 unique files, duplicates by content skipped), then reads each with the reader under test and with `ref_read_a2l`, and the e07fb00 reader for the time ratio; writes per class (the census's 12 classes and the 7 of this graph's corpus table) the count before and after, every difference as `(n, line, field, reader, REF)` with no file text, and the time ratio per file. Expected after Inc 11: classes 1, 3, 4, 5 → `0` objects; class 2 → `0` for every MEASUREMENT whose header REF reads; class 6 → the VAL_BLK/ASCII remainder of CG-2/CG-3 and the CURVE/MAP of CG-4, counted; class 7 → `19` header errors; the `U+FFFD` word errors counted on the 11 Latin-1 files (CG-5); every file within `1.5` × its e07fb00 time. Transcript in `inc-11/evidence-e5/`.
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
desc: the CTX-A2L-TAG keyword list with its arities, MATRIX_DIM as 1 to 3 numbers; distinct from `MEASUREMENT_BODY_KEYWORDS` (`a2l.py:113`, kept for `_extended_kind_anchor` and `parse_measurement_header`'s callers).

[Data: _HEADER_WORDS]
in: dict[str, int]
desc: the header word count per section kind (MEASUREMENT 6, CHARACTERISTIC 7, BLOB 2, INSTANCE 2, TYPEDEF_MEASUREMENT 6, TYPEDEF_CHARACTERISTIC 6, TYPEDEF_BLOB 1, TYPEDEF_STRUCTURE 1).

[Data: a2l_extract.__all__]
in: list[str]
desc: I-11.7. Gains `extract_declared_spans`.

[I/O: A2L file]
desc: the file `build_section_tree` reads: UTF-8 (a BOM dropped), UTF-16 refused, LF/CRLF/CR line ends.

[I/O: e07fb00 tag fixture]
desc: `tests/fixtures/b103_i11/e07fb00_tags.jsonl`: for each of the 35 tracked files, its tag count and each tag's six fields (name, address, length, datatype, byte order, BIT_MASK word), taken on a clean checkout of `e07fb00` with the transcript kept (02-test-cases R-A2L-READ.49/1). The oracle of R-A2L-READ.49: 234,654 tags, of which 234,532 must stay identical; the exceptions are the 122 tags of `../01-requirements.md` "Defect tags at e07fb00" (BalanceTube 104, V161 6, V171 10, update_test1 1, update_test2 1), each taking REF's values. If CG-2 is accepted, every tracked VAL_BLK or ASCII on a layout whose name carries no size joins the exceptions (count owed by the E1 addendum).

[I/O: public A2L corpus]
desc: `~/a2l-corpus/files/` on cachyos-rtx only (licenses mixed: never copied into the repo); identity by `../../design/a2l-corpus/manifest.tsv` sha256.

[Interface: A2L Explorer tag table]
desc: `#a2l_tags_list`, the 16 cells of `_build_a2l_table_cells`; one blank column between cells after Inc 11.

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
decision: PROPOSED — the graph shows the canonical `meta` (the words on the keyword's line); E3 rules on rewording R-A2L-READ.50 to "its words on the line of its keyword, joined by single spaces"

finding F-E2-3 R-A2L-READ.39/1's `-5` input contradicts R-A2L-READ.36
anchor: extract_a2l_tags
seen: R-A2L-READ.38/1 and .39/1 list `LENGTH -5` among the lengths below 1; R-A2L-READ.36/2 makes `-0x10` and `+16` no number word, so `-5` is no number either
cause: a length that is not a number has no value to print in `<length>`
effect: .39/1 cannot reach 5/5
decision: PROPOSED — `LENGTH -5` gives no length (DE-6, meets .38/1) and no length error; .39/1 becomes 4/4 (0, 1048577, 99999999999, `NUMBER 1000000000000`)

finding F-E2-4 E1's REF model reads a short CHARACTERISTIC header by position
anchor: ref_read_a2l
seen: `../evidence-e1/e1-census.py:567` takes the address from the second header word whatever the count; TC-099 (`tests/test_a2l_multiline_headers.py:441-446`) pins fail-closed for fewer than 7 params
cause: no row says how a short CHARACTERISTIC header is read
effect: the E4 REF and the reader could disagree on H3c-like shapes (R-A2L-READ.48/2)
decision: DE-7 (fail closed: no header field; the error of .28); E4's REF follows it; E3 may rule otherwise

finding F-E2-5 TC R-A2L-READ.43/2 cannot pass on the rows as written
anchor: extract_declared_spans
seen: the case's typedef is a VAL_BLK on `RL_U16` with `NUMBER 3`; R-A2L-016 sizes a VAL_BLK by MATRIX_DIM, and the base resolves a layout's datatype for VALUE only ([K6]: VAL_BLK on `RL_U16` → None)
cause: two gaps, CG-2 and CG-3
effect: the expected `12` is unreachable without CG-2 (and CG-3 for the NUMBER form)
decision: PROPOSED — accept CG-2 (and CG-3), or change the case to a VAL_BLK on a layout whose name carries its size (e.g. `RL.FNC.UWORD.ROW_DIR` style with `__UWORD_Z`) with `MATRIX_DIM 3`

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
decision: CG-2 (PROPOSED, E1 addendum)

finding F-E2-8 two number-word rules in one module
anchor: _number_word
seen: `_a2l_number` (`a2l.py:949`, MEMORY_SEGMENT, batch-101 Inc 11): a sign allowed, at most 8 hex or 10 decimal digits; CTX *number word* (R-A2L-READ.34 … .36): no sign, up to 16 hex or 20 decimal digits
cause: two rows families define number words differently (R-A2L-036.x and R-A2L-READ.34 … .36)
effect: none on the 35 files; a reviewer may expect one rule
decision: both kept (different rows); flagged for the canon fold-in (one CTX term, or two named terms)
