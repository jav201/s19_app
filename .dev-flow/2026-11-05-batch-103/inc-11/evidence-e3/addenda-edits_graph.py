EDITS = [
    # header
    ("scripts and transcripts copied in the scratchpad folder `e3c2-11`).\n",
     "scripts and transcripts copied in the scratchpad folder `e3c2-11`). **E3 addenda (2026-11-07; `../E3-rulings.md` \"Round 3 rulings\"):** E3S-24 (a *surplus word* is any hex-like word, not only a number word), E3S-27 (a byte-order source that is no byte-order word gives no address and READ.68's error), E3S-28 (the tag words stream: `_line_words` and `_section_words` yield, `_tag_keyword_lines` consumes one stream and caps what an item carries, and `_lex_a2l_lines` builds no per-line word list) and E3S-29 (the external-axis post-pass compares a standing size) applied in `_lex_a2l_lines`, `_line_words`, `_section_words`, `_tag_keyword_lines`, `extract_a2l_tags` and `parse_a2l_file`; 79 rows, 265 cases; still 37 nodes. Source `E3R3` = the addenda's memory model on cachyos-rtx (`../01-requirements.md` source E3R3; `/tmp/b103-e3a-11/`).\n"),
    # DE-4
    ("the existing field rules then run on those texts |",
     "the existing field rules then run on those texts. **Round 3 (E3S-28):** one stream, never a list: `_section_words` yields, `extract_a2l_tags` takes its first 10 words as the list `_tag_header` reads (name, long identifier, at most 7 header words and the one after) and hands the rest of the stream to `_tag_keyword_lines` |"),
    # DE-8
    ("a tag with no length gets no enriched byte size (E3S-18) | E3S-03:",
     "a tag with no length gets no enriched byte size (E3S-18). **Round 3:** a surplus word is any hex-like word (a number word, a word starting with a decimal digit, or one made only of hex digits and `_`; E3S-24, 0 on the corpus and the tracked files); a byte-order source that is no byte-order word gives no address (E3S-27); the external-axis post-pass compares a standing DATA_SIZE or LENGTH with the span it resolves (E3S-29) | E3S-03:"),
    # DE-10
    ("never a per-character alternation (E3A-18: 1,005 MB on one 8.5 MB string) |",
     "never a per-character alternation (E3A-18: 1,005 MB on one 8.5 MB string). **Round 3 (E3S-28):** no word list per section or per line: `_line_words` and `_section_words` are generators, a long line's canonical text is joined in blocks of 4,096 words, and a keyword item carries at most its arity's words and one surplus word (E3R3: 126.1 MB against e07fb00's 114.0 MB on READ.52/3's 19.8 MB one-section file; the list form 752.7 MB) |"),
    # I-11.6
    ("the 9 new texts of `../E1-slice.md` §3 and the 7 the E3 correction adds there",
     "the 9 new texts of `../E1-slice.md` §3, the 7 the E3 correction adds there and the 1 of the round-3 addenda (READ.68)"),
    # coverage
    ("| R-A2L-READ.65 | `build_section_tree`, `_lex_a2l_lines`, `parse_a2l_file`, `render_a2l_view` | READ.65/1–/5 |",
     "| R-A2L-READ.65 | `build_section_tree`, `_lex_a2l_lines`, `parse_a2l_file`, `render_a2l_view` | READ.65/1–/6 |"),
    ("| R-A2L-READ.59 | `extract_a2l_tags`, `_tag_sizes` | READ.59/1–/7 |",
     "| R-A2L-READ.59 | `extract_a2l_tags`, `_tag_sizes` | READ.59/1–/8 |"),
    ("| R-A2L-READ.60 | `extract_a2l_tags`, `_tag_keyword_lines` | READ.60/1–/8 |",
     "| R-A2L-READ.60 | `extract_a2l_tags`, `_tag_keyword_lines` | READ.60/1–/9 |"),
    ("| R-A2L-READ.67 | `extract_a2l_tags` | READ.67/1–/3 |\n",
     "| R-A2L-READ.67 | `extract_a2l_tags` | READ.67/1–/3 |\n| R-A2L-READ.68 | `extract_a2l_tags`, `_tag_keyword_lines`, `_echo_word` | READ.68/1–/4 |\n"),
    ("| R-A2L-READ.61 | `_tag_sizes`, `extract_a2l_tags`, `_describe_one`, `enrich_a2l_tags_with_values` | READ.61/1–/9 |",
     "| R-A2L-READ.61 | `_tag_sizes`, `extract_a2l_tags`, `_describe_one`, `enrich_a2l_tags_with_values` | READ.61/1–/10 |"),
    ("round 2: e07fb00 peak RSS 535 MB, 95 MB, 70.9 MB, E3A-18) |",
     "round 2: e07fb00 peak RSS 535 MB, 95 MB, 70.9 MB, E3A-18); READ.52/3 (round 3, E3S-28; E3R3) |"),
    # _lex_a2l_lines
    ("so an `/end` there gets that line as `end_line` and an error there names it.\n",
     "so an `/end` there gets that line as `end_line` and an error there names it. **Round 3 (E3S-28).** No word list per line: a tier-2 or tier-3 line's words are joined into its canonical text in blocks of 4,096 words, so a line of 4.8 million words holds its text and one block, never one string object per word.\n"),
    ("examples: (R-A2L-READ.52/1, P2) case_06 (36.7 MB): this shape's tree build",
     "examples: (R-A2L-READ.65/6, R-A2L-READ.52/3, E3S-28) the 4.8 million words of READ.52/3 on one body line (19.2 MB) → one item; the design model peaks at 117.3 MB (e07fb00: 777.4 MB, E3R3)\nexamples: (R-A2L-READ.52/1, P2) case_06 (36.7 MB): this shape's tree build"),
    # _line_words
    ("out: list[str] words\nfunc: new. Splits one canonical text into its words: at each single space outside a quoted word; a quoted word keeps its quotes (so `w[0] == '\"'` tells a quoted word). The inverse of the join `_lex_a2l_lines` makes.",
     "out: Iterator[str] words\nfunc: new. Splits one canonical text into its words: at each single space outside a quoted word; a quoted word keeps its quotes (so `w[0] == '\"'` tells a quoted word). The inverse of the join `_lex_a2l_lines` makes. **Round 3 (E3S-28):** a generator (`re.finditer` over the text, a quoted word by the unrolled pattern), so no line's word list is held; the examples list what it yields, in order."),
    # _section_words
    ("out: list[tuple[str, int]] words\nfunc: new (DE-4). The section's own words in file order,",
     "out: Iterator[tuple[str, int]] words\nfunc: new (DE-4; a generator from the round-3 addenda, E3S-28: it holds nothing but the current text's `_line_words` iterator, so a section of 4.8 million own words costs no list — the list form held 752.7 MB on READ.52/3's 19.8 MB file, E3R3, and 755.5 MB in E3S-28 [MEM words]; the examples list what it yields, in order). The section's own words in file order,"),
    # _tag_keyword_lines
    ("in: list[tuple[str, int]] words; int start; list[str]? errors = None",
     "in: Iterable[tuple[str, int]] words; int start = 0; list[str]? errors = None"),
    ("any other surplus word is still dropped silently (`3E00` in `ECU_ADDRESS 0x1C2D 3E00` is no number word: open, `../01-requirements.md` READ.58).",
     "any other surplus word is still dropped silently (round 3 widens it below)."),
    ("not as a second pass over the texts (READ.52's margin was 0.12 at round 2).\n",
     "not as a second pass over the texts (READ.52's margin was 0.12 at round 2). **Round 3 (addenda).** (E3S-24) A *surplus word* is any hex-like word after the argument of an ECU_ADDRESS, DATA_SIZE, LENGTH, NUMBER, ARRAY_SIZE or BIT_MASK keyword: a number word, a word starting with a decimal digit, or one made only of ASCII hex digits and `_` (`re.fullmatch(r\"[0-9A-Fa-f_]+|[0-9].*\", w)` on an unquoted ASCII word); it gives .58's error and no value, as a surplus number word did; any other word there (`SIG_X`) is dropped, as base. (E3S-28) `words` is consumed as a stream, one word at a time, from `start` (0 when the walk hands it the stream after the header); an item carries at most its arity's argument words (MATRIX_DIM at most 4, enough to tell more than 3) and its first surplus word, and `<k>` counts all of them, so no item grows with the file.\n"),
    ("examples: (R-A2L-READ.60/6, E3S-21) `BYTE_ORDER` ↵ `LENGTH 2` → `(\"BYTE_ORDER\", …)`, `(\"LENGTH 2\", …)`; `… BYTE_ORDER has 0 of its 1 arguments` (`extract_a2l_tags` then gives no address)\n",
     "examples: (R-A2L-READ.60/6, E3S-21) `BYTE_ORDER` ↵ `LENGTH 2` → `(\"BYTE_ORDER\", …)`, `(\"LENGTH 2\", …)`; `… BYTE_ORDER has 0 of its 1 arguments` (`extract_a2l_tags` then gives no address)\n"
     "examples: (R-A2L-READ.58/5, R-A2L-READ.60/8, round 3, E3S-24) `ECU_ADDRESS 0x1C2D 3E00`, `ECU_ADDRESS 0x1C2D3 E00`, `ECU_ADDRESS 0x1C 2D3E00`, `ECU_ADDRESS 0x1C2D3E00 _4026` and `BIT_MASK 0x0F F0` on line 22 → `(\"ECU_ADDRESS 0x1C2D 3E00\", 22)` … `(\"BIT_MASK 0x0F F0\", 22)`; errors `Line 22: ECU_ADDRESS has 2 of its 1 arguments` (× 4) and `Line 22: BIT_MASK has 2 of its 1 arguments`; `ECU_ADDRESS 0x1C2D` (line 22) ↵ `3E00` → `(\"ECU_ADDRESS 0x1C2D 3E00\", 22)` and the same error (round 2: `3E00` dropped, address 0x1C2D, 0 errors, E3S-24 [S3-SURPLUS])\n"
     "examples: (holds as base, R-A2L-READ.58/5) `ECU_ADDRESS 0x10 SIG_X` → `(\"ECU_ADDRESS 0x10\", …)`; no error (`SIG_X` is not hex-like)\n"
     "examples: (R-A2L-READ.52/3, E3S-28) READ.52/3's `ECU_ADDRESS 0x10` followed by 4.8 million words `ab1` … `ab8` (hex-like) → one item `(\"ECU_ADDRESS 0x10 ab1\", 11)`; errors `Line 11: ECU_ADDRESS has 4800001 of its 1 arguments`; at most 1 item held (E3R3: peak 126.1 MB, the list form 752.7 MB)\n"),
    # extract_a2l_tags
    ("and the inline-axis step, the layout-span step and the external-axis post-pass skip it, so the refusal is final.\n",
     "and the inline-axis step, the layout-span step and the external-axis post-pass skip it, so the refusal is final. **Round 3 (addenda).** (E3S-28) Per tag section, `stream = _section_words(section)`, `head = list(itertools.islice(stream, 10))`, `_tag_header(section_name, head)`, then `_tag_keyword_lines(itertools.chain(head[rest:], stream), errors=…)`: no section's words are held as a list. (E3S-27) The tag's *byte-order source* (CTX) is its own BYTE_ORDER item's argument; when it has none, the first `BYTE_ORDER` run of its record layout's canonical `lines` (`record_layouts_by_name[…][\"lines\"]`, read with `_line_words`); when that has none, the first of its module's MOD_COMMON. A source that is not a byte-order word (`_normalize_byte_order` gives `None`) gives the tag **no address** — the fallback to the layout, the module or `little` applies only when no source stands. `Line <n>: BYTE_ORDER <word> is not a byte order` (READ.68, `<word>` by `_echo_word`) is appended once per such word: a tag's own when the tag is read, a MOD_COMMON's when the walk enters its MODULE, a RECORD_LAYOUT's when the walk meets that section (each from its `line_numbers`), never once per inheriting tag. `_byte_order_from_section_lines` keeps its signature and value (I-11.4); the effective byte order of a tag with a byte-order word is the base's. (E3S-29) The external-axis post-pass also visits a CURVE or MAP whose length came from a standing DATA_SIZE or LENGTH while its span was unknown in the walk (a local set beside the refusal set; no new tag key): when `_axis_counts_resolving_external` resolves its span, `_tag_sizes(items, element_size, kind, span)` compares them, and a disagreement gives length `None`, .59's error and a mark in the refusal set.\n"),
    ("examples: (R-A2L-READ.61/8, R-A2L-READ.59/7, E3S-23) SYNMAP with `LENGTH 2264` → length `None` and `… declares the sizes 2264 and 2266`; with `LENGTH x4` → `None` (round 1: the CURVE/MAP step then gave the span 2266); with `LENGTH 2266` → `2266`, no error\n",
     "examples: (R-A2L-READ.61/8, R-A2L-READ.59/7, E3S-23) SYNMAP with `LENGTH 2264` → length `None` and `… declares the sizes 2264 and 2266`; with `LENGTH x4` → `None` (round 1: the CURVE/MAP step then gave the span 2266); with `LENGTH 2266` → `2266`, no error\n"
     "examples: (R-A2L-READ.60/9, R-A2L-READ.68/1, E3S-27) under HDR's MOD_COMMON `MSB_FIRST`, MEAS(X, `ECU_ADDRESS 0x10`) with `BYTE_ORDER MSB_FRIST` (line 23) → address `None`; `Line 23: BYTE_ORDER MSB_FRIST is not a byte order` (base: `0x10`, `effective_byte_order` `big` from the module, E3S-27 [B3-BO]); with `BYTE_ORDER MSB_LAST_MSW_FIRST` → address `None` (base: `big`; the symbol entry wrote `1234` for 4660); with `\"MSB_FIRST\"` or `1` → address `None` and the error\n"
     "examples: (R-A2L-READ.60/9, R-A2L-READ.68/2, E3S-27) MOD_COMMON `BYTE_ORDER MSB_FRIST` (line 5), MEAS(X, `ECU_ADDRESS 0x10`) and MEAS(Y, `ECU_ADDRESS 0x20`) with no BYTE_ORDER → both address `None`; exactly one `Line 5: BYTE_ORDER MSB_FRIST is not a byte order` (base: both `0x10`/`0x20` with `little`); a VALUE `CB` at `0x10` on `RL_BO` (`BYTE_ORDER MSB_FRIST`) → address `None`, one error on `RL_BO`'s line\n"
     "examples: (holds, R-A2L-READ.60/9) MOD_COMMON `BYTE_ORDER MSB_FRIST` and MEAS(X, `ECU_ADDRESS 0x10`, `BYTE_ORDER MSB_LAST`) → address `16`, `effective_byte_order` `little` (its source is its own word); the MOD_COMMON's error once\n"
     "examples: (holds as base, R-A2L-READ.68/3) `BYTE_ORDER` `MSB_FIRST`, `MSB_LAST`, `BIG_ENDIAN`, `LITTLE_ENDIAN` and their lower-case forms → address kept, no READ.68 error; the 35 tracked files → 0 such errors (E3S-27 [TR3])\n"
     "examples: (R-A2L-READ.59/8, R-A2L-READ.61/10, E3S-29) SYNMAP with its axes made COM_AXIS on `AP_X` (87) and `AP_Y` (13), declared after it, and `LENGTH 2264`, `/begin` on line 14 → length `None`; `Line 14: CHARACTERISTIC SYN_MAP_W declares the sizes 2264 and 2266` from the post-pass (round 2: `2264`, no error, E3S-29 [S3-SIZES])\n"
     "examples: (R-A2L-READ.52/3, E3S-28) READ.52/3's MEASUREMENT `BIG` (4.8 million own words) → 1 tag `BIG`, address `None` (its words are hex-like surplus words, E3S-24); no list of its words held (E3R3: peak 126.1 MB against e07fb00's 114.0 MB)\n"),
    # parse_a2l_file
    ("round 2 (E3A-18): peak RSS at most `2` × e07fb00's (`535` MB and `95` MB at E3 round 2)\n",
     "round 2 (E3A-18): peak RSS at most `2` × e07fb00's (`535` MB and `95` MB at E3 round 2); round-3 model (E3R3): `576.7` / `535.2` MB and `98.9` / `95.5` MB\n"
     "examples: (R-A2L-READ.52/3, R-A2L-READ.65/6, E3S-28) READ.52/3's 19.8 MB one-section file → peak RSS at most `2` × e07fb00's `114.0` MB (E3R3 model: `126.1` MB, `1.11` ×; the round-2 list form `752.7` MB → RED); the same words on one line (19.2 MB) → no exception (model `117.3` MB, e07fb00 `777.4` MB); each run reports its RSS before the parse (about `52.5` MB) and the peak minus it (E3S-30)\n"),
    # node count
    ("test-side and evidence 2 unchanged.\n",
     "test-side and evidence 2 unchanged. **After the round-3 addenda (2026-11-07): 37 nodes**, unchanged — no node added; `_lex_a2l_lines`, `_line_words`, `_section_words`, `_tag_keyword_lines`, `extract_a2l_tags` and `parse_a2l_file` change their text (E3S-24, -27, -28, -29).\n"),
]
