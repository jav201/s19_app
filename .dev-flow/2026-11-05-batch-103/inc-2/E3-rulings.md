# Inc 2 — E3 round 1 rulings (2026-11-06T18:27:20-06:00, orchestrator Opus 5.5)

Round 1: `E3-architect.md` **FAIL** (2 MAJOR, 5 MEDIUM, 5 MINOR, 5 LOW, 3 INFO); `E3-security.md` **FAIL** (1 HIGH, 2 MAJOR, 5 MEDIUM, 2 MINOR, 2 LOW, 1 INFO). The design stands; every blocker has a design fix. Every finding below is **accepted with the reviewer's fix** (the "fix" column of the finding's row) unless the ruling says otherwise. Probe evidence copied into `evidence-e3/`.

| Finding | Ruling | Exact change (where the reviewer left the text to the orchestrator, it is fixed here) |
|---|---|---|
| E3S-01 HIGH (+ E3A-08, E2-12) | accept, fail closed | R-A2L-DEF.19's condition gains "or a BIT_MASK line whose word the system cannot read as a number"; the same refusal for a text object with a BIT_MASK line; `describe_definition` cross-checks the tag's `bit_org` (`a2l.py:2683-2684`): set while the definition has no mask → the same refusal. Case .19/4 (E3A-08) and a text-with-mask case. **Never edit an object whose mask the system did not read.** |
| E3S-02 MAJOR | accept | Split R-A2L-DEF.7 into .7.1 (as written) and .7.2: `If an object's length is below 1 or above 1,048,576 bytes, or its address is negative, or its span ends above 0xFFFFFFFF, then the system shall give its definition the refusal A2L-DEF-ADDRESS with the message `<name>: its span of <length> bytes at <address> cannot be read`.` Reuse `MAX_A2L_DECODE_BYTES` (add it to the D-9 import list). Cases from the fix column. |
| E3S-03 MAJOR | accept | Split R-A2L-DEF.58 into .58.1 (as written) and .58.2: `If the A2L payload or the image holds content the system cannot read, then the system shall give a refusal in place of an exception.` Threshold: the hostile corpus of the fix column (≥ 14 shapes) through describe, decode and encode, N/N with 0 exceptions; negative control: remove one guard (e.g. the count `int()` guard) → an exception → RED. |
| E3A-01 MAJOR (E2-10) | accept **B, in Inc 2** | I-2 gains `describe_definitions(names, a2l_data) -> dict[str, Definition]` over one walk; `describe_definition` delegates; `_find_tag` becomes a name-map lookup (E3A-13 falls out). Add a row with a numeric bound: describing all objects of software_a (13,990) ≤ 2.0 s on cachyos-rtx (measured 0.52 s); negative control: per-name walks → RED. |
| E3A-02 MAJOR + E3S-07 MEDIUM | accept both | CTX *agree at the display precision*: `|p − x| ≤ 0.5 × 10^(−d)` in IEEE double (d capped at 17), **or** their 15-significant-digit texts are equal (every datatype), **or**, for FLOAT32_IEEE only, their 6-significant-digit texts are equal. FLOAT64 never at 6 digits. Cases: E3A-02's `%.15` and typed values in .55's grid; .54/3 (E3S-07's example). |
| E3A-03 MEDIUM | accept | `Definition` carries the method record's coefficients / table reference (fields with defaults, before `refusal`); decode and encode never walk `sections`. |
| E3A-04 MEDIUM | accept fix 1 + 2 | Narrow .35's trigger; .38 becomes a `When` row; its cases become class normal. |
| E3A-05 MEDIUM | accept the restatement | R-A2L-DEF.56 as the fix column words it. |
| E3A-06 MEDIUM | accept the recommendation | For d ≥ 15: round to 15 significant digits, then write exactly d decimals (`4.100000000000000`); .36/1 expects `0.10000000000000000`; FLOAT32 keeps its stored digits to 15 significant digits. |
| E3A-07 + E3S-08 MEDIUM | accept, consumer note | I-2 consumer note as E3A-07's fix words it (staging overlay; re-encode later fields of a word when an earlier one is dropped). Backlog row for Inc 8's E1: a row and an AT with two masked edits of one word staged in either order. No Inc 2 row changes. |
| E3S-04 MEDIUM | accept (a) and (b) | (a) I-2 note: every `str` is plain text; consumers render with markup off — rows owed by Inc 6, 8, 9 (backlog for their E1). (b) `Decoded.text` and every message give U+FFFD for U+0000–U+001F, U+007F, U+0080–U+009F in a word taken from the file or the operator — one new row with cases (a NUL and an ESC in an enum text and in a name). |
| E3S-05 MEDIUM | accept the preferred fix | R-A2L-DEF.26: "…when the system decodes or encodes the object"; encode cases get an image that holds the span; add .26/3. |
| E3S-06 MEDIUM | accept | Step 7 checks the written value `p` too (extended limits, else limits), same codes, `<text>` = `<stored>`; the .44 notice when `p` is outside the limits only; FLOAT32 limits compared packed as FLOAT32. Case .45/3. |
| E3A-09, E3A-10, E3A-11, E3A-12, E3A-14, E3A-16, E3A-17 | accept | As their fix columns (`(none)` kind + case .4/8; R-A2L-014/def-1 + counts; masked enum case .46/4; CONVERSION wording; signed mask with bit 0 and sign bit → refuse; count-driven table read; signature pin adds `encode_physical_to_raw_bytes` and `parse_begin_meta`). |
| E3A-13 | resolved by E3A-01 | |
| E3A-15 | accept .59/3 | A digest of `repr` of the object list at 1 MiB, seed 20260001. |
| E3A-18 | accept | CTX line: the inclusive rule holds for every datatype as the system's rule; backlog: the ASAM float reading. |
| E3S-09, E3S-10, E3S-11 | accept | Exact-integer check with `Decimal` for integer datatypes with no conversion or IDENTICAL (.54/4); non-finite words are not numbers (.21/3); ASCII digits only, `strip(" ")` (.40/8, .40/9); Inc 8 note: shorten a long `<text>` when shown. |
| E3S-12 | accept | The definitions case writes `definitions.s19` and `definitions.a2l`. |
| E3A-19, E3A-20, E3S-13 | noted | E2-11 and E2-14 confirmed. |

**Backlog added:** Inc 6/8/9 E1 rows for markup-off rendering (E3S-04a) and masked staging (E3A-07/E3S-08); Inc 8: shorten long `<text>` (E3S-11); ASAM float range reading (E3A-18).

**Next:** one correction pass (targeted edits; records and graph), then round 2 re-checks only the blocking findings (E3S-01, -02, -03, E3A-01, -02) and the rows the pass touched.

## Round 2 rulings (2026-11-06T19:07:42-06:00, orchestrator Opus 5.5)

Round 2: architect **PASS-WITH-NOTES** (round-1 MAJORs closed; new 2 MEDIUM, 7 MINOR, 3 LOW); security **FAIL** (new MAJOR E3S-14, the residue of round 1's HIGH; 1 MEDIUM, 6 MINOR, 1 LOW, 1 INFO). Every round-2 finding is **accepted with its fix column**, with these rulings:

| Finding | Ruling |
|---|---|
| E3S-14 MAJOR | accept: fail closed on the BIT_MASK **keyword** — R-A2L-DEF.19 gains "or the object's record holds a BIT_MASK keyword from which the system read no bit mask" (`<mask>` = the next word, or `(none)`); cases .19/7 and .19/8 per the fix column (renumber against E3A-24's .19/7: the SBYTE 0xFF case becomes .19/9). |
| E3A-25 + E3S-19 (scope of .137) | accept the narrowing: R-A2L-DEF.137 covers the display text of a decoded value and every refusal message and notice, as round 1 ruled; every other `str` field is a raw file word, and the I-2 consumer note says a consumer that renders one replaces control characters as .137 does. |
| E3S-15 + E3A-26 | accept: .137 governs; .40/9 and .52/2 expect U+FFFD. |
| E3A-22 | accept: drop the three defaults; `Definition` states its conversion fields (fail closed). |
| E3A-27 | the .59/3 digest is taken at E4 on a clean checkout of the base tree `e07fb00` before any edit, recorded with its transcript. |
| E3A-32 | accept; it also goes into Inc 3's rebase brief. |
| E3S-22 | done by the orchestrator: PLAN rows of Inc 6, 8 and 9 carry the three consumer obligations. |
| all other round-2 findings (E3A-21, -23, -24, -28 … -31; E3S-16, -17, -18, -20, -21) | accept with their fix columns. |

**Next:** one correction pass (records and graph), then a round-3 security re-check of E3S-14 and the parts the pass touched. The architect does not re-review (PASS-WITH-NOTES; its notes are applied in the same pass).

## Round 3 rulings (2026-11-06T19:38:34-06:00, orchestrator Opus 5.5)

Round 3 (security only): **FAIL** — E3S-14 narrowed, not closed; new MAJOR **E3S-24** (five shapes still lose the mask: a comment glued to the keyword, a one-line IF_DATA before the BIT_MASK line, `/begin` or `/end` inside a comment); MEDIUM E3S-25, E3S-26; MINOR E3S-27; LOW E3S-28. All **accepted with their fix columns**:

- **E3S-24 (the rule that replaces the keyword clause and the `bit_org` cross-check):** R-A2L-DEF.19 gets one clause — "…or the text of the object holds the letters BIT_MASK, in any letter case, more than once, or once while the system read no bit mask" — with *the text of the object* defined in CTX-A2L-DEF exactly as the fix column defines it (its /begin line after the name and long identifier, its own lines, the lines of each child section that is not itself an object; comments and quoted strings included). Plus a refusal `A2L-DEF-MASK` when an object's record ends inside an open comment or an open quote. The reviewer's census: 0 objects refused that the graph accepts, over 234,654 objects in the 35 fixture files. Rationale: one guard on the raw letters fails closed for every tokenizer mistake, instead of guarding each shape (the skill's "prefer removing a feature over guarding it": two guards go, one stays).
- **E3S-25:** .19/6's text as the fix column gives (header on its own body line); its negative control as written there.
- **E3S-26:** covered by "more than once"; case .19/14 (shape P).
- **E3S-27, E3S-28:** as their fix columns.

**Next:** one correction pass (rows/cases; graph), then a round-4 security check that runs the reviewer's reference rule against the graph's text.

## Round 4 rulings (2026-11-06T20:13:11-06:00, orchestrator Opus 5.5)

Round 4 (security): **FAIL** — E3S-24 … -28 closed, census still 0 extra refusals over 234,654 objects; but six more shapes lose the mask (**E3S-30**, MAJOR: a comment or quote opened in a child section; a `/begin` that does not start its line; the literal reading of "lines of each child section"), and **E3S-35** (MAJOR: a commented-out copy of an object is a live tag and the first of its name, so an edit goes to the old address).

**Why the rounds do not converge:** every guard so far defines "the text of the object" through the frozen reader's section tree, and that reader mis-handles comments (a `/begin` inside a comment opens a section; BL-I2-12, BL-I3-11). Each round closes the shapes found and the next finds more. The hazard is the *consequence* — an encode that writes bytes a neighbouring object owns — so this round adds one guard on the consequence, which does not depend on reading the mask at all.

| Finding | Ruling |
|---|---|
| E3S-30 | accept the fix column (the text of the object pinned to reading W; each section of it checked for an open comment or quote; `/begin` not at a line start covered) **and** add the structural guard below. |
| **New guard (orchestrator, E3S-30 + E3S-35)** | New row **R-A2L-DEF.138**: `If the bytes an encode would write overlap the span of another object of the A2L file, then the system shall refuse the encode with the refusal A2L-DEF-OVERLAP and the message `<name>: its bytes at <address> are shared with <other>`, unless both objects' bit masks were read and do not overlap.` The spans come from the tag table's address and byte length of every MEASUREMENT and CHARACTERISTIC (built once in `describe_definitions`'s walk). A mask the system failed to read can then never overwrite a neighbour: the neighbour's span overlaps, the refusal fires. Census the fixtures for false refusals (objects that overlap without masks) and report the count; if it is not 0, list them and the orchestrator rules. |
| E3S-35 | accept the fix column: R-A2L-DEF.5 refuses a name that has more than one tag or object section — new row **R-A2L-DEF.139** if .5's response differs: `A2L-DEF-NAME` `<name>: the A2L declares that name more than once`; cases .5/1, .5/2 and AT-B103-I2-3 change (case 08's issues file declares `VALUE_0001` twice). The reader fix (no `/begin` inside a comment) goes to the backlog as a proposed increment for the operator (it also makes commented-out objects show as live tags in the A2L views today). |
| E3S-31, -32, -33 | accept with their fix columns. |

**Correction by Opus** (design work; one agent, targeted edits), then **round 5 security**, asked specifically to break R-A2L-DEF.138.

## Round 4 census ruling (2026-11-06T20:44:40-06:00, orchestrator Opus 5.5)

The round-4 correction (Opus, 25 min) applied E3S-30 … -35 and R-A2L-DEF.138 / .139; the overlap census (`evidence-e3/corr4-overlap-census*`) refuses **223,524 encodes**: case_06 (220,040 — a synthetic stress file whose 220,040 tags all overlap), software_a (3,189, all at 0x0), from_source (68), small update/validation fixtures; 8 refusals only because two read masks share bits (correct: those objects would clobber each other). Release case 08: 0 (its issues variant: 6, by design). Duplicate names: 0 outside case 08's issues file.

| Item | Ruling |
|---|---|
| I-2 field `shared_with` | **accepted.** |
| R-A2L-DEF.138's index | **refined:** the span index holds only objects whose address the A2L **declares** (a CHARACTERISTIC's header address word, or an ECU_ADDRESS line of a MEASUREMENT / AXIS_PTS) — an object with no declared address cannot be encoded anyway (its own refusal). The value 0x0 is a valid declared address (flash at 0) and is not special. Refusals that remain are declared overlaps; they stay refused (a file whose objects overlap is inconsistent; the refusal names both). |
| Census | re-run with the refinement; report per file. Expected: software_a and from_source's 0x0 refusals disappear if those objects declare no address; case_06 stays refused if its addresses are declared (correct). |
| The 8 V171 cases that contradict .138 (`02-test-cases.md:318`) | the cases follow the row: two masked objects whose read masks share bits are refused. |

**Next:** a narrow Opus pass (the index refinement in the row, CTX and graph; census re-run; the 8 cases), then round 5 security on E3S-30, E3S-35 and .138.
- **Census re-run** (2026-11-06T21:00:22-06:00, `evidence-e3/corr4b-overlap-census*`): the refinement removes nothing — the tag table already takes addresses only from declarations (0 of 234,654 differ; the 10,605 objects with no declared address were never indexed). The 223,524 refusals are **declared overlaps**: case_06 (stress file), software_a / from_source / BalanceTube (objects that declare `0x0` as a placeholder), V171 / V161 (declared overlaps plus 4 each from shared mask bits), small validation fixtures; release case 08: 0 (issues variant 6, by design). **Ruled: the guard stands.** Objects that declare the same bytes are aliases in the image; an edit of one changes the others, so refusing is the safe answer, and the message names the other object. Placeholder-address files cannot be patched meaningfully anyway. **Accepted readings:** case_07's ECU_ADDRESS-only CHARACTERISTICs keep R-A2L-011's address (the one the encode writes); **AXIS_PTS spans join the index in Inc 3** (Inc 3 knows the axis lengths) — added to Inc 3's rebase brief.

## Split status (amendment A2) (2026-11-06T21:46:00-06:00, architect agent, Opus 5.5)

This section states facts only; the orchestrator rules. It draws on `E3-architect.md` (rounds 1–2), `E3-security.md` (rounds 1–5), the rulings above (rounds 1–4b) and the records as they stand now. The sides are those of `01-requirements.md` "Split (amendment A2)": 2a has 50 rows, 2b has 19. Two words are used with fixed meanings below:
- **closed**: a reviewer re-checked the finding;
- **applied**: a correction pass applied it, and no reviewer re-checked it. The round-2 ruling says "the architect does not re-review".

### 2a: E3 findings that touch a 2a row

**Closed, with no residue in a 2a row:**
- **Security:** E3S-01 (1) and (2), -02, -03, -04, -10 and -12 (round 2); E3S-17, -18, -19, -21 and -22 (round 3); E3S-28 (round 4); E3S-31 and E3S-35 (round 5; -35 closed as ruled, with the known limit below).
- **Architect:** E3A-01, -03, -04, -06, -08, -09, -13, -14, -15, -16, -17 and -18 (round 2); E3A-19 and -20 are noted.

**Applied, and in the records now:**
- **E3A-10:** the count reads 29.
- **E3A-12:** the `describe_definitions` func says "(E3A-12)".
- **E3A-22:** no defaults (`codewire/graph-inc2.md:40-44`).
- **E3A-23:** .37 is narrowed.
- **E3A-24:** cases .19/9, .35/5 and .35/6 exist.
- **E3A-25:** .137 is narrowed.
- **E3A-28:** the mask refusal sits at its place in the order, and case .24/4 exists.
- **E3A-29 (a) and (c).**
- **E3A-30:** the 2a items are aligned (.19/4, .137/1 … /4, the count).
- **E3A-31:** case .7.2/6 exists, and `<address>` and `<length>` are in CTX.
- **E3A-32:** the Inc 3 lookups (`codewire/graph-inc2.md:74`).

**Findings the split re-opens for 2a.** These were closed by R-A2L-DEF.19 clauses that now wait for 2b:
- the shapes of E3S-01 (3) and its path (d);
- the shapes of E3S-14, -24, -26, -30 and -33;
- not their cases: E3S-25, -27 and -32 concern cases that are now 2b;
- not E3A-14's case: .19/9 stays in 2a.

In 2a, the shapes of these findings reach decode with no refusal. A lost mask decodes as the whole word, and two BIT_MASK lines decode the field of the first one. Today's A2L views show the whole word, because they apply no mask (`E1-slice.md:60`). 2a writes nothing. On the 35 fixture files these clauses refuse 0 objects (`01-requirements.md` "Split (amendment A2)").

**Open, or a known limit, touching a 2a row:**

| Finding | 2a rows it touches | State | Why it does not block a read-only change |
|---|---|---|---|
| E3S-38 MAJOR (round 5) | cited R-A2L-010, 011, 014 (address and length from the tag); CTX *defined object* and .1 … .4 (a commented `MATRIX_DIM 1` makes an array a scalar of kind number, B4); .7.1 (its fix column puts the cross-check there) | open | 2a takes address and length from the same tag table that the A2L views decode today (`describe_definitions`, `codewire/graph-inc2.md:253`; `enrich_a2l_tags_with_values`, `E1-slice.md:60`). A decode therefore shows the address the views show, and writes nothing. Shapes A1, A2 and A4 (address lost) are already refused by .7.1. Fixtures: 0 objects [FX-lost-address]. The cause is today's reader, which Inc 11 fixes. The operator's report (`../design/operator-report-a2l-reader.md`) describes this class. |
| E3S-36 MAJOR (round 5) | cited R-A2L-024 … 027 (the byte order, from the tag) | open | The hazard is the .138 exemption, which is 2b. With a misread byte order, 2a's decode shows the value in the same frame as today's views (E3S-45 (v)). It writes nothing. Fixtures: 0 shapes [FX3-total]. The fix column's .19 byte-order clause is a 2b guard. |
| E3S-40 MEDIUM (round 5) | CTX *defined object* (MATRIX_DIM 1), `_object_kind`, .4 | open | `MATRIX_DIM 1 4 1` is read as 1, so 2a decodes element 0 as a scalar. That is the same first-number reading as the tag table (`a2l.py:1174-1177`, `:2702-2705`). It writes nothing. Fixtures: 14 multi-number objects, 0 of them edited as a scalar [FX3-total]. |
| E3S-43 LOW (round 5) | .18 (the mask read) | open | `BIT_MASK 0x000F/* nibble */0` is read as `0x000F0`, so 2a decodes the field of that mask. Today's views show the whole word instead. It writes nothing. Fixtures: 0 of the 256 read masks [FX3-total]. The cause is the tokenizer (a comment is not a word break), which Inc 11 fixes. The fix column's .19 clause is a 2b guard. |
| E3S-39 MAJOR (round 5) | .58.2 and .136, but only through the span index | open | The split puts the span index in 2b. 2a's describe has no per-page structure, so the hostile lengths [H1] … [H4] reach 2a only as tags whose definitions .7.2 refuses. The base parser returns those tags (`sec-r5-probe4`). In 2b, the finding stands as filed. |
| E3S-45 INFO (ii), (v) (round 5) | .136; the byte order | noted | (ii) Every describe builds the whole-file maps, about 40 ms; .136 was measured at 0.52 s and 0.817 s. (v) A misread byte order with no mask stays with the reader fix. |
| corr4-2, the known limit of E3S-35 (`codewire/graph-inc2.md:976-981`) | .5, .139 | known limit (round-4 ruling) | A commented-out object with no live copy is still a tag, so 2a decodes it at an address the file no longer declares. Today's A2L views show it as a live tag too (PLAN A2, Inc 11). It writes nothing. |
| E3A-27 MINOR (architect round 2) | .59 (case .59/3) | ruled (line 42 above) | The digest is taken at E4 on a clean checkout of `e07fb00`, before any edit. That step lives only in this record: the case still reads "equals the value pinned at E4", with the precondition "the generator of the tree under test". |
| E3A-29 (b) LOW (architect round 2) | .136 | applied in part | .136's negative control and Base still say "about 67 s" / "≈ 67 s"; the architect counts about 295 s. Either way the mutant (one walk per name) exceeds 2.0 s, so the negative control still turns RED. |

**E3S-37 MAJOR touches no 2a row.** It concerns the .138 index (2b) and AT-B103-I2-1's encode arm (2b). In 2a, AT-B103-I2-1 only decodes the UBYTE and SBYTE objects that V171's INSTANCE also declares, and it applies nothing. E3S-41, -42 and -44 are 2b only.

### 2b: every open finding (waits for Inc 11 and a re-review against the fixed reader)

The security round-5 verdict, FAIL with 4 MAJOR, stands for 2b. None of its findings is ruled yet.

| Finding | 2b rows / nodes | Fix column, in brief |
|---|---|---|
| E3S-36 MAJOR | .138's exemption; CTX *bits an object selects*; `_selected_bits` | a .19 clause that refuses a masked definition whose byte order text holds BYTE_ORDER more than once (or once with no own line); `mask_of` CLEAN |
| E3S-37 MAJOR | .138's index; AT-B103-I2-1's encode arm | (a) index BLOBs and sized INSTANCEs, and refuse every encode of a file that holds `/include`; or (b) rule them into Inc 3 with AXIS_PTS and write the limit down ("safe only if Inc 3 closes the index before Inc 8 or 9 exposes the write path") |
| E3S-38 MAJOR | the index addresses; the fix column's cross-check goes into .7.1, a 2a row (the orchestrator rules its side) | a C-rule cross-check of address and length against the tag; the index files an object under every address it may have |
| E3S-39 MAJOR | the span index in `describe_definitions` (2b part); .58.2 and .136 in 2b | page-file only spans within .7.2's bounds; keep others as intervals; add H1 … H4 to the .58.2 corpus |
| E3S-40 MEDIUM | CTX *span* × MATRIX_DIM; the index lengths | the MATRIX_DIM product; product ≠ 1 → `A2L-DEF-KIND` |
| E3S-41 MINOR | `mask_of` | CLEAN: a mask counts only when the other definition carries no refusal |
| E3S-42 MINOR | encode step 2 (text kind); .138 cases | write step 9 into step 2; case .138/20 (ASCII beside a UBYTE) |
| E3S-43 LOW | .19 (2b clause); the exemption | a .19 clause: the BIT_MASK word read with comments as word breaks differs from the word read |
| E3S-44 LOW | `_shared_with` scan sentence | "…up to the first whose span overlaps and that is not left out" |
| E3S-45 INFO (iii) | I-2 consumer note for `shared_with` | a consumer never clears `shared_with` and re-describes after the A2L or its file changes (Inc 6, Inc 10) |
| E3A-24 residue (architect round 2, applied in part) | .43 / .44 (the written value) | case .43/5 (.45/3's object without EXTENDED_LIMITS, `0.55`) is not in `02-test-cases.md` |
| E3A-30 residue (architect round 2, applied in part) | `_check_limits` example .21/3 | `codewire/graph-inc2.md:571` says UBYTE `XL3`; case .21/3 (`02-test-cases.md:98`) says SWORD |

Notes for the 2b re-review:
- **Clauses tied to the reader.** The .19 clauses on the text of the object, .138 and the write gate of .139 all rest on the frozen reader. E3S-30's fix column says the open-section and `/begin` clauses can be removed once the reader is fixed (BL-I2-12, now Inc 11).
- **AXIS_PTS.** AXIS_PTS spans join the index in Inc 3 (the round-4 census ruling).
- **Last scope.** The round-5 review covered the records at `0821d17f` and `05ec5ebf`.

## Split rulings (2026-11-06T21:48:09-06:00, orchestrator Opus 5.5) — Inc 2a E3 done

- **Cut of R-A2L-DEF.19 accepted as recorded:** the unreadable-word and text-object clauses stay in 2a (they refuse a definition, which protects the display too); the text-of-object clauses (letters, open comment/quote, `/begin`) go to 2b.
- **Inc 2a's open findings** (E3S-36, -38, -40, -43, the lost-mask shapes E3S-14/-24/-26/-30/-33, corr4-2 commented-out object) are **inherited reader defects**: 2a shows what the A2L views show today, with no write path. They are **ruled non-blocking for 2a** and owned by Inc 11 (reader fix); 2a's acceptance after Inc 11 lands re-runs their shapes. E3S-39 is 2b-only (span index).
- E3A-27 (.59/3 text) and E3A-29 (b) are E4 addenda for 2a's tester.
- **Inc 2a goes to E4** (50 rows, 181 cases, 32 nodes). **Inc 2b** (19 rows, 109 cases, 11 nodes) waits for Inc 11 and a security re-review against the fixed reader.

## Inc 2a E5 — known design gaps (2026-11-07T02:56:10-06:00, orchestrator Opus 5.5)

Applied (Opus, 50 min): one `reads` map per walk keyed by section identity, every value immutable (COMPU_METHOD → its 6 fields read-only; COMPU_VTAB / _RANGE → the table tuple by reference; RECORD_LAYOUT → its resolved datatype); new row **R-A2L-DEF.149** (cases /1–/4). Measured: the **current 2a code** takes 42.1 / 57.5 / 52.3 / 6.0 s with 400 objects sharing 256 KiB (> 60 s at 512 KiB) — a real DoS on a hostile A2L; the model 0.032–0.135 s (256 KiB), 0.044–0.218 s (512 KiB); 0 differences on the 35 fixtures.
- **E5-1 (the 1.3× ratio is timing noise at host load 13–16):** the scaling clause of **.148 and .149** is restated to be robust: sizes **S and 8S**, median of 7 **interleaved** runs, the per-object part may grow by at most **2.0×** (a per-object walk of shared content grows ≥ 6×), `serial_timing` lane. Inc 3a's .148 takes the same wording at its E4.
- Next: code (DeepSeek, Sonnet if its API fails) ∥ tests (Sonnet) for .149, GREEN, then Inc 2a's E5 reviews (code, security), mutants, coverage audit.

## Inc 2a E5 — gap pass 2 rulings (2026-11-07, orchestrator Opus 5.5)

**Gap pass 1 is done:**
- the .149 read-once map is code `eb750c6f` (`f2f955aa`);
- its tests are `37168255`;
- the tests are RED on `82f5f8e5` and 8/8 GREEN in 3 of 3 runs.

**Measure ruling for .148, .149 and .150:**
- the timed part runs with `gc.collect()` and then `gc.disable()`, as `timeit` does;
- ×2S ≤ **1.5** and ×8S ≤ 2.0, least of ≥ 15 interleaved runs, process CPU time;
- the 2S bound was relaxed from 1.3 after 3 runs with GC off still measured ×1.2–1.4 on flat code. A per-object walk gives ≥ ×1.78 at 2S and ≥ ×3.2 at 8S.

**Gap pass 2: Inc 2a's lines of Inc 3a's E3 security round 5.** The authority is `../inc-3/E3-rulings.md`, "Round 5 rulings" and the "Round-5 correction done" note; the paths are defined in `../inc-3/E3-security.md`, "## Round 5". It runs before Inc 2a's E5 reviews.
- **The completed rule** holds for Inc 2a's nodes too. Each shared section is reduced once per walk to a form of fixed size, with each word in its final form: echoes at most 256 characters (.151), display texts cleaned once, derived values computed (the FORMAT's decimals in the method record). Definitions and decoded values reference shared texts and never copy them.
- **R-A2L-DEF.150 (U), new, owned here.** "The system shall decode each element in a time and a retained size that do not grow with the size of the conversion table it names."
  - Inc 2a's cases are scalar VALUEs: VT-3 (COMPU_VTAB entries), the VALUE forms of VT-5 (a long matched entry text), VT-6 (a long DEFAULT_VALUE text), VR-1 (COMPU_VTAB_RANGE entries) and VR-2 (a long range text).
  - Design: the enum table's reduced form holds each entry's display text and the default's, each cleaned once. It also holds a private, immutable index, shared by reference: for COMPU_VTAB, a dict from raw value to the **first** entry in file order; for COMPU_VTAB_RANGE, a segmentation built once per table, a sweep over the range ends that gives each segment the first range in file order covering it, then a bisect per element.
  - Pin the design with an equality case against the linear first-match oracle (Inc 2a's `_enum_entry_text` at `82f5f8e5`) on every corpus and tracked enum table, plus hostile overlapping and duplicate ranges.
  - The public `enum_entries: tuple[EnumEntry, ...]` of I-2 stays as pinned.
- **R-A2L-DEF.151 (U), new, owned here.** "The system shall write a file word into a refusal message as at most its first 256 characters, each character outside U+0021 … U+007E written as U+FFFD, and `…` after it when the word is longer."
  - It applies to the shared-section words of Inc 2a's METHOD, CONVERSION (the type word), TABLE (the COMPU_TAB_REF word) and TABLE-EMPTY messages. `<name>` and `<layout>` keep .137.
  - The cap is 256 because 1,993 real names exceed 64 characters, 0 exceed 256, and the longest is 148 (corpus measure in `../inc-3/E3-rulings.md`).
  - Cases: 256 characters kept whole, 257 cut, and U+FFFD for each character outside U+0021 … U+007E. Each message is ≤ 1,024 characters.
- **R-A2L-DEF.149 gains cases, same text:**
  - CM-5: a long `%…` FORMAT word, with decimals derived once in the method record;
  - CM-7: a long conversion-type word, echoed at reduction;
  - CM-9: a long COMPU_TAB_REF word, echoed at reduction;
  - RL-10 / RL-11: `_resolve_datatype` memoised per layout, for VALUE and CUBOID;
  - CM-2: a method block comment, if pass 1 does not already cover it.
  - Each case uses the measure above and asserts the ≤ 1,024-character message bound.
- **Immutability:** the new reduced forms and the index are immutable values (tuples, frozen dataclasses, `MappingProxyType`). Add a case like .149/5.
- **Owners and order:**
  1. records + graph (Opus);
  2. code (DeepSeek; Sonnet if its API fails) ∥ tests (an independent Sonnet tester);
  3. GREEN on cachyos-rtx;
  4. Inc 2a's E5 reviews (code, security), mutants and the coverage audit.

### Gap pass 2 — addendum from Inc 3a's E3 security round 6 (2026-11-07, orchestrator Opus 5.5)

Authority: `../inc-3/E3-rulings.md` "Round 6 rulings" (main worktree `s19_app-b103`); the findings are in `../inc-3/E3-security.md` "## Round 6". The Inc 2a items join gap pass 2:
- **.151's reach is every file word a refusal message echoes**, `<name>` and `<layout>` included (E3S3-25). This replaces the ".137 for `<name>`/`<layout>`" line above. A shared word's echo is computed at reduction; the object's own name echo is computed once at describe and carried.
- **TABLE-EMPTY** (`a2l_definition.py:529`) echoes the stored COMPU_TAB_REF echo, like CONVERSION and TABLE (E3S3-26).
- **Decode fails closed** in `decode_definition` (E3S3-28): a conversion result that is not an `int` or a `float` → `A2L-DEF-DECODE` `<name>: the table <ref> gives a value that is not a number`. Case: a VALUE whose TAB_NOINTP / TAB_INTP method names a COMPU_VTAB → the refusal, 0 exceptions. Negative control: `82f5f8e5` → `TypeError` → RED.
- **The scalar TAB_INTP / TAB_NOINTP lookup** (E3S3-29, -30 (b)) moves to Inc 2a's reduced form: O(log n), with v2's two rules pinned (see the round-6 fix column of E3S3-29). The equality case against the frozen `a2l._table_lookup` runs over every corpus table at the extended values: NaN, ±inf, 2^63, 2^64 − 1, midpoints and ±1 ulp. A table whose x holds a NaN is refused at decode, with the verdict computed once per walk.
- **The range index** (E3S3-30 (a)) is the segment index of the rulings above. The equality case runs over every corpus COMPU_VTAB / _RANGE table at each raw value, min, max, midpoint, ±1, NaN and ±inf, against `_enum_entry_text` at `82f5f8e5`, and gives 0 differences. Negative control: a plain bisect → 780 differences in 30 tables → RED.
- **References resolved at reduction** (E3S3-31): the method record keeps the section its COMPU_TAB_REF names, or none. No per-call name lookup of a shared word remains.
- **The message bound** is "1,024 characters" (E3S3-32).

### Gap pass 2 — records done (Opus, 31 min); orchestrator rulings on what it reported

- **P-2: accept.** `Definition` gets two private fields, `_name_echo` and `_table_form`, each `field(compare=False, repr=False)`. I-2's public names, equality and repr do not change. No consumer reads them except through Inc 2a's own functions; Inc 3a reads them through the helpers its graph names.
- **.149/5:** accepted. The cached-forms immutability test becomes a row case and is extended to `_EnumForm` and `_TabForm`.
- **No new case for RL-10 or CM-2:** accepted. .149/4 already is RL-10, and CM-2 is covered by /1's reader, memo and negative control.
- **The fail-closed cases sit under R-A2L-DEF.58.2 (/18, /19):** accepted, since .58.2 is the row for refusing instead of raising. /18's message matches Inc 3a's ruling. /19's wording, `<name>: the table <ref> has an x that is not a number`, is accepted, and Inc 3a uses the same wording for its arrays.
- **.149/1's Expected measure** was updated in place by the orchestrator to the ruled one; /2–/4 read "as /1's bounds".
