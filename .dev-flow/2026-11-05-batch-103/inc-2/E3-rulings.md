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
