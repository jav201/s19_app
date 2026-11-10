# Inc 2b — E3 security re-review (against the fixed reader)

**Verdict: FAIL.** Two MAJOR design-gaps block E4. Nothing in the 2b write side is
implemented yet (`shared_with` is not in `Definition`; `encode_definition`,
`_shared_with`, `_selected_bits`, `_merge_bit_mask`, `_encode_*`, `_check_limits`
do not exist in `s19_app/tui/a2l_definition.py`), so every finding is a
design-gap, not impl. Read-only review; **nothing was executed** (no pytest, no
probes, no git mutations, per the brief). All premises were checked against the
current `s19_app/tui/a2l.py` (Inc 11 reader, `14fdc3b9` line numbers) and
`s19_app/tui/a2l_definition.py` (Inc 2a + Inc 3a) by reading the code, not by
citing documents.

## Disposition of E3S-36 … E3S-44

| Id | Sev | Disposition | Evidence |
|---|---|---|---|
| E3S-36 | MAJOR | **closed-by-Inc-11 / superseded**, with one LOW residual | Reader `extract_a2l_tags` lexes comments as word breaks and collects BYTE_ORDER from `_section_words` (a2l.py:3642-3686); a masked object with two differing BYTE_ORDER values sets `address_invalid` → address `None` → `A2L-DEF-ADDRESS` (fail closed). C1 (BYTE_ORDER after a one-line IF_DATA) is fixed by proper child nesting; C2/C3 (commented-out BYTE_ORDER) by comment stripping. The proposed `.19` byte-order clause is absent from the row and is not needed for the object's own byte order. **Residual (LOW):** a *live* duplicate BYTE_ORDER inside MOD_COMMON or a RECORD_LAYOUT is still silently first-wins — `_module_byte_order_source` / `layout_sources` use `_byte_order_from_words` (first keyword) with no "declared twice"/conflict check (a2l.py:3460-3468, 3476-3482). 0 fixtures (E3S-36 census: no `mod-bo`). Either add the fix-column's "the byte-order source holds BYTE_ORDER more than once" clause to `.19`, or a reader duplicate check. |
| E3S-37 | MAJOR | **still open (design-gap), MAJOR — blocks E4** | The reader now exposes `a2l_data["declared_spans"]` (BLOB + INSTANCE, sized via TYPEDEF, `_bounded_length`; a2l.py:3894-4008, 4091). But the 2b span index and CTX *span* still say "MEASUREMENT and CHARACTERISTIC only" (`01-requirements.md:50-56`; graph `describe_definitions` span index, `graph-inc2.md:306`). BLOB/INSTANCE option (a) is now cheap and was not taken. `/include` is read-as-error (a2l.py:1001-1013) but no 2b clause refuses encodes of a file holding it. AXIS_PTS is correctly owned by Inc 3b (`../inc-3/E1-slice.md:123`, R-A2L-DEF.140), but that dependency is not written into CTX *span* or AT-B103-I2-1. |
| E3S-38 | MAJOR | **closed-by-Inc-11 / superseded** | Comment word-breaks (`_strip_a2l_comments`, `_lex_a2l_lines`), duplicate-keyword detection ("declared twice", a2l.py:3584-3592), and differing-address → `None` (a2l.py:3678-3685) remove the B3/B3n/B4/A1-A4 attack surface. The C-rule cross-check into `.7.1` is unnecessary; the reader lexes the file. |
| E3S-39 | MAJOR | **closed-by-Inc-11**, with one MINOR residual | `_number_word` rejects >20 decimal / >16 hex digits (a2l.py:344-352); `_bounded_length` caps 1..1,048,576 (a2l.py:354-360); a hostile length yields tag `length` `None` → `A2L-DEF-ADDRESS`, so the page fill of H1-H4 is impossible at the source. `.58.2/8, /9, /20-/23` already cover the hostile inputs. **Residual (MINOR):** the graph's span-index sentence does not state that only tags whose `length is not None` are filed — add that one line so the implementer never files a refused span. |
| E3S-40 | MEDIUM | **closed-by-Inc-11** | MATRIX_DIM product is computed (`_matrix_dim_product` a2l.py:614-631; `_infer_length_*` a2l.py:1957-2030; `tag["matrix_dim"] = prod` a2l.py:3630-3639) and bounded. B1/B1n/B2/C7 are gone. |
| E3S-41 | MINOR | **accept-fix, partially applied** | The CLEAN condition is in the graph (`mask_of` = "…when the rules of R-A2L-DEF.19 give it no refusal, else `None`", `graph-inc2.md:306`). But `_shared_with` still writes `mask_of(position)` / "read on demand for the candidates" (`graph-inc2.md:458-465`) — the positional keying E3A-13 removed. Pin `mask_of(other)` keyed by object identity/definition. |
| E3S-42 | MINOR | **accept-fix, partially applied** | Step 9 is named for the text kind in the step-9 note (`graph-inc2.md:613`), but step 2's sentence still reads "…then the step-6 image-span check, then `Encoded`" without step 9. **Case `.138/20` (ASCII beside a UBYTE → `A2L-DEF-OVERLAP`) does not exist** — `.138` stops at /19 (`02-test-cases.md:284-302`). Write step 2 as "…, the step-6 image-span check, step 9, then `Encoded`" and add `.138/20`. |
| E3S-43 | LOW | **closed-by-Inc-11 / superseded** | `_strip_a2l_comments` inserts a word break at a comment, so `BIT_MASK 0x000F/* nibble */0` yields words `0x000F` then a stray `0`; the model reads the correct mask word; `_SURPLUS_KEYWORDS` flags the surplus (a2l.py:455-458). C5 is gone. |
| E3S-44 | LOW | **accept-fix, NOT applied** | `_shared_with` still reads "each page's entries are scanned in file order up to the first that is not left out" (`graph-inc2.md:462`) — the overlap test is missing from the scan sentence. Fix: "…up to the first whose span overlaps and that is not left out". Fails-closed, so LOW. |

## New / residual findings

### F1 — MAJOR (design-gap): the 2b `.19` text-of-object clauses and the lost-mask case chain are stale after Inc 11

Refs: `01-requirements.md` `.19` row and CTX *the text of the object*; cases
`.19/6-/8, /10-/23` (`02-test-cases.md:77-94`) and `.138/1-/13`
(`02-test-cases.md:284-296`); graph `_read_object_lines` "text-of-object pass"
and `describe_definitions` `.19` clauses (`graph-inc2.md:200, :306, :339`).

The clauses `ends_open`, `begin_inside` and the letters clauses were built to
refuse the shapes the *broken* reader (BL-I2-12) lost or misread. E3S-30's own
fix column says the open-comment/quote and `/begin` clauses "can be removed"
once the reader is fixed. Inc 11 fixed the reader: `_lex_a2l_lines` strips
comments as word breaks and preserves quotes, and `/begin`/`/end` are matched as
words anywhere on a line (a2l.py:700-1054). Consequences, checked against the
code:

- `ends_open` / `begin_inside` can no longer fire: an unterminated comment/quote
  is stripped at the lexer, and every `/begin` the model could flag is now seen
  by the builder. Cases `.19/13, /15, /16, /17, /19, /20, /21` expect
  `A2L-DEF-MASK` with the open/`/begin` messages that will not be produced.
- The letters clause is inverted: shape X2's premise ("the comment is removed
  with no word break") is now false — `BIT_/* x */MASK` lexes to `BIT_` + `MASK`
  (no mask read), so `.19/23`'s expected refusal is wrong.
- Mask-position cases `.19/6-/8, /10-/12, /14, /18, /22` expect `(none)`/glued
  masks; the fixed reader reads the correct mask (or sets address `None` for two
  differing BIT_MASK lines, which yields `A2L-DEF-ADDRESS`, not the expected
  `A2L-DEF-MASK` — `.19/14`).
- `.138/1-/13` depend on the "lost mask" state the fixed reader no longer
  produces: e.g. `.138/1` expects `shared_with = MN` for the L2C shape, but the
  fixed reader reads L2C's `0x0FF0` and MN's `0x000F` are disjoint, so
  `shared_with` is `None` and the case's expected `A2L-DEF-OVERLAP` will not
  occur.

Negative controls that mutate these clauses are consequently non-discriminating
(removing a vacuous clause cannot turn RED). The security posture is *better*
after Inc 11 (the root cause is gone), but the 2b cases cannot pass as written,
so this blocks E4.

**Correction.** Before E4, re-derive the mask-guard surface against the current
reader: (1) drop `ends_open` and `begin_inside` (E3S-30's own note); (2) drop or
re-anchor the letters clauses — the only genuine residual is two *live* BIT_MASK
lines with the *same* value, which the reader reports "declared twice" but does
not refuse; add one case for that, expecting `A2L-DEF-MASK`; (3) keep the
record-word checks `.19/1-/5, /9` (2a, genuine) and `mask_of` CLEAN (E3S-41);
(4) re-anchor `.138/1-/13` from "lost mask" to the still-real condition the
census covers — an *unmasked* object sharing a masked neighbour's bytes
(`.138/14` + the 223,516 census refusals) — and keep `_shared_with` /
`_selected_bits` as the regression target.

### F2 — MAJOR (design-gap): the span index ignores `declared_spans` and `/include` (E3S-37, still open)

Refs: `01-requirements.md` CTX *span* (:50-56) and `.138`; graph span index
(`graph-inc2.md:306`) and `_shared_with` (:458-465); AT-B103-I2-1
(`02-test-cases.md:347-348`); reader `extract_declared_spans` (a2l.py:3894) and
`/include` (a2l.py:1001-1013).

The reader already computes BLOB and INSTANCE spans (bounded, TYPEDEF-sized).
The 2b design still indexes only MEASUREMENT/CHARACTERISTIC tags, so the
V171 encodes AT-B103-I2-1 applies (`…UBYTE.IDENTICAL` at 0x810000,
`…SBYTE.IDENTICAL` at 0x810001) would still write bytes the declared INSTANCE
`ASAM_I_SCALAR_VALUE_UWORD_SINGLE` (2 bytes at 0x810000) shares — the exact
round-4 census hazard. `/include` has no fail-closed refusal.

**Correction.** (a) Add BLOB and INSTANCE entries to the 2b span index from
`a2l_data["declared_spans"]` (address `is not None`, length bounded — the reader
already refuses unsized INSTANCEs with length `None`, which must then be indexed
as covering nothing but never exempted); (b) refuse every encode when the file
holds `/include` outside comments (`<name>: the A2L includes a file the system
does not read`), or rule it into Inc 3 with a written limit; (c) write the
AXIS_PTS dependency (Inc 3b, R-A2L-DEF.140) into CTX *span* and AT-B103-I2-1 as
a known limit and confirm Inc 3b lands before Inc 8/9. Cost: the 4 V171 refusals
already measured (`E3-security.md` round 5), plus 1 `/include` fixture file.

### F3 — MINOR (design-gap): `mask_of` keying and the `.138/20` / scan-sentence edits are unapplied

Refs: E3S-41, E3S-42, E3S-44 above. Corrections are one-line each: key
`mask_of` by object identity; name step 9 in step 2 and add `.138/20`; add
"whose span overlaps" to the `_shared_with` scan sentence.

### F4 — LOW (design-gap): operator `<text>` in `.40`/`.49` messages is not length-capped

Refs: `01-requirements.md` `.40`, `.49`, `.137`, `.151`. `.151` caps *file*
words at 256 chars; the operator's own `<text>` is only control-char-replaced by
`.137`. A very long pasted number text produces a very long `A2L-DEF-NUMBER` /
`A2L-DEF-ENUM` message (self-inflicted, no memory-safety impact, but unbounded
message size). Recommend echoing `<text>` through the same 256-char cut, or
document the cap as operator-input-only.

### Consumer note (E3S-45 (iii))

`shared_with` is computed at describe and trusted by encode; the I-2 note must
keep: a consumer never clears `shared_with` (the `.138` cases clear it only as a
test device) and re-describes after the A2L or its file changes (Inc 6/Inc 10
obligation). The 256-byte page caps page occupancy at 256 single-byte objects,
so `_shared_with` is bounded per page; no DoS beyond the page size.

## Summary

- **Blocking:** E3S-37 (span-index scope) and F1 (stale `.19`/`.138` mask cases
  after Inc 11).
- **Non-blocking:** E3S-41/42/44 wording/case edits, E3S-36 residual (MOD_COMMON
  duplicate BYTE_ORDER), F4 (operator-text message cap).
- **Closed as reader fixes:** E3S-36 (own byte order), E3S-38, E3S-39, E3S-40,
  E3S-43.
