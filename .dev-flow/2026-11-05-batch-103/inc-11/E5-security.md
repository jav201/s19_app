## Verdict: FAIL

Static review at `f1397097`; no edits, tests, probes, or commits performed. Findings: **4 MAJOR, 2 MEDIUM, 1 MINOR**.

1. **MAJOR — impl — backslash-before-LF can inject section structure from inside a quoted string.**  
   `s19_app/tui/a2l.py:377`, `s19_app/tui/a2l.py:390-392`, consumed structurally at `s19_app/tui/a2l.py:926-981`.  
   `_WORD_SPLIT_RE` uses `\\.`; without DOTALL it cannot consume backslash+LF. The quoted alternative therefore fails and the `[^ ]+` fallback can emit `/begin` or `/end` as standalone words. For example, a string containing `"x\<LF> /end MEASUREMENT x"` can close the enclosing section even though the entire sequence is quoted.  
   **Requirements:** R-A2L-001.3.2, R-A2L-READ.13 and .14: a multiline quoted string is one word and contains no structure.  
   **Minimal correction:** make quoted-word matching line-end-aware—DOTALL or explicit CR/LF/CRLF handling—while retaining the bounded, unrolled scan. Ensure `_line_words` returns the complete quoted word before structural processing.

2. **MAJOR — impl — declared spans re-derive lengths that the tag size rules refuse.**  
   `s19_app/tui/a2l.py:3837-3853` calls `_infer_length_characteristic` directly, bypassing the `_tag_sizes` refusal applied to tags at `s19_app/tui/a2l.py:3692-3702`. A typedef VALUE on a two-byte layout with `LENGTH 4`, conflicting duplicate lengths, or VAL_BLK `MATRIX_DIM 4` plus `NUMBER 5` therefore produces a non-null INSTANCE length instead of no length.  
   **Requirements:** R-A2L-READ.43 applies R-A2L-015/.016/.017 to typedefs; CTX *length rows* and R-A2L-READ.61 require disagreement/no-number to give no length, finally. I-11.8(d) makes this unsafe for the declared-span overlap consumer.  
   **Minimal correction:** apply the same `_tag_sizes` agreement/no-number gate to typedef keyword lines before inference and multiplication by the INSTANCE dimension; any refusal must leave the span length `None`.

3. **MAJOR — impl — deposit-name datatype hints override the declared RECORD_LAYOUT datatype.**  
   `s19_app/tui/a2l.py:586-590` and `s19_app/tui/a2l.py:1992-1998` try `sizeof_from_deposit` before resolving the layout. Thus a layout named `__UBYTE_Z` whose FNC_VALUES is ULONG gets element length 1 instead of the declared 4. Enrichment then independently resolves the actual layout and can use a different byte size at `s19_app/tui/a2l.py:3990-4000`.  
   **Requirements:** CTX *datatype (CHARACTERISTIC)* at `01-requirements.md:128`: FNC_VALUES is authoritative; the deposit name is fallback only when the layout names no datatype. Affects R-A2L-015, R-A2L-016 and R-A2L-READ.43.  
   **Minimal correction:** in both helpers, resolve the declared layout’s datatype first and use the deposit-name hint only when that yields none; use the same resolved element size for agreement checking and inference.

4. **MAJOR — impl — CUBOID/CUBE_4/CUBE_5 lengths are not checked against their layout spans.**  
   Although `_CURVE_MAP_FAMILY` includes all five kinds at `s19_app/tui/a2l.py:251`, span computation and the standing-size/external-axis passes are restricted to CURVE/MAP at `s19_app/tui/a2l.py:3684-3690`, `s19_app/tui/a2l.py:3720-3739`, and `s19_app/tui/a2l.py:3780`. Consequently, a CUBOID/CUBE with a resolvable span and conflicting explicit `LENGTH` keeps that length without the required refusal.  
   **Requirements:** CTX *sizes* at `01-requirements.md:126`, R-A2L-READ.59 and .61 explicitly include CUBOID, CUBE_4 and CUBE_5.  
   **Minimal correction:** use `_CURVE_MAP_FAMILY` consistently for inline/external span resolution and standing-size comparison, refusing mismatches and preventing later re-derivation.

5. **MEDIUM — impl — external-axis size refusal reports `Line None`.**  
   `s19_app/tui/a2l.py:3792-3797` reads `tag.get("start_line")`, but tag construction at `s19_app/tui/a2l.py:3428-3457` never stores that key. The required external-axis disagreement diagnostic is therefore `Line None: CHARACTERISTIC …`.  
   **Requirement:** R-A2L-READ.59, especially case /8, requires the tag’s `/begin` line.  
   **Minimal correction:** carry the already-available local `start_line` in `post_info` at `s19_app/tui/a2l.py:3739` and use it in the post-pass; this avoids changing the public tag shape.

6. **MINOR — impl — invalid BYTE_ORDER words can escape the required diagnostic.**  
   At `s19_app/tui/a2l.py:3603-3612`, distinct duplicate arguments take the disagreement branch without assigning `own_bo_word`; validation at `s19_app/tui/a2l.py:3629-3631` consequently checks none. For example, `BYTE_ORDER MSB_FRIST` followed by `BYTE_ORDER MSB_LAST` refuses the address but never reports that `MSB_FRIST` is invalid. Repeated identical invalid words also produce only one diagnostic.  
   **Requirement:** R-A2L-READ.68 requires one error per invalid BYTE_ORDER argument word.  
   **Minimal correction:** validate every entry in `byte_order_words` once, independently of duplicate/source selection; retain the existing address refusal.

7. **MEDIUM — design-gap — EOF-truncated BLOB/INSTANCE sections export usable spans.**  
   `s19_app/tui/a2l.py:3863-3890` appends addresses and computed lengths without checking `end_line`, unlike tag extraction’s closure refusal at `s19_app/tui/a2l.py:3417-3419`. A file ending immediately after a valid-looking BLOB/INSTANCE header therefore yields both an `Unclosed /begin` error and a fully usable declared span.  
   **Requirements/design:** R-A2L-READ.40–.46 do not define closure behavior, while I-11.8(d) assigns these spans to the R-A2L-DEF.138 overlap index. That consumer contract needs complete records, not partial reads.  
   **Minimal correction:** add an explicit closure rule and make unclosed BLOB/INSTANCE sections unusable—omit them or null both address and length. Do not size instances from unclosed typedef declarations either.