## Verdict: FAIL

Static review of the product diff `10d01dc1..f1397097` found **10 findings: 1 HIGH, 3 MAJOR, 5 MEDIUM, 1 MINOR**. No edits, tests, or commits were performed.

### Findings

1. **HIGH — impl — quoted numeric header words are accepted as addresses/sizes**  
   **Location:** `s19_app/tui/a2l.py:445`, affecting `:3502`, `:3869-3879`  
   **Requirement:** R-A2L-READ.34–.36, .63, .40–.41; approved `_number_word` contract explicitly rejects quoted words.  
   `_tag_header` removes quotes before numeric validation. Consequently, `VALUE "0x2000"` is accepted as a CHARACTERISTIC address, and quoted BLOB/INSTANCE addresses and sizes are likewise accepted instead of producing no number. This can re-enable writes to an address that should have been refused.  
   **Minimal correction:** Preserve the canonical quoted word or its quoted flag through `_tag_header` until `_number_word` validation; unquote only nonnumeric fields afterward.

2. **MAJOR — impl — backslash-newline can split a quoted string into structural words**  
   **Location:** `s19_app/tui/a2l.py:377`, used at `:392`  
   **Requirement:** R-A2L-001.3.2, R-A2L-READ.13–.14.  
   The quoted alternative uses `\\.` without `re.DOTALL`. It therefore fails on a quoted string containing backslash followed by a line end. The fallback `[^ ]+` can then emit `/begin` or `/end` inside that string as separate words, corrupting the section tree.  
   **Minimal correction:** Make the quoted-word matcher handle backslash-newline, for example with `re.DOTALL`, or use the quote-aware character scanner for this path.

3. **MAJOR — impl — nested MODULEs lose the enclosing byte-order source**  
   **Location:** `s19_app/tui/a2l.py:3754-3759`, consumed at `:3628-3644`  
   **Requirement:** CTX *byte-order source*; R-A2L-READ.48–.49 and the approved “byte-order fallbacks as base” behavior.  
   Every MODULE replaces `current_module_source`, even when it has no BYTE_ORDER. The enclosing order remains in `current_module_byte_order`, but `_process_tag` never uses that parameter. A nested module without its own source therefore falls to `little`; an enclosing invalid source also stops refusing the address. Both the base reader and reference inherit the enclosing module.  
   **Minimal correction:** Replace `current_module_source` only when the current MODULE has its own source; otherwise carry the enclosing tuple, including invalid-source information.

4. **MAJOR — impl — `/end` spans and structural diagnostics use the name word’s line**  
   **Location:** `s19_app/tui/a2l.py:955-961`; nesting diagnostic at `:929`  
   **Requirement:** R-A2L-001.4–.5, R-A2L-READ.48 and .64; graph I-11.1 defines `end_line` as the `/end` word’s line.  
   When `/end` and its section name are on different lines, `end_line`, mismatch errors, and `/end without /begin` use the name’s line rather than the `/end` line. The nesting-cap diagnostic similarly uses the section keyword’s line rather than the `/begin` line. Incorrect spans can affect downstream line-span refusals.  
   **Minimal correction:** Use `pending_end_line` for `end_line` and both `/end` diagnostics; use `pending_begin_line` for the depth error.

5. **MEDIUM — impl — words across a multiline comment are merged into the first line’s run**  
   **Location:** `s19_app/tui/a2l.py:832-843`  
   **Requirement:** R-A2L-READ.1 and .48; approved lexer contract of one canonical item per line containing words.  
   When words precede `/*` and the comment closes on a later line, the `in_comment` boundary branch advances the line without flushing `pending`. Words after the close are consequently yielded under the earlier line number, producing incorrect runs, metadata, and `/end` lines.  
   **Minimal correction:** At every non-string element boundary, including boundaries inside a block comment, emit pending words before advancing the line.

6. **MEDIUM — design-gap — quoted keyword arguments lose word boundaries and their values**  
   **Location:** `s19_app/tui/a2l.py:514`, with naive splits at `:532`, `:600`, `:1927`, `:1968`, and `:3514`  
   **Requirement:** R-A2L-001.3.1, R-A2L-READ.29, .33, .58, and .68.  
   The approved canonical `"KEYWORD <args>"` representation is later split with `text.split(" ")`. Thus `DISPLAY_IDENTIFIER "XM disp"` becomes the value `"XM`, while quoted UNIT/conversion/symbol arguments can be dropped or misparsed. String-valued fields also retain quotes in the single-space case.  
   **Minimal correction:** Consume structured keyword arguments, or split these items with the quote-aware `_line_words`; unquote string-valued fields while retaining raw quoted words for numeric and byte-order validation.

7. **MEDIUM — impl — external-axis size disagreement reports `Line None`**  
   **Location:** `s19_app/tui/a2l.py:3792-3797`  
   **Requirement:** R-A2L-READ.59, specifically the E3S-29 external-axis case.  
   The error reads `tag.get("start_line")`, but tags created at `:3428-3457` have no such key. Every external-axis standing-size disagreement therefore emits `Line None: CHARACTERISTIC …` instead of the `/begin` line.  
   **Minimal correction:** Carry the section’s `start_line` in `post_info` and use it here; do not add a public tag key.

8. **MEDIUM — impl — argument diagnostics use the keyword’s line instead of the argument’s line**  
   **Location:** `s19_app/tui/a2l.py:3528`, `:3540`, `:3548`, and `:3630`; line information is collapsed at `:514`  
   **Requirement:** R-A2L-READ.63 and .68, both requiring the offending word’s line.  
   For `ECU_ADDRESS` on line 22 with an invalid number on line 23, the diagnostic names line 22. SIZE/MATRIX_DIM and invalid BYTE_ORDER arguments have the same problem.  
   **Minimal correction:** Preserve each argument’s source line in keyword items, or emit these diagnostics while `_tag_keyword_lines` still has the argument’s `l` value.

9. **MEDIUM — impl — unrelated invalidity suppresses mandatory disagreement errors**  
   **Location:** `s19_app/tui/a2l.py:3648-3656` and `:3693-3702`  
   **Requirement:** R-A2L-READ.59.  
   `address_invalid` bypasses disagreement reporting even when valid address words differ; `no_number` similarly bypasses size-disagreement reporting. For example, two differing ECU_ADDRESS values plus an invalid BYTE_ORDER produce no `.59` address error, although the address is correctly refused.  
   **Minimal correction:** Diagnose differing address words and disagreeing sizes independently, then apply the combined refusal conditions.

10. **MINOR — impl — only the first duplicate BYTE_ORDER argument is validated**  
    **Location:** `s19_app/tui/a2l.py:3603-3611` and `:3629-3631`  
    **Requirement:** R-A2L-READ.68 requires one error per invalid BYTE_ORDER argument word.  
    Repeated invalid BYTE_ORDER arguments produce only the first `.68` error. A valid first argument followed by an invalid second produces none, though duplicate/disagreement handling still refuses the address.  
    **Minimal correction:** Validate every entry in `byte_order_words` for `.68`, while retaining the existing duplicate and effective-source rules.

### Compatibility check

No additional findings in `a2l_definition.py` or `a2l_extract.py`: the refused MEASUREMENT length remains refused through `_describe_one`, and `extract_declared_spans` is re-exported correctly. AT-B103-I11-2/-3 use the real application load paths and have recorded green evidence, but their shapes do not exercise the findings above.